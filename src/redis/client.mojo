"""A blocking Redis client: one connection over TCP or a Unix-domain
socket, driving `RespConnection` with a deadline per call. This is the only
`redis` module that does I/O (`net`); not re-exported from `redis`.

    var r = Client.connect(Config.parse("redis://localhost:6379/0"))
    _ = r.command("SET", "greeting", "hello")
    print(r.command("GET", "greeting").text())
    var visits = r.command("INCR", "visits").int()
    r^.close()

`command(args...)` sends one command, each argument in its text form;
`command_args(args)` takes an `Args`, for bytes. The reply is a `Value`
(`redis.resp`). A server error raises `RedisError` with its code
(`e.code()`: "ERR", "WRONGTYPE", "NOAUTH", ...), and the connection goes on.

Connecting runs `HELLO 3` with AUTH and SETNAME as configured; for
`protocol=2`, or a server without HELLO (before Redis 6), RESP2's AUTH and
CLIENT SETNAME instead. Then SELECT, for a database other than 0.

Deadlines:
- `Config.connect_timeout` bounds `connect`.
- A call's `timeout` bounds it. Redis cannot cancel a command, and its
  reply would still come and pair with the next one, so a call whose
  deadline passes closes the connection: the next call raises `Closed`.
  Give blocking commands (BLPOP, XREAD BLOCK, WAIT) a timeout longer than
  they block.

Anything else that goes wrong closes the connection too: a transport
error, or the server breaking the protocol. RESP3 pushes that arrive
during a call (invalidations, after CLIENT TRACKING) are kept for
`take_pushes()`.
"""

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from linux.time import Deadline, Duration
from net.addr import UnixAddr
from net.blocking import (
    DEAD_PEER_KEEPALIVE,
    IdleState,
    detect_dead_peers,
    idle_state,
    recv_with_deadline,
    send_all_with_deadline,
    try_recv,
)
from net.socket import Shutdown, Socket
from net.tcp import TcpStream
from net.unix import UnixStream

from .config import Config
from .connection import EventKind, RespConnection, RespEvent
from .resp import Args, Kind, Value

comptime MAX_PUSHES = 1024
"""Pushes kept until `take_pushes`; past it, the oldest are dropped."""

comptime _RECEIVE = 64 * 1024
comptime _SERVER_ERROR = "redis: the server replied with an error"
comptime _CLOSED = "redis: the connection is closed"
comptime _CLOSED_BY_SERVER = "redis: the server closed the connection"


struct RedisError(Copyable, Movable, Writable):
    """Why a call failed.
    - **The server's error:** `is_server()` is true, `code()` is its first
      word and `message()` all of it. The connection goes on.
    - **Otherwise**, `io` says what failed: the transport, the protocol
      (`InvalidData`), the deadline (`is_deadline()`), or the call itself
      (`InvalidInput`: a refused command, `Closed`: the connection is
      gone). Every such failure but `InvalidInput` has closed the
      connection."""

    var io: IoError
    var _message: String
    var _server: Bool

    def __init__(out self, io: IoError):
        self.io = io
        self._message = String()
        self._server = False

    def __init__(out self, message: String):
        """The server's error."""
        self.io = IoError.of_kind(_SERVER_ERROR, ErrorKind.Other)
        self._message = message
        self._server = True

    def is_server(self) -> Bool:
        return self._server

    def code(self) -> String:
        """The server's error code ("" when it is no server error)."""
        var end = self._message.find(" ")
        if end < 0:
            return self._message
        return String(self._message[byte=0:end])

    def message(self) -> String:
        """The server's whole error ("" when it is no server error)."""
        return self._message

    def is_deadline(self) -> Bool:
        return self.io.is_deadline()

    def write_to(self, mut writer: Some[Writer]):
        if self._server:
            writer.write(self._message)
        else:
            writer.write(self.io)


struct Client(Movable):
    """One connection (see the module docs). Not for use by several threads
    at once."""

    var _sock: Socket
    var _conn: RespConnection
    var _ev: RespEvent
    var _rx: List[UInt8]
    var _tx: ByteBuffer
    var _config: Config
    var _usable: Bool
    var _pushes: List[Value]
    var _protocol: Int
    var _hello: Value
    """HELLO's reply: what the server said about itself (empty without
    HELLO)."""

    def __init__(out self, var sock: Socket, var conn: RespConnection, config: Config):
        self._sock = sock^
        self._conn = conn^
        self._ev = RespEvent()
        self._rx = List[UInt8](length=_RECEIVE, fill=0)
        self._tx = ByteBuffer()
        self._config = config.copy()
        self._usable = True
        self._pushes = List[Value]()
        self._protocol = 2
        self._hello = Value()

    @staticmethod
    def connect(config: Config) raises RedisError -> Client:
        """Open a connection, authenticate and set it up, all within
        `config.connect_timeout`. The server's refusal (WRONGPASS, NOAUTH)
        raises with its code."""
        var deadline = _deadline(config.connect_timeout)
        var c: Client
        try:
            config.check()
            var conn = RespConnection(config.limits)
            var sock = _dial(config, deadline)
            if not config.is_unix() and config.keepalive:
                detect_dead_peers(sock, DEAD_PEER_KEEPALIVE)
            c = Client(sock^, conn^, config)
        except e:
            raise RedisError(e)
        c._setup(deadline)
        return c^

    def _setup(mut self, deadline: Deadline) raises RedisError:
        """HELLO (or AUTH and CLIENT SETNAME), then SELECT."""
        var auth = self._config.password.byte_length() > 0
        var named = self._config.client_name.byte_length() > 0
        var resp2 = self._config.protocol == 2
        if not resp2:
            var hello = Args("HELLO", "3")
            if auth:
                hello.add_text("AUTH")
                hello.add_text(self._config.user if self._config.user.byte_length() > 0 else "default")
                hello.add_text(self._config.password)
            if named:
                hello.add_text("SETNAME")
                hello.add_text(self._config.client_name)
            var reply = self._call(hello, deadline)
            if _no_hello(reply):  # (before Redis 6)
                resp2 = True
            else:
                _raise_if_error(reply)
                self._protocol = 3
                swap(self._hello, reply)
        if resp2:
            if auth:
                var a = Args("AUTH")
                if self._config.user.byte_length() > 0:
                    a.add_text(self._config.user)
                a.add_text(self._config.password)
                _raise_if_error(self._call(a, deadline))
            if named:
                _raise_if_error(self._call(Args("CLIENT", "SETNAME", self._config.client_name), deadline))
        if self._config.database != 0:
            _raise_if_error(self._call(Args("SELECT", self._config.database), deadline))

    # ---- calls ------------------------------------------------------------------

    def command[*Ts: Writable](mut self, *args: *Ts, timeout: Duration = Duration.ZERO) raises RedisError -> Value:
        """Send one command, each argument in its text form, and return its
        reply; a server error raises (the connection goes on). `timeout`:
        `Duration.ZERO` for none."""
        var a = Args()
        comptime for i in range(args.__len__()):
            a.add(args[i])
        return self.command_args(a, timeout)

    def command_args(mut self, args: Args, timeout: Duration = Duration.ZERO) raises RedisError -> Value:
        """`command`, with the arguments in an `Args` (for bytes)."""
        var reply = self._call(args, _deadline(timeout))
        _raise_if_error(reply)
        return reply^

    def _call(mut self, args: Args, deadline: Deadline) raises RedisError -> Value:
        """Send `args` and return the reply, an error reply included."""
        if not self._usable:
            raise RedisError(IoError.of_kind(_CLOSED, ErrorKind.Closed))
        try:
            self._conn.command(args)
        except e:
            raise RedisError(e)  # (refused: nothing was sent, the connection goes on)
        try:
            self._flush(deadline)
            while True:
                if not self._next(deadline):
                    raise IoError.of_kind(_CLOSED_BY_SERVER, ErrorKind.UnexpectedEof)
                if self._ev.kind == EventKind.REPLY:
                    var reply = Value()
                    swap(reply, self._ev.value)
                    return reply^
                self._keep_push()
        except e:
            self._close_now()
            raise RedisError(e)

    # ---- I/O ------------------------------------------------------------------

    def _flush(mut self, deadline: Deadline) raises IoError:
        while self._conn.poll_transmit(self._tx) > 0:
            send_all_with_deadline(self._sock, self._tx.readable_span(), deadline, "redis: send")
            self._tx.clear()

    def _next(mut self, deadline: Deadline) raises IoError -> Bool:
        """The next event into `_ev`; False when the server closed the
        connection with nothing due."""
        while True:
            if self._conn.poll(self._ev):
                return True
            if deadline.is_expired():  # (replies that keep coming never make recv wait)
                raise IoError.of_kind("redis: receive", ErrorKind.TimedOut)
            var room = min(len(self._rx), self._conn.feed_capacity())
            var n = recv_with_deadline(self._sock, Span(self._rx)[:room], 0, deadline, "redis: receive")
            if n == 0:
                self._conn.feed_eof()
                return self._conn.poll(self._ev)
            self._conn.feed(Span(self._rx)[:n])

    def _keep_push(mut self):
        if len(self._pushes) >= MAX_PUSHES:
            _ = self._pushes.pop(0)
        var push = Value()
        swap(push, self._ev.value)
        self._pushes.append(push^)

    # ---- the connection --------------------------------------------------------

    def protocol(self) -> Int:
        """The protocol the connection speaks: 3 or 2."""
        return self._protocol

    def hello(self) -> Value:
        """HELLO's reply, a map: "server", "version", "proto", "id",
        "mode", "role", "modules" (empty without HELLO)."""
        return self._hello.copy()

    def is_usable(self) -> Bool:
        """Whether the connection can take a command: open, not failed."""
        return self._usable and self._conn.is_idle()

    def take_pushes(mut self) -> List[Value]:
        """The pushes received since the last call."""
        var out = List[Value]()
        swap(out, self._pushes)
        return out^

    def check(mut self) -> Bool:
        """Whether the connection can still be used, told without a round
        trip: the socket must still be open, and whatever the server sent
        meanwhile must be pushes (kept), not a reply no command waited for.
        (For a pool, before handing out a connection that sat idle.)"""
        if not self.is_usable():
            return False
        var state = idle_state(self._sock)
        if state == IdleState.EMPTY:
            return True
        if state == IdleState.CLOSED:
            self._close_now()
            return False
        try:  # (DATA: read what is there, without waiting)
            while True:
                while self._conn.poll(self._ev):
                    self._keep_push()  # (a reply would have raised: none is due)
                var room = min(len(self._rx), self._conn.feed_capacity())
                var got = try_recv(self._sock, Span(self._rx)[:room], "redis: receive")
                if not got:
                    break
                if got.value() == 0:
                    self._close_now()
                    return False
                self._conn.feed(Span(self._rx)[: got.value()])
        except:
            self._close_now()
            return False
        return self.is_usable()

    def _close_now(mut self):
        """End the connection; the socket closes with the `Client`."""
        self._usable = False
        try:
            self._sock.shutdown(Shutdown.BOTH)
        except:
            pass

    def close(var self):
        """Close the connection (closing is how a client ends one: QUIT is
        deprecated)."""
        self._close_now()


def _raise_if_error(reply: Value) raises RedisError:
    var message = String()
    var failed: Bool
    try:
        failed = reply.is_error()
        if failed:
            message = reply.text()
    except e:
        raise RedisError(e)
    if failed:
        raise RedisError(message)


def _no_hello(reply: Value) raises RedisError -> Bool:
    """Whether HELLO's reply says the server has no HELLO (or no RESP3)."""
    try:
        if not reply.is_error():
            return False
        var code = reply.error_code()
        return code == "NOPROTO" or (code == "ERR" and reply.text().find("unknown command") >= 0)
    except e:
        raise RedisError(e)


def _deadline(timeout: Duration) -> Deadline:
    if timeout == Duration.ZERO:
        return Deadline.none()
    return Deadline.after(timeout)


def _dial(config: Config, deadline: Deadline) raises IoError -> Socket:
    """A connected socket: the Unix socket at `host` when it is a path,
    else TCP (by name, Happy Eyeballs)."""
    if config.is_unix():
        return UnixStream.connect_deadline(UnixAddr.from_pathname(config.host), deadline).into_socket()
    return TcpStream.connect_host_deadline(config.host, UInt16(config.port), deadline).into_socket()
