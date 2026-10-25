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

Several commands at once:
- `run(pipeline)` sends a `Pipeline`'s commands in one write and returns
  their replies in order. An error reply is a value in its place.
- `transaction(pipeline)` runs them between MULTI and EXEC, in the same
  one round trip: None when a key WATCHed before it changed.

Typed helpers wrap the common commands, reading the reply in either
protocol: `get`, `set`, `delete`, `exists`, `incr`, `expire`, `ttl`, the
hash, list, set and sorted-set ones, and `publish`.

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

from std.collections import Dict

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


struct Pipeline(Movable, Sized):
    """Commands to send at once (`Client.run`, `Client.transaction`)."""

    var _commands: List[Args]

    def __init__(out self):
        self._commands = List[Args]()

    def __len__(self) -> Int:
        return len(self._commands)

    def add[*Ts: Writable](mut self, *args: *Ts):
        """A command, each argument in its text form."""
        var a = Args()
        comptime for i in range(args.__len__()):
            a.add(args[i])
        self._commands.append(a^)

    def add_args(mut self, var args: Args):
        """A command whose arguments are in an `Args` (for bytes)."""
        self._commands.append(args^)

    def clear(mut self):
        self._commands.clear()


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

    def run(mut self, pipeline: Pipeline, timeout: Duration = Duration.ZERO) raises RedisError -> List[Value]:
        """Send the pipeline's commands in one write and return their
        replies, in order. An error reply is a value in its place
        (`is_error()`): the commands after it ran too. A command refused
        here (see `command`) refuses the whole pipeline, with nothing
        sent."""
        return self._batch(pipeline._commands, _deadline(timeout))

    def transaction(mut self, pipeline: Pipeline, timeout: Duration = Duration.ZERO) raises RedisError -> Optional[List[Value]]:
        """Run the pipeline's commands as a transaction: MULTI, the commands
        and EXEC, in one round trip, all or none of them. Their replies come
        back in order; an error the server met running one is a value in
        its place, as the commands after it ran. None when a key WATCHed
        before changed: nothing ran. A command the server refused while
        queuing (unknown, or with wrong arguments) aborts the transaction:
        its error raises, and nothing ran. (Do not mix with a MULTI sent
        by hand.)"""
        var batch = List[Args](capacity=len(pipeline) + 2)
        batch.append(Args("MULTI"))
        for i in range(len(pipeline)):
            batch.append(pipeline._commands[i].copy())
        batch.append(Args("EXEC"))
        var replies = self._batch(batch, _deadline(timeout))
        for i in range(len(replies) - 1):  # (MULTI's OK, then each QUEUED)
            _raise_if_error(replies[i])
        var exec = replies.pop()
        _raise_if_error(exec)
        var out = List[Value]()
        try:
            if exec.is_null():
                return None
            var c = 1
            for _ in range(exec.count()):
                out.append(exec.part(c))
                c = exec.next(c)
        except e:
            raise RedisError(e)
        return out^

    def _batch(mut self, batch: List[Args], deadline: Deadline) raises RedisError -> List[Value]:
        """Send `batch` at once and return the replies, error replies
        included."""
        if not self._usable:
            raise RedisError(IoError.of_kind(_CLOSED, ErrorKind.Closed))
        try:
            self._conn.commands(batch)
        except e:
            raise RedisError(e)  # (refused: nothing was sent, the connection goes on)
        var replies = List[Value](capacity=len(batch))
        try:
            self._flush(deadline)
            while len(replies) < len(batch):
                if not self._next(deadline):
                    raise IoError.of_kind(_CLOSED_BY_SERVER, ErrorKind.UnexpectedEof)
                if self._ev.kind == EventKind.REPLY:
                    var reply = Value()
                    swap(reply, self._ev.value)
                    replies.append(reply^)
                else:
                    self._keep_push()
        except e:
            self._close_now()
            raise RedisError(e)
        return replies^

    # ---- typed helpers ----------------------------------------------------------

    def get(mut self, key: StringSlice) raises RedisError -> Optional[String]:
        """GET: the value, or None when there is no such key."""
        var v = self.command("GET", key)
        if _is_null(v):
            return None
        return _text(v, 0)

    def get_bytes(mut self, key: StringSlice) raises RedisError -> Optional[List[UInt8]]:
        """GET, for a value that is not text."""
        var v = self.command("GET", key)
        if _is_null(v):
            return None
        try:
            return v.bytes()
        except e:
            raise RedisError(e)

    def set[T: Writable](
        mut self, key: StringSlice, value: T, *, expire: Duration = Duration.ZERO, nx: Bool = False, xx: Bool = False
    ) raises RedisError -> Bool:
        """SET, with an expiry (`expire`, `Duration.ZERO` for none) and NX
        (only if absent) or XX (only if present): whether it was set."""
        var a = Args("SET", key, value)
        return self._set(a^, expire, nx, xx)

    def set_bytes(
        mut self, key: StringSlice, value: Span[UInt8, _], *, expire: Duration = Duration.ZERO, nx: Bool = False, xx: Bool = False
    ) raises RedisError -> Bool:
        """`set`, for a value that is not text."""
        var a = Args("SET", key)
        a.add_bytes(value)
        return self._set(a^, expire, nx, xx)

    def _set(mut self, var a: Args, expire: Duration, nx: Bool, xx: Bool) raises RedisError -> Bool:
        if expire != Duration.ZERO:
            a.add_text("PX")
            a.add(expire.as_millis_ceil())
        if nx:
            a.add_text("NX")
        if xx:
            a.add_text("XX")
        return not _is_null(self.command_args(a))  # (NX or XX not met: a null)

    def delete(mut self, *keys: String) raises RedisError -> Int:
        """DEL: how many of the keys there were."""
        var a = Args("DEL")
        for k in keys:
            a.add_text(k)
        return _int(self.command_args(a))

    def exists(mut self, *keys: String) raises RedisError -> Int:
        """EXISTS: how many of the keys there are (a key given twice counts
        twice)."""
        var a = Args("EXISTS")
        for k in keys:
            a.add_text(k)
        return _int(self.command_args(a))

    def incr(mut self, key: StringSlice, by: Int = 1) raises RedisError -> Int:
        """INCRBY: the value after it."""
        return _int(self.command("INCRBY", key, by))

    def expire(mut self, key: StringSlice, after: Duration) raises RedisError -> Bool:
        """PEXPIRE: whether the key exists (and now expires)."""
        return _int(self.command("PEXPIRE", key, after.as_millis_ceil())) == 1

    def ttl(mut self, key: StringSlice) raises RedisError -> Optional[Duration]:
        """PTTL: the time left, or None when the key has no expiry or does
        not exist."""
        var ms = _int(self.command("PTTL", key))
        if ms < 0:
            return None
        return Duration.from_millis(ms)

    def hset[T: Writable](mut self, key: StringSlice, field: StringSlice, value: T) raises RedisError -> Bool:
        """HSET of one field: whether it is a new field."""
        return _int(self.command("HSET", key, field, value)) == 1

    def hget(mut self, key: StringSlice, field: StringSlice) raises RedisError -> Optional[String]:
        var v = self.command("HGET", key, field)
        if _is_null(v):
            return None
        return _text(v, 0)

    def hgetall(mut self, key: StringSlice) raises RedisError -> Dict[String, String]:
        """HGETALL: every field and value (a map in RESP3, a flat array in
        RESP2)."""
        var v = self.command("HGETALL", key)
        var out = Dict[String, String]()
        var pairs = _elements(v) // 2
        try:
            var c = 1
            for _ in range(pairs):
                var k = v.text(c)
                c = v.next(c)
                out[k] = v.text(c)
                c = v.next(c)
        except e:
            raise RedisError(e)
        return out^

    def hdel(mut self, key: StringSlice, *fields: String) raises RedisError -> Int:
        var a = Args("HDEL", key)
        for f in fields:
            a.add_text(f)
        return _int(self.command_args(a))

    def lpush(mut self, key: StringSlice, *values: String) raises RedisError -> Int:
        """LPUSH: the list's length after it."""
        var a = Args("LPUSH", key)
        for x in values:
            a.add_text(x)
        return _int(self.command_args(a))

    def rpush(mut self, key: StringSlice, *values: String) raises RedisError -> Int:
        """RPUSH: the list's length after it."""
        var a = Args("RPUSH", key)
        for x in values:
            a.add_text(x)
        return _int(self.command_args(a))

    def lpop(mut self, key: StringSlice) raises RedisError -> Optional[String]:
        var v = self.command("LPOP", key)
        if _is_null(v):
            return None
        return _text(v, 0)

    def rpop(mut self, key: StringSlice) raises RedisError -> Optional[String]:
        var v = self.command("RPOP", key)
        if _is_null(v):
            return None
        return _text(v, 0)

    def lrange(mut self, key: StringSlice, start: Int, stop: Int) raises RedisError -> List[String]:
        """LRANGE (`stop` included; -1 for the last)."""
        return _strings(self.command("LRANGE", key, start, stop))

    def sadd(mut self, key: StringSlice, *members: String) raises RedisError -> Int:
        """SADD: how many members were new."""
        var a = Args("SADD", key)
        for m in members:
            a.add_text(m)
        return _int(self.command_args(a))

    def srem(mut self, key: StringSlice, *members: String) raises RedisError -> Int:
        var a = Args("SREM", key)
        for m in members:
            a.add_text(m)
        return _int(self.command_args(a))

    def smembers(mut self, key: StringSlice) raises RedisError -> List[String]:
        """SMEMBERS, in the server's order (a set in RESP3, an array in
        RESP2)."""
        return _strings(self.command("SMEMBERS", key))

    def sismember(mut self, key: StringSlice, member: StringSlice) raises RedisError -> Bool:
        return _int(self.command("SISMEMBER", key, member)) == 1

    def zadd(mut self, key: StringSlice, score: Float64, member: StringSlice) raises RedisError -> Bool:
        """ZADD of one member: whether it is a new member."""
        return _int(self.command("ZADD", key, score, member)) == 1

    def zscore(mut self, key: StringSlice, member: StringSlice) raises RedisError -> Optional[Float64]:
        """ZSCORE (a double in RESP3, a bulk string in RESP2)."""
        var v = self.command("ZSCORE", key, member)
        if _is_null(v):
            return None
        try:
            return v.float()
        except e:
            raise RedisError(e)

    def zrange(mut self, key: StringSlice, start: Int, stop: Int) raises RedisError -> List[String]:
        """ZRANGE by rank, lowest score first."""
        return _strings(self.command("ZRANGE", key, start, stop))

    def publish(mut self, channel: StringSlice, message: StringSlice) raises RedisError -> Int:
        """PUBLISH: how many subscribers received the message."""
        return _int(self.command("PUBLISH", channel, message))

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


def _is_null(v: Value) raises RedisError -> Bool:
    try:
        return v.is_null()
    except e:
        raise RedisError(e)


def _int(v: Value) raises RedisError -> Int:
    try:
        return v.int()
    except e:
        raise RedisError(e)


def _text(v: Value, n: Int) raises RedisError -> String:
    try:
        return v.text(n)
    except e:
        raise RedisError(e)


def _elements(v: Value) raises RedisError -> Int:
    """An aggregate's elements (a map's: twice its pairs)."""
    try:
        var count = v.count()
        return 2 * count if v.kind() == Kind.MAP else count
    except e:
        raise RedisError(e)


def _strings(v: Value) raises RedisError -> List[String]:
    """The text of each element of an array or set."""
    var out = List[String]()
    try:
        var c = 1
        for _ in range(v.count()):
            out.append(v.text(c))
            c = v.next(c)
    except e:
        raise RedisError(e)
    return out^


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
