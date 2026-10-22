"""Blocking TCP echo server built on `net.tcp`.

It serves ONE connection at a time: each client is echoed until it closes
(or idles out) before the next `accept`, and other clients wait in the
listen backlog meanwhile. That is the honest limit of blocking I/O on one
thread; the many-connections server is the M2 event loop (`rt`).

    pixi run mojo run -I src examples/net/echo_server.mojo [ADDR] [MAX_CONNS]

ADDR defaults to 127.0.0.1:7878 (port 0 picks a free one; the bound address
is printed). MAX_CONNS > 0 exits after that many connections (handy for
scripted demos); the default 0 serves forever.

Deadlines bound every step, so one stuck client cannot wedge the server:
- A client that sends nothing for 30 s is dropped (read deadline, renewed
  before each read).
- Each echoed chunk (one read, up to 64 KiB) must be written completely
  within 10 s of starting its `write_all`. Deadlines are absolute, and
  partial progress does not extend them. So a client that stops reading is
  dropped, and so is one that keeps reading but slower than about
  6.4 KB/s. A trickling reader therefore cannot hold the server forever.
  For a "no progress for 10 s" rule instead, loop over `write` and renew
  the write deadline after each partial write.
"""

from std.sys import argv

from linux import ErrorKind, IoError
from linux.time import Deadline, Duration, sleep
from net.addr import SocketAddr
from net.tcp import TcpAccepted, TcpListener, TcpStream

comptime IDLE = Duration.from_secs(30)
comptime STALL = Duration.from_secs(10)


def serve(mut conn: TcpStream) raises IoError -> Int:
    """Echo until EOF; returns the bytes echoed."""
    var buf = List[UInt8](length=64 * 1024, fill=0)
    var total = 0
    while True:
        conn.set_read_deadline(Deadline.after(IDLE))
        var n = conn.read(Span(buf))
        if n == 0:
            return total
        # One absolute deadline for the whole chunk (see the module docs).
        conn.set_write_deadline(Deadline.after(STALL))
        conn.write_all(Span(buf)[0:n])
        total += n


def main() raises:
    var args = argv()
    var addr = SocketAddr.parse(args[1] if len(args) > 1 else "127.0.0.1:7878")
    var max_conns = atol(args[2]) if len(args) > 2 else 0
    var listener = TcpListener.bind(addr)
    print("echo_server listening on", listener.local_addr())
    var served = 0
    while max_conns == 0 or served < max_conns:
        var acc: TcpAccepted
        try:
            acc = listener.accept()
        except e:
            # EMFILE/ENFILE leave the connection queued: back off instead of
            # spinning on accept (the M2 loop uses the reserve-fd trick).
            print("accept failed:", e)
            if e.kind == ErrorKind.TooManyFiles:
                sleep(Duration.from_millis(100))
            continue
        served += 1
        var peer = acc.addr
        var conn = acc^.into_stream()
        try:
            var n = serve(conn)
            print("served", peer, "-", n, "bytes")
        except e:
            print("dropped", peer, "-", e)
