"""Unix-domain echo with `net.unix`, in a single process.

    pixi run mojo run -I src examples/unix_echo.mojo [PATH]

Without PATH the listener uses a Linux abstract name (no file, gone when
the socket closes); with PATH it binds that filesystem path and removes the
socket file at the end.

One thread can play both sides because an AF_UNIX connect completes as soon
as the listener's backlog has room: the client connects, the server
accepts, and both exchange messages in turn. It also shows `UnixStream.pair`
and SO_PEERCRED (who is on the other end).
"""

from std.os import remove
from std.sys import argv

from linux.time import Deadline, Duration
from net.addr import UnixAddr
from net.socket import Shutdown
from net.unix import UnixListener, UnixStream


def echo_once(
    mut client: UnixStream, mut server: UnixStream, text: String
) raises:
    client.write_all(text.as_bytes())
    var buf = List[UInt8](length=text.byte_length(), fill=0)
    server.read_exact(Span(buf))
    server.write_all(Span(buf))
    var back = List[UInt8](length=text.byte_length(), fill=0)
    client.read_exact(Span(back))
    print("  echoed:", String(from_utf8_lossy=Span(back)))


def main() raises:
    var args = argv()
    var pathname = len(args) > 1
    var addr = UnixAddr.from_pathname(args[1]) if pathname else (
        UnixAddr.from_abstract_name("mojo_tcp_unix_echo_example")
    )
    var listener = UnixListener.bind(addr)
    print("listening on", listener.local_addr())
    listener.set_deadline(Deadline.after(Duration.from_secs(5)))
    var client = UnixStream.connect_timeout(addr, Duration.from_secs(5))
    var acc = listener.accept()
    print("accepted a peer at", acc.addr)
    var server = acc^.into_stream()
    client.set_deadline(Deadline.after(Duration.from_secs(5)))
    server.set_deadline(Deadline.after(Duration.from_secs(5)))
    var cred = server.socket().peer_cred()
    print("peer credentials: pid", cred.pid, "uid", cred.uid, "gid", cred.gid)
    echo_once(client, server, "hello over AF_UNIX")
    echo_once(client, server, "second message")
    client.shutdown(Shutdown.WRITE)
    var rest = List[UInt8]()
    _ = server.read_to_end(rest)
    print("server saw EOF after the client's shutdown(WRITE)")

    # A connected pair without any name at all.
    var p = UnixStream.pair()
    var a = p.first.take()
    var b = p.second.take()
    a.set_deadline(Deadline.after(Duration.from_secs(5)))
    b.set_deadline(Deadline.after(Duration.from_secs(5)))
    print("socketpair:")
    echo_once(a, b, "pair ping")

    listener^.close()
    if pathname:
        remove(args[1])  # pathname sockets leave a file behind
