"""`BufReader` over real sockets through the syscall fault seam (built with
-D MOJO_NET_FAULTS=1 because of the `_faults.mojo` suffix): one-byte and
short `recv`s plus EINTR must not change a single frame. Fault builds also
turn on `ByteBuffer`'s span check mode (storage moves on every mutation),
so a span the reader kept across a call would read poison here."""

from std.testing import TestSuite, assert_equal, assert_true

from linux import Errno, fault
from linux.nr import SYS_recvfrom
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.reader import BufReader
from net.socket import Shutdown
from net.tcp import TcpListener, TcpStream
from net.unix import UnixStream
from reader_script import (
    INPUT,
    expected_transcript,
    first_difference,
    run_transcript,
)


def _guard() -> Deadline:
    return Deadline.after(Duration.from_secs(10))


def test_transcript_over_one_byte_recvs_and_eintr() raises:
    fault.clear()
    var p = UnixStream.pair()
    var x = p.first.take()
    var y = p.second.take()
    y.set_write_deadline(_guard())
    y.write_all(String(INPUT).as_bytes())
    y.shutdown(Shutdown.WRITE)
    x.set_read_deadline(_guard())
    var r = BufReader(x^, capacity=4)
    fault.clear()
    # EINTR on every third recv (the first rule to fire wins), else one byte.
    fault.inject(SYS_recvfrom, Errno.EINTR, every=3, times=30)
    fault.inject_short(SYS_recvfrom, 1, times=-1)
    var got = run_transcript(r)
    var recvs = fault.calls(SYS_recvfrom)
    fault.clear()
    var diff = first_difference(got, expected_transcript())
    if diff:
        raise Error(diff)
    assert_true(recvs > len(String(INPUT).as_bytes()))  # one byte per recv


def test_read_exact_over_short_tcp_recvs() raises:
    fault.clear()
    var l = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    l.set_deadline(_guard())
    var c = TcpStream.connect(l.local_addr())
    c.set_deadline(_guard())
    var s = l.accept().into_stream()
    s.set_deadline(_guard())
    var data = List[UInt8]()
    for i in range(10_000):
        data.append(UInt8(i % 253))
    c.write_all(Span(data))
    var r = BufReader(s^, capacity=64)
    fault.clear()
    fault.inject_short(SYS_recvfrom, 7, times=-1)
    var body = List[UInt8](length=10_000, fill=0)
    r.read_exact(Span(body))
    var recvs = fault.calls(SYS_recvfrom)
    fault.clear()
    for i in range(10_000):
        if Int(body[i]) != i % 253:
            raise Error("byte ", i, " differs")
    assert_equal(recvs, (10_000 + 6) // 7)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
