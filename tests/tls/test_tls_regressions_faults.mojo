"""Regression tests for TLS review findings that need a fault seam (built
with -D MOJO_NET_FAULTS=1; see tests/tls/test_tls_regressions.mojo)."""

from std.testing import TestSuite, assert_equal, assert_true

from linux import fault
from linux.errno import Errno
from tls import TlsEventKind
from tls.ffi import SEAM_TRANSMIT_FULL
from tls_util import CodecDriver, Peer, trusting


def test_data_written_early_keeps_its_order() raises:
    """64 KiB written before the handshake, of which the transmit queue
    takes only one record when the connection is established (the seam
    makes it full after one); then "MARK\\n" after it. The later write
    went out at once, ahead of the 48 KiB still waiting, which went only
    with the next input. Now earlier bytes go first, and `write` and
    `poll_transmit` both move them on."""
    fault.clear()
    var peer = Peer("echo")
    var d = CodecDriver(peer.port, trusting())
    var early = List[UInt8](length=65536, fill=97)  # "a"
    assert_equal(d.tls.write(Span(early)), 65536)
    fault.inject(SEAM_TRANSMIT_FULL, Errno(1), skip=1, times=1)
    d.handshake()
    var mark = List[UInt8]("MARK\n".as_bytes())
    var taken = 0
    while taken < len(mark):
        taken += d.tls.write(Span(mark)[taken:])
        d.send()
    d.send()
    var got = List[UInt8]()
    var closed = False
    while not closed:
        var ev = d.tls.next_event()
        if ev:
            if ev.value().kind == TlsEventKind.DATA:
                got.extend(Span(ev.value().data))
            closed = ev.value().kind == TlsEventKind.CLOSED
            continue
        d.send()
        if not d.receive():
            break
    var want = List[UInt8]("echo:".as_bytes())
    want.extend(Span(early))
    want.extend(Span(mark))
    assert_equal(len(got), len(want))
    assert_true(Span(got) == Span(want), "the echo is out of order")
    assert_equal(fault.calls(SEAM_TRANSMIT_FULL) > 0, True)
    _ = d^
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
