"""Regression tests for the third TLS review's findings that need a fault
seam (TR3, 2026-10-27; built with -D MOJO_NET_FAULTS=1; see
tests/tls/test_tls_review3_regressions.mojo). Each fails on the code before
its fix."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import fault
from linux.errno import Errno
from linux.consts import POLLIN
from linux.nr import SYS_sendto
from linux.poll import wait_ready
from linux.time import Deadline, Duration
from tls import Category
from tls.ffi import SEAM_CONSTRAINTS, SEAM_TRANSMIT_FULL, SEAM_VERIFIED_CHAIN, SEAM_WIPE
from tls_util import CodecDriver, Peer, connect, connect_error, opts, trusting


def test_int3_reading_works_after_a_failed_send() raises:
    """INT-3: after a send failed (the stream latches it), a read must
    still deliver what the server sent: an early answer, such as a 413
    before the server stopped reading. `read` and `try_read` sent queued
    output first, which raised the latched error, so over TLS the answer
    was lost where plain TCP returned it."""
    fault.clear()
    var peer = Peer("hello")  # ("hello", then close_notify, without reading)
    var s = connect(peer, trusting())
    fault.inject(SYS_sendto, Errno.EPIPE, times=1)
    var failed = False
    try:
        s.write_all("request\n".as_bytes())
    except:
        failed = True
    fault.clear()
    assert_true(failed, "the send did not fail")
    var buf = List[UInt8](length=64, fill=0)
    var got = List[UInt8]()
    while True:
        var n = s.read(Span(buf))
        if n == 0:
            break
        got.extend(Span(buf)[0:n])
    assert_equal(String(unsafe_from_utf8=Span(got)), "hello")
    var refused = False  # (sending stays refused: the stream is cut mid-record)
    try:
        s.write_all("more\n".as_bytes())
    except:
        refused = True
    assert_true(refused, "a send after the failed one went out")
    _ = s^
    peer^.stop()
    # The same through `try_read`, as a readiness loop (the HTTP client's
    # read after a failed send) uses it.
    var peer2 = Peer("hello")
    var s2 = connect(peer2, trusting())
    fault.inject(SYS_sendto, Errno.EPIPE, times=1)
    try:
        s2.write_all("request\n".as_bytes())
    except:
        pass
    fault.clear()
    var got2 = List[UInt8]()
    var deadline = Deadline.after(Duration.from_secs(10))
    while not deadline.is_expired():
        var n = s2.try_read(Span(buf))
        if not n:
            _ = wait_ready(s2.tcp(), Int16(POLLIN), deadline, "test")
            continue
        if n.value() == 0:
            break
        got2.extend(Span(buf)[0 : n.value()])
    assert_equal(String(unsafe_from_utf8=Span(got2)), "hello")
    _ = s2^
    peer2^.stop()


def test_ver1_unreadable_constraints_fail_closed() raises:
    """VER-1's check, when OpenSSL cannot give it the verified chain or a
    CA's name constraints, refuses the connection rather than skipping the
    check (a wildcard match: the check runs; without a seam this
    connection succeeds, see test_tls_review3_regressions.mojo)."""
    fault.clear()
    var seams: List[Int] = [SEAM_VERIFIED_CHAIN, SEAM_CONSTRAINTS]
    for seam in seams:
        var peer = Peer("echo", opts("cert=nc_wild"))
        fault.inject(seam, Errno(1), times=-1)
        var e = connect_error(peer.port, trusting(), "public.wild.test")
        var fired = fault.calls(seam)
        fault.clear()
        assert_equal(e.category, Category.UNTRUSTED, String(seam, ": ", e))
        assert_true(fired > 0, String(seam, " was not reached"))
        peer^.stop()


def test_eng3_close_sends_what_was_written_early_first() raises:
    """ENG-3: 64 KiB written before the handshake, of which the transmit
    queue takes one record at the start (the seam keeps it full until
    `close()` has been called). close_notify went out at once
    and the 48 KiB still waiting were dropped without a word, while
    `has_transmit()` stayed true with nothing to poll (TlsStream's flush
    looped on it). Now close_notify waits for the last of them."""
    fault.clear()
    var peer = Peer("sink")
    var d = CodecDriver(peer.port, trusting())
    var early = List[UInt8](length=65536, fill=97)
    assert_equal(d.tls.write(Span(early)), 65536)
    fault.inject(SEAM_TRANSMIT_FULL, Errno(1), skip=1, times=-1)  # (full until cleared)
    d.handshake()
    d.tls.close()
    fault.clear()
    for _ in range(100):
        d.send()
        if not d.tls.has_transmit():
            break
    assert_false(d.tls.has_transmit(), "output is still queued after 100 sends")
    assert_equal(peer.expect("GOT"), "GOT 65536 close_notify")
    _ = d^
    peer^.stop()


def test_eng4_delivered_plaintext_is_wiped() raises:
    """ENG-4: TlsStream kept each record's plaintext until the next one,
    then dropped it unwiped (and its last at the end), though docs/tls.md
    promised wiping (TB18). Now each is wiped before it is let go."""
    fault.clear()
    var peer = Peer("echo", opts("big=100000"))
    var s = connect(peer, trusting())
    s.write_all("x\n".as_bytes())
    var buf = List[UInt8](length=4096, fill=0)
    var got = 0
    while True:
        var n = s.read(Span(buf))
        if n == 0:
            break
        got += n
    assert_equal(got, 100000 + 7)  # ("echo:x\n", then the 100,000)
    var during = fault.calls(SEAM_WIPE)
    s^.close()
    var after = fault.calls(SEAM_WIPE)
    assert_true(during >= 100000 // 16384, String(during, " wipes while reading"))
    assert_true(after == during + 1, String(after, " after closing (", during, " before)"))
    fault.clear()
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
