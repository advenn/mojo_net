"""Seeded damage between the client and a TLS server (tests/tls/tls_mitm.py;
gate TG5): a flipped bit, lost, repeated, inserted or replaced bytes, or a
cut connection, in the handshake or the data, mostly from the server.

The oracle needs no TLS knowledge: the client must never deliver data the
server did not send. Each connection either completes with exactly the
server's bytes, or fails with an error after delivering a prefix of them;
it never hangs (a deadline error fails the test), and never reports a
damaged stream as a clean end. MOJO_NET_TLS_SEEDS=<n> runs more seeds (80
by default) and MOJO_NET_TLS_SEED=<first> replays from a seed; a failure
names its seed."""

from std.os import getenv
from std.testing import TestSuite, assert_true

from linux.time import Deadline, Duration
from tls import Category, ClientContext, TlsError
from tls.stream import TlsStream
from tls_util import Peer, Proc, opts, pattern, trusting

comptime _BIG = 50000


def _run(port: Int, ctx: ClientContext, mut got: List[UInt8]) raises -> Optional[TlsError]:
    """One connection through the proxy: the error it ended with, if any."""
    try:
        var s = TlsStream.connect_deadline("127.0.0.1", UInt16(port), ctx, Deadline.after(Duration.from_secs(10)), server_name="localhost")
        s.set_deadline(Deadline.after(Duration.from_secs(10)))
        s.write_all("fuzz\n".as_bytes())
        var buf = List[UInt8](length=8192, fill=0)
        while True:
            var n = s.read(Span(buf))
            if n == 0:
                return None
            got.extend(Span(buf)[0:n])
    except e:
        return e^


def _is_prefix(got: List[UInt8], want: List[UInt8]) -> Bool:
    if len(got) > len(want):
        return False
    for i in range(len(got)):
        if got[i] != want[i]:
            return False
    return True


def test_damage_never_changes_the_data() raises:
    var seeds = 80
    var first = 1
    if getenv("MOJO_NET_TLS_SEEDS").byte_length() > 0:
        seeds = atol(getenv("MOJO_NET_TLS_SEEDS"))
    if getenv("MOJO_NET_TLS_SEED").byte_length() > 0:
        first = atol(getenv("MOJO_NET_TLS_SEED"))
    var want = List[UInt8]("echo:fuzz\n".as_bytes())
    want.extend(Span(pattern(_BIG)))
    var server = Peer("echo", opts(String("big=", _BIG), String("count=", seeds), "quiet=1"))
    var mitm = Proc(["tests/tls/tls_mitm.py", String(server.port), String(first), String(seeds)])
    var ctx = trusting()
    var clean = 0
    var failed = 0
    for _ in range(seeds):
        var got = List[UInt8]()
        var err = _run(mitm.port, ctx, got)
        var what = mitm.expect("SEED")
        if not err:
            assert_true(got == want, String(what, ": a clean end with ", len(got), " bytes that differ from the server's"))
            clean += 1
            continue
        var e = err.value().copy()
        assert_true(not e.is_deadline(), String(what, ": hung until the deadline: ", e))
        assert_true(_is_prefix(got, want), String(what, ": delivered bytes the server did not send (then ", e, ")"))
        assert_true(e.category != Category.INPUT, String(what, ": ", e))
        failed += 1
    print(String("    note: ", seeds, " seeds from ", first, ": ", clean, " complete and intact, ", failed, " failed cleanly"))
    mitm^.stop()
    server^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
