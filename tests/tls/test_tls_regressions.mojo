"""Regression tests for the findings of the TLS review (TR, 2026-10-26):
two independent internal reviews, one of verification and the protocol,
one of the FFI layer and memory. Each test fails on the code before its
fix. tests/tls/test_tls_regressions_faults.mojo has those that need a
fault seam, and test_tls_regressions_hostile.mojo the one that needs a
hostile OpenSSL configuration in the process."""

from std.os import getenv
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import sleep

from linux import ErrorKind
from linux.time import Deadline, Duration
from tls import Category, ClientConfig, ClientContext, TlsClient, TlsError, TlsEventKind, Trust
from tls.client import FEED_LIMIT
from tls.consts import SSL_OP_CLEANSE_PLAINTEXT
from tls.ffi import MIN_VERSION
from tls.stream import TlsStream
from tls_util import CodecDriver, Peer, connect, opts, pattern, pki, read_error, trusting

comptime _S_SERVER = "tests/tls/s_server_peer.py"


def _failure(mut d: CodecDriver) raises -> TlsError:
    """Feed what arrives, never sending, until the codec fails."""
    var e = _until_failure(d)
    if not e:
        raise Error("the input ended without a failure")
    return e.take()


def _until_failure(mut d: CodecDriver) -> Optional[TlsError]:
    try:
        while True:
            while d.tls.next_event():
                pass
            if not d.receive():
                while d.tls.next_event():
                    pass
                return None
    except e:
        return e^


# ---- floods of records without data (both reviews' F1/F2) -------------------


def test_a_ticket_flood_fails_instead_of_running_on() raises:
    """20,000 TLS 1.3 session tickets (about 5 MB) before any data: the
    read fails once QUIET_LIMIT has arrived without data, where it used to
    read them all (and a server that kept sending would hold it past every
    deadline)."""
    var peer = Peer("hello", opts("tickets=20000"))
    var s = connect(peer, trusting())
    s.set_deadline(Deadline.after(Duration.from_secs(30)))
    var got = List[UInt8]()
    var e = read_error(s, got)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    assert_true("without any data" in String(e), String(e))
    assert_equal(len(got), 0)
    peer^.stop()


def test_a_pooled_connection_flooded_with_tickets_is_not_reused() raises:
    """`is_reusable` (a pool's check, with no deadline) on a connection
    the server floods with tickets: False within the budget, where it read
    every ticket and said True once the socket was empty (the server then
    stays quiet)."""
    var peer = Peer("stall", opts("tickets=20000"))
    var s = connect(peer, trusting())
    var reusable = True
    for _ in range(300):
        if not s.is_reusable():
            reusable = False
            break
        sleep(0.01)
    assert_false(reusable)
    peer^.stop()


def test_a_key_update_flood_fails() raises:
    """12,000 TLS 1.3 KeyUpdates that each ask for one back, while the
    client reads and never sends: the connection fails (too much input
    without data, or too much output provoked) instead of reading them
    all; s_server then quits without close_notify, which used to be the
    only failure (TRUNCATED)."""
    var peer = Peer("keyflood", opts("12000"), script=_S_SERVER)
    var d = CodecDriver(peer.port, trusting())
    d.handshake()
    var e = _failure(d)
    assert_true(e.category == Category.PROTOCOL or e.category == Category.RESOURCE, String(e))
    _ = d^
    peer^.stop()


def test_tiny_records_count_against_the_feed_room() raises:
    """40,000 one-byte records, fed without draining events: the room runs
    out after one feed's records (a feed of FEED_LIMIT holds at most about
    1,500 such records), where it took 32,768 events (one per byte of
    room) and some 3 MB of event structures."""
    var peer = Peer("drip", opts("records=40000"))
    var d = CodecDriver(peer.port, trusting())
    d.handshake()
    while d.tls.feed_capacity() > 0:
        if not d.receive():
            break
    var events = 0
    while d.tls.next_event():
        events += 1
    assert_true(events > 0 and events <= FEED_LIMIT // 16, String(events, " events held"))
    _ = d^
    peer^.stop()


# ---- trust and loading -----------------------------------------------------


def test_an_empty_ca_file_is_refused() raises:
    """`Trust.ca_file("")` meant the system roots, so an unset variable
    widened the trust to every public CA (TC2). It is now refused."""
    for i in range(2):
        var t = Trust.ca_file("") if i == 0 else Trust(String())
        var e = _build_error(ClientConfig(trust=t^))
        assert_equal(e.category, Category.INPUT, String(e))
        assert_equal(e.io.kind, ErrorKind.InvalidInput)
    _ = ClientConfig(trust=Trust.system()).build()  # (the system roots, said so)


def test_a_ca_file_with_only_a_crl_is_refused() raises:
    """A CRL is an object in the store, not a trust anchor: a file holding
    only one built a context that no handshake could pass. It is now
    refused when the context is built, as an empty file is."""
    var e = _build_error(ClientConfig(trust=Trust.ca_file(pki() + "/root.crl.pem")))
    assert_equal(e.category, Category.NO_TRUST_STORE, String(e))


def test_contexts_make_openssl_wipe_plaintext() raises:
    """SSL_OP_CLEANSE_PLAINTEXT: OpenSSL frees its read buffer after each
    idle read (RELEASE_BUFFERS), and wipes it only with this option."""
    var ctx = trusting()
    ref L = ctx._library()[]
    var options = L.SSL_CTX_get_options(ctx._ssl_ctx())
    _ = ctx  # (alive past the call: the handle alone does not keep it, which TG8 caught)
    assert_true(options & SSL_OP_CLEANSE_PLAINTEXT != 0)


def test_the_version_floor_is_3_5_9() raises:
    """TL1 asks for 3.5.9 (the advisories it fixes); the floor was 3.5.0."""
    assert_true(MIN_VERSION >= 0x30500090, String(MIN_VERSION))


def test_a_foreign_libcrypto_is_refused() raises:
    """libssl finds libcrypto.so.3 by soname, so one loaded first (here by
    LD_PRELOAD, the host's) was used in place of the one beside it, with
    its own version and trust store. Loading now refuses that."""
    var candidates: List[String] = [
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib/aarch64-linux-gnu/libcrypto.so.3",
        "/usr/lib64/libcrypto.so.3",
        "/lib64/libcrypto.so.3",
    ]
    var os = Python.import_module("os")
    var foreign = String()
    for c in candidates:
        if Bool(py=os.path.exists(c)) and String(py=os.path.realpath(c)).find(".pixi") < 0:
            foreign = c
            break
    if foreign.byte_length() == 0:
        print("    (skipped: no system libcrypto.so.3 to preload)")
        return
    var subprocess = Python.import_module("subprocess")
    var tempfile = Python.import_module("tempfile")
    var exe = String(py=os.path.join(tempfile.gettempdir(), String("foreign_crypto_app_", Int(py=os.getpid()))))
    var built = subprocess.run(
        Python.list("mojo", "build", "-I", "src", "tests/tls/foreign_crypto_app.mojo", "-o", exe),
        capture_output=True,
        text=True,
    )
    if Int(py=built.returncode) != 0:
        raise Error(String("building the app failed: ", String(py=built.stderr)))
    var env = os.environ.copy()
    _ = env.pop("LD_LIBRARY_PATH", None)  # (the app is not built with ASan: no instrumented OpenSSL for it)
    var plain = subprocess.run(Python.list(exe), capture_output=True, text=True, env=env)
    assert_equal(String(String(py=plain.stdout).strip()), "BUILT")
    env["LD_PRELOAD"] = foreign
    var preloaded = subprocess.run(Python.list(exe), capture_output=True, text=True, env=env)
    _ = os.remove(exe)
    var out = String(String(py=preloaded.stdout).strip())
    assert_true(out.startswith("REFUSED library") and "beside it" in out, out)


def _build_error(config: ClientConfig) raises -> TlsError:
    try:
        _ = config.build()
    except e:
        return e^
    raise Error("the context was built")


# ---- reuse, ordering and latching ----------------------------------------------


def test_part_of_a_record_is_not_nothing() raises:
    """A pooled connection whose server sent all of a record but its last
    byte (or a man in the middle held it back): `is_reusable` said True,
    and the record would have become the answer to the next request."""
    var peer = Peer("stale")
    var s = connect(peer, trusting())
    s.set_deadline(Deadline.after(Duration.from_secs(10)))
    s.write_all("hi\n".as_bytes())
    var buf = List[UInt8](length=64, fill=0)
    var got = String()
    while got != "echo:hi\n":
        var n = s.read(Span(buf))
        assert_true(n > 0)
        got += String(from_utf8_lossy=Span(buf)[0:n])
    assert_true(peer.expect("HELD").startswith("HELD"))
    sleep(0.2)
    assert_false(s.is_reusable())
    peer^.stop()


def test_a_bad_record_after_the_handshake_is_answered_with_an_alert() raises:
    """A record that fails authentication after the handshake: the client
    raised without telling the server why (it saw the connection end);
    now OpenSSL's alert goes out first (RFC 8446 6.2), as it does for a
    failed handshake."""
    var peer = Peer("tamper")
    var s = connect(peer, trusting())
    s.set_deadline(Deadline.after(Duration.from_secs(10)))
    s.write_all("hi\n".as_bytes())
    var got = List[UInt8]()
    var e = read_error(s, got)
    assert_equal(e.category, Category.PROTOCOL, String(e))
    var seen = peer.expect("ALERT")
    assert_true("BAD_RECORD_MAC" in seen.upper(), seen)
    peer^.stop()


def test_a_failed_send_latches() raises:
    """A send that timed out may have sent part of a record. The next
    write sent the whole record again from its start (the server then saw
    a bad record), or went on as if nothing happened; now every later
    write and close raises the first error."""
    var peer = Peer("sink", opts("delay=1.5", "rcvbuf=32768"))
    var s = connect(peer, trusting())
    s.set_write_deadline(Deadline.after(Duration.from_millis(100)))
    var first = _write_error(s, 8 * 1024 * 1024)
    assert_true(first.is_deadline(), String(first))
    s.set_write_deadline(Deadline.after(Duration.from_secs(10)))  # (the sink reads again soon)
    var again = _write_error(s, 1)
    assert_true(again.is_deadline(), String(again))
    var closing = _close_error(s^)
    assert_true(closing.is_deadline(), String(closing))
    peer^.stop()


def _write_error(mut s: TlsStream, n: Int) raises -> TlsError:
    try:
        s.write_all(Span(pattern(n)))
    except e:
        return e^
    raise Error(String("writing ", n, " bytes succeeded"))


def _close_error(var s: TlsStream) raises -> TlsError:
    try:
        s^.close()
    except e:
        return e^
    raise Error("close succeeded")


def test_data_written_early_is_sent_before_a_close() raises:
    """Plaintext written before the handshake ended goes out when the
    connection is established, and before anything is read: a server
    close_notify in the same flight as its Finished used to be read first,
    and the data was then dropped without a word. Python cannot send that
    flight, so this checks only that the data goes out; its order is in
    test_tls_regressions_faults.mojo."""
    var peer = Peer("bye")
    var d = CodecDriver(peer.port, trusting())
    var early = pattern(4000)
    assert_equal(d.tls.write(Span(early)), 4000)
    d.handshake()
    d.send()
    var closed = False
    while not closed:
        var ev = d.tls.next_event()
        if ev:
            closed = ev.value().kind == TlsEventKind.CLOSED
            continue
        if not d.receive():
            break
    d.send()
    assert_true(closed)
    assert_true(d.sent - d.hello >= 4000, String(d.sent - d.hello, " bytes sent after the ClientHello"))
    _ = d^
    peer^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
