"""10,000 server connections in one process, and its resident memory
stays flat (T2's leak gate): completed handshakes with data and a clean
close, connections dropped mid-handshake, and connections failed by a
damaged byte, each a fresh `TlsClient` and `TlsServer` on shared
contexts. MOJO_NET_TLS_LEAK_ROUNDS=<n> runs another number, and
MOJO_NET_TLS_LEAK_RSS=0 skips the resident check (tools/check_tls_asan.sh:
ASan keeps freed memory in quarantine, and LeakSanitizer checks there)."""

from std.os import getenv
from std.testing import TestSuite, assert_true

from bytes.buffer import ByteBuffer
from linux.fs import read_file
from tls import ClientContext, ServerContext, TlsClient, TlsEventKind, TlsServer
from tls_util import serving, trusting

comptime _GROWTH = 16 * 1024 * 1024
"""Resident growth allowed after the warm-up: a leak of 1.6 KiB a
connection would pass it."""


def _resident() raises -> Int:
    """Resident bytes (/proc/self/statm's second field, in pages)."""
    var text = String(from_utf8_lossy=Span(read_file("/proc/self/statm", "statm")))
    var fields = text.split(" ")
    return atol(fields[1]) * 4096


def _connection(i: Int, cctx: ClientContext, sctx: ServerContext) raises:
    var c = TlsClient(cctx, "localhost")
    var s = TlsServer(sctx)
    var a = ByteBuffer()
    var b = ByteBuffer()
    var mode = i % 3  # 0: whole, 1: dropped mid-handshake, 2: damaged
    for step in range(12):
        _ = c.poll_transmit(a)
        if len(a) > 0:
            if mode == 2 and step == 2:
                var bytes = List[UInt8](a.readable_span())
                bytes[len(bytes) // 2] ^= 0x10
                a.clear()
                a.write_bytes(Span(bytes))
            try:
                s.feed(a.readable_span())
            except:
                pass
            a.clear()
        if mode == 1 and step == 1:
            return  # (both dropped: their destructors free everything)
        try:
            _ = s.poll_transmit(b)
        except:
            pass
        if len(b) > 0:
            try:
                c.feed(b.readable_span())
            except:
                pass
            b.clear()
        try:
            while True:
                var ev = c.next_event()
                if not ev:
                    break
                if ev.value().kind == TlsEventKind.ESTABLISHED:
                    _ = c.write("GET / HTTP/1.1\r\n\r\n".as_bytes())
                elif ev.value().kind == TlsEventKind.DATA:
                    c.close()
        except:
            pass
        try:
            while True:
                var ev = s.next_event()
                if not ev:
                    break
                if ev.value().kind == TlsEventKind.DATA:
                    _ = s.write("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".as_bytes())
                    s.close()
        except:
            pass


def test_ten_thousand_connections_leave_memory_flat() raises:
    var rounds = 10000
    if getenv("MOJO_NET_TLS_LEAK_ROUNDS").byte_length() > 0:
        rounds = atol(getenv("MOJO_NET_TLS_LEAK_ROUNDS"))
    var cctx = trusting()
    var sctx = serving(alpn=[])
    for i in range(300):  # (warm-up: allocator pools, OpenSSL's caches)
        _connection(i, cctx, sctx)
    var before = _resident()
    for i in range(rounds):
        _connection(i, cctx, sctx)
    var after = _resident()
    print(String("    note: ", rounds, " connections: resident ", before // 1024, " KiB before, ", after // 1024, " KiB after"))
    if getenv("MOJO_NET_TLS_LEAK_RSS") == "0":
        return  # (under ASan: LeakSanitizer checks instead)
    assert_true(after - before < _GROWTH, String("grew by ", (after - before) // 1024, " KiB"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
