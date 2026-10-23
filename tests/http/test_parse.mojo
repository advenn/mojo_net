"""`http.parse`: the head parser rule by rule (request strictness, response
leniencies, limits and the statuses they map to), incremental input, and
head encoding. tests/http/test_parse_fuzz.mojo checks the same rules
against an independent Python implementation on mutated inputs."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from http.headers import Headers, is_field_byte, is_tchar
from http.parse import (
    E_BARE_LF,
    E_FIELD_LINE,
    E_FIELD_VALUE,
    E_HEAD_TOO_LARGE,
    E_LEADING_WS,
    E_OBS_FOLD,
    E_REQUEST_LINE,
    E_START_LINE_TOO_LONG,
    E_STATUS_LINE,
    E_TOO_MANY_FIELDS,
    HeadParser,
    Limits,
    RequestHead,
    ResponseHead,
    _V,
    _first,
    _lf_b,
    _lf_v,
    _not_target_b,
    _not_target_v,
    _tchar_mask,
    _value_class,
)
from http.types import Version
from linux import ErrorKind, IoError


def _b(text: StringSlice) -> List[UInt8]:
    """`text` encoded as Latin-1, so "\\xff" is the byte 0xFF, as in a
    Python bytes literal (a Mojo literal's "\\xff" is the code point U+00FF,
    two bytes in UTF-8). Raw UTF-8 is written byte by byte: "\\xc3\\xa9"."""
    var out = List[UInt8]()
    for c in text.codepoints():
        var v = Int(c.to_u32())
        if v > 255:
            out.append(UInt8(0x3F))  # "?": not Latin-1, never used here
        else:
            out.append(UInt8(v))
    return out^


def _req(text: StringSlice, limits: Limits = Limits()) raises -> RequestHead:
    """Parse a complete request head that is all of `text`."""
    var p = HeadParser.for_requests(limits)
    var head = RequestHead()
    var d = _b(text)
    var n = p.request(Span(d), head)
    assert_equal(n.value(), len(d))
    return head^


def _resp(text: StringSlice) raises -> ResponseHead:
    var p = HeadParser.for_responses()
    var head = ResponseHead()
    var d = _b(text)
    var n = p.response(Span(d), head)
    assert_equal(n.value(), len(d))
    return head^


def _req_outcome(data: List[UInt8], limits: Limits = Limits()) -> String:
    """"more", "ok <consumed>", or "<status> <op>"."""
    var p = HeadParser.for_requests(limits)
    var head = RequestHead()
    try:
        var n = p.request(Span(data), head)
        if not n:
            return "more"
        return String("ok ", n.value())
    except e:
        if e.kind != ErrorKind.InvalidData:
            return String("unexpected kind ", e.kind)
        return String(p.error_status(), " ", e.op)


def _resp_outcome(data: List[UInt8], limits: Limits = Limits()) -> String:
    var p = HeadParser.for_responses(limits)
    var head = ResponseHead()
    try:
        var n = p.response(Span(data), head)
        if not n:
            return "more"
        return String("ok ", n.value())
    except e:
        return String(p.error_status(), " ", e.op)


def _rq(text: StringSlice) -> String:
    return _req_outcome(_b(text))


def _rs(text: StringSlice) -> String:
    return _resp_outcome(_b(text))


def _bad(op: StaticString) -> String:
    return String("400 ", op)


# ---- byte classes -----------------------------------------------------------------


def test_vector_byte_classes_match_the_scalar_ones() raises:
    # Every byte value through each SIMD predicate the scans use, at every
    # lane, against the scalar definition.
    for base in range(0, 256, 32):
        var v = _V()
        for i in range(32):
            v[i] = UInt8(base + i)
        var tm = _tchar_mask(v)
        var nt = _not_target_v(v)
        var lf = _lf_v(v)
        for i in range(32):
            var b = UInt8(base + i)
            assert_equal(tm[i], is_tchar(b), String("tchar ", base + i))
            assert_equal(nt[i], _not_target_b(b), String("target ", base + i))
            assert_equal(lf[i], _lf_b(b), String("lf ", base + i))
    # _value_class against is_field_byte, in short and long buffers
    for n in [8, 40]:
        for i in range(256):
            var d = List[UInt8](length=n, fill=0x61)
            d[n // 2] = UInt8(i)
            var want = -1 if not is_field_byte(UInt8(i)) else (1 if i >= 0x80 else 0)
            assert_equal(_value_class(Span(d), 0, n), want, String(n, " ", i))
            assert_equal(_value_class(Span(d), 0, n // 2), 0)  # range excludes it


def test_scans_stay_inside_their_range() raises:
    # Matches outside [lo, hi) are ignored, also in the shifted last block.
    var d = List[UInt8](length=70, fill=0x61)
    d[10] = 10
    d[65] = 10
    assert_equal(_first[_lf_v, _lf_b](Span(d), 0, 70), 10)
    assert_equal(_first[_lf_v, _lf_b](Span(d), 0, 10), 10)  # none before 10: hi
    assert_equal(_first[_lf_v, _lf_b](Span(d), 11, 70), 65)
    assert_equal(_first[_lf_v, _lf_b](Span(d), 11, 60), 60)
    assert_equal(_first[_lf_v, _lf_b](Span(d), 66, 70), 70)
    assert_equal(_first[_lf_v, _lf_b](Span(d), 70, 70), 70)
    var small = List[UInt8](length=5, fill=0x61)  # under one block: scalar
    small[3] = 10
    assert_equal(_first[_lf_v, _lf_b](Span(small), 0, 5), 3)
    assert_equal(_first[_lf_v, _lf_b](Span(small), 0, 3), 3)
    d[60] = 0
    assert_equal(_value_class(Span(d), 40, 60), 0)  # bad byte at hi: outside
    assert_equal(_value_class(Span(d), 40, 61), -1)


# ---- requests -------------------------------------------------------------------


def test_request_line_and_fields() raises:
    var h = _req("GET /index.html?q=1&r=%20 HTTP/1.1\r\nHost: example.com\r\nAccept:  */* \t\r\nX-Empty:\r\n\r\n")
    assert_equal(h.method, "GET")
    assert_equal(h.target, "/index.html?q=1&r=%20")
    assert_true(h.version == Version.HTTP_1_1)
    assert_equal(len(h.headers), 3)
    assert_equal(String(h.headers.get("host").value()), "example.com")
    assert_equal(String(h.headers.get("accept").value()), "*/*")
    assert_equal(String(h.headers.get("x-empty").value()), "")
    assert_equal(String(h.headers.name(0)), "Host")  # case kept
    var o = _req("OPTIONS * HTTP/1.0\r\n\r\n")
    assert_equal(o.target, "*")
    assert_true(o.version == Version.HTTP_1_0)
    assert_equal(len(o.headers), 0)
    var c = _req("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    assert_equal(c.target, "example.com:443")
    var x = _req("M-SEARCH http://h:80/a HTTP/1.1\r\n\r\n")  # any token
    assert_equal(x.method, "M-SEARCH")
    var v = _req("GET / HTTP/2.0\r\n\r\n")  # any digit pair parses; servers decide
    assert_equal(v.version.major, 2)


def test_bytes_after_the_head_are_left_alone() raises:
    var two = _b("POST /a HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyGET /b HTTP/1.1\r\n\r\n")
    var p = HeadParser.for_requests()
    var head = RequestHead()
    var n = p.request(Span(two), head).value()
    assert_equal(n, 18 + 19 + 2)  # request line, Content-Length, blank line
    assert_equal(String(head.headers.get("content-length").value()), "4")
    # the parser is ready for the next head (after the caller skips the body)
    var m = p.request(Span(two)[n + 4 :], head).value()
    assert_equal(m, len(two) - n - 4)
    assert_equal(head.target, "/b")
    assert_equal(len(head.headers), 0)  # the previous fields were cleared


def test_leading_empty_lines_are_skipped() raises:
    assert_equal(_rq("\r\n\r\nGET / HTTP/1.1\r\n\r\n"), "ok 22")
    assert_equal(_rq("\nGET / HTTP/1.1\r\n\r\n"), _bad(E_BARE_LF))
    assert_equal(_rs("\r\n\nHTTP/1.1 200 OK\r\n\r\n"), "ok 22")


def test_incomplete_input_returns_none_at_every_cut() raises:
    var full = _b("GET /x HTTP/1.1\r\nHost: a\r\nX: y\r\n\r\n")
    var p = HeadParser.for_requests()  # one parser, growing input
    var head = RequestHead()
    for k in range(len(full)):
        assert_false(p.request(Span(full)[0:k], head), String("cut ", k))
        assert_equal(p._scanned, k)  # resumes, never rescans
    assert_equal(p.request(Span(full), head).value(), len(full))
    assert_equal(String(head.headers.get("x").value()), "y")
    for k in range(len(full)):  # and a fresh parser per cut
        assert_equal(_req_outcome(List[UInt8](Span(full)[0:k])), "more")


def test_scan_resumes_where_it_stopped() raises:
    # Bytes already scanned are never looked at again: overwrite some of
    # them with a blank line (callers must not do this) and a parser that
    # resumed does not see it, while one that rescanned would.
    var d = _b("GET / HTTP/1.1\r\nX: aaaaaaaa")
    var p = HeadParser.for_requests()
    var head = RequestHead()
    assert_false(p.request(Span(d), head))
    d[20] = 13
    d[21] = 10
    d[22] = 13
    d[23] = 10
    d.extend(Span(_b("bbbb")))
    assert_false(p.request(Span(d), head))
    d.extend(Span(_b("\r\n\r\n")))
    # The parse uses the scan's line boundaries too, so the planted CR LF
    # bytes are inside the X line, where a value may not hold them.
    var op = String()
    try:
        _ = p.request(Span(d), head)
    except e:
        op = String(e.op)
    assert_equal(op, String(E_FIELD_VALUE))


def test_controls_anywhere_in_long_values_are_refused() raises:
    # Values of 1..100 bytes with one bad byte at every position, so both
    # the SIMD blocks and the byte-by-byte tail see one.
    for n in [1, 31, 32, 33, 64, 100]:
        for at in range(n):
            for bad in [0x00, 0x0B, 0x0D, 0x1F, 0x7F]:
                var d = _b("GET / HTTP/1.1\r\nX: ")
                for i in range(n):
                    d.append(UInt8(bad) if i == at else UInt8(0x61))
                d.extend(Span(_b("\r\n\r\n")))
                assert_equal(_req_outcome(d), _bad(E_FIELD_VALUE), String(n, " ", at, " ", bad))
        var ok = _b("GET / HTTP/1.1\r\nX: ")
        for i in range(n):
            ok.append(UInt8(0x61 + i % 26))
        ok.append(9)  # HTAB inside a value is fine
        ok.append(0x62)
        ok.extend(Span(_b("\r\n\r\n")))
        assert_equal(_req_outcome(ok), String("ok ", len(ok)))


def test_request_line_errors() raises:
    var bad = [
        "GET  / HTTP/1.1",  # two spaces
        "GET / HTTP/1.1 ",  # trailing space
        "GET /  HTTP/1.1",
        "GET\t/ HTTP/1.1",
        " GET / HTTP/1.1",
        "GET / http/1.1",  # case-sensitive name
        "GET / HTTP/1.10",
        "GET / HTTP/1",
        "GET / HTTP/a.1",
        "GET / HTTP/1.1x",
        "GET / HTTP/1,1",
        "GET /",
        "GET",
        "/ HTTP/1.1",
        "G(T / HTTP/1.1",
        "GET /a\x7fb HTTP/1.1",
        "GET /\xc3\xa9 HTTP/1.1",  # raw UTF-8 in the target
        "GET /a\x00 HTTP/1.1",
        "GET /\r HTTP/1.1",  # bare CR
        "GET /a\tb HTTP/1.1",
    ]
    for line in bad:
        assert_equal(_rq(String(line) + "\r\n\r\n"), _bad(E_REQUEST_LINE), repr(line))


def test_field_line_errors() raises:
    var cases: List[Tuple[String, String]] = [
        ("Host : x", _bad(E_FIELD_LINE)),  # whitespace before the colon
        ("Host\t: x", _bad(E_FIELD_LINE)),
        (": x", _bad(E_FIELD_LINE)),
        ("Host x", _bad(E_FIELD_LINE)),
        ("Ho st: x", _bad(E_FIELD_LINE)),
        ("H\xc3\xa9: x", _bad(E_FIELD_LINE)),
        ("Host:\rx", _bad(E_FIELD_VALUE)),  # bare CR
        ("X: a\x00b", _bad(E_FIELD_VALUE)),
        ("X: a\x7fb", _bad(E_FIELD_VALUE)),
        ("X: \x01", _bad(E_FIELD_VALUE)),
        ("X: a\x1bb", _bad(E_FIELD_VALUE)),
        ("X: a\r", _bad(E_FIELD_VALUE)),  # CR CR LF: one CR is content
    ]
    for c in cases:
        var text = String("GET / HTTP/1.1\r\n", c[0], "\r\n\r\n")
        assert_equal(_rq(text), c[1], repr(c[0]))
    # obs-text that is not UTF-8 is a valid value
    var raw = _b("GET / HTTP/1.1\r\nX: \xff\xfe\r\n\r\n")
    assert_equal(_req_outcome(raw), String("ok ", len(raw)))
    var p = HeadParser.for_requests()
    var head = RequestHead()
    _ = p.request(Span(raw), head)
    var v = head.headers.get_bytes("x").value()
    assert_equal(len(v), 2)
    assert_equal(Int(v[0]), 0xFF)


def test_request_line_endings_and_folding_are_strict() raises:
    assert_equal(_rq("GET / HTTP/1.1\nHost: x\r\n\r\n"), _bad(E_BARE_LF))
    assert_equal(_rq("GET / HTTP/1.1\r\nHost: x\n\r\n"), _bad(E_BARE_LF))
    assert_equal(_rq("GET / HTTP/1.1\r\nHost: x\r\n\n"), _bad(E_BARE_LF))
    assert_equal(_rq("GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n"), _bad(E_OBS_FOLD))
    assert_equal(_rq("GET / HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n"), _bad(E_OBS_FOLD))
    assert_equal(_rq("GET / HTTP/1.1\r\n Host: x\r\n\r\n"), _bad(E_LEADING_WS))
    assert_equal(_rq("GET / HTTP/1.1\r\n\tHost: x\r\n\r\n"), _bad(E_LEADING_WS))


# ---- limits ---------------------------------------------------------------------


def test_start_line_limit_maps_to_414() raises:
    var lim = Limits(max_start_line=20)
    var line = String("GET /") + "a" * 6 + " HTTP/1.1"  # exactly 20
    assert_equal(_req_outcome(_b(line + "\r\n\r\n"), lim), "ok 24")
    var long = String("GET /") + "a" * 7 + " HTTP/1.1"  # 21
    assert_equal(_req_outcome(_b(long + "\r\n\r\n"), lim), String("414 ", E_START_LINE_TOO_LONG))
    # decided when the line ends, so a long line without its LF waits...
    assert_equal(_req_outcome(_b(String("GET /") + "a" * 100), lim), "more")
    # ...until max_head says otherwise
    var tight = Limits(max_head=64, max_start_line=20)
    assert_equal(_req_outcome(_b(String("GET /") + "a" * 100), tight), String("431 ", E_HEAD_TOO_LARGE))


def test_head_limit_maps_to_431() raises:
    var head = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"  # 27 bytes
    assert_equal(_req_outcome(_b(head), Limits(max_head=27)), "ok 27")
    assert_equal(_req_outcome(_b(head), Limits(max_head=26)), String("431 ", E_HEAD_TOO_LARGE))
    # incomplete input is refused as soon as it reaches max_head
    var part = _b("GET / HTTP/1.1\r\nHost: xxxxxxxx")
    assert_equal(_req_outcome(part, Limits(max_head=len(part) + 1)), "more")
    assert_equal(_req_outcome(part, Limits(max_head=len(part))), String("431 ", E_HEAD_TOO_LARGE))
    # leading empty lines count
    assert_equal(_req_outcome(_b(String("\r\n") * 10 + head), Limits(max_head=40)), String("431 ", E_HEAD_TOO_LARGE))


def test_field_count_limit_maps_to_431() raises:
    var text = String("GET / HTTP/1.1\r\n")
    for i in range(4):
        text += String("X-", i, ": v\r\n")
    text += "\r\n"
    assert_true(_req_outcome(_b(text), Limits(max_fields=4)).startswith("ok"))
    assert_equal(_req_outcome(_b(text), Limits(max_fields=3)), String("431 ", E_TOO_MANY_FIELDS))
    assert_true(_req_outcome(_b("GET / HTTP/1.1\r\n\r\n"), Limits(max_fields=0)).startswith("ok"))


def test_limit_errors_do_not_depend_on_the_split() raises:
    # A long start line that would be 414 alone, in a head that also
    # crosses max_head: whichever limit the bytes cross first wins, the
    # same however they arrive.
    var lim = Limits(max_head=40, max_start_line=10)
    var cases = [
        String("GET /") + "a" * 50 + " HTTP/1.1\r\n\r\n",  # its LF is past max_head: 431
        String("GET /") + "a" * 10 + " HTTP/1.1\r\n\r\n",  # LF within max_head: 414
        String("GET / HTTP/1.1\r\n") + "X: y\r\n" * 10,  # 431, never complete
        String("GET / HTTP/1.1\nX: y\r\n\r\n"),  # bare LF: 400
    ]
    for c in cases:
        var d = _b(c)
        var whole = _req_outcome(d, lim)
        var p = HeadParser.for_requests(lim)
        var head = RequestHead()
        var got = String("more")
        for k in range(1, len(d) + 1):
            try:
                var n = p.request(Span(d)[0:k], head)
                if n:
                    got = String("ok ", n.value())
                    break
            except e:
                got = String(p.error_status(), " ", e.op)
                break
        assert_equal(got, whole, c)
        assert_false(whole == "more")


# ---- responses ------------------------------------------------------------------


def test_status_lines() raises:
    var r = _resp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
    assert_equal(r.status, 200)
    assert_equal(r.reason, "OK")
    assert_true(r.version == Version.HTTP_1_1)
    assert_equal(_resp("HTTP/1.0 404 Not Found\r\n\r\n").reason, "Not Found")
    assert_equal(_resp("HTTP/1.1 204 \r\n\r\n").reason, "")
    assert_equal(_resp("HTTP/1.1 204\r\n\r\n").reason, "")  # SP missing: tolerated
    assert_equal(_resp("HTTP/1.1 200 Fine  thanks \r\n\r\n").reason, "Fine  thanks ")
    assert_equal(_resp("HTTP/1.1 599 x\r\n\r\n").status, 599)
    assert_equal(_resp("HTTP/1.1 100 Continue\r\n\r\n").status, 100)
    assert_equal(_resp("HTTP/1.1 200 \xe9t\xe9\r\n\r\n").reason, "�t�")  # lossy
    var bad = [
        "HTTP/1.1 099 x",
        "HTTP/1.1 600 x",
        "HTTP/1.1 20 x",
        "HTTP/1.1 2000 x",
        "HTTP/1.1 2x0 x",
        "HTTP/1.1  200 x",
        "http/1.1 200 OK",
        "HTTP/1.1 200 O\x01K",
        "HTTP/1.1 200 O\rK",
        "HTTP/11 200 OK",
        "HTTP/1.1",
        "HTTP/1.1 200OK",
    ]
    for line in bad:
        assert_equal(_rs(String(line) + "\r\n\r\n"), _bad(E_STATUS_LINE), repr(line))


def test_obs_text_values_get_both_views() raises:
    # Latin-1 bytes in a parsed value: exact bytes, and a lossy string.
    var r = _resp("HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"r\xe9sum\xe9.txt\"\r\nX: caf\xc3\xa9\r\n\r\n")
    var raw = r.headers.get_bytes("content-disposition").value()
    assert_equal(len(raw), 33)
    assert_equal(Int(raw[23]), 0xE9)
    assert_equal(String(r.headers.get("content-disposition").value()), "attachment; filename=\"r\ufffdsum\ufffd.txt\"")
    assert_equal(String(r.headers.get("x").value()), "café")  # valid UTF-8 stays as is
    var f = _resp("HTTP/1.1 200 OK\r\nX: a\xff\r\n b\r\n\r\n")  # folded, then lossy
    assert_equal(String(f.headers.get("x").value()), "a\ufffd b")


def test_response_leniencies() raises:
    var r = _resp("HTTP/1.1 200 OK\nX: a\nY: b\r\n\n")
    assert_equal(String(r.headers.get("x").value()), "a")
    assert_equal(String(r.headers.get("y").value()), "b")
    var f = _resp("HTTP/1.1 200 OK\r\nX: a\r\n  b \r\n\tc\r\nY: d\r\n\r\n")
    assert_equal(String(f.headers.get("x").value()), "a b c")
    assert_equal(String(f.headers.get("y").value()), "d")
    assert_equal(len(f.headers), 2)
    var g = _resp("HTTP/1.1 200 OK\r\nX:\r\n b\r\n \r\n\r\n")  # empty pieces add nothing
    assert_equal(String(g.headers.get("x").value()), "b")
    # the rest stays strict
    assert_equal(_rs("HTTP/1.1 200 OK\r\n X: a\r\n\r\n"), _bad(E_LEADING_WS))
    assert_equal(_rs("HTTP/1.1 200 OK\r\nX : a\r\n\r\n"), _bad(E_FIELD_LINE))
    assert_equal(_rs("HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n"), _bad(E_FIELD_VALUE))
    assert_equal(_rs("HTTP/1.1 200 OK\r\nX: a\r\n b\x00\r\n\r\n"), _bad(E_FIELD_VALUE))


# ---- encoding -------------------------------------------------------------------


def test_heads_encode_and_parse_back() raises:
    var rq = RequestHead("PATCH", "/items/7?x=1")
    rq.headers.add("Host", "api.example")
    rq.headers.add("Content-Length", "2")
    var out = ByteBuffer()
    rq.encode(out)
    var wire = String(from_utf8_lossy=out.readable_span())
    assert_equal(wire, "PATCH /items/7?x=1 HTTP/1.1\r\nHost: api.example\r\nContent-Length: 2\r\n\r\n")
    assert_equal(rq.encoded_len(), len(out))
    assert_equal(String(rq), wire)
    var back = _req(wire)
    assert_equal(back.method, "PATCH")
    assert_equal(back.target, "/items/7?x=1")
    assert_equal(String(back.headers), String(rq.headers))
    var rs = ResponseHead(404, "Not Found", Version.HTTP_1_0)
    rs.headers.add("Content-Type", "text/plain")
    var o2 = ByteBuffer()
    rs.encode(o2)
    var w2 = String(from_utf8_lossy=o2.readable_span())
    assert_equal(w2, "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\n\r\n")
    assert_equal(rs.encoded_len(), len(o2))
    var rb = _resp(w2)
    assert_equal(rb.status, 404)
    assert_equal(rb.reason, "Not Found")
    var o3 = ByteBuffer()
    ResponseHead(204).encode(o3)
    assert_equal(String(from_utf8_lossy=o3.readable_span()), "HTTP/1.1 204 \r\n\r\n")


def test_encode_refuses_invalid_heads() raises:
    var kinds = List[String]()
    var heads = [
        RequestHead("GE T", "/"),
        RequestHead("GET", "/a b"),
        RequestHead("GET", ""),
        RequestHead("GET", "/\r\nX: injected"),
        RequestHead("", "/"),
        RequestHead("GET", "/", Version(10, 1)),
    ]
    for i in range(len(heads)):
        var out = ByteBuffer()
        try:
            heads[i].encode(out)
        except e:
            kinds.append(String(e.kind))
        assert_equal(len(out), 0)
    var resps = [ResponseHead(99), ResponseHead(600), ResponseHead(200, "OK\r\nX: y")]
    for i in range(len(resps)):
        var out = ByteBuffer()
        try:
            resps[i].encode(out)
        except e:
            kinds.append(String(e.kind))
        assert_equal(len(out), 0)
    assert_equal(len(kinds), 9)
    for k in kinds:
        assert_equal(k, "InvalidInput")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
