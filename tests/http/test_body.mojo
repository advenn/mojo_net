"""`http.body`: framing decisions for requests and responses (RFC 9112
6.3), Content-Length and Transfer-Encoding parsing, chunked decoding rule
by rule (sizes, extensions, line ends, trailers, limits), Content-Length
and close-delimited bodies, end of input, and chunk encoding round trips.
tests/http/test_body_fuzz.mojo checks chunked decoding against an
independent Python decoder."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from http.body import (
    E_BARE_LF,
    E_CHUNK_DATA_END,
    E_CHUNK_EXT,
    E_CHUNK_LINE_TOO_LONG,
    E_CHUNK_SIZE,
    E_CONTENT_LENGTH,
    E_TE_AND_CL,
    E_TE_CODINGS,
    E_TE_HTTP10,
    E_TE_UNSUPPORTED,
    E_UNEXPECTED_EOF,
    BodyDecoder,
    BodyKind,
    BodyLimits,
    Framing,
    Piece,
    content_length,
    encode_chunk,
    encode_last_chunk,
    request_framing,
    response_framing,
)
from http.headers import Headers
from http.parse import E_FIELD_LINE, E_HEAD_TOO_LARGE, E_OBS_FOLD, RequestHead, ResponseHead
from http.types import Version
from linux import ErrorKind, IoError


def _b(text: StringSlice) -> List[UInt8]:
    """Latin-1, so "\\xff" is one byte (see tests/http/test_parse.mojo)."""
    var out = List[UInt8]()
    for c in text.codepoints():
        out.append(UInt8(Int(c.to_u32())))
    return out^


def _req_framing(fields: List[String], version: Version = Version.HTTP_1_1) -> String:
    """The framing of a request with `fields` ("Name: value"), or its error."""
    var head = RequestHead("POST", "/", version)
    try:
        for f in fields:
            var c = f.find(":")
            head.headers.add(f[byte=0:c], f[byte = c + 1 :])
        return String(request_framing(head))
    except e:
        return String(e.kind, " ", e.op)


def _resp_framing(
    status: Int, fields: List[String], method: StaticString = "GET", version: Version = Version.HTTP_1_1
) -> String:
    var head = ResponseHead(status, "", version)
    try:
        for f in fields:
            var c = f.find(":")
            head.headers.add(f[byte=0:c], f[byte = c + 1 :])
        return String(response_framing(head, method))
    except e:
        return String(e.kind, " ", e.op)


def _invalid(op: StaticString) -> String:
    return String("InvalidData ", op)


def _decode(
    text: StringSlice, *, lenient: Bool = False, limits: BodyLimits = BodyLimits(), step: Int = 0
) -> String:
    """Decode a chunked body from `text`, fed whole (step 0) or `step`
    bytes at a time: "ok <consumed> <body> | <trailers>", "more <body>" or
    "err <status> <op>"."""
    var data = _b(text)
    var dec = BodyDecoder(Framing(BodyKind.CHUNKED, 0), lenient=lenient, limits=limits)
    var trailers = Headers()
    var body = List[UInt8]()
    var at = 0
    var avail = len(data) if step == 0 else 0
    while True:
        if step > 0:
            avail = min(len(data), avail + step)
        while True:
            var pc: Piece
            try:
                pc = dec.decode(Span(data)[at:avail], trailers)
            except e:
                return String("err ", dec.error_status(), " ", e.op)
            body.extend(Span(data)[at + pc.start : at + pc.start + pc.len])
            at += pc.consumed
            if dec.is_done():
                return String("ok ", at, " ", String(from_utf8_lossy=Span(body)), " | ", trailers)
            if pc.consumed == 0 and pc.len == 0:
                break
        if avail == len(data):
            return String("more ", String(from_utf8_lossy=Span(body)))


def _ok_everywhere(
    text: StringSlice, body: StringSlice, trailers: StringSlice = "", *, rest: Int = 0, lenient: Bool = False
) raises:
    """`text` decodes to `body` and `trailers` (as `Headers` prints them),
    leaving its last `rest` bytes, whole and at every feed size from 1 to 9."""
    var want = String("ok ", len(_b(text)) - rest, " ", body, " | ", trailers)
    assert_equal(_decode(text, lenient=lenient), want, String(repr(text), " whole"))
    for step in range(1, 10):
        assert_equal(_decode(text, lenient=lenient, step=step), want, String(repr(text), " step ", step))


# ---- framing ----------------------------------------------------------------------


def test_request_framing() raises:
    assert_equal(_req_framing([]), "NONE")
    assert_equal(_req_framing(["Content-Length: 0"]), "LENGTH(0)")
    assert_equal(_req_framing(["Content-Length: 42"]), "LENGTH(42)")
    assert_equal(_req_framing(["Content-Length: 42, 42"]), "LENGTH(42)")
    assert_equal(_req_framing(["Content-Length: 42", "Content-Length: 42"]), "LENGTH(42)")
    assert_equal(_req_framing(["Content-Length: 007"]), "LENGTH(7)")
    assert_equal(_req_framing(["Transfer-Encoding: chunked"]), "CHUNKED")
    assert_equal(_req_framing(["transfer-encoding: Chunked"]), "CHUNKED")
    assert_equal(_req_framing(["Transfer-Encoding: chunked", "Content-Length: 5"]), _invalid(E_TE_AND_CL))
    assert_equal(_req_framing(["Content-Length: 5", "Transfer-Encoding: chunked"]), _invalid(E_TE_AND_CL))
    assert_equal(_req_framing(["Transfer-Encoding: chunked"], Version.HTTP_1_0), _invalid(E_TE_HTTP10))
    assert_equal(_req_framing(["Transfer-Encoding: gzip, chunked"]), String("Unsupported ", E_TE_UNSUPPORTED))
    assert_equal(_req_framing(["Transfer-Encoding: gzip", "Transfer-Encoding: chunked"]), String("Unsupported ", E_TE_UNSUPPORTED))
    for te in ["chunked, gzip", "chunked, chunked", "gzip", "identity", "", " , ", "chunked;q=1", "\"chunked\"", "chunked x", "gzip;level"]:
        assert_equal(_req_framing([String("Transfer-Encoding: ", te)]), _invalid(E_TE_CODINGS), te)
    assert_equal(_req_framing(["Transfer-Encoding: gzip;level=9, chunked"]), String("Unsupported ", E_TE_UNSUPPORTED))
    assert_equal(_req_framing(["Transfer-Encoding: x;a=\"q, z\", chunked"]), String("Unsupported ", E_TE_UNSUPPORTED))


def test_content_length_values() raises:
    for bad in ["+42", "-1", "4 2", "0x10", "", ",", "1e3", "42, 43", "42,,43", "1234567890123456789", "4.0", "٢"]:
        assert_equal(_req_framing([String("Content-Length: ", bad)]), _invalid(E_CONTENT_LENGTH), bad)
    assert_equal(_req_framing(["Content-Length: 42", "Content-Length: 43"]), _invalid(E_CONTENT_LENGTH))
    assert_equal(_req_framing(["Content-Length: 123456789012345678"]), "LENGTH(123456789012345678)")
    assert_equal(_req_framing(["Content-Length: 42, , 42"]), "LENGTH(42)")  # empty elements skipped
    var h = Headers()
    assert_false(content_length(h))
    h.add("Content-Length", "10")
    assert_equal(content_length(h).value(), 10)


def test_response_framing() raises:
    assert_equal(_resp_framing(200, ["Content-Length: 10"], "HEAD"), "NONE")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: chunked"], "HEAD"), "NONE")
    for s in [100, 101, 103, 199, 204, 304]:
        assert_equal(_resp_framing(s, ["Content-Length: 5"]), "NONE", String(s))
    assert_equal(_resp_framing(304, ["Transfer-Encoding: chunked"]), "NONE")
    assert_equal(_resp_framing(200, [], "CONNECT"), "TUNNEL")
    assert_equal(_resp_framing(299, ["Content-Length: 5"], "CONNECT"), "TUNNEL")
    assert_equal(_resp_framing(407, ["Content-Length: 3"], "CONNECT"), "LENGTH(3)")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: chunked"]), "CHUNKED")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: gzip, chunked"]), "CHUNKED")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: chunked", "Content-Length: 5"]), "CHUNKED")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: gzip"]), "CLOSE")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: chunked, gzip"]), "CLOSE")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: chunked"], "GET", Version.HTTP_1_0), "CLOSE")
    assert_equal(_resp_framing(200, ["Transfer-Encoding: chunked, chunked"]), _invalid(E_TE_CODINGS))
    assert_equal(_resp_framing(200, ["Transfer-Encoding: "]), _invalid(E_TE_CODINGS))
    assert_equal(_resp_framing(200, ["Content-Length: 5"]), "LENGTH(5)")
    assert_equal(_resp_framing(200, ["Content-Length: 5x"]), _invalid(E_CONTENT_LENGTH))
    assert_equal(_resp_framing(200, []), "CLOSE")
    assert_equal(_resp_framing(500, [], "POST"), "CLOSE")


# ---- chunked ----------------------------------------------------------------------


def test_chunked_bodies_decode_at_any_split() raises:
    _ok_everywhere("4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\nNEXT", "Wikipedia in\r\n\r\nchunks.", rest=4)
    _ok_everywhere("0\r\n\r\n", "")
    _ok_everywhere("a\r\n0123456789\r\n0\r\n\r\n", "0123456789")
    _ok_everywhere("A\r\n0123456789\r\n000\r\n\r\n", "0123456789")
    _ok_everywhere("0000000000000000001\r\nx\r\n0\r\n\r\n", "x")  # leading zeros
    _ok_everywhere("3;a=b;c=\"x, y\";d\r\nabc\r\n0;last\r\n\r\n", "abc")
    _ok_everywhere("3 ; a = b\t;\tc\r\nabc\r\n0\r\n\r\n", "abc")  # BWS
    _ok_everywhere("3;q=\"a\\\"b\"\r\nabc\r\n0\r\n\r\n", "abc")
    _ok_everywhere("2\r\nhi\r\n0\r\nChecksum: abc\r\nX-T:  1 \r\n\r\n", "hi", "Checksum: abc\r\nX-T: 1\r\n")


def test_chunked_errors() raises:
    assert_equal(_decode("g\r\n"), String("err 400 ", E_CHUNK_SIZE))
    assert_equal(_decode("\r\n"), String("err 400 ", E_CHUNK_SIZE))
    assert_equal(_decode(";a\r\n"), String("err 400 ", E_CHUNK_SIZE))
    assert_equal(_decode("-1\r\n"), String("err 400 ", E_CHUNK_SIZE))
    assert_equal(_decode("1000000000000000\r\n"), String("err 400 ", E_CHUNK_SIZE))  # 16 digits
    assert_equal(_decode("fffffffffffffff\r\n"), "more ")  # 15 digits: fine
    assert_equal(_decode("5\r\nhelloX\r\n"), String("err 400 ", E_CHUNK_DATA_END))
    assert_equal(_decode("5\r\nhello\rX"), String("err 400 ", E_CHUNK_DATA_END))
    assert_equal(_decode("5\nhello\r\n"), String("err 400 ", E_BARE_LF))
    assert_equal(_decode("5\r\nhello\n0\r\n\r\n"), String("err 400 ", E_CHUNK_DATA_END))
    assert_equal(_decode("0\r\n\n"), String("err 400 ", E_BARE_LF))  # the trailer section's blank line
    for ext in [";", ";=", ";a=", ";a b", ";a=\"x", ";a=\"\x7f\"", ";a=\"\\\x01\"", " ", "\t", "x", ";a;", ";a=b c", ";(a)"]:
        assert_equal(_decode(String("5", ext, "\r\nhello\r\n0\r\n\r\n")), String("err 400 ", E_CHUNK_EXT), repr(ext))
    assert_equal(_decode("0\r\nBad Name: x\r\n\r\n"), String("err 400 ", E_FIELD_LINE))
    assert_equal(_decode("0\r\nA: 1\r\n b\r\n\r\n"), String("err 400 ", E_OBS_FOLD))


def test_chunked_response_leniencies() raises:
    _ok_everywhere("5\nhello\n0\n\n", "hello", lenient=True)
    _ok_everywhere("5 \r\nhello\r\n0\t\r\n\r\n", "hello", lenient=True)  # trailing whitespace
    _ok_everywhere("0\r\nA: 1\r\n b\r\n\r\n", "", "A: 1 b\r\n", lenient=True)  # folded trailer
    assert_equal(_decode("5\r\nhello\rX", lenient=True), String("err 400 ", E_CHUNK_DATA_END))
    assert_equal(_decode("5;\r\n", lenient=True), String("err 400 ", E_CHUNK_EXT))


def test_chunk_line_and_trailer_limits() raises:
    var lim = BodyLimits(max_chunk_line=8)
    assert_equal(_decode("5;a=1234\r\nhello\r\n0\r\n\r\n", limits=lim), "ok 22 hello | ")  # exactly 8
    assert_equal(_decode("5;a=12345\r\n", limits=lim), String("err 400 ", E_CHUNK_LINE_TOO_LONG))
    # an incomplete line is refused once a CR before its LF could not save it
    assert_equal(_decode("5;a=1234\r", limits=lim), "more ")
    assert_equal(_decode("5;a=12345", limits=lim), "more ")
    assert_equal(_decode("5;a=123456", limits=lim), String("err 400 ", E_CHUNK_LINE_TOO_LONG))
    for step in range(1, 5):  # and the same whatever the split
        assert_equal(_decode("5;a=123456789\r\n", limits=lim, step=step), String("err 400 ", E_CHUNK_LINE_TOO_LONG))
    var tl = BodyLimits(max_trailers=12, max_trailer_fields=1)
    assert_equal(_decode("0\r\nA: 12345\r\n\r\n", limits=tl), "ok 15  | A: 12345\r\n")  # 12 bytes
    assert_equal(_decode("0\r\nA: 123456\r\n\r\n", limits=tl), String("err 431 ", E_HEAD_TOO_LARGE))
    assert_equal(_decode("0\r\nA: 1\r\nB: 2\r\n\r\n", limits=BodyLimits(max_trailer_fields=1)), "err 431 http: too many field lines")


def test_data_is_delivered_as_it_arrives() raises:
    # A chunk's data comes out in pieces before the chunk is complete, and
    # each piece is a range of the caller's input (no copy).
    var data = _b("a\r\n0123456789\r\n0\r\n\r\n")
    var dec = BodyDecoder(Framing(BodyKind.CHUNKED, 0), lenient=False)
    var t = Headers()
    var p1 = dec.decode(Span(data)[0:6], t)  # size line + 3 data bytes
    assert_equal(String(p1), "Piece(6, 3, 3)")
    var p2 = dec.decode(Span(data)[6:8], t)
    assert_equal(String(p2), "Piece(2, 0, 2)")
    var p3 = dec.decode(Span(data)[8:9], t)  # data, then nothing more fits in one call
    assert_equal(String(p3), "Piece(1, 0, 1)")
    var p4 = dec.decode(Span(data)[9:], t)
    assert_equal(String(p4), "Piece(4, 0, 4)")
    assert_false(dec.is_done())
    var p5 = dec.decode(Span(data)[13:], t)
    assert_equal(String(p5), "Piece(7, 0, 0)")  # CRLF, last chunk, empty trailers
    assert_true(dec.is_done())
    assert_equal(String(dec.decode(Span(data)[20:], t)), "Piece(0, 0, 0)")


# ---- other framings and the end of input ---------------------------------------------


def test_length_and_close_bodies() raises:
    var data = _b("hello worldGET / HTTP/1.1\r\n\r\n")
    var dec = BodyDecoder(Framing.of_length(11), lenient=False)
    var t = Headers()
    assert_equal(dec.remaining().value(), 11)
    var p = dec.decode(Span(data)[0:4], t)
    assert_equal(String(p), "Piece(4, 0, 4)")
    assert_equal(dec.remaining().value(), 7)
    p = dec.decode(Span(data)[4:], t)  # takes only what belongs to the body
    assert_equal(String(p), "Piece(7, 0, 7)")
    assert_true(dec.is_done())
    var zero = BodyDecoder(Framing.of_length(0), lenient=False)
    assert_true(zero.is_done())
    assert_true(BodyDecoder(Framing.none(), lenient=False).is_done())
    var close = BodyDecoder(Framing(BodyKind.CLOSE, 0), lenient=True)
    assert_equal(String(close.decode(Span(data), t)), String("Piece(", len(data), ", 0, ", len(data), ")"))
    assert_false(close.is_done())
    assert_false(close.remaining())
    close.finish()  # EOF ends it
    assert_true(close.is_done())


def test_end_of_input_before_the_body_ends() raises:
    var kinds = List[String]()
    var data = _b("5\r\nhel")
    var t = Headers()
    var chunked = BodyDecoder(Framing(BodyKind.CHUNKED, 0), lenient=False)
    _ = chunked.decode(Span(data), t)
    var length = BodyDecoder(Framing.of_length(10), lenient=False)
    _ = length.decode(Span(data), t)
    for i in range(2):
        try:
            if i == 0:
                chunked.finish()
            else:
                length.finish()
        except e:
            kinds.append(String(e.kind, " ", e.op))
    assert_equal(len(kinds), 2)
    for k in kinds:
        assert_equal(k, String("UnexpectedEof ", E_UNEXPECTED_EOF))
    var done = BodyDecoder(Framing.of_length(1), lenient=False)
    _ = done.decode(Span(data), t)
    done.finish()  # complete: no error


# ---- encoding ---------------------------------------------------------------------


def test_encoded_chunks_decode_back() raises:
    var out = ByteBuffer()
    var body = String()
    for n in [1, 9, 10, 15, 16, 17, 255, 256, 4095, 4096, 70000]:
        var piece = String()
        for i in range(n):
            piece += chr(97 + (i * 7 + n) % 26)
        encode_chunk(piece.as_bytes(), out)
        body += piece
    var empty = List[UInt8]()
    var before = len(out)
    encode_chunk(Span(empty), out)  # empty data appends nothing
    assert_equal(len(out), before)
    var t = Headers()
    t.add("Checksum", "abc")
    t.add("X-Count", "11")
    encode_last_chunk(t, out)
    var wire = String(from_utf8_lossy=out.readable_span())
    assert_true(wire.startswith("1\r\n"))
    assert_true(wire.find("\r\n11170\r\n") >= 0)  # 70000 in hex
    var got = _decode(wire)
    assert_equal(got, String("ok ", len(out), " ", body, " | Checksum: abc\r\nX-Count: 11\r\n"))
    var small = ByteBuffer(max_size=8)
    var kind = String()
    try:
        encode_chunk("123456".as_bytes(), small)  # needs 1 + 2 + 6 + 2
    except e:
        kind = String(e.kind)
    assert_equal(kind, "OutOfMemory")
    assert_equal(len(small), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
