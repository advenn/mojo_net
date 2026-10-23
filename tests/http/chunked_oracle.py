"""Reference chunked-body decoder for tests/http/test_body_fuzz.mojo.

An independent implementation of the chunked rules src/http/body.mojo
documents (RFC 9112 7.1 plus the library's strictness and limit rules),
written with regular expressions from the ABNF; the trailer section goes
through head_oracle's field rules. Also a generator of valid chunked bodies
and their mutations. Test-only Python: src/ never uses it.

`case(seed)` returns one line,
    "<R|S>|<max_chunk_line>|<max_trailers>|<max_trailer_fields>|<input hex>|<expected>"
where R decodes a request body (strict) and S a response body (lenient),
and <expected> is
    more <body hex>                       the body is not complete
    err <status> <rule> <body hex>        the data delivered before the error
    ok <consumed> <body hex> <fields>     fields as name=value-hex;...
"""

import random
import re

import head_oracle

E_BARE_LF = "http: bare LF"
E_CHUNK_SIZE = "http: bad chunk size"
E_CHUNK_EXT = "http: bad chunk extension"
E_CHUNK_LINE_TOO_LONG = "http: chunk-size line too long"
E_CHUNK_DATA_END = "http: no line end after chunk data"

TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
QUOTED = rb'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
EXTS = rb"(?:[ \t]*;[ \t]*" + TOKEN + rb"(?:[ \t]*=[ \t]*(?:" + TOKEN + rb"|" + QUOTED + rb"))?)*"
STRICT_REST = re.compile(EXTS + rb"\Z")
LENIENT_REST = re.compile(EXTS + rb"[ \t]*\Z")
HEX = re.compile(rb"[0-9A-Fa-f]*")


def decode(data, request, max_line, max_trailers, max_fields):
    """("more", body) | ("err", status, rule, body) | ("ok", consumed, body, fields)."""
    lenient = not request
    body = bytearray()
    pos = 0
    while True:
        # chunk-size line
        lf = data.find(b"\n", pos)
        if lf < 0:
            if len(data) - pos > max_line + 1:
                return ("err", 400, E_CHUNK_LINE_TOO_LONG, bytes(body))
            return ("more", bytes(body))
        line = data[pos:lf]
        cr = line.endswith(b"\r")
        if cr:
            line = line[:-1]
        if len(line) > max_line:
            return ("err", 400, E_CHUNK_LINE_TOO_LONG, bytes(body))
        if not cr and not lenient:
            return ("err", 400, E_BARE_LF, bytes(body))
        digits = HEX.match(line).group(0)
        if not digits or len(digits.lstrip(b"0")) > 15:
            return ("err", 400, E_CHUNK_SIZE, bytes(body))
        rest = line[len(digits):]
        if not (LENIENT_REST if lenient else STRICT_REST).match(rest):
            return ("err", 400, E_CHUNK_EXT, bytes(body))
        size = int(digits, 16)
        pos = lf + 1
        if size == 0:
            r = head_oracle.parse(data[pos:], request, max_trailers, 0, max_fields, fields_only=True)
            if r[0] == "more":
                return ("more", bytes(body))
            if r[0] == "err":
                return ("err", r[1], r[2], bytes(body))
            return ("ok", pos + r[1], bytes(body), r[3])
        # chunk data, delivered as it arrives
        take = data[pos : pos + size]
        body += take
        if len(take) < size:
            return ("more", bytes(body))
        pos += size
        # the line end after the data
        if pos == len(data):
            return ("more", bytes(body))
        b = data[pos : pos + 1]
        if b == b"\n" and lenient:
            pos += 1
        elif b == b"\r":
            if pos + 1 == len(data):
                return ("more", bytes(body))
            if data[pos + 1 : pos + 2] != b"\n":
                return ("err", 400, E_CHUNK_DATA_END, bytes(body))
            pos += 2
        else:
            return ("err", 400, E_CHUNK_DATA_END, bytes(body))


def _canon(r):
    if r[0] == "more":
        return f"more {r[1].hex()}"
    if r[0] == "err":
        return f"err {r[1]} {r[2]} {r[3].hex()}"
    fields = ";".join(f"{n.decode()}={v.hex()}" for n, v in r[3])
    return f"ok {r[1]} {r[2].hex()} {fields}"


# ---- generation ------------------------------------------------------------------

EXT_PIECES = [b";a=b", b"; a = b", b";name", b';q="x y"', b';q="a\\"b"', b";x=1;y=2", b" ;z", b"\t;t=\t3"]
TRAILERS = [b"Checksum: abc", b"X-T: 1", b"Expires: Wed, 21 Oct 2015 07:28:00 GMT", b"X-Obs: \xff"]
SPECIAL = b"\r\n \t;=\"\\0aAfFgG:\x00\x7f\x80\xff"


def _eol(rng, request):
    return b"\n" if not request and rng.random() < 0.15 else b"\r\n"


def _valid(rng, request):
    out = bytearray()
    for _ in range(rng.randrange(0, 5)):
        n = rng.choice([1, 2, 5, 15, 16, 31, 33, 100, 255])
        digits = format(n, rng.choice(["x", "X"]))
        if rng.random() < 0.1:
            digits = "000" + digits
        out += digits.encode()
        if rng.random() < 0.3:
            out += rng.choice(EXT_PIECES)
        if not request and rng.random() < 0.05:
            out += b" "  # trailing whitespace: responses only
        out += _eol(rng, request)
        out += bytes(rng.randrange(256) for _ in range(n))
        out += _eol(rng, request)
    out += b"0" * rng.choice([1, 1, 1, 3])
    if rng.random() < 0.2:
        out += rng.choice(EXT_PIECES)
    out += _eol(rng, request)
    for _ in range(rng.choice([0, 0, 1, 2])):
        out += rng.choice(TRAILERS) + _eol(rng, request)
    out += _eol(rng, request)
    if rng.random() < 0.3:
        out += b"GET / HTTP/1.1\r\n\r\n"  # a pipelined message after the body
    return bytes(out)


def _mutate(rng, data):
    data = bytearray(data)
    for _ in range(rng.randrange(1, 4)):
        op = rng.randrange(5)
        at = rng.randrange(len(data) + 1)
        if op == 0 and data:
            data[min(at, len(data) - 1)] = rng.choice(SPECIAL)
        elif op == 1:
            data[at:at] = bytes([rng.choice(SPECIAL)])
        elif op == 2 and data:
            del data[at : at + rng.randrange(1, 4)]
        elif op == 3:
            data[at:at] = data[at : at + rng.randrange(1, 8)]
        else:
            del data[at:]
    return bytes(data)


def case(seed):
    rng = random.Random(seed)
    request = rng.random() < 0.5
    data = _valid(rng, request)
    if rng.random() < 0.6:
        data = _mutate(rng, data)
    if rng.random() < 0.3:
        limits = (rng.randrange(1, 24), rng.randrange(2, 60), rng.randrange(0, 3))
    else:
        limits = (4096, 16384, 100)
    expected = _canon(decode(data, request, *limits))
    kind = "R" if request else "S"
    return f"{kind}|{limits[0]}|{limits[1]}|{limits[2]}|{data.hex()}|{expected}"
