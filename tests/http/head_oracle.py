"""Reference HTTP/1.1 head parser for tests/http/test_parse_fuzz.mojo.

An independent implementation of the rules src/http/parse.mojo documents
(RFC 9112 2-5 plus the library's strictness and limit rules), written with
regular expressions from the ABNF, and a generator of valid heads and their
mutations. Test-only Python: src/ never uses it.

`case(seed)` returns one line,
    "<R|S>|<max_head>|<max_start_line>|<max_fields>|<input hex>|<expected>"
where R parses a request and S a response, and <expected> is
    more                                  the head is not complete
    err <status> <rule>                   rule is the parser's E_* op text
    ok <consumed> <start> <fields>        canonical, see `_canon`
"""

import random
import re

E_REQUEST_LINE = "http: bad request line"
E_STATUS_LINE = "http: bad status line"
E_FIELD_LINE = "http: bad field line"
E_FIELD_VALUE = "http: bad field value"
E_BARE_LF = "http: bare LF"
E_OBS_FOLD = "http: obs-fold"
E_LEADING_WS = "http: whitespace before the first field line"
E_START_LINE_TOO_LONG = "http: start line too long"
E_HEAD_TOO_LARGE = "http: head too large"
E_TOO_MANY_FIELDS = "http: too many field lines"

TCHAR = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]"
REQUEST_LINE = re.compile(rb"(" + TCHAR + rb"+) ([\x21-\x7e]+) HTTP/([0-9])\.([0-9])\Z")
STATUS_LINE = re.compile(rb"HTTP/([0-9])\.([0-9]) ([0-9]{3})(?: (.*))?\Z", re.S)
FIELD_LINE = re.compile(rb"(" + TCHAR + rb"+):(.*)\Z", re.S)
FIELD_BYTES = re.compile(rb"[\t\x20-\x7e\x80-\xff]*\Z")
WS = (b" ", b"\t")


def parse(data, request, max_head, max_start_line, max_fields, fields_only=False):
    """("more",) | ("err", status, rule) | ("ok", consumed, start, fields).
    `fields_only` parses a trailer section: no start line, and the first
    empty line ends it (start is then None in the result)."""
    lenient = not request
    pos = 0
    start = b"" if fields_only else None
    lines = []
    while True:
        lf = data.find(b"\n", pos)
        if lf < 0:
            if len(data) >= max_head:
                return ("err", 431, E_HEAD_TOO_LARGE)
            return ("more",)
        if lf + 1 > max_head:
            return ("err", 431, E_HEAD_TOO_LARGE)
        raw = data[pos:lf]
        if raw.endswith(b"\r"):
            content = raw[:-1]
        elif lenient:
            content = raw
        else:
            return ("err", 400, E_BARE_LF)
        if start is None:
            if content:
                if len(content) > max_start_line:
                    return ("err", 414, E_START_LINE_TOO_LONG)
                start = content
        elif not content:
            consumed = lf + 1
            break
        else:
            lines.append(content)
            if len(lines) > max_fields:
                return ("err", 431, E_TOO_MANY_FIELDS)
        pos = lf + 1

    if fields_only:
        st = None
    elif request:
        m = REQUEST_LINE.match(start)
        if not m:
            return ("err", 400, E_REQUEST_LINE)
        st = ("R", m[1], m[2], int(m[3]), int(m[4]))
    else:
        m = STATUS_LINE.match(start)
        if not m:
            return ("err", 400, E_STATUS_LINE)
        code = int(m[3])
        reason = m[4] or b""
        if not 100 <= code <= 999 or not FIELD_BYTES.match(reason):  # (600..999: treated as 5xx)
            return ("err", 400, E_STATUS_LINE)
        st = ("S", int(m[1]), int(m[2]), code, reason)

    fields = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line[:1] in WS:
            return ("err", 400, E_LEADING_WS if i == 0 else E_OBS_FOLD)
        m = FIELD_LINE.match(line)
        if not m:
            return ("err", 400, E_FIELD_LINE)
        name, value = m[1], m[2].strip(b" \t")
        if not FIELD_BYTES.match(value):
            return ("err", 400, E_FIELD_VALUE)
        i += 1
        if i < len(lines) and lines[i][:1] in WS:
            if request:
                return ("err", 400, E_OBS_FOLD)
            while i < len(lines) and lines[i][:1] in WS:
                piece = lines[i].strip(b" \t")
                if not FIELD_BYTES.match(piece):
                    return ("err", 400, E_FIELD_VALUE)
                if piece:
                    value = value + b" " + piece if value else piece
                i += 1
        fields.append((name, value))
    return ("ok", consumed, st, fields)


def _canon(result):
    if result[0] == "more":
        return "more"
    if result[0] == "err":
        return f"err {result[1]} {result[2]}"
    _, consumed, st, fields = result
    if st[0] == "R":
        start = f"{st[1].decode()}|{st[2].decode()}|{st[3]}.{st[4]}"
    else:
        reason = st[4].decode("utf-8", "replace").encode()
        start = f"{st[1]}.{st[2]}|{st[3]}|{reason.hex()}"
    body = ";".join(f"{n.decode()}={v.hex()}" for n, v in fields)
    return f"ok {consumed} {start} {body}"


# ---- generation -------------------------------------------------------------------

METHODS = [b"GET", b"POST", b"HEAD", b"OPTIONS", b"CONNECT", b"M-SEARCH", b"X"]
TARGETS = [
    b"/",
    b"/a/b?c=d&e",
    b"*",
    b"http://h:80/x",
    b"h:443",
    b"/%20x",
    b"/~user",
    b"/search?q=" + b"abcdefghij" * 7,  # long enough for the SIMD scans
]
VERSIONS = [b"1.1", b"1.1", b"1.0", b"0.9", b"2.0"]
STATUSES = [b"100", b"101", b"200", b"204", b"301", b"404", b"500", b"599", b"600", b"999"]
REASONS = [b" OK", b" ", b"", b" Not Found", b" caf\xc3\xa9", b" \xe9t\xe9", b" a\tb"]
FIELDS = [
    (b"Host", b"example.com"),
    (b"Content-Length", b"5"),
    (b"Transfer-Encoding", b"chunked"),
    (b"X-Empty", b""),
    (b"Cookie", b"a=b; c=d"),
    (b"Accept", b"*/*"),
    (b"X-Obs", b"\xff\xfe"),
    (b"set-cookie", b"id=1; Path=/"),
    (b"User-Agent", b"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"),
    (b"Accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
]
SPECIAL = b"\r\n \t:\x00\x7f\x80\xff\x01/\"()"


def _eol(rng, request):
    if not request and rng.random() < 0.2:
        return b"\n"
    return b"\r\n"


def _valid(rng, request):
    out = bytearray()
    for _ in range(rng.choice([0, 0, 0, 1, 2])):
        out += _eol(rng, request)
    if request:
        out += rng.choice(METHODS) + b" " + rng.choice(TARGETS) + b" HTTP/" + rng.choice(VERSIONS)
    else:
        out += b"HTTP/" + rng.choice(VERSIONS) + b" " + rng.choice(STATUSES) + rng.choice(REASONS)
    out += _eol(rng, request)
    if rng.random() < 0.05:
        out += rng.choice([b" ", b"\t"])  # whitespace before the first field line
    for _ in range(rng.randrange(0, 6)):
        name, value = rng.choice(FIELDS)
        if rng.random() < 0.3:
            name = bytes(c ^ 0x20 if chr(c).isalpha() and rng.random() < 0.5 else c for c in name)
        ows1 = rng.choice([b"", b" ", b"  ", b"\t"])
        ows2 = rng.choice([b"", b"", b" ", b"\t "])
        out += name + b":" + ows1 + value + ows2 + _eol(rng, request)
        if rng.random() < (0.05 if request else 0.15):  # obs-fold
            out += rng.choice([b" ", b"\t", b"  "]) + rng.choice([b"more", b"", b"x y"]) + _eol(rng, request)
    out += _eol(rng, request)
    if rng.random() < 0.5:
        out += rng.choice([b"body", b"GET / HTTP/1.1\r\n\r\n", b"\r\n", b"0\r\n\r\n"])
    return bytes(out)


def _mutate(rng, data):
    data = bytearray(data)
    for _ in range(rng.randrange(1, 4)):
        op = rng.randrange(6)
        at = rng.randrange(len(data) + 1)
        if op == 0 and data:  # replace a byte
            data[min(at, len(data) - 1)] = rng.choice(SPECIAL)
        elif op == 1:  # insert a special byte
            data[at:at] = bytes([rng.choice(SPECIAL)])
        elif op == 2 and data:  # delete a run
            del data[at : at + rng.randrange(1, 4)]
        elif op == 3:  # duplicate a run
            run = data[at : at + rng.randrange(1, 12)]
            data[at:at] = run
        elif op == 4:  # truncate
            del data[at:]
        else:  # flip case
            if data:
                i = min(at, len(data) - 1)
                if chr(data[i]).isalpha():
                    data[i] ^= 0x20
    return bytes(data)


def case(seed):
    rng = random.Random(seed)
    request = rng.random() < 0.5
    data = _valid(rng, request)
    if rng.random() < 0.6:
        data = _mutate(rng, data)
    if rng.random() < 0.3:
        max_head = rng.randrange(8, 120)
        max_start_line = rng.randrange(4, 60)
        max_fields = rng.randrange(0, 6)
    else:
        max_head, max_start_line, max_fields = 65536, 8192, 100
    expected = _canon(parse(data, request, max_head, max_start_line, max_fields))
    kind = "R" if request else "S"
    return f"{kind}|{max_head}|{max_start_line}|{max_fields}|{data.hex()}|{expected}"
