"""Query strings, form bodies and cookies, sans-I/O:
- `percent_decode`: RFC 3986 percent-decoding, strict: a "%" not followed
  by two hex digits, or bytes that are not UTF-8, raise `InvalidData`
  (the router decodes paths the same way), rather than pass through as
  browsers' lenient decoders do, where two spellings would then mean one
  value;
- `parse_query` / `parse_form`: `name=value` pairs joined by "&" (the
  application/x-www-form-urlencoded format of a query or a POSTed form;
  "+" is a space), in order, repeated names kept, at most `limit` pairs;
- `parse_cookie`: the pairs of a request's `Cookie` field (RFC 6265 5.4),
  where a malformed pair is skipped, as browsers send what servers set;
- `SetCookie`: a `Set-Cookie` field value (RFC 6265 4.1), each part
  checked, so that no value can add an attribute or end the field.

Values come out as `String`s in `Pairs`, read by name (the first) or by
index. Lookups scan the pairs (no hash table for a client to flood), which
is why `limit` bounds them."""

from linux import ErrorKind, IoError

from .headers import is_token

comptime DEFAULT_LIMIT = 1000
"""Pairs a query or form may hold (PHP's `max_input_vars`)."""


struct Pairs(Copyable, Movable, Sized):
    """Decoded `name=value` pairs, in order."""

    var _names: List[String]
    var _values: List[String]

    def __init__(out self):
        self._names = List[String]()
        self._values = List[String]()

    def __len__(self) -> Int:
        return len(self._names)

    def get(self, name: StringSlice) -> Optional[String]:
        """The value of the first pair named `name`."""
        for i in range(len(self._names)):
            if self._names[i] == name:
                return self._values[i]
        return None

    def get_all(self, name: StringSlice) -> List[String]:
        """The values of every pair named `name`, in order."""
        var out = List[String]()
        for i in range(len(self._names)):
            if self._names[i] == name:
                out.append(self._values[i])
        return out^

    def name(self, i: Int) -> String:
        return self._names[i]

    def value(self, i: Int) -> String:
        return self._values[i]

    def _add(mut self, var name: String, var value: String):
        self._names.append(name^)
        self._values.append(value^)


@inline(.always)
def _hex(b: UInt8) -> Int:
    if b >= 48 and b <= 57:
        return Int(b) - 48
    if b >= 65 and b <= 70:
        return Int(b) - 55
    if b >= 97 and b <= 102:
        return Int(b) - 87
    return -1


def _decode(s: Span[UInt8, _], plus_is_space: Bool, op: StaticString) raises IoError -> String:
    var out = List[UInt8](capacity=len(s))
    var i = 0
    while i < len(s):
        var b = s[i]
        if b == 37:  # "%"
            var hi = _hex(s[i + 1]) if i + 1 < len(s) else -1
            var lo = _hex(s[i + 2]) if i + 2 < len(s) else -1
            if hi < 0 or lo < 0:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            out.append(UInt8(hi * 16 + lo))
            i += 3
            continue
        out.append(32 if b == 43 and plus_is_space else b)  # ("+")
        i += 1
    try:
        return String(StringSlice(from_utf8=Span(out)))
    except:
        raise IoError.of_kind(op, ErrorKind.InvalidData)


def percent_decode(text: StringSlice, plus_is_space: Bool = False) raises IoError -> String:
    """`text` with each "%XX" replaced by its byte (and "+" by a space if
    `plus_is_space`). `InvalidData` for a malformed escape, or a result
    that is not UTF-8."""
    return _decode(text.as_bytes(), plus_is_space, "http: percent_decode")


def _pairs(text: StringSlice, limit: Int, op: StaticString) raises IoError -> Pairs:
    var out = Pairs()
    var s = text.as_bytes()
    var start = 0
    while start <= len(s):
        var end = start
        while end < len(s) and s[end] != 38:  # "&"
            end += 1
        if end > start:  # (empty parts, as in "a=1&&b=2", are skipped)
            if len(out) >= limit:
                raise IoError.of_kind(op, ErrorKind.InvalidData)
            var eq = start
            while eq < end and s[eq] != 61:  # "="
                eq += 1
            var name = _decode(s[start:eq], True, op)
            var value = _decode(s[min(eq + 1, end) : end], True, op) if eq < end else String()
            out._add(name^, value^)
        start = end + 1
    return out^


def parse_query(query: StringSlice, limit: Int = DEFAULT_LIMIT) raises IoError -> Pairs:
    """The pairs of a query (`Request.query()`, without its "?"): "a=1&b=x+y"
    gives a = "1", b = "x y"; a part without "=" is a name with an empty
    value. `InvalidData` for a malformed escape, a name or value that is
    not UTF-8, or more than `limit` pairs."""
    return _pairs(query, limit, "http: parse_query")


def parse_form(body: Span[UInt8, _], limit: Int = DEFAULT_LIMIT) raises IoError -> Pairs:
    """The pairs of an application/x-www-form-urlencoded body, as
    `parse_query` reads them."""
    var text: StringSlice[body.origin]
    try:
        text = StringSlice(from_utf8=body)
    except:
        raise IoError.of_kind("http: parse_form", ErrorKind.InvalidData)
    return _pairs(text, limit, "http: parse_form")


@inline(.always)
def _cookie_octet(b: UInt8) -> Bool:
    """RFC 6265 4.1.1: US-ASCII but controls, space, DQUOTE, ",", ";" and
    backslash."""
    return b == 0x21 or (b >= 0x23 and b <= 0x2B) or (b >= 0x2D and b <= 0x3A) or (b >= 0x3C and b <= 0x5B) or (b >= 0x5D and b <= 0x7E)


def _cookie_value(v: Span[UInt8, _]) -> Bool:
    var s = v
    if len(s) >= 2 and s[0] == 34 and s[len(s) - 1] == 34:  # (DQUOTE ... DQUOTE)
        s = s[1 : len(s) - 1]
    for b in s:
        if not _cookie_octet(b):
            return False
    return True


def parse_cookie(field: StringSlice, limit: Int = DEFAULT_LIMIT) -> Pairs:
    """The pairs of a `Cookie` field's value, "a=1; b=2" (RFC 6265 5.4):
    split at ";", spaces around each pair dropped, names compared as sent.
    A pair whose name is not a token or whose value has bytes a cookie
    cannot hold is skipped, as is everything past `limit` pairs. Values
    are as sent (no percent-decoding: that is the application's own
    convention), with surrounding DQUOTEs removed."""
    var out = Pairs()
    var s = field.as_bytes()
    var start = 0
    while start < len(s) and len(out) < limit:
        var end = start
        while end < len(s) and s[end] != 59:  # ";"
            end += 1
        var a = start
        var b = end
        while a < b and (s[a] == 32 or s[a] == 9):
            a += 1
        while b > a and (s[b - 1] == 32 or s[b - 1] == 9):
            b -= 1
        var eq = a
        while eq < b and s[eq] != 61:
            eq += 1
        if eq < b and eq > a and is_token(s[a:eq]) and _cookie_value(s[eq + 1 : b]):
            var v = s[eq + 1 : b]
            if len(v) >= 2 and v[0] == 34 and v[len(v) - 1] == 34:
                v = v[1 : len(v) - 1]
            out._add(String(from_utf8_lossy=s[a:eq]), String(from_utf8_lossy=v))
        start = end + 1
    return out^


def _attribute(mut out: String, name: StaticString, value: String) raises IoError:
    """"; name=value" onto `out`, unless `value` is empty: `InvalidInput`
    for a control byte or ";" in it."""
    if value.byte_length() == 0:
        return
    for b in value.as_bytes():
        if b < 0x20 or b == 0x7F or b == 59:
            raise IoError.of_kind("http: SetCookie", ErrorKind.InvalidInput)
    out += String("; ", name, "=", value)


struct SetCookie(Copyable, Movable):
    """A `Set-Cookie` field (RFC 6265 4.1; SameSite from RFC 6265bis).
    `text()` checks every part, so no value can carry a ";" into another
    attribute, or a CR or LF into another field."""

    var name: String
    var value: String
    """Cookie octets only (encode anything else first, for example as
    base64url or with percent-encoding)."""
    var path: String
    var domain: String
    var max_age: Optional[Int]
    """Seconds; 0 or less deletes the cookie."""
    var secure: Bool
    var http_only: Bool
    var same_site: String
    """"Strict", "Lax", "None" (needs `secure`), or "" to leave it out."""

    def __init__(out self, name: StringSlice, value: StringSlice):
        self.name = String(name)
        self.value = String(value)
        self.path = String()
        self.domain = String()
        self.max_age = None
        self.secure = False
        self.http_only = False
        self.same_site = String()

    def text(self) raises IoError -> String:
        """The field value. `InvalidInput` for a name that is not a token,
        a value with bytes a cookie cannot hold, a path or domain with a
        control byte or ";", an unknown SameSite, or SameSite=None
        without Secure (browsers drop such a cookie)."""
        comptime op = "http: SetCookie"
        if self.name.byte_length() == 0 or not is_token(self.name.as_bytes()) or not _cookie_value(self.value.as_bytes()):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var out = String(self.name, "=", self.value)
        _attribute(out, "Path", self.path)
        _attribute(out, "Domain", self.domain)
        if self.max_age:
            out += String("; Max-Age=", max(self.max_age.value(), 0))
        if self.same_site.byte_length() > 0:
            if self.same_site != "Strict" and self.same_site != "Lax" and self.same_site != "None":
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
            if self.same_site == "None" and not self.secure:
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
            out += String("; SameSite=", self.same_site)
        if self.secure:
            out += "; Secure"
        if self.http_only:
            out += "; HttpOnly"
        return out^
