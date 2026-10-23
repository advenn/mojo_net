"""`http.headers`: the field syntax tables against the RFC 9110 grammar,
`Headers` semantics (case-insensitive lookup, order, multi-values, set in
place, remove, validation, obs-text), list elements, the wire encoding, and
a randomized run against a list-of-pairs model that also exercises arena
compaction."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from http.headers import (
    Headers,
    eq_ignore_case,
    is_field_byte,
    is_tchar,
    is_token,
    lower_ascii,
    next_element,
    trim_ows,
)
from linux import ErrorKind, IoError


def _bytes(text: StringSlice) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def _kind_of_add(mut h: Headers, name: String, value: String) -> String:
    try:
        h.add(name, value)
        return "ok"
    except e:
        return String(e.kind)


def _elements(text: StringSlice) -> String:
    var v = _bytes(text)
    var out = String()
    var pos = 0
    while True:
        var e = next_element(Span(v), pos)
        if not e:
            break
        var b = e.value()
        out += String("[", String(from_utf8_lossy=Span(v)[b.start : b.end]), "]")
    return out^


# ---- syntax tables ------------------------------------------------------------


def test_tchar_table_matches_the_rfc() raises:
    var tchars = String("!#$%&'*+-.^_`|~0123456789")
    tchars += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    var want = List[Bool](length=256, fill=False)
    for b in tchars.as_bytes():
        want[Int(b)] = True
    var count = 0
    for i in range(256):
        assert_equal(is_tchar(UInt8(i)), want[i], String("byte ", i))
        if want[i]:
            count += 1
    assert_equal(count, 77)


def test_field_byte_table_matches_the_rfc() raises:
    # field-vchar = VCHAR / obs-text, plus SP and HTAB between them.
    for i in range(256):
        var want = i == 9 or (i >= 0x20 and i <= 0x7E) or i >= 0x80
        assert_equal(is_field_byte(UInt8(i)), want, String("byte ", i))


def test_case_folding_is_ascii_only() raises:
    for i in range(256):
        var want = i + 32 if i >= 65 and i <= 90 else i
        assert_equal(Int(lower_ascii(UInt8(i))), want)
    assert_true(eq_ignore_case(Span(_bytes("Content-Length")), Span(_bytes("content-LENGTH"))))
    # '^' (0x5E) and '~' (0x7E) differ only in bit 0x20: a naive OR-0x20
    # fold would call them equal.
    assert_false(eq_ignore_case(Span(_bytes("a^")), Span(_bytes("a~"))))
    assert_false(eq_ignore_case(Span(_bytes("x@")), Span(_bytes("x`"))))
    assert_false(eq_ignore_case(Span(_bytes("ab")), Span(_bytes("abc"))))
    assert_true(is_token(Span(_bytes("X-Custom_Header.v2"))))
    assert_false(is_token(Span(_bytes(""))))
    assert_false(is_token(Span(_bytes("a b"))))
    assert_false(is_token(Span(_bytes("a:b"))))
    assert_false(is_token(Span(_bytes("é"))))


def test_trim_and_list_elements() raises:
    var v = _bytes(" \t a b\t ")
    var t = trim_ows(Span(v))
    assert_equal(t.start, 3)
    assert_equal(t.end, 6)
    assert_equal(len(trim_ows(Span(_bytes(" \t ")))), 0)
    assert_equal(_elements("a"), "[a]")
    assert_equal(_elements(" a ,b,  c "), "[a][b][c]")
    assert_equal(_elements("a, ,b,,"), "[a][b]")  # empty elements skipped
    assert_equal(_elements(", ,"), "")
    assert_equal(_elements(""), "")
    assert_equal(_elements('x="a, b", y'), '[x="a, b"][y]')
    assert_equal(_elements('"a\\", b", c'), '["a\\", b"][c]')  # quoted-pair
    assert_equal(_elements('"open, x'), '["open, x]')  # unterminated quote
    assert_equal(_elements('"\\'), '["\\]')  # backslash at the very end


# ---- Headers ------------------------------------------------------------------


def test_lookup_is_case_insensitive_and_order_preserving() raises:
    var h = Headers()
    h.add("Host", "example.com")
    h.add("Accept", "text/html")
    h.add("set-cookie", "a=1")
    h.add("Set-Cookie", "b=2")
    assert_equal(len(h), 4)
    assert_equal(String(h.get("HOST").value()), "example.com")
    assert_equal(String(h.get("accept").value()), "text/html")
    assert_false(h.get("Accept-Encoding"))
    assert_false(h.get("Hos"))
    assert_false(h.get("not a token"))
    assert_true(h.contains("SET-COOKIE"))
    assert_equal(h.count("set-COOKIE"), 2)
    assert_equal(h.count("nope"), 0)
    var all = h.get_all("Set-Cookie")
    assert_equal(len(all), 2)
    assert_equal(all[0], "a=1")
    assert_equal(all[1], "b=2")
    assert_equal(h.combined("set-cookie").value(), "a=1, b=2")
    assert_false(h.combined("nope"))
    assert_equal(h.find("set-cookie").value(), 2)
    assert_equal(h.find("set-cookie", 3).value(), 3)
    assert_false(h.find("set-cookie", 4))
    assert_equal(h.find("host", -5).value(), 0)
    # names keep the case they were given
    assert_equal(String(h.name(2)), "set-cookie")
    assert_equal(String(h.name(3)), "Set-Cookie")
    assert_equal(String(h), "Host: example.com\r\nAccept: text/html\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\n")


def test_values_are_trimmed_and_may_be_empty() raises:
    var h = Headers()
    h.add("A", " \t x  y \t")
    h.add("B", "")
    h.add("C", "   ")
    assert_equal(String(h.get("a").value()), "x  y")  # inner whitespace kept
    assert_equal(String(h.get("b").value()), "")
    assert_equal(String(h.get("c").value()), "")
    assert_equal(len(h.get_bytes("c").value()), 0)
    assert_equal(String(h), "A: x  y\r\nB: \r\nC: \r\n")


def test_invalid_names_and_values_are_refused() raises:
    var h = Headers()
    h.add("Keep", "me")
    var bad_names = ["", "a b", "a:b", "a\r", "a\nb", "(x)", "é", "a\x00", "\t"]
    for n in bad_names:
        assert_equal(_kind_of_add(h, String(n), "v"), "InvalidInput", String("name ", repr(n)))
    var bad_values = ["a\rb", "a\nb", "a\r\nX-Injected: 1", "\x00", "a\x7fb", "\x01", "x\x1fy", "\n"]
    for v in bad_values:
        assert_equal(_kind_of_add(h, "X", String(v)), "InvalidInput", String("value ", repr(v)))
    var refused = False
    try:
        h.set("Keep", "bad\r\nvalue")
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    assert_equal(len(h), 1)  # nothing changed
    assert_equal(String(h.get("keep").value()), "me")
    # obs-text that is UTF-8 is allowed, and so are all visible bytes
    h.add("Name", "naïve ~!#\"(),/:;<=>?@[\\]{}")
    assert_equal(String(h.get("name").value()), "naïve ~!#\"(),/:;<=>?@[\\]{}")


def test_set_replaces_in_place() raises:
    var h = Headers()
    h.add("A", "1")
    h.add("B", "2")
    h.add("a", "3")
    h.add("C", "4")
    h.add("A", "5")
    h.set("a", "new")
    assert_equal(String(h), "a: new\r\nB: 2\r\nC: 4\r\n")
    h.set("D", "appended")
    assert_equal(String(h), "a: new\r\nB: 2\r\nC: 4\r\nD: appended\r\n")
    h.set("b", " longer than before ")
    assert_equal(String(h), "a: new\r\nb: longer than before\r\nC: 4\r\nD: appended\r\n")


def test_remove_counts_and_keeps_the_rest_in_order() raises:
    var h = Headers()
    for name in ["X", "Y", "x", "Z", "X"]:
        h.add(String(name), "v")
    assert_equal(h.remove("x"), 3)
    assert_equal(h.remove("x"), 0)
    assert_equal(String(h), "Y: v\r\nZ: v\r\n")
    assert_equal(h.remove("nope"), 0)
    h.clear()
    assert_equal(len(h), 0)
    assert_true(h.is_empty())
    h.add("After", "clear")
    assert_equal(String(h), "After: clear\r\n")


def test_index_access_out_of_range_raises() raises:
    var h = Headers()
    h.add("A", "1")
    assert_equal(String(h.value(0)), "1")
    assert_equal(len(h.value_bytes(0)), 1)
    var kinds = List[String]()
    for i in [-1, 1, 99]:
        try:
            _ = h.name(i)
        except e:
            kinds.append(String(e.kind))
        try:
            _ = h.value(i)
        except e:
            kinds.append(String(e.kind))
        try:
            _ = h.value_bytes(i)
        except e:
            kinds.append(String(e.kind))
    assert_equal(len(kinds), 9)
    for k in kinds:
        assert_equal(k, "InvalidInput")


def test_obs_text_keeps_exact_bytes_and_a_lossy_string() raises:
    # The parser path: bytes already checked as field bytes, not UTF-8.
    var h = Headers()
    var raw = List[UInt8]()
    for b in [0x41, 0xE9, 0x42]:  # "A", Latin-1 e-acute, "B"
        raw.append(UInt8(b))
    h._push(Span(_bytes("Content-Disposition")), Span(raw))
    var exact = h.get_bytes("content-disposition").value()
    assert_equal(len(exact), 3)
    assert_equal(Int(exact[1]), 0xE9)
    assert_equal(String(h.get("content-disposition").value()), "A�B")
    assert_equal(String(h.value(0)), "A�B")
    var out = ByteBuffer()
    h.encode(out)
    var wire = out.readable_span()
    assert_equal(len(wire), 21 + 3 + 2)  # "Content-Disposition: " is 21 bytes
    assert_equal(Int(wire[22]), 0xE9)  # the exact byte goes out
    # a copy keeps both views
    var c = h.copy()
    assert_equal(Int(c.value_bytes(0)[1]), 0xE9)
    assert_equal(String(c.value(0)), "A�B")


def test_has_token() raises:
    var h = Headers()
    h.add("Connection", "keep-alive, Upgrade")
    h.add("connection", "  CLOSE ")
    h.add("Transfer-Encoding", "gzip, chunked;q=1")
    h.add("X", '"a, close", b')
    assert_true(h.has_token("connection", "close"))
    assert_true(h.has_token("CONNECTION", "upgrade"))
    assert_true(h.has_token("Connection", "Keep-Alive"))
    assert_false(h.has_token("Connection", "keep"))
    assert_false(h.has_token("Transfer-Encoding", "chunked"))  # elements compare whole
    assert_true(h.has_token("Transfer-Encoding", "gzip"))
    assert_false(h.has_token("X", "close"))  # inside a quoted string
    assert_true(h.has_token("X", "b"))
    assert_false(h.has_token("Missing", "close"))


def test_encode_writes_the_wire_format() raises:
    var h = Headers()
    h.add("Host", "a.example")
    h.add("Content-Length", "12")
    var out = ByteBuffer()
    out.write_bytes(Span(_bytes("GET / HTTP/1.1\r\n")))  # existing bytes stay
    h.encode(out)
    var want = "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 12\r\n"
    assert_equal(String(from_utf8_lossy=out.readable_span()), want)
    assert_equal(h.encoded_len(), StringSlice(want).byte_length() - 16)
    var empty = Headers()
    var o2 = ByteBuffer()
    empty.encode(o2)
    assert_equal(len(o2), 0)
    assert_equal(empty.encoded_len(), 0)
    # too small: OutOfMemory, and nothing is appended
    var small = ByteBuffer(max_size=20)
    small.write_bytes(Span(_bytes("x")))
    var kind = String()
    try:
        h.encode(small)
    except e:
        kind = String(e.kind)
    assert_equal(kind, "OutOfMemory")
    assert_equal(len(small), 1)


def test_copy_is_independent_and_compact() raises:
    var h = Headers()
    for i in range(50):
        h.add("Churn", String("value number ", i))
    _ = h.remove("churn")
    h.add("Live", "1")
    var c = h.copy()
    h.set("Live", "2")
    assert_equal(String(c.get("live").value()), "1")
    assert_equal(String(h.get("live").value()), "2")
    assert_equal(len(c._data), 5)  # "Live" + "1": no garbage copied


def test_compaction_keeps_both_views_of_obs_text() raises:
    var h = Headers()
    var raw = List[UInt8]()
    for b in [0x61, 0xFF, 0xFE, 0x62]:  # "a", two non-UTF-8 bytes, "b"
        raw.append(UInt8(b))
    h.add("Before", "1")
    h._push(Span(_bytes("X-Raw")), Span(raw))
    h.add("After", "2")
    var before = len(h._data)
    for i in range(3000):
        h.set("Churn", String("c" * 20, i))
    assert_true(len(h._data) < before + 4096 + 64)  # compacted at least once
    assert_equal(String(h.get("x-raw").value()), "a��b")
    var exact = h.get_bytes("x-raw").value()
    assert_equal(len(exact), 4)
    assert_equal(Int(exact[1]), 0xFF)
    assert_equal(Int(exact[2]), 0xFE)
    assert_equal(String(h.get("before").value()), "1")
    assert_equal(String(h.get("after").value()), "2")
    assert_equal(String(h.name(1)), "X-Raw")


def test_repeated_set_keeps_the_arena_bounded() raises:
    var h = Headers()
    h.add("Other", "x")
    var peak = 0
    for i in range(20000):
        h.set("Counter", String(i))
        peak = max(peak, len(h._data))
    assert_true(peak < 3 * 4096, String("arena grew to ", peak))
    assert_equal(String(h.get("counter").value()), "19999")
    assert_equal(String(h.get("other").value()), "x")
    assert_equal(len(h), 2)


def test_add_remove_cycles_keep_the_arena_bounded() raises:
    var h = Headers()
    h.add("Other", "x")
    var peak = 0
    for i in range(20000):
        h.add("Temp", String("temporary value ", i))
        assert_equal(h.remove("temp"), 1)
        peak = max(peak, len(h._data))
    assert_true(peak < 3 * 4096, String("arena grew to ", peak))
    assert_equal(String(h), "Other: x\r\n")


# ---- model-based --------------------------------------------------------------


struct _Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def next(mut self) -> UInt64:
        self.s += 0x9E3779B97F4A7C15
        var z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        return z ^ (z >> 31)

    def below(mut self, n: Int) -> Int:
        return Int(self.next() % UInt64(n))


def _lower(s: String) -> String:
    return s.lower()


def _random_case(name: String, mut rng: _Rng) -> String:
    var out = String()
    for b in name.as_bytes():
        var c = Int(b)
        if c >= 97 and c <= 122 and rng.below(2) == 0:
            c -= 32
        out += chr(c)
    return out^


def _check_model(h: Headers, names: List[String], values: List[String], pool: List[String]) raises:
    assert_equal(len(h), len(names))
    for i in range(len(names)):
        assert_equal(String(h.name(i)), names[i])
        assert_equal(String(h.value(i)), values[i])
    for p in pool:
        var first = -1
        var n = 0
        var joined = String()
        for i in range(len(names)):
            if _lower(names[i]) == p:
                if first < 0:
                    first = i
                else:
                    joined += ", "
                joined += values[i]
                n += 1
        assert_equal(h.count(p), n)
        if first < 0:
            assert_false(h.get(p))
            assert_false(h.combined(p))
        else:
            assert_equal(String(h.get(p).value()), values[first])
            assert_equal(h.combined(p).value(), joined)


def test_random_operations_match_a_model() raises:
    var pool: List[String] = ["host", "accept", "x-a", "x-b", "set-cookie"]
    var rng = _Rng(42)
    var h = Headers()
    var names = List[String]()
    var values = List[String]()
    for step in range(6000):
        var op = rng.below(10)
        var name = _random_case(pool[rng.below(len(pool))], rng)
        var value = String("v", step, "-", "y" * rng.below(300))
        if op < 5:
            h.add(name, value)
            names.append(name)
            values.append(value)
        elif op < 8:
            h.set(name, value)
            var lname = _lower(name)
            var first = -1
            var nn = List[String]()
            var vv = List[String]()
            for i in range(len(names)):
                if _lower(names[i]) == lname:
                    if first < 0:
                        first = len(nn)
                        nn.append(name)
                        vv.append(value)
                else:
                    nn.append(names[i])
                    vv.append(values[i])
            if first < 0:
                nn.append(name)
                vv.append(value)
            names = nn^
            values = vv^
        elif op < 9 or rng.below(20) != 0:
            var lname = _lower(name)
            var want = 0
            var nn = List[String]()
            var vv = List[String]()
            for i in range(len(names)):
                if _lower(names[i]) == lname:
                    want += 1
                else:
                    nn.append(names[i])
                    vv.append(values[i])
            assert_equal(h.remove(name), want)
            names = nn^
            values = vv^
        else:
            h.clear()
            names.clear()
            values.clear()
        _check_model(h, names, values, pool)
        if step % 500 == 0:
            var c = h.copy()
            _check_model(c, names, values, pool)
    # compaction must have run: the arena holds at most live + 4096 + one
    # value of garbage, never the sum of everything ever stored
    var live = 0
    for i in range(len(names)):
        live += names[i].byte_length() + values[i].byte_length()
    assert_true(len(h._data) < 2 * live + 2 * 4096, String("arena ", len(h._data), " for ", live, " live bytes"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
