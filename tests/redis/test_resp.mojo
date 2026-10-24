"""`redis.resp`: every RESP2 and RESP3 type parsed and rendered, the
accessors, attributes, the limits (refused from the header alone),
malformed values, random values from the oracle (`resp_oracle.py`) fed in
random pieces, every split of a transcript (contract 1, rule 4), and
mutated input, which must end in values or an error, never a crash."""

from std.python import PythonObject
from std.random import random_ui64, seed
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from bytes.codec import drive_chunked
from linux import ErrorKind, IoError
from redis import Args, Kind, Limits, RespConnection, RespEvent, Value, write_command
from redis_util import expecting, give, hex, oracle, render, s, sent, unhex


def _one(server: String) raises -> String:
    """The events of a connection waiting for one reply, given `server`."""
    var c = expecting(1)
    return give(c, server)


def _value(server: String) raises -> Value:
    var c = expecting(1)
    var data = unhex(server)
    c.feed(Span(data))
    var ev = RespEvent()
    if not c.poll(ev):
        raise Error("no value")
    var v = Value()
    swap(v, ev.value)
    return v^


def _kind_of_error(server: String, which: Int) raises -> String:
    """The kind of error an accessor raises on the value (or "none")."""
    var v = _value(server)
    try:
        if which == 0:
            _ = v.int()
        elif which == 1:
            _ = v.float()
        elif which == 2:
            _ = v.bool()
        elif which == 3:
            _ = v.text()
        elif which == 4:
            _ = v.count()
        else:
            _ = v.bytes()
    except e:
        return String(e.kind)
    return "none"


def test_every_type() raises:
    var o = oracle()
    assert_equal(_one(s(o.simple("OK"))), "REPLY +OK")
    assert_equal(_one(s(o.error("ERR unknown command"))), "REPLY -ERR unknown command")
    assert_equal(_one(s(o.integer(-42))), "REPLY :-42")
    assert_equal(_one(s(o.integer(-9223372036854775808))), "REPLY :-9223372036854775808")
    assert_equal(_one(s(o.bulk('hi "x"\r\n'))), 'REPLY "hi \\"x\\"\\x0d\\x0a"')
    assert_equal(_one(s(o.bulk(""))), 'REPLY ""')
    assert_equal(_one(s(o.null())), "REPLY _")
    assert_equal(_one(s(o.null_bulk())), "REPLY _")  # (RESP2's nulls are RESP3's)
    assert_equal(_one(s(o.null_array())), "REPLY _")
    assert_equal(_one(s(o.boolean(True))), "REPLY #t")
    assert_equal(_one(s(o.double("3.141"))), "REPLY ,3.141")
    assert_equal(_one(s(o.double("-inf"))), "REPLY ,-inf")
    assert_equal(_one(s(o.big("-1234567890123456789012"))), "REPLY (-1234567890123456789012")
    assert_equal(_one(s(o.blob_error("SYNTAX invalid syntax"))), 'REPLY !"SYNTAX invalid syntax"')
    assert_equal(_one(s(o.verbatim("txt", "Some\nstring"))), 'REPLY =txt:"Some\\x0astring"')
    assert_equal(_one(s(o.array(o.integer(1), o.bulk("a"), o.array()))), 'REPLY *[:1 "a" *[]]')
    assert_equal(
        _one(s(o.map_(o.bulk("k"), o.boolean(False), o.integer(2), o.null()))), 'REPLY %{"k" #f :2 _}'
    )
    assert_equal(_one(s(o.set_(o.simple("a"), o.simple("b")))), "REPLY ~[+a +b]")
    assert_equal(_one(s(o.map_())), "REPLY %{}")
    # a push pairs with no command
    var c = RespConnection()
    assert_equal(
        give(c, s(o.push(o.bulk("message"), o.bulk("ch"), o.bulk("hi")))), 'PUSH >["message" "ch" "hi"]'
    )


def test_accessors() raises:
    var o = oracle()
    var hello = _value(
        s(
            o.map_(
                o.bulk("server"),
                o.bulk("valkey"),
                o.bulk("proto"),
                o.integer(3),
                o.bulk("modules"),
                o.array(o.map_(o.bulk("name"), o.bulk("lua"), o.bulk("args"), o.array())),
            )
        )
    )
    assert_true(hello.kind() == Kind.MAP)
    assert_equal(hello.count(), 3)
    assert_equal(hello.text(hello.get(0, "server").value()), "valkey")
    assert_equal(hello.int(hello.get(0, "proto").value()), 3)
    assert_false(Bool(hello.get(0, "nope")))
    var modules = hello.get(0, "modules").value()
    assert_equal(hello.count(modules), 1)
    var lua = hello.child(modules, 0)
    assert_equal(hello.text(hello.get(lua, "name").value()), "lua")
    assert_true(hello.kind(hello.get(lua, "args").value()) == Kind.ARRAY)  # (not "name", as long)
    assert_equal(hello.text(hello.key(0, 1)), "proto")
    assert_equal(hello.int(hello.val(0, 1)), 3)
    assert_equal(hello.next(hello.key(0, 2)), hello.val(0, 2))
    assert_equal(hello.next(modules), hello.nodes())
    # numbers across their forms: RESP2 sends doubles as bulk strings and
    # booleans as integers
    assert_equal(_value(s(o.bulk("1.5"))).float(), 1.5)
    assert_equal(_value(s(o.double("1.5"))).float(), 1.5)
    assert_true(_value(s(o.double("inf"))).float() > 1e308)
    var nan = _value(s(o.double("nan"))).float()
    assert_true(nan != nan)
    assert_equal(_value(s(o.integer(7))).float(), 7.0)
    assert_equal(_value(s(o.big("12345678901234567890123"))).float(), 1.2345678901234568e22)
    assert_equal(_value(s(o.bulk("-12"))).int(), -12)
    assert_equal(_value(s(o.boolean(True))).int(), 1)
    assert_equal(_value(s(o.big("9223372036854775807"))).int(), Int.MAX)
    assert_true(_value(s(o.integer(1))).bool())
    assert_false(_value(s(o.boolean(False))).bool())
    assert_equal(_value(s(o.integer(5))).text(), "5")
    assert_equal(_value(s(o.boolean(True))).text(), "1")
    assert_equal(_value(s(o.double("2.5"))).text(), "2.5")
    var md = _value(s(o.verbatim("mkd", "# x")))
    assert_equal(md.text(), "# x")
    assert_equal(md.format(), "mkd")
    var err = _value(s(o.error("WRONGTYPE Operation against a key")))
    assert_true(err.is_error())
    assert_equal(err.error_code(), "WRONGTYPE")
    assert_equal(err.text(), "WRONGTYPE Operation against a key")
    assert_equal(_value(s(o.blob_error("SYNTAX x"))).error_code(), "SYNTAX")
    var raw = _value("2433" + "0d0a" + "00ff0d" + "0d0a")  # $3 with NUL, 0xFF, CR
    var b = raw.bytes()
    assert_equal(len(b), 3)
    assert_equal(Int(b[1]), 255)
    # each accessor reads its own kinds
    var invalid = "InvalidData"
    assert_equal(_kind_of_error(s(o.bulk("007")), 0), invalid)  # (as INCR reads it)
    assert_equal(_kind_of_error(s(o.double("1")), 0), invalid)  # (a double is no integer)
    assert_equal(_kind_of_error(s(o.big("9223372036854775808")), 0), invalid)
    assert_equal(_kind_of_error(s(o.bulk("1e400")), 1), invalid)  # (past a Float64's range)
    assert_equal(_kind_of_error(s(o.bulk("1e-400")), 1), invalid)
    assert_equal(_kind_of_error(s(o.bulk(" 1.5")), 1), invalid)
    assert_equal(_kind_of_error(s(o.boolean(True)), 1), invalid)
    assert_equal(_kind_of_error(s(o.integer(2)), 2), invalid)
    assert_equal(_kind_of_error(s(o.null()), 3), invalid)
    assert_equal(_kind_of_error(s(o.array()), 3), invalid)
    assert_equal(_kind_of_error(s(o.integer(1)), 4), invalid)
    assert_equal(_kind_of_error(s(o.null()), 4), invalid)
    assert_equal(_kind_of_error(s(o.integer(1)), 5), invalid)
    assert_equal(_kind_of_error(s(o.bulk("0")), 0), "none")
    # node numbers out of range
    var refused = 0
    for which in range(3):
        try:
            if which == 0:
                _ = hello.text(99)
            elif which == 1:
                _ = hello.child(0, 6)
            else:
                _ = hello.kind(-1)
        except e:
            refused += Int(e.kind == ErrorKind.InvalidInput)
    assert_equal(refused, 3)


def test_attributes_are_dropped() raises:
    var o = oracle()
    # before a reply, as DEBUG PROTOCOL attrib sends one
    assert_equal(
        _one(
            s(o.attribute(o.bulk("key-popularity"), o.array(o.bulk("key:123"), o.integer(90))))
            + s(o.bulk("Some real reply"))
        ),
        'REPLY "Some real reply"',
    )
    # before an element, one inside another, and an empty one
    var inner = s(o.attribute(o.bulk("b"), o.null())) + s(o.integer(2))
    var element = s(o.attribute(o.bulk("a"), inner)) + s(o.integer(3))
    assert_equal(_one(s(o.array(o.integer(1), element))), "REPLY *[:1 :3]")
    assert_equal(_one(s(o.attribute()) + s(o.simple("OK"))), "REPLY +OK")
    # before a push, which stays a push
    var c = RespConnection()
    assert_equal(give(c, s(o.attribute(o.bulk("a"), o.integer(1))) + s(o.push(o.integer(5)))), "PUSH >[:5]")
    # a push is never inside a value
    assert_equal(_one(s(o.array(o.push(o.integer(1))))), "error InvalidData: redis: malformed reply")
    # an attribute with nothing after it is a value unfinished at EOF
    var d = expecting(1)
    assert_equal(
        give(d, s(o.attribute(o.bulk("a"), o.integer(1))), eof=True),
        "error UnexpectedEof: redis: the server closed the connection",
    )


def _limited(server: String, limits: Limits) raises -> String:
    var c = RespConnection(limits)
    c.command(Args("PING"))
    _ = sent(c)
    return give(c, server)


def test_limits_from_the_header_alone() raises:
    var small = Limits(max_bulk=10, max_elements=3, max_depth=2, max_line=64)
    var over = "error InvalidData: redis: reply over a limit"
    assert_equal(_limited(hex("$11\r\n"), small), over)  # (its bytes need not come)
    assert_equal(_limited(hex("$11\r\n01234567890\r\n"), small), over)  # (nor do they help)
    assert_equal(_limited(hex("!11\r\n"), small), over)
    assert_equal(_limited(hex("$10\r\n0123456789\r\n"), small), 'REPLY "0123456789"')
    assert_equal(_limited(hex("*4\r\n"), small), over)
    assert_equal(_limited(hex("%2\r\n"), small), over)  # (two pairs: four elements)
    assert_equal(_limited(hex("|2\r\n"), small), over)
    assert_equal(_limited(hex("*3\r\n:1\r\n:2\r\n:3\r\n"), small), "REPLY *[:1 :2 :3]")
    assert_equal(_limited(hex("*1\r\n*1\r\n*1\r\n"), small), over)  # (depth 3)
    assert_equal(_limited(hex("*1\r\n*1\r\n:1\r\n"), small), "REPLY *[*[:1]]")
    var long_line = String("+")
    for _ in range(70):
        long_line += "x"
    assert_equal(_limited(hex(long_line), small), over)  # (no CRLF yet: it can only grow)
    var fits = String("+")
    for _ in range(61):
        fits += "x"
    assert_equal(_limited(hex(fits + "\r\n"), small), String("REPLY ", fits))  # (64 bytes)
    assert_equal(_limited(hex(fits + "x\r\n"), small), over)
    # streamed values: no server sends them
    var streamed = "error Unsupported: redis: streamed RESP3 values are not supported"
    assert_equal(_one(hex("$?\r\n")), streamed)
    assert_equal(_one(hex("*?\r\n")), streamed)


def test_malformed_values() raises:
    var bad = "error InvalidData: redis: malformed reply"
    var lines: List[String] = [
        "$\r\n",
        "$01\r\n",
        "$-2\r\n",
        "$-0\r\n",
        "!-1\r\n",
        "=-1\r\n",
        "%-1\r\n",
        "~-1\r\n",
        ">-1\r\n",
        ":+5\r\n",
        ":-0\r\n",
        ":05\r\n",
        ":5x\r\n",
        ":\r\n",
        ":9223372036854775808\r\n",
        "#x\r\n",
        "#\r\n",
        "#tt\r\n",
        ",abc\r\n",
        ",1e\r\n",
        ",.\r\n",
        ", 1\r\n",
        "(1a\r\n",
        "(\r\n",
        "_x\r\n",
        "+a\rb\r\n",
        "+ok\n",
        "\r\n",
        "?\r\n",
        "$1\r\nab\r\n",
        "=3\r\ntxt\r\n",
        "=4\r\ntxt-\r\n",
        "*1\r\n>1\r\n:1\r\n",
    ]
    for line in lines:
        assert_equal(_one(hex(line)), bad, line)
    # a bulk string's CRLF is checked when its bytes came in pieces too
    var c = expecting(1)
    var ev = RespEvent()
    c.feed("$3\r\nab".as_bytes())
    assert_false(c.poll(ev))
    c.feed("cX\r\n".as_bytes())
    var refused = False
    try:
        _ = c.poll(ev)
    except e:
        refused = e.kind == ErrorKind.InvalidData
    assert_true(refused)


def _give_in_pieces(mut c: RespConnection, server_hex: StringSlice) raises -> String:
    """`give`, but each receive a random piece of 0 to 40 bytes."""
    var data = unhex(server_hex)
    var out = String()
    var ev = RespEvent()
    try:
        var at = 0
        while True:
            while c.poll(ev):
                if out.byte_length() > 0:
                    out += "|"
                out += String(ev)
            if at == len(data):
                break
            var n = min(Int(random_ui64(0, 40)), len(data) - at, c.feed_capacity())
            c.feed(Span(data)[at : at + n])
            at += n
    except e:
        if out.byte_length() > 0:
            out += "|"
        out += render(e)
    _ = ev^
    return out^


def test_random_values_against_the_oracle() raises:
    var o = oracle()
    seed(7)
    for round in range(400):
        var t = o.transcript(round, 4)
        var c = expecting(Int(py=t[2]))
        assert_equal(_give_in_pieces(c, s(t[0])), s(t[1]), String("seed ", round))
        assert_true(c.is_idle())


def _render(ev: RespEvent) -> String:
    return String(ev)


def test_events_do_not_depend_on_the_split() raises:
    var o = oracle()
    var transcript = (
        s(o.bulk("hello"))
        + s(o.push(o.bulk("x")))
        + s(o.map_(o.bulk("k"), o.array(o.integer(1), o.double("2.5"))))
        + s(o.attribute(o.bulk("a"), o.integer(1)))
        + s(o.verbatim("txt", "v"))
        + s(o.null_bulk())
    )
    var data = unhex(transcript)
    var got = drive_chunked[_render](expecting(4), Span(data))
    assert_equal(
        String("|").join(got), 'REPLY "hello"|PUSH >["x"]|REPLY %{"k" *[:1 ,2.5]}|REPLY =txt:"v"|REPLY _'
    )


def _mutate(mut data: List[UInt8]):
    """Change one to three bytes, maybe cutting the end off."""
    var specials: List[UInt8] = [13, 10, 48, 49, 45, 36, 42, 37, 124, 62, 63, 255]
    for _ in range(1 + Int(random_ui64(0, 2))):
        var at = Int(random_ui64(0, UInt64(len(data) - 1)))
        if random_ui64(0, 1) == 0:
            data[at] = specials[Int(random_ui64(0, UInt64(len(specials) - 1)))]
        else:
            data[at] = UInt8(random_ui64(0, 255))
    if random_ui64(0, 3) == 0:
        data.resize(Int(random_ui64(0, UInt64(len(data)))), 0)


def test_mutated_input_never_crashes() raises:
    var o = oracle()
    seed(11)
    var errors = 0
    for round in range(600):
        var t = o.transcript(5000 + round, 3)
        var data = unhex(s(t[0]))
        if len(data) == 0:
            continue
        _mutate(data)
        var c = expecting(Int(py=t[2]))
        var got = give(c, hex(Span(data)), eof=True)
        errors += Int(got.find("error ") >= 0)
    assert_true(errors > 100)  # (most mutants break something)


def test_large_bulk_strings_stream_through_a_small_buffer() raises:
    # a bulk value's bytes leave the input buffer as they come, so a reply
    # far larger than it is taken in pieces that fit
    var c = expecting(1)
    var size = 1 << 20
    var head = String("$", size, "\r\n")
    var data = List[UInt8]()
    data.extend(head.as_bytes())
    for i in range(size):
        data.append(UInt8(i % 251))
    data.append(13)
    data.append(10)
    var ev = RespEvent()
    var at = 0
    var got = False
    while at < len(data):
        var n = min(c.feed_capacity(), len(data) - at)
        assert_true(n > 0)
        c.feed(Span(data)[at : at + n])
        at += n
        while c.poll(ev):
            got = True
    assert_true(got)
    var b = ev.value.bytes()
    assert_equal(len(b), size)
    assert_equal(Int(b[size - 1]), (size - 1) % 251)
    assert_true(c.feed_capacity() < 256 * 1024)


def test_commands() raises:
    var o = oracle()
    var out = ByteBuffer()
    write_command(out, Args("SET", "key", 5, 2.5, "nineteen-byte-value"))
    var raw: List[UInt8] = [0, 13, 10, 255]
    var a = Args()
    a.add_text("SET")
    a.add_bytes(Span(raw))
    a.add_text("")
    write_command(out, a)
    assert_equal(s(o.commands(hex(out.readable_span()))), "SET key 5 2.5 nineteen-byte-value|SET \\x00\\x0d\\x0a\\xff ")
    # whole or not at all
    var small = ByteBuffer(max_size=16)
    var kind = String()
    try:
        write_command(small, Args("SET", "key", "a value too long"))
    except e:
        kind = String(e.kind)
    assert_equal(kind, "OutOfMemory")
    assert_equal(small.readable(), 0)
    kind = String()
    try:
        write_command(out, Args())
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidInput")


def test_what_a_real_server_sends() raises:
    # recorded from Valkey 9.1.2: DEBUG PROTOCOL <type> after HELLO 3 (and
    # the push that follows its reply), HELLO 3's reply, a transaction with
    # an error inside, and SUBSCRIBE's pushes
    var c = expecting(15)
    var recorded = (
        "$11\r\nHello World\r\n:12345\r\n,3.141\r\n(1234567999999999999999999999999999999\r\n_\r\n"
        + "*3\r\n:0\r\n:1\r\n:2\r\n~3\r\n:0\r\n:1\r\n:2\r\n%3\r\n:0\r\n#f\r\n:1\r\n#t\r\n:2\r\n#f\r\n"
        + "|1\r\n$14\r\nkey-popularity\r\n*2\r\n$7\r\nkey:123\r\n:90\r\n"
        + "$39\r\nSome real reply following the attribute\r\n"
        + "$40\r\nSome real reply following the push reply\r\n>2\r\n$16\r\nserver-cpu-usage\r\n:42\r\n"
        + "=29\r\ntxt:This is a verbatim\nstring\r\n#t\r\n#f\r\n"
        + "%7\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$7\r\nversion\r\n$5\r\n9.1.2\r\n$5\r\nproto\r\n:3\r\n"
        + "$2\r\nid\r\n:3\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n$4\r\nrole\r\n$6\r\nmaster\r\n"
        + "$7\r\nmodules\r\n*1\r\n%4\r\n$4\r\nname\r\n$3\r\nlua\r\n$3\r\nver\r\n:1\r\n$4\r\npath\r\n"
        + "$3\r\nlua\r\n$4\r\nargs\r\n*0\r\n"
        + "*2\r\n:1\r\n-ERR value is not an integer or out of range\r\n"
        + ">3\r\n$9\r\nsubscribe\r\n$2\r\nc1\r\n:1\r\n>3\r\n$11\r\nunsubscribe\r\n_\r\n:0\r\n"
    )
    var got = give(c, hex(recorded))
    var want: List[String] = [
        'REPLY "Hello World"',
        "REPLY :12345",
        "REPLY ,3.141",
        "REPLY (1234567999999999999999999999999999999",
        "REPLY _",
        "REPLY *[:0 :1 :2]",
        "REPLY ~[:0 :1 :2]",
        "REPLY %{:0 #f :1 #t :2 #f}",
        'REPLY "Some real reply following the attribute"',
        'REPLY "Some real reply following the push reply"',
        'PUSH >["server-cpu-usage" :42]',
        'REPLY =txt:"This is a verbatim\\x0astring"',
        "REPLY #t",
        "REPLY #f",
        'REPLY %{"server" "valkey" "version" "9.1.2" "proto" :3 "id" :3 "mode" "standalone" "role" "master"'
        + ' "modules" *[%{"name" "lua" "ver" :1 "path" "lua" "args" *[]}]}',
        "REPLY *[:1 -ERR value is not an integer or out of range]",
        'PUSH >["subscribe" "c1" :1]',
        'PUSH >["unsubscribe" _ :0]',
    ]
    assert_equal(got, String("|").join(want))
    assert_equal(c.pending(), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
