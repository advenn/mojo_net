"""`redis.connection`: `RespConnection` pairs replies with commands in
order and keeps pushes apart; refuses the commands whose replies would not
pair; ends cleanly at EOF only when no reply is due; and stays failed once
the server broke the protocol (contract 1, rule 6)."""

from std.testing import TestSuite, assert_equal, assert_false, assert_true

from bytes.buffer import ByteBuffer
from linux import ErrorKind, IoError
from redis import Args, Limits, RespConnection, RespEvent
from redis_util import expecting, give, hex, oracle, s, sent


def test_replies_pair_with_commands_in_order() raises:
    var o = oracle()
    var c = RespConnection()
    c.command(Args("SET", "k", "v"))
    c.command(Args("GET", "k"))
    c.command(Args("HGETALL", "h"))
    assert_equal(c.pending(), 3)
    assert_false(c.is_idle())
    assert_equal(s(o.commands(sent(c))), "SET k v|GET k|HGETALL h")
    assert_equal(sent(c), "")  # (handed out once)
    # pushes come between replies, and pair with nothing
    assert_equal(
        give(
            c,
            s(o.simple("OK")) + s(o.push(o.bulk("invalidate"), o.array(o.bulk("k")))) + s(o.bulk("v"))
            + s(o.push(o.bulk("x"))),
        ),
        'REPLY +OK|PUSH >["invalidate" *["k"]]|REPLY "v"|PUSH >["x"]',
    )
    assert_equal(c.pending(), 1)
    # an error reply is a reply: the connection goes on
    assert_equal(give(c, s(o.error("WRONGTYPE Operation against a key"))), "REPLY -WRONGTYPE Operation against a key")
    assert_true(c.is_idle())
    c.command(Args("PING"))
    assert_equal(give(c, s(o.simple("PONG"))), "REPLY +PONG")


def _refused(args: Args) raises -> String:
    var c = RespConnection()
    try:
        c.command(args)
    except e:
        return String(e.kind, " ", sent(c), " ", c.pending())
    return "queued"


def test_commands_that_would_break_the_pairing_are_refused() raises:
    # (a subscriber runs on a connection of its own)
    for name in ["SUBSCRIBE", "subscribe", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE"]:
        assert_equal(_refused(Args(name, "ch")), "InvalidInput  0", name)
    assert_equal(_refused(Args("MONITOR")), "InvalidInput  0")
    assert_equal(_refused(Args("CLIENT", "REPLY", "OFF")), "InvalidInput  0")
    assert_equal(_refused(Args("client", "reply", "skip")), "InvalidInput  0")
    assert_equal(_refused(Args("CLIENT", "REPLY", "ON")), "queued")
    assert_equal(_refused(Args("CLIENT", "SETNAME", "x")), "queued")
    assert_equal(_refused(Args("SUBSCRIBERS")), "queued")  # (only the names themselves)
    assert_equal(_refused(Args()), "InvalidInput  0")


def test_quit_and_the_ends_of_a_connection() raises:
    var o = oracle()
    # QUIT: nothing more is queued, and EOF after its reply is the end
    var c = RespConnection()
    c.command(Args("QUIT"))
    assert_false(c.is_open())
    var refused = False
    try:
        c.command(Args("PING"))
    except e:
        refused = e.kind == ErrorKind.InvalidInput
    assert_true(refused)
    assert_equal(give(c, s(o.simple("OK")), eof=True), "REPLY +OK")
    # EOF with nothing due: the server closed an idle connection
    var idle = RespConnection()
    assert_equal(give(idle, "", eof=True), "")
    assert_false(idle.is_open())
    # EOF with a reply due, or inside a value
    var eof = "error UnexpectedEof: redis: the server closed the connection"
    var due = expecting(2)
    assert_equal(give(due, s(o.integer(1)), eof=True), String("REPLY :1|", eof))
    var inside = expecting(1)
    var bulk = s(o.bulk("hello"))
    assert_equal(give(inside, String(bulk[byte = 0 : bulk.byte_length() - 6]), eof=True), eof)
    var line = expecting(1)
    assert_equal(give(line, hex("+OK"), eof=True), eof)


def test_failures_stick() raises:
    var o = oracle()
    # a reply no command waited for
    var c = RespConnection()
    var unpaired = "error InvalidData: redis: a reply no command was waiting for"
    assert_equal(give(c, s(o.simple("OK"))), unpaired)
    assert_equal(give(c, ""), unpaired)  # (rule 6: it stays failed)
    assert_false(c.is_open())
    var kind = String()
    try:
        c.command(Args("PING"))
    except e:
        kind = String(e.kind)
    assert_equal(kind, "InvalidData")  # (the error that ended it)
    assert_equal(sent(c), "")
    # a malformed reply, and the event is left empty
    var d = expecting(1)
    d.feed(":x\r\n".as_bytes())
    var ev = RespEvent()
    var raised = False
    try:
        _ = d.poll(ev)
    except e:
        raised = e.kind == ErrorKind.InvalidData
    assert_true(raised)
    assert_equal(ev.value.nodes(), 0)
    # feeding past feed_capacity() loses input: OutOfMemory, and it sticks
    var f = expecting(1)
    var big = List[UInt8](length=f.feed_capacity() + 1, fill=43)
    var over = String()
    try:
        f.feed(Span(big))
    except e:
        over = String(e.kind)
    assert_equal(over, "OutOfMemory")
    assert_equal(give(f, ""), "error OutOfMemory: redis: fed past feed_capacity()")


def test_limits_are_checked() raises:
    var refused = 0
    for which in range(4):
        var limits = Limits()
        if which == 0:
            limits.max_line = 63
        elif which == 1:
            limits.max_depth = 0
        elif which == 2:
            limits.max_bulk = -1
        else:
            limits.max_elements = -1
        try:
            _ = RespConnection(limits)
        except e:
            refused += Int(e.kind == ErrorKind.InvalidInput)
    assert_equal(refused, 4)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
