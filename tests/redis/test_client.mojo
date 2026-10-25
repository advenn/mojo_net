"""`redis.client` and `redis.config` against a real server (`redis_server.mojo`:
a throwaway Valkey; skipped without one): connecting over both transports
and both protocols, authentication, databases and names, replies of every
shape, binary and large values, server errors that keep the connection,
deadlines that close it, pushes kept aside, and connection URIs."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_false, assert_true
from std.time import sleep

from linux import ErrorKind, IoError
from linux.time import Duration, Instant
from redis import Args, Kind, Value
from redis.client import MAX_PUSHES, Client, Pipeline, RedisError
from redis.config import Config
from redis_server import RedisServer


def _error(mut r: Client, args: Args, timeout: Duration = Duration.ZERO) raises -> RedisError:
    try:
        _ = r.command_args(args, timeout)
    except e:
        return e.copy()
    raise Error("no error")


def _connect_error(config: Config) raises -> RedisError:
    try:
        var r = Client.connect(config)
        r^.close()
    except e:
        return e.copy()
    raise Error("connected")


def _transports_and_protocols(server: RedisServer) raises:
    for which in range(4):
        var config = server.tcp() if which % 2 == 0 else server.unix()
        config.protocol = 3 if which < 2 else 2
        var r = Client.connect(config)
        assert_equal(r.protocol(), config.protocol)
        _ = r.command("DEL", "h", "z")
        assert_equal(r.command("HSET", "h", "a", "1", "b", "2").int(), 2)
        var h = r.command("HGETALL", "h")
        if config.protocol == 3:
            assert_true(h.kind() == Kind.MAP)  # (RESP3 types its replies)
            assert_equal(h.text(h.get(0, "b").value()), "2")
        else:
            assert_true(h.kind() == Kind.ARRAY)  # (RESP2 has flat arrays)
            assert_equal(h.count(), 4)
        _ = r.command("ZADD", "z", "1.5", "m")
        var score = r.command("ZSCORE", "z", "m")
        assert_true(score.kind() == (Kind.DOUBLE if config.protocol == 3 else Kind.BULK))
        assert_equal(score.float(), 1.5)  # (either way)
        assert_true(r.command("GET", "nothing").is_null())
        if config.protocol == 3:
            var hello = r.hello()
            assert_equal(hello.text(hello.get(0, "server").value()), "valkey")
        r^.close()


def test_transports_and_protocols() raises:
    _with_server(0)


def _authentication(server: RedisServer) raises:
    # an ACL user, through HELLO's AUTH and through RESP2's AUTH
    for protocol in [3, 2]:
        var config = server.tcp("alice", "alice-pw")
        config.protocol = protocol
        var r = Client.connect(config)
        assert_equal(r.command("ACL", "WHOAMI").text(), "alice")
        r^.close()
    # refusals carry the server's code
    assert_equal(_connect_error(server.tcp("alice", "wrong")).code(), "WRONGPASS")
    var resp2 = server.tcp("alice", "wrong")
    resp2.protocol = 2
    assert_equal(_connect_error(resp2).code(), "WRONGPASS")
    # a user that may only read: refused commands keep the connection
    var reader = Client.connect(server.tcp("reader", "reader-pw"))
    var e = _error(reader, Args("SET", "pub:x", "1"))
    assert_equal(e.code(), "NOPERM")
    assert_true(reader.is_usable())
    assert_true(reader.command("GET", "pub:x").is_null())
    reader^.close()


def test_authentication() raises:
    _with_server(1)


def _setup_commands(server: RedisServer) raises:
    var config = server.unix()
    config.database = 3
    config.client_name = "mojo-tests"
    var r = Client.connect(config)
    _ = r.command("SET", "where", "db3")
    assert_equal(r.command("CLIENT", "GETNAME").text(), "mojo-tests")
    var other = Client.connect(server.unix())
    assert_true(other.command("GET", "where").is_null())  # (database 0)
    _ = other.command("SELECT", 3)
    assert_equal(other.command("GET", "where").text(), "db3")
    other^.close()
    r^.close()
    # the same over RESP2
    config.protocol = 2
    var r2 = Client.connect(config)
    assert_equal(r2.command("CLIENT", "GETNAME").text(), "mojo-tests")
    assert_equal(r2.command("GET", "where").text(), "db3")
    r2^.close()
    # settings no connection can have
    var kinds = List[String]()
    for which in range(4):
        var bad = server.unix()
        if which == 0:
            bad.protocol = 4
        elif which == 1:
            bad.database = -1
        elif which == 2:
            bad.client_name = "has space"
        else:
            bad.user = "alice"  # (without a password)
        kinds.append(String(_connect_error(bad).io.kind))
    assert_equal(String(",").join(kinds), "InvalidInput,InvalidInput,InvalidInput,InvalidInput")


def test_databases_names_and_settings() raises:
    _with_server(2)


def _values(server: RedisServer) raises:
    var r = Client.connect(server.tcp())
    # bytes of every kind, through Args
    var raw = List[UInt8]()
    for i in range(256):
        raw.append(UInt8(i))
    raw.extend("\r\n$5\r\n*1\r\n".as_bytes())
    var set = Args()
    set.add_text("SET")
    set.add_text("bin")
    set.add_bytes(Span(raw))
    _ = r.command_args(set)
    var got = r.command("GET", "bin").bytes()
    assert_equal(len(got), len(raw))
    for i in range(len(raw)):
        assert_equal(Int(got[i]), Int(raw[i]))
    # a large value, both ways
    var big = String()
    for _ in range(200000):
        big += "0123456789"
    _ = r.command("SET", "big", big)
    assert_equal(r.command("STRLEN", "big").int(), 2000000)
    assert_equal(r.command("GET", "big").text(), big)
    # many elements
    _ = r.command("DEL", "list")
    for i in range(0, 5000, 500):
        var push = Args("RPUSH", "list")
        for k in range(i, i + 500):
            push.add(k)
        _ = r.command_args(push)
    var items = r.command("LRANGE", "list", 0, -1)
    assert_equal(items.count(), 5000)
    assert_equal(items.int(items.child(0, 4999)), 4999)
    # every RESP3 type the server can send, and an attribute dropped
    for t in ["double", "bignum", "null", "set", "map", "verbatim", "true", "attrib"]:
        _ = r.command("DEBUG", "PROTOCOL", t)
    assert_equal(String(r.command("DEBUG", "PROTOCOL", "attrib")), '"Some real reply following the attribute"')
    assert_equal(String(r.command("DEBUG", "PROTOCOL", "bignum")), "(1234567999999999999999999999999999999")
    # a push after a reply is kept aside, up to MAX_PUSHES of them
    assert_equal(String(r.command("DEBUG", "PROTOCOL", "push")), '"Some real reply following the push reply"')
    _ = r.command("PING")
    var pushes = r.take_pushes()
    assert_equal(len(pushes), 1)
    assert_equal(String(pushes[0]), '>["server-cpu-usage" :42]')
    for _ in range(MAX_PUSHES + 10):
        _ = r.command("DEBUG", "PROTOCOL", "push")
    assert_equal(len(r.take_pushes()), MAX_PUSHES)
    assert_true(r._sock.keepalive())  # (a vanished server is noticed)
    # a transaction: per-command errors are values in EXEC's reply
    _ = r.command("SET", "s", "x")
    _ = r.command("MULTI")
    _ = r.command("INCR", "n")
    _ = r.command("INCR", "s")
    var exec = r.command("EXEC")
    assert_equal(exec.count(), 2)
    assert_true(exec.is_error(exec.child(0, 1)))
    r^.close()


def test_values() raises:
    _with_server(3)


def _errors_and_deadlines(server: RedisServer) raises:
    var r = Client.connect(server.tcp())
    _ = r.command("SET", "s", "x")
    var e = _error(r, Args("LPUSH", "s", "1"))
    assert_true(e.is_server())
    assert_equal(e.code(), "WRONGTYPE")
    assert_true(r.is_usable())
    assert_equal(_error(r, Args("NOSUCHCOMMAND")).code(), "ERR")
    # refused before anything is sent: the connection goes on
    var sub = _error(r, Args("SUBSCRIBE", "ch"))
    assert_true(sub.io.kind == ErrorKind.InvalidInput)
    assert_equal(r.command("PING").text(), "PONG")
    # a deadline that passes closes the connection (the reply would come later)
    var t = Instant.now()
    var late = _error(r, Args("BLPOP", "nothing", 0), Duration.from_millis(200))
    assert_true(late.is_deadline())
    assert_true(t.elapsed() < Duration.from_secs(3))
    assert_false(r.is_usable())
    assert_true(_error(r, Args("PING")).io.kind == ErrorKind.Closed)
    # killed by the server
    var victim = Client.connect(server.tcp())
    var id = victim.command("CLIENT", "ID").int()
    var admin = Client.connect(server.tcp())
    _ = admin.command("CLIENT", "KILL", "ID", id)
    assert_false(victim.check())
    assert_false(victim.is_usable())
    admin^.close()
    victim^.close()


def test_errors_and_deadlines() raises:
    _with_server(4)


def _pushes_and_check(server: RedisServer) raises:
    # client tracking: invalidations arrive as pushes between replies
    var watcher = Client.connect(server.tcp())
    _ = watcher.command("CLIENT", "TRACKING", "ON")
    _ = watcher.command("SET", "tracked", "1")
    _ = watcher.command("GET", "tracked")
    var writer = Client.connect(server.tcp())
    _ = writer.command("SET", "tracked", "2")
    writer^.close()
    # check() reads the push without a round trip, and keeps it. (The server
    # may flush it to the watcher after the writer's reply: wait for it.)
    var t = Instant.now()
    var pushes = List[Value]()
    while len(pushes) == 0 and t.elapsed() < Duration.from_secs(5):
        assert_true(watcher.check())
        pushes = watcher.take_pushes()
        if len(pushes) == 0:
            sleep(0.005)
    assert_equal(len(pushes), 1)
    assert_equal(String(pushes[0]), '>["invalidate" *["tracked"]]')
    assert_equal(watcher.command("GET", "tracked").text(), "2")
    watcher^.close()


def test_pushes_and_check() raises:
    _with_server(5)


def _requirepass() raises:
    var started = RedisServer.start(requirepass="sekrit")
    if not started:
        return
    var server = started.take()
    var failure = String()
    try:
        assert_equal(_connect_error(server.tcp()).code(), "NOAUTH")
        for protocol in [3, 2]:
            var config = Config.parse(String("redis://:sekrit@127.0.0.1:", server.port, "?protocol=", protocol))
            var r = Client.connect(config)
            assert_equal(r.command("ACL", "WHOAMI").text(), "default")
            r^.close()
        var bare = Client.connect(Config.parse(String("unix://sekrit@", server.socket_path(), "?db=2")))
        assert_equal(bare.command("ACL", "WHOAMI").text(), "default")
        bare^.close()
    except e:
        failure = String(e)
    server.stop()
    assert_equal(failure, "")


def test_the_default_users_password() raises:
    _requirepass()


def _servers_without_hello() raises:
    var started = RedisServer.start(no_hello=True)
    if not started:
        return
    var server = started.take()
    var failure = String()
    try:
        _without_hello(server)
    except e:
        failure = String(e)
    server.stop()
    assert_equal(failure, "")


def _without_hello(server: RedisServer) raises:
    # RESP3 asked for, RESP2 spoken: AUTH and CLIENT SETNAME instead
    var config = server.tcp("alice", "alice-pw")
    config.client_name = "old-style"
    var r = Client.connect(config)
    assert_equal(r.protocol(), 2)
    assert_equal(r.hello().nodes(), 0)
    assert_equal(r.command("ACL", "WHOAMI").text(), "alice")
    assert_equal(r.command("CLIENT", "GETNAME").text(), "old-style")
    assert_true(r.command("HGETALL", "nothing").kind() == Kind.ARRAY)
    r^.close()
    assert_equal(_connect_error(server.tcp("alice", "wrong")).code(), "WRONGPASS")


def test_servers_without_hello() raises:
    _servers_without_hello()


def test_a_deadline_bounds_input_that_keeps_coming() raises:
    # input that never runs dry never makes a receive wait: the deadline
    # must be checked before each one
    var subprocess = Python.import_module("subprocess")
    var sys = Python.import_module("sys")
    var builtins = Python.import_module("builtins")
    var peer = subprocess.Popen(Python.list(sys.executable, "tests/redis/flood_peer.py"), stdout=subprocess.PIPE)
    var port = Int(py=builtins.int(peer.stdout.readline()))
    var failure = String()
    try:
        _endless(port)
    except e:
        failure = String(e)
    _ = peer.kill()
    _ = peer.wait()
    assert_equal(failure, "")


def _endless(port: Int) raises:
    var r = Client.connect(Config("127.0.0.1", port=port, protocol=2))  # (nothing to set up)
    var t = Instant.now()
    var e = _error(r, Args("GET", "x"), Duration.from_millis(200))
    assert_true(e.is_deadline())
    assert_true(t.elapsed() < Duration.from_secs(5))
    assert_false(r.is_usable())
    assert_equal(len(r.take_pushes()), MAX_PUSHES)  # (the newest kept: memory stays bounded)
    r^.close()


def _run_error(mut r: Client, p: Pipeline, transaction: Bool) raises -> RedisError:
    try:
        if transaction:
            _ = r.transaction(p)
        else:
            _ = r.run(p)
    except e:
        return e.copy()
    raise Error("no error")


def _pipelines(server: RedisServer) raises:
    for protocol in [3, 2]:
        var config = server.tcp()
        config.protocol = protocol
        var r = Client.connect(config)
        _ = r.command("FLUSHDB")
        # one write, every reply in its place, errors included
        var p = Pipeline()
        for i in range(100):
            p.add("SET", String("k", i), i)
        p.add("LPUSH", "k0", "x")
        p.add("INCR", "k99")
        var replies = r.run(p)
        assert_equal(len(replies), 102)
        assert_equal(String(replies[0]), "+OK")
        assert_equal(replies[100].error_code(), "WRONGTYPE")
        assert_equal(replies[101].int(), 100)
        # a push among the replies is kept aside
        if protocol == 3:
            var pushed = Pipeline()
            pushed.add("DEBUG", "PROTOCOL", "push")
            pushed.add("PING")
            assert_equal(len(r.run(pushed)), 2)
            assert_equal(len(r.take_pushes()), 1)
        # refused whole, before anything is sent
        var bad = Pipeline()
        bad.add("SET", "x", 1)
        bad.add("SUBSCRIBE", "ch")
        assert_true(_run_error(r, bad, False).io.kind == ErrorKind.InvalidInput)
        assert_false(Bool(r.get("x")))
        assert_true(r.is_usable())
        # a transaction: all at once, in one round trip
        var t = Pipeline()
        t.add("INCR", "n")
        t.add("INCR", "n")
        t.add("GET", "n")
        _ = r.rpush("list", "a", "b")
        t.add("LRANGE", "list", 0, -1)  # (an aggregate among the results)
        t.add("GET", "n")
        var got = r.transaction(t)
        var done = got.take()
        assert_equal(len(done), 5)
        assert_equal(done[2].text(), "2")
        assert_equal(String(done[3]), '*["a" "b"]')
        assert_equal(done[4].text(), "2")
        var empty = r.transaction(Pipeline())
        assert_equal(len(empty.take()), 0)
        # an error met running one is a value, and the others ran
        t = Pipeline()
        t.add("INCR", "k0")
        t.add("LPUSH", "k1", "x")
        t.add("INCR", "k2")
        var ran = r.transaction(t)
        var mixed = ran.take()
        assert_equal(mixed[0].int(), 1)
        assert_equal(mixed[1].error_code(), "WRONGTYPE")
        assert_equal(mixed[2].int(), 3)
        # one refused while queuing aborts it: that error raises, and nothing ran
        t = Pipeline()
        t.add("SET", "never", 1)
        t.add("NOSUCHCOMMAND")
        var aborted = _run_error(r, t, True)
        assert_true(aborted.is_server())
        assert_equal(aborted.code(), "ERR")
        assert_false(Bool(r.get("never")))
        # WATCH: a key another client changed, and nothing ran
        _ = r.command("WATCH", "w")
        var other = Client.connect(config)
        _ = other.set("w", "theirs")
        other^.close()
        t = Pipeline()
        t.add("SET", "w", "mine")
        assert_false(Bool(r.transaction(t)))
        assert_equal(r.get("w").value(), "theirs")
        _ = r.command("WATCH", "w")
        assert_true(Bool(r.transaction(t)))
        assert_equal(r.get("w").value(), "mine")
        # a deadline that passes closes the connection, as for one command
        var slow = Pipeline()
        slow.add("PING")
        slow.add("BLPOP", "nothing", 0)
        var timed_out = False
        try:
            _ = r.run(slow, Duration.from_millis(100))
        except e:
            timed_out = e.is_deadline()
        assert_true(timed_out)
        assert_true(_error(r, Args("PING")).io.kind == ErrorKind.Closed)
        r^.close()


def test_pipelines_and_transactions() raises:
    _with_server(6)


def _helpers(server: RedisServer) raises:
    for protocol in [3, 2]:
        var config = server.unix()
        config.protocol = protocol
        var r = Client.connect(config)
        _ = r.command("FLUSHDB")
        assert_true(r.set("s", "v"))
        assert_equal(r.get("s").value(), "v")
        assert_false(Bool(r.get("none")))
        assert_false(r.set("s", "x", nx=True))  # (present)
        assert_false(r.set("new", "y", xx=True))  # (absent)
        assert_true(r.set("e", 1, expire=Duration.from_secs(100)))
        assert_true(r.ttl("e").value() > Duration.from_secs(99))
        assert_false(Bool(r.ttl("s")))  # (no expiry)
        assert_true(r.expire("s", Duration.from_secs(50)))
        assert_true(r.ttl("s").value() <= Duration.from_secs(50))
        var raw: List[UInt8] = [0, 13, 10, 255]
        assert_true(r.set_bytes("b", Span(raw)))
        assert_equal(len(r.get_bytes("b").value()), 4)
        assert_equal(r.exists("s", "s", "none"), 2)
        assert_equal(r.delete("s", "e", "none"), 2)
        assert_equal(r.incr("c"), 1)
        assert_equal(r.incr("c", 10), 11)
        assert_true(r.hset("h", "a", 1))
        assert_false(r.hset("h", "a", 2))
        assert_equal(r.hget("h", "a").value(), "2")
        assert_false(Bool(r.hget("h", "zz")))
        _ = r.hset("h", "b", "x y")
        var all = r.hgetall("h")
        assert_equal(len(all), 2)
        assert_equal(all["b"], "x y")
        assert_equal(r.hdel("h", "a", "zz"), 1)
        assert_equal(r.lpush("l", "a", "b"), 2)
        assert_equal(r.rpush("l", "c"), 3)
        assert_equal(String(",").join(r.lrange("l", 0, -1)), "b,a,c")
        assert_equal(r.lpop("l").value(), "b")
        assert_equal(r.rpop("l").value(), "c")
        assert_false(Bool(r.lpop("none")))
        assert_equal(r.sadd("set", "x", "y", "x"), 2)
        assert_true(r.sismember("set", "x"))
        assert_false(r.sismember("set", "z"))
        assert_equal(len(r.smembers("set")), 2)
        assert_equal(r.srem("set", "x"), 1)
        assert_true(r.zadd("z", 2.5, "m"))
        assert_true(r.zadd("z", 1.0, "n"))
        assert_false(r.zadd("z", 3.0, "m"))  # (updated, not new)
        assert_equal(r.zscore("z", "m").value(), 3.0)
        assert_false(Bool(r.zscore("z", "none")))
        assert_equal(String(",").join(r.zrange("z", 0, -1)), "n,m")
        assert_equal(r.publish("ch", "hi"), 0)  # (no subscriber)
        r^.close()


def test_typed_helpers() raises:
    _with_server(7)


def test_uris() raises:
    var c = Config.parse("redis://alice:p%40ss@cache.example.com:6380/4?client_name=web&protocol=2&connect_timeout=3")
    assert_equal(c.user, "alice")
    assert_equal(c.password, "p@ss")
    assert_equal(c.host, "cache.example.com")
    assert_equal(c.port, 6380)
    assert_equal(c.database, 4)
    assert_equal(c.client_name, "web")
    assert_equal(c.protocol, 2)
    assert_true(c.connect_timeout == Duration.from_secs(3))
    var d = Config.parse("redis://")
    assert_equal(d.host, "localhost")
    assert_equal(d.port, 6379)
    assert_equal(d.database, 0)
    assert_equal(d.protocol, 3)
    assert_equal(Config.parse("redis://[::1]:7000").host, "::1")
    assert_equal(Config.parse("redis://:only-pw@h").password, "only-pw")
    assert_equal(Config.parse("redis://only-pw@h").password, "only-pw")  # (as redis-cli reads it)
    assert_equal(Config.parse("redis://only-pw@h").user, "")
    var u = Config.parse("unix://bob:pw@/run/valkey/sock@1?db=5")
    assert_equal(u.host, "/run/valkey/sock@1")
    assert_equal(u.user, "bob")
    assert_equal(u.database, 5)
    assert_true(u.is_unix())
    assert_equal(Config.parse("unix:///tmp/x.sock").host, "/tmp/x.sock")
    assert_equal(Config.parse("unix:///tmp/a@b.sock").host, "/tmp/a@b.sock")  # (no user: the @ is the path's)
    assert_equal(Config.parse("unix:///tmp/a@b.sock").password, "")
    assert_equal(Config.parse("redis://h?db=1&db=2").database, 2)  # (the last value)
    var kinds = List[String]()
    for bad in [
        "http://h",
        "redis://h:0",
        "redis://h:99999",
        "redis://h/x",
        "redis://h?nope=1",
        "redis://h?protocol=4",
        "redis://a@b@h",
        "redis://[::1",
        "unix://relative/path",
        "redis://h?db",
        "redis://%zz@h",
    ]:
        try:
            _ = Config.parse(bad)
            kinds.append("accepted")
        except e:
            kinds.append(String(e.kind))
    for k in kinds:
        assert_equal(k, "InvalidInput")
    var tls = String()
    try:
        _ = Config.parse("rediss://h")
    except e:
        tls = String(e.kind)
    assert_equal(tls, "Unsupported")


def _run(server: RedisServer, which: Int) -> String:
    """Body `which` against `server`: "" or why it failed."""
    try:
        if which == 0:
            _transports_and_protocols(server)
        elif which == 1:
            _authentication(server)
        elif which == 2:
            _setup_commands(server)
        elif which == 3:
            _values(server)
        elif which == 4:
            _errors_and_deadlines(server)
        elif which == 5:
            _pushes_and_check(server)
        elif which == 6:
            _pipelines(server)
        else:
            _helpers(server)
    except e:
        return String(e)
    return ""


def _with_server(which: Int) raises:
    var started = RedisServer.start()
    if not started:
        return
    var server = started.take()
    var failure = _run(server, which)
    server.stop()
    assert_equal(failure, "")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
