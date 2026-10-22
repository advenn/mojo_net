"""`net.resolv`: resolv.conf parsing (nameservers, search/domain, options
with clamping, defaults, comments), hosts parsing and lookup, the search
list (ndots, absolute names, invalid candidates), `linux.fs.read_file`,
and a differential check of this machine's /etc/hosts against glibc's
getaddrinfo (through the test-only Python)."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind, IoError
from linux.fs import read_file
from linux.time import Duration
from net.resolv import Hosts, ResolvConf, search_names


def _strs(xs: List[String]) -> String:
    var out = String()
    for i in range(len(xs)):
        if i > 0:
            out += " "
        out += xs[i]
    return out


def _servers(c: ResolvConf) -> String:
    var out = String()
    for i in range(len(c.nameservers)):
        if i > 0:
            out += " "
        out += String(c.nameservers[i])
    return out


def _ips(h: Hosts, name: StringSlice) -> String:
    var out = String()
    var l = h.lookup(name)
    for i in range(len(l)):
        if i > 0:
            out += " "
        out += String(l[i])
    return out


# ---- resolv.conf -------------------------------------------------------------


def test_resolv_conf_full() raises:
    var c = ResolvConf.parse(
        "# a comment\n"
        + "; another\n"
        + "nameserver 10.0.0.1\n"
        + "nameserver\t2001:db8::53\n"
        + "nameserver not-an-address\n"
        + "nameserver 10.0.0.3\n"
        + "nameserver 10.0.0.4\n"  # beyond the third: ignored
        + "domain old.example\n"
        + "search Svc.Cluster.Local. cluster.local bad..name\n"
        + "options ndots:5 timeout:2 attempts:3 rotate edns0 use-vc"
        + " single-request bogus:9\n"
    )
    assert_equal(_servers(c), "10.0.0.1:53 [2001:db8::53]:53 10.0.0.3:53")
    assert_equal(_strs(c.search), "svc.cluster.local cluster.local")
    assert_equal(c.ndots, 5)
    assert_equal(c.timeout, Duration.from_secs(2))
    assert_equal(c.attempts, 3)
    assert_true(c.rotate and c.edns0 and c.use_tcp)


def test_resolv_conf_defaults_and_clamping() raises:
    var d = ResolvConf.parse("")
    assert_equal(_servers(d), "127.0.0.1:53 [::1]:53")
    assert_equal(len(d.search), 0)
    assert_equal(d.ndots, 1)
    assert_equal(d.timeout, Duration.from_secs(5))
    assert_equal(d.attempts, 2)
    assert_false(d.rotate or d.edns0 or d.use_tcp)
    var c = ResolvConf.parse(
        "options ndots:99 timeout:0 attempts:100\noptions timeout:x ndots:"
    )
    assert_equal(c.ndots, 15)
    assert_equal(c.timeout, Duration.from_secs(1))
    assert_equal(c.attempts, 5)


def test_search_comes_from_the_hostname_unless_configured() raises:
    assert_equal(_strs(ResolvConf.parse("", "web1.Prod.Example.com").search), "prod.example.com")
    assert_equal(len(ResolvConf.parse("", "web1").search), 0)
    assert_equal(_strs(ResolvConf.parse("search a.example\n", "web1.prod.example").search), "a.example")
    # The last search/domain line wins; domain takes one name.
    var c = ResolvConf.parse("search a.example b.example\ndomain c.example d.example\n")
    assert_equal(_strs(c.search), "c.example")


def test_nameserver_with_ipv6_zone() raises:
    var c = ResolvConf.parse("nameserver fe80::1%lo\n")
    assert_equal(len(c.nameservers), 1)
    assert_true(c.nameservers[0].is_ipv6())
    assert_true(c.nameservers[0].as_v6().value().scope_id() > 0)


# ---- hosts -------------------------------------------------------------------


def test_hosts_parse_and_lookup() raises:
    var h = Hosts.parse(
        "127.0.0.1\tlocalhost\n"
        + "::1 localhost ip6-localhost # trailing comment\n"
        + "# 10.9.9.9 commented.example\n"
        + "10.0.0.5  DB.Example.  db  # comment\n"
        + "10.0.0.6  db.example\n"
        + "not-an-ip  broken.example\n"
        + "10.0.0.7\n"
        + "fe80::1%eth0 zoned.example\n"
    )
    assert_equal(_ips(h, "localhost"), "127.0.0.1 ::1")
    assert_equal(_ips(h, "LocalHost."), "127.0.0.1 ::1")
    assert_equal(_ips(h, "ip6-localhost"), "::1")
    assert_equal(_ips(h, "db.example"), "10.0.0.5 10.0.0.6")
    assert_equal(_ips(h, "db"), "10.0.0.5")
    assert_equal(_ips(h, "commented.example"), "")
    assert_equal(_ips(h, "broken.example"), "")
    assert_equal(_ips(h, "zoned.example"), "")
    assert_equal(_ips(h, "missing"), "")


comptime _PY = """
import socket

def names(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.split('#', 1)[0].split()
            out.extend(line[1:])
    return out

def addrs(name):
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return ''
    return ' '.join(sorted({i[4][0] for i in infos}))
"""


def test_this_hosts_file_matches_getaddrinfo() raises:
    var py = Python.evaluate(_PY, file=True, name="resolv_oracle")
    var h = Hosts.load()
    var checked = 0
    for n in py.names("/etc/hosts"):
        var name = String(py=n)
        var want = String(py=py.addrs(name))
        if want.byte_length() == 0:
            continue
        var got = h.lookup(name)
        var mine = Python.list()
        for ip in got:
            mine.append(String(ip))
        var sorted_mine = String(py=Python.evaluate("lambda xs: ' '.join(sorted(set(xs)))")(mine))
        assert_equal(sorted_mine, want, name)
        checked += 1
    assert_true(checked > 0)


# ---- search list -------------------------------------------------------------


def test_search_names_follow_ndots() raises:
    var c = ResolvConf.parse("search ns.svc.cluster.local svc.cluster.local\noptions ndots:2\n")
    assert_equal(_strs(search_names("db", c)), "db.ns.svc.cluster.local db.svc.cluster.local db")
    assert_equal(_strs(search_names("api.example", c)), "api.example.ns.svc.cluster.local api.example.svc.cluster.local api.example")
    assert_equal(_strs(search_names("a.b.example", c)), "a.b.example a.b.example.ns.svc.cluster.local a.b.example.svc.cluster.local")
    assert_equal(_strs(search_names("Absolute.Example.", c)), "absolute.example")
    var zero = ResolvConf.parse("search x.example\noptions ndots:0\n")
    assert_equal(_strs(search_names("db", zero)), "db db.x.example")


def test_search_names_drop_invalid_candidates() raises:
    var long_label = String()
    for _ in range(62):
        long_label += "d"
    var c = ResolvConf.parse(String("search ", long_label, ".", long_label, ".", long_label, ".", long_label, " ok.example\n"))
    # The 4-label domain is valid alone but too long with "host." in front.
    assert_equal(_strs(search_names("host", c)), "host.ok.example host")
    assert_equal(len(search_names("bad..name", c)), 0)
    assert_equal(len(search_names("", c)), 0)


# ---- reading files -----------------------------------------------------------


def test_read_file_errors() raises:
    var kinds = List[ErrorKind]()
    try:
        _ = read_file("/nonexistent/resolv.conf", "read(test)")
    except e:
        kinds.append(e.kind)
    try:
        _ = read_file("/etc/hosts", "read(test)", max_bytes=1)
    except e:
        kinds.append(e.kind)
    try:
        _ = read_file(String("/etc/ho\0sts"), "read(test)")
    except e:
        kinds.append(e.kind)
    assert_equal(len(kinds), 3)
    assert_equal(kinds[0], ErrorKind.NotFound)
    assert_equal(kinds[1], ErrorKind.InvalidData)
    assert_equal(kinds[2], ErrorKind.InvalidInput)
    assert_true(len(read_file("/etc/hosts", "read(test)")) > 0)
    # A missing config file is the defaults, not an error.
    assert_equal(_servers(ResolvConf.load("/nonexistent/resolv.conf")), "127.0.0.1:53 [::1]:53")
    assert_equal(len(Hosts.load("/nonexistent/hosts")), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
