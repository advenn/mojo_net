"""What `http.Client`'s errors say (2026-11 analysis, finding
http-errors-lack-context): a refused certificate raised one IoError for
every reason ("tls: the server failed verification"), and the reason was
only in `last_tls_error()`. Now the error's own text says why: expired,
for another name or address, or not trusted. Against Python's http.server
behind Python's `ssl` (tests/http/http_peer.py --tls)."""

from std.testing import TestSuite, assert_equal, assert_true

from http.client import Client
from linux import ErrorKind, IoError
from linux.time import Duration
from tls import ClientConfig, Trust
from http_peer import HttpPeer


def _error(mut c: Client, url: String) raises -> IoError:
    try:
        _ = c.get(url)
    except e:
        return e
    raise Error(String("GET ", url, " succeeded"))


def _says(e: IoError, what: StringSlice) raises:
    var text = String(e)
    assert_equal(e.kind, ErrorKind.PermissionDenied, text)
    assert_true(what in text, String("'", text, "' does not say '", what, "'"))


def test_a_refused_certificate_says_why() raises:
    var expired = HttpPeer(tls=True, cert="expired")
    var c = Client(timeout=Duration.from_secs(20), tls=ClientConfig(trust=Trust.ca_file(expired.ca())))
    _says(_error(c, expired.named_url("/hello")), "certificate has expired")
    expired^.stop()
    var wrong = HttpPeer(tls=True, cert="wrong_host")
    _says(_error(c, wrong.url("/hello")), "certificate is for another IP address")
    _says(_error(c, wrong.named_url("/hello")), "certificate is for another host name")
    var other = Client(timeout=Duration.from_secs(20), tls=ClientConfig(trust=Trust.ca_file(wrong.pki + "/other.pem")))
    _says(_error(other, wrong.named_url("/hello")), "certificate is not trusted")
    wrong^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
