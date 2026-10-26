"""A hostile OpenSSL configuration loaded into the process before the `tls`
package (TL4, TC16): spikes/tls/hostile.cnf asks for TLS 1.0, security
level 0 and the legacy provider. Python's `ssl`, imported here with
OPENSSL_CONF pointing at it, loads it into the process's OpenSSL, the same
library `tls` uses. T0 found that such a configuration reaches every new
`SSL_CTX`; `tls.config` sets each knob itself, so the policy must hold."""

from std.os import setenv
from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from tls import Category, ClientConfig, Trust
from tls_util import Peer, connect, opts, pki, refused, trusting


def _load_hostile_config() raises:
    var os = Python.import_module("os")
    _ = setenv("OPENSSL_CONF", String(py=os.path.abspath("spikes/tls/hostile.cnf")), True)
    _ = Python.import_module("ssl")
    # The contrast: the configuration did load. Its legacy provider gives
    # Python's hashlib MD4, which the default provider lacks. (Python's
    # SSLContext sets its own floor and level, so it cannot show them.)
    var hashlib = Python.import_module("hashlib")
    _ = hashlib.new("md4")


def test_policy_holds_under_a_hostile_config() raises:
    _load_hostile_config()
    var ctx = trusting()  # (build() reads every setting back)
    var peers = Peer("echo")
    var s = connect(peers, ctx)
    assert_equal(s.version(), "TLSv1.3")
    s^.close()
    peers^.stop()
    var old = Peer("echo", opts("min=1.0", "max=1.1", "seclevel=0"))
    refused(old, ctx, "localhost", Category.PROTOCOL)
    old^.stop()
    var weak = Peer("echo", opts("cert=rsa1024", "seclevel=0"))
    refused(weak, ctx, "localhost", Category.WEAK, 66)
    weak^.stop()
    var cbc = Peer("echo", opts("max=1.2", "cert=rsa", "ciphers=AES128-SHA", "seclevel=0"))
    refused(cbc, ctx, "localhost", Category.PROTOCOL)
    cbc^.stop()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
