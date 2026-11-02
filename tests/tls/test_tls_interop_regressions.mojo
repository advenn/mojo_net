"""Regression tests for what tlsfuzzer found against the HTTPS server
(TG12, 2026-11; `pixi run tls-interop` runs it weekly, docs/tls.md):

- Padding counted against the client's quiet budget (`CLIENT_QUIET_LIMIT`,
  4 KiB that carries no data): a record's data and overhead were taken
  off, its padding was not, so a client that pads its records, as RFC 8446
  5.4 lets it, up to the record limit, had its connection closed once 4 KiB
  of padding had come (test-tls13-record-padding.py, and
  test-tls13-zero-length-data.py's "large padding"). Now a record that
  carries data is taken off whole; a record without data, padded or not,
  still counts.

`TlsClient` pads through libssl directly (`tls_pair.Pair.pad`)."""

from std.testing import TestSuite, assert_equal, assert_true

from tls import Category
from tls.engine import CLIENT_QUIET_LIMIT
from tls_pair import Pair
from tls_util import pattern


def test_padded_records_with_data_are_not_quiet() raises:
    var p = Pair()
    p.pad(16384, 0)  # (every data record padded to 16 KiB: 4 times the budget each)
    p.handshake()
    var data = pattern(100)
    for i in range(40):
        assert_equal(p.c.write(Span(data)), 100)
        assert_true(p.c.pending_transmit() > 16384, String("not padded: ", p.c.pending_transmit(), " bytes"))
        try:
            p.to_server()
        except e:
            raise Error(String("the server failed at record ", i + 1, ": ", e))
    assert_equal(p.got, 4000)


def test_a_padded_record_without_data_still_counts() raises:
    """A key update padded to 16 KiB carries no data: it alone passes the
    budget."""
    var p = Pair()
    p.pad(0, 16384)  # (handshake records only: the Finished, before the budget applies, and key updates)
    p.handshake()
    var data = pattern(100)
    _ = p.c.write(Span(data))
    p.to_server()
    assert_equal(p.got, 100)
    p.key_update(False)
    assert_true(p.c.pending_transmit() > 16384, String("not padded: ", p.c.pending_transmit(), " bytes"))
    var failed = False
    try:
        p.to_server()
    except e:
        assert_equal(e.category, Category.PROTOCOL, String(e))
        assert_true("without any data" in String(e), String(e))
        failed = True
    assert_true(failed, String("a 16 KiB record without data passed a budget of ", CLIENT_QUIET_LIMIT))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
