"""Fault-seam regression tests for the second review of `StaticFiles`
(SR2), each checked to fail on the code before its fix:
- STA-6: where openat2 is missing (ENOSYS) or refused (EPERM, an old
  seccomp profile), `StaticFiles.open` succeeded and every request then
  got 500 or 403 (now `open` raises);
- STA-9: a file that read short (it shrank after its statx) got a 206
  whose Content-Range disagreed with its body (now it is looked up and
  read again, and one that keeps changing raises: a 500)."""

from std.python import Python
from std.testing import TestSuite, assert_equal, assert_true

from linux import ErrorKind, fault
from linux.errno import Errno
from linux.nr import SYS_openat2, SYS_pread64
from net.addr import SocketAddr
from server import Request, Response, StaticFiles


def _root() raises -> String:
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var root = String(py=tempfile.mkdtemp(prefix=String("mojo_net_static_sr2f_", Int(py=os.getpid()), "_")))
    var f = Python.import_module("builtins").open(String(root, "/data.bin"), "wb")
    _ = f.write(Python.evaluate("bytes(i % 251 for i in range(1000))"))
    _ = f.close()
    return root^


def _remove(root: String) raises:
    _ = Python.import_module("shutil").rmtree(root, ignore_errors=True)


def _open_refused(root: String, e: Errno, kind: ErrorKind) raises -> Bool:
    fault.clear()
    fault.inject(SYS_openat2, e, times=-1)
    var refused = False
    try:
        _ = StaticFiles.open(root)
    except err:
        refused = err.kind == kind
    fault.clear()
    return refused


def test_open_needs_openat2() raises:
    var root = _root()
    var unsupported = _open_refused(root, Errno.ENOSYS, ErrorKind.Unsupported)
    var denied = _open_refused(root, Errno.EPERM, ErrorKind.PermissionDenied)
    _ = StaticFiles.open(root)  # (and without the faults it opens)
    _remove(root)
    assert_true(unsupported, "ENOSYS")
    assert_true(denied, "EPERM")


def _range_request() raises -> Request:
    var req = Request(SocketAddr.parse("127.0.0.1:1"))
    req.method = "GET"
    req.target = "/data.bin"
    req.headers.add("Range", "bytes=0-3")
    return req^


def test_a_short_read_is_read_again() raises:
    var root = _root()
    var files = StaticFiles.open(root)
    fault.clear()
    fault.inject_short(SYS_pread64, 0)  # the first read finds nothing, as if it shrank
    var res = Response()
    files.serve(_range_request(), "data.bin", res)
    fault.clear()
    _remove(root)
    assert_equal(res.status, 206)
    assert_equal(String(res.headers.get("content-range").value()), "bytes 0-3/1000")
    assert_equal(len(res.body), 4)
    assert_equal(Int(res.body[3]), 3)


def test_a_file_that_keeps_reading_short_is_an_error() raises:
    var root = _root()
    var files = StaticFiles.open(root)
    fault.clear()
    fault.inject_short(SYS_pread64, 0, times=-1)
    var res = Response()
    var raised = False
    try:
        files.serve(_range_request(), "data.bin", res)
    except:
        raised = True
    fault.clear()
    _remove(root)
    assert_true(raised, String("answered ", res.status, " with ", len(res.body), " bytes"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
