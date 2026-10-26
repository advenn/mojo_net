"""`linux.fs.stat_path`, against Python's `os.stat` (the oracle)."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from linux import ErrorKind
from linux.fs import is_dir, is_regular, stat_path


def _scratch() raises -> PythonObject:
    var tempfile = Python.import_module("tempfile")
    return tempfile.mkdtemp(prefix="mojo_net_stat_")


def test_stat_path_matches_os_stat() raises:
    var os = Python.import_module("os")
    var d = _scratch()
    var p = os.path.join(d, "key.pem")
    var f = Python.import_module("builtins").open(p, "w")
    _ = f.write("12345")
    _ = f.close()
    _ = os.chmod(p, 0o640)
    var st = stat_path(String(py=p))
    var want = os.stat(p)
    assert_true(is_regular(st))
    assert_equal(Int(st.mode) & 0o7777, 0o640)
    assert_equal(Int(st.size), 5)
    assert_equal(Int(st.uid), Int(py=want.st_uid))
    assert_equal(Int(st.ino), Int(py=want.st_ino))
    # A symbolic link is followed (Let's Encrypt's live/ files are links).
    var link = os.path.join(d, "link.pem")
    _ = os.symlink(p, link)
    var via = stat_path(String(py=link))
    assert_equal(Int(via.ino), Int(st.ino))
    assert_true(is_dir(stat_path(String(py=d))))
    _ = Python.import_module("shutil").rmtree(d)


def test_stat_path_errors() raises:
    var d = _scratch()
    var missing = String(String(py=d), "/none")
    var kind = ErrorKind.Other
    try:
        _ = stat_path(missing)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.NotFound)
    kind = ErrorKind.Other
    var nul = String(String(py=d), "/a\x00b")
    try:
        _ = stat_path(nul)
    except e:
        kind = e.kind
    assert_equal(kind, ErrorKind.InvalidInput)
    _ = Python.import_module("shutil").rmtree(d)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
