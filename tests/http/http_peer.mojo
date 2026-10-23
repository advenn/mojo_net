"""Starts tests/http/http_peer.py, Python's http.server with test routes
(not a test file itself). The process is killed when the `HttpPeer` is
destroyed; end each test with `peer^.stop()`, since Mojo destroys a value
right after its last use."""

from std.python import Python, PythonObject


struct HttpPeer(Movable):
    var proc: PythonObject
    var port: Int

    def __init__(out self) raises:
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        self.proc = subprocess.Popen(
            Python.list(pysys.executable, "tests/http/http_peer.py"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        var line = String(py=self.proc.stdout.readline())
        var words = line.split()
        if len(words) != 2 or String(words[0]) != "PORT":
            raise Error("http_peer.py did not start")
        self.port = atol(words[1])

    def url(self, path: StringSlice) -> String:
        return String("http://127.0.0.1:", self.port, path)

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        _kill(self.proc)


def _kill(proc: PythonObject):
    try:
        _ = proc.kill()
        _ = proc.wait()
    except:
        pass
