"""Starts tests/llm/llm_peer.py, a fake model API (not a test file itself).
The process is killed when the `LlmPeer` is destroyed; end each test with
`peer^.stop()`, since Mojo destroys a value right after its last use."""

from std.python import Python, PythonObject

from http.client import Client
from linux.time import Duration


struct LlmPeer(Movable):
    var proc: PythonObject
    var port: Int

    def __init__(out self) raises:
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        self.proc = subprocess.Popen(
            Python.list(pysys.executable, "tests/llm/llm_peer.py"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        var line = String(py=self.proc.stdout.readline())
        var words = line.split()
        if len(words) != 2 or String(words[0]) != "PORT":
            raise Error("llm_peer.py did not start")
        self.port = atol(words[1])

    def base(self, scenario: StringSlice) -> String:
        """The base URL (up to /v1) for one scenario."""
        return String("http://127.0.0.1:", self.port, "/", scenario, "/v1")

    def log(self) raises -> PythonObject:
        """Every request so far: a list of {path, headers, body}. Fetched
        with `http.client`, not Python's urllib, which imports Python's
        `ssl` into this process (OpenSSL's config with it: CLAUDE.md, the
        test-only TLS peers; tools/check_tls_asan.sh saw its leaks)."""
        var c = Client(timeout=Duration.from_secs(10))
        var res = c.get(String("http://127.0.0.1:", self.port, "/_log"))
        return Python.import_module("json").loads(String(from_utf8_lossy=Span(res.body)))

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        _kill(self.proc)


def _kill(proc: PythonObject):
    try:
        _ = proc.kill()
        _ = proc.wait(timeout=10)
    except:
        pass
