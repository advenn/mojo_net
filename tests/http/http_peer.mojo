"""Starts tests/http/http_peer.py, Python's http.server with test routes
(not a test file itself), over TCP or, with `tls=True`, over TLS with a
throwaway PKI from tests/tls/tls_pki.py (`ca()` is its CA file). The process is killed when the `HttpPeer` is
destroyed; end each test with `peer^.stop()`, since Mojo destroys a value
right after its last use."""

from std.python import Python, PythonObject


struct HttpPeer(Movable):
    var proc: PythonObject
    var port: Int
    var tls: Bool
    var pki: String

    def __init__(out self, tls: Bool = False, cert: StringSlice = "good") raises:
        """`cert` names the server's certificate in the PKI (TLS only)."""
        var subprocess = Python.import_module("subprocess")
        var pysys = Python.import_module("sys")
        self.tls = tls
        self.pki = _pki() if tls else String()
        var cmd = Python.list(pysys.executable, "tests/http/http_peer.py")
        if tls:
            _ = cmd.append("--tls")
            _ = cmd.append(self.pki)
            _ = cmd.append(String(cert))
        self.proc = subprocess.Popen(
            cmd,
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
        """At 127.0.0.1 (for TLS, the certificate holds that address)."""
        return String("https://" if self.tls else "http://", "127.0.0.1:", self.port, path)

    def named_url(self, path: StringSlice) -> String:
        """At localhost (/etc/hosts; the certificate holds the name too)."""
        return String("https://" if self.tls else "http://", "localhost:", self.port, path)

    def ca(self) -> String:
        """The CA file that makes the TLS peer's certificate valid."""
        return self.pki + "/root.pem"

    def __deinit__(deinit self):
        _kill(self.proc)

    def stop(deinit self):
        _kill(self.proc)


def _pki() raises -> String:
    """A test PKI, made once per process (tests/tls/tls_pki.py; a watcher
    removes it when the process ends)."""
    var os = Python.import_module("os")
    var tempfile = Python.import_module("tempfile")
    var d = String(py=os.path.join(tempfile.gettempdir(), String("mojo_net_tls_", Int(py=os.getpid()))))
    if Bool(py=os.path.exists(d + "/client_only.pem")):
        return d
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var cmd = Python.list(pysys.executable, "tests/tls/tls_pki.py", d, "--owner", String(Int(py=os.getpid())))
    var r = subprocess.run(cmd, capture_output=True, text=True)
    if Int(py=r.returncode) != 0:
        raise Error(String("tls_pki.py failed: ", String(py=r.stderr)))
    return d


def _kill(proc: PythonObject):
    try:
        _ = proc.kill()
        _ = proc.wait()
    except:
        pass
