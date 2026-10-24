"""A real server for the tests/redis files that need one: a throwaway
Valkey from `valkey_server.py` (users alice and reader besides the default
one, a TCP port and a Unix socket).

`RedisServer.start()` returns None when no server can run here
(`valkey-server` is missing); with MOJO_NET_REQUIRE_REDIS=1 that is an
error instead. Stop the server explicitly, whatever happens in the test
(`server.stop()`, which can be called more than once): it is another
process, which outlives the value. (If the test process crashes, the
server's watcher stops it.)"""

from std.os import getenv
from std.python import Python, PythonObject

from redis.config import Config


struct RedisServer(Movable):
    var port: Int
    var dir: String

    def __init__(out self, port: Int, dir: String):
        self.port = port
        self.dir = dir

    @staticmethod
    def start(requirepass: String = "", no_hello: Bool = False) raises -> Optional[RedisServer]:
        var shutil = Python.import_module("shutil")
        var os = Python.import_module("os")
        if String(py=shutil.which("valkey-server")) == "None":
            if getenv("MOJO_NET_REQUIRE_REDIS") == "1":
                raise Error("no server to test against: no valkey-server")
            print("    (skipped: no valkey-server)")
            return None
        var subprocess = Python.import_module("subprocess")
        var sys = Python.import_module("sys")
        var me = String(Int(py=os.getpid()))  # (watched: a crash cannot leave the server running)
        var command = Python.list(sys.executable, "tests/redis/valkey_server.py", "start", me)
        if requirepass.byte_length() > 0:
            _ = command.append("--requirepass")
            _ = command.append(requirepass)
        if no_hello:
            _ = command.append("--no-hello")
        var r = subprocess.run(command, capture_output=True, text=True)
        if Int(py=r.returncode) != 0:
            raise Error(String("valkey_server.py start failed: ", String(py=r.stderr)))
        var out = String(String(py=r.stdout).strip())
        var bar = out.find("|")
        return RedisServer(atol(out[byte=0:bar]), String(out[byte = bar + 1 :]))

    def tcp(self, user: String = "", password: String = "") -> Config:
        return Config("127.0.0.1", port=self.port, user=user, password=password)

    def unix(self, user: String = "", password: String = "") -> Config:
        return Config(self.socket_path(), user=user, password=password)

    def socket_path(self) -> String:
        return String(self.dir, "/valkey.sock")

    def stop(self) raises:
        var subprocess = Python.import_module("subprocess")
        var sys = Python.import_module("sys")
        _ = subprocess.run(Python.list(sys.executable, "tests/redis/valkey_server.py", "stop", self.dir), capture_output=True)
