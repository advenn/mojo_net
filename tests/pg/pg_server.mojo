"""A real PostgreSQL for the tests/pg files that need one: a throwaway
cluster from `pg_cluster.py` (users for each authentication method, a TCP
port and a Unix socket).

`PgServer.start()` returns None when no server can run here: initdb is
missing, or this is root, which initdb refuses. With
MOJO_NET_REQUIRE_PG=1 that is an error instead. Stop the server
explicitly, whatever happens in the test (`server.stop()`, which can be
called more than once): it is another process, which outlives the value."""

from std.os import getenv
from std.python import Python, PythonObject

from pg.config import Config

def users() -> List[String]:
    """One per method: trust, password, md5, scram-sha-256 (pg_cluster.py)."""
    return ["trusty", "plain", "md5user", "scram"]


def passwords() -> List[String]:
    return ["", "plain-pw", "md5-pw", "pencil é"]


struct PgServer(Movable):
    var port: Int
    var dir: String

    def __init__(out self, port: Int, dir: String):
        self.port = port
        self.dir = dir

    @staticmethod
    def start() raises -> Optional[PgServer]:
        var shutil = Python.import_module("shutil")
        var os = Python.import_module("os")
        var why = String()
        if String(py=shutil.which("initdb")) == "None":
            why = "no initdb"
        elif Int(py=os.geteuid()) == 0:
            why = "root (initdb refuses it)"
        if why.byte_length() > 0:
            if getenv("MOJO_NET_REQUIRE_PG") == "1":
                raise Error(String("no PostgreSQL to test against: ", why))
            print("    (skipped: no PostgreSQL:", why, ")")
            return None
        var subprocess = Python.import_module("subprocess")
        var sys = Python.import_module("sys")
        var r = subprocess.run(
            Python.list(sys.executable, "tests/pg/pg_cluster.py", "start"), capture_output=True, text=True
        )
        if Int(py=r.returncode) != 0:
            raise Error(String("pg_cluster.py start failed: ", String(py=r.stderr)))
        var out = String(String(py=r.stdout).strip())
        var bar = out.find("|")
        return PgServer(atol(out[byte=0:bar]), String(out[byte = bar + 1 :]))

    def tcp(self, user: String, password: String = "") -> Config:
        return Config(user, host="127.0.0.1", port=self.port, password=password, database="postgres")

    def unix(self, user: String, password: String = "") -> Config:
        return Config(user, host=self.dir, port=self.port, password=password, database="postgres")

    def stop(self) raises:
        var subprocess = Python.import_module("subprocess")
        var sys = Python.import_module("sys")
        _ = subprocess.run(Python.list(sys.executable, "tests/pg/pg_cluster.py", "stop", self.dir), capture_output=True)
