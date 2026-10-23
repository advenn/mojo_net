"""The program `tests/server/test_workers.mojo` builds and runs: a server
under `run_workers` (WORKERS of them; 0 for one process with
`Stop.on_signals`). PIN=1 pins the workers; CRASH=1 makes every worker
exit with status 3 as soon as it starts; STUBBORN=1 makes the workers
ignore stop requests (no `stop_on`); STOP_TIMEOUT_MS sets the
supervisor's `stop_timeout`. Routes: /pid ("<worker> <pid>"),
/upload (the body's length), /threads ("<threads> <Cpus_allowed_list>"
of the worker)."""

from std.os import getenv
from std.sys import argv, exit

from linux.fs import read_file
from linux.nr import SYS_getpid
from linux.process import threads
from linux.syscall import syscall0
from linux.time import Duration
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig, Stop, WorkerConfig, run_workers


def _cpus_allowed() raises -> String:
    var text = String(from_utf8_lossy=Span(read_file("/proc/self/status", "status")))
    for line in text.split("\n"):
        if line.startswith("Cpus_allowed_list:"):
            return String(line[byte=18:].strip())
    return String("?")


struct App(Handler):
    var worker: Int
    var pid: Int

    def __init__(out self, worker: Int, pid: Int):
        self.worker = worker
        self.pid = pid

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/pid":
            res.text(200, String(self.worker, " ", self.pid))
        elif path == "/upload":
            res.text(200, String("got ", len(req.body)))
        elif path == "/threads":
            res.text(200, String(len(threads()), " ", _cpus_allowed()))
        else:
            res.text(404, "")


def main() raises:
    var n = atol(getenv("WORKERS", "2"))
    var stop: Stop
    if n == 0:
        stop = Stop.on_signals()
    else:
        var config = WorkerConfig(workers=n, pin=getenv("PIN") == "1")
        var timeout = getenv("STOP_TIMEOUT_MS")
        if timeout.byte_length() > 0:
            config.stop_timeout = Duration.from_millis(atol(timeout))
        var w = run_workers(config)
        if not w:
            return
        stop = w.take()
        if getenv("CRASH") == "1":
            exit(3)
    var server = Server(App(stop.worker, syscall0(SYS_getpid)), ServerConfig(reuseport=True))
    server.bind(SocketAddr.parse(String(argv()[1])))
    if getenv("STUBBORN") != "1":
        server.stop_on(stop^)
    server.run()
