"""Worker processes on one port: a supervisor starts one per CPU (or
WORKERS of them), restarts those that die, and on SIGTERM or Ctrl-C stops
them gracefully (requests in progress finish); a second signal stops them
at once.

    pixi run mojo build -I src examples/server/workers.mojo -o workers
    ./workers [ADDR]
    curl http://127.0.0.1:8080/        # hello from worker 2 (pid 12345)

Run the built binary: under `mojo run`, every worker compiles the program
again. WORKERS=0 serves from this one process, which also stops gracefully
on SIGTERM. Workers bind with SO_REUSEPORT, and the kernel spreads the
connections over them.
"""

from std.os import getenv
from std.sys import argv

from linux.nr import SYS_getpid
from linux.syscall import syscall0
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig, Stop, WorkerConfig, run_workers


struct App(Handler):
    var worker: Int
    var pid: Int

    def __init__(out self, worker: Int, pid: Int):
        self.worker = worker
        self.pid = pid

    def handle(mut self, req: Request, mut res: Response) raises:
        var path = req.path()
        if path == "/":
            res.text(200, String("hello from worker ", self.worker, " (pid ", self.pid, ")\n"))
        elif path == "/pid":
            res.text(200, String(self.worker, " ", self.pid))
        elif path == "/upload":
            res.text(200, String("got ", len(req.body)))
        else:
            res.text(404, "not found\n")


def main() raises:
    var n = atol(getenv("WORKERS", "-1"))
    var stop: Stop
    if n == 0:
        stop = Stop.on_signals()  # one process
    else:
        var w = run_workers(WorkerConfig(workers=max(n, 0)))
        if not w:
            return  # the supervisor: its workers have ended
        stop = w.take()
    var addr = String(argv()[1]) if len(argv()) > 1 else String("127.0.0.1:8080")
    var server = Server(App(stop.worker, syscall0(SYS_getpid)), ServerConfig(reuseport=True))
    server.bind(SocketAddr.parse(addr))
    server.stop_on(stop^)
    server.run()
