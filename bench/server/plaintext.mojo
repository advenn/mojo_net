"""The mojo_net server for bench/server/run.py: GET /plaintext answers
"Hello, World!" (TechEmpower's plaintext test); anything else is a 404.

    pixi run mojo build -I src bench/server/plaintext.mojo -o bench/server/out/plaintext
    WORKERS=0 bench/server/out/plaintext 127.0.0.1:8080   # one process
    WORKERS=4 bench/server/out/plaintext 127.0.0.1:8080   # 4 workers, each pinned to a CPU

With WORKERS > 0 a supervisor runs that many worker processes on one port
(SO_REUSEPORT), each kept on one CPU of the supervisor's affinity mask.
Each serving process prints "LISTEN <addr> pid=<pid>" once it is bound.
SIGTERM stops it gracefully.
"""

from std.os import getenv
from std.sys import argv

from linux.nr import SYS_getpid
from linux.syscall import syscall0
from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig, Stop, WorkerConfig, run_workers


struct App(Handler):
    def __init__(out self):
        pass

    def handle(mut self, req: Request, mut res: Response) raises:
        if req.path() == "/plaintext":
            res.text(200, "Hello, World!")
        else:
            res.text(404, "not found\n")


def main() raises:
    var n = atol(getenv("WORKERS", "0"))
    var stop: Stop
    if n == 0:
        stop = Stop.on_signals()
    else:
        var w = run_workers(WorkerConfig(workers=n, pin=True, log=False))
        if not w:
            return  # the supervisor: its workers have ended
        stop = w.take()
    var addr = String(argv()[1]) if len(argv()) > 1 else String("127.0.0.1:8080")
    var server = Server(App(), ServerConfig(reuseport=n > 0, server_name="mojo-net"))
    server.bind(SocketAddr.parse(addr))
    server.stop_on(stop^)
    print("LISTEN", server.local_addr(), String("pid=", syscall0(SYS_getpid)), flush=True)
    server.run()
