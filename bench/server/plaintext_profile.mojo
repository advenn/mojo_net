"""bench/server/plaintext.mojo for `profile.py`: the same server and
handler, one process, without `Stop`. `Stop.on_signals()` re-executes the
program to block SIGTERM in every thread, and valgrind cannot load the
re-executed program, so this one sets up no signals and is killed when the
profile is taken.

    WORKERS=0 valgrind --tool=callgrind bench/server/out/plaintext_profile 127.0.0.1:8080
"""

from std.sys import argv

from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig


struct App(Handler):
    def __init__(out self):
        pass

    def handle(mut self, req: Request, mut res: Response) raises:
        if req.path() == "/plaintext":
            res.text(200, "Hello, World!")
        else:
            res.text(404, "not found\n")


def main() raises:
    var addr = String(argv()[1]) if len(argv()) > 1 else String("127.0.0.1:8080")
    var server = Server(App(), ServerConfig(server_name="mojo-net"))
    server.bind(SocketAddr.parse(addr))
    print("LISTEN", server.local_addr(), flush=True)
    server.run()
