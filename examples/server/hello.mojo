"""A small HTTP/1.1 server on `server.Server`: "/" says hello, "/echo"
returns the request body, anything else is a 404.

    pixi run mojo run -I src examples/server/hello.mojo [ADDR]
    curl -i http://127.0.0.1:8080/
    curl -i -d 'some text' http://127.0.0.1:8080/echo

ADDR defaults to 127.0.0.1:8080. For several cores, start one process per
core with REUSEPORT=1 on the same address; the kernel spreads the
connections. The handler must not block: one loop serves every connection
of the process.
"""

from std.os import getenv
from std.sys import argv, exit, stderr

from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig


struct App(Handler):
    var requests: Int

    def __init__(out self):
        self.requests = 0

    def handle(mut self, req: Request, mut res: Response) raises:
        self.requests += 1
        var path = req.path()
        if path == "/":
            res.text(200, "Hello, world!\n")
        elif path == "/echo":
            res.bytes(200, Span(req.body), "application/octet-stream")
        else:
            res.text(404, String("no route for ", path, "\n"))


def main() raises:
    var args = argv()
    var addr: SocketAddr
    try:
        addr = SocketAddr.parse(String(args[1]) if len(args) > 1 else String("127.0.0.1:8080"))
    except:
        print("usage: hello [IP:PORT]   (for example 127.0.0.1:8080)", file=stderr)
        exit(2)
        return
    var config = ServerConfig(reuseport=getenv("REUSEPORT") == "1", server_name="mojo-net")
    var server = Server(App(), config)
    server.bind(addr)
    print("listening on", server.local_addr())
    server.run()
