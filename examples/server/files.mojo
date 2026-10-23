"""A static file server: the files of DIR at /, through a `Router` and
`StaticFiles`, stopping gracefully on SIGTERM or Ctrl-C.

    pixi run mojo build -I src examples/server/files.mojo -o files
    ./files DIR [ADDR]
    curl -i http://127.0.0.1:8080/              # DIR/index.html
    curl -r 0-99 http://127.0.0.1:8080/big.iso  # a range

No path leaves DIR: "..", symlinks out of it and the like get 404.
Directories serve their index.html; there are no listings.
"""

from std.sys import argv, exit, stderr

from net.addr import SocketAddr
from server import Handler, Params, Request, Response, Router, Server, ServerConfig, StaticFiles, Stop


struct App(Handler):
    var files: StaticFiles

    def __init__(out self, var files: StaticFiles):
        self.files = files^

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(404, "not found\n")

    def produce(mut self, req: Request, mut out: List[UInt8]) raises -> Bool:
        return self.files.produce(req, out)

    def stream_ended(mut self, req: Request, finished: Bool):
        self.files.stream_ended(req)


def serve_file(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.files.serve(req, params["path"], res)


def serve_root(mut app: App, req: Request, params: Params, mut res: Response) raises:
    app.files.serve(req, "", res)


def main() raises:
    var stop = Stop.on_signals()
    var args = argv()
    if len(args) < 2:
        print("usage: files DIR [ADDR]", file=stderr)
        exit(2)
    var addr = String(args[2]) if len(args) > 2 else String("127.0.0.1:8080")
    var router = Router(App(StaticFiles.open(args[1])))
    router.get("/", serve_root)
    router.get("/*path", serve_file)
    var server = Server(router^, ServerConfig(server_name="mojo_net"))
    server.bind(SocketAddr.parse(addr))
    server.stop_on(stop^)
    print("serving", args[1], "on", server.local_addr())
    server.run()
