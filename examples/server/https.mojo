"""An HTTPS server on `server.Server` (docs/server.md, "TLS"): "/" says
hello, over TLS through OpenSSL, with the certificate reloaded when its
files change.

    pixi run mojo build -I src examples/server/https.mojo -o https
    ./https CERT KEY NAME [ADDR]
    curl --cacert ROOT https://NAME:8443/

CERT is the chain file (the leaf, then its intermediates: certbot's
fullchain.pem), KEY the unencrypted key (privkey.pem), readable by its
owner alone; NAME the host name it is for. ADDR defaults to
127.0.0.1:8443. With workers (examples/server/workers.mojo), each worker
calls `serve_tls` itself, after `run_workers`.
"""

from std.sys import argv, exit, stderr

from net.addr import SocketAddr
from server import Handler, Request, Response, Server, ServerConfig
from tls import ServerConfig as TlsConfig


struct App(Handler):
    def __init__(out self):
        pass

    def handle(mut self, req: Request, mut res: Response) raises:
        res.text(200, String("Hello over TLS, ", req.host(), "!\n"))


def main() raises:
    var args = argv()
    if len(args) < 4:
        print("usage: https CERT KEY NAME [ADDR]", file=stderr)
        exit(2)
    var addr = SocketAddr.parse(String(args[4]) if len(args) > 4 else "127.0.0.1:8443")
    var server = Server(App(), ServerConfig(server_name="mojo_net"))
    server.bind(addr)
    server.serve_tls(TlsConfig(certificate=String(args[1]), key=String(args[2]), names=[String(args[3])]))
    print("serving https on", server.local_addr())
    server.run()
