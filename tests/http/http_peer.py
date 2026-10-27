"""An HTTP/1.1 server for the client tests (test-only Python; src/ never
uses it). It is Python's http.server, so the client is checked against an
independent implementation.

    python http_peer.py              prints "PORT <n>" once it listens on 127.0.0.1
    python http_peer.py --tls <dir> [name]
                                     the same over TLS, with <dir>/<name>.chain.pem
                                     and <name>.key (default: good; made by
                                     tests/tls/tls_pki.py)

Routes:
    GET  /hello            "hello", Content-Length
    HEAD /hello            the same head, no body
    GET  /conn             the id of the connection (1, 2, ... in accept order)
    GET  /headers          the request's field lines, one "name: value" per line
    GET  /chunked          "Wiki" "pedia" chunked, with a trailer X-Sum: 2
    GET  /big?n=N          N bytes of "x"
    GET  /close            a response with Connection: close, then the server closes
    GET  /http10           an HTTP/1.0 response without a length, then close
                           (over TLS: without close_notify, so cut short as far
                           as the client can tell)
    GET  /http10-notify    the same, ended by close_notify over TLS
    *    /bye-later        "ok" with keep-alive, then 200 ms later the server closes
                           the idle connection (with close_notify over TLS)
    GET  /slow             answers after 5 s
    GET  /sse?n=N          N server-sent events (chunked), 20 ms apart: id 1..N,
                           event "tick" for odd ids, data "n=<id>", a comment
                           between, then "data: [DONE]"
    GET  /sse-forever      an event every 20 ms until the client goes away; then
                           /cancelled counts it
    GET  /cancelled        how many /sse-forever streams ended by the client leaving
    GET  /not-sse          a chunked text/plain body
    GET  /typed?t=X        the same with Content-Type X (percent-decoded)
    *    /flaky            the first request on a connection gets "ok"; any later
                           one is read and the connection closed without an answer
    POST|PUT /echo         the request body back (Content-Length or chunked request)
    PUT  /count            reads the body in pieces and answers its length
    PUT  /echo-stream      answers at once and echoes the body as it arrives (full duplex)
    PUT  /reject-hold      an early 413 without reading the body, then 5 s of not reading
    GET  /left             "first", plus an unsolicited second response in the same write
    HEAD /head0            a HEAD response followed by a stray last chunk "0\r\n\r\n"
    GET  /1xx              a stream of 100 Continue responses for 5 s, then "late"
    GET  /drip             Content-Length 50, one byte every 100 ms
    PUT  /rst-closedelim   reads 2 MiB of the body, answers "PARTIAL" delimited by
                           the close, keeps reading 50 ms, then resets (RST)
    PUT  /rst-framed       the same with a whole 413 (Content-Length 4, "full")
    PUT  /early-ok         answers 200 "ok" (keep-alive) at once, then reads the body
    GET  /early-got        how many body bytes the last /early-ok read (once it is done)
    PUT  /flood            a 200 delimited by the close, then "x" without end; never reads
    *    /stale408         "ok" to the first request on a connection; a later one gets
                           408 with Connection: close (an idle timeout racing it)
"""

import http.server
import itertools
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse

_ids = itertools.count(1)
_cancelled = [0]
_early_done = threading.Event()
_early_got = [0]


def _reset(sock):
    """Close `sock` with an RST (SO_LINGER 0)."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()  # (in this connection's thread)
        super().setup()
        self.conn_id = next(_ids)
        self.served = 0

    def log_message(self, *args):
        pass

    def _send(self, status, body, headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _chunk(self, data):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def _read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return out
                out += self.rfile.read(size)
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def _route(self):
        self.served += 1
        path = self.path
        if path == "/flaky":
            if self.served > 1:
                self._read_body()
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self._read_body()
            self._send(200, b"ok")
        elif path == "/hello":
            self._send(200, b"hello", [("Content-Type", "text/plain")])
        elif path == "/conn":
            self._send(200, str(self.conn_id).encode())
        elif path == "/headers":
            lines = "".join(f"{k}: {v}\n" for k, v in self.headers.items())
            self._send(200, lines.encode())
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Sum")
            self.end_headers()
            self.wfile.write(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Sum: 2\r\n\r\n")
        elif path.startswith("/big?n="):
            self._send(200, b"x" * int(path[7:]))
        elif path == "/close":
            self._send(200, b"bye", [("Connection", "close")])
            self.close_connection = True
        elif path == "/http10":
            self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nold style")
            self.close_connection = True
        elif path == "/http10-notify":
            self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nold style")
            self.close_connection = True
            if isinstance(self.connection, ssl.SSLSocket):
                try:
                    self.connection.unwrap()  # (close_notify, then the client's)
                except (ssl.SSLError, OSError):
                    pass
        elif path == "/bye-later":
            self._read_body()
            self._send(200, b"ok")
            self.wfile.flush()
            time.sleep(0.2)
            self.close_connection = True
            if isinstance(self.connection, ssl.SSLSocket):
                self.connection.settimeout(2)
                try:
                    self.connection.unwrap()
                except (ssl.SSLError, OSError):
                    pass
            else:
                self.connection.shutdown(socket.SHUT_RDWR)
        elif path.startswith("/sse?n="):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(1, int(path[7:]) + 1):
                ev = f"id: {i}\n" + ("event: tick\n" if i % 2 else "") + f"data: n={i}\n\n: between\n"
                self._chunk(ev.encode())
                time.sleep(0.02)
            self._chunk(b"data: [DONE]\n\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/sse-forever":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.close_connection = True
            try:
                i = 0
                while True:
                    i += 1
                    self._chunk(f"data: {i}\n\n".encode())
                    time.sleep(0.02)
            except OSError:
                _cancelled[0] += 1
        elif path == "/cancelled":
            self._send(200, str(_cancelled[0]).encode())
        elif path == "/not-sse" or path.startswith("/typed?t="):
            self.send_response(200)
            ctype = "text/plain" if path == "/not-sse" else urllib.parse.unquote(path[9:])
            self.send_header("Content-Type", ctype)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self._chunk(b"data: no\n\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/slow":
            time.sleep(5)
            self._send(200, b"late")
        elif path == "/echo" and self.command in ("POST", "PUT"):
            self._send(200, self._read_body(), [("X-Method", self.command)])
        elif path == "/count":
            left = int(self.headers.get("Content-Length", "0"))
            total = 0
            while left > 0:
                d = self.rfile.read(min(1 << 20, left))
                if not d:
                    break
                total += len(d)
                left -= len(d)
            self._send(200, str(total).encode())
        elif path == "/echo-stream":
            n = int(self.headers.get("Content-Length", "0"))
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.end_headers()
            self.wfile.flush()
            left = n
            while left > 0:
                d = self.rfile.read1(min(65536, left))
                if not d:
                    return
                self.wfile.write(d)
                self.wfile.flush()
                left -= len(d)
        elif path == "/reject-hold":
            self.wfile.write(b"HTTP/1.1 413 Content Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            self.wfile.flush()
            time.sleep(5)  # neither reads the body nor closes
            self.close_connection = True
        elif path == "/left":
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst"
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nEVIL!"
            )
        elif path == "/head0" and self.command == "HEAD":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        elif path == "/1xx":
            blob = b"HTTP/1.1 100 Continue\r\n\r\n" * 1000
            end = time.time() + 5
            while time.time() < end:
                self.wfile.write(blob)
            self._send(200, b"late")
        elif path == "/drip":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n")
            self.wfile.flush()
            for _ in range(50):
                time.sleep(0.1)
                self.wfile.write(b"x")
                self.wfile.flush()
        elif path in ("/rst-closedelim", "/rst-framed"):
            got = 0
            while got < 2 * 1024 * 1024:
                d = self.rfile.read1(65536)
                if not d:
                    break
                got += len(d)
            if path == "/rst-closedelim":
                self.wfile.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nPARTIAL")
            else:
                self.wfile.write(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 4\r\n\r\nfull")
            self.wfile.flush()
            sock = self.connection
            sock.setblocking(False)
            buf = bytearray(1 << 20)
            end = time.time() + 0.05
            while time.time() < end:  # (busy: the client is mid-send at the reset)
                try:
                    sock.recv_into(buf)
                except BlockingIOError:
                    pass
            self.close_connection = True
            _reset(sock)
        elif path == "/early-ok":
            _early_done.clear()
            want = int(self.headers.get("Content-Length", "0"))
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            self.wfile.flush()
            got = 0
            while got < want:
                d = self.rfile.read1(min(1 << 20, want - got))
                if not d:
                    self.close_connection = True
                    break
                got += len(d)
            _early_got[0] = got
            _early_done.set()
        elif path == "/early-got":
            _early_done.wait(5)
            self._send(200, str(_early_got[0]).encode())
        elif path == "/flood":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            blob = b"x" * (1 << 20)
            try:
                while True:
                    self.wfile.write(blob)
            except OSError:
                pass
            self.close_connection = True
        elif path == "/partial-rst":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial")
            self.wfile.flush()
            time.sleep(0.1)
            self.close_connection = True
            _reset(self.connection)
        elif path in ("/te-gzip", "/te-http10"):
            # A body under a coding the client does not decode, or with
            # Transfer-Encoding in HTTP/1.0 (RFC 9112 6.1: faulty framing).
            version, te = {
                "/te-gzip": (b"1.1", b"gzip, chunked"),
                "/te-http10": (b"1.0", b"chunked"),
            }[path]
            self.wfile.write(b"HTTP/" + version + b" 200 OK\r\nTransfer-Encoding: " + te + b"\r\n\r\n")
            if self.command != "HEAD":
                self.wfile.write(b"5\r\nhello\r\n0\r\n\r\n")
            self.close_connection = True
        elif path == "/huge-cl":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\n")
            self.wfile.flush()
            time.sleep(5)  # (the body never comes)
            self.close_connection = True
        elif path == "/stale408":
            if self.served > 1:
                self.wfile.write(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                self.close_connection = True
                return
            self._send(200, b"ok")
        else:
            self._send(404, b"not found")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _route


class Server(http.server.ThreadingHTTPServer):
    tls = None

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls is not None:
            sock = self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        pass  # clients that give up mid-response (the tests make some do so)


def main():
    server = Server(("127.0.0.1", 0), Handler)
    if len(sys.argv) >= 3 and sys.argv[1] == "--tls":
        name = sys.argv[3] if len(sys.argv) > 3 else "good"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{sys.argv[2]}/{name}.chain.pem", f"{sys.argv[2]}/{name}.key")
        ctx.set_alpn_protocols(["http/1.1"])
        server.tls = ctx
    server.daemon_threads = True
    print("PORT", server.server_address[1], flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sys.stdin.read()  # until the test closes our stdin (or kills us)


if __name__ == "__main__":
    main()
