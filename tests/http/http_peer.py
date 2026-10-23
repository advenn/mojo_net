"""An HTTP/1.1 server for the client tests (test-only Python; src/ never
uses it). It is Python's http.server, so the client is checked against an
independent implementation.

    python http_peer.py      prints "PORT <n>" once it listens on 127.0.0.1

Routes:
    GET  /hello            "hello", Content-Length
    HEAD /hello            the same head, no body
    GET  /conn             the id of the connection (1, 2, ... in accept order)
    GET  /headers          the request's field lines, one "name: value" per line
    GET  /chunked          "Wiki" "pedia" chunked, with a trailer X-Sum: 2
    GET  /big?n=N          N bytes of "x"
    GET  /close            a response with Connection: close, then the server closes
    GET  /http10           an HTTP/1.0 response without a length, then close
    GET  /slow             answers after 5 s
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
"""

import http.server
import itertools
import socket
import sys
import threading
import time

_ids = itertools.count(1)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
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
        else:
            self._send(404, b"not found")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = _route


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # clients that give up mid-response (the tests make some do so)


def main():
    server = Server(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    print("PORT", server.server_address[1], flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sys.stdin.read()  # until the test closes our stdin (or kills us)


if __name__ == "__main__":
    main()
