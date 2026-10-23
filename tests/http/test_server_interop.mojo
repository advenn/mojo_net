"""`ServerConnection` over a real socket against Python's http.client as
the client (an independent implementation): keep-alive across requests,
Content-Length and chunked request bodies, HEAD, chunked and fixed-length
responses, Connection: close; and pipelined raw requests whose responses
Python's response parser reads back in order."""

from std.python import Python, PythonObject
from std.testing import TestSuite, assert_equal, assert_true

from bytes.buffer import ByteBuffer
from http.connection import EventKind, ServerConnection
from http.parse import ResponseHead
from linux import IoError
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpListener, TcpStream

comptime _CLIENT = """
import http.client, io, socket, sys
port = int(sys.argv[1])
mode = sys.argv[2]
out = []
if mode == "client":
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/hello")
    r = c.getresponse(); out.append(f"{r.status} {r.read().decode()} {r.getheader('Transfer-Encoding')}")
    c.request("POST", "/echo", body=b"posted body")
    r = c.getresponse(); out.append(f"{r.status} {r.read().decode()}")
    c.request("PUT", "/echo", body=iter([b"chunk one ", b"chunk two"]), encode_chunked=True)
    r = c.getresponse(); out.append(f"{r.status} {r.read().decode()}")
    c.request("HEAD", "/hello")
    r = c.getresponse(); out.append(f"{r.status} [{r.read().decode()}] {r.getheader('Transfer-Encoding')}")
    c.request("GET", "/fixed")
    r = c.getresponse(); out.append(f"{r.status} {r.read().decode()} {r.getheader('Content-Length')}")
    c.request("GET", "/bye", headers={"Connection": "close"})
    r = c.getresponse(); out.append(f"{r.status} {r.read().decode()} {r.getheader('Connection')}")
else:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"GET /a HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"
              b"POST /echo HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 3\\r\\n\\r\\nabc"
              b"GET /c HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n")
    data = b""
    while True:  # the server closes after the third answer (Connection: close)
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    class NoClose(io.BufferedReader):
        def close(self):
            pass
    class Sock:
        def __init__(self, f):
            self.f = f
        def makefile(self, mode):
            return self.f
    f = NoClose(io.BytesIO(data))
    for _ in range(3):  # Python's response parser, one response after another
        r = http.client.HTTPResponse(Sock(f))
        r.begin()
        out.append(f"{r.status} {r.read().decode()}")
print("|".join(out), flush=True)
"""


def _respond(mut s: ServerConnection, target: String, body: List[UInt8]) raises IoError:
    """The routes: /echo returns the body; /fixed answers with a length;
    anything else says hello, chunked (the codec's choice)."""
    if target == "/echo":
        var r = ResponseHead(200)
        r.headers.add("Content-Length", String(len(body)))
        s.send_response(r)
        s.send_body(Span(body))
    elif target == "/fixed":
        var r = ResponseHead(200)
        r.headers.add("Content-Length", "5")
        s.send_response(r)
        s.send_body("fixed".as_bytes())
    else:
        s.send_response(ResponseHead(200))
        s.send_body(String("hello from ", target).as_bytes())
    s.end_response()


def _serve(mut stream: TcpStream) raises -> Int:
    """Drive one connection to its end; return how many requests it served."""
    var s = ServerConnection()
    var buf = List[UInt8](length=16384, fill=0)
    var out = ByteBuffer()
    var served = 0
    var target = String()
    var body = List[UInt8]()
    while True:
        while True:
            var got = s.next_event()
            if not got:
                break
            var ev = got.take()
            if ev.kind == EventKind.HEAD:
                target = ev.take_head().target
                body.clear()
            elif ev.kind == EventKind.DATA:
                body.extend(Span(ev.data))
            else:
                _respond(s, target, body)
                served += 1
        while s.poll_transmit(out) > 0:
            stream.write_all(out.readable_span())
            out.clear()
        if s.should_close():
            return served
        var n = stream.read(Span(buf)[0 : min(len(buf), s.feed_capacity())])
        if n == 0:
            s.feed_eof()
        else:
            s.feed(Span(buf)[0:n])


def _run(mode: StaticString, expect_served: Int) raises -> String:
    var listener = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var port = Int(listener.local_addr().port())
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var proc = subprocess.Popen(
        Python.list(pysys.executable, "-c", _CLIENT, String(port), mode),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    listener.set_deadline(Deadline.after(Duration.from_secs(10)))
    var stream = listener.accept()^.into_stream()
    stream.set_deadline(Deadline.after(Duration.from_secs(10)))
    var served = _serve(stream)
    stream^.close()
    var output = String(py=proc.communicate()[0])
    assert_equal(served, expect_served, output)
    return String(output.strip())


def test_python_http_client_against_the_server_codec() raises:
    var got = _run("client", 6)
    var want = String(
        "200 hello from /hello chunked",
        "|200 posted body",
        "|200 chunk one chunk two",
        "|200 [] None",
        "|200 fixed 5",
        "|200 hello from /bye close",
    )
    assert_equal(got, want)


def test_pipelined_requests_answered_in_order() raises:
    assert_equal(_run("pipelined", 3), "200 hello from /a|200 abc|200 hello from /c")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
