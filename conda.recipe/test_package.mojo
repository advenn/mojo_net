"""The conda package's own test (conda.recipe/recipe.yaml): each library
imports from the installed sources in `$PREFIX/lib/mojo`, with no `-I src`,
and does one real thing. The full suite runs from the repository
(`pixi run ci`); this checks that the package holds what it should and
compiles where it is installed.
"""

from std.testing import assert_equal, assert_true

from bytes import ByteBuffer
from bytes.base64 import base64_decode, base64_encode
from crypto.sha256 import sha256
from http.parse import HeadParser, RequestHead
from json import Writer, format_float, parse
from llm import ChatRequest, Message
from llm.client import Client, Provider
from llm.openai import read_chat, write_chat
from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpListener, TcpStream
from pg.auth import md5_password
from pg.config import Config as PgConfig
from redis.config import Config as RedisConfig
from redis.resp import RespParser, Value
from server.date import http_date
from tls import Category, ClientConfig, ServerConfig, TlsClient, TlsServer
from tls.stream import TlsStream


def _tcp() raises:
    """`linux` and `net`: a TCP round trip over loopback, with deadlines."""
    var listener = TcpListener.bind(SocketAddr.parse("127.0.0.1:0"))
    var client = TcpStream.connect(listener.local_addr())
    var server = listener.accept().into_stream()
    server.set_deadline(Deadline.after(Duration.from_secs(10)))
    client.write_all("ping".as_bytes())
    var got = List[UInt8](length=4, fill=0)
    server.read_exact(got)
    assert_equal(String(unsafe_from_utf8=got), "ping")
    client^.close()
    server^.close()
    listener^.close()


def _bytes_and_crypto() raises:
    var buf = ByteBuffer()
    buf.write_bytes("mojo".as_bytes())
    assert_equal(base64_encode(buf.readable_span()), "bW9qbw==")
    assert_equal(String(unsafe_from_utf8=base64_decode("bW9qbw==")), "mojo")
    var digest = sha256("abc".as_bytes())  # (FIPS 180-2's first vector)
    assert_equal(Int(digest[0]), 0xBA)
    assert_equal(Int(digest[31]), 0xAD)


def _json() raises:
    """`json`: a document parsed and read, and one written."""
    var doc = parse('{"choices": [{"message": {"content": "hi"}}], "usage": {"total_tokens": 7}}')
    var message = doc.member(doc.child(doc.member(0, "choices"), 0), "message")
    assert_equal(doc.text(doc.member(message, "content")), "hi")
    assert_equal(doc.int(doc.member(doc.member(0, "usage"), "total_tokens")), 7)
    var w = Writer()
    w.begin_object()
    w.key("temperature")
    w.float(0.1)
    w.end_object()
    assert_equal(String(unsafe_from_utf8=Span(w.take())), '{"temperature":0.1}')
    assert_equal(format_float(Float64(0.1) + Float64(0.2)), "0.30000000000000004")


def _llm() raises:
    """`llm`: a chat request written and a reply read (no network)."""
    var body = write_chat(ChatRequest("m", [Message.user("hi")]))
    assert_equal(String(unsafe_from_utf8=Span(body)), '{"model":"m","messages":[{"role":"user","content":"hi"}]}')
    var reply = read_chat('{"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}'.as_bytes())
    assert_equal(reply.text, "hello")
    _ = Client(Provider.OPENAI, "http://localhost:8000/v1")  # (the client compiles here too)


def _protocols() raises:
    """`http`, `server`, `pg` and `redis`: their sans-I/O parts."""
    var parser = HeadParser.for_requests()
    var head = RequestHead()
    var request = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"
    var taken = parser.request(request.as_bytes(), head)
    assert_equal(taken.value(), request.byte_length())
    assert_equal(head.target, "/x")
    assert_equal(String(head.headers.get("host").value()), "example.com")

    assert_equal(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT")

    var pg = PgConfig.parse("postgresql://app@db.internal:5433/orders")
    assert_equal(pg.port, 5433)
    assert_equal(pg.database, "orders")
    var salt: List[UInt8] = [1, 2, 3, 4]
    # (as libpq computes it: "md5" + md5(md5(password + user) + salt), from hashlib)
    assert_equal(md5_password("app", "secret", salt), "md5911f527656472583a006e7727877b33e")

    var r = RedisConfig.parse("redis://cache.internal:6380/2")
    assert_equal(r.port, 6380)
    assert_equal(r.database, 2)
    var rx = ByteBuffer()
    rx.write_bytes("*2\r\n:1\r\n$3\r\nabc\r\n".as_bytes())
    var resp = RespParser()
    assert_true(resp.parse(rx))
    var v = Value()
    resp.take(v)
    assert_equal(v.count(), 2)
    assert_equal(v.int(1), 1)
    assert_equal(v.text(2), "abc")


def _tls() raises:
    """`tls`: the environment's OpenSSL loads, the system CA bundle holds
    roots, and a connection queues a ClientHello (no network needed)."""
    var ctx = ClientConfig().build()
    assert_true(ctx.anchors() > 50, String(ctx))
    var hello = TlsClient(ctx, "example.com")
    var out = ByteBuffer()
    assert_true(hello.poll_transmit(out) > 100)
    assert_equal(Int(out.readable_span()[0]), 22)  # (a handshake record)
    _ = TlsStream.connect  # (the blocking stream compiles here too)
    # The server side: a missing key is refused (no certificate needed).
    var refused = False
    try:
        var server_ctx = ServerConfig(certificate="/nonexistent.pem", key="/nonexistent.key", names=["localhost"]).build()
        _ = TlsServer(server_ctx)
    except e:
        refused = e.category == Category.CREDENTIALS
    assert_true(refused)
    print("tls:", ctx)


def main() raises:
    _tcp()
    _tls()
    _bytes_and_crypto()
    _json()
    _llm()
    _protocols()
    print("mojo-net: every library imports and works")
