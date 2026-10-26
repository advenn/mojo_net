"""Fetch a page over HTTPS with a raw HTTP/1.1 request on a `TlsStream`
(docs/tls.md). The certificate is checked against the system's CA bundle.

    pixi run mojo run -I src examples/tls/tls_get.mojo example.com /

Prints the negotiated protocol and the response's status line and headers.
For real HTTP use `http.client` (https:// URLs come with milestone H8).
"""

from std.sys import argv

from linux.time import Duration
from tls import ClientConfig
from tls.stream import TlsStream


def main() raises:
    var args = argv()
    var host = String(args[1]) if len(args) > 1 else String("example.com")
    var path = String(args[2]) if len(args) > 2 else String("/")
    var ctx = ClientConfig().build()
    print(ctx)
    var s = TlsStream.connect(host, 443, ctx, Duration.from_secs(10))
    print(s, s.group())
    var request = String("GET ", path, " HTTP/1.1\r\nHost: ", host, "\r\nConnection: close\r\n\r\n")
    s.write_all(request.as_bytes())
    var body = List[UInt8]()
    var buf = List[UInt8](length=16384, fill=0)
    try:
        while True:
            var n = s.read(Span(buf))
            if n == 0:
                break
            body.extend(Span(buf)[0:n])
    except e:
        # Many servers end the TCP connection without close_notify after a
        # "Connection: close" response: TLS reports that as a truncation,
        # and only HTTP's framing could say the response was complete.
        print("(the stream ended with:", e, ")")
    var text = String(from_utf8_lossy=Span(body))
    var head_end = text.find("\r\n\r\n")
    print(text[byte = 0 : head_end if head_end >= 0 else min(text.byte_length(), 2000)])
