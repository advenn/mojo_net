"""Our side of tools/smuggling/compare.py: `http.ServerConnection` reading
request streams, one per line of the file named by its argument, in hex.
For each it prints one line: the requests it read, "METHOD TARGET BODYLEN"
joined by "|", then "|close" if the codec would close the connection
there (it reads no further), or "|error" if it refused the input. Each
request gets an empty 200, as a server would answer it, so that the next
one is read."""

from std.sys import argv

from bytes.buffer import ByteBuffer
from http.connection import EventKind, ServerConnection, ServerEvent
from http.parse import ResponseHead
from linux.fs import read_file


def _nibble(b: UInt8) -> UInt8:
    return b - 48 if b <= 57 else (b | 32) - 87


def _stream(hex: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(hex) // 2)
    for i in range(0, len(hex) - 1, 2):
        out.append(_nibble(hex[i]) * 16 + _nibble(hex[i + 1]))
    return out^


def _read(data: Span[UInt8, _]) -> String:
    var got = List[String]()
    try:
        _requests(data, got)
    except:
        got.append("error")
    var line = String()
    for i in range(len(got)):
        if i > 0:
            line += "|"
        line += got[i]
    return line^


def _requests(data: Span[UInt8, _], mut got: List[String]) raises:
    var codec = ServerConnection()
    var ev = ServerEvent(EventKind.END)
    var out = ByteBuffer()
    var method = String()
    var target = String()
    var body = 0
    codec.feed(data)
    codec.feed_eof()
    while codec.poll(ev):
        if ev.kind == EventKind.HEAD:
            method = String(ev.head().method)
            target = String(ev.head().target)
            body = 0
        elif ev.kind == EventKind.DATA:
            body += len(ev.data)
        elif ev.kind == EventKind.END:
            got.append(String(method, " ", target, " ", body))
            var res = ResponseHead(200)
            res.headers.add("Content-Length", "0")
            codec.send_response(res)
            codec.end_response()
            while codec.poll_transmit(out) > 0:
                out.clear()
            if codec.should_close():
                got.append("close")
                return


def main() raises:
    var text = read_file(String(argv()[1]), "smuggling: read", max_bytes=1 << 30)
    var out = String()
    var start = 0
    for i in range(len(text) + 1):
        if i == len(text) or text[i] == 10:
            if i > start:
                out += _read(Span(_stream(Span(text)[start:i])))
                out += "\n"
            start = i + 1
    print(out, end="")
