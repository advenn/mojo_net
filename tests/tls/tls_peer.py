"""A TLS server for tests/tls, written with Python's `ssl` module (test-only
Python; started by tests/tls/tls_util.mojo, not a test file itself).

    python tests/tls/tls_peer.py <pki dir> <mode> [key=value ...]

Prints "PORT <n>", then serves `count` connections (default 1) one after
another, printing for each: "SNI <name or ->" when the ClientHello
arrives, "OK <version> <alpn or ->" once the handshake succeeds, then the
mode's own lines; "SERVER_ERROR <reason>" if the handshake fails (the
client refused it, or the server did).

Modes, after the handshake:
  echo      read a line, answer "echo:" + the line, then `big` bytes (0)
            of a pattern (byte i is i % 251), then close_notify
  truncate  read a line, send "partial", close the TCP connection
            without close_notify
  sink      read until the client's close_notify, or an error, print
            "GOT <bytes> close_notify" or "GOT <bytes> error:<reason>",
            then close_notify
  hello     send "hello" and close_notify without reading
  stall     say nothing for 5 s, then close
  bye       close_notify at once (unwrap), print "DONE"
  drip      send `records` (40000) one-byte records, then close_notify
  stale     (memory BIOs) read a line, answer "echo:" + it, then send all
            of one more record ("stale") but its last byte, print "HELD",
            wait 1.5 s, send the last byte, close
  tamper    (memory BIOs) read a line, answer "echo:" + it with the last
            bit of its record flipped, then print "ALERT <reason>" for
            the alert the client sends back, or "NO_ALERT"
Modes without TLS:
  garbage   send an HTTP response instead of a ServerHello, then close
  silent    accept and say nothing for 10 s

Options:
  cert=<name>    the certificate (default good): <name>.chain.pem, <name>.key
  nochain=1      send <name>.pem alone, without its intermediates
  min=, max=     protocol bounds: 1.0 1.1 1.2 1.3
  ciphers=<s>    TLS 1.2 cipher list (OpenSSL syntax)
  seclevel=0     let the server use weak keys and versions
  alpn=<a,b>     protocols the server will choose from
  big=<n>        bytes the echo mode sends after the echo
  count=<n>      connections to serve
  delay=<s>      seconds the sink waits before it starts reading
  rcvbuf=<n>     SO_RCVBUF of the connections (a small receive window)
  tickets=<n>    TLS 1.3 session tickets sent after the handshake (2)
  records=<n>    records the drip mode sends
  host=<addr>    the address to listen on (default 127.0.0.1; ::1 for IPv6)
  quiet=1        print only the PORT line (for long runs whose output
                 nobody reads: a full pipe would block the server)
"""

import socket
import ssl
import sys
import builtins
import time
import warnings

warnings.simplefilter("ignore", DeprecationWarning)  # (TLS 1.0 and 1.1, on purpose)

VERSIONS = {
    "1.0": ssl.TLSVersion.TLSv1,
    "1.1": ssl.TLSVersion.TLSv1_1,
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}


def pattern(n):
    block = bytes(i % 251 for i in range(251 * 64))
    out = bytearray()
    while len(out) < n:
        out += block
    return bytes(out[:n])


def context(d, opts):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ciphers = opts.get("ciphers", "DEFAULT")
    if opts.get("seclevel") == "0":
        ciphers += ":@SECLEVEL=0"
    ctx.set_ciphers(ciphers)
    if "min" in opts:
        ctx.minimum_version = VERSIONS[opts["min"]]
    if "max" in opts:
        ctx.maximum_version = VERSIONS[opts["max"]]
    name = opts.get("cert", "good")
    chain = f"{d}/{name}.pem" if opts.get("nochain") == "1" else f"{d}/{name}.chain.pem"
    ctx.load_cert_chain(chain, f"{d}/{name}.key")
    if "alpn" in opts:
        ctx.set_alpn_protocols(opts["alpn"].split(","))
    if "tickets" in opts:
        ctx.num_tickets = int(opts["tickets"])
    ctx.sni_callback = lambda sock, name, c: print("SNI", name or "-", flush=True)
    return ctx


def read_line(s):
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def serve(ctx, c, mode, opts):
    if mode == "garbage":
        c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        c.close()
        print("SENT garbage", flush=True)
        return
    if mode == "silent":
        time.sleep(10)
        c.close()
        return
    if mode == "stale":
        serve_stale(ctx, c)
        return
    if mode == "tamper":
        serve_tamper(ctx, c)
        return
    try:
        s = ctx.wrap_socket(c, server_side=True)
    except (ssl.SSLError, OSError) as e:
        print("SERVER_ERROR", getattr(e, "reason", None) or type(e).__name__, flush=True)
        c.close()
        return
    print("OK", s.version(), s.selected_alpn_protocol() or "-", flush=True)
    try:
        if mode == "echo":
            line = read_line(s)
            s.sendall(b"echo:" + line + pattern(int(opts.get("big", "0"))))
            s.unwrap()
        elif mode == "truncate":
            read_line(s)
            s.sendall(b"partial")
            s.close()  # (no SSL_shutdown: the TCP connection just ends)
            return
        elif mode == "sink":
            time.sleep(float(opts.get("delay", "0")))
            total, how = 0, "close_notify"
            while True:
                try:
                    chunk = s.recv(65536)
                except ssl.SSLZeroReturnError:
                    break
                except (ssl.SSLError, OSError) as e:
                    how = "error:" + (getattr(e, "reason", None) or type(e).__name__)
                    break
                if not chunk:
                    break
                total += len(chunk)
            print("GOT", total, how, flush=True)
            try:
                s.unwrap()
            except (ssl.SSLError, OSError):
                pass
        elif mode == "hello":
            s.sendall(b"hello")
            s.unwrap()
        elif mode == "stall":
            time.sleep(5)
        elif mode == "bye":
            s.unwrap()
            print("DONE", flush=True)
            return
        elif mode == "drip":
            for _ in range(int(opts.get("records", "40000"))):
                s.sendall(b"x")
            s.unwrap()
    except (ssl.SSLError, OSError) as e:
        print("SERVER_ERROR", getattr(e, "reason", None) or type(e).__name__, flush=True)
    s.close()


class MemoryServer:
    """A server over memory BIOs, for modes that touch records."""

    def __init__(self, ctx, c):
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.inc, self.out, server_side=True)
        self.c = c
        c.settimeout(10)

    def flush(self):
        data = self.out.read()
        if data:
            self.c.sendall(data)

    def more(self):
        data = self.c.recv(65536)
        if not data:
            raise ConnectionError("closed")
        self.inc.write(data)

    def handshake(self):
        while True:
            try:
                self.obj.do_handshake()
                self.flush()
                break
            except ssl.SSLWantReadError:
                self.flush()
                self.more()
        print("OK", self.obj.version(), self.obj.selected_alpn_protocol() or "-", flush=True)

    def read_line(self):
        line = b""
        while not line.endswith(b"\n"):
            try:
                line += self.obj.read(65536)
            except ssl.SSLWantReadError:
                self.flush()
                self.more()
        return line


def serve_tamper(ctx, c):
    m = MemoryServer(ctx, c)
    try:
        m.handshake()
        line = m.read_line()
        m.flush()
        m.obj.write(b"echo:" + line)
        bad = bytearray(m.out.read())
        bad[-1] ^= 1  # (the record's authentication tag)
        c.sendall(bytes(bad))
        c.settimeout(5)
        while True:  # what the client answers
            data = c.recv(65536)
            if not data:
                break
            m.inc.write(data)
            try:
                m.obj.read(65536)
            except ssl.SSLWantReadError:
                continue
    except ssl.SSLError as e:
        print("ALERT", getattr(e, "reason", None) or type(e).__name__, flush=True)
        c.close()
        return
    except OSError:
        pass
    print("NO_ALERT", flush=True)
    c.close()


def serve_stale(ctx, c):
    """The stale mode, over memory BIOs so that one record can be cut."""
    m = MemoryServer(ctx, c)
    out = m.out
    try:
        m.handshake()
        line = m.read_line()
        obj = m.obj
        obj.write(b"echo:" + line)
        m.flush()
        time.sleep(0.3)
        obj.write(b"stale")
        record = out.read()
        c.sendall(record[:-1])
        print("HELD", len(record), flush=True)
        time.sleep(1.5)
        c.sendall(record[-1:])
        time.sleep(0.3)
    except (ssl.SSLError, OSError) as e:
        print("SERVER_ERROR", getattr(e, "reason", None) or type(e).__name__, flush=True)
    c.close()


def main():
    d, mode = sys.argv[1], sys.argv[2]
    opts = dict(a.split("=", 1) for a in sys.argv[3:])
    if opts.get("quiet") == "1":
        say = builtins.print
        builtins.print = lambda *a, **k: say(*a, **k) if a and a[0] == "PORT" else None
    ctx = context(d, opts) if mode not in ("garbage", "silent") else None
    host = opts.get("host", "127.0.0.1")
    ls = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    if "rcvbuf" in opts:  # (inherited by accepted sockets: a small window)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(opts["rcvbuf"]))
    ls.bind((host, 0))
    ls.listen(8)
    print("PORT", ls.getsockname()[1], flush=True)
    for _ in range(int(opts.get("count", "1"))):
        c, _ = ls.accept()
        serve(ctx, c, mode, opts)
    ls.close()


if __name__ == "__main__":
    main()
