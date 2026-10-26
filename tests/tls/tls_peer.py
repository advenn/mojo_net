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
    except (ssl.SSLError, OSError) as e:
        print("SERVER_ERROR", getattr(e, "reason", None) or type(e).__name__, flush=True)
    s.close()


def main():
    d, mode = sys.argv[1], sys.argv[2]
    opts = dict(a.split("=", 1) for a in sys.argv[3:])
    if opts.get("quiet") == "1":
        say = builtins.print
        builtins.print = lambda *a, **k: say(*a, **k) if a and a[0] == "PORT" else None
    ctx = context(d, opts) if mode not in ("garbage", "silent") else None
    host = opts.get("host", "127.0.0.1")
    ls = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    ls.bind((host, 0))
    ls.listen(8)
    print("PORT", ls.getsockname()[1], flush=True)
    for _ in range(int(opts.get("count", "1"))):
        c, _ = ls.accept()
        serve(ctx, c, mode, opts)
    ls.close()


if __name__ == "__main__":
    main()
