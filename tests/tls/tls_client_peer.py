"""TLS clients for tests of `tls.TlsServer`: Python's `ssl`, an
implementation independent of the code under test (test-only Python; not
a test file itself).

    python tests/tls/tls_client_peer.py <pki dir> <port> <scenario> [key=value ...]

Each scenario connects to 127.0.0.1:<port>, prints what it saw, one fact
per line, and exits; a failure prints "ERROR <reason>", the reason being
the alert or error OpenSSL reported to Python (for example
TLSV1_ALERT_NO_APPLICATION_PROTOCOL), or "ENDED" when the server just
closed.

Scenarios:
  hello      handshake, send `msg` (default "ping"), read the echo, then
             close with close_notify (`close=notify`, the default), without
             (`close=abrupt`), or after the server's (`close=wait`: prints
             SERVER_CLOSED first). Prints OK <version> <cipher> <alpn>,
             TICKET <bool>, REPLY <text>, CLOSED.
  reconnect  two handshakes, the second offering the first one's session:
             prints TICKET <bool> and REUSED <bool>.
  junk       send `n` bytes (default 100 KiB) of a ClientHello that never
             ends: a handshake record header claiming a 128 KiB message,
             then records of zeros. Prints SENT <bytes> once the server
             stops reading or closes.

Options: name= (server_hostname: a DNS name sends SNI, an address does
not; default localhost), alpn=a,b (offered, in order), min=, max=
(1.1, 1.2, 1.3), ciphers= (a TLS 1.2 cipher string), verify=none (no
certificate checks, to send an SNI the certificate does not cover). Key
exchange groups are not in Python's ssl: the tests use openssl s_client.
"""

import socket
import ssl
import sys
import time


def options(args):
    out = {"name": "localhost", "msg": "ping", "close": "notify"}
    for a in args:
        k, _, v = a.partition("=")
        out[k] = v
    return out


VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3, "1.1": ssl.TLSVersion.TLSv1_1}


def context(pki, o):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(pki + "/root.pem")
    if "alpn" in o:
        ctx.set_alpn_protocols(o["alpn"].split(","))
    if "min" in o:
        if o["min"] == "1.1":
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.minimum_version = VERSIONS[o["min"]]
    if "max" in o:
        if o["max"] == "1.1":
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.maximum_version = VERSIONS[o["max"]]
    if "ciphers" in o:
        ctx.set_ciphers(o["ciphers"])
    if o.get("verify") == "none":  # (to send an SNI the certificate does not cover)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def reason(e):
    if isinstance(e, ssl.SSLError):
        return e.reason or e.__class__.__name__
    if isinstance(e, (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError)):
        return "ENDED"
    return e.__class__.__name__


def hello(pki, port, o):
    ctx = context(pki, o)
    raw = socket.create_connection(("127.0.0.1", port), timeout=20)
    try:
        s = ctx.wrap_socket(raw, server_hostname=o["name"])
    except Exception as e:  # the handshake failed
        print("ERROR", reason(e), flush=True)
        return
    print("OK", s.version(), s.cipher()[0], s.selected_alpn_protocol() or "-", flush=True)
    try:
        s.sendall((o["msg"] + "\n").encode())
        got = b""
        while not got.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        print("TICKET", s.session is not None and s.session.has_ticket, flush=True)
        print("REPLY", got.decode(errors="replace").strip(), flush=True)
        if o["close"] == "wait":  # (for the server's close_notify)
            while s.recv(65536):
                pass
            print("SERVER_CLOSED", flush=True)
        if o["close"] == "abrupt":
            s.close()  # (Python sends close_notify only from unwrap())
            print("CLOSED abrupt", flush=True)
            return
        s.unwrap()
        print("CLOSED", flush=True)
    except Exception as e:
        print("ERROR", reason(e), flush=True)


def reconnect(pki, port, o):
    ctx = context(pki, o)
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=20), server_hostname=o["name"])
    s.sendall(b"one\n")
    s.recv(65536)
    time.sleep(0.2)  # (TLS 1.3 tickets come after the handshake: read any)
    s.setblocking(False)
    try:
        s.recv(1)
    except (BlockingIOError, ssl.SSLWantReadError):
        pass
    s.setblocking(True)
    session = s.session
    print("TICKET", session is not None and session.has_ticket, flush=True)
    s.unwrap()
    s.close()
    t = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=20), server_hostname=o["name"], session=session)
    print("REUSED", t.session_reused, flush=True)
    t.sendall(b"two\n")
    t.recv(65536)
    t.unwrap()
    t.close()


def junk(pki, port, o):
    n = int(o.get("n", str(100 * 1024)))
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    # One handshake message of 128 KiB (type 1, ClientHello), split over
    # records of 16 KiB, of which only the header is plausible.
    body = bytes([1, 0x02, 0x00, 0x00]) + bytes(n)
    sent = 0
    try:
        for i in range(0, len(body), 16384):
            part = body[i : i + 16384]
            s.sendall(bytes([22, 3, 1, len(part) >> 8, len(part) & 0xFF]) + part)
            sent += len(part) + 5
    except OSError:
        pass
    print("SENT", sent, flush=True)
    s.close()


def main():
    pki, port, scenario = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    o = options(sys.argv[4:])
    {"hello": hello, "reconnect": reconnect, "junk": junk}[scenario](pki, port, o)


if __name__ == "__main__":
    main()
