"""The server side of gate TG2 (tools/limbo.py; test-only Python, started by
tests/tls/limbo_client.mojo, not a test file itself).

    python tests/tls/limbo_peer.py <dir>

Prints "PORT <n>", then reads one command per line on stdin and serves one
connection for each, printing "READY <index>" (or "UNLOADABLE <index>
<reason>") before it accepts and "DONE <index>" after:

  KEY <index>  a real handshake with the case's chain and key
               (<dir>/cases/<index>/chain.pem, key.pem) at security level 0,
               so the server presents whatever the case holds and the
               client's own checks decide; then reads until the client's
               close_notify or an error.
  SUB <index>  for a case without the leaf's key (most of limbo: BetterTLS,
               the online chains): a TLS 1.2 handshake by a server holding
               a key of the leaf's type, whose Certificate message is
               replaced with the case's chain on its way out. TLS 1.2 sends
               it unencrypted, and the client verifies the chain as soon as
               it arrives, before the ServerKeyExchange: a refused chain
               fails there with its verify error, an accepted one fails
               next, at the ServerKeyExchange's signature ("bad signature",
               verify result 0), since the leaf's key did not sign it.

Ends when stdin does.
"""

import base64
import os
import re
import socket
import ssl
import subprocess
import sys

_OIDS = {
    "2a864886f70d010101": "rsa",
    "2a864886f70d01010a": "rsa-pss",
    "2b6570": "ed25519",
    "2b6571": "ed448",
}
_CURVES = {"2a8648ce3d030107": "p256", "2b81040022": "p384", "2b81040023": "p521"}
_GENKEY = {
    "rsa": ["-newkey", "rsa:2048"],
    "rsa-pss": ["-newkey", "rsa-pss", "-pkeyopt", "rsa_keygen_bits:2048"],
    "ed25519": ["-newkey", "ed25519"],
    "ed448": ["-newkey", "ed448"],
    "p256": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "p384": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
    "p521": ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521"],
}


def _ders(path):
    text = open(path).read()
    return [base64.b64decode("".join(b.split())) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)]


def _tlv(b, i):
    t = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i : i + k], "big")
        i += k
    return t, i, i + n


def key_type(der):
    """The leaf's key type ("rsa", "p256", ...), or None."""
    _, s, _ = _tlv(der, 0)  # Certificate
    _, s, _ = _tlv(der, s)  # TBSCertificate
    i = s
    if der[i] == 0xA0:
        i = _tlv(der, i)[2]
    for _ in range(5):  # serial, signature, issuer, validity, subject
        i = _tlv(der, i)[2]
    _, a, _ = _tlv(der, i)  # SubjectPublicKeyInfo
    _, a, _ = _tlv(der, a)  # AlgorithmIdentifier
    _, o, oz = _tlv(der, a)
    oid = der[o:oz].hex()
    if oid == "2a8648ce3d0201":  # id-ecPublicKey: the curve is the parameter
        t, p, pz = _tlv(der, oz)
        return _CURVES.get(der[p:pz].hex()) if t == 0x06 else None
    return _OIDS.get(oid)


def identity(top, kind):
    """A self-signed certificate and key of `kind`, made once."""
    d = os.path.join(top, "sub")
    os.makedirs(d, exist_ok=True)
    cert, key = os.path.join(d, kind + ".pem"), os.path.join(d, kind + ".key")
    if not os.path.exists(cert):
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-days", "36500", "-subj", "/CN=limbo substitute", "-keyout", key, "-out", cert] + _GENKEY[kind],
            check=True,
            capture_output=True,
        )
    return cert, key


def rewrite(flight, chain):
    """The server's first flight with its Certificate message's list
    replaced by `chain` (DER certificates, leaf first)."""
    records, i, version = [], 0, None
    stream = b""
    while i + 5 <= len(flight):
        typ, ver, n = flight[i], flight[i + 1 : i + 3], int.from_bytes(flight[i + 3 : i + 5], "big")
        if typ != 22:
            raise ValueError(f"record type {typ} in the server's first flight")
        version = version or ver
        stream += flight[i + 5 : i + 5 + n]
        i += 5 + n
    if i != len(flight):
        raise ValueError("a partial record in the server's first flight")
    out, j, seen = b"", 0, False
    while j < len(stream):
        typ, n = stream[j], int.from_bytes(stream[j + 1 : j + 4], "big")
        body = stream[j + 4 : j + 4 + n]
        if typ == 11:
            certs = b"".join(len(c).to_bytes(3, "big") + c for c in chain)
            body = len(certs).to_bytes(3, "big") + certs
            seen = True
        out += bytes([typ]) + len(body).to_bytes(3, "big") + body
        j += 4 + n
    if not seen:
        raise ValueError("no Certificate message in the server's first flight")
    for k in range(0, len(out), 16384):
        part = out[k : k + 16384]
        records.append(b"\x16" + version + len(part).to_bytes(2, "big") + part)
    return b"".join(records)


def serve_key(ls, d):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.load_cert_chain(os.path.join(d, "chain.pem"), os.path.join(d, "key.pem"))
    return lambda c: _real(ctx, c)


def _real(ctx, c):
    with ctx.wrap_socket(c, server_side=True) as s:
        while s.recv(4096):
            pass


def serve_sub(top, d):
    chain = _ders(os.path.join(d, "chain.pem"))
    if not chain:
        raise ValueError("no certificate in the case")
    kind = key_type(chain[0])
    if kind is None:
        raise ValueError("a leaf key of a type no TLS 1.2 server can sign with")
    cert, key = identity(top, kind)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.load_cert_chain(cert, key)
    return lambda c: _substituted(ctx, c, chain)


def _substituted(ctx, c, chain):
    inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, outg, server_side=True)
    while True:
        try:
            obj.do_handshake()
            raise ValueError("the substituted handshake completed")
        except ssl.SSLWantReadError:
            pass
        flight = outg.read()
        if flight:
            c.sendall(rewrite(flight, chain))
            break
        data = c.recv(65536)
        if not data:
            return
        inc.write(data)
    while c.recv(65536):  # (the client's alert, then its end)
        pass


def main():
    top = sys.argv[1]
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)
    print("PORT", ls.getsockname()[1], flush=True)
    for line in sys.stdin:
        words = line.split()
        if len(words) != 2:
            continue
        mode, n = words
        d = os.path.join(top, "cases", n)
        try:
            serve = serve_key(ls, d) if mode == "KEY" else serve_sub(top, d)
        except Exception as e:
            print("UNLOADABLE", n, str(e).replace("\n", " ") or type(e).__name__, flush=True)
            continue
        print("READY", n, flush=True)
        ls.settimeout(30)
        try:
            c, _ = ls.accept()
        except socket.timeout:
            print("DONE", n, "no connection", flush=True)
            continue
        c.settimeout(10)
        try:
            serve(c)
        except Exception:
            pass  # (the client refused the chain, or ended the connection)
        finally:
            c.close()
        print("DONE", n, flush=True)


if __name__ == "__main__":
    main()
