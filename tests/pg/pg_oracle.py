"""The backend side of PostgreSQL's protocol 3.0, for tests/pg.

It builds backend messages, parses what a client sent, and runs the server
side of MD5 and SCRAM-SHA-256 authentication (RFC 5802, RFC 7677) with
hashlib and hmac, independently of src/crypto and src/pg. Bytes cross to
Mojo as hex strings: every message builder returns hex, so a transcript is
the concatenation of their results.
"""

import base64
import hashlib
import hmac
import struct


def _b(x):
    return x.encode() if isinstance(x, str) else bytes(x)


def _msg(kind, body=b""):
    return (_b(kind) + struct.pack("!i", len(body) + 4) + body).hex()


def _cstr(s):
    return _b(s) + b"\0"


# ---- backend messages --------------------------------------------------------


def auth(code, data_hex=""):
    return _msg("R", struct.pack("!i", code) + bytes.fromhex(data_hex))


def auth_ok():
    return auth(0)


def auth_cleartext():
    return auth(3)


def auth_md5(salt_hex):
    return auth(5, salt_hex)


def auth_sasl(*mechanisms):
    return auth(10, (b"".join(_cstr(m) for m in mechanisms) + b"\0").hex())


def auth_sasl_continue(data):
    return auth(11, _b(data).hex())


def auth_sasl_final(data):
    return auth(12, _b(data).hex())


def parameter(name, value):
    return _msg("S", _cstr(name) + _cstr(value))


def backend_key(pid, secret):
    return _msg("K", struct.pack("!iI", pid, secret))


def ready(status="I"):
    return _msg("Z", _b(status))


def negotiate(minor, *options):
    return _msg("v", struct.pack("!ii", minor, len(options)) + b"".join(_cstr(o) for o in options))


def session(status="I"):
    """What a server sends after AuthenticationOk: parameters, the key, ready."""
    return (
        parameter("server_version", "18.6")
        + parameter("client_encoding", "UTF8")
        + parameter("TimeZone", "UTC")
        + backend_key(4242, 0xDEADBEEF)
        + ready(status)
    )


def row_description(*columns):
    """Columns as "name:type_oid" (format 0)."""
    body = struct.pack("!h", len(columns))
    for c in columns:
        name, oid = c.rsplit(":", 1)
        body += _cstr(name) + struct.pack("!IhIhih", 16384, 1, int(oid), -1, -1, 0)
    return _msg("T", body)


def data_row(*values):
    """Values as strings; None is NULL."""
    body = struct.pack("!h", len(values))
    for v in values:
        if v is None:
            body += struct.pack("!i", -1)
        else:
            b = _b(v)
            body += struct.pack("!i", len(b)) + b
    return _msg("D", body)


def command_complete(tag):
    return _msg("C", _cstr(tag))


def empty_query():
    return _msg("I")


def _fields(severity, code, message, extra):
    body = b"S" + _cstr(severity) + b"V" + _cstr(severity) + b"C" + _cstr(code) + b"M" + _cstr(message)
    for k, v in extra:
        body += _b(k) + _cstr(v)
    return body + b"\0"


def error(code, message, severity="ERROR", **extra):
    """Extra fields by their codes: D (detail), H (hint), P (position), n
    (constraint), t (table)..."""
    return _msg("E", _fields(severity, code, message, sorted(extra.items())))


def notice(message, severity="NOTICE", code="00000"):
    return _msg("N", _fields(severity, code, message, []))


def notification(pid, channel, payload):
    return _msg("A", struct.pack("!i", pid) + _cstr(channel) + _cstr(payload))


def copy_in():
    return _msg("G", struct.pack("!bh", 0, 1) + struct.pack("!h", 0))


def copy_out():
    return _msg("H", struct.pack("!bh", 0, 1) + struct.pack("!h", 0))


# ---- what the client sent ----------------------------------------------------


def startup(data_hex):
    """The StartupMessage at the start of `data_hex`, as
    "version|name=value|..." then "#" and the hex of what follows."""
    data = bytes.fromhex(data_hex)
    (length, version) = struct.unpack("!ii", data[:8])
    parts = data[8:length].split(b"\0")
    assert parts[-2:] == [b"", b""], parts  # the terminating NUL
    pairs = parts[:-2]
    assert len(pairs) % 2 == 0
    out = [str(version)] + [f"{pairs[i].decode()}={pairs[i + 1].decode()}" for i in range(0, len(pairs), 2)]
    return "|".join(out) + "#" + data[length:].hex()


def frontend(data_hex):
    """The typed messages in `data_hex` as "kind:hexbody" joined by "|";
    raises if they do not frame exactly."""
    data = bytes.fromhex(data_hex)
    out = []
    i = 0
    while i < len(data):
        kind = chr(data[i])
        (length,) = struct.unpack("!i", data[i + 1 : i + 5])
        assert length >= 4 and i + 1 + length <= len(data), (i, length)
        out.append(f"{kind}:{data[i + 5 : i + 1 + length].hex()}")
        i += 1 + length
    return "|".join(out)


def cancel_request(data_hex):
    data = bytes.fromhex(data_hex)
    assert len(data) == 16
    return "|".join(str(x) for x in struct.unpack("!iiiI", data))


# ---- authentication, server side -------------------------------------------


def md5_answer(user, password, salt_hex):
    """What a client must answer to AuthenticationMD5Password."""
    inner = hashlib.md5(_b(password) + _b(user)).hexdigest().encode()
    return "md5" + hashlib.md5(inner + bytes.fromhex(salt_hex)).hexdigest()


def sasl_initial(body_hex):
    """The client-first-message in a SASLInitialResponse body, whose
    mechanism and length are checked."""
    body = bytes.fromhex(body_hex)
    end = body.index(b"\0")
    assert body[:end] == b"SCRAM-SHA-256", body[:end]
    (length,) = struct.unpack("!i", body[end + 1 : end + 5])
    data = body[end + 5 :]
    assert len(data) == length, (len(data), length)
    return data.decode()


def text(data_hex):
    return bytes.fromhex(data_hex).decode()


class ScramServer:
    """The server side of one SCRAM-SHA-256 exchange (RFC 5802 section 3),
    the messages as text."""

    def __init__(self, password, salt_hex, iterations, server_nonce):
        self.salt = bytes.fromhex(salt_hex)
        self.iterations = int(iterations)
        self.server_nonce = _b(server_nonce)
        salted = hashlib.pbkdf2_hmac("sha256", _b(password), self.salt, self.iterations)
        self.stored_key = hashlib.sha256(hmac.new(salted, b"Client Key", "sha256").digest()).digest()
        self.server_key = hmac.new(salted, b"Server Key", "sha256").digest()

    def first(self, client_first):
        """The server-first-message for the client-first-message."""
        client_first = _b(client_first)
        assert client_first.startswith(b"n,,"), client_first  # no channel binding
        self.client_first_bare = client_first[3:]
        attrs = dict(a.split(b"=", 1) for a in self.client_first_bare.split(b","))
        self.nonce = attrs[b"r"] + self.server_nonce
        self.server_first = (
            b"r=" + self.nonce + b",s=" + base64.b64encode(self.salt) + b",i=" + str(self.iterations).encode()
        )
        return self.server_first.decode()

    def final(self, client_final):
        """Check the client-final-message; "ok|v=..." or "bad|v=..."."""
        without_proof, proof = _b(client_final).rsplit(b",p=", 1)
        auth_message = self.client_first_bare + b"," + self.server_first + b"," + without_proof
        signature = hmac.new(self.stored_key, auth_message, "sha256").digest()
        client_key = bytes(a ^ b for a, b in zip(base64.b64decode(proof, validate=True), signature))
        ok = hashlib.sha256(client_key).digest() == self.stored_key and without_proof == b"c=biws,r=" + self.nonce
        server_signature = hmac.new(self.server_key, auth_message, "sha256").digest()
        return ("ok" if ok else "bad") + "|v=" + base64.b64encode(server_signature).decode()


# ---- the extended query protocol -------------------------------------------


def parse_complete():
    return _msg("1")


def bind_complete():
    return _msg("2")


def close_complete():
    return _msg("3")


def no_data():
    return _msg("n")


def parameter_description(*oids):
    return _msg("t", struct.pack("!H", len(oids)) + b"".join(struct.pack("!I", o) for o in oids))


def portal_suspended():
    return _msg("s")


def _cstrings(body, n):
    """The first `n` NUL-terminated strings of `body`, and the rest."""
    out = []
    for _ in range(n):
        end = body.index(b"\0")
        out.append(body[:end].decode())
        body = body[end + 1 :]
    return out, body


def frontend_text(data_hex):
    """The typed messages in `data_hex`, decoded, joined by " | ":
    "Q sql", "P name|sql|types", "B portal|statement|formats|values|results"
    (values as t:text, b:hex or NULL), "D S name" / "D P name",
    "E portal|max_rows", "C S name", "S", "H", "X", "f message"."""
    out = []
    for part in frontend(data_hex).split("|") if data_hex else []:
        kind, body_hex = part.split(":", 1)
        body = bytes.fromhex(body_hex)
        if kind == "Q":
            out.append("Q " + body[:-1].decode())
        elif kind == "P":
            (name, sql), rest = _cstrings(body, 2)
            (n,) = struct.unpack("!H", rest[:2])
            types = struct.unpack(f"!{n}I", rest[2 : 2 + 4 * n])
            assert len(rest) == 2 + 4 * n
            out.append(f"P {name}|{sql}|{','.join(map(str, types))}")
        elif kind == "B":
            (portal, stmt), rest = _cstrings(body, 2)
            (nf,) = struct.unpack("!H", rest[:2])
            formats = struct.unpack(f"!{nf}h", rest[2 : 2 + 2 * nf])
            rest = rest[2 + 2 * nf :]
            (nv,) = struct.unpack("!H", rest[:2])
            rest = rest[2:]
            values = []
            for i in range(nv):
                (length,) = struct.unpack("!i", rest[:4])
                rest = rest[4:]
                if length < 0:
                    values.append("NULL")
                    continue
                v = rest[:length]
                rest = rest[length:]
                f = formats[0] if nf == 1 else (formats[i] if nf == nv else 0)
                values.append("t:" + v.decode() if f == 0 else "b:" + v.hex())
            (nr,) = struct.unpack("!H", rest[:2])
            results = struct.unpack(f"!{nr}h", rest[2 : 2 + 2 * nr])
            assert len(rest) == 2 + 2 * nr
            out.append(
                f"B {portal}|{stmt}|{','.join(map(str, formats))}|{','.join(values)}|{','.join(map(str, results))}"
            )
        elif kind in ("D", "C"):
            assert body[-1] == 0
            out.append(f"{kind} {chr(body[0])} {body[1:-1].decode()}")
        elif kind == "E":
            (portal,), rest = _cstrings(body, 1)
            (max_rows,) = struct.unpack("!i", rest)
            out.append(f"E {portal}|{max_rows}")
        elif kind == "f":
            out.append("f " + body[:-1].decode())
        else:
            assert body == b"", kind
            out.append(kind)
    return " | ".join(out)
