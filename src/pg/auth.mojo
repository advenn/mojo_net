"""The client side of PostgreSQL's password authentication ("SASL
Authentication" in its documentation): the legacy MD5 answer, and
SCRAM-SHA-256 (RFC 5802, with RFC 7677's hash) without channel binding,
since there is no TLS yet (the gs2 header is "n,,").

SCRAM as PostgreSQL runs it:
- The user name inside the SCRAM messages is empty: the server takes the
  one from the startup message. (`ScramClient(user=...)` exists for the
  RFC's own examples.)
- The password is used as its UTF-8 bytes. PostgreSQL normalizes a
  password with SASLprep (RFC 4013) when it is set, and keeps the raw bytes
  when that fails. ASCII passwords come out the same either way; a
  non-ASCII one that SASLprep would change does not authenticate
  (docs/pg.md).
- The client checks that the server's nonce extends its own, and checks
  the server's final signature in constant time, so a server that does
  not know the password cannot pass as authenticated.
- The rounds run on the client, so a server asking for more than
  `MAX_SCRAM_ITERATIONS` is refused.
"""

from bytes.base64 import base64_decode, base64_encode
from crypto import HmacSha256, equal_constant_time, md5, pbkdf2_hmac_sha256, sha256
from linux import ErrorKind, IoError

comptime SCRAM_SHA_256 = "SCRAM-SHA-256"
comptime MAX_SCRAM_ITERATIONS = 10000000
"""About five seconds of PBKDF2 here. PostgreSQL's default is 4096 rounds
(`scram_iterations`)."""

comptime E_SCRAM = "pg: malformed SCRAM message from the server"
comptime E_SCRAM_NONCE = "pg: SCRAM: the server's nonce does not extend ours"
comptime E_SCRAM_SIGNATURE = "pg: SCRAM: wrong server signature"
comptime E_SCRAM_ITERATIONS = "pg: SCRAM: more iterations than MAX_SCRAM_ITERATIONS"
comptime E_SCRAM_EXTENSION = "pg: SCRAM: the server requires an unknown extension"
comptime E_SCRAM_REFUSED = "pg: SCRAM: the server refused the proof"
comptime E_SCRAM_ORDER = "pg: SCRAM: messages out of order"
comptime E_SCRAM_INPUT = "pg: SCRAM: invalid nonce"

comptime _COMMA: UInt8 = 44
comptime _EQUALS: UInt8 = 61
# SCRAM attribute names.
comptime _E: UInt8 = 101  # e: server error
comptime _I: UInt8 = 105  # i: iteration count
comptime _M: UInt8 = 109  # m: reserved for mandatory extensions
comptime _R: UInt8 = 114  # r: nonce
comptime _S: UInt8 = 115  # s: salt
comptime _V: UInt8 = 118  # v: server signature


def _hex(d: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var out = List[UInt8](capacity=2 * len(d))
    for b in d:
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 15)])
    return String(unsafe_from_utf8=Span(out))


def md5_password(user: StringSlice, password: StringSlice, salt: Span[UInt8, _]) -> String:
    """The answer to AuthenticationMD5Password: "md5", then the hex of
    md5(hex(md5(password + user)) + salt)."""
    var inner = List[UInt8]()
    inner.extend(password.as_bytes())
    inner.extend(user.as_bytes())
    var outer = List[UInt8]()
    outer.extend(_hex(md5(Span(inner))).as_bytes())
    outer.extend(salt)
    return String("md5", _hex(md5(Span(outer))))


def _attributes(data: Span[UInt8, _]) -> List[Int]:
    """Where each comma-separated attribute starts and ends."""
    var out = List[Int]()
    var start = 0
    for i in range(len(data)):
        if data[i] == _COMMA:
            out.append(start)
            out.append(i)
            start = i + 1
    out.append(start)
    out.append(len(data))
    return out^


def _is(data: Span[UInt8, _], at: List[Int], k: Int, name: UInt8) -> Bool:
    """Whether attribute `k` is `name=...`."""
    if len(at) <= 2 * k + 1:
        return False
    var start = at[2 * k]
    return at[2 * k + 1] - start >= 2 and data[start] == name and data[start + 1] == _EQUALS


def _saslname(user: StringSlice) -> String:
    """RFC 5802's escaping of a user name: "=" as "=3D", "," as "=2C"."""
    var out = String()
    for b in user.as_bytes():
        if b == _EQUALS:
            out += "=3D"
        elif b == _COMMA:
            out += "=2C"
        else:
            out += chr(Int(b))
    return out^


struct ScramClient(Copyable, Movable):
    """One SCRAM-SHA-256 exchange, client side: `client_first`, then
    `client_final` with the server-first-message, then `verify` with the
    server-final-message. Errors raise `IoError`: `InvalidData` for a
    malformed message, a nonce that does not extend ours or a wrong
    signature; `Unsupported` for an unknown mandatory extension or too many
    iterations; `PermissionDenied` when the server sends an error."""

    var _password: List[UInt8]
    var _nonce: String
    var _first_bare: String
    var _signature: List[UInt8]
    """The server signature `client_final` computed and `verify` expects."""
    var _state: Int
    """0: client-first sent; 1: client-final sent; 2: verified."""

    def __init__(out self, password: StringSlice, nonce: StringSlice, *, user: StringSlice = "") raises IoError:
        """`nonce`: printable ASCII without commas, from a strong random
        source and fresh for each exchange (`InvalidInput` otherwise)."""
        var n = nonce.as_bytes()
        if len(n) == 0:
            raise IoError.of_kind(E_SCRAM_INPUT, ErrorKind.InvalidInput)
        for b in n:
            if b < 0x21 or b > 0x7E or b == _COMMA:
                raise IoError.of_kind(E_SCRAM_INPUT, ErrorKind.InvalidInput)
        self._password = List[UInt8]()
        self._password.extend(password.as_bytes())
        self._nonce = String(nonce)
        self._first_bare = String("n=", _saslname(user), ",r=", nonce)
        self._signature = List[UInt8]()
        self._state = 0

    def client_first(self) -> String:
        """The client-first-message: the gs2 header, then the bare part."""
        return String("n,,", self._first_bare)

    def client_final(mut self, server_first: Span[UInt8, _]) raises IoError -> String:
        """The client-final-message, with the proof, for the server's first
        message (`r=nonce,s=salt,i=iterations`, maybe more)."""
        if self._state != 0:
            raise IoError.of_kind(E_SCRAM_ORDER, ErrorKind.InvalidInput)
        var at = _attributes(server_first)
        if _is(server_first, at, 0, _M):
            raise IoError.of_kind(E_SCRAM_EXTENSION, ErrorKind.Unsupported)
        if not (_is(server_first, at, 0, _R) and _is(server_first, at, 1, _S) and _is(server_first, at, 2, _I)):
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
        var nonce = server_first[at[0] + 2 : at[1]]
        var ours = self._nonce.as_bytes()
        if len(nonce) <= len(ours):
            raise IoError.of_kind(E_SCRAM_NONCE, ErrorKind.InvalidData)
        for i in range(len(ours)):
            if nonce[i] != ours[i]:
                raise IoError.of_kind(E_SCRAM_NONCE, ErrorKind.InvalidData)
        for b in nonce:
            if b < 0x21 or b > 0x7E:
                raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
        var salt: List[UInt8]
        try:
            salt = base64_decode(server_first[at[2] + 2 : at[3]])
        except:
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
        if len(salt) == 0:
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
        var digits = server_first[at[4] + 2 : at[5]]
        var iterations = 0
        for b in digits:
            if b < 48 or b > 57:
                raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
            iterations = iterations * 10 + Int(b) - 48
            if iterations > MAX_SCRAM_ITERATIONS:
                raise IoError.of_kind(E_SCRAM_ITERATIONS, ErrorKind.Unsupported)
        if iterations < 1:
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)

        var salted: List[UInt8]
        try:
            salted = pbkdf2_hmac_sha256(Span(self._password), Span(salt), iterations, 32)
        except:
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)  # (iterations >= 1)
        var keyed = HmacSha256(Span(salted))
        var client_key = keyed.mac("Client Key".as_bytes())
        var stored_key = sha256(Span(client_key))
        var without_proof = String("c=biws,r=", String(from_utf8_lossy=nonce))  # biws: "n,," in base64
        var auth = List[UInt8]()
        auth.extend(self._first_bare.as_bytes())
        auth.append(_COMMA)
        auth.extend(server_first)
        auth.append(_COMMA)
        auth.extend(without_proof.as_bytes())
        var client_signature = HmacSha256(Span(stored_key)).mac(Span(auth))
        var proof = List[UInt8](capacity=32)
        for i in range(32):
            proof.append(client_key[i] ^ client_signature[i])
        var server_key = keyed.mac("Server Key".as_bytes())
        self._signature = HmacSha256(Span(server_key)).mac(Span(auth))
        self._state = 1
        return String(without_proof, ",p=", base64_encode(Span(proof)))

    def verify(mut self, server_final: Span[UInt8, _]) raises IoError:
        """Check the server-final-message (`v=signature`)."""
        if self._state != 1:
            raise IoError.of_kind(E_SCRAM_ORDER, ErrorKind.InvalidInput)
        var at = _attributes(server_final)
        if _is(server_final, at, 0, _E):
            raise IoError.of_kind(E_SCRAM_REFUSED, ErrorKind.PermissionDenied)
        if not _is(server_final, at, 0, _V):
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
        var signature: List[UInt8]
        try:
            signature = base64_decode(server_final[at[0] + 2 : at[1]])
        except:
            raise IoError.of_kind(E_SCRAM, ErrorKind.InvalidData)
        if not equal_constant_time(Span(signature), Span(self._signature)):
            raise IoError.of_kind(E_SCRAM_SIGNATURE, ErrorKind.InvalidData)
        self._state = 2

    def verified(self) -> Bool:
        """Whether the server proved it knows the password."""
        return self._state == 2
