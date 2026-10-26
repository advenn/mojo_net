"""`TlsError`: why a TLS operation failed (rule TC18 of
docs/research/tls_with_openssl.md).

Every failure names one category, the verify code OpenSSL reported (if
any) and OpenSSL's own text, and maps to an `IoError` kind for code that
only looks at kinds. Nothing in this package offers a way to carry on after
a failed verification: there is no "accept anyway".
"""

from linux import ErrorKind, IoError


struct Category(Equatable, TrivialRegisterPassable, Writable):
    """What went wrong."""

    var value: Int

    comptime NONE = Category(0)
    comptime UNTRUSTED = Category(1)
    """The chain does not lead to a trusted CA (or a CA in it is invalid)."""
    comptime EXPIRED = Category(2)
    """A certificate has expired or is not yet valid."""
    comptime HOST_MISMATCH = Category(3)
    """The certificate is not for the expected host name."""
    comptime IP_MISMATCH = Category(4)
    """The certificate is not for the expected IP address."""
    comptime NO_PEER_CERT = Category(5)
    """The server presented no certificate."""
    comptime WEAK = Category(6)
    """A key or signature below the security level (2: RSA 2048, SHA-256)."""
    comptime NO_TRUST_STORE = Category(7)
    """No CA certificates could be loaded."""
    comptime PROTOCOL = Category(8)
    """The handshake or a record failed: version, ciphers, a bad message."""
    comptime ALPN = Category(9)
    """The server chose an application protocol that was not offered."""
    comptime TRUNCATED = Category(10)
    """The connection ended without close_notify (data may be missing)."""
    comptime INPUT = Category(11)
    """The caller passed something unusable (a host name, a config)."""
    comptime LIBRARY = Category(12)
    """OpenSSL could not be loaded, or is not 3.5 or later."""
    comptime RESOURCE = Category(13)
    """A memory bound was reached (the peer sent too much)."""
    comptime CLOSED = Category(14)
    """The connection was used after it closed."""
    comptime CREDENTIALS = Category(15)
    """A server's certificate or key is unusable: missing, mismatched,
    encrypted, below the security level, or readable by other users."""

    def __init__(out self, value: Int):
        self.value = value

    def __eq__(self, other: Category) -> Bool:
        return self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        var names: List[StaticString] = [
            "none",
            "untrusted certificate",
            "expired or not yet valid certificate",
            "host name mismatch",
            "IP address mismatch",
            "no peer certificate",
            "weak key or signature",
            "no trust store",
            "protocol error",
            "ALPN mismatch",
            "truncated (no close_notify)",
            "invalid input",
            "library",
            "resource limit",
            "closed",
            "unusable certificate or key",
        ]
        writer.write(names[self.value] if 0 <= self.value < len(names) else "unknown")


struct TlsError(Copyable, Movable, Writable):
    """A TLS failure: `io` for code that checks kinds (and `is_deadline()`),
    `category` for why, `verify_code` (`X509_V_ERR_*`, 0 when none) and
    `detail`: OpenSSL's verify text and error queue, or the path or name
    concerned."""

    var io: IoError
    var category: Category
    var verify_code: Int
    var detail: String

    def __init__(out self, io: IoError):
        """A transport error (the socket's), or a deadline."""
        self.io = io
        self.category = Category.NONE
        self.verify_code = 0
        self.detail = String()

    def __init__(out self, io: IoError, category: Category, detail: String = "", verify_code: Int = 0):
        self.io = io
        self.category = category
        self.verify_code = verify_code
        self.detail = detail

    def is_deadline(self) -> Bool:
        return self.io.is_deadline()

    def is_authentication(self) -> Bool:
        """The peer failed authentication (the certificate checks)."""
        var c = self.category
        return (
            c == Category.UNTRUSTED
            or c == Category.EXPIRED
            or c == Category.HOST_MISMATCH
            or c == Category.IP_MISMATCH
            or c == Category.NO_PEER_CERT
            or c == Category.WEAK
        )

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.io)
        if self.category != Category.NONE:
            writer.write(" [tls: ", self.category)
            if self.verify_code != 0:
                writer.write(", verify code ", self.verify_code)
            writer.write("]")
        if self.detail.byte_length() > 0:
            writer.write(": ", self.detail)


def tls_error(op: StaticString, kind: ErrorKind, category: Category, detail: String = "", verify_code: Int = 0) -> TlsError:
    return TlsError(IoError.of_kind(op, kind), category, detail, verify_code)
