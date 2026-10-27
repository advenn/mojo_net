"""The identity a TLS client expects: a DNS name or an IP address, decided
once with `net.addr`'s strict parser and refused before OpenSSL sees
anything doubtful (RFC 9525; rules TC4, TC5 and TC7 of
docs/research/tls_with_openssl.md).

- **IP:** a strict IPv4 or IPv6 literal (`net.addr.IpAddr`), checked as
  octets against the certificate's IP SANs; no SNI is sent (RFC 6066). An
  IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) is the IPv4 address it
  reaches, as Go's `net.IP.Equal` has it: a dual-stack socket sends its
  bytes to `a.b.c.d`, so that is the identity checked (and constrained).
- **DNS:** ASCII letters, digits, `-` and `_`, in labels of 1 to 63 bytes
  that neither start nor end with `-` (RFC 1123), 253 at most in all;
  lower-cased, and one trailing dot dropped. Sent as
  SNI and matched against DNS SANs (never the subject CN, no partial
  wildcards).
- **Refused** (`InvalidInput`): an empty name, a leading dot or an empty
  label, a label starting or ending with `-`, `*`, any byte outside that set (NUL, controls, non-ASCII: IDNs
  come in as A-labels, `xn--...`), and a numeric-looking name that is not
  a strict IP literal (`127.1`, `0x7f.0.0.1`, `010.0.0.1`, `1.2.3.4.`),
  since OpenSSL or a resolver might read it as an address while the
  certificate check reads it as a name.
"""

from linux import ErrorKind, IoError
from net.addr import IpAddr

comptime _MAX_NAME = 253
comptime _MAX_LABEL = 63


struct Target(Copyable, Movable, Writable):
    """A validated expected identity."""

    var name: String
    """The normalized DNS name, or the IP literal as given."""
    var is_ip: Bool
    var ip: List[UInt8]
    """For an IP: its 4 or 16 octets."""

    def __init__(out self, text: StringSlice) raises IoError:
        comptime op = "tls: invalid server name"
        var b = text.as_bytes()
        if len(b) == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var addr: Optional[IpAddr]
        try:
            addr = IpAddr.parse(text)
        except:
            addr = None
        if addr:
            self.name = String(text)
            self.is_ip = True
            self.ip = List[UInt8]()
            var a = addr.value().to_canonical()  # (an IPv4-mapped address: its IPv4 address)
            if a.is_ipv4():
                var o = a.v4().octets()
                for i in range(4):
                    self.ip.append(o[i])
            else:
                var o = a.v6().octets()
                for i in range(16):
                    self.ip.append(o[i])
            return
        var n = len(b)
        if b[n - 1] == 46:  # one trailing dot: the absolute form of the same name
            n -= 1
        if n == 0 or n > _MAX_NAME or b[0] == 46:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        var out = List[UInt8](capacity=n)
        var label = 0
        var label_start = 0
        for i in range(n):
            var c = b[i]
            if c == 46:
                if label == 0 or out[len(out) - 1] == 45:
                    raise IoError.of_kind(op, ErrorKind.InvalidInput)  # an empty label, or one ending in -
                label = 0
                label_start = i + 1
                out.append(c)
                continue
            if c >= 65 and c <= 90:
                c += 32  # A-Z: lower-cased
            elif not ((c >= 97 and c <= 122) or (c >= 48 and c <= 57) or c == 45 or c == 95):
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
            elif c == 45 and label == 0:
                raise IoError.of_kind(op, ErrorKind.InvalidInput)  # a label starting with -
            label += 1
            if label > _MAX_LABEL:
                raise IoError.of_kind(op, ErrorKind.InvalidInput)
            out.append(c)
        if label == 0 or out[len(out) - 1] == 45:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        # The last label: all digits, or 0x and hex digits, is an address
        # spelling a strict parser refused (127.1, 0x7f.0.0.1), not a name.
        var last = Span(out)[label_start:]
        if _numeric(last):
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        self.name = String(unsafe_from_utf8=Span(out))
        self.is_ip = False
        self.ip = List[UInt8]()

    def write_to(self, mut writer: Some[Writer]):
        writer.write(self.name)


def _numeric(label: Span[UInt8, _]) -> Bool:
    var digits = True
    for c in label:
        if not (c >= 48 and c <= 57):
            digits = False
            break
    if digits:
        return True
    if len(label) >= 2 and label[0] == 48 and label[1] == 120:  # 0x...
        for i in range(2, len(label)):
            var c = label[i]
            if not ((c >= 48 and c <= 57) or (c >= 97 and c <= 102)):
                return False
        return True
    return False
