"""Network addresses: IPv4/IPv6, socket addresses, Unix socket addresses.

All address types are small values with no heap allocation (names follow
Rust's `std::net`). Text parsing is strict, so a parsed address formats back
to the same canonical text:
- IPv4: exactly four decimal octets 0-255; no leading zeros (`01` is
  ambiguous with octal in `inet_aton`), shorthand (`127.1`), signs, hex or
  whitespace.
- IPv6: RFC 4291 text (1-4 hex digits per group, one `::`, optional dotted
  IPv4 tail); output follows RFC 5952.
- Ports and numeric zones: decimal, no leading zeros.

`RawSockaddr` is the kernel form. Pass `raw.storage`/`raw.len` to
`linux.sys.bind/connect/accept4/getsockname/recvfrom`; decoding validates the
family and length so garbage from a caller (or a bug) raises `InvalidInput`.

Only `if_nametoindex` (and `parse(..., resolve_zone=True)`, which uses it)
performs syscalls. The module does not import `rt`.
"""

from std.hash import Hasher
from std.os import abort
from std.sys import size_of

from linux import Errno, ErrorKind, IoError, OwnedFd, check
from linux import sys
from linux.abi import (
    UNIX_PATH_MAX,
    Ifreq,
    RawSockaddr,
    SockaddrIn,
    SockaddrIn6,
    SockaddrStorage,
    SockaddrUn,
    hton16,
    hton32,
    ntoh16,
    ntoh32,
)
from linux.consts import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    IF_NAMESIZE,
    SIOCGIFINDEX,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
)
from linux.syscall import err_of, is_err

comptime _COLON: UInt8 = 0x3A
comptime _DOT: UInt8 = 0x2E
comptime _ZERO: UInt8 = 0x30
comptime _LBRACKET: UInt8 = 0x5B
comptime _RBRACKET: UInt8 = 0x5D
comptime _PERCENT: UInt8 = 0x25

# Byte offset of sun_path in sockaddr_un (after sa_family_t).
comptime _SUN_PATH_OFFSET = 2


@inline(.always)
def _invalid(op: StaticString) -> IoError:
    return IoError.of_kind(op, ErrorKind.InvalidInput)


# ---- text buffer ----------------------------------------------------------


struct _Text(Movable):
    """Stack buffer for formatting; the longest text written is a
    `SocketAddrV6` with a zone (58 bytes)."""

    var buf: Array[UInt8, 64]
    var len: Int

    @inline(.always)
    def __init__(out self):
        self.buf = Array[UInt8, 64](fill=0)
        self.len = 0

    @inline(.always)
    def push(mut self, c: UInt8):
        self.buf[self.len] = c
        self.len += 1

    def push_str(mut self, s: StaticString):
        for c in s.as_bytes():
            self.push(c)

    def push_dec(mut self, v: UInt32):
        var tmp = Array[UInt8, 10](fill=0)
        var n = 0
        var x = v
        while True:
            tmp[n] = UInt8(x % 10) + _ZERO
            n += 1
            x //= 10
            if x == 0:
                break
        while n > 0:
            n -= 1
            self.push(tmp[n])

    def push_hex(mut self, v: UInt16):
        """Lowercase hex without leading zeros (RFC 5952 4.1, 4.3)."""
        var started = False
        var shift = 12
        while shift >= 0:
            var d = UInt8((v >> UInt16(shift)) & 0xF)
            if d != 0 or started or shift == 0:
                self.push(d + _ZERO if d < 10 else d + 87)
                started = True
            shift -= 4

    def write_to(self, mut writer: Some[Writer]):
        # Only ASCII is ever pushed.
        writer.write_string(
            StringSlice(unsafe_from_utf8=Span(self.buf)[0 : self.len])
        )


def _push_v4(mut t: _Text, bits: UInt32):
    t.push_dec(bits >> 24)
    t.push(_DOT)
    t.push_dec((bits >> 16) & 0xFF)
    t.push(_DOT)
    t.push_dec((bits >> 8) & 0xFF)
    t.push(_DOT)
    t.push_dec(bits & 0xFF)


def _push_v6(mut t: _Text, a: Ipv6Addr):
    """RFC 5952: lowercase, no leading zeros, `::` for the longest run of two
    or more zero groups (the first on ties), IPv4-mapped as ::ffff:a.b.c.d."""
    if a.is_ipv4_mapped():
        t.push_str("::ffff:")
        _push_v4(t, UInt32(a._lo & 0xFFFFFFFF))
        return
    var seg = a.segments()
    var best_start = -1
    var best_len = 0
    var cur_start = 0
    var cur_len = 0
    for k in range(8):
        if seg[k] == 0:
            if cur_len == 0:
                cur_start = k
            cur_len += 1
            if cur_len > best_len:
                best_len = cur_len
                best_start = cur_start
        else:
            cur_len = 0
    if best_len < 2:
        best_start = -1
    var k = 0
    var need_colon = False
    while k < 8:
        if k == best_start:
            t.push(_COLON)
            t.push(_COLON)
            k += best_len
            need_colon = False
            continue
        if need_colon:
            t.push(_COLON)
        t.push_hex(seg[k])
        need_colon = True
        k += 1


# ---- strict text parsers (internal: sentinel results, no raising) ---------


@inline(.always)
def _is_digit(c: UInt8) -> Bool:
    return c >= 0x30 and c <= 0x39


@inline(.always)
def _hex_val(c: UInt8) -> Int:
    if c >= 0x30 and c <= 0x39:
        return Int(c) - 0x30
    if c >= 0x61 and c <= 0x66:
        return Int(c) - 0x61 + 10
    if c >= 0x41 and c <= 0x46:
        return Int(c) - 0x41 + 10
    return -1


def _parse_v4(b: Span[UInt8, _], start: Int, end: Int) -> Int:
    """`b[start:end]` as dotted-quad bits, or -1."""
    var n = end - start
    if n < 7 or n > 15:
        return -1
    var bits = 0
    var i = start
    for k in range(4):
        var os = i
        var v = 0
        while i < end and _is_digit(b[i]):
            if i - os == 3:
                return -1
            v = v * 10 + Int(b[i] - _ZERO)
            i += 1
        if i == os or v > 255:
            return -1
        if i - os > 1 and b[os] == _ZERO:
            return -1
        bits = (bits << 8) | v
        if k < 3:
            if i == end or b[i] != _DOT:
                return -1
            i += 1
    if i != end:
        return -1
    return bits


def _parse_dec(b: Span[UInt8, _], start: Int, end: Int, max: Int) -> Int:
    """`b[start:end]` as a decimal in [0, max] without leading zeros, or -1."""
    var n = end - start
    if n < 1 or n > 10:
        return -1
    if n > 1 and b[start] == _ZERO:
        return -1
    var v = 0
    for i in range(start, end):
        if not _is_digit(b[i]):
            return -1
        v = v * 10 + Int(b[i] - _ZERO)
    if v > max:
        return -1
    return v


def _parse_v6(
    b: Span[UInt8, _], start: Int, end: Int, mut res: Ipv6Addr
) -> Bool:
    """Parse `b[start:end]` as RFC 4291 text into `res`."""
    var n = end - start
    # 45 = six 4-digit groups plus a 15-byte IPv4 tail; 2 = "::".
    if n < 2 or n > 45:
        return False
    var g = Array[UInt16, 8](fill=0)
    var ng = 0
    var dc = -1  # number of groups before "::", or -1 if none
    var i = start
    if b[i] == _COLON:
        if b[i + 1] != _COLON:
            return False
        dc = 0
        i += 2
    while i < end:
        var gs = i
        var v = 0
        while i < end:
            var h = _hex_val(b[i])
            if h < 0:
                break
            # A 5th digit is invalid both as a hex group and as an octet.
            if i - gs == 4:
                return False
            v = v * 16 + h
            i += 1
        if i < end and b[i] == _DOT:
            # Dotted IPv4 tail: covers the last two groups and must end
            # the text (`_parse_v4` rejects anything after it).
            if ng > 6:
                return False
            var v4 = _parse_v4(b, gs, end)
            if v4 < 0:
                return False
            g[ng] = UInt16(v4 >> 16)
            g[ng + 1] = UInt16(v4 & 0xFFFF)
            ng += 2
            break
        if i == gs or ng == 8:
            return False
        g[ng] = UInt16(v)
        ng += 1
        if i == end:
            break
        if b[i] != _COLON:
            return False
        i += 1
        if i == end:
            return False  # a single trailing ':'
        if b[i] == _COLON:
            if dc >= 0:
                return False  # a second "::"
            dc = ng
            i += 1
    if dc < 0:
        if ng != 8:
            return False
    elif ng > 7:
        return False  # "::" must stand for at least one group
    var r = Array[UInt16, 8](fill=0)
    if dc < 0:
        for k in range(8):
            r[k] = g[k]
    else:
        var tail = ng - dc
        for k in range(dc):
            r[k] = g[k]
        for k in range(tail):
            r[8 - tail + k] = g[dc + k]
    res = Ipv6Addr(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7])
    return True


def _find(b: Span[UInt8, _], c: UInt8, start: Int, end: Int) -> Int:
    for i in range(start, end):
        if b[i] == c:
            return i
    return -1


# ---- IPv4 -----------------------------------------------------------------


struct Ipv4Addr(Comparable, Hashable, TrivialRegisterPassable, Writable):
    """An IPv4 address, stored as host-order bits (`a.b.c.d` = a<<24|...)."""

    var _bits: UInt32

    comptime LOCALHOST = Ipv4Addr(127, 0, 0, 1)
    comptime UNSPECIFIED = Ipv4Addr(0, 0, 0, 0)
    comptime BROADCAST = Ipv4Addr(255, 255, 255, 255)

    @inline(.always)
    def __init__(out self, a: UInt8, b: UInt8, c: UInt8, d: UInt8):
        self._bits = (
            (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | UInt32(d)
        )

    @inline(.always)
    def __init__(out self, *, bits: UInt32):
        self._bits = bits

    @staticmethod
    @inline(.always)
    def from_bits(bits: UInt32) -> Self:
        return Self(bits=bits)

    @staticmethod
    @inline(.always)
    def from_octets(o: Array[UInt8, 4]) -> Self:
        return Self(o[0], o[1], o[2], o[3])

    @inline(.always)
    def bits(self) -> UInt32:
        """Host-order bits (`127.0.0.1` is `0x7F000001`)."""
        return self._bits

    @inline(.always)
    def to_bits(self) -> UInt32:
        """Same as `bits()` (Rust's name)."""
        return self._bits

    def octets(self) -> Array[UInt8, 4]:
        var o = Array[UInt8, 4](fill=0)
        o[0] = UInt8(self._bits >> 24)
        o[1] = UInt8((self._bits >> 16) & 0xFF)
        o[2] = UInt8((self._bits >> 8) & 0xFF)
        o[3] = UInt8(self._bits & 0xFF)
        return o^

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._bits == other._bits

    @inline(.always)
    def __lt__(self, other: Self) -> Bool:
        return self._bits < other._bits

    @inline(.always)
    def is_unspecified(self) -> Bool:
        """0.0.0.0."""
        return self._bits == 0

    @inline(.always)
    def is_loopback(self) -> Bool:
        """127.0.0.0/8."""
        return (self._bits >> 24) == 127

    def is_private(self) -> Bool:
        """RFC 1918: 10/8, 172.16/12, 192.168/16."""
        return (
            (self._bits >> 24) == 10
            or (self._bits >> 20) == 0xAC1
            or (self._bits >> 16) == 0xC0A8
        )

    @inline(.always)
    def is_link_local(self) -> Bool:
        """169.254/16."""
        return (self._bits >> 16) == 0xA9FE

    @inline(.always)
    def is_multicast(self) -> Bool:
        """224/4."""
        return (self._bits >> 28) == 0xE

    @inline(.always)
    def is_broadcast(self) -> Bool:
        """255.255.255.255."""
        return self._bits == 0xFFFFFFFF

    def is_documentation(self) -> Bool:
        """RFC 5737: 192.0.2/24, 198.51.100/24, 203.0.113/24."""
        var p = self._bits >> 8
        return p == 0xC00002 or p == 0xC63364 or p == 0xCB0071

    @inline(.always)
    def to_ipv6_mapped(self) -> Ipv6Addr:
        """::ffff:a.b.c.d, the form dual-stack sockets report."""
        return Ipv6Addr(hi=0, lo=0xFFFF_0000_0000 | UInt64(self._bits))

    @staticmethod
    def parse(s: StringSlice) raises IoError -> Self:
        return Self.parse_ascii(s.as_bytes())

    @staticmethod
    def parse_ascii(b: Span[UInt8, _]) raises IoError -> Self:
        var v = _parse_v4(b, 0, len(b))
        if v < 0:
            raise _invalid("Ipv4Addr.parse")
        return Self(bits=UInt32(v))

    def write_to(self, mut writer: Some[Writer]):
        var t = _Text()
        _push_v4(t, self._bits)
        t.write_to(writer)

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("Ipv4Addr(", self, ")")


# ---- IPv6 -----------------------------------------------------------------


struct Ipv6Addr(Comparable, Hashable, TrivialRegisterPassable, Writable):
    """An IPv6 address as two host-order 64-bit halves (`_hi` holds the first
    four segments), so comparisons and predicates are a few integer ops."""

    var _hi: UInt64
    var _lo: UInt64

    comptime LOCALHOST = Ipv6Addr(hi=0, lo=1)
    comptime UNSPECIFIED = Ipv6Addr(hi=0, lo=0)

    @inline(.always)
    def __init__(
        out self,
        a: UInt16,
        b: UInt16,
        c: UInt16,
        d: UInt16,
        e: UInt16,
        f: UInt16,
        g: UInt16,
        h: UInt16,
    ):
        """From the eight 16-bit segments, most significant first."""
        self._hi = (
            (UInt64(a) << 48)
            | (UInt64(b) << 32)
            | (UInt64(c) << 16)
            | UInt64(d)
        )
        self._lo = (
            (UInt64(e) << 48)
            | (UInt64(f) << 32)
            | (UInt64(g) << 16)
            | UInt64(h)
        )

    @inline(.always)
    def __init__(out self, *, hi: UInt64, lo: UInt64):
        self._hi = hi
        self._lo = lo

    @staticmethod
    @inline(.always)
    def from_bits(bits: UInt128) -> Self:
        return Self(hi=UInt64(bits >> 64), lo=UInt64(bits & 0xFFFFFFFFFFFFFFFF))

    @inline(.always)
    def to_bits(self) -> UInt128:
        return (UInt128(self._hi) << 64) | UInt128(self._lo)

    @staticmethod
    def from_octets(o: Array[UInt8, 16]) -> Self:
        """From network-order bytes (`sin6_addr`)."""
        var hi: UInt64 = 0
        var lo: UInt64 = 0
        for k in range(8):
            hi = (hi << 8) | UInt64(o[k])
            lo = (lo << 8) | UInt64(o[k + 8])
        return Self(hi=hi, lo=lo)

    @staticmethod
    def from_segments(s: Array[UInt16, 8]) -> Self:
        return Self(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])

    def octets(self) -> Array[UInt8, 16]:
        """Network-order bytes (`sin6_addr`)."""
        var o = Array[UInt8, 16](fill=0)
        for k in range(8):
            o[k] = UInt8((self._hi >> UInt64(56 - 8 * k)) & 0xFF)
            o[k + 8] = UInt8((self._lo >> UInt64(56 - 8 * k)) & 0xFF)
        return o^

    @inline(.always)
    def segment(self, i: Int) -> UInt16:
        """Segment `i` in 0..7, most significant first. Another index aborts
        in every build (it never reads some other segment)."""
        if i < 0 or i > 7:
            abort("Ipv6Addr.segment index out of range")
        var half = self._hi if i < 4 else self._lo
        return UInt16((half >> UInt64(48 - 16 * (i & 3))) & 0xFFFF)

    def segments(self) -> Array[UInt16, 8]:
        var s = Array[UInt16, 8](fill=0)
        for k in range(8):
            s[k] = self.segment(k)
        return s^

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self._hi == other._hi and self._lo == other._lo

    @inline(.always)
    def __lt__(self, other: Self) -> Bool:
        return self._hi < other._hi or (
            self._hi == other._hi and self._lo < other._lo
        )

    @inline(.always)
    def is_unspecified(self) -> Bool:
        """::. Strict IPv6, like the other `Ipv6Addr` predicates:
        ::ffff:0.0.0.0 is not, but `IpAddr.is_unspecified` (which classifies
        IPv4-mapped addresses by their IPv4 address) says it is."""
        return self._hi == 0 and self._lo == 0

    @inline(.always)
    def is_loopback(self) -> Bool:
        """::1 only. ::ffff:127.0.0.1 is IPv4 loopback: `IpAddr.is_loopback`
        reports it, or check `to_ipv4_mapped()` first."""
        return self._hi == 0 and self._lo == 1

    @inline(.always)
    def is_multicast(self) -> Bool:
        """ff00::/8 (strict IPv6; `IpAddr.is_multicast` also covers
        ::ffff:224.0.0.0/100)."""
        return (self._hi >> 56) == 0xFF

    @inline(.always)
    def is_unicast_link_local(self) -> Bool:
        """fe80::/10; these need a scope id (interface) to be usable."""
        return (self._hi >> 54) == (0xFE80 >> 6)

    @inline(.always)
    def is_unique_local(self) -> Bool:
        """fc00::/7 (RFC 4193)."""
        return (self._hi >> 57) == (0xFC >> 1)

    @inline(.always)
    def is_documentation(self) -> Bool:
        """2001:db8::/32 (RFC 3849)."""
        return (self._hi >> 32) == 0x20010DB8

    @inline(.always)
    def is_ipv4_mapped(self) -> Bool:
        """::ffff:0:0/96."""
        return self._hi == 0 and (self._lo >> 32) == 0xFFFF

    def to_ipv4_mapped(self) -> Optional[Ipv4Addr]:
        """The IPv4 address of an IPv4-mapped address, else None."""
        if self.is_ipv4_mapped():
            return Ipv4Addr(bits=UInt32(self._lo & 0xFFFFFFFF))
        return None

    @staticmethod
    @inline(.always)
    def from_ipv4_mapped(v4: Ipv4Addr) -> Self:
        """::ffff:a.b.c.d (same as `v4.to_ipv6_mapped()`)."""
        return v4.to_ipv6_mapped()

    @staticmethod
    def parse(s: StringSlice) raises IoError -> Self:
        """Strict RFC 4291 text; no zone (`%`): zones belong to
        `SocketAddrV6`."""
        return Self.parse_ascii(s.as_bytes())

    @staticmethod
    def parse_ascii(b: Span[UInt8, _]) raises IoError -> Self:
        var ip = Self.UNSPECIFIED
        if not _parse_v6(b, 0, len(b), ip):
            raise _invalid("Ipv6Addr.parse")
        return ip

    def write_to(self, mut writer: Some[Writer]):
        var t = _Text()
        _push_v6(t, self)
        t.write_to(writer)

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("Ipv6Addr(", self, ")")


# ---- IpAddr ---------------------------------------------------------------


struct IpAddr(Equatable, Hashable, TrivialRegisterPassable, Writable):
    """An IPv4 or IPv6 address (tagged; IPv4 is stored in its mapped form).

    An IPv4 address never equals its IPv4-mapped IPv6 form; use
    `to_canonical()` to fold mapped addresses from dual-stack sockets. The
    `is_*` predicates, however, classify a mapped address by its IPv4
    address (`::ffff:127.0.0.1` is loopback)."""

    var _v6: Bool
    var _addr: Ipv6Addr

    @implicit
    @inline(.always)
    def __init__(out self, v4: Ipv4Addr):
        self._v6 = False
        self._addr = v4.to_ipv6_mapped()

    @implicit
    @inline(.always)
    def __init__(out self, v6: Ipv6Addr):
        self._v6 = True
        self._addr = v6

    @inline(.always)
    def is_ipv4(self) -> Bool:
        return not self._v6

    @inline(.always)
    def is_ipv6(self) -> Bool:
        return self._v6

    @inline(.always)
    def v4(self) -> Ipv4Addr:
        """The IPv4 address. Requires `is_ipv4()`: on an IPv6 address it
        aborts in every build (it never returns the low 32 bits). Use
        `as_v4()` when the family is not known, and `to_canonical()` first
        to accept IPv4-mapped addresses."""
        if self._v6:
            abort("IpAddr.v4() on an IPv6 address; use as_v4()")
        return Ipv4Addr(bits=UInt32(self._addr._lo & 0xFFFFFFFF))

    @inline(.always)
    def v6(self) -> Ipv6Addr:
        """The IPv6 address; for an IPv4 address, its mapped form."""
        return self._addr

    @inline(.always)
    def as_v4(self) -> Optional[Ipv4Addr]:
        """The IPv4 address, or None for an IPv6 address (including an
        IPv4-mapped one; see `to_canonical()`)."""
        if self._v6:
            return None
        return Ipv4Addr(bits=UInt32(self._addr._lo & 0xFFFFFFFF))

    @inline(.always)
    def as_v6(self) -> Optional[Ipv6Addr]:
        """The IPv6 address, or None for an IPv4 address (unlike `v6()`,
        which maps it)."""
        if self._v6:
            return self._addr
        return None

    def to_canonical(self) -> IpAddr:
        """IPv4 for an IPv4-mapped IPv6 address, else unchanged."""
        if self._v6 and self._addr.is_ipv4_mapped():
            return IpAddr(Ipv4Addr(bits=UInt32(self._addr._lo & 0xFFFFFFFF)))
        return self

    # The predicates classify an IPv4-mapped IPv6 address (::ffff:a.b.c.d,
    # how dual-stack sockets report IPv4 peers) by its IPv4 address, since
    # that is the host it reaches; this is CPython >= 3.13's and Go netip's
    # answer. `Ipv6Addr`'s predicates are strict IPv6 (Rust's answer). An
    # IPv4 `IpAddr` is stored mapped, so one test covers both cases.

    def is_unspecified(self) -> Bool:
        """0.0.0.0, ::, or ::ffff:0.0.0.0."""
        if self._addr.is_ipv4_mapped():
            return self._mapped_v4().is_unspecified()
        return self._addr.is_unspecified()

    def is_loopback(self) -> Bool:
        """127.0.0.0/8, ::1, or ::ffff:127.0.0.0/104."""
        if self._addr.is_ipv4_mapped():
            return self._mapped_v4().is_loopback()
        return self._addr.is_loopback()

    def is_multicast(self) -> Bool:
        """224.0.0.0/4, ff00::/8, or ::ffff:224.0.0.0/100."""
        if self._addr.is_ipv4_mapped():
            return self._mapped_v4().is_multicast()
        return self._addr.is_multicast()

    @inline(.always)
    def _mapped_v4(self) -> Ipv4Addr:
        """The low 32 bits (meaningful when `_addr.is_ipv4_mapped()`)."""
        return Ipv4Addr(bits=UInt32(self._addr._lo & 0xFFFFFFFF))

    @staticmethod
    def parse(s: StringSlice) raises IoError -> Self:
        return Self.parse_ascii(s.as_bytes())

    @staticmethod
    def parse_ascii(b: Span[UInt8, _]) raises IoError -> Self:
        """IPv6 if the text contains ':', else IPv4."""
        if _find(b, _COLON, 0, len(b)) >= 0:
            var ip = Ipv6Addr.UNSPECIFIED
            if not _parse_v6(b, 0, len(b), ip):
                raise _invalid("IpAddr.parse")
            return IpAddr(ip)
        var v = _parse_v4(b, 0, len(b))
        if v < 0:
            raise _invalid("IpAddr.parse")
        return IpAddr(Ipv4Addr(bits=UInt32(v)))

    def write_to(self, mut writer: Some[Writer]):
        if self._v6:
            self._addr.write_to(writer)
        else:
            self.v4().write_to(writer)

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("IpAddr(", self, ")")


# ---- socket addresses -----------------------------------------------------


struct SocketAddrV4(Equatable, Hashable, TrivialRegisterPassable, Writable):
    """IPv4 address and port (`sockaddr_in`)."""

    var _ip: Ipv4Addr
    var _port: UInt16

    @inline(.always)
    def __init__(out self, ip: Ipv4Addr, port: UInt16):
        self._ip = ip
        self._port = port

    @inline(.always)
    def ip(self) -> Ipv4Addr:
        return self._ip

    @inline(.always)
    def port(self) -> UInt16:
        return self._port

    @inline(.always)
    def set_ip(mut self, ip: Ipv4Addr):
        self._ip = ip

    @inline(.always)
    def set_port(mut self, port: UInt16):
        self._port = port

    def to_raw(self) -> RawSockaddr:
        var raw = RawSockaddr()
        _store(
            raw.storage,
            SockaddrIn(
                UInt16(AF_INET),
                hton16(self._port),
                hton32(self._ip._bits),
                Array[UInt8, 8](fill=0),
            ),
        )
        raw.len = UInt32(size_of[SockaddrIn]())
        return raw^

    @staticmethod
    def from_raw(raw: RawSockaddr) raises IoError -> Self:
        var a = SocketAddr.from_raw(raw)
        if not a.is_ipv4():
            raise _invalid("SocketAddrV4.from_raw")
        return a.v4()

    @staticmethod
    def parse(s: StringSlice) raises IoError -> Self:
        return Self.parse_ascii(s.as_bytes())

    @staticmethod
    def parse_ascii(b: Span[UInt8, _]) raises IoError -> Self:
        """`a.b.c.d:port`."""
        var n = len(b)
        var colon = _find(b, _COLON, 0, n)
        if colon < 0:
            raise _invalid("SocketAddrV4.parse")
        var ip = _parse_v4(b, 0, colon)
        var port = _parse_dec(b, colon + 1, n, 0xFFFF)
        if ip < 0 or port < 0:
            raise _invalid("SocketAddrV4.parse")
        return Self(Ipv4Addr(bits=UInt32(ip)), UInt16(port))

    def write_to(self, mut writer: Some[Writer]):
        var t = _Text()
        _push_v4(t, self._ip._bits)
        t.push(_COLON)
        t.push_dec(UInt32(self._port))
        t.write_to(writer)

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("SocketAddrV4(", self, ")")


struct SocketAddrV6(Equatable, Hashable, TrivialRegisterPassable, Writable):
    """IPv6 address, port, flow info and scope id (`sockaddr_in6`).

    `scope_id` is the interface index that makes a link-local address
    usable; 0 means none. Text form: `[ip%scope]:port` (flowinfo is not
    part of the text form)."""

    var _ip: Ipv6Addr
    var _port: UInt16
    var _flowinfo: UInt32
    var _scope_id: UInt32

    @inline(.always)
    def __init__(
        out self,
        ip: Ipv6Addr,
        port: UInt16,
        flowinfo: UInt32 = 0,
        scope_id: UInt32 = 0,
    ):
        self._ip = ip
        self._port = port
        self._flowinfo = flowinfo
        self._scope_id = scope_id

    @inline(.always)
    def ip(self) -> Ipv6Addr:
        return self._ip

    @inline(.always)
    def port(self) -> UInt16:
        return self._port

    @inline(.always)
    def flowinfo(self) -> UInt32:
        return self._flowinfo

    @inline(.always)
    def scope_id(self) -> UInt32:
        return self._scope_id

    @inline(.always)
    def set_ip(mut self, ip: Ipv6Addr):
        self._ip = ip

    @inline(.always)
    def set_port(mut self, port: UInt16):
        self._port = port

    @inline(.always)
    def set_flowinfo(mut self, flowinfo: UInt32):
        self._flowinfo = flowinfo

    @inline(.always)
    def set_scope_id(mut self, scope_id: UInt32):
        self._scope_id = scope_id

    def to_raw(self) -> RawSockaddr:
        var raw = RawSockaddr()
        _store(
            raw.storage,
            SockaddrIn6(
                UInt16(AF_INET6),
                hton16(self._port),
                hton32(self._flowinfo),
                self._ip.octets(),
                self._scope_id,
            ),
        )
        raw.len = UInt32(size_of[SockaddrIn6]())
        return raw^

    @staticmethod
    def from_raw(raw: RawSockaddr) raises IoError -> Self:
        var a = SocketAddr.from_raw(raw)
        if not a.is_ipv6():
            raise _invalid("SocketAddrV6.from_raw")
        return a.v6()

    @staticmethod
    def parse(
        s: StringSlice, *, resolve_zone: Bool = False
    ) raises IoError -> Self:
        """`[ip]:port` or `[ip%zone]:port`. The zone must be a decimal
        interface index unless `resolve_zone` is set, which also accepts an
        interface name and looks it up with `if_nametoindex` (a syscall)."""
        return Self.parse_ascii(s.as_bytes(), resolve_zone=resolve_zone)

    @staticmethod
    def parse_ascii(
        b: Span[UInt8, _], *, resolve_zone: Bool = False
    ) raises IoError -> Self:
        comptime op = "SocketAddrV6.parse"
        var n = len(b)
        if n < 1 or b[0] != _LBRACKET:
            raise _invalid(op)
        var close = _find(b, _RBRACKET, 1, n)
        if close < 0 or close + 1 >= n or b[close + 1] != _COLON:
            raise _invalid(op)
        var port = _parse_dec(b, close + 2, n, 0xFFFF)
        if port < 0:
            raise _invalid(op)
        var pct = _find(b, _PERCENT, 1, close)
        var ip_end = pct if pct >= 0 else close
        var ip = Ipv6Addr.UNSPECIFIED
        if not _parse_v6(b, 1, ip_end, ip):
            raise _invalid(op)
        var scope: UInt32 = 0
        if pct >= 0:
            var z = _parse_dec(b, pct + 1, close, 0xFFFFFFFF)
            if z >= 0:
                scope = UInt32(z)
            elif (
                resolve_zone
                and pct + 1 < close
                and not _all_digits(b, pct + 1, close)
            ):
                scope = _if_nametoindex(b, pct + 1, close)
            else:
                raise _invalid(op)
        return Self(ip, UInt16(port), 0, scope)

    def write_to(self, mut writer: Some[Writer]):
        var t = _Text()
        t.push(_LBRACKET)
        _push_v6(t, self._ip)
        if self._scope_id != 0:
            t.push(_PERCENT)
            t.push_dec(self._scope_id)
        t.push(_RBRACKET)
        t.push(_COLON)
        t.push_dec(UInt32(self._port))
        t.write_to(writer)

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("SocketAddrV6(", self)
        if self._flowinfo != 0:
            writer.write(", flowinfo=", self._flowinfo)
        writer.write(")")


def _all_digits(b: Span[UInt8, _], start: Int, end: Int) -> Bool:
    for i in range(start, end):
        if not _is_digit(b[i]):
            return False
    return True


struct SocketAddr(Equatable, Hashable, TrivialRegisterPassable, Writable):
    """A `SocketAddrV4` or `SocketAddrV6` (tagged; IPv4 is stored in its
    mapped form with zero flowinfo and scope id)."""

    var _v6: Bool
    var _ip: Ipv6Addr
    var _port: UInt16
    var _flowinfo: UInt32
    var _scope_id: UInt32

    @implicit
    @inline(.always)
    def __init__(out self, a: SocketAddrV4):
        self._v6 = False
        self._ip = a._ip.to_ipv6_mapped()
        self._port = a._port
        self._flowinfo = 0
        self._scope_id = 0

    @implicit
    @inline(.always)
    def __init__(out self, a: SocketAddrV6):
        self._v6 = True
        self._ip = a._ip
        self._port = a._port
        self._flowinfo = a._flowinfo
        self._scope_id = a._scope_id

    @inline(.always)
    def __init__(out self, ip: IpAddr, port: UInt16):
        self._v6 = ip._v6
        self._ip = ip._addr
        self._port = port
        self._flowinfo = 0
        self._scope_id = 0

    @inline(.always)
    def is_ipv4(self) -> Bool:
        return not self._v6

    @inline(.always)
    def is_ipv6(self) -> Bool:
        return self._v6

    @inline(.always)
    def v4(self) -> SocketAddrV4:
        """Requires `is_ipv4()`: on an IPv6 address it aborts in every build
        (it never returns the low 32 bits). Use `as_v4()` when the family is
        not known; a dual-stack socket reports IPv4 peers as IPv6
        (`[::ffff:a.b.c.d]:port`, see `ip().to_canonical()`)."""
        if self._v6:
            abort("SocketAddr.v4() on an IPv6 address; use as_v4()")
        return SocketAddrV4(
            Ipv4Addr(bits=UInt32(self._ip._lo & 0xFFFFFFFF)), self._port
        )

    @inline(.always)
    def v6(self) -> SocketAddrV6:
        """Requires `is_ipv6()`: on an IPv4 address it aborts in every
        build. Use `as_v6()` when the family is not known."""
        if not self._v6:
            abort("SocketAddr.v6() on an IPv4 address; use as_v6()")
        return SocketAddrV6(
            self._ip, self._port, self._flowinfo, self._scope_id
        )

    @inline(.always)
    def as_v4(self) -> Optional[SocketAddrV4]:
        """The `SocketAddrV4`, or None for an IPv6 address (including an
        IPv4-mapped one)."""
        if self._v6:
            return None
        return SocketAddrV4(
            Ipv4Addr(bits=UInt32(self._ip._lo & 0xFFFFFFFF)), self._port
        )

    @inline(.always)
    def as_v6(self) -> Optional[SocketAddrV6]:
        """The `SocketAddrV6`, or None for an IPv4 address."""
        if not self._v6:
            return None
        return SocketAddrV6(
            self._ip, self._port, self._flowinfo, self._scope_id
        )

    @inline(.always)
    def ip(self) -> IpAddr:
        if self._v6:
            return IpAddr(self._ip)
        return IpAddr(Ipv4Addr(bits=UInt32(self._ip._lo & 0xFFFFFFFF)))

    @inline(.always)
    def port(self) -> UInt16:
        return self._port

    @inline(.always)
    def set_port(mut self, port: UInt16):
        self._port = port

    def set_ip(mut self, ip: IpAddr):
        """Changing the family drops flowinfo and scope id (Rust semantics)."""
        if ip._v6 != self._v6:
            self._flowinfo = 0
            self._scope_id = 0
        self._v6 = ip._v6
        self._ip = ip._addr

    @inline(.always)
    def family(self) -> Int:
        """AF_INET or AF_INET6, for `socket()`."""
        return AF_INET6 if self._v6 else AF_INET

    def to_raw(self) -> RawSockaddr:
        if self._v6:
            return self.v6().to_raw()
        return self.v4().to_raw()

    @staticmethod
    def from_raw(raw: RawSockaddr) raises IoError -> Self:
        """Decode `sockaddr_in`/`sockaddr_in6`; any other family, or a
        length shorter than the family's struct or longer than the storage,
        raises `InvalidInput`."""
        comptime op = "SocketAddr.from_raw"
        var n = Int(raw.len)
        if n > RawSockaddr.capacity():
            raise _invalid(op)
        var fam = raw.family()
        if fam == AF_INET:
            if n < size_of[SockaddrIn]():
                raise _invalid(op)
            ref sin = _view[SockaddrIn](raw.storage)
            return SocketAddrV4(
                Ipv4Addr(bits=ntoh32(sin.addr)), ntoh16(sin.port)
            )
        if fam == AF_INET6:
            if n < size_of[SockaddrIn6]():
                raise _invalid(op)
            ref sin6 = _view[SockaddrIn6](raw.storage)
            return SocketAddrV6(
                Ipv6Addr.from_octets(sin6.addr),
                ntoh16(sin6.port),
                ntoh32(sin6.flowinfo),
                sin6.scope_id,
            )
        raise _invalid(op)

    @staticmethod
    def parse(
        s: StringSlice, *, resolve_zone: Bool = False
    ) raises IoError -> Self:
        """`a.b.c.d:port` or `[v6]:port` / `[v6%zone]:port` (see
        `SocketAddrV6.parse` for zones)."""
        return Self.parse_ascii(s.as_bytes(), resolve_zone=resolve_zone)

    @staticmethod
    def parse_ascii(
        b: Span[UInt8, _], *, resolve_zone: Bool = False
    ) raises IoError -> Self:
        if len(b) > 0 and b[0] == _LBRACKET:
            return SocketAddrV6.parse_ascii(b, resolve_zone=resolve_zone)
        return SocketAddrV4.parse_ascii(b)

    def write_to(self, mut writer: Some[Writer]):
        if self._v6:
            self.v6().write_to(writer)
        else:
            self.v4().write_to(writer)

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("SocketAddr(", self, ")")


# ---- Unix addresses -------------------------------------------------------


struct UnixAddr(Copyable, Equatable, Hashable, Movable, Writable):
    """A Unix-domain socket address: a filesystem pathname, a Linux abstract
    name (`sun_path` starting with NUL; not a file, freed with the socket),
    or unnamed (unbound sockets, socketpair ends).

    Names are bytes, not necessarily UTF-8. A pathname you build must fit
    `sun_path` with its NUL (at most 107 bytes) and contain no NUL; an
    abstract name may hold any bytes (at most 107, after the leading NUL).
    A decoded pathname (`from_raw`) can also be 108 bytes long: Linux lets
    a peer bind a path that fills `sun_path` with no NUL."""

    var _kind: UInt8
    var _len: UInt8
    var _name: Array[UInt8, UNIX_PATH_MAX]
    """Name bytes (no leading NUL for abstract, no trailing NUL); zero
    beyond `_len`."""

    comptime _UNNAMED: UInt8 = 0
    comptime _PATHNAME: UInt8 = 1
    comptime _ABSTRACT: UInt8 = 2

    comptime MAX_PATHNAME = UNIX_PATH_MAX - 1
    comptime MAX_ABSTRACT = UNIX_PATH_MAX - 1

    @inline(.always)
    def __init__(out self, *, _kind: UInt8):
        self._kind = _kind
        self._len = 0
        self._name = Array[UInt8, UNIX_PATH_MAX](fill=0)

    @staticmethod
    def unnamed() -> Self:
        """Binding this address autobinds to a kernel-chosen abstract name."""
        return Self(_kind=Self._UNNAMED)

    @staticmethod
    def from_pathname(path: StringSlice) raises IoError -> Self:
        return Self.from_pathname(path.as_bytes())

    @staticmethod
    def from_pathname(path: Span[UInt8, _]) raises IoError -> Self:
        """Empty, NUL-containing or too long (>107 bytes) paths raise
        `InvalidInput`."""
        var n = len(path)
        if n == 0 or n > Self.MAX_PATHNAME:
            raise _invalid("UnixAddr.from_pathname")
        var a = Self(_kind=Self._PATHNAME)
        for i in range(n):
            if path[i] == 0:
                raise _invalid("UnixAddr.from_pathname")
            a._name[i] = path[i]
        a._len = UInt8(n)
        return a^

    @staticmethod
    def from_abstract_name(name: StringSlice) raises IoError -> Self:
        return Self.from_abstract_name(name.as_bytes())

    @staticmethod
    def from_abstract_name(name: Span[UInt8, _]) raises IoError -> Self:
        """`name` excludes the leading NUL; it may be empty or contain NULs."""
        var n = len(name)
        if n > Self.MAX_ABSTRACT:
            raise _invalid("UnixAddr.from_abstract_name")
        var a = Self(_kind=Self._ABSTRACT)
        for i in range(n):
            a._name[i] = name[i]
        a._len = UInt8(n)
        return a^

    @inline(.always)
    def is_unnamed(self) -> Bool:
        return self._kind == Self._UNNAMED

    @inline(.always)
    def is_pathname(self) -> Bool:
        return self._kind == Self._PATHNAME

    @inline(.always)
    def is_abstract(self) -> Bool:
        return self._kind == Self._ABSTRACT

    def name(ref self) -> Span[UInt8, origin_of(self._name)]:
        """The path (pathname) or the name after the NUL (abstract); empty
        when unnamed."""
        return Span(self._name)[0 : Int(self._len)]

    def __eq__(self, other: Self) -> Bool:
        if self._kind != other._kind or self._len != other._len:
            return False
        for i in range(Int(self._len)):
            if self._name[i] != other._name[i]:
                return False
        return True

    def __hash__[H: Hasher](self, mut hasher: H):
        self._kind.__hash__(hasher)
        hasher.update(self.name())

    def socklen(self) -> Int:
        """offsetof(sun_path) + name, +1 for the pathname NUL or the abstract
        leading NUL; just the family when unnamed."""
        if self._kind == Self._UNNAMED:
            return _SUN_PATH_OFFSET
        return min(_SUN_PATH_OFFSET + Int(self._len) + 1, size_of[SockaddrUn]())

    def to_raw(self) -> RawSockaddr:
        var raw = RawSockaddr()
        ref sun = _view[SockaddrUn](raw.storage)
        sun.family = UInt16(AF_UNIX)
        var at = 1 if self._kind == Self._ABSTRACT else 0
        for i in range(Int(self._len)):
            sun.path[at + i] = self._name[i]
        raw.len = UInt32(self.socklen())
        return raw^

    @staticmethod
    def from_raw(raw: RawSockaddr) raises IoError -> Self:
        """Decode a `sockaddr_un` from accept/getsockname/getpeername/
        recvfrom.

        - A length of exactly the family (2) is unnamed.
        - An abstract name is every byte after the leading NUL; it must fit
          `sun_path`, so the length is at most `sizeof(sockaddr_un)` (110).
        - A pathname ends at its first NUL or at the end of `sun_path`, and
          bytes past `sun_path` are ignored, so any length up to
          `RawSockaddr.capacity()` is accepted. Linux accepts a 108-byte
          path without a NUL (socklen 110) and then reports length 111: it
          NUL-terminates the path past `sun_path`, inside its
          `sockaddr_storage`. Such 108-byte paths decode (one byte longer
          than `from_pathname` allows) and re-encode with socklen 110.

        Another family, a length below 2 or above the capacity, or a too
        long abstract name raises `InvalidInput`."""
        comptime op = "UnixAddr.from_raw"
        var n = Int(raw.len)
        if raw.family() != AF_UNIX:
            raise _invalid(op)
        if n < _SUN_PATH_OFFSET or n > RawSockaddr.capacity():
            raise _invalid(op)
        var plen = n - _SUN_PATH_OFFSET
        if plen == 0:
            return Self.unnamed()
        ref sun = _view[SockaddrUn](raw.storage)
        if sun.path[0] == 0:
            if n > size_of[SockaddrUn]():
                raise _invalid(op)
            var a = Self(_kind=Self._ABSTRACT)
            for i in range(plen - 1):
                a._name[i] = sun.path[i + 1]
            a._len = UInt8(plen - 1)
            return a^
        var a = Self(_kind=Self._PATHNAME)
        var end = min(plen, UNIX_PATH_MAX)
        var k = 0
        while k < end and sun.path[k] != 0:
            a._name[k] = sun.path[k]
            k += 1
        a._len = UInt8(k)
        return a^

    def write_to(self, mut writer: Some[Writer]):
        """Pathname as is, abstract as `@name` (the `ss`/systemd
        convention), unnamed as `(unnamed)`. Bytes outside printable ASCII
        and backslashes are written as `\\xNN`, and so is a pathname's
        leading `@` or `(`, so that no pathname reads as an abstract name
        or as `(unnamed)`."""
        if self._kind == Self._UNNAMED:
            writer.write("(unnamed)")
            return
        if self._kind == Self._ABSTRACT:
            writer.write("@")
        var run = 0
        var n = Int(self._len)
        var lead = self._kind == Self._PATHNAME and n > 0 and (self._name[0] == 0x40 or self._name[0] == 0x28)
        for i in range(n + 1):
            if i < n and _is_plain(self._name[i]) and not (i == 0 and lead):
                continue
            if run < i:
                writer.write_string(
                    StringSlice(unsafe_from_utf8=Span(self._name)[run:i])
                )
            if i < n:
                var t = _Text()
                t.push(0x5C)
                t.push(0x78)
                var c = self._name[i]
                var hi = c >> 4
                var lo = c & 0xF
                t.push(hi + _ZERO if hi < 10 else hi + 87)
                t.push(lo + _ZERO if lo < 10 else lo + 87)
                t.write_to(writer)
            run = i + 1

    def write_repr_to(self, mut writer: Some[Writer]):
        writer.write("UnixAddr(", self, ")")


@inline(.always)
def _is_plain(c: UInt8) -> Bool:
    """Printable ASCII other than backslash."""
    return c >= 0x20 and c < 0x7F and c != 0x5C


# ---- kernel form ----------------------------------------------------------


@inline(.always)
def _view[T: AnyType](ref storage: SockaddrStorage) -> ref[storage] T:
    """`storage` reinterpreted as a concrete sockaddr (all are <= 128 bytes
    and <= 8-aligned, and SockaddrStorage is 8-aligned); mutable when
    `storage` is."""
    return Pointer(to=storage).unsafe_bitcast[T]()[]


@inline(.always)
def _store[T: Movable & Deinitable](mut storage: SockaddrStorage, var value: T):
    Pointer(to=storage).unsafe_bitcast[T]()[] = value^


# ---- interface names ------------------------------------------------------


def if_nametoindex(name: StringSlice) raises IoError -> UInt32:
    """Interface index of `name` (like `if_nametoindex(3)`, without libc).

    Raises `InvalidInput` for an empty, NUL-containing or too long (>15
    bytes) name and `NotFound` (ENODEV) for an unknown interface."""
    var b = name.as_bytes()
    return _if_nametoindex(b, 0, len(b))


def _if_nametoindex(
    b: Span[UInt8, _], start: Int, end: Int
) raises IoError -> UInt32:
    comptime op = "if_nametoindex"
    var n = end - start
    if n < 1 or n >= IF_NAMESIZE:
        raise _invalid(op)
    var req = Ifreq()
    for k in range(n):
        if b[start + k] == 0:
            raise _invalid(op)
        req.name[k] = b[start + k]
    # Any socket works for this ioctl; AF_UNIX needs no network stack.
    var fd = OwnedFd(
        unsafe_from_raw=Int32(
            check("socket", sys.socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0))
        )
    )
    while True:
        var r = sys.ioctl_ref(fd, SIOCGIFINDEX, req)
        if not is_err(r):
            return UInt32(req.ifindex)
        var e = Errno(err_of(r))
        if e == Errno.EINTR:
            continue
        if e == Errno.ENODEV:
            raise IoError(ErrorKind.NotFound, e, op)
        raise IoError.from_errno(op, e)
