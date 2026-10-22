"""DNS messages, sans-I/O: building A/AAAA queries and parsing the responses
(RFC 1035; AAAA from RFC 3596; the EDNS(0) OPT record from RFC 6891).

`net.resolver` sends what `build_query` returns and hands each datagram it
receives to `parse_response` together with the query. Nothing here touches
a socket or a clock.

Accepting a response (RFC 5452's rules against forged answers):
- It must answer *this* query: the same ID, QR set, opcode QUERY, and
  exactly one question equal to the query's (name compared ignoring ASCII
  case, same type and class). Anything else is not an answer and
  `parse_response` returns None: the resolver ignores it and keeps waiting,
  so a forged packet can neither win nor make the lookup fail. The one
  exception is a FORMERR or NOTIMP reply with no question section, which
  some servers send for queries they cannot parse; it is accepted as that
  error.
- The resolver also reads it from a connected socket, so the kernel drops
  datagrams from any other address or port.

Parsing is defensive. Every length and offset is bounds-checked, labels are
at most 63 bytes, names at most 255 bytes, and a compression pointer must
point strictly before itself, so following pointers always terminates.
Whatever does not fit raises `InvalidData` (op "dns"). Names are compared
in wire form (length-prefixed labels, ASCII lowercase), never as dotted
text, so a label that contains a `.` cannot alias two labels.

Answers: the A or AAAA records of the question's name, following a CNAME
chain of at most `MAX_CNAME_HOPS` links through the answer section, in any
record order. Records of other types and classes are skipped.
"""

from linux import ErrorKind, IoError

from .addr import IpAddr, Ipv4Addr, Ipv6Addr

comptime TYPE_A: UInt16 = 1
comptime TYPE_CNAME: UInt16 = 5
comptime TYPE_AAAA: UInt16 = 28
comptime TYPE_OPT: UInt16 = 41
comptime CLASS_IN: UInt16 = 1

comptime RCODE_NOERROR = 0
comptime RCODE_FORMERR = 1
comptime RCODE_SERVFAIL = 2
comptime RCODE_NXDOMAIN = 3
comptime RCODE_NOTIMP = 4
comptime RCODE_REFUSED = 5

comptime HEADER_LEN = 12
comptime MAX_NAME_LEN = 255
"""Longest name in wire form, terminating root label included."""
comptime MAX_LABEL_LEN = 63
comptime MAX_CNAME_HOPS = 16
comptime EDNS_PAYLOAD = 1232
"""The UDP payload size to advertise with EDNS(0): DNS Flag Day 2020's
value, small enough to avoid IP fragmentation on common paths."""

comptime _FLAG_QR: UInt16 = 0x8000
comptime _FLAG_TC: UInt16 = 0x0200
comptime _FLAG_RD: UInt16 = 0x0100
comptime _OPCODE_MASK: UInt16 = 0x7800


# ---- names -------------------------------------------------------------------


@inline(.always)
def _lower(b: UInt8) -> UInt8:
    if b >= 65 and b <= 90:
        return b + 32
    return b


@inline(.always)
def _is_name_byte(b: UInt8) -> Bool:
    """Letters, digits, `-` and `_` (service labels such as `_tcp`)."""
    return (
        (b >= 97 and b <= 122)
        or (b >= 65 and b <= 90)
        or (b >= 48 and b <= 57)
        or b == 45
        or b == 95
    )


def encode_name(name: StringSlice, mut out: List[UInt8]) raises IoError:
    """Append `name` in wire form, ASCII-lowercased. One trailing `.` is
    allowed (an absolute name). `InvalidInput` (op "dns.encode_name") for an
    empty name or label, a label over 63 bytes or starting or ending with
    `-`, a name over 255 bytes, or a byte outside letters, digits, `-` and
    `_` (send IDNs in punycode); `out` is unchanged then."""
    var b = name.as_bytes()
    var n = len(b)
    if n > 0 and b[n - 1] == 46:  # one trailing dot: absolute name
        n -= 1
    if n == 0 or n + 2 > MAX_NAME_LEN:
        raise IoError.of_kind("dns.encode_name", ErrorKind.InvalidInput)
    var wire = List[UInt8](capacity=n + 2)
    var label_at = 0
    wire.append(0)
    var label_len = 0
    for i in range(n):
        var c = b[i]
        if c == 46:
            if label_len == 0 or wire[len(wire) - 1] == 45:
                raise IoError.of_kind("dns.encode_name", ErrorKind.InvalidInput)
            wire[label_at] = UInt8(label_len)
            label_at = len(wire)
            wire.append(0)
            label_len = 0
            continue
        if (
            not _is_name_byte(c)
            or label_len == MAX_LABEL_LEN
            or (label_len == 0 and c == 45)
        ):
            raise IoError.of_kind("dns.encode_name", ErrorKind.InvalidInput)
        wire.append(_lower(c))
        label_len += 1
    if label_len == 0 or wire[len(wire) - 1] == 45:
        raise IoError.of_kind("dns.encode_name", ErrorKind.InvalidInput)
    wire[label_at] = UInt8(label_len)
    wire.append(0)  # the root label
    out.extend(wire^)


def is_valid_name(name: StringSlice) -> Bool:
    """Whether `encode_name` accepts `name`."""
    var tmp = List[UInt8]()
    try:
        encode_name(name, tmp)
    except:
        return False
    return True


@inline(.always)
def _u16(msg: Span[UInt8, _], at: Int) raises IoError -> UInt16:
    if at < 0 or at + 2 > len(msg):
        raise IoError.of_kind("dns", ErrorKind.InvalidData)
    return (UInt16(msg[at]) << 8) | UInt16(msg[at + 1])


@inline(.always)
def _u32(msg: Span[UInt8, _], at: Int) raises IoError -> UInt32:
    if at < 0 or at + 4 > len(msg):
        raise IoError.of_kind("dns", ErrorKind.InvalidData)
    return (
        (UInt32(msg[at]) << 24)
        | (UInt32(msg[at + 1]) << 16)
        | (UInt32(msg[at + 2]) << 8)
        | UInt32(msg[at + 3])
    )


def read_name(
    msg: Span[UInt8, _], at: Int, mut name: List[UInt8]
) raises IoError -> Int:
    """Decode the (possibly compressed) name at `at` into `name` (cleared
    first) in lowercase wire form; returns the offset just after it in the
    message. `InvalidData` for anything out of bounds, a label over 63
    bytes, a name over 255 bytes, a pointer that does not point strictly
    before itself, or a reserved label type."""
    name.clear()
    var pos = at
    var after = -1  # where the name ends in the message, once known
    while True:
        if pos < 0 or pos >= len(msg):
            raise IoError.of_kind("dns", ErrorKind.InvalidData)
        var len_byte = msg[pos]
        if len_byte == 0:
            name.append(0)
            if len(name) > MAX_NAME_LEN:
                raise IoError.of_kind("dns", ErrorKind.InvalidData)
            return after if after >= 0 else pos + 1
        var kind = len_byte & 0xC0
        if kind == 0xC0:
            var target = Int(_u16(msg, pos) & 0x3FFF)
            if target >= pos:  # forward or self pointers could loop
                raise IoError.of_kind("dns", ErrorKind.InvalidData)
            if after < 0:
                after = pos + 2
            pos = target
            continue
        if kind != 0:  # 0x40 and 0x80 are reserved label types
            raise IoError.of_kind("dns", ErrorKind.InvalidData)
        var n = Int(len_byte)
        if pos + 1 + n > len(msg) or len(name) + 1 + n + 1 > MAX_NAME_LEN:
            raise IoError.of_kind("dns", ErrorKind.InvalidData)
        name.append(len_byte)
        for i in range(n):
            name.append(_lower(msg[pos + 1 + i]))
        pos += 1 + n


@inline(.always)
def _same_name(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Both in lowercase wire form already."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


# ---- queries -----------------------------------------------------------------


def build_query(
    id: UInt16, name: StringSlice, qtype: UInt16, edns: Bool = False
) raises IoError -> List[UInt8]:
    """One question (`name`, `qtype`, class IN) with recursion desired. With
    `edns`, an OPT record advertises `EDNS_PAYLOAD` bytes for UDP answers.
    Name errors as for `encode_name`."""
    var q = List[UInt8](capacity=HEADER_LEN + name.byte_length() + 6 + 11)
    q.append(UInt8(id >> 8))
    q.append(UInt8(id & 0xFF))
    q.append(UInt8(_FLAG_RD >> 8))  # RD; opcode QUERY
    q.append(0)
    for v in [UInt16(1), UInt16(0), UInt16(0), UInt16(1 if edns else 0)]:
        q.append(UInt8(v >> 8))
        q.append(UInt8(v & 0xFF))
    encode_name(name, q)
    q.append(UInt8(qtype >> 8))
    q.append(UInt8(qtype & 0xFF))
    q.append(0)
    q.append(UInt8(CLASS_IN))
    if edns:
        q.append(0)  # root owner name
        q.append(0)
        q.append(UInt8(TYPE_OPT))
        q.append(UInt8(EDNS_PAYLOAD >> 8))  # CLASS = payload size
        q.append(UInt8(EDNS_PAYLOAD & 0xFF))
        for _ in range(6):  # TTL (ext. rcode, version, flags), RDLENGTH
            q.append(0)
    return q^


def query_id(query: Span[UInt8, _]) raises IoError -> UInt16:
    return _u16(query, 0)


# ---- responses ---------------------------------------------------------------


struct DnsAnswer(Movable):
    """What a response says about the question."""

    var rcode: Int
    """RCODE_NOERROR with empty `addrs` means the name exists without such
    records (NODATA)."""
    var truncated: Bool
    """TC was set: nothing else was parsed; ask again over TCP."""
    var addrs: List[IpAddr]
    """The question type's addresses for its name, in answer order."""
    var ttl: UInt32
    """The smallest TTL of those records (0 without any)."""

    def __init__(out self, rcode: Int, truncated: Bool):
        self.rcode = rcode
        self.truncated = truncated
        self.addrs = List[IpAddr]()
        self.ttl = 0


@fieldwise_init
struct _Alias(Copyable, Movable):
    var owner: List[UInt8]
    var target: List[UInt8]


@fieldwise_init
struct _Record(Copyable, Movable):
    var owner: List[UInt8]
    var addr: IpAddr
    var ttl: UInt32


def _question_len(query: Span[UInt8, _]) raises IoError -> Int:
    """Length of the query's question section (name + type + class)."""
    var pos = HEADER_LEN
    while True:
        if pos >= len(query):
            raise IoError.of_kind("dns", ErrorKind.InvalidInput)
        var n = Int(query[pos])
        pos += 1
        if n == 0:
            break
        pos += n
    if pos + 4 > len(query):
        raise IoError.of_kind("dns", ErrorKind.InvalidInput)
    return pos + 4 - HEADER_LEN


def parse_response(
    msg: Span[UInt8, _], query: Span[UInt8, _]
) raises IoError -> Optional[DnsAnswer]:
    """Parse `msg` as the response to `query` (as built by `build_query`).
    None if it is not a response to this query (see the module docs);
    `InvalidData` if it is but is malformed."""
    if len(msg) < HEADER_LEN or len(query) < HEADER_LEN:
        return None
    if msg[0] != query[0] or msg[1] != query[1]:
        return None
    var flags = _u16(msg, 2)
    if (flags & _FLAG_QR) == 0 or (flags & _OPCODE_MASK) != 0:
        return None
    var rcode = Int(flags & 0x000F)
    var qdcount = _u16(msg, 4)
    if qdcount == 0 and (rcode == RCODE_FORMERR or rcode == RCODE_NOTIMP):
        return DnsAnswer(rcode, False)
    if qdcount != 1:
        return None
    var qlen = _question_len(query)
    if HEADER_LEN + qlen > len(msg):
        return None
    for i in range(HEADER_LEN, HEADER_LEN + qlen):
        if _lower(msg[i]) != _lower(query[i]):
            return None
    if (flags & _FLAG_TC) != 0:
        return DnsAnswer(rcode, True)
    var result = DnsAnswer(rcode, False)
    if rcode != RCODE_NOERROR:
        return result^
    var qtype = _u16(query, HEADER_LEN + qlen - 4)
    var qname = List[UInt8]()
    _ = read_name(query, HEADER_LEN, qname)

    # Collect CNAMEs and addresses of the question type, then follow the
    # chain from the question's name: record order does not matter.
    var ancount = Int(_u16(msg, 6))
    var aliases = List[_Alias]()
    var records = List[_Record]()
    var pos = HEADER_LEN + qlen
    var rr_name = List[UInt8]()
    for _ in range(ancount):
        pos = read_name(msg, pos, rr_name)
        var rtype = _u16(msg, pos)
        var rclass = _u16(msg, pos + 2)
        var ttl = _u32(msg, pos + 4)
        var rdlen = Int(_u16(msg, pos + 8))
        var rdata = pos + 10
        if rdata + rdlen > len(msg):
            raise IoError.of_kind("dns", ErrorKind.InvalidData)
        pos = rdata + rdlen
        if rclass != CLASS_IN:
            continue
        if rtype == TYPE_CNAME:
            var target = List[UInt8]()
            var end = read_name(msg, rdata, target)
            if end != rdata + rdlen:
                raise IoError.of_kind("dns", ErrorKind.InvalidData)
            aliases.append(_Alias(rr_name.copy(), target^))
        elif rtype == qtype and rtype == TYPE_A:
            if rdlen != 4:
                raise IoError.of_kind("dns", ErrorKind.InvalidData)
            var ip = Ipv4Addr(
                msg[rdata], msg[rdata + 1], msg[rdata + 2], msg[rdata + 3]
            )
            records.append(_Record(rr_name.copy(), IpAddr(ip), ttl))
        elif rtype == qtype and rtype == TYPE_AAAA:
            if rdlen != 16:
                raise IoError.of_kind("dns", ErrorKind.InvalidData)
            var o = Array[UInt8, 16](fill=0)
            for i in range(16):
                o[i] = msg[rdata + i]
            records.append(
                _Record(rr_name.copy(), IpAddr(Ipv6Addr.from_octets(o)), ttl)
            )

    var name = qname^
    var hops = 0
    while True:
        var next = -1
        for i in range(len(aliases)):
            if _same_name(aliases[i].owner, name):
                next = i
                break
        if next < 0:
            break
        hops += 1
        if hops > MAX_CNAME_HOPS:
            raise IoError.of_kind("dns", ErrorKind.InvalidData)
        name = aliases[next].target.copy()
    var min_ttl = UInt32.MAX
    for r in records:
        if _same_name(r.owner, name):
            result.addrs.append(r.addr)
            min_ttl = min(min_ttl, r.ttl)
    if len(result.addrs) > 0:
        result.ttl = min_ttl
    return result^


def tcp_frame(msg: Span[UInt8, _]) raises IoError -> List[UInt8]:
    """`msg` with the 2-byte length prefix of DNS over TCP (RFC 1035
    4.2.2); `InvalidInput` over 65535 bytes."""
    if len(msg) > 0xFFFF:
        raise IoError.of_kind("dns.tcp_frame", ErrorKind.InvalidInput)
    var out = List[UInt8](capacity=len(msg) + 2)
    out.append(UInt8(len(msg) >> 8))
    out.append(UInt8(len(msg) & 0xFF))
    for b in msg:
        out.append(b)
    return out^
