"""Mirrors of kernel/C ABI structs for x86_64 and aarch64 (LP64, little endian).

Layouts are verified against this host's C headers by `pixi run abi-check`:
`tools/gen_abi.py` generates `build/test_abi_layout.mojo` (git-ignored) from
its `STRUCTS` table and runs it; `pixi run test` without a filter runs the
same check. A new mirror
must be added to `STRUCTS`; never edit the generated file. Fixed-size C
arrays use `Array` (not `SIMD`, whose alignment equals its width).
Multi-byte fields documented as "network order" hold big-endian values; use
`hton16`/`hton32` to convert. Other targets (big endian, 32-bit) are a build
error (`linux.syscall.assert_supported_target`).
"""

from std.bit import byte_swap
from std.sys import CompilationTarget, size_of

from .consts import IF_NAMESIZE
from .syscall import assert_supported_target

comptime _X86 = CompilationTarget.is_x86()


@inline(.always)
def hton16(v: UInt16) -> UInt16:
    assert_supported_target()  # the swap is only right on little endian
    return byte_swap(v)


@inline(.always)
def hton32(v: UInt32) -> UInt32:
    assert_supported_target()  # the swap is only right on little endian
    return byte_swap(v)


@inline(.always)
def ntoh16(v: UInt16) -> UInt16:
    assert_supported_target()  # the swap is only right on little endian
    return byte_swap(v)


@inline(.always)
def ntoh32(v: UInt32) -> UInt32:
    assert_supported_target()  # the swap is only right on little endian
    return byte_swap(v)


@fieldwise_init
struct SockaddrIn(Copyable, Movable):
    """`struct sockaddr_in` (16 bytes)."""

    var family: UInt16
    var port: UInt16
    """Network order."""
    var addr: UInt32
    """Network order."""
    var zero: Array[UInt8, 8]


@fieldwise_init
struct SockaddrIn6(Copyable, Movable):
    """`struct sockaddr_in6` (28 bytes)."""

    var family: UInt16
    var port: UInt16
    """Network order."""
    var flowinfo: UInt32
    """Network order."""
    var addr: Array[UInt8, 16]
    var scope_id: UInt32


comptime UNIX_PATH_MAX = 108


@fieldwise_init
struct SockaddrUn(Copyable, Movable):
    """`struct sockaddr_un` (110 bytes). A leading NUL in `path` selects the
    Linux abstract namespace; the socklen passed to the kernel decides how
    many path bytes are significant."""

    var family: UInt16
    var path: Array[UInt8, UNIX_PATH_MAX]


@fieldwise_init
struct SockaddrStorage(Copyable, Movable):
    """`struct sockaddr_storage` (128 bytes, 8-aligned): large enough for any
    address the kernel returns from accept/getsockname/recvfrom."""

    var family: UInt16
    var _pad: Array[UInt8, 118]
    var _align: UInt64

    @staticmethod
    def zeroed() -> Self:
        return Self(0, Array[UInt8, 118](fill=0), 0)


@fieldwise_init
struct Iovec(Copyable, Movable):
    """`struct iovec` (16 bytes)."""

    var base: Int
    """Address of the buffer."""
    var len: UInt


@fieldwise_init
struct Msghdr(Copyable, Movable):
    """`struct msghdr` (56 bytes)."""

    var name: Int
    """Address of a sockaddr, or 0."""
    var namelen: UInt32
    var iov: Int
    """Address of an `Iovec` array."""
    var iovlen: UInt
    var control: Int
    """Address of the control (cmsg) buffer, or 0."""
    var controllen: UInt
    var flags: Int32


@fieldwise_init
struct Cmsghdr(Copyable, Movable):
    """`struct cmsghdr` header (16 bytes); data follows, 8-aligned.

    A control buffer (`Msghdr.control`) is a sequence of these headers, each
    followed by its data. For a message carrying `n` data bytes, `len` is
    `cmsg_len(n)`, the data starts `CMSG_DATA_OFFSET` bytes after the header,
    and the message occupies `cmsg_space(n)` bytes (the next header starts
    there). The buffer itself must be 8-aligned: back it with
    `Array[UInt64, k]`, not a byte list.
    """

    var len: UInt
    var level: Int32
    var type: Int32


@inline(.always)
def cmsg_align(n: Int) -> Int:
    """`CMSG_ALIGN(n)`: `n` rounded up to a multiple of `size_of[UInt]()` (8).
    """
    comptime a = size_of[UInt]()
    return (n + a - 1) & ~(a - 1)


@inline(.always)
def cmsg_len(n: Int) -> Int:
    """`CMSG_LEN(n)`: the `Cmsghdr.len` value for `n` data bytes (header plus
    data, without trailing padding)."""
    return CMSG_DATA_OFFSET + n


@inline(.always)
def cmsg_space(n: Int) -> Int:
    """`CMSG_SPACE(n)`: bytes one control message with `n` data bytes
    occupies, trailing padding included. Size control buffers with it."""
    return CMSG_DATA_OFFSET + cmsg_align(n)


comptime CMSG_DATA_OFFSET = cmsg_align(size_of[Cmsghdr]())
"""Offset of the data from the start of its `Cmsghdr` (`CMSG_DATA`): 16."""


@fieldwise_init
struct Pollfd(Copyable, Movable):
    """`struct pollfd` (8 bytes)."""

    var fd: Int32
    var events: Int16
    var revents: Int16


@fieldwise_init
struct Timespec(Copyable, Movable):
    """`struct timespec` (16 bytes)."""

    var sec: Int
    var nsec: Int


@fieldwise_init
struct Timeval(Copyable, Movable):
    """`struct timeval` (16 bytes): two 64-bit longs on x86_64 and aarch64.
    Socket timeouts (SO_RCVTIMEO/SO_SNDTIMEO) take one."""

    var sec: Int
    var usec: Int


@fieldwise_init
struct Linger(Copyable, Movable):
    """`struct linger` (8 bytes). Linux `l_linger` is in seconds."""

    var onoff: Int32
    var linger: Int32


@fieldwise_init
struct Ucred(Copyable, Movable):
    """`struct ucred` (12 bytes), from `SO_PEERCRED`."""

    var pid: Int32
    var uid: UInt32
    var gid: UInt32


@fieldwise_init
struct Rlimit(TrivialRegisterPassable, Writable):
    """`struct rlimit64` (16 bytes), as prlimit64 takes it: soft (`cur`) and
    hard (`max`) limit; `linux.probe.RLIM_INFINITY` means unlimited."""

    var cur: UInt64
    var max: UInt64

    def write_to(self, mut writer: Some[Writer]):
        writer.write("Rlimit(cur=", self.cur, ", max=", self.max, ")")


struct Ifreq(Copyable, Movable):
    """`struct ifreq` (40 bytes, 8-aligned) as SIOCGIFINDEX uses it: the
    interface name, then a 24-byte union whose first int is `ifr_ifindex`.
    """

    var name: Array[UInt8, IF_NAMESIZE]
    var ifindex: Int32
    var _pad: Array[UInt8, 12]
    var _align: UInt64

    def __init__(out self):
        """Zeroed (an empty name)."""
        self.name = Array[UInt8, IF_NAMESIZE](fill=0)
        self.ifindex = 0
        self._pad = Array[UInt8, 12](fill=0)
        self._align = 0


comptime _EPOLL_WORDS = 3 if _X86 else 4


struct EpollEvent(Copyable, Movable):
    """`struct epoll_event`. Packed (12 bytes) on x86_64, 16 bytes with the
    64-bit `data` at offset 8 on aarch64. Stored as 32-bit words because Mojo
    has no packed structs; use `events`/`data` accessors."""

    var _w: Array[UInt32, _EPOLL_WORDS]

    def __init__(out self, events: UInt32, data: UInt64):
        self._w = Array[UInt32, _EPOLL_WORDS](fill=0)
        self._w[0] = events
        self.set_data(data)

    @inline(.always)
    def events(self) -> UInt32:
        return self._w[0]

    @inline(.always)
    def data(self) -> UInt64:
        comptime lo = 1 if _X86 else 2
        return UInt64(self._w[lo]) | (UInt64(self._w[lo + 1]) << 32)

    @inline(.always)
    def set_data(mut self, data: UInt64):
        comptime lo = 1 if _X86 else 2
        self._w[lo] = UInt32(data & 0xFFFFFFFF)
        self._w[lo + 1] = UInt32(data >> 32)


comptime UTS_LEN = 65


@fieldwise_init
struct Utsname(Copyable, Movable):
    """`struct utsname` (6 x 65 bytes)."""

    var sysname: Array[UInt8, UTS_LEN]
    var nodename: Array[UInt8, UTS_LEN]
    var release: Array[UInt8, UTS_LEN]
    var version: Array[UInt8, UTS_LEN]
    var machine: Array[UInt8, UTS_LEN]
    var domainname: Array[UInt8, UTS_LEN]

    @staticmethod
    def zeroed() -> Self:
        return Self(
            Array[UInt8, UTS_LEN](fill=0),
            Array[UInt8, UTS_LEN](fill=0),
            Array[UInt8, UTS_LEN](fill=0),
            Array[UInt8, UTS_LEN](fill=0),
            Array[UInt8, UTS_LEN](fill=0),
            Array[UInt8, UTS_LEN](fill=0),
        )


struct RawSockaddr(Copyable, Movable):
    """A socket address in kernel form plus its socklen.

    `RawSockaddr()` is zeroed with `len` = capacity, ready to receive from
    `sys.accept4/getsockname/getpeername/recvfrom(fd, raw.storage, raw.len)`.
    `X.to_raw()` fills it for `sys.bind/connect/sendto(fd, raw.storage,
    raw.socklen())`."""

    var storage: SockaddrStorage
    var len: UInt32

    @inline(.always)
    def __init__(out self):
        self.storage = SockaddrStorage.zeroed()
        self.len = UInt32(size_of[SockaddrStorage]())

    @inline(.always)
    def __init__(out self, *, var storage: SockaddrStorage, len: UInt32):
        self.storage = storage^
        self.len = len

    @staticmethod
    @inline(.always)
    def capacity() -> Int:
        return size_of[SockaddrStorage]()

    @inline(.always)
    def family(self) -> Int:
        return Int(self.storage.family)

    @inline(.always)
    def socklen(self) -> Int:
        return Int(self.len)

    def reset(mut self):
        """Zero and restore `len` to capacity before reusing as a receive
        buffer (the kernel shrinks `len`)."""
        self.storage = SockaddrStorage.zeroed()
        self.len = UInt32(size_of[SockaddrStorage]())


@fieldwise_init
struct IpMreqn(Copyable, Movable):
    """`struct ip_mreqn` (12 bytes): an IPv4 multicast membership request
    (IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP)."""

    var multiaddr: UInt32
    """The group, network order."""
    var address: UInt32
    """The local interface's address (network order), or 0 for any."""
    var ifindex: Int32
    """The interface index, or 0 to pick by `address`."""


@fieldwise_init
struct Ipv6Mreq(Copyable, Movable):
    """`struct ipv6_mreq` (20 bytes): an IPv6 multicast membership request
    (IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP)."""

    var multiaddr: Array[UInt8, 16]
    var interface: UInt32
    """The interface index, or 0 for the kernel's choice."""


@fieldwise_init
struct Mmsghdr(Copyable, Movable):
    """`struct mmsghdr` (64 bytes): one message of sendmmsg/recvmmsg."""

    var hdr: Msghdr
    var len: UInt32
    """Bytes sent or received for this message (set by the kernel)."""


struct CloneArgs(Copyable, Movable):
    """`struct clone_args` (88 bytes, the size since Linux 5.7), as clone3
    takes it. Pointer fields (`pidfd`, `child_tid`, `parent_tid`) hold
    addresses."""

    var flags: UInt64
    var pidfd: UInt64
    """Where the kernel stores the child's pidfd (with CLONE_PIDFD)."""
    var child_tid: UInt64
    var parent_tid: UInt64
    var exit_signal: UInt64
    """The signal the parent gets when the child ends (SIGCHLD for a
    child that waitid sees without __WALL)."""
    var stack: UInt64
    var stack_size: UInt64
    var tls: UInt64
    var set_tid: UInt64
    var set_tid_size: UInt64
    var cgroup: UInt64

    def __init__(out self):
        """All zero: a fork-like clone on the caller's stack."""
        self.flags = 0
        self.pidfd = 0
        self.child_tid = 0
        self.parent_tid = 0
        self.exit_signal = 0
        self.stack = 0
        self.stack_size = 0
        self.tls = 0
        self.set_tid = 0
        self.set_tid_size = 0
        self.cgroup = 0


struct Siginfo(Copyable, Movable):
    """`siginfo_t` (128 bytes) with the fields `waitid` fills for a child:
    `code` is CLD_EXITED (then `status` is its exit code) or CLD_KILLED /
    CLD_DUMPED (then `status` is the signal)."""

    var signo: Int32
    var errno: Int32
    var code: Int32
    var _pad0: Int32
    var pid: Int32
    """0 if waitid with WNOHANG found no child that changed state."""
    var uid: UInt32
    var status: Int32
    var _pad1: Int32
    var _rest: Array[UInt64, 12]

    def __init__(out self):
        """Zeroed (`pid` 0: nothing found)."""
        self.signo = 0
        self.errno = 0
        self.code = 0
        self._pad0 = 0
        self.pid = 0
        self.uid = 0
        self.status = 0
        self._pad1 = 0
        self._rest = Array[UInt64, 12](fill=0)


struct SignalfdSiginfo(Copyable, Movable):
    """`struct signalfd_siginfo` (128 bytes): one signal read from a
    signalfd. Only the leading fields are mirrored by name."""

    var signo: UInt32
    var errno: Int32
    var code: Int32
    var pid: UInt32
    """The sender's pid (for `kill`)."""
    var uid: UInt32
    var _pad: UInt32
    var _rest: Array[UInt64, 13]

    def __init__(out self):
        self.signo = 0
        self.errno = 0
        self.code = 0
        self.pid = 0
        self.uid = 0
        self._pad = 0
        self._rest = Array[UInt64, 13](fill=0)


@fieldwise_init
struct OpenHow(Copyable, Movable):
    """`struct open_how` (24 bytes), as openat2 takes it: open flags, the
    mode for O_CREAT, and RESOLVE_* restrictions on the path walk."""

    var flags: UInt64
    var mode: UInt64
    var resolve: UInt64


struct Statx(Copyable, Movable):
    """`struct statx` (256 bytes, the same on x86_64 and aarch64, unlike
    `struct stat`), as statx fills it. Only the fields used are named."""

    var mask: UInt32
    """Which fields the kernel filled (STATX_*)."""
    var blksize: UInt32
    var attributes: UInt64
    var nlink: UInt32
    var uid: UInt32
    var gid: UInt32
    var mode: UInt16
    """The file type (S_IFMT bits) and permissions."""
    var _pad0: UInt16
    var ino: UInt64
    var size: UInt64
    var blocks: UInt64
    var _attributes_mask: UInt64
    var _atime: Array[UInt64, 2]
    var _btime: Array[UInt64, 2]
    var _ctime: Array[UInt64, 2]
    var mtime_sec: Int64
    var mtime_nsec: UInt32
    var _mtime_reserved: Int32
    var _rest: Array[UInt64, 16]

    def __init__(out self):
        self.mask = 0
        self.blksize = 0
        self.attributes = 0
        self.nlink = 0
        self.uid = 0
        self.gid = 0
        self.mode = 0
        self._pad0 = 0
        self.ino = 0
        self.size = 0
        self.blocks = 0
        self._attributes_mask = 0
        self._atime = Array[UInt64, 2](fill=0)
        self._btime = Array[UInt64, 2](fill=0)
        self._ctime = Array[UInt64, 2](fill=0)
        self.mtime_sec = 0
        self.mtime_nsec = 0
        self._mtime_reserved = 0
        self._rest = Array[UInt64, 16](fill=0)
