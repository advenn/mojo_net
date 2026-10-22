"""The seam between the readiness proactor (`rt.core.Loop`) and the world.

A `Driver` supplies a readiness source (edge-triggered: an event says "this
fd *became* ready"), nonblocking socket syscalls and a clock. `EpollDriver`
talks to the kernel; `SimDriver` simulates a network in memory with a virtual
clock, so the same proactor logic runs deterministically in tests.

Conventions: every call returns the raw result (`>= 0`, or `-errno`), fds are
raw numbers owned by the `Loop` (it closes them through `close`), sockets are
always nonblocking and CLOEXEC, and sends never raise SIGPIPE.
"""

from bytes.buffer import ByteBuffer
from linux import IoError, Instant
from linux.abi import RawSockaddr
from linux.consts import EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLLRDHUP

# Readiness bits use the epoll values so the epoll driver passes them through.
comptime READ_READY: UInt32 = UInt32(EPOLLIN)
comptime WRITE_READY: UInt32 = UInt32(EPOLLOUT)
comptime READ_CLOSED: UInt32 = UInt32(EPOLLRDHUP)
comptime HANGUP: UInt32 = UInt32(EPOLLHUP)
comptime ERROR: UInt32 = UInt32(EPOLLERR)


@fieldwise_init
struct ReadyEvent(TrivialRegisterPassable, Writable):
    """`token` is the FdId the fd was registered with (stale tokens are
    dropped by the loop); `events` is a mask of the bits above."""

    var token: UInt64
    var events: UInt32

    def write_to(self, mut writer: Some[Writer]):
        writer.write("ReadyEvent(", self.token, ", ", self.events, ")")


trait Driver(Movable):
    @staticmethod
    def create() raises IoError -> Self:
        ...

    def now(self) -> Instant:
        """Monotonic time (virtual in the simulator)."""
        ...

    def socket(mut self, family: Int, type_: Int) -> Int:
        """A new nonblocking, CLOEXEC socket of `type_` (SOCK_STREAM...)."""
        ...

    def set_int_option(
        mut self, fd: Int32, level: Int, name: Int, value: Int32
    ) -> Int:
        ...

    def bind(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        ...

    def listen(mut self, fd: Int32, backlog: Int) -> Int:
        ...

    def local_addr(mut self, fd: Int32, mut addr: RawSockaddr) -> Int:
        ...

    def accept(mut self, fd: Int32, mut peer: RawSockaddr) -> Int:
        """Returns the new nonblocking, CLOEXEC fd or -errno."""
        ...

    def connect(mut self, fd: Int32, addr: RawSockaddr) -> Int:
        """0, -EINPROGRESS, or another -errno."""
        ...

    def socket_error(mut self, fd: Int32) -> Int:
        """SO_ERROR as -errno (0 if none)."""
        ...

    def recv(mut self, fd: Int32, mut buf: ByteBuffer) -> Int:
        """Receive into `buf`'s writable tail (the caller reserved room) and
        commit what arrived. Bytes (0 = EOF) or -errno."""
        ...

    def send(mut self, fd: Int32, buf: ByteBuffer) -> Int:
        """Send from `buf`'s readable bytes (MSG_NOSIGNAL); the caller
        consumes what was sent. Bytes or -errno."""
        ...

    def shutdown(mut self, fd: Int32, how: Int) -> Int:
        ...

    def close(mut self, fd: Int32) -> Int:
        ...

    def register(mut self, fd: Int32, token: UInt64) -> Int:
        """Watch `fd` for all readiness, edge-triggered, reporting `token`."""
        ...

    def deregister(mut self, fd: Int32) -> Int:
        ...

    def wait(mut self, timeout_ns: Int, mut out: List[ReadyEvent]) raises IoError:
        """Append readiness events, waiting at most `timeout_ns` (< 0:
        forever, 0: poll). May return with no events (signal, timeout)."""
        ...
