"""Sockets: addresses, socket options (L1), blocking TCP/Unix streams with
deadlines (L2), and the sans-I/O codec contract. `ByteBuffer` lives in
`bytes` (re-exported here). Coming next: buffered reading, DNS resolution
and connect-by-name.

This is a socket library, not an async runtime: a concurrent server drives
nonblocking sockets from its own readiness loop (`linux.Epoll`). The
experimental event-loop runtime that used to live here is in the separate
mojo_rt repository.
"""

from .addr import (
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    RawSockaddr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
    UnixAddr,
    if_nametoindex,
)
from bytes.buffer import ByteBuffer
from .codec import Codec, LineCodec
from .socket import (
    Accepted,
    Domain,
    Protocol,
    Shutdown,
    Socket,
    SocketPair,
    SockType,
    TcpInfo,
    TcpKeepalive,
)
from .tcp import TcpAccepted, TcpListener, TcpStream
from .unix import UnixAccepted, UnixListener, UnixStream, UnixStreamPair
