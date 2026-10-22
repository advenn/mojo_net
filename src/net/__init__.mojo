"""Sockets: addresses, socket options (L1) and blocking TCP/Unix streams with
deadlines (L2), and `BufReader` for bounded, frame-at-a-time reads over
them. `ByteBuffer` and the sans-I/O `Codec` contract live in `bytes` and are
re-exported here. Coming next: DNS resolution and connect-by-name
(docs/net.md).

This is a socket library, not an async runtime: a concurrent server drives
nonblocking sockets from its own readiness loop (`linux.Epoll`). The
experimental event loop is the separate, frozen `rt` package, which builds
on `net`; `net` never imports it.
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
from bytes.codec import Codec, LineCodec
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
from .reader import BufReader, BufReaderParts, Read
from .tcp import TcpAccepted, TcpListener, TcpStream
from .unix import UnixAccepted, UnixListener, UnixStream, UnixStreamPair
