"""Sockets: addresses, socket options (L1), blocking TCP/Unix streams with
deadlines (L2), and the sans-I/O codec contract. `ByteBuffer` lives in
`bytes` (re-exported here).

Evented connections on the `rt` event loop are in `net.evented`
(`TcpServer[H]`, `dial[H]`, `ConnHandler`, `Conn`). It is deliberately not
re-exported here, so blocking users never pull in `rt`; blocking modules and
codecs must not import `rt`. DNS comes in M3.
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
