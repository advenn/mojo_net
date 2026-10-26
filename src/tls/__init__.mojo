"""TLS through OpenSSL (docs/tls.md): no TLS or cryptography of its own.

- `config`: `ClientConfig` (trust, ALPN) builds a `ClientContext`, the
  shared, read-only `SSL_CTX` with every policy knob set and read back.
- `client`: `TlsClient`, one connection as a sans-I/O state machine over
  memory BIOs, which verifies the server before anything is exchanged.
- `server_config`: `ServerConfig` (certificate, key, names, ALPN) builds a
  `ServerContext`; `server`: `TlsServer`, the server side of a connection.
- `engine`: what both sides share (records, events, bounds, latching).
- `stream`: `TlsStream`, a blocking client stream over `net.TcpStream`
  (not re-exported here, so the state machine never pulls in sockets:
  `from tls.stream import TlsStream`).
- `target`: the expected identity, a validated DNS name or IP address.
- `error`: `TlsError`, an `IoError` plus a `Category` saying why.
- `ffi`: the only module that calls C (`Library`).
"""

from .client import TlsClient
from .config import ClientConfig, ClientContext, Trust
from .engine import TlsEvent, TlsEventKind
from .server import TlsServer
from .server_config import ServerConfig, ServerContext
from .error import Category, TlsError
from .target import Target
