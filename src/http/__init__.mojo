"""HTTP/1.1 (RFC 9110, RFC 9112): message types, the header map, the
sans-I/O message parser, body framing and connection state machines,
server-sent events (`sse`) and Retry-After (`retry`), and a blocking client.

The protocol modules are sans-I/O (docs/design.md, contract 1): they parse
and build bytes and never touch a socket or a clock, so the same code runs
under a blocking stream, an epoll loop or a test that feeds byte arrays.
Only `http.client` imports `net` and `tls`; `tools/check_imports.py`
enforces it. It is not re-exported here, so importing the protocol modules
never pulls in the transport: `from http.client import Client`. The server
is its own package, `server` (docs/server.md).
"""

from .body import (
    BodyDecoder,
    BodyKind,
    BodyLimits,
    Framing,
    Piece,
    content_length,
    encode_chunk,
    encode_last_chunk,
    request_framing,
    response_framing,
)
from .connection import (
    ClientConnection,
    ClientEvent,
    EventKind,
    ServerConnection,
    ServerEvent,
)
from .headers import Headers
from .parse import HeadParser, Limits, RequestHead, ResponseHead
from .retry import parse_http_date, retry_after
from .sse import SseEvent, SseParser, write_comment, write_event
from .types import (
    CONNECT,
    DELETE,
    GET,
    HEAD,
    OPTIONS,
    PATCH,
    POST,
    PUT,
    TRACE,
    Version,
    check_status,
    is_client_error,
    is_informational,
    is_redirect,
    is_server_error,
    is_success,
    reason,
)
