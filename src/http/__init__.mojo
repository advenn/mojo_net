"""HTTP/1.1 (RFC 9110, RFC 9112): message types, the header map, and (as
the milestones land) the sans-I/O message parser, body framing, connection
state machines, and a blocking client.

The protocol modules are sans-I/O (docs/design.md, contract 1): they parse
and build bytes and never touch a socket or a clock, so the same code runs
under a blocking stream, an epoll loop or a test that feeds byte arrays.
Only `http.client` and `http.server` import `net`; `tools/check_imports.py`
enforces it.
"""

from .headers import Headers
from .parse import HeadParser, Limits, RequestHead, ResponseHead
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
