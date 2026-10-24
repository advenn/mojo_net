"""PostgreSQL (docs/pg.md): the wire format (`message`), password
authentication (`auth`: MD5 and SCRAM-SHA-256) and the sans-I/O codec for
one session (`connection`). All of it is sans-I/O; the blocking client
over `net` is planned as `pg.client` (P3)."""

from .auth import MAX_SCRAM_ITERATIONS, SCRAM_SHA_256, ScramClient, md5_password
from .connection import DEFAULT_MAX_MESSAGE, AuthMethods, EventKind, PgConnection, PgEvent, Startup
from .message import (
    BINARY,
    FAILED_TRANSACTION,
    IDLE,
    IN_TRANSACTION,
    TEXT,
    BackendKey,
    Column,
    Notification,
    Params,
    ServerMessage,
    write_cancel_request,
)
