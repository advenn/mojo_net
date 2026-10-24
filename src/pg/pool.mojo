"""A pool of PostgreSQL sessions for one configuration: `acquire` hands out
an open `Client`, and `release` takes it back for the next caller.

For a program that runs one query at a time but needs sessions often, a
server loop taking one per request say. Each new session pays a TCP
handshake, authentication (SCRAM's PBKDF2 among it) and the startup round
trips; a pooled one is ready at once. Single-threaded, like `Client`.

    var pool = Pool(Config.parse("postgresql://app@localhost/shop"), max_idle=8)
    var db = pool.acquire()
    var r = db.query("SELECT name FROM users WHERE id = $1", 7)
    pool.release(db^)

What a released session keeps:
- **It is pooled** only if it is usable, idle, outside a transaction, and
  the pool has room; otherwise it is closed. A session acquired again is
  checked first (`Client.check`): one the server ended meanwhile (an
  administrator's `pg_terminate_backend`, an idle timeout) is replaced by
  a new one.
- **Session state stays with it:** settings made with SET, temporary
  tables, LISTEN subscriptions, and its prepared statements (the
  statement cache, which is the point). Queued notices and notifications
  are dropped on release. A caller that changes the session in ways the
  next one must not see resets it before releasing (`RESET ALL`,
  `UNLISTEN *`), or closes it instead.
"""

from .client import Client, PgError
from .config import Config
from .message import IDLE


struct Pool(Movable):
    """Sessions for `config`, at most `max_idle` of them kept while idle."""

    var _config: Config
    var _idle: List[Client]
    var max_idle: Int
    var _opened: Int

    def __init__(out self, config: Config, *, max_idle: Int = 4):
        self._config = config.copy()
        self._idle = List[Client]()
        self.max_idle = max_idle
        self._opened = 0

    def acquire(mut self) raises PgError -> Client:
        """A usable session: the one released last that still passes
        `Client.check`, or a new one (`Client.connect`, which raises as it
        does)."""
        while len(self._idle) > 0:
            var db = self._idle.pop()
            if db.check():
                return db^
            db^.close()
        self._opened += 1
        return Client.connect(self._config)

    def release(mut self, var db: Client):
        """Take a session back: kept for the next `acquire` if it is usable,
        idle outside a transaction, and there is room; closed otherwise."""
        if len(self._idle) < self.max_idle and db.is_usable() and db.transaction_status() == IDLE:
            _ = db.take_notices()
            _ = db.take_notifications()
            self._idle.append(db^)
        else:
            db^.close()

    def idle(self) -> Int:
        """How many sessions wait in the pool."""
        return len(self._idle)

    def opened(self) -> Int:
        """How many sessions `acquire` opened in all."""
        return self._opened

    def close(mut self):
        """Close the idle sessions (one acquired and not released is the
        caller's to close)."""
        while len(self._idle) > 0:
            var db = self._idle.pop()
            db^.close()
