"""A Redis client (see `docs/redis.md`): RESP2 and RESP3, sans-I/O.

- `resp`: values (`Value`, `Kind`), the resumable parser (`RespParser`,
  `Limits`), and commands (`Args`, `write_command`).
- `connection`: `RespConnection`, the codec for one connection, and its
  events.

The blocking client is `redis.client`; it does I/O (`net`), so it is not
re-exported here.
"""

from .connection import EventKind, RespConnection, RespEvent
from .resp import Args, Kind, Limits, RespParser, Value, write_command
