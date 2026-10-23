"""The HTTP/1.1 server (roadmap step 3; docs/server.md): one edge-triggered
epoll loop per process over `http.connection.ServerConnection`s, calling the
application's `Handler` once per complete request. Run one process per core
with `ServerConfig(reuseport=True)` for multi-core."""

from .date import DateCache, http_date
from .server import Handler, Request, Response, Server, ServerConfig
