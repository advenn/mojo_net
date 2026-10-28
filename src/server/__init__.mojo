"""The HTTP/1.1 server (roadmap step 3; docs/server.md): one edge-triggered
epoll loop per process over `http.connection.ServerConnection`s, calling the
application's `Handler` once per complete request. For several cores,
`run_workers` runs the program as supervised worker processes on one port
(`ServerConfig(reuseport=True)`); `Stop` and `Server.stop_on` shut a server
down gracefully on SIGTERM or when its supervisor asks. `Router` sends
requests to functions by method and path pattern, and `StaticFiles` serves
a directory's files."""

from .date import DateCache, http_date, parse_http_date
from .process import Stop, WorkerConfig, run_workers
from .router import Params, Router
from .static import StaticFiles, content_type
from .server import Exchange, Handler, Request, Response, Server, ServerConfig
