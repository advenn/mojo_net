"""A peer that answers any command with RESP3 pushes, as fast as it can,
until the client goes away: the reply never comes, and the input never
runs dry. A client that checks its deadline only when a receive would
wait never stops reading. (The client keeps at most MAX_PUSHES of them.)

    python tests/redis/flood_peer.py   prints its port, then serves one client
"""

import socket

s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
c, _ = s.accept()
c.recv(65536)  # (the command)
block = b">2\r\n$7\r\nmessage\r\n:1\r\n" * (1 << 15)  # (about 800 KB)
try:
    while True:
        c.sendall(block)
except OSError:
    pass
