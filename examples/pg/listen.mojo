"""Print the notifications sent on a channel (LISTEN) as they come.

Until interrupted:

    pixi run mojo run -I src examples/pg/listen.mojo 'postgresql://alice@localhost/shop' jobs

and in another session: NOTIFY jobs, 'hello'. Each line is the sender's
backend process ID and the payload.
"""

from std.sys import argv

from linux.time import Duration
from pg.client import Client, PgError, quote_identifier
from pg.config import Config


def _listen(mut db: Client, channel: StringSlice) raises PgError:
    _ = db.execute(String("LISTEN ", quote_identifier(channel)))
    print("listening on", channel)
    while True:
        var n = db.wait_notification(Duration.ZERO)  # (no time limit)
        if n:
            print(n.value().pid, n.value().payload)


def main() raises:
    var args = argv()
    if len(args) != 3:
        print("usage: listen.mojo <postgresql://...> <channel>")
        return
    var config = Config.parse(args[1])
    try:
        var db = Client.connect(config)
        _listen(db, args[2])
    except e:
        print("error:", e)
