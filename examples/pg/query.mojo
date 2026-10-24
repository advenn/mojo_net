"""Run SQL against PostgreSQL and print what comes back (`pg.client`).

    pixi run mojo run -I src examples/pg/query.mojo \\
        'postgresql://alice:secret@localhost/shop' 'SELECT id, name FROM users'

Several statements may be given, separated by semicolons; each result is
printed: its column names, its rows (tab-separated, NULL as \\N), and its
command tag. A server error prints its SQLSTATE and message. For a Unix
socket, give its directory as the host, percent-encoded
(`postgresql://alice@%2Fvar%2Frun%2Fpostgresql/shop`).
"""

from std.sys import argv

from pg.client import Client, PgError
from pg.config import Config


def _print(mut db: Client, sql: StringSlice) raises PgError:
    var results = db.simple_query(sql)
    for k in range(len(results)):
        ref r = results[k]
        if r.width() > 0:
            var header = String()
            for c in range(r.width()):
                header += String("\t" if c > 0 else "", r.columns[c].name)
            print(header)
            for i in range(len(r)):
                var line = String()
                for c in range(r.width()):
                    line += String("\t" if c > 0 else "", "\\N" if r.is_null(i, c) else r.text(i, c))
                print(line)
        print("--", r.tag)
    for n in db.take_notices():
        print(n.severity(), n.message())


def main() raises:
    var args = argv()
    if len(args) != 3:
        print("usage: query.mojo <postgresql://...> <sql>")
        return
    var config = Config.parse(args[1])
    try:
        var db = Client.connect(config)
        _print(db, args[2])
        db^.close()
    except e:
        print("error:", e)
