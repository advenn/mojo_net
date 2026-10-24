"""Run one command against a Redis (or Valkey) server and print the reply.

Like redis-cli:

    pixi run mojo run -I src examples/redis/cli.mojo redis://localhost:6379 SET greeting hello
    pixi run mojo run -I src examples/redis/cli.mojo redis://localhost:6379 HGETALL user:7

The reply is printed in `redis.resp.Value`'s rendering: `+OK`, `:42`,
`"text"`, `_` for null, `*[...]` for an array, `%{key value ...}` for a
map. A server error prints its message and exits with status 1.
"""

from std.sys import argv, exit

from redis import Args
from redis.client import Client, RedisError
from redis.config import Config


def main() raises:
    var args = argv()
    if len(args) < 3:
        print("usage: cli.mojo <redis://...> <command> [arguments...]")
        exit(2)
    var command = Args()
    for i in range(2, len(args)):
        command.add_text(args[i])
    var r = Client.connect(Config.parse(args[1]))
    var failed = False
    try:
        print(r.command_args(command))
    except e:
        print(String("(error) ", e))
        failed = True
    r^.close()
    if failed:
        exit(1)
