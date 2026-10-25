"""Move an amount between two balances atomically, retrying on a conflict.

WATCH both balances, read them, then run the change between MULTI and EXEC;
EXEC refuses it when another client changed a balance meanwhile, and the
loop reads them again:

    pixi run mojo run -I src examples/redis/transfer.mojo redis://localhost:6379 alice bob 25

Balances live in `balance:<name>` and start at 100 (a pipeline of SET NX,
one round trip).
"""

from std.sys import argv, exit

from redis.client import Client, Pipeline
from redis.config import Config


def main() raises:
    var args = argv()
    if len(args) != 5:
        print("usage: transfer.mojo <redis://...> <from> <to> <amount>")
        exit(2)
    var source = String("balance:", args[2])
    var target = String("balance:", args[3])
    var amount = atol(args[4])
    var r = Client.connect(Config.parse(args[1]))
    var seed = Pipeline()
    seed.add("SET", source, 100, "NX")
    seed.add("SET", target, 100, "NX")
    _ = r.run(seed)
    var tries = 0
    var short = False
    while True:
        tries += 1
        _ = r.command("WATCH", source, target)
        var have = atol(r.get(source).value())
        if have < amount:
            _ = r.command("UNWATCH")
            print(source, "has only", have)
            short = True
            break
        var change = Pipeline()
        change.add("DECRBY", source, amount)
        change.add("INCRBY", target, amount)
        var done = r.transaction(change)
        if done:
            var balances = done.take()
            print(source, balances[0].int(), "|", target, balances[1].int(), "| tries:", tries)
            break
        # (another client changed a balance between WATCH and EXEC)
    r^.close()
    if short:
        exit(1)
