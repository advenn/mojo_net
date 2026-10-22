"""`net.evented` under the simulator's fault injection (built only with
-D MOJO_TCP_SIM=1): the contract scenarios, repeated across seeds with the
benign faults on (short reads/writes, spurious EAGAIN and edges, shuffled
readiness, accept EMFILE bursts). These faults never fail a connection, so
every byte must arrive intact and every connection must close normally;
they exercise the multishot receive's pause/resume (backpressure) and the
lingering close under adversarial timing. Reproduce a failing seed with the
seed printed in the assertion message."""

from std.testing import TestSuite, assert_equal, assert_true

from net.evented import CloseReason, ConnConfig, ConnRef, ServerConfig, dial
from rt.event_loop import EventLoop
from rt.sim import SimDriver, SimFaults

from test_evented_contract import (
    MS,
    Bulk,
    Counters,
    EchoH,
    Pinger,
    finish,
    kptr,
    run_until_closed,
    start,
)

comptime SEEDS = 8


@always_inline
def sim(mut ev: EventLoop) -> ref[ev.driver] SimDriver:
    return rebind[SimDriver](ev.driver)


def _faulty(mut ev: EventLoop, seed: Int):
    sim(ev).set_seed(UInt64(seed))
    sim(ev).faults = SimFaults.benign(0.2)


def test_concurrent_echo_under_faults() raises:
    for seed in range(1, SEEDS + 1):
        var k = Counters()
        var ev = EventLoop()
        _faulty(ev, seed)
        var srv = start(ev, EchoH(kptr(k)))
        var addr = srv.local_addr().value()
        var refs = List[ConnRef[Pinger]]()
        for i in range(20):
            refs.append(dial(ev.loop, addr, Pinger(size=1 + 97 * i, rounds=8)))
        run_until_closed(ev, refs)
        for i in range(20):
            assert_equal(refs[i].handler().done, 8, String("seed ", seed))
            assert_equal(refs[i].handler().bad, 0, String("seed ", seed))
            assert_equal(refs[i].handler().reason.code, CloseReason.LOCAL, String("seed ", seed))
        finish(ev, srv)
        assert_equal(srv.stats().errors, 0, String("seed ", seed))
        assert_true(sim(ev).stats.total_faults() > 0, String("seed ", seed, ": no fault was injected"))


def test_bulk_backpressure_under_faults() raises:
    for seed in range(1, SEEDS + 1):
        var k = Counters()
        var ev = EventLoop()
        _faulty(ev, seed)
        var srv = start(ev, EchoH(kptr(k)), ServerConfig(conn=ConnConfig(write_high_water=32 * 1024)))
        var total = 2 * 1024 * 1024
        var refs = List[ConnRef[Bulk]]()
        refs.append(
            dial(
                ev.loop,
                srv.local_addr().value(),
                Bulk(total, pause_ns=20 * MS),
                ConnConfig(write_high_water=64 * 1024, read_backpressure=False),
            )
        )
        run_until_closed(ev, refs)
        ref b = refs[0].handler()
        assert_equal(b.sent, total, String("seed ", seed))
        assert_equal(b.received, total, String("seed ", seed))
        assert_equal(b.bad, 0, String("seed ", seed))
        assert_equal(b.reason.code, CloseReason.PEER, String("seed ", seed))
        finish(ev, srv)
        assert_true(srv.stats().bp_pauses > 0, String("seed ", seed, ": backpressure never engaged"))
        assert_equal(srv.stats().errors, 0, String("seed ", seed))
        assert_true(sim(ev).stats.total_faults() > 0, String("seed ", seed, ": no fault was injected"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
