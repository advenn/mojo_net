"""Processes for the server (docs/server.md, "Processes"): `Stop`, what
tells a server to shut down, and `run_workers`, which runs this program as
worker processes on one port under a supervisor.

Signals are read from a signalfd, never handled: the library installs no
handlers. For that every thread must block them, and the Mojo runtime
starts its threads before `main` with the mask the process was started
with. So `Stop.on_signals` and `run_workers` block SIGTERM and SIGINT and,
unless every thread already blocks them, execute the program again
(/proc/self/exe, same arguments and environment), whose threads then start
with them blocked (docs/spikes.md). Call them first in `main`: what comes
before runs twice, and under `mojo run` the program is compiled again.
"""

from std.os import getenv

from linux import Epoll, ErrorKind, IoError, RawFd, check
from linux import sys
from linux.abi import EpollEvent
from linux.consts import (
    AF_UNIX,
    EPOLLIN,
    F_SETFD,
    FD_CLOEXEC,
    SIGINT,
    SIGKILL,
    SIGTERM,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOCK_STREAM,
)
from linux.errno import Errno
from linux.fd import OwnedFd
from linux.process import Child, Exec, ExitStatus, all_threads_block, allowed_cpus, set_allowed_cpus, spawn
from linux.signal import SignalFd, SignalSet, block
from linux.syscall import err_of, is_err
from linux.time import Duration, Instant

comptime _WORKER_ENV = "MOJO_NET_WORKER"
"""Set by the supervisor in each worker: "<index>:<lifeline fd>:<cpus>"."""
comptime _SIGNALS_KEY: UInt64 = UInt64.MAX


def _stop_signals() -> SignalSet:
    return SignalSet.of(SIGTERM, SIGINT)


def _log(msg: String):
    """A line on stderr, with raw write(2) (CLAUDE.md: never print in
    library code)."""
    var line = String("mojo_net: ", msg, "\n")
    _ = sys.write(RawFd(2), line.as_bytes())


def _ensure_blocked(set: SignalSet) raises IoError:
    """Block `set` in this thread; if some thread still does not block it,
    run the program again with it blocked (does not return then)."""
    _ = block(set)
    if all_threads_block(set):
        return
    var again = Exec.this_program()
    again.exec()


struct Stop(Movable):
    """Stop requests for a server (`Server.stop_on`): SIGTERM or SIGINT,
    and in a worker its supervisor, which asks by closing the worker's
    lifeline (or by dying). The first request asks for a graceful shutdown;
    a signal after it asks to stop at once."""

    comptime NONE = 0
    comptime GRACEFUL = 1
    comptime NOW = 2

    var signals: SignalFd
    var lifeline: Optional[OwnedFd]
    """A worker's end of its lifeline to the supervisor."""
    var worker: Int
    """The worker's index, 0 to workers - 1; -1 outside `run_workers`."""
    var _asked: Bool

    def __init__(out self, var signals: SignalFd, var lifeline: Optional[OwnedFd], worker: Int):
        self.signals = signals^
        self.lifeline = lifeline^
        self.worker = worker
        self._asked = False

    @staticmethod
    def on_signals() raises IoError -> Stop:
        """SIGTERM and SIGINT as stop requests, for a single process. This
        may run the program again (see the module docs)."""
        _ensure_blocked(_stop_signals())
        return Stop(SignalFd.new(_stop_signals()), None, -1)

    def requested(mut self) raises IoError -> Int:
        """What arrived since the last call: `NONE`, `GRACEFUL` (the first
        request) or `NOW` (a signal after a request, or two at once)."""
        var signals = 0
        while self.signals.take() != 0:
            signals += 1
        var lifeline = False
        if self.lifeline:
            var buf = Array[UInt8, 16](fill=0)
            var r = sys.read(self.lifeline.value(), Span(buf))
            if not (is_err(r) and Errno(err_of(r)) == Errno.EAGAIN):
                lifeline = True  # its end (or a byte): asked, or the supervisor is gone
                self.lifeline = None  # closing it also leaves the epoll
        if signals == 0 and not lifeline:
            return Self.NONE
        if (self._asked and signals > 0) or signals > 1:
            self._asked = True
            return Self.NOW
        self._asked = True
        return Self.GRACEFUL


struct WorkerConfig(Copyable, Movable):
    """How `run_workers` runs and supervises its workers."""

    var workers: Int
    """How many; 0 for one per CPU this process may run on."""
    var stop_timeout: Duration
    """How long the supervisor waits for its workers to finish after asking
    them to stop, before it kills what is left. Longer than the workers'
    `ServerConfig.shutdown_timeout`."""
    var restart_delay: Duration
    """The wait before restarting a worker that ended; it doubles, up to
    `max_restart_delay`, while workers end within a second of starting."""
    var max_restart_delay: Duration
    var pin: Bool
    """Keep each worker on its CPU. Otherwise only its runtime starts there
    (one runtime thread instead of one per CPU) and the worker then runs
    on all of them."""
    var log: Bool
    """Report starts, ends and restarts on stderr."""

    def __init__(
        out self,
        *,
        workers: Int = 0,
        stop_timeout: Duration = Duration.from_secs(15),
        restart_delay: Duration = Duration.from_millis(100),
        max_restart_delay: Duration = Duration.from_secs(10),
        pin: Bool = False,
        log: Bool = True,
    ):
        self.workers = workers
        self.stop_timeout = stop_timeout
        self.restart_delay = restart_delay
        self.max_restart_delay = max_restart_delay
        self.pin = pin
        self.log = log


def _parse_int(s: StringSlice) raises -> Int:
    return atol(s)


def run_workers(config: WorkerConfig = WorkerConfig()) raises -> Optional[Stop]:
    """Run this program as worker processes on one port, supervised by the
    process that calls it first. Returns in a worker, with the `Stop` its
    server runs until (`Server.stop_on`); bind with `reuseport=True`. In
    the supervisor it returns None, once all workers have ended after a
    stop: `main` should then return.

    The supervisor:
    - starts the workers, each a new execution of this program (as
      `Exec.this_program`, plus `MOJO_NET_WORKER` in its environment);
      worker i's runtime starts on the i-th allowed CPU;
    - restarts a worker that ends, after `restart_delay` (growing while
      workers die young);
    - on SIGTERM or SIGINT closes every worker's lifeline, which asks it
      to shut down gracefully, waits up to `stop_timeout`, then kills what
      is left; a second signal kills them at once.

    A worker whose supervisor dies sees its lifeline close, and shuts down
    gracefully too. Call it first in `main` (see the module docs)."""
    var env = getenv(_WORKER_ENV)
    if env.byte_length() > 0:
        return _worker(env, config)
    _ensure_blocked(_stop_signals())
    var sup = _Supervisor(config)
    sup.run()
    return None


def _worker(env: String, config: WorkerConfig) raises -> Stop:
    """This process is worker <index>: adopt its lifeline (CLOEXEC again,
    so that its own children do not keep it), widen its affinity unless
    pinned, and read the stop signals, which the supervisor's mask
    blocked from the start."""
    # Normally a no-op: the supervisor started this process with its mask.
    _ensure_blocked(_stop_signals())
    var parts = env.split(":")
    if len(parts) != 3:
        raise Error("bad ", _WORKER_ENV, ": ", env)
    var index = _parse_int(parts[0])
    var fd = Int32(_parse_int(parts[1]))
    var lifeline = OwnedFd(unsafe_from_raw=fd)
    _ = check("fcntl(F_SETFD)", sys.fcntl(lifeline, F_SETFD, FD_CLOEXEC))
    lifeline.set_nonblocking(True)  # `Stop.requested` reads it in the loop
    if not config.pin and parts[2].byte_length() > 0:
        var cpus = List[Int]()
        for c in parts[2].split(","):
            cpus.append(_parse_int(c))
        set_allowed_cpus(cpus)
    var stop = Stop(SignalFd.new(_stop_signals()), lifeline^, index)
    return stop^


struct _Worker(Movable):
    var child: Child
    var lifeline: Optional[OwnedFd]
    """The supervisor's end: closing it asks the worker to stop."""
    var started: Instant

    def __init__(out self, var child: Child, var lifeline: OwnedFd, started: Instant):
        self.child = child^
        self.lifeline = lifeline^
        self.started = started


struct _Supervisor:
    var config: WorkerConfig
    var signals: SignalFd
    var ep: Epoll
    var program: Exec
    var cpus: List[Int]
    var cpu_list: String
    var workers: List[Optional[_Worker]]
    var delay: List[Duration]
    var restart_at: List[Optional[Instant]]
    var stopping: Bool
    var deadline: Instant
    var killed: Bool

    def __init__(out self, config: WorkerConfig) raises:
        self.config = config.copy()
        self.signals = SignalFd.new(_stop_signals())
        self.ep = Epoll.new()
        self.ep.add(self.signals, UInt32(EPOLLIN), _SIGNALS_KEY)
        self.program = Exec.this_program()
        self.program.remove_env(_WORKER_ENV)
        self.cpus = allowed_cpus()
        self.cpu_list = String()
        for i in range(len(self.cpus)):
            if i > 0:
                self.cpu_list += ","
            self.cpu_list += String(self.cpus[i])
        var n = config.workers if config.workers > 0 else len(self.cpus)
        self.workers = List[Optional[_Worker]]()
        self.delay = List[Duration]()
        self.restart_at = List[Optional[Instant]]()
        for _ in range(n):
            self.workers.append(None)
            self.delay.append(config.restart_delay)
            self.restart_at.append(None)
        self.stopping = False
        self.deadline = Instant.now()
        self.killed = False

    def _say(self, msg: String):
        if self.config.log:
            _log(msg)

    def live(self) -> Int:
        var n = 0
        for i in range(len(self.workers)):
            if self.workers[i]:
                n += 1
        return n

    def start(mut self, i: Int, now: Instant) raises IoError:
        var fds = Array[Int32, 2](fill=-1)
        _ = check("socketpair", sys.socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, fds))
        var mine = OwnedFd(unsafe_from_raw=fds[0])
        var theirs = OwnedFd(unsafe_from_raw=fds[1])
        self.program.set_env(_WORKER_ENV, String(i, ":", theirs.raw_fd(), ":", self.cpu_list))
        var child = spawn(self.program, keep=theirs.raw_fd(), cpu=self.cpus[i % len(self.cpus)])
        sys.keep_alive(theirs)  # the child has its copy; ours closes here
        self.ep.add(child, UInt32(EPOLLIN), UInt64(i))
        self._say(String("worker ", i, " started (pid ", child.pid, ")"))
        self.workers[i] = _Worker(child^, mine^, now)
        self.restart_at[i] = None

    def try_start(mut self, i: Int, now: Instant):
        """Start worker i; if that fails (a process limit, say), try again
        after its restart delay, which grows."""
        try:
            self.start(i, now)
        except e:
            self.delay[i] = min(self.delay[i] + self.delay[i], self.config.max_restart_delay)
            self.restart_at[i] = now + self.delay[i]
            self._say(
                String(
                    "could not start worker ", i, ": ", e,
                    "; trying again in ", self.delay[i].as_nanos() // 1000000, " ms",
                )
            )

    def ended(mut self, i: Int, now: Instant) raises IoError:
        if i >= len(self.workers) or not self.workers[i]:
            return
        var status: Optional[ExitStatus]
        try:
            status = self.workers[i].value().child.try_wait()
        except:
            # ECHILD: reaped already, as when this process inherited SIGCHLD
            # ignored; it has ended, how is unknown.
            status = ExitStatus(-1, 0)
        if not status:
            return  # (not yet)
        var pid = self.workers[i].value().child.pid
        var lived = now - self.workers[i].value().started
        self.workers[i] = None  # closes its pidfd (leaving the epoll) and lifeline
        if self.stopping:
            self._say(String("worker ", i, " (pid ", pid, ") ended: ", status.value()))
            return
        if lived < Duration.from_secs(1):
            self.delay[i] = min(self.delay[i] + self.delay[i], self.config.max_restart_delay)
        else:
            self.delay[i] = self.config.restart_delay
        self.restart_at[i] = now + self.delay[i]
        self._say(
            String(
                "worker ", i, " (pid ", pid, ") ended: ", status.value(),
                "; restarting in ", self.delay[i].as_nanos() // 1000000, " ms",
            )
        )

    def signalled(mut self, now: Instant) raises IoError:
        var got = 0
        while self.signals.take() != 0:
            got += 1
        if got == 0:
            return
        if self.stopping:
            self._say("stopping now")
            self.kill_all()
            return
        self.stopping = True
        self.deadline = now + self.config.stop_timeout
        self._say(String("stopping ", self.live(), " workers"))
        for i in range(len(self.workers)):
            self.restart_at[i] = None
            if self.workers[i]:
                self.workers[i].value().lifeline = None  # asks it to stop
        if got > 1:
            self.kill_all()

    def kill_all(mut self):
        self.killed = True
        for i in range(len(self.workers)):
            if self.workers[i]:
                try:
                    self.workers[i].value().child.signal(SIGKILL)
                except:
                    pass  # (already ended)

    def run(mut self) raises IoError:
        var now = Instant.now()
        for i in range(len(self.workers)):
            self.try_start(i, now)
        var events = List[EpollEvent](capacity=64)
        while True:
            now = Instant.now()
            if self.stopping:
                if self.live() == 0:
                    self._say("all workers ended")
                    return
                if not self.killed and now >= self.deadline:
                    self._say("stop timeout: killing the workers left")
                    self.kill_all()
            var wait = Duration.from_secs(1)
            if self.stopping and not self.killed:
                wait = min(wait, self.deadline - now)
            for i in range(len(self.restart_at)):
                if self.restart_at[i]:
                    wait = min(wait, self.restart_at[i].value() - now)
            var n = self.ep.wait(events, Optional[Duration](max(wait, Duration.ZERO)))
            now = Instant.now()
            for e in range(n):
                var key = events[e].data()
                if key == _SIGNALS_KEY:
                    self.signalled(now)
                else:
                    self.ended(Int(key), now)
            if not self.stopping:
                for i in range(len(self.restart_at)):
                    if self.restart_at[i] and now >= self.restart_at[i].value():
                        self.try_start(i, now)
