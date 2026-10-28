"""Processes for the server (docs/server.md, "Processes"): `Stop`, what
tells a server to shut down, and `run_workers`, which runs this program as
worker processes on one port under a supervisor.

Signals are read from a signalfd, never handled: the library installs no
handlers. For that every thread must block them, and the Mojo runtime
starts its threads with the mask the process was started with. So
`Stop.on_signals` and `run_workers` block SIGTERM and SIGINT and, unless
the process was started with them blocked and every thread blocks them,
execute the program again (/proc/self/exe, same arguments and
environment), whose threads then start with them blocked
(docs/spikes.md). The mask it was started with decides, not a look at the
threads alone: on GitHub's aarch64 runners every thread seemed to block
them while one did not (a SIGTERM then ended the process), presumably
because the runtime was still starting its threads when `main` ran.
Call them first in `main`: what comes before runs twice, and under
`mojo run` the program is compiled again. It runs again at most once: if
some thread still does not block them after that (something unblocks
them), a warning says so on stderr.

Before anything else they open /dev/null on whichever of fds 0, 1 and 2
is closed, so that no socket of the server can land there and receive
what is written to stderr.

Processes the server starts inherit SIGTERM and SIGINT blocked (exec keeps
the mask): reset it in them (`linux.process.spawn(signal_mask=...)`, or
Python's `signal.pthread_sigmask` in a `preexec_fn`) if they are to stop on
those signals. A SIGINT the parent set to be ignored is still a stop
request, since a blocked signal is never discarded.
"""

from std.os import getenv, unsetenv

from linux import Epoll, ErrorKind, IoError, RawFd, check
from linux import sys
from linux.abi import EpollEvent
from linux.consts import (
    AF_UNIX,
    AT_FDCWD,
    EPOLLIN,
    F_GETFD,
    F_SETFD,
    FD_CLOEXEC,
    O_RDWR,
    SIGINT,
    SIGKILL,
    SIGPIPE,
    SIGTERM,
    SOCK_CLOEXEC,
    SOCK_NONBLOCK,
    SOCK_STREAM,
)
from linux.errno import Errno
from linux.fd import OwnedFd
from linux.nr import SYS_fcntl, SYS_getpid, SYS_openat
from linux.probe import cpu_quota
from linux.process import (
    Child,
    Exec,
    ExitStatus,
    all_threads_block,
    allowed_cpus,
    reap_others,
    set_allowed_cpus,
    spawn,
)
from linux.signal import SignalFd, SignalSet, block, write_no_sigpipe
from linux.syscall import err_of, is_err, syscall0, syscall3, syscall4
from linux.time import Duration, Instant

comptime _WORKER_ENV = "MOJO_NET_WORKER"
"""Set by the supervisor in each worker: "<index>:<lifeline fd>:<cpus>"."""
comptime _REEXEC_ENV = "MOJO_NET_REEXEC"
"""Set for the one execution again that blocking the stop signals takes."""
comptime _SIGNALS_KEY: UInt64 = UInt64.MAX


def _stop_signals() -> SignalSet:
    return SignalSet.of(SIGTERM, SIGINT)


def _log(msg: String):
    """A line on stderr, with raw write(2) (CLAUDE.md: never print in
    library code), raising no SIGPIPE: a stderr whose reader has gone must
    not end the process (`linux.signal.write_no_sigpipe`, SR2 BP-1)."""
    var line = String("mojo_net: ", msg, "\n")
    _ = write_no_sigpipe(RawFd(2), line.as_bytes())


def _ensure_stdio():
    """Open /dev/null on fds 0, 1 and 2 where they are closed (so that no
    socket lands there and gets what goes to stderr). Not CLOEXEC: they
    are inherited as stdio."""
    var null = List[UInt8]("/dev/null".as_bytes())
    null.append(0)
    for fd in range(3):
        if not is_err(syscall3(SYS_fcntl, fd, F_GETFD, 0)):
            continue
        # The lowest free fd is this one, since the ones below are open.
        _ = syscall4(SYS_openat, AT_FDCWD, Int(null.unsafe_ptr()), O_RDWR, 0)
    sys.keep_alive(null)


def _ensure_blocked(set: SignalSet) raises IoError:
    """Block `set` in this thread. Unless the process started with it
    blocked and every thread blocks it, run the program again with it
    blocked (does not return then), once: after that a warning goes to
    stderr instead (module docs)."""
    _ensure_stdio()
    var started = block(set)  # (the mask this thread had: the exec-time one)
    var again = getenv(_REEXEC_ENV).byte_length() > 0
    if again:
        _ = unsetenv(_REEXEC_ENV)  # (not for the processes this one starts)
    if started.includes(set) and all_threads_block(set):
        return
    if again:
        _log("a thread does not block SIGTERM/SIGINT even after running again: a stop signal may end the process at once")
        return
    var program = Exec.this_program()
    program.set_env(_REEXEC_ENV, "1")
    program.exec()


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
    var _signalled: Bool
    """A stop signal came before."""

    def __init__(out self, var signals: SignalFd, var lifeline: Optional[OwnedFd], worker: Int):
        self.signals = signals^
        self.lifeline = lifeline^
        self.worker = worker
        self._signalled = False

    @staticmethod
    def on_signals() raises IoError -> Stop:
        """SIGTERM and SIGINT as stop requests, for a single process. This
        may run the program again (see the module docs)."""
        _ensure_blocked(_stop_signals())
        return Stop(SignalFd.new(_stop_signals()), None, -1)

    def requested(mut self) raises IoError -> Int:
        """What arrived since the last call: `NONE`, `GRACEFUL`, or `NOW`
        for a signal after an earlier signal (or two at once). The lifeline
        only ever asks for a graceful stop: under systemd a worker sees its
        supervisor close it and then gets its own SIGTERM, which must not
        cut its requests."""
        var signals = 0
        while self.signals.take() != 0:
            signals += 1
        var lifeline = False
        if self.lifeline:
            var buf = Array[UInt8, 64](fill=0)
            while True:
                var r = sys.read(self.lifeline.value(), Span(buf))
                if r > 0:
                    continue  # bytes mean nothing: only its end does
                if not (is_err(r) and Errno(err_of(r)) == Errno.EAGAIN):
                    lifeline = True  # its end: asked, or the supervisor is gone
                    self.lifeline = None  # closing it also leaves the epoll
                break
        if signals == 0 and not lifeline:
            return Self.NONE
        var now = (signals > 0 and self._signalled) or signals > 1
        if signals > 0:
            self._signalled = True
        return Self.NOW if now else Self.GRACEFUL


struct WorkerConfig(Copyable, Movable):
    """How `run_workers` runs and supervises its workers."""

    var workers: Int
    """How many; 0 for one per CPU this process may run on (and its cgroup
    quota allows: `linux.probe.cpu_quota`)."""
    var stop_timeout: Duration
    """How long the supervisor waits for its workers to finish after asking
    them to stop, before it kills what is left. Longer than the workers'
    `ServerConfig.shutdown_timeout`."""
    var restart_delay: Duration
    """The wait before restarting a worker that ended. While a worker keeps
    ending within a second of starting, the wait doubles each time (from
    at least 50 ms), up to `max_restart_delay`."""
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
    # A broken stderr pipe must not kill the supervisor (its log writes
    # then fail with EPIPE instead); its workers start without this.
    _ = block(SignalSet.of(SIGPIPE))
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
    _ = unsetenv(_WORKER_ENV)  # (the processes this one starts are no workers)
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
    var quick: List[Int]
    """Per worker: how many times in a row it ended within a second."""
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
        self.program.remove_env(_REEXEC_ENV)
        self.program.remove_env("SSLKEYLOGFILE")  # (TS11: no libssl writes session keys)
        self.cpus = allowed_cpus()
        self.cpu_list = String()
        for i in range(len(self.cpus)):
            if i > 0:
                self.cpu_list += ","
            self.cpu_list += String(self.cpus[i])
        var n = config.workers
        if n <= 0:
            n = len(self.cpus)
            var quota = cpu_quota()
            if quota:
                n = min(n, quota.value())  # (a container's --cpus)
        self.workers = List[Optional[_Worker]]()
        self.quick = List[Int]()
        self.restart_at = List[Optional[Instant]]()
        for _ in range(n):
            self.workers.append(None)
            self.quick.append(0)
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
        var child = spawn(
            self.program,
            keep=theirs.raw_fd(),
            cpu=self.cpus[i % len(self.cpus)],
            signal_mask=_stop_signals(),  # (not the supervisor's SIGPIPE)
        )
        sys.keep_alive(theirs)  # the child has its copy; ours closes here
        try:
            self.ep.add(child, UInt32(EPOLLIN), UInt64(i))
        except e:
            try:  # unwatched, it would end a zombie: end it now
                child.signal(SIGKILL)
                _ = child.wait()
            except:
                pass
            raise e
        self._say(String("worker ", i, " started (pid ", child.pid, ")"))
        self.workers[i] = _Worker(child^, mine^, now)
        self.restart_at[i] = None

    def backoff(mut self, i: Int, quick: Bool) -> Duration:
        """The wait before restarting worker i: `restart_delay`, doubled for
        each further quick end in a row (from at least 50 ms), at most
        `max_restart_delay`."""
        if not quick:
            self.quick[i] = 0
            return self.config.restart_delay
        self.quick[i] += 1
        var d = self.config.restart_delay
        if self.quick[i] > 1:
            d = max(d, Duration.from_millis(50))
            for _ in range(min(self.quick[i] - 1, 30)):
                d = d + d
        return min(d, self.config.max_restart_delay)

    def try_start(mut self, i: Int, now: Instant) raises IoError:
        """Start worker i; if that fails for a while (a process limit), try
        again later, waiting longer each time. Raises if processes cannot
        be made at all here (ENOSYS, EPERM: a sandbox)."""
        try:
            self.start(i, now)
        except e:
            if e.errno == Errno.ENOSYS or e.errno == Errno.EPERM:
                self._say(String("cannot start workers: ", e))
                raise e
            var wait = self.backoff(i, True)
            self.restart_at[i] = now + wait
            self._say(
                String(
                    "could not start worker ", i, ": ", e,
                    "; trying again in ", wait.as_nanos() // 1000000, " ms",
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
        var wait = self.backoff(i, lived < Duration.from_secs(1))
        self.restart_at[i] = now + wait
        self._say(
            String(
                "worker ", i, " (pid ", pid, ") ended: ", status.value(),
                "; restarting in ", wait.as_nanos() // 1000000, " ms",
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
            if syscall0(SYS_getpid) == 1:
                # PID 1 (a container's init) inherits orphans: reap them,
                # or they stay zombies
                var known = List[Int]()
                for i in range(len(self.workers)):
                    if self.workers[i]:
                        known.append(self.workers[i].value().child.pid)
                _ = reap_others(known)
            if not self.stopping:
                for i in range(len(self.restart_at)):
                    if self.restart_at[i] and now >= self.restart_at[i].value():
                        self.try_start(i, now)
