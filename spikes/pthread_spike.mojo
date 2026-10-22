"""Spike 1: can Mojo code run on threads made with `pthread_create`?

`pthread_create`/`pthread_join` are a candidate libc *control-plane*
exception (design.md: "Control-plane exceptions need an explicit, documented
decision"). Everything the threads do on the I/O-ish side (gettid, getpid,
sched_setaffinity, getcpu, sched_yield) is a raw syscall.

What runs on each of N=4 threads, all checked by `main` after join:
- heap churn (List 200k appends, 10k Strings, Dict with String keys), plus a
  List allocated on the thread and freed by main (cross-thread free);
- typed `raise IoError` / generic `raise Error` caught on the thread;
- `print` from the thread;
- raw syscalls (gettid != main tid, getpid == main pid);
- pin to one CPU with raw sched_setaffinity, verified with
  sched_getaffinity and getcpu; an all-absent-CPU mask must fail with EINVAL;
- 1M contended `Atomic[Int64].fetch_add` per thread (total must be exact).
Thread 0 is created with a pthread_attr_t (256 KiB stack); a too-small
stack size must be rejected with EINVAL. Then 200 rounds of create/join
check for task/RSS leaks.

EINTR: the Mojo runtime installs a SIGUSR1 handler that does nothing, so
`tgkill(pid, tid, SIGUSR1)` interrupts a blocking syscall on one thread
without killing the process. The spike reports whether a blocked `read` on a
pipe and a blocked `ppoll` see EINTR (i.e. whether that handler has
SA_RESTART) - this decides how EINTR paths can be tested.

Exit modes (env SPIKE_EXIT): `detached-sleep` / `detached-busy` return from
main while a thread is still blocked in a syscall / still allocating, to see
whether process exit hangs or crashes.

    pixi run mojo run -I src -I spikes spikes/pthread_spike.mojo
    pixi run mojo build -I src -I spikes spikes/pthread_spike.mojo -o spikes/out/pthread_spike
    SPIKE_EXIT=detached-busy timeout 10 spikes/out/pthread_spike
"""

from std.atomic import Atomic
from std.ffi import external_call
from std.memory import OwnedPointer
from std.os import getenv
from std.sys import CompilationTarget

from linux import Errno, ErrorKind, IoError, OwnedFd, RawFd, check, sys
from linux.abi import Pollfd
from linux.consts import O_CLOEXEC, POLLIN
from linux.nr import (
    SYS_getpid,
    SYS_sched_getaffinity,
    SYS_sched_setaffinity,
    SYS_tgkill,
)
from linux.poll import ppoll
from linux.syscall import err_of, is_err, syscall0, syscall3
from linux.time import Duration, Instant, sleep

from spike_util import count_tasks, getcpu, gettid, status_field

comptime _X86 = CompilationTarget.is_x86()
comptime SYS_sched_yield: Int = 24 if _X86 else 124

comptime N_THREADS = 4
comptime ATOMIC_ITERS = 1_000_000
comptime ROUNDS = 200
comptime SIGUSR1 = 10
"""Same number on x86_64 and aarch64."""
comptime MASK_WORDS = 16
"""Mask words: a 1024-bit cpu_set_t, like glibc's default."""

# ---- libc control plane ------------------------------------------------------
#
# The C-callable entry type. `thin` = plain function pointer (no context);
# `abi("C")` = C calling convention. A `def` declared with `abi("C")` converts
# to this type; a plain Mojo `def` does not (compile error), which is the only
# place the compiler checks the ABI: external_call itself accepts any value.
comptime ThreadEntry = def(OpaquePointer[MutAnyOrigin]) thin abi(
    "C"
) -> OpaquePointer[MutAnyOrigin]

comptime PTHREAD_ATTR_WORDS = 8
"""64 bytes: glibc's pthread_attr_t is 56 bytes on x86_64, 64 on aarch64."""


# Exactly one wrapper per C symbol, with one fixed signature. Two
# `external_call["pthread_join", ...]` sites with different argument types in
# one program fail at LLVM lowering with "existing function with conflicting
# signature". `void*` is passed as `Int` because OpaquePointer is non-nullable
# (OpaquePointer(unsafe_from_address=0) fails a constraint at compile time), and
# NULL is needed for attr/retval. `Optional[OpaquePointer[MutAnyOrigin]]` (8
# bytes, None == NULL) also works as a nullable `void*` argument.
def pthread_create(
    mut thread: UInt64,
    attr_addr: Int,
    entry: ThreadEntry,
    ctx: OpaquePointer[MutAnyOrigin],
) -> Int32:
    """Returns 0 or a positive errno (pthreads do not use -1/errno)."""
    return external_call["pthread_create", Int32](
        Int(Pointer(to=thread)), attr_addr, entry, ctx
    )


def pthread_join(thread: UInt64, retval_addr: Int) -> Int32:
    return external_call["pthread_join", Int32](thread, retval_addr)


def pthread_attr_init(attr_addr: Int) -> Int32:
    return external_call["pthread_attr_init", Int32](attr_addr)


def pthread_attr_setstacksize(attr_addr: Int, size: Int) -> Int32:
    return external_call["pthread_attr_setstacksize", Int32](attr_addr, size)


def pthread_attr_destroy(attr_addr: Int) -> Int32:
    return external_call["pthread_attr_destroy", Int32](attr_addr)


# ---- raw syscalls ------------------------------------------------------------


@inline(.always)
def _sched_setaffinity_self(mask: Span[UInt64, _]) -> Int:
    return syscall3(
        SYS_sched_setaffinity, 0, len(mask) * 8, Int(mask.unsafe_ptr())
    )


@inline(.always)
def _sched_getaffinity_self(mask: MutSpan[UInt64, _]) -> Int:
    """Raw syscall: returns the number of bytes written (glibc returns 0)."""
    return syscall3(
        SYS_sched_getaffinity, 0, len(mask) * 8, Int(mask.unsafe_ptr())
    )


@inline(.always)
def _yield():
    _ = syscall0(SYS_sched_yield)


def _mask_with(cpu: Int) -> List[UInt64]:
    var m = List[UInt64](length=MASK_WORDS, fill=0)
    m[cpu // 64] = UInt64(1) << UInt64(cpu % 64)
    return m^


def allowed_cpus() raises IoError -> List[Int]:
    var m = List[UInt64](length=MASK_WORDS, fill=0)
    var r = _sched_getaffinity_self(Span(m))
    if is_err(r):
        raise IoError.from_errno("sched_getaffinity", Errno(err_of(r)))
    var out = List[Int]()
    for w in range(MASK_WORDS):
        for b in range(64):
            if (m[w] >> UInt64(b)) & 1 == 1:
                out.append(w * 64 + b)
    return out^


# ---- per-thread context ------------------------------------------------------


struct Shared(Movable):
    var started: Atomic[Int64]
    var go: Atomic[Int64]
    var counter: Atomic[Int64]

    def __init__(out self):
        self.started = Atomic[Int64](0)
        self.go = Atomic[Int64](0)
        self.counter = Atomic[Int64](0)


struct ThreadCtx(Movable):
    """Heap-allocated (OwnedPointer) by main; its address is the pthread
    `void* arg`. Main keeps the OwnedPointer alive until after join."""

    var index: Int
    var target_cpu: Int
    var shared: Pointer[Shared, MutUntrackedOrigin]
    var mode: Int
    # Written by the thread, read by main after join.
    var tid: Int
    var pid_seen: Int
    var list_sum: Int
    var string_bytes: Int
    var dict_ok: Bool
    var caught_io: Bool
    var caught_error: Bool
    var bad_mask_errno: Int
    var pinned_mask_ok: Bool
    var cpu_after_pin: Int
    var payload: List[Int]
    var done: Bool

    def __init__(
        out self,
        index: Int,
        target_cpu: Int,
        shared: Pointer[Shared, MutUntrackedOrigin],
        mode: Int,
    ):
        self.index = index
        self.target_cpu = target_cpu
        self.shared = shared
        self.mode = mode
        self.tid = 0
        self.pid_seen = 0
        self.list_sum = 0
        self.string_bytes = 0
        self.dict_ok = False
        self.caught_io = False
        self.caught_error = False
        self.bad_mask_errno = 0
        self.pinned_mask_ok = False
        self.cpu_after_pin = -1
        self.payload = List[Int]()
        self.done = False


comptime MODE_FULL = 0
comptime MODE_MINIMAL = 1
comptime MODE_SLEEP_FOREVER = 2
comptime MODE_BUSY_FOREVER = 3


def _raise_io(i: Int) raises IoError:
    if i >= 0:
        raise IoError.from_errno("spike_recv", Errno.EAGAIN)


def _raise_generic(i: Int) raises:
    if i >= 0:
        raise Error("generic error from thread ", i)


def _nested(i: Int) raises -> Int:
    _raise_generic(i)
    return 0


def _body(mut c: ThreadCtx):
    """Everything a thread does. Not `raises`: the C entry cannot raise
    (`abi("C")` + `raises` is a compile error), so all errors stop here."""
    c.tid = gettid()
    c.pid_seen = syscall0(SYS_getpid)
    if c.mode == MODE_MINIMAL:
        c.payload.append(c.index)
        c.done = True
        return
    if c.mode == MODE_SLEEP_FOREVER:
        _ = c.shared[].started.fetch_add(1)
        try:
            sleep(Duration.from_secs(3600))
        except:
            pass
        return
    if c.mode == MODE_BUSY_FOREVER:
        _ = c.shared[].started.fetch_add(1)
        while True:  # allocates until the process dies under it
            var l = List[String]()
            for i in range(100):
                l.append(String("busy ") + String(i))
            c.list_sum += len(l)

    # Barrier: main counts /proc/self/task while all threads are alive.
    _ = c.shared[].started.fetch_add(1)
    while c.shared[].go.load() == 0:
        _yield()

    # Heap churn.
    var l = List[Int]()
    for i in range(200_000):
        l.append(i)
    var sum = 0
    for v in l:
        sum += v
    c.list_sum = sum
    var bytes = 0
    for i in range(10_000):
        var s = String("thread-") + String(c.index) + "-" + String(i)
        bytes += s.byte_length()
    c.string_bytes = bytes
    var d = Dict[String, Int]()
    for i in range(1000):
        d[String(i)] = i * c.index
    try:
        c.dict_ok = len(d) == 1000 and d["999"] == 999 * c.index
    except:
        c.dict_ok = False
    for i in range(10_000):
        c.payload.append(i + c.index)  # freed by main: cross-thread free

    # Errors raised and caught on a foreign thread.
    try:
        _raise_io(c.index)
    except e:
        c.caught_io = e.kind == ErrorKind.WouldBlock and e.errno == Errno.EAGAIN
    try:
        _ = _nested(c.index)
    except e:
        c.caught_error = String(e) == String(
            "generic error from thread ", c.index
        )

    # Contended atomics.
    for _ in range(ATOMIC_ITERS):
        _ = c.shared[].counter.fetch_add(1)

    # Affinity: a mask of only absent CPUs is EINVAL; then pin for real.
    var bad = _mask_with(MASK_WORDS * 64 - 1)
    var r = _sched_setaffinity_self(Span(bad))
    c.bad_mask_errno = Int(err_of(r)) if is_err(r) else 0
    if c.target_cpu >= 0:
        var want = _mask_with(c.target_cpu)
        r = _sched_setaffinity_self(Span(want))
        if not is_err(r):
            var got = List[UInt64](length=MASK_WORDS, fill=0)
            var g = _sched_getaffinity_self(Span(got))
            var same = not is_err(g)
            for w in range(MASK_WORDS):
                if got[w] != want[w]:
                    same = False
            c.pinned_mask_ok = same
            # Changing one's own affinity migrates synchronously.
            c.cpu_after_pin = getcpu()

    print(
        "  [thread",
        c.index,
        "] tid",
        c.tid,
        "pinned to cpu",
        c.target_cpu,
        "-> running on",
        c.cpu_after_pin,
        "| list_sum",
        c.list_sum,
    )
    c.done = True


def thread_main(
    arg: OpaquePointer[MutAnyOrigin],
) abi("C") -> OpaquePointer[MutAnyOrigin]:
    """The C entry: cast the context word back and run normal Mojo code."""
    var ctx = arg.unsafe_bitcast[ThreadCtx]()
    _body(ctx[])
    return arg


# ---- EINTR via SIGUSR1 ------------------------------------------------------


struct EintrCtx(Movable):
    var fd: Int32
    """Read end of a pipe owned by main, which outlives the join."""
    var use_ppoll: Bool
    var started: Atomic[Int64]
    var tid: Atomic[Int64]
    var eintr: Atomic[Int64]
    var final_ret: Int

    def __init__(out self, fd: Int32, use_ppoll: Bool):
        self.fd = fd
        self.use_ppoll = use_ppoll
        self.started = Atomic[Int64](0)
        self.tid = Atomic[Int64](0)
        self.eintr = Atomic[Int64](0)
        self.final_ret = 0


def _eintr_body(mut c: EintrCtx):
    c.tid.store(Int64(gettid()))
    _ = c.started.fetch_add(1)
    var buf = List[UInt8](length=1, fill=0)
    var pfd = List[Pollfd]()
    pfd.append(Pollfd(c.fd, Int16(POLLIN), 0))
    var fd = RawFd(c.fd)
    while True:
        var r: Int
        if c.use_ppoll:
            r = ppoll(Span(pfd), None)
        else:
            r = sys.read(fd, Span(buf))
        if is_err(r) and Errno(err_of(r)) == Errno.EINTR:
            _ = c.eintr.fetch_add(1)
            continue
        if c.use_ppoll and r == 1:
            r = sys.read(fd, Span(buf))
        c.final_ret = r
        return


def eintr_main(
    arg: OpaquePointer[MutAnyOrigin],
) abi("C") -> OpaquePointer[MutAnyOrigin]:
    _eintr_body(arg.unsafe_bitcast[EintrCtx]()[])
    return arg


def _eintr_probe(use_ppoll: Bool) raises -> Tuple[Int, Int, Int]:
    """(EINTRs seen, signals sent, final syscall result)."""
    var fds = Array[Int32, 2](fill=-1)
    _ = check("pipe2", sys.pipe2(fds, O_CLOEXEC))
    var rd = OwnedFd(unsafe_from_raw=fds[0])
    var wr = OwnedFd(unsafe_from_raw=fds[1])
    var ctx = OwnedPointer(EintrCtx(rd.raw_fd(), use_ppoll))
    var t: UInt64 = 0
    if (
        pthread_create(
            t,
            0,
            eintr_main,
            OpaquePointer[MutAnyOrigin](unsafe_from_address=Int(ctx.ptr())),
        )
        != 0
    ):
        raise Error("pthread_create failed")
    while ctx[].started.load() == 0:
        _yield()
    var pid = syscall0(SYS_getpid)
    var tid = Int(ctx[].tid.load())
    var sent = 0
    # A signal that lands before the thread blocks is simply absorbed by the
    # handler; keep signalling until an EINTR shows up (or give up: restart).
    for _ in range(40):
        sleep(Duration.from_millis(5))
        _ = check("tgkill", syscall3(SYS_tgkill, pid, tid, SIGUSR1))
        sent += 1
        if ctx[].eintr.load() > 0:
            break
    sleep(Duration.from_millis(5))
    _ = check("write", sys.write(wr, String("x").as_bytes()))
    if pthread_join(t, 0) != 0:
        raise Error("pthread_join failed")
    var res = (Int(ctx[].eintr.load()), sent, ctx[].final_ret)
    sys.keep_alive(rd)  # the thread used its raw number
    sys.keep_alive(wr)
    return res


# ---- main --------------------------------------------------------------------


def _expect(cond: Bool, what: String, mut failures: Int):
    if cond:
        print("  ok  ", what)
    else:
        print("  FAIL", what)
        failures += 1


def _addr_of(ref p: OwnedPointer[ThreadCtx]) -> OpaquePointer[MutAnyOrigin]:
    return OpaquePointer[MutAnyOrigin](unsafe_from_address=Int(p.ptr()))


def _wait_started(ref sh: Shared, n: Int) raises -> Bool:
    var deadline = Instant.now() + Duration.from_secs(10)
    while Int(sh.started.load()) < n:
        if deadline < Instant.now():
            return False
        _yield()
    return True


def _exit_mode(mode: Int) raises:
    """Leave a thread running and return from main without joining."""
    var shared = OwnedPointer(Shared())
    var sp = Pointer[Shared, MutUntrackedOrigin](
        unsafe_from_address=Int(shared.ptr())
    )
    var ctx = OwnedPointer(ThreadCtx(0, -1, sp, mode))
    var t: UInt64 = 0
    var rc = pthread_create(t, 0, thread_main, _addr_of(ctx))
    print("  pthread_create rc", rc)
    _ = _wait_started(shared[], 1)
    print("  thread running; returning from main without join (mode", mode, ")")
    # Leak both on purpose: the thread still uses them while the process exits.
    _ = ctx^.unsafe_take_allocation().unsafe_leak()
    _ = shared^.unsafe_take_allocation().unsafe_leak()


def main() raises:
    var exit_mode = getenv("SPIKE_EXIT")
    if exit_mode == "detached-sleep":
        _exit_mode(MODE_SLEEP_FOREVER)
        return
    if exit_mode == "detached-busy":
        _exit_mode(MODE_BUSY_FOREVER)
        return

    var failures = 0
    var main_tid = gettid()
    var main_pid = syscall0(SYS_getpid)
    var base_tasks = count_tasks()
    var cpus = allowed_cpus()
    print(
        "main tid",
        main_tid,
        "tasks at start",
        base_tasks,
        "allowed cpus",
        len(cpus),
    )

    # pthread_attr_t for thread 0: small explicit stack, and an invalid size.
    var attr = Array[UInt64, PTHREAD_ATTR_WORDS](fill=0)
    var attr_addr = Int(Pointer(to=attr))
    _expect(pthread_attr_init(attr_addr) == 0, "pthread_attr_init", failures)
    var too_small = pthread_attr_setstacksize(attr_addr, 1024)
    _expect(
        too_small == 22,
        "setstacksize(1024) is EINVAL (got " + String(too_small) + ")",
        failures,
    )
    _expect(
        pthread_attr_setstacksize(attr_addr, 256 * 1024) == 0,
        "setstacksize(256 KiB)",
        failures,
    )

    var shared = OwnedPointer(Shared())
    var sp = Pointer[Shared, MutUntrackedOrigin](
        unsafe_from_address=Int(shared.ptr())
    )
    var ctxs = List[OwnedPointer[ThreadCtx]]()
    for i in range(N_THREADS):
        ctxs.append(
            OwnedPointer(ThreadCtx(i, cpus[i % len(cpus)], sp, MODE_FULL))
        )

    var tids = List[UInt64](length=N_THREADS, fill=0)
    for i in range(N_THREADS):
        var rc = pthread_create(
            tids[i], attr_addr if i == 0 else 0, thread_main, _addr_of(ctxs[i])
        )
        _expect(rc == 0, "pthread_create #" + String(i), failures)
    _expect(
        pthread_attr_destroy(attr_addr) == 0, "pthread_attr_destroy", failures
    )
    _ = attr  # only its address reached libc; keep it alive until here

    _expect(_wait_started(shared[], N_THREADS), "all threads started", failures)
    var during = count_tasks()
    _expect(
        during == base_tasks + N_THREADS,
        "tasks while running = base + N (" + String(during) + ")",
        failures,
    )
    shared[].go.store(1)

    for i in range(N_THREADS):
        var ret: Int = 0
        var rc = pthread_join(tids[i], Int(Pointer(to=ret)))
        _expect(
            rc == 0 and ret == Int(ctxs[i].ptr()),
            "pthread_join #" + String(i) + " returns the ctx pointer",
            failures,
        )

    var expect_sum = 200_000 * (200_000 - 1) // 2
    var seen_tids = List[Int]()
    for i in range(N_THREADS):
        ref c = ctxs[i][]
        var p = "thread " + String(i) + ": "
        _expect(c.done, p + "ran to completion", failures)
        _expect(
            c.tid != main_tid and c.tid > 0,
            p + "own tid " + String(c.tid),
            failures,
        )
        _expect(c.pid_seen == main_pid, p + "getpid == main pid", failures)
        for t in seen_tids:
            if t == c.tid:
                _expect(False, p + "tid unique", failures)
        seen_tids.append(c.tid)
        _expect(c.list_sum == expect_sum, p + "List sum", failures)
        _expect(c.string_bytes > 0, p + "Strings built", failures)
        _expect(c.dict_ok, p + "Dict ok", failures)
        _expect(c.caught_io, p + "typed IoError caught", failures)
        _expect(
            c.caught_error,
            p + "generic Error caught (message intact)",
            failures,
        )
        _expect(
            c.bad_mask_errno == Int(Errno.EINVAL.value),
            p + "absent-CPU mask is EINVAL (" + String(c.bad_mask_errno) + ")",
            failures,
        )
        _expect(c.pinned_mask_ok, p + "affinity mask reads back", failures)
        _expect(
            c.cpu_after_pin == c.target_cpu,
            p + "getcpu == pinned cpu " + String(c.target_cpu),
            failures,
        )
        var psum = 0
        for v in c.payload:
            psum += v
        _expect(
            len(c.payload) == 10_000
            and psum == 10_000 * 9_999 // 2 + 10_000 * i,
            p + "payload allocated on thread readable by main",
            failures,
        )
    var total = Int(shared[].counter.load())
    _expect(
        total == N_THREADS * ATOMIC_ITERS,
        "atomic counter exact: " + String(total),
        failures,
    )
    ctxs.clear()  # frees the thread-allocated payloads on the main thread

    # Main's own affinity is untouched by the threads' pinning.
    _expect(
        len(allowed_cpus()) == len(cpus), "main affinity unchanged", failures
    )

    # Leak check: many create/join rounds.
    var rss0 = status_field("/proc/self/status", "VmRSS:")
    var t0 = Instant.now()
    for _ in range(ROUNDS):
        var round = List[OwnedPointer[ThreadCtx]]()
        var rt = List[UInt64](length=N_THREADS, fill=0)
        for i in range(N_THREADS):
            round.append(OwnedPointer(ThreadCtx(i, -1, sp, MODE_MINIMAL)))
        for i in range(N_THREADS):
            if pthread_create(rt[i], 0, thread_main, _addr_of(round[i])) != 0:
                failures += 1
        for i in range(N_THREADS):
            if pthread_join(rt[i], 0) != 0:
                failures += 1
            if not round[i][].done or round[i][].payload[0] != i:
                failures += 1
    var dt = Instant.now() - t0
    var settled = count_tasks()
    var spins = 0
    while settled != base_tasks and spins < 1000:
        sleep(Duration.from_millis(1))
        settled = count_tasks()
        spins += 1
    print(
        "  ",
        ROUNDS * N_THREADS,
        "create+join in",
        dt.as_micros(),
        "us (",
        dt.as_micros() // (ROUNDS * N_THREADS),
        "us each); VmRSS",
        rss0,
        "->",
        status_field("/proc/self/status", "VmRSS:"),
    )
    _expect(
        settled == base_tasks,
        "tasks back to base after rounds (" + String(settled) + ")",
        failures,
    )

    # EINTR on a foreign thread, driven by SIGUSR1 from main.
    var rd = _eintr_probe(False)
    print(
        "  blocking read(pipe): EINTR seen",
        rd[0],
        "after",
        rd[1],
        "SIGUSR1; final read =",
        rd[2],
    )
    _expect(
        rd[2] == 1,
        "read completed after signals (got " + String(rd[2]) + ")",
        failures,
    )
    var pp = _eintr_probe(True)
    print(
        "  blocking ppoll: EINTR seen",
        pp[0],
        "after",
        pp[1],
        "SIGUSR1; final read =",
        pp[2],
    )
    _expect(
        pp[0] > 0, "ppoll returns EINTR when SIGUSR1 hits the thread", failures
    )
    _expect(pp[2] == 1, "ppoll retried and completed", failures)
    _expect(
        count_tasks() >= base_tasks, "process survived SIGUSR1 storms", failures
    )

    _ = shared^  # threads used it through `sp`; keep alive until here
    if failures > 0:
        raise Error("PTHREAD SPIKE: ", failures, " failure(s)")
    print("PTHREAD SPIKE: PASS")
