"""Deterministic fault injection for real syscalls (docs/design.md contract 7).

Test builds only. The seam exists only when compiled with
`-D MOJO_NET_FAULTS=1` (`tools/run_tests.sh` passes it to files named
`test_*_faults.mojo`, and only to those). Without the define,
`linux.syscall` never imports this module and every `syscallN` compiles to
the bare inline asm; calling anything here is a compile error, so a test
cannot silently run without its faults.

With the define, every `syscallN` first calls `_intercept`, which counts the
call per syscall number and consults a process-global plan of rules:
- `inject(nr, errno, ...)`: return `-errno` *without* issuing the syscall.
  Nothing happens in the kernel: an injected EAGAIN on recv consumes no
  data, and an injected error on close leaves the descriptor open (unlike a
  real close, where Linux releases the fd even on EINTR).
- `inject_short(nr, max_bytes, ...)`: clamp the length argument (arg 3) of
  read, write, sendto or recvfrom to `max_bytes` and issue the real
  syscall, so a short transfer really moves only that many bytes.

Schedule (per rule, counted from when the rule is added): of the calls to
`nr`, skip the first `skip`; after that the rule fires on every `every`-th
call (`every=1`: each one) until it has fired `times` times (`-1`: forever).
Rules are checked in the order added and the first one that fires wins; a
rule shadowed by an earlier one does not use up one of its `times`. Every
live rule for `nr` still counts the call, so schedules do not depend on
each other.

Mechanism and limits:
- Mojo 1.2 has no global variables. The plan lives in a named
  process-global created by the private stdlib API `std.ffi._Global`
  (backed by the Mojo runtime's `KGEN_CompilerRT_GetOrCreateGlobal`, not
  libc). Library code must not use private stdlib APIs; this is acceptable
  only because this module is compiled exclusively under the test-only
  define (the import sits inside `_plan`, behind a `comptime assert`).
  It may break on a Mojo upgrade; only fault builds would notice.
- One plan per process, shared by all threads and not synchronized: use it
  from one thread at a time (the test runner is single-threaded). It is
  not per-loop state, which is why it is confined to test builds
  (contract 6 forbids global mutable state in `linux`).
- Only syscalls issued through `linux.syscall` are seen. libc, the Mojo
  runtime and Python interop make their own syscalls; those are neither
  counted nor faulted. Seams elsewhere (the `tls` package's OpenSSL calls)
  call `fire` with numbers from `SEAM_BASE` up.
- Counters exist for syscall numbers `0 <= nr < 1024` (all numbers on
  x86_64 and aarch64 today). Each intercepted call costs a runtime lookup
  plus a scan of the rules.
- The plan persists across tests in one process: start each test with
  `clear()`.
"""

from std.os import abort
from std.sys import get_defined_bool

from .errno import Errno
from .error import ErrorKind, IoError
from .nr import SYS_read, SYS_recvfrom, SYS_sendto, SYS_write
from .syscall import MAX_ERRNO

comptime ENABLED = get_defined_bool["MOJO_NET_FAULTS"]()
"""True when compiled with `-D MOJO_NET_FAULTS=1`. Use it to guard optional
fault scenarios: `comptime if fault.ENABLED: ...`."""

comptime _NEED_DEFINE = (
    "linux.fault is test-only: build with -D MOJO_NET_FAULTS=1"
    " (tools/run_tests.sh does this for files named test_*_faults.mojo)"
)

# Name of the process-global. Versioned: two copies of the library with
# different `_Plan` layouts in one process must not share the storage.
comptime _GLOBAL_NAME = "mojo_net.linux.fault.plan.v1"

# Counters cover syscall numbers below this (the highest today is ~470).
comptime _NR_SLOTS = 1024

comptime _FAIL = 0
comptime _SHORT = 1


@fieldwise_init
struct _Rule(TrivialRegisterPassable):
    var nr: Int
    var action: Int  # _FAIL or _SHORT
    var value: Int  # errno (_FAIL) or maximum bytes (_SHORT)
    var skip: Int
    var times: Int  # firings left; -1 = forever, 0 = exhausted
    var every: Int
    var seen: Int  # calls to `nr` observed while live


struct _Plan(Movable):
    var rules: List[_Rule]
    var counts: List[Int]

    def __init__(out self):
        self.rules = List[_Rule]()
        self.counts = List[Int](length=_NR_SLOTS, fill=0)


def _new_plan() -> _Plan:
    return _Plan()


@inline(.always)
def _plan() -> Pointer[_Plan, MutUntrackedOrigin]:
    comptime assert ENABLED, _NEED_DEFINE
    # Private stdlib API, allowed only because this is test-only (see above).
    from std.ffi import _Global

    try:
        return _Global[_GLOBAL_NAME, _new_plan].get_or_create_ptr()
    except e:
        abort(String("linux.fault: cannot create the fault plan: ", e))


@no_inline
def _intercept(nr: Int, mut length: Int) -> Int:
    """Called by `syscallN` before the real syscall (fault builds only).

    Returns `-errno` to fail the call without issuing it, or 0 to issue it
    with `length` (arg 3), which a short-transfer rule may have lowered.
    Never issues a syscall itself, so it cannot recurse.
    """
    var plan = _plan()
    if nr >= 0 and nr < _NR_SLOTS:
        plan[].counts[nr] += 1
    var hit = -1
    for i in range(len(plan[].rules)):
        ref rule = plan[].rules[i]
        if rule.nr != nr or rule.times == 0:
            continue
        rule.seen += 1
        var past_skip = rule.seen - rule.skip
        if hit < 0 and past_skip > 0 and past_skip % rule.every == 0:
            hit = i
    if hit < 0:
        return 0
    ref fired = plan[].rules[hit]
    if fired.times > 0:
        fired.times -= 1
    if fired.action == _FAIL:
        return -fired.value
    if length > fired.value:
        length = fired.value
    return 0


def _add(
    op: StaticString,
    nr: Int,
    action: Int,
    value: Int,
    skip: Int,
    times: Int,
    every: Int,
) raises IoError:
    if nr < 0 or nr >= _NR_SLOTS or skip < 0 or every < 1:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    if times < -1 or times == 0:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)
    _plan()[].rules.append(_Rule(nr, action, value, skip, times, every, 0))


def inject(
    nr: Int, errno: Errno, skip: Int = 0, times: Int = 1, every: Int = 1
) raises IoError:
    """Fail calls to syscall `nr` with `errno`, without issuing them.

    Raises InvalidInput for an errno outside `1..4095`, a syscall number
    outside `0..1023`, `skip < 0`, `every < 1`, or `times` not `-1` or
    positive.
    """
    comptime assert ENABLED, _NEED_DEFINE
    var e = Int(errno.value)
    if e < 1 or e > MAX_ERRNO:
        raise IoError.of_kind("fault.inject", ErrorKind.InvalidInput)
    _add("fault.inject", nr, _FAIL, e, skip, times, every)


def inject_short(
    nr: Int, max_bytes: Int, skip: Int = 0, times: Int = 1, every: Int = 1
) raises IoError:
    """Clamp the length of calls to `nr` (read, write, sendto or recvfrom
    only) to `max_bytes`, then issue the real syscall.

    `max_bytes = 0` turns the call into a zero-length transfer: write and
    send return 0 (which no real socket does), read and recv return 0 and
    look like EOF. Same schedule rules as `inject`; also raises
    InvalidInput for any other syscall or a negative `max_bytes`.
    """
    comptime assert ENABLED, _NEED_DEFINE
    if max_bytes < 0 or not (
        nr == SYS_read
        or nr == SYS_write
        or nr == SYS_sendto
        or nr == SYS_recvfrom
    ):
        raise IoError.of_kind("fault.inject_short", ErrorKind.InvalidInput)
    _add("fault.inject_short", nr, _SHORT, max_bytes, skip, times, every)


def fire(nr: Int) -> Int:
    """For seams outside `linux.syscall` (the `tls` package numbers its
    OpenSSL seams from `SEAM_BASE`): count a call to `nr` and return the
    value of the `inject` rule that fires on it (its errno, which the seam
    reads as it documents), or 0 when none does."""
    comptime assert ENABLED, _NEED_DEFINE
    var length = 0
    return -_intercept(nr, length)


comptime SEAM_BASE = 1000
"""Numbers from here to 1023 are no syscall (the highest is ~470): seams
outside `linux.syscall` use them with `inject` and `fire`."""


def clear():
    """Remove every rule and zero every call counter."""
    comptime assert ENABLED, _NEED_DEFINE
    var plan = _plan()
    plan[].rules.clear()
    for i in range(_NR_SLOTS):
        plan[].counts[i] = 0


def calls(nr: Int) -> Int:
    """How many times `syscallN(nr, ...)` ran since the last `clear()`,
    including calls a rule failed or shortened (0 for unknown numbers)."""
    comptime assert ENABLED, _NEED_DEFINE
    if nr < 0 or nr >= _NR_SLOTS:
        return 0
    return _plan()[].counts[nr]


def pending() -> Int:
    """How many rules can still fire. 0 at the end of a test shows that the
    scenario reached every fault it planned (rules with `times=-1` always
    count as pending)."""
    comptime assert ENABLED, _NEED_DEFINE
    var n = 0
    for rule in _plan()[].rules:
        if rule.times != 0:
            n += 1
    return n
