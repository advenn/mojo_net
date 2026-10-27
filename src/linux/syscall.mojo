"""Raw Linux syscalls via inline assembly (x86_64 and aarch64). No libc.

Every function returns the kernel's raw result: a non-negative value on
success, or `-errno` in `[-4095, -1]` on failure. Use `is_err` / `err_of` to
decode. Arguments are passed as `Int`; callers that pass addresses must keep
the pointee alive across the call (take a typed pointer or `Span` in the
calling wrapper so its origin extends the owner's lifetime).

Register conventions:
- x86_64: `syscall`, nr in rax, args rdi rsi rdx r10 r8 r9, result in rax;
  the instruction clobbers rcx and r11.
- aarch64: `svc #0`, nr in x8, args x0..x5, result in x0.

Fault injection: built with `-D MOJO_NET_FAULTS=1` (test builds only), each
`syscallN` first asks `linux.fault` whether to fail the call or shorten its
length argument (arg 3). Without the define the hook and its import do not
exist: `syscallN` is exactly `_asmN`.

Supported targets: little-endian 64-bit Linux on x86_64 or aarch64 only.
Everything below treats "not x86" as aarch64, and the ABI layer assumes LP64
little endian (`abi.hton16` swaps unconditionally; `TcpInfo` and auxv
decoding read little-endian words). `assert_supported_target` makes any
other target (aarch64_be, riscv64, 32-bit x86/arm, ...) a build error
instead of a binary that sends byte-swapped ports and addresses; every
`syscallN` and every `abi` byte-order helper calls it.
"""

from std.sys import CompilationTarget, get_defined_bool, inlined_assembly
from std.sys.info import Endian, is_64bit

comptime _X86 = CompilationTarget.is_x86()

comptime SUPPORTED_TARGET = (
    CompilationTarget.is_linux()
    and (CompilationTarget.is_x86() or CompilationTarget.is_arm())
    and is_64bit()
    and Endian.native() == Endian.little
)
"""True on the targets this library supports: Linux, x86_64 or aarch64,
64-bit, little endian."""


@inline(.always)
def assert_supported_target():
    """Compile-time check of `SUPPORTED_TARGET`; no code is generated."""
    comptime assert SUPPORTED_TARGET, (
        "mojo_net supports only little-endian 64-bit Linux on x86_64 or"
        " aarch64; this target would get wrong syscall registers or byte order"
    )

# Same switch as `linux.fault.ENABLED`; kept here so that normal builds never
# import `linux.fault`.
comptime _FAULTS = get_defined_bool["MOJO_NET_FAULTS"]()

# Largest errno the kernel returns through a syscall result.
comptime MAX_ERRNO = 4095


@inline(.always)
def is_err(ret: Int) -> Bool:
    """True if `ret` is a raw syscall error result (`-4095..-1`)."""
    return ret < 0 and ret >= -MAX_ERRNO


@inline(.always)
def err_of(ret: Int) -> Int32:
    """The errno carried by an error result (`is_err(ret)` must hold)."""
    return Int32(-ret)


# ---- public entry points (fault seam) --------------------------------------


@inline(.always)
def syscall0(nr: Int) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var unused = 0
        var r = _intercept(nr, unused)
        if r != 0:
            return r
    return _asm0(nr)


@inline(.always)
def syscall1(nr: Int, a1: Int) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var unused = 0
        var r = _intercept(nr, unused)
        if r != 0:
            return r
    return _asm1(nr, a1)


@inline(.always)
def syscall2(nr: Int, a1: Int, a2: Int) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var unused = 0
        var r = _intercept(nr, unused)
        if r != 0:
            return r
    return _asm2(nr, a1, a2)


@inline(.always)
def syscall3(nr: Int, a1: Int, a2: Int, a3: Int) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var len3 = a3
        var r = _intercept(nr, len3)
        if r != 0:
            return r
        return _asm3(nr, a1, a2, len3)
    else:
        return _asm3(nr, a1, a2, a3)


@inline(.always)
def syscall4(nr: Int, a1: Int, a2: Int, a3: Int, a4: Int) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var len3 = a3
        var r = _intercept(nr, len3)
        if r != 0:
            return r
        return _asm4(nr, a1, a2, len3, a4)
    else:
        return _asm4(nr, a1, a2, a3, a4)


@inline(.always)
def syscall5(nr: Int, a1: Int, a2: Int, a3: Int, a4: Int, a5: Int) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var len3 = a3
        var r = _intercept(nr, len3)
        if r != 0:
            return r
        return _asm5(nr, a1, a2, len3, a4, a5)
    else:
        return _asm5(nr, a1, a2, a3, a4, a5)


@inline(.always)
def syscall6(
    nr: Int, a1: Int, a2: Int, a3: Int, a4: Int, a5: Int, a6: Int
) -> Int:
    assert_supported_target()
    comptime if _FAULTS:
        from .fault import _intercept

        var len3 = a3
        var r = _intercept(nr, len3)
        if r != 0:
            return r
        return _asm6(nr, a1, a2, len3, a4, a5, a6)
    else:
        return _asm6(nr, a1, a2, a3, a4, a5, a6)


# ---- inline asm (the only asm in the library) ------------------------------


@inline(.always)
def _asm0(nr: Int) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints="={rax},{rax},~{rcx},~{r11},~{memory}",
        ](nr)
    else:
        return inlined_assembly[
            "svc #0", Int, constraints="={x0},{x8},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}"
        ](nr)


@inline(.always)
def _asm1(nr: Int, a1: Int) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints="={rax},{rax},{rdi},~{rcx},~{r11},~{memory}",
        ](nr, a1)
    else:
        return inlined_assembly[
            "svc #0", Int, constraints="={x0},{x8},{x0},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}"
        ](nr, a1)


@inline(.always)
def _asm2(nr: Int, a1: Int, a2: Int) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints="={rax},{rax},{rdi},{rsi},~{rcx},~{r11},~{memory}",
        ](nr, a1, a2)
    else:
        return inlined_assembly[
            "svc #0", Int, constraints="={x0},{x8},{x0},{x1},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}"
        ](nr, a1, a2)


@inline(.always)
def _asm3(nr: Int, a1: Int, a2: Int, a3: Int) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints="={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory}",
        ](nr, a1, a2, a3)
    else:
        return inlined_assembly[
            "svc #0",
            Int,
            constraints="={x0},{x8},{x0},{x1},{x2},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}",
        ](nr, a1, a2, a3)


@inline(.always)
def _asm4(nr: Int, a1: Int, a2: Int, a3: Int, a4: Int) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints=(
                "={rax},{rax},{rdi},{rsi},{rdx},{r10},~{rcx},~{r11},~{memory}"
            ),
        ](nr, a1, a2, a3, a4)
    else:
        return inlined_assembly[
            "svc #0",
            Int,
            constraints="={x0},{x8},{x0},{x1},{x2},{x3},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}",
        ](nr, a1, a2, a3, a4)


@inline(.always)
def _asm5(nr: Int, a1: Int, a2: Int, a3: Int, a4: Int, a5: Int) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints=(
                "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},"
                "~{rcx},~{r11},~{memory}"
            ),
        ](nr, a1, a2, a3, a4, a5)
    else:
        return inlined_assembly[
            "svc #0",
            Int,
            constraints="={x0},{x8},{x0},{x1},{x2},{x3},{x4},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}",
        ](nr, a1, a2, a3, a4, a5)


@inline(.always)
def _asm6(
    nr: Int, a1: Int, a2: Int, a3: Int, a4: Int, a5: Int, a6: Int
) -> Int:
    comptime if _X86:
        return inlined_assembly[
            "syscall",
            Int,
            constraints=(
                "={rax},{rax},{rdi},{rsi},{rdx},{r10},{r8},{r9},"
                "~{rcx},~{r11},~{memory}"
            ),
        ](nr, a1, a2, a3, a4, a5, a6)
    else:
        return inlined_assembly[
            "svc #0",
            Int,
            constraints="={x0},{x8},{x0},{x1},{x2},{x3},{x4},{x5},~{memory},~{p0},~{p1},~{p2},~{p3},~{p4},~{p5},~{p6},~{p7},~{p8},~{p9},~{p10},~{p11},~{p12},~{p13},~{p14},~{p15},~{ffr}",
        ](nr, a1, a2, a3, a4, a5, a6)
