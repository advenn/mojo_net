#!/usr/bin/env python3
"""ABI oracle: derive constants, errno names and struct layouts from the C headers.

  gen_abi.py --write   regenerate src/linux/consts.mojo and src/linux/errno.mojo
  gen_abi.py --check   fail if the committed files differ from this host's headers
                       (run on every CI architecture)

Both modes also write build/test_abi_layout.mojo, which asserts that every
mirror struct in src/linux/abi.mojo has the size and field offsets the C
compiler reports on this host. Run it with `pixi run abi-check`.
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HEADERS = """
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/auxv.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <time.h>
#include <linux/sockios.h>
"""

# (section comment, [constant names])
CONSTS = [
    ("Address families", ["AF_UNSPEC", "AF_UNIX", "AF_INET", "AF_INET6"]),
    ("Socket types and creation flags",
     ["SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_SEQPACKET",
      "SOCK_NONBLOCK", "SOCK_CLOEXEC"]),
    ("Protocols / option levels",
     ["SOL_SOCKET", "IPPROTO_IP", "IPPROTO_IPV6", "IPPROTO_TCP", "IPPROTO_UDP"]),
    ("SOL_SOCKET options",
     ["SO_REUSEADDR", "SO_REUSEPORT", "SO_KEEPALIVE", "SO_LINGER", "SO_RCVBUF",
      "SO_SNDBUF", "SO_ERROR", "SO_TYPE", "SO_DOMAIN", "SO_PROTOCOL",
      "SO_ACCEPTCONN", "SO_PEERCRED", "SO_RCVLOWAT", "SO_SNDLOWAT",
      "SO_RCVTIMEO", "SO_SNDTIMEO", "SO_INCOMING_CPU", "SO_MARK",
      "SO_ZEROCOPY", "SO_BINDTODEVICE", "SO_BUSY_POLL",
      "SO_ATTACH_REUSEPORT_CBPF"]),
    ("IPPROTO_TCP options",
     ["TCP_NODELAY", "TCP_MAXSEG", "TCP_CORK", "TCP_KEEPIDLE", "TCP_KEEPINTVL",
      "TCP_KEEPCNT", "TCP_SYNCNT", "TCP_LINGER2", "TCP_DEFER_ACCEPT",
      "TCP_INFO", "TCP_QUICKACK", "TCP_CONGESTION", "TCP_USER_TIMEOUT",
      "TCP_FASTOPEN", "TCP_FASTOPEN_CONNECT", "TCP_NOTSENT_LOWAT", "TCP_ULP"]),
    ("TCP states (tcp_info state)",
     ["TCP_ESTABLISHED", "TCP_SYN_SENT", "TCP_SYN_RECV", "TCP_FIN_WAIT1",
      "TCP_FIN_WAIT2", "TCP_TIME_WAIT", "TCP_CLOSE", "TCP_CLOSE_WAIT",
      "TCP_LAST_ACK", "TCP_LISTEN", "TCP_CLOSING"]),
    ("TCP congestion-avoidance states (tcp_info ca_state)",
     ["TCP_CA_Open", "TCP_CA_Disorder", "TCP_CA_CWR", "TCP_CA_Recovery",
      "TCP_CA_Loss"]),
    ("IP / IPv6 options", ["IP_TOS", "IP_TTL", "IPV6_V6ONLY", "IPV6_TCLASS"]),
    ("send/recv flags",
     ["MSG_OOB", "MSG_PEEK", "MSG_DONTWAIT", "MSG_NOSIGNAL", "MSG_MORE",
      "MSG_WAITALL", "MSG_TRUNC", "MSG_CTRUNC", "MSG_ERRQUEUE", "MSG_ZEROCOPY",
      "MSG_CMSG_CLOEXEC"]),
    ("shutdown(2)", ["SHUT_RD", "SHUT_WR", "SHUT_RDWR"]),
    ("Vectored I/O", ["IOV_MAX"]),
    ("Control messages", ["SCM_RIGHTS", "SCM_CREDENTIALS"]),
    ("poll(2) events",
     ["POLLIN", "POLLPRI", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL",
      "POLLRDHUP"]),
    ("epoll(7)",
     ["EPOLLIN", "EPOLLPRI", "EPOLLOUT", "EPOLLERR", "EPOLLHUP", "EPOLLRDHUP",
      "EPOLLEXCLUSIVE", "EPOLLWAKEUP", "EPOLLONESHOT", "EPOLLET",
      "EPOLL_CTL_ADD", "EPOLL_CTL_DEL", "EPOLL_CTL_MOD", "EPOLL_CLOEXEC"]),
    ("eventfd / timerfd / signalfd",
     ["EFD_CLOEXEC", "EFD_NONBLOCK", "EFD_SEMAPHORE", "TFD_CLOEXEC",
      "TFD_NONBLOCK", "TFD_TIMER_ABSTIME", "SFD_CLOEXEC", "SFD_NONBLOCK"]),
    ("open / fcntl",
     ["O_RDONLY", "O_WRONLY", "O_RDWR", "O_NONBLOCK", "O_CLOEXEC", "AT_FDCWD",
      "F_DUPFD_CLOEXEC", "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL",
      "FD_CLOEXEC"]),
    ("ioctl", ["FIONREAD", "FIONBIO", "SIOCINQ", "SIOCOUTQ", "SIOCGIFINDEX"]),
    ("Interfaces", ["IF_NAMESIZE"]),
    ("Clocks", ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_MONOTONIC_RAW",
                "CLOCK_BOOTTIME"]),
    ("mmap", ["PROT_NONE", "PROT_READ", "PROT_WRITE", "MAP_SHARED",
              "MAP_PRIVATE", "MAP_ANONYMOUS", "MAP_POPULATE"]),
    ("Resources / random", ["RLIMIT_NOFILE", "GRND_NONBLOCK", "GRND_RANDOM"]),
    ("Signals", ["SIG_BLOCK", "SIG_UNBLOCK", "SIG_SETMASK", "SIGINT", "SIGPIPE",
                 "SIGALRM", "SIGTERM", "SIGCHLD", "SIGUSR1", "SIGUSR2"]),
    ("Timers", ["TIMER_ABSTIME", "SIGEV_THREAD_ID"]),
    ("Aux vector (/proc/self/auxv)",
     ["AT_NULL", "AT_PAGESZ", "AT_UID", "AT_EUID", "AT_GID", "AT_EGID",
      "AT_SYSINFO_EHDR"]),
]

# `struct tcp_info` from <linux/tcp.h>. That header conflicts with
# <netinet/tcp.h> (both define struct tcphdr / TCP_* option macros), so the
# offsets come from a second translation unit. Only fields that exist since
# Linux 5.5 are listed: the kernel copies min(optlen, its sizeof), so a
# reader must check how many bytes it got before trusting a later field.
# Emitted as TCPI_OFF_<FIELD> (byte offset).
TCP_INFO_FIELDS = [
    "state", "ca_state", "retransmits", "probes", "backoff", "options",
    "rto", "ato", "snd_mss", "rcv_mss", "unacked", "sacked", "lost",
    "retrans", "fackets", "last_data_sent", "last_ack_sent",
    "last_data_recv", "last_ack_recv", "pmtu", "rcv_ssthresh", "rtt",
    "rttvar", "snd_ssthresh", "snd_cwnd", "advmss", "reordering", "rcv_rtt",
    "rcv_space", "total_retrans", "pacing_rate", "max_pacing_rate",
    "bytes_acked", "bytes_received", "segs_out", "segs_in", "notsent_bytes",
    "min_rtt", "data_segs_in", "data_segs_out", "delivery_rate", "busy_time",
    "rwnd_limited", "sndbuf_limited", "delivered", "delivered_ce",
    "bytes_sent", "bytes_retrans", "dsack_dups", "reord_seen", "rcv_ooopack",
    "snd_wnd",
]
# Bitfields (offsetof is not allowed on them): the oracle sets each one to
# all-ones in a zeroed struct and reports the byte, the shift and the width.
# Emitted as TCPI_OFF_/TCPI_SHIFT_/TCPI_BITS_<FIELD>.
TCP_INFO_BITFIELDS = [
    "snd_wscale", "rcv_wscale", "delivery_rate_app_limited",
    "fastopen_client_fail",
]


def tcp_info_names():
    names = [f"TCPI_OFF_{f.upper()}" for f in TCP_INFO_FIELDS]
    for f in TCP_INFO_BITFIELDS:
        u = f.upper()
        names += [f"TCPI_OFF_{u}", f"TCPI_SHIFT_{u}", f"TCPI_BITS_{u}"]
    return names


def tcp_info_program() -> str:
    out = [
        "#include <stddef.h>",
        "#include <stdio.h>",
        "#include <string.h>",
        "#include <linux/tcp.h>",
        "int main(void) {",
    ]
    for f in TCP_INFO_FIELDS:
        out.append(f'  printf("C TCPI_OFF_{f.upper()} %zu\\n", '
                   f"offsetof(struct tcp_info, tcpi_{f}));")
    out.append("  struct tcp_info t;")
    out.append("  const unsigned char *b = (const unsigned char *)&t;")
    for f in TCP_INFO_BITFIELDS:
        u = f.upper()
        out += [
            "  memset(&t, 0, sizeof t);",
            f"  t.tcpi_{f} = -1;",
            "  for (size_t i = 0; i < sizeof t; i++) {",
            "    if (!b[i]) continue;",
            f'    printf("C TCPI_OFF_{u} %zu\\n", i);',
            f'    printf("C TCPI_SHIFT_{u} %d\\n", __builtin_ctz(b[i]));',
            f'    printf("C TCPI_BITS_{u} %d\\n", __builtin_popcount(b[i]));',
            "    break;",
            "  }",
        ]
    out.append("  return 0;\n}")
    return "\n".join(out)


# Extra errno spellings that alias a canonical one.
ERRNO_ALIASES = {"EWOULDBLOCK": "EAGAIN", "EDEADLOCK": "EDEADLK",
                 "ENOTSUP": "EOPNOTSUPP"}

# (C type, Mojo type, [(C field, Mojo field)]); the Mojo type lives in
# linux.abi unless STRUCT_MODULES names another module.
STRUCTS = [
    ("struct sockaddr_in", "SockaddrIn",
     [("sin_family", "family"), ("sin_port", "port"), ("sin_addr", "addr"),
      ("sin_zero", "zero")]),
    ("struct sockaddr_in6", "SockaddrIn6",
     [("sin6_family", "family"), ("sin6_port", "port"),
      ("sin6_flowinfo", "flowinfo"), ("sin6_addr", "addr"),
      ("sin6_scope_id", "scope_id")]),
    ("struct sockaddr_un", "SockaddrUn",
     [("sun_family", "family"), ("sun_path", "path")]),
    ("struct sockaddr_storage", "SockaddrStorage", [("ss_family", "family")]),
    ("struct iovec", "Iovec", [("iov_base", "base"), ("iov_len", "len")]),
    ("struct msghdr", "Msghdr",
     [("msg_name", "name"), ("msg_namelen", "namelen"), ("msg_iov", "iov"),
      ("msg_iovlen", "iovlen"), ("msg_control", "control"),
      ("msg_controllen", "controllen"), ("msg_flags", "flags")]),
    ("struct cmsghdr", "Cmsghdr",
     [("cmsg_len", "len"), ("cmsg_level", "level"), ("cmsg_type", "type")]),
    ("struct pollfd", "Pollfd",
     [("fd", "fd"), ("events", "events"), ("revents", "revents")]),
    ("struct timespec", "Timespec", [("tv_sec", "sec"), ("tv_nsec", "nsec")]),
    ("struct timeval", "Timeval", [("tv_sec", "sec"), ("tv_usec", "usec")]),
    ("struct linger", "Linger", [("l_onoff", "onoff"), ("l_linger", "linger")]),
    ("struct ucred", "Ucred", [("pid", "pid"), ("uid", "uid"), ("gid", "gid")]),
    ("struct utsname", "Utsname",
     [("sysname", "sysname"), ("nodename", "nodename"), ("release", "release"),
      ("version", "version"), ("machine", "machine"),
      ("domainname", "domainname")]),
    ("struct rlimit64", "Rlimit", [("rlim_cur", "cur"), ("rlim_max", "max")]),
    ("struct ifreq", "Ifreq",
     [("ifr_name", "name"), ("ifr_ifindex", "ifindex")]),
]

# Mirrors kept outside linux.abi ({Mojo type: module}); currently none.
STRUCT_MODULES: dict[str, str] = {}


def c_program() -> str:
    out = [HEADERS, "int main(void) {"]
    for _, names in CONSTS:
        for n in names:
            out.append(f'  printf("C {n} %lld\\n", (long long)({n}));')
    out.append("  for (int e = 1; e < 134; e++) {")
    out.append("    const char *n = strerrorname_np(e);")
    out.append('    if (n) printf("E %d %s\\n", e, n);')
    out.append("  }")
    for ctype, mojo, fields in STRUCTS:
        out.append(f'  printf("S {mojo} %zu %zu\\n", sizeof({ctype}), '
                   f"_Alignof({ctype}));")
        for cf, mf in fields:
            out.append(f'  printf("F {mojo} {mf} %zu\\n", '
                       f"offsetof({ctype}, {cf}));")
    out.append('  printf("S EpollEvent %zu %zu\\n", sizeof(struct epoll_event), '
               "_Alignof(struct epoll_event));")
    out.append('  printf("D EpollEvent %zu\\n", '
               "offsetof(struct epoll_event, data));")
    out.append("  return 0;\n}")
    return "\n".join(out)


def compile_and_run(d: str, name: str, program: str) -> str:
    src, exe = os.path.join(d, name + ".c"), os.path.join(d, name)
    with open(src, "w") as f:
        f.write(program)
    subprocess.run(["gcc", "-O0", "-o", exe, src], check=True)
    return subprocess.run([exe], capture_output=True, text=True,
                          check=True).stdout


def run_oracle():
    with tempfile.TemporaryDirectory() as d:
        text = compile_and_run(d, "oracle", c_program())
        text += compile_and_run(d, "oracle_tcp_info", tcp_info_program())
    consts, errnos, sizes, offsets, epoll_data = {}, [], {}, {}, None
    for line in text.splitlines():
        kind, *rest = line.split()
        if kind == "C":
            consts[rest[0]] = int(rest[1])
        elif kind == "E":
            errnos.append((int(rest[0]), rest[1]))
        elif kind == "S":
            sizes[rest[0]] = (int(rest[1]), int(rest[2]))
        elif kind == "F":
            offsets.setdefault(rest[0], []).append((rest[1], int(rest[2])))
        elif kind == "D":
            epoll_data = int(rest[1])
    return consts, errnos, sizes, offsets, epoll_data


def render_consts(consts) -> str:
    lines = [
        '"""Linux constants for x86_64 and aarch64.',
        "",
        "GENERATED by tools/gen_abi.py from the C headers; do not edit.",
        "`pixi run abi-check` verifies them on each CI architecture.",
        '"""',
    ]
    for title, names in CONSTS:
        lines += ["", f"# {title}"]
        lines += [f"comptime {n}: Int = {consts[n]}" for n in names]
    lines += [
        "",
        "# struct tcp_info (<linux/tcp.h>): byte offsets; bitfields also have",
        "# a shift and a width in bits. Fields up to snd_wnd exist since 5.5.",
    ]
    names = tcp_info_names()
    missing = [n for n in names if n not in consts]
    if missing:
        raise SystemExit(f"tcp_info oracle did not report {missing}")
    lines += [f"comptime {n}: Int = {consts[n]}" for n in names]
    return "\n".join(lines) + "\n"


def render_errno(errnos) -> str:
    by_name = {n: v for v, n in errnos}
    lines = [
        '"""Linux errno values (identical on x86_64 and aarch64).',
        "",
        "GENERATED by tools/gen_abi.py from the C headers; do not edit.",
        '"""',
        "",
        "",
        "@fieldwise_init",
        "struct Errno(TrivialRegisterPassable, Equatable, Writable):",
        '    """A Linux errno value. Constants: `Errno.EAGAIN`, ..."""',
        "",
        "    var value: Int32",
        "",
    ]
    for v, n in errnos:
        lines.append(f"    comptime {n} = Errno({v})")
    for alias, canon in ERRNO_ALIASES.items():
        lines.append(f"    comptime {alias} = Errno({by_name[canon]})")
    lines += [
        "",
        "    @inline(.always)",
        "    def __eq__(self, other: Self) -> Bool:",
        "        return self.value == other.value",
        "",
        "    def name(self) -> StaticString:",
        '        """Symbolic name, e.g. "ECONNRESET"; "E?" if unknown."""',
    ]
    for v, n in errnos:
        lines += [f"        if self.value == {v}:", f'            return "{n}"']
    lines += [
        '        return "E?"',
        "",
        "    def write_to(self, mut writer: Some[Writer]):",
        '        writer.write(self.name(), "(", self.value, ")")',
    ]
    return "\n".join(lines) + "\n"


def render_layout_test(sizes, offsets, epoll_data) -> str:
    lines = [
        '"""GENERATED by tools/gen_abi.py for this host; do not edit or commit."""',
        "",
        "from std.reflection import reflect",
        "from std.sys import align_of, size_of",
        "from std.testing import TestSuite, assert_equal",
        "",
        "from linux.abi import *",
    ]
    for mojo, module in sorted(STRUCT_MODULES.items()):
        lines.append(f"from {module} import {mojo}")
    lines.append("")
    for _, mojo, _ in STRUCTS:
        size, align = sizes[mojo]
        lines += [
            "",
            f"def test_{mojo.lower()}() raises:",
            f"    assert_equal(size_of[{mojo}](), {size})",
            f"    assert_equal(align_of[{mojo}](), {align})",
        ]
        for mf, off in offsets.get(mojo, []):
            lines.append(f'    assert_equal(reflect[{mojo}].field_offset'
                         f'[name="{mf}"](), {off})')
    size, _ = sizes["EpollEvent"]
    lines += [
        "",
        "def test_epollevent() raises:",
        f"    assert_equal(size_of[EpollEvent](), {size})",
        "    var ev = EpollEvent(7, 0x1122334455667788)",
        "    var p = Pointer(to=ev).unsafe_bitcast[UInt8]()",
        "    assert_equal(p.unsafe_offset(0)[], 7)",
        f"    assert_equal(p.unsafe_offset({epoll_data})[], 0x88)",
        f"    assert_equal(p.unsafe_offset({epoll_data} + 7)[], 0x11)",
        "    assert_equal(ev.data(), 0x1122334455667788)",
        "",
        "",
        "def main() raises:",
        "    TestSuite.discover_tests[__functions_in_module()]().run()",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    consts, errnos, sizes, offsets, epoll_data = run_oracle()
    files = {
        os.path.join(ROOT, "src", "linux", "consts.mojo"): render_consts(consts),
        os.path.join(ROOT, "src", "linux", "errno.mojo"): render_errno(errnos),
    }
    status = 0
    for path, text in files.items():
        if mode == "--write":
            with open(path, "w") as f:
                f.write(text)
            print(f"wrote {os.path.relpath(path, ROOT)}")
        else:
            current = open(path).read() if os.path.exists(path) else ""
            if current != text:
                print(f"MISMATCH: {os.path.relpath(path, ROOT)} differs from "
                      "this host's headers", file=sys.stderr)
                status = 1
    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    test_path = os.path.join(ROOT, "build", "test_abi_layout.mojo")
    with open(test_path, "w") as f:
        f.write(render_layout_test(sizes, offsets, epoll_data))
    print(f"wrote {os.path.relpath(test_path, ROOT)}")
    return status


if __name__ == "__main__":
    sys.exit(main())
