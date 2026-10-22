// C baseline for the 10k-connection epoll spike (docs/spikes.md).
//
// The same server as server.mojo, written as close to line by line as C
// allows, so the two can be compared directly:
// - single thread, nonblocking sockets, edge-triggered epoll;
// - a slab of 48-byte slots, with epoll data = generation << 32 | slot;
// - each socket registered once with EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET;
// - reads into one shared 64 KiB buffer until EAGAIN or a short read, but
//   only until EOF/EAGAIN once RDHUP/HUP/ERR was seen (--strict-eagain:
//   until EAGAIN always);
// - echo with partial-write queueing, pausing reads once 256 KiB is queued;
// - accept4(NONBLOCK|CLOEXEC) until EAGAIN, pausing accepts on EMFILE;
// - RLIMIT_NOFILE raised to the hard limit;
// - the same counters and the same LISTEN/STATS/FINAL lines.
// The I/O goes through glibc's thin wrappers. The clock is glibc's
// clock_gettime, served by the vDSO (no syscall), unlike the Mojo server's
// raw syscall; it is read once per 64 waits in both, so this hardly matters.
//
//   gcc -O2 -Wall -Wextra -o spikes/epoll_echo/out/baseline spikes/epoll_echo/baseline.c

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define READ_BUF (64 * 1024)
#define PENDING_CAP (256 * 1024)
#define LISTENER_TOKEN UINT64_MAX
#define CONN_EVENTS (EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET)
#define READABLE (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)
#define CLOCK_EVERY 64

struct slot {
    uint32_t gen;
    int fd; // -1 while free
    uint8_t *pending;
    size_t plen, pcap, sent;
    bool read_paused;
    bool peer_eof;    // half-closed with echo bytes still queued
    bool read_closed; // RDHUP/HUP/ERR seen: no short-read shortcut (sticky)
};

static struct {
    long waits, events, accept_calls, accepted, accept_exhausted, recvs,
        recv_eagain, sends, send_eagain, send_partial, ctls, setsockopts,
        closes, clock_reads, eintr, stale, resets, pauses, bytes_in, bytes_out;
} st;

static struct slot *slots;
static size_t nslots, cap_slots;
static size_t *free_list;
static size_t nfree, cap_free;
static int ep, lfd;
static long open_conns;
static bool strict_eagain, accept_paused, retry_accept;
static uint8_t buf[READ_BUF];

static long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    st.clock_reads++;
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static void die(const char *what) {
    perror(what);
    exit(1);
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) die("realloc");
    return q;
}

static size_t alloc_slot(void) {
    if (nfree) return free_list[--nfree];
    if (nslots == cap_slots) {
        cap_slots = cap_slots ? cap_slots * 2 : 1024;
        slots = xrealloc(slots, cap_slots * sizeof *slots);
    }
    slots[nslots] = (struct slot){.gen = 0, .fd = -1};
    return nslots++;
}

static void push_free(size_t idx) {
    if (nfree == cap_free) {
        cap_free = cap_free ? cap_free * 2 : 1024;
        free_list = xrealloc(free_list, cap_free * sizeof *free_list);
    }
    free_list[nfree++] = idx;
}

static uint64_t token(size_t idx, uint32_t gen) {
    return ((uint64_t)gen << 32) | (uint64_t)idx;
}

static bool transient_accept_error(int e) {
    return e == ECONNABORTED || e == EPROTO || e == ENETDOWN ||
           e == ENOPROTOOPT || e == EHOSTDOWN || e == ENONET ||
           e == EHOSTUNREACH || e == EOPNOTSUPP || e == ENETUNREACH ||
           e == EPERM;
}

static void accept_all(void) {
    for (;;) {
        int fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        st.accept_calls++;
        if (fd < 0) {
            int e = errno;
            if (e == EAGAIN) {
                if (accept_paused) {
                    accept_paused = false;
                    printf("accept: resumed, open=%ld\n", open_conns);
                    fflush(stdout);
                }
                return;
            }
            if (e == EINTR) { st.eintr++; continue; }
            if (transient_accept_error(e)) continue;
            if (e == EMFILE || e == ENFILE || e == ENOBUFS || e == ENOMEM) {
                st.accept_exhausted++;
                if (!accept_paused) {
                    accept_paused = true;
                    printf("accept: %s, pausing accepts (open=%ld)\n",
                           strerrorname_np(e), open_conns);
                    fflush(stdout);
                }
                return;
            }
            die("accept4");
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        st.setsockopts++;
        size_t idx = alloc_slot();
        struct epoll_event ev = {.events = CONN_EVENTS,
                                 .data.u64 = token(idx, slots[idx].gen)};
        st.ctls++;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) < 0) {
            perror("epoll_ctl(ADD)");
            close(fd);
            st.closes++;
            push_free(idx);
            continue;
        }
        slots[idx].fd = fd;
        open_conns++;
        st.accepted++;
    }
}

static void close_slot(size_t idx) {
    struct slot *s = &slots[idx];
    struct epoll_event ev = {0};
    epoll_ctl(ep, EPOLL_CTL_DEL, s->fd, &ev);
    st.ctls++;
    close(s->fd);
    st.closes++;
    s->fd = -1;
    s->gen++;
    free(s->pending);
    s->pending = NULL;
    s->plen = s->pcap = s->sent = 0;
    s->read_paused = false;
    s->peer_eof = false;
    s->read_closed = false;
    push_free(idx);
    open_conns--;
    if (accept_paused) retry_accept = true;
}

static void queue(struct slot *s, const uint8_t *p, size_t n) {
    // Drop the sent prefix once it is most of the queue (see server.mojo).
    if (s->sent >= 4096 && 2 * s->sent >= s->plen) {
        memmove(s->pending, s->pending + s->sent, s->plen - s->sent);
        s->plen -= s->sent;
        s->sent = 0;
    }
    if (s->plen + n > s->pcap) {
        size_t c = s->pcap ? s->pcap : 4096;
        while (c < s->plen + n) c *= 2;
        s->pending = xrealloc(s->pending, c);
        s->pcap = c;
    }
    memcpy(s->pending + s->plen, p, n);
    s->plen += n;
}

// Returns false if the connection was closed.
static bool echo(size_t idx, size_t n) {
    struct slot *s = &slots[idx];
    if (s->plen > s->sent) {
        queue(s, buf, n);
        return true;
    }
    size_t off = 0;
    while (off < n) {
        ssize_t r = send(s->fd, buf + off, n - off, MSG_NOSIGNAL);
        st.sends++;
        if (r < 0) {
            if (errno == EINTR) { st.eintr++; continue; }
            if (errno == EAGAIN) { st.send_eagain++; break; }
            st.resets++;
            close_slot(idx);
            return false;
        }
        st.bytes_out += r;
        off += (size_t)r;
        if (off < n) st.send_partial++;
    }
    if (off < n) {
        s->plen = s->sent = 0;
        queue(s, buf + off, n - off);
    }
    return true;
}

static void on_readable(size_t idx) {
    for (;;) {
        struct slot *s = &slots[idx];
        if (s->plen - s->sent >= PENDING_CAP) {
            if (!s->read_paused) { s->read_paused = true; st.pauses++; }
            return;
        }
        ssize_t r = recv(s->fd, buf, READ_BUF, 0);
        st.recvs++;
        if (r < 0) {
            if (errno == EAGAIN) { st.recv_eagain++; return; }
            if (errno == EINTR) { st.eintr++; continue; }
            st.resets++;
            close_slot(idx);
            return;
        }
        if (r == 0) { // orderly EOF (the peer may still be reading)
            if (s->plen > s->sent) s->peer_eof = true;
            else close_slot(idx);
            return;
        }
        st.bytes_in += r;
        if (!echo(idx, (size_t)r)) return;
        if (r < READ_BUF && !strict_eagain && !s->read_closed) return;
    }
}

static bool flush_slot(size_t idx) {
    struct slot *s = &slots[idx];
    while (s->sent < s->plen) {
        ssize_t r = send(s->fd, s->pending + s->sent, s->plen - s->sent,
                         MSG_NOSIGNAL);
        st.sends++;
        if (r < 0) {
            if (errno == EINTR) { st.eintr++; continue; }
            if (errno == EAGAIN) { st.send_eagain++; return true; }
            st.resets++;
            close_slot(idx);
            return false;
        }
        st.bytes_out += r;
        s->sent += (size_t)r;
    }
    free(s->pending);
    s->pending = NULL;
    s->plen = s->pcap = s->sent = 0;
    if (s->peer_eof) {
        close_slot(idx);
        return false;
    }
    if (s->read_paused) {
        s->read_paused = false;
        on_readable(idx);
    }
    return slots[idx].fd >= 0;
}

static void on_event(size_t idx, uint32_t ev) {
    if (ev & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) slots[idx].read_closed = true;
    if ((ev & EPOLLOUT) && slots[idx].plen > 0) {
        if (!flush_slot(idx)) return;
    }
    if ((ev & READABLE) && !slots[idx].read_paused && !slots[idx].peer_eof)
        on_readable(idx);
}

static void print_stats(const char *tag, long now) {
    long sys = st.waits + st.accept_calls + st.recvs + st.sends + st.ctls +
               st.setsockopts + st.closes + st.clock_reads;
    printf("%s mono_ns=%ld open=%ld slots=%zu accepted=%ld closes=%ld "
           "waits=%ld events=%ld recvs=%ld recv_eagain=%ld sends=%ld "
           "send_eagain=%ld send_partial=%ld accept_calls=%ld "
           "accept_exhausted=%ld ctls=%ld setsockopts=%ld clock_reads=%ld "
           "syscalls=%ld eintr=%ld stale=%ld resets=%ld pauses=%ld "
           "bytes_in=%ld bytes_out=%ld\n",
           tag, now, open_conns, nslots, st.accepted, st.closes, st.waits,
           st.events, st.recvs, st.recv_eagain, st.sends, st.send_eagain,
           st.send_partial, st.accept_calls, st.accept_exhausted, st.ctls,
           st.setsockopts, st.clock_reads, sys, st.eintr, st.stale,
           st.resets, st.pauses, st.bytes_in, st.bytes_out);
    fflush(stdout);
}

static const char *arg(int argc, char **argv, const char *name) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], name) == 0) return i + 1 < argc ? argv[i + 1] : "";
    return NULL;
}

int main(int argc, char **argv) {
    static const char *valued[] = {"--host", "--port", "--duration",
                                   "--nofile", "--max-events", "--stats-ms",
                                   "--backlog", NULL};
    for (int i = 1; i < argc; i++) {
        bool ok = !strcmp(argv[i], "--strict-eagain") ||
                  !strcmp(argv[i], "--quiet");
        for (const char **v = valued; !ok && *v; v++)
            if (!strcmp(argv[i], *v)) {
                if (i + 1 >= argc) { fprintf(stderr, "missing value for %s\n", argv[i]); return 2; }
                ok = true;
                i++;
            }
        if (!ok) { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
    }
    const char *a;
    const char *host = (a = arg(argc, argv, "--host")) ? a : "127.0.0.1";
    int port = (a = arg(argc, argv, "--port")) ? atoi(a) : 0;
    long duration_s = (a = arg(argc, argv, "--duration")) ? atol(a) : 0;
    long nofile = (a = arg(argc, argv, "--nofile")) ? atol(a) : 0;
    int max_events = (a = arg(argc, argv, "--max-events")) ? atoi(a) : 1024;
    long stats_ms = (a = arg(argc, argv, "--stats-ms")) ? atol(a) : 1000;
    int backlog = (a = arg(argc, argv, "--backlog")) ? atoi(a) : 4096;
    bool quiet = arg(argc, argv, "--quiet") != NULL;
    strict_eagain = arg(argc, argv, "--strict-eagain") != NULL;
    if (port < 0 || port > 65535 || max_events < 1 || stats_ms < 1) {
        fprintf(stderr, "bad arguments\n");
        return 2;
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) die("getrlimit");
    rl.rlim_cur = nofile > 0 ? (rlim_t)nofile : rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) die("setrlimit");

    lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (lfd < 0) die("socket");
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { fprintf(stderr, "bad --host\n"); return 2; }
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0) die("bind");
    if (listen(lfd, backlog) < 0) die("listen");
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) die("epoll_create1");
    struct epoll_event lev = {.events = EPOLLIN | EPOLLET, .data.u64 = LISTENER_TOKEN};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &lev) < 0) die("epoll_ctl(listener)");

    printf("LISTEN %s:%d pid=%d nofile_soft=%lu nofile_hard=%lu strict_eagain=%s slot_bytes=%zu\n",
           host, ntohs(sa.sin_port), getpid(), (unsigned long)rl.rlim_cur,
           (unsigned long)rl.rlim_max, strict_eagain ? "True" : "False",
           sizeof(struct slot));
    fflush(stdout);

    struct epoll_event *events = malloc((size_t)max_events * sizeof *events);
    if (!events) die("malloc");
    long tick_ns = stats_ms * 1000000L;
    long start = now_ns();
    long next_tick = start + tick_ns;
    long iter = 0;
    for (;;) {
        int n = epoll_wait(ep, events, max_events, (int)stats_ms);
        st.waits++;
        if (n < 0) {
            if (errno == EINTR) { st.eintr++; n = 0; }
            else die("epoll_wait");
        }
        st.events += n;
        for (int i = 0; i < n; i++) {
            uint64_t d = events[i].data.u64;
            if (d == LISTENER_TOKEN) { accept_all(); continue; }
            size_t idx = (size_t)(d & 0xFFFFFFFFu);
            if (idx >= nslots || slots[idx].gen != (uint32_t)(d >> 32) ||
                slots[idx].fd < 0) {
                st.stale++;
                continue;
            }
            on_event(idx, events[i].events);
        }
        if (retry_accept) { retry_accept = false; accept_all(); }
        iter++;
        if (n == 0 || iter % CLOCK_EVERY == 0) {
            long now = now_ns();
            if (now >= next_tick) {
                next_tick = now + tick_ns;
                if (accept_paused) accept_all();
                if (!quiet) print_stats("STATS", now);
            }
            if (duration_s > 0 && now - start >= duration_s * 1000000000L) {
                print_stats("FINAL", now);
                return 0;
            }
        }
    }
}
