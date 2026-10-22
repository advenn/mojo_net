// Why a Mojo server stalls in accept4 at fd 64, 128, ..., 8192
// (docs/spikes.md, 10k-connection epoll spike).
//
// The kernel fd table doubles when an fd number reaches its size. In a
// process with more than one thread (shared files_struct), expand_fdtable()
// in fs/file.c calls synchronize_rcu() first: the syscall that allocates the
// fd waits for an RCU grace period. Every Mojo process has runtime worker
// threads, so this hits Mojo servers and not the single-threaded C baseline.
// This program times dup3() onto each power-of-two fd, with 1 and 2 threads.
//
//   gcc -O2 -pthread -o spikes/epoll_echo/out/fdtable_grow spikes/epoll_echo/fdtable_grow.c
//   spikes/epoll_echo/out/fdtable_grow; spikes/epoll_echo/out/fdtable_grow threads

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static void *idle(void *a) {
    (void)a;
    pause();
    return 0;
}

static long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

int main(int argc, char **argv) {
    (void)argv;
    pthread_t t;
    if (argc > 1) pthread_create(&t, 0, idle, 0);
    printf("%s:", argc > 1 ? "2 threads" : "1 thread");
    for (int fd = 64; fd <= 16384; fd *= 2) {
        long t0 = now_ns();
        if (dup3(0, fd, O_CLOEXEC) < 0) { perror("dup3"); return 1; }
        printf(" fd %d %ld us;", fd, (now_ns() - t0) / 1000);
        close(fd);
    }
    printf("\n");
    return 0;
}
