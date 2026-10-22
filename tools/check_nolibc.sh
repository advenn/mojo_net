#!/usr/bin/env bash
# Enforce "no libc on the I/O path": build binaries that exercise the library
# and fail if any socket/poll/epoll/io_uring libc symbol is imported. (The Mojo
# runtime itself links libc; we only forbid the I/O entry points.)
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/nolibc
FORBIDDEN='^(socket|socketpair|bind|listen|accept|accept4|connect|send|sendto|sendmsg|sendmmsg|recv|recvfrom|recvmsg|recvmmsg|setsockopt|getsockopt|getsockname|getpeername|shutdown|poll|ppoll|select|pselect|epoll_create|epoll_create1|epoll_ctl|epoll_wait|epoll_pwait|epoll_pwait2|eventfd|io_uring_.*|getaddrinfo|gethostbyname|sendfile|splice|readv|writev|fcntl|ioctl|syscall)(@.*)?$'
status=0
for f in "$@"; do
  exe="build/nolibc/$(basename "${f%.mojo}")"
  mojo build -I src -o "$exe" "$f"
  bad=$(nm -D --undefined-only "$exe" | awk '{print $NF}' | grep -E "$FORBIDDEN" || true)
  if [[ -n "$bad" ]]; then
    echo "FAIL $f imports libc I/O symbols:"; echo "$bad"; status=1
  else
    echo "ok   $f"
  fi
done
exit $status
