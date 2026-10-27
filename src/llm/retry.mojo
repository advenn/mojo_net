"""When to send a call again, as the official OpenAI and Anthropic SDKs do:
on 408, 409, 429 and 5xx answers, and on connection failures and
timeouts, at most `max_retries` times (2 by default). The wait is the
server's `retry-after-ms` or `Retry-After` when it gives one above zero
and at most `max_retry_after` (60 s), and otherwise 0.5 s doubling per
retry up to 8 s, less a random quarter (jitter). `x-should-retry: true`
or `false` overrides the status. Sans-I/O: the caller passes the time and the
jitter, so tests can fix them."""

from http.headers import Headers
from http.retry import retry_after
from linux import ErrorKind, IoError
from linux.time import Duration


@fieldwise_init
struct RetryPolicy(Copyable, TrivialRegisterPassable):
    var max_retries: Int
    var initial: Duration
    var max_delay: Duration
    var max_retry_after: Duration
    """A server's wait longer than this is not taken (the backoff is used,
    as the SDKs do)."""

    def __init__(out self):
        self.max_retries = 2
        self.initial = Duration.from_millis(500)
        self.max_delay = Duration.from_secs(8)
        self.max_retry_after = Duration.from_secs(60)

    @staticmethod
    def none() -> RetryPolicy:
        """Never send again."""
        var p = RetryPolicy()
        p.max_retries = 0
        return p


def retryable_status(status: Int, headers: Headers) -> Bool:
    var should = headers.get("x-should-retry")
    if should:
        var v = String(should.value())
        if v == "true":
            return True
        if v == "false":
            return False
    return status == 408 or status == 409 or status == 429 or status >= 500


def retryable_io(e: IoError) -> Bool:
    """Failures a new attempt may not meet: timeouts and lost or refused
    connections. Not a refused certificate, bad input or a broken
    protocol."""
    var k = e.kind
    return (
        k == ErrorKind.TimedOut
        or k == ErrorKind.ConnectionRefused
        or k == ErrorKind.ConnectionReset
        or k == ErrorKind.ConnectionAborted
        or k == ErrorKind.BrokenPipe
        or k == ErrorKind.NotConnected
        or k == ErrorKind.UnexpectedEof
        or k == ErrorKind.NetworkUnreachable
        or k == ErrorKind.HostUnreachable
        or k == ErrorKind.NetworkDown
    )


def backoff(policy: RetryPolicy, retry: Int, jitter: Float64) -> Duration:
    """The wait before retry number `retry` (0 for the first), `jitter` in
    [0, 1): min(initial * 2^retry, max_delay) * (1 - jitter / 4)."""
    var d = policy.initial
    for _ in range(retry):
        if not (d < policy.max_delay):
            break
        d = d * 2
    if policy.max_delay < d:
        d = policy.max_delay
    var ns = Float64(d.as_nanos()) * (1.0 - 0.25 * jitter)
    return Duration.from_nanos(Int(ns))


def wait_before_retry(policy: RetryPolicy, retry: Int, headers: Headers, now_unix: Int, jitter: Float64) -> Duration:
    """The server's wait when it gave one within `max_retry_after`, else
    the backoff."""
    var asked = retry_after(headers, now_unix)
    if asked and Duration.ZERO < asked.value() and not (policy.max_retry_after < asked.value()):
        return asked.value()
    return backoff(policy, retry, jitter)


struct Jitter(Movable):
    """Numbers in [0, 1) for spreading retries (splitmix64 from a seed),
    not for anything secret."""

    var _s: UInt64

    def __init__(out self, seed: UInt64):
        self._s = seed

    def next(mut self) -> Float64:
        self._s += 0x9E3779B97F4A7C15
        var z = self._s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        z ^= z >> 31
        return Float64(z >> 11) / Float64(UInt64(1) << 53)
