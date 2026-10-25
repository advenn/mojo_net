"""HTTP basics (RFC 9110): methods, protocol versions and status codes.

Methods are case-sensitive tokens, kept as strings; the standard ones are
named here. Status codes are three-digit integers (100..599); `reason`
gives the registered phrase. This module does no I/O.
"""

from linux import ErrorKind, IoError

comptime GET = "GET"
comptime HEAD = "HEAD"
comptime POST = "POST"
comptime PUT = "PUT"
comptime DELETE = "DELETE"
comptime CONNECT = "CONNECT"
comptime OPTIONS = "OPTIONS"
comptime TRACE = "TRACE"
comptime PATCH = "PATCH"


@fieldwise_init
struct Version(Equatable, TrivialRegisterPassable, Writable):
    """An HTTP version as on the wire: `HTTP/<major>.<minor>`."""

    var major: Int
    var minor: Int

    comptime HTTP_1_0 = Version(1, 0)
    comptime HTTP_1_1 = Version(1, 1)

    @inline(.always)
    def __eq__(self, other: Self) -> Bool:
        return self.major == other.major and self.minor == other.minor

    @inline(.always)
    def at_least_1_1(self) -> Bool:
        """HTTP/1.1 or later (persistent connections by default, chunked
        encoding, Host required)."""
        return self.major > 1 or (self.major == 1 and self.minor >= 1)

    def write_to(self, mut writer: Some[Writer]):
        writer.write("HTTP/", self.major, ".", self.minor)


@inline(.always)
def is_informational(status: Int) -> Bool:
    return status >= 100 and status < 200


@inline(.always)
def is_success(status: Int) -> Bool:
    return status >= 200 and status < 300


@inline(.always)
def is_redirect(status: Int) -> Bool:
    return status >= 300 and status < 400


@inline(.always)
def is_client_error(status: Int) -> Bool:
    return status >= 400 and status < 500


@inline(.always)
def is_server_error(status: Int) -> Bool:
    """5xx, and the invalid codes 600..999 a response may carry, which a
    client treats as 5xx (RFC 9110 15)."""
    return status >= 500 and status < 1000


def check_status(status: Int, op: StaticString) raises IoError:
    """`InvalidInput` unless `100 <= status <= 599` (RFC 9110 15)."""
    if status < 100 or status > 599:
        raise IoError.of_kind(op, ErrorKind.InvalidInput)


def reason(status: Int) -> StaticString:
    """The reason phrase the IANA status code registry gives `status`
    (RFC 9110 15 and the RFCs registered since), or "" for an unregistered
    code. 418 is reserved, not "I'm a teapot" (RFC 9110 15.5.19). A reason
    phrase carries no meaning: clients must not rely on it."""
    if status < 300:
        if status == 100:
            return "Continue"
        if status == 101:
            return "Switching Protocols"
        if status == 102:
            return "Processing"
        if status == 103:
            return "Early Hints"
        if status == 200:
            return "OK"
        if status == 201:
            return "Created"
        if status == 202:
            return "Accepted"
        if status == 203:
            return "Non-Authoritative Information"
        if status == 204:
            return "No Content"
        if status == 205:
            return "Reset Content"
        if status == 206:
            return "Partial Content"
        if status == 207:
            return "Multi-Status"
        if status == 208:
            return "Already Reported"
        if status == 226:
            return "IM Used"
        return ""
    if status < 400:
        if status == 300:
            return "Multiple Choices"
        if status == 301:
            return "Moved Permanently"
        if status == 302:
            return "Found"
        if status == 303:
            return "See Other"
        if status == 304:
            return "Not Modified"
        if status == 305:
            return "Use Proxy"
        if status == 307:
            return "Temporary Redirect"
        if status == 308:
            return "Permanent Redirect"
        return ""
    if status < 500:
        if status == 400:
            return "Bad Request"
        if status == 401:
            return "Unauthorized"
        if status == 402:
            return "Payment Required"
        if status == 403:
            return "Forbidden"
        if status == 404:
            return "Not Found"
        if status == 405:
            return "Method Not Allowed"
        if status == 406:
            return "Not Acceptable"
        if status == 407:
            return "Proxy Authentication Required"
        if status == 408:
            return "Request Timeout"
        if status == 409:
            return "Conflict"
        if status == 410:
            return "Gone"
        if status == 411:
            return "Length Required"
        if status == 412:
            return "Precondition Failed"
        if status == 413:
            return "Content Too Large"
        if status == 414:
            return "URI Too Long"
        if status == 415:
            return "Unsupported Media Type"
        if status == 416:
            return "Range Not Satisfiable"
        if status == 417:
            return "Expectation Failed"
        if status == 421:
            return "Misdirected Request"
        if status == 422:
            return "Unprocessable Content"
        if status == 423:
            return "Locked"
        if status == 424:
            return "Failed Dependency"
        if status == 425:
            return "Too Early"
        if status == 426:
            return "Upgrade Required"
        if status == 428:
            return "Precondition Required"
        if status == 429:
            return "Too Many Requests"
        if status == 431:
            return "Request Header Fields Too Large"
        if status == 451:
            return "Unavailable For Legal Reasons"
        return ""
    if status == 500:
        return "Internal Server Error"
    if status == 501:
        return "Not Implemented"
    if status == 502:
        return "Bad Gateway"
    if status == 503:
        return "Service Unavailable"
    if status == 504:
        return "Gateway Timeout"
    if status == 505:
        return "HTTP Version Not Supported"
    if status == 506:
        return "Variant Also Negotiates"
    if status == 507:
        return "Insufficient Storage"
    if status == 508:
        return "Loop Detected"
    if status == 510:
        return "Not Extended"
    if status == 511:
        return "Network Authentication Required"
    return ""
