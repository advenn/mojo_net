"""Fetch URLs and print each response: status line, header fields, body.

    pixi run mojo run -I src examples/http/http_get.mojo URL [URL...]

`http://` and `https://` (certificates checked against the system's CA
bundle: docs/tls.md). Host names resolve without libc, and URLs on the same
scheme, host and port reuse one kept-alive connection.
"""

from std.sys import argv, exit, stderr

from http.client import Client


def main() raises:
    var args = argv()
    if len(args) < 2:
        print("usage: http_get URL [URL...]", file=stderr)
        exit(2)
        return
    var client = Client()
    for i in range(1, len(args)):
        var r = client.get(String(args[i]))
        print(r.version, r.status, r.reason)
        for k in range(len(r.headers)):
            print(r.headers.name(k), ": ", r.headers.value(k), sep="")
        print()
        print(r.text())
