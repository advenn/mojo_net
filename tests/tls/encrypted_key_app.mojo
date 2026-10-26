"""Builds a server context from an encrypted key and prints the outcome,
for tests/tls/test_server_config.mojo, which runs it on a pseudo-terminal
of its own: libssl's default password callback would prompt there and
wait, and `tls` must refuse the key instead."""

from std.sys import argv

from tls import ServerConfig


def main():
    var args = argv()
    try:
        _ = ServerConfig(certificate=String(args[1]), key=String(args[2]), names=["localhost"]).build()
        print("BUILT")
    except e:
        print("REFUSED", e.category, e)
