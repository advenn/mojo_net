"""Builds a client context and prints the outcome, for
tests/tls/test_tls_regressions.mojo, which runs it with another
libcrypto.so.3 preloaded (LD_PRELOAD): `tls` must refuse to run on it."""

from tls import ClientConfig


def main():
    try:
        _ = ClientConfig().build()
        print("BUILT")
    except e:
        print("REFUSED", e.category, e)
