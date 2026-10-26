"""T0 spike: which ELF version node each OpenSSL function bound by the spike
comes from, and a failure if any is newer than OPENSSL_3.5.0 (rule TL2 of
docs/research/tls_with_openssl.md). Test-only Python.

    python spikes/tls/symver.py <lib dir> <mojo files...>
"""

import re
import subprocess
import sys

FLOOR = (3, 5, 0)


def nodes(path):
    """{symbol: version node} for the defined dynamic symbols of `path`."""
    out = subprocess.run(["readelf", "--dyn-syms", "--wide", path], check=True, capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[6] == "UND":
            continue
        name = parts[7]
        if "@" in name:
            sym, _, node = name.partition("@")
            found[sym] = node.lstrip("@")
    return found


def version(node):
    m = re.fullmatch(r"OPENSSL_(\d+)\.(\d+)\.(\d+)[a-z]?", node)
    return tuple(int(x) for x in m.groups()) if m else None


def main():
    libdir, files = sys.argv[1], sys.argv[2:]
    table = {**nodes(f"{libdir}/libcrypto.so.3"), **nodes(f"{libdir}/libssl.so.3")}
    bound = set()
    for f in files:
        bound |= set(re.findall(r'sym\[[^\]]*\]\(\s*"(\w+)"', open(f).read()))
    bound |= {"SSL_get_wbio", "SSL_get_rbio"}  # (called through a name variable)
    bad = 0
    for name in sorted(bound):
        node = table.get(name)
        v = version(node) if node else None
        ok = v is not None and v <= FLOOR
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name:40} {node}")
    print(f"{len(bound)} symbols, {bad} outside OPENSSL_3.5.0 or older")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
