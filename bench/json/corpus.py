"""The JSON benchmark corpus: the files every JSON library measures itself
on (nativejson-benchmark's canada, citm_catalog and twitter; orjson's
github; simdjson's recipe_book), fetched once at pinned commits and
checked by SHA-256, beside the AI-shaped payloads of payloads.py.

    python3 bench/json/corpus.py <dir>   fetch what is missing, check all
"""

import hashlib
import lzma
import os
import sys
import urllib.request

_NATIVE = "https://raw.githubusercontent.com/miloyip/nativejson-benchmark/478d5727c2a4048e835a29c65adecc7d795360d5/data/"
_ORJSON = "https://raw.githubusercontent.com/ijl/orjson/bd00937c5c46ab20eb5d7fe1cfc034b906c4578f/data/"
_SIMDJSON = "https://raw.githubusercontent.com/simdjson/simdjson/3b679b101ac0ad29a135eaddda718307b2a95a1f/jsonexamples/"

FILES = {
    # name: (url, sha256 of the JSON text)
    "canada": (_NATIVE + "canada.json", "f83b3b354030d5dd58740c68ac4fecef64cb730a0d12a90362a7f23077f50d78"),
    "citm_catalog": (_NATIVE + "citm_catalog.json", "a73e7a883f6ea8de113dff59702975e60119b4b58d451d518a929f31c92e2059"),
    "twitter": (_SIMDJSON + "twitter.json", "30721e496a8d73cfc50658923c34eb2c0fbe15ee6835005e43ee624d8dedf200"),
    "github": (_ORJSON + "github.json.xz", "275e688d9081f1528483eccc7d87290957a67768d4413817e30e092a68cb2124"),
    "recipe_book": (_SIMDJSON + "recipe_book.json", "9f8a7781ba9c61f3760fbb12d69f994bbe89e48413041aba0e476edee5f5c9df"),
}


def fetch(out):
    os.makedirs(out, exist_ok=True)
    for name, (url, digest) in FILES.items():
        path = os.path.join(out, name + ".json")
        if not os.path.exists(path):
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read()
            if url.endswith(".xz"):
                data = lzma.decompress(data)
            with open(path + ".part", "wb") as f:
                f.write(data)
            os.replace(path + ".part", path)
        with open(path, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != digest:
            sys.exit("corpus: %s has SHA-256 %s, not %s" % (path, got, digest))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    fetch(sys.argv[1])
