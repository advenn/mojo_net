#!/usr/bin/env bash
# Gate TG8 (docs/tls.md, "Checks"): the tls tests, built with
# AddressSanitizer, against an OpenSSL built with AddressSanitizer from
# source. Plain ASan (tools/check_tls_asan.sh) sees a misuse of our memory
# inside libssl only through the memcpy calls it intercepts; here every
# load and store libssl and libcrypto make is checked, so a buffer or an
# out-parameter freed before OpenSSL is done with it fails the run.
#
# How the instrumented library is loaded, without any switch in src/:
# tls.ffi opens libssl.so.3 from the directory the Mojo runtime library was
# mapped from. The script builds a directory holding a copy of that runtime
# library, the instrumented libssl and libcrypto, and links to the rest of
# the environment's libraries, and puts it first on LD_LIBRARY_PATH (the
# test binaries use RUNPATH, which LD_LIBRARY_PATH precedes). The Python
# peers keep the environment's OpenSSL: their _ssl module uses RPATH.
#
#   pixi run tls-asan-openssl              the gate
#   pixi run tls-asan-openssl --self-test  a planted bug it must catch
#
# The OpenSSL source is downloaded once (the version pinned below, checked
# against its SHA-256) and built under build/openssl-asan/ (about 1.5 min
# with 6 cores). The version must be the environment's: update the pin
# when pixi.lock moves.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=3.5.9
SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
URL="https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"

env_lib="${CONDA_PREFIX:?run through pixi}/lib"
have=$("$CONDA_PREFIX/bin/openssl" version | awk '{print $2}')
if [[ "$have" != "$VERSION" ]]; then
  echo "FAIL the environment has OpenSSL $have, this gate is pinned to $VERSION: update VERSION and SHA256 in $0"
  exit 1
fi

top=build/openssl-asan
src="$top/openssl-$VERSION"
prefix="$top/prefix-$VERSION"
rt="$top/rt-$VERSION"
mkdir -p "$top"

if [[ ! -f "$prefix/lib/libssl.so.3" ]]; then
  tarball="$top/openssl-$VERSION.tar.gz"
  if [[ ! -f "$tarball" ]]; then
    curl -sSfL -o "$tarball.part" "$URL"
    mv "$tarball.part" "$tarball"
  fi
  echo "$SHA256  $tarball" | sha256sum -c --quiet - || { echo "FAIL $tarball does not match its pinned SHA-256"; rm -f "$tarball"; exit 1; }
  rm -rf "$src"
  tar xzf "$tarball" -C "$top"
  abs_prefix="$(pwd)/$prefix"
  (cd "$src" && ./Configure linux-$(uname -m) enable-asan shared no-tests no-docs -g -O1 -fno-omit-frame-pointer \
      --prefix="$abs_prefix" --libdir=lib --openssldir="$abs_prefix/ssl" >"../configure.log" 2>&1 \
    && make -j"$(nproc)" >"../make.log" 2>&1 && make install_sw >"../install.log" 2>&1) \
    || { echo "FAIL building OpenSSL $VERSION with ASan (logs in $top)"; exit 1; }
fi
syms=$(nm -D "$prefix/lib/libssl.so.3")
[[ "$syms" == *__asan_init* ]] || { echo "FAIL $prefix/lib/libssl.so.3 is not instrumented"; exit 1; }

# The runtime directory: the Mojo runtime library copied (its mapped path
# decides where tls.ffi looks), the instrumented libraries, links to the rest.
rm -rf "$rt"
mkdir -p "$rt"
for f in "$env_lib"/*.so*; do
  case "$(basename "$f")" in
    libssl.so*|libcrypto.so*|libKGENCompilerRTShared.so) ;;
    *) ln -s "$f" "$rt/$(basename "$f")" ;;
  esac
done
cp "$env_lib/libKGENCompilerRTShared.so" "$rt/"
cp "$prefix/lib/libssl.so.3" "$prefix/lib/libcrypto.so.3" "$rt/"
rt="$(cd "$rt" && pwd)"

if [[ "${1:-}" == "--self-test" ]]; then
  # A size_t out-parameter freed before SSL_write_ex writes it: libssl
  # stores to it directly, without a memcpy, so only this gate sees it.
  plant="$top/selftest"
  rm -rf "$plant"
  mkdir -p "$plant"
  cp -r src "$plant/src"
  python3 - "$plant/src/tls/engine.mojo" <<'PY'
import sys
p = sys.argv[1]
t = open(p).read()
old = "            var rc = L.SSL_write_ex(self._ssl, in_buf(data[taken : taken + n]), n, size_out(done)) if forced == 0 else c_int(0)"
new = """            var w = unsafe_alloc[Int](1)
            w.unsafe_free()  # (planted)
            var rc = L.SSL_write_ex(self._ssl, in_buf(data[taken : taken + n]), n, w.unsafe_origin_cast[MutAnyOrigin]()) if forced == 0 else c_int(0)
            done[0] = n"""
assert t.count(old) == 1, "the planted bug's anchor moved: update the self-test"
t = t.replace(old, new).replace("from bytes.buffer import ByteBuffer\n", "from bytes.buffer import ByteBuffer\nfrom std.memory.alloc import unsafe_alloc\n", 1)
open(p, "w").write(t)
PY
  mojo build --sanitize address -I "$plant/src" -I tests/tls tests/tls/test_client.mojo -o "$plant/client" >"$plant/build.log" 2>&1 \
    || { echo "FAIL the self-test's planted build"; tail -5 "$plant/build.log"; exit 1; }
  set +e
  LD_LIBRARY_PATH="$rt" ASAN_OPTIONS=detect_leaks=0 timeout 600 "$plant/client" --only test_dns_name_tls13 </dev/null >"$plant/run.log" 2>&1
  set -e
  if grep -q "ERROR: AddressSanitizer: heap-use-after-free" "$plant/run.log" && grep -q "ssl3_write_bytes" "$plant/run.log"; then
    echo "ok   self-test: the freed out-parameter is caught inside libssl"
    exit 0
  fi
  echo "FAIL self-test: the planted use-after-free was not caught"; tail -20 "$plant/run.log"
  exit 1
fi

TLS_ASAN_LIBDIR="$rt" bash tools/check_tls_asan.sh
