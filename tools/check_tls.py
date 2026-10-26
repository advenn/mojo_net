#!/usr/bin/env python3
"""Checks on the `tls` package's use of OpenSSL (docs/tls.md, "Checks";
rules TL2, TL5, TL7 and TB14 of docs/research/tls_with_openssl.md).

1. FFI stays in one module (TL7, TB16): `OwnedDLHandle`, `DLHandle`,
   `external_call`, `get_symbol`, `dlopen`, `dlsym` and `abi("C")` appear
   in code under src/ only in src/tls/ffi.mojo.
2. The binding table is an allowlist (TL5): every OpenSSL function
   src/tls/ffi.mojo binds is listed in BINDINGS below, so binding a new one
   is a reviewed change to this file. Every binding names its function as
   a literal (`_sym[F](self._handle, "name")`), so none escapes the list,
   and `get_symbol` is called only inside `_sym`.
3. No dangerous API by name (TL5): code in src/tls names none of FORBIDDEN
   (APIs with a CVE history, and features this package never enables).
4. Symbol versions (TL2): each bound function's ELF version node in the
   environment's libssl.so.3 / libcrypto.so.3 is OPENSSL_3.5.0 or older, so
   the package runs on any OpenSSL 3.5 or later 3.x.
5. Constants (TB14): src/tls/consts.mojo matches the headers
   (tools/gen_tls_consts.py --check).
6. A built context is read-only (TB3): no public function in src/tls
   outside ffi.mojo returns an OpenSSL handle (`Obj`) or the `Library`.
7. The package needs OpenSSL 3.5.9 or later (TL1): conda.recipe/recipe.yaml
   says `openssl >=3.5.9`.

    python3 tools/check_tls.py [--root DIR]

Docstrings and comments are skipped (prose may name anything). A built-in
self-test plants a violation of each of 1-3 first and fails if any goes
unreported. Exits 1 on any violation.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

FFI_MODULE = os.path.join("src", "tls", "ffi.mojo")
FFI_TOKENS = ("OwnedDLHandle", "DLHandle", "external_call", "get_symbol", "dlopen", "dlsym")
FFI_LITERALS = ('abi("C")',)
RECIPE = os.path.join("conda.recipe", "recipe.yaml")

BINDINGS = {
    # library, errors, memory
    "OpenSSL_version_num", "OpenSSL_version", "OPENSSL_init_ssl", "OSSL_LIB_CTX_new", "OSSL_LIB_CTX_free",
    "OSSL_PROVIDER_load", "OSSL_PROVIDER_unload", "ERR_clear_error", "ERR_get_error", "ERR_peek_error",
    "ERR_error_string_n", "OPENSSL_cleanse", "OPENSSL_sk_num", "OPENSSL_sk_value", "X509_OBJECT_get_type",
    # certificates and verification
    "X509_verify_cert_error_string", "X509_get_default_cert_file", "X509_STORE_get0_objects",
    "X509_VERIFY_PARAM_set_flags", "X509_VERIFY_PARAM_clear_flags", "X509_VERIFY_PARAM_get_flags",
    "X509_VERIFY_PARAM_set_hostflags", "X509_VERIFY_PARAM_get_hostflags", "X509_VERIFY_PARAM_set1_host",
    "X509_VERIFY_PARAM_set1_ip", "X509_check_host", "X509_check_ip",
    # memory BIOs
    "BIO_s_mem", "BIO_new", "BIO_write_ex", "BIO_read_ex", "BIO_ctrl", "BIO_ctrl_pending",
    # contexts
    "TLS_client_method", "SSL_CTX_new_ex", "SSL_CTX_free", "SSL_CTX_ctrl", "SSL_CTX_set_options",
    "SSL_CTX_clear_options", "SSL_CTX_get_options", "SSL_CTX_set_security_level", "SSL_CTX_get_security_level",
    "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites", "SSL_CTX_set_verify", "SSL_CTX_get_verify_mode",
    "SSL_CTX_get0_param", "SSL_CTX_get_cert_store", "SSL_CTX_load_verify_file", "SSL_CTX_load_verify_dir",
    "SSL_CTX_set_alpn_protos",
    # connections
    "SSL_new", "SSL_free", "SSL_set0_rbio", "SSL_set0_wbio", "SSL_set_connect_state", "SSL_ctrl",
    "SSL_get0_param", "SSL_do_handshake", "SSL_get_error", "SSL_read_ex", "SSL_write_ex", "SSL_shutdown",
    "SSL_get_verify_result", "SSL_get0_peer_certificate", "SSL_get0_peername", "SSL_version",
    "SSL_get_version", "SSL_get_current_cipher", "SSL_CIPHER_get_name", "SSL_get0_group_name",
    "SSL_get0_alpn_selected", "SSL_session_reused",
}

# Substrings no code in src/tls may contain (case-sensitive).
FORBIDDEN = (
    "SSL_set_SSL_CTX",  # CVE-2026-72897
    "SSL_select_next_proto",  # CVE-2024-5535
    "SSL_free_buffers",  # CVE-2024-4741
    "SSL_check_chain",  # CVE-2020-1967
    "next_proto",  # NPN
    "early_data",  # 0-RTT
    "psk", "PSK", "SRP", "srp_",
    "keylog",  # key logging
    "passwd_cb",
    "OCSP", "ocsp", "dane", "DANE", "tlsext_status",
    "client_cert_type", "server_cert_type",  # raw public keys
    "SSL_VERIFY_NONE", "verify_callback", "cert_verify_callback",
    "X509_V_FLAG_CRL_CHECK", "X509_V_FLAG_POLICY_CHECK", "X509_V_FLAG_EXPLICIT_POLICY",
    "X509_V_FLAG_ALLOW_PROXY_CERTS", "X509_V_FLAG_NO_CHECK_TIME",
    "LEGACY_SERVER_CONNECT", "UNSAFE_LEGACY_RENEGOTIATION", "CLIENT_RENEGOTIATION", "SSL_OP_ALL",
    "IGNORE_UNEXPECTED_EOF",  # (it hides truncation)
    "ENABLE_KTLS",
    "SSL_MODE_ENABLE_PARTIAL_WRITE", "SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER",
    "SSL_set_verify", "SSL_set_security_level", "SSL_set_cipher_list", "SSL_set_options",
    "legacy",  # the legacy provider
    "_get1_peer",  # (each get1 needs a free; the package uses get0)
    # TL6: libssl talks only to memory BIOs
    "SSL_set_fd", "SSL_set_rfd", "SSL_set_wfd", "BIO_s_socket", "BIO_new_socket", "BIO_s_connect",
    "BIO_new_connect", "BIO_s_accept", "BIO_new_accept", "BIO_s_fd", "BIO_new_fd",
    # TB1: the BIOs belong to the SSL (set0), never freed or shared here
    "SSL_set_bio", "BIO_free", "BIO_up_ref",
    # TC16: no resumption
    "SSL_set_session", "sess_set_new_cb",
    # TC1: trust is loaded explicitly and counted
    "SSL_CTX_set_default_verify_paths",
    # TB9: read until WANT_READ, never by what is pending
    "SSL_pending", "SSL_has_pending",
    # TB16: no callbacks into Mojo
    "set_info_callback", "set_msg_callback",
)

_TRIPLE = re.compile(r'("""|\'\'\')(?:.|\n)*?\1')
_COMMENT = re.compile(r"#.*$", re.M)
_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_BOUND = re.compile(r'_sym\[[^\]]*\]\(\s*self\._handle\s*,\s*"(\w+)"\s*\)')
_SYM_CALL = re.compile(r'(?<!def )\b_sym\[')
_HANDLE_OUT = re.compile(r'^\s*def ([A-Za-z]\w*)\(.*\)\s*(?:raises(?:\s+\w+)?\s*)?->\s*(Obj|ArcPointer\[Library\])\s*:', re.M)


def _blank(m):
    return "\n" * m.group(0).count("\n")


def code_of(text, keep_strings=True):
    """`text` without docstrings and comments (line numbers kept)."""
    code = _TRIPLE.sub(_blank, text)
    lines = []
    for line in code.split("\n"):
        # Drop a comment that is not inside a string literal ('...' or "...").
        out, i, quote = [], 0, ""
        while i < len(line):
            c = line[i]
            if c in "\"'" and (not quote or quote == c):
                quote = "" if quote else c
            elif c == "\\" and quote:
                out.append(line[i : i + 2])
                i += 2
                continue
            elif c == "#" and not quote:
                break
            out.append(c)
            i += 1
        lines.append("".join(out))
    code = "\n".join(lines)
    return code if keep_strings else _STRING.sub('""', code)


def mojo_files(root, top):
    base = os.path.join(root, top)
    for d, dirs, names in os.walk(base):
        dirs[:] = sorted(x for x in dirs if not x.startswith("."))
        for n in sorted(names):
            if n.endswith(".mojo"):
                p = os.path.join(d, n)
                yield os.path.relpath(p, root), p


def check_source(root):
    """Checks 1-3; returns (violations, bound names)."""
    bad = []
    for rel, path in mojo_files(root, "src"):
        code = code_of(open(path, encoding="utf-8").read())
        if rel != FFI_MODULE:
            for n, line in enumerate(code.split("\n"), 1):
                for tok in FFI_TOKENS:
                    if re.search(r"\b" + tok + r"\b", line):
                        bad.append(f"{rel}:{n}: {tok} outside {FFI_MODULE} (TL7)")
                for tok in FFI_LITERALS:
                    if tok in line:
                        bad.append(f"{rel}:{n}: {tok} outside {FFI_MODULE} (TB16)")
            if rel.startswith(os.path.join("src", "tls") + os.sep):
                for m in _HANDLE_OUT.finditer(code):
                    n = code[: m.start()].count("\n") + 1
                    bad.append(f"{rel}:{n}: public {m.group(1)}() hands out an OpenSSL handle ({m.group(2)}): a built context must stay read-only (TB3)")
        if rel.startswith(os.path.join("src", "tls") + os.sep):
            for n, line in enumerate(code.split("\n"), 1):
                for tok in FORBIDDEN:
                    if tok in line:
                        bad.append(f"{rel}:{n}: forbidden OpenSSL name {tok!r} (TL5)")
    bound = []
    ffi = os.path.join(root, FFI_MODULE)
    if os.path.exists(ffi):
        code = code_of(open(ffi, encoding="utf-8").read())
        bound = _BOUND.findall(code)
        for name in sorted(set(bound) - BINDINGS):
            bad.append(f"{FFI_MODULE}: binds {name}, which is not in BINDINGS in tools/check_tls.py (TL5)")
        calls = len(_SYM_CALL.findall(code))
        if calls != len(bound):
            bad.append(f"{FFI_MODULE}: {calls - len(bound)} _sym binding(s) without a literal name on self._handle (TL5)")
        uses = len(re.findall(r"\bget_symbol\b", code))
        if uses > 1:
            bad.append(f"{FFI_MODULE}: get_symbol is called outside _sym ({uses} uses) (TL5)")
    recipe = os.path.join(root, RECIPE)
    if os.path.exists(recipe) and not re.search(r"openssl\s*>=\s*3\.5\.9\b", open(recipe, encoding="utf-8").read()):
        bad.append(f"{RECIPE}: openssl must be >=3.5.9 (TL1)")
    return bad, sorted(set(bound))


def version_nodes(path):
    """{symbol: version node} for the defined dynamic symbols of `path`."""
    out = subprocess.run(["readelf", "--dyn-syms", "--wide", path], check=True, capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[6] == "UND" or "@" not in parts[7]:
            continue
        sym, _, node = parts[7].partition("@")
        found[sym] = node.lstrip("@")
    return found


def check_versions(names):
    """Check 4."""
    prefix = os.environ.get("CONDA_PREFIX")
    if not prefix:
        return ["CONDA_PREFIX is not set: run through pixi (check 4 needs the environment's OpenSSL)"]
    table = {}
    for lib in ("libcrypto.so.3", "libssl.so.3"):
        table.update(version_nodes(os.path.join(prefix, "lib", lib)))
    bad = []
    for name in names:
        node = table.get(name)
        m = re.fullmatch(r"OPENSSL_(\d+)\.(\d+)\.(\d+)[a-z]?", node or "")
        if not m or tuple(int(x) for x in m.groups()) > (3, 5, 0):
            bad.append(f"{FFI_MODULE}: {name} comes from version node {node} (newer than OPENSSL_3.5.0, or none) (TL2)")
    return bad


def _self_test():
    plant = {
        "src/net/a.mojo": ('from std.ffi import external_call\n"""external_call in a docstring is prose"""\n', "external_call outside"),
        "src/tls/b.mojo": ("var x = 1  # SSL_free_buffers in a comment is fine\nL.SSL_free_buffers(s)\n", "SSL_free_buffers"),
        "src/tls/c.mojo": ('var m = "SSL_VERIFY_NONE"\n', "SSL_VERIFY_NONE"),
        "src/tls/ffi.mojo": ('def _sym[F](h, name):\n    return h.get_symbol(name)\nself.f = _sym[F](self._handle, "SSL_new")\nself.g = _sym[F](self._handle, "SSL_CTX_set_keylog_x")\nself.h = _sym[F](self._handle, name)\n', "keylog"),
        "src/linux/d.mojo": ("var h = OwnedDLHandle(path)\n", "OwnedDLHandle outside"),
        "src/tls/e.mojo": ("L.SSL_set_fd(s, 3)\n", "SSL_set_fd"),
        "src/tls/f.mojo": ("var s = '#'; L.SSL_free_buffers(s)\n", "SSL_free_buffers"),
        "src/tls/g.mojo": ('comptime G = def() thin abi("C") -> None\n', 'abi("C") outside'),
        "src/tls/h.mojo": ("struct C:\n    def ssl_ctx(self) -> Obj:\n        return 0\n    def _ok(self) -> Obj:\n        return 0\n", "hands out"),
        RECIPE: ("requirements:\n  run:\n    - openssl >=3.5,<4\n", "openssl must be"),
    }
    with tempfile.TemporaryDirectory() as root:
        for rel, (src, _) in plant.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(src)
        bad, bound = check_source(root)
        errors = []
        for rel, (_, want) in plant.items():
            if not any(b.startswith(rel) and want in b for b in bad):
                errors.append(f"{rel}: expected a violation containing {want!r}")
        if not any("not in BINDINGS" in b and "SSL_CTX_set_keylog_x" in b for b in bad):
            errors.append("an unlisted binding went unreported")
        if not any("without a literal name" in b for b in bad):
            errors.append("a binding without a literal name went unreported")
        if any("_ok()" in b for b in bad) or any("get_symbol is called outside" in b for b in bad):
            errors.append(f"a private accessor, or get_symbol inside _sym, was reported: {bad}")
        if any("docstring" in b or (b.startswith("src/tls/b.mojo:1") ) for b in bad):
            errors.append(f"prose or a comment was reported: {bad}")
        if bound != ["SSL_CTX_set_keylog_x", "SSL_new"]:
            errors.append(f"bound names misread: {bound}")
        if os.environ.get("CONDA_PREFIX"):
            if check_versions(["SSL_new"]) or not check_versions(["SSL_no_such_function"]):
                errors.append("the version-node check misjudged SSL_new or a missing function")
        if errors:
            sys.exit("check_tls self-test failed:\n" + "\n".join(errors) + "\nreported:\n" + "\n".join(bad))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()
    _self_test()
    bad, bound = check_source(args.root)
    if len(bound) < 50:
        bad.append(f"{FFI_MODULE}: only {len(bound)} bindings found; the pattern no longer matches the module")
    bad += check_versions(bound)
    consts = subprocess.run([sys.executable, os.path.join(args.root, "tools", "gen_tls_consts.py"), "--check"], capture_output=True, text=True)
    if consts.returncode != 0:
        bad.append("src/tls/consts.mojo differs from the headers (TB14):\n" + consts.stdout + consts.stderr)
    for b in bad:
        print(b)
    print(f"---- tls checks: {len(bound)} bindings (all OPENSSL_3.5.0 or older unless listed), {len(bad)} violations")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
