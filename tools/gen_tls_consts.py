"""Generate src/tls/consts.mojo from the environment's OpenSSL headers
(rule TB14 of docs/research/tls_with_openssl.md).

Several calls the `tls` package needs are macros in OpenSSL 3
(`SSL_set_tlsext_host_name`, `SSL_CTX_set_min_proto_version`, ...): they
are made through `SSL_ctrl`, `SSL_CTX_ctrl` or `BIO_ctrl` with the command
codes below, which this tool reads from the headers rather than from
memory. Every value is printed by a C program compiled against
$CONDA_PREFIX/include, as tools/gen_abi.py does for the kernel's constants.

  gen_tls_consts.py --write   regenerate src/tls/consts.mojo
  gen_tls_consts.py --check   fail if the committed file differs (CI)
"""

import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "tls", "consts.mojo")

# (name, Mojo type, comment)
CONSTS = [
    ("OPENSSL_VERSION_NUMBER", "UInt64", "the headers' version (0xMNN00PP0)"),
    ("OPENSSL_VERSION", "c_int", "OpenSSL_version(): the version text"),
    ("OPENSSL_DIR", "c_int", "OpenSSL_version(): OPENSSLDIR"),
    ("OPENSSL_INIT_NO_LOAD_CONFIG", "UInt64", "OPENSSL_init_ssl: never read openssl.cnf"),
    # SSL_ctrl / SSL_CTX_ctrl command codes (the macros' entry points)
    ("SSL_CTRL_SET_TLSEXT_HOSTNAME", "c_int", "SSL_set_tlsext_host_name"),
    ("TLSEXT_NAMETYPE_host_name", "Int", "its name type"),
    ("SSL_CTRL_MODE", "c_int", "SSL_CTX_set_mode"),
    ("SSL_CTRL_CLEAR_MODE", "c_int", "SSL_CTX_clear_mode"),
    ("SSL_CTRL_SET_MIN_PROTO_VERSION", "c_int", "SSL_CTX_set_min_proto_version"),
    ("SSL_CTRL_SET_MAX_PROTO_VERSION", "c_int", "SSL_CTX_set_max_proto_version"),
    ("SSL_CTRL_GET_MIN_PROTO_VERSION", "c_int", "SSL_CTX_get_min_proto_version"),
    ("SSL_CTRL_GET_MAX_PROTO_VERSION", "c_int", "SSL_CTX_get_max_proto_version"),
    ("SSL_CTRL_SET_GROUPS_LIST", "c_int", "SSL_CTX_set1_groups_list"),
    ("SSL_CTRL_SET_SIGALGS_LIST", "c_int", "SSL_CTX_set1_sigalgs_list"),
    ("SSL_CTRL_SET_SESS_CACHE_MODE", "c_int", "SSL_CTX_set_session_cache_mode"),
    ("SSL_CTRL_GET_SESS_CACHE_MODE", "c_int", "SSL_CTX_get_session_cache_mode"),
    ("SSL_SESS_CACHE_OFF", "Int", "no session cache"),
    ("BIO_C_SET_BUF_MEM_EOF_RETURN", "c_int", "BIO_set_mem_eof_return"),
    # protocol versions
    ("TLS1_VERSION", "Int", ""),
    ("TLS1_1_VERSION", "Int", ""),
    ("TLS1_2_VERSION", "Int", "the floor"),
    ("TLS1_3_VERSION", "Int", ""),
    # verification
    ("SSL_VERIFY_PEER", "c_int", ""),
    ("SSL_FILETYPE_PEM", "c_int", ""),
    ("X509_V_FLAG_X509_STRICT", "UInt64", ""),
    ("X509_V_FLAG_TRUSTED_FIRST", "UInt64", ""),
    ("X509_V_FLAG_PARTIAL_CHAIN", "UInt64", "kept off"),
    ("X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS", "c_uint", ""),
    ("X509_CHECK_FLAG_NEVER_CHECK_SUBJECT", "c_uint", "no subject CN fallback"),
    # SSL_get_error results
    ("SSL_ERROR_NONE", "c_int", ""),
    ("SSL_ERROR_SSL", "c_int", ""),
    ("SSL_ERROR_WANT_READ", "c_int", ""),
    ("SSL_ERROR_WANT_WRITE", "c_int", ""),
    ("SSL_ERROR_WANT_X509_LOOKUP", "c_int", ""),
    ("SSL_ERROR_SYSCALL", "c_int", ""),
    ("SSL_ERROR_ZERO_RETURN", "c_int", ""),
    ("SSL_ERROR_WANT_CONNECT", "c_int", ""),
    ("SSL_ERROR_WANT_ACCEPT", "c_int", ""),
    ("SSL_ERROR_WANT_ASYNC", "c_int", ""),
    ("SSL_ERROR_WANT_ASYNC_JOB", "c_int", ""),
    ("SSL_ERROR_WANT_CLIENT_HELLO_CB", "c_int", ""),
    ("SSL_ERROR_WANT_RETRY_VERIFY", "c_int", ""),
    # options and modes
    ("SSL_OP_NO_COMPRESSION", "UInt64", ""),
    ("SSL_OP_NO_RENEGOTIATION", "UInt64", ""),
    ("SSL_OP_ENABLE_MIDDLEBOX_COMPAT", "UInt64", ""),
    ("SSL_OP_NO_TICKET", "UInt64", ""),
    ("SSL_OP_CLEANSE_PLAINTEXT", "UInt64", "wipe OpenSSL's own copies of plaintext (TB18)"),
    ("SSL_OP_NO_TX_CERTIFICATE_COMPRESSION", "UInt64", "send no compressed certificates (RFC 8879)"),
    ("SSL_OP_NO_RX_CERTIFICATE_COMPRESSION", "UInt64", "offer to take none"),
    ("SSL_MODE_AUTO_RETRY", "Int", ""),
    ("SSL_MODE_RELEASE_BUFFERS", "Int", ""),
    ("SSL_MODE_NO_AUTO_CHAIN", "Int", "a server sends exactly the chain configured (TS3)"),
    # verify results (X509_V_*) the error categories name
    ("X509_V_OK", "Int", ""),
    ("X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT", "Int", ""),
    ("X509_V_ERR_CERT_SIGNATURE_FAILURE", "Int", ""),
    ("X509_V_ERR_CERT_NOT_YET_VALID", "Int", ""),
    ("X509_V_ERR_CERT_HAS_EXPIRED", "Int", ""),
    ("X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT", "Int", ""),
    ("X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN", "Int", ""),
    ("X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "Int", ""),
    ("X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE", "Int", ""),
    ("X509_V_ERR_INVALID_CA", "Int", ""),
    ("X509_V_ERR_INVALID_PURPOSE", "Int", ""),
    ("X509_V_ERR_CERT_UNTRUSTED", "Int", ""),
    ("X509_V_ERR_CERT_REJECTED", "Int", ""),
    ("X509_V_ERR_HOSTNAME_MISMATCH", "Int", ""),
    ("X509_V_ERR_IP_ADDRESS_MISMATCH", "Int", ""),
    ("X509_V_ERR_EE_KEY_TOO_SMALL", "Int", ""),
    ("X509_V_ERR_CA_KEY_TOO_SMALL", "Int", ""),
    ("X509_V_ERR_CA_MD_TOO_WEAK", "Int", ""),
    # trust store objects
    ("X509_LU_X509", "c_int", "a certificate (not a CRL) in an X509_STORE"),
    # error-queue reason codes
    ("ERR_LIB_SSL", "Int", ""),
    ("SSL_R_UNEXPECTED_EOF_WHILE_READING", "Int", ""),
    ("SSL_R_NO_APPLICATION_PROTOCOL", "Int", "the ALPN refusal (TS5)"),
    ("ERR_SYSTEM_FLAG", "UInt64", "ERR_GET_LIB / ERR_GET_REASON (inline functions)"),
    ("ERR_LIB_OFFSET", "UInt64", ""),
    ("ERR_LIB_MASK", "UInt64", ""),
    ("ERR_REASON_MASK", "UInt64", ""),
    # a server's ALPN selection callback (TS5)
    ("SSL_TLSEXT_ERR_OK", "c_int", ""),
    ("SSL_TLSEXT_ERR_ALERT_FATAL", "c_int", ""),
    # name constraints, read by the client's gate (a wildcard against an
    # excluded name): the structs are public in x509v3.h, their offsets
    # checked here on each architecture
    ("NID_name_constraints", "c_int", "the nameConstraints extension"),
    ("GEN_DNS", "Int", "a GENERAL_NAME's dNSName"),
    ("NC_EXCLUDED_OFFSET", "Int", "NAME_CONSTRAINTS.excludedSubtrees", "offsetof(NAME_CONSTRAINTS, excludedSubtrees)"),
    ("SUBTREE_BASE_OFFSET", "Int", "GENERAL_SUBTREE.base", "offsetof(GENERAL_SUBTREE, base)"),
    ("GENERAL_NAME_TYPE_OFFSET", "Int", "GENERAL_NAME.type (an int)", "offsetof(GENERAL_NAME, type)"),
    ("GENERAL_NAME_D_OFFSET", "Int", "GENERAL_NAME.d (the union's pointer)", "offsetof(GENERAL_NAME, d)"),
]

PROGRAM = """#include <stddef.h>
#include <stdio.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
int main(void) {
  printf("%s\\n", OPENSSL_VERSION_TEXT);
@BODY@
  return 0;
}
"""


def run_headers():
    prefix = os.environ.get("CONDA_PREFIX")
    if not prefix:
        sys.exit("gen_tls_consts.py: run it through pixi (CONDA_PREFIX is unset)")
    lines = "\n".join(f'  printf("%llu\\n", (unsigned long long)({c[3] if len(c) > 3 else c[0]}));' for c in CONSTS)
    with tempfile.TemporaryDirectory() as d:
        src, exe = os.path.join(d, "consts.c"), os.path.join(d, "consts")
        with open(src, "w") as f:
            f.write(PROGRAM.replace("@BODY@", lines))
        subprocess.run(["gcc", "-O0", "-I", os.path.join(prefix, "include"), "-o", exe, src], check=True)
        out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout.splitlines()
    return out[0], [int(v) for v in out[1:]]


def render(version_text, values):
    major_minor = ".".join(version_text.split()[1].split(".")[:2])
    lines = [
        f'"""OpenSSL constants, generated from the OpenSSL {major_minor} headers by',
        "tools/gen_tls_consts.py. Do not edit: run `pixi run gen-tls`, and CI's",
        "`--check` fails on any drift (rule TB14). The macros' command codes are",
        'here because the macros themselves are not symbols in libssl."""',
        "",
        "from std.ffi import c_int, c_uint",
        "",
    ]
    for (name, ty, comment, *_), v in zip(CONSTS, values):
        if name == "OPENSSL_VERSION_NUMBER":
            v = v & 0xFFF00000  # the major.minor line, not the patch (the check survives 3.5.x updates)
            comment = "the major.minor line of the headers"
        lines.append(f"comptime {name}: {ty} = {v}" + (f"  # {comment}" if comment else ""))
    return "\n".join(lines) + "\n"


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    text = render(*run_headers())
    if mode == "--write":
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as f:
            f.write(text)
        print(f"wrote {os.path.relpath(OUT, ROOT)}")
        return 0
    current = open(OUT).read() if os.path.exists(OUT) else ""
    if current != text:
        print(f"MISMATCH: {os.path.relpath(OUT, ROOT)} differs from the environment's OpenSSL headers", file=sys.stderr)
        return 1
    print("---- tls constants match the OpenSSL headers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
