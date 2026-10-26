"""A throwaway PKI for tests/tls, made with the environment's `openssl`
command (test-only Python; not a test file itself).

    python tests/tls/tls_pki.py <dir> [--owner <pid>]

Writes, into <dir>, PEM files named <name>.pem (the certificate), <name>.key
and, for leaves, <name>.chain.pem (the certificate followed by the
intermediates a server sends). Every certificate is valid for two days
unless its purpose is to be expired or not yet valid. Prints "PKI <dir>".
With --owner, a detached watcher removes <dir> once process <pid> has
ended, so a test process that crashes leaves nothing behind.

CAs:      root, other (unrelated), inter (signed by root, CA:TRUE),
          inter_noca (signed by root, CA:FALSE: no CA at all)
Leaves (signed by root unless said):
  good          DNS:localhost, IP:127.0.0.1, IP:::1          (ECDSA P-256)
  rsa           the same names, RSA 2048, for TLS 1.2 ECDHE-RSA
  chained       DNS:localhost, signed by inter; chain has inter
  bad_ca        DNS:localhost, signed by inter_noca; chain has it
  wrong_host    DNS:other.test
  cn_only       subject CN=localhost, no subjectAltName
  wildcard      DNS:*.wild.test
  partial_wild  DNS:a*.wild.test
  ip_as_dns     DNS:127.0.0.1 (an address spelt as a name)
  expired       localhost, valid 2020-01-01 to 2020-01-02
  future        localhost, valid from 2099-01-01
  self_signed   localhost, its own issuer
  rsa1024       localhost, RSA 1024 (below security level 2)
  sha1          localhost, signed with SHA-1
  client_only   localhost, extendedKeyUsage clientAuth only
  by_other      localhost and 127.0.0.1, signed by other (an unrelated root)
  soon          localhost, valid from 47 hours ago to 1 hour from now
Other files:
  root.crl.pem  an empty CRL issued by root (a CRL is no trust anchor)
"""

import os
import shutil
import subprocess
import sys
import time

SERIALS = iter(range(2, 1000))
LEAF_EXT = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"


def run(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def key(d, name, kind="ec"):
    path = os.path.join(d, name + ".key")
    if kind == "ec":
        run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path)
    else:
        run("genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{kind}", "-out", path)
    return path


def ca(d, name, cn):
    k = key(d, name)
    run(
        "req", "-x509", "-new", "-key", k, "-days", "2", "-subj", f"/CN={cn}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-out", os.path.join(d, name + ".pem"),
    )


def signed(d, name, issuer, subject, ext, *, kind="ec", digest="sha256", dates=None, chain=(), ca_ext=False):
    k = key(d, name, kind)
    csr = os.path.join(d, name + ".csr")
    run("req", "-new", "-key", k, "-subj", subject, "-out", csr)
    extfile = os.path.join(d, name + ".ext")
    with open(extfile, "w") as f:
        f.write(ext)
    cert = os.path.join(d, name + ".pem")
    args = ["x509", "-req", "-in", csr, "-CA", os.path.join(d, issuer + ".pem"),
            "-CAkey", os.path.join(d, issuer + ".key"), "-set_serial", str(next(SERIALS)),
            "-extfile", extfile, f"-{digest}", "-out", cert]
    if dates:
        args += ["-not_before", dates[0], "-not_after", dates[1]]
    else:
        args += ["-days", "2"]
    run(*args)
    write_chain(d, name, chain)


def crl(d, issuer):
    """<issuer>.crl.pem: an empty CRL, through `openssl ca -gencrl`."""
    db = os.path.join(d, issuer + ".crl.db")
    os.makedirs(db, exist_ok=True)
    open(os.path.join(db, "index.txt"), "w").close()
    with open(os.path.join(db, "crlnumber"), "w") as f:
        f.write("01\n")
    cnf = os.path.join(db, "ca.cnf")
    with open(cnf, "w") as f:
        f.write(f"[ca]\ndefault_ca = d\n[d]\ndatabase = {db}/index.txt\ncrlnumber = {db}/crlnumber\n"
                "default_md = sha256\ndefault_crl_days = 2\n")
    run("ca", "-gencrl", "-config", cnf, "-keyfile", os.path.join(d, issuer + ".key"),
        "-cert", os.path.join(d, issuer + ".pem"), "-out", os.path.join(d, issuer + ".crl.pem"))


def write_chain(d, name, chain):
    with open(os.path.join(d, name + ".chain.pem"), "w") as out:
        for part in (name, *chain):
            with open(os.path.join(d, part + ".pem")) as f:
                out.write(f.read())


def main():
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    ca(d, "root", "mojo_net test root")
    ca(d, "other", "unrelated test root")
    signed(d, "inter", "root", "/CN=mojo_net test intermediate",
           "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
    signed(d, "inter_noca", "root", "/CN=not a CA", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyCertSign,digitalSignature\n")
    names = "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
    host = "subjectAltName=DNS:localhost\n"
    signed(d, "good", "root", "/CN=localhost", LEAF_EXT + names + "extendedKeyUsage=serverAuth\n")
    signed(d, "rsa", "root", "/CN=localhost", LEAF_EXT + names, kind="2048")
    signed(d, "chained", "inter", "/CN=localhost", LEAF_EXT + host, chain=("inter",))
    signed(d, "bad_ca", "inter_noca", "/CN=localhost", LEAF_EXT + host, chain=("inter_noca",))
    signed(d, "wrong_host", "root", "/CN=other.test", LEAF_EXT + "subjectAltName=DNS:other.test\n")
    signed(d, "cn_only", "root", "/CN=localhost", LEAF_EXT)
    signed(d, "wildcard", "root", "/CN=wild", LEAF_EXT + "subjectAltName=DNS:*.wild.test\n")
    signed(d, "partial_wild", "root", "/CN=partial", LEAF_EXT + "subjectAltName=DNS:a*.wild.test\n")
    signed(d, "ip_as_dns", "root", "/CN=ip", LEAF_EXT + "subjectAltName=DNS:127.0.0.1\n")
    signed(d, "expired", "root", "/CN=localhost", LEAF_EXT + host, dates=("20200101000000Z", "20200102000000Z"))
    signed(d, "future", "root", "/CN=localhost", LEAF_EXT + host, dates=("20990101000000Z", "20990102000000Z"))
    k = key(d, "self_signed")
    run("req", "-x509", "-new", "-key", k, "-days", "2", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost", "-out", os.path.join(d, "self_signed.pem"))
    write_chain(d, "self_signed", ())
    signed(d, "rsa1024", "root", "/CN=localhost", LEAF_EXT + host, kind="1024")
    signed(d, "sha1", "root", "/CN=localhost", LEAF_EXT + host, digest="sha1")
    signed(d, "client_only", "root", "/CN=localhost", LEAF_EXT + host + "extendedKeyUsage=clientAuth\n")
    signed(d, "by_other", "other", "/CN=localhost", LEAF_EXT + names)
    now = time.time()
    stamp = lambda t: time.strftime("%Y%m%d%H%M%SZ", time.gmtime(t))
    signed(d, "soon", "root", "/CN=localhost", LEAF_EXT + host, dates=(stamp(now - 47 * 3600), stamp(now + 3600)))
    crl(d, "root")
    if len(sys.argv) == 4 and sys.argv[2] == "--owner":
        watch(int(sys.argv[3]), d)
    print("PKI", d, flush=True)


def watch(pid, d):
    """Fork a detached process that removes `d` once `pid` has ended."""
    if os.fork() != 0:
        return
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            pass
        time.sleep(0.5)
    shutil.rmtree(d, ignore_errors=True)
    os._exit(0)


if __name__ == "__main__":
    main()
