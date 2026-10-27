"""The client side of gate TG2 (tools/limbo.py; not a test file itself):
verified handshakes for each x509-limbo case, against
tests/tls/limbo_peer.py.

    mojo run -I src -I tests/tls tests/tls/limbo_client.mojo <dir> <results.tsv> [first] [count]

For each line of <dir>/cases.tsv the client trusts the case's
`trusted_certs` only (`Trust.ca_file`) and expects the case's name (a DNS
name or an IP address, reached at 127.0.0.1). Each case runs as SUB (its
chain in a substituted TLS 1.2 Certificate message: limbo_peer.py), and a
case that comes with the leaf's key also as KEY, a real handshake through
the whole client, the gate included. <results.tsv> gets one line per run:
index, KEY or SUB, SUCCESS or FAILURE, OpenSSL's verify result (0: the
chain verified) and the error.

SUB's verdict: the chain was accepted when the handshake fails at the
ServerKeyExchange's signature with verify result 0, refused when it fails
with anything else. A SUB handshake that completes is impossible, and is
reported as UNEXPECTED. A case whose certificate the server cannot load
(an encoding OpenSSL refuses) is a FAILURE: the same parser would refuse it
in the client."""

from std.python import Python, PythonObject
from std.sys import argv

from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpStream
from tls import ClientConfig, TlsError, Trust
from tls.stream import TlsStream


def _tcp(port: Int) raises TlsError -> TcpStream:
    try:
        return TcpStream.connect_deadline(SocketAddr.parse(String("127.0.0.1:", port)), Deadline.after(Duration.from_secs(10)))
    except e:
        raise TlsError(e)


def _verdict(dir: String, port: Int, name: String, sub: Bool) -> String:
    var ctx = ClientConfig(trust=Trust.ca_file(dir + "/ca.pem"))
    try:
        var built = ctx.build()
        var s = TlsStream.handshake(_tcp(port), built, name, Deadline.after(Duration.from_secs(10)))
        s^.close()
        return "UNEXPECTED\t0\tthe substituted handshake completed" if sub else "SUCCESS\t0\t"
    except e:
        var why = String(e).replace("\t", " ").replace("\n", " ")
        if sub and e.verify_code == 0 and "bad signature" in e.detail:
            return "SUCCESS\t0\tchain accepted, then " + why
        return String("FAILURE\t", e.verify_code, "\t", why)


def _run(proc: PythonObject, peer: PythonObject, top: String, port: Int, mode: String, n: String, name: String) raises -> String:
    _ = proc.stdin.write(mode + " " + n + "\n")
    _ = proc.stdin.flush()
    var reply = String(py=peer.next(30.0))
    if reply.startswith("UNLOADABLE"):
        return "FAILURE\t0\tthe server could not present it: " + reply
    if not reply.startswith("READY"):
        raise Error(String("limbo_peer.py: ", reply))
    var verdict = _verdict(top + "/cases/" + n, port, name, mode == "SUB")
    var end = String(py=peer.next(30.0))
    if not end.startswith("DONE"):
        raise Error(String("limbo_peer.py: ", end))
    return verdict


def main() raises:
    var args = argv()
    var top = String(args[1])
    var out_path = String(args[2])
    var first = atol(args[3]) if len(args) > 3 else 0
    var count = atol(args[4]) if len(args) > 4 else -1
    var lines = open(top + "/cases.tsv", "r").read().split("\n")
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    _ = pysys.path.insert(0, "tests/tls")
    var cmd = Python.list(pysys.executable, "tests/tls/limbo_peer.py", top)
    var proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    var peer = Python.import_module("peer_io").Lines(proc.stdout)
    var words = String(py=peer.next(30.0)).split()
    if len(words) != 2 or String(words[0]) != "PORT":
        raise Error("limbo_peer.py did not start")
    var port = atol(words[1])
    var out = open(out_path, "w")
    var done = 0
    for i in range(first, len(lines)):
        if count >= 0 and done >= count:
            break
        if lines[i].byte_length() == 0:
            continue
        var f = lines[i].split("\t")
        var n = String(f[0])
        out.write(n, "\tSUB\t", _run(proc, peer, top, port, "SUB", n, String(f[3])), "\n")
        if f[5] == "KEY":
            out.write(n, "\tKEY\t", _run(proc, peer, top, port, "KEY", n, String(f[3])), "\n")
        done += 1
        if done % 500 == 0:
            print("limbo:", done, "cases")
    out.close()
    _ = proc.stdin.close()
    _ = proc.wait()
    print("limbo:", done, "cases run")
