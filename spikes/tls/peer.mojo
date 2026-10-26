"""T0 spike: the OpenSSL client over a real TCP connection (the repo's own
`net.TcpStream` does all the I/O; libssl sees only memory BIOs), against a
TLS server written with Python's `ssl` module.

    pixi run mojo run -I src -I spikes/tls spikes/tls/peer.mojo build/tls_spike
"""

from std.ffi import c_int, c_uint
from std.python import Python
from std.sys import argv

from linux.time import Deadline, Duration
from net.addr import SocketAddr
from net.tcp import TcpStream
from ffi import F_i_p, F_i_pi, F_i_ppi, F_i_ppnp, F_i_ppp, F_i_pp, F_i_u64p, F_l_pilp, F_p, F_p_p, F_p_pp, F_p_ppp
from ffi import F_u64, F_u64_pu64, F_v, F_v_p, F_v_pip, F_v_pp, F_v_pu, Lib, cstr, from_cstr

comptime SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
comptime SSL_CTRL_SET_MIN_PROTO_VERSION = 123
comptime BIO_C_SET_BUF_MEM_EOF_RETURN = 130
comptime SSL_ERROR_WANT_READ = 2
comptime SSL_ERROR_ZERO_RETURN = 6

comptime _PEER = """
import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(sys.argv[1] + "/server.pem", sys.argv[1] + "/server.key")
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(1)
print(ls.getsockname()[1], flush=True)
c, _ = ls.accept()
s = ctx.wrap_socket(c, server_side=True)
data = s.recv(1024)
s.sendall(b"echo:" + data + b" from " + s.version().encode())
s.unwrap()  # close_notify, and wait for the client's
print("peer: clean TLS close", flush=True)
c.close()
"""


def flush_out(lib: Lib, ssl: Int, stream: TcpStream) raises -> Int:
    """Send whatever libssl wrote into its write BIO."""
    var wbio = lib.sym[F_p_p]("SSL_get_wbio")(ssl)
    var buf = List[UInt8](length=16384, fill=0)
    var sent = 0
    while True:
        var n = lib.sym[def(Int, UnsafePointer[UInt8, MutAnyOrigin], c_int) thin abi("C") -> c_int]("BIO_read")(
            wbio, buf.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](), c_int(len(buf))
        )
        if n <= 0:
            return sent
        stream.write_all(Span(buf)[0 : Int(n)])
        sent += Int(n)


def fill_in(lib: Lib, ssl: Int, stream: TcpStream) raises -> Int:
    """One read from the socket into libssl's read BIO (0 at EOF, which then
    marks the BIO's end)."""
    var rbio = lib.sym[F_p_p]("SSL_get_rbio")(ssl)
    var buf = List[UInt8](length=16384, fill=0)
    var n = stream.read(Span(buf))
    if n == 0:
        _ = lib.sym[F_l_pilp]("BIO_ctrl")(rbio, c_int(BIO_C_SET_BUF_MEM_EOF_RETURN), 0, 0)
        return 0
    _ = lib.sym[def(Int, UnsafePointer[UInt8, MutAnyOrigin], c_int) thin abi("C") -> c_int]("BIO_write")(
        rbio, buf.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](), c_int(n)
    )
    return n


def main() raises:
    var dir = String(argv()[1])
    var subprocess = Python.import_module("subprocess")
    var pysys = Python.import_module("sys")
    var peer = subprocess.Popen(Python.list(pysys.executable, "-c", _PEER, dir), stdout=subprocess.PIPE, text=True)
    var port = atol(String(py=peer.stdout.readline()).strip())
    var lib = Lib.beside_runtime("libssl.so.3")
    _ = lib.sym[F_i_u64p]("OPENSSL_init_ssl")(UInt64(128), 0)  # NO_LOAD_CONFIG
    var ctx = lib.sym[F_p_p]("SSL_CTX_new")(lib.sym[F_p]("TLS_client_method")())
    _ = lib.sym[F_l_pilp]("SSL_CTX_ctrl")(ctx, c_int(SSL_CTRL_SET_MIN_PROTO_VERSION), 771, 0)
    var ca = cstr(dir + "/ca.pem")
    _ = lib.sym[F_i_ppp]("SSL_CTX_load_verify_locations")(ctx, Int(ca.unsafe_ptr()), 0)
    _ = ca^
    var ssl = lib.sym[F_p_p]("SSL_new")(ctx)
    var bio_method = lib.sym[F_p]("BIO_s_mem")()
    lib.sym[F_v_pp]("SSL_set0_rbio")(ssl, lib.sym[F_p_p]("BIO_new")(bio_method))
    lib.sym[F_v_pp]("SSL_set0_wbio")(ssl, lib.sym[F_p_p]("BIO_new")(bio_method))
    lib.sym[F_v_p]("SSL_set_connect_state")(ssl)
    lib.sym[F_v_pip]("SSL_set_verify")(ssl, c_int(1), 0)
    var host = cstr("localhost")
    var param = lib.sym[F_p_p]("SSL_get0_param")(ssl)
    _ = lib.sym[F_i_ppp]("X509_VERIFY_PARAM_set1_host")(param, Int(host.unsafe_ptr()), 9)
    _ = lib.sym[F_l_pilp]("SSL_ctrl")(ssl, c_int(SSL_CTRL_SET_TLSEXT_HOSTNAME), 0, Int(host.unsafe_ptr()))
    var stream = TcpStream.connect(SocketAddr.parse(String("127.0.0.1:", port)))
    stream.set_read_deadline(Deadline.after(Duration.from_secs(10)))
    var rounds = 0
    while True:
        lib.sym[F_v]("ERR_clear_error")()
        var rc = lib.sym[F_i_p]("SSL_do_handshake")(ssl)
        _ = flush_out(lib, ssl, stream)
        if rc == 1:
            break
        var e = lib.sym[F_i_pi]("SSL_get_error")(ssl, rc)
        if e != SSL_ERROR_WANT_READ:
            raise Error(String("handshake failed: SSL_get_error ", e))
        if fill_in(lib, ssl, stream) == 0:
            raise Error("EOF in the handshake")
        rounds += 1
    print("handshake over TcpStream: ok after", rounds, "reads; verify result", lib.sym[F_l_pilp]("SSL_get_verify_result")(ssl, 0, 0, 0))
    var msg = List[UInt8]("ping".as_bytes())
    var n = List[Int](length=1, fill=0)
    _ = lib.sym[def(Int, UnsafePointer[UInt8, MutAnyOrigin], Int, UnsafePointer[Int, MutAnyOrigin]) thin abi("C") -> c_int]("SSL_write_ex")(
        ssl, msg.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](), len(msg), n.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
    )
    _ = flush_out(lib, ssl, stream)
    var got = String()
    var closed = False
    var buf = List[UInt8](length=4096, fill=0)
    while not closed:
        lib.sym[F_v]("ERR_clear_error")()
        var rc = lib.sym[def(Int, UnsafePointer[UInt8, MutAnyOrigin], Int, UnsafePointer[Int, MutAnyOrigin]) thin abi("C") -> c_int]("SSL_read_ex")(
            ssl, buf.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](), len(buf), n.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()
        )
        _ = flush_out(lib, ssl, stream)
        if rc == 1:
            got += String(unsafe_from_utf8=Span(buf)[0 : n[0]])
            continue
        var e = lib.sym[F_i_pi]("SSL_get_error")(ssl, rc)
        if e == SSL_ERROR_ZERO_RETURN:
            closed = True
        elif e == SSL_ERROR_WANT_READ:
            if fill_in(lib, ssl, stream) == 0:
                raise Error("EOF without close_notify")
        else:
            raise Error(String("read failed: SSL_get_error ", e))
    print("reply:", repr(got), "| ended by close_notify:", closed)
    # Answer the peer's close_notify with ours (one SSL_shutdown call: the
    # peer's has arrived, so it returns 1).
    lib.sym[F_v]("ERR_clear_error")()
    print("SSL_shutdown ->", lib.sym[F_i_p]("SSL_shutdown")(ssl))
    _ = flush_out(lib, ssl, stream)
    lib.sym[F_v_p]("SSL_free")(ssl)
    lib.sym[F_v_p]("SSL_CTX_free")(ctx)
    _ = host^
    print("peer exit code", peer.wait(), "|", String(py=peer.stdout.read()).strip())
