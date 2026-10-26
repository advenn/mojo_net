"""T0 spike: a TLS client and server in one process, joined only by memory
BIOs (no sockets), on the environment's OpenSSL, loaded at run time.

    pixi run mojo run -I spikes/tls spikes/tls/pair.mojo build/tls_spike [load-config]

It prints one line per measured fact (docs/spikes.md, "TLS through
OpenSSL"). With `load-config`, OpenSSL is initialised the default way, so an
`OPENSSL_CONF` file takes effect: the contrast run for the isolation check.
"""

from std.ffi import c_int, c_uint
from std.sys import argv

from ffi import (
    F_i_p,
    F_i_pi,
    F_i_ppi,
    F_i_ppnp,
    F_i_ppp,
    F_i_pp,
    F_i_u64p,
    F_l_p,
    F_l_pilp,
    F_p,
    F_p_p,
    F_p_pp,
    F_p_ppp,
    F_u64,
    F_u64_pu64,
    F_v,
    F_v_p,
    F_v_pip,
    F_v_pp,
    F_v_pu,
    Lib,
    cstr,
    from_cstr,
)

comptime ErrStrFn = def(UInt64, UnsafePointer[UInt8, MutAnyOrigin], Int) thin abi("C") -> None

comptime SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
comptime SSL_CTRL_SET_MIN_PROTO_VERSION = 123
comptime SSL_CTRL_GET_MIN_PROTO_VERSION = 130
comptime SSL_CTRL_SET_GROUPS_LIST = 92
comptime BIO_C_SET_BUF_MEM_EOF_RETURN = 130
comptime TLS1_2_VERSION = 771
comptime SSL_VERIFY_PEER = 1
comptime SSL_VERIFY_NONE = 0
comptime SSL_ERROR_NONE = 0
comptime SSL_ERROR_SSL = 1
comptime SSL_ERROR_WANT_READ = 2
comptime SSL_ERROR_ZERO_RETURN = 6
comptime SSL_OP_NO_RENEGOTIATION: UInt64 = 1073741824
comptime SSL_OP_NO_COMPRESSION: UInt64 = 131072
comptime X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 4
comptime X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 32
comptime OPENSSL_INIT_NO_LOAD_CONFIG: UInt64 = 128
comptime OPENSSL_INIT_LOAD_CONFIG: UInt64 = 64


struct Ossl(Movable):
    var lib: Lib

    def __init__(out self) raises:
        self.lib = Lib.beside_runtime("libssl.so.3")

    def clear(self) raises:
        self.lib.sym[F_v]("ERR_clear_error")()

    def last_error(self) raises -> String:
        """The oldest queued error as text, and the queue drained. The
        buffer goes to C as a typed mutable pointer: passed as a bare `Int`
        address, the compiler read back its zero fill (T0 finding)."""
        var e = self.lib.sym[F_u64]("ERR_get_error")()
        var out = String()
        if e != 0:
            var buf = List[UInt8](length=256, fill=0)
            self.lib.sym[ErrStrFn]("ERR_error_string_n")(e, buf.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](), len(buf))
            var n = 0
            while n < len(buf) and buf[n] != 0:
                n += 1
            out = String(unsafe_from_utf8=Span(buf)[0:n])
        while self.lib.sym[F_u64]("ERR_get_error")() != 0:
            pass
        return out^


struct Mem(Movable):
    """A memory BIO, owned by its SSL once set (SSL_set0_*bio)."""

    var bio: Int

    def __init__(out self, o: Ossl) raises:
        self.bio = o.lib.sym[F_p_p]("BIO_new")(o.lib.sym[F_p]("BIO_s_mem")())


def ctrl(o: Ossl, ctx_fn: StringSlice, obj: Int, cmd: Int, larg: Int, parg: Int) raises -> Int:
    return o.lib.sym[F_l_pilp](ctx_fn)(obj, c_int(cmd), larg, parg)


def make_ctx(o: Ossl, libctx: Int, server: Bool, dir: String, ca: StringSlice) raises -> Int:
    var method = o.lib.sym[F_p](String("TLS_server_method") if server else String("TLS_client_method"))()
    var ctx = o.lib.sym[F_p_ppp]("SSL_CTX_new_ex")(libctx, 0, method)
    if ctx == 0:
        raise Error("SSL_CTX_new_ex: " + o.last_error())
    print("    min proto before setting it:", ctrl(o, "SSL_CTX_ctrl", ctx, SSL_CTRL_GET_MIN_PROTO_VERSION, 0, 0),
          "| security level before:", o.lib.sym[F_i_p]("SSL_CTX_get_security_level")(ctx))
    if ctrl(o, "SSL_CTX_ctrl", ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, 0) != 1:
        raise Error("min proto")
    _ = o.lib.sym[F_u64_pu64]("SSL_CTX_set_options")(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION)
    var groups = cstr("X25519MLKEM768:X25519:P-256:P-384")
    if ctrl(o, "SSL_CTX_ctrl", ctx, SSL_CTRL_SET_GROUPS_LIST, 0, Int(groups.unsafe_ptr())) != 1:
        raise Error("groups: " + o.last_error())
    _ = groups^
    if server:
        var chain = cstr(dir + "/server.pem")
        var key = cstr(dir + "/server.key")
        if o.lib.sym[F_i_pp]("SSL_CTX_use_certificate_chain_file")(ctx, Int(chain.unsafe_ptr())) != 1:
            raise Error("chain: " + o.last_error())
        if o.lib.sym[F_i_ppi]("SSL_CTX_use_PrivateKey_file")(ctx, Int(key.unsafe_ptr()), c_int(1)) != 1:
            raise Error("key: " + o.last_error())
        if o.lib.sym[F_i_p]("SSL_CTX_check_private_key")(ctx) != 1:
            raise Error("key mismatch")
        _ = chain^
        _ = key^
    else:
        var cafile = cstr(dir + "/" + ca)
        if o.lib.sym[F_i_ppp]("SSL_CTX_load_verify_locations")(ctx, Int(cafile.unsafe_ptr()), 0) != 1:
            raise Error("CA: " + o.last_error())
        _ = cafile^
    return ctx


def pump(o: Ossl, from_ssl: Int, to_ssl: Int) raises -> Int:
    """Move every byte `from_ssl` has written into `to_ssl`'s read BIO."""
    var wbio = o.lib.sym[F_p_p]("SSL_get_wbio")(from_ssl)
    var rbio = o.lib.sym[F_p_p]("SSL_get_rbio")(to_ssl)
    var buf = List[UInt8](length=16384, fill=0)
    var moved = 0
    while True:
        var n = o.lib.sym[F_i_ppi]("BIO_read")(wbio, Int(buf.unsafe_ptr()), c_int(len(buf)))
        if n <= 0:
            break
        var w = o.lib.sym[F_i_ppi]("BIO_write")(rbio, Int(buf.unsafe_ptr()), n)
        if w != n:
            raise Error("BIO_write short")
        moved += Int(n)
    return moved


@fieldwise_init
struct Outcome(Movable):
    var ok: Bool
    var verify: Int
    var error: String
    var detail: String


def connect(
    o: Ossl, cctx: Int, sctx: Int, verify: Bool, host: StringSlice, ip: StringSlice, sni: StringSlice, mut data_check: Bool
) raises -> Outcome:
    var c = o.lib.sym[F_p_p]("SSL_new")(cctx)
    var s = o.lib.sym[F_p_p]("SSL_new")(sctx)
    for ssl in [c, s]:
        var r = Mem(o)
        var w = Mem(o)
        o.lib.sym[F_v_pp]("SSL_set0_rbio")(ssl, r.bio)
        o.lib.sym[F_v_pp]("SSL_set0_wbio")(ssl, w.bio)
    o.lib.sym[F_v_p]("SSL_set_connect_state")(c)
    o.lib.sym[F_v_p]("SSL_set_accept_state")(s)
    o.lib.sym[F_v_pip]("SSL_set_verify")(c, c_int(SSL_VERIFY_PEER if verify else SSL_VERIFY_NONE), 0)
    var param = o.lib.sym[F_p_p]("SSL_get0_param")(c)
    o.lib.sym[F_v_pu]("X509_VERIFY_PARAM_set_hostflags")(
        param, c_uint(X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT)
    )
    var h = cstr(host)
    var sn = cstr(sni)
    var ipb = cstr(ip)
    if host.byte_length() > 0 or ip.byte_length() == 0:
        # (also for "", to show what an empty name does)
        var rc = o.lib.sym[F_i_ppp]("X509_VERIFY_PARAM_set1_host")(param, Int(h.unsafe_ptr()), host.byte_length())
        print("    set1_host(", repr(host), ") ->", rc)
    if ip.byte_length() > 0:
        var rc = o.lib.sym[F_i_pp]("X509_VERIFY_PARAM_set1_ip_asc")(param, Int(ipb.unsafe_ptr()))
        print("    set1_ip_asc(", repr(ip), ") ->", rc)
    if sni.byte_length() > 0:
        _ = ctrl(o, "SSL_ctrl", c, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, Int(sn.unsafe_ptr()))
    var c_done = False
    var s_done = False
    var failed = String()
    for _ in range(20):
        if not c_done:
            o.clear()
            var rc = o.lib.sym[F_i_p]("SSL_do_handshake")(c)
            if rc == 1:
                c_done = True
            else:
                var e = o.lib.sym[F_i_pi]("SSL_get_error")(c, rc)
                if e != SSL_ERROR_WANT_READ:
                    failed = String("client SSL_get_error ", e, ": ", o.last_error())
        _ = pump(o, c, s)
        if failed:
            break
        if not s_done:
            o.clear()
            var rc = o.lib.sym[F_i_p]("SSL_do_handshake")(s)
            if rc == 1:
                s_done = True
            else:
                var e = o.lib.sym[F_i_pi]("SSL_get_error")(s, rc)
                if e != SSL_ERROR_WANT_READ:
                    failed = String("server SSL_get_error ", e, ": ", o.last_error())
        _ = pump(o, s, c)
        if (c_done and s_done) or failed:
            break
    var vr = o.lib.sym[F_l_p]("SSL_get_verify_result")(c)
    var detail = String()
    if c_done and s_done:
        var version = from_cstr(o.lib.sym[F_p_p]("SSL_get_version")(c))
        var cipher = from_cstr(o.lib.sym[F_p_p]("SSL_CIPHER_get_name")(o.lib.sym[F_p_p]("SSL_get_current_cipher")(c)))
        var group = from_cstr(o.lib.sym[F_p_p]("SSL_get0_group_name")(c))
        var peer = o.lib.sym[F_p_p]("SSL_get0_peer_certificate")(c)
        var peername = from_cstr(o.lib.sym[F_p_p]("SSL_get0_peername")(c))
        detail = String(version, " ", cipher, " ", group, " peer_cert=", peer != 0, " peername=", repr(peername))
        if data_check:
            data_check = exchange(o, c, s)
    _ = h^
    _ = sn^
    _ = ipb^
    o.lib.sym[F_v_p]("SSL_free")(c)
    o.lib.sym[F_v_p]("SSL_free")(s)
    return Outcome(c_done and s_done, vr, failed^, detail^)


def exchange(o: Ossl, c: Int, s: Int) raises -> Bool:
    """Application data both ways, then a close_notify, then a cut."""
    var msg = List[UInt8]("hello over memory BIOs".as_bytes())
    var n = List[Int](length=1, fill=0)
    o.clear()
    if o.lib.sym[F_i_ppnp]("SSL_write_ex")(c, Int(msg.unsafe_ptr()), len(msg), Int(n.unsafe_ptr())) != 1:
        return False
    _ = pump(o, c, s)
    var buf = List[UInt8](length=4096, fill=0)
    o.clear()
    if o.lib.sym[F_i_ppnp]("SSL_read_ex")(s, Int(buf.unsafe_ptr()), len(buf), Int(n.unsafe_ptr())) != 1:
        print("    server read failed:", o.last_error())
        return False
    var got = String(unsafe_from_utf8=Span(buf)[0 : n[0]])
    print("    server got:", repr(got))
    # The server's TLS 1.3 tickets reach the client on its next read.
    _ = pump(o, s, c)
    o.clear()
    var rc = o.lib.sym[F_i_ppnp]("SSL_read_ex")(c, Int(buf.unsafe_ptr()), len(buf), Int(n.unsafe_ptr()))
    print("    client read with only tickets queued: rc", rc, "error", o.lib.sym[F_i_pi]("SSL_get_error")(c, rc))
    # A cut: the server writes, the client's input then ends without close_notify.
    var reply = List[UInt8]("partial".as_bytes())
    o.clear()
    _ = o.lib.sym[F_i_ppnp]("SSL_write_ex")(s, Int(reply.unsafe_ptr()), len(reply), Int(n.unsafe_ptr()))
    _ = pump(o, s, c)
    var rbio = o.lib.sym[F_p_p]("SSL_get_rbio")(c)
    _ = ctrl(o, "BIO_ctrl", rbio, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, 0)
    o.clear()
    rc = o.lib.sym[F_i_ppnp]("SSL_read_ex")(c, Int(buf.unsafe_ptr()), len(buf), Int(n.unsafe_ptr()))
    print("    client read before the cut: rc", rc, "bytes", n[0])
    o.clear()
    rc = o.lib.sym[F_i_ppnp]("SSL_read_ex")(c, Int(buf.unsafe_ptr()), len(buf), Int(n.unsafe_ptr()))
    var e = o.lib.sym[F_i_pi]("SSL_get_error")(c, rc)
    print("    client read at the cut: rc", rc, "SSL_get_error", e, "->", o.last_error())
    _ = msg^
    _ = reply^
    return e == SSL_ERROR_SSL


def main() raises:
    var args = argv()
    var dir = String(args[1])
    var load_config = len(args) > 2 and String(args[2]) == "load-config"
    var o = Ossl()
    print("version:", from_cstr(o.lib.sym[def(c_int) thin abi("C") -> Int]("OpenSSL_version")(c_int(0))))
    print("OPENSSLDIR:", from_cstr(o.lib.sym[def(c_int) thin abi("C") -> Int]("OpenSSL_version")(c_int(4))))
    print("libssl from:", o.lib.path_of("SSL_new"))
    print("libcrypto from:", o.lib.path_of("ERR_get_error"))
    var init = OPENSSL_INIT_LOAD_CONFIG if load_config else OPENSSL_INIT_NO_LOAD_CONFIG
    print("OPENSSL_init_ssl(", "LOAD_CONFIG" if load_config else "NO_LOAD_CONFIG", ") ->", o.lib.sym[F_i_u64p]("OPENSSL_init_ssl")(init, 0))
    var libctx = o.lib.sym[F_p]("OSSL_LIB_CTX_new")()
    var dflt = cstr("default")
    var legacy = cstr("legacy")
    var prov = o.lib.sym[F_p_pp]("OSSL_PROVIDER_load")(libctx, Int(dflt.unsafe_ptr()))
    print("legacy provider in the private context:", o.lib.sym[F_i_pp]("OSSL_PROVIDER_available")(libctx, Int(legacy.unsafe_ptr())))
    print("legacy provider in the default context:", o.lib.sym[F_i_pp]("OSSL_PROVIDER_available")(0, Int(legacy.unsafe_ptr())))
    _ = dflt^
    _ = legacy^
    print("client context:")
    var cctx = make_ctx(o, libctx, False, dir, "ca.pem")
    print("server context:")
    var sctx = make_ctx(o, libctx, True, dir, "")
    var other = make_ctx(o, libctx, False, dir, "other_ca.pem")

    var check = True
    var cases = List[Tuple[String, Bool, String, String, String, Bool]]()
    #             name                        verify host           ip            sni          ctx=other
    cases.append(("good host", True, "localhost", "", "localhost", False))
    cases.append(("wrong host", True, "evil.example", "", "evil.example", False))
    cases.append(("unrelated CA", True, "localhost", "", "localhost", True))
    cases.append(("IP target", True, "", "127.0.0.1", "", False))
    cases.append(("wrong IP", True, "", "127.0.0.2", "", False))
    cases.append(("empty host (silent)", True, "", "", "", False))
    cases.append(("VERIFY_NONE, unrelated CA (silent)", False, "localhost", "", "localhost", True))
    for i in range(len(cases)):
        ref k = cases[i]
        print("case", k[0] + ":")
        var dc = i == 0
        var r = connect(o, other if k[5] else cctx, sctx, k[1], k[2], k[3], k[4], dc)
        print("    handshake ok:", r.ok, "| verify result:", r.verify, "|", r.detail if r.ok else r.error)
        if i == 0:
            print("    truncation reported as SSL_ERROR_SSL:", dc)
    o.lib.sym[F_v_p]("SSL_CTX_free")(cctx)
    o.lib.sym[F_v_p]("SSL_CTX_free")(sctx)
    o.lib.sym[F_v_p]("SSL_CTX_free")(other)
    # The provider is a reference of its own: freeing the context does not
    # drop it (ASan found the leak).
    _ = o.lib.sym[F_i_p]("OSSL_PROVIDER_unload")(prov)
    o.lib.sym[F_v_p]("OSSL_LIB_CTX_free")(libctx)
    _ = check
