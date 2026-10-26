"""OpenSSL, loaded at run time: the only module in `src/` that calls C
(rule TL7 of docs/research/tls_with_openssl.md; docs/tls.md, "FFI").

How (docs/spikes.md, "TLS through OpenSSL" has the measurements):
- **Which library.** `libssl.so.3` is opened by absolute path from the
  directory the Mojo runtime library was mapped from (/proc/self/maps):
  the program's own environment, where the `openssl` 3.5 package sits. A
  bare `dlopen("libssl.so.3")` searches from its caller, and under
  AddressSanitizer it found the host's OpenSSL instead. The version must be
  3.5 or later in the 3.x line (TL3), and the version text and path are
  kept for diagnostics.
- **How it is called.** `std.ffi.OwnedDLHandle` opens it (RTLD_NOW |
  RTLD_NODELETE: it is never unloaded, TB5) and `get_symbol` gives each
  function's address once, kept as a typed C function pointer. No linker
  flags, and a missing symbol is an error at load, not a crash later.
  `dlopen`/`dlsym` are not declared here: the standard library declares
  them, and a second declaration breaks programs that also use Python.
- **Argument types.** OpenSSL objects (`SSL*`, `SSL_CTX*`, `BIO*`,
  `X509*`) travel as `Obj` (an `Int` address: Mojo never dereferences
  them, and 0 is NULL, which Mojo 1.2's non-nullable pointers cannot
  hold). Every buffer C reads or writes travels as a typed mutable pointer
  (`Buf`, `SizeOut`), never as an address: passed as an `Int`, the
  compiler read a buffer C had written back as its old contents (T0).
- **One callback** (TS5): `alpn_select`, a server's ALPN choice, the only
  Mojo function libssl calls. It reads its arguments and nothing else.
- **Initialisation.** `OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG)` is
  the first call, so no `openssl.cnf` is read (TL4), and contexts are made
  in a private `OSSL_LIB_CTX` with only the default provider. A config
  that something else in the process loaded first still reaches
  `SSL_CTX_new_ex` (T0), so `tls.config` sets every policy knob itself.
"""

from std.ffi import OwnedDLHandle, c_int, c_uint
from std.memory import ArcPointer
from std.sys import get_defined_bool

from linux import ErrorKind, IoError
from linux.fs import read_file

from .consts import (
    ERR_LIB_MASK,
    ERR_LIB_OFFSET,
    ERR_LIB_SSL,
    ERR_REASON_MASK,
    ERR_SYSTEM_FLAG,
    OPENSSL_DIR,
    OPENSSL_INIT_NO_LOAD_CONFIG,
    OPENSSL_VERSION,
    SSL_R_NO_APPLICATION_PROTOCOL,
    SSL_TLSEXT_ERR_ALERT_FATAL,
    SSL_TLSEXT_ERR_OK,
)

comptime Obj = Int
"""An OpenSSL object's address (0: NULL)."""
comptime Buf = Pointer[UInt8, MutAnyOrigin]
"""A buffer C reads or writes (strings are NUL-terminated `Buf`s)."""
comptime SizeOut = Pointer[Int, MutAnyOrigin]
"""A `size_t *` (or `const unsigned char **`) out-parameter."""
comptime U32Out = Pointer[UInt32, MutAnyOrigin]
"""An `unsigned int *` out-parameter."""
comptime I32Out = Pointer[Int32, MutAnyOrigin]
"""An `int *` out-parameter."""

comptime _RTLD_NOW = 2
comptime _RTLD_NODELETE = 0x1000
comptime _RUNTIME_LIB = "libKGENCompilerRTShared.so"
comptime _LIBSSL = "libssl.so.3"
comptime _LIBCRYPTO = "libcrypto.so.3"
comptime MIN_VERSION: UInt64 = 0x30500090
"""The floor: OpenSSL 3.5.9 on the 3.5 LTS line, the first with every fix
TL1 names (TL1, TL3). The low nibbles are the patch: 3.5.9 is 0x30500090."""
comptime _NEXT_MAJOR: UInt64 = 0x40000000
"""4.x has a new soname and is not bound here."""

# ---- fault seams (test builds only; gate TG6) -------------------------------

comptime _FAULTS = get_defined_bool["MOJO_NET_FAULTS"]()
"""As in `linux.syscall`: normal builds never import `linux.fault`."""

comptime SEAM_VERSION = 1000
"""`Library`: the loaded OpenSSL reports version 3.4."""
comptime SEAM_CTX_NEW = 1001
"""`SSL_CTX_new_ex` returns NULL."""
comptime SEAM_READBACK = 1002
"""`tls.config`: the options read back differ from those set."""
comptime SEAM_SSL_NEW = 1003
"""`SSL_new` returns NULL."""
comptime SEAM_BIO_NEW = 1004
"""`BIO_new` returns NULL (the read BIO)."""
comptime SEAM_BIO_WRITE = 1005
"""`BIO_write_ex` fails."""
comptime SEAM_HANDSHAKE = 1006
"""`SSL_do_handshake` is not called and fails, as `SSL_get_error` says the
injected value."""
comptime SEAM_READ = 1007
"""`SSL_read_ex` is not called and fails, as `SSL_get_error` says the
injected value."""
comptime SEAM_WRITE = 1008
"""`SSL_write_ex` is not called and fails, as `SSL_get_error` says the
injected value."""
comptime SEAM_PEER_CERT = 1009
"""The gate: `SSL_get0_peer_certificate` returns NULL."""
comptime SEAM_VERIFY_RESULT = 1010
"""The gate: `SSL_get_verify_result` returns the injected value."""
comptime SEAM_CHECK_HOST = 1011
"""The gate: `X509_check_host` does not match."""
comptime SEAM_CHECK_IP = 1012
"""The gate: `X509_check_ip` does not match."""
comptime SEAM_PEERNAME = 1013
"""The gate: `SSL_get0_peername` returns NULL."""
comptime SEAM_VERSION_LOW = 1014
"""The gate: `SSL_version` says TLS 1.0."""
comptime SEAM_REUSED = 1015
"""The gate: `SSL_session_reused` says a session was resumed."""
comptime SEAM_ALPN = 1016
"""The gate: the server's ALPN choice is "h3", which nobody offers."""
comptime SEAM_TRANSMIT_FULL = 1017
"""`_encrypt`: the transmit queue counts as full (each check of its room
is a call)."""
comptime SEAM_WBIO_NEW = 1018
"""`BIO_new` returns NULL (the write BIO)."""
comptime SEAM_SNI = 1019
"""Setting the SNI name fails."""
comptime SEAM_SET_HOST = 1020
"""`X509_VERIFY_PARAM_set1_host` (or `set1_ip`) fails."""
comptime SEAM_ALPN_SET = 1021
"""`SSL_CTX_set_alpn_protos` fails."""
comptime SEAM_LOAD_VERIFY = 1022
"""`SSL_CTX_load_verify_file` (or `_dir`) fails."""
comptime SEAM_LIBCTX = 1023
"""`Library`: 1, `OSSL_LIB_CTX_new` returns NULL; 2, the default provider
does not load."""
comptime SEAM_CHAIN = 1024
"""`SSL_CTX_use_certificate_chain_file` fails."""
comptime SEAM_KEY = 1025
"""`SSL_CTX_use_PrivateKey_file` fails."""
comptime SEAM_KEY_MATCH = 1026
"""`SSL_CTX_check_private_key` says the key does not match."""
comptime SEAM_LEAF = 1027
"""`SSL_CTX_get0_certificate` returns NULL."""
comptime SEAM_TICKETS = 1028
"""A server context: the ticket count read back is 2."""
comptime SEAM_EARLY = 1029
"""A server context: the early data limit read back is 16384."""
comptime SEAM_TIME = 1030
"""`ASN1_TIME_diff` fails."""
comptime SEAM_SERVER_NAME = 1031
"""The server's gate: the client's SNI reads as "unknown.invalid".
(Seams go up to 1099: `linux.fault`'s table.)"""


@always_inline
def seam(n: Int) -> Int:
    """Under `-D MOJO_NET_FAULTS=1`, the value a `linux.fault.inject` rule
    for seam `n` fires with (0: none); otherwise 0, and nothing to call.
    Each seam above says what a firing means."""
    comptime if _FAULTS:
        from linux.fault import fire

        return fire(n)
    return 0


def buf(mut b: List[UInt8]) -> Buf:
    """`b`'s storage as a `Buf` (the caller keeps `b` alive across the call)."""
    return b.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


def in_buf(data: Span[UInt8, _]) -> Buf:
    """Bytes C only reads (a `const` parameter); `data`'s owner stays alive
    across the call."""
    return data.unsafe_ptr().unsafe_mut_cast[True]().unsafe_origin_cast[MutAnyOrigin]()


def out_buf(data: MutSpan[UInt8, _]) -> Buf:
    """Bytes C writes."""
    return data.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


def i32_out(mut b: List[Int32]) -> I32Out:
    return b.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


def size_out(mut b: List[Int]) -> SizeOut:
    return b.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


def u32_out(mut b: List[UInt32]) -> U32Out:
    return b.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


def c_string(s: StringSlice, op: StaticString) raises IoError -> List[UInt8]:
    """`s` NUL-terminated, for C. `InvalidInput` if `s` holds a NUL, which C
    would read as the end (a name cut short there is a different name)."""
    var out = List[UInt8](capacity=s.byte_length() + 1)
    for b in s.as_bytes():
        if b == 0:
            raise IoError.of_kind(op, ErrorKind.InvalidInput)
        out.append(b)
    out.append(0)
    return out^


def from_c_string(addr: Obj) -> String:
    """A copy of the NUL-terminated string C owns at `addr` ("" for NULL);
    bytes that are not UTF-8 are replaced."""
    if addr == 0:
        return String()
    var p = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=addr)
    var out = List[UInt8]()
    var n = 0
    while p[unsafe_offset=n] != 0:
        out.append(p[unsafe_offset=n])
        n += 1
    return String(from_utf8_lossy=Span(out))


def is_alpn_refusal(e: UInt64) -> Bool:
    """Whether the error-queue code `e` is libssl's "no application
    protocol" (ERR_GET_LIB and ERR_GET_REASON are inline functions)."""
    if e == 0 or e & ERR_SYSTEM_FLAG != 0:
        return False
    return Int((e >> ERR_LIB_OFFSET) & ERR_LIB_MASK) == ERR_LIB_SSL and Int(e & ERR_REASON_MASK) == SSL_R_NO_APPLICATION_PROTOCOL


# ---- the one callback (TS5) ----------------------------------------------------

comptime AlpnSelect = def(Obj, SizeOut, Buf, Buf, c_uint, Obj) thin abi("C") -> c_int
"""`SSL_CTX_alpn_select_cb_func`."""


def alpn_select(ssl: Obj, chosen: SizeOut, chosen_len: Buf, offered: Buf, offered_len: c_uint, prefs: Obj) abi("C") -> c_int:
    """A server's ALPN choice, called by libssl inside `SSL_do_handshake`
    when the client offers protocols: the first of the server's (`prefs`,
    the address of a buffer holding the wire list's length in two bytes,
    big-endian, then the list) that the client offered, matched as bytes.
    `chosen` points into the client's list, which libssl copies on return.
    None in common, or a malformed list: a fatal no_application_protocol
    alert (RFC 7301 3.2; ALPACA, RFC 9325). It reads its arguments only:
    it never raises, allocates, or touches any other state."""
    var mine = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=prefs)
    var mine_end = 2 + ((Int(mine[unsafe_offset=0]) << 8) | Int(mine[unsafe_offset=1]))
    var n = Int(offered_len)
    var i = 2
    while i < mine_end:
        var want = Int(mine[unsafe_offset=i])
        var j = 0
        while j < n:
            var have = Int(offered[unsafe_offset=j])
            if have == 0 or j + 1 + have > n:
                return SSL_TLSEXT_ERR_ALERT_FATAL  # (libssl checks the list first)
            if have == want:
                var k = 0
                while k < want and offered[unsafe_offset=j + 1 + k] == mine[unsafe_offset=i + 1 + k]:
                    k += 1
                if k == want:
                    chosen[] = Int(offered) + j + 1
                    chosen_len[] = UInt8(want)
                    return SSL_TLSEXT_ERR_OK
            j += 1 + have
        i += 1 + want
    return SSL_TLSEXT_ERR_ALERT_FATAL


def runtime_dir() raises IoError -> String:
    """The directory the Mojo runtime library was mapped from."""
    return _dir_of(mapped_path(_RUNTIME_LIB))


def mapped_path(file_name: StaticString) raises IoError -> String:
    """The path the first mapping of `file_name` in /proc/self/maps comes
    from (searched as bytes: other mappings' names need not be UTF-8)."""
    var maps = read_file("/proc/self/maps", "tls: /proc/self/maps")
    var want = String("/", file_name)
    var w = want.as_bytes()
    var start = 0
    var n = len(maps)
    while start < n:
        var end = start
        while end < n and maps[end] != 10:
            end += 1
        if end - start >= len(w):
            var tail = True
            for i in range(len(w)):
                if maps[end - len(w) + i] != w[i]:
                    tail = False
                    break
            if tail:
                var slash = start
                while slash < end and maps[slash] != 47:
                    slash += 1
                return String(from_utf8_lossy=Span(maps)[slash:end])
        start = end + 1
    raise IoError.of_kind("tls: a library expected in this process is not mapped", ErrorKind.NotFound)


def _dir_of(path: String) -> String:
    var i = path.rfind("/")
    return String(path[byte=0:i]) if i > 0 else String()


# ---- C signatures (LP64: long and size_t are Int, int is c_int) -------------

comptime _F_u64 = def() thin abi("C") -> UInt64
comptime _F_o = def() thin abi("C") -> Obj
comptime _F_v = def() thin abi("C") -> None
comptime _F_o_i = def(c_int) thin abi("C") -> Obj
comptime _F_o_o = def(Obj) thin abi("C") -> Obj
comptime _F_o_oi = def(Obj, c_int) thin abi("C") -> Obj
comptime _F_v_o = def(Obj) thin abi("C") -> None
comptime _F_i_o = def(Obj) thin abi("C") -> c_int
comptime _F_l_o = def(Obj) thin abi("C") -> Int
comptime _F_u64_o = def(Obj) thin abi("C") -> UInt64
comptime _F_u64_ou64 = def(Obj, UInt64) thin abi("C") -> UInt64
comptime _F_i_ou64 = def(Obj, UInt64) thin abi("C") -> c_int
comptime _F_v_oi = def(Obj, c_int) thin abi("C") -> None
comptime _F_i_oi = def(Obj, c_int) thin abi("C") -> c_int
comptime _F_v_oo = def(Obj, Obj) thin abi("C") -> None
comptime _F_o_ob = def(Obj, Buf) thin abi("C") -> Obj
comptime _F_i_ob = def(Obj, Buf) thin abi("C") -> c_int
comptime _F_o_ooo = def(Obj, Obj, Obj) thin abi("C") -> Obj
comptime _F_l_oilo = def(Obj, c_int, Int, Obj) thin abi("C") -> Int
comptime _F_l_oilb = def(Obj, c_int, Int, Buf) thin abi("C") -> Int
comptime _F_v_oio = def(Obj, c_int, Obj) thin abi("C") -> None
comptime _F_i_obo = def(Obj, Buf, Obj) thin abi("C") -> c_int
comptime _F_i_oob = def(Obj, Obj, Buf) thin abi("C") -> c_int
comptime _F_i_obl = def(Obj, Buf, Int) thin abi("C") -> c_int
comptime _F_i_obu = def(Obj, Buf, c_uint) thin abi("C") -> c_int
comptime _F_v_ou = def(Obj, c_uint) thin abi("C") -> None
comptime _F_u_o = def(Obj) thin abi("C") -> c_uint
comptime _F_i_u64o = def(UInt64, Obj) thin abi("C") -> c_int
comptime _F_v_u64bl = def(UInt64, Buf, Int) thin abi("C") -> None
comptime _F_o_l = def(Int) thin abi("C") -> Obj
comptime _F_i_obls = def(Obj, Buf, Int, SizeOut) thin abi("C") -> c_int
comptime _F_i_oblub = def(Obj, Buf, Int, c_uint, Obj) thin abi("C") -> c_int
comptime _F_i_oblu = def(Obj, Buf, Int, c_uint) thin abi("C") -> c_int
comptime _F_v_osu = def(Obj, SizeOut, U32Out) thin abi("C") -> None
comptime _F_v_bl = def(Buf, Int) thin abi("C") -> None
comptime _F_i_obi = def(Obj, Buf, c_int) thin abi("C") -> c_int
comptime _F_v_ob = def(Obj, Buf) thin abi("C") -> None
comptime _F_i_ol = def(Obj, Int) thin abi("C") -> c_int
comptime _F_u32_o = def(Obj) thin abi("C") -> UInt32
comptime _F_i_ccoo = def(I32Out, I32Out, Obj, Obj) thin abi("C") -> c_int
comptime _F_v_oao = def(Obj, AlpnSelect, Obj) thin abi("C") -> None


struct Library(Movable):
    """libssl and libcrypto, loaded once per `Library` (the process keeps
    the code mapped: RTLD_NODELETE), with a private library context and the
    typed entry points the `tls` package calls. Shared through
    `ArcPointer[Library]` by every context and connection built on it, so
    it outlives them (TB1, TB5)."""

    var _handle: OwnedDLHandle
    var path: String
    """The absolute path of the libssl that was loaded."""
    var crypto_path: String
    """The libcrypto it uses: the one beside it, or loading fails."""
    var version: String
    """`OpenSSL_version(OPENSSL_VERSION)`, for diagnostics."""
    var version_number: UInt64
    var openssl_dir: String
    """OPENSSLDIR of the loaded library."""
    var libctx: Obj
    """The private OSSL_LIB_CTX (default provider only)."""
    var _provider: Obj

    # libcrypto
    var OpenSSL_version_num: _F_u64
    var OpenSSL_version: _F_o_i
    var OPENSSL_init_ssl: _F_i_u64o
    var OSSL_LIB_CTX_new: _F_o
    var OSSL_LIB_CTX_free: _F_v_o
    var OSSL_PROVIDER_load: _F_o_ob
    var OSSL_PROVIDER_unload: _F_i_o
    var ERR_clear_error: _F_v
    var ERR_get_error: _F_u64
    var ERR_peek_error: _F_u64
    var ERR_error_string_n: _F_v_u64bl
    var X509_verify_cert_error_string: _F_o_l
    var X509_get_default_cert_file: _F_o
    var X509_STORE_get0_objects: _F_o_o
    var OPENSSL_sk_num: _F_i_o
    var OPENSSL_sk_value: _F_o_oi
    var X509_OBJECT_get_type: _F_i_o
    var X509_VERIFY_PARAM_set_flags: _F_i_ou64
    var X509_VERIFY_PARAM_clear_flags: _F_i_ou64
    var X509_VERIFY_PARAM_get_flags: _F_u64_o
    var X509_VERIFY_PARAM_set_hostflags: _F_v_ou
    var X509_VERIFY_PARAM_get_hostflags: _F_u_o
    var X509_VERIFY_PARAM_set1_host: _F_i_obl
    var X509_VERIFY_PARAM_set1_ip: _F_i_obl
    var X509_check_host: _F_i_oblub
    var X509_check_ip: _F_i_oblu
    var X509_get0_notBefore: _F_o_o
    var X509_get0_notAfter: _F_o_o
    var ASN1_TIME_diff: _F_i_ccoo
    var OPENSSL_cleanse: _F_v_bl
    var BIO_s_mem: _F_o
    var BIO_new: _F_o_o
    var BIO_write_ex: _F_i_obls
    var BIO_read_ex: _F_i_obls
    var BIO_ctrl: _F_l_oilo
    var BIO_ctrl_pending: _F_l_o
    # libssl: contexts
    var TLS_client_method: _F_o
    var SSL_CTX_new_ex: _F_o_ooo
    var SSL_CTX_free: _F_v_o
    var SSL_CTX_ctrl: _F_l_oilo
    var SSL_CTX_ctrl_str: _F_l_oilb
    var SSL_CTX_set_options: _F_u64_ou64
    var SSL_CTX_clear_options: _F_u64_ou64
    var SSL_CTX_get_options: _F_u64_o
    var SSL_CTX_set_security_level: _F_v_oi
    var SSL_CTX_get_security_level: _F_i_o
    var SSL_CTX_set_cipher_list: _F_i_ob
    var SSL_CTX_set_ciphersuites: _F_i_ob
    var SSL_CTX_set_verify: _F_v_oio
    var SSL_CTX_get_verify_mode: _F_i_o
    var SSL_CTX_get0_param: _F_o_o
    var SSL_CTX_get_cert_store: _F_o_o
    var SSL_CTX_load_verify_file: _F_i_ob
    var SSL_CTX_load_verify_dir: _F_i_ob
    var SSL_CTX_set_alpn_protos: _F_i_obu
    # libssl: server contexts
    var TLS_server_method: _F_o
    var SSL_CTX_use_certificate_chain_file: _F_i_ob
    var SSL_CTX_use_PrivateKey_file: _F_i_obi
    var SSL_CTX_check_private_key: _F_i_o
    var SSL_CTX_get0_certificate: _F_o_o
    var SSL_CTX_set_default_passwd_cb_userdata: _F_v_ob
    var SSL_CTX_set_num_tickets: _F_i_ol
    var SSL_CTX_get_num_tickets: _F_l_o
    var SSL_CTX_get_max_early_data: _F_u32_o
    var SSL_CTX_set_alpn_select_cb: _F_v_oao
    # libssl: connections
    var SSL_new: _F_o_o
    var SSL_free: _F_v_o
    var SSL_set0_rbio: _F_v_oo
    var SSL_set0_wbio: _F_v_oo
    var SSL_set_connect_state: _F_v_o
    var SSL_set_accept_state: _F_v_o
    var SSL_get_servername: _F_o_oi
    var SSL_ctrl: _F_l_oilo
    var SSL_ctrl_str: _F_l_oilb
    var SSL_get0_param: _F_o_o
    var SSL_do_handshake: _F_i_o
    var SSL_get_error: _F_i_oi
    var SSL_read_ex: _F_i_obls
    var SSL_write_ex: _F_i_obls
    var SSL_shutdown: _F_i_o
    var SSL_get_verify_result: _F_l_o
    var SSL_get0_peer_certificate: _F_o_o
    var SSL_get0_peername: _F_o_o
    var SSL_version: _F_i_o
    var SSL_get_version: _F_o_o
    var SSL_get_current_cipher: _F_o_o
    var SSL_CIPHER_get_name: _F_o_o
    var SSL_get0_group_name: _F_o_o
    var SSL_get0_alpn_selected: _F_v_osu
    var SSL_session_reused: _F_i_o

    def __init__(out self, path: String) raises IoError:
        """Open `path` (libssl.so.3), check its version, initialise it
        without a config file and make the private library context."""
        try:
            self._handle = OwnedDLHandle(path, _RTLD_NOW | _RTLD_NODELETE)
        except:
            raise IoError.of_kind("tls: cannot load libssl.so.3 (is the openssl 3.5 package installed?)", ErrorKind.NotFound)
        self.path = path
        # libssl finds its libcrypto by soname, so one some other code
        # loaded first (another OpenSSL, through LD_PRELOAD or a library)
        # would be used instead of the one beside it: refuse that (TL3).
        self.crypto_path = mapped_path(_LIBCRYPTO)
        if _dir_of(self.crypto_path) != _dir_of(path):
            raise IoError.of_kind("tls: libssl.so.3 is not using the libcrypto.so.3 beside it (another OpenSSL was loaded first)", ErrorKind.Unsupported)
        self.OpenSSL_version_num = _sym[_F_u64](self._handle, "OpenSSL_version_num")
        self.version_number = self.OpenSSL_version_num() if seam(SEAM_VERSION) == 0 else 0x30400000
        if self.version_number < MIN_VERSION or self.version_number >= _NEXT_MAJOR:
            raise IoError.of_kind("tls: OpenSSL 3.5 or a later 3.x is required", ErrorKind.Unsupported)
        self.OPENSSL_init_ssl = _sym[_F_i_u64o](self._handle, "OPENSSL_init_ssl")
        if self.OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, 0) != 1:
            raise IoError.of_kind("tls: OPENSSL_init_ssl failed", ErrorKind.Other)
        self.OpenSSL_version = _sym[_F_o_i](self._handle, "OpenSSL_version")
        self.version = from_c_string(self.OpenSSL_version(OPENSSL_VERSION))
        self.openssl_dir = from_c_string(self.OpenSSL_version(OPENSSL_DIR))
        self.OSSL_LIB_CTX_new = _sym[_F_o](self._handle, "OSSL_LIB_CTX_new")
        self.OSSL_LIB_CTX_free = _sym[_F_v_o](self._handle, "OSSL_LIB_CTX_free")
        self.OSSL_PROVIDER_load = _sym[_F_o_ob](self._handle, "OSSL_PROVIDER_load")
        self.OSSL_PROVIDER_unload = _sym[_F_i_o](self._handle, "OSSL_PROVIDER_unload")
        self.ERR_clear_error = _sym[_F_v](self._handle, "ERR_clear_error")
        self.ERR_get_error = _sym[_F_u64](self._handle, "ERR_get_error")
        self.ERR_peek_error = _sym[_F_u64](self._handle, "ERR_peek_error")
        self.ERR_error_string_n = _sym[_F_v_u64bl](self._handle, "ERR_error_string_n")
        self.X509_verify_cert_error_string = _sym[_F_o_l](self._handle, "X509_verify_cert_error_string")
        self.X509_get_default_cert_file = _sym[_F_o](self._handle, "X509_get_default_cert_file")
        self.X509_STORE_get0_objects = _sym[_F_o_o](self._handle, "X509_STORE_get0_objects")
        self.OPENSSL_sk_num = _sym[_F_i_o](self._handle, "OPENSSL_sk_num")
        self.OPENSSL_sk_value = _sym[_F_o_oi](self._handle, "OPENSSL_sk_value")
        self.X509_OBJECT_get_type = _sym[_F_i_o](self._handle, "X509_OBJECT_get_type")
        self.X509_VERIFY_PARAM_set_flags = _sym[_F_i_ou64](self._handle, "X509_VERIFY_PARAM_set_flags")
        self.X509_VERIFY_PARAM_clear_flags = _sym[_F_i_ou64](self._handle, "X509_VERIFY_PARAM_clear_flags")
        self.X509_VERIFY_PARAM_get_flags = _sym[_F_u64_o](self._handle, "X509_VERIFY_PARAM_get_flags")
        self.X509_VERIFY_PARAM_set_hostflags = _sym[_F_v_ou](self._handle, "X509_VERIFY_PARAM_set_hostflags")
        self.X509_VERIFY_PARAM_get_hostflags = _sym[_F_u_o](self._handle, "X509_VERIFY_PARAM_get_hostflags")
        self.X509_VERIFY_PARAM_set1_host = _sym[_F_i_obl](self._handle, "X509_VERIFY_PARAM_set1_host")
        self.X509_VERIFY_PARAM_set1_ip = _sym[_F_i_obl](self._handle, "X509_VERIFY_PARAM_set1_ip")
        self.X509_check_host = _sym[_F_i_oblub](self._handle, "X509_check_host")
        self.X509_check_ip = _sym[_F_i_oblu](self._handle, "X509_check_ip")
        self.X509_get0_notBefore = _sym[_F_o_o](self._handle, "X509_get0_notBefore")
        self.X509_get0_notAfter = _sym[_F_o_o](self._handle, "X509_get0_notAfter")
        self.ASN1_TIME_diff = _sym[_F_i_ccoo](self._handle, "ASN1_TIME_diff")
        self.OPENSSL_cleanse = _sym[_F_v_bl](self._handle, "OPENSSL_cleanse")
        self.BIO_s_mem = _sym[_F_o](self._handle, "BIO_s_mem")
        self.BIO_new = _sym[_F_o_o](self._handle, "BIO_new")
        self.BIO_write_ex = _sym[_F_i_obls](self._handle, "BIO_write_ex")
        self.BIO_read_ex = _sym[_F_i_obls](self._handle, "BIO_read_ex")
        self.BIO_ctrl = _sym[_F_l_oilo](self._handle, "BIO_ctrl")
        self.BIO_ctrl_pending = _sym[_F_l_o](self._handle, "BIO_ctrl_pending")
        self.TLS_client_method = _sym[_F_o](self._handle, "TLS_client_method")
        self.SSL_CTX_new_ex = _sym[_F_o_ooo](self._handle, "SSL_CTX_new_ex")
        self.SSL_CTX_free = _sym[_F_v_o](self._handle, "SSL_CTX_free")
        self.SSL_CTX_ctrl = _sym[_F_l_oilo](self._handle, "SSL_CTX_ctrl")
        self.SSL_CTX_ctrl_str = _sym[_F_l_oilb](self._handle, "SSL_CTX_ctrl")
        self.SSL_CTX_set_options = _sym[_F_u64_ou64](self._handle, "SSL_CTX_set_options")
        self.SSL_CTX_clear_options = _sym[_F_u64_ou64](self._handle, "SSL_CTX_clear_options")
        self.SSL_CTX_get_options = _sym[_F_u64_o](self._handle, "SSL_CTX_get_options")
        self.SSL_CTX_set_security_level = _sym[_F_v_oi](self._handle, "SSL_CTX_set_security_level")
        self.SSL_CTX_get_security_level = _sym[_F_i_o](self._handle, "SSL_CTX_get_security_level")
        self.SSL_CTX_set_cipher_list = _sym[_F_i_ob](self._handle, "SSL_CTX_set_cipher_list")
        self.SSL_CTX_set_ciphersuites = _sym[_F_i_ob](self._handle, "SSL_CTX_set_ciphersuites")
        self.SSL_CTX_set_verify = _sym[_F_v_oio](self._handle, "SSL_CTX_set_verify")
        self.SSL_CTX_get_verify_mode = _sym[_F_i_o](self._handle, "SSL_CTX_get_verify_mode")
        self.SSL_CTX_get0_param = _sym[_F_o_o](self._handle, "SSL_CTX_get0_param")
        self.SSL_CTX_get_cert_store = _sym[_F_o_o](self._handle, "SSL_CTX_get_cert_store")
        self.SSL_CTX_load_verify_file = _sym[_F_i_ob](self._handle, "SSL_CTX_load_verify_file")
        self.SSL_CTX_load_verify_dir = _sym[_F_i_ob](self._handle, "SSL_CTX_load_verify_dir")
        self.SSL_CTX_set_alpn_protos = _sym[_F_i_obu](self._handle, "SSL_CTX_set_alpn_protos")
        self.TLS_server_method = _sym[_F_o](self._handle, "TLS_server_method")
        self.SSL_CTX_use_certificate_chain_file = _sym[_F_i_ob](self._handle, "SSL_CTX_use_certificate_chain_file")
        self.SSL_CTX_use_PrivateKey_file = _sym[_F_i_obi](self._handle, "SSL_CTX_use_PrivateKey_file")
        self.SSL_CTX_check_private_key = _sym[_F_i_o](self._handle, "SSL_CTX_check_private_key")
        self.SSL_CTX_get0_certificate = _sym[_F_o_o](self._handle, "SSL_CTX_get0_certificate")
        self.SSL_CTX_set_default_passwd_cb_userdata = _sym[_F_v_ob](self._handle, "SSL_CTX_set_default_passwd_cb_userdata")
        self.SSL_CTX_set_num_tickets = _sym[_F_i_ol](self._handle, "SSL_CTX_set_num_tickets")
        self.SSL_CTX_get_num_tickets = _sym[_F_l_o](self._handle, "SSL_CTX_get_num_tickets")
        self.SSL_CTX_get_max_early_data = _sym[_F_u32_o](self._handle, "SSL_CTX_get_max_early_data")
        self.SSL_CTX_set_alpn_select_cb = _sym[_F_v_oao](self._handle, "SSL_CTX_set_alpn_select_cb")
        self.SSL_new = _sym[_F_o_o](self._handle, "SSL_new")
        self.SSL_free = _sym[_F_v_o](self._handle, "SSL_free")
        self.SSL_set0_rbio = _sym[_F_v_oo](self._handle, "SSL_set0_rbio")
        self.SSL_set0_wbio = _sym[_F_v_oo](self._handle, "SSL_set0_wbio")
        self.SSL_set_connect_state = _sym[_F_v_o](self._handle, "SSL_set_connect_state")
        self.SSL_set_accept_state = _sym[_F_v_o](self._handle, "SSL_set_accept_state")
        self.SSL_get_servername = _sym[_F_o_oi](self._handle, "SSL_get_servername")
        self.SSL_ctrl = _sym[_F_l_oilo](self._handle, "SSL_ctrl")
        self.SSL_ctrl_str = _sym[_F_l_oilb](self._handle, "SSL_ctrl")
        self.SSL_get0_param = _sym[_F_o_o](self._handle, "SSL_get0_param")
        self.SSL_do_handshake = _sym[_F_i_o](self._handle, "SSL_do_handshake")
        self.SSL_get_error = _sym[_F_i_oi](self._handle, "SSL_get_error")
        self.SSL_read_ex = _sym[_F_i_obls](self._handle, "SSL_read_ex")
        self.SSL_write_ex = _sym[_F_i_obls](self._handle, "SSL_write_ex")
        self.SSL_shutdown = _sym[_F_i_o](self._handle, "SSL_shutdown")
        self.SSL_get_verify_result = _sym[_F_l_o](self._handle, "SSL_get_verify_result")
        self.SSL_get0_peer_certificate = _sym[_F_o_o](self._handle, "SSL_get0_peer_certificate")
        self.SSL_get0_peername = _sym[_F_o_o](self._handle, "SSL_get0_peername")
        self.SSL_version = _sym[_F_i_o](self._handle, "SSL_version")
        self.SSL_get_version = _sym[_F_o_o](self._handle, "SSL_get_version")
        self.SSL_get_current_cipher = _sym[_F_o_o](self._handle, "SSL_get_current_cipher")
        self.SSL_CIPHER_get_name = _sym[_F_o_o](self._handle, "SSL_CIPHER_get_name")
        self.SSL_get0_group_name = _sym[_F_o_o](self._handle, "SSL_get0_group_name")
        self.SSL_get0_alpn_selected = _sym[_F_v_osu](self._handle, "SSL_get0_alpn_selected")
        self.SSL_session_reused = _sym[_F_i_o](self._handle, "SSL_session_reused")
        var forced = seam(SEAM_LIBCTX)
        self.libctx = self.OSSL_LIB_CTX_new() if forced != 1 else 0
        if self.libctx == 0:
            raise IoError.of_kind("tls: OSSL_LIB_CTX_new failed", ErrorKind.OutOfMemory)
        var name = c_string("default", "tls: provider")
        var provider = self.OSSL_PROVIDER_load(self.libctx, buf(name)) if forced != 2 else 0
        _ = name^
        if provider == 0:
            self.OSSL_LIB_CTX_free(self.libctx)  # (no __deinit__ without every field)
            raise IoError.of_kind("tls: the default provider did not load", ErrorKind.Other)
        self._provider = provider
        self.ERR_clear_error()

    def __deinit__(deinit self):
        # Every context and connection holds the ArcPointer, so none is left
        # here. The provider is a reference of its own (T0: freeing the
        # library context does not drop it). The code stays mapped.
        if self._provider != 0:
            _ = self.OSSL_PROVIDER_unload(self._provider)
        if self.libctx != 0:
            self.OSSL_LIB_CTX_free(self.libctx)

    @staticmethod
    def load() raises IoError -> ArcPointer[Library]:
        """The environment's libssl.so.3, beside the Mojo runtime."""
        return ArcPointer(Library(runtime_dir() + "/" + _LIBSSL))

    def drain_errors(self) -> String:
        """Every queued OpenSSL error as text ("; "-separated), leaving the
        thread's queue empty (TB6)."""
        var out = String()
        while True:
            var e = self.ERR_get_error()
            if e == 0:
                return out^
            var b = List[UInt8](length=256, fill=0)
            self.ERR_error_string_n(e, buf(b), len(b))
            var n = 0
            while n < len(b) and b[n] != 0:
                n += 1
            if out.byte_length() > 0:
                out += "; "
            out += String(from_utf8_lossy=Span(b)[0:n])


def _sym[F: TrivialRegisterPassable](h: OwnedDLHandle, name: StaticString) raises IoError -> F:
    """`name`'s address in `h` as a C function of type `F`."""
    var p = h.get_symbol[NoneType](name)
    if not p:
        raise IoError.of_kind("tls: libssl lacks a function this package needs", ErrorKind.Unsupported)
    var addr = Int(p.value())
    return Pointer(to=addr).unsafe_bitcast[F]()[]
