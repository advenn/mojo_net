"""mojson: the json module's API, its parsing and writing done in Mojo.

``import mojson as json`` is meant to change nothing but the speed:
``loads``, ``load``, ``dumps`` and ``dump`` take json's arguments and
give json's results, byte for byte, and json's exceptions
(``JSONDecodeError`` is json's own class). The Mojo extension
(``_mojson``, built from python/mojson/_mojson.mojo) takes the common
cases; whatever it does not, it hands to the standard library's json
unchanged: a custom ``cls``, keyword arguments json would refuse, text
that is not UTF-8, and every input its parser refuses, so that errors
are json's, with json's messages and positions.

Beyond json:

- ``loads(s, rfc8259=True)`` reads strictly by RFC 8259: a key twice in
  one object, NaN and Infinity, and lone surrogates are errors
  (JSONDecodeError), where json accepts them;
- ``loads(s, max_depth=n)``: nesting past ``n`` arrays and objects is a
  JSONDecodeError (json's limit is the recursion limit);
- ``dumpb(obj, **kw)``: ``dumps`` as UTF-8 bytes, without the str;
- ``dumps(obj, extended=True)``: datetime, date and time (ISO 8601),
  UUID, Decimal, Enum, dataclass instances, set and frozenset written
  too, before ``default`` is asked.

Not for production use: see the repository's README.
"""

import dataclasses as _dataclasses
import datetime as _datetime
import decimal as _decimal
import enum as _enum
import functools as _functools
import json as _json
import uuid as _uuid
from json import JSONDecodeError, JSONDecoder, JSONEncoder, decoder, detect_encoding, encoder, scanner

__version__ = "0.1.8"

# The extension, and Mojo's own module setup inside it, read CPython's
# object layout as the GIL build lays it out; the free-threaded build's
# headers differ, and loading it there crashes before any check of its
# own can run. (Its wheels' cpXY-cpXY tags keep pip from installing them
# there; this is for imports by path.)
import sysconfig as _sysconfig

if _sysconfig.get_config_var("Py_GIL_DISABLED"):
    raise ImportError("mojson does not support the free-threaded build of CPython: its extension reads the GIL build's object layout")


def _load_mojo_runtime():
    """Load the Mojo runtime the extension links (libKGENCompilerRTShared.so
    and the two it needs) from the mojo-compiler distribution, wherever it
    is installed. The wheel's extension finds them by its RUNPATH,
    $ORIGIN/../modular/lib, when both are in one site-packages; this is for
    the other layouts (mojson and mojo-compiler in different directories)."""
    import ctypes
    import importlib.metadata

    try:
        dist = importlib.metadata.distribution("mojo-compiler")
    except importlib.metadata.PackageNotFoundError:
        raise ImportError("mojson needs the Mojo runtime: pip install mojo-compiler (the version mojson requires)") from None
    for name in ("libMSupportGlobals.so", "libAsyncRTRuntimeGlobals.so", "libKGENCompilerRTShared.so"):
        ctypes.CDLL(str(dist.locate_file("modular/lib/" + name)), mode=ctypes.RTLD_GLOBAL)


import os as _os
import sys as _sys

# Mojo's module setup (inside the extension's import) looks for a Python
# library to link to, as a Mojo program that embeds Python does. Unless
# MOJO_PYTHON_LIBRARY names an existing file, it runs `python3` from PATH
# (any interpreter, of any version) to find one, and aborts the process
# when there is none. It also exports MOJO_PYTHON_LIBRARY,
# PYTHONEXECUTABLE (the `python3` on PATH) and an empty entry first in
# PYTHONPATH (the current directory) through the C environment, which
# every child process inherits: a child started from a virtualenv's
# `sys.executable` (multiprocessing's workers, say) lost the virtualenv
# and imported from its working directory. Inside an extension the
# library is only checked to exist, never loaded (the C API is the
# running interpreter's), so mojson names the interpreter's own, and puts
# the three back as they were once the extension is loaded.
_MOJO_ENV = ("MOJO_PYTHON_LIBRARY", "PYTHONEXECUTABLE", "PYTHONPATH")


def _own_python_library():
    """The running interpreter's shared library when it has one, else the
    interpreter itself: an existing file either way."""
    libdir = _sysconfig.get_config_var("LIBDIR") or ""
    for name in (_sysconfig.get_config_var("INSTSONAME"), _sysconfig.get_config_var("LDLIBRARY")):
        if name and ".so" in name and _os.path.isfile(_os.path.join(libdir, name)):
            return _os.path.join(libdir, name)
    if _sys.executable and _os.path.isfile(_sys.executable):
        return _sys.executable
    return _os.path.abspath(__file__)


_env_before = {k: _os.environ.get(k) for k in _MOJO_ENV}
try:
    if _env_before["MOJO_PYTHON_LIBRARY"] is None:
        _os.putenv("MOJO_PYTHON_LIBRARY", _own_python_library())  # (the C environment only)
    try:
        from . import _mojson
    except ImportError as e:
        if "libKGENCompilerRTShared" not in str(e):
            raise
        _load_mojo_runtime()
        from . import _mojson
finally:
    for _k, _v in _env_before.items():
        if _v is None:
            _os.unsetenv(_k)
        else:
            _os.putenv(_k, _v)
    del _k, _v

__all__ = ["dump", "dumps", "load", "loads", "JSONDecoder", "JSONDecodeError", "JSONEncoder", "dumpb"]

_codec = _mojson.Codec()


class _Refused(Exception):
    """Raised by the extension for a text it refuses itself (rfc8259,
    max_depth): (reason, byte offset)."""


def _decode_error(s, reason, offset):
    """JSONDecodeError at byte `offset` of `s`, its position in characters."""
    if isinstance(s, (bytes, bytearray)):
        text = bytes(s).decode("utf-8", "surrogatepass")
        pos = len(bytes(s[:offset]).decode("utf-8", "surrogatepass"))
    else:
        text = s
        pos = len(s.encode("utf-8", "surrogatepass")[:offset].decode("utf-8", "surrogatepass"))
    return JSONDecodeError(reason, text, pos)


def _loads_kw(s, *, cls=None, object_hook=None, parse_float=None, parse_int=None, parse_constant=None,
              object_pairs_hook=None, rfc8259=False, max_depth=None, **kw):
    """loads with keyword arguments (the extension calls it)."""
    own = rfc8259 or max_depth is not None
    if (cls is not None and cls is not JSONDecoder) or (set(kw) - {"strict"}):
        if own:
            raise TypeError("rfc8259 and max_depth do not combine with cls or other decoder arguments")
        return _json.loads(s, cls=cls, object_hook=object_hook, parse_float=parse_float, parse_int=parse_int,
                           parse_constant=parse_constant, object_pairs_hook=object_pairs_hook, **kw)
    strict = kw.get("strict", True)
    pf = None if parse_float is float else parse_float
    pi = None if parse_int is int else parse_int
    try:
        r = _codec.loads_with(s, object_hook, object_pairs_hook, pf, pi, parse_constant, bool(strict),
                              bool(rfc8259), max_depth)
    except _Refused as e:
        raise _decode_error(s, e.args[0], e.args[1]) from None
    if r is NotImplemented:
        if rfc8259:
            # (text the parser does not take: not UTF-8 bytes or str, or
            # past 2 GiB; RFC 8259 text is UTF-8)
            if not isinstance(s, (str, bytes, bytearray)):
                raise TypeError(f"the JSON object must be str, bytes or bytearray, not {s.__class__.__name__}")
            raise JSONDecodeError("Not text the strict parser reads (UTF-8, under 2 GiB)", s if isinstance(s, str) else "", 0)
        return _json.loads(s, object_hook=object_hook, parse_float=parse_float, parse_int=parse_int,
                           parse_constant=parse_constant, object_pairs_hook=object_pairs_hook, **kw)
    return r


def _extend(default):
    """`default` with the types `extended=True` writes asked first."""

    def write(o):
        if isinstance(o, (_datetime.datetime, _datetime.date, _datetime.time)):
            return o.isoformat()
        if isinstance(o, _uuid.UUID):
            return str(o)
        if isinstance(o, _decimal.Decimal):
            # (a finite one as its digits, a JSON number; NaN and the
            # infinities as json writes the floats)
            return _Raw(_decimal_text(o)) if o.is_finite() else float(o)
        if isinstance(o, _enum.Enum):
            return o.value
        if _dataclasses.is_dataclass(o) and not isinstance(o, type):
            return {f.name: getattr(o, f.name) for f in _dataclasses.fields(o)}
        if isinstance(o, (set, frozenset)):
            return list(o)
        if default is not None:
            return default(o)
        raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

    return write


class _Raw(str):
    """Text the extension writes as it is: a finite Decimal's digits
    (extended=True)."""

    __slots__ = ()


def _decimal_text(d):
    """A finite Decimal in JSON's number grammar ('1E+2' is '1E+2', but
    '.5' must be '0.5' and '-0' stays '-0')."""
    t = str(d)
    if "E" in t:
        mantissa, exp = t.split("E")
        return mantissa + "e" + exp
    return t


def _dumps_kw(obj, *, skipkeys=False, ensure_ascii=True, check_circular=True, allow_nan=True, cls=None,
              indent=None, separators=None, default=None, sort_keys=False, extended=False, _as_bytes=False,
              _fp=None, **kw):
    """dumps with keyword arguments (the extension calls it); with `_fp`,
    dump: the text written to it, as json.dump writes it, None returned."""
    if cls is not None and cls is not JSONEncoder:
        enc = cls(skipkeys=skipkeys, ensure_ascii=ensure_ascii, check_circular=check_circular,
                  allow_nan=allow_nan, indent=indent, separators=separators, default=default,
                  sort_keys=sort_keys, **kw)
        if type(enc).encode is not JSONEncoder.encode or type(enc).iterencode is not JSONEncoder.iterencode:
            if extended:
                enc.default = _extend(enc.default)
            if _fp is not None:
                for chunk in enc.iterencode(obj):  # (json.dump's own loop)
                    _fp.write(chunk)
                return None
            text = enc.encode(obj)
            return text.encode("utf-8") if _as_bytes else text
        # A subclass that only changes default (or the options): its
        # settings, written here.
        skipkeys, ensure_ascii, check_circular = enc.skipkeys, enc.ensure_ascii, enc.check_circular
        allow_nan, sort_keys, indent = enc.allow_nan, enc.sort_keys, enc.indent
        item_sep, key_sep = enc.item_separator, enc.key_separator
        default = enc.default if type(enc).default is not JSONEncoder.default else default
    else:
        if kw:
            write = _json.dumps if _fp is None else _functools.partial(_json.dump, fp=_fp)
            return write(obj, skipkeys=skipkeys, ensure_ascii=ensure_ascii, check_circular=check_circular,
                         allow_nan=allow_nan, indent=indent, separators=separators, default=default,
                         sort_keys=sort_keys, **kw)
        if separators is not None:
            item_sep, key_sep = separators
        elif indent is not None:
            item_sep, key_sep = ",", ": "
        else:
            item_sep, key_sep = ", ", ": "
    if indent is not None and not isinstance(indent, str):
        indent = " " * indent
    if type(item_sep) is not str or type(key_sep) is not str or (indent is not None and type(indent) is not str):
        # (json's own TypeError for separators that are not str)
        write = _json.dumps if _fp is None else _functools.partial(_json.dump, fp=_fp)
        text = write(obj, skipkeys=skipkeys, ensure_ascii=ensure_ascii, check_circular=check_circular,
                     allow_nan=allow_nan, indent=indent, separators=(item_sep, key_sep), default=default,
                     sort_keys=sort_keys)
        return text.encode("utf-8") if _as_bytes and text is not None else text
    if extended:
        default = _extend(default)
    return _codec.dumps_with(obj, bool(skipkeys), bool(ensure_ascii), bool(check_circular), bool(allow_nan),
                             indent, item_sep, key_sep, default, bool(sort_keys), _as_bytes, _fp)


_codec.set_fallbacks(_json.loads, _loads_kw, _dumps_kw, _Refused, _Raw)

loads = _codec.loads
dumps = _codec.dumps


def load(fp, **kw):
    """Read `fp` (`fp.read()`) as loads reads text."""
    return loads(fp.read(), **kw)


def dump(obj, fp, **kw):
    """Write `obj` to `fp` as json.dump does: `fp.write` takes str pieces,
    here of about 64 KiB each, so that the whole text is never held at
    once."""
    _dumps_kw(obj, _fp=fp, **kw)


def dumpb(obj, **kw):
    """dumps as UTF-8 bytes."""
    if not kw:
        return _codec.dumps_with(obj, False, True, True, True, None, ", ", ": ", None, False, True)
    return _dumps_kw(obj, _as_bytes=True, **kw)
