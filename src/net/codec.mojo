"""Compatibility re-export: the sans-I/O codec contract moved to
`bytes.codec`, so protocol packages can implement it without importing
sockets."""

from bytes.codec import Codec, LineCodec, drive_chunked, escape_bytes
