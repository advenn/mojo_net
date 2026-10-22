"""Compatibility re-export: `ByteBuffer` lives in the `bytes` package, so
codecs and other packages can use it without importing sockets."""

from bytes.buffer import CHECK_SPANS, DEFAULT_MAX_SIZE, MIN_GROWTH, POISON, ByteBuffer
