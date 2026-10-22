"""Compatibility re-export: `ByteBuffer` moved to the `bytes` package so the
event loop (`rt`), which must not import `net`, can own buffers too."""

from bytes.buffer import CHECK_SPANS, DEFAULT_MAX_SIZE, MIN_GROWTH, POISON, ByteBuffer
