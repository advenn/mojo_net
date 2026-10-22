"""Shared protocol-side building blocks, below every library that moves
bytes: `ByteBuffer` (owned buffers that codecs read from and append to, and
that event-loop ops move) and the sans-I/O `Codec` contract with its
reference `LineCodec` (docs/design.md, contract 1). Nothing here does I/O.
Imports only `std` and `linux`."""

from .buffer import ByteBuffer
from .codec import Codec, LineCodec
