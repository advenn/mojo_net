"""Owned byte buffers shared by every layer above `linux`: the event loop
(`rt`) moves them through send/recv ops, and sans-I/O codecs (`net.codec`)
read from and append to them. Imports only `std` and `linux`."""

from .buffer import ByteBuffer
