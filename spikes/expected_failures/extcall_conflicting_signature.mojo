# Two external_call sites for one C symbol with different argument types.
# Fix: one typed wrapper per symbol (see spikes/pthread_spike.mojo).
# EXPECT: existing function with conflicting signature
from std.ffi import external_call


def main():
    var r1 = external_call["pthread_join", Int32](UInt64(0), 0)
    var r2 = external_call["pthread_join", Int32](Int32(0), 0)
    print(r1, r2)
