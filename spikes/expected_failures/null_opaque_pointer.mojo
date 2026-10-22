# OpaquePointer (= Pointer[NoneType, ...]) is non-nullable; pass C NULL as Int 0.
# EXPECT: Pointer is non-nullable
def main():
    var p = OpaquePointer[MutAnyOrigin](unsafe_from_address=0)
    print(Int(p))
