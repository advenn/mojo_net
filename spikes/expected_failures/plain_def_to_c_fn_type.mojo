# A plain Mojo def is not a C function pointer. Typing the value as the
# C fn type is what catches it: passing `entry` straight to external_call
# compiles silently.
# EXPECT: cannot implicitly convert 'def entry(arg: Int) thin -> Int' value to 'F'
def entry(arg: Int) -> Int:
    return arg


def main():
    comptime F = def(Int) thin abi("C") -> Int
    var f: F = entry
    print(f(1))
