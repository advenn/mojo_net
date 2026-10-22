# Without `thin` the type is a (context-carrying) closure type, not a bare
# C function pointer; a C-ABI def does not convert to it.
# EXPECT: cannot implicitly convert 'def entry(arg: Int) abi("C") thin -> Int' value to 'F'
def entry(arg: Int) abi("C") -> Int:
    return arg


def main():
    comptime F = def(Int) abi("C") -> Int
    var f: F = entry
    print(f(1))
