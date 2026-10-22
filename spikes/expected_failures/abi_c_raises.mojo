# A C-ABI entry cannot raise; catch everything inside it.
# EXPECT: 'abi("C")' function may not be marked 'raises'
def entry(arg: Int) abi("C") raises -> Int:
    raise Error("x")


def main():
    print("unreachable")
