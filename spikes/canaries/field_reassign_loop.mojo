"""Canary for a Mojo 1.2.0 compiler bug (CLAUDE.md, "Field reassignment in
a loop corrupts memory"): after one heap-owning field of a local struct is
last used, reassigning another field in a loop corrupts the heap, and the
process crashes later in the allocator. On 1.2.0 this program crashes.

.github/workflows/mojo-nightly.yml runs it against Mojo's nightly: when it
exits 0 there, the bug is fixed upstream, and the workarounds (`_ = x^`
after such loops) can go once the pin moves past the fix."""


struct H(Movable):
    var s: String
    var l: List[UInt8]

    def __init__(out self):
        self.s = String()
        self.l = List[UInt8]()


def main():
    var h = H()
    h.l.append(1)
    for _ in range(100_000):
        h.s = String("ab")
    print("no crash: the field-reassignment bug looks fixed")
