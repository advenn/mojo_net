# Raw back-pointers stored in structs must use MutUntrackedOrigin.
# EXPECT: struct fields cannot expose AnyOrigin in their type
struct Ctx(Movable):
    var shared: Pointer[Int, MutAnyOrigin]

    def __init__(out self, a: Int):
        self.shared = Pointer[Int, MutAnyOrigin](unsafe_from_address=a)


def main():
    var c = Ctx(8)
    _ = c^
