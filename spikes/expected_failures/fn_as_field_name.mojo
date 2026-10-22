# `fn` is gone as a keyword for functions but still reserved.
# EXPECT: escape keyword 'fn' with backticks to use it as an identifier
@fieldwise_init
struct Target(TrivialRegisterPassable):
    var fn: Int
    var ctx: Int


def main():
    print(Target(1, 2).ctx)
