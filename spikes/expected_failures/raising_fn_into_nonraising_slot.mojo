# A raising def does not fit a non-raising thin fn type (the reverse works).
# EXPECT: cannot implicitly convert 'def r(ctx: Int, res: Int) raises thin -> None' value to 'CompletionFn'
comptime CompletionFn = def(Int, Int) thin -> None


def r(ctx: Int, res: Int) raises:
    raise Error("x")


def main():
    var g: CompletionFn = r
    _ = g
