# Completion targets must be non-capturing: state goes in the ctx word.
# EXPECT: cannot implicitly convert 'def(ctx: Int, res: Int) -> None' value to 'CompletionFn'
comptime CompletionFn = def(Int, Int) thin -> None


def main():
    var total = 0

    def closure(ctx: Int, res: Int) {mut total}:
        total += res

    var f: CompletionFn = closure
    f(0, 1)
