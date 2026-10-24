"""Comparing secrets without timing leaks."""


def equal_constant_time(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    """Whether `a` and `b` are equal, taking the same time whatever bytes
    differ (their lengths are not secret: different lengths are unequal at
    once). For comparing a server's signature with the expected one."""
    if len(a) != len(b):
        return False
    var acc: UInt8 = 0
    for i in range(len(a)):
        acc |= a[i] ^ b[i]
    return acc == 0
