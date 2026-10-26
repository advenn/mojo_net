"""Random HTTP-dates in their three forms with their times, made with
Python's standard library, for tests/http/test_retry.mojo (test-only)."""

import calendar
import email.utils
import random
import time

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def cases(seed, n):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        # (Up to 2068: Python reads a two-digit 69 as 1969, a fixed pivot,
        # where RFC 9110's 50-year rule reads 2069.)
        t = rng.randrange(0, calendar.timegm((2068, 12, 31, 23, 59, 59)))
        tm = time.gmtime(t)
        imf = email.utils.formatdate(t, usegmt=True)  # IMF-fixdate
        rfc850 = time.strftime(f"{DAYS[tm.tm_wday]}, %d-%b-%y %H:%M:%S GMT", tm)
        asctime = time.strftime("%a %b ", tm) + f"{tm.tm_mday:2d}" + time.strftime(" %H:%M:%S %Y", tm)
        for text in (imf, rfc850, asctime):
            parsed = email.utils.parsedate_tz(text)
            assert parsed is not None and calendar.timegm(parsed[:6]) == t, text
            out.append((text, t))
    return out
