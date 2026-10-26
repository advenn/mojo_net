#!/usr/bin/env python3
"""Gate TG14 (docs/tls.md, "Updates"; rules TA2 and TA6 of
docs/research/tls_with_openssl.md): fail when conda-forge has had a newer
build of `openssl` (on the line pixi.toml allows, 3.5.*) or of
`ca-certificates` than pixi.lock holds for more than two days.

    python3 tools/check_freshness.py   (run through pixi: `pixi run tls-freshness`)

It asks `pixi update --dry-run --json`, which changes nothing. On failure,
`pixi update openssl ca-certificates` and the full `pixi run ci` are the
fix. Not part of `ci`: its answer depends on the day, so it runs daily
(.github/workflows/freshness.yml).
"""

import json
import subprocess
import sys
import time

PACKAGES = ("openssl", "ca-certificates")
GRACE_DAYS = 2


def main():
    out = subprocess.run(["pixi", "update", "--dry-run", "--json", *PACKAGES], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"pixi update --dry-run failed:\n{out.stderr}")
    report = json.loads(out.stdout) if out.stdout.strip() else {}
    now = time.time()
    stale = []
    for env, platforms in report.get("environment", {}).items():
        for platform, changes in platforms.items():
            for c in changes:
                after = c.get("after") or {}
                built = (after.get("timestamp") or 0) / 1000
                age = (now - built) / 86400 if built else float("inf")
                line = f"{env}/{platform}: {c['name']} {c.get('before', {}).get('conda', '?').rsplit('/', 1)[-1]} -> {after.get('conda', '?').rsplit('/', 1)[-1]} ({age:.1f} days old)"
                print(line)
                if age > GRACE_DAYS:
                    stale.append(line)
    if stale:
        print(f"---- {len(stale)} update(s) older than {GRACE_DAYS} days: run `pixi update {' '.join(PACKAGES)}` and the full `pixi run ci`")
        sys.exit(1)
    print(f"---- {', '.join(PACKAGES)}: the lock is current (or the update is under {GRACE_DAYS} days old)")


if __name__ == "__main__":
    main()
