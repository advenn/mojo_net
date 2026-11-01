#!/usr/bin/env python3
"""Check that GitHub CI still runs everything `pixi run ci` runs.

CI splits `ci` into parallel jobs (.github/workflows/ci.yml): the checks,
the tests in parts (MOJO_NET_TEST_SHARD=i/n), and tls-asan. A task added
to `ci` in pixi.toml would otherwise run locally and never in CI. This
fails unless every task `ci` depends on appears in the workflow as
`pixi run <task>`, and the test parts listed in its matrix are 1/n to n/n
for a single n.

    python3 tools/check_ci.py
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    tasks = tomllib.loads((ROOT / "pixi.toml").read_text())["tasks"]
    deps = tasks["ci"]["depends-on"]
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    problems = []
    for task in deps:
        if not re.search(rf"pixi run {re.escape(task)}(\s|$)", workflow, re.M):
            problems.append(f"`ci` runs {task}, but ci.yml never runs `pixi run {task}`")
    parts = {(int(i), int(n)) for i, n in re.findall(r"\btest (\d+)/(\d+)\b", workflow)}
    sizes = {n for _, n in parts}
    if "test" in deps:
        if len(sizes) != 1:
            problems.append(f"ci.yml's test parts must share one n: found {sorted(parts)}")
        else:
            n = sizes.pop()
            missing = sorted(set(range(1, n + 1)) - {i for i, _ in parts})
            if missing:
                problems.append(f"ci.yml runs the tests in {n} parts but lacks part(s) {missing}")
    for p in problems:
        print("FAIL", p)
    if not problems:
        print(f"ok   ci.yml runs all {len(deps)} tasks of `ci`, the tests in {len(parts)} parts")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
