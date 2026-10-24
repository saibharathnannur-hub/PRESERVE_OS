"""
compare.py -- side-by-side comparison of a PRESERVE live run and a baseline run.

An experiment is a *pair* of runs of the same scenario:

* the **baseline**: the governor only observes and the kernel's cgroup-local
  OOM killer decides (``run_demo.sh --scenario X --baseline``);
* the **live run**: PRESERVE checkpoints and restores
  (``run_demo.sh --scenario X``).

Both runs save an evidence directory (``evidence/demo-<stamp>-<mode>-<scenario>/``).
This tool reads two such directories, read-only, and prints the comparison
table that the report uses. It answers: what did the kernel kill, how much
accumulated work did that destroy, and how much did PRESERVE keep instead?

Usage::

    python3 src/compare.py --live evidence/<live dir> --baseline evidence/<baseline dir>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from config import PROJECT_ROOT
from governor import BASELINE_RESULT, load_reference_run, side_by_side_table


def _resolve(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else PROJECT_ROOT / path


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare a live PRESERVE run with a kernel-OOM baseline.")
    ap.add_argument("--live", required=True, help="evidence directory of the live run")
    ap.add_argument("--baseline", required=True, help="evidence directory of the baseline run")
    args = ap.parse_args()

    live_dir, base_dir = _resolve(args.live), _resolve(args.baseline)
    ref = load_reference_run(live_dir)
    if not ref.get("available"):
        print(f"live run directory not found: {live_dir}")
        return 1
    try:
        base = json.loads((base_dir / BASELINE_RESULT).read_text())
    except (OSError, ValueError) as exc:
        print(f"cannot read {base_dir / BASELINE_RESULT}: {exc}")
        return 1
    base.setdefault("scenario", "A")  # baselines recorded before scenarios existed used the base values
    if ref.get("scenario") != base.get("scenario"):
        print(f"WARNING: comparing scenario {ref.get('scenario')} (live) with "
              f"scenario {base.get('scenario')} (baseline)")

    print(f"live run : {live_dir}")
    print(f"baseline : {base_dir}")
    for v in base.get("victims", []):
        print(f"kernel victim in baseline: {v['role']} pid={v['pid']} at iteration {v.get('last_iteration')}, "
              f"work destroyed {v.get('work_lost_s', 0):.2f}s")
        if v.get("kernel_line"):
            print(f"  {v['kernel_line']}")
    print("-" * 100)
    for name, a, b in side_by_side_table(ref, base):
        print(f"  {name:30s} | {str(a):46s} | {b}")
    print("-" * 100)
    return 0


if __name__ == "__main__":
    sys.exit(main())
