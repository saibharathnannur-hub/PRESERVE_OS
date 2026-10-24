"""
hog.py -- allocates memory steadily to drive the test cgroup into pressure.

Purpose in the experiment
-------------------------
The hog is the *antagonist*. Every ``--interval-s`` seconds it allocates
another ``--chunk-mb`` MiB until it holds ``--target-mb``. It then keeps the
memory for ``--hold-s`` seconds and exits, which lets pressure recover so the
governor can demonstrate restore.

How it produces pressure (and why the pages must be touched)
------------------------------------------------------------
``bytearray(n)`` asks the allocator for zeroed memory. For large sizes that
becomes an anonymous ``mmap`` whose pages are *not yet backed by RAM*. Linux
allocates a physical page only on the first write (demand paging). Untouched,
a 400 MiB bytearray would barely move ``memory.current``. The hog therefore
writes one byte per page, forcing a page fault and a charged page for each.

Once the cgroup approaches ``memory.max`` (or ``memory.high``), each new
page fault must first reclaim memory: drop page cache, or swap out anonymous
pages up to ``memory.swap.max``. Tasks waiting in reclaim are counted as
*stalled* by PSI, which is the signal the governor watches. While holding,
the hog re-touches its pages (``--retouch``), so pages that were swapped out
fault back in. That sustains the stall instead of letting it decay.

If the governor does nothing, or decides nothing is worth preserving, the
cgroup's OOM killer eventually picks a victim. That baseline is exactly what
PRESERVE is compared against.

The hog never touches the CPU-bound job and has no knowledge of the governor.

Outputs
-------
State file (JSON): ``pid, allocated_mib, phase`` with phase in
``allocating | holding | done``.

Standalone use (it is safe *inside a cgroup*; outside one it really does
allocate the target)::

    python3 workloads/hog.py --target-mb 64 --hold-s 2 --state-file /tmp/hog.json
"""
from __future__ import annotations

import argparse
import configparser
import json
import mmap
import os
import signal
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PAGE = mmap.PAGESIZE

_stop = False


def _on_term(signum, _frame) -> None:
    global _stop
    _stop = True


def conf_defaults(path: Path) -> dict[str, str]:
    cp = configparser.ConfigParser(inline_comment_prefixes=("#",), interpolation=None)
    cp.read(path)
    return dict(cp["workloads"]) if cp.has_section("workloads") else {}


def touch(buf: bytearray, value: int) -> None:
    n = len(range(0, len(buf), PAGE))
    buf[::PAGE] = bytes([value & 0xFF or 1]) * n


def write_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, path)


def main() -> int:
    d = conf_defaults(PROJECT_ROOT / "preserve.conf")
    ap = argparse.ArgumentParser(description="Steady memory allocator for inducing cgroup pressure.")
    ap.add_argument("--chunk-mb", type=int, default=int(d.get("hog_chunk_mb", 1)))
    ap.add_argument("--interval-s", type=float, default=float(d.get("hog_interval_s", 1)))
    ap.add_argument("--target-mb", type=int, default=int(d.get("hog_target_mb", 1)))
    ap.add_argument("--hold-s", type=float, default=float(d.get("hog_hold_s", 0)),
                    help="seconds to hold the memory after reaching target (0 = until SIGTERM)")
    ap.add_argument("--retouch-interval-s", type=float, default=float(d.get("hog_retouch_interval_s", 0)),
                    help="while holding, re-dirty all pages this often (0 = never)")
    ap.add_argument("--state-file", default="hog.state.json")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    state = Path(args.state_file)
    chunks: list[bytearray] = []
    allocated = 0

    def report(phase: str) -> None:
        write_state(state, {"pid": os.getpid(), "allocated_mib": allocated, "phase": phase,
                            "updated_wall": time.time()})

    while not _stop and allocated < args.target_mb:
        size = min(args.chunk_mb, args.target_mb - allocated)
        buf = bytearray(size << 20)
        touch(buf, len(chunks) + 1)  # fault every page in: this is what charges the cgroup
        chunks.append(buf)
        allocated += size
        report("allocating")
        time.sleep(args.interval_s)

    report("holding")
    end = time.monotonic() + args.hold_s
    last_touch = time.monotonic()
    while not _stop and (args.hold_s == 0 or time.monotonic() < end):
        if args.retouch_interval_s > 0 and time.monotonic() - last_touch >= args.retouch_interval_s:
            for i, buf in enumerate(chunks):
                touch(buf, i + 2)  # swapped-out pages fault back in -> sustained pressure
            last_touch = time.monotonic()
        time.sleep(args.interval_s)

    report("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
