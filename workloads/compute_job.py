"""
compute_job.py -- a long-running, CPU-bound job whose progress is measurable.

Purpose in the experiment
-------------------------
This is the process PRESERVE is supposed to *save*. It stands for any job
whose value lies in accumulated in-memory state (a simulation, a training
loop, a long build): killing it means redoing all the work.

Each iteration extends a SHA-256 hash chain::

        d_0 = SHA256(seed)
        d_k = SHA256^h(d_{k-1})        (h = hashes per iteration)

The chain has two useful properties:

* **Progress is unambiguous.** Iteration ``k`` can only be reached by
  computing iterations ``1..k-1`` first, so "the job resumed at iteration
  N+1" is a strong claim.
* **State is verifiable.** The digest at iteration ``k`` is a pure function
  of ``k``. ``--verify-log`` recomputes the chain and checks every logged
  digest. That proves the restored process continued from *correct* memory
  contents, not just from the right counter value.

Memory footprint
----------------
The job also holds a working set of ``--working-set-mb`` MiB (a
``bytearray``). Every ``--touch-every`` iterations it writes one byte per page
so all pages stay dirty and resident. This makes the job a realistic eviction
target: dumping it frees that much memory inside the cgroup.

CRIU-friendliness
-----------------
* stdin/stdout/stderr are expected to be ``/dev/null``, which the governor
  arranges.
* The state file is written atomically (write ``.tmp``, then
  ``os.replace``), and the progress log is opened, appended and closed each
  time. No file descriptor stays open across the sleep in which a dump is
  most likely to happen, so there is nothing fragile to restore.
* ``work_seconds`` is accumulated in a Python variable, not read from
  ``time.process_time()``. CRIU restores memory but not the kernel's
  per-task CPU accounting, so the process CPU clock restarts near zero after
  a restore, while a variable in memory survives.

Outputs (paths given on the command line)
-----------------------------------------
* state file (JSON): ``pid, iteration, work_seconds, digest, updated_wall``
* progress log, one line per report::

      <unix_time> iteration=<k> work_s=<s> digest=<hex16> pid=<pid>

Standalone use::

    python3 workloads/compute_job.py --iterations 50 --state-file /tmp/cj.json --progress-log /tmp/cj.log
    python3 workloads/compute_job.py --verify-log /tmp/cj.log
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import mmap
import os
import re
import signal
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PAGE = mmap.PAGESIZE
SEED = b"PRESERVE compute_job seed v1"
LINE_RE = re.compile(r"iteration=(\d+) .*digest=([0-9a-f]+)")

_stop = False


def _on_term(signum, _frame) -> None:
    global _stop
    _stop = True


def conf_defaults(path: Path) -> dict[str, str]:
    """Read [workloads] from preserve.conf so standalone runs need no flags."""
    cp = configparser.ConfigParser(inline_comment_prefixes=("#",), interpolation=None)
    cp.read(path)
    return dict(cp["workloads"]) if cp.has_section("workloads") else {}


def advance(digest: bytes, hashes: int) -> bytes:
    for _ in range(hashes):
        digest = hashlib.sha256(digest).digest()
    return digest


def touch(buf: bytearray, value: int) -> None:
    """Write one byte in every page so the whole buffer is dirty and resident."""
    n = len(range(0, len(buf), PAGE))
    buf[::PAGE] = bytes([value & 0xFF or 1]) * n


def write_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, path)  # atomic rename: readers never see a half-written file


def run(args: argparse.Namespace) -> int:
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    state_file, progress = Path(args.state_file), Path(args.progress_log)
    working_set = bytearray(args.working_set_mb << 20)
    touch(working_set, 1)

    digest = hashlib.sha256(SEED).digest()
    iteration, work_s = 0, 0.0
    max_credit = args.max_iteration_credit_s

    while not _stop and (args.iterations == 0 or iteration < args.iterations):
        t0 = time.perf_counter()
        digest = advance(digest, args.hashes_per_iteration)
        iteration += 1
        if iteration % args.touch_every == 0:
            touch(working_set, iteration)
        dt = time.perf_counter() - t0
        # An iteration that spans a checkpoint would count the downtime as work.
        if 0 <= dt <= max_credit:
            work_s += dt
        if iteration % args.report_every == 0:
            now = time.time()
            write_state(state_file, {"pid": os.getpid(), "iteration": iteration,
                                     "work_seconds": round(work_s, 4), "digest": digest.hex(),
                                     "updated_wall": now})
            with open(progress, "a") as f:
                f.write(f"{now:.3f} iteration={iteration} work_s={work_s:.3f} "
                        f"digest={digest.hex()[:16]} pid={os.getpid()}\n")
        time.sleep(args.step_sleep_s)

    write_state(state_file, {"pid": os.getpid(), "iteration": iteration,
                             "work_seconds": round(work_s, 4), "digest": digest.hex(),
                             "updated_wall": time.time(), "final": True})
    return 0


def verify_log(path: Path, hashes: int) -> int:
    """Recompute the hash chain and check every digest recorded in a progress log."""
    entries = [(int(m.group(1)), m.group(2)) for m in map(LINE_RE.search, path.read_text().splitlines()) if m]
    if not entries:
        print(f"no progress lines in {path}")
        return 1
    digest, at, bad = hashlib.sha256(SEED).digest(), 0, 0
    resets = 0
    for i, (iteration, logged) in enumerate(entries):
        if iteration <= at:  # counter went backwards: job restarted from scratch
            resets += 1
            digest, at = hashlib.sha256(SEED).digest(), 0
        digest = advance(digest, hashes * (iteration - at))
        at = iteration
        if not digest.hex().startswith(logged):
            bad += 1
            print(f"MISMATCH line {i + 1}: iteration {iteration} logged {logged}, expected {digest.hex()[:16]}")
    print(f"verified {len(entries)} lines up to iteration {at}: {bad} mismatches, {resets} restart(s) from scratch")
    return 0 if bad == 0 else 1


def main() -> int:
    d = conf_defaults(PROJECT_ROOT / "preserve.conf")
    ap = argparse.ArgumentParser(description="Hash-chain compute job with a resident working set.")
    ap.add_argument("--state-file", default="compute_job.state.json")
    ap.add_argument("--progress-log", default="compute_job.progress.log")
    ap.add_argument("--working-set-mb", type=int, default=int(d.get("compute_working_set_mb", 0)))
    ap.add_argument("--hashes-per-iteration", type=int, default=int(d.get("compute_hashes_per_iteration", 1)))
    ap.add_argument("--step-sleep-s", type=float, default=float(d.get("compute_step_sleep_s", 0)))
    ap.add_argument("--report-every", type=int, default=int(d.get("compute_report_every", 1)))
    ap.add_argument("--touch-every", type=int, default=int(d.get("compute_touch_every", 1)))
    ap.add_argument("--max-iteration-credit-s", type=float,
                    default=float(d.get("compute_max_iteration_credit_s", 1)))
    ap.add_argument("--iterations", type=int, default=0, help="stop after N iterations (0 = run until SIGTERM)")
    ap.add_argument("--verify-log", default=None, help="verify a progress log instead of running")
    args = ap.parse_args()
    if args.verify_log:
        return verify_log(Path(args.verify_log), args.hashes_per_iteration)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
