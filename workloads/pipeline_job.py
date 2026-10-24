"""
pipeline_job.py -- two dependent processes: a parent and one forked child joined by a pipe.

Purpose in the experiment (Objective 6)
---------------------------------------
compute_job is one process. Real jobs are often several cooperating processes
(a producer and a consumer, a driver and a worker), and they depend on each
other: if the kernel OOM-kills one, the others lose their work as well. This
workload is the smallest such group.

* The parent creates a pipe and forks one child. The parent keeps the read
  end, the child keeps the write end; the unused ends are closed, so both
  processes hold the same ``pipe:[inode]`` in ``/proc/<pid>/fd``. That shared
  inode, plus the child's ``ppid``, is the evidence the governor uses to
  detect the dependency.
* Each process extends its own SHA-256 hash chain exactly like compute_job
  (``d_k = SHA256^h(d_{k-1})``), but from its own seed, and holds its own
  working set (``--parent-mb`` / ``--child-mb``).
* Every report the child writes one line ``<iteration> <digest>`` into the
  pipe; the parent drains the pipe each iteration.
* **The dependency is real.** If the child dies, the parent reads EOF and
  exits with ``EXIT_PARTNER_LOST`` without saving anything. If the parent dies,
  the child's next write fails with EPIPE and it exits the same way. Killing
  either member destroys the work of both.

Outputs (in the working directory, or under ``--run-dir``)
-----------------------------------------------------------
* ``pipeline_job.<role>.state.json``  ``pid, role, iteration, work_seconds, digest, ...``
* ``pipeline_job.<role>.progress.log`` one line per report, same format as compute_job::

      <unix_time> iteration=<k> work_s=<s> digest=<hex16> pid=<pid>

CRIU-friendliness
-----------------
Same rules as compute_job (stdio on /dev/null, state written atomically,
progress log opened and closed per report). The pipe is the only long-lived
descriptor and both of its ends are inside the dumped tree, which CRIU can
restore. ``work_seconds`` lives in memory, so it survives a restore.

Standalone use::

    python3 workloads/pipeline_job.py --iterations 40 --run-dir /tmp/pj
    python3 workloads/pipeline_job.py --verify-log /tmp/pj/pipeline_job.child.progress.log --role child
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import select
import signal
import sys
import time
from pathlib import Path

from compute_job import PROJECT_ROOT, advance, conf_defaults, touch, write_state

SEEDS = {"parent": b"PRESERVE pipeline_job parent seed v1",
         "child": b"PRESERVE pipeline_job child seed v1"}
ROLES = tuple(SEEDS)
EXIT_PARTNER_LOST = 3  # the other member died: this member's work is lost too
LINE_RE = re.compile(r"iteration=(\d+) .*digest=([0-9a-f]+)")

_stop = False


def _on_term(signum, _frame) -> None:
    global _stop
    _stop = True


def files(run_dir: Path, role: str) -> tuple[Path, Path]:
    return (run_dir / f"pipeline_job.{role}.state.json",
            run_dir / f"pipeline_job.{role}.progress.log")


def member(role: str, args: argparse.Namespace, rfd: int | None, wfd: int | None) -> int:
    """One member's main loop. ``rfd`` (parent) or ``wfd`` (child) is the shared pipe."""
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    state_file, progress = files(Path(args.run_dir), role)
    working_set = bytearray((args.parent_mb if role == "parent" else args.child_mb) << 20)
    touch(working_set, 1)

    digest = hashlib.sha256(SEEDS[role]).digest()
    iteration, work_s, received = 0, 0.0, 0
    max_credit = args.max_iteration_credit_s
    partner_lost = ""

    while not _stop and (args.iterations == 0 or iteration < args.iterations):
        t0 = time.perf_counter()
        digest = advance(digest, args.hashes_per_iteration)
        iteration += 1
        if iteration % args.touch_every == 0:
            touch(working_set, iteration)
        dt = time.perf_counter() - t0
        if 0 <= dt <= max_credit:  # an iteration spanning a checkpoint is not work
            work_s += dt
        if rfd is not None:  # parent: drain whatever the child sent
            while select.select([rfd], [], [], 0)[0]:
                chunk = os.read(rfd, 65536)
                if not chunk:
                    partner_lost = "pipe EOF: child is gone"
                    break
                received += chunk.count(b"\n")
        if iteration % args.report_every == 0 and not partner_lost:
            if wfd is not None:  # child: tell the parent how far it is
                try:
                    os.write(wfd, f"{iteration} {digest.hex()[:16]}\n".encode())
                except BrokenPipeError:
                    partner_lost = "EPIPE: parent is gone"
            now = time.time()
            write_state(state_file, {"pid": os.getpid(), "role": role, "iteration": iteration,
                                     "work_seconds": round(work_s, 4), "digest": digest.hex(),
                                     "received": received, "updated_wall": now})
            with open(progress, "a") as f:
                f.write(f"{now:.3f} iteration={iteration} work_s={work_s:.3f} "
                        f"digest={digest.hex()[:16]} pid={os.getpid()}\n")
        if partner_lost:
            # The dependency: without its partner this member's work is worthless.
            write_state(state_file, {"pid": os.getpid(), "role": role, "iteration": iteration,
                                     "work_seconds": round(work_s, 4), "digest": digest.hex(),
                                     "received": received, "updated_wall": time.time(),
                                     "partner_lost": partner_lost})
            return EXIT_PARTNER_LOST
        time.sleep(args.step_sleep_s)

    write_state(state_file, {"pid": os.getpid(), "role": role, "iteration": iteration,
                             "work_seconds": round(work_s, 4), "digest": digest.hex(),
                             "received": received, "updated_wall": time.time(), "final": True})
    return 0


def run(args: argparse.Namespace) -> int:
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)  # EPIPE as an exception, not a silent death
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rfd)
        rc = 1
        try:
            rc = member("child", args, None, wfd)
        finally:
            os._exit(rc)
    os.close(wfd)
    rc = member("parent", args, rfd, None)
    if rc == 0:  # clean stop: let the child stop too, then reap it
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass  # after a CRIU restore the child may already have been reaped elsewhere
    return rc


def verify_log(path: Path, role: str, hashes: int) -> int:
    """Recompute ``role``'s hash chain and check every digest in its progress log."""
    seed = SEEDS[role]
    entries = [(int(m.group(1)), m.group(2)) for m in map(LINE_RE.search, path.read_text().splitlines()) if m]
    if not entries:
        print(f"no progress lines in {path}")
        return 1
    digest, at, bad, resets = hashlib.sha256(seed).digest(), 0, 0, 0
    for i, (iteration, logged) in enumerate(entries):
        if iteration <= at:  # counter went backwards: restarted from scratch
            resets += 1
            digest, at = hashlib.sha256(seed).digest(), 0
        digest = advance(digest, hashes * (iteration - at))
        at = iteration
        if not digest.hex().startswith(logged):
            bad += 1
            print(f"MISMATCH line {i + 1}: iteration {iteration} logged {logged}, expected {digest.hex()[:16]}")
    print(f"[{role}] verified {len(entries)} lines up to iteration {at}: {bad} mismatches, "
          f"{resets} restart(s) from scratch")
    return 0 if bad == 0 and resets == 0 else 1


def main() -> int:
    d = conf_defaults(PROJECT_ROOT / "preserve.conf")
    ap = argparse.ArgumentParser(description="Parent + forked child joined by a pipe, each with a hash chain.")
    ap.add_argument("--run-dir", default=".")
    ap.add_argument("--parent-mb", type=int, default=int(d.get("pipeline_parent_mb", 0)))
    ap.add_argument("--child-mb", type=int, default=int(d.get("pipeline_child_mb", 0)))
    ap.add_argument("--hashes-per-iteration", type=int, default=int(d.get("compute_hashes_per_iteration", 1)))
    ap.add_argument("--step-sleep-s", type=float, default=float(d.get("compute_step_sleep_s", 0)))
    ap.add_argument("--report-every", type=int, default=int(d.get("compute_report_every", 1)))
    ap.add_argument("--touch-every", type=int, default=int(d.get("compute_touch_every", 1)))
    ap.add_argument("--max-iteration-credit-s", type=float,
                    default=float(d.get("compute_max_iteration_credit_s", 1)))
    ap.add_argument("--iterations", type=int, default=0, help="stop after N iterations (0 = run until SIGTERM)")
    ap.add_argument("--verify-log", default=None, help="verify a progress log instead of running")
    ap.add_argument("--role", choices=ROLES, default=None, help="whose chain --verify-log checks")
    args = ap.parse_args()
    if args.verify_log:
        if args.role is None:
            ap.error("--verify-log needs --role parent|child")
        return verify_log(Path(args.verify_log), args.role, args.hashes_per_iteration)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
