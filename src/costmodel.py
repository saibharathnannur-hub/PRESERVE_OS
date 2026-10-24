"""
costmodel.py -- M2: restart cost vs. capture cost scoring.

The decision being modelled
---------------------------
When a memory-limited cgroup comes under pressure, the kernel's default
answer is the OOM killer: it picks a victim by ``oom_score`` (roughly "who
uses the most memory") and sends SIGKILL. All work done by that process is
lost. PRESERVE offers a second option, *eviction by checkpoint*: freeze the
process with CRIU, write its address space and kernel state to disk, kill it
to release its memory, and restore it later. Eviction is not free, so the
governor needs a cost model to decide **which** process to evict and
**whether** eviction is worth it at all.

Two costs are estimated, both in seconds so that they are comparable:

* **Restart cost R**: the work lost if the process were killed and had to
  start again. Without application cooperation the best OS-level proxy is
  consumed CPU time (``utime + stime`` from ``/proc/<pid>/stat``). A
  workload may also *declare* its progress in a state file; the larger of
  the two is used. The declared value is needed because CRIU restores a
  process's memory and registers but **not** the kernel's per-task CPU
  accounting, so a restored process reports a small ``utime`` again even
  though its in-memory work survived.

* **Capture cost C**: the time to dump the process. CRIU writes, among other
  things, every private anonymous page, so the image is roughly the
  resident set size. The model estimates::

        image_bytes = RSS * image_size_factor + image_fixed_overhead
        C           = dump_fixed_overhead_s + image_MiB / throughput_MiB_s

  ``throughput`` is refined after every real dump with an exponentially
  weighted moving average (EWMA), so the model calibrates itself to this
  machine's disk. The estimate is **persisted** to a small JSON state file
  after each dump and loaded at the next start, so a new run begins from
  what was measured before instead of from the configured guess
  (``initial_dump_mib_per_s``, used only when no saved estimate exists).
  Without this, every cold start would overestimate C and the admission
  test (``max_capture_s``) could refuse dumps that would have succeeded.

Score and eligibility
---------------------
A process is **eligible** for preservation only if

* ``R >= min_restart_cost_s`` (cheap processes are simply not worth it), and
* ``R >= benefit_ratio * C`` (saving the work must clearly beat the cost of
  saving it).

Among eligible processes the victim is the one with the highest score::

        score = w_restart * R + w_memory * RSS_MiB - w_capture * C

The memory term rewards evicting a process that frees a lot of memory, which
is the point of acting under pressure. The capture term penalises slow dumps
that would leave the system stalled for longer. Weights are in
``preserve.conf`` [costmodel].

Standalone use::

    python3 src/costmodel.py                 # score a set of synthetic processes
    python3 src/costmodel.py --pid 1234      # score real processes (read-only)
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from config import Config
from sensor import MIB, ProcSnapshot, read_proc

log = logging.getLogger("preserve.costmodel")


@dataclass(frozen=True)
class Score:
    """Cost-model verdict for one process."""

    pid: int
    role: str
    mem_mib: float
    restart_cost_s: float
    capture_cost_s: float
    est_image_bytes: int
    score: float
    eligible: bool
    reason: str

    def describe(self) -> str:
        flag = "ELIGIBLE" if self.eligible else "skip"
        return (
            f"pid={self.pid} role={self.role} rss={self.mem_mib:.1f}MiB "
            f"R={self.restart_cost_s:.2f}s C={self.capture_cost_s:.2f}s "
            f"score={self.score:.2f} [{flag}: {self.reason}]"
        )


class CostModel:
    """Scores processes for eviction-by-checkpoint (see module docstring)."""

    def __init__(self, cfg: Config) -> None:
        s = "costmodel"
        self.w_restart = cfg.get_float(s, "weight_restart")
        self.w_memory = cfg.get_float(s, "weight_memory")
        self.w_capture = cfg.get_float(s, "weight_capture")
        self.min_restart_cost_s = cfg.get_float(s, "min_restart_cost_s")
        self.benefit_ratio = cfg.get_float(s, "benefit_ratio")
        self.throughput_mib_s = cfg.get_float(s, "initial_dump_mib_per_s")
        self.last_observed_mib_s: float | None = None
        self.observations = 0  # dumps folded into the estimate, across runs
        self.dump_fixed_overhead_s = cfg.get_float(s, "dump_fixed_overhead_s")
        self.ewma_alpha = cfg.get_float(s, "ewma_alpha")
        self.image_size_factor = cfg.get_float(s, "image_size_factor")
        self.image_fixed_overhead = int(cfg.get_float(s, "image_fixed_overhead_mib") * MIB)

    # -- cost estimates -----------------------------------------------------
    def estimate_image_bytes(self, rss_bytes: int) -> int:
        return int(rss_bytes * self.image_size_factor) + self.image_fixed_overhead

    def capture_cost_s(self, rss_bytes: int) -> float:
        image_mib = self.estimate_image_bytes(rss_bytes) / MIB
        return self.dump_fixed_overhead_s + image_mib / self.throughput_mib_s

    @staticmethod
    def restart_cost_s(snap: ProcSnapshot, declared_work_s: float | None = None) -> float:
        return max(snap.cpu_seconds, declared_work_s or 0.0)

    # -- scoring --------------------------------------------------------------
    def score(self, snap: ProcSnapshot, role: str, declared_work_s: float | None = None) -> Score:
        r = self.restart_cost_s(snap, declared_work_s)
        c = self.capture_cost_s(snap.rss_bytes)
        m = snap.rss_bytes / MIB
        value = self.w_restart * r + self.w_memory * m - self.w_capture * c
        if r < self.min_restart_cost_s:
            eligible, reason = False, f"R {r:.2f}s < min_restart_cost_s {self.min_restart_cost_s}s"
        elif r < self.benefit_ratio * c:
            eligible, reason = False, f"R {r:.2f}s < benefit_ratio*C {self.benefit_ratio * c:.2f}s"
        else:
            eligible, reason = True, f"R/C = {r / c:.1f}"
        return Score(snap.pid, role, m, r, c, self.estimate_image_bytes(snap.rss_bytes),
                     value, eligible, reason)

    def score_group(self, root_pid: int, role: str,
                    members: list[tuple[ProcSnapshot, float | None]]) -> Score:
        """Score a dependent group as one unit (Objective 6).

        Killing any member destroys every member's work, and CRIU dumps them
        together, so R is the SUM of the members' R, and RSS (memory freed) and
        C (one dump writing all of their pages) cover all members. The same
        eligibility rules and score formula as :meth:`score` then apply.
        ``pid`` of the result is the group's root (the pid CRIU is given).
        """
        r = sum(self.restart_cost_s(snap, declared) for snap, declared in members)
        rss = sum(snap.rss_bytes for snap, _ in members)
        merged = ProcSnapshot(root_pid, role, "R", 0, rss, 0.0, 0)
        s = self.score(merged, role, r)
        return s

    @staticmethod
    def rank(scores: list[Score]) -> list[Score]:
        """Eligible processes first, then by descending score."""
        return sorted(scores, key=lambda s: (s.eligible, s.score), reverse=True)

    # -- online calibration ---------------------------------------------------
    def observe_capture(self, image_bytes: int, seconds: float) -> None:
        """Fold a measured dump into the throughput estimate (EWMA)."""
        if image_bytes <= 0 or seconds <= 0:
            return
        observed = (image_bytes / MIB) / seconds
        old = self.throughput_mib_s
        self.throughput_mib_s = self.ewma_alpha * observed + (1 - self.ewma_alpha) * old
        self.last_observed_mib_s = observed
        self.observations += 1
        log.info("dump throughput observed %.1f MiB/s; estimate %.1f -> %.1f MiB/s",
                 observed, old, self.throughput_mib_s)

    # -- persistence of the estimate across runs -------------------------------
    def load_throughput(self, path: Path, shown_as: str | None = None) -> str:
        """Adopt a saved estimate if ``path`` holds a valid one; return its provenance.

        Falls back to the configured ``initial_dump_mib_per_s`` (already set
        in ``__init__``) when the file is missing or unusable. ``shown_as`` is
        the name used in messages (e.g. the path relative to the project).
        """
        name = shown_as or str(path)
        try:
            data = json.loads(Path(path).read_text())
            value = float(data["throughput_mib_s"])
        except FileNotFoundError:
            return "default, no saved estimate"
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("ignoring unreadable throughput state %s: %s", name, exc)
            return f"default, saved estimate in {name} unreadable"
        if not math.isfinite(value) or value <= 0:
            log.warning("ignoring invalid saved throughput %r in %s", value, name)
            return f"default, saved estimate in {name} invalid"
        self.throughput_mib_s = value
        self.observations = int(data.get("observations", 0))
        self.last_observed_mib_s = data.get("last_observed_mib_s")
        return f"loaded from {name}"

    def save_throughput(self, path: Path) -> None:
        """Write the current estimate atomically (tmp file + rename)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps({
            "throughput_mib_s": round(self.throughput_mib_s, 3),
            "last_observed_mib_s": None if self.last_observed_mib_s is None
            else round(self.last_observed_mib_s, 3),
            "observations": self.observations,
            "ewma_alpha": self.ewma_alpha,
            "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, indent=2))
        os.replace(tmp, path)


def _main() -> int:
    ap = argparse.ArgumentParser(description="Score processes with the PRESERVE cost model (M2).")
    ap.add_argument("--config", default=None)
    ap.add_argument("--pid", type=int, action="append", default=[], help="score this real PID (read-only)")
    args = ap.parse_args()
    model = CostModel(Config(args.config))
    print(f"throughput estimate: {model.throughput_mib_s:.1f} MiB/s")

    if args.pid:
        snaps = [(read_proc(p), "observed") for p in args.pid]
        missing = [p for p, (s, _) in zip(args.pid, snaps) if s is None]
        if missing:
            print(f"no such process: {missing}")
        scores = [model.score(s, role) for s, role in snaps if s is not None]
    else:
        # Synthetic population: a long CPU-heavy job, a fresh memory hog, a tiny daemon.
        synthetic = [
            (ProcSnapshot(1001, "compute_job", "R", 1, 128 * MIB, 60.0, 0), "compute", None),
            (ProcSnapshot(1002, "hog", "R", 1, 400 * MIB, 0.8, 0), "hog", None),
            (ProcSnapshot(1003, "daemon", "S", 1, 8 * MIB, 0.1, 0), "daemon", None),
            (ProcSnapshot(1004, "restored", "R", 1, 128 * MIB, 0.5, 0), "compute", 75.0),
        ]
        scores = [model.score(s, role, declared) for s, role, declared in synthetic]

    for s in model.rank(scores):
        print("  " + s.describe())
    print("\nsimulated dump of 128 MiB in 0.8 s:")
    model.observe_capture(128 * MIB, 0.8)
    print(f"throughput estimate now {model.throughput_mib_s:.1f} MiB/s")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.exit(_main())
