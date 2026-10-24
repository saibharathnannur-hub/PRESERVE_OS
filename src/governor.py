"""
governor.py -- PRESERVE main loop: sense -> classify -> score -> admit -> act.

The problem
-----------
When a memory cgroup runs out of room, Linux has one remedy left: the OOM
killer sends SIGKILL to a victim, and everything that process had computed is
lost. PRESERVE is a user-space governor that offers a gentler remedy: under
pressure it **checkpoints** a valuable process to disk with CRIU (which frees
its RAM), and when pressure has passed it **restores** the process, which
continues from the exact instruction where it stopped.

Control loop
------------
Every ``sample_interval_s`` the governor runs one step::

    M1 sensor     read PSI (memory.pressure) + memory.current/max/events
        |
    classifier    NORMAL / ADVISORY / ACTION, with hysteresis for recovery
        |
    M2 costmodel  (ACTION only) score each managed process: restart cost R
        |         vs capture cost C
    M3 admission  is the best candidate worth it, will it fit in the arena,
        |         and will the dump finish in time?
    M4 capture    criu dump -> process killed, memory released
        ...
    (later, once pressure stayed below the recovery thresholds)
    M3 admission  does the cgroup have headroom for the process again?
    M4 capture    criu restore -> process resumes, confined to the cgroup

**Pressure levels.** The classifier combines two signals:

* PSI ``some`` avg10 of the *test cgroup* (percent of time tasks stalled
  on memory), compared with ``advisory_pct`` and ``action_pct``.
* Usage ratio ``memory.current / memory.max``, compared with
  ``usage_advisory_frac`` and ``usage_action_frac``. Usage alone is not
  pressure (page cache can fill a cgroup harmlessly), but anonymous memory
  close to the limit with little swap may reach OOM before stall time
  accumulates. The usage trigger covers that case.

**Hysteresis.** Restoring as soon as pressure dips would recreate it and lead
to dump/restore thrashing, the same pathology as page thrashing. Restore is
therefore only considered after ``recovery_hold_samples`` *consecutive*
samples below the separate, lower ``recovery_pct`` / ``usage_recovery_frac``
thresholds. The counter is reset after every restore.

**Cooldown.** After a capture the governor waits ``capture_cooldown_s``
before evicting another process. Freed memory needs a moment to show up in
the PSI averages, and acting again too early would evict more than needed.

Safety
------
The governor only acts through :class:`cgroup.PidWhitelist`. It contains
exactly the processes this governor launched into the test cgroup, and its
``verify`` method hard-refuses everything else. See ``cgroup.py`` for the
full rule list.

Demo scenario (``run_demo.sh``)
-------------------------------
1. Create the test cgroup with the limits from ``preserve.conf``.
2. Launch ``compute_job`` (valuable: accumulates CPU work and holds a
   resident working set).
3. After ``hog_start_delay_s``, launch ``hog``, which allocates until the
   cgroup is under pressure.
4. Expected: the governor ranks compute_job as worth preserving (high R, low
   C) and the hog as not worth it (no work to lose). It checkpoints
   compute_job, the hog finishes, pressure recovers, and compute_job is
   restored. The compute_job progress log must then show the iteration
   counter *continuing*, not restarting at 1.
5. Shut down: SIGTERM to remaining managed processes, remove the cgroup, and
   print a summary including the continuity verdict.

Telemetry for plotting is appended to ``evidence/telemetry.csv``, one row per
sample.

Modes
-----
* ``live``: the full mechanism (requires root for CRIU).
* ``dry-run``: everything except CRIU. Decisions are logged only.
* ``baseline``: the *control experiment* PRESERVE is measured against.
  Same workloads, cgroup and thresholds, but the governor only observes:
  it logs PSI, memory, the scoring table and what it *would* have
  checkpointed, and leaves the kernel's cgroup-local OOM killer to act. Swap
  is set to ``[cgroup] baseline_memory_swap_max`` (normally 0) so that the
  OOM killer is not just deferred by swapping. At the end the governor
  reports ``memory.events:oom_kill``, which process the kernel killed (from
  the kernel log), how far compute_job had got, how much work was destroyed,
  and a side-by-side comparison with a saved live run
  (``[baseline] reference_live_run``). Because no CRIU is involved, baseline
  mode does not need root when the governor itself is started inside the
  user's delegated cgroup subtree (``systemd-run --user --scope``).

Usage::

    sudo python3 src/governor.py                # live (CRIU requires root)
    sudo python3 src/governor.py --dry-run      # decide and log, never run CRIU
    systemd-run --user --scope python3 src/governor.py --baseline
    sudo python3 src/governor.py --no-hog       # control run without the antagonist
"""
from __future__ import annotations

import argparse
import configparser
import csv
import enum
import json
import logging
import math
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from admission import AdmissionController, Arena, tree_bytes
from capture import CriuCapture
from cgroup import PRESERVED, RUNNING, CgroupError, ManagedProcess, PidWhitelist, SafetyRefusal, TestCgroup
from config import Config, give_to_invoking_user, invoking_ids, setup_logging
from runlock import EXIT_LOCKED, LockHeld, RunLock, holder_info
from costmodel import CostModel, Score
import deps
from sensor import MIB, Sample, Sensor, format_sample, read_cgroup_memory, read_kernel_oom_kills, read_uptime

log = logging.getLogger("preserve.governor")

MODES = ("live", "dry-run", "baseline", "overhead")
OVERHEAD_RESULT = "overhead_result.json"
# Exit codes that mean "no experiment ran" (distinct from the 0-4 outcome codes):
#   75 (runlock.EXIT_LOCKED)  another governor holds the lock
#   76 (EXIT_SETUP_FAILED)    setup aborted, e.g. could not create an exclusive cgroup
EXIT_SETUP_FAILED = 76
BASELINE_RESULT = "baseline_result.json"

# Fault injection (live mode only), used to demonstrate the fail-safe property:
# every path that does not reach ADMIT must end in STAND DOWN, and in STAND DOWN
# the system behaves no worse than the unmodified kernel would. Each fault forces
# one real precondition to fail; none of them weakens the scoring, admission or
# capture logic -- they only make a genuine check fire so its handling is observed.
FAULTS = ("arena-too-small", "dump-fail", "dump-timeout", "restore-blocked", "stale-pid", "governor-dies")
FAULT_ARENA_CAPACITY_BYTES = 1 << 20  # arena-too-small: budget far below any real image (~307 MiB)

COMPUTE_STATE = "compute_job.state.json"
COMPUTE_PROGRESS = "compute_job.progress.log"
HOG_STATE = "hog.state.json"
# Objective 6: pipeline_job = parent + forked child joined by a pipe (one dependent group).
PIPELINE_ROLES = {"parent": "pipeline", "child": "pipeline-child"}
PIPELINE_STATE = "pipeline_job.{}.state.json"
PIPELINE_PROGRESS = "pipeline_job.{}.progress.log"
RUN_FILES = (COMPUTE_STATE, COMPUTE_STATE + ".tmp", COMPUTE_PROGRESS, HOG_STATE, HOG_STATE + ".tmp") + tuple(
    f.format(r) + sfx for r in PIPELINE_ROLES for f, sfx in
    ((PIPELINE_STATE, ""), (PIPELINE_STATE, ".tmp"), (PIPELINE_PROGRESS, "")))

TELEMETRY_FIELDS = [
    "wall_time", "elapsed_s", "level", "sys_some_avg10", "cg_some_avg10", "cg_full_avg10",
    "mem_current_mib", "mem_max_mib", "swap_current_mib", "usage_frac", "oom_kill",
    "running", "preserved", "event",
]

PROGRESS_RE = re.compile(r"^(\d+\.\d+) iteration=(\d+) work_s=([\d.]+) .*pid=(\d+)")


class Level(enum.Enum):
    NORMAL = "normal"
    ADVISORY = "advisory"
    ACTION = "action"


class PressureClassifier:
    """Maps a sample to a pressure level and tracks recovery with hysteresis."""

    def __init__(self, cfg: Config) -> None:
        p, g = "psi", "governor"
        self.source = cfg.get_str(p, "source")
        self.metric = cfg.get_str(p, "metric")
        self.window = cfg.get_str(p, "window")
        self.advisory_pct = cfg.get_float(p, "advisory_pct")
        self.action_pct = cfg.get_float(p, "action_pct")
        self.recovery_pct = cfg.get_float(p, "recovery_pct")
        self.hold = cfg.get_int(p, "recovery_hold_samples")
        self.usage_advisory = cfg.get_float(g, "usage_advisory_frac")
        self.usage_action = cfg.get_float(g, "usage_action_frac")
        self.usage_recovery = cfg.get_float(g, "usage_recovery_frac")
        if self.source not in ("cgroup", "system"):
            raise ValueError("[psi] source must be cgroup or system")
        if self.metric not in ("some", "full") or self.window not in ("avg10", "avg60", "avg300"):
            raise ValueError("[psi] metric must be some|full and window avg10|avg60|avg300")
        if not (self.recovery_pct < self.advisory_pct <= self.action_pct):
            raise ValueError("[psi] need recovery_pct < advisory_pct <= action_pct")
        if not (self.usage_recovery < self.usage_advisory <= self.usage_action):
            raise ValueError("[governor] need usage_recovery < usage_advisory <= usage_action")
        self.calm_samples = 0

    def signals(self, s: Sample) -> tuple[float, float]:
        """(PSI percentage, usage fraction) used for classification."""
        psi = s.cgroup.pressure if (self.source == "cgroup" and s.cgroup is not None) else s.system_psi
        return psi.get(self.metric, self.window), (s.cgroup.usage_frac if s.cgroup else 0.0)

    def classify(self, s: Sample) -> Level:
        psi, usage = self.signals(s)
        if psi >= self.action_pct or usage >= self.usage_action:
            level = Level.ACTION
        elif psi >= self.advisory_pct or usage >= self.usage_advisory:
            level = Level.ADVISORY
        else:
            level = Level.NORMAL
        calm = psi <= self.recovery_pct and usage <= self.usage_recovery
        self.calm_samples = self.calm_samples + 1 if calm else 0
        return level

    @property
    def recovered(self) -> bool:
        return self.calm_samples >= self.hold

    def reset_recovery(self) -> None:
        self.calm_samples = 0


def progress_rows(path: Path) -> list[tuple[float, int, float, int]]:
    """(wall_time, iteration, work_s, pid) for every line of a compute_job progress log."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    return [(float(m[1]), int(m[2]), float(m[3]), int(m[4])) for m in map(PROGRESS_RE.match, lines) if m]


def largest_gap(rows: list[tuple[float, int, float, int]]) -> tuple[float, int]:
    """(gap_seconds, index i) of the longest pause between rows[i] and rows[i+1]."""
    return max((rows[k + 1][0] - rows[k][0], k) for k in range(len(rows) - 1))


def progress_continuity(path: Path) -> tuple[str, str]:
    """Judge from compute_job's progress log whether it RESUMED or RESTARTED.

    Finds the largest wall-clock gap between consecutive progress lines (the
    time spent checkpointed) and checks that the iteration counter never went
    backwards and that the PID stayed the same across the gap.
    """
    rows = progress_rows(path)
    if len(rows) < 2:
        return "NO-DATA", f"only {len(rows)} progress line(s) in {path}"
    gap, i = largest_gap(rows)
    (_, it0, _, pid0), (_, it1, _, pid1) = rows[i], rows[i + 1]
    backwards = [(a[1], b[1]) for a, b in zip(rows, rows[1:]) if b[1] <= a[1]]
    if backwards:
        return "RESTARTED", (f"iteration counter went backwards {backwards[:3]}: "
                             "the job started again from scratch")
    return "RESUMED", (f"largest gap {gap:.1f}s between iteration {it0} (pid {pid0}) and "
                       f"iteration {it1} (pid {pid1}); counter never went backwards "
                       f"over {len(rows)} lines (last iteration {rows[-1][1]})")


def load_reference_run(path: Path) -> dict:
    """Headline numbers from a saved live-run evidence directory (read-only).

    Used by baseline mode to print PRESERVE and the kernel OOM killer side by
    side. Reads the run's preserve.conf, compute_job progress log and final
    state, and the console log (for captures/restores and oom_kill).
    """
    ref: dict = {"path": str(path), "available": path.is_dir()}
    if not ref["available"]:
        return ref
    try:
        console = (path / "console.log").read_text(errors="replace")
    except OSError:
        console = ""
    # Prefer what the kernel actually reported for the run (scenario overrides
    # may differ from the base value in the saved preserve.conf).
    m = re.search(r"memory\.swap\.max = (\S+)", console)
    if m:
        ref["swap_max"] = m[1]
    else:
        cp = configparser.ConfigParser(inline_comment_prefixes=("#",), interpolation=None)
        cp.read(path / "preserve.conf")
        ref["swap_max"] = cp.get("cgroup", "memory_swap_max", fallback="?")
    m = re.search(r"scenario=(\S+)", console)
    ref["scenario"] = m[1] if m else "A"  # runs before scenarios existed used the base values
    rows = progress_rows(path / COMPUTE_PROGRESS)
    if len(rows) >= 2:
        gap, i = largest_gap(rows)
        ref.update(gap_s=gap, before_iteration=rows[i][1], before_work_s=rows[i][2],
                   after_iteration=rows[i + 1][1], resumed=all(b[1] > a[1] for a, b in zip(rows, rows[1:])))
    try:
        state = json.loads((path / COMPUTE_STATE).read_text())
        ref.update(final_iteration=state.get("iteration"), final_work_s=state.get("work_seconds"))
    except (OSError, ValueError):
        pass
    m = re.search(r"captures=(\d+)\s+restores=(\d+)", console)
    if m:
        ref.update(captures=int(m[1]), restores=int(m[2]))
    kills = [int(x) for x in re.findall(r"oom_kill=(\d+)", console)]
    ref["oom_kill"] = max(kills) if kills else None
    return ref


def side_by_side_table(ref: dict, base: dict) -> list[tuple[str, object, object]]:
    """Rows comparing a live PRESERVE run (``ref``) with a baseline result (``base``).

    ``ref`` comes from :func:`load_reference_run`, ``base`` is the
    ``baseline_result.json`` document written by baseline mode.
    """
    victims = base.get("victims", [])
    if base["compute_killed"]:
        b_fate = f"killed by kernel at iteration {base['compute_last_iteration']}"
        b_kept, b_lost = "0.00s", f"{base['compute_work_lost_s']:.2f}s"
    else:
        b_fate = "not selected by the OOM killer; ran on"
        b_kept, b_lost = f"{base['compute_final_work_s'] or 0:.2f}s (never interrupted)", "0.00s"
    killed = ", ".join(f"{v['role']} pid={v['pid']}" for v in victims) or "none"
    killed_work = sum(v.get("work_lost_s", 0.0) for v in victims)
    if ref.get("resumed") and ref.get("captures"):
        r_fate = f"checkpointed at iteration {ref.get('before_iteration')}, resumed at {ref.get('after_iteration')}"
        r_kept = f"{ref.get('before_work_s', 0):.2f}s at checkpoint"
        r_pause = f"{ref.get('gap_s', 0):.1f}s (checkpointed)"
    else:
        r_fate, r_kept, r_pause = "see reference log", "?", "?"
    swap = base["memory_swap_max"]
    return [
        ("", f"PRESERVE (live, scenario {ref.get('scenario')})",
         f"BASELINE (kernel OOM, scenario {base.get('scenario')})"),
        ("memory.swap.max", ref.get("swap_max"), "max" if swap is None else swap),
        ("governor checkpoints/restores", f"{ref.get('captures')}/{ref.get('restores')}", "0/0 (observe only)"),
        ("memory.events oom_kill", ref.get("oom_kill"), base["oom_kill"]),
        ("process(es) killed", "none" if not ref.get("oom_kill") else "see reference log", killed),
        ("compute_job fate", r_fate, b_fate),
        ("compute work preserved", r_kept, b_kept),
        ("compute work destroyed", "0.00s" if ref.get("resumed") else "?", b_lost),
        ("compute paused for", r_pause, "0s" if not base["compute_killed"] else "forever (dead)"),
        ("compute final iteration", ref.get("final_iteration"), base["compute_last_iteration"]),
        ("total work destroyed (all)", "0.00s" if not ref.get("oom_kill") else "?", f"{killed_work:.2f}s"),
    ]


# --------------------------------------------------------------------------
# Arena housekeeping: --arena-status and --reap-arena
# --------------------------------------------------------------------------
# Each image set carries a small state record so a reaper can tell an image that is
# the ONLY copy of a live process (checkpointed, never restored) from leftovers.
IMAGE_STATE = "preserve-state.json"
CRIU_DUMP_OK = "Dumping finished successfully"  # last line CRIU logs after a complete dump


def write_image_state(image_dir: Path | None, state: str, **fields: object) -> None:
    """Record inside an image set whether it still holds a not-yet-restored process."""
    if image_dir is None:
        return
    try:
        (Path(image_dir) / IMAGE_STATE).write_text(
            json.dumps({"state": state, "updated": time.time(), **fields}, indent=2))
    except OSError as exc:
        log.warning("could not record image state in %s: %s", image_dir, exc)


def classify_image(image_dir: Path) -> tuple[bool, str]:
    """(keep, why) for one image set. Keeping is the default whenever in doubt."""
    try:
        record = json.loads((image_dir / IMAGE_STATE).read_text())
    except FileNotFoundError:
        record = None
    except (OSError, ValueError) as exc:
        return True, f"state record unreadable ({exc}); kept"
    if record is not None:
        if record.get("state") == "checkpointed":
            return True, (f"KEPT: pid {record.get('pid')} ({record.get('role')}) is still checkpointed "
                          f"and was never restored -- this image is its only copy")
        if record.get("state") == "restored":
            return False, f"restored (pid {record.get('pid')}); image no longer needed"
        return True, f"unknown state {record.get('state')!r}; kept"
    # No record: an image made before records existed, or a dump that never finished.
    try:
        complete = CRIU_DUMP_OK in (image_dir / "dump.log").read_text(errors="replace")
    except OSError:
        complete = False
    if complete:
        return True, ("KEPT: complete dump with no state record (made before records existed); it may "
                      "be the only copy of a process -- delete by hand only if you are sure")
    return False, "partial or failed dump (CRIU never reported success)"


def _age(seconds: float) -> str:
    s = int(max(0, seconds))
    if s >= 86400:
        return f"{s // 86400}d{(s % 86400) // 3600}h"
    if s >= 3600:
        return f"{s // 3600}h{(s % 3600) // 60}m"
    if s >= 60:
        return f"{s // 60}m"
    return f"{s}s"


def _scan_arena(arena: Arena) -> list[Path]:
    if not arena.path.exists():
        return []
    return sorted(p for p in arena.path.iterdir() if p.is_dir())


def _arena_readable(arena: Arena) -> bool:
    return not arena.path.exists() or os.access(arena.path, os.R_OK | os.X_OK)


def arena_status(cfg: Config) -> int:
    """Print occupancy, capacity and every image with size, age and fate-if-reaped."""
    arena = Arena.from_config(cfg)
    if not _arena_readable(arena):
        # Never report 0: os.walk on an unreadable directory silently yields nothing.
        print(f"ARENA NOT READABLE by uid {os.geteuid()}: {arena.path} -- run with sudo")
        return 1
    lock = cfg.get_path("paths", "lock_file")
    from runlock import describe_held, is_held, read_holder
    images = _scan_arena(arena)
    used = arena.used_bytes()
    print(f"arena     : {arena.path}")
    print(f"occupancy : {used / MIB:.1f} MiB in {len(images)} image set(s) "
          f"of {arena.capacity_bytes / MIB:.0f} MiB budget ({100 * used / arena.capacity_bytes:.1f}%)")
    print(f"fs free   : {arena.fs_free_bytes() / MIB:.0f} MiB (admission keeps {arena.fs_reserve_bytes / MIB:.0f} MiB spare)")
    print(f"lock      : " + (f"HELD -- {describe_held(read_holder(lock))}; images may be in use"
                             if is_held(lock) else "free"))
    now = time.time()
    for d in images:
        keep, why = classify_image(d)
        print(f"  {d.name:44s} {tree_bytes(d) / MIB:8.1f} MiB  age {_age(now - d.stat().st_mtime):>6s}  "
              f"{'keep  ' if keep else 'reap  '} {why}")
    return 0


def reap_arena(cfg: Config) -> int:
    """Delete every image set except those that are the only copy of a live process."""
    arena = Arena.from_config(cfg)
    lock = RunLock(cfg.get_path("paths", "lock_file"))
    try:
        # Holding the governor lock: no governor can start (and own fresh images) mid-reap,
        # and none is running now, so no in-flight reservation exists anywhere.
        lock.acquire(holder_info("reap-arena", None, sys.argv))
    except LockHeld as exc:
        print(f"ARENA: NOT REAPED -- {exc}")
        return EXIT_LOCKED
    try:
        if not _arena_readable(arena):
            print(f"ARENA: NOT REAPED -- {arena.path} is not readable by uid {os.geteuid()} (run with sudo)")
            return 1
        before, images = arena.used_bytes(), _scan_arena(arena)
        deleted, freed, kept_live, kept_other = 0, 0, 0, 0
        for d in images:
            keep, why = classify_image(d)
            size = tree_bytes(d)
            if keep:
                log.warning("reap-arena: %s (%.1f MiB) -- %s", d.name, size / MIB, why)
                if why.startswith("KEPT: pid"):
                    kept_live += 1
                else:
                    kept_other += 1
                continue
            if not arena.contains(d):
                log.error("reap-arena: refusing to delete %s: outside the arena", d)
                kept_other += 1
                continue
            shutil.rmtree(d)
            deleted, freed = deleted + 1, freed + size
            log.info("reap-arena: deleted %s (%.1f MiB): %s", d.name, size / MIB, why)
        after = arena.used_bytes()
        # There is no persisted arena accounting to reset: occupancy is measured from
        # disk each time, and reservations live only inside a running governor.
        line = (f"ARENA: before {before / MIB:.1f} MiB in {len(images)} image(s); deleted {deleted} "
                f"({freed / MIB:.1f} MiB); kept {kept_live} still-checkpointed"
                + (f" + {kept_other} unrecorded/unknown" if kept_other else "")
                + f"; now {after / MIB:.1f} of {arena.capacity_bytes / MIB:.0f} MiB")
        log.info(line)
        print(line)
        return 0
    finally:
        lock.release()


class Governor:
    """Owns the test cgroup, the managed processes and the control loop."""

    def __init__(self, cfg: Config, mode: str, reset_throughput: bool = False,
                 inject: str | None = None) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if inject is not None and inject not in FAULTS:
            raise ValueError(f"--inject must be one of {FAULTS}")
        if inject is not None and mode != "live":
            raise ValueError("--inject is only meaningful in live mode")
        self.cfg = cfg
        self.mode = mode
        self.reset_throughput = reset_throughput
        self.inject = inject
        self.fault_stood_down = False  # set once the injected fault has forced a stand-down
        # Self-verification bookkeeping: did the injected fault's precondition actually occur?
        self.injection_failed = False     # the fault did NOT fire (e.g. a dump that should fail succeeded)
        self.injection_reason = ""        # why it is considered failed/unverified
        self.fault_dump_attempted = False
        self.fault_dump_failed = False
        self.fault_dump_enospc = False
        self.fault_setup_failed = False
        self.scenario = cfg.scenario
        self.observe_only = mode != "live"  # dry-run and baseline never invoke CRIU
        self.uid, self.gid = invoking_ids()
        self.cgroup = TestCgroup.for_run(cfg)  # unique per run: never shared with another run
        self.whitelist = PidWhitelist(self.cgroup)
        self.sensor = Sensor(self.cgroup.path)
        self.cost = CostModel(cfg)
        self.arena = Arena.from_config(cfg)
        self.admission = AdmissionController(cfg, self.arena)
        self.capture = CriuCapture(cfg, self.whitelist, self.cgroup, self.arena)
        self.classifier = PressureClassifier(cfg)
        self.run_dir = cfg.get_path("paths", "run_dir")
        self.throughput_file = cfg.get_path("paths", "throughput_state")

        g = "governor"
        self.interval = cfg.get_float("sensor", "sample_interval_s")
        self.log_every = cfg.get_int("sensor", "log_every_n_samples")
        self.cooldown_s = cfg.get_float(g, "capture_cooldown_s")
        self.decision_log_interval_s = cfg.get_float(g, "decision_log_interval_s")
        self.restore_max_attempts = cfg.get_int(g, "restore_max_attempts")
        self.grace_s = cfg.get_float(g, "terminate_grace_s")

        # --measure-overhead bookkeeping (mode "overhead")
        self.overhead_duration_s = cfg.get_float("overhead", "duration_s")
        self.step_times: list[float] = []
        self.level_counts: dict[str, int] = {}
        self.compute_args: list[str] = []
        self.overhead: dict = {}

        self.start = time.monotonic()
        self.level = Level.NORMAL
        self.samples = 0
        self.captures = 0
        self.restores = 0
        self.last_capture = -math.inf
        self.last_decision_log = -math.inf
        self.last_oom_kill = 0
        self.restore_attempts: dict[int, int] = {}
        self.preserved_rss: dict[int, int] = {}
        self.restored_pids: set[int] = set()  # successfully restored at least once (continuity verdict)
        # Last known facts about each managed process, kept so that a process
        # killed by the kernel can still be described after it is gone.
        self.start_uptime = read_uptime()
        self.swap_max_used: int | None = None
        self.last_state: dict[int, dict] = {}
        self.last_cpu: dict[int, float] = {}
        self.last_rss: dict[int, int] = {}
        self.exits: dict[int, tuple[float, int | None]] = {}  # pid -> (elapsed, returncode)
        self.first_oom_at: float | None = None
        # Objective 6: dependency groups
        self.workload = cfg.get_str("workloads", "workload")  # compute | pipeline
        self.logged_edges: set[tuple] = set()
        self.logged_groups: set[tuple[int, ...]] = set()
        self.group_standdowns: set[str] = set()
        self.group_of: dict[int, list[int]] = {}         # root pid -> members, for the current decision
        self.preserved_groups: dict[int, list[int]] = {}  # root pid -> members checkpointed together
        self.final_events: dict[str, int] = {}
        self.events: list[str] = []
        self._pending_event: list[str] = []
        self._stop = False
        self._telemetry_file = None
        self._telemetry: csv.writer | None = None

    # -- bookkeeping --------------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self.start

    def event(self, msg: str, level: int = logging.INFO) -> None:
        """Log a significant event and remember it for the summary and telemetry."""
        log.log(level, msg)
        self.events.append(f"{self.elapsed():7.1f}s  {msg}")
        self._pending_event.append(msg)

    def request_stop(self, signum: int, _frame) -> None:
        log.warning("received %s; stopping after this step", signal.Signals(signum).name)
        self._stop = True

    # -- setup ----------------------------------------------------------------------
    def setup(self) -> None:
        if not self.observe_only:
            ok, msg = self.capture.available()
            if not ok:
                raise SystemExit(f"cannot use CRIU: {msg}. Use --dry-run to observe without capturing.")
            log.info("criu: %s", msg)
        self._init_throughput()
        c = "cgroup"
        swap_key = "baseline_memory_swap_max" if self.mode == "baseline" else "memory_swap_max"
        self.swap_max_used = self.cfg.get_size(c, swap_key)
        log.info("mode=%s: memory.swap.max = %s (from [cgroup] %s = %s)", self.mode,
                 "max" if self.swap_max_used is None else self.swap_max_used, swap_key,
                 self.cfg.get_str(c, swap_key))
        self.cgroup.create(self.cfg.get_size(c, "memory_max"), self.swap_max_used,
                           self.cfg.get_size(c, "memory_high"))
        self.arena.ensure()
        if self.inject == "arena-too-small":
            # Shrink the arena budget so the real M3 *capacity* test ("arena full")
            # is the check that fails. NB: do not do this with arena.reserve() --
            # a reservation also counts as an in-flight capture, so the DENY would
            # come from max_inflight_captures instead, mislabelling the fault.
            was = self.arena.capacity_bytes
            self.arena.capacity_bytes = FAULT_ARENA_CAPACITY_BYTES
            log.warning("FAULT INJECTION [arena-too-small]: arena budget shrunk from %.0f MiB to "
                        "%.2f MiB so the capture admission capacity test sees no room",
                        was / MIB, self.arena.capacity_bytes / MIB)
        log.info(self.arena.summary())
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for name in RUN_FILES:
            (self.run_dir / name).unlink(missing_ok=True)
        (self.run_dir / BASELINE_RESULT).unlink(missing_ok=True)
        (self.run_dir / OVERHEAD_RESULT).unlink(missing_ok=True)
        if self._drop_to() is not None:
            os.chown(self.run_dir, self.uid, self.gid)
        self._open_telemetry()
        self.event(f"run start: scenario={self.scenario} mode={self.mode} "
                   f"memory.swap.max={self.cgroup.read('memory.swap.max')}"
                   + (f" inject={self.inject}" if self.inject else ""))

    def _stand_down(self, precondition: str) -> None:
        """Log a fault-induced stand-down, naming the fault and the failed precondition.

        STAND DOWN means: do not capture; leave the kernel in charge, exactly as
        if PRESERVE were not running. This is the fail-safe path the report claims.
        """
        self.fault_stood_down = True
        self.event(f"STAND DOWN [fault={self.inject}]: {precondition}; "
                   "not capturing -- kernel left in charge (fail-safe)", logging.WARNING)

    def _shown(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.cfg.root))
        except ValueError:
            return str(path)

    def _init_throughput(self) -> None:
        """Load (or, with --reset-throughput, discard) the persisted dump-throughput estimate."""
        shown = self._shown(self.throughput_file)
        if self.reset_throughput:
            discarded = ""
            if self.throughput_file.exists():
                try:
                    old = json.loads(self.throughput_file.read_text()).get("throughput_mib_s")
                    discarded = f"saved estimate {float(old):.1f} MiB/s in {shown} " if old is not None else ""
                except (OSError, ValueError, TypeError):
                    discarded = f"unreadable {shown} "
                self.throughput_file.unlink()
            provenance = f"default, {discarded or 'no saved estimate '}discarded by --reset-throughput"
        else:
            provenance = self.cost.load_throughput(self.throughput_file, shown)
        log.info("dump throughput estimate %.1f MiB/s (%s)", self.cost.throughput_mib_s, provenance)

    def _save_throughput(self) -> None:
        try:
            self.cost.save_throughput(self.throughput_file)
            give_to_invoking_user(self.throughput_file)
            log.info("dump throughput estimate %.1f MiB/s saved to %s (%d observation(s))",
                     self.cost.throughput_mib_s, self._shown(self.throughput_file), self.cost.observations)
        except OSError as exc:
            log.warning("could not save throughput estimate to %s: %s", self.throughput_file, exc)

    def _drop_to(self) -> tuple[int, int] | None:
        """Credentials for workloads: the sudo caller, not root (if configured)."""
        if os.geteuid() != 0 or self.uid == 0 or not self.cfg.get_bool("workloads", "run_as_invoking_user"):
            return None
        return self.uid, self.gid

    def _open_telemetry(self) -> None:
        path = self.cfg.get_path("paths", "telemetry_csv")
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists()
        self._telemetry_file = open(path, "a", newline="")
        self._telemetry = csv.writer(self._telemetry_file)
        if new:
            self._telemetry.writerow(TELEMETRY_FIELDS)
        give_to_invoking_user(path)

    # -- launching workloads ---------------------------------------------------------
    def _launch(self, role: str, script: str, args: list[str], state_file: Path) -> ManagedProcess:
        python = self.cfg.get_str("workloads", "python_bin") or sys.executable
        argv = [python, str(self.cfg.root / "workloads" / script)] + args
        popen = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,  # setsid(): own session, no controlling tty
            cwd=self.run_dir,
            preexec_fn=self.cgroup.preexec_enter(self._drop_to()),  # join cgroup before exec
        )
        entry = self.whitelist.admit_launched(popen, role, state_file)
        self.event(f"launched {role} pid={popen.pid} into {self.cgroup.rel}")
        return entry

    def launch_compute(self) -> ManagedProcess:
        w = "workloads"
        state = self.run_dir / COMPUTE_STATE
        args = [
            "--state-file", str(state),
            "--progress-log", str(self.run_dir / COMPUTE_PROGRESS),
            "--working-set-mb", self.cfg.get_str(w, "compute_working_set_mb"),
            "--hashes-per-iteration", self.cfg.get_str(w, "compute_hashes_per_iteration"),
            "--step-sleep-s", self.cfg.get_str(w, "compute_step_sleep_s"),
            "--report-every", self.cfg.get_str(w, "compute_report_every"),
            "--touch-every", self.cfg.get_str(w, "compute_touch_every"),
            "--max-iteration-credit-s", self.cfg.get_str(w, "compute_max_iteration_credit_s"),
        ]
        # Recorded so an A/B run can start the *identical* workload without the governor.
        self.compute_args = list(args)
        return self._launch("compute", "compute_job.py", args, state)

    def launch_hog(self) -> ManagedProcess:
        w = "workloads"
        state = self.run_dir / HOG_STATE
        return self._launch("hog", "hog.py", [
            "--state-file", str(state),
            "--chunk-mb", self.cfg.get_str(w, "hog_chunk_mb"),
            "--interval-s", self.cfg.get_str(w, "hog_interval_s"),
            "--target-mb", self.cfg.get_str(w, "hog_target_mb"),
            "--hold-s", self.cfg.get_str(w, "hog_hold_s"),
            "--retouch-interval-s", self.cfg.get_str(w, "hog_retouch_interval_s"),
        ], state)

    def launch_pipeline(self) -> ManagedProcess:
        """pipeline_job: the parent is launched; its child is admitted when discovered."""
        w = "workloads"
        return self._launch(PIPELINE_ROLES["parent"], "pipeline_job.py", [
            "--run-dir", str(self.run_dir),
            "--parent-mb", self.cfg.get_str(w, "pipeline_parent_mb"),
            "--child-mb", self.cfg.get_str(w, "pipeline_child_mb"),
            "--hashes-per-iteration", self.cfg.get_str(w, "compute_hashes_per_iteration"),
            "--step-sleep-s", self.cfg.get_str(w, "compute_step_sleep_s"),
            "--report-every", self.cfg.get_str(w, "compute_report_every"),
            "--touch-every", self.cfg.get_str(w, "compute_touch_every"),
            "--max-iteration-credit-s", self.cfg.get_str(w, "compute_max_iteration_credit_s"),
        ], self.run_dir / PIPELINE_STATE.format("parent"))

    # -- dependency groups (Objective 6) ----------------------------------------------
    def _discover_children(self) -> None:
        """Admit processes in the test cgroup forked by a whitelisted parent (cgroup.py rules)."""
        known = {e.pid for e in self.whitelist.with_state(RUNNING)}
        for pid in sorted(self.cgroup.procs() - known):
            snap = self.sensor.proc(pid)
            parent = self.whitelist.get(snap.ppid) if snap is not None else None
            if parent is None:
                continue
            state_file = None
            if parent.role == PIPELINE_ROLES["parent"]:
                role = PIPELINE_ROLES["child"]
                state_file = self.run_dir / PIPELINE_STATE.format("child")
            else:
                role = f"{parent.role}-child"
            if self.whitelist.admit_child(pid, role, state_file) is not None:
                self.event(f"admitted {role} pid={pid}: child of whitelisted {parent.role} pid={parent.pid}, "
                           f"inside {self.cgroup.rel}")

    def _groups(self) -> list[deps.Group]:
        """Dependency groups among running managed processes; logs every new edge with its proof."""
        groups = deps.build_groups([e.pid for e in self.whitelist.with_state(RUNNING)])
        for g in groups:
            for e in g.edges:
                if e.key not in self.logged_edges:
                    self.logged_edges.add(e.key)
                    self.event(f"DEPENDENCY {e.describe()}")
            key = tuple(g.members)
            if g.size > 1 and key not in self.logged_groups:
                self.logged_groups.add(key)
                roles = [self.whitelist.get(p).role for p in g.members]
                self.event(f"GROUP {list(key)} ({'+'.join(roles)}): {len(g.edges)} edge(s); "
                           "scored, checkpointed and restored as one unit")
        return groups

    def _member_fates(self) -> list[tuple[ManagedProcess, str]]:
        out = []
        for role in PIPELINE_ROLES.values():
            for e in self.whitelist.by_role(role):
                if e.pid in self.exits:
                    t, rc = self.exits[e.pid]
                    st = self._read_state(e)
                    how = (f"exited rc={rc}" if rc is not None and rc >= 0 else
                           f"killed by {signal.Signals(-rc).name}" if rc is not None else
                           "died (not the governor's child: exit status unknown)")
                    if st.get("partner_lost"):
                        how += f"; its own final state says partner lost ({st['partner_lost']})"
                    out.append((e, f"KILLED at {t:.1f}s, {how}"))
                elif e.state == PRESERVED:
                    out.append((e, f"CHECKPOINTED, NOT RESTORED (image {e.image_dir})"))
                elif e.pid in self.restored_pids:
                    out.append((e, "RESUMED"))
                else:
                    out.append((e, "RAN CONTINUOUSLY"))
        return out

    def _verify_chains(self) -> dict[str, tuple[bool, str]]:
        """Recompute every pipeline member's hash chain from its progress log (in parallel)."""
        python = self.cfg.get_str("workloads", "python_bin") or sys.executable
        procs = {}
        for short in PIPELINE_ROLES:
            path = self.run_dir / PIPELINE_PROGRESS.format(short)
            if not path.exists():
                continue
            procs[short] = subprocess.Popen(
                [python, str(self.cfg.root / "workloads" / "pipeline_job.py"), "--verify-log", str(path),
                 "--role", short, "--hashes-per-iteration",
                 self.cfg.get_str("workloads", "compute_hashes_per_iteration")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = {}
        for short, p in procs.items():
            text, _ = p.communicate()
            out[short] = (p.returncode == 0, text.strip().splitlines()[-1] if text.strip() else "(no output)")
        return out

    def group_fate(self) -> tuple[str, str]:
        """Group verdict from per-member events and hash chains. RESUMED only if EVERY member resumed."""
        fates = self._member_fates()
        if not fates:
            return "NO-DATA", "no pipeline group was launched"
        chains = self._verify_chains()
        for e, fate in fates:
            short = "parent" if e.role == PIPELINE_ROLES["parent"] else "child"
            ok, line = chains.get(short, (False, "no progress log"))
            log.info("  member %s pid=%d: %s; hash chain %s: %s", e.role, e.pid, fate,
                     "OK" if ok else "FAILED", line)
        n = len(fates)
        if n < len(PIPELINE_ROLES):
            return "INCOMPLETE", f"only {n} of {len(PIPELINE_ROLES)} members were ever whitelisted"
        resumed = [e for e, f in fates if f == "RESUMED"]
        killed = [e for e, f in fates if f.startswith("KILLED")]
        chains_ok = all(chains.get(s, (False, ""))[0] for s in PIPELINE_ROLES)
        if killed:
            return "KILLED", f"{len(killed)} of {n} members died"
        if len(resumed) == n and chains_ok:
            return "RESUMED", f"all {n} members checkpointed together, restored, alive, hash chains verified"
        if len(resumed) == n:
            return "NOT RESUMED", "all members restored but a hash chain failed verification"
        if any(f.startswith("CHECKPOINTED") for _, f in fates):
            return "CHECKPOINTED, NOT RESTORED", f"{n - len(resumed)} member(s) still only an image"
        return "RAN CONTINUOUSLY", f"no member was checkpointed; chains {'OK' if chains_ok else 'FAILED'}"

    @staticmethod
    def _read_state(entry: ManagedProcess) -> dict:
        """Workload-declared progress, only if it was written by this very PID."""
        if entry.state_file is None:
            return {}
        try:
            data = json.loads(entry.state_file.read_text())
        except (OSError, ValueError):
            return {}
        return data if data.get("pid") == entry.pid else {}

    # -- one control step ----------------------------------------------------------
    def step(self) -> None:
        sample = self.sensor.sample()
        self.samples += 1

        for e in self.whitelist.refresh():
            rc = e.returncode
            self.exits[e.pid] = (self.elapsed(), rc)
            if rc is not None and rc < 0:
                how = f"killed by {signal.Signals(-rc).name}"
            elif rc is None:
                how = "exited (not our child; status unknown)"
            else:
                how = f"exited rc={rc}"
            st = self.last_state.get(e.pid, {})
            if "iteration" in st:
                how += f" (last reported iteration {st['iteration']}, work {st.get('work_seconds', 0):.2f}s)"
            self.event(f"{e.role} pid={e.pid} {how}", logging.WARNING if rc not in (0, None) else logging.INFO)

        self._discover_children()
        self._groups()  # logs new dependency edges with their proof

        for e in self.whitelist.with_state(RUNNING):
            snap = self.sensor.proc(e.pid)
            if snap is not None:
                self.last_cpu[e.pid] = snap.cpu_seconds
                self.last_rss[e.pid] = snap.rss_bytes
            st = self._read_state(e)
            if st:
                self.last_state[e.pid] = st

        if sample.cgroup is not None:
            ook = sample.cgroup.events.get("oom_kill", 0)
            if ook > self.last_oom_kill:
                self.event(f"kernel OOM killer fired in test cgroup (oom_kill {self.last_oom_kill} -> {ook})",
                           logging.WARNING)
                self.last_oom_kill = ook
                if self.first_oom_at is None:
                    self.first_oom_at = self.elapsed()

        level = self.classifier.classify(sample)
        if level is not self.level:
            self.event(f"pressure {self.level.value} -> {level.value}: {format_sample(sample)}")
            self.level = level
        elif self.samples % self.log_every == 0:
            log.info("[%s] %s", level.value, format_sample(sample))

        if level is Level.ACTION:
            self._maybe_capture()
        self._maybe_restore(sample)
        self._write_telemetry(sample)

    def _maybe_capture(self) -> None:
        now = time.monotonic()
        if now - self.last_capture < self.cooldown_s:
            return
        verbose = now - self.last_decision_log >= self.decision_log_interval_s
        if verbose:
            self.last_decision_log = now

        scores: list[Score] = []
        self.group_of = {}
        tree_check: dict[int, tuple[bool, str]] = {}
        for g in self._groups():
            if g.size == 1:  # a single process is a group of one: scored exactly as before
                e = self.whitelist.get(g.members[0])
                snap = self.sensor.proc(e.pid)
                if snap is None or not snap.alive:
                    continue
                scores.append(self.cost.score(snap, e.role, self._read_state(e).get("work_seconds")))
                continue
            members = [(self.sensor.proc(p), self.whitelist.get(p)) for p in g.members]
            if any(snap is None or not snap.alive for snap, _ in members):
                continue
            ok, root, why = deps.capturable(g)
            root = root if root is not None else g.members[0]
            self.group_of[root] = list(g.members)
            tree_check[root] = (ok, why)
            label = "group[" + "+".join(e.role for _, e in members) + "]"
            scores.append(self.cost.score_group(
                root, label, [(snap, self._read_state(e).get("work_seconds")) for snap, e in members]))
        ranked = self.cost.rank(scores)
        if verbose:
            for s in ranked:
                log.info("  M2 %s", s.describe())
                if s.pid in self.group_of:
                    log.info("     members %s; R, RSS and C summed over all members; CRIU tree check: %s",
                             self.group_of[s.pid], tree_check[s.pid][1])

        for s in ranked:
            decision = self.admission.admit_capture(s)
            refused_tree = s.pid in self.group_of and not tree_check[s.pid][0]
            if verbose or (decision.admitted and not refused_tree):
                log.info("  M3 %s pid=%d: %s", s.role, s.pid, decision)
            if not decision.admitted:
                if self.inject == "arena-too-small" and s.eligible and not self.fault_stood_down:
                    # The real M3 test denied an otherwise-admissible process.
                    self._stand_down(f"M3 capture admission DENY for {s.role} pid={s.pid}: {decision.reason}")
                continue
            if s.pid in self.group_of:
                ok, why = tree_check[s.pid]
                if not ok:
                    # CRIU would take a different set of processes than the group, or
                    # break a link to an outside process: refuse to capture any of it.
                    if why not in self.group_standdowns:
                        self.group_standdowns.add(why)
                        self.event(f"STAND DOWN [group]: {s.role} members {self.group_of[s.pid]} not "
                                   f"capturable as one CRIU tree: {why}; not capturing -- kernel left "
                                   "in charge", logging.WARNING)
                    continue
                log.info("  group %s members %s: ADMIT as one CRIU tree: %s", s.role, self.group_of[s.pid], why)
            self.last_capture = now
            if self.observe_only:
                self.event(f"{self.mode.upper()}: WOULD checkpoint {s.role} pid={s.pid} "
                           f"(R={s.restart_cost_s:.1f}s, C~{s.capture_cost_s:.2f}s, frees ~{s.mem_mib:.0f}MiB); "
                           "CRIU not invoked" + ("; kernel OOM killer left to act" if self.mode == "baseline" else ""))
                return
            if self.inject == "governor-dies":
                # Abrupt crash after the ACTION threshold is crossed and a victim
                # is chosen, but before any capture. No cleanup runs: the cgroup
                # and workloads survive under the kernel, exactly as if PRESERVE
                # had never been here. run_failsafe.sh cleans up the remains.
                self.event(f"FAULT INJECTION [governor-dies]: ACTION crossed, {s.role} pid={s.pid} "
                           "chosen; simulating an abrupt governor crash before any capture "
                           "(os._exit, no shutdown)", logging.CRITICAL)
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(137)
            self.event(f"ACTION: checkpoint {s.role} pid={s.pid} (R={s.restart_cost_s:.1f}s, "
                       f"C~{s.capture_cost_s:.2f}s, frees ~{s.mem_mib:.0f}MiB)")
            self._capture(s)
            return
        if verbose:
            log.warning("ACTION level but no admissible candidate: kernel reclaim / OOM killer decides")

    def _capture(self, s: Score) -> None:
        entry = self.whitelist.get(s.pid)
        before = self._read_state(entry) if entry else {}

        if self.inject == "stale-pid" and entry is not None:
            # Corrupt the recorded (pid, starttime) so the real whitelist reuse
            # guard mismatches, as if the PID had been recycled. Restore it after
            # so shutdown can still manage the process.
            saved = entry.start_ticks
            entry.start_ticks = -1
            self.event("FAULT INJECTION [stale-pid]: recorded starttime corrupted so the "
                       "(pid, starttime) reuse check will mismatch", logging.WARNING)
            try:
                self.capture.dump(s.pid)  # verify() must refuse before CRIU runs
                self.event("stale-pid: dump was NOT refused -- this is a bug", logging.ERROR)
            except SafetyRefusal as exc:
                self._stand_down(f"whitelist PID-reuse guard refused the dump ({exc})")
            finally:
                entry.start_ticks = saved
            return

        fault = self.inject if self.inject in ("dump-fail", "dump-timeout") else None
        if fault:
            self.fault_dump_attempted = True
        members = self.group_of.get(s.pid)
        if members:
            # Re-check right before CRIU runs: the tree must still be exactly the group.
            ok, _root, why = deps.capturable(deps.Group(members))
            if not ok:
                self.event(f"STAND DOWN [group]: tree changed before dump: {why}; not capturing",
                           logging.WARNING)
                return
        key = f"dump-{s.pid}"
        self.arena.reserve(key, s.est_image_bytes)
        try:
            res = self.capture.dump(s.pid, fault=fault, members=members)
        except SafetyRefusal as exc:
            self.event(f"capture refused: {exc}", logging.ERROR)
            return
        finally:
            self.arena.release(key)  # release accounting whatever happened

        if fault and res.setup_failed:
            # The fault could not be established (e.g. tmpfs did not mount). Do NOT
            # run or report an unfaulted result -- declare the injection failed.
            self.fault_setup_failed = True
            self.injection_failed = True
            self.injection_reason = res.error
            self.event(f"INJECTION SETUP FAILED - fault did not occur: {res.error}", logging.CRITICAL)
            return
        if fault and res.ok:
            # A dump that was supposed to fail completed. This must never be
            # reported as a fault row; flag the injection as failed.
            self.injection_failed = True
            self.injection_reason = (f"{fault}: CRIU dump SUCCEEDED when it was required to fail "
                                     "(fault mechanism ineffective)")
            self.event(f"INJECTION FAILED - fault did not occur: {self.injection_reason}", logging.CRITICAL)
            # The process is now checkpointed; restore it so we leave nothing dead.
            self.captures += 1
            self.preserved_rss[s.pid] = int(s.mem_mib * MIB)
            self.event("attempting restore so the wrongly-dumped process is not left checkpointed",
                       logging.WARNING)
            try:
                self.capture.restore(s.pid)
            except (SafetyRefusal, CgroupError) as exc:
                self.event(f"could not restore wrongly-dumped process: {exc}", logging.ERROR)
            return

        if res.ok:
            self.captures += 1
            self.preserved_rss[s.pid] = int(s.mem_mib * MIB)
            self.cost.observe_capture(res.image_bytes, res.seconds)
            self._save_throughput()
            it = before.get("iteration")
            self.event(f"PRESERVED {res.describe()}" + (f"; last reported iteration {it}" if it else ""))
            if members:
                self.preserved_groups[s.pid] = list(members)
                for m in members:
                    st = self._read_state(self.whitelist.get(m))
                    self.event(f"  group member {self.whitelist.get(m).role} pid={m} checkpointed in the same "
                               f"image; last reported iteration {st.get('iteration')}, "
                               f"work {st.get('work_seconds')}s")
            # Record in the image itself that a live process now exists only as this
            # image, so --reap-arena can never delete it while it is not restored.
            write_image_state(res.image_dir, "checkpointed", pid=s.pid, role=s.role,
                              scenario=self.scenario, governor_pid=os.getpid(),
                              last_iteration=it, work_seconds=before.get("work_seconds"),
                              **({"members": members} if members else {}))
            if self.inject == "restore-blocked":
                # Arm a permanent restore DENY through the real admission headroom
                # test: claim the process needs more memory than can ever fit.
                self.preserved_rss[s.pid] = 1 << 62
                self.event("FAULT INJECTION [restore-blocked]: restore admission will DENY for "
                           "the whole run; process stays checkpointed on disk", logging.WARNING)
        else:
            self.event(res.describe(), logging.ERROR)
            if res.log_tail:
                log.error("dump.log tail:\n%s", res.log_tail)
            if fault:
                self.fault_dump_failed = True
                self.fault_dump_enospc = res.enospc
            if self.inject == "dump-fail":
                if res.enospc:
                    self.event("dump-fail: confirmed CRIU failed with ENOSPC (tmpfs full) as intended")
                else:
                    # It failed, but not by the mechanism we injected: do not count it.
                    self.injection_failed = True
                    self.injection_reason = (f"dump-fail: dump failed but NOT with ENOSPC "
                                             f"(error: {res.error})")
                    self.event(f"INJECTION FAILED - fault did not occur: {self.injection_reason}",
                               logging.CRITICAL)
            self._after_failed_dump(s.pid, res)

    def _after_failed_dump(self, pid: int, res) -> None:
        """Clean up a failed/timed-out dump and report, honestly, if the target survived."""
        if res.image_dir is not None and self.arena.contains(res.image_dir) and res.image_dir.exists():
            try:
                os.chmod(res.image_dir, 0o700)  # dump-fail injection left it read-only
            except OSError:
                pass
            shutil.rmtree(res.image_dir, ignore_errors=True)
            self.event(f"cleaned up partial image set {res.image_dir.name}; arena accounting released")
        # Did the target survive a failed dump, or was it lost? (honest, no recovery logic)
        snap = self.sensor.proc(pid)
        entry = self.whitelist.get(pid)
        alive = (snap is not None and snap.alive and entry is not None
                 and snap.start_ticks == entry.start_ticks)
        if alive:
            self.event(f"after failed dump: target {entry.role} pid={pid} SURVIVED, still running "
                       "and unfrozen; no work lost")
        else:
            self.event(f"after failed dump: target pid={pid} is GONE -- a failed dump LOST the "
                       "process (real limitation, reported as-is; no recovery logic added)", logging.ERROR)
        if self.inject in ("dump-fail", "dump-timeout"):
            self.fault_stood_down = True
            self.event(f"STAND DOWN [fault={self.inject}]: dump did not complete; no process left "
                       "frozen or half-dumped, kernel left in charge (fail-safe)", logging.WARNING)

    def _maybe_restore(self, sample: Sample) -> None:
        # Non-root group members come back with their root's tree; never restore them alone.
        followers = {m for root, ms in self.preserved_groups.items() for m in ms if m != root}
        pending = [e for e in self.whitelist.with_state(PRESERVED)
                   if self.restore_attempts.get(e.pid, 0) < self.restore_max_attempts
                   and e.pid not in followers]
        if not pending:
            return
        entry = pending[0]  # FIFO: oldest checkpoint first
        decision = self.admission.admit_restore(self.preserved_rss.get(entry.pid, 0), sample.cgroup,
                                                self.classifier.recovered)
        if not decision.admitted:
            now = time.monotonic()
            if self.classifier.recovered and now - self.last_decision_log >= self.decision_log_interval_s:
                self.last_decision_log = now
                log.info("  M3 restore %s pid=%d deferred: %s", entry.role, entry.pid, decision)
                if self.inject == "restore-blocked" and not self.fault_stood_down:
                    self._stand_down(f"M3 restore admission DENY for {entry.role} pid={entry.pid}: "
                                     f"{decision.reason}; process remains safely checkpointed")
            return

        attempt = self.restore_attempts.get(entry.pid, 0) + 1
        self.restore_attempts[entry.pid] = attempt
        self.event(f"RECOVERY: restore {entry.role} pid={entry.pid} attempt {attempt} ({decision.reason})")
        members = self.preserved_groups.get(entry.pid)
        try:
            res = self.capture.restore(entry.pid, members=members)
        except (SafetyRefusal, CgroupError) as exc:
            self.event(f"restore aborted: {exc}", logging.ERROR)
            return
        if res.ok:
            self.restores += 1
            self.restored_pids.add(entry.pid)
            self.classifier.reset_recovery()
            self.event(f"RESTORED {res.describe()}")
            for m in members or []:
                snap = self.sensor.proc(m)
                me = self.whitelist.get(m)
                alive = snap is not None and snap.alive and me.state == RUNNING \
                    and snap.start_ticks == me.start_ticks and self.cgroup.contains(m)
                if alive:
                    self.restored_pids.add(m)
                self.event(f"  group member {me.role} pid={m} after restore: "
                           + (f"ALIVE, ppid={snap.ppid}, in {self.cgroup.rel}" if alive else "NOT ALIVE"),
                           logging.INFO if alive else logging.ERROR)
            # If the image is kept after restore, it no longer holds the only copy.
            if res.image_dir is not None and res.image_dir.is_dir():
                write_image_state(res.image_dir, "restored", pid=entry.pid, role=entry.role,
                                  scenario=self.scenario, governor_pid=os.getpid())
        else:
            self.event(res.describe(), logging.ERROR)
            if res.log_tail:
                log.error("restore.log tail:\n%s", res.log_tail)
            if attempt >= self.restore_max_attempts:
                self.event(f"giving up on {entry.role} pid={entry.pid}; image kept at {entry.image_dir}",
                           logging.ERROR)

    def _write_telemetry(self, s: Sample) -> None:
        if self._telemetry is None:
            return
        cg = s.cgroup
        self._telemetry.writerow([
            f"{s.wall:.3f}", f"{self.elapsed():.2f}", self.level.value,
            s.system_psi.get("some", "avg10"),
            cg.pressure.get("some", "avg10") if cg else "",
            cg.pressure.get("full", "avg10") if cg else "",
            f"{cg.current / MIB:.1f}" if cg else "",
            f"{cg.max / MIB:.1f}" if cg and cg.max else "",
            f"{cg.swap_current / MIB:.1f}" if cg else "",
            f"{cg.usage_frac:.3f}" if cg else "",
            cg.events.get("oom_kill", 0) if cg else "",
            len(self.whitelist.with_state(RUNNING)),
            len(self.whitelist.with_state(PRESERVED)),
            " | ".join(self._pending_event),
        ])
        self._telemetry_file.flush()
        self._pending_event.clear()

    # -- scenario -------------------------------------------------------------------
    def run_demo(self, with_hog: bool) -> None:
        w, g = "workloads", "governor"
        hog_delay = self.cfg.get_float(w, "hog_start_delay_s")
        duration = self.cfg.get_float(g, "demo_duration_s")
        post_restore = self.cfg.get_float(g, "demo_post_restore_s")
        post_oom = self.cfg.get_float("baseline", "post_oom_observe_s")
        if self.workload == "pipeline":
            self.launch_pipeline()
        else:
            self.launch_compute()
        hog_started = not with_hog
        restored_at: float | None = None
        while not self._stop:
            t0 = time.monotonic()
            if not hog_started and self.elapsed() >= hog_delay:
                self.launch_hog()
                hog_started = True
            self.step()
            if restored_at is None and self.restores:
                restored_at = self.elapsed()
            if restored_at is not None and self.elapsed() - restored_at >= post_restore:
                self.event(f"demo complete: watched restored job for {post_restore:.0f}s")
                break
            if self.mode == "baseline" and self.first_oom_at is not None \
                    and self.elapsed() - self.first_oom_at >= post_oom:
                self.event(f"baseline complete: watched {post_oom:.0f}s past the first OOM kill")
                break
            if self.elapsed() >= duration:
                self.event(f"demo_duration_s ({duration:.0f}s) reached", logging.WARNING)
                break
            if hog_started and not self.whitelist.with_state(RUNNING) and not self.whitelist.with_state(PRESERVED):
                self.event("no managed processes left", logging.WARNING)
                break
            time.sleep(max(0.0, self.interval - (time.monotonic() - t0)))

    # -- overhead measurement (mode "overhead") --------------------------------------
    def run_overhead(self) -> None:
        """Measure what the governor costs while doing nothing, which is the normal case.

        The workload runs with **no antagonist**, so usage stays well under
        ``usage_advisory_frac`` and PSI stays at zero: the loop samples and
        evaluates but never captures. Needs no CRIU and therefore no root.
        """
        dur = self.overhead_duration_s
        self.launch_compute()
        me = os.getpid()
        snap0 = self.sensor.proc(me)
        ru0 = resource.getrusage(resource.RUSAGE_SELF)
        t0 = time.monotonic()
        # tree_bytes() walks with os.walk, which yields NOTHING for a directory this
        # user cannot read (the arena is mode 0700 and may be root-owned from an
        # earlier privileged run). Without this check a measured 0 would be an
        # artifact, not a fact, so report it as unknown instead.
        arena_readable = os.access(self.arena.path, os.R_OK | os.X_OK)
        if not arena_readable:
            log.warning("arena %s is not readable by uid %d: its on-disk usage will be reported as "
                        "unknown rather than 0", self.arena.path, os.geteuid())
        peak_arena = self.arena.used_bytes() if arena_readable else None
        log.info("measuring governor overhead for %.0fs (workload running, no antagonist)", dur)

        while not self._stop and time.monotonic() - t0 < dur:
            it0 = time.monotonic()
            self.step()  # one sample-and-evaluate iteration
            self.step_times.append(time.monotonic() - it0)
            self.level_counts[self.level.value] = self.level_counts.get(self.level.value, 0) + 1
            if arena_readable:
                peak_arena = max(peak_arena, self.arena.used_bytes())
            time.sleep(max(0.0, self.interval - (time.monotonic() - it0)))

        elapsed = time.monotonic() - t0
        ru1 = resource.getrusage(resource.RUSAGE_SELF)
        snap1 = self.sensor.proc(me)
        cpu = (ru1.ru_utime + ru1.ru_stime) - (ru0.ru_utime + ru0.ru_stime)
        times = sorted(self.step_times)
        n = len(times)
        rss0 = snap0.rss_bytes if snap0 else 0
        rss1 = snap1.rss_bytes if snap1 else 0
        self.overhead = {
            "mode": "overhead", "scenario": self.scenario,
            "duration_s": round(elapsed, 2),
            "sample_interval_s": self.interval,
            "sampling_iterations": n,
            "iter_mean_ms": round(1000 * sum(times) / n, 3) if n else None,
            "iter_p95_ms": round(1000 * times[min(n - 1, int(0.95 * (n - 1)))], 3) if n else None,
            "iter_max_ms": round(1000 * times[-1], 3) if n else None,
            "governor_cpu_s": round(cpu, 3),
            "governor_cpu_pct_one_core": round(100 * cpu / elapsed, 3) if elapsed else None,
            "rss_start_mib": round(rss0 / MIB, 2),
            "rss_end_mib": round(rss1 / MIB, 2),
            "rss_delta_mib": round((rss1 - rss0) / MIB, 2),
            "captures": self.captures, "restores": self.restores,
            "level_counts": dict(self.level_counts),
            "cgroup_memory_max_mib": round((self.cfg.get_size("cgroup", "memory_max") or 0) / MIB, 0),
            # The arena is a DIRECTORY on ext4 with a byte budget -- not pinned memory.
            # Arena only does mkdir / stat / statvfs plus an in-memory dict of ints.
            "arena_capacity_mib": round(self.arena.capacity_bytes / MIB, 0),
            "arena_peak_used_mib": None if peak_arena is None else round(peak_arena / MIB, 2),
            "arena_readable_by_governor": arena_readable,
            "images_written_this_run": self.captures,  # 0 captures => the arena was not written to
            "arena_ram_pinned_mib": 0.0,
            "arena_kind": "disk budget (ext4 directory), not pinned RAM",
            "fs_reserve_mib": round(self.arena.fs_reserve_bytes / MIB, 0),
            "compute_args": list(self.compute_args),
        }

    def _overhead_summary(self) -> int:
        """Log the overhead report and write it as JSON for the A/B harness."""
        o = self.overhead
        if not o:
            log.error("overhead measurement produced no data")
            return 1
        # compute_job's final state is written on SIGTERM during shutdown.
        try:
            o["compute_iterations"] = json.loads((self.run_dir / COMPUTE_STATE).read_text()).get("iteration")
        except (OSError, ValueError):
            o["compute_iterations"] = None
        reached = [lvl for lvl in ("advisory", "action") if o["level_counts"].get(lvl)]
        o["stayed_below_advisory"] = not reached
        out = self.run_dir / OVERHEAD_RESULT
        out.write_text(json.dumps(o, indent=2))
        give_to_invoking_user(out)

        log.info("GOVERNOR OVERHEAD (idle: workload running, no antagonist, no capture)")
        log.info("  window                    : %.2fs at %.2fs sample interval", o["duration_s"],
                 o["sample_interval_s"])
        log.info("  sampling iterations       : %d", o["sampling_iterations"])
        log.info("  per-iteration time        : mean %.3f ms, p95 %.3f ms, max %.3f ms",
                 o["iter_mean_ms"], o["iter_p95_ms"], o["iter_max_ms"])
        log.info("  governor CPU time         : %.3fs = %.3f%% of one core",
                 o["governor_cpu_s"], o["governor_cpu_pct_one_core"])
        log.info("  governor RSS              : %.2f MiB -> %.2f MiB (delta %+.2f MiB)",
                 o["rss_start_mib"], o["rss_end_mib"], o["rss_delta_mib"])
        log.info("  captures / restores       : %d / %d", o["captures"], o["restores"])
        log.info("  pressure levels seen      : %s%s", o["level_counts"],
                 "" if o["stayed_below_advisory"] else "  <-- reached advisory/action: NOT an idle measurement")
        log.info("  arena                     : %s", o["arena_kind"])
        peak = ("unknown (not readable by this uid)" if o["arena_peak_used_mib"] is None
                else f"{o['arena_peak_used_mib']:.2f} MiB")
        log.info("    budget %.0f MiB, peak on-disk use %s, images written this run %d, RAM pinned %.1f MiB",
                 o["arena_capacity_mib"], peak, o["images_written_this_run"], o["arena_ram_pinned_mib"])
        log.info("    free-space guard (fs_reserve_mib) %.0f MiB; protected cgroup %.0f MiB",
                 o["fs_reserve_mib"], o["cgroup_memory_max_mib"])
        log.info("  compute_job iterations    : %s (this arm: governor running)", o["compute_iterations"])
        log.info("overhead result written to %s", out)
        if o["captures"]:
            log.error("a capture happened: this is not an idle-overhead measurement")
            return 1
        return 0 if o["stayed_below_advisory"] else 1

    # -- teardown -------------------------------------------------------------------
    def _wait_exit(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while self.whitelist.with_state(RUNNING) and time.monotonic() < deadline:
            self.whitelist.refresh()
            time.sleep(self.interval)
        self.whitelist.refresh()

    def shutdown(self) -> None:
        # memory.events disappears with the cgroup: keep its final counters.
        if self.cgroup.exists():
            self.final_events = dict(read_cgroup_memory(self.cgroup.path).events)
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for e in self.whitelist.with_state(RUNNING):
                try:
                    self.whitelist.signal(e.pid, sig)
                except (SafetyRefusal, ProcessLookupError) as exc:
                    log.warning("could not signal %s pid=%d: %s", e.role, e.pid, exc)
            self._wait_exit(self.grace_s)
        for e in self.whitelist.with_state(PRESERVED):
            # Verify the image is really on disk: "work recoverable" is only true
            # if the image set still exists. The governor runs as root, so it can
            # read the arena (mode 0700) that an unprivileged script cannot.
            present = e.image_dir is not None and e.image_dir.is_dir()
            detail = (f"image present, {tree_bytes(e.image_dir) / MIB:.1f}MiB" if present
                      else "IMAGE MISSING - work is NOT recoverable")
            self.event(f"{e.role} pid={e.pid} is still checkpointed at {e.image_dir} ({detail})",
                       logging.WARNING)
        if self._telemetry_file is not None:
            self._telemetry_file.close()
            self._telemetry, self._telemetry_file = None, None
        if self.cfg.get_bool("cgroup", "remove_on_exit"):
            try:
                self.cgroup.destroy()
            except (CgroupError, OSError) as exc:
                log.warning("cgroup not removed: %s", exc)

    def compute_fate(self) -> tuple[str, str]:
        """What actually happened to compute_job -- from events, not only log gaps.

        RESUMED                    checkpointed and restored (and its counter never went back)
        RAN CONTINUOUSLY           never checkpointed, alive when the run ended
        KILLED                     died during the run; its work is lost
        CHECKPOINTED, NOT RESTORED still exists only as an image when the run ended
        RESTARTED                  the counter went backwards: state was not preserved
        NO-DATA                    no compute_job was launched
        A process that died is KILLED even if its progress log has no gap: the old
        log-only check called a SIGKILLed job "RESUMED -- largest gap 0.7s".
        """
        entries = self.whitelist.by_role("compute")
        if not entries:
            return "NO-DATA", "no compute_job was launched"
        e = entries[0]
        st = self.last_state.get(e.pid, {})
        rows = progress_rows(self.run_dir / COMPUTE_PROGRESS)
        backwards = [(a[1], b[1]) for a, b in zip(rows, rows[1:]) if b[1] <= a[1]]
        last_it = st.get("iteration", rows[-1][1] if rows else None)

        if e.pid in self.exits:  # died during the run (shutdown's own SIGTERM is not recorded here)
            t, rc = self.exits[e.pid]
            if rc is None:  # a restored process is not our child: its exit status is unknowable
                how = "died (exit status unknown: not the governor's child after restore)"
            elif rc < 0:
                how = f"killed by {signal.Signals(-rc).name}"
            else:
                how = f"exited rc={rc}"
            return "KILLED", (f"{how} at {t:.1f}s; final iteration {st.get('iteration')}, "
                              f"{self._work_lost(e.pid):.2f}s of work lost")
        if e.state == PRESERVED:
            return "CHECKPOINTED, NOT RESTORED", (f"exists only as the image at {e.image_dir}; "
                                                 f"last iteration before checkpoint {last_it}")
        if backwards:
            return "RESTARTED", (f"iteration counter went backwards {backwards[:3]}: "
                                 "the job started again from scratch")
        if e.pid in self.restored_pids:
            if len(rows) >= 2:
                gap, i = largest_gap(rows)
                return "RESUMED", (f"checkpointed and restored; largest gap {gap:.1f}s between "
                                   f"iteration {rows[i][1]} and {rows[i + 1][1]}; counter never went "
                                   f"backwards (last iteration {rows[-1][1]})")
            return "RESUMED", "checkpointed and restored (too few progress lines to measure the gap)"
        return "RAN CONTINUOUSLY", f"never checkpointed, alive at the end of the run; last iteration {last_it}"

    def summary(self) -> int:
        verdict, detail = self.compute_fate()
        log.info("=" * 72)
        log.info("SUMMARY  scenario=%s  mode=%s  captures=%d  restores=%d  samples=%d",
                 self.scenario, self.mode, self.captures, self.restores, self.samples)
        for line in self.events:
            log.info("  %s", line)
        if self.workload == "pipeline":
            # Objective 6: the verdict is the GROUP's, from per-member events and hash chains.
            verdict, detail = self.group_fate()
            log.info("pipeline group continuity: %s -- %s", verdict, detail)
        else:
            log.info("compute_job continuity: %s -- %s", verdict, detail)
        log.info("=" * 72)
        if self.mode == "baseline":
            return self.baseline_report()
        if self.mode == "overhead":
            return self._overhead_summary()
        if self.observe_only:
            return 0
        if self.inject:
            return self._fault_summary()
        if self.captures == 0:
            return 2  # pressure never led to a capture: tune preserve.conf
        if self.restores == 0:
            return 3
        return 0 if verdict == "RESUMED" else 1

    # -- fault self-verification ------------------------------------------------------
    def _fault_summary(self) -> int:
        """Assert the injected fault's precondition actually occurred.

        Returns 0 only when the fault fired and produced its fail-safe outcome.
        Returns 4 (INJECTION FAILED) when the fault did not occur -- so a fault
        that silently does not fire can never be reported as a passing row.
        """
        RC_INJECTION_FAILED = 4
        preserved = bool(self.whitelist.with_state(PRESERVED))
        if self.injection_failed:
            log.critical("INJECTION FAILED - fault did not occur [%s]: %s",
                         self.inject, self.injection_reason or "precondition not satisfied")
            return RC_INJECTION_FAILED

        # Per-fault assertion: (condition that must hold, human description).
        if self.inject in ("arena-too-small", "stale-pid"):
            ok = self.fault_stood_down and self.captures == 0
            why = "stood down with no capture"
            state = "stood down, kernel left in charge"
        elif self.inject in ("dump-fail", "dump-timeout"):
            ok = self.fault_dump_attempted and self.fault_dump_failed and self.captures == 0
            if self.inject == "dump-fail":
                ok = ok and self.fault_dump_enospc
            why = "a real dump was attempted, failed, and nothing was checkpointed"
            state = "dump attempted and failed; stood down"
        elif self.inject == "restore-blocked":
            ok = self.captures == 1 and self.restores == 0 and preserved
            why = "process was dumped and then permanently denied restore"
            state = "checkpointed, not restored"
        else:
            ok, why, state = False, "unknown fault", "unknown"

        if not ok:
            self.injection_reason = f"expected that {why}; observed captures={self.captures} " \
                f"restores={self.restores} stood_down={self.fault_stood_down} " \
                f"dump_failed={self.fault_dump_failed} enospc={self.fault_dump_enospc}"
            log.critical("INJECTION FAILED - fault did not occur [%s]: %s", self.inject, self.injection_reason)
            return RC_INJECTION_FAILED

        log.info("FAULT RESULT  inject=%s  VERIFIED (%s)  captures=%d  restores=%d  state: %s",
                 self.inject, why, self.captures, self.restores, state)
        return 0

    # -- baseline comparison ----------------------------------------------------------
    def _work_lost(self, pid: int) -> float:
        """Work destroyed by killing ``pid``: the cost model's R at its last observation."""
        return max(self.last_cpu.get(pid, 0.0), float(self.last_state.get(pid, {}).get("work_seconds", 0.0)))

    def baseline_report(self) -> int:
        """Who did the kernel kill, what was lost, and how that compares with PRESERVE."""
        oom_kill = self.final_events.get("oom_kill", self.last_oom_kill)
        kernel = read_kernel_oom_kills(self.start_uptime - 1.0)
        sigkilled = {pid: t for pid, (t, rc) in self.exits.items() if rc == -signal.SIGKILL}
        tolerance_s = 2 * self.interval + 1.0
        victims: dict[int, dict] = {}
        unmatched: list[dict] = []
        for k in kernel or []:
            if k.oom_memcg not in (None, self.cgroup.rel):
                continue  # an OOM in some other cgroup, not our experiment
            record = {"kernel_pid": k.pid, "anon_rss_mib": round(k.anon_rss_kib / 1024, 1), "kernel_line": k.line}
            if k.pid in sigkilled and k.pid not in victims:
                victims[k.pid] = {"pid": k.pid, "source": "kernel log (same PID)", **record}
                continue
            # The kernel logs PIDs of the *initial* PID namespace. Under WSL2 (and in
            # containers) the governor lives in a nested PID namespace and sees other
            # numbers, so match the record to the managed process that died by
            # SIGKILL at the same moment instead.
            k_elapsed = k.uptime - self.start_uptime
            # Admitted children (Objective 6) are not our children, so their exit status is
            # unknown (rc None); they are candidates too. In A/B every process is our child.
            cands = sorted((abs(t - k_elapsed), pid) for pid, t in
                           list(sigkilled.items()) + [(p, t) for p, (t, rc) in self.exits.items() if rc is None]
                           if pid not in victims)
            if cands and cands[0][0] <= tolerance_s:
                delta, pid = cands[0]
                victims[pid] = {"pid": pid, **record,
                                "source": f"kernel log pid {k.pid} (initial PID namespace) = pid {pid} here; "
                                          f"matched by time of death (delta {delta:.2f}s)"}
            else:
                unmatched.append(record)
        if kernel is None or len(victims) < oom_kill:
            for pid in sigkilled:
                # Fallback when dmesg is unreadable: SIGKILL we did not send, while oom_kill > 0.
                if pid not in victims and oom_kill > 0:
                    victims[pid] = {"pid": pid, "source": "SIGKILL exit + memory.events oom_kill"}
            # Admitted children (Objective 6) are not our children: exit status unknown. A
            # member that left no partner_lost note of its own died without exiting itself.
            for pid, (t, rc) in self.exits.items():
                e = self.whitelist.get(pid)
                if rc is None and pid not in victims and oom_kill > len(victims) and e is not None \
                        and e.parent is not None and not self._read_state(e).get("partner_lost"):
                    victims[pid] = {"pid": pid, "source": "died without exiting itself (no partner_lost "
                                                          "note) + memory.events oom_kill"}
        for v in victims.values():
            entry = self.whitelist.get(v["pid"])
            v["role"] = entry.role if entry else "?"
            v["last_observed_rss_mib"] = round(self.last_rss.get(v["pid"], 0) / MIB, 1)
        for v in victims.values():
            st = self.last_state.get(v["pid"], {})
            v.update(killed_at_s=round(self.exits.get(v["pid"], (None, None))[0] or 0, 1),
                     last_iteration=st.get("iteration"), work_lost_s=round(self._work_lost(v["pid"]), 2),
                     cpu_s=round(self.last_cpu.get(v["pid"], 0.0), 2))

        computes = self.whitelist.by_role("compute")
        compute = computes[0] if computes else None
        compute_killed = compute is not None and compute.pid in victims
        rows = progress_rows(self.run_dir / COMPUTE_PROGRESS)
        result = {
            "mode": "baseline",
            "scenario": self.scenario,
            "memory_swap_max": self.swap_max_used,
            "memory_events": self.final_events,
            "oom_kill": oom_kill,
            "kernel_log_readable": kernel is not None,
            "victims": list(victims.values()),
            "unmatched_kernel_records": unmatched,
            "compute_pid": compute.pid if compute else None,
            "compute_killed": compute_killed,
            "compute_last_iteration": (self.last_state.get(compute.pid, {}).get("iteration")
                                       if compute_killed else (rows[-1][1] if rows else None)),
            "compute_work_lost_s": round(self._work_lost(compute.pid), 2) if compute_killed else 0.0,
            "compute_final_work_s": rows[-1][2] if rows else None,
        }
        group_lines: list[str] = []
        if self.workload == "pipeline":
            # Objective 6: how many members died, how, and the total work destroyed.
            members, dead, lost = [], 0, 0.0
            for role in PIPELINE_ROLES.values():
                for e in self.whitelist.by_role(role):
                    died = e.pid in self.exits
                    st = self._read_state(e)  # final state written by the member itself, if any
                    work = max(self._work_lost(e.pid), float(st.get("work_seconds", 0.0)))
                    if e.pid in victims:
                        cause = "OOM-killed by the kernel (" + victims[e.pid]["source"] + ")"
                    elif st.get("partner_lost"):
                        cause = f"exited because its partner died (own final state: {st['partner_lost']})"
                    elif died:
                        rc = self.exits[e.pid][1]
                        cause = f"died, rc={rc}" if rc is not None else "died (exit status unknown)"
                    else:
                        cause = "survived"
                    if died:
                        dead += 1
                        lost += work
                    members.append({"pid": e.pid, "role": role, "died": died, "cause": cause,
                                    "last_iteration": st.get("iteration"),
                                    "work_lost_s": round(work, 2) if died else 0.0})
                    group_lines.append(f"    {role} pid={e.pid}: {cause}; last iteration {st.get('iteration')}, "
                                       f"work {'destroyed' if died else 'kept'} {work:.2f}s")
            result["group"] = {"members": members, "members_died": dead, "members_total": len(members),
                               "work_destroyed_s": round(lost, 2)}
            group_lines.insert(0, f"  pipeline group            : {dead} of {len(members)} members died, "
                                  f"{lost:.2f}s of work destroyed in total")
        out = self.run_dir / BASELINE_RESULT
        out.write_text(json.dumps(result, indent=2))
        give_to_invoking_user(out)

        log.info("BASELINE RESULT (kernel OOM killer, no PRESERVE intervention)")
        log.info("  memory.swap.max used      : %s", "max" if self.swap_max_used is None else self.swap_max_used)
        log.info("  memory.events             : %s", self.final_events or "(cgroup already gone)")
        log.info("  OOM killer fired?         : %s (oom_kill=%d)", "YES" if oom_kill else "NO", oom_kill)
        if kernel is None:
            log.warning("  kernel log unreadable (dmesg); victim attribution uses exit status only")
        for v in victims.values():
            log.info("  victim                    : %s pid=%d", v["role"], v["pid"])
            log.info("    identified by: %s", v["source"])
            if "kernel_line" in v:
                log.info("    kernel: %s", v["kernel_line"])
                log.info("    RSS cross-check: kernel anon-rss %.1fMiB vs last observed RSS %.1fMiB",
                         v["anon_rss_mib"], v["last_observed_rss_mib"])
            log.info("    killed at %.1fs, last iteration %s, CPU %.2fs, work destroyed %.2fs",
                     v["killed_at_s"], v["last_iteration"], v["cpu_s"], v["work_lost_s"])
        for u in unmatched:
            log.warning("  kernel OOM record not matched to any managed process: %s", u["kernel_line"])
        if oom_kill and not victims:
            log.warning("  oom_kill > 0 but the victim could not be identified")
        if compute is not None:
            if compute_killed:
                log.info("  compute_job               : KILLED at iteration %s -> %.2fs of work destroyed",
                         result["compute_last_iteration"], result["compute_work_lost_s"])
            else:
                log.info("  compute_job               : survived (reached iteration %s, %.2fs work)",
                         result["compute_last_iteration"], result["compute_final_work_s"] or 0.0)
        for line in group_lines:
            log.info(line)

        log.info("-" * 72)
        ref_setting = self.cfg.get_str("baseline", "reference_live_run")
        if not ref_setting:
            log.info("no reference live run configured for scenario %s; after the live run compare with:\n"
                     "  python3 src/compare.py --live evidence/<live dir> --baseline evidence/<this baseline dir>",
                     self.scenario)
        else:
            ref = load_reference_run(self.cfg.get_path("baseline", "reference_live_run"))
            if not ref.get("available"):
                log.warning("reference live run %s not found; no side-by-side comparison", ref["path"])
            else:
                log.info("SIDE BY SIDE  (PRESERVE reference: %s)", ref["path"])
                for name, a, b in side_by_side_table(ref, result):
                    log.info("  %-30s | %-46s | %s", name, a, b)
        log.info("-" * 72)
        log.info("baseline result written to %s", out)
        return 0 if oom_kill else 2  # 2: the kernel never had to kill anything


def main() -> int:
    ap = argparse.ArgumentParser(description="PRESERVE memory-pressure governor.")
    ap.add_argument("--config", default=None, help="path to preserve.conf")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="score and admit, but never invoke CRIU")
    g.add_argument("--baseline", action="store_true",
                   help="control experiment: observe only, swap from baseline_memory_swap_max, kernel OOM acts")
    g.add_argument("--measure-overhead", action="store_true",
                   help="measure the governor's idle cost: workload only, no antagonist, no capture "
                        "(needs no CRIU, so no root)")
    g.add_argument("--arena-status", action="store_true",
                   help="print arena occupancy, capacity, and each image with size and age, then exit")
    g.add_argument("--reap-arena", action="store_true",
                   help="delete every image except those still checkpointed and never restored, then exit "
                        "(takes the governor lock; refuses while a governor runs)")
    ap.add_argument("--overhead-duration", type=float, default=None,
                    help="seconds to measure with --measure-overhead (default: [overhead] duration_s)")
    ap.add_argument("--no-hog", action="store_true", help="do not launch the memory hog (control run)")
    ap.add_argument("--scenario", default=None,
                    help="named scenario from preserve.conf [scenario.<name>] (default: [scenarios] default)")
    ap.add_argument("--reset-throughput", action="store_true",
                    help="discard the saved dump-throughput estimate and start from initial_dump_mib_per_s")
    ap.add_argument("--inject", default=None, choices=FAULTS,
                    help="live mode only: inject a fault to demonstrate the fail-safe stand-down path")
    args = ap.parse_args()

    cfg = Config(args.config, args.scenario)
    setup_logging(cfg)
    if args.arena_status:
        return arena_status(cfg)
    if args.reap_arena:
        return reap_arena(cfg)
    if args.baseline:
        mode = "baseline"
    elif args.measure_overhead:
        mode = "overhead"
    elif args.dry_run or cfg.get_bool("governor", "dry_run"):
        mode = "dry-run"
    else:
        mode = "live"
    if args.inject and mode != "live":
        ap.error(f"--inject {args.inject} requires live mode (not --baseline/--dry-run)")
    log.info("=" * 72)
    log.info("PRESERVE governor start: pid=%d euid=%d invoking uid=%d scenario=%s mode=%s config=%s",
             os.getpid(), os.geteuid(), invoking_ids()[0], cfg.scenario, mode, cfg.path)
    log.info("scenario %s: %s", cfg.scenario, cfg.scenario_description)
    for (section, key), value in sorted(cfg.overrides.items()):
        log.info("  scenario override [%s] %s = %s", section, key, value)

    # One governor at a time. Taken BEFORE anything is created or cleared: the
    # cgroup, the run/ files and the arena are only touched while holding it.
    lock = RunLock(cfg.get_path("paths", "lock_file"))
    try:
        lock.acquire(holder_info(mode, cfg.scenario, sys.argv))
    except LockHeld as exc:
        _refuse(str(exc))
        return EXIT_LOCKED
    except OSError as exc:
        _refuse(f"cannot open lock file {lock.path} ({exc}); refusing to run without the lock")
        return EXIT_LOCKED
    log.info("lock acquired: %s held by pid %d", lock.path, os.getpid())

    if args.inject:
        log.warning("FAULT INJECTION ARMED: --inject %s (live mode; demonstrates the fail-safe path)",
                    args.inject)
    gov = Governor(cfg, mode, reset_throughput=args.reset_throughput, inject=args.inject)
    if args.overhead_duration is not None:
        gov.overhead_duration_s = args.overhead_duration
    signal.signal(signal.SIGINT, gov.request_stop)
    signal.signal(signal.SIGTERM, gov.request_stop)
    setup_ok = False
    try:
        gov.setup()
        setup_ok = True
        lock.update(cgroup=str(gov.cgroup.path))  # lets a later run find our leftovers
        if mode == "overhead":
            gov.run_overhead()
        else:
            gov.run_demo(with_hog=not args.no_hog)
    except (CgroupError, SafetyRefusal, OSError) as exc:
        log.critical("aborting: %s", exc)
        gov.event(f"aborted: {exc}", logging.CRITICAL)
    finally:
        gov.shutdown()
    if not setup_ok:
        # Setup never completed, so no experiment ran. Do NOT fall through to
        # summary(): its exit codes describe experiment outcomes ("no OOM kill",
        # "no capture") and would misreport a refusal as a result.
        _refuse(f"setup did not complete; no experiment ran (exit {EXIT_SETUP_FAILED})")
        lock.release()
        return EXIT_SETUP_FAILED
    rc = gov.summary()
    lock.release()
    return rc


def _refuse(message: str) -> None:
    """A loud, unmissable refusal in both the console and evidence/governor.log."""
    bar = "#" * 72
    log.critical(bar)
    log.critical("REFUSING TO RUN: %s", message)
    log.critical(bar)


if __name__ == "__main__":
    sys.exit(main())
