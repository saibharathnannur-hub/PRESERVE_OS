"""
admission.py -- M3: checkpoint-arena accounting and admission tests.

The arena
---------
A checkpoint moves a process's memory from RAM to disk. That is only a
win if the disk side is bounded and the move itself cannot make things worse.
The **arena** is the directory that holds CRIU image sets, with a fixed byte
budget (``arena_size_mib``). It is managed like a simple allocator:

* ``used``: bytes of image sets already on disk (measured with ``lstat``).
* ``reserved``: bytes promised to dumps that are in flight. A dump's size
  is only known afterwards, so the cost model's estimate is reserved *before*
  CRIU starts and released when it finishes. This is the same
  reserve-then-commit pattern a kernel uses for memory overcommit
  accounting.
* ``capacity``: the configured budget.

The arena must live on a persistent, native filesystem (ext4 inside WSL2).
On ``tmpfs`` the "evicted" pages would still be in RAM, and on ``/mnt/c``
(9P to Windows, OneDrive-synced) image files could be modified behind
CRIU's back.

Admission tests
---------------
Before **capture** (checkpoint + evict), all must hold:

1. The cost model judged the process *eligible* (worth preserving).
2. Estimated dump time <= ``max_capture_s``. A dump that takes longer than
   the time left before the OOM killer acts would be wasted work.
3. Fewer than ``max_inflight_captures`` dumps are running. CRIU freezes
   the target and reads all of its memory, so parallel dumps compete for the
   same disk and prolong the stall.
4. ``used + reserved + estimate <= capacity`` (arena budget).
5. The filesystem keeps at least ``fs_reserve_mib`` free afterwards
   (``statvfs`` free blocks), so a full arena cannot fill the root disk.

Before **restore**, all must hold:

1. Pressure has *recovered*: PSI and usage stayed below the recovery
   thresholds for several consecutive samples. This hysteresis prevents
   thrashing between dump and restore.
2. The cgroup has headroom: ``limit - memory.current >= RSS * (1 + margin)``,
   where ``limit`` is the tighter of ``memory.high`` and ``memory.max``.
   Restoring into a cgroup without room for the process would itself trigger
   reclaim or an OOM kill.

Standalone use (only touches a private temporary directory)::

    python3 src/admission.py
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from config import Config
from costmodel import Score
from sensor import MIB, CgroupMemory


@dataclass(frozen=True)
class Decision:
    admitted: bool
    reason: str

    def __str__(self) -> str:
        return f"{'ADMIT' if self.admitted else 'DENY'}: {self.reason}"


def tree_bytes(path: Path) -> int:
    """Total size of regular files below ``path`` (no symlink following)."""
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except FileNotFoundError:
                pass
    return total


class Arena:
    """Byte-budgeted directory of CRIU image sets."""

    def __init__(self, path: Path, capacity_bytes: int, fs_reserve_bytes: int) -> None:
        self.path = Path(path)
        self.capacity_bytes = capacity_bytes
        self.fs_reserve_bytes = fs_reserve_bytes
        self.reservations: dict[str, int] = {}

    @classmethod
    def from_config(cls, cfg: Config, path: Path | None = None) -> "Arena":
        return cls(
            path or cfg.get_path("paths", "arena_dir"),
            int(cfg.get_float("admission", "arena_size_mib") * MIB),
            int(cfg.get_float("admission", "fs_reserve_mib") * MIB),
        )

    def ensure(self) -> None:
        """Create the arena directory (mode 0700: images contain process memory)."""
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)

    def contains(self, p: Path) -> bool:
        """True if ``p`` resolves to a location strictly inside the arena."""
        try:
            return Path(p).resolve().is_relative_to(self.path.resolve()) and \
                Path(p).resolve() != self.path.resolve()
        except OSError:
            return False

    def used_bytes(self) -> int:
        return tree_bytes(self.path) if self.path.exists() else 0

    def reserved_bytes(self) -> int:
        return sum(self.reservations.values())

    def fs_free_bytes(self) -> int:
        st = os.statvfs(self.path if self.path.exists() else self.path.parent)
        return st.f_bavail * st.f_frsize

    def reserve(self, key: str, nbytes: int) -> None:
        self.reservations[key] = nbytes

    def release(self, key: str) -> None:
        self.reservations.pop(key, None)

    def summary(self) -> str:
        return (f"arena {self.path}: used={self.used_bytes() / MIB:.1f}MiB "
                f"reserved={self.reserved_bytes() / MIB:.1f}MiB "
                f"capacity={self.capacity_bytes / MIB:.0f}MiB")


class AdmissionController:
    """Implements the capture and restore admission tests above."""

    def __init__(self, cfg: Config, arena: Arena) -> None:
        s = "admission"
        self.arena = arena
        self.max_inflight = cfg.get_int(s, "max_inflight_captures")
        self.max_capture_s = cfg.get_float(s, "max_capture_s")
        self.restore_margin = cfg.get_float(s, "restore_headroom_margin")

    def admit_capture(self, score: Score) -> Decision:
        if not score.eligible:
            return Decision(False, f"not worth preserving ({score.reason})")
        if score.capture_cost_s > self.max_capture_s:
            return Decision(False, f"estimated dump {score.capture_cost_s:.2f}s > "
                                   f"max_capture_s {self.max_capture_s}s")
        if len(self.arena.reservations) >= self.max_inflight:
            return Decision(False, f"{len(self.arena.reservations)} capture(s) in flight "
                                   f"(max {self.max_inflight})")
        est = score.est_image_bytes
        committed = self.arena.used_bytes() + self.arena.reserved_bytes()
        if committed + est > self.arena.capacity_bytes:
            return Decision(False, f"arena full: {committed / MIB:.1f}+{est / MIB:.1f}MiB > "
                                   f"{self.arena.capacity_bytes / MIB:.0f}MiB")
        free = self.arena.fs_free_bytes()
        if free - est < self.arena.fs_reserve_bytes:
            return Decision(False, f"filesystem would drop below reserve: free "
                                   f"{free / MIB:.0f}MiB - {est / MIB:.1f}MiB < "
                                   f"{self.arena.fs_reserve_bytes / MIB:.0f}MiB")
        return Decision(True, f"image ~{est / MIB:.1f}MiB fits arena "
                              f"({committed / MIB:.1f}/{self.arena.capacity_bytes / MIB:.0f}MiB used), "
                              f"dump ~{score.capture_cost_s:.2f}s")

    def admit_restore(self, rss_bytes: int, cg: CgroupMemory | None, recovered: bool) -> Decision:
        if not recovered:
            return Decision(False, "pressure has not stayed below recovery thresholds yet")
        if cg is None or cg.effective_limit is None:
            return Decision(True, "cgroup has no memory limit")
        need = int(rss_bytes * (1 + self.restore_margin))
        headroom = cg.effective_limit - cg.current
        if headroom < need:
            return Decision(False, f"headroom {headroom / MIB:.1f}MiB < needed {need / MIB:.1f}MiB "
                                   f"(RSS x {1 + self.restore_margin:.2f})")
        return Decision(True, f"headroom {headroom / MIB:.1f}MiB >= needed {need / MIB:.1f}MiB")


def _main() -> int:
    ap = argparse.ArgumentParser(description="Exercise arena accounting and admission tests (M3).")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = Config(args.config)

    with tempfile.TemporaryDirectory(prefix="preserve-arena-test-") as tmp:
        arena = Arena.from_config(cfg, Path(tmp) / "arena")
        arena.ensure()
        ctl = AdmissionController(cfg, arena)
        print(arena.summary())

        def mk(eligible: bool, image_mib: float, cost_s: float) -> Score:
            return Score(1, "synthetic", image_mib, 60.0, cost_s, int(image_mib * MIB),
                         1.0, eligible, "synthetic")

        cases = [
            ("eligible, small", mk(True, 128, 1.0)),
            ("not eligible", mk(False, 128, 1.0)),
            ("dump too slow", mk(True, 128, ctl.max_capture_s + 1)),
            ("larger than arena", mk(True, arena.capacity_bytes / MIB + 1, 1.0)),
        ]
        for label, sc in cases:
            print(f"capture  {label:20s} -> {ctl.admit_capture(sc)}")

        arena.reserve("inflight", 64 * MIB)
        print(f"capture  {'while one in flight':20s} -> {ctl.admit_capture(mk(True, 128, 1.0))}")
        arena.release("inflight")

        limit = 512 * MIB
        for current_mib, recovered in [(300, True), (450, True), (300, False)]:
            cg = CgroupMemory(Path("/synthetic"), current_mib * MIB, limit, None, 0, None, 0, 0)
            print(f"restore  cur={current_mib}MiB/512MiB recovered={recovered!s:5} -> "
                  f"{ctl.admit_restore(128 * MIB, cg, recovered)}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
