"""
cgroup.py -- test-cgroup lifecycle, process confinement, and the PID whitelist.

Part 1: the test cgroup
-----------------------
Control groups (cgroups) are the kernel mechanism for grouping processes and
applying resource controllers to the group. cgroup v2 has a single
hierarchy mounted at ``/sys/fs/cgroup``. Every directory is a cgroup, and its
files are the controller interface: writing ``536870912`` to ``memory.max``
caps the group at 512 MiB, and writing a PID to ``cgroup.procs`` moves that
process into the group.

**Why experiments are safe.** Every workload runs in one leaf cgroup whose
``memory.max`` and ``memory.swap.max`` are far below the machine's RAM. When
the group exceeds its limit, the kernel reclaims or OOM-kills *inside that
group only* (cgroup-local OOM). Processes outside it are unaffected. Under
WSL2 there is a second wall: the whole Linux kernel runs in a Hyper-V VM, so
even a total failure is contained in the VM, not Windows.

**One cgroup per run, never shared.** The configured ``[cgroup] name`` is only
a *prefix*. Each governor run creates ``<name>-<pid>-<YYYYmmddHHMMSS>`` (see
:meth:`TestCgroup.for_run`) with an atomic ``mkdir``: if the directory already
exists, creation fails loudly instead of adopting it. Two runs therefore
cannot share a memory limit, even if they start at the same instant. Before
this, every run used the bare name ``preserve-test``; two concurrent runs then
shared one 512 MiB limit, pushed each other's workloads into the OOM killer,
and produced output that looked valid. ``runlock.py`` additionally stops a
second governor from starting at all.

**Where the cgroup lives: systemd delegation.** systemd owns the cgroup tree.
The documented way for anything else to create cgroups is inside a subtree
systemd has *delegated*. Every logged-in user gets one at
``user.slice/user-<uid>.slice/user@<uid>.service``, with the ``memory``
controller enabled in its ``cgroup.subtree_control``. PRESERVE creates its
leaf cgroup there and **never modifies** the parent: if the parent does not
offer the memory controller, creation fails with an explanation.

**Confinement before exec.** A process must be inside the cgroup *before* it
allocates anything, or its first allocations would be charged elsewhere and
the limit would not apply. :meth:`TestCgroup.preexec_enter` returns a
function that :class:`subprocess.Popen` runs in the child after ``fork()``
and before ``execve()``. It writes the child's own PID into
``cgroup.procs`` and only then drops root privileges. By the time the
workload's first instruction runs, it is already confined. (Popen's own
``user=``/``group=`` arguments are not used because they drop privileges
*before* ``preexec_fn`` runs, and an unprivileged child could not write to
the root-owned ``cgroup.procs``.)

Part 2: the PID whitelist (safety gate)
---------------------------------------
Checkpointing kills the dumped process, so pointing CRIU at the wrong PID is
destructive. :class:`PidWhitelist` is the **only** path through which the
governor may checkpoint or signal a process. :meth:`PidWhitelist.verify`
contains hard-coded refusals that no configuration can switch off:

1. The PID must be an int greater than 1. PID 0 (scheduler/kernel) and PID
   1 (init) are always refused.
2. It must not be the governor itself or its parent.
3. It must have been *launched by this governor* (registered by
   :meth:`admit_launched`). Membership in the cgroup alone is not enough.
4. Its recorded ``starttime`` (``/proc/<pid>/stat`` field 22) must still
   match. PIDs are recycled by the kernel, so a PID that was ours may now
   belong to a stranger. (pid, starttime) is unique for the life of the
   kernel, so this defeats PID reuse.
5. ``/proc/<pid>/cgroup`` must show that it is *currently inside the test
   cgroup*.
6. The action must be one of the known actions, and a signal must be one of
   SIGTERM, SIGINT or SIGKILL.

Every refusal raises :class:`SafetyRefusal` and is logged at ERROR level.

Standalone use::

    python3 src/cgroup.py              # show where the cgroup would live and its state (read-only)
    python3 src/cgroup.py --create     # create it with limits from preserve.conf (needs permission)
    python3 src/cgroup.py --destroy    # remove it if empty
    python3 src/cgroup.py --refusal-demo   # show the whitelist refusing foreign PIDs (no side effects)
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from config import Config, format_size
from sensor import CGROUP_ROOT, PAGE_SIZE, proc_cgroup, read_proc

log = logging.getLogger("preserve.cgroup")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class CgroupError(RuntimeError):
    """The test cgroup could not be created, configured or removed."""


class SafetyRefusal(PermissionError):
    """The governor was asked to act on a process it is not allowed to touch."""


# ==========================================================================
# Part 1: the test cgroup
# ==========================================================================
class TestCgroup:
    """One leaf cgroup-v2 directory with memory limits, owned by the governor."""

    def __init__(self, parent: Path, name: str) -> None:
        if not _NAME_RE.match(name) or name in (".", ".."):
            raise CgroupError(f"invalid cgroup name {name!r}")
        self.parent = Path(parent)
        if not self.parent.resolve().is_relative_to(CGROUP_ROOT):
            raise CgroupError(f"parent {self.parent} is not under {CGROUP_ROOT}")
        self.path = self.parent / name
        # Path as it appears in /proc/<pid>/cgroup ("0::/user.slice/...").
        self.rel = "/" + str(self.path.relative_to(CGROUP_ROOT))
        self.created = False  # True only once THIS object's mkdir succeeded

    @classmethod
    def from_config(cls, cfg: Config) -> "TestCgroup":
        """The bare configured name -- for the standalone inspection tool only.

        Governor runs must use :meth:`for_run`, never this.
        """
        return cls(Path(cfg.get_str("cgroup", "parent")), cfg.get_str("cgroup", "name"))

    @classmethod
    def for_run(cls, cfg: Config) -> "TestCgroup":
        """A cgroup name unique to this run: ``<prefix>-<pid>-<YYYYmmddHHMMSS>``.

        The pid makes it unique among live processes, and the timestamp keeps it
        unique even if the kernel later reuses the pid.
        """
        name = f"{cfg.get_str('cgroup', 'name')}-{os.getpid()}-{time.strftime('%Y%m%d%H%M%S')}"
        return cls(Path(cfg.get_str("cgroup", "parent")), name)

    # -- inspection ---------------------------------------------------------
    @staticmethod
    def unified_hierarchy_mounted() -> bool:
        return (CGROUP_ROOT / "cgroup.controllers").exists()

    def parent_controllers(self) -> list[str]:
        """Controllers the parent hands down to its children (subtree_control)."""
        return (self.parent / "cgroup.subtree_control").read_text().split()

    def exists(self) -> bool:
        return (self.path / "cgroup.procs").exists()

    def procs(self) -> set[int]:
        if not self.exists():
            return set()
        return {int(x) for x in (self.path / "cgroup.procs").read_text().split()}

    def contains(self, pid: int) -> bool:
        """True if ``pid`` is currently a member of this cgroup."""
        return proc_cgroup(pid) == self.rel

    def read(self, knob: str) -> str:
        return (self.path / knob).read_text().strip()

    def _write(self, knob: str, value: str) -> None:
        (self.path / knob).write_text(value)

    # -- lifecycle ----------------------------------------------------------
    def create(self, memory_max: int | None, swap_max: int | None, memory_high: int | None) -> None:
        """Create the leaf cgroup and apply limits. Never touches the parent."""
        if not self.unified_hierarchy_mounted():
            raise CgroupError("cgroup v2 unified hierarchy is not mounted at /sys/fs/cgroup")
        if not self.parent.is_dir():
            raise CgroupError(f"parent cgroup {self.parent} does not exist "
                              "(is systemd running and the user logged in?)")
        if "memory" not in self.parent_controllers():
            raise CgroupError(f"memory controller is not enabled in {self.parent}/cgroup.subtree_control; "
                              "PRESERVE will not modify the parent")
        # Atomic: mkdir either creates the directory or fails with EEXIST, so there
        # is no window between "check" and "create" for another run to slip into.
        # An existing directory is NEVER reused, empty or not.
        try:
            self.path.mkdir()
        except FileExistsError:
            members = sorted(self.procs())
            raise CgroupError(
                f"REFUSING TO SHARE A CGROUP: {self.path} already exists"
                + (f" and contains PIDs {members}" if members else " (empty)")
                + ". Each run must have its own cgroup; another run is using this name, "
                  "or a previous run did not clean up.") from None
        self.created = True
        log.info("created cgroup %s (unique to this run)", self.path)

        for knob, value in (("memory.max", memory_max),
                            ("memory.swap.max", swap_max),
                            ("memory.high", memory_high)):
            self._write(knob, format_size(value))
            got = self.read(knob)
            # The kernel rounds limits down to a page boundary.
            ok = (got == "max") if value is None else (got != "max" and abs(int(got) - value) < PAGE_SIZE)
            if not ok:
                raise CgroupError(f"{knob}: wrote {format_size(value)}, kernel reports {got}")
            log.info("  %s = %s", knob, got)

    def destroy(self) -> None:
        """rmdir the cgroup -- but only one THIS run created.

        If create() failed because the directory already existed, that directory
        belongs to someone else; removing it (even when momentarily empty) would
        pull the cgroup out from under another run.
        """
        if not self.created:
            if self.exists():
                log.info("not removing %s: this run did not create it", self.path)
            return
        if not self.exists():
            return
        members = self.procs()
        if members:
            raise CgroupError(f"not removing {self.path}: still contains {sorted(members)}")
        self.path.rmdir()
        log.info("removed cgroup %s", self.path)

    # -- confinement --------------------------------------------------------
    def preexec_enter(self, drop_to: tuple[int, int] | None) -> Callable[[], None]:
        """Build a ``preexec_fn`` that joins this cgroup, then optionally drops root.

        Runs in the forked child before exec. Only plain ``os`` calls are used,
        because the child is a copy of the parent at fork time and must not
        rely on locks other threads may have held. If anything raises here,
        Popen reports it and the child never execs.
        """
        procs_file = str(self.path / "cgroup.procs")

        def _enter() -> None:
            fd = os.open(procs_file, os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode())
            finally:
                os.close(fd)
            if drop_to is not None:
                uid, gid = drop_to
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)

        return _enter

    def migrate(self, pid: int) -> None:
        """Move an existing process into this cgroup (used only after CRIU restore)."""
        self._write("cgroup.procs", str(pid))


# ==========================================================================
# Part 2: the PID whitelist
# ==========================================================================
RUNNING, PRESERVED, EXITED = "running", "preserved", "exited"

FORBIDDEN_PIDS = frozenset({0, 1})
ALLOWED_ACTIONS = frozenset({"checkpoint", "signal", "restore"})
ALLOWED_SIGNALS = frozenset({signal.SIGTERM, signal.SIGINT, signal.SIGKILL})


@dataclass
class ManagedProcess:
    """A process the governor launched into the test cgroup."""

    pid: int
    role: str
    start_ticks: int
    state: str = RUNNING
    popen: subprocess.Popen | None = None  # None after restore: no longer our child
    image_dir: Path | None = None  # set while PRESERVED
    state_file: Path | None = None  # workload-declared progress (JSON), optional
    returncode: int | None = None
    parent: int | None = None  # set for a child admitted via admit_child (its whitelisted parent)


class PidWhitelist:
    """The explicit set of PIDs the governor may act on (see module docstring)."""

    def __init__(self, cgroup: TestCgroup) -> None:
        self.cgroup = cgroup
        self._entries: dict[int, ManagedProcess] = {}

    # -- registration ---------------------------------------------------------
    def admit_launched(self, popen: subprocess.Popen, role: str,
                       state_file: Path | None = None) -> ManagedProcess:
        """Register a child we just launched. Fails if it is not confined."""
        pid = popen.pid
        snap = read_proc(pid)
        if snap is None:
            entry = ManagedProcess(pid, role, -1, EXITED, popen, state_file=state_file,
                                   returncode=popen.poll())
            self._entries[pid] = entry
            log.warning("%s pid=%d exited immediately (rc=%s)", role, pid, entry.returncode)
            return entry
        if not self.cgroup.contains(pid):
            raise CgroupError(f"launched {role} pid={pid} is in {proc_cgroup(pid)}, "
                              f"not {self.cgroup.rel}")
        entry = ManagedProcess(pid, role, snap.start_ticks, RUNNING, popen, state_file=state_file)
        self._entries[pid] = entry
        log.info("whitelisted %s pid=%d starttime=%d cgroup=%s", role, pid, snap.start_ticks,
                 self.cgroup.rel)
        return entry

    def admit_child(self, pid: int, role: str, state_file: Path | None = None) -> ManagedProcess | None:
        """Register a process forked by a whitelisted, running parent (Objective 6).

        Admitted only if: its ppid is a whitelisted RUNNING entry whose recorded
        (pid, starttime) still matches, and the child itself is inside the test
        cgroup. The child is then keyed on its own (pid, starttime), so every
        later action still passes through verify() unchanged. Returns None
        (and admits nothing) if any condition fails.
        """
        if pid in self._entries:
            return None
        snap = read_proc(pid)
        if snap is None or not snap.alive:
            return None
        parent = self._entries.get(snap.ppid)
        if parent is None or parent.state != RUNNING:
            return None
        psnap = read_proc(parent.pid)
        if psnap is None or psnap.start_ticks != parent.start_ticks:
            log.warning("not admitting pid=%d: parent pid=%d starttime changed (PID reuse?)", pid, snap.ppid)
            return None
        if not self.cgroup.contains(pid):
            log.warning("not admitting pid=%d (child of %s pid=%d): outside the test cgroup (in %s)",
                        pid, parent.role, parent.pid, proc_cgroup(pid))
            return None
        entry = ManagedProcess(pid, role, snap.start_ticks, RUNNING, None, state_file=state_file,
                               parent=parent.pid)
        self._entries[pid] = entry
        log.info("whitelisted %s pid=%d starttime=%d cgroup=%s (child of whitelisted %s pid=%d "
                 "starttime=%d)", role, pid, snap.start_ticks, self.cgroup.rel, parent.role,
                 parent.pid, parent.start_ticks)
        return entry

    # -- the safety gate ----------------------------------------------------
    def verify(self, pid: int, action: str, expect_state: str = RUNNING) -> ManagedProcess:
        """Return the entry for ``pid`` or raise SafetyRefusal. Hard-coded rules."""

        def refuse(why: str) -> None:
            log.error("SAFETY REFUSAL: %s pid=%r: %s", action, pid, why)
            raise SafetyRefusal(f"refusing to {action} pid {pid!r}: {why}")

        if action not in ALLOWED_ACTIONS:
            refuse("unknown action")
        if not isinstance(pid, int) or isinstance(pid, bool):
            refuse("pid is not an integer")
        if pid in FORBIDDEN_PIDS or pid <= 1:
            refuse("kernel/init PIDs are never touched")
        if pid in (os.getpid(), os.getppid()):
            refuse("that is the governor itself or its parent")
        entry = self._entries.get(pid)
        if entry is None:
            refuse("not launched by this governor (not in whitelist)")
        assert entry is not None
        if entry.state != expect_state:
            refuse(f"whitelisted {entry.role} is {entry.state}, expected {expect_state}")
        if expect_state == PRESERVED:
            return entry  # nothing is running under this PID by design
        snap = read_proc(pid)
        if snap is None or not snap.alive:
            refuse("process is not alive")
        assert snap is not None
        if snap.start_ticks != entry.start_ticks:
            refuse(f"PID was reused (starttime {snap.start_ticks} != recorded {entry.start_ticks})")
        if not self.cgroup.contains(pid):
            refuse(f"process is outside the test cgroup (in {proc_cgroup(pid)})")
        return entry

    def signal(self, pid: int, sig: int) -> None:
        """Send ``sig`` to a whitelisted, confined process."""
        if sig not in ALLOWED_SIGNALS:
            log.error("SAFETY REFUSAL: signal %s to pid=%r: signal not allowed", sig, pid)
            raise SafetyRefusal(f"signal {sig} is not in the allowed set")
        entry = self.verify(pid, "signal")
        os.kill(pid, sig)
        log.info("sent %s to %s pid=%d", signal.Signals(sig).name, entry.role, pid)

    # -- state transitions ----------------------------------------------------
    def mark_preserved(self, pid: int, image_dir: Path) -> None:
        entry = self._entries[pid]
        entry.state, entry.image_dir = PRESERVED, image_dir

    def mark_restored(self, pid: int) -> ManagedProcess:
        """After CRIU restore: refresh starttime and confirm confinement."""
        entry = self._entries[pid]
        snap = read_proc(pid)
        if snap is None:
            raise CgroupError(f"restored pid {pid} is not running")
        if not self.cgroup.contains(pid):
            log.warning("restored pid %d landed in %s; moving it into %s",
                        pid, proc_cgroup(pid), self.cgroup.rel)
            self.cgroup.migrate(pid)
            if not self.cgroup.contains(pid):
                raise CgroupError(f"restored pid {pid} could not be confined; "
                                  "it is NOT whitelisted and must be inspected manually")
        # The kernel assigns a new starttime to the restored task; record it so
        # the PID-reuse guard keeps working.
        entry.start_ticks = snap.start_ticks
        entry.state, entry.image_dir, entry.popen = RUNNING, None, None
        return entry

    def refresh(self) -> list[ManagedProcess]:
        """Reap children and detect exits. Returns entries that exited just now."""
        gone: list[ManagedProcess] = []
        for entry in self._entries.values():
            if entry.state != RUNNING:
                continue
            if entry.popen is not None:
                rc = entry.popen.poll()  # waitpid(WNOHANG): reaps the zombie
                if rc is None:
                    continue
                entry.returncode = rc
            else:
                snap = read_proc(entry.pid)
                if snap is not None and snap.alive and snap.start_ticks == entry.start_ticks:
                    continue
            entry.state = EXITED
            gone.append(entry)
        return gone

    # -- queries --------------------------------------------------------------
    def get(self, pid: int) -> ManagedProcess | None:
        return self._entries.get(pid)

    def with_state(self, state: str) -> list[ManagedProcess]:
        return [e for e in self._entries.values() if e.state == state]

    def by_role(self, role: str) -> list[ManagedProcess]:
        return [e for e in self._entries.values() if e.role == role]


def _refusal_demo(cg: TestCgroup) -> int:
    """Show the gate refusing foreign PIDs. Never sends a signal or runs CRIU."""
    wl = PidWhitelist(cg)
    targets = [("init", 1), ("kernel", 0), ("this process", os.getpid()),
               ("parent shell", os.getppid()), ("non-integer", "1234"),
               ("not launched by us", 2)]
    for label, pid in targets:
        try:
            wl.verify(pid, "checkpoint")  # type: ignore[arg-type]
            print(f"  {label:20s} -> ALLOWED (this would be a bug)")
            return 1
        except SafetyRefusal as exc:
            print(f"  {label:20s} -> refused: {exc}")
    try:
        wl.signal(os.getpid(), signal.SIGHUP)
    except SafetyRefusal as exc:
        print(f"  {'SIGHUP to self':20s} -> refused: {exc}")
    return 0


def _main() -> int:
    ap = argparse.ArgumentParser(description="Inspect / manage the PRESERVE test cgroup.")
    ap.add_argument("--config", default=None)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--create", action="store_true")
    g.add_argument("--destroy", action="store_true")
    g.add_argument("--refusal-demo", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = Config(args.config)
    cg = TestCgroup.from_config(cfg)
    if args.refusal_demo:
        return _refusal_demo(cg)
    if args.create:
        cg.create(cfg.get_size("cgroup", "memory_max"), cfg.get_size("cgroup", "memory_swap_max"),
                  cfg.get_size("cgroup", "memory_high"))
    elif args.destroy:
        cg.destroy()
        return 0

    print(f"cgroup v2 mounted : {cg.unified_hierarchy_mounted()}")
    print(f"parent            : {cg.parent} (exists={cg.parent.is_dir()})")
    if cg.parent.is_dir():
        ctl = cg.parent_controllers()
        print(f"parent subtree    : {' '.join(ctl)}  (memory delegated: {'memory' in ctl})")
        print(f"parent writable   : {os.access(cg.parent, os.W_OK)}")
    # Governor runs use per-run names (<prefix>-<pid>-<timestamp>); list them all,
    # plus the bare legacy name, so leftovers and concurrent runs are visible.
    found = sorted(p for p in cg.parent.glob(f"{cg.path.name}-*") if (p / "cgroup.procs").exists()) \
        if cg.parent.is_dir() else []
    if cg.exists():
        found.insert(0, cg.path)
    print(f"run cgroups       : {len(found)} under prefix {cg.path.name!r}")
    for path in found:
        run = TestCgroup(cg.parent, path.name)
        print(f"  {path}")
        for knob in ("memory.max", "memory.swap.max", "memory.current"):
            print(f"    {knob:16s}: {run.read(knob)}")
        print(f"    members         : {sorted(run.procs())}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
