"""
capture.py -- M4: CRIU checkpoint (dump) and restore wrapper.

What CRIU does
--------------
CRIU (Checkpoint/Restore In Userspace) saves a running process tree to a set
of image files and later recreates it, with the same PID, from those files.

**Dump** (``criu dump -t PID``):

1. *Seize and freeze*: CRIU attaches to every task in the tree with
   ``ptrace(PTRACE_SEIZE)`` and interrupts it, so nothing changes while it
   is being read.
2. *Collect state* from procfs and syscalls: memory mappings
   (``/proc/PID/smaps``, ``map_files``), registers, signal masks, open file
   descriptors with their offsets and flags, credentials, session/process
   group, namespaces, cgroup membership.
3. *Dump memory*: a small "parasite" blob is injected into the frozen task.
   It runs inside the victim's address space and streams private pages to
   CRIU through a pipe (``vmsplice``), which writes ``pages-*.img``.
4. *Finish*: by default the dumped tasks are then **killed**. For PRESERVE
   that is the point: their memory is released back to the cgroup, which is
   what relieves pressure. (``--leave-running`` and ``--leave-stopped`` would
   keep the RAM occupied, so this wrapper refuses those flags.)

**Restore** (``criu restore -D dir``): CRIU forks a task with the original
PID (``clone3`` with ``set_tid``, which needs ``CAP_CHECKPOINT_RESTORE`` or
root), re-creates mappings, reloads pages, reopens files at their saved
offsets, restores registers, and finally lets the process continue from the
instruction where it was frozen. ``--restore-detached`` lets CRIU exit once
the tree is running, so the restored process is reparented to init.

Constraints this places on workloads
------------------------------------
* The PID must be **free** at restore time. After a dump the governor
  reaps its dead child (``waitpid``) immediately, otherwise a zombie would
  keep holding the PID.
* Files open at dump time must be reopenable unchanged at restore. CRIU
  records each regular file's path and size. The workloads therefore send
  stdio to ``/dev/null`` and only hold their own state files open briefly,
  never pipes back to the governor (a pipe whose other end has gone cannot
  be restored).
* ``--shell-job`` lets CRIU dump a session leader whose session/process
  group were inherited from outside the dumped tree. The workloads are
  started with ``setsid`` (``start_new_session=True``), as in the
  feasibility test recorded in ``evidence/00_criu_feasibility.log``.

Confinement on restore
----------------------
The ``criu restore`` command itself is started inside the test cgroup (same
``preexec_fn`` as the workloads). A forked child inherits its parent's
cgroup, so the restored tree is *born confined*. The governor then checks
``/proc/PID/cgroup`` anyway.

Safety
------
:meth:`CriuCapture.dump` and :meth:`CriuCapture.restore` take a PID, and their
first statement is the whitelist gate (:meth:`cgroup.PidWhitelist.verify`).
There is no code path in this module that runs CRIU on a PID the gate did
not approve. The gate is checked a second time immediately before CRIU is
executed, to narrow the window in which the PID could change hands.

Standalone use::

    sudo python3 src/capture.py --check          # criu check (+ --extra)
    python3 src/capture.py --refusal-demo        # show dump() refusing a foreign PID
"""
from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from admission import Arena, tree_bytes
from cgroup import PRESERVED, PidWhitelist, SafetyRefusal, TestCgroup
from config import Config
from sensor import MIB

log = logging.getLogger("preserve.capture")

FORBIDDEN_DUMP_FLAGS = frozenset({"--leave-running", "-R", "--leave-stopped", "-s"})
FAULT_DUMP_TIMEOUT_S = 0.05  # dump-timeout fault: deadline short enough that criu cannot finish
FAULT_TMPFS_SIZE = "16m"     # dump-fail fault: tmpfs far smaller than the image (~307 MiB) -> ENOSPC


@dataclass
class CaptureResult:
    ok: bool
    action: str  # "dump" | "restore"
    pid: int
    image_dir: Path | None
    seconds: float
    image_bytes: int = 0
    returncode: int | None = None
    error: str = ""
    log_tail: str = ""
    setup_failed: bool = False  # fault injection could not be established (e.g. tmpfs did not mount)
    enospc: bool = False        # the dump failed specifically with ENOSPC (disk/tmpfs full)

    def describe(self) -> str:
        if self.ok:
            return (f"{self.action} pid={self.pid} OK in {self.seconds:.2f}s, "
                    f"image {self.image_bytes / MIB:.1f}MiB at {self.image_dir}")
        return f"{self.action} pid={self.pid} FAILED (rc={self.returncode}): {self.error}"


def _tail(path: Path, n: int) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except OSError as exc:
        return f"(could not read {path}: {exc})"


class CriuCapture:
    """Runs CRIU on whitelisted processes only."""

    def __init__(self, cfg: Config, whitelist: PidWhitelist, cgroup: TestCgroup, arena: Arena) -> None:
        s = "capture"
        self.whitelist = whitelist
        self.cgroup = cgroup
        self.arena = arena
        self.criu = cfg.get_str(s, "criu_bin")
        self.shell_job = cfg.get_bool(s, "shell_job")
        self.verbosity = cfg.get_int(s, "log_level")
        self.dump_timeout_s = cfg.get_float(s, "dump_timeout_s")
        self.restore_timeout_s = cfg.get_float(s, "restore_timeout_s")
        self.keep_images = cfg.get_bool(s, "keep_images_after_restore")
        self.log_tail_lines = cfg.get_int(s, "log_tail_lines")
        self.dump_extra = cfg.get_args(s, "dump_extra_args")
        self.restore_extra = cfg.get_args(s, "restore_extra_args")
        bad = FORBIDDEN_DUMP_FLAGS.intersection(self.dump_extra)
        if bad:
            raise ValueError(f"dump_extra_args may not contain {sorted(bad)}: "
                             "eviction requires CRIU to kill the dumped task")

    # -- environment ------------------------------------------------------------
    def criu_path(self) -> str | None:
        return shutil.which(self.criu) or shutil.which(self.criu, path="/usr/sbin:/sbin")

    def available(self) -> tuple[bool, str]:
        path = self.criu_path()
        if path is None:
            return False, f"{self.criu} not found"
        if os.geteuid() != 0:
            return False, "CRIU dump/restore needs root (run the governor with sudo)"
        return True, path

    def check(self, extra: bool = False) -> tuple[int, str]:
        """Run ``criu check [--extra]`` and return (returncode, combined output)."""
        cmd = [self.criu_path() or self.criu, "check"] + (["--extra"] if extra else [])
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        return p.returncode, (p.stdout + p.stderr).strip()

    def _common_flags(self, logname: str) -> list[str]:
        return [f"-v{self.verbosity}", "-o", logname] + (["--shell-job"] if self.shell_job else [])

    # -- dump -----------------------------------------------------------------------
    def dump(self, pid: int, fault: str | None = None, members: list[int] | None = None) -> CaptureResult:
        """Checkpoint a whitelisted process into a new arena image set, then let CRIU kill it.

        ``fault`` (fail-safe demonstration, from governor --inject):
          * ``dump-fail``: a tiny tmpfs (``FAULT_TMPFS_SIZE``, far smaller than
            the image) is mounted over the image directory, so CRIU's writes
            genuinely fail with ENOSPC partway through -- a real disk-full
            failure that even root cannot bypass (unlike a chmod, which
            CAP_DAC_OVERRIDE ignores). The mount is verified before CRIU runs
            and always unmounted afterwards.
          * ``dump-timeout``: the subprocess deadline is cut to a fraction of a
            second, so ``criu dump`` is still working when it is killed, exercising
            the real timeout path.
        Neither weakens any check; both make a real dump genuinely not complete.

        ``members`` (Objective 6): a dependent group rooted at ``pid``. CRIU dumps
        the whole tree from the root, so EVERY member must pass the gate, and all
        of them are marked preserved with the same image set. The caller has
        already checked that the tree is exactly these members (deps.capturable).
        """
        others = [m for m in (members or []) if m != pid]
        entry = self.whitelist.verify(pid, "checkpoint")  # SAFETY GATE
        for m in others:
            self.whitelist.verify(m, "checkpoint")  # SAFETY GATE, every member
        image_dir = self.arena.path / f"{entry.role}-{pid}-{time.strftime('%Y%m%d-%H%M%S')}"
        image_dir.mkdir(mode=0o700)
        cmd = [self.criu_path() or self.criu, "dump", "-t", str(pid), "-D", str(image_dir)]
        cmd += self._common_flags("dump.log") + self.dump_extra

        timeout = self.dump_timeout_s
        tmpfs_mounted = False
        if fault == "dump-fail":
            # Mount a tmpfs too small to hold the image; verify it took effect, or abort.
            if not self._mount_tmpfs(image_dir, FAULT_TMPFS_SIZE):
                log.error("FAULT INJECTION [dump-fail]: tmpfs did NOT mount on %s; aborting rather "
                          "than running an unfaulted dump", image_dir)
                self._umount(image_dir)  # best effort, in case of a half-mount
                return CaptureResult(False, "dump", pid, image_dir, 0.0, setup_failed=True,
                                     error="INJECTION SETUP FAILED: tmpfs did not mount on the image dir")
            tmpfs_mounted = True
            log.warning("FAULT INJECTION [dump-fail]: %s tmpfs (%s) mounted over %s; CRIU writes will "
                        "hit ENOSPC", FAULT_TMPFS_SIZE, "size", image_dir)
        elif fault == "dump-timeout":
            timeout = FAULT_DUMP_TIMEOUT_S
            log.warning("FAULT INJECTION [dump-timeout]: dump deadline cut to %.2fs so the dump "
                        "cannot complete in time", timeout)

        self.whitelist.verify(pid, "checkpoint")  # re-check right before exec
        for m in others:
            self.whitelist.verify(m, "checkpoint")
        log.info("CRIU dump %s pid=%d%s -> %s", entry.role, pid,
                 f" (tree with members {others})" if others else "", image_dir)
        log.debug("exec: %s", " ".join(cmd))
        t0 = time.monotonic()
        try:
            try:
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                   timeout=timeout)
            except subprocess.TimeoutExpired:
                secs = time.monotonic() - t0
                return CaptureResult(False, "dump", pid, image_dir, secs, error=f"timed out after {secs:.1f}s",
                                     log_tail=_tail(image_dir / "dump.log", self.log_tail_lines))
            secs = time.monotonic() - t0

            if p.returncode != 0:
                # On failure CRIU resumes the frozen task; it keeps running and stays whitelisted.
                combined = p.stderr + "\n" + _tail(image_dir / "dump.log", self.log_tail_lines)
                enospc = ("ENOSPC" in combined) or ("No space left on device" in combined)
                return CaptureResult(False, "dump", pid, image_dir, secs, returncode=p.returncode,
                                     error=(p.stderr.strip().splitlines() or ["criu dump failed"])[-1],
                                     log_tail=_tail(image_dir / "dump.log", self.log_tail_lines),
                                     enospc=enospc)

            # CRIU killed the task. Reap our child now so the PID is free for restore.
            if entry.popen is not None:
                try:
                    entry.returncode = entry.popen.wait(timeout=self.dump_timeout_s)
                except subprocess.TimeoutExpired:
                    log.error("dumped pid %d did not exit after dump", pid)
            self.whitelist.mark_preserved(pid, image_dir)
            for m in others:
                self.whitelist.mark_preserved(m, image_dir)
            return CaptureResult(True, "dump", pid, image_dir, secs, tree_bytes(image_dir), 0)
        finally:
            if tmpfs_mounted:
                self._umount(image_dir)  # always unmount, even on success or exception

    # -- tmpfs helpers for the dump-fail injection ----------------------------------
    def _mount_tmpfs(self, path: Path, size: str) -> bool:
        """Mount a size-limited tmpfs over ``path`` and confirm it took effect."""
        subprocess.run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", str(path)],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True)
        return self._is_mountpoint(path)

    @staticmethod
    def _is_mountpoint(path: Path) -> bool:
        """True iff ``path`` is a tmpfs mount point right now (checked via /proc/self/mounts)."""
        target = str(Path(path).resolve())
        try:
            for line in Path("/proc/self/mounts").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == target and parts[2] == "tmpfs":
                    return True
        except OSError:
            pass
        return False

    def _umount(self, path: Path) -> None:
        """Unmount ``path`` if mounted; fall back to a lazy unmount. Never raises."""
        if not self._is_mountpoint(path):
            return
        if subprocess.run(["umount", str(path)], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True).returncode != 0:
            subprocess.run(["umount", "-l", str(path)], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True)
        if self._is_mountpoint(path):
            log.error("could not unmount fault tmpfs at %s", path)

    # -- restore --------------------------------------------------------------------
    def restore(self, pid: int, members: list[int] | None = None) -> CaptureResult:
        """Restore a previously dumped whitelisted process, confined to the test cgroup.

        With ``members`` the whole tree is restored from the root's image set;
        every member must pass the gate and every member must be alive and
        confined afterwards, or the restore is reported as failed.
        """
        others = [m for m in (members or []) if m != pid]
        entry = self.whitelist.verify(pid, "restore", expect_state=PRESERVED)  # SAFETY GATE
        image_dir = entry.image_dir
        if image_dir is None or not self.arena.contains(image_dir):
            raise SafetyRefusal(f"image dir {image_dir} for pid {pid} is not inside the arena")
        for m in others:
            me = self.whitelist.verify(m, "restore", expect_state=PRESERVED)  # SAFETY GATE
            if me.image_dir != image_dir:
                raise SafetyRefusal(f"member pid {m} belongs to image {me.image_dir}, not {image_dir}")
        # Dumped members that were not our children are reaped by init; give it a moment.
        deadline = time.monotonic() + 5.0
        while any(Path(f"/proc/{p}").exists() for p in [pid] + others) and time.monotonic() < deadline:
            time.sleep(0.1)
        busy = [p for p in [pid] + others if Path(f"/proc/{p}").exists()]
        if busy:
            return CaptureResult(False, "restore", pid, image_dir, 0.0,
                                 error=f"PID(s) {busy} in use by another process; CRIU cannot reuse them")

        pidfile = image_dir / "restore.pid"
        pidfile.unlink(missing_ok=True)
        cmd = [self.criu_path() or self.criu, "restore", "-D", str(image_dir),
               "--restore-detached", "--pidfile", str(pidfile)]
        cmd += self._common_flags("restore.log") + self.restore_extra
        log.info("CRIU restore %s pid=%d <- %s", entry.role, pid, image_dir)
        log.debug("exec: %s", " ".join(cmd))
        t0 = time.monotonic()
        try:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               timeout=self.restore_timeout_s,
                               preexec_fn=self.cgroup.preexec_enter(None))
        except subprocess.TimeoutExpired:
            secs = time.monotonic() - t0
            return CaptureResult(False, "restore", pid, image_dir, secs, error=f"timed out after {secs:.1f}s",
                                 log_tail=_tail(image_dir / "restore.log", self.log_tail_lines))
        secs = time.monotonic() - t0
        if p.returncode != 0:
            return CaptureResult(False, "restore", pid, image_dir, secs, returncode=p.returncode,
                                 error=(p.stderr.strip().splitlines() or ["criu restore failed"])[-1],
                                 log_tail=_tail(image_dir / "restore.log", self.log_tail_lines))

        restored = int(pidfile.read_text().strip())
        if restored != pid:
            log.error("CRIU restored pid %d but image was pid %d; leaving it untouched", restored, pid)
            return CaptureResult(False, "restore", pid, image_dir, secs, returncode=0,
                                 error=f"restored under unexpected pid {restored}")
        size = tree_bytes(image_dir)
        self.whitelist.mark_restored(pid)
        for m in others:  # raises CgroupError if a member is not running or not confined
            self.whitelist.mark_restored(m)
            log.info("restored member pid=%d alive and confined in %s", m, self.cgroup.rel)
        if not self.keep_images:
            shutil.rmtree(image_dir)
        return CaptureResult(True, "restore", pid, image_dir, secs, size, 0)


def _main() -> int:
    ap = argparse.ArgumentParser(description="CRIU wrapper (M4).")
    ap.add_argument("--config", default=None)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="run criu check and criu check --extra")
    g.add_argument("--refusal-demo", action="store_true",
                   help="ask dump() to checkpoint foreign PIDs; must be refused before CRIU runs")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = Config(args.config)
    cg = TestCgroup.from_config(cfg)
    cap = CriuCapture(cfg, PidWhitelist(cg), cg, Arena.from_config(cfg))
    if args.check:
        ok, msg = cap.available()
        print(f"available: {ok} ({msg})")
        for extra in (False, True):
            rc, out = cap.check(extra)
            print(f"--- criu check{' --extra' if extra else ''} (rc={rc}) ---\n{out}")
        return 0
    for pid in (1, os.getpid(), os.getppid()):
        try:
            cap.dump(pid)
            print(f"pid {pid}: dump was NOT refused -- this is a bug")
            return 1
        except SafetyRefusal as exc:
            print(f"pid {pid}: refused before CRIU ran: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
