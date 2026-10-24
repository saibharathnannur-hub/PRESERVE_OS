"""
runlock.py -- at most one governor at a time, with a named holder.

Why this exists
---------------
Every governor run used the same cgroup name and the same ``run/`` directory.
Two runs started at once therefore shared one memory limit (each one's
workloads pushed the other's into the OOM killer) and deleted each other's
state files. Nothing detected it: both runs produced output that looked valid.

The fix has two halves. ``cgroup.py`` gives every run its own cgroup, and this
module makes a second governor *refuse to start* while one is running.

Mechanism
---------
An exclusive ``flock(2)`` on ``[paths] lock_file``, taken with ``LOCK_NB`` so a
second governor fails immediately instead of waiting. ``flock`` is used rather
than a PID file because the kernel releases the lock the moment its holder
dies -- normal exit, crash, SIGKILL, or the ``os._exit`` of the
``governor-dies`` fault injection -- so a dead run can never leave a stale lock
behind that blocks the next one.

While holding the lock, the governor writes a JSON description of itself
into the file (pid, uid, mode, scenario, start time, argv and, once created,
its cgroup path). That text is only *trusted* as "the current holder" when the
lock is actually held. When the lock is free, it describes the most recent run,
which is how ``run_failsafe.sh`` finds the leftover cgroup of a run that died.

The file descriptor is opened ``O_CLOEXEC`` (Python's default since PEP 446),
so workloads and CRIU, which are started as subprocesses, never inherit the
lock and cannot keep it alive after the governor has gone.

Standalone use (the shell scripts call these)::

    python3 src/runlock.py --status        # exit 0 if free, 75 if held (prints holder)
    python3 src/runlock.py --last-cgroup   # exit 0 + cgroup of the last run if free; 75 if held
    python3 src/runlock.py --hold --label "what I am" -- CMD ARGS...
                                           # hold the lock (described) while CMD runs;
                                           # exit 75 if held, else CMD's exit code
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from config import Config, give_to_invoking_user

EXIT_LOCKED = 75  # EX_TEMPFAIL: another governor is running


class LockHeld(RuntimeError):
    """Another governor holds the lock."""


def read_holder(path: Path) -> dict:
    """The JSON a governor wrote into the lock file, or {} if absent/unreadable."""
    try:
        return json.loads(Path(path).read_text() or "{}")
    except (OSError, ValueError):
        return {}


def _alive(pid: object) -> str:
    if not isinstance(pid, int):
        return "unknown"
    return "alive" if Path(f"/proc/{pid}").exists() else "NOT RUNNING"


def describe(holder: dict) -> str:
    """One line naming the process a lock-holder record describes."""
    if not holder:
        return "holder unknown (the lock file has no description yet)"
    started = holder.get("started")
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)) if started else "?"
    parts = [
        f"pid {holder.get('pid')} ({_alive(holder.get('pid'))})",
        f"uid {holder.get('uid')}",
        f"mode {holder.get('mode')}",
        f"scenario {holder.get('scenario')}",
        f"started {when}",
    ]
    if holder.get("cgroup"):
        parts.append(f"cgroup {holder['cgroup']}")
    if holder.get("argv"):
        parts.append("cmd: " + " ".join(holder["argv"]))
    return ", ".join(parts)


def describe_held(holder: dict) -> str:
    """Describe the holder of a lock that IS held, without trusting a stale record.

    The record is only rewritten by holders that go through RunLock. If its pid is
    not running, the real holder took the lock some other way (e.g. a bare
    flock(1)), so say exactly that rather than naming a dead process.
    """
    pid = holder.get("pid")
    if isinstance(pid, int) and not Path(f"/proc/{pid}").exists():
        return ("held by a process that did not describe itself (the recorded holder, "
                f"pid {pid}, is not running); last record: {describe(holder)}")
    return describe(holder)


def is_held(path: Path) -> bool:
    """True if some process currently holds the lock (probed without taking it)."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


class RunLock:
    """Exclusive, non-blocking, crash-safe lock held for the governor's lifetime."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.fd: int | None = None
        self.info: dict = {}

    def acquire(self, info: dict) -> None:
        """Take the lock or raise LockHeld naming the holder. Never waits."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_RDWR so the holder can describe itself. A PermissionError here (e.g. a
        # root-owned lock file and an unprivileged governor) propagates: the
        # caller must refuse to start rather than run unlocked.
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise LockHeld(f"another governor holds {self.path}: "
                           f"{describe_held(read_holder(self.path))}") from None
        self.fd = fd
        # Hand the file to the sudo caller so later unprivileged runs can open it.
        give_to_invoking_user(self.path)
        self.update(**info)

    def update(self, **fields: object) -> None:
        """Rewrite the holder description in place (only while holding the lock)."""
        if self.fd is None:
            return
        self.info.update(fields)
        data = json.dumps(self.info, indent=2).encode()
        os.ftruncate(self.fd, 0)
        os.pwrite(self.fd, data, 0)
        os.fsync(self.fd)

    def release(self) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def holder_info(mode: str, scenario: str | None, argv: list[str]) -> dict:
    return {"pid": os.getpid(), "uid": os.getuid(), "euid": os.geteuid(),
            "mode": mode, "scenario": scenario, "started": time.time(), "argv": argv}


def _main() -> int:
    ap = argparse.ArgumentParser(description="Inspect the PRESERVE governor lock.")
    ap.add_argument("--config", default=None)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--status", action="store_true", help="exit 0 if free, 75 if held")
    g.add_argument("--last-cgroup", action="store_true",
                   help="print the cgroup recorded by the most recent run (only when the lock is free)")
    g.add_argument("--hold", action="store_true",
                   help="take the lock, describe this holder (--label), run CMD, release; "
                        "exit 75 if already held, else CMD's exit code")
    ap.add_argument("--since", type=float, default=None,
                    help="with --last-cgroup: print nothing unless that run started at/after this epoch "
                         "time (so a caller only ever sees a run it launched itself)")
    ap.add_argument("--label", default="script",
                    help="with --hold: what the holder is, shown to anyone who is refused")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="with --hold: -- command [args...]")
    args = ap.parse_args()
    path = Config(args.config).get_path("paths", "lock_file")

    if args.hold:
        # Scripts take the lock through this wrapper rather than bare flock(1), so a
        # refused governor is told exactly what holds it (e.g. "overhead arm B run 2").
        cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
        if not cmd:
            ap.error("--hold needs a command after --")
        lock = RunLock(path)
        try:
            lock.acquire(holder_info(args.label, None, cmd))
        except LockHeld as exc:
            print(f"HELD: {exc}", file=sys.stderr)
            return EXIT_LOCKED
        try:
            return subprocess.call(cmd)
        finally:
            lock.release()

    holder = read_holder(path)
    if is_held(path):
        print(f"HELD: {describe_held(holder)}")
        return EXIT_LOCKED
    if args.status:
        print(f"free (lock file {path}; last run: {describe(holder)})")
        return 0
    cg = holder.get("cgroup")
    if args.since is not None and float(holder.get("started") or 0) < args.since:
        cg = None  # the last run predates the caller's launch: not the caller's run
    if cg:
        print(cg)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
