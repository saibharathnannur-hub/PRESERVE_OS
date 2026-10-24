"""
sensor.py -- M1: memory-pressure telemetry from PSI and cgroup v2.

What this module observes, in OS terms
--------------------------------------
**Pressure Stall Information (PSI).** Since Linux 4.20 the kernel accounts,
for each resource (cpu, io, memory), the share of wall-clock time in which
tasks were *stalled* waiting for that resource. For memory, a task is stalled
while it performs direct reclaim, waits on a refault of a recently evicted
page (thrashing), or swaps a page back in. Two lines are reported:

* ``some``: % of time at least one runnable task was stalled on memory.
  It measures added latency.
* ``full``: % of time *all* non-idle tasks were stalled at once. Nothing
  productive happened, so it measures lost throughput.

Each line carries exponentially-decaying averages over 10 s, 60 s and 300 s
windows (``avg10/avg60/avg300``, in percent) plus a monotonically increasing
``total`` stall time in microseconds. PSI is exposed system-wide in
``/proc/pressure/memory`` and per cgroup in ``<cgroup>/memory.pressure``.
The per-cgroup file is the key signal here: it shows pressure *inside the
test cgroup*, caused by its ``memory.max`` limit, even when the host as a
whole has plenty of free RAM.

**cgroup v2 memory controller** (all values in bytes):

* ``memory.current``: memory currently charged to the cgroup (anonymous
  pages, page cache, kernel memory).
* ``memory.max``: hard limit. Above it the kernel reclaims and, failing that,
  invokes the cgroup-local OOM killer.
* ``memory.high``: throttle point. Above it allocating tasks are forced into
  reclaim, which shows up as PSI stall long before an OOM kill.
* ``memory.swap.current`` / ``memory.swap.max``: swap usage and its limit.
* ``memory.events``: counters of how often the cgroup hit ``high``/``max``
  and how many ``oom`` / ``oom_kill`` events happened.
* ``memory.stat``: breakdown, of which ``anon`` (heap/stack; must be swapped
  to be reclaimed) and ``file`` (page cache; can be dropped) are recorded.

**Per-process accounting** from procfs:

* ``/proc/<pid>/stat`` field 14/15 ``utime``/``stime``: CPU time consumed,
  in clock ticks (``SC_CLK_TCK`` per second). The cost model uses it as the
  work a process would lose if it were killed.
* field 22 ``starttime``: when the process started, in ticks since boot.
  The pair (pid, starttime) uniquely names a process even if the kernel
  later *reuses* the numeric PID. The safety whitelist relies on this.
* ``/proc/<pid>/statm`` field 2: resident set size in pages.
* ``/proc/<pid>/cgroup``: on a pure cgroup-v2 system, one line ``0::<path>``
  naming the cgroup the process belongs to.

**Kernel OOM-killer records.** When the cgroup-local OOM killer fires, the
kernel prints to its ring buffer (read with ``dmesg``)::

    oom-kill:constraint=CONSTRAINT_MEMCG,...,oom_memcg=<cg>,task_memcg=<cg>,task=python3,pid=1234,uid=1000
    Memory cgroup out of memory: Killed process 1234 (python3) total-vm:..., anon-rss:351232kB, ...

``memory.events`` only *counts* kills (``oom_kill``). These lines say *which*
process the kernel chose. The victim is the task with the highest
``oom_badness`` (RSS + swap entries + page tables, adjusted by
``oom_score_adj``). Lines are timestamped in seconds since boot, so they are
filtered against ``/proc/uptime`` taken at the start of a run.

This module is strictly **read-only**: it never writes to /proc or /sys.

Standalone use::

    python3 src/sensor.py                    # one sample (system + test cgroup if present)
    python3 src/sensor.py --count 20         # 20 samples at the configured interval
    python3 src/sensor.py --cgroup /sys/fs/cgroup/some/group --pid 1234
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from config import Config

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MIB = 1 << 20
CGROUP_ROOT = Path("/sys/fs/cgroup")
SYSTEM_PSI_PATH = Path("/proc/pressure/memory")


# --------------------------------------------------------------------------
# PSI
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class PsiLine:
    """One line of a PSI file: averaged stall percentages and total stall time."""

    avg10: float
    avg60: float
    avg300: float
    total_us: int


@dataclass(frozen=True)
class Psi:
    """Parsed PSI file. ``full`` is None for resources that do not report it."""

    some: PsiLine
    full: PsiLine | None

    def get(self, metric: str, window: str) -> float:
        """Return e.g. ``get("some", "avg10")`` as a percentage."""
        line = self.some if metric == "some" else self.full
        return 0.0 if line is None else float(getattr(line, window))


ZERO_PSI = Psi(PsiLine(0.0, 0.0, 0.0, 0), PsiLine(0.0, 0.0, 0.0, 0))


def parse_psi(text: str) -> Psi:
    """Parse ``some avg10=.. avg60=.. avg300=.. total=..`` (+ optional ``full``)."""
    lines: dict[str, PsiLine] = {}
    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        kv = dict(p.split("=", 1) for p in parts[1:])
        lines[parts[0]] = PsiLine(
            float(kv["avg10"]), float(kv["avg60"]), float(kv["avg300"]), int(kv["total"])
        )
    if "some" not in lines:
        raise ValueError(f"unrecognised PSI content: {text!r}")
    return Psi(lines["some"], lines.get("full"))


def read_psi(path: Path) -> Psi:
    return parse_psi(Path(path).read_text())


# --------------------------------------------------------------------------
# cgroup v2 memory controller
# --------------------------------------------------------------------------
def _read_limit(path: Path) -> int | None:
    """Read a cgroup limit file; ``max`` (unlimited) becomes None."""
    text = path.read_text().strip()
    return None if text == "max" else int(text)


def _read_keyed(path: Path) -> dict[str, int]:
    """Read a flat-keyed cgroup file ("key value" per line)."""
    out: dict[str, int] = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition(" ")
        if value:
            out[key] = int(value)
    return out


@dataclass(frozen=True)
class CgroupMemory:
    """Snapshot of one cgroup's memory controller state (bytes)."""

    path: Path
    current: int
    max: int | None
    high: int | None
    swap_current: int
    swap_max: int | None
    anon: int
    file: int
    events: dict[str, int] = field(default_factory=dict)
    pressure: Psi = ZERO_PSI

    @property
    def effective_limit(self) -> int | None:
        """The tighter of memory.high and memory.max (None if both unlimited)."""
        limits = [v for v in (self.max, self.high) if v is not None]
        return min(limits) if limits else None

    @property
    def usage_frac(self) -> float:
        """memory.current as a fraction of memory.max (0.0 when unlimited)."""
        return self.current / self.max if self.max else 0.0


def read_cgroup_memory(path: Path) -> CgroupMemory:
    """Read all memory-controller files of a cgroup directory."""
    path = Path(path)
    stat = _read_keyed(path / "memory.stat")
    swap_cur = path / "memory.swap.current"
    swap_max = path / "memory.swap.max"
    pressure_file = path / "memory.pressure"
    return CgroupMemory(
        path=path,
        current=int((path / "memory.current").read_text()),
        max=_read_limit(path / "memory.max"),
        high=_read_limit(path / "memory.high"),
        swap_current=int(swap_cur.read_text()) if swap_cur.exists() else 0,
        swap_max=_read_limit(swap_max) if swap_max.exists() else None,
        anon=stat.get("anon", 0),
        file=stat.get("file", 0),
        events=_read_keyed(path / "memory.events"),
        pressure=read_psi(pressure_file) if pressure_file.exists() else ZERO_PSI,
    )


# --------------------------------------------------------------------------
# Per-process accounting
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ProcSnapshot:
    """What procfs says about one process at one instant."""

    pid: int
    comm: str
    state: str  # R running, S sleeping, D uninterruptible, T stopped, Z zombie ...
    ppid: int
    rss_bytes: int
    cpu_seconds: float  # utime + stime
    start_ticks: int  # field 22: start time in clock ticks since boot

    @property
    def alive(self) -> bool:
        return self.state not in ("Z", "X", "x")


def read_proc(pid: int) -> ProcSnapshot | None:
    """Snapshot ``/proc/<pid>``; None if the process does not exist (any more)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        statm = Path(f"/proc/{pid}/statm").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    # comm is wrapped in parentheses and may itself contain spaces or ')',
    # so split on the *last* ')'. After it, fields[0] is stat field 3.
    rparen = stat.rindex(")")
    comm = stat[stat.index("(") + 1 : rparen]
    fields = stat[rparen + 2 :].split()
    utime, stime = int(fields[11]), int(fields[12])  # fields 14, 15
    return ProcSnapshot(
        pid=pid,
        comm=comm,
        state=fields[0],  # field 3
        ppid=int(fields[1]),  # field 4
        rss_bytes=int(statm.split()[1]) * PAGE_SIZE,
        cpu_seconds=(utime + stime) / CLK_TCK,
        start_ticks=int(fields[19]),  # field 22
    )


def proc_cgroup(pid: int) -> str | None:
    """Return the cgroup-v2 path of ``pid`` (e.g. ``/user.slice/...``), or None."""
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return None


# --------------------------------------------------------------------------
# Kernel OOM-killer records
# --------------------------------------------------------------------------
_DMESG_RE = re.compile(r"^\[\s*(\d+\.\d+)\]\s?(.*)$")
_OOM_CTX_RE = re.compile(r"oom-kill:.*?oom_memcg=([^,]+),task_memcg=([^,]+),task=([^,]+),pid=(\d+)")
_KILLED_RE = re.compile(r"Killed process (\d+) \(([^)]*)\).*?anon-rss:(\d+)kB")


@dataclass(frozen=True)
class KernelOomKill:
    """One OOM-killer victim as reported by the kernel."""

    uptime: float  # seconds since boot when the kill was logged
    pid: int
    comm: str
    anon_rss_kib: int
    oom_memcg: str | None  # cgroup whose limit was exceeded
    line: str


def read_uptime() -> float:
    """Seconds since boot (first field of /proc/uptime); same clock as dmesg."""
    return float(Path("/proc/uptime").read_text().split()[0])


def read_kernel_oom_kills(since_uptime: float) -> list[KernelOomKill] | None:
    """OOM-killer victims logged since ``since_uptime``; None if dmesg is unreadable."""
    try:
        p = subprocess.run(["dmesg"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    memcg_of: dict[int, str] = {}
    kills: list[KernelOomKill] = []
    for raw in p.stdout.splitlines():
        m = _DMESG_RE.match(raw)
        if not m or float(m.group(1)) < since_uptime:
            continue
        ts, msg = float(m.group(1)), m.group(2)
        ctx = _OOM_CTX_RE.search(msg)
        if ctx:
            memcg_of[int(ctx.group(4))] = ctx.group(1)
            continue
        k = _KILLED_RE.search(msg)
        if k:
            pid = int(k.group(1))
            kills.append(KernelOomKill(ts, pid, k.group(2), int(k.group(3)), memcg_of.get(pid), raw.strip()))
    return kills


# --------------------------------------------------------------------------
# Sampler
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Sample:
    """One telemetry sample: system PSI plus (optionally) the test cgroup."""

    monotonic: float
    wall: float
    system_psi: Psi
    cgroup: CgroupMemory | None


class Sensor:
    """Periodic sampler of system-wide and per-cgroup memory pressure."""

    def __init__(self, cgroup_path: Path | None = None) -> None:
        self.cgroup_path = Path(cgroup_path) if cgroup_path else None

    def sample(self) -> Sample:
        cg = None
        if self.cgroup_path is not None and (self.cgroup_path / "memory.current").exists():
            cg = read_cgroup_memory(self.cgroup_path)
        system = read_psi(SYSTEM_PSI_PATH) if SYSTEM_PSI_PATH.exists() else ZERO_PSI
        return Sample(time.monotonic(), time.time(), system, cg)

    @staticmethod
    def proc(pid: int) -> ProcSnapshot | None:
        return read_proc(pid)


def format_sample(s: Sample) -> str:
    """One human-readable line summarising a sample."""
    out = f"sys.some.avg10={s.system_psi.get('some', 'avg10'):5.2f}%"
    if s.cgroup is not None:
        c = s.cgroup
        lim = "max" if c.max is None else f"{c.max / MIB:.0f}M"
        out += (
            f" | cg.some.avg10={c.pressure.get('some', 'avg10'):5.2f}%"
            f" cg.full.avg10={c.pressure.get('full', 'avg10'):5.2f}%"
            f" cur={c.current / MIB:7.1f}M/{lim} ({c.usage_frac * 100:4.1f}%)"
            f" swap={c.swap_current / MIB:6.1f}M"
            f" oom_kill={c.events.get('oom_kill', 0)}"
        )
    return out


def _main() -> int:
    ap = argparse.ArgumentParser(description="Read-only PSI / cgroup memory sampler (M1).")
    ap.add_argument("--config", default=None)
    ap.add_argument("--cgroup", default=None, help="cgroup directory (default: test cgroup from config)")
    ap.add_argument("--pid", type=int, action="append", default=[], help="also snapshot this PID")
    ap.add_argument("--count", type=int, default=1, help="number of samples")
    args = ap.parse_args()

    cfg = Config(args.config)
    interval = cfg.get_float("sensor", "sample_interval_s")
    cg_path = Path(args.cgroup) if args.cgroup else (
        Path(cfg.get_str("cgroup", "parent")) / cfg.get_str("cgroup", "name")
    )
    if not (cg_path / "memory.current").exists():
        print(f"(cgroup {cg_path} does not exist; system PSI only)")
    sensor = Sensor(cg_path)
    for i in range(args.count):
        print(f"{time.strftime('%H:%M:%S')} {format_sample(sensor.sample())}")
        for pid in args.pid:
            print(f"    {read_proc(pid)}  cgroup={proc_cgroup(pid)}")
        if i + 1 < args.count:
            time.sleep(interval)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
