# PRESERVE: A Work-Preserving Memory Reclamation Governor for Linux

When a memory-limited Linux cgroup runs out of memory, the kernel OOM killer terminates a
process and all of its accumulated work is lost. PRESERVE is a user-space governor that
watches memory pressure (PSI and cgroup v2 memory counters), uses a cost model to pick the
process whose termination would lose the most work, and checkpoints it to disk with CRIU
instead of letting the kernel kill it, which frees its memory. When pressure clears, the
process is restored and continues exactly where it stopped, verified by a SHA-256 hash
chain. Dependent processes (a parent and child joined by a pipe) are detected and
checkpointed together as one unit. On any failure (no room in the checkpoint arena, a
failed or timed-out dump, a blocked restore, a stale PID, or the governor itself crashing)
PRESERVE stands down and the normal kernel behaviour applies.

**Course:** BITE303P Operating Systems Lab, VIT Vellore

**Team:**
- Arvind Gotluru (24BIT0176)
- S G Subhiksha (24BIT0188)
- Sai Bharath Chandra Nannur (24BIT0138)

**Guide:** Dr. G.N. Vivekananda

## Requirements

- Linux with cgroup v2 and PSI, or WSL2 (tested on kernel 6.18 WSL2)
- systemd user session (the test cgroup is created in the user's delegated subtree)
- Python 3 (standard library only)
- CRIU 4.x (`criu`)
- root (`sudo`) for checkpoint/restore; baseline runs do not need root
- the project must live on a native Linux filesystem (ext4), not `/mnt/c`

## How to run

Full test set with summary tables (asks for the sudo password once, about 17 minutes):

```bash
./scripts/video_demo.sh
```

Single scenarios:

```bash
./run_demo.sh --scenario A|B|C              # PRESERVE (live, needs sudo)
./run_demo.sh --scenario A|B|C --baseline   # control run: kernel OOM killer acts
```

- **A**: the hog is the largest process; the kernel already kills the right process.
- **B**: the valuable long-running job is the largest process; the kernel kills it.
- **C**: a dependent group (parent + child joined by a pipe); killing one destroys both.

Other runners: `./run_failsafe.sh` (fault injection), `./run_overhead.sh` (idle cost),
`./run_all.sh` (interactive experiment matrix). All tunables are in `preserve.conf`.

## Project layout

| Path | Contents |
|---|---|
| `src/governor.py` | control loop, scenarios, baseline report |
| `src/sensor.py` | PSI and cgroup memory telemetry |
| `src/costmodel.py` | restart cost R vs capture cost C scoring |
| `src/admission.py` | checkpoint-arena budget, capture/restore admission |
| `src/capture.py` | CRIU dump/restore wrapper |
| `src/cgroup.py` | test cgroup and PID whitelist safety gate |
| `src/deps.py` | dependency detection (parent/child, shared pipes/sockets) |
| `src/runlock.py`, `src/config.py`, `src/matrix.py`, `src/compare.py` | run lock, configuration, result tables |
| `workloads/` | `compute_job.py`, `pipeline_job.py` (valuable work), `hog.py` (antagonist) |
| `scripts/video_demo.sh` | one-command full test set |
| `evidence/` | result summaries from the experiments |
| `PRESERVE_Code_and_Dataset.pdf` | full source listing and dataset summary |

## Results

From `evidence/video-20261025-003739/summary.txt` (full test set, 22/22 checks passed):

```text
TABLE 1 - SCENARIOS
Scenario | Mode     | Valuable job outcome    | Work lost (s) | Work preserved (s) | Capture time (s) | Restore time (s) | Hash chain (mismatches) | Check
---------+----------+-------------------------+---------------+--------------------+------------------+------------------+-------------------------+------
A        | baseline | not touched             | 0.00          | -                  | -                | -                | 0                       | PASS
A        | PRESERVE | preserved               | 0.00          | 7.79               | 0.26             | 0.15             | 0                       | PASS
B        | baseline | killed                  | 12.46         | -                  | -                | -                | 0                       | PASS
B        | PRESERVE | preserved               | 0.00          | 11.25              | 0.31             | 0.32             | 0                       | PASS
C        | baseline | killed (2/2 members)    | 19.72         | -                  | -                | -                | 0 (2 chains)            | PASS
C        | PRESERVE | preserved (2/2 members) | 0.00          | 16.97              | 0.29             | 0.19             | 0 (2 chains)            | PASS

TABLE 2 - FAULT INJECTION (scenario B)
Fault           | Expected safe behaviour                              | Observed                                                                                                         | Verified
----------------+------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+---------
arena-too-small | M3 denies capture -> STAND DOWN, no dump             | stood down; compute_job killed by kernel OOM                                                                     | YES
dump-fail       | real dump fails (ENOSPC) -> clean up, STAND DOWN     | dump failed (ENOSPC); survived the failure, then killed by kernel OOM                                            | YES
dump-timeout    | dump times out -> clean up, STAND DOWN               | dump failed (timeout); survived the failure, then killed by kernel OOM                                           | YES
restore-blocked | restore denied -> image kept on disk, no restore     | checkpointed, not restored; image present on disk                                                                | YES
stale-pid       | PID-reuse guard refuses -> STAND DOWN, no dump       | stood down; compute_job killed by kernel OOM                                                                     | YES
governor-dies   | governor crashes -> kernel in charge, nothing frozen | governor died before capture; compute_job still under kernel (2 workload pid(s) left running); governor exit 137 | YES

TABLE 3 - SAFETY GATE
Target                | Refusal class                                    | Refused
----------------------+--------------------------------------------------+--------
init                  | kernel/init PIDs are never touched               | YES
kernel                | kernel/init PIDs are never touched               | YES
this process          | that is the governor itself or its parent        | YES
parent shell          | that is the governor itself or its parent        | YES
non-integer           | pid is not an integer                            | YES
not launched by us    | not launched by this governor (not in whitelist) | YES
SIGHUP to self        | signal 1 is not in the allowed set               | YES
CRIU dump of pid 1    | kernel/init PIDs are never touched               | YES
CRIU dump of pid 3197 | that is the governor itself or its parent        | YES
CRIU dump of pid 3193 | that is the governor itself or its parent        | YES

RESULT: 22/22 checks passed
```
