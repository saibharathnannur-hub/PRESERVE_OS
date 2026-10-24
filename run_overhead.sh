#!/usr/bin/env bash
# =====================================================================
# run_overhead.sh -- what PRESERVE costs when it is doing nothing.
#
# The governor is idle in the normal case: it samples PSI and cgroup
# counters and decides not to act. This measures that cost.
#
#   Part 1  governor self-cost over a window (CPU, % of one core, per-
#           iteration mean/p95/max, RSS start vs end, arena cost)
#   Part 2  A/B workload throughput: the SAME compute_job for the SAME
#           duration, with the governor running and without it, repeated
#           so the difference can be compared against run-to-run noise.
#
# Neither part needs CRIU, so neither needs root: the governor runs in the
# user's own delegated cgroup subtree via systemd-run --user --scope.
#
# Usage: ./run_overhead.sh [--duration N] [--repeat N] [--scenario A|B]
# Writes evidence/overhead-<timestamp>.txt (rendered with awk, not column).
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/evidence/overhead-$STAMP.txt"
WORK="$ROOT/evidence/overhead-$STAMP"
SCEN=B
DURATION=""
REPEAT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --repeat)   REPEAT="$2";   shift 2 ;;
    --scenario) SCEN="$2";     shift 2 ;;
    -h|--help)  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$ROOT" in /mnt/*) echo "REFUSING: project under $ROOT; must be on native ext4." >&2; exit 1 ;; esac

# Defaults from preserve.conf unless overridden.
conf() { "$PY" - "$1" <<EOF
import sys
sys.path.insert(0, "$ROOT/src")
from config import Config
print(Config(None, "$SCEN").get_str("overhead", sys.argv[1]))
EOF
}
[ -n "$DURATION" ] || DURATION="$(conf duration_s)"
[ -n "$REPEAT" ]   || REPEAT="$(conf repeat)"
mkdir -p "$WORK"

# ---- governor lock and per-run cgroups --------------------------------------
# Every governor run creates its own <prefix>-<pid>-<timestamp> cgroup and holds an
# exclusive flock while it runs (src/runlock.py). This script NEVER kills by cgroup
# name: an earlier reap() of "preserve-test" SIGKILLed another session's workloads.
# It only reaps the cgroup its own governor recorded in the lock file.
LOCKCLI=("$PY" "$ROOT/src/runlock.py" --config "$ROOT/preserve.conf")
LOCK="$(cd "$ROOT/src" && "$PY" -c 'from config import Config; print(Config().get_path("paths", "lock_file"))')"
mkdir -p "$(dirname "$LOCK")"
CG_PARENT="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service"
CG_PREFIX="$(cd "$ROOT/src" && "$PY" -c 'from config import Config; print(Config().get_str("cgroup", "name"))')"

refuse() {  # loud abort: nothing further is started and nothing is killed
  echo "########################################################################"
  echo "##  REFUSED -- $1"
  echo "##  Nothing further was started or killed; this session's data is incomplete."
  echo "########################################################################"
  exit 75
}
refuse_if_locked() {
  local st
  st="$("${LOCKCLI[@]}" --status 2>&1)" || refuse "another governor is running: $st"
}
reap_own() {  # launched_at_epoch -- leftovers of the governor THIS script launched only
  local cg p
  cg="$("${LOCKCLI[@]}" --last-cgroup --since "$1" 2>/dev/null)" || return 0   # 75: a governor is running
  [ -n "$cg" ] || return 0
  case "$cg" in
    "$CG_PARENT/$CG_PREFIX"-[0-9]*-[0-9]*) ;;
    *) echo "  NOT reaping unexpected cgroup path '$cg'"; return 0 ;;
  esac
  [ -d "$cg" ] || return 0
  p="$(cat "$cg/cgroup.procs" 2>/dev/null)"
  if [ -n "$p" ]; then
    echo "  cleaning up this run's leftover processes in $cg: $p"
    # shellcheck disable=SC2086
    kill -KILL $p 2>/dev/null || echo "  WARNING: could not kill $p"
    sleep 1
  fi
  rmdir "$cg" 2>/dev/null || echo "  WARNING: could not remove $cg"
}
unpriv() { command -v systemd-run >/dev/null && systemctl --user show-environment >/dev/null 2>&1; }
launch() { if unpriv; then systemd-run --user --scope --quiet -- "$@"; else "$@"; fi; }

refuse_if_locked
echo "PRESERVE overhead measurement: scenario $SCEN, ${DURATION}s window, $REPEAT run(s) per arm"
echo "(no CRIU involved, so no root required)"

# ---- arm A: governor running (also yields the governor self-cost) -----------
for i in $(seq 1 "$REPEAT"); do
  echo; echo "### arm A (governor running) run $i/$REPEAT"
  # Clear run/ UNDER the lock, so a running governor's live files are never deleted.
  "${LOCKCLI[@]}" --hold --label "run_overhead.sh: clearing run/ before arm A run $i" -- \
    rm -f "$ROOT/run/"*.progress.log "$ROOT/run/"*.state.json "$ROOT/run/overhead_result.json" 2>/dev/null
  case $? in
    0) ;;
    75) refuse "a governor started before arm A run $i (lock held)" ;;
    *)  refuse "could not clear run/ state before arm A run $i" ;;
  esac
  launched_at="$(date +%s)"
  launch "$PY" "$ROOT/src/governor.py" --config "$ROOT/preserve.conf" --scenario "$SCEN" \
         --measure-overhead --overhead-duration "$DURATION" 2>&1 | tee -i "$WORK/A$i.log"
  rc=${PIPESTATUS[0]}
  echo "$rc" > "$WORK/A$i.rc"
  case "$rc" in 75|76) refuse "arm A run $i: governor refused to start (exit $rc)" ;; esac
  if [ -f "$ROOT/run/overhead_result.json" ]; then cp "$ROOT/run/overhead_result.json" "$WORK/A$i.json"
  else echo "WARNING: arm A run $i produced no overhead_result.json"; fi
  # The governor exits 1 if pressure left 'normal' or anything was captured: not idle.
  [ "$rc" = 0 ] || echo "  arm A run $i: governor exit $rc -> INVALID, excluded from the aggregate"
  reap_own "$launched_at"
done

# ---- arm B: identical workload, NO governor, but HOLDING THE LOCK ------------
# With no governor running, nothing would stop another governor (and its workload)
# from starting mid-window and competing for the CPU. So each arm B run holds the
# same exclusive lock for its whole duration; a governor that tries to start in the
# meantime refuses with exit 75.
REF=""
for i in $(seq 1 "$REPEAT"); do
  if [ "$(cat "$WORK/A$i.rc" 2>/dev/null)" = 0 ] && [ -f "$WORK/A$i.json" ]; then REF="$WORK/A$i.json"; break; fi
done
[ -n "$REF" ] || refuse "no valid arm A run to take the workload arguments from"
MEMMAX="$("$PY" -c "import json; print(int(json.load(open('$REF'))['cgroup_memory_max_mib']))")"
# Decide the memory environment ONCE with a probe. The old version used
# 'confined || unconfined' around the run itself, and because timeout(1) exits 124
# at the normal end of the window, the unconfined fallback ran every time.
CONFINE=()
if unpriv && systemd-run --user --scope --quiet -p "MemoryMax=${MEMMAX}M" -p MemorySwapMax=0 -- true 2>/dev/null; then
  CONFINE=(systemd-run --user --scope --quiet -p "MemoryMax=${MEMMAX}M" -p MemorySwapMax=0 --)
  BCONF="confined: MemoryMax=${MEMMAX}M, MemorySwapMax=0 (same limits as arm A)"
else
  BCONF="UNCONFINED: systemd-run with memory properties unavailable (arms not comparable)"
fi
echo; echo "arm B memory environment: $BCONF"
echo "$BCONF" > "$WORK/B.memenv"

for i in $(seq 1 "$REPEAT"); do
  echo; echo "### arm B (no governor, holding the lock) run $i/$REPEAT"
  mapfile -t ARGS < <("$PY" -c "
import json
a = json.load(open('$REF'))['compute_args']
repl = {'--state-file': '$WORK/B$i.state.json', '--progress-log': '$WORK/B$i.progress.log'}
out, k = [], 0
while k < len(a):
    if a[k] in repl: out += [a[k], repl[a[k]]]; k += 2
    else: out.append(a[k]); k += 1
print('\n'.join(out))")
  "${LOCKCLI[@]}" --hold --label "run_overhead.sh: arm B run $i/$REPEAT (compute_job, no governor)" -- \
    "${CONFINE[@]}" timeout -s TERM "$DURATION" "$PY" "$ROOT/workloads/compute_job.py" "${ARGS[@]}" \
    > "$WORK/B$i.log" 2>&1
  rc=$?
  echo "$rc" > "$WORK/B$i.rc"
  case "$rc" in
    0|124) ;;   # 124 = timeout expired: the normal end of the window
    75) refuse "a governor holds the lock; arm B run $i was not started" ;;
    *)  echo "  arm B run $i: exit $rc -> INVALID, excluded from the aggregate" ;;
  esac
  echo "arm B run $i: $(grep -o '"iteration": [0-9]*' "$WORK/B$i.state.json" 2>/dev/null | head -1)"
done

# ---- aggregate + render ----------------------------------------------------
"$PY" - "$WORK" "$REPEAT" "$DURATION" "$SCEN" <<'PYEOF' > "$WORK/rows.psv"
import json, statistics, sys
from pathlib import Path
work, repeat, duration, scen = Path(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]

def rc(path):
    try: return int(path.read_text().strip())
    except Exception: return None

# Only runs that passed their own validity checks are aggregated: an arm A run must
# have exited 0 (the governor exits 1 if pressure left 'normal' or anything was
# captured), and an arm B run must have ended normally (0, or 124 = window over).
A, excluded = [], []
for i in range(1, repeat + 1):
    j, r = work / f"A{i}.json", rc(work / f"A{i}.rc")
    if r != 0 or not j.exists():
        excluded.append(f"A{i} (governor exit {r}{'' if j.exists() else ', no result'})"); continue
    x = json.loads(j.read_text())
    if not x.get("stayed_below_advisory", False) or x.get("captures"):
        excluded.append(f"A{i} (not idle: levels {x.get('level_counts')}, captures {x.get('captures')})"); continue
    A.append(x)
b_it = []
for i in range(1, repeat + 1):
    r = rc(work / f"B{i}.rc")
    try: it = json.loads((work / f"B{i}.state.json").read_text()).get("iteration")
    except Exception: it = None
    if r in (0, 124) and it: b_it.append(it)
    else: excluded.append(f"B{i} (exit {r}, iterations {it})")
a_it = [x.get("compute_iterations") for x in A if x.get("compute_iterations")]

rows = []
def row(k, v): rows.append(f"{k}|{v}")

if not A:
    print("measurement|FAILED: no valid arm A run" + (f" (excluded: {'; '.join(excluded)})" if excluded else ""))
    raise SystemExit(0)
o = A[0]
def agg(vals, unit="", nd=3):
    vals = [v for v in vals if v is not None]
    if not vals: return "n/a"
    f = lambda x: f"{x:.{nd}f}{unit}" if isinstance(x, float) else f"{x}{unit}"
    if len(vals) == 1: return f(vals[0])
    return f"{f(statistics.median(vals))} [{f(min(vals))}-{f(max(vals))}]"

row("scenario / window", f"{scen} / {o['duration_s']:.1f}s at {o['sample_interval_s']}s interval")
row("runs per arm", f"{repeat} requested; used A={len(A)} B={len(b_it)}")
row("excluded runs", "; ".join(excluded) if excluded else "none")
try: memenv = (work / "B.memenv").read_text().strip()
except Exception: memenv = "unknown"
row("arm B memory environment", memenv)
row("-- GOVERNOR SELF-COST --", "")
row("sampling iterations", agg([x["sampling_iterations"] for x in A], nd=0))
row("per-iteration mean", agg([x["iter_mean_ms"] for x in A], " ms"))
row("per-iteration p95", agg([x["iter_p95_ms"] for x in A], " ms"))
row("per-iteration max", agg([x["iter_max_ms"] for x in A], " ms"))
row("governor CPU time", agg([x["governor_cpu_s"] for x in A], " s"))
row("governor CPU, % of one core", agg([x["governor_cpu_pct_one_core"] for x in A], " %"))
row("governor RSS start", agg([x["rss_start_mib"] for x in A], " MiB", 2))
row("governor RSS end", agg([x["rss_end_mib"] for x in A], " MiB", 2))
row("governor RSS delta (leak check)", agg([x["rss_delta_mib"] for x in A], " MiB", 2))
row("captures / restores", f"{o['captures']} / {o['restores']}  (idle: must be 0/0)")
row("pressure levels seen", f"{o['level_counts']}  stayed below advisory: {o['stayed_below_advisory']}")
row("-- ARENA COST --", "")
row("arena kind", o["arena_kind"])
row("arena budget (disk cap)", f"{o['arena_capacity_mib']:.0f} MiB")
peak = o["arena_peak_used_mib"]
row("arena peak on-disk use", f"{peak:.2f} MiB" if peak is not None
    else f"unknown - arena not readable by this uid (readable={o['arena_readable_by_governor']})")
row("images written while idle", f"{o['images_written_this_run']} (captures=0 => the arena was not written to)")
row("arena RAM pinned", f"{o['arena_ram_pinned_mib']:.1f} MiB")
row("free-space guard (fs_reserve)", f"{o['fs_reserve_mib']:.0f} MiB kept free on the filesystem")
row("budget vs protected cgroup", f"{o['arena_capacity_mib']:.0f} MiB disk / {o['cgroup_memory_max_mib']:.0f} MiB "
    f"= {o['arena_capacity_mib']/max(o['cgroup_memory_max_mib'],1):.1f}x (arena_size_mib is configurable)")
row("-- WORKLOAD THROUGHPUT A/B --", "")
row("iterations, governor running", agg(a_it, nd=0))
row("iterations, no governor", agg(b_it, nd=0))

if len(a_it) >= 2 and len(b_it) >= 2:
    ma, mb = statistics.median(a_it), statistics.median(b_it)
    diff = mb - ma
    noise = max(max(a_it) - min(a_it), max(b_it) - min(b_it))
    row("difference (no-gov - gov)", f"{diff:+.0f} iterations ({100*diff/mb:+.2f}% of no-governor median)")
    row("run-to-run noise band", f"+/-{noise:.0f} iterations (widest within-arm spread)")
    if abs(diff) <= noise:
        # NB: never put '|' in cell text -- it is the awk formatter's column separator.
        row("verdict", f"INDISTINGUISHABLE from noise: abs({diff:+.0f}) <= band {noise:.0f}. "
                       f"No throughput cost can be claimed from this data.")
    else:
        row("verdict", f"difference {diff:+.0f} exceeds the noise band {noise:.0f}; "
                       f"a real cost of about {100*diff/mb:.2f}% is indicated")
else:
    row("difference", "NOT MEASURED - needs >=2 runs per arm; a single-run difference is not a measurement")
print("\n".join(rows))
PYEOF

{
  echo "PRESERVE idle-overhead report -- $(date '+%Y-%m-%d %H:%M:%S')"
  echo
  { echo "Metric|Value"; cat "$WORK/rows.psv"; } | awk -F'|' '
    function pad(s, n) { while (length(s) < n) s = s " "; return s }
    { rows++; if (NF > nc) nc = NF
      for (i = 1; i <= NF; i++) { cell[rows, i] = $i; if (length($i) > w[i]) w[i] = length($i) } }
    END {
      for (r = 1; r <= rows; r++) {
        out = ""
        for (i = 1; i <= nc; i++) { out = out pad(cell[r, i], w[i]); if (i < nc) out = out " | " }
        sub(/ +$/, "", out); print out
        if (r == 1) { sep = ""
          for (i = 1; i <= nc; i++) { d = ""; for (k = 0; k < w[i]; k++) d = d "-"
            sep = sep d; if (i < nc) sep = sep "-+-" } print sep }
      } }'
  echo
  echo "Idle = the normal case: the workload runs, there is no antagonist, pressure never"
  echo "reaches the advisory threshold, and the governor samples and decides not to act."
  echo
  echo "The arena is a byte-budgeted DIRECTORY on ext4, not pinned memory: the code only"
  echo "creates it (mkdir), stats the files in it, and calls statvfs. It holds no RAM at any"
  echo "time, and an idle governor writes nothing into it (images written: 0 above). A"
  echo "checkpoint of this workload is ~307 MiB, so the 2048 MiB budget is a cap on"
  echo "concurrent image sets, not a reservation. The 4x ratio against the 512 MiB protected"
  echo "cgroup is a configuration choice (arena_size_mib): in a real deployment it would be"
  echo "sized to the protected workload, not left at 4x. The real standing cost of an idle"
  echo "governor is the CPU and RSS above, plus fs_reserve_mib of filesystem free space that"
  echo "the admission test keeps spare."
  echo
  echo "Per-run logs and JSON: evidence/overhead-$STAMP/"
} | tee "$OUT"
echo
echo "report saved to $OUT"
