#!/usr/bin/env bash
# =====================================================================
# run_demo.sh -- PRESERVE Review I demonstration.
#
# What it shows:
#   1. Pre-flight: cgroup v2, PSI, CRIU and the project location are sane.
#   2. Safety: the PID whitelist refuses to touch foreign processes.
#   3. The governor run: compute_job + hog in a 512 MiB cgroup; under
#      pressure compute_job is checkpointed, later restored, and resumes.
#   4. Verification: the compute_job hash chain is recomputed from scratch
#      and every logged digest is checked.
#
# Modes:
#   (default)    live: PRESERVE checkpoints and restores (sudo, CRIU needs root)
#   --dry-run    decisions logged, CRIU never invoked (sudo)
#   --baseline   control experiment: governor observes only, swap set to
#                [cgroup] baseline_memory_swap_max, kernel OOM killer acts.
#                No CRIU, so no root: the governor is started with
#                `systemd-run --user --scope`, which places it inside the
#                user's delegated cgroup subtree where it may move its
#                children into preserve-test without privileges.
#
# Everything printed is also saved under evidence/demo-<timestamp>-<mode>/.
# The workloads always run as the invoking user.
#
# Scenarios (named sections in preserve.conf):
#   --scenario A   kernel already right: hog is the largest process (default)
#   --scenario B   large long-running job vs smaller burst: the kernel's
#                  footprint-based OOM selection picks compute_job
#   --scenario C   dependent group: pipeline_job parent+child (pipe); the
#                  kernel kills the child and the parent loses its work too
#
# Usage:  ./run_demo.sh [--scenario A|B] [--dry-run | --baseline] [--no-hog]
#         (all args are passed to governor.py)
# =====================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
MODE=live
SCENARIO=A
prev=""
for arg in "$@"; do
  case "$arg" in
    --dry-run)  MODE=dry-run ;;
    --baseline) MODE=baseline ;;
    --scenario=*) SCENARIO="${arg#--scenario=}" ;;
  esac
  [ "$prev" = "--scenario" ] && SCENARIO="$arg"
  prev="$arg"
done
OUT="$ROOT/evidence/demo-$STAMP-$MODE-$SCENARIO"
PY="$(command -v python3)"

banner() { printf '\n=== %s ===\n' "$*"; }

# Meaning of a governor exit code, from the documented exit-code table (per mode).
rc_meaning() {  # mode rc
  case "$2" in   # codes meaning "no experiment ran", the same in every mode
    75) echo "REFUSED: another governor is running (lock held); no experiment ran"; return ;;
    76) echo "REFUSED: setup aborted (e.g. could not create an exclusive cgroup); no experiment ran"; return ;;
  esac
  case "$1" in
    baseline) case "$2" in
        0) echo "kernel OOM killer fired and was recorded" ;;
        2) echo "no OOM kill happened (no memory crisis occurred)" ;;
        1) echo "error" ;;  *) echo "unexpected exit code" ;; esac ;;
    *) case "$2" in
        0) echo "preserved and resumed" ;;
        2) echo "no capture happened" ;;
        3) echo "no restore happened" ;;
        1) echo "error, or compute_job restarted instead of resuming" ;;
        *) echo "unexpected exit code" ;; esac ;;
  esac
}

# A run is only a success at rc 0 (and, for baseline, the no-crisis rc 2 is
# reported but still treated as a non-success so it cannot masquerade as a demo).
fail_banner() {  # rc
  local meaning; meaning="$(rc_meaning "$MODE" "$1")"
  printf '\n'
  echo "########################################################################"
  echo "##  RUN FAILED  --  governor exited $1: $meaning"
  echo "##  scenario $SCENARIO, mode $MODE.  Verification and evidence skipped."
  echo "########################################################################"
  { echo "FAILED: governor exit $1 ($meaning)"; echo "scenario=$SCENARIO mode=$MODE stamp=$STAMP"; } > "$OUT/FAILED"
  echo "marked $OUT/FAILED"
  echo "console log : $OUT/console.log"
  exit "$1"
}

case "$ROOT" in
  /mnt/*) echo "REFUSING: project is under $ROOT (Windows/OneDrive filesystem); CRIU images must live on native ext4." >&2
          exit 1 ;;
esac

mkdir -p "$OUT"
exec > >(tee "$OUT/console.log") 2>&1

banner "PRESERVE Review I demo  ($STAMP, scenario: $SCENARIO, mode: $MODE)"
echo "project : $ROOT"
echo "kernel  : $(uname -r)"
echo "python  : $($PY --version 2>&1)"
(cd "$ROOT/src" && "$PY" config.py --scenario "$SCENARIO" | grep -E "^# scenario|scenario override") || {
  echo "unknown scenario '$SCENARIO'"; echo "FAILED: unknown scenario '$SCENARIO'" > "$OUT/FAILED"; exit 1; }

banner "1. Pre-flight checks"
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "  PASS  $1"; else echo "  FAIL  $1"; fail=1; fi; }
check "cgroup v2 mounted"            "test -f /sys/fs/cgroup/cgroup.controllers"
check "memory controller available"  "grep -qw memory /sys/fs/cgroup/cgroup.controllers"
check "PSI /proc/pressure/memory"    "test -r /proc/pressure/memory"
check "criu installed"               "command -v criu || test -x /usr/sbin/criu"
check "systemd user delegation"      "test -d /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service"
[ "$fail" -eq 0 ] || { echo "pre-flight failed; not starting the governor"
  echo "FAILED: pre-flight checks failed" > "$OUT/FAILED"; exit 1; }

banner "2. Safety gate: whitelist refuses foreign PIDs"
(cd "$ROOT/src" && "$PY" cgroup.py --refusal-demo)

if [ "$MODE" = baseline ] && command -v systemd-run >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
  banner "3. Governor run (mode: baseline, unprivileged via systemd-run --user --scope)"
  LAUNCH=(systemd-run --user --scope --quiet --)
else
  banner "3. Governor run (mode: $MODE, sudo)"
  sudo -v
  LAUNCH=(sudo)
fi
cp "$ROOT/preserve.conf" "$OUT/preserve.conf"

# (defence 2) Clear stale workload state BEFORE the run, so a governor that
# exits before writing (bad argument, --help, early abort) cannot leave an
# old progress log behind for the verification step to read as success.
#
# The clearing runs UNDER the governor lock (runlock.py --hold, which also records
# what holds it). If another governor is running, its live run/ files are left
# alone and this run is refused: earlier, an unguarded rm here deleted another
# run's state mid-run. While we hold the lock for the rm, no governor can start,
# so there is no check-then-act gap.
set +e
"$PY" "$ROOT/src/runlock.py" --config "$ROOT/preserve.conf" --hold \
  --label "run_demo.sh: clearing run/ before a $MODE run" -- \
  rm -f "$ROOT/run/"*.progress.log "$ROOT/run/"*.state.json 2>/dev/null
clr=$?
set -e
if [ "$clr" -eq 75 ]; then
  # `|| true`: --status exits 75 when held, and under `set -e` a failing command
  # substitution in an assignment would kill the script before the banner printed.
  holder="$(cd "$ROOT/src" && "$PY" runlock.py --status 2>&1)" || true
  echo "########################################################################"
  echo "##  REFUSED -- another governor is running; nothing was cleared or started"
  echo "##  $holder"
  echo "########################################################################"
  { echo "FAILED: refused, another governor is running"; echo "$holder"; } > "$OUT/FAILED"
  echo "console log : $OUT/console.log"
  exit 75
elif [ "$clr" -ne 0 ]; then
  echo "FATAL: could not clear stale run/ state files; aborting" >&2
  { echo "FAILED: could not clear stale run/ state"; } > "$OUT/FAILED"
  echo "console log : $OUT/console.log"
  exit 1
fi
RUN_START=$(date +%s)   # (defence 3) verification refuses progress older than this

set +e
"${LAUNCH[@]}" "$PY" "$ROOT/src/governor.py" --config "$ROOT/preserve.conf" "$@"
rc=$?
set -e
echo "governor exit code: $rc  ($(rc_meaning "$MODE" "$rc"))"

# (requirement 1) Any non-zero exit stops here with a failure banner; the
# verification and evidence steps below never run for a failed run.
[ "$rc" -eq 0 ] || fail_banner "$rc"

if [ "$MODE" = baseline ]; then
  banner "Kernel log: OOM-killer records for this run"
  dmesg 2>/dev/null | grep -E "oom-kill:|Killed process" | tail -6 || echo "(dmesg not readable)"
fi

if ls "$ROOT/run/"pipeline_job.*.progress.log >/dev/null 2>&1; then
  # Scenario C (Objective 6): the governor already recomputed every member's hash
  # chain and printed the group verdict in its SUMMARY; keep the logs as evidence.
  banner "4. Pipeline group: per-member hash chains (verified by the governor, see SUMMARY)"
  grep -hE "member pipeline|pipeline group continuity" "$ROOT/evidence/governor.log" | tail -3 || true
  cp "$ROOT/run/"*.json "$ROOT/run/"*.log "$OUT/" 2>/dev/null || true
else
banner "4. Verify compute_job hash chain"
PROG="$ROOT/run/compute_job.progress.log"
if [ ! -f "$PROG" ]; then
  echo "no progress log found (nothing was run); not reporting a result"
elif [ "$(awk 'END{print int($1)}' "$PROG" 2>/dev/null || echo 0)" -lt "$RUN_START" ]; then
  # (defence 3) newest line predates this run: a leftover we must not trust.
  echo "STALE progress log (newest line older than this run's start $RUN_START); refusing to verify"
  { echo "FAILED: only stale progress data (newest line < run start)"; } > "$OUT/FAILED"
  echo "console log : $OUT/console.log"
  exit 1
else
  "$PY" "$ROOT/workloads/compute_job.py" --verify-log "$PROG" || true
  echo "--- progress lines around the largest gap ---"
  awk 'NR>1 { gap=$1-prev; if (gap>best) { best=gap; line=NR } } { prev=$1; rows[NR]=$0 }
       END { for (i=line-3; i<=line+2; i++) if (i in rows) print (i==line ? ">> " : "   ") rows[i];
             printf "largest gap: %.1f s\n", best }' "$PROG"
  cp "$ROOT/run/"*.json "$ROOT/run/"*.log "$OUT/" 2>/dev/null || true
fi

fi

banner "Evidence"
echo "console log : $OUT/console.log"
echo "governor log: $ROOT/evidence/governor.log"
echo "telemetry   : $ROOT/evidence/telemetry.csv"
exit "$rc"
