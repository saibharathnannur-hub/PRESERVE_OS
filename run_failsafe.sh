#!/usr/bin/env bash
# =====================================================================
# run_failsafe.sh -- demonstrate PRESERVE's fail-safe property.
#
# The report claims: every path that does not reach ADMIT ends in STAND
# DOWN, and in STAND DOWN the system behaves no worse than the unmodified
# kernel. This script exercises that claim by running Scenario B once per
# injected fault (governor --inject FAULT), plus:
#   * one clean baseline (kernel OOM killer acts, no governor intervention)
#   * one clean live run with NO fault, to confirm unchanged behaviour
#     (it must still capture AND restore)
#
# For each run it prints, in the matrix style:
#   Fault | Reached capture? | Process state at exit | Same as baseline?
# and saves the table to evidence/failsafe-<timestamp>.txt.
#
# Live runs (the clean live run and every fault) need root for CRIU; the
# baseline does not. Safe to run non-interactively with cached sudo.
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3)"
SCEN=B
STAMP="$(date +%Y%m%d-%H%M%S)"
TABLE="$ROOT/evidence/failsafe-$STAMP.txt"
FAULTS=(arena-too-small dump-fail dump-timeout restore-blocked stale-pid governor-dies)
LOCKCLI=("$PY" "$ROOT/src/runlock.py" --config "$ROOT/preserve.conf")
# Every governor run now creates its own <prefix>-<pid>-<timestamp> cgroup.
CG_PARENT="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service"
CG_PREFIX="$(cd "$ROOT/src" && "$PY" -c 'from config import Config; print(Config().get_str("cgroup", "name"))')"

case "$ROOT" in
  /mnt/*) echo "REFUSING: project under $ROOT; must be on native ext4." >&2; exit 1 ;;
esac

refuse_if_locked() {  # abort the whole session loudly if another governor is running
  local st
  if ! st="$("${LOCKCLI[@]}" --status 2>&1)"; then
    echo "########################################################################"
    echo "##  REFUSED -- another governor is running. Nothing was started or killed."
    echo "##  $st"
    echo "########################################################################"
    exit 75
  fi
}

# ---- leftover cleanup: ONLY the cgroup of a run this script launched ----------
# Earlier versions SIGKILLed every process in a cgroup found by NAME. With a shared
# name that killed another session's workloads. Now the only cgroup ever reaped is
# the one recorded in the lock file by the governor this script started (started
# at/after $1), and only while no governor holds the lock.
reap_own() {  # launched_at_epoch
  local cg procs
  cg="$("${LOCKCLI[@]}" --last-cgroup --since "$1" 2>/dev/null)" || return 0   # 75: a governor is running
  [ -n "$cg" ] || return 0
  case "$cg" in
    "$CG_PARENT/$CG_PREFIX"-[0-9]*-[0-9]*) ;;
    *) echo "  NOT reaping unexpected cgroup path '$cg'"; return 0 ;;
  esac
  [ -d "$cg" ] || return 0
  procs="$(cat "$cg/cgroup.procs" 2>/dev/null)"
  if [ -n "$procs" ]; then
    echo "  cleaning up this run's leftover processes in $cg: $procs"
    # shellcheck disable=SC2086
    sudo kill -KILL $procs 2>/dev/null
    sleep 1
  fi
  sudo rmdir "$cg" 2>/dev/null || true
}

ROWS="$ROOT/evidence/.failsafe-$STAMP.rows"   # one "fault|reached|state|same" line per run
: > "$ROWS"

# ---- run one scenario-B governor invocation, capture its evidence dir -------
# args: label  inject-or-empty  mode(live|baseline)
run_one() {
  local label=$1 inject=$2 mode=$3 dir rc gargs log
  dir="$ROOT/evidence/failsafe-$STAMP-$label"
  mkdir -p "$dir"
  log="$dir/console.log"
  gargs=(--config "$ROOT/preserve.conf" --scenario "$SCEN")
  [ "$mode" = baseline ] && gargs+=(--baseline)
  [ -n "$inject" ] && gargs+=(--inject "$inject")

  echo; echo "########## $label ##########"
  # Clear stale workload state UNDER the governor lock (same defence as run_demo.sh):
  # if another governor is running, refuse instead of deleting its live files.
  if ! "${LOCKCLI[@]}" --hold --label "run_failsafe.sh: clearing run/ before $label" -- \
         rm -f "$ROOT/run/"*.progress.log "$ROOT/run/"*.state.json 2>/dev/null; then
    refuse_if_locked
    echo "FATAL: could not clear stale run/ state files"; exit 1
  fi
  cp "$ROOT/preserve.conf" "$dir/preserve.conf"

  local launched_at; launched_at="$(date +%s)"
  if [ "$mode" = baseline ] && command -v systemd-run >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
    systemd-run --user --scope --quiet -- "$PY" "$ROOT/src/governor.py" "${gargs[@]}" 2>&1 | tee -i "$log"
  else
    sudo "$PY" "$ROOT/src/governor.py" "${gargs[@]}" 2>&1 | tee -i "$log"
  fi
  rc=${PIPESTATUS[0]}
  echo "exit code: $rc"
  if [ "$rc" -eq 75 ] || [ "$rc" -eq 76 ]; then
    # Refused before any experiment ran: never collect run/ files or classify.
    echo "$label|REFUSED - governor exit $rc (another governor running or no exclusive cgroup)|$dir|REFUSED" >> "$ROWS"
    echo "FAILED: governor exit $rc (refused; no experiment ran)" > "$dir/FAILED"
    return
  fi
  cp "$ROOT/run/"*.json "$ROOT/run/"*.log "$dir/" 2>/dev/null || true
  # Record reality for governor-dies, whose governor cannot log its own aftermath:
  # the members of THIS run's own cgroup (path recorded in the lock file).
  local leftover="none" own
  own="$("${LOCKCLI[@]}" --last-cgroup --since "$launched_at" 2>/dev/null)"
  if [ -n "$own" ] && [ -d "$own" ]; then leftover="$(cat "$own/cgroup.procs" 2>/dev/null | tr '\n' ' ')"; fi
  classify "$label" "$inject" "$mode" "$rc" "$log" "$leftover" "$dir"
  reap_own "$launched_at"
}

# ---- derive the four columns from a run's console log + reality -------------
# Every column must be backed by a string the governor actually logged. If the
# required evidence is not present, the row is emitted as UNCLASSIFIED with its
# evidence path -- never a guessed or confident-looking wrong value.
classify() {
  local label=$1 inject=$2 mode=$3 rc=$4 log=$5 leftover=$6 dir=$7
  local reached state same
  # emit an UNCLASSIFIED row (naming the label and the evidence dir) and return
  unclass() { echo "$label|UNCLASSIFIED - check log|$dir|UNCLASSIFIED" >> "$ROWS"; }

  if [ "$mode" = baseline ]; then
    if grep -q "compute_job .*KILLED" "$log"; then
      echo "baseline (clean)|n/a|compute_job killed by kernel OOM|reference" >> "$ROWS"
    elif [ "$rc" = 2 ]; then
      echo "baseline (clean)|n/a|no OOM kill (no memory crisis)|reference (no kill)" >> "$ROWS"
    else unclass; fi
    return
  fi

  if [ -z "$inject" ]; then
    # clean live run: must capture AND restore, else it is a regression (loud).
    local caps res; caps=$(grep -c "PRESERVED dump" "$log"); res=$(grep -c "RESTORED restore" "$log")
    if [ "$caps" -ge 1 ] && [ "$res" -ge 1 ]; then
      echo "none (clean live)|yes (dumped+restored)|restored, resumed|better (work preserved)" >> "$ROWS"
    else
      echo "none (clean live)|INCOMPLETE|clean run did NOT capture+restore -- regression!|WORSE" >> "$ROWS"
    fi
    return
  fi

  # --- fault runs: each requires positive evidence of its own precondition ---
  # A self-verified injection that did not fire aborts as INJECTION FAILED; never a pass.
  if grep -q "INJECTION FAILED\|INJECTION SETUP FAILED" "$log"; then
    local reason; reason="$(grep -m1 "INJECTION \(SETUP \)\?FAILED" "$log" | sed 's/.*INJECTION/INJECTION/')"
    echo "$inject|INJECTION FAILED - fault did not occur|$dir|${reason:-INJECTION FAILED}" >> "$ROWS"; return
  fi
  case "$inject" in
    arena-too-small|stale-pid)
      # Must show a stand-down for THIS fault. Then the kernel is in charge; in
      # scenario B (no swap) it kills compute_job. Require that kill to claim
      # "== baseline"; if the kill is absent, do not guess -- UNCLASSIFIED.
      grep -q "STAND DOWN \[fault=$inject\]" "$log" || { unclass; return; }
      reached="no (stood down)"
      if grep -q "compute.*killed by SIGKILL" "$log" || grep -q "oom_kill 0 -> 1" "$log"; then
        state="stood down; compute_job killed by kernel OOM"; same="yes (compute killed == baseline)"
      else
        state="stood down; compute_job NOT killed in window"; same="UNCLASSIFIED - check log"
      fi ;;
    dump-fail|dump-timeout)
      # Must have attempted a real dump and then stood down after it failed.
      grep -q "ACTION: checkpoint" "$log" || { unclass; return; }
      grep -q "STAND DOWN \[fault=$inject\]" "$log" || { unclass; return; }
      reached="attempted (dump failed)"
      local how="dump failed"
      [ "$inject" = dump-fail ]    && grep -q "ENOSPC" "$log" && how="dump failed (ENOSPC)"
      [ "$inject" = dump-timeout ] && how="dump failed (timeout)"
      # "Process state at exit" is the FINAL state. A process that survives the
      # failed dump but is then killed by the kernel OOM is dead at exit == baseline.
      local killed=""
      grep -q "compute.*killed by SIGKILL" "$log" && killed=1
      grep -q "oom_kill 0 -> 1" "$log" && killed=1
      if grep -q "is GONE" "$log"; then
        state="$how; process LOST by the failed dump"; same="yes (process lost == baseline)"
      elif grep -q "SURVIVED" "$log"; then
        if [ -n "$killed" ]; then
          state="$how; survived the failure, then killed by kernel OOM"; same="yes (== baseline)"
        else
          # survived the failure AND still alive when the run ended: verify no kill in log
          state="$how; survived the failure, still running at exit"; same="better (alive at exit)"
        fi
      else unclass; return; fi ;;
    restore-blocked)
      # Must have dumped, then been permanently denied restore.
      grep -q "PRESERVED dump" "$log" || { unclass; return; }
      grep -q "restore admission will DENY\|STAND DOWN \[fault=restore-blocked\]" "$log" || { unclass; return; }
      reached="yes (dumped)"
      # "work recoverable" is only true if the image set is still on disk. The
      # governor (root) verifies that at shutdown and logs it; trust nothing else.
      if grep -q "still checkpointed at .*image present" "$log"; then
        state="checkpointed, not restored; image present on disk"
        same="work recoverable, job incomplete"
      elif grep -q "IMAGE MISSING" "$log"; then
        state="checkpointed but IMAGE MISSING; work NOT recoverable"
        same="worse than baseline (work lost and job dead)"
      else
        unclass; return   # no evidence either way: do not claim recoverability
      fi ;;
    governor-dies)
      grep -q "crash.*before any capture" "$log" || { unclass; return; }
      reached="no (crashed first)"; same="yes (kernel in charge, == no governor)"
      if [ -n "$leftover" ] && [ "$leftover" != "none" ]; then
        state="governor died before capture; compute_job still under kernel at that point (pids: $leftover)"
      else
        state="governor died before capture; workloads already gone by then"
      fi ;;
    *) unclass; return ;;
  esac
  echo "$inject|$reached|$state|$same" >> "$ROWS"
}

# ---- render the matrix-style table ------------------------------------------
render() {
  {
    echo "PRESERVE fail-safe matrix -- $(date '+%Y-%m-%d %H:%M:%S')  (scenario $SCEN)"
    echo "Arena at session start (reaped first): ${ARENA_START:-not reaped}"
    echo
    # Formatted with awk, not column(1): column is not installed everywhere and
    # its absence silently produced an EMPTY table body in earlier runs.
    { echo "Fault|Reached capture?|Process state at exit|Same as baseline?"
      cat "$ROWS"; } | awk -F'|' '
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
    echo "Reached capture?  = did the governor get as far as attempting a CRIU dump."
    echo "Process state     = the valuable compute_job's fate when the run ended."
    echo "Same as baseline? = baseline kills compute_job and destroys its work; a fail-safe"
    echo "                    outcome is no worse ('yes'). A cell may say 'better' ONLY if the"
    echo "                    valuable process was in a better state AT EXIT than in baseline."
    echo "failed dumps      : a dump that fails after the process is frozen and partially written"
    echo "                    does not cost the process -- PRESERVE does not destroy work the"
    echo "                    kernel would have kept. The process resumes unfrozen and is then left"
    echo "                    to the kernel, which kills it exactly as in baseline. That is a"
    echo "                    fail-safe guarantee, not an improvement over baseline."
    echo "restore-blocked   : a permanently blocked restore leaves the work intact on disk but the"
    echo "                    job unfinished ('work recoverable, job incomplete'). That is better"
    echo "                    than baseline only if the restore can eventually proceed; within the"
    echo "                    run itself the job does not complete, so it does not beat baseline on"
    echo "                    completion."
    echo "UNCLASSIFIED      : the run's log lacked the evidence to decide this row; read the named"
    echo "                    evidence directory. Never treated as a pass."
    echo
    echo "Per-run evidence: evidence/failsafe-$STAMP-<label>/"
  } | tee "$TABLE"
}

# Allow sourcing (FAILSAFE_LIB=1) to unit-test classify()/render without running.
if [ "${FAILSAFE_LIB:-}" != 1 ]; then
  refuse_if_locked   # another governor running: do nothing at all
  # ---- sudo guard (works interactively and non-interactively) -----------
  if [ -t 0 ]; then
    sudo -v || exit 1
  else
    sudo -n true 2>/dev/null || { echo "need cached sudo (run 'sudo -v' first, or run interactively)"; exit 1; }
  fi
  # keep the timestamp fresh for the whole session
  ( while kill -0 "$$" 2>/dev/null; do sudo -n true 2>/dev/null; sleep 50; done ) & KEEPALIVE=$!
  trap 'kill "$KEEPALIVE" 2>/dev/null' EXIT

  # Reap finished images before the batch (never one still checkpointed and not
  # restored, e.g. a previous restore-blocked run's), and record the starting state.
  ARENA_OUT="$(sudo "$PY" "$ROOT/src/governor.py" --config "$ROOT/preserve.conf" --reap-arena 2>&1)"; arc=$?
  ARENA_START="$(printf '%s\n' "$ARENA_OUT" | grep -o 'ARENA: .*' | tail -1)"
  [ -n "$ARENA_START" ] || ARENA_START="ARENA: NOT REAPED (exit $arc): $(printf '%s\n' "$ARENA_OUT" | tail -1)"
  [ "$arc" -eq 0 ] || ARENA_START="$ARENA_START  [reap exit $arc -- starting occupancy unverified]"
  echo "$ARENA_START"

  echo "Fail-safe demonstration (scenario $SCEN). Each fault forces one real precondition to fail."
  run_one baseline      ""               baseline   # reference: kernel OOM acts
  run_one clean         ""               live       # no fault: must still capture+restore
  for f in "${FAULTS[@]}"; do
    run_one "$f" "$f" live
  done
  echo
  render
  echo
  echo "table saved to $TABLE"
fi
