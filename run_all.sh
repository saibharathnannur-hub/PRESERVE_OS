#!/usr/bin/env bash
# =====================================================================
# run_all.sh -- interactive runner for the PRESERVE experiment matrix.
#
# Menu-driven: runs the scenario A/B baseline and PRESERVE experiments,
# a dry run, or a custom run with chosen workload sizes, and after every
# run prints a results table (also saved to evidence/matrix-<ts>.txt).
#
#   ./run_all.sh              each chosen run executes once
#   ./run_all.sh --repeat 5   each chosen run executes 5 times; the table
#                             then shows median [min-max] per column
#
# How runs are executed
#   * Scenario A/B baseline and PRESERVE runs go through run_demo.sh, so
#     they produce the same evidence folders as before. The folder is read
#     from the "console log : <path>" line run_demo.sh prints.
#   * Dry runs and custom runs call src/governor.py directly: run_demo.sh
#     would use sudo for a dry run and does not know custom scenarios.
#     Baseline and dry runs run unprivileged (systemd-run --user --scope);
#     only PRESERVE (live) runs use sudo, because CRIU needs root.
#   * Custom sizes are written to a generated copy of preserve.conf with a
#     [scenario.custom] section; preserve.conf itself is never edited.
#
# Numbers in the table come from src/matrix.py, which reads only what each
# run wrote (baseline_result.json, the governor's console log and SUMMARY
# block, the compute_job progress log).
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3)"
MATRIX=("$PY" "$ROOT/src/matrix.py")
REPEAT=1

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --repeat)   REPEAT="${2:-}"; shift 2 ;;
    --repeat=*) REPEAT="${1#--repeat=}"; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done
if ! [[ "$REPEAT" =~ ^[1-9][0-9]*$ ]]; then
  echo "--repeat needs a positive integer (got '$REPEAT')" >&2; exit 2
fi
case "$ROOT" in
  /mnt/*) echo "REFUSING: project is under $ROOT; it must live on the native Linux filesystem." >&2; exit 1 ;;
esac

SESSION_TS="$(date +%Y%m%d-%H%M%S)"
SESSION="$ROOT/evidence/matrix-$SESSION_TS.jsonl"     # raw per-run rows (Review II statistics)
TABLE="$ROOT/evidence/matrix-$SESSION_TS.txt"         # the printed table
ARENA_LOG="$ROOT/evidence/matrix-$SESSION_TS.arena"   # per-batch arena occupancy, shown in the table header
CUSTOM_CONF="$ROOT/.run_all-custom.conf"              # project root, so relative paths resolve
BATCH=0
KEEPALIVE=""

cleanup() {
  [ -n "$KEEPALIVE" ] && kill "$KEEPALIVE" 2>/dev/null
  rm -f "$CUSTOM_CONF"
}
trap cleanup EXIT
# Ctrl-C stops the current run (the governor shuts down cleanly) and returns to the menu.
trap 'echo; echo "(interrupted -- returning to the menu)"' INT

# ---- sudo once, kept alive for the session ----------------------------
echo "PRESERVE runs need root for CRIU (checkpoint/restore); baseline and dry runs do not."
echo "Enter your sudo password once now; it is kept alive for this session."
SUDO_OK=0
if sudo -v; then
  SUDO_OK=1
  ( while kill -0 "$$" 2>/dev/null; do sudo -n -v 2>/dev/null; sleep 50; done ) &
  KEEPALIVE=$!
else
  echo "sudo not available: PRESERVE runs (options 2 and 4, PRESERVE custom runs) will be marked FAILED."
fi

can_run_unprivileged() {
  command -v systemd-run >/dev/null && systemctl --user show-environment >/dev/null 2>&1
}

# ---- recording and table ----------------------------------------------
record() {  # scenario mode rc evidence_dir
  local args=(row --scenario "$1" --mode "$2" --rc "$3" --batch "$BATCH")
  [ -n "$4" ] && args+=(--evidence "$4")
  if ! "${MATRIX[@]}" "${args[@]}" >> "$SESSION"; then
    echo "!! could not summarise the $1 $2 run (evidence: ${4:-none})"
  fi
}

show_table() {
  echo
  "${MATRIX[@]}" table --session "$SESSION" --out "$TABLE" --repeat "$REPEAT" --arena-log "$ARENA_LOG" \
    || echo "!! could not build the results table"
}

# Before each batch: delete finished images (never one still checkpointed and not
# restored) and record the starting occupancy for the table header. The arena is
# root-owned after live runs, so this uses sudo when the session has it.
reap_arena() {
  local out rc line
  if [ "$SUDO_OK" -eq 1 ]; then
    out="$(sudo "$PY" "$ROOT/src/governor.py" --config "$ROOT/preserve.conf" --reap-arena 2>&1)"; rc=$?
  else
    out="$("$PY" "$ROOT/src/governor.py" --config "$ROOT/preserve.conf" --reap-arena 2>&1)"; rc=$?
  fi
  line="$(printf '%s\n' "$out" | grep -o 'ARENA: .*' | tail -1)"
  [ -n "$line" ] || line="ARENA: NOT REAPED (exit $rc): $(printf '%s\n' "$out" | tail -1)"
  [ "$rc" -eq 0 ] || line="$line  [reap exit $rc -- starting occupancy unverified]"
  echo "batch $BATCH: $line" >> "$ARENA_LOG"
  echo ">> batch $BATCH $line"
}

report_rc() {  # label rc
  if [ "$2" -eq 0 ]; then echo ">> $1: finished (exit 0)"; else echo ">> $1: exit code $2 (see table)"; fi
}

# ---- run executors ------------------------------------------------------
run_standard() {  # scenario(A|B) mode(baseline|live)
  local scen=$1 mode=$2 log rc dir
  local args=(--scenario "$scen")
  [ "$mode" = baseline ] && args+=(--baseline)
  if [ "$mode" = live ] && [ "$SUDO_OK" -ne 1 ]; then
    echo ">> Scenario $scen PRESERVE: FAILED -- needs sudo"; record "$scen" live 126 ""; return
  fi
  echo; echo "########## Scenario $scen -- ${mode/live/PRESERVE} ##########"
  log="$(mktemp)"
  "$ROOT/run_demo.sh" "${args[@]}" 2>&1 | tee -i "$log"   # -i: Ctrl-C must not cut the log
  rc=${PIPESTATUS[0]}
  dir="$(grep -E '^console log : ' "$log" | tail -1 | sed 's/^console log : //')"
  rm -f "$log"
  [ -n "$dir" ] && dir="$(dirname "$dir")"
  [ -z "$dir" ] && echo ">> run_demo.sh did not report an evidence folder"
  report_rc "Scenario $scen ${mode/live/PRESERVE}" "$rc"
  record "$scen" "$mode" "$rc" "$dir"
}

run_direct() {  # label scenario-name mode(baseline|live|dry-run) config-file
  local label=$1 scen=$2 mode=$3 conf=$4 rc launch
  local dir="$ROOT/evidence/demo-$(date +%Y%m%d-%H%M%S)-$mode-$label"
  local gargs=(--config "$conf" --scenario "$scen")
  [ "$mode" = baseline ] && gargs+=(--baseline)
  [ "$mode" = dry-run ] && gargs+=(--dry-run)
  if [ "$mode" != live ] && can_run_unprivileged; then
    launch=(systemd-run --user --scope --quiet --)
  elif [ "$SUDO_OK" -eq 1 ]; then
    launch=(sudo)
  else
    echo ">> $label $mode: FAILED -- needs sudo"; record "$label" "$mode" 126 ""; return
  fi
  echo; echo "########## $label -- $mode ##########"
  mkdir -p "$dir"
  cp "$conf" "$dir/preserve.conf"
  "${launch[@]}" "$PY" "$ROOT/src/governor.py" "${gargs[@]}" 2>&1 | tee -i "$dir/console.log"
  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then
    cp "$ROOT/run/"*.json "$ROOT/run/"*.log "$dir/" 2>/dev/null
    if [ -f "$dir/compute_job.progress.log" ]; then
      "$PY" "$ROOT/workloads/compute_job.py" --verify-log "$dir/compute_job.progress.log" 2>&1 | tee -a "$dir/console.log"
    fi
  else
    # A refused or failed run must not pick up run/ files: they may belong to a
    # different run that is still going (rc 75 = another governor holds the lock).
    echo "FAILED: governor exit $rc; run/ files not collected" > "$dir/FAILED"
    echo ">> $label $mode: governor exit $rc -- marked FAILED, run/ not collected"
  fi
  echo "console log : $dir/console.log"
  report_rc "$label $mode" "$rc"
  record "$label" "$mode" "$rc" "$dir"
}

batch() {  # run one menu choice REPEAT times as one table row
  BATCH=$((BATCH + 1))
  reap_arena
  local i
  for ((i = 1; i <= REPEAT; i++)); do
    [ "$REPEAT" -gt 1 ] && echo && echo "=== repetition $i of $REPEAT ==="
    "$@"
  done
}

# ---- prompts -------------------------------------------------------------
ask_scenario() {  # sets SCEN
  local v
  read -r -p "Scenario A or B? [B]: " v
  SCEN="${v:-B}"; SCEN="${SCEN^^}"
  [[ "$SCEN" =~ ^[AB]$ ]] || { echo "unknown scenario '$SCEN'"; return 1; }
}

ask_number() {  # prompt default regex -> REPLY_VALUE
  local v
  while true; do
    read -r -p "$1 [$2]: " v
    v="${v:-$2}"
    [[ "$v" =~ $3 ]] && { REPLY_VALUE="$v"; return 0; }
    echo "   not a valid number: '$v'"
  done
}

custom_run() {
  local defaults c h d v mode
  defaults="$("${MATRIX[@]}" defaults --scenario B)" || { echo "could not read preserve.conf"; return; }
  eval "$defaults"   # COMPUTE HOG DELAY MEMMAX_MIB (shell-quoted by matrix.py)
  echo "Custom run (based on scenario B: no swap, same thresholds). Press Enter to keep a value."
  ask_number "compute_working_set_mb" "$COMPUTE" '^[0-9]+$'; c=$REPLY_VALUE
  ask_number "hog_target_mb"          "$HOG"     '^[0-9]+$'; h=$REPLY_VALUE
  ask_number "hog_start_delay_s"      "$DELAY"   '^[0-9]+([.][0-9]+)?$'; d=$REPLY_VALUE
  if [ $((c + h)) -le "$MEMMAX_MIB" ]; then
    echo
    echo "  !!! WARNING: compute ($c) + hog ($h) = $((c + h)) MiB does NOT exceed memory_max ($MEMMAX_MIB MiB)."
    echo "  !!! No memory crisis will occur: the OOM killer will not fire and PRESERVE has nothing to save."
    echo "  !!! (Each Python process adds ~8 MiB of its own, so values just under the limit are borderline.)"
    read -r -p "  Run anyway? [y/N]: " v
    [[ "$v" =~ ^[yY] ]] || { echo "cancelled"; return; }
  fi
  read -r -p "Mode: 1) baseline  2) PRESERVE  3) dry run  [1]: " v
  case "${v:-1}" in 1) mode=baseline ;; 2) mode=live ;; 3) mode=dry-run ;; *) echo "invalid mode"; return ;; esac
  "${MATRIX[@]}" custom-config --base B --compute "$c" --hog "$h" --delay "$d" --out "$CUSTOM_CONF" \
    || { echo "could not generate the custom configuration"; return; }
  batch run_direct "custom-c${c}-h${h}-d${d}" custom "$mode" "$CUSTOM_CONF"
}

menu() {
  cat <<EOF

  PRESERVE experiment runner$( [ "$REPEAT" -gt 1 ] && echo "   (each run repeated $REPEAT times)" )
  --------------------------------------------------
   1) Scenario B - baseline   (kernel OOM kills the valuable job)
   2) Scenario B - PRESERVE   (we checkpoint and restore it)
   3) Scenario A - baseline   (kernel correctly kills the hog)
   4) Scenario A - PRESERVE   (no benefit - the honest negative case)
   5) Run all four, in order
   6) Dry run (decisions only, nothing frozen)
   7) Show the last saved results table
   8) Custom run - choose workload sizes
   q) Quit
  --------------------------------------------------
EOF
}

# ---- main loop -------------------------------------------------------------
while true; do
  menu
  read -r -p "  Choose: " choice || break
  case "$choice" in
    1) batch run_standard B baseline ;;
    2) batch run_standard B live ;;
    3) batch run_standard A baseline ;;
    4) batch run_standard A live ;;
    5) batch run_standard B baseline
       batch run_standard B live
       batch run_standard A baseline
       batch run_standard A live ;;
    6) ask_scenario || continue
       batch run_direct "$SCEN" "$SCEN" dry-run "$ROOT/preserve.conf" ;;
    7) "${MATRIX[@]}" latest; continue ;;
    8) custom_run ;;
    q|Q) break ;;
    "") continue ;;
    *) echo "  unknown choice '$choice'"; continue ;;
  esac
  show_table
done
echo "bye. session table: $( [ -f "$TABLE" ] && echo "$TABLE" || echo "(none: no runs completed)")"
