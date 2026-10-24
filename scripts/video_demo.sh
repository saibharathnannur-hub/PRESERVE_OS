#!/usr/bin/env bash
# =====================================================================
# scripts/video_demo.sh -- run the whole PRESERVE test set with one command
# and finish with three summary tables (for recording the project video).
#
#   ./scripts/video_demo.sh
#   ./scripts/video_demo.sh --render evidence/video-<ts>   # re-print the tables of THAT
#                                                          # run from its own logs (no runs)
#
# Runs, one at a time (raw output goes to evidence/video-<ts>/, the screen
# shows one banner line with an elapsed timer per step):
#   1-6   Scenarios A, B, C: baseline and PRESERVE      (run_demo.sh)
#   7-12  Fault injections on scenario B                (run_failsafe.sh's run_one + classify,
#                                                        governor --inject, self-verifying)
#   13    PID whitelist safety gate                      (cgroup.py / capture.py --refusal-demo)
#
# Nothing here re-implements an experiment or a check: every run goes through
# the existing scripts, and every number in the tables is parsed from the logs
# this invocation wrote (matrix.py build_row, baseline_result.json, governor
# SUMMARY lines, the failsafe classifier). A value that is not in this run's
# logs is printed as "-".
#
# Exit: 0 all checks passed, 1 some check failed, 75 another governor holds
# the run lock (nothing started).
# =====================================================================
set -uo pipefail

V_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Reuse run_failsafe.sh as a library: run_one (runs one scenario-B governor with
# --inject and collects its evidence), classify, refuse_if_locked, reap helpers.
FAILSAFE_LIB=1 source "$V_ROOT/run_failsafe.sh"
rm -f "$ROWS"   # the library created an empty evidence/.failsafe-<stamp>.rows on load

V_PY="$(command -v python3)"
V_RENDER_ONLY=0
if [ "${1:-}" = --render ]; then
  [ -d "${2:-}" ] || { echo "usage: $0 --render evidence/video-<ts>"; exit 2; }
  V_RENDER_ONLY=1
  V_DIR="$(cd "$2" && pwd)"
  V_TS="${V_DIR##*/video-}"
else
  V_TS="$(date +%Y%m%d-%H%M%S)"
  V_DIR="$V_ROOT/evidence/video-$V_TS"
  mkdir -p "$V_DIR"
fi
STAMP="video-$V_TS"                  # run_one writes evidence/failsafe-video-<ts>-<fault>/
ROWS="$V_DIR/failsafe.rows"          # classify appends one row per fault here
V_SCEN_LIST="$V_DIR/scenarios.list"  # scen|mode|rc|evidence_dir|wrapper_log
V_START=$(date +%s)
V_TOTAL=13
V_STEP=0

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_G=$'\e[32m'; C_R=$'\e[31m'; C_B=$'\e[1m'; C_D=$'\e[2m'; C_N=$'\e[0m'
else
  C_G=""; C_R=""; C_B=""; C_D=""; C_N=""
fi

locked_stop() {  # explain exit 75 and stop
  echo
  echo "########################################################################"
  echo "##  STOPPED -- another PRESERVE governor holds the run lock (exit 75)."
  echo "##  Nothing further was started. Wait for it to finish, then re-run."
  echo "##  $("${LOCKCLI[@]}" --status 2>&1)"
  echo "########################################################################"
  echo "partial logs: $V_DIR"
  exit 75
}

if [ "$V_RENDER_ONLY" -eq 0 ]; then
: > "$ROWS"
: > "$V_SCEN_LIST"
# ---- 1. lock + sudo ----------------------------------------------------------
"${LOCKCLI[@]}" --status >/dev/null 2>&1 || locked_stop
echo "PRESERVE needs root for CRIU. Enter your sudo password once; it is kept alive."
if [ -t 0 ]; then
  sudo -v || { echo "sudo failed; cannot run the PRESERVE runs."; exit 1; }
else
  sudo -n true 2>/dev/null || { echo "need cached sudo (run 'sudo -v' first)"; exit 1; }
fi
( while kill -0 "$$" 2>/dev/null; do sudo -n true 2>/dev/null; sleep 50; done ) &
V_KEEPALIVE=$!
trap 'kill "$V_KEEPALIVE" 2>/dev/null' EXIT

# ---- 2. header -------------------------------------------------------------------
V_CRIU="$( (command -v criu >/dev/null && criu --version || /usr/sbin/criu --version) 2>/dev/null \
          | awk '/^Version/ {print $2; exit}')"
V_ARENA_MIB="$(cd "$V_ROOT/src" && "$V_PY" -c \
  'from config import Config; print(Config().get_str("admission", "arena_size_mib"))' 2>/dev/null)"
# Reap finished images first (never one still checkpointed and not restored), as the
# matrix and failsafe runners do, and record the occupancy line it reports.
V_ARENA_LINE="$(sudo "$V_PY" "$V_ROOT/src/governor.py" --config "$V_ROOT/preserve.conf" --reap-arena 2>&1 \
               | tee "$V_DIR/arena-reap.log" | grep -o 'ARENA: .*' | tail -1)"
{
  echo "PRESERVE -- checkpoint instead of kill under memory pressure"
  echo "kernel : $(uname -r)"
  echo "date   : $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "CRIU   : ${V_CRIU:--}"
  echo "arena  : budget ${V_ARENA_MIB:--} MiB; ${V_ARENA_LINE:-occupancy -}"
  echo "logs   : $V_DIR"
} | tee "$V_DIR/header.txt"
echo

# ---- step runner: hide output, show banner + elapsed timer ------------------------
V_SPIN='|/-\'
run_step() {  # label logfile cmd...  -> sets STEP_RC, STEP_SECS
  local label=$1 log=$2; shift 2
  V_STEP=$((V_STEP + 1))
  local tag; tag="$(printf '[%2d/%d]' "$V_STEP" "$V_TOTAL")"
  local t0; t0=$(date +%s)
  "$@" > "$log" 2>&1 < /dev/null &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r%s %-36s %s %4ds ' "$tag" "$label" "${V_SPIN:i++%4:1}" "$(( $(date +%s) - t0 ))"
    sleep 1
  done
  wait "$pid"; STEP_RC=$?
  STEP_SECS=$(( $(date +%s) - t0 ))
  printf '\r%s %-36s ... done (%d s)%s\n' "$tag" "$label" "$STEP_SECS" "$( [ "$STEP_RC" -eq 75 ] && echo '  LOCKED')"
  [ "$STEP_RC" -eq 75 ] && locked_stop
}

scenario_step() {  # scen mode(baseline|live)
  local scen=$1 mode=$2 label log dir
  label="Scenario $scen - $( [ "$mode" = live ] && echo PRESERVE || echo baseline)"
  log="$V_DIR/scenario-$scen-$mode.log"
  if [ "$mode" = baseline ]; then run_step "$label" "$log" "$V_ROOT/run_demo.sh" --scenario "$scen" --baseline
  else run_step "$label" "$log" "$V_ROOT/run_demo.sh" --scenario "$scen"; fi
  dir="$(grep -E '^console log : ' "$log" | tail -1 | sed 's/^console log : //')"
  [ -n "$dir" ] && dir="$(dirname "$dir")"
  echo "$scen|$mode|$STEP_RC|$dir|$log" >> "$V_SCEN_LIST"
}

fault_step() {  # fault
  local f=$1
  run_step "Fault - $f" "$V_DIR/fault-$f.log" run_one "$f" "$f" live
  # keep the run's evidence with this video session
  if [ -d "$V_ROOT/evidence/failsafe-$STAMP-$f" ]; then
    mv "$V_ROOT/evidence/failsafe-$STAMP-$f" "$V_DIR/fault-$f"
    sed -i "s#$V_ROOT/evidence/failsafe-$STAMP-$f#$V_DIR/fault-$f#g" "$ROWS"
  fi
}

gate_check() {
  cd "$V_ROOT/src" || return 1
  local rc=0
  echo "## cgroup.py --refusal-demo"; "$V_PY" cgroup.py --refusal-demo || rc=1
  echo "## capture.py --refusal-demo"; "$V_PY" capture.py --refusal-demo || rc=1
  return $rc
}

# ---- 3-5. the runs ------------------------------------------------------------------
for s in A B C; do
  scenario_step "$s" baseline
  scenario_step "$s" live
done
for f in "${FAULTS[@]}"; do
  fault_step "$f"
done
run_step "PID whitelist safety gate" "$V_DIR/gate.log" gate_check
echo "$STEP_RC" > "$V_DIR/gate.rc"
echo "$(( $(date +%s) - V_START ))" > "$V_DIR/runtime.s"
fi  # end of the runs (skipped with --render)
V_GATE_RC="$(cat "$V_DIR/gate.rc" 2>/dev/null || echo 1)"
V_RUNTIME="$(cat "$V_DIR/runtime.s" 2>/dev/null || echo 0)"

# ---- 6. parse THIS run's logs into three pipe-separated tables ---------------------
"$V_PY" - "$V_ROOT" "$V_DIR" "$V_GATE_RC" <<'PYEOF' > "$V_DIR/tables.psv" 2> "$V_DIR/parse-errors.log"
import json, re, sys
from pathlib import Path

root, vdir, gate_rc = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
sys.path.insert(0, str(root / "src"))
from matrix import build_row  # the existing per-run extractor (dump/restore times, preserved work)

D = "-"
def f2(x): return D if x is None else f"{float(x):.2f}"
def read(p):
    try: return Path(p).read_text(errors="replace")
    except OSError: return ""

# ---------------- TABLE 1: scenarios ----------------
print("#T1")
print("Scenario|Mode|Valuable job outcome|Work lost (s)|Work preserved (s)|Capture time (s)|Restore time (s)|Hash chain (mismatches)|Check")
COMPUTE_V = re.compile(r"compute_job continuity: (.+?) -- (.*)")
GROUP_V = re.compile(r"pipeline group continuity: (.+?) -- ")
CHAIN_C = re.compile(r"^verified \d+ lines up to iteration \d+: (\d+) mismatches, (\d+) restart", re.M)
CHAIN_G = re.compile(r"member (pipeline\S*) pid=\d+: .*?verified \d+ lines up to iteration \d+: (\d+) mismatches, (\d+) restart")
MEMBER_CKPT = re.compile(r"group member \S+ pid=(\d+) checkpointed in the same image; .*?work ([\d.]+)s")
MEMBER_EXIT = re.compile(r"\] (pipeline(?:-child)?) pid=(\d+) (?:exited|killed)[^(\n]*\(last reported iteration \d+, work ([\d.]+)s\)")
for line in read(vdir / "scenarios.list").splitlines():
    scen, mode, rc, ev, wlog = line.split("|")
    rc = int(rc)
    evp = Path(ev) if ev else None
    row = build_row(scen, mode, rc, 0, evp)
    console = read(evp / "console.log") if evp else ""
    wrapper = read(wlog)
    group = "pipeline group continuity" in console or (evp is not None and (evp / "pipeline_job.parent.progress.log").exists())
    outcome = lost = kept = cap = res = D
    # hash chain: run_demo.sh step 4 (compute_job) or the governor's per-member check (group)
    chain, chain_ok = D, None
    if group:
        per = {}
        for m in CHAIN_G.finditer(console):
            per.setdefault(m[1], (int(m[2]), int(m[3])))
        if per:
            mm, rs = sum(v[0] for v in per.values()), sum(v[1] for v in per.values())
            chain = f"{mm} ({len(per)} chains)" + (f" +{rs} restarts" if rs else "")
            chain_ok = mm == 0 and rs == 0
    else:
        m = CHAIN_C.search(wrapper) or CHAIN_C.search(console)
        if m:
            chain = m[1] + (f" +{m[2]} restarts" if int(m[2]) else "")
            chain_ok = int(m[1]) == 0 and int(m[2]) == 0
    verdict = None
    if mode == "baseline":
        try:
            br = json.loads(read(evp / "baseline_result.json")) if evp else None
        except ValueError:
            br = None
        if br:
            if group and br.get("group"):
                g = br["group"]
                outcome = (f"killed ({g['members_died']}/{g['members_total']} members)"
                           if g["members_died"] else "not touched")
                lost = f2(g["work_destroyed_s"])
            elif not group:
                outcome = "killed" if br.get("compute_killed") else "not touched"
                lost = f2(br.get("compute_work_lost_s"))
        ok = rc == 0 and br is not None and outcome != D
    else:
        if row.get("dump_s") is not None: cap = f2(row["dump_s"])
        if row.get("restore_s") is not None: res = f2(row["restore_s"])
        if group:
            m = GROUP_V.search(console); verdict = m[1] if m else None
            members = sorted({m[1] for m in MEMBER_CKPT.finditer(console)})
            if verdict == "RESUMED":
                work = {m[1]: float(m[2]) for m in MEMBER_CKPT.finditer(console)}
                outcome, lost, kept = f"preserved ({len(work)}/{len(work)} members)", "0.00", f2(sum(work.values()))
            elif verdict == "KILLED":
                work = {m[2]: float(m[3]) for m in MEMBER_EXIT.finditer(console)}
                outcome, lost, kept = f"killed ({len(work)} members)", f2(sum(work.values())), "0.00"
            elif verdict == "RAN CONTINUOUSLY":
                outcome, lost, kept = "not touched", "0.00", "0.00"
            elif verdict:
                outcome = verdict.lower()
        else:
            m = COMPUTE_V.search(console); verdict = m[1] if m else None
            if verdict == "RESUMED":
                outcome, lost, kept = "preserved", "0.00", f2(row.get("preserved_s"))
            elif verdict == "KILLED":
                w = re.search(r"([\d.]+)s of work lost", m[2])
                outcome, lost, kept = "killed", f2(w[1]) if w else D, "0.00"
            elif verdict == "RAN CONTINUOUSLY":
                outcome, lost, kept = "not touched", "0.00", "0.00"
            elif verdict:
                outcome = verdict.lower()
        ok = rc == 0 and verdict == "RESUMED"
    if chain_ok is False:
        ok = False
    label = "PRESERVE" if mode == "live" else "baseline"
    print("|".join([scen, label, outcome, lost, kept, cap, res, chain, "PASS" if ok else "FAIL"]))

# ---------------- TABLE 2: fault injection ----------------
print("#T2")
print("Fault|Expected safe behaviour|Observed|Verified")
EXPECT = {
    "arena-too-small": "M3 denies capture -> STAND DOWN, no dump",
    "dump-fail":       "real dump fails (ENOSPC) -> clean up, STAND DOWN",
    "dump-timeout":    "dump times out -> clean up, STAND DOWN",
    "restore-blocked": "restore denied -> image kept on disk, no restore",
    "stale-pid":       "PID-reuse guard refuses -> STAND DOWN, no dump",
    "governor-dies":   "governor crashes -> kernel in charge, nothing frozen",
}
rows = {}
for line in read(vdir / "failsafe.rows").splitlines():
    parts = line.split("|")
    if len(parts) == 4:
        rows[parts[0]] = parts
for fault, expect in EXPECT.items():
    r = rows.get(fault)
    console = read(vdir / f"fault-{fault}" / "console.log")
    wrapper = read(vdir / f"fault-{fault}.log")
    if r is None:
        print(f"{fault}|{expect}|-|NO"); continue
    bad = any(w in "|".join(r[1:]) for w in ("UNCLASSIFIED", "INJECTION FAILED", "REFUSED"))
    if fault == "governor-dies":
        m = re.search(r"^exit code: (\d+)", wrapper, re.M)
        verified = (not bad and m is not None and m[1] == "137"
                    and "simulating an abrupt governor crash before any capture" in console)
        state = re.sub(r" at that point \(pids: ([\d ]+)\)",
                       lambda p: f" ({len(p[1].split())} workload pid(s) left running)", r[2])
        observed = state + (f"; governor exit {m[1]}" if m else "")
    else:
        verified = not bad and re.search(rf"FAULT RESULT\s+inject={re.escape(fault)}\s+VERIFIED", console) is not None
        observed = r[2]
    if bad:  # classifier lacked evidence: say so and point at the log, never a guessed state
        observed = f"{r[1]} (fault-{fault}/console.log)"
    print(f"{fault}|{expect}|{observed}|{'YES' if verified else 'NO'}")

# ---------------- TABLE 3: safety gate ----------------
print("#T3")
print("Target|Refusal class|Refused")
gate = read(vdir / "gate.log")
n = 0
for line in gate.splitlines():
    m = re.match(r"^\s+(.+?)\s+-> (refused|ALLOWED)(?::\s*(.*))?$", line)
    if m:
        why = m[3] or ""
        c = re.search(r"refusing to \w+ pid \S+: (.*)$", why)
        print(f"{m[1]}|{c[1] if c else why or '-'}|{'YES' if m[2] == 'refused' else 'NO'}"); n += 1
        continue
    m = re.match(r"^pid (\d+): (refused before CRIU ran|dump was NOT refused)(?::\s*(.*))?$", line)
    if m:
        c = re.search(r"refusing to \w+ pid \S+: (.*)$", m[3] or "")
        print(f"CRIU dump of pid {m[1]}|{c[1] if c else '-'}|{'YES' if m[2].startswith('refused') else 'NO'}"); n += 1
if n == 0 or gate_rc != 0:
    print(f"refusal demos|exit status {gate_rc}, {n} refusal lines parsed|{'YES' if gate_rc == 0 and n else 'NO'}")
PYEOF

# ---- render: awk-aligned tables (no column(1)), saved plain, colored on screen -----
render_table() {  # section-tag title
  echo "$2"
  awk -v tag="$1" -F'|' '
    function pad(s, n) { while (length(s) < n) s = s " "; return s }
    /^#T/ { on = ($0 == "#" tag); next }
    on { rows++; if (NF > nc) nc = NF
         for (i = 1; i <= NF; i++) { cell[rows, i] = $i; if (length($i) > w[i]) w[i] = length($i) } }
    END {
      for (r = 1; r <= rows; r++) {
        out = ""
        for (i = 1; i <= nc; i++) { out = out pad(cell[r, i], w[i]); if (i < nc) out = out " | " }
        sub(/ +$/, "", out); print out
        if (r == 1) { sep = ""
          for (i = 1; i <= nc; i++) { d = ""; for (k = 0; k < w[i]; k++) d = d "-"
            sep = sep d; if (i < nc) sep = sep "-+-" } print sep }
      } }' "$V_DIR/tables.psv"
  echo
}

V_PASS=$(awk -F'|' '/^#T/ {t=$0; next} t=="#T1" && $NF=="PASS" {p++} (t=="#T2"||t=="#T3") && $NF=="YES" {p++} END {print p+0}' "$V_DIR/tables.psv")
V_CHECKS=$(awk -F'|' '/^#T/ {t=$0; hdr=1; next} hdr {hdr=0; next} t!="" && NF>1 {n++} END {print n+0}' "$V_DIR/tables.psv")
{
  cat "$V_DIR/header.txt"
  echo "total runtime: $((V_RUNTIME / 60)) min $((V_RUNTIME % 60)) s"
  echo
  render_table T1 "TABLE 1 - SCENARIOS"
  render_table T2 "TABLE 2 - FAULT INJECTION (scenario B)"
  render_table T3 "TABLE 3 - SAFETY GATE"
  echo "RESULT: $V_PASS/$V_CHECKS checks passed"
} > "$V_DIR/summary.txt"

[ -t 1 ] && printf '\033[2J\033[H'
# Color only the verdict words (trailing column) on screen; the saved file stays plain.
sed -E -e "s/\| PASS\$/| ${C_G}PASS${C_N}/" -e "s/\| FAIL\$/| ${C_R}FAIL${C_N}/" \
       -e "s/\| YES\$/| ${C_G}YES${C_N}/"   -e "s/\| NO\$/| ${C_R}NO${C_N}/" \
       -e "s/^(TABLE .*)\$/${C_B}\1${C_N}/" \
       -e "s#^RESULT: (.*)\$#${C_B}RESULT: \1${C_N}#" "$V_DIR/summary.txt"
echo
echo "${C_D}summary saved to $V_DIR/summary.txt${C_N}"
[ -s "$V_DIR/parse-errors.log" ] && echo "${C_R}parser messages: $V_DIR/parse-errors.log${C_N}"
[ "$V_PASS" -eq "$V_CHECKS" ] && [ "$V_CHECKS" -gt 0 ] && exit 0 || exit 1
