#!/bin/bash
# ci-timeout-watchdog.sh -- informative CI timeout sidecar.
#
# GitHub Actions' job-level `timeout-minutes` is a HARD box but a SILENT one: it
# cancels the job with a bare "exceeded the maximum execution time" and no clue
# which step was running or why. That reproduces, at smaller scale, exactly the
# diagnosis problem an aggressive timeout is meant to solve (a silent multi-hour
# wedge). This sidecar makes the box INFORMATIVE.
#
# Launch it in the BACKGROUND at the start of a long step, run the real command,
# then kill it when the command finishes:
#
#   scripts/ci-timeout-watchdog.sh \
#       --step "Host-dependent workspace tests" \
#       --soft-deadline 360 --hard-box 600 &
#   watchdog=$!
#   set +e; cargo test ...; status=$?
#   kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
#   exit "$status"
#
# If the step is still running at --soft-deadline seconds (the watchdog was NOT
# killed because the command finished), it prints -- BEFORE the job-level hard
# kill at --hard-box -- which step is running, for how long, the host load, and
# TWO live thread/wchan snapshots ~15s apart so a reader can tell a genuine HANG
# (threads stuck on the same kernel wait channel) from a job that is merely SLOW
# under host load (threads advancing) -- the latter ties into the
# "host too loaded to measure" precondition. On the green path the command
# finishes first and the watchdog is killed mid-sleep, so it costs nothing and
# prints nothing. It NEVER fails the build itself; `timeout-minutes` stays the
# enforcement mechanism.
set -u

STEP="(unnamed step)"
SOFT_DEADLINE=360
HARD_BOX=600
# Subtree to snapshot: default to the watchdog's parent (the step shell), whose
# descendants are the build/test processes.
ROOT_PID="${PPID}"
GAP=15   # seconds between the two snapshots

while [ $# -gt 0 ]; do
  case "$1" in
    --step)          STEP="${2:-}"; shift 2 ;;
    --soft-deadline) SOFT_DEADLINE="${2:-360}"; shift 2 ;;
    --hard-box)      HARD_BOX="${2:-600}"; shift 2 ;;
    --root-pid)      ROOT_PID="${2:-$PPID}"; shift 2 ;;
    --gap)           GAP="${2:-15}"; shift 2 ;;
    *) echo "ci-timeout-watchdog: ignoring unknown arg: $1" >&2; shift ;;
  esac
done

start=$(date +%s)

# Sleep in short slices so a killed watchdog dies promptly (clean green path).
remaining="$SOFT_DEADLINE"
while [ "$remaining" -gt 0 ]; do
  slice=5; [ "$remaining" -lt 5 ] && slice="$remaining"
  sleep "$slice"
  remaining=$(( remaining - slice ))
done

# Still alive at the soft deadline => the step is still running.

# Collect the descendant pids of ROOT_PID (BFS over the ps ppid map).
descendants() {
  local root="$1" map queue seen pid kids
  map=$(ps -eo pid=,ppid= 2>/dev/null)
  queue="$root"; seen=""
  while [ -n "$queue" ]; do
    pid="${queue%% *}"
    if [ "$queue" = "$pid" ]; then queue=""; else queue="${queue#* }"; fi
    case " $seen " in *" $pid "*) continue ;; esac
    seen="$seen $pid"
    kids=$(printf '%s\n' "$map" | awk -v p="$pid" '$2==p{print $1}')
    queue="$queue $kids"
  done
  echo "$seen"
}

# snapshot <tag> <sig_out_file> <cpu_out_file> : print a human-readable live
# thread table, write a movement signature (sorted "tid:wchan" lines) to
# <sig_out_file>, and write the subtree's total consumed CPU (utime+stime, in
# clock ticks) to <cpu_out_file>.
snapshot() {
  local tag="$1" sigfile="$2" cpufile="$3" pid comm t tid state wch now elapsed self_tree cpu_ticks=0 st
  now=$(date +%s); elapsed=$(( now - start ))
  : > "$sigfile"
  # Exclude the watchdog's OWN subtree (itself + its sleep slices + the ps/awk it
  # spawns) by pid, so the snapshot shows only the real build/test processes.
  self_tree=" $(descendants "$$") "
  echo "----- watchdog snapshot [$tag] : step '$STEP' still running at t+${elapsed}s -----"
  local load1="?" load5="" load15=""
  read -r load1 load5 load15 _ < /proc/loadavg 2>/dev/null || true
  echo "  host loadavg: ${load1} ${load5} ${load15}   nproc=$(nproc 2>/dev/null || echo '?')"
  local real_pids=""
  for pid in $(descendants "$ROOT_PID"); do
    case "$self_tree" in *" $pid "*) continue ;; esac
    real_pids="$real_pids $pid"
  done
  echo "  top CPU consumers in subtree (pcpu):"
  ps -o pid=,pcpu=,comm= $real_pids 2>/dev/null \
    | awk 'NF' | sort -k2 -rn | head -5 | sed 's/^/    /'
  printf '  %-6s %-6s %-5s %-26s %s\n' pid tid stat wchan comm
  for pid in $real_pids; do
    comm=$(cat "/proc/$pid/comm" 2>/dev/null) || continue
    # CPU-progress signal: utime+stime (all threads of this proc) plus
    # cutime+cstime (CPU of already-reaped children), so a test that forks/reaps
    # short-lived helpers still registers as progressing. Parse AFTER the final
    # ')' of the comm field, which may itself contain spaces/parens (e.g. a guest
    # named "(hermit run)"), so positional /proc/pid/stat parsing stays correct.
    st=$(awk '{ i=index($0,") "); r=substr($0,i+2); n=split(r,f," ");
                print f[12]+f[13]+f[14]+f[15] }' "/proc/$pid/stat" 2>/dev/null)
    cpu_ticks=$(( cpu_ticks + ${st:-0} ))
    for t in "/proc/$pid/task/"*; do
      [ -e "$t" ] || continue
      tid="${t##*/}"
      state=$(awk '/^State:/{print $2; exit}' "$t/status" 2>/dev/null)
      wch=$(cat "$t/wchan" 2>/dev/null); [ -z "$wch" ] && wch="0"
      printf '  %-6s %-6s %-5s %-26s %s\n' "$pid" "$tid" "${state:-?}" "$wch" "$comm"
      printf '%s:%s\n' "$tid" "$wch" >> "$sigfile"
    done
  done
  sort -o "$sigfile" "$sigfile"
  echo "$cpu_ticks" > "$cpufile"
}

now=$(date +%s); elapsed=$(( now - start ))
budget_left=$(( HARD_BOX - elapsed ))
sig_a="${TMPDIR:-/tmp}/ci-wd-sig-a.$$"
sig_b="${TMPDIR:-/tmp}/ci-wd-sig-b.$$"
cpu_a="${TMPDIR:-/tmp}/ci-wd-cpu-a.$$"
cpu_b="${TMPDIR:-/tmp}/ci-wd-cpu-b.$$"
clk=$(getconf CLK_TCK 2>/dev/null); [ -z "$clk" ] && clk=100

echo ""
echo "::group::CI TIMEOUT WATCHDOG (informative)"
echo "::error title=CI timeout watchdog: step '${STEP}' overran ${SOFT_DEADLINE}s::Step '${STEP}' has been running ${elapsed}s and is approaching the job's hard timeout-minutes box (~${budget_left}s of the ${HARD_BOX}s budget left). Two live thread snapshots follow: identical wchan across both = a genuine HANG on that kernel wait channel; advancing threads = merely SLOW under host load (see the host-load precondition)."

snapshot "A" "$sig_a" "$cpu_a"
sleep "$GAP"
snapshot "B" "$sig_b" "$cpu_b"

# Two independent progress signals over the GAP window:
#  - wchan set changed?           (threads moved between kernel wait channels)
#  - subtree CPU time advanced?   (utime+stime burned = doing work / spinning)
wchan_changed=1; cmp -s "$sig_a" "$sig_b" && wchan_changed=0
ca=$(cat "$cpu_a" 2>/dev/null); cb=$(cat "$cpu_b" 2>/dev/null)
cpu_delta=$(( ${cb:-0} - ${ca:-0} ))
cpu_secs=$(awk -v d="$cpu_delta" -v k="$clk" 'BEGIN{ printf "%.1f", (k>0? d/k : 0) }')
# Host contention gate: on an overloaded runner a genuinely-progressing job can
# be starved of CPU and thus look idle. loadavg > cores means "no spare CPU", so
# a low-CPU reading is ambiguous (could be load-starvation, not a hang) -- which
# is exactly the "host too loaded to measure" case the load precondition targets.
read -r load1 _ < /proc/loadavg 2>/dev/null || load1=0
cores=$(nproc 2>/dev/null || echo 1)
overloaded=$(awk -v l="$load1" -v c="$cores" 'BEGIN{ print (l > c) ? 1 : 0 }')
echo "----- progress hint (heuristic; snapshots ${GAP}s apart) -----"
echo "  wchan set changed: $([ "$wchan_changed" = 1 ] && echo yes || echo no)   subtree CPU burned in window: ${cpu_secs}s (${cpu_delta} ticks)   host 1m-load: ${load1}/${cores} cores"
if [ ! -s "$sig_a" ]; then
  echo "  HINT: no live descendant threads observed (subtree may have just exited or is not visible to this uid)."
elif [ "$overloaded" = 1 ] && [ "$cpu_delta" -le 1 ]; then
  echo "  HINT: host is OVERLOADED (1m-load ${load1} > ${cores} cores) and the subtree burned ~no CPU -> most likely"
  echo "        HOST TOO LOADED TO MEASURE / CPU-starved, NOT necessarily a hang. Re-run on a quiesced runner"
  echo "        (see the host-load precondition / single-runner SPOF). If it recurs on an idle host, treat as a hang."
elif [ "$wchan_changed" = 0 ] && [ "$cpu_delta" -le 1 ]; then
  echo "  HINT: threads pinned to the same wait channel AND ~no CPU burned on an un-loaded host -> looks like an"
  echo "        IDLE HANG (blocked on a lock/wait). A fresh runner likely will NOT help; investigate the wchan above."
elif [ "$wchan_changed" = 0 ]; then
  echo "  HINT: same wait channel but CPU IS being burned -> looks like a BUSY-SPIN (e.g. a hot retry loop),"
  echo "        not idle-blocked. Investigate the spinning thread above."
else
  echo "  HINT: threads are moving between wait channels -> job is PROGRESSING but slow."
  echo "        Most likely host contention (PMU tests degrade under load); a fresh/quiesced runner should help."
fi
echo "  (The thread table + elapsed above are authoritative; this one-line HINT is a heuristic.)"
rm -f "$sig_a" "$sig_b" "$cpu_a" "$cpu_b"
echo "::endgroup::"
exit 0
