#!/usr/bin/env bash
#
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
# End-to-end check that the DBI-native equivalents of the reverie example tools
# run under DynamoRIO and produce correct output. Each tool is selected by its
# environment variable and dispatched by the native client through
# `run_active_tool`. A `bash -c` guest is used because DynamoRIO reliably
# intercepts its terminating `exit_group` (some tiny statically-exiting programs
# do not surface the final exit to the client, so exit-time output is skipped).

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
workspace_dir=$(cd -- "$crate_dir/.." && pwd)
profile=${PROFILE:-debug}
target_dir=${CARGO_TARGET_DIR:-"$workspace_dir/target"}

client=$("$script_dir/build-client.sh" | tail -n 1)
path_helper="$target_dir/$profile/reverie-dbi-dynamorio-path"
drrun=$("$path_helper" drrun)

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
pthread_guest="$tmpdir/pthread-lifecycle"
rewrite_exit_guest="$tmpdir/rewrite-exit"
identity_policy_guest="$tmpdir/identity-policy"
fork_pthread_guest="$tmpdir/fork-pthread-identity"
blocked_exit_guest="$tmpdir/blocked-exit-group"
simultaneous_exit_guest="$tmpdir/simultaneous-exit-group"
"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -Werror -pthread \
  "$crate_dir/tests/fixtures/pthread_lifecycle.c" -o "$pthread_guest"
"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -Werror \
  "$crate_dir/tests/fixtures/rewrite_exit.c" -o "$rewrite_exit_guest"
"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -Werror \
  "$crate_dir/tests/fixtures/identity_policy.c" -o "$identity_policy_guest"
"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -Werror -pthread \
  "$crate_dir/tests/fixtures/fork_pthread_identity.c" -o "$fork_pthread_guest"
"${CC:-cc}" -O2 -g -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
  -Wno-unused-parameter -pthread "$workspace_dir/tests/c_tests/threads_group_exit_blocking.c" \
  -o "$blocked_exit_guest"
"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -Werror -pthread \
  "$crate_dir/tests/fixtures/simultaneous_exit_group.c" -o "$simultaneous_exit_guest"

# Run the guest under one tool (selected by $1=ENV) and capture stdout/stderr.
run_tool() {
  local env_var=$1
  shift
  local -a guest=(/bin/bash -c 'echo GUEST-STDOUT; true')
  if (($# > 0)); then
    guest=("$@")
  fi
  env "$env_var=1" "$drrun" -disable_rseq -stack_size 2M -c "$client" -- \
    "${guest[@]}" \
    >"$tmpdir/out" 2>"$tmpdir/err"
}

run_pthread_tool() {
  local env_var=$1
  local label=$2
  run_tool "$env_var" "$pthread_guest"
  grep -q '^threads=8 total=14 unique_tids=8$' "$tmpdir/out" \
    || fail "$label: pthread lifecycle guest failed"
  echo "PASS: $label (concurrent pthread clone/join lifecycle)"
}

fail() {
  echo "FAIL: $1" >&2
  echo "--- stdout ---" >&2; cat "$tmpdir/out" >&2
  echo "--- stderr (tool output) ---" >&2
  grep -v '^WARNING' "$tmpdir/err" >&2 || true
  exit 1
}

set +e
run_tool HERMIT_DBI_TEST_REWRITE_EXIT "$rewrite_exit_guest"
rewrite_status=$?
set -e
[[ $rewrite_status -eq 42 ]] || fail "deferred getpid-to-exit_group rewrite returned $rewrite_status"
echo "PASS: deferred lifecycle syscall preserves replacement number and arguments"

run_tool HERMIT_DBI_NOOP "$identity_policy_guest"
grep -q '^pid=3 ppid=1 tid=3 identity_fd=open$' "$tmpdir/out" \
  || fail "noop: deferred syscall bypassed virtual identity or private descriptor policy"
echo "PASS: deferred syscall preserves virtual identity and private descriptors"

run_tool HERMIT_DBI_NOOP "$fork_pthread_guest"
grep -q '^fork-pthread-race=64$' "$tmpdir/out" \
  || fail "noop: pthread consumed a concurrent process-clone identity"
echo "PASS: process-clone identity handoff excludes concurrent pthreads"

# noop: pure passthrough — guest output must be intact, no tool output.
run_tool HERMIT_DBI_NOOP
grep -q '^GUEST-STDOUT$' "$tmpdir/out" || fail "noop: guest stdout not passed through"
echo "PASS: noop (guest stdout intact)"

# strace: must log decoded syscalls including the terminating exit_group.
run_tool HERMIT_DBI_STRACE
grep -q 'dbi strace' "$tmpdir/err" || fail "strace: no trace lines"
grep -Eq 'exit_group\([0-9]+\) = \?' "$tmpdir/err" || fail "strace: missing exit_group"
echo "PASS: strace (decoded trace incl. exit_group)"

# counter (histogram): must print a per-number histogram at exit.
run_tool HERMIT_DBI_SYSCALL_HISTOGRAM
grep -Eq 'syscall histogram \([1-9][0-9]* calls, [1-9][0-9]* distinct\)' "$tmpdir/err" \
  || fail "counter: no histogram"
echo "PASS: counter (histogram printed)"

# counter1 (GlobalState RPC): must print a nonzero total obtained via send_rpc.
run_tool HERMIT_DBI_COUNTER1
grep -Eq 'counter1 total system calls: [1-9][0-9]*' "$tmpdir/err" \
  || fail "counter1: no RPC total"
echo "PASS: counter1 (GlobalState RPC total)"

# counter2: drives tail_inject and reports process-wide admission accounting.
run_tool HERMIT_DBI_COUNTER2
grep -Eq 'counter2 total system calls: [1-9][0-9]*, from 1 processes, 1 thread\(s\)' \
  "$tmpdir/err" || fail "counter2: no lifecycle summary"
echo "PASS: counter2 (admission accounting + process exit lifecycle)"

# chunky_print: suppress guest writes to fd 1, buffer the bytes, and re-emit them
# to the real stdout at the exit flush (through the native stdout emit path). The
# guest's stdout must survive the round-trip (unlike a naive suppression), while
# the suppression + flush diagnostics prove the buffering path actually ran
# rather than a plain passthrough.
run_tool HERMIT_DBI_CHUNKY_PRINT
grep -q '^GUEST-STDOUT$' "$tmpdir/out" \
  || fail "chunky_print: buffered guest stdout not re-emitted to real stdout"
grep -q 'chunky_print suppressed write of .* bytes to fd 1' "$tmpdir/err" \
  || fail "chunky_print: guest stdout write was not suppressed/buffered"
grep -q 'chunky_print flushed buffered output at exit' "$tmpdir/err" \
  || fail "chunky_print: buffered output not flushed at exit"
echo "PASS: chunky_print (suppress guest stdout, re-emit at exit flush)"

# chrome_trace: record a per-thread syscall timeline and emit it as a Chrome
# trace JSON array at exit. The guest's stdout must pass through untouched
# (chrome_trace only observes), and the emitted JSON must be a well-formed array
# containing the process (B/E) and syscall (X) trace events.
run_tool HERMIT_DBI_CHROME_TRACE
grep -q '^GUEST-STDOUT$' "$tmpdir/out" \
  || fail "chrome_trace: guest stdout not passed through"
grep -Eq 'chrome_trace [1-9][0-9]* trace events across [1-9][0-9]* thread\(s\)' "$tmpdir/err" \
  || fail "chrome_trace: no trace summary"
chrome_json=$(grep -o 'reverie-dbi: chrome_trace_json=.*' "$tmpdir/err" \
  | sed 's/^reverie-dbi: chrome_trace_json=//')
[[ -n "$chrome_json" ]] || fail "chrome_trace: no JSON emitted"
grep -q '"cat":"process"' <<<"$chrome_json" \
  || fail "chrome_trace: JSON missing process (B/E) events"
grep -q '"cat":"syscall"' <<<"$chrome_json" \
  || fail "chrome_trace: JSON missing syscall events"
grep -q '"ph":"X"' <<<"$chrome_json" \
  || fail "chrome_trace: JSON missing complete (X) syscall events"
echo "PASS: chrome_trace (per-thread timeline -> Chrome trace JSON at exit)"

run_pthread_tool HERMIT_DBI_NOOP noop
run_pthread_tool HERMIT_DBI_STRACE strace
run_pthread_tool HERMIT_DBI_COUNTER1 counter1
run_pthread_tool HERMIT_DBI_COUNTER2 counter2
grep -Eq 'counter2 total system calls: [1-9][0-9]*, from 1 processes, 9 thread\(s\)' \
  "$tmpdir/err" || fail "counter2: incorrect pthread lifecycle summary"
echo "PASS: counter2 (concurrent admission accounting + exit lifecycle)"
run_tool HERMIT_DBI_NOOP "$blocked_exit_guest"
echo "PASS: noop (exit_group interrupts blocked sibling syscalls)"
run_tool HERMIT_DBI_COUNTER2 "$blocked_exit_guest"
grep -Eq 'counter2 total system calls: [1-9][0-9]*, from 1 processes, 9 thread\(s\)' \
  "$tmpdir/err" || fail "counter2: incorrect blocked exit_group summary"
echo "PASS: counter2 (exit_group interrupts blocked sibling syscalls)"
run_tool HERMIT_DBI_COUNTER2 "$simultaneous_exit_guest"
grep -Eq 'counter2 total system calls: [1-9][0-9]*, from 1 processes, 2 thread\(s\)' \
  "$tmpdir/err" || fail "counter2: concurrent exit_group callers lost lifecycle summary"
echo "PASS: counter2 (simultaneous exit_group lifecycle election)"
echo "All DBI example tools passed."
