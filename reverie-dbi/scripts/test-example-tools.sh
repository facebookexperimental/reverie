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

# Run the guest under one tool (selected by $1=ENV) and capture stdout/stderr.
run_tool() {
  local env_var=$1
  shift
  env "$env_var=1" "$drrun" -disable_rseq -c "$client" -- \
    /bin/bash -c 'echo GUEST-STDOUT; true' \
    >"$tmpdir/out" 2>"$tmpdir/err"
}

fail() {
  echo "FAIL: $1" >&2
  echo "--- stdout ---" >&2; cat "$tmpdir/out" >&2
  echo "--- stderr (tool output) ---" >&2
  grep -v '^WARNING' "$tmpdir/err" >&2 || true
  exit 1
}

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

echo "All DBI example tools passed."
