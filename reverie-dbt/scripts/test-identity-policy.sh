#!/usr/bin/env bash
#
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
workspace_dir=$(cd -- "$crate_dir/.." && pwd)
profile=${PROFILE:-debug}
target_dir=${CARGO_TARGET_DIR:-"$workspace_dir/target"}

client=$("$script_dir/build-client.sh" | tail -n 1)
path_helper="$target_dir/$profile/reverie-dbt-dynamorio-path"
drrun=$("$path_helper" drrun)

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
guest="$tmpdir/identity-policy"

"${CC:-cc}" -O2 -g -std=c11 -Wall -Wextra -Werror \
  "$crate_dir/tests/fixtures/identity_policy.c" -o "$guest"

set +e
env HERMIT_DBT_NOOP=1 \
  "$drrun" -quiet -disable_rseq -stack_size 2M -c "$client" \
  -diagnostic_fd 198 -- "$guest" \
  >"$tmpdir/out" 2>"$tmpdir/err" 198>&2
status=$?
set -e

if ((status != 0)); then
  case "$status" in
    4)
      reason="pidfd_open did not target the virtual child"
      ;;
    5)
      reason="pidfd_open did not preserve unknown-identity and invalid-flag error order"
      ;;
    *)
      reason="identity-policy fixture exited with status $status"
      ;;
  esac
  echo "FAIL: DBT virtual identity and pidfd_open policy: $reason" >&2
  echo "--- stdout ---" >&2
  cat "$tmpdir/out" >&2
  echo "--- stderr ---" >&2
  cat "$tmpdir/err" >&2
  exit 1
fi

if ! grep -qx 'pid=3 ppid=1 tid=3 internal_fds=open' "$tmpdir/out"; then
  echo "FAIL: DBT virtual identity and pidfd_open policy: unexpected guest output" >&2
  echo "--- stdout ---" >&2
  cat "$tmpdir/out" >&2
  echo "--- stderr ---" >&2
  cat "$tmpdir/err" >&2
  exit 1
fi

echo "PASS: DBT virtual identity and pidfd_open policy"

# A guest dup2 onto the runtime's diagnostic descriptor cannot be given its
# Linux outcome (a copy at that number) yet, so a fail-closed run ends with
# the policy-refusal status and names the call, instead of reporting a dup2
# that did nothing.
dup_guest="$tmpdir/dup-onto-reserved"
cat >"$tmpdir/dup-onto-reserved.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) {
  int result = dup2(1, 198);
  printf("dup2 returned %d\n", result);
  return 0;
}
EOF
"${CC:-cc}" -O2 -std=c11 -Wall -Wextra -Werror \
  "$tmpdir/dup-onto-reserved.c" -o "$dup_guest"
set +e
env HERMIT_DBT_NOOP=1 \
  "$drrun" -quiet -disable_rseq -stack_size 2M -c "$client" \
  -diagnostic_fd 198 -panic-on-unsupported-syscalls -- "$dup_guest" \
  >"$tmpdir/dup-out" 2>"$tmpdir/dup-err" 198>&2
status=$?
set -e
if ((status != 122)) || [[ -s "$tmpdir/dup-out" ]] ||
  ! grep -q "refusing dup2 onto descriptor 198" "$tmpdir/dup-err"; then
  echo "FAIL: DBT dup2 onto a reserved descriptor: status $status" >&2
  echo "--- stdout ---" >&2
  cat "$tmpdir/dup-out" >&2
  echo "--- stderr ---" >&2
  cat "$tmpdir/dup-err" >&2
  exit 1
fi
echo "PASS: DBT refuses dup2 onto a reserved descriptor"
