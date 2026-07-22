#!/usr/bin/env bash
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

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
  "$crate_dir/tests/cpuid_probe.c" -o "$tmpdir/cpuid-probe"
"$drrun" -disable_rseq -c "$client" -- "$tmpdir/cpuid-probe" \
  >"$tmpdir/stdout" 2>"$tmpdir/stderr"

grep -Fx 'CPUID-SUCCESS vendor=GenuineIntel signature=00000663' \
  "$tmpdir/stdout"
cat "$tmpdir/stderr"
