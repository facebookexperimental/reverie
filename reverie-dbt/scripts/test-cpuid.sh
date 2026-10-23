#!/usr/bin/env bash
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

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
  "$crate_dir/tests/cpuid_probe.c" -o "$tmpdir/cpuid-probe"
# Leaves 1, 4 and 0xb report the CPU the program runs on, so both runs use the
# same one.
cpu=$(awk '/^Cpus_allowed_list/ {split($2, first, /[-,]/); print first[1]}' \
  /proc/self/status)
taskset -c "$cpu" "$tmpdir/cpuid-probe" >"$tmpdir/native"
taskset -c "$cpu" "$drrun" -quiet -disable_rseq -stack_size 2M -c "$client" -- "$tmpdir/cpuid-probe" \
  >"$tmpdir/stdout" 2>"$tmpdir/stderr"

# The client answers CPUID only through the runtime's tool (ABI version 9), and
# the prototype runtime forwards the host's answer, so every row must be the
# native one. A table left in the client would change rows here.
cmp "$tmpdir/native" "$tmpdir/stdout"
cat "$tmpdir/stderr"
