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

expected="hello from reverie-dbi"
"$drrun" -disable_rseq -c "$client" -summary -- \
  /bin/echo "$expected" >"$tmpdir/stdout" 2>"$tmpdir/stderr"

[[ $(cat "$tmpdir/stdout") == "$expected" ]]
grep -Eq 'reverie-dbi: branches=[1-9][0-9]* syscalls=[1-9][0-9]* rewritten_writes=[1-9][0-9]*' \
  "$tmpdir/stderr"
cat "$tmpdir/stderr"
