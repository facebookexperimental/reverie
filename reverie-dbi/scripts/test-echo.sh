#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DYNAMORIO_HOME:-}" ]]; then
  echo "DYNAMORIO_HOME must point to a built DynamoRIO source tree" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
client=$("$script_dir/build-client.sh" | tail -n 1)
if [[ -x "$DYNAMORIO_HOME/build/bin64/drrun" ]]; then
  drrun="$DYNAMORIO_HOME/build/bin64/drrun"
else
  drrun="$DYNAMORIO_HOME/install/bin64/drrun"
fi
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

expected="hello from reverie-dbi"
"$drrun" -disable_rseq -c "$client" -- \
  /bin/echo "$expected" >"$tmpdir/stdout" 2>"$tmpdir/stderr"

[[ $(cat "$tmpdir/stdout") == "$expected" ]]
grep -Eq 'reverie-dbi: branches=[1-9][0-9]* syscalls=[1-9][0-9]* rewritten_writes=[1-9][0-9]*' \
  "$tmpdir/stderr"
cat "$tmpdir/stderr"
