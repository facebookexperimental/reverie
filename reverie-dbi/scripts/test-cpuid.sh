#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DYNAMORIO_HOME:-}" ]]; then
  echo "DYNAMORIO_HOME must point to a built DynamoRIO source tree" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
client=$("$script_dir/build-client.sh" | tail -n 1)
if [[ -x "$DYNAMORIO_HOME/build/bin64/drrun" ]]; then
  drrun="$DYNAMORIO_HOME/build/bin64/drrun"
else
  drrun="$DYNAMORIO_HOME/install/bin64/drrun"
fi
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
  "$crate_dir/tests/cpuid_probe.c" -o "$tmpdir/cpuid-probe"
"$drrun" -disable_rseq -c "$client" -- "$tmpdir/cpuid-probe" \
  >"$tmpdir/stdout" 2>"$tmpdir/stderr"

grep -Fx 'CPUID-SUCCESS vendor=GenuineIntel signature=00000663' \
  "$tmpdir/stdout"
cat "$tmpdir/stderr"
