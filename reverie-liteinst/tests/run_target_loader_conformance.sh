#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

set -euo pipefail

repository=$(cd "$(dirname "$0")/../.." && pwd -P)
target_dir=${CARGO_TARGET_DIR:-"$repository/target/liteinst-conformance"}
mkdir -p "$target_dir"
target_dir=$(cd "$target_dir" && pwd -P)

if [[ ! -f "$repository/Cargo.lock" ]]; then
  timeout --kill-after=5s 60s cargo generate-lockfile \
    --manifest-path "$repository/Cargo.toml" --offline
fi

timeout --kill-after=5s 180s cargo build \
  --manifest-path "$repository/Cargo.toml" \
  --target-dir "$target_dir" \
  --locked \
  --offline \
  --release \
  --no-default-features \
  --package reverie-liteinst \
  --lib

runtime=$(realpath "$target_dir/release/libreverie_liteinst.so")
digest_line=$(sha256sum -- "$runtime")
digest=${digest_line%% *}
test_log=$(mktemp)
trap 'rm -f "$test_log"' EXIT

set +e
REVERIE_LITEINST_CONFORMANCE_DSO="$runtime" \
REVERIE_LITEINST_CONFORMANCE_SHA256="$digest" \
timeout --kill-after=5s 300s cargo test \
  --manifest-path "$repository/Cargo.toml" \
  --target-dir "$target_dir" \
  --locked \
  --offline \
  --release \
  --no-default-features \
  --package reverie-liteinst \
  --test target_loader_conformance \
  -- \
  real_release_runtime_matches_native_loader_oracles_while_stopped \
  --exact \
  --ignored \
  --test-threads=1 >"$test_log" 2>&1
test_status=$?
set -e
cat "$test_log"
if [[ $test_status -ne 0 ]]; then
  exit "$test_status"
fi

result_count=$(grep -c \
  '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' \
  "$test_log") || result_count=0
if [[ $result_count -ne 1 ]]; then
  echo "target-loader conformance did not run exactly one passing test" >&2
  exit 1
fi
