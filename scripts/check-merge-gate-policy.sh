#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

set -euo pipefail

root=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
workflow="$root/.github/workflows/merge-gate.yml"

fail() {
    echo "check-merge-gate-policy: $*" >&2
    exit 1
}

grep -Fq 'ref: f9e61247e83bb07c11297541b591606de24a89a8' "$workflow" ||
    fail "gate must pin the canonical parent authority"
grep -Fq 'python3 .dev-hermit-policy/ci-hub/check_outcome.py' "$workflow" ||
    fail "gate must call the canonical check-status classifier"
grep -Fq 'NO_RESULT: re-dispatching ci.yml' "$workflow" ||
    fail "NO_RESULT must re-dispatch CI"
grep -Fq '/force-cancel' "$workflow" ||
    fail "NO_RESULT must cancel the required context instead of exiting red or green"
grep -Fq 'N=2 PASSED, N=4 FAILED, N=11 NO_RESULT' "$workflow" ||
    fail "gate must exercise both sides of the trinary predicate"
if grep -Eq 'if \[ "\$locally_validated" = true \]|any\(.labels.*locally-validated' "$workflow"; then
    fail "a bare locally-validated label must not authorize Reverie landing"
fi
if grep -Fq 'if [ "$status:$conclusion" = completed:success ]' "$workflow"; then
    fail "gate must not force every non-success state into FAILED"
fi

echo "check-merge-gate-policy: PASS - all status consumers use PASSED/FAILED/NO_RESULT"
