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

grep -Fq 'ref: 4b78d727f35bc8612ac460a6e270dda5f5df304c' "$workflow" ||
    fail "gate must pin the canonical parent authority"
grep -Fq 'python3 .dev-hermit-policy/ci-hub/check_outcome.py' "$workflow" ||
    fail "gate must call the canonical check-status classifier"
grep -Fq -- '--select-latest-run --head-sha "$head_sha"' "$workflow" ||
    fail "gate must select the latest run at the exact PR head"
grep -Fq -- '-f head_sha="$HEAD_SHA"' "$workflow" ||
    fail "workflow-run controller must bind a dispatch to the completed CI head"
grep -Fq 'SHA: ${{ github.sha }}' "$workflow" ||
    fail "gate must observe the SHA where its required context attaches"
grep -Fq 'EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha || inputs.head_sha }}' "$workflow" ||
    fail "gate must carry an explicit expected PR head"
grep -Fq '[ "$EVENT_NAME" = workflow_dispatch ] && [ "$SHA" != "$EXPECTED_HEAD_SHA" ]' "$workflow" ||
    fail "gate must reject a dispatch attached to another head"
grep -Fq '.head.sha == $sha' "$workflow" ||
    fail "gate must bind the PR current head to the attached check SHA"
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

# Cross-PR negative control for the exact jq predicate embedded above.
fixture='{"number":7,"state":"open","base":{"ref":"main"},"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
[[ $(jq --arg sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    '[select(.base.ref == "main" and .state == "open" and .head.sha == $sha)] | length' \
    <<<"$fixture") -eq 1 ]] || fail "positive exact-head fixture was rejected"
[[ $(jq --arg sha bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    '[select(.base.ref == "main" and .state == "open" and .head.sha == $sha)] | length' \
    <<<"$fixture") -eq 0 ]] || fail "cross-PR/head fixture was accepted"

echo "check-merge-gate-policy: PASS - all status consumers use PASSED/FAILED/NO_RESULT"
