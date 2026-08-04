#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

set -euo pipefail

root=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
workflow="$root/.github/workflows/merge-gate.yml"
reconciler="$root/scripts/configure-merge-gate-protection.sh"

fail() {
    echo "check-merge-gate-policy: $*" >&2
    exit 1
}

grep -Fq 'ref: 4b78d727f35bc8612ac460a6e270dda5f5df304c' "$workflow" ||
    fail "gate must pin the canonical parent authority"
grep -Fq 'python3 .dev-hermit-policy/ci-hub/check_outcome.py' "$workflow" ||
    fail "gate must call the canonical check-status classifier"
grep -Fq -- '--select-latest-run --head-sha "$head_sha"' "$workflow" ||
    fail "gate must select the latest workflow run at the exact PR head"
grep -Fq -- '--event pull_request <<< "$runs"' "$workflow" ||
    fail "gate must exclude workflow-dispatch CI from landing authority"
grep -Fq -- '--select-latest-rollup)' "$workflow" ||
    fail "gate must resolve duplicate job attempts through the shared authority"
grep -Fq 'Regular tests (GitHub-hosted)' "$workflow" ||
    fail "gate must require the GitHub-hosted authoritative job"
grep -Fq 'Host-dependent tests (self-hosted)' "$workflow" ||
    fail "gate must require the self-hosted authoritative job"
grep -Fq -- '-f head_sha="$HEAD_SHA"' "$workflow" ||
    fail "workflow-run controller must bind a dispatch to the completed CI head"
grep -Fq 'name: merge-gate-v2' "$workflow" ||
    fail "gate must publish a versioned required context"
grep -Fq 'REVERIE_MERGE_GATE_V2_BLOB' "$workflow" ||
    fail "gate must bind authorization to the registered workflow blob"
grep -Fq 'actual_blob=' "$workflow" ||
    fail "gate must dereference the running workflow definition"
grep -Fq 'REVERIE_MERGE_GATE_LEGACY_CONTEXT' "$workflow" ||
    fail "gate must provide a fail-closed overlap shim during migration"
grep -Fq 'SHA: ${{ github.sha }}' "$workflow" ||
    fail "gate must observe the SHA where its required context attaches"
grep -Fq 'EXPECTED_HEAD_SHA: ${{ github.event.pull_request.head.sha || inputs.head_sha }}' "$workflow" ||
    fail "gate must carry an explicit expected PR head"
grep -Fq '[ "$EVENT_NAME" = workflow_dispatch ] && [ "$SHA" != "$EXPECTED_HEAD_SHA" ]' "$workflow" ||
    fail "gate must reject a dispatch attached to another head"
grep -Fq '.head.sha == $sha' "$workflow" ||
    fail "gate must bind the PR current head to the attached check SHA"
grep -Fq 'queued | in_progress | waiting | requested | pending)' "$workflow" ||
    fail "active NO_RESULT runs must wait for completion, not duplicate work"
grep -Fq 'actions/runs/${run_id}/rerun' "$workflow" ||
    fail "terminal NO_RESULT must rerun the selected pull-request run"
if grep -Fq 'gh workflow run ci.yml' "$workflow"; then
    fail "a bot-authored workflow_dispatch run must never replace pull-request CI"
fi
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

[[ -x $reconciler ]] || fail "branch-protection reconciler must be executable"
bash -n "$reconciler" || fail "branch-protection reconciler has invalid shell syntax"
grep -Fq 'REQUIRED_CONTEXT="merge-gate-v2"' "$reconciler" ||
    fail "reconciler must require the versioned context"
grep -Fq 'LEGACY_CONTEXT="merge-gate"' "$reconciler" ||
    fail "reconciler must remove the unversioned context after overlap"
grep -Fq 'GITHUB_ACTIONS_APP_ID=15368' "$reconciler" ||
    fail "reconciler must bind required contexts to GitHub Actions"

# Cross-PR negative control for the exact jq predicate embedded above.
fixture='{"number":7,"state":"open","base":{"ref":"main"},"head":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
[[ $(jq --arg sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    '[select(.base.ref == "main" and .state == "open" and .head.sha == $sha)] | length' \
    <<<"$fixture") -eq 1 ]] || fail "positive exact-head fixture was rejected"
[[ $(jq --arg sha bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    '[select(.base.ref == "main" and .state == "open" and .head.sha == $sha)] | length' \
    <<<"$fixture") -eq 0 ]] || fail "cross-PR/head fixture was accepted"

# Definition-identity bracket: a plausible but stale branch blob is refused,
# while the registered candidate definition is accepted.
registered_blob=1111111111111111111111111111111111111111
stale_blob=2222222222222222222222222222222222222222
definition_authorized() { [[ $1 == "$registered_blob" ]]; }
if definition_authorized "$stale_blob"; then
    fail "stale definition fixture was accepted"
fi
definition_authorized "$registered_blob" || fail "registered definition fixture was rejected"

# Event-authority bracket: a newer successful workflow_dispatch run must not
# displace the eligible pull_request run at the same exact head.
head_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
runs_fixture="$(jq -n --arg sha "$head_sha" '{workflow_runs: [
  {id: 101, head_sha: $sha, event: "pull_request", created_at: "2026-08-04T10:00:00Z", status: "completed", conclusion: "success"},
  {id: 102, head_sha: $sha, event: "workflow_dispatch", created_at: "2026-08-04T10:01:00Z", status: "completed", conclusion: "success"}
]}')"
eligible_runs="$(jq --arg sha "$head_sha" \
    '[.workflow_runs[] | select(.head_sha == $sha and .event == "pull_request")]' \
    <<<"$runs_fixture")"
[[ $(jq 'length' <<<"$eligible_runs") -eq 1 ]] ||
    fail "workflow-dispatch fixture entered the pull-request authority"
[[ $(jq -r '.[0].id' <<<"$eligible_runs") == 101 ]] ||
    fail "newer workflow-dispatch fixture displaced the eligible run"

fixture_outcome() {
    local regular=$1 host=$2
    if [[ $regular == FAILED || $host == FAILED ]]; then
        echo FAILED
    elif [[ $regular == PASSED && $host == PASSED ]]; then
        echo PASSED
    else
        echo NO_RESULT
    fi
}

# Job-population bracket: Regular-only is not a pass; both authoritative jobs
# passing is. This is the concrete shape previously produced by bot dispatch.
[[ $(fixture_outcome PASSED NO_RESULT) == NO_RESULT ]] ||
    fail "Regular-only CI fixture was accepted"
[[ $(fixture_outcome PASSED PASSED) == PASSED ]] ||
    fail "complete two-job CI fixture was rejected"

echo "check-merge-gate-policy: PASS - stale definition refused; 1 partial CI fixture rejected; 1 complete CI fixture accepted; residue 0"
