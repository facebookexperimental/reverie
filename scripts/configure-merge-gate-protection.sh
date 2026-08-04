#!/usr/bin/env bash
# Migrate Reverie's branch protection from the legacy Merge Gate context to a
# versioned, workflow-blob-bound context without an authorization gap.

set -euo pipefail

readonly DEFAULT_REPO="rrnewton/reverie"
readonly BRANCH="main"
readonly GATE_PATH=".github/workflows/merge-gate.yml"
readonly REQUIRED_CONTEXT="merge-gate-v2"
readonly LEGACY_CONTEXT="merge-gate"
readonly EXPECTED_BLOB_VARIABLE="REVERIE_MERGE_GATE_V2_BLOB"
readonly LEGACY_SHIM_VARIABLE="REVERIE_MERGE_GATE_LEGACY_CONTEXT"
readonly GITHUB_ACTIONS_APP_ID=15368

repo=$DEFAULT_REPO
mode=check
prepare_ref=""

usage() {
    cat <<'EOF'
Usage: scripts/configure-merge-gate-protection.sh MODE [options]

Modes:
  --check          Verify v2-only protection, main's bound blob, and shim off.
  --prepare REF    Require legacy + v2, bind REF's blob, and enable the shim.
  --apply          Bind main's blob, require v2 only, and disable the shim.

Options:
  --repo R         Repository (default: rrnewton/reverie).
  -h, --help       Show this help.
EOF
}

while (($# > 0)); do
    case "$1" in
        --check) mode=check; shift ;;
        --prepare) mode=prepare; prepare_ref=${2:?--prepare requires a ref}; shift 2 ;;
        --apply) mode=apply; shift ;;
        --repo) repo=${2:?--repo requires OWNER/NAME}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'configure-merge-gate-protection: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

for command in gh jq sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'configure-merge-gate-protection: required command not found: %s\n' "$command" >&2
        exit 2
    }
done

gh_cmd=(gh)
command -v with-proxy >/dev/null 2>&1 && gh_cmd=(with-proxy gh)

read_variable() {
    "${gh_cmd[@]}" variable get "$1" --repo "$repo" --json value -q .value 2>/dev/null || true
}

set_variable() {
    "${gh_cmd[@]}" variable set "$1" --repo "$repo" --body "$2" >/dev/null
}

gate_blob() {
    "${gh_cmd[@]}" api --method GET "repos/$repo/contents/$GATE_PATH" \
        -f ref="$1" --jq .sha
}

gate_source() {
    "${gh_cmd[@]}" api --method GET "repos/$repo/contents/$GATE_PATH" \
        -f ref="$1" --jq .content | tr -d '\n' | base64 -d
}

read_checks() {
    "${gh_cmd[@]}" api "repos/$repo/branches/$BRANCH/protection/required_status_checks"
}

write_checks() {
    "${gh_cmd[@]}" api --method PATCH \
        "repos/$repo/branches/$BRANCH/protection/required_status_checks" \
        --input - >/dev/null
}

normalized_checks() {
    jq -S '{strict, checks: ((.checks // []) | sort_by(.context, .app_id))}'
}

checks_fingerprint() {
    normalized_checks | sha256sum | cut -d' ' -f1
}

context_count() {
    local context=$1
    jq --arg context "$context" '[.checks[]? | select(.context == $context)] | length'
}

context_app() {
    local context=$1
    jq -r --arg context "$context" \
        '[.checks[]? | select(.context == $context) | .app_id] | if length == 1 then .[0] else empty end'
}

current=$(read_checks)
required_count=$(context_count "$REQUIRED_CONTEXT" <<<"$current")
legacy_count=$(context_count "$LEGACY_CONTEXT" <<<"$current")
required_app=$(context_app "$REQUIRED_CONTEXT" <<<"$current")
legacy_app=$(context_app "$LEGACY_CONTEXT" <<<"$current")

if [[ $mode == prepare ]]; then
    blob=$(gate_blob "$prepare_ref")
    source=$(gate_source "$prepare_ref")
    if ! grep -Fq "name: $REQUIRED_CONTEXT" <<<"$source" ||
       ! grep -Fq "$EXPECTED_BLOB_VARIABLE" <<<"$source"; then
        printf 'configure-merge-gate-protection: %s does not define bound %s\n' \
            "$prepare_ref" "$REQUIRED_CONTEXT" >&2
        exit 1
    fi
    if ! { [[ $legacy_count == 1 && $required_count == 0 &&
              $legacy_app == "$GITHUB_ACTIONS_APP_ID" ]] ||
           [[ $legacy_count == 1 && $required_count == 1 &&
              $legacy_app == "$GITHUB_ACTIONS_APP_ID" &&
              $required_app == "$GITHUB_ACTIONS_APP_ID" ]]; }; then
        printf 'configure-merge-gate-protection: prepare requires legacy-only or overlap; got legacy=%s/%s v2=%s/%s\n' \
            "$legacy_count" "${legacy_app:-unset}" "$required_count" "${required_app:-unset}" >&2
        exit 1
    fi

    desired=$(jq --arg context "$REQUIRED_CONTEXT" --argjson app "$GITHUB_ACTIONS_APP_ID" '
      {strict, checks: (((.checks // []) + [{context: $context, app_id: $app}])
        | unique_by(.context, .app_id))}' <<<"$current")

    set_variable "$LEGACY_SHIM_VARIABLE" true
    latest=$(read_checks)
    if [[ $(checks_fingerprint <<<"$latest") != $(checks_fingerprint <<<"$current") ]]; then
        echo 'configure-merge-gate-protection: protection changed concurrently; refusing stale overlap update' >&2
        exit 1
    fi
    if [[ $(checks_fingerprint <<<"$current") != $(checks_fingerprint <<<"$desired") ]]; then
        write_checks <<<"$desired"
    fi
    set_variable "$EXPECTED_BLOB_VARIABLE" "$blob"

    updated=$(read_checks)
    if [[ $(checks_fingerprint <<<"$updated") != $(checks_fingerprint <<<"$desired") ]] ||
       [[ $(read_variable "$EXPECTED_BLOB_VARIABLE") != "$blob" ]] ||
       [[ $(read_variable "$LEGACY_SHIM_VARIABLE") != true ]]; then
        echo 'configure-merge-gate-protection: overlap transition verification failed' >&2
        exit 1
    fi
    printf 'PREPARED: protection requires %s + %s; %s=%s for %s; legacy shim enabled.\n' \
        "$LEGACY_CONTEXT" "$REQUIRED_CONTEXT" "$EXPECTED_BLOB_VARIABLE" "$blob" "$prepare_ref"
    exit 0
fi

main_blob=$(gate_blob refs/heads/main)
expected_blob=$(read_variable "$EXPECTED_BLOB_VARIABLE")
legacy_shim=$(read_variable "$LEGACY_SHIM_VARIABLE")

if [[ $mode == check ]]; then
    failed=0
    if [[ $required_count != 1 || $legacy_count != 0 ||
          $required_app != "$GITHUB_ACTIONS_APP_ID" ]]; then
        printf 'FAIL: protection has v2=%s/%s and legacy=%s/%s.\n' \
            "$required_count" "${required_app:-unset}" "$legacy_count" "${legacy_app:-unset}" >&2
        failed=1
    fi
    if [[ $expected_blob != "$main_blob" ]]; then
        printf 'FAIL: %s=%s, main workflow blob=%s.\n' \
            "$EXPECTED_BLOB_VARIABLE" "${expected_blob:-unset}" "$main_blob" >&2
        failed=1
    fi
    if [[ $legacy_shim != false ]]; then
        printf 'FAIL: %s=%s, expected false.\n' \
            "$LEGACY_SHIM_VARIABLE" "${legacy_shim:-unset}" >&2
        failed=1
    fi
    ((failed == 0)) || exit 1
    printf 'PASS: protection requires %s; main blob %s is bound; legacy shim disabled.\n' \
        "$REQUIRED_CONTEXT" "$main_blob"
    exit 0
fi

source=$(gate_source refs/heads/main)
if ! grep -Fq "name: $REQUIRED_CONTEXT" <<<"$source" ||
   ! grep -Fq "$EXPECTED_BLOB_VARIABLE" <<<"$source"; then
    echo 'configure-merge-gate-protection: main does not define the bound v2 context' >&2
    exit 1
fi
if ! { [[ $legacy_count == 1 && $required_count == 1 &&
          $legacy_app == "$GITHUB_ACTIONS_APP_ID" &&
          $required_app == "$GITHUB_ACTIONS_APP_ID" ]] ||
       [[ $legacy_count == 0 && $required_count == 1 &&
          $required_app == "$GITHUB_ACTIONS_APP_ID" ]]; }; then
    printf 'configure-merge-gate-protection: apply requires overlap or v2-only; got legacy=%s/%s v2=%s/%s\n' \
        "$legacy_count" "${legacy_app:-unset}" "$required_count" "${required_app:-unset}" >&2
    exit 1
fi

set_variable "$EXPECTED_BLOB_VARIABLE" "$main_blob"
desired=$(jq --arg legacy "$LEGACY_CONTEXT" '
  {strict, checks: [(.checks // [])[] | select(.context != $legacy)]}' <<<"$current")
latest=$(read_checks)
if [[ $(checks_fingerprint <<<"$latest") != $(checks_fingerprint <<<"$current") ]]; then
    echo 'configure-merge-gate-protection: protection changed concurrently; refusing stale v2-only update' >&2
    exit 1
fi
if [[ $(checks_fingerprint <<<"$current") != $(checks_fingerprint <<<"$desired") ]]; then
    write_checks <<<"$desired"
fi
set_variable "$LEGACY_SHIM_VARIABLE" false

updated=$(read_checks)
if [[ $(checks_fingerprint <<<"$updated") != $(checks_fingerprint <<<"$desired") ]] ||
   [[ $(read_variable "$EXPECTED_BLOB_VARIABLE") != "$main_blob" ]] ||
   [[ $(read_variable "$LEGACY_SHIM_VARIABLE") != false ]]; then
    echo 'configure-merge-gate-protection: v2 steady-state verification failed' >&2
    exit 1
fi
printf 'APPLIED: protection requires %s; main blob %s is bound; legacy shim disabled.\n' \
    "$REQUIRED_CONTEXT" "$main_blob"
