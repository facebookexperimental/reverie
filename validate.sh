#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

set -uo pipefail

# CI installs the development package and links with -llzma. Some supported
# hosts provide only the versioned runtime library; rust-lld accepts its absolute
# path and still resolves libunwind-ptrace's transitive xz symbols.
LZMA_LINK_TARGET=-llzma
if [[ $(cc -print-file-name=liblzma.so 2>/dev/null) == liblzma.so ]] &&
    command -v ldconfig >/dev/null 2>&1; then
    lzma_runtime=$(ldconfig -p 2>/dev/null |
        awk '$1 ~ /^liblzma[.]so[.][0-9]+$/ { print $NF; exit }')
    if [[ -n $lzma_runtime && -e $lzma_runtime ]]; then
        LZMA_LINK_TARGET=$lzma_runtime
    fi
fi
readonly LZMA_LINK_TARGET
unset lzma_runtime

export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-D warnings -C link-arg=$LZMA_LINK_TARGET"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }-D warnings"

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR
cd "$ROOT_DIR" || exit 1

LABEL_PR=1
[[ ${VALIDATE_LABEL_PR:-1} == 0 ]] && LABEL_PR=0
PR_NUMBER=${PR_NUMBER:-}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --label-pr) LABEL_PR=1; shift ;;
        --no-label-pr) LABEL_PR=0; shift ;;
        -h|--help)
            echo "Usage: ./validate.sh [--label-pr|--no-label-pr]"
            echo "A green run labels the current PR locally-validated by default."
            exit 0
            ;;
        *)
            echo "validate.sh: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

LOG_FILE=${VALIDATE_LOG_FILE:-}
if [[ -z $LOG_FILE ]]; then
    LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/reverie-validate.XXXXXX.log")"
fi
readonly LOG_FILE
printf "Reverie validation\nRoot: %s\n\n" "$ROOT_DIR" >"$LOG_FILE"

checks=0
failures=0

run_check() {
    local name=$1
    shift
    local started=$SECONDS
    checks=$((checks + 1))

    {
        printf "== %s ==\nCommand:" "$name"
        printf " %q" "$@"
        printf "\n"
    } >>"$LOG_FILE"

    if "$@" >>"$LOG_FILE" 2>&1; then
        printf "PASS: %s (%ss)\n" "$name" "$((SECONDS - started))"
    else
        local status=$?
        failures=$((failures + 1))
        printf "FAIL: %s (exit %s; %ss; log: %s)\n" \
            "$name" "$status" "$((SECONDS - started))" "$LOG_FILE" >&2
    fi
}

readonly LOCALLY_VALIDATED_LABEL=locally-validated

apply_locally_validated_label() {
    local pr=$PR_NUMBER
    local pr_head=""
    local local_head
    local -a gh_cmd=(gh)

    if ! command -v gh >/dev/null 2>&1; then
        echo "WARN: gh CLI not found; skipping $LOCALLY_VALIDATED_LABEL label" >&2
        return 0
    fi
    if command -v with-proxy >/dev/null 2>&1; then
        gh_cmd=(with-proxy gh)
    fi

    if [[ -z $pr ]]; then
        pr="$("${gh_cmd[@]}" pr view --json number -q .number 2>/dev/null)" || true
    fi
    if [[ -z $pr ]]; then
        echo "WARN: no PR found for this branch; skipping $LOCALLY_VALIDATED_LABEL label" >&2
        return 0
    fi
    pr_head=$("${gh_cmd[@]}" pr view "$pr" --json headRefOid -q .headRefOid \
        2>/dev/null) || true
    if [[ -z $pr_head ]]; then
        echo "WARN: could not read PR #$pr head; skipping $LOCALLY_VALIDATED_LABEL label" >&2
        return 0
    fi
    local_head=$(git rev-parse HEAD)
    if [[ $pr_head != "$local_head" ]]; then
        echo "WARN: PR #$pr advanced from $local_head to $pr_head; skipping $LOCALLY_VALIDATED_LABEL label" >&2
        return 0
    fi

    "${gh_cmd[@]}" label create "$LOCALLY_VALIDATED_LABEL" \
        --color 1d76db \
        --description "Full local validation passed for the current PR head" \
        --force >>"$LOG_FILE" 2>&1 || true

    if "${gh_cmd[@]}" pr edit "$pr" --add-label "$LOCALLY_VALIDATED_LABEL" \
        >>"$LOG_FILE" 2>&1; then
        echo "Applied $LOCALLY_VALIDATED_LABEL to PR #$pr"
    else
        echo "WARN: failed to label PR #$pr (log: $LOG_FILE)" >&2
    fi
}

readonly -a REGULAR_TEST_SKIP_ARGS=(
    --skip container::tests::bind_to_low_port
    --skip container::tests::pin_affinity_to_all_cores
    --skip tests::domainname
    --skip tests::hostname
    --skip tests::local_networking_loopback_flags
    --skip tests::local_networking_ping
    --skip tests::local_networking_there_can_be_only_one
    --skip tests::mount_and_move_tmpfs
    --skip tests::mount_bind
    --skip tests::mount_devpts_basic
    --skip tests::mount_devpts_isolated
    --skip tests::mount_proc
    --skip tests::mount_tmpfs
    --skip tests::pid_namespace
    --skip tests::port_isolation
    --skip tests::seccomp_notify
    --skip tests::uid_namespace
)

run_check "Build workspace" cargo build --workspace --all-features
run_check "Test regular workspace cases" cargo test --workspace --all-features \
    -- --test-threads=1 "${REGULAR_TEST_SKIP_ARGS[@]}"
run_check "Documentation tests" cargo test --workspace --doc
run_check "Clippy" cargo clippy --workspace --all-targets --all-features -- -D warnings
run_check "Rustfmt" cargo fmt --all -- --check

passed=$((checks - failures))
if ((failures == 0)); then
    printf "Validation summary: %s passed, 0 failed (log: %s)\n" "$passed" "$LOG_FILE"
    if ((LABEL_PR == 1)); then
        apply_locally_validated_label
    fi
else
    printf "Validation summary: %s passed, %s failed (log: %s)\n" \
        "$passed" "$failures" "$LOG_FILE" >&2
fi

((failures == 0))
