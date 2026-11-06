#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Run the workspace test suite one package at a time and write a per-package
# scorecard. This splits validate.sh's "Test regular workspace cases" gate
# per package for attribution; it is not a substitute for that gate:
# per-package feature selection loses workspace feature unification, and
# validate.sh itself builds the LiteInst fixtures and exports their
# variables into the gate (below they only pass through). A green run here
# is weaker evidence than a green validate.sh. Counts come from scripts/libtest-counts.rs
# (the same producer validate.sh trusts), never from grepping cargo's
# output: several test binaries re-invoke themselves per test, so result
# lines in the log do not sum to distinct executed tests.
#
# Usage: scripts/run-percrate-tests.sh [--results DIR] [--no-skip-list]
#                                        [--packages "a b c"]
#   --results DIR     logs, counts and scorecard.tsv (default: target/percrate)
#   --no-skip-list    run the tests validate.sh skips too (they need mount,
#                     namespace, network, or low-port privileges)
#   --packages LIST   space-separated package subset (default: workspace)
#
# Environment: TMPDIR is set to a directory under the results dir when the
# caller did not set one (some fixture tests require a caller-owned TMPDIR).
# REVERIE_REQUIRE_KVM and the LiteInst fixture variables pass through when
# the caller sets them. Bound the run from outside with a service manager
# CPU/memory cap; each package also gets PERCRATE_TIMEOUT seconds (default
# 2400, 0 disables), but GNU timeout signals only its direct child, so an
# outer scope is what reaps a timed-out package's whole process tree.
#
# Exit status: 0 only when every package passed and its counts were read.

set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 2

# Stable feature set; each package gets its own entries from the list.
# shellcheck source=stable-features.sh
source "$ROOT_DIR/scripts/stable-features.sh"

RESULTS="$ROOT_DIR/target/percrate"
SKIP_LIST=1
PACKAGES=

usage() {
    cat <<'EOF'
usage: scripts/run-percrate-tests.sh [--results DIR] [--no-skip-list]
                                       [--packages "a b c"]

  --results DIR     logs, counts and scorecard.tsv (default: target/percrate)
  --no-skip-list    run the tests validate.sh skips too (they need mount,
                    namespace, network, or low-port privileges)
  --packages LIST   space-separated package subset (default: workspace)

Exit status: 0 only when every package passed and its counts were read.
EOF
}

while (($#)); do
    case $1 in
        --results)
            if (($# < 2)); then
                echo "run-percrate-tests.sh: --results needs a directory" >&2
                exit 2
            fi
            RESULTS=$2; shift 2 ;;
        --no-skip-list) SKIP_LIST=0; shift ;;
        --packages)
            if (($# < 2)); then
                echo "run-percrate-tests.sh: --packages needs a list" >&2
                exit 2
            fi
            PACKAGES=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "run-percrate-tests.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

# The same 17 skips as validate.sh REGULAR_TEST_SKIP_ARGS.
SKIP_ARGS=()
if ((SKIP_LIST)); then
    SKIP_ARGS=(
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
fi

mkdir -p "$RESULTS/logs" "$RESULTS/counts" || exit 2
if [[ -z ${TMPDIR:-} ]]; then
    # Unique per run, so concurrent runs never share fixture scratch. It
    # stays under the results dir because tests name it as evidence.
    TMPDIR=$(mktemp -d "$RESULTS/tmp.XXXXXXXX") || exit 2
    export TMPDIR
else
    mkdir -p "$TMPDIR" || exit 2
fi

if [[ -z $PACKAGES ]]; then
    PACKAGES=$(cargo metadata --no-deps --format-version 1 |
        python3 -c 'import json,sys; print(" ".join(sorted(p["name"] for p in json.load(sys.stdin)["packages"])))') || exit 2
fi
read -r -a PACKAGE_LIST <<<"$PACKAGES"
if ((${#PACKAGE_LIST[@]} == 0)); then
    echo "run-percrate-tests.sh: --packages names no packages" >&2
    exit 2
fi
# One row per package: drop repeats, keeping first-seen order.
declare -A SEEN_PACKAGE=()
DEDUPED_PACKAGES=()
for pkg in "${PACKAGE_LIST[@]}"; do
    if [[ -z ${SEEN_PACKAGE[$pkg]:-} ]]; then
        SEEN_PACKAGE[$pkg]=1
        DEDUPED_PACKAGES+=("$pkg")
    fi
done
PACKAGE_LIST=("${DEDUPED_PACKAGES[@]}")

SCORECARD="$RESULTS/scorecard.tsv"
printf 'package\texit\texecuted\tpassed\tfailed\tskipped\tfiltered\twall_s\tuser_s\tsys_s\n' >"$SCORECARD"
failures=0
for pkg in "${PACKAGE_LIST[@]}"; do
    log="$RESULTS/logs/$pkg.log"
    counts="$RESULTS/counts/$pkg.json"
    start=$SECONDS
    timeout_cmd=()
    if [[ ${PERCRATE_TIMEOUT:-2400} != 0 ]]; then
        timeout_cmd=(timeout --signal=TERM --kill-after=30 "${PERCRATE_TIMEOUT:-2400}")
    fi
    pkg_features=()
    for feature in $STABLE_FEATURES; do
        [[ $feature == "$pkg"/* ]] && pkg_features+=("$feature")
    done
    feature_args=()
    ((${#pkg_features[@]})) && feature_args=(--features "${pkg_features[*]}")
    /usr/bin/time -v "${timeout_cmd[@]}" \
        "$ROOT_DIR/scripts/libtest-counts.rs" run "$counts" -- \
        cargo test -p "$pkg" "${feature_args[@]}" --no-fail-fast \
        -- --test-threads=1 "${SKIP_ARGS[@]}" >"$log" 2>&1
    rc=$?
    wall=$((SECONDS - start))
    # Tests report a skipped leg with a REVERIE_SKIP line written past
    # libtest's capture, so it lands in the log. The match is deliberately
    # unanchored: libtest prints `test NAME ... ` with no newline before
    # the test body runs, so the marker can land mid-line. Libtest still
    # counts such a leg as passed; the scorecard moves it to skipped.
    skipped=$(grep -c 'REVERIE_SKIP: ' "$log" || true)
    if read -r executed passed filtered counts_extra < <("$ROOT_DIR/scripts/libtest-counts.rs" read "$counts") &&
        [[ -z ${counts_extra:-} && $skipped -le $passed ]]; then
        failed=$((executed - passed))
        passed=$((passed - skipped))
    else
        # Attributable counts are this script's purpose, so a package whose
        # counts cannot be read (or whose skip lines outnumber its passes)
        # fails even when cargo passed, as in validate.sh's counted gates.
        executed='?'; passed='?'; failed='?'; skipped='?'; filtered='?'
        if ((rc == 0)); then
            rc=2
        fi
        echo "$pkg: counts unreadable or inconsistent ($counts); see $log" >&2
    fi
    user=$(awk '/User time \(seconds\)/{value = $NF} END {print value}' "$log")
    sys=$(awk '/System time \(seconds\)/{value = $NF} END {print value}' "$log")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$pkg" "$rc" "$executed" "$passed" "$failed" "$skipped" "$filtered" "$wall" "${user:-?}" "${sys:-?}" >>"$SCORECARD"
    printf '%s: exit %s, executed %s passed %s failed %s skipped %s filtered %s (%ss)\n' \
        "$pkg" "$rc" "$executed" "$passed" "$failed" "$skipped" "$filtered" "$wall"
    ((rc == 0)) || failures=$((failures + 1))
done

echo "scorecard: $SCORECARD"
((failures == 0))
