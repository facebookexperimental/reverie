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

# Find the dev-hermit wrapper without making it a prerequisite. A canonical
# nested slot is three directories below the parent; bounding the walk keeps a
# standalone Reverie checkout independent of unrelated ancestors.
find_dev_hermit_parent() {
    local candidate=$ROOT_DIR
    local reverie_path

    for _ in 0 1 2 3; do
        if [[ -f $candidate/.gitmodules ]]; then
            reverie_path=$(git -C "$candidate" config -f .gitmodules \
                --get submodule.reverie.path 2>/dev/null || true)
            if [[ $reverie_path == reverie ]]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        fi
        [[ $candidate != / ]] || break
        candidate=$(dirname -- "$candidate")
    done
    return 1
}

validation_slot_name() {
    local parent=$1
    local relative

    if [[ -z $parent ]]; then
        printf 'standalone\n'
        return
    fi
    relative=${ROOT_DIR#"$parent"/}
    case "$relative" in
        reverie) printf 'primary\n' ;;
        worktrees/*/reverie)
            relative=${relative#worktrees/}
            printf '%s\n' "${relative%%/*}"
            ;;
        *) printf 'standalone\n' ;;
    esac
}

LABEL_PR=1
[[ ${VALIDATE_LABEL_PR:-1} == 0 ]] && LABEL_PR=0
PR_NUMBER=${PR_NUMBER:-}
SELF_TEST_GATE_COUNTS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --label-pr) LABEL_PR=1; shift ;;
        --no-label-pr) LABEL_PR=0; shift ;;
        --self-test-gate-counts) SELF_TEST_GATE_COUNTS=1; shift ;;
        -h|--help)
            echo "Usage: ./validate.sh [--label-pr|--no-label-pr] [--self-test-gate-counts]"
            echo "A green exact-head run writes a receipt; the optional PR label is derived cache."
            echo "  -h, --help                 Show this help"
            echo "  --self-test-gate-counts    Exercise structured test-count evidence without validation"
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
declare -a ledger_gate_names=()
declare -a ledger_gate_statuses=()
declare -a ledger_gate_durations=()
declare -a ledger_gate_executed_tests=()
declare -a ledger_gate_passed_tests=()
declare -a ledger_gate_filtered_tests=()

VALIDATION_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VALIDATION_STARTED_EPOCH=$(date +%s)
VALIDATION_HOST=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf unknown)
DEV_HERMIT_PARENT=$(find_dev_hermit_parent || true)
VALIDATION_SLOT=$(validation_slot_name "$DEV_HERMIT_PARENT")
if [[ -n $DEV_HERMIT_PARENT ]]; then
    VALIDATION_LEDGER_TOOL="$DEV_HERMIT_PARENT/ci-hub/ledger/validate_rows.py"
else
    VALIDATION_LEDGER_TOOL="${HOME:?HOME is required}/work/dev-hermit/ci-hub/ledger/validate_rows.py"
fi
VALIDATION_COMMIT=$(git rev-parse HEAD 2>/dev/null || printf unknown)
VALIDATION_GIT_DEPTH=$(git rev-list --count HEAD 2>/dev/null || printf 0)
VALIDATION_GIT_AHEAD=0
VALIDATION_GIT_BEHIND=0
if git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null; then
    read -r VALIDATION_GIT_BEHIND VALIDATION_GIT_AHEAD < <(
        git rev-list --left-right --count origin/main...HEAD 2>/dev/null || printf '0 0\n'
    )
fi
if [[ -n $(git status --porcelain 2>/dev/null || printf '') ]]; then
    VALIDATION_TREE_DIRTY=1
else
    VALIDATION_TREE_DIRTY=0
fi
if [[ $VALIDATION_COMMIT != unknown ]] && ((VALIDATION_TREE_DIRTY == 0)); then
    VALIDATION_COMMIT_ANCHORED=1
else
    VALIDATION_COMMIT_ANCHORED=0
fi
if [[ -d $ROOT_DIR/target/debug/deps ]]; then
    VALIDATION_CACHE_STATE=warm
else
    VALIDATION_CACHE_STATE=cold
fi
VALIDATION_CPU_TIMES_FILE=$(mktemp "${TMPDIR:-/tmp}/reverie-validate-cpu.XXXXXX")
readonly VALIDATION_STARTED_AT VALIDATION_STARTED_EPOCH VALIDATION_HOST
readonly DEV_HERMIT_PARENT VALIDATION_SLOT VALIDATION_LEDGER_TOOL
readonly VALIDATION_COMMIT VALIDATION_GIT_DEPTH VALIDATION_GIT_AHEAD
readonly VALIDATION_GIT_BEHIND VALIDATION_TREE_DIRTY VALIDATION_COMMIT_ANCHORED
readonly VALIDATION_CACHE_STATE VALIDATION_CPU_TIMES_FILE
VALIDATION_TEST_COUNTS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/reverie-test-counts.XXXXXX")
readonly VALIDATION_TEST_COUNTS_DIR
readonly LIBTEST_COUNTS_TOOL="$ROOT_DIR/scripts/libtest-counts.rs"
readonly MAX_LEDGER_TEST_COUNT=9223372036854775807

record_ledger_gate() {
    ledger_gate_names+=("$1")
    ledger_gate_statuses+=("$2")
    ledger_gate_durations+=("$3")
    ledger_gate_executed_tests+=("$4")
    ledger_gate_passed_tests+=("$5")
    ledger_gate_filtered_tests+=("$6")
}

json_quote() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '"%s"' "$value"
}

ledger_gates_json() {
    local gates_json='[' gate_result i
    for i in "${!ledger_gate_names[@]}"; do
        ((i == 0)) || gates_json+=','
        if ((ledger_gate_statuses[i] == 0)); then
            gate_result=pass
        else
            gate_result=fail
        fi
        gates_json+="{\"name\":$(json_quote "${ledger_gate_names[i]}"),"
        gates_json+="\"result\":\"$gate_result\","
        gates_json+="\"exit_code\":${ledger_gate_statuses[i]},"
        gates_json+="\"real_seconds\":${ledger_gate_durations[i]}"
        if [[ ${ledger_gate_executed_tests[i]} != null ]]; then
            gates_json+=",\"executed_tests\":${ledger_gate_executed_tests[i]}"
            gates_json+=",\"passed_tests\":${ledger_gate_passed_tests[i]}"
            gates_json+=",\"filtered_tests\":${ledger_gate_filtered_tests[i]}"
        fi
        gates_json+='}'
    done
    gates_json+=']'
    printf '%s\n' "$gates_json"
}

append_validation_ledger() {
    local exit_status=$1
    local wall_seconds=$2 cpu_user=$3 cpu_sys=$4
    local finished_at result gates_json line
    local commit_anchored_json tree_dirty_json
    local executed_tests passed_tests filtered_tests

    read -r executed_tests passed_tests filtered_tests < <(aggregate_test_counts)

    finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if ((exit_status == 0 && failures == 0)) &&
        [[ $executed_tests != null && $passed_tests != null ]] &&
        ((executed_tests > 0 && passed_tests == executed_tests)); then
        result=pass
    else
        result=fail
    fi

    gates_json=$(ledger_gates_json)

    if ((VALIDATION_COMMIT_ANCHORED == 1)); then commit_anchored_json=true; else commit_anchored_json=false; fi
    if ((VALIDATION_TREE_DIRTY == 1)); then tree_dirty_json=true; else tree_dirty_json=false; fi

    # `producer` names the writer that emitted this row, so receipt provenance is
    # a recorded fact rather than forensics inferred from `repo`/`cwd`. The slug
    # is repo-qualified because both hermit and reverie ship a `validate.sh` and
    # a bare name could not distinguish them. It must stay registered in the
    # parent's qualifying-receipt `producer.known` list; an unregistered value is
    # REFUSED once `applies_from_finished_at` is set, which is exactly the drift
    # this field exists to make visible.
    line="{\"schema_version\":4,\"producer\":\"reverie-validate-sh\",\"repo\":\"reverie\","
    line+="\"started_at\":$(json_quote "$VALIDATION_STARTED_AT"),"
    line+="\"finished_at\":$(json_quote "$finished_at"),\"host\":$(json_quote "$VALIDATION_HOST"),"
    line+="\"slot\":$(json_quote "$VALIDATION_SLOT"),\"cwd\":$(json_quote "$ROOT_DIR"),"
    line+="\"profile\":\"full\",\"selection_mode\":\"full\",\"full_coverage\":true,"
    line+="\"cache_state\":$(json_quote "$VALIDATION_CACHE_STATE"),"
    line+="\"commit\":$(json_quote "$VALIDATION_COMMIT"),\"git_depth\":$VALIDATION_GIT_DEPTH,"
    line+="\"git_ahead\":$VALIDATION_GIT_AHEAD,\"git_behind\":$VALIDATION_GIT_BEHIND,"
    line+="\"commit_anchored\":$commit_anchored_json,\"tree_dirty\":$tree_dirty_json,"
    line+="\"result\":\"$result\",\"exit_code\":$exit_status,"
    line+="\"executed_tests\":$executed_tests,\"passed_tests\":$passed_tests,"
    line+="\"filtered_tests\":$filtered_tests,"
    line+="\"checks\":$checks,\"failures\":$failures,"
    line+="\"real_seconds\":$wall_seconds,\"user_seconds\":$cpu_user,\"sys_seconds\":$cpu_sys,"
    line+="\"log_file\":$(json_quote "$LOG_FILE"),\"gates\":$gates_json}"

    if [[ ! -r $VALIDATION_LEDGER_TOOL ]]; then
        printf 'WARN: canonical validation ledger writer is unavailable at %s\n' \
            "$VALIDATION_LEDGER_TOOL" >&2
    elif ! printf '%s\n' "$line" | python3 "$VALIDATION_LEDGER_TOOL" record >/dev/null; then
        printf 'WARN: canonical validation ledger writer refused the row\n' >&2
    fi
}

cleanup() {
    local exit_status=$?
    local finished_epoch validation_wall validation_user=0 validation_sys=0

    trap - EXIT
    finished_epoch=$(date +%s)
    validation_wall=$((finished_epoch - VALIDATION_STARTED_EPOCH))
    if times >"$VALIDATION_CPU_TIMES_FILE" 2>/dev/null; then
        read -r validation_user validation_sys < <(
            awk '
                function seconds(value, parts) {
                    split(value, parts, "m")
                    sub(/s$/, "", parts[2])
                    return parts[1] * 60 + parts[2]
                }
                NR == 1 { user += seconds($1); sys += seconds($2) }
                NR == 2 { user += seconds($1); sys += seconds($2) }
                END { printf "%.3f %.3f\n", user, sys }
            ' "$VALIDATION_CPU_TIMES_FILE"
        )
    fi
    append_validation_ledger "$exit_status" \
        "$validation_wall" "$validation_user" "$validation_sys"
    rm -f "$VALIDATION_CPU_TIMES_FILE"
    rm -r -- "$VALIDATION_TEST_COUNTS_DIR"
    exit "$exit_status"
}

interrupted() {
    trap - INT TERM
    printf 'Validation interrupted (log: %s)\n' "$LOG_FILE" >&2
    exit 130
}

is_supported_test_count() {
    local value=$1
    [[ $value =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    if ((${#value} < ${#MAX_LEDGER_TEST_COUNT})); then
        return 0
    fi
    if ((${#value} > ${#MAX_LEDGER_TEST_COUNT})); then
        return 1
    fi
    ((value >= 0))
}

checked_add_test_count() {
    local left=$1 right=$2
    ((right <= MAX_LEDGER_TEST_COUNT - left)) || return 1
    printf '%s\n' "$((left + right))"
}

run_check_impl() {
    local name=$1 counts_file=$2
    shift 2
    local started=$SECONDS
    local counts counts_extra gate_executed=null gate_passed=null gate_filtered=null
    checks=$((checks + 1))

    {
        printf "== %s ==\nCommand:" "$name"
        printf " %q" "$@"
        printf "\n"
    } >>"$LOG_FILE"
    local status=0
    if "$@" >>"$LOG_FILE" 2>&1; then
        :
    else
        status=$?
    fi
    if [[ -n $counts_file ]]; then
        if counts=$("$LIBTEST_COUNTS_TOOL" read "$counts_file" 2>>"$LOG_FILE") &&
            read -r gate_executed gate_passed gate_filtered counts_extra <<<"$counts" &&
            [[ -z $counts_extra ]] &&
            is_supported_test_count "$gate_executed" &&
            is_supported_test_count "$gate_passed" &&
            is_supported_test_count "$gate_filtered"; then
            if ((status == 0 && gate_passed != gate_executed)); then
                printf 'count evidence refused: passing gate recorded %s passed of %s executed tests; rerun the counted test command\n' \
                    "$gate_passed" "$gate_executed" >>"$LOG_FILE"
                status=2
            fi
        else
            gate_executed=null
            gate_passed=null
            gate_filtered=null
            if ((status == 0)); then
                status=2
            fi
        fi
    fi
    if ((status == 0)); then
        printf "PASS: %s (%ss)\n" "$name" "$((SECONDS - started))"
    else
        failures=$((failures + 1))
        printf "FAIL: %s (exit %s; %ss; log: %s)\n" \
            "$name" "$status" "$((SECONDS - started))" "$LOG_FILE" >&2
    fi
    record_ledger_gate \
        "$name" "$status" "$((SECONDS - started))" \
        "$gate_executed" "$gate_passed" "$gate_filtered"
}

aggregate_test_counts() {
    local executed=0 passed=0 filtered=0 i next
    for i in "${!ledger_gate_names[@]}"; do
        case "${ledger_gate_names[i]}" in
            "Test regular workspace cases"|"Documentation tests")
                if [[ ${ledger_gate_executed_tests[i]} == null ||
                    ${ledger_gate_passed_tests[i]} == null ||
                    ${ledger_gate_filtered_tests[i]} == null ]]; then
                    printf 'null null null\n'
                    return
                fi
                if ! is_supported_test_count "${ledger_gate_executed_tests[i]}" ||
                    ! is_supported_test_count "${ledger_gate_passed_tests[i]}" ||
                    ! is_supported_test_count "${ledger_gate_filtered_tests[i]}"; then
                    printf 'test-count aggregation refused: gate %s has a count outside the nonnegative signed-64-bit range\n' \
                        "${ledger_gate_names[i]}" >>"$LOG_FILE"
                    printf 'null null null\n'
                    return
                fi
                if ! next=$(checked_add_test_count \
                    "$executed" "${ledger_gate_executed_tests[i]}"); then
                    printf 'test-count aggregation refused: executed_tests sum exceeds the signed-64-bit range\n' \
                        >>"$LOG_FILE"
                    printf 'null null null\n'
                    return
                fi
                executed=$next
                if ! next=$(checked_add_test_count \
                    "$passed" "${ledger_gate_passed_tests[i]}"); then
                    printf 'test-count aggregation refused: passed_tests sum exceeds the signed-64-bit range\n' \
                        >>"$LOG_FILE"
                    printf 'null null null\n'
                    return
                fi
                passed=$next
                if ! next=$(checked_add_test_count \
                    "$filtered" "${ledger_gate_filtered_tests[i]}"); then
                    printf 'test-count aggregation refused: filtered_tests sum exceeds the signed-64-bit range\n' \
                        >>"$LOG_FILE"
                    printf 'null null null\n'
                    return
                fi
                filtered=$next
                ;;
        esac
    done
    printf '%s %s %s\n' "$executed" "$passed" "$filtered"
}

aggregate_test_counts_are_passing() {
    local counts executed passed filtered extra
    counts=$(aggregate_test_counts)
    read -r executed passed filtered extra <<<"$counts"
    [[ -z $extra ]] || return 1
    is_supported_test_count "$executed" || return 1
    is_supported_test_count "$passed" || return 1
    is_supported_test_count "$filtered" || return 1
    ((executed > 0 && passed == executed))
}

run_check() {
    local name=$1
    shift
    run_check_impl "$name" "" "$@"
}

run_test_check() {
    local name=$1
    shift
    local counts_file="$VALIDATION_TEST_COUNTS_DIR/${#ledger_gate_names[@]}.json"
    run_check_impl "$name" "$counts_file" \
        "$LIBTEST_COUNTS_TOOL" run "$counts_file" -- "$@"
}

build_workspace_with_loader_conformance() {
    printf 'Required substep: Build workspace\nCommand: cargo build --workspace --all-features\n'
    if cargo build --workspace --all-features; then
        :
    else
        return "$?"
    fi

    # The real release artifact is intentionally ignored by the all-features
    # test harness. Its runner binds the DSO and requires exactly one test.
    printf 'Required substep: LiteInst real target-loader conformance\nCommand:'
    printf ' %q' env "CARGO_TARGET_DIR=$ROOT_DIR/target/liteinst-conformance" \
        "$ROOT_DIR/reverie-liteinst/tests/run_target_loader_conformance.sh"
    printf '\n'
    env CARGO_TARGET_DIR="$ROOT_DIR/target/liteinst-conformance" \
        "$ROOT_DIR/reverie-liteinst/tests/run_target_loader_conformance.sh"
}

if ((SELF_TEST_GATE_COUNTS == 1)); then
    set -e
    reset_self_test_gates() {
        ledger_gate_names=()
        ledger_gate_statuses=()
        ledger_gate_durations=()
        ledger_gate_executed_tests=()
        ledger_gate_passed_tests=()
        ledger_gate_filtered_tests=()
    }
    expect_count_refusal() {
        local counts_file=$1
        reset_self_test_gates
        run_check_impl "Test regular workspace cases" "$counts_file" true
        [[ ${ledger_gate_statuses[0]} == 2 ]]
        [[ ${ledger_gate_executed_tests[0]} == null ]]
        [[ ${ledger_gate_passed_tests[0]} == null ]]
        [[ ${ledger_gate_filtered_tests[0]} == null ]]
        local record
        record=$(ledger_gates_json)
        [[ $record != *'"executed_tests"'* ]]
        [[ $record != *'"passed_tests"'* ]]
        [[ $record != *'"filtered_tests"'* ]]
        if aggregate_test_counts_are_passing; then
            printf 'self-test accepted refused count evidence from %s\n' "$counts_file" >&2
            exit 1
        fi
        grep -Fq 'rerun the counted test command' "$LOG_FILE"
    }
    expect_aggregate_refusal() {
        local aggregate executed passed filtered
        aggregate=$(aggregate_test_counts)
        read -r executed passed filtered <<<"$aggregate"
        [[ $executed == null && $passed == null && $filtered == null ]]
        if aggregate_test_counts_are_passing; then
            printf 'self-test accepted overflowing aggregate test counts\n' >&2
            exit 1
        fi
    }

    fixed_output='test result: ok. 999 passed; 0 failed; 0 ignored; 0 measured; 999 filtered out;'
    first_counts="$VALIDATION_TEST_COUNTS_DIR/first.json"
    second_counts="$VALIDATION_TEST_COUNTS_DIR/second.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":2,"filtered_tests":3}' \
        >"$first_counts"
    printf '%s\n' "$fixed_output" >>"$LOG_FILE"
    run_check_impl "Test regular workspace cases" "$first_counts" true
    [[ ${ledger_gate_executed_tests[0]} == 2 ]]
    [[ ${ledger_gate_passed_tests[0]} == 2 ]]
    [[ ${ledger_gate_filtered_tests[0]} == 3 ]]
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":5,"passed_tests":5,"filtered_tests":1}' \
        >"$second_counts"
    printf '%s\n' "$fixed_output" >>"$LOG_FILE"
    run_check_impl "Documentation tests" "$second_counts" true
    [[ ${ledger_gate_executed_tests[1]} == 5 ]]
    [[ ${ledger_gate_passed_tests[1]} == 5 ]]
    [[ ${ledger_gate_filtered_tests[1]} == 1 ]]
    positive_record=$(ledger_gates_json)
    [[ $positive_record == *'"executed_tests":2,"passed_tests":2,"filtered_tests":3'* ]]
    [[ $positive_record == *'"executed_tests":5,"passed_tests":5,"filtered_tests":1'* ]]
    read -r total_executed total_passed total_filtered < <(aggregate_test_counts)
    [[ $total_executed == 7 && $total_passed == 7 && $total_filtered == 4 ]]
    aggregate_test_counts_are_passing

    mixed_fixture="$VALIDATION_TEST_COUNTS_DIR/mixed-fixture"
    mixed_counts="$VALIDATION_TEST_COUNTS_DIR/mixed.json"
    mkdir -p "$mixed_fixture/fails-first/src" "$mixed_fixture/passes-second/src"
    printf '%s\n' \
        '[workspace]' \
        'members = ["fails-first", "passes-second"]' \
        'resolver = "2"' >"$mixed_fixture/Cargo.toml"
    printf '%s\n' \
        '[package]' \
        'name = "aaa-libtest-counts-fails"' \
        'version = "0.0.0"' \
        'edition = "2021"' >"$mixed_fixture/fails-first/Cargo.toml"
    printf '%s\n' \
        '#[cfg(test)]' \
        'mod tests {' \
        '    #[test]' \
        '    fn fails() {' \
        '        panic!("intentional count-fixture failure");' \
        '    }' \
        '}' >"$mixed_fixture/fails-first/src/lib.rs"
    printf '%s\n' \
        '[package]' \
        'name = "zzz-libtest-counts-passes"' \
        'version = "0.0.0"' \
        'edition = "2021"' >"$mixed_fixture/passes-second/Cargo.toml"
    printf '%s\n' \
        '#[cfg(test)]' \
        'mod tests {' \
        '    #[test]' \
        '    fn passes() {}' \
        '}' >"$mixed_fixture/passes-second/src/lib.rs"
    reset_self_test_gates
    run_check_impl "Test regular workspace cases" "$mixed_counts" \
        "$LIBTEST_COUNTS_TOOL" run "$mixed_counts" -- \
        cargo test --workspace --manifest-path "$mixed_fixture/Cargo.toml"
    [[ ${ledger_gate_statuses[0]} == 101 ]]
    [[ ${ledger_gate_executed_tests[0]} == 2 ]]
    [[ ${ledger_gate_passed_tests[0]} == 1 ]]
    [[ ${ledger_gate_filtered_tests[0]} == 0 ]]
    mixed_record=$(ledger_gates_json)
    [[ $mixed_record == *'"result":"fail"'* ]]
    [[ $mixed_record == *'"executed_tests":2,"passed_tests":1,"filtered_tests":0'* ]]
    if aggregate_test_counts_are_passing; then
        printf 'self-test treated a failed mixed test gate as passing\n' >&2
        exit 1
    fi

    expect_count_refusal "$VALIDATION_TEST_COUNTS_DIR/missing.json"

    missing_passed="$VALIDATION_TEST_COUNTS_DIR/missing-passed.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"filtered_tests":3}' \
        >"$missing_passed"
    expect_count_refusal "$missing_passed"
    grep -Fq "missing field \`passed_tests\`" "$LOG_FILE"

    typed_executed="$VALIDATION_TEST_COUNTS_DIR/typed-executed.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":"2","passed_tests":2,"filtered_tests":3}' \
        >"$typed_executed"
    expect_count_refusal "$typed_executed"

    typed_filtered="$VALIDATION_TEST_COUNTS_DIR/typed-filtered.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":2,"filtered_tests":"3"}' \
        >"$typed_filtered"
    expect_count_refusal "$typed_filtered"

    null_passed="$VALIDATION_TEST_COUNTS_DIR/null-passed.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":null,"filtered_tests":3}' \
        >"$null_passed"
    expect_count_refusal "$null_passed"

    typed_passed="$VALIDATION_TEST_COUNTS_DIR/typed-passed.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":"2","filtered_tests":3}' \
        >"$typed_passed"
    expect_count_refusal "$typed_passed"

    negative_passed="$VALIDATION_TEST_COUNTS_DIR/negative-passed.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":-1,"filtered_tests":3}' \
        >"$negative_passed"
    expect_count_refusal "$negative_passed"

    excessive_passed="$VALIDATION_TEST_COUNTS_DIR/excessive-passed.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":3,"filtered_tests":3}' \
        >"$excessive_passed"
    expect_count_refusal "$excessive_passed"
    grep -Fq 'passed_tests 3 exceeds executed_tests 2' "$LOG_FILE"

    max_u64_counts="$VALIDATION_TEST_COUNTS_DIR/max-u64.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":18446744073709551615,"passed_tests":18446744073709551615,"filtered_tests":0}' \
        >"$max_u64_counts"
    expect_count_refusal "$max_u64_counts"
    grep -Fq "exceeds the validation ledger's supported maximum" "$LOG_FILE"

    mismatch_counts="$VALIDATION_TEST_COUNTS_DIR/mismatch.json"
    printf '%s\n' \
        '{"schema_version":2,"executed_tests":2,"passed_tests":1,"filtered_tests":3}' \
        >"$mismatch_counts"
    reset_self_test_gates
    run_check_impl "Test regular workspace cases" "$mismatch_counts" true
    [[ ${ledger_gate_statuses[0]} == 2 ]]
    [[ ${ledger_gate_executed_tests[0]} == 2 ]]
    [[ ${ledger_gate_passed_tests[0]} == 1 ]]
    [[ ${ledger_gate_filtered_tests[0]} == 3 ]]
    mismatch_record=$(ledger_gates_json)
    [[ $mismatch_record == *'"result":"fail"'* ]]
    [[ $mismatch_record == *'"executed_tests":2,"passed_tests":1,"filtered_tests":3'* ]]
    if aggregate_test_counts_are_passing; then
        printf 'self-test accepted passed_tests != executed_tests for a passing command\n' >&2
        exit 1
    fi

    legacy_counts="$VALIDATION_TEST_COUNTS_DIR/legacy.json"
    printf '%s\n' \
        '{"schema_version":1,"executed_tests":2,"filtered_tests":3}' \
        >"$legacy_counts"
    expect_count_refusal "$legacy_counts"
    grep -Fq 'schema 1 has no authoritative passed_tests' "$LOG_FILE"

    duplicate_counts="$VALIDATION_TEST_COUNTS_DIR/duplicate.json"
    for duplicate_json in \
        '{"schema_version":2,"executed_tests":2,"passed_tests":1,"filtered_tests":0,"executed_tests":1}' \
        '{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"executed_tests":1}' \
        '{"schema_version":2,"executed_tests":1,"passed_tests":0,"filtered_tests":0,"passed_tests":1}' \
        '{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"passed_tests":1}' \
        '{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":3,"filtered_tests":0}' \
        '{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"filtered_tests":0}' \
        '{"schema_version":1,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"schema_version":2}' \
        '{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"schema_version":2}'; do
        printf '%s\n' "$duplicate_json" >"$duplicate_counts"
        expect_count_refusal "$duplicate_counts"
    done

    reset_self_test_gates
    record_ledger_gate "Test regular workspace cases" 1 0 \
        "$MAX_LEDGER_TEST_COUNT" 0 0
    record_ledger_gate "Documentation tests" 1 0 2 0 0
    expect_aggregate_refusal
    grep -Fq 'executed_tests sum exceeds the signed-64-bit range' "$LOG_FILE"

    reset_self_test_gates
    record_ledger_gate "Test regular workspace cases" 1 0 \
        0 "$MAX_LEDGER_TEST_COUNT" 0
    record_ledger_gate "Documentation tests" 1 0 0 2 0
    expect_aggregate_refusal
    grep -Fq 'passed_tests sum exceeds the signed-64-bit range' "$LOG_FILE"

    reset_self_test_gates
    record_ledger_gate "Test regular workspace cases" 1 0 \
        0 0 "$MAX_LEDGER_TEST_COUNT"
    record_ledger_gate "Documentation tests" 1 0 0 0 2
    expect_aggregate_refusal
    grep -Fq 'filtered_tests sum exceeds the signed-64-bit range' "$LOG_FILE"

    reset_self_test_gates
    record_ledger_gate "Test regular workspace cases" 1 0 \
        18446744073709551615 18446744073709551615 0
    record_ledger_gate "Documentation tests" 1 0 2 2 0
    expect_aggregate_refusal
    grep -Fq 'outside the nonnegative signed-64-bit range' "$LOG_FILE"

    "$LIBTEST_COUNTS_TOOL" -h >/dev/null
    "$LIBTEST_COUNTS_TOOL" --help >/dev/null
    "$LIBTEST_COUNTS_TOOL" run -h >/dev/null
    "$LIBTEST_COUNTS_TOOL" run --help >/dev/null
    "$LIBTEST_COUNTS_TOOL" read -h >/dev/null
    "$LIBTEST_COUNTS_TOOL" read --help >/dev/null
    "$ROOT_DIR/validate.sh" -h >/dev/null
    "$ROOT_DIR/validate.sh" --help >/dev/null
    "$LIBTEST_COUNTS_TOOL" --self-test || exit 1
    printf 'PASS: typed executed/passed/filtered counts drive gate and aggregate records\n'
    rm -f "$VALIDATION_CPU_TIMES_FILE"
    rm -r -- "$VALIDATION_TEST_COUNTS_DIR"
    exit 0
fi

trap cleanup EXIT
trap interrupted INT TERM

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

run_check "Cross-client skill discovery" "$ROOT_DIR/scripts/check-skill-discovery.rs"
run_check "Build workspace" build_workspace_with_loader_conformance
run_check "DBT virtual identity and pidfd_open policy" \
    "$ROOT_DIR/reverie-dbt/scripts/test-identity-policy.sh"
run_test_check "Test regular workspace cases" cargo test --workspace --all-features \
    -- --test-threads=1 "${REGULAR_TEST_SKIP_ARGS[@]}"
run_test_check "Documentation tests" cargo test --workspace --doc
run_check "Clippy" cargo clippy --workspace --all-targets --all-features -- -D warnings
run_check "Rustfmt" cargo fmt --all -- --check

if ((failures == 0)) && ! aggregate_test_counts_are_passing; then
    failures=$((failures + 1))
    printf 'FAIL: aggregate test-count evidence is missing, empty, or passed_tests != executed_tests (log: %s)\n' \
        "$LOG_FILE" >&2
fi

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
