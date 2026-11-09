#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
# run-dag.sh — run Reverie's full validation lane as a dagrun DAG.
#
# Each gate is an independently boxed node with explicit dependencies
# and CPU-first limits (ci/dag/validate.json). This launcher only
# resolves the dagrun binary and forwards allowlisted runner controls;
# it never rewrites the graph, the selection, or node commands.
#
# Usage:
#   ci/run-dag.sh [--perf-dir DIR] [--max-cpus N] [--max-mem SIZE] [-v|-q]
#   ci/run-dag.sh --print-dagrun
#
# Environment:
#   DAGRUN_BIN  override the runner executable to use.

set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR

find_dagrun() {
    if [[ -n ${DAGRUN_BIN:-} ]]; then
        if [[ -x $DAGRUN_BIN ]]; then
            printf '%s\n' "$DAGRUN_BIN"
            return 0
        fi
        printf 'run-dag: DAGRUN_BIN=%s is not executable\n' "$DAGRUN_BIN" >&2
        return 1
    fi
    # dev-hermit checkout layout: the parent harness carries a pinned
    # agent-utils dagrun. Walk up like validate.sh does (bounded), so a
    # standalone Reverie checkout stays independent.
    local candidate=$ROOT_DIR
    local reverie_path
    for _ in 0 1 2 3; do
        if [[ -x $candidate/agent-utils/py/bin/dagrun ]]; then
            printf '%s\n' "$candidate/agent-utils/py/bin/dagrun"
            return 0
        fi
        if [[ -f $candidate/.gitmodules ]]; then
            reverie_path=$(git -C "$candidate" config -f .gitmodules \
                --get submodule.reverie.path 2>/dev/null || true)
            if [[ $reverie_path == reverie && -x $candidate/agent-utils/py/bin/dagrun ]]; then
                printf '%s\n' "$candidate/agent-utils/py/bin/dagrun"
                return 0
            fi
        fi
        [[ $candidate != / ]] || break
        candidate=$(dirname -- "$candidate")
    done
    if command -v dagrun >/dev/null 2>&1; then
        command -v dagrun
        return 0
    fi
    return 1
}

if [[ ${1:-} == --print-dagrun ]]; then
    find_dagrun || exit 3
    exit 0
fi

DAGRUN=$(find_dagrun) || {
    echo "run-dag: no dagrun binary found (DAGRUN_BIN, dev-hermit agent-utils, or PATH)" >&2
    exit 3
}
readonly DAGRUN

forward=()
while (($#)); do
    case $1 in
        --perf-dir|--max-cpus|--max-mem|--max-steps)
            forward+=("$1" "${2:?run-dag: $1 needs a value}")
            shift 2
            ;;
        --perf-dir=*|--max-cpus=*|--max-mem=*|--max-steps=*)
            forward+=("$1")
            shift
            ;;
        -v|-q|--verbose|--quiet)
            forward+=("$1")
            shift
            ;;
        *)
            echo "run-dag: refusing non-allowlisted runner argument: $1" >&2
            exit 2
            ;;
    esac
done

cd "$ROOT_DIR" || exit 2
exec "$DAGRUN" run --dag ci/dag/validate.json --labels full \
    --keep-going --planner critical-path "${forward[@]}"
