#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# The cross-backend end-to-end check's one entry point (README.md): build what
# each requested backend needs, refuse by name a backend whose inputs this host
# lacks, and run the comparator over the corpus against the ledger measured for
# this environment. The ledger records each program's first difference, which
# depends on the host's libraries and tools, so without one for this
# environment nothing can be judged: the run fails by name (NO LEDGER) before
# it builds anything, unless --report-only asks for a report. A measurement
# (--write-ledger without --report-only) writes its rows, then fails the same
# way. --report-only-if-no-ledger restores the rule this script had before it
# failed closed: judge where this environment has a ledger, and only report
# where it has none.

set -uo pipefail

usage() {
    cat <<'EOF'
usage: reverie-examples/e2e/run.sh [--backends LIST] [--environment NAME]
                                   [--artifacts DIR] [--report-only]
                                   [--report-only-if-no-ledger]
                                   [--write-ledger FILE]
                                   [--require-compared LIST]

  --backends LIST      comma-separated; default: every first-party backend
                       (ptrace,kvm,liteinst,in-guest-trap)
  --environment NAME   the ledger to judge against, ledgers/NAME.tsv; default:
                       this host's, <os id>-<os version>-glibc<version>
  --artifacts DIR      records and logs; default: target/e2e
  --report-only        report the verdicts without judging them
  --report-only-if-no-ledger
                       judge against the environment's ledger where it has
                       one, exactly as without this option; where it has
                       none, report the verdicts without judging them (NO
                       LEDGER ...: report only) instead of failing
  --write-ledger FILE  also write every verdict other than match as a ledger
                       row, to measure a new environment's ledger
  --require-compared LIST
                       comma-separated backends, each also in --backends, on
                       which every corpus cell must be compared (match or
                       mismatch): a refusal, a failed run or an unstable
                       native baseline fails the run, also with --report-only

Cargo's own environment applies (CARGO_TARGET_DIR, CARGO_NET_OFFLINE, ...).
Exit status: 0 when every verdict is in the ledger and no row is stale, or in
a report-only run (--report-only, or --report-only-if-no-ledger without a
ledger); 1 for an unexpected verdict, a stale row, a
--require-compared gap, or no ledger for the environment (NO LEDGER, also
after a --write-ledger measurement); 2 for a usage or build error.
EOF
}

E2E_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$E2E_DIR/../.." && pwd)"
ALL_BACKENDS=ptrace,kvm,liteinst,in-guest-trap
backends=$ALL_BACKENDS
environment=
artifacts=
report_only=0
report_if_no_ledger=0
report_reason="by request"
write_ledger=
require_compared=

while (($#)); do
    case $1 in
        --backends) backends=${2:?--backends needs a list}; shift 2 ;;
        --environment) environment=${2:?--environment needs a name}; shift 2 ;;
        --artifacts) artifacts=${2:?--artifacts needs a directory}; shift 2 ;;
        --report-only) report_only=1; shift ;;
        --report-only-if-no-ledger) report_if_no_ledger=1; shift ;;
        --write-ledger) write_ledger=${2:?--write-ledger needs a file}; shift 2 ;;
        --require-compared) require_compared=${2:?--require-compared needs a list}; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

# Each backend --require-compared lists must be one --backends requests: a
# coverage rule over a backend that never runs could not be met.
listed=()
if [[ -n $require_compared ]]; then
    # Every item must name a backend. An empty one (a leading, trailing or
    # doubled comma) is a usage error here, before the build, rather than the
    # comparator's after it.
    if [[ $require_compared == ,* || $require_compared == *, || $require_compared == *,,* ]]; then
        printf 'reverie e2e: --require-compared has an empty item: %s\n' "$require_compared" >&2
        exit 2
    fi
    IFS=, read -r -a listed <<<"$require_compared"
    IFS=, read -r -a requested <<<"$backends"
    for backend in "${listed[@]}"; do
        found=0
        for candidate in "${requested[@]}"; do
            [[ $candidate == "$backend" ]] && found=1
        done
        if ((found == 0)); then
            printf 'reverie e2e: --require-compared lists %s, which --backends does not request (%s)\n' \
                "$backend" "$backends" >&2
            exit 2
        fi
    done
fi

if [[ -z $environment ]]; then
    os_id=unknown
    os_version=unknown
    if [[ -r /etc/os-release ]]; then
        # shellcheck source=/dev/null
        os_id=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
        # shellcheck source=/dev/null
        os_version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-unknown}")
    fi
    glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{ print $2 }')
    environment="$os_id-$os_version-glibc${glibc:-unknown}"
fi

target_dir=${CARGO_TARGET_DIR:-$ROOT_DIR/target}
# Keep this script's default-feature build out of the shared workspace
# target: the validation DAG populates that target with $STABLE_FEATURES,
# and both builds would otherwise replace target/debug/deps'
# libreverie_examples.so. The comparator must use this build's binaries.
e2e_target_dir=$target_dir/e2e-cargo
binaries=$e2e_target_dir/debug
artifacts=${artifacts:-$target_dir/e2e}
mkdir -p "$artifacts" || exit 2

say() { printf 'reverie e2e: %s\n' "$*"; }

say "environment $environment; backends requested: $backends"
ledger=$E2E_DIR/ledgers/$environment.tsv
have_ledger=0
if [[ -f $ledger ]]; then
    have_ledger=1
fi
# --report-only-if-no-ledger is the rule this script had before it failed
# closed: judge where this environment has a ledger (no change below), and
# only report where it has none.
if ((report_if_no_ledger == 1 && have_ledger == 0 && report_only == 0)); then
    report_only=1
    report_reason="--report-only-if-no-ledger"
fi
# Without a ledger nothing can be judged: fail by name before the build,
# unless --report-only asked for a report or --write-ledger measures this
# environment (which still fails once its rows are written, below).
if ((have_ledger == 0 && report_only == 0)) && [[ -z $write_ledger ]]; then
    say "NO LEDGER for environment $environment (ledgers/$environment.tsv): nothing judged"
    exit 1
fi
if ! CARGO_TARGET_DIR="$e2e_target_dir" cargo build --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p reverie-examples --lib --bins; then
    say "build failed"
    exit 2
fi

# Keep each requested backend whose inputs this host has, refusing the rest by
# name. A backend whose inputs are present but whose build fails is a failure,
# not a refusal.
run_backends=()
refused=()
IFS=, read -r -a requested <<<"$backends"
for backend in "${requested[@]}"; do
    case $backend in
        ptrace | liteinst | in-guest-trap) run_backends+=("$backend") ;;
        kvm)
            # `<>` would create a missing /dev/kvm as an ordinary file where
            # /dev is writable, so require the character device first.
            if [[ -c /dev/kvm ]] && (exec 9<>/dev/kvm) 2>/dev/null; then
                run_backends+=(kvm)
            else
                refused+=("kvm: /dev/kvm is not a character device this user can open read-write")
            fi
            ;;
        e9patch | dbt | dynamorio | sabre)
            say "backend $backend is owned by its extension repository; use that extension's E2E entry with the explicit core comparator/data inputs"
            exit 2
            ;;
        *) say "unknown backend $backend"; exit 2 ;;
    esac
done
for refusal in "${refused[@]}"; do
    say "REFUSED $refusal"
done
if ((${#run_backends[@]} == 0)); then
    say "no requested backend can run on this host"
    exit 1
fi
# A --require-compared backend this host refused compares no cell: a
# coverage gap, by name.
gaps=0
for backend in "${listed[@]}"; do
    case " ${run_backends[*]} " in
        *" $backend "*) ;;
        *)
            say "COVERAGE $backend: refused on this host, so no corpus cell is compared"
            gaps=1
            ;;
    esac
done
if ((gaps == 1)); then
    exit 1
fi

compare=(
    "$binaries/reverie-e2e-compare"
    --recorder "$binaries/recorder"
    --backends "$(IFS=,; printf '%s' "${run_backends[*]}")"
    --corpus "$E2E_DIR/corpus.tsv"
    --artifacts "$artifacts"
)
if [[ -n $write_ledger ]]; then
    compare+=(--write-ledger "$write_ledger")
fi
if [[ -n $require_compared ]]; then
    compare+=(--require-compared "$require_compared")
fi
measuring=0
if ((report_only == 1)); then
    if ((have_ledger == 1)); then
        say "report only, by request: ledgers/$environment.tsv is not judged"
    else
        say "NO LEDGER for environment $environment (ledgers/$environment.tsv): report only, $report_reason"
    fi
    compare+=(--report-only)
elif ((have_ledger == 1)); then
    say "judging against ledgers/$environment.tsv"
    compare+=(--expected "$ledger")
else
    say "NO LEDGER for environment $environment (ledgers/$environment.tsv): measuring for --write-ledger"
    compare+=(--report-only)
    measuring=1
fi
cd "$ROOT_DIR" || exit 2
"${compare[@]}"
status=$?
if ((measuring == 1)); then
    say "NO LEDGER for environment $environment (ledgers/$environment.tsv): nothing judged"
    # A clean measurement is still not a pass; the comparator's own failures
    # (a coverage gap, a usage error, a crash) keep their status.
    if ((status == 0)); then
        exit 1
    fi
fi
exit "$status"
