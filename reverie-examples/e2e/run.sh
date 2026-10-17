#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# The cross-backend end-to-end check's one entry point (README.md): build what
# each requested backend needs, refuse by name a backend whose inputs this host
# lacks, and run the comparator over the corpus against the ledger measured for
# this environment. Without such a ledger the verdicts are reported, not
# judged: the ledger records each program's first difference, which depends on
# the host's libraries and tools.

set -uo pipefail

usage() {
    cat <<'EOF'
usage: reverie-examples/e2e/run.sh [--backends LIST] [--environment NAME]
                                   [--artifacts DIR] [--report-only]
                                   [--write-ledger FILE]

  --backends LIST      comma-separated; default: every backend
                       (ptrace,kvm,liteinst,in-guest-trap,e9patch,dbt,sabre)
  --environment NAME   the ledger to judge against, ledgers/NAME.tsv; default:
                       this host's, <os id>-<os version>-glibc<version>
  --artifacts DIR      records and logs; default: target/e2e
  --report-only        report the verdicts without judging them
  --write-ledger FILE  also write every verdict other than match as a ledger
                       row, to measure a new environment's ledger

Cargo's own environment applies (CARGO_TARGET_DIR, CARGO_NET_OFFLINE, ...).
Exit status: 0 when every verdict is in the ledger and no row is stale (or in
a report-only run), 1 otherwise, 2 for a usage or build error.
EOF
}

E2E_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$E2E_DIR/../.." && pwd)"
ALL_BACKENDS=ptrace,kvm,liteinst,in-guest-trap,e9patch,dbt,sabre
backends=$ALL_BACKENDS
environment=
artifacts=
report_only=0
write_ledger=

while (($#)); do
    case $1 in
        --backends) backends=${2:?--backends needs a list}; shift 2 ;;
        --environment) environment=${2:?--environment needs a name}; shift 2 ;;
        --artifacts) artifacts=${2:?--artifacts needs a directory}; shift 2 ;;
        --report-only) report_only=1; shift ;;
        --write-ledger) write_ledger=${2:?--write-ledger needs a file}; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

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
binaries=$target_dir/debug
artifacts=${artifacts:-$target_dir/e2e}
mkdir -p "$artifacts" || exit 2

say() { printf 'reverie e2e: %s\n' "$*"; }

say "environment $environment; backends requested: $backends"
if ! cargo build --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p reverie-examples -p reverie-sabre-strace --lib --bins; then
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
        ptrace | liteinst | in-guest-trap | e9patch) run_backends+=("$backend") ;;
        kvm)
            # `<>` would create a missing /dev/kvm as an ordinary file where
            # /dev is writable, so require the character device first.
            if [[ -c /dev/kvm ]] && (exec 9<>/dev/kvm) 2>/dev/null; then
                run_backends+=(kvm)
            else
                refused+=("kvm: /dev/kvm is not a character device this user can open read-write")
            fi
            ;;
        dbt)
            if ! command -v cmake >/dev/null; then
                refused+=("dbt: cmake, which builds DynamoRIO and the DBT client, is not on PATH")
            elif [[ ! -f $ROOT_DIR/reverie-dbt/vendor/dynamorio/CMakeLists.txt ]]; then
                refused+=("dbt: the vendored DynamoRIO source (reverie-dbt/vendor/dynamorio) is missing")
            elif CARGO_TARGET_DIR=$target_dir bash "$ROOT_DIR/reverie-dbt/scripts/build-client.sh" \
                >"$artifacts/dbt-client-build.log" 2>&1; then
                run_backends+=(dbt)
            else
                say "the DBT client failed to build ($artifacts/dbt-client-build.log)"
                exit 2
            fi
            ;;
        sabre)
            loader=$("$binaries/reverie-sabre-strace" --print-sabre 2>/dev/null)
            if [[ -n $loader && -x $loader ]]; then
                export SABRE_BINARY=$loader
                run_backends+=(sabre)
            else
                refused+=("sabre: the SaBRe loader reverie-sabre builds was not found")
            fi
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

ledger=$E2E_DIR/ledgers/$environment.tsv
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
if ((report_only == 0)) && [[ -f $ledger ]]; then
    say "judging against ledgers/$environment.tsv"
    compare+=(--expected "$ledger")
else
    if ((report_only == 0)); then
        say "NO LEDGER for environment $environment (ledgers/$environment.tsv): the verdicts are reported, not judged. Measure one with --write-ledger."
    fi
    compare+=(--report-only)
fi
cd "$ROOT_DIR" || exit 2
"${compare[@]}"
