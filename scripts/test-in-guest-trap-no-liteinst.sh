#!/usr/bin/env bash
# Additive qualification for the in-guest runtime without the site patcher.
# Run after the default LiteInst suites, from a clean source checkout.
set -euo pipefail

if [[ $# != 1 || $1 != /* ]]; then
    echo "usage: scripts/test-in-guest-trap-no-liteinst.sh /absolute/unique-generation" >&2
    exit 2
fi

generation=$1
features=allocator-fixture,rpc-io-fixture,exec-native-injection,loader-private-runtime
graph=$(mktemp)
trap 'rm -f "$graph"' EXIT

# Selecting every consumer root also catches accidental default-feature
# activation through the preload or example CLI. Include build and dev edges.
cargo tree --locked --no-default-features \
    -p reverie-liteinst -p reverie-liteinst-preload -p reverie-examples \
    --features "reverie-liteinst/allocator-fixture,reverie-liteinst/rpc-io-fixture,reverie-liteinst/exec-native-injection,reverie-liteinst/loader-private-runtime,reverie-examples/runtime" \
    --edges normal,build,dev --prefix none --format '{p}' > "$graph"
if [[ ! -s "$graph" ]]; then
    echo 'in-guest-trap dependency graph is empty' >&2
    exit 1
fi
if grep -q '^liteinst2 v' "$graph"; then
    dependency_grep_status=0
else
    dependency_grep_status=$?
fi
case "$dependency_grep_status" in
    0)
        echo 'in-guest-trap dependency graph unexpectedly includes liteinst2' >&2
        cat "$graph" >&2
        exit 1
        ;;
    1) ;;
    *)
        echo "in-guest-trap dependency graph grep failed (exit $dependency_grep_status)" >&2
        exit "$dependency_grep_status"
        ;;
esac
echo 'in-guest-trap graph: liteinst2 absent, including loader/native-exec features'

scripts/build-liteinst-test-runtime.rs --for-ci "$generation" --no-liteinst
# The producer binds this exact feature set and source identity. The test
# consumers reject an ON runtime, a dirty tree, or a mismatched receipt.
source "$generation/bundle/fixture.env"
# The full shared cohort exercises fixed gates, native exec and the private
# loader. The lean cohort also executes the original nongate branch of the
# inherited-filter assertion and the public generic Compatibility controls.
cargo test --locked -p reverie-liteinst --no-default-features \
    --features "$features" --no-fail-fast -- --test-threads=1
cargo test --locked -p reverie-liteinst --no-default-features \
    --features allocator-fixture,rpc-io-fixture \
    --test generic_bootstrap --test rpc_tool --no-fail-fast -- --test-threads=1
cargo test --locked -p reverie-liteinst-preload -p reverie-loader \
    --no-default-features --no-fail-fast -- --test-threads=1
cargo check --locked -p reverie-inguest --no-default-features \
    --features exec-stop,stage1a-probe,exec-native-injection,loader-private-runtime \
    --all-targets
cargo test --locked -p reverie-inguest --no-default-features \
    --features coordinator-rpc,rcb-clock,launcher,allocator-fixture,rpc-io-fixture,exec-stop,stage1a-probe,exec-native-injection,loader-private-runtime,native-exec-state-fixture \
    --lib --no-fail-fast -- --test-threads=1
cargo build --locked -p reverie-examples --no-default-features --features runtime
cargo test --locked -p reverie-examples --no-default-features \
    --features runtime --test liteinst -- --test-threads=1
