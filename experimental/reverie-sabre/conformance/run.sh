#!/usr/bin/env bash
set -euo pipefail

backend="${1:-all}"
case "$backend" in
    all|ptrace|sabre) ;;
    *)
        echo "usage: $0 [all|ptrace|sabre]" >&2
        exit 2
        ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd -- "$script_dir/../../.." && pwd)"
build_dir="${SABRE_CONFORMANCE_BUILD_DIR:-$root/target/sabre-conformance}"
timeout_seconds="${SABRE_CONFORMANCE_TIMEOUT:-30}"
cc="${CC:-cc}"

mkdir -p "$build_dir"
"$cc" -std=c11 -O2 -Wall -Wextra -Werror -pthread     "$script_dir/thread_lifecycle.c" -o "$build_dir/thread_lifecycle"
"$cc" -std=c11 -O2 -Wall -Wextra -Werror     "$script_dir/signal_forwarding.c" -o "$build_dir/signal_forwarding"

if [[ "$backend" == "all" || "$backend" == "ptrace" ]]; then
    cargo build --manifest-path "$root/Cargo.toml"         -p reverie-examples --bin counter2
fi

if [[ "$backend" == "all" || "$backend" == "sabre" ]]; then
    sabre_binary="${SABRE_BINARY:?set SABRE_BINARY to the upstream SaBRe executable}"
    sabre_plugin="${SABRE_PLUGIN:-$root/target/debug/libriptrace_plugin.so}"

    [[ -x "$sabre_binary" ]] || {
        echo "SaBRe executable is not executable: $sabre_binary" >&2
        exit 2
    }
    cargo build --manifest-path "$root/Cargo.toml" -p riptrace -p riptrace-tool
    [[ -f "$sabre_plugin" ]] || {
        echo "SaBRe plugin does not exist: $sabre_plugin" >&2
        exit 2
    }
fi

for workload in thread_lifecycle signal_forwarding; do
    executable="$build_dir/$workload"

    if [[ "$backend" == "all" || "$backend" == "ptrace" ]]; then
        echo "gate: ptrace/$workload"
        timeout "${timeout_seconds}s" "$root/target/debug/counter2" -- "$executable"
    fi

    if [[ "$backend" == "all" || "$backend" == "sabre" ]]; then
        echo "gate: sabre/$workload"
        timeout "${timeout_seconds}s" "$root/target/debug/riptrace"             --sabre "$sabre_binary"             --plugin "$sabre_plugin"             --quiet             --summary             -- "$executable"
    fi
done
