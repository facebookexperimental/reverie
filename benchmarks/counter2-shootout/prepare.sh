#!/usr/bin/env bash
set -euo pipefail

root=$(git -C "$(dirname -- "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
requested=${1:-ptrace,kvm,liteinst}

has_backend() {
  [[ ",$requested," == *",$1,"* ]]
}

example_bins=()
# counter2 runs on the first-party ptrace and KVM hosts with --backend.
{ has_backend ptrace || has_backend kvm; } &&
  example_bins+=(--bin counter2)
has_backend liteinst && example_bins+=(--bin reverie-liteinst-examples)

if ((${#example_bins[@]} > 0)); then
  cargo build --manifest-path "$root/Cargo.toml" --release \
    -p reverie-examples "${example_bins[@]}"
fi
