#!/usr/bin/env bash
set -euo pipefail

root=$(git -C "$(dirname -- "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
requested=${1:-ptrace,kvm,liteinst,dbt,sabre,e9patch}
jobs=${JOBS:-8}

has_backend() {
  [[ ",$requested," == *",$1,"* ]]
}

example_bins=()
has_backend ptrace && example_bins+=(--bin counter2)
has_backend kvm && example_bins+=(--bin reverie-kvm-counter2)
has_backend liteinst && example_bins+=(--bin reverie-liteinst-examples)
has_backend e9patch && example_bins+=(--bin reverie-e9patch-counter2)

if ((${#example_bins[@]} > 0)); then
  cargo build --manifest-path "$root/Cargo.toml" --release \
    -p reverie-examples "${example_bins[@]}"
fi

if has_backend dbt; then
  "$root/scripts/backend-submodule.sh" activate dynamorio
  PROFILE=release "$root/reverie-dbt/scripts/build-client.sh"
fi

if has_backend sabre; then
  "$root/scripts/backend-submodule.sh" activate sabre
  cmake -S "$root/third-party/sabre" -B "$root/target/sabre" \
    -DCMAKE_BUILD_TYPE=Release
  cmake --build "$root/target/sabre" --parallel "$jobs"
  cargo build --manifest-path "$root/Cargo.toml" --release \
    -p reverie-sabre-strace
fi

if has_backend e9patch; then
  "$root/scripts/backend-submodule.sh" activate e9patch
  make -C "$root/third-party/e9patch" -j"$jobs" release
fi
