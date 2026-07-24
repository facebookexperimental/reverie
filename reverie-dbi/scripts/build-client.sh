#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
workspace_dir=$(cd -- "$crate_dir/.." && pwd)
profile=${PROFILE:-debug}
target_dir=${CARGO_TARGET_DIR:-"$workspace_dir/target"}
native_build_dir="$target_dir/$profile/reverie-dbi-native"

cargo_args=(build --manifest-path "$workspace_dir/Cargo.toml" -p reverie-dbi)
if [[ "$profile" == "release" ]]; then
  cargo_args+=(--release)
fi
cargo "${cargo_args[@]}"

path_helper="$target_dir/$profile/reverie-dbi-dynamorio-path"
dynamorio_cmake_dir=$("$path_helper" cmake)
runtime="$target_dir/$profile/libreverie_dbi.so"
"${CMAKE:-cmake}" -S "$crate_dir/native" -B "$native_build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DDynamoRIO_DIR="$dynamorio_cmake_dir" \
  -DREVERIE_DBI_RUNTIME="$runtime"
"${CMAKE:-cmake}" --build "$native_build_dir" --parallel

echo "$native_build_dir/libreverie_dbi_client.so"
