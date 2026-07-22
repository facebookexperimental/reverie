#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DYNAMORIO_HOME:-}" ]]; then
  echo "DYNAMORIO_HOME must point to a DynamoRIO source tree with build/" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
workspace_dir=$(cd -- "$crate_dir/.." && pwd)
profile=${PROFILE:-debug}
target_dir=${CARGO_TARGET_DIR:-"$workspace_dir/target"}
native_build_dir="$target_dir/reverie-dbi-native"
if [[ -f "$DYNAMORIO_HOME/install/cmake/DynamoRIOConfig.cmake" ]]; then
  dynamorio_cmake_dir="$DYNAMORIO_HOME/install/cmake"
else
  dynamorio_cmake_dir="$DYNAMORIO_HOME/build/cmake"
fi

cargo_args=(build --manifest-path "$workspace_dir/Cargo.toml" -p reverie-dbi)
if [[ "$profile" == "release" ]]; then
  cargo_args+=(--release)
fi
cargo "${cargo_args[@]}"

runtime="$target_dir/$profile/libreverie_dbi.so"
cmake -S "$crate_dir/native" -B "$native_build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DDynamoRIO_DIR="$dynamorio_cmake_dir" \
  -DREVERIE_DBI_RUNTIME="$runtime"
cmake --build "$native_build_dir" --parallel

echo "$native_build_dir/libreverie_dbi_client.so"
