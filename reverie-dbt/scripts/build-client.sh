#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
workspace_dir=$(cd -- "$crate_dir/.." && pwd)

# Explicit external caller production has its own strict manifest/identity
# contract. The no-argument invocation below retains the prototype producer.
if (( $# != 0 )); then
  export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$workspace_dir/target"}
  if [[ ! -d $CARGO_TARGET_DIR ]]; then
    echo 'Caller production requires the existing shared target directory.' >&2
    exit 2
  fi
  CARGO_TARGET_DIR=$(realpath -e -- "$CARGO_TARGET_DIR")
  export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-8}
  bootstrap_profile=${PROFILE:-debug}
  caller_arguments=("$@")
  for (( index=0; index<${#caller_arguments[@]}; index++ )); do
    case "${caller_arguments[index]}" in
      --profile|--jobs)
        if (( index + 1 >= ${#caller_arguments[@]} )); then
          echo "Missing value for ${caller_arguments[index]}." >&2
          exit 2
        fi
        if [[ ${caller_arguments[index]} == --profile ]]; then
          bootstrap_profile=${caller_arguments[index+1]}
        else
          CARGO_BUILD_JOBS=${caller_arguments[index+1]}
        fi
        ((index+=1))
        ;;
    esac
  done
  case "$bootstrap_profile" in
    debug) bootstrap_profile=dev ;;
    release|validate) ;;
    *) echo 'Caller production requires profile debug, release, or validate.' >&2; exit 2 ;;
  esac
  case "$CARGO_BUILD_JOBS" in
    [1-8]) ;;
    *) echo 'Caller production requires CARGO_BUILD_JOBS from 1 through 8.' >&2; exit 2 ;;
  esac
  export CARGO_NET_OFFLINE=true
  export CARGO_INCREMENTAL=0
  # Package generation does not compile or run the Rust script. Build that
  # ordinary Cargo package in the same target instead of rust-script's private
  # executable cache. Seed resolution from this repository's lockfile.
  bootstrap="$CARGO_TARGET_DIR/ci/reverie-dbt-caller-producer"
  mkdir -p -- "$bootstrap"
  rust-script --package --pkg-path "$bootstrap/producer" "$script_dir/build-caller.rs"
  cat > "$bootstrap/Cargo.toml" <<'CARGO'
[workspace]
resolver = "2"
members = ["producer"]

[profile.validate]
inherits = "release"
debug-assertions = true
overflow-checks = true
lto = "off"
CARGO
  cp -- "$workspace_dir/Cargo.lock" "$bootstrap/Cargo.lock"
  cargo metadata --offline --format-version 1 \
    --manifest-path "$bootstrap/Cargo.toml" > "$bootstrap/metadata.json"
  exec cargo run --offline --locked --manifest-path "$bootstrap/Cargo.toml" \
    --target-dir "$CARGO_TARGET_DIR" --profile "$bootstrap_profile" \
    --jobs "$CARGO_BUILD_JOBS" -- --workspace "$workspace_dir" "$@"
fi

profile=${PROFILE:-debug}
target_dir=${CARGO_TARGET_DIR:-"$workspace_dir/target"}
native_build_dir="$target_dir/$profile/reverie-dbt-native"

cargo_args=(--manifest-path "$workspace_dir/Cargo.toml" -p reverie-dbt --locked)
case "$profile" in
  debug) ;;
  release) cargo_args+=(--release) ;;
  validate)
    cargo_args+=(--profile validate
      --config 'profile.validate.inherits="release"'
      --config 'profile.validate.debug-assertions=true'
      --config 'profile.validate.overflow-checks=true'
      --config 'profile.validate.lto="off"')
    ;;
  *) echo 'Prototype production requires PROFILE=debug, release, or validate.' >&2; exit 2 ;;
esac
# Retain the path helper and both Counter2 binaries. A dependency build emits
# only a hash-bearing rlib; request the prototype cdylib as a separate Cargo
# artifact so it cannot overwrite another dependency closure's rlib.
cargo build "${cargo_args[@]}"
cargo rustc "${cargo_args[@]}" --lib --crate-type cdylib \
  --message-format=json-render-diagnostics

path_helper="$target_dir/$profile/reverie-dbt-dynamorio-path"
dynamorio_cmake_dir=$("$path_helper" cmake)
runtime="$target_dir/$profile/libreverie_dbt.so"
"${CMAKE:-cmake}" -S "$crate_dir/native" -B "$native_build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DDynamoRIO_DIR="$dynamorio_cmake_dir" \
  -DREVERIE_DBT_RUNTIME="$runtime"
"${CMAKE:-cmake}" --build "$native_build_dir" --parallel "${CARGO_BUILD_JOBS:-8}"

echo "$native_build_dir/libreverie_dbt_client.so"
