/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::process::Command;
use std::time::Duration;
#[path = "../../reverie-rpc-transport/tests/fixtures/owned_lifecycle.rs"]
mod owned_lifecycle;
fn run(mode: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-preload-native-syscall-result"));
    command.arg(mode);
    let (output, _) = owned_lifecycle::run(command, Duration::from_secs(10)).unwrap();
    println!(
        "mode={mode}; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "mode={mode}: {output:?}");
    assert!(output.stderr.is_empty(), "mode={mode}: {output:?}");
}
#[test]
fn scalar_path_without_pkru_observation() {
    run("no-pkru");
}
#[test]
fn native_pkey_allocation_and_free_effects() {
    run("allocation");
}
#[test]
fn native_implicit_execute_only_key_effect() {
    run("mprotect");
}
#[test]
fn native_partial_mprotect_error_keeps_permission_effect() {
    run("partial-error");
}
#[test]
fn original_denied_pointer_is_checked_by_linux() {
    run("pointers");
}
#[test]
fn all_six_mmap_arguments_reach_linux() {
    run("six-arguments");
}
#[test]
fn caller_rights_return_before_stack_access() {
    run("caller-rights");
}
