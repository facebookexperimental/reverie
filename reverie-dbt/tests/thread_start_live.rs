/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live regressions for DBT thread virtual-identity startup.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use reverie_dbt::DbtRunner;

fn compile_fixture(directory: &Path, name: &str) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.c"));
    let output = directory.join(name);
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-pthread")
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap_or_else(|error| panic!("compile {}: {error}", source.display()));
    assert!(status.success(), "fixture compilation failed");
    output
}

fn run_fixture(name: &str, client_argument: &str) -> Output {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = compile_fixture(directory.path(), name);
    // A broken startup gate can prevent the guest from handling even SIGALRM.
    // Bound the native launcher outside DynamoRIO and terminate its process
    // group, so the test reports a failed status instead of hanging forever.
    let launcher = directory.path().join("bounded-drrun");
    std::fs::write(
        &launcher,
        b"#!/bin/sh\nexec timeout --signal=TERM --kill-after=2s 10s \"$REVERIE_DBT_TEST_DRRUN\" \"$@\"\n",
    )
    .expect("write bounded launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make bounded launcher executable");
    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    let mut guest = Command::new(fixture);
    guest.env("REVERIE_DBT_TEST_DRRUN", reverie_dbt::bundled_drrun_path());
    DbtRunner::new(launcher, client)
        .expect("create bounded native runner")
        .client_argument(client_argument)
        .output(&guest)
        .unwrap_or_else(|error| panic!("run {name}: {error}"))
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn reused_host_tid_waits_for_the_clone_parents_virtual_identity() {
    let output = run_fixture("reused_tid_start", "-test-reused-tid");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"reused-tid-start=ok tid=4\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("REUSED_TID_TEST exercised=1"),
        "the stale host-TID mapping was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn an_exiting_process_does_not_block_another_process_thread_start() {
    let output = run_fixture(
        "thread_clone_process_exit",
        "-test-thread-clone-process-exit",
    );
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"thread-clone-process-exit=ok tid=6\n");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("THREAD_CLONE_PROCESS_EXIT_TEST exercised=1"),
        "the exiting process path was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_failed_thread_clone_does_not_block_the_next_thread_start() {
    let output = run_fixture("failed_thread_clone", "-test-wait-for-background");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"failed-thread-clone=ok tid=5\n");
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_new_thread_cannot_write_memory_before_admission() {
    let output = run_fixture("thread_start_write", "-test-thread-start-write");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"thread-start-write=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("THREAD_START_WRITE_TEST blocked=1"),
        "the pre-admission write check was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_copied_process_thread_uses_its_parents_published_identity() {
    let output = run_fixture("copied_thread_identity", "-test-reused-tid");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"copied-thread-identity=ok pid=4 tid=5\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("REUSED_TID_TEST exercised=1"),
        "the copied thread's stale host-TID mapping was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_precompiled_entry_cannot_bypass_thread_admission() {
    let output = run_fixture("thread_start_write_precompiled", "-test-thread-start-write");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"precompiled-thread-start-write=ok\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("THREAD_START_WRITE_TEST blocked=1"),
        "the pre-admission write check was not exercised: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn a_stalled_clone_fails_with_an_admission_diagnostic() {
    let output = run_fixture("reused_tid_start", "-test-stalled-thread-start");
    assert_eq!(output.status.code(), Some(96), "guest result: {output:?}");
    assert!(output.stdout.is_empty(), "unadmitted guest ran: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("STALLED_THREAD_START_TEST exercised=1"),
        "the stalled clone was not exercised: {output:?}"
    );
    let diagnostic = stderr
        .lines()
        .find(|line| line.starts_with("reverie-dbt: thread admission timed out:"))
        .unwrap_or_else(|| panic!("missing admission diagnostic: {output:?}"));
    assert!(diagnostic.contains("virtual_pid=3 "), "{diagnostic}");
    assert!(diagnostic.contains("pending_clones=1 "), "{diagnostic}");
    assert!(diagnostic.contains("pending_start=2 "), "{diagnostic}");
    assert!(diagnostic.ends_with("timeout_ms=100"), "{diagnostic}");
    let host_tid = diagnostic
        .split_whitespace()
        .find_map(|field| field.strip_prefix("host_tid="))
        .expect("diagnostic host TID")
        .parse::<u32>()
        .expect("positive numeric host TID");
    assert!(host_tid > 0, "{diagnostic}");
}
