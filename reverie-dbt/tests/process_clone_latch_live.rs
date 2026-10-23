/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live regressions for the DBT process-clone callback latch boundary.

use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

fn compile_fixture(output: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/process_clone_latch.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("compile process-clone latch fixture");
    assert!(status.success(), "fixture compilation failed");
}

fn runner() -> DbtRunner {
    DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background")
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn injected_invalid_clone_does_not_arm_an_original_syscall_result_latch() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("process-clone-latch");
    compile_fixture(&fixture);

    let mut guest = Command::new(&fixture);
    guest
        .arg("injected")
        .env("HERMIT_DBT_TEST_INJECT_INVALID_CLONE", "1")
        .env("REVERIE_DBT_TEST_PROCESS_CLONE_RESULTS", "1");
    let output = runner()
        .output(&guest)
        .expect("injected clone probe must run");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"injected-clone-latch-ok\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reverie-dbt-test: injected invalid clone returned EINVAL"),
        "Guest::inject did not execute the invalid clone probe: {output:?}"
    );
    assert!(
        !stderr.contains("reverie-dbt-test: process-clone-result"),
        "an injected clone incorrectly emitted an original-syscall callback: {output:?}"
    );
    assert!(
        !stderr.contains("stale process-clone result state"),
        "an injected clone leaked the original-syscall callback latch: {output:?}"
    );
}

fn assert_stale_refused_before_tool(
    fixture: &Path,
    mode: &str,
    sysnum: i64,
    tool_env: &str,
    forbidden_tool_fragment: &str,
) {
    let mut guest = Command::new(fixture);
    guest
        .arg(mode)
        .env(tool_env, "1")
        .env("REVERIE_DBT_TEST_PROCESS_CLONE_RESULTS", "1");
    let output = runner()
        .client_argument("-test-leave-process-clone-result-pending")
        .output(&guest)
        .expect("stale clone-result probe must run");
    assert_eq!(
        output.status.code(),
        Some(101),
        "stale clone-result state was not refused: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "reverie-dbt: stale process-clone result state before syscall {sysnum}"
        )),
        "missing exact stale-state diagnostic: {output:?}"
    );
    let callback_rows: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("reverie-dbt-test: process-clone-result "))
        .collect();
    let expected_callback = format!(
        "reverie-dbt-test: process-clone-result sysnum={} result={}",
        libc::SYS_clone,
        -libc::EINVAL as i64
    );
    assert_eq!(
        callback_rows,
        [expected_callback.as_str()],
        "the stale latch must come from the real failed clone post-event: {output:?}"
    );
    assert!(
        !stderr.contains(forbidden_tool_fragment),
        "the external Tool observed a syscall before stale-state refusal: {output:?}"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn stale_clone_result_is_refused_before_clone3_decode_or_external_callback() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("process-clone-latch");
    compile_fixture(&fixture);

    assert_stale_refused_before_tool(
        &fixture,
        "clone3",
        libc::SYS_clone3,
        "HERMIT_DBT_STRACE",
        "clone3(",
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn stale_clone_result_is_refused_before_suppressed_path() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("process-clone-latch");
    compile_fixture(&fixture);

    assert_stale_refused_before_tool(
        &fixture,
        "suppressed",
        libc::SYS_getpid,
        "HERMIT_DBT_TEST_SET_REG",
        "r15=0xdeadbeefcafef00d",
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn stale_clone_result_is_refused_before_deferred_path() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("process-clone-latch");
    compile_fixture(&fixture);

    assert_stale_refused_before_tool(
        &fixture,
        "deferred",
        libc::SYS_getuid,
        "HERMIT_DBT_STRACE",
        "getuid(",
    );
}
