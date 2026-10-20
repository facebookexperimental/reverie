/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live coverage of completed Tool results across the native callback boundary.

use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn completed_tool_results_and_register_edits_reach_the_guest() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("set-reg-probe");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/set_reg_probe.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&fixture)
        .status()
        .expect("compile Tool result fixture");
    assert!(status.success(), "fixture compilation failed");

    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(&fixture);
    guest.env("HERMIT_DBT_TEST_SET_REG", "1");
    let output = runner.output(&guest).expect("Tool result fixture must run");
    assert_eq!(
        output.stdout, b"r15=0xdeadbeefcafef00d\ntool identities pid=4321 ppid=4322 tid=4323\n",
        "completed Tool results were changed before reaching the guest: {output:?}"
    );
    assert!(output.status.success(), "guest failed: {output:?}");
}

/// The independent witness is a raw syscall in the actual application Tool
/// callback, not another Guest::inject or a fabricated completed result.
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn returning_identity_injections_match_application_kernel_ids() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("kernel-identity-inject");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernel_identity_inject.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&fixture)
        .status()
        .expect("compile kernel identity injection fixture");
    assert!(status.success(), "fixture compilation failed");

    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(&fixture);
    guest.env("HERMIT_DBT_TEST_SET_REG", "1");
    let output = runner
        .output(&guest)
        .expect("kernel identity fixture must run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rows: Vec<_> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-identity "))
        .collect();
    assert_eq!(rows.len(), 3, "missing query observation: {output:?}");
    for (row, expected) in rows
        .iter()
        .zip([libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid])
    {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "malformed observation: {row}");
        assert_eq!(fields[0], format!("sysnum={expected}"));
        let kernel: i64 = fields[1].strip_prefix("kernel=").unwrap().parse().unwrap();
        let injected: i64 = fields[2]
            .strip_prefix("injected=")
            .unwrap()
            .parse()
            .unwrap();
        if expected == libc::SYS_getppid {
            assert_eq!(fields[3], "adapter=none");
        } else {
            let adapter: i64 = fields[3].strip_prefix("adapter=").unwrap().parse().unwrap();
            assert_eq!(adapter, kernel, "Guest identity differs from kernel: {row}");
        }
        assert!(kernel > 0, "invalid kernel identity: {row}");
        assert_eq!(
            injected, kernel,
            "native projection changed the kernel identity: {row}"
        );
    }
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"kernel-identity-inject=ok\n");
    let mut guest = Command::new(&fixture);
    guest
        .arg("pselect-validation")
        .env("HERMIT_DBT_TEST_SET_REG", "1");
    let output = runner
        .output(&guest)
        .expect("returning validation fixture must run");
    assert!(
        output.status.success(),
        "returning validation failed: {output:?}"
    );
    assert_eq!(output.stdout, b"returning-pselect-validation=ok\n");
}
