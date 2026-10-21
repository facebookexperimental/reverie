/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live regression coverage for DBT virtual-PID translation in `pidfd_open`.
//!
//! The fixture obtains each process's native identity from `/proc/self/stat`,
//! requires that it differs from the DBT-visible identity, and checks the
//! resulting pidfd's `/proc/self/fdinfo` target before sending `SIGUSR1` through
//! it. The fixture also covers self/unknown PID crossed with valid/invalid flags,
//! pinning Linux's EINVAL-before-ESRCH precedence. Together these prove both the
//! self and foreign-child pidfds target the mapped host process rather than
//! merely proving that some file descriptor was returned.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

fn compile_fixture(output: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pidfd_identity.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("compile pidfd identity fixture");
    assert!(status.success(), "fixture compilation failed");
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn pidfd_open_targets_virtual_self_and_foreign_child_identities() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("pidfd-identity");
    compile_fixture(&fixture);

    // A native runtime stall may prevent the guest alarm from being delivered.
    // Bound the launcher process group independently, including its children.
    let launcher = directory.path().join("bounded-drrun");
    std::fs::write(
        &launcher,
        b"#!/bin/sh\nexec timeout --signal=TERM --kill-after=2s 15s \"$REVERIE_DBT_TEST_DRRUN\" \"$@\"\n",
    )
    .expect("write bounded launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make bounded launcher executable");
    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    let runner = DbtRunner::new(launcher, client)
        .expect("create bounded native runner")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(fixture);
    guest.env("REVERIE_DBT_TEST_DRRUN", reverie_dbt::bundled_drrun_path());
    guest.env("HERMIT_DBT_NOOP", "1");
    let output = runner
        .output(&guest)
        .expect("pidfd identity probe must run");

    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"pidfd-identity-ok\n");
}
