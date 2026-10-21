/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Compare queued-signal validation with Linux and require actual self/child delivery.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

#[test]
#[ignore = "requires a built DynamoRIO native client and python3; run explicitly with --ignored"]
fn queued_signals_preserve_identity_delivery_and_kernel_validation_order() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("queued-signal-identity");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/queued_signal_identity.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&fixture)
        .status()
        .expect("compile queued-signal identity fixture");
    assert!(status.success(), "fixture compilation failed");

    // The guest starts as its own session/group leader, so its process group
    // has a mapped identity. The supervisor stays outside that group and
    // terminates all remaining group members even if native signal delivery
    // prevents the guest alarm from working or the guest exits before a child.
    let launcher = directory.path().join("bounded-launcher");
    std::fs::write(
        &launcher,
        r#"#!/usr/bin/env python3
import os, signal, subprocess, sys
child = subprocess.Popen([os.environ["REVERIE_DBT_TEST_PROGRAM"], *sys.argv[1:]], start_new_session=True)
try:
    try:
        result = child.wait(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        result = 124
finally:
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()
sys.exit(result)
"#,
    )
    .expect("write bounded launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make bounded launcher executable");

    let native = Command::new(&launcher)
        .arg("native")
        .env("REVERIE_DBT_TEST_PROGRAM", &fixture)
        .output()
        .expect("run Linux oracle");
    assert!(native.status.success(), "native fixture failed: {native:?}");
    assert_eq!(native.stdout.split(|byte| *byte == b'\n').count(), 74);
    assert!(native.stdout.ends_with(b"queued-signal-identity=ok\n"));

    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    let mut guest = Command::new(&fixture);
    guest.arg("dbt").env("HERMIT_DBT_NOOP", "1").env(
        "REVERIE_DBT_TEST_PROGRAM",
        reverie_dbt::bundled_drrun_path(),
    );
    let output = DbtRunner::new(launcher, client)
        .expect("create bounded native runner")
        .client_argument("-test-wait-for-background")
        .output(&guest)
        .expect("run DBT identity fixture");
    assert!(output.status.success(), "DBT fixture failed: {output:?}");
    assert_eq!(
        output.stdout, native.stdout,
        "DBT must match the Linux oracle"
    );
}
