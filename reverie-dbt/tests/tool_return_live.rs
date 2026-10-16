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
