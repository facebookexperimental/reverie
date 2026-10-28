/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Component controls for the native controller-capture certainty provider.
//!
//! The client exercises its production query and admission helpers against a
//! scratch owner. This does not replace full-Tool fork/chroot coverage or prove
//! that a real followed exec preserves the transport.

use std::process::Command;

use reverie_dbt::DbtRunner;

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn controller_capture_certainty_tracks_admission_and_native_uncertainty() {
    let client = std::env::var_os("REVERIE_DBT_CLIENT")
        .expect("REVERIE_DBT_CLIENT must point to the built native client");
    let output = DbtRunner::new(reverie_dbt::bundled_drrun_path(), client)
        .expect("create the native runner")
        .client_argument("-test-controller-capture")
        .output(&Command::new("/bin/true"))
        .expect("run the native certainty controls");
    assert!(
        output.status.success(),
        "native controls failed: {output:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "unexpected guest stdout: {output:?}"
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("native diagnostic is UTF-8");
    let observations: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("CONTROLLER_CAPTURE_TEST "))
        .collect();
    assert_eq!(
        observations,
        [concat!(
            "CONTROLLER_CAPTURE_TEST fresh=1 pending=1 wrong_birth=1 wrong_pid=1 ",
            "admitted=1 exact_failure=1 thread_pending=1 contention=1 sticky=1 ",
            "lost=1 exec_loss=1 capacity=1",
        )],
        "missing or failed native certainty control: {output:?}",
    );
}
