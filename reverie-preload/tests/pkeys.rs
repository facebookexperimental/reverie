/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

const CHILD: &str = "REVERIE_TEST_PKEY_BUFFERS";
const MARKER: &str = "buffer row: ";

fn rows(output: &std::process::Output) -> Vec<String> {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(MARKER).map(|(_, row)| row.to_owned()))
        .collect()
}

#[test]
fn guest_buffer_permissions_match_native_on_both_signal_stacks() {
    let run = |mode| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_reverie-preload-pkey-buffers"))
            .env(CHILD, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("protected-buffer helper timed out in {mode}: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    };
    let native = run("native");
    let expected = rows(&native);
    if String::from_utf8_lossy(&native.stdout).contains("OSPKE unavailable") {
        eprintln!("OSPKE unavailable; protected-buffer hardware cases were not measured");
        return;
    }
    assert_eq!(expected.len(), 40);
    for mode in ["alt-stack", "guest-stack"] {
        assert_eq!(rows(&run(mode)), expected, "signal stack mode {mode}");
    }
    println!(
        "40 native buffer cases match on each signal stack: 12 pipe, 4 partial transfer, 24 clock/time/signal-action cases"
    );
}
