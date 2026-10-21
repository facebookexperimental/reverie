/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style LICENSE in the root directory.
 */

//! Counter-branch exit disambiguation must use the decoded address-size width.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn bounded(command: &mut Command) -> Output {
    let output = Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=2s", "30s"])
        .arg(command.get_program())
        .args(command.get_args())
        .output()
        .expect("execute counter-branch fixture command");
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

#[test]
fn counter_branches_preserve_decoded_width_and_flags() {
    let directory = tempfile::tempdir().expect("counter-branch fixture directory");
    let guest = directory.path().join("counter-branch-width");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    bounded(
        Command::new(compiler)
            .args(["-nostdlib", "-static", "-fno-pie", "-no-pie"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/counter_branch_width.S"),
            )
            .arg("-o")
            .arg(&guest),
    );
    let native = bounded(&mut Command::new(&guest));
    let high = 0x1122_3344_0000_0000;
    // Each row is (taken, remaining full RCX, RFLAGS), in fixture order.
    // ECX updates zero-extend, while JECXZ leaves the full RCX untouched.
    let expected: [[u64; 3]; 24] = [
        [1, 0, 0x202],
        [0, high, 0x202],
        [0, 1, 0x202],
        [1, 0, 0x202],
        [1, high, 0x202],
        [0, high + 1, 0x202],
        [1, 1, 0x202],
        [0, 0, 0x202],
        [1, u64::MAX, 0x202],
        [1, 1, 0x202],
        [0, 0, 0x202],
        [1, u32::MAX.into(), 0x202],
        [1, 1, 0x242],
        [0, 0, 0x242],
        [0, 1, 0x202],
        [1, 1, 0x242],
        [0, 0, 0x242],
        [0, 1, 0x202],
        [1, 1, 0x202],
        [0, 0, 0x202],
        [0, 1, 0x242],
        [1, 1, 0x202],
        [0, 0, 0x202],
        [0, 1, 0x242],
    ];
    let expected_bytes: Vec<u8> = expected
        .iter()
        .flatten()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(native.stdout, expected_bytes, "native architectural oracle");
    assert!(native.stderr.is_empty(), "{native:?}");
    // Default shared-exit stubs must work: do not disable the faulty mechanism.
    let instrumented = bounded(
        Command::new(reverie_dbt::bundled_drrun_path())
            .args(["-quiet", "--"])
            .arg(&guest),
    );
    assert_eq!(
        instrumented.stdout, expected_bytes,
        "DynamoRIO counter-branch semantics"
    );
    assert!(instrumented.stderr.is_empty(), "{instrumented:?}");
}
