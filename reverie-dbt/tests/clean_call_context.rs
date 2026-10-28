/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live regression for application-context updates while drreg owns registers.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn bounded(command: &mut Command) -> Output {
    let mut launcher = Command::new("timeout");
    launcher
        .args(["--signal=TERM", "--kill-after=2s", "30s"])
        .arg(command.get_program())
        .args(command.get_args());
    let output = launcher.output().expect("launch bounded native command");
    assert!(
        output.status.success(),
        "{command:?}: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn clean_calls_preserve_reserved_and_application_registers() {
    let directory = tempfile::tempdir().expect("native context fixture directory");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/clean_call_context");
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    bounded(
        Command::new(&cmake)
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(directory.path())
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
    );
    bounded(
        Command::new(&cmake)
            .arg("--build")
            .arg(directory.path())
            .args(["--parallel", "2"]),
    );
    let output = bounded(
        Command::new(reverie_dbt::bundled_drrun_path())
            .arg("-c")
            .arg(directory.path().join("libclean_call_context_client.so"))
            .arg("--")
            .arg(directory.path().join("clean_call_context_guest")),
    );
    let stdout = String::from_utf8(output.stdout).expect("native fixture stdout");
    assert!(stdout.contains(
        "application completed cases=9612 general_registers=16 xmm_registers=16 flags_mask=0xcd5 threads=9"
    ));
    assert!(stdout.contains("client completed cases=9612 actual_clean_call=1"));
}
