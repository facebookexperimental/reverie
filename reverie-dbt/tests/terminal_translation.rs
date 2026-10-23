/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A terminal app jump may translate to its own unreadable target.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn bounded(command: &mut Command) -> Output {
    Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=2s", "30s"])
        .arg(command.get_program())
        .args(command.get_args())
        .output()
        .unwrap_or_else(|error| panic!("launch {command:?}: {error}"))
}

fn success(command: &mut Command) {
    let output = bounded(command);
    assert!(
        output.status.success(),
        "{command:?}: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn check_case(command: &mut Command, case: &str, instrumented: bool) {
    let output = bounded(command);
    let (status, stdout): (i32, &[u8]) = match case {
        "unmapped" => (77, b"before\nfault\n"),
        "readable" => (0, b"before\nresult=1\n"),
        "selfmod" => (0, b"before\nselfmod=1,2\n"),
        "truncate" => (0, b"truncate=3\n"),
        _ => unreachable!(),
    };
    assert_eq!(
        (output.status.code(), output.stdout.as_slice()),
        (Some(status), stdout),
        "{command:?}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if instrumented {
        let stderr = String::from_utf8(output.stderr).expect("fixture diagnostic UTF-8");
        let completed = stderr
            .lines()
            .find(|line| line.starts_with("translation completed enabled=1 "))
            .expect("actual instrumented client completion");
        let field = if case == "truncate" {
            "truncations="
        } else {
            "rewrites="
        };
        let count: usize = completed
            .split_whitespace()
            .find_map(|part| part.strip_prefix(field))
            .expect("actual callback count")
            .parse()
            .expect("numeric callback count");
        assert!(count >= if case == "selfmod" { 2 } else { 1 });
        // Cache rebuilds may invoke a callback more than once. The exact guest
        // result above proves both source versions; this is not a retirement
        // count, nor does selecting stored mode prove a restore occurred.
        eprintln!("case={case} {completed}");
    }
}

#[test]
fn terminal_jump_translation_preserves_target_fault_and_source_extent() {
    let directory = tempfile::tempdir()
        .expect("terminal translation fixture directory")
        .keep();
    // Keep failed fixtures/ELFs for diagnosis; remove only after all checks pass.
    eprintln!("terminal translation artifacts: {}", directory.display());
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/terminal_translation");
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    success(
        Command::new(&cmake)
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(&directory)
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
    );
    success(
        Command::new(&cmake)
            .arg("--build")
            .arg(&directory)
            .args(["--parallel", "2"]),
    );
    let guest = directory.join("terminal_translation_guest");
    let client = directory.join("libterminal_translation_client.so");
    let cases = ["unmapped", "readable", "selfmod", "truncate"];
    for case in cases {
        check_case(Command::new(&guest).arg(case), case, false);
    }
    for mode in ["normal", "stored"] {
        for case in cases {
            check_case(
                Command::new(reverie_dbt::bundled_drrun_path())
                    .arg("-c")
                    .arg(&client)
                    .arg(mode)
                    .arg("--")
                    .arg(&guest)
                    .arg(case),
                case,
                true,
            );
        }
        // One source write above tests invalidation, not necessarily the sandbox
        // path. This separately labeled existing option forces writable-code
        // sandboxing, whose source extent also consumes the builder's cur_pc.
        check_case(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-sandbox_writable")
                .arg("-c")
                .arg(&client)
                .arg(mode)
                .arg("--")
                .arg(&guest)
                .arg("selfmod"),
            "selfmod",
            true,
        );
    }
    std::fs::remove_dir_all(directory).expect("remove successful fixture artifacts");
}
