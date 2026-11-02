/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(not(sanitized), test))]

#[path = "support/inject_then_tail_command.rs"]
mod command;
#[path = "tool_fixtures/inject_then_tail.rs"]
mod inject_then_tail_tool;

use inject_then_tail_tool::NUM_REPS;
use inject_then_tail_tool::TestTool;

fn assert_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "inject-then-tail command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert_eq!(output.stdout, b"inject-then-tail=ok\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn ptrace_inject_then_tail_command() {
    let guest = command::GuestBinary::compile();
    guest.assert_native();
    guest.record_before_launch("ptrace");
    let (output, _state): (_, TestTool) =
        reverie_test_support::test_cmd_with_config::<TestTool>(guest.program(), &[], NUM_REPS)
            .unwrap();
    assert_command_output("ptrace", &output);
    rust_command_test();
}

fn assert_rust_guest_records(stdout: &[u8]) {
    let text = std::str::from_utf8(stdout).unwrap();
    let lines: Vec<_> = text.split_terminator('\n').collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "Running in guest mode (actual test).");
    let ids = lines[1].strip_prefix("Read IDs: t ").unwrap();
    let fields: Vec<_> = ids.split(", ").collect();
    assert_eq!(fields.len(), 6);
    for (field, prefix) in fields.iter().zip(["", "p ", "g ", "pp ", "pg ", "s"]) {
        field.strip_prefix(prefix).unwrap().parse::<i64>().unwrap();
    }
    lines[2]
        .strip_prefix("Generated random number: ")
        .unwrap()
        .parse::<u64>()
        .unwrap();
}

fn assert_rust_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "inject-then-tail Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert_rust_guest_records(&output.stdout);
}

fn rust_command_test() {
    let program = env!("CARGO_BIN_EXE_inject-then-tail-rust-command-guest");
    eprintln!("inject-then-tail Rust guest: image={program}");

    let native = std::process::Command::new(program).output().unwrap();
    eprintln!(
        "inject-then-tail Rust command native: status={:?} stdout={:02x?} stderr={:02x?}",
        native.status, native.stdout, native.stderr,
    );
    assert_eq!(native.status.code(), Some(0));
    assert_rust_guest_records(&native.stdout);

    let (ptrace, _state): (_, TestTool) =
        reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], NUM_REPS).unwrap();
    assert_rust_command_output("ptrace", &ptrace);
}
