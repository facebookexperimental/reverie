/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// reinject stat* as fstatat unittest

#[cfg(all(not(sanitized), test))]
#[path = "tool_fixtures/stat.rs"]
mod stat_tool;

#[cfg(all(not(sanitized), test))]
use stat_tool::LocalState;

#[cfg(all(not(sanitized), test))]
#[path = "support/stat_rust_guest.rs"]
mod rust_guest;

#[cfg(all(not(sanitized), test))]
mod tests {
    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[test]
    fn stat_can_be_reinjected() {
        check_fn::<LocalState, _>(rust_guest::stat_can_be_reinjected);
        assert_rust_command("stat");
    }

    #[test]
    fn statx_fstat_returns_same_ino() {
        check_fn::<LocalState, _>(rust_guest::statx_fstat_returns_same_ino);
        assert_rust_command("statx");
    }
}

#[cfg(all(not(sanitized), test))]
fn assert_rust_command(operation: &str) {
    let program = reverie_test_support::guest_binary!("stat-rust-command-guest");
    eprintln!("stat Rust command {operation}: image={program}");
    let output = std::process::Command::new(program)
        .arg(operation)
        .output()
        .expect("run native Rust stat fixture");
    eprintln!(
        "stat Rust command {operation}/native: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());

    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(program, &[operation]).unwrap();
    assert_command_output(&format!("rust/{operation}/ptrace"), &output);
}

#[cfg(all(not(sanitized), test))]
#[path = "support/stat_command.rs"]
mod command;

#[cfg(all(not(sanitized), test))]
fn assert_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "stat command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[cfg(all(not(sanitized), test))]
#[test]
fn ptrace_stat_command() {
    let guest = command::GuestBinary::compile(command::Operation::Stat);
    guest.assert_native();
    guest.record_before_launch("ptrace");
    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(guest.program(), &[]).unwrap();
    assert_command_output("stat/ptrace", &output);
}

#[cfg(all(not(sanitized), test))]
#[test]
fn ptrace_statx_command() {
    let guest = command::GuestBinary::compile(command::Operation::Statx);
    guest.assert_native();
    guest.record_before_launch("ptrace");
    let (output, ()) = reverie_test_support::test_cmd::<LocalState>(guest.program(), &[]).unwrap();
    assert_command_output("statx/ptrace", &output);
}
