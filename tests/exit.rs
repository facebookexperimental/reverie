/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(not(sanitized))]

//! Tests surrounding exit logic.

#[path = "support/exit_command.rs"]
mod command;
#[path = "tool_fixtures/exit.rs"]
mod exit_tool;
#[path = "support/exit_rust_guest.rs"]
mod rust_guest;

use exit_tool::GlobalState;
use exit_tool::InjectExitTool;
use reverie::ExitStatus;
use reverie::Tool;
use reverie::process::Output;

/// The actual do-nothing Tool: it intercepts nothing and reports nothing.
#[derive(Debug, Default)]
struct NoopTool;
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();
}

fn record_command(label: &str, output: &Output, state: &GlobalState) {
    eprintln!(
        "injected exit {label}: status={:?} stdout={:02x?} stderr={:02x?} exited={:?}",
        output.status,
        output.stdout,
        output.stderr,
        *state.exited.lock().unwrap(),
    );
}

fn assert_exit_oracle(output: &Output, state: &GlobalState) {
    assert_eq!(output.status, ExitStatus::Exited(42));
    let mut mg = state.exited.lock().unwrap();
    assert_eq!(mg.pop().map(|x| x.1), Some(ExitStatus::Exited(42)));
    assert!(mg.is_empty());
}

#[test]
fn ptrace_inject_exit_command() {
    let guest = command::GuestBinary::compile();
    guest.assert_native();
    guest.record_before_launch("ptrace");
    let (output, state) =
        reverie_test_support::test_cmd::<InjectExitTool>(guest.program(), &[]).unwrap();
    record_command("ptrace", &output, &state);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_exit_oracle(&output, &state);
}

#[test]
fn ptrace_noop_rejects_injected_exit_oracle() {
    let guest = command::GuestBinary::compile();
    guest.assert_native();
    guest.record_before_launch("noop");
    // The actual Noop Tool injects no exit and reports no exit RPC, so its real
    // run is paired with an empty exit GlobalState.
    let (output, ()) = reverie_test_support::test_cmd::<NoopTool>(guest.program(), &[]).unwrap();
    let state = GlobalState::default();
    record_command("noop", &output, &state);
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(state.exited.lock().unwrap().is_empty());
    assert!(std::panic::catch_unwind(|| assert_exit_oracle(&output, &state)).is_err());
}

#[test]
fn smoke() {
    use reverie_ptrace::testing::test_fn;

    let (output, state) = test_fn::<InjectExitTool, _>(rust_guest::smoke).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(42));
    let mut mg = state.exited.lock().unwrap();
    assert_eq!(mg.pop().map(|x| x.1), Some(ExitStatus::Exited(42)));
    assert!(mg.is_empty());
    drop(mg);

    check_rust_command();
}

fn check_rust_command() {
    let program = reverie_test_support::guest_binary!("exit-rust-command-guest");
    eprintln!("injected exit Rust command: image={program}");

    let output = std::process::Command::new(program).output().unwrap();
    eprintln!(
        "injected exit rust/native: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, rust_guest::PRE_BODY_MARKER);
    assert!(output.stderr.is_empty());

    let (output, state) = reverie_test_support::test_cmd::<InjectExitTool>(program, &[]).unwrap();
    record_command("rust/ptrace", &output, &state);
    assert_eq!(output.stdout, rust_guest::PRE_BODY_MARKER);
    assert!(output.stderr.is_empty());
    assert_exit_oracle(&output, &state);

    let (output, ()) = reverie_test_support::test_cmd::<NoopTool>(program, &[]).unwrap();
    let state = GlobalState::default();
    record_command("rust/noop", &output, &state);
    assert_eq!(output.stdout, rust_guest::PRE_BODY_MARKER);
    assert!(output.stderr.is_empty());
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert!(state.exited.lock().unwrap().is_empty());
    assert!(std::panic::catch_unwind(|| assert_exit_oracle(&output, &state)).is_err());
}
