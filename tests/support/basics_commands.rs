/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::process::Output;

use super::tools::CounterGlobal;

type Command<G> = fn(&str, &[&str]) -> Result<(Output, G), Error>;

pub(super) fn noop_tool_test(run: Command<()>) {
    let (output, _) = run("/bin/pwd", &[]).unwrap();
    // pwd should succeed & print some characters:
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

pub(super) fn counter_tool_test(run: Command<CounterGlobal>) {
    let (output, state) = run("ls", &[]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    // ls should print some characters and perform some syscalls:
    assert!(!output.stdout.is_empty());
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 30);
}

pub(super) fn error_exit_test(run: Command<CounterGlobal>) {
    let (output, state) = run("/bin/bash", &["-c", "exit 42"]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(42));
    assert_eq!(output.stdout.len(), 0);
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 0);
}

#[cfg(not(sanitized))]
pub(super) fn run_guest_command_test(run: Command<CounterGlobal>) {
    let (output, _state) = run("/bin/echo", &["-n", "abcd"]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), b"abcd");
}

#[cfg(not(sanitized))]
pub(super) fn run_guest_command_test_closure(run: Command<CounterGlobal>) {
    let msg = "abcd";
    let (output, _state) = run("/bin/echo", &["-n", msg]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), msg.as_bytes());
}
