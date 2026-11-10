/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(not(sanitized), test))]

#[path = "tool_fixtures/at_random.rs"]
mod at_random_tool;
#[path = "support/at_random_command.rs"]
mod command;

use at_random_tool::PRNG_SEED;
use at_random_tool::TestTool;

fn assert_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "at-random command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert_eq!(output.stdout.len(), PRNG_SEED.len());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, PRNG_SEED);
}

#[test]
fn ptrace_at_random_command() {
    let guest = command::GuestBinary::compile();
    guest.assert_native();
    guest.record_before_launch("ptrace");
    let (output, _state): (_, ()) =
        reverie_test_support::test_cmd_with_config::<TestTool>(guest.program(), &[], ()).unwrap();
    assert_command_output("ptrace", &output);
    rust_command_test();
}

fn assert_rust_command_output(label: &str, output: &reverie::process::Output) {
    eprintln!(
        "at-random Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert_eq!(
        output.stdout,
        b"Running in guest mode (actual test).\nEntropy (intercepted) at at_random [12, 34, 56, 78, de, ad, be, ef, ca, fe, ca, fe, 87, 65, 43, 21]\n"
    );
    assert!(output.stderr.is_empty());
}

fn rust_command_test() {
    let program = reverie_test_support::guest_binary!("at-random-rust-command-guest");
    eprintln!("at-random Rust guest: image={program}");
    let (output, ()): (_, ()) =
        reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ()).unwrap();
    assert_rust_command_output("ptrace", &output);
}
