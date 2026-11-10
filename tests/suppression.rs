/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests that syscall suppression works. That is, when we intercept a syscall,
//! we should not run the real syscall.

#[cfg(all(not(sanitized), test))]
#[path = "support/suppression_rust_guest.rs"]
mod suppression_rust_guest;

#[cfg(all(not(sanitized), test))]
#[path = "tool_fixtures/suppression.rs"]
mod suppression_tool;

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::sync::atomic::Ordering;

    use reverie_ptrace::testing::check_fn;

    use super::suppression_rust_guest;
    use super::suppression_tool::TestTool;

    #[test]
    fn suppress_tgkill() {
        let state = check_fn::<TestTool, _>(suppression_rust_guest::guest);
        let count = state.count.load(Ordering::SeqCst);
        eprintln!("suppression function: count={count}");
        assert_eq!(count, 100);

        rust_command_test();
    }

    /// The same guest body as an ordinary command under ptrace: the Tool
    /// suppresses all 100 tgkill calls, so the command exits 0 with no output.
    fn rust_command_test() {
        let program = reverie_test_support::guest_binary!("suppression-rust-command-guest");
        eprintln!("suppression Rust command image={program}");
        let (output, state) =
            reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ())
                .expect("Rust suppression command should succeed");
        let count = state.count.load(Ordering::SeqCst);
        eprintln!(
            "suppression Rust command ptrace: status={:?} stdout={:02x?} stderr={:02x?} count={count}",
            output.status, output.stdout, output.stderr,
        );
        assert_eq!(output.status, reverie::ExitStatus::Exited(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert_eq!(count, 100);
    }
}
