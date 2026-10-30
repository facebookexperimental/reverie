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

        #[cfg(feature = "dbt")]
        rust_command_test();
    }

    #[cfg(feature = "dbt")]
    fn caller_manifest() -> std::path::PathBuf {
        let executable = std::env::current_exe().unwrap();
        executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("reverie-dbt-callers")
            .join("suppression-tgkill")
            .join("manifest.json")
    }

    #[cfg(feature = "dbt")]
    type CommandResult = Result<
        (
            reverie::process::Output,
            super::suppression_tool::SuppressionCount,
        ),
        reverie::Error,
    >;

    #[cfg(feature = "dbt")]
    fn record_rust_command_result(label: &str, result: &CommandResult) {
        match result {
            Ok((output, state)) => {
                let count = state.count.load(Ordering::SeqCst);
                eprintln!(
                    "suppression Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?} count={count}",
                    output.status, output.stdout, output.stderr,
                );
            }
            Err(error) => {
                eprintln!("suppression Rust command {label}: error={error:?}");
                let output = match error {
                    reverie::Error::Io(error) => reverie_dbt::failed_run_output(error),
                    _ => None,
                };
                match output {
                    Some(output) => eprintln!(
                        "suppression Rust command {label} failed: status={:?} stdout={:02x?} stderr={:02x?}",
                        output.status, output.stdout, output.stderr,
                    ),
                    None => {
                        eprintln!("suppression Rust command {label} failed: output unavailable")
                    }
                }
            }
        }
    }

    #[cfg(feature = "dbt")]
    fn assert_rust_command_result(label: &str, result: CommandResult) {
        record_rust_command_result(label, &result);
        let (output, state) = result.expect("Rust suppression command should succeed");
        assert_eq!(output.status, reverie::ExitStatus::Exited(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert_eq!(state.count.load(Ordering::SeqCst), 100);
    }

    #[cfg(feature = "dbt")]
    fn rust_command_test() {
        let program = env!("CARGO_BIN_EXE_suppression-rust-command-guest");
        eprintln!("suppression Rust command image={program}");
        let ptrace = reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ());
        assert_rust_command_result("ptrace", ptrace);

        let manifest = caller_manifest();
        let dbt =
            reverie_test_support::test_dbt_cmd_with_config::<TestTool>(program, &[], (), &manifest);
        assert_rust_command_result("dbt", dbt);
    }

    #[cfg(feature = "dbt")]
    #[test]
    fn dbt_suppression_missing_artifact_refuses() {
        let manifest = caller_manifest();
        reverie_dbt::CallerArtifact::load(&manifest).unwrap();
        let missing = manifest.with_file_name("missing-suppression-manifest.json");
        assert!(!missing.exists());
        let program = env!("CARGO_BIN_EXE_suppression-rust-command-guest");
        let error =
            reverie_test_support::test_dbt_cmd_with_config::<TestTool>(program, &[], (), &missing)
                .unwrap_err();
        eprintln!(
            "explicit missing suppression artifact {}: {error}",
            missing.display()
        );
        let reverie::Error::Io(error) = error else {
            panic!("expected missing manifest I/O error: {error}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(feature = "dbt")]
    #[test]
    fn dbt_suppression_noop_refuses() {
        let manifest = caller_manifest();
        let noop = manifest
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("basics-noop/manifest.json");
        reverie_dbt::CallerArtifact::load(&noop).unwrap();
        let program = env!("CARGO_BIN_EXE_suppression-rust-command-guest");
        eprintln!("suppression Rust command image={program}");
        // The authenticated artifact contains the actual Noop Tool. The
        // controller keeps the same real global type; failure exposes no state.
        let result =
            reverie_test_support::test_dbt_cmd_with_config::<TestTool>(program, &[], (), &noop);
        record_rust_command_result("noop", &result);
        let reverie::Error::Io(error) = result.unwrap_err() else {
            panic!("expected captured Noop refusal");
        };
        let output = reverie_dbt::failed_run_output(&error).expect("actual failed-run capture");
        assert_eq!(output.status.and_then(|status| status.code()), Some(101));
        assert!(output.stdout.is_empty());
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        let refusal = "reverie-dbt: caller-tail-lifecycle-unsupported";
        assert_eq!(stderr.lines().next(), Some(refusal));
        assert_eq!(stderr.lines().filter(|line| *line == refusal).count(), 1);
    }
}
