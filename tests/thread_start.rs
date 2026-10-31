/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(not(sanitized))]

#[path = "support/thread_start_guest.rs"]
mod thread_start_guest;
#[path = "tool_fixtures/thread_start_tail.rs"]
mod thread_start_tail_tool;
#[path = "tool_fixtures/thread_start.rs"]
mod thread_start_tool;

use std::sync::atomic::Ordering;

use thread_start_tool::TestTool;

#[test]
fn thread_start_inject() {
    let state = reverie_ptrace::testing::check_fn::<TestTool, _>(thread_start_guest::guest);
    let observed = state.observed.load(Ordering::SeqCst);
    eprintln!("thread-start function: observed={observed}");
    assert!(observed);

    #[cfg(feature = "dbt")]
    rust_command_test();
}

#[test]
fn thread_start_tail_inject() {
    use thread_start_tail_tool::TestTool;

    reverie_ptrace::testing::check_fn::<TestTool, _>(|| {});
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
        .join("thread-start-inject")
        .join("manifest.json")
}

#[cfg(feature = "dbt")]
fn assert_command_output(
    label: &str,
    output: &reverie::process::Output,
    state: &thread_start_tool::StartupObserved,
) {
    let observed = state.observed.load(Ordering::SeqCst);
    eprintln!(
        "thread-start Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?} observed={observed}",
        output.status, output.stdout, output.stderr,
    );
    assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert!(observed);
}

#[cfg(feature = "dbt")]
fn rust_command_test() {
    let manifest = caller_manifest();
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let program = env!("CARGO_BIN_EXE_thread-start-rust-command-guest");
    eprintln!("thread-start Rust command image={program}");

    let native = std::process::Command::new(program).output().unwrap();
    eprintln!(
        "thread-start Rust command native: status={:?} stdout={:02x?} stderr={:02x?}",
        native.status, native.stdout, native.stderr,
    );
    assert_eq!(native.status.code(), Some(0));
    assert!(native.stdout.is_empty());
    assert!(native.stderr.is_empty());

    let (output, state) =
        reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ()).unwrap();
    assert_command_output("ptrace", &output, &state);
    let (output, state) =
        reverie_test_support::test_dbt_cmd_with_config::<TestTool>(program, &[], (), &manifest)
            .unwrap();
    assert_command_output("dbt", &output, &state);
}

#[cfg(feature = "dbt")]
#[test]
fn dbt_thread_start_missing_artifact_refuses() {
    let manifest = caller_manifest();
    let _valid_default = reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let missing = manifest.with_file_name("missing-thread-start-inject-manifest.json");
    assert!(!missing.exists());
    let error =
        reverie_test_support::test_dbt_cmd_with_config::<TestTool>("/bin/true", &[], (), &missing)
            .unwrap_err();
    eprintln!(
        "explicit missing thread-start artifact {}: {error}",
        missing.display()
    );
    let reverie::Error::Io(error) = error else {
        panic!("expected missing manifest I/O error: {error}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(feature = "dbt")]
#[test]
fn rust_thread_start_tail_command() {
    use thread_start_tail_tool::TestTool;

    let manifest = caller_manifest()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("thread-start-tail/manifest.json");
    let _valid = reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let program = env!("CARGO_BIN_EXE_thread-start-rust-command-guest");
    eprintln!("thread-start tail Rust command image={program}");
    let check = |label: &str, output: &reverie::process::Output| {
        eprintln!(
            "thread-start tail Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?}",
            output.status, output.stdout, output.stderr,
        );
        assert_eq!(output.status, reverie::ExitStatus::Exited(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    };
    let (ptrace, ()) =
        reverie_test_support::test_cmd_with_config::<TestTool>(program, &[], ()).unwrap();
    check("ptrace", &ptrace);
    let (dbt, ()) =
        reverie_test_support::test_dbt_cmd_with_config::<TestTool>(program, &[], (), &manifest)
            .unwrap();
    check("dbt", &dbt);

    let missing = manifest.with_file_name("missing-thread-start-tail-manifest.json");
    assert!(!missing.exists());
    let error =
        reverie_test_support::test_dbt_cmd_with_config::<TestTool>(program, &[], (), &missing)
            .unwrap_err();
    eprintln!(
        "explicit missing thread-start tail artifact {}: {error}",
        missing.display()
    );
    let reverie::Error::Io(error) = error else {
        panic!("expected missing manifest I/O error: {error}");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}
