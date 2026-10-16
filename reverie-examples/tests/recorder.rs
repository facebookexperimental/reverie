/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The pass-through recorder (`reverie-examples/recorder.rs`) gives a program
//! the syscall results native Linux gives it, on ptrace, for programs whose
//! record does not depend on the environment. The full corpus, with its
//! expected-mismatch ledger, runs in the environment the ledger was measured
//! in (`reverie-examples/e2e/`).

use std::path::Path;
use std::process::Command;

fn record(backend: &str, program: &[&str], output: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_recorder"))
        .args(["--backend", backend, "--output"])
        .arg(output)
        .args(program)
        .output()
        .expect("run the recorder")
}

#[test]
fn ptrace_records_what_native_linux_returns() {
    let directory = tempfile::tempdir().unwrap();
    for program in [
        &["/bin/true"][..],
        &["/bin/false"],
        &["/bin/echo", "hello"],
        &["/bin/sh", "-c", "echo a; exit 3"],
    ] {
        let native = directory.path().join("native");
        let ptrace = directory.path().join("ptrace");
        for (backend, path) in [("native", &native), ("ptrace", &ptrace)] {
            let output = record(backend, program, path);
            assert!(
                output.status.success(),
                "{backend} {program:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let native = std::fs::read_to_string(&native).unwrap();
        let ptrace = std::fs::read_to_string(&ptrace).unwrap();
        assert!(
            native.starts_with("exit ") && native.contains("\nthread 0\nexecve=ok\n"),
            "{program:?}: {native}"
        );
        assert_eq!(ptrace, native, "{program:?}");
    }
}

/// The in-guest backends host the recorder in the example preload; a program
/// whose calls all come after the loader records as natively.
#[test]
fn in_guest_backends_host_the_recorder_in_the_example_preload() {
    let directory = tempfile::tempdir().unwrap();
    for program in [&["/bin/true"][..], &["/bin/false"]] {
        let native = directory.path().join("native");
        let output = record("native", program, &native);
        assert!(output.status.success(), "native {program:?}");
        let native = std::fs::read_to_string(&native).unwrap();
        for backend in ["liteinst", "in-guest-trap"] {
            let path = directory.path().join(backend);
            let output = record(backend, program, &path);
            assert!(
                output.status.success(),
                "{backend} {program:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let got = std::fs::read_to_string(&path).unwrap();
            // The loader's calls come before the preload's constructor, so
            // the backend's record is the end of the native one.
            let (exit, calls) = got.split_once("\nthread 0\n").unwrap();
            assert_eq!(
                exit,
                native.lines().next().unwrap(),
                "{backend} {program:?}"
            );
            assert!(
                native.ends_with(calls) && !calls.is_empty(),
                "{backend} {program:?}:\n{got}\nnative:\n{native}"
            );
        }
    }
}

#[test]
fn a_backend_without_a_generic_tool_host_refuses_by_name() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("record");
    let output = record("sabre", &["/bin/true"], &output_path);
    assert!(!output.status.success(), "sabre ran");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("REFUSED:"), "sabre: {stderr}");
    assert!(!output_path.exists(), "sabre wrote a record");
}

/// DBT hosts the recorder in reverie-dbt's prototype runtime, its GlobalState
/// served from the recorder over DBT's coordinator socket: the tool sees every
/// call native Linux makes after DynamoRIO takes over, in order, and the exit
/// code. (Some results differ, a DynamoRIO descriptor and rseq among them;
/// those are the cross-backend check's ledger rows, reverie-examples/e2e/.) It
/// needs the DBT client, built by reverie-dbt/scripts/build-client.sh (found
/// beside the recorder, or through REVERIE_DBT_CLIENT).
#[test]
#[ignore = "requires the DBT client built by reverie-dbt/scripts/build-client.sh; run with --ignored"]
fn dbt_hosts_the_recorder_in_its_prototype_runtime() {
    fn names(record: &str) -> Vec<&str> {
        record
            .lines()
            .filter(|line| !line.starts_with("exit ") && !line.starts_with("thread "))
            .map(|line| line.split_once('=').map_or(line, |(name, _)| name))
            .collect()
    }
    let directory = tempfile::tempdir().unwrap();
    for program in [&["/bin/true"][..], &["/bin/false"]] {
        let native = directory.path().join("native");
        let output = record("native", program, &native);
        assert!(output.status.success(), "native {program:?}");
        let native = std::fs::read_to_string(&native).unwrap();
        let path = directory.path().join("dbt");
        let output = record("dbt", program, &path);
        assert!(
            output.status.success(),
            "dbt {program:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let got = std::fs::read_to_string(&path).unwrap();
        assert_eq!(got.lines().next(), native.lines().next(), "dbt {program:?}");
        // The execve that starts the program runs before DynamoRIO takes over.
        let mut native_names = names(&native);
        assert_eq!(native_names.remove(0), "execve", "{native}");
        assert_eq!(names(&got), native_names, "dbt {program:?}:\n{got}");
    }
}
