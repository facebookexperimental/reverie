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

#[test]
fn a_backend_without_a_generic_tool_host_refuses_by_name() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("record");
    for backend in ["dbt", "sabre"] {
        let output = record(backend, &["/bin/true"], &output_path);
        assert!(!output.status.success(), "{backend} ran");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("REFUSED:"), "{backend}: {stderr}");
        assert!(!output_path.exists(), "{backend} wrote a record");
    }
}
