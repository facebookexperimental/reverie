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
fn sabre_without_its_loader_refuses_by_name() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("record");
    let output = Command::new(env!("CARGO_BIN_EXE_recorder"))
        .env("SABRE_BINARY", directory.path().join("no-such-loader"))
        .args(["--backend", "sabre", "--output"])
        .arg(&output_path)
        .arg("/bin/true")
        .output()
        .expect("run the recorder");
    assert!(!output.status.success(), "sabre ran");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("REFUSED: the SaBRe loader was not found"),
        "sabre: {stderr}"
    );
    assert!(!output_path.exists(), "sabre wrote a record");
}

/// SaBRe hosts the recorder in experimental/reverie-sabre-strace's plugin, its
/// GlobalState served from the recorder: the tool sees the program's calls
/// from when SaBRe's loader has loaded it, and the exit code. (Which calls,
/// and their results, are the cross-backend check's ledger rows,
/// reverie-examples/e2e/.) It needs reverie-sabre-strace built beside the
/// recorder (`cargo build -p reverie-sabre-strace`), for the plugin and for
/// the loader it names (`--print-sabre`).
#[test]
#[ignore = "requires `cargo build -p reverie-sabre-strace`; run with --ignored"]
fn sabre_hosts_the_recorder_in_its_example_tool_plugin() {
    let binaries = Path::new(env!("CARGO_BIN_EXE_recorder")).parent().unwrap();
    let loader = Command::new(binaries.join("reverie-sabre-strace"))
        .arg("--print-sabre")
        .output()
        .expect("run reverie-sabre-strace --print-sabre");
    assert!(loader.status.success(), "{loader:?}");
    let loader = String::from_utf8(loader.stdout).unwrap();
    let directory = tempfile::tempdir().unwrap();
    for program in [&["/bin/true"][..], &["/bin/false"]] {
        let native = directory.path().join("native");
        let output = record("native", program, &native);
        assert!(output.status.success(), "native {program:?}");
        let native = std::fs::read_to_string(&native).unwrap();
        let path = directory.path().join("sabre");
        let output = Command::new(env!("CARGO_BIN_EXE_recorder"))
            .env("SABRE_BINARY", loader.trim_end())
            .args(["--backend", "sabre", "--output"])
            .arg(&path)
            .args(program)
            .output()
            .expect("run the recorder");
        assert!(
            output.status.success(),
            "sabre {program:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let got = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            got.lines().next(),
            native.lines().next(),
            "sabre {program:?}"
        );
        assert!(
            got.ends_with("\nexit_group=?\n") && got.lines().count() > 3,
            "sabre {program:?}:\n{got}"
        );
    }
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
