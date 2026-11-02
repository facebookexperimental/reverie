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

/// Every run gets the sanitizer settings reverie-ptrace adds to its guest's
/// environment (tracer.rs), so that ptrace's guest has the native one: the
/// number of variables decides when `sh -c` grows its heap.
fn record(backend: &str, program: &[&str], output: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_recorder"))
        .env("ASAN_OPTIONS", "detect_leaks=0")
        .env("LSAN_OPTIONS", "detect_leaks=0")
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

// These use the real recorder/GlobalState route, not scripted RPC responses.
// A static raw-entry fixture makes the first application syscall observable.
fn compile_descriptor_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/recorder_descriptor_lifecycle.c");
    let guest = directory.path().join("recorder-descriptor-lifecycle");
    let output = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args([
            "-std=c11",
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-nostdlib",
            "-static",
            "-Wl,-e,_start",
            "-Wl,--build-id=none",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&guest)
        .output()
        .expect("compile raw-entry descriptor fixture");
    assert!(
        output.status.success(),
        "{}: {}",
        source.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "descriptor fixture: compiler={:?} source={} guest={} image={:02x?}",
        std::env::var_os("CC").unwrap_or_else(|| "cc".into()),
        source.display(),
        guest.display(),
        std::fs::read(&guest).expect("retain compiled descriptor image")
    );
    (directory, guest)
}

#[derive(Clone, Debug)]
struct DescriptorRecord {
    words: Vec<i64>,
    threads: Vec<Vec<String>>,
    text: String,
}

fn descriptor_frontend(backend: &str, output_path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_recorder"));
    command
        .args(["--backend", backend, "--output"])
        .arg(output_path);
    command
}

fn descriptor_command(backend: &str, guest: &Path, mode: &str, output_path: &Path) -> Command {
    use std::os::unix::process::CommandExt as _;

    let mut command = descriptor_frontend(backend, output_path);
    // The lowest-free-descriptor fixture starts with only its standard streams.
    // Mark the fork copy only; retain the parent's lease and Rust's exec-error
    // pipe until the recorder is successfully exec'd.
    unsafe {
        command.pre_exec(|| {
            const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.arg(guest).arg(mode);
    command
}

fn record_descriptors(
    backend: &str,
    guest: &Path,
    mode: &str,
    output_path: &Path,
) -> DescriptorRecord {
    let output = descriptor_command(backend, guest, mode, output_path)
        .output()
        .expect("run raw-entry recorder fixture");
    parse_descriptor_output(backend, mode, output_path, output)
}

fn retain_recorder_output(label: &str, output: &std::process::Output, path: &Path) {
    eprintln!(
        "recorder bytes {label}: status={:?} stdout={:02x?} stderr={:02x?} record={:02x?}",
        output.status.code(),
        output.stdout,
        output.stderr,
        std::fs::read(path)
    );
}

fn parse_descriptor_output(
    backend: &str,
    mode: &str,
    output_path: &Path,
    output: std::process::Output,
) -> DescriptorRecord {
    retain_recorder_output(&format!("{backend}/{mode}"), &output, output_path);
    let text = std::fs::read_to_string(output_path);
    // Keep successful controls and failed guest output in --nocapture receipts
    // before the fixture/record TempDir is dropped.
    eprintln!(
        "descriptor {backend}/{mode}: status={} stdout={:02x?} stderr={}\nrecord:\n{}",
        output.status,
        output.stdout,
        String::from_utf8_lossy(&output.stderr),
        text.as_deref().unwrap_or("<no UTF-8 recorder output>")
    );
    assert!(output.status.success(), "{backend} {mode}: {output:?}");
    let text = text.expect("read complete recorder output");
    let mut lines = text.lines();
    // The recorder's own exit code alone does not establish the guest's exit.
    assert_eq!(lines.next(), Some("exit 0"), "{backend} {mode}:\n{text}");
    let mut threads: Vec<Vec<String>> = Vec::new();
    for line in lines {
        if let Some(number) = line.strip_prefix("thread ") {
            assert_eq!(number.parse::<usize>().unwrap(), threads.len(), "{text}");
            threads.push(Vec::new());
        } else {
            assert!(line.contains('='), "{text}");
            threads
                .last_mut()
                .expect("event after thread header")
                .push(line.into());
        }
    }
    assert!(!threads.is_empty(), "{text}");
    if backend == "native" {
        // This launch exec precedes _start; remove nothing from DBT's record.
        assert_eq!(threads[0].remove(0), "execve=ok", "{text}");
    }
    assert_eq!(output.stdout.len() % 8, 0, "{backend} {mode}: {output:?}");
    let words = output
        .stdout
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bytes| i64::from_le_bytes(*bytes))
        .collect();
    DescriptorRecord {
        words,
        threads,
        text,
    }
}

fn assert_descriptor_records(mode: &str, native: DescriptorRecord, ptrace: DescriptorRecord) {
    let mut expected = vec!["openat", "openat", "write", "close", "close", "exit_group"];
    if mode == "warm" {
        expected.insert(0, "getpid");
    }
    for record in [&native, &ptrace] {
        assert_eq!(record.threads.len(), 1, "{record:?}");
        let names: Vec<_> = record.threads[0]
            .iter()
            .map(|event| event.split_once('=').unwrap().0)
            .collect();
        // Check the first-call premise in the real record, not just the source.
        assert_eq!(names, expected, "{record:?}");
    }
    assert_eq!(
        native.words,
        [3, 4],
        "native lowest-free controls: {native:?}"
    );
    assert_eq!(
        ptrace.words, native.words,
        "first two available descriptors held together: {ptrace:?}"
    );
    // Retain all results too: the recorder must report the actual guest fd.
    assert_eq!(ptrace.threads, native.threads, "{ptrace:?}\n{native:?}");
}

fn check_ptrace_first_descriptor(mode: &str) {
    let (directory, guest) = compile_descriptor_fixture();
    let native = record_descriptors("native", &guest, mode, &directory.path().join("native"));
    let mut ptrace = record_descriptors("ptrace", &guest, mode, &directory.path().join("ptrace"));
    // Require the complete native report before making a post-launch view.
    assert_eq!(ptrace.text, native.text, "{ptrace:?}\n{native:?}");
    assert_eq!(ptrace.threads[0].remove(0), "execve=ok", "{ptrace:?}");
    assert_descriptor_records(mode, native, ptrace);
}

#[test]
fn ptrace_recorder_cold_open_keeps_the_first_linux_descriptor() {
    check_ptrace_first_descriptor("cold");
}

#[test]
fn ptrace_recorder_prior_rpc_keeps_the_first_linux_descriptor() {
    check_ptrace_first_descriptor("warm");
}

#[test]
fn ptrace_recorder_descriptor_oracle_rejects_missing_or_wrong_events() {
    let (directory, guest) = compile_descriptor_fixture();
    let native = record_descriptors("native", &guest, "cold", &directory.path().join("native"));
    let mut ptrace = record_descriptors("ptrace", &guest, "cold", &directory.path().join("ptrace"));
    assert_eq!(ptrace.threads[0].remove(0), "execve=ok", "{ptrace:?}");
    // The unchanged oracle first accepts the real records, so each rejection
    // below comes from the one mutation applied to the real ptrace record.
    assert_descriptor_records("cold", native.clone(), ptrace.clone());

    // A Tool that records nothing reports the thread with no events.
    let mut eventless = ptrace.clone();
    eventless.threads = vec![Vec::new()];
    let control = native.clone();
    assert!(
        std::panic::catch_unwind(move || assert_descriptor_records("cold", control, eventless))
            .is_err()
    );

    // The right event names with a result other than the guest's actual one.
    let mut wrong = ptrace;
    let event = &mut wrong.threads[0][0];
    let (name, _) = event.split_once('=').unwrap();
    *event = format!("{name}=wrong");
    assert!(
        std::panic::catch_unwind(move || assert_descriptor_records("cold", native, wrong)).is_err()
    );
}

#[test]
fn ptrace_recorder_preserves_inherited_stdin() {
    use std::io::Write as _;

    let directory = tempfile::tempdir().unwrap();
    let (label, backend, expected) = ("ptrace", "ptrace", &b"hello\n"[..]);
    let path = directory.path().join(label);
    // std::io::pipe creates close-on-exec descriptors. Supply exactly six
    // bytes and EOF before spawning, as in the shared caller control.
    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(b"hello\n").unwrap();
    drop(writer);
    let output = descriptor_frontend(backend, &path)
        .stdin(reader)
        .arg("/bin/cat")
        .output()
        .expect("run Recorder with fresh inherited input");
    retain_recorder_output(label, &output, &path);
    assert!(output.status.success(), "{label}: {output:?}");
    let report = std::fs::read_to_string(&path).unwrap();
    assert_eq!(report.lines().next(), Some("exit 0"), "{label}: {report}");
    assert_eq!(output.stdout, expected, "{label}: {output:?}");
    assert!(output.stderr.is_empty(), "{label}: {output:?}");
}
