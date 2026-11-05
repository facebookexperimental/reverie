/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Cross-tool, cross-backend conformance for the environment-independent
//! programs (the full corpus with its expected-mismatch ledger lives in
//! `reverie-examples/e2e/`).
//!
//! One program runs under several example tools on every first-party
//! backend. The pass-through recorder is the reference: its record is the
//! syscall stream the backend gave the program. The other tools must agree
//! with that record on the same backend, and must not change what the
//! program prints or how it exits:
//!
//! * `counter1` counts every syscall event its tool handler receives. The
//!   recorder's comparable record omits the vDSO calls (`VDSO` in
//!   `recorder_tool.rs`), so the counter total is the record's call count
//!   plus the vDSO calls `strace_minimal` saw.
//! * `strace_minimal` prints each syscall it intercepts. With the vDSO
//!   calls removed, its call-name sequence is the recorder's. One named
//!   exception: an in-guest tool prints through the guest's own stderr, so
//!   when the guest closes stderr during exit cleanup (for example
//!   `/bin/echo` closes descriptors 1 and 2 before `exit_group`), the
//!   in-guest print for that final call has nowhere to go. The recorder
//!   and counter report through tool RPC and still record it.
//! * `noop` subscribes to nothing and must be transparent: the program's
//!   stdout, stderr, and exit status are its own.
//!
//! Agreement between tools is not enough on its own: a backend that
//! delivered no events to any tool would satisfy it vacuously. Each
//! backend's record is therefore also anchored to a native record of the
//! same program, and to landmark calls every run of it must contain. The
//! judged call-by-call comparison against native, with its ledger of known
//! backend differences, is the e2e comparator's job.

use std::path::Path;
use std::process::Command;
use std::process::Output;

/// The vDSO calls the recorder's comparable record omits: the kernel
/// usually answers them in the process, while a backend may turn them
/// into syscalls a tool can see. The list is the recorder's own, so the
/// two cannot drift apart.
use reverie_examples::recorder_tool::VDSO;

/// Every run gets the sanitizer settings reverie-ptrace adds to its guest's
/// environment (tracer.rs), so every tool's guest has the same one: the
/// number of variables decides when `sh -c` grows its heap. Cargo's own
/// loader variables for test binaries (`LD_LIBRARY_PATH`, and any ambient
/// `LD_PRELOAD`) are removed: inherited into a guest they change the
/// dynamic loader's searches, and each backend's loader answers those
/// searches with a different number of syscalls.
fn tool_command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .env("ASAN_OPTIONS", "detect_leaks=0")
        .env("LSAN_OPTIONS", "detect_leaks=0")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD");
    command
}

/// Whether this host can run the KVM backend. KVM needs a usable
/// `/dev/kvm`; when `REVERIE_REQUIRE_KVM` is set its absence is a failure,
/// as in `tests/kvm_cli.rs`.
fn kvm_available() -> bool {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => true,
        Err(error) if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() => {
            panic!("conformance tests require usable /dev/kvm: {error}")
        }
        Err(error) => {
            eprintln!("skipping kvm conformance backend: cannot open /dev/kvm: {error}");
            false
        }
    }
}

fn run(binary: &str, backend: &str, program: &[&str]) -> Output {
    tool_command(binary)
        .args(["--backend", backend, "--"])
        .args(program)
        .output()
        .expect("run the tool launcher")
}

fn run_direct(program: &[&str]) -> Output {
    tool_command(program[0])
        .args(&program[1..])
        .output()
        .expect("run the program directly")
}

/// The recorder's record for one run: its exit line and every call name,
/// in the record's thread order (these programs are single-threaded).
fn record(backend: &str, program: &[&str], output: &Path) -> (i32, Vec<String>) {
    let run = tool_command(env!("CARGO_BIN_EXE_recorder"))
        .args(["--backend", backend, "--output"])
        .arg(output)
        .args(program)
        .output()
        .expect("run the recorder");
    assert!(
        run.status.success(),
        "recorder {backend} {program:?}: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let text = std::fs::read_to_string(output).unwrap();
    let mut lines = text.lines();
    let exit: i32 = lines
        .next()
        .and_then(|line| line.strip_prefix("exit "))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("recorder {backend} {program:?}: bad record: {text}"));
    let calls = lines
        .filter(|line| !line.starts_with("thread "))
        .map(|line| {
            line.split_once('=')
                .map_or(line, |(name, _)| name)
                .to_owned()
        })
        .collect();
    (exit, calls)
}

/// The syscall names `strace_minimal` printed, one per intercepted call.
/// Only the tool's own `[pid N] name(...) = ?` lines count: the guest's
/// stderr reaches the same stream on some backends, and a guest line that
/// merely contains `] ` is not a syscall.
fn strace_names(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| {
            let call = line.strip_prefix("[pid ")?.split_once("] ")?.1;
            let (name, _) = call.split_once('(')?;
            (!name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
            .then(|| name.to_owned())
        })
        .collect()
}

fn counter1_total(output: &Output, backend: &str, program: &[&str]) -> usize {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("counter1-global syscalls="))
        .and_then(|total| total.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "counter1 {backend} {program:?}: no total in stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

const PROGRAMS: &[&[&str]] = &[
    &["/bin/true"],
    &["/bin/echo", "hello"],
    &["/bin/sh", "-c", "echo a; exit 3"],
];

/// The calls every record of `program` must contain, in order, ending the
/// run: the anchor that keeps tool agreement from passing on an empty or
/// nearly empty stream. `/bin/true` makes no observable call but its exit;
/// the other two write before they exit.
fn assert_landmarks(program: &[&str], backend: &str, recorded: &[String]) {
    assert!(!recorded.is_empty(), "{backend} {program:?}: empty record");
    assert_eq!(
        recorded.last().map(String::as_str),
        Some("exit_group"),
        "{backend} {program:?}: record does not end in exit_group: {recorded:?}"
    );
    if program[0] != "/bin/true" {
        let write = recorded
            .iter()
            .position(|call| call == "write")
            .unwrap_or_else(|| panic!("{backend} {program:?}: no write in {recorded:?}"));
        assert!(
            write < recorded.len() - 1,
            "{backend} {program:?}: write is not before the exit: {recorded:?}"
        );
    }
}

fn tools_agree_with_the_recorder(backend: &str) {
    let directory = tempfile::tempdir().unwrap();
    for (index, program) in PROGRAMS.iter().enumerate() {
        // The native anchor for this program: plain ptrace syscall stops,
        // no Reverie. Its stream is what a backend is compared against
        // call by call in the judged e2e run; here it bounds this test.
        let (native_exit, native) = record(
            "native",
            program,
            &directory.path().join(format!("native-{index}")),
        );
        assert_landmarks(program, "native", &native);
        let (exit, recorded) = record(
            backend,
            program,
            &directory.path().join(format!("{backend}-{index}")),
        );
        assert_eq!(exit, native_exit, "{backend} {program:?}");
        assert_landmarks(program, backend, &recorded);
        match backend {
            // The recorder test already proves the full record here;
            // the name sequence is this test's anchor.
            "ptrace" => assert_eq!(recorded, native, "{backend} {program:?}"),
            // Results may differ from native (for example `rseq`
            // answering ENOSYS); the call count may not.
            "kvm" => assert_eq!(recorded.len(), native.len(), "{backend} {program:?}"),
            // In-guest tools start late and legitimately miss calls;
            // the judged native comparison is the e2e ledger's job.
            _ => assert!(
                recorded.len() <= native.len(),
                "{backend} {program:?}: in-guest record longer than native"
            ),
        }
        let direct = run_direct(program);
        assert_eq!(direct.status.code(), Some(exit), "{backend} {program:?}");

        let strace = run(env!("CARGO_BIN_EXE_strace_minimal"), backend, program);
        assert_eq!(strace.status.code(), Some(exit), "{backend} {program:?}");
        assert_eq!(strace.stdout, direct.stdout, "{backend} {program:?}");
        let printed = strace_names(&strace);
        let vdso = printed
            .iter()
            .filter(|name| VDSO.contains(&name.as_str()))
            .count();
        let comparable: Vec<String> = printed
            .iter()
            .filter(|name| !VDSO.contains(&name.as_str()))
            .cloned()
            .collect();
        // The one named exception from the module documentation: the
        // in-guest print of a final call the guest makes after closing
        // its own stderr. Everything before it must still agree. Among
        // PROGRAMS only `/bin/echo` takes this path (its record ends
        // `close(1), close(2), exit_group`); `/bin/true` and the shell
        // keep stderr open and take full equality, so this exemption
        // cannot hide a missing print there.
        let in_guest = matches!(backend, "liteinst" | "in-guest-trap");
        if in_guest
            && recorded.len() >= 3
            && recorded[recorded.len() - 3..] == ["close", "close", "exit_group"]
            && comparable.len() + 1 == recorded.len()
            && comparable[..] == recorded[..recorded.len() - 1]
        {
            // The guest closed stderr before `exit_group` (see above).
        } else {
            assert_eq!(comparable, recorded, "{backend} {program:?}");
        }

        // A separate execution from the strace run above: transferring
        // its vDSO count assumes these programs make the same calls
        // every run, the stability the e2e corpus requires natively.
        let counter = run(env!("CARGO_BIN_EXE_counter1"), backend, program);
        assert_eq!(counter.status.code(), Some(exit), "{backend} {program:?}");
        assert_eq!(counter.stdout, direct.stdout, "{backend} {program:?}");
        assert_eq!(
            counter1_total(&counter, backend, program),
            recorded.len() + vdso,
            "{backend} {program:?}"
        );

        let noop = run(env!("CARGO_BIN_EXE_noop"), backend, program);
        assert_eq!(noop.status.code(), Some(exit), "{backend} {program:?}");
        assert_eq!(noop.stdout, direct.stdout, "{backend} {program:?}");
        assert_eq!(noop.stderr, direct.stderr, "{backend} {program:?}");
    }
}

#[test]
fn ptrace_tools_agree_with_the_recorder() {
    tools_agree_with_the_recorder("ptrace");
}

#[test]
fn liteinst_tools_agree_with_the_recorder() {
    tools_agree_with_the_recorder("liteinst");
}

#[test]
fn in_guest_trap_tools_agree_with_the_recorder() {
    tools_agree_with_the_recorder("in-guest-trap");
}

#[test]
fn kvm_tools_agree_with_the_recorder() {
    if kvm_available() {
        tools_agree_with_the_recorder("kvm");
    }
}
