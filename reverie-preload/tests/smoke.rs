/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end skeleton verification (the task's "Verify" bar):
//!
//! * the cdylib loads via `LD_PRELOAD`,
//! * its constructor installs seccomp + the SIGSYS handler,
//! * a trapped syscall is caught and mediated by the dispatcher.
//!
//! `passthrough` proves syscalls are trapped and correctly forwarded (the guest
//! behaves normally); `spoof-getpid` proves the trap can *mutate* a result; and
//! a `fork` guest proves the filter is inherited by children.

use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use reverie_preload::BuiltinTool;
use reverie_preload::SPOOF_PID;
use reverie_preload::configure_command;

fn preload_path() -> PathBuf {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_reverie-preload-probe"));
    let target = probe.parent().unwrap();
    [
        target.join("libreverie_preload.so"),
        target.join("deps/libreverie_preload.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build the preload cdylib")
}

fn run(program: &str, args: &[&str], tool: BuiltinTool) -> Output {
    let mut command = Command::new(program);
    command.args(args);
    // Point the launcher helper at the freshly built cdylib.
    unsafe {
        std::env::set_var("REVERIE_PRELOAD_LIB", preload_path());
    }
    configure_command(&mut command, tool).unwrap();
    command.output().unwrap()
}

#[test]
fn passthrough_traps_and_forwards_echo() {
    let output = run("/bin/echo", &["hello"], BuiltinTool::Passthrough);
    assert!(
        output.status.success(),
        "status={:?}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    // Correct output means every syscall /bin/echo made was trapped via SIGSYS
    // and forwarded through the trusted gate without corruption.
    assert_eq!(output.stdout, b"hello\n");
}

#[test]
fn spoof_getpid_proves_result_mutation() {
    let probe = env!("CARGO_BIN_EXE_reverie-preload-probe");
    let output = run(probe, &[], BuiltinTool::SpoofGetpid);
    assert!(
        output.status.success(),
        "status={:?}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("getpid={SPOOF_PID}"),
        "the SIGSYS trap did not rewrite the getpid result"
    );
}

#[test]
fn passthrough_probe_reports_real_pid() {
    // Control: under passthrough the same probe must NOT see the spoof value.
    let probe = env!("CARGO_BIN_EXE_reverie-preload-probe");
    let output = run(probe, &[], BuiltinTool::Passthrough);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_ne!(stdout.trim(), format!("getpid={SPOOF_PID}"));
    assert!(stdout.trim().starts_with("getpid="));
}

#[test]
fn fork_child_inherits_the_filter() {
    // A shell that forks a child (subshell) and both write output. If the child
    // did not inherit the seccomp filter + handler, its syscalls would either
    // escape instrumentation or crash with default SIGSYS; either way the guest
    // would not produce this exact output under passthrough.
    let output = run(
        "/bin/sh",
        &["-c", "(echo child) ; echo parent"],
        BuiltinTool::Passthrough,
    );
    assert!(
        output.status.success(),
        "status={:?}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"child\nparent\n");
}
