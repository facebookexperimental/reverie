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
//!
//! Every test here needs the cdylib's `.init_array` constructor, which only the
//! `preload-constructor` feature (a default) builds. Without it the cdylib
//! loads but installs nothing: the passthrough tests would pass vacuously and
//! `spoof_getpid_proves_result_mutation` would fail with the real pid. Such a
//! build runs one test instead, which fails by name.

#![cfg_attr(not(feature = "preload-constructor"), allow(dead_code, unused_imports))]

use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use reverie_inguest::BuiltinTool;
use reverie_inguest::SPOOF_PID;
use reverie_inguest::configure_command;

fn preload_path() -> PathBuf {
    let probe = PathBuf::from(env!("CARGO_BIN_EXE_reverie-inguest-probe"));
    let target = probe.parent().unwrap();
    [
        target.join("libreverie_inguest.so"),
        target.join("deps/libreverie_inguest.so"),
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
        std::env::set_var("REVERIE_INGUEST_LIB", preload_path());
    }
    configure_command(&mut command, tool).unwrap();
    command.output().unwrap()
}

#[cfg(feature = "preload-constructor")]
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

#[cfg(feature = "preload-constructor")]
#[test]
fn spoof_getpid_proves_result_mutation() {
    let probe = env!("CARGO_BIN_EXE_reverie-inguest-probe");
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

#[cfg(feature = "preload-constructor")]
#[test]
fn passthrough_probe_reports_real_pid() {
    // Control: under passthrough the same probe must NOT see the spoof value.
    let probe = env!("CARGO_BIN_EXE_reverie-inguest-probe");
    let output = run(probe, &[], BuiltinTool::Passthrough);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_ne!(stdout.trim(), format!("getpid={SPOOF_PID}"));
    assert!(stdout.trim().starts_with("getpid="));
}

#[cfg(feature = "preload-constructor")]
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

#[cfg(not(feature = "preload-constructor"))]
#[test]
fn smoke_tests_need_the_preload_constructor_feature() {
    panic!(
        "smoke tests need reverie-inguest's preload-constructor feature: without it the \
         cdylib has no constructor, so nothing is trapped and these tests would prove nothing"
    );
}
