/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

fn kvm_available() -> bool {
    match OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        Ok(_) => true,
        Err(error) if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() => {
            panic!("KVM CLI tests require usable /dev/kvm: {error}")
        }
        Err(error) => {
            eprintln!("skipping KVM CLI tests: cannot open /dev/kvm: {error}");
            false
        }
    }
}

fn run(binary: &str, arguments: &[&str]) -> Output {
    Command::new(binary).args(arguments).output().unwrap()
}

fn run_with_stdin(binary: &str, arguments: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(binary)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn run_with_closed_stdin(binary: &str, arguments: &[&str]) -> Output {
    let mut command = Command::new(binary);
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: This closure runs after fork and before exec, and only closes the
    // child's inherited descriptor without touching memory shared with threads.
    unsafe {
        command.pre_exec(|| {
            if libc::close(libc::STDIN_FILENO) == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EBADF) {
                    return Err(error);
                }
            }
            Ok(())
        });
    }
    command.output().unwrap()
}

fn non_executable_copy() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("reverie-kvm-non-executable-{}", std::process::id()));
    fs::copy("/bin/true", &path).unwrap();
    // Root may execute a regular file when any execute bit is set. Non-root
    // uses 0401 to exercise owner-class selection despite the other bit.
    // SAFETY: geteuid has no preconditions.
    let mode = if unsafe { libc::geteuid() } == 0 {
        0o000
    } else {
        0o401
    };
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn production_example_clis_run_real_program_with_kvm_guest() {
    if !kvm_available() {
        return;
    }

    let counter1 = run(
        env!("CARGO_BIN_EXE_reverie-kvm-counter1"),
        &["/bin/echo", "counter1"],
    );
    assert_success(&counter1);
    assert_eq!(counter1.stdout, b"counter1\n");
    assert!(String::from_utf8_lossy(&counter1.stderr).contains("counter1-global syscalls="));

    let counter2 = run(
        env!("CARGO_BIN_EXE_reverie-kvm-counter2"),
        &["/bin/echo", "counter2"],
    );
    assert_success(&counter2);
    assert_eq!(counter2.stdout, b"counter2\n");
    assert!(String::from_utf8_lossy(&counter2.stderr).contains("from 1 processes"));

    let noop = run(
        env!("CARGO_BIN_EXE_noop"),
        &["--runner", "kvm", "--no-host-envs", "/bin/echo", "noop"],
    );
    assert_success(&noop);
    assert_eq!(noop.stdout, b"noop\n");
    assert!(noop.stderr.is_empty());

    let false_status = run(
        env!("CARGO_BIN_EXE_noop"),
        &["--runner", "kvm", "--no-host-envs", "/bin/false"],
    );
    assert_eq!(false_status.status.code(), Some(1));
    assert!(false_status.stdout.is_empty());
    assert!(false_status.stderr.is_empty());

    let cat = run_with_stdin(
        env!("CARGO_BIN_EXE_noop"),
        &["--runner", "kvm", "--no-host-envs", "/bin/cat"],
        b"stdin-through-kvm\n",
    );
    assert_success(&cat);
    assert_eq!(cat.stdout, b"stdin-through-kvm\n");
    assert!(cat.stderr.is_empty());

    let strace = run(
        env!("CARGO_BIN_EXE_strace"),
        &[
            "--runner",
            "kvm",
            "--trace",
            "write",
            "--no-host-envs",
            "/bin/echo",
            "strace",
        ],
    );
    assert_success(&strace);
    assert_eq!(strace.stdout, b"strace\n");
    assert!(String::from_utf8_lossy(&strace.stderr).contains("[pid 1] write("));
}

#[test]
fn kvm_runner_preserves_process_boundary_errors() {
    if !kvm_available() {
        return;
    }

    let closed_stdin = run_with_closed_stdin(
        env!("CARGO_BIN_EXE_noop"),
        &["--runner", "kvm", "--no-host-envs", "/bin/cat"],
    );
    // Rust normalizes an inherited closed standard descriptor to /dev/null.
    // The guest must observe that EOF rather than a Tokio or KVM descriptor
    // that happened to reuse fd 0 during runner initialization.
    assert_success(&closed_stdin);
    assert!(closed_stdin.stdout.is_empty());
    assert!(closed_stdin.stderr.is_empty());

    let non_executable = non_executable_copy();
    let output = run(
        env!("CARGO_BIN_EXE_noop"),
        &[
            "--runner",
            "kvm",
            "--no-host-envs",
            non_executable.to_str().unwrap(),
        ],
    );
    fs::remove_file(&non_executable).unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not executable"));

    let invalid_value = OsString::from_vec(vec![0xff]);
    let output = Command::new(env!("CARGO_BIN_EXE_noop"))
        .args(["--runner", "kvm", "/bin/true"])
        .env("REVERIE_KVM_INVALID_UTF8", invalid_value)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("non-UTF-8 environment value"));
}
