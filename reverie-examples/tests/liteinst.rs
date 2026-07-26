/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end checks for the exact example `Tool` types on LiteInst.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

fn preload() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    let profile = deps.parent().unwrap();
    [
        profile.join("libreverie_examples.so"),
        deps.join("libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build libreverie_examples.so")
}

fn run(tool: &str, extra: &[&str], guest: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .arg("--tool")
        .arg(tool)
        .arg("--preload")
        .arg(preload())
        .args(extra)
        .arg("--")
        .args(guest);
    command.output().unwrap()
}

#[test]
fn launcher_does_not_activate_the_guest_constructor() {
    let output = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"))
        .env("REVERIE_LITEINST_COORDINATOR", "/tmp/not-a-coordinator")
        .env("REVERIE_LITEINST_EXAMPLE_TOOL", "noop")
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.starts_with(b"Usage:"), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_output_and_hides_control_environment() {
    let output = run(
        "noop",
        &[],
        &[
            "/bin/sh",
            "-c",
            "test -z \"$REVERIE_LITEINST_EXAMPLE_TOOL\" && test -z \"$REVERIE_LITEINST_COORDINATOR\" && printf hello",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_user_coordinator_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"))
        .env("REVERIE_LITEINST_COORDINATOR", "guest-value")
        .arg("--tool")
        .arg("noop")
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("check-coordinator-environment")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"coordinator-environment-preserved\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_raw_environment_entries() {
    let output = run(
        "noop",
        &[],
        &[env!("CARGO_BIN_EXE_reverie-liteinst-env-guest")],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"raw-environment-ok\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_unrelated_inherited_descriptor() {
    let inherited = File::open("/dev/null").unwrap();
    let inherited_fd = inherited.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .arg("--tool")
        .arg("noop")
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("check-fd-198");
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(inherited_fd, 198) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"fd-198-preserved\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_repeatedly_runs_fast_guest() {
    for attempt in 0..50 {
        let output = run("noop", &[], &["/bin/true"]);
        assert!(output.status.success(), "attempt {attempt}: {output:?}");
        assert!(output.stdout.is_empty(), "attempt {attempt}: {output:?}");
        assert!(output.stderr.is_empty(), "attempt {attempt}: {output:?}");
    }
}

#[test]
fn exact_counter1_tool_reports_a_nonzero_total() {
    let output = run("counter1", &[], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let total = stderr
        .lines()
        .find_map(|line| line.strip_prefix(" [counter tool] Total system calls in process tree: "))
        .expect("counter1 summary is missing")
        .parse::<u64>()
        .unwrap();
    assert!(total > 0, "{stderr}");
}

#[test]
fn exact_strace_tool_observes_filtered_write() {
    let output = run("strace", &["--trace", "write"], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = 6"), "{stderr}");
}
