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
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

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
    output_with_timeout(&mut command)
}

fn output_with_timeout(command: &mut Command) -> Output {
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let process_group = i32::try_from(child.id()).unwrap();
            // SAFETY: the child created its own process group before exec.
            let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("LiteInst example timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn launcher_does_not_activate_the_guest_constructor() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .env("REVERIE_LITEINST_COORDINATOR", "/tmp/not-a-coordinator")
        .env("REVERIE_LITEINST_EXAMPLE_TOOL", "noop")
        .arg("--help");
    let output = output_with_timeout(&mut command);

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
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .env("REVERIE_LITEINST_COORDINATOR", "guest-value")
        .arg("--tool")
        .arg("noop")
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("check-coordinator-environment");
    let output = output_with_timeout(&mut command);

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
    let output = output_with_timeout(&mut command);

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
fn exact_counter1_tool_does_not_reenter_the_guest_allocator() {
    let output = run(
        "counter1",
        &[],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-allocator",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"allocator-growth-ok\n");
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
fn exact_counter2_tool_reports_process_and_thread_totals() {
    let output = run("counter2", &[], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let summary = stderr
        .lines()
        .find_map(|line| line.strip_prefix(" [counter tool] Total system calls in process tree: "))
        .expect("counter2 summary is missing");
    let total = summary
        .split_once(',')
        .expect("counter2 total is not followed by process details")
        .0
        .parse::<u64>()
        .unwrap();
    assert!(total > 0, "{stderr}");
    assert!(
        summary.ends_with("from 1 processes, 1 thread(s)."),
        "{stderr}"
    );
}

#[test]
fn exact_chaos_tool_limits_reads_after_skip() {
    let output = run(
        "chaos",
        &["--skip", "200", "--no-interrupt"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-read",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("read("), "{stderr}");
    assert!(stderr.contains(", 1) = 1"), "{stderr}");
}

#[test]
fn exact_chaos_skip_suppresses_intervention_before_boundary() {
    let output = run(
        "chaos",
        &["--skip", "18446744073709551615", "--no-interrupt"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-full-read",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-four\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("SKIPPED"), "{stderr}");
    assert!(!stderr.contains(" = -512"), "{stderr}");
}

#[test]
fn exact_chaos_tool_interrupts_then_limits_retry() {
    let output = run(
        "chaos",
        &["--skip", "200"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-interrupt",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-interrupt-then-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(" = -512"), "{stderr}");
    assert!(stderr.contains(", 1) = 1"), "{stderr}");
}

#[test]
fn chaos_options_require_the_chaos_tool() {
    for skip in ["0", "1"] {
        let output = run("noop", &["--skip", skip], &["/bin/true"]);
        assert!(!output.status.success(), "skip={skip}: {output:?}");
        assert!(output.stdout.is_empty(), "skip={skip}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("chaos options are only valid with --tool chaos"),
            "skip={skip}: {stderr}"
        );
    }
}

#[test]
fn exact_chunky_print_delays_buffered_write_behind_later_alias_write() {
    let output = run(
        "chunky-print",
        &[],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "chunky-alias-order",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.len(), 16 * 8, "{stdout}");
    let mut observed_buffering = false;
    for index in 0..16 {
        let buffered = format!("B{index:02};");
        let pass_through = format!("P{index:02};");
        assert_eq!(stdout.matches(&buffered).count(), 1, "{stdout}");
        assert_eq!(stdout.matches(&pass_through).count(), 1, "{stdout}");
        let buffered_at = stdout.find(&buffered).unwrap();
        let pass_through_at = stdout.find(&pass_through).unwrap();
        observed_buffering |= pass_through_at < buffered_at;
    }
    assert!(observed_buffering, "output was pure pass-through: {stdout}");
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

#[test]
fn exact_strace_tool_observes_thread_and_process_exit() {
    let output = run("strace", &["--trace", "write"], &["/bin/true"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Thread "), "{stderr}");
    assert!(stderr.contains("Process "), "{stderr}");
    assert_eq!(stderr.matches("exited with status Exited(0)").count(), 2);
}
