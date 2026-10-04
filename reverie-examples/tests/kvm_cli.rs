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
use std::time::Duration;
use std::time::Instant;

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

fn counter2_total(output: &Output) -> u64 {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("[counter tool] Total system calls in process tree: ")
                .and_then(|summary| summary.split(',').next())
                .and_then(|total| total.parse().ok())
        })
        .unwrap_or_else(|| panic!("missing counter2 total in {:?}", output.stderr))
}

fn median_runtime(binary: &str, arguments: &[&str]) -> Duration {
    const SAMPLES: usize = 3;

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let output = run(binary, arguments);
        let elapsed = started.elapsed();
        assert_success(&output);
        samples.push(elapsed);
    }
    samples.sort_unstable();
    samples[SAMPLES / 2]
}

fn benchmark_pair(
    tool: &str,
    ptrace_binary: &str,
    ptrace_arguments: &[&str],
    kvm_binary: &str,
    kvm_arguments: &[&str],
) {
    let ptrace = median_runtime(ptrace_binary, ptrace_arguments);
    let kvm = median_runtime(kvm_binary, kvm_arguments);
    eprintln!(
        "reverie-tool-microbenchmark tool={tool} samples=3 ptrace_us={} kvm_us={}",
        ptrace.as_micros(),
        kvm.as_micros(),
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

    let awk = run(
        env!("CARGO_BIN_EXE_noop"),
        &[
            "--runner",
            "kvm",
            "--no-host-envs",
            "/usr/bin/awk",
            "BEGIN { print 42 }",
        ],
    );
    assert_success(&awk);
    assert_eq!(awk.stdout, b"42\n");
    assert!(awk.stderr.is_empty());

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
            "execve",
            "--trace",
            "write",
            "--no-host-envs",
            "/bin/echo",
            "strace",
        ],
    );
    assert_success(&strace);
    assert_eq!(strace.stdout, b"strace\n");
    let strace_stderr = String::from_utf8_lossy(&strace.stderr);
    assert!(strace_stderr.contains("[pid 1] execve("));
    assert!(strace_stderr.contains("[pid 1] write("));

    let chaos = run(
        env!("CARGO_BIN_EXE_chaos"),
        &[
            "--runner",
            "kvm",
            "--no-read",
            "--no-recv",
            "--no-interrupt",
            "--no-host-envs",
            "/bin/echo",
            "chaos",
        ],
    );
    assert_success(&chaos);
    assert_eq!(chaos.stdout, b"chaos\n");

    let trace_path = std::env::temp_dir().join(format!(
        "reverie-kvm-chrome-trace-{}.json",
        std::process::id()
    ));
    let chrome_trace = run(
        env!("CARGO_BIN_EXE_chrome_trace"),
        &[
            "--runner",
            "kvm",
            "--out",
            trace_path.to_str().unwrap(),
            "--no-host-envs",
            "/bin/echo",
            "chrome-trace",
        ],
    );
    assert_success(&chrome_trace);
    assert_eq!(chrome_trace.stdout, b"chrome-trace\n");
    let trace: serde_json::Value = serde_json::from_slice(&fs::read(&trace_path).unwrap()).unwrap();
    fs::remove_file(trace_path).unwrap();
    assert!(!trace.as_array().unwrap().is_empty());

    let chunky_print = run(
        env!("CARGO_BIN_EXE_chunky_print"),
        &[
            "--runner",
            "kvm",
            "--no-host-envs",
            "/bin/echo",
            "chunky-print",
        ],
    );
    assert_success(&chunky_print);
    assert_eq!(chunky_print.stdout, b"chunky-print\n");

    let debug = run(
        env!("CARGO_BIN_EXE_debug"),
        &["--runner", "kvm", "--no-host-envs", "/bin/echo", "debug"],
    );
    assert_success(&debug);
    assert_eq!(debug.stdout, b"debug\n");

    let strace_minimal = run(
        env!("CARGO_BIN_EXE_strace_minimal"),
        &[
            "--runner",
            "kvm",
            "--no-host-envs",
            "/bin/echo",
            "strace-minimal",
        ],
    );
    assert_success(&strace_minimal);
    assert_eq!(strace_minimal.stdout, b"strace-minimal\n");
    assert!(String::from_utf8_lossy(&strace_minimal.stderr).contains("[pid 1] write("));
}

#[test]
fn counter2_matches_ptrace_echo_syscall_count() {
    if !kvm_available() {
        return;
    }

    let ptrace = run(
        env!("CARGO_BIN_EXE_counter2"),
        &["--no-host-envs", "--", "/bin/echo", "count-parity"],
    );
    let kvm = run(
        env!("CARGO_BIN_EXE_reverie-kvm-counter2"),
        &["/bin/echo", "count-parity"],
    );

    assert_success(&ptrace);
    assert_success(&kvm);
    assert_eq!(ptrace.stdout, b"count-parity\n");
    assert_eq!(kvm.stdout, ptrace.stdout);
    let ptrace_total = counter2_total(&ptrace);
    let kvm_total = counter2_total(&kvm);
    assert_eq!(kvm_total, ptrace_total);
    for (output, total) in [(&ptrace, ptrace_total), (&kvm, kvm_total)] {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("syscalls={total}")), "{stderr}");
        assert!(stderr.contains("from 1 processes, 1 thread"), "{stderr}");
    }
}

#[test]
fn cross_backend_tool_startup_microbenchmark() {
    if !kvm_available() {
        return;
    }

    benchmark_pair(
        "counter1",
        env!("CARGO_BIN_EXE_counter1"),
        &["--no-host-envs", "--", "/bin/true"],
        env!("CARGO_BIN_EXE_reverie-kvm-counter1"),
        &["/bin/true"],
    );
    benchmark_pair(
        "counter2",
        env!("CARGO_BIN_EXE_counter2"),
        &["--no-host-envs", "--", "/bin/true"],
        env!("CARGO_BIN_EXE_reverie-kvm-counter2"),
        &["/bin/true"],
    );
    benchmark_pair(
        "noop",
        env!("CARGO_BIN_EXE_noop"),
        &["--runner", "ptrace", "--no-host-envs", "--", "/bin/true"],
        env!("CARGO_BIN_EXE_noop"),
        &["--runner", "kvm", "--no-host-envs", "--", "/bin/true"],
    );
    benchmark_pair(
        "strace",
        env!("CARGO_BIN_EXE_strace"),
        &[
            "--runner",
            "ptrace",
            "--trace",
            "exit_group",
            "--no-host-envs",
            "--",
            "/bin/true",
        ],
        env!("CARGO_BIN_EXE_strace"),
        &[
            "--runner",
            "kvm",
            "--trace",
            "exit_group",
            "--no-host-envs",
            "--",
            "/bin/true",
        ],
    );
    benchmark_pair(
        "chaos",
        env!("CARGO_BIN_EXE_chaos"),
        &[
            "--runner",
            "ptrace",
            "--no-read",
            "--no-recv",
            "--no-interrupt",
            "--no-host-envs",
            "--",
            "/bin/true",
        ],
        env!("CARGO_BIN_EXE_chaos"),
        &[
            "--runner",
            "kvm",
            "--no-read",
            "--no-recv",
            "--no-interrupt",
            "--no-host-envs",
            "--",
            "/bin/true",
        ],
    );

    let trace_path = std::env::temp_dir().join(format!(
        "reverie-cross-backend-benchmark-{}.json",
        std::process::id()
    ));
    let trace_path = trace_path.to_str().unwrap();
    benchmark_pair(
        "chrome_trace",
        env!("CARGO_BIN_EXE_chrome_trace"),
        &[
            "--runner",
            "ptrace",
            "--out",
            trace_path,
            "--no-host-envs",
            "--",
            "/bin/true",
        ],
        env!("CARGO_BIN_EXE_chrome_trace"),
        &[
            "--runner",
            "kvm",
            "--out",
            trace_path,
            "--no-host-envs",
            "--",
            "/bin/true",
        ],
    );
    fs::remove_file(trace_path).unwrap();

    benchmark_pair(
        "chunky_print",
        env!("CARGO_BIN_EXE_chunky_print"),
        &["--runner", "ptrace", "--no-host-envs", "--", "/bin/true"],
        env!("CARGO_BIN_EXE_chunky_print"),
        &["--runner", "kvm", "--no-host-envs", "--", "/bin/true"],
    );
    benchmark_pair(
        "strace_minimal",
        env!("CARGO_BIN_EXE_strace_minimal"),
        &["--runner", "ptrace", "--no-host-envs", "--", "/bin/true"],
        env!("CARGO_BIN_EXE_strace_minimal"),
        &["--runner", "kvm", "--no-host-envs", "--", "/bin/true"],
    );
}

#[test]
fn counter2_matches_ptrace_fork_process_and_thread_counts() {
    if !kvm_available() {
        return;
    }

    let workload = "for i in 1 2 3 4; do /bin/true; done; printf 'fork-parity\\n'";
    let ptrace = run(
        env!("CARGO_BIN_EXE_counter2"),
        &["--no-host-envs", "--", "/bin/sh", "-c", workload],
    );
    let kvm = run(
        env!("CARGO_BIN_EXE_reverie-kvm-counter2"),
        &["/bin/sh", "-c", workload],
    );

    assert_success(&ptrace);
    assert_success(&kvm);
    assert_eq!(ptrace.stdout, b"fork-parity\n");
    assert_eq!(kvm.stdout, ptrace.stdout);

    for output in [&ptrace, &kvm] {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.matches("counter2-local thread=").count(), 5);
        assert!(stderr.contains("from 5 processes, 5 thread(s)"), "{stderr}");
    }
}

#[test]
fn strace_observes_syscalls_from_forked_kvm_processes() {
    if !kvm_available() {
        return;
    }

    let output = run(
        env!("CARGO_BIN_EXE_strace"),
        &[
            "--runner",
            "kvm",
            "--trace",
            "execve",
            "--no-host-envs",
            "--",
            "/bin/sh",
            "-c",
            "for i in 1 2 3 4; do /bin/true; done",
        ],
    );

    assert_success(&output);
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    for pid in 2..=5 {
        assert!(stderr.contains(&format!("[pid {pid}] execve(")), "{stderr}");
    }
}

#[test]
fn strace_observes_root_process_syscalls_with_kvm_guest() {
    if !kvm_available() {
        return;
    }

    let output = run(
        env!("CARGO_BIN_EXE_strace"),
        &[
            "--runner",
            "kvm",
            "--trace",
            "clone",
            "--trace",
            "vfork",
            "--trace",
            "wait4",
            "--trace",
            "execve",
            "--no-host-envs",
            "--",
            "/bin/sh",
            "-c",
            "/bin/true; exec /bin/true",
        ],
    );
    assert_success(&output);
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("[pid 1] clone(") || stderr.contains("[pid 1] vfork("),
        "{stderr}"
    );
    assert!(stderr.contains("[pid 1] wait4("), "{stderr}");
    assert!(stderr.contains("[pid 1] execve("), "{stderr}");

    let failed_exec = run(
        env!("CARGO_BIN_EXE_strace"),
        &[
            "--runner",
            "kvm",
            "--trace",
            "execve",
            "--no-host-envs",
            "--",
            "/bin/sh",
            "-c",
            "exec /definitely-not-a-reverie-executable",
        ],
    );
    assert_eq!(failed_exec.status.code(), Some(127));
    assert!(failed_exec.stdout.is_empty());
    let stderr = String::from_utf8(failed_exec.stderr).unwrap();
    assert!(stderr.contains("[pid 1] execve("), "{stderr}");
    assert!(stderr.contains("(execve) = ENOENT"), "{stderr}");
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
