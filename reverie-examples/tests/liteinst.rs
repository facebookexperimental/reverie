/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end checks for the exact example `Tool` types on LiteInst, with
//! Counter1 allocator coverage through the shared backend launcher.
//! DBT Counter1 and Strace require their explicit caller producers for the
//! same Cargo profile; they use the standard manifest layout. The separate
//! Counter1 local-Global case requires the no-argument prototype producer
//! `reverie-dbt/scripts/build-client.sh`, or `REVERIE_DBT_CLIENT`.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV;

#[path = "../dbt_client.rs"]
mod dbt_client;

const TEST_STRADDLER_STALENESS_TICKS: &str = "20000";

fn preload() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    let profile = deps.parent().unwrap();
    [
        // `cargo test` refreshes the copy in `deps`; the profile-root copy can
        // belong to another worktree when both share one Cargo target directory.
        deps.join("libreverie_examples.so"),
        profile.join("libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build libreverie_examples.so")
}

fn run(tool: &str, extra: &[&str], guest: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        // The direct runtime has no ptrace fallback supervisor. Exercise its
        // concurrent WordPatch++ path explicitly; this test value is not a
        // production machine-calibration claim.
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
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
fn launcher_exposes_the_complete_ptrace_example_surface() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command.arg("--help");
    let output = output_with_timeout(&mut command);

    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).unwrap();
    for tool in [
        "chaos",
        "chrome-trace",
        "chunky-print",
        "counter1",
        "counter2",
        "debug",
        "noop",
        "strace",
        "strace-minimal",
    ] {
        assert!(help.contains(tool), "missing {tool:?} from help:\n{help}");
    }
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
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
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

    assert_counter1_allocator_output(
        &output,
        " [counter tool] Total system calls in process tree: ",
    );
}

fn assert_counter1_allocator_output(output: &Output, summary_prefix: &str) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"allocator-growth-ok\n");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let total = stderr
        .lines()
        .find_map(|line| line.strip_prefix(summary_prefix))
        .expect("counter1 summary is missing")
        .parse::<u64>()
        .unwrap();
    assert!(total > 0, "{stderr}");
}

fn assert_one_counter1_allocator_summary(output: &Output) {
    let prefix = "counter1-global syscalls=";
    assert_counter1_allocator_output(output, prefix);
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(prefix))
            .count(),
        1,
        "{stderr}"
    );
}

fn counter1_allocator_on(backend: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_counter1"));
    command
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
        .arg("--backend")
        .arg(backend)
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-allocator");
    assert_one_counter1_allocator_summary(&output_with_timeout(&mut command));
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator_on_ptrace() {
    counter1_allocator_on("ptrace");
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator_on_dbt() {
    counter1_allocator_on("dbt");
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator_on_in_guest_trap() {
    counter1_allocator_on("in-guest-trap");
}

#[test]
fn exact_counter1_tool_reports_its_local_global_without_a_coordinator() {
    let client = dbt_client::find(Some(Path::new(env!("CARGO_BIN_EXE_counter1")))).expect(
        "build the DBT client with reverie-dbt/scripts/build-client.sh or set REVERIE_DBT_CLIENT",
    );
    // The documented exact-mode flag selects the same Tool with a local GlobalState.
    // Use the native launch shape from reverie-dbt/scripts/test-example-tools.sh.
    let mut command = Command::new(reverie_dbt::bundled_drrun_path());
    command
        .env_remove(reverie_dbt::TOOL_ENV)
        .env_remove(reverie_dbt::sync_rpc::RPC_SOCKET_ENV)
        .env("HERMIT_DBT_COUNTER1_EXACT", "1")
        .args(["-quiet", "-disable_rseq", "-stack_size", "2M", "-c"])
        .arg(client)
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-allocator");
    assert_one_counter1_allocator_summary(&output_with_timeout(&mut command));
}

#[test]
fn dbt_counter1_explicit_caller_selection_bypasses_prototype_client() {
    let manifest = Path::new(env!("CARGO_BIN_EXE_counter1"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/counter1/manifest.json");
    // A valid, current pair is a prerequisite; a missing caller cannot prove
    // that the CLI selected the actual shared Tool through the caller owner.
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing_prototype = directory.path().join("missing-prototype-client.so");
    assert!(!missing_prototype.exists());
    let mut command = Command::new(env!("CARGO_BIN_EXE_counter1"));
    command
        .env("REVERIE_DBT_CALLER_ARTIFACT", &manifest)
        .env("REVERIE_DBT_CLIENT", &missing_prototype)
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-allocator");
    assert_one_counter1_allocator_summary(&output_with_timeout(&mut command));
}

#[test]
fn dbt_counter1_bad_override_never_uses_the_valid_default_pair() {
    let default = Path::new(env!("CARGO_BIN_EXE_counter1"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/counter1/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let malformed = directory.path().join("malformed.json");
    std::fs::write(&malformed, b"{}").unwrap();
    for path in [directory.path().join("absent.json"), malformed] {
        for via_environment in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_counter1"));
            command
                .env_remove("REVERIE_DBT_CALLER_ARTIFACT")
                .args(["--backend", "dbt"]);
            if via_environment {
                command.env("REVERIE_DBT_CALLER_ARTIFACT", &path);
            } else {
                command.arg("--dbt-artifact").arg(&path);
            }
            command
                .arg("--")
                .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
                .arg("exercise-allocator");
            let output = output_with_timeout(&mut command);
            assert!(!output.status.success(), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("cannot load DBT caller artifact"),
                "{output:?}"
            );
        }
    }
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
        &["--skip", "32", "--no-interrupt"],
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
        &["--skip", "32"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-interrupt",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-interrupt-then-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(" = -4"), "{stderr}");
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
fn chrome_trace_output_requires_the_chrome_trace_tool() {
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-liteinst-invalid-chrome-trace-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let output = run(
        "noop",
        &["--out", trace_path.to_str().unwrap()],
        &["/bin/true"],
    );

    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--out is only valid with --tool chrome-trace"),
        "{stderr}"
    );
    assert!(!trace_path.exists(), "unexpected artifact: {trace_path:?}");
}

#[test]
fn exact_chrome_trace_tool_writes_process_and_syscall_events() {
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-liteinst-chrome-trace-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let output = run(
        "chrome-trace",
        &["--out", trace_path.to_str().unwrap()],
        &["/bin/echo", "hello"],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    assert!(output.stderr.is_empty(), "{output:?}");

    let trace = std::fs::read(&trace_path).unwrap();
    std::fs::remove_file(&trace_path).unwrap();
    let trace: serde_json::Value = serde_json::from_slice(&trace).unwrap();
    let events = trace
        .as_array()
        .expect("chrome trace is not an event array");
    assert!(
        events
            .iter()
            .any(|event| event["cat"] == "process" && event["ph"] == "B"),
        "{trace}"
    );
    assert!(
        events.iter().any(|event| {
            event["cat"] == "syscall"
                && event["name"] == "write"
                && event["args"]["pretty"]
                    .as_str()
                    .is_some_and(|pretty| pretty.starts_with("write(1,"))
                && event["args"]["result"] == "Ok(6)"
        }),
        "{trace}"
    );
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

fn run_dbt_strace(extra: &[&str], guest: &[&str]) -> Output {
    run_strace("dbt", extra, guest)
}

fn run_strace(backend: &str, extra: &[&str], guest: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_strace"));
    command
        .arg("--backend")
        .arg(backend)
        .args(extra)
        .arg("--")
        .args(guest);
    output_with_timeout(&mut command)
}

#[test]
fn dbt_exact_strace_tool_observes_filtered_write() {
    let output = run_dbt_strace(&["--trace", "write"], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = 6"), "{stderr}");
}

#[test]
fn dbt_strace_reports_exit_after_echo_closes_stdio() {
    strace_reports_exit_after_echo_closes_stdio("dbt");
}

#[test]
fn ptrace_strace_reports_exit_after_echo_closes_stdio() {
    strace_reports_exit_after_echo_closes_stdio("ptrace");
}

fn strace_reports_exit_after_echo_closes_stdio(backend: &str) {
    // GNU echo closes stdout and stderr before exit. Keep the original write
    // oracle above unchanged, and also require the consuming Tool diagnostics
    // to survive those application descriptor closes through controller RPC.
    let output = run_strace(backend, &["--trace", "write"], &["/bin/echo", "hello"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let lines: Vec<_> = stderr.lines().collect();
    let write = lines
        .iter()
        .position(|line| line.contains("write(1,") && line.ends_with(" = 6"))
        .expect("missing completed write diagnostic");
    let threads: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("Thread "))
        .collect();
    let processes: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("Process "))
        .collect();
    assert_eq!(threads.len(), 1, "{stderr}");
    assert_eq!(processes.len(), 1, "{stderr}");
    assert!(
        threads[0].1.ends_with(" exited with status Exited(0)"),
        "{stderr}"
    );
    assert!(
        processes[0].1.ends_with(" exited with status Exited(0)"),
        "{stderr}"
    );
    assert!(
        write < threads[0].0 && threads[0].0 < processes[0].0,
        "{stderr}"
    );
}

#[test]
fn exact_strace_minimal_tool_observes_write() {
    let output = run("strace-minimal", &[], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = ?"), "{stderr}");
}

#[test]
fn debug_port_requires_debug_selector() {
    let output = run("noop", &["--port", "0"], &["/bin/true"]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--port is only valid with --tool debug"),
        "{stderr}"
    );
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

#[test]
fn dbt_exact_strace_tool_observes_thread_and_process_exit() {
    let output = run_dbt_strace(&["--trace", "write"], &["/bin/true"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Thread "), "{stderr}");
    assert!(stderr.contains("Process "), "{stderr}");
    assert_eq!(stderr.matches("exited with status Exited(0)").count(), 2);
}

#[test]
fn dbt_strace_bad_override_never_uses_the_valid_default_pair() {
    // Require the real production prerequisite: a failed fallback to another
    // absent artifact would not establish this negative control.
    let default = Path::new(env!("CARGO_BIN_EXE_strace"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/strace/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let malformed = directory.path().join("malformed.json");
    std::fs::write(&malformed, b"{}").unwrap();
    let mut valid: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&default).unwrap()).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let inputs = valid["inputs"].as_array().unwrap();
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "reverie-examples/strace/config.rs",
        "reverie-examples/strace/filter.rs",
        "reverie-examples/strace/global_state.rs",
        "reverie-examples/strace/tool.rs",
        "reverie-examples/strace-dbt-runtime/Cargo.toml",
        "reverie-examples/strace-dbt-runtime/Cargo.lock",
        "reverie-examples/strace-dbt-runtime/build.rs",
        "reverie-examples/strace-dbt-runtime/src/lib.rs",
        "reverie-dbt/build.rs",
        "reverie-dbt/native/client.c",
        "reverie-dbt/native/CMakeLists.txt",
        "reverie-dbt/scripts/build-client.sh",
        "reverie-dbt/scripts/build-caller.rs",
    ] {
        let required = workspace.join(relative).canonicalize().unwrap();
        assert!(
            inputs
                .iter()
                .any(|input| { Path::new(input["path"].as_str().unwrap()) == required }),
            "missing declared input {relative}"
        );
    }
    for marker in [
        ".reverie-dbt-install.provenance",
        ".reverie-dbt-install.sha256",
    ] {
        assert!(
            inputs
                .iter()
                .any(|input| { Path::new(input["path"].as_str().unwrap()).ends_with(marker) }),
            "missing SDK input {marker}"
        );
    }
    for image in ["runtime", "client"] {
        valid[image]["path"] = serde_json::json!(
            default
                .parent()
                .unwrap()
                .join(valid[image]["path"].as_str().unwrap())
        );
    }
    let copied = directory.path().join("valid.json");
    std::fs::write(&copied, serde_json::to_vec(&valid).unwrap()).unwrap();
    reverie_dbt::CallerArtifact::load(&copied).unwrap();
    let mut bad_paths = vec![directory.path().join("absent.json"), malformed];
    for (label, pointer) in [
        ("stale-runtime", "/runtime/sha256"),
        ("stale-client", "/client/sha256"),
        ("stale-source", "/inputs/0/sha256"),
    ] {
        let mut stale = valid.clone();
        let digest = stale.pointer_mut(pointer).unwrap();
        let mut changed = digest.as_str().unwrap().as_bytes().to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        *digest = serde_json::Value::String(String::from_utf8(changed).unwrap());
        let path = directory.path().join(format!("{label}.json"));
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        bad_paths.push(path);
    }
    for path in bad_paths {
        for via_environment in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_strace"));
            command.args(["--backend", "dbt"]);
            if via_environment {
                command.env("REVERIE_DBT_CALLER_ARTIFACT", &path);
            } else {
                command.arg("--dbt-artifact").arg(&path);
            }
            command.args(["--trace", "write", "--", "/bin/echo", "hello"]);
            let output = output_with_timeout(&mut command);
            assert!(!output.status.success(), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(!output.stderr.is_empty(), "{output:?}");
        }
    }
}
