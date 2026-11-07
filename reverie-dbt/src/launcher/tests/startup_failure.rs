/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Native startup refusals must complete the application owner's real wait.

use std::io;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::super::DbtRunner;
use crate::CallerArtifact;
use crate::bundled_drrun_path;

const CHILD_CASE: &str = "REVERIE_DBT_STARTUP_FAILURE_CASE";
const CHILD_WAIT: &str = "REVERIE_DBT_STARTUP_FAILURE_WAIT";
const WITNESS: &str = "DBT_NATIVE_STARTUP_REFUSAL_COMPLETED";

fn profile_directory() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    assert_eq!(deps.file_name().unwrap(), "deps");
    deps.parent().unwrap().to_owned()
}

fn assert_reaped() {
    // The self-exec supervisor gives this test a process with no unrelated
    // children. The runner must have waited its real native root before return.
    let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(result, -1, "native root remains waitable: {result}");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn native_case(name: &str, wait_for_background: bool) {
    let mut guest = Command::new("/bin/echo");
    guest.arg("application-must-not-start");
    let output = if name == "caller-without-coordinator" {
        let artifact = CallerArtifact::load(
            profile_directory().join("reverie-dbt-callers/caller-lifecycle/manifest.json"),
        )
        .unwrap();
        let runner = DbtRunner::new(bundled_drrun_path(), artifact.native_client()).unwrap();
        assert!(!runner.manages_process_group());
        assert!(!wait_for_background);
        let output = runner.output(&guest).unwrap();
        assert_eq!(output.status.code(), Some(101), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("caller Tool requires coordinated native startup"),
            "missing the original no-coordinator refusal: {output:?}"
        );
        output
    } else {
        let mut runner = DbtRunner::new(
            bundled_drrun_path(),
            profile_directory().join("reverie-dbt-native/libreverie_dbt_client.so"),
        )
        .unwrap();
        assert!(!runner.manages_process_group());
        if wait_for_background {
            runner = runner.client_argument("-test-wait-for-background");
        }
        guest.env(crate::TOOL_ENV, name);
        let (output, ()) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(runner.output_with_global::<()>(&guest, ()))
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(crate::CLIENT_THREAD_START_FAILURE_EXIT_CODE),
            "{output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("REVERIE_DBT_TOOL={name:?} names no tool")),
            "missing the actual unknown-name refusal: {output:?}"
        );
        assert!(
            stderr.contains("reverie-dbt: runtime background initialization failed"),
            "application owner did not report helper failure: {output:?}"
        );
        output
    };
    assert_eq!(output.status.signal(), None, "{output:?}");
    assert!(output.stdout.is_empty(), "application entered: {output:?}");
    assert_reaped();
    println!(
        "DBT_STARTUP_REFUSAL:{}",
        serde_json::json!({
            "case": name,
            "wait_for_background": wait_for_background,
            "status": output.status.code(),
            "signal": output.status.signal(),
            "stdout_bytes": output.stdout.len(),
            "stderr": String::from_utf8(output.stderr).unwrap(),
            "no_waitable_children": true,
        })
    );
}

struct SupervisedChild(Option<Child>);

impl SupervisedChild {
    fn kill_group(&mut self) {
        if let Some(child) = &mut self.0 {
            let group = i32::try_from(child.id()).unwrap();
            // Only the process group created for this self-exec test is owned.
            let _ = unsafe { libc::kill(-group, libc::SIGKILL) };
            let _ = child.kill();
        }
    }

    fn finish(mut self) -> Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        self.kill_group();
        if let Some(mut child) = self.0.take() {
            let _ = child.wait();
        }
    }
}

fn run_case(selector: &str, name: &str, wait_for_background: bool) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .env(CHILD_CASE, name)
        .env(CHILD_WAIT, if wait_for_background { "1" } else { "0" })
        .env_remove(crate::sync_rpc::RPC_SOCKET_ENV)
        .env_remove(crate::TOOL_ENV)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe setpgid runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = SupervisedChild(Some(command.spawn().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(10);
    let output = loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break child.finish();
        }
        if Instant::now() >= deadline {
            child.kill_group();
            let output = child.finish();
            panic!("native startup refusal timed out: {name}: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(output.status.success(), "{selector}/{name}: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.matches("test result: ok. 1 passed;").count(),
        1,
        "{stdout}"
    );
    assert_eq!(stdout.matches(WITNESS).count(), 1, "{stdout}");
    let records: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.find("DBT_STARTUP_REFUSAL:").map(|at| &line[at..]))
        .collect();
    assert_eq!(records.len(), 1, "{stdout}");
    println!("{}", records[0]);
    assert!(
        output.stderr.is_empty(),
        "helper stderr: {:?}",
        output.stderr
    );
}

fn child_case() -> bool {
    if let Some(name) = std::env::var_os(CHILD_CASE) {
        let wait = std::env::var(CHILD_WAIT).unwrap();
        assert!(wait == "0" || wait == "1");
        native_case(name.to_str().unwrap(), wait == "1");
        println!("{WITNESS}");
        true
    } else {
        false
    }
}

#[test]
fn unknown_hosted_tool_completes_default_coordinated_startup_failure() {
    if child_case() {
        return;
    }
    let selector = "launcher::tests::startup_failure::unknown_hosted_tool_completes_default_coordinated_startup_failure";
    for name in ["noop", "unknown-startup-regression"] {
        for wait in [false, true] {
            run_case(selector, name, wait);
        }
    }
}

#[test]
fn caller_without_coordinator_keeps_named_native_refusal() {
    if child_case() {
        return;
    }
    run_case(
        "launcher::tests::startup_failure::caller_without_coordinator_keeps_named_native_refusal",
        "caller-without-coordinator",
        false,
    );
}
