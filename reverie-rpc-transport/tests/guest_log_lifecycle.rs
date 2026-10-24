#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

#[path = "fixtures/owned_lifecycle.rs"]
mod owned_lifecycle;

fn lifecycle(mode: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
    command.arg(mode);
    let (output, _) = owned_lifecycle::run(command, Duration::from_secs(50)).unwrap();
    let status = output.status;
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        status.success(),
        "lifecycle {mode}: {status}\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "ordinary lifecycle case completed and descendants reaped: {mode}"
        )),
        "{stdout}"
    );
    print!("{stdout}");
}

#[test]
fn fork() {
    lifecycle("fork");
}
#[test]
fn wait_error() {
    lifecycle("wait-error");
}
#[test]
fn failed_fork() {
    lifecycle("failed-fork");
}
#[test]
fn death_before_attach() {
    lifecycle("death-before-attach");
}
#[test]
fn parent_first_exit() {
    lifecycle("parent-first-exit");
}

fn ownership_control(mode: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
    command.args(["--ownership-control", mode]);
    let (output, _) = owned_lifecycle::run(command, Duration::from_secs(50)).unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!("ownership control completed: {mode}")),
        "{stdout}"
    );
    print!("{stdout}");
}

#[test]
fn early_leader_exit_closes_descendant_pipes() {
    ownership_control("early-exit");
}

#[test]
fn cleanup_does_not_signal_after_reap() {
    ownership_control("single-signal");
}
