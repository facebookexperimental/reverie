#![cfg(target_os = "linux")]

#[path = "fixtures/owned_lifecycle.rs"]
mod owned_lifecycle;

fn rpc_shutdown(mode: &str) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
    command.args(["--split-rpc-shutdown", mode]);
    let (output, _) = owned_lifecycle::run(command, std::time::Duration::from_secs(50)).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{mode}: {:?}\n{stdout}\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains(&format!(
            "split RPC shutdown completed with actual runtime teardown: {mode}"
        )),
        "{stdout}"
    );
    print!("{stdout}");
}

#[test]
fn split_rpc_clean_shutdown_has_real_teardown() {
    rpc_shutdown("clean");
}
#[test]
fn split_rpc_planned_cancellation_has_real_teardown() {
    rpc_shutdown("planned");
}
#[test]
fn split_rpc_unplanned_cancellation_keeps_failure() {
    rpc_shutdown("unplanned");
}
#[test]
fn split_rpc_panic_keeps_original_payload_after_teardown() {
    rpc_shutdown("panic");
}
#[test]
fn split_rpc_decode_failure_survives_teardown() {
    rpc_shutdown("decode");
}

#[test]
fn split_rpc_destructor_panic_cannot_be_clean() {
    rpc_shutdown("drop-panic");
    rpc_shutdown("planned-drop-panic");
}

fn lifecycle(mode: &str) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
    command.args(["--split-lifecycle", mode]);
    let (output, _) = owned_lifecycle::run(command, std::time::Duration::from_secs(50)).unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{mode}: {:?}\n{stdout}\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains(&format!("split lifecycle completed: {mode}")),
        "{stdout}"
    );
    print!("{stdout}");
}
#[test]
fn split_real_child_orders_serializer_and_destructors_before_finish() {
    lifecycle("complete");
}
#[test]
fn split_nonzero_guest_remains_nonqualifying() {
    lifecycle("guest-nonzero");
}
#[test]
fn split_caught_coordinator_panic_is_not_exit_zero_success() {
    for mode in [
        "caught-panic",
        "coordinator-error",
        "policy-refusal",
        "run-timeout",
    ] {
        lifecycle(mode);
    }
}
#[test]
fn split_missing_guest_finish_refuses() {
    lifecycle("missing-finish");
}
#[test]
fn split_large_result_drains_before_wait() {
    lifecycle("large");
}
#[test]
fn split_second_clone_follows_real_joins_and_factory_reclamation() {
    lifecycle("second-clone");
}

#[test]
fn split_startup_refusal_and_parent_unwind_keep_factory_ownership() {
    for mode in ["child-refusal", "parent-refusal", "parent-panic"] {
        let mut command =
            std::process::Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
        command.args(["--split-startup-failure", mode]);
        let (output, _) =
            owned_lifecycle::run(command, std::time::Duration::from_secs(50)).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{mode}: {:?}\n{stdout}\n{stderr}",
            output.status
        );
        assert!(stdout.contains(&format!("split startup cleanup completed: {mode}")));
        print!("{stdout}");
    }
}

#[test]
fn split_unjoined_output_retains_factory_and_frozen_failure() {
    lifecycle("held-publication");
}

#[test]
fn split_serializer_error_and_actual_child_deaths_never_qualify() {
    for mode in [
        "serialize-error",
        "coordinator-exit",
        "coordinator-sigpipe",
        "serialize-panic",
        "T-panic",
        "field-panic",
        "U-panic",
        "W-panic",
    ] {
        lifecycle(mode);
    }
}
#[test]
fn split_stalled_serializer_requires_outer_bound() {
    let marker =
        std::env::temp_dir().join(format!("sabre-split-serializer-{}", std::process::id()));
    assert!(!marker.exists());
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
    command
        .args(["--split-lifecycle", "stalled-serializer"])
        .env("SPLIT_STALL_MARKER", &marker);
    let result = owned_lifecycle::run(command, std::time::Duration::from_secs(50));
    let error = result.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"actual serializer entered"
    );
    std::fs::remove_file(marker).unwrap();
    println!(
        "actual 50-second outer fixture bound refused stalled serialization; no finite library acquisition claimed"
    );
}

#[test]
fn split_namespace_population_keeps_reservation_and_helper_distinct() {
    for mode in [
        "namespace",
        "namespace-helper",
        "namespace-double-reservation",
    ] {
        lifecycle(mode);
    }
}

#[test]
fn split_cancel_and_implicit_disposal_settle_actual_post_eof_child() {
    for mode in ["cancel-pending", "drop-pending"] {
        lifecycle(mode);
    }
}

#[test]
fn split_real_rpc_causal_bytes_and_failures_survive_full_teardown() {
    for mode in [
        "rpc-complete",
        "rpc-panic",
        "rpc-drop-panic",
        "rpc-truncated-header",
    ] {
        lifecycle(mode);
    }
}

#[test]
fn split_implicit_held_output_disposal_and_factory_panic_keep_ownership() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let marker = std::env::temp_dir().join(format!("sabre-split-dispose-{}", std::process::id()));
    assert!(!marker.exists());
    let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = reader.as_raw_fd();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_guest_log_lifecycle_fixture"));
    command
        .args(["--split-lifecycle", "drop-publication"])
        .env("SPLIT_DISPOSE_MARKER", &marker)
        .env("SPLIT_DISPOSE_FD", fd.to_string());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let observed_marker = marker.clone();
    // This controller is outside O/C. It adds no O worker or pre-clone helper.
    let release = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(50);
        while !observed_marker.exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            std::fs::read(&observed_marker).unwrap(),
            b"entering owned disposal with held publication"
        );
        writer.write_all(b"R").unwrap();
    });
    let result = owned_lifecycle::run(command, std::time::Duration::from_secs(50));
    drop(reader);
    release.join().unwrap();
    let (output, _) = result.unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("split lifecycle completed: drop-publication")
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    std::fs::remove_file(marker).unwrap();
    lifecycle("factory-drop-panic");
}

#[test]
fn split_integrity_preserves_nonzero_status_and_independent_real_faults() {
    for mode in [
        "complete-guest7",
        "flush-eio",
        "flush-eio-guest7",
        "output-ceiling",
        "output-ceiling-guest7",
        "rpc-panic-guest7",
        "rpc-drop-panic-guest7",
        "rpc-truncated-header-guest7",
        "missing-finish-guest7",
        "held-publication-guest7",
        "decode-error",
        "decode-error-guest7",
        "held-endpoint",
        "held-endpoint-guest7",
    ] {
        lifecycle(mode);
    }
}
