//! Actual native return-state regressions for the owned DR signal API.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn bounded(command: &mut Command) -> Output {
    bounded_with_status(command, 0)
}

fn bounded_with_status(command: &mut Command, expected: i32) -> Output {
    let output = Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=2s", "30s"])
        .arg(command.get_program())
        .args(command.get_args())
        .output()
        .expect("start bounded native fixture");
    assert!(
        output.status.code() == Some(expected),
        "{command:?}: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn owned_signal_preserves_native_fp_restart_and_masks() {
    let directory = tempfile::tempdir().expect("native state fixture directory");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signal_admission_state");
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    bounded(
        Command::new(&cmake)
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(directory.path())
            .arg("-DCMAKE_BUILD_TYPE=Release")
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
    );
    bounded(
        Command::new(&cmake)
            .arg("--build")
            .arg(directory.path())
            .args(["--parallel", "2"]),
    );
    let guest = directory.path().join("signal_admission_state_guest");
    let client = directory.path().join("libsignal_admission_state_client.so");
    // Real Linux controls establish the guest's permitted signal/restart/mask
    // behavior. Suppression is a DR client operation, so its control below is
    // DR's existing DR_SIGNAL_SUPPRESS path, not an invented Linux outcome.
    for case in [
        "control",
        "deliver",
        "mask",
        "restart-control",
        "restart-deliver",
        "ppoll-mask",
    ] {
        let output = bounded(Command::new(&guest).arg(case));
        let stdout = String::from_utf8(output.stdout).expect("native stdout");
        assert!(stdout.contains(&format!("guest completed case={case} ")));
    }
    for case in ["suppress", "restart-suppress"] {
        let output = bounded(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-c")
                .arg(&client)
                .arg("legacy")
                .arg("--")
                .arg(&guest)
                .arg(case),
        );
        let stdout = String::from_utf8(output.stdout).expect("legacy stdout");
        assert!(stdout.contains(&format!("guest completed case={case} ")));
        assert!(stdout.contains("client completed legacy=1 signals=1 admissions=0 commits=0 "));
    }
    for case in [
        "control",
        "deliver",
        "suppress",
        "mask",
        "restart-control",
        "restart-deliver",
        "restart-suppress",
        "ppoll-mask",
    ] {
        let output = bounded(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-c")
                .arg(&client)
                .arg("owned")
                .arg("--")
                .arg(&guest)
                .arg(case),
        );
        let stdout = String::from_utf8(output.stdout).expect("owned stdout");
        assert!(stdout.contains(&format!("guest completed case={case} ")));
        let expected = if case == "control" || case == "restart-control" {
            0
        } else {
            1
        };
        assert!(stdout.contains(&format!(
            "client completed legacy=0 signals={expected} admissions={expected} commits={expected} "
        )));
    }

    // One ignored signal must not complete the wait. The guest's helper sends
    // the caught second signal only after observing the real main thread in
    // kernel sigsuspend. Suppression additionally requires the real client
    // admission handshake before that observation. These extend, rather than
    // replace, the original sixteen return-state cases above.
    let output = bounded(Command::new(&guest).arg("mask-ignore"));
    let stdout = String::from_utf8(output.stdout).expect("native ignore stdout");
    assert!(stdout.contains("guest completed case=mask-ignore "));
    for mode in ["legacy", "owned"] {
        for case in ["mask-suppress", "mask-ignore"] {
            let output = bounded(
                Command::new(reverie_dbt::bundled_drrun_path())
                    .arg("-c")
                    .arg(&client)
                    .arg(mode)
                    .arg("--")
                    .arg(&guest)
                    .arg(case),
            );
            let stdout = String::from_utf8(output.stdout).expect("suspend retry stdout");
            assert!(stdout.contains(&format!("guest completed case={case} ")));
            // The client asserts exact second-signal/commit counts. SIG_IGN
            // may legitimately be discarded by Linux without a callback.
            assert!(stdout.contains(&format!(
                "client completed legacy={} ",
                usize::from(mode == "legacy")
            )));
            if case == "mask-suppress" {
                let admitted = if mode == "owned" { 2 } else { 0 };
                assert!(stdout.contains(&format!(
                    "signals=2 admissions={admitted} commits={admitted} restart_contexts=0"
                )));
            }
        }
    }

    // A code_api client requires full interception, even if argv requests
    // partial interception. Assert the effective mode and the distinct guest
    // and physical masks during real legacy/owned suppression and retry.
    for mode in ["legacy", "owned"] {
        let output = bounded(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-c")
                .arg(&client)
                .arg(mode)
                .arg("require-emulated-mask")
                .arg("--")
                .arg(&guest)
                .arg("mask-suppress-emulated"),
        );
        let stdout = String::from_utf8(output.stdout).expect("emulated mask stdout");
        assert!(stdout.contains("client mode code_api=1 intercept_all_signals=1"));
        assert!(stdout.contains("guest completed case=mask-suppress-emulated "));
        let admitted = if mode == "owned" { 2 } else { 0 };
        assert!(stdout.contains(&format!(
            "client completed legacy={} signals=2 admissions={admitted} commits={admitted} restart_contexts=0",
            usize::from(mode == "legacy")
        )));
    }

    // With no client, partial interception is supported. The guest requires
    // SIGURG to lack a kernel handler before checking its physical temporary
    // block and restoration. Linux SIG_IGN replaces client suppression here;
    // this does not claim a partial-interception client-suppression path.
    let output = bounded(
        Command::new(reverie_dbt::bundled_drrun_path())
            .args(["-no_code_api", "-no_intercept_all_signals", "--"])
            .arg(&guest)
            .arg("mask-ignore-physical"),
    );
    let stdout = String::from_utf8(output.stdout).expect("kernel-owned mask stdout");
    assert!(stdout.contains("guest completed case=mask-ignore-physical "));

    let output = bounded(
        Command::new(reverie_dbt::bundled_drrun_path())
            .args(["-no_code_api", "-no_intercept_all_signals", "--"])
            .arg(&guest)
            .arg("mask-readonly"),
    );
    let stdout = String::from_utf8(output.stdout).expect("read-only mask stdout");
    assert!(stdout.contains("guest completed case=mask-readonly"));

    // Exercise returning injection while its actual syscall callback owns the
    // native stack. Queued delivery and a later, authenticated kernel-wait
    // arrival use the same atomic entry path. Suppression must re-enter that
    // real callback; it cannot resume a hidden native wait after completion.
    for case in ["mask", "mask-suppress", "mask-ignore"] {
        let output = bounded(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-c")
                .arg(&client)
                .arg("owned-inject")
                .arg("--")
                .arg(&guest)
                .arg(case),
        );
        let stdout = String::from_utf8(output.stdout).expect("returning injection stdout");
        assert!(stdout.contains(&format!("guest completed case={case} ")));
        assert!(stdout.contains("returning injections entries="));
        if case == "mask-suppress" {
            assert!(stdout.contains("returning injections entries=2 completions=2"));
            assert!(stdout.contains(
                "client completed legacy=0 signals=2 admissions=2 commits=2 restart_contexts=0"
            ));
        }
    }

    let output = bounded(
        Command::new(reverie_dbt::bundled_drrun_path())
            .arg("-c")
            .arg(&client)
            .arg("owned-inject-result")
            .arg("--")
            .arg(&guest)
            .arg("mask-tool-result"),
    );
    let stdout = String::from_utf8(output.stdout).expect("transformed result stdout");
    assert!(stdout.contains("guest completed case=mask-tool-result "));
    assert!(stdout.contains("returning injections entries=1 completions=1"));
    assert!(stdout.contains("signals=1 admissions=1 commits=1 restart_contexts=0"));

    let output = bounded_with_status(
        Command::new(reverie_dbt::bundled_drrun_path())
            .arg("-c")
            .arg(&client)
            .arg("owned-inject-terminal")
            .arg("--")
            .arg(&guest)
            .arg("mask"),
        31,
    );
    let stdout = String::from_utf8(output.stdout).expect("terminal result stdout");
    assert!(stdout.contains("terminal interruption consumed status=31"));
    assert!(!stdout.contains("guest completed"));

    // Signal policy sees the restart result before disposition and may replace
    // both the ordinary result and PC. Suppression must honor those writes,
    // rather than reconstructing the pre-policy syscall context.
    let output = bounded(
        Command::new(reverie_dbt::bundled_drrun_path())
            .arg("-c")
            .arg(&client)
            .arg("owned-inject-signal-result")
            .arg("--")
            .arg(&guest)
            .arg("mask-signal-result"),
    );
    let stdout = String::from_utf8(output.stdout).expect("signal policy result stdout");
    assert!(stdout.contains("guest completed case=mask-signal-result "));
    assert!(stdout.contains("handler_count=0"));
    assert!(stdout.contains("returning injections entries=1 completions=1"));
    assert!(stdout.contains("signals=1 admissions=1 commits=1 restart_contexts=0"));
}

#[test]
fn injected_sigpipe_projects_only_fresh_epipe_and_preserves_replacements() {
    let directory = tempfile::tempdir().expect("SIGPIPE fixture directory");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/signal_admission_state");
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    bounded(
        Command::new(&cmake)
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(directory.path())
            .arg("-DCMAKE_BUILD_TYPE=Release")
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
    );
    bounded(
        Command::new(&cmake)
            .arg("--build")
            .arg(directory.path())
            .args([
                "--parallel",
                "2",
                "--target",
                "signal_admission_sigpipe_client",
                "signal_admission_sigpipe_guest",
            ]),
    );
    let guest = directory.path().join("signal_admission_sigpipe_guest");
    let client = directory
        .path()
        .join("libsignal_admission_sigpipe_client.so");
    bounded(Command::new(&guest).arg("native"));
    for mode in ["project", "replace"] {
        let output = bounded(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-c")
                .arg(&client)
                .arg(mode)
                .arg("--")
                .arg(&guest)
                .arg(mode),
        );
        let stdout = String::from_utf8(output.stdout).expect("SIGPIPE fixture stdout");
        assert!(
            stdout
                .contains("SIGPIPE guest: EPIPE handler/read/readv and queued collision preserved")
        );
        assert!(stdout.contains("SIGPIPE client: raw admissions=5 commits=5"));
    }
}
