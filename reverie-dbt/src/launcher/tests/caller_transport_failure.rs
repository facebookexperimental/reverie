/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Native negative controls using the real fixture artifact and owner-fatal
//! callback. They do not inject native or wire facts.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use reverie::GlobalTool;
use reverie::MappingCaptureRunOwner;
use reverie_rpc_transport::RpcServer;
// Owner-agreed export; the real fatal-path implementation must precede integration.
// Do not replace an unavailable export with a local fallback definition.
use reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE;
use reverie_rpc_transport::tool_activation::ActivationRun;
use tempfile::TempDir;

use super::super::DbtRunner;
use super::super::DbtStatsSink;
use crate::CallerArtifact;
use crate::bundled_drrun_path;
use crate::failed_run_output;

#[path = "../../../tests/fixtures/caller-lifecycle-runtime/src/protocol.rs"]
mod protocol;
use protocol as tool;
use tool::Config;
use tool::DisconnectPoint;
use tool::Event;
use tool::LifecycleGlobal;

const CHILD_POINT: &str = "REVERIE_DBT_CALLER_DISCONNECT_POINT";
const CHILD_GUEST: &str = "REVERIE_DBT_CALLER_DISCONNECT_GUEST";
const WITNESS: &str = "CALLER_RPC_DISCONNECT_NATIVE_COMPLETED";
const GUEST_SOURCE: &str = include_str!("../../../tests/fixtures/caller-lifecycle-runtime/guest.S");
// Exact text agreed with the native rpc_transport_fatal owner. This is a
// diagnostic oracle, not a test switch or a synthetic backend-failure record.
const FATAL_DIAGNOSTIC: &[u8] = b"reverie-dbt: caller Tool RPC transport failure\n";

fn profile_directory() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    assert_eq!(deps.file_name().unwrap(), "deps");
    deps.parent().unwrap().to_owned()
}

fn temporary_directory(prefix: &str) -> TempDir {
    // Library tests have no CARGO_TARGET_TMPDIR. Keep this fixture under the
    // current test executable's existing target tree, without a second target.
    let root = profile_directory().parent().unwrap().join("tmp");
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .unwrap()
}

fn guest_binary() -> PathBuf {
    static GUEST: OnceLock<TempDir> = OnceLock::new();
    GUEST
        .get_or_init(|| {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/caller-lifecycle-runtime/guest.S");
            assert_eq!(fs::read_to_string(source).unwrap(), GUEST_SOURCE);
            let directory = temporary_directory("caller-disconnect-guest-");
            let source = directory.path().join("guest.S");
            fs::write(&source, GUEST_SOURCE).unwrap();
            // Same tiny guest, compiled before the ten-second native bound.
            let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
            let output = Command::new(compiler)
                .args([
                    "-nostdlib",
                    "-static",
                    "-no-pie",
                    "-Wl,-e,_start",
                    "-Wl,--build-id=none",
                    "-o",
                ])
                .arg(directory.path().join("guest"))
                .arg(source)
                .output()
                .unwrap();
            assert!(output.status.success(), "guest compiler failed: {output:?}");
            directory
        })
        .path()
        .join("guest")
}

fn expected_events(point: DisconnectPoint) -> Vec<Event> {
    if point == DisconnectPoint::Startup {
        return vec![Event::StartHook];
    }
    let mut events = vec![Event::StartHook, Event::PostExecHook];
    match point {
        DisconnectPoint::Async | DisconnectPoint::Sync | DisconnectPoint::AsyncControllerPanic => {
            events.push(Event::Disconnect { point });
        }
        DisconnectPoint::ThreadExit | DisconnectPoint::ProcessExit => {
            events.push(Event::ThreadExit {
                code: 23,
                attempts: 0,
                drops: 0,
                continued: false,
            });
            if point == DisconnectPoint::ProcessExit {
                events.push(Event::ProcessExit { code: 23 });
            }
        }
        DisconnectPoint::Startup | DisconnectPoint::None => panic!("unexpected disconnect point"),
    }
    events
}

async fn native_case(point: DisconnectPoint, guest: &Path) {
    assert_eq!(TOOL_RPC_FAILURE_EXIT_CODE, 123);
    let config = Config::disconnect_at(point);
    let artifact = CallerArtifact::load(
        profile_directory().join("reverie-dbt-callers/caller-lifecycle/manifest.json"),
    )
    .unwrap();
    let directory = temporary_directory("caller-disconnect-");
    let diagnostics_path = directory.path().join("native.log");
    let diagnostics = fs::File::create(&diagnostics_path).unwrap();
    // Native records supply an independent backend-failure observation. The
    // fixture does not write their bytes or invoke a test failure switch.
    let stats = DbtStatsSink::new().unwrap();
    let runner = stats.configure(
        DbtRunner::new(bundled_drrun_path(), artifact.native_client())
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap()
            .client_argument("-external-global"),
    );
    // Preserve the helper's supervised process group. Do not enable a nested
    // process group that the existing ten-second supervisor could not kill.
    assert!(!runner.manages_process_group());

    let mut global = LifecycleGlobal::init_global_state(&config).await;
    let (mapping_owner, mapping_control) = MappingCaptureRunOwner::disabled();
    global.install_mapping_capture_run(mapping_control);
    let global = Arc::new(global);
    let received = global.arm_disconnect();
    let activation = ActivationRun::new();
    // As in run_with_global, keep the AF_UNIX pathname below its native length
    // bound even when the existing Cargo target path is deeply nested.
    let socket_directory = tempfile::Builder::new()
        .prefix("reverie-dbt-")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = socket_directory.path().join("coordinator.sock");
    let server = RpcServer::bind(&socket, Arc::clone(&global), config.clone())
        .unwrap()
        .tool_activation(activation.clone());
    let connections = server.connection_monitor();

    let mut guest_command = Command::new(guest);
    guest_command.args([point.guest_argument(), "231", "23"]);
    let mut command = runner.command(&guest_command, None).unwrap();
    command
        .env(crate::sync_rpc::RPC_SOCKET_ENV, &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = runner.spawn_command(&mut command).unwrap();
    let actual_pid = i32::try_from(child.id()).unwrap();
    if let Err(error) = mapping_owner.bind_root(&child) {
        runner.terminate_and_reap(&mut child);
        panic!("actual child binding failed: {error}");
    }
    if let Err(error) = activation.bind_root(actual_pid) {
        runner.terminate_and_reap(&mut child);
        panic!("actual activation binding failed: {error}");
    }
    drop(command);
    let (setup_sender, setup) = tokio::sync::oneshot::channel();
    let wait =
        tokio::task::spawn_blocking(move || runner.wait_with_output(child, Some(setup_sender)));
    // Same parent I/O-before-Config ordering as run_with_global.
    setup.await.expect("native launch I/O setup failed");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(server.serve_until(async {
        stopped
            .await
            .expect("disconnect owner disappeared before shutdown");
    }));
    let witnessed = tokio::task::spawn_blocking(move || received.recv())
        .await
        .unwrap()
        .expect("designated real RPC was never received");
    let expected = expected_events(point);
    assert_eq!(witnessed.sender, actual_pid);
    assert_eq!(witnessed.sequence, expected.len());
    assert_eq!(witnessed.event, *expected.last().unwrap());
    assert_eq!(global.cancelled_requests(), 0);
    assert_eq!(connections.active_connections(), 1);

    // This is the only disconnect: ordinary owner shutdown of the real server
    // while the witnessed GlobalTool request awaits its never-issued response.
    stop.send(()).unwrap();
    serving.await.unwrap().unwrap();
    assert_eq!(connections.active_connections(), 0);
    assert_eq!(global.cancelled_requests(), 1);
    let output = wait.await.unwrap().unwrap();
    mapping_owner.finish().unwrap();

    // A synthetic numeric status, generic nonzero result or timeout is not an
    // acceptable witness. This is the actual reaped native child.
    assert_eq!(
        output.status.code(),
        Some(TOOL_RPC_FAILURE_EXIT_CODE),
        "{output:?}"
    );
    let expected_stdout: &[u8] = if point == DisconnectPoint::Startup {
        b""
    } else {
        b"before\n"
    };
    assert_eq!(
        output.stdout, expected_stdout,
        "RPC returned or guest executed: {output:?}"
    );
    assert!(
        output.stderr.is_empty(),
        "panic/guest-stderr leak: {output:?}"
    );
    let native_diagnostics = fs::read(diagnostics_path).unwrap();
    assert_eq!(
        native_diagnostics,
        FATAL_DIAGNOSTIC,
        "unexpected/panic diagnostic: {}",
        String::from_utf8_lossy(&native_diagnostics)
    );
    let failed = activation
        .completed()
        .expect_err("disconnect acquired a Finished receipt");
    assert!(
        failed
            .to_string()
            .contains("Tool connection dropped without clean protocol completion"),
        "unexpected activation failure: {failed}"
    );
    let capture = stats.capture();
    let snapshot = capture.snapshot().unwrap();
    assert_eq!(snapshot.process_images(), 1, "{snapshot}");
    assert_eq!(snapshot.backend_failures(), 1, "{snapshot}");
    let (received_config, rows) = global.snapshot();
    assert_eq!(received_config, config);
    assert!(rows.iter().all(|(sender, _)| *sender == actual_pid));
    assert_eq!(
        rows.into_iter().map(|(_, event)| event).collect::<Vec<_>>(),
        expected
    );
    // Process-exit pending implies the thread-exit RPC completed first. A
    // thread-exit disconnect must have no later process-exit RPC. Exact rows
    // reject repeated callback dispatch; they do not force a native duplicate.
}

struct SupervisedChild(Option<Child>);

impl SupervisedChild {
    fn kill_group(&mut self) {
        if let Some(child) = &mut self.0 {
            let group = i32::try_from(child.id()).unwrap();
            // SAFETY: pre_exec created this helper's own process group.
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

fn output_with_timeout(command: &mut Command) -> Output {
    // Existing ten-second supervised process-group mechanism, unchanged limit.
    // SAFETY: only async-signal-safe setpgid runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = SupervisedChild(Some(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return child.finish();
        }
        if Instant::now() >= deadline {
            child.kill_group();
            let output = child.finish();
            panic!("native RPC disconnect timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_case(name: &str, point: DisconnectPoint) {
    let selector = format!("launcher::tests::caller_transport_failure::{name}");
    if let Some(actual) = std::env::var_os(CHILD_POINT) {
        assert_eq!(actual.to_str().unwrap(), point.guest_argument());
        let guest = PathBuf::from(std::env::var_os(CHILD_GUEST).unwrap());
        assert!(guest.is_file());
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(native_case(point, &guest));
        println!("{WITNESS}:{selector}");
        return;
    }
    assert!(std::env::var_os(CHILD_GUEST).is_none());
    let guest = guest_binary();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &selector, "--nocapture", "--test-threads=1"])
        .env(CHILD_POINT, point.guest_argument())
        .env(CHILD_GUEST, guest);
    let output = output_with_timeout(&mut command);
    assert!(output.status.success(), "{selector}: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.matches("test result: ok. 1 passed;").count(),
        1,
        "missing/duplicate exact-selector harness result: {stdout}"
    );
    assert_eq!(
        stdout.matches(&format!("{WITNESS}:{selector}\n")).count(),
        1,
        "missing/duplicate native disconnect witness: {stdout}"
    );
    assert!(
        output.stderr.is_empty(),
        "helper stderr: {:?}",
        output.stderr
    );
}

#[test]
fn caller_async_rpc_disconnect_is_native_transport_failure() {
    run_case(
        "caller_async_rpc_disconnect_is_native_transport_failure",
        DisconnectPoint::Async,
    );
}

#[test]
fn caller_sync_rpc_disconnect_is_native_transport_failure() {
    run_case(
        "caller_sync_rpc_disconnect_is_native_transport_failure",
        DisconnectPoint::Sync,
    );
}

#[test]
fn caller_thread_exit_rpc_disconnect_is_native_transport_failure() {
    run_case(
        "caller_thread_exit_rpc_disconnect_is_native_transport_failure",
        DisconnectPoint::ThreadExit,
    );
}

#[test]
fn caller_process_exit_rpc_disconnect_is_native_transport_failure() {
    run_case(
        "caller_process_exit_rpc_disconnect_is_native_transport_failure",
        DisconnectPoint::ProcessExit,
    );
}

async fn public_native_case(guest: &Path) {
    // No cfg exclusion or skip: an aborting controller cannot establish this
    // connection-unwind control and must fail its stated admission condition.
    const {
        assert!(
            cfg!(panic = "unwind"),
            "public controller-panic control requires panic=unwind"
        );
    }
    assert_eq!(TOOL_RPC_FAILURE_EXIT_CODE, 123);
    let point = DisconnectPoint::AsyncControllerPanic;
    let config = Config::disconnect_at(point);
    let (observer, watch) = LifecycleGlobal::observe_public_failure(&config);
    let tool::PublicFailureWatch {
        request,
        acknowledge,
        global_dropped,
    } = watch;
    let request_witness = std::thread::spawn(move || {
        let witness = request
            .recv()
            .expect("public runner never dispatched the target RPC");
        assert!(witness.sender > 0);
        assert_ne!(witness.sender as u32, std::process::id());
        assert_eq!(witness.sequence, 3);
        assert_eq!(witness.event, Event::Disconnect { point });
        // The controller cannot deliberately panic until this independent host
        // thread has actually received and checked its real request witness.
        acknowledge.send(()).unwrap();
        witness
    });

    let artifact = CallerArtifact::load(
        profile_directory().join("reverie-dbt-callers/caller-lifecycle/manifest.json"),
    )
    .unwrap();
    let stats = DbtStatsSink::new().unwrap();
    // The normal public diagnostic setup duplicates the captured stderr pipe
    // into the native diagnostic descriptor before exec. guest.S closes only
    // application fd 2. Thus the actual public Err must retain the protected
    // native diagnostic while an ordinary Tool stderr write cannot be used.
    // No separate diagnostic file or private spawn/wait helper is used here.
    let runner =
        stats.configure(DbtRunner::new(bundled_drrun_path(), artifact.native_client()).unwrap());
    let mut command = Command::new(guest);
    command.args([point.guest_argument(), "231", "23"]);
    let error = match runner
        .output_with_caller_tool::<LifecycleGlobal>(&command, config.clone())
        .await
    {
        Err(error) => error,
        Ok((output, _)) => panic!("public runner accepted controller disconnection: {output:?}"),
    };
    let witnessed = request_witness
        .join()
        .expect("request witness observer panicked");
    // Await destruction through an independent blocking receiver, letting the
    // current Tokio executor finish any queued connection-task cancellation.
    // The existing outer ten-second group supervisor is the only deadline.
    tokio::task::spawn_blocking(move || global_dropped.recv())
        .await
        .unwrap()
        .expect("public runner leaked its owned Global");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    let cause = error.to_string();
    assert!(
        cause.contains("Tool connection dropped without clean protocol completion"),
        "public failure did not report incomplete activation: {error}"
    );
    // This is the existing public accessor, not a guess at a private downcast.
    let output = failed_run_output(&error)
        .unwrap_or_else(|| panic!("public error lost actual native output: {error}"));
    assert_eq!(
        output.status.and_then(|status| status.code()),
        Some(TOOL_RPC_FAILURE_EXIT_CODE),
        "actual reaped status absent/wrong: {output:?}"
    );
    assert_eq!(
        output.stdout, b"before\n",
        "guest resumed or bytes were lost: {output:?}"
    );
    assert_eq!(
        output.stderr, FATAL_DIAGNOSTIC,
        "native diagnostic lost or forbidden guest/runtime panic: {output:?}"
    );
    assert!(
        !output
            .stderr
            .windows(tool::EXPECTED_CONTROLLER_PANIC.len())
            .any(|bytes| bytes == tool::EXPECTED_CONTROLLER_PANIC.as_bytes())
    );

    let observed = observer.snapshot();
    assert_eq!(observed.config, config);
    assert_eq!(observed.globals_created, 1, "{observed:?}");
    assert_eq!(
        observed.globals_dropped, 1,
        "server retained its Global: {observed:?}"
    );
    assert_eq!(
        observed.active_requests, 0,
        "connection retained its request: {observed:?}"
    );
    assert_eq!(observed.requests_dropped, 1, "{observed:?}");
    assert!(
        observed
            .events
            .iter()
            .all(|(sender, _)| *sender == witnessed.sender)
    );
    assert_eq!(
        observed
            .events
            .into_iter()
            .map(|(_, event)| event)
            .collect::<Vec<_>>(),
        expected_events(point)
    );
    let capture = stats.capture();
    let snapshot = capture.snapshot().unwrap();
    assert_eq!(snapshot.process_images(), 1, "{snapshot}");
    assert_eq!(snapshot.backend_failures(), 1, "{snapshot}");
    // The public API has no FinishedReceipt/ConnectionMonitor accessor. Its
    // actual activation-refusal cause, attached wait, and final Global/request
    // destruction are the observations here; no private receipt is invented.
}

#[test]
fn caller_public_runner_retains_native_transport_failure_after_controller_panic() {
    const NAME: &str =
        "caller_public_runner_retains_native_transport_failure_after_controller_panic";
    let selector = format!("launcher::tests::caller_transport_failure::{NAME}");
    let point = DisconnectPoint::AsyncControllerPanic;
    if let Some(actual) = std::env::var_os(CHILD_POINT) {
        assert_eq!(actual.to_str().unwrap(), "public-controller-panic");
        let guest = PathBuf::from(std::env::var_os(CHILD_GUEST).unwrap());
        assert!(guest.is_file());
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(public_native_case(&guest));
        println!("{WITNESS}:{selector}");
        return;
    }
    assert!(std::env::var_os(CHILD_GUEST).is_none());
    assert_eq!(point.guest_argument(), "6");
    let guest = guest_binary();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &selector, "--nocapture", "--test-threads=1"])
        .env(CHILD_POINT, "public-controller-panic")
        .env(CHILD_GUEST, guest);
    let output = output_with_timeout(&mut command);
    assert!(output.status.success(), "{selector}: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.matches("test result: ok. 1 passed;").count(),
        1,
        "missing/duplicate exact-selector harness result: {stdout}"
    );
    assert_eq!(
        stdout.matches(&format!("{WITNESS}:{selector}\n")).count(),
        1,
        "missing/duplicate public native witness: {stdout}"
    );
    // Expected host panic uses the normal panic hook; nothing is suppressed.
    // Native stderr above has its own exact, nonpanic byte oracle. Do not mix
    // this deliberately panicking controller with the native runtime process.
    let host_stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        host_stderr.matches(tool::EXPECTED_CONTROLLER_PANIC).count(),
        1,
        "missing/duplicate intentional controller panic: {host_stderr}"
    );
    assert_eq!(
        host_stderr.matches("panicked at").count(),
        1,
        "unexpected additional host panic: {host_stderr}"
    );
}

#[test]
fn caller_startup_rpc_disconnect_before_started_is_native_transport_failure() {
    // Real Claim and Tool/thread-state construction precede handle_thread_start.
    // Its ordinary RPC is witnessed while pending. Started, post-exec, first
    // application execution and all consuming hooks must remain unreachable.
    run_case(
        "caller_startup_rpc_disconnect_before_started_is_native_transport_failure",
        DisconnectPoint::Startup,
    );
}
