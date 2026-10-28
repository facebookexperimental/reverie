/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;

use reverie_rpc_transport::codec::encode;

use super::*;

struct Remote;
impl Default for Remote {
    fn default() -> Self {
        panic!("bootstrap must not construct a GlobalTool")
    }
}
#[reverie::global_tool]
impl GlobalTool for Remote {
    type Config = u64;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Pid, _: ()) {
        panic!("bootstrap must not send Tool RPC")
    }
}
#[derive(Default)]
struct Configured;
#[reverie::tool]
impl Tool for Configured {
    type GlobalState = Remote;
    type ThreadState = u64;
    fn subscriptions(config: &u64) -> reverie::Subscription {
        assert_eq!(*config, 71);
        reverie::Subscription::from_iter([Sysno::write])
    }
    fn new(_: Pid, _: &u64) -> Self {
        panic!("a configuration reader is not an application process")
    }
}

#[test]
fn typed_configuration_uses_exact_decoder_and_selects_without_constructing_a_tool() {
    for bytes in [
        encode(&71_u64).unwrap(),
        vec![1],
        [encode(&71_u64).unwrap(), vec![0]].concat(),
    ] {
        let valid = bytes == encode(&71_u64).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            socket
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            socket.write_all(&bytes).unwrap();
            assert_eq!(
                socket.read(&mut [0_u8; 1]).unwrap(),
                0,
                "configuration receipt sent an application request"
            );
        });
        let result = read_tool_configuration::<Configured>(&path);
        if valid {
            let owner = result.unwrap();
            assert_eq!(*owner.config(), 71);
            assert!(std::ptr::eq(
                owner.config(),
                Arc::as_ptr(&owner.shared_config())
            ));
            assert_eq!(
                owner.subscriptions().iter_syscalls().collect::<Vec<_>>(),
                [Sysno::write]
            );
        } else {
            assert!(result.is_err(), "malformed/trailing Config was accepted");
        }
        server.join().unwrap();
    }
}

#[cfg(feature = "prototype-runtime")]
#[test]
fn exact_unit_configuration_requires_publication_and_never_defaults_after_refusal() {
    #[derive(Default)]
    struct Unit;
    #[reverie::tool]
    impl Tool for Unit {
        type GlobalState = ();
        type ThreadState = ();
        fn new(_: Pid, _: &()) -> Self {
            panic!("bootstrap must not construct T")
        }
    }
    let slot = std::sync::OnceLock::new();
    assert_eq!(
        required_tool_configuration::<Unit>(&slot).err(),
        Some("selected Tool configuration was not published")
    );
    assert!(unit_tool_configuration::<Unit>(DbtStartupMode::Coordinated, None).is_err());
    assert!(
        unit_tool_configuration::<Unit>(DbtStartupMode::Standalone, Some(std::ffi::OsStr::new("")))
            .is_err()
    );
    assert!(required_tool_configuration::<Unit>(&slot).is_err());
    let owner = unit_tool_configuration::<Unit>(DbtStartupMode::Standalone, None).unwrap();
    let original = owner.shared_config();
    assert!(slot.set(owner).is_ok());
    assert!(Arc::ptr_eq(
        &original,
        &required_tool_configuration(&slot).unwrap().shared_config()
    ));
    // Selection remains all-syscalls; the prototype does not add filtering.
    assert!(
        required_tool_configuration(&slot)
            .unwrap()
            .subscriptions()
            .iter_syscalls()
            .any(|s| s == Sysno::read)
    );
}

#[cfg(feature = "prototype-runtime")]
#[test]
fn exact_configuration_is_retained_before_background_ready() {
    const CHILD: &str = "REVERIE_DBT_CONFIGURATION_READY_CHILD";
    const TEST: &str =
        "tests::tool_configuration::exact_configuration_is_retained_before_background_ready";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env(TOOL_ENV, "counter1")
            .env_remove(sync_rpc::RPC_SOCKET_ENV)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("background initialization exceeded ten seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let summaries: Vec<_> = stdout
            .lines()
            .filter(|line| line.starts_with("test result: "))
            .collect();
        assert!(
            matches!(summaries.as_slice(), [summary] if summary.starts_with(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            )),
            "expected exactly one completed child test: {stdout}"
        );
        return;
    }
    unsafe extern "C" fn emit(_: *const u8, _: usize) {}
    unsafe extern "C" fn idle() {
        panic!("no background polling")
    }
    unsafe extern "C" fn compare(_: usize, _: u32, _: u32, _: *mut u32) -> i32 {
        panic!("no memory access")
    }
    unsafe extern "C" fn capture(_: usize, _: u32, _: *mut NativeControllerCaptureFact) -> i32 {
        panic!("no admission")
    }
    unsafe extern "C" fn private(
        _: usize,
        _: *const NativePrivateMemorySnapshot,
        _: *mut NativePrivateMemorySnapshot,
    ) -> i32 {
        panic!("no memory query")
    }
    unsafe extern "C" fn branches(_: usize, _: *mut NativeBranchFact) -> i32 {
        panic!("no branch query")
    }
    unsafe extern "C" fn mapping(_: usize, _: u32, _: *mut NativeMappingCapture) -> i32 {
        panic!("no capture")
    }
    unsafe extern "C" fn terminal(
        _: usize,
        _: i64,
        _: *const u64,
        _: *mut caller_abi::TerminalFact,
    ) -> i32 {
        panic!("no terminal admission")
    }
    let mut callbacks = DbtRuntimeCallbacks {
        emit,
        idle,
        panic_on_unsupported_syscalls: 0,
        unsupported_report_fd: -1,
        emit_stdout: emit,
        emit_evidence: emit,
        evidence_log_level: 0,
        compare_exchange_u32: compare,
        controller_capture_control: capture,
        runtime_private_memory: private,
        branch_fact: branches,
        mapping_capture: mapping,
        admit_terminal: terminal,
        rpc_transport_fatal: None,
    };
    let generation = reverie_dbt_runtime_image_init().image_generation;
    assert_eq!(READY_IMAGE_GENERATION.load(Ordering::Acquire), 0);
    assert!(tools::counter1_exact_configuration().is_err());
    let argument = (&mut callbacks as *mut DbtRuntimeCallbacks).cast();
    // Config-only failure cannot publish an owner or READY.
    assert_eq!(
        unsafe { reverie_dbt_runtime_background_init_v3(argument, 2) },
        1
    );
    assert_eq!(READY_IMAGE_GENERATION.load(Ordering::Acquire), 0);
    assert!(tools::counter1_exact_configuration().is_err());
    assert_eq!(
        unsafe { reverie_dbt_runtime_background_init_v3(argument, 1) },
        0
    );
    assert_eq!(READY_IMAGE_GENERATION.load(Ordering::Acquire), generation);
    assert!(tools::counter1_exact_configuration().is_ok());
    assert!(
        tools::recorder_configuration().is_err(),
        "unselected Tool was initialized"
    );
}
