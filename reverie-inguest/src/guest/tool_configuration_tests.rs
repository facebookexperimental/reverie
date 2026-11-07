/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;

use reverie::Subscription;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::codec::encode;

use super::super::rpc::GuestRpcStream;
use super::*;

static EVENTS: Mutex<Vec<(i32, usize)>> = Mutex::new(Vec::new());
#[cfg(feature = "rcb-clock")]
const PREFLIGHT_CHILD: &str = "REVERIE_CONFIGURATION_PREFLIGHT_CHILD";

// One-byte writes witness constructor entry even if failed installation later
// terminates the process without unwinding. A failed witness is never exit127.
#[cfg(feature = "rcb-clock")]
fn preflight_witness(event: u8) {
    // SAFETY: fd0 is the child-only socket supplied by this test's parent, and
    // event is a live one-byte buffer for the duration of the write.
    if unsafe { libc::write(0, (&event as *const u8).cast(), 1) } != 1 {
        // SAFETY: this is an unrecoverable test-control failure in a subprocess.
        unsafe { libc::_exit(125) };
    }
}
struct Remote;
impl Default for Remote {
    fn default() -> Self {
        panic!("the coordinator owns G")
    }
}
#[reverie::global_tool]
impl GlobalTool for Remote {
    type Config = u64;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Pid, _: ()) {
        panic!("no local RPC")
    }
}
#[derive(Default)]
struct Probe {
    pid: i32,
}
#[reverie::tool]
impl Tool for Probe {
    type GlobalState = Remote;
    type ThreadState = (i32, i32, u64);
    fn subscriptions(config: &u64) -> Subscription {
        assert_eq!(*config, 71);
        EVENTS
            .lock()
            .unwrap()
            .push((-1, config as *const u64 as usize));
        Subscription::from_iter([Sysno::write])
    }
    fn new(pid: Pid, config: &u64) -> Self {
        #[cfg(feature = "rcb-clock")]
        if std::env::var_os(PREFLIGHT_CHILD).is_some() {
            preflight_witness(b'C');
        }
        assert_eq!(*config, 71);
        EVENTS
            .lock()
            .unwrap()
            .push((pid.as_raw(), config as *const u64 as usize));
        Self { pid: pid.as_raw() }
    }
    fn init_thread_state(
        &self,
        tid: Pid,
        parent: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        assert_eq!(EVENTS.lock().unwrap().last().unwrap().0, self.pid);
        match parent {
            None => (self.pid, tid.as_raw(), 71),
            Some((parent_tid, state)) => {
                assert_eq!(parent_tid.as_raw(), state.1);
                (self.pid, tid.as_raw(), state.2 + 1)
            }
        }
    }
}

fn send_config_and_require_no_request(mut server: UnixStream) {
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let bytes = encode(&71_u64).unwrap();
    server
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    server.write_all(&bytes).unwrap();
    assert_eq!(server.read(&mut [0; 1]).unwrap(), 0);
}
fn coordinator() -> (CoordinatorRpc<Remote>, std::thread::JoinHandle<()>) {
    let (client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || send_config_and_require_no_request(server));
    let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
    let client =
        BlockingRpcClient::from_connected_stream(GuestRpcStream::from(client), tid).unwrap();
    let rpc = CoordinatorRpc::from_live_client("unused-fork-path", client, |_, _| Ok(())).unwrap();
    (rpc, server)
}

#[test]
fn retained_configuration_is_shared_by_rpc_host_and_fork_constructor() {
    // These are distinct modeled application process/thread identities. The
    // live coordinator connection is stamped with this test's actual TID.
    let pid = Pid::from_raw(31);
    let tid = Pid::from_raw(37);
    let child_pid = Pid::from_raw(41);
    let child_tid = Pid::from_raw(43);
    EVENTS.lock().unwrap().clear();
    let (rpc, server) = coordinator();
    let original = rpc.shared_config();
    let owner = ToolConfiguration::<Probe>::select(rpc.shared_config());
    assert!(Arc::ptr_eq(&original, &owner.shared_config()));
    assert!(std::ptr::eq(rpc.config(), owner.config()));
    let inherited = owner.clone();
    assert!(Arc::ptr_eq(&original, &inherited.shared_config()));
    let tool = owner.new_process(pid);
    let parent = tool.init_thread_state(tid, None);
    let selection = owner.subscriptions().iter_syscalls().collect();
    let host = ToolHost::with_configuration(tool, rpc, pid, owner, selection, Runtime);
    assert!(std::ptr::eq(host.rpc().config(), Arc::as_ptr(&original)));
    assert!(host.tool.lock().selected_configuration().is_some());
    let child = host.tool.lock().new_process(child_pid, host.rpc().config());
    let state = child.init_thread_state(child_tid, Some((tid, &parent)));
    assert_eq!(parent, (31, 37, 71));
    assert_eq!(state, (41, 43, 72));
    let address = Arc::as_ptr(&original) as usize;
    assert_eq!(
        *EVENTS.lock().unwrap(),
        [(-1, address), (31, address), (41, address)]
    );
    drop(host);
    server.join().unwrap();

    // The private installer can retain a restored Tool. Its explicit legacy
    // constructor neither selects nor constructs another root Tool.
    let (rpc, server) = coordinator();
    let address = rpc.config() as *const u64 as usize;
    EVENTS.lock().unwrap().clear();
    let host = ToolHost::new(Probe { pid: 97 }, rpc, pid, HashSet::new(), false, Runtime);
    assert!(host.tool.lock().selected_configuration().is_none());
    assert!(EVENTS.lock().unwrap().is_empty());
    assert_eq!(host.tool.lock().as_ref().unwrap().pid, 97);
    assert_eq!(
        host.tool
            .lock()
            .new_process(child_pid, host.rpc().config())
            .as_ref()
            .unwrap()
            .pid,
        41
    );
    assert_eq!(*EVENTS.lock().unwrap(), [(41, address)]);
    drop(host);
    server.join().unwrap();
}

struct Runtime;
impl HostRuntime for Runtime {
    fn fork_child_rebind(&self) {
        panic!("no physical fork")
    }
    fn emit_stage(&self, _: &[u8]) {}
    fn fork_child_reset(&self, _: &SyscallEvent) {
        panic!("no physical fork")
    }
    fn cpuid_interception_enabled(&self) -> bool {
        false
    }
    fn exit_process_stats(&self, _: Pid) -> io::Result<()> {
        panic!("no exit dispatch")
    }
    fn read_clock(&self) -> io::Result<u64> {
        panic!("no clock dispatch")
    }
    fn signal_action_supported(&self, _: i64, _: [u64; 6]) -> bool {
        false
    }
    fn reserved_signal_mask(&self) -> u64 {
        0
    }
}

// Exercise the standard installer, including both sides of selection. The
// fixed-gate feature also requires unfiltered-process admission and terminates
// a failed install after gate publication. The witness covers the entire failed
// attempt, including any erroneous construction before that mandatory exit.
#[cfg(feature = "rcb-clock")]
#[test]
fn retained_configuration_preflight_failure_never_constructs_the_tool() {
    use super::super::tool_install::PatchHost;
    use super::super::tool_install::install_tool_with;
    use crate::guest::runtime_seam::PatcherRef;
    use crate::lifecycle::RuntimeConfig;
    use crate::stats::GuestStatsHooks;
    const TEST: &str = "guest::host::tool_configuration_tests::retained_configuration_preflight_failure_never_constructs_the_tool";
    let Some(phase) = std::env::var_os(PREFLIGHT_CHILD) else {
        for phase in ["before-selection", "after-selection"] {
            let (mut witness, child_witness) = UnixStream::pair().unwrap();
            witness
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(PREFLIGHT_CHILD, phase)
                .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
                    child_witness,
                )))
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("preflight control exceeded ten seconds");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let socket_path =
                std::env::temp_dir().join(format!("reverie-config-preflight-{}.sock", child.id()));
            let output = child.wait_with_output().unwrap();
            if socket_path.exists() {
                std::fs::remove_file(socket_path).unwrap();
            }
            let mut events = Vec::new();
            witness.read_to_end(&mut events).unwrap();
            let expected: &[u8] = if phase == "before-selection" {
                b""
            } else {
                b"S"
            };
            assert_eq!(
                events,
                expected,
                "selection/constructor witness for {phase}, child status {:?}",
                output.status.code()
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            let summaries: Vec<_> = stdout
                .lines()
                .filter(|line| line.starts_with("test result: "))
                .collect();
            if cfg!(feature = "fixed-syscall-gates") && phase == "after-selection" {
                assert_eq!(output.status.code(), Some(127));
                assert!(
                    summaries.is_empty(),
                    "failed install must not return: {stdout}"
                );
            } else {
                assert!(output.status.success(), "child failed: {stdout}");
                assert!(
                    matches!(summaries.as_slice(), [summary] if summary.starts_with(
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                    )),
                    "expected exactly one completed child test: {stdout}"
                );
            }
        }
        return;
    };
    struct RefusingHost {
        early: bool,
    }
    // SAFETY: this fixture refuses before vDSO/signal/filter activation and
    // never supplies a patcher or runs application code.
    unsafe impl PatchHost for RefusingHost {
        type Runtime = Runtime;
        fn patcher(&self) -> &'static PatcherRef {
            panic!("preflight must precede patching")
        }
        fn preflight(&self) -> io::Result<()> {
            if self.early {
                Err(io::Error::other("before-selection"))
            } else {
                Ok(())
            }
        }
        fn initialize_continuation(&self) -> io::Result<()> {
            Ok(())
        }
        fn site_patching(&self) -> io::Result<bool> {
            let events = EVENTS.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].0, -1);
            drop(events);
            assert_eq!(
                crate::trap::fixed_gates_published(),
                cfg!(feature = "fixed-syscall-gates")
            );
            preflight_witness(b'S');
            Err(io::Error::other("after-selection"))
        }
        fn stage_stream(&self) -> io::Result<bool> {
            panic!("must not activate")
        }
        fn process_forks_allowed(&self) -> io::Result<bool> {
            panic!("must not activate")
        }
        fn sigalrm_handlers(&self) -> io::Result<bool> {
            panic!("must not activate")
        }
        fn runtime_config(&self) -> io::Result<RuntimeConfig> {
            panic!("must not activate")
        }
        fn runtime(&self, _: GuestStatsHooks) -> Runtime {
            panic!("must not construct host")
        }
    }
    let early = phase == "before-selection";
    let path = std::env::temp_dir().join(format!(
        "reverie-config-preflight-{}.sock",
        std::process::id()
    ));
    let server = if early {
        None
    } else {
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        Some(std::thread::spawn(move || {
            send_config_and_require_no_request(listener.accept().unwrap().0)
        }))
    };
    EVENTS.lock().unwrap().clear();
    // SAFETY: one fresh subprocess, fixture refuses before any runtime activation.
    let result = unsafe { install_tool_with::<Probe, _>(&path, false, RefusingHost { early }) };
    assert_eq!(result.unwrap_err().to_string(), phase.to_str().unwrap());
    let events = EVENTS.lock().unwrap();
    assert_eq!(events.len(), usize::from(!early));
    assert!(events.iter().all(|(operation, _)| *operation == -1));
    drop(events);
    if let Some(server) = server {
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
