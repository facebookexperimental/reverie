/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Explicit mock-driver component controls. No test performs kernel exec,
//! authenticates a watched native launch, provisions FDs, or claims successor
//! execution. Actual host dispatch/borrows and callback query leaves are used.

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::*;
use crate::guest::native_exec::ExecCut;
use crate::guest::native_exec::NativeExecDriver;
use crate::guest::native_exec::NativeExecFailure;
use crate::guest::native_exec::NativeExecSession;
use crate::guest::native_exec::PreparedNativeExec;
use crate::guest::native_exec::ReturnedNativeExec;
use crate::guest::native_exec::TerminalExecFailure;

type ReturnedCalls = Arc<Mutex<Vec<(Errno, Option<reverie::UnsupportedRefusal>)>>>;

#[derive(Default)]
struct ModelGlobal;
#[reverie::tool]
impl GlobalTool for ModelGlobal {
    type Request = u64;
    type Response = u64;
    type Config = u64;
    async fn receive_rpc(&self, _from: Pid, message: u64) -> u64 {
        message
    }
}

#[derive(Default)]
struct ModelTool {
    mode: usize,
    calls: Arc<Mutex<Vec<&'static str>>>,
    returned: ReturnedCalls,
}
#[reverie::tool]
impl Tool for ModelTool {
    type GlobalState = ModelGlobal;
    type ThreadState = (u64, u64); // model epoch and table identity, not Detcore
    fn init_thread_state(&self, _tid: Pid, _parent: Option<(Pid, &(u64, u64))>) -> (u64, u64) {
        self.calls.lock().unwrap().push("init");
        (3, 1)
    }
    async fn handle_thread_start<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Error> {
        self.calls.lock().unwrap().push("thread-start");
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Errno> {
        self.calls.lock().unwrap().push("initial-post-exec");
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        self.calls.lock().unwrap().push("handler-prepare");
        assert_eq!(*guest.thread_state(), (3, 1));
        *guest.thread_state_mut() = (4, 2); // model normal prepared replacement
        let (number, args) = call.into_parts();
        let mut injected = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        if number == Sysno::execve {
            injected = [
                libc::AT_FDCWD as i64 as u64,
                injected[0],
                injected[1],
                injected[2],
                0,
                0,
            ];
        } else if number != Sysno::execveat {
            injected = [libc::AT_FDCWD as i64 as u64, 0x1000, 0x2000, 0x3000, 0, 0];
        }
        if self.mode == 3 {
            injected[2] ^= 1;
        }
        let normalized = syscall(libc::SYS_execveat, injected);
        let errno = guest.inject(normalized).await.unwrap_err();
        if self.mode == 17 {
            // Most-recent-injection semantics: an ordinary operation clears
            // the earlier named refusal even if the Tool did not take it.
            assert_eq!(
                guest
                    .inject(reverie::syscalls::Getpid::default())
                    .await
                    .unwrap(),
                raw_pid(libc::SYS_getpid).as_raw() as i64
            );
        }
        let refusal = guest.take_unsupported_refusal();
        assert_eq!(guest.take_unsupported_refusal(), None);
        self.returned.lock().unwrap().push((errno, refusal));
        *guest.thread_state_mut() = (3, 1); // model ordinary Detcore rollback
        self.calls.lock().unwrap().push("rollback");
        if self.mode == 13 {
            let errno = guest
                .inject(syscall(libc::SYS_execveat, injected))
                .await
                .unwrap_err();
            let refusal = guest
                .take_unsupported_refusal()
                .expect("duplicate named refusal");
            assert_eq!(errno, Errno::EOPNOTSUPP);
            assert!(refusal.diagnostic.contains("already attempted"));
            assert_eq!(guest.take_unsupported_refusal(), None);
        }
        Ok(-i64::from(errno.into_raw()))
    }
}

struct ModelRuntime;
impl HostRuntime for ModelRuntime {
    fn fork_child_rebind(&self) {
        panic!("mock exec does not fork")
    }
    fn emit_stage(&self, _stage: &[u8]) {}
    fn fork_child_reset(&self, _event: &SyscallEvent) {
        panic!("mock exec does not fork")
    }
    fn cpuid_interception_enabled(&self) -> bool {
        false
    }
    fn exit_process_stats(&self, _tid: Pid) -> io::Result<()> {
        Ok(())
    }
    fn read_clock(&self) -> io::Result<u64> {
        panic!("mock exec observes no clock")
    }
    fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
        crate::guest::signal::signal_action_supported(number, args)
    }
    fn reserved_signal_mask(&self) -> u64 {
        1_u64 << (libc::SIGSYS - 1)
    }
}

struct ModelDriver {
    mode: usize,
    host: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
struct ModelSession {
    mode: usize,
    tool: usize,
    state: usize,
    old_table: u64,
    original: (i64, [u64; 6]),
    host: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}
struct ModelPrepared<'a> {
    session: &'a ModelSession,
}

fn assert_host_guards(host: &AtomicUsize) {
    // Read-only component observation of the exact fixture host; never used by
    // a concrete driver. Failed try_lock cannot release the existing owner.
    let host =
        unsafe { &*(host.load(Ordering::Acquire) as *const ToolHost<ModelTool, ModelRuntime>) };
    assert!(host.tool.try_lock().is_none());
    assert!(host.states.try_lock().is_none());
}
fn named(text: &'static str) -> reverie::UnsupportedRefusal {
    reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::NativeExec,
        Errno::EOPNOTSUPP,
        text,
    )
}

// SAFETY: explicitly model-only driver. It runs no physical exec or native RPC
// and is never installed by a production initializer. Values below simulate
// returned errors solely to exercise the typed host boundary.
unsafe impl NativeExecDriver<ModelTool> for ModelDriver {
    fn capture_old<'owner>(
        &'owner self,
        tool: &ModelTool,
        state: &(u64, u64),
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<ModelGlobal>,
    ) -> Result<Box<dyn NativeExecSession<ModelTool> + 'owner>, reverie::UnsupportedRefusal> {
        assert_host_guards(&self.host);
        assert_eq!(*state, (3, 1)); // before model replacement preparation
        self.calls.lock().unwrap().push("capture-old");
        if self.mode == 2 || self.mode == 17 {
            return Err(named("mock-driver: old capability still live"));
        }
        Ok(Box::new(ModelSession {
            mode: self.mode,
            tool: tool as *const ModelTool as usize,
            state: state as *const (u64, u64) as usize,
            old_table: state.1,
            original: (cut.original().number(), cut.original().args()),
            host: self.host.clone(),
            calls: self.calls.clone(),
        }))
    }
}
// SAFETY: model-only session, no native ticket or descriptor is created.
unsafe impl NativeExecSession<ModelTool> for ModelSession {
    fn prepare<'a>(
        &'a mut self,
        tool: &ModelTool,
        state: &(u64, u64),
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<ModelGlobal>,
    ) -> Result<Box<dyn PreparedNativeExec<ModelTool> + 'a>, NativeExecFailure> {
        assert_host_guards(&self.host);
        assert_eq!(self.tool, tool as *const ModelTool as usize);
        assert_eq!(self.state, state as *const (u64, u64) as usize);
        assert_eq!(*state, (4, 2)); // same actual mutable storage after preparation
        assert_eq!(self.old_table, 1); // retained old identity, not replacement
        assert_eq!(
            self.original,
            (cut.original().number(), cut.original().args())
        );
        self.calls.lock().unwrap().push("native-prepare");
        if self.mode == 4 {
            return Err(NativeExecFailure::Refused(named(
                "mock-driver: prepared cut refused",
            )));
        }
        Ok(Box::new(ModelPrepared { session: self }))
    }
}
// SAFETY: no lease or kernel exec exists in this model transaction. It models
// cleanup/call outcomes, never an actual native launch or successful exec.
unsafe impl PreparedNativeExec<ModelTool> for ModelPrepared<'_> {
    fn revalidate(
        &mut self,
        tool: &ModelTool,
        state: &(u64, u64),
        _cut: &ExecCut,
        _rpc: &CoordinatorRpc<ModelGlobal>,
    ) -> Result<(), NativeExecFailure> {
        assert_host_guards(&self.session.host);
        assert_eq!(self.session.tool, tool as *const ModelTool as usize);
        assert_eq!(self.session.state, state as *const (u64, u64) as usize);
        assert_eq!(*state, (4, 2));
        self.session.calls.lock().unwrap().push("native-revalidate");
        if self.session.mode == 15 {
            panic!("deliberate model revalidation panic")
        }
        if self.session.mode == 18 {
            return Err(NativeExecFailure::Terminal(TerminalExecFailure {
                diagnostic: "mock-driver: revalidation transport lost",
            }));
        }
        if self.session.mode == 5 {
            return Err(NativeExecFailure::Refused(named(
                "mock-driver: final cut refused",
            )));
        }
        Ok(())
    }
    unsafe fn issue_and_call(
        &mut self,
        tool: &ModelTool,
        state: &(u64, u64),
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<ModelGlobal>,
    ) -> Result<ReturnedNativeExec, NativeExecFailure> {
        assert_host_guards(&self.session.host);
        assert_eq!(
            self.session.original,
            (cut.original().number(), cut.original().args())
        );
        assert_eq!(self.session.tool, tool as *const ModelTool as usize);
        assert_eq!(self.session.state, state as *const (u64, u64) as usize);
        assert_eq!(*state, (4, 2));
        self.session.calls.lock().unwrap().push("call-original");
        if self.session.mode == 16 {
            return Err(NativeExecFailure::Refused(named(
                "mock-driver: issue refused",
            )));
        }
        Ok(ReturnedNativeExec {
            errno: match self.session.mode {
                6 => Errno::ENOSYS,
                7 => Errno::EOPNOTSUPP,
                8 => Errno::EACCES,
                9 => Errno::ENOEXEC,
                _ => Errno::ENOENT,
            },
            pkru: if self.session.mode == 19 {
                Some(0x40)
            } else {
                cut.original().pkru()
            },
        })
    }
    fn cancel(
        self: Box<Self>,
        _rpc: &CoordinatorRpc<ModelGlobal>,
    ) -> Result<(), TerminalExecFailure> {
        if self.session.mode == 18 {
            // A terminal transport failure must make no further driver call.
            // Distinct child status makes any attempted Cancel a test failure.
            unsafe { libc::_exit(126) }
        }
        assert_host_guards(&self.session.host);
        self.session.calls.lock().unwrap().push("native-cancel");
        if self.session.mode == 14 {
            return Err(TerminalExecFailure {
                diagnostic: "mock-driver: cancel transport lost",
            });
        }
        Ok(())
    }
}

fn syscall(number: i64, args: [u64; 6]) -> Syscall {
    Syscall::from_raw(
        Sysno::new(number as usize).unwrap(),
        SyscallArgs::new(
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
            args[5] as usize,
        ),
    )
}
fn write_frame(stream: &mut UnixStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
}
fn rpc() -> (CoordinatorRpc<ModelGlobal>, std::thread::JoinHandle<()>) {
    let (client, mut server) = UnixStream::pair().unwrap();
    for socket in [&client, &server] {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let tid = raw_pid(libc::SYS_gettid);
    let worker = std::thread::spawn(move || {
        write_frame(
            &mut server,
            &reverie_rpc_transport::codec::encode(&902_u64).unwrap(),
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            server.read(&mut byte).unwrap(),
            0,
            "mock injection makes no RPC"
        );
    });
    let client = reverie_rpc_transport::BlockingRpcClient::from_connected_stream(
        crate::guest::rpc::GuestRpcStream::from(client),
        tid,
    )
    .unwrap();
    let rpc = CoordinatorRpc::from_live_client("unused-mock-native-exec", client, |_, _| {
        panic!("mock injection must not reconnect")
    })
    .unwrap();
    (rpc, worker)
}
fn isolated(body: impl FnOnce() + std::panic::UnwindSafe, expected: i32) {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let status = if std::panic::catch_unwind(body).is_ok() {
            0
        } else {
            125
        };
        unsafe { libc::_exit(status) }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), expected);
}

fn run_model(mode: usize, original_execve: bool, installed: bool, source: SyscallDispatch) {
    let _native = crate::guest::exec_private::native_exec_mock_callback();
    let (rpc, worker) = rpc();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let returned = Arc::new(Mutex::new(Vec::new()));
    let owner = Arc::new(AtomicUsize::new(0));
    let tool = ModelTool {
        mode,
        calls: calls.clone(),
        returned: returned.clone(),
    };
    let mut host = Box::new(ToolHost::new(
        tool,
        rpc,
        raw_pid(libc::SYS_getpid),
        HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid]),
        false,
        ModelRuntime,
    ));
    assert!(host.native_exec_driver.is_none());
    owner.store(
        &*host as *const ToolHost<ModelTool, ModelRuntime> as usize,
        Ordering::Release,
    );
    if installed {
        unsafe {
            host.install_native_exec_driver(Arc::new(ModelDriver {
                mode,
                host: owner.clone(),
                calls: calls.clone(),
            }))
        }
        .unwrap();
        assert!(
            unsafe {
                host.install_native_exec_driver(Arc::new(ModelDriver {
                    mode,
                    host: owner.clone(),
                    calls: calls.clone(),
                }))
            }
            .is_err()
        );
    }
    let number = if mode == 10 {
        libc::SYS_getpid
    } else if original_execve {
        libc::SYS_execve
    } else {
        libc::SYS_execveat
    };
    let args = if original_execve {
        [0x1000, 0x2000, 0x3000, 0, 0, 0]
    } else {
        [libc::AT_FDCWD as i64 as u64, 0x1000, 0x2000, 0x3000, 0, 0]
    };
    let mut event = SyscallEvent {
        number,
        args,
        instruction_pointer: 0x1234,
        result: 0,
        context: 0,
        dispatch: source,
        guest_pkru: if mode == 19 { Some(0) } else { None },
    };
    unsafe { host.dispatch(&mut event) };
    if mode == 19 {
        assert_eq!(event.guest_pkru, Some(0x40));
    }
    let results = returned.lock().unwrap();
    assert_eq!(results.len(), 1);
    let (errno, refusal) = results[0];
    assert_eq!(event.result, -i64::from(errno.into_raw()));
    assert_eq!(
        host.states.lock().get(&raw_pid(libc::SYS_gettid).as_raw()),
        Some(&(3, 1))
    );
    if !installed {
        assert_eq!(errno, Errno::EOPNOTSUPP);
        assert_eq!(
            refusal,
            Some(reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::Exec,
                Errno::EOPNOTSUPP,
                "the in-guest backend cannot replace the process image: execve and execveat \
                 are not forwarded",
            ))
        );
        assert!(
            unsafe {
                host.install_native_exec_driver(Arc::new(ModelDriver {
                    mode,
                    host: owner.clone(),
                    calls: calls.clone(),
                }))
            }
            .is_err()
        );
        assert!(host.native_exec_driver.is_none());
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "init",
                "thread-start",
                "initial-post-exec",
                "handler-prepare",
                "rollback"
            ]
        );
    } else if matches!(mode, 2 | 3 | 4 | 5 | 10 | 11 | 16 | 17) {
        assert_eq!(errno, Errno::EOPNOTSUPP);
        if mode == 17 {
            assert_eq!(refusal, None);
        } else {
            assert_eq!(
                refusal.unwrap().operation,
                reverie::UnsupportedOperation::NativeExec
            );
        }
        let log = calls.lock().unwrap();
        assert_eq!(&log[..3], &["init", "thread-start", "initial-post-exec"]);
        assert_eq!(log.last(), Some(&"rollback"));
        if mode == 2 || mode == 17 {
            assert_eq!(&log[3..], &["capture-old", "handler-prepare", "rollback"]);
        }
        if mode == 3 || mode == 10 || mode == 11 {
            assert!(!log.contains(&"native-prepare"));
            assert!(!log.contains(&"call-original"));
        }
        if mode == 4 {
            assert!(!log.contains(&"native-cancel"));
        }
        if mode == 5 {
            assert!(!log.contains(&"call-original"));
            assert_eq!(log[log.len() - 2], "native-cancel");
        }
        if mode == 16 {
            assert_eq!(log[log.len() - 2], "native-cancel");
        }
    } else {
        assert_eq!(refusal, None); // even model ENOSYS/EOPNOTSUPP stays untagged
        assert_eq!(
            errno,
            match mode {
                6 => Errno::ENOSYS,
                7 => Errno::EOPNOTSUPP,
                8 => Errno::EACCES,
                9 => Errno::ENOEXEC,
                _ => Errno::ENOENT,
            }
        );
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "init",
                "thread-start",
                "initial-post-exec",
                "capture-old",
                "handler-prepare",
                "native-prepare",
                "native-revalidate",
                "call-original",
                "native-cancel",
                "rollback"
            ]
        );
    }
    drop(results);
    drop(host);
    worker.join().unwrap();
}

#[test]
fn mock_driver_exact_original_and_detcore_normalization_borrow_real_state_before_rollback() {
    for execve in [false, true] {
        isolated(
            move || run_model(1, execve, true, SyscallDispatch::Fallback),
            0,
        );
    }
    isolated(|| run_model(1, false, true, SyscallDispatch::Trap), 0);
}
#[test]
fn mock_driver_default_absent_reports_the_named_exec_refusal() {
    isolated(|| run_model(0, false, false, SyscallDispatch::Fallback), 0);
}
#[test]
fn mock_driver_capture_error_is_deferred_until_the_actual_nested_exec_and_rolled_back() {
    isolated(|| run_model(2, false, true, SyscallDispatch::Fallback), 0);
}
#[test]
fn mock_driver_altered_argument_wrong_original_and_installed_hook_cannot_borrow_receipt() {
    for mode in [3, 10] {
        isolated(
            move || run_model(mode, false, true, SyscallDispatch::Fallback),
            0,
        );
    }
    isolated(
        || run_model(11, false, true, SyscallDispatch::InstalledHook),
        0,
    );
}
#[test]
fn mock_driver_prepared_and_final_refusals_cancel_only_owned_provision_before_rollback() {
    for mode in [4, 5, 16] {
        isolated(
            move || run_model(mode, false, true, SyscallDispatch::Fallback),
            0,
        );
    }
}
#[test]
fn mock_driver_returned_kernel_errno_has_no_named_refusal_even_when_errno_matches() {
    for mode in [1, 6, 7, 8, 9] {
        isolated(
            move || run_model(mode, false, true, SyscallDispatch::Fallback),
            0,
        );
    }
}
#[test]
fn mock_driver_receipt_is_single_attempt_and_injection_record_is_consumed_or_replaced() {
    for mode in [13, 17] {
        isolated(
            move || run_model(mode, false, true, SyscallDispatch::Fallback),
            0,
        );
    }
}
#[test]
fn mock_driver_cancel_transport_failure_and_abandoned_transaction_are_terminal() {
    for mode in [14, 15, 18] {
        isolated(
            move || run_model(mode, false, true, SyscallDispatch::Fallback),
            127,
        );
    }
}
#[test]
fn mock_driver_assertion_panic_is_an_explicit_nonzero_child_failure() {
    isolated(|| panic!("deliberate mock driver assertion"), 125);
}

#[test]
fn mock_driver_tail_exec_keeps_the_original_process_guard_refusal() {
    let runtime = ModelRuntime;
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        assert_eq!(
            injected_syscall_guard(&runtime, number, [0; 6]),
            Some(Errno::EOPNOTSUPP)
        );
    }
}

#[test]
fn mock_returned_exec_permission_effect_survives_cancellation_and_errno() {
    // Typed host propagation only, not a physical PKRU or kernel exec claim.
    isolated(|| run_model(19, true, true, SyscallDispatch::Fallback), 0);
}
