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
        if self.mode == 21 {
            // Thread-creation injection: exercises the clone admission
            // sites instead of the exec route.
            let errno = guest
                .inject(syscall(libc::SYS_clone, [0x7d0f11, 0, 0, 0, 0, 0]))
                .await
                .unwrap_err();
            let refusal = guest.take_unsupported_refusal();
            self.returned.lock().unwrap().push((errno, refusal));
            *guest.thread_state_mut() = (3, 1);
            self.calls.lock().unwrap().push("rollback");
            return Ok(-i64::from(errno.into_raw()));
        }
        if self.mode == 22 {
            // Refused-first probe: an AT_EMPTY_PATH injection against a
            // plain-path original, then the exact original. Both must
            // refuse (scope exclusion, then already-attempted) with no
            // driver prepare in between.
            let plain = [libc::AT_FDCWD as i64 as u64, 0x1000, 0x2000, 0x3000, 0, 0];
            let mut empty_path = plain;
            empty_path[4] = libc::AT_EMPTY_PATH as u64;
            let first = guest
                .inject(syscall(libc::SYS_execveat, empty_path))
                .await
                .unwrap_err();
            let first_refusal = guest.take_unsupported_refusal();
            self.returned.lock().unwrap().push((first, first_refusal));
            let second = guest
                .inject(syscall(libc::SYS_execveat, plain))
                .await
                .unwrap_err();
            let second_refusal = guest.take_unsupported_refusal();
            self.returned.lock().unwrap().push((second, second_refusal));
            *guest.thread_state_mut() = (3, 1);
            self.calls.lock().unwrap().push("rollback");
            return Ok(-i64::from(first.into_raw()));
        }
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

struct ModelRuntime {
    watched: bool,
}
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
    fn exec_watch_armed(&self) -> bool {
        self.watched
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
    // a concrete driver. Under the lease model no lock is held across the
    // callback: the proof is now that a dispatch is counted active and the
    // calling thread's state is leased out, so reacquisition by the driver
    // would be refused rather than deadlock.
    let host =
        unsafe { &*(host.load(Ordering::Acquire) as *const ToolHost<ModelTool, ModelRuntime>) };
    assert!(host.dispatch_active());
    assert!(host.states.any_leased());
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

fn run_model(
    mode: usize,
    original_execve: bool,
    installed: bool,
    admitted: bool,
    source: SyscallDispatch,
) {
    run_model_watched(mode, original_execve, installed, admitted, source, false)
}

fn run_model_watched(
    mode: usize,
    original_execve: bool,
    installed: bool,
    admitted: bool,
    source: SyscallDispatch,
    watched: bool,
) {
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
        HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid, Sysno::clone]),
        false,
        ModelRuntime { watched },
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
        if admitted {
            unsafe { host.admit_native_exec() }.unwrap();
            assert!(host.native_exec_admitted());
        } else {
            assert!(!host.native_exec_admitted());
        }
    }
    let number = if mode == 10 {
        libc::SYS_getpid
    } else if mode == 21 {
        libc::SYS_clone
    } else if original_execve {
        libc::SYS_execve
    } else {
        libc::SYS_execveat
    };
    let args = if mode == 21 {
        [0x7d0f11, 0, 0, 0, 0, 0]
    } else if original_execve {
        [0x1000, 0x2000, 0x3000, 0, 0, 0]
    } else if mode == 20 {
        [
            libc::AT_FDCWD as i64 as u64,
            0x1000,
            0x2000,
            0x3000,
            libc::AT_EMPTY_PATH as u64,
            0,
        ]
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
        unsupported_refusal: None,
    };
    unsafe { host.dispatch(&mut event) };
    if mode == 19 {
        // No issue is reached in this stage, so no kernel permission
        // effect is applied: the event keeps its original PKRU.
        assert_eq!(event.guest_pkru, Some(0));
    }
    let results = returned.lock().unwrap();
    assert_eq!(results.len(), 1);
    let (errno, refusal) = results[0];
    assert_eq!(event.result, -i64::from(errno.into_raw()));
    assert_eq!(
        host.states
            .with_state(raw_pid(libc::SYS_gettid).as_raw(), |state| state.copied()),
        Some((3, 1))
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
    } else if !admitted {
        // Installed but not admitted: the driver is never consulted and
        // both routes keep their pre-admission typed refusals.
        assert_eq!(errno, Errno::EOPNOTSUPP);
        assert!(host.native_exec_driver.is_some());
        if mode == 21 {
            let refusal = refusal.expect("named thread-creation refusal");
            assert_eq!(
                refusal.operation,
                reverie::UnsupportedOperation::ThreadCreation
            );
            assert!(refusal.diagnostic.contains("cannot create a thread"));
        } else {
            assert_eq!(
                refusal,
                Some(reverie::UnsupportedRefusal::new(
                    reverie::UnsupportedOperation::Exec,
                    Errno::EOPNOTSUPP,
                    "the in-guest backend cannot replace the process image: execve and execveat \
                     are not forwarded",
                ))
            );
        }
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
    } else if mode == 20 {
        assert_eq!(errno, Errno::EOPNOTSUPP);
        let refusal = refusal.expect("named empty-path refusal");
        assert_eq!(refusal.operation, reverie::UnsupportedOperation::Exec);
        assert!(refusal.diagnostic.contains("AT_EMPTY_PATH"));
        let log = calls.lock().unwrap();
        assert!(log.contains(&"capture-old"));
        assert!(!log.contains(&"native-prepare"));
        assert_eq!(log.last(), Some(&"rollback"));
    } else if mode == 21 {
        assert_eq!(errno, Errno::EOPNOTSUPP);
        let refusal = refusal.expect("named thread-creation refusal");
        assert_eq!(
            refusal.operation,
            reverie::UnsupportedOperation::ThreadCreation
        );
        assert!(refusal.diagnostic.contains("does not arm thread"));
        let log = calls.lock().unwrap();
        assert_eq!(log.last(), Some(&"rollback"));
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
        // Contract correction (stage-1 final refusal): these modes used
        // to expect the mock driver's returned kernel errno via
        // "call-original". The host now cancels after revalidation and
        // refuses at the final step, so issue is unreachable and no
        // driver-chosen errno (modes 6-9) can leak to the guest.
        assert_eq!(errno, Errno::EOPNOTSUPP);
        let refusal = refusal.expect("named final-step refusal");
        assert_eq!(refusal.operation, reverie::UnsupportedOperation::NativeExec);
        assert!(refusal.diagnostic.contains("final step"));
        let log = calls.lock().unwrap();
        assert_eq!(
            *log,
            [
                "init",
                "thread-start",
                "initial-post-exec",
                "capture-old",
                "handler-prepare",
                "native-prepare",
                "native-revalidate",
                "native-cancel",
                "rollback"
            ]
        );
        assert_eq!(log.iter().filter(|c| **c == "call-original").count(), 0);
    }
    drop(results);
    drop(host);
    worker.join().unwrap();
}

#[test]
fn mock_driver_exact_original_and_detcore_normalization_borrow_real_state_before_rollback() {
    for execve in [false, true] {
        isolated(
            move || run_model(1, execve, true, true, SyscallDispatch::Fallback),
            0,
        );
    }
    isolated(|| run_model(1, false, true, true, SyscallDispatch::Trap), 0);
}
#[test]
fn mock_driver_default_absent_reports_the_named_exec_refusal() {
    isolated(
        || run_model(0, false, false, false, SyscallDispatch::Fallback),
        0,
    );
}
#[test]
fn mock_driver_capture_error_is_deferred_until_the_actual_nested_exec_and_rolled_back() {
    isolated(
        || run_model(2, false, true, true, SyscallDispatch::Fallback),
        0,
    );
}
#[test]
fn mock_driver_altered_argument_wrong_original_and_installed_hook_cannot_borrow_receipt() {
    for mode in [3, 10] {
        isolated(
            move || run_model(mode, false, true, true, SyscallDispatch::Fallback),
            0,
        );
    }
    isolated(
        || run_model(11, false, true, true, SyscallDispatch::InstalledHook),
        0,
    );
}
#[test]
fn mock_driver_prepared_and_final_refusals_cancel_only_owned_provision_before_rollback() {
    for mode in [4, 5, 16] {
        isolated(
            move || run_model(mode, false, true, true, SyscallDispatch::Fallback),
            0,
        );
    }
}
#[test]
fn admitted_exec_final_refusal_never_reaches_issue_for_any_driver_errno_mode() {
    for mode in [1, 6, 7, 8, 9] {
        isolated(
            move || run_model(mode, false, true, true, SyscallDispatch::Fallback),
            0,
        );
    }
}
#[test]
fn mock_driver_receipt_is_single_attempt_and_injection_record_is_consumed_or_replaced() {
    for mode in [13, 17] {
        isolated(
            move || run_model(mode, false, true, true, SyscallDispatch::Fallback),
            0,
        );
    }
}
#[test]
fn mock_driver_cancel_transport_failure_and_abandoned_transaction_are_terminal() {
    for mode in [14, 15, 18] {
        isolated(
            move || run_model(mode, false, true, true, SyscallDispatch::Fallback),
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
    let runtime = ModelRuntime { watched: false };
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        assert_eq!(
            injected_syscall_guard(&runtime, number, [0; 6]),
            Some(Errno::EOPNOTSUPP)
        );
    }
    // The guard alone defers to the watch; installed-native priority
    // on the tail route is enforced before the guard (see the
    // watched tail witness below), not by this predicate.
    let watched = ModelRuntime { watched: true };
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        assert_eq!(injected_syscall_guard(&watched, number, [0; 6]), None);
    }
}

#[test]
fn admitted_final_refusal_applies_no_kernel_permission_effect() {
    // Component-level only: with issue unreachable, cancellation
    // cannot carry a returned PKRU effect into the event.
    isolated(
        || run_model(19, true, true, true, SyscallDispatch::Fallback),
        0,
    );
}

#[test]
fn installed_driver_without_admission_keeps_named_exec_refusal() {
    for execve in [false, true] {
        isolated(
            move || run_model(1, execve, true, false, SyscallDispatch::Fallback),
            0,
        );
    }
}

#[test]
fn admitted_empty_path_execveat_refuses_by_name_before_prepare() {
    isolated(
        || run_model(20, false, true, true, SyscallDispatch::Fallback),
        0,
    );
}

#[test]
fn clone_refusal_names_admitted_final_step_only_when_admitted() {
    isolated(
        || run_model(21, false, true, true, SyscallDispatch::Fallback),
        0,
    );
    isolated(
        || run_model(21, false, true, false, SyscallDispatch::Fallback),
        0,
    );
}

#[test]
fn admission_requires_installed_driver_and_is_single_shot() {
    isolated(
        || {
            let (rpc, worker) = rpc();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let owner = Arc::new(AtomicUsize::new(0));
            let tool = ModelTool {
                mode: 1,
                calls: calls.clone(),
                returned: Arc::new(Mutex::new(Vec::new())),
            };
            let mut host = Box::new(ToolHost::new(
                tool,
                rpc,
                raw_pid(libc::SYS_getpid),
                HashSet::from([Sysno::execve]),
                false,
                ModelRuntime { watched: false },
            ));
            assert!(!host.native_exec_admitted());
            assert!(unsafe { host.admit_native_exec() }.is_err());
            unsafe {
                host.install_native_exec_driver(Arc::new(ModelDriver {
                    mode: 1,
                    host: owner,
                    calls,
                }))
            }
            .unwrap();
            assert!(!host.native_exec_admitted());
            unsafe { host.admit_native_exec() }.unwrap();
            assert!(host.native_exec_admitted());
            assert!(unsafe { host.admit_native_exec() }.is_err());
            drop(host);
            worker.join().unwrap();
        },
        0,
    );
}

#[test]
fn component_only_final_refusal_keeps_model_old_image_dispatching() {
    // COMPONENT-ONLY evidence: mock driver, synthetic events, manual
    // state rollback. This proves the host dispatch boundary stays
    // live after a final-step refusal (second dispatch captures and
    // refuses again); it is NOT a physical atomicity witness — no
    // kernel exec is issued and no genuine errno is observed. The
    // physical witness needs harness pieces that do not exist yet
    // (see the S1 fix-round design note).
    isolated(
        || {
            let _native = crate::guest::exec_private::native_exec_mock_callback();
            let (rpc, worker) = rpc();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let returned = Arc::new(Mutex::new(Vec::new()));
            let owner = Arc::new(AtomicUsize::new(0));
            let tool = ModelTool {
                mode: 1,
                calls: calls.clone(),
                returned: returned.clone(),
            };
            let mut host = Box::new(ToolHost::new(
                tool,
                rpc,
                raw_pid(libc::SYS_getpid),
                HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid]),
                false,
                ModelRuntime { watched: false },
            ));
            owner.store(
                &*host as *const ToolHost<ModelTool, ModelRuntime> as usize,
                Ordering::Release,
            );
            unsafe {
                host.install_native_exec_driver(Arc::new(ModelDriver {
                    mode: 1,
                    host: owner,
                    calls: calls.clone(),
                }))
            }
            .unwrap();
            unsafe { host.admit_native_exec() }.unwrap();
            for _ in 0..2 {
                let mut event = SyscallEvent {
                    number: libc::SYS_execveat,
                    args: [libc::AT_FDCWD as i64 as u64, 0x1000, 0x2000, 0x3000, 0, 0],
                    instruction_pointer: 0x1234,
                    result: 0,
                    context: 0,
                    dispatch: SyscallDispatch::Fallback,
                    guest_pkru: None,
                    unsupported_refusal: None,
                };
                unsafe { host.dispatch(&mut event) };
                assert_eq!(event.result, -i64::from(Errno::EOPNOTSUPP.into_raw()));
                assert_eq!(
                    host.states
                        .with_state(raw_pid(libc::SYS_gettid).as_raw(), |state| state.copied()),
                    Some((3, 1))
                );
            }
            let results = returned.lock().unwrap();
            assert_eq!(results.len(), 2);
            for (errno, refusal) in results.iter() {
                assert_eq!(*errno, Errno::EOPNOTSUPP);
                let refusal = refusal.expect("named final-step refusal");
                assert_eq!(refusal.operation, reverie::UnsupportedOperation::NativeExec);
                assert!(refusal.diagnostic.contains("final step"));
            }
            let log = calls.lock().unwrap();
            assert_eq!(log.iter().filter(|c| **c == "capture-old").count(), 2);
            assert_eq!(log.iter().filter(|c| **c == "call-original").count(), 0);
            drop(results);
            drop(log);
            drop(host);
            worker.join().unwrap();
        },
        0,
    );
}

#[test]
fn refused_first_empty_path_consumes_the_single_attempt() {
    // Refused-first probe: plain-path original; first injection adds
    // AT_EMPTY_PATH (scope refusal), second injects the exact
    // original and must meet the already-attempted latch, with no
    // driver prepare or issue in between.
    isolated(
        || {
            let _native = crate::guest::exec_private::native_exec_mock_callback();
            let (rpc, worker) = rpc();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let returned = Arc::new(Mutex::new(Vec::new()));
            let owner = Arc::new(AtomicUsize::new(0));
            let tool = ModelTool {
                mode: 22,
                calls: calls.clone(),
                returned: returned.clone(),
            };
            let mut host = Box::new(ToolHost::new(
                tool,
                rpc,
                raw_pid(libc::SYS_getpid),
                HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid]),
                false,
                ModelRuntime { watched: false },
            ));
            owner.store(
                &*host as *const ToolHost<ModelTool, ModelRuntime> as usize,
                Ordering::Release,
            );
            unsafe {
                host.install_native_exec_driver(Arc::new(ModelDriver {
                    mode: 22,
                    host: owner,
                    calls: calls.clone(),
                }))
            }
            .unwrap();
            unsafe { host.admit_native_exec() }.unwrap();
            let mut event = SyscallEvent {
                number: libc::SYS_execveat,
                args: [libc::AT_FDCWD as i64 as u64, 0x1000, 0x2000, 0x3000, 0, 0],
                instruction_pointer: 0x1234,
                result: 0,
                context: 0,
                dispatch: SyscallDispatch::Fallback,
                guest_pkru: None,
                unsupported_refusal: None,
            };
            unsafe { host.dispatch(&mut event) };
            assert_eq!(event.result, -i64::from(Errno::EOPNOTSUPP.into_raw()));
            let results = returned.lock().unwrap();
            assert_eq!(results.len(), 2);
            assert_eq!(results[0].0, Errno::EOPNOTSUPP);
            let first = results[0].1.expect("named empty-path refusal");
            assert_eq!(first.operation, reverie::UnsupportedOperation::Exec);
            assert!(first.diagnostic.contains("AT_EMPTY_PATH"));
            assert_eq!(results[1].0, Errno::EOPNOTSUPP);
            let second = results[1].1.expect("already-attempted refusal");
            assert_eq!(second.operation, reverie::UnsupportedOperation::NativeExec);
            assert!(second.diagnostic.contains("already attempted"));
            let log = calls.lock().unwrap();
            assert_eq!(log.iter().filter(|c| **c == "capture-old").count(), 1);
            assert_eq!(log.iter().filter(|c| **c == "native-prepare").count(), 0);
            assert_eq!(log.iter().filter(|c| **c == "call-original").count(), 0);
            drop(results);
            drop(log);
            drop(host);
            worker.join().unwrap();
        },
        0,
    );
}

#[test]
fn admission_after_dispatch_is_refused() {
    // Pins the states-nonempty guard: once a dispatch created Tool
    // state, admission follows dispatch and must fail. The sibling
    // dispatch-active WouldBlock guard (install gate held, an active
    // dispatch elsewhere) stays explicitly deferred (identical guard
    // to driver installation, same gate and errors).
    isolated(
        || {
            let _native = crate::guest::exec_private::native_exec_mock_callback();
            let (rpc, worker) = rpc();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let owner = Arc::new(AtomicUsize::new(0));
            let tool = ModelTool {
                mode: 1,
                calls: calls.clone(),
                returned: Arc::new(Mutex::new(Vec::new())),
            };
            let mut host = Box::new(ToolHost::new(
                tool,
                rpc,
                raw_pid(libc::SYS_getpid),
                HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid]),
                false,
                ModelRuntime { watched: false },
            ));
            owner.store(
                &*host as *const ToolHost<ModelTool, ModelRuntime> as usize,
                Ordering::Release,
            );
            unsafe {
                host.install_native_exec_driver(Arc::new(ModelDriver {
                    mode: 1,
                    host: owner,
                    calls,
                }))
            }
            .unwrap();
            let mut event = SyscallEvent {
                number: libc::SYS_execveat,
                args: [libc::AT_FDCWD as i64 as u64, 0x1000, 0x2000, 0x3000, 0, 0],
                instruction_pointer: 0x1234,
                result: 0,
                context: 0,
                dispatch: SyscallDispatch::Fallback,
                guest_pkru: None,
                unsupported_refusal: None,
            };
            unsafe { host.dispatch(&mut event) };
            assert!(unsafe { host.admit_native_exec() }.is_err());
            assert!(!host.native_exec_admitted());
            drop(host);
            worker.join().unwrap();
        },
        0,
    );
}

#[test]
fn mock_driver_watched_ordinary_inject_keeps_native_priority() {
    // Capture-refusing driver (mode 2) with the watch armed: the
    // ordinary subscribed route must still consult the admitted
    // native route and surface its exact NativeExec refusal.
    for execve in [false, true] {
        isolated(
            move || run_model_watched(2, execve, true, true, SyscallDispatch::Fallback, true),
            0,
        );
    }
}

// --- Watched-route controls (S-C fix round) ---
//
// Ordinary subscribed inject consults the admitted native route
// first (above). These controls pin the other physical routes —
// tail injection, lifecycle callbacks, unsubscribed originals —
// where no native capture exists for the dispatch: with the route
// admitted a watched exec must refuse by name instead of
// forwarding past native authority; with no driver it forwards
// and the kernel answers for the NULL path (EFAULT, untagged).
// All cases run in fork-isolated children; filenames are NULL so
// no exec can succeed.

#[derive(Clone, Copy, PartialEq)]
enum WatchAction {
    HandlerInject,
    HandlerHandledSuccess,
    HandlerHandledError,
    TailInject,
    TailMapping,
    ThreadStartInject,
    PostExecInject,
    Plain,
}

struct WatchedTool {
    action: WatchAction,
    number: i64,
    returned: ReturnedCalls,
}

// Only for the Tool supertrait bound; tests always construct with an
// explicit action and never fork (new_process would lose both).
impl Default for WatchedTool {
    fn default() -> Self {
        Self {
            action: WatchAction::Plain,
            number: libc::SYS_execve,
            returned: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl WatchedTool {
    fn null_args(&self) -> [u64; 6] {
        if self.number == libc::SYS_execveat {
            [libc::AT_FDCWD as i64 as u64, 0, 0, 0, 0, 0]
        } else {
            [0; 6]
        }
    }

    async fn record_exec<G: Guest<Self>>(&self, guest: &mut G) {
        let errno = guest
            .inject(syscall(self.number, self.null_args()))
            .await
            .unwrap_err();
        let refusal = guest.take_unsupported_refusal();
        self.returned.lock().unwrap().push((errno, refusal));
    }
}

#[reverie::tool]
impl Tool for WatchedTool {
    type GlobalState = ModelGlobal;
    type ThreadState = (u64, u64);
    fn init_thread_state(&self, _tid: Pid, _parent: Option<(Pid, &(u64, u64))>) -> (u64, u64) {
        (3, 1)
    }
    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        if self.action == WatchAction::ThreadStartInject {
            self.record_exec(guest).await;
        }
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        if self.action == WatchAction::PostExecInject {
            self.record_exec(guest).await;
        }
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _call: Syscall,
    ) -> Result<i64, Error> {
        match self.action {
            WatchAction::HandlerInject => {
                self.record_exec(guest).await;
                Ok(0)
            }
            WatchAction::HandlerHandledSuccess | WatchAction::HandlerHandledError => {
                // Handle the injection refusal WITHOUT taking its tag
                // (taking is an optional query), then answer with a
                // Tool-selected result. The outward event must not
                // attribute that handled refusal to this result.
                let errno = guest
                    .inject(syscall(self.number, self.null_args()))
                    .await
                    .unwrap_err();
                // The pair records the errno only; the tag is
                // deliberately left untaken.
                self.returned.lock().unwrap().push((errno, None));
                if self.action == WatchAction::HandlerHandledSuccess {
                    Ok(42)
                } else {
                    Err(Errno::EIO.into())
                }
            }
            WatchAction::TailInject => {
                guest
                    .tail_inject(syscall(self.number, self.null_args()))
                    .await
            }
            WatchAction::TailMapping => {
                guest.tail_inject(syscall(libc::SYS_mprotect, [0; 6])).await
            }
            _ => Ok(guest
                .inject(reverie::syscalls::Getpid::default())
                .await
                .unwrap()),
        }
    }
}

struct DenyDriver {
    captures: Arc<AtomicUsize>,
}

// SAFETY: model-only deny driver; capture always refuses by name and
// no session, ticket or kernel exec is ever created.
unsafe impl NativeExecDriver<WatchedTool> for DenyDriver {
    fn capture_old<'owner>(
        &'owner self,
        _tool: &WatchedTool,
        _state: &(u64, u64),
        _cut: &ExecCut,
        _rpc: &CoordinatorRpc<ModelGlobal>,
    ) -> Result<Box<dyn NativeExecSession<WatchedTool> + 'owner>, reverie::UnsupportedRefusal> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        Err(named("deny-driver: capture refused"))
    }
}

struct WatchOutcome {
    event_result: i64,
    event_refusal: Option<reverie::UnsupportedRefusal>,
    returned: Vec<(Errno, Option<reverie::UnsupportedRefusal>)>,
    captures: usize,
}

fn run_watched_case(
    action: WatchAction,
    number: i64,
    admitted: bool,
    subscribed: bool,
) -> WatchOutcome {
    let _native = crate::guest::exec_private::native_exec_mock_callback();
    let (rpc, worker) = rpc();
    let returned: ReturnedCalls = Arc::new(Mutex::new(Vec::new()));
    let captures = Arc::new(AtomicUsize::new(0));
    let tool = WatchedTool {
        action,
        number,
        returned: returned.clone(),
    };
    let subscriptions = if subscribed {
        HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid])
    } else {
        HashSet::from([Sysno::getpid])
    };
    let mut host = Box::new(ToolHost::new(
        tool,
        rpc,
        raw_pid(libc::SYS_getpid),
        subscriptions,
        false,
        ModelRuntime { watched: true },
    ));
    if admitted {
        unsafe {
            host.install_native_exec_driver(Arc::new(DenyDriver {
                captures: captures.clone(),
            }))
        }
        .unwrap();
        unsafe { host.admit_native_exec() }.unwrap();
        assert!(host.native_exec_admitted());
    }
    let (event_number, event_args) = match action {
        WatchAction::ThreadStartInject | WatchAction::PostExecInject => (libc::SYS_getpid, [0; 6]),
        _ if number == libc::SYS_execveat => {
            (number, [libc::AT_FDCWD as i64 as u64, 0, 0, 0, 0, 0])
        }
        _ => (number, [0; 6]),
    };
    let mut event = SyscallEvent {
        number: event_number,
        args: event_args,
        instruction_pointer: 0x1234,
        result: 0,
        context: 0,
        dispatch: SyscallDispatch::Fallback,
        guest_pkru: None,
        unsupported_refusal: None,
    };
    unsafe { host.dispatch(&mut event) };
    let outcome = WatchOutcome {
        event_result: event.result,
        event_refusal: event.unsupported_refusal,
        returned: returned.lock().unwrap().clone(),
        captures: captures.load(Ordering::SeqCst),
    };
    drop(host);
    worker.join().unwrap();
    outcome
}

#[test]
fn watched_tail_exec_refuses_with_admitted_driver() {
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        isolated(
            move || {
                let outcome = run_watched_case(WatchAction::TailInject, number, true, true);
                assert_eq!(outcome.event_result, -i64::from(libc::EOPNOTSUPP));
                // The named refusal must surface on the outward event,
                // not die in the dropped guest view.
                let refusal = outcome
                    .event_refusal
                    .expect("tail refusal identity on the event");
                assert_eq!(refusal.operation, reverie::UnsupportedOperation::NativeExec);
                assert!(refusal.diagnostic.contains("tail-injected"), "{refusal:?}");
                // The subscribed dispatch attempted its (refused)
                // capture once; the tail refusal precedes any
                // prepare/issue or physical forward.
                assert_eq!(outcome.captures, 1);
            },
            0,
        );
    }
}

#[test]
fn watched_tail_exec_forwards_without_driver() {
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        isolated(
            move || {
                let outcome = run_watched_case(WatchAction::TailInject, number, false, true);
                assert_eq!(outcome.event_result, -i64::from(libc::EFAULT));
            },
            0,
        );
    }
}

#[test]
fn watched_lifecycle_exec_refuses_with_admitted_driver() {
    for action in [WatchAction::ThreadStartInject, WatchAction::PostExecInject] {
        for number in [libc::SYS_execve, libc::SYS_execveat] {
            isolated(
                move || {
                    let outcome = run_watched_case(action, number, true, true);
                    assert_eq!(outcome.returned.len(), 1);
                    let (errno, refusal) = outcome.returned[0];
                    assert_eq!(errno, Errno::EOPNOTSUPP);
                    assert_eq!(
                        refusal.map(|r| r.operation),
                        Some(reverie::UnsupportedOperation::NativeExec)
                    );
                    assert_eq!(outcome.captures, 0);
                    assert!(outcome.event_result > 0, "getpid completes the dispatch");
                },
                0,
            );
        }
    }
}

#[test]
fn watched_lifecycle_exec_forwards_without_driver() {
    for action in [WatchAction::ThreadStartInject, WatchAction::PostExecInject] {
        for number in [libc::SYS_execve, libc::SYS_execveat] {
            isolated(
                move || {
                    let outcome = run_watched_case(action, number, false, true);
                    assert_eq!(outcome.returned, [(Errno::EFAULT, None)]);
                    assert!(outcome.event_result > 0, "getpid completes the dispatch");
                },
                0,
            );
        }
    }
}

#[test]
fn watched_unsubscribed_exec_refuses_with_admitted_driver() {
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        isolated(
            move || {
                let outcome = run_watched_case(WatchAction::Plain, number, true, false);
                assert_eq!(outcome.event_result, -i64::from(libc::EOPNOTSUPP));
                let refusal = outcome
                    .event_refusal
                    .expect("unsubscribed refusal identity on the event");
                assert_eq!(refusal.operation, reverie::UnsupportedOperation::NativeExec);
                assert_eq!(outcome.captures, 0);
            },
            0,
        );
    }
}

#[test]
fn watched_unsubscribed_exec_forwards_without_driver() {
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        isolated(
            move || {
                let outcome = run_watched_case(WatchAction::Plain, number, false, false);
                assert_eq!(outcome.event_result, -i64::from(libc::EFAULT));
            },
            0,
        );
    }
}

#[test]
fn watched_handled_inject_refusal_stays_off_event() {
    // The Tool receives the installed driver's refusal, handles it
    // without taking the optional tag, and answers with its own
    // result. That handled refusal is not behind the terminal
    // result, so the outward event must not attribute it.
    for (action, expected) in [
        (WatchAction::HandlerHandledSuccess, 42_i64),
        (WatchAction::HandlerHandledError, -i64::from(libc::EIO)),
    ] {
        for number in [libc::SYS_execve, libc::SYS_execveat] {
            isolated(
                move || {
                    let outcome = run_watched_case(action, number, true, true);
                    assert_eq!(outcome.returned, [(Errno::EOPNOTSUPP, None)]);
                    assert_eq!(outcome.event_result, expected);
                    assert_eq!(outcome.event_refusal, None);
                    assert_eq!(outcome.captures, 1);
                },
                0,
            );
        }
    }
}

#[test]
fn watched_consumed_tag_stays_off_event() {
    // Positive control: the Tool takes the tag inside the handler;
    // the event carries no refusal and the taken identity is exact.
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        isolated(
            move || {
                let outcome = run_watched_case(WatchAction::HandlerInject, number, true, true);
                assert_eq!(outcome.returned.len(), 1);
                let (errno, refusal) = outcome.returned[0];
                assert_eq!(errno, Errno::EOPNOTSUPP);
                assert_eq!(
                    refusal.map(|r| r.operation),
                    Some(reverie::UnsupportedOperation::NativeExec)
                );
                assert_eq!(outcome.event_refusal, None);
            },
            0,
        );
    }
}

#[test]
fn watched_tail_mapping_refusal_identity_reaches_event() {
    // check_native_mapping's terminal tail return: the driver's
    // typed refusal must surface on the outward event, whose
    // terminal result it is — not die in the guest-local slot.
    isolated(
        || {
            let outcome = run_watched_case(WatchAction::TailMapping, libc::SYS_getpid, true, true);
            assert_eq!(outcome.event_result, -i64::from(libc::EOPNOTSUPP));
            let refusal = outcome
                .event_refusal
                .expect("tail mapping refusal identity on the event");
            assert_eq!(refusal.operation, reverie::UnsupportedOperation::NativeExec);
            assert!(
                refusal
                    .diagnostic
                    .contains("native executable mapping owner is not installed"),
                "{refusal:?}"
            );
            // A non-exec dispatch attempts no native capture; the
            // mapping refusal precedes any prepare/issue.
            assert_eq!(outcome.captures, 0);
        },
        0,
    );
}

#[test]
fn watched_unsubscribed_mapping_refusal_identity_reaches_event() {
    isolated(
        || {
            let outcome = run_watched_case(WatchAction::Plain, libc::SYS_mprotect, true, false);
            assert_eq!(outcome.event_result, -i64::from(libc::EOPNOTSUPP));
            let refusal = outcome
                .event_refusal
                .expect("unsubscribed mapping refusal identity on the event");
            assert_eq!(refusal.operation, reverie::UnsupportedOperation::NativeExec);
            assert!(
                refusal
                    .diagnostic
                    .contains("native executable mapping owner is not installed"),
                "{refusal:?}"
            );
            assert_eq!(outcome.captures, 0);
        },
        0,
    );
}

#[test]
fn watched_ordinary_inject_forwards_without_driver() {
    for number in [libc::SYS_execve, libc::SYS_execveat] {
        isolated(
            move || {
                let outcome = run_watched_case(WatchAction::HandlerInject, number, false, true);
                assert_eq!(outcome.returned, [(Errno::EFAULT, None)]);
            },
            0,
        );
    }
}
