/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! CallerRuntime with the real RPC server, codec and sockets. Native contexts,
//! filter admission and terminal reservations below are explicit unit fixtures,
//! not DynamoRIO execution or evidence of actual application exit.

use std::cell::Cell;
use std::cell::RefCell;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Waker;
use std::thread::ThreadId;
use std::time::Duration;
use std::time::Instant;

use reverie::ExitStatus;
use reverie::Guest;
use reverie::InjectionPurpose;
use reverie::Subscription;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::SyscallInfo;
use reverie_rpc_transport::ConnectionMonitor;
use reverie_rpc_transport::RpcIssueMonitor;
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::tool_activation::ActivationRun;
use serde::Deserialize;
use serde::Serialize;

use super::*;

const CHILD_CASE: &str = "REVERIE_DBT_CALLER_RUNTIME_UNIT_CASE";
const TEST_NAME: &str = "caller_runtime::tests::caller_runtime_protocol";
const WITNESS: &str = "CALLER_RUNTIME_UNIT_COMPLETED";
const SEED: u64 = 73;
const FINAL_ARGS: [u64; 6] = [0x12f, 2, 3, 4, 5, 6];
const ASYNC_ARGS: [u64; 6] = [0x117, 17, 34, 51, 68, 85];
const ASYNC_CASES: [&str; 8] = [
    "inject-exit-ready-ok",
    "inject-exit-group-ready-err",
    "application-exit-ready-err",
    "application-exit-group-ready-ok",
    "inject-exit-ready-ok-mismatch",
    "inject-exit-group-ready-err-mismatch",
    "application-exit-ready-err-mismatch",
    "application-exit-group-ready-ok-mismatch",
];
const SUPPRESSION_CASES: [&str; 11] = [
    "tgkill-suppress",
    "tgkill-arbitrary",
    "tgkill-unselected",
    "tgkill-returning-caught",
    "tgkill-tail",
    "getpid-tail-tgkill",
    "tgkill-deferred-getpid",
    "tgkill-deferred-primary-close",
    "tgkill-deferred-primary-range",
    "tgkill-safe-returning",
    "tgkill-terminal",
];
const TGKILL_ARGS: [u64; 6] = [0, u64::MAX, 999, 17, 34, 51];
const STARTUP_CASES: [&str; 12] = [
    "startup-pending",
    "startup-ready-ok",
    "startup-ready-err",
    "startup-errno",
    "startup-read-failed",
    "startup-write-failed",
    "startup-unsupported",
    "startup-duplicate",
    "startup-post-exec",
    "startup-completed-post-exec",
    "startup-stale-owner",
    "startup-repeated-owner",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum StartupInjection {
    Pending,
    ReadyOk,
    ReadyErr,
    Errno,
    ReadFailed,
    WriteFailed,
    Unsupported,
    Duplicate,
    PostExec,
    CompletedPostExec,
    StaleOwner,
    RepeatedOwner,
}
impl StartupInjection {
    fn for_case(case: &str) -> Option<Self> {
        Some(match case {
            "startup-pending" => Self::Pending,
            "startup-ready-ok" => Self::ReadyOk,
            "startup-ready-err" => Self::ReadyErr,
            "startup-errno" => Self::Errno,
            "startup-read-failed" => Self::ReadFailed,
            "startup-write-failed" => Self::WriteFailed,
            "startup-unsupported" => Self::Unsupported,
            "startup-duplicate" => Self::Duplicate,
            "startup-post-exec" => Self::PostExec,
            "startup-completed-post-exec" => Self::CompletedPostExec,
            "startup-stale-owner" => Self::StaleOwner,
            "startup-repeated-owner" => Self::RepeatedOwner,
            _ => return None,
        })
    }
    fn raw_result(self) -> i64 {
        if self == Self::Errno {
            -i64::from(libc::EBADF)
        } else {
            i64::from(pid().as_raw())
        }
    }
    fn refusal(self) -> Option<&'static str> {
        match self {
            Self::ReadFailed => Some("caller-startup-register-read-failed"),
            Self::WriteFailed => Some("caller-startup-register-write-failed"),
            Self::Unsupported => Some("caller-startup-tail-lifecycle-unsupported"),
            Self::Duplicate => Some("caller-startup-tail-already-completed"),
            Self::PostExec | Self::CompletedPostExec => Some("caller-startup-terminal-unsupported"),
            Self::StaleOwner => Some("caller-initial-single-thread-owner-required"),
            Self::RepeatedOwner => Some("caller-application-admission-repeated"),
            _ => None,
        }
    }
}

static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static DIAGNOSTICS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static SELECTIONS: AtomicUsize = AtomicUsize::new(0);
static CONSTRUCTORS: AtomicUsize = AtomicUsize::new(0);
static CONFIG_ADDRESS: AtomicUsize = AtomicUsize::new(0);

fn event(name: &'static str) {
    EVENTS.lock().unwrap().push(name);
}
fn events() -> Vec<&'static str> {
    EVENTS.lock().unwrap().clone()
}
fn pid() -> Pid {
    Pid::from_raw(std::process::id() as i32)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum AsyncInjection {
    InjectExitOk,
    InjectExitGroupErr,
    ApplicationExitErr,
    ApplicationExitGroupOk,
}

impl AsyncInjection {
    fn for_case(case: &str) -> Option<Self> {
        match case.strip_suffix("-mismatch").unwrap_or(case) {
            "inject-exit-ready-ok" => Some(Self::InjectExitOk),
            "inject-exit-group-ready-err" => Some(Self::InjectExitGroupErr),
            "application-exit-ready-err" => Some(Self::ApplicationExitErr),
            "application-exit-group-ready-ok" => Some(Self::ApplicationExitGroupOk),
            _ => None,
        }
    }

    fn syscall(self) -> Sysno {
        match self {
            Self::InjectExitOk | Self::ApplicationExitErr => Sysno::exit,
            Self::InjectExitGroupErr | Self::ApplicationExitGroupOk => Sysno::exit_group,
        }
    }

    fn application_purpose(self) -> bool {
        matches!(
            self,
            Self::ApplicationExitErr | Self::ApplicationExitGroupOk
        )
    }

    fn returns_error(self) -> bool {
        matches!(self, Self::InjectExitGroupErr | Self::ApplicationExitErr)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Suppression {
    Zero,
    Arbitrary,
    Unselected,
    ReturningCaught,
    Tail,
    SafeOriginal,
    DeferredGetpid,
    DeferredClose,
    DeferredRange,
    SafeReturning,
    Terminal,
}
impl Suppression {
    fn for_case(case: &str) -> Option<Self> {
        Some(match case {
            "tgkill-suppress" => Self::Zero,
            "tgkill-arbitrary" => Self::Arbitrary,
            "tgkill-unselected" => Self::Unselected,
            "tgkill-returning-caught" => Self::ReturningCaught,
            "tgkill-tail" => Self::Tail,
            "getpid-tail-tgkill" => Self::SafeOriginal,
            "tgkill-deferred-getpid" => Self::DeferredGetpid,
            "tgkill-deferred-primary-close" => Self::DeferredClose,
            "tgkill-deferred-primary-range" => Self::DeferredRange,
            "tgkill-safe-returning" => Self::SafeReturning,
            "tgkill-terminal" => Self::Terminal,
            _ => return None,
        })
    }
    fn suppresses(self) -> bool {
        matches!(self, Self::Zero | Self::Arbitrary | Self::SafeReturning)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Config {
    seed: u64,
    label: String,
    instructions: u8,
    async_injection: Option<AsyncInjection>,
    suppression: Option<Suppression>,
    startup: Option<StartupInjection>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Request {
    Start,
    PostExec,
    ThreadExit,
    ProcessExit,
    AfterFinished,
    Suppression,
}

impl Request {
    fn response(self) -> u64 {
        SEED + self as u64
    }
    fn event(self) -> &'static str {
        match self {
            Self::Start => "remote-start",
            Self::PostExec => "remote-post",
            Self::ThreadExit => "remote-thread-exit",
            Self::ProcessExit => "remote-process-exit",
            Self::AfterFinished => panic!("RPC escaped the finished primary"),
            Self::Suppression => "remote-suppression",
        }
    }
}

struct RemoteGlobal {
    owner: ThreadId,
    calls: AtomicUsize,
}
impl Default for RemoteGlobal {
    fn default() -> Self {
        panic!("caller must never create a local default GlobalTool")
    }
}

#[reverie::global_tool]
impl GlobalTool for RemoteGlobal {
    type Config = Config;
    type Request = Request;
    type Response = u64;

    async fn receive_rpc(&self, from: Pid, request: Request) -> u64 {
        assert_eq!(
            std::thread::current().id(),
            self.owner,
            "local GlobalTool fallback"
        );
        assert_eq!(from, pid());
        self.calls.fetch_add(1, Ordering::SeqCst);
        event(request.event());
        request.response()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    tid: i32,
    stamp: u64,
    primary: Option<i32>,
    original: Option<(i64, [u64; 6])>,
    requested: Option<(i64, [u64; 6])>,
    injection_count: Option<u64>,
}
impl Drop for State {
    fn drop(&mut self) {
        if self.tid != 0 {
            event("state-drop");
        }
    }
}

struct Probe {
    process: Pid,
    config: usize,
}
impl Default for Probe {
    fn default() -> Self {
        panic!("actual Tool::new must construct the caller")
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        event("tool-drop");
    }
}

struct InjectionDrop<'a>(&'a AtomicUsize);
impl Drop for InjectionDrop<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        event("injection-future-drop");
    }
}

struct StartupDrop;
impl Drop for StartupDrop {
    fn drop(&mut self) {
        event("startup-drop");
    }
}

struct CallbackDrop;
impl Drop for CallbackDrop {
    fn drop(&mut self) {
        event("callback-drop");
    }
}

fn pending<F: Future>(future: F) {
    let mut future = Box::pin(future);
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

fn poll_then_drop_injection<F: Future>(future: F) {
    let drops = AtomicUsize::new(0);
    let mut owned = Box::pin(async {
        let _drop = InjectionDrop(&drops);
        future.await
    });
    for _ in 0..2 {
        assert!(
            owned
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    // Drop the owned async frame, not merely a temporary Pin<&mut _>.
    drop(owned);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

fn exercise_async_injection<G: Guest<Probe>>(
    guest: &mut G,
    mode: AsyncInjection,
) -> Result<i64, Error> {
    assert_eq!(guest.injected_syscalls(), Some(0));
    let mut memory = guest.memory();
    let mut source = [3_u8, 5, 7, 11];
    let address = AddrMut::from_raw(source.as_mut_ptr() as usize).unwrap();
    let mut output = [0_u8; 4];
    assert_eq!(memory.read(address, &mut output), Ok(4));
    assert_eq!(output, source);
    let call = Syscall::from_raw(mode.syscall(), SyscallArgs::new(0x117, 17, 34, 51, 68, 85));
    if mode.application_purpose() {
        poll_then_drop_injection(guest.inject_with_purpose(call, InjectionPurpose::Application));
    } else {
        poll_then_drop_injection(guest.inject(call));
    }
    assert_eq!(guest.injected_syscalls(), Some(1));
    // This handle predates admission. Neither it nor later Guest operations
    // may escape the established ending, even after its future was abandoned.
    output.fill(99);
    assert_eq!(memory.read(address, &mut output), Err(Errno::ESRCH));
    assert_eq!(memory.read_exact(address, &mut []), Err(Errno::ESRCH));
    assert_eq!(memory.write(address, &[17; 4]), Err(Errno::ESRCH));
    assert_eq!(source, [3, 5, 7, 11]);
    assert_eq!(output, [99; 4]);
    assert!(matches!(
        guest.try_send_rpc_sync(Request::AfterFinished),
        Err(Request::AfterFinished)
    ));
    pending(guest.send_rpc(Request::AfterFinished));
    pending(guest.inject(Syscall::from_raw(
        Sysno::getpid,
        SyscallArgs::new(0, 0, 0, 0, 0, 0),
    )));
    pending(guest.inject_with_purpose(call, InjectionPurpose::Application));
    pending(guest.regs());
    pending(guest.set_regs(unsafe { std::mem::zeroed() }));
    assert_eq!(guest.injected_syscalls(), Some(1));
    if mode.returns_error() {
        Err(Errno::EACCES.into())
    } else {
        Ok(19)
    }
}

fn syscall_parts(syscall: Syscall) -> (i64, [u64; 6]) {
    let (number, args) = syscall.into_parts();
    (
        number.id() as i64,
        [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ],
    )
}
fn requested_call<G: Guest<Probe>>(guest: &mut G, number: Sysno, args: [u64; 6]) -> Syscall {
    guest.thread_state_mut().requested = Some((number.id() as i64, args));
    Syscall::from_raw(
        number,
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

async fn exercise_suppression_callback<G: Guest<Probe>>(
    guest: &mut G,
    syscall: Syscall,
    mode: Suppression,
) -> Result<i64, Error> {
    check_config(guest.config());
    assert_eq!(guest.thread_state().stamp, SEED + 3);
    event("syscall");
    guest.thread_state_mut().stamp += 4;
    guest.thread_state_mut().original = Some(syscall_parts(syscall));
    let _drop = CallbackDrop;
    if mode.suppresses() {
        assert_eq!(
            guest.send_rpc(Request::Suppression).await,
            Request::Suppression.response()
        );
    }
    match mode {
        Suppression::Zero | Suppression::Arbitrary => {}
        Suppression::ReturningCaught => {
            let call = requested_call(guest, Sysno::tgkill, TGKILL_ARGS);
            assert_eq!(guest.inject(call).await, Err(Errno::EOPNOTSUPP));
        }
        Suppression::Tail | Suppression::SafeOriginal => {
            let call = requested_call(guest, Sysno::tgkill, TGKILL_ARGS);
            pending(guest.tail_inject(call));
        }
        Suppression::DeferredGetpid => {
            let call = requested_call(guest, Sysno::getpid, [0; 6]);
            // Snapshot before the nonreturning tail; the common snapshot below
            // is unreachable. Await it so the callback stays Pending, not Ready(Ok(0)).
            let count = guest.injected_syscalls();
            guest.thread_state_mut().injection_count = count;
            guest.tail_inject(call).await
        }
        Suppression::DeferredClose | Suppression::DeferredRange => {
            let fd = guest.thread_state().primary.unwrap();
            assert!(crate::sync_rpc::is_runtime_owned_fd(fd));
            let (number, args) = if mode == Suppression::DeferredClose {
                (Sysno::close, [fd as u64, 0, 0, 0, 0, 0])
            } else {
                // A nonempty gap follows the actual primary. The invoker
                // records a regressed gap without closing any Rust-owned FD.
                (Sysno::close_range, [fd as u64, fd as u64 + 1, 0, 0, 0, 0])
            };
            let call = requested_call(guest, number, args);
            let count = guest.injected_syscalls();
            guest.thread_state_mut().injection_count = count;
            guest.tail_inject(call).await
        }
        Suppression::SafeReturning => {
            let call = requested_call(guest, Sysno::getpid, [0; 6]);
            assert_eq!(guest.inject(call).await, Ok(317));
        }
        Suppression::Terminal => {
            let call = requested_call(guest, Sysno::exit_group, FINAL_ARGS);
            guest.tail_inject(call).await
        }
        Suppression::Unselected => panic!("unselected Tgkill reached the Tool"),
    }
    let count = guest.injected_syscalls();
    guest.thread_state_mut().injection_count = count;
    Ok(if mode == Suppression::Arbitrary {
        917
    } else {
        0
    })
}

fn check_config(config: &Config) {
    assert_eq!(config.seed, SEED);
    assert_eq!(config.label, "received-config");
    assert_eq!(
        config as *const Config as usize,
        CONFIG_ADDRESS.load(Ordering::SeqCst)
    );
}

#[reverie::tool]
impl Tool for Probe {
    type GlobalState = RemoteGlobal;
    type ThreadState = State;

    fn subscriptions(config: &Config) -> Subscription {
        assert_eq!(config.seed, SEED);
        assert_eq!(config.label, "received-config");
        assert_eq!(SELECTIONS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        CONFIG_ADDRESS.store(config as *const Config as usize, Ordering::SeqCst);
        event("select");
        let mut selected = Subscription::none();
        selected.syscall(Sysno::getpid);
        if config
            .suppression
            .is_some_and(|mode| mode != Suppression::Unselected)
        {
            selected.syscall(Sysno::tgkill);
        }
        if config.instructions & 1 != 0 {
            selected.cpuid();
        }
        if config.instructions & 2 != 0 {
            selected.rdtsc();
        }
        selected
    }

    fn new(process: Pid, config: &Config) -> Self {
        check_config(config);
        assert_eq!(process, pid());
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 1);
        assert_eq!(CONSTRUCTORS.fetch_add(1, Ordering::SeqCst), 0);
        event("new");
        Self {
            process,
            config: config as *const Config as usize,
        }
    }

    fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &State)>) -> State {
        assert_eq!(tid, self.process);
        assert!(parent.is_none());
        event("state");
        State {
            tid: tid.as_raw(),
            stamp: SEED,
            ..State::default()
        }
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        check_config(guest.config());
        assert_eq!(guest.config() as *const Config as usize, self.config);
        assert_eq!(guest.pid(), self.process);
        assert_eq!(guest.tid(), self.process);
        assert_eq!(guest.ppid(), None);
        assert_eq!(guest.thread_state().stamp, SEED);
        event("start");
        assert_eq!(
            guest.send_rpc(Request::Start).await,
            Request::Start.response()
        );
        guest.thread_state_mut().stamp += 1;
        if let Some(mode) = guest.config().startup {
            if mode == StartupInjection::PostExec {
                return Ok(());
            }
            let _drop = StartupDrop;
            let call = Syscall::from_raw(
                if mode == StartupInjection::Unsupported {
                    Sysno::execve
                } else {
                    Sysno::getpid
                },
                SyscallArgs::new(0, 0, 0, 0, 0, 0),
            );
            if mode == StartupInjection::Duplicate {
                pending(guest.tail_inject(call));
                guest.tail_inject(call).await;
            }
            let mut tail = Box::pin(guest.tail_inject(call));
            return std::future::poll_fn(|cx| {
                assert!(tail.as_mut().poll(cx).is_pending());
                match mode {
                    StartupInjection::ReadyOk => std::task::Poll::Ready(Ok(())),
                    StartupInjection::ReadyErr => std::task::Poll::Ready(Err(Errno::EACCES.into())),
                    _ => std::task::Poll::Pending,
                }
            })
            .await;
        }
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        check_config(guest.config());
        assert_eq!(guest.thread_state().stamp, SEED + 1);
        event("post");
        if matches!(
            guest.config().startup,
            Some(StartupInjection::PostExec | StartupInjection::CompletedPostExec)
        ) {
            guest.tail_inject(reverie::syscalls::Getpid::new()).await;
        }
        assert_eq!(
            guest.send_rpc(Request::PostExec).await,
            Request::PostExec.response()
        );
        guest.thread_state_mut().stamp += 2;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if let Some(mode) = guest.config().suppression {
            return exercise_suppression_callback(guest, syscall, mode).await;
        }
        assert_eq!(syscall.number(), Sysno::getpid);
        check_config(guest.config());
        assert_eq!(guest.thread_state().stamp, SEED + 3);
        event("syscall");
        guest.thread_state_mut().stamp += 4;
        if let Some(mode) = guest.config().async_injection {
            let _drop = CallbackDrop;
            return exercise_async_injection(guest, mode);
        }
        guest
            .tail_inject(Syscall::from_raw(
                Sysno::exit_group,
                SyscallArgs::new(FINAL_ARGS[0] as usize, 2, 3, 4, 5, 6),
            ))
            .await
    }

    async fn on_exit_thread<G: GlobalRPC<RemoteGlobal>>(
        &self,
        tid: Pid,
        rpc: &G,
        state: State,
        status: ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(tid, self.process);
        assert_eq!(state.tid, tid.as_raw());
        assert!(state.stamp == SEED + 3 || state.stamp == SEED + 7);
        if rpc.config().async_injection.is_some() {
            assert_eq!(status, reverie::exit_status_from_raw(ASYNC_ARGS[0]));
        } else {
            assert_eq!(status, reverie::exit_status_from_raw(FINAL_ARGS[0]));
        }
        check_config(rpc.config());
        event("thread-exit");
        assert_eq!(
            rpc.send_rpc(Request::ThreadExit).await,
            Request::ThreadExit.response()
        );
        drop(state);
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<RemoteGlobal>>(
        self,
        process: Pid,
        rpc: &G,
        status: ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(process, self.process);
        if rpc.config().async_injection.is_some() {
            assert_eq!(status, reverie::exit_status_from_raw(ASYNC_ARGS[0]));
        } else {
            assert_eq!(status, reverie::exit_status_from_raw(FINAL_ARGS[0]));
        }
        check_config(rpc.config());
        event("process-exit");
        assert_eq!(
            rpc.send_rpc(Request::ProcessExit).await,
            Request::ProcessExit.response()
        );
        Ok(())
    }
}

/// Passive frame-order witness. All framing, validation and acknowledgements
/// still execute in the existing shared client/server; this never sends an ack.
#[derive(Default)]
struct Frames(Vec<u8>);
impl Frames {
    fn observe(&mut self, bytes: &[u8], incoming: bool) {
        self.0.extend_from_slice(bytes);
        while self.0.len() >= 4 {
            let length = u32::from_be_bytes(self.0[..4].try_into().unwrap()) as usize;
            assert!(length <= reverie_rpc_transport::codec::DEFAULT_MAX_FRAME_LEN);
            if self.0.len() < 4 + length {
                break;
            }
            let frame = &self.0[4..4 + length];
            if frame.starts_with(&[0xff; 4]) {
                assert_eq!(length, reverie_rpc_transport::tool_activation::FRAME_LEN);
                assert_eq!(&frame[4..7], b"TA\x02");
                event(match (incoming, frame[7]) {
                    (false, 1) => "claim",
                    (true, 2) => "claim-ack",
                    (false, 3) => "started",
                    (true, 4) => "started-ack",
                    (false, 5) => "finished",
                    (true, 6) => "finished-ack",
                    _ => panic!("unexpected actual control frame"),
                });
            }
            self.0.drain(..4 + length);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Invocation {
    number: i64,
    args: [u64; 6],
    purpose: u32,
}

/// Only this context/filter/reservation is synthetic. Transport calls below
/// execute real Linux socket I/O. No exit or lifecycle syscall is executed.
#[derive(Default)]
struct NativeFixture {
    primary: Cell<Option<i32>>,
    calls: Cell<usize>,
    reservation: Cell<Option<TerminalFact>>,
    async_injection: Cell<Option<AsyncInjection>>,
    admissions: Cell<usize>,
    register_reads: Cell<usize>,
    startup: Cell<Option<StartupInjection>>,
    startup_calls: Cell<usize>,
    startup_writes: Cell<usize>,
    written: RefCell<Option<libc::user_regs_struct>>,
    sent: RefCell<Frames>,
    received: RefCell<Frames>,
    probing_suppression: Cell<bool>,
    guest_invocations: RefCell<Vec<Invocation>>,
    transport_invocations: RefCell<Vec<Invocation>>,
}
impl NativeFixture {
    fn context(&self) -> usize {
        self as *const Self as usize
    }
    fn shutdown(&self) {
        if let Some(fd) = self.primary.take() {
            // The production connection owner retains its FD until process
            // exit. Shutdown supplies EOF for a joined server drain here.
            unsafe {
                libc::shutdown(fd, libc::SHUT_RDWR);
            }
        }
    }
}
impl Drop for NativeFixture {
    fn drop(&mut self) {
        self.shutdown();
    }
}

unsafe extern "C" fn invoke(context: usize, number: i64, args: *const u64, purpose: u32) -> i64 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    let args = unsafe { args.cast::<[u64; 6]>().read() };
    assert_eq!(purpose, InjectionPurpose::Application as u32);
    fixture.calls.set(fixture.calls.get() + 1);
    if number == libc::SYS_getpid && fixture.startup.get().is_some() {
        let mode = fixture
            .startup
            .get()
            .expect("only startup fixture admits this unit effect");
        assert_eq!(args, [0; 6]);
        fixture.startup_calls.set(fixture.startup_calls.get() + 1);
        assert_eq!(fixture.startup_calls.get(), 1, "startup effect replayed");
        event("startup-effect");
        return mode.raw_result();
    }
    if number == libc::SYS_prctl {
        assert_eq!(args, [libc::PR_GET_SECCOMP as u64, 0, 0, 0, 0, 0]);
        event("unit-filter-probe");
        return 0; // Unit native-admission fixture, never a host filter claim.
    }
    let invocation = Invocation {
        number,
        args,
        purpose,
    };
    if fixture.probing_suppression.get()
        && (matches!(
            number,
            libc::SYS_tgkill | libc::SYS_getpid | libc::SYS_close_range
        ) || number == libc::SYS_close && Some(args[0] as i32) == fixture.primary.get())
    {
        fixture.guest_invocations.borrow_mut().push(invocation);
        return 317;
    }
    fixture.transport_invocations.borrow_mut().push(invocation);
    assert!(matches!(
        number,
        libc::SYS_socket
            | libc::SYS_fcntl
            | libc::SYS_close
            | libc::SYS_connect
            | libc::SYS_read
            | libc::SYS_write
    ));
    let result =
        unsafe { libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 {
        return -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    if number == libc::SYS_connect {
        fixture.primary.set(Some(args[0] as i32));
    }
    if matches!(number, libc::SYS_read | libc::SYS_write) && result > 0 {
        let bytes = unsafe { std::slice::from_raw_parts(args[1] as *const u8, result as usize) };
        if number == libc::SYS_read {
            fixture.received.borrow_mut().observe(bytes, true);
        } else {
            fixture.sent.borrow_mut().observe(bytes, false);
        }
    }
    result
}

unsafe extern "C" fn admit(
    context: usize,
    number: i64,
    args: *const u64,
    out: *mut TerminalFact,
) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    assert!(fixture.reservation.get().is_none());
    assert_eq!(number, libc::SYS_exit_group);
    let fact = TerminalFact {
        size: std::mem::size_of::<TerminalFact>() as u32,
        kind: 1,
        image: 1,
        context: context as u64,
        pid: pid().as_raw(),
        tid: pid().as_raw(),
        sysno: number,
        args: unsafe { args.cast::<[u64; 6]>().read() },
        cookie: 91,
        origin: 2,
        reserved: 0,
    };
    assert_eq!(fact.args, FINAL_ARGS);
    fixture.reservation.set(Some(fact));
    event("unit-reservation");
    unsafe {
        out.write(fact);
    }
    1
}

unsafe extern "C" fn admit_async(
    context: usize,
    number: i64,
    args: *const u64,
    out: *mut TerminalFact,
) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    let mode = fixture.async_injection.get().unwrap();
    assert_eq!(number, mode.syscall().id() as i64);
    assert_eq!(fixture.admissions.get(), 0);
    assert!(fixture.reservation.get().is_none());
    fixture.admissions.set(fixture.admissions.get() + 1);
    let fact = TerminalFact {
        size: std::mem::size_of::<TerminalFact>() as u32,
        kind: 1,
        image: 1,
        context: context as u64,
        pid: pid().as_raw(),
        tid: pid().as_raw(),
        sysno: number,
        args: unsafe { args.cast::<[u64; 6]>().read() },
        cookie: 91,
        origin: 2,
        reserved: 0,
    };
    assert_eq!(fact.args, ASYNC_ARGS);
    fixture.reservation.set(Some(fact));
    event("unit-reservation");
    unsafe {
        out.write(fact);
    }
    1
}

unsafe extern "C" fn emit(bytes: *const u8, length: usize) {
    let bytes = unsafe { std::slice::from_raw_parts(bytes, length) };
    DIAGNOSTICS
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(bytes).into_owned());
}
unsafe extern "C" fn idle() {
    std::thread::yield_now();
}
unsafe extern "C" fn read_registers(context: usize, output: *mut libc::user_regs_struct) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    fixture.register_reads.set(fixture.register_reads.get() + 1);
    if fixture.startup.get().is_some() {
        event("startup-read");
        if fixture.startup.get() == Some(StartupInjection::ReadFailed) {
            return 0;
        }
        unsafe {
            output.write(startup_registers());
        }
    } else {
        unsafe {
            output.write(std::mem::zeroed());
        }
    }
    1
}
unsafe extern "C" fn write_registers(
    context: usize,
    registers: *const libc::user_regs_struct,
) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    let mode = fixture.startup.get().expect("unexpected register write");
    fixture.startup_writes.set(fixture.startup_writes.get() + 1);
    assert_eq!(fixture.startup_writes.get(), 1);
    let actual = unsafe { registers.read() };
    let mut expected = startup_registers();
    expected.rax = mode.raw_result() as u64;
    assert_eq!(register_words(&actual), register_words(&expected));
    *fixture.written.borrow_mut() = Some(actual);
    event("startup-write");
    i32::from(mode != StartupInjection::WriteFailed)
}
fn startup_registers() -> libc::user_regs_struct {
    libc::user_regs_struct {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 17,
        rbx: 3,
        r11: 11,
        r10: 10,
        r9: 9,
        r8: 8,
        rax: 0x55,
        rcx: 0x33,
        rdx: 4,
        rsi: 5,
        rdi: 6,
        orig_rax: 0x77,
        rip: 0x401000,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x700000,
        ss: 0x2b,
        fs_base: 0x1000,
        gs_base: 0x2000,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}
fn register_words(r: &libc::user_regs_struct) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}
unsafe extern "C" fn read_memory(_: usize, _: *mut u8, _: usize) -> i32 {
    panic!("unexpected memory read")
}
unsafe extern "C" fn compare_exchange(_: usize, _: u32, _: u32, _: *mut u32) -> i32 {
    panic!("unexpected atomic memory effect")
}
unsafe extern "C" fn capture(
    _: usize,
    operation: u32,
    out: *mut crate::NativeControllerCaptureFact,
) -> i32 {
    assert_eq!(operation, 1);
    event("native-ack-call");
    unsafe {
        out.write(Default::default());
    }
    0
}
unsafe extern "C" fn private_memory(
    _: usize,
    _: *const crate::NativePrivateMemorySnapshot,
    out: *mut crate::NativePrivateMemorySnapshot,
) -> i32 {
    unsafe {
        out.write(Default::default());
    }
    0
}
unsafe extern "C" fn branch(_: usize, out: *mut crate::NativeBranchFact) -> i32 {
    unsafe {
        out.write(Default::default());
    }
    0
}
unsafe extern "C" fn mapping(_: usize, _: u32, _: *mut crate::NativeMappingCapture) -> i32 {
    panic!("unexpected mapping capture")
}

fn callbacks() -> DbtRuntimeCallbacks {
    DbtRuntimeCallbacks {
        emit,
        idle,
        panic_on_unsupported_syscalls: 0,
        unsupported_report_fd: -1,
        emit_stdout: emit,
        emit_evidence: emit,
        evidence_log_level: 0,
        compare_exchange_u32: compare_exchange,
        controller_capture_control: capture,
        runtime_private_memory: private_memory,
        branch_fact: branch,
        mapping_capture: mapping,
        admit_terminal: admit,
        rpc_transport_fatal: Some(unexpected_rpc_transport_failure),
    }
}

// Positive unit fixtures never disconnect. Actual native failure/cleanup is
// exercised by the separately produced caller artifact, not this callback.
unsafe extern "C" fn unexpected_rpc_transport_failure(_: usize) -> ! {
    std::process::abort()
}

struct Server {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    monitor: ConnectionMonitor,
    issues: RpcIssueMonitor,
    global: Arc<RemoteGlobal>,
}
impl Server {
    fn start(config: Config, run: ActivationRun) -> Self {
        let path = std::env::var_os(crate::sync_rpc::RPC_SOCKET_ENV).unwrap();
        let listener = UnixListener::bind(path).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let global = Arc::new(RemoteGlobal {
                    owner: std::thread::current().id(),
                    calls: AtomicUsize::new(0),
                });
                let mut server = RpcServer::from_prebound(listener, global.clone(), config)
                    .unwrap()
                    .tool_activation(run);
                let monitor = server.connection_monitor();
                let issues = server.retain_connection_issues();
                send.send((monitor.clone(), issues, global)).unwrap();
                server
                    .serve_until(async move {
                        let _ = stopped.await;
                        tokio::time::timeout(Duration::from_secs(2), monitor.wait_for_idle())
                            .await
                            .expect("RPC connections did not drain");
                    })
                    .await
                    .unwrap();
            });
        });
        let (monitor, issues, global) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        Self {
            stop: Some(stop),
            thread: Some(thread),
            monitor,
            issues,
            global,
        }
    }
    fn finish(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        assert_eq!(self.monitor.active_connections(), 0);
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.finish();
    }
}

fn init(
    runtime: &CallerRuntime<Probe>,
    counters: &mut CallerCounters,
    fixture: &NativeFixture,
    defer: i32,
) -> i32 {
    unsafe {
        runtime.thread_init(
            counters,
            fixture.context(),
            pid().as_raw(),
            pid().as_raw(),
            -1,
            37,
            defer,
            invoke,
            read_registers,
            write_registers,
        )
    }
}

fn sentinel() -> ReadySnapshot {
    ReadySnapshot {
        size: 123,
        selected_event_bits: 456,
        raw_config_digest: [0xa5; 32],
        owner_generation: 789,
    }
}

fn exercise(case: &str) {
    let runtime = CallerRuntime::<Probe>::new([0x6b; 32]);
    let image = runtime.image_init();
    assert!(image.is_valid());
    assert_eq!(image.runtime_input_identity, [0x6b; 32]);
    let mut counters = CallerCounters {
        branches: 0,
        observed_syscalls: 0,
        rewritten_syscalls: 0,
        runtime_state: std::ptr::null_mut(),
    };
    let fixture = NativeFixture::default();
    let mut snapshot = sentinel();
    assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, 0);
    assert_eq!(snapshot, sentinel());
    assert_eq!(init(&runtime, &mut counters, &fixture, 1), 0);
    assert_eq!(init(&runtime, &mut counters, &fixture, 0), 1);
    assert!(events().is_empty());
    assert_eq!(fixture.calls.get(), 0);
    assert!(counters.runtime_state.is_null());
    if case == "missing-fatal" {
        let mut callbacks = callbacks();
        callbacks.rpc_transport_fatal = None;
        assert_eq!(
            unsafe {
                runtime.background_init(
                    (&mut callbacks as *mut DbtRuntimeCallbacks).cast(),
                    crate::DbtStartupMode::Coordinated as u32,
                )
            },
            -1
        );
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
        assert_eq!(init(&runtime, &mut counters, &fixture, 0), -1);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.calls.get(), 0);
        assert!(counters.runtime_state.is_null());
        assert!(events().is_empty());
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller RPC failure owner missing\n"]
        );
        runtime.process_exit();
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller RPC failure owner missing\n"]
        );
        assert!(events().is_empty());
        assert_eq!(fixture.calls.get(), 0);
        return;
    }
    if case == "failed" {
        assert_eq!(
            unsafe {
                runtime.background_init(
                    std::ptr::null_mut(),
                    crate::DbtStartupMode::Coordinated as u32,
                )
            },
            -1
        );
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
        assert_eq!(init(&runtime, &mut counters, &fixture, 0), -1);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.calls.get(), 0);
        assert!(counters.runtime_state.is_null());
        assert!(events().is_empty());
        return;
    }

    let config = Config {
        seed: SEED,
        label: "received-config".into(),
        instructions: match case {
            "cpuid" => 1,
            "rdtsc" => 2,
            _ => 0,
        },
        async_injection: AsyncInjection::for_case(case),
        suppression: Suppression::for_case(case),
        startup: StartupInjection::for_case(case),
    };
    fixture.async_injection.set(config.async_injection);
    fixture.startup.set(config.startup);
    let run = ActivationRun::new();
    run.bind_root(pid().as_raw()).unwrap();
    let mut server = Server::start(config.clone(), run.clone());
    // Fix the unit context's address before admission and drop it before Server
    // on panic, so the cached primary has EOF before the serving owner joins.
    // Pending/defer1 retained no context or application state above.
    let fixture = Box::new(fixture);
    let mut callbacks = callbacks();
    if config.async_injection.is_some() {
        callbacks.admit_terminal = admit_async;
    }
    assert_eq!(
        unsafe {
            runtime.background_init(
                (&mut callbacks as *mut DbtRuntimeCallbacks).cast(),
                crate::DbtStartupMode::Coordinated as u32,
            )
        },
        0
    );
    assert_eq!(events(), ["select"]);
    assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
    assert!(counters.runtime_state.is_null());
    assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, 1);
    assert_eq!(snapshot.size as usize, std::mem::size_of::<ReadySnapshot>());
    assert_eq!(snapshot.owner_generation, 1);
    assert_eq!(snapshot.selected_event_bits, u32::from(config.instructions));
    assert_eq!(
        snapshot.raw_config_digest,
        reverie_rpc_transport::initial_image::config_digest(
            &reverie_rpc_transport::codec::encode(&config).unwrap()
        )
    );
    let untouched = sentinel();
    let mut wrong_image = untouched;
    assert_eq!(unsafe { runtime.ready(2, &mut wrong_image) }, -1);
    assert_eq!(wrong_image, untouched);
    assert_eq!(init(&runtime, &mut counters, &fixture, 1), 0);
    assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
    if config.instructions != 0 {
        assert_eq!(init(&runtime, &mut counters, &fixture, 0), -1);
        assert_eq!(events(), ["select"]);
        assert_eq!(fixture.calls.get(), 0);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert!(counters.runtime_state.is_null());
        snapshot = sentinel();
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
        assert!(run.completed().is_err());
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 0);
        assert!(
            DIAGNOSTICS
                .lock()
                .unwrap()
                .iter()
                .any(|message| message.contains("caller-instruction-subscription-unsupported"))
        );
        server.finish();
        assert!(server.issues.snapshot().is_empty());
        return;
    }

    if let Some(mode) = config.startup {
        exercise_startup(mode, &runtime, &mut counters, &fixture, &mut server, &run);
        return;
    }
    assert_eq!(init(&runtime, &mut counters, &fixture, 0), 0);
    assert_eq!(
        events(),
        [
            "select",
            "unit-filter-probe",
            "claim",
            "claim-ack",
            "new",
            "state",
            "start",
            "remote-start",
            "post",
            "remote-post",
            "started",
            "started-ack",
            "native-ack-call"
        ]
    );
    assert!(run.completed().is_err());
    if case == "missing-finished" {
        // Real construction and startup RPC have completed, but this unit
        // notification establishes neither a native ending nor a receipt.
        let before = events();
        assert!(DIAGNOSTICS.lock().unwrap().is_empty());
        runtime.process_exit();
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller process ended without acknowledged consuming lifecycle\n"]
        );
        assert_eq!(runtime.ready.load(Ordering::Acquire), -1);
        runtime.process_exit();
        assert_eq!(
            DIAGNOSTICS.lock().unwrap().as_slice(),
            ["reverie-dbt: caller process ended without acknowledged consuming lifecycle\n"]
        );
        assert_eq!(events(), before);
        assert!(run.completed().is_err());
        // The unit fixture owns the attachment allocation; no exit hook is
        // called to dispose of a process whose ending was never admitted.
        unsafe {
            drop(Box::from_raw(
                counters.runtime_state.cast::<RootAttachment<Probe>>(),
            ));
        }
        fixture.shutdown();
        server.finish();
        return;
    }
    let selected = runtime
        .configuration
        .get()
        .unwrap()
        .selected
        .shared_config();
    let attachment = unsafe {
        runtime
            .attachment(
                &mut counters,
                fixture.context(),
                pid().as_raw(),
                pid().as_raw(),
                1,
            )
            .unwrap()
    };
    assert!(Arc::ptr_eq(
        &selected,
        &attachment
            .process
            .selected_configuration()
            .unwrap()
            .shared_config()
    ));
    assert_eq!(attachment.state.as_ref().unwrap().stamp, SEED + 3);
    assert!(attachment.phase == Phase::Running);

    let mut result = -1234;
    let mut deferred_number = -4321;
    let mut deferred_args = [0xa5; 6];
    let number = if case == "original" {
        libc::SYS_exit_group
    } else if config
        .suppression
        .is_some_and(|mode| mode != Suppression::SafeOriginal)
    {
        libc::SYS_tgkill
    } else {
        libc::SYS_getpid
    };
    let args = if config.suppression.is_some() {
        TGKILL_ARGS
    } else {
        FINAL_ARGS
    };
    if config.suppression.is_some() {
        let fd = fixture
            .primary
            .get()
            .expect("actual primary connected during admission");
        assert!(crate::sync_rpc::is_runtime_owned_fd(fd));
        attachment.state.as_mut().unwrap().primary = Some(fd);
        fixture.probing_suppression.set(true);
    }
    let before_callback = events();
    let before_calls = fixture.calls.get();
    let before_registers = fixture.register_reads.get();
    let action = unsafe {
        runtime.pre_syscall(
            fixture.context(),
            &mut counters,
            pid().as_raw(),
            pid().as_raw(),
            1,
            number,
            args.as_ptr(),
            41,
            &mut result,
            &mut deferred_number,
            deferred_args.as_mut_ptr(),
            invoke,
            read_registers,
            write_registers,
            read_memory,
        )
    };
    fixture.probing_suppression.set(false);
    if let Some(mode) = config
        .suppression
        .filter(|mode| *mode != Suppression::Terminal)
    {
        let attachment = unsafe {
            runtime
                .attachment(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    pid().as_raw(),
                    1,
                )
                .unwrap()
        };
        let state = attachment.state.as_ref().unwrap();
        let diagnostics = DIAGNOSTICS.lock().unwrap().clone();
        println!(
            "CallerRuntime suppression: case={case}; action={action}; result={result}; deferred={deferred_number}/{deferred_args:?}; original={:?}; requested={:?}; primary={:?}; injected={:?}; guest_invocations={:?}; transport_invocations={:?}; remote_calls={}; observed={}; rewritten={}; ending={:?}; refusal={:?}; diagnostics={diagnostics:?}; events={:?}",
            state.original,
            state.requested,
            state.primary,
            state.injection_count,
            fixture.guest_invocations.borrow(),
            fixture.transport_invocations.borrow(),
            server.global.calls.load(Ordering::SeqCst),
            runtime.observed.load(Ordering::Relaxed),
            runtime.rewritten.load(Ordering::Relaxed),
            attachment.effects.ending(),
            attachment.effects.refusal(),
            events()
        );
        assert_eq!(deferred_number, -4321);
        assert_eq!(deferred_args, [0xa5; 6]);
        assert!(fixture.reservation.get().is_none());
        assert!(attachment.effects.ending().is_none());
        assert_eq!(fixture.admissions.get(), 0);
        assert_eq!(fixture.register_reads.get(), before_registers);
        assert_eq!(
            runtime.observed.load(Ordering::Relaxed),
            u64::from(mode != Suppression::Unselected)
        );
        assert_eq!(
            runtime.rewritten.load(Ordering::Relaxed),
            u64::from(mode.suppresses())
        );
        assert_eq!(
            state.original,
            if mode == Suppression::Unselected {
                None
            } else {
                Some((number, args))
            }
        );
        assert_eq!(
            state.stamp,
            if mode == Suppression::Unselected {
                SEED + 3
            } else {
                SEED + 7
            }
        );
        let expected_request = match mode {
            Suppression::ReturningCaught | Suppression::Tail | Suppression::SafeOriginal => {
                Some((libc::SYS_tgkill, TGKILL_ARGS))
            }
            Suppression::DeferredGetpid | Suppression::SafeReturning => {
                Some((libc::SYS_getpid, [0; 6]))
            }
            Suppression::DeferredClose => Some((
                libc::SYS_close,
                [state.primary.unwrap() as u64, 0, 0, 0, 0, 0],
            )),
            Suppression::DeferredRange => Some((
                libc::SYS_close_range,
                [
                    state.primary.unwrap() as u64,
                    state.primary.unwrap() as u64 + 1,
                    0,
                    0,
                    0,
                    0,
                ],
            )),
            _ => None,
        };
        assert_eq!(state.requested, expected_request);
        assert_eq!(
            state.injection_count,
            if mode == Suppression::Unselected {
                None
            } else {
                Some(u64::from(matches!(
                    mode,
                    Suppression::ReturningCaught | Suppression::SafeReturning
                )))
            }
        );
        let expected_invocations = if mode == Suppression::SafeReturning {
            vec![Invocation {
                number: libc::SYS_getpid,
                args: [0; 6],
                purpose: InjectionPurpose::Application as u32,
            }]
        } else {
            Vec::new()
        };
        assert_eq!(*fixture.guest_invocations.borrow(), expected_invocations);
        // Real startup/callback RPC socket I/O is deliberately not counted as
        // execution of the suppressed or refused application operation.
        assert!(!fixture.transport_invocations.borrow().is_empty());
        assert_eq!(
            server.global.calls.load(Ordering::SeqCst),
            if mode.suppresses() { 3 } else { 2 }
        );
        let reason = match mode {
            Suppression::Unselected => Some("caller-application-lifecycle-unsupported"),
            Suppression::ReturningCaught => Some("caller-returning-lifecycle-unsupported"),
            Suppression::Tail | Suppression::SafeOriginal => {
                Some("caller-tail-lifecycle-unsupported")
            }
            Suppression::DeferredGetpid
            | Suppression::DeferredClose
            | Suppression::DeferredRange => Some("caller-suppression-only-forwarding-unsupported"),
            _ => None,
        };
        let latched = match mode {
            Suppression::ReturningCaught | Suppression::Tail | Suppression::SafeOriginal => reason,
            _ => None,
        };
        assert_eq!(attachment.effects.refusal(), latched);
        if let Some(reason) = reason {
            assert_eq!(action, -1);
            assert_eq!(result, -1234);
            assert_eq!(diagnostics, [format!("reverie-dbt: {reason}\n")]);
        } else {
            assert_eq!(action, 1);
            assert_eq!(
                result,
                if mode == Suppression::Arbitrary {
                    917
                } else {
                    0
                }
            );
            assert!(diagnostics.is_empty());
        }
        assert_eq!(
            events()[before_callback.len()..]
                .iter()
                .filter(|e| **e == "syscall")
                .count(),
            usize::from(mode != Suppression::Unselected)
        );
        assert_eq!(
            events()[before_callback.len()..]
                .iter()
                .filter(|e| **e == "callback-drop")
                .count(),
            usize::from(mode != Suppression::Unselected)
        );
        assert!(!events().contains(&"thread-exit") && !events().contains(&"finished"));
        assert!(run.completed().is_err());
        // These rows stop at one nonterminal callback outcome. Dispose only
        // the fixture-owned attachment; do not invent a consuming completion.
        unsafe {
            drop(Box::from_raw(
                counters.runtime_state.cast::<RootAttachment<Probe>>(),
            ));
        }
        counters.runtime_state = std::ptr::null_mut();
        assert!(counters.runtime_state.is_null());
        fixture.shutdown();
        server.finish();
        println!(
            "CallerRuntime suppression closed: case={case}; issues={:?}; completed={:?}",
            server.issues.snapshot(),
            run.completed()
        );
        assert!(!events().contains(&"finished"));
        assert!(run.completed().is_err());
        return;
    }
    let fact = if case == "original" {
        assert_eq!(action, 0);
        assert_eq!(deferred_number, -4321);
        assert_eq!(deferred_args, [0xa5; 6]);
        assert!(fixture.reservation.get().is_none());
        TerminalFact {
            size: std::mem::size_of::<TerminalFact>() as u32,
            kind: 1,
            image: 1,
            context: fixture.context() as u64,
            pid: pid().as_raw(),
            tid: pid().as_raw(),
            sysno: libc::SYS_exit_group,
            args: FINAL_ARGS,
            cookie: 92,
            origin: 1,
            reserved: 0,
        }
    } else {
        assert_eq!(action, 2);
        if let Some(mode) = config.async_injection {
            assert_eq!(deferred_number, mode.syscall().id() as i64);
            assert_eq!(deferred_args, ASYNC_ARGS);
            assert_eq!(fixture.admissions.get(), 1);
            assert_eq!(fixture.calls.get(), before_calls);
            assert_eq!(fixture.register_reads.get(), before_registers);
            assert_eq!(server.global.calls.load(Ordering::SeqCst), 2);
            assert_eq!(
                &events()[before_callback.len()..],
                [
                    "syscall",
                    "unit-reservation",
                    "injection-future-drop",
                    "callback-drop",
                ]
            );
        } else {
            assert_eq!(deferred_number, libc::SYS_exit_group);
            assert_eq!(deferred_args, FINAL_ARGS);
        }
        fixture.reservation.get().unwrap()
    };
    assert_eq!(result, -1234);
    assert!(!events().contains(&"thread-exit"));
    assert!(!events().contains(&"finished"));
    assert!(run.completed().is_err());
    let attachment = unsafe {
        runtime
            .attachment(
                &mut counters,
                fixture.context(),
                pid().as_raw(),
                pid().as_raw(),
                1,
            )
            .unwrap()
    };
    assert_eq!(
        attachment.state.as_ref().unwrap().stamp,
        if case == "original" {
            SEED + 3
        } else {
            SEED + 7
        }
    );

    if config.async_injection.is_some() {
        assert_eq!(attachment.effects.ending(), Some(fact));
        assert_eq!(attachment.effects.refusal(), None);
    }
    let mismatch = case == "mismatch" || case.ends_with("-mismatch");
    if mismatch {
        let before = events();
        let calls = fixture.calls.get();
        for field in 0..4 {
            let mut changed = fact;
            match field {
                0 => changed.cookie += 1,
                1 => changed.args[0] += 1,
                2 => changed.context += 1,
                _ => changed.origin = 1,
            }
            assert_eq!(
                unsafe {
                    runtime.thread_exit(
                        &mut counters,
                        fixture.context(),
                        pid().as_raw(),
                        invoke,
                        &changed,
                    )
                },
                -1
            );
            let attachment = unsafe {
                runtime
                    .attachment(
                        &mut counters,
                        fixture.context(),
                        pid().as_raw(),
                        pid().as_raw(),
                        1,
                    )
                    .unwrap()
            };
            assert_eq!(events(), before);
            assert_eq!(fixture.calls.get(), calls);
            assert!(attachment.phase == Phase::Running);
            assert!(attachment.state.is_some());
            assert!(attachment.process.as_ref().is_some());
            assert_eq!(attachment.effects.ending(), Some(fact));
        }
        assert!(!events().contains(&"thread-exit"));
        assert!(!events().contains(&"finished"));
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 2);
        assert!(run.completed().is_err());
        snapshot = sentinel();
        assert_eq!(unsafe { runtime.ready(1, &mut snapshot) }, -1);
        assert_eq!(snapshot, sentinel());
    } else {
        assert_eq!(
            unsafe {
                runtime.thread_exit(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    invoke,
                    &fact,
                )
            },
            0
        );
        let before = events();
        assert_eq!(
            &before[before.len() - 8..],
            [
                "thread-exit",
                "remote-thread-exit",
                "state-drop",
                "process-exit",
                "remote-process-exit",
                "tool-drop",
                "finished",
                "finished-ack"
            ]
        );
        let calls = fixture.calls.get();
        let attachment = unsafe {
            runtime
                .attachment(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    pid().as_raw(),
                    1,
                )
                .unwrap()
        };
        assert!(attachment.phase == Phase::Finished);
        assert!(attachment.state.is_none());
        assert!(attachment.process.as_ref().is_none());
        assert_eq!(attachment.effects.check_memory(), Err(Errno::ESRCH));
        assert!(
            attachment
                .primary
                .send::<RemoteGlobal>(
                    fixture.context(),
                    invoke,
                    pid(),
                    &selected,
                    Request::AfterFinished
                )
                .is_err()
        );
        assert!(
            attachment
                .primary
                .control(
                    fixture.context(),
                    invoke,
                    &ToolControl::Started {
                        digest: snapshot.raw_config_digest
                    }
                )
                .is_err()
        );
        assert_eq!(
            unsafe {
                runtime.thread_exit(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    invoke,
                    &fact,
                )
            },
            0
        );
        runtime.process_exit();
        runtime.process_exit();
        assert_eq!(events(), before);
        assert_eq!(fixture.calls.get(), calls);
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            before.iter().filter(|event| **event == "finished").count(),
            1
        );
    }
    assert_eq!(SELECTIONS.load(Ordering::SeqCst), 1);
    assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 1);
    // Retire the test-owned attachment only after all runtime operations; its
    // production lifetime ends with the application process, not a second hook.
    unsafe {
        drop(Box::from_raw(
            counters.runtime_state.cast::<RootAttachment<Probe>>(),
        ));
    }
    counters.runtime_state = std::ptr::null_mut();
    assert!(counters.runtime_state.is_null());
    fixture.shutdown();
    server.finish();
    if !mismatch {
        let receipt = run.completed().unwrap();
        if let Some(mode) = config.async_injection {
            assert_eq!(receipt.exit_code(), 23);
            assert_eq!(receipt.syscall(), mode.syscall().id() as i64);
        } else {
            assert_eq!(receipt.exit_code(), 47);
            assert_eq!(receipt.syscall(), libc::SYS_exit_group);
        }
        assert_eq!(
            receipt.origin(),
            if case == "original" {
                ExitOrigin::Original
            } else {
                ExitOrigin::Deferred
            }
        );
        assert!(server.issues.snapshot().is_empty());
        assert!(DIAGNOSTICS.lock().unwrap().is_empty());
    }
}

fn exercise_startup(
    mode: StartupInjection,
    runtime: &CallerRuntime<Probe>,
    counters: &mut CallerCounters,
    fixture: &NativeFixture,
    server: &mut Server,
    run: &ActivationRun,
) {
    let status = if mode == StartupInjection::StaleOwner {
        unsafe {
            runtime.thread_init(
                counters,
                fixture.context(),
                pid().as_raw() + 1,
                pid().as_raw(),
                0,
                0,
                0,
                invoke,
                read_registers,
                write_registers,
            )
        }
    } else {
        init(runtime, counters, fixture, 0)
    };
    if mode == StartupInjection::RepeatedOwner {
        assert_eq!(status, 0);
        let before = events();
        let calls = fixture.startup_calls.get();
        assert_eq!(init(runtime, counters, fixture, 0), -1);
        assert_eq!(fixture.startup_calls.get(), calls);
        assert_eq!(events(), before);
    }
    if let Some(reason) = mode.refusal() {
        if mode != StartupInjection::RepeatedOwner {
            assert_eq!(status, -1);
        }
        assert!(
            DIAGNOSTICS
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains(reason))
        );
        let effects = usize::from(matches!(
            mode,
            StartupInjection::WriteFailed
                | StartupInjection::Duplicate
                | StartupInjection::CompletedPostExec
                | StartupInjection::RepeatedOwner
        ));
        assert_eq!(fixture.startup_calls.get(), effects);
        assert_eq!(fixture.startup_writes.get(), effects);
        assert_eq!(
            events().iter().filter(|e| **e == "started").count(),
            usize::from(mode == StartupInjection::RepeatedOwner)
        );
        assert!(!events().contains(&"thread-exit"));
        assert!(run.completed().is_err());
        if matches!(
            mode,
            StartupInjection::PostExec | StartupInjection::CompletedPostExec
        ) {
            assert!(events().contains(&"post"));
            assert!(!events().contains(&"remote-post"));
            assert_eq!(
                fixture.register_reads.get(),
                usize::from(mode == StartupInjection::CompletedPostExec)
            );
            assert_eq!(server.global.calls.load(Ordering::SeqCst), 1);
        }
        if mode != StartupInjection::StaleOwner {
            assert!(fixture.calls.get() > 0);
        }
    } else {
        assert_eq!(status, 0);
        assert_eq!(fixture.startup_calls.get(), 1);
        assert_eq!(fixture.register_reads.get(), 1);
        assert_eq!(fixture.startup_writes.get(), 1);
        let rows = events();
        let locate = |name| rows.iter().position(|row| *row == name).unwrap();
        assert!(locate("startup-effect") < locate("startup-write"));
        assert!(locate("startup-write") < locate("startup-drop"));
        assert!(locate("startup-drop") < locate("post"));
        assert!(locate("remote-post") < locate("started"));
        assert!(locate("started-ack") < locate("native-ack-call"));
        assert_eq!(rows.iter().filter(|e| **e == "startup-drop").count(), 1);
        assert_eq!(
            fixture.written.borrow().as_ref().unwrap().rax,
            mode.raw_result() as u64
        );
        let mut result = -1234;
        let mut number = -4321;
        let mut args = [0xa5; 6];
        assert_eq!(
            unsafe {
                runtime.pre_syscall(
                    fixture.context(),
                    counters,
                    pid().as_raw(),
                    pid().as_raw(),
                    1,
                    libc::SYS_getpid,
                    FINAL_ARGS.as_ptr(),
                    41,
                    &mut result,
                    &mut number,
                    args.as_mut_ptr(),
                    invoke,
                    read_registers,
                    write_registers,
                    read_memory,
                )
            },
            2
        );
        assert_eq!(result, -1234);
        assert_eq!(number, libc::SYS_exit_group);
        assert_eq!(args, FINAL_ARGS);
        let fact = fixture.reservation.get().unwrap();
        assert_eq!(
            unsafe {
                runtime.thread_exit(counters, fixture.context(), pid().as_raw(), invoke, &fact)
            },
            0
        );
        assert_eq!(
            fixture.startup_calls.get(),
            1,
            "no replay during completion"
        );
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 4);
        assert_eq!(run.completed().unwrap().exit_code(), 47);
        assert!(DIAGNOSTICS.lock().unwrap().is_empty());
    }
    eprintln!(
        "caller startup protocol: mode={mode:?} status={status} effect_calls={} reads={} writes={} rows={:?} raw={:?} diagnostics={:?}",
        fixture.startup_calls.get(),
        fixture.register_reads.get(),
        fixture.startup_writes.get(),
        events(),
        fixture.written.borrow().as_ref().map(register_words),
        DIAGNOSTICS.lock().unwrap()
    );
    if !counters.runtime_state.is_null() {
        unsafe {
            drop(Box::from_raw(
                counters.runtime_state.cast::<RootAttachment<Probe>>(),
            ));
        }
        counters.runtime_state = std::ptr::null_mut();
    }
    fixture.shutdown();
    server.finish();
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn caller_runtime_protocol() {
    if let Some(case) = std::env::var_os(CHILD_CASE) {
        let case = case.to_str().unwrap();
        assert!(
            matches!(
                case,
                "deferred"
                    | "original"
                    | "mismatch"
                    | "cpuid"
                    | "rdtsc"
                    | "failed"
                    | "missing-fatal"
                    | "missing-finished"
            ) || ASYNC_CASES.contains(&case)
                || SUPPRESSION_CASES.contains(&case)
                || STARTUP_CASES.contains(&case)
        );
        exercise(case);
        println!("{WITNESS}:{case}");
        return;
    }
    // Installers and the cached primary are process globals. Exec starts a
    // fresh libtest process; no Rust allocator/async work follows a raw fork of
    // the multithreaded harness. Every timeout/panic kills and reaps the child.
    for case in [
        "deferred",
        "original",
        "mismatch",
        "cpuid",
        "rdtsc",
        "failed",
        "missing-fatal",
        "missing-finished",
    ]
    .into_iter()
    .chain(ASYNC_CASES)
    .chain(SUPPRESSION_CASES)
    .chain(STARTUP_CASES)
    {
        let directory = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(directory.path()).unwrap();
        // Keep the real socket under TMPDIR while its held parent dirfd gives
        // both processes a short pathname, independent of harness nesting.
        let socket = format!(
            "/proc/{}/fd/{}/caller.sock",
            std::process::id(),
            dirfd.as_raw_fd()
        );
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
            .env(CHILD_CASE, case)
            .env(crate::sync_rpc::RPC_SOCKET_ENV, socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(Some(child));
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "CallerRuntime {case} child timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        if SUPPRESSION_CASES.contains(&case) {
            println!("CallerRuntime {case} actual output: {output:?}");
        }
        assert!(output.status.success(), "CallerRuntime {case}: {output:?}");
        if STARTUP_CASES.contains(&case) {
            eprintln!(
                "caller startup protocol child {case}: status={:?} stdout={:?} stderr={:?}",
                output.status, output.stdout, output.stderr
            );
        }
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("test result: ok. 1 passed;"),
            "wrong libtest selection: {stdout}"
        );
        assert_eq!(stdout.matches(&format!("{WITNESS}:{case}")).count(), 1);
    }
}

mod facility_admission;
// This selector uses the existing real RPC/exec isolation harness. Native
// registers and admission are controlled; no live DR/fork claim follows.
const STACK_CASE: &str = "REVERIE_DBT_INITIAL_STACK_UNIT_CASE";
const STACK_TEST: &str = "caller_runtime::tests::initial_stack_fact_owner_and_lifetime";
static STACK_OBSERVATIONS: Mutex<Vec<(u8, Option<u64>, u64)>> = Mutex::new(Vec::new());

#[derive(Default)]
struct StackProbe;

#[reverie::tool]
impl Tool for StackProbe {
    type GlobalState = RemoteGlobal;
    type ThreadState = ();

    fn subscriptions(_: &Config) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.syscall(Sysno::getpid);
        subscriptions
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        let observed = guest.initial_stack_pointer();
        let mut regs = guest.regs().await;
        STACK_OBSERVATIONS
            .lock()
            .unwrap()
            .push((0, observed, regs.rsp));
        assert_eq!(
            guest.send_rpc(Request::Start).await,
            Request::Start.response()
        );
        regs.rsp = 0x710000;
        guest.set_regs(regs).await?;
        assert_eq!(guest.initial_stack_pointer(), observed);
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let rsp = guest.regs().await.rsp;
        STACK_OBSERVATIONS
            .lock()
            .unwrap()
            .push((1, guest.initial_stack_pointer(), rsp));
        assert_eq!(
            guest.send_rpc(Request::PostExec).await,
            Request::PostExec.response()
        );
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(call.number(), Sysno::getpid);
        let rsp = guest.regs().await.rsp;
        STACK_OBSERVATIONS
            .lock()
            .unwrap()
            .push((2, guest.initial_stack_pointer(), rsp));
        Ok(0)
    }
}

unsafe extern "C" fn stack_read(context: usize, out: *mut libc::user_regs_struct) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    let regs = fixture
        .written
        .borrow()
        .as_ref()
        .copied()
        .unwrap_or_else(startup_registers);
    unsafe { out.write(regs) };
    1
}

unsafe extern "C" fn stack_write(context: usize, regs: *const libc::user_regs_struct) -> i32 {
    let fixture = unsafe { &*(context as *const NativeFixture) };
    let actual = unsafe { regs.read() };
    let mut expected = startup_registers();
    expected.rsp = 0x710000;
    assert_eq!(register_words(&actual), register_words(&expected));
    assert!(
        fixture.written.borrow().is_none(),
        "one explicit Tool write"
    );
    *fixture.written.borrow_mut() = Some(actual);
    1
}

fn exercise_initial_stack(case: &str) {
    let runtime = CallerRuntime::<StackProbe>::new([0x6b; 32]);
    let image = runtime.image_init();
    let run = ActivationRun::new();
    run.bind_root(pid().as_raw()).unwrap();
    let mut server = Server::start(Config::default(), run.clone());
    // Drop the fixture (EOF) before the server on an assertion failure.
    let fixture = Box::<NativeFixture>::default();
    let mut counters = CallerCounters {
        branches: 0,
        observed_syscalls: 0,
        rewritten_syscalls: 0,
        runtime_state: std::ptr::null_mut(),
    };
    let mut table = callbacks();
    assert_eq!(
        unsafe {
            runtime.background_init(
                (&mut table as *mut DbtRuntimeCallbacks).cast(),
                crate::DbtStartupMode::Coordinated as u32,
            )
        },
        0
    );
    let mut fact = InitialStackFact {
        size: std::mem::size_of::<InitialStackFact>() as u32,
        version: 1,
        kind: 1,
        context: fixture.context() as u64,
        pid: pid().as_raw(),
        tid: pid().as_raw(),
        image: image.image_generation,
        pc: 0x401000,
        rsp: 0x700000,
        reserved: 0,
    };
    let expected = match case {
        "observed" | "repeated" => Some(fact.rsp),
        "zero" => {
            fact.rsp = 0;
            Some(0)
        }
        "unobserved" => {
            fact.kind = 0;
            None
        }
        "wrong-context" => {
            fact.context += 1;
            None
        }
        "wrong-pid" => {
            fact.pid += 1;
            None
        }
        "wrong-tid" => {
            fact.tid += 1;
            None
        }
        "wrong-image" => {
            fact.image += 1;
            None
        }
        "invalid-version" => {
            fact.version += 1;
            None
        }
        "legacy" | "null" | "invalid-owner" => None,
        _ => panic!("unknown initial-stack case {case}"),
    };
    let tid = pid().as_raw() + i32::from(case == "invalid-owner");
    let fact_pointer = if case == "null" {
        std::ptr::null()
    } else {
        &fact
    };
    let status = unsafe {
        if case == "legacy" {
            runtime.thread_init(
                &mut counters,
                fixture.context(),
                tid,
                pid().as_raw(),
                -1,
                37,
                0,
                invoke,
                stack_read,
                stack_write,
            )
        } else {
            runtime.thread_init_with_stack(
                &mut counters,
                fixture.context(),
                tid,
                pid().as_raw(),
                -1,
                37,
                0,
                invoke,
                stack_read,
                stack_write,
                fact_pointer,
            )
        }
    };
    let mut admitted = false;
    if matches!(case, "invalid-version" | "null" | "invalid-owner") {
        assert_eq!(status, -1);
        assert!(counters.runtime_state.is_null());
        assert!(STACK_OBSERVATIONS.lock().unwrap().is_empty());
        assert!(fixture.written.borrow().is_none());
        assert_eq!(fixture.calls.get(), 0, "refusal before native effects");
        let reason = if case == "invalid-owner" {
            "caller-initial-single-thread-owner-required"
        } else {
            "caller-initial-stack-fact-invalid"
        };
        assert!(
            DIAGNOSTICS
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains(reason))
        );
    } else {
        assert_eq!(status, 0);
        admitted = true;
        let mut result = -1234;
        let mut deferred_number = -4321;
        let mut deferred_args = [0xa5; 6];
        assert_eq!(
            unsafe {
                runtime.pre_syscall(
                    fixture.context(),
                    &mut counters,
                    pid().as_raw(),
                    pid().as_raw(),
                    image.image_generation,
                    libc::SYS_getpid,
                    [0; 6].as_ptr(),
                    41,
                    &mut result,
                    &mut deferred_number,
                    deferred_args.as_mut_ptr(),
                    invoke,
                    stack_read,
                    stack_write,
                    read_memory,
                )
            },
            1
        );
        assert_eq!(result, 0);
        assert_eq!(deferred_number, -4321);
        assert_eq!(deferred_args, [0xa5; 6]);
        let rows = STACK_OBSERVATIONS.lock().unwrap().clone();
        eprintln!("initial-stack owner {case}: observations={rows:?}");
        assert_eq!(
            rows,
            [
                (0, expected, 0x700000),
                (1, expected, 0x710000),
                (2, expected, 0x710000)
            ]
        );
        assert_eq!(server.global.calls.load(Ordering::SeqCst), 2);
        if case == "repeated" {
            let owner = counters.runtime_state;
            assert_eq!(
                unsafe {
                    runtime.thread_init_with_stack(
                        &mut counters,
                        fixture.context(),
                        tid,
                        pid().as_raw(),
                        -1,
                        37,
                        0,
                        invoke,
                        stack_read,
                        stack_write,
                        &fact,
                    )
                },
                -1
            );
            assert_eq!(counters.runtime_state, owner);
            assert_eq!(*STACK_OBSERVATIONS.lock().unwrap(), rows);
            assert!(
                DIAGNOSTICS
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|line| line.contains("caller-application-admission-repeated"))
            );
        }
        // Model the existing native original-exit notification before closing
        // the claimed primary. This is unit teardown, not an actual kernel exit.
        let terminal = TerminalFact {
            size: std::mem::size_of::<TerminalFact>() as u32,
            kind: 1,
            image: image.image_generation,
            context: fixture.context() as u64,
            pid: pid().as_raw(),
            tid: pid().as_raw(),
            sysno: libc::SYS_exit_group,
            args: FINAL_ARGS,
            cookie: 92,
            origin: 1,
            reserved: 0,
        };
        assert!(run.completed().is_err());
        assert_eq!(
            unsafe {
                runtime.thread_exit(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    invoke,
                    &terminal,
                )
            },
            0
        );
        // The fixture owns this allocation; this is not a kernel exit claim.
        unsafe {
            drop(Box::from_raw(
                counters.runtime_state.cast::<RootAttachment<StackProbe>>(),
            ));
        }
        counters.runtime_state = std::ptr::null_mut();
        assert!(
            unsafe {
                runtime.attachment(
                    &mut counters,
                    fixture.context(),
                    pid().as_raw(),
                    pid().as_raw(),
                    image.image_generation,
                )
            }
            .is_err()
        );
    }
    fixture.shutdown();
    server.finish();
    if admitted {
        // Joining the server orders this read after its FinishedAck commit.
        let completed = run.completed().unwrap();
        assert_eq!(completed.exit_code(), 47);
        assert_eq!(completed.syscall(), libc::SYS_exit_group);
        assert_eq!(completed.origin(), ExitOrigin::Original);
    }
    assert!(server.issues.snapshot().is_empty());
}

#[test]
fn initial_stack_fact_owner_and_lifetime() {
    const CASES: [&str; 12] = [
        "observed",
        "zero",
        "unobserved",
        "legacy",
        "wrong-context",
        "wrong-pid",
        "wrong-tid",
        "wrong-image",
        "invalid-version",
        "null",
        "invalid-owner",
        "repeated",
    ];
    if let Some(case) = std::env::var_os(STACK_CASE) {
        let case = case.to_str().unwrap();
        assert!(CASES.contains(&case));
        exercise_initial_stack(case);
        println!("INITIAL_STACK_OWNER_COMPLETED:{case}");
        return;
    }
    for case in CASES {
        let directory = tempfile::tempdir().unwrap();
        let dirfd = std::fs::File::open(directory.path()).unwrap();
        let socket = format!(
            "/proc/{}/fd/{}/initial-stack.sock",
            std::process::id(),
            dirfd.as_raw_fd()
        );
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", STACK_TEST, "--test-threads=1", "--nocapture"])
            .env(STACK_CASE, case)
            .env(crate::sync_rpc::RPC_SOCKET_ENV, socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child = ChildGuard(Some(child));
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "initial-stack {case} child timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        eprintln!(
            "initial-stack owner child {case}: status={:?} stdout={:?} stderr={:?}",
            output.status.code(),
            output.stdout,
            output.stderr
        );
        assert!(output.status.success(), "initial-stack {case}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "{stdout}"
        );
        assert_eq!(
            stdout
                .matches(&format!("INITIAL_STACK_OWNER_COMPLETED:{case}"))
                .count(),
            1
        );
    }
}
