/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `TracedTask` and its methods.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::ops::DerefMut;
use std::os::unix::ffi::OsStringExt;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock as StdOnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use async_trait::async_trait;
use futures::future;
use futures::future::Either;
use futures::future::Future;
use futures::future::FutureExt;
use futures::future::TryFutureExt;
use nix::sys::mman::ProtFlags;
use nix::sys::signal::Signal;
use reverie::BackendFailure;
use reverie::Backtrace;
use reverie::Errno;
use reverie::ExitStatus;
use reverie::Frame;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
#[cfg(target_arch = "x86_64")]
use reverie::Rdtsc;
use reverie::Subscription;
use reverie::Tid;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mprotect;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use safeptrace::ChildOp;
use safeptrace::Error as TraceError;
use safeptrace::Event;
use safeptrace::OwnedWaitError;
use safeptrace::Running;
use safeptrace::Stopped;
use safeptrace::TraceeGeneration;
use safeptrace::Wait;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::LiteinstInstrumentationStats;
use crate::PtraceBackendStatsSource;
use crate::children;
use crate::cp;
use crate::error::Error;
use crate::error::LiteinstActivationFailure;
use crate::error::LiteinstActivationFailureReason;
use crate::error::LiteinstActivationOperation;
use crate::error::LiteinstActivationStage;
use crate::error::TraceResultExt;
use crate::error::liteinst_activation_failure_reason;
use crate::failure::PtraceCleanupFailure;
use crate::failure::PtraceRunFailure;
use crate::gdbstub::BreakpointType;
use crate::gdbstub::CoreRegs;
use crate::gdbstub::GdbRequest;
use crate::gdbstub::GdbServer;
use crate::gdbstub::ResumeAction;
use crate::gdbstub::ResumeInferior;
use crate::gdbstub::StopEvent;
use crate::gdbstub::StopReason;
use crate::gdbstub::StoppedInferior;
#[cfg(target_arch = "x86_64")]
use crate::injected_syscall::InjectedSyscallFrame;
use crate::liteinst_census::Census;
use crate::liteinst_census::CensusError;
use crate::liteinst_census::REFUSED_ENTRY_LIMIT;
use crate::liteinst_census::Refusal;
use crate::liteinst_census::Segment;
use crate::liteinst_census::SiteEntries;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::LANDING_LEN;
use crate::liteinst_restart::LANDING_OFFSET;
use crate::liteinst_restart::LandingOutcome;
use crate::liteinst_restart::PrivateStep;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::RUNTIME_OWNED_HANDLERS;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::RestartAction;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::changed_landing_register;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::check_landing_bytes;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::check_rewind_preconditions;
use crate::liteinst_restart::classify_landing_trap;
use crate::liteinst_restart::classify_private_step;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::landing_regs;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::liteinst_restart_action;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::restart_depends_on_handler;
#[cfg(target_arch = "x86_64")]
use crate::liteinst_restart::signal_bit;
use crate::liteinst_stats::LiteinstPatchOutcome;
use crate::liteinst_trap_only::StoredSiginfo;
use crate::liteinst_trap_only::TrapOnlyTask;
use crate::poll_on_wake::PollOnWake;
use crate::tracer::PtracerController;
use crate::tracer::PtracerWaitOwner;
use crate::tracer::WaitOnPtracer;

#[path = "task_trap_only.rs"]
mod trap_only;
use trap_only::TrapOnlyRoute;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use trap_only::step_count_for_test;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use trap_only::stepped_seccomp_count_for_test;

use crate::regs::Reg;
use crate::regs::RegAccess;
use crate::stack::GuestStack;
use crate::timer::HandleFailure;
use crate::timer::OwnNotification;
use crate::timer::Timer;
use crate::timer::TimerEventRequest;
use crate::timer::Unfinished;
use crate::tracer::FatalNewborn;
use crate::tracer::FatalTaskStop;
use crate::tracer::HeldRootStop;
use crate::tracer::NewbornTracee;
use crate::tracer::RootStopLease;
use crate::tracer::TraceeIdentity;
use crate::vdso;

// A lifecycle association failure must prevent the following resume, not just
// report a flag whose waiter may be polled after this future resumes the guest.
fn observe_ready_thread_state<T: Tool>(
    tool: &T,
    pid: Pid,
    tid: Tid,
    global: &T::GlobalState,
    state: &T::ThreadState,
) -> Result<(), Errno> {
    tool.on_thread_state_ready(tid, global, state)
        .map_err(|error| {
            tracing::error!(%pid, %tid, %error, "owned Tool state association failed");
            global.report_backend_failure(reverie::BackendFailure {
                pid,
                tid,
                phase: "owned Tool state association failed",
            });
            Errno::EPROTO
        })
}

#[cfg(test)]
mod thread_state_ready_tests;

#[cfg(target_arch = "x86_64")]
fn validate_liteinst_user_regs_update(
    current: &libc::user_regs_struct,
    requested: &libc::user_regs_struct,
) -> Result<(), Errno> {
    if current.rsp == requested.rsp {
        Ok(())
    } else {
        Err(Errno::ENOTSUPP)
    }
}

#[cfg(target_arch = "x86_64")]
fn liteinst_helper_entry_rflags(flags: u64) -> u64 {
    const RFLAGS_TF: u64 = 1 << 8;
    const RFLAGS_DF: u64 = 1 << 10;
    const RFLAGS_RF: u64 = 1 << 16;
    const RFLAGS_AC: u64 = 1 << 18;
    flags & !(RFLAGS_TF | RFLAGS_DF | RFLAGS_RF | RFLAGS_AC)
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiteinstCpuidPolicy {
    Unsupported,
    UnchangedEnabled,
    RestoreDisabled,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiteinstTscPolicy {
    Unsupported,
    UnchangedEnabled,
    RestoreFaulting,
}

#[cfg(target_arch = "x86_64")]
struct LiteinstHelperSavedState {
    cpuid_policy: LiteinstCpuidPolicy,
    tsc_policy: LiteinstTscPolicy,
    regs: libc::user_regs_struct,
    xstate: safeptrace::XState,
    stack_address: usize,
    stack_value: u64,
}

#[cfg(target_arch = "x86_64")]
fn is_legacy_vsyscall_ip(ip: Reg) -> bool {
    const VSYSCALL_START: Reg = 0xffff_ffff_ff60_0000;
    const VSYSCALL_END: Reg = VSYSCALL_START + 0x1000;

    (VSYSCALL_START..VSYSCALL_END).contains(&ip)
}

#[derive(Debug)]
struct Suspended {
    waker: Option<mpsc::Sender<Pid>>,
    suspended: Arc<AtomicBool>,
}

/// Expected resume action sent by gdb client, when the task is in a gdb stop.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ExpectedGdbResume {
    /// Expecting a normal gdb resume, either single step, until or continue
    Resume,
    /// Expecting a gdb step over, this happens the underlying task hit a sw
    /// breakpoint, gdb then needs to restore the original instruction --
    /// which implies deleting the breakpoint, single-step, then restore
    /// the breakpoint. This is a special case because we need to serialize
    /// the whole operation, otherwise when there's a different thread in
    /// the same process group which share the same breakpoint, removing
    /// breakpoint can cause the 2nd thread to miss the breakpoint.
    StepOver,
    /// Force single-step, even if Resume(continue) is requested. This
    /// is a workaround when fork/vfork/clone event is reported to gdb,
    /// gdb could then issue an `vCont;p<pid>:-1` to resume all threads in
    /// the thread group, which could cause the main thread to miss events.
    StepOnly,
}

enum OrdinaryStart {
    Stopped(Stopped),
    Exec(Stopped, Pid),
    Newborn(Running, Option<Box<libc::user_regs_struct>>),
}

/// Where in a process's life [`TracedTask::tracee_preinit`] runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreinitPlace {
    /// At the root's first stop, before it calls execve. Its stack is the
    /// launcher's own, or the spawned function's.
    BeforeExec,
    /// At the stop that follows a successful execve, before the new image's
    /// first instruction. Its stack holds argc, argv, envp and the auxv.
    AtExec,
}

/// The actual host threads and tracee tids whose images were canonicalized.
/// The host separates independent libtests; the tid binds each count to its tracee.
#[cfg(test)]
pub(crate) static CANONICALIZED_FOR_TEST: StdMutex<Vec<(std::thread::ThreadId, i32)>> =
    StdMutex::new(Vec::new());

/// How [`TracedTask::tracee_preinit`] ended.
pub enum PreinitOutcome {
    /// The tracee is initialized and still stopped.
    Ready(Stopped),
    /// A wait during initialization returned the tracee's final status. A
    /// SIGKILLed tracee first stops at `PTRACE_EVENT_EXIT`, but that stop is
    /// published to the exit notifier, not to the waits initialization makes,
    /// so initialization can resume the tracee from it and then see it exit.
    /// See <https://github.com/rrnewton/reverie/issues/760>.
    Exited(Pid, ExitStatus),
}

/// Returns `error` unchanged unless a probe of `task` confirms its death.
///
/// `process_vm_readv`, `process_vm_writev`, `PTRACE_PEEKDATA` and
/// `PTRACE_POKEDATA` report a tracee that a SIGKILL has just ended as a bare
/// `ESRCH`, which carries no [`TraceError::Died`] for the caller to reap. The
/// probe is [`Stopped::getregs`] (`PTRACE_GETREGSET` with `NT_PRSTATUS`),
/// which safeptrace turns into `Died` exactly when it fails with `ESRCH`.
///
/// A request made while the SIGKILL carries the tracee to its
/// `PTRACE_EVENT_EXIT` stop fails with `ESRCH`, but once the tracee is in that
/// exit stop the probe succeeds again. So when the original error is
/// `ESRCH` and the probe succeeds, [`Stopped::died_into_exit_stop`] checks
/// whether the tracee is now in its exit stop, and reports that as its death.
/// See <https://github.com/rrnewton/hermit/issues/3357>. Any other probe
/// result keeps the original error.
pub(crate) fn dead_or(task: &Stopped, error: TraceError) -> TraceError {
    match error {
        TraceError::Errno(errno) => match task.getregs() {
            Err(died @ TraceError::Died(_)) => died,
            Ok(_) if errno == Errno::ESRCH => task.died_into_exit_stop().unwrap_or(error),
            _ => error,
        },
        error => error,
    }
}

/// Returns the result of a memory request on `task`, passing an error through
/// [`dead_or`].
fn memory_request<T, E: Into<TraceError>>(
    task: &Stopped,
    result: Result<T, E>,
) -> Result<T, TraceError> {
    let result: Result<T, TraceError> = result.map_err(Into::into);
    #[cfg(test)]
    let result = match FORCED_ESRCH.with(|forced| forced.take()) {
        Some(pid) if pid == task.pid() => Err(TraceError::Errno(Errno::ESRCH)),
        forced => {
            FORCED_ESRCH.with(|slot| slot.set(forced));
            result
        }
    };
    result.map_err(|error| dead_or(task, error))
}

#[cfg(test)]
type PostExecStepForTest = Box<dyn FnOnce(Running) -> Running>;

#[cfg(test)]
thread_local! {
    static FORCED_ESRCH: std::cell::Cell<Option<Pid>> = const { std::cell::Cell::new(None) };
    static POST_EXEC_STEP_FOR_TEST: std::cell::RefCell<Option<PostExecStepForTest>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: makes the next [`memory_request`] on `pid` fail with `ESRCH`,
/// as one made between a SIGKILL and the exit stop it leads to does.
#[cfg(test)]
pub(crate) fn force_esrch_for_test(pid: Pid) {
    FORCED_ESRCH.with(|forced| forced.set(Some(pid)));
}

/// Test-only: whether an ESRCH set by [`force_esrch_for_test`] is unused.
#[cfg(test)]
pub(crate) fn forced_esrch_pending_for_test() -> bool {
    FORCED_ESRCH.with(|forced| forced.get().is_some())
}

#[cfg(test)]
thread_local! {
    static PARKED_PREINIT: std::cell::Cell<Option<Pid>> = const { std::cell::Cell::new(None) };
}

/// Test-only: makes the initialization of `pid` stop making progress after
/// it steps into the injected mmap, before it waits for the stop the step
/// leads to, as one whose wait is pending when the notifier publishes that
/// stop and an exit stop after it does.
#[cfg(test)]
pub(crate) fn park_preinit_for_test(pid: Pid) {
    PARKED_PREINIT.with(|parked| parked.set(Some(pid)));
}

/// A same-process task rendezvous authorized only by an actual leader Exec
/// event naming this former TID. No numeric-PID inference can request it.
struct OrdinaryExecSlot<L: Tool> {
    stop: Arc<FatalTaskStop>,
    requested: AtomicBool,
    /// Set by a nonleader owner, in a failed run or not, once its former
    /// TID's exit wait met ECHILD with no final status: exec's de_thread
    /// released the TID.
    lost_former: AtomicBool,
    changed: Notify,
    transferred: StdMutex<Option<Box<TracedTask<L>>>>,
    /// On a leader owner's slot only: the task a same-process nonleader
    /// owner handed over from its lost-former arm. The leader owner takes it
    /// after its child-thread joins, in `tool_exit_ordinary`.
    lost_former_task: StdMutex<Option<Box<TracedTask<L>>>>,
}
impl<L: Tool> OrdinaryExecSlot<L> {
    async fn requested(&self) {
        loop {
            let changed = self.changed.notified();
            if self.requested.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
    async fn lost_former(&self) {
        loop {
            let changed = self.changed.notified();
            if self.lost_former.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
    async fn take(&self) -> Box<TracedTask<L>> {
        loop {
            let changed = self.changed.notified();
            if let Some(task) = self.transferred.lock().unwrap().take() {
                return task;
            }
            changed.await;
        }
    }
}

pub struct Child {
    id: Pid,
    /// Task is suspended, either stopped by gdb (client), or received
    /// SIGSTOP sent by other threads in the same process group.
    suspended: Arc<AtomicBool>,
    /// Notify a task reached SIGSTOP.
    wait_all_stop_tx: Option<mpsc::Sender<(Pid, Suspended)>>,
    /// Channel to receive if a child task is becoming a daemon, when
    /// `daemonize()` is called.
    pub(crate) daemonizer_rx: Option<mpsc::Receiver<broadcast::Receiver<()>>>,
    /// Join handle to let child task exit gracefully.
    pub(crate) handle: ChildCompletion,
    /// Subscription to a successfully captured original group. The session
    /// retains its authority until actual retirement and consuming hooks finish;
    /// completed Child history must not retain the generation's descriptors.
    pub(crate) ordinary_group: Option<OrdinaryGroupSubscription>,
}

impl Child {
    /// Child task identifier.
    pub fn id(&self) -> Pid {
        self.id
    }
}

impl fmt::Debug for Child {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Child").field("id", &self.id).finish()
    }
}

pub(crate) enum ChildCompletion {
    Legacy(JoinHandle<Option<ExitStatus>>),
    Owned(oneshot::Receiver<Option<ExitStatus>>),
}

impl Future for ChildCompletion {
    type Output = Result<Option<ExitStatus>, reverie::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Legacy(handle) => handle
                .poll_unpin(cx)
                .map_err(|error| anyhow::Error::new(error).into()),
            Self::Owned(receiver) => receiver
                .poll_unpin(cx)
                .map_err(|error| anyhow::Error::new(error).into()),
        }
    }
}

impl Future for Child {
    type Output = Result<Option<ExitStatus>, reverie::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}

pub type Children = children::Children<Child>;

enum HandleSignalResult {
    /// Signal is suppressed with task resumed.
    SignalSuppressed(Wait),
    /// signal needs to be delivered.
    SignalToDeliver(Stopped, Signal),
}

#[cfg(target_arch = "x86_64")]
// Linux can report PTRACE_SINGLESTEP completion from a seccomp syscall skip as
// TRAP_BRKPT without advancing RIP. Distinguish that kernel transition from an
// external or guest breakpoint using the controller's exact pre-step state.
fn is_expected_syscall_skip_breakpoint(
    si_code: i32,
    pre_rip: u64,
    post_rip: u64,
    syscall_opcode: [u8; cp::SYSCALL_INSTR_SIZE],
    post_opcode: u8,
    forced_external_for_test: bool,
) -> bool {
    !forced_external_for_test
        && si_code == libc::TRAP_BRKPT
        && post_rip == pre_rip
        && syscall_opcode == [0x0f, 0x05]
        && post_opcode != 0xcc
}

fn is_expected_syscall_skip_trap(
    task: &Stopped,
    pre_rip: u64,
    forced_external_for_test: bool,
) -> Result<bool, TraceError> {
    if forced_external_for_test {
        return Ok(false);
    }
    let siginfo = task.getsiginfo()?;
    if siginfo.si_code == libc::TRAP_TRACE {
        return Ok(true);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        return Ok(false);
    }
    #[cfg(target_arch = "x86_64")]
    if siginfo.si_code != libc::TRAP_BRKPT {
        return Ok(false);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let post_rip = task.getregs()?.ip();
        let syscall_site = pre_rip
            .checked_sub(cp::SYSCALL_INSTR_SIZE as u64)
            .ok_or(Errno::EOVERFLOW)? as usize;
        let mut syscall_opcode = [0; cp::SYSCALL_INSTR_SIZE];
        task.read_exact(syscall_site, &mut syscall_opcode)?;
        let mut post_opcode = [0];
        task.read_exact(post_rip as usize, &mut post_opcode)?;
        Ok(is_expected_syscall_skip_breakpoint(
            siginfo.si_code,
            pre_rip,
            post_rip,
            syscall_opcode,
            post_opcode[0],
            forced_external_for_test,
        ))
    }
}

fn is_expected_breakpoint_trap(
    task: &Stopped,
    breakpoint_rip: u64,
    forced_external_for_test: bool,
) -> Result<bool, TraceError> {
    if forced_external_for_test {
        return Ok(false);
    }
    let siginfo = task.getsiginfo()?;
    let observed_rip = task.getregs()?.ip();
    let after_breakpoint = breakpoint_rip.checked_add(1);
    Ok((siginfo.si_code == libc::TRAP_BRKPT
        && (observed_rip == breakpoint_rip || Some(observed_rip) == after_breakpoint))
        || (siginfo.si_code == libc::SI_KERNEL && Some(observed_rip) == after_breakpoint))
}

/// Whether a stop reported as `sig` without a ptrace event is a job-control
/// group stop rather than a signal-delivery stop. Under `PTRACE_TRACEME` both
/// look identical in the wait status; only a group stop has no siginfo, so
/// `PTRACE_GETSIGINFO` fails with `EINVAL` (see ptrace(2), "Group-stop").
fn is_group_stop(task: &Stopped, sig: Signal) -> Result<bool, TraceError> {
    if !matches!(
        sig,
        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
    ) {
        return Ok(false);
    }
    match task.getsiginfo() {
        Ok(_) => Ok(false),
        Err(safeptrace::Error::Errno(Errno::EINVAL)) => Ok(true),
        Err(err) => Err(err),
    }
}

/// `is_group_stop` at a stop where main makes no `PTRACE_GETSIGINFO`:
/// `false`, without the request, when the tracer thread may be under a
/// seccomp filter (`thread_may_be_seccomp_filtered`), which can refuse it or
/// kill the tracer at it. The stop is then taken for a signal-delivery stop,
/// as main takes it.
fn is_group_stop_unless_filtered(task: &Stopped, sig: Signal) -> Result<bool, TraceError> {
    if !matches!(
        sig,
        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
    ) || thread_may_be_seccomp_filtered()
    {
        return Ok(false);
    }
    is_group_stop(task, sig)
}

/// The bit for `sig` in a kernel signal mask as read by `PTRACE_GETSIGMASK`.
fn signal_mask_bit(sig: Signal) -> u64 {
    1u64 << (sig as i32 - 1)
}

/// A signal as its signal-delivery stop took it from the kernel, with its
/// siginfo.
#[derive(Clone, Copy)]
struct TakenSignal {
    signal: Signal,
    siginfo: StoredSiginfo,
}

impl TakenSignal {
    /// Reads the record of `signal` at its signal-delivery stop, `None` if
    /// the stop's siginfo cannot be read, or if the tracer thread may be
    /// under a seccomp filter (`thread_may_be_seccomp_filtered`). Main makes
    /// no `PTRACE_GETSIGINFO` at these stops, and a filter can refuse it or
    /// kill the tracer at it. Without the record, the signal is resumed as
    /// main resumes it, and nothing is restored or counted for it
    /// (`resume_with_signal`).
    fn at_stop(task: &Stopped, signal: Signal) -> Option<Self> {
        if thread_may_be_seccomp_filtered() {
            return None;
        }
        Some(Self {
            signal,
            siginfo: StoredSiginfo(task.getsiginfo().ok()?),
        })
    }
}

/// The signal a stopped guest resumes with, and, if
/// `Tool::handle_signal_event` reported it, how its delivery stop took it.
struct SignalResume {
    signal: Option<Signal>,
    reported: Option<TakenSignal>,
}

/// What `Tool::handle_signal_event` left for a signal (`report_signal`).
struct SignalVerdict {
    /// The signal to resume with, `None` if the callback suppressed it.
    signal: Option<Signal>,
}

/// The signal mask the kernel dequeues under for the stopped thread `tid`
/// (`task->blocked`, procfs `SigBlk`).
///
/// `PTRACE_GETSIGMASK` reports the saved mask instead while a mask-swapping
/// syscall's restore is pending (`TIF_RESTORE_SIGMASK`), so it cannot tell
/// whether that syscall's temporary mask blocks a signal.
fn blocked_signal_mask(tid: Pid) -> Result<u64, TraceError> {
    let status = crate::launch_window::read_to_string(format!("/proc/{tid}/status"))
        .map_err(|err| Errno::new(err.raw_os_error().unwrap_or(libc::EIO)))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| Errno::EPROTO.into())
}

/// The signals pending in the kernel for the stopped thread `tid`: its own
/// and its thread group's (procfs `SigPnd` and `ShdPnd`).
fn pending_signal_mask(tid: Pid) -> Result<u64, TraceError> {
    let status = crate::launch_window::read_to_string(format!("/proc/{tid}/status"))
        .map_err(|err| Errno::new(err.raw_os_error().unwrap_or(libc::EIO)))?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            .ok_or(Errno::EPROTO)
    };
    Ok(field("SigPnd:")? | field("ShdPnd:")?)
}

/// Whether a seccomp filter may restrict the calling thread's syscalls, or
/// its mode cannot be read (procfs `Seccomp` of `/proc/thread-self`, read
/// afresh at each call). Called on the tracer thread, which makes every
/// ptrace request, at the point that decides on a request or step main does
/// not make. Filters are never removed, so mode 0 there means no filter can
/// refuse it. A thread gets one only by installing it or by another thread
/// synchronizing its own (`SECCOMP_FILTER_FLAG_TSYNC`).
///
/// Where the status cannot be read, for example with no descriptor left to
/// open (EMFILE), the thread is taken as filtered, and the decision goes as
/// on main: no syscall can ask the mode safely, as a filter can kill the
/// tracer at it or answer it falsely (`prctl(PR_GET_SECCOMP)`), and a
/// descriptor held open for the purpose changes the descriptors guests get.
/// On an unfiltered thread this gives up 831's corrections there, a
/// disclosed gap (https://github.com/rrnewton/reverie/issues/845,
/// https://github.com/rrnewton/reverie/issues/912).
fn thread_may_be_seccomp_filtered() -> bool {
    crate::launch_window::read_to_string("/proc/thread-self/status")
        .ok()
        .is_none_or(|status| !status_unfiltered(&status))
}

/// Whether a procfs status reports seccomp mode 0.
fn status_unfiltered(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .is_some_and(|mode| mode.trim() == "0")
}

/// `si_code` of a SIGSYS raised by a seccomp filter's `SECCOMP_RET_TRAP`.
const SYS_SECCOMP: libc::c_int = 1;

/// Whether `wait` is a SIGTRAP signal-delivery stop at the private-page
/// `syscall`, before it ran.
fn is_sigtrap_before_private_syscall(wait: &Wait) -> Result<bool, TraceError> {
    Ok(match wait {
        Wait::Stopped(stopped, Event::Signal(Signal::SIGTRAP)) => {
            stopped.getregs()?.ip() == cp::PRIVATE_PAGE_OFFSET as u64
        }
        _ => false,
    })
}

/// Whether the SIGTRAP `task` stopped with is the single-step report of a
/// private-page `syscall`: x86 raises it at syscall exit with `si_addr` set to
/// the RIP just past the instruction (`after_syscall`).
fn is_private_step_trap(task: &Stopped, after_syscall: u64) -> Result<bool, TraceError> {
    let siginfo = task.getsiginfo()?;
    // SAFETY: si_addr reads the fault-address member that SIGTRAP's
    // TRAP_TRACE and TRAP_BRKPT reports fill in.
    Ok(siginfo.si_signo == libc::SIGTRAP
        && matches!(siginfo.si_code, libc::TRAP_TRACE | libc::TRAP_BRKPT)
        && unsafe { siginfo.si_addr() } as u64 == after_syscall)
}

/// Whether the SIGSYS `task` stopped with was raised by a guest seccomp
/// filter's `SECCOMP_RET_TRAP` for the private-page `syscall`. Its
/// `si_call_addr` (which shares `si_addr`'s place in the siginfo union) is
/// the RIP just past the trapped instruction (`after_syscall`).
fn is_private_seccomp_trap(task: &Stopped, after_syscall: u64) -> Result<bool, TraceError> {
    let siginfo = task.getsiginfo()?;
    // SAFETY: for SYS_SECCOMP the union holds `_sigsys`, whose first member
    // `_call_addr` is at the offset si_addr reads.
    Ok(siginfo.si_signo == libc::SIGSYS
        && siginfo.si_code == SYS_SECCOMP
        && unsafe { siginfo.si_addr() } as u64 == after_syscall)
}

/// Whether `nr` installs a temporary signal mask that the kernel restores only
/// after signal handling (`TIF_RESTORE_SIGMASK`). A ptrace mask write discards
/// that pending restore, so a signal stopping such a syscall must not be
/// returned to the kernel queue by masking it.
fn swaps_signal_mask(nr: Sysno) -> bool {
    matches!(
        nr,
        Sysno::rt_sigsuspend
            | Sysno::ppoll
            | Sysno::pselect6
            | Sysno::epoll_pwait
            | Sysno::epoll_pwait2
            | Sysno::io_pgetevents
            | Sysno::io_uring_enter
    )
}

fn is_expected_private_syscall_trap(
    task: &Stopped,
    expected_rip: u64,
    forced_external_for_test: bool,
) -> Result<bool, TraceError> {
    if forced_external_for_test {
        return Ok(false);
    }
    if task.getregs()?.ip() != expected_rip {
        return Ok(false);
    }
    let siginfo = task.getsiginfo()?;
    if !matches!(siginfo.si_code, libc::TRAP_TRACE | libc::TRAP_BRKPT) {
        return Ok(false);
    }

    // Some x86 kernels report PTRACE_SINGLESTEP completion after `syscall` as
    // TRAP_BRKPT rather than TRAP_TRACE. In either case, the private page is
    // RWX and therefore guest-mutable, so accept the stop only while the exact
    // controller-installed `syscall; ud2` stub remains intact.
    #[cfg(target_arch = "x86_64")]
    let expected_stub = [0x0f, 0x05, 0x0f, 0x0b];
    #[cfg(target_arch = "aarch64")]
    let expected_stub = [
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xad, 0xde, 0x00, 0x00, // udf 0xdead
    ];
    let mut observed_stub = [0; cp::SYSCALL_INSTR_SIZE * 2];
    task.read_exact(cp::PRIVATE_PAGE_OFFSET, &mut observed_stub)?;
    Ok(observed_stub == expected_stub)
}

enum NestedTrapExpectation {
    None,
    SyscallSkip { pre_rip: u64 },
    Breakpoint(u64),
    PrivateSyscall(u64),
}
#[derive(Clone)]
pub(crate) struct InjectedSyscallTrap {
    pub(crate) marker: u64,
    pub(crate) rip: u64,
    pub(crate) provenance: Option<InjectedSyscallProvenance>,
}

#[derive(Clone)]
pub(crate) struct InjectedSyscallProvenance {
    pub(crate) image: PathBuf,
    pub(crate) image_inode: u64,
    pub(crate) image_entry_address: u64,
    pub(crate) patched_site_addresses: Arc<[u64]>,
}

#[derive(Clone, Debug)]
struct GuestMap {
    start: u64,
    end: u64,
    offset: u64,
    device_major: u64,
    device_minor: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    shared: bool,
    inode: u64,
    path: Option<PathBuf>,
}

impl GuestMap {
    fn contains(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }

    fn contains_range(&self, range: GuestRange) -> bool {
        self.start <= range.start && range.end <= self.end
    }

    /// The file this mapping maps: its device and inode.
    fn file(&self) -> (u64, u64, u64) {
        (self.device_major, self.device_minor, self.inode)
    }
}

/// Where an object whose code the tracer censuses is mapped.
#[derive(Debug, Eq, PartialEq)]
struct CensusObject {
    /// The executable mapping that holds the site.
    text: (u64, u64),
    /// The address of the object's ELF header.
    header: u64,
    /// Each readable mapping of the object.
    ranges: Vec<CensusRange>,
    /// The device and inode of the object's file, as the tracee's maps name
    /// them.
    file: (u64, u64, u64),
    /// The path of the object's file, as the tracee's maps name it.
    path: Option<PathBuf>,
}

/// One readable mapping of a census object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CensusRange {
    start: u64,
    end: u64,
    /// The offset in the object's file that `start` maps.
    offset: u64,
    executable: bool,
}

const NO_CENSUS_OBJECT: CensusError =
    CensusError("the executable mapping belongs to no identifiable object");
const CHANGED_CENSUS_OBJECT: CensusError =
    CensusError("the object's mappings changed while its census was built");
const FAULTING_CENSUS_OBJECT: CensusError =
    CensusError("a page of the object faults when read, such as a page past the end of its file");

/// Returns the readable mappings of the file that `maps` maps executable over
/// `site`, with the address of its ELF header. This is the tracer's copy of the
/// LiteInst runtime's `object_image`
/// (<https://github.com/rrnewton/reverie/issues/812>).
///
/// Mappings belong to one object when they share the text mapping's device and
/// inode. The header is the single such mapping at file offset zero. A file
/// that is mapped twice has two, so it gets no object, and neither does an
/// anonymous mapping.
fn census_object(maps: &[GuestMap], site: u64) -> Result<CensusObject, CensusError> {
    let text = maps
        .iter()
        .find(|map| map.executable && map.contains(site))
        .filter(|map| map.inode != 0)
        .ok_or(NO_CENSUS_OBJECT)?;
    let object = maps
        .iter()
        .filter(|map| map.readable && map.file() == text.file());
    let mut headers = object.clone().filter(|map| map.offset == 0);
    let header = match (headers.next(), headers.next()) {
        (Some(header), None) => header.start,
        _ => return Err(NO_CENSUS_OBJECT),
    };
    Ok(CensusObject {
        text: (text.start, text.end),
        header,
        ranges: object
            .map(|map| CensusRange {
                start: map.start,
                end: map.end,
                offset: map.offset,
                executable: map.executable,
            })
            .collect(),
        file: text.file(),
        path: text.path.clone(),
    })
}

/// Positioned reads of a tracee's memory, as `pread` makes them on
/// `/proc/<pid>/mem`, and the size of the file that a census object maps.
trait CensusMemory {
    fn read_at(&self, address: u64, bytes: &mut [u8]) -> std::io::Result<usize>;

    /// The size of `object`'s file, or an error if the tracer cannot find
    /// that file.
    fn file_size(&self, object: &CensusObject) -> std::io::Result<u64>;
}

/// A tracee's memory, read through its open `/proc/<pid>/mem`.
struct TraceeMemory(std::fs::File);

impl CensusMemory for TraceeMemory {
    fn read_at(&self, address: u64, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(&self.0, bytes, address)
    }

    fn file_size(&self, object: &CensusObject) -> std::io::Result<u64> {
        mapped_file_size(object)
    }
}

/// Returns the size of `object`'s file, which the tracer finds through the
/// path in the tracee's maps.
///
/// The kernel prints that path relative to the root of the process that reads
/// the maps, the tracer, so it can name another file than the mapped one, or
/// none. The file at the path is the object's file only if its inode, and the
/// device of the superblock of the mount that holds it, are the ones in the
/// maps; anything else is an error. The maps name the superblock's device,
/// which is not always the file's `st_dev`: btrfs reports a subvolume's own
/// anonymous device there (on devbig014, maps `00:2f` and `st_dev` 0:48 for
/// the same file), so the device is read from the mount's line in the tracer's
/// mountinfo, which names the superblock's.
fn mapped_file_size(object: &CensusObject) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;

    let path = object
        .path
        .as_ref()
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let wanted = libc::STATX_INO | libc::STATX_SIZE | libc::STATX_MNT_ID;
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: `path` is a NUL-terminated string and `stat` is a writable
    // `statx` buffer, both live for the call.
    if unsafe { libc::statx(libc::AT_FDCWD, path.as_ptr(), 0, wanted, stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the buffer started zeroed, and statx returned 0 having filled it.
    let stat = unsafe { stat.assume_init() };
    if stat.stx_mask & wanted != wanted {
        return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let mountinfo = crate::launch_window::read_to_string("/proc/thread-self/mountinfo")?;
    let (major, minor) = mount_device(&mountinfo, stat.stx_mnt_id)
        .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
    if (major, minor, stat.stx_ino) != object.file {
        return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
    }
    Ok(stat.stx_size)
}

/// Returns the device of the superblock of the mount numbered `mount_id`, the
/// third field of its line in `mountinfo`.
fn mount_device(mountinfo: &str, mount_id: u64) -> Option<(u64, u64)> {
    mountinfo.lines().find_map(|line| {
        let mut fields = line.split(' ');
        if fields.next()?.parse::<u64>().ok()? != mount_id {
            return None;
        }
        let (major, minor) = fields.nth(1)?.split_once(':')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    })
}

/// Builds the census of `object` from the tracee's current bytes, which
/// `memory` reads as `/proc/<pid>/mem` does.
///
/// That file reads with the kernel's FOLL_FORCE, as a debugger does, so a
/// range that the guest made PROT_NONE or execute-only after Ready is still
/// read, where `process_vm_readv` fails with EFAULT. A page that faults even
/// so makes the read fail with EIO (`mem_rw` in fs/proc/base.c), after a short
/// count if the read had copied some bytes. One cause is the guest's own: a
/// file page wholly past the end of a file that the guest truncated. Only when
/// `memory` shows that the faulting page is such a page does the census refuse
/// every site of the object with [`FAULTING_CENSUS_OBJECT`], a verdict that the
/// caller caches like any other.
///
/// Every other EIO is the outer error. The host causes those too: an I/O
/// error paging the file in, a poisoned page, an out-of-memory fault, a
/// truncation from outside the guest, or, on a kernel that does not let this
/// tracer read with FOLL_FORCE, a page that the guest made PROT_NONE. So is
/// any other failed read, such as ENOMEM, or EFAULT for the tracer's own
/// buffer. Those say nothing about the object, so the caller must neither
/// cache them nor turn them into a refusal: refusing sites because of them
/// would move the guest's schedule without any report. A read that returns no
/// bytes means the tracee's address space is gone, because `mem_rw` returns 0
/// when it holds no reference to it, so it is reported as ESRCH.
fn read_census<M: CensusMemory>(
    memory: &M,
    object: &CensusObject,
) -> Result<Result<Census, CensusError>, Errno> {
    let mut contents = Vec::with_capacity(object.ranges.len());
    for range in &object.ranges {
        let Some(len) = range
            .end
            .checked_sub(range.start)
            .and_then(|len| usize::try_from(len).ok())
        else {
            return Ok(Err(CensusError::TRUNCATED));
        };
        let mut bytes = vec![0; len];
        let mut filled = 0;
        while filled < len {
            let address = range.start + filled as u64;
            match memory.read_at(address, &mut bytes[filled..]) {
                Ok(0) => return Err(Errno::ESRCH),
                Ok(read) => filled += read,
                Err(error) => match error.raw_os_error() {
                    Some(libc::EINTR) => {}
                    Some(libc::EIO) => {
                        return if faults_past_end_of_file(memory, object, range, address)? {
                            Ok(Err(FAULTING_CENSUS_OBJECT))
                        } else {
                            Err(Errno::EIO)
                        };
                    }
                    errno => return Err(Errno::new(errno.unwrap_or(libc::EINVAL))),
                },
            }
        }
        contents.push(bytes);
    }
    let segments: Vec<Segment<'_>> = object
        .ranges
        .iter()
        .zip(&contents)
        .map(|(range, bytes)| Segment {
            address: range.start,
            bytes,
            executable: range.executable,
        })
        .collect();
    Ok(Census::build(&segments, object.header, object.text))
}

/// Whether the page of `range` that holds `address`, whose read failed with
/// EIO, lies wholly past the end of `object`'s file. A page that holds the
/// end of the file reads as the file's tail and zeros, so it does not count.
///
/// Each answer is logged at warning level, so that a refusal, or a run that
/// fails because of the read, says which page and file. The caller holds the
/// census's transient open, so the warning waits until it closes.
fn faults_past_end_of_file<M: CensusMemory>(
    memory: &M,
    object: &CensusObject,
    range: &CensusRange,
    address: u64,
) -> Result<bool, Errno> {
    let page_size = host_page_size()?;
    let page = address & !(page_size - 1);
    let offset = page
        .checked_sub(range.start)
        .and_then(|delta| range.offset.checked_add(delta))
        .ok_or(Errno::EIO)?;
    let size = match memory.file_size(object) {
        Ok(size) => size,
        Err(error) => {
            let message = format!(
                "[liteinst] the entry census read of {:?} faulted at {address:#x}, \
                 and the tracer cannot find the mapped file: {error}",
                object.path
            );
            crate::launch_window::run_after_guards(move || tracing::warn!("{message}"));
            return Err(Errno::EIO);
        }
    };
    // A mapping's file offset is a multiple of the page size, and so is
    // `offset`: the page lies wholly past the end exactly when it starts at or
    // after it.
    let past = offset >= size;
    let message = format!(
        "[liteinst] the entry census read of {:?} faulted at {address:#x}, file \
         offset {offset:#x}, which is {} the file's {size} bytes",
        object.path,
        if past { "past the end of" } else { "within" }
    );
    crate::launch_window::run_after_guards(move || tracing::warn!("{message}"));
    Ok(past)
}

/// How the tracer goes on from a site's entry census.
#[derive(Debug, Eq, PartialEq)]
enum CensusOutcome {
    /// Hand the patch helper this entry limit, which is
    /// [`REFUSED_ENTRY_LIMIT`] for a refused site.
    Install(u64),
    /// Fail the run closed, recording a LiteInst activation failure.
    Fail(Errno),
    /// The tracee is gone. The error returns along the ordinary ptrace-error
    /// path, like a failed `getregs` or `read_value` on the same stop, and is
    /// not a LiteInst activation failure.
    Gone,
}

/// Decides what the tracer does with `site` from the result of its entry
/// census, `entries`.
///
/// A refusal is a verdict about the site's object, so the site stays on
/// ptrace and the run goes on. A failure to read the tracee's code says
/// nothing about the site: refusing the site because of it would move the
/// guest's schedule without any report, so the run fails closed instead.
fn census_outcome(
    site: u64,
    entries: Result<Result<SiteEntries, Refusal>, Errno>,
) -> CensusOutcome {
    match entries {
        Ok(Ok(entries)) => CensusOutcome::Install(entries.limit),
        Ok(Err(refusal)) => {
            tracing::debug!("[liteinst] leaving syscall site {site:#x} unpatched: {refusal}");
            CensusOutcome::Install(REFUSED_ENTRY_LIMIT)
        }
        Err(Errno::ESRCH) => CensusOutcome::Gone,
        Err(errno) => CensusOutcome::Fail(errno),
    }
}

/// Returns the entries of `site` in `census`, or why the site is refused.
fn census_site_entries(
    census: &Result<Census, CensusError>,
    site: u64,
) -> Result<SiteEntries, Refusal> {
    let entries = census
        .as_ref()
        .map_err(|error| Refusal::NoCensus(*error))?
        .site(site)?;
    // The helper installs only two-byte `syscall` instructions.
    if entries.len != 2 {
        return Err(Refusal::InstructionMismatch);
    }
    Ok(entries)
}

fn read_guest_maps(pid: Pid) -> std::io::Result<Vec<GuestMap>> {
    let maps = crate::launch_window::read(format!("/proc/{pid}/maps"))?;
    Ok(maps
        .split(|byte| *byte == b'\n')
        .filter_map(parse_guest_map)
        .collect())
}

fn guest_maps(pid: Pid) -> Option<Vec<GuestMap>> {
    read_guest_maps(pid).ok()
}

fn next_proc_maps_field<'a>(line: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    while line.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
    let start = *cursor;
    while line
        .get(*cursor)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *cursor += 1;
    }
    (start < *cursor).then(|| &line[start..*cursor])
}

fn parse_guest_map(line: &[u8]) -> Option<GuestMap> {
    let mut cursor = 0;
    let range = std::str::from_utf8(next_proc_maps_field(line, &mut cursor)?).ok()?;
    let permissions = next_proc_maps_field(line, &mut cursor)?;
    let offset = std::str::from_utf8(next_proc_maps_field(line, &mut cursor)?).ok()?;
    let device = std::str::from_utf8(next_proc_maps_field(line, &mut cursor)?).ok()?;
    let inode = std::str::from_utf8(next_proc_maps_field(line, &mut cursor)?).ok()?;

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let offset = u64::from_str_radix(offset, 16).ok()?;
    let (device_major, device_minor) = device.split_once(':')?;
    let device_major = u64::from_str_radix(device_major, 16).ok()?;
    let device_minor = u64::from_str_radix(device_minor, 16).ok()?;
    let inode = inode.parse::<u64>().ok()?;

    while line.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    let path = (cursor < line.len()).then(|| decode_proc_maps_path(&line[cursor..]));
    Some(GuestMap {
        start,
        end,
        offset,
        device_major,
        device_minor,
        readable: permissions.first() == Some(&b'r'),
        writable: permissions.get(1) == Some(&b'w'),
        executable: permissions.get(2) == Some(&b'x'),
        shared: permissions.get(3) == Some(&b's'),
        inode,
        path,
    })
}

fn decode_proc_maps_path(bytes: &[u8]) -> PathBuf {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..index + 4]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
        {
            let value = u16::from(bytes[index + 1] - b'0') * 64
                + u16::from(bytes[index + 2] - b'0') * 8
                + u16::from(bytes[index + 3] - b'0');
            if let Ok(value) = u8::try_from(value) {
                decoded.push(value);
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    PathBuf::from(OsString::from_vec(decoded))
}

fn guest_auxv_entry(pid: Pid, key: u64) -> Option<u64> {
    let bytes = crate::launch_window::read(format!("/proc/{pid}/auxv")).ok()?;
    bytes.as_chunks::<16>().0.iter().find_map(|entry| {
        let entry_key = u64::from_ne_bytes(entry[..8].try_into().ok()?);
        let value = u64::from_ne_bytes(entry[8..].try_into().ok()?);
        (entry_key == key).then_some(value)
    })
}

impl InjectedSyscallTrap {
    // TODO-HUMAN-REVIEW(PR-271): Review rewritten-image load-bias and patched-site
    // collision filtering before Tool dispatch.
    #[cfg(target_arch = "x86_64")]
    fn validates_site_provenance(
        &self,
        pid: Pid,
        trap_rip: u64,
        frame: &InjectedSyscallFrame,
    ) -> bool {
        let Some(provenance) = &self.provenance else {
            return trap_rip == self.rip;
        };
        let Some(maps) = guest_maps(pid) else {
            return false;
        };
        let matches_image = |mapping: &&GuestMap| {
            mapping.inode == provenance.image_inode
                && mapping.path.as_ref() == Some(&provenance.image)
        };
        let Some(load_bias) = guest_auxv_entry(pid, libc::AT_ENTRY)
            .and_then(|entry| entry.checked_sub(provenance.image_entry_address))
        else {
            return false;
        };
        self.rip.checked_add(load_bias) == Some(trap_rip)
            && maps
                .iter()
                .filter(matches_image)
                .any(|mapping| mapping.executable && mapping.contains(trap_rip))
            && maps
                .iter()
                .filter(matches_image)
                .any(|mapping| mapping.executable && mapping.contains(frame.instruction_pointer()))
            && frame
                .instruction_pointer()
                .checked_sub(load_bias)
                .is_some_and(|address| {
                    provenance
                        .patched_site_addresses
                        .binary_search(&address)
                        .is_ok()
                })
    }
}

#[derive(Clone)]
pub(crate) struct LiteinstRuntimeConfig {
    pub(crate) preload: PathBuf,
    pub(crate) begin_marker: u64,
    pub(crate) ready_marker: u64,
    pub(crate) helper_return_marker: u64,
    pub(crate) syscall_marker: u64,
    /// RAX of the runtime's report, at the ready trap site, that its
    /// preparation failed after the begin trap.
    pub(crate) failed_marker: u64,
    pub(crate) newborn_tracees: Arc<StdMutex<HashMap<Pid, NewbornTracee>>>,
    pub(crate) held_root_stop: Arc<StdMutex<Option<HeldRootStop>>>,
    /// Records a fail-closed LiteInst refusal raised by any task.
    ///
    /// A non-root task's error cannot reach the root's cleanup guard, so
    /// without this the session could finish "successfully" after a child was
    /// released untraced. The root consults it before reporting success.
    pub(crate) session_failure: Arc<StdMutex<Option<String>>>,
    /// Wakes the root task as soon as a non-root refusal records the shared
    /// failure. The root may otherwise remain blocked in a guest wait for the
    /// refused child and never return control to the session cleanup guard.
    pub(crate) session_failure_changed: Arc<Notify>,
    /// Set once the guest has created a second task.
    ///
    /// Hook installation is single-task-only (see `maybe_install_liteinst_site`).
    pub(crate) multi_task: Arc<AtomicBool>,
    /// TID of the session's root tracee, published once the guest is spawned.
    ///
    /// The root-stop lease and its cleanup guard are owned by exactly this
    /// TID. A forked child is its own thread-group leader, so the
    /// `tid == pid` shape cannot distinguish it from the root.
    pub(crate) root_tid: Arc<StdOnceLock<Pid>>,
    pub(crate) instrumentation_stats: Option<Arc<StdMutex<LiteinstInstrumentationStats>>>,
    #[cfg(test)]
    pub(crate) fail_preinit: bool,
    /// Synthesises a fail-closed error at the new-task boundary.
    ///
    /// Production no longer refuses task creation, so the cleanup guard's
    /// whole-group reaping needs an explicit trigger that still produces a
    /// multi-task tree at the moment of failure.
    #[cfg(test)]
    pub(crate) fail_new_task: bool,
    #[cfg(test)]
    pub(crate) pause_new_task: Option<mpsc::UnboundedSender<Pid>>,
    #[cfg(test)]
    pub(crate) pause_after_new_task: bool,
    #[cfg(test)]
    pub(crate) pause_before_new_task: Option<mpsc::UnboundedSender<Pid>>,
    #[cfg(test)]
    pub(crate) fail_discovery_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) fail_after_scan_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_task_scan_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) pause_root_stop: Option<(RootStopPause, mpsc::UnboundedSender<Pid>)>,
    #[cfg(test)]
    pub(crate) pause_preinit_step: Option<(usize, mpsc::UnboundedSender<Pid>)>,
    #[cfg(test)]
    pub(crate) pause_precise_timer_step: Option<mpsc::UnboundedSender<Pid>>,
    #[cfg(test)]
    pub(crate) activate_without_handshake: bool,
    #[cfg(test)]
    pub(crate) queue_pending_signal_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_skip_signal_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_context_none_signal_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_context_signal_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_preinit_signal_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_post_exec_signal_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) force_private_stub_mutation_once: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    pub(crate) displace_newborn: Option<Arc<NewbornDisplacement>>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum RootStopPause {
    Seccomp,
    Signal(Signal),
}

/// The ownership check in `handle_new_task` at which a test makes the handler
/// hold another generation.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NewbornDisplacementStage {
    RegistrationLookup,
    IdentityStore,
    VforkTermination,
}

/// Makes `handle_new_task` hold `foreign` instead of the decoded child's
/// generation from `stage` on, for the first child that reaches `stage`.
///
/// A test cannot make the kernel reuse a TID. When it does, the entry under
/// the TID is owned by an earlier generation and the reusing child is in the
/// entry's history. This hook builds the same relation the other way round:
/// it records `foreign` in the child's entry history, where the child stays
/// the owner, and hands the handler `foreign`. The handler then holds a
/// generation the entry records but that does not own it, while the child
/// itself stays live and owned, so the session's ordinary cleanup reaps it.
#[cfg(test)]
pub(crate) struct NewbornDisplacement {
    pub(crate) stage: NewbornDisplacementStage,
    pub(crate) foreign: Running,
    pub(crate) displaced_child: StdOnceLock<Pid>,
    /// The displaced child's own generation, which the handler held until the
    /// hook handed it `foreign`.
    pub(crate) displaced_generation: StdOnceLock<safeptrace::TerminalCleanup>,
    pub(crate) outcome: mpsc::UnboundedSender<NewbornDisplacementOutcome>,
}

/// What `handle_new_task` did for the displaced child, reported as it returns.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct NewbornDisplacementOutcome {
    /// The process whose task handled the new child.
    pub(crate) parent: Pid,
    pub(crate) child: Pid,
    /// The handler's own error, before task exit reports the recorded failure
    /// in its place. `None` if it did not fail with an errno.
    pub(crate) errno: Option<Errno>,
    pub(crate) child_owns_entry: bool,
    pub(crate) child_identity_stored: bool,
    pub(crate) foreign_in_history: bool,
}

#[cfg(test)]
impl LiteinstRuntimeConfig {
    /// Returns the generation `handle_new_task` checks ownership with at
    /// `stage`: `generation`, or the displacement's foreign generation once
    /// recorded in the child's entry history.
    fn displace_newborn_generation_for_test(
        &self,
        stage: NewbornDisplacementStage,
        child_pid: Pid,
        parent_tid: Pid,
        op: ChildOp,
        generation: safeptrace::TerminalCleanup,
    ) -> safeptrace::TerminalCleanup {
        let Some(displacement) = self.displace_newborn.as_ref() else {
            return generation;
        };
        if displacement.stage != stage || displacement.displaced_child.set(child_pid).is_err() {
            return generation;
        }
        if displacement.displaced_generation.set(generation).is_err() {
            unreachable!("only the child that set displaced_child stores its generation");
        }
        NewbornTracee::register_generation_for_test(
            &self.newborn_tracees,
            child_pid,
            parent_tid,
            op,
            displacement.foreign.terminal_cleanup(),
        );
        displacement.foreign.terminal_cleanup()
    }

    fn report_newborn_displacement_for_test(
        &self,
        parent_pid: Pid,
        child_pid: Pid,
        result: &Result<Wait, TraceError>,
    ) {
        let Some(displacement) = self.displace_newborn.as_ref() else {
            return;
        };
        if displacement.displaced_child.get() != Some(&child_pid) {
            return;
        }
        let child = displacement
            .displaced_generation
            .get()
            .expect("the hook stores the displaced child's generation with its pid");
        let foreign = displacement.foreign.terminal_cleanup();
        let newborns = self.newborn_tracees.lock().unwrap();
        let entry = newborns.get(&child_pid);
        let _ = displacement.outcome.send(NewbornDisplacementOutcome {
            parent: parent_pid,
            child: child_pid,
            errno: match result {
                Err(TraceError::Errno(errno)) => Some(*errno),
                _ => None,
            },
            child_owns_entry: entry.is_some_and(|entry| entry.same_generation(child)),
            child_identity_stored: entry.is_some_and(NewbornTracee::has_identity_for_test),
            foreign_in_history: entry
                .is_some_and(|entry| entry.records_in_history_for_test(&foreign)),
        });
    }
}

#[derive(Clone)]
struct LiteinstRootStopArmer {
    root_tid: Pid,
    held_root_stop: Arc<StdMutex<Option<HeldRootStop>>>,
}

impl LiteinstRootStopArmer {
    fn arm(&self, task: &Stopped, event: &Event) -> Result<(), TraceError> {
        if task.pid() != self.root_tid {
            return Ok(());
        }
        HeldRootStop::arm_empty(&self.held_root_stop, task, event)
    }

    fn ensure(&self, task: &Stopped, event: &Event) -> Result<(), TraceError> {
        if task.pid() != self.root_tid {
            return Ok(());
        }
        HeldRootStop::ensure_current(&self.held_root_stop, task, event)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct LiteinstHandshakeFrame {
    version: u64,
    begin_rip: u64,
    ready_rip: u64,
    install_helper: u64,
    helper_stack_top: u64,
    helper_return: u64,
    helper_return_rip: u64,
    syscall_trap_rip: u64,
    syscall_trap_return_rip: u64,
    install_result: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct LiteinstInstallResult {
    version: u64,
    site_start: u64,
    site_len: u64,
    relocated_tail: u64,
    trampoline_start: u64,
    trampoline_len: u64,
    arena_writable_start: u64,
    arena_writable_len: u64,
    arena_executable_start: u64,
    arena_executable_len: u64,
    instruction_len: u64,
    straddle_prefix: u64,
    complete: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestRange {
    start: u64,
    end: u64,
}

impl GuestRange {
    fn new(start: u64, len: u64) -> Option<Self> {
        let end = start.checked_add(len)?;
        (start < end).then_some(Self { start, end })
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

fn kernel_page_range(start: u64, len: u64, page_size: u64) -> Result<Option<GuestRange>, ()> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(());
    }
    if len == 0 {
        return Ok(None);
    }

    let end = start.checked_add(len).ok_or(())?;
    let page_mask = page_size - 1;
    let start = start & !page_mask;
    let end = end.checked_add(page_mask).ok_or(())? & !page_mask;
    Ok(Some(GuestRange { start, end }))
}

fn host_page_size() -> Result<u64, Errno> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = u64::try_from(page_size).map_err(|_| Errno::EIO)?;
    page_size
        .is_power_of_two()
        .then_some(page_size)
        .ok_or(Errno::EIO)
}

fn is_liteinst_mapping_syscall(nr: Sysno) -> bool {
    // TODO-HUMAN-REVIEW(PR-270): Review pkey_mprotect mapping-lifecycle classification.
    matches!(
        nr,
        // AUTONOMOUS-BOT-IMPLEMENTED
        Sysno::mmap | Sysno::munmap | Sysno::mremap | Sysno::mprotect | Sysno::pkey_mprotect
    )
}

/// Syscalls whose return lands in two tasks at once.
///
/// The kernel starts the new task at the instruction following the `syscall`,
/// so the site must still decode as the original instruction stream there.
fn is_task_creating_syscall(nr: Sysno) -> bool {
    match nr {
        Sysno::clone | Sysno::clone3 => true,
        #[cfg(target_arch = "x86_64")]
        Sysno::fork | Sysno::vfork => true,
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveHookFootprint {
    site: GuestRange,
    trampoline: GuestRange,
    arena_writable: GuestRange,
    arena_executable: GuestRange,
}

impl ActiveHookFootprint {
    fn protected_ranges(&self) -> [(GuestRange, i32); 4] {
        [
            (self.site, libc::PROT_READ | libc::PROT_EXEC),
            (self.trampoline, libc::PROT_READ | libc::PROT_EXEC),
            (self.arena_writable, libc::PROT_READ | libc::PROT_WRITE),
            (self.arena_executable, libc::PROT_READ | libc::PROT_EXEC),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiteinstRuntimePhase {
    PreExec,
    Waiting,
    /// Between the validated begin trap and the matching ready or failed
    /// report of this execution generation.
    Bootstrap,
    Ready,
    /// The runtime reported that its preparation failed after the begin trap.
    /// Terminal for this execution generation: nothing leaves it, so every
    /// exit, exec, signal, or executable-entry arrival fails closed exactly
    /// as it does before Ready.
    Failed,
}

#[derive(Clone, Debug)]
struct LiteinstRuntimeState {
    phase: LiteinstRuntimePhase,
    frame: Option<LiteinstHandshakeFrame>,
    /// The thread that executed the begin trap and so runs the runtime's
    /// bootstrap. Another thread of the same process, or a process forked
    /// from it, keeps running guest code while the phase is `Bootstrap`.
    /// Set only on entry to `Bootstrap` and cleared on every exit from it
    /// (Ready, Failed, and the exec reset), so it is `Some` exactly while the
    /// phase is `Bootstrap`.
    bootstrap_tid: Option<Pid>,
    generation: u64,
    ready_generation: Option<u64>,
    attempted_sites: HashSet<u64>,
    fallback_sites: HashMap<u64, LiteinstPatchOutcome>,
    active_hooks: HashMap<u64, ActiveHookFootprint>,
    /// The readable file-backed mappings when the runtime became Ready. The
    /// tracer builds an object's entry census from these mappings at the first
    /// site attempt in its code
    /// (<https://github.com/rrnewton/reverie/issues/812>). A later mapping
    /// change that touches any mapping of an object removes the whole object,
    /// and nothing adds it back, so no census is built from text that a
    /// `syscall` patch has already changed.
    census_maps: Arc<[GuestMap]>,
    /// Entry censuses by the start of their text mapping.
    censuses: HashMap<u64, Arc<Result<Census, CensusError>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiteinstEntryGuard {
    address: u64,
    saved_instruction: u64,
}

impl Default for LiteinstRuntimeState {
    fn default() -> Self {
        Self {
            phase: LiteinstRuntimePhase::PreExec,
            frame: None,
            bootstrap_tid: None,
            generation: 0,
            ready_generation: None,
            attempted_sites: HashSet::new(),
            fallback_sites: HashMap::new(),
            active_hooks: HashMap::new(),
            census_maps: Vec::new().into(),
            censuses: HashMap::new(),
        }
    }
}

impl LiteinstRuntimeState {
    fn after_exec(&self) -> Result<Self, Errno> {
        Ok(Self {
            phase: LiteinstRuntimePhase::Waiting,
            generation: self.generation.checked_add(1).ok_or(Errno::EOVERFLOW)?,
            ..Self::default()
        })
    }

    fn mapping_mutates_active_hook(&self, nr: Sysno, args: SyscallArgs, page_size: u64) -> bool {
        let operation_range = match nr {
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::mmap if args.arg3 as i32 & libc::MAP_FIXED != 0 => {
                kernel_page_range(args.arg0 as u64, args.arg1 as u64, page_size)
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::munmap | Sysno::mprotect | Sysno::pkey_mprotect | Sysno::mremap => {
                kernel_page_range(args.arg0 as u64, args.arg1 as u64, page_size)
            }
            _ => return false,
        };
        let requested_protection = match nr {
            Sysno::mprotect => Some(args.arg2 as i32),
            Sysno::pkey_mprotect if args.arg3 == 0 => Some(args.arg2 as i32),
            _ => None,
        };
        let source_mutates_active_hook = match operation_range {
            Ok(Some(operation_range)) => self.active_hooks.values().any(|hook| {
                hook.protected_ranges()
                    .into_iter()
                    .any(|(range, protection)| {
                        range.overlaps(operation_range) && requested_protection != Some(protection)
                    })
            }),
            Ok(None) => false,
            Err(()) => !self.active_hooks.is_empty(),
        };
        if source_mutates_active_hook {
            return true;
        }
        if nr == Sysno::mremap && args.arg3 as i32 & libc::MREMAP_FIXED != 0 {
            let destination = match kernel_page_range(args.arg4 as u64, args.arg2 as u64, page_size)
            {
                Ok(Some(range)) => range,
                Ok(None) => return false,
                Err(()) => return !self.active_hooks.is_empty(),
            };
            return self.active_hooks.values().any(|hook| {
                hook.protected_ranges()
                    .into_iter()
                    .any(|(range, _)| range.overlaps(destination))
            });
        }
        false
    }

    /// Enters Ready with the census snapshot taken from `maps`; see
    /// [`Self::census_maps`].
    fn enter_ready(&mut self, maps: Vec<GuestMap>) {
        self.phase = LiteinstRuntimePhase::Ready;
        self.ready_generation = Some(self.generation);
        self.bootstrap_tid = None;
        self.census_maps = maps
            .into_iter()
            .filter(|map| map.readable && map.inode != 0)
            .collect();
        self.censuses.clear();
    }

    /// Removes every object with a mapping in the pages that `start` and `len`
    /// name, and its census.
    fn forget_census_objects(&mut self, start: u64, len: u64, page_size: u64) {
        let range = match kernel_page_range(start, len, page_size) {
            Ok(Some(range)) if range.start < range.end => range,
            Ok(None) => return,
            _ => {
                self.forget_all_census_objects();
                return;
            }
        };
        let touched: HashSet<(u64, u64, u64)> = self
            .census_maps
            .iter()
            .filter(|map| {
                GuestRange {
                    start: map.start,
                    end: map.end,
                }
                .overlaps(range)
            })
            .map(GuestMap::file)
            .collect();
        if touched.is_empty() {
            return;
        }
        self.census_maps = self
            .census_maps
            .iter()
            .filter(|map| !touched.contains(&map.file()))
            .cloned()
            .collect();
        let maps = &self.census_maps;
        self.censuses
            .retain(|text, _| maps.iter().any(|map| map.executable && map.start == *text));
    }

    fn forget_all_census_objects(&mut self) {
        self.census_maps = Vec::new().into();
        self.censuses.clear();
    }

    fn invalidate_attempted_pages(&mut self, start: u64, len: u64, page_size: u64) {
        let range = match kernel_page_range(start, len, page_size) {
            Ok(Some(range)) => range,
            Ok(None) => return,
            Err(()) => {
                self.attempted_sites.clear();
                self.fallback_sites.clear();
                return;
            }
        };
        if range.start >= range.end {
            self.attempted_sites.clear();
            self.fallback_sites.clear();
            return;
        }
        self.attempted_sites
            .retain(|address| !(*address >= range.start && *address < range.end));
        self.fallback_sites
            .retain(|address, _| !(*address >= range.start && *address < range.end));
    }
}

fn callback_owner_decision(
    held: crate::PtraceCallbackStop,
    sample: &safeptrace::StopObservationSample,
) -> Result<bool, crate::PtraceCallbackRefusal> {
    callback_observation_decision(
        held,
        sample.refusal(),
        sample.siginfo(),
        sample.flags(),
        sample.pidfd_live(),
    )
}

// Keep the observed fields separate from physical ownership. The private seam
// also lets refusal tests supply exact failures without inventing kernel events.
fn callback_observation_decision(
    held: crate::PtraceCallbackStop,
    refusal: Option<safeptrace::StopObservationError>,
    siginfo: Option<Result<safeptrace::StopSiginfo, Errno>>,
    flags: Option<&Result<u32, safeptrace::ProcStatError>>,
    pidfd_live: Option<Result<bool, Errno>>,
) -> Result<bool, crate::PtraceCallbackRefusal> {
    use crate::PtraceCallbackRefusal as Refusal;
    use crate::PtraceCallbackStop as Stop;
    if let Some(error) = refusal {
        return Err(Refusal::Binding(error));
    }
    let info = siginfo.ok_or(Refusal::Inconsistent("missing siginfo query"))?;
    if let Err(error) = info
        && error != Errno::ESRCH
    {
        return Err(Refusal::Query(error));
    }
    let live = pidfd_live
        .ok_or(Refusal::Inconsistent("missing final pidfd query"))?
        .map_err(Refusal::Pidfd)?;
    if let Some(Err(error)) = flags {
        if !live
            && matches!(
                error,
                safeptrace::ProcStatError::Io(Errno::ESRCH | Errno::ENOENT)
            )
        {
            return Ok(true);
        }
        return Err(Refusal::Proc(error.clone()));
    }
    if !live || info == Err(Errno::ESRCH) {
        return Ok(true);
    }
    let info = info.map_err(Refusal::Query)?;
    if held == Stop::Stop {
        return Err(Refusal::Inconsistent("unexpected group-stop class"));
    }
    if info.has_exit_signature() {
        if held != Stop::Signal(libc::SIGTRAP) {
            return Ok(true);
        }
        let flags = flags
            .ok_or(Refusal::Inconsistent("missing ambiguous EXIT flags"))?
            .as_ref()
            .map_err(|error| Refusal::Proc(error.clone()))?;
        // PF_SIGNALED precedes EXIT for killed/zapped ordinary user tasks.
        // It permits waiting on the original owner, never terminal inference.
        return Ok(flags & 0x400 != 0);
    }
    let matches = match held {
        Stop::Signal(signal) => info.signo == signal,
        Stop::Event(event) => {
            info.signo == libc::SIGTRAP && info.code == (event << 8) | libc::SIGTRAP
        }
        Stop::Syscall => info.signo == libc::SIGTRAP && info.code == libc::SIGTRAP | 0x80,
        Stop::Stop => false,
    };
    if matches {
        Ok(false)
    } else {
        Err(Refusal::Inconsistent(
            "siginfo disagrees with held stop class",
        ))
    }
}

/// A host-hybrid syscall restart in flight: the controller was rewound to the
/// runtime `int3` and will re-trap there (see `restart_liteinst_syscall`).
///
/// A thread keeps these on a stack, innermost last. A signal handler delivered
/// while one is pending can itself make host-hybrid syscalls that restart, so
/// the stack relies on how handlers leave:
///
/// - A handler that returns through `rt_sigreturn` restores the registers it
///   was delivered with. The controller then re-traps at its rewound `int3`,
///   or reaches the landing with the stack pointer it was armed with, so
///   `controller_rsp` names the restart it resolves even when restarts nested
///   inside the handler were abandoned.
/// - A handler left by `siglongjmp` abandons its restarts. They stay below
///   the top until an enclosing restart's re-trap or landing drops everything
///   above it, or a new restart at the same controller stack pointer
///   replaces them, and `LITEINST_PENDING_RESTART_LIMIT` bounds them
///   meanwhile (see `push_liteinst_pending_restart`).
/// - A handler that edits its `ucontext` edits the runtime's trap context, not
///   the guest's syscall registers. At an armed landing only `rax` keeps its
///   plain-ptrace meaning (the result, or the number of the syscall to
///   restart) and is applied; any other register edit fails closed
///   (`changed_landing_register`). A handler that moves `rip` never reaches
///   the landing, so its restart is abandoned as by `siglongjmp`.
///
/// A fork child inherits the parent's stack with the address space it
/// resolves (`inherited_liteinst_restarts`); a thread starts with none.
#[derive(Clone, Copy, Debug)]
// Only the x86_64 host-hybrid path pushes an entry.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
struct LiteinstPendingRestart {
    /// Address of the runtime `int3` the controller was rewound to.
    restart_rip: u64,
    /// The trap's injected frame and controller stack pointer, which tie the
    /// re-trap to this site.
    frame_address: usize,
    controller_rsp: u64,
    /// The restart code that decides a signal delivered before the re-trap.
    /// Once the outcome is fixed (the syscall never ran, or the kernel already
    /// chose to restart), this is `ERESTARTNOINTR`: a signal delivered before
    /// a syscall is entered never interrupts it.
    errno: Errno,
    /// The rewound controller registers while the kernel decides the restart
    /// at the private-page landing (`landing_regs`).
    landing: Option<libc::user_regs_struct>,
}

impl LiteinstPendingRestart {
    /// Whether a runtime `int3` trap is this restart's re-trap.
    ///
    /// The runtime `int3` is shared by every site and a frame address repeats
    /// at the same call depth, so an entry abandoned by `siglongjmp` matches a
    /// later trap made at exactly its stack depth. Such a trap is then served
    /// as a re-trap: the site's hook entry is not counted in the
    /// instrumentation statistics, and the entries above it are dropped. A
    /// dropped entry that was still armed makes its landing fail closed
    /// (`finish_liteinst_restart_landing`); the syscall itself is dispatched
    /// the same either way.
    #[cfg(target_arch = "x86_64")]
    fn is_retrap(&self, restart_rip: u64, frame_address: usize, rsp: u64) -> bool {
        self.landing.is_none()
            && self.restart_rip == restart_rip
            && self.frame_address == frame_address
            && self.controller_rsp == rsp
    }
}

/// Deepest nesting of pending host-hybrid restarts kept per thread; see
/// `push_liteinst_pending_restart`.
#[cfg(target_arch = "x86_64")]
const LITEINST_PENDING_RESTART_LIMIT: usize = 64;

/// The private-page landing address (see `liteinst_restart::landing_regs`).
const fn liteinst_landing() -> u64 {
    (cp::PRIVATE_PAGE_OFFSET + LANDING_OFFSET) as u64
}

/// Whether a host-hybrid syscall's trap stop decided the timer event
/// (`TracedTask::restart_liteinst_syscall`).
#[cfg(target_arch = "x86_64")]
enum TrapTimer {
    /// The Tool observed the trap, which decided the event.
    Decided,
    /// The trap was disregarded (`Timer::disregard_stop`) and left this of
    /// the event to finish.
    Disregarded(Option<Unfinished>),
}

/// Why a restart landing trap could not be resolved
/// (`TracedTask::resolve_liteinst_landing`).
enum LandingFailure {
    /// The trap contradicts the pending restarts; the caller fails closed
    /// with this message.
    Invariant(String),
    Trace(TraceError),
}

impl From<TraceError> for LandingFailure {
    fn from(error: TraceError) -> Self {
        Self::Trace(error)
    }
}

#[cfg(target_arch = "x86_64")]
fn read_injected_frame(task: &Stopped, address: usize) -> Result<InjectedSyscallFrame, TraceError> {
    let address = Addr::from_raw(address).ok_or(Errno::EFAULT)?;
    Ok(task.read_value(address)?)
}

#[cfg(target_arch = "x86_64")]
fn write_injected_frame(
    task: &Stopped,
    address: usize,
    frame: &InjectedSyscallFrame,
) -> Result<(), TraceError> {
    let address = AddrMut::from_raw(address).ok_or(Errno::EFAULT)?;
    let mut task = task.generation().assume_stopped();
    Ok(task.write_value(address, frame)?)
}

enum LiteinstTrap {
    HandshakeBegin,
    HandshakeReady,
    HandshakeFailed,
    #[cfg(target_arch = "x86_64")]
    Syscall(usize),
    Invalid,
}

/// The first ordinary-ptrace fatal error cancels every followed task. Keep the
/// actual error until the entire tree has completed its real terminal waits.
#[derive(Default)]
pub(crate) struct FatalSession {
    ptracer_thread: Option<std::thread::ThreadId>,
    ptracer_controller: StdMutex<Option<PtracerController>>,
    callback_diagnostics: StdMutex<Vec<crate::PtraceCallbackDiagnostic>>,
    backend_signalling: AtomicBool,
    failure: StdMutex<Option<PtraceRunFailure>>,
    published: AtomicBool,
    reporter: Option<Box<dyn Fn(BackendFailure) -> bool + Send + Sync>>,
    closed: AtomicBool,
    root: Option<Pid>,
    changed: Notify,
    tree: StdMutex<FatalTree>,
    joins: StdMutex<Vec<JoinHandle<()>>>,
    retry_epoch: AtomicUsize,
    retry_changed: Notify,
    groups: StdMutex<Vec<Arc<FatalGroup>>>,
    cleanup_deadline: StdMutex<Option<std::time::Instant>>,
    #[cfg(test)]
    pub(crate) observed_child_ops: StdMutex<Vec<(Pid, ChildOp, Pid)>>,
}

#[derive(Debug, thiserror::Error)]
#[error("original global Tool owner was unavailable for synchronous failure publication")]
struct GlobalFailurePublicationLost;

/// The replaced leader of a lost former has no exit-stop status to report:
/// its leader owner's terminal path left that exit stop before GETEVENTMSG
/// read it, or did not enter holding it. No status is fabricated.
#[derive(Debug, thiserror::Error)]
#[error(
    "replaced leader {leader} of lost former {former} has no read exit-stop status ({entry:?}); its Tool thread state gets no on_exit_thread"
)]
struct ReplacedLeaderStatusUnavailable {
    leader: Pid,
    former: Pid,
    entry: crate::tracer::EntryExitStop,
}

struct FatalGroup {
    terminal: safeptrace::TerminalCleanup,
    identity: crate::tracer::TraceeIdentity,
}

/// Only subscribe_group constructs this after successful same-generation capture.
/// Weak expiry therefore means that this session completed that owner, rather
/// than that an unknown or failed capture may be treated as retired.
pub(crate) struct OrdinaryGroupSubscription {
    session: std::sync::Weak<FatalSession>,
    group: std::sync::Weak<FatalGroup>,
}

#[derive(Default)]
struct FatalTree {
    tasks: Vec<Arc<FatalTaskStop>>,
    newborns: Vec<FatalNewborn>,
    // Retained across initialization: a handed vfork child can still block its parent.
    vfork_children: Vec<Arc<safeptrace::TerminalCleanup>>,
    unconfirmed_newborns: Vec<(Pid, Arc<safeptrace::TerminalCleanup>)>,
    killing: bool,
    cleanup_refusal: Option<String>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct FatalForkPause {
    pub(crate) ready: Notify,
    pub(crate) child: StdMutex<Option<Running>>,
    pub(crate) waiting_word: std::sync::atomic::AtomicUsize,
    pub(crate) generation: StdMutex<Option<(u64, u64)>>,
    pub(crate) terminal_status: StdMutex<Option<(Pid, ExitStatus)>>,
    pub(crate) live_stop_opponent: AtomicBool,
    /// Selects the timer-decoded fork control: the fork is decoded by a
    /// precise-timer single step, and the run loop's receive of the aborted
    /// stop is held so a sibling failure cancels the loop first.
    pub(crate) timer: bool,
    pub(crate) timer_parent: std::sync::atomic::AtomicI32,
    pub(crate) timer_child: StdMutex<Option<FatalTimerChild>>,
    pub(crate) timer_published: AtomicBool,
    pub(crate) timer_receive_blocked: AtomicBool,
}

/// The actual child a timer step decoded, retained only for test assertions.
/// It carries no cleanup ownership of its own.
#[cfg(test)]
pub(crate) struct FatalTimerChild {
    pub(crate) pid: Pid,
    pub(crate) start_time: u64,
    pub(crate) proc_inode: u64,
    pub(crate) terminal: Arc<safeptrace::TerminalCleanup>,
}

#[cfg(test)]
fn record_timer_decoded_fork_for_test(task: &Stopped, event: &Event) {
    let Event::NewChild(ChildOp::Fork, child) = event else {
        return;
    };
    let Some(pause) = FATAL_FORK_PAUSE
        .with(|slot| slot.borrow().clone())
        .filter(|pause| pause.timer)
    else {
        return;
    };
    use std::os::unix::fs::MetadataExt;
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.pid())).unwrap();
    let start = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let inode = std::fs::metadata(format!("/proc/{}", child.pid()))
        .unwrap()
        .ino();
    pause
        .timer_parent
        .store(task.pid().as_raw(), Ordering::SeqCst);
    *pause.timer_child.lock().unwrap() = Some(FatalTimerChild {
        pid: child.pid(),
        start_time: start,
        proc_inode: inode,
        terminal: Arc::new(child.terminal_cleanup()),
    });
    eprintln!(
        "timer decoded actual fork: parent={}, child={}, start={start}, inode={inode}",
        task.pid(),
        child.pid()
    );
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct FatalSetupControl {
    pub(crate) child: StdMutex<Option<(Pid, Arc<safeptrace::TerminalCleanup>)>>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct FatalFreezeControl {
    pub(crate) calls: std::sync::atomic::AtomicUsize,
    pub(crate) session: StdMutex<Option<Arc<FatalSession>>>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ExecTimerTransfer {
    pub displaced: Option<crate::timer::ExecTimerIdentity>,
    pub before: Option<crate::timer::ExecTimerIdentity>,
    pub after: Option<crate::timer::ExecTimerIdentity>,
    pub displaced_fds_closed: bool,
}
#[cfg(test)]
thread_local! {
    pub(crate) static EXEC_TIMER_TRANSFERS: std::cell::RefCell<Option<Arc<StdMutex<Vec<ExecTimerTransfer>>>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Forces the order a loaded tracer thread produces by chance: a nonleader
    /// thread's run loop observes its own TID vanish in a non-leader execve
    /// before `drive_ordinary` polls that thread's exit future again. Every
    /// nonleader `drive_ordinary` on this thread leaves its exit future
    /// unpolled for the duration of its run-loop race; the leader is
    /// unaffected.
    pub(crate) static NONLEADER_RUN_LOOP_OBSERVES_ECHILD_FIRST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// The wait operation of every own-TID ECHILD for which a nonleader's run
    /// loop stayed pending, in order. Tests read it to prove that a pass went
    /// through that branch rather than through the exit future or an earlier
    /// Exec transfer.
    pub(crate) static NONLEADER_RUN_LOOP_ECHILD_PENDED: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Holds the leader's run loop between its post-clone single step and the
/// wait for that step, so the step stop stays queued while a nonleader exec's
/// zap moves the leader into its exit stop. This is the ordering behind
/// https://github.com/rrnewton/reverie/issues/686, which a loaded tracer
/// thread produces by chance. The hold fabricates no status: it only observes
/// the notifier FIFO and the exit publication, then leaves the run loop
/// pending so the exit future wins in `drive_ordinary`.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct LeaderStepExitHold {
    /// Armed by the test; the first leader post-clone step disarms it.
    pub(crate) armed: AtomicBool,
    /// The decoded FIFO front after the step, before any consumer.
    pub(crate) queued_step: StdMutex<Option<String>>,
    /// Whether that front decoded as a SIGTRAP signal stop.
    pub(crate) queued_step_is_trap: AtomicBool,
    /// Whether the leader's exit stop had been published when the held run
    /// loop was dropped.
    pub(crate) exit_published: AtomicBool,
    /// The held leader's notifier generation, for diagnostics readback.
    pub(crate) terminal: StdMutex<Option<safeptrace::TerminalCleanup>>,
    /// When nonzero, the address of a word shared with the forked guest. The
    /// hold then single-steps the leader once more, so a second real step
    /// stop is queued behind the first, and stores 1 into that word once the
    /// notifier holds both. The guest's exec'ing thread waits for the word.
    pub(crate) second_step_release: AtomicUsize,
    /// The result of that second real single step.
    pub(crate) second_step: StdMutex<Option<String>>,
    /// The raw statuses queued for the leader when the word was released.
    pub(crate) queued_statuses: StdMutex<Vec<i32>>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static LEADER_STEP_EXIT_HOLD: std::cell::RefCell<Option<Arc<LeaderStepExitHold>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
async fn hold_leader_step_until_exit(hold: Arc<LeaderStepExitHold>, running: &Running) {
    let terminal = running.terminal_cleanup();
    let mut cleanup = running.terminal_cleanup_on_ptracer_thread().into_driver();
    // The step stop is a real kernel report that the notifier queues. Observe
    // it without consuming it: dropping the reservation rolls it back in
    // place. It must be dropped before waiting, because publishing the exit
    // stop takes the same status lock.
    if let Some(pending) = cleanup
        .reserve_pending_on_ptracer_thread(std::time::Duration::from_secs(2))
        .expect("actual held-step owner")
    {
        let decoded = match pending.decode() {
            Ok(Wait::Stopped(_, event)) => format!("Stopped({event:?})"),
            Ok(Wait::Exited(_, status)) => format!("Exited({status:?})"),
            Err(error) => format!("Err({error:?})"),
        };
        let is_trap = decoded == format!("Stopped({:?})", Event::Signal(Signal::SIGTRAP));
        drop(pending);
        hold.queued_step_is_trap.store(is_trap, Ordering::SeqCst);
        *hold.queued_step.lock().unwrap() = Some(decoded);
    }
    let release = hold.second_step_release.load(Ordering::SeqCst);
    if release != 0 {
        // The leader is still in the real stop whose report is queued above.
        // One more real single step leaves a second stale report behind it.
        // The capability is unmarked: it names no exit stop and retires
        // nothing.
        let step = running
            .generation()
            .assume_stopped()
            .step(None)
            .map(drop)
            .map_err(|error| format!("{error:?}"));
        *hold.second_step.lock().unwrap() = Some(format!("{step:?}"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut queued = terminal.queued_raw_statuses();
        while step.is_ok() && queued.len() < 2 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            cleanup
                .progress_on_ptracer_thread()
                .expect("actual second-step owner");
            queued = terminal.queued_raw_statuses();
        }
        *hold.queued_statuses.lock().unwrap() = queued;
        // Release the guest's exec whatever was observed; the test asserts
        // the readback.
        unsafe { &*(release as *const AtomicUsize) }.store(1, Ordering::SeqCst);
    }
    // The hold ends only when `drive_ordinary` drops the run loop, normally
    // because the exit future won. Record what was true at that moment.
    struct Release(Arc<LeaderStepExitHold>, Option<safeptrace::TerminalCleanup>);
    impl Drop for Release {
        fn drop(&mut self) {
            let terminal = self.1.take().expect("held generation");
            self.0
                .exit_published
                .store(terminal.exit_stop_observed(), Ordering::SeqCst);
            *self.0.terminal.lock().unwrap() = Some(terminal);
        }
    }
    let _release = Release(hold, Some(terminal));
    future::pending::<()>().await;
}

#[cfg(test)]
thread_local! {
    pub(crate) static FATAL_FORK_PAUSE: std::cell::RefCell<Option<Arc<FatalForkPause>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static FATAL_SETUP_CONTROL: std::cell::RefCell<Option<Arc<FatalSetupControl>>> = const { std::cell::RefCell::new(None) };
    pub(crate) static FATAL_FREEZE_CONTROL: std::cell::RefCell<Option<Arc<FatalFreezeControl>>> = const { std::cell::RefCell::new(None) };
}

impl FatalSession {
    pub(crate) fn bind_controller(&self, waits: &PtracerWaitOwner) {
        let mut controller = self.ptracer_controller.lock().unwrap();
        match controller.as_ref() {
            Some(controller) => controller.retain_from(&waits.controller()),
            None => *controller = Some(waits.controller()),
        }
    }

    pub(crate) fn capture(&self, parent: Pid, op: ChildOp, child: &Running) {
        let mut tree = self.tree.lock().unwrap();
        let terminal = child.generation().terminal_cleanup();
        if tree
            .newborns
            .iter()
            .any(|entry| entry.terminal.same_generation(&terminal))
            || tree
                .tasks
                .iter()
                .any(|entry| entry.terminal.same_generation(&terminal))
        {
            return;
        }
        if op == ChildOp::Vfork {
            tree.vfork_children
                .push(Arc::new(child.generation().terminal_cleanup()));
        }
        #[cfg(test)]
        self.observed_child_ops
            .lock()
            .unwrap()
            .push((parent, op, child.pid()));
        // Store the original receiver before any fallible group capture.
        // Keep the session's original host anchor. The child still owns its
        // own generation, mode, FIFO and exit epoch. An unset inherited cell
        // refuses progress; it cannot mint whichever sibling called capture.
        let controller = self
            .ptracer_controller
            .lock()
            .unwrap()
            .get_or_insert_with(PtracerController::default)
            .clone();
        tree.newborns
            .push(FatalNewborn::with_controller(parent, child, controller));
        drop(tree);
        match crate::tracer::TraceeIdentity::capture_event_child(child.pid(), parent, op) {
            Ok(identity) => self
                .groups
                .lock()
                .unwrap()
                .push(Arc::new(FatalGroup { terminal, identity })),
            Err(error) => self.fail_at(
                BackendFailure {
                    pid: parent,
                    tid: child.pid(),
                    phase: "ptrace child group capture",
                },
                error.into(),
            ),
        }
    }

    pub(crate) fn capture_root(&self, stopped: &Stopped) {
        let root = stopped.pid();
        if self.ptracer_controller.lock().unwrap().is_none() {
            let waits = PtracerWaitOwner::default();
            waits.bind_stopped(stopped);
            if let Err(error) = waits.prime_controller() {
                self.fail_at(
                    BackendFailure {
                        pid: root,
                        tid: root,
                        phase: "ptrace root controller capture",
                    },
                    error.into(),
                );
                return;
            }
            self.bind_controller(&waits);
        }
        match crate::tracer::TraceeIdentity::open_root(root) {
            Ok(identity) => self.groups.lock().unwrap().push(Arc::new(FatalGroup {
                terminal: stopped.generation().terminal_cleanup(),
                identity,
            })),
            Err(error) => self.fail_at(
                BackendFailure {
                    pid: root,
                    tid: root,
                    phase: "ptrace root group capture",
                },
                error.into(),
            ),
        }
    }

    pub(crate) fn signal_groups(&self) -> Vec<Errno> {
        self.groups
            .lock()
            .unwrap()
            .iter()
            .filter_map(|group| {
                group
                    .identity
                    .signal_owned_group()
                    .err()
                    .filter(|error| *error != Errno::ESRCH)
            })
            .collect()
    }

    /// Requests an old-kernel cleanup stop through already captured regular
    /// group pidfds. Shared SIGSTOPs can coalesce; only the original task
    /// owners' actual stops/terminal observations acknowledge freezing.
    pub(crate) fn request_legacy_group_sigstop(&self) -> Result<(), Errno> {
        let groups = self.groups.lock().unwrap();
        let mut captured = false;
        let mut retired = false;
        let mut first_error = None;
        for group in groups.iter() {
            #[cfg(test)]
            let repetitions = crate::tracer::group_stop_request_repetitions_for_test();
            #[cfg(not(test))]
            let repetitions = 1;
            for _ in 0..repetitions {
                let Some(result) = group.identity.request_legacy_group_sigstop() else {
                    continue;
                };
                #[cfg(test)]
                crate::tracer::record_group_stop_request_for_test();
                captured = true;
                match result {
                    Err(Errno::ESRCH) => retired = true,
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    _ => {}
                }
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else if retired {
            Err(Errno::ESRCH)
        } else if captured {
            Ok(())
        } else {
            Err(Errno::ENODATA)
        }
    }

    fn handed(&self, child: Pid) {
        let mut tree = self.tree.lock().unwrap();
        tree.newborns
            .iter_mut()
            .find(|entry| entry.tid == child)
            .expect("child handoff requires retained kernel edge")
            .handed = true;
    }

    fn newborn_exited(&self, child: Pid) {
        self.tree
            .lock()
            .unwrap()
            .newborns
            .retain(|entry| entry.tid != child);
        self.changed.notify_waiters();
    }

    fn refuse_cleanup(&self, error: reverie::Error) -> reverie::Error {
        let message = error.to_string();
        self.fail(error);
        self.tree
            .lock()
            .unwrap()
            .cleanup_refusal
            .get_or_insert(message.clone());
        // Retain every unconfirmed task/newborn authority. Refusal releases
        // other barrier waiters, but never marks those tracees as completed.
        self.changed.notify_waiters();
        anyhow::anyhow!("fatal ptrace cleanup refused: {message}").into()
    }

    #[cfg(test)]
    pub(crate) fn unconfirmed_task_count(&self) -> usize {
        self.tree.lock().unwrap().tasks.len()
    }

    #[cfg(test)]
    pub(crate) fn retained_group_counts_for_test(&self) -> (usize, usize, usize) {
        let tree = self.tree.lock().unwrap();
        (
            self.groups.lock().unwrap().len(),
            tree.vfork_children.len(),
            tree.unconfirmed_newborns.len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn cleanup_was_refused(&self) -> bool {
        self.tree.lock().unwrap().cleanup_refusal.is_some()
    }

    /// A session with a root owner on this ptracer thread and no Tool to
    /// report a failure to, for tests that drive one cleanup owner directly.
    #[cfg(test)]
    pub(crate) fn for_test(root: Pid) -> Self {
        Self {
            root: Some(root),
            ptracer_thread: Some(std::thread::current().id()),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn capture_for_group_stop_test(&self, parent: Pid, op: ChildOp, child: &Running) {
        self.capture(parent, op, child);
    }

    #[cfg(test)]
    pub(crate) fn take_group_stop_newborn_for_test(
        &self,
        terminal: &safeptrace::TerminalCleanup,
    ) -> Option<FatalNewborn> {
        let mut tree = self.tree.lock().unwrap();
        let index = tree
            .newborns
            .iter()
            .position(|child| child.terminal.same_generation(terminal))?;
        Some(tree.newborns.remove(index))
    }

    fn register(&self, task: Arc<FatalTaskStop>) -> Option<FatalNewborn> {
        self.bind_controller(&task.waits);
        #[cfg(test)]
        crate::tracer::record_fatal_task_for_test(&task);
        let mut tree = self.tree.lock().unwrap();
        let newborn = tree
            .newborns
            .iter()
            .position(|entry| {
                entry.tid == task.tid && entry.terminal.same_generation(&task.terminal)
            })
            .map(|index| tree.newborns.remove(index));
        assert!(
            !tree
                .tasks
                .iter()
                .any(|entry| entry.terminal.same_generation(&task.terminal))
        );
        if let Some(newborn) = &newborn {
            task.waits.inherit(newborn.waits.clone());
        }
        tree.tasks.push(task);
        self.changed.notify_waiters();
        newborn
    }

    fn finished(&self, stop: &FatalTaskStop) {
        let mut tree = self.tree.lock().unwrap();
        tree.tasks
            .retain(|task| !task.terminal.same_generation(&stop.terminal));
        tree.vfork_children
            .retain(|child| !child.same_generation(&stop.terminal));
        drop(tree);
        // Initialized leaders reach this only after child-thread joins and
        // consuming hooks. In particular, retain the regular group pidfd while
        // an exited leader still owns live daemon siblings.
        self.groups
            .lock()
            .unwrap()
            .retain(|group| !group.terminal.same_generation(&stop.terminal));
        #[cfg(test)]
        crate::tracer::record_capacity_finished_for_test(stop);
        self.changed.notify_waiters();
    }

    pub(crate) fn finished_unhanded(&self, terminal: &safeptrace::TerminalCleanup) {
        // Called by the sole newborn owner only after its actual final status
        // and worker retirement. A refusal/Pending keeps all these authorities.
        let mut tree = self.tree.lock().unwrap();
        tree.unconfirmed_newborns
            .retain(|(_, entry)| !entry.same_generation(terminal));
        tree.vfork_children
            .retain(|entry| !entry.same_generation(terminal));
        drop(tree);
        self.groups
            .lock()
            .unwrap()
            .retain(|group| !group.terminal.same_generation(terminal));
        self.changed.notify_waiters();
    }

    pub(crate) fn subscribe_group(
        self: &Arc<Self>,
        terminal: &safeptrace::TerminalCleanup,
    ) -> Result<OrdinaryGroupSubscription, Errno> {
        let groups = self.groups.lock().unwrap();
        let group = groups
            .iter()
            .find(|group| group.terminal.same_generation(terminal))
            .ok_or(Errno::ESTALE)?;
        Ok(OrdinaryGroupSubscription {
            session: Arc::downgrade(self),
            group: Arc::downgrade(group),
        })
    }

    pub(crate) fn signal_subscribed_group(
        self: &Arc<Self>,
        subscription: &OrdinaryGroupSubscription,
    ) -> Result<(), Errno> {
        if !std::sync::Weak::ptr_eq(&subscription.session, &Arc::downgrade(self)) {
            return Err(Errno::ESTALE);
        }
        let Some(group) = subscription.group.upgrade() else {
            // This exact successful capture was released at its owner-complete
            // boundary. Do not capture or signal a possibly reused numeric PID.
            return Ok(());
        };
        let groups = self.groups.lock().unwrap();
        if !groups.iter().any(|entry| Arc::ptr_eq(entry, &group)) {
            return Err(Errno::ESTALE);
        }
        self.backend_signalling.store(true, Ordering::Release);
        group.identity.signal_owned_process_group()
    }

    pub(crate) fn ordinary_receipt(&self) -> crate::tracer::OrdinaryReceipt {
        crate::tracer::OrdinaryReceipt {
            failure_published: self.is_failed(),
            backend_signalling: self.backend_signalling.load(Ordering::Acquire),
        }
    }

    #[cfg(test)]
    pub(crate) fn owned_daemon_signal(
        &self,
        terminal: &safeptrace::TerminalCleanup,
    ) -> Result<(), Errno> {
        self.backend_signalling.store(true, Ordering::Release);
        // The orphan carries its original generation across late exit hooks.
        // A numeric PID match could select a later captured process. A thread
        // pidfd can also accept SIGKILL without reaching an exited leader's
        // live siblings; use this generation's captured regular group pidfd.
        self.groups
            .lock()
            .unwrap()
            .iter()
            .find(|group| group.terminal.same_generation(terminal))
            .ok_or(Errno::ESTALE)?
            .identity
            .signal_owned_process_group()
    }

    pub(crate) async fn retry_after(&self, error: reverie::Error) {
        let epoch = self.retry_epoch.load(Ordering::Acquire);
        let _ = self.refuse_cleanup(error);
        self.wait_retry(epoch).await;
    }

    async fn freeze_and_kill(&self, task: &FatalTaskStop) {
        self.backend_signalling.store(true, Ordering::Release);
        // A vfork parent can be kernel-blocked behind a captured child. Signal
        // these exact child generations before waiting for the parent stop.
        loop {
            let error = {
                let tree = self.tree.lock().unwrap();
                tree.vfork_children
                    .iter()
                    .find_map(|child| {
                        child
                            .request_sigkill()
                            .err()
                            .filter(|error| *error != Errno::ESRCH)
                    })
                    .or_else(|| {
                        tree.newborns.iter().find_map(|child| {
                            child.signal().err().filter(|error| *error != Errno::ESRCH)
                        })
                    })
            };
            if let Some(error) = error {
                self.retry_after(error.into()).await;
            } else {
                break;
            }
        }
        // Retain the original owning Stopped in this suspended session future
        // across a relay refusal and retry_after; never construct a numeric
        // replacement to continue that transition.
        let mut retained_delivery = None;
        loop {
            match task
                .freeze(
                    self.deadline(),
                    |parent, op, child| self.capture(parent, op, child),
                    || self.request_legacy_group_sigstop(),
                    &mut retained_delivery,
                )
                .await
            {
                Ok(()) => break,
                Err(error) => self.retry_after(error).await,
            }
        }
        #[cfg(test)]
        if FATAL_FREEZE_CONTROL.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|control| control.calls.fetch_add(1, Ordering::SeqCst) == 1)
        }) {
            self.retry_after(
                anyhow::anyhow!("injected refusal after actual owned freeze stop").into(),
            )
            .await;
        }
        task.frozen.store(true, Ordering::Release);
        self.changed.notify_waiters();
        if self
            .tree
            .lock()
            .unwrap()
            .vfork_children
            .iter()
            .any(|child| child.same_generation(&task.terminal))
        {
            // This captured vfork child has already been signalled through its
            // exact generation. Its existing exit owner must advance the real
            // EXIT stop before the kernel can release its suspended parent.
            // Waiting for that parent at the all-task barrier would deadlock.
            return;
        }
        loop {
            let changed = self.changed.notified();
            let cleanup = {
                let mut tree = self.tree.lock().unwrap();
                if tree.killing {
                    return;
                }
                if tree
                    .tasks
                    .iter()
                    .all(|task| task.frozen.load(Ordering::Acquire))
                    && tree.newborns.iter().all(|child| !child.handed)
                {
                    tree.killing = true;
                    tree.unconfirmed_newborns = tree
                        .newborns
                        .iter()
                        .map(|child| (child.tid, child.terminal.clone()))
                        .collect();
                    Some((tree.tasks.clone(), std::mem::take(&mut tree.newborns)))
                } else {
                    None
                }
            };
            if let Some((tasks, mut newborns)) = cleanup {
                // This future, retained by the run driver on refusal, is the
                // sole owner of these unhanded child receivers until reaping.
                for newborn in &mut newborns {
                    loop {
                        let signal = newborn.signal();
                        match signal {
                            Ok(()) | Err(Errno::ESRCH) => break,
                            Err(error) => self.retry_after(error.into()).await,
                        }
                    }
                }
                loop {
                    let errors = self.signal_groups();
                    if errors.is_empty() {
                        break;
                    }
                    for error in errors {
                        self.retry_after(error.into()).await;
                    }
                }
                for task in &tasks {
                    loop {
                        match task.terminal.request_sigkill() {
                            Ok(()) | Err(Errno::ESRCH) => break,
                            Err(error) => self.retry_after(error.into()).await,
                        }
                    }
                }
                self.changed.notify_waiters();
                future::join_all(newborns.into_iter().map(|child| async move {
                    child.reap_owned(self).await;
                }))
                .await;
                return;
            }
            changed.await;
        }
    }
    fn new<G: GlobalTool + 'static>(global: &Arc<G>, root: Pid) -> Self {
        let weak = Arc::downgrade(global);
        Self {
            root: Some(root),
            ptracer_thread: Some(std::thread::current().id()),
            reporter: Some(Box::new(move |origin| {
                if let Some(global) = weak.upgrade() {
                    global.report_backend_failure(origin);
                    true
                } else {
                    false
                }
            })),
            ..Self::default()
        }
    }

    pub(crate) fn fail_at(&self, origin: BackendFailure, error: reverie::Error) {
        self.try_fail_at(origin, error);
    }

    fn try_fail_at(&self, origin: BackendFailure, error: reverie::Error) -> bool {
        let first = {
            let mut failure = self.failure.lock().unwrap();
            if self.closed.load(Ordering::Acquire) {
                return false;
            }
            if let Some(failure) = failure.as_mut() {
                failure.secondary.push(PtraceCleanupFailure {
                    origin,
                    error: Arc::new(error),
                });
                false
            } else {
                *failure = Some(PtraceRunFailure {
                    primary: Arc::new(error),
                    origin,
                    secondary: Vec::new(),
                    captured_prefix: None,
                });
                true
            }
        };
        if first {
            *self.cleanup_deadline.lock().unwrap() =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
            // No cause/tree lock spans the synchronous Tool transition. Local
            // observers cannot see publication until the Tool closes its waits.
            if !self.reporter.as_ref().is_some_and(|report| report(origin)) {
                self.failure
                    .lock()
                    .unwrap()
                    .as_mut()
                    .expect("stored primary")
                    .secondary
                    .push(PtraceCleanupFailure {
                        origin: BackendFailure {
                            phase: "ptrace failure publication",
                            ..origin
                        },
                        error: Arc::new(anyhow::Error::new(GlobalFailurePublicationLost).into()),
                    });
            }
            self.published.store(true, Ordering::Release);
        }
        self.changed.notify_waiters();
        true
    }

    pub(crate) fn request_termination(&self, error: reverie::Error) -> bool {
        let Some(root) = self.root else {
            return false;
        };
        self.try_fail_at(
            BackendFailure {
                pid: root,
                tid: root,
                phase: "ptrace supervisor termination",
            },
            error,
        )
    }

    pub(crate) fn fail(&self, error: reverie::Error) {
        let root = self.root.expect("ordinary failure has a root owner");
        self.fail_at(
            BackendFailure {
                pid: root,
                tid: root,
                phase: "ptrace tree cleanup",
            },
            error,
        );
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    pub(crate) fn callback_diagnostics(&self) -> Vec<crate::PtraceCallbackDiagnostic> {
        self.callback_diagnostics.lock().unwrap().clone()
    }

    pub(crate) fn take_callback_diagnostics(&self) -> Vec<crate::PtraceCallbackDiagnostic> {
        std::mem::take(&mut *self.callback_diagnostics.lock().unwrap())
    }

    pub(crate) fn failure_snapshot(&self) -> Option<PtraceRunFailure> {
        self.failure
            .lock()
            .unwrap()
            .as_ref()
            .map(PtraceRunFailure::snapshot)
    }

    pub(crate) async fn take_public_failure(&self) -> Option<PtraceRunFailure> {
        loop {
            let changed = self.changed.notified();
            {
                let mut failure = self.failure.lock().unwrap();
                // A supervisor can publish from another thread. Do not move
                // its cause while its synchronous logical publication runs.
                if failure.is_none() || self.published.load(Ordering::Acquire) {
                    self.closed.store(true, Ordering::Release);
                    return failure.take();
                }
            }
            changed.await;
        }
    }

    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.cleanup_deadline
            .lock()
            .unwrap()
            .expect("cleanup follows failure publication")
    }

    pub(crate) fn resume_cleanup(&self) {
        self.tree.lock().unwrap().cleanup_refusal = None;
        *self.cleanup_deadline.lock().unwrap() =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
        self.retry_epoch.fetch_add(1, Ordering::AcqRel);
        self.retry_changed.notify_waiters();
    }

    async fn wait_retry(&self, epoch: usize) {
        loop {
            let changed = self.retry_changed.notified();
            if self.retry_epoch.load(Ordering::Acquire) != epoch {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn join_owned(&self) {
        loop {
            let handles = std::mem::take(&mut *self.joins.lock().unwrap());
            if handles.is_empty() {
                break;
            }
            for handle in handles {
                if let Err(error) = handle.await {
                    self.fail(anyhow::Error::new(error).into());
                }
            }
        }
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            if self.is_failed() {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn cleanup_refused(&self) -> reverie::Error {
        loop {
            let changed = self.changed.notified();
            if let Some(message) = &self.tree.lock().unwrap().cleanup_refusal {
                return anyhow::anyhow!("fatal ptrace cleanup refused: {message}").into();
            }
            changed.await;
        }
    }
}

/// All the info needed to be able to interact with the global state.
struct GlobalState<G: GlobalTool> {
    /// The tool's static configuration data.
    cfg: G::Config,

    /// Reference to the tool's global state. This is used to send it "rpc" messages.
    gs_ref: Arc<G>,

    /// Events the tool is subscripted (like interception)
    subscriptions: Arc<Subscription>,

    /// guests are sequentialized already (by detcore for example), gdbserver
    /// should avoid sequentialize threads.
    sequentialized_guest: Arc<bool>,

    /// Marker and exact RIP identifying a binary-rewriter syscall trap.
    injected_syscall_trap: Option<InjectedSyscallTrap>,

    /// Optional dynamic LiteInst runtime configuration.
    liteinst_runtime: Option<LiteinstRuntimeConfig>,

    fatal_session: Arc<FatalSession>,

    /// Optional collector for general ptrace lifecycle activity.
    backend_stats: Option<PtraceBackendStatsSource>,

    #[cfg(test)]
    final_resume_signal_for_test: Option<FinalResumeSignalForTest>,

    #[cfg(test)]
    pre_syscall_for_test: Option<PreSyscallForTest>,

    #[cfg(test)]
    preinit_point_for_test: Option<PreinitPointForTest>,
}

/// Test-only: picks a signal to leave pending for the final resume of a
/// seccomp stop, from the stopped thread and its registers. It stands in for
/// a signal an earlier injection deferred, which no current path leaves
/// pending while a trap-only live entry survives.
#[cfg(test)]
pub(crate) type FinalResumeSignalForTest =
    Arc<dyn Fn(Pid, &libc::user_regs_struct) -> Option<Signal> + Send + Sync>;

/// Test-only: runs immediately before a Tool-visible syscall's own execution
/// starts, with the stopped thread, the syscall's registers and the point,
/// and is awaited before the tracer goes on. Under plain ptrace both points
/// are the final resume of the seccomp stop (or the exact inject's resume),
/// one after the other; under trap-only they are inside the masked hop, after
/// the slot stop and before the syscall runs (see [`PreSyscallPoint`]). It
/// parks a thread at the same logical point under both backends, so that a
/// test can deliver a signal there deterministically.
#[cfg(test)]
pub(crate) type PreSyscallForTest = Arc<
    dyn Fn(Pid, &libc::user_regs_struct, PreSyscallPoint) -> futures::future::BoxFuture<'static, ()>
        + Send
        + Sync,
>;

/// Test-only: runs synchronously at a [`PreinitPoint`] of every
/// `tracee_preinit`, with the tracee's PID and terminal-status observer.
/// Being synchronous, it can end the tracee and let the next ptrace operation
/// or wait of the same poll observe that, as a SIGKILL racing initialization
/// does.
#[cfg(test)]
pub(crate) type PreinitPointForTest =
    Arc<dyn Fn(Pid, &safeptrace::TerminalCleanup, PreinitPoint) + Send + Sync>;

/// Calls the [`PreinitPointForTest`] hook, if any. `cleanup` runs only then.
#[cfg(test)]
fn at_preinit_point(
    hook: &Option<PreinitPointForTest>,
    pid: Pid,
    cleanup: impl FnOnce() -> safeptrace::TerminalCleanup,
    point: PreinitPoint,
) {
    if let Some(hook) = hook {
        hook(pid, &cleanup(), point);
    }
}

/// Test-only: where `tracee_preinit`, or the post-exec step before it, calls a
/// [`PreinitPointForTest`] hook.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreinitPoint {
    /// After saving the registers, before reading the code at RIP.
    RegsSaved,
    /// After reading the code at RIP, before patching it.
    CodeRead,
    /// After stepping into the injected mmap, before waiting for its stop.
    MmapStepped,
    /// After checking the mmap's result, before populating the page.
    MmapReturned,
    /// After populating the page, before restoring the code at RIP.
    PagePopulated,
    /// After making the vDSO writable, before patching it.
    VdsoWritable,
    /// After patching the vDSO, or skipping that, before the injected
    /// `mprotect` of the trampoline page.
    TrampolineUnprotected,
    /// At the exec stop, before the post-exec SIGTRAP step. Not on the
    /// LiteInst path.
    ExecStopped,
    /// After the post-exec SIGTRAP step, before waiting for its stop. Not on
    /// the LiteInst path.
    PostExecStepped,
}

/// Test-only: where the masked hop calls a [`PreSyscallForTest`] hook.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PreSyscallPoint {
    /// At the hop's first slot seccomp stop, before the hop reads the
    /// thread's pending signals to settle any SIGSTOP it deferred. A hook
    /// that returns without awaiting lets the hop make that read before any
    /// other task of the tracer runs.
    Early,
    /// After that read (and with no await between the two), immediately
    /// before the hop restores the signal mask, raises the deferred SIGSTOPs
    /// again and runs the syscall.
    Late,
}

/// The owner that must retain a decoded `Event::NewChild` before any
/// cancellation point can drop the stop that carries it.
#[derive(Clone, Copy)]
enum NewbornOwner<'a> {
    /// Ordinary ptrace: the fatal session's retained kernel edge.
    Ordinary(&'a FatalSession),
    /// Dynamic LiteInst: the session cleanup guard's newborn table.
    Liteinst(&'a StdMutex<HashMap<Pid, NewbornTracee>>),
}

impl NewbornOwner<'_> {
    /// Synchronous and idempotent for the same child generation: a repeated
    /// registration of an already retained child is a no-op, so a nested
    /// handler and the run loop can both register the same stop.
    fn register(self, parent: Pid, event: &Event) {
        let Event::NewChild(op, child) = event else {
            return;
        };
        match self {
            Self::Ordinary(session) => session.capture(parent, *op, child),
            Self::Liteinst(newborns) => NewbornTracee::register(newborns, parent, *op, child),
        }
    }
}

impl<G: GlobalTool> GlobalState<G> {
    /// Borrows only the global state, so a closure passed to a nested stepper
    /// that also borrows the task's timer can still register a newborn.
    fn newborn_owner(&self) -> NewbornOwner<'_> {
        // `liteinst_runtime.is_none()` is `TracedTask::ordinary_failure_enabled`.
        match self.liteinst_runtime.as_ref() {
            None => NewbornOwner::Ordinary(&self.fatal_session),
            Some(runtime) => NewbornOwner::Liteinst(&runtime.newborn_tracees),
        }
    }
}

impl<G: GlobalTool> Clone for GlobalState<G> {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            gs_ref: self.gs_ref.clone(),
            subscriptions: self.subscriptions.clone(),
            sequentialized_guest: self.sequentialized_guest.clone(),
            injected_syscall_trap: self.injected_syscall_trap.clone(),
            liteinst_runtime: self.liteinst_runtime.clone(),
            fatal_session: self.fatal_session.clone(),
            backend_stats: self.backend_stats.clone(),
            #[cfg(test)]
            final_resume_signal_for_test: self.final_resume_signal_for_test.clone(),
            #[cfg(test)]
            pre_syscall_for_test: self.pre_syscall_for_test.clone(),
            #[cfg(test)]
            preinit_point_for_test: self.preinit_point_for_test.clone(),
        }
    }
}

/// A raw argument remains exact unless both its type and launch ownership are known.
struct SyscallArgsForLog {
    nr: Sysno,
    args: SyscallArgs,
    command_bootstrap: bool,
}

struct CommandBootstrapAddress(usize);

impl fmt::Debug for CommandBootstrapAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            f.write_str("0")
        } else {
            write!(f, "<hostaddr {:#x}>", self.0)
        }
    }
}

impl fmt::Debug for SyscallArgsForLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.command_bootstrap || self.nr != Sysno::execve {
            return fmt::Debug::fmt(&self.args, f);
        }
        // Command::do_exec passes pathname, argv and envp pointers from the
        // inherited launcher image. The ABI-unused registers are still raw.
        f.debug_struct("SyscallArgs")
            .field("arg0", &CommandBootstrapAddress(self.args.arg0))
            .field("arg1", &CommandBootstrapAddress(self.args.arg1))
            .field("arg2", &CommandBootstrapAddress(self.args.arg2))
            .field("arg3", &self.args.arg3)
            .field("arg4", &self.args.arg4)
            .field("arg5", &self.args.arg5)
            .finish()
    }
}

/// Event configuration supplied when a traced task is created.
pub(crate) struct TracedTaskOptions<'a> {
    pub(crate) command_bootstrap: bool,
    pub(crate) events: &'a Subscription,
    pub(crate) injected_syscall_trap: Option<InjectedSyscallTrap>,
    pub(crate) liteinst_runtime: Option<LiteinstRuntimeConfig>,
    /// The root task's trap-only state; `Some` only when sites are patched.
    pub(crate) liteinst_trap_only: Option<TrapOnlyTask>,
    pub(crate) backend_stats: Option<PtraceBackendStatsSource>,
    #[cfg(test)]
    pub(crate) final_resume_signal_for_test: Option<FinalResumeSignalForTest>,
    #[cfg(test)]
    pub(crate) pre_syscall_for_test: Option<PreSyscallForTest>,
    #[cfg(test)]
    pub(crate) preinit_point_for_test: Option<PreinitPointForTest>,
}

/// Our runtime representation of what Reverie knows about a guest thread. Its
/// lifetime matches the lifetime of the thread.
pub struct TracedTask<L: Tool> {
    // Shared with the original fatal owner before any callback can suspend.
    // Driver refusals and cancelled adapters keep their exact core here.
    pub(crate) ptracer_waits: Arc<PtracerWaitOwner>,
    ordinary_held_stop: Arc<StdMutex<Option<HeldRootStop>>>,
    // Session diagnostics are append-only until every task owner completes.
    // Therefore another task cannot invalidate this private entry index.
    pending_callback_diagnostic: Option<usize>,
    ordinary_exec: Arc<StdMutex<HashMap<Pid, Arc<OrdinaryExecSlot<L>>>>>,
    /// Thread ID.
    tid: Pid,

    /// Process ID.
    pid: Pid,

    /// Parent process ID.
    ppid: Option<Pid>,

    /// State associated with the thread. Unique for each thread.
    thread_state: L::ThreadState,

    /// State associated with the process. This is shared among threads in the
    /// same thread group.
    process_state: Arc<L>,

    /// Global state. This is shared among all threads in a process tree.
    global_state: GlobalState<L::GlobalState>,

    /// True only for TracerBuilder::spawn's Command root until successful exec.
    /// Descendants and spawn_fn never inherit this logging provenance.
    command_bootstrap: bool,

    /// True if we can intercept CPUID, false otherwise.
    has_cpuid_interception: bool,

    /// Original call still owned by the current syscall callback. Only an
    /// ordinary, unconverted seccomp callback owns a kernel entry to skip;
    /// an injected frame and an already-skipped call are logical operations.
    /// Taking this record consumes that authority, including fast tail injection
    /// which transfers the original call to the callback's final resume.
    pending_syscall: Option<(Sysno, SyscallArgs)>,

    /// The pending syscall was converted out of its seccomp stop before Tool dispatch.
    pending_syscall_already_skipped: bool,

    /// Address of the writable e9tool register frame for the active event.
    injected_syscall_frame: Option<usize>,

    /// Result of a fast tail injection made from an injected-frame callback.
    /// The dispatcher that owns the frame writes it, or restarts the trap when
    /// it is a Linux restart code, after the callback is dropped.
    injected_tail_result: Option<Result<i64, Errno>>,

    /// Host-hybrid syscalls whose controller was rewound to the runtime
    /// `int3` for a restart and has not re-trapped yet, innermost last. A
    /// signal handler that runs while a restart is pending can itself make a
    /// syscall that restarts, so restarts nest like the handlers do.
    liteinst_pending_restarts: Vec<LiteinstPendingRestart>,

    /// Per-process dynamic LiteInst handshake and patched-site state.
    liteinst_runtime: Arc<StdMutex<LiteinstRuntimeState>>,

    /// Controller-owned breakpoint preventing the executable entry before Ready.
    liteinst_entry_guard: Option<LiteinstEntryGuard>,

    /// Original typed fail-closed error retained while the exit waiter reaps root.
    liteinst_failure: Option<LiteinstActivationFailure>,

    /// Trap-only LiteInst site-patching state; `None` unless sites are
    /// patched.
    trap_only: Option<TrapOnlyTask>,

    /// pending signal to deliver. This can happen when
    /// syscall got interrupted (by signal)
    pending_signal: Option<Signal>,

    /// How the delivery stop of the signal in `pending_signal` took it, when
    /// `status_to_result` held it.
    pending_signal_taken: Option<TakenSignal>,

    /// Whether an injected syscall's single step ended at a held signal
    /// (`step_private_syscall`) before collecting its step SIGTRAP, which the
    /// kernel therefore still has queued. The next SIGTRAP stop carrying that
    /// step's siginfo is discarded instead of being read as a later step's
    /// completion or reported as an unexpected trap.
    stale_private_step_trap: bool,

    /// The generation [`Self::tracee_preinit`] is initializing, while it runs.
    preinit_generation: Option<TraceeGeneration>,

    /// The stop an injection last ended at since the current stop was
    /// dispatched (`handle_stop_event`), as its wait status classifies it:
    /// `Some(Some(sig))` for a signal-delivery stop of `sig`, `Some(None)`
    /// for any other stop, `None` if no injection has completed. Set by
    /// `status_to_result`. Siginfo cannot classify the stop, because a guest
    /// may queue itself a SIGTRAP whose `si_code` mimics a syscall stop.
    latest_injection_stop: Option<Option<Signal>>,

    /// Whether `Tool::handle_signal_event` is running (`report_signal`).
    in_signal_callback: bool,

    /// Whether a syscall the running held-signal callback
    /// (`in_held_signal_callback`) injected, other than `restart_syscall`,
    /// returned
    /// `-ERESTART_RESTARTBLOCK`. Linux then replaced the thread's restart
    /// block with the injection's, so a guest return register of that code
    /// would restart the injected syscall in place of the guest's
    /// (`signal_callback_guest_ret`). An interrupted injected
    /// `restart_syscall` ran the thread's restart block and leaves it the
    /// guest's.
    signal_callback_replaced_restart_block: bool,

    /// Whether the guest's return register held `-ERESTART_RESTARTBLOCK` in
    /// a syscall during the running held-signal callback: in the registers
    /// an injection saved, or in those a Tool's register write
    /// (`Guest::set_regs`) replaced, which that write notes only when its
    /// read of the outgoing registers succeeds. `report_held_signal` starts
    /// no held-signal callback while the guest's own return register holds
    /// that code, so it comes from a Tool's write.
    signal_callback_guest_restart_block: bool,

    /// Whether the running `Tool::handle_signal_event` callback reports a
    /// held signal (`report_held_signal`). A syscall the callback injects
    /// then restores the guest's return register as well
    /// (`status_to_result`): main resumed the guest with its own registers
    /// there, without a callback, often in an interrupted syscall whose
    /// `-ERESTART*` value decides whether the kernel restarts it. A callback
    /// at a signal's own delivery stop leaves the injection's return
    /// register, as main does: the Tool sees that value after the injection,
    /// and may save it and write it back. A signal that stops one of its
    /// injections before the `syscall` instruction is then put back in the
    /// kernel's queue (`requeue_signals_before_original_syscall`) instead of
    /// being held: the held signal's resume empties `pending_signal` no
    /// more, so a signal held there would wait for a later syscall stop
    /// that a guest about to exit need not make.
    in_held_signal_callback: bool,

    /// Set by every successful exec (`handle_exec_event`). A held signal's
    /// report clears it before `Tool::handle_signal_event` runs, so it then
    /// tells whether the callback executed a program (`report_signal`).
    signal_callback_execed: bool,

    /// A job-control stop signal (SIGTSTP, SIGTTIN, SIGTTOU) that a stop
    /// resumed held and unreported (`pass_held_signal_unreported`). The
    /// group stop its delivery makes at the next stop is then reported
    /// (`handle_signal`), as every group stop was before held signals were
    /// reported: it is the Tool's only sight of that signal.
    unreported_stop_signal: Option<Signal>,

    /// How many instances of each signal `Tool::handle_signal_event`
    /// reported and then passed back into the kernel's queue instead of
    /// delivering it (`resume_with_signal`). `report_held_signal` passes one
    /// such instance on unreported when an injection later holds it, rather
    /// than report it twice.
    reported_requeued_signals: HashMap<Signal, u32>,

    /// A channel to allow short-circuiting the next state to main run loop. This
    /// is useful inside of `inject` or `tail_inject` where we might need to
    /// cancel a future early.
    next_state: mpsc::Sender<Result<Wait, TraceError>>,

    /// The receiving end of the next_state channel.
    next_state_rx: Option<mpsc::Receiver<Result<Wait, TraceError>>>,

    /// The timer tracking this task. Used to trigger RCB-based `timeouts`.
    timer: Timer,

    /// Set when `tail_inject` needs to cancel the current tool handler.
    cancel_handler: Arc<AtomicBool>,

    /// Child processes to wait on. When one of the children exits, it should be
    /// removed from this list.
    child_procs: Arc<Mutex<Children>>,

    /// Child threads to wait on. When one of the child threads exits, it should
    /// be removed from this list.
    child_threads: Arc<Mutex<Children>>,

    /// Channel to send child processes to that are left over by the time this
    /// task exits.
    orphanage: mpsc::Sender<Child>,

    /// broadcast to kill all daemons
    daemon_kill_switch: broadcast::Sender<()>,

    /// Channel to damonize a process
    daemonizer: mpsc::Sender<broadcast::Receiver<()>>,

    /// The rx end of `daemonizer`.
    daemonizer_rx: Option<mpsc::Receiver<broadcast::Receiver<()>>>,

    /// Total number of tasks
    ntasks: Arc<AtomicUsize>,

    /// Total number of daemons
    ndaemons: Arc<AtomicUsize>,

    /// Task is a daemon
    is_a_daemon: bool,

    /// Software breakpoints.
    // NB: For multi-threaded programs, sw breakpoints apply to all threads
    // because they're in the same address space. Hence removing sw
    // breakpoint in one thread also remove it for the rest of the threads
    // in the same process group. *However*, our model is slightly different
    // because we use different tx/rx channels even the threads are in the
    // same process group, hence each threads owns `breakpoints: HashMap`
    // instead of `Arc<Mutex<..>>`.
    breakpoints: HashMap<u64, u64>,

    /// Notify gdbserver start accepting incoming packets.
    gdbserver_start_tx: Option<oneshot::Sender<()>>,

    /// task is suspended (received SIGSTOP)
    suspended: Arc<AtomicBool>,

    /// Notify gdbserver there's a new stop event.
    gdb_stop_tx: Option<mpsc::Sender<StoppedInferior>>,

    /// Task is attached by gdb.
    // NB: gdb doesn't always attach everything, when fork/clone is called.
    // gdb also allows detach from a task, and re-attach again.
    attached_by_gdb: bool,

    /// Task is resumed by gdb.
    // NB: gdb doesn't always attach everything, when fork/clone is called.
    // gdb also allows detach from a task, and re-attach again.
    resumed_by_gdb: Option<ResumeAction>,

    /// GDB resume request, gdbstub is the sender
    gdb_resume_tx: Option<mpsc::Sender<ResumeInferior>>,

    /// GDB resume request, reverie is the receiver
    gdb_resume_rx: Option<mpsc::Receiver<ResumeInferior>>,

    /// Request sent by gdb. the tx channel is used by gdb instead of
    /// `TracedTask`.
    gdb_request_tx: Option<mpsc::Sender<GdbRequest>>,

    /// Receiver to receive gdb request.
    gdb_request_rx: Option<mpsc::Receiver<GdbRequest>>,

    /// Wait to be resumed when in sigstop due to all stop mode.
    exit_suspend_tx: Option<mpsc::Sender<Pid>>,

    /// Wait to be resumed when in sigstop due to all stop mode.
    exit_suspend_rx: Option<mpsc::Receiver<Pid>>,

    /// Suspended task when hitting swbp. This is used to implement gdb's
    /// all stop mode.
    suspended_tasks: BTreeMap<Pid, Suspended>,

    /// Task needs (single) step over the swbp instruciton when a swbp is
    /// hit. unless this is done, if is not safe for other threads running
    /// in parallel to report breakpoint, otherwise there're could be an
    /// interleaved step-over, which might remove the breakpoint, hence
    /// causing others to miss the breakpoint.
    needs_step_over: Arc<Mutex<()>>,

    /// Whether or not the tool is currently holding a handle on the guest Stack (and thus
    /// potentially using actual stack memory within the guest).
    stack_checked_out: Arc<AtomicBool>,
}

impl<L: Tool> fmt::Debug for TracedTask<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TracedTask")
            .field("tid", &self.tid)
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .finish()
    }
}

impl<L: Tool> TracedTask<L> {
    /// Create a new TracedTask.
    pub(crate) fn new(
        tid: Pid,
        cfg: <L::GlobalState as GlobalTool>::Config,
        gs_ref: Arc<L::GlobalState>,
        options: TracedTaskOptions<'_>,
        orphanage: mpsc::Sender<Child>,
        daemon_kill_switch: broadcast::Sender<()>,
        mut gdbserver: Option<GdbServer>,
    ) -> Self
    where
        L::GlobalState: 'static,
    {
        let process_state = Arc::new(L::new(tid, &cfg));
        let fatal_session = Arc::new(FatalSession::new(&gs_ref, tid));
        let global_state = GlobalState {
            gs_ref,
            cfg,
            subscriptions: Arc::new(options.events.clone()),
            sequentialized_guest: Arc::new(
                gdbserver
                    .as_ref()
                    .map(|s| s.sequentialized_guest)
                    .unwrap_or(false),
            ),
            injected_syscall_trap: options.injected_syscall_trap.clone(),
            liteinst_runtime: options.liteinst_runtime,
            fatal_session,
            backend_stats: options.backend_stats,
            #[cfg(test)]
            final_resume_signal_for_test: options.final_resume_signal_for_test,
            #[cfg(test)]
            pre_syscall_for_test: options.pre_syscall_for_test,
            #[cfg(test)]
            preinit_point_for_test: options.preinit_point_for_test,
        };
        let thread_state = process_state.init_thread_state(tid, None);
        let (next_state, next_state_rx) = mpsc::channel(1);
        let (daemonizer, daemonizer_rx) = mpsc::channel(1);
        let (gdb_resume_tx, gdb_resume_rx) = mpsc::channel(1);
        let (gdb_request_tx, gdb_request_rx) = mpsc::channel(1);
        let (exit_suspend_tx, exit_suspend_rx) = mpsc::channel(16);
        Self {
            tid,
            pid: tid,
            ppid: None,
            thread_state,
            process_state,
            global_state,
            ordinary_held_stop: Arc::new(StdMutex::new(None)),
            pending_callback_diagnostic: None,
            ordinary_exec: Arc::new(StdMutex::new(HashMap::new())),
            command_bootstrap: options.command_bootstrap,
            has_cpuid_interception: false,
            pending_syscall: None,
            pending_syscall_already_skipped: false,
            injected_syscall_frame: None,
            injected_tail_result: None,
            liteinst_pending_restarts: Vec::new(),
            liteinst_runtime: Arc::new(StdMutex::new(LiteinstRuntimeState::default())),
            liteinst_entry_guard: None,
            liteinst_failure: None,
            trap_only: options.liteinst_trap_only,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: if options.command_bootstrap {
                Timer::for_initial_command(tid, tid)
            } else {
                Timer::new(tid, tid)
            },
            cancel_handler: Arc::new(AtomicBool::new(false)),
            pending_signal: None,
            pending_signal_taken: None,
            stale_private_step_trap: false,
            ptracer_waits: Arc::new(PtracerWaitOwner::default()),
            preinit_generation: None,
            latest_injection_stop: None,
            in_signal_callback: false,
            signal_callback_replaced_restart_block: false,
            signal_callback_guest_restart_block: false,
            in_held_signal_callback: false,
            signal_callback_execed: false,
            unreported_stop_signal: None,
            reported_requeued_signals: HashMap::new(),
            child_procs: Arc::new(Mutex::new(Children::new())),
            child_threads: Arc::new(Mutex::new(Children::new())),
            orphanage,
            daemon_kill_switch,
            daemonizer,
            daemonizer_rx: Some(daemonizer_rx),
            ntasks: Arc::new(AtomicUsize::new(1)),
            ndaemons: Arc::new(AtomicUsize::new(0)),
            is_a_daemon: false,
            gdbserver_start_tx: gdbserver.as_mut().and_then(|s| s.server_tx.take()),
            gdb_stop_tx: gdbserver
                .as_mut()
                .and_then(|s| s.inferior_attached_tx.take()),
            attached_by_gdb: false,
            resumed_by_gdb: None,
            gdb_resume_tx: Some(gdb_resume_tx),
            gdb_resume_rx: Some(gdb_resume_rx),
            breakpoints: HashMap::new(),
            suspended: Arc::new(AtomicBool::new(false)),
            gdb_request_tx: Some(gdb_request_tx),
            gdb_request_rx: Some(gdb_request_rx),
            exit_suspend_tx: Some(exit_suspend_tx),
            exit_suspend_rx: Some(exit_suspend_rx),
            needs_step_over: Arc::new(Mutex::new(())),
            suspended_tasks: BTreeMap::new(),
            stack_checked_out: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The pending host-hybrid restarts a new child resolves.
    ///
    /// A child that forks inside a signal handler returns through the same
    /// handler frames, copied into its own address space, to the same
    /// re-traps and landings, and serves each against its own copy of the
    /// injected frames. A child sharing the parent's address space (a thread,
    /// or a `CLONE_VM` process) runs on its own stack and starts with none.
    /// `PTRACE_EVENT_FORK` and `PTRACE_EVENT_CLONE` follow the exit signal,
    /// not `CLONE_VM`, so the kernel is asked; if it cannot answer, the child
    /// starts with none, and a landing it reaches fails closed.
    fn inherited_liteinst_restarts(&self, child: Pid) -> Vec<LiteinstPendingRestart> {
        if self.liteinst_pending_restarts.is_empty() {
            return Vec::new();
        }
        const KCMP_VM: libc::c_long = 1;
        // SAFETY: kcmp only compares kernel objects of the two tasks.
        let order = unsafe {
            libc::syscall(
                libc::SYS_kcmp,
                self.tid.as_raw() as libc::c_long,
                child.as_raw() as libc::c_long,
                KCMP_VM,
                0 as libc::c_long,
                0 as libc::c_long,
            )
        };
        if order > 0 {
            self.liteinst_pending_restarts.clone()
        } else {
            Vec::new()
        }
    }

    /// Create a child TracedTask corresponding to a clone()
    fn cloned(&self, child: Pid) -> Self {
        let ptracer_waits = Arc::new(self.ptracer_waits.child_owner());
        let global_state = self.global_state.clone();
        let process_state = self.process_state.clone();
        let thread_state =
            process_state.init_thread_state(child, Some((self.tid, &self.thread_state)));
        let (next_state, next_state_rx) = mpsc::channel(1);
        let (daemonizer, daemonizer_rx) = mpsc::channel(1);
        let (gdb_resume_tx, gdb_resume_rx) = mpsc::channel(1);
        let (gdb_request_tx, gdb_request_rx) = mpsc::channel(1);
        let (exit_suspend_tx, exit_suspend_rx) = mpsc::channel(16);
        self.ntasks.fetch_add(1, Ordering::SeqCst);
        Self {
            tid: child,
            pid: self.pid,
            ppid: self.ppid,
            thread_state,
            process_state,
            global_state,
            ordinary_held_stop: Arc::new(StdMutex::new(None)),
            pending_callback_diagnostic: None,
            ordinary_exec: self.ordinary_exec.clone(),
            command_bootstrap: false,
            has_cpuid_interception: self.has_cpuid_interception,
            pending_syscall: None,
            pending_syscall_already_skipped: false,
            injected_syscall_frame: None,
            injected_tail_result: None,
            liteinst_pending_restarts: self.inherited_liteinst_restarts(child),
            liteinst_runtime: self.liteinst_runtime.clone(),
            liteinst_entry_guard: None,
            liteinst_failure: None,
            // Set by `handle_new_task`, which knows the clone flags.
            trap_only: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(self.pid, child),
            cancel_handler: Arc::new(AtomicBool::new(false)),
            pending_signal: None,
            pending_signal_taken: None,
            stale_private_step_trap: false,
            ptracer_waits,
            preinit_generation: None,
            latest_injection_stop: None,
            in_signal_callback: false,
            signal_callback_replaced_restart_block: false,
            signal_callback_guest_restart_block: false,
            in_held_signal_callback: false,
            signal_callback_execed: false,
            unreported_stop_signal: None,
            reported_requeued_signals: HashMap::new(),
            child_procs: self.child_procs.clone(),
            child_threads: self.child_threads.clone(),
            orphanage: self.orphanage.clone(),
            daemon_kill_switch: self.daemon_kill_switch.clone(),
            daemonizer,
            daemonizer_rx: Some(daemonizer_rx),
            ntasks: self.ntasks.clone(),
            ndaemons: self.ndaemons.clone(),
            is_a_daemon: self.is_a_daemon,
            gdbserver_start_tx: None,
            gdb_stop_tx: None,
            attached_by_gdb: self.attached_by_gdb,
            resumed_by_gdb: self.resumed_by_gdb,
            gdb_resume_tx: Some(gdb_resume_tx),
            gdb_resume_rx: Some(gdb_resume_rx),
            breakpoints: self.breakpoints.clone(),
            suspended: Arc::new(AtomicBool::new(false)),
            gdb_request_tx: Some(gdb_request_tx),
            gdb_request_rx: Some(gdb_request_rx),
            exit_suspend_tx: Some(exit_suspend_tx),
            exit_suspend_rx: Some(exit_suspend_rx),
            needs_step_over: self.needs_step_over.clone(),
            suspended_tasks: BTreeMap::new(),
            stack_checked_out: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a child TracedTask corresponding to a fork()
    fn forked(&self, child: Pid) -> Self {
        let ptracer_waits = Arc::new(self.ptracer_waits.child_owner());
        let process_state = Arc::new(L::new(child, &self.global_state.cfg));
        let thread_state =
            process_state.init_thread_state(child, Some((self.tid, &self.thread_state)));
        let (next_state, next_state_rx) = mpsc::channel(1);
        let (daemonizer, daemonizer_rx) = mpsc::channel(1);
        let (gdb_resume_tx, gdb_resume_rx) = mpsc::channel(1);
        let (gdb_request_tx, gdb_request_rx) = mpsc::channel(1);
        let (exit_suspend_tx, exit_suspend_rx) = mpsc::channel(16);
        self.ntasks.fetch_add(1, Ordering::SeqCst);
        Self {
            tid: child,
            pid: child,
            ppid: Some(self.pid),
            thread_state,
            process_state,
            global_state: self.global_state.clone(),
            ordinary_held_stop: Arc::new(StdMutex::new(None)),
            pending_callback_diagnostic: None,
            ordinary_exec: Arc::new(StdMutex::new(HashMap::new())),
            command_bootstrap: false,
            has_cpuid_interception: self.has_cpuid_interception,
            pending_syscall: None,
            pending_syscall_already_skipped: false,
            injected_syscall_frame: None,
            injected_tail_result: None,
            liteinst_pending_restarts: self.inherited_liteinst_restarts(child),
            liteinst_runtime: Arc::new(StdMutex::new(
                self.liteinst_runtime.lock().unwrap().clone(),
            )),
            liteinst_entry_guard: None,
            liteinst_failure: None,
            // Set by `handle_new_task`, which knows the clone flags.
            trap_only: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(child, child),
            cancel_handler: Arc::new(AtomicBool::new(false)),
            pending_signal: None,
            pending_signal_taken: None,
            stale_private_step_trap: false,
            ptracer_waits,
            preinit_generation: None,
            latest_injection_stop: None,
            in_signal_callback: false,
            signal_callback_replaced_restart_block: false,
            signal_callback_guest_restart_block: false,
            in_held_signal_callback: false,
            signal_callback_execed: false,
            unreported_stop_signal: None,
            reported_requeued_signals: HashMap::new(),
            child_procs: Arc::new(Mutex::new(Children::new())),
            child_threads: Arc::new(Mutex::new(Children::new())),
            orphanage: self.orphanage.clone(),
            daemon_kill_switch: self.daemon_kill_switch.clone(),
            daemonizer,
            daemonizer_rx: Some(daemonizer_rx),
            ntasks: self.ntasks.clone(),
            ndaemons: self.ndaemons.clone(),
            // NB: if daemon forks, then its child's parent pid is no longer 1.
            is_a_daemon: false,
            gdbserver_start_tx: None,
            gdb_stop_tx: None,
            attached_by_gdb: self.attached_by_gdb,
            resumed_by_gdb: None,
            gdb_resume_tx: Some(gdb_resume_tx),
            gdb_resume_rx: Some(gdb_resume_rx),
            breakpoints: self.breakpoints.clone(),
            suspended: Arc::new(AtomicBool::new(false)),
            gdb_request_tx: Some(gdb_request_tx),
            gdb_request_rx: Some(gdb_request_rx),
            exit_suspend_tx: Some(exit_suspend_tx),
            exit_suspend_rx: Some(exit_suspend_rx),
            needs_step_over: Arc::new(Mutex::new(())),
            suspended_tasks: BTreeMap::new(),
            stack_checked_out: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn read_injected_syscall_frame(
        &self,
        task: &Stopped,
        address: usize,
    ) -> Result<InjectedSyscallFrame, TraceError> {
        read_injected_frame(task, address)
    }

    #[cfg(target_arch = "x86_64")]
    fn write_injected_syscall_frame(
        &self,
        task: &Stopped,
        address: usize,
        frame: &InjectedSyscallFrame,
    ) -> Result<(), TraceError> {
        write_injected_frame(task, address, frame)
    }

    #[cfg(target_arch = "x86_64")]
    fn write_injected_syscall_result(
        &self,
        task: &Stopped,
        result: Result<i64, Errno>,
    ) -> Result<(), TraceError> {
        let address = self.injected_syscall_frame.ok_or(Errno::EIO)?;
        let mut frame = self.read_injected_syscall_frame(task, address)?;
        let result = result.unwrap_or_else(|errno| -(errno.into_raw() as i64));
        frame.set_result(result);
        self.write_injected_syscall_frame(task, address, &frame)
    }

    #[cfg(target_arch = "x86_64")]
    fn read_guest_registers(&self, task: &Stopped) -> Result<libc::user_regs_struct, TraceError> {
        let mut regs = task.getregs()?;
        if let Some(address) = self.injected_syscall_frame {
            let frame = self.read_injected_syscall_frame(task, address)?;
            frame.copy_to_user_regs(&mut regs);
        }
        Ok(regs)
    }

    #[cfg(target_arch = "x86_64")]
    fn write_guest_registers(
        &self,
        task: &Stopped,
        regs: &libc::user_regs_struct,
    ) -> Result<(), TraceError> {
        if let Some(address) = self.injected_syscall_frame {
            let mut frame = self.read_injected_syscall_frame(task, address)?;
            let current = self.read_guest_registers(task)?;
            InjectedSyscallFrame::validate_user_regs_update(&current, regs)?;
            if self.global_state.liteinst_runtime.is_some() {
                validate_liteinst_user_regs_update(&current, regs)?;
            }
            frame.copy_from_user_regs(regs);
            self.write_injected_syscall_frame(task, address, &frame)
        } else {
            task.setregs(regs)
        }
    }

    // Only the x86_64 rewritten-trap path sets `injected_syscall_frame`.
    #[cfg(not(target_arch = "x86_64"))]
    fn read_guest_registers(&self, task: &Stopped) -> Result<libc::user_regs_struct, TraceError> {
        task.getregs()
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn write_guest_registers(
        &self,
        task: &Stopped,
        regs: &libc::user_regs_struct,
    ) -> Result<(), TraceError> {
        task.setregs(regs)
    }

    fn get_syscall(&self, task: &Stopped) -> Result<Syscall, TraceError> {
        let regs = task.getregs()?;
        // A checked decode: the filter traces only numbers the syscall table
        // knows (trap-only H0 routes every other patched-site number before
        // this), so an unknown number here is an error, never a panic.
        let nr = Sysno::new(regs.orig_syscall() as i32 as usize).ok_or(Errno::ENOSYS)?;

        let args = regs.args();

        Ok(Syscall::from_raw(
            nr,
            SyscallArgs::new(
                args.0 as usize,
                args.1 as usize,
                args.2 as usize,
                args.3 as usize,
                args.4 as usize,
                args.5 as usize,
            ),
        ))
    }
}

fn set_ret(task: &Stopped, ret: Reg) -> Result<Reg, TraceError> {
    let mut regs = task.getregs()?;
    let old = regs.ret();
    *regs.ret_mut() = ret;
    task.setregs(&regs)?;
    Ok(old)
}

/// Late timer overflow signals discarded at injected syscalls, for tests.
pub(crate) static LATE_TIMER_SIGNALS_DISCARDED: AtomicU64 = AtomicU64::new(0);

/// Live timer overflow signals taken at injected syscalls, for their events to
/// be delivered, for tests.
pub(crate) static LIVE_TIMER_SIGNALS_TAKEN: AtomicU64 = AtomicU64::new(0);

/// Timer overflow signals discarded while the LiteInst patch helper ran, for
/// tests.
pub(crate) static LITEINST_HELPER_TIMER_SIGNALS_DISCARDED: AtomicU64 = AtomicU64::new(0);

/// LiteInst restart landings that interrupted a precise timer's single steps,
/// after which the run loop resolved the landing and the steps continued
/// (`finish_liteinst_restart_landing`), for tests.
pub(crate) static LITEINST_TIMER_STEP_LANDINGS_RESOLVED: AtomicU64 = AtomicU64::new(0);

/// SIGTRAP stops that `handle_sigtrap` resumed without delivering the signal
/// because nothing claimed them, for tests.
pub(crate) static UNCLAIMED_SIGTRAPS_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Canonical marker emitted when a guest-thread task dies of a panic.
///
/// The token is what a harness greps for, in the same spirit as
/// `HERMIT_SKID_OVERSHOOT`; keep it stable. It exists because an exit code
/// alone cannot say *why* a run ended, and this failure mode was expensive
/// precisely because it was unreadable: the run hung, so a panic was
/// indistinguishable from a slow run to every harness that judges by wall time.
const TASK_PANIC_MARKER: &str = "HERMIT_TASK_PANIC";

/// Exit status used when a guest-thread task panics.
///
/// This is rustc's conventional panic status inside the tracer process. An
/// embedding executable may normalize it at an outer process boundary, so the
/// marker above remains the authoritative machine-readable diagnosis.
const TASK_PANIC_EXIT_CODE: i32 = 101;

/// Renders the one-line panic marker. Separate from the exit so it can be
/// tested without ending the test process.
fn format_task_panic_marker(tid: Pid, payload: &(dyn std::any::Any + Send)) -> String {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&'static str>().copied())
        .unwrap_or("<non-string panic payload>");
    // Always exactly one line: a marker that can wrap is a marker a harness
    // cannot grep. The default hook may have written into a test capture
    // buffer; this independent line exists to be machine-read.
    let message: String = message
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    format!(
        "{} tid={} exit={} message={}",
        TASK_PANIC_MARKER,
        tid,
        TASK_PANIC_EXIT_CODE,
        message.trim()
    )
}

/// A guest-thread task died of a panic. End the run, loudly.
///
/// WHY THE PROCESS EXITS RATHER THAN PROPAGATING AN ERROR. Tokio's task harness
/// catches a panic in a `spawn_local` task and parks it in the `JoinHandle`,
/// which nothing polls until `tool_exit`. The run cannot reach `tool_exit`,
/// because by then the tool's scheduler is parked waiting for a turn request
/// this task will never post, and detcore's `Ivar` has no way to report that
/// its writer is gone -- so every other guest thread waits forever and the run
/// hangs until an external timeout kills it. There is no live party left to
/// hand an error to. detcore reached the same conclusion about its own
/// scheduler task and built `immediate_fatal_exit` for exactly this.
///
/// Exiting does not leak the guest: `postspawn` sets `PTRACE_O_EXITKILL`, so
/// the tracees die with the tracer. The terminal-deadlock path already relies
/// on that.
fn guest_task_panic_is_fatal(tid: Pid, payload: Box<dyn std::any::Any + Send>) -> ! {
    // Write directly: eprintln! can stop in libtest's capture buffer, which
    // process::exit never returns to the harness. Keep this marker free of
    // tracing's real wall-clock prefix and preserve the fatal exit on I/O error.
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        format_task_panic_marker(tid, payload.as_ref())
    );
    let _ = std::io::stderr().flush();
    let _ = std::io::stdout().flush();
    std::process::exit(TASK_PANIC_EXIT_CODE)
}

fn log_guest_exit(tid: Pid, pid: Pid, exit_status: ExitStatus) {
    if let ExitStatus::Signaled(signal, core_dumped) = exit_status {
        tracing::error!(
            target: "reverie_ptrace::lifecycle",
            %tid,
            %pid,
            %signal,
            core_dumped,
            "guest terminated by signal"
        );
    }
}

/// Handles a potentially internal error, converting it to an exit status.
async fn handle_internal_error(
    err: Error,
    owner: &Arc<PtracerWaitOwner>,
) -> Result<ExitStatus, reverie::Error> {
    #[cfg(test)]
    crate::tracer::record_fatal_phase_for_test(|| {
        format!("handle_internal_error entered: {err:?}")
    });
    match err {
        Error::Internal(TraceError::Died(zombie))
        | Error::Tracee {
            source: TraceError::Died(zombie),
            ..
        } => crate::tracer::reap_ptracer_zombie(owner, zombie).await,
        Error::Internal(TraceError::Errno(errno)) => Err(errno.into()),
        Error::Tracee {
            operation,
            pid,
            source: TraceError::Errno(errno),
        } => Err(anyhow::anyhow!("{operation} failed for tracee {pid}: {errno}").into()),
        Error::Runtime {
            operation,
            pid,
            message,
        } => Err(anyhow::anyhow!("{operation} failed for tracee {pid}: {message}").into()),
        Error::External(err) => Err(err),
        Error::RunFailed => future::pending().await,
    }
}

/// Helper for canceling handlers.
async fn cancellable<F>(cancel_handler: Arc<AtomicBool>, f: F) -> Option<F::Output>
where
    F: Future,
{
    futures::pin_mut!(f);
    future::poll_fn(|cx| {
        let result = f.as_mut().poll(cx);

        // `tail_inject` sets this while polling `f`, then remains pending. We
        // can cancel the handler in the same poll instead of waking the Tokio
        // task solely to make this future observe its own notification.
        if cancel_handler.swap(false, Ordering::SeqCst) {
            Poll::Ready(None)
        } else {
            result.map(Some)
        }
    })
    .await
}

#[cfg(target_arch = "x86_64")]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum SegfaultTrapInfo {
    Cpuid,
    Rdtscs(Rdtsc),
}

#[cfg(target_arch = "x86_64")]
impl SegfaultTrapInfo {
    /// Check if segfault is called by cpuid/rdtsc trap
    pub fn decode_segfault(insn_at_rip: u64) -> Option<SegfaultTrapInfo> {
        if insn_at_rip & 0xffffu64 == 0xa20fu64 {
            Some(SegfaultTrapInfo::Cpuid)
        } else if insn_at_rip & 0xffffu64 == 0x310fu64 {
            Some(SegfaultTrapInfo::Rdtscs(Rdtsc::Tsc))
        } else if insn_at_rip & 0xffffffu64 == 0xf9010fu64 {
            Some(SegfaultTrapInfo::Rdtscs(Rdtsc::Tscp))
        } else {
            None
        }
    }
}

// restore syscall context when it returns. This is needed because we might
// have injected a different syscall (or arguments) in handle_seccomp.
fn restore_context(
    task: &Stopped,
    context: libc::user_regs_struct,
    retval: Option<Reg>,
    restore_stack: bool,
) -> Result<(), TraceError> {
    let mut regs = task.getregs()?;

    if let Some(ret) = retval {
        *regs.ret_mut() = ret;
    }
    // TODO-HUMAN-REVIEW(PR-103): Review injected parent-stack restoration.
    if restore_stack {
        *regs.stack_ptr_mut() = context.stack_ptr();
    }

    // Restore instruction pointer.
    *regs.ip_mut() = context.ip();

    // Restore syscall arguments.
    regs.set_args(context.args());

    // This is needed when syscall is interrupted by a signal (ERESTARTSYS)
    // we need restore the original syscall number as well because it is
    // possible syscall is reinjected as a different variant, like vfork ->
    // clone, which accepts different arguments.
    *regs.orig_syscall_mut() = context.orig_syscall();

    // The `syscall` instruction clobbers %rcx/%r11. When we injected a syscall
    // (or a different syscall variant) from the private trampoline page, %rcx
    // and %r11 now hold the *trampoline's* return RIP / RFLAGS rather than the
    // guest's. Although the ABI leaves these "undefined" after a syscall, an
    // injection should be transparent, and leaving Reverie's private trampoline
    // address in %rcx would leak a tracer-internal (and potentially
    // nondeterministic) pointer to the guest. Restore them from the guest's own
    // pre-syscall snapshot. (No-op on aarch64.)
    regs.restore_syscall_clobbers(&context);

    task.setregs(&regs)
}

impl<L: Tool + 'static> TracedTask<L> {
    #[cfg(target_arch = "x86_64")]
    async fn cpuid_state(&mut self) -> Result<i64, Errno> {
        use reverie::syscalls::ArchPrctl;
        use reverie::syscalls::ArchPrctlCmd;

        self.inject_with_retry(ArchPrctl::new().with_cmd(ArchPrctlCmd::ARCH_GET_CPUID(None)))
            .await
    }

    #[cfg(target_arch = "x86_64")]
    async fn intercept_cpuid(&mut self) -> Result<(), Errno> {
        use reverie::syscalls::ArchPrctl;
        use reverie::syscalls::ArchPrctlCmd;

        self.inject_with_retry(ArchPrctl::new().with_cmd(ArchPrctlCmd::ARCH_SET_CPUID(0)))
            .await
            .map(|_| ())
    }

    /// Perform the very first setup of a fresh tracee process:
    ///
    /// (1) Set up the special reverie/guest shared page in the tracee.
    ///
    /// (2) Also disables vdso within the guest
    ///
    /// Warning: this function MUTATES guest code to accomplish the modifications, even though this
    /// mutation is undone before it returns.  As a result, it  has an extra precondition.
    ///
    /// Precondition: all threads in the guest process are stopped. Otherwise a guest state may be
    /// executing the instructions that are mutated and may crash (due to problems with incoherent
    /// instruction fetch resulting in non-atomic writes to instructions that straddle cache line
    /// boundaries).
    ///
    /// Precondition: the caller is entitled to execute (blocking, destructive) waitpids against the
    /// target tracee.  This must not race with concurrent asynchronous tasks operating on the same
    /// TID.
    ///
    /// Postcondition: the guest registers and code memory are restored to their original state,
    /// including RIP, but the vdso page and special shared page are modified accordingly.
    #[tracing::instrument(
        target = "reverie_ptrace::lifecycle",
        name = "tracee.initialize",
        level = "debug",
        skip_all,
        fields(pid = %task.pid())
    )]
    pub async fn tracee_preinit(
        &mut self,
        task: Stopped,
        place: PreinitPlace,
    ) -> Result<PreinitOutcome, TraceError> {
        // Injections rebuild their capability through `assume_stopped`. Bind
        // it to this generation, so that once the tracee dies and is reaped,
        // a request refuses instead of reaching a task that reused the TID.
        self.ptracer_waits.bind_stopped(&task);
        self.preinit_generation = Some(task.generation());
        let outcome = self.tracee_preinit_bound(task, place).await;
        self.preinit_generation = None;
        outcome
    }

    async fn tracee_preinit_bound(
        &mut self,
        task: Stopped,
        place: PreinitPlace,
    ) -> Result<PreinitOutcome, TraceError> {
        // A forked child can initialize a replacement image too. It must not
        // consume or overwrite the session root's held-stop cleanup lease.
        let held_root_stop = self.liteinst_root_stop_slot(&task);
        #[cfg(test)]
        let preinit_point = self.global_state.preinit_point_for_test.clone();
        let reject_activation_signals = self.global_state.liteinst_runtime.is_some();
        let unexpected_preinit_signal = Arc::new(StdMutex::new(None));
        #[cfg(test)]
        let pause_preinit_step = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|runtime| runtime.pause_preinit_step.clone());
        #[cfg(test)]
        let force_preinit_signal_once = (self.liteinst_runtime.lock().unwrap().phase
            == LiteinstRuntimePhase::Waiting)
            .then(|| {
                self.global_state
                    .liteinst_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.force_preinit_signal_once.clone())
            })
            .flatten();

        fn arm_preinit_stop(
            held_root_stop: &Option<Arc<StdMutex<Option<HeldRootStop>>>>,
            task: &Stopped,
            event: &Event,
        ) {
            if let Some(slot) = held_root_stop {
                let previous = slot
                    .lock()
                    .unwrap()
                    .replace(HeldRootStop::from_event(task, event));
                debug_assert!(
                    previous.is_none(),
                    "rearmed an undisarmed preinit stop lease"
                );
            }
        }

        #[cfg(test)]
        async fn pause_preinit(
            pause: &Option<(usize, mpsc::UnboundedSender<Pid>)>,
            step: usize,
            task: &Stopped,
        ) {
            if let Some((target, sender)) = pause
                && *target == step
            {
                let _ = sender.send(task.pid());
                future::pending::<()>().await;
            }
        }

        #[cfg(test)]
        if self
            .global_state
            .liteinst_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.fail_preinit)
        {
            return Err(Errno::EPERM.into());
        }

        type SavedInstructions = [u8; 8];

        /// The test-only hooks `setup_special_mmap_page` consults.
        #[cfg(test)]
        struct PreinitTestHooks<'a> {
            pause_preinit_step: &'a Option<(usize, mpsc::UnboundedSender<Pid>)>,
            force_preinit_signal_once: &'a Option<Arc<AtomicBool>>,
            preinit_point: &'a Option<PreinitPointForTest>,
        }

        /// Helper function for tracee_preinit that does the core work.
        async fn setup_special_mmap_page(
            task: Stopped,
            waits: &Arc<PtracerWaitOwner>,
            saved_regs: &libc::user_regs_struct,
            held_root_stop: &Option<Arc<StdMutex<Option<HeldRootStop>>>>,
            reject_activation_signals: bool,
            unexpected_signal: &Arc<StdMutex<Option<Signal>>>,
            #[cfg(test)] hooks: PreinitTestHooks<'_>,
        ) -> Result<PreinitOutcome, TraceError> {
            #[cfg(test)]
            let PreinitTestHooks {
                pause_preinit_step,
                force_preinit_signal_once,
                preinit_point,
            } = hooks;
            // NOTE: This point in the code assumes that a specific instruction
            // sequence "SYSCALL; INT3", has been patched into the guest, and
            // that RIP points to the syscall.
            let mut regs = *saved_regs;

            let page_addr = cp::PRIVATE_PAGE_OFFSET;

            *regs.syscall_mut() = Sysno::mmap as Reg;
            *regs.orig_syscall_mut() = regs.syscall();
            regs.set_args((
                page_addr as Reg,
                cp::PRIVATE_PAGE_SIZE as Reg,
                (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as Reg,
                (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as Reg,
                -1i64 as Reg,
                0,
            ));

            task.setregs(&regs)?;
            // Execute the injected mmap call.
            let mut running = RootStopLease::new(task, held_root_stop.clone()).step(None)?;
            #[cfg(test)]
            at_preinit_point(
                preinit_point,
                running.pid(),
                || running.terminal_cleanup(),
                PreinitPoint::MmapStepped,
            );
            #[cfg(test)]
            if PARKED_PREINIT.with(|parked| parked.get()) == Some(running.pid()) {
                PARKED_PREINIT.with(|parked| parked.set(None));
                future::pending::<()>().await;
            }

            // loop until second breakpoint hit after injected syscall.
            #[cfg(test)]
            let mut step = 0;
            let mut task = loop {
                let (task, event) = match running.next_state_with_owner(waits).await? {
                    Wait::Stopped(task, event) => (task, event),
                    Wait::Exited(pid, exit_status) => {
                        return Ok(PreinitOutcome::Exited(pid, exit_status));
                    }
                };
                arm_preinit_stop(held_root_stop, &task, &event);
                #[cfg(test)]
                let forced_external_sigtrap = event == Event::Signal(Signal::SIGTRAP)
                    && force_preinit_signal_once
                        .as_ref()
                        .is_some_and(|force_once| force_once.load(Ordering::SeqCst));
                #[cfg(not(test))]
                let forced_external_sigtrap = false;
                #[cfg(test)]
                if let Some((target, sender)) = pause_preinit_step
                    && *target == step
                {
                    let _ = sender.send(task.pid());
                    future::pending::<()>().await;
                }
                #[cfg(test)]
                {
                    step += 1;
                }
                match event {
                    Event::Signal(Signal::SIGTRAP) => {
                        let expected_rip = saved_regs
                            .ip()
                            .checked_add(cp::SYSCALL_INSTR_SIZE as u64)
                            .ok_or(Errno::EOVERFLOW)?;
                        if reject_activation_signals
                            && !is_expected_breakpoint_trap(
                                &task,
                                expected_rip,
                                forced_external_sigtrap,
                            )?
                        {
                            #[cfg(test)]
                            if forced_external_sigtrap
                                && let Some(force_once) = force_preinit_signal_once.as_ref()
                            {
                                force_once.store(false, Ordering::SeqCst);
                            }
                            *unexpected_signal.lock().unwrap() = Some(Signal::SIGTRAP);
                            return Err(Errno::EPROTO.into());
                        }
                        break task;
                    }
                    Event::Signal(sig) => {
                        if reject_activation_signals {
                            *unexpected_signal.lock().unwrap() = Some(sig);
                            return Err(Errno::EPROTO.into());
                        }
                        // We can catch spurious signals here, such as SIGWINCH.
                        // All we can do is skip over them.
                        tracing::debug!(
                            "[{}] Skipping {:?} during initialization",
                            task.pid(),
                            event
                        );
                        running = RootStopLease::new(task, held_root_stop.clone()).resume(sig)?;
                    }
                    Event::Seccomp => {
                        // Injected mmap trapped. We may not necessarily
                        // intercept a seccomp event here if the tool hasn't
                        // subscribed to the mmap syscall.
                        running = RootStopLease::new(task, held_root_stop.clone()).resume(None)?;
                    }
                    unknown => {
                        panic!("task {} returned unknown event {:?}", task.pid(), unknown);
                    }
                }
            };

            // Make sure we got our desired address.
            assert_eq!(
                Errno::from_ret(task.getregs()?.ret() as usize)?,
                page_addr,
                "Could not mmap address {}",
                page_addr
            );

            #[cfg(test)]
            at_preinit_point(
                preinit_point,
                task.pid(),
                || task.terminal_cleanup(),
                PreinitPoint::MmapReturned,
            );
            // Write through the task's own capability, which refuses once
            // its TID is being reaped, so the page contents can never land
            // in a task that reused the TID.
            let page = AddrMut::from_raw(page_addr).ok_or(Errno::EFAULT)?;
            let populated = task.write_exact(page, &cp::mmap_page_contents());
            memory_request(&task, populated)?;

            // Restore our saved registers, including our instruction pointer.
            task.setregs(saved_regs)?;
            Ok(PreinitOutcome::Ready(task))
        }

        /// Put the guest into the weird state where it has an
        /// "INT3;SYSCALL;INT3" patched into the code wherever RIP happens to be
        /// pointing. It leaves RIP pointing at the syscall instruction. This
        /// allows forcible injection of syscalls into the guest.
        async fn establish_injection_state(
            mut task: Stopped,
            #[cfg(test)] preinit_point: &Option<PreinitPointForTest>,
        ) -> Result<(Stopped, libc::user_regs_struct, SavedInstructions), TraceError> {
            #[cfg(target_arch = "x86_64")]
            const SYSCALL_BP: SavedInstructions = [
                0x0f, 0x05, // syscall
                0xcc, // int3
                0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
            ];

            #[cfg(target_arch = "aarch64")]
            const SYSCALL_BP: SavedInstructions = [
                0x01, 0x00, 0x00, 0xd4, // svc 0
                0x20, 0x00, 0x20, 0xd4, // brk 1
            ];

            // Save the original registers so we can restore them later.
            let regs = task.getregs()?;
            #[cfg(test)]
            at_preinit_point(
                preinit_point,
                task.pid(),
                || task.terminal_cleanup(),
                PreinitPoint::RegsSaved,
            );

            // Saved instruction memory
            let ip = AddrMut::from_raw(regs.ip() as usize).ok_or(Errno::EFAULT)?;
            let saved: SavedInstructions = memory_request(&task, task.read_value(ip))?;
            #[cfg(test)]
            at_preinit_point(
                preinit_point,
                task.pid(),
                || task.terminal_cleanup(),
                PreinitPoint::CodeRead,
            );

            // Patch the tracee at the current instruction pointer.
            //
            // NOTE: `process_vm_writev` cannot write to write-protected pages,
            // but `PTRACE_POKEDATA` can! Thus, we need to make sure we only
            // write one word-sized chunk at a time. Luckily, the instructions
            // we want to inject fit inside of just one 64-bit word.
            let patched = task.write_value(ip.cast(), &SYSCALL_BP);
            memory_request(&task, patched)?;

            Ok((task, regs, saved))
        }

        /// Undo the effects of `establish_injection_state` and put the program
        /// code memory and instruction pointer back to normal.
        fn remove_injection_state(
            task: &mut Stopped,
            regs: libc::user_regs_struct,
            saved: SavedInstructions,
        ) -> Result<(), TraceError> {
            // NOTE: Again, because `process_vm_writev` cannot write to
            // write-protected pages, we must write in word-sized chunks with
            // PTRACE_POKEDATA.
            let ip = AddrMut::from_raw(regs.ip() as usize).ok_or(Errno::EFAULT)?;
            let restored = task.write_value(ip, &saved);
            memory_request(task, restored)?;
            task.setregs(&regs)?;
            Ok(())
        }

        let (task, regs, prev_state) = establish_injection_state(
            task,
            #[cfg(test)]
            &preinit_point,
        )
        .await?;
        let outcome = setup_special_mmap_page(
            task,
            &self.ptracer_waits,
            &regs,
            &held_root_stop,
            reject_activation_signals,
            &unexpected_preinit_signal,
            #[cfg(test)]
            PreinitTestHooks {
                pause_preinit_step: &pause_preinit_step,
                force_preinit_signal_once: &force_preinit_signal_once,
                preinit_point: &preinit_point,
            },
        )
        .await;
        if let Some(sig) = unexpected_preinit_signal.lock().unwrap().take() {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::UnexpectedPreinitSignal,
                Error::runtime(
                    self.tid(),
                    "reject unexpected LiteInst activation signal",
                    format!(
                        "received {sig} before the required preload handshake completed: tracee pre-initialization observed an unexpected nested signal"
                    ),
                ),
            );
        }
        let mut task = match outcome? {
            PreinitOutcome::Ready(task) => task,
            exited @ PreinitOutcome::Exited(..) => return Ok(exited),
        };
        #[cfg(test)]
        pause_preinit(&pause_preinit_step, 1, &task).await;
        #[cfg(test)]
        at_preinit_point(
            &preinit_point,
            task.pid(),
            || task.terminal_cleanup(),
            PreinitPoint::PagePopulated,
        );

        // Restore registers after adding our temporary injection state.
        remove_injection_state(&mut task, regs, prev_state)?;

        if vdso::is_patch_required(&self.global_state.subscriptions) {
            let subscriptions = self.global_state.subscriptions.clone();
            #[cfg(test)]
            let vdso_hook = preinit_point.clone().map(|hook| {
                let pid = task.pid();
                let terminal = task.terminal_cleanup();
                vdso::vdso_writable_hook_for_test(
                    pid.as_raw(),
                    Box::new(move || hook(pid, &terminal, PreinitPoint::VdsoWritable)),
                )
            });
            let patched = vdso::vdso_patch(self, &subscriptions).await;
            #[cfg(test)]
            drop(vdso_hook);
            match patched {
                Ok(()) => {}
                // A tracee that died during the patch reports a bare errno.
                Err(reverie::Error::Errno(errno)) => match dead_or(&task, errno.into()) {
                    died @ TraceError::Died(_) => return Err(died),
                    error => panic!("unable to patch vdso: {error:?}"),
                },
                Err(error) => panic!("unable to patch vdso: {error:?}"),
            }
        }
        // Give the guest the vDSO and auxiliary values every backend gives its
        // guests, in place of the host's. Only a freshly exec'd image has
        // argc, argv, envp and the auxv at its stack pointer; before the exec
        // the stack is the launcher's (or a spawned function's) own, and
        // reading it as an initial process stack would scan and overwrite
        // unrelated memory.
        #[cfg(target_arch = "x86_64")]
        if place == PreinitPlace::AtExec
            && self
                .global_state
                .subscriptions
                .iter_syscalls()
                .next()
                .is_some()
        {
            #[cfg(test)]
            CANONICALIZED_FOR_TEST
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((std::thread::current().id(), task.pid().as_raw()));
            match vdso::canonicalize_new_image(self, regs.rsp).await {
                Ok(()) => {}
                // A tracee that died meanwhile reports a bare errno.
                Err(reverie::Error::Errno(errno)) => match dead_or(&task, errno.into()) {
                    died @ TraceError::Died(_) => return Err(died),
                    error => {
                        panic!("unable to give the guest its canonical vdso and auxv: {error:?}")
                    }
                },
                Err(error) => {
                    panic!("unable to give the guest its canonical vdso and auxv: {error:?}")
                }
            }
        }
        #[cfg(test)]
        pause_preinit(&pause_preinit_step, 2, &task).await;
        #[cfg(test)]
        at_preinit_point(
            &preinit_point,
            task.pid(),
            || task.terminal_cleanup(),
            PreinitPoint::TrampolineUnprotected,
        );

        // Protect our trampoline page from being written to. We won't need to
        // change this again for the lifetime of the guest process.
        self.inject_with_retry(
            Mprotect::new()
                .with_addr(AddrMut::from_raw(cp::TRAMPOLINE_BASE))
                .with_len(cp::TRAMPOLINE_SIZE)
                .with_protection(ProtFlags::PROT_READ | ProtFlags::PROT_EXEC),
        )
        .await?;
        #[cfg(test)]
        pause_preinit(&pause_preinit_step, 3, &task).await;

        // Try to intercept cpuid instructions on x86_64
        #[cfg(target_arch = "x86_64")]
        if self.global_state.subscriptions.has_cpuid() {
            self.has_cpuid_interception = match self.cpuid_state().await {
                Ok(initial_state @ (0 | 1)) => match self.intercept_cpuid().await {
                    Ok(()) => match self.cpuid_state().await {
                        Ok(0) => true,
                        Ok(state) => {
                            tracing::error!(
                                state,
                                "ARCH_SET_CPUID succeeded but ARCH_GET_CPUID did not report the disabled state; continuing without CPUID interception"
                            );
                            false
                        }
                        Err(err) => {
                            tracing::error!(
                                "Unable to verify ARCH_SET_CPUID with ARCH_GET_CPUID: {}; continuing without CPUID interception",
                                err
                            );
                            false
                        }
                    },
                    Err(Errno::ENODEV) => {
                        tracing::error!(
                            initial_state,
                            "ARCH_GET_CPUID reported a valid state, but ARCH_SET_CPUID returned ENODEV. The kernel exposes CPUID state without hardware faulting support. On AMD hosts, use Linux 6.17+ upstream or a kernel with CPUID faulting backported; continuing without CPUID interception"
                        );
                        false
                    }
                    Err(err) => {
                        tracing::error!(
                            "Unable to disable CPUID after ARCH_GET_CPUID reported a valid state: {}; continuing without CPUID interception",
                            err
                        );
                        false
                    }
                },
                Ok(state) => {
                    tracing::error!(
                        state,
                        "ARCH_GET_CPUID returned an unexpected state; continuing without CPUID interception"
                    );
                    false
                }
                Err(Errno::ENODEV) => {
                    tracing::error!(
                        "CPUID faulting is unavailable: arch_prctl(ARCH_GET_CPUID) returned ENODEV. On AMD hosts, use Linux 6.17+ upstream or a kernel with CPUID faulting backported; continuing without CPUID interception"
                    );
                    false
                }
                Err(err) => {
                    tracing::error!(
                        "Unable to query CPUID faulting with arch_prctl(ARCH_GET_CPUID): {}; continuing without CPUID interception",
                        err
                    );
                    false
                }
            };
        }
        #[cfg(test)]
        pause_preinit(&pause_preinit_step, 4, &task).await;

        // Restore registers again after we've injected syscalls so that we
        // don't leave the return value register (%rax) in a dirty state.
        task.setregs(&regs)?;

        Ok(PreinitOutcome::Ready(task))
    }

    /// Runs [`Self::tracee_preinit`] on the root tracee before its run loop
    /// exists, and turns a death during it into its exit.
    ///
    /// Two things the run loop does for the exec-time initialization are
    /// missing here, so without them a SIGKILL during this one hangs the
    /// spawn:
    /// - An injected syscall that sees the tracee die aborts through the
    ///   `next_state` channel, which only the run loop reads.
    /// - The tracee's `PTRACE_EVENT_EXIT` stop is published only to its exit
    ///   future, which only the run loop polls. Until a resume from that stop,
    ///   neither a wait on the tracee nor [`safeptrace::Zombie::reap`] returns.
    ///
    /// So this races the initialization against both. An abort carrying the
    /// tracee's exit or death ends it; so does the exit stop, which this
    /// claims and resumes to receive the final status. A [`TraceError::Died`]
    /// returned by the initialization itself is finished the same way. See
    /// <https://github.com/rrnewton/reverie/issues/760>.
    pub(crate) async fn postspawn_preinit(
        &mut self,
        task: Stopped,
    ) -> Result<PreinitOutcome, TraceError> {
        enum Raced {
            Done(Result<PreinitOutcome, TraceError>),
            Aborted(Option<Result<Wait, TraceError>>),
            ExitStop(Stopped),
        }

        let mut aborted = self
            .next_state_rx
            .take()
            .expect("the root's next-state receiver is unused before its run loop");
        // The exit stop of this tracee generation. Its claim fails only once
        // the final status is published, which a wait reports instead.
        let mut exit_stop = self.ptracer_waits.exit_stopped(&task);
        // This generation, to reap after its exit. An injection reports a
        // death through a task it rebuilds by TID, which is unbound once the
        // tracee has exited, so that report cannot reap it. This handle is
        // only waited on, through its own notifier event, never named to
        // ptrace: after the exit its numeric PID may name another tracee.
        let generation = task.generation().assume_stopped();
        let raced = {
            let preinit = self.tracee_preinit(task, PreinitPlace::BeforeExec).fuse();
            let abort = aborted.recv().fuse();
            let exit = async {
                match (&mut exit_stop).await {
                    Ok(stopped) => stopped,
                    Err(_) => future::pending().await,
                }
            }
            .fuse();
            futures::pin_mut!(preinit, abort, exit);
            futures::select_biased! {
                outcome = preinit => Raced::Done(outcome),
                next = abort => Raced::Aborted(next),
                stopped = exit => Raced::ExitStop(stopped),
            }
        };
        self.next_state_rx = Some(aborted);
        // A lost race drops the initialization before it unbinds.
        self.preinit_generation = None;
        match raced {
            Raced::Done(Err(TraceError::Died(_))) => {}
            Raced::Done(outcome) => return outcome,
            Raced::Aborted(Some(Ok(Wait::Exited(pid, exit_status)))) => {
                return Ok(PreinitOutcome::Exited(pid, exit_status));
            }
            Raced::Aborted(Some(Err(TraceError::Died(_)))) => {}
            Raced::Aborted(Some(Err(error))) => return Err(error),
            // Initialization makes no exec, so no abort hands over a stop.
            Raced::Aborted(Some(Ok(Wait::Stopped(..)))) | Raced::Aborted(None) => {
                return Err(Errno::EPROTO.into());
            }
            Raced::ExitStop(stopped) => return self.preinit_exit_stop(stopped).await,
        }
        // A death the initialization saw first: the tracee is in its exit
        // stop or on its way there, unless it has already exited.
        match exit_stop.await {
            Ok(stopped) => self.preinit_exit_stop(stopped).await,
            // The exit stop expired, so its final status is published or
            // about to be. This waits for it on the generation's own event,
            // and stays pending until it is published.
            Err(_) => {
                let mut wait = self.ptracer_waits.wait_owned_stopped(generation);
                loop {
                    match (&mut wait).await {
                        Ok(Wait::Exited(pid, exit_status)) => {
                            break Ok(PreinitOutcome::Exited(pid, exit_status));
                        }
                        Ok(Wait::Stopped(stopped, Event::Exit)) => {
                            break self.preinit_exit_stop(stopped).await;
                        }
                        // Only a nonleader's exec can follow an exit stop.
                        Ok(Wait::Stopped(_, Event::Exec(_))) => break Err(Errno::EPROTO.into()),
                        // A stop queued before the exit stop, which the tracee
                        // left to reach it (as in the run loop's exit wait).
                        Ok(Wait::Stopped(stale, _)) => {
                            wait = self.ptracer_waits.wait_owned_stopped(stale)
                        }
                        // The wait keeps the generation and settles only on
                        // its actual next state.
                        Err(OwnedWaitError::Died) => {}
                        Err(OwnedWaitError::Errno(errno)) => {
                            break Err(errno.into());
                        }
                        Err(OwnedWaitError::Completed) => {
                            break Err(Errno::EPROTO.into());
                        }
                    }
                }
            }
        }
    }

    /// Resumes the root from its exit stop during initialization and returns
    /// its final status.
    async fn preinit_exit_stop(&self, stopped: Stopped) -> Result<PreinitOutcome, TraceError> {
        let held_root_stop = self.liteinst_root_stop_slot(&stopped);
        let mut wait =
            match Self::wait_after_exit_event(stopped, &self.ptracer_waits, held_root_stop).await {
                Ok(Wait::Exited(pid, exit_status)) => {
                    return Ok(PreinitOutcome::Exited(pid, exit_status));
                }
                // The notifier publishes the exit stop out of band, so a stop
                // queued before it (initialization's single-step trap) can still
                // be at the front of the queue. The tracee left that stop to reach
                // its exit, so wait again without resuming it.
                Ok(Wait::Stopped(stale, event)) if Self::preinit_stale_stop(&event) => {
                    self.ptracer_waits.wait_owned_stopped(stale)
                }
                // Only a nonleader's exec can follow an exit stop, and the root
                // has no other thread yet.
                Ok(Wait::Stopped(..)) => return Err(Errno::EPROTO.into()),
                // Initialization had already resumed it from the stop.
                Err(TraceError::Died(zombie)) => {
                    let pid = zombie.pid();
                    return Ok(PreinitOutcome::Exited(
                        pid,
                        self.ptracer_waits.reap_zombie(zombie).await?,
                    ));
                }
                Err(error) => return Err(error),
            };
        loop {
            match (&mut wait).await {
                Ok(Wait::Exited(pid, exit_status)) => {
                    break Ok(PreinitOutcome::Exited(pid, exit_status));
                }
                Ok(Wait::Stopped(stale, event)) if Self::preinit_stale_stop(&event) => {
                    wait = self.ptracer_waits.wait_owned_stopped(stale);
                }
                // The exit stop was resumed above.
                Ok(Wait::Stopped(..)) => break Err(Errno::EPROTO.into()),
                // The wait keeps the generation and settles only on its
                // actual next state.
                Err(OwnedWaitError::Died) => {}
                Err(OwnedWaitError::Errno(errno)) => break Err(errno.into()),
                Err(OwnedWaitError::Completed) => break Err(Errno::EPROTO.into()),
            }
        }
    }

    /// Whether `event` is an ordinary stop that a tracee in its exit stop has
    /// already left, rather than the exit stop or an exec that replaced it.
    fn preinit_stale_stop(event: &Event) -> bool {
        *event != Event::Exit && !matches!(event, Event::Exec(_))
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_cpuid(
        &mut self,
        mut regs: libc::user_regs_struct,
    ) -> Result<libc::user_regs_struct, TraceError> {
        let eax = regs.rax as u32;
        let ecx = regs.rcx as u32;
        let result = self
            .process_state
            .clone()
            .handle_cpuid_event(self, eax, ecx)
            .await;
        let cpuid = self
            .ordinary_callback_errno("ptrace cpuid callback", result)
            .await?;
        regs.rax = cpuid.eax as u64;
        regs.rbx = cpuid.ebx as u64;
        regs.rcx = cpuid.ecx as u64;
        regs.rdx = cpuid.edx as u64;
        regs.rip += 2;
        self.ordinary_trace_continuation()?;
        self.timer.finalize_requests();
        Ok(regs)
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_rdtscs(
        &mut self,
        mut regs: libc::user_regs_struct,
        request: Rdtsc,
    ) -> Result<libc::user_regs_struct, TraceError> {
        let result = self
            .process_state
            .clone()
            .handle_rdtsc_event(self, request)
            .await;
        let retval = self
            .ordinary_callback_errno("ptrace rdtsc callback", result)
            .await?;
        regs.rax = retval.tsc & 0xffff_ffffu64;
        regs.rdx = retval.tsc >> 32;
        match request {
            Rdtsc::Tsc => {
                regs.rip += 2;
            }
            Rdtsc::Tscp => {
                regs.rip += 3;
                regs.rcx = retval.aux.unwrap_or(0) as u64;
            }
        }
        self.ordinary_trace_continuation()?;
        self.timer.finalize_requests();
        Ok(regs)
    }

    /// Whether a signal-delivery stop reports this thread's own unconsumed
    /// precise-timer overflow notification, which must never be delivered to
    /// the guest. A match is recorded as consumed.
    fn consume_own_timer_overflow(&mut self, task: &Stopped) -> Result<bool, TraceError> {
        let siginfo = task.getsiginfo()?;
        self.timer
            .consume_overflow_signal(&siginfo)
            .map_err(TraceError::Errno)
    }

    /// Takes this thread's own precise-timer overflow notification that a
    /// signal-delivery stop inside an injected syscall reports. See
    /// [`Timer::take_overflow_signal`].
    fn take_own_timer_notification(
        &mut self,
        task: &Stopped,
    ) -> Result<Option<OwnNotification>, TraceError> {
        let siginfo = task.getsiginfo()?;
        self.timer
            .take_overflow_signal(&siginfo)
            .map_err(TraceError::Errno)
    }

    /// Returns `true` if the signal was actually meant for the timer, and
    /// therefore should not be forwarded to the tool / guest.
    async fn handle_timer(&mut self, task: Stopped) -> Result<(bool, Stopped), TraceError> {
        self.drive_timer(task, None).await
    }

    /// Drives a timer event to completion from its timer signal, or from what
    /// of it a disregarded stop left `unfinished`, and makes the Tool's timer
    /// callback.
    async fn drive_timer(
        &mut self,
        task: Stopped,
        unfinished: Option<Unfinished>,
    ) -> Result<(bool, Stopped), TraceError> {
        let armer = self.liteinst_root_stop_armer(&task);
        let held_root_stop = armer
            .as_ref()
            .map(|armer| Arc::clone(&armer.held_root_stop));
        let mut step = move |task| RootStopLease::new(task, held_root_stop.clone()).step(None);
        let newborn_owner = self.global_state.newborn_owner();
        let mut observe = |wait: &Wait| {
            if let Wait::Stopped(task, event) = wait {
                // A step can decode a new child. `HandleFailure::Event` then
                // hands it to `abort`, and a cancellation can drop the run
                // loop before the loop-top registration. Retain it here,
                // before arming, in the order `arm_liteinst_wait` uses.
                newborn_owner.register(task.pid(), event);
                #[cfg(test)]
                record_timer_decoded_fork_for_test(task, event);
                if let Some(armer) = armer.as_ref() {
                    armer.arm(task, event)?;
                }
            }
            Ok(())
        };
        let result = match unfinished {
            None => {
                self.timer
                    .handle_signal(task, &mut step, &mut observe, &self.ptracer_waits)
                    .await
            }
            Some(unfinished) => {
                self.timer
                    .continue_stepping(
                        task,
                        unfinished,
                        &mut step,
                        &mut observe,
                        &self.ptracer_waits,
                    )
                    .await
            }
        };
        let task = match result {
            Err(HandleFailure::ImproperSignal(task)) => return Ok((false, task)),
            Err(HandleFailure::Cancelled(task)) => return Ok((true, task)),
            Err(HandleFailure::TraceError(e)) => {
                #[cfg(test)]
                crate::tracer::record_fatal_phase_for_test(|| {
                    format!("handle_timer TraceError: {e:?}")
                });
                if self.ordinary_failure_enabled()
                    && let TraceError::Errno(errno) = &e
                {
                    // Keep the actual timer/query errno before the generic
                    // signal-delivery context projects it into a message.
                    // The existing task owner still owns physical cleanup.
                    self.publish_ordinary_failure("ptrace timer signal", (*errno).into());
                }
                return Err(e);
            }
            Err(HandleFailure::Event(wait)) => self.abort(Ok(wait)).await,
            Err(HandleFailure::SeccompStop(task)) => {
                // A step onto a traced syscall. Trap-only must first refuse a
                // patched site carrying an Allow-class number (O4 rule 4)
                // instead of re-dispatching it; plain ptrace re-dispatches.
                #[cfg(test)]
                trap_only::record_stepped_seccomp_for_test(task.pid());
                self.trap_only_stepped_seccomp(&task)?;
                self.abort(Ok(Wait::Stopped(task, Event::Seccomp))).await
            }
            Ok(task) => task,
        };
        #[cfg(test)]
        if let Some(sender) = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|runtime| runtime.pause_precise_timer_step.as_ref())
        {
            let _ = sender.send(task.pid());
            future::pending::<()>().await;
        }
        self.process_state.clone().handle_timer_event(self).await;
        self.ordinary_trace_continuation()?;
        self.timer.finalize_requests();
        Ok((true, task))
    }

    /// Finishes, before the guest resumes, what of the timer event a
    /// disregarded stop left (`disregarded`, from `Timer::disregard_stop`), or
    /// a notification an injection took (`Timer::take_notification`), by
    /// driving it from this stop. A guest signal held for the resume instead
    /// retires the event (`Timer::retire`); see `handle_injected_syscall`.
    async fn finish_disregarded_timer(
        &mut self,
        task: Stopped,
        disregarded: Option<Unfinished>,
    ) -> Result<Stopped, TraceError> {
        if self.pending_signal.is_some() {
            self.timer.retire()?;
            return Ok(task);
        }
        match disregarded.or_else(|| self.timer.take_notification()) {
            Some(unfinished) => Ok(self.drive_timer(task, Some(unfinished)).await?.1),
            None => Ok(task),
        }
    }

    /// Handle a state change in the guest, and leave it in a stopped state.
    /// Return the signal that the process would be resumed with, if any.
    ///
    /// Preconditions:
    ///  * running on the ptracer pthread
    ///
    /// Postconditions:
    ///  * guest thread may or may not be stopped, depending on value of GuestNext
    async fn handle_stop_event(&mut self, stopped: Stopped, event: Event) -> Result<Wait, Error> {
        self.latest_injection_stop = None;
        let unreported_stop_signal = self.unreported_stop_signal.take();
        // A trap-only seccomp stop may be the int 0x80 stop of an Allow-class
        // number at a patched site, or of a foreign int 0x80, neither of
        // which plain ptrace produces: they must not advance the timer's
        // cancellation state (O4 rule 3), so `trap_only_route` observes
        // itself exactly the seccomp stops plain ptrace also reports.
        if !(self.trap_only.is_some() && matches!(event, Event::Seccomp)) {
            self.timer.observe_event(&event);
        }
        // The guest can remove a timer notification between two stops without
        // an injection seeing the queue. See `untraced_syscall`. This reads
        // the kernel's pending queue, not a Tool-visible event, so it runs at
        // every stop, the trap-only ones included.
        self.timer.expire_overflow_records(&stopped);
        let tid = self.tid();
        if matches!(event, Event::Seccomp) {
            self.trap_only_forget_reraised_stops();
        }

        #[cfg(test)]
        if let Some((pause, sender)) = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|runtime| runtime.pause_root_stop.as_ref())
        {
            let selected = match &event {
                Event::Seccomp => match pause {
                    RootStopPause::Seccomp => true,
                    RootStopPause::Signal(_) => false,
                },
                Event::Signal(actual) => match pause {
                    RootStopPause::Seccomp => false,
                    RootStopPause::Signal(expected) => expected == actual,
                },
                Event::NewChild(..)
                | Event::Exec(_)
                | Event::VforkDone
                | Event::Exit
                | Event::Stop
                | Event::Syscall => false,
            };
            if selected {
                let _ = sender.send(stopped.pid());
                future::pending::<()>().await;
            }
        }

        self.ordinary_continuation()?;
        let result = match event {
            Event::Signal(sig) => self
                .handle_signal(stopped, sig, unreported_stop_signal == Some(sig))
                .await
                .tracee_context(tid, "handle signal-delivery stop"),
            Event::Exec(former_tid) => self
                .handle_exec_event(stopped, former_tid)
                .await
                .tracee_context(tid, "handle exec stop"),
            Event::Seccomp => self.handle_seccomp(stopped).await,
            Event::NewChild(op, child) => {
                // A trap-only tail hop that ended at this stop restores both
                // tasks from the patched site's view, exactly as the inject
                // path (`trap_only_inject_hop`) does: the parent without rax,
                // which the kernel writes when the call returns (plain ptrace
                // restores nothing here, so a vfork parent still shows the
                // entry's -ENOSYS at its vfork-done stop), and the child from
                // the view.
                let (context, child_context) = match self.trap_only_take_new_child_view() {
                    Some(view) => {
                        restore_context(&stopped, view, None, false)
                            .tracee_context(tid, "restore trap-only tail parent")?;
                        (None, Some(view))
                    }
                    None => (None, None),
                };
                self.dispatch_new_task(op, stopped, child, context, child_context)
                    .await
                    .tracee_context(tid, "handle new tracee stop")
            }
            Event::VforkDone => self
                .handle_vfork_done_event(stopped)
                .await
                .tracee_context(tid, "handle vfork completion stop"),
            task_state => panic!("unknown task state for tracee {}: {:?}", tid, task_state),
        };
        // Unless its handling disregarded it, the stop decided the timer event.
        self.timer.settle_stop();
        result
    }

    async fn get_stop_tx(&self) -> Option<(Arc<AtomicBool>, mpsc::Sender<(Pid, Suspended)>)> {
        for child in self.child_threads.lock().await.deref_mut().into_iter() {
            if child.id() == self.tid() {
                return Some((child.suspended.clone(), child.wait_all_stop_tx.take()?));
            }
        }
        None
    }

    // TODO-HUMAN-REVIEW(PR-103): Review rewritten rt_sigreturn tail execution.
    #[cfg(target_arch = "x86_64")]
    async fn resume_injected_rt_sigreturn(
        &mut self,
        task: Stopped,
        frame: &InjectedSyscallFrame,
    ) -> Result<Wait, TraceError> {
        let mut regs = task.getregs()?;
        frame.copy_to_user_regs(&mut regs);
        *regs.syscall_mut() = Sysno::rt_sigreturn as Reg;
        *regs.orig_syscall_mut() = Sysno::rt_sigreturn as Reg;

        // rt_sigreturn consumes the signal frame at the original guest stack
        // pointer and does not return to its caller. Run it from Reverie's
        // seccomp-allowed private page, then follow the restored guest state.
        *regs.ip_mut() = cp::PRIVATE_PAGE_OFFSET as Reg;
        task.setregs(&regs)?;
        self.resume_stopped(task, None)?
            .next_state_with_owner(&self.ptracer_waits)
            .await
    }

    // TODO-HUMAN-REVIEW(PR-102): Review rewritten-syscall dispatch and result handling.
    //
    // `restart_rip` is the address of the LiteInst runtime's trap `int3` for a
    // host-hybrid trap, and `None` for an e9patch marker trap. With it, a Linux
    // restart result rewinds the controller to that `int3` instead of writing
    // the private code into the guest frame; see `restart_liteinst_syscall`.
    #[cfg(target_arch = "x86_64")]
    async fn handle_injected_syscall(
        &mut self,
        task: Stopped,
        frame_address: usize,
        trap_rflags: u64,
        restart_rip: Option<u64>,
    ) -> Result<Wait, TraceError> {
        self.injected_tail_result = None;
        let mut frame = self.read_injected_syscall_frame(&task, frame_address)?;
        let syscall = frame.syscall();
        let (nr, args) = syscall.into_parts();
        // AUTONOMOUS-BOT-IMPLEMENTED
        if nr == Sysno::rt_sigreturn {
            // The trap makes no Tool callback. More than the keep margin
            // (`PmuConfig::keep_margin`) short of a precise event's target,
            // before the programming can pass its period on any supported
            // processor, it leaves the timer event as it was, and the
            // notification, yet to come, reaches the restored context and
            // delivers the event. Nothing of the event is continued across
            // the context switch, so closer to the target, where host timing
            // decides whether the notification is still pending, was taken
            // as single steps began, or was lost, the event is cancelled
            // outright. The event's fate at the trap then depends only on
            // the guest's clock relative to its target: not on host timing,
            // on the processor's skid margin, or on whether overflow records
            // are mapped.
            self.timer.disregard_stop_before_period()?;
            return self.resume_injected_rt_sigreturn(task, &frame).await;
        }

        frame.emulate_syscall_entry(trap_rflags);
        self.write_injected_syscall_frame(&task, frame_address, &frame)?;

        if !self
            .global_state
            .subscriptions
            .iter_syscalls()
            .any(|subscribed| subscribed == nr)
        {
            // The trap makes no Tool callback, so it leaves the timer event as
            // it was. Before the syscall, since the event's notification can
            // arrive at the injection (`untraced_syscall`).
            let disregarded = self.timer.disregard_stop()?;
            self.injected_syscall_frame = Some(frame_address);
            if let Some(restart_rip) = restart_rip {
                return self
                    .untraced_liteinst_syscall(
                        task,
                        frame_address,
                        nr,
                        args,
                        restart_rip,
                        disregarded,
                    )
                    .await;
            }
            let result = self.untraced_syscall(task, nr, args).await?;
            let task = self.assume_stopped();
            self.write_injected_syscall_result(&task, result)?;
            self.injected_syscall_frame = None;
            // What of the event nothing else will drive, the single steps
            // toward it that the trap interrupted, a lost notification, or one
            // the injection took, is finished at the syscall's return, where
            // the guest would have taken the notification.
            //
            // A guest signal that the injection held is instead delivered as
            // the guest resumes. Only a signal that Linux dequeues ahead of
            // the step's SIGTRAP is held: a synchronous one with a positive
            // si_code, such as the SIGSYS of a seccomp filter that traps the
            // injected syscall. An asynchronous signal, such as SIGCHLD or
            // one from another process, comes after the step's SIGTRAP, and
            // is reported at a later stop. The held signal's handler must run
            // before the guest's next instruction, so the steps cannot come
            // first, and stepping into the handler is not implemented. The
            // event is therefore cancelled here, at the trap's clock, whether
            // or not anything was handed on, and the Tool loses that
            // preemption: `Timer::retire` records the event as a skid
            // overshoot if no stop has decided it and the guest has reached
            // its delivery point, cancels it, and disables the counter, so
            // that no new notification is raised in the handler. A
            // notification already queued is still delivered to a stop, where
            // `handle_signal` finds the event Cancelled and discards it.
            // Without this, the
            // injection's step SIGTRAP, which the kernel still reports as the
            // guest resumes (`stale_private_step_trap`), would be the next
            // stop: `handle_sigtrap` discards it without disregarding it, so
            // its observation would decide the event at the same clock, and
            // the event's notification would then be discarded as cancelled.
            // That stop is one that no Tool sees and that still cancels
            // (https://github.com/rrnewton/reverie/issues/746).
            let task = self.finish_disregarded_timer(task, disregarded).await?;
            let held = self.take_pending_signal_for_resume(
                LiteinstActivationOperation::ResumeInjectedSyscall,
            )?;
            let resume = self
                .report_held_signal(&task, Some(Signal::SIGTRAP), held)
                .await?;
            return self.resume_with_signal(task, resume).await;
        }

        let span = tracing::trace_span!(
            target: "reverie_ptrace::syscall",
            "syscall.intercept",
            tid = %self.tid(),
            syscall = %nr,
            args = ?args,
            source = "injected-trap",
        );

        async {
            self.injected_syscall_frame = Some(frame_address);
            self.pending_syscall = Some((nr, args));
            self.pending_syscall_already_skipped = false;

            let retval = cancellable(self.cancel_handler.clone(), async {
                self.process_state
                    .clone()
                    .handle_syscall_event(self, syscall)
                    .await
            })
            .await;

            let retval = match retval {
                Some(Err(error)) => match error.into_errno() {
                    Ok(errno) => Some(Err(errno)),
                    Err(error) => {
                        // Effects performed by the callback cannot be rolled back.
                        // Publish the original cause and park this exact stop for
                        // its tree owner; do not finalize timers, encode a guest
                        // errno, resume, or enter the legacy child-detach path.
                        self.publish_ordinary_failure("ptrace injected syscall callback", error);
                        return future::pending().await;
                    }
                },
                Some(Ok(value)) => Some(Ok(value)),
                None => None,
            };
            // A fast tail injection ended the callback early; its result is
            // this dispatcher's to apply.
            let retval = retval.or_else(|| self.injected_tail_result.take());
            self.ordinary_trace_continuation()?;
            self.timer.finalize_requests();

            if let (Some(restart_rip), Some(result)) = (restart_rip, retval)
                && let Some(action) = liteinst_restart_action(result)
            {
                let errno = result.expect_err("only an errno is a restart request");
                return self
                    .restart_liteinst_syscall(
                        task,
                        frame_address,
                        restart_rip,
                        errno,
                        action,
                        LiteinstActivationOperation::ResumeInterceptedInjectedSyscall,
                        TrapTimer::Decided,
                    )
                    .await;
            }

            if let Some(retval) = retval {
                let result = match retval {
                    Ok(value) => value,
                    Err(errno) => -(errno.into_raw() as i64),
                };
                self.write_injected_syscall_result(&task, Ok(result))?;
            }

            self.pending_syscall = None;
            self.pending_syscall_already_skipped = false;
            self.injected_syscall_frame = None;
            let held = self.take_pending_signal_for_resume(
                LiteinstActivationOperation::ResumeInterceptedInjectedSyscall,
            )?;
            let resume = self
                .report_held_signal(&task, Some(Signal::SIGTRAP), held)
                .await?;
            let wait = self.resume_with_signal(task, resume).await?;
            tracing::trace!(
                target: "reverie_ptrace::syscall",
                "completed injected syscall interception"
            );
            Ok(wait)
        }
        .instrument(span)
        .await
    }

    /// Runs an unsubscribed host-hybrid syscall on the private page and
    /// applies Linux's restart rule to it.
    ///
    /// The controller is stopped at the runtime `int3` with `orig_rax == -1`,
    /// so the kernel never restarts this syscall on its own. The private step
    /// ends in one of three ways (`classify_private_step`):
    ///
    /// * `NotRun`: a signal was pending before the `syscall` executed. The
    ///   controller is rewound to the `int3` and the signal stop is handed to
    ///   the run loop exactly as ptrace would see a signal that arrives before
    ///   an unsubscribed syscall; the re-trap issues the syscall afterwards.
    /// * `Ran`: a restart code is rewound (`restart_liteinst_syscall`), with
    ///   the interrupting signal still kernel-pending; anything else is the
    ///   syscall's result.
    /// * `Held`: the syscall ran and `step_private_syscall` held a signal it
    ///   could not requeue; the result is handled as for `Ran`, with the held
    ///   signal reported to the Tool (`report_held_signal`), as plain ptrace
    ///   reports it at its own delivery stop, and the verdict delivered on
    ///   the resume.
    /// * `Unexpected`: fails closed.
    ///
    /// The step itself is `step_private_syscall`, as for every other
    /// untraced syscall, so group stops, stale step reports, signals after
    /// the syscall completed, guest seccomp traps and late timer
    /// notifications are handled before the outcome is classified.
    #[cfg(target_arch = "x86_64")]
    async fn untraced_liteinst_syscall(
        &mut self,
        task: Stopped,
        frame_address: usize,
        nr: Sysno,
        args: SyscallArgs,
        restart_rip: u64,
        disregarded: Option<Unfinished>,
    ) -> Result<Wait, TraceError> {
        self.validate_liteinst_mapping_execution(nr, args)?;
        self.timer.expire_overflow_records(&task);
        let controller = task.getregs()?;
        let mut regs = self.read_guest_registers(&task)?;
        *regs.syscall_mut() = nr as Reg;
        *regs.orig_syscall_mut() = nr as Reg;
        regs.set_args((
            args.arg0 as Reg,
            args.arg1 as Reg,
            args.arg2 as Reg,
            args.arg3 as Reg,
            args.arg4 as Reg,
            args.arg5 as Reg,
        ));
        let child_context = regs;
        *regs.ip_mut() = cp::PRIVATE_PAGE_OFFSET as Reg;
        task.setregs(&regs)?;

        let (wait, seccomp_trapped) = self
            .step_private_syscall_discarding_late_timer(task, nr)
            .await?;

        let (stopped, sig) = match wait {
            Wait::Stopped(stopped, Event::Signal(sig)) => (stopped, sig),
            other => {
                // Fork, exec, exit and syscall stops keep their existing
                // handling; none of them carries a restart code.
                let result = self
                    .status_to_result(other, Some(controller), Some(child_context))
                    .await?;
                self.observe_liteinst_mapping_result(nr, args, result);
                let task = self.assume_stopped();
                self.write_injected_syscall_result(&task, result)?;
                self.injected_syscall_frame = None;
                let task = self.finish_disregarded_timer(task, disregarded).await?;
                let signal = self.take_pending_signal_for_resume(
                    LiteinstActivationOperation::ResumeInjectedSyscall,
                )?;
                return self
                    .resume_stopped(task, signal)?
                    .next_state_with_owner(&self.ptracer_waits)
                    .await;
            }
        };

        self.validate_nested_liteinst_activation_signal(
            &stopped,
            sig,
            LiteinstActivationOperation::FinishInjectedSyscall,
            NestedTrapExpectation::PrivateSyscall(
                (cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE) as u64,
            ),
            false,
        )?;
        let step_regs = stopped.getregs()?;
        match classify_private_step(
            step_regs.ip(),
            sig,
            cp::PRIVATE_PAGE_OFFSET as u64,
            cp::SYSCALL_INSTR_SIZE as u64,
        ) {
            PrivateStep::NotRun => {
                let byte = self.read_restart_byte(&stopped, restart_rip)?;
                self.check_liteinst_rewind(&controller, restart_rip, byte)?;
                let mut rewound = controller;
                *rewound.ip_mut() = restart_rip as Reg;
                stopped.setregs(&rewound)?;
                self.injected_syscall_frame = None;
                // The syscall never ran, so no handler can interrupt it: the
                // re-executed int3 issues it after the signal is handled.
                self.push_liteinst_pending_restart(LiteinstPendingRestart {
                    restart_rip,
                    frame_address,
                    controller_rsp: controller.rsp,
                    errno: Errno::ERESTARTNOINTR,
                    landing: None,
                });
                // The run loop observes this signal stop, and it decides the
                // timer event as plain ptrace's stop for the same signal would:
                // the int3 stop was disregarded, so the event is as it was
                // before the trap. A stop other than the timer's own cancels
                // it, as `handle_injected_syscall` retires the event for a
                // guest signal that an injection holds. The single steps the
                // int3 stop interrupted, a lost notification, or one the step
                // took (`disregarded`, `Timer::take_notification`) therefore
                // end with that stop and are not driven here.
                let _ = disregarded;
                Ok(Wait::Stopped(stopped, Event::Signal(sig)))
            }
            step @ (PrivateStep::Ran | PrivateStep::Held) => {
                if step == PrivateStep::Held {
                    self.hold_pending_signal(&stopped, sig);
                }
                // A guest seccomp filter's `SECCOMP_RET_TRAP` skipped the
                // syscall and left its number in RAX (see `untraced_syscall`).
                let result = if seccomp_trapped {
                    Err(Errno::ENOSYS)
                } else {
                    Errno::from_ret(step_regs.ret() as usize).map(|x| x as i64)
                };
                stopped.setregs(&controller)?;
                if let Some(action) = liteinst_restart_action(result) {
                    let errno = result.expect_err("only an errno is a restart request");
                    return self
                        .restart_liteinst_syscall(
                            stopped,
                            frame_address,
                            restart_rip,
                            errno,
                            action,
                            LiteinstActivationOperation::ResumeInjectedSyscall,
                            TrapTimer::Disregarded(disregarded),
                        )
                        .await;
                }
                self.observe_liteinst_mapping_result(nr, args, result);
                self.write_injected_syscall_result(&stopped, result)?;
                self.injected_syscall_frame = None;
                let stopped = self.finish_disregarded_timer(stopped, disregarded).await?;
                let held = self.take_pending_signal_for_resume(
                    LiteinstActivationOperation::ResumeInjectedSyscall,
                )?;
                let resume = self
                    .report_held_signal(&stopped, Some(Signal::SIGTRAP), held)
                    .await?;
                self.resume_with_signal(stopped, resume).await
            }
            PrivateStep::Unexpected => {
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::SyscallRestartInvariant,
                    Error::runtime(
                        self.tid(),
                        "restart LiteInst host-hybrid syscall",
                        format!(
                            "private-page step of {nr} stopped with {sig} at {:#x}, \
                             outside the private syscall",
                            step_regs.ip()
                        ),
                    ),
                );
                Err(Errno::EPROTO.into())
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn read_restart_byte(&self, task: &Stopped, restart_rip: u64) -> Result<u8, TraceError> {
        let address = Addr::from_raw(restart_rip as usize).ok_or(Errno::EFAULT)?;
        Ok(task.read_value(address)?)
    }

    /// Fails closed unless rewinding the controller one byte re-executes the
    /// runtime `int3` that produced this trap.
    #[cfg(target_arch = "x86_64")]
    fn check_liteinst_rewind(
        &mut self,
        controller: &libc::user_regs_struct,
        restart_rip: u64,
        restart_byte: u8,
    ) -> Result<(), TraceError> {
        let marker = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .map(|config| config.syscall_marker)
            .ok_or(Errno::EPROTO)?;
        if let Err(message) = check_rewind_preconditions(
            controller.ip(),
            controller.rax,
            restart_rip,
            marker,
            restart_byte,
        ) {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::SyscallRestartInvariant,
                Error::runtime(self.tid(), "restart LiteInst host-hybrid syscall", message),
            );
            return Err(Errno::EPROTO.into());
        }
        Ok(())
    }

    /// Restarts a host-hybrid syscall whose final result is a Linux restart
    /// code, applying Linux's signal-delivery restart rule.
    ///
    /// The controller must be stopped just after the runtime `int3` (see
    /// `check_liteinst_rewind`). Instead of writing the private code into the
    /// guest frame, the controller is rewound to the `int3` and resumed. With
    /// no signal delivered, or one with no guest handler, the re-executed
    /// `int3` traps again and re-dispatches the syscall.
    /// `ERESTART_RESTARTBLOCK` re-dispatches as `restart_syscall` with the
    /// argument registers kept.
    ///
    /// A signal delivered before the re-trap is decided by the kernel itself:
    /// a signal the tracer holds is reported to the Tool
    /// (`report_held_signal`) and the verdict delivered from this stop, or
    /// passed on unreported for `restart_syscall`, whose restart block a
    /// callback injection could replace, and a
    /// kernel-pending one reaches `handle_signal` at the rewound `int3`. Both
    /// arm the private-page landing (`arm_liteinst_restart_landing`), where
    /// x86 `handle_signal` restarts or returns `-EINTR` according to the code
    /// and the delivered handler's `SA_RESTART`.
    ///
    /// No retry bound applies: a Tool that keeps returning a restart code with
    /// nothing pending re-traps forever, as it would re-stop forever at the
    /// kernel's own restart under plain ptrace.
    ///
    /// `timer` says whether the trap stop decided the timer event. A trap the
    /// Tool observed did; one it did not was disregarded, and what of the
    /// event it left is finished at the rewound `int3`, as
    /// `handle_injected_syscall` finishes it at an unsubscribed syscall's
    /// return. Single steps from there end at the kernel-pending signal's stop
    /// or at the re-trap, which the run loop observes.
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::too_many_arguments)]
    async fn restart_liteinst_syscall(
        &mut self,
        task: Stopped,
        frame_address: usize,
        restart_rip: u64,
        errno: Errno,
        action: RestartAction,
        operation: LiteinstActivationOperation,
        timer: TrapTimer,
    ) -> Result<Wait, TraceError> {
        let mut controller = task.getregs()?;
        let byte = self.read_restart_byte(&task, restart_rip)?;
        self.check_liteinst_rewind(&controller, restart_rip, byte)?;

        if action == RestartAction::RestartSyscall {
            // Re-read: the callback may have rewritten guest registers.
            let mut frame = self.read_injected_syscall_frame(&task, frame_address)?;
            frame.set_restart_syscall();
            self.write_injected_syscall_frame(&task, frame_address, &frame)?;
        }

        *controller.ip_mut() = restart_rip as Reg;
        task.setregs(&controller)?;
        self.injected_syscall_frame = None;
        self.pending_syscall = None;
        self.pending_syscall_already_skipped = false;
        self.push_liteinst_pending_restart(LiteinstPendingRestart {
            restart_rip,
            frame_address,
            controller_rsp: controller.rsp,
            errno,
            landing: None,
        });
        let task = match timer {
            TrapTimer::Decided => task,
            TrapTimer::Disregarded(disregarded) => {
                self.finish_disregarded_timer(task, disregarded).await?
            }
        };
        let held = self.take_pending_signal_for_resume(operation)?;
        let resume = if action == RestartAction::RestartSyscall {
            // The guest's restart block is the kernel's, and this stop's
            // registers are the controller's, so a callback injection that
            // replaced it would go unseen (`signal_callback_guest_ret`) and
            // `restart_syscall` would run the injection's restart block.
            self.pending_signal_taken = None;
            self.pass_held_signal_unreported(held)
        } else {
            self.report_held_signal(&task, Some(Signal::SIGTRAP), held)
                .await?
        };
        if let Some(signal) = resume.signal {
            // A held signal is delivered from this `int3` stop, so the kernel
            // decides this restart as it delivers it.
            self.arm_liteinst_restart_landing(&task, signal)?;
        }
        self.resume_with_signal(task, resume).await
    }

    /// Hands a pending host-hybrid restart to the kernel's own restart rule
    /// for the signal about to be delivered from this stop.
    ///
    /// Does nothing unless a restart is pending with the controller at its
    /// rewound `int3` and the code can become `EINTR`. Otherwise the
    /// controller is parked at the landing (`landing_regs`); the `int3` it
    /// reaches reports the outcome to `finish_liteinst_restart_landing`. A
    /// SIGTRAP delivery fails closed instead (`RUNTIME_OWNED_HANDLERS`).
    #[cfg(target_arch = "x86_64")]
    fn arm_liteinst_restart_landing(
        &mut self,
        task: &Stopped,
        signal: Signal,
    ) -> Result<(), TraceError> {
        let Some(&pending) = self.liteinst_pending_restarts.last() else {
            return Ok(());
        };
        if pending.landing.is_some() || !restart_depends_on_handler(pending.errno) {
            return Ok(());
        }
        // Both a held signal (after `restart_liteinst_syscall` rewound the
        // int3 stop) and a kernel-pending one (stopped at the rewound int3)
        // are delivered with the controller at the int3.
        let rewound = task.getregs()?;
        if rewound.ip() != pending.restart_rip || rewound.rsp != pending.controller_rsp {
            return Ok(());
        }
        if signal_bit(signal as i32) & RUNTIME_OWNED_HANDLERS != 0 {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::SyscallRestartInvariant,
                Error::runtime(
                    self.tid(),
                    "restart LiteInst host-hybrid syscall",
                    format!(
                        "{signal} delivered while a {} restart is pending: the runtime's \
                         {signal} router hides whether the guest's disposition would restart it",
                        pending.errno
                    ),
                ),
            );
            return Err(Errno::EPROTO.into());
        }
        let syscall_number = self
            .read_injected_syscall_frame(task, pending.frame_address)?
            .raw_syscall_number();
        let landing = liteinst_landing();
        let mut bytes = [0u8; LANDING_LEN];
        task.read_exact(landing as usize, &mut bytes)?;
        if let Err(message) = check_landing_bytes(&bytes) {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::SyscallRestartInvariant,
                Error::runtime(self.tid(), "restart LiteInst host-hybrid syscall", message),
            );
            return Err(Errno::EPROTO.into());
        }
        task.setregs(&landing_regs(
            &rewound,
            landing,
            pending.errno,
            syscall_number,
        ))?;
        if let Some(innermost) = self.liteinst_pending_restarts.last_mut() {
            innermost.landing = Some(rewound);
        }
        Ok(())
    }

    /// Puts the syscall marker back in `rax` when the controller is stopped
    /// at a pending restart's rewound `int3`.
    ///
    /// The rewind left the marker there (`check_liteinst_rewind`), and the
    /// controller has not run since, but a syscall the Tool injects from this
    /// stop returns its result in `rax`: `restore_context` restores the
    /// instruction pointer, the arguments and the syscall clobbers, and the
    /// return register only inside a held-signal callback
    /// (`in_held_signal_callback`).
    /// Without the marker the re-executed `int3` would not be
    /// recognised as the syscall trap, and an armed landing would restore the
    /// clobbered value for the re-trap.
    #[cfg(target_arch = "x86_64")]
    fn restore_liteinst_restart_marker(&self, task: &Stopped) -> Result<(), TraceError> {
        let Some(config) = self.global_state.liteinst_runtime.as_ref() else {
            return Ok(());
        };
        let Some(pending) = self.liteinst_pending_restarts.last() else {
            return Ok(());
        };
        if pending.landing.is_some() {
            return Ok(());
        }
        let mut regs = task.getregs()?;
        if regs.ip() != pending.restart_rip
            || regs.rsp != pending.controller_rsp
            || regs.rax == config.syscall_marker
        {
            return Ok(());
        }
        regs.rax = config.syscall_marker;
        task.setregs(&regs)?;
        Ok(())
    }

    /// Records a restart the thread will re-trap for. A restart abandoned by
    /// `siglongjmp` out of a handler is never re-trapped, so two rules keep
    /// such entries from accumulating:
    ///
    /// - An entry with the new restart's controller stack pointer is dropped.
    ///   A live restart keeps its controller frame on the stack until its
    ///   re-trap or landing, and a handler delivered while it is pending runs
    ///   below that frame or on another stack, so a new trap at the same
    ///   stack pointer means the older restart was abandoned. A loop that
    ///   abandons a restart on every iteration therefore keeps one entry.
    /// - Past `LITEINST_PENDING_RESTART_LIMIT` entries the oldest is dropped.
    ///   That entry is live only if a handler abandoned more than the limit
    ///   of restarts at distinct stack depths inside it; its landing or
    ///   re-trap then fails closed.
    #[cfg(target_arch = "x86_64")]
    fn push_liteinst_pending_restart(&mut self, pending: LiteinstPendingRestart) {
        self.liteinst_pending_restarts
            .retain(|older| older.controller_rsp != pending.controller_rsp);
        if self.liteinst_pending_restarts.len() >= LITEINST_PENDING_RESTART_LIMIT {
            self.liteinst_pending_restarts.remove(0);
        }
        self.liteinst_pending_restarts.push(pending);
    }

    /// Serves the landing `int3` that reports the kernel's restart decision.
    ///
    /// Returns the stop untouched unless this is the kernel-generated SIGTRAP
    /// of one of the landing's two `int3`s. The landing is entered only from
    /// an armed restart, so such a trap with none armed fails closed.
    ///
    /// The trap belongs to the armed restart whose `controller_rsp` it
    /// carries: `rt_sigreturn` restored the stack pointer the landing was
    /// armed with (see `LiteinstPendingRestart`). The innermost such restart
    /// is chosen, and every restart above it was pushed inside a handler that
    /// has now returned past it, so they are dropped. A landing trap that
    /// matches no armed restart fails closed.
    ///
    /// Plain ptrace has no stop where the kernel decides a restart after a
    /// handler: an interrupted syscall returns to the guest unseen, and a
    /// restarted one stops next at its own re-entry, which the re-trap
    /// reproduces. So the landing stop is disregarded
    /// (`Timer::disregard_stop`), and what of the timer event it left is
    /// finished once the landing is resolved, as at an unsubscribed
    /// syscall's return: single steps toward a precise event that the
    /// landing interrupted continue from the resolved state.
    async fn finish_liteinst_restart_landing(
        &mut self,
        task: Stopped,
        regs: &libc::user_regs_struct,
    ) -> Result<Result<Wait, Stopped>, TraceError> {
        if self.global_state.liteinst_runtime.is_none() {
            return Ok(Err(task));
        }
        let Some(outcome) = classify_landing_trap(regs.ip(), liteinst_landing()) else {
            return Ok(Err(task));
        };
        if task.getsiginfo()?.si_code != libc::SI_KERNEL {
            return Ok(Err(task));
        }
        match Self::resolve_liteinst_landing(
            &mut self.liteinst_pending_restarts,
            &task,
            regs,
            outcome,
        ) {
            Ok(()) => {}
            Err(LandingFailure::Trace(error)) => return Err(error),
            Err(LandingFailure::Invariant(message)) => {
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::SyscallRestartInvariant,
                    Error::runtime(self.tid(), "restart LiteInst host-hybrid syscall", message),
                );
                return Err(Errno::EPROTO.into());
            }
        }
        let disregarded = self.timer.disregard_stop()?;
        if self.pending_signal.is_none() && matches!(disregarded, Some(Unfinished::Steps(_))) {
            LITEINST_TIMER_STEP_LANDINGS_RESOLVED.fetch_add(1, Ordering::Relaxed);
        }
        let task = self.finish_disregarded_timer(task, disregarded).await?;
        let signal = self
            .take_pending_signal_for_resume(LiteinstActivationOperation::ResumeInjectedSyscall)?;
        Ok(Ok(self
            .resume_stopped(task, signal)?
            .next_state_with_owner(&self.ptracer_waits)
            .await?))
    }

    /// Applies the kernel's restart decision that a landing trap reports
    /// (`finish_liteinst_restart_landing`). The thread is left at the rewound
    /// runtime `int3` of a restart that will re-trap, or at the instruction
    /// after it with the frame completed. The caller resumes the thread.
    #[cfg(target_arch = "x86_64")]
    fn resolve_liteinst_landing(
        pending_restarts: &mut Vec<LiteinstPendingRestart>,
        task: &Stopped,
        regs: &libc::user_regs_struct,
        outcome: LandingOutcome,
    ) -> Result<(), LandingFailure> {
        let Some(index) = pending_restarts
            .iter()
            .rposition(|pending| pending.landing.is_some() && pending.controller_rsp == regs.rsp)
        else {
            return Err(LandingFailure::Invariant(format!(
                "restart landing trap at {:#x} with stack pointer {:#x} matches no armed restart",
                regs.ip(),
                regs.rsp
            )));
        };
        pending_restarts.truncate(index + 1);
        let pending = pending_restarts[index];
        let rewound = pending
            .landing
            .expect("rposition selected an armed restart");
        if let Some(register) = changed_landing_register(&rewound, regs) {
            return Err(LandingFailure::Invariant(format!(
                "a signal handler changed controller register {register} across the restart \
                 landing"
            )));
        }
        let mut frame = read_injected_frame(task, pending.frame_address)?;
        match outcome {
            LandingOutcome::Restart => {
                // The kernel restarted with `rax` = the frame's syscall
                // number, which a handler may have edited as it can edit the
                // number a plain restarted `syscall` instruction makes.
                if regs.rax != frame.raw_syscall_number() {
                    frame.set_raw_syscall_number(regs.rax);
                    write_injected_frame(task, pending.frame_address, &frame)?;
                }
                // The next signal, if any, reaches a syscall that has not
                // been re-entered, so it cannot interrupt it.
                task.setregs(&rewound)?;
                pending_restarts[index] = LiteinstPendingRestart {
                    errno: Errno::ERESTARTNOINTR,
                    landing: None,
                    ..pending
                };
            }
            LandingOutcome::Interrupted => {
                // `rax` is the kernel's `-EINTR`, or what the handler left in
                // its place, which is the syscall's result under plain ptrace.
                frame.set_result(regs.rax as i64);
                write_injected_frame(task, pending.frame_address, &frame)?;
                let mut completed = rewound;
                *completed.ip_mut() = (pending.restart_rip + 1) as Reg;
                task.setregs(&completed)?;
                pending_restarts.truncate(index);
            }
        }
        Ok(())
    }

    // Only the x86_64 host-hybrid path pushes a pending restart, so elsewhere
    // no landing is armed and no rewound `int3` carries the marker. These
    // match the x86_64 functions with an empty pending stack.
    #[cfg(not(target_arch = "x86_64"))]
    fn arm_liteinst_restart_landing(
        &mut self,
        _task: &Stopped,
        _signal: Signal,
    ) -> Result<(), TraceError> {
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn restore_liteinst_restart_marker(&self, _task: &Stopped) -> Result<(), TraceError> {
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn resolve_liteinst_landing(
        _pending_restarts: &mut Vec<LiteinstPendingRestart>,
        _task: &Stopped,
        regs: &libc::user_regs_struct,
        _outcome: LandingOutcome,
    ) -> Result<(), LandingFailure> {
        Err(LandingFailure::Invariant(format!(
            "restart landing trap at {:#x} matches no armed restart",
            regs.ip()
        )))
    }

    #[cfg(target_arch = "x86_64")]
    fn validate_liteinst_handshake(
        &self,
        task: &Stopped,
        frame_address: usize,
        trap_rip: u64,
        ready: bool,
    ) -> Option<LiteinstHandshakeFrame> {
        let config = self.global_state.liteinst_runtime.as_ref()?;
        let address = Addr::from_raw(frame_address)?;
        let frame: LiteinstHandshakeFrame = task.read_value(address).ok()?;
        if frame.version != 5
            || frame.helper_stack_top < 8
            || frame.helper_stack_top & 0xf != 0
            || trap_rip
                != if ready {
                    frame.ready_rip
                } else {
                    frame.begin_rip
                }
        {
            return None;
        }
        let maps = guest_maps(task.pid())?;
        let preload_code = |address| {
            maps.iter().any(|mapping| {
                mapping.executable
                    && mapping.path.as_ref() == Some(&config.preload)
                    && mapping.contains(address)
            })
        };
        if ![
            frame.begin_rip,
            frame.ready_rip,
            frame.install_helper,
            frame.helper_return,
            frame.helper_return_rip,
            frame.syscall_trap_rip,
            frame.syscall_trap_return_rip,
        ]
        .into_iter()
        .all(preload_code)
        {
            return None;
        }
        let frame_readable = maps
            .iter()
            .any(|mapping| mapping.readable && mapping.contains(frame_address as u64));
        let helper_stack_map = maps.iter().find(|mapping| {
            mapping.writable && mapping.contains(frame.helper_stack_top.saturating_sub(8))
        });
        let install_result = GuestRange::new(
            frame.install_result,
            core::mem::size_of::<LiteinstInstallResult>() as u64,
        )?;
        let install_result_writable = maps.iter().any(|mapping| {
            Some((mapping.start, mapping.end))
                == helper_stack_map.map(|stack| (stack.start, stack.end))
                && mapping.readable
                && mapping.writable
                && mapping.contains_range(install_result)
        });
        (frame_readable && helper_stack_map.is_some() && install_result_writable).then_some(frame)
    }

    fn install_liteinst_entry_guard(&mut self, task: &mut Stopped) -> Result<(), TraceError> {
        if self.global_state.liteinst_runtime.is_none() {
            return Ok(());
        }
        if self.liteinst_entry_guard.is_some() {
            return Err(Errno::EALREADY.into());
        }
        let address = guest_auxv_entry(task.pid(), libc::AT_ENTRY).ok_or(Errno::ENOEXEC)?;
        let range =
            GuestRange::new(address, core::mem::size_of::<u64>() as u64).ok_or(Errno::ENOEXEC)?;
        if !guest_maps(task.pid()).is_some_and(|maps| {
            maps.iter().any(|mapping| {
                mapping.readable && mapping.executable && mapping.contains_range(range)
            })
        }) {
            return Err(Errno::ENOEXEC.into());
        }
        let read_address = Addr::<u64>::from_raw(address as usize).ok_or(Errno::EFAULT)?;
        let guard_address = AddrMut::<u64>::from_raw(address as usize).ok_or(Errno::EFAULT)?;
        let saved_instruction: u64 = task.read_value(read_address)?;
        if saved_instruction as u8 == 0xcc {
            return Err(Errno::EPROTO.into());
        }
        let guarded_instruction = (saved_instruction & !0xff) | 0xcc;
        task.write_value(guard_address, &guarded_instruction)?;
        let observed: u64 = task.read_value(read_address)?;
        if observed != guarded_instruction {
            let _ = task.write_value(guard_address, &saved_instruction);
            return Err(Errno::EIO.into());
        }
        self.liteinst_entry_guard = Some(LiteinstEntryGuard {
            address,
            saved_instruction,
        });
        Ok(())
    }

    fn restore_liteinst_entry_guard(&mut self, task: &mut Stopped) -> Result<(), TraceError> {
        let guard = self.liteinst_entry_guard.ok_or(Errno::EPROTO)?;
        let read_address = Addr::<u64>::from_raw(guard.address as usize).ok_or(Errno::EFAULT)?;
        let address = AddrMut::<u64>::from_raw(guard.address as usize).ok_or(Errno::EFAULT)?;
        let guarded_instruction = (guard.saved_instruction & !0xff) | 0xcc;
        let observed: u64 = task.read_value(read_address)?;
        if observed != guarded_instruction {
            return Err(Errno::EPROTO.into());
        }
        task.write_value(address, &guard.saved_instruction)?;
        let restored: u64 = task.read_value(read_address)?;
        if restored != guard.saved_instruction {
            return Err(Errno::EIO.into());
        }
        self.liteinst_entry_guard = None;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn classify_liteinst_trap(
        &mut self,
        task: &Stopped,
        regs: &libc::user_regs_struct,
    ) -> Option<LiteinstTrap> {
        let config = self.global_state.liteinst_runtime.as_ref()?;
        if regs.rax == config.begin_marker {
            let frame =
                self.validate_liteinst_handshake(task, regs.rdi as usize, regs.ip(), false)?;
            let mut state = self.liteinst_runtime.lock().unwrap();
            if state.phase != LiteinstRuntimePhase::Waiting {
                return None;
            }
            state.phase = LiteinstRuntimePhase::Bootstrap;
            state.frame = Some(frame);
            state.bootstrap_tid = Some(self.tid());
            return Some(LiteinstTrap::HandshakeBegin);
        }
        if regs.rax == config.ready_marker || regs.rax == config.failed_marker {
            // Both outcomes are reported at the ready trap site.
            let frame =
                self.validate_liteinst_handshake(task, regs.rdi as usize, regs.ip(), true)?;
            let state = self.liteinst_runtime.lock().unwrap();
            if state.phase != LiteinstRuntimePhase::Bootstrap || state.frame != Some(frame) {
                return None;
            }
            return Some(if regs.rax == config.ready_marker {
                LiteinstTrap::HandshakeReady
            } else {
                LiteinstTrap::HandshakeFailed
            });
        }
        if regs.rax != config.syscall_marker {
            return None;
        }
        let handshake = self.liteinst_runtime.lock().unwrap().frame?;
        if regs.ip() != handshake.syscall_trap_rip {
            return None;
        }
        let stack_address = usize::try_from(regs.rsp).ok()?;
        let frame_address = usize::try_from(regs.rdi).ok()?;
        let maps = guest_maps(task.pid())?;
        let controller_stack = maps.iter().find(|mapping| {
            mapping.readable
                && mapping.writable
                && mapping.contains(regs.rsp)
                && mapping.contains(
                    regs.rsp
                        .saturating_add(core::mem::size_of::<u64>() as u64 - 1),
                )
                && mapping.contains(regs.rdi)
                && mapping.contains(
                    regs.rdi
                        .saturating_add(core::mem::size_of::<InjectedSyscallFrame>() as u64 - 1),
                )
        });
        if controller_stack.is_none() || regs.rsp.abs_diff(regs.rdi) > 128 * 1024 {
            return None;
        }
        let return_address: u64 = task.read_value(Addr::from_raw(stack_address)?).ok()?;
        if return_address != handshake.syscall_trap_return_rip {
            // A same-process caller can find the raw trap entry, but only the
            // hidden runtime wrapper produces this exact inner return site.
            return None;
        }
        let frame = match self.read_injected_syscall_frame(task, frame_address) {
            Ok(frame) => frame,
            Err(_) => return Some(LiteinstTrap::Invalid),
        };
        let state = self.liteinst_runtime.lock().unwrap();
        if state.phase != LiteinstRuntimePhase::Ready
            || state.ready_generation != Some(state.generation)
            || !state
                .active_hooks
                .contains_key(&frame.instruction_pointer())
        {
            return Some(LiteinstTrap::Invalid);
        }
        Some(LiteinstTrap::Syscall(frame_address))
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn classify_liteinst_trap(
        &mut self,
        _task: &Stopped,
        _regs: &libc::user_regs_struct,
    ) -> Option<LiteinstTrap> {
        None
    }

    async fn handle_sigtrap(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        let resumed_by_gdb_step = self
            .resumed_by_gdb
            .is_some_and(|action| matches!(action, ResumeAction::Step(_)));
        // A standard signal is queued at most once, so any SIGTRAP stop
        // consumes the step SIGTRAP an injection left queued.
        if std::mem::take(&mut self.stale_private_step_trap)
            && !resumed_by_gdb_step
            && is_private_step_trap(
                &task,
                (cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE) as u64,
            )?
        {
            tracing::debug!(
                "[scheduler/tool] (pid = {}) discarding the step SIGTRAP of an injected syscall that ended at a held signal",
                task.pid()
            );
            return Ok(HandleSignalResult::SignalSuppressed(
                self.resume_stopped(task, None)?
                    .next_state_with_owner(&self.ptracer_waits)
                    .await?,
            ));
        }
        let mut regs = task.getregs()?;
        if let Some(guard) = self.liteinst_entry_guard
            && regs.ip() == guard.address.saturating_add(1)
        {
            let address = Addr::from_raw(guard.address as usize).ok_or(Errno::EFAULT)?;
            let observed: u64 = task.read_value(address)?;
            let guarded_instruction = (guard.saved_instruction & !0xff) | 0xcc;
            if observed != guarded_instruction {
                return Err(Errno::EPROTO.into());
            }
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::ExecutableEntryBeforeHandshake,
                Error::runtime(
                    self.tid(),
                    "verify LiteInst runtime before executable entry",
                    format!(
                        "tracee reached guarded executable entry {:#x} before the required preload handshake completed",
                        guard.address
                    ),
                ),
            );
            return Err(Errno::EPROTO.into());
        }
        let mut task = match self.finish_liteinst_restart_landing(task, &regs).await? {
            Ok(wait) => return Ok(HandleSignalResult::SignalSuppressed(wait)),
            Err(task) => task,
        };
        match self.classify_liteinst_trap(&task, &regs) {
            Some(LiteinstTrap::HandshakeBegin) => {
                return Ok(HandleSignalResult::SignalSuppressed(
                    self.resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?,
                ));
            }
            Some(LiteinstTrap::HandshakeReady) => {
                if let Err(error) = self.restore_liteinst_entry_guard(&mut task) {
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::RestoreExecutableEntryGuard,
                        Error::runtime(
                            self.tid(),
                            "restore LiteInst executable-entry guard",
                            error.to_string(),
                        ),
                    );
                    return Err(error);
                }
                {
                    let maps = self.read_ready_guest_maps(&task, "LiteInst Ready")?;
                    let mut state = self.liteinst_runtime.lock().unwrap();
                    if state.phase != LiteinstRuntimePhase::Bootstrap {
                        return Err(Errno::EPROTO.into());
                    }
                    state.enter_ready(maps);
                }
                return Ok(HandleSignalResult::SignalSuppressed(
                    self.resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?,
                ));
            }
            Some(LiteinstTrap::HandshakeFailed) => {
                // The runtime returns its error to its caller. It is not
                // active, so the executable-entry guard stays armed and this
                // generation can no longer reach Ready: whatever the guest does
                // next ends in a fail-closed refusal. Leaving Bootstrap now
                // stops attributing the guest's own syscalls to the runtime.
                {
                    let mut state = self.liteinst_runtime.lock().unwrap();
                    if state.phase != LiteinstRuntimePhase::Bootstrap {
                        return Err(Errno::EPROTO.into());
                    }
                    state.phase = LiteinstRuntimePhase::Failed;
                    state.bootstrap_tid = None;
                }
                return Ok(HandleSignalResult::SignalSuppressed(
                    self.resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?,
                ));
            }
            #[cfg(target_arch = "x86_64")]
            Some(LiteinstTrap::Syscall(frame_address)) => {
                // A restart re-executes only the runtime int3 of the hook
                // entry already counted; kernel-interrupted restarts depend on
                // signal timing, so they must not change the hook count.
                // `classify_liteinst_trap` matched this stop against the
                // validated handshake's exact post-int3 RIP, so the runtime's
                // `int3` is the byte before it (runtime.rs host trap asm).
                let restart_rip = self
                    .liteinst_runtime
                    .lock()
                    .unwrap()
                    .frame
                    .and_then(|handshake| handshake.syscall_trap_rip.checked_sub(1))
                    .ok_or(Errno::EPROTO)?;
                // Any other trap is a hook entry nested inside a signal handler
                // delivered while a restart is pending (a handler can call
                // through a patched site), so the pending restarts are kept
                // for the re-trap or the landing that follows the handler.
                // Restarts above a re-trapped one were abandoned.
                let restart_retrap = self
                    .liteinst_pending_restarts
                    .iter()
                    .rposition(|pending| pending.is_retrap(restart_rip, frame_address, regs.rsp));
                if let Some(index) = restart_retrap {
                    self.liteinst_pending_restarts.truncate(index);
                }
                let restart_retrap = restart_retrap.is_some();
                // The hook count is logical, one per hook entry; the stop
                // count is physical, so a restart's re-trap is a stop too.
                if let Some(stats) = &self.global_state.backend_stats {
                    stats.record_injected_trap();
                }
                if !restart_retrap
                    && let Some(stats) = self
                        .global_state
                        .liteinst_runtime
                        .as_ref()
                        .and_then(|config| config.instrumentation_stats.as_ref())
                {
                    stats.lock().unwrap().record_direct_hook();
                }
                let next_state = self
                    .handle_injected_syscall(task, frame_address, regs.eflags, Some(restart_rip))
                    .await?;
                return Ok(HandleSignalResult::SignalSuppressed(next_state));
            }
            Some(LiteinstTrap::Invalid) => return Err(Errno::EPROTO.into()),
            None => {}
        }
        let phase = self.liteinst_runtime.lock().unwrap().phase;
        if self.global_state.liteinst_runtime.is_some() && phase != LiteinstRuntimePhase::Ready {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::UnexpectedActivationTrap,
                Error::runtime(
                    self.tid(),
                    "reject unexpected LiteInst activation trap",
                    format!(
                        "received SIGTRAP at RIP {:#x} with RAX {:#x} that matched neither the entry guard nor a validated runtime handshake (phase {phase:?})",
                        regs.ip(), regs.ret()
                    ),
                ),
            );
            return Err(Errno::EPROTO.into());
        }
        // TODO-HUMAN-REVIEW(PR-103): Review rewritten-trap provenance validation.
        #[cfg(target_arch = "x86_64")]
        if let Some(trap) = self.global_state.injected_syscall_trap.as_ref()
            && regs.rax == trap.marker
        {
            if let Ok(frame) = self.read_injected_syscall_frame(&task, regs.rdi as usize)
                && trap.validates_site_provenance(task.pid(), regs.ip(), &frame)
            {
                if let Some(stats) = &self.global_state.backend_stats {
                    stats.record_injected_trap();
                }
                let next_state = self
                    .handle_injected_syscall(task, regs.rdi as usize, regs.eflags, None)
                    .await?;
                return Ok(HandleSignalResult::SignalSuppressed(next_state));
            }
            return Ok(HandleSignalResult::SignalToDeliver(task, Signal::SIGTRAP));
        }

        let rip_minus_one = regs.ip() - 1;

        Ok(if self.breakpoints.contains_key(&rip_minus_one) {
            *regs.ip_mut() = rip_minus_one;
            let next_state = self.resume_from_swbreak(task, regs).await?;
            HandleSignalResult::SignalSuppressed(next_state)
        } else if resumed_by_gdb_step {
            self.notify_gdb_stop(StopReason::stopped(
                task.pid(),
                self.pid(),
                StopEvent::Signal(Signal::SIGTRAP),
                regs.into(),
            ))
            .await?;
            let running = self
                .await_gdb_resume(task, ExpectedGdbResume::Resume)
                .await?;
            HandleSignalResult::SignalSuppressed(
                running.next_state_with_owner(&self.ptracer_waits).await?,
            )
        } else {
            UNCLAIMED_SIGTRAPS_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            // The trap is not delivered and makes no Tool callback, so it
            // leaves the timer event as it was, and what of the event nothing
            // else will drive, the single steps toward it that it interrupted
            // or a lost notification, is finished here.
            let task = match self.timer.disregard_stop()? {
                Some(unfinished) => self.drive_timer(task, Some(unfinished)).await?.1,
                None => task,
            };
            let running = self.resume_stopped(task, None)?;
            HandleSignalResult::SignalSuppressed(
                running.next_state_with_owner(&self.ptracer_waits).await?,
            )
        })
    }

    async fn handle_sigstop(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        let resumed_by_gdb_step = self
            .resumed_by_gdb
            .is_some_and(|action| matches!(action, ResumeAction::Step(_)));
        debug_assert!(!resumed_by_gdb_step);
        if let Some((suspended_flag, stop_tx)) = self.get_stop_tx().await {
            let notify_stop_tx = stop_tx
                .send((
                    task.pid(),
                    Suspended {
                        waker: self.exit_suspend_tx.clone(),
                        suspended: suspended_flag,
                    },
                ))
                .await;
            drop(stop_tx);
            if notify_stop_tx.is_ok()
                && let Some(rx) = self.exit_suspend_rx.as_mut()
                && rx.recv().await.is_none()
            {
                tracing::warn!(
                    tid = %self.tid(),
                    "tracee suspension channel closed before resume"
                );
            }
        }
        Ok(HandleSignalResult::SignalSuppressed(
            self.resume_stopped(task, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await?,
        ))
    }

    #[cfg(target_arch = "x86_64")]
    async fn handle_sigsegv(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        let regs = task.getregs()?;
        let trap_info = Addr::from_raw(regs.rip as usize)
            .and_then(|addr| task.read_value(addr).ok())
            .and_then(SegfaultTrapInfo::decode_segfault);
        Ok(match trap_info {
            Some(SegfaultTrapInfo::Cpuid)
                if self.global_state.subscriptions.has_cpuid() && self.has_cpuid_interception =>
            {
                let regs = self.handle_cpuid(regs).await?;
                task.setregs(&regs)?;
                HandleSignalResult::SignalSuppressed(
                    self.resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?,
                )
            }
            Some(SegfaultTrapInfo::Rdtscs(req)) if self.global_state.subscriptions.has_rdtsc() => {
                let regs = self.handle_rdtscs(regs, req).await?;
                task.setregs(&regs)?;
                HandleSignalResult::SignalSuppressed(
                    self.resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?,
                )
            }
            _ => HandleSignalResult::SignalToDeliver(task, Signal::SIGSEGV),
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    async fn handle_sigsegv(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        Ok(HandleSignalResult::SignalToDeliver(task, Signal::SIGSEGV))
    }

    fn liteinst_activation_in_progress(&self) -> bool {
        #[cfg(test)]
        let test_activation_bypass = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.activate_without_handshake);
        #[cfg(not(test))]
        let test_activation_bypass = false;

        self.global_state.liteinst_runtime.is_some()
            && self.liteinst_runtime.lock().unwrap().phase != LiteinstRuntimePhase::Ready
            && !test_activation_bypass
    }

    /// Reads the tracee's mappings for the census snapshot that Ready takes.
    /// A failed read fails the run closed: entering Ready without the
    /// mappings would refuse every site, which changes the guest's schedule
    /// without any report.
    fn read_ready_guest_maps(&mut self, task: &Stopped, at: &str) -> Result<Vec<GuestMap>, Errno> {
        read_guest_maps(task.pid()).map_err(|error| {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::ReadGuestMaps,
                Error::runtime(
                    self.tid(),
                    "read the tracee's mappings for the LiteInst entry census",
                    format!("at {at}: {error}"),
                ),
            );
            Errno::new(error.raw_os_error().unwrap_or(libc::EIO))
        })
    }

    fn record_liteinst_failure(&mut self, reason: LiteinstActivationFailureReason, error: Error) {
        let stage = match self.liteinst_runtime.lock().unwrap().phase {
            LiteinstRuntimePhase::Ready => LiteinstActivationStage::PostReady,
            LiteinstRuntimePhase::PreExec
            | LiteinstRuntimePhase::Waiting
            | LiteinstRuntimePhase::Bootstrap
            | LiteinstRuntimePhase::Failed => LiteinstActivationStage::PreReady,
        };
        let failure = LiteinstActivationFailure::new(stage, reason, error);
        if let Some(runtime) = self.global_state.liteinst_runtime.clone() {
            let mut slot = runtime.session_failure.lock().unwrap();
            if slot.is_none() {
                *slot = Some(format!("tracee {}: {failure}", self.tid()));
                drop(slot);
                runtime.session_failure_changed.notify_waiters();
            }
        }
        self.liteinst_failure = Some(failure);
    }

    fn reject_liteinst_activation_signal(
        &mut self,
        sig: Signal,
        reason: LiteinstActivationFailureReason,
        detail: impl Into<String>,
    ) -> TraceError {
        self.record_liteinst_failure(
            reason,
            Error::runtime(
                self.tid(),
                "reject unexpected LiteInst activation signal",
                format!(
                    "received {sig} before the required preload handshake completed: {}",
                    detail.into()
                ),
            ),
        );
        Errno::EPROTO.into()
    }

    fn take_pending_signal_for_resume(
        &mut self,
        operation: LiteinstActivationOperation,
    ) -> Result<Option<Signal>, TraceError> {
        let signal = self.pending_signal.take();
        if self.liteinst_activation_in_progress()
            && let Some(sig) = signal
        {
            return Err(self.reject_liteinst_activation_signal(
                sig,
                LiteinstActivationFailureReason::SignalBeforeHandshake(operation),
                format!(
                    "{} attempted to deliver a queued signal",
                    operation.as_str()
                ),
            ));
        }
        Ok(signal)
    }

    /// Reports a signal taken from `pending_signal` to `Tool::handle_signal_event`
    /// and returns the Tool's verdict for the resume. `stop_signal` is the
    /// signal of the delivery stop the callback started at, `None` if that
    /// stop is not a signal-delivery stop.
    ///
    /// A signal is held when it stopped an injected syscall's step (see
    /// `status_to_result`), which consumed the kernel's copy. The callback's
    /// final resume hands it back from a signal-delivery stop (the held
    /// signal's own, or a later injection's step SIGTRAP), where the kernel
    /// delivers whatever signal it is given without another stop. Without
    /// this report `handle_signal` never sees the signal and the Tool cannot
    /// act on it: Hermit's `--sigint-instakill` missed a SIGINT that
    /// interrupted a blocking stdin read
    /// (<https://github.com/rrnewton/hermit/issues/3468>).
    ///
    /// From any other stop the signal is passed on unreported, because the
    /// resume does not deliver it there: at a syscall stop Linux queues it,
    /// so the main loop meets it at a later signal-delivery stop, and at a
    /// ptrace event stop or a group stop Linux drops it. The stop is the
    /// latest injection's (`latest_injection_stop`) or else the callback's
    /// own. A signal the guest's mask blocks by now is also passed on
    /// unreported: `ptrace_signal` requeues a resumed signal that
    /// `task->blocked` blocks, and the main loop reports it when it is
    /// delivered after an unblock. This happens when a later injection's step
    /// let the kernel restore a mask-swapping syscall's saved mask. SIGSTOP
    /// and the timer signal are also passed on unreported, as before:
    /// `handle_signal` never reports SIGSTOP to the Tool, and a held timer
    /// signal is <https://github.com/rrnewton/reverie/issues/747>.
    ///
    /// A signal is also passed on unreported while a mask-swapping syscall's
    /// restore of its saved mask is pending (`PTRACE_GETSIGMASK` differs from
    /// the mask in effect), or when that cannot be read. An injection by the
    /// callback would let the kernel restore the saved mask before the
    /// signal is delivered, and the guest's registers would restart that
    /// syscall, which takes the signal again. Unreported, the signal is
    /// resumed as before this report existed.
    ///
    /// A signal is also passed on unreported when an earlier report already
    /// covered it: `Tool::handle_signal_event` reported it at an earlier stop
    /// and the resume put it back in the kernel's queue
    /// (`reported_requeued_signals`), from which an injection took it again.
    /// The count is by signal number, and only a held signal takes from it:
    /// a second instance of that number, or a later one after the counted
    /// instance was delivered at its own stop instead, goes unreported, as
    /// every held signal did before this report.
    ///
    /// Last, a signal is passed on unreported while another signal is
    /// pending in the kernel (`SigPnd` or `ShdPnd`). The callback's
    /// injections step the guest, and a pending signal the guest's mask lets
    /// through can stop a step. It is put back in the kernel's queue
    /// (`in_held_signal_callback`) unless it is SIGTRAP, which coalesces
    /// with the step's own or, before the `syscall`, is discarded
    /// (`untraced_syscall`), or SIGSTOP, which cannot be blocked and is taken
    /// into `pending_signal`, whose single slot this resume does not empty.
    /// Unreported, the pending signal stays in the kernel and
    /// reaches the main loop at its own delivery stop. A pending SIGTRAP is
    /// let through only while the step of the injection that held this
    /// signal left its own SIGTRAP queued (`stale_private_step_trap`); the
    /// two coalesce, and the next step discards the stale one. The timer
    /// signal is not let through: a pending signal of its number need not be
    /// this thread's own timer notification, which is all a step discards
    /// (`take_own_timer_notification`). Not handled here
    /// (<https://github.com/rrnewton/reverie/issues/845>): a SIGSTOP that
    /// arrives while the callback runs, or a signal a mask-swapping
    /// injection of the callback holds (`step_private_syscall`), can still be
    /// taken into `pending_signal` and stay there. In plain words: if the
    /// callback queues a signal to its thread and then injects a
    /// mask-swapping syscall such as `ppoll` that the signal interrupts, the
    /// signal is held, and if the guest exits before another stop empties
    /// `pending_signal`, its handler never runs. Main's ordinary signal hooks
    /// lose a signal the same way
    /// (`signal_held_by_a_signal_hook_injection_is_not_delivered`).
    ///
    /// A signal is also passed on unreported, as every held signal was
    /// before this report, while the main loop may do more with a SIGTRAP
    /// the guest or another process sends than discard it
    /// (`sigtrap_may_be_claimed`). Such a trap can arrive while the
    /// callback's injection runs, after every check above: past the
    /// `syscall` it merges with the step's own SIGTRAP, which Linux queues
    /// at most once, and the step takes it for its report. Without the
    /// callback the trap stops the guest's own code, where `handle_sigtrap`
    /// decides it from the guest's registers.
    ///
    /// A signal is also passed on unreported while the guest's return
    /// register holds `-ERESTART_RESTARTBLOCK` in a syscall. Linux restarts
    /// that syscall through the thread's restart block, which any injected
    /// syscall that returns the same code replaces; the guest would then
    /// get the callback's last injection result in place of the restarted
    /// syscall's (`signal_callback_guest_ret`). Main resumes the guest with
    /// its own block there. A failed read of the mask, the pending set or
    /// the registers passes the signal on unreported as well, as main
    /// resumes it, rather than failing the resume.
    /// So does a signal whose siginfo was not recorded at its stop
    /// (`TakenSignal::at_stop`), which could not be written back after the
    /// callback's injections.
    ///
    /// A signal is also passed on unreported when the tracer thread may be
    /// under a seccomp filter, or its mode cannot be read
    /// (`thread_may_be_seccomp_filtered`). A filter can make the
    /// `PTRACE_SETSIGINFO` of `resume_with_signal` fail, and a signal resumed
    /// from a callback injection's stop would then reach the guest with the
    /// siginfo Linux makes up (`SI_USER`, the tracer's thread ID, no value).
    /// Main resumes it with the siginfo of the stop it is resumed from, which
    /// with no injection in between is its own. A request the filter allowed
    /// earlier does not show that it allows this one: a filter that denies
    /// after a first success would see the earlier one succeed. This is
    /// checked before the other checks' ptrace requests, which main does not
    /// make here and a filter can refuse, or kill the tracer at. The cost is
    /// that a tracer run under such a policy (a container's default seccomp
    /// profile, for one) gets no held report, as on main.
    ///
    /// A returning `tail_inject` from the callback ends it and passes the
    /// signal on (`report_signal`).
    async fn report_held_signal(
        &mut self,
        task: &Stopped,
        stop_signal: Option<Signal>,
        signal: Option<Signal>,
    ) -> Result<SignalResume, TraceError> {
        let taken = self.pending_signal_taken.take();
        let Some(sig) = signal else {
            return Ok(self.pass_held_signal_unreported(None));
        };
        if sig == Signal::SIGSTOP
            || sig == Timer::signal_type()
            || self.latest_injection_stop.unwrap_or(stop_signal).is_none()
            || self.sigtrap_may_be_claimed()
        {
            return Ok(self.pass_held_signal_unreported(signal));
        }
        // `resume_with_signal` writes the siginfo back with
        // `PTRACE_SETSIGINFO`, which a seccomp filter of the tracer can make
        // fail while the guest is alive. An earlier request a filter allows
        // does not tell that it allows that later one. Checked before the
        // ptrace requests below, which main does not make here and a filter
        // can deny as well. The record was not taken under a filter
        // (`TakenSignal::at_stop`), and a filter is never removed, so no
        // later held signal is reported.
        if thread_may_be_seccomp_filtered() {
            return Ok(self.pass_held_signal_unreported(signal));
        }
        // A procfs or register read that fails passes the signal on
        // unreported, as main resumes every held signal, rather than failing
        // a resume main makes.
        let Ok(blocked) = blocked_signal_mask(task.pid()) else {
            return Ok(self.pass_held_signal_unreported(signal));
        };
        if blocked & signal_mask_bit(sig) != 0
            || !task.getsigmask().is_ok_and(|saved| saved == blocked)
        {
            return Ok(self.pass_held_signal_unreported(signal));
        }
        // The guest's syscall is to restart through its own restart block.
        // A callback injection can replace that block, and the guest would
        // then restart the injection's syscall or keep its result
        // (`signal_callback_guest_ret`), where main, which reports no held
        // signal, restarts the guest's own.
        if !task.getregs().is_ok_and(|regs| {
            (regs.orig_syscall() as i64) < 0
                || Errno::from_ret(regs.ret() as usize) != Err(Errno::ERESTART_RESTARTBLOCK)
        }) {
            return Ok(self.pass_held_signal_unreported(signal));
        }
        if let Some(count) = self.reported_requeued_signals.get_mut(&sig) {
            *count -= 1;
            if *count == 0 {
                self.reported_requeued_signals.remove(&sig);
            }
            return Ok(self.pass_held_signal_unreported(signal));
        }
        // Without its record the siginfo cannot be written back after the
        // callback's injections, and the guest would get one Linux makes up.
        // The capture can fail where this check passes: a procfs open the
        // capture made can fail (EMFILE) and a later one succeed.
        let Some(taken) = taken.filter(|taken| taken.signal == sig) else {
            return Ok(self.pass_held_signal_unreported(signal));
        };
        let stale_step_trap = if self.stale_private_step_trap {
            signal_mask_bit(Signal::SIGTRAP)
        } else {
            0
        };
        if pending_signal_mask(task.pid()).map_or(true, |pending| pending & !stale_step_trap != 0) {
            return Ok(self.pass_held_signal_unreported(signal));
        }
        tracing::debug!(
            "[{}] reporting held signal {} before resuming",
            self.tid(),
            sig
        );
        let verdict = self.report_signal(sig, true).await?;
        Ok(SignalResume {
            signal: verdict.signal,
            reported: Some(taken),
        })
    }

    /// A conservative guard used while a private injection runs: whether an
    /// asynchronous SIGTRAP from the guest or another process could be
    /// claimed by a consumer other than the injection, so the injection must
    /// not discard it. True when a binary rewriter's trap is configured
    /// (`injected_syscall_trap`), which delivers a trap with its marker in
    /// RAX; when gdb has resumed this thread or set a breakpoint in it, so a
    /// trap can be reported to gdb; or when a LiteInst runtime has not
    /// reached Ready, so the trap fails the run. This is not an exhaustive
    /// classifier of `handle_sigtrap`, which also claims a Ready LiteInst
    /// controller's traps and `SI_KERNEL` restart landings; those are not
    /// asynchronous traps that can interrupt a private injection.
    fn sigtrap_may_be_claimed(&self) -> bool {
        self.global_state.injected_syscall_trap.is_some()
            || self.resumed_by_gdb.is_some()
            || !self.breakpoints.is_empty()
            || (self.global_state.liteinst_runtime.is_some()
                && self.liteinst_runtime.lock().unwrap().phase != LiteinstRuntimePhase::Ready)
    }

    /// The resume of a held `signal` that is passed on without a report to
    /// `Tool::handle_signal_event`. A job-control stop signal is recorded
    /// (`unreported_stop_signal`), so that the group stop its delivery makes
    /// is reported instead.
    fn pass_held_signal_unreported(&mut self, signal: Option<Signal>) -> SignalResume {
        if let Some(sig @ (Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU)) = signal {
            self.unreported_stop_signal = Some(sig);
        }
        SignalResume {
            signal,
            reported: None,
        }
    }

    /// Resumes `task` with `resume.signal` and waits for its next stop.
    ///
    /// When the signal is one `Tool::handle_signal_event` reported and the
    /// callback's injections ran, the stop is the latest injection's, not
    /// the signal's own. Resumed with another signal than the one it stopped
    /// with, a signal-delivery stop delivers a siginfo that Linux makes up
    /// (`SI_USER`, the tracer's thread ID, no value), so the signal's own is
    /// written back first, when its stop recorded it (`TakenSignal::at_stop`,
    /// which records nothing under a tracer seccomp filter). Without the
    /// record, or when that write fails, the signal is still delivered, with
    /// the made-up siginfo. For a signal at its own delivery
    /// stop that is what main delivers after the callback's injections. A
    /// held signal is reported only while the tracer thread is under no
    /// seccomp filter (`report_held_signal`), so its write can fail only when
    /// the guest is gone, when the callback installs a filter on the tracer
    /// thread, or when something else outside Reverie fails the request
    /// (<https://github.com/rrnewton/reverie/issues/845>).
    ///
    /// The kernel puts the signal back in its queue instead of delivering it
    /// when the guest's mask blocks it by now (`ptrace_signal`). From a stop
    /// that is not a signal-delivery stop the outcome depends on the stop: a
    /// syscall stop queues the signal anew, while a ptrace event stop or a
    /// group stop drops it. A reported signal with a record resumed from
    /// such a stop, or put back because the mask blocks it, is counted in
    /// `reported_requeued_signals`; the count does not tell a queued
    /// instance from a dropped one
    /// (<https://github.com/rrnewton/reverie/issues/845>). Only an injection
    /// can bring either about, so without one there is nothing to check.
    async fn resume_with_signal(
        &mut self,
        task: Stopped,
        resume: SignalResume,
    ) -> Result<Wait, TraceError> {
        let SignalResume { signal, reported } = resume;
        if let (Some(sig), Some(taken), Some(stop)) = (signal, reported, self.latest_injection_stop)
            && sig == taken.signal
        {
            // Main writes no siginfo here, so a failed write must not fail
            // the resume. A task that is gone fails the resume instead.
            if stop.is_some()
                && let Err(err) = task.setsiginfo(&taken.siginfo.0)
            {
                tracing::debug!("could not restore the siginfo of {sig:?}: {err}");
            }
            // An unreadable mask is counted as blocking: main reads nothing
            // here, so the resume must not fail on it, and a count only
            // leaves a later held instance unreported, as main does.
            if stop.is_none()
                || blocked_signal_mask(task.pid())
                    .map_or(true, |blocked| blocked & signal_mask_bit(sig) != 0)
            {
                // Bounded: a count that is not consumed (`report_held_signal`
                // declines first) must not overflow on a long run.
                let count = self.reported_requeued_signals.entry(sig).or_default();
                *count = count.saturating_add(1);
            }
        }
        self.resume_stopped(task, signal)?
            .next_state_with_owner(&self.ptracer_waits)
            .await
    }

    /// Runs `Tool::handle_signal_event` for `sig` and returns its verdict.
    ///
    /// For a held signal (`held`, from `report_held_signal`), a returning
    /// `tail_inject` ends the callback (`do_tail_inject`) and the signal is
    /// passed on, as if the callback had returned it. Nothing else would
    /// end it: the syscall callback whose scope cancels a tail injection
    /// has already returned. A `tail_inject` from a post-exec callback
    /// (`Tool::handle_post_exec`) after the callback executed a program ends
    /// it as well, and the replacement image resumes with no signal. For a
    /// signal at its own delivery stop the callback is still awaited directly
    /// (<https://github.com/rrnewton/reverie/issues/862>).
    async fn report_signal(
        &mut self,
        sig: Signal,
        held: bool,
    ) -> Result<SignalVerdict, TraceError> {
        let outer = std::mem::replace(&mut self.in_signal_callback, true);
        let outer_replaced =
            std::mem::replace(&mut self.signal_callback_replaced_restart_block, false);
        let outer_guest_block =
            std::mem::replace(&mut self.signal_callback_guest_restart_block, false);
        let outer_held = std::mem::replace(&mut self.in_held_signal_callback, held);
        let result = if held {
            let outer_execed = std::mem::replace(&mut self.signal_callback_execed, false);
            let result = cancellable(self.cancel_handler.clone(), async {
                self.process_state
                    .clone()
                    .handle_signal_event(self, sig)
                    .await
            })
            .await;
            let execed = self.signal_callback_execed;
            self.signal_callback_execed = outer_execed || execed;
            // A callback that executed a program cannot ask for the signal:
            // a successful exec does not return from `Guest::inject`, and an
            // ordinary signal callback's exec resumes the replacement with
            // no signal. A held report matches, even when a post-exec
            // `tail_inject` cancels it. On main the guest's handler took the
            // signal when it made the exec, and the replacement resumed with
            // none.
            result.unwrap_or(Ok((!execed).then_some(sig)))
        } else {
            self.process_state
                .clone()
                .handle_signal_event(self, sig)
                .await
        };
        self.in_signal_callback = outer;
        self.in_held_signal_callback = outer_held;
        self.signal_callback_replaced_restart_block = outer_replaced;
        self.signal_callback_guest_restart_block = outer_guest_block;
        let signal = self
            .ordinary_callback_errno("ptrace signal callback", result)
            .await?;
        self.ordinary_trace_continuation()?;
        self.timer.finalize_requests();
        Ok(SignalVerdict { signal })
    }

    /// The guest's return register `ret`, saved in `context`, that a
    /// held-signal callback's injection restores, or `None` to leave the
    /// injection's own, as main always does.
    ///
    /// That is once an injection replaced the thread's restart block
    /// (`signal_callback_replaced_restart_block`) while the guest's return
    /// register held `-ERESTART_RESTARTBLOCK` in a syscall, now or earlier in
    /// the callback (`signal_callback_guest_restart_block`), and for every
    /// later injection of the callback. Restoring that code would make
    /// Linux restart the guest's syscall through `restart_syscall`, which
    /// runs the injection's restart block instead: an interrupted injected
    /// `nanosleep` would sleep out its own deadline in place of the guest's.
    /// The guest's return register is then the latest injection's return, or
    /// a Tool's write after it (`Guest::set_regs`).
    ///
    /// That is right only when it happens to be what the guest's syscall
    /// would have returned, as the zero of an injected sleep that outlasts
    /// the guest's deadline. When no handler is delivered at the resume,
    /// untraced Linux would restart the guest's syscall through its own
    /// restart block, which the injection replaced, so Reverie cannot
    /// restart it; when a handler runs, Linux returns `-EINTR`. The kernel
    /// decides which at the resume, from dispositions that another thread
    /// can change after any read Reverie could make, and so can a process
    /// that shares them without being traced (`CLONE_SIGHAND` with
    /// `CLONE_UNTRACED`), which procfs and `kcmp` cannot rule out: such a
    /// process can make itself uninspectable, or create another and exit
    /// while procfs is read (<https://github.com/rrnewton/reverie/issues/845>).
    fn signal_callback_guest_ret(
        &mut self,
        context: &libc::user_regs_struct,
        ret: Reg,
    ) -> Option<Reg> {
        self.note_guest_restart_block(context, ret);
        let keep_injection_ret =
            self.signal_callback_replaced_restart_block && self.signal_callback_guest_restart_block;
        (!keep_injection_ret).then_some(ret)
    }

    /// Notes in `signal_callback_guest_restart_block` whether `ret`, the
    /// guest's return register in `regs`, is `-ERESTART_RESTARTBLOCK` in a
    /// syscall.
    fn note_guest_restart_block(&mut self, regs: &libc::user_regs_struct, ret: Reg) {
        if (regs.orig_syscall() as i64) >= 0
            && Errno::from_ret(ret as usize) == Err(Errno::ERESTART_RESTARTBLOCK)
        {
            self.signal_callback_guest_restart_block = true;
        }
    }

    fn validate_nested_liteinst_activation_signal(
        &mut self,
        task: &Stopped,
        sig: Signal,
        operation: LiteinstActivationOperation,
        expected_trap: NestedTrapExpectation,
        forced_external_for_test: bool,
    ) -> Result<(), TraceError> {
        if !self.liteinst_activation_in_progress() {
            return Ok(());
        }
        let expected = sig == Signal::SIGTRAP
            && match expected_trap {
                NestedTrapExpectation::None => false,
                NestedTrapExpectation::SyscallSkip { pre_rip } => {
                    is_expected_syscall_skip_trap(task, pre_rip, forced_external_for_test)?
                }
                NestedTrapExpectation::Breakpoint(expected_rip) => {
                    is_expected_breakpoint_trap(task, expected_rip, forced_external_for_test)?
                }
                NestedTrapExpectation::PrivateSyscall(expected_rip) => {
                    is_expected_private_syscall_trap(task, expected_rip, forced_external_for_test)?
                }
            };
        if expected {
            return Ok(());
        }
        Err(self.reject_liteinst_activation_signal(
            sig,
            LiteinstActivationFailureReason::UnexpectedControllerProvenance(operation),
            format!(
                "{} observed a nested signal without the expected controller provenance",
                operation.as_str()
            ),
        ))
    }

    /// Handles a signal-delivery stop, or a group stop, of `sig`.
    /// `report_group_stop` says that the previous stop resumed `sig` held
    /// and unreported (`unreported_stop_signal`), so a group stop of it is
    /// reported.
    async fn handle_signal(
        &mut self,
        task: Stopped,
        sig: Signal,
        report_group_stop: bool,
    ) -> Result<Wait, TraceError> {
        if sig == Signal::SIGSTOP {
            self.trap_only_restore_reraised_stop(&task)?;
        }
        #[cfg(test)]
        if let Some(stats) = self.global_state.backend_stats.as_ref() {
            stats.record_signal_stop(&task, sig);
        }
        tracing::debug!("[{}] handle_signal: received signal {}", task.pid(), sig);
        if self.liteinst_activation_in_progress() {
            match sig {
                Signal::SIGTRAP => {}
                Signal::SIGSEGV => {
                    return match self.handle_sigsegv(task).await? {
                        HandleSignalResult::SignalSuppressed(wait) => Ok(wait),
                        HandleSignalResult::SignalToDeliver(_, _) => {
                            Err(self.reject_liteinst_activation_signal(
                                sig,
                                LiteinstActivationFailureReason::UnexpectedActivationSignal,
                                "the fault was not a subscribed, controller-intercepted CPUID or RDTSC instruction",
                            ))
                        }
                    };
                }
                sig if sig == Timer::signal_type() => {
                    let (was_timer, task) = self.handle_timer(task).await?;
                    if !was_timer {
                        return Err(self.reject_liteinst_activation_signal(
                            sig,
                            LiteinstActivationFailureReason::UnexpectedActivationSignal,
                            "the signal was not generated by this tracee's controller timer",
                        ));
                    }
                    return self
                        .resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await;
                }
                sig => {
                    return Err(self.reject_liteinst_activation_signal(
                        sig,
                        LiteinstActivationFailureReason::UnexpectedActivationSignal,
                        "the signal is outside the activation allowlist",
                    ));
                }
            }
        }
        if sig != Signal::SIGSTOP
            && !report_group_stop
            && is_group_stop_unless_filtered(&task, sig)?
        {
            // A group stop follows a stop signal's delivery, which reported
            // it to the Tool on the thread that took it, unless that thread
            // resumed it held and unreported (`report_group_stop`). Reporting
            // the group stop as well would report one signal twice, and once
            // more on every other thread of the group. A restarted ptraced tracee
            // does not honor the stop, so it is resumed without a signal.
            // Like a trap that `handle_sigtrap` discards, it makes no Tool
            // callback and leaves the timer event as it was.
            // Under a tracer filter it is not told apart, as on main, and is
            // reported again (`is_group_stop_unless_filtered`).
            let task = match self.timer.disregard_stop()? {
                Some(unfinished) => self.drive_timer(task, Some(unfinished)).await?.1,
                None => task,
            };
            return self
                .resume_stopped(task, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await;
        }
        let result = match sig {
            Signal::SIGSEGV => self.handle_sigsegv(task).await?,
            Signal::SIGSTOP => self.handle_sigstop(task).await?,
            Signal::SIGTRAP => self.handle_sigtrap(task).await?,
            sig if sig == Timer::signal_type() => {
                let (was_timer, task) = self.handle_timer(task).await?;
                if was_timer {
                    // The Tool's timer callback can inject from this stop.
                    self.restore_liteinst_restart_marker(&task)?;
                    HandleSignalResult::SignalSuppressed(
                        self.resume_stopped(task, None)?
                            .next_state_with_owner(&self.ptracer_waits)
                            .await?,
                    )
                } else {
                    HandleSignalResult::SignalToDeliver(task, sig)
                }
            }
            sig => HandleSignalResult::SignalToDeliver(task, sig),
        };

        match result {
            HandleSignalResult::SignalSuppressed(wait) => Ok(wait),
            HandleSignalResult::SignalToDeliver(task, sig) => {
                let taken = TakenSignal::at_stop(&task, sig);
                let verdict = self.report_signal(sig, false).await?;
                let signal = verdict.signal;
                self.restore_liteinst_restart_marker(&task)?;
                if let Some(sig) = signal {
                    // A signal delivered at a rewound host-hybrid int3 decides
                    // the pending restart, as Linux decides it at delivery.
                    self.arm_liteinst_restart_landing(&task, sig)?;
                }
                let resume = SignalResume {
                    signal,
                    reported: taken,
                };
                self.resume_with_signal(task, resume).await
            }
        }
    }

    fn reject_liteinst_nonleader_exec(&mut self, former_tid: Pid) -> TraceError {
        self.record_liteinst_failure(
            LiteinstActivationFailureReason::PostStartExec,
            Error::runtime(
                self.tid(),
                "reject LiteInst post-start exec",
                format!(
                    "exec requires the original thread-group leader (former tid {former_tid}, event tid {}, pid {})",
                    self.tid(), self.pid()
                ),
            ),
        );
        Errno::ENOTSUPP.into()
    }

    // PTRACE_GETEVENTMSG reports the caller's former TID. A nonleader exec
    // already has the leader's TID at this stop, so is_main_thread alone cannot
    // establish which thread replaced the image.
    async fn handle_exec_event(
        &mut self,
        task: Stopped,
        former_tid: Pid,
    ) -> Result<Wait, TraceError> {
        // A signal callback that injected the exec never resumes, so the
        // replacement image runs outside it, and its state, which
        // `report_signal` would have restored, must not reach the post-exec
        // callbacks' injections: a held callback's injections keep the
        // guest's return register.
        self.in_signal_callback = false;
        self.in_held_signal_callback = false;
        self.signal_callback_replaced_restart_block = false;
        self.signal_callback_guest_restart_block = false;
        self.signal_callback_execed = true;
        // PTRACE_EVENT_EXEC proves replacement succeeded. Clear before any
        // post-exec Tool callback; failed exec attempts retain launch provenance.
        let initial_command = self.command_bootstrap;
        if initial_command {
            self.timer.begin_initial_exec();
        }
        self.command_bootstrap = false;
        self.trap_only_exec(initial_command);
        // The replaced image has no rewound host-hybrid trap to re-execute.
        self.liteinst_pending_restarts.clear();
        if self.global_state.liteinst_runtime.is_some() {
            if former_tid != self.tid() {
                return Err(self.reject_liteinst_nonleader_exec(former_tid));
            }
            let state = self.liteinst_runtime.lock().unwrap();
            if state.phase != LiteinstRuntimePhase::PreExec
                && !(state.phase == LiteinstRuntimePhase::Ready && self.is_main_thread())
            {
                let phase = state.phase;
                drop(state);
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::PostStartExec,
                    Error::runtime(
                        self.tid(),
                        "reject LiteInst post-start exec",
                        format!(
                            "exec requires an activated thread-group leader (phase {phase:?}, tid {}, pid {})",
                            self.tid(), self.pid()
                        ),
                    ),
                );
                return Err(Errno::ENOTSUPP.into());
            }
            let next = state.after_exec();
            drop(state);
            let next = match next {
                Ok(next) => next,
                Err(error) => {
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::PostStartExec,
                        Error::runtime(
                            self.tid(),
                            "advance LiteInst execution generation",
                            error.to_string(),
                        ),
                    );
                    return Err(error.into());
                }
            };
            // The kernel has replaced this address space. Other holders of the
            // old image's state must not observe this reset, and no saved code
            // or controller-stack address may be reused by the new image.
            self.liteinst_runtime = Arc::new(StdMutex::new(next));
            self.liteinst_entry_guard = None;
        }
        // execve/execveat are tail injected, however, after exec, the new
        // program start as a clean slate, hence it is actually ok to do either
        // inject or tail inject after execve succeeded.
        self.pending_syscall = None;
        self.pending_syscall_already_skipped = false;
        self.injected_syscall_frame = None;

        // TODO: Update PID? Need to write a test checking this.

        // Step the tracee to get the SIGTRAP that immediately follows the
        // PTRACE_EVENT_EXEC. We can't call `tracee_preinit` until after this
        // because when it tries to step the tracee, it'll get this SIGTRAP
        // signal instead.
        let task = if self.global_state.liteinst_runtime.is_some() {
            let expected_post_exec_rip = task.getregs()?.ip();
            let wait = self
                .step_stopped(task, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await?;
            self.arm_liteinst_wait(&wait);
            match wait {
                Wait::Stopped(task, Event::Signal(Signal::SIGTRAP)) => {
                    #[cfg(test)]
                    let forced_external_sigtrap = self
                        .global_state
                        .liteinst_runtime
                        .as_ref()
                        .and_then(|runtime| runtime.force_post_exec_signal_once.as_ref())
                        .is_some_and(|force_once| force_once.swap(false, Ordering::SeqCst));
                    #[cfg(not(test))]
                    let forced_external_sigtrap = false;
                    self.validate_nested_liteinst_activation_signal(
                        &task,
                        Signal::SIGTRAP,
                        LiteinstActivationOperation::WaitForPostExecTrap,
                        NestedTrapExpectation::Breakpoint(expected_post_exec_rip),
                        forced_external_sigtrap,
                    )?;
                    task
                }
                Wait::Stopped(task, Event::Signal(sig)) => {
                    self.validate_nested_liteinst_activation_signal(
                        &task,
                        sig,
                        LiteinstActivationOperation::WaitForPostExecTrap,
                        NestedTrapExpectation::None,
                        false,
                    )?;
                    unreachable!("activation validation must reject a non-SIGTRAP signal")
                }
                Wait::Stopped(_, event) => {
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::UnexpectedPostExecEvent,
                        Error::runtime(
                            self.tid(),
                            "validate LiteInst post-exec trap",
                            format!(
                                "received unexpected {event:?} before tracee pre-initialization"
                            ),
                        ),
                    );
                    return Err(Errno::EPROTO.into());
                }
                Wait::Exited(pid, exit_status) => {
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::ExitedBeforePostExecTrap,
                        Error::runtime(
                            pid,
                            "validate LiteInst post-exec trap",
                            format!(
                                "tracee exited with {exit_status:?} before the required post-exec SIGTRAP"
                            ),
                        ),
                    );
                    return Err(Errno::EPROTO.into());
                }
            }
        } else {
            #[cfg(test)]
            let preinit_point = self.global_state.preinit_point_for_test.clone();
            #[cfg(test)]
            at_preinit_point(
                &preinit_point,
                task.pid(),
                || task.terminal_cleanup(),
                PreinitPoint::ExecStopped,
            );
            let stepped = self.step_stopped(task, None)?;
            #[cfg(test)]
            let stepped = match POST_EXEC_STEP_FOR_TEST.with(|slot| slot.borrow_mut().take()) {
                Some(hook) => hook(stepped),
                None => stepped,
            };
            #[cfg(test)]
            at_preinit_point(
                &preinit_point,
                stepped.pid(),
                || stepped.terminal_cleanup(),
                PreinitPoint::PostExecStepped,
            );
            // A SIGKILL at the exec stop leaves the tracee in its exit stop,
            // which is published to the exit notifier, not to this wait. The
            // step resumes it from there, so the wait can see it exit, as the
            // mmap wait in `tracee_preinit` can.
            // Keep the task's original owner/generation while filtering, as
            // every other ordinary wait does. Generic wait_for_signal requires
            // a native thread pidfd, even when its input retained legacy mode.
            let mut running = stepped;
            let (task, event) = loop {
                match running.next_state_with_owner(&self.ptracer_waits).await? {
                    Wait::Stopped(task, event) if event == Event::Signal(Signal::SIGTRAP) => {
                        break (task, event);
                    }
                    Wait::Stopped(task, event) => {
                        self.arm_liteinst_root_stop(&task, &event);
                        let signal = match event {
                            Event::Signal(signal) => Some(signal),
                            _ => None,
                        };
                        running = self.resume_stopped(task, signal)?;
                    }
                    Wait::Exited(pid, exit_status) => return Ok(Wait::Exited(pid, exit_status)),
                }
            };
            assert_eq!(event, Event::Signal(Signal::SIGTRAP));
            self.arm_liteinst_root_stop(&task, &event);
            task
        };
        let mut task = match self.tracee_preinit(task, PreinitPlace::AtExec).await? {
            PreinitOutcome::Ready(task) => task,
            PreinitOutcome::Exited(pid, exit_status) => {
                return Ok(Wait::Exited(pid, exit_status));
            }
        };
        if let Err(error) = self.install_liteinst_entry_guard(&mut task) {
            self.record_liteinst_failure(
                LiteinstActivationFailureReason::InstallExecutableEntryGuard,
                Error::runtime(
                    self.tid(),
                    "install LiteInst executable-entry guard",
                    error.to_string(),
                ),
            );
            return Err(error);
        }

        #[cfg(test)]
        if self
            .global_state
            .liteinst_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.activate_without_handshake)
        {
            if let Err(error) = self.restore_liteinst_entry_guard(&mut task) {
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::RestoreExecutableEntryGuard,
                    Error::runtime(
                        self.tid(),
                        "restore test LiteInst executable-entry guard",
                        error.to_string(),
                    ),
                );
                return Err(error);
            }
            {
                let maps = self.read_ready_guest_maps(&task, "test LiteInst Ready")?;
                self.liteinst_runtime.lock().unwrap().enter_ready(maps);
            }
        }

        if initial_command {
            self.timer.finish_initial_exec();
        }
        let result = self.process_state.clone().handle_post_exec(self).await;
        self.ordinary_callback_errno("ptrace post-exec callback", result)
            .await?;
        self.ordinary_trace_continuation()?;
        self.observe_ready_thread_state()?;
        self.timer.finalize_requests();

        if self.attached_by_gdb {
            let request_tx = self.gdb_request_tx.clone();
            let resume_tx = self.gdb_resume_tx.clone();

            let proc_exe = format!("/proc/{}/exe", task.pid());
            let exe = std::fs::read_link(&proc_exe).unwrap_or_else(|err| {
                tracing::warn!(
                    tid = %self.tid(),
                    path = %proc_exe,
                    error = %err,
                    "failed to resolve executable after exec; reporting procfs path to GDB"
                );
                proc_exe.clone().into()
            });

            let stopped = StoppedInferior {
                reason: StopReason::stopped(
                    task.pid(),
                    self.pid(),
                    StopEvent::Exec(exe),
                    task.getregs()?.into(),
                ),
                request_tx: request_tx.ok_or(Errno::EIO)?,
                resume_tx: resume_tx.ok_or(Errno::EIO)?,
            };

            // NB: notify initial gdb stop, this is the first time we can
            // tell gdb tracee is ready, because a new memory map has been
            // loaded (due to execve). Otherwise gdb may try to manipulate
            // old process' address space.
            if let Some(attach_tx) = self.gdb_stop_tx.as_ref()
                && attach_tx.send(stopped).await.is_err()
            {
                tracing::warn!(
                    tid = %self.tid(),
                    "GDB stop channel closed while reporting exec"
                );
                self.attached_by_gdb = false;
                return self
                    .step_stopped(task, None)?
                    .next_state_with_owner(&self.ptracer_waits)
                    .await;
            }
            let running = self
                .await_gdb_resume(task, ExpectedGdbResume::Resume)
                .await?;
            Ok(running.next_state_with_owner(&self.ptracer_waits).await?)
        } else {
            if self.global_state.liteinst_runtime.is_some() {
                return self
                    .resume_stopped(task, None)?
                    .next_state_with_owner(&self.ptracer_waits)
                    .await;
            }
            let wait = self
                .step_stopped(task, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await?;
            self.arm_liteinst_wait(&wait);
            match wait {
                Wait::Stopped(task, Event::Signal(Signal::SIGTRAP))
                    if task.getsiginfo()?.si_code == libc::TRAP_TRACE =>
                {
                    // This is the directly awaited controller single-step,
                    // with no debugger attached. It is not a Tool event and
                    // must not cancel the timer just requested in post-exec.
                    // A real signal, breakpoint, instruction fault, or other
                    // stop still goes through ordinary event accounting.
                    self.ordinary_trace_continuation()?;
                    self.timer.finalize_requests();
                    self.resume_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await
                }
                wait => Ok(wait),
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    async fn liteinst_arch_prctl<S: SyscallInfo>(
        &mut self,
        task: Stopped,
        syscall: S,
    ) -> (Stopped, Result<Result<i64, Errno>, TraceError>) {
        let (nr, args) = syscall.into_parts();
        let result = self.untraced_syscall(task, nr, args).await;
        (self.assume_stopped(), result)
    }

    #[cfg(target_arch = "x86_64")]
    async fn liteinst_prctl(
        &mut self,
        task: Stopped,
        option: libc::c_int,
        arg2: usize,
    ) -> (Stopped, Result<Result<i64, Errno>, TraceError>) {
        let result = self
            .untraced_syscall(
                task,
                Sysno::prctl,
                SyscallArgs::new(option as usize, arg2, 0, 0, 0, 0),
            )
            .await;
        (self.assume_stopped(), result)
    }

    #[cfg(target_arch = "x86_64")]
    async fn liteinst_get_tsc_state(
        &mut self,
        task: Stopped,
        scratch_address: usize,
    ) -> (Stopped, Result<Result<libc::c_int, Errno>, String>) {
        // PR_GET_TSC writes a c_int through a tracee pointer. Reuse the
        // already-validated helper return slot: its original eight bytes are
        // saved before this call, the helper return address replaces them
        // before execution, and every exit path restores them.
        let (task, result) = self
            .liteinst_prctl(task, libc::PR_GET_TSC, scratch_address)
            .await;
        let result = match result {
            Ok(Ok(0)) => match Addr::<libc::c_int>::from_raw(scratch_address) {
                Some(address) => task
                    .read_value(address)
                    .map(Ok)
                    .map_err(|error| format!("read PR_GET_TSC state: {error}")),
                None => Err("PR_GET_TSC scratch address is null".to_owned()),
            },
            Ok(Ok(result)) => Err(format!("PR_GET_TSC returned unexpected value {result}")),
            Ok(Err(error)) => Ok(Err(error)),
            Err(error) => Err(format!("inject PR_GET_TSC: {error}")),
        };
        (task, result)
    }

    #[cfg(target_arch = "x86_64")]
    async fn liteinst_set_tsc_state(
        &mut self,
        task: Stopped,
        state: libc::c_int,
    ) -> (Stopped, Result<Result<i64, Errno>, TraceError>) {
        self.liteinst_prctl(task, libc::PR_SET_TSC, state as usize)
            .await
    }

    #[cfg(target_arch = "x86_64")]
    async fn liteinst_get_cpuid_state(
        &mut self,
        task: Stopped,
    ) -> (Stopped, Result<Result<i64, Errno>, TraceError>) {
        use reverie::syscalls::ArchPrctl;
        use reverie::syscalls::ArchPrctlCmd;

        self.liteinst_arch_prctl(
            task,
            ArchPrctl::new().with_cmd(ArchPrctlCmd::ARCH_GET_CPUID(None)),
        )
        .await
    }

    #[cfg(target_arch = "x86_64")]
    async fn liteinst_set_cpuid_state(
        &mut self,
        task: Stopped,
        state: u64,
    ) -> (Stopped, Result<Result<i64, Errno>, TraceError>) {
        use reverie::syscalls::ArchPrctl;
        use reverie::syscalls::ArchPrctlCmd;

        self.liteinst_arch_prctl(
            task,
            ArchPrctl::new().with_cmd(ArchPrctlCmd::ARCH_SET_CPUID(state)),
        )
        .await
    }

    #[cfg(target_arch = "x86_64")]
    async fn set_and_verify_liteinst_cpuid_state(
        &mut self,
        task: Stopped,
        state: u64,
    ) -> (Stopped, Vec<String>) {
        let (task, set_result) = self.liteinst_set_cpuid_state(task, state).await;
        let mut failures = Vec::new();
        match set_result {
            Ok(Ok(0)) => {}
            Ok(Ok(result)) => failures.push(format!(
                "ARCH_SET_CPUID({state}) returned unexpected value {result}"
            )),
            Ok(Err(error)) => failures.push(format!("ARCH_SET_CPUID({state}): {error}")),
            Err(error) => failures.push(format!("inject ARCH_SET_CPUID({state}): {error}")),
        }
        let (task, verify_failures) = self.verify_liteinst_cpuid_state(task, state).await;
        failures.extend(verify_failures);
        (task, failures)
    }

    #[cfg(target_arch = "x86_64")]
    async fn verify_liteinst_cpuid_state(
        &mut self,
        task: Stopped,
        state: u64,
    ) -> (Stopped, Vec<String>) {
        let mut failures = Vec::new();
        let (task, get_result) = self.liteinst_get_cpuid_state(task).await;
        match get_result {
            Ok(Ok(observed)) if observed == state as i64 => {}
            Ok(Ok(observed)) => failures.push(format!(
                "ARCH_GET_CPUID returned {observed} after setting {state}"
            )),
            Ok(Err(error)) => failures.push(format!("verify ARCH_GET_CPUID({state}): {error}")),
            Err(error) => failures.push(format!("inject verification ARCH_GET_CPUID: {error}")),
        }
        (task, failures)
    }

    #[cfg(target_arch = "x86_64")]
    async fn prepare_liteinst_helper_cpuid(
        &mut self,
        task: Stopped,
    ) -> (Stopped, Result<LiteinstCpuidPolicy, String>) {
        let (task, result) = self.liteinst_get_cpuid_state(task).await;
        match result {
            Ok(Ok(1)) => (task, Ok(LiteinstCpuidPolicy::UnchangedEnabled)),
            Ok(Ok(0)) => {
                let (task, enable_failures) =
                    self.set_and_verify_liteinst_cpuid_state(task, 1).await;
                if enable_failures.is_empty() {
                    (task, Ok(LiteinstCpuidPolicy::RestoreDisabled))
                } else {
                    let (task, restore_failures) =
                        self.set_and_verify_liteinst_cpuid_state(task, 0).await;
                    let mut message = format!(
                        "enable native CPUID for patch helper: {}",
                        enable_failures.join("; ")
                    );
                    if !restore_failures.is_empty() {
                        message.push_str(&format!(
                            "; restore original CPUID policy after enable failure: {}",
                            restore_failures.join("; ")
                        ));
                    }
                    (task, Err(message))
                }
            }
            Ok(Ok(state)) => (
                task,
                Err(format!("ARCH_GET_CPUID returned unexpected value {state}")),
            ),
            Ok(Err(Errno::ENODEV)) => (task, Ok(LiteinstCpuidPolicy::Unsupported)),
            Ok(Err(error)) => (task, Err(format!("ARCH_GET_CPUID: {error}"))),
            Err(error) => (task, Err(format!("inject ARCH_GET_CPUID: {error}"))),
        }
    }

    #[cfg(target_arch = "x86_64")]
    async fn set_and_verify_liteinst_tsc_state(
        &mut self,
        task: Stopped,
        scratch_address: usize,
        state: libc::c_int,
    ) -> (Stopped, Vec<String>) {
        let (task, set_result) = self.liteinst_set_tsc_state(task, state).await;
        let mut failures = Vec::new();
        match set_result {
            Ok(Ok(0)) => {}
            Ok(Ok(result)) => {
                failures.push(format!(
                    "PR_SET_TSC({state}) returned unexpected value {result}"
                ));
            }
            Ok(Err(error)) => failures.push(format!("PR_SET_TSC({state}): {error}")),
            Err(error) => failures.push(format!("inject PR_SET_TSC({state}): {error}")),
        }
        let (task, verify_failures) = self
            .verify_liteinst_tsc_state(task, scratch_address, state)
            .await;
        failures.extend(verify_failures);
        (task, failures)
    }

    #[cfg(target_arch = "x86_64")]
    async fn verify_liteinst_tsc_state(
        &mut self,
        task: Stopped,
        scratch_address: usize,
        state: libc::c_int,
    ) -> (Stopped, Vec<String>) {
        let mut failures = Vec::new();
        let (task, get_result) = self.liteinst_get_tsc_state(task, scratch_address).await;
        match get_result {
            Ok(Ok(observed)) if observed == state => {}
            Ok(Ok(observed)) => failures.push(format!(
                "PR_GET_TSC returned {observed} after setting {state}"
            )),
            Ok(Err(error)) => failures.push(format!("verify PR_GET_TSC({state}): {error}")),
            Err(error) => failures.push(format!("verify PR_GET_TSC({state}): {error}")),
        }
        (task, failures)
    }

    #[cfg(target_arch = "x86_64")]
    async fn prepare_liteinst_helper_tsc(
        &mut self,
        task: Stopped,
        scratch_address: usize,
    ) -> (Stopped, Result<LiteinstTscPolicy, String>) {
        let (task, result) = self.liteinst_get_tsc_state(task, scratch_address).await;
        match result {
            Ok(Ok(libc::PR_TSC_ENABLE)) => (task, Ok(LiteinstTscPolicy::UnchangedEnabled)),
            Ok(Ok(libc::PR_TSC_SIGSEGV)) => {
                let (task, enable_failures) = self
                    .set_and_verify_liteinst_tsc_state(task, scratch_address, libc::PR_TSC_ENABLE)
                    .await;
                if enable_failures.is_empty() {
                    (task, Ok(LiteinstTscPolicy::RestoreFaulting))
                } else {
                    let (task, restore_failures) = self
                        .set_and_verify_liteinst_tsc_state(
                            task,
                            scratch_address,
                            libc::PR_TSC_SIGSEGV,
                        )
                        .await;
                    let mut message = format!(
                        "enable native TSC for patch helper: {}",
                        enable_failures.join("; ")
                    );
                    if !restore_failures.is_empty() {
                        message.push_str(&format!(
                            "; restore original TSC policy after enable failure: {}",
                            restore_failures.join("; ")
                        ));
                    }
                    (task, Err(message))
                }
            }
            Ok(Ok(state)) => (
                task,
                Err(format!("PR_GET_TSC returned unexpected state {state}")),
            ),
            // EINVAL is the documented prctl response when this option is not
            // supported by the running kernel/architecture.
            Ok(Err(Errno::EINVAL)) => (task, Ok(LiteinstTscPolicy::Unsupported)),
            Ok(Err(error)) => (task, Err(format!("PR_GET_TSC: {error}"))),
            Err(error) => (task, Err(error)),
        }
    }

    #[cfg(target_arch = "x86_64")]
    async fn restore_liteinst_helper_state(
        &mut self,
        task: Stopped,
        saved: &LiteinstHelperSavedState,
    ) -> (Stopped, Vec<String>) {
        let (task, mut failures) = match saved.tsc_policy {
            LiteinstTscPolicy::Unsupported => (task, Vec::new()),
            LiteinstTscPolicy::RestoreFaulting => {
                let (task, failures) = self
                    .set_and_verify_liteinst_tsc_state(
                        task,
                        saved.stack_address,
                        libc::PR_TSC_SIGSEGV,
                    )
                    .await;
                (
                    task,
                    failures
                        .into_iter()
                        .map(|failure| format!("TSC policy: {failure}"))
                        .collect(),
                )
            }
            LiteinstTscPolicy::UnchangedEnabled => {
                let (task, failures) = self
                    .verify_liteinst_tsc_state(task, saved.stack_address, libc::PR_TSC_ENABLE)
                    .await;
                (
                    task,
                    failures
                        .into_iter()
                        .map(|failure| format!("TSC policy: {failure}"))
                        .collect(),
                )
            }
        };
        let (mut task, cpuid_failures) = match saved.cpuid_policy {
            LiteinstCpuidPolicy::Unsupported => (task, Vec::new()),
            LiteinstCpuidPolicy::RestoreDisabled => {
                let (task, failures) = self.set_and_verify_liteinst_cpuid_state(task, 0).await;
                (
                    task,
                    failures
                        .into_iter()
                        .map(|failure| format!("CPUID policy: {failure}"))
                        .collect(),
                )
            }
            LiteinstCpuidPolicy::UnchangedEnabled => {
                let (task, failures) = self.verify_liteinst_cpuid_state(task, 1).await;
                (
                    task,
                    failures
                        .into_iter()
                        .map(|failure| format!("CPUID policy: {failure}"))
                        .collect(),
                )
            }
        };
        failures.extend(cpuid_failures);
        match AddrMut::from_raw(saved.stack_address) {
            Some(address) => {
                if let Err(error) = task.write_value(address, &saved.stack_value) {
                    failures.push(format!("helper stack: {error}"));
                }
            }
            None => failures.push("helper stack: invalid restore address".to_owned()),
        }
        if let Err(error) = task.setxstate(&saved.xstate) {
            failures.push(format!("XSTATE: {error}"));
        }
        if let Err(error) = task.setregs(&saved.regs) {
            failures.push(format!("general registers: {error}"));
        }
        (task, failures)
    }

    #[cfg(target_arch = "x86_64")]
    async fn rollback_liteinst_helper_error(
        &mut self,
        task: Stopped,
        saved: &LiteinstHelperSavedState,
        original: Error,
    ) -> Error {
        let (_, rollback_failures) = self.restore_liteinst_helper_state(task, saved).await;
        self.liteinst_helper_failure(original, rollback_failures)
    }

    fn liteinst_helper_failure(&self, original: Error, rollback_failures: Vec<String>) -> Error {
        if rollback_failures.is_empty() {
            original
        } else {
            Error::runtime(
                self.tid(),
                "restore LiteInst patch-helper state",
                format!(
                    "original failure: {original}; rollback failures: {}",
                    rollback_failures.join("; ")
                ),
            )
        }
    }

    fn record_liteinst_fallback_stats(
        &self,
        task: &Stopped,
        frame: LiteinstHandshakeFrame,
        site: u64,
    ) {
        let stats = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|config| config.instrumentation_stats.as_ref());
        crate::liteinst_stats::with_liteinst_stats(stats, |stats| {
            let shape = Addr::from_raw(frame.install_result as usize)
                .and_then(|address| {
                    let result: LiteinstInstallResult = task.read_value(address).ok()?;
                    Some(result)
                })
                .and_then(|result| {
                    let instruction_len = usize::try_from(result.instruction_len).ok()?;
                    let straddle_prefix = usize::try_from(result.straddle_prefix).ok()?;
                    (result.version == 2
                        && result.complete == 0
                        && result.site_start == site
                        && result.site_len == 8
                        && (1..=15).contains(&instruction_len)
                        && straddle_prefix < instruction_len.min(5))
                    .then_some((
                        instruction_len,
                        (straddle_prefix != 0).then_some(straddle_prefix),
                    ))
                });
            let outcome = if shape.as_ref().is_some_and(|(_, prefix)| prefix.is_some()) {
                LiteinstPatchOutcome::PtraceStraddlerBail
            } else {
                LiteinstPatchOutcome::PtraceOtherFallback
            };
            let process_identity =
                u64::try_from(self.pid.as_raw()).expect("tracee PID must be positive");
            let execution_generation = {
                let mut runtime = self.liteinst_runtime.lock().unwrap();
                runtime.fallback_sites.insert(site, outcome);
                runtime.generation
            };
            stats.record_process_site(process_identity, execution_generation, site, outcome, shape);
            match outcome {
                LiteinstPatchOutcome::PtraceStraddlerBail => {
                    stats.record_cacheline_straddler_fallback();
                }
                LiteinstPatchOutcome::PtraceOtherFallback => {
                    stats.record_unpatchable_or_other_fallback();
                }
                LiteinstPatchOutcome::DirectPunPatched | LiteinstPatchOutcome::RelocatedPatched => {
                    unreachable!("fallback accounting received a patched outcome")
                }
            }
        });
    }

    fn record_retained_liteinst_fallback_hit(&self, task: &Stopped) {
        let Some(stats) = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|config| config.instrumentation_stats.as_ref())
        else {
            return;
        };
        let Some(site) = task
            .getregs()
            .ok()
            .and_then(|regs| regs.ip().checked_sub(2))
        else {
            return;
        };
        let outcome = self
            .liteinst_runtime
            .lock()
            .unwrap()
            .fallback_sites
            .get(&site)
            .copied();
        crate::liteinst_stats::with_liteinst_stats(Some(stats), |stats| match outcome {
            Some(LiteinstPatchOutcome::PtraceStraddlerBail) => {
                stats.record_cacheline_straddler_fallback();
            }
            Some(LiteinstPatchOutcome::PtraceOtherFallback) => {
                stats.record_unpatchable_or_other_fallback();
            }
            Some(
                LiteinstPatchOutcome::DirectPunPatched | LiteinstPatchOutcome::RelocatedPatched,
            )
            | None => {}
        });
    }

    fn validate_liteinst_install_result(
        &self,
        task: &Stopped,
        frame: LiteinstHandshakeFrame,
        site: u64,
    ) -> Option<(u64, ActiveHookFootprint)> {
        let address = Addr::from_raw(frame.install_result as usize)?;
        let result: LiteinstInstallResult = task.read_value(address).ok()?;
        let instruction_len = usize::try_from(result.instruction_len).ok()?;
        let straddle_prefix = usize::try_from(result.straddle_prefix).ok()?;
        if result.version != 2
            || result.complete != 1
            || result.site_start != site
            || result.site_len != 8
            || !(1..=15).contains(&instruction_len)
            || straddle_prefix >= instruction_len.min(5)
        {
            return None;
        }
        let site = GuestRange::new(result.site_start, result.site_len)?;
        let trampoline = GuestRange::new(result.trampoline_start, result.trampoline_len)?;
        let arena_writable =
            GuestRange::new(result.arena_writable_start, result.arena_writable_len)?;
        let arena_executable =
            GuestRange::new(result.arena_executable_start, result.arena_executable_len)?;
        if !arena_executable.contains(trampoline)
            || !trampoline.contains(GuestRange::new(result.relocated_tail, 1)?)
        {
            return None;
        }
        let maps = guest_maps(task.pid())?;
        let site_map = maps.iter().find(|mapping| {
            mapping.readable
                && !mapping.writable
                && mapping.executable
                && mapping.contains_range(site)
        })?;
        let writable_map = maps.iter().find(|mapping| {
            mapping.start == arena_writable.start
                && mapping.end == arena_writable.end
                && mapping.offset == 0
                && mapping.inode != 0
                && mapping.shared
                && mapping.readable
                && mapping.writable
                && !mapping.executable
        })?;
        let executable_map = maps.iter().find(|mapping| {
            mapping.start == arena_executable.start
                && mapping.end == arena_executable.end
                && mapping.offset == 0
                && mapping.inode != 0
                && mapping.shared
                && mapping.readable
                && !mapping.writable
                && mapping.executable
        })?;
        if writable_map.device_major != executable_map.device_major
            || writable_map.device_minor != executable_map.device_minor
            || writable_map.inode != executable_map.inode
            || writable_map.end - writable_map.start != executable_map.end - executable_map.start
            || site_map.start == writable_map.start
            || site_map.start == executable_map.start
        {
            return None;
        }
        if let Some(stats) = self
            .global_state
            .liteinst_runtime
            .as_ref()?
            .instrumentation_stats
            .as_ref()
        {
            let mut stats = stats.lock().unwrap();
            let process_identity =
                u64::try_from(self.pid.as_raw()).expect("tracee PID must be positive");
            let execution_generation = self.liteinst_runtime.lock().unwrap().generation;
            stats.record_process_site(
                process_identity,
                execution_generation,
                result.site_start,
                LiteinstPatchOutcome::RelocatedPatched,
                Some((
                    instruction_len,
                    (straddle_prefix != 0).then_some(straddle_prefix),
                )),
            );
            stats.record_ptrace_installation();
        }
        Some((
            result.relocated_tail,
            ActiveHookFootprint {
                site,
                trampoline,
                arena_writable,
                arena_executable,
            },
        ))
    }

    /// Runs the runtime's installation helper for `site`. `entry_limit` is the
    /// lowest entry that the tracer's census found in the 64 bytes after the
    /// site, `u64::MAX` if there is none, or [`REFUSED_ENTRY_LIMIT`] if the
    /// census refused the site.
    #[cfg(target_arch = "x86_64")]
    async fn call_liteinst_install_helper(
        &mut self,
        task: Stopped,
        frame: LiteinstHandshakeFrame,
        site: u64,
        entry_limit: u64,
    ) -> Result<(Stopped, Option<(u64, ActiveHookFootprint)>), Error> {
        let helper_return_marker = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .ok_or(Errno::EIO)?
            .helper_return_marker;
        let saved_regs = task.getregs()?;
        let saved_xstate = task.getxstate()?;
        let stack_address = frame.helper_stack_top.saturating_sub(8) as usize;
        let stack_read_address = Addr::from_raw(stack_address).ok_or(Errno::EFAULT)?;
        let stack_write_address = AddrMut::from_raw(stack_address).ok_or(Errno::EFAULT)?;
        let saved_stack: u64 = task.read_value(stack_read_address)?;
        let mut saved = LiteinstHelperSavedState {
            cpuid_policy: LiteinstCpuidPolicy::Unsupported,
            tsc_policy: LiteinstTscPolicy::Unsupported,
            regs: saved_regs,
            xstate: saved_xstate,
            stack_address,
            stack_value: saved_stack,
        };
        let (task, cpuid_policy) = self.prepare_liteinst_helper_cpuid(task).await;
        saved.cpuid_policy = match cpuid_policy {
            Ok(policy) => policy,
            Err(message) => {
                let original = Error::runtime(
                    self.tid(),
                    "prepare LiteInst patch-helper CPUID policy",
                    message,
                );
                let (_, rollback_failures) = self.restore_liteinst_helper_state(task, &saved).await;
                return Err(self.liteinst_helper_failure(original, rollback_failures));
            }
        };
        let (task, tsc_policy) = self.prepare_liteinst_helper_tsc(task, stack_address).await;
        saved.tsc_policy = match tsc_policy {
            Ok(policy) => policy,
            Err(message) => {
                let original = Error::runtime(
                    self.tid(),
                    "prepare LiteInst patch-helper TSC policy",
                    message,
                );
                let (_, rollback_failures) = self.restore_liteinst_helper_state(task, &saved).await;
                return Err(self.liteinst_helper_failure(original, rollback_failures));
            }
        };
        let mut task = task;
        if let Err(error) = task.write_value(stack_write_address, &frame.helper_return) {
            let original = Error::from(error);
            return Err(self
                .rollback_liteinst_helper_error(task, &saved, original)
                .await);
        }

        let mut helper_regs = saved.regs;
        *helper_regs.ip_mut() = frame.install_helper;
        *helper_regs.stack_ptr_mut() = frame.helper_stack_top - 8;
        helper_regs.rdi = site;
        helper_regs.rsi = entry_limit;
        *helper_regs.orig_syscall_mut() = -1_i64 as u64;
        helper_regs.eflags = liteinst_helper_entry_rflags(saved.regs.eflags);
        if let Err(error) = task.setregs(&helper_regs) {
            let original = Error::Internal(error);
            return Err(self
                .rollback_liteinst_helper_error(task, &saved, original)
                .await);
        }

        let running = match self.resume_stopped(task, None) {
            Ok(running) => running,
            Err(error) => {
                return Err(self
                    .rollback_liteinst_helper_error(
                        self.assume_stopped(),
                        &saved,
                        Error::Internal(error),
                    )
                    .await);
            }
        };
        let mut wait = match running.next_state_with_owner(&self.ptracer_waits).await {
            Ok(wait) => wait,
            Err(error) => {
                return Err(self
                    .rollback_liteinst_helper_error(
                        self.assume_stopped(),
                        &saved,
                        Error::Internal(error),
                    )
                    .await);
            }
        };
        self.arm_liteinst_wait(&wait);
        loop {
            match wait {
                Wait::Stopped(stopped, Event::Seccomp) => {
                    // Controller-owned helper syscalls execute natively and are
                    // never delivered to the user Tool.
                    let running = match self.resume_stopped(stopped, None) {
                        Ok(running) => running,
                        Err(error) => {
                            return Err(self
                                .rollback_liteinst_helper_error(
                                    self.assume_stopped(),
                                    &saved,
                                    Error::Internal(error),
                                )
                                .await);
                        }
                    };
                    wait = match running.next_state_with_owner(&self.ptracer_waits).await {
                        Ok(wait) => wait,
                        Err(error) => {
                            return Err(self
                                .rollback_liteinst_helper_error(
                                    self.assume_stopped(),
                                    &saved,
                                    Error::Internal(error),
                                )
                                .await);
                        }
                    };
                    self.arm_liteinst_wait(&wait);
                }
                Wait::Stopped(stopped, Event::Signal(Signal::SIGTRAP)) => {
                    let regs = match stopped.getregs() {
                        Ok(regs) => regs,
                        Err(error) => {
                            let original = Error::Internal(error);
                            return Err(self
                                .rollback_liteinst_helper_error(stopped, &saved, original)
                                .await);
                        }
                    };
                    if regs.r10 != helper_return_marker || regs.ip() != frame.helper_return_rip {
                        let original = Error::runtime(
                            self.tid(),
                            "validate LiteInst patch-helper return",
                            "unexpected helper return marker or instruction pointer",
                        );
                        return Err(self
                            .rollback_liteinst_helper_error(stopped, &saved, original)
                            .await);
                    }
                    let result = regs.rax as i64;
                    let install = if u64::try_from(result).is_ok() {
                        match self.validate_liteinst_install_result(&stopped, frame, site) {
                            Some(install) => Some(install),
                            None => {
                                let original = Error::runtime(
                                    self.tid(),
                                    "validate LiteInst patch-helper result",
                                    "successful helper returned invalid active-hook metadata",
                                );
                                return Err(self
                                    .rollback_liteinst_helper_error(stopped, &saved, original)
                                    .await);
                            }
                        }
                    } else {
                        self.record_liteinst_fallback_stats(&stopped, frame, site);
                        None
                    };
                    let (stopped, rollback) =
                        self.restore_liteinst_helper_state(stopped, &saved).await;
                    if rollback.is_empty() {
                        return Ok((stopped, install));
                    }
                    let original = Error::runtime(
                        self.tid(),
                        "restore LiteInst patch-helper state",
                        "patch helper completed successfully",
                    );
                    return Err(self.liteinst_helper_failure(original, rollback));
                }
                Wait::Stopped(stopped, Event::Signal(sig)) if sig == Timer::signal_type() => {
                    // The counter counts the helper's branches, so the timer's
                    // own overflow notification can be raised while the helper
                    // runs. (One already pending at the seccomp stop that led
                    // here is taken by untraced_syscall when the helper's CPUID
                    // policy is read, before the helper starts, when overflow
                    // records exist.) That stop ticked the timer event, and
                    // nothing has requested one since, so the event is Armed or
                    // Cancelled and its signal's own stop would drop it. It
                    // never reaches the guest; resume the helper without it.
                    // Any other signal, one not backed by an unconsumed
                    // overflow record, a notification of an event that no
                    // stop has decided (which `consume_overflow_signal` does
                    // not match; unreachable here, since the seccomp stop was
                    // not disregarded), and a failure to tell still roll the
                    // helper back. Without overflow records (the kernel is or
                    // may be PREEMPT_RT, or the records could not be mapped)
                    // no signal is backed by one, so an overflow raised in
                    // the helper still fails the run, as it did before this
                    // arm.
                    match self.consume_own_timer_overflow(&stopped) {
                        Ok(true) => {}
                        Ok(false) => {
                            let original = Error::runtime(
                                self.tid(),
                                "run LiteInst patch helper",
                                format!("unexpected stopped event: {:?}", Event::Signal(sig)),
                            );
                            return Err(self
                                .rollback_liteinst_helper_error(stopped, &saved, original)
                                .await);
                        }
                        Err(error) => {
                            return Err(self
                                .rollback_liteinst_helper_error(
                                    stopped,
                                    &saved,
                                    Error::Internal(error),
                                )
                                .await);
                        }
                    }
                    tracing::debug!(
                        "[{}] discarding a timer overflow signal in the LiteInst patch helper",
                        stopped.pid()
                    );
                    LITEINST_HELPER_TIMER_SIGNALS_DISCARDED.fetch_add(1, Ordering::Relaxed);
                    let running = match self.resume_stopped(stopped, None) {
                        Ok(running) => running,
                        Err(error) => {
                            return Err(self
                                .rollback_liteinst_helper_error(
                                    self.assume_stopped(),
                                    &saved,
                                    Error::Internal(error),
                                )
                                .await);
                        }
                    };
                    wait = match running.next_state_with_owner(&self.ptracer_waits).await {
                        Ok(wait) => wait,
                        Err(error) => {
                            return Err(self
                                .rollback_liteinst_helper_error(
                                    self.assume_stopped(),
                                    &saved,
                                    Error::Internal(error),
                                )
                                .await);
                        }
                    };
                    self.arm_liteinst_wait(&wait);
                }
                Wait::Stopped(stopped, event) => {
                    let original = Error::runtime(
                        self.tid(),
                        "run LiteInst patch helper",
                        format!("unexpected stopped event: {event:?}"),
                    );
                    return Err(self
                        .rollback_liteinst_helper_error(stopped, &saved, original)
                        .await);
                }
                Wait::Exited(_, exit_status) => self.exit(exit_status).await,
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    async fn call_liteinst_install_helper(
        &mut self,
        _task: Stopped,
        _frame: LiteinstHandshakeFrame,
        _site: u64,
        _entry_limit: u64,
    ) -> Result<(Stopped, Option<(u64, ActiveHookFootprint)>), Error> {
        Err(Error::runtime(
            self.tid(),
            "run LiteInst patch helper",
            "the dynamic LiteInst hybrid requires x86-64 XSTATE support",
        ))
    }

    async fn maybe_install_liteinst_site(
        &mut self,
        task: Stopped,
        nr: Sysno,
    ) -> Result<(Stopped, bool, Option<u64>), Error> {
        if self.global_state.liteinst_runtime.is_none() {
            return Ok((task, false, None));
        }
        // A task-creating syscall must not be patched. Patching overwrites the
        // instruction bytes AT the site, and the new task is resumed with the
        // register context captured before the injection -- i.e. with `rip`
        // pointing just past the original two-byte `syscall`. Once the site
        // holds a longer relocating jump, that address is no longer an
        // instruction boundary and the child executes rubbish. Leaving these
        // sites unpatched costs nothing: they are entered once per task.
        if is_task_creating_syscall(nr) {
            return Ok((task, false, None));
        }
        if self
            .global_state
            .liteinst_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.multi_task.load(Ordering::Acquire))
        {
            return Ok((task, false, None));
        }
        let regs = task.getregs()?;
        let Some(site) = regs.ip().checked_sub(2) else {
            return Ok((task, false, None));
        };
        let site_address = Addr::from_raw(site as usize).ok_or(Errno::EFAULT)?;
        let instruction: u16 = task.read_value(site_address)?;
        if instruction != 0x050f {
            return Ok((task, false, None));
        }
        let frame = {
            let mut state = self.liteinst_runtime.lock().unwrap();
            if state.phase != LiteinstRuntimePhase::Ready
                || state.ready_generation != Some(state.generation)
                || !state.attempted_sites.insert(site)
            {
                return Ok((task, false, None));
            }
            state.frame.ok_or(Errno::EIO)?
        };

        if let Some(stats) = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|config| config.instrumentation_stats.as_ref())
        {
            stats.lock().unwrap().record_first_site_seccomp();
        }

        // A refused site still goes to the helper, which records the site's
        // trap and leaves it on ptrace, as for any other failed installation.
        let entry_limit = match census_outcome(site, self.liteinst_site_entries(&task, site)) {
            CensusOutcome::Install(limit) => limit,
            CensusOutcome::Fail(errno) => {
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::ReadCensusObject,
                    Error::runtime(
                        self.tid(),
                        "read the tracee's code for the LiteInst entry census",
                        format!("site {site:#x}: {errno}"),
                    ),
                );
                return Err(errno.into());
            }
            CensusOutcome::Gone => return Err(Errno::ESRCH.into()),
        };

        // Convert the active seccomp stop into an ordinary stopped state before
        // calling arbitrary tracee code. The original event is still serviced
        // exactly once by the host Tool below.
        let task = self.skip_seccomp_syscall(task).await?;
        let (task, install) = self
            .call_liteinst_install_helper(task, frame, site, entry_limit)
            .await?;
        let relocated_tail = install.as_ref().map(|(address, _)| *address);
        if let Some((_, footprint)) = install {
            self.liteinst_runtime
                .lock()
                .unwrap()
                .active_hooks
                .insert(site, footprint);
        }
        Ok((task, true, relocated_tail))
    }

    /// Returns the census entries of `site`, building its object's census from
    /// the tracee's memory at the first site attempt in that object
    /// (<https://github.com/rrnewton/reverie/issues/812>). The outer error is
    /// a failure to open or read the tracee's memory; see [`read_census`].
    ///
    /// The census runs here rather than in the guest because it decodes every
    /// function of the object: about 12.9 million conditional branches for
    /// glibc 2.34's `libc.so.6`, which a guest's own instruction count would
    /// include.
    fn liteinst_site_entries(
        &self,
        task: &Stopped,
        site: u64,
    ) -> Result<Result<SiteEntries, Refusal>, Errno> {
        // No other guest task can change the object while the census reads it
        // only because installation stops once the guest has a second task.
        debug_assert!(
            !self
                .global_state
                .liteinst_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.multi_task.load(Ordering::Acquire)),
            "the LiteInst entry census ran after the guest created a second task"
        );
        let maps = Arc::clone(&self.liteinst_runtime.lock().unwrap().census_maps);
        let object = match census_object(&maps, site) {
            Ok(object) => object,
            Err(error) => return Ok(Err(Refusal::NoCensus(error))),
        };
        let cached = self
            .liteinst_runtime
            .lock()
            .unwrap()
            .censuses
            .get(&object.text.0)
            .cloned();
        let census = match cached {
            Some(census) => census,
            None => {
                let census = {
                    // The guard ends before the runtime lock is taken.
                    let _open = crate::launch_window::TransientOpen::begin();
                    let memory = std::fs::File::open(format!("/proc/{}/mem", task.pid()))
                        .map(TraceeMemory)
                        .map_err(|error| Errno::new(error.raw_os_error().unwrap_or(libc::EIO)))?;
                    Arc::new(read_census(&memory, &object)?)
                };
                let mut state = self.liteinst_runtime.lock().unwrap();
                if !Arc::ptr_eq(&state.census_maps, &maps) {
                    return Ok(Err(Refusal::NoCensus(CHANGED_CENSUS_OBJECT)));
                }
                Arc::clone(state.censuses.entry(object.text.0).or_insert(census))
            }
        };
        Ok(census_site_entries(&census, site))
    }

    fn validate_liteinst_mapping_execution(
        &self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<(), Errno> {
        let page_size = host_page_size()?;
        if self
            .liteinst_runtime
            .lock()
            .unwrap()
            .mapping_mutates_active_hook(nr, args, page_size)
        {
            Err(Errno::ENOTSUPP)
        } else {
            Ok(())
        }
    }

    fn observe_liteinst_mapping_result(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
        result: Result<i64, Errno>,
    ) {
        if self.global_state.liteinst_runtime.is_none() {
            return;
        }
        let Ok(result) = result else {
            return;
        };
        let mut state = self.liteinst_runtime.lock().unwrap();
        let Ok(page_size) = host_page_size() else {
            state.attempted_sites.clear();
            state.fallback_sites.clear();
            state.forget_all_census_objects();
            return;
        };
        // A protection change leaves an object's bytes where they are, the
        // census reads them whatever their protection (`read_census`), and
        // the installation helper makes one for every patch, so only the
        // calls that map, unmap or move pages remove census objects.
        match nr {
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::mmap => {
                if let Ok(start) = u64::try_from(result) {
                    state.invalidate_attempted_pages(start, args.arg1 as u64, page_size);
                    state.forget_census_objects(start, args.arg1 as u64, page_size);
                }
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::munmap => {
                state.invalidate_attempted_pages(args.arg0 as u64, args.arg1 as u64, page_size);
                state.forget_census_objects(args.arg0 as u64, args.arg1 as u64, page_size);
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::mprotect | Sysno::pkey_mprotect => {
                state.invalidate_attempted_pages(args.arg0 as u64, args.arg1 as u64, page_size);
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::mremap => {
                state.invalidate_attempted_pages(args.arg0 as u64, args.arg1 as u64, page_size);
                state.forget_census_objects(args.arg0 as u64, args.arg1 as u64, page_size);
                if let Ok(start) = u64::try_from(result) {
                    state.invalidate_attempted_pages(start, args.arg2 as u64, page_size);
                    state.forget_census_objects(start, args.arg2 as u64, page_size);
                }
            }
            _ => {}
        }
    }

    async fn handle_liteinst_mapping_syscall(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Wait, Error> {
        let tid = self.tid();
        if self.validate_liteinst_mapping_execution(nr, args).is_err() {
            return Err(Error::runtime(
                tid,
                "validate LiteInst mapping mutation",
                format!("{nr} overlaps an active LiteInst hook footprint"),
            ));
        }
        let wait = self
            .syscall_stopped(task, None)
            .tracee_context(tid, "resume controller-observed mapping syscall")?
            .next_state_with_owner(&self.ptracer_waits)
            .await
            .tracee_context(tid, "wait for controller-observed mapping syscall")?;
        self.arm_liteinst_wait(&wait);
        match wait {
            Wait::Stopped(stopped, Event::Syscall) => {
                let regs = stopped
                    .getregs()
                    .tracee_context(tid, "read controller-observed mapping result")?;
                let result = Errno::from_ret(regs.ret() as usize).map(|value| value as i64);
                self.observe_liteinst_mapping_result(nr, args, result);
                self.resume_stopped(stopped, None)
                    .tracee_context(tid, "resume after controller-observed mapping syscall")?
                    .next_state_with_owner(&self.ptracer_waits)
                    .await
                    .tracee_context(tid, "wait after controller-observed mapping syscall")
            }
            Wait::Stopped(_, event) => Err(Error::runtime(
                tid,
                "observe LiteInst mapping syscall",
                format!("unexpected stopped event: {event:?}"),
            )),
            Wait::Exited(_, exit_status) => self.exit(exit_status).await,
        }
    }

    async fn handle_seccomp(&mut self, mut task: Stopped) -> Result<Wait, Error> {
        let tid = self.tid();
        // Trap-only routing (H0) runs before anything reads the syscall: a
        // patched site's stop carries an ia32 entry that must first be
        // normalized, and must never reach the mapping shortcut below.
        let mut trap_only_patch_site = None;
        let mut trap_only_patched = false;
        if self.trap_only.is_some() {
            match self.trap_only_route(task).await {
                Ok(TrapOnlyRoute::Ordinary {
                    task: ordinary,
                    patch_site,
                }) => {
                    task = ordinary;
                    trap_only_patch_site = Some(patch_site);
                }
                Ok(TrapOnlyRoute::Patched(patched)) => {
                    task = patched;
                    trap_only_patched = true;
                }
                Ok(TrapOnlyRoute::Done(wait)) => return Ok(wait),
                Err(error) => return Err(self.trap_only_error(tid, error, "trap-only routing")),
            }
        }
        let syscall = self
            .get_syscall(&task)
            .tracee_context(tid, "read registers at seccomp stop")?;
        let (nr, args) = syscall.into_parts();
        // Trap-only site-table lifecycle: before the syscall runs and before
        // any Tool code, for x86_64 and patched-site stops alike.
        if self.trap_only.is_some()
            && let Err(error) = self.trap_only_lifecycle(nr, &args)
        {
            return Err(self.trap_only_error(tid, error, "trap-only site-table lifecycle"));
        }
        let tool_subscribed = self
            .global_state
            .subscriptions
            .iter_syscalls()
            .any(|subscribed| subscribed == nr);
        if !trap_only_patched && is_liteinst_mapping_syscall(nr) && !tool_subscribed {
            if let Some(stats) = &self.global_state.backend_stats {
                stats.record_internal_seccomp_stop();
            }
            return self.handle_liteinst_mapping_syscall(task, nr, args).await;
        }
        let (syscall_already_skipped, liteinst_resume_rip) = if self.trap_only.is_some() {
            (false, None)
        } else {
            self.record_retained_liteinst_fallback_hit(&task);
            let (installed_task, syscall_already_skipped, liteinst_resume_rip) =
                self.maybe_install_liteinst_site(task, nr).await?;
            task = installed_task;
            (syscall_already_skipped, liteinst_resume_rip)
        };
        #[cfg(target_arch = "x86_64")]
        let is_legacy_vsyscall = !syscall_already_skipped
            && is_legacy_vsyscall_ip(
                task.getregs()
                    .tracee_context(tid, "identify legacy vsyscall stop")?
                    .ip(),
            );
        #[cfg(not(target_arch = "x86_64"))]
        let is_legacy_vsyscall = false;
        let span = tracing::trace_span!(
            target: "reverie_ptrace::syscall",
            "syscall.intercept",
            tid = %tid,
            syscall = %nr,
            args = ?SyscallArgsForLog {
                nr,
                args,
                command_bootstrap: self.command_bootstrap,
            },
        );

        async {
            tracing::trace!(
                target: "reverie_ptrace::syscall",
                "intercepting guest syscall"
            );
            self.pending_syscall = Some((nr, args));
            self.pending_syscall_already_skipped = syscall_already_skipped;

            let retval = cancellable(self.cancel_handler.clone(), async {
                self.process_state
                    .clone()
                    .handle_syscall_event(self, syscall)
                    .await
            })
            .await;

            let retval = if self.ordinary_failure_enabled() {
                match retval {
                    Some(Err(error)) if !matches!(error, reverie::Error::Errno(_)) => {
                        self.publish_ordinary_failure("ptrace syscall callback", error);
                        return Err(Error::RunFailed);
                    }
                    result => result,
                }
            } else {
                retval
            };
            self.ordinary_continuation()?;

            // A returned emulation must consume its original stop just like an
            // injection. Keeping Some after skipping would let a later signal
            // or timer callback mistake an ordinary stop for a seccomp entry.
            let pending_syscall = self.pending_syscall.take();
            let emulate_legacy_vsyscall = is_legacy_vsyscall && pending_syscall.is_some();
            // The kernel owns the synthetic `ret` from the fixed vsyscall
            // page. That path stays at its seccomp stop and is marked skipped
            // below, so the kernel returns without stepping the caller.
            if pending_syscall.is_some() && !syscall_already_skipped && !emulate_legacy_vsyscall {
                task = self
                    .skip_seccomp_syscall(task)
                    .await
                    .tracee_context(tid, "skip intercepted syscall")?;
            }

            self.ordinary_trace_continuation()?;
            self.timer.finalize_requests();

            if let Some(retval) = retval {
                let ret = match retval {
                    Ok(x) => x as u64,
                    Err(err) => (-(err.into_errno()?.into_raw() as i64)) as u64,
                };

                #[cfg(target_arch = "x86_64")]
                if emulate_legacy_vsyscall {
                    let mut regs = task
                        .getregs()
                        .tracee_context(tid, "read legacy-vsyscall registers")?;
                    *regs.orig_syscall_mut() = -1i64 as u64;
                    *regs.ret_mut() = ret;
                    task.setregs(&regs)
                        .tracee_context(tid, "set legacy-vsyscall result")?;
                } else {
                    set_ret(&task, ret).tracee_context(tid, "set intercepted syscall result")?;
                }

                #[cfg(not(target_arch = "x86_64"))]
                set_ret(&task, ret).tracee_context(tid, "set intercepted syscall result")?;
            }

            self.pending_syscall_already_skipped = false;

            if let Some(resume_rip) = liteinst_resume_rip {
                let mut regs = task
                    .getregs()
                    .tracee_context(tid, "read registers before LiteInst tail resume")?;
                *regs.ip_mut() = resume_rip;
                task.setregs(&regs)
                    .tracee_context(tid, "resume after displaced LiteInst window")?;
            }

            #[cfg(test)]
            if self.liteinst_runtime.lock().unwrap().phase == LiteinstRuntimePhase::Waiting
                && let Some(queue_once) = self
                    .global_state
                    .liteinst_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.queue_pending_signal_once.as_ref())
                && queue_once.swap(false, Ordering::SeqCst)
            {
                self.pending_signal = Some(Signal::SIGUSR1);
                self.pending_signal_taken = None;
            }
            if let Some(site) = trap_only_patch_site
                && let Err(error) = self.trap_only_maybe_patch(site, nr)
            {
                return Err(self.trap_only_error(tid, error, "trap-only site patch"));
            }
            #[cfg(test)]
            if let Some(hook) = self.global_state.final_resume_signal_for_test.clone() {
                let regs = task
                    .getregs()
                    .tracee_context(tid, "read registers for a test resume signal")?;
                if let Some(sig) = hook(self.tid, &regs) {
                    self.pending_signal = Some(sig);
                    self.pending_signal_taken = None;
                }
            }
            let held = self.take_pending_signal_for_resume(
                LiteinstActivationOperation::ResumeAfterSeccompStop,
            )?;
            if let Some(view) = self.trap_only_take_live_entry() {
                // The patched site's syscall is still live: run it through the
                // masked hop instead of resuming the ia32 stop. `sig` is
                // dropped, as the kernel drops a signal passed on resume from
                // ptrace's seccomp event stop.
                let _ = held;
                return self
                    .trap_only_tail_hop(task, view)
                    .await
                    .map_err(|error| self.trap_only_error(tid, error, "trap-only tail hop"));
            }
            #[cfg(test)]
            if self.global_state.pre_syscall_for_test.is_some() {
                let regs = task
                    .getregs()
                    .tracee_context(tid, "read registers for the pre-syscall test hook")?;
                self.pre_syscall_for_test(&regs, PreSyscallPoint::Early)
                    .await;
                self.pre_syscall_for_test(&regs, PreSyscallPoint::Late)
                    .await;
            }
            let resume = self.report_held_signal(&task, None, held).await?;
            let wait = self
                .resume_with_signal(task, resume)
                .await
                .tracee_context(tid, "resume after seccomp stop")?;
            tracing::trace!(
                target: "reverie_ptrace::syscall",
                "completed guest syscall interception"
            );
            Ok(wait)
        }
        .instrument(span)
        .await
    }

    /// The LiteInst config, but only when this task is the session root.
    ///
    /// The root-stop lease and the fail-closed cleanup guard are owned by the
    /// single spawned root TID. `tid == pid` is NOT that predicate: a forked
    /// child is its own thread-group leader and would otherwise take the
    /// root's shared lease, whose `root_tid` check then rejects every
    /// transition with `EINVAL`.
    fn liteinst_root_runtime(&self, task: &Stopped) -> Option<&LiteinstRuntimeConfig> {
        let runtime = self.liteinst_root_config()?;
        (Some(&task.pid()) == runtime.root_tid.get()).then_some(runtime)
    }

    /// The LiteInst config, but only when *this task* is the session root.
    fn liteinst_root_config(&self) -> Option<&LiteinstRuntimeConfig> {
        let runtime = self.global_state.liteinst_runtime.as_ref()?;
        (Some(&self.tid()) == runtime.root_tid.get()).then_some(runtime)
    }

    fn liteinst_root_stop_slot(
        &self,
        task: &Stopped,
    ) -> Option<Arc<StdMutex<Option<HeldRootStop>>>> {
        if self.ordinary_failure_enabled() {
            Some(self.ordinary_held_stop.clone())
        } else {
            self.liteinst_root_runtime(task)
                .map(|runtime| Arc::clone(&runtime.held_root_stop))
        }
    }

    fn liteinst_root_stop_armer(&self, task: &Stopped) -> Option<LiteinstRootStopArmer> {
        let slot = self.liteinst_root_stop_slot(task)?;
        Some(LiteinstRootStopArmer {
            root_tid: task.pid(),
            held_root_stop: slot,
        })
    }

    pub(crate) fn arm_liteinst_root_stop(&self, task: &Stopped, event: &Event) {
        let Some(armer) = self.liteinst_root_stop_armer(task) else {
            return;
        };
        armer
            .arm(task, event)
            .expect("rearmed an undisarmed or mismatched root stop lease");
    }

    /// Gives the cleanup guard ownership of a newborn tracee's wait statuses.
    ///
    /// This is deliberately NOT root-scoped, unlike the root-stop lease: the
    /// guard has to be able to reap the whole descendant tree, and
    /// `handle_new_task` requires the entry to exist for every child it sees.
    /// A grandchild is reported to its own non-root parent, so scoping this to
    /// the root leaves it unregistered.
    fn register_liteinst_newborn(&self, task: &Stopped, event: &Event) {
        self.global_state
            .newborn_owner()
            .register(task.pid(), event);
    }

    fn arm_liteinst_wait(&self, wait: &Wait) {
        if let Wait::Stopped(task, event) = wait {
            self.register_liteinst_newborn(task, event);
            self.arm_liteinst_root_stop(task, event);
        }
    }

    fn ensure_liteinst_wait(&self, wait: &Wait) {
        if let Wait::Stopped(task, event) = wait {
            self.register_liteinst_newborn(task, event);
            let Some(armer) = self.liteinst_root_stop_armer(task) else {
                return;
            };
            armer
                .ensure(task, event)
                .expect("run-loop stop mismatched its armed root lease");
        }
    }

    fn lease_liteinst_root_stop(&self, task: Stopped) -> RootStopLease {
        let slot = self.liteinst_root_stop_slot(&task);
        RootStopLease::new(task, slot)
    }

    fn resume_stopped<T: Into<Option<Signal>>>(
        &self,
        task: Stopped,
        signal: T,
    ) -> Result<Running, TraceError> {
        if self.global_state.fatal_session.is_failed() {
            return Err(Errno::ECANCELED.into());
        }
        self.lease_liteinst_root_stop(task).resume(signal)
    }

    fn step_stopped<T: Into<Option<Signal>>>(
        &self,
        task: Stopped,
        signal: T,
    ) -> Result<Running, TraceError> {
        if self.global_state.fatal_session.is_failed() {
            return Err(Errno::ECANCELED.into());
        }
        trap_only::assert_not_in_hop(self.trap_only.as_ref());
        #[cfg(test)]
        trap_only::record_step_for_test(task.pid());
        self.lease_liteinst_root_stop(task).step(signal)
    }

    fn syscall_stopped<T: Into<Option<Signal>>>(
        &self,
        task: Stopped,
        signal: T,
    ) -> Result<Running, TraceError> {
        if self.global_state.fatal_session.is_failed() {
            return Err(Errno::ECANCELED.into());
        }
        self.lease_liteinst_root_stop(task).syscall(signal)
    }

    async fn dispatch_new_task(
        &mut self,
        op: ChildOp,
        parent: Stopped,
        child: Running,
        context: Option<libc::user_regs_struct>,
        child_context: Option<libc::user_regs_struct>,
    ) -> Result<Wait, TraceError> {
        #[cfg(test)]
        if let Some(sender) = self
            .global_state
            .liteinst_runtime
            .as_ref()
            .and_then(|runtime| runtime.pause_before_new_task.as_ref())
        {
            let _ = sender.send(child.pid());
            future::pending::<()>().await;
        }
        #[cfg(test)]
        let (parent_pid, child_pid) = (self.pid(), child.pid());
        let result = self
            .handle_new_task(op, parent, child, context, child_context)
            .await;
        #[cfg(test)]
        if let Some(runtime) = self.global_state.liteinst_runtime.as_ref() {
            runtime.report_newborn_displacement_for_test(parent_pid, child_pid, &result);
        }
        result
    }

    async fn handle_new_task(
        &mut self,
        op: ChildOp,
        parent: Stopped,
        child: Running,
        context: Option<libc::user_regs_struct>,
        child_context: Option<libc::user_regs_struct>,
    ) -> Result<Wait, TraceError> {
        if let Some(runtime) = self.global_state.liteinst_runtime.clone() {
            runtime.multi_task.store(true, Ordering::Release);
            let newborn_tracees = Arc::clone(&runtime.newborn_tracees);
            let child_pid = child.pid();
            let generation = child.terminal_cleanup();
            #[cfg(test)]
            let generation = runtime.displace_newborn_generation_for_test(
                NewbornDisplacementStage::RegistrationLookup,
                child_pid,
                parent.pid(),
                op,
                generation,
            );
            let registration_error = {
                let newborns = newborn_tracees.lock().unwrap();
                let Some(newborn) = newborns.get(&child_pid) else {
                    drop(newborns);
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::NewbornRegistration,
                        Error::runtime(
                            self.tid(),
                            "register LiteInst newborn tracee",
                            format!("newborn {child_pid} event ownership is absent"),
                        ),
                    );
                    return Err(Errno::ESRCH.into());
                };
                if !newborn.same_generation(&generation) {
                    drop(newborns);
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::NewbornRegistration,
                        Error::runtime(
                            self.tid(),
                            "register LiteInst newborn tracee",
                            format!("newborn {child_pid} event ownership names another generation"),
                        ),
                    );
                    return Err(Errno::ESRCH.into());
                }
                newborn.registration_error()
            };
            if let Some(error) = registration_error {
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::NewbornRegistration,
                    Error::runtime(
                        self.tid(),
                        "register LiteInst newborn tracee",
                        format!("newborn {child_pid} registration failed: {error}"),
                    ),
                );
                return Err(error.into());
            }
            let child_identity =
                match TraceeIdentity::capture_event_child(child_pid, parent.pid(), op) {
                    Ok(identity) => identity,
                    Err(error) => {
                        self.record_liteinst_failure(
                            LiteinstActivationFailureReason::NewbornIdentity,
                            Error::runtime(
                                self.tid(),
                                "capture LiteInst newborn identity",
                                format!("newborn {child_pid} identity capture failed: {error}"),
                            ),
                        );
                        return Err(error.into());
                    }
                };
            if op == ChildOp::Vfork {
                // A vfork child borrows the parent's memory and suspends it
                // until the child execs or exits. Bind and terminate this exact
                // child generation before returning the refusal; otherwise the
                // parent remains kernel-frozen and orderly task cleanup cannot
                // reach the session-level guard.
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::VforkUnsupported,
                    Error::runtime(
                        self.tid(),
                        "refuse vfork under the LiteInst hybrid",
                        format!(
                            "vfork child of {} refused: exec cannot preserve the preload runtime",
                            parent.pid()
                        ),
                    ),
                );
            }
            #[cfg(test)]
            let generation = runtime.displace_newborn_generation_for_test(
                NewbornDisplacementStage::IdentityStore,
                child_pid,
                parent.pid(),
                op,
                generation,
            );
            {
                let mut newborns = newborn_tracees.lock().unwrap();
                let Some(newborn) = newborns
                    .get_mut(&child_pid)
                    .filter(|newborn| newborn.same_generation(&generation))
                else {
                    drop(newborns);
                    self.record_liteinst_failure(
                        LiteinstActivationFailureReason::NewbornRegistration,
                        Error::runtime(
                            self.tid(),
                            "store LiteInst newborn identity",
                            format!(
                                "newborn {child_pid} event ownership disappeared before identity storage"
                            ),
                        ),
                    );
                    return Err(Errno::ESRCH.into());
                };
                newborn.set_identity(child_identity);
            }
            #[cfg(test)]
            if let Some(sender) = self
                .global_state
                .liteinst_runtime
                .as_ref()
                .and_then(|runtime| runtime.pause_new_task.as_ref())
            {
                let _ = sender.send(child.pid());
                if self
                    .global_state
                    .liteinst_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.pause_after_new_task)
                {
                    future::pending::<()>().await;
                }
            }
            #[cfg(test)]
            if runtime.fail_new_task {
                return Err(Errno::ENOTSUPP.into());
            }
            if op == ChildOp::Vfork {
                #[cfg(test)]
                let generation = runtime.displace_newborn_generation_for_test(
                    NewbornDisplacementStage::VforkTermination,
                    child_pid,
                    parent.pid(),
                    op,
                    generation,
                );
                // This refusal records no NewbornRegistration on top of the
                // VforkUnsupported recorded above. The task's latest recorded
                // reason decides at task exit whether a non-root vfork parent
                // skips the tool's exit bookkeeping, and this child was not
                // terminated, so its parent is still held behind it. The
                // refusals before this block do not keep VforkUnsupported
                // last: https://github.com/rrnewton/reverie/issues/878.
                let termination = newborn_tracees
                    .lock()
                    .unwrap()
                    .get(&child_pid)
                    .filter(|newborn| newborn.same_generation(&generation))
                    .ok_or(Errno::ESRCH)?
                    .terminate_vfork_child();
                termination?;
                return Err(Errno::ENOTSUPP.into());
            }
            // Any other new task proceeds under the ordinary ptrace lifecycle.
            // Root cleanup still owns every process child and CLONE_THREAD TID
            // if a later LiteInst failure does fail closed: it signals only
            // group-leader pidfds and drains every bound notifier generation on
            // the ptracer thread.
        }
        tracing::debug!(
            "[scheduler] handling fork from parent {} to child {}: {:?}",
            parent.pid(),
            child.pid(),
            op
        );

        #[cfg(test)]
        if matches!(op, ChildOp::Fork | ChildOp::Vfork) && self.ordinary_failure_enabled() {
            let pause = FATAL_FORK_PAUSE.with(|slot| slot.borrow().clone());
            if let Some(pause) = pause {
                // Retain this real Event::NewChild capability for emergency
                // test cleanup, before any child TracedTask has been created.
                child.terminal_cleanup();
                let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.pid())).unwrap();
                let start = stat
                    .rsplit_once(") ")
                    .unwrap()
                    .1
                    .split_whitespace()
                    .nth(19)
                    .unwrap()
                    .parse()
                    .unwrap();
                use std::os::unix::fs::MetadataExt;
                let inode = std::fs::metadata(format!("/proc/{}", child.pid()))
                    .unwrap()
                    .ino();
                *pause.generation.lock().unwrap() = Some((start, inode));
                *pause.child.lock().unwrap() = Some(child);
                pause.ready.notify_waiters();
                return future::pending().await;
            }
        }

        let mut child_task = match op {
            ChildOp::Clone => self.cloned(child.pid()),
            ChildOp::Fork => self.forked(child.pid()),
            ChildOp::Vfork => self.forked(child.pid()),
        };
        child_task.ptracer_waits.bind_running(&child);
        child_task.trap_only = self.trap_only_new_child(&parent, child.pid(), op)?;

        let (child_stop_tx, child_stop_rx) = mpsc::channel(1);
        child_task.gdb_stop_tx = Some(child_stop_tx);

        let daemonizer_rx = child_task.daemonizer_rx.take();
        let child_resume_tx = child_task.gdb_resume_tx.clone();
        let child_request_tx = child_task.gdb_request_tx.clone();
        let suspended = child_task.suspended.clone();

        // TODO-HUMAN-REVIEW(PR-103): Review rewritten clone parent/child restoration.
        let parent_restore = context
            .map(|context| {
                restore_context(
                    &parent,
                    context,
                    Some(child.pid().as_raw() as u64),
                    child_context.is_some(),
                )
            })
            .transpose();
        let parent_restore = if !self.ordinary_failure_enabled() {
            parent_restore?;
            Ok(None)
        } else {
            parent_restore
        };
        let child_restore_context = child_context.or(context);

        let id = child.pid();
        // Both cancellation domains register every newborn with the notifier
        // the moment its parent reports `Event::NewChild`, so
        // the "notifier is not yet aware of this PID" precondition for the raw
        // `wait` below no longer holds: the notifier worker would consume the
        // initial stop and the raw `wait` would block forever. Take the initial
        // stop from the notifier instead, which is the same state by a
        // registered route.

        // A panic anywhere in this body would otherwise be caught by tokio's
        // task harness and silently wedge the whole run; see
        // `guest_task_panic_is_fatal`. The body is built as its own future so
        // the catch sits at the task boundary and covers all of it.
        let panic_tid = id;
        let ordinary_failure = self
            .ordinary_failure_enabled()
            .then(|| self.fatal_session());
        let report_failure = ordinary_failure.clone();
        let ordinary_group = ordinary_failure.as_ref().and_then(|session| {
            match session.subscribe_group(&child.terminal_cleanup()) {
                Ok(subscription) => Some(subscription),
                Err(error) => {
                    session.fail_at(
                        BackendFailure {
                            pid: self.pid(),
                            tid: id,
                            phase: "ptrace orphan group subscription",
                        },
                        error.into(),
                    );
                    None
                }
            }
        });
        // Heap-place the child operation before the catch/completion wrappers
        // capture it. Tokio's automatic boxing occurs after its by-value spawn
        // entry, which can already exhaust the container's small host stack.
        let child_waits = child_task.ptracer_waits.clone();
        let body = Box::pin(async move {
            if ordinary_failure.is_some() {
                return child_task
                    .run_ordinary_newborn(child, child_restore_context)
                    .await;
            }
            // The child could potentially exit here. In most cases the first
            // event we get here should be `Event::Signal(Signal::SIGSTOP)`, but
            // we can also receive `Event::Exit` if a thread is created via
            // `clone`, but immediately killed via an `exit_group`. We have to
            // handle that rare case here.
            //
            // The notifier already owns this exact child generation.
            let initial_stop = child.next_state_with_owner(&child_task.ptracer_waits).await;
            let (child, event) = match initial_stop {
                Ok(Wait::Stopped(child, event)) => (child, event),
                Ok(Wait::Exited(_, exit_status)) => {
                    if let Some(failure) = &ordinary_failure {
                        failure.newborn_exited(id);
                    }
                    return Ok(Some(exit_status));
                }
                Err(TraceError::Died(zombie)) => {
                    let exit_status = match child_waits.reap_zombie(zombie).await {
                        Ok(exit_status) => exit_status,
                        Err(error) => {
                            tracing::error!(
                                target: "reverie_ptrace::lifecycle",
                                tid = %id,
                                %error,
                                "failed to reap new tracee after its initial-stop race"
                            );
                            if ordinary_failure.is_some() {
                                return Err(anyhow::anyhow!(
                                    "newborn {id} terminal wait failed: {error}"
                                )
                                .into());
                            }
                            return Ok(Some(ExitStatus::Exited(1)));
                        }
                    };
                    tracing::error!(
                        target: "reverie_ptrace::lifecycle",
                        tid = %id,
                        ?exit_status,
                        "new tracee exited before its initial stop"
                    );
                    if let Some(failure) = &ordinary_failure {
                        failure.newborn_exited(id);
                    }
                    return Ok(Some(exit_status));
                }
                Err(TraceError::Errno(errno)) => {
                    tracing::error!(
                        target: "reverie_ptrace::lifecycle",
                        tid = %id,
                        %errno,
                        "failed waiting for new tracee initial stop"
                    );
                    if ordinary_failure.is_some() {
                        return Err(errno.into());
                    }
                    return Ok(Some(ExitStatus::Exited(1)));
                }
            };

            assert!(
                event == Event::Signal(Signal::SIGSTOP) || event == Event::Exit,
                "Got unexpected event {:?}",
                event
            );

            child_task.arm_liteinst_root_stop(&child, &event);
            #[cfg(test)]
            if ordinary_failure.is_some() {
                let control = FATAL_SETUP_CONTROL.with(|slot| slot.borrow_mut().take());
                if let Some(control) = control {
                    *control.child.lock().unwrap() = Some((id, Arc::new(child.terminal_cleanup())));
                    return Err(
                        anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EIO))
                            .context("injected newborn setup refusal after its actual initial stop")
                            .into(),
                    );
                }
            }
            if let Some(context) = child_restore_context {
                // Restore context, but only if the child hasn't arrived at
                // `Event::Exit`.
                if event == Event::Signal(Signal::SIGSTOP)
                    && let Err(err) = restore_context(&child, context, None, false)
                {
                    tracing::error!(
                        tid = %child.pid(),
                        error = %err,
                        "failed to restore new tracee register context"
                    );
                    if ordinary_failure.is_some() {
                        return Err(anyhow::anyhow!(
                            "restore newborn {id} register context failed: {err}"
                        )
                        .into());
                    }
                    return Ok(Some(ExitStatus::Exited(1)));
                }
            }

            if child_task.is_a_daemon {
                child_task.ndaemons.fetch_add(1, Ordering::SeqCst);
            }

            let tid = child.pid();
            let detach_held_root_stop = child_task
                .liteinst_root_config()
                .map(|runtime| Arc::clone(&runtime.held_root_stop));
            let result = child_task.run(child).await;
            if ordinary_failure.is_some() {
                // A failed cleanup has no exit status. Never detach it or
                // invent one; the session retains its original fatal error.
                return result.map(Some);
            }
            Ok(Some(match result {
                Err(err) => {
                    tracing::error!("Error in tracee tid {}: {}", tid, err);

                    if liteinst_activation_failure_reason(&err).is_some() {
                        // Every typed LiteInst activation failure has already
                        // notified the session root. Its cleanup guard owns the
                        // exact pidfds and notifier handles for this tree.
                        // Detaching here lets a guest parent consume the child
                        // before that notifier acknowledges terminal status.
                        // This includes failed reactivation after exec, as well
                        // as a refused exec or a kernel-frozen vfork parent.
                        return Ok(Some(ExitStatus::Exited(1)));
                    }

                    // We assume the tracee is stopped since this error likely
                    // originated from the tool itself when the tracee is
                    // already stopped. If the tracee is not in a stopped state,
                    // that's fine too and ignore the detach error.
                    let detach_span = tracing::debug_span!(
                        target: "reverie_ptrace::lifecycle",
                        "tracee.detach",
                        %tid,
                        reason = "handler error"
                    );
                    let detach_guard = detach_span.enter();
                    let running =
                        match RootStopLease::new(child_waits.stopped(), detach_held_root_stop)
                            .detach(None)
                        {
                            Err(err) => {
                                // If we get an error here, the child process may
                                // not be in a ptrace stop.
                                tracing::error!("Failed to detach from {}: {}", tid, err);
                                return Ok(Some(ExitStatus::Exited(1)));
                            }
                            Ok(running) => running,
                        };
                    drop(detach_guard);

                    match running.next_state_with_owner(&child_waits).await {
                        Ok(wait) => wait.assume_exited().1,
                        Err(TraceError::Died(zombie)) => {
                            match child_waits.reap_zombie(zombie).await {
                                Ok(exit_status) => exit_status,
                                Err(error) => {
                                    tracing::error!(
                                        %tid,
                                        %error,
                                        "failed to reap detached tracee"
                                    );
                                    ExitStatus::Exited(1)
                                }
                            }
                        }
                        Err(TraceError::Errno(errno)) => {
                            tracing::error!(
                                %tid,
                                %errno,
                                "failed waiting for detached tracee exit"
                            );
                            ExitStatus::Exited(1)
                        }
                    }
                }
                Ok(exit_status) => exit_status,
            }))
        });
        if self.ordinary_failure_enabled() {
            self.global_state.fatal_session.handed(id);
        }
        let task_body = async move {
            match AssertUnwindSafe(body).catch_unwind().await {
                Ok(Ok(exit_status)) => exit_status,
                Ok(Err(error)) => {
                    if let Some(failure) = report_failure {
                        failure.fail(error);
                    }
                    None
                }
                Err(payload) => guest_task_panic_is_fatal(panic_tid, payload),
            }
        };
        let task = if self.ordinary_failure_enabled() {
            let (sender, receiver) = oneshot::channel();
            let handle = tokio::task::spawn_local(async move {
                #[cfg(not(test))]
                let result = task_body.await;
                #[cfg(test)]
                let result = {
                    // Drop the whole child future before publishing a scalar
                    // capacity receipt. Do not retain its terminal authority.
                    let mut task_body = std::pin::pin!(task_body);
                    task_body.as_mut().await
                };
                #[cfg(test)]
                crate::tracer::record_capacity_body_dropped_for_test(id, result);
                let _ = sender.send(result);
            });
            self.global_state
                .fatal_session
                .joins
                .lock()
                .unwrap()
                .push(handle);
            ChildCompletion::Owned(receiver)
        } else {
            ChildCompletion::Legacy(tokio::task::spawn_local(task_body))
        };

        if op == ChildOp::Clone {
            let mut child_threads = self.child_threads.lock().await;
            child_threads.push(Child {
                id,
                suspended,
                wait_all_stop_tx: None,
                daemonizer_rx,
                handle: task,
                ordinary_group,
            });
        } else {
            let mut child_procs = self.child_procs.lock().await;
            child_procs.push(Child {
                id,
                suspended,
                wait_all_stop_tx: None,
                daemonizer_rx,
                handle: task,
                ordinary_group,
            });
        }

        // Even a failed parent restoration leaves the initialized child owned
        // by the registered task before the error crosses the callback boundary.
        parent_restore?;
        let parent_regs = parent.getregs()?;
        if self.attached_by_gdb {
            // NB: We report T05;create event (for clone). However gdbserver
            // from binutils-gdb doesn't report it, even after toggling
            // QThreadEvents, as mentioned in https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#QThreadEvents
            // We report `create` event anyway.
            self.notify_gdb_stop(StopReason::new_task(
                self.tid(),
                self.pid(),
                id,
                parent_regs.into(),
                op,
                child_request_tx,
                child_resume_tx,
                Some(child_stop_rx),
            ))
            .await?;
            // We just reported a new event, wait for gdb resume.
            let running = self
                .await_gdb_resume(parent, ExpectedGdbResume::StepOnly)
                .await?;
            // NB: We could potentially hit a breakpoint after above resume,
            // make sure we don't miss the breakpoint and await for gdb
            // resume (once again). This is possible because result of
            // handle_new_task in status_to_result is ignored, while it could be
            // a valid state like SIGTRAP, which could be a breakpoint is hit.
            running
                .next_state_with_owner(&self.ptracer_waits)
                .and_then(|wait| self.check_swbreak(wait))
                .await
        } else {
            // This nested parent step consumes the root-stop lease, so the
            // resulting stop has to re-arm it before returning to a caller
            // that will transition the root again. Every other nested handler
            // does the same; this one only looks new because the whole
            // new-task path used to be unreachable under LiteInst.
            #[cfg(test)]
            let hold = LEADER_STEP_EXIT_HOLD
                .with(|slot| slot.borrow().clone())
                .filter(|hold| {
                    self.tid() == self.pid() && hold.armed.swap(false, Ordering::SeqCst)
                });
            let running = self.step_stopped(parent, None)?;
            #[cfg(test)]
            if let Some(hold) = hold {
                hold_leader_step_until_exit(hold, &running).await;
            }
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            Ok(wait)
        }
    }

    async fn handle_vfork_done_event(&mut self, stopped: Stopped) -> Result<Wait, TraceError> {
        self.resume_stopped(stopped, None)?
            .next_state_with_owner(&self.ptracer_waits)
            .await
    }

    async fn wait_after_exit_event(
        task: Stopped,
        waits: &Arc<PtracerWaitOwner>,
        held_root_stop: Option<Arc<StdMutex<Option<HeldRootStop>>>>,
    ) -> Result<Wait, TraceError> {
        // de_thread can replace the leader after its PTRACE_EVENT_EXIT, so
        // this wait may report Exec with the caller's former TID, not death.
        if let Some(slot) = held_root_stop.as_ref() {
            HeldRootStop::supersede_with_exit(slot, &task)?;
        }
        RootStopLease::new(task, held_root_stop)
            .resume(None)?
            .next_state_with_owner(waits)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn handle_exit_event(
        task: Stopped,
        held_root_stop: Option<Arc<StdMutex<Option<HeldRootStop>>>>,
    ) -> Result<ExitStatus, TraceError> {
        let waits = Arc::new(PtracerWaitOwner::default());
        waits.bind_stopped(&task);
        let wait = Self::wait_after_exit_event(task, &waits, held_root_stop).await?;
        let (_pid, exit_status) = wait.assume_exited();
        Ok(exit_status)
    }

    /// Aborts the current handler. This just sends a result through a channel to
    /// the `run_loop`, which should cause the current future to be dropped and
    /// canceled. Thus, this function will never return so that execution of the
    /// current future doesn't proceed any further.
    async fn abort(&mut self, result: Result<Wait, TraceError>) -> ! {
        #[cfg(test)]
        let timer_pause = FATAL_FORK_PAUSE.with(|slot| {
            slot.borrow().clone().filter(|pause| {
                pause.timer
                    && pause.timer_parent.load(Ordering::SeqCst) == self.tid().as_raw()
                    && matches!(&result, Ok(Wait::Stopped(_, Event::NewChild(ChildOp::Fork, child)))
                        if pause.timer_child.lock().unwrap().as_ref().is_some_and(|observed| observed.pid == child.pid()))
            })
        });
        #[cfg(test)]
        if let Err(TraceError::Errno(errno)) = &result {
            crate::tracer::record_bare_errno_abort_for_test(self.tid(), *errno);
        }
        if self.next_state.send(result).await.is_err() {
            panic!(
                "failed to abort tracee {}: run-loop next-state channel is closed",
                self.tid()
            );
        }
        #[cfg(test)]
        if let Some(pause) = timer_pause {
            pause.timer_published.store(true, Ordering::SeqCst);
            eprintln!(
                "timer fork published to next-state channel: parent={}",
                self.tid()
            );
        }

        // Wait on a future that will never complete. This pending future will
        // be dropped when the channel receives the event just sent.
        future::pending().await
    }

    /// Marks the current task as exited via a channel. The receiver end of the
    /// channel should cause the current future to be dropped and canceled. Thus,
    /// this function will never return so that execution doesn't proceed any
    /// further.
    async fn exit(&mut self, exit_status: ExitStatus) -> ! {
        self.abort(Ok(Wait::Exited(self.tid(), exit_status))).await
    }

    /// Marks the current task as having successfully called `execve` and so it
    /// should never return.
    async fn execve(&mut self, next_state: Wait) -> ! {
        self.abort(Ok(next_state)).await
    }

    /// Triggers the tool exit callbacks.
    async fn tool_exit(self, exit_status: ExitStatus) -> Result<(), reverie::Error> {
        if self.is_main_thread() {
            // Wait for all child threads to fully exit. This *must* happen before
            // the main thread can exit.
            // TODO: Use FuturesUnordered instead of `join_all` for better
            // performance.
            {
                let children = self.child_threads.lock().await.take_inner();
                future::join_all(children).await;
            }

            // Check if there are any children who's futures are still pending. If
            // this is the case, then they shall be considered "orphans" and are
            // "adopted" by the tracer process who shall then wait for them to exit
            // and get their final exit code. Normally, when not running under
            // ptrace, orphans are adopted by the init process who should
            // automatically reap them by waiting for the final exit status.
            let orphans = if self.global_state.liteinst_runtime.is_some() {
                // A LiteInst session follows process children as part of one
                // fail-closed instrumentation domain. Do not let root exit end
                // the LocalSet while a child can still publish a session
                // failure: join those exact followed tasks first.
                let children = self.child_procs.lock().await.take_inner();
                future::join_all(children).await;
                Children::new()
            } else {
                let (orphans, _) = {
                    let mut child_procs = self.child_procs.lock().await;
                    child_procs.deref_mut().await
                };
                orphans
            };

            for orphan in orphans.into_inner() {
                // Bon voyage.
                if let Err(err) = self.orphanage.send(orphan).await {
                    let orphan = err.0;
                    tracing::warn!(
                        pid = %orphan.id(),
                        "orphan reaper closed; waiting for child inline"
                    );
                    let _ = orphan.await;
                }
            }

            let _ = self
                .notify_gdb_stop(StopReason::Exited(self.pid(), exit_status))
                .await;

            let wrapped = WrappedFrom(self.tid, &self.global_state);

            // Thread exit
            self.process_state
                .on_exit_thread(self.tid, &wrapped, self.thread_state, exit_status)
                .await?;

            // The try_unwrap and subsequent unwrap are safe to do. ptrace
            // guarantees that all threads in the thread group have exited
            // before the main thread.
            let process_state = Arc::try_unwrap(self.process_state).unwrap_or_else(|_| {
                // If you end up seeing this panic, make sure that all clones of
                // `process_state` are dropped before reaching this point.
                panic!("Reverie internal invariant broken. try_unwrap on process state failed")
            });
            let wrapped = WrappedFrom(self.tid, &self.global_state);
            process_state
                .on_exit_process(self.tid, &wrapped, exit_status)
                .await?;

            let ntasks_remaining = self.ntasks.fetch_sub(1, Ordering::SeqCst);
            let ndaemons = self.ndaemons.load(Ordering::SeqCst);

            if self.is_a_daemon {
                self.ndaemons.fetch_sub(1, Ordering::SeqCst);
            }

            if ntasks_remaining == 1 + ndaemons {
                // daemonize() might not get called, this is not an error.
                let _ = self.daemon_kill_switch.send(());
            }
        } else {
            let _ = self
                .notify_gdb_stop(StopReason::ThreadExited(
                    self.tid(),
                    self.pid(),
                    exit_status,
                ))
                .await;
            let wrapped = WrappedFrom(self.tid, &self.global_state);

            self.child_threads
                .lock()
                .await
                .retain(|child| child.id() != self.tid);

            // Thread exit
            self.process_state
                .on_exit_thread(self.tid, &wrapped, self.thread_state, exit_status)
                .await?;

            self.ntasks.fetch_sub(1, Ordering::SeqCst);
            if self.is_a_daemon {
                self.ndaemons.fetch_sub(1, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    async fn run_loop(&mut self, task: Stopped) -> Result<ExitStatus, reverie::Error> {
        self.ptracer_waits.bind_stopped(&task);
        match self.run_loop_internal(task).await {
            Ok(exit_status) => Ok(exit_status),
            Err(Error::RunFailed) => future::pending().await,
            Err(err) => {
                if self.global_state.liteinst_runtime.is_some() {
                    // Return immediately to the outer LiteInst cleanup guard.
                    // It owns the original root pidfd and every generation-
                    // bound notifier handle; this task must not reopen or
                    // numerically signal the root PID.
                    return Err(anyhow::Error::new(err).into());
                }
                if !self.is_main_thread()
                    && let Some(_operation) = self.own_tid_echild_operation(&err)
                {
                    // A nonleader execve (de_thread) hands this thread's TID
                    // to the leader's pid object and releases it, so a wait on
                    // the former TID reports ECHILD. The run loop can see that
                    // before `drive_ordinary` re-polls this thread's exit
                    // future, which applies the same rule. ECHILD authorizes
                    // neither exit nor failure: stay pending so the leader's
                    // actual Exec edge transfers this state, while session
                    // cancellation and backend failure remain observable.
                    #[cfg(test)]
                    {
                        NONLEADER_RUN_LOOP_ECHILD_PENDED
                            .with(|pended| pended.borrow_mut().push(_operation));
                        if let Some(slot) = self.ordinary_exec.lock().unwrap().get(&self.tid()) {
                            slot.changed.notify_waiters();
                        }
                    }
                    return future::pending().await;
                }
                // Note: Calling handle_internal_error cannot happen in the
                // `select!()` of the `run` function because then the exit
                // events that get generated in here cannot be caught by the
                // `select!()`.
                handle_internal_error(err, &self.ptracer_waits).await
            }
        }
    }

    fn observe_ready_thread_state(&self) -> Result<(), Errno> {
        observe_ready_thread_state(
            self.process_state.as_ref(),
            self.pid(),
            self.tid(),
            self.global_state.gs_ref.as_ref(),
            &self.thread_state,
        )
    }

    async fn run_loop_internal(&mut self, task: Stopped) -> Result<ExitStatus, Error> {
        // This is the beginning of the life of the guest. Allow the tool to
        // inject syscalls as soon as the thread starts.
        match cancellable(self.cancel_handler.clone(), async {
            self.process_state.clone().handle_thread_start(self).await
        })
        .await
        {
            Some(Ok(())) => self.observe_ready_thread_state()?,
            Some(Err(err)) => {
                if self.ordinary_failure_enabled() && !matches!(err, reverie::Error::Errno(_)) {
                    self.publish_ordinary_failure("ptrace thread start", err);
                    return Err(Error::RunFailed);
                }
                // Legitimate guest errno keeps the existing startup behavior.
                err.into_errno()?;
            }
            None => {}
        }
        self.ordinary_continuation()?;
        self.ordinary_trace_continuation()?;
        self.timer.finalize_requests();

        // Resume the guest for the first time. Note that the root task and
        // child tasks start out in a stopped state for different reasons: The
        // root task is stopped because of the SIGSTOP raised inside of `fork()`
        // after calling `traceme`. Child tasks start out in a running state,
        // but we wait for them to stop in `Event::NewChild`.
        //
        // NB: await_gdb_resume == resume if not attached_by_gdb.
        let running = self
            .await_gdb_resume(task, ExpectedGdbResume::Resume)
            .await
            .tracee_context(self.tid(), "initial tracee resume")?;

        // Notify gdb server (if any) that tracee is ready.
        if let Some(server_tx) = self.gdbserver_start_tx.take() {
            self.attached_by_gdb = true;
            if server_tx.send(()).is_err() {
                tracing::warn!(tid = %self.tid(), "GDB server closed before tracee attach");
                self.attached_by_gdb = false;
            }
        }

        let task_state = running
            .next_state_with_owner(&self.ptracer_waits)
            .await
            .tracee_context(self.tid(), "wait after initial tracee resume")?;
        self.run_loop_events(task_state).await
    }

    async fn run_loop_events(&mut self, mut task_state: Wait) -> Result<ExitStatus, Error> {
        let mut next_state_rx = self.next_state_rx.take().ok_or_else(|| {
            Error::runtime(
                self.tid(),
                "initialize run loop",
                "next-state receiver was already taken",
            )
        })?;

        loop {
            if let Some(stats) = &self.global_state.backend_stats {
                stats.record_wait(self.pid(), &task_state);
            }
            // A nested handler may forward a stop it already armed before
            // inspecting the status. Accept only that exact generation/status;
            // every ordinary returned transition still requires an empty slot.
            self.ensure_liteinst_wait(&task_state);
            match task_state {
                Wait::Stopped(stopped, event) => {
                    // Allow short-circuiting of the event stream. This makes it
                    // easier to send exit and execve events directly to the run
                    // loop from within `inject` or `tail_inject`.
                    let tid = self.tid();
                    let fut1 = next_state_rx.recv().fuse();
                    // Holds the queued timer-decoded fork unconsumed, so the
                    // control's sibling failure cancels this loop first.
                    #[cfg(test)]
                    let fut1 = {
                        let mut receive = Box::pin(fut1);
                        let pause = FATAL_FORK_PAUSE.with(|slot| slot.borrow().clone());
                        future::poll_fn(move |cx| {
                            if let Some(pause) = pause.as_ref().filter(|pause| {
                                pause.timer
                                    && pause.timer_parent.load(Ordering::SeqCst) == tid.as_raw()
                                    && pause.timer_published.load(Ordering::SeqCst)
                            }) {
                                if !pause.timer_receive_blocked.swap(true, Ordering::SeqCst) {
                                    eprintln!(
                                        "timer fork receiver held before consuming queued child: parent={tid}"
                                    );
                                    pause.ready.notify_waiters();
                                }
                                return Poll::Pending;
                            }
                            receive.as_mut().poll(cx)
                        })
                        .fuse()
                    };
                    let fut2 = self.handle_stop_event(stopped, event).fuse();

                    futures::pin_mut!(fut1, fut2);

                    task_state = futures::select_biased! {
                        next_state = fut1 => {
                            if let Some(next_state) = next_state {
                                next_state.map_err(|error| match error {
                                    // Only this task's own handlers send here
                                    // (`abort`), from `inject`, `tail_inject`
                                    // and the nested handlers they run. Their
                                    // waits are all on this TID: a new child is
                                    // waited on in its own spawned task. ptrace
                                    // and process_vm_* never return ECHILD. So
                                    // an ECHILD here is a wait on this TID, or
                                    // a Tool post-exec callback's errno that a
                                    // nested `handle_exec_event` relays
                                    // (`ordinary_callback_errno` returns it as
                                    // `TraceError::Errno`). Both get this label.
                                    // The callback case is harmless: before
                                    // returning the errno, that function has
                                    // published the session failure, which
                                    // `drive_ordinary` sees as cancellation.
                                    // Other errors keep their unattributed form.
                                    TraceError::Errno(Errno::ECHILD) => Error::Tracee {
                                        operation: "wait during injected syscall",
                                        pid: tid,
                                        source: error,
                                    },
                                    error => Error::Internal(error),
                                })
                            } else {
                                Err(Error::runtime(
                                    tid,
                                    "receive injected tracee state",
                                    "next-state channel closed unexpectedly",
                                ))
                            }
                        }
                        next_state = fut2 => next_state,
                    }?;
                }
                Wait::Exited(pid, exit_status) => {
                    self.notify_gdb_stop(StopReason::Exited(pid, exit_status))
                        .await?;
                    break Ok(exit_status);
                }
            }
        }
    }

    /// Errno erases causal provenance. Resolve against the current held stop,
    /// retaining the original return while only the original owner can exit.
    async fn ordinary_callback_errno<T>(
        &mut self,
        phase: &'static str,
        result: Result<T, Errno>,
    ) -> Result<T, TraceError> {
        let errno = match result {
            Ok(value) => return Ok(value),
            Err(errno) if !self.ordinary_failure_enabled() => return Err(errno.into()),
            Err(errno) => errno,
        };
        use crate::PtraceCallbackDecision as Decision;
        use crate::PtraceCallbackRefusal as Refusal;
        let session = self.fatal_session();
        let mut diagnostic = crate::PtraceCallbackDiagnostic {
            origin: BackendFailure {
                pid: self.pid(),
                tid: self.tid(),
                phase,
            },
            errno,
            held: None,
            sample: None,
            refusal: None,
            decision: Decision::AwaitingOwner,
            outcome: None,
            failure_published_at_outcome: false,
            backend_signalling_at_outcome: false,
        };
        let decision = if session.is_failed() {
            diagnostic.decision = Decision::Cancelled;
            session.fail_at(diagnostic.origin, errno.into());
            Ok(true)
        } else if session.ptracer_thread != Some(std::thread::current().id()) {
            Err(Refusal::WrongThread)
        } else {
            let stop = session
                .tree
                .lock()
                .unwrap()
                .tasks
                .iter()
                .find(|stop| stop.tid == self.tid())
                .cloned();
            let observation = match stop {
                Some(stop) => self
                    .ordinary_held_stop
                    .lock()
                    .unwrap()
                    .as_ref()
                    .ok_or(Refusal::HeldStop)
                    .and_then(|held| held.callback_observation(self.tid(), &stop.terminal)),
                None => Err(Refusal::HeldStop),
            };
            match observation {
                Ok((held, sample)) => {
                    let result = callback_owner_decision(held, &sample);
                    diagnostic.held = Some(held);
                    diagnostic.sample = Some(sample);
                    result
                }
                Err(error) => Err(error),
            }
        };
        let park = match decision {
            Ok(park) => {
                if !park {
                    diagnostic.decision = Decision::Fatal;
                }
                park
            }
            Err(refusal) => {
                diagnostic.decision = Decision::Refused;
                diagnostic.refusal = Some(refusal);
                false
            }
        };
        let refusal = diagnostic.refusal.clone();
        {
            let mut records = session.callback_diagnostics.lock().unwrap();
            self.pending_callback_diagnostic = Some(records.len());
            records.push(diagnostic);
        }
        if park {
            // No timer finalization, result encoding, continuation or new wait.
            // drive_ordinary retains and polls the one existing exit receiver.
            return future::pending().await;
        }
        self.publish_ordinary_failure(phase, errno.into());
        if let Some(refusal) = refusal {
            session.fail_at(
                BackendFailure {
                    pid: self.pid(),
                    tid: self.tid(),
                    phase: "ptrace callback lifecycle observation",
                },
                anyhow::Error::new(refusal).into(),
            );
        }
        Err(errno.into())
    }

    fn resolve_callback_diagnostic(
        &mut self,
        outcome: crate::PtraceCallbackOutcome,
        receipt: crate::tracer::OrdinaryReceipt,
    ) {
        if let Some(index) = self.pending_callback_diagnostic.take() {
            let session = self.fatal_session();
            let mut records = session.callback_diagnostics.lock().unwrap();
            let record = &mut records[index];
            record.outcome = Some(outcome);
            record.failure_published_at_outcome = receipt.failure_published;
            record.backend_signalling_at_outcome = receipt.backend_signalling;
            if record.decision == crate::PtraceCallbackDecision::AwaitingOwner
                && receipt.failure_published
            {
                record.decision = crate::PtraceCallbackDecision::Cancelled;
            }
        }
    }

    fn publish_ordinary_failure(&self, phase: &'static str, error: reverie::Error) {
        self.global_state.fatal_session.fail_at(
            BackendFailure {
                pid: self.pid(),
                tid: self.tid(),
                phase,
            },
            error,
        );
        if let Err(error) = self.timer.cancel() {
            self.global_state.fatal_session.fail_at(
                BackendFailure {
                    pid: self.pid(),
                    tid: self.tid(),
                    phase: "ptrace timer cancellation",
                },
                error.into(),
            );
        }
    }

    /// The wait operation, when `err` is ECHILD from a wait on this task's own
    /// TID. Only an error that names this TID qualifies: a bare
    /// `Error::Internal` ECHILD could come from any `?` (`From<Errno>` makes
    /// every propagated errno one), so it does not. Every own-TID wait that
    /// can report ECHILD to the ordinary run loop carries this TID: the
    /// initial resume and seccomp resume waits, the handlers that
    /// `handle_stop_event` annotates, and waits inside injected syscalls,
    /// which `run_loop_events` annotates when their result comes back through
    /// the next-state channel.
    ///
    /// The converse does not hold: not every qualifying error is a wait.
    /// `handle_stop_event` names this TID on any error from `handle_signal`,
    /// `handle_exec_event`, `dispatch_new_task` and `handle_vfork_done_event`,
    /// and `ordinary_callback_errno` returns a Tool callback's errno as
    /// `TraceError::Errno`, so a callback that returns ECHILD qualifies too.
    /// That is harmless today. This rule applies only without LiteInst, and
    /// there `ordinary_callback_errno` either never returns or publishes the
    /// session failure before it returns the errno, so `drive_ordinary` takes
    /// its cancellation branch while the run loop stays pending.
    fn own_tid_echild_operation(&self, err: &Error) -> Option<&'static str> {
        match err {
            Error::Tracee {
                operation,
                pid,
                source: TraceError::Errno(Errno::ECHILD),
            } if *pid == self.tid() => Some(operation),
            _ => None,
        }
    }

    fn ordinary_failure_enabled(&self) -> bool {
        // Configured static traps use the same stopped-task ownership as
        // seccomp. Dynamic LiteInst retains its separate session cleanup guard.
        self.global_state.liteinst_runtime.is_none()
    }

    fn ordinary_trace_continuation(&self) -> Result<(), TraceError> {
        if self.global_state.fatal_session.is_failed() {
            Err(Errno::ECANCELED.into())
        } else {
            Ok(())
        }
    }

    fn ordinary_continuation(&self) -> Result<(), Error> {
        if self.global_state.fatal_session.is_failed() {
            Err(Error::RunFailed)
        } else {
            Ok(())
        }
    }

    pub(crate) fn fatal_session(&self) -> Arc<FatalSession> {
        self.global_state.fatal_session.clone()
    }

    async fn ordinary_start(&mut self, start: OrdinaryStart) -> Result<ExitStatus, reverie::Error> {
        let child = match start {
            OrdinaryStart::Exec(child, former) => {
                let result = match self.handle_exec_event(child, former).await {
                    Ok(state) => self.run_loop_events(state).await,
                    Err(error) => Err(Error::Internal(error)),
                };
                return match result {
                    Ok(status) => Ok(status),
                    Err(Error::RunFailed) => future::pending().await,
                    Err(error) => handle_internal_error(error, &self.ptracer_waits).await,
                };
            }
            OrdinaryStart::Stopped(child) => child,
            OrdinaryStart::Newborn(child, context) => {
                let wait = match child.next_state_with_owner(&self.ptracer_waits).await {
                    Ok(wait) => wait,
                    Err(TraceError::Died(zombie)) => {
                        return self
                            .ptracer_waits
                            .reap_zombie(zombie)
                            .await
                            .map_err(|error| anyhow::Error::new(error).into());
                    }
                    Err(error) => return Err(anyhow::Error::new(error).into()),
                };
                let (child, event) = match wait {
                    Wait::Exited(_, status) => return Ok(status),
                    Wait::Stopped(child, event) => (child, event),
                };
                self.arm_liteinst_root_stop(&child, &event);
                #[cfg(test)]
                if let Some(control) = FATAL_SETUP_CONTROL.with(|slot| slot.borrow_mut().take()) {
                    *control.child.lock().unwrap() =
                        Some((self.tid(), Arc::new(child.terminal_cleanup())));
                    return Err(
                        anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EIO))
                            .context("injected newborn setup refusal after its actual initial stop")
                            .into(),
                    );
                }
                if event == Event::Exit {
                    return future::pending().await;
                }
                if event != Event::Signal(Signal::SIGSTOP) {
                    return Err(
                        anyhow::anyhow!("unexpected newborn initial event: {event:?}").into(),
                    );
                }
                if let Some(context) = context {
                    restore_context(&child, *context, None, false).map_err(anyhow::Error::new)?;
                }
                child
            }
        };
        self.run_loop(child).await
    }

    async fn run_ordinary_newborn(
        self,
        child: Running,
        context: Option<libc::user_regs_struct>,
    ) -> Result<Option<ExitStatus>, reverie::Error> {
        self.run_ordinary_owned(OrdinaryStart::Newborn(child, context.map(Box::new)))
            .await
    }

    async fn run_ordinary(self, child: Stopped) -> Result<ExitStatus, reverie::Error> {
        match self
            .run_ordinary_owned(OrdinaryStart::Stopped(child))
            .await?
        {
            Some(status) => Ok(status),
            None => unreachable!("only a nonleader child can transfer at exec"),
        }
    }

    async fn run_ordinary_owned(
        mut self,
        mut start: OrdinaryStart,
    ) -> Result<Option<ExitStatus>, reverie::Error> {
        let session = self.fatal_session();
        #[cfg(test)]
        crate::tracer::record_group_stop_session_for_test(&session);
        #[cfg(test)]
        FATAL_FREEZE_CONTROL.with(|slot| {
            if let Some(control) = slot.borrow().as_ref() {
                *control.session.lock().unwrap() = Some(session.clone());
            }
        });
        match &start {
            OrdinaryStart::Stopped(child) | OrdinaryStart::Exec(child, _) => {
                self.ptracer_waits.bind_stopped(child)
            }
            OrdinaryStart::Newborn(child, _) => self.ptracer_waits.bind_running(child),
        }
        let terminal = match &start {
            OrdinaryStart::Stopped(child) | OrdinaryStart::Exec(child, _) => {
                child.generation().terminal_cleanup()
            }
            OrdinaryStart::Newborn(child, _) => child.generation().terminal_cleanup(),
        };
        let stop = Arc::new(FatalTaskStop {
            tid: self.tid(),
            terminal,
            held: self.ordinary_held_stop.clone(),
            frozen: AtomicBool::new(false),
            waits: self.ptracer_waits.clone(),
        });
        let slot = Arc::new(OrdinaryExecSlot {
            stop: stop.clone(),
            requested: AtomicBool::new(false),
            lost_former: AtomicBool::new(false),
            changed: Notify::new(),
            transferred: StdMutex::new(None),
            lost_former_task: StdMutex::new(None),
        });
        // A nonleader's owner retains its own process's leader owner slot. The
        // leader removes that slot only after consuming its actual final wait
        // status, and never after an Exec edge; see `run_ordinary_owned`'s
        // lost-former arm, which hands its task over through that slot.
        let leader = {
            let mut exec = self.ordinary_exec.lock().unwrap();
            exec.insert(self.tid(), slot.clone());
            if self.is_main_thread() {
                None
            } else {
                exec.get(&self.pid()).cloned()
            }
        };
        let exec_owners = self.ordinary_exec.clone();
        let newborn = session.register(stop.clone());
        let mut exit_event = match newborn {
            Some(newborn) => newborn.into_exit(),
            None => match &start {
                OrdinaryStart::Stopped(child) | OrdinaryStart::Exec(child, _) => {
                    self.ptracer_waits.exit_stopped(child)
                }
                OrdinaryStart::Newborn(_, _) => {
                    panic!("initialized newborn lost its original exit receiver")
                }
            },
        };
        if matches!(&start, OrdinaryStart::Newborn(..)) && self.is_a_daemon {
            self.ndaemons.fetch_add(1, Ordering::SeqCst);
        }
        #[cfg(test)]
        let hold_transfer = !self.is_main_thread()
            && NONLEADER_RUN_LOOP_OBSERVES_ECHILD_FIRST.with(std::cell::Cell::get);
        loop {
            // Covers the entire run, parked callbacks, terminal waits, and
            // failure cleanup. The actual Exec requester owns the replacement
            // stop before this original task can transfer its state.
            let outcome = {
                let drive = self
                    .drive_ordinary(
                        start,
                        &mut exit_event,
                        &stop,
                        &session,
                        leader.is_some().then_some(&*slot),
                    )
                    .fuse();
                // Only after drive_ordinary has recorded its former TID's
                // ECHILD, and only once the same process's leader owner has
                // consumed its actual final wait status and left the registry.
                // After that no Exec edge can request this slot: the leader
                // requests before it resumes an Exec stop, and it removes its
                // own slot only on its Exited route.
                // Polled only after a waker fired, like `transfer` below.
                let lost = PollOnWake::new(Box::pin(async {
                    slot.lost_former().await;
                    let Some(leader) = leader.as_ref() else {
                        return future::pending().await;
                    };
                    loop {
                        let changed = leader.changed.notified();
                        let present = exec_owners
                            .lock()
                            .unwrap()
                            .get(&leader.stop.tid)
                            .is_some_and(|entry| Arc::ptr_eq(entry, leader));
                        if !present {
                            break;
                        }
                        changed.await;
                    }
                }))
                .fuse();
                // Polled only after `slot.changed` woke it, not on every
                // resume of this task: it completes at most once per exec.
                let transfer = PollOnWake::new(Box::pin(async {
                    slot.requested().await;
                    // The forced order is complete only once the run loop,
                    // not an earlier Exec transfer, has observed the former
                    // TID's ECHILD. Hold the transfer until then.
                    #[cfg(test)]
                    if hold_transfer {
                        loop {
                            let changed = slot.changed.notified();
                            if NONLEADER_RUN_LOOP_ECHILD_PENDED
                                .with(|pended| !pended.borrow().is_empty())
                            {
                                break;
                            }
                            changed.await;
                        }
                    }
                }))
                .fuse();
                futures::pin_mut!(drive, transfer, lost);
                futures::select_biased! {
                    () = transfer => None,
                    () = lost => Some(None),
                    result = drive => Some(Some(result)),
                }
            };
            match outcome {
                Some(None) => {
                    // This former thread became the leader through de_thread
                    // and died before its exec stop, so no Exec edge requested
                    // this task. Its final status is the one the leader owner
                    // consumed under the leader TID, and this TID has none.
                    // Hand the task, Tool thread state included, to the leader
                    // owner: its child-thread join in `tool_exit_ordinary`
                    // waits for this owner, then reports this state under the
                    // leader TID with that final status, and the replaced
                    // leader's state with that leader's own exit-stop status.
                    // This owner runs no on_exit hook and returns no
                    // ExitStatus.
                    self.ordinary_exec.lock().unwrap().remove(&self.tid());
                    crate::tracer::retire_ordinary_terminal(&stop.terminal, &stop.held).await;
                    session.finished(&stop);
                    let leader = leader
                        .as_ref()
                        .expect("`lost` completes only with a leader owner slot");
                    let previous = leader
                        .lost_former_task
                        .lock()
                        .unwrap()
                        .replace(Box::new(self));
                    // One de_thread per process can release a former TID
                    // without an Exec edge following: its thread is the last
                    // one, and the process ends with it. Any earlier exec
                    // reached its Exec edge, which transfers its former task
                    // instead, since this arm requires the leader slot gone.
                    assert!(
                        previous.is_none(),
                        "a second lost former handed over to one leader owner"
                    );
                    return Ok(None);
                }
                None => {
                    *slot.transferred.lock().unwrap() = Some(Box::new(self));
                    slot.changed.notify_waiters();
                    // No on_exit hook or fabricated ExitStatus for the
                    // surviving former thread. Its state now has one owner.
                    return Ok(None);
                }
                Some(Some(crate::tracer::OrdinaryTerminal::Exited(
                    status,
                    receipt,
                    entry_exit_stop,
                ))) => {
                    // Every actual terminal route, including direct run-loop
                    // return, keeps its original owner registered until the
                    // notifier retires. Announce physical quiescence first so a
                    // later peer failure does not wait for this finished loop.
                    stop.frozen.store(true, Ordering::Release);
                    session.changed.notify_waiters();
                    crate::tracer::retire_ordinary_terminal(&stop.terminal, &stop.held).await;
                    self.resolve_callback_diagnostic(
                        crate::PtraceCallbackOutcome::Exited(status),
                        receipt,
                    );
                    self.ordinary_exec.lock().unwrap().remove(&self.tid());
                    // Wakes a nonleader owner whose former TID was lost to
                    // exec (the lost-former arm above). It hands its task to
                    // this slot before it completes, and the child-thread
                    // join in `tool_exit_ordinary` waits for it.
                    slot.changed.notify_waiters();
                    if let Some(stats) = &self.global_state.backend_stats {
                        stats.record_tracee_exit();
                    }
                    // Whether the run loop returned or the exit stop cut it
                    // short, the thread has ended its timer event.
                    self.timer.settle_at_exit();
                    log_guest_exit(self.tid(), self.pid(), status);
                    self.tool_exit_ordinary(status, &slot, entry_exit_stop)
                        .await;
                    session.finished(&stop);
                    return Ok(Some(status));
                }
                Some(Some(crate::tracer::OrdinaryTerminal::Exec {
                    stopped,
                    former,
                    replaced_status,
                    receipt,
                })) => {
                    self.resolve_callback_diagnostic(
                        crate::PtraceCallbackOutcome::Exec {
                            former,
                            exit_stop_status: replaced_status,
                        },
                        receipt,
                    );
                    let former_slot = loop {
                        let candidate = self.ordinary_exec.lock().unwrap().get(&former).cloned();
                        if former != self.tid()
                            && self.is_main_thread()
                            && stopped.pid() == self.tid()
                            && stopped.terminal_cleanup().same_generation(&stop.terminal)
                            && let Some(candidate) = candidate
                        {
                            break candidate;
                        }
                        session.retry_after(anyhow::anyhow!("actual exec former {former} has no same-process initialized owner").into()).await;
                    };
                    former_slot.requested.store(true, Ordering::Release);
                    former_slot.changed.notify_waiters();
                    let mut former_task = former_slot.take().await;
                    while !former_slot.stop.terminal.wait(std::time::Duration::ZERO) {
                        tokio::task::yield_now().await;
                    }
                    // Registry membership and immutable stop generation bind
                    // the request; the actual kernel Exec supplies the edge.
                    assert!(Arc::ptr_eq(&self.process_state, &former_task.process_state));
                    self.ordinary_exec.lock().unwrap().remove(&former);
                    session.finished(&former_slot.stop);
                    #[cfg(test)]
                    let timer_before = EXEC_TIMER_TRANSFERS.with(|control| {
                        control.borrow().as_ref().map(|_| {
                            (
                                self.timer
                                    .exec_test_identity()
                                    .expect("read old leader perf identity"),
                                former_task
                                    .timer
                                    .exec_test_identity()
                                    .expect("read former perf identity"),
                            )
                        })
                    });
                    std::mem::swap(&mut self.thread_state, &mut former_task.thread_state);
                    std::mem::swap(&mut self.timer, &mut former_task.timer);
                    std::mem::swap(&mut self.is_a_daemon, &mut former_task.is_a_daemon);
                    former_task
                        .retire_replaced_leader(self.tid(), replaced_status)
                        .await;
                    for (phase, error) in self.timer.retarget_after_exec(self.pid(), self.tid()) {
                        session.fail_at(
                            BackendFailure {
                                pid: self.pid(),
                                tid: self.tid(),
                                phase,
                            },
                            error.into(),
                        );
                    }
                    #[cfg(test)]
                    if let Some((displaced, before)) = timer_before {
                        let after = self
                            .timer
                            .exec_test_identity()
                            .expect("read replacement perf identity");
                        // Probe by event ID, not by descriptor number: other
                        // tests in this process reuse a freed number at once.
                        let closed = displaced.as_ref().is_some_and(|old| {
                            [
                                (old.clock_fd, old.clock_event_id),
                                (old.timer_fd, old.timer_event_id),
                            ]
                            .into_iter()
                            .all(|(fd, id)| crate::perf::fd_no_longer_names_event(fd, id))
                        });
                        EXEC_TIMER_TRANSFERS.with(|control| {
                            control.borrow().as_ref().unwrap().lock().unwrap().push(
                                ExecTimerTransfer {
                                    displaced,
                                    before,
                                    after,
                                    displaced_fds_closed: closed,
                                },
                            )
                        });
                    }
                    // The old callback and its receiver were cancelled. A new
                    // channel carries only events from the replacement image.
                    let (tx, rx) = mpsc::channel(1);
                    self.next_state = tx;
                    self.next_state_rx = Some(rx);
                    self.pending_signal = None;
                    self.pending_signal_taken = None;
                    self.in_signal_callback = false;
                    self.signal_callback_replaced_restart_block = false;
                    self.signal_callback_guest_restart_block = false;
                    self.in_held_signal_callback = false;
                    self.unreported_stop_signal = None;
                    self.reported_requeued_signals.clear();
                    self.stale_private_step_trap = false;
                    self.pending_syscall = None;
                    self.pending_syscall_already_skipped = false;
                    self.cancel_handler.store(false, Ordering::Release);
                    stop.frozen.store(false, Ordering::Release);
                    self.arm_liteinst_root_stop(&stopped, &Event::Exec(former));
                    exit_event = self.ptracer_waits.exit_stopped(&stopped);
                    start = OrdinaryStart::Exec(stopped, former);
                }
            }
        }
    }

    /// Retires the task a nonleader owner handed to the leader owner after
    /// exec's de_thread released its former TID: its thread became the
    /// leader and died before its exec stop, so no Exec edge transferred it.
    /// The leader owner calls this after its child-thread joins and after
    /// swapping Tool thread states with this task, so this task carries the
    /// replaced leader's state. That state gets its one on_exit_thread here,
    /// under the leader TID, with `replaced`: the replaced leader's own
    /// exit-stop status, the stop the leader owner's ExitFuture claimed.
    /// This is the swap `retire_replaced_leader` makes for an Exec edge. The
    /// exec thread's state gets its hook from the leader owner, under the
    /// leader TID with the final status, before `on_exit_process`. If that
    /// exit stop's status was never read, there is no status to report: the
    /// session fails and the replaced leader's state gets no hook. This task
    /// otherwise releases only its own timer and thread accounting.
    async fn retire_lost_former(mut self, leader: Pid, replaced: crate::tracer::EntryExitStop) {
        let session = self.fatal_session();
        let former = self.tid();
        let pid = self.pid();
        #[cfg(test)]
        crate::tracer::record_fatal_phase_for_test(|| format!("lost former retired: tid={former}"));
        if let Err(error) = self.timer.cancel() {
            session.fail_at(
                BackendFailure {
                    pid,
                    tid: former,
                    phase: "ptrace lost former timer cancellation",
                },
                error.into(),
            );
        }
        for (phase, error) in self.timer.close_after_failure() {
            session.fail_at(
                BackendFailure {
                    pid,
                    tid: former,
                    phase,
                },
                error.into(),
            );
        }
        match replaced {
            crate::tracer::EntryExitStop::Read(status) => {
                let wrapped = WrappedFrom(leader, &self.global_state);
                if let Err(error) = self
                    .process_state
                    .on_exit_thread(leader, &wrapped, self.thread_state, status)
                    .await
                {
                    session.fail_at(
                        BackendFailure {
                            pid,
                            tid: leader,
                            phase: "ptrace lost former replaced leader on_exit_thread",
                        },
                        error,
                    );
                }
            }
            entry => session.fail_at(
                BackendFailure {
                    pid,
                    tid: leader,
                    phase: "ptrace lost former replaced leader exit status",
                },
                anyhow::Error::new(ReplacedLeaderStatusUnavailable {
                    leader,
                    former,
                    entry,
                })
                .into(),
            ),
        }
        self.child_threads
            .lock()
            .await
            .retain(|child| child.id() != former);
        self.ntasks.fetch_sub(1, Ordering::SeqCst);
        if self.is_a_daemon {
            self.ndaemons.fetch_sub(1, Ordering::SeqCst);
        }
    }

    async fn retire_replaced_leader(mut self, leader: Pid, status: ExitStatus) {
        let session = self.fatal_session();
        let former = self.tid();
        let pid = self.pid();
        if let Err(error) = self.timer.cancel() {
            session.fail_at(
                BackendFailure {
                    pid,
                    tid: leader,
                    phase: "ptrace replaced leader timer cancellation",
                },
                error.into(),
            );
        }
        for (phase, error) in self.timer.close_after_failure() {
            session.fail_at(
                BackendFailure {
                    pid,
                    tid: leader,
                    phase,
                },
                error.into(),
            );
        }
        let wrapped = WrappedFrom(leader, &self.global_state);
        if let Err(error) = self
            .process_state
            .on_exit_thread(leader, &wrapped, self.thread_state, status)
            .await
        {
            session.fail_at(
                BackendFailure {
                    pid,
                    tid: leader,
                    phase: "ptrace replaced leader on_exit_thread",
                },
                error,
            );
        }
        // The process and surviving thread have not exited. Only the old
        // leader's actual Exit-event state is consumed here.
        self.child_threads
            .lock()
            .await
            .retain(|child| child.id() != former);
        self.ntasks.fetch_sub(1, Ordering::SeqCst);
        if self.is_a_daemon {
            self.ndaemons.fetch_sub(1, Ordering::SeqCst);
        }
        if let Some(stats) = &self.global_state.backend_stats {
            stats.record_tracee_exit();
        }
    }

    async fn drive_ordinary(
        &mut self,
        start: OrdinaryStart,
        exit_event: &mut futures::future::BoxFuture<'static, Result<Stopped, TraceError>>,
        stop: &Arc<FatalTaskStop>,
        session: &Arc<FatalSession>,
        lost_former: Option<&OrdinaryExecSlot<L>>,
    ) -> crate::tracer::OrdinaryTerminal {
        let global = self.global_state.gs_ref.clone();
        #[cfg(test)]
        let exit_deferred = !self.is_main_thread()
            && NONLEADER_RUN_LOOP_OBSERVES_ECHILD_FIRST.with(std::cell::Cell::get);
        let outcome = {
            let run_loop = self.ordinary_start(start).fuse();
            // Both watchers complete at most once per run and wake this task
            // when they do, so poll them only after their own wakers fired.
            let cancelled = PollOnWake::new(Box::pin(session.cancelled())).fuse();
            let global_failure = PollOnWake::new(global.wait_for_backend_failure()).fuse();
            futures::pin_mut!(run_loop, cancelled, global_failure);
            let exit = async {
                #[cfg(test)]
                if exit_deferred {
                    return future::pending().await;
                }
                (&mut *exit_event).await
            }
            .fuse();
            futures::pin_mut!(exit);
            futures::select_biased! {
                () = cancelled => None,
                () = global_failure => {
                    if !session.is_failed() {
                        session.fail(anyhow::anyhow!("GlobalTool reported a failed ptrace run").into());
                    }
                    None
                },
                task = exit => Some(Either::Left(task)),
                result = run_loop => Some(Either::Right(result)),
            }
        };
        drop(global);
        match outcome {
            Some(Either::Right(Ok(status))) => {
                // The run loop consumed the final status itself; this path
                // claimed no exit stop.
                crate::tracer::OrdinaryTerminal::Exited(
                    status,
                    session.ordinary_receipt(),
                    crate::tracer::EntryExitStop::NotHeld,
                )
            }
            Some(Either::Left(mut stopped)) => {
                while let Err(TraceError::Errno(error)) = stopped {
                    if stop
                        .terminal
                        .observed_exit_status()
                        .ok()
                        .flatten()
                        .is_some()
                    {
                        break;
                    }
                    if error == Errno::ECHILD && !self.is_main_thread() {
                        // A former TID can lose its pidfd wait during exec. It
                        // has no terminal status to consume. The outer owner
                        // remains available for the leader's actual Exec edge;
                        // ECHILD itself authorizes neither transfer nor exit.
                        //
                        // If the notifier recorded that ECHILD for this exact
                        // generation, de_thread released the TID, and a fatal
                        // signal can land before that thread's exec stop, so no
                        // Exec edge need follow, in a run that has not failed
                        // too. Record it as on the failure path below; the
                        // owner's lost-former arm then hands this task to the
                        // leader owner only once that owner has consumed its
                        // actual final status and left the registry.
                        if let Some(slot) = lost_former
                            && stop.terminal.observed_exit_status() == Err(Errno::ECHILD)
                        {
                            slot.lost_former.store(true, Ordering::Release);
                            slot.changed.notify_waiters();
                        }
                        return future::pending().await;
                    }
                    session.retry_after(error.into()).await;
                    stopped = (&mut *exit_event).await;
                }
                stop.frozen.store(true, Ordering::Release);
                session.changed.notify_waiters();
                crate::tracer::finish_ordinary_exit(stopped, stop, session).await
            }
            failure => {
                if let Some(Either::Right(Err(error))) = failure {
                    self.publish_ordinary_failure("ptrace task callback", error);
                } else if let Err(error) = self.timer.cancel() {
                    session.fail_at(
                        BackendFailure {
                            pid: self.pid(),
                            tid: self.tid(),
                            phase: "ptrace timer cancellation",
                        },
                        error.into(),
                    );
                }
                session.freeze_and_kill(stop).await;
                let stopped = loop {
                    match (&mut *exit_event).await {
                        Ok(stopped) => break Ok(stopped),
                        Err(TraceError::Died(zombie)) => break Err(TraceError::Died(zombie)),
                        // As on the exit-future path above: once the notifier
                        // has published this generation's actual final wait
                        // status (for example a SIGKILLed tracee that exited
                        // without an exit stop, so the exit wait meets ECHILD),
                        // finish_ordinary_exit reports exactly that status.
                        // An error without a published final status still
                        // refuses cleanup.
                        Err(error)
                            if stop
                                .terminal
                                .observed_exit_status()
                                .ok()
                                .flatten()
                                .is_some() =>
                        {
                            break Err(error);
                        }
                        // The notifier recorded ECHILD for this nonleader's
                        // exact generation with no final status: exec's
                        // de_thread released the former TID, and the thread
                        // now runs as the leader. This failed run's group
                        // SIGKILL can land before that thread's exec stop, so
                        // no Exec edge need follow. Record it and stay
                        // pending: an Exec request still transfers this task
                        // first, and otherwise the owner's lost-former arm
                        // hands it to the leader owner once that owner has
                        // consumed its actual final status. ECHILD itself
                        // authorizes neither.
                        Err(TraceError::Errno(Errno::ECHILD))
                            if lost_former.is_some()
                                && stop.terminal.observed_exit_status() == Err(Errno::ECHILD) =>
                        {
                            let slot = lost_former.unwrap();
                            slot.lost_former.store(true, Ordering::Release);
                            slot.changed.notify_waiters();
                            return future::pending().await;
                        }
                        Err(error) => session.retry_after(anyhow::Error::new(error).into()).await,
                    }
                };
                crate::tracer::finish_ordinary_exit(stopped, stop, session).await
            }
        }
    }

    async fn tool_exit_ordinary(
        mut self,
        status: ExitStatus,
        slot: &OrdinaryExecSlot<L>,
        entry_exit_stop: crate::tracer::EntryExitStop,
    ) {
        let session = self.fatal_session();
        let pid = self.pid();
        let tid = self.tid();
        let main = self.is_main_thread();
        if main {
            let children = self.child_threads.lock().await.take_inner();
            for result in future::join_all(children).await {
                if let Err(error) = result {
                    session.fail_at(
                        BackendFailure {
                            pid,
                            tid,
                            phase: "ptrace thread join",
                        },
                        error,
                    );
                }
            }
            let (orphans, _) = {
                let mut children = self.child_procs.lock().await;
                children.deref_mut().await
            };
            for orphan in orphans.into_inner() {
                if let Err(error) = self.orphanage.send(orphan).await
                    && let Err(error) = error.0.await
                {
                    session.fail(error);
                }
            }
            // The join above waited for every child-thread owner, including
            // a nonleader owner whose former TID exec's de_thread released:
            // that owner handed its task to this slot before completing. Its
            // thread took this TID and died before its exec stop, so `status`
            // is that thread's, while the exit stop this owner's ExitFuture
            // claimed was the replaced leader's own. Swap only the Tool
            // thread states, as the Exec arm does: the replaced leader's state
            // is reported first, with that exit stop's status, and the exec
            // thread's state below, with `status`, before on_exit_process.
            // Timers and daemon accounting stay with their own owners, since
            // no thread survives to carry either.
            let lost_former = slot.lost_former_task.lock().unwrap().take();
            if let Some(mut former) = lost_former {
                std::mem::swap(&mut self.thread_state, &mut former.thread_state);
                former.retire_lost_former(tid, entry_exit_stop).await;
            }
        }
        let reason = if main {
            StopReason::Exited(pid, status)
        } else {
            StopReason::ThreadExited(tid, pid, status)
        };
        let _ = self.notify_gdb_stop(reason).await;
        let wrapped = WrappedFrom(tid, &self.global_state);
        if let Err(error) = self
            .process_state
            .on_exit_thread(tid, &wrapped, self.thread_state, status)
            .await
        {
            session.fail_at(
                BackendFailure {
                    pid,
                    tid,
                    phase: "ptrace on_exit_thread",
                },
                error,
            );
        }
        if main {
            let mut process = self.process_state;
            let process = loop {
                match Arc::try_unwrap(process) {
                    Ok(process) => break process,
                    Err(retained) => {
                        process = retained;
                        session
                            .retry_after(
                                anyhow::anyhow!("process Tool still has owners after child joins")
                                    .into(),
                            )
                            .await;
                    }
                }
            };
            if let Err(error) = process.on_exit_process(tid, &wrapped, status).await {
                session.fail_at(
                    BackendFailure {
                        pid,
                        tid,
                        phase: "ptrace on_exit_process",
                    },
                    error,
                );
            }
        } else {
            // The session still owns the actual JoinHandle. Removing this
            // completion subscription cannot detach a pending consuming hook.
            self.child_threads
                .lock()
                .await
                .retain(|child| child.id() != tid);
        }
        if session.is_failed() {
            if let Err(error) = self.timer.cancel() {
                session.fail_at(
                    BackendFailure {
                        pid,
                        tid,
                        phase: "ptrace timer cancellation",
                    },
                    error.into(),
                );
            }
            for (phase, error) in self.timer.close_after_failure() {
                session.fail_at(BackendFailure { pid, tid, phase }, error.into());
            }
        }
        let remaining = self.ntasks.fetch_sub(1, Ordering::SeqCst);
        let daemons = self.ndaemons.load(Ordering::SeqCst);
        if self.is_a_daemon {
            self.ndaemons.fetch_sub(1, Ordering::SeqCst);
        }
        if main && remaining == 1 + daemons {
            let _ = self.daemon_kill_switch.send(());
        }
    }

    /// Drive a single guest thread to completion. Returns the final exit code
    /// when that guest thread exits.
    pub async fn run(mut self, child: Stopped) -> Result<ExitStatus, reverie::Error> {
        if self.ordinary_failure_enabled() {
            return self.run_ordinary(child).await;
        }
        // Only the session root owns the shared root-stop lease; a child task
        // that superseded it would strand the root's cleanup handoff.
        let exit_held_root_stop = self
            .liteinst_root_config()
            .map(|runtime| Arc::clone(&runtime.held_root_stop));
        let root_session_failure = self.liteinst_root_config().map(|runtime| {
            (
                Arc::clone(&runtime.session_failure),
                Arc::clone(&runtime.session_failure_changed),
            )
        });
        let exit_waits = self.ptracer_waits.clone();
        let completion = {
            let exit_event = self.ptracer_waits.exit_stopped(&child).fuse();
            let run_loop = self.run_loop(child).fuse();
            let session_failure = async move {
                let Some((failure, changed)) = root_session_failure else {
                    return future::pending::<String>().await;
                };
                loop {
                    let notified = changed.notified();
                    if let Some(message) = failure.lock().unwrap().clone() {
                        return message;
                    }
                    notified.await;
                }
            }
            .fuse();
            futures::pin_mut!(exit_event, run_loop, session_failure);

            futures::select_biased! {
                task = exit_event => match task {
                    Ok(task) => Either::Left(Self::wait_after_exit_event(task, &exit_waits, exit_held_root_stop).await),
                    Err(err) => Either::Left(Err(err)),
                },
                message = session_failure => Either::Right(Err(anyhow::anyhow!(
                    "LiteInst session failed closed in a non-root task: {message}"
                ).into())),
                exit_status = run_loop => Either::Right(exit_status),
            }
        };
        // Drop the old run-loop future before mutating its owner. The stopped
        // event carries the existing notifier generation; re-arm that exact
        // stop before publishing failure so session cleanup can consume it.
        let outcome = match completion {
            Either::Left(Ok(wait @ Wait::Stopped(_, Event::Exec(former_tid))))
                if self.global_state.liteinst_runtime.is_some() && former_tid != self.tid() =>
            {
                self.arm_liteinst_wait(&wait);
                let (stopped, _) = wait.assume_stopped();
                // SAFETY: this branch owns the continuation of the single
                // ExitFuture-minted Stopped. wait_after_exit_event consumed
                // that capability through resume, and the old run-loop future
                // was dropped above. Retire its claimed exit permission before
                // handing the actual Exec stop to cancellation cleanup.
                match unsafe { stopped.terminal_cleanup().revoke_owned_exit_stop() } {
                    Ok(()) => {
                        let error = self.reject_liteinst_nonleader_exec(former_tid);
                        handle_internal_error(error.into(), &self.ptracer_waits).await
                    }
                    Err(error) => Err(error.into()),
                }
            }
            Either::Left(Ok(wait)) => Ok(wait.assume_exited().1),
            Either::Left(Err(error)) => {
                handle_internal_error(error.into(), &self.ptracer_waits).await
            }
            Either::Right(outcome) => outcome,
        };
        if self.global_state.fatal_session.is_failed() {
            // The legacy session owner will terminate this generation. In
            // particular, a child must not turn cancellation into detach or a
            // fabricated exit status, nor run another ordinary Tool observer.
            return future::pending().await;
        }
        if outcome.is_ok() && self.global_state.liteinst_runtime.is_some() {
            let phase = self.liteinst_runtime.lock().unwrap().phase;
            if phase != LiteinstRuntimePhase::Ready {
                let detail = if phase == LiteinstRuntimePhase::Failed {
                    "tracee terminated after its preload runtime reported that preparation failed"
                        .to_owned()
                } else {
                    format!(
                        "tracee terminated before the required preload handshake completed (phase {phase:?})"
                    )
                };
                self.record_liteinst_failure(
                    LiteinstActivationFailureReason::TerminatedBeforeHandshake,
                    Error::runtime(self.tid(), "verify LiteInst runtime activation", detail),
                );
            }
        }
        let local_failure_reason = self
            .liteinst_failure
            .as_ref()
            .map(LiteinstActivationFailure::reason);
        let (exit_status, failure) = match (outcome, self.liteinst_failure.take()) {
            (_, Some(original)) => (
                None,
                Some(reverie::Error::from(anyhow::Error::new(original))),
            ),
            (Ok(exit_status), None) => (Some(exit_status), None),
            (Err(error), _) => (None, Some(error)),
        };
        if let Some(failure) = failure {
            let vfork_failure =
                local_failure_reason == Some(LiteinstActivationFailureReason::VforkUnsupported);
            if self.global_state.liteinst_runtime.is_some()
                && self.liteinst_root_config().is_none()
                && !vfork_failure
            {
                let tid = self.tid();
                if let Err(error) = self.tool_exit(ExitStatus::Exited(1)).await {
                    tracing::warn!(
                        %tid,
                        %error,
                        "tool exit hook failed while releasing a failed LiteInst task"
                    );
                }
            }
            // A vfork parent returns directly to the session-level cleanup
            // guard because orderly per-task exit cannot advance while the
            // kernel has it frozen behind that child. Other non-root failures
            // complete the existing tool-exit bookkeeping. The root failure
            // notification allows cleanup to proceed independently if that
            // bookkeeping blocks on a tracee which has not exited yet.
            return Err(failure);
        }
        let exit_status = exit_status.expect("a task without a failure has an exit status");
        let root_session_failure = self.liteinst_root_config().and_then(|_| {
            self.global_state.liteinst_runtime.as_ref().map(|runtime| {
                (
                    Arc::clone(&runtime.session_failure),
                    Arc::clone(&runtime.session_failure_changed),
                )
            })
        });

        // A fail-closed refusal raised by a non-root task cannot reach the
        // root's cleanup guard, and that task's tracee was released so the rest
        // of the guest could finish. Refuse to report success over it.
        if let Some(message) = root_session_failure
            .as_ref()
            .and_then(|(slot, _)| slot.lock().unwrap().clone())
        {
            return Err(anyhow::anyhow!(
                "LiteInst session failed closed in a non-root task: {message}"
            )
            .into());
        }

        if let Some(stats) = &self.global_state.backend_stats {
            stats.record_tracee_exit();
        }
        // Whether the run loop returned or the exit stop cut it short, the
        // thread has ended its timer event.
        self.timer.settle_at_exit();
        log_guest_exit(self.tid(), self.pid(), exit_status);

        let tool_exit = self.tool_exit(exit_status).fuse();
        if let Some((failure, changed)) = root_session_failure.as_ref() {
            let session_failure = async {
                loop {
                    let notified = changed.notified();
                    if let Some(message) = failure.lock().unwrap().clone() {
                        return message;
                    }
                    notified.await;
                }
            }
            .fuse();
            futures::pin_mut!(tool_exit, session_failure);
            futures::select_biased! {
                message = session_failure => return Err(anyhow::anyhow!(
                    "LiteInst session failed closed in a non-root task: {message}"
                ).into()),
                result = tool_exit => result?,
            }
        } else {
            tool_exit.await?;
        }

        // A child can fail while the root is joining it in `tool_exit`, after
        // the fast-path check above.  The join is the final ordering boundary:
        // re-read the shared slot before allowing the root's success to escape.
        if let Some(message) = root_session_failure
            .as_ref()
            .and_then(|(slot, _)| slot.lock().unwrap().clone())
        {
            return Err(anyhow::anyhow!(
                "LiteInst session failed closed in a non-root task: {message}"
            )
            .into());
        }

        Ok(exit_status)
    }

    /// Skip the syscall which is about to happen in the tracee, switching the tracee
    /// from Seccomp() state to Stopped(SIGTRAP) state.
    ///
    /// This uses the convention that setting the syscall number to -1 causes the
    /// kernel to skip it. This function takes as argument the current register state
    /// and restores it after stepping over the skipped syscall instruction.
    ///
    /// Preconditions:
    ///  Ptrace tracee is in a (seccomp) stopped state.
    ///  The tracee was stopped with the RIP pointing just after a syscall instruction (+2).
    ///
    /// Postconditions:
    ///  Set tracee state to Stopped/SIGTRP.
    ///  Restore the registers to the state specified by the regs arg.
    async fn skip_seccomp_syscall(&mut self, task: Stopped) -> Result<Stopped, TraceError> {
        // Skipping consumes a patched site's live syscall (orig_rax = -1).
        let _ = self.trap_only_take_live_entry();
        // So here we are, at ptrace seccomp stop, if we simply resume, the kernel
        // would do the syscall, without our patch. we change to syscall number to
        // -1, so that kernel would simply skip the syscall, so that we can jump to
        // our patched syscall on the first run. Please note after calling this
        // function, the task state will no longer be in ptrace event seccomp.
        let regs = task.getregs()?;
        let pre_rip = regs.ip();

        #[cfg(target_arch = "x86_64")]
        {
            let mut new_regs = regs;
            *new_regs.orig_syscall_mut() = -1i64 as u64;
            task.setregs(&new_regs)?;
        }

        #[cfg(target_arch = "aarch64")]
        task.set_syscall(-1)?;

        let mut running = self.step_stopped(task, None)?;

        // After the step, wait for the next transition. Note that this can return
        // an exited state if there is a group exit while some thread is blocked on
        // a syscall.
        loop {
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            match wait {
                Wait::Stopped(task, Event::Signal(Signal::SIGTRAP)) => {
                    #[cfg(test)]
                    let forced_external_sigtrap = self.liteinst_runtime.lock().unwrap().phase
                        == LiteinstRuntimePhase::Waiting
                        && self
                            .global_state
                            .liteinst_runtime
                            .as_ref()
                            .and_then(|runtime| runtime.force_skip_signal_once.as_ref())
                            .is_some_and(|force_once| force_once.swap(false, Ordering::SeqCst));
                    #[cfg(not(test))]
                    let forced_external_sigtrap = false;
                    self.validate_nested_liteinst_activation_signal(
                        &task,
                        Signal::SIGTRAP,
                        LiteinstActivationOperation::SkipInterceptedSyscall,
                        NestedTrapExpectation::SyscallSkip { pre_rip },
                        forced_external_sigtrap,
                    )?;
                    #[cfg(target_arch = "x86_64")]
                    task.setregs(&regs)?;
                    break Ok(task);
                }
                Wait::Stopped(task, Event::Signal(sig)) => {
                    self.validate_nested_liteinst_activation_signal(
                        &task,
                        sig,
                        LiteinstActivationOperation::SkipInterceptedSyscall,
                        NestedTrapExpectation::SyscallSkip { pre_rip },
                        false,
                    )?;
                    // We can get a spurious signal here, such as SIGWINCH. Skip
                    // past them until the tracee eventually arrives at SIGTRAP.
                    running = self.step_stopped(task, sig)?;
                }
                Wait::Stopped(task, event) => {
                    panic!(
                        "skip_seccomp_syscall: PID {} got unexpected event: {:?}",
                        task.pid(),
                        event
                    );
                }
                Wait::Exited(_pid, exit_status) => {
                    #[allow(unreachable_code)]
                    break self.exit(exit_status).await;
                }
            }
        }
    }

    /// inject syscall for given tracee
    ///
    /// NB: limitations:
    /// - tracee must be in stopped state.
    /// - the tracee must have returned from PTRACE_EXEC_EVENT
    /// - must be called on the ptracer thread
    ///
    /// Side effects:
    /// - mutates contexts
    async fn untraced_syscall(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        self.untraced_syscall_with(task, nr, args, false).await
    }

    /// `untraced_syscall`; `original` marks a LiteInst frame-mode injection of
    /// the event's own pending syscall, which a signal must not stop from
    /// running (`requeue_signals_before_original_syscall`). Neither may a
    /// signal stop an injection of a callback that reports a held signal
    /// (`in_held_signal_callback`): its resume does not deliver a signal
    /// held for it.
    async fn untraced_syscall_with(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
        original: bool,
    ) -> Result<Result<i64, Errno>, TraceError> {
        self.validate_liteinst_mapping_execution(nr, args)?;
        self.timer.expire_overflow_records(&task);
        tracing::trace!(
            "[scheduler/tool] (pid = {}) untraced syscall: {:?}",
            task.pid(),
            nr
        );
        // TODO-HUMAN-REVIEW(PR-103): Review original-frame syscall injection.
        let oldregs = task.getregs()?;
        let mut regs = if self.injected_syscall_frame.is_some() {
            self.read_guest_registers(&task)?
        } else {
            oldregs
        };

        *regs.syscall_mut() = nr as Reg;
        *regs.orig_syscall_mut() = nr as Reg;
        regs.set_args((
            args.arg0 as Reg,
            args.arg1 as Reg,
            args.arg2 as Reg,
            args.arg3 as Reg,
            args.arg4 as Reg,
            args.arg5 as Reg,
        ));
        let child_context = self.injected_syscall_frame.is_some().then_some(regs);

        // Jump to our private page to run the syscall instruction there. See
        // `mmap_page_contents` for details.
        *regs.ip_mut() = cp::PRIVATE_PAGE_OFFSET as Reg;

        task.setregs(&regs)?;

        // Step to run the syscall instruction.
        let (mut wait, mut seccomp_trapped) = self
            .step_private_syscall_discarding_late_timer(task, nr)
            .await?;
        // A SIGTRAP the guest or another process sent can stop the step
        // before the `syscall` ran; a stale step SIGTRAP was discarded there
        // already (`step_private_syscall`). `status_to_result` would take it
        // for the step's report, and the injection would return its own
        // syscall number. It is discarded instead, as the main loop discards
        // an unclaimed SIGTRAP (`handle_sigtrap`), and the step runs the
        // syscall. A held signal is not reported while the trap could be
        // claimed (`sigtrap_may_be_claimed`). A LiteInst frame-mode injection
        // holds the trap for the resume instead (`status_to_result`), and
        // during LiteInst activation the trap is rejected there. Under a
        // tracer filter the trap is not discarded, as on main: the retried
        // step can stop again at requests that filter may refuse or kill the
        // tracer at (`thread_may_be_seccomp_filtered`).
        while child_context.is_none()
            && !self.liteinst_activation_in_progress()
            && is_sigtrap_before_private_syscall(&wait)?
            && !thread_may_be_seccomp_filtered()
        {
            let Wait::Stopped(stopped, _) = wait else {
                unreachable!("a SIGTRAP stop");
            };
            tracing::debug!(
                "[scheduler/tool] (pid = {}) discarding a SIGTRAP that stopped injected {} before it ran",
                stopped.pid(),
                nr
            );
            (wait, seccomp_trapped) = self
                .step_private_syscall_discarding_late_timer(stopped, nr)
                .await?;
        }
        if (original && child_context.is_some()) || self.in_held_signal_callback {
            (wait, seccomp_trapped) = self
                .requeue_signals_before_original_syscall(wait, seccomp_trapped, nr)
                .await?;
        }

        // Get the result of the syscall to return to the caller.
        let result = self
            .status_to_result(wait, Some(oldregs), child_context)
            .await?;
        // A guest seccomp filter's `SECCOMP_RET_TRAP` skipped the syscall and
        // left its number in RAX. Report that it did not run; the guest's
        // SIGSYS handler still runs, and seccomp(2) leaves the register it
        // finds architecture-dependent.
        let result = if seccomp_trapped {
            Err(Errno::ENOSYS)
        } else {
            result
        };
        self.observe_liteinst_mapping_result(nr, args, result);
        Ok(result)
    }

    /// Runs `step_private_syscall`, discarding the timer's own late overflow
    /// notifications that stop the step before the `syscall` executes.
    async fn step_private_syscall_discarding_late_timer(
        &mut self,
        task: Stopped,
        nr: Sysno,
    ) -> Result<(Wait, bool), TraceError> {
        let (mut wait, mut seccomp_trapped) = self.step_private_syscall(task, nr).await?;

        // A late overflow notification of the timer can be pending when the
        // step starts. Its delivery stop precedes the syscall instruction. No
        // guest branch runs during an injection, so the overflow predates the
        // current stop. If that stop ended the event it belongs to, the
        // notification has nothing to deliver: discard it and step again.
        // If the stop was disregarded, so that no stop has decided the event
        // (see `Timer::take_overflow_signal`), the notification is the
        // event's own: take it, for the caller to deliver the event when the
        // syscall returns (`Timer::take_notification`), and step again.
        //
        // A guest signal can carry the same signal number, code, and file
        // descriptor number, so a match also requires a kernel record of an
        // overflow whose notification has not been consumed. At each stop and
        // before each injection, the records expire unless such a
        // notification is pending for the thread. This still leaves these
        // cases:
        //
        // - A guest signal with the same siginfo that is pending when the
        //   injection starts is discarded while a record is unconsumed and
        //   its notification
        //   - is pending too, since the kernel keeps one instance of a
        //     standard signal;
        //   - left the queue after the last check, for example because
        //     another guest thread flushed it;
        //   - never had a queue entry of its own, because it coalesced into
        //     a pending guest signal of the same number with other siginfo,
        //     such as one sent by `tgkill`. That signal does not consume the
        //     record.
        // - A late notification reaches the guest when no record backs it or
        //   its records expired early:
        //   - the kernel also notifies when a non-sample record, such as a
        //     throttling record, crosses the buffer's wakeup watermark, and
        //     when a full buffer loses the sample;
        //   - another guest thread removed an earlier queue entry while the
        //     queue was being read, so the read skipped the notification;
        //   - the queue was read after the kernel wrote the record but before
        //     it queued the notification, which follows from an irq_work;
        //   - the timer's records could not be mapped, or the kernel is or
        //     may be PREEMPT_RT, where a notification can follow its record,
        //     so records are not used.
        while let Wait::Stopped(stopped, Event::Signal(sig)) = &wait
            && *sig == Timer::signal_type()
            && stopped.getregs()?.ip() as usize == cp::PRIVATE_PAGE_OFFSET
            && let Some(notification) = self.take_own_timer_notification(stopped)?
        {
            self.validate_nested_liteinst_activation_signal(
                stopped,
                *sig,
                LiteinstActivationOperation::FinishInjectedSyscall,
                NestedTrapExpectation::PrivateSyscall(
                    (cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE) as u64,
                ),
                false,
            )?;
            match notification {
                OwnNotification::Live => {
                    tracing::debug!(
                        "[{}] taking the timer event's overflow signal before an injected syscall",
                        stopped.pid()
                    );
                    LIVE_TIMER_SIGNALS_TAKEN.fetch_add(1, Ordering::Relaxed);
                }
                OwnNotification::Late => {
                    tracing::debug!(
                        "[{}] discarding a late timer overflow signal before an injected syscall",
                        stopped.pid()
                    );
                    LATE_TIMER_SIGNALS_DISCARDED.fetch_add(1, Ordering::Relaxed);
                }
            }
            let Wait::Stopped(stopped, _) = wait else {
                unreachable!("the loop condition matched a stopped task")
            };
            // The step again needs every case `step_private_syscall` handles:
            // a group stop, a signal delivered after the `syscall` completed,
            // a seccomp trap. The discarded stop preceded the `syscall`, so
            // the finished step requeued nothing, saw no seccomp trap, and
            // collected any stale step SIGTRAP, which Linux dequeues ahead of
            // this notification. A new step therefore starts from the same
            // state. During LiteInst activation the validation above rejects
            // the notification, so this is reached only outside activation.
            //
            // The notification is never seen after the `syscall`: the step
            // SIGTRAP queued at syscall exit is a synchronous signal, which
            // Linux dequeues first, so a notification sent during the syscall
            // stays queued past this step and reaches the timer's own
            // handling at the next run-loop stop. It is therefore never
            // requeued or held in `pending_signal` here.
            (wait, seccomp_trapped) = self.step_private_syscall(stopped, nr).await?;
        }
        Ok((wait, seccomp_trapped))
    }

    /// Single-steps the private-page `syscall` and waits for the stop that
    /// reports its outcome. Also returns whether a seccomp filter the guest
    /// installed trapped the syscall (`SECCOMP_RET_TRAP`), in which case the
    /// kernel did not execute it and RAX holds the syscall number that
    /// `syscall_rollback` restored rather than a result; the SIGSYS it raised
    /// (`si_code` `SYS_SECCOMP`, `si_call_addr` just past the private
    /// `syscall`) is handled like any other signal below.
    ///
    /// Three kinds of stop can precede that outcome without describing it:
    ///
    /// - A job-control group stop. Under `PTRACE_TRACEME` it is reported as a
    ///   bare stop signal, distinguishable from a signal-delivery stop only
    ///   because `PTRACE_GETSIGINFO` fails with `EINVAL`. A restarted ptraced
    ///   tracee does not honor a group stop, so the step is simply resumed:
    ///   before the `syscall` this executes it; after it, the kernel next
    ///   dequeues the step SIGTRAP that syscall exit already queued. Linux
    ///   checks for a pending group stop before dequeuing any signal, so this
    ///   stop can arrive after the syscall completed. As in the main loop
    ///   (`handle_signal`), it is not reported to `Tool::handle_signal_event`:
    ///   honoring it is impossible either way.
    /// - A stale step SIGTRAP before the `syscall` executed: the single-step
    ///   report of an earlier injection whose step ended at a held signal
    ///   (below), recognized by its siginfo (`si_addr` just past the private
    ///   `syscall`, which this step has not reached). It is discarded, as the
    ///   main loop discards it when no further injection follows; read as
    ///   this step's completion it would report a syscall that never ran.
    /// - A genuine signal-delivery stop after the `syscall` completed (RIP past
    ///   the instruction). Linux dequeues a synchronous-class signal (positive
    ///   `si_code`) queued before the step SIGTRAP ahead of it; several such
    ///   signals arrive one stop each. RAX already holds the kernel's result
    ///   (or, after `SECCOMP_RET_TRAP`, the rolled-back syscall number), so
    ///   none of them may turn the syscall into a restart. Each is returned
    ///   to the kernel's queue unchanged: the tracer blocks it and resumes
    ///   with it, and `ptrace_signal` requeues a resumed signal that is now
    ///   blocked, with its original siginfo, behind the step SIGTRAP. Once
    ///   the step SIGTRAP is collected the masks are lifted again. Nothing
    ///   has run in between, so the kernel then delivers the signals in their
    ///   original order at the next resume, each through a signal-delivery
    ///   stop that the main loop reports to `Tool::handle_signal_event`, just
    ///   as it would after the syscall returned in place. No signal is taken
    ///   into `pending_signal`, whose single slot could otherwise be
    ///   overwritten.
    ///
    ///   This does not reproduce native delivery when the same callback
    ///   injects another syscall: natively the handlers would run between
    ///   the two syscalls and the second would succeed, but here the
    ///   requeued signals are still pending before the next injected
    ///   `syscall`, which is then reported as interrupted (the case below).
    ///   With `SA_RESTART` the guest's syscall is restarted and the callback
    ///   runs again, including injections that already completed. This
    ///   limitation predates the requeueing.
    ///
    ///   The signal may already be blocked: `dequeue_synchronous_signal`
    ///   returns the first queued synchronous-class entry without consulting
    ///   the mask whenever any unblocked synchronous signal (the step SIGTRAP
    ///   among them) is pending. Such a signal is resumed without touching
    ///   the mask, so `ptrace_signal` requeues it still blocked, as it does
    ///   for any tracer (which then sees it again whenever the quirk next
    ///   dequeues it); recording it for the final unmask would unblock a
    ///   signal the guest itself blocked. After a mask-swapping syscall the
    ///   temporary mask decides, read through procfs because
    ///   `PTRACE_GETSIGMASK` reports the saved mask while its restore is
    ///   pending.
    ///
    ///   The one exception is an unblocked signal after a syscall that swaps
    ///   in a temporary signal mask (`swaps_signal_mask`): a ptrace mask
    ///   write would discard the saved mask the kernel restores after signal
    ///   handling, so the signal cannot be returned to the queue. Its stop is
    ///   returned as the outcome instead, and `status_to_result` holds the
    ///   signal in `pending_signal` for delivery at the guest's syscall site.
    ///   Stepping stops there, so any further signals and the step SIGTRAP
    ///   stay queued in the kernel with the temporary mask and its pending
    ///   restore intact, and the kernel delivers them after the held signal
    ///   exactly as it would for the syscall run in place.
    ///
    /// The same signal returning to this stop is a protocol violation (a
    /// standard signal is queued at most once, a requeued entry lands behind
    /// the step SIGTRAP, and the step SIGTRAP ends the loop) and fails closed
    /// rather than stepping forever.
    ///
    /// A genuine signal-delivery stop before the `syscall` executed is returned
    /// for `status_to_result` to report as an interrupted syscall. During
    /// LiteInst activation every stop is returned unchanged so the activation
    /// signal validation keeps rejecting it.
    async fn step_private_syscall(
        &mut self,
        task: Stopped,
        nr: Sysno,
    ) -> Result<(Wait, bool), TraceError> {
        let after_syscall = (cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE) as u64;
        // Signals returned to the kernel queue during this step, still blocked
        // by the tracer. Only these bits are lifted at the final stop.
        let mut requeued: u64 = 0;
        // Every signal resumed at a stop after the `syscall`, including those
        // the guest already blocked.
        let mut returned: u64 = 0;
        let mut seccomp_trapped = false;
        let lift_requeued = |stopped: &Stopped, requeued: u64| -> Result<(), TraceError> {
            if requeued != 0 {
                let mask = stopped.getsigmask()?;
                stopped.setsigmask(mask & !requeued)?;
            }
            Ok(())
        };
        let mut running = self.step_stopped(task, None)?;
        loop {
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            let (stopped, sig) = match wait {
                Wait::Stopped(stopped, Event::Signal(sig))
                    if !self.liteinst_activation_in_progress() =>
                {
                    if sig == Signal::SIGTRAP
                        && std::mem::take(&mut self.stale_private_step_trap)
                        && stopped.getregs()?.ip() != after_syscall
                        && is_private_step_trap(&stopped, after_syscall)?
                    {
                        tracing::debug!(
                            "[scheduler/tool] (pid = {}) discarding a stale step SIGTRAP before injected {}",
                            stopped.pid(),
                            nr
                        );
                        running = self.step_stopped(stopped, None)?;
                        continue;
                    }
                    if sig == Signal::SIGTRAP {
                        lift_requeued(&stopped, requeued)?;
                        return Ok((Wait::Stopped(stopped, Event::Signal(sig)), seccomp_trapped));
                    }
                    (stopped, sig)
                }
                Wait::Stopped(stopped, event) => {
                    lift_requeued(&stopped, requeued)?;
                    return Ok((Wait::Stopped(stopped, event), seccomp_trapped));
                }
                wait => return Ok((wait, seccomp_trapped)),
            };
            if is_group_stop(&stopped, sig)? {
                tracing::debug!(
                    "[scheduler/tool] (pid = {}) resuming injected syscall step past {} group stop",
                    stopped.pid(),
                    sig
                );
                running = self.step_stopped(stopped, None)?;
            } else if stopped.getregs()?.ip() == after_syscall {
                let bit = signal_mask_bit(sig);
                if returned & bit != 0 {
                    tracing::error!(
                        "[scheduler/tool] (pid = {}) {} stopped injected {} again after it was returned",
                        stopped.pid(),
                        sig,
                        nr
                    );
                    return Err(Errno::EPROTO.into());
                }
                if sig == Signal::SIGSYS && is_private_seccomp_trap(&stopped, after_syscall)? {
                    tracing::debug!(
                        "[scheduler/tool] (pid = {}) injected {} was trapped by the guest's seccomp filter",
                        stopped.pid(),
                        nr
                    );
                    seccomp_trapped = true;
                }
                // The mask in force, and a mask to write back if not. A
                // mask-swapping syscall's temporary mask is visible only
                // through procfs and must not be written.
                let (blocked, mask) = if swaps_signal_mask(nr) {
                    (blocked_signal_mask(stopped.pid())?, None)
                } else {
                    let mask = stopped.getsigmask()?;
                    (mask, Some(mask))
                };
                if blocked & bit != 0 {
                    tracing::debug!(
                        "[scheduler/tool] (pid = {}) requeueing already-blocked {} delivered after injected {} completed",
                        stopped.pid(),
                        sig,
                        nr
                    );
                    returned |= bit;
                    running = self.step_stopped(stopped, sig)?;
                } else if let Some(mask) = mask {
                    tracing::debug!(
                        "[scheduler/tool] (pid = {}) requeueing {} delivered after injected {} completed",
                        stopped.pid(),
                        sig,
                        nr
                    );
                    stopped.setsigmask(mask | bit)?;
                    requeued |= bit;
                    returned |= bit;
                    running = self.step_stopped(stopped, sig)?;
                } else {
                    tracing::debug!(
                        "[scheduler/tool] (pid = {}) holding {} delivered after injected {} completed; later signals stay queued",
                        stopped.pid(),
                        sig,
                        nr
                    );
                    lift_requeued(&stopped, requeued)?;
                    self.stale_private_step_trap = true;
                    return Ok((Wait::Stopped(stopped, Event::Signal(sig)), seccomp_trapped));
                }
            } else {
                lift_requeued(&stopped, requeued)?;
                return Ok((Wait::Stopped(stopped, Event::Signal(sig)), seccomp_trapped));
            }
        }
    }

    /// Runs a LiteInst frame-mode injection of the event's original syscall
    /// that a signal stopped before its private-page `syscall` instruction,
    /// the way plain ptrace runs the original: once, with the signal pending.
    ///
    /// Plain ptrace resumes the original from its seccomp stop, so the kernel
    /// enters the syscall with the signal still pending and delivers it on the
    /// way back to the guest, as a signal stop the Tool sees. A
    /// non-blocking syscall completes; a blocking one that the signal can
    /// interrupt returns its `-ERESTART*` code or `-EINTR` at once. The
    /// private-page step instead dequeued the signal before the instruction.
    /// This puts it back, in the kernel, and reaches the syscall entry:
    ///
    /// 1. The signal is added to the thread's blocked mask and resumed into
    ///    it with `PTRACE_SYSCALL`; the kernel requeues a blocked signal the
    ///    tracer injects, with its siginfo. Any further signal stop before the
    ///    instruction is requeued the same way; the thread's own late timer
    ///    overflow is discarded, as `step_private_syscall_discarding_late_timer`
    ///    discards it, and a group stop is resumed without a signal, as
    ///    `step_private_syscall` resumes it.
    /// 2. At the syscall-entry stop the original mask is restored, which
    ///    leaves the signals pending and deliverable.
    /// 3. `step_private_syscall` then runs the syscall, which sees them
    ///    pending. It handles what can stop that step after the syscall
    ///    returned exactly as for any injected syscall: a guest seccomp trap
    ///    (whose flag is returned), a synchronous-class signal dequeued ahead
    ///    of the step's report, which is requeued behind it or, after a
    ///    mask-swapping syscall, held; and group stops.
    ///
    /// The signals stay queued in the kernel; nothing is held for the resume
    /// (`pending_signal`) except by step 3, so the next resume delivers them as
    /// a signal stop the Tool handles, and a restart code the syscall returns
    /// is decided by the ordinary rewound-`int3` delivery.
    ///
    /// `SIGSTOP` cannot be blocked, and an external `SIGTRAP` would coalesce
    /// with the step's own report, so a stop with one of them is returned
    /// unchanged. A `SIGSTOP` keeps the generic not-run handling
    /// (`status_to_result`): the injection returns `-ERESTARTSYS` with the
    /// signal held for the resume. A plain injection discards a `SIGTRAP`
    /// stop before its instruction and steps the syscall again
    /// (`untraced_syscall_with`); a LiteInst frame injection keeps the
    /// not-run handling for it, and an injection during LiteInst activation
    /// rejects it with `EPROTO` (`status_to_result`). `SIGKILL` has
    /// no signal stop to return; `requeueable` names it only for
    /// completeness. Signals requeued before it stay pending.
    async fn requeue_signals_before_original_syscall(
        &mut self,
        wait: Wait,
        seccomp_trapped: bool,
        nr: Sysno,
    ) -> Result<(Wait, bool), TraceError> {
        fn requeueable(sig: Signal) -> bool {
            !matches!(sig, Signal::SIGKILL | Signal::SIGSTOP | Signal::SIGTRAP)
        }
        fn before_instruction(stopped: &Stopped) -> Result<bool, TraceError> {
            Ok(stopped.getregs()?.ip() as usize == cp::PRIVATE_PAGE_OFFSET)
        }
        match &wait {
            Wait::Stopped(stopped, Event::Signal(sig))
                if requeueable(*sig)
                    && !self.liteinst_activation_in_progress()
                    && before_instruction(stopped)? => {}
            _ => return Ok((wait, seccomp_trapped)),
        }
        let Wait::Stopped(stopped, _) = &wait else {
            unreachable!("matched a stopped task")
        };
        let original_mask = stopped.getsigmask()?;
        let mut mask = original_mask;
        let mut wait = wait;
        loop {
            match wait {
                Wait::Stopped(stopped, Event::Signal(sig))
                    if requeueable(sig) && before_instruction(&stopped)? =>
                {
                    let deliver = if is_group_stop(&stopped, sig)? {
                        None
                    } else if sig == Timer::signal_type()
                        && self.consume_own_timer_overflow(&stopped)?
                    {
                        LATE_TIMER_SIGNALS_DISCARDED.fetch_add(1, Ordering::Relaxed);
                        None
                    } else {
                        mask |= signal_mask_bit(sig);
                        stopped.setsigmask(mask)?;
                        Some(sig)
                    };
                    wait = self
                        .syscall_stopped(stopped, deliver)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?;
                    self.arm_liteinst_wait(&wait);
                }
                Wait::Stopped(stopped, Event::Syscall) => {
                    stopped.setsigmask(original_mask)?;
                    return self.step_private_syscall(stopped, nr).await;
                }
                other => {
                    if let Wait::Stopped(stopped, _) = &other {
                        stopped.setsigmask(original_mask)?;
                    }
                    return Ok((other, false));
                }
            }
        }
    }

    // Replace an actual, unconverted seccomp entry. The caller must have taken
    // its pending record; this is not valid for a stopped task with no original
    // syscall left to consume (for example, a post-exec callback).
    async fn private_inject(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        let task = self.skip_seccomp_syscall(task).await?;

        self.untraced_syscall(task, nr, args).await
    }

    /// Records the stop an injection ended at in `latest_injection_stop`.
    /// Under a tracer filter a group stop is recorded as its signal
    /// (`is_group_stop_unless_filtered`); no held signal is reported there
    /// (`report_held_signal`), and only a reported one uses the record.
    fn note_injection_stop(&mut self, wait: &Wait) -> Result<(), TraceError> {
        if let Wait::Stopped(stopped, event) = wait {
            self.latest_injection_stop = Some(match event {
                Event::Signal(sig) if !is_group_stop_unless_filtered(stopped, *sig)? => Some(*sig),
                _ => None,
            });
        }
        Ok(())
    }

    /// Holds `sig`, which stopped a private-page step at its signal-delivery
    /// stop `stopped`, in `pending_signal` for delivery when the guest resumes
    /// at its syscall site, and records what it was taken with
    /// (`pending_signal_taken`, see `status_to_result`).
    fn hold_pending_signal(&mut self, stopped: &Stopped, sig: Signal) {
        if let Some(held) = self.pending_signal {
            // TaskGraph reverie_pending_signal_single_slot.
            tracing::warn!(
                "[scheduler/tool] (pid = {}) {} replaces held {} in the single pending-signal slot",
                stopped.pid(),
                sig,
                held
            );
        }
        self.pending_signal = Some(sig);
        self.pending_signal_taken = TakenSignal::at_stop(stopped, sig);
    }

    async fn status_to_result(
        &mut self,
        wait_status: Wait,
        context: Option<libc::user_regs_struct>,
        child_context: Option<libc::user_regs_struct>,
    ) -> Result<Result<i64, Errno>, TraceError> {
        #[cfg(test)]
        let forced_external_sigtrap = matches!(&wait_status, Wait::Stopped(_, _))
            && self.liteinst_runtime.lock().unwrap().phase == LiteinstRuntimePhase::Waiting
            && self
                .global_state
                .liteinst_runtime
                .as_ref()
                .is_some_and(|runtime| {
                    let force_once = if context.is_none() {
                        runtime.force_context_none_signal_once.as_ref()
                    } else {
                        runtime.force_context_signal_once.as_ref()
                    };
                    force_once.is_some_and(|force_once| force_once.swap(false, Ordering::SeqCst))
                });
        #[cfg(not(test))]
        let forced_external_sigtrap = false;
        #[cfg(test)]
        let wait_status = if forced_external_sigtrap {
            match wait_status {
                Wait::Stopped(task, _) => Wait::Stopped(task, Event::Signal(Signal::SIGTRAP)),
                other => other,
            }
        } else {
            wait_status
        };
        #[cfg(test)]
        if context.is_some()
            && self.liteinst_runtime.lock().unwrap().phase == LiteinstRuntimePhase::Waiting
            && let Wait::Stopped(stopped, _) = &wait_status
            && self
                .global_state
                .liteinst_runtime
                .as_ref()
                .and_then(|runtime| runtime.force_private_stub_mutation_once.as_ref())
                .is_some_and(|force_once| force_once.swap(false, Ordering::SeqCst))
        {
            let mut mutated_stub = [0; cp::SYSCALL_INSTR_SIZE * 2];
            stopped.read_exact(cp::PRIVATE_PAGE_OFFSET, &mut mutated_stub)?;
            mutated_stub[0] ^= 0xff;
            let mut stopped_writer = stopped.generation().assume_stopped();
            let address = AddrMut::from_raw(cp::PRIVATE_PAGE_OFFSET).ok_or(Errno::EFAULT)?;
            stopped_writer.write_value(address, &mutated_stub)?;
        }
        self.note_injection_stop(&wait_status)?;
        match wait_status {
            Wait::Stopped(stopped, event) => match event {
                Event::Signal(sig) if context.is_none() => {
                    self.validate_nested_liteinst_activation_signal(
                        &stopped,
                        sig,
                        LiteinstActivationOperation::FinishReinjectedSyscall,
                        NestedTrapExpectation::None,
                        forced_external_sigtrap,
                    )?;
                    let regs = stopped.getregs()?;
                    Ok(Ok(regs.ret() as i64))
                }
                Event::Signal(sig) => {
                    self.validate_nested_liteinst_activation_signal(
                        &stopped,
                        sig,
                        LiteinstActivationOperation::FinishInjectedSyscall,
                        NestedTrapExpectation::PrivateSyscall(
                            (cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE) as u64,
                        ),
                        forced_external_sigtrap,
                    )?;
                    let mut regs = stopped.getregs()?;
                    // NB: it is possible to get interrupted by signal (such as
                    // SIGCHLD) before single step finishes, while RIP still
                    // points at the private page.
                    debug_assert!(
                        regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE
                            || regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET
                    );
                    if child_context.is_some() {
                        // A LiteInst injected frame: the controller is parked
                        // at the runtime int3, so the tracer, not the kernel,
                        // decides restarts (see `untraced_liteinst_syscall`).
                        match classify_private_step(
                            regs.ip(),
                            sig,
                            cp::PRIVATE_PAGE_OFFSET as u64,
                            cp::SYSCALL_INSTR_SIZE as u64,
                        ) {
                            PrivateStep::NotRun => {
                                // Any signal, including an external SIGTRAP,
                                // stopped the step before the syscall ran.
                                *regs.ret_mut() = (-(Errno::ERESTARTSYS.into_raw()) as i64) as u64;
                                self.hold_pending_signal(&stopped, sig);
                            }
                            PrivateStep::Ran => {}
                            PrivateStep::Held => {
                                // The syscall ran; `step_private_syscall` held
                                // a signal it could not requeue after a
                                // mask-swapping syscall. RAX holds the
                                // syscall's outcome and is kept.
                                self.hold_pending_signal(&stopped, sig);
                            }
                            PrivateStep::Unexpected => {
                                self.record_liteinst_failure(
                                    LiteinstActivationFailureReason::SyscallRestartInvariant,
                                    Error::runtime(
                                        self.tid(),
                                        "restart LiteInst host-hybrid syscall",
                                        format!(
                                            "private-page step stopped with {sig} at {:#x}, \
                                             outside the private syscall",
                                            regs.ip()
                                        ),
                                    ),
                                );
                                return Err(Errno::EPROTO.into());
                            }
                        }
                    } else if sig != Signal::SIGTRAP {
                        // Interrupted by a signal before the `syscall`
                        // executed: return -ERESTARTSYS so that the tracee
                        // restarts it once the signal is delivered. Past the
                        // instruction, `step_private_syscall` returns only a
                        // signal it could not requeue after a mask-swapping
                        // syscall. That syscall already ran and RAX holds its
                        // outcome (usually -ERESTARTNOHAND, which the kernel
                        // resolves when the held signal is delivered);
                        // overwriting it would execute the syscall twice.
                        if regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET {
                            *regs.ret_mut() = (-(Errno::ERESTARTSYS.into_raw()) as i64) as u64;
                        }
                        self.hold_pending_signal(&stopped, sig);
                    }
                    let result = Errno::from_ret(regs.ret() as usize).map(|x| x as i64);
                    if let Some(context) = context {
                        if child_context.is_some() {
                            // An injected-frame event temporarily replaces the
                            // controller's live trap registers with the logical
                            // guest frame. Restore every controller register;
                            // leaving even a callee-saved register (notably R12,
                            // used by LiteInst as its HookContext base) would
                            // corrupt the callback that resumes after injection.
                            stopped.setregs(&context)?;
                        } else {
                            // Restore syscall args to original values. This is
                            // needed when we convert syscalls like SYS_open ->
                            // SYS_openat, syscall args are modified need to restore
                            // it back. A held-signal callback's injection keeps
                            // the guest's return register too
                            // (`in_held_signal_callback`). An interrupted
                            // `restart_syscall` resumed the thread's restart
                            // block rather than replacing it.
                            let retval = self.in_held_signal_callback.then(|| context.ret());
                            if retval.is_some() {
                                let injection = stopped.getregs()?;
                                if Errno::from_ret(injection.ret() as usize)
                                    == Err(Errno::ERESTART_RESTARTBLOCK)
                                    && injection.orig_syscall() as i64
                                        != Sysno::restart_syscall.id() as i64
                                {
                                    self.signal_callback_replaced_restart_block = true;
                                }
                            }
                            let retval = retval
                                .and_then(|ret| self.signal_callback_guest_ret(&context, ret));
                            restore_context(&stopped, context, retval, false)?;
                        }
                    }
                    Ok(result)
                }
                Event::NewChild(op, child) => {
                    let ret = child.pid().as_raw() as i64;
                    // A held-signal callback's injection keeps the guest's
                    // return register, as above. The kernel writes the
                    // child's PID after the event stop, so it is restored at
                    // the stop the parent's step ends at.
                    let guest_ret = match context {
                        Some(context) if self.in_held_signal_callback => {
                            self.signal_callback_guest_ret(&context, context.ret())
                        }
                        _ => None,
                    };
                    let wait = self
                        .dispatch_new_task(op, stopped, child, context, child_context)
                        .await?;
                    // A vfork parent's step ends at its PTRACE_EVENT_VFORK_DONE
                    // stop, once the child exits or execs. Linux drops a signal
                    // passed on resume from an event stop, and writes the
                    // child's PID after it. So a signal callback's injection
                    // steps once more, to the step trap the syscall's return
                    // reports: the stop a fork parent's step ends at. No guest
                    // instruction runs in between. Other injections keep the
                    // event stop, which the LiteInst backend's matches. So
                    // does a signal callback's under a tracer filter, as on
                    // main, where the signal is dropped: delivered, its
                    // handler can make requests of the tracer that the filter
                    // may refuse or kill it at
                    // (`thread_may_be_seccomp_filtered`).
                    let wait = match wait {
                        Wait::Stopped(parent, Event::VforkDone)
                            if self.in_signal_callback && !thread_may_be_seccomp_filtered() =>
                        {
                            let wait = self
                                .step_stopped(parent, None)?
                                .next_state_with_owner(&self.ptracer_waits)
                                .await?;
                            self.arm_liteinst_wait(&wait);
                            wait
                        }
                        wait => wait,
                    };
                    // That stop, not the event stop, is the one a resume from
                    // a signal callback leaves (`report_held_signal`).
                    self.note_injection_stop(&wait)?;
                    if let (Some(guest_ret), Wait::Stopped(parent, _)) = (guest_ret, &wait) {
                        let mut regs = parent.getregs()?;
                        *regs.ret_mut() = guest_ret;
                        parent.setregs(&regs)?;
                    }
                    Ok(Ok(ret))
                }
                Event::Exec(former_tid) => {
                    // The callback that injected the exec never resumes, so
                    // the replacement image runs outside it
                    // (`handle_exec_event` ends its state).
                    // This should never return.
                    let next_state = self.handle_exec_event(stopped, former_tid).await?;
                    self.execve(next_state).await
                }
                Event::Syscall => {
                    let regs = stopped.getregs()?;
                    Ok(Errno::from_ret(regs.ret() as usize).map(|x| x as i64))
                }
                st => panic!("untraced_syscall returned unknown state: {:?}", st),
            },
            Wait::Exited(_pid, exit_status) => self.exit(exit_status).await,
        }
    }

    async fn do_inject(&mut self, nr: Sysno, args: SyscallArgs) -> Result<i64, Errno> {
        match self.inner_inject(nr, args).await {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn inner_inject(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        let task = self.assume_stopped();

        tracing::debug!(
            "[tool] (tid {}) beginning inject of syscall: {}, args {:?}",
            self.tid(),
            nr,
            args,
        );

        if self.injected_syscall_frame.is_some() || self.pending_syscall_already_skipped {
            let original = self.injected_syscall_frame.is_some()
                && self.pending_syscall.take() == Some((nr, args));
            self.pending_syscall = None;
            self.untraced_syscall_with(task, nr, args, original).await
        } else {
            match self.pending_syscall.take() {
                Some(original) if original == (nr, args) => {
                    if let Some(view) = self.trap_only_take_live_entry() {
                        // A patched site: the masked hop replaces the
                        // in-place resume of the ia32 stop.
                        return self.trap_only_inject_hop(task, view).await;
                    }
                    // Run the exact pending syscall and stop at its exit.
                    self.validate_liteinst_mapping_execution(nr, args)?;
                    #[cfg(test)]
                    if self.global_state.pre_syscall_for_test.is_some() {
                        let regs = task.getregs()?;
                        self.pre_syscall_for_test(&regs, PreSyscallPoint::Early)
                            .await;
                        self.pre_syscall_for_test(&regs, PreSyscallPoint::Late)
                            .await;
                    }
                    let wait = self
                        .syscall_stopped(task, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?;
                    self.arm_liteinst_wait(&wait);
                    let result = self.status_to_result(wait, None, None).await?;
                    self.observe_liteinst_mapping_result(nr, args, result);
                    Ok(result)
                }
                Some(_) => self.private_inject(task, nr, args).await,
                None => self.untraced_syscall(task, nr, args).await,
            }
        }
    }

    async fn do_tail_inject(&mut self, nr: Sysno, args: SyscallArgs) -> ! {
        match self.inner_tail_inject(nr, args).await {
            Ok(_) => {
                // Drop the handle_syscall_event future.
                self.cancel_handler.store(true, Ordering::SeqCst);
                future::pending().await
            }
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn inner_tail_inject(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        let tid = self.tid();

        tracing::info!(
            "[tool] (tid {}) beginning tail_inject of syscall: {}",
            &tid,
            nr,
        );

        let task = self.assume_stopped();

        if self.injected_syscall_frame.is_some() {
            let original = self.pending_syscall.take() == Some((nr, args));
            let result = self.untraced_syscall_with(task, nr, args, original).await?;
            // `handle_injected_syscall` owns the frame and applies this after
            // the callback is dropped, restarting the trap for a Linux restart
            // code instead of leaking it into the guest frame.
            self.injected_tail_result = Some(result);
            return Ok(result);
        }

        if self.pending_syscall_already_skipped {
            self.pending_syscall = None;
            let result = self.untraced_syscall(task, nr, args).await?;
            let task = self.assume_stopped();
            set_ret(
                &task,
                result.unwrap_or_else(|errno| -(errno.into_raw() as i64)) as u64,
            )?;
            return Ok(result);
        }

        if is_liteinst_mapping_syscall(nr) && self.pending_syscall == Some((nr, args)) {
            self.pending_syscall = None;
            let result = self.private_inject(task, nr, args).await?;
            let task = self.assume_stopped();
            set_ret(
                &task,
                result.unwrap_or_else(|errno| -(errno.into_raw() as i64)) as u64,
            )?;
            return Ok(result);
        }

        match self.pending_syscall.take() {
            Some(original) if original == (nr, args) => {
                // The callback is cancelled next. Its final resume still owns
                // execution of this original syscall; no second skip is due.
                Ok(Ok(0))
            }
            Some(_) => self.private_inject(task, nr, args).await,
            None => self.untraced_syscall(task, nr, args).await,
        }
    }

    /// Awaits the test's pre-syscall hook, if any (see [`PreSyscallForTest`]).
    #[cfg(test)]
    pub(crate) async fn pre_syscall_for_test(
        &self,
        regs: &libc::user_regs_struct,
        point: PreSyscallPoint,
    ) {
        if let Some(hook) = self.global_state.pre_syscall_for_test.clone() {
            hook(self.tid, regs, point).await;
        }
    }

    /// Get a ptrace stub which can do ptrace operations
    // Assumption: Task is in stopped state as long as we have a valid
    // reference to `TracedTask`.
    fn assume_stopped(&self) -> Stopped {
        match &self.preinit_generation {
            Some(generation) if generation.pid() == self.tid() => generation.assume_stopped(),
            _ => self.ptracer_waits.stopped(),
        }
    }

    async fn notify_gdb_stop(&self, reason: StopReason) -> Result<(), TraceError> {
        if !self.attached_by_gdb {
            return Ok(());
        }

        if let Some(stop_tx) = self.gdb_stop_tx.as_ref() {
            let request_tx = self.gdb_request_tx.clone();
            let resume_tx = self.gdb_resume_tx.clone();
            let stop = StoppedInferior {
                reason,
                request_tx: request_tx.ok_or(Errno::EIO)?,
                resume_tx: resume_tx.ok_or(Errno::EIO)?,
            };
            if stop_tx.send(stop).await.is_err() {
                tracing::warn!(
                    tid = %self.tid(),
                    "GDB stop channel closed while reporting tracee stop"
                );
            }
        }
        Ok(())
    }

    async fn handle_gdb_request(&mut self, request: Option<GdbRequest>) {
        if let Some(request) = request {
            match request {
                GdbRequest::SetBreakpoint(bkpt, reply_tx) => {
                    if bkpt.ty == BreakpointType::Software {
                        let result = self.add_breakpoint(bkpt.addr).await;
                        let _ = reply_tx.send(result);
                    }
                }
                GdbRequest::RemoveBreakpoint(bkpt, reply_tx) => {
                    if bkpt.ty == BreakpointType::Software {
                        let result = self.remove_breakpoint(bkpt.addr).await;
                        let _ = reply_tx.send(result);
                    }
                }
                GdbRequest::ReadInferiorMemory(addr, length, reply_tx) => {
                    let result = self.read_inferior_memory(addr, length);
                    let _ = reply_tx.send(result);
                }
                GdbRequest::WriteInferiorMemory(addr, length, data, reply_tx) => {
                    let result = self.write_inferior_memory(addr, length, data);
                    let _ = reply_tx.send(result);
                }
                GdbRequest::ReadRegisters(reply_tx) => {
                    let result = self.read_registers();
                    let _ = reply_tx.send(result);
                }
                GdbRequest::WriteRegisters(core_regs, reply_tx) => {
                    let result = self.write_registers(core_regs);
                    let _ = reply_tx.send(result);
                }
            }
        }
    }

    async fn handle_gdb_resume(
        &mut self,
        resume: Option<ResumeInferior>,
        task: Stopped,
        resume_action: ExpectedGdbResume,
    ) -> Result<(Running, Option<ResumeInferior>), TraceError> {
        match resume {
            None => Ok((self.resume_stopped(task, None)?, None)),
            Some(resume) => {
                let is_resume = resume_action == ExpectedGdbResume::Resume || resume.detach;
                let is_step_only = resume_action == ExpectedGdbResume::StepOnly;
                // During a step-over, gdb normally single-steps over the
                // breakpoint installed at the current PC. But if gdb has already
                // removed that breakpoint it issues a plain continue instead of a
                // single-step. This happens, for example, after `finish`: gdb
                // implements it with a temporary breakpoint at the return address
                // which it deletes as soon as it is hit, so when the user then
                // resumes there is no breakpoint left to step over. No step-over
                // is required in that case, so resume normally rather than
                // treating the continue as an unexpected action (which used to
                // panic here).
                let is_step_over = resume_action == ExpectedGdbResume::StepOver;
                let running = match resume.action {
                    ResumeAction::Step(sig) => self.step_stopped(task, sig)?,
                    ResumeAction::Continue(sig) if is_resume => self.resume_stopped(task, sig)?,
                    ResumeAction::Continue(sig) if is_step_only => self.step_stopped(task, sig)?,
                    ResumeAction::Continue(sig) if is_step_over => {
                        self.resume_stopped(task, sig)?
                    }
                    action => panic!(
                        "[pid = {}] unexpected resume action {:?}, expecting: {:?}",
                        task.pid(),
                        action,
                        resume_action,
                    ),
                };
                Ok((running, Some(resume)))
            }
        }
    }

    async fn await_gdb_resume(
        &mut self,
        task: Stopped,
        resume_action: ExpectedGdbResume,
    ) -> Result<Running, TraceError> {
        if !self.attached_by_gdb {
            return self.resume_stopped(task, None);
        }

        let mut resume_rx = self.gdb_resume_rx.take().ok_or(Errno::EIO)?;
        let mut gdb_request_rx = self.gdb_request_rx.take().ok_or(Errno::EIO)?;

        let mut resume_future = Box::pin(resume_rx.recv());

        let (running, resumed) = loop {
            let request_future = Box::pin(gdb_request_rx.recv());

            match future::select(request_future, resume_future).await {
                Either::Left((gdb_request, pending_resume_future)) => {
                    self.handle_gdb_request(gdb_request).await;
                    resume_future = pending_resume_future;
                }
                Either::Right((resume_request, _)) => {
                    break self
                        .handle_gdb_resume(resume_request, task, resume_action)
                        .await?;
                }
            }
        };

        self.gdb_request_rx = Some(gdb_request_rx);
        self.gdb_resume_rx = Some(resume_rx);

        if let Some(resumed) = resumed {
            if resumed.detach {
                tracing::debug!(
                    target: "reverie_ptrace::lifecycle",
                    parent: &tracing::debug_span!(
                        target: "reverie_ptrace::lifecycle",
                        "tracee.detach",
                        tid = %self.tid(),
                        reason = "GDB detach"
                    ),
                    "GDB detached from tracee"
                );
                // no longer report stop event to gdb
                // self.gdb_stop_tx = None;
                self.attached_by_gdb = false;
            }

            self.resumed_by_gdb = Some(resumed.action);
        }

        Ok(running)
    }

    /// Resume from a software breakpoint set by gdb. The resume action is
    /// initiated from gdb (client).
    // NB: caller to %rip accordingly prior to hitting breakpoint.
    async fn resume_from_swbreak(
        &mut self,
        task: Stopped,
        regs: libc::user_regs_struct,
    ) -> Result<Wait, TraceError> {
        task.setregs(&regs)?;

        // Task could be hitting a breakpoint, after previously suspended by
        // a different task, need to notify this task is fully stopped.
        self.suspended.store(true, Ordering::SeqCst);
        if let Some((suspended_flag, stop_tx)) = self.get_stop_tx().await
            && stop_tx
                .send((
                    self.tid(),
                    Suspended {
                        waker: None,
                        suspended: suspended_flag,
                    },
                ))
                .await
                .is_err()
        {
            tracing::warn!(
                    tid = %self.tid(),
                    "tracee freeze channel closed during GDB breakpoint handling"
            );
        }

        // When resuming from breakpoint, gdb (client) needs to remove the
        // breakpoint (implying restore the original instruction), do a
        // single-step (step-over), and re-insert the breakpoint.
        // Because removing (sw) breakpoint modifies the instructions, other
        // thread might miss the breakpoint after the breakpoint is removed
        // and before the breakpoint is (re-)inserted. Hence we must make
        // serialize this sequence.
        let needs_step_over = self.needs_step_over.clone();
        let _guard = needs_step_over.lock().await;

        self.notify_gdb_stop(StopReason::stopped(
            task.pid(),
            self.pid(),
            StopEvent::SwBreak,
            regs.into(),
        ))
        .await?;

        self.freeze_all().await?;

        let running = self
            .await_gdb_resume(task, ExpectedGdbResume::StepOver)
            .await?;

        // If gdb removed the breakpoint at the current PC and issued a plain
        // continue instead of the usual step-over single-step (e.g. after a
        // `finish` temporary breakpoint was hit and deleted, and the user then
        // continues), there is no intermediate single-step stop to report back
        // to gdb. Just run to the next event and return it directly. The task
        // may run all the way to exit in this case, so we must not assume it
        // stops again.
        if !matches!(self.resumed_by_gdb, Some(ResumeAction::Step(_))) {
            // Release the siblings frozen above *before* waiting for this
            // task's next event. gdb has resumed everything, and this task may
            // now block on a sibling -- a join, a futex, a pipe read -- which a
            // frozen sibling can never satisfy. Waiting first deadlocks the
            // guest.
            self.thaw_all().await?;
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            return Ok(wait);
        }

        let wait = running
            .next_state_with_owner(&self.ptracer_waits)
            .await?
            .assume_stopped();
        let mut task = wait.0;
        let mut event = wait.1;
        self.arm_liteinst_root_stop(&task, &event);

        // Detached by client.
        if !self.attached_by_gdb {
            self.thaw_all().await?;
            return Ok(Wait::Stopped(task, event));
        }

        task = loop {
            match event {
                Event::Signal(Signal::SIGTRAP) => break task,
                Event::Signal(Signal::SIGSTOP) => {
                    let running = self.step_stopped(task, None)?;
                    let wait = running
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?
                        .assume_stopped();
                    task = wait.0;
                    event = wait.1;
                    self.arm_liteinst_root_stop(&task, &event);
                }
                // TODO: combine with handle_signal!
                Event::Signal(Signal::SIGCHLD) => {
                    let running = self.step_stopped(task, Signal::SIGCHLD)?;
                    let wait = running
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?
                        .assume_stopped();
                    task = wait.0;
                    event = wait.1;
                    self.arm_liteinst_root_stop(&task, &event);
                }
                unknown => panic!("[pid = {}] got unexpected event {:?}", self.tid(), unknown),
            }
        };
        self.notify_gdb_stop(StopReason::stopped(
            task.pid(),
            self.pid(),
            StopEvent::Signal(Signal::SIGTRAP),
            task.getregs()?.into(),
        ))
        .await?;

        let running = self
            .await_gdb_resume(task, ExpectedGdbResume::Resume)
            .await?;
        // Same ordering requirement as the plain-continue path above: the
        // step-over is finished and the breakpoint is back in place, so the
        // siblings must be released before this task's next event is awaited.
        self.thaw_all().await?;
        let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
        self.arm_liteinst_wait(&wait);
        Ok(wait)
    }

    /// check if the stop is caused by sw breakpoint.
    async fn check_swbreak(&mut self, wait: Wait) -> Result<Wait, TraceError> {
        self.arm_liteinst_wait(&wait);
        match wait {
            Wait::Stopped(task, event) if event == Event::Signal(Signal::SIGTRAP) => {
                let mut regs = task.getregs()?;
                let rip_minus_one = regs.ip() - 1;
                if self.breakpoints.contains_key(&rip_minus_one) {
                    *regs.ip_mut() = rip_minus_one;
                    self.resume_from_swbreak(task, regs).await
                } else {
                    Ok(Wait::Stopped(task, event))
                }
            }
            other => Ok(other),
        }
    }

    async fn add_breakpoint(&mut self, addr: u64) -> Result<(), TraceError> {
        if let Some(bkpt_addr) = AddrMut::from_raw(addr as usize) {
            let mut task = self.assume_stopped();
            // The word read here can include the int3 of another live
            // breakpoint up to 7 bytes later. That is harmless: only the
            // lowest byte, this breakpoint's own, is ever restored.
            let saved_insn: u64 = task.read_value(bkpt_addr)?;
            // `Z0` must be idempotent (GDB remote protocol, "Z0"). Inserting again
            // would save the int3 as the original byte, so a later `z0` would
            // leave the breakpoint in the tracee for good. Each thread keeps
            // its own copy of `breakpoints` (see the field), so an entry here
            // can be stale: another thread may have removed the breakpoint.
            // Trust the entry only while the int3 is still in memory;
            // otherwise insert again, replacing the stale entry.
            if self.breakpoints.contains_key(&addr) && saved_insn & 0xff == 0xcc {
                return Ok(());
            }
            task.write_value(bkpt_addr, &breakpoint_inserted(saved_insn))?;
            self.breakpoints.insert(addr, saved_insn);
        }
        Ok(())
    }

    /// thaw all threads.
    async fn thaw_all(&mut self) -> Result<(), TraceError> {
        for (_pid, suspended_task) in core::mem::take(&mut self.suspended_tasks) {
            if let Some(tx) = suspended_task.waker.as_ref() {
                suspended_task.suspended.store(false, Ordering::SeqCst);
                let _sent = tx.try_send(self.tid());
            }
        }
        Ok(())
    }

    /// freeze all threads, except the caller.
    async fn freeze_all(&mut self) -> Result<(), TraceError> {
        // The tool have chosen to sequentialize thread execution, gdbserver
        // should avoid doing its own thread serialization, otherwise this
        // could lead to deadlock.
        if *self.global_state.sequentialized_guest {
            return Ok(());
        }
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        for child in self.child_threads.lock().await.deref_mut().into_iter() {
            if child.id() != self.tid() && !child.suspended.load(Ordering::SeqCst) {
                let killed = Errno::result(unsafe {
                    libc::syscall(libc::SYS_tgkill, self.pid(), child.id(), Signal::SIGSTOP)
                });
                if killed.is_ok() {
                    child.suspended.store(true, Ordering::SeqCst);
                    child.wait_all_stop_tx = Some(stop_tx.clone());
                }
            }
        }
        drop(stop_tx);
        while let Some((pid, suspended_task)) = stop_rx.recv().await {
            self.suspended_tasks.insert(pid, suspended_task);
        }
        Ok(())
    }

    async fn remove_breakpoint(&mut self, addr: u64) -> Result<(), TraceError> {
        let insn = self.breakpoints.remove(&addr).ok_or(Errno::ENOENT)?;
        let mut task = self.assume_stopped();
        if let Some(bkpt_addr) = AddrMut::from_raw(addr as usize) {
            // Restore this breakpoint's byte only. Writing the whole saved
            // word back would also restore the 7 bytes after it as they were
            // at insertion, erasing the int3 of any breakpoint inserted there
            // since, such as GDB's breakpoint on a following short source
            // line when it steps over this one.
            let current: u64 = task.read_value(bkpt_addr)?;
            task.write_value(bkpt_addr, &breakpoint_removed(current, insn))?;
        }
        Ok(())
    }

    fn read_inferior_memory(&self, addr: u64, mut size: usize) -> Result<Vec<u8>, TraceError> {
        let task = self.assume_stopped();

        // NB: dont' trust size to be sane blindly.
        if size > 0x8000 {
            size = 0x8000;
        }

        let mut res = vec![0; size];
        if let Some(addr) = Addr::from_raw(addr as usize) {
            let nb = task.read(addr, &mut res)?;
            res.resize(nb, 0);
        }

        // There could be a software breakpoint within the address requested,
        // we should return the orignal contents without the breakpoint insn.
        // This is *not* documented in gdb remote protocol, however, both
        // gdbserver and rr does this. see:
        // rr: https://github.com/rr-debugger/rr/blob/master/src/GdbServer.cc#L561
        // gdbserver: https://github.com/bminor/binutils-gdb/blob/master/gdbserver/mem-break.cc#L1914
        for (bkpt, saved_insn) in self.breakpoints.iter() {
            if (addr..addr + res.len() as u64).contains(bkpt) {
                // This abuses bkpt insn 0xcc is single byte.
                res[*bkpt as usize - addr as usize] = *saved_insn as u8;
            }
        }

        Ok(res)
    }

    fn write_inferior_memory(
        &self,
        addr: u64,
        size: usize,
        data: Vec<u8>,
    ) -> Result<(), TraceError> {
        let mut task = self.assume_stopped();
        let size = std::cmp::min(size, data.len());
        let addr = AddrMut::from_raw(addr as usize).ok_or(Errno::EFAULT)?;
        task.write(addr, &data[..size])?;
        Ok(())
    }

    fn read_registers(&self) -> Result<CoreRegs, TraceError> {
        let task = self.assume_stopped();
        let regs = task.getregs()?;
        let fpregs = task.getfpregs()?;
        let core_regs = CoreRegs::from_parts(regs, fpregs);
        Ok(core_regs)
    }

    fn write_registers(&self, core_regs: CoreRegs) -> Result<(), TraceError> {
        let task = self.assume_stopped();
        let (regs, fpregs) = core_regs.into_parts();
        task.setregs(&regs)?;
        task.setfpregs(&fpregs)?;
        Ok(())
    }
}

#[async_trait]
impl<L: Tool + 'static> Guest<L> for TracedTask<L> {
    type Memory = Stopped;
    type Stack = GuestStack;

    #[inline]
    fn tid(&self) -> Pid {
        self.tid
    }

    #[inline]
    fn pid(&self) -> Pid {
        self.pid
    }

    #[inline]
    fn ppid(&self) -> Option<Pid> {
        self.ppid
    }

    fn is_command_bootstrap(&self) -> bool {
        self.command_bootstrap
    }

    fn is_backend_runtime_bootstrap(&self) -> bool {
        // Bootstrap is entered only by a validated begin trap in the Waiting
        // phase and left only by the matching validated ready or failed report
        // (classify_liteinst_trap, handle_sigtrap). The state is shared by the
        // threads of one address space, copied into a forked child, and
        // replaced on exec, so the window also names the one thread that runs
        // the bootstrap: other threads and forked children run guest code.
        // Exit, exec, a signal, or reaching the guarded executable entry inside
        // the window fails the session closed.
        if self.global_state.liteinst_runtime.is_none() {
            return false;
        }
        let state = self.liteinst_runtime.lock().unwrap();
        state.phase == LiteinstRuntimePhase::Bootstrap && state.bootstrap_tid == Some(self.tid())
    }

    fn memory(&self) -> Self::Memory {
        self.assume_stopped()
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        let task = self.assume_stopped();

        match self.read_guest_registers(&task) {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), reverie::Error> {
        let task = self.assume_stopped();

        if self.in_held_signal_callback {
            // The registers this write replaces may hold the guest's
            // `-ERESTART_RESTARTBLOCK` (`signal_callback_guest_ret`). A
            // failed read notes nothing; it does not fail the write.
            if let Ok(current) = self.read_guest_registers(&task) {
                self.note_guest_restart_block(&current, current.ret());
            }
        }
        if let Err(err) = self.write_guest_registers(&task, &regs) {
            // Mirror `regs()`: a ptrace register access failure aborts the task.
            self.abort(Err(err)).await;
        }
        Ok(())
    }

    async fn stack(&mut self) -> Self::Stack {
        match GuestStack::new_on_ptracer_thread(
            self.assume_stopped(),
            self.stack_checked_out.clone(),
        ) {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    fn thread_state_mut(&mut self) -> &mut L::ThreadState {
        &mut self.thread_state
    }

    fn thread_state(&self) -> &L::ThreadState {
        &self.thread_state
    }

    async fn daemonize(&mut self) {
        let pid = self.pid();
        self.ndaemons.fetch_add(1, Ordering::SeqCst);
        self.is_a_daemon = true;

        tracing::info!("[reverie] daemonizing pid {} ..", pid);
        if self
            .daemonizer
            .send(self.daemon_kill_switch.subscribe())
            .await
            .is_err()
        {
            tracing::error!(%pid, "failed to notify orphan reaper while daemonizing tracee");
            self.ndaemons.fetch_sub(1, Ordering::SeqCst);
            self.is_a_daemon = false;
            return;
        }

        if self.ndaemons.load(Ordering::SeqCst) == self.ntasks.load(Ordering::SeqCst) {
            let _ = self.daemon_kill_switch.send(());
        }
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        // Call a non-templatized function to reduce code bloat.
        let (nr, args) = syscall.into_parts();
        self.do_inject(nr, args).await
    }

    #[allow(unreachable_code)]
    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        // Call a non-templatized function to reduce code bloat.
        let (nr, args) = syscall.into_parts();
        self.do_tail_inject(nr, args).await
    }

    fn set_timer(&mut self, sched: TimerSchedule) -> Result<(), reverie::Error> {
        let rcbs = match sched {
            TimerSchedule::Rcbs(r) => r,
            TimerSchedule::Time(dur) => Timer::as_ticks(dur),
            //if timer is imprecise there is no really a point in trying to single step any further than r
            TimerSchedule::RcbsAndInstructions(r, _) => r,
        };
        self.timer
            .request_event(TimerEventRequest::Imprecise(rcbs))?;
        Ok(())
    }

    fn set_timer_precise(&mut self, sched: TimerSchedule) -> Result<(), reverie::Error> {
        match sched {
            TimerSchedule::Rcbs(r) => self.timer.request_event(TimerEventRequest::Precise(r))?,
            TimerSchedule::Time(dur) => self
                .timer
                .request_event(TimerEventRequest::Precise(Timer::as_ticks(dur)))?,
            TimerSchedule::RcbsAndInstructions(r, i) => self
                .timer
                .request_event(TimerEventRequest::PreciseInstruction(r, i))?,
        };
        Ok(())
    }

    fn read_clock(&mut self) -> Result<u64, reverie::Error> {
        Ok(self.timer.read_clock())
    }

    fn backtrace(&mut self) -> Option<Backtrace> {
        use unwind::Accessors;
        use unwind::AddressSpace;
        use unwind::Byteorder;
        use unwind::Cursor;
        use unwind::PTraceState;
        use unwind::RegNum;

        let mut frames = Vec::new();

        let space = AddressSpace::new(Accessors::ptrace(), Byteorder::DEFAULT).ok()?;
        let state = PTraceState::new(self.tid.as_raw() as u32).ok()?;
        let mut cursor = Cursor::remote(&space, &state).ok()?;

        loop {
            let ip = cursor.register(RegNum::IP).ok()?;
            let is_signal = cursor.is_signal_frame().ok()?;

            frames.push(Frame { ip, is_signal });

            if !cursor.step().ok()? {
                break;
            }
        }

        // TODO: Take a snapshot of `/proc/self/maps` so the backtrace can be
        // processed offline?

        Some(Backtrace::new(self.tid(), frames))
    }

    fn has_cpuid_interception(&self) -> bool {
        self.has_cpuid_interception
    }
}

#[async_trait]
impl<L: Tool + 'static> GlobalRPC<L::GlobalState> for TracedTask<L> {
    async fn send_rpc<'a>(
        &'a self,
        args: <L::GlobalState as GlobalTool>::Request,
    ) -> <L::GlobalState as GlobalTool>::Response {
        let wrapped = WrappedFrom(self.tid(), &self.global_state);
        wrapped.send_rpc(args).await
    }

    fn config(&self) -> &<L::GlobalState as GlobalTool>::Config {
        &self.global_state.cfg
    }
}

/// Wrap a GlobalState with a Tid from which the messages originate.  This enables the
/// GlobalRPC instance below.
struct WrappedFrom<'a, G: GlobalTool>(Tid, &'a GlobalState<G>);

#[async_trait]
impl<'a, G: GlobalTool> GlobalRPC<G> for WrappedFrom<'a, G> {
    async fn send_rpc(&self, args: G::Request) -> G::Response {
        // In debugging mode we round-trip through a serialized representation
        // to make sure it works.
        let deserial = if cfg!(debug_assertions) {
            let serial = bincode::serde::encode_to_vec(&args, bincode::config::legacy())
                .expect("GlobalRPC request must serialize in debug validation mode");
            bincode::serde::decode_from_slice(&serial, bincode::config::legacy())
                .expect("serialized GlobalRPC request must deserialize in debug validation mode")
                .0
        } else {
            args
        };
        self.1.gs_ref.receive_rpc(self.0, deserial).await
    }
    fn config(&self) -> &G::Config {
        &self.1.cfg
    }
}

/// The word at a software breakpoint's address with the breakpoint inserted:
/// `int3` (0xcc) in the lowest byte, the address's own, and the other 7 bytes
/// as they are.
fn breakpoint_inserted(word: u64) -> u64 {
    (word & !0xffu64) | 0xccu64
}

/// The word at a software breakpoint's address with the breakpoint removed:
/// the lowest byte restored from `saved`, the word read when the breakpoint
/// was inserted, and the other 7 bytes left as they are in `current`. They
/// can hold breakpoints inserted or removed since `saved` was read.
fn breakpoint_removed(current: u64, saved: u64) -> u64 {
    (current & !0xffu64) | (saved & 0xffu64)
}

#[cfg(test)]
mod breakpoint_word_tests {
    use super::breakpoint_inserted;
    use super::breakpoint_removed;

    // Tracee bytes are little-endian: byte k of the word is the address + k.
    fn word(bytes: [u8; 8]) -> u64 {
        u64::from_le_bytes(bytes)
    }

    #[test]
    fn inserting_writes_int3_at_the_address_only() {
        let code = word([0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x90, 0xc3]);
        assert_eq!(
            breakpoint_inserted(code).to_le_bytes(),
            [0xcc, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x90, 0xc3]
        );
    }

    #[test]
    fn removing_keeps_a_later_breakpoint_inserted_after_this_one() {
        // A at offset 0, then B at offset 6, then A is removed.
        let code = word([0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x66, 0x0f]);
        let saved_a = code;
        let with_a = breakpoint_inserted(code);
        let mut bytes = with_a.to_le_bytes();
        bytes[6] = 0xcc;
        let with_a_and_b = word(bytes);
        assert_eq!(
            breakpoint_removed(with_a_and_b, saved_a).to_le_bytes(),
            [0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xcc, 0x0f]
        );
    }

    #[test]
    fn removing_does_not_restore_a_later_breakpoint_removed_first() {
        // B at offset 6 is live when A is inserted, so A's saved word holds
        // B's int3. B is removed, then A.
        let code = word([0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x66, 0x0f]);
        let mut bytes = code.to_le_bytes();
        bytes[6] = 0xcc;
        let with_b = word(bytes);
        let saved_a = with_b;
        let with_a_and_b = breakpoint_inserted(with_b);
        let mut bytes = with_a_and_b.to_le_bytes();
        bytes[6] = 0x66;
        let with_a = word(bytes);
        assert_eq!(breakpoint_removed(with_a, saved_a), code);
    }
}

#[cfg(test)]
#[path = "task_exec_owner_tests.rs"]
mod exec_owner_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn callback_observation_refuses_typed_faults_and_only_defers_disappearance_with_gone_identity()
    {
        use safeptrace::ProcStatError as P;
        use safeptrace::StopObservationError as B;
        use safeptrace::StopSiginfo;

        use crate::PtraceCallbackRefusal as R;
        use crate::PtraceCallbackStop as S;
        // These are explicitly projected field failures, not claims that the
        // kernel returned these errno values in the real lifecycle fixtures.
        let info = StopSiginfo {
            signo: libc::SIGTRAP,
            code: 1541,
            sender_pid: 42,
            sender_uid: 1,
        };
        fn decide(
            binding: Option<B>,
            query: Option<Result<StopSiginfo, Errno>>,
            flags: Option<&Result<u32, P>>,
            live: Option<Result<bool, Errno>>,
        ) -> Result<bool, R> {
            super::callback_observation_decision(
                S::Signal(libc::SIGTRAP),
                binding,
                query,
                flags,
                live,
            )
        }

        for error in [Errno::EPERM, Errno::EIO, Errno::EINVAL] {
            assert_eq!(
                decide(None, Some(Err(error)), None, Some(Ok(false))),
                Err(R::Query(error))
            );
        }
        assert_eq!(
            decide(None, Some(Ok(info)), None, Some(Err(Errno::EPERM))),
            Err(R::Pidfd(Errno::EPERM))
        );
        for error in [
            P::Io(Errno::EPERM),
            P::Io(Errno::EIO),
            P::Io(Errno::EINTR),
            P::Format("short record"),
            P::PidMismatch,
        ] {
            for live in [false, true] {
                let result = Err(error.clone());
                assert_eq!(
                    decide(None, Some(Ok(info)), Some(&result), Some(Ok(live))),
                    Err(R::Proc(error.clone()))
                );
            }
        }
        for errno in [Errno::ESRCH, Errno::ENOENT] {
            let flags = Err(P::Io(errno));
            assert_eq!(
                decide(None, Some(Ok(info)), Some(&flags), Some(Ok(false))),
                Ok(true)
            );
            assert_eq!(
                decide(None, Some(Ok(info)), Some(&flags), Some(Ok(true))),
                Err(R::Proc(P::Io(errno)))
            );
        }
        for error in [
            B::WrongThread,
            B::GenerationMismatch,
            B::ExecEpochMismatch,
            B::PidMismatch,
            B::Identity(Errno::ENODATA),
        ] {
            assert_eq!(
                decide(Some(error), None, None, None),
                Err(R::Binding(error))
            );
        }
        assert_eq!(
            decide(None, None, None, None),
            Err(R::Inconsistent("missing siginfo query"))
        );
        assert_eq!(
            decide(None, Some(Ok(info)), None, None),
            Err(R::Inconsistent("missing final pidfd query"))
        );
        assert_eq!(
            decide(None, Some(Ok(info)), None, Some(Ok(true))),
            Err(R::Inconsistent("missing ambiguous EXIT flags"))
        );
        assert_eq!(
            decide(None, Some(Err(Errno::ESRCH)), None, Some(Ok(true))),
            Ok(true)
        );
        assert_eq!(
            decide(None, Some(Ok(info)), Some(&Ok(0)), Some(Ok(true))),
            Ok(false)
        );
        assert_eq!(
            decide(None, Some(Ok(info)), Some(&Ok(0x400)), Some(Ok(true))),
            Ok(true)
        );
    }

    #[test]
    fn command_bootstrap_arguments_preserve_types_and_raw_tail() {
        let args = super::SyscallArgs::new(0x1000, 0x2000, 0, 41, 0x3000, 43);
        let render = |nr, command_bootstrap| {
            format!(
                "{:?}",
                super::SyscallArgsForLog {
                    nr,
                    args,
                    command_bootstrap,
                }
            )
        };
        assert_eq!(
            render(super::Sysno::execve, true),
            "SyscallArgs { arg0: <hostaddr 0x1000>, arg1: <hostaddr 0x2000>, arg2: 0, arg3: 41, arg4: 12288, arg5: 43 }"
        );
        for nr in [
            super::Sysno::execve,
            super::Sysno::write,
            super::Sysno::execveat,
        ] {
            assert_eq!(render(nr, false), format!("{args:?}"));
        }
        assert_eq!(render(super::Sysno::write, true), format!("{args:?}"));
        assert_eq!(render(super::Sysno::execveat, true), format!("{args:?}"));
        let aliased = super::SyscallArgsForLog {
            nr: super::Sysno::execve,
            args: super::SyscallArgs::new(0x1000, 0x1000, 0, 41, 0x3000, 43),
            command_bootstrap: true,
        };
        assert_ne!(format!("{aliased:?}"), render(super::Sysno::execve, true));
    }

    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn syscall_skip_breakpoint_requires_exact_captured_provenance() {
        let exec_rip = 0x7f00_1234_530b;
        let arch_prctl_rip = 0x7f00_1234_cb19;
        let syscall_opcode = [0x0f, 0x05];
        assert!(is_expected_syscall_skip_breakpoint(
            libc::TRAP_BRKPT,
            exec_rip,
            exec_rip,
            syscall_opcode,
            0x48,
            false,
        ));
        assert!(is_expected_syscall_skip_breakpoint(
            libc::TRAP_BRKPT,
            arch_prctl_rip,
            arch_prctl_rip,
            syscall_opcode,
            0x48,
            false,
        ));

        for rejected in [
            is_expected_syscall_skip_breakpoint(
                libc::SI_USER,
                exec_rip,
                exec_rip,
                syscall_opcode,
                0x48,
                false,
            ),
            is_expected_syscall_skip_breakpoint(
                libc::TRAP_BRKPT,
                exec_rip,
                exec_rip + 1,
                syscall_opcode,
                0x48,
                false,
            ),
            is_expected_syscall_skip_breakpoint(
                libc::TRAP_BRKPT,
                exec_rip,
                exec_rip,
                [0xcc, 0x05],
                0x48,
                false,
            ),
            is_expected_syscall_skip_breakpoint(
                libc::TRAP_BRKPT,
                exec_rip,
                exec_rip,
                syscall_opcode,
                0xcc,
                false,
            ),
            is_expected_syscall_skip_breakpoint(
                libc::TRAP_BRKPT,
                exec_rip,
                exec_rip,
                syscall_opcode,
                0x48,
                true,
            ),
        ] {
            assert!(!rejected);
        }
    }

    fn active_state() -> LiteinstRuntimeState {
        let mut state = LiteinstRuntimeState::default();
        state.active_hooks.insert(
            0x401005,
            ActiveHookFootprint {
                site: GuestRange::new(0x401005, 8).unwrap(),
                trampoline: GuestRange::new(0x7000_1000, 0x1000).unwrap(),
                arena_writable: GuestRange::new(0x7100_0000, 0x80_000).unwrap(),
                arena_executable: GuestRange::new(0x7000_0000, 0x80_000).unwrap(),
            },
        );
        state
    }

    #[test]
    fn exec_generation_replaces_image_state_without_changing_old_holders() {
        let mut old = active_state();
        old.phase = LiteinstRuntimePhase::Ready;
        old.generation = 41;
        old.ready_generation = Some(41);
        old.bootstrap_tid = Some(Pid::from_raw(4242));
        old.frame = Some(LiteinstHandshakeFrame {
            begin_rip: 0x7000_1000,
            ..Default::default()
        });
        old.attempted_sites.insert(0x401005);
        old.fallback_sites
            .insert(0x401005, LiteinstPatchOutcome::PtraceOtherFallback);
        let old = Arc::new(StdMutex::new(old));
        let holder = Arc::clone(&old);
        let next = Arc::new(StdMutex::new(old.lock().unwrap().after_exec().unwrap()));
        assert!(!Arc::ptr_eq(&holder, &next));
        let next = next.lock().unwrap();
        assert_eq!(next.phase, LiteinstRuntimePhase::Waiting);
        assert_eq!(next.generation, 42);
        assert!(next.ready_generation.is_none());
        assert!(next.frame.is_none());
        assert!(next.bootstrap_tid.is_none());
        assert!(next.attempted_sites.is_empty());
        assert!(next.fallback_sites.is_empty());
        assert!(next.active_hooks.is_empty());
        let mut old = holder.lock().unwrap();
        assert_eq!(old.phase, LiteinstRuntimePhase::Ready);
        assert_eq!(old.ready_generation, Some(41));
        assert_eq!(old.frame.unwrap().begin_rip, 0x7000_1000);
        assert!(old.attempted_sites.contains(&0x401005));
        assert_eq!(
            old.fallback_sites.get(&0x401005),
            Some(&LiteinstPatchOutcome::PtraceOtherFallback)
        );
        assert_eq!(old.active_hooks.len(), 1);
        old.generation = u64::MAX;
        assert_eq!(old.after_exec().unwrap_err(), Errno::EOVERFLOW);
        assert_eq!(old.generation, u64::MAX);
        assert_eq!(old.phase, LiteinstRuntimePhase::Ready);
    }

    #[test]
    fn kernel_page_ranges_floor_ceil_and_reject_overflow() {
        assert_eq!(
            kernel_page_range(0x401005, 1, 4096),
            Ok(Some(GuestRange {
                start: 0x401000,
                end: 0x402000,
            }))
        );
        assert_eq!(kernel_page_range(0x401000, 0, 4096), Ok(None));
        assert_eq!(kernel_page_range(u64::MAX - 1, 4, 4096), Err(()));
        assert_eq!(kernel_page_range(0x401000, 1, 3000), Err(()));
    }

    #[test]
    fn short_successful_mapping_invalidates_the_whole_attempted_page() {
        let mut state = LiteinstRuntimeState::default();
        state.attempted_sites.extend([0x401005, 0x401fff, 0x402005]);

        state.invalidate_attempted_pages(0x401000, 1, 4096);

        assert_eq!(state.attempted_sites, HashSet::from([0x402005]));
    }

    const CENSUS_TEST_MAPS: &str = concat!(
        "555555554000-555555556000 r--p 00000000 00:1f 11 /usr/bin/guest\n",
        "555555556000-555555558000 r-xp 00002000 00:1f 11 /usr/bin/guest\n",
        "555555558000-55555555a000 rw-p 00004000 00:1f 11 /usr/bin/guest\n",
        "55555555a000-55555557b000 rw-p 00000000 00:00 0 [heap]\n",
        "7ffff7c00000-7ffff7c28000 r--p 00000000 00:1f 22 /usr/lib64/libc.so.6\n",
        "7ffff7c28000-7ffff7db0000 r-xp 00028000 00:1f 22 /usr/lib64/libc.so.6\n",
        "7ffff7db0000-7ffff7dff000 r--p 001b0000 00:1f 22 /usr/lib64/libc.so.6\n",
        "7ffff7dff000-7ffff7e00000 ---p 001ff000 00:1f 22 /usr/lib64/libc.so.6\n",
        "7ffff7e00000-7ffff7e04000 r--p 001ff000 00:1f 22 /usr/lib64/libc.so.6\n",
        "7ffff7e04000-7ffff7e06000 rw-p 00203000 00:1f 22 /usr/lib64/libc.so.6\n",
        "7ffff7e06000-7ffff7e13000 rw-p 00000000 00:00 0\n",
        "7ffff7f00000-7ffff7f01000 r-xp 00000000 00:00 0\n",
        "7ffff7f10000-7ffff7f11000 r--p 00000000 00:2a 22 /other/device/same-inode\n",
        "7ffff7f20000-7ffff7f21000 r--p 00000000 00:1f 33 /twice.so\n",
        "7ffff7f21000-7ffff7f22000 r-xp 00001000 00:1f 33 /twice.so\n",
        "7ffff7f30000-7ffff7f31000 r--p 00000000 00:1f 33 /twice.so\n",
    );

    fn census_test_maps() -> Vec<GuestMap> {
        CENSUS_TEST_MAPS
            .lines()
            .filter_map(|line| parse_guest_map(line.as_bytes()))
            .collect()
    }

    fn census_range(start: u64, end: u64, offset: u64, executable: bool) -> CensusRange {
        CensusRange {
            start,
            end,
            offset,
            executable,
        }
    }

    /// The tracer's census reads an object through the mappings recorded at
    /// Ready (https://github.com/rrnewton/reverie/issues/812), so those must be
    /// exactly the readable mappings of the text mapping's file. The LiteInst
    /// runtime's object_image test checks its own copy of this rule against
    /// the same maps.
    #[test]
    fn census_object_records_the_readable_mappings_of_the_text_file() {
        let maps = census_test_maps();

        // The gap mapping (---p), the anonymous .bss continuation and the
        // mapping of another device's inode 22 are all left out.
        assert_eq!(
            census_object(&maps, 0x7fff_f7c3_0000),
            Ok(CensusObject {
                text: (0x7fff_f7c2_8000, 0x7fff_f7db_0000),
                header: 0x7fff_f7c0_0000,
                ranges: vec![
                    census_range(0x7fff_f7c0_0000, 0x7fff_f7c2_8000, 0, false),
                    census_range(0x7fff_f7c2_8000, 0x7fff_f7db_0000, 0x28000, true),
                    census_range(0x7fff_f7db_0000, 0x7fff_f7df_f000, 0x1b_0000, false),
                    census_range(0x7fff_f7e0_0000, 0x7fff_f7e0_4000, 0x1f_f000, false),
                    census_range(0x7fff_f7e0_4000, 0x7fff_f7e0_6000, 0x20_3000, false),
                ],
                file: (0, 0x1f, 22),
                path: Some(PathBuf::from("/usr/lib64/libc.so.6")),
            })
        );
        assert_eq!(
            census_object(&maps, 0x5555_5555_7ffe),
            Ok(CensusObject {
                text: (0x5555_5555_6000, 0x5555_5555_8000),
                header: 0x5555_5555_4000,
                ranges: vec![
                    census_range(0x5555_5555_4000, 0x5555_5555_6000, 0, false),
                    census_range(0x5555_5555_6000, 0x5555_5555_8000, 0x2000, true),
                    census_range(0x5555_5555_8000, 0x5555_5555_a000, 0x4000, false),
                ],
                file: (0, 0x1f, 11),
                path: Some(PathBuf::from("/usr/bin/guest")),
            })
        );
        // Anonymous text, a file mapped twice (two headers), a mapping that is
        // not executable, and an unmapped address have no object.
        for site in [0x7fff_f7f0_0010, 0x7fff_f7f2_1010, 0x7fff_f7c0_0010, 0x1000] {
            assert_eq!(
                census_object(&maps, site),
                Err(NO_CENSUS_OBJECT),
                "{site:#x}"
            );
        }
    }

    /// A mapping change that touches any page of an object removes every
    /// mapping of that object and its census, so the census is never rebuilt
    /// from text that was patched before the change.
    #[test]
    fn a_mapping_change_forgets_every_census_object_it_touches() {
        const LIBC_TEXT: u64 = 0x7fff_f7c2_8000;
        const GUEST_TEXT: u64 = 0x5555_5555_6000;
        let mut state = LiteinstRuntimeState::default();
        state.enter_ready(census_test_maps());
        // Only the readable file-backed mappings are kept: three of the
        // guest, five of libc, one of the other device and three of twice.so.
        assert_eq!(state.census_maps.len(), 12);
        state
            .censuses
            .insert(LIBC_TEXT, Arc::new(Err(CensusError::TRUNCATED)));
        state
            .censuses
            .insert(GUEST_TEXT, Arc::new(Err(CensusError::TRUNCATED)));

        // A range with no recorded mapping changes nothing.
        state.forget_census_objects(0x5555_5555_a000, 0x1000, 4096);
        assert_eq!(state.census_maps.len(), 12);
        assert_eq!(state.censuses.len(), 2);

        // One byte of libc's data mapping removes all of libc.
        state.forget_census_objects(0x7fff_f7e0_5fff, 1, 4096);
        assert_eq!(state.census_maps.len(), 7);
        assert_eq!(
            census_object(&state.census_maps, LIBC_TEXT),
            Err(NO_CENSUS_OBJECT)
        );
        assert_eq!(
            state.censuses.keys().copied().collect::<Vec<_>>(),
            [GUEST_TEXT]
        );
        assert!(census_object(&state.census_maps, GUEST_TEXT).is_ok());

        // An exec starts over without any object.
        let next = state.after_exec().unwrap();
        assert!(next.census_maps.is_empty() && next.censuses.is_empty());

        // A range that the kernel would reject removes every object.
        state.forget_census_objects(u64::MAX - 1, 4, 4096);
        assert!(state.census_maps.is_empty() && state.censuses.is_empty());
    }

    /// A reply of `ScriptedMemory` that copies every byte asked for.
    const FULL: usize = usize::MAX;

    /// Tracee memory that answers each read with the next of its replies:
    /// a count of bytes, which it fills with zeros, or an errno. It records
    /// the address and length of each read. Its object's file has the size
    /// `file_size`, or is not found with that errno; with `None`, asking for
    /// the size fails the test.
    struct ScriptedMemory {
        replies: std::cell::RefCell<std::collections::VecDeque<Result<usize, i32>>>,
        reads: std::cell::RefCell<Vec<(u64, usize)>>,
        file_size: Option<Result<u64, i32>>,
    }

    impl ScriptedMemory {
        fn new(replies: Vec<Result<usize, i32>>) -> Self {
            Self {
                replies: std::cell::RefCell::new(replies.into()),
                reads: std::cell::RefCell::new(Vec::new()),
                file_size: None,
            }
        }

        fn with_file_size(replies: Vec<Result<usize, i32>>, file_size: Result<u64, i32>) -> Self {
            Self {
                file_size: Some(file_size),
                ..Self::new(replies)
            }
        }

        fn reads(&self) -> Vec<(u64, usize)> {
            self.reads.borrow().clone()
        }
    }

    impl CensusMemory for ScriptedMemory {
        fn read_at(&self, address: u64, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.reads.borrow_mut().push((address, bytes.len()));
            match self.replies.borrow_mut().pop_front() {
                Some(Ok(count)) => {
                    let count = count.min(bytes.len());
                    bytes[..count].fill(0);
                    Ok(count)
                }
                Some(Err(errno)) => Err(std::io::Error::from_raw_os_error(errno)),
                None => panic!(
                    "an unexpected read of {} bytes at {address:#x}",
                    bytes.len()
                ),
            }
        }

        fn file_size(&self, _object: &CensusObject) -> std::io::Result<u64> {
            match self.file_size {
                Some(Ok(size)) => Ok(size),
                Some(Err(errno)) => Err(std::io::Error::from_raw_os_error(errno)),
                None => panic!("an unexpected question for the size of the object's file"),
            }
        }
    }

    const CENSUS_HEADER: u64 = 0x5555_5555_4000;
    const CENSUS_TEXT: u64 = 0x5555_5555_6000;

    /// An object whose header page and text map file offsets 0 to 0x4000.
    fn two_range_census_object() -> CensusObject {
        CensusObject {
            text: (CENSUS_TEXT, CENSUS_TEXT + 0x2000),
            header: CENSUS_HEADER,
            ranges: vec![
                census_range(CENSUS_HEADER, CENSUS_TEXT, 0, false),
                census_range(CENSUS_TEXT, CENSUS_TEXT + 0x2000, 0x2000, true),
            ],
            file: (0, 0x1f, 11),
            path: Some(PathBuf::from("/usr/bin/guest")),
        }
    }

    /// A page that faults when the census reads it refuses every site of the
    /// object, also after a short count, when it lies wholly past the end of
    /// the object's file, as a page of a file that the guest truncated does
    /// (review finding F7 on <https://github.com/rrnewton/reverie/pull/818>).
    #[test]
    fn a_census_read_faulting_past_the_end_of_the_file_refuses_the_object() {
        let object = two_range_census_object();
        // A file cut to nothing faults at its header.
        let memory = ScriptedMemory::with_file_size(vec![Err(libc::EIO)], Ok(0));
        assert_eq!(
            read_census(&memory, &object).map(Result::err),
            Ok(Some(FAULTING_CENSUS_OBJECT))
        );

        // The text's second page maps file offset 0x3000, so a file of at
        // most 0x3000 bytes ends before it.
        for size in [0x2001, 0x3000] {
            let memory = ScriptedMemory::with_file_size(
                vec![Ok(FULL), Ok(0x1000), Err(libc::EIO)],
                Ok(size),
            );
            assert_eq!(
                read_census(&memory, &object).map(Result::err),
                Ok(Some(FAULTING_CENSUS_OBJECT)),
                "{size:#x}"
            );
            assert_eq!(
                memory.reads(),
                [
                    (CENSUS_HEADER, 0x2000),
                    (CENSUS_TEXT, 0x2000),
                    (CENSUS_TEXT + 0x1000, 0x1000),
                ]
            );
        }
    }

    /// An EIO from a page that is not wholly past the end of the object's
    /// file is the outer error of `read_census`, not a refusal: the host
    /// causes those as well, by an I/O error paging the file in, a poisoned
    /// page or an out-of-memory fault (review finding F9 on
    /// <https://github.com/rrnewton/reverie/pull/818>). So is an EIO when the
    /// tracer cannot find the mapped file to tell.
    #[test]
    fn a_census_read_faulting_within_the_file_is_an_error_not_a_refusal() {
        let object = two_range_census_object();
        // The faulting page, at file offset 0x3000, holds the end of a file
        // of 0x3001 bytes, and lies inside one of 0x4000.
        for size in [0x3001, 0x4000, u64::MAX] {
            let memory = ScriptedMemory::with_file_size(
                vec![Ok(FULL), Ok(0x1000), Err(libc::EIO)],
                Ok(size),
            );
            assert_eq!(
                read_census(&memory, &object).map(Result::err),
                Err(Errno::EIO),
                "{size:#x}"
            );
        }
        let memory = ScriptedMemory::with_file_size(vec![Err(libc::EIO)], Ok(0x4000));
        assert_eq!(
            read_census(&memory, &object).map(Result::err),
            Err(Errno::EIO)
        );
        // After a short count that ends inside a page, the faulting page is
        // the one that holds the next byte, here the page at file offset
        // 0x3000, which holds the end of a file of 0x3400 bytes.
        let memory =
            ScriptedMemory::with_file_size(vec![Ok(FULL), Ok(0x1800), Err(libc::EIO)], Ok(0x3400));
        assert_eq!(
            read_census(&memory, &object).map(Result::err),
            Err(Errno::EIO)
        );
        assert_eq!(
            memory.reads(),
            [
                (CENSUS_HEADER, 0x2000),
                (CENSUS_TEXT, 0x2000),
                (CENSUS_TEXT + 0x1800, 0x800),
            ]
        );

        // No file, or another file, at the mapping's path.
        for errno in [libc::ENOENT, libc::ESTALE, libc::EACCES] {
            let memory = ScriptedMemory::with_file_size(vec![Err(libc::EIO)], Err(errno));
            assert_eq!(
                read_census(&memory, &object).map(Result::err),
                Err(Errno::EIO),
                "{errno}"
            );
        }
    }

    /// Any other failed read of the tracee's code is the outer error of
    /// `read_census`, never a census refusal, so the caller fails the run
    /// closed instead of refusing the site
    /// (<https://github.com/rrnewton/reverie/pull/818> review finding F1).
    /// A read of no bytes means the tracee's address space is gone, an
    /// interrupted read is repeated, and a range that cannot be a mapping is
    /// refused before any read. None of these asks for the file's size.
    #[test]
    fn a_host_failure_to_read_a_census_object_is_an_error_not_a_refusal() {
        let object = two_range_census_object();
        for errno in [libc::ENOMEM, libc::EFAULT] {
            let memory = ScriptedMemory::new(vec![Ok(FULL), Err(errno)]);
            assert_eq!(
                read_census(&memory, &object).map(Result::err),
                Err(Errno::new(errno))
            );
        }

        let memory = ScriptedMemory::new(vec![Ok(0)]);
        assert_eq!(
            read_census(&memory, &object).map(Result::err),
            Err(Errno::ESRCH)
        );

        let memory = ScriptedMemory::new(vec![Err(libc::EINTR), Ok(FULL), Ok(FULL)]);
        let census = read_census(&memory, &object).expect("an interrupted read was not repeated");
        assert_ne!(census.err(), Some(FAULTING_CENSUS_OBJECT));
        assert_eq!(
            memory.reads(),
            [
                (CENSUS_HEADER, 0x2000),
                (CENSUS_HEADER, 0x2000),
                (CENSUS_TEXT, 0x2000),
            ]
        );

        let reversed = CensusObject {
            ranges: vec![census_range(CENSUS_TEXT, CENSUS_HEADER, 0, false)],
            ..object
        };
        let memory = ScriptedMemory::new(Vec::new());
        assert_eq!(
            read_census(&memory, &reversed).map(Result::err),
            Ok(Some(CensusError::TRUNCATED))
        );
        assert!(memory.reads().is_empty());
    }

    /// The tracer finds a census object's file, and its size, through the
    /// path in the maps, here the maps of this test's own process for its
    /// own executable, and refuses a file whose inode or mount device differs
    /// from the maps'. On a btrfs subvolume, such as devbig014's /home, the
    /// file's `st_dev` differs from the maps' device, so this also checks
    /// that the device comes from the mount (review finding F9 on
    /// <https://github.com/rrnewton/reverie/pull/818>).
    #[test]
    fn the_census_finds_the_size_of_the_mapped_file() {
        let maps = read_guest_maps(Pid::this()).unwrap();
        let site = the_census_finds_the_size_of_the_mapped_file as fn() as usize as u64;
        let object = census_object(&maps, site).unwrap();
        let path = object.path.clone().unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        assert_eq!(mapped_file_size(&object).unwrap(), size, "{path:?}");

        let (major, minor, inode) = object.file;
        for file in [(major, minor, inode + 1), (major, minor + 1, inode)] {
            let other = CensusObject {
                file,
                path: Some(path.clone()),
                ..census_object(&maps, site).unwrap()
            };
            assert_eq!(
                mapped_file_size(&other).unwrap_err().raw_os_error(),
                Some(libc::ESTALE),
                "{file:?}"
            );
        }

        let gone = CensusObject {
            path: Some(PathBuf::from("/proc/self/no-such-file")),
            ..census_object(&maps, site).unwrap()
        };
        assert_eq!(
            mapped_file_size(&gone).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        let anonymous = CensusObject {
            path: None,
            ..object
        };
        assert_eq!(
            mapped_file_size(&anonymous).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn mount_device_reads_the_mount_line_of_the_mount_id() {
        let mountinfo = concat!(
            "22 1 0:32 / / rw,relatime shared:1 - btrfs /dev/vda2 rw,subvol=/root\n",
            "29 22 0:47 /home /home rw,relatime shared:12 - btrfs /dev/vda2 rw\n",
            "300 29 259:1 / /mnt/data rw - ext4 /dev/nvme0n1p1 rw\n",
        );
        assert_eq!(mount_device(mountinfo, 22), Some((0, 32)));
        assert_eq!(mount_device(mountinfo, 29), Some((0, 47)));
        assert_eq!(mount_device(mountinfo, 300), Some((259, 1)));
        assert_eq!(mount_device(mountinfo, 1), None);
        assert_eq!(mount_device(mountinfo, 30), None);
    }

    /// A census refusal leaves the site on ptrace and the run goes on; any
    /// failure to read the tracee's code fails the run closed, except a
    /// tracee that is gone (review finding F8 on
    /// <https://github.com/rrnewton/reverie/pull/818>).
    #[test]
    fn a_census_read_failure_fails_the_run_and_a_refusal_does_not() {
        let site = 0x5555_5555_7000;
        assert_eq!(
            census_outcome(
                site,
                Ok(Ok(SiteEntries {
                    len: 2,
                    limit: 0x5555_5555_7010
                }))
            ),
            CensusOutcome::Install(0x5555_5555_7010)
        );
        for error in [
            FAULTING_CENSUS_OBJECT,
            CHANGED_CENSUS_OBJECT,
            NO_CENSUS_OBJECT,
            CensusError::TRUNCATED,
        ] {
            assert_eq!(
                census_outcome(site, Ok(Err(Refusal::NoCensus(error)))),
                CensusOutcome::Install(REFUSED_ENTRY_LIMIT),
                "{error:?}"
            );
        }
        for errno in [
            Errno::EIO,
            Errno::ENOMEM,
            Errno::EMFILE,
            Errno::ENFILE,
            Errno::EACCES,
            Errno::EFAULT,
        ] {
            assert_eq!(
                census_outcome(site, Err(errno)),
                CensusOutcome::Fail(errno),
                "{errno}"
            );
        }
        assert_eq!(census_outcome(site, Err(Errno::ESRCH)), CensusOutcome::Gone);
    }

    /// A census that could not be built refuses every site of its object with
    /// the census's own error.
    #[test]
    fn a_failed_census_refuses_its_sites_with_its_error() {
        assert_eq!(
            census_site_entries(&Err(CensusError::TRUNCATED), 0x5555_5555_7000),
            Err(Refusal::NoCensus(CensusError::TRUNCATED))
        );
    }

    /// The maps read that Ready's census snapshot depends on reports a
    /// failure instead of returning no mappings, which would refuse every
    /// site without any report (review finding F1 on
    /// <https://github.com/rrnewton/reverie/pull/818>).
    #[test]
    fn reading_the_maps_of_a_missing_process_is_an_error() {
        // Linux caps pid_max at 2^22, so this pid never exists.
        let error = read_guest_maps(Pid::from_raw(i32::MAX)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(guest_maps(Pid::from_raw(i32::MAX)).is_none());

        let own = read_guest_maps(Pid::from_raw(std::process::id() as i32)).unwrap();
        assert!(own.iter().any(|map| map.executable && map.inode != 0));
    }

    #[test]
    fn proc_maps_paths_preserve_literal_whitespace_and_decode_octal_escapes() {
        let mapping = parse_guest_map(
            br"00400000-00401000 r-xp 00000000 08:02 123 /tmp/a  double	tab\040space\011escaped\134slash",
        )
        .unwrap();
        assert_eq!(
            mapping.path.unwrap(),
            PathBuf::from("/tmp/a  double\ttab space\tescaped\\slash")
        );
    }

    #[test]
    fn cancellable_returns_a_completed_result() {
        let cancel_handler = Arc::new(AtomicBool::new(false));

        assert_eq!(
            futures::executor::block_on(cancellable(cancel_handler, async { 42 })),
            Some(42)
        );
    }

    #[test]
    fn cancellable_observes_cancellation_in_the_same_poll() {
        let cancel_handler = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancel_handler);
        let pending = future::poll_fn(move |_| {
            signal.store(true, Ordering::SeqCst);
            Poll::<()>::Pending
        });

        assert_eq!(
            futures::executor::block_on(cancellable(Arc::clone(&cancel_handler), pending)),
            None
        );
        assert!(!cancel_handler.load(Ordering::SeqCst));
    }

    #[test]
    fn active_hook_footprint_rejects_destructive_mapping_overlap() {
        let state = active_state();
        assert!(state.mapping_mutates_active_hook(
            Sysno::mprotect,
            SyscallArgs::new(0x401000, 0x1000, libc::PROT_NONE as usize, 0, 0, 0),
            4096,
        ));
        assert!(state.mapping_mutates_active_hook(
            Sysno::mremap,
            SyscallArgs::new(0x7000_1000, 0x1000, 0x2000, 0, 0, 0),
            4096,
        ));
        assert!(state.mapping_mutates_active_hook(
            Sysno::munmap,
            SyscallArgs::new(0x7100_0000, 0x1000, 0, 0, 0, 0),
            4096,
        ));
        assert!(state.mapping_mutates_active_hook(
            Sysno::mmap,
            SyscallArgs::new(
                0x7000_0000,
                0x1000,
                libc::PROT_READ as usize,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as usize,
                usize::MAX,
                0,
            ),
            4096,
        ));
    }

    #[test]
    fn short_mapping_lengths_cover_the_whole_active_page() {
        let state = active_state();
        for nr in [Sysno::mprotect, Sysno::pkey_mprotect, Sysno::munmap] {
            assert!(state.mapping_mutates_active_hook(
                nr,
                SyscallArgs::new(0x401000, 1, libc::PROT_NONE as usize, 0, 0, 0),
                4096,
            ));
        }
        assert!(state.mapping_mutates_active_hook(
            Sysno::mmap,
            SyscallArgs::new(0x401000, 1, 0, libc::MAP_FIXED as usize, 0, 0),
            4096,
        ));
        assert!(state.mapping_mutates_active_hook(
            Sysno::mremap,
            SyscallArgs::new(0x5000_0000, 1, 1, libc::MREMAP_FIXED as usize, 0x401000, 0,),
            4096,
        ));
        assert!(state.mapping_mutates_active_hook(
            Sysno::mremap,
            SyscallArgs::new(0x5000_0000, 0, 1, libc::MREMAP_FIXED as usize, 0x401000, 0,),
            4096,
        ));
        assert!(state.mapping_mutates_active_hook(
            Sysno::mprotect,
            SyscallArgs::new(u64::MAX as usize - 1, 4, libc::PROT_NONE as usize, 0, 0, 0),
            4096,
        ));
    }

    #[test]
    fn pkey_mprotect_is_a_controller_mapping_syscall() {
        assert!(is_liteinst_mapping_syscall(Sysno::pkey_mprotect));
    }

    #[test]
    fn active_hook_noop_protection_retains_provenance() {
        let mut state = active_state();
        assert!(!state.mapping_mutates_active_hook(
            Sysno::mprotect,
            SyscallArgs::new(
                0x401000,
                0x1000,
                (libc::PROT_READ | libc::PROT_EXEC) as usize,
                0,
                0,
                0,
            ),
            4096,
        ));
        state.invalidate_attempted_pages(0x401000, 1, 4096);
        assert_eq!(state.active_hooks.len(), 1);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn liteinst_rejects_stack_pointer_updates_without_weakening_shared_frame() {
        let current = libc::user_regs_struct {
            rsp: 0x7fff_1000,
            ..unsafe { core::mem::zeroed() }
        };
        let requested = libc::user_regs_struct {
            rsp: current.rsp + 8,
            ..current
        };
        assert_eq!(
            validate_liteinst_user_regs_update(&current, &requested),
            Err(Errno::ENOTSUPP)
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn liteinst_helper_clears_only_abi_sensitive_transient_flags() {
        let transient = (1 << 8) | (1 << 10) | (1 << 16) | (1 << 18);
        let preserved = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 9) | (1 << 11);
        assert_eq!(
            liteinst_helper_entry_rflags(transient | preserved),
            preserved
        );
    }

    #[test]
    fn task_panic_marker_has_canonical_shape() {
        // The token and the field order are what a harness greps for; keep
        // them stable.
        let line = format_task_panic_marker(
            Pid::from_raw(4242),
            &"Clock perf counter exceeds target value" as &(dyn std::any::Any + Send),
        );
        assert_eq!(
            line,
            "HERMIT_TASK_PANIC tid=4242 exit=101 \
             message=Clock perf counter exceeds target value"
        );
        assert!(line.starts_with(TASK_PANIC_MARKER));
        assert_eq!(TASK_PANIC_MARKER, "HERMIT_TASK_PANIC");
        assert_eq!(TASK_PANIC_EXIT_CODE, 101);
    }

    #[test]
    fn task_panic_marker_is_always_one_greppable_line() {
        // A `panic!` with a formatted message arrives as `String`, and a
        // multi-line message would otherwise split the marker across lines and
        // make it unmatchable.
        let payload = String::from("first line\nsecond line\r\nthird");
        let line =
            format_task_panic_marker(Pid::from_raw(7), &payload as &(dyn std::any::Any + Send));
        assert_eq!(line.lines().count(), 1);
        assert_eq!(
            line,
            "HERMIT_TASK_PANIC tid=7 exit=101 message=first line second line  third"
        );
    }

    #[test]
    fn task_panic_marker_survives_a_non_string_payload() {
        // `panic_any(42)` carries no string. The marker must still be emitted:
        // an unreadable reason is not a reason to go back to hanging.
        let line =
            format_task_panic_marker(Pid::from_raw(9), &42u32 as &(dyn std::any::Any + Send));
        assert_eq!(
            line,
            "HERMIT_TASK_PANIC tid=9 exit=101 message=<non-string panic payload>"
        );
    }
    // These tests use the real libtest default capture, then end the child
    // process through the real fatal leaf. Regular files avoid pipe-drain waits.
    mod fatal_marker_capture_tests {
        use std::fs::File;
        use std::fs::OpenOptions;
        use std::io::Read;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::process::CommandExt;
        use std::process::Child;
        use std::process::Command;
        use std::process::ExitStatus as ProcessStatus;
        use std::process::Stdio;
        use std::time::Duration;
        use std::time::Instant;

        use super::*;

        const ROLE: &str = "REVERIE_TASK_PANIC_CAPTURE_CHILD";
        const CAPTURED: &str = "REVERIE_CAPTURE_ONLY_MUST_NOT_REACH_REAL_STDERR";
        const LOG_LIMIT: u64 = 65536;

        struct MarkerChild {
            child: Child,
            status: Option<ProcessStatus>,
            deadline: Instant,
            cleanup_deadline: Option<Instant>,
        }
        impl MarkerChild {
            fn observe_until(&mut self, deadline: Instant) -> std::io::Result<ProcessStatus> {
                loop {
                    if let Some(status) = self.child.try_wait()? {
                        self.status = Some(status);
                        if Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "marker terminal observation arrived after original bound",
                            ));
                        }
                        return Ok(status);
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "marker child exceeded original bound",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            fn finish(&mut self) -> std::io::Result<ProcessStatus> {
                if let Some(status) = self.status {
                    return Ok(status);
                }
                // This original Child has not been reaped or passed to any other
                // waiter. Never discover or signal descendants by numeric PID.
                let cleanup_deadline = *self.cleanup_deadline.get_or_insert_with(|| {
                    self.deadline.min(Instant::now() + Duration::from_secs(2))
                });
                let signal = self.child.kill();
                let result = self.observe_until(cleanup_deadline);
                if let Err(error) = &result {
                    let _ = writeln!(
                        std::io::stderr(),
                        "MARKER_OWNED_CLEANUP_UNCONFIRMED signal={signal:?} wait={error}"
                    );
                }
                result
            }
        }
        impl Drop for MarkerChild {
            fn drop(&mut self) {
                if self.status.is_none() {
                    // Unexpected Rust error/unwind does not obtain a fresh budget.
                    let _ = self.finish();
                }
            }
        }
        fn read_log(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            File::open(path)?
                .take(LOG_LIMIT + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > LOG_LIMIT {
                return Err(std::io::Error::other("marker log exceeded fixed cap"));
            }
            Ok(bytes)
        }
        fn capture_case(mode: &str, selector: &str) -> std::io::Result<()> {
            if let Some(role) = std::env::var_os(ROLE) {
                if role != mode {
                    return Err(std::io::Error::other("unexpected marker child role"));
                }
                // This self-exec child has no tracees or further children.
                // Contain an unexpected abort without relying on RLIMIT_CORE
                // to suppress an external piped core collector.
                if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
                    || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
                {
                    unsafe { libc::_exit(90) };
                }
                eprintln!("{CAPTURED}");
                writeln!(std::io::stderr(), "MARKER_CAPTURE_ENTER mode={mode}")?;
                if mode == "fatal" {
                    guest_task_panic_is_fatal(
                        Pid::from_raw(4242),
                        Box::new(String::from("first\nsecond\r\nthird")),
                    );
                }
                writeln!(std::io::stderr(), "MARKER_CAPTURE_RETURN mode=ordinary")?;
                return Ok(());
            }

            let started = Instant::now();
            let predicate_deadline = started + Duration::from_secs(3);
            let final_deadline = started + Duration::from_secs(5);
            let directory = std::env::temp_dir().join(format!(
                "reverie-marker-capture-{}-{mode}",
                std::process::id(),
            ));
            std::fs::create_dir(&directory)?; // exclusive; never reuse old logs
            let stdout_path = directory.join("stdout.log");
            let stderr_path = directory.join("stderr.log");
            let log = |path: &std::path::Path| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
            };
            let mut command = Command::new(std::env::current_exe()?);
            command
                .args([selector, "--exact", "--test-threads=1"])
                .env(ROLE, mode)
                .env_remove("RUST_TEST_NOCAPTURE")
                .stdin(Stdio::null())
                .stdout(log(&stdout_path)?)
                .stderr(log(&stderr_path)?);
            unsafe {
                command.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: LOG_LIMIT,
                        rlim_max: LOG_LIMIT,
                    };
                    if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut owned = MarkerChild {
                child: command.spawn()?,
                status: None,
                deadline: final_deadline,
                cleanup_deadline: None,
            };
            let original = owned.observe_until(predicate_deadline);
            // Seal original status/timeout before separate cleanup. All fallible
            // log reads and assertions occur after the actual owned wait.
            let retirement = owned.finish();
            let stdout = read_log(&stdout_path);
            let stderr = read_log(&stderr_path);
            let _ = writeln!(
                std::io::stderr(),
                "MARKER_CAPTURE_OBSERVED mode={mode} original={original:?} original_code={:?} retirement={retirement:?} elapsed={:?} stdout={stdout:?} stderr={stderr:?}",
                original.as_ref().ok().and_then(|status| status.code()),
                started.elapsed()
            );
            retirement?;
            let status = original?; // late cleanup never repairs the predicate
            let stdout = stdout?;
            let stderr = stderr?;
            std::fs::remove_file(&stdout_path)?;
            std::fs::remove_file(&stderr_path)?;
            std::fs::remove_dir(&directory)?;
            assert!(started.elapsed() < Duration::from_secs(5));
            assert_eq!(status.code(), Some(if mode == "fatal" { 101 } else { 0 }));
            assert!(
                !String::from_utf8_lossy(&stderr).contains(CAPTURED),
                "this discriminator must use real normal libtest capture"
            );
            let expected = if mode == "fatal" {
                b"MARKER_CAPTURE_ENTER mode=fatal\nHERMIT_TASK_PANIC tid=4242 exit=101 message=first second  third\n".as_slice()
            } else {
                b"MARKER_CAPTURE_ENTER mode=ordinary\nMARKER_CAPTURE_RETURN mode=ordinary\n"
                    .as_slice()
            };
            assert_eq!(stderr, expected, "real stderr marker missing or altered");
            assert!(String::from_utf8_lossy(&stdout).contains("running 1 test"));
            if mode == "ordinary" {
                assert!(String::from_utf8_lossy(&stdout).contains("1 passed; 0 failed"));
            } else {
                let output = String::from_utf8_lossy(&stdout);
                for returned_marker in ["... ok", "... FAILED", "test result:", "failures:"] {
                    assert!(
                        !output.contains(returned_marker),
                        "fatal leaf must not return a libtest result: {output}"
                    );
                }
            }
            Ok(())
        }
        #[test]
        fn captured_marker_survives_fatal_exit() -> std::io::Result<()> {
            capture_case(
                "fatal",
                "task::tests::fatal_marker_capture_tests::captured_marker_survives_fatal_exit",
            )
        }
        #[test]
        fn ordinary_return_uses_real_capture_without_fatal_marker() -> std::io::Result<()> {
            capture_case(
                "ordinary",
                "task::tests::fatal_marker_capture_tests::ordinary_return_uses_real_capture_without_fatal_marker",
            )
        }
    }
}
