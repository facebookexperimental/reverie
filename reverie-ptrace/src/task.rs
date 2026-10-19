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
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
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
use safeptrace::AnySignal;
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
use tokio::sync::OwnedMutexGuard;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::PtraceBackendStatsSource;
use crate::children;
use crate::cp;
use crate::error::Error;
use crate::error::TraceResultExt;
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
use crate::poll_on_wake::PollOnWake;
use crate::regs::Reg;
use crate::regs::RegAccess;
use crate::sigtrap_state::BLOCKABLE_SIGNAL_BITS;
use crate::sigtrap_state::KernelSigaction;
use crate::sigtrap_state::SIGTRAP_BIT;
use crate::sigtrap_state::SigtrapAction;
use crate::sigtrap_state::StepKind;
use crate::sigtrap_state::instruction_raises_sigtrap;
use crate::sigtrap_state::mask_after_sigprocmask;
use crate::sigtrap_state::parse_sigtrap_disposition;
use crate::sigtrap_state::step_kind;
use crate::stack::GuestStack;
use crate::timer::HandleFailure;
use crate::timer::OwnNotification;
use crate::timer::StepUnit;
use crate::timer::Timer;
use crate::timer::TimerEventRequest;
use crate::timer::Unfinished;
use crate::tracer::FatalNewborn;
use crate::tracer::FatalTaskStop;
use crate::tracer::HeldRootStop;
use crate::tracer::PtracerController;
use crate::tracer::PtracerWaitOwner;
use crate::tracer::RootStopLease;
use crate::tracer::WaitOnPtracer;
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

mod host_linux;

#[cfg(test)]
mod thread_state_ready_tests;

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
    Exec(Stopped),
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

/// Failure to establish a requested interception contract. Kernel refusal and
/// an unexpected successful reply are both failures, never reduced coverage.
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
struct CpuidFaultingUnavailable {
    place: PreinitPlace,
    operation: &'static str,
    result: Result<i64, Errno>,
}

#[cfg(target_arch = "x86_64")]
impl fmt::Display for CpuidFaultingUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ptrace-cpuid-faulting-unavailable: phase={:?} operation={} ",
            self.place, self.operation
        )?;
        match self.result {
            Ok(state) => write!(f, "observed={state}"),
            Err(errno) => write!(f, "errno={}", errno.into_raw()),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl std::error::Error for CpuidFaultingUnavailable {}

/// The actual host threads and tracee tids whose images were canonicalized.
/// The host separates independent libtests; the tid binds each count to its tracee.
#[cfg(test)]
pub(crate) static CANONICALIZED_FOR_TEST: StdMutex<Vec<(std::thread::ThreadId, i32)>> =
    StdMutex::new(Vec::new());

/// How [`TracedTask::tracee_preinit`] ended.
/// How the root's first initialization ended (`postspawn_preinit`).
pub(crate) enum PostspawnPreinit {
    /// Initialization finished, or the root exited during it.
    Outcome(PreinitOutcome),
    /// The GlobalTool reported a failed run before initialization finished;
    /// the unfinished initialization was dropped.
    GlobalToolFailed,
}

pub enum PreinitOutcome {
    /// The tracee is initialized and still stopped.
    Ready(Stopped),
    /// Initialization published a named fatal-session failure. Keep its stop
    /// owned until the ordinary task-tree driver completes consuming cleanup.
    Refused(Stopped),
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
type PostExecReturnForTest = Box<dyn FnOnce(&Stopped, &safeptrace::SyscallInfo)>;

#[cfg(test)]
thread_local! {
    static FORCED_ESRCH: std::cell::Cell<Option<Pid>> = const { std::cell::Cell::new(None) };
    static POST_EXEC_RETURN_FOR_TEST: std::cell::RefCell<Option<PostExecReturnForTest>> =
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
    Owned(oneshot::Receiver<Option<ExitStatus>>),
}

impl Future for ChildCompletion {
    type Output = Result<Option<ExitStatus>, reverie::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
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
    SignalToDeliver(Stopped, AnySignal),
}

/// Whether a stop reported as `sig` without a ptrace event is a job-control
/// group stop rather than a signal-delivery stop. Under `PTRACE_TRACEME` both
/// look identical in the wait status; only a group stop has no siginfo, so
/// `PTRACE_GETSIGINFO` fails with `EINVAL` (see ptrace(2), "Group-stop").
fn is_group_stop(task: &Stopped, sig: impl Into<AnySignal>) -> Result<bool, TraceError> {
    // A realtime signal (one nix cannot name) is never a stop signal.
    if !matches!(
        sig.into().as_nix(),
        Some(Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU)
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
fn is_group_stop_unless_filtered(
    task: &Stopped,
    sig: impl Into<AnySignal>,
) -> Result<bool, TraceError> {
    let sig = sig.into();
    if !matches!(
        sig.as_nix(),
        Some(Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU)
    ) || thread_may_be_seccomp_filtered()
    {
        return Ok(false);
    }
    is_group_stop(task, sig)
}

/// The bit for `sig` in a kernel signal mask as read by `PTRACE_GETSIGMASK`.
fn signal_mask_bit(sig: impl Into<AnySignal>) -> u64 {
    1u64 << (sig.into().raw() - 1)
}

/// A copy of a stop's siginfo, kept to be written back with
/// `PTRACE_SETSIGINFO`. From libc 0.2.190 `siginfo_t` holds a raw pointer
/// (`si_addr`), so it is neither `Send` nor `Sync`, and a task that keeps one
/// could no longer be a `Guest`.
#[derive(Clone, Copy)]
pub(crate) struct StoredSiginfo(pub(crate) libc::siginfo_t);

// SAFETY: the tracer only copies these bytes and hands them back to the
// kernel. It never dereferences the pointer fields, which are addresses in
// the guest's address space, not the tracer's.
unsafe impl Send for StoredSiginfo {}
// SAFETY: as above; a shared reference only reads the copied bytes.
unsafe impl Sync for StoredSiginfo {}

/// What a single step of the private-page `syscall` instruction observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateStep {
    /// The stop is still at the `syscall` instruction: a signal was already
    /// pending when the step began, so the syscall never executed.
    NotRun,
    /// The single-step report after the `syscall` instruction. Its `rax` is
    /// the raw kernel result, which may itself be a restart code whose
    /// interrupting signal is still kernel-pending.
    Ran,
    /// A non-SIGTRAP stop after the instruction: the syscall ran, and the
    /// step returned a signal it could not requeue (after a syscall that
    /// swaps in a temporary signal mask). `rax` is the kernel's result; the
    /// signal is held for delivery and the step's own SIGTRAP stays queued,
    /// to be discarded as stale by its siginfo.
    Held,
    /// A stop anywhere else, which no private-page step can produce.
    Unexpected,
}

/// The realtime signals, 32 to 64, as bits of a kernel signal mask (bit
/// `n - 1` for signal `n`).
const REALTIME_SIGNAL_BITS: u64 = !0u64 << 31;

/// The signals an injection never shields (`step_shielded_injection`): the
/// timer's own signal and SIGTRAP, which the private-page step handles, and
/// SIGKILL and SIGSTOP, which cannot be blocked.
const NEVER_SHIELDED: u64 = 1 << (reverie::PERF_EVENT_SIGNAL as u64 - 1)
    | 1 << (Signal::SIGTRAP as u64 - 1)
    | 1 << (Signal::SIGKILL as u64 - 1)
    | 1 << (Signal::SIGSTOP as u64 - 1);

/// Whether the registers of the syscall `nr` with `args` may name a temporary
/// signal mask that `temporary_signal_mask` reads: a non-NULL mask argument
/// of size 8, or, for pselect6, a non-NULL wrapper. Checked before any read
/// or ptrace request, so a call that installs no mask, such as a wait probe
/// with a NULL mask, costs nothing.
fn may_name_temporary_signal_mask(nr: Sysno, args: &SyscallArgs) -> bool {
    match nr {
        Sysno::rt_sigsuspend => args.arg0 != 0 && args.arg1 == 8,
        Sysno::ppoll => args.arg3 != 0 && args.arg4 == 8,
        Sysno::epoll_pwait | Sysno::epoll_pwait2 => args.arg4 != 0 && args.arg5 == 8,
        Sysno::pselect6 => args.arg5 != 0,
        _ => false,
    }
}

/// The temporary signal mask that the syscall `nr` with `args` installs, read
/// from the tracee: ppoll's, pselect6's, epoll_pwait's and epoll_pwait2's
/// mask argument, or rt_sigsuspend's. `None` when the call installs none (a
/// NULL mask), names a size other than 8, or names memory that is not mapped.
///
/// The words are read with `PTRACE_PEEKDATA`, which, like the kernel's own
/// `copy_from_user`, reads an x86 write-only mapping: a valid write-only mask
/// is shielded as a readable one is (Codex review of
/// https://github.com/rrnewton/reverie/pull/996). It also reads a `PROT_NONE`
/// page, which the kernel's copy faults on. Such a call is shielded too: it
/// still fails with EFAULT at entry, before it would wait, and a pending
/// signal is then taken after it returns, as it is after the guest's own
/// call. io_pgetevents and io_uring_enter are not read.
fn temporary_signal_mask(task: &Stopped, nr: Sysno, args: &SyscallArgs) -> Option<u64> {
    let read = |address: usize| task.read_value(Addr::<u64>::from_raw(address)?).ok();
    let (mask, size) = match nr {
        Sysno::rt_sigsuspend => (args.arg0, args.arg1),
        Sysno::ppoll => (args.arg3, args.arg4),
        Sysno::epoll_pwait | Sysno::epoll_pwait2 => (args.arg4, args.arg5),
        Sysno::pselect6 => {
            // A `{ const sigset_t *ss; size_t ss_len; }` wrapper.
            let wrapper = args.arg5;
            if wrapper == 0 {
                return None;
            }
            (
                read(wrapper)? as usize,
                read(wrapper.checked_add(8)?)? as usize,
            )
        }
        _ => return None,
    };
    if mask == 0 || size != 8 {
        return None;
    }
    read(mask)
}

/// Classifies the signal-delivery stop that ended a private-page step.
fn classify_private_step(
    ip: u64,
    signal: impl Into<AnySignal>,
    private_syscall: u64,
    syscall_len: u64,
) -> PrivateStep {
    let signal = signal.into();
    if ip == private_syscall {
        PrivateStep::NotRun
    } else if Some(ip) == private_syscall.checked_add(syscall_len) {
        if signal == Signal::SIGTRAP {
            PrivateStep::Ran
        } else {
            PrivateStep::Held
        }
    } else {
        PrivateStep::Unexpected
    }
}

/// A signal as its signal-delivery stop took it from the kernel, with its
/// siginfo.
#[derive(Clone, Copy)]
struct TakenSignal {
    signal: AnySignal,
    siginfo: StoredSiginfo,
    /// The same siginfo's bytes, as the kernel wrote them
    /// (`Stopped::getsiginfo_bytes`), which a Tool sees.
    bytes: SiginfoBytes,
}

impl TakenSignal {
    /// Reads the record of `signal` at its signal-delivery stop, `None` if
    /// the stop's siginfo cannot be read, or if the tracer thread may be
    /// under a seccomp filter (`thread_may_be_seccomp_filtered`). Main makes
    /// no `PTRACE_GETSIGINFO` at these stops, and a filter can refuse it or
    /// kill the tracer at it. Without the record, the signal is resumed as
    /// main resumes it, and nothing is restored or counted for it
    /// (`resume_with_signal`).
    fn at_stop(task: &Stopped, signal: AnySignal) -> Option<Self> {
        if thread_may_be_seccomp_filtered() {
            return None;
        }
        let bytes = task.getsiginfo_bytes().ok()?;
        Some(Self {
            signal,
            siginfo: StoredSiginfo::from_bytes(&bytes),
            bytes,
        })
    }
}

/// The signal a stopped guest resumes with, and, if
/// `Tool::handle_signal_event` reported it, how its delivery stop took it.
struct SignalResume {
    signal: Option<AnySignal>,
    reported: Option<TakenSignal>,
    /// Whether the reporting callback approved the signal's delivery
    /// (`Guest::deliver_signal`): its siginfo must then be the one its stop
    /// recorded, so restoring it is no longer best-effort.
    approved: bool,
    /// The siginfo the reporting callback chose for the signal
    /// (`Guest::set_signal_info`), written when the signal is resumed from a
    /// signal-delivery stop (`resume_with_signal`).
    replacement: Option<(AnySignal, SiginfoBytes)>,
}

/// A delivery that `Guest::deliver_signal` approved in the running signal
/// callback, after every check against the kernel passed.
#[derive(Clone, Copy, Debug)]
struct SignalApproval {
    /// The approved signal: the one the callback reports.
    signal: AnySignal,
    /// Whether an injection completed (`note_injection_stop`), or the Tool
    /// wrote the registers (`Guest::set_regs`), after the approval. The
    /// thread is then at another stop, or in another state, than the one the
    /// checks read, so the approval no longer holds.
    voided: bool,
}

/// What `Tool::handle_signal_event` left for a signal (`report_signal`).
struct SignalVerdict {
    /// The signal to resume with, `None` if the callback suppressed it.
    signal: Option<AnySignal>,
    /// Whether the callback approved `signal`'s delivery
    /// (`Guest::deliver_signal`), and the approval held when it returned.
    approved: bool,
    /// The siginfo the callback chose for its signal, with that signal
    /// (`Guest::set_signal_info`).
    replacement: Option<(AnySignal, SiginfoBytes)>,
}

/// Why a signal callback's verdict `signal` breaks the delivery it approved
/// (`Guest::deliver_signal`), if it does: an injection after the approval
/// voided it, or the callback returns another signal or none.
fn approval_violation(approval: SignalApproval, signal: Option<AnySignal>) -> Option<&'static str> {
    if approval.voided {
        Some(
            "an injection or a register write after the approval changed the stop it was checked at",
        )
    } else if signal != Some(approval.signal) {
        Some("the callback returned another signal or none")
    } else {
        None
    }
}

/// Linux's `siginfo_t` as bytes, the form a Tool reads and writes.
type SiginfoBytes = [u8; reverie::SIGNAL_INFO_SIZE];

impl StoredSiginfo {
    /// The `siginfo_t` whose bytes are `bytes`. Built in place from zeroed,
    /// then fully written, storage, so no byte is undefined, padding included.
    fn from_bytes(bytes: &SiginfoBytes) -> Self {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: `siginfo_t` is `SIGNAL_INFO_SIZE` bytes on the supported
        // targets; the copy fills all of them, and any bytes are a valid
        // `siginfo_t` to copy and hand to the kernel.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                info.as_mut_ptr().cast::<u8>(),
                reverie::SIGNAL_INFO_SIZE.min(std::mem::size_of::<libc::siginfo_t>()),
            );
            Self(info.assume_init())
        }
    }
}

/// A procfs text file (`status`, `maps`), read as bytes and decoded lossily:
/// `status`'s `Name:` line holds the thread's name as the thread set it,
/// which need not be UTF-8 (`prctl(PR_SET_NAME)` takes any bytes), and a
/// `maps` path is any file name; a strict decode would fail with no errno,
/// which the callers would read as a thread that is gone. Every field Reverie
/// reads from them is ASCII.
fn read_status<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<String> {
    crate::launch_window::read(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Whether a SIGTRAP is queued for the stopped `task`, in its own signal
/// queue or its thread group's (`PTRACE_PEEKSIGINFO`).
fn sigtrap_queued(task: &Stopped) -> Result<bool, TraceError> {
    for flags in [None, Some(safeptrace::PeekSigInfoFlags::SHARED)] {
        if task
            .peeksiginfo_any(flags, |info| info.si_signo == libc::SIGTRAP)
            .map_err(|error| dead_or(task, error))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether syscall `nr` with `args` is an `rt_sigaction` that may set
/// SIGTRAP's action: the kernel takes the signal from the low 32 bits.
fn sets_sigtrap_action(nr: Sysno, args: &SyscallArgs) -> bool {
    nr == Sysno::rt_sigaction && args.arg0 as i32 == libc::SIGTRAP && args.arg1 != 0
}

/// The signal mask the kernel dequeues under for the stopped thread `tid`
/// (`task->blocked`, procfs `SigBlk`).
///
/// `PTRACE_GETSIGMASK` reports the saved mask instead while a mask-swapping
/// syscall's restore is pending (`TIF_RESTORE_SIGMASK`), so it cannot tell
/// whether that syscall's temporary mask blocks a signal.
fn blocked_signal_mask(tid: Pid) -> Result<u64, TraceError> {
    let status = read_status(format!("/proc/{tid}/status"))
        .map_err(|err| Errno::new(err.raw_os_error().unwrap_or(libc::EIO)))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| Errno::EPROTO.into())
}

/// `PTRACE_GETSIGMASK`, with an error from a tracee that died passed
/// through `dead_or`, so that the paths that handle a killed tracee take it.
fn sigmask(task: &Stopped) -> Result<u64, TraceError> {
    task.getsigmask().map_err(|error| dead_or(task, error))
}

/// `PTRACE_SETSIGMASK`, with errors passed through `dead_or` as in `sigmask`.
fn set_sigmask(task: &Stopped, mask: u64) -> Result<(), TraceError> {
    task.setsigmask(mask).map_err(|error| dead_or(task, error))
}

/// The signal masks procfs reports for a stopped thread, read once
/// (`/proc/<tid>/status`).
#[derive(Clone, Copy, Debug)]
struct ProcSignalState {
    /// The mask the kernel dequeues under (`SigBlk`); it differs from
    /// `PTRACE_GETSIGMASK` while a temporary mask's restore is pending.
    blocked: u64,
    /// The thread's and the thread group's pending signals (`SigPnd`,
    /// `ShdPnd`).
    pending: u64,
    /// Whether SIGTRAP is ignored (`SigIgn`) and whether it is caught
    /// (`SigCgt`).
    sigtrap_ignored: bool,
    sigtrap_caught: bool,
}

impl ProcSignalState {
    /// Reads the state of `task`. A thread that is gone reads as procfs's
    /// `ENOENT`; it is reported as a ptrace request on it would be, through
    /// `dead_or`, so that the paths that handle a killed tracee take it.
    fn read(task: &Stopped) -> Result<Self, TraceError> {
        let tid = task.pid();
        let status = read_status(format!("/proc/{tid}/status")).map_err(|err| {
            let errno = match err.raw_os_error() {
                Some(libc::ENOENT) | None => Errno::ESRCH,
                Some(raw) => Errno::new(raw),
            };
            dead_or(task, errno.into())
        })?;
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .ok_or(Errno::EPROTO)
        };
        let (sigtrap_ignored, sigtrap_caught) =
            parse_sigtrap_disposition(&status).ok_or(Errno::EPROTO)?;
        Ok(Self {
            blocked: field("SigBlk:")?,
            pending: field("SigPnd:")? | field("ShdPnd:")?,
            sigtrap_ignored,
            sigtrap_caught,
        })
    }
}

/// What `unblock_sigtrap_for_step_with` did before a Reverie single-step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepShield {
    /// Nothing: SIGTRAP is not blocked, or a temporary mask's restore is
    /// pending, which a mask write would discard (`swaps_signal_mask`).
    None,
    /// SIGTRAP was unblocked, to be blocked again at the step's stop.
    Unblocked,
    /// A blocked SIGTRAP is pending: no step can keep it, because the step's
    /// trap is absorbed into it while SIGTRAP is blocked, and it is taken
    /// before the instruction while unblocked. Nothing was changed; the run
    /// must end (`PendingSigtrapAtStep`).
    PendingTrap,
}

/// Unblocks SIGTRAP for one Reverie single-step (`sigtrap_state`'s shield),
/// with the mask `PTRACE_GETSIGMASK` reported. procfs is read only when
/// SIGTRAP is blocked.
fn unblock_sigtrap_for_step_with(task: &Stopped, mask: u64) -> Result<StepShield, TraceError> {
    unblock_sigtrap_for_step_known(task, mask, None)
}

/// `unblock_sigtrap_for_step_with`, with `known` the procfs state read for
/// this same stop, if it was (`TracedTask::injection_proc_state`).
fn unblock_sigtrap_for_step_known(
    task: &Stopped,
    mask: u64,
    known: Option<ProcSignalState>,
) -> Result<StepShield, TraceError> {
    if mask & SIGTRAP_BIT == 0 {
        return Ok(StepShield::None);
    }
    let state = match known {
        Some(state) => state,
        None => ProcSignalState::read(task)?,
    };
    if state.pending & SIGTRAP_BIT != 0 {
        return Ok(StepShield::PendingTrap);
    }
    if state.blocked != mask {
        return Ok(StepShield::None);
    }
    set_sigmask(task, mask & !SIGTRAP_BIT)?;
    Ok(StepShield::Unblocked)
}

/// Blocks SIGTRAP again at the stop a step shielded by
/// `unblock_sigtrap_for_step_with` ended at, keeping any other change the stepped
/// instruction made to the mask.
fn reblock_sigtrap_after_step(wait: &Wait) -> Result<(), TraceError> {
    if let Wait::Stopped(stopped, _) = wait {
        let mask = sigmask(stopped)?;
        set_sigmask(stopped, mask | SIGTRAP_BIT)?;
    }
    Ok(())
}

/// SIGTRAP's state across the single-steps of one timer sequence
/// (`sigtrap_state`), shared by `drive_timer`'s step and observe closures.
#[derive(Default)]
struct TimerStepShield {
    /// Whether SIGTRAP is ignored for this sequence, read once at its start
    /// (`TracedTask::sigtrap_ignored`).
    ignored: bool,
    /// Whether no step of this sequence can reset SIGTRAP: it is neither
    /// ignored nor blocked at the start, and a step can change neither,
    /// because every syscall that could stops the step at its seccomp stop
    /// (`GlobalState::traces_signal_state_syscalls`). Then nothing is read or
    /// written per step.
    quiet: bool,
    /// Whether any step of the sequence ran.
    stepped: bool,
    /// Whether a step ran an instruction that raises its own SIGTRAP, whose
    /// reset is native, so that no repair follows.
    native_trap: bool,
    /// Whether a step met a pending, blocked SIGTRAP, which no step can keep
    /// (`PendingSigtrapAtStep`); the step was not made.
    pending_trap: bool,
    /// Whether SIGTRAP is to be blocked again at the step's stop.
    reblock: bool,
    /// For a step over a guest `rt_sigreturn` whose frame blocks SIGTRAP: the
    /// frame mask's address and value, and the step's rip. SIGTRAP is cleared
    /// from the frame for the step, so that its trap cannot see it blocked.
    frame_mask: Option<(usize, u64, u64)>,
}

impl TimerStepShield {
    /// Before a step: shield SIGTRAP as `unblock_sigtrap_for_step_with` does, or,
    /// for a guest `rt_sigreturn`, in the frame it restores.
    fn prepare(&mut self, task: &Stopped) -> Result<(), TraceError> {
        if self.quiet {
            self.stepped = true;
            return Ok(());
        }
        let regs = task.getregs()?;
        // A guest `int3` (or `int 3`, `int1`, behind any prefixes) resets a
        // blocked or ignored SIGTRAP natively, and natively the process then
        // takes SIGTRAP's default action; neither the shield nor a repair may
        // undo that. With SIGTRAP neither blocked nor ignored, its trap resets
        // nothing, so the instruction is decoded only otherwise.
        let mask = sigmask(task)?;
        let sensitive = self.ignored || mask & SIGTRAP_BIT != 0;
        if sensitive && instruction_at_raises_sigtrap(task, regs.ip()) {
            self.stepped = true;
            self.native_trap = true;
            return Ok(());
        }
        #[cfg(target_arch = "x86_64")]
        if let Some((address, rip)) = sigreturn_frame_mask_address(task, &regs)? {
            let frame = Addr::<u64>::from_raw(address).ok_or(Errno::EFAULT)?;
            let mask: u64 = task.read_value(frame)?;
            if mask & SIGTRAP_BIT != 0 {
                let frame = AddrMut::<u64>::from_raw(address).ok_or(Errno::EFAULT)?;
                task.generation()
                    .assume_stopped()
                    .write_value(frame, &(mask & !SIGTRAP_BIT))?;
                self.frame_mask = Some((address, mask, rip));
                #[cfg(test)]
                FRAME_SHIELDS_FOR_TEST.fetch_add(1, Ordering::SeqCst);
            }
            self.stepped = true;
            return Ok(());
        }
        match unblock_sigtrap_for_step_with(task, mask)? {
            StepShield::None => {}
            StepShield::Unblocked => self.reblock = true,
            StepShield::PendingTrap => {
                self.pending_trap = true;
                return Err(Errno::ECANCELED.into());
            }
        }
        self.stepped = true;
        Ok(())
    }

    /// At the step's stop: put back what `prepare` changed. After a frame
    /// shield, the restored mask lacks SIGTRAP only if the `rt_sigreturn` ran
    /// (rip moved, and the stop is not its seccomp stop).
    fn settle(&mut self, task: &Stopped) -> Result<(), TraceError> {
        let mut reblock = std::mem::take(&mut self.reblock);
        if let Some((address, mask, rip)) = self.frame_mask.take() {
            let frame = AddrMut::<u64>::from_raw(address).ok_or(Errno::EFAULT)?;
            // The frame is dead once restored; it is written back so that a
            // stop before the instruction leaves it as the guest wrote it.
            let _ = task.generation().assume_stopped().write_value(frame, &mask);
            reblock = task.getregs()?.ip() != rip;
        }
        if reblock {
            let mask = sigmask(task)?;
            set_sigmask(task, mask | SIGTRAP_BIT)?;
        }
        Ok(())
    }
}

/// If the task's next instruction is a guest `rt_sigreturn` (a `syscall`
/// with rax 15), the address of the mask in the frame it restores, and the
/// instruction's address.
#[cfg(target_arch = "x86_64")]
fn sigreturn_frame_mask_address(
    task: &Stopped,
    regs: &libc::user_regs_struct,
) -> Result<Option<(usize, u64)>, TraceError> {
    if regs.rax != libc::SYS_rt_sigreturn as u64 {
        return Ok(None);
    }
    let Some(ip) = Addr::<[u8; 2]>::from_raw(regs.rip as usize) else {
        return Ok(None);
    };
    if task.read_value(ip).ok() != Some([0x0f, 0x05]) {
        return Ok(None);
    }
    Ok(Some((
        regs.rsp as usize + crate::sigtrap_state::SIGRETURN_UC_SIGMASK_OFFSET,
        regs.rip,
    )))
}

/// What a private-page step decided about SIGTRAP, at the step itself
/// (`TracedTask::step_private_syscall`).
#[derive(Clone, Copy, Debug)]
struct StepChoice {
    /// The step ran without the shield although the guest's mask, `Some` of
    /// which this is, blocked SIGTRAP (`TracedTask::may_unshield_step`).
    unshielded_mask: Option<u64>,
    /// The shield unblocked SIGTRAP for the step.
    shielded: bool,
}

/// What an injection's single-step can change of SIGTRAP's state, read
/// before the injection (`TracedTask::read_sigtrap_before_injection`).
struct SigtrapBeforeInjection {
    /// Whether the step can reset nothing, so that nothing is read after it
    /// (`read_sigtrap_before_injection`'s quiet case); the other fields then
    /// hold only `kind` and `mask`.
    quiet: bool,
    kind: StepKind,
    /// The blocked mask before the injection, as `PTRACE_GETSIGMASK` reports
    /// it.
    mask: u64,
    /// The mask the kernel blocked under (procfs `SigBlk`).
    blocked: u64,
    /// Whether SIGTRAP was ignored before the injection (procfs `SigIgn`).
    ignored: bool,
    /// SIGTRAP's handler before an injection whose trap may reset it, if
    /// SIGTRAP was caught (procfs `SigCgt`) and the action could be read.
    caught_action: Option<KernelSigaction>,
    /// For an injected `rt_sigaction(SIGTRAP, act)`: the action it sets.
    sets_action: Option<SigtrapAction>,
    /// For the same call: `act`'s address, and whether it asked for the old
    /// action (`oldact` not null).
    sigaction_call: Option<(usize, bool)>,
    /// For an injected `rt_sigprocmask`: the mask it sets.
    sets_mask: Option<u64>,
    /// For a mask-swapping injection: its temporary mask, if it can be read.
    temporary_mask: Option<u64>,
}

/// Whether SIGTRAP is ignored and whether it is caught for the stopped
/// `task` (procfs `SigIgn` and `SigCgt`).
fn sigtrap_disposition(task: &Stopped) -> Result<(bool, bool), TraceError> {
    let state = ProcSignalState::read(task)?;
    Ok((state.sigtrap_ignored, state.sigtrap_caught))
}

/// SIGTRAP's action as a Reverie trap reset it, to be written back
/// (`sigtrap_state`). The reset sets the handler to `SIG_DFL` and keeps the
/// flags, mask and restorer.
#[derive(Clone, Copy, Debug)]
enum SigtrapRepair {
    /// SIGTRAP was ignored: `SIG_IGN` goes back, with the rest as kept.
    Ignored,
    /// SIGTRAP's whole action before the reset.
    Action(KernelSigaction),
}

/// The SIGTRAP repairs owed, by signal-action table (`sigtrap_state`). A
/// table is the kernel's `sighand`: every thread of a group uses its group's,
/// and a clone with `CLONE_SIGHAND` but not `CLONE_THREAD` makes another
/// group that uses the same one. A fork copies it, with any repair it owes,
/// and an exec moves its group to a copy of its own. Tables are named by
/// number, never reused.
#[derive(Debug, Default)]
struct SigtrapTables {
    /// The last table number given out.
    last: u64,
    /// The repair each table owes.
    repairs: HashMap<u64, SigtrapRepair>,
    /// The live thread groups that use each table.
    users: HashMap<u64, HashSet<Pid>>,
    /// The tables that a second thread has used: a thread cloned with
    /// `CLONE_THREAD` into a group that uses it, or another group made with
    /// `CLONE_SIGHAND`. Marked when the creator's clone event is handled,
    /// before the new thread runs, and never cleared while the table lives:
    /// an exec moves its group to a fresh copy, and a fork child gets one
    /// (`copy`). So a table is unshared only while exactly one thread has ever
    /// used it, which no other thread's timing can change. Detcore may let
    /// another thread of the table run while an injected call blocks, and
    /// the step's trap resets whatever action is in force when it fires, so
    /// steps on a shared table keep the shield
    /// (`read_sigtrap_before_injection`).
    shared: HashSet<u64>,
    /// Whether SIGTRAP is ignored and whether it is caught in each table,
    /// where it is known (`TracedTask::sigtrap_disposition_known`).
    ignored: HashMap<u64, (bool, bool)>,
    /// The tables an `rt_sigaction` of SIGTRAP may be changing, each with the
    /// threads that made one, until each such thread's next seccomp stop or
    /// its exit. While a table has any, its disposition is read afresh.
    changing: HashMap<u64, HashSet<Pid>>,
}

impl SigtrapTables {
    /// A new table for `group`, a copy of `from` with the repair it owes.
    fn copy(&mut self, group: Pid, from: Option<u64>) -> u64 {
        self.last += 1;
        let table = self.last;
        if let Some(repair) = from.and_then(|from| self.repairs.get(&from).copied()) {
            self.repairs.insert(table, repair);
        }
        if let Some(ignored) = from.and_then(|from| self.ignored.get(&from).copied()) {
            self.ignored.insert(table, ignored);
        }
        self.users.entry(table).or_default().insert(group);
        table
    }

    /// `group` uses `table` too.
    fn share(&mut self, group: Pid, table: u64) -> u64 {
        self.users.entry(table).or_default().insert(group);
        self.shared.insert(table);
        table
    }

    /// A second thread of a group uses `table`.
    fn add_thread(&mut self, table: u64) {
        self.shared.insert(table);
    }

    /// `group` no longer uses `table`; a table no live group uses owes
    /// nothing.
    fn leave(&mut self, group: Pid, table: u64) {
        if let Some(users) = self.users.get_mut(&table) {
            users.remove(&group);
            if users.is_empty() {
                self.users.remove(&table);
                self.repairs.remove(&table);
                self.ignored.remove(&table);
                self.changing.remove(&table);
                self.shared.remove(&table);
            }
        }
    }
}

#[cfg(test)]
mod sigtrap_tables_tests {
    use super::*;

    /// A fork copies the owed repair, a `CLONE_SIGHAND` process shares it,
    /// and a table owes nothing once its last group leaves it.
    #[test]
    fn a_repair_follows_the_table_it_is_owed_to() {
        let (a, b, c) = (Pid::from_raw(10), Pid::from_raw(11), Pid::from_raw(12));
        let mut tables = SigtrapTables::default();
        let first = tables.copy(a, None);
        tables.repairs.insert(first, SigtrapRepair::Ignored);
        let shared = tables.share(b, first);
        assert_eq!(shared, first);
        let forked = tables.copy(c, Some(first));
        assert_ne!(forked, first);
        assert!(matches!(
            tables.repairs.get(&forked),
            Some(SigtrapRepair::Ignored)
        ));
        tables.repairs.remove(&forked);
        assert!(tables.repairs.contains_key(&first));
        tables.leave(a, first);
        assert!(tables.repairs.contains_key(&first), "b still uses it");
        tables.leave(b, first);
        assert!(!tables.repairs.contains_key(&first));
        assert!(!tables.users.contains_key(&first));
    }
}

/// Whether `pid`'s address space, a fork's child at its fork event, has a
/// read-write mapping at Reverie's SIGTRAP repair page (`cp::SCRATCH_BASE`),
/// by procfs `maps`. The child has not run, and its parent's page is sealed,
/// so such a mapping can only be the kernel's sealed copy of it; `maps` tells
/// that without the page-table walk `smaps` makes. Unreadable is false.
fn repair_page_sealed_in(pid: Pid) -> bool {
    let Ok(maps) = read_status(format!("/proc/{pid}/maps")) else {
        return false;
    };
    maps.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
            return false;
        };
        let Some((low, high)) = range.split_once('-') else {
            return false;
        };
        matches!(
            (usize::from_str_radix(low, 16), usize::from_str_radix(high, 16)),
            (Ok(low), Ok(high)) if low <= cp::SCRATCH_BASE && cp::SCRATCH_BASE < high
        ) && perms.starts_with("rw")
    })
}

/// Whether the creator of a new process made it share its address space
/// (`CLONE_VM`), read from the creating `clone` or `clone3` at its ptrace
/// event stop as `shares_signal_actions` reads `CLONE_SIGHAND`. A `vfork`
/// shares it too, which its event tells (`ChildOp::Vfork`).
fn shares_address_space(parent: &Stopped) -> bool {
    clone_flags(parent).is_some_and(|flags| flags & libc::CLONE_VM as u64 != 0)
}

/// The flags of the `clone` or `clone3` a new process's creator is stopped
/// in at its ptrace event stop, if it made one of those.
fn clone_flags(parent: &Stopped) -> Option<u64> {
    let regs = parent.getregs().ok()?;
    match Sysno::new(regs.orig_syscall() as usize) {
        Some(Sysno::clone) => Some(regs.args().0),
        Some(Sysno::clone3) => Addr::<u64>::from_raw(regs.args().0 as usize)
            .and_then(|address| parent.read_value(address).ok()),
        _ => None,
    }
}

/// Whether the creator of a new process made it share its signal-action
/// table (`CLONE_SIGHAND`), read from the creating syscall at its ptrace
/// event stop: `clone`'s flags argument, or `clone3`'s `clone_args.flags`.
/// `fork` and `vfork` copy the table.
fn shares_signal_actions(parent: &Stopped) -> bool {
    clone_flags(parent).is_some_and(|flags| flags & libc::CLONE_SIGHAND as u64 != 0)
}

/// Whether the instruction at `rip` raises a SIGTRAP of its own (`int3`,
/// `int 3` or `int1`, behind any prefixes: `instruction_raises_sigtrap`). Its
/// `force_sig` resets a blocked or ignored SIGTRAP natively too, so a step
/// over it is neither shielded nor repaired. Up to 15 bytes are read, the
/// longest instruction, as aligned words with `PTRACE_PEEKDATA` (an 8-byte
/// read), which reads an execute-only page as the CPU fetches it, where
/// `process_vm_readv` fails; the read stops at the first unreadable word.
fn instruction_at_raises_sigtrap(task: &Stopped, rip: u64) -> bool {
    let rip = rip as usize;
    let start = rip & !7;
    let mut bytes = [0u8; 24];
    let mut len = 0;
    while len < bytes.len() && start + len < rip + 15 {
        let word =
            Addr::<u64>::from_raw(start + len).and_then(|address| task.read_value(address).ok());
        let Some(word) = word else {
            break;
        };
        bytes[len..len + 8].copy_from_slice(&word.to_ne_bytes());
        len += 8;
    }
    let skip = rip - start;
    instruction_raises_sigtrap(bytes.get(skip..len).unwrap_or(&[]))
}

/// `instruction_at_raises_sigtrap` at the task's current rip.
fn next_instruction_raises_sigtrap(task: &Stopped) -> Result<bool, TraceError> {
    let rip = task.getregs()?.ip();
    Ok(instruction_at_raises_sigtrap(task, rip))
}

/// Reads a guest `struct sigaction` at `address`: a page the guest made
/// write-only is readable to the kernel, but not to `process_vm_readv`, so the
/// struct is read again as four words with `PTRACE_PEEKDATA`. That a read
/// succeeds says nothing of whether the kernel's own copy will: `PTRACE_PEEKDATA`
/// also reads a `PROT_NONE` page, and a foreign read ignores the guest's
/// protection keys. Whether the call installed it is decided from the call's
/// result (`repair_sigtrap_after_injection`).
fn read_sigaction_forced(task: &Stopped, address: usize) -> Option<KernelSigaction> {
    if let Some(action) =
        Addr::<KernelSigaction>::from_raw(address).and_then(|address| task.read_value(address).ok())
    {
        return Some(action);
    }
    let word = |offset: usize| {
        Addr::<u64>::from_raw(address.checked_add(offset)?)
            .and_then(|address| task.read_value(address).ok())
    };
    Some(KernelSigaction {
        handler: word(0)?,
        flags: word(8)?,
        restorer: word(16)?,
        mask: word(24)?,
    })
}

/// The signals pending in the kernel for the stopped thread `tid`: its own
/// and its thread group's (procfs `SigPnd` and `ShdPnd`).
fn pending_signal_mask(tid: Pid) -> Result<u64, TraceError> {
    let status = read_status(format!("/proc/{tid}/status"))
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
    read_status("/proc/thread-self/status")
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

/// The mask `Guest::set_blocked_signals` writes for a requested `mask` over
/// the thread's `old` one: the request, except that the signals no injection
/// shields (`NEVER_SHIELDED`) keep their bits from `old`. So the call never
/// blocks SIGTRAP or the timer signal for the guest, and never unblocks one
/// the guest blocked itself; putting `old` back restores it exactly.
fn mask_keeping_never_shielded(mask: u64, old: u64) -> u64 {
    (mask & !NEVER_SHIELDED) | (old & NEVER_SHIELDED)
}

/// Whether `Guest::set_blocked_signals` may change the mask at the current
/// stop, given the callback state: only in `Tool::handle_syscall_event`
/// (`in_syscall_callback`), outside a frame-mode event (`frame_mode`), whose
/// registers live in an e9tool frame rather than the stopped thread, and
/// outside a signal callback (`in_signal_callback`, which a held signal's
/// callback also sets), and only on a tracer thread that no seccomp filter
/// may restrict (`seccomp_filtered`), as for the temporary shield.
fn may_set_blocked_signals(
    in_syscall_callback: bool,
    frame_mode: bool,
    in_signal_callback: bool,
    seccomp_filtered: bool,
) -> bool {
    in_syscall_callback && !frame_mode && !in_signal_callback && !seccomp_filtered
}

/// `Guest::set_blocked_signals`'s answer to a ptrace mask request that
/// failed with `error`: the thread is gone, or the request failed with an
/// errno and left the mask as it was (`mask_unknown` false) or unknown.
fn mask_change_failure(error: TraceError, mask_unknown: bool) -> reverie::MaskChangeRefused {
    match error {
        TraceError::Died(_) => reverie::MaskChangeRefused::Gone,
        TraceError::Errno(errno) => reverie::MaskChangeRefused::Failed {
            errno,
            mask_unknown,
        },
    }
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

/// The number of seccomp filters on thread `tid` (procfs `Seccomp_filters`),
/// or `None` if it cannot be read.
/// Whether thread group `pid` has a thread other than `tid` that has not
/// exited, as procfs lists them (`/proc/<pid>/task`, and each thread's `stat`
/// state): a thread Reverie does not trace counts, and an exited one that
/// has not been reaped (state `Z` or `X`) does not. Anything that cannot be
/// read counts as another thread.
fn group_has_other_live_threads(pid: Pid, tid: Pid) -> bool {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return true;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return true;
        };
        let name = entry.file_name();
        let Some(other) = name.to_str().and_then(|name| name.parse::<i32>().ok()) else {
            return true;
        };
        if other == tid.as_raw() {
            continue;
        }
        match std::fs::read(format!("/proc/{pid}/task/{other}/stat")) {
            Ok(stat) => {
                // The state follows the command name's closing parenthesis.
                let state = stat
                    .iter()
                    .rposition(|&byte| byte == b')')
                    .and_then(|close| stat.get(close + 2).copied());
                if !matches!(state, Some(b'Z' | b'X')) {
                    return true;
                }
            }
            // Gone since the listing: it has been reaped.
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
            Err(_) => return true,
        }
    }
    false
}

fn guest_seccomp_filters(tid: Pid) -> Option<u64> {
    let status = read_status(format!("/proc/{tid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .and_then(|count| count.trim().parse().ok())
}

/// The states of an address space's SIGTRAP repair page
/// (`TracedTask::sigtrap_scratch_state`): not set up yet (a new image before
/// pre-init), sealed, or none.
const SCRATCH_PENDING: u8 = 0;
const SCRATCH_SEALED: u8 = 1;
const SCRATCH_UNAVAILABLE: u8 = 2;

/// `mseal(2)`'s number on x86-64 (Linux 6.10), which `Sysno` does not name.
const SYS_MSEAL: Reg = 462;

/// The `si_code` of a SIGILL for an illegal operand (`ud2`), which `libc`
/// does not export.
const ILL_ILLOPN: libc::c_int = 2;

/// Whether the SIGILL `task` stopped with is the fault of the `ud2` that
/// follows the private-page `syscall` (`after_syscall`): `ILL_ILLOPN` at that
/// address, with RIP still on it.
fn is_private_guard_fault(task: &Stopped, after_syscall: u64) -> Result<bool, TraceError> {
    let siginfo = task.getsiginfo()?;
    // SAFETY: si_addr reads the fault-address member that SIGILL fills in.
    Ok(siginfo.si_signo == libc::SIGILL
        && siginfo.si_code == ILL_ILLOPN
        && unsafe { siginfo.si_addr() } as u64 == after_syscall
        && task.getregs()?.ip() == after_syscall)
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

/// The `si_code` Linux gives the SIGTRAP of a `#BP` (`int3`) that no ptrace
/// mechanism raised: `do_int3_user` sends it with `force_sig`, which stamps
/// `SI_KERNEL`. `libc` does not export it.
const SI_KERNEL: libc::c_int = 0x80;

/// The one-byte `int3` opcode.
const INT3: u8 = 0xcc;

/// `int $3`, the two-byte encoding of the same trap, which Linux reports the
/// same way.
const INT_3: [u8; 2] = [0xcd, 0x03];

/// Whether the SIGTRAP `task` stopped with is the guest's own `int3`, retired
/// just before `rip`. Two observations must agree: the kernel's `si_code` is
/// `SI_KERNEL`, which no single step (`TRAP_TRACE`), ptrace breakpoint report
/// (`TRAP_BRKPT`, also `icebp`'s) or sender (`SI_USER`, `SI_TKILL`, `SI_QUEUE`)
/// carries; and the instruction that ends at `rip` is `int3` (`0xcc`) or
/// `int $3` (`0xcd 0x03`). Bytes that cannot be read are not evidence, and the
/// trap stays undelivered; so does an `int3` another thread overwrote or
/// unmapped before this read. The caller excludes the `int3`s Reverie
/// planted itself.
fn is_guest_int3_trap(task: &Stopped, rip: u64) -> Result<bool, TraceError> {
    if !cfg!(target_arch = "x86_64") {
        return Ok(false);
    }
    let siginfo = task.getsiginfo()?;
    if siginfo.si_signo != libc::SIGTRAP || siginfo.si_code != SI_KERNEL {
        return Ok(false);
    }
    let byte_before = |distance: u64| -> Option<u8> {
        let site = rip.checked_sub(distance)?;
        task.read_value(Addr::<u8>::from_raw(site as usize)?).ok()
    };
    Ok(match byte_before(1) {
        Some(INT3) => true,
        Some(last) if last == INT_3[1] => byte_before(2) == Some(INT_3[0]),
        _ => false,
    })
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
    executable: bool,
    inode: u64,
    path: Option<PathBuf>,
}

impl GuestMap {
    fn contains(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
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
    u64::from_str_radix(offset, 16).ok()?;
    let (device_major, device_minor) = device.split_once(':')?;
    u64::from_str_radix(device_major, 16).ok()?;
    u64::from_str_radix(device_minor, 16).ok()?;
    let inode = inode.parse::<u64>().ok()?;

    while line.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    let path = (cursor < line.len()).then(|| decode_proc_maps_path(&line[cursor..]));
    Some(GuestMap {
        start,
        end,
        executable: permissions.get(2) == Some(&b'x'),
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

fn is_liteinst_mapping_syscall(nr: Sysno) -> bool {
    // TODO-HUMAN-REVIEW(PR-270): Review pkey_mprotect mapping-lifecycle classification.
    matches!(
        nr,
        // AUTONOMOUS-BOT-IMPLEMENTED
        Sysno::mmap | Sysno::munmap | Sysno::mremap | Sysno::mprotect | Sysno::pkey_mprotect
    )
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

/// The offset of `uc_sigmask` in the x86-64 kernel `ucontext` that
/// `rt_sigreturn` restores: after uc_flags (8), uc_link (8), uc_stack (24) and
/// uc_mcontext (256 bytes). `uc_flags` is at offset 0.
#[cfg(target_arch = "x86_64")]
const UC_SIGMASK_OFFSET: u64 = 8 + 8 + 24 + 256;

/// Whether the mask a reported `rt_sigreturn`'s `frame` installs is known
/// and leaves reverie-ptrace's timer signal unblocked, so that a timer
/// notification requested at the stop reaches the guest after the return
/// (see [`crate::timer::Timer::disregard_sigreturn_stop`]). A frame the
/// backend could not read may also make the kernel's read fault.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn timer_notified_after_return(frame: reverie::SigreturnFrame) -> bool {
    matches!(
        frame,
        reverie::SigreturnFrame::Readable { mask }
            if mask & (1 << (reverie::PERF_EVENT_SIGNAL as u32 - 1)) == 0
    )
}

/// What of the `rt_sigreturn` frame at stack pointer `sp` can be read: see
/// [`TracedTask::report_sigreturn`].
#[cfg(target_arch = "x86_64")]
fn sigreturn_frame(task: &Stopped, sp: u64) -> reverie::SigreturnFrame {
    let mut words = [0u64; 2];
    let mut protected = false;
    for (word, offset) in words.iter_mut().zip([0, UC_SIGMASK_OFFSET]) {
        let Some(address) = sp
            .checked_add(offset)
            .and_then(|address| usize::try_from(address).ok())
            .and_then(Addr::<u8>::from_raw)
        else {
            return reverie::SigreturnFrame::Unmapped;
        };
        let mut bytes = [0u8; 8];
        if task
            .read_exact_with_user_access(address, &mut bytes)
            .is_ok()
        {
            *word = u64::from_ne_bytes(bytes);
        } else if task.read_value(address.cast::<u64>()).is_ok() {
            protected = true;
        } else {
            return reverie::SigreturnFrame::Unmapped;
        }
    }
    if protected {
        reverie::SigreturnFrame::Protected
    } else {
        reverie::SigreturnFrame::Readable { mask: words[1] }
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

/// Hands a thread that a core-dumping signal killed to the global tool.
type FatalSignalExitHook = Box<dyn Fn(&reverie::FatalSignalExit) + Send + Sync>;

/// `PF_DUMPCORE` and `PF_SIGNALED` from the kernel's `include/linux/sched.h`.
const PF_DUMPCORE: u64 = 0x200;
const PF_SIGNALED: u64 = 0x400;

/// The kernel's `task_struct::flags` for `tid`, field 9 of `/proc/<tid>/stat`.
fn kernel_task_flags(tid: Pid) -> std::io::Result<u64> {
    // The name field may hold any bytes the thread named itself with.
    let stat = String::from_utf8_lossy(&std::fs::read(format!("/proc/{tid}/stat"))?).into_owned();
    let invalid = |what| std::io::Error::new(std::io::ErrorKind::InvalidData, what);
    stat.rsplit_once(") ")
        .ok_or_else(|| invalid("malformed stat"))?
        .1
        .split_ascii_whitespace()
        .nth(6)
        .ok_or_else(|| invalid("missing flags"))?
        .parse()
        .map_err(|_| invalid("malformed flags"))
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
    fatal_signal_exit: Option<FatalSignalExitHook>,
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
        let fatal_weak = weak.clone();
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
            fatal_signal_exit: Some(Box::new(move |exit| {
                if let Some(global) = fatal_weak.upgrade() {
                    global.on_fatal_signal_exit(exit);
                }
            })),
            ..Self::default()
        }
    }

    /// Offers a thread held at its exit stop while a core-dumping fatal signal
    /// ends its process to the global Tool. Its memory is normally still
    /// mapped, but the exit stop does not pin it: it can be reaped before or
    /// during the call, so the Tool's reads of it may fail or come back short.
    /// Reads the thread's registers and kernel flags without changing them; a
    /// thread whose registers or flags cannot be read is not offered.
    pub(crate) fn offer_fatal_signal_exit(&self, stopped: &Stopped, status: ExitStatus) {
        let (Some(hook), ExitStatus::Signaled(signal, _)) = (&self.fatal_signal_exit, status)
        else {
            return;
        };
        if !reverie::signal_dumps_core(signal) {
            return;
        }
        // The kernel's fatal-signal path marks every thread of the dying
        // process PF_SIGNALED. A thread that exits with a signal number
        // without it (seccomp KILL_THREAD, a kernel oops) leaves its process
        // running. PF_DUMPCORE marks the thread that ran the core dump step.
        let Ok(flags) = kernel_task_flags(stopped.pid()) else {
            return;
        };
        if flags & PF_SIGNALED == 0 {
            return;
        }
        let Ok(regs) = stopped.getregs() else {
            return;
        };
        let deadline = *self.cleanup_deadline.lock().unwrap();
        let dumping = flags & PF_DUMPCORE != 0;
        if let Some(exit) =
            reverie::FatalSignalExit::new(stopped.pid(), status, dumping, deadline, regs)
        {
            hook(&exit);
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

    /// Whether the guest's own `rt_sigreturn` is reported to
    /// `Tool::handle_sigreturn`: the Tool observes sigreturns and no
    /// gdbserver is attached. A gdbserver's single-step into the call would
    /// otherwise be interrupted by the report's seccomp stop. The seccomp
    /// filter traces `rt_sigreturn` under the same rule (`seccomp_filter`).
    reports_sigreturns: bool,

    /// Whether Reverie keeps the guest's SIGTRAP action and mask across its
    /// own single-steps (`sigtrap_state`): only for a Tool that enforces a
    /// serialized-execution contract (`Tool::enforces_serialized_execution`),
    /// and only on x86-64, whose instruction encodings and syscall rewind
    /// this relies on. The repair injects `rt_sigaction` into a stopped
    /// thread, which a guest thread running meanwhile could defeat. Otherwise
    /// SIGTRAP is left as at base.
    keeps_sigtrap_state: bool,

    /// Whether Reverie may remember SIGTRAP's disposition between procfs reads
    /// (`TracedTask::sigtrap_ignored`): the Tool subscribes to
    /// `rt_sigaction`, so that every guest change of it stops at a seccomp
    /// stop Reverie sees.
    caches_sigtrap_disposition: bool,

    /// Whether every clone that can share a signal-action table stops at a
    /// seccomp stop Reverie sees: the Tool subscribes to `clone` and
    /// `clone3`. Only then may a step leave the shield on a table Reverie
    /// believes unshared (`TracedTask::may_unshield_step`), since a
    /// `CLONE_UNTRACED` child gives no new-child event.
    sees_every_sighand_clone: bool,

    /// Whether the Tool subscribes to every syscall that can change the
    /// blocked mask or SIGTRAP's action (`rt_sigprocmask`, `rt_sigaction`,
    /// `rt_sigreturn` and the mask-swapping waits, `swaps_signal_mask`), so
    /// that a timer step reaching one stops at its seccomp stop and ends the
    /// sequence (`drive_timer`).
    traces_signal_state_syscalls: bool,

    /// guests are sequentialized already (by detcore for example), gdbserver
    /// should avoid sequentialize threads.
    sequentialized_guest: Arc<bool>,

    /// Marker and exact RIP identifying a binary-rewriter syscall trap.
    injected_syscall_trap: Option<InjectedSyscallTrap>,

    fatal_session: Arc<FatalSession>,
    /// SIGTRAP repairs owed, by signal-action table (`sigtrap_state`): a
    /// Reverie trap reset the table's SIGTRAP action, and the repair could
    /// not run yet. Any thread that uses the table writes it back at its next
    /// stop that can take it, so that no thread reads the reset action.
    sigtrap_tables: Arc<StdMutex<SigtrapTables>>,
    /// Serializes the SIGTRAP repairs, so that a repair reads the owed entry
    /// and the action, and writes it, before another thread's repair of the
    /// same table runs (`TracedTask::apply_sigtrap_repair`).
    sigtrap_scratch_lock: Arc<Mutex<()>>,
    /// The seccomp filters a guest gets from outside: the tracer's own,
    /// which the guest inherits, and the one its launch installs
    /// (`seccomp_filter` in the tracer); an image with more has filters of the
    /// guest's own (`seal_sigtrap_scratch`), except at the root's first stop,
    /// before the launch filter is installed, where one fewer is. `None` if
    /// the tracer's count cannot be read.
    seccomp_filter_baseline: Option<u64>,

    /// Optional collector for general ptrace lifecycle activity.
    backend_stats: Option<PtraceBackendStatsSource>,

    #[cfg(test)]
    final_resume_signal_for_test: Option<FinalResumeSignalForTest>,

    #[cfg(test)]
    pre_syscall_for_test: Option<PreSyscallForTest>,

    #[cfg(test)]
    preinit_point_for_test: Option<PreinitPointForTest>,
}

/// Test-only: sees the registers at the final resume of every Tool-visible
/// seccomp stop, from the stopped thread, and may pick a signal to leave
/// pending for that resume.
#[cfg(test)]
pub(crate) type FinalResumeSignalForTest =
    Arc<dyn Fn(Pid, &libc::user_regs_struct) -> Option<Signal> + Send + Sync>;

/// Test-only: runs immediately before a Tool-visible syscall's own execution
/// starts, with the stopped thread, the syscall's registers and the point,
/// and is awaited before the tracer goes on. Both points are the final
/// resume of the seccomp stop (or the exact inject's resume), one after the
/// other (see [`PreSyscallPoint`]). It parks a thread at a fixed logical
/// point, so that a test can deliver a signal there deterministically.
#[cfg(test)]
pub(crate) type PreSyscallForTest = Arc<
    dyn Fn(Pid, &libc::user_regs_struct, PreSyscallPoint) -> futures::future::BoxFuture<'static, ()>
        + Send
        + Sync,
>;

#[cfg(test)]
static STEP_COUNTS_GLOBAL: std::sync::Mutex<std::collections::BTreeMap<i32, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Timer sequences whose single-steps ran (`drive_timer`), counted for
/// tests that must know a sequence stepped: the per-thread step count
/// (`record_step_for_test`) counts only `step_stopped`'s steps.
#[cfg(test)]
pub(crate) static TIMER_SEQUENCES_STEPPED_FOR_TEST: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    /// The unstepped injections of SIGTRAP repairs (the action's query, its
    /// write, and an `act`'s re-install), counted for the tests that bound
    /// them. Pre-init's sealing of the repair page is not counted. Per
    /// thread: a test's tracer runs on its own `current_thread` runtime, so
    /// tests running beside it in one process cannot add to its count.
    pub(crate) static UNSTEPPED_INJECTIONS_FOR_TEST: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// Timer steps over a guest `rt_sigreturn` whose frame blocked SIGTRAP
/// (`TimerStepShield::prepare`), counted for the test that must know one ran.
#[cfg(test)]
pub(crate) static FRAME_SHIELDS_FOR_TEST: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Test-only: counts every tracer single-step request per tid, so a test
/// tool can measure the forced-SIGTRAP profile of a run.
#[cfg(test)]
pub(crate) fn record_step_for_test(tid: Pid) {
    *STEP_COUNTS_GLOBAL
        .lock()
        .unwrap()
        .entry(tid.as_raw())
        .or_default() += 1;
}

/// Test-only: the number of single-step requests issued for `tid` so far.
#[cfg(test)]
pub(crate) fn step_count_for_test(tid: Pid) -> u64 {
    STEP_COUNTS_GLOBAL
        .lock()
        .unwrap()
        .get(&tid.as_raw())
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
static STEPPED_SECCOMP_GLOBAL: std::sync::Mutex<std::collections::BTreeMap<i32, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Test-only: counts, per tid, every timer single-step that ended at a
/// seccomp stop, so that a test Tool can tell a stepped syscall entry from
/// any other.
#[cfg(test)]
pub(crate) fn record_stepped_seccomp_for_test(tid: Pid) {
    *STEPPED_SECCOMP_GLOBAL
        .lock()
        .unwrap()
        .entry(tid.as_raw())
        .or_default() += 1;
}

/// Test-only: the number of timer single-steps of `tid` so far that ended
/// at a seccomp stop.
#[cfg(test)]
pub(crate) fn stepped_seccomp_count_for_test(tid: Pid) -> u64 {
    STEPPED_SECCOMP_GLOBAL
        .lock()
        .unwrap()
        .get(&tid.as_raw())
        .copied()
        .unwrap_or(0)
}

/// Test-only: where the tracer calls a [`PreSyscallForTest`] hook. The two
/// points come one after the other, with no tracer work between them.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PreSyscallPoint {
    /// The first call.
    Early,
    /// The second call, immediately before the syscall runs.
    Late,
}

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

/// Test-only: where `tracee_preinit`, or the exec-return drain before it, calls a
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
    /// At the exec stop, before resuming only toward its syscall-exit stop.
    ExecStopped,
    /// At the validated exec syscall-exit stop, before any guest instruction.
    PostExecDrained,
}

/// The owner that must retain a decoded `Event::NewChild` before any
/// cancellation point can drop the stop that carries it.
#[derive(Clone, Copy)]
enum NewbornOwner<'a> {
    /// Ordinary ptrace: the fatal session's retained kernel edge.
    Ordinary(&'a FatalSession),
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
        }
    }
}

impl<G: GlobalTool> GlobalState<G> {
    /// Borrows only the global state, so a closure passed to a nested stepper
    /// that also borrows the task's timer can still register a newborn.
    fn newborn_owner(&self) -> NewbornOwner<'_> {
        NewbornOwner::Ordinary(&self.fatal_session)
    }
}

impl<G: GlobalTool> Clone for GlobalState<G> {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            gs_ref: self.gs_ref.clone(),
            subscriptions: self.subscriptions.clone(),
            reports_sigreturns: self.reports_sigreturns,
            keeps_sigtrap_state: self.keeps_sigtrap_state,
            caches_sigtrap_disposition: self.caches_sigtrap_disposition,
            sees_every_sighand_clone: self.sees_every_sighand_clone,
            traces_signal_state_syscalls: self.traces_signal_state_syscalls,
            sequentialized_guest: self.sequentialized_guest.clone(),
            injected_syscall_trap: self.injected_syscall_trap.clone(),
            fatal_session: self.fatal_session.clone(),
            sigtrap_tables: self.sigtrap_tables.clone(),
            sigtrap_scratch_lock: self.sigtrap_scratch_lock.clone(),
            seccomp_filter_baseline: self.seccomp_filter_baseline,
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

    /// The stack pointer the current image started with, recorded at its
    /// exec stop (`Guest::initial_stack_pointer`). Tasks forked or cloned
    /// from the image share it.
    initial_stack_pointer: Option<u64>,

    /// Original call still owned by the current syscall callback. Only an
    /// ordinary, unconverted seccomp callback owns a kernel entry to skip;
    /// an injected frame and an already-skipped call are logical operations.
    /// Taking this record consumes that authority, including fast tail injection
    /// which transfers the original call to the callback's final resume.
    pending_syscall: Option<(Sysno, SyscallArgs)>,

    /// Address of the writable e9tool register frame for the active event.
    injected_syscall_frame: Option<usize>,

    /// Result of a fast tail injection made from an injected-frame callback.
    /// The dispatcher that owns the frame writes it, or restarts the trap when
    /// it is a Linux restart code, after the callback is dropped.
    injected_tail_result: Option<Result<i64, Errno>>,

    /// pending signal to deliver. This can happen when
    /// syscall got interrupted (by signal)
    pending_signal: Option<AnySignal>,

    /// How the delivery stop of the signal in `pending_signal` took it, when
    /// `status_to_result` held it.
    pending_signal_taken: Option<TakenSignal>,

    /// Whether the signal in `pending_signal` is an instance
    /// `Tool::handle_signal_event` already reported: one that was back in the
    /// kernel's queue as a reported, requeued instance of its number
    /// (`reported_requeued_signals`) when the hold took it. The hold takes
    /// that count over (`hold_pending_signal`), so it follows the instance
    /// rather than its number.
    pending_signal_reported: bool,

    /// Whether an injected syscall's single step ended at a held signal
    /// (`step_private_syscall`) before collecting its step SIGTRAP, which the
    /// kernel therefore still has queued. The next SIGTRAP stop carrying that
    /// step's siginfo is discarded instead of being read as a later step's
    /// completion or reported as an unexpected trap.
    stale_private_step_trap: bool,
    /// Whether the OS thread named here, the one that made this traced
    /// thread's ptrace requests when it was read, had no seccomp filter
    /// (`keeps_sigtrap_state`). Set only from a successful read.
    tracer_unfiltered: StdMutex<Option<(std::thread::ThreadId, bool)>>,
    /// The mask and procfs state `read_sigtrap_before_injection` read for
    /// the injection about to be stepped, for that step's shield to reuse:
    /// no guest code runs between the two (`step_private_syscall`).
    injection_proc_state: Option<(u64, ProcSignalState)>,
    /// Whether a temporary mask's restore (`TIF_RESTORE_SIGMASK`) may be
    /// pending, so that procfs `SigBlk` may differ from `PTRACE_GETSIGMASK`.
    /// It cannot at a seccomp stop, a syscall's entry; it may at any other
    /// stop, and after a mask-swapping syscall runs, until the next seccomp
    /// stop (`read_sigtrap_before_injection`).
    restore_maybe_pending: bool,
    /// Set at an exec stop when SIGTRAP is neither ignored nor blocked and no
    /// repair is owed: then no step through pre-init and the new image's
    /// first instruction can reset it, and those steps skip the SIGTRAP work
    /// (`sigtrap_state`).
    exec_sigtrap_quiet: bool,
    /// Whether the injection being prepared installs a caught SIGTRAP handler
    /// (`read_sigtrap_before_injection`); its step then keeps the shield.
    injection_installs_caught: bool,
    /// What the last private-page step of the injection decided
    /// (`step_private_syscall`), for its repair.
    step_choice: Option<StepChoice>,
    /// The signal-action table this thread's group uses
    /// (`GlobalState::sigtrap_tables`).
    sigtrap_table: u64,
    /// Whether this thread's address space holds Reverie's sealed SIGTRAP
    /// repair page (`SCRATCH_PENDING`, `SCRATCH_SEALED`,
    /// `SCRATCH_UNAVAILABLE`; `seal_sigtrap_scratch`), shared by every task
    /// that shares the address space.
    sigtrap_scratch_state: Arc<AtomicU8>,

    /// The generation [`Self::tracee_preinit`] is initializing, while it runs.
    preinit_generation: Option<TraceeGeneration>,

    /// The stop an injection last ended at since the current stop was
    /// dispatched (`handle_stop_event`), as its wait status classifies it:
    /// `Some(Some(sig))` for a signal-delivery stop of `sig`, `Some(None)`
    /// for any other stop, `None` if no injection has completed. Set by
    /// `status_to_result`. Siginfo cannot classify the stop, because a guest
    /// may queue itself a SIGTRAP whose `si_code` mimics a syscall stop.
    latest_injection_stop: Option<Option<AnySignal>>,

    /// Whether the syscall of the injection that last completed ran. False
    /// when `status_to_result` reported that a signal stopped it before its
    /// `syscall` instruction (`-ERESTARTSYS`, not run). Read only by
    /// `HostLinux::execute`, right after its injection, which reports such a
    /// call as `ProviderOutcome::Interrupted` (`host_linux::classify`).
    last_injection_ran: bool,

    /// Whether `Tool::handle_signal_event` is running (`report_signal`).
    in_signal_callback: bool,

    /// Whether `Tool::handle_syscall_event` is running for this thread, the
    /// only callback in which `Guest::set_blocked_signals` changes the mask.
    in_syscall_callback: bool,

    /// The signal the running `Tool::handle_signal_event` reports, and its
    /// siginfo when its stop recorded one (`Guest::signal_info`).
    reported_signal: Option<(AnySignal, Option<SiginfoBytes>)>,

    /// The siginfo the running `Tool::handle_signal_event` chose for its
    /// signal (`Guest::set_signal_info`).
    replacement_signal_info: Option<(AnySignal, SiginfoBytes)>,

    /// The delivery the running `Tool::handle_signal_event` approved
    /// (`Guest::deliver_signal`), which `report_signal` enforces when the
    /// callback returns.
    signal_approval: Option<SignalApproval>,

    /// Whether a check of `Guest::deliver_signal` failed in the running
    /// `Tool::handle_signal_event`, after which it approves nothing more.
    signal_delivery_mismatched: bool,

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
    /// that a guest about to exit need not make. A realtime signal is not
    /// taken from the queue at all there (`step_shielded_injection`):
    /// put back, it would go behind later instances of its number.
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
    /// delivering it (`resume_with_signal`), and that are still there. A hold
    /// that takes such an instance takes its count with it
    /// (`hold_pending_signal`, `pending_signal_reported`), and
    /// `report_held_signal` passes that instance on unreported rather than
    /// report it twice. Any other stop that takes it from the queue ends its
    /// count: an ordinary signal-delivery stop (`handle_signal`) or a direct
    /// path (`filter_direct_unreported`). The count is by signal number, so
    /// it follows instances only for standard signals, which have at most
    /// one pending instance per queue. For a realtime signal, which can queue
    /// several instances, it can mark the wrong one: a later instance of the
    /// same number may be passed on unreported while the requeued one is
    /// reported again. A realtime signal passed back this way also goes to
    /// the tail of its queue, behind later instances of its number, and one
    /// passed back from a syscall stop loses its siginfo (the kernel sends it
    /// as SI_KERNEL). These arise only when `resume_with_signal` resumes a
    /// reported realtime signal from an injection's stop while the thread
    /// blocks it, or from a syscall stop
    /// (<https://github.com/rrnewton/reverie/issues/207>).
    reported_requeued_signals: HashMap<AnySignal, u32>,

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
        // The report reads an x86-64 signal frame (`report_sigreturn`).
        let reports_sigreturns =
            cfg!(target_arch = "x86_64") && L::observes_sigreturns(&cfg) && gdbserver.is_none();
        let keeps_sigtrap_state =
            cfg!(target_arch = "x86_64") && L::enforces_serialized_execution(&cfg);
        let caches_sigtrap_disposition = options
            .events
            .iter_syscalls()
            .any(|sysno| sysno == Sysno::rt_sigaction);
        let sees_every_sighand_clone = {
            let traced: HashSet<Sysno> = options.events.iter_syscalls().collect();
            traced.contains(&Sysno::clone) && traced.contains(&Sysno::clone3)
        };
        let traces_signal_state_syscalls = {
            let traced: HashSet<Sysno> = options.events.iter_syscalls().collect();
            [
                Sysno::rt_sigprocmask,
                Sysno::rt_sigaction,
                Sysno::rt_sigreturn,
            ]
            .into_iter()
            .chain(Sysno::iter().filter(|&nr| swaps_signal_mask(nr)))
            .all(|nr| traced.contains(&nr))
        };
        let global_state = GlobalState {
            gs_ref,
            cfg,
            subscriptions: Arc::new(options.events.clone()),
            reports_sigreturns,
            keeps_sigtrap_state,
            caches_sigtrap_disposition,
            sees_every_sighand_clone,
            traces_signal_state_syscalls,
            sequentialized_guest: Arc::new(
                gdbserver
                    .as_ref()
                    .map(|s| s.sequentialized_guest)
                    .unwrap_or(false),
            ),
            injected_syscall_trap: options.injected_syscall_trap.clone(),
            fatal_session,
            sigtrap_tables: Arc::new(StdMutex::new(SigtrapTables::default())),
            sigtrap_scratch_lock: Arc::new(Mutex::new(())),
            seccomp_filter_baseline: read_status("/proc/thread-self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
                        .and_then(|count| count.trim().parse::<u64>().ok())
                })
                .map(|own| own + 1),
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
        let sigtrap_table = global_state.sigtrap_tables.lock().unwrap().copy(tid, None);
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
            initial_stack_pointer: None,
            pending_syscall: None,
            injected_syscall_frame: None,
            injected_tail_result: None,
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
            pending_signal_reported: false,
            reported_signal: None,
            replacement_signal_info: None,
            signal_approval: None,
            signal_delivery_mismatched: false,
            stale_private_step_trap: false,
            exec_sigtrap_quiet: false,
            injection_installs_caught: false,
            step_choice: None,
            tracer_unfiltered: StdMutex::new(None),
            injection_proc_state: None,
            restore_maybe_pending: true,
            sigtrap_table,
            sigtrap_scratch_state: Arc::new(AtomicU8::new(SCRATCH_PENDING)),
            ptracer_waits: Arc::new(PtracerWaitOwner::default()),
            preinit_generation: None,
            latest_injection_stop: None,
            last_injection_ran: true,
            in_signal_callback: false,
            in_syscall_callback: false,
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

    /// Create a child TracedTask corresponding to a clone()
    fn cloned(&self, child: Pid) -> Self {
        // The new thread uses its group's table, which is now shared.
        self.global_state
            .sigtrap_tables
            .lock()
            .unwrap()
            .add_thread(self.sigtrap_table);
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
            initial_stack_pointer: self.initial_stack_pointer,
            pending_syscall: None,
            injected_syscall_frame: None,
            injected_tail_result: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(self.pid, child),
            cancel_handler: Arc::new(AtomicBool::new(false)),
            pending_signal: None,
            pending_signal_taken: None,
            pending_signal_reported: false,
            reported_signal: None,
            replacement_signal_info: None,
            signal_approval: None,
            signal_delivery_mismatched: false,
            stale_private_step_trap: false,
            exec_sigtrap_quiet: false,
            injection_installs_caught: false,
            step_choice: None,
            tracer_unfiltered: StdMutex::new(None),
            injection_proc_state: None,
            restore_maybe_pending: true,
            sigtrap_table: self.sigtrap_table,
            sigtrap_scratch_state: self.sigtrap_scratch_state.clone(),
            ptracer_waits,
            preinit_generation: None,
            latest_injection_stop: None,
            last_injection_ran: true,
            in_signal_callback: false,
            in_syscall_callback: false,
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

    /// Create a child TracedTask corresponding to a fork(), or a clone that
    /// makes a process; `shares_signal_actions` if it shares the creator's
    /// signal-action table (`CLONE_SIGHAND`).
    fn forked(&self, child: Pid, shares_signal_actions: bool, shares_address_space: bool) -> Self {
        // A shared address space is the same address space. A copied one
        // holds a sealed copy of the repair page only if the child's own
        // mappings show it: the guest can keep the page out of a fork's copy
        // (`MADV_DONTFORK`), which the seal allows on a read-write page, and
        // then map its own page there.
        let sigtrap_scratch_state = if shares_address_space {
            self.sigtrap_scratch_state.clone()
        } else {
            let state = match self.sigtrap_scratch_state.load(Ordering::SeqCst) {
                SCRATCH_SEALED if repair_page_sealed_in(child) => SCRATCH_SEALED,
                SCRATCH_SEALED => SCRATCH_UNAVAILABLE,
                state => state,
            };
            Arc::new(AtomicU8::new(state))
        };
        let sigtrap_table = {
            let mut tables = self.global_state.sigtrap_tables.lock().unwrap();
            if shares_signal_actions {
                tables.share(child, self.sigtrap_table)
            } else {
                tables.copy(child, Some(self.sigtrap_table))
            }
        };
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
            initial_stack_pointer: self.initial_stack_pointer,
            pending_syscall: None,
            injected_syscall_frame: None,
            injected_tail_result: None,
            next_state,
            next_state_rx: Some(next_state_rx),
            timer: Timer::new(child, child),
            cancel_handler: Arc::new(AtomicBool::new(false)),
            pending_signal: None,
            pending_signal_taken: None,
            pending_signal_reported: false,
            reported_signal: None,
            replacement_signal_info: None,
            signal_approval: None,
            signal_delivery_mismatched: false,
            stale_private_step_trap: false,
            exec_sigtrap_quiet: false,
            injection_installs_caught: false,
            step_choice: None,
            tracer_unfiltered: StdMutex::new(None),
            injection_proc_state: None,
            restore_maybe_pending: true,
            sigtrap_table,
            sigtrap_scratch_state,
            ptracer_waits,
            preinit_generation: None,
            latest_injection_stop: None,
            last_injection_ran: true,
            in_signal_callback: false,
            in_syscall_callback: false,
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
        // knows, so an unknown number here is an error, never a panic.
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
    let (signal, core_dumped) = match exit_status {
        ExitStatus::Signaled(signal, core_dumped) => (AnySignal::from(signal), core_dumped),
        ExitStatus::SignaledRaw(raw, core_dumped) => match AnySignal::new(raw) {
            Some(signal) => (signal, core_dumped),
            None => return,
        },
        ExitStatus::Exited(_) => return,
    };
    tracing::error!(
        target: "reverie_ptrace::lifecycle",
        %tid,
        %pid,
        %signal,
        core_dumped,
        "guest terminated by signal"
    );
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
    async fn intercept_cpuid(&mut self) -> Result<i64, Errno> {
        use reverie::syscalls::ArchPrctl;
        use reverie::syscalls::ArchPrctlCmd;

        self.inject_with_retry(ArchPrctl::new().with_cmd(ArchPrctlCmd::ARCH_SET_CPUID(0)))
            .await
    }

    #[cfg(target_arch = "x86_64")]
    async fn arm_cpuid(&mut self, place: PreinitPlace) -> Result<(), CpuidFaultingUnavailable> {
        let result = self.cpuid_state().await;
        if !matches!(result, Ok(0 | 1)) {
            return Err(CpuidFaultingUnavailable {
                place,
                operation: "initial-get",
                result,
            });
        }
        let result = self.intercept_cpuid().await;
        if result != Ok(0) {
            return Err(CpuidFaultingUnavailable {
                place,
                operation: "set-disabled",
                result,
            });
        }
        let result = self.cpuid_state().await;
        if result != Ok(0) {
            return Err(CpuidFaultingUnavailable {
                place,
                operation: "verify-get",
                result,
            });
        }
        Ok(())
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
        let held_root_stop = self.liteinst_root_stop_slot();
        #[cfg(test)]
        let preinit_point = self.global_state.preinit_point_for_test.clone();

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

        type SavedInstructions = [u8; 8];

        /// The test-only hooks `setup_special_mmap_page` consults.
        #[cfg(test)]
        struct PreinitTestHooks<'a> {
            preinit_point: &'a Option<PreinitPointForTest>,
        }

        /// Helper function for tracee_preinit that does the core work.
        async fn setup_special_mmap_page<L: Tool + 'static>(
            task: Stopped,
            waits: &Arc<PtracerWaitOwner>,
            saved_regs: &libc::user_regs_struct,
            held_root_stop: &Option<Arc<StdMutex<Option<HeldRootStop>>>>,
            // Only to show a signal skipped here to
            // `Tool::filter_unreported_signal`.
            owner: &mut TracedTask<L>,
            // Whether SIGTRAP is to be unblocked for the mmap's step
            // (`sigtrap_state`).
            shield_sigtrap: bool,
            #[cfg(test)] hooks: PreinitTestHooks<'_>,
        ) -> Result<PreinitOutcome, TraceError> {
            #[cfg(test)]
            let PreinitTestHooks { preinit_point } = hooks;
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
            // The step's trap must not reset a blocked SIGTRAP, which the new
            // image keeps across exec (`sigtrap_state`).
            let shielded =
                shield_sigtrap && owner.shield_sigtrap_for_step(&task, "pre-init mmap")?;
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
            let mut task = loop {
                let (task, event) = match running.next_state_with_owner(waits).await? {
                    Wait::Stopped(task, event) => (task, event),
                    Wait::Exited(pid, exit_status) => {
                        return Ok(PreinitOutcome::Exited(pid, exit_status));
                    }
                };
                arm_preinit_stop(held_root_stop, &task, &event);
                match event {
                    Event::Signal(Signal::SIGTRAP) => {
                        if shielded {
                            let mask = sigmask(&task)?;
                            set_sigmask(&task, mask | SIGTRAP_BIT)?;
                        }
                        break task;
                    }
                    Event::Signal(_) | Event::RawSignal(_) => {
                        // We can catch spurious signals here, such as SIGWINCH.
                        // All we can do is skip over them.
                        tracing::debug!(
                            "[{}] Skipping {:?} during initialization",
                            task.pid(),
                            event
                        );
                        let sig = match event {
                            Event::Signal(sig) => AnySignal::from(sig),
                            Event::RawSignal(raw) => AnySignal::new(raw).ok_or(Errno::EINVAL)?,
                            _ => unreachable!(),
                        };
                        let sig = owner.filter_direct_unreported(&task, sig).await;
                        running =
                            RootStopLease::new(task, held_root_stop.clone()).resume_any(sig)?;
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

        // The new image keeps an ignored or blocked SIGTRAP across exec, and
        // the mmap's single-step below must leave both (`sigtrap_state`). Not
        // under a tracer filter, which may refuse the requests
        // (`thread_may_be_seccomp_filtered`).
        let shield_sigtrap = self.keeps_sigtrap_state() && !self.exec_sigtrap_quiet;
        if shield_sigtrap && sigtrap_disposition(&task)?.0 {
            self.note_sigtrap_repair(SigtrapRepair::Ignored);
        }
        let (task, regs, prev_state) = establish_injection_state(
            task,
            #[cfg(test)]
            &preinit_point,
        )
        .await?;
        let waits = self.ptracer_waits.clone();
        let outcome = setup_special_mmap_page(
            task,
            &waits,
            &regs,
            &held_root_stop,
            self,
            shield_sigtrap,
            #[cfg(test)]
            PreinitTestHooks {
                preinit_point: &preinit_point,
            },
        )
        .await;
        let mut task = match outcome? {
            PreinitOutcome::Ready(task) => task,
            ended @ (PreinitOutcome::Exited(..) | PreinitOutcome::Refused(_)) => return Ok(ended),
        };
        #[cfg(test)]
        at_preinit_point(
            &preinit_point,
            task.pid(),
            || task.terminal_cleanup(),
            PreinitPoint::PagePopulated,
        );

        // Restore registers after adding our temporary injection state.
        remove_injection_state(&mut task, regs, prev_state)?;
        // At the exec stop no instruction of the new image has run: its stack
        // pointer is the one it starts with, at argc.
        if place == PreinitPlace::AtExec {
            // A register is 32 bits wide on aarch64's `Reg`, 64 on x86_64.
            #[allow(clippy::useless_conversion)]
            let stack = u64::from(regs.stack_ptr());
            self.initial_stack_pointer = Some(stack);
        }

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

        // Reverie's sealed SIGTRAP repair page is mapped after the trampoline
        // while the new image is still single-threaded, and an
        // ignored SIGTRAP that the mmap's or pre-init's
        // later steps reset is put back through it.
        let task = self.seal_sigtrap_scratch(task, place).await?;
        let task = if shield_sigtrap {
            self.apply_sigtrap_repair(task).await?
        } else {
            task
        };

        // A subscription is a required contract: if the kernel cannot arm
        // and confirm faulting, no guest continuation is permitted.
        #[cfg(target_arch = "x86_64")]
        if self.global_state.subscriptions.has_cpuid() {
            self.has_cpuid_interception = false;
            if let Err(error) = self.arm_cpuid(place).await {
                // An injection which observes genuine death aborts to its
                // existing owner. Do not replace a concurrent failure or a
                // now-observed death with an unsupported-feature diagnostic.
                if self.fatal_session().is_failed() {
                    return Ok(PreinitOutcome::Refused(task));
                }
                task.getregs()?;
                self.fatal_session().fail_at(
                    BackendFailure {
                        pid: self.pid(),
                        tid: self.tid(),
                        phase: "ptrace CPUID initialization",
                    },
                    anyhow::Error::new(error).into(),
                );
                // Retain the primary refusal if restoring the saved context
                // also fails. Cleanup owns this stopped generation either way.
                if let Err(error) = task.setregs(&regs) {
                    self.fatal_session().fail_at(
                        BackendFailure {
                            pid: self.pid(),
                            tid: self.tid(),
                            phase: "ptrace CPUID refusal context restoration",
                        },
                        anyhow::Error::new(error).into(),
                    );
                }
                return Ok(PreinitOutcome::Refused(task));
            }
            self.has_cpuid_interception = true;
        }

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
    ) -> Result<PostspawnPreinit, TraceError> {
        enum Raced {
            Done(Result<PreinitOutcome, TraceError>),
            Aborted(Option<Result<Wait, TraceError>>),
            ExitStop(Stopped),
            GlobalToolFailed,
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
        // Initialization shows a signal it skips to
        // `Tool::filter_unreported_signal`, which can await a GlobalTool RPC.
        // A GlobalTool failure ends that wait here, as the run loop's watcher
        // does later (`drive_ordinary`): the unfinished initialization is
        // dropped, as when a race below is lost, the root is killed and
        // reaped as for a death during initialization, and the spawn fails.
        let global = self.global_state.gs_ref.clone();
        let terminal = task.terminal_cleanup();
        let mut global_tool_failed = false;
        let raced = {
            let global_failure =
                PollOnWake::new(Box::pin(global.wait_for_backend_failure())).fuse();
            let preinit = self.tracee_preinit(task, PreinitPlace::BeforeExec).fuse();
            let abort = aborted.recv().fuse();
            let exit = async {
                match (&mut exit_stop).await {
                    Ok(stopped) => stopped,
                    Err(_) => future::pending().await,
                }
            }
            .fuse();
            futures::pin_mut!(preinit, abort, exit, global_failure);
            futures::select_biased! {
                outcome = preinit => Raced::Done(outcome),
                next = abort => Raced::Aborted(next),
                stopped = exit => Raced::ExitStop(stopped),
                () = global_failure => Raced::GlobalToolFailed,
            }
        };
        self.next_state_rx = Some(aborted);
        // A lost race drops the initialization before it unbinds.
        self.preinit_generation = None;
        match raced {
            Raced::Done(Err(TraceError::Died(_))) => {}
            Raced::Done(outcome) => return outcome.map(PostspawnPreinit::Outcome),
            Raced::GlobalToolFailed => {
                terminal.request_sigkill()?;
                global_tool_failed = true;
            }
            Raced::Aborted(Some(Ok(Wait::Exited(pid, exit_status)))) => {
                return Ok(PostspawnPreinit::Outcome(PreinitOutcome::Exited(
                    pid,
                    exit_status,
                )));
            }
            Raced::Aborted(Some(Err(TraceError::Died(_)))) => {}
            Raced::Aborted(Some(Err(error))) => return Err(error),
            // Initialization makes no exec, so no abort hands over a stop.
            Raced::Aborted(Some(Ok(Wait::Stopped(..)))) | Raced::Aborted(None) => {
                return Err(Errno::EPROTO.into());
            }
            Raced::ExitStop(stopped) => {
                return self
                    .preinit_exit_stop(stopped)
                    .await
                    .map(PostspawnPreinit::Outcome);
            }
        }
        // A death the initialization saw first: the tracee is in its exit
        // stop or on its way there, unless it has already exited.
        let outcome = match exit_stop.await {
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
        };
        if global_tool_failed {
            outcome?;
            return Ok(PostspawnPreinit::GlobalToolFailed);
        }
        outcome.map(PostspawnPreinit::Outcome)
    }

    /// Resumes the root from its exit stop during initialization and returns
    /// its final status.
    async fn preinit_exit_stop(&self, stopped: Stopped) -> Result<PreinitOutcome, TraceError> {
        let held_root_stop = self.liteinst_root_stop_slot();
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
        // The sequence steps guest code, an instruction or a block at a
        // time, and its traps must not reset SIGTRAP (`sigtrap_state`): each
        // step is shielded, and an ignored SIGTRAP is put back after the
        // sequence. A block step's block holds no `syscall`, interrupt or
        // exception instruction (`decode_block_bound`), so its only trap is
        // the step's own, as for an instruction step. Not under a tracer
        // filter, which may refuse the requests
        // (`thread_may_be_seccomp_filtered`).
        let filtered = !self.keeps_sigtrap_state();
        let sigtrap_ignored = !filtered && self.sigtrap_ignored(&task)?;
        // A preemption-heavy guest makes many steps per timer event, and
        // reading the registers and mask for each one made such a guest about
        // a tenth slower.
        // The filter traces a guest `rt_sigreturn` only where it is reported
        // (`GlobalState::reports_sigreturns`); otherwise a step can run one,
        // and the frame shield is needed.
        // Nor where a filter of higher precedence than Reverie's could let
        // one run without a stop (a `SECCOMP_RET_USER_NOTIF` answered with
        // `CONTINUE`): only Reverie's own launch filter may be there. The
        // tracer has none of its own (`GlobalState::seccomp_filter_baseline`
        // is 1), the address space had no other, such as one a caller's
        // `pre_exec` installs, when pre-init sealed its repair page
        // (`seal_sigtrap_scratch`, which refuses otherwise), and the guest
        // installs none later under the contract.
        let quiet = !filtered
            && !sigtrap_ignored
            && self.global_state.traces_signal_state_syscalls
            && self.global_state.reports_sigreturns
            && self.global_state.seccomp_filter_baseline == Some(1)
            && self.sigtrap_scratch_state.load(Ordering::SeqCst) == SCRATCH_SEALED
            && sigmask(&task)? & SIGTRAP_BIT == 0;
        let shield = Arc::new(StdMutex::new(TimerStepShield {
            ignored: sigtrap_ignored,
            quiet,
            ..TimerStepShield::default()
        }));
        let step_shield = Arc::clone(&shield);
        let mut step = move |task: Stopped, unit| {
            if !filtered {
                step_shield.lock().unwrap().prepare(&task)?;
            }
            let lease = RootStopLease::new(task, held_root_stop.clone());
            match unit {
                StepUnit::Instruction => lease.step(None),
                #[cfg(target_arch = "x86_64")]
                StepUnit::Block => lease.block_step(),
            }
        };
        let observe_shield = Arc::clone(&shield);
        let newborn_owner = self.global_state.newborn_owner();
        let mut observe = |wait: &Wait| {
            if let Wait::Stopped(task, _) = wait {
                observe_shield.lock().unwrap().settle(task)?;
            }
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
        // An ignored SIGTRAP that a step reset is put back before the Tool's
        // callback. A stop that is passed on or kept for later cannot take an
        // injection here, so the next injection or syscall skip puts it back.
        let (stepped, native_trap, pending_trap) = {
            let mut shield = shield.lock().unwrap();
            (
                std::mem::take(&mut shield.stepped),
                std::mem::take(&mut shield.native_trap),
                std::mem::take(&mut shield.pending_trap),
            )
        };
        // A guest instruction's own trap may have reset SIGTRAP natively.
        if native_trap {
            self.forget_sigtrap_ignored();
        }
        if pending_trap {
            return Err(self.fail_pending_sigtrap(self.tid(), "precise timer"));
        }
        #[cfg(test)]
        if stepped {
            TIMER_SEQUENCES_STEPPED_FOR_TEST.fetch_add(1, Ordering::SeqCst);
        }
        // A guest instruction's own trap resets SIGTRAP natively too.
        if sigtrap_ignored && stepped && !native_trap {
            self.note_sigtrap_repair(SigtrapRepair::Ignored);
        }
        let task = match result {
            Err(HandleFailure::ImproperSignal(task)) => return Ok((false, task)),
            Err(HandleFailure::Cancelled(task)) => return Ok((true, task)),
            Err(HandleFailure::TraceError(e)) => {
                #[cfg(test)]
                crate::tracer::record_fatal_phase_for_test(|| {
                    format!("handle_timer TraceError: {e:?}")
                });
                if let TraceError::Errno(errno) = &e {
                    // Keep the actual timer/query errno before the generic
                    // signal-delivery context projects it into a message.
                    // The existing task owner still owns physical cleanup.
                    self.publish_ordinary_failure("ptrace timer signal", (*errno).into());
                }
                return Err(e);
            }
            Err(HandleFailure::Event(wait)) => self.abort(Ok(wait)).await,
            Err(HandleFailure::SeccompStop(task)) => {
                // A step onto a traced syscall: re-dispatch it.
                #[cfg(test)]
                record_stepped_seccomp_for_test(task.pid());
                self.abort(Ok(Wait::Stopped(task, Event::Seccomp))).await
            }
            Ok(task) => task,
        };
        let task = if filtered {
            task
        } else {
            self.apply_sigtrap_repair(task).await?
        };
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
        self.restore_maybe_pending = !matches!(event, Event::Seccomp);
        self.injection_proc_state = None;

        let unreported_stop_signal = self.unreported_stop_signal.take();
        self.timer.observe_event(&event);
        // The guest can remove a timer notification between two stops without
        // an injection seeing the queue. See `untraced_syscall`.
        self.timer.expire_overflow_records(&stopped);
        let tid = self.tid();

        self.ordinary_continuation()?;
        let result = match event {
            Event::Signal(sig) => self
                .handle_signal(stopped, sig.into(), unreported_stop_signal == Some(sig))
                .await
                .tracee_context(tid, "handle signal-delivery stop"),
            // A realtime signal: reported to `Tool::handle_raw_signal_event`
            // and delivered by its raw number
            // (https://github.com/rrnewton/reverie/issues/207).
            Event::RawSignal(raw) => match AnySignal::new(raw) {
                Some(sig) => self
                    .handle_signal(stopped, sig, false)
                    .await
                    .tracee_context(tid, "handle realtime signal-delivery stop"),
                None => panic!(
                    "tracee {} stopped for signal {}, which Linux does not have",
                    tid, raw
                ),
            },
            Event::Exec(_new_pid) => self
                .handle_exec_event(stopped)
                .await
                .tracee_context(tid, "handle exec stop"),
            Event::Seccomp => self.handle_seccomp(stopped).await,
            Event::NewChild(op, child) => self
                .handle_new_task(op, stopped, child, None, None)
                .await
                .tracee_context(tid, "handle new tracee stop"),
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

    /// Reports to `Tool::handle_sigreturn` the guest's `rt_sigreturn` about
    /// to run with stack pointer `sp`. x86-64 `rt_sigreturn` reads its frame
    /// at `sp - 8`, so the frame's `ucontext`, whose `uc_flags` word comes
    /// first, starts at `sp`. Each word is read with the guest's own access
    /// rights (`process_vm_readv`). A word that read fails on is read again
    /// with ptrace's forced access (`PTRACE_PEEKDATA`), which reads any
    /// mapped page whatever its protection: if that succeeds the word is
    /// mapped but protected, otherwise it is unmapped.
    #[cfg(target_arch = "x86_64")]
    fn report_sigreturn(&mut self, task: &Stopped, sp: u64) -> reverie::SigreturnFrame {
        let frame = sigreturn_frame(task, sp);
        let report = reverie::SigreturnReport::new(self.tid(), sp, frame);
        let tool = self.process_state.clone();
        tool.handle_sigreturn(&mut self.thread_state, report);
        frame
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
    #[cfg(target_arch = "x86_64")]
    async fn handle_injected_syscall(
        &mut self,
        task: Stopped,
        frame_address: usize,
        trap_rflags: u64,
    ) -> Result<Wait, TraceError> {
        self.injected_tail_result = None;
        let mut frame = self.read_injected_syscall_frame(&task, frame_address)?;
        let syscall = frame.syscall();
        let (nr, args) = syscall.into_parts();
        // AUTONOMOUS-BOT-IMPLEMENTED
        if nr == Sysno::rt_sigreturn {
            // The trap makes no Tool callback, `Tool::handle_sigreturn`
            // included: an injected-trap site is e9patch's, whose
            // capabilities say it does not report sigreturns. More than the keep margin
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
            let held = self.take_pending_signal_for_resume()?;
            let resume = self
                .report_held_signal(&task, Some(Signal::SIGTRAP.into()), held)
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

            self.in_syscall_callback = true;
            let retval = cancellable(self.cancel_handler.clone(), async {
                self.process_state
                    .clone()
                    .handle_syscall_event(self, syscall)
                    .await
            })
            .await;
            self.in_syscall_callback = false;

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

            if let Some(retval) = retval {
                let result = match retval {
                    Ok(value) => value,
                    Err(errno) => -(errno.into_raw() as i64),
                };
                self.write_injected_syscall_result(&task, Ok(result))?;
            }

            self.pending_syscall = None;
            self.injected_syscall_frame = None;
            let held = self.take_pending_signal_for_resume()?;
            let resume = self
                .report_held_signal(&task, Some(Signal::SIGTRAP.into()), held)
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

    async fn handle_sigtrap(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        // A SIGTRAP that reaches here may be a guest's own trap, whose forced
        // delivery reset an ignored SIGTRAP natively, or a delivery whose
        // `SA_RESETHAND` reset a caught one.
        self.forget_sigtrap_ignored();
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
                    .handle_injected_syscall(task, regs.rdi as usize, regs.eflags)
                    .await?;
                return Ok(HandleSignalResult::SignalSuppressed(next_state));
            }
            return Ok(HandleSignalResult::SignalToDeliver(
                task,
                Signal::SIGTRAP.into(),
            ));
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
        } else if is_guest_int3_trap(&task, regs.ip())? {
            // The guest's own `int3`, at a site that holds no breakpoint of
            // Reverie's (the first arm). Linux delivers its SIGTRAP: a handler
            // runs, or the default action kills the guest with a core. Before,
            // it fell to the arm below, and the guest ran past its own
            // breakpoint (https://github.com/rrnewton/hermit/issues/1715).
            if self.attached_by_gdb {
                // Under a debugger, as natively, the trap stops the guest and
                // is reported to GDB, whose resume decides whether the guest
                // gets the signal (`continue` drops it; `signal SIGTRAP`
                // passes it on).
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
                HandleSignalResult::SignalToDeliver(task, Signal::SIGTRAP.into())
            }
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
            _ => HandleSignalResult::SignalToDeliver(task, Signal::SIGSEGV.into()),
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    async fn handle_sigsegv(&mut self, task: Stopped) -> Result<HandleSignalResult, TraceError> {
        Ok(HandleSignalResult::SignalToDeliver(
            task,
            Signal::SIGSEGV.into(),
        ))
    }

    fn take_pending_signal_for_resume(&mut self) -> Result<Option<AnySignal>, TraceError> {
        Ok(self.pending_signal.take())
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
    /// The hold took the count (`pending_signal_reported`), so a held instance
    /// that was not in the queue then, such as one held before the reported
    /// instance was requeued, is never taken for it, and the counted instance
    /// delivered at its own stop instead ends its count there
    /// (`handle_signal`). A real-time signal's count is by number.
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
        stop_signal: Option<AnySignal>,
        signal: Option<AnySignal>,
    ) -> Result<SignalResume, TraceError> {
        let taken = self.pending_signal_taken;
        // Resumed from a signal-delivery stop, whose siginfo can be written.
        let writable = self.latest_injection_stop.unwrap_or(stop_signal).is_some()
            && !thread_may_be_seccomp_filtered();
        let mut resume = self
            .report_or_pass_held_signal(task, stop_signal, signal)
            .await?;
        // A signal passed on unreported keeps its siginfo, which can carry a
        // `sigqueue` value and its sender; Linux would otherwise make one up
        // (SI_USER from the tracer, no value) for the stop it is resumed from
        // after the callback's injections
        // (<https://github.com/rrnewton/reverie/issues/207>,
        // <https://github.com/rrnewton/reverie/issues/999>).
        if resume.reported.is_none()
            && resume.replacement.is_none()
            && writable
            && let (Some(sig), Some(taken)) = (resume.signal, taken)
            && sig == taken.signal
        {
            resume.replacement = Some((sig, taken.bytes));
        }
        Ok(resume)
    }

    /// `report_held_signal`, before a signal passed on unreported gets its
    /// siginfo back.
    async fn report_or_pass_held_signal(
        &mut self,
        task: &Stopped,
        stop_signal: Option<AnySignal>,
        signal: Option<AnySignal>,
    ) -> Result<SignalResume, TraceError> {
        let record = self.pending_signal_taken.take();
        let reported = std::mem::take(&mut self.pending_signal_reported);
        let taken = record;
        let Some(sig) = signal else {
            return Ok(self.pass_held_signal_unreported(None));
        };
        if sig == Signal::SIGSTOP
            || sig == Timer::signal_type()
            || self.latest_injection_stop.unwrap_or(stop_signal).is_none()
            || self.sigtrap_may_be_claimed()
        {
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, reported)
                .await;
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
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, reported)
                .await;
        }
        // A procfs or register read that fails passes the signal on
        // unreported, as main resumes every held signal, rather than failing
        // a resume main makes.
        let Ok(blocked) = blocked_signal_mask(task.pid()) else {
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, reported)
                .await;
        };
        if blocked & signal_mask_bit(sig) != 0
            || !task.getsigmask().is_ok_and(|saved| saved == blocked)
        {
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, reported)
                .await;
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
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, reported)
                .await;
        }
        // An instance that was reported already is passed on unreported, and
        // its count stays taken: it is delivered now.
        if reported {
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, false)
                .await;
        }
        // Without its record the siginfo cannot be written back after the
        // callback's injections, and the guest would get one Linux makes up.
        // The capture can fail where this check passes: a procfs open the
        // capture made can fail (EMFILE) and a later one succeed.
        let Some(taken) = taken.filter(|taken| taken.signal == sig) else {
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, false)
                .await;
        };
        let stale_step_trap = if self.stale_private_step_trap {
            signal_mask_bit(Signal::SIGTRAP)
        } else {
            0
        };
        if pending_signal_mask(task.pid()).map_or(true, |pending| pending & !stale_step_trap != 0) {
            return self
                .pass_held_signal_unreported_unless_filtered(signal, record, false)
                .await;
        }
        tracing::debug!(
            "[{}] reporting held signal {} before resuming",
            self.tid(),
            sig
        );
        let verdict = self.report_signal(sig, true, Some(taken.bytes)).await?;
        Ok(SignalResume {
            signal: verdict.signal,
            reported: Some(taken),
            approved: verdict.approved,
            replacement: verdict.replacement,
        })
    }

    /// A conservative guard used while a private injection runs: whether an
    /// asynchronous SIGTRAP from the guest or another process could be
    /// claimed by a consumer other than the injection, so the injection must
    /// not discard it. True when a binary rewriter's trap is configured
    /// (`injected_syscall_trap`), which delivers a trap with its marker in
    /// RAX; or when gdb has resumed this thread or set a breakpoint in it, so
    /// a trap can be reported to gdb.
    fn sigtrap_may_be_claimed(&self) -> bool {
        self.global_state.injected_syscall_trap.is_some()
            || self.resumed_by_gdb.is_some()
            || !self.breakpoints.is_empty()
    }

    /// The resume of a held `signal` that is passed on without a report to
    /// `Tool::handle_signal_event`. A job-control stop signal is recorded
    /// (`unreported_stop_signal`), so that the group stop its delivery makes
    /// is reported instead.
    fn pass_held_signal_unreported(&mut self, signal: Option<AnySignal>) -> SignalResume {
        if let Some(sig @ (Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU)) =
            signal.and_then(AnySignal::as_nix)
        {
            self.unreported_stop_signal = Some(sig);
        }
        SignalResume {
            signal,
            reported: None,
            approved: false,
            replacement: None,
        }
    }

    /// `pass_held_signal_unreported`, after `Tool::filter_unreported_signal`
    /// keeps the signal (`keeps_unreported_signal`); a signal it drops is
    /// resumed as none. `taken` is the held signal's record, whose siginfo
    /// the hook gets when it is this signal's.
    ///
    /// `restore_count` says the signal is an instance the Tool was told about
    /// already, whose count its hold took (`pending_signal_reported`), passed
    /// on where that count must stay: the resume can put it back in the
    /// kernel's queue (a mask that blocks it), as when it was counted, so a
    /// kept signal gives its count back. A dropped signal leaves the queue for
    /// good, so its count stays taken. An instance the hold took no count for
    /// changes no count, kept or dropped.
    async fn pass_held_signal_unreported_unless_filtered(
        &mut self,
        signal: Option<AnySignal>,
        taken: Option<TakenSignal>,
        restore_count: bool,
    ) -> Result<SignalResume, TraceError> {
        if let Some(sig) = signal {
            let info = taken
                .filter(|taken| taken.signal == sig)
                .map(|taken| taken.bytes);
            if !self.keeps_unreported_signal(sig, info).await {
                return Ok(self.pass_held_signal_unreported(None));
            }
            if restore_count {
                let count = self.reported_requeued_signals.entry(sig).or_default();
                *count = count.saturating_add(1);
            }
        }
        Ok(self.pass_held_signal_unreported(signal))
    }

    /// Ends one reported, requeued instance of `sig`
    /// (`reported_requeued_signals`), returning whether there was one.
    fn take_reported_requeue(&mut self, sig: impl Into<AnySignal>) -> bool {
        let sig = sig.into();
        let Some(count) = self.reported_requeued_signals.get_mut(&sig) else {
            return false;
        };
        *count -= 1;
        if *count == 0 {
            self.reported_requeued_signals.remove(&sig);
        }
        true
    }

    /// The signal `sig`, which stop `task` took and Reverie is about to pass
    /// to the guest without reporting it to `Tool::handle_signal_event`, or
    /// `None` if `Tool::filter_unreported_signal` drops it
    /// (`keeps_unreported_signal`). The caller resumes `task` with the result
    /// exactly as it would have resumed it with `sig`.
    ///
    /// The stop took `sig` from the kernel's queue, so if a reported,
    /// requeued instance of `sig` was there, this is it, as for a hold
    /// (`hold_pending_signal`), and its count ends. Kept, it goes back into
    /// the queue when the guest's mask blocks it (Linux's synchronous dequeue
    /// can take a blocked signal at a step), and then keeps its count.
    async fn filter_direct_unreported(
        &mut self,
        task: &Stopped,
        sig: impl Into<AnySignal>,
    ) -> Option<AnySignal> {
        let sig = sig.into();
        let counted = self.take_reported_requeue(sig);
        let info = TakenSignal::at_stop(task, sig).map(|taken| taken.bytes);
        if !self.keeps_unreported_signal(sig, info).await {
            return None;
        }
        // An unreadable mask counts as blocking, as in `resume_with_signal`.
        if counted
            && blocked_signal_mask(task.pid())
                .map_or(true, |blocked| blocked & signal_mask_bit(sig) != 0)
        {
            let count = self.reported_requeued_signals.entry(sig).or_default();
            *count = count.saturating_add(1);
        }
        Some(sig)
    }

    /// Whether a signal that Reverie passes to the guest unreported reaches it:
    /// it does if `Tool::filter_unreported_signal` keeps it. The hook gets
    /// only the signal's description and an RPC handle, so it cannot change
    /// the guest.
    ///
    /// Every such signal is shown, Reverie's own included: a SIGSTOP of a gdb
    /// freeze or the timer's notification. Linux does not tell them apart
    /// from a guest's signal of the same number. A guest's SIGSTOP and
    /// Reverie's are one pending instance, and a guest can queue itself the
    /// timer's number with the timer's `si_code` and `si_fd`. So no state of
    /// Reverie's can exempt one exactly, and an inexact exemption would keep
    /// a guest's signal from the hook. Showing them all changes nothing for a
    /// Tool that keeps the signals it does not own, as the hook's contract
    /// requires and its default does.
    async fn keeps_unreported_signal(&self, sig: AnySignal, info: Option<SiginfoBytes>) -> bool {
        // Every `AnySignal` is numbered 1 to 64, which `from_number` accepts.
        let Some(unreported) =
            reverie::UnreportedSignal::from_number(self.pid(), self.tid(), sig.raw(), info)
        else {
            return true;
        };
        let keep = self
            .process_state
            .clone()
            .filter_unreported_signal(self, unreported)
            .await;
        if !keep {
            tracing::debug!(
                "[{}] the tool dropped signal {} passed on unreported",
                self.tid(),
                sig
            );
        }
        keep
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
        let SignalResume {
            signal,
            reported,
            approved,
            replacement,
        } = resume;
        if let (Some(sig), Some(taken), Some(stop)) = (signal, reported, self.latest_injection_stop)
            && sig == taken.signal
        {
            // Main writes no siginfo here, so a failed write must not fail
            // the resume. A task that is gone fails the resume instead. An
            // approved delivery (`Guest::deliver_signal`) is of exactly the
            // recorded instance, so for it a failed write fails the resume
            // rather than deliver the signal with another siginfo.
            if stop.is_some()
                && let Err(err) = task.setsiginfo(&taken.siginfo.0)
            {
                if approved {
                    tracing::error!("could not restore the siginfo of approved {sig:?}: {err}");
                    return Err(err);
                }
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
        // A siginfo the reporting callback chose (`Guest::set_signal_info`)
        // replaces the signal's own when it is resumed from a signal-delivery
        // stop: its own, when no injection ran, or the latest injection's.
        // `set_signal_info` wrote it already; it is written again for a later
        // injection. Unlike the best-effort restore above, an explicit choice
        // that cannot be delivered fails the resume rather than letting the
        // guest see another siginfo: from a stop that is not a signal-delivery
        // stop, Linux would make one up.
        // A replacement chosen for the reported signal is dropped when the
        // callback resumes another signal or none.
        if let (Some(sig), Some((chosen_for, bytes))) = (signal, replacement)
            && sig == chosen_for
        {
            if !self.latest_injection_stop.is_none_or(|stop| stop.is_some()) {
                return Err(Errno::EBUSY.into());
            }
            task.setsiginfo_bytes(&bytes)?;
        }
        self.resume_stopped_any(task, signal)?
            .next_state_with_owner(&self.ptracer_waits)
            .await
    }

    /// The Tool's verdict on `sig`: `Tool::handle_signal_event` for a signal
    /// nix can name, `Tool::handle_raw_signal_event` for one it cannot (a
    /// realtime signal; https://github.com/rrnewton/reverie/issues/207).
    async fn tool_signal_verdict(&mut self, sig: AnySignal) -> Result<Option<AnySignal>, Errno> {
        match sig.as_nix() {
            Some(signal) => self
                .process_state
                .clone()
                .handle_signal_event(self, signal)
                .await
                .map(|verdict| verdict.map(AnySignal::from)),
            None => self
                .process_state
                .clone()
                .handle_raw_signal_event(self, sig.raw())
                .await?
                // A number outside 1 to 64 names no signal to deliver.
                .map(|raw| AnySignal::new(raw).ok_or(Errno::EINVAL))
                .transpose(),
        }
    }

    /// Ends the run for a signal callback that broke the delivery it
    /// approved (`Guest::deliver_signal`), with a named failure, and returns
    /// the error that stops the task.
    fn fail_broken_approval(&self, approval: SignalApproval, reason: &'static str) -> TraceError {
        let failure = crate::BrokenSignalApproval {
            tid: self.tid().as_raw(),
            signal: approval.signal.raw(),
            reason,
        };
        tracing::error!("{failure}");
        self.fatal_session().fail_at(
            BackendFailure {
                pid: self.pid(),
                tid: self.tid(),
                phase: "signal callback after an approved delivery",
            },
            anyhow::Error::new(failure).into(),
        );
        Errno::ENOTRECOVERABLE.into()
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
        sig: AnySignal,
        held: bool,
        info: Option<SiginfoBytes>,
    ) -> Result<SignalVerdict, TraceError> {
        let outer = std::mem::replace(&mut self.in_signal_callback, true);
        let outer_reported = self.reported_signal.replace((sig, info));
        let outer_replacement = self.replacement_signal_info.take();
        let outer_approval = self.signal_approval.take();
        let outer_mismatched = std::mem::replace(&mut self.signal_delivery_mismatched, false);
        let outer_replaced =
            std::mem::replace(&mut self.signal_callback_replaced_restart_block, false);
        let outer_guest_block =
            std::mem::replace(&mut self.signal_callback_guest_restart_block, false);
        let outer_held = std::mem::replace(&mut self.in_held_signal_callback, held);
        let result = if held {
            let outer_execed = std::mem::replace(&mut self.signal_callback_execed, false);
            let result =
                cancellable(self.cancel_handler.clone(), self.tool_signal_verdict(sig)).await;
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
            self.tool_signal_verdict(sig).await
        };
        self.in_signal_callback = outer;
        self.reported_signal = outer_reported;
        let replacement = std::mem::replace(&mut self.replacement_signal_info, outer_replacement);
        let approval = std::mem::replace(&mut self.signal_approval, outer_approval);
        self.signal_delivery_mismatched = outer_mismatched;
        self.in_held_signal_callback = outer_held;
        self.signal_callback_replaced_restart_block = outer_replaced;
        self.signal_callback_guest_restart_block = outer_guest_block;
        let signal = self
            .ordinary_callback_errno("ptrace signal callback", result)
            .await?;
        if let Some(approval) = approval
            && let Some(reason) = approval_violation(approval, signal)
        {
            // A Tool defect: delivering would hand the guest something the
            // checks did not cover, and suppressing would lose an approved
            // signal. Neither is safe, so the guest is not resumed.
            return Err(self.fail_broken_approval(approval, reason));
        }
        self.ordinary_trace_continuation()?;
        self.timer.finalize_requests();
        Ok(SignalVerdict {
            signal,
            approved: approval.is_some(),
            replacement,
        })
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

    /// Handles a signal-delivery stop, or a group stop, of `sig`.
    /// `report_group_stop` says that the previous stop resumed `sig` held
    /// and unreported (`unreported_stop_signal`), so a group stop of it is
    /// reported.
    async fn handle_signal(
        &mut self,
        task: Stopped,
        sig: AnySignal,
        report_group_stop: bool,
    ) -> Result<Wait, TraceError> {
        #[cfg(test)]
        if let Some(stats) = self.global_state.backend_stats.as_ref()
            && let Some(sig) = sig.as_nix()
        {
            stats.record_signal_stop(&task, sig);
        }
        tracing::debug!("[{}] handle_signal: received signal {}", task.pid(), sig);
        let group_stop = sig != Signal::SIGSTOP && is_group_stop_unless_filtered(&task, sig)?;
        if group_stop && !report_group_stop {
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
        // A signal-delivery stop took `sig` from the kernel's queue. If a
        // reported, requeued instance of `sig` was there, this is it, as for a
        // hold (`hold_pending_signal`), and its count ends here: before the
        // backend's own handling below, which can suppress it (a SIGSEGV that
        // is an emulated instruction's fault, Reverie's own trap or timer
        // signal), and whether the Tool then delivers or suppresses it. A
        // resume that requeues it again counts it again
        // (`resume_with_signal`). A group stop, reported or not, takes
        // nothing from the queue.
        if !group_stop {
            self.take_reported_requeue(sig);
        }
        // A SIGILL at the `ud2` after the untraced `syscall` of the private
        // page is a guest's own call through it: Reverie's injections step
        // that `syscall` in `step_private_syscall` and take their stops there,
        // so none reaches this point. The call was invisible to the Tool and
        // has already taken effect. End the run with a named failure instead
        // of delivering the SIGILL, which a handler or a forked child could use
        // to keep the result (https://github.com/rrnewton/reverie/issues/1064).
        if sig.as_nix() == Some(Signal::SIGILL) && !group_stop {
            let address = task.getregs()?.ip();
            if address == (cp::TRAMPOLINE_BASE + cp::SYSCALL_INSTR_SIZE) as u64 {
                self.fatal_session().fail_at(
                    BackendFailure {
                        pid: self.pid(),
                        tid: self.tid(),
                        phase: "guest syscall through the untraced private-page stub",
                    },
                    anyhow::Error::new(crate::UntracedStubSyscall {
                        tid: self.tid().as_raw(),
                        address,
                    })
                    .into(),
                );
                return Err(Errno::ECANCELED.into());
            }
        }
        let result = match sig.as_nix() {
            Some(Signal::SIGSEGV) => self.handle_sigsegv(task).await?,
            Some(Signal::SIGSTOP) => self.handle_sigstop(task).await?,
            Some(Signal::SIGTRAP) => self.handle_sigtrap(task).await?,
            Some(timer) if timer == Timer::signal_type() => {
                let (was_timer, task) = self.handle_timer(task).await?;
                if was_timer {
                    HandleSignalResult::SignalSuppressed(
                        self.resume_stopped(task, None)?
                            .next_state_with_owner(&self.ptracer_waits)
                            .await?,
                    )
                } else {
                    HandleSignalResult::SignalToDeliver(task, sig)
                }
            }
            // A realtime signal (one nix cannot name) is always delivered
            // to the guest after the Tool's verdict, like any other signal.
            _ => HandleSignalResult::SignalToDeliver(task, sig),
        };

        match result {
            HandleSignalResult::SignalSuppressed(wait) => Ok(wait),
            HandleSignalResult::SignalToDeliver(task, sig) => {
                let taken = TakenSignal::at_stop(&task, sig);
                let verdict = self
                    .report_signal(sig, false, taken.map(|taken| taken.bytes))
                    .await?;
                let signal = verdict.signal;
                let resume = SignalResume {
                    signal,
                    reported: taken,
                    approved: verdict.approved,
                    replacement: verdict.replacement,
                };
                self.resume_with_signal(task, resume).await
            }
        }
    }

    fn refuse_exec_return(&self, error: anyhow::Error) -> TraceError {
        self.fatal_session().fail_at(
            BackendFailure {
                pid: self.pid(),
                tid: self.tid(),
                phase: "ptrace exec return boundary",
            },
            error.context("ptrace-exec-return-unobserved").into(),
        );
        Errno::EPROTO.into()
    }

    // handle ptrace exec event
    async fn handle_exec_event(&mut self, task: Stopped) -> Result<Wait, TraceError> {
        // Linux enables CPUID again on every successful replacement exec.
        // This old-image fact must not survive until the new arm is verified.
        self.has_cpuid_interception = false;
        // A signal callback that injected the exec never resumes, so the
        // replacement image runs outside it, and its state, which
        // `report_signal` would have restored, must not reach the post-exec
        // callbacks' injections: a held callback's injections keep the
        // guest's return register.
        self.in_signal_callback = false;
        // Likewise a syscall callback that injected the exec never resumes:
        // the post-exec callbacks run for the replacement image, outside it,
        // so `Guest::set_blocked_signals` refuses there (Codex review of
        // https://github.com/rrnewton/reverie/pull/1083, P2).
        self.in_syscall_callback = false;
        self.reported_signal = None;
        self.replacement_signal_info = None;
        self.signal_delivery_mismatched = false;
        if let Some(approval) = self.signal_approval.take() {
            // The callback that approved a delivery executed a program, which
            // never returns to it: the approved signal would be lost, and the
            // replacement image would run on unchecked. As in `report_signal`,
            // the guest is not resumed.
            return Err(self.fail_broken_approval(approval, "then executed a program"));
        }
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
        // execve/execveat are tail injected, however, after exec, the new
        // program start as a clean slate, hence it is actually ok to do either
        // inject or tail inject after execve succeeded.
        self.pending_syscall = None;
        self.injected_syscall_frame = None;

        // TODO: Update PID? Need to write a test checking this.

        // Drain the kernel's exec return, not a user instruction. Linux runs
        // syscall-exit tracing before ordinary pending-signal delivery on this
        // path. Keep those signals queued; searching for a later stop with
        // CONT or SINGLESTEP could execute the first guest opcode unarmed.
        let entry_regs = task.getregs()?;
        #[allow(clippy::useless_conversion)]
        let entry_ip = u64::from(entry_regs.ip());
        #[allow(clippy::useless_conversion)]
        let entry_sp = u64::from(entry_regs.stack_ptr());
        #[cfg(test)]
        let preinit_point = self.global_state.preinit_point_for_test.clone();
        #[cfg(test)]
        at_preinit_point(
            &preinit_point,
            task.pid(),
            || task.terminal_cleanup(),
            PreinitPoint::ExecStopped,
        );
        // Retain the per-image SIGTRAP disposition/mask owner for injected
        // pre-init steps. Draining the exec syscall below creates no user
        // single-step trap and therefore needs no temporary mask change.
        // The table bookkeeping follows the kernel whatever this tracer
        // thread's filter state: siblings sharing the table may keep SIGTRAP.
        // Exec gives the group a table of its own, a copy of the one it used,
        // which another group may go on using, and a change this thread
        // marked on its old table ends here.
        if self.global_state.keeps_sigtrap_state {
            self.end_sigtrap_changing();
            {
                let pid = self.pid();
                let mut tables = self.global_state.sigtrap_tables.lock().unwrap();
                let table = tables.copy(pid, Some(self.sigtrap_table));
                tables.leave(pid, self.sigtrap_table);
                self.sigtrap_table = table;
            }
            // The new image has no repair page until pre-init seals one
            // (`seal_sigtrap_scratch`); a repair owed meanwhile waits for it.
            self.sigtrap_scratch_state = Arc::new(AtomicU8::new(SCRATCH_PENDING));
            // Exec resets a caught handler to `SIG_DFL` and keeps `SIG_IGN`, so
            // only an ignored action can still be owed a repair.
            if matches!(self.sigtrap_repair(), Some(SigtrapRepair::Action(_))) {
                self.set_sigtrap_repair(None);
            }
        }
        if self.keeps_sigtrap_state() {
            // One procfs read decides for the whole exec: with SIGTRAP
            // neither ignored nor blocked, and no repair owed, the injected
            // pre-init steps need no shielding.
            let state = ProcSignalState::read(&task)?;
            {
                let mut tables = self.global_state.sigtrap_tables.lock().unwrap();
                tables.changing.remove(&self.sigtrap_table);
                tables.ignored.insert(
                    self.sigtrap_table,
                    (state.sigtrap_ignored, state.sigtrap_caught),
                );
            }
            self.exec_sigtrap_quiet = !state.sigtrap_ignored
                && state.blocked & SIGTRAP_BIT == 0
                && self.sigtrap_repair().is_none();
            if state.sigtrap_ignored {
                self.note_sigtrap_repair(SigtrapRepair::Ignored);
            }
        }
        let running = self.syscall_stopped(task, None)?;
        let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
        self.arm_liteinst_wait(&wait);
        let (task, event) = match wait {
            Wait::Stopped(task, event) => (task, event),
            Wait::Exited(pid, exit_status) => return Ok(Wait::Exited(pid, exit_status)),
        };
        let info = match task.getsyscallinfo() {
            Ok(info) => info,
            Err(safeptrace::SyscallInfoError::Trace(died @ TraceError::Died(_))) => {
                return Err(died);
            }
            Err(error) => return Err(self.refuse_exec_return(anyhow::Error::new(error))),
        };
        #[cfg(target_arch = "x86_64")]
        const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
        #[cfg(target_arch = "aarch64")]
        const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;
        let returned_regs = task.getregs()?;
        if event != Event::Syscall
            || info.architecture != NATIVE_AUDIT_ARCH
            || info.operation
                != (safeptrace::SyscallInfoOp::Exit {
                    return_value: 0,
                    is_error: false,
                })
            || info.instruction_pointer != entry_ip
            || info.stack_pointer != entry_sp
            || returned_regs.ip() != entry_regs.ip()
            || returned_regs.stack_ptr() != entry_regs.stack_ptr()
            || returned_regs.ret() != 0
        {
            // This stop does not authorize guest execution or another resume
            // toward an assumed exit. Retain its owned stop for fatal cleanup;
            // do not consume or reinject a signal while guessing the phase.
            let signal_observation = event.signal().map(|signal| {
                (
                    is_group_stop(&task, signal),
                    task.getsiginfo()
                        .map(|si| (si.si_signo, si.si_errno, si.si_code)),
                )
            });
            return Err(self.refuse_exec_return(anyhow::anyhow!(
                "expected native EXIT(0) at entry ip={entry_ip:#x} sp={entry_sp:#x}; \
                 observed event={event:?} info={info:?} ip={:#x} sp={:#x} return={:#x} signal={signal_observation:?}",
                returned_regs.ip(),
                returned_regs.stack_ptr(),
                returned_regs.ret(),
            )));
        }
        #[cfg(test)]
        if let Some(hook) = POST_EXEC_RETURN_FOR_TEST.with(|slot| slot.borrow_mut().take()) {
            hook(&task, &info);
        }
        #[cfg(test)]
        at_preinit_point(
            &preinit_point,
            task.pid(),
            || task.terminal_cleanup(),
            PreinitPoint::PostExecDrained,
        );
        let task = match self.tracee_preinit(task, PreinitPlace::AtExec).await? {
            PreinitOutcome::Ready(task) => task,
            PreinitOutcome::Refused(_task) => return Err(Errno::ECANCELED.into()),
            PreinitOutcome::Exited(pid, exit_status) => {
                self.exec_sigtrap_quiet = false;
                return Ok(Wait::Exited(pid, exit_status));
            }
        };
        let exec_sigtrap_quiet = std::mem::take(&mut self.exec_sigtrap_quiet);

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
            // This step runs the new image's first instruction; its trap must
            // not reset SIGTRAP either (`sigtrap_state`).
            // An instruction that raises its own SIGTRAP resets it natively too,
            // so its step is neither shielded nor repaired.
            let (shielded, ignored) = if exec_sigtrap_quiet
                || !self.keeps_sigtrap_state()
                || next_instruction_raises_sigtrap(&task)?
            {
                (false, false)
            } else {
                let ignored = sigtrap_disposition(&task)?.0;
                (
                    self.shield_sigtrap_for_step(&task, "first instruction after exec")?,
                    ignored,
                )
            };
            let wait = self
                .step_stopped(task, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await?;
            self.arm_liteinst_wait(&wait);
            if shielded {
                reblock_sigtrap_after_step(&wait)?;
            }
            if ignored {
                self.note_sigtrap_repair(SigtrapRepair::Ignored);
            }
            match wait {
                Wait::Stopped(task, Event::Signal(Signal::SIGTRAP))
                    if task.getsiginfo()?.si_code == libc::TRAP_TRACE =>
                {
                    let task = if ignored {
                        self.apply_sigtrap_repair(task).await?
                    } else {
                        task
                    };
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

    /// Runs an unsubscribed memory-mapping syscall from its seccomp stop
    /// without a Tool callback.
    ///
    /// A plain run reaches this when a guest-installed seccomp filter returns
    /// `SECCOMP_RET_TRACE` for a mapping syscall the Tool did not subscribe
    /// to (`PTRACE_O_TRACESECCOMP` is always set). The Tool contract says
    /// only subscribed syscalls reach its handler, so the tracer lets the
    /// kernel run the call and resumes the guest at its return.
    async fn handle_unsubscribed_mapping_syscall(&mut self, task: Stopped) -> Result<Wait, Error> {
        let tid = self.tid();
        let wait = self
            .syscall_stopped(task, None)
            .tracee_context(tid, "resume unsubscribed mapping syscall")?
            .next_state_with_owner(&self.ptracer_waits)
            .await
            .tracee_context(tid, "wait for unsubscribed mapping syscall")?;
        self.arm_liteinst_wait(&wait);
        match wait {
            Wait::Stopped(stopped, Event::Syscall) => self
                .resume_stopped(stopped, None)
                .tracee_context(tid, "resume after unsubscribed mapping syscall")?
                .next_state_with_owner(&self.ptracer_waits)
                .await
                .tracee_context(tid, "wait after unsubscribed mapping syscall"),
            Wait::Stopped(_, event) => Err(Error::runtime(
                tid,
                "run unsubscribed mapping syscall",
                format!("unexpected stopped event: {event:?}"),
            )),
            Wait::Exited(_, exit_status) => self.exit(exit_status).await,
        }
    }

    async fn handle_seccomp(&mut self, mut task: Stopped) -> Result<Wait, Error> {
        let tid = self.tid();
        let syscall = self
            .get_syscall(&task)
            .tracee_context(tid, "read registers at seccomp stop")?;
        let (nr, args) = syscall.into_parts();
        // Whatever this thread's own tracer filter state: a sibling sharing
        // the table may keep SIGTRAP.
        if self.global_state.keeps_sigtrap_state {
            self.note_sigtrap_action_syscall(nr, &args);
        }
        let tool_subscribed = self
            .global_state
            .subscriptions
            .iter_syscalls()
            .any(|subscribed| subscribed == nr);
        if is_liteinst_mapping_syscall(nr) && !tool_subscribed {
            if let Some(stats) = &self.global_state.backend_stats {
                stats.record_internal_seccomp_stop();
            }
            return self.handle_unsubscribed_mapping_syscall(task).await;
        }
        #[cfg(target_arch = "x86_64")]
        let is_legacy_vsyscall = is_legacy_vsyscall_ip(
            task.getregs()
                .tracee_context(tid, "identify legacy vsyscall stop")?
                .ip(),
        );
        #[cfg(not(target_arch = "x86_64"))]
        let is_legacy_vsyscall = false;
        // A SIGTRAP action that a Reverie trap reset is written back before
        // the Tool or the syscall can read it (`repair_sigtrap_at_seccomp_stop`).
        if !is_legacy_vsyscall {
            task = self
                .repair_sigtrap_at_seccomp_stop(task)
                .await
                .tracee_context(tid, "write back SIGTRAP's action at a seccomp stop")?;
        }
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
            // Reverie's filter traces rt_sigreturn only where it is reported
            // (`GlobalState::reports_sigreturns`). Any other traced
            // rt_sigreturn, which only a guest's own filter can trace, goes
            // to `handle_syscall_event` as before.
            #[cfg(target_arch = "x86_64")]
            let sigreturn = nr == Sysno::rt_sigreturn && self.global_state.reports_sigreturns;
            #[cfg(not(target_arch = "x86_64"))]
            let sigreturn = false;
            if sigreturn {
                // The Tool does not see this stop as an event and cannot ask
                // for a timer here, so the stop keeps the timer event as an
                // injected-trap rt_sigreturn does (`handle_injected_syscall`)
                // more than `PmuConfig::keep_margin` short of its target.
                // Within the margin, where host timing decides whether its
                // notification is pending, taken or lost, an undelivered
                // precise event is cancelled and requested again at the same
                // target, so that it still fires there, as the guest's clock
                // alone decides, or, if a late notification let the guest
                // pass the target, one branch after the return
                // (`Timer::disregard_sigreturn_stop`). Only if
                // the mask the frame installs leaves the timer's signal
                // unblocked, since the new request's notification comes after
                // the return; otherwise the event is cancelled, as before.
                #[cfg(target_arch = "x86_64")]
                {
                    let sp = task
                        .getregs()
                        .tracee_context(tid, "read rt_sigreturn registers")?
                        .rsp;
                    let frame = self.report_sigreturn(&task, sp);
                    let notified_after_return = timer_notified_after_return(frame);
                    self.timer
                        .disregard_sigreturn_stop(notified_after_return)
                        .map_err(TraceError::from)
                        .tracee_context(tid, "keep the timer across rt_sigreturn")?;
                }
                self.ordinary_continuation()?;
                self.ordinary_trace_continuation()?;
                self.timer.finalize_requests();
                // With nothing pending, the guest's own call is neither
                // skipped nor given a result: it runs untouched on this
                // resume. Linux ignores a signal handed to a resume from a
                // ptrace event stop such as this seccomp stop, so a signal
                // held for the resume stays held for the guest's next stop,
                // as `handle_unsubscribed_mapping_syscall` leaves it.
                return self
                    .resume_stopped(task, None)
                    .tracee_context(tid, "resume rt_sigreturn")?
                    .next_state_with_owner(&self.ptracer_waits)
                    .await
                    .tracee_context(tid, "wait after rt_sigreturn");
            }
            self.pending_syscall = Some((nr, args));

            self.in_syscall_callback = true;
            let retval = cancellable(self.cancel_handler.clone(), async {
                self.process_state
                    .clone()
                    .handle_syscall_event(self, syscall)
                    .await
            })
            .await;
            self.in_syscall_callback = false;

            let retval = match retval {
                Some(Err(error)) if !matches!(error, reverie::Error::Errno(_)) => {
                    self.publish_ordinary_failure("ptrace syscall callback", error);
                    return Err(Error::RunFailed);
                }
                result => result,
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
            if pending_syscall.is_some() && !emulate_legacy_vsyscall {
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

            #[cfg(test)]
            if let Some(hook) = self.global_state.final_resume_signal_for_test.clone() {
                let regs = task
                    .getregs()
                    .tracee_context(tid, "read registers for a test resume signal")?;
                if let Some(sig) = hook(self.tid, &regs) {
                    self.pending_signal = Some(sig.into());
                    self.pending_signal_taken = None;
                    self.pending_signal_reported = false;
                }
            }
            let held = self.take_pending_signal_for_resume()?;
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

    fn liteinst_root_stop_slot(&self) -> Option<Arc<StdMutex<Option<HeldRootStop>>>> {
        Some(self.ordinary_held_stop.clone())
    }

    fn liteinst_root_stop_armer(&self, task: &Stopped) -> Option<LiteinstRootStopArmer> {
        let slot = self.liteinst_root_stop_slot()?;
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
        let slot = self.liteinst_root_stop_slot();
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
        #[cfg(test)]
        record_step_for_test(task.pid());
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

    /// `resume_stopped` for a signal that may be one nix cannot name
    /// (`AnySignal`), delivered by its raw number.
    fn resume_stopped_any(
        &self,
        task: Stopped,
        signal: Option<AnySignal>,
    ) -> Result<Running, TraceError> {
        match signal {
            Some(signal) if signal.as_nix().is_none() => {
                if self.global_state.fatal_session.is_failed() {
                    return Err(Errno::ECANCELED.into());
                }
                self.lease_liteinst_root_stop(task).resume_raw(signal.raw())
            }
            signal => self.resume_stopped(task, signal.and_then(AnySignal::as_nix)),
        }
    }

    /// `step_stopped` for a signal that may be one nix cannot name.
    fn step_stopped_any(
        &self,
        task: Stopped,
        signal: Option<AnySignal>,
    ) -> Result<Running, TraceError> {
        match signal {
            Some(signal) if signal.as_nix().is_none() => {
                if self.global_state.fatal_session.is_failed() {
                    return Err(Errno::ECANCELED.into());
                }
                #[cfg(test)]
                record_step_for_test(task.pid());
                self.lease_liteinst_root_stop(task).step_raw(signal.raw())
            }
            signal => self.step_stopped(task, signal.and_then(AnySignal::as_nix)),
        }
    }

    /// `syscall_stopped` for a signal that may be one nix cannot name.
    fn syscall_stopped_any(
        &self,
        task: Stopped,
        signal: Option<AnySignal>,
    ) -> Result<Running, TraceError> {
        match signal {
            Some(signal) if signal.as_nix().is_none() => {
                if self.global_state.fatal_session.is_failed() {
                    return Err(Errno::ECANCELED.into());
                }
                self.lease_liteinst_root_stop(task)
                    .syscall_raw(signal.raw())
            }
            signal => self.syscall_stopped(task, signal.and_then(AnySignal::as_nix)),
        }
    }

    async fn handle_new_task(
        &mut self,
        op: ChildOp,
        parent: Stopped,
        child: Running,
        context: Option<libc::user_regs_struct>,
        child_context: Option<libc::user_regs_struct>,
    ) -> Result<Wait, TraceError> {
        tracing::debug!(
            "[scheduler] handling fork from parent {} to child {}: {:?}",
            parent.pid(),
            child.pid(),
            op
        );

        #[cfg(test)]
        if matches!(op, ChildOp::Fork | ChildOp::Vfork) {
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

        // A clone without CLONE_THREAD but with a non-SIGCHLD exit signal is
        // also reported as a clone event. It is a process, with its own pid,
        // and its creator's exit must not wait for it as for a thread. A
        // failed read is reported only after the child is owned, below.
        let own_process_parent = match op {
            ChildOp::Clone => crate::tracer::newborn_own_process_parent(child.pid()),
            ChildOp::Fork | ChildOp::Vfork => Ok(Some(self.pid)),
        };
        let is_thread = op == ChildOp::Clone && !matches!(own_process_parent, Ok(Some(_)));
        let mut child_task = if is_thread {
            self.cloned(child.pid())
        } else {
            self.forked(
                child.pid(),
                shares_signal_actions(&parent),
                op == ChildOp::Vfork || shares_address_space(&parent),
            )
        };
        // A process made by a clone event has the parent the kernel recorded
        // for it: `CLONE_PARENT` makes that the creator's parent, which
        // `cloned()` reported for it before it was built as a process.
        if op == ChildOp::Clone
            && let Ok(Some(parent)) = own_process_parent
        {
            child_task.ppid = Some(parent);
        }
        child_task.ptracer_waits.bind_running(&child);

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
        let child_restore_context = child_context.or(context);

        let id = child.pid();
        // The notifier registers every newborn the moment its parent reports
        // `Event::NewChild`, so a raw `wait` for the child's initial stop
        // would block forever: the notifier worker consumes that stop.
        // `run_ordinary_owned` takes the initial stop from the notifier
        // instead, which is the same state by a registered route.

        // A panic anywhere in this body would otherwise be caught by tokio's
        // task harness and silently wedge the whole run; see
        // `guest_task_panic_is_fatal`. The body is built as its own future so
        // the catch sits at the task boundary and covers all of it.
        let panic_tid = id;
        let report_failure = self.fatal_session();
        let ordinary_group = match report_failure.subscribe_group(&child.terminal_cleanup()) {
            Ok(subscription) => Some(subscription),
            Err(error) => {
                report_failure.fail_at(
                    BackendFailure {
                        pid: self.pid(),
                        tid: id,
                        phase: "ptrace orphan group subscription",
                    },
                    error.into(),
                );
                None
            }
        };
        // Heap-place the child operation before the catch/completion wrappers
        // capture it. Tokio's automatic boxing occurs after its by-value spawn
        // entry, which can already exhaust the container's small host stack.
        let body = Box::pin(async move {
            child_task
                .run_ordinary_newborn(child, child_restore_context)
                .await
        });
        self.global_state.fatal_session.handed(id);
        let task_body = async move {
            match AssertUnwindSafe(body).catch_unwind().await {
                Ok(Ok(exit_status)) => exit_status,
                Ok(Err(error)) => {
                    report_failure.fail(error);
                    None
                }
                Err(payload) => guest_task_panic_is_fatal(panic_tid, payload),
            }
        };
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
        let task = ChildCompletion::Owned(receiver);

        if is_thread {
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
        // The child is owned either way; a clone whose thread group could not
        // be read was kept on the thread path, and the session hears why.
        own_process_parent.map_err(|error| {
            TraceError::from(Errno::new(error.raw_os_error().unwrap_or(libc::EIO)))
        })?;
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
            // does the same.
            #[cfg(test)]
            let hold = LEADER_STEP_EXIT_HOLD
                .with(|slot| slot.borrow().clone())
                .filter(|hold| {
                    self.tid() == self.pid() && hold.armed.swap(false, Ordering::SeqCst)
                });
            // The step's trap must not reset the parent's blocked or ignored
            // SIGTRAP (`sigtrap_state`). The child already took its mask and
            // action table when the clone event was raised, so unblocking the
            // parent now leaves the child's as the parent had them. An ignored
            // SIGTRAP is put back at the step's report, or else at the next
            // stop that can take the repair (`sigtrap_repair`). The repair is
            // noted only once the step has stopped, after its trap, as at the
            // syscall skip (`skip_seccomp_syscall`). Not under a tracer filter
            // (`thread_may_be_seccomp_filtered`).
            let filtered = !self.keeps_sigtrap_state();
            let (shielded, ignored) = if filtered {
                (false, false)
            } else {
                // The step can run into a guest `int3` or `int1`, whose own trap
                // resets SIGTRAP natively, so what it leaves is read afresh.
                let ignored = self.sigtrap_ignored(&parent)?;
                self.forget_sigtrap_ignored();
                (
                    self.shield_sigtrap_for_step(&parent, "clone parent")?,
                    ignored,
                )
            };
            let running = self.step_stopped(parent, None)?;
            #[cfg(test)]
            if let Some(hold) = hold {
                hold_leader_step_until_exit(hold, &running).await;
            }
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            if ignored {
                self.note_sigtrap_repair(SigtrapRepair::Ignored);
            }
            if shielded {
                reblock_sigtrap_after_step(&wait)?;
            }
            match wait {
                Wait::Stopped(parent, Event::Signal(Signal::SIGTRAP))
                    if !filtered
                        && self.sigtrap_repair().is_some()
                        && parent.getsiginfo()?.si_code == libc::TRAP_TRACE =>
                {
                    let parent = self.apply_sigtrap_repair(parent).await?;
                    Ok(Wait::Stopped(parent, Event::Signal(Signal::SIGTRAP)))
                }
                wait => Ok(wait),
            }
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

    async fn run_loop(&mut self, task: Stopped) -> Result<ExitStatus, reverie::Error> {
        self.ptracer_waits.bind_stopped(&task);
        match self.run_loop_internal(task).await {
            Ok(exit_status) => Ok(exit_status),
            Err(Error::RunFailed) => future::pending().await,
            Err(err) => {
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
                if !matches!(err, reverie::Error::Errno(_)) {
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
    /// `handle_exec_event`, `handle_new_task` and `handle_vfork_done_event`,
    /// and `ordinary_callback_errno` returns a Tool callback's errno as
    /// `TraceError::Errno`, so a callback that returns ECHILD qualifies too.
    /// That is harmless today: `ordinary_callback_errno` either never returns
    /// or publishes the session failure before it returns the errno, so
    /// `drive_ordinary` takes its cancellation branch while the run loop stays
    /// pending.
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
            OrdinaryStart::Exec(child) => {
                let result = match self.handle_exec_event(child).await {
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
            OrdinaryStart::Stopped(child) | OrdinaryStart::Exec(child) => {
                self.ptracer_waits.bind_stopped(child)
            }
            OrdinaryStart::Newborn(child, _) => self.ptracer_waits.bind_running(child),
        }
        let terminal = match &start {
            OrdinaryStart::Stopped(child) | OrdinaryStart::Exec(child) => {
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
                OrdinaryStart::Stopped(child) | OrdinaryStart::Exec(child) => {
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
                    if self.is_main_thread() {
                        // The process leader's final wait status has been
                        // consumed, which the kernel allows only once every
                        // thread of the process is gone. For a traced child
                        // that consumption is when the kernel publishes the
                        // exit to the guest parent, so report it now
                        // (BackendCapabilities::reports_child_exit_publication),
                        // before the Tool's exit hooks run.
                        self.global_state
                            .gs_ref
                            .on_backend_process_exited(self.pid().as_raw());
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
                    // The exec'ing thread was stopped for its whole callback,
                    // so an approval it holds means its own signal callback
                    // approved a delivery and then executed a program, which
                    // never returns to it. As in `handle_exec_event`, which
                    // that thread's own loop never reaches, the run ends: the
                    // named failure is published, and the fatal session stops
                    // the guest. The handover below still runs, so the old
                    // task is retired as usual.
                    if let Some(approval) = former_task.signal_approval.take() {
                        let _ =
                            former_task.fail_broken_approval(approval, "then executed a program");
                    }
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
                    self.pending_signal_reported = false;
                    self.in_signal_callback = false;
                    // A callback that approved a delivery and was cancelled
                    // here, with its thread, broke nothing: Linux loses that
                    // signal with the thread.
                    self.signal_approval = None;
                    self.signal_delivery_mismatched = false;
                    self.signal_callback_replaced_restart_block = false;
                    self.signal_callback_guest_restart_block = false;
                    self.in_held_signal_callback = false;
                    self.unreported_stop_signal = None;
                    self.reported_requeued_signals.clear();
                    self.stale_private_step_trap = false;
                    self.pending_syscall = None;
                    self.cancel_handler.store(false, Ordering::Release);
                    stop.frozen.store(false, Ordering::Release);
                    self.arm_liteinst_root_stop(&stopped, &Event::Exec(former));
                    exit_event = self.ptracer_waits.exit_stopped(&stopped);
                    start = OrdinaryStart::Exec(stopped);
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
        // A change of SIGTRAP's action this thread marked ends with it.
        if self.global_state.keeps_sigtrap_state {
            self.end_sigtrap_changing();
        }
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
        // A change of SIGTRAP's action this thread marked ends with it.
        if self.global_state.keeps_sigtrap_state {
            self.end_sigtrap_changing();
        }
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
        // A change of SIGTRAP's action this thread marked ends with it.
        if self.global_state.keeps_sigtrap_state {
            self.end_sigtrap_changing();
        }
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
            // The group is gone; its table owes nothing once no group uses it.
            self.global_state
                .sigtrap_tables
                .lock()
                .unwrap()
                .leave(pid, self.sigtrap_table);
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
    pub async fn run(self, child: Stopped) -> Result<ExitStatus, reverie::Error> {
        self.run_ordinary(child).await
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
        // So here we are, at ptrace seccomp stop, if we simply resume, the kernel
        // would do the syscall, without our patch. we change to syscall number to
        // -1, so that kernel would simply skip the syscall, so that we can jump to
        // our patched syscall on the first run. Please note after calling this
        // function, the task state will no longer be in ptrace event seccomp.
        #[cfg(target_arch = "x86_64")]
        let regs = task.getregs()?;

        #[cfg(target_arch = "x86_64")]
        {
            let mut new_regs = regs;
            *new_regs.orig_syscall_mut() = -1i64 as u64;
            task.setregs(&new_regs)?;
        }

        #[cfg(target_arch = "aarch64")]
        task.set_syscall(-1)?;

        // The step's trap must not reset a blocked or ignored SIGTRAP
        // (`sigtrap_state`): SIGTRAP is unblocked for the step, and an ignored
        // one is put back after it. The repair is noted only once the step
        // has stopped, after its trap: noted before, another thread's
        // seccomp-stop repair could take it, find SIG_IGN not yet reset, and
        // drop it. Not under a tracer filter, which may refuse the requests
        // (`thread_may_be_seccomp_filtered`).
        let (shielded, ignored) = if !self.keeps_sigtrap_state() {
            (false, false)
        } else {
            let ignored = self.sigtrap_ignored(&task)?;
            (
                self.shield_sigtrap_for_step(&task, "syscall skip")?,
                ignored,
            )
        };

        let mut running = self.step_stopped(task, None)?;

        // After the step, wait for the next transition. Note that this can return
        // an exited state if there is a group exit while some thread is blocked on
        // a syscall.
        loop {
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            if ignored {
                self.note_sigtrap_repair(SigtrapRepair::Ignored);
            }
            match wait {
                Wait::Stopped(task, Event::Signal(Signal::SIGTRAP)) => {
                    #[cfg(target_arch = "x86_64")]
                    task.setregs(&regs)?;
                    if shielded {
                        let mask = sigmask(&task)?;
                        set_sigmask(&task, mask | SIGTRAP_BIT)?;
                    }
                    if self.sigtrap_repair().is_some() && self.keeps_sigtrap_state() {
                        break self.apply_sigtrap_repair(task).await;
                    }
                    break Ok(task);
                }
                Wait::Stopped(task, event) if let Some(sig) = event.signal() => {
                    // We can get a spurious signal here, such as SIGWINCH. Skip
                    // past them until the tracee eventually arrives at SIGTRAP.
                    let sig = self.filter_direct_unreported(&task, sig).await;
                    running = self.step_stopped_any(task, sig)?;
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

    /// `untraced_syscall`; `original` marks a frame-mode injection
    /// (`injected_syscall_frame`) of the event's own pending syscall, which a signal must not stop from
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
        self.timer.expire_overflow_records(&task);
        tracing::trace!(
            "[scheduler/tool] (pid = {}) untraced syscall: {:?}",
            task.pid(),
            nr
        );
        // What the step's trap can reset of SIGTRAP's state, read before the
        // registers change (`sigtrap_state`). The reads and the repair make
        // requests main does not, which a tracer filter may refuse
        // (`thread_may_be_seccomp_filtered`); under one, SIGTRAP is left as on
        // main.
        // An exec never returns to this injection's repair; the exec stop and
        // pre-init keep SIGTRAP across it (`handle_exec_event`).
        let (task, sigtrap) =
            if !self.keeps_sigtrap_state() || matches!(nr, Sysno::execve | Sysno::execveat) {
                (task, None)
            } else {
                let task = self.apply_sigtrap_repair(task).await?;
                let (task, before) = self.read_sigtrap_before_injection(task, nr, &args).await?;
                (task, Some(before))
            };
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

        // An injection in a held signal's callback, or one that starts with
        // a signal already held, keeps every realtime signal queued, and a
        // mask-swapping injection the signals its temporary mask blocks
        // (`step_shielded_injection`).
        let shield = if child_context.is_none()
            && (self.in_held_signal_callback || self.pending_signal.is_some())
        {
            REALTIME_SIGNAL_BITS
        } else {
            0
        };
        // A mask-swapping injection's shield takes requests and reads that
        // main does not make, which a tracer filter may refuse
        // (`thread_may_be_seccomp_filtered`).
        let mut temporary_shield = 0;
        if child_context.is_none()
            && swaps_signal_mask(nr)
            && may_name_temporary_signal_mask(nr, &args)
            && !thread_may_be_seccomp_filtered()
            && let Some(temporary) = temporary_signal_mask(&task, nr, &args)
        {
            temporary_shield = temporary & !NEVER_SHIELDED;
        }
        // Only a shielded injection reads the thread's mask.
        let shield = if shield | temporary_shield != 0 {
            let mask = task.getsigmask()?;
            // While an earlier mask-swapping syscall's restore is pending
            // (`TIF_RESTORE_SIGMASK`), `PTRACE_GETSIGMASK` reports the saved
            // mask, not the one the kernel blocks under, and writing a mask
            // discards the restore (`swaps_signal_mask`). The temporary
            // shield is then not taken, as before it existed.
            if temporary_shield != 0 && blocked_signal_mask(task.pid()).ok() != Some(mask) {
                temporary_shield = 0;
            }
            (shield | temporary_shield) & !mask
        } else {
            0
        };
        if shield != 0 {
            // The shielded injection runs the thread to the syscall's entry
            // first, so the state read before is not reused for its step.
            self.injection_proc_state = None;
            let requeue = self.in_held_signal_callback;
            let (wait, seccomp_trapped) = self
                .step_shielded_injection(task, nr, shield, requeue)
                .await?;
            let result = self
                .status_to_result(wait, Some(oldregs), child_context)
                .await?;
            if let Some(sigtrap) = sigtrap {
                self.repair_sigtrap_after_injection(sigtrap, &result)
                    .await?;
            }
            return Ok(if seccomp_trapped {
                Err(Errno::ENOSYS)
            } else {
                result
            });
        }

        // Step to run the syscall instruction.
        let (mut wait, mut seccomp_trapped) = self
            .step_private_syscall_discarding_late_timer(task, nr)
            .await?;
        // A SIGTRAP the guest or another process sent can stop the step
        // before the `syscall` ran; a stale step SIGTRAP was discarded there
        // already (`step_private_syscall`). `status_to_result` would report
        // that the syscall did not run (`-ERESTARTSYS`). The trap is
        // discarded instead, as the main loop discards an unclaimed SIGTRAP
        // (`handle_sigtrap`), and the step runs the syscall. A held signal is
        // not reported while the trap could be claimed
        // (`sigtrap_may_be_claimed`). A frame-mode injection holds the trap
        // for the resume instead (`status_to_result`). Under a tracer filter
        // the trap is not discarded, as on main: the retried step can stop
        // again at requests that filter may refuse or kill the tracer at
        // (`thread_may_be_seccomp_filtered`).
        while child_context.is_none()
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
        if let Some(sigtrap) = sigtrap {
            self.repair_sigtrap_after_injection(sigtrap, &result)
                .await?;
        }
        // A guest seccomp filter's `SECCOMP_RET_TRAP` skipped the syscall and
        // left its number in RAX. Report that it did not run; the guest's
        // SIGSYS handler still runs, and seccomp(2) leaves the register it
        // finds architecture-dependent.
        let result = if seccomp_trapped {
            Err(Errno::ENOSYS)
        } else {
            result
        };
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
            // state.
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
    /// for `status_to_result` to report as an interrupted syscall.
    async fn step_private_syscall_unshielded(
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
                Wait::Stopped(stopped, event) if let Some(sig) = event.signal() => {
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
                        return Ok((
                            Wait::Stopped(stopped, Event::from_signal(sig)),
                            seccomp_trapped,
                        ));
                    }
                    // The `syscall` ran, but its step SIGTRAP was discarded
                    // before the stop reported it: installing SIG_IGN for
                    // SIGTRAP, as another thread of the table may do meanwhile
                    // (the guest's own `rt_sigaction`, or a SIGTRAP repair),
                    // discards every thread's pending SIGTRAP. The thread then
                    // faulted on the `ud2` that follows the private `syscall`.
                    // That is the step's end: RAX holds the syscall's result,
                    // and the SIGILL is not the guest's.
                    if sig == Signal::SIGILL && is_private_guard_fault(&stopped, after_syscall)? {
                        tracing::debug!(
                            "[scheduler/tool] (pid = {}) injected {} ran, and its step SIGTRAP was discarded",
                            stopped.pid(),
                            nr
                        );
                        lift_requeued(&stopped, requeued)?;
                        return Ok((
                            Wait::Stopped(stopped, Event::Signal(Signal::SIGTRAP)),
                            seccomp_trapped,
                        ));
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
                    running = self.step_stopped_any(stopped, Some(sig))?;
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
                    running = self.step_stopped_any(stopped, Some(sig))?;
                } else {
                    tracing::debug!(
                        "[scheduler/tool] (pid = {}) holding {} delivered after injected {} completed; later signals stay queued",
                        stopped.pid(),
                        sig,
                        nr
                    );
                    lift_requeued(&stopped, requeued)?;
                    self.stale_private_step_trap = true;
                    return Ok((
                        Wait::Stopped(stopped, Event::from_signal(sig)),
                        seccomp_trapped,
                    ));
                }
            } else {
                lift_requeued(&stopped, requeued)?;
                return Ok((
                    Wait::Stopped(stopped, Event::from_signal(sig)),
                    seccomp_trapped,
                ));
            }
        }
    }

    /// `unblock_sigtrap_for_step_with` before the Reverie single-step at `site`.
    /// Returns whether SIGTRAP was unblocked, to be blocked again at the
    /// step's stop; ends the run with the named failure
    /// `PendingSigtrapAtStep` when a blocked SIGTRAP is pending.
    fn shield_sigtrap_for_step(
        &self,
        task: &Stopped,
        site: &'static str,
    ) -> Result<bool, TraceError> {
        self.shield_sigtrap_for_step_known(task, site, None)
    }

    /// `shield_sigtrap_for_step`, reusing `known`, the mask and procfs state
    /// read for this stop, while the mask is still the one read then: a
    /// shielded injection's own masking changes it first.
    fn shield_sigtrap_for_step_known(
        &self,
        task: &Stopped,
        site: &'static str,
        known: Option<(u64, ProcSignalState)>,
    ) -> Result<bool, TraceError> {
        if !self.keeps_sigtrap_state() {
            return Ok(false);
        }
        let mask = sigmask(task)?;
        let known = known.and_then(|(read_mask, state)| (read_mask == mask).then_some(state));
        match unblock_sigtrap_for_step_known(task, mask, known)? {
            StepShield::None => Ok(false),
            StepShield::Unblocked => Ok(true),
            StepShield::PendingTrap => Err(self.fail_pending_sigtrap(task.pid(), site)),
        }
    }

    /// Records `PendingSigtrapAtStep` with the session, which ends the run,
    /// and returns the error that unwinds the handler.
    fn fail_pending_sigtrap(&self, tid: Pid, site: &'static str) -> TraceError {
        self.fatal_session().fail_at(
            BackendFailure {
                pid: self.pid(),
                tid: self.tid(),
                phase: "blocked SIGTRAP pending at a Reverie single-step",
            },
            anyhow::Error::new(crate::PendingSigtrapAtStep {
                tid: tid.as_raw(),
                site,
            })
            .into(),
        );
        Errno::ECANCELED.into()
    }

    /// `step_private_syscall_unshielded`, with SIGTRAP unblocked for the
    /// step of an `execve` or `execveat`, so that the step's trap cannot
    /// reset a blocked SIGTRAP's action or unblock it
    /// (<https://github.com/rrnewton/hermit/issues/4409>). SIGTRAP is blocked
    /// again at the stop the step ends at, before anything reads that stop.
    ///
    /// Every other injected syscall runs under the guest's own mask, so that
    /// what the call reads of it is what it reads natively: a read of the
    /// thread's procfs `status` reports `SigBlk` with SIGTRAP blocked. Its
    /// trap may then reset SIGTRAP, and the injection puts back what it
    /// reset (`repair_sigtrap_after_injection`). An exec never returns to
    /// that repair; the exec stop and pre-init keep SIGTRAP across it
    /// (`handle_exec_event`).
    async fn step_private_syscall(
        &mut self,
        task: Stopped,
        nr: Sysno,
    ) -> Result<(Wait, bool), TraceError> {
        // The shield makes requests main does not, which a tracer filter may
        // refuse (`thread_may_be_seccomp_filtered`).
        let known = self.injection_proc_state.take();
        // Decided at each step, retries included, from the state then: the
        // shield as before injected calls ran under the guest's own mask,
        // unless `may_unshield_step` finds that nothing another thread does
        // can meet the trap's reset.
        let keeps_mask = step_kind(nr, swaps_signal_mask(nr)) == StepKind::KeepsMask;
        let unshielded_mask = if keeps_mask
            && !matches!(nr, Sysno::execve | Sysno::execveat)
            && self.keeps_sigtrap_state()
        {
            self.may_unshield_step(&task, known)?
        } else {
            None
        };
        let shielded = keeps_mask
            && unshielded_mask.is_none()
            && self.keeps_sigtrap_state()
            && self.shield_sigtrap_for_step_known(&task, "private-page injection", known)?;
        self.step_choice = Some(StepChoice {
            unshielded_mask,
            shielded,
        });
        let (wait, seccomp_trapped) = self.step_private_syscall_unshielded(task, nr).await?;
        if shielded {
            reblock_sigtrap_after_step(&wait)?;
        }
        Ok((wait, seccomp_trapped))
    }

    /// Runs `nr` with `args` on the private page without single-stepping it,
    /// so that no trap's `force_sig` can reset SIGTRAP (`sigtrap_state`), and
    /// returns the task at the syscall's exit stop, its registers restored,
    /// with the result.
    ///
    /// The thread is resumed with `PTRACE_SYSCALL` to the syscall's entry
    /// stop and again to its exit stop; neither stop sends a signal. Every
    /// signal that can be blocked is blocked until the exit stop, so none is
    /// taken from the kernel's queue before the `syscall` instruction, and the
    /// thread's mask is then restored, leaving them pending as they were. A
    /// group stop before the instruction is resumed, as the stepped
    /// injections resume one.
    ///
    /// The mask write would discard a pending temporary-mask restore
    /// (`swaps_signal_mask`), so while one is pending nothing runs, and
    /// `EBUSY` is returned with the task unchanged.
    async fn untraced_syscall_unstepped(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<(Stopped, Result<i64, Errno>), TraceError> {
        self.untraced_syscall_number_unstepped(task, nr as Reg, args)
            .await
    }

    /// `untraced_syscall_unstepped` for a syscall number, which may be one
    /// `Sysno` does not name (`mseal`).
    async fn untraced_syscall_number_unstepped(
        &mut self,
        task: Stopped,
        nr: Reg,
        args: SyscallArgs,
    ) -> Result<(Stopped, Result<i64, Errno>), TraceError> {
        let original_mask = sigmask(&task)?;
        if ProcSignalState::read(&task)?.blocked != original_mask {
            return Ok((task, Err(Errno::EBUSY)));
        }
        let oldregs = task.getregs()?;
        let mut regs = oldregs;
        *regs.syscall_mut() = nr;
        *regs.orig_syscall_mut() = nr;
        regs.set_args((
            args.arg0 as Reg,
            args.arg1 as Reg,
            args.arg2 as Reg,
            args.arg3 as Reg,
            args.arg4 as Reg,
            args.arg5 as Reg,
        ));
        *regs.ip_mut() = cp::PRIVATE_PAGE_OFFSET as Reg;
        task.setregs(&regs)?;
        set_sigmask(&task, original_mask | BLOCKABLE_SIGNAL_BITS)?;
        let mut entered = false;
        let mut running = self.syscall_stopped_any(task, None)?;
        loop {
            let wait = running.next_state_with_owner(&self.ptracer_waits).await?;
            self.arm_liteinst_wait(&wait);
            // Without PTRACE_O_TRACESYSGOOD, which Reverie's own launch sets, a
            // syscall stop is reported as a SIGTRAP whose siginfo's code is
            // SIGTRAP itself (`ptrace_notify`); no SIGTRAP sent or raised
            // carries that code.
            let wait = match wait {
                Wait::Stopped(stopped, Event::Signal(Signal::SIGTRAP))
                    if stopped.getsiginfo()?.si_code == libc::SIGTRAP =>
                {
                    Wait::Stopped(stopped, Event::Syscall)
                }
                wait => wait,
            };
            match wait {
                Wait::Stopped(stopped, Event::Syscall) if !entered => {
                    entered = true;
                    running = self.syscall_stopped_any(stopped, None)?;
                }
                Wait::Stopped(stopped, Event::Syscall) => {
                    let ret = stopped.getregs()?.ret();
                    stopped.setregs(&oldregs)?;
                    set_sigmask(&stopped, original_mask)?;
                    return Ok((stopped, Errno::from_ret(ret as usize).map(|x| x as i64)));
                }
                Wait::Stopped(stopped, Event::Signal(sig))
                    if !entered && is_group_stop(&stopped, sig)? =>
                {
                    running = self.syscall_stopped_any(stopped, None)?;
                }
                // An outside SIGKILL: the paths that handle a killed tracee
                // take ESRCH, as from a ptrace request.
                Wait::Stopped(_, Event::Exit) => return Err(Errno::ESRCH.into()),
                Wait::Stopped(stopped, event) => {
                    tracing::error!(
                        "[scheduler/tool] (pid = {}) unstepped syscall {} stopped at {:?}",
                        stopped.pid(),
                        nr,
                        event
                    );
                    stopped.setregs(&oldregs)?;
                    set_sigmask(&stopped, original_mask)?;
                    return Err(Errno::EPROTO.into());
                }
                Wait::Exited(..) => return Err(Errno::ESRCH.into()),
            }
        }
    }

    /// Whether Reverie keeps the guest's SIGTRAP state across its own steps:
    /// the Tool enforces serialized execution (`GlobalState::keeps_sigtrap_state`)
    /// and the tracer thread has no seccomp filter, which may refuse the
    /// requests main does not make (`thread_may_be_seccomp_filtered`). The
    /// filter state is read once per traced thread and OS thread
    /// (`tracer_unfiltered`), not at each decision: each read is a procfs
    /// read, a syscall the Tool emulates made five of them, and a guest making
    /// 160,000 such syscalls ran 2.2 times as long. A filter is never removed,
    /// so a filtered answer stays right; an unfiltered one rests on the
    /// contract's promise that the tracer installs no filter on its own
    /// threads once the trace has started (`Tool::enforces_serialized_execution`).
    fn keeps_sigtrap_state(&self) -> bool {
        if !self.global_state.keeps_sigtrap_state {
            return false;
        }
        let thread = std::thread::current().id();
        let mut cached = self.tracer_unfiltered.lock().unwrap();
        if let Some((read_on, unfiltered)) = *cached
            && read_on == thread
        {
            return unfiltered;
        }
        // An unreadable status counts as filtered, as before, and is read
        // again at the next decision.
        match read_status("/proc/thread-self/status") {
            Ok(status) => {
                let unfiltered = status_unfiltered(&status);
                *cached = Some((thread, unfiltered));
                unfiltered
            }
            Err(_) => false,
        }
    }

    /// Waits for the session's SIGTRAP repair lock (`sigtrap_scratch_lock`).
    async fn lock_sigtrap_repairs(&self) -> OwnedMutexGuard<()> {
        self.global_state
            .sigtrap_scratch_lock
            .clone()
            .lock_owned()
            .await
    }

    /// Reverie's SIGTRAP repair page (`cp::SCRATCH_BASE`) for the address
    /// space of thread `tid`: `Ok(Some(_))` if it is sealed there, `Ok(None)` if
    /// pre-init has not set it up yet (a repair stays owed until it has),
    /// `Err(())` if the address space has none (`seal_sigtrap_scratch`), or the
    /// thread has seccomp filters of the guest's own, which a repair's
    /// injected `rt_sigaction` could meet (`guest_has_own_seccomp_filter`): then
    /// the address space is marked as having none. The count is read once,
    /// before the repair's injections, and the repair lock does not hold off
    /// a guest's filter install: a filter that another thread installs with
    /// `SECCOMP_FILTER_FLAG_TSYNC` while a repair runs reaches this thread
    /// anyway, and can kill or trap the repair's `rt_sigaction`. Only a Tool
    /// that breaks its serialized-execution contract
    /// (`Tool::enforces_serialized_execution`), under which no guest thread
    /// runs during a repair and no guest filter is installed, meets this;
    /// without the contract no repair runs.
    fn sigtrap_scratch(&self, tid: Pid) -> Result<Option<usize>, ()> {
        match self.sigtrap_scratch_state.load(Ordering::SeqCst) {
            SCRATCH_SEALED if self.guest_has_own_seccomp_filter(tid) => {
                self.sigtrap_scratch_state
                    .store(SCRATCH_UNAVAILABLE, Ordering::SeqCst);
                Err(())
            }
            SCRATCH_SEALED => Ok(Some(cp::SCRATCH_BASE)),
            SCRATCH_PENDING => Ok(None),
            _ => Err(()),
        }
    }

    /// Whether thread `tid` has seccomp filters beyond those a guest gets from
    /// outside (`GlobalState::seccomp_filter_baseline`), or its count cannot be
    /// read: an injection of Reverie's own could meet a filter of the guest's.
    fn guest_has_own_seccomp_filter(&self, tid: Pid) -> bool {
        match (
            guest_seccomp_filters(tid),
            self.global_state.seccomp_filter_baseline,
        ) {
            (Some(filters), Some(baseline)) => filters > baseline,
            _ => true,
        }
    }

    /// Maps Reverie's sealed SIGTRAP repair page after the trampoline
    /// (`cp::SCRATCH_BASE`): an unstepped `mmap(..., MAP_FIXED_NOREPLACE)`,
    /// read-write, then `mseal`. Pre-init runs at an exec stop, where the new
    /// address space has a single thread, stopped, so no other task can map
    /// there before the page is sealed; once sealed, no task can unmap,
    /// replace or reprotect it (`EPERM`), so a repair's writes there never
    /// reach a guest page. A fork's copy keeps the seal. NOREPLACE never maps
    /// over what the new image already has there, such as an ELF segment:
    /// then, as without `mseal` (before Linux 6.10), the address space has no
    /// repair page, no repair is written in it, and the guest's mappings are
    /// left as they were (logged once). A page a kernel without NOREPLACE
    /// placed elsewhere, or one `mseal` refused, is unmapped again, which no
    /// other task can race here.
    async fn seal_sigtrap_scratch(
        &mut self,
        task: Stopped,
        place: PreinitPlace,
    ) -> Result<Stopped, TraceError> {
        // The address space has no repair page unless it is sealed below.
        self.sigtrap_scratch_state = Arc::new(AtomicU8::new(SCRATCH_UNAVAILABLE));
        if !self.keeps_sigtrap_state() {
            return Ok(task);
        }
        // A guest's own seccomp filter can kill or trap the injected `mseal`
        // (a filter written before `mseal` existed does not list it), so no
        // repair page is set up in an image whose thread has more filters than
        // the guest gets from the tracer and its launch
        // (`GlobalState::seccomp_filter_baseline`). At the root's first stop,
        // before its exec, Reverie's own launch filter is not installed yet
        // (it is loaded after the last `pre_exec` callback, and a caller's
        // callbacks run before Reverie's stops), so then only the tracer's
        // filters count: a filter there is the caller's.
        let filters = guest_seccomp_filters(task.pid());
        let baseline = match place {
            PreinitPlace::BeforeExec => self
                .global_state
                .seccomp_filter_baseline
                .map(|baseline| baseline - 1),
            PreinitPlace::AtExec => self.global_state.seccomp_filter_baseline,
        };
        let warn_once = |pid: Pid, why: String| {
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "[scheduler/tool] (pid = {}) no SIGTRAP repair page: {}; SIGTRAP repairs are off in this address space",
                    pid,
                    why
                );
            }
        };
        match (filters, baseline) {
            (Some(filters), Some(baseline)) if filters <= baseline => {}
            (Some(filters), Some(baseline)) => {
                warn_once(
                    task.pid(),
                    format!(
                        "the guest has seccomp filters of its own ({filters}, {baseline} before it ran)"
                    ),
                );
                return Ok(task);
            }
            _ => {
                warn_once(
                    task.pid(),
                    String::from("a seccomp filter count cannot be read"),
                );
                return Ok(task);
            }
        }
        let args = SyscallArgs::new(
            cp::SCRATCH_BASE,
            cp::SCRATCH_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as usize,
            usize::MAX,
            0,
        );
        let (task, result) = self
            .untraced_syscall_unstepped(task, Sysno::mmap, args)
            .await?;
        let mapped = match result {
            Ok(address) => address as usize,
            Err(errno) => {
                warn_once(
                    task.pid(),
                    format!("mmap at {:#x}: {}", cp::SCRATCH_BASE, errno),
                );
                return Ok(task);
            }
        };
        let (task, sealed) = if mapped == cp::SCRATCH_BASE {
            let args = SyscallArgs::new(cp::SCRATCH_BASE, cp::SCRATCH_SIZE, 0, 0, 0, 0);
            let (task, result) = self
                .untraced_syscall_number_unstepped(task, SYS_MSEAL, args)
                .await?;
            if let Err(errno) = result {
                warn_once(task.pid(), format!("mseal: {}", errno));
            }
            (task, result.is_ok())
        } else {
            warn_once(
                task.pid(),
                format!(
                    "the kernel placed it at {:#x} (no MAP_FIXED_NOREPLACE)",
                    mapped
                ),
            );
            (task, false)
        };
        if sealed {
            self.sigtrap_scratch_state
                .store(SCRATCH_SEALED, Ordering::SeqCst);
            return Ok(task);
        }
        let args = SyscallArgs::new(mapped, cp::SCRATCH_SIZE, 0, 0, 0, 0);
        let (task, result) = self
            .untraced_syscall_unstepped(task, Sysno::munmap, args)
            .await?;
        result.map_err(TraceError::from)?;
        Ok(task)
    }

    /// SIGTRAP's whole action for this thread, read with an unstepped
    /// `rt_sigaction` into Reverie's repair page (`sigtrap_scratch`). `None`
    /// if it cannot be read now (`untraced_syscall_unstepped` refused with
    /// `EBUSY`). Must not be called at a seccomp stop, where a resume runs the
    /// stop's own syscall.
    async fn query_sigtrap_action(
        &mut self,
        task: Stopped,
    ) -> Result<(Stopped, Option<KernelSigaction>), TraceError> {
        let _repairs = self.lock_sigtrap_repairs().await;
        let Ok(Some(scratch)) = self.sigtrap_scratch(task.pid()) else {
            return Ok((task, None));
        };
        self.query_sigtrap_action_at(task, scratch).await
    }

    /// `query_sigtrap_action`, into the page at `scratch`.
    async fn query_sigtrap_action_at(
        &mut self,
        task: Stopped,
        scratch: usize,
    ) -> Result<(Stopped, Option<KernelSigaction>), TraceError> {
        #[cfg(test)]
        UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.set(count.get() + 1));
        let args = SyscallArgs::new(
            libc::SIGTRAP as usize,
            0,
            scratch,
            std::mem::size_of::<u64>(),
            0,
            0,
        );
        let (task, result) = self
            .untraced_syscall_unstepped(task, Sysno::rt_sigaction, args)
            .await?;
        let read = match result {
            Ok(_) => Addr::<KernelSigaction>::from_raw(scratch)
                .ok_or(Errno::EFAULT)
                .and_then(|address| task.read_value(address)),
            Err(errno) => Err(errno),
        };
        match read {
            Ok(action) => Ok((task, Some(action))),
            Err(Errno::EBUSY) => Ok((task, None)),
            // Any other failure of Reverie's own call (EFAULT: no page; a
            // refusal: a filter of the guest's) drops the repair, and none is
            // tried again in this address space, rather than fail the trace.
            Err(errno) => {
                self.lose_sigtrap_scratch(&task, errno);
                Ok((task, None))
            }
        }
    }

    /// Marks this address space as having no SIGTRAP repair page, after a
    /// repair's own call failed with `errno` (`EFAULT`: no page at
    /// `cp::SCRATCH_BASE`; another errno: a refusal, such as a filter of the
    /// guest's), so that the repair is dropped rather than the trace failed,
    /// and no later repair tries. Logged once.
    fn lose_sigtrap_scratch(&self, task: &Stopped, errno: Errno) {
        self.sigtrap_scratch_state
            .store(SCRATCH_UNAVAILABLE, Ordering::SeqCst);
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "[scheduler/tool] (pid = {}) a SIGTRAP repair failed ({}); SIGTRAP repairs are off in this address space",
                task.pid(),
                errno
            );
        }
    }

    /// Whether a second thread has used this thread's signal-action table
    /// (`SigtrapTables::shared`).
    fn sigtrap_table_shared(&self) -> bool {
        self.global_state
            .sigtrap_tables
            .lock()
            .unwrap()
            .shared
            .contains(&self.sigtrap_table)
    }

    /// The guest's mask, if this private-page step of a call that keeps the
    /// mask may run without the shield while that mask blocks SIGTRAP: the
    /// step's trap then clears only the mask bit, and resets an ignored
    /// action, both of which the repair puts back. Every condition is read
    /// at the step:
    /// - SIGTRAP is not caught, and the call installs no handler: a caught
    ///   handler keeps the shield, so that no trap resets it;
    /// - no temporary mask's restore is pending, and no SIGTRAP is pending,
    ///   read as the shield reads them;
    /// - no other thread uses the signal-action table: none has been made in
    ///   it (`SigtrapTables::shared`, marked at the clone event, or at a
    ///   `CLONE_SIGHAND` clone the Tool runs), the Tool sees every clone that
    ///   could make one (`GlobalState::sees_every_sighand_clone`), and procfs
    ///   lists no other live thread in the group (`group_has_other_live_threads`).
    ///   Another thread could install a handler while this call blocks, which
    ///   the trap would reset.
    ///
    /// Otherwise `None`, and the step keeps the shield exactly as before.
    fn may_unshield_step(
        &self,
        task: &Stopped,
        known: Option<(u64, ProcSignalState)>,
    ) -> Result<Option<u64>, TraceError> {
        if self.injection_installs_caught
            || !self.global_state.sees_every_sighand_clone
            || self.sigtrap_table_shared()
        {
            return Ok(None);
        }
        let mask = sigmask(task)?;
        if mask & SIGTRAP_BIT == 0 {
            return Ok(None);
        }
        let state = match known {
            Some((read_mask, state)) if read_mask == mask => state,
            _ if self.restore_maybe_pending => ProcSignalState::read(task)?,
            _ => {
                let (sigtrap_ignored, sigtrap_caught) = self.sigtrap_disposition_known(task)?;
                ProcSignalState {
                    blocked: mask,
                    pending: if sigtrap_queued(task)? {
                        SIGTRAP_BIT
                    } else {
                        0
                    },
                    sigtrap_ignored,
                    sigtrap_caught,
                }
            }
        };
        if state.sigtrap_caught || state.blocked != mask || state.pending & SIGTRAP_BIT != 0 {
            return Ok(None);
        }
        if group_has_other_live_threads(self.pid(), self.tid()) {
            return Ok(None);
        }
        Ok(Some(mask))
    }

    /// Whether no other thread uses this thread's signal-action table, by the
    /// sharing tests of `may_unshield_step`.
    fn table_unshared_now(&self) -> bool {
        self.global_state.sees_every_sighand_clone
            && !self.sigtrap_table_shared()
            && !group_has_other_live_threads(self.pid(), self.tid())
    }

    /// Whether syscall `nr` with `args` is a `clone` or `clone3` that may
    /// share the caller's signal-action table (`CLONE_SIGHAND`, which
    /// `CLONE_THREAD` requires). A `clone3` whose flags cannot be read is
    /// taken as one.
    fn clone_may_share_signal_actions(&self, nr: Sysno, args: &SyscallArgs) -> bool {
        let sighand = libc::CLONE_SIGHAND as u64;
        match nr {
            Sysno::clone => args.arg0 as u64 & sighand != 0,
            Sysno::clone3 => Addr::<u64>::from_raw(args.arg0)
                .and_then(|flags| self.assume_stopped().read_value(flags).ok())
                .is_none_or(|flags| flags & sighand != 0),
            _ => false,
        }
    }

    /// Whether SIGTRAP is ignored in this thread's signal-action table. procfs
    /// is read only when the table's answer is not known, or while a guest
    /// `rt_sigaction` of SIGTRAP may be changing it, which is read again each
    /// time. A Reverie trap's reset leaves the remembered answer as it was:
    /// the reset is repaired back to it (`sigtrap_repair`), and a repair
    /// checks what it finds before it writes.
    fn sigtrap_ignored(&self, task: &Stopped) -> Result<bool, TraceError> {
        Ok(self.sigtrap_disposition_known(task)?.0)
    }

    /// Whether SIGTRAP is ignored and whether it is caught in this thread's
    /// signal-action table (procfs `SigIgn` and `SigCgt`), remembered as
    /// `sigtrap_ignored` describes.
    fn sigtrap_disposition_known(&self, task: &Stopped) -> Result<(bool, bool), TraceError> {
        // Not while a repair of Reverie's own is owed either: until it is
        // written, procfs reads the reset (`SIG_DFL`), not the guest's action.
        let cacheable = self.global_state.caches_sigtrap_disposition && {
            let tables = self.global_state.sigtrap_tables.lock().unwrap();
            !tables
                .changing
                .get(&self.sigtrap_table)
                .is_some_and(|threads| !threads.is_empty())
                && !tables.repairs.contains_key(&self.sigtrap_table)
        };
        if cacheable
            && let Some(disposition) = self
                .global_state
                .sigtrap_tables
                .lock()
                .unwrap()
                .ignored
                .get(&self.sigtrap_table)
        {
            return Ok(*disposition);
        }
        let disposition = sigtrap_disposition(task)?;
        if cacheable {
            self.global_state
                .sigtrap_tables
                .lock()
                .unwrap()
                .ignored
                .insert(self.sigtrap_table, disposition);
        }
        Ok(disposition)
    }

    /// Forgets whether SIGTRAP is ignored in this thread's table, after an
    /// event that may have changed it.
    fn forget_sigtrap_ignored(&self) {
        self.global_state
            .sigtrap_tables
            .lock()
            .unwrap()
            .ignored
            .remove(&self.sigtrap_table);
    }

    /// At a seccomp stop of syscall `nr` with `args`: this thread's next
    /// seccomp stop ends a change it marked before (`mark_sigtrap_changing`),
    /// and a guest `rt_sigaction` of SIGTRAP marks one.
    fn note_sigtrap_action_syscall(&self, nr: Sysno, args: &SyscallArgs) {
        self.end_sigtrap_changing();
        if sets_sigtrap_action(nr, args) {
            self.mark_sigtrap_changing();
        }
    }

    /// Marks this thread's table as changing, for an `rt_sigaction` of SIGTRAP
    /// that has run or may run before this thread's next seccomp stop, and
    /// forgets the disposition.
    fn mark_sigtrap_changing(&self) {
        let mut tables = self.global_state.sigtrap_tables.lock().unwrap();
        let table = self.sigtrap_table;
        tables.changing.entry(table).or_default().insert(self.tid());
        tables.ignored.remove(&table);
    }

    /// Ends a change this thread marked, at its next seccomp stop or its exit.
    fn end_sigtrap_changing(&self) {
        let mut tables = self.global_state.sigtrap_tables.lock().unwrap();
        let table = self.sigtrap_table;
        if let Some(threads) = tables.changing.get_mut(&table)
            && threads.remove(&self.tid())
        {
            if threads.is_empty() {
                tables.changing.remove(&table);
            }
            tables.ignored.remove(&table);
        }
    }

    /// Records a SIGTRAP repair owed for a Reverie trap, for the signal-action
    /// table this thread uses (`GlobalState::sigtrap_tables`).
    /// An earlier one still owed is kept: until it is written, the action
    /// reads as the reset left it, so no later read can know more.
    fn note_sigtrap_repair(&mut self, repair: SigtrapRepair) {
        if self.keeps_sigtrap_state() {
            self.global_state
                .sigtrap_tables
                .lock()
                .unwrap()
                .repairs
                .entry(self.sigtrap_table)
                .or_insert(repair);
        }
    }

    /// The SIGTRAP repair owed for this thread's signal-action table, if any.
    fn sigtrap_repair(&self) -> Option<SigtrapRepair> {
        self.global_state
            .sigtrap_tables
            .lock()
            .unwrap()
            .repairs
            .get(&self.sigtrap_table)
            .copied()
    }

    /// Replaces the SIGTRAP repair owed for this thread's signal-action table.
    /// Clearing one, written or dropped, also forgets the disposition: a
    /// dropped repair leaves the reset `SIG_DFL` in force (`sigtrap_ignored`).
    fn set_sigtrap_repair(&mut self, repair: Option<SigtrapRepair>) {
        let mut tables = self.global_state.sigtrap_tables.lock().unwrap();
        match repair {
            Some(repair) => {
                tables.repairs.insert(self.sigtrap_table, repair);
            }
            None => {
                tables.repairs.remove(&self.sigtrap_table);
                tables.ignored.remove(&self.sigtrap_table);
            }
        }
    }

    /// Writes back the SIGTRAP repair owed (`sigtrap_repair`), if this stop
    /// can take it; must not be called at a seccomp stop
    /// (`repair_sigtrap_at_seccomp_stop`). While a temporary mask's restore is
    /// pending, the unstepped injections cannot run, and the repair stays
    /// owed. It is written only if the action is still what the reset left
    /// (`SIG_DFL`, with the flags, mask and restorer the repair expects);
    /// otherwise the reset no longer stands, and the repair is dropped.
    async fn apply_sigtrap_repair(&mut self, task: Stopped) -> Result<Stopped, TraceError> {
        // In a signal callback the Tool's resume expects the stop its last
        // injection ended at; the repair's injections end at a syscall-exit
        // stop, from which a resumed signal would be sent anew instead of
        // delivered. The repair stays owed until the next stop outside it.
        if self.in_signal_callback || self.in_held_signal_callback || !self.keeps_sigtrap_state() {
            return Ok(task);
        }
        if self.sigtrap_repair().is_none() {
            return Ok(task);
        }
        let _repairs = self.lock_sigtrap_repairs().await;
        // Read again under the lock: another thread of the table may have
        // written it while this one waited, and the guest may have set the
        // action since.
        let Some(repair) = self.sigtrap_repair() else {
            return Ok(task);
        };
        let scratch = match self.sigtrap_scratch(task.pid()) {
            Ok(Some(scratch)) => scratch,
            // Owed until pre-init has set up the page.
            Ok(None) => return Ok(task),
            // Dropped: it cannot be written without Reverie's sealed page,
            // and retrying it at every syscall would only repeat that.
            Err(()) => {
                self.set_sigtrap_repair(None);
                return Ok(task);
            }
        };
        let (task, current) = self.query_sigtrap_action_at(task, scratch).await?;
        self.repair_sigtrap_at(task, scratch, repair, current).await
    }

    /// The rest of `apply_sigtrap_repair`, with the action read into the page
    /// at `scratch`: writes `repair` back through that page if the action is
    /// still what the reset left.
    async fn repair_sigtrap_at(
        &mut self,
        task: Stopped,
        scratch: usize,
        repair: SigtrapRepair,
        current: Option<KernelSigaction>,
    ) -> Result<Stopped, TraceError> {
        let Some(current) = current else {
            return Ok(task);
        };
        self.set_sigtrap_repair(None);
        if current.handler != libc::SIG_DFL as u64 {
            return Ok(task);
        }
        let action = match repair {
            SigtrapRepair::Ignored => KernelSigaction {
                handler: libc::SIG_IGN as u64,
                ..current
            },
            SigtrapRepair::Action(action)
                if (action.flags, action.restorer, action.mask)
                    == (current.flags, current.restorer, current.mask) =>
            {
                action
            }
            SigtrapRepair::Action(_) => return Ok(task),
        };
        self.write_sigtrap_action_at(task, scratch, action).await
    }

    /// Writes back the SIGTRAP repair owed (`sigtrap_repair`) at a seccomp
    /// stop, before the Tool sees the syscall, so that neither the syscall nor
    /// the Tool reads the reset action.
    ///
    /// A seccomp stop cannot take an injection: a resume runs the stop's own
    /// syscall. The syscall has not run, so it is skipped (number -1) to its
    /// exit stop, which sends no signal; rip is put back on its `syscall`
    /// instruction with its number in rax; the repair runs there; and the
    /// thread re-executes the instruction to the same seccomp stop, with the
    /// same registers. No restore of a temporary mask can be pending at a
    /// syscall's entry. Every blockable signal stays blocked from the skip to
    /// the new seccomp stop, so none is delivered before the syscall, which a
    /// native run would have run first.
    async fn repair_sigtrap_at_seccomp_stop(
        &mut self,
        task: Stopped,
    ) -> Result<Stopped, TraceError> {
        if self.sigtrap_repair().is_none() || !self.keeps_sigtrap_state() {
            return Ok(task);
        }
        let regs = task.getregs()?;
        let mask = sigmask(&task)?;
        if ProcSignalState::read(&task)?.blocked != mask {
            return Ok(task);
        }
        set_sigmask(&task, mask | BLOCKABLE_SIGNAL_BITS)?;
        let mut skipped = regs;
        *skipped.orig_syscall_mut() = -1i64 as Reg;
        task.setregs(&skipped)?;
        let mut wait = self
            .syscall_stopped(task, None)?
            .next_state_with_owner(&self.ptracer_waits)
            .await?;
        self.arm_liteinst_wait(&wait);
        // A group stop (an outside SIGSTOP) is resumed, as the stepped
        // injections resume one.
        while let Wait::Stopped(stopped, Event::Signal(sig)) = &wait
            && is_group_stop(stopped, *sig)?
        {
            let Wait::Stopped(stopped, _) = wait else {
                unreachable!("matched a stop");
            };
            wait = self
                .syscall_stopped(stopped, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await?;
            self.arm_liteinst_wait(&wait);
        }
        let task = match wait {
            Wait::Stopped(task, Event::Syscall) => task,
            Wait::Stopped(_, Event::Exit) | Wait::Exited(..) => {
                return Err(Errno::ESRCH.into());
            }
            Wait::Stopped(task, event) => {
                tracing::error!(
                    "[scheduler/tool] (pid = {}) skipping a syscall for a SIGTRAP repair stopped at {:?}",
                    task.pid(),
                    event
                );
                return Err(Errno::EPROTO.into());
            }
        };
        let mut again = regs;
        *again.ip_mut() = regs.ip() - cp::SYSCALL_INSTR_SIZE as Reg;
        *again.syscall_mut() = regs.orig_syscall();
        *again.orig_syscall_mut() = -1i64 as Reg;
        task.setregs(&again)?;
        let task = self.apply_sigtrap_repair(task).await?;
        let mut wait = self
            .resume_stopped(task, None)?
            .next_state_with_owner(&self.ptracer_waits)
            .await?;
        self.arm_liteinst_wait(&wait);
        while let Wait::Stopped(stopped, Event::Signal(sig)) = &wait
            && is_group_stop(stopped, *sig)?
        {
            let Wait::Stopped(stopped, _) = wait else {
                unreachable!("matched a stop");
            };
            wait = self
                .resume_stopped(stopped, None)?
                .next_state_with_owner(&self.ptracer_waits)
                .await?;
            self.arm_liteinst_wait(&wait);
        }
        match wait {
            Wait::Stopped(task, Event::Seccomp) => {
                set_sigmask(&task, mask)?;
                Ok(task)
            }
            Wait::Stopped(_, Event::Exit) | Wait::Exited(..) => Err(Errno::ESRCH.into()),
            Wait::Stopped(task, event) => {
                tracing::error!(
                    "[scheduler/tool] (pid = {}) re-executing a syscall after a SIGTRAP repair stopped at {:?}",
                    task.pid(),
                    event
                );
                Err(Errno::EPROTO.into())
            }
        }
    }

    /// Writes `action` back as SIGTRAP's action, with an unstepped
    /// `rt_sigaction` from the page at `scratch` (`sigtrap_scratch`),
    /// after a Reverie trap reset it. While a temporary mask's
    /// restore is pending it cannot be written (`untraced_syscall_unstepped`
    /// refuses with `EBUSY`), and a warning is logged.
    async fn write_sigtrap_action_at(
        &mut self,
        task: Stopped,
        scratch: usize,
        action: KernelSigaction,
    ) -> Result<Stopped, TraceError> {
        // What the write leaves is read again when next needed
        // (`sigtrap_ignored`).
        self.forget_sigtrap_ignored();
        #[cfg(test)]
        UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.set(count.get() + 1));
        let written = AddrMut::from_raw(scratch)
            .ok_or(Errno::EFAULT)
            .and_then(|address| {
                task.generation()
                    .assume_stopped()
                    .write_value(address, &action)
            });
        if let Err(errno) = written {
            self.lose_sigtrap_scratch(&task, errno);
            return Ok(task);
        }
        let args = SyscallArgs::new(
            libc::SIGTRAP as usize,
            scratch,
            0,
            std::mem::size_of::<u64>(),
            0,
            0,
        );
        let (task, result) = self
            .untraced_syscall_unstepped(task, Sysno::rt_sigaction, args)
            .await?;
        match result {
            Ok(_) => Ok(task),
            Err(Errno::EBUSY) => {
                tracing::warn!(
                    "[scheduler/tool] (pid = {}) cannot write back SIGTRAP's action while a temporary mask's restore is pending",
                    task.pid()
                );
                Ok(task)
            }
            Err(errno) => {
                self.lose_sigtrap_scratch(&task, errno);
                Ok(task)
            }
        }
    }

    /// Installs the guest's `act` at `act` as SIGTRAP's action again, with an
    /// unstepped `rt_sigaction` and no `oldact`, after an injected
    /// `rt_sigaction(SIGTRAP, act, oldact)` failed with `EFAULT`: the kernel's
    /// copy of `act` runs in the guest thread, under its own protections and
    /// protection keys, so it fails again exactly when the first call's did.
    /// `Some(true)` if it succeeded (the first call installed `act`, and this
    /// one undid any trap reset of it), `Some(false)` if it failed with
    /// `EFAULT` (the first call installed nothing), `None` if it cannot run
    /// here: in a signal callback, whose resume expects the stop the last
    /// injection ended at, or while a temporary mask's restore is pending.
    async fn reinstall_sigtrap_action(&mut self, act: usize) -> Result<Option<bool>, TraceError> {
        if self.in_signal_callback || self.in_held_signal_callback || !self.keeps_sigtrap_state() {
            return Ok(None);
        }
        let task = self.assume_stopped();
        // The guest's own seccomp filter could kill or trap the injection.
        if self.guest_has_own_seccomp_filter(task.pid()) {
            return Ok(None);
        }
        #[cfg(test)]
        UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.set(count.get() + 1));
        let args = SyscallArgs::new(
            libc::SIGTRAP as usize,
            act,
            0,
            std::mem::size_of::<u64>(),
            0,
            0,
        );
        let (_task, result) = self
            .untraced_syscall_unstepped(task, Sysno::rt_sigaction, args)
            .await?;
        match result {
            Ok(_) => Ok(Some(true)),
            Err(Errno::EFAULT) => Ok(Some(false)),
            // Undecided: EBUSY, or a refusal Reverie's own call met.
            Err(_) => Ok(None),
        }
    }

    /// Reads, before an injection of `nr` with `args` changes the registers,
    /// what its single-step's trap can change of SIGTRAP's state
    /// (`sigtrap_state`).
    async fn read_sigtrap_before_injection(
        &mut self,
        task: Stopped,
        nr: Sysno,
        args: &SyscallArgs,
    ) -> Result<(Stopped, SigtrapBeforeInjection), TraceError> {
        let kind = step_kind(nr, swaps_signal_mask(nr));
        let mask = sigmask(&task)?;
        self.injection_proc_state = None;
        self.injection_installs_caught = false;
        self.step_choice = None;
        // The quiet case, without procfs: a syscall that keeps the mask, with
        // SIGTRAP unblocked in the guest's mask and its action `SIG_DFL`
        // (neither ignored nor caught, `sigtrap_disposition_known`), and the
        // call not setting SIGTRAP's action. The step's trap then resets
        // nothing the guest keeps: the action is already `SIG_DFL`, and a
        // temporary mask still to be restored (procfs `SigBlk`, unread here)
        // gives way to the saved mask, which does not block SIGTRAP. Not
        // read either: a pending SIGTRAP that such a temporary mask blocks,
        // which the step would take as its trap, as it did before the keep.
        // A Tool's polling loop of injections made two procfs reads each.
        if kind == StepKind::KeepsMask
            && !self.restore_maybe_pending
            && mask & SIGTRAP_BIT == 0
            && !sets_sigtrap_action(nr, args)
            && self.sigtrap_disposition_known(&task)? == (false, false)
        {
            return Ok((
                task,
                SigtrapBeforeInjection {
                    quiet: true,
                    kind,
                    mask,
                    blocked: mask,
                    ignored: false,
                    caught_action: None,
                    sets_action: None,
                    sigaction_call: None,
                    sets_mask: None,
                    temporary_mask: None,
                },
            ));
        }
        // With no temporary mask's restore possibly pending, the kernel blocks
        // under the guest's mask, the disposition is the remembered one, and
        // a pending SIGTRAP is in one of the two signal queues
        // (`PTRACE_PEEKSIGINFO`): procfs, which a Tool's polling loop of
        // injections read on every one, is not needed. Not seen this way: a
        // SIGTRAP pending without a queued siginfo, which the kernel leaves
        // only when it cannot allocate one.
        let state = if self.restore_maybe_pending {
            ProcSignalState::read(&task)?
        } else {
            let (sigtrap_ignored, sigtrap_caught) = self.sigtrap_disposition_known(&task)?;
            ProcSignalState {
                blocked: mask,
                pending: if sigtrap_queued(&task)? {
                    SIGTRAP_BIT
                } else {
                    0
                },
                sigtrap_ignored,
                sigtrap_caught,
            }
        };
        self.injection_proc_state = Some((mask, state));
        // A pending, blocked SIGTRAP cannot be kept across the step: the
        // step's trap is absorbed into it, and the reset unblocks it, so it is
        // taken as if it were the trap (`PendingSigtrapAtStep`). An unblocked
        // one is taken before the
        // instruction and discarded, as before (`untraced_syscall_with`).
        if state.pending & state.blocked & SIGTRAP_BIT != 0 {
            return Err(self.fail_pending_sigtrap(task.pid(), "private-page injection"));
        }
        let sets_action = (sets_sigtrap_action(nr, args)
            && args.arg3 == std::mem::size_of::<u64>())
        .then(|| read_sigaction_forced(&task, args.arg1))
        .flatten()
        .map(|action: KernelSigaction| {
            if action.handler == libc::SIG_DFL as u64 {
                SigtrapAction::Default
            } else {
                // The kernel drops SIGKILL and SIGSTOP from a handler's mask.
                SigtrapAction::Set(KernelSigaction {
                    mask: action.mask & BLOCKABLE_SIGNAL_BITS,
                    ..action
                })
            }
        });
        // Whether the step may leave the shield is decided at the step itself
        // (`step_private_syscall`), from the state then. A call that installs
        // a caught handler keeps it.
        self.injection_installs_caught =
            matches!(sets_action, Some(SigtrapAction::Set(action)) if !action.ignored());
        // A caught handler that the trap may reset is lost with it, so it is
        // read now: for a syscall that may set the mask, or one whose shield
        // a pending restore keeps from writing the mask. (A caught SIGTRAP
        // never leaves the shield.) An ignored action keeps the rest of itself
        // and is read back at the repair.
        let restore_pending = state.blocked != mask;
        let (task, caught_action) =
            if state.sigtrap_caught && (kind != StepKind::KeepsMask || restore_pending) {
                self.query_sigtrap_action(task).await?
            } else {
                (task, None)
            };
        let read_u64 = |address: usize| {
            Addr::<u64>::from_raw(address).and_then(|address| task.read_value(address).ok())
        };
        let sigaction_call = sets_action.is_some().then_some((args.arg1, args.arg2 != 0));
        let sets_mask = (kind == StepKind::SetsMask).then(|| {
            let set = (args.arg1 != 0 && args.arg3 == std::mem::size_of::<u64>())
                .then(|| read_u64(args.arg1))
                .flatten();
            mask_after_sigprocmask(mask, args.arg0 as i32, set)
        });
        let temporary_mask = (kind == StepKind::SwapsMask)
            .then(|| temporary_signal_mask(&task, nr, args))
            .flatten();
        Ok((
            task,
            SigtrapBeforeInjection {
                quiet: false,
                kind,
                mask,
                blocked: state.blocked,
                ignored: state.sigtrap_ignored,
                caught_action,
                sets_action,
                sigaction_call,
                sets_mask,
                temporary_mask,
            },
        ))
    }

    /// After an injection's single-step, puts back what its trap reset of
    /// SIGTRAP's state (`sigtrap_state`): the mask bit, which the trap clears
    /// where the guest's mask blocks SIGTRAP (no injection but an exec's is
    /// shielded, `step_private_syscall`), and the action, if the trap could
    /// have seen SIGTRAP blocked or ignored. Runs after `status_to_result`, so that any
    /// signal the step stopped at is already held, and the unstepped
    /// `rt_sigaction` cannot discard it.
    async fn repair_sigtrap_after_injection(
        &mut self,
        before: SigtrapBeforeInjection,
        result: &Result<i64, Errno>,
    ) -> Result<(), TraceError> {
        let choice = self.step_choice.take();
        self.injection_installs_caught = false;
        if !self.last_injection_ran || before.quiet {
            // Stopped before its instruction, so no trap was raised; or a
            // trap that reset nothing.
            return Ok(());
        }
        let task = self.assume_stopped();
        // With no restore possibly pending before the call
        // (`restore_maybe_pending`), only a mask-swapping call can leave one,
        // and only `rt_sigreturn` replaces the mask from a frame: after any
        // other there is none now either. Otherwise the kernel may have done
        // the restore during the call's step (resuming a signal stop with no
        // signal restores the saved mask), so it is read again.
        let restore_pending = if !self.restore_maybe_pending
            && matches!(
                before.kind,
                StepKind::KeepsMask | StepKind::SetsMask | StepKind::Clones
            ) {
            false
        } else {
            ProcSignalState::read(&task)?.blocked != sigmask(&task)?
        };
        // Whether the trap could have seen SIGTRAP blocked, and whether the
        // guest's mask should block it now.
        let (trap_blocked, should_block) = match before.kind {
            // Decided at the step (`step_private_syscall`).
            StepKind::KeepsMask => match choice {
                // Unshielded while the guest's mask blocked SIGTRAP and no
                // restore was pending: the trap saw SIGTRAP blocked, cleared
                // the bit, and reset an ignored action; the bit goes back.
                Some(StepChoice {
                    unshielded_mask: Some(mask),
                    ..
                }) => (mask & SIGTRAP_BIT != 0, Some(mask & SIGTRAP_BIT != 0)),
                // The shield unblocked SIGTRAP for the trap, and blocked it
                // again.
                Some(StepChoice { shielded: true, .. }) => (false, None),
                // No shield was applied because a temporary mask's restore
                // was pending, on a table no other thread uses
                // (`table_unshared_now`): resuming from the signal stop may
                // have restored the saved mask first, so the trap saw either
                // the temporary or the saved mask, and either is taken (a
                // repair writes only over the reset it expects,
                // `repair_sigtrap_at`). The guest's mask bit goes back unless
                // the restore is still pending. The mask is this thread's
                // alone.
                _ if before.blocked != before.mask && self.table_unshared_now() => (
                    (before.blocked | before.mask) & SIGTRAP_BIT != 0,
                    Some(before.mask & SIGTRAP_BIT != 0),
                ),
                // As before: no shield was applied, because the mask admitted
                // SIGTRAP or a pending restore kept the shield from writing
                // it; the trap saw the mask the kernel blocked under.
                _ => (
                    before.blocked != before.mask && before.blocked & SIGTRAP_BIT != 0,
                    None,
                ),
            },
            StepKind::SetsMask => {
                let after = match result {
                    Ok(_) => before.sets_mask.unwrap_or(before.mask),
                    Err(_) => before.mask,
                };
                (after & SIGTRAP_BIT != 0, Some(after & SIGTRAP_BIT != 0))
            }
            StepKind::Clones => (
                before.mask & SIGTRAP_BIT != 0,
                Some(before.mask & SIGTRAP_BIT != 0),
            ),
            // Interrupted, with the restore still pending: the trap saw the
            // temporary mask, and the saved mask the kernel restores later is
            // intact. Otherwise the kernel restored the saved mask before the
            // trap.
            StepKind::SwapsMask if restore_pending => (
                before
                    .temporary_mask
                    .is_none_or(|temporary| temporary & SIGTRAP_BIT != 0),
                None,
            ),
            StepKind::SwapsMask => (
                before.mask & SIGTRAP_BIT != 0,
                Some(before.mask & SIGTRAP_BIT != 0),
            ),
            // The frame's mask is not known here.
            StepKind::Sigreturn => (true, None),
        };
        if should_block == Some(true) && !restore_pending {
            let mask = sigmask(&task)?;
            if mask & SIGTRAP_BIT == 0 {
                set_sigmask(&task, mask | SIGTRAP_BIT)?;
            }
        }
        // The action in force after the call, before any trap reset it. An
        // injected `rt_sigaction(SIGTRAP, act)` that succeeded installed
        // `act`, which replaces any repair owed from before the call. The
        // kernel copies `act` in before it installs anything and the old
        // action out after, so `EFAULT` without `oldact` installed nothing.
        // With `oldact`, either copy may have failed: `act` is installed
        // again, unstepped, which fails the same way exactly when its copy
        // does (`reinstall_sigtrap_action`); if it succeeds, the action is
        // `act` again and nothing is owed. Where that cannot run (in a signal
        // callback, or while a temporary mask's restore is pending), the call
        // is taken to have installed nothing, a documented limit.
        let sets_action = match (result, before.sigaction_call) {
            (Ok(_), _) => before.sets_action,
            (Err(Errno::EFAULT), Some((act, true))) => {
                match self.reinstall_sigtrap_action(act).await? {
                    Some(true) => {
                        self.set_sigtrap_repair(None);
                        return Ok(());
                    }
                    Some(false) | None => None,
                }
            }
            _ => None,
        };
        match sets_action {
            Some(SigtrapAction::Set(action)) => {
                self.set_sigtrap_repair(
                    (action.ignored() || trap_blocked).then_some(SigtrapRepair::Action(action)),
                );
            }
            Some(SigtrapAction::Default) => self.set_sigtrap_repair(None),
            None if before.ignored => self.note_sigtrap_repair(SigtrapRepair::Ignored),
            None if trap_blocked => {
                if let Some(action) = before.caught_action {
                    self.note_sigtrap_repair(SigtrapRepair::Action(action));
                }
            }
            None => {}
        }
        if self.sigtrap_repair().is_some() {
            self.apply_sigtrap_repair(task).await?;
        }
        Ok(())
    }

    /// Runs a frame-mode injection of the event's original syscall
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
    /// (`untraced_syscall_with`); a frame-mode injection keeps the not-run
    /// handling for it (`status_to_result`). `SIGKILL` has
    /// no signal stop to return; `requeueable` names it only for
    /// completeness. Signals requeued before it stay pending.
    async fn requeue_signals_before_original_syscall(
        &mut self,
        wait: Wait,
        seccomp_trapped: bool,
        nr: Sysno,
    ) -> Result<(Wait, bool), TraceError> {
        fn requeueable(sig: AnySignal) -> bool {
            !matches!(
                sig.as_nix(),
                Some(Signal::SIGKILL | Signal::SIGSTOP | Signal::SIGTRAP)
            )
        }
        fn before_instruction(stopped: &Stopped) -> Result<bool, TraceError> {
            Ok(stopped.getregs()?.ip() as usize == cp::PRIVATE_PAGE_OFFSET)
        }
        match &wait {
            Wait::Stopped(stopped, event)
                if event.signal().is_some_and(requeueable) && before_instruction(stopped)? => {}
            _ => return Ok((wait, seccomp_trapped)),
        }
        let Wait::Stopped(stopped, _) = &wait else {
            unreachable!("matched a stopped task")
        };
        let original_mask = stopped.getsigmask()?;
        self.requeue_signals_until_syscall_entry(
            wait,
            original_mask,
            original_mask,
            nr,
            false,
            true,
        )
        .await
    }

    /// Runs an injected syscall with the signals in `shield` blocked until the
    /// syscall's entry, so none of them is taken from the kernel's queue
    /// before the `syscall` instruction. Three injections need this; the
    /// first two shield every realtime signal (32 to 64):
    ///
    /// - One in a held signal's callback (`in_held_signal_callback`, with
    ///   `requeue`). A signal taken before its instruction is put back in the
    ///   queue (`requeue_signals_before_original_syscall`), and a realtime
    ///   one would go to the tail, behind later instances of its number,
    ///   which Linux delivers first in, first out.
    /// - One that starts while a signal is held (`pending_signal`), such as
    ///   the retry of an injection a realtime signal stopped
    ///   (`Guest::inject_with_retry`). A signal taken before its instruction
    ///   is held, and a second would replace the first in the single slot,
    ///   losing it and its siginfo.
    /// - A mask-swapping injection (`swaps_signal_mask`) shields the signals
    ///   its temporary mask blocks and the thread's own mask admits
    ///   (`temporary_signal_mask`), except the timer's own and SIGTRAP
    ///   (`NEVER_SHIELDED`). The private-page step returns to user space
    ///   under the thread's own mask before the syscall installs its
    ///   temporary one, so such a signal would stop the step there, and the
    ///   injection would report the call interrupted, where the guest's own
    ///   call keeps waiting with the signal pending
    ///   (<https://github.com/rrnewton/hermit/issues/4149>). Requeuing it
    ///   after the stop would keep the answer, but a process-directed signal
    ///   is off the shared queue while this thread holds it, so a sibling
    ///   that Linux would give it to can run past it.
    ///
    /// Other signals stop the step as before: requeued with `requeue`, else
    /// returned for the generic not-run handling (`status_to_result`). For a
    /// mask-swapping injection those are signals both masks admit, which end
    /// the call either way. (For rt_sigsuspend, Linux would run the call and
    /// the handler would see its temporary mask; the not-run report predates
    /// this shield.)
    ///
    /// A frame-mode injection (`injected_syscall_frame`) is never shielded,
    /// and neither is a mask-swapping injection on a tracer thread a seccomp
    /// filter may restrict (`thread_may_be_seccomp_filtered`) or while an
    /// earlier mask-swapping syscall's mask restore is pending.
    ///
    /// The thread is resumed with `PTRACE_SYSCALL` to the syscall-entry stop,
    /// where its own mask is restored before `step_private_syscall` runs the
    /// syscall, so the syscall sees the mask and pending signals it would
    /// have seen. After the syscall the step's SIGTRAP is reported before any
    /// realtime signal (it is synchronous-class), so the realtime signals stay
    /// queued, in order, until the guest resumes. Before the instruction, a
    /// standard signal is requeued as there, the thread's own timer
    /// notification is taken as `step_private_syscall_discarding_late_timer`
    /// takes it, and a SIGTRAP is discarded as `untraced_syscall_with`
    /// discards it.
    async fn step_shielded_injection(
        &mut self,
        task: Stopped,
        nr: Sysno,
        shield: u64,
        requeue: bool,
    ) -> Result<(Wait, bool), TraceError> {
        let original_mask = task.getsigmask()?;
        let mask = original_mask | shield;
        task.setsigmask(mask)?;
        let wait = self
            .syscall_stopped_any(task, None)?
            .next_state_with_owner(&self.ptracer_waits)
            .await?;
        self.arm_liteinst_wait(&wait);
        self.requeue_signals_until_syscall_entry(wait, original_mask, mask, nr, true, requeue)
            .await
    }

    /// The loop of `requeue_signals_before_original_syscall` and
    /// `step_shielded_injection`: runs the thread, blocked in `mask`, to
    /// its private-page syscall's entry stop, where `original_mask` is
    /// restored and `step_private_syscall` runs the syscall. A signal that
    /// stops it before the `syscall` instruction is requeued with `requeue`,
    /// else returned with `original_mask` restored. With `plain_injection`
    /// (not a frame-mode injection of the original syscall), a SIGTRAP
    /// before the instruction is discarded and the thread's own timer
    /// notification, live or late, is taken, as
    /// `step_private_syscall_discarding_late_timer` takes it; otherwise only
    /// a late timer overflow is.
    async fn requeue_signals_until_syscall_entry(
        &mut self,
        wait: Wait,
        original_mask: u64,
        mut mask: u64,
        nr: Sysno,
        plain_injection: bool,
        requeue: bool,
    ) -> Result<(Wait, bool), TraceError> {
        fn requeueable(sig: AnySignal) -> bool {
            !matches!(
                sig.as_nix(),
                Some(Signal::SIGKILL | Signal::SIGSTOP | Signal::SIGTRAP)
            )
        }
        fn before_instruction(stopped: &Stopped) -> Result<bool, TraceError> {
            Ok(stopped.getregs()?.ip() as usize == cp::PRIVATE_PAGE_OFFSET)
        }
        let mut wait = wait;
        loop {
            match wait {
                Wait::Stopped(stopped, Event::Signal(Signal::SIGTRAP))
                    if plain_injection
                        && before_instruction(&stopped)?
                        && !thread_may_be_seccomp_filtered() =>
                {
                    tracing::debug!(
                        "[scheduler/tool] (pid = {}) discarding a SIGTRAP that stopped injected {} before it ran",
                        stopped.pid(),
                        nr
                    );
                    wait = self
                        .syscall_stopped_any(stopped, None)?
                        .next_state_with_owner(&self.ptracer_waits)
                        .await?;
                    self.arm_liteinst_wait(&wait);
                }
                Wait::Stopped(stopped, event)
                    if let Some(sig) = event.signal()
                        && requeueable(sig)
                        && before_instruction(&stopped)? =>
                {
                    let deliver = if is_group_stop(&stopped, sig)? {
                        None
                    } else if plain_injection
                        && sig == Timer::signal_type()
                        && let Some(notification) = self.take_own_timer_notification(&stopped)?
                    {
                        match notification {
                            OwnNotification::Live => {
                                LIVE_TIMER_SIGNALS_TAKEN.fetch_add(1, Ordering::Relaxed)
                            }
                            OwnNotification::Late => {
                                LATE_TIMER_SIGNALS_DISCARDED.fetch_add(1, Ordering::Relaxed)
                            }
                        };
                        None
                    } else if !plain_injection
                        && sig == Timer::signal_type()
                        && self.consume_own_timer_overflow(&stopped)?
                    {
                        LATE_TIMER_SIGNALS_DISCARDED.fetch_add(1, Ordering::Relaxed);
                        None
                    } else if !requeue {
                        stopped.setsigmask(original_mask)?;
                        return Ok((Wait::Stopped(stopped, event), false));
                    } else {
                        mask |= signal_mask_bit(sig);
                        stopped.setsigmask(mask)?;
                        Some(sig)
                    };
                    wait = self
                        .syscall_stopped_any(stopped, deliver)?
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
        // Every completed injection moves the thread off the stop an approved
        // delivery was checked at.
        if let Some(approval) = &mut self.signal_approval {
            approval.voided = true;
        }
        if let Wait::Stopped(stopped, event) = wait {
            self.latest_injection_stop = Some(match event {
                event
                    if let Some(sig) = event.signal()
                        && !is_group_stop_unless_filtered(stopped, sig)? =>
                {
                    Some(sig)
                }
                _ => None,
            });
        }
        Ok(())
    }

    /// Holds `sig`, which stopped a private-page step at its signal-delivery
    /// stop `stopped`, in `pending_signal` for delivery when the guest resumes
    /// at its syscall site, and records what it was taken with
    /// (`pending_signal_taken`, see `status_to_result`).
    fn hold_pending_signal(&mut self, stopped: &Stopped, sig: AnySignal) {
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
        // A reported, requeued instance of `sig` is in the thread's own queue,
        // which Linux dequeues first, and a standard signal has at most one
        // pending instance there, so this is that instance. Its count goes
        // with it. (A real-time signal can queue several instances; the count
        // stays by number for those.)
        self.pending_signal_reported = self.take_reported_requeue(sig);
    }

    async fn status_to_result(
        &mut self,
        wait_status: Wait,
        context: Option<libc::user_regs_struct>,
        child_context: Option<libc::user_regs_struct>,
    ) -> Result<Result<i64, Errno>, TraceError> {
        self.note_injection_stop(&wait_status)?;
        self.last_injection_ran = true;
        match wait_status {
            Wait::Stopped(stopped, event) => match event {
                event
                    if let Some(sig) = event.signal()
                        && context.is_none() =>
                {
                    // The guest's own pending syscall, resumed from its
                    // syscall stop to its exit (`inner_inject`). Linux reports
                    // the exit stop before any signal-delivery stop for a
                    // syscall it ran, so this one did not run, and RAX holds
                    // no result of it. Report that it did not run, holding the
                    // signal for the resume as for a private-page step that a
                    // signal stopped before its `syscall`. An unclaimed
                    // SIGTRAP is not held: the main loop does not deliver one
                    // (`handle_sigtrap`).
                    if sig != Signal::SIGTRAP {
                        self.hold_pending_signal(&stopped, sig);
                    }
                    self.last_injection_ran = false;
                    Ok(Err(Errno::ERESTARTSYS))
                }
                event if let Some(sig) = event.signal() => {
                    let mut regs = stopped.getregs()?;
                    // NB: it is possible to get interrupted by signal (such as
                    // SIGCHLD) before single step finishes, while RIP still
                    // points at the private page.
                    debug_assert!(
                        regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET + cp::SYSCALL_INSTR_SIZE
                            || regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET
                    );
                    if child_context.is_some() {
                        // An injected frame (`injected_syscall_frame`): the
                        // controller is parked at its trap, so the tracer, not
                        // the kernel, decides restarts.
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
                                self.last_injection_ran = false;
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
                                // The private-page step stopped outside the
                                // private syscall.
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
                            self.last_injection_ran = false;
                        }
                        self.hold_pending_signal(&stopped, sig);
                    } else if regs.ip() as usize == cp::PRIVATE_PAGE_OFFSET {
                        // A SIGTRAP the guest or another process sent stopped
                        // the step before the `syscall` ran, and
                        // `untraced_syscall_with` did not discard it and step
                        // again (see there). RAX still holds the syscall
                        // number, which is no result: report that the syscall
                        // did not run. The trap is not held, as the main loop
                        // does not deliver an unclaimed SIGTRAP
                        // (`handle_sigtrap`).
                        *regs.ret_mut() = (-(Errno::ERESTARTSYS.into_raw()) as i64) as u64;
                        self.last_injection_ran = false;
                    }
                    let result = Errno::from_ret(regs.ret() as usize).map(|x| x as i64);
                    if let Some(context) = context {
                        if child_context.is_some() {
                            // An injected-frame event temporarily replaces the
                            // controller's live trap registers with the logical
                            // guest frame. Restore every controller register;
                            // leaving even a callee-saved register would
                            // corrupt the code that resumes after injection.
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
                        .handle_new_task(op, stopped, child, context, child_context)
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
                            // The step's trap must not reset a blocked SIGTRAP
                            // (`sigtrap_state`); an ignored one is repaired
                            // with the rest of the injection.
                            let shielded = self.shield_sigtrap_for_step(&parent, "vfork parent")?;
                            let wait = self
                                .step_stopped(parent, None)?
                                .next_state_with_owner(&self.ptracer_waits)
                                .await?;
                            self.arm_liteinst_wait(&wait);
                            if shielded {
                                reblock_sigtrap_after_step(&wait)?;
                            }
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
                Event::Exec(_new_pid) => {
                    // The callback that injected the exec never resumes, so
                    // the replacement image runs outside it
                    // (`handle_exec_event` ends its state).
                    // This should never return.
                    let next_state = self.handle_exec_event(stopped).await?;
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

    /// Runs an injection through ptrace's [`LinuxProvider`], the host kernel
    /// ([`host_linux::HostLinux`]), which runs it in this stopped tracee with
    /// [`Self::inner_inject`].
    ///
    /// [`LinuxProvider`]: reverie::provider::LinuxProvider
    async fn do_inject(&mut self, nr: Sysno, args: SyscallArgs) -> Result<i64, Errno> {
        let outcome = self.do_inject_outcome(nr, args).await;
        match host_linux::guest_result(outcome) {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    /// The provider outcome of one injection; a broken invariant ends the
    /// run here, as in [`Self::do_inject`].
    async fn do_inject_outcome(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> reverie::provider::ProviderOutcome<std::convert::Infallible> {
        use reverie::provider::LinuxProvider;
        let request = host_linux::request(nr, args);
        let tid = self.tid();
        match host_linux::HostLinux::<L>::new()
            .execute(tid, &request, self)
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    async fn inner_inject(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
    ) -> Result<Result<i64, Errno>, TraceError> {
        // A Tool's own `rt_sigaction` of SIGTRAP may change whether it is
        // ignored (`sigtrap_ignored`), here or, run in place, on the resume.
        if self.global_state.keeps_sigtrap_state && sets_sigtrap_action(nr, &args) {
            self.mark_sigtrap_changing();
        }
        // A clone that may share this group's signal-action table marks it
        // shared before it runs, whether or not its child is traced
        // (`CLONE_UNTRACED` gives no new-child event).
        if self.global_state.keeps_sigtrap_state && self.clone_may_share_signal_actions(nr, &args) {
            self.global_state
                .sigtrap_tables
                .lock()
                .unwrap()
                .add_thread(self.sigtrap_table);
        }
        // A mask-swapping call can leave its temporary mask's restore pending.
        if swaps_signal_mask(nr) {
            self.restore_maybe_pending = true;
        }
        self.inner_inject_unobserved(nr, args).await
    }

    /// `inner_inject`, without forgetting SIGTRAP's disposition.
    async fn inner_inject_unobserved(
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

        if self.injected_syscall_frame.is_some() {
            let original = self.pending_syscall.take() == Some((nr, args));
            self.pending_syscall = None;
            self.untraced_syscall_with(task, nr, args, original).await
        } else {
            match self.pending_syscall.take() {
                Some(original) if original == (nr, args) => {
                    // Run the exact pending syscall and stop at its exit.
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
                    // A clone run in place steps its parent once
                    // (`handle_new_task`); an ignored SIGTRAP its trap reset is
                    // put back before the Tool goes on.
                    if self.sigtrap_repair().is_some() && self.keeps_sigtrap_state() {
                        let task = self.assume_stopped();
                        self.apply_sigtrap_repair(task).await?;
                    }
                    Ok(result)
                }
                Some(_) => self.private_inject(task, nr, args).await,
                None => self.untraced_syscall(task, nr, args).await,
            }
        }
    }

    async fn do_tail_inject(&mut self, nr: Sysno, args: SyscallArgs) -> ! {
        // A tail injection never returns to the signal callback that approved
        // a delivery (`Guest::deliver_signal`), so `report_signal` would never
        // enforce the approval. It is refused before anything runs.
        if let Some(approval) = self.signal_approval {
            let error = self.fail_broken_approval(approval, "then made a tail injection");
            self.abort(Err(error)).await
        }
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
        // As for `inner_inject`: whichever path runs it, and whenever.
        if self.global_state.keeps_sigtrap_state && sets_sigtrap_action(nr, &args) {
            self.mark_sigtrap_changing();
        }
        // A clone that may share this group's signal-action table marks it
        // shared before it runs, whether or not its child is traced
        // (`CLONE_UNTRACED` gives no new-child event).
        if self.global_state.keeps_sigtrap_state && self.clone_may_share_signal_actions(nr, &args) {
            self.global_state
                .sigtrap_tables
                .lock()
                .unwrap()
                .add_thread(self.sigtrap_table);
        }
        if swaps_signal_mask(nr) {
            self.restore_maybe_pending = true;
        }

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
                    let sig = self.filter_direct_unreported(&task, Signal::SIGCHLD).await;
                    let running = self.step_stopped_any(task, sig)?;
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
    type Memory = crate::tool_memory::ToolMemory;
    type Stack = GuestStack;

    fn signal_info(&self) -> Option<[u8; reverie::SIGNAL_INFO_SIZE]> {
        self.reported_signal.and_then(|(_, info)| info)
    }

    fn set_signal_info(&mut self, info: [u8; reverie::SIGNAL_INFO_SIZE]) -> Result<(), Errno> {
        let Some((signal, _)) = self.reported_signal else {
            return Err(Errno::EINVAL);
        };
        // Linux replaces a siginfo whose `si_signo` is not the resumed
        // signal's, so a mismatched one could never be delivered.
        if i32::from_ne_bytes(info[0..4].try_into().expect("four bytes")) != signal.raw() {
            return Err(Errno::EINVAL);
        }
        // Written now, from the signal-delivery stop the thread is at, so a
        // refusal reaches the caller; the resume writes it again after any
        // later injection (`resume_with_signal`). After an injection whose
        // stop is not a signal-delivery stop, Linux would make up the
        // resumed signal's siginfo, so the replacement cannot apply.
        if !self.latest_injection_stop.is_none_or(|stop| stop.is_some()) {
            return Err(Errno::EBUSY);
        }
        self.assume_stopped()
            .setsiginfo_bytes(&info)
            .map_err(|error| match error {
                TraceError::Errno(errno) => errno,
                TraceError::Died(_) => Errno::ESRCH,
            })?;
        self.replacement_signal_info = Some((signal, info));
        Ok(())
    }

    /// Checks the approval at the reported signal's own delivery stop, or at
    /// its held-signal report, with read-only requests: `PTRACE_GETSIGMASK`
    /// (the mask the frame saves), procfs `SigBlk` (the mask in effect) and
    /// the guest's registers (`orig_rax`, `rax`). The signal's identity is
    /// its recorded `TakenSignal`, never a live `PTRACE_GETSIGINFO`, which
    /// after an injection describes the injection's stop. When every check
    /// passes the approval is recorded, and `report_signal` enforces it when
    /// the callback returns.
    async fn deliver_signal(
        &mut self,
        delivery: reverie::SignalDelivery,
    ) -> reverie::SignalDeliveryOutcome {
        use reverie::SignalDeliveryOutcome as Outcome;
        use reverie::SignalDeliveryUnavailable as Unavailable;
        let unavailable = Outcome::Unavailable;
        let Some((reported, record)) = self.reported_signal.filter(|_| self.in_signal_callback)
        else {
            return unavailable(Unavailable::NotInSignalCallback);
        };
        if delivery.signal != reported.raw() {
            return unavailable(Unavailable::NotTheReportedSignal {
                reported: reported.raw(),
            });
        }
        if record.is_none() {
            return unavailable(Unavailable::NoSignalRecord);
        }
        if self.signal_approval.is_some() {
            return unavailable(Unavailable::AlreadyApproved);
        }
        if self.signal_delivery_mismatched {
            return unavailable(Unavailable::AfterMismatch);
        }
        if delivery.unchecked_mask & reverie::signal_set_bit(delivery.signal) != 0 {
            return unavailable(Unavailable::UncheckedSignal);
        }
        if self.injected_syscall_frame.is_some() {
            return unavailable(Unavailable::FrameModeStop);
        }
        if self.latest_injection_stop == Some(None) {
            return unavailable(Unavailable::NotADeliveryStop);
        }
        if thread_may_be_seccomp_filtered() {
            return unavailable(Unavailable::TracerFiltered);
        }
        if !cfg!(target_arch = "x86_64") {
            return unavailable(Unavailable::UnsupportedArchitecture);
        }
        let task = self.assume_stopped();
        let read_failure = |error: TraceError| match error {
            TraceError::Died(_) | TraceError::Errno(Errno::ENOENT | Errno::ESRCH) => {
                Unavailable::Gone
            }
            TraceError::Errno(errno) => Unavailable::Unreadable(errno),
        };
        let kernel = (|| -> Result<reverie::KernelDeliveryState, TraceError> {
            let frame_mask = task.getsigmask()?;
            let current_mask = blocked_signal_mask(self.tid())?;
            let regs = self.read_guest_registers(&task)?;
            Ok(reverie::KernelDeliveryState {
                frame_mask,
                current_mask,
                orig_syscall: regs.orig_syscall() as i64,
                ret: regs.ret() as i64,
            })
        })();
        let kernel = match kernel {
            Ok(kernel) => kernel,
            Err(error) => return unavailable(read_failure(error)),
        };
        if kernel.current_mask & reverie::signal_set_bit(delivery.signal) != 0 {
            return unavailable(Unavailable::BlockedAtResume);
        }
        match delivery.check(&kernel) {
            Ok(()) => {
                self.signal_approval = Some(SignalApproval {
                    signal: reported,
                    voided: false,
                });
                Outcome::Accepted
            }
            Err(mismatch) => {
                self.signal_delivery_mismatched = true;
                tracing::debug!(
                    "[{}] signal delivery of {reported:?} does not match the kernel: {mismatch:?}",
                    self.tid()
                );
                Outcome::Mismatch(mismatch)
            }
        }
    }

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

    fn initial_stack_pointer(&self) -> Option<u64> {
        self.initial_stack_pointer
    }

    fn memory(&self) -> Self::Memory {
        crate::tool_memory::ToolMemory::new(self.assume_stopped())
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        let task = self.assume_stopped();

        match self.read_guest_registers(&task) {
            Ok(ret) => ret,
            Err(err) => self.abort(Err(err)).await,
        }
    }

    /// `PTRACE_SETSIGMASK` on the stopped thread. Both refusals come before
    /// the write (`Unsupported`, `RestorePending`): outside a syscall callback, in a frame-mode event or a
    /// signal callback, or on a tracer thread a seccomp filter may restrict
    /// (`may_set_blocked_signals`); and when `PTRACE_GETSIGMASK` differs from
    /// procfs `SigBlk`, which means a mask-swapping syscall's temporary mask
    /// is in effect with its restore pending (`TIF_RESTORE_SIGMASK`): a ptrace
    /// mask write would discard that restore, so the signal the temporary mask
    /// admits would no longer be delivered under it. When the two agree, a
    /// pending restore would put back the mask already in effect, so
    /// discarding it changes nothing the guest can see. The written mask is
    /// read back; if it is not the one written, or cannot be read, the old
    /// one is written again and the call fails (`Failed`), saying whether the
    /// mask is the old one again.
    async fn set_blocked_signals(&mut self, mask: u64) -> Result<u64, reverie::MaskChangeRefused> {
        if !may_set_blocked_signals(
            self.in_syscall_callback,
            self.injected_syscall_frame.is_some(),
            self.in_signal_callback || self.in_held_signal_callback,
            thread_may_be_seccomp_filtered(),
        ) {
            return Err(reverie::MaskChangeRefused::Unsupported);
        }
        let task = self.assume_stopped();
        let old = task
            .getsigmask()
            .map_err(|error| mask_change_failure(error, false))?;
        // A thread that died since the first read has no procfs entry, or
        // one that is going away.
        let effective = blocked_signal_mask(self.tid()).map_err(|error| match error {
            TraceError::Errno(Errno::ENOENT | Errno::ESRCH) => reverie::MaskChangeRefused::Gone,
            error => mask_change_failure(error, false),
        })?;
        if effective != old {
            return Err(reverie::MaskChangeRefused::RestorePending {
                saved: old,
                effective,
            });
        }
        let new = mask_keeping_never_shielded(mask, old);
        task.setsigmask(new)
            .map_err(|error| mask_change_failure(error, false))?;
        // From here on the write may have taken effect, so a failure puts
        // the old mask back and says whether that took.
        let errno = match task.getsigmask() {
            Ok(written) if written == new => return Ok(old),
            // The kernel stored another mask than the one written.
            Ok(_) => Errno::EIO,
            Err(TraceError::Died(_)) => return Err(reverie::MaskChangeRefused::Gone),
            Err(TraceError::Errno(errno)) => errno,
        };
        let restored = task.setsigmask(old).and_then(|()| task.getsigmask());
        Err(match restored {
            Ok(mask) => reverie::MaskChangeRefused::Failed {
                errno,
                mask_unknown: mask != old,
            },
            Err(TraceError::Died(_)) => reverie::MaskChangeRefused::Gone,
            Err(TraceError::Errno(_)) => reverie::MaskChangeRefused::Failed {
                errno,
                mask_unknown: true,
            },
        })
    }

    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), reverie::Error> {
        let task = self.assume_stopped();
        // The checks of an approved delivery read these registers
        // (`Guest::deliver_signal`); a write voids it, as an injection does.
        if let Some(approval) = &mut self.signal_approval {
            approval.voided = true;
        }

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

    /// Returns `EINTR` or `ERESTARTSYS` from a syscall that ran while a
    /// signal is held (`pending_signal`). An injection that starts with a
    /// signal held keeps realtime signals queued until the syscall's entry,
    /// so one queued then is pending there, and a retry would return the same
    /// code at once until the syscall's own condition is met
    /// (<https://github.com/rrnewton/reverie/issues/998>). The held signal is
    /// delivered as the guest resumes, and Linux restarts the guest's
    /// syscall or fails it with `EINTR` by its handler. Without a held
    /// signal the code is retried as before, for example after a group stop
    /// or a signal the tracer consumes. A syscall that a signal stopped
    /// before it ran (the provider's `Interrupted` outcome) is retried. The
    /// decision is `host_linux::restartable`.
    async fn inject_restartable<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (nr, args) = syscall.into_parts();
        loop {
            let outcome = self.do_inject_outcome(nr, args).await;
            match host_linux::restartable(outcome, self.pending_signal.is_some()) {
                Ok(host_linux::Restart::Retry) => continue,
                Ok(host_linux::Restart::Return(result)) => return result,
                Err(err) => self.abort(Err(err)).await,
            }
        }
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
#[path = "task_deliver_signal_tests.rs"]
mod deliver_signal_tests;
#[cfg(test)]
#[path = "task_exec_owner_tests.rs"]
mod exec_owner_tests;
#[cfg(test)]
#[path = "task_set_blocked_signals_tests.rs"]
mod set_blocked_signals_tests;

#[cfg(test)]
mod tests {
    /// `set_blocked_signals` never adds SIGTRAP or the timer signal and never
    /// clears a guest's own block of them, so restoring `old` is exact.
    #[test]
    fn set_blocked_signals_keeps_the_never_shielded_bits_of_the_old_mask() {
        use super::NEVER_SHIELDED;
        use super::mask_keeping_never_shielded;
        let bit = |signal: i32| 1u64 << (signal - 1);
        let trap = bit(libc::SIGTRAP);
        let timer = bit(reverie::PERF_EVENT_SIGNAL as i32);
        let usr1 = bit(libc::SIGUSR1);
        // A full request over a mask that blocks neither: neither is added.
        let new = mask_keeping_never_shielded(!0, usr1);
        assert_eq!(new & (trap | timer), 0);
        assert_eq!(new, !NEVER_SHIELDED);
        // The guest blocks both itself: a request that clears every bit keeps them.
        let old = trap | timer | usr1;
        assert_eq!(mask_keeping_never_shielded(0, old), trap | timer);
        // A full request keeps them as well, and restoring `old` is exact.
        let new = mask_keeping_never_shielded(!0, old);
        assert_eq!(new & (trap | timer), trap | timer);
        assert_eq!(mask_keeping_never_shielded(old, new), old);
        // SIGKILL and SIGSTOP, which the kernel ignores, are never written.
        let unblockable = bit(libc::SIGKILL) | bit(libc::SIGSTOP);
        assert_eq!(mask_keeping_never_shielded(!0, 0) & unblockable, 0);
    }

    /// The mask changes only in a syscall callback, outside a frame-mode event
    /// and a signal callback, on a tracer thread no seccomp filter restricts.
    #[test]
    fn set_blocked_signals_is_refused_outside_a_plain_syscall_callback() {
        use super::may_set_blocked_signals;
        assert!(may_set_blocked_signals(true, false, false, false));
        assert!(!may_set_blocked_signals(false, false, false, false));
        assert!(!may_set_blocked_signals(true, true, false, false));
        assert!(!may_set_blocked_signals(true, false, true, false));
        assert!(!may_set_blocked_signals(true, false, false, true));
    }

    #[test]
    fn a_timer_is_notified_after_a_return_only_through_a_known_open_mask() {
        use reverie::SigreturnFrame;

        use super::timer_notified_after_return;
        let timer = 1u64 << (reverie::PERF_EVENT_SIGNAL as u32 - 1);
        let usr1 = 1u64 << (libc::SIGUSR1 - 1);
        assert!(timer_notified_after_return(SigreturnFrame::Readable {
            mask: 0
        }));
        assert!(timer_notified_after_return(SigreturnFrame::Readable {
            mask: usr1
        }));
        assert!(!timer_notified_after_return(SigreturnFrame::Readable {
            mask: timer
        }));
        assert!(!timer_notified_after_return(SigreturnFrame::Readable {
            mask: !0
        }));
        assert!(!timer_notified_after_return(SigreturnFrame::Unmapped));
        assert!(!timer_notified_after_return(SigreturnFrame::Protected));
    }

    #[test]
    fn private_step_distinguishes_not_run_ran_held_and_unexpected() {
        use super::PrivateStep;
        use super::Signal;
        use super::classify_private_step;
        const PRIVATE: u64 = 0x7000_0000;
        assert_eq!(
            classify_private_step(PRIVATE, Signal::SIGURG, PRIVATE, 2),
            PrivateStep::NotRun
        );
        // An external SIGTRAP pending before the step still stops before the
        // instruction; it is not a single-step report.
        assert_eq!(
            classify_private_step(PRIVATE, Signal::SIGTRAP, PRIVATE, 2),
            PrivateStep::NotRun
        );
        assert_eq!(
            classify_private_step(PRIVATE + 2, Signal::SIGTRAP, PRIVATE, 2),
            PrivateStep::Ran
        );
        assert_eq!(
            classify_private_step(PRIVATE + 2, Signal::SIGSYS, PRIVATE, 2),
            PrivateStep::Held
        );
        assert_eq!(
            classify_private_step(PRIVATE + 7, Signal::SIGTRAP, PRIVATE, 2),
            PrivateStep::Unexpected
        );
        assert_eq!(
            classify_private_step(u64::MAX, Signal::SIGTRAP, u64::MAX - 1, 2),
            PrivateStep::Unexpected
        );
    }

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

    /// The maps read reports a failure instead of returning no mappings
    /// (review finding F1 on
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
    fn pkey_mprotect_is_a_controller_mapping_syscall() {
        assert!(is_liteinst_mapping_syscall(Sysno::pkey_mprotect));
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

    /// A thread offered after the run has failed carries the failed run's
    /// cleanup deadline, so a Tool can bound its capture by it; one offered
    /// before carries none. Drives a real tracee to its SIGSEGV exit stop.
    #[test]
    fn a_fatal_signal_exit_offered_after_the_run_failed_carries_the_cleanup_deadline() {
        use nix::unistd::ForkResult;

        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        // A core limit of one byte makes the kernel run its dump step without
        // writing a host core. Under a hard limit of 0 the child cannot raise
        // its limit to 1, and whether it dumps then depends on core_pattern.
        let refuses_core = limit.rlim_max >= 1;
        let pid = match unsafe { nix::unistd::fork() }.expect("fork crashing child") {
            ForkResult::Child => {
                safeptrace::traceme_and_stop().expect("TRACEME crashing child");
                // The test harness's inherited SIGSEGV handler would
                // otherwise catch the signal.
                unsafe {
                    if refuses_core {
                        limit.rlim_cur = 1;
                        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                            libc::_exit(1);
                        }
                    }
                    libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                    libc::raise(libc::SIGSEGV);
                    libc::_exit(0)
                }
            }
            ForkResult::Parent { child } => Pid::from(child),
        };
        let (stopped, event) = Running::new(pid).wait().expect("wait").assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGSTOP));
        stopped
            .setoptions(safeptrace::Options::PTRACE_O_TRACEEXIT)
            .expect("set PTRACE_O_TRACEEXIT");
        let (stopped, event) = stopped
            .resume(None)
            .expect("resume")
            .wait()
            .expect("wait")
            .assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGSEGV));
        let (stopped, event) = stopped
            .resume(Signal::SIGSEGV)
            .expect("deliver SIGSEGV")
            .wait()
            .expect("wait")
            .assume_stopped();
        assert_eq!(event, Event::Exit);
        let status = ExitStatus::from_raw(stopped.getevent().expect("exit status") as i32);
        match status {
            ExitStatus::Signaled(Signal::SIGSEGV, dumped) => {
                assert!(!(refuses_core && dumped), "dumped core at limit 1");
            }
            _ => panic!("expected death by SIGSEGV, got {status:?}"),
        }

        let offers = Arc::new(StdMutex::new(Vec::new()));
        let record = offers.clone();
        let session = FatalSession {
            fatal_signal_exit: Some(Box::new(move |exit: &reverie::FatalSignalExit| {
                record
                    .lock()
                    .unwrap()
                    .push((exit.tid, exit.signal, exit.dumping, exit.deadline));
            })),
            ..FatalSession::default()
        };
        session.offer_fatal_signal_exit(&stopped, status);
        let before_failure = std::time::Instant::now();
        session.fail_at(
            BackendFailure {
                pid,
                tid: pid,
                phase: "fatal signal exit test",
            },
            anyhow::anyhow!("deliberate run failure").into(),
        );
        session.offer_fatal_signal_exit(&stopped, status);

        let offers = offers.lock().unwrap().clone();
        assert_eq!(offers.len(), 2, "{offers:?}");
        assert_eq!(offers[0], (pid, Signal::SIGSEGV, true, None));
        let (tid, signal, dumping, deadline) = offers[1];
        assert_eq!((tid, signal, dumping), (pid, Signal::SIGSEGV, true));
        let deadline = deadline.expect("an offer after the failure carries the deadline");
        assert!(deadline > before_failure, "{deadline:?} {before_failure:?}");

        let exited = stopped
            .resume(None)
            .expect("finish exit")
            .wait()
            .expect("wait");
        assert_eq!(exited.assume_exited().1, status);
    }
}
