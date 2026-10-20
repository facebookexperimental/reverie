/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::future::poll_fn;
use std::pin::Pin;
use std::pin::pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Poll;

use futures::FutureExt;
use kvm_bindings::kvm_regs;
use kvm_ioctls::VcpuExit;
use reverie::Auxv;
use reverie::DetlogMemoryRegion;
use reverie::DetlogRegionKind;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::SignalEvent;
use reverie::Stack;
use reverie::Subscription;
use reverie::ThreadOwnership;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::SyscallInfo;

use crate::Error;
use crate::GuestMemory;
use crate::KvmBackend;
use crate::Result;
use crate::SyscallRequest;
use crate::VMCALL_SYSCALL_TRANSPORT;
use crate::bootstrap::TOOL_STACK_SIZE;
use crate::bootstrap::process_syscall_return_registers;
use crate::bootstrap::set_user_segment_base;
use crate::bootstrap::stage_process_syscall_return;
use crate::executor::ChildStartCancellation;
#[cfg(test)]
use crate::executor::ChildStartCommand;
use crate::executor::ChildStartGate;
use crate::executor::ElfExecutor;
use crate::executor::PendingSignal;
use crate::executor::ProcessAction;
use crate::executor::ProcessExit;
use crate::executor::RunAdmission;
use crate::executor::conventional_exit_code;
use crate::failure::FailureContext;
use crate::failure::RunFailure;
use crate::failure::wait_for_failure;
use crate::memory::RegionKind;

/// Bounded test observations around the existing wait registration boundary.
/// Registration is current-host scoped and invokes no closure under its borrow.
#[cfg(test)]
pub(crate) mod entry_wait_observation {
    use std::cell::RefCell;
    use std::sync::Arc;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Site {
        HostMain,
        ToolMain,
        Parking,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Boundary {
        BeforeSubscription,
        AfterSubscription,
    }
    type Observer = Arc<dyn Fn(Site, Boundary) + Send + Sync>;
    thread_local! {
        static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
    }
    pub(crate) struct Scope {
        prior: Option<Observer>,
        thread: std::thread::ThreadId,
        _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }
    impl Scope {
        pub(crate) fn new(observer: Observer) -> Self {
            Self {
                prior: OBSERVER.with(|slot| slot.replace(Some(observer))),
                thread: std::thread::current().id(),
                _same_thread: std::marker::PhantomData,
            }
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            assert_eq!(self.thread, std::thread::current().id());
            OBSERVER.with(|slot| slot.replace(self.prior.take()));
        }
    }
    pub(crate) fn observe(site: Site, boundary: Boundary) {
        let observer = OBSERVER.with(|slot| slot.borrow().clone());
        if let Some(observer) = observer {
            observer(site, boundary);
        }
    }
}
use crate::memory::UserMemory;
use crate::vm::CompletedSyscallBoundary;
use crate::vm::PageZeroFault;
use crate::vm::ProcessActionContinuation;
use crate::vm::ProcessActionOutcome;

const STACK_CAPACITY: usize = TOOL_STACK_SIZE as usize;

#[cfg(any(test, feature = "native-test-support"))]
pub mod native_test_support;

enum HandlerSignal {
    ParkedFatal(reverie::PreparedSignalToken),
    ParkedCancelled(reverie::ParkedSignalFailureContext),
    ParkedRetired(reverie::ParkedSignalFailureContext),
    ThreadCancelled,
    GroupExit(ExitStatus),
    ThreadRetired,
    TailInjected {
        result: std::result::Result<i64, Errno>,
        image_replaced: bool,
        process_exited: bool,
    },
    RuntimeError(Error),
}

type SharedHandlerSignal = Arc<Mutex<Option<HandlerSignal>>>;
pub(crate) type SharedChildStarts = Arc<Mutex<Vec<PendingChildStart>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingChildKind {
    ForkProcess(i32),
    ToolThread(i32),
}

pub(crate) enum PendingChildCancellation {
    NewlyCancelled {
        child: PendingChildKind,
        delivery_failed: bool,
    },
    AlreadyStarted,
    AlreadyCancelled,
}

pub(crate) struct PendingChildStart {
    child: PendingChildKind,
    start: ChildStartGate,
}

impl PendingChildStart {
    pub(crate) fn fork_process(pid: i32, start: ChildStartGate) -> Self {
        Self {
            child: PendingChildKind::ForkProcess(pid),
            start,
        }
    }

    pub(crate) fn tool_thread(tid: i32, start: ChildStartGate) -> Self {
        Self {
            child: PendingChildKind::ToolThread(tid),
            start,
        }
    }

    fn start(&self) -> std::result::Result<(), std::sync::mpsc::SendError<()>> {
        self.start.start().map(|_| ())
    }

    fn is_pending(&self) -> bool {
        self.start.is_pending()
    }

    pub(crate) fn tool_thread_gate(&self) -> Option<(i32, &ChildStartGate)> {
        match self.child {
            PendingChildKind::ToolThread(tid) => Some((tid, &self.start)),
            PendingChildKind::ForkProcess(_) => None,
        }
    }

    pub(crate) fn cancel(self) -> PendingChildCancellation {
        self.cancel_with_reason(false)
    }

    pub(crate) fn cancel_after_failure(self) -> PendingChildCancellation {
        self.cancel_with_reason(true)
    }

    fn cancel_with_reason(self, failed: bool) -> PendingChildCancellation {
        let cancelled = if failed {
            self.start.cancel_after_failure()
        } else {
            self.start.cancel()
        };
        match cancelled {
            ChildStartCancellation::NewlyCancelled { delivery_failed } => {
                PendingChildCancellation::NewlyCancelled {
                    child: self.child,
                    delivery_failed,
                }
            }
            ChildStartCancellation::AlreadyStarted => PendingChildCancellation::AlreadyStarted,
            ChildStartCancellation::AlreadyCancelled => PendingChildCancellation::AlreadyCancelled,
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED: Keep root syscalls that share worker state in one backend.
// TODO-HUMAN-REVIEW(PR-173): Review KVM root syscall ownership.
pub(crate) fn is_backend_owned_syscall(number: u64, thread_ownership: ThreadOwnership) -> bool {
    // `futex` ownership follows the thread's `ThreadOwnership`, so it can never
    // disagree with how that thread executes:
    //
    // * `ThreadOwnership::Tool`: every thread — root and worker alike — is
    //   registered in the Tool's (Detcore's) scheduler. `futex` must therefore
    //   route to the Tool so that a join's `FUTEX_WAIT` becomes a logical
    //   scheduler wait woken by the exiting worker's logical `CLONE_CHILD_CLEARTID`
    //   wake. Executing it as a real host futex here deadlocks: the exiting
    //   worker's wake is only simulated inside Detcore and never reaches a real
    //   host futex word, so the waiter sleeps forever.
    // * `ThreadOwnership::Host`: workers run uninstrumented outside the Tool's
    //   scheduler, so the root's futex must use the same host-backed words as
    //   those siblings and stays backend-owned.
    if number == libc::SYS_futex as u64 {
        return thread_ownership.futex_is_host_owned();
    }
    // QEMU's root event loop waits on worker eventfds. KVM syscall
    // injection cannot perform ppoll, so use translated host descriptors in
    // either ownership mode.
    if number == libc::SYS_ppoll as u64 {
        return true;
    }

    // Host-owned workers execute outside the Tool and can create descriptors
    // that the root event loop consumes. Their scalar and vectored reads must
    // therefore use the backend's shared descriptor table. Tool-owned workers,
    // however, are registered with the Tool's scheduler, so their reads must
    // reach Tool::handle_syscall_event. In particular, Detcore makes internal
    // pipes physically nonblocking while keeping them logically blocking; if
    // the backend consumes those reads itself, the implementation-only EAGAIN
    // leaks to the guest instead of entering Detcore's polling retry path.
    thread_ownership.executes_on_host()
        && (number == libc::SYS_read as u64 || number == libc::SYS_readv as u64)
}

/// Executes a syscall on behalf of a KVM guest.
///
/// A full KVM backend will delegate this operation to its guest kernel. The
/// current bare-guest prototype accepts an executor explicitly so that Reverie
/// tools can use `Guest::inject` and `Guest::tail_inject` with the same contract
/// as the ptrace backend.
pub trait SyscallExecutor: Send + Sync {
    /// Executes `request` and returns its raw Linux syscall result.
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64;
}

impl<F> SyscallExecutor for F
where
    F: FnMut(&SyscallRequest, &GuestMemory) -> i64 + Send + Sync,
{
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        self(request, memory)
    }
}

enum InjectionCompletion {
    ThreadCancelled,
    Returns {
        syscall_result: Option<i64>,
    },
    DoesNotReturn {
        image_replaced: bool,
        process_exited: bool,
    },
}

// TODO-HUMAN-REVIEW(PR-192): Review awaitable KVM injection Tool context.
pub(crate) struct ToolContext<'a, T: Tool> {
    /// The process (thread-group) identity of the thread issuing the action.
    pub(crate) pid: Pid,
    /// The thread identity of the thread issuing the action. Equals `pid` for a
    /// process leader; differs for a CLONE_THREAD worker.
    pub(crate) tid: Pid,
    /// Process Tool state shared by every CLONE_THREAD worker.
    pub(crate) process_state: Arc<T>,
    pub(crate) thread_state: &'a T::ThreadState,
    // TODO-HUMAN-REVIEW(PR-235): Review shared GlobalTool ownership across KVM forks.
    pub(crate) global_state: Option<Arc<T::GlobalState>>,
    pub(crate) config: <T::GlobalState as GlobalTool>::Config,
    pub(crate) subscriptions: Subscription,
    // TODO-HUMAN-REVIEW(PR-235): Review child release on parent handler suspension.
    pub(crate) pending_child_starts: SharedChildStarts,
}

// TODO-HUMAN-REVIEW(PR-192): Review async KVM process-action completion.
trait GuestSyscallExecutor<T: Tool>: Send + Sync {
    fn read_clock(&self) -> Result<u64>;

    fn has_cpuid_interception(&self) -> bool {
        false
    }

    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> Result<i64>;

    /// Reserve backend bookkeeping before executing an injected syscall.
    /// Refusal is terminal backend failure, never an emulated syscall errno.
    fn prepare_signal_effects(&mut self) -> std::result::Result<(), Errno> {
        Ok(())
    }

    fn failure_subscription(&self) -> Option<crate::failure::FailureSubscription> {
        None
    }

    fn defer_signal_delivery(&mut self, _event: SignalEvent) -> std::result::Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn queue_child_exit_signal(&mut self, _event: SignalEvent) -> reverie::ChildExitSignalOutcome {
        reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ChildExitSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }

    fn queue_process_alarm_signal(
        &mut self,
        _event: SignalEvent,
    ) -> reverie::ProcessAlarmSignalOutcome {
        reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }

    fn signal_controlled(&self) -> bool {
        false
    }
    fn finish_parked_delivery(&mut self) {}

    fn signal_task_identity(&self) -> Option<reverie::SignalTaskIdentity> {
        None
    }
    fn begin_signal_callback(&mut self) -> Option<reverie::CallbackSignalSite> {
        None
    }
    fn parked_signal_site(&self) -> Option<reverie::CallbackSignalSite> {
        None
    }
    fn invalidate_polled_read_attempt(&mut self) {}

    fn polled_read_signal_site(
        &self,
        _call: reverie::syscalls::Read,
    ) -> Option<reverie::CallbackSignalSite> {
        None
    }
    fn captured_write_signal_site(
        &self,
        _call: reverie::syscalls::Write,
    ) -> Option<reverie::CallbackSignalSite> {
        None
    }
    fn parent_death_syscall_preflight(
        &self,
        _call: reverie::syscalls::Syscall,
    ) -> std::result::Result<reverie::ParentDeathSyscallAdmission, reverie::Error> {
        Err(Errno::ENOSYS.into())
    }
    fn set_signal_guard(&mut self, _guard: SignalGuard) -> SignalGuard {
        SignalGuard::Ordinary
    }
    fn admit_signal_observation(
        &mut self,
        _site: reverie::CallbackSignalSite,
        _lease: reverie::ParkedObservationLease,
    ) -> std::result::Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn signal_failure_context_is_current(
        &self,
        _context: reverie::ParkedSignalFailureContext,
    ) -> bool {
        false
    }
    fn signal_dequeue_front(&self) -> Option<reverie::SignalDequeue> {
        None
    }
    fn poll_signal_dequeue(
        &self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<reverie::SignalDequeue>>> {
        std::task::Poll::Ready(Ok(self.signal_dequeue_front()))
    }
    fn acknowledge_signal_dequeue(
        &mut self,
        _effect: reverie::SignalDequeue,
    ) -> std::result::Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn retain_signal_dequeue(&mut self, _effect: reverie::SignalDequeue) {}
    fn retain_signal_effect_result(&mut self, _raw: Option<i64>) {}
    fn signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
        None
    }
    fn with_signal_effects(&mut self, error: Error, _raw: Option<i64>) -> Error {
        error
    }
    fn take_signal_for_observation(&mut self) -> std::result::Result<Option<PendingSignal>, Errno> {
        Err(Errno::ENOSYS)
    }
    fn filter_signal_replacement(
        &mut self,
        _event: SignalEvent,
        _domain: crate::executor::PendingSignalDomain,
    ) -> std::result::Result<Option<PendingSignal>, Errno> {
        Err(Errno::ENOSYS)
    }
    fn signal_disposition(&self, _signal: i32) -> crate::executor::SignalDisposition {
        crate::executor::SignalDisposition::Terminate
    }
    fn reserve_signal_delivery(
        &mut self,
        _pending: PendingSignal,
        _id: reverie::DequeueId,
        _fatal: bool,
    ) -> std::result::Result<reverie::PreparedSignalToken, Errno> {
        Err(Errno::ENOSYS)
    }
    fn prepared_signal_is_fatal(&self, _token: reverie::PreparedSignalToken) -> bool {
        false
    }

    fn ordinary_injection_allowed(&self, _request: &SyscallRequest) -> bool {
        true
    }

    fn tail_injection_allowed(&self, _request: &SyscallRequest) -> bool {
        true
    }

    // TODO-HUMAN-REVIEW(PR-235): Review virtual process ancestry exposed to Tool handlers.
    fn parent_pid(&self) -> Option<Pid> {
        None
    }

    /// The brk-managed heap region `[heap_base, program_break)` of the guest,
    /// when this executor backs a loaded static ELF. `None` for executors that
    /// do not model a heap (e.g. the direct pass-through executor). Used to
    /// report the guest heap region for deterministic memory-map logging.
    fn heap_region(&self) -> Option<(u64, u64)> {
        None
    }

    fn complete_injection<'a>(
        &'a mut self,
        _context: ToolContext<'a, T>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        T: 'a,
    {
        Box::pin(async {
            Ok(InjectionCompletion::Returns {
                syscall_result: None,
            })
        })
    }
}

struct DirectSyscallExecutor<'a> {
    executor: &'a mut dyn SyscallExecutor,
    vcpu: &'a crate::clock::CountedVcpu,
}

impl<T: Tool> GuestSyscallExecutor<T> for DirectSyscallExecutor<'_> {
    fn read_clock(&self) -> Result<u64> {
        self.vcpu.read_clock()
    }

    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> Result<i64> {
        Ok(self.executor.execute(request, memory))
    }
}

#[derive(Clone)]
enum ProcessExecutionContext {
    InitialExec(SyscallRequest),
    InitialExecCompleted,
    Lifecycle,
    Instruction,
    ThreadEntrySignal,
    SignalBoundary(CompletedSyscallBoundary),
    FaultBoundary(Box<PageZeroFault>),
    SyscallBoundary(CompletedSyscallBoundary),
}

impl ProcessExecutionContext {
    fn has_resumable_signal_boundary(&self) -> bool {
        // These contexts carry an exact user continuation for a signal frame.
        // Lifecycle and initial-exec callbacks have no such transport.
        matches!(
            self,
            Self::SignalBoundary(_)
                | Self::FaultBoundary(_)
                | Self::SyscallBoundary(_)
                | Self::ThreadEntrySignal
        )
    }

    fn tail_injection_allowed(&self, request: &SyscallRequest) -> bool {
        if matches!(self, Self::Instruction) {
            // Terminal exits do not need a syscall return frame. Every other
            // tail still requires a transport that can consume its result.
            return injection_is_explicit_exit(request);
        }
        !matches!(
            self,
            Self::SignalBoundary(_) | Self::FaultBoundary(_) | Self::ThreadEntrySignal
        )
    }

    fn ordinary_injection_allowed(&self, request: &SyscallRequest) -> bool {
        if matches!(self, Self::Instruction) && injection_is_explicit_exit(request) {
            // inject() itself is nonreturning once the real exit is staged;
            // tail_inject() uses that same path and both executor preflights.
            return true;
        }
        if matches!(self, Self::ThreadEntrySignal | Self::Instruction) {
            // There is a real user continuation, but no consumed syscall
            // transport to restore after an injected process action.
            return !injection_can_be_nonreturning(request)
                && !matches!(
                    request.number() as libc::c_long,
                    libc::SYS_fork | libc::SYS_vfork | libc::SYS_clone | libc::SYS_clone3
                );
        }
        !matches!(self, Self::SignalBoundary(_) | Self::FaultBoundary(_))
            || !injection_can_be_nonreturning(request)
    }

    fn injected_signal_allowed(&self, request: &SyscallRequest) -> bool {
        !signal_request_requires_return_frame(request)
            || matches!(
                self,
                Self::SignalBoundary(_)
                    | Self::SyscallBoundary(_)
                    | Self::FaultBoundary(_)
                    | Self::ThreadEntrySignal
            )
    }
}

fn injection_is_explicit_exit(request: &SyscallRequest) -> bool {
    matches!(
        request.number() as libc::c_long,
        libc::SYS_exit | libc::SYS_exit_group
    )
}

/// Returns whether a successful injected syscall can abandon the current Tool
/// handler instead of producing an ordinary scalar result.
fn injection_can_be_nonreturning(request: &SyscallRequest) -> bool {
    match request.number() {
        number
            if number == libc::SYS_execve as u64
                || number == libc::SYS_execveat as u64
                || number == libc::SYS_exit as u64
                || number == libc::SYS_exit_group as u64 =>
        {
            true
        }
        number if number == libc::SYS_kill as u64 || number == libc::SYS_tkill as u64 => {
            request.args()[1] == libc::SIGKILL as u64
        }
        number if number == libc::SYS_tgkill as u64 => request.args()[2] == libc::SIGKILL as u64,
        _ => false,
    }
}

/// Returns whether an injected request is the already-installed initial exec.
///
/// Tools may forward the synthetic `execve` unchanged, or use Reverie's
/// canonical `From<Execve> for Execveat` conversion. Only those two exact
/// requests are equivalent: accepting any other `execveat` would suppress a
/// real image replacement requested by the tool.
fn matches_initial_exec(expected: &SyscallRequest, request: &SyscallRequest) -> bool {
    if expected.number() != libc::SYS_execve as u64 || expected.args()[3..] != [0, 0, 0] {
        return false;
    }
    if expected == request {
        return true;
    }

    let [path, argv, envp, _, _, _] = *expected.args();
    request.number() == libc::SYS_execveat as u64
        && *request.args() == [libc::AT_FDCWD as u64, path, argv, envp, 0, 0]
}

fn signal_request_requires_return_frame(request: &SyscallRequest) -> bool {
    let signal = match request.number() {
        number if number == libc::SYS_kill as u64 || number == libc::SYS_tkill as u64 => {
            request.args()[1]
        }
        number if number == libc::SYS_tgkill as u64 => request.args()[2],
        _ => 0,
    };
    // Signal zero is an existence/permission probe and cannot create pending
    // delivery, so it is safe in lifecycle callbacks without a return frame.
    signal != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalGuard {
    Ordinary,
    Observation,
    DequeueNotification,
}

struct StaticElfSyscallExecutor<'a> {
    backend: &'a mut KvmBackend,
    executor: &'a mut ElfExecutor,
    memory: GuestMemory,
    process_context: ProcessExecutionContext,
    last_result: Option<i64>,
    // Exact request/result pair for zero-effect original-read observation.
    // Invalidated by every attempted injected execution, including refusals.
    polled_read_attempt: Option<(SyscallRequest, i64)>,
    process_completed: &'a mut bool,
    callback_site: Option<reverie::CallbackSignalSite>,
    original_syscall: Option<SyscallRequest>,
    signal_guard: SignalGuard,
}

impl Drop for StaticElfSyscallExecutor<'_> {
    fn drop(&mut self) {
        if matches!(
            self.process_context,
            ProcessExecutionContext::SyscallBoundary(_)
        ) && self.original_syscall.is_some_and(|request| {
            matches!(
                request.number() as libc::c_long,
                libc::SYS_execve | libc::SYS_execveat
            )
        }) && let Some(site) = self.callback_site
        {
            self.executor.retire_parent_death_exec(site);
        }
    }
}

impl<T> GuestSyscallExecutor<T> for StaticElfSyscallExecutor<'_>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    fn read_clock(&self) -> Result<u64> {
        self.backend.vcpu.read_clock()
    }

    fn has_cpuid_interception(&self) -> bool {
        self.backend.has_cpuid_interception()
    }

    fn failure_subscription(&self) -> Option<crate::failure::FailureSubscription> {
        self.backend
            .tool_failure
            .as_ref()
            .map(|failure| failure.run.subscribe())
    }

    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> Result<i64> {
        self.polled_read_attempt = None;
        if !self.signal_injection_allowed(request) {
            // KvmGuest performs the same check before dispatch. Keep the
            // production executor fail-closed as well: a future Guest caller
            // must not execute an irreversible transition and only then learn
            // that SignalBoundary cannot resume its Tool hook.
            return Ok(-(i64::from(Errno::ENOSYS.into_raw())));
        }
        if matches!(
            self.process_context,
            ProcessExecutionContext::Lifecycle | ProcessExecutionContext::Instruction
        ) && let Some(result) = self
            .executor
            .lifecycle_signal_mask_preflight(request, memory)
        {
            return Ok(result);
        }
        if !self.process_context.injected_signal_allowed(request) {
            // A successful injected self-signal would become pending, but a
            // lifecycle callback has no transported userspace context in which
            // to run the structured hook or build a signal frame. Refuse before
            // mutating pending state instead of delaying it to another syscall.
            return Ok(-(i64::from(Errno::ENOSYS.into_raw())));
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-233): Review synthetic initial exec completion.
        if matches!(
            &self.process_context,
            ProcessExecutionContext::InitialExec(expected)
                if matches_initial_exec(expected, request)
        ) {
            if self.executor.parent_death_enrolled() {
                return Err(crate::Error::ParentDeathSignal {
                    operation: "enrolled synthetic initial exec has no original image authority",
                    errno: libc::ENOSYS,
                });
            }
            self.last_result = Some(0);
            self.process_context = ProcessExecutionContext::InitialExecCompleted;
            return Ok(0);
        }
        let result = self
            .backend
            .execute_static_elf_syscall(self.executor, request, memory)?;
        self.last_result = Some(result);
        self.polled_read_attempt = Some((*request, result));
        Ok(result)
    }

    fn prepare_signal_effects(&mut self) -> std::result::Result<(), Errno> {
        self.executor.reserve_signal_effects(64)
    }

    fn defer_signal_delivery(&mut self, event: SignalEvent) -> std::result::Result<(), Errno> {
        if self.signal_guard == SignalGuard::DequeueNotification {
            return Err(Errno::ENOSYS);
        }
        if self.process_context.has_resumable_signal_boundary() {
            self.executor.defer_signal_delivery(event)
        } else {
            Err(Errno::ENOSYS)
        }
    }

    fn queue_child_exit_signal(&mut self, event: SignalEvent) -> reverie::ChildExitSignalOutcome {
        if self.signal_guard == SignalGuard::DequeueNotification {
            return reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
                kind: reverie::ChildExitSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        if self.process_context.has_resumable_signal_boundary() {
            self.executor.queue_child_exit_signal(event)
        } else {
            reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
                kind: reverie::ChildExitSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            }
        }
    }

    fn queue_process_alarm_signal(
        &mut self,
        event: SignalEvent,
    ) -> reverie::ProcessAlarmSignalOutcome {
        if self.signal_guard == SignalGuard::DequeueNotification {
            return reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
                kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        // Opted-in timer Tools require the exact original boundary and ledger.
        // Preserve the existing primitive contexts for unopted Tools.
        if self.executor.signal_dequeues_enabled() && self.current_parked_site().is_none() {
            return reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
                kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        // Process actions may consume and restore this transport. This bounded
        // primitive requires the callback's original, unconsumed boundary.
        if *self.process_completed {
            return reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
                kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        if self.process_context.has_resumable_signal_boundary() {
            if let Some(site) = self.current_parked_site()
                && let Err(errno) = self.executor.retain_parked_effects(site)
            {
                return reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
                    kind: reverie::ProcessAlarmSignalErrorKind::Backend,
                    errno,
                };
            }
            let outcome = self.executor.queue_process_alarm_signal(event);
            self.executor.retain_signal_publication(outcome);
            outcome
        } else {
            reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
                kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            }
        }
    }

    fn signal_controlled(&self) -> bool {
        self.executor.signal_controlled()
    }
    fn finish_parked_delivery(&mut self) {
        self.executor.finish_parked_delivery();
    }

    fn signal_task_identity(&self) -> Option<reverie::SignalTaskIdentity> {
        self.executor.signal_task_identity()
    }
    fn begin_signal_callback(&mut self) -> Option<reverie::CallbackSignalSite> {
        // Only the driver's dequeue/structured-signal reborrows supply a site.
        // They consume the same operation's ledger, rather than beginning a
        // new guest callback. Every other constructor (including post-exec)
        // supplies None and keeps the fresh-nonce invalidation fence.
        let continuation = !matches!(
            self.process_context,
            ProcessExecutionContext::SyscallBoundary(_)
        ) && self.callback_site.is_some_and(|site| {
            self.executor
                .signal_failure_context()
                .is_some_and(|context| {
                    context.site == site && self.executor.signal_failure_context_is_current(context)
                })
        });
        if !continuation {
            self.callback_site = self.executor.begin_signal_callback();
        }
        // A continuation does not acquire original-syscall parked admission.
        self.current_parked_site()
    }
    fn parked_signal_site(&self) -> Option<reverie::CallbackSignalSite> {
        self.current_parked_site()
    }
    fn invalidate_polled_read_attempt(&mut self) {
        self.polled_read_attempt = None;
    }

    fn polled_read_signal_site(
        &self,
        call: reverie::syscalls::Read,
    ) -> Option<reverie::CallbackSignalSite> {
        let request = SyscallRequest::from_syscall(call);
        if self.signal_guard != SignalGuard::Ordinary
            || self.original_syscall != Some(request)
            || !matches!(self.polled_read_attempt, Some((actual, result))
                if actual == request && result == -(i64::from(Errno::EAGAIN.into_raw())))
        {
            return None;
        }
        self.current_parked_site()
    }
    fn captured_write_signal_site(
        &self,
        call: reverie::syscalls::Write,
    ) -> Option<reverie::CallbackSignalSite> {
        let request = SyscallRequest::from_syscall(call);
        if self.signal_guard != SignalGuard::Ordinary
            || self.last_result.is_some()
            || self.original_syscall != Some(request)
        {
            return None;
        }
        let site = self.current_parked_site()?;
        // Descriptor lookup uses Linux's low 32 bits only after exact raw-call
        // equality above; distinct upper argument bits do not share admission.
        let fd = request.args()[0] as libc::c_int;
        self.executor.captured_write_site(site, fd)
    }
    fn parent_death_syscall_preflight(
        &self,
        call: reverie::syscalls::Syscall,
    ) -> std::result::Result<reverie::ParentDeathSyscallAdmission, reverie::Error> {
        let refuse = || {
            reverie::Error::Tool(
                Error::ParentDeathSignal {
                    operation: "original-call preflight outside active callback",
                    errno: libc::ENOSYS,
                }
                .into(),
            )
        };
        if self.signal_guard != SignalGuard::Ordinary
            || self.last_result.is_some()
            || *self.process_completed
            || self.executor.has_prepared_signal()
        {
            return Err(refuse());
        }
        let site = self.callback_site.ok_or_else(refuse)?;
        let original = matches!(
            self.process_context,
            ProcessExecutionContext::SyscallBoundary(_)
        )
        .then_some(self.original_syscall)
        .flatten();
        self.executor
            .parent_death_original_syscall_preflight(
                site,
                &SyscallRequest::from_syscall(call),
                original,
                self.current_parked_site() == Some(site),
            )
            .map_err(|error| reverie::Error::Tool(error.into()))
    }
    fn set_signal_guard(&mut self, guard: SignalGuard) -> SignalGuard {
        std::mem::replace(&mut self.signal_guard, guard)
    }
    fn admit_signal_observation(
        &mut self,
        site: reverie::CallbackSignalSite,
        lease: reverie::ParkedObservationLease,
    ) -> std::result::Result<(), Errno> {
        self.executor.admit_signal_observation(site, lease)
    }
    fn signal_failure_context_is_current(
        &self,
        context: reverie::ParkedSignalFailureContext,
    ) -> bool {
        self.callback_site == Some(context.site)
            && !*self.process_completed
            && self.executor.signal_failure_context_is_current(context)
    }
    fn signal_dequeue_front(&self) -> Option<reverie::SignalDequeue> {
        self.executor.signal_dequeue_front()
    }
    fn poll_signal_dequeue(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<reverie::SignalDequeue>>> {
        self.executor.poll_signal_dequeue(cx)
    }
    fn retain_signal_dequeue(&mut self, effect: reverie::SignalDequeue) {
        self.executor.retain_signal_dequeue(effect);
    }
    fn retain_signal_effect_result(&mut self, raw: Option<i64>) {
        self.executor.retain_signal_effect_result(raw);
    }
    fn acknowledge_signal_dequeue(
        &mut self,
        effect: reverie::SignalDequeue,
    ) -> std::result::Result<(), Errno> {
        self.executor.acknowledge_signal_dequeue(effect)?;
        self.executor
            .mark_signal_dequeue_acknowledged(effect.sequence);
        Ok(())
    }
    fn signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
        self.executor.signal_failure_context()
    }
    fn with_signal_effects(&mut self, error: Error, raw: Option<i64>) -> Error {
        self.executor.with_signal_effects(error, raw)
    }
    fn take_signal_for_observation(&mut self) -> std::result::Result<Option<PendingSignal>, Errno> {
        self.executor.reserve_signal_effects(1)?;
        self.executor.take_pending_signal_for_delivery()
    }
    fn filter_signal_replacement(
        &mut self,
        event: SignalEvent,
        domain: crate::executor::PendingSignalDomain,
    ) -> std::result::Result<Option<PendingSignal>, Errno> {
        self.executor
            .prepare_filtered_signal_delivery(event, domain)
    }
    fn signal_disposition(&self, signal: i32) -> crate::executor::SignalDisposition {
        self.executor.signal_disposition(signal)
    }
    fn reserve_signal_delivery(
        &mut self,
        pending: PendingSignal,
        id: reverie::DequeueId,
        fatal: bool,
    ) -> std::result::Result<reverie::PreparedSignalToken, Errno> {
        self.executor.reserve_signal_delivery(pending, id, fatal)
    }
    fn prepared_signal_is_fatal(&self, token: reverie::PreparedSignalToken) -> bool {
        self.callback_site == Some(token.site)
            && !*self.process_completed
            && self.executor.prepared_signal_is_fatal(token)
    }

    fn ordinary_injection_allowed(&self, request: &SyscallRequest) -> bool {
        self.signal_injection_allowed(request)
    }

    fn tail_injection_allowed(&self, request: &SyscallRequest) -> bool {
        self.signal_guard == SignalGuard::Ordinary
            && !self.executor.has_prepared_signal()
            && self.process_context.tail_injection_allowed(request)
    }

    fn parent_pid(&self) -> Option<Pid> {
        self.executor.parent_pid()
    }

    fn heap_region(&self) -> Option<(u64, u64)> {
        Some(self.executor.heap_region())
    }

    fn complete_injection<'a>(
        &'a mut self,
        context: ToolContext<'a, T>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        T: 'a,
    {
        Box::pin(async move {
            if matches!(
                self.process_context,
                ProcessExecutionContext::InitialExecCompleted
            ) {
                *self.process_completed = true;
                return Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced: true,
                    process_exited: false,
                });
            }
            let Some(action) = self.executor.take_process_action() else {
                return Ok(if self.executor.has_pending_exit() {
                    InjectionCompletion::DoesNotReturn {
                        image_replaced: false,
                        process_exited: true,
                    }
                } else {
                    InjectionCompletion::Returns {
                        syscall_result: None,
                    }
                });
            };
            if !action.returns_to_original_image() && self.executor.has_eligible_pending_signal() {
                return Err(Error::UnexpectedVcpuExit(
                    "KVM Tool exec with an eligible deferred signal is unsupported; \
                     delivery requires a syscall return frame"
                        .to_owned(),
                ));
            }
            hide_tool_scratch(&self.memory, self.backend.tool_stack_top())?;
            let action_result: Result<ProcessActionOutcome> = async {
                match self.process_context.clone() {
                    ProcessExecutionContext::FaultBoundary(fault) => {
                        self.backend
                            .run_process_action_with_tool_from_fault(
                                self.executor,
                                action,
                                context,
                                &fault,
                            )
                            .await
                    }
                    ProcessExecutionContext::SignalBoundary(boundary)
                    | ProcessExecutionContext::SyscallBoundary(boundary) => {
                        let result = self
                            .last_result
                            .expect("process action must have an injected syscall result");
                        boundary.stage_action_result(self.backend, result)?;
                        let continuation =
                            ProcessActionContinuation::from_captured(&action, boundary);
                        self.backend
                            .run_injected_process_action_with_tool_at_boundary(
                                self.executor,
                                action,
                                context,
                                continuation,
                            )
                            .await
                    }
                    ProcessExecutionContext::InitialExec(_)
                    | ProcessExecutionContext::Lifecycle => match action {
                        ProcessAction::Exec {
                            executable_path,
                            executable_file,
                            image,
                            argv,
                            envp,
                        } => {
                            self.backend.exec_process(
                                self.executor,
                                (&executable_path, executable_file),
                                &image,
                                &argv,
                                &envp,
                            )?;
                            Ok(ProcessActionOutcome::replaced())
                        }
                        _ => Err(Error::UnexpectedVcpuExit(
                            "fork/clone injection requires a guest syscall boundary".to_owned(),
                        )),
                    },
                    ProcessExecutionContext::InitialExecCompleted => unreachable!(
                        "synthetic initial exec completes before process actions are inspected"
                    ),
                    ProcessExecutionContext::Instruction => Err(Error::UnexpectedVcpuExit(
                        "process injection from an instruction callback is unsupported".to_owned(),
                    )),
                    ProcessExecutionContext::ThreadEntrySignal => Err(Error::UnexpectedVcpuExit(
                        "process injection from a thread-entry signal hook is unsupported"
                            .to_owned(),
                    )),
                }
            }
            .await;
            let expose_result = expose_tool_scratch(&self.memory, self.backend.tool_stack_top());
            let outcome = action_result?;
            expose_result?;
            if outcome.cancelled {
                return Ok(InjectionCompletion::ThreadCancelled);
            }
            *self.process_completed = true;
            if outcome.image_replaced || self.executor.has_pending_exit() {
                Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced: outcome.image_replaced,
                    process_exited: self.executor.has_pending_exit(),
                })
            } else {
                Ok(InjectionCompletion::Returns {
                    syscall_result: Some(outcome.syscall_result),
                })
            }
        })
    }
}

include!("parked_signal_runtime.rs");

struct KvmGlobal<'a, G: GlobalTool> {
    // The scheduler derives the requesting DetTid from the RPC sender, so this
    // is the issuing thread's tid (equal to the pid for a process leader,
    // distinct for a CLONE_THREAD worker), not the thread-group pid.
    tid: Pid,
    state: &'a G,
    config: &'a G::Config,
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for KvmGlobal<'_, G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        self.state.receive_rpc(self.tid, message).await
    }

    fn config(&self) -> &G::Config {
        self.config
    }
}

struct KvmGuest<'a, T: Tool> {
    pid: Pid,
    tid: Pid,
    process_state: Arc<T>,
    memory: GuestMemory,
    auxv: &'a [(libc::c_ulong, libc::c_ulong)],
    registers: libc::user_regs_struct,
    thread_state: &'a mut T::ThreadState,
    executor: &'a mut dyn GuestSyscallExecutor<T>,
    global_state: &'a T::GlobalState,
    shared_global_state: Option<Arc<T::GlobalState>>,
    config: &'a <T::GlobalState as GlobalTool>::Config,
    subscriptions: &'a Subscription,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    tool_stack_top: u64,
    stack_checked_out: Arc<AtomicBool>,
    observation_lease: Option<reverie::ParkedObservationLease>,
    notifying_dequeue: bool,
    entry_watch: crate::entry::driver::EntryDriverWatch,
}

impl<'a, T: Tool> KvmGuest<'a, T> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        pid: Pid,
        tid: Pid,
        process_state: Arc<T>,
        memory: GuestMemory,
        auxv: &'a [(libc::c_ulong, libc::c_ulong)],
        registers: libc::user_regs_struct,
        thread_state: &'a mut T::ThreadState,
        executor: &'a mut dyn GuestSyscallExecutor<T>,
        global_state: &'a T::GlobalState,
        shared_global_state: Option<Arc<T::GlobalState>>,
        config: &'a <T::GlobalState as GlobalTool>::Config,
        subscriptions: &'a Subscription,
        handler_signal: SharedHandlerSignal,
        pending_child_starts: SharedChildStarts,
        tool_stack_top: u64,
        stack_checked_out: Arc<AtomicBool>,
    ) -> Self {
        executor.begin_signal_callback();
        let entry_watch = crate::entry::driver::EntryDriverWatch::for_memory(&memory);
        Self {
            pid,
            tid,
            process_state,
            memory,
            auxv,
            registers,
            thread_state,
            executor,
            global_state,
            shared_global_state,
            config,
            subscriptions,
            handler_signal,
            pending_child_starts,
            tool_stack_top,
            stack_checked_out,
            observation_lease: None,
            notifying_dequeue: false,
            entry_watch,
        }
    }

    /// Preserve a previously selected nonlocal disposition. Its outer owner
    /// folds the sticky private cause after settling the selected effects.
    fn signal_ordinary_failure(&self, error: Error) {
        let mut signal = self
            .handler_signal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *signal = Some(match signal.take() {
            Some(HandlerSignal::RuntimeError(prior)) => HandlerSignal::RuntimeError(
                crate::entry::driver::combine_pending::<()>(Err(prior), Err(error)).unwrap_err(),
            ),
            Some(selected) => selected,
            None => HandlerSignal::RuntimeError(error),
        });
    }

    fn check_ordinary_operation(&self) -> Result<()> {
        self.entry_watch
            .check_operation(self.memory.entry_origin().operation.as_ref())
    }

    async fn admit_ordinary_operation(&self) {
        if let Err(error) = self.check_ordinary_operation() {
            self.signal_ordinary_failure(error);
            std::future::pending::<()>().await;
        }
    }

    /// Stop a continuation only after irreversible signal bookkeeping has
    /// been retained. The ordinary admission check does not own that ledger.
    async fn resume_ordinary_operation(&mut self, raw: Option<i64>) {
        if let Err(error) = self.check_ordinary_operation() {
            // A selected result already owns its ledger or nonlocal action.
            // Do not copy that ledger into another branch of the error tree.
            let selected = self
                .handler_signal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_some();
            let error = if selected {
                error
            } else {
                self.executor.with_signal_effects(error, raw)
            };
            self.signal_ordinary_failure(error);
            std::future::pending::<()>().await;
        }
    }

    fn signal_handler(&self, signal: HandlerSignal) {
        *self
            .handler_signal
            .lock()
            .expect("KVM handler signal lock poisoned") = Some(signal);
    }
}

#[reverie::tool]
impl<T: Tool> GlobalRPC<T::GlobalState> for KvmGuest<'_, T> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        if self.notifying_dequeue {
            return self.global_state.receive_rpc(self.tid, message).await;
        }
        // Route by the issuing thread's tid: the scheduler keys each thread's
        // turn (and global-time accounting) on the RPC sender. For a
        // CLONE_THREAD worker this is the worker tid, not the thread-group pid.
        // An independent process may finish ordinary work after a peer fails,
        // but a pending ordinary RPC can prevent its owner's physical join.
        // Signal the driver and leave this response unconstructed on failure.
        // Consuming hooks use KvmGlobal instead and must still deregister.
        self.admit_ordinary_operation().await;
        let response = {
            let mut private_failure = pin!(self.entry_watch.wait());
            let mut failure = pin!(wait_for_failure(
                self.global_state,
                self.executor.failure_subscription(),
            ));
            // Admission precedes construction: an implementation of receive_rpc
            // can perform work before returning its future.
            let mut response = pin!(self.global_state.receive_rpc(self.tid, message));
            poll_fn(|context| {
                let _ = private_failure.as_mut().poll(context);
                if let Err(error) = self.check_ordinary_operation() {
                    self.signal_ordinary_failure(error);
                    return Poll::Ready(None);
                }
                if failure.as_mut().poll(context).is_ready() {
                    self.signal_ordinary_failure(Error::RunAborted);
                    return Poll::Ready(None);
                }
                let result = response.as_mut().poll(context);
                if let Err(error) = self.check_ordinary_operation() {
                    // Retain the cause before dropping a ready response: its
                    // destructor can unwind into the existing outer catcher.
                    self.signal_ordinary_failure(error);
                    return Poll::Ready(None);
                }
                if failure.as_mut().poll(context).is_ready() {
                    self.signal_ordinary_failure(Error::RunAborted);
                    return Poll::Ready(None);
                }
                result.map(Some)
            })
            .await
        };
        match response {
            Some(response) => response,
            None => {
                // The signal already owns the cause before ordinary request
                // destruction. Repolling this losing future cannot dispatch.
                std::future::pending().await
            }
        }
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

#[reverie::tool]
impl<T: Tool> Guest<T> for KvmGuest<'_, T> {
    fn has_cpuid_interception(&self) -> bool {
        self.executor.has_cpuid_interception()
    }

    type Memory = UserMemory;
    type Stack = KvmStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        self.executor.parent_pid()
    }

    // The KVM bootstrap builds page tables and loads the image from the host;
    // no guest-resident runtime issues syscalls through the Tool.
    fn is_backend_runtime_bootstrap(&self) -> bool {
        false
    }

    fn memory(&self) -> Self::Memory {
        self.memory.user()
    }

    fn auxv(&self) -> Auxv {
        Auxv::from_entries(self.auxv.iter().copied())
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.thread_state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        self.registers
    }

    async fn defer_signal_delivery(
        &mut self,
        event: SignalEvent,
    ) -> std::result::Result<(), reverie::Error> {
        self.admit_ordinary_operation().await;
        self.executor
            .defer_signal_delivery(event)
            .map_err(Into::into)
    }

    async fn queue_child_exit_signal(
        &mut self,
        event: SignalEvent,
    ) -> reverie::ChildExitSignalOutcome {
        self.admit_ordinary_operation().await;
        self.executor.queue_child_exit_signal(event)
    }

    async fn queue_process_alarm_signal(
        &mut self,
        event: SignalEvent,
    ) -> reverie::ProcessAlarmSignalOutcome {
        self.admit_ordinary_operation().await;
        self.executor.queue_process_alarm_signal(event)
    }

    fn signal_task_identity(&self) -> Option<reverie::SignalTaskIdentity> {
        self.executor.signal_task_identity()
    }
    fn parked_signal_site(&self) -> Option<reverie::CallbackSignalSite> {
        if self.notifying_dequeue || self.stack_checked_out.load(Ordering::Acquire) {
            None
        } else {
            self.executor.parked_signal_site()
        }
    }
    fn polled_read_signal_site(
        &self,
        call: reverie::syscalls::Read,
    ) -> Option<reverie::CallbackSignalSite> {
        if self.notifying_dequeue
            || self.observation_lease.is_some()
            || self.stack_checked_out.load(Ordering::Acquire)
        {
            None
        } else {
            self.executor.polled_read_signal_site(call)
        }
    }
    fn captured_write_signal_site(
        &self,
        call: reverie::syscalls::Write,
    ) -> Option<reverie::CallbackSignalSite> {
        if self.notifying_dequeue
            || self.observation_lease.is_some()
            || self.stack_checked_out.load(Ordering::Acquire)
        {
            None
        } else {
            self.executor.captured_write_signal_site(call)
        }
    }
    fn parent_death_syscall_preflight(
        &self,
        call: reverie::syscalls::Syscall,
    ) -> std::result::Result<reverie::ParentDeathSyscallAdmission, reverie::Error> {
        if self.notifying_dequeue
            || self.observation_lease.is_some()
            || self.stack_checked_out.load(Ordering::Acquire)
        {
            return Err(reverie::Error::Tool(
                Error::ParentDeathSignal {
                    operation: "original-call preflight during foreign observation",
                    errno: libc::ENOSYS,
                }
                .into(),
            ));
        }
        self.executor.parent_death_syscall_preflight(call)
    }
    fn signal_observation_lease(&self) -> Option<reverie::ParkedObservationLease> {
        self.observation_lease
    }
    async fn observe_parked_signal(
        &mut self,
        site: reverie::CallbackSignalSite,
        lease: reverie::ParkedObservationLease,
    ) -> std::result::Result<reverie::ParkedSignalObservation, reverie::SignalObservationFailure>
    {
        self.admit_ordinary_operation().await;
        self.observe_parked_signal_impl(site, lease).await
    }
    fn parked_signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
        self.executor.signal_failure_context()
    }
    async fn terminate_from_parked_signal(
        &mut self,
        selection: reverie::PreparedSignalToken,
    ) -> std::result::Result<Never, reverie::SignalObservationFailure> {
        if !self.executor.prepared_signal_is_fatal(selection) {
            return Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                errno: Errno::EINVAL,
            });
        }
        self.signal_handler(HandlerSignal::ParkedFatal(selection));
        std::future::pending().await
    }
    async fn cancel_parked_signal(
        &mut self,
        context: reverie::ParkedSignalFailureContext,
    ) -> std::result::Result<Never, reverie::SignalObservationFailure> {
        if !self.executor.signal_failure_context_is_current(context) {
            return Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                errno: Errno::EINVAL,
            });
        }
        self.signal_handler(HandlerSignal::ParkedCancelled(context));
        std::future::pending().await
    }

    async fn stack(&mut self) -> Self::Stack {
        self.admit_ordinary_operation().await;
        KvmStack::new(
            self.memory.clone(),
            self.tool_stack_top,
            self.stack_checked_out.clone(),
        )
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> std::result::Result<i64, Errno> {
        self.admit_ordinary_operation().await;
        self.executor.invalidate_polled_read_attempt();
        let request = SyscallRequest::from_syscall(syscall);
        if !self.executor.ordinary_injection_allowed(&request) {
            return Err(Errno::ENOSYS);
        }
        if injection_can_be_nonreturning(&request)
            && self
                .pending_child_starts
                .lock()
                .expect("KVM child-start lock poisoned")
                .iter()
                .any(PendingChildStart::is_pending)
        {
            return Err(Errno::ENOSYS);
        }
        if let Err(errno) = self.executor.prepare_signal_effects() {
            let error = self
                .executor
                .with_signal_effects(Error::Reverie(errno.into()), None);
            self.signal_handler(HandlerSignal::RuntimeError(error));
            return std::future::pending().await;
        }
        self.admit_ordinary_operation().await;
        let raw = match self.executor.execute(&request, &self.memory) {
            Ok(raw) => raw,
            Err(Error::ChildWaitGroupExit { status }) => {
                // The group exit is already committed, not a request to cancel
                // an ordinary callback. Preserve its status across owned future
                // destruction and terminal signal-boundary settlement.
                self.signal_handler(HandlerSignal::GroupExit(status));
                return std::future::pending().await;
            }

            Err(Error::TerminalReadCancelled) => {
                // Reuse the existing nonreturning cancellation disposition,
                // including parked/dequeue ownership. No syscall result or
                // signal-effect wrapper may be manufactured for this read.
                match self.cancel_current_thread().await {}
            }
            Err(error) => {
                let error = self.executor.with_signal_effects(error, None);
                self.signal_handler(HandlerSignal::RuntimeError(error));
                return std::future::pending().await;
            }
        };
        if let Err(error) = self.complete_signal_effects(Some(raw)).await {
            self.signal_handler(HandlerSignal::RuntimeError(error));
            return std::future::pending().await;
        }
        self.resume_ordinary_operation(Some(raw)).await;
        let mut result = raw_to_result(raw);
        if result.is_ok() {
            let context = ToolContext {
                pid: self.pid,
                tid: self.tid,
                process_state: self.process_state.clone(),
                thread_state: self.thread_state,
                global_state: self.shared_global_state.clone(),
                config: self.config.clone(),
                subscriptions: self.subscriptions.clone(),
                pending_child_starts: self.pending_child_starts.clone(),
            };
            match self.executor.complete_injection(context).await {
                Ok(InjectionCompletion::ThreadCancelled) => {
                    self.signal_handler(HandlerSignal::ThreadCancelled);
                    return std::future::pending().await;
                }
                Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced,
                    process_exited,
                }) => {
                    // TODO-HUMAN-REVIEW(PR-156): Review non-returning exec/exit injection.
                    // Successful exec and exit injection cannot resume the old
                    // handler after their process state transition completes.
                    self.signal_handler(HandlerSignal::TailInjected {
                        result,
                        image_replaced,
                        process_exited,
                    });
                    return std::future::pending().await;
                }
                Ok(InjectionCompletion::Returns { syscall_result }) => {
                    if let Some(raw) = syscall_result {
                        result = raw_to_result(raw);
                    }
                }
                Err(error) => {
                    self.signal_handler(HandlerSignal::RuntimeError(error));
                    return std::future::pending().await;
                }
            }
        }
        self.resume_ordinary_operation(Some(match result {
            Ok(raw) => raw,
            Err(errno) => -i64::from(errno.into_raw()),
        }))
        .await;
        result
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        self.admit_ordinary_operation().await;
        self.executor.invalidate_polled_read_attempt();
        let request = SyscallRequest::from_syscall(syscall);
        if !self.executor.tail_injection_allowed(&request) {
            // Refuse before executing any syscall so write/fd/process/address-
            // space/pending/exit state cannot change before the hook errors.
            self.signal_handler(HandlerSignal::RuntimeError(Error::Reverie(
                Errno::ENOSYS.into(),
            )));
            return std::future::pending().await;
        }
        let result = self.inject(syscall).await;
        self.signal_handler(HandlerSignal::TailInjected {
            result,
            image_replaced: false,
            process_exited: false,
        });
        std::future::pending().await
    }

    async fn cancel_current_thread(&mut self) -> Never {
        if let Some(context) = self.executor.signal_failure_context() {
            self.signal_handler(HandlerSignal::ParkedCancelled(context));
            return std::future::pending().await;
        }
        if self.notifying_dequeue {
            // A consuming notification cannot turn an irreversible removal
            // into a successful thread cancellation, even outside a parked wait.
            let error = self.executor.with_signal_effects(Error::RunAborted, None);
            self.signal_handler(HandlerSignal::RuntimeError(error));
        } else {
            self.signal_handler(HandlerSignal::ThreadCancelled);
        }
        std::future::pending().await
    }

    async fn retire_current_thread(&mut self) -> Never {
        if self.notifying_dequeue {
            // A consuming notification cannot turn an irreversible removal
            // into a successful thread retirement, even outside a parked wait.
            let error = self.executor.with_signal_effects(Error::RunAborted, None);
            self.signal_handler(HandlerSignal::RuntimeError(error));
        } else if let Some(context) = self.executor.signal_failure_context() {
            self.signal_handler(HandlerSignal::ParkedRetired(context));
        } else {
            self.signal_handler(HandlerSignal::ThreadRetired);
        }
        std::future::pending().await
    }

    fn set_timer(&mut self, _schedule: TimerSchedule) -> std::result::Result<(), reverie::Error> {
        Ok(())
    }

    fn set_timer_precise(
        &mut self,
        _schedule: TimerSchedule,
    ) -> std::result::Result<(), reverie::Error> {
        Ok(())
    }

    fn read_clock(&mut self) -> std::result::Result<u64, reverie::Error> {
        if let Err(error) = self.check_ordinary_operation() {
            self.signal_ordinary_failure(error);
            return Err(Errno::EIO.into());
        }
        self.executor
            .read_clock()
            .map_err(|error| reverie::Error::Io(std::io::Error::other(error)))
    }

    fn detlog_memory_regions(&self) -> Option<Vec<DetlogMemoryRegion>> {
        // For KVM, `pid()` is the host VMM process, so the default
        // `/proc/<pid>/maps` enumeration would hash the VMM's own stack/heap at
        // host addresses that are not valid guest addresses. Report the real
        // guest-address regions instead, readable through `memory()`.
        let mut regions = Vec::new();

        // Heap: the brk-managed heap spans [heap_base, program_break), where
        // heap_base is the initial break (align_up(main_end)). `brk()` maps
        // exactly these pages as it grows, so hashing this range reads only
        // mapped guest memory. The gap below heap_base (down to
        // BOOT_RESERVED_END) is unmapped and must NOT be hashed. Skip an empty
        // heap (guest never grew its break).
        if let Some((heap_base, program_break)) = self.executor.heap_region()
            && program_break > heap_base
        {
            regions.push(DetlogMemoryRegion {
                kind: DetlogRegionKind::Heap,
                start: heap_base,
                end: program_break,
            });
        }

        // Stack: the live user stack spans [rsp, guest_end). The unused pages
        // below rsp are deterministically zeroed at setup, so hashing the live
        // region is both cheaper than the full 8 MiB mapping and deterministic
        // across the two runs of a `--verify` pair (execution is deterministic,
        // so rsp is identical at the same syscall stop).
        let guest_end = self.memory.guest_end();
        let rsp = self.registers.rsp;
        if rsp >= self.memory.guest_base() && rsp < guest_end {
            regions.push(DetlogMemoryRegion {
                kind: DetlogRegionKind::Stack,
                start: rsp,
                end: guest_end,
            });
        }

        Some(regions)
    }
}

/// A stack allocator backed by a low page reserved for Tool injection buffers.
pub struct KvmStack {
    memory: UserMemory,
    entry_watch: crate::entry::driver::EntryDriverWatch,
    operation_origin: Option<crate::entry::owner::OperationOrigin>,
    top: u64,
    stack_pointer: u64,
    capacity: usize,
    writes: Vec<(u64, Vec<u8>)>,
    checked_out: Option<Arc<AtomicBool>>,
}

impl KvmStack {
    fn new(memory: GuestMemory, top: u64, checked_out: Arc<AtomicBool>) -> Self {
        let bottom = top
            .checked_sub(TOOL_STACK_SIZE)
            .expect("KVM Tool stack address underflow");
        assert!(
            memory.guest_base() <= bottom && top <= memory.guest_end(),
            "KVM Tool stack lies outside guest memory"
        );
        assert!(
            !checked_out.swap(true, Ordering::SeqCst),
            "cannot retrieve a KVM guest stack while its previous guard is live",
        );
        Self {
            capacity: STACK_CAPACITY,
            entry_watch: crate::entry::driver::EntryDriverWatch::for_memory(&memory),
            operation_origin: memory.entry_origin().operation,
            memory: memory.user(),
            top,
            stack_pointer: top,
            writes: Vec::new(),
            checked_out: Some(checked_out),
        }
    }

    fn allocate<'stack, T>(&mut self, bytes: Vec<u8>) -> AddrMut<'stack, T> {
        let alignment = std::mem::align_of::<T>() as u64;
        let unaligned = self
            .stack_pointer
            .checked_sub(bytes.len() as u64)
            .expect("KVM guest stack address underflow");
        let address = unaligned & !(alignment - 1);
        assert!(
            self.top - address <= self.capacity as u64,
            "KVM guest stack overflow: capacity={} requested={}",
            self.capacity,
            self.top - address,
        );
        self.stack_pointer = address;
        self.writes.push((address, bytes));
        AddrMut::from_raw(address as usize)
            .expect("KVM guest stack allocation produced a null address")
    }
}

impl Drop for KvmStack {
    fn drop(&mut self) {
        if let Some(checked_out) = self.checked_out.take() {
            assert!(
                checked_out.swap(false, Ordering::SeqCst),
                "KVM stack dropped without a checked-out stack",
            );
        }
    }
}

/// Guard returned after KVM guest stack writes are committed.
pub struct KvmStackGuard {
    checked_out: Arc<AtomicBool>,
}

impl Drop for KvmStackGuard {
    fn drop(&mut self) {
        assert!(
            self.checked_out.swap(false, Ordering::SeqCst),
            "KVM stack guard dropped without a checked-out stack",
        );
    }
}

impl Stack for KvmStack {
    type StackGuard = KvmStackGuard;

    fn size(&self) -> usize {
        (self.top - self.stack_pointer) as usize
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&value).cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        }
        .to_vec();
        self.allocate(bytes).into()
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        self.allocate(vec![0; std::mem::size_of::<T>()])
    }

    fn commit(mut self) -> std::result::Result<Self::StackGuard, Errno> {
        self.entry_watch
            .check_operation(self.operation_origin.as_ref())
            .map_err(|_| Errno::EIO)?;
        for (address, bytes) in &self.writes {
            self.entry_watch
                .check_operation(self.operation_origin.as_ref())
                .map_err(|_| Errno::EIO)?;
            self.memory.write_injection(*address, bytes).map_err(|_| {
                if self
                    .entry_watch
                    .check_operation(self.operation_origin.as_ref())
                    .is_err()
                {
                    Errno::EIO
                } else {
                    Errno::EFAULT
                }
            })?;
            self.entry_watch
                .check_operation(self.operation_origin.as_ref())
                .map_err(|_| Errno::EIO)?;
        }
        Ok(KvmStackGuard {
            checked_out: self
                .checked_out
                .take()
                .expect("KVM stack commit lost its checkout"),
        })
    }
}

impl MemoryAccess for KvmStack {
    fn write_with_user_access(
        &mut self,
        addr: AddrMut<u8>,
        buf: &[u8],
    ) -> std::result::Result<usize, Errno> {
        self.memory.write_with_user_access(addr, buf)
    }

    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        self.memory.read_vectored(read_from, write_to)
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        self.memory.write_vectored(read_from, write_to)
    }
}

enum HandlerOutcome<T> {
    ParkedFatal(reverie::PreparedSignalToken),
    ParkedCancelled(reverie::ParkedSignalFailureContext),
    ParkedRetired(reverie::ParkedSignalFailureContext),
    Returned(T),
    RunFailed,
    ThreadCancelled,
    GroupExit(ExitStatus),
    ThreadRetired,
    TailInjected {
        result: std::result::Result<i64, Errno>,
        image_replaced: bool,
        process_exited: bool,
    },
    RuntimeError(Error),
}

/// Map only a completed callback value, after the actual Tool future has been
/// polled and destroyed by the driver. Nonlocal outcomes and payloads stay owned.
fn map_handler_completion<T, U>(
    completion: crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>>,
    map: impl FnOnce(T) -> U,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<U>> {
    use crate::failure::owned_future::CaughtFuture;
    let output = completion.output.map(|outcome| match outcome {
        HandlerOutcome::Returned(value) => HandlerOutcome::Returned(map(value)),
        HandlerOutcome::ParkedFatal(value) => HandlerOutcome::ParkedFatal(value),
        HandlerOutcome::ParkedCancelled(value) => HandlerOutcome::ParkedCancelled(value),
        HandlerOutcome::ParkedRetired(value) => HandlerOutcome::ParkedRetired(value),
        HandlerOutcome::RunFailed => HandlerOutcome::RunFailed,
        HandlerOutcome::ThreadCancelled => HandlerOutcome::ThreadCancelled,
        HandlerOutcome::GroupExit(status) => HandlerOutcome::GroupExit(status),
        HandlerOutcome::ThreadRetired => HandlerOutcome::ThreadRetired,
        HandlerOutcome::TailInjected {
            result,
            image_replaced,
            process_exited,
        } => HandlerOutcome::TailInjected {
            result,
            image_replaced,
            process_exited,
        },
        HandlerOutcome::RuntimeError(error) => HandlerOutcome::RuntimeError(error),
    });
    CaughtFuture {
        output,
        panics: completion.panics,
    }
}

/// Scratch teardown follows destruction of the callback. An injected action
/// error has not yet been published, so keep it ahead of any teardown error.
fn finish_handler_scratch<T>(
    outcome: HandlerOutcome<T>,
    hidden: Result<()>,
) -> Result<HandlerOutcome<T>> {
    match outcome {
        HandlerOutcome::RuntimeError(error) => Ok(HandlerOutcome::RuntimeError(
            error.with_cleanup(hidden.err().into_iter().collect()),
        )),
        outcome => hidden.map(|()| outcome),
    }
}

#[cfg(test)]
mod handler_scratch_tests {
    use super::*;

    #[test]
    fn injected_error_survives_scratch_failure_after_callback_destruction() {
        struct CallbackGuard(Arc<AtomicBool>);
        impl Drop for CallbackGuard {
            fn drop(&mut self) {
                assert!(!self.0.swap(true, Ordering::SeqCst));
            }
        }

        for hide_fails in [false, true] {
            let destroyed = Arc::new(AtomicBool::new(false));
            let guard = CallbackGuard(destroyed.clone());
            let primary = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
                libc::EAGAIN,
            )));
            let scratch = Arc::new(Error::GuestClock("scratch cleanup".to_owned()));
            let signal = Arc::new(Mutex::new(None));
            let callback_signal = signal.clone();
            let callback_error = primary.clone();
            let outcome = futures::executor::block_on(drive_handler(
                async move {
                    let _guard = guard;
                    *callback_signal.lock().unwrap() = Some(HandlerSignal::RuntimeError(
                        Error::SharedFailure(callback_error),
                    ));
                    std::future::pending::<()>().await
                },
                signal,
                Arc::new(Mutex::new(Vec::new())),
                std::future::pending(),
            ));
            assert!(destroyed.load(Ordering::SeqCst));
            let hidden = if hide_fails {
                Err(Error::SharedFailure(scratch.clone()))
            } else {
                Ok(())
            };
            let HandlerOutcome::RuntimeError(error) =
                finish_handler_scratch(outcome, hidden).unwrap()
            else {
                panic!("injected failure was replaced");
            };
            assert!(error.retains_primary(&primary));
            if hide_fails {
                let Error::WithCleanup { cleanup, .. } = error else {
                    panic!("scratch failure was discarded");
                };
                assert_eq!(cleanup.len(), 1);
                assert!(cleanup[0].retains_primary(&scratch));
            } else {
                assert!(
                    matches!(error, Error::SharedFailure(ref error) if Arc::ptr_eq(error, &primary))
                );
            }
        }
    }

    #[test]
    fn ordinary_callback_value_requires_successful_scratch_cleanup() {
        assert!(matches!(
            finish_handler_scratch(HandlerOutcome::Returned(29), Ok(())),
            Ok(HandlerOutcome::Returned(29))
        ));
        let error = Arc::new(Error::GuestClock("scratch cleanup".to_owned()));
        let failed = finish_handler_scratch(
            HandlerOutcome::Returned(29),
            Err(Error::SharedFailure(error.clone())),
        );
        assert!(matches!(failed, Err(ref returned) if returned.retains_primary(&error)));
    }
}

/// A callback can terminate the thread without selecting a guest continuation.
enum CallbackOutcome<T> {
    Completed(T),
    ThreadCancelled,
    GroupExit(ExitStatus),
    ThreadRetired,
}

fn handler_signal_outcome<T>(signal: HandlerSignal) -> HandlerOutcome<T> {
    match signal {
        HandlerSignal::ParkedFatal(selection) => HandlerOutcome::ParkedFatal(selection),
        HandlerSignal::ParkedCancelled(context) => HandlerOutcome::ParkedCancelled(context),
        HandlerSignal::ParkedRetired(context) => HandlerOutcome::ParkedRetired(context),
        HandlerSignal::ThreadCancelled => HandlerOutcome::ThreadCancelled,
        HandlerSignal::GroupExit(status) => HandlerOutcome::GroupExit(status),
        HandlerSignal::ThreadRetired => HandlerOutcome::ThreadRetired,
        HandlerSignal::TailInjected {
            result,
            image_replaced,
            process_exited,
        } => HandlerOutcome::TailInjected {
            result,
            image_replaced,
            process_exited,
        },
        HandlerSignal::RuntimeError(error) => HandlerOutcome::RuntimeError(error),
    }
}

/// A callback constructor can record a terminal signal before returning its
/// future. Retain that outcome even if construction itself then panics.
#[cfg(test)]
async fn drive_handler_completion_from<B, F, T>(
    build: B,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    failure: impl Future<Output = ()>,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>>
where
    B: FnOnce() -> F,
    F: Future<Output = T>,
{
    drive_handler_completion_from_inner(build, handler_signal, pending_child_starts, failure, None)
        .await
}

async fn drive_entry_handler_completion_from<B, F, T>(
    build: B,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    failure: impl Future<Output = ()>,
    watch: crate::entry::driver::EntryDriverWatch,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>>
where
    B: FnOnce() -> F,
    F: Future<Output = T>,
{
    drive_handler_completion_from_inner(
        build,
        handler_signal,
        pending_child_starts,
        failure,
        Some(watch),
    )
    .await
}

async fn drive_handler_completion_from_inner<B, F, T>(
    build: B,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    failure: impl Future<Output = ()>,
    watch: Option<crate::entry::driver::EntryDriverWatch>,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>>
where
    B: FnOnce() -> F,
    F: Future<Output = T>,
{
    use std::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use crate::failure::owned_future::CaughtFuture;

    if let Some(error) = watch.as_ref().and_then(|watch| watch.check().err()) {
        // The factory itself can own user values with destructors. Keep the
        // pending typed cause outside their separate destruction catch.
        let mut completion = CaughtFuture {
            output: Some(HandlerOutcome::RuntimeError(error)),
            panics: Vec::new(),
        };
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(build))) {
            completion.panics.push(payload);
        }
        if let Some(signal) = handler_signal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            completion.output = Some(match signal {
                HandlerSignal::RuntimeError(error) => HandlerOutcome::RuntimeError(
                    crate::entry::driver::combine_pending::<()>(
                        Err(error),
                        watch.as_ref().unwrap().check(),
                    )
                    .unwrap_err(),
                ),
                signal => handler_signal_outcome(signal),
            });
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(failure))) {
            completion.panics.push(payload);
        }
        return completion;
    }

    match catch_unwind(AssertUnwindSafe(build)) {
        Ok(future) => {
            drive_handler_completion_inner(
                future,
                handler_signal,
                pending_child_starts,
                failure,
                watch,
                HandlerFailureOrder::BeforeCallback,
            )
            .await
        }
        Err(payload) => {
            // Construction may have moved the only error owner into this slot
            // and poisoned its lock. Recover it before another destructor can
            // unwind. No callback future was returned, and no child may start.
            let output = handler_signal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .map(handler_signal_outcome);
            let mut completion = CaughtFuture {
                output,
                panics: vec![payload],
            };
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(failure))) {
                completion.panics.push(payload);
            }
            if let Some(error) = watch.as_ref().and_then(|watch| watch.check().err())
                && completion.output.is_none()
            {
                completion.output = Some(HandlerOutcome::RuntimeError(error));
            }
            completion
        }
    }
}

#[cfg(any(test, feature = "native-test-support"))]
async fn drive_handler_completion<T>(
    future: impl Future<Output = T>,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    failure: impl Future<Output = ()>,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>> {
    drive_handler_completion_inner(
        future,
        handler_signal,
        pending_child_starts,
        failure,
        None,
        HandlerFailureOrder::BeforeCallback,
    )
    .await
}

enum HandlerFailureOrder {
    BeforeCallback,
    // Consuming signal cleanup keeps an already-ready result after failure.
    // A pending cleanup still cancels before releasing any child-start gate.
    AfterReadyCleanup,
}

async fn drive_handler_completion_inner<T>(
    future: impl Future<Output = T>,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    failure: impl Future<Output = ()>,
    watch: Option<crate::entry::driver::EntryDriverWatch>,
    failure_order: HandlerFailureOrder,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>> {
    use std::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use crate::failure::owned_future::CaughtFuture;
    use crate::failure::owned_future::catch_owned_future;

    // The callback may already have moved irreversible effects into this
    // terminal error. Failure still wins over ordinary values/child starts,
    // but must not replace the owned error with an empty cancellation marker.
    let terminal = || match handler_signal
        .lock()
        .expect("KVM handler signal lock poisoned")
        .take()
    {
        Some(HandlerSignal::RuntimeError(error)) => HandlerOutcome::RuntimeError(error),
        _ => HandlerOutcome::RunFailed,
    };
    // Own the pinned allocation: dropping a Pin<&mut F> would only end a
    // borrow. Any caller's callback receipt must follow destruction of this
    // future, including an inline RPC that was pending when failure arrived.
    let mut future = Box::pin(future);
    let mut failure = Box::pin(failure);
    let private_watch = watch.clone();
    let mut private_failure = Box::pin(async move {
        match private_watch {
            Some(watch) => watch.wait().await,
            None => std::future::pending::<()>().await,
        }
    });
    let mut selected = None;
    let mut select = |outcome| {
        selected = Some(outcome);
        Poll::Ready(())
    };
    // This driver only borrows the callback. Its caught poll cannot destroy the
    // callback allocation or an outcome already moved out of the signal slot.
    let caught = catch_owned_future(poll_fn(|context| {
        // Register the private wake before rechecking the sticky obligation.
        let _ = private_failure.as_mut().poll(context);
        if let Some(error) = watch.as_ref().and_then(|watch| watch.check().err()) {
            let prior = handler_signal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            return select(match prior {
                Some(HandlerSignal::RuntimeError(prior)) => HandlerOutcome::RuntimeError(
                    crate::entry::driver::combine_pending::<()>(Err(prior), Err(error))
                        .unwrap_err(),
                ),
                Some(signal) => handler_signal_outcome(signal),
                None => HandlerOutcome::RuntimeError(error),
            });
        }
        if matches!(failure_order, HandlerFailureOrder::BeforeCallback)
            && failure.as_mut().poll(context).is_ready()
        {
            return select(terminal());
        }
        let result = future.as_mut().poll(context);
        if let Some(error) = watch.as_ref().and_then(|watch| watch.check().err()) {
            // Keep a selected typed callback value/nonlocal result intact.
            // The outer finalizer maps its error before combining this sticky
            // cause; dropping a Ready Err here would lose its actual payload.
            let signal = handler_signal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(signal) = signal {
                return select(handler_signal_outcome(signal));
            }
            return select(match result {
                Poll::Ready(value) => HandlerOutcome::Returned(value),
                Poll::Pending => HandlerOutcome::RuntimeError(error),
            });
        }
        if matches!(failure_order, HandlerFailureOrder::BeforeCallback)
            && failure.as_mut().poll(context).is_ready()
        {
            return select(terminal());
        }
        // A callback can select another ready future after an operation records
        // a nonlocal result. Consume that result before accepting either a
        // returned callback value or an ordinary suspension.
        let handler_signal = handler_signal
            .lock()
            .expect("KVM handler signal lock poisoned")
            .take();
        if let Some(signal) = handler_signal {
            return select(handler_signal_outcome(signal));
        }
        match result {
            Poll::Ready(result) => select(HandlerOutcome::Returned(result)),
            Poll::Pending => {
                if matches!(failure_order, HandlerFailureOrder::AfterReadyCleanup)
                    && failure.as_mut().poll(context).is_ready()
                {
                    return select(terminal());
                }
                if let Some(error) = watch.as_ref().and_then(|watch| watch.check().err()) {
                    return select(HandlerOutcome::RuntimeError(error));
                }
                let mut starts = pending_child_starts
                    .lock()
                    .expect("KVM child-start lock poisoned");
                if starts.iter().any(|start| start.start().is_err()) {
                    return select(HandlerOutcome::RuntimeError(Error::UnexpectedVcpuExit(
                        "KVM child exited before its parent suspended registration".to_owned(),
                    )));
                }
                starts.clear();
                Poll::Pending
            }
        }
    }))
    .await;
    // Selection precedes unwinding any discarded callback value as well as
    // destruction of the callback future itself. Neither owns this outcome.
    let mut completion = CaughtFuture {
        output: selected,
        panics: caught.panics,
    };
    if completion.output.is_none() {
        // Polling may have stored the original error and then panicked while
        // holding this mutex. Keep that owned result before callback Drop can
        // panic too; lock poison must not replace the already-caught payload.
        completion.output = handler_signal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .map(handler_signal_outcome);
    }
    // Keep the selected outcome outside both destruction catches. Neither a
    // callback panic nor destruction of the failure future may discard it.
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(future))) {
        completion.panics.push(payload);
    }
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(failure))) {
        completion.panics.push(payload);
    }
    // Destructors may themselves capture a cause. Do not discard a selected
    // value before its typed mapping; the production finalizer rechecks it.
    if let Some(error) = watch.as_ref().and_then(|watch| watch.check().err())
        && completion.output.is_none()
    {
        completion.output = Some(HandlerOutcome::RuntimeError(error));
    }
    completion
}

/// Compatibility for the old non-panicking controls. Production callers must
/// retain both fields of the completion instead of using this wrapper.
#[cfg(any(test, feature = "native-test-support"))]
async fn drive_handler<T>(
    future: impl Future<Output = T>,
    handler_signal: SharedHandlerSignal,
    pending_child_starts: SharedChildStarts,
    failure: impl Future<Output = ()>,
) -> HandlerOutcome<T> {
    let mut completion =
        drive_handler_completion(future, handler_signal, pending_child_starts, failure).await;
    if !completion.panics.is_empty() {
        std::panic::resume_unwind(completion.panics.remove(0));
    }
    completion
        .output
        .expect("non-panicking callback driver returned no outcome")
}

pub(crate) fn start_pending_children(pending_child_starts: &SharedChildStarts) -> Result<()> {
    let mut starts = pending_child_starts
        .lock()
        .expect("KVM child-start lock poisoned");
    for start in starts.iter() {
        // Both fork and Tool-thread workers block on this receiver as their
        // first operation after a successful host spawn. A disconnected
        // receiver therefore indicates an internal registration invariant
        // violation rather than a guest-visible failure.
        start.start().map_err(|_| {
            Error::UnexpectedVcpuExit("registered KVM child lost its parent start gate".to_owned())
        })?;
    }
    starts.clear();
    Ok(())
}

fn tool_stack_bottom(tool_stack_top: u64) -> u64 {
    tool_stack_top - TOOL_STACK_SIZE
}

fn expose_tool_scratch(memory: &GuestMemory, tool_stack_top: u64) -> Result<()> {
    let reservation = memory.reserve_region(
        tool_stack_bottom(tool_stack_top),
        TOOL_STACK_SIZE,
        RegionKind::ToolScratch,
    )?;
    memory.map_user_range(tool_stack_bottom(tool_stack_top), TOOL_STACK_SIZE, false)?;
    reservation.commit();
    Ok(())
}

fn hide_tool_scratch(memory: &GuestMemory, tool_stack_top: u64) -> Result<()> {
    memory.unmap_user_range(tool_stack_bottom(tool_stack_top), TOOL_STACK_SIZE)
}

// TODO-HUMAN-REVIEW(PR-156): Review repeated post-exec lifecycle delivery.
#[allow(clippy::too_many_arguments)]
async fn run_post_exec_handler<T>(
    backend: &mut KvmBackend,
    tool: &Arc<T>,
    pid: Pid,
    memory: &GuestMemory,
    auxv: &mut Vec<(libc::c_ulong, libc::c_ulong)>,
    thread_state: &mut T::ThreadState,
    executor: &mut ElfExecutor,
    global_state: Arc<T::GlobalState>,
    config: &<T::GlobalState as GlobalTool>::Config,
    subscriptions: &Subscription,
    stack_checked_out: &Arc<AtomicBool>,
) -> Result<CallbackOutcome<()>>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    let tool_stack_top = backend.tool_stack_top();
    let failure_subscription = backend.failure_subscription(executor.is_traced_tree_root());
    loop {
        if executor.has_eligible_pending_signal() {
            return Err(Error::UnexpectedVcpuExit(
                "KVM post-exec lifecycle has an eligible preserved signal; delivery requires a \
                 syscall return frame"
                    .to_owned(),
            ));
        }

        let registers = kvm_registers(backend.vcpu.get_regs()?, 0);
        let handler_signal = Arc::new(Mutex::new(None));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        backend.check_entry_owner()?;
        expose_tool_scratch(memory, tool_stack_top)?;
        let mut _process_completed = false;
        let callback_scope = backend.begin_entry_callback()?;
        let callback_watch = backend.entry_driver_watch();
        let callback_memory = backend.memory.clone();
        executor.bind_address_space(&callback_memory);
        let outcome = {
            let memory = callback_memory;
            let mut guest_executor = StaticElfSyscallExecutor {
                backend,
                executor,
                memory: memory.clone(),
                process_context: ProcessExecutionContext::Lifecycle,
                callback_site: None,
                original_syscall: None,
                signal_guard: SignalGuard::Ordinary,
                last_result: None,
                polled_read_attempt: None,
                process_completed: &mut _process_completed,
            };
            let mut guest = KvmGuest::<T>::new(
                pid,
                // A process leader (root, fork child, or the post-exec thread
                // that became the new leader) has tid == pid.
                pid,
                tool.clone(),
                memory.clone(),
                auxv,
                registers,
                thread_state,
                &mut guest_executor,
                global_state.as_ref(),
                Some(global_state.clone()),
                config,
                subscriptions,
                handler_signal.clone(),
                pending_child_starts.clone(),
                tool_stack_top,
                stack_checked_out.clone(),
            );
            drive_entry_handler_completion_from(
                || tool.handle_post_exec(&mut guest),
                handler_signal,
                pending_child_starts.clone(),
                wait_for_failure(global_state.as_ref(), failure_subscription.clone()),
                callback_watch.clone(),
            )
            .await
        };
        drop(callback_scope);
        backend.restore_entry_origin();
        executor.bind_address_space(&backend.memory);

        let outcome = backend
            .finish_entry_handler_completion(
                outcome,
                hide_tool_scratch(memory, tool_stack_top),
                Error::PostExec,
                &callback_watch,
            )
            .await?;
        match outcome {
            HandlerOutcome::Returned(Ok(())) => return Ok(CallbackOutcome::Completed(())),
            HandlerOutcome::Returned(Err(error)) => return Err(Error::PostExec(error)),
            HandlerOutcome::GroupExit(status) => {
                backend.prepare_wait_group_exit(executor, status, &pending_child_starts)?;
                return Ok(CallbackOutcome::GroupExit(status));
            }
            HandlerOutcome::ThreadCancelled => {
                backend.start_pending_tool_children(executor, &pending_child_starts)?;
                return Ok(CallbackOutcome::ThreadCancelled);
            }
            HandlerOutcome::ThreadRetired => {
                backend.start_pending_tool_children(executor, &pending_child_starts)?;
                return Ok(CallbackOutcome::ThreadRetired);
            }
            HandlerOutcome::RunFailed => {
                return Err(backend.cleanup_unstarted_tool_children_after_error(
                    executor,
                    &pending_child_starts,
                    Error::RunAborted,
                ));
            }
            HandlerOutcome::ParkedFatal(_)
            | HandlerOutcome::ParkedCancelled(_)
            | HandlerOutcome::ParkedRetired(_) => {
                return Err(Error::UnexpectedVcpuExit(
                    "parked outcome outside its original syscall callback".to_owned(),
                ));
            }
            HandlerOutcome::RuntimeError(error) => return Err(error),
            HandlerOutcome::TailInjected {
                process_exited: true,
                ..
            } => return Ok(CallbackOutcome::Completed(())),
            HandlerOutcome::TailInjected {
                image_replaced: true,
                ..
            } => *auxv = executor.auxv().to_vec(),
            HandlerOutcome::TailInjected { .. } => {
                return Err(Error::UnexpectedVcpuExit(
                    "post-exec handler tail-injected a syscall".to_owned(),
                ));
            }
        }
    }
}

fn initial_exec_request(memory: &GuestMemory, stack_pointer: u64) -> Result<SyscallRequest> {
    fn read_word(memory: &GuestMemory, address: u64) -> Result<u64> {
        let mut bytes = [0; std::mem::size_of::<u64>()];
        memory.user().read(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    let argc = read_word(memory, stack_pointer)?;
    let argv = stack_pointer
        .checked_add(std::mem::size_of::<u64>() as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    let path = read_word(memory, argv)?;
    let envp = argc
        .checked_add(1)
        .and_then(|words| words.checked_mul(std::mem::size_of::<u64>() as u64))
        .and_then(|offset| argv.checked_add(offset))
        .ok_or(Error::LongModeMemoryTooSmall)?;

    Ok(SyscallRequest::new(
        libc::SYS_execve as u64,
        [path, argv, envp, 0, 0, 0],
    ))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-233): Review synthetic initial exec Tool delivery.
// TODO-HUMAN-REVIEW(PR-235): Review shared Tool state during initial exec.
#[allow(clippy::too_many_arguments)]
async fn run_initial_exec_handler<T>(
    backend: &mut KvmBackend,
    tool: &Arc<T>,
    pid: Pid,
    memory: &GuestMemory,
    auxv: &[(libc::c_ulong, libc::c_ulong)],
    thread_state: &mut T::ThreadState,
    executor: &mut ElfExecutor,
    global_state: &Arc<T::GlobalState>,
    config: &<T::GlobalState as GlobalTool>::Config,
    subscriptions: &Subscription,
    stack_checked_out: &Arc<AtomicBool>,
) -> Result<CallbackOutcome<()>>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    let tool_stack_top = backend.tool_stack_top();
    let failure_subscription = backend.failure_subscription(executor.is_traced_tree_root());
    let request = initial_exec_request(memory, executor.initial_stack_pointer())?;
    let syscall = request.into_syscall()?;
    let mut registers = kvm_registers(backend.vcpu.get_regs()?, request.number());
    registers.rdi = request.args()[0];
    registers.rsi = request.args()[1];
    registers.rdx = request.args()[2];

    let handler_signal = Arc::new(Mutex::new(None));
    let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
    backend.check_entry_owner()?;
    expose_tool_scratch(memory, tool_stack_top)?;
    let mut _process_completed = false;
    let callback_scope = backend.begin_entry_callback()?;
    let callback_watch = backend.entry_driver_watch();
    let callback_memory = backend.memory.clone();
    executor.bind_address_space(&callback_memory);
    let outcome = {
        let memory = callback_memory;
        let mut guest_executor = StaticElfSyscallExecutor {
            backend,
            executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::InitialExec(request),
            callback_site: None,
            original_syscall: None,
            signal_guard: SignalGuard::Ordinary,
            last_result: None,
            polled_read_attempt: None,
            process_completed: &mut _process_completed,
        };
        let mut guest = KvmGuest::<T>::new(
            pid,
            // The initial exec runs on the root thread, where tid == pid.
            pid,
            tool.clone(),
            memory.clone(),
            auxv,
            registers,
            thread_state,
            &mut guest_executor,
            global_state.as_ref(),
            Some(global_state.clone()),
            config,
            subscriptions,
            handler_signal.clone(),
            pending_child_starts.clone(),
            tool_stack_top,
            stack_checked_out.clone(),
        );
        drive_entry_handler_completion_from(
            || tool.handle_syscall_event(&mut guest, syscall),
            handler_signal,
            pending_child_starts.clone(),
            wait_for_failure(global_state.as_ref(), failure_subscription.clone()),
            callback_watch.clone(),
        )
        .await
    };
    drop(callback_scope);
    backend.restore_entry_origin();
    executor.bind_address_space(&backend.memory);

    let outcome = backend
        .finish_entry_handler_completion(
            outcome,
            hide_tool_scratch(memory, tool_stack_top),
            Error::Reverie,
            &callback_watch,
        )
        .await?;

    match outcome {
        HandlerOutcome::Returned(result) => result
            .map(|_| CallbackOutcome::Completed(()))
            .map_err(Error::Reverie),
        HandlerOutcome::TailInjected {
            result: Ok(_),
            process_exited: true,
            ..
        } => Ok(CallbackOutcome::Completed(())),
        HandlerOutcome::TailInjected {
            result: Ok(_),
            image_replaced: true,
            ..
        } => Ok(CallbackOutcome::Completed(())),
        HandlerOutcome::TailInjected {
            result: Err(error), ..
        } => Err(Error::Reverie(error.into())),
        HandlerOutcome::TailInjected { .. } => Err(Error::UnexpectedVcpuExit(
            "initial exec handler tail-injected without completing exec".to_owned(),
        )),
        HandlerOutcome::GroupExit(status) => {
            backend.prepare_wait_group_exit(executor, status, &pending_child_starts)?;
            Ok(CallbackOutcome::GroupExit(status))
        }
        HandlerOutcome::ThreadCancelled => {
            backend.start_pending_tool_children(executor, &pending_child_starts)?;
            Ok(CallbackOutcome::ThreadCancelled)
        }
        HandlerOutcome::ThreadRetired => {
            backend.start_pending_tool_children(executor, &pending_child_starts)?;
            Ok(CallbackOutcome::ThreadRetired)
        }
        HandlerOutcome::RunFailed => Err(backend.cleanup_unstarted_tool_children_after_error(
            executor,
            &pending_child_starts,
            Error::RunAborted,
        )),
        HandlerOutcome::ParkedFatal(_)
        | HandlerOutcome::ParkedCancelled(_)
        | HandlerOutcome::ParkedRetired(_) => Err(Error::UnexpectedVcpuExit(
            "parked outcome during initial exec".to_owned(),
        )),
        HandlerOutcome::RuntimeError(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToolExitDisposition {
    GuestExit,
    /// Already retired through an authenticated existing group decision; this
    /// completion must not freeze a second logical death in the finalizer.
    CommittedGroupFollower,
    ExplicitCancellation,
    Retirement,
}

#[derive(Clone, Copy)]
struct ToolProcessExit {
    exit: ProcessExit,
    disposition: ToolExitDisposition,
}

impl ProcessExit {
    fn signal_boundary_outcome(self) -> reverie::SignalBoundaryOutcome {
        reverie::SignalBoundaryOutcome::Terminated {
            group: self.group,
            wait_status: self.status.into_raw(),
        }
    }
}

impl ToolProcessExit {
    fn commit_guest_death(&mut self, executor: &mut ElfExecutor) {
        if self.disposition == ToolExitDisposition::GuestExit {
            self.exit = executor.retire_guest_thread(self.exit.status, self.exit.group);
        }
    }

    fn joins_live_peers(self) -> bool {
        self.disposition != ToolExitDisposition::ExplicitCancellation && !self.exit.group
    }

    fn signal_boundary_outcome(self) -> reverie::SignalBoundaryOutcome {
        match self.disposition {
            ToolExitDisposition::GuestExit | ToolExitDisposition::CommittedGroupFollower => {
                self.exit.signal_boundary_outcome()
            }
            ToolExitDisposition::ExplicitCancellation | ToolExitDisposition::Retirement => {
                reverie::SignalBoundaryOutcome::Cancelled
            }
        }
    }
}

impl From<ProcessExit> for ToolProcessExit {
    fn from(exit: ProcessExit) -> Self {
        Self {
            exit,
            disposition: ToolExitDisposition::GuestExit,
        }
    }
}

/// A published run failure can interrupt a permitted CLONE_THREAD worker even
/// before the backend's ordinary cancellation flag becomes visible.
pub(crate) fn is_peer_cancelled_tool_worker<R>(
    identity: (Pid, Pid),
    start_permitted: bool,
    outcome: &Result<R>,
) -> bool {
    start_permitted
        && identity.0 != identity.1
        && outcome
            .as_ref()
            .is_err_and(|error| matches!(error.primary(), Error::RunAborted))
}

/// Keep the interrupted worker's error tree for final cleanup while preserving
/// ordinary cancellation retirement and any established guest exit status.
fn retire_peer_cancelled_tool_worker(
    executor: &mut ElfExecutor,
    identity: (Pid, Pid),
    start_permitted: bool,
    group_status: Option<ExitStatus>,
    outcome: &Result<ToolProcessExit>,
) -> Option<ToolProcessExit> {
    if !is_peer_cancelled_tool_worker(identity, start_permitted, outcome) {
        return None;
    }
    let exit = match group_status {
        Some(status) => executor.retire_current_thread(status, true),
        None => executor.cancel_current_thread(),
    };
    Some(ToolProcessExit {
        exit,
        disposition: ToolExitDisposition::ExplicitCancellation,
    })
}

#[derive(Clone, Copy)]
struct ToolExit {
    status: ExitStatus,
    process_exited: bool,
}

/// Execution panic may bypass the affected worker's consuming hook. Destroy
/// each remaining owner separately: neither destructor may unwind through the
/// other owner or replace the retained execution error and original payload.
fn drop_panicked_worker_tool<T: Tool>(
    tool: Arc<T>,
    thread_state: T::ThreadState,
    panics: &crate::failure::tool_panics::ToolPanics,
) -> Result<()> {
    let thread = panics.drop_value(thread_state, "panicked worker thread-state destruction");
    let process = panics.drop_value(tool, "panicked worker Tool destruction");
    Error::combine(
        [thread, process]
            .into_iter()
            .filter_map(Result::err)
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
async fn notify_tool_exit_with_panics<T: Tool>(
    tool: Arc<T>,
    pid: Pid,
    tid: Pid,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    thread_state: T::ThreadState,
    exit: ToolExit,
    failure: Option<&FailureContext>,
    panics: &crate::failure::tool_panics::ToolPanics,
) -> Result<()> {
    use crate::failure::owned_future::CaughtFuture;
    use crate::failure::owned_future::catch_owned_future_from;

    // on_exit_thread deregisters this thread from the scheduler, so its RPCs
    // must be attributed to the exiting thread's tid.
    let thread_global = KvmGlobal {
        tid,
        state: global_state,
        config,
    };
    let caught = catch_owned_future_from(|| {
        tool.on_exit_thread(tid, &thread_global, thread_state, exit.status)
    })
    .await;
    let thread_result = panics
        .finish(
            CaughtFuture {
                output: caught.output.map(|result| result.map_err(Error::Reverie)),
                panics: caught.panics,
            },
            "thread exit hook",
        )
        .map_err(|error| match failure {
            Some(failure) => failure.publish("thread exit hook", error),
            None => {
                global_state.report_backend_failure(reverie::BackendFailure {
                    pid,
                    tid,
                    phase: "thread exit hook",
                });
                error
            }
        });
    if !exit.process_exited {
        return thread_result;
    }
    // The process-exit hook belongs to the thread-group leader (tid == pid).
    let process_global = KvmGlobal {
        tid: pid,
        state: global_state,
        config,
    };
    // A failed thread hook has still consumed ThreadState. Attempt the
    // process hook as well, after every worker has dropped its process Arc.
    let process_result = match Arc::try_unwrap(tool) {
        Ok(tool) => {
            let caught =
                catch_owned_future_from(|| tool.on_exit_process(pid, &process_global, exit.status))
                    .await;
            panics.finish(
                CaughtFuture {
                    output: caught.output.map(|result| result.map_err(Error::Reverie)),
                    panics: caught.panics,
                },
                "process exit hook",
            )
        }
        Err(_) => Err(Error::UnexpectedVcpuExit(
            "KVM worker retained process Tool state after exit".to_owned(),
        )),
    };
    let process_result = process_result.map_err(|error| match failure {
        Some(failure) => failure.publish("process exit hook", error),
        None => {
            global_state.report_backend_failure(reverie::BackendFailure {
                pid,
                tid,
                phase: "process exit hook",
            });
            error
        }
    });
    match (thread_result, process_result) {
        (Ok(()), process) => process,
        (Err(error), Ok(())) => Err(error),
        (Err(thread), Err(process)) => Err(thread.with_cleanup(vec![process])),
    }
}

/// Compatibility for existing non-panicking controls. Production owners retain
/// their ToolPanics through all hooks and joins instead of using this wrapper.
#[cfg(any(test, feature = "native-test-support"))]
#[allow(clippy::too_many_arguments)]
async fn notify_tool_exit<T: Tool>(
    tool: Arc<T>,
    pid: Pid,
    tid: Pid,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    thread_state: T::ThreadState,
    exit: ToolExit,
    failure: Option<&FailureContext>,
) -> Result<()> {
    let panics = crate::failure::tool_panics::ToolPanics::default();
    let result = notify_tool_exit_with_panics(
        tool,
        pid,
        tid,
        global_state,
        config,
        thread_state,
        exit,
        failure,
        &panics,
    )
    .await;
    let mut payloads = panics.take();
    if !payloads.is_empty() {
        std::panic::resume_unwind(payloads.remove(0));
    }
    result
}

/// Compatibility for existing native controls which expect panic propagation.
#[cfg(any(test, feature = "native-test-support"))]
#[allow(clippy::too_many_arguments)]
async fn finish_tool_process_after_workers<T: Tool>(
    executor: &mut ElfExecutor,
    tool: Arc<T>,
    identity: (Pid, Pid),
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    thread_state: T::ThreadState,
    outcome: Result<ToolProcessExit>,
    cancelled_exit: Option<ToolProcessExit>,
    workers: Result<()>,
    failure: Option<&FailureContext>,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let panics = crate::failure::tool_panics::ToolPanics::default();
    let result = finish_tool_process_after_workers_with_panics(
        executor,
        tool,
        identity,
        global_state,
        config,
        thread_state,
        outcome,
        cancelled_exit,
        workers,
        failure,
        &panics,
        None,
        None,
        false,
    )
    .await;
    let mut payloads = panics.take();
    if !payloads.is_empty() {
        std::panic::resume_unwind(payloads.remove(0));
    }
    result
}

/// Result of a Tool run after owned workers and children have completed.
pub struct ToolRunCompletion<G> {
    /// Global Tool state, retained on runtime failure for consuming cleanup.
    pub global_state: G,
    /// Guest output/status, or a typed fatal runtime/Tool cause.
    pub result: Result<(i32, Vec<u8>, Vec<u8>)>,
}

/// Complete the owner after physical worker joins. A fork child's logical wait
/// result and callback publish immediately after its authoritative process
/// status, before consuming hooks or recursively joining descendants.
fn validate_tool_child_completion(
    completion: reverie::ChildExitCompletion,
    expected_child: reverie::SignalProcessId,
    process_status: ExitStatus,
    raw_child_pid: i32,
) -> Result<()> {
    if completion.child != expected_child {
        return Err(Error::UnexpectedVcpuExit(format!(
            "KVM child process {raw_child_pid} family identity {:?} disagrees with admitted identity {expected_child:?}",
            completion.child,
        )));
    }
    validate_tool_child_status(completion.status, process_status, raw_child_pid)
}

fn validate_tool_child_status(
    family_status: ExitStatus,
    process_status: ExitStatus,
    raw_child_pid: i32,
) -> Result<()> {
    if family_status != process_status {
        return Err(Error::UnexpectedVcpuExit(format!(
            "KVM child process {raw_child_pid} family status {family_status:?} disagrees with its process status {process_status:?}",
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn finish_tool_process_after_workers_with_panics<T: Tool>(
    executor: &mut ElfExecutor,
    tool: Arc<T>,
    identity: (Pid, Pid),
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    thread_state: T::ThreadState,
    outcome: Result<ToolProcessExit>,
    cancelled_exit: Option<ToolProcessExit>,
    workers: Result<()>,
    failure: Option<&FailureContext>,
    panics: &crate::failure::tool_panics::ToolPanics,
    backend: Option<&KvmBackend>,
    child_exit: Option<crate::vm::OwnChildExitContext>,
    start_permitted: bool,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let (pid, tid) = identity;
    let report = |phase, error| match failure {
        Some(failure) => failure.publish(phase, error),
        None => {
            global_state.report_backend_failure(reverie::BackendFailure { pid, tid, phase });
            error
        }
    };
    let workers = workers.map_err(|error| {
        let worker_tid = error.worker_tid().map(Pid::from_raw).unwrap_or(tid);
        match failure {
            Some(failure) => failure
                .for_thread(worker_tid)
                .publish("worker teardown", error),
            None => {
                global_state.report_backend_failure(reverie::BackendFailure {
                    pid,
                    tid: worker_tid,
                    phase: "worker teardown",
                });
                error
            }
        }
    });
    let mut status = cancelled_exit.map_or_else(
        || {
            outcome
                .as_ref()
                .map_or(ExitStatus::Exited(255), |exit| exit.exit.status)
        },
        |exit| exit.exit.status,
    );
    let mut process_status = Ok(());
    if pid == tid && outcome.is_ok() {
        match executor.process_exit_status() {
            Some(final_status) => status = final_status,
            None if workers.is_err() => status = ExitStatus::Exited(255),
            None => {
                status = ExitStatus::Exited(255);
                process_status = Err(report(
                    "process exit status",
                    Error::UnexpectedVcpuExit(
                        "KVM process has no final task exit status after joining workers"
                            .to_owned(),
                    ),
                ));
            }
        }
    }
    let child_wait = match (
        child_exit,
        outcome.is_ok() && workers.is_ok() && process_status.is_ok(),
    ) {
        (Some(context), true) => {
            // Claiming decides, atomically with the parent's exit, whether this
            // status is announced to a live parent or reaped by the namespace
            // init that adopted the parent's children.
            let family_exit = executor
                .claim_process_family_exit()
                .map_err(|error| report("child family exit", error));
            match family_exit {
                Err(error) => Err(error),
                Ok(crate::executor::ProcessFamilyExit::Child(snapshot)) => {
                    match validate_tool_child_completion(
                        snapshot.completion,
                        context.child,
                        status,
                        context.raw_child_pid,
                    ) {
                        Err(error) => Err(report("child family exit", error)),
                        Ok(()) => {
                            let completion = crate::executor::ChildCompletion::from_waitability(
                                snapshot.completion.status,
                                snapshot.completion.waitable,
                            );
                            if let Err(error) = executor
                                .begin_child_wait_publication(context.child, &context.completion)
                            {
                                Err(report("child wait completion", error))
                            } else {
                                let event = reverie::BackendChildWaitEvent {
                                    parent: snapshot.completion.parent,
                                    child: context.child,
                                    state: reverie::BackendChildWaitState::Exited {
                                        status: snapshot.completion.status,
                                        waitable: snapshot.completion.waitable,
                                        uid: snapshot.completion.uid,
                                        user_ticks: snapshot.completion.user_ticks,
                                        system_ticks: snapshot.completion.system_ticks,
                                    },
                                };
                                let mut callback = Box::pin(
                                    crate::failure::owned_future::catch_owned_future_from(|| {
                                        global_state.on_backend_child_wait_event(event)
                                    }),
                                );
                                // Poll through the Tool's synchronous admission prefix
                                // before exposing waitability. The retained future may
                                // then suspend on parent progress without hiding the
                                // already-committed publication decision.
                                let first_poll =
                                    poll_fn(|cx| Poll::Ready(callback.as_mut().poll(cx))).await;
                                let waitability = executor
                                    .publish_child_wait(
                                        context.child,
                                        completion,
                                        &context.completion,
                                        true,
                                    )
                                    .map_err(|error| report("child wait completion", error));
                                let caught = match first_poll {
                                    Poll::Ready(caught) => caught,
                                    Poll::Pending => callback.await,
                                };
                                let hook = panics
                                    .finish(
                                        crate::failure::owned_future::CaughtFuture {
                                            output: caught
                                                .output
                                                .map(|result| result.map_err(Error::Reverie)),
                                            panics: caught.panics,
                                        },
                                        "child wait hook",
                                    )
                                    .map_err(|error| report("child wait hook", error));
                                match (waitability, hook) {
                                    (Ok(()), result) | (result, Ok(())) => result,
                                    (Err(error), Err(hook)) => Err(error.with_cleanup(vec![hook])),
                                }
                            }
                        }
                    }
                }
                // An orphan reaped by an outside namespace init completes
                // exactly like teardown: the host slot is auto-reaped and no
                // traced parent receives a Tool child event.
                Ok(
                    crate::executor::ProcessFamilyExit::RunTeardownChild {
                        status: family_status,
                    }
                    | crate::executor::ProcessFamilyExit::ReapedByNamespaceInit {
                        status: family_status,
                    },
                ) => {
                    if let Err(error) =
                        validate_tool_child_status(family_status, status, context.raw_child_pid)
                    {
                        Err(report("child family exit", error))
                    } else {
                        executor
                            .publish_child_wait(
                                context.child,
                                crate::executor::ChildCompletion::AutoReaped(family_status),
                                &context.completion,
                                false,
                            )
                            .map_err(|error| report("child teardown completion", error))
                    }
                }
                Ok(crate::executor::ProcessFamilyExit::Root) => Err(report(
                    "child family exit",
                    Error::UnexpectedVcpuExit(format!(
                        "KVM child process {} was recorded as a traced root",
                        context.raw_child_pid
                    )),
                )),
                Ok(crate::executor::ProcessFamilyExit::Failed) => {
                    unreachable!("executor maps failed family state to an error")
                }
                Ok(crate::executor::ProcessFamilyExit::DescendantReparentingUnsupported {
                    ..
                }) => unreachable!("executor maps unsupported reparenting to an error"),
                Ok(crate::executor::ProcessFamilyExit::ParentGenerationUnavailable { .. }) => {
                    unreachable!("executor maps a missing parent generation to an error")
                }
                Ok(crate::executor::ProcessFamilyExit::ParentChildRelationUnavailable {
                    ..
                }) => {
                    unreachable!("executor maps a missing parent-child relation to an error")
                }
                Ok(crate::executor::ProcessFamilyExit::AncestryCycle { .. }) => {
                    unreachable!("executor maps a family ancestry cycle to an error")
                }
                Ok(crate::executor::ProcessFamilyExit::MultipleParents { .. }) => {
                    unreachable!("executor maps ambiguous family parents to an error")
                }
            }
        }
        (None, true) if pid == tid => executor
            .process_family_exit()
            .map(|_| ())
            .map_err(|error| report("process family exit", error)),
        (Some(_), false) | (None, _) => Ok(()),
    };
    let retirement = if start_permitted
        && pid == tid
        && outcome.is_ok()
        && workers.is_ok()
        && process_status.is_ok()
        && child_wait.is_ok()
    {
        // The leader has joined every peer's cleanup. If a controlled terminal
        // receipt established a Tool fence, it can now open before independent
        // children need further deterministic turns. A synchronous hardware
        // fault can reach this callback without such a receipt or fence.
        let event = reverie::BackendProcessRetirement {
            process: executor.retired_process_identity(),
            status,
        };
        let caught = crate::failure::owned_future::catch_owned_future_from(|| {
            std::future::ready(global_state.on_backend_process_retired(event))
        })
        .await;
        panics
            .finish(
                crate::failure::owned_future::CaughtFuture {
                    output: caught.output.map(|result| result.map_err(Error::Reverie)),
                    panics: caught.panics,
                },
                "process retirement",
            )
            .map_err(|error| report("process retirement", error))
    } else {
        Ok(())
    };
    // Worker hooks precede the leader. Owner hooks precede independent forks
    // that may need the parent's deregistration/accounting to finish.
    let owner = if pid != tid && panics.worker_execution_panicked() {
        // An execution panic is not an ordinary returned runtime error. The
        // Tool API permits this worker's own hook to be bypassed; independently
        // retained children still completed their consuming cleanup above.
        drop_panicked_worker_tool(tool, thread_state, panics)
    } else {
        notify_tool_exit_with_panics(
            tool,
            pid,
            tid,
            global_state,
            config,
            thread_state,
            ToolExit {
                status,
                process_exited: pid == tid,
            },
            failure,
            panics,
        )
        .await
    }
    .map_err(|error| report("owner exit", error));
    // Consuming hooks may use retained memory. Route their newly captured
    // obligation before any physical child join, outside all callback scopes.
    let entry = match backend {
        Some(backend) => backend.route_entry_outcome(Ok(())).await,
        None => Ok(()),
    }
    .map_err(|error| report("entry completion", error));
    // A peer can publish after this process's successful local outcome. Its
    // terminal state must still select Cancel for every pending child gate.
    let terminal = wait_for_failure(global_state, failure.map(|failure| failure.run.subscribe()))
        .now_or_never()
        .is_some();
    let children = if pid == tid {
        if terminal
            || outcome.is_err()
            || owner.is_err()
            || workers.is_err()
            || process_status.is_err()
            || child_wait.is_err()
            || retirement.is_err()
            || entry.is_err()
        {
            executor.join_child_processes_after_failure_async().await
        } else {
            executor.join_all_child_processes_async().await
        }
    } else {
        executor.transfer_child_processes_to_owner();
        Ok(())
    };
    let errors = [
        outcome.map(|_| ()),
        workers,
        process_status,
        child_wait,
        retirement,
        owner,
        entry,
        children,
    ]
    .into_iter()
    .filter_map(Result::err)
    .collect();
    Error::combine(errors)?;
    let (stdout, stderr) = executor.take_output();
    Ok((status, stdout, stderr))
}

/// Failed spawns transfer their unpolled consuming cleanup out of the parent
/// callback. Its driver publishes the parent failure before calling this;
/// a bare RunAborted is the child's derived failure-cleanup marker only.
#[cfg(test)]
async fn finish_unstarted_tool_cleanups(executor: &mut ElfExecutor) -> Result<()> {
    let mut errors = Vec::new();
    for cleanup in executor.take_unstarted_tool_cleanup() {
        match cleanup.await {
            Ok(()) | Err(Error::RunAborted) => {}
            Err(error) => errors.push(error),
        }
    }
    Error::combine(errors)
}

/// Drain constructed children in order while retaining each completed panic
/// before polling the next child. A child's own transfer guard may also append
/// payloads while its future is polled or destroyed.
pub(crate) async fn finish_unstarted_tool_cleanups_with_panics(
    executor: &mut ElfExecutor,
    panics: &crate::failure::tool_panics::ToolPanics,
) -> Result<()> {
    let cleanups = executor.take_unstarted_tool_cleanup();
    let mut errors = Vec::new();
    for cleanup in cleanups {
        let caught = crate::failure::owned_future::catch_owned_future(cleanup).await;
        match panics.finish(caught, "unstarted-child cleanup") {
            Ok(()) | Err(Error::RunAborted) => {}
            Err(error) => errors.push(error),
        }
    }
    Error::combine(errors)
}

/// Drain the retained consumers after their owner's caught panic. Publication
/// and propagation of that panic remain the caller's responsibility.
#[cfg(test)]
pub(crate) async fn finish_unstarted_tool_cleanups_after_panic(
    executor: &mut ElfExecutor,
) -> crate::failure::owned_future::CaughtFuture<Result<()>> {
    use crate::failure::owned_future::CaughtFuture;
    use crate::failure::owned_future::catch_owned_future;

    // Take the whole queue before polling a consumer. The iterator and all
    // prior outcomes stay outside each individual poll/destruction catch.
    let cleanups = executor.take_unstarted_tool_cleanup();
    let mut errors = Vec::new();
    let mut panics = Vec::new();
    for cleanup in cleanups {
        let caught = catch_owned_future(cleanup).await;
        match caught.output {
            None | Some(Ok(())) | Some(Err(Error::RunAborted)) => {}
            Some(Err(error)) => errors.push(error),
        }
        panics.extend(caught.panics);
    }
    CaughtFuture {
        output: Some(Error::combine(errors)),
        panics,
    }
}

#[cfg(test)]
mod unstarted_cleanup_panic_tests {
    use std::panic::resume_unwind;
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;
    use std::task::Waker;

    use futures::channel::oneshot;

    use super::*;
    use crate::failure::owned_future::PanicPayload;

    #[derive(Default)]
    struct Counts {
        polls: AtomicUsize,
        drops: AtomicUsize,
    }

    struct Consumer {
        counts: Arc<Counts>,
        output: Option<Result<()>>,
        release: Option<oneshot::Receiver<()>>,
        poll_panic: Option<PanicPayload>,
        drop_panic: Option<PanicPayload>,
    }

    impl Consumer {
        fn ready(output: Result<()>, counts: Arc<Counts>) -> Self {
            Self {
                counts,
                output: Some(output),
                release: None,
                poll_panic: None,
                drop_panic: None,
            }
        }
    }

    impl Future for Consumer {
        type Output = Result<()>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.counts.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(payload) = this.poll_panic.take() {
                resume_unwind(payload);
            }
            if let Some(release) = this.release.as_mut() {
                match Pin::new(release).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(_)) => panic!("consumer release was dropped"),
                }
            }
            this.release.take();
            Poll::Ready(this.output.take().expect("completed consumer was repolled"))
        }
    }

    impl Drop for Consumer {
        fn drop(&mut self) {
            self.counts.drops.fetch_add(1, Ordering::SeqCst);
            if let Some(payload) = self.drop_panic.take() {
                resume_unwind(payload);
            }
        }
    }

    struct PanicMarker(&'static str);

    fn payload(label: &'static str) -> (PanicPayload, usize) {
        let marker = Box::new(PanicMarker(label));
        let address = std::ptr::from_ref(marker.as_ref()) as usize;
        (marker, address)
    }

    fn assert_payload(payload: &PanicPayload, address: usize, label: &'static str) {
        let marker = payload.downcast_ref::<PanicMarker>().unwrap();
        assert_eq!(std::ptr::from_ref(marker) as usize, address);
        assert_eq!(marker.0, label);
    }

    fn executor() -> ElfExecutor {
        ElfExecutor::new(
            crate::executor::native_loaded_state(std::path::Path::new("/")),
            false,
        )
    }

    #[test]
    fn poll_and_drop_panics_preserve_pending_and_later_consumers() {
        let mut executor = executor();
        let first = Arc::new(Counts::default());
        let second = Arc::new(Counts::default());
        let third = Arc::new(Counts::default());
        let (poll_panic, poll_address) = payload("first poll");
        let (drop_panic, drop_address) = payload("first drop");
        let mut consumer = Consumer::ready(Ok(()), first.clone());
        consumer.poll_panic = Some(poll_panic);
        consumer.drop_panic = Some(drop_panic);
        executor.retain_unstarted_tool_cleanup(Box::pin(consumer));
        let (release, wait) = oneshot::channel();
        let mut consumer = Consumer::ready(Ok(()), second.clone());
        consumer.release = Some(wait);
        executor.retain_unstarted_tool_cleanup(Box::pin(consumer));
        executor.retain_unstarted_tool_cleanup(Box::pin(Consumer::ready(Ok(()), third.clone())));

        let mut drain = Box::pin(finish_unstarted_tool_cleanups_after_panic(&mut executor));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(drain.as_mut().poll(&mut cx).is_pending());
        assert_eq!(first.polls.load(Ordering::SeqCst), 1);
        assert_eq!(first.drops.load(Ordering::SeqCst), 1);
        assert_eq!(second.polls.load(Ordering::SeqCst), 1);
        assert_eq!(second.drops.load(Ordering::SeqCst), 0);
        assert_eq!(third.polls.load(Ordering::SeqCst), 0);
        assert_eq!(third.drops.load(Ordering::SeqCst), 0);

        release.send(()).unwrap();
        let Poll::Ready(caught) = drain.as_mut().poll(&mut cx) else {
            panic!("released consumer stayed pending");
        };
        assert!(matches!(caught.output, Some(Ok(()))));
        assert_eq!(caught.panics.len(), 2);
        assert_payload(&caught.panics[0], poll_address, "first poll");
        assert_payload(&caught.panics[1], drop_address, "first drop");
        drop(drain);
        assert_eq!(first.polls.load(Ordering::SeqCst), 1);
        assert_eq!(first.drops.load(Ordering::SeqCst), 1);
        assert_eq!(second.polls.load(Ordering::SeqCst), 2);
        assert_eq!(second.drops.load(Ordering::SeqCst), 1);
        assert_eq!(third.polls.load(Ordering::SeqCst), 1);
        assert_eq!(third.drops.load(Ordering::SeqCst), 1);
        assert!(executor.take_unstarted_tool_cleanup().is_empty());
    }

    #[test]
    fn returned_error_and_drop_panic_preserve_later_real_errors() {
        let mut executor = executor();
        let first = Arc::new(Counts::default());
        let second = Arc::new(Counts::default());
        let third = Arc::new(Counts::default());
        let first_cause = Arc::new(Error::GuestClock("first consumer error".to_owned()));
        let second_cause = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)));
        let (drop_panic, drop_address) = payload("drop after returned error");
        let (later_panic, later_address) = payload("drop after later error");
        let mut consumer = Consumer::ready(
            Err(Error::SharedFailure(first_cause.clone())),
            first.clone(),
        );
        consumer.drop_panic = Some(drop_panic);
        executor.retain_unstarted_tool_cleanup(Box::pin(consumer));
        let mut consumer = Consumer::ready(
            Err(Error::RunAborted.with_cleanup(vec![Error::SharedFailure(second_cause.clone())])),
            second.clone(),
        );
        consumer.drop_panic = Some(later_panic);
        executor.retain_unstarted_tool_cleanup(Box::pin(consumer));
        executor.retain_unstarted_tool_cleanup(Box::pin(Consumer::ready(Ok(()), third.clone())));

        let mut drain = Box::pin(finish_unstarted_tool_cleanups_after_panic(&mut executor));
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(caught) = drain.as_mut().poll(&mut cx) else {
            panic!("ready consumers stayed pending");
        };
        let Some(Err(error)) = caught.output else {
            panic!("consumer errors were lost");
        };
        let Error::WithCleanup { primary, cleanup } = error else {
            panic!("later error was not retained");
        };
        assert!(matches!(
            primary.as_ref(),
            Error::SharedFailure(cause) if Arc::ptr_eq(cause, &first_cause)
        ));
        assert_eq!(cleanup.len(), 1);
        let Error::WithCleanup { primary, cleanup } = cleanup[0].as_ref() else {
            panic!("wrapped abort hid its real cleanup error");
        };
        assert!(matches!(primary.as_ref(), Error::RunAborted));
        assert_eq!(cleanup.len(), 1);
        assert!(matches!(
            cleanup[0].as_ref(),
            Error::SharedFailure(cause) if Arc::ptr_eq(cause, &second_cause)
        ));
        assert_eq!(caught.panics.len(), 2);
        assert_payload(&caught.panics[0], drop_address, "drop after returned error");
        assert_payload(&caught.panics[1], later_address, "drop after later error");
        drop(drain);
        for counts in [&first, &second, &third] {
            assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
            assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
        }
        assert!(executor.take_unstarted_tool_cleanup().is_empty());
    }

    #[test]
    fn only_bare_abort_is_ignored_and_empty_drain_has_an_output() {
        let mut executor = executor();
        let shared_abort = Arc::new(Error::RunAborted);
        for error in [
            Error::RunAborted,
            Error::SharedFailure(shared_abort.clone()),
            Error::RunAborted.cleanup("retained phase"),
        ] {
            executor.retain_unstarted_tool_cleanup(Box::pin(std::future::ready(Err(error))));
        }
        let mut drain = Box::pin(finish_unstarted_tool_cleanups_after_panic(&mut executor));
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(caught) = drain.as_mut().poll(&mut cx) else {
            panic!("ready consumers stayed pending");
        };
        let Some(Err(Error::WithCleanup { primary, cleanup })) = caught.output else {
            panic!("wrapped abort was incorrectly ignored");
        };
        assert!(matches!(
            primary.as_ref(),
            Error::SharedFailure(cause) if Arc::ptr_eq(cause, &shared_abort)
        ));
        assert_eq!(cleanup.len(), 1);
        assert!(matches!(
            cleanup[0].as_ref(),
            Error::Cleanup { phase: "retained phase", error }
                if matches!(error.as_ref(), Error::RunAborted)
        ));
        assert!(caught.panics.is_empty());
        drop(drain);
        assert!(executor.take_unstarted_tool_cleanup().is_empty());

        let mut empty = Box::pin(finish_unstarted_tool_cleanups_after_panic(&mut executor));
        let Poll::Ready(caught) = empty.as_mut().poll(&mut cx) else {
            panic!("empty drain stayed pending");
        };
        assert!(matches!(caught.output, Some(Ok(()))));
        assert!(caught.panics.is_empty());
    }
}

impl KvmBackend {
    fn finish_tool_execution_completion<R>(
        &self,
        caught: crate::failure::owned_future::CaughtFuture<Result<R>>,
        phase: &'static str,
    ) -> Result<R> {
        let panics = self.tool_panic_owner();
        if self.is_tool_guest_worker() {
            panics.finish_worker_execution(caught, phase)
        } else {
            panics.finish(caught, phase)
        }
    }

    /// The callback borrow scope has ended. Keep its selected error and panic
    /// until this concrete owner's outer cleanup and publication have finished.
    fn finish_handler_completion<T, E>(
        &self,
        completion: crate::failure::owned_future::CaughtFuture<
            HandlerOutcome<std::result::Result<T, E>>,
        >,
        hidden: Result<()>,
        map_error: impl FnOnce(E) -> Error,
    ) -> Result<HandlerOutcome<std::result::Result<T, E>>> {
        use crate::failure::owned_future::CaughtFuture;

        if completion.panics.is_empty() {
            let outcome = completion.output.expect("Tool callback lost its outcome");
            return match (outcome, hidden) {
                (HandlerOutcome::Returned(Err(error)), Err(hidden)) => Ok(
                    HandlerOutcome::RuntimeError(map_error(error).with_cleanup(vec![hidden])),
                ),
                (outcome, hidden) => finish_handler_scratch(outcome, hidden),
            };
        }
        let original = match completion.output {
            Some(HandlerOutcome::RuntimeError(error)) => Some(Err(error)),
            Some(HandlerOutcome::Returned(Err(error))) => Some(Err(map_error(error))),
            Some(HandlerOutcome::RunFailed) => Some(Err(Error::RunAborted)),
            _ => None,
        };
        let caught = CaughtFuture {
            output: original,
            panics: completion.panics,
        };
        let error = self
            .finish_tool_execution_completion::<()>(caught, "Tool callback")
            .expect_err("callback panic must remain fatal");
        Ok(HandlerOutcome::RuntimeError(
            error.with_cleanup(hidden.err().into_iter().collect()),
        ))
    }

    /// Recheck after actual callback destruction and typed result mapping.
    /// Nonlocal outcomes keep their existing settlement path; the sticky entry
    /// obligation is routed before the outer boundary publishes or joins.
    async fn finish_entry_handler_completion<T, E>(
        &mut self,
        completion: crate::failure::owned_future::CaughtFuture<
            HandlerOutcome<std::result::Result<T, E>>,
        >,
        hidden: Result<()>,
        map_error: impl Fn(E) -> Error + Copy,
        watch: &crate::entry::driver::EntryDriverWatch,
    ) -> Result<HandlerOutcome<std::result::Result<T, E>>> {
        let outcome = self.finish_handler_completion(completion, hidden, map_error)?;
        let outcome = if let Err(entry) = watch.check() {
            let error = match outcome {
                HandlerOutcome::RuntimeError(error) => {
                    crate::entry::driver::combine_pending::<()>(Err(error), Err(entry)).unwrap_err()
                }
                HandlerOutcome::Returned(Err(error)) => {
                    crate::entry::driver::combine_pending::<()>(Err(map_error(error)), Err(entry))
                        .unwrap_err()
                }
                HandlerOutcome::RunFailed => {
                    crate::entry::driver::combine_pending::<()>(Err(Error::RunAborted), Err(entry))
                        .unwrap_err()
                }
                HandlerOutcome::Returned(Ok(value)) => {
                    // Retain the typed cause while discarding an ordinary success.
                    // A user value destructor must not unwind through that cause.
                    let panics =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value)))
                            .err()
                            .into_iter()
                            .collect();
                    self.finish_tool_execution_completion::<()>(
                        crate::failure::owned_future::CaughtFuture {
                            output: Some(Err(entry)),
                            panics,
                        },
                        "Tool callback result",
                    )
                    .unwrap_err()
                }
                outcome => {
                    // Preserve the actual nonlocal continuation and its settlement
                    // ownership. Routing releases foreign observers first; the
                    // retained cause still stops the next ordinary operation.
                    let _ = self.route_entry_outcome::<()>(Err(entry)).await;
                    return Ok(outcome);
                }
            };
            HandlerOutcome::RuntimeError(error)
        } else {
            outcome
        };
        match outcome {
            HandlerOutcome::RuntimeError(error) => Ok(HandlerOutcome::RuntimeError(
                self.route_entry_outcome::<()>(Err(error))
                    .await
                    .unwrap_err(),
            )),
            outcome => Ok(outcome),
        }
    }

    async fn finish_signal_boundary<G: GlobalTool>(
        &mut self,
        executor: &mut ElfExecutor,
        global: &G,
        outcome: reverie::SignalBoundaryOutcome,
    ) -> Result<()> {
        executor.check_parent_death_failure()?;
        let Some(permit) = executor.owned_delivery_permit() else {
            return Ok(());
        };
        if matches!(
            outcome,
            reverie::SignalBoundaryOutcome::Terminated { group: false, .. }
        ) {
            // This receipt is the Tool's observation of the thread's death, and
            // a Tool may wake a joiner from it. Linux clears CLONE_CHILD_CLEARTID
            // before that death is observable, so the joiner must not see the
            // stale TID word.
            self.clear_worker_tid_before_terminal_receipt(executor);
        }
        if let reverie::SignalBoundaryOutcome::Terminated {
            group: true,
            wait_status,
        } = outcome
        {
            // Publish the already-committed winner before the scheduler wakes
            // any peer's pending RPC. This does not join or run a guest hook.
            self.request_guest_thread_group_exit(ExitStatus::from_raw(wait_status));
        }
        if matches!(outcome, reverie::SignalBoundaryOutcome::Terminated { .. }) {
            // Retire only this task's descriptor references before its terminal
            // receipt. Peers keep their copies and shared-table references until
            // their own cleanup; a process-retirement fence must cover those
            // owners through the leader's final worker join.
            executor.finish_terminal_cleanup().await?;
            self.release_stdin_on_exit();
        }
        // Consuming notification is after the actual frame/register/mask commit,
        // or on owned terminal/image cleanup. It is never an ordinary posthook
        // request and never waits for a guest rt_sigreturn.
        let completion = crate::failure::owned_future::catch_owned_future_from(|| {
            global.on_backend_signal_boundary(reverie::SignalBoundaryReceipt { permit, outcome })
        })
        .await;
        self.tool_panic_owner().finish(
            crate::failure::owned_future::CaughtFuture {
                output: completion
                    .output
                    .map(|result| result.map_err(Error::Reverie)),
                panics: completion.panics,
            },
            "signal boundary receipt",
        )?;
        executor.check_parent_death_boundary(reverie::SignalBoundaryReceipt { permit, outcome })?;
        executor
            .backend_signal_control()
            .process
            .release_delivery(permit)
            .map_err(|errno| Error::Reverie(errno.into()))
    }

    fn prepare_wait_group_exit(
        &mut self,
        executor: &mut ElfExecutor,
        status: ExitStatus,
        starts: &SharedChildStarts,
    ) -> Result<()> {
        executor.validate_child_wait_group_exit(status)?;
        // Keep the existing nonlocal callback child-start settlement, but make
        // the committed group cancellation visible before releasing any gate.
        self.request_guest_thread_group_exit(status);
        self.start_pending_tool_children(executor, starts)
    }

    fn wait_group_exit_status(
        &self,
        executor: &mut ElfExecutor,
        status: ExitStatus,
    ) -> Result<ToolProcessExit> {
        let exit = executor.retire_child_wait_group_exit(status)?;
        self.request_guest_thread_group_exit(exit.status);
        // This is an acknowledgement of the existing group death, not another
        // source of events. Only a previously owned permit can have an empty
        // retained batch; finalization must not recreate removed task authority.
        Ok(ToolProcessExit {
            exit,
            disposition: ToolExitDisposition::CommittedGroupFollower,
        })
    }

    fn cancelled_tool_thread_status(&self, executor: &mut ElfExecutor) -> ToolProcessExit {
        let exit = if let Some(status) = self.guest_thread_group_exit_status() {
            executor.retire_current_thread(status, true)
        } else {
            executor.cancel_current_thread()
        };
        if exit.group {
            self.request_guest_thread_group_exit(exit.status);
        }
        ToolProcessExit {
            exit,
            disposition: ToolExitDisposition::ExplicitCancellation,
        }
    }

    // Retain the exact terminal status without turning retirement of a leader
    // into a request to cancel the still-owned issuer of a later group exit.
    fn retired_tool_thread_status(&self, executor: &mut ElfExecutor) -> Result<ToolProcessExit> {
        executor.validate_signal_retirement(executor.signal_failure_context())?;
        let exit = if let Some(status) = self.guest_thread_group_exit_status() {
            executor.retire_current_thread(status, true)
        } else {
            executor.cancel_current_thread()
        };
        if exit.group {
            self.request_guest_thread_group_exit(exit.status);
        }
        Ok(ToolProcessExit {
            exit,
            disposition: ToolExitDisposition::Retirement,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_tool_process<T: Tool>(
        &mut self,
        executor: &mut ElfExecutor,
        tool: Arc<T>,
        identity: (Pid, Pid),
        global_state: &T::GlobalState,
        config: &<T::GlobalState as GlobalTool>::Config,
        thread_state: T::ThreadState,
        outcome: Result<ToolProcessExit>,
        start_permitted: bool,
        child_exit: Option<crate::vm::OwnChildExitContext>,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let (pid, tid) = identity;
        // Failed exec already reports the joined worker errors as its primary
        // cause. Do not add those same cached diagnostics a second time.
        let (outcome, exec_worker_failure) = match outcome {
            Err(Error::ExecWorkerTeardown(primary)) => (Err(*primary), true),
            outcome => (outcome, false),
        };
        let mut outcome = self.route_entry_outcome(outcome).await;
        // Preserve the committed group's winning status in BOTH the retained
        // death batch and the emitted receipt. Cleanup/cancellation is distinct.
        if let Ok(exit) = &mut outcome {
            exit.commit_guest_death(executor);
        }
        let settlement = self
            .finish_signal_boundary(
                executor,
                global_state,
                match &outcome {
                    Err(_) => reverie::SignalBoundaryOutcome::Failed,
                    Ok(exit) => exit.signal_boundary_outcome(),
                },
            )
            .await;
        let outcome = match (outcome, settlement) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(settlement)) => Err(error.with_cleanup(vec![settlement])),
        };
        if outcome
            .as_ref()
            .is_ok_and(|exit| exit.disposition == ToolExitDisposition::Retirement)
        {
            executor.finish_parked_delivery();
        }
        let outcome = outcome.map_err(|error| executor.with_signal_effects(error, None));
        let outcome = self.route_entry_outcome(outcome).await;
        let outcome = outcome.map_err(|error| self.report_tool_failure("execution", error));
        // These futures own child ThreadState and consuming hooks. They were
        // never polled inside the now-destroyed parent callback. Complete all
        // of them before the parent's hooks can unwrap its shared Tool state.
        let unstarted =
            finish_unstarted_tool_cleanups_with_panics(executor, &self.tool_panic_owner()).await;
        let outcome = match (outcome, unstarted) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(self.report_tool_failure("unstarted-child cleanup", error)),
            (Err(error), Err(cleanup)) => Err(error.with_cleanup(vec![cleanup])),
        };
        let outcome = self
            .route_entry_outcome(outcome)
            .await
            .map_err(|error| self.report_tool_failure("unstarted-child entry cleanup", error));
        let natural_exit = outcome.as_ref().is_ok_and(|exit| exit.joins_live_peers());
        let cancelled_exit = retire_peer_cancelled_tool_worker(
            executor,
            identity,
            start_permitted,
            self.guest_thread_group_exit_status(),
            &outcome,
        );
        if let Some(exit) = cancelled_exit
            && exit.exit.group
        {
            self.request_guest_thread_group_exit(exit.exit.status);
        }
        // Retire the exact task generation before consuming hooks can wake a
        // peer. No guest callback can still borrow Tool or descriptor state.
        if cancelled_exit.is_none() {
            match &outcome {
                Ok(exit) => {
                    executor.retire_current_thread(exit.exit.status, exit.exit.group);
                }
                Err(_) => executor.retire_failed_thread(),
            }
        }
        self.release_thread_slot();
        self.clear_registered_worker_tid_before_exit(executor);
        let cleanup = executor.finish_terminal_cleanup().await;
        self.release_stdin_on_exit();
        let outcome = match (outcome, cleanup) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(error.with_cleanup(vec![cleanup])),
        };
        let outcome = self
            .route_entry_outcome(outcome)
            .await
            .map_err(|error| self.report_tool_failure("thread retirement entry cleanup", error));
        let cancelled_exit = cancelled_exit
            .filter(|_| is_peer_cancelled_tool_worker(identity, start_permitted, &outcome));
        if outcome.is_err() && cancelled_exit.is_none() {
            // A failed worker must interrupt live siblings before a leader's
            // natural join can block on an earlier handle. Cancellation does
            // not supply a guest group-exit status; the original error remains.
            if pid == tid {
                self.cancel_guest_threads_after_failure();
            } else {
                self.record_guest_worker_failure(tid.as_raw());
            }
        } else if pid == tid {
            if natural_exit {
                self.join_guest_threads();
            } else {
                self.cancel_guest_threads();
            }
        }
        let workers = if exec_worker_failure {
            Ok(())
        } else {
            self.guest_worker_teardown_result()
        };
        finish_tool_process_after_workers_with_panics(
            executor,
            tool,
            identity,
            global_state,
            config,
            thread_state,
            outcome,
            cancelled_exit,
            workers,
            self.tool_failure.as_ref(),
            &self.tool_panic_owner(),
            Some(self),
            child_exit,
            start_permitted,
        )
        .await
    }

    /// Consume a constructed child whose start gate was cancelled or whose
    /// host spawn failed. Do not manufacture handle_thread_start or admission.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish_unstarted_tool<T: Tool>(
        &mut self,
        executor: &mut ElfExecutor,
        tool: Arc<T>,
        identity: (Pid, Pid),
        global_state: &T::GlobalState,
        config: &<T::GlobalState as GlobalTool>::Config,
        thread_state: T::ThreadState,
        failure: Option<Error>,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let outcome = match failure {
            Some(error) => Err(error),
            None => Ok(self.cancelled_tool_thread_status(executor)),
        };
        self.finish_tool_process(
            executor,
            tool,
            identity,
            global_state,
            config,
            thread_state,
            outcome,
            false,
            None,
        )
        .await
    }

    /// Releases a worker's reusable slot before its exit becomes visible to
    /// the scheduler. A newly admitted guest thread can then make the same
    /// first-free choice independent of host-thread destruction timing.
    pub(crate) async fn notify_tool_exit<T: Tool>(
        &mut self,
        tool: Arc<T>,
        identity: (Pid, Pid),
        global_state: &T::GlobalState,
        config: &<T::GlobalState as GlobalTool>::Config,
        thread_state: T::ThreadState,
        status: ExitStatus,
    ) -> Result<()> {
        let (pid, tid) = identity;
        if pid == tid {
            // This also covers a terminal lifecycle-hook error, whose caller
            // may not already have joined the workers.
            self.cancel_guest_threads();
        }
        // No guest execution or Tool callback can use this backend's transport
        // or scratch page after a terminal exit has been observed. Release it
        // before on_exit_thread can wake and admit another guest thread.
        self.release_thread_slot();
        let panics = self.tool_panic_owner();
        let result = notify_tool_exit_with_panics(
            tool,
            pid,
            tid,
            global_state,
            config,
            thread_state,
            ToolExit {
                status,
                process_exited: pid == tid,
            },
            self.tool_failure.as_ref(),
            &panics,
        )
        .await;
        // Run the owner's consuming hooks even when an earlier worker failed.
        // Intermediate joins retain errors, so no earlier caller can silently
        // turn the final process result into success.
        match (result, self.guest_worker_teardown_result()) {
            (Ok(()), workers) => workers,
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(workers)) => Err(error.with_cleanup(vec![workers])),
        }
    }

    /// Runs the installed guest program through a shared Reverie `Tool`.
    ///
    /// The executor supplies Linux syscall semantics that a future guest kernel
    /// will provide. Tool lifecycle, typed syscall dispatch, thread state,
    /// global RPC, memory, stack, injection, and tail injection use the same
    /// Reverie contracts as the ptrace backend.
    pub async fn run_with_tool<T, E>(
        &mut self,
        config: <T::GlobalState as GlobalTool>::Config,
        executor: E,
    ) -> Result<T::GlobalState>
    where
        T: Tool,
        E: SyscallExecutor,
    {
        // Any return finishes the run. Only a dropped or unwinding run leaves
        // its backend abandoned.
        let admission = RunAdmission::begin(&self.abandoned_runs)?;
        let global_state = self.run_admitted_with_tool::<T, E>(config, executor).await;
        self.finish_run(admission);
        global_state
    }

    async fn run_admitted_with_tool<T, E>(
        &mut self,
        config: <T::GlobalState as GlobalTool>::Config,
        mut executor: E,
    ) -> Result<T::GlobalState>
    where
        T: Tool,
        E: SyscallExecutor,
    {
        // This public non-ELF loop has no instruction consumer. Establish its
        // ownership locally even if the vCPU previously ran a subscribed Tool.
        self.set_rdtsc_interception(false)?;
        self.set_cpuid_interception(false)?;
        self.vcpu.track_clock()?;
        let tool_stack_top = self.tool_stack_top();
        let pid = Pid::from_raw(self.root_pid);
        let global_state = T::GlobalState::init_global_state(&config).await;
        global_state
            .install_backend_signal_control(None)
            .map_err(Error::Reverie)?;
        let entry_scope = self.start_entry_driver();
        let tool = Arc::new(T::new(pid, &config));
        let subscriptions = T::subscriptions(&config);
        let mut thread_state = tool.init_thread_state(pid, None);
        let memory = self.memory.clone();
        let auxv = Vec::new();
        let stack_checked_out = Arc::new(AtomicBool::new(false));

        let panics = self.tool_panic_owner();
        let execution = async {
            let registers = kvm_registers(self.vcpu.get_regs()?, 0);
            let handler_signal = Arc::new(Mutex::new(None));
            let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
            self.check_entry_owner()?;
            expose_tool_scratch(&memory, tool_stack_top)?;
            let callback_scope = self.begin_entry_callback()?;
            let callback_watch = self.entry_driver_watch();
            let callback_memory = self.memory.clone();
            let start_outcome = {
                let memory = callback_memory;
                let mut guest_executor = DirectSyscallExecutor {
                    executor: &mut executor,
                    vcpu: &self.vcpu,
                };
                let mut guest = KvmGuest::<T>::new(
                    pid,
                    // run_with_tool drives a single root thread (tid == pid).
                    pid,
                    tool.clone(),
                    memory.clone(),
                    &auxv,
                    registers,
                    &mut thread_state,
                    &mut guest_executor,
                    &global_state,
                    None,
                    &config,
                    &subscriptions,
                    handler_signal.clone(),
                    pending_child_starts.clone(),
                    tool_stack_top,
                    stack_checked_out.clone(),
                );
                drive_entry_handler_completion_from(
                    || tool.handle_thread_start(&mut guest),
                    handler_signal,
                    pending_child_starts,
                    wait_for_failure(&global_state, None),
                    callback_watch.clone(),
                )
                .await
            };
            drop(callback_scope);
            self.restore_entry_origin();

            let start_outcome = self
                .finish_entry_handler_completion(
                    start_outcome,
                    hide_tool_scratch(&memory, tool_stack_top),
                    Error::Reverie,
                    &callback_watch,
                )
                .await?;
            match start_outcome {
                HandlerOutcome::Returned(result) => result.map_err(Error::Reverie)?,
                HandlerOutcome::GroupExit(_) => {
                    return Err(Error::UnexpectedVcpuExit(
                        "group wait exit outside a static-ELF process".to_owned(),
                    ));
                }
                HandlerOutcome::ThreadCancelled => {
                    return Ok(ExitStatus::SUCCESS);
                }
                HandlerOutcome::ThreadRetired => {
                    return Ok(ExitStatus::SUCCESS);
                }
                HandlerOutcome::RunFailed => return Err(Error::RunAborted),
                HandlerOutcome::ParkedFatal(_)
                | HandlerOutcome::ParkedCancelled(_)
                | HandlerOutcome::ParkedRetired(_) => {
                    return Err(Error::UnexpectedVcpuExit(
                        "parked outcome outside its original syscall callback".to_owned(),
                    ));
                }
                HandlerOutcome::RuntimeError(error) => return Err(error),
                HandlerOutcome::TailInjected { .. } => {}
            }

            loop {
                self.check_entry_owner()?;
                let changed = memory.entry_gate().subscribe();
                memory
                    .entry_gate()
                    .admit_operation()
                    .map_err(|failure| failure.error())?;
                if wait_for_failure(&global_state, None)
                    .now_or_never()
                    .is_some()
                {
                    return Err(Error::RunAborted);
                }
                let Some(vcpu_exit) = self.vcpu.run()? else {
                    let failure = pin!(wait_for_failure(&global_state, None));
                    let _ = futures::future::select(changed, failure).await;
                    continue;
                };
                Self::record_exit(self.exit_collector.as_deref(), &vcpu_exit);
                match vcpu_exit {
                    VcpuExit::Hypercall(exit) => {
                        if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                            return Err(Error::UnexpectedHypercall(exit.nr));
                        }
                        let frame_address = exit.args[0];
                        let return_slot = std::ptr::from_mut(exit.ret) as usize;
                        let registers = self.vcpu.get_regs()?;
                        let request = SyscallRequest::read_from(&memory, frame_address)?;
                        let syscall = request.into_syscall()?;
                        let subscribed = subscriptions
                            .iter_syscalls()
                            .any(|number| number == syscall.number());
                        let result = if subscribed {
                            // Same `ERESTARTSYS` restart protocol as the
                            // process-syscall path below; see
                            // `classify_handler_result`.
                            loop {
                                let handler_signal = Arc::new(Mutex::new(None));
                                let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
                                self.check_entry_owner()?;
                                expose_tool_scratch(&memory, tool_stack_top)?;
                                let callback_scope = self.begin_entry_callback()?;
                                let callback_watch = self.entry_driver_watch();
                                let callback_memory = self.memory.clone();
                                let outcome = {
                                    let memory = callback_memory;
                                    let mut guest_executor = DirectSyscallExecutor {
                                        executor: &mut executor,
                                        vcpu: &self.vcpu,
                                    };
                                    let mut guest = KvmGuest::<T>::new(
                                        pid,
                                        // run_with_tool drives a single root thread.
                                        pid,
                                        tool.clone(),
                                        memory.clone(),
                                        &auxv,
                                        kvm_registers(registers, request.number()),
                                        &mut thread_state,
                                        &mut guest_executor,
                                        &global_state,
                                        None,
                                        &config,
                                        &subscriptions,
                                        handler_signal.clone(),
                                        pending_child_starts.clone(),
                                        tool_stack_top,
                                        stack_checked_out.clone(),
                                    );
                                    drive_entry_handler_completion_from(
                                        || tool.handle_syscall_event(&mut guest, syscall),
                                        handler_signal,
                                        pending_child_starts,
                                        wait_for_failure(&global_state, None),
                                        callback_watch.clone(),
                                    )
                                    .await
                                };
                                drop(callback_scope);
                                self.restore_entry_origin();

                                let outcome = self
                                    .finish_entry_handler_completion(
                                        outcome,
                                        hide_tool_scratch(&memory, tool_stack_top),
                                        Error::Reverie,
                                        &callback_watch,
                                    )
                                    .await?;
                                break match outcome {
                                    HandlerOutcome::Returned(result) => {
                                        match classify_handler_result(result)? {
                                            Some(raw) => raw,
                                            None => continue,
                                        }
                                    }
                                    HandlerOutcome::TailInjected { result, .. } => {
                                        result_to_raw(result)
                                    }
                                    HandlerOutcome::GroupExit(_) => {
                                        return Err(Error::UnexpectedVcpuExit(
                                            "group wait exit outside a static-ELF process"
                                                .to_owned(),
                                        ));
                                    }
                                    HandlerOutcome::ThreadCancelled => {
                                        return Ok(ExitStatus::SUCCESS);
                                    }
                                    HandlerOutcome::ThreadRetired => {
                                        return Ok(ExitStatus::SUCCESS);
                                    }
                                    HandlerOutcome::RunFailed => return Err(Error::RunAborted),
                                    HandlerOutcome::ParkedFatal(_)
                                    | HandlerOutcome::ParkedCancelled(_)
                                    | HandlerOutcome::ParkedRetired(_) => {
                                        return Err(Error::UnexpectedVcpuExit(
                                            "parked outcome outside its original syscall callback"
                                                .to_owned(),
                                        ));
                                    }
                                    HandlerOutcome::RuntimeError(error) => return Err(error),
                                };
                            }
                        } else {
                            executor.execute(&request, &memory)
                        };
                        self.check_entry_owner()?;
                        // SAFETY: return_slot points into this vCPU's stable KVM_RUN
                        // mapping. The vCPU remains stopped and is not run again while
                        // the tool callback is active.
                        unsafe {
                            (return_slot as *mut u64).write(result as u64);
                        }
                    }
                    VcpuExit::Hlt => {
                        return Ok(ExitStatus::SUCCESS);
                    }
                    exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
                }
            }
        };
        let outcome: Result<ExitStatus> = panics.finish(
            crate::failure::owned_future::catch_owned_future(execution).await,
            "direct Tool execution",
        );
        self.restore_entry_origin();
        let entry_was_failed = self.check_entry_owner().is_err();
        let outcome = self.route_entry_outcome(outcome).await;
        if outcome.is_err() {
            global_state.report_backend_failure(reverie::BackendFailure {
                pid,
                tid: pid,
                phase: "direct Tool execution",
            });
        }
        let status = outcome.as_ref().copied().unwrap_or(ExitStatus::Exited(255));
        let cleanup = self
            .notify_tool_exit(
                tool,
                (pid, pid),
                &global_state,
                &config,
                thread_state,
                status,
            )
            .await;
        let result = Error::combine(
            [outcome.map(|_| ()), cleanup]
                .into_iter()
                .filter_map(Result::err)
                .collect(),
        );
        let late_entry = !entry_was_failed && self.check_entry_owner().is_err();
        let result = self.route_entry_outcome(result).await;
        let before_retirement_ok = result.is_ok();
        let result = self.finish_entry_driver(entry_scope, result);
        if (late_entry || before_retirement_ok) && result.is_err() {
            global_state.report_backend_failure(reverie::BackendFailure {
                pid,
                tid: pid,
                phase: "direct entry completion",
            });
        }
        self.finish_public_tool_panic(result, None)?;
        Ok(global_state)
    }

    /// Runs an installed static ELF through a Reverie `Tool`.
    ///
    /// This is the integration of the M1 ELF guest kernel
    /// ([`Self::run_static_elf`]) with the tool-interception path of
    /// [`Self::run_with_tool`]. A static ELF loaded by
    /// [`Self::install_static_elf`]/[`Self::install_static_elf_with_args`] runs
    /// in long mode. Root-thread syscalls selected by the tool's subscriptions
    /// are delivered to `Tool::handle_syscall_event`, including deferred
    /// fork/clone/exec/wait operations. A successful injected exec replaces the
    /// image without resuming the old handler. Forked process children receive
    /// their own process/thread tool state and dispatch subscribed syscalls through
    /// the same global state. `CLONE_THREAD` workers are Tool-owned by default and
    /// may explicitly opt into host ownership through the existing thread-ownership
    /// contract. Tool `inject`/`tail_inject` calls are serviced by the ELF guest kernel
    /// (`ElfExecutor`). Unlike [`Self::run_with_tool`], results are written
    /// back into the guest's syscall frame (the trampoline reads them and
    /// `SYSRET`s) and the guest exits via `exit`/`exit_group` rather than `HLT`.
    ///
    /// Returns the tool's global state, guest exit code, stdout, and stderr.
    pub async fn run_static_elf_with_tool<T>(
        &mut self,
        config: <T::GlobalState as GlobalTool>::Config,
        capture_output: bool,
    ) -> Result<(T::GlobalState, i32, Vec<u8>, Vec<u8>)>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        let completion = self
            .run_static_elf_with_tool_completion::<T>(config, capture_output)
            .await?;
        let (status, stdout, stderr) = completion.result?;
        Ok((completion.global_state, status, stdout, stderr))
    }

    /// Runs the installed ELF and retains GlobalState even after a runtime
    /// failure, so its owner can finish scheduler/global cleanup. An outer
    /// error means setup failed before the global state existed, or ownership
    /// could not be recovered after all owned children were joined.
    pub async fn run_static_elf_with_tool_completion<T>(
        &mut self,
        config: <T::GlobalState as GlobalTool>::Config,
        capture_output: bool,
    ) -> Result<ToolRunCompletion<T::GlobalState>>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        // Any return, including a setup error, finishes the run. Only a
        // dropped or unwinding run leaves its backend abandoned.
        let admission = RunAdmission::begin(&self.abandoned_runs)?;
        let completion = self
            .run_admitted_static_elf_with_tool::<T>(&admission, config, capture_output)
            .await;
        self.finish_run(admission);
        completion
    }

    async fn run_admitted_static_elf_with_tool<T>(
        &mut self,
        admission: &RunAdmission,
        config: <T::GlobalState as GlobalTool>::Config,
        capture_output: bool,
    ) -> Result<ToolRunCompletion<T::GlobalState>>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        // Resolve thread ownership before any CLONE_THREAD worker is created: an
        // explicit caller override wins, otherwise follow the tool's
        // `Tool::thread_ownership` (default: Tool-owned "follow children"). This
        // is why the KVM backend no longer needs the caller to opt threads in.
        self.resolve_thread_ownership(T::thread_ownership(&config));
        if T::observe_signal_dequeues(&config) && self.thread_ownership.executes_on_host() {
            // This combination is known before GlobalState initialization or
            // consuming the installed image. An uninstrumented worker has no
            // removing Guest on which to acknowledge its pending-state effects.
            return Err(Error::SignalObservationRequiresToolThreads);
        }
        self.admit_host_metadata_timestamps(self.thread_ownership.executes_on_tool())?;
        // Capture setup can fail before image consumption or any Tool state.
        // Keep this root owner until the later executor and its workers retire.
        let capture_owner = self.prepare_captured_output(capture_output)?;
        let mut loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        // Output capture replaces stdout and stderr with the executor's pipes,
        // but an explicitly configured stdin remains the guest's input. Use
        // /dev/null only when the caller supplied no stdin, matching
        // `run_static_elf_captured` while keeping the no-input default.
        if capture_output && loaded.stdin.is_none() {
            loaded.stdin = Some(std::fs::File::open("/dev/null")?);
        }
        let pid = Pid::from_raw(self.root_pid);
        let global_state = Arc::new(T::GlobalState::init_global_state(&config).await);
        let failure = RunFailure::new(&global_state);
        self.set_tool_failure(Some(FailureContext::new(failure.clone(), pid, pid)));
        let entry_scope = self.start_entry_driver();
        let executor = ElfExecutor::with_output(loaded, capture_owner.clone());
        // Atomic run-level installation precedes Tool/thread construction and
        // the first handle_thread_start. No capability is inferred from a PID.
        let mode = match global_state
            .install_backend_signal_control(Some(executor.backend_signal_control()))
        {
            Ok(mode) => mode,
            Err(error) => {
                let context = FailureContext::new(failure.clone(), pid, pid);
                let result = self
                    .route_entry_outcome::<()>(Err(Error::Reverie(error)))
                    .await;
                let error = context.publish(
                    "process signal control installation",
                    self.finish_entry_driver(entry_scope, result).unwrap_err(),
                );
                self.set_tool_failure(None);
                let global_state = Arc::try_unwrap(global_state).map_err(|_| {
                    Error::UnexpectedVcpuExit("signal setup retained GlobalState".to_owned())
                })?;
                return Ok(ToolRunCompletion {
                    global_state,
                    result: Err(error),
                });
            }
        };
        executor.install_signal_control(mode, &failure);
        let tool = Arc::new(T::new(pid, &config));
        let subscriptions = T::subscriptions(&config);
        let thread_state = tool.init_thread_state(pid, None);
        let mut root = admission.root(executor);
        if let Some(client) = self.native_exit_broker.clone() {
            root.configure_terminal_cleanup(
                admission.terminal_factory(client),
                self.stdin.clone(),
            )?;
        }
        let result = self
            .run_static_elf_process_with_tool(
                &mut root,
                pid,
                // The root process leader has tid == pid.
                pid,
                tool,
                thread_state,
                global_state.clone(),
                &config,
                &subscriptions,
                true,
                None,
            )
            .await;
        let executor = root.returned();
        let result = match (result, executor.take_process_publication_failure()) {
            (result, None) => result,
            (Ok(_), Some(publication)) => Err(publication),
            (Err(error), Some(publication)) => Err(error.with_cleanup(vec![publication])),
        };
        let result = self.route_entry_outcome(result).await;
        let result = self
            .finish_entry_driver(entry_scope, result)
            .map_err(|error| self.report_tool_failure("entry driver completion", error));
        // All owned children have returned. Do not leave the backend holding
        // a reporter whose Weak owner is about to be consumed or released.
        self.set_tool_failure(None);
        let global_state = match Arc::try_unwrap(global_state) {
            Ok(global) => global,
            Err(_) => {
                let ownership = Error::UnexpectedVcpuExit(
                    "KVM child retained global Tool state after exit".to_owned(),
                );
                let result = Err(match result {
                    Err(primary) => primary.with_cleanup(vec![ownership]),
                    Ok(_) => ownership,
                });
                return self
                    .finish_public_tool_panic(failure.complete(result), Some(failure.clone()));
            }
        };
        let result = failure
            .complete(result)
            .map(|(status, stdout, stderr)| (conventional_exit_code(status), stdout, stderr));
        let result = self.finish_public_tool_panic(result, Some(failure.clone()));
        Ok(ToolRunCompletion {
            global_state,
            result,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn filter_one_pending_signal_with_tool<T>(
        &mut self,
        executor: &mut ElfExecutor,
        pid: Pid,
        tid: Pid,
        tool: &Arc<T>,
        memory: &GuestMemory,
        auxv: &[(libc::c_ulong, libc::c_ulong)],
        registers: kvm_regs,
        syscall_number: u64,
        frame_address: u64,
        thread_state: &mut T::ThreadState,
        global_state: &Arc<T::GlobalState>,
        config: &<T::GlobalState as GlobalTool>::Config,
        subscriptions: &Subscription,
        stack_checked_out: &Arc<AtomicBool>,
        thread_entry: bool,
    ) -> Result<CallbackOutcome<Option<PendingSignal>>>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        // Linux repeats signal selection on the same exit-to-user path when a
        // tracer suppresses a signal or the replacement disposition ignores
        // it. There are at most two standard-signal domains of 31 entries; the
        // bound also prevents a Tool that keeps generating events from
        // monopolizing this boundary forever.
        for _ in 0..64 {
            let pending = self
                .filter_next_pending_signal_with_tool(
                    executor,
                    pid,
                    tid,
                    tool,
                    memory,
                    auxv,
                    registers,
                    syscall_number,
                    frame_address,
                    thread_state,
                    global_state,
                    config,
                    subscriptions,
                    stack_checked_out,
                    None,
                    thread_entry,
                )
                .await?;
            if matches!(
                pending,
                CallbackOutcome::ThreadCancelled
                    | CallbackOutcome::GroupExit(_)
                    | CallbackOutcome::ThreadRetired
                    | CallbackOutcome::Completed(Some(_))
            ) || executor.has_pending_exit()
                || !executor.has_eligible_pending_signal()
            {
                return Ok(pending);
            }
        }
        Err(Error::UnexpectedVcpuExit(
            "KVM signal hook exhausted one return boundary without selecting delivery".to_owned(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn filter_next_pending_signal_with_tool<T>(
        &mut self,
        executor: &mut ElfExecutor,
        pid: Pid,
        tid: Pid,
        tool: &Arc<T>,
        memory: &GuestMemory,
        auxv: &[(libc::c_ulong, libc::c_ulong)],
        registers: kvm_regs,
        syscall_number: u64,
        frame_address: u64,
        thread_state: &mut T::ThreadState,
        global_state: &Arc<T::GlobalState>,
        config: &<T::GlobalState as GlobalTool>::Config,
        subscriptions: &Subscription,
        stack_checked_out: &Arc<AtomicBool>,
        fault: Option<&PageZeroFault>,
        thread_entry: bool,
    ) -> Result<CallbackOutcome<Option<PendingSignal>>>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        if fault.is_none() && executor.signal_controlled() && executor.delivery_permit().is_none() {
            let identity = executor.signal_task_identity().ok_or_else(|| {
                Error::UnexpectedVcpuExit("signal return lost task generation".to_owned())
            })?;
            let permit = global_state
                .authorize_backend_signal_boundary(identity)
                .map_err(Error::Reverie)?;
            if permit.is_none() {
                return Ok(CallbackOutcome::Completed(None));
            }
            if executor.delivery_permit() != permit {
                return Err(Error::UnexpectedVcpuExit(
                    "unregistered signal return permit".to_owned(),
                ));
            }
        }
        let selected = if let Some(fault) = fault {
            Ok(Some(fault.pending()))
        } else {
            executor.take_pending_signal_for_delivery()
        };
        flush_pending_signal_effects_with_tool(
            self,
            executor,
            pid,
            tid,
            tool,
            memory,
            auxv,
            fault.map_or_else(
                || kvm_registers(registers, syscall_number),
                PageZeroFault::user_registers,
            ),
            thread_state,
            global_state,
            config,
            subscriptions,
            stack_checked_out,
            None,
        )
        .await?;
        let Some(pending) = selected.map_err(|errno| Error::Reverie(errno.into()))? else {
            return Ok(CallbackOutcome::Completed(None));
        };

        let handler_signal = Arc::new(Mutex::new(None));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        let mut process_completed = false;
        let tool_stack_top = self.tool_stack_top();
        let failure_subscription = self.failure_subscription(executor.is_traced_tree_root());
        self.check_entry_owner()?;
        expose_tool_scratch(memory, tool_stack_top)?;
        let process_context = if let Some(fault) = fault {
            ProcessExecutionContext::FaultBoundary(Box::new(fault.clone()))
        } else if thread_entry {
            ProcessExecutionContext::ThreadEntrySignal
        } else {
            let mut stop = pin!(wait_for_failure(
                global_state.as_ref(),
                failure_subscription.clone(),
            ));
            let Some(boundary) = CompletedSyscallBoundary::capture_admitted(
                self,
                frame_address,
                Some(registers),
                stop.as_mut(),
            )
            .await?
            else {
                hide_tool_scratch(memory, tool_stack_top)?;
                return Ok(CallbackOutcome::ThreadCancelled);
            };
            ProcessExecutionContext::SignalBoundary(boundary)
        };
        let continuation_site = executor
            .signal_failure_context()
            .map(|context| context.site);
        let callback_scope = self.begin_entry_callback()?;
        let callback_watch = self.entry_driver_watch();
        let callback_memory = self.memory.clone();
        executor.bind_address_space(&callback_memory);
        let outcome = {
            let memory = callback_memory;
            let mut guest_executor = StaticElfSyscallExecutor {
                backend: self,
                executor,
                memory: memory.clone(),
                process_context,
                callback_site: continuation_site,
                original_syscall: None,
                signal_guard: SignalGuard::Ordinary,
                last_result: None,
                polled_read_attempt: None,
                process_completed: &mut process_completed,
            };
            let mut guest = KvmGuest::<T>::new(
                pid,
                tid,
                tool.clone(),
                memory.clone(),
                auxv,
                fault.map_or_else(
                    || kvm_registers(registers, syscall_number),
                    PageZeroFault::user_registers,
                ),
                thread_state,
                &mut guest_executor,
                global_state.as_ref(),
                Some(global_state.clone()),
                config,
                subscriptions,
                handler_signal.clone(),
                pending_child_starts.clone(),
                tool_stack_top,
                stack_checked_out.clone(),
            );
            drive_entry_handler_completion_from(
                || tool.handle_structured_signal_event(&mut guest, pending.event),
                handler_signal,
                pending_child_starts.clone(),
                wait_for_failure(global_state.as_ref(), failure_subscription.clone()),
                callback_watch.clone(),
            )
            .await
        };
        drop(callback_scope);
        self.restore_entry_origin();
        executor.bind_address_space(&self.memory);

        let outcome = self
            .finish_entry_handler_completion(
                outcome,
                hide_tool_scratch(memory, tool_stack_top),
                |error| Error::Reverie(error.into()),
                &callback_watch,
            )
            .await?;
        let replacement = match outcome {
            HandlerOutcome::Returned(Ok(replacement)) => replacement,
            HandlerOutcome::Returned(Err(errno)) => {
                let error = self.cleanup_unstarted_tool_children_after_error(
                    executor,
                    &pending_child_starts,
                    Error::Reverie(errno.into()),
                );
                return Err(error);
            }
            HandlerOutcome::ParkedRetired(context) => {
                executor.validate_signal_retirement(Some(context))?;
                self.start_pending_tool_children(executor, &pending_child_starts)?;
                return Ok(CallbackOutcome::ThreadRetired);
            }
            HandlerOutcome::GroupExit(status) => {
                self.prepare_wait_group_exit(executor, status, &pending_child_starts)?;
                return Ok(CallbackOutcome::GroupExit(status));
            }
            HandlerOutcome::ThreadCancelled => {
                self.start_pending_tool_children(executor, &pending_child_starts)?;
                return Ok(CallbackOutcome::ThreadCancelled);
            }
            HandlerOutcome::ThreadRetired => {
                self.start_pending_tool_children(executor, &pending_child_starts)?;
                return Ok(CallbackOutcome::ThreadRetired);
            }
            HandlerOutcome::RunFailed => {
                return Err(self.cleanup_unstarted_tool_children_after_error(
                    executor,
                    &pending_child_starts,
                    Error::RunAborted,
                ));
            }
            HandlerOutcome::ParkedFatal(_) | HandlerOutcome::ParkedCancelled(_) => {
                return Err(Error::UnexpectedVcpuExit(
                    "parked outcome outside its original syscall callback".to_owned(),
                ));
            }
            HandlerOutcome::RuntimeError(error) => {
                return Err(self.cleanup_unstarted_tool_children_after_error(
                    executor,
                    &pending_child_starts,
                    error,
                ));
            }
            HandlerOutcome::TailInjected { .. } => {
                let error = Error::UnexpectedVcpuExit(
                    "tail injection from a KVM signal hook is unsupported".to_owned(),
                );
                return Err(self.cleanup_unstarted_tool_children_after_error(
                    executor,
                    &pending_child_starts,
                    error,
                ));
            }
        };
        self.start_pending_tool_children(executor, &pending_child_starts)?;
        if executor.take_process_action().is_some() {
            return Err(Error::UnexpectedVcpuExit(
                "process action from a KVM signal hook is unsupported".to_owned(),
            ));
        }
        match replacement {
            Some(event) => {
                let pending = if let Some(fault) = fault.filter(|fault| event == fault.event) {
                    Some(fault.pending())
                } else {
                    executor
                        .prepare_filtered_signal_delivery(event, pending.domain)
                        .map_err(|errno| Error::Reverie(errno.into()))?
                };
                if pending.is_some_and(|pending| {
                    executor.signal_disposition(pending.event.signal())
                        == crate::executor::SignalDisposition::Ignore
                }) {
                    Ok(CallbackOutcome::Completed(None))
                } else {
                    Ok(CallbackOutcome::Completed(pending))
                }
            }
            None => Ok(CallbackOutcome::Completed(None)),
        }
    }

    // TODO-HUMAN-REVIEW(PR-192): Review recursive KVM process Tool runtime.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_static_elf_process_with_tool<T>(
        &mut self,
        executor: &mut ElfExecutor,
        pid: Pid,
        tid: Pid,
        tool: Arc<T>,
        mut thread_state: T::ThreadState,
        global_state: Arc<T::GlobalState>,
        config: &<T::GlobalState as GlobalTool>::Config,
        subscriptions: &Subscription,
        initial_post_exec: bool,
        child_exit: Option<crate::vm::OwnChildExitContext>,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        if let Some(failure) = &self.tool_failure {
            self.set_tool_failure(Some(failure.for_thread(tid)));
        }
        executor.observe_ignored_signals_with_tool();
        if T::observe_signal_dequeues(config) {
            executor.enable_signal_dequeues();
        }
        let tool_stack_top = self.tool_stack_top();
        let failure_subscription = self.failure_subscription(executor.is_traced_tree_root());
        let mut _registration = None;
        let mut auxv = executor.auxv().to_vec();
        // Clones share the MAP_SHARED guest mapping; a mutable handle lets the
        // loop write syscall results back into the guest's frame.
        let mut memory = self.memory.clone();
        let stack_checked_out = Arc::new(AtomicBool::new(false));

        let handler_signal = Arc::new(Mutex::new(None));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        let mut _process_completed = false;
        let execution = async {
            // Host cleanup capability must be genuinely ready before the first
            // guest hook. Resource setup failure is a run failure, not a late
            // guest-exit fallback to ordinary socket close.
            executor.ready_terminal_cleanup().await?;
            // Each actual Tool consumer admits its own subscription before
            // any user instruction. New fork/thread vCPUs start unarmed; the
            // tool-less Host worker loop never inherits trapping without a hook.
            self.set_rdtsc_interception(subscriptions.has_rdtsc())?;
            self.set_cpuid_interception(subscriptions.has_cpuid())?;
            self.vcpu.track_clock()?;
            _registration = Some(self.register_guest_thread()?);
            let registers = kvm_registers(self.vcpu.get_regs()?, 0);
            self.check_entry_owner()?;
            expose_tool_scratch(&memory, tool_stack_top)?;
            let callback_scope = self.begin_entry_callback()?;
            let callback_watch = self.entry_driver_watch();
            let callback_memory = self.memory.clone();
            executor.bind_address_space(&callback_memory);
            let start_outcome = {
                let memory = callback_memory;
                let mut guest_executor = StaticElfSyscallExecutor {
                    backend: self,
                    executor,
                    memory: memory.clone(),
                    process_context: ProcessExecutionContext::Lifecycle,
                    callback_site: None,
                    original_syscall: None,
                    signal_guard: SignalGuard::Ordinary,
                    last_result: None,
                    polled_read_attempt: None,
                    process_completed: &mut _process_completed,
                };
                let mut guest = KvmGuest::<T>::new(
                    pid,
                    tid,
                    tool.clone(),
                    memory.clone(),
                    &auxv,
                    registers,
                    &mut thread_state,
                    &mut guest_executor,
                    global_state.as_ref(),
                    Some(global_state.clone()),
                    config,
                    subscriptions,
                    handler_signal.clone(),
                    pending_child_starts.clone(),
                    tool_stack_top,
                    stack_checked_out.clone(),
                );
                drive_entry_handler_completion_from(
                    || tool.handle_thread_start(&mut guest),
                    handler_signal,
                    pending_child_starts.clone(),
                    wait_for_failure(global_state.as_ref(), failure_subscription.clone()),
                    callback_watch.clone(),
                )
                .await
            };
            drop(callback_scope);
            self.restore_entry_origin();
            executor.bind_address_space(&self.memory);

            let start_outcome = self
                .finish_entry_handler_completion(
                    start_outcome,
                    hide_tool_scratch(&memory, tool_stack_top),
                    Error::Reverie,
                    &callback_watch,
                )
                .await?;
            match start_outcome {
                HandlerOutcome::GroupExit(status) => {
                    self.prepare_wait_group_exit(executor, status, &pending_child_starts)?;
                    return self.wait_group_exit_status(executor, status);
                }
                HandlerOutcome::ThreadCancelled => {
                    self.start_pending_tool_children(executor, &pending_child_starts)?;
                    return Ok(self.cancelled_tool_thread_status(executor));
                }
                HandlerOutcome::ThreadRetired => {
                    self.start_pending_tool_children(executor, &pending_child_starts)?;
                    return self.retired_tool_thread_status(executor);
                }
                HandlerOutcome::Returned(result) => result.map_err(Error::Reverie)?,
                HandlerOutcome::RunFailed => return Err(Error::RunAborted),
                HandlerOutcome::ParkedFatal(_)
                | HandlerOutcome::ParkedCancelled(_)
                | HandlerOutcome::ParkedRetired(_) => {
                    return Err(Error::UnexpectedVcpuExit(
                        "parked outcome outside its original syscall callback".to_owned(),
                    ));
                }
                HandlerOutcome::RuntimeError(error) => return Err(error),
                HandlerOutcome::TailInjected { .. } => {}
            }
            if self.guest_thread_is_cancelled() {
                // The parent releases the start gate after it has begun scheduler
                // registration. handle_thread_start completes the child-side
                // ordering. Preserve handle_thread_start -> on_exit ordering,
                // but do not execute post-exec hooks or a guest instruction after
                // cancellation. Clear CHILD_CLEARTID immediately before the Tool
                // exit callback; the worker wrapper then observes that the address
                // has already been consumed.
                return Ok(self.cancelled_tool_thread_status(executor));
            }
            auxv = executor.auxv().to_vec();
            if let Some(exit) = executor.take_exit() {
                if exit.group {
                    self.request_guest_thread_group_exit(exit.status);
                }
                return Ok(exit.into());
            }

            if initial_post_exec {
                // The root ELF image is already installed when this backend begins.
                // Present the same initial exec syscall and successful-exec lifecycle
                // boundaries as ptrace without loading the installed image twice.
                if subscriptions
                    .iter_syscalls()
                    .any(|number| number == reverie::syscalls::Sysno::execve)
                {
                    let initial_outcome = run_initial_exec_handler(
                        self,
                        &tool,
                        pid,
                        &memory,
                        &auxv,
                        &mut thread_state,
                        executor,
                        &global_state,
                        config,
                        subscriptions,
                        &stack_checked_out,
                    )
                    .await?;
                    if let CallbackOutcome::GroupExit(status) = initial_outcome {
                        return self.wait_group_exit_status(executor, status);
                    }
                    if matches!(initial_outcome, CallbackOutcome::ThreadCancelled) {
                        return Ok(self.cancelled_tool_thread_status(executor));
                    }
                    if matches!(initial_outcome, CallbackOutcome::ThreadRetired) {
                        return self.retired_tool_thread_status(executor);
                    }
                    auxv = executor.auxv().to_vec();
                    if let Some(exit) = executor.take_exit() {
                        if exit.group {
                            self.request_guest_thread_group_exit(exit.status);
                        }
                        return Ok(exit.into());
                    }
                }
                let post_exec_outcome = run_post_exec_handler(
                    self,
                    &tool,
                    pid,
                    &memory,
                    &mut auxv,
                    &mut thread_state,
                    executor,
                    global_state.clone(),
                    config,
                    subscriptions,
                    &stack_checked_out,
                )
                .await;
                let post_exec_error = match post_exec_outcome {
                    Ok(CallbackOutcome::GroupExit(status)) => {
                        return self.wait_group_exit_status(executor, status);
                    }
                    Ok(CallbackOutcome::ThreadCancelled) => {
                        return Ok(self.cancelled_tool_thread_status(executor));
                    }
                    Ok(CallbackOutcome::ThreadRetired) => {
                        return self.retired_tool_thread_status(executor);
                    }
                    Ok(CallbackOutcome::Completed(())) => None,
                    Err(error) => Some(error),
                };
                if let Some(error) = post_exec_error {
                    return Err(error);
                }
            }

            // CLONE_THREAD has a complete user continuation before its first
            // KVM_RUN. Admission comes first; then deliver an already queued event
            // without executing a synthetic guest syscall or the child's first
            // instruction. Root/exec lifecycle contexts keep their existing limit.
            if pid != tid && executor.has_eligible_pending_signal() {
                let entry_registers = self.vcpu.get_regs()?;
                executor.set_current_user_stack_pointer(entry_registers.rsp);
                let pending = self
                    .filter_one_pending_signal_with_tool(
                        executor,
                        pid,
                        tid,
                        &tool,
                        &memory,
                        &auxv,
                        entry_registers,
                        u64::MAX,
                        self.syscall_frame_address,
                        &mut thread_state,
                        &global_state,
                        config,
                        subscriptions,
                        &stack_checked_out,
                        true,
                    )
                    .await?;
                let pending = match pending {
                    CallbackOutcome::Completed(pending) => pending,
                    CallbackOutcome::GroupExit(status) => {
                        return self.wait_group_exit_status(executor, status);
                    }
                    CallbackOutcome::ThreadCancelled => {
                        return Ok(self.cancelled_tool_thread_status(executor));
                    }
                    CallbackOutcome::ThreadRetired => {
                        return self.retired_tool_thread_status(executor);
                    }
                };
                let delivered = if !executor.has_pending_exit()
                    && let Some(pending) = pending
                {
                    self.deliver_selected_signal_before_thread_entry(
                        executor,
                        entry_registers,
                        pending,
                    )?
                } else {
                    false
                };
                let exit = executor.take_exit();
                let outcome = if let Some(exit) = exit {
                    exit.signal_boundary_outcome()
                } else if delivered {
                    reverie::SignalBoundaryOutcome::Caught
                } else {
                    reverie::SignalBoundaryOutcome::NoHandler
                };
                self.finish_signal_boundary(executor, global_state.as_ref(), outcome)
                    .await?;
                if let Some(exit) = exit {
                    if exit.group {
                        self.request_guest_thread_group_exit(exit.status);
                    }
                    return Ok(exit.into());
                }
            }

            if let Some((segment, address)) = executor.take_segment() {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }
            if let Some(exit) = executor.take_exit() {
                if exit.group {
                    self.request_guest_thread_group_exit(exit.status);
                }
                return Ok(exit.into());
            }

            // Read once so the per-syscall classifier can borrow it while `self` is
            // borrowed elsewhere in the loop body.
            let thread_ownership = self.thread_ownership;
            loop {
                self.check_entry_owner()?;
                #[cfg(test)]
                entry_wait_observation::observe(
                    entry_wait_observation::Site::ToolMain,
                    entry_wait_observation::Boundary::BeforeSubscription,
                );
                let changed = memory.entry_gate().subscribe();
                let cancelled = self.entry_cancellation();
                #[cfg(test)]
                entry_wait_observation::observe(
                    entry_wait_observation::Site::ToolMain,
                    entry_wait_observation::Boundary::AfterSubscription,
                );
                memory
                    .entry_gate()
                    .admit_operation()
                    .map_err(|failure| failure.error())?;
                if wait_for_failure(global_state.as_ref(), failure_subscription.clone())
                    .now_or_never()
                    .is_some()
                {
                    return Err(Error::RunAborted);
                }
                if let Some(status) = self.guest_thread_group_exit_status() {
                    return Ok(ProcessExit {
                        status,
                        group: true,
                    }
                    .into());
                }
                if self.guest_thread_is_cancelled() {
                    return Ok(self.cancelled_tool_thread_status(executor));
                }
                let vcpu_exit = match self.vcpu.run() {
                    Ok(Some(exit)) => exit,
                    Ok(None) => {
                        let stop = pin!(wait_for_failure(
                            global_state.as_ref(),
                            failure_subscription.clone()
                        ));
                        let _ = futures::future::select(
                            futures::future::select(changed, cancelled),
                            stop,
                        )
                        .await;
                        continue;
                    }
                    Err(Error::Kvm(error)) if error.errno() == libc::EINTR => continue,
                    Err(error) => return Err(error),
                };
                Self::record_exit(self.exit_collector.as_deref(), &vcpu_exit);
                let (frame_address, return_slot) = match vcpu_exit {
                    VcpuExit::Hypercall(exit) => {
                        if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                            return Err(Error::UnexpectedHypercall(exit.nr));
                        }
                        (exit.args[0], std::ptr::from_mut(exit.ret) as usize)
                    }
                    VcpuExit::Hlt => {
                        if let Some(boundary) = self.tool_instruction_exception()? {
                            executor.set_current_user_stack_pointer(boundary.user_registers().rsp);
                            let handler_signal = Arc::new(Mutex::new(None));
                            let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
                            let mut process_completed = false;
                            self.check_entry_owner()?;
                            expose_tool_scratch(&memory, tool_stack_top)?;
                            let callback_scope = self.begin_entry_callback()?;
                            let callback_watch = self.entry_driver_watch();
                            let callback_memory = self.memory.clone();
                            executor.bind_address_space(&callback_memory);
                            let result = {
                                let memory = callback_memory;
                                let mut guest_executor = StaticElfSyscallExecutor {
                                    backend: self,
                                    executor,
                                    memory: memory.clone(),
                                    process_context: ProcessExecutionContext::Instruction,
                                    callback_site: None,
                                    original_syscall: None,
                                    signal_guard: SignalGuard::Ordinary,
                                    last_result: None,
                                    polled_read_attempt: None,
                                    process_completed: &mut process_completed,
                                };
                                let mut guest = KvmGuest::<T>::new(
                                    pid,
                                    tid,
                                    tool.clone(),
                                    memory.clone(),
                                    &auxv,
                                    boundary.user_registers(),
                                    &mut thread_state,
                                    &mut guest_executor,
                                    global_state.as_ref(),
                                    Some(global_state.clone()),
                                    config,
                                    subscriptions,
                                    handler_signal.clone(),
                                    pending_child_starts.clone(),
                                    tool_stack_top,
                                    stack_checked_out.clone(),
                                );
                                match &boundary {
                                    crate::vm::ToolInstructionBoundary::Timestamp(boundary) => {
                                        let completion = drive_entry_handler_completion_from(
                                            || {
                                                tool.handle_rdtsc_event(
                                                    &mut guest,
                                                    boundary.instruction.request,
                                                )
                                            },
                                            handler_signal,
                                            pending_child_starts.clone(),
                                            wait_for_failure(
                                                global_state.as_ref(),
                                                failure_subscription.clone(),
                                            ),
                                            callback_watch.clone(),
                                        )
                                        .await;
                                        map_handler_completion(completion, |result| {
                                            result.map(crate::vm::ToolInstructionResult::Timestamp)
                                        })
                                    }
                                    crate::vm::ToolInstructionBoundary::Cpuid(boundary) => {
                                        let completion = drive_entry_handler_completion_from(
                                            || {
                                                tool.handle_cpuid_event(
                                                    &mut guest,
                                                    boundary.registers.rax as u32,
                                                    boundary.registers.rcx as u32,
                                                )
                                            },
                                            handler_signal,
                                            pending_child_starts.clone(),
                                            wait_for_failure(
                                                global_state.as_ref(),
                                                failure_subscription.clone(),
                                            ),
                                            callback_watch.clone(),
                                        )
                                        .await;
                                        map_handler_completion(completion, |result| {
                                            result.map(crate::vm::ToolInstructionResult::Cpuid)
                                        })
                                    }
                                }
                            };
                            drop(callback_scope);
                            self.restore_entry_origin();
                            executor.bind_address_space(&self.memory);

                            // Hide scratch even on callback failure. The outer
                            // process supervisor retains any committed effects.
                            let hidden = hide_tool_scratch(&memory, tool_stack_top);
                            let result = self
                                .finish_entry_handler_completion(
                                    result,
                                    Ok(()),
                                    |error| Error::Reverie(error.into()),
                                    &callback_watch,
                                )
                                .await?;
                            let value = match result {
                                HandlerOutcome::Returned(Ok(value)) => value,
                                HandlerOutcome::Returned(Err(error)) => {
                                    return Err(Error::Reverie(error.into())
                                        .with_cleanup(hidden.err().into_iter().collect()));
                                }
                                HandlerOutcome::GroupExit(status) => {
                                    hidden?;
                                    self.prepare_wait_group_exit(
                                        executor,
                                        status,
                                        &pending_child_starts,
                                    )?;
                                    return self.wait_group_exit_status(executor, status);
                                }
                                HandlerOutcome::ThreadCancelled => {
                                    hidden?;
                                    return Ok(self.cancelled_tool_thread_status(executor));
                                }
                                HandlerOutcome::ThreadRetired => {
                                    hidden?;
                                    return self.retired_tool_thread_status(executor);
                                }
                                HandlerOutcome::RunFailed => {
                                    return Err(Error::RunAborted
                                        .with_cleanup(hidden.err().into_iter().collect()));
                                }
                                HandlerOutcome::RuntimeError(error) => {
                                    return Err(
                                        error.with_cleanup(hidden.err().into_iter().collect())
                                    );
                                }
                                HandlerOutcome::TailInjected {
                                    result: Ok(_),
                                    image_replaced: false,
                                    process_exited: true,
                                } => {
                                    hidden?;
                                    let exit = executor.take_exit().ok_or_else(|| {
                                        Error::UnexpectedVcpuExit(
                                            "terminal instruction injection lost its exit"
                                                .to_owned(),
                                        )
                                    })?;
                                    if exit.group {
                                        self.request_guest_thread_group_exit(exit.status);
                                    }
                                    // The original instruction never resumes. Normal
                                    // retirement and consuming hooks own cleanup.
                                    return Ok(exit.into());
                                }
                                HandlerOutcome::TailInjected { .. }
                                | HandlerOutcome::ParkedFatal(_)
                                | HandlerOutcome::ParkedCancelled(_)
                                | HandlerOutcome::ParkedRetired(_) => {
                                    return Err(Error::UnexpectedVcpuExit(
                                        "nonreturning instruction callback outcome".to_owned(),
                                    )
                                    .with_cleanup(hidden.err().into_iter().collect()));
                                }
                            };
                            hidden?;
                            if process_completed {
                                return Err(Error::UnexpectedVcpuExit(
                                    "instruction callback changed the process continuation"
                                        .to_owned(),
                                ));
                            }
                            if let Some((segment, address)) = executor.take_segment() {
                                set_user_segment_base(&self.vcpu, segment, address)?;
                            }
                            self.resume_tool_instruction(boundary, value)?;
                            continue;
                        }
                        if self.try_resume_vmware_backdoor_probe()? {
                            continue;
                        }
                        let Some(fault) = self.capture_page_zero_fault(executor)? else {
                            return Err(self.static_elf_halt_error()?);
                        };
                        executor.prepare_captured_page_zero_fault();
                        executor.set_current_user_stack_pointer(fault.registers.rsp);
                        let pending = self
                            .filter_next_pending_signal_with_tool(
                                executor,
                                pid,
                                tid,
                                &tool,
                                &memory,
                                &auxv,
                                fault.registers,
                                u64::MAX,
                                self.syscall_frame_address,
                                &mut thread_state,
                                &global_state,
                                config,
                                subscriptions,
                                &stack_checked_out,
                                Some(&fault),
                                false,
                            )
                            .await?;
                        let pending = match pending {
                            CallbackOutcome::Completed(pending) => pending,
                            CallbackOutcome::GroupExit(status) => {
                                return self.wait_group_exit_status(executor, status);
                            }
                            CallbackOutcome::ThreadCancelled => {
                                return Ok(self.cancelled_tool_thread_status(executor));
                            }
                            CallbackOutcome::ThreadRetired => {
                                return self.retired_tool_thread_status(executor);
                            }
                        };
                        if let Some((segment, address)) = executor.take_segment() {
                            set_user_segment_base(&self.vcpu, segment, address)?;
                        }
                        if !executor.has_pending_exit() {
                            if let Some(pending) = pending {
                                self.deliver_page_zero_fault(executor, &fault, pending)?;
                            } else {
                                fault.resume_user(self, fault.registers)?;
                            }
                        }
                        if let Some(exit) = executor.take_exit() {
                            self.discard_process_clear_tid_at_signal_return(executor);
                            if exit.group {
                                self.request_guest_thread_group_exit(exit.status);
                            }
                            return Ok(exit.into());
                        }
                        continue;
                    }
                    exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
                };
                // A CLONE_THREAD worker runs on its own vCPU with a per-thread
                // syscall area, so the transported frame is `self.syscall_frame_address`
                // (equal to the root constant for the process leader, distinct for
                // each worker), not the fixed root `SYSCALL_FRAME_ADDRESS`.
                if frame_address != self.syscall_frame_address {
                    return Err(Error::UnexpectedVcpuExit(format!(
                        "syscall frame is at unexpected address {frame_address:#x}"
                    )));
                }
                let registers = self.vcpu.get_regs()?;
                let request = SyscallRequest::read_from(&memory, frame_address)?;
                // The KVM_RUN hypercall return slot is one-shot storage. Publish
                // its unused value exactly once while this decoded exit is live;
                // process actions may re-enter the vCPU before the Tool callback
                // returns, after which this pointer must never be reused.
                unsafe {
                    (return_slot as *mut u64).write(0);
                }
                let userspace =
                    process_syscall_return_registers(&memory, registers, frame_address, 0, None)?;
                executor.set_current_user_stack_pointer(userspace.rsp);
                if request.number() == libc::SYS_rt_sigreturn as u64 {
                    // `rt_sigreturn` is backend-owned: its apparent syscall result
                    // is the register file restored from the guest frame, not an
                    // ordinary scalar return value that a Tool can replace.
                    let mut signal_exit = None;
                    let mut signal_delivered = false;
                    if let Some(restored) = self.restore_rt_sigreturn(executor, frame_address)? {
                        executor.set_current_user_stack_pointer(restored.rsp);
                        let pending = self
                            .filter_one_pending_signal_with_tool(
                                executor,
                                pid,
                                tid,
                                &tool,
                                &memory,
                                &auxv,
                                restored,
                                request.number(),
                                frame_address,
                                &mut thread_state,
                                &global_state,
                                config,
                                subscriptions,
                                &stack_checked_out,
                                false,
                            )
                            .await?;
                        let pending = match pending {
                            CallbackOutcome::Completed(pending) => pending,
                            CallbackOutcome::GroupExit(status) => {
                                return self.wait_group_exit_status(executor, status);
                            }
                            CallbackOutcome::ThreadCancelled => {
                                return Ok(self.cancelled_tool_thread_status(executor));
                            }
                            CallbackOutcome::ThreadRetired => {
                                return self.retired_tool_thread_status(executor);
                            }
                        };
                        if let Some((segment, address)) = executor.take_segment() {
                            set_user_segment_base(&self.vcpu, segment, address)?;
                        }
                        signal_exit = executor.take_exit();
                        let delivered = if signal_exit.is_none()
                            && let Some(pending) = pending
                        {
                            self.deliver_selected_signal_from_registers(
                                executor,
                                frame_address,
                                restored,
                                pending,
                            )?
                        } else {
                            false
                        };
                        signal_exit = signal_exit.or_else(|| executor.take_exit());
                        signal_delivered = delivered;
                        if !delivered && signal_exit.is_none() {
                            stage_process_syscall_return(
                                &mut memory,
                                &self.vcpu,
                                frame_address,
                                restored,
                            )?;
                        }
                    }
                    signal_exit = signal_exit.or_else(|| executor.take_exit());
                    let outcome = if let Some(exit) = signal_exit {
                        exit.signal_boundary_outcome()
                    } else if signal_delivered {
                        reverie::SignalBoundaryOutcome::Caught
                    } else {
                        reverie::SignalBoundaryOutcome::NoHandler
                    };
                    self.finish_signal_boundary(executor, global_state.as_ref(), outcome)
                        .await?;
                    signal_exit = signal_exit.or_else(|| executor.take_exit());
                    if let Some(exit) = signal_exit {
                        self.discard_process_clear_tid_at_signal_return(executor);
                        if exit.group {
                            self.request_guest_thread_group_exit(exit.status);
                        }
                        return Ok(exit.into());
                    }
                    continue;
                }
                let syscall = request.into_syscall()?;
                // TODO-HUMAN-REVIEW(PR-156): Review root process-syscall Tool dispatch.
                // CLONE_THREAD is deliberately NOT backend-owned: the parent's
                // clone is delivered to the Tool (Detcore) so the worker inherits
                // process-shared Tool state (fd table, memory identity) and joins
                // Detcore's scheduler. `run_process_action_with_tool` then spawns
                // the worker on the Tool loop, which issues the matching
                // `handle_thread_start` the parent's clone handler waits for.
                let backend_owned = is_backend_owned_syscall(request.number(), thread_ownership)
                    && !executor.is_random_device_read(&request)
                    && !executor.is_tool_visible_read(&request);
                let subscribed = !backend_owned
                    && subscriptions
                        .iter_syscalls()
                        .any(|number| number == syscall.number());
                let (
                    mut result,
                    handler_replaced_image,
                    _handler_process_completed,
                    restart_requested,
                ) = if subscribed {
                    let mut handler_process_completed = false;
                    // With no eligible virtual signal, ERESTARTSYS immediately
                    // re-enters the callback as before. With one, leave the loop so
                    // the structured signal hook and disposition decide whether
                    // the saved context reports EINTR or rewinds the syscall under
                    // SA_RESTART. The private errno itself never reaches userspace.
                    loop {
                        let handler_signal = Arc::new(Mutex::new(None));
                        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
                        self.check_entry_owner()?;
                        expose_tool_scratch(&memory, tool_stack_top)?;
                        let boundary = {
                            let mut stop = pin!(wait_for_failure(
                                global_state.as_ref(),
                                failure_subscription.clone(),
                            ));
                            CompletedSyscallBoundary::capture_admitted(
                                self,
                                frame_address,
                                None,
                                stop.as_mut(),
                            )
                            .await?
                        };
                        let Some(boundary) = boundary else {
                            hide_tool_scratch(&memory, tool_stack_top)?;
                            return Ok(self.cancelled_tool_thread_status(executor));
                        };
                        let callback_scope = self.begin_entry_callback()?;
                        let callback_watch = self.entry_driver_watch();
                        let callback_memory = self.memory.clone();
                        executor.bind_address_space(&callback_memory);
                        let outcome = {
                            let memory = callback_memory;
                            let mut guest_executor = StaticElfSyscallExecutor {
                                backend: self,
                                executor,
                                memory: memory.clone(),
                                process_context: ProcessExecutionContext::SyscallBoundary(boundary),
                                callback_site: None,
                                original_syscall: Some(request),
                                signal_guard: SignalGuard::Ordinary,
                                last_result: None,
                                polled_read_attempt: None,
                                process_completed: &mut handler_process_completed,
                            };
                            let mut guest = KvmGuest::<T>::new(
                                pid,
                                tid,
                                tool.clone(),
                                memory.clone(),
                                &auxv,
                                kvm_registers(registers, request.number()),
                                &mut thread_state,
                                &mut guest_executor,
                                global_state.as_ref(),
                                Some(global_state.clone()),
                                config,
                                subscriptions,
                                handler_signal.clone(),
                                pending_child_starts.clone(),
                                tool_stack_top,
                                stack_checked_out.clone(),
                            );
                            drive_entry_handler_completion_from(
                                || tool.handle_syscall_event(&mut guest, syscall),
                                handler_signal,
                                pending_child_starts.clone(),
                                wait_for_failure(
                                    global_state.as_ref(),
                                    failure_subscription.clone(),
                                ),
                                callback_watch.clone(),
                            )
                            .await
                        };
                        drop(callback_scope);
                        self.restore_entry_origin();
                        executor.bind_address_space(&self.memory);

                        let outcome = self
                            .finish_entry_handler_completion(
                                outcome,
                                hide_tool_scratch(&memory, tool_stack_top),
                                Error::Reverie,
                                &callback_watch,
                            )
                            .await?;
                        let classified = match outcome {
                            HandlerOutcome::Returned(result) => {
                                let classified = match classify_handler_result(result) {
                                    Ok(classified) => classified,
                                    Err(error) => {
                                        return Err(self
                                            .cleanup_unstarted_tool_children_after_error(
                                                executor,
                                                &pending_child_starts,
                                                error,
                                            ));
                                    }
                                };
                                match classified {
                                    Some(raw) => (raw, false, handler_process_completed, false),
                                    None if !handler_process_completed
                                        && (executor.has_prepared_signal()
                                            || executor.has_eligible_pending_signal()) =>
                                    {
                                        // A prepared signal was already removed from
                                        // pending. Deliver its frame before another
                                        // callback invalidates the selection's nonce;
                                        // the frame's SA_RESTART policy decides whether
                                        // the syscall runs again after the handler.
                                        (-(libc::EINTR as i64), false, false, true)
                                    }
                                    // A restart is only meaningful while the process
                                    // is still live to re-run the syscall.
                                    None if !handler_process_completed => {
                                        self.start_pending_tool_children(
                                            executor,
                                            &pending_child_starts,
                                        )?;
                                        continue;
                                    }
                                    None => (
                                        -(i64::from(Errno::ERESTARTSYS.into_raw())),
                                        false,
                                        handler_process_completed,
                                        false,
                                    ),
                                }
                            }
                            HandlerOutcome::TailInjected {
                                result,
                                image_replaced,
                                ..
                            } => (
                                result_to_raw(result),
                                image_replaced,
                                handler_process_completed,
                                false,
                            ),
                            HandlerOutcome::GroupExit(status) => {
                                self.prepare_wait_group_exit(
                                    executor,
                                    status,
                                    &pending_child_starts,
                                )?;
                                return self.wait_group_exit_status(executor, status);
                            }
                            HandlerOutcome::ThreadCancelled => {
                                self.start_pending_tool_children(executor, &pending_child_starts)?;
                                return Ok(self.cancelled_tool_thread_status(executor));
                            }
                            HandlerOutcome::ThreadRetired => {
                                self.start_pending_tool_children(executor, &pending_child_starts)?;
                                return self.retired_tool_thread_status(executor);
                            }
                            HandlerOutcome::RunFailed => return Err(Error::RunAborted),
                            HandlerOutcome::ParkedFatal(selection) => {
                                if !executor.prepared_signal_is_fatal(selection) {
                                    return Err(Error::UnexpectedVcpuExit(
                                        "fatal selection identity changed".to_owned(),
                                    ));
                                }
                                let pending = executor
                                    .take_prepared_signal()
                                    .map_err(|errno| Error::Reverie(errno.into()))?
                                    .expect("validated fatal selection");
                                self.deliver_selected_signal_from_registers(
                                    executor,
                                    frame_address,
                                    registers,
                                    pending,
                                )?;
                                let exit = executor.take_exit().ok_or_else(|| {
                                    Error::UnexpectedVcpuExit(
                                        "fatal parked selection did not terminate".to_owned(),
                                    )
                                })?;
                                self.finish_signal_boundary(
                                    executor,
                                    global_state.as_ref(),
                                    exit.signal_boundary_outcome(),
                                )
                                .await?;
                                executor.finish_parked_delivery();
                                if exit.group {
                                    self.request_guest_thread_group_exit(exit.status);
                                }
                                return Ok(exit.into());
                            }
                            HandlerOutcome::ParkedRetired(context) => {
                                executor.validate_signal_retirement(Some(context))?;
                                self.start_pending_tool_children(executor, &pending_child_starts)?;
                                return self.retired_tool_thread_status(executor);
                            }
                            HandlerOutcome::ParkedCancelled(context) => {
                                if !executor.signal_failure_context_is_current(context) {
                                    return Err(Error::UnexpectedVcpuExit(
                                        "parked cancellation ledger identity changed".to_owned(),
                                    ));
                                }
                                return Err(executor.with_signal_effects(Error::RunAborted, None));
                            }
                            HandlerOutcome::RuntimeError(error) => {
                                let error = self.cleanup_unstarted_tool_children_after_error(
                                    executor,
                                    &pending_child_starts,
                                    error,
                                );
                                return Err(error);
                            }
                        };
                        self.start_pending_tool_children(executor, &pending_child_starts)?;
                        break classified;
                    }
                } else {
                    executor.reserve_signal_effects(64).map_err(|errno| {
                        executor.with_signal_effects(Error::Reverie(errno.into()), None)
                    })?;
                    let raw = match self.execute_static_elf_syscall(executor, &request, &memory) {
                        Ok(raw) => raw,
                        Err(Error::ChildWaitGroupExit { status }) => {
                            return self.wait_group_exit_status(executor, status);
                        }
                        Err(Error::TerminalReadCancelled) => {
                            return Ok(self.cancelled_tool_thread_status(executor));
                        }
                        Err(error) => return Err(executor.with_signal_effects(error, None)),
                    };
                    flush_pending_signal_effects_with_tool(
                        self,
                        executor,
                        pid,
                        tid,
                        &tool,
                        &memory,
                        &auxv,
                        kvm_registers(registers, request.number()),
                        &mut thread_state,
                        &global_state,
                        config,
                        subscriptions,
                        &stack_checked_out,
                        Some(raw),
                    )
                    .await?;
                    (raw, false, false, false)
                };
                let mut returned_registers = process_syscall_return_registers(
                    &memory,
                    registers,
                    frame_address,
                    result,
                    None,
                )?;
                let mut restarted_registers = restart_requested
                    .then(|| restart_syscall_registers(returned_registers, request.number()))
                    .transpose()?;
                // The ring0 trampoline reads the result from the frame and then
                // SYSRETs, so the hypercall return slot is unused here.
                SyscallRequest::write_result(&mut memory, frame_address, result)?;
                let pending_segment = executor.take_segment();
                let mut pending_exit = executor.take_exit();
                let pending_process = executor.take_process_action();

                if let Some((segment, address)) = pending_segment {
                    set_user_segment_base(&self.vcpu, segment, address)?;
                }
                let mut replaced_image = handler_replaced_image;
                if let Some(action) = pending_process {
                    let continuation = {
                        let mut stop = pin!(wait_for_failure(
                            global_state.as_ref(),
                            failure_subscription.clone(),
                        ));
                        CompletedSyscallBoundary::capture_for_action_admitted(
                            self,
                            frame_address,
                            None,
                            &action,
                            stop.as_mut(),
                        )
                        .await?
                    };
                    let Some(continuation) = continuation else {
                        return Ok(self.cancelled_tool_thread_status(executor));
                    };
                    let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
                    let context: ToolContext<'_, T> = ToolContext {
                        pid,
                        tid,
                        process_state: tool.clone(),
                        thread_state: &thread_state,
                        global_state: Some(global_state.clone()),
                        config: config.clone(),
                        subscriptions: subscriptions.clone(),
                        pending_child_starts: pending_child_starts.clone(),
                    };
                    let outcome = self
                        .run_process_action_with_tool_at_boundary(
                            executor,
                            action,
                            context,
                            continuation,
                        )
                        .await;
                    let outcome = outcome?;
                    if outcome.cancelled {
                        return Ok(self.cancelled_tool_thread_status(executor));
                    }
                    if !outcome.image_replaced {
                        result = outcome.syscall_result;
                        returned_registers = process_syscall_return_registers(
                            &memory,
                            registers,
                            frame_address,
                            result,
                            None,
                        )?;
                        restarted_registers = restart_requested
                            .then(|| {
                                restart_syscall_registers(returned_registers, request.number())
                            })
                            .transpose()?;
                    }
                    replaced_image |= outcome.image_replaced;
                    self.start_pending_tool_children(executor, &pending_child_starts)?;
                }
                if replaced_image {
                    self.finish_signal_boundary(
                        executor,
                        global_state.as_ref(),
                        reverie::SignalBoundaryOutcome::ImageReplaced,
                    )
                    .await?;
                }
                if replaced_image {
                    auxv = executor.auxv().to_vec();
                    let post_exec_outcome = run_post_exec_handler(
                        self,
                        &tool,
                        pid,
                        &memory,
                        &mut auxv,
                        &mut thread_state,
                        executor,
                        global_state.clone(),
                        config,
                        subscriptions,
                        &stack_checked_out,
                    )
                    .await;
                    let post_exec_error = match post_exec_outcome {
                        Ok(CallbackOutcome::GroupExit(status)) => {
                            return self.wait_group_exit_status(executor, status);
                        }
                        Ok(CallbackOutcome::ThreadCancelled) => {
                            return Ok(self.cancelled_tool_thread_status(executor));
                        }
                        Ok(CallbackOutcome::ThreadRetired) => {
                            return self.retired_tool_thread_status(executor);
                        }
                        Ok(CallbackOutcome::Completed(())) => None,
                        Err(error) => Some(error),
                    };
                    if let Some(error) = post_exec_error {
                        return Err(error);
                    }
                }
                if let Some((segment, address)) = executor.take_segment() {
                    set_user_segment_base(&self.vcpu, segment, address)?;
                }
                let mut signal_boundary_outcome = reverie::SignalBoundaryOutcome::NoHandler;
                if !replaced_image && pending_exit.is_none() {
                    let pending = if let Some(prepared) = executor
                        .take_prepared_signal()
                        .map_err(|errno| Error::Reverie(errno.into()))?
                    {
                        CallbackOutcome::Completed(Some(prepared))
                    } else {
                        self.filter_one_pending_signal_with_tool(
                            executor,
                            pid,
                            tid,
                            &tool,
                            &memory,
                            &auxv,
                            returned_registers,
                            request.number(),
                            frame_address,
                            &mut thread_state,
                            &global_state,
                            config,
                            subscriptions,
                            &stack_checked_out,
                            false,
                        )
                        .await?
                    };
                    let pending = match pending {
                        CallbackOutcome::Completed(pending) => pending,
                        CallbackOutcome::GroupExit(status) => {
                            return self.wait_group_exit_status(executor, status);
                        }
                        CallbackOutcome::ThreadCancelled => {
                            return Ok(self.cancelled_tool_thread_status(executor));
                        }
                        CallbackOutcome::ThreadRetired => {
                            return self.retired_tool_thread_status(executor);
                        }
                    };
                    if let Some((segment, address)) = executor.take_segment() {
                        set_user_segment_base(&self.vcpu, segment, address)?;
                    }
                    pending_exit = pending_exit.or_else(|| executor.take_exit());
                    let mut delivered = false;
                    if pending_exit.is_none()
                        && let Some(pending) = pending
                    {
                        let signal_registers = if restart_requested
                            && executor.caught_signal_restarts_syscall(pending)
                        {
                            restarted_registers.expect("restart registers were constructed")
                        } else {
                            returned_registers
                        };
                        delivered = self.deliver_selected_signal_from_registers(
                            executor,
                            frame_address,
                            signal_registers,
                            pending,
                        )?;
                    }
                    pending_exit = pending_exit.or_else(|| executor.take_exit());
                    signal_boundary_outcome = if let Some(exit) = pending_exit {
                        exit.signal_boundary_outcome()
                    } else if delivered {
                        reverie::SignalBoundaryOutcome::Caught
                    } else {
                        reverie::SignalBoundaryOutcome::NoHandler
                    };
                    if restart_requested && !delivered && pending_exit.is_none() {
                        // Suppression, an ignored replacement, or a replacement
                        // newly blocked by its signal number means no handler ran;
                        // resume by re-executing the original syscall rather than
                        // leaking EINTR or the kernel-private ERESTARTSYS value.
                        stage_process_syscall_return(
                            &mut memory,
                            &self.vcpu,
                            frame_address,
                            restarted_registers.expect("restart registers were constructed"),
                        )?;
                    }
                }
                if let Some(exit) = pending_exit {
                    signal_boundary_outcome = exit.signal_boundary_outcome();
                }
                self.finish_signal_boundary(
                    executor,
                    global_state.as_ref(),
                    signal_boundary_outcome,
                )
                .await?;
                executor.finish_parked_delivery();
                pending_exit = pending_exit.or_else(|| executor.take_exit());
                if let Some(exit) = pending_exit {
                    if exit.group {
                        self.request_guest_thread_group_exit(exit.status);
                    }
                    return Ok(exit.into());
                }
            }
        };
        let caught = crate::failure::owned_future::catch_owned_future(execution).await;
        let outcome: Result<ToolProcessExit> =
            self.finish_tool_execution_completion(caught, "Tool execution");
        self.restore_entry_origin();
        executor.bind_address_space(&self.memory);
        let outcome = self.route_entry_outcome(outcome).await;
        let outcome = outcome.map_err(|error| {
            self.cleanup_unstarted_tool_children_after_error(executor, &pending_child_starts, error)
        });
        self.finish_tool_process(
            executor,
            tool,
            (pid, tid),
            global_state.as_ref(),
            config,
            thread_state,
            outcome,
            true,
            child_exit,
        )
        .await
    }
}

/// Resolve a Tool handler's return value into the raw word written to the
/// guest's syscall frame, or `None` when the `ERESTARTSYS` protocol requires
/// either re-running the Tool callback or applying signal-disposition restart
/// policy at the static-ELF return boundary.
///
/// `ERESTARTSYS` is kernel-private: Linux never delivers it to userspace. It
/// either re-issues the interrupted syscall or reports `EINTR`. Detcore returns
/// it from `signal_interrupt_errno()` for the syscalls it models as restartable
/// (`read`, `futex`, ...) to mean exactly "re-run me". Under `reverie-ptrace`
/// the host kernel consumes it: the tracee's return register is set to
/// `-ERESTARTSYS` alongside a pending signal and Linux's signal-delivery path
/// rewinds and re-issues the syscall. A KVM guest is not a host process resumed
/// through that path, so this backend must repeat the callback itself. Without
/// it the private 512 reaches the guest as an application-visible errno.
///
/// With no eligible virtual signal the callback is re-entered immediately. If
/// one is pending, the static-ELF loop runs the structured signal hook first,
/// then saves either `EINTR` or a rewound syscall according to the final
/// signal's disposition and `SA_RESTART`. The other Linux-internal restart
/// classes are not part of Reverie's current Tool contract and fail explicitly
/// if a Tool manufactures one.
///
/// Isolating the policy in one pure function keeps it directly testable. Note
/// that testing it does not test restart execution; integration tests cover
/// both callback re-entry and signal-disposition-dependent frame restoration.
fn classify_handler_result(
    result: std::result::Result<i64, reverie::Error>,
) -> Result<Option<i64>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => match error.into_errno().map_err(Error::Reverie)? {
            Errno::ERESTARTSYS => Ok(None),
            errno if matches!(errno.into_raw(), 513 | 514 | 516) => {
                Err(Error::UnexpectedVcpuExit(format!(
                    "unsupported Linux-internal syscall restart class {}",
                    errno.into_raw(),
                )))
            }
            errno => Ok(Some(-(i64::from(errno.into_raw())))),
        },
    }
}

fn restart_syscall_registers(mut registers: kvm_regs, syscall_number: u64) -> Result<kvm_regs> {
    registers.rip = registers.rip.checked_sub(2).ok_or_else(|| {
        Error::UnexpectedVcpuExit(
            "cannot rewind a syscall at an instruction pointer below two".to_owned(),
        )
    })?;
    registers.rax = syscall_number;
    Ok(registers)
}

fn raw_to_result(result: i64) -> std::result::Result<i64, Errno> {
    Errno::from_ret(result as usize).map(|value| value as i64)
}

fn result_to_raw(result: std::result::Result<i64, Errno>) -> i64 {
    match result {
        Ok(value) => value,
        Err(error) => -(error.into_raw() as i64),
    }
}

pub(crate) fn kvm_registers(registers: kvm_regs, syscall_number: u64) -> libc::user_regs_struct {
    libc::user_regs_struct {
        r15: registers.r15,
        r14: registers.r14,
        r13: registers.r13,
        r12: registers.r12,
        rbp: registers.rbp,
        rbx: registers.rbx,
        r11: registers.r11,
        r10: registers.r10,
        r9: registers.r9,
        r8: registers.r8,
        rax: registers.rax,
        rcx: registers.rcx,
        rdx: registers.rdx,
        rsi: registers.rsi,
        rdi: registers.rdi,
        orig_rax: syscall_number,
        rip: registers.rip,
        cs: 0,
        eflags: registers.rflags,
        rsp: registers.rsp,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BOOT_RESERVED_END;
    use crate::bootstrap::TOOL_STACK_TOP;
    use crate::bootstrap::thread_tool_stack_top;

    fn synthetic_initial_exec() -> SyscallRequest {
        SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 0, 0, 0])
    }

    #[test]
    fn tool_child_completion_validation_is_exact_and_release_active() {
        let parent = reverie::SignalProcessId {
            tgid: Pid::from_raw(1),
            generation: 10,
        };
        let child = reverie::SignalProcessId {
            tgid: Pid::from_raw(2),
            generation: 11,
        };
        let completion = reverie::ChildExitCompletion {
            parent,
            child,
            status: ExitStatus::Exited(7),
            waitable: true,
            uid: 0,
            user_ticks: 0,
            system_ticks: 0,
        };

        validate_tool_child_completion(completion, child, ExitStatus::Exited(7), 2).unwrap();

        let stale_child = reverie::SignalProcessId {
            generation: 12,
            ..child
        };
        assert!(matches!(
            validate_tool_child_completion(completion, stale_child, ExitStatus::Exited(7), 2),
            Err(Error::UnexpectedVcpuExit(message))
                if message.contains("family identity")
                    && message.contains("admitted identity")
        ));
        assert!(matches!(
            validate_tool_child_completion(completion, child, ExitStatus::Exited(8), 2),
            Err(Error::UnexpectedVcpuExit(message))
                if message.contains("family status Exited(7)")
                    && message.contains("process status Exited(8)")
        ));
    }

    #[test]
    fn initial_exec_matches_original_and_canonical_execveat() {
        let expected = synthetic_initial_exec();
        assert!(matches_initial_exec(&expected, &expected));
        assert!(matches_initial_exec(
            &expected,
            &SyscallRequest::new(
                libc::SYS_execveat as u64,
                [libc::AT_FDCWD as u64, 0x100, 0x200, 0x300, 0, 0],
            )
        ));
    }

    #[test]
    fn initial_exec_rejects_every_other_execveat_shape() {
        let expected = synthetic_initial_exec();
        let canonical = [libc::AT_FDCWD as u64, 0x100, 0x200, 0x300, 0, 0];

        for index in 0..canonical.len() {
            let mut args = canonical;
            args[index] ^= 1;
            assert!(
                !matches_initial_exec(
                    &expected,
                    &SyscallRequest::new(libc::SYS_execveat as u64, args),
                ),
                "accepted execveat with argument {index} changed"
            );
        }

        assert!(!matches_initial_exec(
            &expected,
            &SyscallRequest::new(libc::SYS_execve as u64 + 1, *expected.args()),
        ));
    }

    #[test]
    fn initial_exec_match_requires_a_well_formed_execve_expectation() {
        let non_exec = SyscallRequest::new(libc::SYS_read as u64, [0x100, 0x200, 0x300, 0, 0, 0]);
        assert!(!matches_initial_exec(&non_exec, &non_exec));

        let malformed =
            SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 1, 0, 0]);
        assert!(!matches_initial_exec(&malformed, &malformed));
    }

    #[test]
    fn converts_linux_error_results() {
        assert_eq!(raw_to_result(7), Ok(7));
        assert_eq!(raw_to_result(-(libc::EIO as i64)), Err(Errno::EIO));
        assert_eq!(result_to_raw(Err(Errno::EFAULT)), -(libc::EFAULT as i64));
    }

    #[test]
    fn worker_shared_syscall_ownership_follows_thread_ownership() {
        // ppoll always stays backend-owned because KVM injection cannot execute it.
        for ownership in [ThreadOwnership::Host, ThreadOwnership::Tool] {
            assert!(is_backend_owned_syscall(libc::SYS_ppoll as u64, ownership));
            assert!(!is_backend_owned_syscall(
                libc::SYS_clock_gettime as u64,
                ownership
            ));
        }

        // Host-owned workers share descriptors outside the Tool, so reads stay
        // backend-owned. Tool-owned reads must reach the Tool's subscriptions.
        for number in [libc::SYS_read, libc::SYS_readv] {
            assert!(is_backend_owned_syscall(
                number as u64,
                ThreadOwnership::Host
            ));
            assert!(!is_backend_owned_syscall(
                number as u64,
                ThreadOwnership::Tool
            ));
        }
    }

    #[test]
    fn futex_ownership_follows_thread_ownership() {
        // Host-owned threads (uninstrumented workers): the root shares host
        // futex words, so futex stays backend-owned.
        assert!(is_backend_owned_syscall(
            libc::SYS_futex as u64,
            ThreadOwnership::Host
        ));
        // Tool-owned threads: futex routes to the Tool (Detcore) so joins are
        // logical scheduler waits woken by the exiting worker's CLEARTID.
        assert!(!is_backend_owned_syscall(
            libc::SYS_futex as u64,
            ThreadOwnership::Tool
        ));
    }

    #[test]
    fn handler_suspension_releases_registered_child_start() {
        let handler_signal = Arc::new(Mutex::new(None));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        let (start_sender, start_receiver) = std::sync::mpsc::channel();
        let start_gate = ChildStartGate::new(start_sender);
        pending_child_starts
            .lock()
            .unwrap()
            .push(PendingChildStart::fork_process(2, start_gate));
        let handler = poll_fn(|context| match start_receiver.try_recv() {
            Ok(ChildStartCommand::Start) => Poll::Ready(true),
            Ok(ChildStartCommand::Cancel) => Poll::Ready(false),
            Ok(ChildStartCommand::CancelAfterFailure) => {
                panic!("normal handler sent fatal cancellation")
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Poll::Ready(false),
        });

        assert!(matches!(
            futures::executor::block_on(drive_handler(
                handler,
                handler_signal,
                pending_child_starts,
                std::future::pending(),
            )),
            HandlerOutcome::Returned(true)
        ));
    }

    #[test]
    fn handler_failure_destroys_owned_callback_before_scope_acknowledgement() {
        use std::task::Context;
        use std::task::Waker;

        use crate::entry::owner::DriverScope;
        use crate::entry::owner::OperationOrigin;

        struct CallbackGuard {
            origin: OperationOrigin,
            destroyed: Arc<AtomicBool>,
        }
        impl Drop for CallbackGuard {
            fn drop(&mut self) {
                assert!(!self.origin.callback_dropped());
                assert!(!self.destroyed.swap(true, Ordering::SeqCst));
            }
        }

        for fail_during_poll in [false, true] {
            let driver = DriverScope::new();
            let owner = driver.owner();
            let callback = owner.begin_callback(None).unwrap();
            let origin = callback.origin();
            let destroyed = Arc::new(AtomicBool::new(false));
            let guard = CallbackGuard {
                origin: origin.clone(),
                destroyed: destroyed.clone(),
            };
            let (sender, receiver) = futures::channel::oneshot::channel();
            let sender = Arc::new(Mutex::new(Some(sender)));
            let callback_sender = sender.clone();
            let future = async move {
                let _guard = guard;
                poll_fn(|_| {
                    if fail_during_poll {
                        callback_sender
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(())
                            .unwrap();
                        Poll::Ready(17)
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            let mut driven = Box::pin(drive_handler(
                future,
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(Vec::new())),
                async {
                    receiver.await.unwrap();
                },
            ));
            fn require_send<T: Send>(_: &T) {}
            require_send(&driven);
            let mut context = Context::from_waker(Waker::noop());
            if !fail_during_poll {
                assert!(driven.as_mut().poll(&mut context).is_pending());
                assert!(!destroyed.load(Ordering::SeqCst));
                assert!(!origin.callback_dropped());
                sender.lock().unwrap().take().unwrap().send(()).unwrap();
            }
            assert!(matches!(
                driven.as_mut().poll(&mut context),
                Poll::Ready(HandlerOutcome::RunFailed)
            ));
            assert!(
                destroyed.load(Ordering::SeqCst),
                "returned while callback still owned its guard"
            );
            assert!(
                !origin.callback_dropped(),
                "driver acknowledged caller's scope"
            );
            drop(driven);
            drop(callback);
            assert!(origin.callback_dropped());
            let retirement = driver.retire();
            retirement.result.unwrap();
            assert!(retirement.pending.is_empty());
            retirement.notification.notify();
        }
    }

    #[test]
    fn unstarted_cleanup_retains_pending_future_and_real_errors() {
        use std::sync::atomic::AtomicUsize;
        use std::task::Context;
        use std::task::Waker;

        struct OwnedState(Arc<AtomicUsize>);
        impl Drop for OwnedState {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut executor = ElfExecutor::new(
            crate::executor::native_loaded_state(std::path::Path::new("/")),
            false,
        );
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(1));
        let drops = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let (release, wait) = futures::channel::oneshot::channel();
        let cleanup_cause = Arc::new(Error::GuestClock("retained cleanup error".to_owned()));
        let owned = OwnedState(drops.clone());
        let observed_run = run.clone();
        let observed_polls = polls.clone();
        executor.retain_unstarted_tool_cleanup(Box::pin(async move {
            let _owned = owned;
            assert!(observed_run.published_primary().is_some());
            observed_polls.fetch_add(1, Ordering::SeqCst);
            wait.await.unwrap();
            Err(Error::RunAborted)
        }));
        let owned = OwnedState(drops.clone());
        let observed_polls = polls.clone();
        let cause = cleanup_cause.clone();
        executor.retain_unstarted_tool_cleanup(Box::pin(async move {
            let _owned = owned;
            observed_polls.fetch_add(1, Ordering::SeqCst);
            Err(Error::RunAborted.with_cleanup(vec![Error::SharedFailure(cause)]))
        }));
        let owned = OwnedState(drops.clone());
        let observed_polls = polls.clone();
        executor.retain_unstarted_tool_cleanup(Box::pin(async move {
            let _owned = owned;
            assert_eq!(observed_polls.fetch_add(1, Ordering::SeqCst), 2);
            Err(Error::RunAborted)
        }));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let parent = context.publish(
            "failed spawn",
            Error::HostIo(std::io::Error::from_raw_os_error(libc::EAGAIN)),
        );
        let first = run.published_primary().unwrap();
        let mut cleanup = Box::pin(finish_unstarted_tool_cleanups(&mut executor));
        let mut context = Context::from_waker(Waker::noop());
        assert!(cleanup.as_mut().poll(&mut context).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        let Poll::Ready(Err(error)) = cleanup.as_mut().poll(&mut context) else {
            panic!("cleanup did not retain its real failure");
        };
        drop(cleanup);
        assert_eq!(polls.load(Ordering::SeqCst), 3);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert!(executor.take_unstarted_tool_cleanup().is_empty());
        let Error::WithCleanup { primary, cleanup } = &error else {
            panic!("derived marker hid the cleanup aggregate");
        };
        assert!(matches!(primary.as_ref(), Error::RunAborted));
        assert_eq!(cleanup.len(), 1);
        assert!(cleanup[0].retains_primary(&cleanup_cause));
        let combined = parent.with_cleanup(vec![error]);
        assert!(combined.retains_primary(&first));
        assert!(
            matches!(combined.primary(), Error::HostIo(error) if error.raw_os_error() == Some(libc::EAGAIN))
        );
        assert!(Arc::ptr_eq(&first, &run.published_primary().unwrap()));
    }

    #[test]
    fn handler_runtime_error_precedes_and_preserves_unstarted_child_gate() {
        let handler_signal = Arc::new(Mutex::new(Some(HandlerSignal::RuntimeError(
            Error::UnexpectedVcpuExit("forced boundary restore failure".to_owned()),
        ))));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        let (start_sender, start_receiver) = std::sync::mpsc::channel();
        let start_gate = ChildStartGate::new(start_sender);
        pending_child_starts
            .lock()
            .unwrap()
            .push(PendingChildStart::tool_thread(2, start_gate));

        let outcome = futures::executor::block_on(drive_handler(
            std::future::pending::<()>(),
            handler_signal,
            pending_child_starts.clone(),
            std::future::pending(),
        ));
        assert!(matches!(
            outcome,
            HandlerOutcome::RuntimeError(Error::UnexpectedVcpuExit(message))
                if message == "forced boundary restore failure"
        ));
        assert!(matches!(
            start_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        let pending = pending_child_starts.lock().unwrap().pop().unwrap();
        assert!(matches!(
            pending.cancel(),
            PendingChildCancellation::NewlyCancelled {
                child: PendingChildKind::ToolThread(2),
                delivery_failed: false
            }
        ));
        assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Cancel);
    }

    #[test]
    fn erestartsys_requests_a_restart_and_every_other_result_is_returned() {
        // The whole point of the protocol: the kernel-private 512 must never
        // become the guest's syscall result, so it maps to "re-run", not to a
        // raw word.
        assert_eq!(
            classify_handler_result(Err(Errno::ERESTARTSYS.into())).unwrap(),
            None
        );

        // Ordinary errnos still reach the guest, negated, exactly as before.
        assert_eq!(
            classify_handler_result(Err(Errno::EINTR.into())).unwrap(),
            Some(-(libc::EINTR as i64))
        );
        assert_eq!(
            classify_handler_result(Err(Errno::EBADF.into())).unwrap(),
            Some(-(libc::EBADF as i64))
        );

        for unsupported in [513, 514, 516] {
            let error = classify_handler_result(Err(Errno::new(unsupported).into())).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unsupported Linux-internal syscall restart class"),
                "unexpected error for restart class {unsupported}: {error}",
            );
        }

        // Success values pass through untouched, including 0 and large reads.
        assert_eq!(classify_handler_result(Ok(0)).unwrap(), Some(0));
        assert_eq!(classify_handler_result(Ok(4096)).unwrap(), Some(4096));

        // A guard against the defect this replaced: no input may produce the
        // private restart value as a guest-visible result.
        let private = -(i64::from(Errno::ERESTARTSYS.into_raw()));
        for result in [
            Err(Errno::ERESTARTSYS.into()),
            Err(Errno::EINTR.into()),
            Err(Errno::EAGAIN.into()),
            Ok(0),
        ] {
            assert_ne!(classify_handler_result(result).unwrap(), Some(private));
        }
    }

    #[derive(Debug, Default, Eq, PartialEq)]
    struct TailInjectionSideEffects {
        output_bytes: usize,
        descriptors: usize,
        tasks: usize,
        address_space_generation: usize,
        pending_signal: bool,
        pending_process_action: bool,
        exited: bool,
        completion_callbacks: usize,
    }

    #[derive(Default)]
    struct SideEffectingExecutor {
        state: TailInjectionSideEffects,
    }

    struct FailingSyscallExecutor;

    impl GuestSyscallExecutor<crate::StraceTool> for FailingSyscallExecutor {
        fn read_clock(&self) -> Result<u64> {
            Err(Error::GuestClock(
                "failing executor has no guest counter".into(),
            ))
        }

        fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
            Err(Error::FamilyWaitLedgerMismatch {
                parent: reverie::SignalProcessId {
                    tgid: Pid::from_raw(1),
                    generation: 7,
                },
                child_pid: 2,
            })
        }
    }

    impl GuestSyscallExecutor<crate::StraceTool> for SideEffectingExecutor {
        fn read_clock(&self) -> Result<u64> {
            Err(Error::GuestClock(
                "side-effect test has no guest counter".into(),
            ))
        }

        fn execute(&mut self, request: &SyscallRequest, _memory: &GuestMemory) -> Result<i64> {
            match request.number() as libc::c_long {
                libc::SYS_write => self.state.output_bytes += request.args()[2] as usize,
                libc::SYS_pipe2 => self.state.descriptors += 2,
                libc::SYS_fork | libc::SYS_clone => {
                    self.state.tasks += 1;
                    self.state.pending_process_action = true;
                }
                libc::SYS_execve | libc::SYS_execveat => {
                    self.state.address_space_generation += 1;
                    self.state.pending_process_action = true;
                }
                libc::SYS_mmap => self.state.address_space_generation += 1,
                libc::SYS_kill | libc::SYS_tkill | libc::SYS_tgkill => {
                    self.state.pending_signal = true
                }
                libc::SYS_exit | libc::SYS_exit_group => self.state.exited = true,
                number => panic!("unexpected side-effect probe syscall {number}"),
            }
            Ok(0)
        }

        fn ordinary_injection_allowed(&self, request: &SyscallRequest) -> bool {
            !injection_can_be_nonreturning(request)
        }

        fn complete_injection<'a>(
            &'a mut self,
            _context: ToolContext<'a, crate::StraceTool>,
        ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
        where
            crate::StraceTool: 'a,
        {
            self.state.completion_callbacks += 1;
            Box::pin(async {
                Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced: true,
                    process_exited: true,
                })
            })
        }

        fn tail_injection_allowed(&self, _request: &SyscallRequest) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct PermissiveSideEffectingExecutor {
        state: TailInjectionSideEffects,
    }

    impl GuestSyscallExecutor<crate::StraceTool> for PermissiveSideEffectingExecutor {
        fn read_clock(&self) -> Result<u64> {
            Err(Error::GuestClock(
                "side-effect test has no guest counter".into(),
            ))
        }

        fn execute(&mut self, request: &SyscallRequest, _memory: &GuestMemory) -> Result<i64> {
            match request.number() as libc::c_long {
                libc::SYS_execve | libc::SYS_execveat => {
                    self.state.address_space_generation += 1;
                    self.state.pending_process_action = true;
                }
                libc::SYS_kill | libc::SYS_tkill | libc::SYS_tgkill => {
                    self.state.pending_signal = true
                }
                libc::SYS_exit | libc::SYS_exit_group => self.state.exited = true,
                number => panic!("unexpected nonreturning probe syscall {number}"),
            }
            Ok(0)
        }

        fn complete_injection<'a>(
            &'a mut self,
            _context: ToolContext<'a, crate::StraceTool>,
        ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
        where
            crate::StraceTool: 'a,
        {
            self.state.completion_callbacks += 1;
            Box::pin(async {
                Ok(InjectionCompletion::Returns {
                    syscall_result: None,
                })
            })
        }
    }

    #[test]
    fn injected_backend_failure_is_runtime_fatal_not_a_guest_errno() {
        let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
        let auxv = [];
        let mut thread_state = ();
        let global_state = crate::StraceLog::default();
        let config = ();
        let subscriptions = Subscription::none();
        let handler_signal = Arc::new(Mutex::new(None));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        let mut executor = FailingSyscallExecutor;
        let mut guest = KvmGuest::<crate::StraceTool>::new(
            Pid::from_raw(1),
            Pid::from_raw(1),
            Arc::new(crate::StraceTool),
            memory,
            &auxv,
            // SAFETY: the test does not inspect any register field.
            unsafe { std::mem::zeroed() },
            &mut thread_state,
            &mut executor,
            &global_state,
            None,
            &config,
            &subscriptions,
            handler_signal.clone(),
            pending_child_starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        let syscall = SyscallRequest::new(libc::SYS_getpid as u64, [0; 6])
            .into_syscall()
            .unwrap();
        let outcome = futures::executor::block_on(drive_handler(
            guest.inject(syscall),
            handler_signal,
            pending_child_starts,
            std::future::pending(),
        ));
        assert!(matches!(
            outcome,
            HandlerOutcome::RuntimeError(Error::FamilyWaitLedgerMismatch {
                parent,
                child_pid: 2,
            }) if parent.tgid == Pid::from_raw(1) && parent.generation == 7
        ));
    }

    #[test]
    fn unresolved_children_refuse_every_nonreturning_injection_before_mutation() {
        let requests = [
            SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 0, 0, 0]),
            SyscallRequest::new(
                libc::SYS_execveat as u64,
                [libc::AT_FDCWD as u64, 0x100, 0x200, 0x300, 0, 0],
            ),
            SyscallRequest::new(libc::SYS_exit as u64, [7, 0, 0, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_exit_group as u64, [8, 0, 0, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_kill as u64, [1, libc::SIGKILL as u64, 0, 0, 0, 0]),
            SyscallRequest::new(
                libc::SYS_tkill as u64,
                [1, libc::SIGKILL as u64, 0, 0, 0, 0],
            ),
            SyscallRequest::new(
                libc::SYS_tgkill as u64,
                [1, 1, libc::SIGKILL as u64, 0, 0, 0],
            ),
        ];
        for thread in [false, true] {
            for request in requests {
                let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
                let auxv = [];
                let mut thread_state = ();
                let global_state = crate::StraceLog::default();
                let config = ();
                let subscriptions = Subscription::none();
                let handler_signal = Arc::new(Mutex::new(None));
                let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
                let (start_sender, start_receiver) = std::sync::mpsc::channel();
                let start_gate = ChildStartGate::new(start_sender);
                pending_child_starts.lock().unwrap().push(if thread {
                    PendingChildStart::tool_thread(2, start_gate)
                } else {
                    PendingChildStart::fork_process(2, start_gate)
                });
                let child = std::thread::spawn(move || {
                    assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Cancel);
                });
                let mut executor = PermissiveSideEffectingExecutor::default();
                let mut guest = KvmGuest::<crate::StraceTool>::new(
                    Pid::from_raw(1),
                    Pid::from_raw(1),
                    Arc::new(crate::StraceTool),
                    memory,
                    &auxv,
                    // SAFETY: the test does not inspect any register field.
                    unsafe { std::mem::zeroed() },
                    &mut thread_state,
                    &mut executor,
                    &global_state,
                    None,
                    &config,
                    &subscriptions,
                    handler_signal.clone(),
                    pending_child_starts.clone(),
                    crate::bootstrap::TOOL_STACK_TOP,
                    Arc::new(AtomicBool::new(false)),
                );
                let result =
                    futures::FutureExt::now_or_never(guest.inject(request.into_syscall().unwrap()));
                assert_eq!(result, Some(Err(Errno::ENOSYS)));
                assert!(handler_signal.lock().unwrap().is_none());
                assert_eq!(executor.state, TailInjectionSideEffects::default());

                let pending = pending_child_starts.lock().unwrap().pop().unwrap();
                let expected = if thread {
                    PendingChildKind::ToolThread(2)
                } else {
                    PendingChildKind::ForkProcess(2)
                };
                assert!(matches!(
                    pending.cancel(),
                    PendingChildCancellation::NewlyCancelled {
                        child,
                        delivery_failed: false
                    } if child == expected
                ));
                child.join().unwrap();
            }
        }

        for started_gate in [false, true] {
            let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
            let auxv = [];
            let mut thread_state = ();
            let global_state = crate::StraceLog::default();
            let config = ();
            let subscriptions = Subscription::none();
            let handler_signal = Arc::new(Mutex::new(None));
            let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
            if started_gate {
                let (start_sender, start_receiver) = std::sync::mpsc::channel();
                let start_gate = ChildStartGate::new(start_sender);
                assert_eq!(start_gate.start(), Ok(true));
                assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Start);
                pending_child_starts
                    .lock()
                    .unwrap()
                    .push(PendingChildStart::fork_process(2, start_gate));
            }
            let mut executor = PermissiveSideEffectingExecutor::default();
            let mut guest = KvmGuest::<crate::StraceTool>::new(
                Pid::from_raw(1),
                Pid::from_raw(1),
                Arc::new(crate::StraceTool),
                memory,
                &auxv,
                // SAFETY: the test does not inspect any register field.
                unsafe { std::mem::zeroed() },
                &mut thread_state,
                &mut executor,
                &global_state,
                None,
                &config,
                &subscriptions,
                handler_signal,
                pending_child_starts,
                crate::bootstrap::TOOL_STACK_TOP,
                Arc::new(AtomicBool::new(false)),
            );
            let result = futures::FutureExt::now_or_never(
                guest.inject(
                    SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 0, 0, 0])
                        .into_syscall()
                        .unwrap(),
                ),
            );
            assert_eq!(result, Some(Ok(0)));
            assert_eq!(executor.state.address_space_generation, 1);
            assert_eq!(executor.state.completion_callbacks, 1);
        }
    }

    fn assert_tail_injection_rejected_before_execute(
        executor: &mut SideEffectingExecutor,
        request: SyscallRequest,
    ) {
        let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
        let auxv = [];
        let mut thread_state = ();
        let global_state = crate::StraceLog::default();
        let config = ();
        let subscriptions = Subscription::none();
        let handler_signal = Arc::new(Mutex::new(None));
        let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
        let mut guest = KvmGuest::<crate::StraceTool>::new(
            Pid::from_raw(1),
            Pid::from_raw(1),
            Arc::new(crate::StraceTool),
            memory,
            &auxv,
            // SAFETY: the test does not inspect any register field.
            unsafe { std::mem::zeroed() },
            &mut thread_state,
            executor,
            &global_state,
            None,
            &config,
            &subscriptions,
            handler_signal.clone(),
            pending_child_starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        let syscall = request.into_syscall().unwrap();
        match futures::executor::block_on(drive_handler(
            guest.tail_inject(syscall),
            handler_signal,
            pending_child_starts,
            std::future::pending(),
        )) {
            HandlerOutcome::RuntimeError(Error::Reverie(reverie::Error::Errno(errno))) => {
                assert_eq!(errno, Errno::ENOSYS)
            }
            HandlerOutcome::ParkedFatal(_)
            | HandlerOutcome::ParkedCancelled(_)
            | HandlerOutcome::ParkedRetired(_) => {
                panic!("tail refusal produced unrelated parked outcome")
            }
            HandlerOutcome::RuntimeError(error) => panic!("unexpected tail refusal: {error}"),
            HandlerOutcome::TailInjected { .. } => panic!("tail injection unexpectedly ran"),
            HandlerOutcome::GroupExit(_) => panic!("tail injection unexpectedly exited the group"),
            HandlerOutcome::ThreadCancelled => {
                panic!("tail injection unexpectedly cancelled the thread")
            }
            HandlerOutcome::ThreadRetired => {
                panic!("tail injection unexpectedly retired the thread")
            }
            HandlerOutcome::Returned(_) => panic!("tail injection unexpectedly returned"),
            HandlerOutcome::RunFailed => panic!("unexpected run failure"),
        }
    }

    fn test_process_boundary() -> CompletedSyscallBoundary {
        CompletedSyscallBoundary::for_test()
    }

    #[test]
    fn signal_hook_tail_injection_is_rejected_before_every_executor_side_effect() {
        let boundary = test_process_boundary();
        let request = SyscallRequest::new(libc::SYS_write as u64, [1, 0x100, 4, 0, 0, 0]);
        assert!(
            !ProcessExecutionContext::SignalBoundary(boundary.clone())
                .tail_injection_allowed(&request)
        );
        assert!(
            ProcessExecutionContext::SyscallBoundary(boundary.clone())
                .tail_injection_allowed(&request)
        );
        assert!(ProcessExecutionContext::Lifecycle.tail_injection_allowed(&request));

        let nonfatal_signal =
            SyscallRequest::new(libc::SYS_kill as u64, [1, libc::SIGUSR1 as u64, 0, 0, 0, 0]);
        assert!(
            ProcessExecutionContext::SignalBoundary(boundary)
                .injected_signal_allowed(&nonfatal_signal)
        );
        assert!(
            !ProcessExecutionContext::Lifecycle.injected_signal_allowed(&nonfatal_signal),
            "a lifecycle callback still lacks a resumable signal frame",
        );

        let requests = [
            SyscallRequest::new(libc::SYS_write as u64, [1, 0x100, 4, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_pipe2 as u64, [0x200, 0, 0, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_fork as u64, [0; 6]),
            SyscallRequest::new(
                libc::SYS_clone as u64,
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
            ),
            SyscallRequest::new(libc::SYS_execve as u64, [0x300, 0, 0, 0, 0, 0]),
            SyscallRequest::new(
                libc::SYS_mmap as u64,
                [
                    0,
                    4096,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                    (-1_i32) as u64,
                    0,
                ],
            ),
            SyscallRequest::new(libc::SYS_kill as u64, [1, libc::SIGUSR1 as u64, 0, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_exit as u64, [7, 0, 0, 0, 0, 0]),
        ];
        let mut executor = SideEffectingExecutor::default();
        for request in requests {
            assert_tail_injection_rejected_before_execute(&mut executor, request);
        }
        assert_eq!(executor.state, TailInjectionSideEffects::default());
    }

    #[test]
    fn signal_hook_ordinary_nonreturning_injection_is_rejected_before_side_effects() {
        let requests = [
            SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 0, 0, 0]),
            SyscallRequest::new(
                libc::SYS_execveat as u64,
                [libc::AT_FDCWD as u64, 0x100, 0x200, 0x300, 0, 0],
            ),
            SyscallRequest::new(libc::SYS_exit as u64, [7, 0, 0, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_exit_group as u64, [8, 0, 0, 0, 0, 0]),
            SyscallRequest::new(libc::SYS_kill as u64, [1, libc::SIGKILL as u64, 0, 0, 0, 0]),
            SyscallRequest::new(
                libc::SYS_tkill as u64,
                [1, libc::SIGKILL as u64, 0, 0, 0, 0],
            ),
            SyscallRequest::new(
                libc::SYS_tgkill as u64,
                [1, 1, libc::SIGKILL as u64, 0, 0, 0],
            ),
        ];
        let mut executor = SideEffectingExecutor::default();
        for request in requests {
            let boundary = test_process_boundary();
            assert!(
                !ProcessExecutionContext::SignalBoundary(boundary)
                    .ordinary_injection_allowed(&request)
            );
            let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
            let auxv = [];
            let mut thread_state = ();
            let global_state = crate::StraceLog::default();
            let config = ();
            let subscriptions = Subscription::none();
            let handler_signal = Arc::new(Mutex::new(None));
            let pending_child_starts = Arc::new(Mutex::new(Vec::new()));
            let mut guest = KvmGuest::<crate::StraceTool>::new(
                Pid::from_raw(1),
                Pid::from_raw(1),
                Arc::new(crate::StraceTool),
                memory,
                &auxv,
                // SAFETY: the test does not inspect any register field.
                unsafe { std::mem::zeroed() },
                &mut thread_state,
                &mut executor,
                &global_state,
                None,
                &config,
                &subscriptions,
                handler_signal.clone(),
                pending_child_starts.clone(),
                crate::bootstrap::TOOL_STACK_TOP,
                Arc::new(AtomicBool::new(false)),
            );
            let result =
                futures::FutureExt::now_or_never(guest.inject(request.into_syscall().unwrap()));
            assert_eq!(result, Some(Err(Errno::ENOSYS)));
            assert!(handler_signal.lock().unwrap().is_none());
            assert!(pending_child_starts.lock().unwrap().is_empty());
            assert_eq!(executor.state, TailInjectionSideEffects::default());
        }

        // Returning injections remain available to a structured hook.
        assert!(
            ProcessExecutionContext::SignalBoundary(test_process_boundary())
                .ordinary_injection_allowed(&SyscallRequest::new(
                    libc::SYS_write as u64,
                    [1, 0x100, 4, 0, 0, 0],
                ))
        );
        assert!(
            ProcessExecutionContext::SignalBoundary(test_process_boundary())
                .ordinary_injection_allowed(&SyscallRequest::new(
                    libc::SYS_kill as u64,
                    [1, libc::SIGUSR1 as u64, 0, 0, 0, 0],
                ))
        );
    }

    #[test]
    fn hidden_scratch_commit_initializes_physical_bytes_without_exposing_tool_access() {
        let memory = GuestMemory::new(0, TOOL_STACK_TOP as usize).unwrap();
        expose_tool_scratch(&memory, TOOL_STACK_TOP).unwrap();
        memory.enable_user_access();
        hide_tool_scratch(&memory, TOOL_STACK_TOP).unwrap();
        let checked_out = Arc::new(AtomicBool::new(false));
        let mut stack = KvmStack::new(memory.clone(), TOOL_STACK_TOP, checked_out.clone());
        let address = stack.push(0x1122_3344_u32);
        assert!(stack.read_value(address).is_err());
        let guard = stack.commit().unwrap();
        let mut bytes = [0; 4];
        memory
            .read_raw(address.as_raw() as u64, &mut bytes)
            .unwrap();
        assert_eq!(bytes, 0x1122_3344_u32.to_ne_bytes());
        assert!(memory.user().read_value(address).is_err());
        assert_eq!(
            memory.reservation_kind(TOOL_STACK_TOP - TOOL_STACK_SIZE),
            Some(RegionKind::ToolScratch)
        );
        assert!(checked_out.load(Ordering::SeqCst));
        drop(guard);
        assert!(!checked_out.load(Ordering::SeqCst));
    }

    #[test]
    fn user_copy_stack_forwarder_enforces_permissions_and_exact_prefix() {
        for accessible in [false, true] {
            for (offset, copied) in [(4096, 0), (4093, 3), (0, 8)] {
                let memory = GuestMemory::new(0, TOOL_STACK_TOP as usize).unwrap();
                let base = TOOL_STACK_TOP - 8192;
                memory.write_raw(base, &[0xa5; 8192]).unwrap();
                memory.map_user_permissions(base, 8192, true, true).unwrap();
                memory
                    .map_user_permissions(base + 4096, 4096, accessible, false)
                    .unwrap();
                memory.enable_user_access();
                let checked_out = Arc::new(AtomicBool::new(false));
                let mut stack = KvmStack::new(memory.clone(), TOOL_STACK_TOP, checked_out.clone());
                let address = AddrMut::from_raw((base + offset) as usize).unwrap();
                assert_eq!(
                    stack.write_with_user_access(address, b"12345678"),
                    if copied == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        Ok(copied)
                    }
                );
                assert_eq!(
                    stack.write_with_user_access(AddrMut::from_raw(usize::MAX).unwrap(), &[]),
                    Ok(0)
                );
                let mut actual = [0; 8192];
                memory.read_raw(base, &mut actual).unwrap();
                let mut expected = [0xa5; 8192];
                expected[offset as usize..offset as usize + copied]
                    .copy_from_slice(&b"12345678"[..copied]);
                assert_eq!(actual, expected);
                drop(stack);
                assert!(!checked_out.load(Ordering::SeqCst));
            }
        }
    }

    #[test]
    fn stack_commits_to_shared_guest_memory() {
        let memory = GuestMemory::new(0, TOOL_STACK_TOP as usize).unwrap();
        let checked_out = Arc::new(AtomicBool::new(false));
        let mut stack = KvmStack::new(memory.clone(), TOOL_STACK_TOP, checked_out.clone());
        let address = stack.push(0x1122_3344_u32);
        let guard = stack.commit().unwrap();

        let value = memory.read_value(address).unwrap();
        assert_eq!(value, 0x1122_3344_u32);
        assert!(checked_out.load(Ordering::SeqCst));

        drop(guard);
        assert!(!checked_out.load(Ordering::SeqCst));
    }

    #[test]
    fn dropping_uncommitted_stack_releases_checkout() {
        let memory = GuestMemory::new(0, TOOL_STACK_TOP as usize).unwrap();
        let checked_out = Arc::new(AtomicBool::new(false));

        drop(KvmStack::new(
            memory.clone(),
            TOOL_STACK_TOP,
            checked_out.clone(),
        ));
        assert!(!checked_out.load(Ordering::SeqCst));

        drop(KvmStack::new(memory, TOOL_STACK_TOP, checked_out));
    }

    #[test]
    fn failed_stack_commit_releases_checkout() {
        let memory = GuestMemory::new(0, TOOL_STACK_TOP as usize).unwrap();
        let checked_out = Arc::new(AtomicBool::new(false));
        let mut stack = KvmStack::new(memory.clone(), TOOL_STACK_TOP, checked_out.clone());
        stack.writes.push((memory.guest_end(), vec![0]));

        assert!(matches!(stack.commit(), Err(Errno::EFAULT)));
        assert!(!checked_out.load(Ordering::SeqCst));

        drop(KvmStack::new(memory, TOOL_STACK_TOP, checked_out));
    }

    #[test]
    fn guest_threads_use_disjoint_tool_stacks() {
        let memory = GuestMemory::new(0, BOOT_RESERVED_END as usize).unwrap();
        let first_top = thread_tool_stack_top(0);
        let second_top = thread_tool_stack_top(1);
        let first_checked_out = Arc::new(AtomicBool::new(false));
        let second_checked_out = Arc::new(AtomicBool::new(false));

        expose_tool_scratch(&memory, first_top).unwrap();
        expose_tool_scratch(&memory, second_top).unwrap();
        let mut first = KvmStack::new(memory.clone(), first_top, first_checked_out.clone());
        let mut second = KvmStack::new(memory.clone(), second_top, second_checked_out.clone());
        let first_address = first.push(0x1122_3344_u32);
        let second_address = second.push(0x5566_7788_u32);
        let first_guard = first.commit().unwrap();
        let second_guard = second.commit().unwrap();

        assert_ne!(first_address, second_address);
        assert_eq!(memory.read_value(first_address).unwrap(), 0x1122_3344_u32);
        assert_eq!(memory.read_value(second_address).unwrap(), 0x5566_7788_u32);
        assert!(first_checked_out.load(Ordering::SeqCst));
        assert!(second_checked_out.load(Ordering::SeqCst));

        hide_tool_scratch(&memory, first_top).unwrap();
        assert!(!memory.user_range_is_mapped(tool_stack_bottom(first_top), TOOL_STACK_SIZE));
        assert!(memory.user_range_is_mapped(tool_stack_bottom(second_top), TOOL_STACK_SIZE));

        drop(first_guard);
        drop(second_guard);
        hide_tool_scratch(&memory, second_top).unwrap();
    }

    #[test]
    #[should_panic(expected = "cannot retrieve a KVM guest stack while its previous guard is live")]
    fn same_thread_stack_checkout_still_panics() {
        let memory = GuestMemory::new(0, TOOL_STACK_TOP as usize).unwrap();
        let checked_out = Arc::new(AtomicBool::new(false));
        let _first = KvmStack::new(memory.clone(), TOOL_STACK_TOP, checked_out.clone());

        let _second = KvmStack::new(memory, TOOL_STACK_TOP, checked_out);
    }
}

#[cfg(test)]
#[path = "terminal_runtime_tests.rs"]
mod terminal_tests;

#[cfg(test)]
#[path = "child_exit_runtime_tests.rs"]
mod child_exit_tests;

#[cfg(test)]
#[path = "runtime/failure_tests.rs"]
mod failure_tests;

#[cfg(test)]
#[path = "process_alarm_runtime_tests.rs"]
mod process_alarm_tests;

#[cfg(test)]
#[path = "captured_write_runtime_tests.rs"]
mod captured_write_tests;

#[cfg(test)]
mod callback_completion_tests;

#[cfg(test)]
mod signal_cleanup_completion_tests;

#[cfg(test)]
mod consuming_panic_tests;

#[cfg(test)]
mod worker_execution_panic_tests;

#[cfg(test)]
mod entry_owner_tests;

#[cfg(test)]
mod entry_operation_tests;

#[cfg(test)]
mod exit_descriptor_tests;

#[cfg(test)]
#[path = "runtime/parent_death_tests.rs"]
mod parent_death_tests;
