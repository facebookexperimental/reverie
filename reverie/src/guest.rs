/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Guest (i.e. thread) structure and traits

use async_trait::async_trait;
use reverie_syscalls::Errno;
use reverie_syscalls::MemoryAccess;
use reverie_syscalls::SyscallInfo;

use crate::Never;
use crate::Pid;
use crate::SignalEvent;
use crate::auxv::Auxv;
use crate::backtrace::Backtrace;
use crate::error::Error;
use crate::stack::Stack;
use crate::timer::TimerSchedule;
use crate::tool::GlobalRPC;
use crate::tool::GlobalTool;
use crate::tool::Tool;

/// The logical kind of a guest memory region reported by
/// [`Guest::detlog_memory_regions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetlogRegionKind {
    /// The current thread's user stack.
    Stack,
    /// The program-break heap.
    Heap,
}

/// A guest-address-space memory region a backend can expose for deterministic
/// memory-map logging (`--detlog-stack` / `--detlog-heap`).
///
/// The `[start, end)` bounds are guest virtual addresses readable through
/// [`Guest::memory`]. This exists for out-of-process backends (for example the
/// KVM backend) where [`Guest::pid`] is the host VMM process rather than a
/// process whose `/proc/<pid>/maps` describes the guest's own address space, so
/// the default `/proc`-based enumeration would read the wrong process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetlogMemoryRegion {
    /// Which logical region this is.
    pub kind: DetlogRegionKind,
    /// Inclusive start guest virtual address.
    pub start: u64,
    /// Exclusive end guest virtual address.
    pub end: u64,
}

/// A representation of a guest task (thread).
#[async_trait]
pub trait Guest<T: Tool>: Send + GlobalRPC<T::GlobalState> {
    /// Access to guest memory
    type Memory: MemoryAccess + Send;

    /// Access to guest stack
    type Stack: Send + Stack;

    /// Thread ID of the guest task.
    fn tid(&self) -> Pid;

    /// Process ID of the process containing the guest task.
    fn pid(&self) -> Pid;

    /// Process ID of the parent process. Returns `None` if this is the root of
    /// the traced process tree. A return value of `None` does not necessarily
    /// mean it is the root process in the system.
    fn ppid(&self) -> Option<Pid>;

    /// Returns true if this thread is the thread group leader (i.e., the main
    /// thread).
    fn is_main_thread(&self) -> bool {
        self.tid() == self.pid()
    }

    /// Returns true if this is considered the root process of the traced task
    /// tree (i.e., if `getppid()` returns `None`).
    fn is_root_process(&self) -> bool {
        self.ppid().is_none()
    }

    /// Returns true if this is considered the root thread of the traced task
    /// tree (i.e., if `getppid()` returns `None` and `is_main_thread` returns
    /// true).
    fn is_root_thread(&self) -> bool {
        self.is_root_process() && self.is_main_thread()
    }

    /// Whether this task is still executing the launcher for a spawned Command.
    ///
    /// This is logging provenance, not a guest identity or execution-mode test.
    /// A backend may return true only for its Command-launch root before the
    /// first successful exec replaces the inherited launcher address space.
    /// Function tests, attached tasks, descendants and post-exec guest tasks
    /// must return false. Callers must additionally establish the type of any
    /// value before formatting a launch-image pointer as a host address.
    fn is_command_bootstrap(&self) -> bool {
        false
    }

    /// Whether this task is executing a backend-owned, guest-resident
    /// runtime's bootstrap on the guest's behalf, rather than guest code.
    ///
    /// A backend may return true only for the one thread that executed a
    /// validated runtime-begin event, and only until the matching event that
    /// ends the bootstrap of that exec generation: the runtime's ready report,
    /// or its report that preparation failed. These events are trap points at
    /// fixed positions in the traced program, so the window is deterministic.
    /// Backends without a guest-resident runtime, every other thread or forked
    /// process, and every task outside such a window, return false.
    ///
    /// The window covers the runtime's own preparation between those two
    /// events. Guest constructors that run before the begin event (for example
    /// those of the executable's `DT_NEEDED` libraries) or after the ending
    /// event are outside it. One kind of guest code is inside it: code that
    /// the runtime reaches through an import the guest interposes on, such as
    /// an exported `malloc` or `open64`. It runs on the bootstrapping thread
    /// and is reported as part of the bootstrap.
    ///
    /// The syscalls issued in this window are still delivered to the Tool,
    /// which must still handle them: the Tool keeps full knowledge of the file
    /// descriptors and mappings they create. A Tool that models guest-visible
    /// resource consumption, such as a virtual clock charged per syscall, must
    /// not attribute these syscalls to the guest. Otherwise the same program
    /// observes a different state under a backend that performs no such
    /// bootstrap.
    fn is_backend_runtime_bootstrap(&self) -> bool {
        false
    }

    /// Reads and returns the auxv table for this process.
    fn auxv(&self) -> Auxv {
        Auxv::new(self.pid()).expect("failed to read auxv table")
    }

    /// Returns a representation of the address space associated with this guest
    /// thread.
    fn memory(&self) -> Self::Memory;

    /// Returns a mutable reference to thread state.
    fn thread_state_mut(&mut self) -> &mut T::ThreadState;

    /// Returns an immutable reference to thread state.
    fn thread_state(&self) -> &T::ThreadState;

    /// Returns the current register values of the guest thread.
    async fn regs(&mut self) -> libc::user_regs_struct;

    /// Overwrites the register values of the guest thread. This is the write
    /// counterpart to [`Guest::regs`].
    ///
    /// This is a generic, determinism-agnostic mechanism: it lets a tool control
    /// the guest's register file at a stop, and the tool decides what values to
    /// write. For example, a determinism tool can use it to canonicalize
    /// registers that the syscall instruction clobbers (`%rcx`/`%r11` on
    /// x86-64) so that even a misbehaving guest observes deterministic state.
    ///
    /// Preconditions: the guest is in a stopped state and Reverie is currently
    /// running a handler on that guest thread's behalf.
    ///
    /// The default implementation returns [`Errno::ENOSYS`] for backends that
    /// cannot write guest registers.
    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        let _ = regs;
        Err(Errno::ENOSYS.into())
    }

    /// Returns the current stack pointer with this guest thread.
    async fn stack(&mut self) -> Self::Stack;

    /// Task is trying to become a daemon. The tracer may choose to kill all
    /// remaining tasks when daemons are the only ones left.
    async fn daemonize(&mut self);

    /// Inject a system call into the guest and wait for the return value. This
    /// function dirties the register file while its executing, but restores at
    /// the end.
    ///
    /// Preconditions: the guest is in a stopped state and Reverie is currently
    /// running a handler on that guest thread's behalf.
    ///
    /// Postconditions: the register file is the same as before the call to this
    /// function. However, any side effects, including to guest memory, persist
    /// after the injected call.
    ///
    /// # Caveats
    ///
    /// A few syscalls are special and behave differently from the rest:
    ///  - `exit` or `exit_group` will never return when injected. Since these
    ///    syscalls will cause the current thread or process to exit, no code that
    ///    comes after can be executed.
    ///  - `execve` will never return when *successfully* injected. If you wish to
    ///    handle successful calls to `execve`, use [`Tool::handle_post_exec`].
    ///    Failed calls to `execve` will still return, however. Thus, it is safe to
    ///    use [`Result::unwrap_err`] on the result of the `inject`.
    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno>;

    /// Similar to [`Guest::inject`], except that it never returns. Since it does
    /// not return to the caller, the syscall return value cannot be altered or
    /// inspected. This method exists as an optimization for the `ptrace`
    /// backend, so that we can avoid interrupting the guest if we don't care
    /// about the syscall return value.
    ///
    /// # Caveats
    ///
    /// This method comes with a major footgun. Any code written after
    /// `tail_inject` will never be executed:
    ///
    /// ```no_run
    /// use reverie::syscalls::*;
    /// use reverie::*;
    ///
    /// #[derive(Debug, Default, Clone)]
    /// struct MyTool;
    ///
    /// #[reverie::tool]
    /// impl Tool for MyTool {
    ///     /// Global state is unused
    ///     type GlobalState = ();
    ///     /// Count of successful syscalls.
    ///     type ThreadState = u64;
    ///
    ///     async fn handle_syscall_event<T: Guest<Self>>(
    ///         &self,
    ///         guest: &mut T,
    ///         syscall: Syscall,
    ///     ) -> Result<i64, Error> {
    ///         let ret = match syscall {
    ///             Syscall::Open(syscall) => guest.tail_inject(syscall).await,
    ///             _ => guest.inject(syscall).await?,
    ///         };
    ///
    ///         // This is never called if we got the `open` syscall above!!
    ///         *guest.thread_state_mut() += 1;
    ///
    ///         Ok(ret)
    ///     }
    /// }
    /// ```
    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never;

    /// Terminates the current guest thread with status zero after the Tool has
    /// determined that this thread must never resume guest execution.
    ///
    /// This abandons the current callback and runs the backend's consuming
    /// thread-exit cleanup exactly once. It accepts no syscall and does not
    /// authorize other nonreturning injections from restricted callbacks.
    /// It does not request termination of other live threads. Backends whose
    /// ordinary exit injection already provides this contract use that path.
    /// An already-established backend exit retains its status.
    ///
    /// Backend process-lifetime limits still apply. Explicit KVM leader cancellation
    /// cancels live siblings, while normal raw leader `SYS_exit` leaves them running.
    /// Nonleader cancellation also leaves live siblings running.
    async fn cancel_current_thread(&mut self) -> Never {
        self.tail_inject(reverie_syscalls::Exit::default()).await
    }

    /// Retires only the current guest thread after the Tool has determined
    /// that it must never resume, without requesting cancellation of peers.
    ///
    /// This abandons the callback and runs consuming thread cleanup once. It
    /// defaults to a raw thread exit with status zero; an established backend
    /// exit keeps its status. A KVM leader retains and joins live workers, then
    /// adopts the final process status, including a peer's later group exit.
    /// Unlike explicit cancellation, retirement does not discard their work.
    /// Restricted signal callbacks do not gain arbitrary syscall injection.
    async fn retire_current_thread(&mut self) -> Never {
        self.tail_inject(reverie_syscalls::Exit::default()).await
    }

    /// Defers one already-selected signal for delivery by the backend at its
    /// next safe return-to-userspace boundary.
    ///
    /// Backends may return `ENOSYS` when the current callback has no resumable
    /// userspace register context (for example, a lifecycle callback), when
    /// signal provenance is unsupported, or when deterministic recipient
    /// selection is not available. Callers must handle that refusal rather
    /// than assuming the event was queued.
    ///
    /// This is additive to the historical host-signal path. Backends that do
    /// not own a virtual guest signal frame retain the default explicit
    /// `ENOSYS`; adding this method does not change ptrace signal delivery.
    async fn defer_signal_delivery(&mut self, _event: SignalEvent) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    /// Queues a Tool-selected terminal child event for the current process.
    ///
    /// The caller supplies a complete process-directed `SIGCHLD` event with
    /// `CLD_EXITED`, `CLD_KILLED`, or `CLD_DUMPED`, and owns its child-status
    /// provenance and deterministic ordering. `CLD_EXITED` carries an unsigned
    /// exit byte; `CLD_KILLED` carries a terminal-default Linux signal number;
    /// `CLD_DUMPED` carries a core-default signal number. The backend validates
    /// the receiver and that class-specific status domain, preserves
    /// process-wide pending ownership and first-siginfo coalescing, and reports
    /// whether queue publication preceded any failure. Wait status and child reaping remain
    /// independent. This operation never recursively invokes a Tool hook or
    /// resumes guest instructions; normal receiver boundaries own delivery.
    ///
    /// Backends may refuse unsupported contexts or process lifetimes. In
    /// particular, KVM initially supports only a live single-thread parent at
    /// a transported return-to-user boundary. A KVM run that installs
    /// [`crate::BackendSignalControlMode::ToolControlled`] must instead use the
    /// generation-bound run-scoped
    /// [`crate::ProcessSignalControl::publish_child_exit`] operation; this
    /// generation-free compatibility surface is then refused before mutation.
    /// The historical private deferral operation and its refusal policy are
    /// otherwise unchanged.
    async fn queue_child_exit_signal(
        &mut self,
        _event: SignalEvent,
    ) -> crate::ChildExitSignalOutcome {
        crate::ChildExitSignalOutcome::RejectedBeforeCommit {
            kind: crate::ChildExitSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }

    /// Publishes a Tool-selected process alarm at this stopped task's boundary.
    ///
    /// The caller owns deterministic ordering and supplies the complete normal
    /// Linux SIGALRM/SI_KERNEL siginfo (zero except for signo and code). KVM
    /// supports only the current sole live receiver, with no pending process
    /// action and a resumable transported boundary that has not completed an
    /// injected process action. The operation preserves
    /// shared pending ownership and first siginfo, including when blocked or
    /// ignored. Installing SIG_IGN later invalidates older pending generations.
    ///
    /// No Tool hook, guest instruction, timer operation, or wait completion is
    /// performed. The receipt is only pending-state publication. The historical
    /// private [`Guest::defer_signal_delivery`] operation remains independent.
    async fn queue_process_alarm_signal(
        &mut self,
        _event: SignalEvent,
    ) -> crate::ProcessAlarmSignalOutcome {
        crate::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
            kind: crate::ProcessAlarmSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }

    /// Backend process/task lifetime identity, including at thread start.
    fn signal_task_identity(&self) -> Option<crate::SignalTaskIdentity> {
        None
    }

    /// Current parked-observation capability, bound to this exact callback.
    fn parked_signal_site(&self) -> Option<crate::CallbackSignalSite> {
        None
    }

    /// Authenticates a zero-effect attempt of this exact original scalar read.
    ///
    /// A site is returned only after an actual injection of the identical raw
    /// syscall and arguments returned EAGAIN/EWOULDBLOCK, while its original
    /// callback remains live. A later injection invalidates that attempt. A
    /// positive/partial result, EOF, another errno or another syscall is never
    /// eligible. This query does not execute or restart the read, consume a
    /// signal or grant scheduler ownership. Unsupported backends return None.
    fn polled_read_signal_site(
        &self,
        _call: crate::syscalls::Read,
    ) -> Option<crate::CallbackSignalSite> {
        None
    }

    /// Authenticates the current original scalar write to backend-captured output.
    ///
    /// This read-only query returns the full callback identity only when `call`
    /// is the exact unconsumed original syscall (including all raw arguments)
    /// and its current descriptor aliases an enabled captured stdout/stderr
    /// stream. It does not execute the write, publish or consume a signal,
    /// validate the buffer, or promise a successful byte count.
    ///
    /// The caller must query again with the identical call immediately before
    /// publication and require the same identity, without an intervening guest
    /// operation or injection. KVM additionally requires its existing sole-live-
    /// leader boundary, no prior injected execution, and no active observation
    /// or checked-out stack. Ordinary files, pipes, sockets and uncaptured host
    /// streams are not admitted by this query. The query does not change signal
    /// publication admission; callers must act on `None` themselves. Unsupported
    /// backends return `None`.
    fn captured_write_signal_site(
        &self,
        _call: crate::syscalls::Write,
    ) -> Option<crate::CallbackSignalSite> {
        None
    }

    /// Active nested observation, available to the Tool's real signal-hook RPCs.
    fn signal_observation_lease(&self) -> Option<crate::ParkedObservationLease> {
        None
    }

    /// Sequentially observes real pending events without abandoning the original syscall.
    async fn observe_parked_signal(
        &mut self,
        _site: crate::CallbackSignalSite,
        _lease: crate::ParkedObservationLease,
    ) -> Result<crate::ParkedSignalObservation, crate::SignalObservationFailure> {
        Err(crate::SignalObservationFailure::RejectedBeforeRemoval {
            errno: Errno::ENOSYS,
        })
    }

    /// Transfers a reserved fatal selection to the driver; success never returns.
    async fn terminate_from_parked_signal(
        &mut self,
        _selection: crate::PreparedSignalToken,
    ) -> Result<Never, crate::SignalObservationFailure> {
        Err(crate::SignalObservationFailure::RejectedBeforeRemoval {
            errno: Errno::ENOSYS,
        })
    }

    /// Retained irreversible effects, independently of the current observation lease.
    fn parked_signal_failure_context(&self) -> Option<crate::ParkedSignalFailureContext> {
        None
    }

    /// Cancels through the driver without tail-injecting Exit or rolling back effects.
    async fn cancel_parked_signal(
        &mut self,
        _context: crate::ParkedSignalFailureContext,
    ) -> Result<Never, crate::SignalObservationFailure> {
        Err(crate::SignalObservationFailure::RejectedBeforeRemoval {
            errno: Errno::ENOSYS,
        })
    }

    /// Like [`Guest::inject`], but will retry the syscall if `EINTR` or
    /// `ERESTARTSYS` are returned.
    ///
    /// This is useful if we need to inject a syscall other than the one
    /// currently being handled in `handle_syscall_event`. If we don't retry
    /// interrupted syscalls, we could end up running the real syscall more than
    /// once.
    async fn inject_with_retry<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        loop {
            match self.inject(syscall).await {
                Ok(x) => return Ok(x),
                Err(Errno::EINTR) | Err(Errno::ERESTARTSYS) => continue,
                Err(other) => return Err(other),
            }
        }
    }

    /// Converts this `Guest<T>` such that it implements `Guest<U>`. This is
    /// useful when forwarding callbacks to a "child" tool.
    #[allow(clippy::wrong_self_convention)]
    fn into_guest(&mut self) -> IntoGuest<'_, Self, T> {
        IntoGuest::new(self)
    }

    /// Request that a single timer event occur in the future according to
    /// `sched`.
    ///
    /// There is only a single timer, so repeatedly setting a timer event delays
    /// the delivery of the single timer event that will eventually fire.
    ///
    /// Timer events are cancelled by the delivery of other event types. If
    /// receiving timer events is critical, your tool must override all event
    /// listeners and reschedule your timer within them.
    ///
    /// This requests a non-deterministic timer event, which will occur after _at
    /// least_ `sched` has elapsed, but no guarantees are made for delivery. As a
    /// result, the event will likely have much less overhead than one set with
    /// [`Guest::set_timer_precise`].
    fn set_timer(&mut self, sched: TimerSchedule) -> Result<(), Error>;

    /// Request that a single timer event occur in the future according to
    /// `sched`.
    ///
    /// Functions identically to [`Guest::set_timer`], except that the resulting
    /// event will be delivered _exactly_ when `sched` has elapsed. This results
    /// in a far higher overhead to deliver an event.
    fn set_timer_precise(&mut self, sched: TimerSchedule) -> Result<(), Error>;

    /// Read a thread-local monotonic clock which is never reset. The starting
    /// value, resolution, and semantics of the ticks are
    /// implementation-specific.
    fn read_clock(&mut self) -> Result<u64, Error>;

    /// Returns a stack trace starting at the current location of the guest
    /// thread. If a backtrace is not available, returns `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use reverie::syscalls::*;
    /// use reverie::*;
    ///
    /// #[derive(Debug, Default, Clone)]
    /// struct MyTool;
    ///
    /// #[reverie::tool]
    /// impl Tool for MyTool {
    ///     type GlobalState = ();
    ///     type ThreadState = ();
    ///
    ///     async fn handle_syscall_event<T: Guest<Self>>(
    ///         &self,
    ///         guest: &mut T,
    ///         syscall: Syscall,
    ///     ) -> Result<i64, Error> {
    ///         // Generate a backtrace whenever we receive a call to getpid().
    ///         if let Syscall::Getpid(_) = &syscall {
    ///             if let Some(frames) = guest.backtrace() {
    ///                 println!("Backtrace for getpid():");
    ///                 for frame in frames {
    ///                     println!("  {}", frame);
    ///                 }
    ///             }
    ///         }
    ///
    ///         Ok(guest.inject(syscall).await?)
    ///     }
    /// }
    /// ```
    fn backtrace(&mut self) -> Option<Backtrace> {
        None
    }

    /// Returns true if all of the following conditions are true:
    ///  1. [`Tool::subscriptions`] returns an interest in intercepting CPUID.
    ///  2. We're able to trap and intercept the CPUID instruction. We may not
    ///     be able to do this for virtual machines as this functionality is
    ///     often disabled for VMs.
    ///  3. We're running on x86-64. Other architectures don't have the CPUID
    ///     instruction.
    fn has_cpuid_interception(&self) -> bool {
        false
    }

    /// Returns the guest-address memory regions this backend wants hashed for
    /// deterministic memory-map logging, or `None` to fall back to reading
    /// `/proc/<pid>/maps` for the process returned by [`Guest::pid`].
    ///
    /// The default is `None`, which preserves the historical behavior used by
    /// the ptrace backend, where `pid()` is the guest process and its
    /// `/proc/<pid>/maps` correctly describes the guest address space.
    ///
    /// Out-of-process backends whose `pid()` is not the guest (for example the
    /// KVM backend, where it is the host VMM process) override this to return
    /// real guest stack/heap ranges readable through [`Guest::memory`], so the
    /// determinism engine hashes the guest's memory instead of the VMM's.
    fn detlog_memory_regions(&self) -> Option<Vec<DetlogMemoryRegion>> {
        None
    }
}

/// Wraps a `Guest<T>` such that it implements `Guest<U>`.
///
/// # Limitations
///
/// `T` and `U` must have the same global state. This limitation may be removed
/// in the future.
pub struct IntoGuest<'a, G: ?Sized, U> {
    inner: &'a mut G,
    _phantom: core::marker::PhantomData<U>,
}

impl<'a, G: ?Sized, U> IntoGuest<'a, G, U> {
    /// Creates a new `IntoGuest`.
    pub fn new(guest: &'a mut G) -> Self {
        Self {
            inner: guest,
            _phantom: core::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<'a, G, U> GlobalRPC<U::GlobalState> for IntoGuest<'a, G, U>
where
    G: Guest<U> + ?Sized,
    U: Tool,
{
    async fn send_rpc(
        &self,
        message: <U::GlobalState as GlobalTool>::Request,
    ) -> <U::GlobalState as GlobalTool>::Response {
        self.inner.send_rpc(message).await
    }

    fn config(&self) -> &<U::GlobalState as GlobalTool>::Config {
        self.inner.config()
    }
}

#[async_trait]
impl<'a, G, U, L> Guest<L> for IntoGuest<'a, G, U>
where
    G: Guest<U> + ?Sized,
    L: Tool<GlobalState = U::GlobalState>,
    U: Tool + AsMut<L>,
    U::ThreadState: AsRef<L::ThreadState> + AsMut<L::ThreadState>,
{
    type Memory = G::Memory;
    type Stack = G::Stack;

    fn tid(&self) -> Pid {
        self.inner.tid()
    }

    fn pid(&self) -> Pid {
        self.inner.pid()
    }

    fn ppid(&self) -> Option<Pid> {
        self.inner.ppid()
    }

    fn is_command_bootstrap(&self) -> bool {
        self.inner.is_command_bootstrap()
    }

    fn is_backend_runtime_bootstrap(&self) -> bool {
        self.inner.is_backend_runtime_bootstrap()
    }

    fn is_main_thread(&self) -> bool {
        self.inner.is_main_thread()
    }

    fn is_root_process(&self) -> bool {
        self.inner.is_root_process()
    }

    fn is_root_thread(&self) -> bool {
        self.inner.is_root_thread()
    }

    fn memory(&self) -> Self::Memory {
        self.inner.memory()
    }

    fn thread_state_mut(&mut self) -> &mut L::ThreadState {
        self.inner.thread_state_mut().as_mut()
    }

    fn thread_state(&self) -> &L::ThreadState {
        self.inner.thread_state().as_ref()
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        self.inner.regs().await
    }

    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        self.inner.set_regs(regs).await
    }

    async fn stack(&mut self) -> Self::Stack {
        self.inner.stack().await
    }

    async fn daemonize(&mut self) {
        self.inner.daemonize().await
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        self.inner.inject(syscall).await
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        #![allow(unreachable_code)]
        self.inner.tail_inject(syscall).await
    }

    async fn cancel_current_thread(&mut self) -> Never {
        self.inner.cancel_current_thread().await
    }

    async fn retire_current_thread(&mut self) -> Never {
        self.inner.retire_current_thread().await
    }

    async fn defer_signal_delivery(&mut self, event: SignalEvent) -> Result<(), Error> {
        self.inner.defer_signal_delivery(event).await
    }

    async fn queue_child_exit_signal(
        &mut self,
        event: SignalEvent,
    ) -> crate::ChildExitSignalOutcome {
        self.inner.queue_child_exit_signal(event).await
    }

    async fn queue_process_alarm_signal(
        &mut self,
        event: SignalEvent,
    ) -> crate::ProcessAlarmSignalOutcome {
        self.inner.queue_process_alarm_signal(event).await
    }

    fn signal_task_identity(&self) -> Option<crate::SignalTaskIdentity> {
        self.inner.signal_task_identity()
    }
    fn parked_signal_site(&self) -> Option<crate::CallbackSignalSite> {
        self.inner.parked_signal_site()
    }
    fn polled_read_signal_site(
        &self,
        call: crate::syscalls::Read,
    ) -> Option<crate::CallbackSignalSite> {
        self.inner.polled_read_signal_site(call)
    }
    fn captured_write_signal_site(
        &self,
        call: crate::syscalls::Write,
    ) -> Option<crate::CallbackSignalSite> {
        self.inner.captured_write_signal_site(call)
    }
    fn signal_observation_lease(&self) -> Option<crate::ParkedObservationLease> {
        self.inner.signal_observation_lease()
    }
    async fn observe_parked_signal(
        &mut self,
        site: crate::CallbackSignalSite,
        lease: crate::ParkedObservationLease,
    ) -> Result<crate::ParkedSignalObservation, crate::SignalObservationFailure> {
        self.inner.observe_parked_signal(site, lease).await
    }
    async fn terminate_from_parked_signal(
        &mut self,
        selection: crate::PreparedSignalToken,
    ) -> Result<Never, crate::SignalObservationFailure> {
        self.inner.terminate_from_parked_signal(selection).await
    }
    fn parked_signal_failure_context(&self) -> Option<crate::ParkedSignalFailureContext> {
        self.inner.parked_signal_failure_context()
    }
    async fn cancel_parked_signal(
        &mut self,
        context: crate::ParkedSignalFailureContext,
    ) -> Result<Never, crate::SignalObservationFailure> {
        self.inner.cancel_parked_signal(context).await
    }

    fn set_timer(&mut self, sched: TimerSchedule) -> Result<(), Error> {
        self.inner.set_timer(sched)
    }

    fn set_timer_precise(&mut self, sched: TimerSchedule) -> Result<(), Error> {
        self.inner.set_timer_precise(sched)
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        self.inner.read_clock()
    }

    fn backtrace(&mut self) -> Option<Backtrace> {
        self.inner.backtrace()
    }

    fn has_cpuid_interception(&self) -> bool {
        self.inner.has_cpuid_interception()
    }

    fn detlog_memory_regions(&self) -> Option<Vec<DetlogMemoryRegion>> {
        self.inner.detlog_memory_regions()
    }
}
