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
use reverie_syscalls::Sysno;

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

/// Backend facts permitting a shared controller to inspect this physical task.
///
/// The procfs identity names the authenticated root directory of the backend's
/// initial procfs view, not a task directory. A controller must match that view
/// and its registered task incarnation, and exclude all other guest execution,
/// before opening a temporary metadata descriptor. This is not itself a
/// scheduling grant or permission to inspect an arbitrary process.
///
/// `Some` also attests that RPCs use an external controller and that no native
/// child admission or copied-execution uncertainty remains. Under the shared
/// controller's exclusive-execution guard, that certainty lasts through a
/// non-yielding synchronous request; the caller must not inject a lifecycle or
/// namespace operation between obtaining the fact and sending that request.
/// The numeric fields alone convey none of this authority.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize
)]
pub struct ControllerCaptureFact {
    /// Physical process ID in the authenticated procfs view.
    pub physical_pid: Pid,
    /// Physical thread ID in the authenticated procfs view.
    pub physical_tid: Pid,
    /// Device of the authenticated procfs root directory.
    pub procfs_device: u64,
    /// Inode of the authenticated procfs root directory.
    pub procfs_inode: u64,
}

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

/// Why [`Guest::set_blocked_signals`] did not set the mask. `Unsupported` and
/// `RestorePending` are refusals made before anything changed; `Gone` and
/// `Failed` can follow a write.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    thiserror::Error,
    serde::Serialize,
    serde::Deserialize
)]
pub enum MaskChangeRefused {
    /// The backend cannot change the mask at this stop. Nothing was changed.
    #[error("the backend cannot set the blocked-signal mask at this stop")]
    Unsupported,
    /// A mask-swapping syscall's temporary mask (`effective`) is in effect and
    /// its restore of `saved` is pending; changing the mask would discard that
    /// restore. Nothing was changed.
    #[error("a temporary signal mask {effective:#x} is in effect, restoring {saved:#x}")]
    RestorePending {
        /// The mask the pending restore would put back.
        saved: u64,
        /// The mask the kernel dequeues under now.
        effective: u64,
    },
    /// The thread is gone. Nothing will resume it.
    #[error("the thread is gone")]
    Gone,
    /// The change failed with `errno`, possibly after the new mask was
    /// written. The backend then tried to put the old mask back: when
    /// `mask_unknown` is false, the thread's mask is the one before the call;
    /// when it is true, the mask could not be confirmed, and the caller must
    /// not resume the guest as if it were known.
    #[error("setting the blocked-signal mask failed ({errno}); mask unknown: {mask_unknown}")]
    Failed {
        /// The error that stopped the change.
        errno: Errno,
        /// Whether the thread's mask may be neither the old nor the new one.
        mask_unknown: bool,
    },
}

/// An exclusively runtime-owned half-open interval in a guest address space.
///
/// These facts do not describe a complete guest VMA inventory. Tools decide
/// how to project them into observations without hiding adjacent guest bytes.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize
)]
pub struct RuntimePrivateMemoryRegion {
    /// Inclusive virtual address.
    pub start: u64,
    /// Exclusive virtual address.
    pub end: u64,
}

/// A bounded set of private intervals belonging to one address-space image.
///
/// The opaque owner and version are meaningful only within the authenticated
/// run that supplied them. They must not be reconstructed from a PID or an
/// address. A Tool may retain the snapshot for a bound target, but must validate
/// it before and after observing that target. Validation cannot silently
/// substitute the calling task's image.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimePrivateMemorySnapshot {
    /// Backend-owned lifetime identity, opaque to the Tool.
    pub owner: [u64; 4],
    /// Non-reused revision of this owner's authority.
    pub version: u64,
    /// Exclusively owned intervals; no allocator lock is retained.
    pub regions: Vec<RuntimePrivateMemoryRegion>,
}

/// Result from a backend that advertises private-memory ownership facts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuntimePrivateMemory {
    /// Current authoritative facts, subject to live validation.
    Ready(RuntimePrivateMemorySnapshot),
    /// The provider cannot establish current ownership. This is not the
    /// absence of a provider and must not authorize a best-effort projection.
    Unavailable,
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

    /// Facts for a synchronous controller capture while this task is stopped.
    ///
    /// `Some` additionally certifies that no backend-native child is outside
    /// Tool admission. It remains valid only while the caller retains its
    /// exclusive shared execution turn and does not resume or inject a guest
    /// lifecycle operation. Unknown ownership, lost state, or an unmediated
    /// execution history must return `None`. Other backends default to no fact.
    fn controller_capture_fact(&self) -> Option<ControllerCaptureFact> {
        None
    }

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

    /// Whether `fd` in this task's current descriptor table is owned by the
    /// backend runtime rather than the guest application.
    ///
    /// This reports an actual live ownership fact, not a reserved numeric
    /// range. A backend must not report a descriptor after releasing its slot
    /// for application reuse, or apply another process's ownership to this
    /// task. Tools decide how to project these facts into guest observations.
    /// Backends without guest-resident private descriptors return false.
    fn is_runtime_owned_fd(&self, _fd: i32) -> bool {
        false
    }

    /// Reports this image's known runtime-private memory intervals.
    ///
    /// The default has no provider and preserves the Tool's existing behavior.
    /// A provider must return `Some(Unavailable)` when its authority is lost,
    /// including a retired image, rather than masquerading as this default.
    /// Returned intervals must remain exclusively owned while their token is
    /// valid; internal commitment/protection changes do not alter that fact.
    fn runtime_private_memory_regions(&self) -> Option<RuntimePrivateMemory> {
        None
    }

    /// Validates a previously supplied target's ownership snapshot in this run.
    ///
    /// This may be a different task's image. The backend must validate the
    /// supplied opaque owner and version, not the caller's current addresses.
    /// A false result forbids using the snapshot. Calls must not retain a lock
    /// or borrowed runtime storage across subsequent Tool work.
    fn runtime_private_memory_is_current(&self, _snapshot: &RuntimePrivateMemorySnapshot) -> bool {
        false
    }

    /// The guest's stack pointer at the current image's first instruction:
    /// the address of `argc`, above which the kernel (or a loader standing
    /// in for it) laid out `argv`, `envp` and the auxiliary vector. `Some`
    /// only when the backend observed that stack pointer itself, at the exec
    /// stop or the image's entry, before any guest instruction ran; a task
    /// forked or cloned from such an image reports the same value, as it
    /// shares that image. `None` where the backend did not observe it, for
    /// example where the post-exec callback runs only at the image's first
    /// syscall, by which point the stack pointer has moved.
    ///
    /// A Tool that reads the initial stack through `Guest::memory` must take
    /// its address from here and never from `regs()` in the post-exec
    /// callback, which on some backends is not the image's first
    /// instruction.
    fn initial_stack_pointer(&self) -> Option<u64> {
        None
    }

    /// Reads and returns the auxv table for this process.
    fn auxv(&self) -> Auxv {
        Auxv::new(self.pid()).expect("failed to read auxv table")
    }

    /// Returns a representation of the address space associated with this guest
    /// thread.
    fn memory(&self) -> Self::Memory;

    /// Execute one synchronous syscall on behalf of the Tool, on the calling
    /// operating-system thread. This is a host operation, not guest injection:
    /// the syscall number, six arguments, result and errno pass through unchanged.
    /// The executor adds no allocation, lock, RPC, callback dispatch, retry or
    /// caching, and retains no pointers after returning to the original stack.
    /// Normal syscall interception and kernel-delivered signals still apply.
    ///
    /// # Safety
    ///
    /// The caller must supply valid Tool-owned addresses and physical file
    /// descriptors, with every memory access and other syscall effect respecting
    /// Rust's invariants. Guest addresses and logical descriptors must first be
    /// resolved by their owning abstractions. The call must return normally on
    /// this thread and stack: replacement-stack clone, `rt_sigreturn`, and other
    /// operations that invalidate the calling Rust context are not supported.
    /// Kernel-delivered signals and an `EINTR` result retain their normal meaning.
    unsafe fn tool_syscall(&self, number: Sysno, args: [usize; 6]) -> Result<usize, Errno> {
        unsafe { syscalls::syscall6(number, args[0], args[1], args[2], args[3], args[4], args[5]) }
    }

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
    ///
    /// A signal can stop the injected syscall before it runs. The call then
    /// returns `Err(ERESTARTSYS)` rather than a value read from the register
    /// file, and the syscall has had no effect; [`Guest::inject_with_retry`]
    /// injects it again.
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

    /// Like [`Guest::defer_signal_delivery`], but from a syscall's entry: the
    /// current syscall has not run and the Tool must not run it. The backend
    /// delivers the signal first and the syscall then starts from the
    /// beginning, with its registers as the guest left them; whatever the
    /// callback returns is discarded.
    ///
    /// This is a pending signal that became deliverable without passing a
    /// delivery point: Linux delivers it before the next guest instruction,
    /// so before this syscall. Backends without a virtual guest signal frame
    /// keep the default `ENOSYS`, and the Tool then runs the syscall as usual.
    async fn defer_signal_delivery_before_syscall(
        &mut self,
        _event: SignalEvent,
    ) -> Result<(), Error> {
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

    /// The siginfo of the signal [`Tool::handle_signal_event`] is reporting,
    /// while that callback runs: the Linux `siginfo_t` bytes the kernel
    /// delivered with it, as in [`crate::SignalEvent`]. `None` outside that
    /// callback, and where the backend cannot read it.
    fn signal_info(&self) -> Option<[u8; crate::SIGNAL_INFO_SIZE]> {
        None
    }

    /// From inside [`Tool::handle_signal_event`], replaces the siginfo that the
    /// reported signal is delivered with, if the callback returns it to be
    /// delivered. A later call replaces an earlier one. Fails, and changes
    /// nothing, with `EINVAL` outside that callback or for a siginfo whose
    /// `si_signo` is not the reported signal's, with `ENOSYS` where the
    /// backend cannot set a siginfo, and with the backend's error where it
    /// cannot set this one now (the ptrace backend: `EBUSY` after an
    /// injection left the thread at a stop other than a signal-delivery stop,
    /// or `PTRACE_SETSIGINFO`'s error). The backend fails the guest's resume,
    /// rather than deliver another siginfo, if an injection after a successful
    /// call makes the replacement impossible.
    fn set_signal_info(&mut self, _info: [u8; crate::SIGNAL_INFO_SIZE]) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// From inside [`Tool::handle_signal_event`] (or
    /// [`Tool::handle_raw_signal_event`]), approves the reported signal for
    /// delivery with what Linux will do with it, as the tool computed from its
    /// own copy of the thread's signal state: its caught action, the mask the
    /// frame saves, the mask in effect now, the handler's mask, and what the
    /// thread was doing ([`crate::SignalDelivery`]).
    ///
    /// A backend whose kernel delivers the signal (ptrace) checks the
    /// approval against the kernel at the stop, reading only, and answers
    /// [`crate::SignalDeliveryOutcome::Accepted`] when every check passes; the
    /// callback then returns the signal, and the kernel delivers exactly that
    /// instance, with masks equal to the approved ones on every checked bit;
    /// the handler's mask holds as far as the tool's copy of the action is
    /// right.
    /// A check that fails answers
    /// [`crate::SignalDeliveryOutcome::Mismatch`] naming the field, and a
    /// point where it cannot check answers
    /// [`crate::SignalDeliveryOutcome::Unavailable`] naming why. Neither
    /// approves anything or changes the guest. A backend that builds the
    /// handler's frame itself answers
    /// [`crate::SignalDeliveryOutcome::Installed`] or
    /// [`crate::SignalDeliveryOutcome::FrameFault`], and its callback returns
    /// no signal. The default refuses
    /// ([`crate::UnsupportedOperation::SignalDelivery`]) and changes nothing.
    ///
    /// The contract, for every backend:
    /// - It never replaces, emulates or reorders a kernel mask-swapping
    ///   syscall (`rt_sigsuspend`, `ppoll`, `pselect6`, `epoll_pwait`).
    /// - It is offered only the signal instance the backend reported, from
    ///   the callback that reports it: at that signal's own stop or at its
    ///   held-signal report, or at a later signal-delivery stop an injection
    ///   of that callback ended at, from which the backend resumes the
    ///   recorded instance. A held signal whose temporary mask's restore is
    ///   pending is not reported, so it is never offered; the backend passes
    ///   it on unreported, and [`Tool::note_unreported_signal`] records it
    ///   with [`crate::UnreportedSignalReason::HeldRestorePending`] unless an
    ///   earlier reason applies (for example, the temporary mask blocks it:
    ///   [`crate::UnreportedSignalReason::HeldBlocked`]).
    /// - An approval is consumed at most once, by the resume of the callback
    ///   it was made in, and only from the stop it was checked at. It must be
    ///   the last thing the callback does before it returns the signal. An
    ///   injection or a register write after it voids it, and a tail
    ///   injection after it ends the run before it injects. A callback that
    ///   made an approval and then returns anything but that signal, returns
    ///   it after the approval was voided, or executes a program, fails
    ///   rather than deliver something unchecked: the backend ends the run.
    ///   [`Guest::set_signal_info`] changes neither registers nor masks and
    ///   composes with an approval; the signal is then delivered with the
    ///   replacement siginfo.
    /// - After a check fails, the callback cannot approve that signal again.
    async fn deliver_signal(
        &mut self,
        _delivery: crate::SignalDelivery,
    ) -> crate::SignalDeliveryOutcome {
        crate::SignalDeliveryOutcome::Refused(crate::UnsupportedRefusal::new(
            crate::UnsupportedOperation::SignalDelivery,
            Errno::ENOSYS,
            "Guest::deliver_signal: this backend keeps its own signal delivery (the default refusal)",
        ))
    }

    /// From inside [`Tool::handle_signal_event`] (or
    /// [`Tool::handle_raw_signal_event`]), how the backend reports the signal
    /// the callback is handling ([`crate::SignalReportPath`]): at its own
    /// stop, or held during a Tool's injection and reported after the
    /// callback that held it. `None` outside a signal callback, and from a
    /// backend that does not tell (the default).
    fn signal_report_path(&self) -> Option<crate::SignalReportPath> {
        None
    }

    /// Backend process/task lifetime identity, including at thread start.
    fn signal_task_identity(&self) -> Option<crate::SignalTaskIdentity> {
        None
    }

    /// The process signal control mode installed for this run: what
    /// [`GlobalTool::install_backend_signal_control`] returned when the
    /// backend offered its control. The answer is fixed before the first
    /// guest hook and is the same for every task of the run. A backend that
    /// offers no control answers `Unchanged`.
    fn signal_control_mode(&self) -> crate::BackendSignalControlMode {
        crate::BackendSignalControlMode::Unchanged
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

    /// Admission without guest-visible effects, before Tool metadata changes.
    ///
    /// Unenrolled requires a live exact task/process generation and grants no
    /// descriptor authority. Admitted additionally authenticates the current,
    /// unconsumed original callback and every raw operand. The result must not
    /// be cached: later or rewritten injection is checked independently. The
    /// backend may privately stage the authenticated current-image exec target
    /// for this callback. Repeated preflight reuses its first immutable snapshot;
    /// a new callback, cancellation, or consumption cannot reuse that authority.
    /// Unsupported backends fail closed; this is not a default-success opt-in.
    fn parent_death_syscall_preflight(
        &self,
        _call: crate::syscalls::Syscall,
    ) -> Result<crate::ParentDeathSyscallAdmission, crate::Error> {
        Err(crate::syscalls::Errno::ENOSYS.into())
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

    /// Sets the stopped thread's blocked-signal mask to `mask`, without
    /// running any guest code, and returns the mask it replaced. Bit `n - 1`
    /// stands for signal `n`.
    ///
    /// No instruction runs, so no pending signal is dequeued: every signal
    /// pending when this is called is still pending afterwards, and is
    /// delivered by the kernel, in its own order, once the guest runs with a
    /// mask that admits it. The caller owns putting the returned mask back
    /// before the guest resumes. That second call is refused under the same
    /// rules: for example with `RestorePending` after the caller injected a
    /// mask-swapping syscall that ended with its restore pending, or with
    /// `Unsupported` outside a syscall callback. So a caller that blocks
    /// must also handle a refused restore, typically by restoring another
    /// way or by ending the run before the guest resumes.
    ///
    /// The signals a backend needs for itself (on ptrace: SIGTRAP and the
    /// timer signal, besides SIGKILL and SIGSTOP, which cannot be blocked) are
    /// never added, and a guest's own block of them is kept: their bits in the
    /// new mask are those of the replaced one. Putting the returned mask back
    /// therefore restores exactly the mask that was there.
    ///
    /// Both refusals happen before anything is changed. A backend refuses
    /// ([`MaskChangeRefused::Unsupported`]) outside the stops where it can
    /// make the change atomically, and when the thread runs under a
    /// mask-swapping syscall's temporary mask whose restore is still pending
    /// ([`MaskChangeRefused::RestorePending`]): changing the mask then would
    /// discard that restore. The default refuses always and changes nothing.
    /// A failure after the write is reported as [`MaskChangeRefused::Failed`],
    /// which says whether the old mask could be put back, or as
    /// [`MaskChangeRefused::Gone`].
    async fn set_blocked_signals(&mut self, _mask: u64) -> Result<u64, MaskChangeRefused> {
        Err(MaskChangeRefused::Unsupported)
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

    /// Like [`Guest::inject_with_retry`], but for a call whose callback can be
    /// re-run: a backend may return `EINTR` or `ERESTARTSYS` from a syscall
    /// that ran, instead of retrying it, when it will deliver a signal as the
    /// guest resumes. The caller must return that code unchanged as the
    /// guest's syscall result. For `ERESTARTSYS`, Linux then restarts the
    /// guest's syscall or fails it with `EINTR`, by the handler's
    /// `SA_RESTART`; a returned `EINTR` stays `EINTR`. A restart runs
    /// the whole callback again, including every injection before this one,
    /// so those must be safe to repeat.
    ///
    /// A syscall that a signal stopped before it ran is retried, as by
    /// `inject_with_retry`. The default retries every interrupted call; the
    /// ptrace backend returns the code when a signal is held for delivery
    /// (<https://github.com/rrnewton/reverie/issues/998>).
    async fn inject_restartable<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        self.inject_with_retry(syscall).await
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

    /// Takes the backend's typed refusal of the most recent syscall that this
    /// handler injected, if the backend refused it as an operation it cannot
    /// perform.
    ///
    /// A refused injection returns the errno named in the refusal, which can
    /// also be an ordinary Linux failure of the same syscall. This query is how
    /// a tool tells the two apart without knowing which backend it runs on.
    ///
    /// Every injection through this guest replaces the record, whether or not
    /// it was refused, and taking it clears it, so a second call returns
    /// `None`. Call it before injecting anything else. Backends that perform
    /// every operation they accept always return `None`, which is the default.
    fn take_unsupported_refusal(&mut self) -> Option<crate::UnsupportedRefusal> {
        None
    }

    /// Returns half-open guest address ranges, `(start, end)`, that together
    /// contain every address at which a syscall could store its output into
    /// guest memory, as Linux's `put_user` does for `time(2)`'s `tloc`.
    ///
    /// A tool uses this to rule out a store it cannot observe: a word that
    /// does not lie wholly inside these ranges cannot have been stored by a
    /// syscall, because a syscall's store to any of its bytes faults. The
    /// ranges may also contain addresses at which such a store faults, so a
    /// word inside them proves nothing. They may be unsorted, overlapping or
    /// adjacent.
    ///
    /// The default lists every mapping in `/proc/<pid>/maps` for the process
    /// returned by [`Guest::pid`], whatever its protection. That is correct
    /// when `pid()` is the guest process. Backends whose `pid()` is not the
    /// guest (for example the KVM backend, where it is the host VMM process)
    /// override this with their own record of the guest's address space.
    fn storable_memory_ranges(&self) -> Result<Vec<(u64, u64)>, crate::Error> {
        let maps = {
            let _open = crate::process::launch_window::TransientOpen::begin();
            procfs::process::Process::new(self.pid().as_raw()).and_then(|process| process.maps())
        };
        match maps {
            Ok(maps) => Ok(maps.into_iter().map(|map| map.address).collect()),
            Err(procfs::ProcError::Io(err, _)) => Err(crate::Error::Io(err)),
            Err(err) => Err(crate::Error::Tool(anyhow::anyhow!(err))),
        }
    }

    /// Returns how the guest's kernel checks a range of guest memory before a
    /// syscall reads or writes it: the user address limit that Linux's
    /// `access_ok` enforces (a syscall accepts `[base, base + len)` exactly
    /// when `base + len` does not overflow and is at most
    /// [`max_end`](crate::UserAddressLimit::max_end)), and whether a lone I/O
    /// vector is shortened to `MAX_RW_COUNT` bytes before that check
    /// ([`caps_single_vector`](crate::UserAddressLimit::caps_single_vector)).
    /// On x86-64 Linux the limit is `TASK_SIZE_MAX`, which is
    /// [`X86_64_FOUR_LEVEL_USER_ADDRESS_LIMIT`](crate::X86_64_FOUR_LEVEL_USER_ADDRESS_LIMIT)
    /// under four-level paging.
    ///
    /// The limit says nothing about what is mapped: copying a range within it
    /// can still fault.
    ///
    /// The default asks the running kernel and caches the answer for the
    /// tool's process after the first successful measurement, which is
    /// correct when the guest runs as a host process: both facts belong to
    /// the kernel, so the tool's process and the guest's share them. Backends
    /// whose guest address space has its own bound (for example the KVM
    /// backend, whose guest page tables are four-level whatever the host's
    /// are) override this with the rule their own syscall emulation applies.
    fn user_address_limit(&self) -> Result<crate::UserAddressLimit, crate::Error> {
        crate::user_address::host_user_address_limit()
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

    fn try_send_rpc_sync(
        &self,
        message: <U::GlobalState as GlobalTool>::Request,
    ) -> Result<<U::GlobalState as GlobalTool>::Response, <U::GlobalState as GlobalTool>::Request>
    {
        self.inner.try_send_rpc_sync(message)
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

    fn controller_capture_fact(&self) -> Option<ControllerCaptureFact> {
        self.inner.controller_capture_fact()
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

    fn is_runtime_owned_fd(&self, fd: i32) -> bool {
        self.inner.is_runtime_owned_fd(fd)
    }

    fn runtime_private_memory_regions(&self) -> Option<RuntimePrivateMemory> {
        self.inner.runtime_private_memory_regions()
    }

    fn runtime_private_memory_is_current(&self, snapshot: &RuntimePrivateMemorySnapshot) -> bool {
        self.inner.runtime_private_memory_is_current(snapshot)
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

    unsafe fn tool_syscall(&self, number: Sysno, args: [usize; 6]) -> Result<usize, Errno> {
        // SAFETY: forwarding preserves the caller's syscall and safety obligations.
        unsafe { self.inner.tool_syscall(number, args) }
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

    async fn inject_restartable<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        self.inner.inject_restartable(syscall).await
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

    fn signal_info(&self) -> Option<[u8; crate::SIGNAL_INFO_SIZE]> {
        self.inner.signal_info()
    }
    fn set_signal_info(&mut self, info: [u8; crate::SIGNAL_INFO_SIZE]) -> Result<(), Errno> {
        self.inner.set_signal_info(info)
    }
    async fn deliver_signal(
        &mut self,
        delivery: crate::SignalDelivery,
    ) -> crate::SignalDeliveryOutcome {
        self.inner.deliver_signal(delivery).await
    }
    fn signal_report_path(&self) -> Option<crate::SignalReportPath> {
        self.inner.signal_report_path()
    }
    fn signal_task_identity(&self) -> Option<crate::SignalTaskIdentity> {
        self.inner.signal_task_identity()
    }
    fn signal_control_mode(&self) -> crate::BackendSignalControlMode {
        self.inner.signal_control_mode()
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
    fn parent_death_syscall_preflight(
        &self,
        call: crate::syscalls::Syscall,
    ) -> Result<crate::ParentDeathSyscallAdmission, crate::Error> {
        self.inner.parent_death_syscall_preflight(call)
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

    async fn set_blocked_signals(&mut self, mask: u64) -> Result<u64, MaskChangeRefused> {
        self.inner.set_blocked_signals(mask).await
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

    fn take_unsupported_refusal(&mut self) -> Option<crate::UnsupportedRefusal> {
        self.inner.take_unsupported_refusal()
    }

    fn storable_memory_ranges(&self) -> Result<Vec<(u64, u64)>, crate::Error> {
        self.inner.storable_memory_ranges()
    }

    fn user_address_limit(&self) -> Result<crate::UserAddressLimit, crate::Error> {
        self.inner.user_address_limit()
    }
}
