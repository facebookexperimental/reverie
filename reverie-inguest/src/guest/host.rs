/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The in-guest host for a Reverie Tool: it owns the Tool, its per-thread
//! state and its coordinator connection, runs each guest syscall and
//! instruction event through the Tool's handlers, follows forks, and
//! implements [`Guest`] for the Tool's callbacks. The backend that owns the
//! trap and hook paths implements [`HostRuntime`] for the services the host
//! calls back into.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Rdtsc;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool;
#[cfg(any(test, feature = "rcb-clock"))]
use reverie::ToolConfiguration;
use reverie::ToolProcess;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::LocalMemory;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

use super::context::RegisterContext;
use super::event::InstructionEventKind;
use super::event::SyscallDispatch;
use super::event::SyscallEvent;
use super::isa::InstructionResult;
use super::isa::Isa;
use super::isa::NativeIsa;
use super::native_rpc::NativeApplicationRpc;
use super::native_rpc::NativeRpc;
use super::native_services::NativeEntryObservation;
use super::native_services::NativeEntryStage;
use super::native_services::NativeServices;
use super::rpc::CoordinatorRpc;
use super::signal::core_dump_expected;
use super::signal::current_pending_set;
use super::signal::self_directed_fatal_signal;
use super::signal::signal_ends_process_now;
use super::support::tool_callback_active;
use crate::sync::SpinMutex;
use crate::tool_host::CallbackOutcome;
use crate::tool_host::DrivenSyscall;
use crate::tool_host::TailResult;
use crate::tool_host::drive_callback;
use crate::tool_host::drive_ready;
use crate::tool_host::drive_tool_process_syscall;
use crate::trap::raw_syscall6;

#[path = "host_linux.rs"]
mod host_linux;

#[path = "native_copied.rs"]
mod native_copied;
#[path = "native_entry.rs"]
mod native_entry;
#[path = "native_initialize.rs"]
mod native_initialize;
/// Exclusive state and scratch owners for live native callbacks.
#[path = "native_state.rs"]
pub mod native_state;
/// Lease (checkout/checkin) per-thread state for the ordinary dispatch path.
#[path = "thread_lease.rs"]
pub(crate) mod thread_lease;
pub use native_entry::NativeCallResult;
pub use native_entry::NativeInstruction;
pub use native_entry::NativeInstructionResult;
pub use native_entry::NativeSignalResult;
#[path = "native_exit.rs"]
mod native_exit;
pub use native_exit::NativeExitRpc;
#[cfg(test)]
#[path = "native_entry_tests.rs"]
mod native_entry_tests;

#[cfg(feature = "exec-private-init")]
#[path = "image_guest.rs"]
mod image_guest;
#[cfg(feature = "exec-private-init")]
#[path = "mapped_successor_image_guest.rs"]
mod mapped_successor_image_guest;
#[cfg(all(test, feature = "exec-native-injection"))]
#[path = "native_exec_tests.rs"]
mod native_exec_tests;
#[cfg(all(test, feature = "exec-native-injection"))]
#[path = "native_exec_witness_tests.rs"]
mod native_exec_witness_tests;
#[cfg(feature = "exec-private-successor")]
#[path = "successor_image_guest.rs"]
mod successor_image_guest;

/// The services a [`ToolHost`] needs from the backend that owns the trap and
/// hook paths.
pub trait HostRuntime: Send + Sync + 'static {
    /// In a forked child, before anything else: rebind per-process trap-path
    /// state (such as the fallback continuation) to the child.
    fn fork_child_rebind(&self);
    /// Reports a lifecycle stage on the backend's diagnostic stream, if any.
    fn emit_stage(&self, stage: &[u8]);
    /// Optional read-only diagnostics at the actual native callback boundary.
    /// The borrowed view cannot alter Tool state, registers, memory or admission.
    fn observe_native_entry(
        &self,
        _stage: NativeEntryStage,
        _observation: NativeEntryObservation<'_, '_>,
    ) {
    }
    /// In a forked child, after the Tool and thread state are replaced: reset
    /// the inherited observability and statistics, and account the child's
    /// first event (`event`) to the path that entered it.
    fn fork_child_reset(&self, event: &SyscallEvent);
    /// Whether CPUID is delivered to the Tool in this process.
    fn cpuid_interception_enabled(&self) -> bool;
    /// At process exit, after the Tool's exit callbacks: submit the process's
    /// statistics, if the backend collects them. An error ends the process
    /// with status 125.
    fn exit_process_stats(&self, tid: Pid) -> io::Result<()>;
    /// Reads the guest thread's retired-conditional-branch clock.
    fn read_clock(&self) -> io::Result<u64>;
    /// Whether a guest `rt_sigaction`-family call may be forwarded.
    fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool;
    /// The signals the runtime keeps for itself; stripped from any set the
    /// guest blocks.
    fn reserved_signal_mask(&self) -> u64;
    /// Whether an external exec watcher is armed for this process: a
    /// supervisor seized over the guest that catches the kernel exec
    /// event and re-bootstraps the successor image before its first
    /// instruction runs (the exec-stop supervisor's watched mode).
    ///
    /// When this returns `true`, `execve`/`execveat` are forwarded to
    /// the kernel instead of refused — dynamic and static images
    /// alike. The gate applies wherever it is queried, including in
    /// plain-fork children (runtime state is inherited; each child
    /// is its own thread-group leader under this runtime's
    /// single-thread model, and thread creation stays refused, so a
    /// non-leader exec cannot arise) — but a child's leader status
    /// does not establish its ptracer: arming asserts watcher
    /// coverage in every process where the gate can fire. The
    /// in-tree supervisor watches a single leader and does not
    /// follow forks yet, so until fork-following exists arming is
    /// sound only when the embedder watches each child itself or
    /// the guest cannot fork. A successful exec never returns here:
    /// this runtime image is replaced, and successor
    /// admission/reconnection is the coordinator's business. A
    /// failed exec returns the genuine kernel errno, untagged.
    ///
    /// Arming the watch asserts the watcher will in fact catch the
    /// exec and re-bootstrap the successor (or terminate it) before
    /// resuming it: the inherited trap filter survives exec but its
    /// handler does not, so a successor resumed without
    /// re-bootstrap is not viable. The default is unarmed, which
    /// keeps the historical fail-closed refusal.
    fn exec_watch_armed(&self) -> bool {
        false
    }

    /// Per-thread admission checklist step (W7): verify any backend
    /// per-thread arming for a just-created guest thread — alternate
    /// signal stack above all — before its first Tool callback runs.
    /// Called on the new thread itself, after its state lease exists and
    /// before `handle_thread_start`. An error is a host invariant break
    /// (the thread physically exists), so failure is fatal, never a
    /// guest errno. Default: nothing per-thread to arm.
    fn verify_thread_admission(&self, _tid: Pid) -> io::Result<()> {
        Ok(())
    }
}

/// Decide a guest signal call through the runtime's virtual SIGALRM state;
/// `Some` is its result and it must not be forwarded.
fn virtual_signal_call(
    runtime: &impl HostRuntime,
    guest_pkru: Option<u32>,
    original_args: [u64; 6],
    number: i64,
    args: [u64; 6],
) -> Option<i64> {
    let rights = super::sigalrm::GuestRights {
        pkru: guest_pkru,
        original_args,
    };
    if super::sigalrm::original_input_denied(rights, number, args) {
        return Some(-i64::from(libc::EFAULT));
    }
    let policy = super::sigalrm::Policy {
        reserved: runtime.reserved_signal_mask(),
        rights,
    };
    // SAFETY: called only while forwarding the guest's own call, in its turn.
    if let Some(result) = unsafe { super::sigalrm::intercept(&policy, number, args) } {
        return Some(result);
    }
    if !super::runtime_mask::delivers_signals() {
        return None;
    }
    // Under the signal-delivery gate the kernel's mask is the runtime's while
    // the call is handled: the calls on the blocked set act on the guest's
    // saved mask instead (`runtime_mask::saved_mask_call`).
    // SAFETY: as above, under the gate.
    match unsafe { super::runtime_mask::saved_mask_call(rights, policy.reserved, number, args) } {
        None => None,
        Some(Ok(result)) => Some(result),
        Some(Err(reason)) => tool_fatal(125, &Error::Tool(io::Error::other(reason).into())),
    }
}

/// Under the signal-delivery gate, ends the process by name before a raw
/// forward of `number(args)` that would install a signal mask of its own in
/// the kernel ([`super::runtime_mask::installs_signal_mask`]): the kernel
/// could then deliver a guest signal while the runtime runs. A Tool decides
/// such calls itself under the gate, so reaching here is a defect. Before a
/// forwarded `rt_sigtimedwait`, the ignored instances Linux discarded at send
/// are taken from the queue ([`super::runtime_mask::prepare_forward`]).
/// `rights` are those the forward runs under: the guest's saved PKRU for the
/// guest's own call ([`ForwardRights::Guest`]), and the calling thread's
/// current rights for a Tool's injection ([`ForwardRights::Runtime`]), so
/// that a Tool's private buffer is read as the kernel will read it. With the
/// gate off it checks nothing.
fn refuse_mask_installing_forward(
    runtime: &impl HostRuntime,
    rights: ForwardRights,
    number: i64,
    args: [u64; 6],
) {
    if !super::runtime_mask::delivers_signals() {
        return;
    }
    let rights = match rights {
        ForwardRights::Guest(pkru) => super::sigalrm::GuestRights {
            pkru,
            original_args: args,
        },
        ForwardRights::Runtime => super::sigalrm::GuestRights::default(),
    };
    match super::runtime_mask::prepare_forward(rights, runtime.reserved_signal_mask(), number, args)
    {
        Ok(false) => {}
        Ok(true) => tool_fatal(
            125,
            &Error::Tool(
                io::Error::other(format!(
                    "a raw forward of syscall {number}, which would install a signal mask in \
                     the kernel while the runtime runs, under in-guest signal delivery is refused"
                ))
                .into(),
            ),
        ),
        Err(reason) => tool_fatal(125, &Error::Tool(io::Error::other(reason).into())),
    }
}

/// The protection-key rights a raw forward runs under
/// ([`refuse_mask_installing_forward`]).
#[derive(Clone, Copy)]
enum ForwardRights {
    /// The guest's own call, forwarded with its saved PKRU.
    Guest(Option<u32>),
    /// A Tool's injection, forwarded with the calling thread's current
    /// rights.
    Runtime,
}

/// Retain allocation's native permission effect in this event's return image.
/// Existing admission guards must run first. Scalar allocation operands need
/// no private-buffer permission policy; other injections keep caller rights.
fn perform_pkey_alloc(event: &mut SyscallEvent, number: i64, args: [u64; 6]) -> Option<i64> {
    if number != libc::SYS_pkey_alloc {
        return None;
    }
    if !crate::trap::pkru_present() {
        // Installation established that PKRU instructions are unavailable.
        // Keep Linux's allocation answer through the ordinary scalar gate.
        return Some(unsafe { crate::trap::physical_guest_syscall6(number, args, None) }.result);
    }
    let Some(guest_pkru) = event.guest_pkru else {
        // A hook or instruction placeholder has no owned permission image.
        // Refuse before allocating a key whose rights cannot be retained.
        return Some(-i64::from(libc::EOPNOTSUPP));
    };
    // SAFETY: installation established OSPKE, and this live event owns the
    // guest's saved PKRU. Allocation has scalar operands and preserves the
    // helper's storage; the gate restores callback rights before Rust resumes.
    let result = unsafe { crate::trap::physical_guest_syscall6(number, args, Some(guest_pkru)) };
    // Retain the actual effect before scalar errno or Tool result handling.
    event.guest_pkru = result.pkru;
    Some(result.result)
}

const STACK_CAPACITY: usize = 4096;

/// The type of [`COMMITTED_STACKS`]. It must not need dropping: see there.
type CommittedStacks = core::mem::ManuallyDrop<core::cell::RefCell<Vec<Box<[u8]>>>>;

thread_local! {
    /// Arenas committed by this thread's in-flight dispatch. Per-thread:
    /// a sibling dispatch's scope entry/exit must never free arenas this
    /// thread committed and may still reference through stack guards.
    ///
    /// Destructor-free on purpose. A thread-local whose type needs
    /// dropping makes std register a thread-exit destructor on first
    /// access, through libc's `__cxa_thread_atexit_impl`, which allocates
    /// its record from the C library heap. The first access is
    /// [`ToolHost::from_parts`], which for an in-guest runtime runs while
    /// the preload's constructor installs the Tool, before the guest's
    /// `main`: the guest's heap then started with libc's per-thread cache
    /// and that record in it. Every dispatch touches the slot as well. No
    /// destructor is needed, because [`DispatchScratchScope`] empties the
    /// vector and releases its buffer whenever a dispatch ends, so a
    /// thread exits holding nothing; only a thread that exits inside a
    /// dispatch leaks what that dispatch retained, the vector's buffer
    /// included, which freeing could not have made sound anyway.
    ///
    /// Without a destructor the slot is never destroyed, so the syscalls a
    /// thread makes after libc ran its TLS destructors (the `exit_group`
    /// after `exit()`, the thread-exit syscall after pthread teardown)
    /// still reach it. Access stays on `try_with` regardless: `.with()`
    /// panicking inside the nounwind trap handler would abort the guest.
    static COMMITTED_STACKS: CommittedStacks =
        const { core::mem::ManuallyDrop::new(core::cell::RefCell::new(Vec::new())) };
}

fn retain_committed_stack(arena: Box<[u8]>) {
    let mut arena = Some(arena);
    let retained = COMMITTED_STACKS.try_with(|stacks| {
        stacks
            .borrow_mut()
            .push(arena.take().expect("arena retained once"));
    });
    if retained.is_err() {
        // Unreachable while the slot has no destructor. Leaking is the
        // only sound answer if it ever is: freeing here could release
        // memory a stack guard of this dispatch still references.
        std::mem::forget(arena.take().expect("arena retained once"));
    }
}

struct DispatchScratchScope {
    _allocation_scope: super::alloc::DispatchAllocationScope,
}

impl DispatchScratchScope {
    fn enter() -> Self {
        let _ = COMMITTED_STACKS.try_with(|stacks| stacks.borrow_mut().clear());
        Self {
            _allocation_scope: super::alloc::enter_dispatch(),
        }
    }
}

impl Drop for DispatchScratchScope {
    fn drop(&mut self) {
        // A forked child inherits this thread's vector; releasing it here
        // only ever touches the calling thread's own committed arenas.
        // Its buffer goes too, not only its arenas: the slot has no
        // destructor, so nothing else would free it when the thread exits.
        let _ = COMMITTED_STACKS.try_with(|stacks| {
            let released = core::mem::take(&mut *stacks.borrow_mut());
            drop(released);
        });
    }
}

thread_local! {
    /// This thread's own live `ActiveDispatch` guards. The fork-child
    /// reinit resets the process-wide counter to exactly this: the
    /// surviving thread's guards are the only ones that will drop in
    /// the child, so the counter stays balanced across the fork.
    /// Const no-drop TLS: readable even in exit teardown.
    static LOCAL_DISPATCHES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// One in-flight dispatch, counted so install/initial-image flows can
/// prove no Tool callback is active without relying on lock failure.
struct ActiveDispatch<'a, T: Tool, R: HostRuntime> {
    host: &'a ToolHost<T, R>,
}

impl<T: Tool, R: HostRuntime> Drop for ActiveDispatch<'_, T, R> {
    fn drop(&mut self) {
        LOCAL_DISPATCHES.set(LOCAL_DISPATCHES.get() - 1);
        self.host
            .active_dispatches
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    }
}

/// Hosts one Reverie Tool inside the guest process: owns the Tool, its
/// per-thread state and its coordinator connection, and runs each guest
/// syscall or instruction event through the Tool's handlers. The backend that
/// owns the trap and hook paths supplies `R`, the runtime services the host
/// calls back into.
pub struct ToolHost<T: Tool, R: HostRuntime> {
    tool: SpinMutex<Option<Arc<ToolProcess<T>>>>,
    rpc: CoordinatorRpc<T::GlobalState>,
    root_pid: Pid,
    subscriptions: HashSet<Sysno>,
    cpuid_interception: bool,
    /// Per-thread Tool state, leased per dispatch (see
    /// [`thread_lease::ThreadStates`]). No lock into this registry is held
    /// across Tool code, RPC, or any blocking call.
    states: thread_lease::ThreadStates<T::ThreadState>,
    /// Dispatches currently inside a Tool callback on any thread, and the
    /// gate that makes incrementing it atomic against install flows'
    /// quiescence checks: `begin_dispatch` takes the gate briefly to
    /// increment, install flows hold it across their check-and-install
    /// section, so "counter was zero" cannot race a dispatch starting.
    active_dispatches: core::sync::atomic::AtomicUsize,
    install_gate: SpinMutex<()>,
    /// W7 thread-admission capability: when false (default), guest thread
    /// creation refuses exactly as before W7; when true, admitted
    /// CLONE_THREAD shapes are performed through the birth trampoline.
    admit_threads: bool,
    /// Runtime birth stacks by admitted thread tid (base, len), freed by
    /// `finish_tool_exit` when that thread retires. Registered by the
    /// child itself during admission (its tid is unknown parent-side
    /// until the clone returns, and the record must exist before the
    /// child can be signalled as a thread).
    birth_stacks: SpinMutex<HashMap<i32, (usize, usize)>>,
    native_threads: Option<native_state::NativeThreads<T::ThreadState>>,
    // Prepared only by the ordinary installer, before publication. Keeping it
    // outside `states` preserves the real first-event lifecycle callbacks.
    ordinary_root_state: SpinMutex<Option<T::ThreadState>>,
    #[cfg(feature = "exec-private-init")]
    mapped_successor_state: SpinMutex<Option<MappedSuccessorState<T>>>,
    /// Whether `mapped_successor_state` currently holds a state, mirrored
    /// under its lock so ordinary dispatch can refuse without contending
    /// for the slot lock.
    #[cfg(feature = "exec-private-init")]
    mapped_successor_pending: core::sync::atomic::AtomicBool,
    runtime: R,
    #[cfg(feature = "exec-private-successor")]
    prepared_exec: SpinMutex<Option<PreparedExecState<T>>>,
    /// Whether `prepared_exec` currently holds a state, mirrored under
    /// its lock so the ordinary dispatch entries can check it without
    /// contending for the lock: concurrent dispatches both probe it,
    /// and the loser of a lock race must not be read as a pending
    /// successor. Writers store while holding the lock.
    #[cfg(feature = "exec-private-successor")]
    prepared_exec_pending: core::sync::atomic::AtomicBool,
    #[cfg(feature = "exec-native-injection")]
    native_exec_driver: Option<std::sync::Arc<dyn super::native_exec::NativeExecDriver<T>>>,
    // Embedder opt-in, separate from driver installation: the admitted
    // native exec/clone route is consulted only when the authenticated
    // installer explicitly admitted it via `admit_native_exec`.
    #[cfg(feature = "exec-native-injection")]
    native_exec_admitted: bool,
}

#[cfg(feature = "exec-private-init")]
enum MappedSuccessorPhase {
    Pending,
    Failed,
    Complete,
}
#[cfg(feature = "exec-private-init")]
struct MappedSuccessorState<T: Tool> {
    state: T::ThreadState,
    phase: MappedSuccessorPhase,
}

#[cfg(feature = "exec-private-successor")]
enum PreparedExecPhase {
    Pending,
    Failed,
    Complete,
}
#[cfg(feature = "exec-private-successor")]
struct PreparedExecState<T: Tool> {
    state: T::ThreadState,
    binding: super::exec_private::SuccessorBinding,
    phase: PreparedExecPhase,
}

impl<T: Tool, R: HostRuntime> ToolHost<T, R> {
    /// This process's coordinator connection.
    pub fn rpc(&self) -> &CoordinatorRpc<T::GlobalState> {
        &self.rpc
    }

    /// Marks one dispatch active until the returned guard drops. The
    /// increment happens under `install_gate` so an install flow holding
    /// the gate and observing zero cannot race a dispatch starting.
    fn begin_dispatch(&self) -> ActiveDispatch<'_, T, R> {
        let _gate = self.install_gate.lock();
        self.active_dispatches
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        LOCAL_DISPATCHES.set(LOCAL_DISPATCHES.get() + 1);
        ActiveDispatch { host: self }
    }

    /// Begin an install/initial-image section that requires quiescence:
    /// succeeds only when no dispatch is active, and the returned guard
    /// keeps new dispatches from starting (they spin briefly in
    /// `begin_dispatch`) until the section ends. This replaces the old
    /// proof by failed `try_lock` on locks dispatch used to hold across
    /// callbacks; unlike a bare counter read it has no check-then-act
    /// window.
    fn begin_install(&self) -> Option<crate::sync::SpinGuard<'_, ()>> {
        let gate = self.install_gate.lock();
        if self.dispatch_active() {
            return None;
        }
        Some(gate)
    }

    fn dispatch_active(&self) -> bool {
        self.active_dispatches
            .load(core::sync::atomic::Ordering::Acquire)
            != 0
    }

    /// Reinitialize this host's synchronization state in a fork child
    /// whose copies of the spinlocks may have been made mid-hold by
    /// sibling threads that do not exist here (fork quiescence), and
    /// reset the dispatch counter to this surviving thread's own live
    /// guards. Runs at the top of `finish_fork_child`, where the child
    /// is still single-threaded and this thread holds none of these
    /// locks (its live guards are the dispatch counter's, which is
    /// exactly what is preserved).
    ///
    /// Per-lock disposition (the force-unlock contract needs a
    /// data-consistency argument per lock, not just dead holders):
    /// - `install_gate` guards nothing (the counter is a separate
    ///   atomic), `tool` and `ordinary_root_state` and `prepared_exec`
    ///   each guard one `Option` word plus a value only ever moved
    ///   wholesale under install-time exclusion, and the RPC
    ///   `fork_reset` guards one pid word: force-release is sound.
    /// - The three hash-map registries (`states` slots, RPC `by_tid`,
    ///   `birth_stacks`) may have been copied mid-rehash: their locks
    ///   are force-released only so the maps can be *leak-replaced*
    ///   (`ThreadStates::reset_to`, the RPC fork reset, and below)
    ///   without ever traversing or dropping the copied contents.
    /// - The Tool-heap locks are not here at all: the forwarding path
    ///   holds them across the physical fork
    ///   (`alloc::quiesce_for_fork`), so the child inherits a
    ///   consistent free list; per-connection locks are likewise
    ///   never touched (see `CoordinatorRpc::reinit_after_fork`).
    fn reinit_after_fork(&self) {
        // SAFETY: the force-unlock contract holds here — the only
        // surviving thread is the forking one, it holds none of these
        // locks at this point, and no other thread exists yet in the
        // child to hold or later drop a guard.
        unsafe {
            self.install_gate.force_unlock();
            self.tool.force_unlock();
            self.birth_stacks.force_unlock();
            self.ordinary_root_state.force_unlock();
            #[cfg(feature = "exec-private-successor")]
            self.prepared_exec.force_unlock();
            self.states.force_unlock_slots();
            self.rpc.reinit_after_fork();
        }
        // Leak-replace the birth-stack registry: the copied map is
        // forgotten without traversal (a sibling's admission insert
        // or retire remove may have been copied mid-operation). The
        // dead threads' birth stacks leak as unused mappings in this
        // child only — munmapping them would require reading the
        // copied entries — and this thread's own birth stack, if any,
        // likewise stays mapped until process exit instead of being
        // released at retire.
        // Reuse the copied map's hasher: building a fresh
        // RandomState on a thread that has never made one issues
        // getrandom through libc, outside the trusted gate, in
        // this post-fork context. The hasher is fixed at map
        // construction, so cloning it reads no bucket state.
        let copied = {
            let mut stacks = self.birth_stacks.lock();
            let hasher = stacks.hasher().clone();
            core::mem::replace(&mut *stacks, HashMap::with_hasher(hasher))
        };
        core::mem::forget(copied);
        self.active_dispatches.store(
            LOCAL_DISPATCHES.get(),
            core::sync::atomic::Ordering::Release,
        );
    }

    /// Install an already-admitted continuation's Tool state for this thread.
    ///
    /// The owner must restore every field of its `ThreadState`, including its
    /// logical time, before the first dispatch. The saved state must already
    /// have completed the Tool's thread-start and post-exec callbacks; restoring
    /// it does not repeat those callbacks. A thread with existing state, or a
    /// dispatch currently holding the state lock, is refused without replacing
    /// anything. No production backend calls this inactive input seam.
    pub fn restore_current_thread_state(&self, state: T::ThreadState) -> io::Result<()> {
        #[cfg(feature = "exec-private-init")]
        if self
            .mapped_successor_pending
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(io::Error::other(
                "mapped successor lifecycle state is not complete",
            ));
        }
        // Read the occupancy mirror, not the lock: momentary
        // contention (a writer updating the slot) must not read as a
        // pending successor and spuriously refuse a legitimate
        // restore (same misread the dh-n6qjq dispatch probes had).
        #[cfg(feature = "exec-private-successor")]
        if self
            .prepared_exec_pending
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return Err(io::Error::other(
                "successor lifecycle state is not complete",
            ));
        }
        let _allocation_scope = super::alloc::enter_dispatch();
        let tid = raw_pid(libc::SYS_gettid).as_raw();
        let Some(_install) = self.begin_install() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Tool state dispatch is active",
            ));
        };
        self.states.try_publish(tid, state).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Tool state already exists for this thread",
            )
        })
    }
}

impl<T, R> ToolHost<T, R>
where
    T: Tool + 'static,
    R: HostRuntime,
{
    /// Creates the host for the root process's Tool. `subscriptions` are the
    /// Tool's syscall subscriptions; `cpuid_interception` says whether CPUID
    /// is delivered to the Tool.
    pub fn new(
        tool: T,
        rpc: CoordinatorRpc<T::GlobalState>,
        root_pid: Pid,
        subscriptions: HashSet<Sysno>,
        cpuid_interception: bool,
        runtime: R,
    ) -> Self {
        Self::from_parts(
            ToolProcess::adopt_legacy(tool),
            rpc,
            root_pid,
            subscriptions,
            cpuid_interception,
            runtime,
        )
    }

    /// Construct a host whose callback state is owned by a native runtime.
    ///
    /// This selects storage/lifetimes only. The native owner must separately
    /// provide the actual callback services before invoking a Tool. It cannot
    /// use the local `dispatch`/`dispatch_instruction` path.
    ///
    /// # Safety
    /// The caller owns the live native image, thread admission, allocator/TLS,
    /// service table and lifecycle. No local dispatch may run in this process
    /// concurrently. The coordinator configuration must be authentic. A
    /// native initializer may use CoordinatorRpc::from_native_configuration
    /// after closing its temporary config connection; callbacks use their
    /// separately owned native RPC route, never an ordinary fallback. This
    /// constructor grants no private-image authority.
    pub unsafe fn new_native(
        tool: T,
        rpc: CoordinatorRpc<T::GlobalState>,
        root_pid: Pid,
        subscriptions: HashSet<Sysno>,
        cpuid_interception: bool,
        runtime: R,
    ) -> Self {
        let mut host = Self::from_parts(
            ToolProcess::adopt_legacy(tool),
            rpc,
            root_pid,
            subscriptions,
            cpuid_interception,
            runtime,
        );
        host.native_threads = Some(native_state::NativeThreads::new());
        host
    }

    /// Retain the original state created at the actual native lifecycle
    /// boundary; no default state or synthetic lifecycle event is substituted.
    ///
    /// # Safety
    /// `identity` and `state` must belong to this Tool's admitted native task
    /// and image, including its real parent snapshot where applicable. The
    /// owner must have entered its actual allocation/callback context.
    pub unsafe fn register_native_thread(
        &self,
        identity: native_state::NativeThreadIdentity,
        state: T::ThreadState,
    ) -> io::Result<native_state::NativeThreadHandle> {
        self.native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?
            .register(identity, state)
    }

    /// Register state for an actual newly admitted image. This retains the
    /// same real thread-start then post-exec ordering; ordinary created child
    /// tasks use register_native_thread and do not acquire a post-exec event.
    ///
    /// # Safety
    /// The native image owner must have completed its real image/config/state
    /// admission. Serialized flags or a child-registration request cannot
    /// authorize this entry or restore initial/successor authority.
    pub unsafe fn register_native_image_thread(
        &self,
        identity: native_state::NativeThreadIdentity,
        state: T::ThreadState,
    ) -> io::Result<native_state::NativeThreadHandle> {
        self.native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?
            .register_image(identity, state)
    }

    /// Pin this one Tool and take this thread's exclusive state. All process
    /// owner guards are released before the returned value reaches callbacks.
    ///
    /// # Safety
    /// The caller must validate current native service/task/image facts and
    /// borrow the live callback context. The returned lease stays on this
    /// thread and cannot outlive its actual native callback/continuation.
    pub unsafe fn enter_native_callback(
        &self,
        handle: native_state::NativeThreadHandle,
        identity: native_state::NativeThreadIdentity,
    ) -> io::Result<native_state::NativeCallbackLease<'_, T>> {
        let owner = self
            .native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        let tool = self
            .tool
            .lock_unless_reentered()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EDEADLK))?
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        native_state::NativeCallbackLease::new(tool, owner, handle, identity)
    }

    /// Take the original state once, after actual native callback use ended,
    /// so the owner can invoke the existing Tool thread-exit lifecycle.
    ///
    /// # Safety
    /// The native task is genuinely retiring and its callbacks/continuations
    /// are quiescent. This is not a request to create or resume a task.
    pub unsafe fn retire_native_thread(
        &self,
        handle: native_state::NativeThreadHandle,
        identity: native_state::NativeThreadIdentity,
    ) -> io::Result<T::ThreadState> {
        self.native_threads
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?
            .retire(handle, identity)
    }

    /// Retain the standard installer's selected configuration for later forks.
    /// The Tool has already been constructed after that installer's preflight.
    #[cfg(any(test, feature = "rcb-clock"))]
    pub(crate) fn with_configuration(
        tool: T,
        rpc: CoordinatorRpc<T::GlobalState>,
        root_pid: Pid,
        configuration: ToolConfiguration<T>,
        subscriptions: HashSet<Sysno>,
        runtime: R,
    ) -> Self {
        let cpuid_interception = configuration.subscriptions().has_cpuid();
        Self::from_parts(
            ToolProcess::adopt_selected(tool, configuration),
            rpc,
            root_pid,
            subscriptions,
            cpuid_interception,
            runtime,
        )
    }

    fn from_parts(
        tool: ToolProcess<T>,
        rpc: CoordinatorRpc<T::GlobalState>,
        root_pid: Pid,
        subscriptions: HashSet<Sysno>,
        cpuid_interception: bool,
        runtime: R,
    ) -> Self {
        let _ = COMMITTED_STACKS.try_with(|stacks| stacks.borrow_mut().clear());
        Self {
            tool: SpinMutex::new(Some(Arc::new(tool))),
            rpc,
            root_pid,
            subscriptions,
            cpuid_interception,
            states: thread_lease::ThreadStates::new(),
            active_dispatches: core::sync::atomic::AtomicUsize::new(0),
            install_gate: SpinMutex::new(()),
            admit_threads: false,
            birth_stacks: SpinMutex::new(HashMap::new()),
            native_threads: None,
            ordinary_root_state: SpinMutex::new(None),
            #[cfg(feature = "exec-private-init")]
            mapped_successor_state: SpinMutex::new(None),
            #[cfg(feature = "exec-private-init")]
            mapped_successor_pending: core::sync::atomic::AtomicBool::new(false),
            runtime,
            #[cfg(feature = "exec-private-successor")]
            prepared_exec: SpinMutex::new(None),
            #[cfg(feature = "exec-private-successor")]
            prepared_exec_pending: core::sync::atomic::AtomicBool::new(false),
            #[cfg(feature = "exec-native-injection")]
            native_exec_driver: None,
            #[cfg(feature = "exec-native-injection")]
            native_exec_admitted: false,
        }
    }

    /// Prepare an ordinary root before this newly constructed host is published.
    /// The initializer has config/state only, no RPC or lifecycle authority.
    /// Errors return to installation; they cannot become a fresh default state.
    /// Present where its installer (`tool_install`) is, and for its tests.
    #[cfg(any(test, all(feature = "coordinator-rpc", feature = "rcb-clock")))]
    pub(crate) fn prepare_ordinary_root_state<F>(&mut self, initialize: F) -> io::Result<()>
    where
        F: FnOnce(
            &<T::GlobalState as GlobalTool>::Config,
            Pid,
            &mut T::ThreadState,
        ) -> io::Result<()>,
    {
        if !self.states.is_empty() || self.ordinary_root_state.lock().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "ordinary root preparation follows state creation",
            ));
        }
        let tool_arc = self
            .tool_process()
            .ok_or_else(|| io::Error::other("ordinary root Tool is absent"))?;
        let tool: &ToolProcess<T> = &tool_arc;
        let mut state = tool.init_thread_state(self.root_pid, None);
        initialize(self.rpc.config(), self.root_pid, &mut state)?;
        *self.ordinary_root_state.lock() = Some(state);
        Ok(())
    }

    /// The installed Tool, cloned out from its slot. The slot lock is
    /// held only for this clone (and for install/take), never across a
    /// Tool callback: callbacks on different guest threads proceed
    /// concurrently against the shared `Arc`.
    fn tool_process(&self) -> Option<Arc<ToolProcess<T>>> {
        self.tool.lock().clone()
    }

    /// Enable or disable guest thread admission (W7). Default off:
    /// CLONE_THREAD creations refuse exactly as before. Set before the
    /// host dispatches; toggling mid-run is not synchronized against
    /// in-flight creations.
    ///
    /// Admission is a test-only capability for now. Known gaps that
    /// block enabling it outside tests are tracked for the enabling
    /// slice as minibeads dh-2414s
    /// (<https://github.com/rrnewton/dev-hermit-beads/blob/main/issues/dh-2414s.md>);
    /// each was measured or traced at the W7 respin reviews:
    /// - Multi-threaded exit lifecycle: process exit unwraps the
    ///   Tool slot's `Arc` (`finish_tool_exit`), which fatals (126)
    ///   while any sibling dispatch holds a clone; a leader's plain
    ///   `SYS_exit` is also treated as process exit.
    /// - The signal gate's `event_identity` handling can attribute a
    ///   sibling's signal event to the wrong thread, and the signal
    ///   runtime still assumes one thread per process: the cached
    ///   identity in `runtime_mask` and the per-process virtual mask
    ///   in `sigalrm` are process-wide, not per-thread.
    /// - The liteinst site table (`INSTALL_HELD`/`SITE_INSTALLING`
    ///   in the liteinst runtime) is process-wide state no fork or
    ///   thread path reinitializes.
    /// - Reported creations across sibling threads share the one
    ///   runtime pidfd output word (see `creation_storage`).
    /// - `CoordinatorRpc::relocate` against a sibling connection
    ///   that is mid-exchange answers EBUSY (by contract), which a
    ///   guest `dup2` onto that number surfaces as a refusal Linux
    ///   would not produce.
    /// - `ThreadBirth` without `CLONE_SETTLS` runs the whole
    ///   admission on the parent's TLS (the trampoline never
    ///   changes FS): the parent's `LOCAL_DISPATCHES`,
    ///   `DISPATCH_DEPTH`, `TOOL_CALLBACK_ACTIVE`, `IN_HANDLER`
    ///   and `COMMITTED_STACKS` cells are written by two threads
    ///   at once (the last is a non-atomic `RefCell`). Refusing
    ///   no-SETTLS births by name, or giving admission
    ///   runtime-owned TLS, is enabling-slice work.
    /// - A birth whose thread-start callback ends the thread
    ///   leaks its 64 KiB birth-stack mapping (and its birth
    ///   record) until process exit or exec — measured at about
    ///   +64 KiB virtual and +20 KiB RSS per ended birth — because
    ///   the ending thread is still running on that stack when
    ///   every release path runs.
    /// - Tool-internal locks (inside the Tool, its process object
    ///   and thread states) copied while held at a fork are not
    ///   reinitialized; the fork child runs `new_process`,
    ///   `init_thread_state` and `handle_thread_start` against the
    ///   copied Tool before any contract covers them.
    /// - The close-then-`F_GETFD` survivor check (inherited-fd
    ///   close, runtime-fd placement, the clock counter move)
    ///   fires falsely when a sibling reuses the descriptor number
    ///   first: the guest's new descriptor is then recorded as
    ///   runtime-owned, and eight such misfires fill the recorded
    ///   set and end the process (pre-existing, measured at the
    ///   respin head).
    pub fn set_thread_admission(&mut self, enabled: bool) {
        self.admit_threads = enabled;
    }

    /// The physical thread-birth entry for guests built by this host, or
    /// `None` while thread admission is off.
    fn thread_birth_ops(&self) -> Option<ThreadBirthOps>
    where
        T: 'static,
    {
        self.admit_threads.then_some(ThreadBirthOps {
            host: core::ptr::from_ref(self) as usize,
            forward: forward_thread_creation::<T, R>,
        })
    }

    fn new_thread_state(&self, tool: &ToolProcess<T>, tid: Pid) -> T::ThreadState {
        if tid == self.root_pid
            && let Some(state) = self.ordinary_root_state.lock().take()
        {
            return state;
        }
        tool.init_thread_state(tid, None)
    }

    /// Install the inactive native exec driver exactly once, before dispatch.
    ///
    /// # Safety
    /// Only the authenticated experimental installer may call this. It must
    /// own the actual native main-thread/birth/immutable launch authority and
    /// vouch for every unsafe driver/session/provision contract. No guest
    /// Config, environment or request is installation authority. The driver
    /// must not reacquire this host's Tool/state locks during its callbacks.
    #[cfg(feature = "exec-native-injection")]
    pub unsafe fn install_native_exec_driver(
        &mut self,
        driver: std::sync::Arc<dyn super::native_exec::NativeExecDriver<T>>,
    ) -> io::Result<()> {
        if self.native_exec_driver.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native exec driver already installed",
            ));
        }
        // Field-level gate: holding the returned guard would borrow all
        // of `self` and block the driver assignment below.
        let _install = self.install_gate.lock();
        if self.dispatch_active() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Tool state dispatch is active",
            ));
        }
        if !self.states.is_empty() {
            return Err(io::Error::other(
                "native exec driver installation follows dispatch",
            ));
        }
        self.native_exec_driver = Some(driver);
        Ok(())
    }

    /// Admit the native exec/clone route for this host: the embedder
    /// opt-in, distinct from installing a driver. Until admitted, an
    /// installed driver is never consulted for exec or clone; both
    /// keep their typed refusals unless an exec watch is armed, in
    /// which case exec forwards to the kernel and clone still keeps
    /// its typed refusal. Admission is single-shot and must
    /// precede dispatch, under the same guards as driver installation.
    ///
    /// # Safety
    /// Only the authenticated experimental installer that installed the
    /// driver may call this, under every contract of
    /// `install_native_exec_driver`. No guest Config, environment or
    /// request is admission authority.
    #[cfg(feature = "exec-native-injection")]
    pub unsafe fn admit_native_exec(&mut self) -> io::Result<()> {
        if self.native_exec_driver.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "native exec admission requires an installed driver",
            ));
        }
        if self.native_exec_admitted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "native exec route already admitted",
            ));
        }
        // Field-level gate, mirroring install_native_exec_driver: holding
        // the returned guard would borrow all of `self` and block the
        // admission assignment below.
        let _install = self.install_gate.lock();
        if self.dispatch_active() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Tool state dispatch is active",
            ));
        }
        if !self.states.is_empty() {
            return Err(io::Error::other("native exec admission follows dispatch"));
        }
        self.native_exec_admitted = true;
        Ok(())
    }

    /// Whether the admitted native exec/clone route may be consulted:
    /// feature compiled, driver installed, and embedder admitted.
    #[cfg(feature = "exec-native-injection")]
    fn native_exec_admitted(&self) -> bool {
        self.native_exec_admitted && self.native_exec_driver.is_some()
    }

    /// Bind the actual stable installed successor host before its frontend.
    ///
    /// # Safety
    /// The backend must supply its published stable handler, the same admitted
    /// RPC/Tool/control and exact restored successor binding. The host must not
    /// move or be replaced. Guest memory effects must preserve Rust invariants.
    #[cfg(feature = "exec-private-successor")]
    pub unsafe fn bind_successor_image_control(
        &self,
        control: &super::exec_private::SuccessorImageControl,
    ) -> io::Result<()> {
        control.bind_lifecycle_host(core::ptr::from_ref(self) as usize)
    }

    /// Attach the exact authenticated prepared state as ExecPending. This
    /// neither creates thread state nor calls startup/post-exec callbacks.
    ///
    /// # Safety
    /// The same installer must have decoded/validated this state from the
    /// admitted successor snapshot with all runtime/Config/cut checks. A
    /// matching digest alone does not prove correct Tool-state restoration.
    #[cfg(feature = "exec-private-successor")]
    pub unsafe fn restore_prepared_exec_state(
        &self,
        state: T::ThreadState,
        control: &super::exec_private::SuccessorImageControl,
    ) -> io::Result<()> {
        control.begin_restore(core::ptr::from_ref(self) as usize)?;
        let result = (|| {
            let _allocation_scope = super::alloc::enter_dispatch();
            if self.root_pid != raw_pid(libc::SYS_gettid)
                || self.root_pid != raw_pid(libc::SYS_getpid)
            {
                return Err(io::Error::other("successor host root identity differs"));
            }
            let Some(_install) = self.begin_install() else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "successor state dispatch is active",
                ));
            };
            let mut pending = self.prepared_exec.try_lock().ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "successor restoration is active")
            })?;
            if !self.states.is_empty() || pending.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "successor thread state already exists",
                ));
            }
            *pending = Some(PreparedExecState {
                state,
                binding: control.binding(),
                phase: PreparedExecPhase::Pending,
            });
            self.prepared_exec_pending
                .store(true, core::sync::atomic::Ordering::Release);
            control.restore_completed();
            Ok(())
        })();
        if result.is_err() {
            control.restore_failed();
        }
        result
    }

    /// Run exactly the real post-exec on the restored Tool/state before loader
    /// entry. There is no thread_start, init_thread_state or syscall callback.
    #[cfg(feature = "exec-private-successor")]
    pub fn run_post_exec_before_loader(
        &self,
        entry: &mut super::exec_private::ImageGuestEntry,
        control: &super::exec_private::SuccessorImageControl,
    ) -> io::Result<()> {
        let permit = control.begin_post_exec(core::ptr::from_ref(self) as usize, entry)?;
        let _scratch_scope = DispatchScratchScope::enter();
        let tid = raw_pid(libc::SYS_gettid);
        if tid != self.root_pid {
            return Err(io::Error::other("successor host root identity differs"));
        }
        let Some(_install) = self.begin_install() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "successor Tool callback is active",
            ));
        };
        let tool_arc = self
            .tool_process()
            .ok_or_else(|| io::Error::other("successor Tool is absent"))?;
        let tool: &ToolProcess<T> = &tool_arc;
        let mut pending = self.prepared_exec.try_lock().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "successor post-exec is active")
        })?;
        let restored = pending
            .as_mut()
            .ok_or_else(|| io::Error::other("successor state is absent"))?;
        if !self.states.is_empty()
            || !matches!(restored.phase, PreparedExecPhase::Pending)
            || restored.binding != control.binding()
        {
            return Err(io::Error::other("successor ExecPending binding differs"));
        }
        // Mark failed before invoking untrusted hook code, including unwind.
        restored.phase = PreparedExecPhase::Failed;
        let tail = TailResult::default();
        {
            let mut guest = successor_image_guest::SuccessorImageGuest::<T, R>::new(
                tid,
                &mut restored.state,
                self,
                &tail,
                permit.injection_permit(),
                entry,
            );
            #[cfg(feature = "exec-native-injection")]
            if let Some(driver) = &self.native_exec_driver {
                let mode = guest.signal_control_mode();
                let actual = guest.signal_task_identity();
                driver.bind_post_exec_state(guest.thread_state_mut(), mode, actual)?;
            }
            match drive_callback(tool.handle_post_exec(&mut guest), &tail) {
                CallbackOutcome::Ready(Ok(())) => {}
                CallbackOutcome::Ready(Err(error)) => {
                    return Err(io::Error::from_raw_os_error(error.into_raw()));
                }
                CallbackOutcome::Exit { .. } | CallbackOutcome::Unsupported(_) => {
                    return Err(io::Error::other("successor post-exec transition refused"));
                }
            }
            guest.check_refusal()?;
        }
        permit.complete()?;
        restored.phase = PreparedExecPhase::Complete;
        // ExecComplete publication uses the same restored state. Dispatch now
        // observes an existing state and cannot repeat either startup hook.
        let completed = pending.take().expect("owned successor state");
        self.prepared_exec_pending
            .store(false, core::sync::atomic::Ordering::Release);
        drop(pending);
        self.states
            .publish(tid.as_raw(), completed.state)
            .map_err(|_| io::Error::other("successor thread state already exists"))?;
        // Release-store after the publish above: a dispatch whose
        // Acquire load observes it clear synchronizes-with the
        // publish and must see the published state.
        self.prepared_exec_pending
            .store(false, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Bind this actual installed host to its authenticated InitialImage.
    ///
    /// # Safety
    /// The backend must call this only on its stable, installed ToolHost,
    /// before controller installation, using the control and same live RPC
    /// connection consumed by that installation. The host may not move or be
    /// replaced afterwards. Binding an independently constructed host would
    /// not establish installed-handler provenance. The installed Tool's guest
    /// memory effects must preserve Rust's memory invariants, as on dispatch.
    #[cfg(feature = "exec-private-init")]
    pub(super) unsafe fn bind_initial_image_control(
        &self,
        control: &super::exec_private::InitialImageControl,
    ) -> io::Result<()> {
        control.bind_lifecycle_host(core::ptr::from_ref(self) as usize)
    }

    /// Attach the exact decoded selected root state as pending for a
    /// mapped successor. This neither creates thread state nor calls
    /// `on_initial_image_attached`, `init_thread_state`,
    /// `handle_thread_start`, or post-exec callbacks.
    ///
    /// # Safety
    /// The same installer must have decoded and validated this state
    /// from the admitted carrier's exact delivered bytes for this
    /// authenticated mapped image. A matching digest alone does not
    /// prove correct Tool-state restoration.
    #[cfg(feature = "exec-private-init")]
    pub unsafe fn restore_mapped_successor_state(
        &self,
        state: T::ThreadState,
        control: &super::exec_private::InitialImageControl,
    ) -> io::Result<()> {
        control.begin_mapped_successor_restore(core::ptr::from_ref(self) as usize)?;
        let result = (|| {
            let _allocation_scope = super::alloc::enter_dispatch();
            if self.root_pid != raw_pid(libc::SYS_gettid)
                || self.root_pid != raw_pid(libc::SYS_getpid)
            {
                return Err(io::Error::other(
                    "mapped successor host root identity differs",
                ));
            }
            let Some(_install) = self.begin_install() else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "mapped successor state dispatch is active",
                ));
            };
            let mut pending = self.mapped_successor_state.lock();
            if !self.states.is_empty() || pending.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "mapped successor thread state already exists",
                ));
            }
            *pending = Some(MappedSuccessorState {
                state,
                phase: MappedSuccessorPhase::Pending,
            });
            self.mapped_successor_pending
                .store(true, core::sync::atomic::Ordering::Release);
            control.mapped_successor_restore_completed();
            Ok(())
        })();
        if result.is_err() {
            control.mapped_successor_restore_failed();
        }
        result
    }

    /// Run the restored mapped successor's post-exec with the
    /// same callback order as the native successor. There is no
    /// `on_initial_image_attached`, `init_thread_state`,
    /// thread-start, or syscall callback. Only the callback order
    /// and published state are native parity: the mapped path
    /// supplies its mapped-successor guest, with guarded injection
    /// under the selected-restore permit and the verified mapped
    /// resume registers/PKRU; stack access still terminates.
    #[cfg(feature = "exec-private-init")]
    pub(super) fn initialize_mapped_successor_lifecycle(
        &self,
        control: &super::exec_private::InitialImageControl,
        entry: &super::exec_private::MappedSuccessorEntry,
    ) -> io::Result<()> {
        let permit = control.begin_mapped_successor_lifecycle(core::ptr::from_ref(self) as usize)?;
        let _scratch_scope = DispatchScratchScope::enter();
        let tid = raw_pid(libc::SYS_gettid);
        if tid != self.root_pid {
            return Err(io::Error::other(
                "mapped successor host root identity differs",
            ));
        }
        let Some(_install) = self.begin_install() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "mapped successor Tool callback is active",
            ));
        };
        control.verify_mapped_successor_entry(entry)?;
        let tool_arc = self
            .tool_process()
            .ok_or_else(|| io::Error::other("mapped successor Tool is absent"))?;
        let tool: &ToolProcess<T> = &tool_arc;
        let mut pending = self.mapped_successor_state.lock();
        let restored = pending
            .as_mut()
            .ok_or_else(|| io::Error::other("mapped successor state is absent"))?;
        if !self.states.is_empty() || !matches!(restored.phase, MappedSuccessorPhase::Pending) {
            return Err(io::Error::other(
                "mapped successor pending state binding differs",
            ));
        }
        // Mark failed before invoking Tool code, including unwind.
        restored.phase = MappedSuccessorPhase::Failed;
        let tail = TailResult::default();
        {
            let mut guest = mapped_successor_image_guest::MappedSuccessorImageGuest::<T, R>::new(
                tid,
                &mut restored.state,
                self,
                &tail,
                &permit,
                entry,
            );
            #[cfg(feature = "exec-native-injection")]
            if let Some(driver) = &self.native_exec_driver {
                let mode = guest.signal_control_mode();
                let actual = guest.signal_task_identity();
                driver.bind_post_exec_state(guest.thread_state_mut(), mode, actual)?;
            }
            match drive_callback(tool.handle_post_exec(&mut guest), &tail) {
                CallbackOutcome::Ready(Ok(())) => {}
                CallbackOutcome::Ready(Err(error)) => {
                    return Err(io::Error::from_raw_os_error(error.into_raw()));
                }
                CallbackOutcome::Exit { .. } | CallbackOutcome::Unsupported(_) => {
                    return Err(io::Error::other(
                        "mapped successor post-exec transition refused",
                    ));
                }
            }
            guest.check_refusal()?;
        }
        permit.complete()?;
        restored.phase = MappedSuccessorPhase::Complete;
        let completed = pending.take().expect("owned mapped successor state");
        self.mapped_successor_pending
            .store(false, core::sync::atomic::Ordering::Release);
        drop(pending);
        if self
            .states
            .try_publish(tid.as_raw(), completed.state)
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "mapped successor thread state already exists",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "exec-private-init")]
    fn refuse_if_mapped_successor_pending(&self) {
        if self
            .mapped_successor_pending
            .load(core::sync::atomic::Ordering::Acquire)
        {
            unsafe { super::exec_private::initialization_failed(core::ptr::null_mut()) }
        }
    }

    /// Run this installed InitialImage's real thread-start and post-exec
    /// callbacks before any guest instruction. This creates no syscall event
    /// or register snapshot. Unsupported lifecycle operations are retained
    /// even when the Tool ignores their returned error.
    #[cfg(feature = "exec-private-init")]
    pub(super) fn initialize_initial_image_lifecycle(
        &self,
        control: &super::exec_private::InitialImageControl,
    ) -> io::Result<()> {
        let permit = control.begin_lifecycle(core::ptr::from_ref(self) as usize)?;
        let _scratch_scope = DispatchScratchScope::enter();
        let tid = raw_pid(libc::SYS_gettid);
        if tid != self.root_pid {
            return Err(io::Error::other("InitialImage host root identity differs"));
        }
        let Some(_install) = self.begin_install() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "InitialImage Tool callback is active",
            ));
        };
        let tool_arc = self
            .tool_process()
            .ok_or_else(|| io::Error::other("InitialImage Tool is absent"))?;
        let tool: &ToolProcess<T> = &tool_arc;
        if self.states.contains(tid.as_raw()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "InitialImage thread state already exists",
            ));
        }
        let mut state = tool.init_thread_state(tid, None);
        #[cfg(feature = "exec-native-injection")]
        if let Some(driver) = &self.native_exec_driver {
            driver.bind_initial_state(
                tool.as_ref().expect("checked live Tool"),
                &mut state,
                tid.as_raw(),
            )?;
        }
        // The same live permit authenticates this already-completed initial
        // image. Bind before any callback can register the freshly built state.
        // Native physical binding above intentionally still sees initial state.
        tool.as_ref()
            .expect("checked live Tool")
            .on_initial_image_attached(tid, &mut state)
            .map_err(|error| match error {
                Error::Errno(errno) => io::Error::from_raw_os_error(errno.into_raw()),
                other => io::Error::other(describe_reverie_error(&other)),
            })?;
        let tail = TailResult::default();
        {
            let mut guest = image_guest::ImageGuest::<T, R>::new(
                tid,
                &mut state,
                &self.rpc,
                &self.runtime,
                self.cpuid_interception,
                &tail,
                control,
            );
            match drive_callback(tool.handle_thread_start(&mut guest), &tail) {
                CallbackOutcome::Ready(Ok(())) => {}
                CallbackOutcome::Ready(Err(error)) => {
                    return Err(match error {
                        Error::Errno(errno) => io::Error::from_raw_os_error(errno.into_raw()),
                        other => io::Error::other(describe_reverie_error(&other)),
                    });
                }
                CallbackOutcome::Exit { .. } | CallbackOutcome::Unsupported(_) => {
                    return Err(io::Error::other(
                        "InitialImage thread-start transition refused",
                    ));
                }
            }
            guest.check_refusal()?;
            #[cfg(feature = "exec-native-injection")]
            if let Some(driver) = &self.native_exec_driver {
                let mode = guest.signal_control_mode();
                let actual = guest.signal_task_identity();
                driver.bind_post_exec_state(guest.thread_state_mut(), mode, actual)?;
            }
            match drive_callback(tool.handle_post_exec(&mut guest), &tail) {
                CallbackOutcome::Ready(Ok(())) => {}
                CallbackOutcome::Ready(Err(error)) => {
                    return Err(io::Error::from_raw_os_error(error.into_raw()));
                }
                CallbackOutcome::Exit { .. } | CallbackOutcome::Unsupported(_) => {
                    return Err(io::Error::other(
                        "InitialImage post-exec transition refused",
                    ));
                }
            }
            guest.check_refusal()?;
        }
        // Publish completed state before the owner records completion. A failed
        // revalidation removes it and permanently poisons the affine attempt.
        if self.states.try_publish(tid.as_raw(), state).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "InitialImage thread state already exists",
            ));
        }
        if let Err(error) = permit.complete() {
            self.states.remove(tid.as_raw());
            return Err(error);
        }
        Ok(())
    }

    /// Ordinary dispatch must not run while a successor exec state is
    /// pending: the process is a successor image whose post-exec has
    /// not completed, so there is no valid Tool state to dispatch
    /// against. Read the occupancy mirror, never the slot lock —
    /// dispatch itself is the multi-threaded probe here, and plain
    /// contention on the empty slot is not a pending successor
    /// (dh-n6qjq).
    ///
    /// This runs *before* `begin_dispatch`, deliberately. The window
    /// between it and a concurrent restore publishing the pending
    /// state is closed by the restore's own preconditions, not by
    /// `begin_install` — which checks only `active_dispatches` and so
    /// cannot stop a dispatch that has passed this probe but not yet
    /// incremented: `restore_prepared_exec_state` requires the root
    /// thread's identity and runs single-threaded before loader
    /// entry, so no sibling ordinary dispatch is live then.
    #[cfg(feature = "exec-private-successor")]
    fn refuse_if_prepared_exec_pending(&self) {
        if self
            .prepared_exec_pending
            .load(core::sync::atomic::Ordering::Acquire)
        {
            unsafe { super::exec_private::initialization_failed(core::ptr::null_mut()) }
        }
    }

    /// Runs one guest syscall through the Tool and sets `event.result`.
    ///
    /// # Safety
    ///
    /// `event.context` must be 0 or the address of a [`RegisterContext`]
    /// that is valid for reads and writes, and accessed by nothing else, for
    /// the whole call: the Tool reads and writes the guest's registers
    /// through it. The caller must be on the guest thread's syscall path that
    /// produced the event (a trap, a hook or the fallback continuation), so
    /// that forwarding and injecting run as that thread.
    ///
    /// The Tool runs in this process, and a Tool callback can inject
    /// syscalls that read or write any memory of the process (a `read` into
    /// an arbitrary address, for instance). The caller vouches for the Tool:
    /// its injections must not break Rust's memory invariants for any memory
    /// they touch.
    pub unsafe fn dispatch(&self, event: &mut SyscallEvent) {
        // The refusal identity describes this dispatch's terminal
        // result only; never carry a reused event's stale name.
        event.unsupported_refusal = None;
        if self.native_threads.is_some() {
            fatal(126);
        }
        #[cfg(feature = "exec-private-init")]
        self.refuse_if_mapped_successor_pending();
        #[cfg(feature = "exec-private-successor")]
        self.refuse_if_prepared_exec_pending();

        let _scratch_scope = DispatchScratchScope::enter();
        #[cfg(feature = "exec-native-injection")]
        let original_event = *event;
        let (tid, pid) = event_identity();
        let ppid = (pid != self.root_pid).then(|| raw_pid(libc::SYS_getppid));

        // No lock is held across the Tool callback below: the Tool is
        // cloned out of its slot and this thread's state is leased
        // (checked out) for the whole dispatch, so a scheduler RPC that
        // blocks until a sibling thread runs cannot deadlock against a
        // sibling's dispatch. The clone guard further below still keeps
        // guest thread *creation* fail-closed until its own slice.
        let _active = self.begin_dispatch();
        let tool_arc = self.tool_process().unwrap_or_else(|| fatal(126));
        let tool: &ToolProcess<T> = &tool_arc;
        let mut lease = self
            .states
            .checkout(tid.as_raw(), || self.new_thread_state(tool, tid))
            .unwrap_or_else(|| fatal(126));
        let is_new = lease.is_new();
        let state = lease.state_mut();
        let tail = TailResult::default();
        let mut guest = InGuest::<T, R> {
            event,
            tid,
            pid,
            ppid,
            state,
            rpc: &self.rpc,
            native: None,
            tail: &tail,
            cpuid_interception: self.cpuid_interception,
            admit_threads: self.admit_threads,
            thread_birth: self.thread_birth_ops(),
            fork_parent_state: None,
            runtime: &self.runtime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: false,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: self.native_exec_driver.as_deref(),
            #[cfg(feature = "exec-native-injection")]
            native_exec_admitted: self.native_exec_admitted(),
            #[cfg(feature = "exec-native-injection")]
            native_exec_route_active: self.native_exec_admitted(),
            unsupported_refusal: None,
            injected_syscalls: 0,
        };

        // Admission checklist (W7): a thread first seen here was either
        // admitted at birth (lease not new) or is being seen without a
        // birth (admission off, or a backend-created thread); verify its
        // per-thread arming before its first callback either way.
        if is_new
            && self.admit_threads
            && let Err(error) = self.runtime.verify_thread_admission(tid)
        {
            tool_fatal(126, &Error::from(error));
        }
        let mut lifecycle =
            CallbackLifecycle::new(is_new, is_new && tid.as_raw() == self.root_pid.as_raw());
        if let Err(failure) = enter_tool_callbacks(tool, &mut guest, &mut lifecycle) {
            match failure {
                EntryFailure::Tool(error) => tool_fatal(124, &error),
                EntryFailure::Ending(ending) => {
                    drop(guest);
                    drop(tool_arc);
                    finish_ending(self, lease, (tid, pid), ending);
                }
            }
        }

        let Some(number) = usize::try_from(guest.event.number)
            .ok()
            .and_then(Sysno::new)
        else {
            guest.event.result = -i64::from(libc::ENOSYS);
            return;
        };
        if !self.subscriptions.contains(&number) {
            let number = guest.event.number;
            let args = guest.event.args;
            let guest_pkru = guest.event.guest_pkru;
            #[cfg(feature = "exec-native-injection")]
            if let Err(error) = guest.check_native_mapping(number, args) {
                // Terminal unsubscribed return: no Tool callback
                // runs, so the stored name rides on the event.
                guest.surface_terminal_refusal();
                guest.event.result = -i64::from(error.into_raw());
                return;
            }
            if is_plain_fork(number, args) {
                guest.prepare_fork_parent_state();
                let result = forward_plain_fork(number, args, Some(&mut guest.event.guest_pkru));
                if result == 0 {
                    let parent_state = guest.take_fork_parent_state();
                    drop(guest);
                    drop(tool_arc);
                    finish_fork_child(
                        self,
                        lease,
                        event,
                        parent_state,
                        ForkChildContext {
                            parent_tid: tid,
                            parent_pid: pid,
                            child_tid: raw_pid(libc::SYS_gettid),
                            child_pid: raw_pid(libc::SYS_getpid),
                            #[cfg(feature = "exec-native-injection")]
                            native_exec_route_active: self.native_exec_admitted(),
                        },
                    );
                } else {
                    guest.event.result = result;
                }
                return;
            } else if self.admit_threads
                && creation_admission(number, args) == CreationAdmission::ThreadBirth
            {
                // Pre-callback intercept (W7 review): an admitted thread
                // creation reaching dispatch unsubscribed must run the
                // birth trampoline here, never the raw forward below --
                // a plain forward would return the child into these
                // frames on its guest stack.
                let Some(birth) = guest.thread_birth else {
                    guest.event.result = -i64::from(libc::EOPNOTSUPP);
                    return;
                };
                // SAFETY: creation_admission classified this exact call
                // ThreadBirth above; the event is this dispatch's live
                // guest event with its saved context.
                guest.event.result =
                    unsafe { (birth.forward)(birth.host, number, args, guest.event) };
                return;
            } else if number == libc::SYS_clone3
                && self.admit_threads
                && creation_admission(number, args) == CreationAdmission::KernelDecides
            {
                // Deferred to the kernel — but from a checked copy,
                // never the guest's own record pointer: the raw
                // forward below would let a sibling flip a shape the
                // kernel rejects into a creation that skips every
                // fork-child step. The checked copy gets EINVAL.
                guest.event.result =
                    forward_clone3_kernel_decides(args, Some(&mut guest.event.guest_pkru));
                return;
            } else if is_exit_syscall(number) {
                drop(guest);
                drop(tool_arc);
                finish_tool_exit(
                    self,
                    lease,
                    ToolExitContext::exit_syscall(tid, pid, number, args),
                );
                event.result = unsafe { event.forward() };
                return;
            } else if !guest_filter_admitted()
                && let Some(signal) = unsafe { self_directed_fatal_signal(number, args) }
            {
                // The guest is sending itself a signal that would end its
                // process as this call returns, through a call the Tool does
                // not subscribe to. The call reports success (Linux cannot
                // refuse a valid signal to the caller itself, and with no
                // guest seccomp filter nothing else can refuse it), and the
                // signal is sent after the Tool has seen its delivery
                // (`deliver_staged_signals`). With a guest filter admitted,
                // the call is not staged: it runs below as the guest's own
                // call, so Linux's answer (a filter's errno included) is the
                // guest's, and a death by it is the recorded loss of a process
                // that exits without deregistering (see `guest_filter_admitted`).
                guest.event.result = 0;
                guest.stage_signal(StagedSignal {
                    number,
                    args,
                    signal,
                });
                if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
                    drop(guest);
                    drop(tool_arc);
                    finish_ending(self, lease, (tid, pid), ending);
                }
                return;
            } else if matches!(number, libc::SYS_execve | libc::SYS_execveat)
                && let Some(refusal) = guest.exec_native_priority_refusal()
            {
                // Unsubscribed originals never capture the installed
                // native route; a watched exec refuses by name here
                // instead of forwarding past it. No Tool callback
                // runs on this route, so the name rides on the event
                // itself for the dispatch consumer. Unwatched, the
                // guard below keeps the historical refusal.
                guest.event.unsupported_refusal = Some(refusal);
                guest.event.result = -i64::from(Errno::EOPNOTSUPP.into_raw());
                return;
            } else if let Some(error) =
                injected_syscall_guard(&self.runtime, number, args, self.admit_threads)
            {
                guest.event.result = -i64::from(error.into_raw());
                return;
            } else if let Some(result) = super::restorer::mapping_change_result(number, args) {
                guest.event.result = result;
                return;
            } else if let Some(result) =
                unsafe { super::protect::protect_forwarded_descriptor_change(number, args) }
            {
                // A close or close_range the runtime left for dispatch, of a
                // Tool that does not subscribe to it: protected here instead.
                guest.event.result = result;
                return;
            }
            if let Some(result) = virtual_signal_call(&self.runtime, guest_pkru, args, number, args)
            {
                guest.event.result = result;
                return;
            }
            if let Some(result) = perform_pkey_alloc(guest.event, number, args) {
                guest.event.result = result;
                return;
            }
            // This is the original unsubscribed guest operation. Private
            // inject/tail_inject below keep caller rights except for the
            // scalar pkey allocation handled above.
            refuse_mask_installing_forward(
                &self.runtime,
                ForwardRights::Guest(guest_pkru),
                number,
                args,
            );
            match stripped_signal_mask(&self.runtime, number, args) {
                Err(error) => guest.event.result = -i64::from(error.into_raw()),
                Ok(None) => guest.event.result = unsafe { guest.event.forward() },
                Ok(Some(mask)) => {
                    // The stripped copy is runtime-private, so the call runs
                    // through the ordinary raw gate, as on inject and
                    // tail_inject, with the thread's current keys rather than
                    // the guest's saved PKRU (see stripped_signal_mask).
                    let mut stripped_args = args;
                    stripped_args[1] = (&raw const mask) as u64;
                    guest.event.result = unsafe {
                        crate::trap::physical_guest_syscall6(number, stripped_args, None)
                    }
                    .result;
                }
            }
            return;
        }
        let args = guest.event.args.map(|arg| arg as usize);
        let syscall = Syscall::from_raw(
            number,
            SyscallArgs::new(args[0], args[1], args[2], args[3], args[4], args[5]),
        );

        // Drive the Tool handler to a terminal outcome. The shared driver owns
        // the ERESTARTSYS restart protocol (Reverie #362) so it cannot
        // drift between the in-guest backends; this host maps each terminal
        // outcome onto its own per-thread lifecycle (exit/fork-child) state.
        #[cfg(feature = "exec-native-injection")]
        if self.native_exec_admitted()
            && let Some(driver) = self.native_exec_driver.as_ref()
        {
            let mut site = guest.native_exec_site();
            // Capture belongs immediately before this actual handler; it is
            // not a native authorization for thread-start/post-exec callbacks.
            site.in_handler = true;
            site.main_tid = self.root_pid.as_raw();
            guest.exec = Some(super::native_exec::ExecInjection::capture(
                tool.as_ref().expect("checked live Tool"),
                driver,
                (&original_event, guest.event),
                &site,
                &*guest.state,
                &self.rpc,
            ));
        }
        guest.in_syscall_handler = true;
        let driven = drive_tool_process_syscall(tool, &mut guest, syscall, &tail);
        guest.in_syscall_handler = false;
        match driven {
            DrivenSyscall::Result(value) => {
                guest.event.result = value;
                // Deliberately no harvest of guest.unsupported_refusal
                // here: an injection refusal the Tool received and
                // handled (taking the tag is an optional query) is
                // not behind this Tool-selected result. Only routes
                // whose terminal result IS the refusal (tail and
                // unsubscribed) write the event's refusal identity,
                // at the refusal site itself.
                // Signals the Tool's handler sent the guest itself that would
                // end its process (`InGuest::inject` staged them), now that
                // the handler has run to its end, as a tracer delivers a
                // signal held during an injection when the handler returns.
                if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
                    drop(guest);
                    drop(tool_arc);
                    finish_ending(self, lease, (tid, pid), ending);
                }
            }
            DrivenSyscall::Exit { number, .. } if !is_exit_syscall(number) => {
                // The handler injected a SIGKILL of the guest itself
                // (`InGuest::inject`), which ended the handler there, as a
                // tracer's injection of it ends the guest at once. Signals it
                // held before are never delivered.
                drop(guest);
                drop(tool_arc);
                finish_ending(self, lease, (tid, pid), Ending::Death(SignalDeath::KILL));
            }
            DrivenSyscall::Exit { number, args } => {
                // A signal the handler held before its exit is not delivered:
                // the exit ends the process first.
                drop(guest);
                drop(tool_arc);
                finish_tool_exit(
                    self,
                    lease,
                    ToolExitContext::exit_syscall(tid, pid, number, args),
                );
                event.result = unsafe { raw_syscall6(number, args) };
            }
            DrivenSyscall::ForkChild {
                parent_tid,
                parent_pid,
                child_tid,
                child_pid,
            } => {
                let parent_state = guest.take_fork_parent_state();
                drop(guest);
                drop(tool_arc);
                finish_fork_child(
                    self,
                    lease,
                    event,
                    parent_state,
                    ForkChildContext {
                        parent_tid,
                        parent_pid,
                        child_tid,
                        child_pid,
                        #[cfg(feature = "exec-native-injection")]
                        native_exec_route_active: self.native_exec_admitted(),
                    },
                );
            }
            DrivenSyscall::DeferredNative { .. } => tool_fatal(
                125,
                &Error::Tool(
                    io::Error::other("local entry cannot complete a native deferred syscall")
                        .into(),
                ),
            ),
            DrivenSyscall::Fatal(error) => tool_fatal(125, &error),
        }
    }

    /// Runs one CPUID, RDTSC or RDTSCP event through the Tool and writes its
    /// result into `context`.
    ///
    /// # Safety
    ///
    /// `context` must be the registers of the guest instruction being
    /// handled, on the guest thread's path that intercepted it.
    ///
    /// The Tool runs in this process, and a Tool callback can inject
    /// syscalls that read or write any memory of the process (a `read` into
    /// an arbitrary address, for instance). The caller vouches for the Tool:
    /// its injections must not break Rust's memory invariants for any memory
    /// they touch.
    pub unsafe fn dispatch_instruction(
        &self,
        kind: InstructionEventKind,
        context: &mut RegisterContext,
    ) {
        if self.native_threads.is_some() {
            fatal(126);
        }
        #[cfg(feature = "exec-private-init")]
        self.refuse_if_mapped_successor_pending();
        #[cfg(feature = "exec-private-successor")]
        self.refuse_if_prepared_exec_pending();

        let _scratch_scope = DispatchScratchScope::enter();
        let _active = self.begin_dispatch();
        let (tid, pid) = event_identity();
        let ppid = (pid != self.root_pid).then(|| raw_pid(libc::SYS_getppid));
        let tool_arc = self.tool_process().unwrap_or_else(|| fatal(126));
        let tool: &ToolProcess<T> = &tool_arc;
        let mut lease = self
            .states
            .checkout(tid.as_raw(), || self.new_thread_state(tool, tid))
            .unwrap_or_else(|| fatal(126));
        let is_new = lease.is_new();
        let state = lease.state_mut();
        let tail = TailResult::default();
        let mut event = SyscallEvent {
            number: -1,
            args: [0; 6],
            instruction_pointer: NativeIsa::instruction_pointer(context),
            result: 0,
            context: context as *mut RegisterContext as usize,
            dispatch: SyscallDispatch::InstalledHook,
            guest_pkru: None,
            unsupported_refusal: None,
        };
        let mut guest = InGuest::<T, R> {
            event: &mut event,
            tid,
            pid,
            ppid,
            state,
            rpc: &self.rpc,
            native: None,
            tail: &tail,
            cpuid_interception: self.cpuid_interception,
            admit_threads: self.admit_threads,
            thread_birth: self.thread_birth_ops(),
            fork_parent_state: None,
            runtime: &self.runtime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: false,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: self.native_exec_driver.as_deref(),
            #[cfg(feature = "exec-native-injection")]
            native_exec_admitted: self.native_exec_admitted(),
            #[cfg(feature = "exec-native-injection")]
            native_exec_route_active: self.native_exec_admitted(),
            unsupported_refusal: None,
            injected_syscalls: 0,
        };
        // Admission checklist (W7): a thread first seen here was either
        // admitted at birth (lease not new) or is being seen without a
        // birth (admission off, or a backend-created thread); verify its
        // per-thread arming before its first callback either way.
        if is_new
            && self.admit_threads
            && let Err(error) = self.runtime.verify_thread_admission(tid)
        {
            tool_fatal(126, &Error::from(error));
        }
        let mut lifecycle =
            CallbackLifecycle::new(is_new, is_new && tid.as_raw() == self.root_pid.as_raw());
        if let Err(failure) = enter_tool_callbacks(tool, &mut guest, &mut lifecycle) {
            match failure {
                EntryFailure::Tool(error) => tool_fatal(124, &error),
                EntryFailure::Ending(ending) => {
                    drop(guest);
                    drop(tool_arc);
                    finish_ending(self, lease, (tid, pid), ending);
                }
            }
        }

        match kind {
            InstructionEventKind::Cpuid => {
                let outcome = drive_callback(
                    tool.as_ref()
                        .expect("checked live Tool")
                        .handle_cpuid_event(
                            &mut guest,
                            NativeIsa::cpuid_inputs(context).0,
                            NativeIsa::cpuid_inputs(context).1,
                        ),
                    &tail,
                );
                let result = match callback_result(outcome) {
                    Ok(result) => {
                        result.unwrap_or_else(|error| tool_fatal(125, &Error::from(error)))
                    }
                    Err(ending) => {
                        drop(guest);
                        drop(tool_arc);
                        finish_ending(self, lease, (tid, pid), ending)
                    }
                };
                NativeIsa::apply_instruction_result(
                    context,
                    kind,
                    InstructionResult::Cpuid {
                        eax: result.eax,
                        ebx: result.ebx,
                        ecx: result.ecx,
                        edx: result.edx,
                    },
                );
            }
            InstructionEventKind::Rdtsc | InstructionEventKind::Rdtscp => {
                let request = if kind == InstructionEventKind::Rdtscp {
                    Rdtsc::Tscp
                } else {
                    Rdtsc::Tsc
                };
                let outcome = drive_callback(
                    tool.as_ref()
                        .expect("checked live Tool")
                        .handle_rdtsc_event(&mut guest, request),
                    &tail,
                );
                let result = match callback_result(outcome) {
                    Ok(result) => {
                        result.unwrap_or_else(|error| tool_fatal(125, &Error::from(error)))
                    }
                    Err(ending) => {
                        drop(guest);
                        drop(tool_arc);
                        finish_ending(self, lease, (tid, pid), ending)
                    }
                };
                NativeIsa::apply_instruction_result(
                    context,
                    kind,
                    InstructionResult::Tsc {
                        value: result.tsc,
                        aux: result.aux,
                    },
                );
            }
        }
        // The instruction callback can send the guest a signal that ends it;
        // it then ends before the instruction completes.
        if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
            drop(guest);
            drop(tool_arc);
            finish_ending(self, lease, (tid, pid), ending);
        }
    }
}

fn finish_fork_child<T: Tool + 'static, R: HostRuntime>(
    host: &ToolHost<T, R>,
    parent_lease: thread_lease::Lease<'_, T::ThreadState>,
    event: &mut SyscallEvent,
    parent_snapshot: T::ThreadState,
    context: ForkChildContext,
) {
    let ForkChildContext {
        parent_tid,
        parent_pid,
        child_tid,
        child_pid,
        #[cfg(feature = "exec-native-injection")]
        native_exec_route_active,
    } = context;
    let rpc = &host.rpc;
    let runtime = &host.runtime;
    // First child-side acts in this function, before the runtime
    // rebind or any Tool callback below (the heap locks were
    // already released by the forking thread's quiesce guard
    // immediately at the raw fork return; signals are NOT blocked
    // across that window — the runtime action mask is empty
    // outside the signal-delivery gate, and the window consists of
    // the one raw syscall, in which no handler can be admitted):
    // flag the inherited coordinator connection and reinitialize
    // the copied host locks.
    // This child inherited the parent's coordinator connection. Flag it before
    // any child-side callback can issue an RPC (`handle_thread_start` below is
    // the first such opportunity) so the next `send_rpc` reconnects under the
    // child's own identity. Doing it here rather than from a `pthread_atfork`
    // hook also covers forks that never enter libc, such as a raw `SYS_fork` or
    // a raw plain `SYS_clone`.
    super::rpc::note_fork_in_child();
    // Sibling dispatches may have held host spinlocks at the fork
    // instant; their copies here would spin forever. Reinitialize
    // before the first host-lock use below.
    host.reinit_after_fork();
    runtime.fork_child_rebind();
    runtime.emit_stage(b"fork-child-thread-start-begin");
    // The parent lease object is this child's inherited copy of the
    // parent's checkout: abandon it (drop the inherited state without
    // touching the copied registry map, which the reset below
    // leak-replaces).
    drop(parent_lease.abandon());
    let child_tool = host
        .tool_process()
        .unwrap_or_else(|| fatal(126))
        .new_process(child_pid, rpc.config());
    let child_state = child_tool.init_thread_state(child_tid, Some((parent_tid, &parent_snapshot)));
    host.states.reset_to(child_tid.as_raw(), child_state);
    *host.tool.lock() = Some(Arc::new(child_tool));
    // Both installed hooks and deferred fallback carry a register context.
    // Attribute the child's first event to the path that actually entered it.
    runtime.fork_child_reset(event);

    let tool_arc = host.tool_process().unwrap_or_else(|| fatal(126));
    let tool: &ToolProcess<T> = &tool_arc;
    let mut child_lease = host
        .states
        .checkout_existing(child_tid.as_raw())
        .unwrap_or_else(|| fatal(126));
    let state = child_lease.state_mut();
    let child_tail = TailResult::default();
    let mut child_guest = InGuest::<T, R> {
        event,
        tid: child_tid,
        pid: child_pid,
        ppid: Some(parent_pid),
        state,
        rpc,
        native: None,
        tail: &child_tail,
        cpuid_interception: runtime.cpuid_interception_enabled(),
        admit_threads: host.admit_threads,
        thread_birth: host.thread_birth_ops(),
        fork_parent_state: None,
        runtime,
        staged_signals: Vec::new(),
        staged_signal_delivery: false,
        in_syscall_handler: false,
        #[cfg(feature = "exec-native-injection")]
        exec: None,
        #[cfg(feature = "exec-native-injection")]
        mapping_driver: None,
        #[cfg(feature = "exec-native-injection")]
        native_exec_admitted: false,
        #[cfg(feature = "exec-native-injection")]
        native_exec_route_active,
        unsupported_refusal: None,
        injected_syscalls: 0,
    };
    match callback_result(drive_callback(
        tool.handle_thread_start(&mut child_guest),
        &child_tail,
    )) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tool_fatal(124, &error),
        Err(ending) => {
            drop(child_guest);
            // Process exit unwraps the slot's Arc; no clone may be live.
            drop(tool_arc);
            finish_ending(host, child_lease, (child_tid, child_pid), ending)
        }
    }
    if let Some(ending) = deliver_staged_signals(tool, &mut child_guest) {
        drop(child_guest);
        drop(tool_arc);
        finish_ending(host, child_lease, (child_tid, child_pid), ending);
    }
    runtime.emit_stage(b"fork-child-thread-start-complete");
    child_guest.event.result = 0;
}

struct ForkChildContext {
    parent_tid: Pid,
    parent_pid: Pid,
    child_tid: Pid,
    child_pid: Pid,
    #[cfg(feature = "exec-native-injection")]
    native_exec_route_active: bool,
}

// TODO-HUMAN-REVIEW(PR-143): Review single-process Tool exit lifecycle.
fn finish_tool_exit<T: Tool + 'static, R: HostRuntime>(
    host: &ToolHost<T, R>,
    lease: thread_lease::Lease<'_, T::ThreadState>,
    context: ToolExitContext,
) {
    let ToolExitContext {
        tid,
        pid,
        status,
        process_exit,
    } = context;
    let rpc = &host.rpc;
    let runtime = &host.runtime;
    // The exit callbacks run from here: an ending a callback staged has
    // reached the host, and these callbacks may reach the coordinator.
    ENDING_STAGED.store(false, core::sync::atomic::Ordering::Release);
    let state = lease.retire();
    // Scoped so no Arc clone is live when process exit unwraps the slot's.
    let on_exit = {
        let tool = host.tool_process().unwrap_or_else(|| fatal(126));
        drive_ready(tool.on_exit_thread(tid, rpc, state, status))
    };
    if let Err(error) = on_exit {
        tool_fatal(125, &error);
    }
    if let Some((birth_base, birth_len)) = host.birth_stacks.lock().remove(&tid.as_raw()) {
        // The exiting thread resumed on its guest stack long ago; its
        // birth stack is free to release from here. (A thread whose
        // admission itself ended it unregisters its stack first in
        // thread_birth_admit: it is still running on that stack, so
        // no entry is present to release here.)
        unsafe {
            raw_syscall6(
                libc::SYS_munmap,
                [birth_base as u64, birth_len as u64, 0, 0, 0, 0],
            )
        };
    }
    if process_exit {
        let tool = host.tool.lock().take().unwrap_or_else(|| fatal(126));
        let mut tool = Arc::try_unwrap(tool).unwrap_or_else(|_| fatal(126));
        if let Err(error) = drive_ready(tool.on_exit_process(pid, rpc, status)) {
            tool_fatal(125, &error);
        }
        if let Err(error) = runtime.exit_process_stats(tid) {
            tool_fatal(125, &Error::from(error));
        }
    }
    // The exit callbacks above may have used this thread's connection
    // (on_exit_process receives the RPC handle too); past this point it
    // will not be used again. Closing it earlier would make a later
    // callback lazily open a second connection for the same process,
    // which the coordinator admits as a second process connection.
    rpc.close_current_thread();
}

struct ToolExitContext {
    tid: Pid,
    pid: Pid,
    /// The status the exit callbacks report.
    status: reverie::ExitStatus,
    /// Whether the whole process ends, so `on_exit_process` runs too.
    process_exit: bool,
}

impl ToolExitContext {
    /// The exit of `tid` (of process `pid`) by its `exit` or `exit_group`
    /// call `number(args)`.
    fn exit_syscall(tid: Pid, pid: Pid, number: i64, args: [u64; 6]) -> Self {
        Self {
            tid,
            pid,
            status: reverie::exit_status_from_raw(args[0]),
            process_exit: is_process_exit(number, tid, pid),
        }
    }

    /// The end of `tid`'s process `pid` by a signal it sent itself. A fatal
    /// signal ends every thread of the process.
    fn signal_death(tid: Pid, pid: Pid, status: reverie::ExitStatus) -> Self {
        Self {
            tid,
            pid,
            status,
            process_exit: true,
        }
    }
}

/// A `kill`, `tkill` or `tgkill` the guest, or a Tool injection on its
/// behalf, made to send `signal` to the calling thread or process, and which
/// would have ended the process as it returned
/// (`self_directed_fatal_signal`). It is held until the Tool has seen the
/// signal's delivery (`deliver_staged_signals`).
struct StagedSignal {
    number: i64,
    args: [u64; 6],
    signal: i32,
}

/// A signal that is pending and blocked on the calling thread, and whose
/// delivery ends the process once it is unblocked (`die_by_pending_signal`),
/// and the status the Tool's exit callbacks report for that death. SIGKILL,
/// which cannot be blocked, is not sent yet.
struct SignalDeath {
    signal: i32,
    status: reverie::ExitStatus,
}

impl SignalDeath {
    /// A death by SIGKILL, which the kernel never dumps core for, so its
    /// status is exact.
    const KILL: Self = Self {
        signal: libc::SIGKILL,
        status: reverie::ExitStatus::Signaled(reverie::Signal::SIGKILL, false),
    };
}

/// How a process ends at a callback boundary.
enum Ending {
    /// By a signal ([`SignalDeath`]).
    Death(SignalDeath),
    /// By the call `number(args)` a non-handler callback injected: an exit,
    /// or a SIGKILL of the guest itself ([`drive_callback`]).
    Call { number: i64, args: [u64; 6] },
}

/// What a Tool callback other than a syscall handler returned, or how it
/// ended the process. A transition only a syscall handler can complete ends
/// the process as a Tool error, named, before it has any guest-visible
/// effect (the callback is not resumed).
fn callback_result<V>(outcome: CallbackOutcome<V>) -> Result<V, Ending> {
    match outcome {
        CallbackOutcome::Ready(value) => Ok(value),
        CallbackOutcome::Exit { number, args } => Err(Ending::Call { number, args }),
        CallbackOutcome::Unsupported(what) => tool_fatal(
            125,
            &Error::Tool(io::Error::other(format!("{what} is unsupported")).into()),
        ),
    }
}

/// Runs the exit callbacks of thread `tid` of process `pid` for `ending`,
/// and ends the process: by its signal ([`die_by_pending_signal`]), or by
/// the exit a callback injected.
fn finish_ending<T: Tool + 'static, R: HostRuntime>(
    host: &ToolHost<T, R>,
    lease: thread_lease::Lease<'_, T::ThreadState>,
    ids: (Pid, Pid),
    ending: Ending,
) -> ! {
    finish_ending_releasing(host, lease, ids, ending, &mut || {})
}

/// `finish_ending` with a guard-release hook: `release` runs after
/// `finish_tool_exit` (so the exit callbacks still run counted and
/// inside the caller's allocation scope) and immediately before
/// the terminal action in every arm. The birth-admission caller
/// uses it to drop its dispatch guards, which the
/// never-returning terminal action would otherwise leak on
/// whichever TLS the admission ran (the parent's, without
/// CLONE_SETTLS).
fn finish_ending_releasing<T: Tool + 'static, R: HostRuntime>(
    host: &ToolHost<T, R>,
    lease: thread_lease::Lease<'_, T::ThreadState>,
    (tid, pid): (Pid, Pid),
    ending: Ending,
    release: &mut dyn FnMut(),
) -> ! {
    match ending {
        Ending::Death(death) => {
            finish_tool_exit(
                host,
                lease,
                ToolExitContext::signal_death(tid, pid, death.status),
            );
            release();
            die_by_pending_signal(death.signal)
        }
        Ending::Call { number, args } if is_exit_syscall(number) => {
            finish_tool_exit(
                host,
                lease,
                ToolExitContext::exit_syscall(tid, pid, number, args),
            );
            release();
            let _ = unsafe { raw_syscall6(number, args) };
            fatal(126)
        }
        // `InGuest::inject` ends a callback this way only for a SIGKILL of
        // the guest itself.
        Ending::Call { .. } => {
            finish_tool_exit(
                host,
                lease,
                ToolExitContext::signal_death(tid, pid, SignalDeath::KILL.status),
            );
            release();
            die_by_pending_signal(SignalDeath::KILL.signal)
        }
    };
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-self-signal-death): Review the signal-death
// lifecycle.
/// Delivers the signals `guest` holds (`InGuest::stage_signal`), at a
/// callback boundary: after a syscall handler has run to its end (with
/// whatever it did after its injection), after a start-up callback, or after
/// an instruction callback. A tracer delivers a signal it held during an
/// injection at the same point.
///
/// Signals are taken in the order they were sent, and the queue is refilled
/// after every signal callback, so a signal a callback sends is delivered
/// too; a standard signal already waiting in the queue is not queued again,
/// as Linux keeps one pending instance of it. Each signal other than SIGKILL
/// is reported to
/// [`Tool::handle_signal_event`], and then sent unless the Tool suppressed
/// it. Whether it ends the process is decided after the callback, from the
/// kernel's state then ([`signal_ends_process_now`]), because the callback
/// can change the signal's action or the thread's mask, or name another
/// signal to deliver; one that no longer ends the process is sent as the
/// guest asked, and Linux discards or holds it as it would have.
///
/// The first signal that ends the process makes the process die by it,
/// except that a SIGKILL takes its place: SIGKILL cannot be caught, blocked
/// or ignored, and under a tracer its injection ends the process at once,
/// before any held signal is delivered. A Tool's injection of it ends the
/// callback that made it (`InGuest::inject`); the guest's own, held here,
/// wins over everything held with it. It is never shown to the signal
/// callback, as a tracer never sees its delivery. Signals after the one that ends the process are never
/// delivered and are not shown. The death is returned with its signal
/// pending and blocked ([`send_blocked`]; SIGKILL is sent by
/// [`die_by_pending_signal`]), so the caller can run the exit callbacks with
/// nothing left that can fail but the unblock.
fn deliver_staged_signals<T: Tool, R: HostRuntime>(
    tool: &ToolProcess<T>,
    guest: &mut InGuest<'_, T, R>,
) -> Option<Ending> {
    guest.staged_signal_delivery = true;
    let ending = drain_staged_signals(tool, guest);
    guest.staged_signal_delivery = false;
    ending
}

fn drain_staged_signals<T: Tool, R: HostRuntime>(
    tool: &ToolProcess<T>,
    guest: &mut InGuest<'_, T, R>,
) -> Option<Ending> {
    let mut queue: std::collections::VecDeque<StagedSignal> = std::collections::VecDeque::new();
    let mut ending: Option<(StagedSignal, i32)> = None;
    let tail = guest.tail;
    loop {
        for staged in core::mem::take(&mut guest.staged_signals) {
            if !queue.iter().any(|waiting| waiting.signal == staged.signal) {
                queue.push_back(staged);
            }
        }
        if queue.iter().any(|staged| staged.signal == libc::SIGKILL) {
            return Some(Ending::Death(SignalDeath::KILL));
        }
        let Some(staged) = queue.pop_front() else {
            break;
        };
        if ending.is_some() {
            continue;
        }
        let shown = reverie::Signal::try_from(staged.signal).unwrap_or_else(|_| fatal(126));
        let deliver =
            match callback_result(drive_callback(tool.handle_signal_event(guest, shown), tail)) {
                // Suppressed: never sent.
                Ok(Ok(None)) => continue,
                Ok(Ok(Some(chosen))) => chosen as i32,
                Ok(Err(errno)) => tool_fatal(125, &Error::from(errno)),
                // The callback injected an exit or a SIGKILL of the guest.
                Err(ending) => return Some(ending),
            };
        if deliver == libc::SIGKILL {
            return Some(Ending::Death(SignalDeath::KILL));
        }
        // Decided on SIGALRM's disposition now, after the callback: a staged
        // SIGALRM was fatal when it was sent, so the guest had no handler
        // then, but the Tool (this callback, or the handler that held the
        // signal) can have installed one since.
        if deliver == libc::SIGALRM && super::sigalrm::handled() {
            // A guest SIGALRM handler kept virtual by this runtime receives
            // SIGALRM only through a delivery the runtime prepares in the
            // guest call's own turn (signal phase 1); a raw SIGALRM would
            // stay physically blocked and the handler would never run.
            // Refused by name before anything is sent.
            let what = if deliver == staged.signal {
                "delivering the guest's own SIGALRM after the Tool made the guest's SIGALRM \
                 handler virtual is unsupported"
                    .to_owned()
            } else {
                format!(
                    "replacing {shown} with SIGALRM while the guest's SIGALRM handler is \
                     virtual is unsupported"
                )
            };
            tool_fatal(125, &Error::Tool(io::Error::other(what).into()));
        }
        if unsafe { signal_ends_process_now(deliver) } {
            ending = Some((staged, deliver));
        } else {
            let _ = unsafe { send_signal(staged.number, staged.args, staged.signal, deliver) };
        }
    }
    let (staged, deliver) = ending?;
    let shown = reverie::Signal::try_from(deliver).unwrap_or_else(|_| fatal(126));
    if let Err(what) = unsafe { send_blocked(staged.number, staged.args, staged.signal, deliver) } {
        // Before any exit callback: the process is still registered.
        tool_fatal(
            125,
            &Error::Tool(
                io::Error::other(format!(
                    "{shown}, which ends this process, could not be made pending: {what}"
                ))
                .into(),
            ),
        );
    }
    let core = unsafe { core_dump_expected(deliver) };
    Some(Ending::Death(SignalDeath {
        signal: deliver,
        status: reverie::ExitStatus::Signaled(shown, core),
    }))
}

/// Sends `deliver` to the calling thread: the guest's own call
/// `number(args)` when the Tool kept its `signal`, or a `tgkill` of the
/// calling thread when it chose another. Returns the kernel's result.
unsafe fn send_signal(number: i64, args: [u64; 6], signal: i32, deliver: i32) -> i64 {
    if deliver == signal {
        return unsafe { raw_syscall6(number, args) };
    }
    unsafe {
        let pid = raw_syscall6(libc::SYS_getpid, [0; 6]);
        let tid = raw_syscall6(libc::SYS_gettid, [0; 6]);
        raw_syscall6(
            libc::SYS_tgkill,
            [pid as u64, tid as u64, deliver as u64, 0, 0, 0],
        )
    }
}

/// Blocks `deliver` on the calling thread, sends it ([`send_signal`]) and
/// checks that it is pending, so that only the unblock remains between the
/// exit callbacks and the death. On failure the step that failed is named.
/// The block is undone only where the signal is known not to be pending (it
/// was not sent, or the pending set shows it absent), so the undo cannot
/// deliver it; if the pending set cannot be read, the signal stays blocked.
unsafe fn send_blocked(
    number: i64,
    args: [u64; 6],
    signal: i32,
    deliver: i32,
) -> Result<(), String> {
    let bit = 1_u64 << (deliver - 1);
    let unblock = || unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_UNBLOCK as u64,
                (&raw const bit) as u64,
                0,
                8,
                0,
                0,
            ],
        )
    };
    let blocked = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [libc::SIG_BLOCK as u64, (&raw const bit) as u64, 0, 8, 0, 0],
        )
    };
    if blocked != 0 {
        return Err(format!("blocking it returned {blocked}"));
    }
    let sent = unsafe { send_signal(number, args, signal, deliver) };
    if sent != 0 {
        unblock();
        return Err(format!("sending it returned {sent}"));
    }
    match unsafe { current_pending_set() } {
        Some(pending) if pending & bit != 0 => Ok(()),
        Some(pending) => {
            unblock();
            Err(format!(
                "it is not pending after it was sent (pending set {pending:#x})"
            ))
        }
        None => Err("the pending set could not be read after it was sent; it stays blocked".into()),
    }
}

/// Ends the process with `signal`, after its exit callbacks have run: a
/// SIGKILL is sent now, and any other signal, already pending and blocked
/// ([`send_blocked`]), is unblocked, so Linux delivers it as the call
/// returns.
///
/// Neither call can fail except by a guest seccomp filter refusing the
/// runtime's own call (under Hermit a guest's filter install fails with
/// ENOSYS, so there only a runtime defect can reach what follows). If the
/// process survives anyway, the Tool has already
/// retired it, and its physical exit holds every other guest's turn: it must
/// not write to a guest descriptor (a full pipe another guest would have to
/// drain cannot be drained while the hold lasts) or run guest code. It blocks
/// every signal and waits without end. The backend's exit watchdog then fails
/// the run as a backend failure naming the process, and kills it
/// (Hermit: `EXIT_WATCHDOG`, 60 s after the hold began).
fn die_by_pending_signal(signal: i32) -> ! {
    unsafe {
        if signal == libc::SIGKILL {
            let pid = raw_syscall6(libc::SYS_getpid, [0; 6]);
            let tid = raw_syscall6(libc::SYS_gettid, [0; 6]);
            let _ = raw_syscall6(
                libc::SYS_tgkill,
                [pid as u64, tid as u64, libc::SIGKILL as u64, 0, 0, 0],
            );
        } else {
            let bit = 1_u64 << (signal - 1);
            let _ = raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_UNBLOCK as u64,
                    (&raw const bit) as u64,
                    0,
                    8,
                    0,
                    0,
                ],
            );
        }
        let all = u64::MAX;
        let _ = raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_SETMASK as u64,
                (&raw const all) as u64,
                0,
                8,
                0,
                0,
            ],
        );
        loop {
            let _ = raw_syscall6(libc::SYS_ppoll, [0, 0, 0, 0, 8, 0]);
        }
    }
}

// TODO-HUMAN-REVIEW(PR-143): Review exit syscall lifecycle classification.
fn is_exit_syscall(number: i64) -> bool {
    // AUTONOMOUS-BOT-IMPLEMENTED
    matches!(number, libc::SYS_exit | libc::SYS_exit_group)
}

// TODO-HUMAN-REVIEW(PR-143): Review single-process exit classification.
fn is_process_exit(number: i64, tid: Pid, pid: Pid) -> bool {
    // AUTONOMOUS-BOT-IMPLEMENTED
    number == libc::SYS_exit_group || tid == pid
}

/// The calling thread's id and its process's id for one event: read from the
/// kernel, or, under the signal-delivery gate, which admits one guest thread
/// per process and no exec, the values cached at installation and rebound in
/// a fork child (`runtime_mask::cached_identity`).
fn event_identity() -> (Pid, Pid) {
    if super::runtime_mask::delivers_signals() {
        let (tid, pid) = super::runtime_mask::cached_identity();
        if tid <= 0 || pid <= 0 {
            fatal(126);
        }
        return (Pid::from_raw(tid), Pid::from_raw(pid));
    }
    (raw_pid(libc::SYS_gettid), raw_pid(libc::SYS_getpid))
}

fn raw_pid(number: i64) -> Pid {
    let value = unsafe { raw_syscall6(number, [0; 6]) };
    if value <= 0 {
        fatal(126);
    }
    Pid::from_raw(value as i32)
}

/// The [`Guest`] a Tool callback receives: the calling thread's identity and
/// state, the event being handled, and the coordinator connection.
impl<T: Tool, R: HostRuntime> InGuest<'_, T, R> {
    /// Whether this callback can deliver `event`: a SIGALRM to a guest handler
    /// this runtime keeps virtual, from a fallback syscall, whose completion
    /// marker opens the delivery window.
    fn delivers_sigalrm(&self, event: &reverie::SignalEvent) -> bool {
        event.signal() == libc::SIGALRM
            && super::sigalrm::handled()
            && matches!(self.event.dispatch, SyscallDispatch::Fallback)
    }
}

/// Per-thread lifecycle advanced only by the real callbacks below. This is
/// internal state, never serialized image or resumable/register authority.
struct CallbackLifecycle {
    start_pending: bool,
    post_exec_pending: bool,
}
impl CallbackLifecycle {
    fn new(start_pending: bool, post_exec_pending: bool) -> Self {
        Self {
            start_pending,
            post_exec_pending,
        }
    }
}

enum EntryFailure {
    Tool(Error),
    Ending(Ending),
}

// Only the selected native mechanism uses the native wake/park driver.
// Lifecycle tail injection remains refused there, as in the existing native
// start/post-exec owners. Local endings retain their existing finalizer.
fn drive_entry_callback<F, V>(future: F, tail: &TailResult, native: bool) -> Result<V, EntryFailure>
where
    F: core::future::Future<Output = V>,
{
    if native {
        match crate::tool_host::drive_native_callback(future, tail) {
            crate::tool_host::NativeCallbackOutcome::Ready(value) => Ok(value),
            crate::tool_host::NativeCallbackOutcome::Deferred { .. } => Err(EntryFailure::Tool(
                io::Error::other("native lifecycle handler unexpectedly tail-injected").into(),
            )),
            crate::tool_host::NativeCallbackOutcome::Unsupported(reason) => {
                Err(EntryFailure::Tool(io::Error::other(reason).into()))
            }
        }
    } else {
        callback_result(drive_callback(future, tail)).map_err(EntryFailure::Ending)
    }
}

/// Both entry mechanisms use this exact start -> signals -> post-exec ->
/// signals order. Each mechanism still owns its existing ending/finalizer.
fn enter_tool_callbacks<T: Tool, R: HostRuntime>(
    tool: &ToolProcess<T>,
    guest: &mut InGuest<'_, T, R>,
    lifecycle: &mut CallbackLifecycle,
) -> Result<(), EntryFailure> {
    let tail = guest.tail;
    let native = guest.native.is_some();
    if lifecycle.start_pending {
        #[cfg(feature = "native-entry-observer")]
        guest.observe_native_entry(NativeEntryStage::StartEnter);
        drive_entry_callback(tool.handle_thread_start(guest), tail, native)?
            .map_err(EntryFailure::Tool)?;
        #[cfg(feature = "native-entry-observer")]
        guest.observe_native_entry(NativeEntryStage::StartComplete);
        lifecycle.start_pending = false;
        if let Some(native) = &guest.native {
            native.services.acknowledge_tool_admission();
        }
        if let Some(ending) = deliver_staged_signals(tool, guest) {
            return Err(EntryFailure::Ending(ending));
        }
    }
    if lifecycle.post_exec_pending {
        #[cfg(feature = "native-entry-observer")]
        guest.observe_native_entry(NativeEntryStage::PostExecEnter);
        drive_entry_callback(tool.handle_post_exec(guest), tail, native)?
            .map_err(|e| EntryFailure::Tool(e.into()))?;
        #[cfg(feature = "native-entry-observer")]
        guest.observe_native_entry(NativeEntryStage::PostExecComplete);
        lifecycle.post_exec_pending = false;
    }
    if let Some(ending) = deliver_staged_signals(tool, guest) {
        return Err(EntryFailure::Ending(ending));
    }
    Ok(())
}

#[cfg(feature = "native-entry-observer")]
impl<T: Tool, R: HostRuntime> InGuest<'_, T, R> {
    fn observe_native_entry(&self, stage: NativeEntryStage) {
        if let Some(native) = &self.native {
            self.runtime
                .observe_native_entry(stage, NativeEntryObservation::new(native.services));
        }
    }
}

struct NativeGuestView<'callback, G: GlobalTool> {
    services: &'callback NativeServices<'callback>,
    rpc: NativeApplicationRpc<'callback, G>,
    scratch: native_state::CallbackScratch,
    signal_info_replacement: Option<[u8; reverie::SIGNAL_INFO_SIZE]>,
}

/// The common Tool-facing Guest. Fields remain private: only the local host
/// and an admitted native callback lease can construct a view.
/// Type-erased physical thread creation for one host instantiation:
/// performs an admitted CLONE_THREAD creation and returns in the parent
/// only (child tid or negative errno); the child starts life in the
/// birth path and never returns through the injecting frames.
#[derive(Clone, Copy)]
struct ThreadBirthOps {
    host: usize,
    forward: unsafe fn(usize, i64, [u64; 6], &SyscallEvent) -> i64,
}

pub struct InGuest<'a, T: Tool, R: HostRuntime> {
    event: &'a mut SyscallEvent,
    tid: Pid,
    pid: Pid,
    ppid: Option<Pid>,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    native: Option<NativeGuestView<'a, T::GlobalState>>,
    tail: &'a TailResult,
    cpuid_interception: bool,
    /// Mirrors the host's W7 thread-admission capability for guard checks
    /// on injected creations.
    admit_threads: bool,
    /// Physical thread-birth entry (host pointer + monomorphized
    /// forward), present only where a dispatch installed it.
    thread_birth: Option<ThreadBirthOps>,
    fork_parent_state: Option<T::ThreadState>,
    runtime: &'a R,
    /// Signals sent to the caller itself that would end its process, held
    /// until the handler returns (`InGuest::inject`).
    staged_signals: Vec<StagedSignal>,
    /// The signal drain owns a queue, including its currently executing callback.
    staged_signal_delivery: bool,
    /// Whether the Tool callback running is a syscall handler, the only
    /// callback whose `tail_inject` resolves a guest syscall.
    in_syscall_handler: bool,
    #[cfg(feature = "exec-native-injection")]
    exec: Option<super::native_exec::ExecInjection<'a, T>>,
    #[cfg(feature = "exec-native-injection")]
    mapping_driver: Option<&'a dyn super::native_exec::NativeExecDriver<T>>,
    /// Whether the host admitted the native exec/clone route for this
    /// dispatch (embedder opt-in; see `ToolHost::admit_native_exec`).
    #[cfg(feature = "exec-native-injection")]
    native_exec_admitted: bool,
    /// Whether the host's native exec route is admitted, including in
    /// views that cannot capture it themselves (lifecycle callbacks,
    /// unsubscribed originals, tail calls, fork-child and native-entry
    /// views). Those routes use this to refuse a watched exec by name
    /// instead of forwarding past the admitted native authority.
    #[cfg(feature = "exec-native-injection")]
    native_exec_route_active: bool,
    /// The typed refusal of the last injection, if the backend refused it
    /// ([`reverie::Guest::take_unsupported_refusal`]).
    unsupported_refusal: Option<reverie::UnsupportedRefusal>,
    /// Injections made through this guest
    /// ([`reverie::Guest::injected_syscalls`]).
    injected_syscalls: u64,
}

impl<T: Tool, R: HostRuntime> InGuest<'_, T, R> {
    #[cfg(feature = "exec-native-injection")]
    fn native_exec_site(&self) -> super::native_exec::ExecSite {
        super::native_exec::ExecSite {
            tid: self.tid.as_raw(),
            pid: self.pid.as_raw(),
            main_tid: self
                .exec
                .as_ref()
                .map_or(self.pid.as_raw(), |exec| exec.main_tid()),
            in_handler: self.in_syscall_handler,
            staged_signals: !self.staged_signals.is_empty(),
            ending: self.tail.ending(),
            signal_delivery: self.staged_signal_delivery,
            guest_filter: guest_filter_admitted(),
            guest_signal_mode: super::sigalrm::admitted(),
            fork_state: self.fork_parent_state.is_some(),
        }
    }

    /// Whether a watched exec would forward past admitted native
    /// authority from this view: the host's native route is admitted
    /// but this dispatch never captured it (lifecycle callbacks and
    /// unsubscribed originals capture nothing; the subscribed handler
    /// captures before the Tool runs). Forwarding there would bypass
    /// the admitted route's priority, so those routes refuse by name
    /// instead.
    fn exec_native_route_unreachable(&self) -> bool {
        #[cfg(feature = "exec-native-injection")]
        {
            self.native_exec_route_active && self.exec.is_none()
        }
        #[cfg(not(feature = "exec-native-injection"))]
        {
            false
        }
    }

    /// The named refusal for a watched exec on a route that cannot
    /// consult the admitted native exec route, or `None` when the
    /// exec may proceed (unwatched handling is the caller's existing
    /// refusal; no admitted route — whether no driver is installed
    /// or it is installed but unadmitted — or a captured route
    /// forwards through the ordinary paths).
    fn exec_native_priority_refusal(&self) -> Option<reverie::UnsupportedRefusal> {
        if self.runtime.exec_watch_armed() && self.exec_native_route_unreachable() {
            Some(reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::NativeExec,
                Errno::EOPNOTSUPP,
                "watched exec cannot forward from a dispatch route that did not capture \
                 the admitted native exec route",
            ))
        } else {
            None
        }
    }

    /// The named refusal for a watched tail-injected exec while the
    /// native route is admitted: a tail call has no native cut of
    /// its own (the capture belongs to the original dispatch and is
    /// single-attempt), so it refuses by name in every capture state
    /// rather than forwarding past — or re-spending — the admitted
    /// route.
    fn exec_tail_native_refusal(&self) -> Option<reverie::UnsupportedRefusal> {
        #[cfg(feature = "exec-native-injection")]
        if self.runtime.exec_watch_armed() && self.native_exec_route_active {
            return Some(reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::NativeExec,
                Errno::EOPNOTSUPP,
                "tail-injected exec has no native cut of its own and cannot bypass \
                 the admitted native exec route",
            ));
        }
        None
    }

    /// Move this view's stored refusal onto the outward event.
    /// Only for terminal routes whose result IS that refusal and
    /// where no live Tool callback remains to take it from the
    /// view (tail and unsubscribed mapping refusals; the exec
    /// routes write the event directly at their refusal sites).
    /// Never call this for a refusal a Tool received and handled
    /// en route to its own selected result.
    #[cfg(feature = "exec-native-injection")]
    fn surface_terminal_refusal(&mut self) {
        if self.event.unsupported_refusal.is_none() {
            self.event.unsupported_refusal = self.unsupported_refusal.take();
        }
    }

    #[cfg(feature = "exec-native-injection")]
    fn check_native_mapping(&mut self, number: i64, args: [u64; 6]) -> Result<(), Errno> {
        if let Some(driver) = self.mapping_driver
            && let Err(refusal) = driver.check_mapping(number, args)
        {
            self.unsupported_refusal = Some(refusal);
            return Err(refusal.errno);
        }
        Ok(())
    }

    fn inject_native<S: SyscallInfo>(
        &mut self,
        syscall: S,
        purpose: reverie::InjectionPurpose,
    ) -> Result<i64, Errno> {
        self.unsupported_refusal = None;
        self.injected_syscalls += 1;
        let native = self
            .native
            .as_ref()
            .expect("native injection selected by the Guest");
        native
            .services
            .invocation()
            .ensure_current()
            .map_err(|_| Errno::ESTALE)?;
        let (number, args) = syscall.into_parts();
        let args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        let number = number.id() as i64;
        if let Some(result) =
            native
                .rpc
                .owner()
                .protect_operation(native.services.invocation(), number, &args, false)
        {
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        let result = super::native_linux::forward(
            native.services.invocation(),
            purpose,
            &reverie::provider::SyscallRequest::new(number as u64, args),
        );
        Errno::from_ret(result as usize).map(|value| value as i64)
    }

    /// Materialize the parent view while every synchronization owner still
    /// exists. A raw process fork can otherwise copy a locked Tool-state mutex
    /// into the child after its owning thread disappeared. Round-tripping via
    /// the existing ThreadState migration contract gives the child private,
    /// unlocked synchronization primitives without a backend-specific Tool API.
    fn prepare_fork_parent_state(&mut self) {
        let encoded = bincode::serde::encode_to_vec(&*self.state, bincode::config::standard())
            .unwrap_or_else(|_| fatal(126));
        let (snapshot, consumed) = bincode::serde::decode_from_slice::<T::ThreadState, _>(
            &encoded,
            bincode::config::standard(),
        )
        .unwrap_or_else(|_| fatal(126));
        if consumed != encoded.len() {
            fatal(126);
        }
        self.fork_parent_state = Some(snapshot);
    }

    /// Holds `staged` until the handler returns. A standard signal already
    /// held is not held twice: Linux keeps one pending instance of it, so a
    /// handler that sends it again (one the restart protocol re-runs, for
    /// example) still delivers it once.
    fn stage_signal(&mut self, staged: StagedSignal) {
        if !self
            .staged_signals
            .iter()
            .any(|held| held.signal == staged.signal)
        {
            self.staged_signals.push(staged);
        }
    }

    fn take_fork_parent_state(&mut self) -> T::ThreadState {
        self.fork_parent_state.take().unwrap_or_else(|| fatal(126))
    }
}

#[reverie::tool]
impl<T: Tool, R: HostRuntime> GlobalRPC<T::GlobalState> for InGuest<'_, T, R> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        if self.tail.ending() {
            // The guest is ending (see `inject`): the exchange is not entered,
            // since a request can block until the coordinator answers, and
            // the callback stays parked until the host ends the process. The
            // exit callbacks reach the coordinator through the connection
            // they are passed, which this does not gate.
            return std::future::pending().await;
        }
        match &self.native {
            Some(native) => native.rpc.send_rpc(message).await,
            None => self.rpc.send_rpc(message).await,
        }
    }

    fn try_send_rpc_sync(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> Result<<T::GlobalState as GlobalTool>::Response, <T::GlobalState as GlobalTool>::Request>
    {
        if self.tail.ending() {
            return Err(message);
        }
        match &self.native {
            Some(native) => native.rpc.try_send_rpc_sync(message),
            // Preserve the local Guest's former default unsupported hook.
            None => Err(message),
        }
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        match &self.native {
            Some(native) => native.rpc.config(),
            None => self.rpc.config(),
        }
    }
}

/// Set while a Tool callback of this process has staged an injection that
/// ends the guest (an exit, or a SIGKILL of the guest itself) that the host
/// has not taken yet: Tool code that runs then runs after an injection it
/// abandoned. Cleared when the exit callbacks begin (`finish_tool_exit`).
/// Process-wide, because a process's guest code is single-threaded (thread
/// creation is refused), so one callback runs at a time.
static ENDING_STAGED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether the Tool callback running in this process has staged an
/// injection that ends the guest, which the host has not taken yet (see
/// [`reverie::Tool::on_exit_thread`] for what a Tool may still do then).
/// Tool-facing entry points outside the [`Guest`] interface, such as a
/// backend's blocking coordinator request, refuse to act while it is true;
/// the exit callbacks run after it is cleared.
pub fn callback_ending_staged() -> bool {
    super::native_rpc::callback_ending_staged()
        .unwrap_or_else(|| ENDING_STAGED.load(core::sync::atomic::Ordering::Acquire))
}

/// Set once a guest seccomp filter install passed the runtime's guard
/// (`injected_syscall_guard`), whether the guest made the call or a Tool
/// injected it; never cleared, and inherited by a fork child with the rest of
/// the process's memory. A filter can refuse or fake the guest's own calls,
/// so from then on a self-directed signal is not staged: it runs as the
/// guest's own call, Linux's answer is the guest's, and a death by it is the
/// recorded loss of a process that exits without deregistering. Set before
/// the call is made, so a failed install also sets it (the fallback is
/// main's path, never a silent pass). A filter the process had before the
/// runtime started is not seen.
static GUEST_FILTER_ADMITTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Whether a guest seccomp filter may be installed ([`GUEST_FILTER_ADMITTED`]).
fn guest_filter_admitted() -> bool {
    GUEST_FILTER_ADMITTED.load(core::sync::atomic::Ordering::Acquire)
}

/// Refuses, by syscall number alone, a process creation (fork, vfork, clone
/// or clone3) a Tool injects outside a syscall handler: a named Tool error,
/// status 125, before anything runs, reading no guest memory. Only a syscall
/// handler's creation can complete in the child.
fn refuse_creation_outside_handler(number: i64, in_syscall_handler: bool) {
    if !in_syscall_handler && crate::arch::is_fork_family(number) {
        tool_fatal(
            125,
            &Error::Tool(
                io::Error::other(format!(
                    "a process creation (syscall {number}) injected outside a syscall handler \
                     is unsupported"
                ))
                .into(),
            ),
        );
    }
}

impl<T: Tool, R: HostRuntime> InGuest<'_, T, R> {
    /// A filter admitted after staging could invalidate the success already
    /// reported to the Tool. Refuse its installation before the syscall runs,
    /// including while the drain owns signals moved out of `staged_signals`.
    fn refuse_filter_while_staging(&self, number: i64, args: [u64; 6]) {
        if installs_seccomp_filter(number, args)
            && (!self.staged_signals.is_empty()
                || self.staged_signal_delivery
                || self.tail.ending())
        {
            tool_fatal(
                125,
                &Error::Tool(
                    io::Error::other(
                        "a seccomp filter installation while a self-signal is staged or being \
                         delivered is unsupported",
                    )
                    .into(),
                ),
            );
        }
    }

    /// Stages the call `number(args)`, which ends the guest, for the host to
    /// take when the callback parks or returns, and latches the ending: from
    /// here no effect of this callback reaches the guest (see `inject`).
    fn stage_ending(&self, number: i64, args: [u64; 6]) {
        ENDING_STAGED.store(true, core::sync::atomic::Ordering::Release);
        self.tail.set_exit(number, args);
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-326): Review the plain-fork injection boundary.
fn is_plain_fork(number: i64, args: [u64; 6]) -> bool {
    if Some(number) == crate::arch::SYS_FORK {
        return true;
    }
    if Some(number) == crate::arch::SYS_VFORK {
        return true;
    }
    if number == libc::SYS_clone3 {
        return clone3_is_plain_fork(args[0], args[1]);
    }
    if number != libc::SYS_clone {
        return false;
    }
    const SIGNAL_MASK: u64 = 0xff;
    let allowed_flags =
        (libc::CLONE_CHILD_CLEARTID | libc::CLONE_CHILD_SETTID | libc::CLONE_PARENT_SETTID) as u64;
    args[1] == 0
        && args[0] & SIGNAL_MASK == libc::SIGCHLD as u64
        && args[0] & !(SIGNAL_MASK | allowed_flags) == 0
}

/// Read up to the first 88 bytes (eleven words) of a guest
/// `struct clone_args`, or `None` when the record is absent, short, or
/// unreadable. Fields past the guest's stated size read as zero, as the
/// kernel's own zero-extension presents them.
fn read_clone3_fields(address: u64, size: u64) -> Option<[u64; 11]> {
    const CLONE_ARGS_SIZE_VER0: usize = 64;
    const CLONE_ARGS_SIZE_VER2: usize = 88;
    if address == 0 || size < CLONE_ARGS_SIZE_VER0 as u64 {
        return None;
    }
    let mut fields = [0_u64; CLONE_ARGS_SIZE_VER2 / core::mem::size_of::<u64>()];
    let read_len = usize::try_from(size)
        .unwrap_or(usize::MAX)
        .min(core::mem::size_of_val(&fields));
    let local = libc::iovec {
        iov_base: fields.as_mut_ptr().cast(),
        iov_len: read_len,
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: read_len,
    };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let read = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_readv,
            [
                pid as u64,
                (&raw const local) as u64,
                1,
                (&raw const remote) as u64,
                1,
                0,
            ],
        )
    };
    (read == read_len as i64).then_some(fields)
}

fn clone3_is_plain_fork(address: u64, size: u64) -> bool {
    read_clone3_fields(address, size).is_some_and(|fields| clone_args_are_plain_fork(&fields))
}

/// How one guest creation call is admitted when thread admission is on
/// (see [`ToolHost::set_thread_admission`]). With admission off, every
/// shape but [`CreationAdmission::PlainFork`] is refused exactly as
/// before W7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreationAdmission {
    /// The existing plain-fork subset.
    PlainFork,
    /// A `CLONE_THREAD` creation the runtime can track: performed
    /// through the thread-birth trampoline so the new thread's first
    /// runtime act is its admission checklist, never shared frames.
    ThreadBirth,
    /// `CLONE_THREAD` is set but the shape cannot create a thread on
    /// Linux — missing `CLONE_SIGHAND`, missing `CLONE_VM`, a clone3
    /// stack/stack_size pair with exactly one zero, or a clone3 exit
    /// signal on a thread: forward it and let the kernel produce its
    /// own `EINVAL`; no child can result. Every other
    /// kernel-accepted thread shape (no `CLONE_FS`/`CLONE_FILES`, or
    /// a zero stack, which returns the child on the parent's stack)
    /// is `ThreadBirth` or a named refusal, never this.
    KernelDecides,
    /// Shapes the runtime cannot track (namespaces, set_tid, cgroup,
    /// pidfd outputs, shared-VM processes, unknown flag bits).
    Unsupported,
}

/// The clone flag bits a thread creation may carry besides the required
/// sharing set. Anything outside this allowlist — namespace creation,
/// pidfd outputs, ptrace, parent-sibling creation, future bits — is
/// [`CreationAdmission::Unsupported`].
const THREAD_ALLOWED_FLAGS: u64 = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_SYSVSEM
    | libc::CLONE_SETTLS
    | libc::CLONE_PARENT_SETTID
    | libc::CLONE_CHILD_SETTID
    | libc::CLONE_CHILD_CLEARTID) as u64;

/// Pure flag half of thread admission (table-tested). Linux requires
/// only THREAD ⇒ SIGHAND ⇒ VM: a shape carrying those three creates
/// a real thread whether or not it shares fs/files, and a zero stack
/// likewise creates one (returning on the parent's stack). Only the
/// shapes Linux itself rejects with `EINVAL` may defer to it.
fn thread_flags_admission(flags: u64) -> CreationAdmission {
    if flags & libc::CLONE_THREAD as u64 == 0 {
        return CreationAdmission::Unsupported;
    }
    if flags & !THREAD_ALLOWED_FLAGS != 0 {
        return CreationAdmission::Unsupported;
    }
    if flags & libc::CLONE_SIGHAND as u64 == 0 || flags & libc::CLONE_VM as u64 == 0 {
        return CreationAdmission::KernelDecides;
    }
    CreationAdmission::ThreadBirth
}

/// `clone_args` half of thread admission: set_tid/cgroup outputs stay
/// unsupported (no runtime path tracks chosen-TID or cgroup births);
/// the thread shapes Linux itself rejects (exit signal, half-given
/// stack) defer to its `EINVAL`; everything else defers to
/// [`thread_flags_admission`]. Fields are the eleven ver2 words
/// (flags, pidfd, child_tid, parent_tid, exit_signal, stack,
/// stack_size, tls, set_tid, set_tid_size, cgroup).
fn clone_args_thread_admission(fields: &[u64; 11]) -> CreationAdmission {
    if fields[8] != 0 || fields[9] != 0 || fields[10] != 0 {
        return CreationAdmission::Unsupported;
    }
    if fields[0] & libc::CLONE_THREAD as u64 != 0 {
        // Kernel-rejected thread shapes keep Linux's own EINVAL:
        // an exit signal on a thread, or exactly one of the stack
        // pair zero.
        if fields[4] != 0 || (fields[5] == 0) != (fields[6] == 0) {
            return CreationAdmission::KernelDecides;
        }
    } else if fields[4] != 0 {
        return CreationAdmission::Unsupported;
    }
    thread_flags_admission(fields[0])
}

/// Classify one creation call for admission. Plain fork keeps its exact
/// existing meaning; thread shapes are recognized only for the caller to
/// admit under the thread-admission capability.
fn creation_admission(number: i64, args: [u64; 6]) -> CreationAdmission {
    if is_plain_fork(number, args) {
        return CreationAdmission::PlainFork;
    }
    const SIGNAL_MASK: u64 = 0xff;
    if number == libc::SYS_clone {
        return thread_flags_admission(args[0] & !SIGNAL_MASK);
    }
    if number == libc::SYS_clone3 {
        return match read_clone3_fields(args[0], args[1]) {
            Some(fields) => clone_args_thread_admission(&fields),
            None => CreationAdmission::Unsupported,
        };
    }
    CreationAdmission::Unsupported
}

/// Whether `struct clone_args` fields (at least its first 88 bytes, as
/// eleven words) describe the plain-fork subset the runtime accepts: only
/// the TID-output flags, exit signal SIGCHLD, no stack, and nothing in the
/// later fields (set_tid, set_tid_size, cgroup).
fn clone_args_are_plain_fork(fields: &[u64]) -> bool {
    let allowed_flags =
        (libc::CLONE_CHILD_CLEARTID | libc::CLONE_CHILD_SETTID | libc::CLONE_PARENT_SETTID) as u64;
    let flags = fields[0];
    flags & !allowed_flags == 0
        && fields[4] == libc::SIGCHLD as u64
        && fields[5] == 0
        && fields[6] == 0
        && fields[8..11].iter().all(|field| *field == 0)
}

/// One process creation the guest asked for, as the runtime performed or
/// refused it; reported to the [`PhysicalCreationHook`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalCreation {
    /// The child exists. Its birth identity is the pidfs inode number of the
    /// pidfd the kernel created atomically with it (`CLONE_PIDFD`): one inode
    /// per process, never reused while the kernel runs, so it names the child
    /// even after the child has died, been reaped and had its pid reused.
    Created {
        /// The child's pid, which the guest receives.
        pid: i32,
        /// The child's pidfs inode number.
        birth_identity: u64,
    },
    /// The guest's own call failed with this errno, which the guest
    /// receives. No child exists.
    Failed {
        /// The errno the guest receives.
        errno: i32,
    },
    /// The runtime could not perform the creation exactly as the guest's own
    /// call would have run. Whatever the hook returns, the creating process
    /// then ends with status 125.
    Refused {
        /// Why.
        refusal: CreationRefusal,
        /// A child that was created anyway.
        child: Option<RefusedChild>,
    },
}

/// A child created for a refused creation (see [`PhysicalCreation::Refused`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusedChild {
    /// The child's pid.
    pub pid: i32,
    /// Whether Linux accepted the runtime's SIGKILL, sent through the
    /// child's pidfd before it was closed.
    pub killed: bool,
}

/// Why the runtime refused a creation; see [`PhysicalCreation::Refused`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreationRefusal {
    /// The guest's protection keys deny access to key 0, which the runtime's
    /// own clone3 record and pidfd output carry.
    ProtectionKeyDenied,
    /// The runtime cannot tell what Linux's own reading of the guest's
    /// clone_args would return: it cannot copy a page Linux can read (a
    /// write-only page), or its readability probe of a page gave a result
    /// that proves neither a read nor a fault.
    ArgumentsUnreadable,
    /// The physical clone3 failed with an errno other than those the guest's
    /// own call returns for the same reason (EAGAIN or ENOSPC, and for a
    /// guest clone3 also E2BIG or EINVAL from its own record). Errors such as
    /// EMFILE, ENFILE or ENOMEM, which allocating the runtime's pidfd can
    /// return, cannot be attributed to the guest's call.
    RuntimeError(i32),
    /// The guest's parent TID output (`CLONE_PARENT_SETTID`) overlaps the
    /// runtime's own pidfd output: Linux refuses an equal pair with EINVAL
    /// for the substituted call, and an overlapping one would corrupt the
    /// descriptor number, while the guest's own call would succeed.
    OutputAliased,
    /// The guest's clone_args changed between the runtime's classification of
    /// the call and its copy (another process sharing that memory), and the
    /// copy is no longer a plain fork. Nothing was created.
    ArgumentsChanged,
    /// The child exists, but its pidfd is not a pidfs inode or cannot be
    /// read, so it has no birth identity.
    IdentityUnavailable,
    /// The child exists, but the runtime's pidfd was not closed: close failed
    /// with this errno, or (0) close reported success or EINTR while the
    /// descriptor stayed open.
    CloseFailed(i32),
}

/// Called by the runtime in the creating process only, exactly once for each
/// process creation the guest asks for (fork, the copying vfork, and the
/// plain-fork forms of clone and clone3), whether it succeeded, failed or was
/// refused. The call happens synchronously after the physical call returns,
/// and before the copying vfork's wait or the return to the Tool. For
/// `Created` the transient pidfd is closed, and its closure confirmed, before
/// the call. For `Refused` it may still be open (a child that could not be
/// killed, or a failed close); the process then ends right after the call,
/// which releases it. The hook must not wait for guest progress or take
/// the dispatch locks. An error, like a refusal, ends the creating process
/// with status 125; the Tool reports its own failure before returning one.
pub type PhysicalCreationHook = fn(PhysicalCreation) -> io::Result<()>;

static CREATION_HOOK: std::sync::OnceLock<PhysicalCreationHook> = std::sync::OnceLock::new();

/// Why [`set_physical_creation_hook`] failed.
#[derive(Debug)]
pub enum CreationHookError {
    /// A hook is already registered.
    AlreadyRegistered,
    /// The kernel's pidfds are not pidfs inodes (Linux before 6.9), so a
    /// pidfd's inode number does not identify one process.
    PidfsUnavailable,
    /// The runtime's own seccomp filter is not installed yet, so a guest
    /// syscall made before it could attach a filter without the runtime
    /// seeing it. Register the hook after the runtime is installed.
    InterceptionNotInstalled,
    /// The runtime's private page for the pidfd output could not be mapped
    /// (this errno).
    StorageUnavailable(i32),
}

/// Registers the process's [`PhysicalCreationHook`].
///
/// Prerequisite, which the runtime cannot check: no seccomp filter other than
/// the runtime's own may be attached to the process. Another filter would see
/// the runtime's own calls (its readability probes, clone3, close,
/// pidfd_send_signal, exit_group) and could fail them or fake their results,
/// and it could fake any evidence of itself the process might look for
/// (PR_GET_SECCOMP, /proc/self/status). So the registering side establishes
/// it from outside the process: Hermit's coordinator reads the process's
/// `Seccomp_filters` count through the `/proc/<pid>` directory it holds for
/// every admitted process. The runtime guarantees the rest: registration
/// requires the runtime's filter to be installed already, so every later
/// guest syscall is intercepted, and once a hook is registered a guest call
/// that installs a filter is refused with EOPNOTSUPP.
///
/// Threat model: like every in-guest runtime structure, this mechanism
/// assumes the guest does not deliberately corrupt the runtime's memory. The
/// guest shares the runtime's address space and could overwrite the runtime's
/// private page, or replace its mapping, with ordinary stores or mapping
/// calls; that is outside these guarantees. What is guaranteed is that no
/// value the runtime reads after a kernel write (the pidfd and its
/// fstatfs/fstat results) sits in memory a well-behaved guest's own outputs or
/// mappings can reach.
///
/// Scope: the in-guest Tool host's dispatch (a full Tool, with single-threaded
/// guest processes). Calls a built-in tool forwards (`install_builtin`), and
/// syscalls a Tool makes itself through its trusted path, do not pass the
/// creation report or the filter refusal; a Tool that registers a hook must
/// not install a filter or create a process through those paths, and a
/// built-in-tool process must not register one.
///
/// Registration must happen while the process is still
/// single-threaded (before thread admission can create a second
/// thread): the hook cell is a plain `OnceLock` read without
/// synchronization on the creation path, so a fork or thread
/// creation racing registration can observe either state, and a
/// child forked mid-registration can inherit a cell that never
/// completes. The installer already registers before the guest
/// runs; this names the requirement.
///
/// With a hook registered,
/// the runtime performs every process creation as `clone3` with a
/// runtime-owned `CLONE_PIDFD` output, to report the child's birth identity;
/// without one, creations run exactly as before. Fails if a hook is already
/// registered, or if the kernel's pidfds are not pidfs inodes.
pub fn set_physical_creation_hook(hook: PhysicalCreationHook) -> Result<(), CreationHookError> {
    if !crate::seccomp::runtime_filter_installed() {
        return Err(CreationHookError::InterceptionNotInstalled);
    }
    creation_storage().map_err(CreationHookError::StorageUnavailable)?;
    pidfs_available()?;
    CREATION_HOOK
        .set(hook)
        .map_err(|_| CreationHookError::AlreadyRegistered)
}

/// The filesystem magic of pidfs (`PIDFS_MAGIC`), where Linux 6.9 and later
/// give each process one pidfd inode.
const PIDFS_MAGIC: i64 = 0x5049_4446;

/// The address of the four-byte word the kernel writes the runtime's pidfd
/// into: the start of a page the runtime maps privately and anonymously at
/// registration. Nothing else can alias it. A guest-controlled stack could be
/// a shared mapping whose bytes the guest also maps elsewhere and names as a
/// TID output; a private anonymous page has no other mapping of its bytes,
/// and after a fork the child's TID stores reach only its own copy.
/// Inherited by fork children.
fn creation_storage() -> Result<u64, i32> {
    static STORAGE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    if let Some(address) = STORAGE.get() {
        return Ok(*address);
    }
    let mapped = unsafe {
        raw_syscall6(
            libc::SYS_mmap,
            [
                0,
                4096,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        )
    };
    if (-4095..0).contains(&mapped) {
        return Err((-mapped) as i32);
    }
    Ok(*STORAGE.get_or_init(|| mapped as u64))
}

/// Whether a pidfd for this process is a pidfs inode. With no filter but the
/// runtime's (the prerequisite), closing the probe cannot fail but for a
/// kernel fault; if it does, the process ends rather than continue with the
/// probe's descriptor open.
fn pidfs_available() -> Result<(), CreationHookError> {
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let pidfd = unsafe { raw_syscall6(libc::SYS_pidfd_open, [pid as u64, 0, 0, 0, 0, 0]) };
    if pidfd < 0 {
        return Err(CreationHookError::PidfsUnavailable);
    }
    let identity = pidfs_identity(pidfd as libc::c_int);
    if close_runtime_descriptor(pidfd as libc::c_int).is_err() {
        end_process();
    }
    identity
        .map(|_| ())
        .ok_or(CreationHookError::PidfsUnavailable)
}

/// Ends the process with status 125.
fn end_process() -> ! {
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [125, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Closes a descriptor the runtime opened, and confirms that Linux released
/// it: a seccomp filter can report success or EINTR without running close.
/// Linux releases the descriptor even when close reports EINTR. Fails with
/// close's errno, or 0 if the descriptor is still open.
fn close_runtime_descriptor(fd: libc::c_int) -> Result<(), i32> {
    let closed = unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    if closed < 0 && closed != -i64::from(libc::EINTR) {
        return Err((-closed) as i32);
    }
    let open = unsafe {
        raw_syscall6(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
        )
    };
    if open == -i64::from(libc::EBADF) {
        Ok(())
    } else {
        Err(if closed < 0 { (-closed) as i32 } else { 0 })
    }
}

/// Whether a guest call installs a seccomp filter, with its arguments read at
/// the kernel's widths: seccomp's operation is an unsigned int and prctl's
/// option an int; prctl's mode is an unsigned long.
fn installs_seccomp_filter(number: i64, args: [u64; 6]) -> bool {
    (number == libc::SYS_seccomp && args[0] as u32 == libc::SECCOMP_SET_MODE_FILTER)
        || (number == libc::SYS_prctl
            && args[0] as u32 as i32 == libc::PR_SET_SECCOMP
            && args[1] == u64::from(libc::SECCOMP_MODE_FILTER))
}

/// Whether a guest call would give memory a protection key other than 0: an
/// execute-only mapping (protection exactly `PROT_EXEC` once Linux has
/// dropped the `PROT_GROWSDOWN`/`PROT_GROWSUP` modifiers), which Linux backs
/// with an implicit key, or `pkey_mprotect` naming a key other than 0 or -1
/// (-1 is plain `mprotect`).
fn assigns_protection_key(number: i64, args: [u64; 6]) -> bool {
    let prot = match number {
        libc::SYS_mmap | libc::SYS_mprotect => args[2],
        libc::SYS_pkey_mprotect => {
            if !matches!(args[3] as i32, 0 | -1) {
                return true;
            }
            args[2]
        }
        _ => return false,
    };
    prot as i32 & !(libc::PROT_GROWSDOWN | libc::PROT_GROWSUP) == libc::PROT_EXEC
}

/// A guest call that installs a seccomp filter is refused once a creation
/// hook is registered (see [`set_physical_creation_hook`]), and in a process
/// that admits guest SIGALRM handlers: a guest filter could make the
/// runtime's own signal calls report success without running
/// ([`super::sigalrm::record_filter_baseline`]).
fn guest_seccomp_filter_policy(number: i64, args: [u64; 6]) -> Option<Errno> {
    (installs_seccomp_filter(number, args)
        && (CREATION_HOOK.get().is_some() || super::sigalrm::admitted()))
    .then_some(Errno::EOPNOTSUPP)
}

/// The birth identity of `pidfd`: its inode number, if it is a pidfs inode.
/// Before pidfs every pidfd shares one anonymous inode, which names no
/// process.
fn pidfs_identity(pidfd: libc::c_int) -> Option<u64> {
    // The kernel's results go to the runtime's private page when it exists
    // (see `creation_storage`), past the pidfd word, rather than to a stack
    // the guest's own mappings might alias.
    const STATFS_OFFSET: usize = 64;
    const STAT_OFFSET: usize = 512;
    let mut local_statfs = core::mem::MaybeUninit::<libc::statfs>::zeroed();
    let mut local_stat = core::mem::MaybeUninit::<libc::stat>::zeroed();
    let (filesystem, metadata) = match creation_storage() {
        Ok(page) => (
            (page as usize + STATFS_OFFSET) as *mut libc::statfs,
            (page as usize + STAT_OFFSET) as *mut libc::stat,
        ),
        Err(_) => (local_statfs.as_mut_ptr(), local_stat.as_mut_ptr()),
    };
    let statfs = unsafe {
        raw_syscall6(
            libc::SYS_fstatfs,
            [pidfd as u64, filesystem as u64, 0, 0, 0, 0],
        )
    };
    if statfs != 0 {
        return None;
    }
    // `f_type`'s width differs between targets.
    #[allow(clippy::unnecessary_cast)]
    let magic =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*filesystem).f_type)) } as i64;
    if magic != PIDFS_MAGIC {
        return None;
    }
    let stat =
        unsafe { raw_syscall6(libc::SYS_fstat, [pidfd as u64, metadata as u64, 0, 0, 0, 0]) };
    (stat == 0)
        .then(|| unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*metadata).st_ino)) })
}

/// The end of user memory on x86-64 with four-level paging (TASK_SIZE_MAX).
const FOUR_LEVEL_USER_LIMIT: usize = (1 << 47) - 4096;
/// The same with five-level paging.
const FIVE_LEVEL_USER_LIMIT: usize = (1 << 56) - 4096;

/// Linux's limit on a clone3 `size` (PAGE_SIZE); a larger one is E2BIG.
const CLONE_ARGS_SIZE_LIMIT: usize = 4096;
/// The `struct clone_args` size Linux knows (CLONE_ARGS_SIZE_VER2). It copies
/// this much first, then requires any longer record's tail to be zero.
const CLONE_ARGS_SIZE_KNOWN: usize = 88;

/// A creation the runtime did not perform.
enum Unperformed {
    /// The guest's own call would fail with this errno.
    Failed(i32),
    Refused(CreationRefusal),
}

/// Whether the guest's protection keys deny the runtime's key-0 memory,
/// which the kernel must read and write under them.
fn guest_keys_deny_runtime_memory(permissions: Option<u32>) -> bool {
    // PKRU holds an access-disable and a write-disable bit per key; key 0's
    // are bits 0 and 1.
    permissions.is_some_and(|pkru| pkru & 0b11 != 0)
}

/// Fills `record` with the `clone3` arguments that perform the plain-fork
/// creation `number`/`args` with a `CLONE_PIDFD` output at `pidfd`, and
/// returns their size. Callers have already accepted the call with
/// [`is_plain_fork`].
fn clone3_record_for(
    number: i64,
    args: [u64; 6],
    pidfd: u64,
    permissions: Option<u32>,
    record: &mut [u64; CLONE_ARGS_SIZE_LIMIT / 8],
) -> Result<usize, Unperformed> {
    const PIDFD: u64 = libc::CLONE_PIDFD as u64;
    const SIGNAL_MASK: u64 = 0xff;
    const SIZE_VER0: usize = 64;
    // The copying vfork stays a COW fork with the parent waiting: no
    // CLONE_VM or CLONE_VFORK is applied physically. Fork/vfork numbers
    // exist only in the x86-64 table (clone shapes on aarch64 arrive as
    // clone below), so this arm is selected by value, not pattern.
    if Some(number) == crate::arch::SYS_FORK || Some(number) == crate::arch::SYS_VFORK {
        record[..8].copy_from_slice(&[PIDFD, pidfd, 0, 0, libc::SIGCHLD as u64, 0, 0, 0]);
        return Ok(SIZE_VER0);
    }
    let fields: [u64; 8] = match number {
        // Legacy clone(flags, stack, parent_tid, child_tid, tls): the CSIGNAL
        // byte becomes exit_signal, and each TID output keeps its own
        // destination, separate from the pidfd output. The plain-fork subset
        // has no stack and no CLONE_SETTLS.
        libc::SYS_clone => {
            let flags = args[0];
            let child_tid_flags = (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID) as u64;
            let child_tid = if flags & child_tid_flags != 0 {
                args[3]
            } else {
                0
            };
            let parent_tid = if flags & libc::CLONE_PARENT_SETTID as u64 != 0 {
                args[2]
            } else {
                0
            };
            [
                (flags & !SIGNAL_MASK) | PIDFD,
                pidfd,
                child_tid,
                parent_tid,
                flags & SIGNAL_MASK,
                0,
                0,
                0,
            ]
        }
        // The guest's whole record at its own size, so Linux checks the size
        // and the tail on the same bytes, plus the runtime's CLONE_PIDFD
        // output.
        libc::SYS_clone3 => {
            let size = copy_guest_clone_args(args[0], args[1], permissions, record)?;
            // The copy is what runs, and the guest's memory may have changed
            // since the call was classified (a peer sharing it): check the
            // copy itself before adding the runtime's output.
            if !clone_args_are_plain_fork(&record[..]) {
                return Err(Unperformed::Refused(CreationRefusal::ArgumentsChanged));
            }
            record[0] |= PIDFD;
            record[1] = pidfd;
            return Ok(size);
        }
        _ => unreachable!("is_plain_fork accepts only fork, vfork, clone and clone3"),
    };
    record[..fields.len()].copy_from_slice(&fields);
    Ok(SIZE_VER0)
}

/// Copies the guest's `clone_args` (`size` bytes at `address`) into `record`,
/// failing exactly where Linux's own reading (`copy_struct_from_user`) fails,
/// or refusing where the runtime cannot tell what Linux would return.
///
/// Linux reads the record under the guest's protection keys and native page
/// permissions. For a record longer than the 88 bytes it knows, it first
/// checks that the tail is zero, in ascending order: a nonzero byte is E2BIG,
/// and a fault before any nonzero byte is EFAULT. Only then does it copy the
/// first 88 bytes, where a fault is EFAULT.
fn copy_guest_clone_args(
    address: u64,
    size: u64,
    permissions: Option<u32>,
    record: &mut [u64; CLONE_ARGS_SIZE_LIMIT / 8],
) -> Result<usize, Unperformed> {
    const PAGE: usize = 4096;
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    if size > CLONE_ARGS_SIZE_LIMIT {
        return Err(Unperformed::Failed(libc::E2BIG));
    }
    let start = address as usize;
    let Some(end) = start.checked_add(size) else {
        return Err(Unperformed::Failed(libc::EFAULT));
    };
    let unknown = || Unperformed::Refused(CreationRefusal::ArgumentsUnreadable);
    // Linux first checks that the whole range is user memory (access_ok, on
    // the tail and then the head), before reading any of it. The limit is
    // the paging mode's highest user address.
    if end > FIVE_LEVEL_USER_LIMIT {
        return Err(Unperformed::Failed(libc::EFAULT));
    }
    if end > FOUR_LEVEL_USER_LIMIT {
        // EFAULT with four-level paging, readable with five: which one is
        // not known here.
        return Err(unknown());
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(record.as_mut_ptr().cast::<u8>(), size) };
    // Checks [from, to) page by page, copying each readable page's bytes.
    // Stops at the first page Linux cannot read, or (with `zero_tail`) at the
    // first page holding a nonzero byte.
    let mut walk = |from: usize, to: usize, zero_tail: bool| -> Result<(), Unperformed> {
        if from >= to {
            return Ok(());
        }
        let mut page = from & !(PAGE - 1);
        while page < to {
            let low = page.max(from);
            let high = (page + PAGE).min(to);
            match native_readability(low & !3, permissions) {
                Readability::Readable => {}
                Readability::Unreadable => return Err(Unperformed::Failed(libc::EFAULT)),
                Readability::Unknown => return Err(unknown()),
            }
            if !read_guest(low, &mut bytes[low - start..high - start]) {
                return Err(unknown());
            }
            if zero_tail
                && bytes[low - start..high - start]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(Unperformed::Failed(libc::E2BIG));
            }
            page += PAGE;
        }
        Ok(())
    };
    let head_end = start + size.min(CLONE_ARGS_SIZE_KNOWN);
    walk(head_end, end, true)?;
    walk(start, head_end, false)?;
    Ok(size)
}

/// Copies guest memory at `address` into `buffer` without the guest's
/// protection keys (process_vm_readv); false unless every byte was copied.
fn read_guest(address: usize, buffer: &mut [u8]) -> bool {
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let read = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_readv,
            [
                pid as u64,
                (&raw const local) as u64,
                1,
                (&raw const remote) as u64,
                1,
                0,
            ],
        )
    };
    read == buffer.len() as i64
}

/// What Linux's own read of a page would do, under the guest's rights.
enum Readability {
    Readable,
    Unreadable,
    /// The probes proved neither a read nor a fault.
    Unknown,
}

/// Whether Linux can read the aligned word at `address` under the guest's
/// protection keys and native page permissions. Two `FUTEX_WAIT`s with a
/// zero timeout read it without any effect: one expecting the word's actual
/// value (copied without the keys) must time out, and one expecting another
/// value must return EAGAIN; each faults with EFAULT where Linux cannot
/// read. A result that a fixed errno could fake is not accepted as either.
/// When the runtime cannot copy the word, both probes faulting still proves
/// that Linux cannot read it; any other result is unknown.
fn native_readability(address: usize, permissions: Option<u32>) -> Readability {
    let mut word = [0_u8; 4];
    let copied = read_guest(address, &mut word);
    let actual = u32::from_ne_bytes(word);
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let wait = |expected: u32| unsafe {
        crate::trap::raw_syscall6_with_result(
            libc::SYS_futex,
            [
                address as u64,
                (libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG) as u64,
                u64::from(expected),
                (&raw const timeout) as u64,
                0,
                0,
            ],
            permissions,
        )
    }
    .result;
    let fault = -i64::from(libc::EFAULT);
    match (wait(actual), wait(!actual)) {
        (equal, different)
            if copied
                && equal == -i64::from(libc::ETIMEDOUT)
                && different == -i64::from(libc::EAGAIN) =>
        {
            Readability::Readable
        }
        (equal, different) if equal == fault && different == fault => Readability::Unreadable,
        _ => Readability::Unknown,
    }
}

/// Whether a clone3 record's parent TID output (`CLONE_PARENT_SETTID`, field
/// 3) overlaps its pidfd output (field 1); both are four bytes. Linux refuses
/// an equal pair with EINVAL, and for an overlapping one writes the pidfd
/// first and then the child's pid over part of it, so the runtime would read
/// a different descriptor number than the one it owns.
fn parent_tid_aliases_pidfd(record: &[u64]) -> bool {
    let overlaps = |a: u64, b: u64| a < b.saturating_add(4) && b < a.saturating_add(4);
    record[0] & libc::CLONE_PARENT_SETTID as u64 != 0 && overlaps(record[3], record[1])
}

/// Whether a physical clone3 errno is one the guest's own call returns for
/// the same reason; any other is refused (see
/// [`CreationRefusal::RuntimeError`]).
fn errno_is_the_guests(number: i64, errno: i32) -> bool {
    matches!(errno, libc::EAGAIN | libc::ENOSPC)
        || (number == libc::SYS_clone3 && matches!(errno, libc::E2BIG | libc::EINVAL))
}

/// Reports `creation` to `hook`; ends the process if the hook fails or the
/// creation was refused.
fn report_creation(hook: PhysicalCreationHook, creation: PhysicalCreation) {
    let refused = matches!(creation, PhysicalCreation::Refused { .. });
    if hook(creation).is_err() || refused {
        end_process();
    }
}

/// Performs a plain-fork creation as clone3 with the runtime's CLONE_PIDFD
/// output, and reports it to `hook`. Never runs the guest's call another way.
fn reported_creation(
    hook: PhysicalCreationHook,
    number: i64,
    args: [u64; 6],
    guest_pkru: Option<&mut Option<u32>>,
) -> i64 {
    let permissions = guest_pkru.as_ref().and_then(|value| **value);
    let refuse = |refusal, child| {
        report_creation(hook, PhysicalCreation::Refused { refusal, child });
        unreachable!("a refused creation ends the process");
    };
    // The record (on this stack) and the pidfd output (the runtime's private
    // page) carry key 0, and the kernel reads and writes them under the
    // guest's protection keys.
    if guest_keys_deny_runtime_memory(permissions) {
        refuse(CreationRefusal::ProtectionKeyDenied, None);
    }
    // Mapped at registration, so this does not fail here.
    let Ok(pidfd_output) = creation_storage() else {
        refuse(CreationRefusal::RuntimeError(libc::ENOMEM), None);
        unreachable!();
    };
    let pidfd_word = pidfd_output as *mut libc::c_int;
    unsafe { pidfd_word.write_volatile(-1) };
    let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
    let size = match clone3_record_for(number, args, pidfd_output, permissions, &mut record) {
        Ok(size) if parent_tid_aliases_pidfd(&record) => {
            let _ = size;
            refuse(CreationRefusal::OutputAliased, None);
            unreachable!();
        }
        Ok(size) => size,
        Err(Unperformed::Failed(errno)) => {
            report_creation(hook, PhysicalCreation::Failed { errno });
            return -i64::from(errno);
        }
        Err(Unperformed::Refused(refusal)) => {
            refuse(refusal, None);
            unreachable!();
        }
    };
    // Fork quiescence for the Tool heaps: hold their locks across the
    // physical fork so the child copies consistent free lists. No
    // allocation happens between the acquire and the drop in either
    // process (the raw gate below only issues the syscall).
    let physical = {
        let quiesce = super::alloc::quiesce_for_fork();
        let physical = unsafe {
            crate::trap::raw_syscall6_with_result(
                libc::SYS_clone3,
                [record.as_ptr() as u64, size as u64, 0, 0, 0, 0],
                permissions,
            )
        };
        drop(quiesce);
        physical
    };
    if let Some(output) = guest_pkru {
        *output = physical.pkru;
    }
    let result = physical.result;
    if result == 0 {
        // The child, which holds no copy of the pidfd: the kernel installs
        // it in the parent's table only.
        return 0;
    }
    if result < 0 {
        let errno = (-result) as i32;
        if !errno_is_the_guests(number, errno) {
            refuse(CreationRefusal::RuntimeError(errno), None);
        }
        report_creation(hook, PhysicalCreation::Failed { errno });
        return result;
    }
    let pid = result as i32;
    let pidfd = unsafe { pidfd_word.read_volatile() };
    let refused_child = || {
        let sent = unsafe {
            raw_syscall6(
                libc::SYS_pidfd_send_signal,
                [pidfd as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            )
        };
        Some(RefusedChild {
            pid,
            killed: sent == 0,
        })
    };
    let Some(birth_identity) = pidfs_identity(pidfd) else {
        let child = refused_child();
        // A child that could not be killed keeps its handle until the
        // process ends.
        if child.is_some_and(|child| child.killed) {
            let _ = close_runtime_descriptor(pidfd);
        }
        refuse(CreationRefusal::IdentityUnavailable, child);
        unreachable!();
    };
    if let Err(errno) = close_runtime_descriptor(pidfd) {
        // The descriptor may still be open, so the kill can still use it.
        refuse(CreationRefusal::CloseFailed(errno), refused_child());
    }
    report_creation(
        hook,
        PhysicalCreation::Created {
            pid,
            birth_identity,
        },
    );
    result
}

/// Runtime-owned stack a newborn guest thread runs its admission on
/// before resuming on its guest stack. Bounded by the coordinator
/// connection cap in practice (one live birth stack per admitted
/// thread); freed by `finish_tool_exit` when the thread retires.
const BIRTH_STACK_BYTES: usize = 64 * 1024;

/// Birth record handed across the physical clone: the trap context
/// (whose first fields the trampoline reads) plus what admission needs.
#[repr(C)]
struct ThreadBirth<T: Tool, R: HostRuntime> {
    trap: crate::trap::ThreadBirthContext,
    host: *const ToolHost<T, R>,
    number: i64,
    args: [u64; 6],
    birth_stack: (usize, usize),
}

// SAFETY: the record crosses into the child by shared memory (the clone
// shares the address space); the parent neither reads nor writes it after
// a successful clone, and the child owns it from birth (it drops the Box
// it was allocated in). The host pointer is the process-singleton host
// the birth was dispatched from.
unsafe impl<T: Tool, R: HostRuntime> Send for ThreadBirth<T, R> {}

/// Perform one admitted `CLONE_THREAD` creation physically and return in
/// the parent only. The child starts in [`thread_birth_admit`] on a
/// runtime birth stack and resumes as guest code from its clone return;
/// it never returns through the injecting frames it shares memory with.
///
/// # Safety
/// `host` must be the live `ToolHost<T, R>` this pointer was taken from,
/// and `event` the dispatch's event for the clone call.
unsafe fn forward_thread_creation<T: Tool + 'static, R: HostRuntime>(
    host: usize,
    number: i64,
    args: [u64; 6],
    event: &SyscallEvent,
) -> i64 {
    let host = unsafe { &*(host as *const ToolHost<T, R>) };
    if event.context == 0
        || event
            .guest_pkru
            .is_some_and(|_| crate::trap::pkru_present())
    {
        // No saved guest context to resume a child from, or a PKRU guest
        // whose permissions the plain trusted-gate trampoline cannot
        // honor: the typed refusal the guard would have produced.
        return -i64::from(libc::EOPNOTSUPP);
    }
    // SAFETY: event.context names this dispatch's RegisterContext.
    let saved = unsafe { core::ptr::read(event.context as *const RegisterContext) };
    let mut guest_regs = [0_u64; 22];
    // SAFETY: RegisterContext is a 176-byte repr(C) register block; the
    // trap context's guest array has its asserted layout.
    unsafe {
        core::ptr::copy_nonoverlapping(
            &raw const saved as *const u8,
            guest_regs.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<RegisterContext>(),
        );
    }
    guest_regs[16] = 0; // rax: the child's clone return value
    guest_regs[0] = match event.dispatch {
        SyscallDispatch::Trap => event.instruction_pointer,
        _ => event.instruction_pointer + 2,
    };
    // A guest clone3 record lives in guest memory: copy it, re-check
    // the copy's admission, and perform the physical clone from the
    // copy — the same check/use gap as the plain-fork path, where a
    // sibling rewriting the record between classification and the
    // kernel's read could turn the admitted thread shape into a
    // shared-VM process the birth admission would then run in.
    let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
    let physical_args = if number == libc::SYS_clone3 {
        let size = match copy_guest_clone_args(args[0], args[1], event.guest_pkru, &mut record) {
            Ok(size) => size,
            Err(Unperformed::Failed(errno)) => return -i64::from(errno),
            Err(Unperformed::Refused(_)) => return -i64::from(libc::EOPNOTSUPP),
        };
        let fields: [u64; 11] = record[..11].try_into().expect("eleven copied words");
        if clone_args_thread_admission(&fields) != CreationAdmission::ThreadBirth {
            return -i64::from(libc::EOPNOTSUPP);
        }
        // Stack 0 keeps the saved guest stack pointer: Linux returns
        // a stack-less thread on the parent's own stack pointer
        // (the very same stack, VM being shared), and the trampoline
        // switches off it before any stack access in either shape.
        if fields[5] != 0 {
            guest_regs[1] = fields[5].saturating_add(fields[6]);
        }
        [record.as_ptr() as u64, size as u64, 0, 0, 0, 0]
    } else {
        if args[1] != 0 {
            guest_regs[1] = args[1];
        }
        args
    };
    // SAFETY: anonymous private mapping owned by this birth until the
    // child registers it for retire-time release.
    let birth_base = unsafe {
        raw_syscall6(
            libc::SYS_mmap,
            [
                0,
                BIRTH_STACK_BYTES as u64,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        )
    };
    if (-4095..0).contains(&birth_base) {
        return birth_base;
    }
    let birth_base = birth_base as usize;
    let mut birth = Box::new(ThreadBirth {
        trap: crate::trap::ThreadBirthContext {
            birth_stack_top: (birth_base + BIRTH_STACK_BYTES) as u64 & !15,
            birth: thread_birth_entry::<T, R>,
            opaque: [0; 4],
            guest: guest_regs,
            guest_pkru: u64::from(event.guest_pkru.unwrap_or(0)),
            has_pkru: u64::from(event.guest_pkru.is_some()),
        },
        host,
        number,
        args,
        birth_stack: (birth_base, BIRTH_STACK_BYTES),
    });
    let result = unsafe {
        crate::trap::thread_clone(number, physical_args, core::ptr::addr_of_mut!(birth.trap))
    };
    if result < 0 {
        // No child: reclaim the stack and record on the parent side.
        unsafe {
            raw_syscall6(
                libc::SYS_munmap,
                [birth_base as u64, BIRTH_STACK_BYTES as u64, 0, 0, 0, 0],
            );
        }
        drop(birth);
        return result;
    }
    // The child owns the record and the birth stack from here.
    core::mem::forget(birth);
    result
}

/// Trampoline target (monomorphized per host): unpack and admit.
unsafe extern "C" fn thread_birth_entry<T: Tool + 'static, R: HostRuntime>(
    context: *mut crate::trap::ThreadBirthContext,
) -> ! {
    // SAFETY: the trampoline was handed the address of the `trap` field,
    // the first field of ThreadBirth (repr(C) on both), boxed by
    // forward_thread_creation and not yet touched by the parent since.
    let birth = unsafe { Box::from_raw(context as *mut ThreadBirth<T, R>) };
    unsafe { thread_birth_admit(birth) }
}

/// Admission checklist for a newborn guest thread, on its birth stack:
/// state lease, backend per-thread arming, thread-start callbacks, then
/// resume as guest code at its clone return. Never returns.
unsafe fn thread_birth_admit<T: Tool + 'static, R: HostRuntime>(
    birth: Box<ThreadBirth<T, R>>,
) -> ! {
    // The bare allocation scope dispatch uses, NOT
    // DispatchScratchScope: without an allocation scope, on
    // GuestAllocator/ScopedToolAllocator hosts the newborn's
    // registry inserts below would take glibc malloc under the
    // birth_stacks/slots locks — a lock-order inversion against
    // glibc fork's arena prepare on a sibling's fork. The scratch
    // scope would additionally clear COMMITTED_STACKS, which must
    // never happen here: without CLONE_SETTLS this admission runs
    // on the parent's TLS, so clearing would free arenas the
    // parent's live dispatch still references. The scope is
    // dropped explicitly before the never-returning resume below,
    // so DISPATCH_DEPTH is also restored on whichever TLS this is.
    let allocation_scope = super::alloc::enter_dispatch();
    let host = unsafe { &*birth.host };
    let tid = raw_pid(libc::SYS_gettid);
    let pid = raw_pid(libc::SYS_getpid);
    // Register the birth stack for retire-time release before anything
    // can observe this thread as admitted.
    host.birth_stacks
        .lock()
        .insert(tid.as_raw(), birth.birth_stack);
    // One admission checklist order everywhere (trait doc): state lease,
    // then per-thread arming verification, then thread-start callbacks.
    // The per-thread coordinator connection opens lazily at this
    // thread's first RPC (slice 2), between lease and first callback use.
    let tool = host.tool_process().unwrap_or_else(|| fatal(126));
    let _active = host.begin_dispatch();
    let mut lease = host
        .states
        .checkout(tid.as_raw(), || host.new_thread_state(&tool, tid))
        .unwrap_or_else(|| fatal(126));
    if let Err(error) = host.runtime.verify_thread_admission(tid) {
        tool_fatal(126, &Error::from(error));
    }
    if !lease.is_new() {
        // A birth whose state already exists is a host invariant break:
        // this thread was just created by this very clone.
        fatal(126);
    }
    let mut event = SyscallEvent {
        number: birth.number,
        args: birth.args,
        instruction_pointer: birth.trap.guest[0],
        result: 0,
        context: core::ptr::addr_of!(birth.trap.guest) as usize,
        dispatch: SyscallDispatch::Trap,
        guest_pkru: (birth.trap.has_pkru != 0).then_some(birth.trap.guest_pkru as u32),
        unsupported_refusal: None,
    };
    let tail = TailResult::default();
    let mut guest = InGuest::<T, R> {
        event: &mut event,
        tid,
        pid,
        ppid: Some(raw_pid(libc::SYS_getppid)),
        state: lease.state_mut(),
        rpc: &host.rpc,
        native: None,
        tail: &tail,
        cpuid_interception: host.cpuid_interception,
        admit_threads: host.admit_threads,
        thread_birth: host.thread_birth_ops(),
        fork_parent_state: None,
        runtime: &host.runtime,
        staged_signals: Vec::new(),
        staged_signal_delivery: false,
        in_syscall_handler: false,
        #[cfg(feature = "exec-native-injection")]
        exec: None,
        #[cfg(feature = "exec-native-injection")]
        mapping_driver: None,
        #[cfg(feature = "exec-native-injection")]
        native_exec_admitted: host.native_exec_admitted(),
        #[cfg(feature = "exec-native-injection")]
        native_exec_route_active: host.native_exec_admitted(),
        unsupported_refusal: None,
        injected_syscalls: 0,
    };
    let mut lifecycle = CallbackLifecycle::new(true, false);
    match enter_tool_callbacks(&tool, &mut guest, &mut lifecycle) {
        Ok(()) => {}
        Err(EntryFailure::Tool(error)) => {
            drop(guest);
            tool_fatal(124, &error);
        }
        Err(EntryFailure::Ending(ending)) => {
            drop(guest);
            drop(tool);
            // This thread still runs on its birth stack: unregister
            // it so finish_tool_exit cannot munmap the stack in use
            // (the mapping is deliberately leaked until process
            // exit or exec). Both dispatch guards stay live across
            // finish_tool_exit — the exit callbacks must run
            // counted and inside the allocation scope, exactly as
            // on every other dispatch path — and are released by
            // the hook immediately before the terminal action,
            // restoring the counters/depth this admission raised
            // on whichever TLS it ran (the parent's, without
            // SETTLS).
            host.birth_stacks.lock().remove(&tid.as_raw());
            let mut guards = Some((_active, allocation_scope));
            finish_ending_releasing(host, lease, (tid, pid), ending, &mut || {
                drop(guards.take());
            });
        }
    }
    drop(guest);
    drop(lease);
    drop(tool);
    drop(_active);
    // resume_guest_context never returns, so no guard drop would
    // run after it: release the allocation scope explicitly here,
    // restoring DISPATCH_DEPTH on whichever thread's TLS this
    // admission ran (the parent's, without CLONE_SETTLS).
    drop(allocation_scope);
    // The context outlives the box on the birth stack copy below; read
    // the registers out before freeing the record.
    // SAFETY: the box is uniquely owned here and dropped right after.
    let trap_context = unsafe { core::ptr::read(&birth.trap) };
    drop(birth);
    // SAFETY: built by forward_thread_creation from the clone event's
    // saved registers with rax=0 and the guest stack from its arguments.
    unsafe { crate::trap::resume_guest_context(&trap_context) }
}

/// Copy a guest clone3 record into `record`, verify the *copy* is a
/// [`CreationAdmission::KernelDecides`] shape, and return the
/// forwarding arguments that name the copy. Every clone3 a ToolHost
/// path actually forwards — plain fork, thread birth, and the
/// deferred KernelDecides shapes on dispatch, inject and
/// tail_inject — goes from a checked runtime-owned copy, and any
/// clone3 that reaches the generic forward instead is refused by
/// `injected_syscall_guard`: no ToolHost forward ever hands the
/// kernel the guest's own pointer, so a sibling rewriting the
/// record between classification and the kernel's read cannot
/// turn a shape classified as kernel-rejected into a real thread
/// or a shared-memory child that skips the fork-child lifecycle.
/// A copy that no
/// longer classifies KernelDecides, or one the runtime cannot read
/// as Linux would, ends the process exactly like a refused
/// reported creation; a copy Linux's own reading would fail
/// returns that failure as `Err(-errno)`.
fn checked_kernel_decides_clone3(
    args: [u64; 6],
    permissions: Option<u32>,
    record: &mut [u64; CLONE_ARGS_SIZE_LIMIT / 8],
) -> Result<[u64; 6], i64> {
    let size = match copy_guest_clone_args(args[0], args[1], permissions, record) {
        Ok(size) => size,
        Err(Unperformed::Failed(errno)) => return Err(-i64::from(errno)),
        Err(Unperformed::Refused(_)) => end_process(),
    };
    let fields: [u64; 11] = record[..11].try_into().expect("eleven copied words");
    if clone_args_thread_admission(&fields) != CreationAdmission::KernelDecides {
        end_process();
    }
    Ok([record.as_ptr() as u64, size as u64, 0, 0, 0, 0])
}

/// Forward one KernelDecides clone3 on the dispatch path, with the
/// guest's rights: the checked copy receives the kernel's own
/// EINVAL, so no child can result and no heap quiesce is owed. The
/// copy carries key 0 and the kernel reads it under the guest's
/// protection keys, so key denial ends the process as in
/// `forward_plain_fork`.
fn forward_clone3_kernel_decides(args: [u64; 6], guest_pkru: Option<&mut Option<u32>>) -> i64 {
    let permissions = guest_pkru.as_ref().and_then(|value| **value);
    if guest_keys_deny_runtime_memory(permissions) {
        end_process();
    }
    let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
    let copy_args = match checked_kernel_decides_clone3(args, permissions, &mut record) {
        Ok(copy_args) => copy_args,
        Err(result) => return result,
    };
    let physical =
        unsafe { crate::trap::raw_syscall6_with_result(libc::SYS_clone3, copy_args, permissions) };
    if let Some(output) = guest_pkru {
        *output = physical.pkru;
    }
    physical.result
}

fn forward_plain_fork(number: i64, args: [u64; 6], guest_pkru: Option<&mut Option<u32>>) -> i64 {
    let result = if let Some(hook) = CREATION_HOOK.get().copied() {
        reported_creation(hook, number, args, guest_pkru)
    } else {
        let permissions = guest_pkru.as_ref().and_then(|value| **value);
        // A guest clone3 record lives in guest memory: copy it,
        // re-check the copy, and forward the copy. Forwarding the
        // guest's own pointer after checking it would let a sibling
        // thread rewrite the flags (to CLONE_VM|CLONE_VFORK, say)
        // between the check and the kernel's read, producing a child
        // that shares the parent's memory — in which the fork-child
        // reinit would then rewrite the parent's live locks and
        // counters. The hook path already copies via
        // `clone3_record_for`; this is the same copy without the
        // pidfd output. A copy that is no longer a plain fork, or
        // one the runtime cannot read as Linux would, ends the
        // process exactly like a refused reported creation: the
        // guest racing its own arguments gets no other answer.
        let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
        let (number, args) = if number == libc::SYS_clone3 {
            // The runtime's copy carries key 0 and the kernel reads
            // it under the guest's protection keys (see
            // `reported_creation`'s ProtectionKeyDenied refusal).
            if guest_keys_deny_runtime_memory(permissions) {
                end_process();
            }
            match copy_guest_clone_args(args[0], args[1], permissions, &mut record) {
                Ok(size) if clone_args_are_plain_fork(&record) => {
                    (number, [record.as_ptr() as u64, size as u64, 0, 0, 0, 0])
                }
                Ok(_) => end_process(),
                Err(Unperformed::Failed(errno)) => return -i64::from(errno),
                Err(Unperformed::Refused(_)) => end_process(),
            }
        } else {
            (number, args)
        };
        // Fork quiescence for the Tool heaps, as in
        // `reported_creation`: hold their locks across the physical
        // fork, with no allocation in the window, and release them
        // immediately on return in both processes.
        let physical = if Some(number) == crate::arch::SYS_VFORK {
            // A real vfork child would run the instrumentation callback on the
            // parent's shared stack. Use a COW fork and preserve vfork's parent
            // suspension until the child exits. Exec remains fail-closed, so exit
            // is the only supported vfork completion boundary for now. Only
            // reachable where the table has fork (vfork is a clone shape on
            // aarch64 and never takes this branch).
            let fork_nr = crate::arch::SYS_FORK.expect("vfork exists only beside fork");
            let quiesce = super::alloc::quiesce_for_fork();
            let physical =
                unsafe { crate::trap::raw_syscall6_with_result(fork_nr, [0; 6], permissions) };
            drop(quiesce);
            physical
        } else {
            let quiesce = super::alloc::quiesce_for_fork();
            let physical =
                unsafe { crate::trap::raw_syscall6_with_result(number, args, permissions) };
            drop(quiesce);
            physical
        };
        if let Some(output) = guest_pkru {
            *output = physical.pkru;
        }
        physical.result
    };
    if Some(number) == crate::arch::SYS_VFORK && result > 0 {
        let mut info = core::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        loop {
            let waited = unsafe {
                raw_syscall6(
                    libc::SYS_waitid,
                    [
                        libc::P_PID as u64,
                        result as u64,
                        info.as_mut_ptr() as u64,
                        (libc::WEXITED | libc::WNOWAIT) as u64,
                        0,
                        0,
                    ],
                )
            };
            if waited == -i64::from(libc::EINTR) {
                continue;
            }
            if waited < 0 {
                return waited;
            }
            break;
        }
    }
    result
}

// TODO-HUMAN-REVIEW(PR-127): Review injected process/signal safety policy.
fn injected_syscall_guard(
    runtime: &impl HostRuntime,
    number: i64,
    args: [u64; 6],
    admit_threads: bool,
) -> Option<Errno> {
    // Every forwarded guest call passes here, so this is where a guest's own
    // seccomp filter is noticed or refused.
    if let Some(error) = guest_seccomp_filter_policy(number, args) {
        return Some(error);
    }
    if installs_seccomp_filter(number, args) {
        // Admitted: from here the guest's own calls may be refused or faked
        // by a filter the runtime does not know (see `guest_filter_admitted`).
        GUEST_FILTER_ADMITTED.store(true, core::sync::atomic::Ordering::Release);
    }
    // Signal phase 1: the runtime's virtual signal calls copy guest memory
    // with every protection key open, so a process that admits SIGALRM
    // handlers allocates none: Linux's answer when no key is left.
    if number == libc::SYS_pkey_alloc && super::sigalrm::admitted() {
        return Some(Errno::ENOSPC);
    }
    // Nor gives memory any key but 0: Linux backs an execute-only mapping
    // with an implicit key of its own.
    if super::sigalrm::admitted() && assigns_protection_key(number, args) {
        return Some(Errno::EPERM);
    }
    // Mapping protection is result-bearing and checked separately at each
    // physical forwarding site: raw brk refusals return the current break,
    // not an errno that would corrupt libc's saved break.
    let unsupported_process =
        // AUTONOMOUS-BOT-IMPLEMENTED
        // Any clone3 reaching this guard is refused outright: every
        // legitimate clone3 on a ToolHost path is intercepted and
        // forwarded from a checked runtime copy before the guard is
        // consulted (plain fork, thread birth, KernelDecides), so a
        // clone3 here could only have arrived by falling through
        // those intercepts — where forwarding the guest's own
        // record pointer would reopen the classification/read race
        // those copies close. This also covers admission-off, where
        // the same fall-through existed before W7. Legacy clone and
        // vfork carry register values only and keep the taxonomy
        // match below.
        number == libc::SYS_clone3
        || ((number == libc::SYS_clone || Some(number) == crate::arch::SYS_VFORK)
            && match creation_admission(number, args) {
                CreationAdmission::PlainFork => false,
                // Admitted thread shapes are performed by the caller's
                // birth path, never by plain forwarding; with admission
                // off they refuse here exactly as before W7.
                CreationAdmission::ThreadBirth | CreationAdmission::KernelDecides => {
                    !admit_threads
                }
                CreationAdmission::Unsupported => true,
            })
        // With an armed exec watch the exec forwards to the kernel
        // and the watcher re-bootstraps the successor; without one
        // it stays refused (see HostRuntime::exec_watch_armed).
        || (matches!(number, libc::SYS_execve | libc::SYS_execveat)
            && !runtime.exec_watch_armed());
    let protected_signal =
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-133): Review fail-closed guest signal-handler policy.
        (!runtime.signal_action_supported(number, args)
            && !super::sigalrm::decides_action(number, args))
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (number == libc::SYS_sigaltstack && args[0] != 0);

    if unsupported_process {
        Some(Errno::EOPNOTSUPP)
    } else if protected_signal {
        Some(Errno::EPERM)
    } else {
        None
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-913): Review stripping reserved signals from
// rt_sigprocmask sets instead of refusing them.
/// For an `rt_sigprocmask` that installs a set, returns a copy of that set
/// without [`HostRuntime::reserved_signal_mask`], to forward in its place.
///
/// Linux silently drops SIGKILL and SIGSTOP from such a set; the reserved
/// signals are dropped the same way. A guest, or a Tool such as Detcore that
/// blocks every signal around a blocking `wait4`, can then block everything
/// else and keep running, instead of failing with EPERM. A later read of the
/// mask shows the reserved signals unblocked, which Linux would not. A reserved
/// signal that the guest asked to block also stays deliverable: one sent with
/// `kill`, `tgkill` or `sigqueue` reaches the runtime's handler, which ends the
/// process with status 126 for SIGSYS and applies the default action to
/// SIGSEGV, where Linux would hold it pending for `rt_sigpending`,
/// `rt_sigtimedwait` or `signalfd` to observe. Both deviations are tracked in
/// <https://github.com/rrnewton/reverie/issues/915>.
///
/// `Ok(None)` forwards the call unchanged: it installs no set, or its size is
/// not 8, which Linux rejects with EINVAL before reading the set. A set that
/// cannot be read returns `Err(EFAULT)`, as Linux would, and nothing is
/// forwarded, so an unstripped set never reaches Linux.
///
/// The set is copied by `process_vm_writev` from this process to itself: the
/// kernel reads the source with the same user copy `rt_sigprocmask` uses, so
/// any set Linux could read is read here, including one on a write-only page,
/// and an unreadable one fails without a fault in the runtime.
///
/// The copy, and the stripped call that writes the old set, run with the
/// calling thread's current protection-key rights; neither switches PKRU. At an
/// installed hook those are the guest's rights, so a set or old set in memory
/// whose key the guest's PKRU denies fails with EFAULT, as on Linux. On the
/// SIGSYS fallback path the runtime has opened every key, so the same call is
/// accepted there and the old set is written.
///
/// A seccomp filter the guest added sees calls Linux would not make. If it
/// refuses `gettid` or `process_vm_writev` with an error, that error is returned
/// instead of EFAULT; if it kills or traps on either, that happens to a call
/// Linux would have accepted. A filter that inspects `rt_sigprocmask`'s
/// arguments sees the runtime's set pointer in place of the guest's, so one
/// that allows only the guest's pointer refuses the stripped call. Each case
/// fails closed: no unstripped set is installed.
fn stripped_signal_mask(
    runtime: &impl HostRuntime,
    number: i64,
    args: [u64; 6],
) -> Result<Option<u64>, Errno> {
    const SIGSET_SIZE: u64 = core::mem::size_of::<u64>() as u64;
    if number != libc::SYS_rt_sigprocmask || args[1] == 0 || args[3] != SIGSET_SIZE {
        return Ok(None);
    }
    let mut requested = 0_u64;
    // The guest's set is the local source; this runtime's copy is the remote
    // destination, written into the same address space.
    let source = libc::iovec {
        iov_base: args[1] as usize as *mut libc::c_void,
        iov_len: SIGSET_SIZE as usize,
    };
    let destination = libc::iovec {
        iov_base: (&raw mut requested).cast(),
        iov_len: SIGSET_SIZE as usize,
    };
    // A thread id names this address space even after the thread-group leader
    // has exited, when its process id no longer does.
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    if tid < 0 {
        return Err(Errno::new(-tid as i32));
    }
    let copied = unsafe {
        raw_syscall6(
            libc::SYS_process_vm_writev,
            [
                tid as u64,
                (&raw const source) as u64,
                1,
                (&raw const destination) as u64,
                1,
                0,
            ],
        )
    };
    if copied == SIGSET_SIZE as i64 {
        Ok(Some(requested & !runtime.reserved_signal_mask()))
    } else if copied >= 0 || copied == -i64::from(libc::EFAULT) {
        // Part of the set, or none of it, could be read.
        Err(Errno::EFAULT)
    } else {
        Err(Errno::new(-copied as i32))
    }
}

/// Outcome of the one shared lifecycle injection guard chain.
/// `Refused` still requires the guest to record its sticky
/// first refusal before returning the carried result.
#[cfg(any(feature = "exec-private-successor", feature = "exec-private-init"))]
pub(super) enum GuardedLifecycleInjection {
    /// Run the route's physical lifecycle leaf with these exact
    /// arguments; `mask`, when present, must outlive that call so
    /// the caller can point `args[1]` at it.
    Physical {
        /// Guard-adjusted syscall arguments.
        args: [u64; 6],
        /// Stripped signal mask storage, when the call needs one.
        mask: Option<u64>,
    },
    /// Do not run any physical call; return this precomputed
    /// result after recording the caller's sticky refusal.
    Refused(core::result::Result<i64, Errno>),
}

/// The one deny/mapping/signal/descriptor guard chain shared by
/// native and mapped successor lifecycle injection.
#[cfg(any(feature = "exec-private-successor", feature = "exec-private-init"))]
pub(super) fn guard_lifecycle_injection(
    runtime: &impl HostRuntime,
    number: i64,
    mut args: [u64; 6],
    mapping_allowed: impl FnOnce() -> bool,
) -> GuardedLifecycleInjection {
    // Lifecycle may not create/replace/terminate an image, admit an extra
    // filter/namespace, stage delivery, or activate keys/guest handlers.
    if matches!(
        number,
        libc::SYS_clone
            | libc::SYS_clone3
            | libc::SYS_fork
            | libc::SYS_vfork
            | libc::SYS_execve
            | libc::SYS_execveat
            | libc::SYS_exit
            | libc::SYS_exit_group
            | libc::SYS_rt_sigreturn
            | libc::SYS_rseq
            | libc::SYS_seccomp
            | libc::SYS_unshare
            | libc::SYS_setns
            | libc::SYS_mount
            | libc::SYS_umount2
            | libc::SYS_chroot
            | libc::SYS_pivot_root
            | libc::SYS_pkey_alloc
            | libc::SYS_pkey_free
            | libc::SYS_pkey_mprotect
            | libc::SYS_kill
            | libc::SYS_tkill
            | libc::SYS_tgkill
            | libc::SYS_rt_sigqueueinfo
            | libc::SYS_rt_tgsigqueueinfo
    ) || (number == libc::SYS_prctl && args[0] == libc::PR_SET_SECCOMP as u64)
        || (number == libc::SYS_arch_prctl && args[0] == 0x1001)
    {
        return GuardedLifecycleInjection::Refused(Err(Errno::EOPNOTSUPP));
    }
    if !mapping_allowed() {
        return GuardedLifecycleInjection::Refused(Err(Errno::EOPNOTSUPP));
    }
    if let Some(error) = injected_syscall_guard(runtime, number, args, false) {
        return GuardedLifecycleInjection::Refused(Err(error));
    }
    if let Some(result) = super::restorer::mapping_change_result(number, args) {
        return GuardedLifecycleInjection::Refused(
            Errno::from_ret(result as usize).map(|value| value as i64),
        );
    }
    if let Some(result) =
        unsafe { super::protect::protect_forwarded_descriptor_change(number, args) }
    {
        return GuardedLifecycleInjection::Refused(
            Errno::from_ret(result as usize).map(|value| value as i64),
        );
    }
    let mask = match stripped_signal_mask(runtime, number, args) {
        Ok(mask) => mask,
        Err(error) => return GuardedLifecycleInjection::Refused(Err(error)),
    };
    if mask.is_some() {
        // The caller points args[1] at the returned mask storage
        // immediately before its physical call.
        args[1] = 0;
    }
    GuardedLifecycleInjection::Physical { args, mask }
}

/// The guest memory a Tool callback reaches through [`Guest::memory`]: this
/// process's own memory ([`LocalMemory`]), until the guest is ending.
///
/// Every handle carries its dispatch's [`TailResult`], so once a callback has
/// staged an injection that ends the guest (an exit, or a SIGKILL of the
/// guest itself), every primitive copy through any handle of that dispatch,
/// one obtained before the injection included, fails with ESRCH, as a
/// tracer's access to a tracee its injection killed fails, and copies
/// nothing. A handle cannot outlive its dispatch, so the exit callbacks,
/// which have no [`Guest`], never hold one.
/// Empty exact-copy helpers can return without invoking a primitive, as with
/// the other [`MemoryAccess`] implementations.
pub struct GuestMemory<'a> {
    kind: GuestMemoryKind<'a>,
    tail: &'a TailResult,
}

enum GuestMemoryKind<'a> {
    Local(LocalMemory),
    Native(super::native_services::NativeMemory<'a>),
}

impl GuestMemory<'_> {
    fn new(tail: &TailResult) -> GuestMemory<'_> {
        GuestMemory {
            // SAFETY: the immutable executor below forwards one syscall with
            // unchanged arguments and result, synchronously on this thread.
            kind: GuestMemoryKind::Local(unsafe {
                LocalMemory::with_syscall_executor(runtime_tool_syscall)
            }),
            tail,
        }
    }

    fn with_services<'a>(
        tail: &'a TailResult,
        services: Option<&'a NativeServices<'a>>,
    ) -> GuestMemory<'a> {
        match services {
            Some(native) => GuestMemory {
                kind: GuestMemoryKind::Native(native.memory()),
                tail,
            },
            None => GuestMemory::new(tail),
        }
    }

    fn check(&self) -> Result<(), Errno> {
        if self.tail.ending() {
            Err(Errno::ESRCH)
        } else {
            Ok(())
        }
    }
}

/// Route Tool-owned operations through the existing admitted instruction
/// only inside an actual Tool callback. Initial/successor lifecycle work and
/// callers outside that scope keep ordinary syscall interception.
unsafe fn runtime_tool_syscall(number: Sysno, args: [usize; 6]) -> Result<usize, Errno> {
    if tool_callback_active() {
        // SAFETY: the caller retains valid Tool-owned operands for this
        // synchronous call. This grants no callback scope and changes neither
        // the syscall operands nor the kernel result.
        let result = unsafe { raw_syscall6(number as i64, args.map(|arg| arg as u64)) };
        Errno::from_ret(result as usize)
    } else {
        unsafe { syscalls::syscall6(number, args[0], args[1], args[2], args[3], args[4], args[5]) }
    }
}

// The primitives pass the same ending check. Exact-copy helpers may shortcut
// empty buffers without invoking one; the native-user write stays unsupported.
impl MemoryAccess for GuestMemory<'_> {
    fn read_vectored(
        &self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.check()?;
        match &self.kind {
            GuestMemoryKind::Local(memory) => memory.read_vectored(read_from, write_to),
            GuestMemoryKind::Native(memory) => memory.read_vectored(read_from, write_to),
        }
    }

    fn write_vectored(
        &mut self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.check()?;
        match &mut self.kind {
            GuestMemoryKind::Local(memory) => memory.write_vectored(read_from, write_to),
            GuestMemoryKind::Native(memory) => memory.write_vectored(read_from, write_to),
        }
    }

    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        // The caller's conversion is Tool code, which can stage an ending
        // (abandon a SIGKILL injection, say), so it runs before the check.
        let addr: Addr<'a, u8> = addr.into();
        self.check()?;
        match &self.kind {
            GuestMemoryKind::Local(memory) => memory.read(addr, buf),
            GuestMemoryKind::Native(memory) => memory.read(addr, buf),
        }
    }

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        self.check()?;
        match &mut self.kind {
            GuestMemoryKind::Local(memory) => memory.write(addr, buf),
            GuestMemoryKind::Native(memory) => memory.write(addr, buf),
        }
    }

    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        self.check()?;
        match &mut self.kind {
            GuestMemoryKind::Local(memory) => memory.write_with_user_access(addr, buf),
            GuestMemoryKind::Native(memory) => memory.write_with_user_access(addr, buf),
        }
    }

    fn compare_exchange_u32(
        &mut self,
        addr: AddrMut<u32>,
        expected: u32,
        desired: u32,
    ) -> Result<u32, Errno> {
        self.check()?;
        match &mut self.kind {
            GuestMemoryKind::Local(memory) => memory.compare_exchange_u32(addr, expected, desired),
            GuestMemoryKind::Native(memory) => memory.compare_exchange_u32(addr, expected, desired),
        }
    }
}

#[reverie::tool]
impl<'a, T: Tool, R: HostRuntime> Guest<T> for InGuest<'a, T, R> {
    // This backend has no stopped-generation private input implementation.
    // The typed default injection methods refuse without issuing a native call.
    fn reserved_input_control(&self) -> Option<reverie::reserved_input::ReservedInputControl> {
        None
    }

    type Memory = GuestMemory<'a>;
    type Stack = LocalStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        self.ppid
    }

    // This in-process host has no begin/ready runtime window: install_runtime
    // prepares instrumentation before reverie_inguest::install arms the
    // seccomp filter through which the Tool receives syscalls, so the
    // runtime's own preparation is never delivered to it.
    fn is_backend_runtime_bootstrap(&self) -> bool {
        false
    }

    /// The runtime's own descriptors in this process: the coordinator
    /// connection, the Tool output socket, the performance counters and any
    /// native-exec lease ([`crate::guest::protect::is_runtime_owned_fd`]).
    fn is_runtime_owned_fd(&self, fd: i32) -> bool {
        match &self.native {
            Some(native) => {
                native
                    .rpc
                    .owner()
                    .descriptor(native.services.invocation().identity().physical_pid())
                    == Some(fd)
            }
            None => crate::guest::protect::is_runtime_owned_fd(fd),
        }
    }

    fn controller_capture_fact(&self) -> Option<reverie::ControllerCaptureFact> {
        self.native
            .as_ref()
            .and_then(|native| native.services.controller_fact())
    }

    fn runtime_private_memory_regions(&self) -> Option<reverie::RuntimePrivateMemory> {
        self.native
            .as_ref()
            .map(|native| native.services.private_regions())
    }

    fn runtime_private_memory_is_current(
        &self,
        snapshot: &reverie::RuntimePrivateMemorySnapshot,
    ) -> bool {
        self.native
            .as_ref()
            .is_some_and(|native| native.services.private_is_current(snapshot))
    }

    fn try_mapping_capture(
        &self,
        prepared: reverie::PreparedMappingCapture<<T::GlobalState as GlobalTool>::Request>,
    ) -> Result<<T::GlobalState as GlobalTool>::Response, reverie::MappingCaptureError> {
        let native = self
            .native
            .as_ref()
            .ok_or(reverie::MappingCaptureError::Unavailable)?;
        super::native_capture::execute::<T>(
            native.services,
            native.rpc.owner(),
            self.tid,
            self.config(),
            prepared,
        )
    }

    fn initial_stack_pointer(&self) -> Option<u64> {
        self.native
            .as_ref()
            .and_then(|native| native.services.facts().initial_stack)
    }

    fn auxv(&self) -> reverie::Auxv {
        match &self.native {
            Some(native) => {
                reverie::Auxv::from_entries(native.services.facts().auxv.iter().copied())
            }
            None => reverie::Auxv::from_pid(self.pid()).expect("failed to read auxv table"),
        }
    }

    fn memory(&self) -> Self::Memory {
        GuestMemory::with_services(
            self.tail,
            self.native.as_ref().map(|native| native.services),
        )
    }

    unsafe fn tool_syscall(&self, number: Sysno, args: [usize; 6]) -> Result<usize, Errno> {
        // SAFETY: Guest::tool_syscall's caller vouches for these Tool-owned
        // operands; the adapter preserves them and grants no callback scope.
        match &self.native {
            Some(native) => {
                let value = unsafe {
                    native.services.invocation().invoke(
                        number.id() as i64,
                        args.map(|arg| arg as u64),
                        reverie::InjectionPurpose::Application,
                    )
                };
                Errno::from_ret(value as usize)
            }
            None => unsafe { runtime_tool_syscall(number, args) },
        }
    }

    /// Qualified at the guest's trusted physical gate, where this backend's
    /// forwarded syscalls run (`host_linux::forward`), and only inside the
    /// admitted Tool callback that owns this guest thread's turn. Outside
    /// that scope, or once the guest admitted a seccomp filter of its own
    /// (which could fail or fake the gate's calls), nothing is executed and
    /// the spelling is unknown.
    fn pidfd_self_spelling(&self) -> reverie::PidfdSelfSpelling {
        if let Some(native) = &self.native {
            return native.services.facts().pidfd_self_spelling;
        }
        // Read, never qualified, here: an image whose runtime installed its
        // trap qualified it before the filter
        // (`pidfd_self::initialize_before_runtime_filter`); any other image
        // published nothing and reads Unknown. Outside the admitted callback, or once the guest has installed a
        // filter of its own that could stand between the gate and the
        // kernel, it is unknown. No syscall either way.
        if !tool_callback_active() || guest_filter_admitted() {
            return reverie::PidfdSelfSpelling::Unknown;
        }
        super::pidfd_self::spelling()
    }

    fn signal_info(&self) -> Option<[u8; reverie::SIGNAL_INFO_SIZE]> {
        self.native.as_ref().and_then(|native| {
            native
                .signal_info_replacement
                .or(native.services.facts().signal_info)
        })
    }

    fn set_signal_info(&mut self, info: [u8; reverie::SIGNAL_INFO_SIZE]) -> Result<(), Errno> {
        let Some(native) = &mut self.native else {
            return Err(Errno::ENOSYS);
        };
        let original = native.services.facts().signal_info.ok_or(Errno::EINVAL)?;
        if info[..4] != original[..4] {
            return Err(Errno::EINVAL);
        }
        native.signal_info_replacement = Some(info);
        Ok(())
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        if let Some(native) = &self.native {
            return native
                .services
                .regs()
                .expect("native failed to translate the guest registers");
        }
        if self.event.context != 0 {
            let context = unsafe { &*(self.event.context as *const RegisterContext) };
            return NativeIsa::user_regs_from_context(context);
        }
        NativeIsa::user_regs_from_event(
            self.event.number,
            self.event.args,
            self.event.instruction_pointer,
        )
    }
    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        if self.tail.ending() {
            // The guest is ending: no further guest effect (see `inject`).
            return std::future::pending().await;
        }
        if let Some(native) = &self.native {
            return native.services.set_regs(&regs).map_err(Error::from);
        }
        (self.event.number, self.event.args) = NativeIsa::event_from_user_regs(&regs);
        if self.event.context != 0 {
            let context = unsafe { &mut *(self.event.context as *mut RegisterContext) };
            NativeIsa::apply_user_regs(context, &regs);
        }
        Ok(())
    }
    async fn stack(&mut self) -> Self::Stack {
        match &self.native {
            Some(native) => native.scratch.stack(),
            None => LocalStack::new(),
        }
    }

    async fn daemonize(&mut self) {}

    /// Under the signal-delivery gate, the mask the guest resumes under: the
    /// mask its handler runs under when a delivery is prepared for this
    /// return (signal phase 1's open window), and otherwise the guest mask
    /// the continuation saved and its completion installs. `None` with the
    /// gate off, where the kernel's mask is the guest's own.
    fn resume_signal_mask(&self) -> Option<u64> {
        // The native owner, not the local SIGALRM continuation, restores it.
        if self.native.is_some() {
            return None;
        }
        if !super::runtime_mask::delivers_signals() {
            return None;
        }
        super::sigalrm::open_window_handler_mask().or_else(super::continuation::saved_guest_mask)
    }

    fn take_unsupported_refusal(&mut self) -> Option<reverie::UnsupportedRefusal> {
        self.unsupported_refusal.take()
    }

    fn injected_syscalls(&self) -> Option<u64> {
        Some(self.injected_syscalls)
    }

    async fn inject_with_purpose<S: SyscallInfo>(
        &mut self,
        syscall: S,
        purpose: reverie::InjectionPurpose,
    ) -> std::result::Result<i64, reverie::Error> {
        if self.native.is_some() {
            return self.inject_native(syscall, purpose).map_err(Error::from);
        }
        // This route keeps its existing guarded injection behavior.
        match purpose {
            reverie::InjectionPurpose::Application
            | reverie::InjectionPurpose::Pselect6WrapperValidation => {
                self.inject(syscall).await.map_err(reverie::Error::from)
            }
        }
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        if self.native.is_some() {
            return self.inject_native(syscall, reverie::InjectionPurpose::Application);
        }
        self.unsupported_refusal = None;
        self.injected_syscalls += 1;
        if self.tail.ending() {
            // The guest is ending (an exit or a SIGKILL of itself was staged,
            // perhaps in a future the Tool abandoned): no further call is
            // made, and the callback stays parked until the host ends the
            // process.
            return std::future::pending().await;
        }
        let (number, args) = syscall.into_parts();
        let number = number.id() as i64;
        let mut raw_args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];

        refuse_creation_outside_handler(number, self.in_syscall_handler);
        if is_plain_fork(number, raw_args) {
            let parent_tid = self.tid;
            let parent_pid = self.pid;
            self.prepare_fork_parent_state();
            let result = forward_plain_fork(number, raw_args, None);
            if result == 0 {
                let child_tid = raw_pid(libc::SYS_gettid);
                let child_pid = raw_pid(libc::SYS_getpid);
                self.tail
                    .set_fork_child(parent_tid, parent_pid, child_tid, child_pid);
                return std::future::pending().await;
            }
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }

        if self.admit_threads
            && creation_admission(number, raw_args) == CreationAdmission::ThreadBirth
        {
            let Some(birth) = self.thread_birth else {
                return Err(Errno::EOPNOTSUPP);
            };
            // SAFETY: creation_admission just classified this exact call
            // as an admissible thread shape, and the event is this
            // dispatch's live guest event with its saved context.
            let result = unsafe { (birth.forward)(birth.host, number, raw_args, self.event) };
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }

        // With admission on, a KernelDecides shape is one Linux itself
        // rejects: it is forwarded so the guest sees the kernel's
        // EINVAL, exactly as on dispatch and tail_inject — clone3
        // from a checked copy below, legacy clone (register values
        // only, nothing to race) by the ordinary forward. Every
        // other creation here is the typed refusal.
        let kernel_decides = self.admit_threads
            && creation_admission(number, raw_args) == CreationAdmission::KernelDecides;
        if kernel_decides && number == libc::SYS_clone3 {
            let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
            let result =
                match checked_kernel_decides_clone3(raw_args, self.event.guest_pkru, &mut record) {
                    Ok(copy_args) => {
                        // SAFETY: the copy was classified KernelDecides
                        // above; the kernel reads only the checked copy.
                        unsafe { host_linux::forward(self.tid, number, copy_args) }
                    }
                    Err(result) => result,
                };
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        #[cfg(feature = "exec-native-injection")]
        if (matches!(number, libc::SYS_clone | libc::SYS_clone3)
            || Some(number) == crate::arch::SYS_VFORK)
            && self.native_exec_admitted
        {
            // Admitted route, final-step refusal: admission plumbing is
            // consulted, but no thread is armed yet, so creation still
            // refuses by typed name rather than running unmediated or
            // crashing. Plain forks (including vfork and fork-shaped
            // clone/clone3) never reach this arm: `is_plain_fork`
            // forwards them above, in admitted and unadmitted mode alike.
            self.unsupported_refusal = Some(reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::ThreadCreation,
                Errno::EOPNOTSUPP,
                "the admitted native exec route does not arm thread creation: \
                 clone and clone3 that are not plain forks are refused at the \
                 final step",
            ));
            return Err(Errno::EOPNOTSUPP);
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        if !kernel_decides
            && (number == libc::SYS_clone
                || number == libc::SYS_clone3
                || Some(number) == crate::arch::SYS_VFORK)
        {
            // A typed refusal, so the Tool can tell this from a clone that
            // Linux failed: the in-guest runtime runs one thread of the guest
            // and has no thread or vfork-child creation to forward.
            self.unsupported_refusal = Some(reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::ThreadCreation,
                Errno::EOPNOTSUPP,
                "the in-guest backend cannot create a thread or a vfork child: \
                 clone, clone3 and vfork other than a plain fork are not forwarded",
            ));
            const MESSAGE: &[u8] = b"reverie-liteinst: clone injection requires ptrace fallback\n";
            unsafe {
                let _ = raw_syscall6(
                    libc::SYS_write,
                    [
                        libc::STDERR_FILENO as u64,
                        MESSAGE.as_ptr() as u64,
                        MESSAGE.len() as u64,
                        0,
                        0,
                        0,
                    ],
                );
            }
            return Err(Errno::EOPNOTSUPP);
        }
        #[cfg(feature = "exec-native-injection")]
        if super::native_exec::is_exec(number) {
            let site = self.native_exec_site();
            if let Some(exec) = self.exec.as_mut() {
                let result = exec.inject(
                    (number, raw_args),
                    self.event,
                    &site,
                    &*self.state,
                    self.rpc,
                );
                return match result {
                    Ok(returned) => {
                        // Preserve the real kernel permission effect on errno.
                        // The captured OriginalExec remains immutable authority.
                        self.event.guest_pkru = returned.pkru;
                        Err(returned.errno) // genuine kernel errno, no refusal tag
                    }
                    Err(refusal) => {
                        self.unsupported_refusal = Some(refusal);
                        Err(refusal.errno)
                    }
                };
            }
        }
        if matches!(number, libc::SYS_execve | libc::SYS_execveat) {
            // Admitted native authority first: on a route that never
            // captured it (lifecycle callbacks run before capture), a
            // watched exec refuses by name here instead of forwarding
            // past the admitted route.
            if let Some(refusal) = self.exec_native_priority_refusal() {
                self.unsupported_refusal = Some(refusal);
                return Err(Errno::EOPNOTSUPP);
            }
            if !self.runtime.exec_watch_armed() {
                // A typed refusal, so the Tool can tell this from an exec
                // that Linux failed: without an admitted native exec
                // route or an armed exec watch the in-guest runtime has
                // no way to replace the process image. With a watch
                // armed (and no unreachable native route), execution
                // falls through to the ordinary forward below: success
                // never returns (the watcher re-bootstraps the
                // successor), and failure returns the genuine kernel
                // errno untagged.
                self.unsupported_refusal = Some(reverie::UnsupportedRefusal::new(
                    reverie::UnsupportedOperation::Exec,
                    Errno::EOPNOTSUPP,
                    "the in-guest backend cannot replace the process image: execve and execveat \
                 are not forwarded",
                ));
                return Err(Errno::EOPNOTSUPP);
            }
        }
        #[cfg(feature = "exec-native-injection")]
        self.check_native_mapping(number, raw_args)?;
        self.refuse_filter_while_staging(number, raw_args);
        if let Some(error) =
            injected_syscall_guard(self.runtime, number, raw_args, self.admit_threads)
        {
            return Err(error);
        }
        if let Some(result) = super::restorer::mapping_change_result(number, raw_args) {
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        if let Some(result) =
            unsafe { super::protect::protect_forwarded_descriptor_change(number, raw_args) }
        {
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        if is_exit_syscall(number) {
            self.stage_ending(number, raw_args);
            return std::future::pending().await;
        }
        // A signal to the calling thread or process that would end it as
        // this call returns: staged, and sent once the handler has returned
        // and the Tool has seen its delivery (`deliver_staged_signals`). The
        // call reports what Linux reports for a valid signal to the caller
        // itself, success, and the handler goes on.
        if !guest_filter_admitted()
            && let Some(signal) = unsafe { self_directed_fatal_signal(number, raw_args) }
        {
            if signal == libc::SIGKILL {
                // A SIGKILL ends the guest at once under a tracer: the Tool's
                // callback does not resume, and nothing after it runs. The
                // host runs the exit lifecycle and sends it.
                self.stage_ending(number, raw_args);
                return std::future::pending().await;
            }
            self.stage_signal(StagedSignal {
                number,
                args: raw_args,
                signal,
            });
            return Ok(0);
        }
        if let Some(result) = virtual_signal_call(
            self.runtime,
            self.event.guest_pkru,
            self.event.args,
            number,
            raw_args,
        ) {
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        if let Some(result) = perform_pkey_alloc(self.event, number, raw_args) {
            return Errno::from_ret(result as usize).map(|value| value as i64);
        }
        refuse_mask_installing_forward(self.runtime, ForwardRights::Runtime, number, raw_args);
        let kernel_signal_mask = stripped_signal_mask(self.runtime, number, raw_args)?;
        if let Some(mask) = kernel_signal_mask.as_ref() {
            raw_args[1] = mask as *const u64 as u64;
        }

        // SAFETY: every admission filter above has run on exactly these arguments.
        let result = unsafe { host_linux::forward(self.tid, number, raw_args) };
        Errno::from_ret(result as usize).map(|value| value as i64)
    }

    /// Signal phase 1, step I4: deliver a SIGALRM the Tool has committed (the
    /// ledger entry is already taken) as this fallback syscall completes. Only
    /// a guest SIGALRM handler kept virtual by this runtime can be the target;
    /// everything else keeps the default refusal.
    async fn defer_signal_delivery(&mut self, event: reverie::SignalEvent) -> Result<(), Error> {
        if self.tail.ending() {
            return std::future::pending().await;
        }
        if self.native.is_some() {
            return Err(Errno::ENOSYS.into());
        }
        if !self.delivers_sigalrm(&event) {
            return Err(Errno::ENOSYS.into());
        }
        // SAFETY: inside the guest call's own turn, in its dispatch.
        unsafe { super::sigalrm::prepare_delivery(event, self.runtime.reserved_signal_mask()) }
            .map_err(|errno| Error::Errno(Errno::new(errno)))
    }

    /// Signal phase 1, the I4 addendum's point c: deliver a SIGALRM the Tool
    /// has committed at this fallback syscall's entry; the syscall then runs
    /// from the start once the handler returns.
    async fn defer_signal_delivery_before_syscall(
        &mut self,
        event: reverie::SignalEvent,
    ) -> Result<(), Error> {
        if self.tail.ending() {
            return std::future::pending().await;
        }
        if self.native.is_some() {
            return Err(Errno::ENOSYS.into());
        }
        if !self.delivers_sigalrm(&event) {
            return Err(Errno::ENOSYS.into());
        }
        // SAFETY: inside the guest call's own turn, in its dispatch; the Tool
        // does not run the syscall.
        unsafe {
            super::sigalrm::prepare_delivery_before_syscall(
                event,
                self.runtime.reserved_signal_mask(),
            )
        }
        .map_err(|errno| Error::Errno(Errno::new(errno)))
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        if let Some(native) = &self.native {
            native
                .services
                .invocation()
                .ensure_current()
                .unwrap_or_else(|error| tool_fatal(125, &error.into()));
            let (number, args) = syscall.into_parts();
            let args = [
                args.arg0 as u64,
                args.arg1 as u64,
                args.arg2 as u64,
                args.arg3 as u64,
                args.arg4 as u64,
                args.arg5 as u64,
            ];
            let number = number.id() as i64;
            if !self.in_syscall_handler && is_exit_syscall(number) {
                self.tail.set_exit(number, args);
            } else {
                self.tail.set_deferred_native(number, args);
            }
            // The caller retains the callback lease and its committed storage
            // through native completion, after this future and Guest end.
            return std::future::pending().await;
        }
        self.unsupported_refusal = None;
        if self.tail.ending() {
            // As in `inject`: the guest is ending, so nothing is made.
            return std::future::pending().await;
        }
        let (number, syscall_args) = syscall.into_parts();
        let args = [
            syscall_args.arg0 as u64,
            syscall_args.arg1 as u64,
            syscall_args.arg2 as u64,
            syscall_args.arg3 as u64,
            syscall_args.arg4 as u64,
            syscall_args.arg5 as u64,
        ];
        let tail_number = number;
        let number = number.id() as i64;
        #[cfg(feature = "exec-native-injection")]
        if let Err(error) = self.check_native_mapping(number, args) {
            // Terminal tail return: the parked Tool can never take
            // the stored tag, so it rides on the event.
            self.surface_terminal_refusal();
            self.tail.set_result(-i64::from(error.into_raw()));
            return std::future::pending().await;
        }
        self.refuse_filter_while_staging(number, args);
        refuse_creation_outside_handler(number, self.in_syscall_handler);
        let ends_guest = is_exit_syscall(number)
            || unsafe { self_directed_fatal_signal(number, args) } == Some(libc::SIGKILL);
        if !self.in_syscall_handler && !ends_guest {
            // There is no guest syscall for the call to resolve, and the
            // callback could only stay parked: refused by name, before the
            // call is made.
            tool_fatal(
                125,
                &Error::Tool(
                    io::Error::other(format!(
                        "tail_inject of syscall {number}, a call that does not end the guest, \
                         outside a syscall handler is unsupported"
                    ))
                    .into(),
                ),
            );
        }
        // Scope/filter/native-mapping refusals above produced no admitted tail.
        // Observe before any actual effect and before stage_ending closes the
        // callback's counted output cut. Result guards below are syscall errno
        // outcomes, not a second tail operation.
        reverie::observe_tail_start(self.tid, tail_number);
        if is_plain_fork(number, args) {
            let parent_tid = self.tid;
            let parent_pid = self.pid;
            self.prepare_fork_parent_state();
            let result = forward_plain_fork(number, args, None);
            if result == 0 {
                self.tail.set_fork_child(
                    parent_tid,
                    parent_pid,
                    raw_pid(libc::SYS_gettid),
                    raw_pid(libc::SYS_getpid),
                );
            } else {
                self.tail.set_result(result);
            }
        } else if matches!(number, libc::SYS_execve | libc::SYS_execveat)
            && let Some(refusal) = self.exec_tail_native_refusal()
        {
            // A tail call has no native cut of its own; with the
            // native route admitted it refuses by name in every
            // capture state rather than forwarding past (or
            // re-spending) the admitted route. The name rides on the event, whose
            // terminal result this refusal is; the parked Tool
            // continuation can never take it from the guest view.
            // Unwatched, the guard below refuses.
            self.event.unsupported_refusal = Some(refusal);
            self.tail
                .set_result(-i64::from(Errno::EOPNOTSUPP.into_raw()));
        } else if self.admit_threads
            && creation_admission(number, args) == CreationAdmission::ThreadBirth
        {
            // Tail-injected admitted creations run the same birth
            // trampoline as every other admitted path (W7 review);
            // the plain forward below must never execute one raw.
            match self.thread_birth {
                Some(birth) => {
                    // SAFETY: classified ThreadBirth just above; the
                    // event is this dispatch's live guest event.
                    let result = unsafe { (birth.forward)(birth.host, number, args, self.event) };
                    self.tail.set_result(result);
                }
                None => self.tail.set_result(-i64::from(libc::EOPNOTSUPP)),
            }
        } else if number == libc::SYS_clone3
            && self.admit_threads
            && creation_admission(number, args) == CreationAdmission::KernelDecides
        {
            // Deferred to the kernel from a checked copy, as on
            // dispatch and inject: the plain forward below must
            // never hand the kernel the guest's own record pointer.
            let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
            let result =
                match checked_kernel_decides_clone3(args, self.event.guest_pkru, &mut record) {
                    Ok(copy_args) => {
                        // SAFETY: the copy was classified KernelDecides
                        // above; the kernel reads only the checked copy.
                        unsafe { host_linux::forward(self.tid, number, copy_args) }
                    }
                    Err(result) => result,
                };
            self.tail.set_result(result);
        } else if let Some(error) =
            injected_syscall_guard(self.runtime, number, args, self.admit_threads)
        {
            self.tail.set_result(-i64::from(error.into_raw()));
        } else if let Some(result) = super::restorer::mapping_change_result(number, args) {
            self.tail.set_result(result);
        } else if let Some(result) =
            unsafe { super::protect::protect_forwarded_descriptor_change(number, args) }
        {
            self.tail.set_result(result);
        } else if is_exit_syscall(number) {
            self.stage_ending(number, args);
        } else if !guest_filter_admitted()
            && let Some(signal) = unsafe { self_directed_fatal_signal(number, args) }
        {
            if signal == libc::SIGKILL {
                // As in `inject`: the guest ends here.
                self.stage_ending(number, args);
            } else {
                // Staged as in `inject`; the guest's call returns 0.
                self.stage_signal(StagedSignal {
                    number,
                    args,
                    signal,
                });
                self.tail.set_result(0);
            }
        } else if let Some(result) = virtual_signal_call(
            self.runtime,
            self.event.guest_pkru,
            self.event.args,
            number,
            args,
        ) {
            self.tail.set_result(result);
        } else if let Some(result) = perform_pkey_alloc(self.event, number, args) {
            self.tail.set_result(result);
        } else {
            refuse_mask_installing_forward(self.runtime, ForwardRights::Runtime, number, args);
            let value = match stripped_signal_mask(self.runtime, number, args) {
                Err(error) => -i64::from(error.into_raw()),
                // SAFETY: every admission filter above has run on exactly these arguments.
                Ok(None) => unsafe { host_linux::forward(self.tid, number, args) },
                Ok(Some(mask)) => {
                    let mut args = args;
                    args[1] = (&raw const mask) as u64;
                    // SAFETY: as above, with the reserved signals stripped.
                    unsafe { host_linux::forward(self.tid, number, args) }
                }
            };
            self.tail.set_result(value);
        }
        std::future::pending().await
    }

    // TODO-HUMAN-REVIEW(PR-326): Review the coarse
    // syscall-boundary clock until the minimal ptrace supervisor wires PMU delivery.
    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        // Nothing in the guest arms an RCB threshold or dispatches
        // `Tool::handle_timer_event`. Accepting the request would let a Tool
        // believe a CPU-bound thread is bounded while it runs unpreempted to
        // its next syscall, so refuse, as reverie-dbt does, and let a Tool
        // that needs preemption fail closed. Clock reads still work.
        Err(Errno::ENOSYS.into())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        // Same refusal as set_timer; never synthesize host time.
        Err(Errno::ENOSYS.into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        match &self.native {
            Some(native) => Ok(native.services.facts().branches),
            None => self.runtime.read_clock().map_err(Error::from),
        }
    }

    fn backtrace(&mut self) -> Option<reverie::Backtrace> {
        // Preserve the local default (no in-process unwind) and the native
        // owner's bounded, fault-safe saved-frame-pointer walk.
        let native = self.native.as_ref()?;
        let regs = native.services.regs().ok()?;
        let mut frames = vec![reverie::Frame {
            ip: NativeIsa::user_regs_instruction_pointer(&regs),
            is_signal: false,
        }];
        let mut fp = NativeIsa::user_regs_frame_pointer(&regs);
        while frames.len() < 256 {
            if fp == 0 || !fp.is_multiple_of(std::mem::align_of::<u64>() as u64) {
                break;
            }
            let Some(saved_fp) = native.services.read_word(fp) else {
                break;
            };
            let Some(return_addr) = native.services.read_word(fp.wrapping_add(8)) else {
                break;
            };
            if return_addr == 0 {
                break;
            }
            frames.push(reverie::Frame {
                ip: return_addr,
                is_signal: false,
            });
            if saved_fp <= fp {
                break;
            }
            fp = saved_fp;
        }
        Some(reverie::Backtrace::new(self.tid, frames))
    }

    fn has_cpuid_interception(&self) -> bool {
        self.cpuid_interception
    }
}

pub struct LocalStack {
    arena: Box<[u8]>,
    offset: usize,
    callback_scratch: Option<native_state::CallbackScratch>,
}

impl LocalStack {
    fn new() -> Self {
        Self {
            arena: vec![0; STACK_CAPACITY].into_boxed_slice(),
            offset: 0,
            callback_scratch: None,
        }
    }

    fn with_callback_scratch(scratch: native_state::CallbackScratch) -> Self {
        let mut stack = Self::new();
        stack.callback_scratch = Some(scratch);
        stack
    }

    /// Claims the next `size_of::<V>()` bytes aligned for `V` and returns
    /// their address. Nothing is written to them.
    fn claim<V>(&mut self) -> *mut V {
        let align = core::mem::align_of::<V>();
        let base = self.arena.as_ptr() as usize;
        let start = (base + self.offset + align - 1) & !(align - 1);
        let offset = start - base;
        let end = offset + core::mem::size_of::<V>();
        assert!(end <= self.arena.len(), "LiteInst guest stack overflow");
        let pointer = unsafe { self.arena.as_mut_ptr().add(offset).cast::<V>() };
        self.offset = end;
        pointer
    }

    fn allocate<'stack, V>(&mut self, value: V) -> AddrMut<'stack, V> {
        let pointer = self.claim::<V>();
        unsafe { pointer.write(value) };
        AddrMut::from_raw(pointer as usize).expect("LiteInst stack produced a null address")
    }
}

pub struct LocalStackGuard {
    arena: Option<Box<[u8]>>,
    callback_scratch: Option<native_state::CallbackScratch>,
}

impl Drop for LocalStackGuard {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            if let Some(scratch) = &self.callback_scratch {
                scratch.retain(arena);
            } else {
                retain_committed_stack(arena);
            }
        }
    }
}

impl Stack for LocalStack {
    type StackGuard = LocalStackGuard;

    fn size(&self) -> usize {
        self.offset
    }

    fn capacity(&self) -> usize {
        self.arena.len()
    }

    fn push<'stack, V>(&mut self, value: V) -> Addr<'stack, V> {
        self.allocate(value).into()
    }

    fn reserve<'stack, V>(&mut self) -> AddrMut<'stack, V> {
        // Zero the bytes without making a `V`: all zeros is not a valid value
        // of every type (a reference or a NonZeroU64, for instance).
        let pointer = self.claim::<V>();
        unsafe {
            pointer
                .cast::<u8>()
                .write_bytes(0, core::mem::size_of::<V>())
        };
        AddrMut::from_raw(pointer as usize).expect("LiteInst stack produced a null address")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(LocalStackGuard {
            arena: Some(self.arena),
            callback_scratch: self.callback_scratch,
        })
    }
}

/// Describes a Reverie error without the C library's errno messages (see
/// [`crate::guest::support::describe_io_error`]): an I/O error, alone or in a
/// Tool error's chain of causes, by its kind and number; an errno by its name
/// and description (the `syscalls` crate's own table); anything else by its
/// `Display`.
pub fn describe_reverie_error(error: &Error) -> String {
    use crate::guest::support::describe_io_error;
    match error {
        Error::Io(inner) => describe_io_error(inner),
        Error::Errno(errno) => errno.to_string(),
        Error::Tool(tool) => tool
            .chain()
            .map(|cause| match cause.downcast_ref::<std::io::Error>() {
                Some(inner) => describe_io_error(inner),
                None => cause.to_string(),
            })
            .collect::<Vec<_>>()
            .join(": "),
    }
}

fn tool_fatal(status: i32, error: &Error) -> ! {
    let message = format!(
        "reverie-liteinst tool error: {}\n",
        describe_reverie_error(error)
    );
    unsafe {
        let _ = raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                message.as_ptr() as u64,
                message.len() as u64,
                0,
                0,
                0,
            ],
        );
    }
    fatal(status)
}

fn fatal(status: i32) -> ! {
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
#[path = "tool_configuration_tests.rs"]
mod tool_configuration_tests;

#[cfg(test)]
#[path = "native_state_tests.rs"]
mod native_state_tests;

#[cfg(test)]
#[path = "ordinary_root_tests.rs"]
mod ordinary_root_tests;

#[cfg(test)]
mod process_owner_tests {
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    use super::*;

    static EVENTS: Mutex<Vec<(&str, i32)>> = Mutex::new(Vec::new());
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    /// When set, the getpid handler rendezvouses on this barrier, so two
    /// dispatches must be inside the Tool at once for either to proceed.
    static RENDEZVOUS: Mutex<Option<std::sync::Arc<std::sync::Barrier>>> = Mutex::new(None);
    /// When set, Probe's thread-start ends the newborn thread.
    static END_ON_START: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    /// Dispatch depth the Probe's on_exit_thread observed.
    static EXIT_SEEN_DEPTH: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(usize::MAX);
    /// The ToolHost address whose dispatch counter on_exit_thread
    /// samples (the ending-birth test installs it before the birth).
    static EXIT_HOST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// Whether on_exit_thread observed the host dispatch-active.
    static EXIT_SEEN_ACTIVE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    struct Remote;
    impl Default for Remote {
        fn default() -> Self {
            panic!("test requires a remote global owner")
        }
    }
    #[reverie::global_tool]
    impl GlobalTool for Remote {
        type Config = (u64, bool, bool);
        type Request = ();
        type Response = ();
        async fn receive_rpc(&self, _: Pid, _: ()) {
            panic!("test must not construct a local global owner")
        }
    }

    #[derive(Default, serde::Serialize, serde::Deserialize)]
    struct State {
        pid: i32,
        tid: i32,
        attempts: u32,
    }
    impl Drop for State {
        fn drop(&mut self) {
            EVENTS.lock().unwrap().push(("state-drop", self.tid));
        }
    }

    #[derive(Default)]
    struct Probe {
        pid: i32,
        abandon: bool,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            EVENTS.lock().unwrap().push(("tool-drop", self.pid));
        }
    }
    struct Attempt(u32);
    impl Drop for Attempt {
        fn drop(&mut self) {
            EVENTS.lock().unwrap().push(("attempt-drop", self.0 as i32));
        }
    }
    #[reverie::tool]
    impl Tool for Probe {
        type GlobalState = Remote;
        type ThreadState = State;
        fn subscriptions(config: &<Remote as GlobalTool>::Config) -> reverie::Subscription {
            assert_eq!(config.0, 71);
            EVENTS.lock().unwrap().push(("select", 0));
            let mut subscription =
                reverie::Subscription::from_iter([Sysno::write, Sysno::getpid, Sysno::getppid]);
            if config.1 {
                subscription.syscall(Sysno::clone);
            }
            subscription
        }
        fn new(pid: Pid, config: &<Remote as GlobalTool>::Config) -> Self {
            assert_eq!(pid, raw_pid(libc::SYS_getpid));
            assert_eq!(config.0, 71);
            EVENTS.lock().unwrap().push(("new", pid.as_raw()));
            Self {
                pid: pid.as_raw(),
                abandon: config.2,
            }
        }
        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &State)>) -> State {
            assert_eq!(tid, raw_pid(libc::SYS_gettid));
            if let Some((parent_tid, snapshot)) = parent {
                assert_eq!(parent_tid.as_raw(), snapshot.tid);
                assert_ne!(snapshot.pid, self.pid);
            }
            EVENTS.lock().unwrap().push(("init", tid.as_raw()));
            State {
                pid: self.pid,
                tid: tid.as_raw(),
                attempts: 0,
            }
        }
        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            assert_eq!(guest.pid().as_raw(), self.pid);
            assert_eq!(guest.tid().as_raw(), guest.thread_state().tid);
            EVENTS.lock().unwrap().push(("start", guest.tid().as_raw()));
            if END_ON_START.load(std::sync::atomic::Ordering::Acquire) {
                // End this thread from its own start callback: the
                // injected exit stages the ending the birth path
                // must finish still on the birth stack.
                let _ = guest.inject(reverie::syscalls::Exit::default()).await;
            }
            Ok(())
        }
        async fn on_exit_thread<G: GlobalRPC<Remote>>(
            &self,
            _tid: reverie::Tid,
            _global_state: &G,
            _thread_state: State,
            _exit_status: reverie::ExitStatus,
        ) -> Result<(), Error> {
            EXIT_SEEN_DEPTH.store(
                super::super::alloc::dispatch_depth_for_test(),
                std::sync::atomic::Ordering::Release,
            );
            let host_addr = EXIT_HOST.load(std::sync::atomic::Ordering::Acquire);
            if host_addr != 0 {
                // SAFETY: the ending-birth test installs its live
                // host's address for exactly this read and clears
                // it before the host drops.
                let host = unsafe { &*(host_addr as *const ToolHost<Probe, Runtime>) };
                EXIT_SEEN_ACTIVE
                    .store(host.dispatch_active(), std::sync::atomic::Ordering::Release);
            }
            Ok(())
        }
        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            call: Syscall,
        ) -> Result<i64, Error> {
            if call.number() == Sysno::getpid {
                let rendezvous = RENDEZVOUS.lock().unwrap().clone();
                if let Some(barrier) = &rendezvous {
                    barrier.wait();
                }
                assert_eq!(guest.config().0, 71);
                assert_eq!(guest.thread_state().pid, self.pid);
                guest.thread_state_mut().attempts += 1;
                let attempt = Attempt(guest.thread_state().attempts);
                // The attempt-drop ordering is a single-dispatch contract;
                // concurrent dispatches interleave attempts by design.
                if attempt.0 == 2 && rendezvous.is_none() {
                    assert_eq!(EVENTS.lock().unwrap().last(), Some(&("attempt-drop", 1)));
                }
                EVENTS.lock().unwrap().push(("attempt", attempt.0 as i32));
                return if attempt.0 == 1 {
                    Err(Errno::ERESTARTSYS.into())
                } else {
                    Ok(71)
                };
            }
            if call.number() == Sysno::getppid {
                return Err(Errno::EACCES.into());
            }
            if self.abandon {
                use core::future::Future;
                let mut tail = core::pin::pin!(guest.tail_inject(call));
                core::future::poll_fn(|cx| {
                    assert!(tail.as_mut().poll(cx).is_pending());
                    core::task::Poll::Ready(())
                })
                .await;
                Ok(71)
            } else {
                guest.tail_inject(call).await
            }
        }
    }

    struct Runtime;
    impl HostRuntime for Runtime {
        fn fork_child_rebind(&self) {
            EVENTS
                .lock()
                .unwrap()
                .push(("rebind", raw_pid(libc::SYS_getpid).as_raw()));
        }
        fn emit_stage(&self, stage: &[u8]) {
            let name = match stage {
                b"fork-child-thread-start-begin" => "begin",
                b"fork-child-thread-start-complete" => "complete",
                _ => panic!("unexpected fork stage"),
            };
            EVENTS
                .lock()
                .unwrap()
                .push((name, raw_pid(libc::SYS_gettid).as_raw()));
        }
        fn fork_child_reset(&self, _: &SyscallEvent) {
            EVENTS
                .lock()
                .unwrap()
                .push(("reset", raw_pid(libc::SYS_getpid).as_raw()));
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
        fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
            super::super::signal::signal_action_supported(number, args)
        }
        fn reserved_signal_mask(&self) -> u64 {
            0
        }
    }

    fn coordinator(selected_fork: bool, abandon: bool) -> (CoordinatorRpc<Remote>, UnixStream) {
        let (client, mut peer) = UnixStream::pair().unwrap();
        let config =
            reverie_rpc_transport::codec::encode(&(71_u64, selected_fork, abandon)).unwrap();
        peer.write_all(&(config.len() as u32).to_be_bytes())
            .unwrap();
        peer.write_all(&config).unwrap();
        let tid = raw_pid(libc::SYS_gettid);
        let client = reverie_rpc_transport::BlockingRpcClient::from_connected_stream(
            super::super::rpc::GuestRpcStream::from(client),
            tid,
        )
        .unwrap();
        let rpc = CoordinatorRpc::from_live_client("unused-process-owner-test", client, |_, _| {
            panic!("test hooks must not request reconnection")
        })
        .unwrap();
        (rpc, peer)
    }

    fn host(selected_fork: bool, abandon: bool) -> (ToolHost<Probe, Runtime>, UnixStream) {
        let (rpc, peer) = coordinator(selected_fork, abandon);
        let pid = raw_pid(libc::SYS_getpid);
        let selected = ToolConfiguration::<Probe>::select(rpc.shared_config());
        let subscriptions = selected.subscriptions().iter_syscalls().collect();
        let tool = selected.new_process(pid);
        (
            ToolHost::with_configuration(tool, rpc, pid, selected, subscriptions, Runtime),
            peer,
        )
    }

    fn event(number: i64, args: [u64; 6]) -> SyscallEvent {
        SyscallEvent {
            number,
            args,
            instruction_pointer: 0,
            result: -1,
            context: 0,
            dispatch: SyscallDispatch::InstalledHook,
            guest_pkru: None,
            unsupported_refusal: None,
        }
    }

    #[test]
    fn actual_owner_dispatch_executes_completed_tail_once_even_when_abandoned() {
        let _test = TEST_LOCK.lock().unwrap();
        for abandon in [false, true] {
            let (host, _peer) = host(false, abandon);
            let (writer, mut reader) = UnixStream::pair().unwrap();
            reader
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let byte = [0x5a_u8];
            let mut call = event(
                libc::SYS_write,
                [writer.as_raw_fd() as u64, byte.as_ptr() as u64, 1, 0, 0, 0],
            );
            // SAFETY: these are this thread's live syscall operands and buffer.
            unsafe { host.dispatch(&mut call) };
            assert_eq!(call.result, if abandon { 71 } else { 1 });
            drop(writer);
            let mut written = Vec::new();
            reader.read_to_end(&mut written).unwrap();
            assert_eq!(
                written, byte,
                "a completed tail must never be forwarded again"
            );
        }
    }

    /// The thread-admission taxonomy: every creation shape lands in
    /// exactly one class, with plain fork's meaning unchanged. The
    /// classes track Linux's own rules (THREAD ⇒ SIGHAND ⇒ VM): every
    /// shape the kernel would turn into a real thread is ThreadBirth
    /// or a named refusal, and only shapes the kernel itself rejects
    /// defer to its EINVAL.
    #[test]
    fn creation_admission_taxonomy() {
        const REQUIRED: u64 = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD) as u64;
        assert_eq!(
            thread_flags_admission(REQUIRED),
            CreationAdmission::ThreadBirth
        );
        assert_eq!(
            thread_flags_admission(REQUIRED | libc::CLONE_SETTLS as u64),
            CreationAdmission::ThreadBirth
        );
        // No FS/FILES sharing: still a real thread on Linux.
        assert_eq!(
            thread_flags_admission(
                (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64
            ),
            CreationAdmission::ThreadBirth
        );
        assert_eq!(
            thread_flags_admission(REQUIRED & !(libc::CLONE_VM as u64)),
            CreationAdmission::KernelDecides
        );
        assert_eq!(
            thread_flags_admission(REQUIRED & !(libc::CLONE_SIGHAND as u64)),
            CreationAdmission::KernelDecides
        );
        assert_eq!(
            thread_flags_admission(REQUIRED | libc::CLONE_NEWNS as u64),
            CreationAdmission::Unsupported
        );
        assert_eq!(
            thread_flags_admission(REQUIRED | libc::CLONE_PIDFD as u64),
            CreationAdmission::Unsupported
        );
        assert_eq!(
            thread_flags_admission(libc::CLONE_VM as u64),
            CreationAdmission::Unsupported,
            "shared-VM process without CLONE_THREAD stays unsupported"
        );
        // clone_args: set_tid / cgroup stay unsupported; an exit
        // signal or a half-given stack on a thread defers to the
        // kernel's EINVAL; no stack at all is a real thread.
        let mut fields = [0_u64; 11];
        fields[0] = REQUIRED;
        fields[5] = 0x1000;
        fields[6] = 0x8000;
        assert_eq!(
            clone_args_thread_admission(&fields),
            CreationAdmission::ThreadBirth
        );
        fields[5] = 0;
        fields[6] = 0;
        assert_eq!(
            clone_args_thread_admission(&fields),
            CreationAdmission::ThreadBirth,
            "stack-less clone3 thread returns on the parent's stack"
        );
        fields[6] = 0x8000;
        assert_eq!(
            clone_args_thread_admission(&fields),
            CreationAdmission::KernelDecides,
            "stack_size without stack is the kernel's EINVAL"
        );
        fields[5] = 0x1000;
        fields[6] = 0;
        assert_eq!(
            clone_args_thread_admission(&fields),
            CreationAdmission::KernelDecides,
            "stack without stack_size is the kernel's EINVAL"
        );
        fields[6] = 0x8000;
        fields[8] = 1;
        assert_eq!(
            clone_args_thread_admission(&fields),
            CreationAdmission::Unsupported
        );
        fields[8] = 0;
        fields[4] = libc::SIGCHLD as u64;
        assert_eq!(
            clone_args_thread_admission(&fields),
            CreationAdmission::KernelDecides,
            "a thread exit signal is the kernel's EINVAL"
        );
    }

    // The born thread's whole guest program: write its own tid to the
    // pointer in rdi, then exit. It runs on the guest stack the birth
    // resume installs, after admission has already run on the birth
    // stack, and must touch nothing else (no Rust runtime, no TLS).
    // x86_64 only, like the birth trampoline it exercises.
    #[cfg(target_arch = "x86_64")]
    core::arch::global_asm!(
        r#"
        .text
        .p2align 4
        .global w7_birth_stub
        .hidden w7_birth_stub
        .type w7_birth_stub,@function
    w7_birth_stub:
        endbr64
        mov rax, 186
        syscall
        mov [rdi], rax
        mov rax, 60
        xor edi, edi
        syscall
        ud2
        .size w7_birth_stub, .-w7_birth_stub
    "#
    );

    /// Raw clone syscall for tail-inject tests (typed Clone needs the
    /// nix sched type this crate does not depend on in tests).
    #[cfg(target_arch = "x86_64")]
    #[derive(Copy, Clone)]
    struct RawClone([u64; 6]);

    #[cfg(target_arch = "x86_64")]
    impl reverie::syscalls::Displayable for RawClone {
        fn fmt<M: reverie::syscalls::MemoryAccess>(
            &self,
            _memory: &M,
            _outputs: bool,
            f: &mut core::fmt::Formatter,
        ) -> core::fmt::Result {
            write!(f, "clone({:#x}, {:#x})", self.0[0], self.0[1])
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl reverie::syscalls::SyscallInfo for RawClone {
        type Return = Result<i64, Errno>;

        fn name(&self) -> &'static str {
            "clone"
        }

        fn number(&self) -> reverie::syscalls::Sysno {
            reverie::syscalls::Sysno::clone
        }

        fn into_parts(self) -> (reverie::syscalls::Sysno, reverie::syscalls::SyscallArgs) {
            (
                reverie::syscalls::Sysno::clone,
                reverie::syscalls::SyscallArgs::new(
                    self.0[0] as usize,
                    self.0[1] as usize,
                    self.0[2] as usize,
                    self.0[3] as usize,
                    self.0[4] as usize,
                    self.0[5] as usize,
                ),
            )
        }
    }

    /// A default-Tool tail_inject of an admitted thread creation runs
    /// the same birth trampoline (and checklist) as dispatch and inject
    /// (W7 review): the tail result is the child tid, the child was
    /// admitted (thread-start observed), and its stub ran.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn tail_injected_thread_creation_runs_birth_checklist() {
        let _test = TEST_LOCK.lock().unwrap();
        let (mut host, _peer) = host(false, false);
        host.set_thread_admission(true);
        static TAIL_SEEN: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
        TAIL_SEEN.store(0, core::sync::atomic::Ordering::Release);
        EVENTS.lock().unwrap().clear();
        let guest_stack_len = 64 * 1024usize;
        let guest_stack = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                guest_stack_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(guest_stack, libc::MAP_FAILED);
        let stack_top = guest_stack as u64 + guest_stack_len as u64;
        unsafe extern "C" {
            fn w7_birth_stub();
        }
        let mut saved = RegisterContext::default();
        saved.rdi = core::ptr::addr_of!(TAIL_SEEN) as u64;
        let root_tid = raw_pid(libc::SYS_gettid);
        let pid = raw_pid(libc::SYS_getpid);
        let mut event = SyscallEvent {
            number: libc::SYS_getpid,
            args: [0; 6],
            instruction_pointer: w7_birth_stub as *const () as usize as u64,
            result: 0,
            context: &raw const saved as usize,
            dispatch: SyscallDispatch::Trap,
            guest_pkru: None,
            unsupported_refusal: None,
        };
        let tail = TailResult::default();
        let mut state = State {
            pid: pid.as_raw(),
            tid: root_tid.as_raw(),
            attempts: 0,
        };
        let mut guest = InGuest::<Probe, Runtime> {
            event: &mut event,
            tid: root_tid,
            pid,
            ppid: None,
            state: &mut state,
            rpc: &host.rpc,
            native: None,
            tail: &tail,
            cpuid_interception: false,
            admit_threads: true,
            thread_birth: host.thread_birth_ops(),
            fork_parent_state: None,
            runtime: &host.runtime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: true,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: None,
            #[cfg(feature = "exec-native-injection")]
            native_exec_admitted: host.native_exec_admitted(),
            #[cfg(feature = "exec-native-injection")]
            native_exec_route_active: host.native_exec_admitted(),
            unsupported_refusal: None,
            injected_syscalls: 0,
        };
        let flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM) as u64;
        let call = RawClone([flags, stack_top, 0, 0, 0, 0]);
        let mut tail_future = core::pin::pin!(guest.tail_inject(call));
        // tail_inject parks once it has stored the result.
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(matches!(
            tail_future.as_mut().poll(&mut context),
            core::task::Poll::Pending
        ));
        let result = match crate::tool_host::drive_syscall(
            std::future::pending::<Result<i64, Error>>(),
            &tail,
        ) {
            crate::tool_host::SyscallOutcome::Return(result) => {
                result.expect("tail thread creation failed")
            }
            _ => panic!("tail_inject did not park a result"),
        };
        assert!(result > 0, "child tid {result}");
        let child_tid = result as i32;
        let mut seen = 0;
        for _ in 0..500 {
            seen = TAIL_SEEN.load(core::sync::atomic::Ordering::Acquire);
            if seen != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(seen, i64::from(child_tid), "born thread ran its guest stub");
        assert!(
            EVENTS
                .lock()
                .unwrap()
                .iter()
                .any(|(name, _)| *name == "start"),
            "birth checklist ran thread-start for the tail-injected creation"
        );
        assert!(host.states.contains(child_tid));
        unsafe { libc::munmap(guest_stack, guest_stack_len) };
    }

    /// Physical thread birth end to end: a real clone through the birth
    /// trampoline. The child is admitted (lease + thread-start) on its
    /// birth stack, then resumes at the stub above on its guest stack,
    /// records its tid, and exits — all inside this test process.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn physical_thread_birth_admits_and_resumes() {
        let _test = TEST_LOCK.lock().unwrap();
        let (mut host, _peer) = host(false, false);
        host.set_thread_admission(true);
        static SEEN: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
        SEEN.store(0, core::sync::atomic::Ordering::Release);
        EVENTS.lock().unwrap().clear();
        // Guest stack for the child (its clone stack argument).
        let guest_stack_len = 64 * 1024usize;
        let guest_stack = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                guest_stack_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(guest_stack, libc::MAP_FAILED);
        let stack_top = guest_stack as u64 + guest_stack_len as u64;
        unsafe extern "C" {
            fn w7_birth_stub();
        }
        let mut saved = RegisterContext::default();
        saved.rdi = core::ptr::addr_of!(SEEN) as u64;
        let flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM) as u64;
        let args = [flags, stack_top, 0, 0, 0, 0];
        assert_eq!(
            creation_admission(libc::SYS_clone, args),
            CreationAdmission::ThreadBirth
        );
        let event = SyscallEvent {
            number: libc::SYS_clone,
            args,
            instruction_pointer: w7_birth_stub as *const () as usize as u64,
            result: 0,
            context: &raw const saved as usize,
            dispatch: SyscallDispatch::Trap,
            guest_pkru: None,
            unsupported_refusal: None,
        };
        // This shape has no CLONE_SETTLS, so the newborn's admission
        // runs on THIS thread's TLS: it must leave the parent's
        // dispatch depth and committed arenas exactly as they were
        // (a leaked birth scope once raised the depth and cleared
        // the arenas here).
        retain_committed_stack(vec![0_u8; 64].into_boxed_slice());
        let parent_depth = super::super::alloc::dispatch_depth_for_test();
        let parent_committed = COMMITTED_STACKS.with(|stacks| stacks.borrow().len());
        // SAFETY: host/event as constructed above; the child resumes at
        // the stub with SEEN's address in rdi and exits by raw syscall.
        let child_tid = unsafe {
            forward_thread_creation::<Probe, Runtime>(
                core::ptr::from_ref(&host) as usize,
                libc::SYS_clone,
                args,
                &event,
            )
        };
        assert!(child_tid > 0, "clone failed with {child_tid}");
        // The child writes its own tid before exiting; poll briefly.
        let mut seen = 0;
        for _ in 0..500 {
            seen = SEEN.load(core::sync::atomic::Ordering::Acquire);
            if seen != 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(seen, child_tid, "born thread ran its guest stub");
        assert_eq!(
            super::super::alloc::dispatch_depth_for_test(),
            parent_depth,
            "birth admission on the parent's TLS must restore its depth"
        );
        assert_eq!(
            COMMITTED_STACKS.with(|stacks| stacks.borrow().len()),
            parent_committed,
            "birth admission must not clear the parent's committed arenas"
        );
        // Admission ran on the child: a lease exists for its tid and the
        // birth stack is registered for retire-time release.
        assert!(host.states.contains(child_tid as i32));
        assert!(host.birth_stacks.lock().contains_key(&(child_tid as i32)));
        assert!(
            EVENTS
                .lock()
                .unwrap()
                .iter()
                .any(|(name, _)| *name == "start"),
            "thread_start callback ran for the born thread"
        );
        unsafe { libc::munmap(guest_stack, guest_stack_len) };
    }

    /// A birth whose own thread-start callback ends the thread:
    /// the Ending path finishes still standing on the birth stack.
    /// The parent must observe: the process survives, the exit
    /// callback ran counted and in scope (depth > 0,
    /// dispatch_active), the counters are back at baseline after
    /// the newborn is gone, the parent's committed arenas are
    /// untouched, and no birth-stack entry remains (the mapping
    /// itself is deliberately leaked — unmapping the stack in use
    /// is the SIGSEGV this guards against). Runs no-SETTLS first
    /// (admission on the parent's TLS), then with CLONE_SETTLS
    /// onto a copied FS page.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn birth_ending_on_start_restores_parent_dispatch_state() {
        let _test = TEST_LOCK.lock().unwrap();
        for settls in [false, true] {
            let (mut host, _peer) = host(false, false);
            host.set_thread_admission(true);
            static END_SEEN: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
            END_SEEN.store(0, core::sync::atomic::Ordering::Release);
            EVENTS.lock().unwrap().clear();
            EXIT_SEEN_DEPTH.store(usize::MAX, std::sync::atomic::Ordering::Release);
            EXIT_SEEN_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
            EXIT_HOST.store(
                core::ptr::from_ref(&host) as usize,
                std::sync::atomic::Ordering::Release,
            );
            END_ON_START.store(true, std::sync::atomic::Ordering::Release);
            let guest_stack_len = 64 * 1024usize;
            let guest_stack = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    guest_stack_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(guest_stack, libc::MAP_FAILED);
            let stack_top = guest_stack as u64 + guest_stack_len as u64;
            // For SETTLS: a private FS page copied from the
            // parent's, with its self-pointer retargeted. The DTV
            // still aliases the parent's module blocks (only the
            // depth/active invariants are under test, and those
            // read the cells either way).
            let tls_page = if settls {
                // x86_64 TLS variant II: variables live BELOW the
                // FS base (the TCB head), so copy the block on
                // both sides of a retargeted self-pointer.
                let span = 64 * 1024usize;
                let tls = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        span * 2,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(tls, libc::MAP_FAILED);
                let mut fs_base: u64 = 0;
                // SAFETY: ARCH_GET_FS writes the FS base to fs_base.
                let got = unsafe {
                    libc::syscall(libc::SYS_arch_prctl, 0x1003_i64, &mut fs_base as *mut u64)
                };
                assert_eq!(got, 0, "ARCH_GET_FS failed");
                // Clip both sides to the mappings that actually
                // contain them: the thread-stack mapping ends only
                // ~2.5 KiB above fs_base, so copying a full span
                // upward reads into the next mapping (or a guard
                // page) and segfaults beside sibling tests.
                let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
                let clip = |addr: u64, want: usize, upward: bool| -> usize {
                    for line in maps.lines() {
                        let mut parts = line.split(['-', ' ']);
                        let Ok(start) = u64::from_str_radix(parts.next().unwrap_or(""), 16) else {
                            continue;
                        };
                        let Ok(end) = u64::from_str_radix(parts.next().unwrap_or(""), 16) else {
                            continue;
                        };
                        if upward && addr >= start && addr < end {
                            return want.min((end - addr) as usize);
                        }
                        if !upward && addr > start && addr <= end {
                            return want.min((addr - start) as usize);
                        }
                    }
                    0
                };
                let below = clip(fs_base, span, false);
                assert!(below > 0, "FS mapping not found below fs_base");
                let above = clip(fs_base, span, true);
                assert!(above > 0, "FS mapping not found above fs_base");
                // SAFETY: both sides are clipped to their mappings;
                // the copy is this test's private span, placed so
                // the new base sits at the same offsets.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (fs_base as *const u8).sub(below),
                        (tls as *mut u8).add(span - below),
                        below + above,
                    );
                    let new_base = (tls as u64) + span as u64;
                    (new_base as *mut u64).write(new_base);
                    new_base
                }
            } else {
                0
            };
            retain_committed_stack(vec![0_u8; 64].into_boxed_slice());
            let parent_depth = super::super::alloc::dispatch_depth_for_test();
            let parent_committed = COMMITTED_STACKS.with(|stacks| stacks.borrow().len());
            unsafe extern "C" {
                fn w7_birth_stub();
            }
            let mut saved = RegisterContext::default();
            saved.rdi = core::ptr::addr_of!(END_SEEN) as u64;
            let mut flags = (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD
                | libc::CLONE_SYSVSEM) as u64;
            if settls {
                flags |= libc::CLONE_SETTLS as u64;
            }
            let args = [flags, stack_top, 0, 0, tls_page, 0];
            assert_eq!(
                creation_admission(libc::SYS_clone, args),
                CreationAdmission::ThreadBirth
            );
            let event = SyscallEvent {
                number: libc::SYS_clone,
                args,
                instruction_pointer: w7_birth_stub as *const () as usize as u64,
                result: 0,
                context: &raw const saved as usize,
                dispatch: SyscallDispatch::Trap,
                guest_pkru: None,
                unsupported_refusal: None,
            };
            // SAFETY: host/event as constructed; the newborn's
            // start callback ends it before any guest resume.
            let child_tid = unsafe {
                forward_thread_creation::<Probe, Runtime>(
                    core::ptr::from_ref(&host) as usize,
                    libc::SYS_clone,
                    args,
                    &event,
                )
            };
            assert!(child_tid > 0, "clone failed with {child_tid}");
            // The newborn ends itself during admission; poll until
            // its state slot and birth-stack entry are gone.
            let child_tid = child_tid as i32;
            let mut finished = false;
            for _ in 0..500 {
                if !host.states.contains(child_tid)
                    && !host.birth_stacks.lock().contains_key(&child_tid)
                    && EXIT_SEEN_DEPTH.load(std::sync::atomic::Ordering::Acquire) != usize::MAX
                {
                    finished = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            END_ON_START.store(false, std::sync::atomic::Ordering::Release);
            if !finished {
                // The newborn may still reach the host through
                // its guard drops (inline fields included, which
                // forget alone would leave in this unwound
                // frame); leak it on the heap rather than turn
                // this failure into a suite-wide SIGSEGV.
                let _ = Box::leak(Box::new(host));
                panic!("ending birth did not finish (settls={settls})");
            }
            // The poll above can complete as soon as on_exit_thread
            // ran — before the newborn released its guards and
            // exited. Wait for the thread to really be gone
            // before asserting baselines, unmapping its live TLS
            // copy, or dropping the host its guard drops write to.
            let mypid = raw_pid(libc::SYS_getpid);
            let mut exited = false;
            for _ in 0..500 {
                // SAFETY: signal 0 only probes existence.
                let probe = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        mypid.as_raw() as i64,
                        child_tid as i64,
                        0_i64,
                    )
                };
                if probe == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    exited = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !exited {
                let _ = Box::leak(Box::new(host));
                panic!("ending newborn thread did not exit");
            }
            EXIT_HOST.store(0, std::sync::atomic::Ordering::Release);
            assert!(
                EXIT_SEEN_DEPTH.load(std::sync::atomic::Ordering::Acquire) > 0,
                "on_exit_thread must run inside the allocation scope"
            );
            assert!(
                EXIT_SEEN_ACTIVE.load(std::sync::atomic::Ordering::Acquire),
                "on_exit_thread must run counted as an active dispatch"
            );
            assert_eq!(
                super::super::alloc::dispatch_depth_for_test(),
                parent_depth,
                "parent dispatch depth changed by the ending birth"
            );
            assert_eq!(
                COMMITTED_STACKS.with(|stacks| stacks.borrow().len()),
                parent_committed,
                "parent committed arenas changed by the ending birth"
            );
            assert!(!host.dispatch_active());
            unsafe { libc::munmap(guest_stack, guest_stack_len) };
            if settls {
                // SAFETY: the copied TLS span's base is 64 KiB in.
                unsafe { libc::munmap((tls_page as *mut libc::c_void).sub(64 * 1024), 128 * 1024) };
            }
        }
    }

    /// The install gate and the active-dispatch counter are atomic
    /// against each other: an install section that observed zero cannot
    /// race a dispatch starting, and a live dispatch refuses install.
    #[test]
    fn install_gate_and_dispatch_counter_are_atomic() {
        let _test = TEST_LOCK.lock().unwrap();
        let (host, _peer) = host(false, false);
        // No dispatch: install may begin.
        let install = host.begin_install().expect("quiescent host installs");
        assert!(!host.dispatch_active());
        // While install holds the gate, a dispatch cannot mark itself
        // active: its begin spins on the gate, counter still zero.
        let (tx, rx) = std::sync::mpsc::channel();
        let began = std::thread::scope(|scope| {
            let blocker = scope.spawn(|| {
                let _active = host.begin_dispatch();
                tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(50));
            });
            let early = rx.recv_timeout(std::time::Duration::from_millis(150));
            assert!(early.is_err(), "dispatch began during install section");
            assert!(!host.dispatch_active());
            drop(install);
            blocker.join().unwrap();
            rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok()
        });
        assert!(began, "dispatch proceeds after install section ends");
        assert!(!host.dispatch_active());
        // While a dispatch is active, install is refused.
        let _active = host.begin_dispatch();
        assert!(host.begin_install().is_none());
    }

    /// Two dispatches for distinct guest threads run their Tool callbacks
    /// at the same time: the handler rendezvous would deadlock if any
    /// process-wide lock were still held across the callback (W7 lease
    /// model). Each thread keeps its own leased state (attempts counted
    /// per tid, restart protocol intact).
    #[test]
    fn concurrent_dispatches_on_distinct_threads_overlap() {
        let _test = TEST_LOCK.lock().unwrap();
        let (host, _peer) = host(false, false);
        let host = std::sync::Arc::new(host);
        *RENDEZVOUS.lock().unwrap() = Some(std::sync::Arc::new(std::sync::Barrier::new(2)));
        let results: Vec<(i32, i64)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let host = std::sync::Arc::clone(&host);
                    scope.spawn(move || {
                        let tid = raw_pid(libc::SYS_gettid).as_raw();
                        let mut call = event(libc::SYS_getpid, [0; 6]);
                        // SAFETY: this thread owns the event and its
                        // argument-free call; dispatch runs as this thread.
                        unsafe { host.dispatch(&mut call) };
                        (tid, call.result)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        *RENDEZVOUS.lock().unwrap() = None;
        assert_eq!(results.len(), 2);
        for (tid, result) in &results {
            assert_eq!(*result, 71);
            assert_eq!(
                host.states
                    .with_state(*tid, |state| state.unwrap().attempts),
                2,
                "restart protocol must run per thread under concurrency"
            );
        }
        assert_ne!(results[0].0, results[1].0);
    }

    #[cfg(feature = "exec-private-successor")]
    fn isolated(body: impl FnOnce() + std::panic::UnwindSafe, expected: i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(body).is_ok() {
                0
            } else {
                125
            };
            unsafe { libc::_exit(status) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }

    /// Hold the empty `prepared_exec` slot locked from a locker
    /// thread for exactly the duration of `run`, so a dispatch under
    /// way really does contend on the slot; a timed hold could
    /// expire before the dispatching thread is even scheduled.
    #[cfg(feature = "exec-private-successor")]
    fn with_empty_prepared_exec_slot_locked<T>(
        host: &std::sync::Arc<ToolHost<Probe, Runtime>>,
        run: impl FnOnce() -> T,
    ) -> T {
        let (locked_tx, locked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let locker_host = std::sync::Arc::clone(host);
        let locker = std::thread::spawn(move || {
            let guard = locker_host.prepared_exec.lock();
            assert!(guard.is_none());
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
            drop(guard);
        });
        locked_rx.recv().unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        let _ = release_tx.send(());
        locker.join().unwrap();
        match outcome {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// Plain contention on the `prepared_exec` slot must not be read as
    /// a pending successor state: the slot is empty here, and an
    /// ordinary dispatch that loses the momentary lock race used to
    /// take the "initialization failed" exit and jump at the unmapped
    /// fixed native gate (SIGSEGV, dh-n6qjq; 14/200 unpatched,
    /// 3/3 pre-flight aborts). Under `isolated` so the unfixed crash
    /// is a clean child failure rather than a whole-harness death.
    #[cfg(feature = "exec-private-successor")]
    #[test]
    fn dispatch_with_prepared_exec_slot_under_contention_completes() {
        let _test = TEST_LOCK.lock().unwrap();
        isolated(
            || {
                let (host, _peer) = host(false, false);
                let host = std::sync::Arc::new(host);
                let (tid, result) = with_empty_prepared_exec_slot_locked(&host, || {
                    std::thread::scope(|scope| {
                        scope
                            .spawn(|| {
                                let tid = raw_pid(libc::SYS_gettid).as_raw();
                                let mut call = event(libc::SYS_getpid, [0; 6]);
                                // SAFETY: this thread owns the event and its
                                // argument-free call; dispatch runs as this thread.
                                unsafe { host.dispatch(&mut call) };
                                (tid, call.result)
                            })
                            .join()
                            .unwrap()
                    })
                });
                assert_eq!(result, 71);
                assert_eq!(
                    host.states.with_state(tid, |state| state.unwrap().attempts),
                    2,
                    "restart protocol must run under slot contention"
                );
            },
            0,
        );
    }

    /// `dispatch_instruction` probes the same slot at its entry; it
    /// gets the same contention twin so neither probe can regress to
    /// the lock probe independently.
    #[cfg(feature = "exec-private-successor")]
    #[test]
    fn dispatch_instruction_with_prepared_exec_slot_under_contention_completes() {
        let _test = TEST_LOCK.lock().unwrap();
        isolated(
            || {
                let (host, _peer) = host(false, false);
                let host = std::sync::Arc::new(host);
                let tid = with_empty_prepared_exec_slot_locked(&host, || {
                    std::thread::scope(|scope| {
                        scope
                            .spawn(|| {
                                let tid = raw_pid(libc::SYS_gettid).as_raw();
                                let mut context = RegisterContext::default();
                                context.instruction_pointer = 0x1234;
                                context.rax = u64::MAX;
                                // SAFETY: the context outlives the call on
                                // this thread and is not aliased.
                                unsafe {
                                    host.dispatch_instruction(
                                        InstructionEventKind::Rdtsc,
                                        &mut context,
                                    );
                                }
                                assert_ne!(context.rax, u64::MAX);
                                tid
                            })
                            .join()
                            .unwrap()
                    })
                });
                assert!(
                    host.states.with_state(tid, |state| state.is_some()),
                    "instruction dispatch must publish its thread state"
                );
            },
            0,
        );
    }

    /// The restore seam's twin of the dispatch regression: the
    /// empty `prepared_exec` slot being *locked* by a sibling must
    /// not read as a pending successor there either. The pre-fix
    /// `try_lock().is_none_or(..)` refuses a legitimate restore
    /// with "successor lifecycle state is not complete" for exactly
    /// the duration of the contention.
    #[cfg(feature = "exec-private-successor")]
    #[test]
    fn restore_current_thread_state_with_prepared_exec_slot_under_contention_completes() {
        let _test = TEST_LOCK.lock().unwrap();
        let (host, _peer) = host(false, false);
        let host = std::sync::Arc::new(host);
        let pid = raw_pid(libc::SYS_getpid).as_raw();
        let tid = with_empty_prepared_exec_slot_locked(&host, || {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let tid = raw_pid(libc::SYS_gettid).as_raw();
                        host.restore_current_thread_state(State {
                            pid,
                            tid,
                            attempts: 7,
                        })
                        .unwrap();
                        tid
                    })
                    .join()
                    .unwrap()
            })
        });
        assert_eq!(
            host.states.with_state(tid, |state| state.unwrap().attempts),
            7,
            "the restored state must publish under slot contention"
        );
    }

    #[test]
    fn actual_owner_dispatch_reborrows_after_restart_and_preserves_errno() {
        let _test = TEST_LOCK.lock().unwrap();
        let (host, _peer) = host(false, false);
        let mut call = event(libc::SYS_getpid, [0; 6]);
        // SAFETY: this test thread owns the event and its argument-free call.
        unsafe { host.dispatch(&mut call) };
        assert_eq!(call.result, 71);
        let tid = raw_pid(libc::SYS_gettid).as_raw();
        assert_eq!(
            host.states.with_state(tid, |state| state.unwrap().attempts),
            2
        );
        let mut call = event(libc::SYS_getppid, [0; 6]);
        // SAFETY: the same live host and thread, no guest pointers.
        unsafe { host.dispatch(&mut call) };
        assert_eq!(call.result, -i64::from(Errno::EACCES.into_raw()));
    }

    /// Exercises production reconstruction in a separately exec'd child, not
    /// the physical fork routes. Native fork controls remain integration tests.
    #[test]
    fn actual_child_reconstruction_preserves_selected_and_legacy_owner_order() {
        use std::os::unix::process::CommandExt;
        const MODE: &str = "REVERIE_PROCESS_OWNER_RECONSTRUCTION_TEST";
        const PARENT: &str = "REVERIE_PROCESS_OWNER_PARENT_IDENTITIES";
        const TEST: &str = "guest::host::process_owner_tests::actual_child_reconstruction_preserves_selected_and_legacy_owner_order";
        let Some(mode) = std::env::var_os(MODE) else {
            let identities = format!(
                "{}:{}",
                raw_pid(libc::SYS_getpid),
                raw_pid(libc::SYS_gettid)
            );
            for mode in ["selected", "legacy"] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                    .env(MODE, mode)
                    .env(PARENT, &identities)
                    .process_group(0)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if std::time::Instant::now() >= deadline {
                        assert_eq!(
                            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                            0
                        );
                        child.wait().unwrap();
                        panic!("reconstruction test exceeded ten seconds");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                let output = child.wait_with_output().unwrap();
                assert!(status.success(), "{mode}: {status}; {output:?}");
                assert_eq!(output.status, status);
                let stdout = String::from_utf8(output.stdout).unwrap();
                let summaries: Vec<_> = stdout
                    .lines()
                    .filter(|line| line.starts_with("test result: "))
                    .collect();
                assert!(
                    matches!(summaries.as_slice(), [summary] if summary.starts_with(
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                    )),
                    "expected exactly one completed {mode} child test: {stdout}"
                );
                assert!(
                    stdout
                        .lines()
                        .any(|line| line == format!("test {TEST} ... ok"))
                );
            }
            return;
        };
        let identities = std::env::var(PARENT).unwrap();
        let (parent_pid, parent_tid) = identities.split_once(':').unwrap();
        let parent_pid: i32 = parent_pid.parse().unwrap();
        let parent_tid: i32 = parent_tid.parse().unwrap();
        assert_eq!(parent_pid, raw_pid(libc::SYS_getppid).as_raw());
        let child_pid = raw_pid(libc::SYS_getpid).as_raw();
        let child_tid = raw_pid(libc::SYS_gettid).as_raw();
        let (rpc, _peer) = coordinator(false, false);
        EVENTS.lock().unwrap().clear();
        // Model only the inherited Rust values; no allocation or async code
        // runs in a copy of a multithreaded libtest process after raw fork.
        let inherited = Probe {
            pid: parent_pid,
            abandon: false,
        };
        let owner = if mode == "selected" {
            ToolProcess::adopt_selected(inherited, ToolConfiguration::select(rpc.shared_config()))
        } else {
            ToolProcess::adopt_legacy(inherited)
        };
        assert_eq!(
            EVENTS.lock().unwrap().len(),
            usize::from(mode == "selected")
        );
        EVENTS.lock().unwrap().clear();
        let host = ToolHost::from_parts(
            owner,
            rpc,
            Pid::from_raw(parent_pid),
            HashSet::new(),
            false,
            Runtime,
        );
        assert!(
            host.states
                .try_publish(
                    parent_tid,
                    State {
                        pid: parent_pid,
                        tid: parent_tid,
                        attempts: 0,
                    },
                )
                .is_ok(),
            "fresh host has no parent state"
        );
        let parent_lease = host
            .states
            .checkout_existing(parent_tid)
            .expect("parent state just published");
        let snapshot = State {
            pid: parent_pid,
            tid: parent_tid,
            attempts: 0,
        };
        let mut call = event(crate::arch::SYS_FORK.unwrap_or(libc::SYS_clone), [0; 6]);
        finish_fork_child(
            &host,
            parent_lease,
            &mut call,
            snapshot,
            ForkChildContext {
                parent_tid: Pid::from_raw(parent_tid),
                parent_pid: Pid::from_raw(parent_pid),
                child_tid: Pid::from_raw(child_tid),
                child_pid: Pid::from_raw(child_pid),
                #[cfg(feature = "exec-native-injection")]
                native_exec_route_active: false,
            },
        );
        assert_eq!(call.result, 0);
        assert_eq!(
            *EVENTS.lock().unwrap(),
            [
                ("rebind", child_pid),
                ("begin", child_tid),
                ("state-drop", parent_tid),
                ("new", child_pid),
                ("init", child_tid),
                ("tool-drop", parent_pid),
                ("reset", child_pid),
                ("start", child_tid),
                ("complete", child_tid),
                ("state-drop", parent_tid),
            ]
        );
        let owner = host.tool_process().unwrap();
        assert_eq!(ToolProcess::as_ref(&owner).unwrap().pid, child_pid);
        assert_eq!(owner.selected_configuration().is_some(), mode == "selected");
        assert_eq!(
            host.states
                .with_state(child_tid, |state| state.map(|state| state.pid)),
            Some(child_pid)
        );
        assert!(!host.states.contains(parent_tid));
    }

    /// Wiring witness for fork quiescence: `finish_fork_child` must
    /// complete in a child whose copies of every host lock were made
    /// mid-hold by sibling threads that do not exist here, with a
    /// dispatch counter including those siblings' guards. Leaked
    /// guards stand in for the dead holders; deleting the host
    /// reinit call deadlocks the exec'd child (deadline below),
    /// and deleting the nested RPC reinit fails the registry-lock
    /// assertions after the call.
    #[test]
    fn fork_child_reinit_recovers_copied_locked_host() {
        use std::os::unix::process::CommandExt;
        const MODE: &str = "REVERIE_FORK_REINIT_TEST";
        const TEST: &str =
            "guest::host::process_owner_tests::fork_child_reinit_recovers_copied_locked_host";
        if std::env::var_os(MODE).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(MODE, "child")
                .process_group(0)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    assert_eq!(
                        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                        0
                    );
                    child.wait().unwrap();
                    panic!("fork reinit test exceeded ten seconds (a copied lock deadlocked)");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            let output = child.wait_with_output().unwrap();
            assert!(status.success(), "{status}; {output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .lines()
                    .any(|line| line == format!("test {TEST} ... ok")),
                "expected exactly one completed child test"
            );
            return;
        }
        let (host, _peer) = host(false, false);
        EVENTS.lock().unwrap().clear();
        let child_pid = raw_pid(libc::SYS_getpid).as_raw();
        let child_tid = raw_pid(libc::SYS_gettid).as_raw();
        let parent_pid = raw_pid(libc::SYS_getppid).as_raw();
        // A sibling's tid which is not this thread's: the parent
        // lease's identity in the copied registry.
        let parent_tid = child_tid + 100_000;
        assert!(
            host.states
                .try_publish(
                    parent_tid,
                    State {
                        pid: parent_pid,
                        tid: parent_tid,
                        attempts: 0,
                    },
                )
                .is_ok()
        );
        let parent_lease = host
            .states
            .checkout_existing(parent_tid)
            .expect("parent state just published");
        let snapshot = State {
            pid: parent_pid,
            tid: parent_tid,
            attempts: 0,
        };
        // Sibling stand-ins: every host/registry lock held by a
        // thread that no longer exists, plus three sibling dispatches
        // counted in the process-wide counter.
        core::mem::forget(host.install_gate.lock());
        core::mem::forget(host.tool.lock());
        core::mem::forget(host.birth_stacks.lock());
        core::mem::forget(host.ordinary_root_state.lock());
        #[cfg(feature = "exec-private-successor")]
        core::mem::forget(host.prepared_exec.lock());
        host.states.forget_lock_guard_for_test();
        host.rpc.forget_lock_guards_for_test();
        host.active_dispatches
            .fetch_add(3, core::sync::atomic::Ordering::AcqRel);
        assert!(host.install_gate.try_lock().is_none());
        assert!(host.tool.try_lock().is_none());
        assert!(host.dispatch_active());
        let mut call = event(crate::arch::SYS_FORK.unwrap_or(libc::SYS_clone), [0; 6]);
        finish_fork_child(
            &host,
            parent_lease,
            &mut call,
            snapshot,
            ForkChildContext {
                parent_tid: Pid::from_raw(parent_tid),
                parent_pid: Pid::from_raw(parent_pid),
                child_tid: Pid::from_raw(child_tid),
                child_pid: Pid::from_raw(child_pid),
                #[cfg(feature = "exec-native-injection")]
                native_exec_route_active: false,
            },
        );
        assert_eq!(call.result, 0);
        assert!(
            !host.dispatch_active(),
            "sibling dispatch counts must be reset away"
        );
        assert!(host.install_gate.try_lock().is_some());
        assert!(host.tool.try_lock().is_some());
        assert!(host.birth_stacks.try_lock().is_some());
        assert!(host.ordinary_root_state.try_lock().is_some());
        #[cfg(feature = "exec-private-successor")]
        assert!(host.prepared_exec.try_lock().is_some());
        assert!(
            host.rpc.registry_locks_free_for_test(),
            "RPC registry locks leaked above must be free after reinit"
        );
        assert!(host.states.contains(child_tid));
        assert!(!host.states.contains(parent_tid));
        assert!(
            EVENTS
                .lock()
                .unwrap()
                .iter()
                .any(|(name, tid)| *name == "start" && *tid == child_tid),
            "thread-start ran in the recovered child"
        );
    }

    /// Real-wiring heap witness: a sibling thread holds the Tool
    /// heap lock directly (not through the quiesce under test)
    /// while the main thread performs a REAL plain fork through
    /// `forward_plain_fork` and runs `finish_fork_child` in the
    /// child, which then allocates from the Tool heap. The sibling
    /// holds past the forker's entry and then keeps re-acquiring
    /// the lock, so a fork taken without the quiesce — or one
    /// whose quiesce is released before the raw syscall — copies
    /// a held heap lock and the child hangs; the pipe deadline
    /// fails the test. Replacing the quiesce calls with `()` must
    /// therefore kill this test. Legs run fork, COW-vfork, and
    /// fork again with `CREATION_HOOK` set directly in this
    /// exec'd child (reported_creation itself never checks for an
    /// installed filter; only set_physical_creation_hook does),
    /// covering all three quiesce sites.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn fork_heap_quiesce_through_real_forward() {
        use std::os::unix::process::CommandExt;
        const MODE: &str = "REVERIE_FORK_HEAP_QUIESCE_TEST";
        const TEST: &str =
            "guest::host::process_owner_tests::fork_heap_quiesce_through_real_forward";
        if std::env::var_os(MODE).is_none() {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(MODE, "child")
                .process_group(0)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    assert_eq!(
                        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                        0
                    );
                    child.wait().unwrap();
                    panic!("heap quiesce wiring test exceeded twenty seconds");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            let output = child.wait_with_output().unwrap();
            assert!(status.success(), "{status}; {output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .lines()
                    .any(|line| line == format!("test {TEST} ... ok")),
                "expected exactly one completed child test"
            );
            return;
        }
        use core::sync::atomic::AtomicBool;
        use core::sync::atomic::Ordering;
        static HOOK_CREATED: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        fn counting_creation_hook(creation: PhysicalCreation) -> io::Result<()> {
            if matches!(creation, PhysicalCreation::Created { .. }) {
                HOOK_CREATED.fetch_add(1, Ordering::AcqRel);
            }
            Ok(())
        }
        for (number, use_hook) in [
            (
                crate::arch::SYS_FORK.expect("x86_64 gate keeps fork beside vfork"),
                false,
            ),
            (
                crate::arch::SYS_VFORK.expect("x86_64 gate keeps vfork beside fork"),
                false,
            ),
            (
                crate::arch::SYS_FORK.expect("x86_64 gate keeps fork beside vfork"),
                true,
            ),
        ] {
            if use_hook {
                // Direct set, exec'd-child only: reported_creation
                // reads the cell; only the registration API checks
                // for an installed runtime filter.
                let _ = CREATION_HOOK.set(counting_creation_hook);
            }
            let (host, _peer) = host(false, false);
            EVENTS.lock().unwrap().clear();
            let parent_pid = raw_pid(libc::SYS_getppid).as_raw();
            let parent_tid = raw_pid(libc::SYS_gettid).as_raw() + 100_000;
            assert!(
                host.states
                    .try_publish(
                        parent_tid,
                        State {
                            pid: parent_pid,
                            tid: parent_tid,
                            attempts: 0,
                        },
                    )
                    .is_ok()
            );
            let parent_lease = host
                .states
                .checkout_existing(parent_tid)
                .expect("parent state just published");
            let snapshot = State {
                pid: parent_pid,
                tid: parent_tid,
                attempts: 0,
            };
            let mut pipe_fds = [-1; 2];
            // SAFETY: pipe2 writes two descriptors into the array.
            assert_eq!(unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), 0) }, 0);
            let held = std::sync::Arc::new(AtomicBool::new(false));
            let entered = std::sync::Arc::new(AtomicBool::new(false));
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let sibling = {
                let held = std::sync::Arc::clone(&held);
                let entered = std::sync::Arc::clone(&entered);
                let stop = std::sync::Arc::clone(&stop);
                std::thread::spawn(move || {
                    // Hold the heap lock directly, not through the
                    // quiesce under test.
                    let guard = super::super::alloc::hold_tool_heap_lock_for_test();
                    held.store(true, Ordering::Release);
                    while !entered.load(Ordering::Acquire) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    // Hold well past the forker's syscall entry: a
                    // fork taken inside this window without the
                    // quiesce copies the held heap lock.
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    drop(guard);
                    // Then keep re-acquiring: a quiesce released
                    // before the raw syscall (instead of after it)
                    // lets this churn win the lock back in the gap,
                    // and the fork copies it held again.
                    while !stop.load(Ordering::Acquire) {
                        let guard = super::super::alloc::hold_tool_heap_lock_for_test();
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        drop(guard);
                        std::thread::yield_now();
                    }
                })
            };
            while !held.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let mut call = event(number, [0; 6]);
            entered.store(true, Ordering::Release);
            let result = forward_plain_fork(number, [0; 6], None);
            if result == 0 {
                // Fork child: the sibling and its held guard do not
                // exist here. Run the real child finish, then prove
                // the Tool heap allocates.
                // SAFETY: closing this child's copy of the read end.
                unsafe { libc::close(pipe_fds[0]) };
                let child_pid = raw_pid(libc::SYS_getpid);
                let child_tid = raw_pid(libc::SYS_gettid);
                finish_fork_child(
                    &host,
                    parent_lease,
                    &mut call,
                    snapshot,
                    ForkChildContext {
                        parent_tid: Pid::from_raw(parent_tid),
                        parent_pid: Pid::from_raw(parent_pid),
                        child_tid,
                        child_pid,
                        #[cfg(feature = "exec-native-injection")]
                        native_exec_route_active: false,
                    },
                );
                let ok = {
                    use core::alloc::GlobalAlloc;
                    let _scope = super::super::alloc::enter_dispatch();
                    let layout = core::alloc::Layout::from_size_align(512, 64).unwrap();
                    // SAFETY: layout is valid for this allocator.
                    let pointer = unsafe { super::super::alloc::GuestAllocator.alloc(layout) };
                    if pointer.is_null() {
                        false
                    } else {
                        // SAFETY: pointer covers layout.size bytes.
                        unsafe { pointer.write_bytes(0xa5, layout.size()) };
                        // SAFETY: pointer is live with layout.
                        unsafe { super::super::alloc::GuestAllocator.dealloc(pointer, layout) };
                        true
                    }
                };
                let byte = [u8::from(ok)];
                // SAFETY: write end is open in this child.
                unsafe {
                    libc::write(pipe_fds[1], byte.as_ptr().cast(), 1);
                }
                // SAFETY: _exit avoids inherited atexit state.
                unsafe { libc::_exit(if ok { 0 } else { 71 }) };
            }
            assert!(result > 0, "forward_plain_fork failed with {result}");
            // SAFETY: closing the parent's write end so the read
            // side sees EOF when the child exits.
            unsafe { libc::close(pipe_fds[1]) };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            let mut byte = [0_u8; 1];
            let read = loop {
                let mut poll = libc::pollfd {
                    fd: pipe_fds[0],
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one pollfd for this test's pipe read end.
                let ready = unsafe { libc::poll(&mut poll, 1, 100) };
                if ready > 0 {
                    // SAFETY: reading the one status byte.
                    break unsafe { libc::read(pipe_fds[0], byte.as_mut_ptr().cast(), 1) };
                }
                if std::time::Instant::now() >= deadline {
                    // SAFETY: killing this test's direct child.
                    unsafe { libc::kill(result as libc::pid_t, libc::SIGKILL) };
                    break -1;
                }
            };
            let mut status = 0;
            // SAFETY: `result` is this test's direct child pid.
            assert_eq!(
                unsafe { libc::waitpid(result as libc::pid_t, &mut status, 0) },
                result as libc::pid_t
            );
            // SAFETY: closing the parent's read end.
            unsafe { libc::close(pipe_fds[0]) };
            drop(parent_lease);
            stop.store(true, Ordering::Release);
            sibling.join().unwrap();
            if use_hook {
                assert!(
                    HOOK_CREATED.load(Ordering::Acquire) >= 1,
                    "the hooked leg must have reported its creation"
                );
            }
            assert_eq!(read, 1, "child hung before its Tool-heap allocation");
            assert_eq!(byte, [1]);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "fork child failed with status {status:#x}"
            );
        }
    }

    /// Raw clone3 syscall for the flip test's tail injections.
    #[cfg(target_arch = "x86_64")]
    #[derive(Copy, Clone)]
    struct RawClone3([u64; 2]);

    #[cfg(target_arch = "x86_64")]
    impl reverie::syscalls::Displayable for RawClone3 {
        fn fmt<M: reverie::syscalls::MemoryAccess>(
            &self,
            _memory: &M,
            _outputs: bool,
            f: &mut core::fmt::Formatter,
        ) -> core::fmt::Result {
            write!(f, "clone3({:#x}, {:#x})", self.0[0], self.0[1])
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl reverie::syscalls::SyscallInfo for RawClone3 {
        type Return = Result<i64, Errno>;

        fn name(&self) -> &'static str {
            "clone3"
        }

        fn number(&self) -> reverie::syscalls::Sysno {
            reverie::syscalls::Sysno::clone3
        }

        fn into_parts(self) -> (reverie::syscalls::Sysno, reverie::syscalls::SyscallArgs) {
            (
                reverie::syscalls::Sysno::clone3,
                reverie::syscalls::SyscallArgs::new(
                    self.0[0] as usize,
                    self.0[1] as usize,
                    0,
                    0,
                    0,
                    0,
                ),
            )
        }
    }

    /// Flip regression: a sibling thread rewrites a shared clone3
    /// record between shapes while creations are classified and
    /// forwarded in a loop, in separately exec'd phases:
    /// dispatch flips plain-fork vs KernelDecides, tail_inject
    /// flips KernelDecides vs plain-fork vs Unsupported vs the
    /// stack-less full-sharing birth shape, and a births phase
    /// holds that birth shape steady. Outcomes
    /// accumulate on a memfd-shared page across the 40 exec'd runs
    /// of each phase (guard refusals, kernel EINVALs, reset fork
    /// children, admitted births, raw children): each phase must
    /// show a minimum number of real outcomes, so a run that ends
    /// with the classification-mismatch refusal (bare 125) at
    /// iteration 0 does not count as coverage, and raw children
    /// must stay zero. Per-phase exec modes keep a dispatch-phase
    /// 125 from ending the tail phase unrun. Exec'd throughout so
    /// a regression's raw child cannot take the suite with it.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn clone3_flip_never_creates_unreset_child() {
        use std::os::unix::process::CommandExt;
        const MODE: &str = "REVERIE_CLONE3_FLIP_TEST";
        const COUNT_FD: &str = "REVERIE_CLONE3_FLIP_COUNT_FD";
        const TEST: &str =
            "guest::host::process_owner_tests::clone3_flip_never_creates_unreset_child";
        // Counter page layout (u64 slots): 0 raw children,
        // 1 guard/typed refusals (EOPNOTSUPP), 2 kernel EINVAL,
        // 3 reset fork children, 4 admitted births.
        const MIN_OUTCOMES_PER_PHASE: u64 = 200;
        let mode = std::env::var(MODE).ok();
        if mode.is_none() {
            // The counter page lives in a memfd so every exec'd run
            // of the three phases accumulates into the same counts.
            let counter_fd = unsafe { libc::memfd_create(c"clone3-flip-counts".as_ptr(), 0) };
            assert!(counter_fd >= 0, "memfd_create failed");
            assert_eq!(unsafe { libc::ftruncate(counter_fd, 4096) }, 0);
            let counter_page = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    counter_fd,
                    0,
                )
            };
            assert_ne!(counter_page, libc::MAP_FAILED);
            let counts = |slot: usize| {
                // SAFETY: the counter page is this test's memfd.
                let word: &core::sync::atomic::AtomicU64 = unsafe {
                    core::sync::atomic::AtomicU64::from_ptr(
                        (counter_page as *mut u8).add(slot * 8).cast(),
                    )
                };
                word.load(core::sync::atomic::Ordering::Acquire)
            };
            for phase in ["dispatch", "tail", "births"] {
                let before: u64 = (1..5).map(&counts).sum();
                let refusals_before = counts(1);
                let einval_before = counts(2);
                let resets_before = counts(3);
                let births_before = counts(4);
                for run in 0..40 {
                    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                        .env(MODE, phase)
                        .env(COUNT_FD, counter_fd.to_string())
                        .process_group(0)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .unwrap();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    let status = loop {
                        if let Some(status) = child.try_wait().unwrap() {
                            break status;
                        }
                        if std::time::Instant::now() >= deadline {
                            assert_eq!(
                                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                                0
                            );
                            child.wait().unwrap();
                            panic!("clone3 flip test exceeded thirty seconds");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    };
                    let output = child.wait_with_output().unwrap();
                    if status.success() {
                        assert!(
                            String::from_utf8(output.stdout)
                                .unwrap()
                                .lines()
                                .any(|line| line == format!("test {TEST} ... ok")),
                            "phase {phase} run {run}: expected one completed child test"
                        );
                    } else {
                        assert_eq!(
                            status.code(),
                            Some(125),
                            "phase {phase} run {run}: unsafe flip outcome {status}; {output:?}"
                        );
                    }
                }
                if std::env::var_os("FLIP_DEBUG").is_some() {
                    eprintln!(
                        "phase {phase}: raw={} eopnotsupp={} einval={} reset={} births={}",
                        counts(0),
                        counts(1),
                        counts(2),
                        counts(3),
                        counts(4)
                    );
                }
                let outcomes: u64 = (1..5).map(&counts).sum::<u64>() - before;
                // The tail phase holds shapes for 300 us (its
                // raw-forward window is the classify-to-kernel-read
                // gap, which needs tight flips to hit), so most of
                // its runs end in the 125 mismatch refusal after
                // only a few counted outcomes. Floor 100 is from
                // measurement at e021968d: tail minimum 229 and
                // mean ~350-430 outcomes per 40 runs over 497 head
                // runs, so 100 stays well clear of the observed
                // minimum without pretending to the dispatch
                // phase's counts. Do not raise it towards 200 at
                // this stimulus: 229 is only ~15% above 200.
                let minimum = if phase == "tail" {
                    100
                } else {
                    MIN_OUTCOMES_PER_PHASE
                };
                assert!(
                    outcomes >= minimum,
                    "phase {phase} produced only {outcomes} counted outcomes in 40 runs"
                );
                // The KernelDecides branch itself must have run
                // on both forwarding paths: deleting either branch
                // (guard-only refusals) leaves its kernel-EINVAL
                // slot empty. Dispatch head minimum measured at
                // e021968d was 2514 over 497 runs, so 20 is a
                // wide-margin floor there too.
                if phase != "births" {
                    let einvals = counts(2) - einval_before;
                    assert!(
                        einvals >= 20,
                        "phase {phase} produced only {einvals} kernel EINVAL outcomes"
                    );
                } else {
                    // Births-phase exactness: with the shape
                    // pre-written steady, every one of the 1000
                    // iterations admits a birth and nothing else
                    // is counted, so the bar is exact equality —
                    // a partial refusal at any rate (even 49%)
                    // misses it. Load cannot turn a correct birth
                    // into a refusal: a slow newborn fails the
                    // per-iteration seen==result assert instead.
                    let births = counts(4) - births_before;
                    let refusals = counts(1) - refusals_before;
                    let einvals_b = counts(2) - einval_before;
                    let resets = counts(3) - resets_before;
                    assert_eq!(
                        births, 1000,
                        "births phase admitted only {births} of 1000 steady-shape births"
                    );
                    assert_eq!(
                        (refusals, einvals_b, resets),
                        (0, 0, 0),
                        "births phase counted non-birth outcomes"
                    );
                }
            }
            // The stack-less full-sharing shape is a birth only
            // under the Linux-shaped taxonomy. Two mutants die
            // differently here: the refusal variant (stack-less
            // ThreadBirth turned into Unsupported) leaves this
            // slot empty and fails the births-phase floor above,
            // while the restored pre-Linux rule defers the shape to the
            // kernel as KernelDecides, forwarding it into a raw
            // thread on the parent's stack — which the tail
            // phase's raw-child accounting and status asserts
            // kill first, never reaching this floor. Asserted
            // across the tail + dedicated births phases:
            // births are Poisson-rare under the mixed flip load
            // alone, so the births phase holds the FULL shape
            // steady to make the stimulus deterministic.
            assert!(
                counts(4) >= 1,
                "no stack-less birth admitted across the tail and births phases"
            );
            assert_eq!(
                counts(0),
                0,
                "raw (unreset/unadmitted) children were created"
            );
            unsafe {
                libc::munmap(counter_page, 4096);
                libc::close(counter_fd);
            }
            return;
        }
        let phase = mode.unwrap();
        use core::sync::atomic::AtomicBool;
        use core::sync::atomic::AtomicU64;
        use core::sync::atomic::Ordering;
        let counter_fd: i32 = std::env::var(COUNT_FD).unwrap().parse().unwrap();
        let counter_page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                counter_fd,
                0,
            )
        };
        assert_ne!(counter_page, libc::MAP_FAILED);
        let count = |slot: usize| {
            // SAFETY: the counter page is the parent's memfd.
            let word: &AtomicU64 =
                unsafe { AtomicU64::from_ptr((counter_page as *mut u8).add(slot * 8).cast()) };
            word.fetch_add(1, Ordering::AcqRel);
        };
        // One shared page: the clone3 record at 0, a set_tid array
        // word at 1024.
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let record = page as *mut u64;
        fn write_shape(record: *mut u64, flags: u64, exit_signal: u64, set_tid: u64) {
            let words = [flags, 0, 0, 0, exit_signal, 0, 0, 0, set_tid, 0, 0];
            for (index, word) in words.iter().enumerate() {
                // SAFETY: the record fits the shared page.
                unsafe { record.add(index).write_volatile(*word) };
            }
        }
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let mypid = raw_pid(libc::SYS_getpid).as_raw();
        let mytid = raw_pid(libc::SYS_gettid).as_raw();
        let count_result = |result: i64| {
            if result == -i64::from(libc::EINVAL) {
                count(2);
            } else if result == -i64::from(Errno::EOPNOTSUPP.into_raw()) {
                count(1);
            }
        };

        if phase == "dispatch" {
            let (mut host, _peer) = host(false, false);
            host.set_thread_admission(true);
            let flipper = {
                let stop = std::sync::Arc::clone(&stop);
                let record_addr = record as usize;
                std::thread::spawn(move || {
                    let record = record_addr as *mut u64;
                    while !stop.load(Ordering::Acquire) {
                        // Duty cycle with edge bursts: shapes stay
                        // put for 5 ms (most iterations
                        // classify and copy one stable shape and
                        // count an outcome), and each transition
                        // flip-flops back-to-back ~200 times so the
                        // classify-to-kernel-read window is hit at
                        // the edges, not only by luck.
                        write_shape(record, 0, libc::SIGCHLD as u64, 0);
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        for _ in 0..200 {
                            write_shape(record, (libc::CLONE_THREAD | libc::CLONE_VM) as u64, 0, 0);
                            write_shape(record, 0, libc::SIGCHLD as u64, 0);
                        }
                        write_shape(record, (libc::CLONE_THREAD | libc::CLONE_VM) as u64, 0, 0);
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        for _ in 0..200 {
                            write_shape(record, 0, libc::SIGCHLD as u64, 0);
                            write_shape(record, (libc::CLONE_THREAD | libc::CLONE_VM) as u64, 0, 0);
                        }
                    }
                })
            };
            for _ in 0..600 {
                let mut call = event(libc::SYS_clone3, [record as u64, 88, 0, 0, 0, 0]);
                // SAFETY: no guest pointers but the shared record,
                // which every forward path must copy before use.
                unsafe { host.dispatch(&mut call) };
                if raw_pid(libc::SYS_getpid).as_raw() != mypid {
                    // A fork child: reset (thread-start recorded
                    // for this tid) or raw (counted, exit nonzero).
                    let me = raw_pid(libc::SYS_gettid).as_raw();
                    let reset = EVENTS
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(name, tid)| *name == "start" && *tid == me);
                    if !reset {
                        count(0);
                    }
                    // SAFETY: _exit avoids inherited atexit state.
                    unsafe { libc::_exit(if reset { 0 } else { 73 }) };
                }
                if call.result > 0 {
                    count(3);
                    let mut status = 0;
                    // SAFETY: reaping this test's direct child.
                    assert_eq!(
                        unsafe { libc::waitpid(call.result as libc::pid_t, &mut status, 0) },
                        call.result as libc::pid_t
                    );
                    assert!(
                        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                        "fork child without a reset: status {status:#x}"
                    );
                } else {
                    count_result(call.result);
                    assert!(
                        [
                            -i64::from(libc::EINVAL),
                            -i64::from(Errno::EOPNOTSUPP.into_raw())
                        ]
                        .contains(&call.result),
                        "unexpected clone3 result {}",
                        call.result
                    );
                }
            }
            stop.store(true, Ordering::Release);
            flipper.join().unwrap();
            return;
        }

        // Tail phase: KernelDecides <-> plain <-> FULL (birth)
        // <-> Unsupported rotation.
        // Births phase: the same body, but the flipper holds the
        // stack-less full-sharing shape steady so admitted births
        // are deterministic rather than Poisson-rare under load.
        assert!(phase == "tail" || phase == "births");
        let phase_is_births = phase == "births";
        {
            let (mut host, _peer) = host(false, false);
            host.set_thread_admission(true);
            static FLIP_SEEN: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
            unsafe extern "C" {
                fn w7_birth_stub();
            }
            let set_tid_word = (page as u64) + 1024;
            if phase_is_births {
                // Pre-write the steady shape BEFORE spawning the
                // flipper, so no iteration can read the zeroed
                // record (an all-zero record classifies
                // Unsupported and the early iterations would count
                // as refusals, not births).
                const FULL_ONLY: u64 = (libc::CLONE_THREAD
                    | libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND) as u64;
                write_shape(record, FULL_ONLY, 0, 0);
            }
            let flipper = {
                let stop = std::sync::Arc::clone(&stop);
                let record_addr = record as usize;
                std::thread::spawn(move || {
                    let record = record_addr as *mut u64;
                    if phase_is_births {
                        const FULL_ONLY: u64 = (libc::CLONE_THREAD
                            | libc::CLONE_VM
                            | libc::CLONE_FS
                            | libc::CLONE_FILES
                            | libc::CLONE_SIGHAND)
                            as u64;
                        write_shape(record, FULL_ONLY, 0, 0);
                        while !stop.load(Ordering::Acquire) {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        return;
                    }
                    while !stop.load(Ordering::Acquire) {
                        // 300 us duty cycle with edge bursts,
                        // as in the dispatch phase: shapes stay put
                        // long enough for the multi-read copy walk
                        // to usually see one shape (so runs
                        // accumulate counted outcomes), and each
                        // transition flip-flops back-to-back ~200
                        // times so the classify-to-kernel-read
                        // window is hit at the edges. Rotation
                        // KD -> plain -> FULL -> set_tid -> plain:
                        // plain directly follows KernelDecides, so a
                        // forward that reads the record after a
                        // KernelDecides classification can create a
                        // real fork child, not only EINVAL shapes.
                        const KD: u64 = (libc::CLONE_THREAD | libc::CLONE_VM) as u64;
                        const PLAIN: u64 = 0;
                        const UNSUP: u64 =
                            (libc::CLONE_THREAD | libc::CLONE_VM | libc::CLONE_SIGHAND) as u64;
                        const FULL: u64 = (libc::CLONE_THREAD
                            | libc::CLONE_VM
                            | libc::CLONE_FS
                            | libc::CLONE_FILES
                            | libc::CLONE_SIGHAND) as u64;
                        const SHAPES: [(u64, u64, u64); 5] = [
                            (KD, 0, 0),
                            (PLAIN, libc::SIGCHLD as u64, 0),
                            (FULL, 0, 0),
                            (UNSUP, 0, 1024),
                            (PLAIN, libc::SIGCHLD as u64, 0),
                        ];
                        for index in 0..SHAPES.len() {
                            let (shape, exit, set_tid) = SHAPES[index];
                            let set_tid = if set_tid == 1024 {
                                set_tid_word
                            } else {
                                set_tid
                            };
                            write_shape(record, shape, exit, set_tid);
                            std::thread::sleep(std::time::Duration::from_micros(300));
                            // Burst across this edge into the next
                            // shape, ending on it.
                            let (next, next_exit, next_tid) = SHAPES[(index + 1) % SHAPES.len()];
                            let next_tid = if next_tid == 1024 {
                                set_tid_word
                            } else {
                                next_tid
                            };
                            for _ in 0..200 {
                                write_shape(record, next, next_exit, next_tid);
                                write_shape(record, shape, exit, set_tid);
                            }
                            write_shape(record, next, next_exit, next_tid);
                        }
                    }
                })
            };
            // The births phase is deterministic per iteration,
            // so a short loop gives the same floor evidence
            // without 400 real thread births per run.
            for iteration in 0..if phase_is_births { 25 } else { 400 } {
                FLIP_SEEN.store(0, Ordering::Release);
                // A correctly routed plain fork surfaces as the
                // ForkChild outcome and its child runs the real
                // finish below (counted as reset only once
                // thread-start is recorded); prepare its lease.
                let parent_pid = raw_pid(libc::SYS_getppid).as_raw();
                let parent_tid = mytid + 200_000 + iteration;
                assert!(
                    host.states
                        .try_publish(
                            parent_tid,
                            State {
                                pid: parent_pid,
                                tid: parent_tid,
                                attempts: 0,
                            },
                        )
                        .is_ok()
                );
                let parent_lease = host
                    .states
                    .checkout_existing(parent_tid)
                    .expect("parent state just published");
                let snapshot = State {
                    pid: parent_pid,
                    tid: parent_tid,
                    attempts: 0,
                };
                let mut saved = RegisterContext::default();
                saved.rdi = core::ptr::addr_of!(FLIP_SEEN) as u64;
                let root_tid = raw_pid(libc::SYS_gettid);
                let pid = raw_pid(libc::SYS_getpid);
                let mut event = SyscallEvent {
                    number: libc::SYS_getpid,
                    args: [0; 6],
                    instruction_pointer: w7_birth_stub as *const () as usize as u64,
                    result: 0,
                    context: &raw const saved as usize,
                    dispatch: SyscallDispatch::Trap,
                    guest_pkru: None,
                    unsupported_refusal: None,
                };
                let tail = TailResult::default();
                let mut state = State {
                    pid: pid.as_raw(),
                    tid: root_tid.as_raw(),
                    attempts: 0,
                };
                let mut guest = InGuest::<Probe, Runtime> {
                    event: &mut event,
                    tid: root_tid,
                    pid,
                    ppid: None,
                    state: &mut state,
                    rpc: &host.rpc,
                    native: None,
                    tail: &tail,
                    cpuid_interception: false,
                    admit_threads: true,
                    thread_birth: host.thread_birth_ops(),
                    fork_parent_state: None,
                    runtime: &host.runtime,
                    staged_signals: Vec::new(),
                    staged_signal_delivery: false,
                    in_syscall_handler: true,
                    #[cfg(feature = "exec-native-injection")]
                    exec: None,
                    #[cfg(feature = "exec-native-injection")]
                    mapping_driver: None,
                    #[cfg(feature = "exec-native-injection")]
                    native_exec_admitted: host.native_exec_admitted(),
                    #[cfg(feature = "exec-native-injection")]
                    native_exec_route_active: host.native_exec_admitted(),
                    unsupported_refusal: None,
                    injected_syscalls: 0,
                };
                let call = RawClone3([record as u64, 88]);
                // Boxed so the fork child can drop the future (and
                // its guest borrow) before running finish_fork_child.
                let mut tail_future = Box::pin(guest.tail_inject(call));
                let waker = std::task::Waker::noop();
                let mut context = std::task::Context::from_waker(waker);
                assert!(matches!(
                    tail_future.as_mut().poll(&mut context),
                    core::task::Poll::Pending
                ));
                // A raw thread created from the guest pointer would
                // resume these very frames on a tid that is not the
                // test thread's (a fork child keeps its leader tid
                // equal to its new pid, handled after the drive).
                if raw_pid(libc::SYS_gettid).as_raw() != mytid
                    && raw_pid(libc::SYS_getpid).as_raw() == mypid
                {
                    count(0);
                    // SAFETY: end the wedged subprocess loudly.
                    unsafe { libc::_exit(73) };
                }
                let outcome = crate::tool_host::drive_syscall(
                    std::future::pending::<Result<i64, Error>>(),
                    &tail,
                );
                if raw_pid(libc::SYS_getpid).as_raw() != mypid {
                    // Fork child. The correctly routed plain fork
                    // parked a ForkChild outcome: run the real
                    // finish (thread-start recorded) and leave as a
                    // reset child. A raw fall-through child instead
                    // surfaces as a plain Return here.
                    let reset = match outcome {
                        crate::tool_host::SyscallOutcome::ForkChild {
                            parent_tid: ft,
                            parent_pid: fp,
                            child_tid,
                            child_pid,
                        } => {
                            drop(tail_future);
                            drop(guest);
                            finish_fork_child(
                                &host,
                                parent_lease,
                                &mut event,
                                snapshot,
                                ForkChildContext {
                                    parent_tid: ft,
                                    parent_pid: fp,
                                    child_tid,
                                    child_pid,
                                    #[cfg(feature = "exec-native-injection")]
                                    native_exec_route_active: false,
                                },
                            );
                            let me = raw_pid(libc::SYS_gettid).as_raw();
                            EVENTS
                                .lock()
                                .unwrap()
                                .iter()
                                .any(|(name, tid)| *name == "start" && *tid == me)
                        }
                        _ => false,
                    };
                    if !reset {
                        count(0);
                    }
                    // SAFETY: _exit avoids inherited atexit state.
                    unsafe { libc::_exit(if reset { 0 } else { 73 }) };
                }
                drop(parent_lease);
                match outcome {
                    crate::tool_host::SyscallOutcome::Return(result) => {
                        let result = result.expect("tail clone3 failed");
                        if result > 0 {
                            // Two admitted shapes can return a tid:
                            // a plain-fork child (reaped below) or
                            // an admitted birth (stub writes seen).
                            let mut status = 0;
                            // Poll briefly: a fork child exits as
                            // soon as its poll returns, but the reap
                            // can still race its _exit. A born thread
                            // is not a child process, so waitpid keeps
                            // returning 0 for it (ECHILD only once the
                            // tid is meaningless as a pid; either way
                            // the probe distinguishes the two).
                            let mut waited = 0;
                            for _ in 0..200 {
                                // SAFETY: WNOHANG probe for a fork child.
                                waited = unsafe {
                                    libc::waitpid(result as libc::pid_t, &mut status, libc::WNOHANG)
                                };
                                if waited != 0 {
                                    break;
                                }
                                if FLIP_SEEN.load(Ordering::Acquire) != 0 {
                                    break;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(5));
                            }
                            if waited == result as libc::pid_t {
                                assert!(
                                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                                    "tail fork child failed: status {status:#x}"
                                );
                                count(3);
                            } else {
                                let mut seen = 0;
                                for _ in 0..200 {
                                    seen = FLIP_SEEN.load(Ordering::Acquire);
                                    if seen != 0 {
                                        break;
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(5));
                                }
                                assert_eq!(
                                    seen, result,
                                    "created thread {result} was not admitted through birth"
                                );
                                count(4);
                            }
                        } else {
                            count_result(result);
                            assert!(
                                [
                                    -i64::from(libc::EINVAL),
                                    -i64::from(Errno::EOPNOTSUPP.into_raw())
                                ]
                                .contains(&result),
                                "unexpected tail clone3 result {result}"
                            );
                        }
                    }
                    crate::tool_host::SyscallOutcome::ForkChild { .. } => {
                        // In the parent this outcome is unreachable
                        // (the fork returns in the child only); if it
                        // is ever observed here the loop above has
                        // already left via _exit in the child.
                        panic!("ForkChild observed in the tail parent");
                    }
                    _ => panic!("tail_inject did not park a result"),
                }
            }
            stop.store(true, Ordering::Release);
            flipper.join().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ToolSyscallRuntime;
    impl HostRuntime for ToolSyscallRuntime {
        fn fork_child_rebind(&self) {
            panic!("test does not dispatch fork")
        }
        fn emit_stage(&self, _stage: &[u8]) {}
        fn fork_child_reset(&self, _event: &SyscallEvent) {
            panic!("test does not dispatch fork")
        }
        fn cpuid_interception_enabled(&self) -> bool {
            false
        }
        fn exit_process_stats(&self, _tid: Pid) -> io::Result<()> {
            panic!("test does not dispatch exit")
        }
        fn read_clock(&self) -> io::Result<u64> {
            panic!("test does not read a clock")
        }
        fn signal_action_supported(&self, _number: i64, _args: [u64; 6]) -> bool {
            false
        }
        fn reserved_signal_mask(&self) -> u64 {
            1_u64 << (libc::SIGSYS - 1)
        }
    }

    /// A public Guest method alone grants no callback authority. The fresh
    /// subprocess avoids allocating Rust between fork and exec and installs the
    /// real filter with default SIGSYS disposition, without a Tool callback,
    /// fabricated guard, handler, or extra syscall allowance.
    #[test]
    fn tool_syscall_outside_callback_still_reaches_interception() {
        use std::io::Write;
        use std::os::unix::process::ExitStatusExt;
        const CHILD: &str = "REVERIE_TOOL_SYSCALL_TEST_CHILD";
        const TEST: &str =
            "guest::host::tests::tool_syscall_outside_callback_still_reaches_interception";
        const READY: &[u8] = b"tool-syscall-outside-ready\n";
        if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new(TEST)) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, TEST)
                .output()
                .unwrap();
            assert_eq!(output.status.signal(), Some(libc::SIGSYS), "{output:?}");
            assert_eq!(output.stderr, READY, "{output:?}");
            return;
        }

        assert!(!tool_callback_active());
        let mut filter =
            crate::seccomp::SeccompFilter::for_trusted_gate(crate::trap::trusted_gate()).unwrap();
        // Prewrite the actual config handshake; no server thread or pending
        // RPC survives installation. No operation below may send an RPC.
        let (client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let config = reverie_rpc_transport::codec::encode(&()).unwrap();
        peer.write_all(&(config.len() as u32).to_be_bytes())
            .unwrap();
        peer.write_all(&config).unwrap();
        let client = reverie_rpc_transport::BlockingRpcClient::<(), _>::from_connected_stream(
            super::super::rpc::GuestRpcStream::from(client),
            raw_pid(libc::SYS_gettid),
        )
        .unwrap();
        let rpc = CoordinatorRpc::from_live_client("unused-tool-syscall-test", client, |_, _| {
            panic!("Tool syscall test must not reconnect")
        })
        .unwrap();
        let mut event = SyscallEvent {
            number: libc::SYS_getpid,
            args: [0; 6],
            instruction_pointer: 0,
            result: 0,
            context: 0,
            dispatch: SyscallDispatch::InstalledHook,
            guest_pkru: None,
            unsupported_refusal: None,
        };
        let tail = TailResult::default();
        let mut state = ();
        let tid = raw_pid(libc::SYS_gettid);
        let guest = InGuest::<(), _> {
            event: &mut event,
            tid,
            pid: raw_pid(libc::SYS_getpid),
            ppid: None,
            state: &mut state,
            rpc: &rpc,
            native: None,
            tail: &tail,
            cpuid_interception: false,
            admit_threads: false,
            thread_birth: None,
            fork_parent_state: None,
            runtime: &ToolSyscallRuntime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: false,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: None,
            #[cfg(feature = "exec-native-injection")]
            native_exec_admitted: false,
            #[cfg(feature = "exec-native-injection")]
            native_exec_route_active: false,
            unsupported_refusal: None,
            injected_syscalls: 0,
        };
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        let mut unblock: libc::sigset_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        assert_eq!(unsafe { libc::sigemptyset(&mut unblock) }, 0);
        assert_eq!(unsafe { libc::sigaddset(&mut unblock, libc::SIGSYS) }, 0);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
                || libc::sigaction(libc::SIGSYS, &action, core::ptr::null_mut()) != 0
                || libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, core::ptr::null_mut()) != 0
                || filter.install().is_err()
            {
                super::super::support::exit_now(117);
            }
            if raw_syscall6(libc::SYS_getpid, [0; 6]) != i64::from(guest.pid.as_raw()) {
                super::super::support::exit_now(119);
            }
            if raw_syscall6(
                libc::SYS_write,
                [
                    libc::STDERR_FILENO as u64,
                    READY.as_ptr() as u64,
                    READY.len() as u64,
                    0,
                    0,
                    0,
                ],
            ) != READY.len() as i64
            {
                super::super::support::exit_now(120);
            }
            // SAFETY: getpid has no pointer or descriptor effects. No active
            // callback means the method must still use an intercepted site.
            let _ = guest.tool_syscall(Sysno::getpid, [0; 6]);
            super::super::support::exit_now(118);
        }
    }

    /// Outside the admitted Tool callback the spelling is unknown, even with
    /// the image's fact published, and nothing is executed.
    #[test]
    fn pidfd_self_spelling_outside_callback_executes_nothing() {
        pidfd_self_spelling_under_the_runtime_filter(
            "guest::host::tests::pidfd_self_spelling_outside_callback_executes_nothing",
            false,
        );
    }

    /// Inside the admitted Tool callback, under the runtime's real filter
    /// with no SIGSYS handler (so any syscall but the trusted gate's kills the
    /// process), the getter returns the fact the image published before the
    /// filter, repeatedly, making no syscall.
    #[test]
    fn pidfd_self_spelling_inside_callback_reads_the_published_fact_without_syscalls() {
        pidfd_self_spelling_under_the_runtime_filter(
            "guest::host::tests::pidfd_self_spelling_inside_callback_reads_the_published_fact_without_syscalls",
            true,
        );
    }

    /// Runs `test` again in a child process that publishes the image's fact,
    /// installs the runtime's real filter and asks for the spelling, inside a
    /// Tool callback or not.
    fn pidfd_self_spelling_under_the_runtime_filter(test: &str, inside: bool) {
        use std::io::Write;
        const CHILD: &str = "REVERIE_PIDFD_SELF_SPELLING_TEST_CHILD";
        const READY: &[u8] = b"pidfd-self-filter-ready\n";
        if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new(test)) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture", "--test-threads=1"])
                .env(CHILD, test)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert_eq!(output.stderr, READY, "{output:?}");
            return;
        }

        assert!(!tool_callback_active());
        // Published as the runtime publishes it, before its filter.
        let published = crate::guest::pidfd_self::initialize_before_runtime_filter();
        let mut filter =
            crate::seccomp::SeccompFilter::for_trusted_gate(crate::trap::trusted_gate()).unwrap();
        // Prewrite the actual config handshake; no server thread or pending
        // RPC survives installation. No operation below may send an RPC.
        let (client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let config = reverie_rpc_transport::codec::encode(&()).unwrap();
        peer.write_all(&(config.len() as u32).to_be_bytes())
            .unwrap();
        peer.write_all(&config).unwrap();
        let client = reverie_rpc_transport::BlockingRpcClient::<(), _>::from_connected_stream(
            super::super::rpc::GuestRpcStream::from(client),
            raw_pid(libc::SYS_gettid),
        )
        .unwrap();
        let rpc = CoordinatorRpc::from_live_client("unused-tool-syscall-test", client, |_, _| {
            panic!("Tool syscall test must not reconnect")
        })
        .unwrap();
        let mut event = SyscallEvent {
            number: libc::SYS_getpid,
            args: [0; 6],
            instruction_pointer: 0,
            result: 0,
            context: 0,
            dispatch: SyscallDispatch::InstalledHook,
            guest_pkru: None,
            unsupported_refusal: None,
        };
        let tail = TailResult::default();
        let mut state = ();
        let tid = raw_pid(libc::SYS_gettid);
        let guest = InGuest::<(), _> {
            event: &mut event,
            tid,
            pid: raw_pid(libc::SYS_getpid),
            ppid: None,
            state: &mut state,
            rpc: &rpc,
            native: None,
            tail: &tail,
            cpuid_interception: false,
            admit_threads: false,
            thread_birth: None,
            fork_parent_state: None,
            runtime: &ToolSyscallRuntime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: false,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: None,
            #[cfg(feature = "exec-native-injection")]
            native_exec_admitted: false,
            #[cfg(feature = "exec-native-injection")]
            native_exec_route_active: false,
            unsupported_refusal: None,
            injected_syscalls: 0,
        };
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        let mut unblock: libc::sigset_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        assert_eq!(unsafe { libc::sigemptyset(&mut unblock) }, 0);
        assert_eq!(unsafe { libc::sigaddset(&mut unblock, libc::SIGSYS) }, 0);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
                || libc::sigaction(libc::SIGSYS, &action, core::ptr::null_mut()) != 0
                || libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, core::ptr::null_mut()) != 0
                || filter.install().is_err()
            {
                super::super::support::exit_now(117);
            }
            if raw_syscall6(libc::SYS_getpid, [0; 6]) != i64::from(guest.pid.as_raw()) {
                super::super::support::exit_now(119);
            }
            if raw_syscall6(
                libc::SYS_write,
                [
                    libc::STDERR_FILENO as u64,
                    READY.as_ptr() as u64,
                    READY.len() as u64,
                    0,
                    0,
                    0,
                ],
            ) != READY.len() as i64
            {
                super::super::support::exit_now(120);
            }
            if inside {
                // Any syscall but the gate's would meet the filter and, with
                // SIGSYS at its default action, end the process.
                let _callback = crate::guest::support::ToolCallbackGuard::enter();
                for _ in 0..3 {
                    if guest.pidfd_self_spelling() != published {
                        super::super::support::exit_now(122);
                    }
                }
            } else if guest.pidfd_self_spelling() != reverie::PidfdSelfSpelling::Unknown {
                // Outside a Tool callback the spelling must be unknown with
                // nothing executed.
                super::super::support::exit_now(121);
            }
            super::super::support::exit_now(0);
        }
    }

    /// A Reverie error that carries an operating-system error, directly or in
    /// a Tool error's causes, is described by kind and number, never by the C
    /// library's message, which its `Debug` (what tool_fatal printed) fetches.
    #[test]
    fn reverie_errors_are_described_without_the_c_library_message() {
        let io = Error::Io(std::io::Error::from_raw_os_error(libc::EACCES));
        assert!(format!("{io:?}").contains("Permission denied"), "{io:?}");
        assert_eq!(describe_reverie_error(&io), "PermissionDenied (errno 13)");
        let tool = Error::Tool(
            std::io::Error::other(std::io::Error::from_raw_os_error(libc::ENOENT)).into(),
        );
        assert!(format!("{tool:?}").contains("No such file"), "{tool:?}");
        assert_eq!(describe_reverie_error(&tool), "NotFound (errno 2)");
        let errno = Error::Errno(reverie::Errno::EPERM);
        assert!(describe_reverie_error(&errno).contains("EPERM"));
    }

    #[test]
    fn only_key_zero_memory_is_admitted_for_signal_phase_one() {
        let exec = libc::PROT_EXEC as u64;
        let grows = (libc::PROT_EXEC | libc::PROT_GROWSDOWN) as u64;
        let grows_up = (libc::PROT_EXEC | libc::PROT_GROWSUP) as u64;
        let read_exec = (libc::PROT_READ | libc::PROT_EXEC) as u64;
        for number in [libc::SYS_mmap, libc::SYS_mprotect] {
            assert!(assigns_protection_key(number, [0, 4096, exec, 0, 0, 0]));
            assert!(assigns_protection_key(number, [0, 4096, grows, 0, 0, 0]));
            assert!(assigns_protection_key(number, [0, 4096, grows_up, 0, 0, 0]));
            assert!(!assigns_protection_key(
                number,
                [0, 4096, read_exec, 0, 0, 0]
            ));
            assert!(!assigns_protection_key(number, [0, 4096, 0, 0, 0, 0]));
        }
        let pkey = libc::SYS_pkey_mprotect;
        assert!(assigns_protection_key(pkey, [0, 4096, read_exec, 1, 0, 0]));
        assert!(!assigns_protection_key(pkey, [0, 4096, read_exec, 0, 0, 0]));
        assert!(!assigns_protection_key(
            pkey,
            [0, 4096, read_exec, u32::MAX as u64, 0, 0]
        ));
        assert!(assigns_protection_key(
            pkey,
            [0, 4096, exec, u32::MAX as u64, 0, 0]
        ));
        assert!(!assigns_protection_key(
            libc::SYS_munmap,
            [0, 4096, exec, 0, 0, 0]
        ));
    }

    #[test]
    fn reserve_zeroes_aligned_storage_for_types_without_a_zero_value() {
        let mut stack = LocalStack::new();
        let _ = stack.push(1_u8);
        let reference = stack.reserve::<&'static u64>().as_raw();
        let nonzero = stack.reserve::<core::num::NonZeroU64>().as_raw();
        for address in [reference, nonzero] {
            assert_eq!(address % core::mem::align_of::<u64>(), 0);
            // SAFETY: the stack owns these eight bytes; they are read as bytes.
            let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, 8) };
            assert_eq!(bytes, [0; 8]);
        }
        assert_eq!(stack.size(), 24);
    }

    /// A pidfd's inode is a birth identity only on pidfs. An anonymous inode,
    /// which every pidfd shared before pidfs, is rejected.
    #[test]
    fn only_a_pidfs_inode_is_a_birth_identity() {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
        assert!(pidfd >= 0, "{}", std::io::Error::last_os_error());
        let mut metadata: libc::stat = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(pidfd, &mut metadata) }, 0);
        // pidfs arrived in Linux 6.9; before it, pidfds have no identity.
        let mut name: libc::utsname = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::uname(&mut name) }, 0);
        let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let mut numbers = release
            .split(|c: char| !c.is_ascii_digit())
            .map(|part| part.parse::<u32>().unwrap_or(0));
        let version = (numbers.next().unwrap_or(0), numbers.next().unwrap_or(0));
        if version >= (6, 9) {
            assert_eq!(pidfs_identity(pidfd), Some(metadata.st_ino), "{release}");
            assert!(pidfs_available().is_ok(), "{release}");
        } else {
            assert_eq!(pidfs_identity(pidfd), None, "{release}");
            assert!(
                matches!(pidfs_available(), Err(CreationHookError::PidfsUnavailable)),
                "{release}"
            );
        }
        let anonymous = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(anonymous >= 0);
        assert_eq!(pidfs_identity(anonymous), None);
        unsafe {
            libc::close(pidfd);
            libc::close(anonymous);
        }
    }

    /// Only a PKRU that denies key 0's access or writes refuses the creation.
    #[test]
    fn guest_keys_deny_runtime_memory_only_when_key_0_is_restricted() {
        assert!(!guest_keys_deny_runtime_memory(None));
        assert!(!guest_keys_deny_runtime_memory(Some(0)));
        assert!(!guest_keys_deny_runtime_memory(Some(0x5555_5554)));
        assert!(guest_keys_deny_runtime_memory(Some(0b01)));
        assert!(guest_keys_deny_runtime_memory(Some(0b10)));
    }

    /// Only errors the guest's own call returns for the same reason reach
    /// the guest; ENOMEM, which the runtime's pidfd allocation can return,
    /// does not.
    #[test]
    fn only_the_guests_own_errors_reach_the_guest() {
        for number in [
            crate::arch::SYS_FORK.unwrap_or(libc::SYS_clone),
            libc::SYS_clone,
            libc::SYS_clone3,
        ] {
            assert!(errno_is_the_guests(number, libc::EAGAIN));
            assert!(errno_is_the_guests(number, libc::ENOSPC));
            for errno in [
                libc::ENOMEM,
                libc::EMFILE,
                libc::ENFILE,
                libc::EFAULT,
                libc::EPERM,
            ] {
                assert!(!errno_is_the_guests(number, errno), "{number} {errno}");
            }
        }
        assert!(errno_is_the_guests(libc::SYS_clone3, libc::E2BIG));
        assert!(!errno_is_the_guests(
            crate::arch::SYS_FORK.unwrap_or(libc::SYS_clone),
            libc::E2BIG
        ));
        assert!(!errno_is_the_guests(
            crate::arch::SYS_FORK.unwrap_or(libc::SYS_clone),
            libc::ENOSYS
        ));
    }

    /// Linux range-checks a whole clone3 record before reading any of it: a
    /// record ending past the highest user address is EFAULT, even with a
    /// nonzero byte in a readable part of its tail. Past the four-level limit
    /// but within the five-level one, the paging mode decides, so it is
    /// refused. Neither case reads memory.
    #[test]
    fn a_clone3_record_past_user_memory_is_range_checked_first() {
        let mut record = [0_u64; CLONE_ARGS_SIZE_LIMIT / 8];
        let failed =
            copy_guest_clone_args((FIVE_LEVEL_USER_LIMIT - 200) as u64, 300, None, &mut record);
        assert!(matches!(failed, Err(Unperformed::Failed(libc::EFAULT))));
        let refused =
            copy_guest_clone_args((FOUR_LEVEL_USER_LIMIT - 200) as u64, 300, None, &mut record);
        assert!(matches!(
            refused,
            Err(Unperformed::Refused(CreationRefusal::ArgumentsUnreadable))
        ));
    }

    /// A parent TID output overlapping the runtime's four-byte pidfd output
    /// at any offset is refused before the call; an adjacent one is not, and
    /// addresses near the top of the range do not wrap.
    #[test]
    fn a_parent_tid_overlapping_the_pidfd_output_is_refused() {
        let pidfd = 0x7000_u64;
        let set = libc::CLONE_PARENT_SETTID as u64 | libc::CLONE_PIDFD as u64;
        for offset in -3_i64..=3 {
            let parent_tid = pidfd.wrapping_add_signed(offset);
            assert!(
                parent_tid_aliases_pidfd(&[set, pidfd, 0, parent_tid]),
                "{offset}"
            );
        }
        for offset in [-4_i64, 4, 8, -8] {
            let parent_tid = pidfd.wrapping_add_signed(offset);
            assert!(
                !parent_tid_aliases_pidfd(&[set, pidfd, 0, parent_tid]),
                "{offset}"
            );
        }
        let unset = libc::CLONE_PIDFD as u64;
        assert!(!parent_tid_aliases_pidfd(&[unset, pidfd, 0, pidfd]));
        assert!(parent_tid_aliases_pidfd(&[
            set,
            u64::MAX - 1,
            0,
            u64::MAX - 2
        ]));
        assert!(!parent_tid_aliases_pidfd(&[set, u64::MAX - 1, 0, 0]));
    }

    /// The pidfd output lives in a private anonymous page of its own, which
    /// no other mapping can alias, and the same page is used every time.
    #[test]
    fn the_pidfd_output_is_a_private_anonymous_page() {
        let address = creation_storage().unwrap();
        assert_eq!(creation_storage().unwrap(), address);
        assert_eq!(address % 4096, 0);
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let line = maps
            .lines()
            .find(|line| {
                let (range, _) = line.split_once(' ').unwrap();
                let (start, end) = range.split_once('-').unwrap();
                let start = u64::from_str_radix(start, 16).unwrap();
                let end = u64::from_str_radix(end, 16).unwrap();
                (start..end).contains(&address)
            })
            .unwrap();
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields[1], "rw-p", "{line}");
        assert_eq!(fields[4], "0", "anonymous, no inode: {line}");
        assert!(fields.len() == 5 || fields[5].starts_with('['), "{line}");
    }

    /// The copied clone3 record is checked as a plain fork itself: a copy that
    /// asks for CLONE_PIDFD, CLONE_FILES, a stack, another exit signal or a
    /// set_tid is not, whatever the earlier classification saw.
    #[test]
    fn a_copied_clone3_record_must_still_be_a_plain_fork() {
        let mut plain = [0_u64; 11];
        plain[4] = libc::SIGCHLD as u64;
        assert!(clone_args_are_plain_fork(&plain));
        plain[0] = libc::CLONE_PARENT_SETTID as u64 | libc::CLONE_CHILD_SETTID as u64;
        assert!(clone_args_are_plain_fork(&plain));
        for (field, value) in [
            (0, libc::CLONE_PIDFD as u64),
            (0, libc::CLONE_FILES as u64),
            (0, libc::CLONE_VM as u64),
            (4, libc::SIGUSR1 as u64),
            (5, 0x1000),
            (6, 0x1000),
            (8, 0x1000),
            (9, 1),
            (10, 3),
        ] {
            let mut changed = plain;
            if field == 0 {
                changed[0] |= value;
            } else {
                changed[field] = value;
            }
            assert!(!clone_args_are_plain_fork(&changed), "{field} {value:#x}");
        }
    }

    /// A guest memory handle reads and writes this process's memory until its
    /// dispatch stages an injection that ends the guest; from then on every
    /// read and write fails with ESRCH and copies nothing, through a handle
    /// obtained before as through a new one.
    #[test]
    fn guest_memory_is_refused_once_the_guest_is_ending() {
        let tail = TailResult::default();
        let mut before = GuestMemory::new(&tail);
        let mut word = 0_u64;
        let address = AddrMut::from_raw(&raw mut word as usize).unwrap();
        before.write_value(address, &1_u64).unwrap();
        assert_eq!(word, 1);
        tail.set_exit(libc::SYS_exit_group, [0; 6]);
        assert_eq!(before.write_value(address, &2_u64), Err(Errno::ESRCH));
        let mut after = GuestMemory::new(&tail);
        assert_eq!(after.write_value(address, &3_u64), Err(Errno::ESRCH));
        assert_eq!(
            before.read_value::<_, u64>(Addr::from_raw(&raw const word as usize).unwrap()),
            Err(Errno::ESRCH)
        );
        assert_eq!(word, 1);
        // Primitives retain ESRCH even for empty buffers. The trait's empty
        // exact-copy shortcuts do not call a primitive and remain successful.
        assert_eq!(
            before.read(Addr::from_raw(address.as_raw()).unwrap(), &mut []),
            Err(Errno::ESRCH)
        );
        assert_eq!(after.write(address.cast(), &[]), Err(Errno::ESRCH));
        assert_eq!(before.read_vectored(&[], &mut []), Err(Errno::ESRCH));
        assert_eq!(after.write_vectored(&[], &mut []), Err(Errno::ESRCH));
        assert_eq!(
            before.read_exact(Addr::from_raw(address.as_raw()).unwrap(), &mut []),
            Ok(())
        );
        assert_eq!(after.write_exact(address.cast(), &[]), Ok(()));
    }

    /// A memory handle alone grants no private-gate authority. The real filter
    /// must still trap its ordinary syscall when no Tool callback is active.
    #[test]
    fn guest_memory_outside_callback_still_reaches_interception() {
        assert!(!tool_callback_active()); // Initialize callback TLS before fork.
        let mut filter =
            crate::seccomp::SeccompFilter::for_trusted_gate(crate::trap::trusted_gate()).unwrap();
        let tail = TailResult::default();
        let memory = GuestMemory::new(&tail);
        let source = [0x5a_u8; 8];
        let address = Addr::from_ptr(source.as_ptr()).unwrap();
        let mut destination = [0_u8; 8];
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction = libc::SIG_DFL;
        let mut unblock: libc::sigset_t = unsafe { core::mem::zeroed() };
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        assert_eq!(unsafe { libc::sigemptyset(&mut unblock) }, 0);
        assert_eq!(unsafe { libc::sigaddset(&mut unblock, libc::SIGSYS) }, 0);
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let child = unsafe { libc::fork() };
        if child == 0 {
            // Prepare storage before fork, and leave through the raw exit path
            // on setup failure rather than unwinding or running destructors.
            unsafe {
                if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
                    || libc::sigaction(libc::SIGSYS, &action, core::ptr::null_mut()) != 0
                    || libc::sigprocmask(libc::SIG_UNBLOCK, &unblock, core::ptr::null_mut()) != 0
                {
                    super::super::support::exit_now(101);
                }
                let pid = raw_syscall6(libc::SYS_getpid, [0; 6]);
                if pid <= 0 || filter.install().is_err() {
                    super::super::support::exit_now(102);
                }
                if raw_syscall6(libc::SYS_getpid, [0; 6]) != pid {
                    super::super::support::exit_now(103);
                }
                // With no handler, the first ordinary memory syscall must
                // terminate with SIGSYS. An unconditional private gate would
                // return here and fail the parent's exact signal assertion.
                let _ = memory.read(address, &mut destination);
                super::super::support::exit_now(104);
            }
        }
        assert!(child > 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFSIGNALED(status), "child status {status}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGSYS, "{status}");
    }

    /// A read's address conversion is the caller's code, and runs before the
    /// ending check: a conversion that stages an ending (as a Tool's
    /// conversion that abandons a SIGKILL injection does) gets ESRCH and the
    /// read copies nothing. (Before, the check ran first, and the read then
    /// copied.)
    #[test]
    fn a_reads_address_conversion_runs_before_the_ending_check() {
        struct Ending<'t> {
            tail: &'t TailResult,
            address: usize,
        }
        impl<'a> From<Ending<'_>> for Addr<'a, u8> {
            fn from(ending: Ending<'_>) -> Self {
                ending.tail.set_exit(libc::SYS_exit_group, [0; 6]);
                Addr::from_raw(ending.address).unwrap()
            }
        }
        let tail = TailResult::default();
        let memory = GuestMemory::new(&tail);
        let word = 0x5a5a_u64;
        let mut buffer = [0_u8; 8];
        let read = memory.read(
            Ending {
                tail: &tail,
                address: (&raw const word) as usize,
            },
            &mut buffer,
        );
        assert_eq!(read, Err(Errno::ESRCH));
        assert_eq!(buffer, [0; 8]);
    }

    /// A hook cannot be registered before the runtime's own filter is
    /// installed (this test process has none), and nothing is registered.
    #[test]
    fn a_hook_is_refused_before_interception_is_installed() {
        fn hook(_: PhysicalCreation) -> io::Result<()> {
            Ok(())
        }
        assert!(matches!(
            set_physical_creation_hook(hook),
            Err(CreationHookError::InterceptionNotInstalled)
        ));
        assert!(CREATION_HOOK.get().is_none());
    }

    /// seccomp's operation and prctl's option are read at the kernel's
    /// widths, so high bits cannot hide a filter installation.
    #[test]
    fn filter_installation_is_recognised_at_kernel_widths() {
        let high = 1_u64 << 32;
        let seccomp = u64::from(libc::SECCOMP_SET_MODE_FILTER);
        assert!(installs_seccomp_filter(
            libc::SYS_seccomp,
            [seccomp, 0, 0, 0, 0, 0]
        ));
        assert!(installs_seccomp_filter(
            libc::SYS_seccomp,
            [high | seccomp, 0, 0, 0, 0, 0]
        ));
        let prctl = libc::PR_SET_SECCOMP as u64;
        let mode = u64::from(libc::SECCOMP_MODE_FILTER);
        assert!(installs_seccomp_filter(
            libc::SYS_prctl,
            [high | prctl, mode, 0, 0, 0, 0]
        ));
        assert!(!installs_seccomp_filter(
            libc::SYS_prctl,
            [prctl, high | mode, 0, 0, 0, 0]
        ));
        assert!(!installs_seccomp_filter(
            libc::SYS_seccomp,
            [u64::from(libc::SECCOMP_GET_ACTION_AVAIL), 0, 0, 0, 0, 0]
        ));
    }

    #[cfg(test)]
    mod tail_start_route_tests {
        use std::future::Future;
        use std::io::Write;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::task::Context;
        use std::task::Poll;
        use std::task::Waker;

        use super::*;

        /// The old ToolSyscallRuntime deliberately denies all signal admission
        /// for its unrelated interception control. Reuse its other services,
        /// but use the actual installed runtime's signal predicate here so an
        /// ordinary exit reaches the production tail-ending path.
        struct TailStartRuntime;
        impl HostRuntime for TailStartRuntime {
            fn fork_child_rebind(&self) {
                super::ToolSyscallRuntime.fork_child_rebind()
            }
            fn emit_stage(&self, stage: &[u8]) {
                super::ToolSyscallRuntime.emit_stage(stage)
            }
            fn fork_child_reset(&self, event: &SyscallEvent) {
                super::ToolSyscallRuntime.fork_child_reset(event)
            }
            fn cpuid_interception_enabled(&self) -> bool {
                super::ToolSyscallRuntime.cpuid_interception_enabled()
            }
            fn exit_process_stats(&self, tid: Pid) -> io::Result<()> {
                super::ToolSyscallRuntime.exit_process_stats(tid)
            }
            fn read_clock(&self) -> io::Result<u64> {
                super::ToolSyscallRuntime.read_clock()
            }
            fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
                crate::guest::signal::signal_action_supported(number, args)
            }
            fn reserved_signal_mask(&self) -> u64 {
                super::ToolSyscallRuntime.reserved_signal_mask()
            }
        }

        /// TailStartRuntime with an armed exec watch.
        struct WatchedRuntime;
        impl HostRuntime for WatchedRuntime {
            fn fork_child_rebind(&self) {
                TailStartRuntime.fork_child_rebind()
            }
            fn emit_stage(&self, stage: &[u8]) {
                TailStartRuntime.emit_stage(stage)
            }
            fn fork_child_reset(&self, event: &SyscallEvent) {
                TailStartRuntime.fork_child_reset(event)
            }
            fn cpuid_interception_enabled(&self) -> bool {
                TailStartRuntime.cpuid_interception_enabled()
            }
            fn exit_process_stats(&self, tid: Pid) -> io::Result<()> {
                TailStartRuntime.exit_process_stats(tid)
            }
            fn read_clock(&self) -> io::Result<u64> {
                TailStartRuntime.read_clock()
            }
            fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
                TailStartRuntime.signal_action_supported(number, args)
            }
            fn reserved_signal_mask(&self) -> u64 {
                TailStartRuntime.reserved_signal_mask()
            }
            fn exec_watch_armed(&self) -> bool {
                true
            }
        }

        /// The guard is the backstop of the clone3 copy discipline:
        /// every legitimate clone3 is intercepted and forwarded from
        /// a checked copy before the guard, so ANY clone3 reaching
        /// it — plain fork, thread birth, KernelDecides, or
        /// unsupported, admission on or off — refuses here instead
        /// of falling through to a raw guest-pointer forward.
        #[test]
        fn guard_refuses_every_clone3_shape() {
            const REQUIRED: u64 = (libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD) as u64;
            let args = |fields: &[u64; 11]| [fields.as_ptr() as u64, 88, 0, 0, 0, 0];
            for admit in [false, true] {
                // Plain fork.
                let mut fields = [0_u64; 11];
                fields[4] = libc::SIGCHLD as u64;
                assert_eq!(
                    injected_syscall_guard(
                        &TailStartRuntime,
                        libc::SYS_clone3,
                        args(&fields),
                        admit
                    ),
                    Some(Errno::EOPNOTSUPP),
                    "plain-fork clone3 must never reach the generic forward (admit={admit})"
                );
                // Thread birth.
                fields = [0; 11];
                fields[0] = REQUIRED;
                fields[5] = 0x1000;
                fields[6] = 0x8000;
                assert_eq!(
                    injected_syscall_guard(
                        &TailStartRuntime,
                        libc::SYS_clone3,
                        args(&fields),
                        admit
                    ),
                    Some(Errno::EOPNOTSUPP)
                );
                // KernelDecides (missing SIGHAND).
                fields[0] = (libc::CLONE_VM | libc::CLONE_THREAD) as u64;
                assert_eq!(
                    injected_syscall_guard(
                        &TailStartRuntime,
                        libc::SYS_clone3,
                        args(&fields),
                        admit
                    ),
                    Some(Errno::EOPNOTSUPP)
                );
                // Unsupported (set_tid).
                fields[0] = REQUIRED;
                fields[8] = 1;
                assert_eq!(
                    injected_syscall_guard(
                        &TailStartRuntime,
                        libc::SYS_clone3,
                        args(&fields),
                        admit
                    ),
                    Some(Errno::EOPNOTSUPP)
                );
            }
        }

        #[test]
        fn exec_guard_refuses_unwatched_and_forwards_watched() {
            for number in [libc::SYS_execve, libc::SYS_execveat] {
                assert_eq!(
                    injected_syscall_guard(&TailStartRuntime, number, [0; 6], false),
                    Some(Errno::EOPNOTSUPP)
                );
                assert_eq!(
                    injected_syscall_guard(&WatchedRuntime, number, [0; 6], false),
                    None
                );
            }
            // The watch scopes to exec only: a thread-creating clone
            // (non-null child stack via clone3) stays refused.
            assert_eq!(
                injected_syscall_guard(&WatchedRuntime, libc::SYS_clone3, [0; 6], false),
                Some(Errno::EOPNOTSUPP)
            );
            assert_eq!(
                injected_syscall_guard(&WatchedRuntime, libc::SYS_getpid, [0; 6], false),
                None
            );
        }

        static EVENTS: AtomicUsize = AtomicUsize::new(0);
        fn observe(tid: Pid, number: Sysno) {
            assert!(tid.as_raw() > 0);
            assert_eq!(number, Sysno::exit_group);
            EVENTS.fetch_add(1, Ordering::SeqCst);
            eprintln!("TAIL_START_OBSERVED");
        }

        #[test]
        fn actual_tail_scope_and_ending_reentry_observe_once() {
            const TEST: &str = "guest::host::tests::tail_start_route_tests::actual_tail_scope_and_ending_reentry_observe_once";
            const MODE: &str = "REVERIE_TAIL_START_ROUTE_MODE";
            let Some(mode) = std::env::var_os(MODE) else {
                for mode in ["ending", "refused"] {
                    let output = std::process::Command::new(std::env::current_exe().unwrap())
                        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                        .env(MODE, mode)
                        .output()
                        .unwrap();
                    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
                    if mode == "ending" {
                        assert!(output.status.success(), "{output:?}");
                        assert_eq!(
                            stderr.matches("TAIL_START_OBSERVED").count(),
                            1,
                            "{output:?}"
                        );
                        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
                    } else {
                        assert_eq!(output.status.code(), Some(125), "{output:?}");
                        assert!(!stderr.contains("TAIL_START_OBSERVED"), "{output:?}");
                        assert!(
                            stderr.contains("outside a syscall handler is unsupported"),
                            "{output:?}"
                        );
                    }
                }
                return;
            };
            // Check real production admission, not a forced ending flag or
            // a bypass of injected_syscall_guard. The scope-refusal child still
            // fails earlier at the actual outside-handler check.
            assert!(
                injected_syscall_guard(&TailStartRuntime, libc::SYS_exit_group, [0; 6], false)
                    .is_none()
            );
            assert!(
                injected_syscall_guard(&TailStartRuntime, libc::SYS_getpid, [0; 6], false)
                    .is_none()
            );
            reverie::set_tail_start_forwarder(observe).unwrap();
            let (client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let config = reverie_rpc_transport::codec::encode(&()).unwrap();
            peer.write_all(&(config.len() as u32).to_be_bytes())
                .unwrap();
            peer.write_all(&config).unwrap();
            let tid = raw_pid(libc::SYS_gettid);
            let client = reverie_rpc_transport::BlockingRpcClient::<(), _>::from_connected_stream(
                crate::guest::rpc::GuestRpcStream::from(client),
                tid,
            )
            .unwrap();
            let rpc = CoordinatorRpc::from_live_client("unused-tail-route-test", client, |_, _| {
                panic!("tail control must not reconnect")
            })
            .unwrap();
            let mut event = SyscallEvent {
                number: libc::SYS_exit_group,
                args: [0; 6],
                instruction_pointer: 0,
                result: 0,
                context: 0,
                dispatch: SyscallDispatch::InstalledHook,
                guest_pkru: None,
                unsupported_refusal: None,
            };
            let tail = TailResult::default();
            let mut state = ();
            let mut guest = InGuest::<(), _> {
                event: &mut event,
                tid,
                pid: raw_pid(libc::SYS_getpid),
                ppid: None,
                state: &mut state,
                rpc: &rpc,
                native: None,
                tail: &tail,
                cpuid_interception: false,
                admit_threads: false,
                thread_birth: None,
                fork_parent_state: None,
                runtime: &TailStartRuntime,
                staged_signals: Vec::new(),
                staged_signal_delivery: false,
                in_syscall_handler: false,
                #[cfg(feature = "exec-native-injection")]
                exec: None,
                #[cfg(feature = "exec-native-injection")]
                mapping_driver: None,
                #[cfg(feature = "exec-native-injection")]
                native_exec_admitted: false,
                #[cfg(feature = "exec-native-injection")]
                native_exec_route_active: false,
                unsupported_refusal: None,
                injected_syscalls: 0,
            };
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            if mode == "refused" {
                let mut future =
                    core::pin::pin!(guest.tail_inject(reverie::syscalls::Getpid::default()));
                let _ = future.as_mut().poll(&mut context);
                panic!("real scope refusal must terminate the isolated test child");
            }
            {
                let mut future =
                    core::pin::pin!(guest.tail_inject(reverie::syscalls::ExitGroup::default()));
                assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
                assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
                assert_eq!(EVENTS.load(Ordering::SeqCst), 1);
            }
            assert!(tail.ending());
            assert_eq!(EVENTS.load(Ordering::SeqCst), 1);
            {
                let mut future =
                    core::pin::pin!(guest.tail_inject(reverie::syscalls::ExitGroup::default()));
                assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
            }
            assert_eq!(EVENTS.load(Ordering::SeqCst), 1);
        }
    }

    fn needs_drop_of<T: 'static>(_: &'static std::thread::LocalKey<T>) -> bool {
        core::mem::needs_drop::<T>()
    }

    /// `ToolHost::from_parts` touches `COMMITTED_STACKS`, and for an
    /// in-guest runtime it runs while the preload's constructor installs
    /// the Tool, before the guest's `main`. std registers a thread-exit
    /// destructor for a thread-local exactly when its type needs dropping,
    /// through libc's `__cxa_thread_atexit_impl`, which allocates from the
    /// C library heap: the guest's heap then reached `main` holding libc's
    /// per-thread cache and that record (704 bytes with glibc 2.34).
    #[test]
    fn committed_stacks_registers_no_thread_exit_destructor() {
        assert!(!needs_drop_of(&COMMITTED_STACKS));
    }

    /// With no destructor, ending a dispatch is the only thing that frees
    /// the vector's buffer: a thread exits holding whatever the last
    /// dispatch scope left behind.
    #[test]
    fn dispatch_scratch_scope_releases_the_committed_stack_buffer() {
        let capacity = || COMMITTED_STACKS.with(|stacks| stacks.borrow().capacity());
        let scope = DispatchScratchScope::enter();
        retain_committed_stack(vec![0; STACK_CAPACITY].into_boxed_slice());
        assert_ne!(capacity(), 0);
        drop(scope);
        assert_eq!(capacity(), 0);
    }

    /// Regression for the W7 TLS-teardown abort: a guest thread's last
    /// syscalls dispatch after libc destroyed that thread's TLS
    /// (`exit_group` after `exit()` ran the main thread's
    /// `__cxa_thread_atexit` destructors, the thread-exit syscall after
    /// pthread teardown on a worker), and every dispatch enters
    /// [`DispatchScratchScope`]. Its `COMMITTED_STACKS` access must
    /// survive libc's TLS teardown instead of panicking in the nounwind
    /// trap handler. The probe TLS below is touched before
    /// `COMMITTED_STACKS` on each thread, so its destructor runs during
    /// that teardown and re-enters the scope exactly like that late
    /// dispatch. Subprocess-isolated: the failure this guards against is
    /// a process abort, not a catchable panic.
    #[test]
    fn dispatch_scratch_scope_survives_tls_teardown_at_exit() {
        use std::io::Write;
        const CHILD: &str = "REVERIE_TLS_TEARDOWN_TEST_CHILD";
        const TEST: &str =
            "guest::host::tests::dispatch_scratch_scope_survives_tls_teardown_at_exit";
        const READY: &[u8] = b"tls-teardown-ready\n";
        if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new(TEST)) {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, TEST)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert_eq!(output.stderr, READY, "{output:?}");
            return;
        }

        struct ReenterOnTeardown;
        impl Drop for ReenterOnTeardown {
            fn drop(&mut self) {
                let scope = DispatchScratchScope::enter();
                retain_committed_stack(vec![0; STACK_CAPACITY].into_boxed_slice());
                drop(scope);
            }
        }
        thread_local! {
            static REENTER_ON_TEARDOWN: ReenterOnTeardown = const { ReenterOnTeardown };
        }

        let states = std::sync::Arc::new(super::thread_lease::ThreadStates::<u32>::new());
        // Worker-thread teardown: the probe destructor re-enters the
        // scope during pthread exit's TLS teardown, while the thread
        // holds a live lease.
        let worker_states = std::sync::Arc::clone(&states);
        std::thread::spawn(move || {
            REENTER_ON_TEARDOWN.with(|_| {});
            let mut lease = worker_states.checkout(4243, || 7).unwrap();
            *lease.state_mut() += 1;
            let scope = DispatchScratchScope::enter();
            retain_committed_stack(vec![0; STACK_CAPACITY].into_boxed_slice());
            drop(scope);
            drop(lease);
        })
        .join()
        .unwrap();

        // exit()-driven teardown on this dispatching thread, modeling the
        // guest main thread: libc exit() runs this thread's TLS
        // destructors, after which the exit_group dispatch re-enters the
        // scope via the probe destructor. The lease stays live across
        // exit() on purpose.
        REENTER_ON_TEARDOWN.with(|_| {});
        let _lease = states.checkout(4242, || 7).unwrap();
        let scope = DispatchScratchScope::enter();
        retain_committed_stack(vec![0; STACK_CAPACITY].into_boxed_slice());
        drop(scope);
        std::io::stderr().write_all(READY).unwrap();
        // SAFETY: exit runs this thread's TLS destructors and then
        // terminates; the intentionally leaked lease/Arc are reclaimed by
        // process teardown.
        unsafe { libc::exit(0) };
    }
}
