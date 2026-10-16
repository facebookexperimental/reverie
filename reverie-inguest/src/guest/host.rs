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
use super::rpc::CoordinatorRpc;
use super::signal::core_dump_expected;
use super::signal::current_pending_set;
use super::signal::self_directed_fatal_signal;
use super::signal::signal_ends_process_now;
use crate::sync::SpinMutex;
use crate::tool_host::CallbackOutcome;
use crate::tool_host::DrivenSyscall;
use crate::tool_host::TailResult;
use crate::tool_host::drive_callback;
use crate::tool_host::drive_ready;
use crate::tool_host::drive_tool_syscall;
use crate::trap::raw_syscall6;

#[cfg(feature = "exec-private-init")]
#[path = "image_guest.rs"]
mod image_guest;
#[cfg(all(test, feature = "exec-native-injection"))]
#[path = "native_exec_tests.rs"]
mod native_exec_tests;
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
    unsafe { super::sigalrm::intercept(&policy, number, args) }
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

static COMMITTED_STACKS: SpinMutex<Vec<Box<[u8]>>> = SpinMutex::new(Vec::new());

struct DispatchScratchScope {
    _allocation_scope: super::alloc::DispatchAllocationScope,
}

impl DispatchScratchScope {
    fn enter() -> Self {
        COMMITTED_STACKS.lock().clear();
        Self {
            _allocation_scope: super::alloc::enter_dispatch(),
        }
    }
}

impl Drop for DispatchScratchScope {
    fn drop(&mut self) {
        COMMITTED_STACKS.lock().clear();
    }
}

/// Hosts one Reverie Tool inside the guest process: owns the Tool, its
/// per-thread state and its coordinator connection, and runs each guest
/// syscall or instruction event through the Tool's handlers. The backend that
/// owns the trap and hook paths supplies `R`, the runtime services the host
/// calls back into.
pub struct ToolHost<T: Tool, R: HostRuntime> {
    tool: SpinMutex<Option<T>>,
    rpc: CoordinatorRpc<T::GlobalState>,
    root_pid: Pid,
    subscriptions: HashSet<Sysno>,
    cpuid_interception: bool,
    states: SpinMutex<HashMap<i32, T::ThreadState>>,
    runtime: R,
    #[cfg(feature = "exec-private-successor")]
    prepared_exec: SpinMutex<Option<PreparedExecState<T>>>,
    #[cfg(feature = "exec-native-injection")]
    native_exec_driver: Option<std::sync::Arc<dyn super::native_exec::NativeExecDriver<T>>>,
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

    /// Install an already-admitted continuation's Tool state for this thread.
    ///
    /// The owner must restore every field of its `ThreadState`, including its
    /// logical time, before the first dispatch. The saved state must already
    /// have completed the Tool's thread-start and post-exec callbacks; restoring
    /// it does not repeat those callbacks. A thread with existing state, or a
    /// dispatch currently holding the state lock, is refused without replacing
    /// anything. No production backend calls this inactive input seam.
    pub fn restore_current_thread_state(&self, state: T::ThreadState) -> io::Result<()> {
        #[cfg(feature = "exec-private-successor")]
        if self
            .prepared_exec
            .try_lock()
            .is_none_or(|pending| pending.is_some())
        {
            return Err(io::Error::other(
                "successor lifecycle state is not complete",
            ));
        }
        let _allocation_scope = super::alloc::enter_dispatch();
        let tid = raw_pid(libc::SYS_gettid).as_raw();
        let mut states = self.states.try_lock().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "Tool state dispatch is active")
        })?;
        if let std::collections::hash_map::Entry::Vacant(entry) = states.entry(tid) {
            entry.insert(state);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Tool state already exists for this thread",
            ))
        }
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
        COMMITTED_STACKS.lock().clear();
        Self {
            tool: SpinMutex::new(Some(tool)),
            rpc,
            root_pid,
            subscriptions,
            cpuid_interception,
            states: SpinMutex::new(HashMap::new()),
            runtime,
            #[cfg(feature = "exec-private-successor")]
            prepared_exec: SpinMutex::new(None),
            #[cfg(feature = "exec-native-injection")]
            native_exec_driver: None,
        }
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
        let states = self.states.try_lock().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "Tool state dispatch is active")
        })?;
        if !states.is_empty() {
            return Err(io::Error::other(
                "native exec driver installation follows dispatch",
            ));
        }
        drop(states);
        self.native_exec_driver = Some(driver);
        Ok(())
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
            let states = self.states.try_lock().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "successor state dispatch is active",
                )
            })?;
            let mut pending = self.prepared_exec.try_lock().ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "successor restoration is active")
            })?;
            if !states.is_empty() || pending.is_some() {
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
        let tool_slot = self.tool.try_lock().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "successor Tool callback is active",
            )
        })?;
        let tool = tool_slot
            .as_ref()
            .ok_or_else(|| io::Error::other("successor Tool is absent"))?;
        let mut states = self.states.try_lock().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "successor state dispatch is active",
            )
        })?;
        let mut pending = self.prepared_exec.try_lock().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "successor post-exec is active")
        })?;
        let restored = pending
            .as_mut()
            .ok_or_else(|| io::Error::other("successor state is absent"))?;
        if !states.is_empty()
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
        states.insert(tid.as_raw(), completed.state);
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
        let tool_slot = self.tool.try_lock().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "InitialImage Tool callback is active",
            )
        })?;
        let tool = tool_slot
            .as_ref()
            .ok_or_else(|| io::Error::other("InitialImage Tool is absent"))?;
        let mut states = self.states.try_lock().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "InitialImage state dispatch is active",
            )
        })?;
        if states.contains_key(&tid.as_raw()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "InitialImage thread state already exists",
            ));
        }
        let mut state = tool.init_thread_state(tid, None);
        #[cfg(feature = "exec-native-injection")]
        if let Some(driver) = &self.native_exec_driver {
            driver.bind_initial_state(tool, &mut state, tid.as_raw())?;
        }
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
        states.insert(tid.as_raw(), state);
        if let Err(error) = permit.complete() {
            states.remove(&tid.as_raw());
            return Err(error);
        }
        Ok(())
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
        #[cfg(feature = "exec-private-successor")]
        if self
            .prepared_exec
            .try_lock()
            .is_none_or(|pending| pending.is_some())
        {
            unsafe { super::exec_private::initialization_failed(core::ptr::null_mut()) }
        }

        let _scratch_scope = DispatchScratchScope::enter();
        #[cfg(feature = "exec-native-injection")]
        let original_event = *event;
        let tid = raw_pid(libc::SYS_gettid);
        let pid = raw_pid(libc::SYS_getpid);
        let ppid = (pid != self.root_pid).then(|| raw_pid(libc::SYS_getppid));

        // These process-wide locks are valid only while thread creation stays
        // fail-closed. A scheduler RPC may block until a sibling runs, so MT
        // support requires per-thread RPC/state ownership before relaxing the
        // clone guard below.
        let mut tool_slot = self.tool.lock();
        let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
        let mut states = self.states.lock();
        let is_new = !states.contains_key(&tid.as_raw());
        let state = states
            .entry(tid.as_raw())
            .or_insert_with(|| tool.init_thread_state(tid, None));
        let tail = TailResult::default();
        let mut guest = InGuest::<T, R> {
            event,
            tid,
            pid,
            ppid,
            state,
            rpc: &self.rpc,
            tail: &tail,
            cpuid_interception: self.cpuid_interception,
            fork_parent_state: None,
            runtime: &self.runtime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: false,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: self.native_exec_driver.as_deref(),
            unsupported_refusal: None,
        };

        if is_new {
            match callback_result(drive_callback(tool.handle_thread_start(&mut guest), &tail)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tool_fatal(124, &error),
                Err(ending) => {
                    drop(guest);
                    finish_ending(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        (tid, pid),
                        ending,
                    )
                }
            }
            // A signal the thread-start callback sent is delivered before the
            // next callback runs, as a tracer delivers it when the thread
            // resumes.
            if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
                drop(guest);
                finish_ending(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    &self.runtime,
                    (tid, pid),
                    ending,
                );
            }
        }

        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-liteinst-post-exec): The kernel exec'd the guest
        // image before this LD_PRELOAD backend attached, so — unlike the ptrace
        // backend — the `Tool::handle_post_exec` lifecycle callback never fired.
        // A Tool such as Detcore relies on it to determinize the auxv AT_RANDOM
        // vector and to advance per-thread state (e.g. its seeded PRNG) exactly
        // as the ptrace backend does; without it the guest-visible getrandom(2)
        // stream is offset relative to ptrace and cross-backend parity fails.
        // The guest genuinely did execve into this image, so emitting the event
        // once for the root process's main thread restores contract parity. It
        // is intentionally not emitted for child threads (there is none in the
        // current single-process/thread tool mode) nor re-emitted per dispatch.
        if is_new && tid.as_raw() == self.root_pid.as_raw() {
            match callback_result(drive_callback(tool.handle_post_exec(&mut guest), &tail)) {
                Ok(Ok(())) => {}
                // handle_post_exec returns Errno; tool_fatal expects reverie::Error.
                Ok(Err(error)) => tool_fatal(124, &Error::from(error)),
                Err(ending) => {
                    drop(guest);
                    finish_ending(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        (tid, pid),
                        ending,
                    )
                }
            }
        }
        // A signal the post-exec callback sent.
        if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
            drop(guest);
            finish_ending(
                &mut tool_slot,
                &mut states,
                &self.rpc,
                &self.runtime,
                (tid, pid),
                ending,
            );
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
                guest.event.result = -i64::from(error.into_raw());
                return;
            }
            if is_plain_fork(number, args) {
                guest.prepare_fork_parent_state();
                let result = forward_plain_fork(number, args, Some(&mut guest.event.guest_pkru));
                if result == 0 {
                    let parent_state = guest.take_fork_parent_state();
                    drop(guest);
                    finish_fork_child(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        event,
                        parent_state,
                        ForkChildContext {
                            parent_tid: tid,
                            parent_pid: pid,
                            child_tid: raw_pid(libc::SYS_gettid),
                            child_pid: raw_pid(libc::SYS_getpid),
                        },
                    );
                } else {
                    guest.event.result = result;
                }
                return;
            } else if is_exit_syscall(number) {
                drop(guest);
                finish_tool_exit(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    &self.runtime,
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
                    finish_ending(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        (tid, pid),
                        ending,
                    );
                }
                return;
            } else if let Some(error) = injected_syscall_guard(&self.runtime, number, args) {
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
        if let Some(driver) = self.native_exec_driver.as_ref() {
            let mut site = guest.native_exec_site();
            // Capture belongs immediately before this actual handler; it is
            // not a native authorization for thread-start/post-exec callbacks.
            site.in_handler = true;
            site.main_tid = self.root_pid.as_raw();
            guest.exec = Some(super::native_exec::ExecInjection::capture(
                tool,
                driver,
                (&original_event, guest.event),
                &site,
                &*guest.state,
                &self.rpc,
            ));
        }
        guest.in_syscall_handler = true;
        let driven = drive_tool_syscall(tool, &mut guest, syscall, &tail);
        guest.in_syscall_handler = false;
        match driven {
            DrivenSyscall::Result(value) => {
                guest.event.result = value;
                // Signals the Tool's handler sent the guest itself that would
                // end its process (`InGuest::inject` staged them), now that
                // the handler has run to its end, as a tracer delivers a
                // signal held during an injection when the handler returns.
                if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
                    drop(guest);
                    finish_ending(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        (tid, pid),
                        ending,
                    );
                }
            }
            DrivenSyscall::Exit { number, .. } if !is_exit_syscall(number) => {
                // The handler injected a SIGKILL of the guest itself
                // (`InGuest::inject`), which ended the handler there, as a
                // tracer's injection of it ends the guest at once. Signals it
                // held before are never delivered.
                drop(guest);
                finish_ending(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    &self.runtime,
                    (tid, pid),
                    Ending::Death(SignalDeath::KILL),
                );
            }
            DrivenSyscall::Exit { number, args } => {
                // A signal the handler held before its exit is not delivered:
                // the exit ends the process first.
                drop(guest);
                finish_tool_exit(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    &self.runtime,
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
                finish_fork_child(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    &self.runtime,
                    event,
                    parent_state,
                    ForkChildContext {
                        parent_tid,
                        parent_pid,
                        child_tid,
                        child_pid,
                    },
                );
            }
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
        #[cfg(feature = "exec-private-successor")]
        if self
            .prepared_exec
            .try_lock()
            .is_none_or(|pending| pending.is_some())
        {
            unsafe { super::exec_private::initialization_failed(core::ptr::null_mut()) }
        }

        let _scratch_scope = DispatchScratchScope::enter();
        let tid = raw_pid(libc::SYS_gettid);
        let pid = raw_pid(libc::SYS_getpid);
        let ppid = (pid != self.root_pid).then(|| raw_pid(libc::SYS_getppid));
        let mut tool_slot = self.tool.lock();
        let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
        let mut states = self.states.lock();
        let is_new = !states.contains_key(&tid.as_raw());
        let state = states
            .entry(tid.as_raw())
            .or_insert_with(|| tool.init_thread_state(tid, None));
        let tail = TailResult::default();
        let mut event = SyscallEvent {
            number: -1,
            args: [0; 6],
            instruction_pointer: context.instruction_pointer,
            result: 0,
            context: context as *mut RegisterContext as usize,
            dispatch: SyscallDispatch::InstalledHook,
            guest_pkru: None,
        };
        let mut guest = InGuest::<T, R> {
            event: &mut event,
            tid,
            pid,
            ppid,
            state,
            rpc: &self.rpc,
            tail: &tail,
            cpuid_interception: self.cpuid_interception,
            fork_parent_state: None,
            runtime: &self.runtime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: false,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: self.native_exec_driver.as_deref(),
            unsupported_refusal: None,
        };
        if is_new {
            match callback_result(drive_callback(tool.handle_thread_start(&mut guest), &tail)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tool_fatal(124, &error),
                Err(ending) => {
                    drop(guest);
                    finish_ending(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        (tid, pid),
                        ending,
                    )
                }
            }
            if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
                drop(guest);
                finish_ending(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    &self.runtime,
                    (tid, pid),
                    ending,
                );
            }
        }
        if is_new && tid.as_raw() == self.root_pid.as_raw() {
            match callback_result(drive_callback(tool.handle_post_exec(&mut guest), &tail)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tool_fatal(124, &Error::from(error)),
                Err(ending) => {
                    drop(guest);
                    finish_ending(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        &self.runtime,
                        (tid, pid),
                        ending,
                    )
                }
            }
        }
        if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
            drop(guest);
            finish_ending(
                &mut tool_slot,
                &mut states,
                &self.rpc,
                &self.runtime,
                (tid, pid),
                ending,
            );
        }

        match kind {
            InstructionEventKind::Cpuid => {
                let outcome = drive_callback(
                    tool.handle_cpuid_event(&mut guest, context.rax as u32, context.rcx as u32),
                    &tail,
                );
                let result = match callback_result(outcome) {
                    Ok(result) => {
                        result.unwrap_or_else(|error| tool_fatal(125, &Error::from(error)))
                    }
                    Err(ending) => {
                        drop(guest);
                        finish_ending(
                            &mut tool_slot,
                            &mut states,
                            &self.rpc,
                            &self.runtime,
                            (tid, pid),
                            ending,
                        )
                    }
                };
                context.rax = u64::from(result.eax);
                context.rbx = u64::from(result.ebx);
                context.rcx = u64::from(result.ecx);
                context.rdx = u64::from(result.edx);
            }
            InstructionEventKind::Rdtsc | InstructionEventKind::Rdtscp => {
                let request = if kind == InstructionEventKind::Rdtscp {
                    Rdtsc::Tscp
                } else {
                    Rdtsc::Tsc
                };
                let outcome = drive_callback(tool.handle_rdtsc_event(&mut guest, request), &tail);
                let result = match callback_result(outcome) {
                    Ok(result) => {
                        result.unwrap_or_else(|error| tool_fatal(125, &Error::from(error)))
                    }
                    Err(ending) => {
                        drop(guest);
                        finish_ending(
                            &mut tool_slot,
                            &mut states,
                            &self.rpc,
                            &self.runtime,
                            (tid, pid),
                            ending,
                        )
                    }
                };
                context.rax = result.tsc as u32 as u64;
                context.rdx = result.tsc.checked_shr(32).unwrap_or(0);
                if let Some(aux) = result.aux {
                    context.rcx = u64::from(aux);
                }
            }
        }
        // The instruction callback can send the guest a signal that ends it;
        // it then ends before the instruction completes.
        if let Some(ending) = deliver_staged_signals(tool, &mut guest) {
            drop(guest);
            finish_ending(
                &mut tool_slot,
                &mut states,
                &self.rpc,
                &self.runtime,
                (tid, pid),
                ending,
            );
        }
    }
}

fn finish_fork_child<T: Tool, R: HostRuntime>(
    tool_slot: &mut Option<T>,
    states: &mut HashMap<i32, T::ThreadState>,
    rpc: &CoordinatorRpc<T::GlobalState>,
    runtime: &R,
    event: &mut SyscallEvent,
    parent_snapshot: T::ThreadState,
    context: ForkChildContext,
) {
    let ForkChildContext {
        parent_tid,
        parent_pid,
        child_tid,
        child_pid,
    } = context;
    runtime.fork_child_rebind();
    runtime.emit_stage(b"fork-child-thread-start-begin");
    // This child inherited the parent's coordinator connection. Flag it before
    // any child-side callback can issue an RPC (`handle_thread_start` below is
    // the first such opportunity) so the next `send_rpc` reconnects under the
    // child's own identity. Doing it here rather than from a `pthread_atfork`
    // hook also covers forks that never enter libc, such as a raw `SYS_fork` or
    // a raw plain `SYS_clone`.
    super::rpc::note_fork_in_child();
    let inherited_parent_state = states
        .remove(&parent_tid.as_raw())
        .unwrap_or_else(|| fatal(126));
    drop(inherited_parent_state);
    let child_tool = T::new(child_pid, rpc.config());
    let child_state = child_tool.init_thread_state(child_tid, Some((parent_tid, &parent_snapshot)));
    states.clear();
    states.insert(child_tid.as_raw(), child_state);
    *tool_slot = Some(child_tool);
    // Both installed hooks and deferred fallback carry a register context.
    // Attribute the child's first event to the path that actually entered it.
    runtime.fork_child_reset(event);

    let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
    let state = states
        .get_mut(&child_tid.as_raw())
        .unwrap_or_else(|| fatal(126));
    let child_tail = TailResult::default();
    let mut child_guest = InGuest::<T, R> {
        event,
        tid: child_tid,
        pid: child_pid,
        ppid: Some(parent_pid),
        state,
        rpc,
        tail: &child_tail,
        cpuid_interception: runtime.cpuid_interception_enabled(),
        fork_parent_state: None,
        runtime,
        staged_signals: Vec::new(),
        staged_signal_delivery: false,
        in_syscall_handler: false,
        #[cfg(feature = "exec-native-injection")]
        exec: None,
        #[cfg(feature = "exec-native-injection")]
        mapping_driver: None,
        unsupported_refusal: None,
    };
    match callback_result(drive_callback(
        tool.handle_thread_start(&mut child_guest),
        &child_tail,
    )) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tool_fatal(124, &error),
        Err(ending) => {
            drop(child_guest);
            finish_ending(
                tool_slot,
                states,
                rpc,
                runtime,
                (child_tid, child_pid),
                ending,
            )
        }
    }
    if let Some(ending) = deliver_staged_signals(tool, &mut child_guest) {
        drop(child_guest);
        finish_ending(
            tool_slot,
            states,
            rpc,
            runtime,
            (child_tid, child_pid),
            ending,
        );
    }
    runtime.emit_stage(b"fork-child-thread-start-complete");
    child_guest.event.result = 0;
}

struct ForkChildContext {
    parent_tid: Pid,
    parent_pid: Pid,
    child_tid: Pid,
    child_pid: Pid,
}

// TODO-HUMAN-REVIEW(PR-143): Review single-process Tool exit lifecycle.
fn finish_tool_exit<T: Tool, R: HostRuntime>(
    tool_slot: &mut Option<T>,
    states: &mut HashMap<i32, T::ThreadState>,
    rpc: &CoordinatorRpc<T::GlobalState>,
    runtime: &R,
    context: ToolExitContext,
) {
    let ToolExitContext {
        tid,
        pid,
        status,
        process_exit,
    } = context;
    // The exit callbacks run from here: an ending a callback staged has
    // reached the host, and these callbacks may reach the coordinator.
    ENDING_STAGED.store(false, core::sync::atomic::Ordering::Release);
    let state = states
        .remove(&tid.as_raw())
        .expect("LiteInst thread state disappeared before exit");
    let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
    if let Err(error) = drive_ready(tool.on_exit_thread(tid, rpc, state, status)) {
        tool_fatal(125, &error);
    }
    if process_exit {
        let tool = tool_slot.take().unwrap_or_else(|| fatal(126));
        if let Err(error) = drive_ready(tool.on_exit_process(pid, rpc, status)) {
            tool_fatal(125, &error);
        }
        if let Err(error) = runtime.exit_process_stats(tid) {
            tool_fatal(125, &Error::from(error));
        }
    }
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
            status: reverie::ExitStatus::Exited((args[0] & 0xff) as i32),
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
fn finish_ending<T: Tool, R: HostRuntime>(
    tool_slot: &mut Option<T>,
    states: &mut HashMap<i32, T::ThreadState>,
    rpc: &CoordinatorRpc<T::GlobalState>,
    runtime: &R,
    (tid, pid): (Pid, Pid),
    ending: Ending,
) -> ! {
    let death = match ending {
        Ending::Death(death) => death,
        Ending::Call { number, args } if is_exit_syscall(number) => {
            finish_tool_exit(
                tool_slot,
                states,
                rpc,
                runtime,
                ToolExitContext::exit_syscall(tid, pid, number, args),
            );
            let _ = unsafe { raw_syscall6(number, args) };
            fatal(126)
        }
        // `InGuest::inject` ends a callback this way only for a SIGKILL of
        // the guest itself.
        Ending::Call { .. } => SignalDeath::KILL,
    };
    finish_tool_exit(
        tool_slot,
        states,
        rpc,
        runtime,
        ToolExitContext::signal_death(tid, pid, death.status),
    );
    die_by_pending_signal(death.signal)
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
    tool: &T,
    guest: &mut InGuest<'_, T, R>,
) -> Option<Ending> {
    guest.staged_signal_delivery = true;
    let ending = drain_staged_signals(tool, guest);
    guest.staged_signal_delivery = false;
    ending
}

fn drain_staged_signals<T: Tool, R: HostRuntime>(
    tool: &T,
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

struct InGuest<'a, T: Tool, R: HostRuntime> {
    event: &'a mut SyscallEvent,
    tid: Pid,
    pid: Pid,
    ppid: Option<Pid>,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    tail: &'a TailResult,
    cpuid_interception: bool,
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
    /// The typed refusal of the last injection, if the backend refused it
    /// ([`reverie::Guest::take_unsupported_refusal`]).
    unsupported_refusal: Option<reverie::UnsupportedRefusal>,
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
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
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
    ENDING_STAGED.load(core::sync::atomic::Ordering::Acquire)
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
    if !in_syscall_handler
        && matches!(
            number,
            libc::SYS_fork | libc::SYS_vfork | libc::SYS_clone | libc::SYS_clone3
        )
    {
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
    if number == libc::SYS_fork {
        return true;
    }
    if number == libc::SYS_vfork {
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

fn clone3_is_plain_fork(address: u64, size: u64) -> bool {
    const CLONE_ARGS_SIZE_VER0: usize = 64;
    const CLONE_ARGS_SIZE_VER2: usize = 88;
    if address == 0 || size < CLONE_ARGS_SIZE_VER0 as u64 {
        return false;
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
    if read != read_len as i64 {
        return false;
    }

    clone_args_are_plain_fork(&fields)
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
    let fields: [u64; 8] = match number {
        // The copying vfork stays a COW fork with the parent waiting: no
        // CLONE_VM or CLONE_VFORK is applied physically.
        libc::SYS_fork | libc::SYS_vfork => [PIDFD, pidfd, 0, 0, libc::SIGCHLD as u64, 0, 0, 0],
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
    let physical = unsafe {
        crate::trap::raw_syscall6_with_result(
            libc::SYS_clone3,
            [record.as_ptr() as u64, size as u64, 0, 0, 0, 0],
            permissions,
        )
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

fn forward_plain_fork(number: i64, args: [u64; 6], guest_pkru: Option<&mut Option<u32>>) -> i64 {
    let result = if let Some(hook) = CREATION_HOOK.get().copied() {
        reported_creation(hook, number, args, guest_pkru)
    } else {
        let permissions = guest_pkru.as_ref().and_then(|value| **value);
        let physical = if number == libc::SYS_vfork {
            // A real vfork child would run the instrumentation callback on the
            // parent's shared stack. Use a COW fork and preserve vfork's parent
            // suspension until the child exits. Exec remains fail-closed, so exit
            // is the only supported vfork completion boundary for now.
            unsafe { crate::trap::raw_syscall6_with_result(libc::SYS_fork, [0; 6], permissions) }
        } else {
            unsafe { crate::trap::raw_syscall6_with_result(number, args, permissions) }
        };
        if let Some(output) = guest_pkru {
            *output = physical.pkru;
        }
        physical.result
    };
    if number == libc::SYS_vfork && result > 0 {
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
        (matches!(number, libc::SYS_clone | libc::SYS_clone3 | libc::SYS_vfork)
            && !is_plain_fork(number, args))
        // AUTONOMOUS-BOT-IMPLEMENTED
        || matches!(number, libc::SYS_execve | libc::SYS_execveat);
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

/// The guest memory a Tool callback reaches through [`Guest::memory`]: this
/// process's own memory ([`LocalMemory`]), until the guest is ending.
///
/// Every handle carries its dispatch's [`TailResult`], so once a callback has
/// staged an injection that ends the guest (an exit, or a SIGKILL of the
/// guest itself), every read and write through any handle of that dispatch,
/// one obtained before the injection included, fails with ESRCH, as a
/// tracer's access to a tracee its injection killed fails, and copies
/// nothing. A handle cannot outlive its dispatch, so the exit callbacks,
/// which have no [`Guest`], never hold one.
pub struct GuestMemory<'a> {
    local: LocalMemory,
    tail: &'a TailResult,
}

impl GuestMemory<'_> {
    fn check(&self) -> Result<(), Errno> {
        if self.tail.ending() {
            Err(Errno::ESRCH)
        } else {
            Ok(())
        }
    }
}

// Every other `MemoryAccess` method is built on these, so each passes the
// same check; the native-user write keeps its default refusal.
impl MemoryAccess for GuestMemory<'_> {
    fn read_vectored(
        &self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.check()?;
        self.local.read_vectored(read_from, write_to)
    }

    fn write_vectored(
        &mut self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.check()?;
        self.local.write_vectored(read_from, write_to)
    }

    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        // The caller's conversion is Tool code, which can stage an ending
        // (abandon a SIGKILL injection, say), so it runs before the check.
        let addr: Addr<'a, u8> = addr.into();
        self.check()?;
        self.local.read(addr, buf)
    }

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        self.check()?;
        self.local.write(addr, buf)
    }

    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        self.check()?;
        self.local.write_with_user_access(addr, buf)
    }
}

#[reverie::tool]
impl<'a, T: Tool, R: HostRuntime> Guest<T> for InGuest<'a, T, R> {
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

    fn memory(&self) -> Self::Memory {
        GuestMemory {
            local: LocalMemory::new(),
            tail: self.tail,
        }
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
        if self.event.context != 0 {
            let context = unsafe { &*(self.event.context as *const RegisterContext) };
            regs.r15 = context.r15;
            regs.r14 = context.r14;
            regs.r13 = context.r13;
            regs.r12 = context.r12;
            regs.rbp = context.rbp;
            regs.rbx = context.rbx;
            regs.r11 = context.r11;
            regs.r10 = context.r10;
            regs.r9 = context.r9;
            regs.r8 = context.r8;
            regs.rax = context.rax;
            regs.rcx = context.rcx;
            regs.rdx = context.rdx;
            regs.rsi = context.rsi;
            regs.rdi = context.rdi;
            regs.orig_rax = context.rax;
            regs.rip = context.instruction_pointer;
            regs.rsp = context.stack_pointer;
            regs.eflags = context.rflags;
            return regs;
        }
        regs.rax = self.event.number as u64;
        regs.orig_rax = self.event.number as u64;
        regs.rdi = self.event.args[0];
        regs.rsi = self.event.args[1];
        regs.rdx = self.event.args[2];
        regs.r10 = self.event.args[3];
        regs.r8 = self.event.args[4];
        regs.r9 = self.event.args[5];
        regs.rip = self.event.instruction_pointer;
        regs
    }
    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        if self.tail.ending() {
            // The guest is ending: no further guest effect (see `inject`).
            return std::future::pending().await;
        }
        self.event.number = regs.rax as i64;
        self.event.args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        if self.event.context != 0 {
            let context = unsafe { &mut *(self.event.context as *mut RegisterContext) };
            context.r15 = regs.r15;
            context.r14 = regs.r14;
            context.r13 = regs.r13;
            context.r12 = regs.r12;
            context.rbp = regs.rbp;
            context.rbx = regs.rbx;
            context.r11 = regs.r11;
            context.r10 = regs.r10;
            context.r9 = regs.r9;
            context.r8 = regs.r8;
            context.rax = regs.rax;
            context.rcx = regs.rcx;
            context.rdx = regs.rdx;
            context.rsi = regs.rsi;
            context.rdi = regs.rdi;
            context.stack_pointer = regs.rsp;
            context.rflags = regs.eflags;
        }
        Ok(())
    }
    async fn stack(&mut self) -> Self::Stack {
        LocalStack::new()
    }

    async fn daemonize(&mut self) {}

    fn take_unsupported_refusal(&mut self) -> Option<reverie::UnsupportedRefusal> {
        self.unsupported_refusal.take()
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        self.unsupported_refusal = None;
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

        // AUTONOMOUS-BOT-IMPLEMENTED
        if matches!(number, libc::SYS_clone | libc::SYS_clone3 | libc::SYS_vfork) {
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
        #[cfg(feature = "exec-native-injection")]
        self.check_native_mapping(number, raw_args)?;
        self.refuse_filter_while_staging(number, raw_args);
        if let Some(error) = injected_syscall_guard(self.runtime, number, raw_args) {
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
        let kernel_signal_mask = stripped_signal_mask(self.runtime, number, raw_args)?;
        if let Some(mask) = kernel_signal_mask.as_ref() {
            raw_args[1] = mask as *const u64 as u64;
        }

        let result = unsafe { crate::trap::physical_guest_syscall6(number, raw_args, None) }.result;
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
        if !self.delivers_sigalrm(&event) {
            return Err(Errno::ENOSYS.into());
        }
        // SAFETY: inside the guest call's own turn, in its dispatch.
        unsafe { super::sigalrm::prepare_delivery(self.runtime.reserved_signal_mask()) }
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
        if !self.delivers_sigalrm(&event) {
            return Err(Errno::ENOSYS.into());
        }
        // SAFETY: inside the guest call's own turn, in its dispatch; the Tool
        // does not run the syscall.
        unsafe {
            super::sigalrm::prepare_delivery_before_syscall(self.runtime.reserved_signal_mask())
        }
        .map_err(|errno| Error::Errno(Errno::new(errno)))
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
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
        let number = number.id() as i64;
        #[cfg(feature = "exec-native-injection")]
        if let Err(error) = self.check_native_mapping(number, args) {
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
        } else if let Some(error) = injected_syscall_guard(self.runtime, number, args) {
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
            let value = match stripped_signal_mask(self.runtime, number, args) {
                Err(error) => -i64::from(error.into_raw()),
                Ok(None) => {
                    unsafe { crate::trap::physical_guest_syscall6(number, args, None) }.result
                }
                Ok(Some(mask)) => {
                    let mut args = args;
                    args[1] = (&raw const mask) as u64;
                    unsafe { crate::trap::physical_guest_syscall6(number, args, None) }.result
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
        self.runtime.read_clock().map_err(Error::from)
    }

    fn has_cpuid_interception(&self) -> bool {
        self.cpuid_interception
    }
}

pub struct LocalStack {
    arena: Box<[u8]>,
    offset: usize,
}

impl LocalStack {
    fn new() -> Self {
        Self {
            arena: vec![0; STACK_CAPACITY].into_boxed_slice(),
            offset: 0,
        }
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
}

impl Drop for LocalStackGuard {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            COMMITTED_STACKS.lock().push(arena);
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
mod tests {
    use super::*;

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
        for number in [libc::SYS_fork, libc::SYS_clone, libc::SYS_clone3] {
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
        assert!(!errno_is_the_guests(libc::SYS_fork, libc::E2BIG));
        assert!(!errno_is_the_guests(libc::SYS_fork, libc::ENOSYS));
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
        let mut before = GuestMemory {
            local: LocalMemory::new(),
            tail: &tail,
        };
        let mut word = 0_u64;
        let address = AddrMut::from_raw(&raw mut word as usize).unwrap();
        before.write_value(address, &1_u64).unwrap();
        assert_eq!(word, 1);
        tail.set_exit(libc::SYS_exit_group, [0; 6]);
        assert_eq!(before.write_value(address, &2_u64), Err(Errno::ESRCH));
        let mut after = GuestMemory {
            local: LocalMemory::new(),
            tail: &tail,
        };
        assert_eq!(after.write_value(address, &3_u64), Err(Errno::ESRCH));
        assert_eq!(
            before.read_value::<_, u64>(Addr::from_raw(&raw const word as usize).unwrap()),
            Err(Errno::ESRCH)
        );
        assert_eq!(word, 1);
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
        let memory = GuestMemory {
            local: LocalMemory::new(),
            tail: &tail,
        };
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
}
