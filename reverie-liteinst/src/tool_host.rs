//! Generic in-guest host for Reverie tools.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::path::Path;

use reverie::Error;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::LocalMemory;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_preload::tool_host::DrivenSyscall;
use reverie_preload::tool_host::TailResult;
use reverie_preload::tool_host::drive_ready;
use reverie_preload::tool_host::drive_tool_syscall;
use reverie_preload::trap::raw_syscall6;

use crate::rpc::CoordinatorRpc;
use crate::rpc::SpinMutex;
use crate::runtime;
use crate::runtime::SyscallEvent;

const STACK_CAPACITY: usize = 4096;

static COMMITTED_STACKS: SpinMutex<Vec<Box<[u8]>>> = SpinMutex::new(Vec::new());

struct DispatchScratchScope {
    _allocation_scope: crate::patch_alloc::DispatchAllocationScope,
}

impl DispatchScratchScope {
    fn enter() -> Self {
        COMMITTED_STACKS.lock().clear();
        Self {
            _allocation_scope: crate::patch_alloc::enter_dispatch(),
        }
    }
}

impl Drop for DispatchScratchScope {
    fn drop(&mut self) {
        COMMITTED_STACKS.lock().clear();
    }
}

trait ToolHandler: Send + Sync {
    fn dispatch(&self, event: &mut SyscallEvent);
}

static HANDLER: std::sync::OnceLock<Box<dyn ToolHandler>> = std::sync::OnceLock::new();

// TODO-HUMAN-REVIEW(PR-127): Review generic in-guest Tool hosting.
/// Install a concrete Reverie tool in this guest and connect it to its coordinator.
///
/// The caller is normally a tool-specific preload DSO. It must invoke this
/// before application threads start and before any seccomp filter is active.
///
/// # Safety
///
/// Installs process-global signal, seccomp, allocator, and instrumentation state.
// TODO-HUMAN-REVIEW(PR-133): Review fail-closed preinstalled signal-handler boundary.
pub unsafe fn install_tool<T>(coordinator: impl AsRef<Path>) -> io::Result<()>
where
    T: Tool + 'static,
{
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            true,
            runtime::PatchPublication::Concurrent,
        )
    }
}

/// Install a concrete Reverie tool with quiescent patch publication.
///
/// This has the same process-global effects as [`install_tool`], but skips the
/// concurrent instruction-tearing and straddler protocol when publishing a new
/// site. The caller must keep every other application thread from fetching
/// guest text for the full lifetime of the installed tool.
///
/// # Safety
///
/// In addition to [`install_tool`]'s requirements, the caller asserts that no
/// other application thread can execute while a syscall site is installed.
pub unsafe fn install_tool_quiescent<T>(coordinator: impl AsRef<Path>) -> io::Result<()>
where
    T: Tool + 'static,
{
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            true,
            runtime::PatchPublication::Quiescent,
        )
    }
}

// TODO-HUMAN-REVIEW(PR-139): Review the environment-preserving bootstrap install API.
/// Installs a concrete tool using a consumed bootstrap coordinator path.
///
/// Unlike the legacy install entry point, this does not remove its coordinator
/// environment variable because the bootstrap path did not introduce one.
///
/// # Safety
///
/// Installs process-global signal, seccomp, allocator, and instrumentation state.
pub unsafe fn install_tool_from_bootstrap<T>(coordinator: impl AsRef<Path>) -> io::Result<()>
where
    T: Tool + 'static,
{
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            false,
            runtime::PatchPublication::Concurrent,
        )
    }
}

unsafe fn install_tool_inner<T>(
    coordinator: &Path,
    remove_legacy_environment: bool,
    publication: runtime::PatchPublication,
) -> io::Result<()>
where
    T: Tool + 'static,
{
    let _signal_state = runtime::prepare_guest_signal_state()?;
    let rpc = CoordinatorRpc::<T::GlobalState>::connect(coordinator)?;
    runtime::reserve_coordinator_fd(rpc.raw_fd())?;
    let stats =
        if let Some(stats_coordinator) = std::env::var_os(crate::backend::STATS_COORDINATOR_ENV) {
            let stats = crate::stats::initialize_guest_stats(Path::new(&stats_coordinator))?;
            // SAFETY: tool installation runs before application-created threads.
            unsafe { std::env::remove_var(crate::backend::STATS_COORDINATOR_ENV) };
            stats
        } else {
            crate::stats::GuestStatsHooks::DISABLED
        };
    COMMITTED_STACKS.lock().clear();
    let pid = Pid::from_raw(unsafe { libc::getpid() });
    let subscriptions = T::subscriptions(rpc.config()).iter_syscalls().collect();
    if remove_legacy_environment {
        // SAFETY: legacy tool installation runs before application-created threads.
        unsafe { std::env::remove_var(crate::backend::COORDINATOR_ENV) };
    }
    let tool = T::new(pid, rpc.config());
    HANDLER
        .set(Box::new(ToolHost::<T> {
            tool: SpinMutex::new(Some(tool)),
            rpc,
            root_pid: pid,
            subscriptions,
            states: SpinMutex::new(HashMap::new()),
            stats,
        }))
        .map_err(|_| {
            io::Error::new(io::ErrorKind::AlreadyExists, "Reverie tool installed twice")
        })?;
    runtime::initialize_reverie_tool(stats, publication)
}

pub(crate) fn dispatch(event: &mut SyscallEvent) {
    match HANDLER.get() {
        Some(handler) => handler.dispatch(event),
        None => event.result = -i64::from(libc::ENOSYS),
    }
}

struct ToolHost<T: Tool> {
    tool: SpinMutex<Option<T>>,
    rpc: CoordinatorRpc<T::GlobalState>,
    root_pid: Pid,
    subscriptions: HashSet<Sysno>,
    states: SpinMutex<HashMap<i32, T::ThreadState>>,
    stats: crate::stats::GuestStatsHooks,
}

impl<T> ToolHandler for ToolHost<T>
where
    T: Tool + 'static,
{
    fn dispatch(&self, event: &mut SyscallEvent) {
        let _scratch_scope = DispatchScratchScope::enter();
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
        let mut guest = LiteinstGuest::<T> {
            event,
            tid,
            pid,
            ppid,
            state,
            rpc: &self.rpc,
            tail: &tail,
        };

        if is_new && let Err(error) = drive_ready(tool.handle_thread_start(&mut guest)) {
            tool_fatal(124, &error);
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
        if is_new
            && tid.as_raw() == self.root_pid.as_raw()
            && let Err(error) = drive_ready(tool.handle_post_exec(&mut guest))
        {
            // handle_post_exec returns Errno; tool_fatal expects reverie::Error.
            tool_fatal(124, &Error::from(error));
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
            if is_plain_fork(number, args) {
                let result = unsafe { raw_syscall6(number, args) };
                if result == 0 {
                    finish_fork_child(
                        &mut tool_slot,
                        &mut states,
                        &self.rpc,
                        self.stats,
                        event,
                        ForkChildContext {
                            parent_tid: tid,
                            parent_pid: pid,
                            child_tid: raw_pid(libc::SYS_gettid),
                            child_pid: raw_pid(libc::SYS_getpid),
                        },
                    );
                } else {
                    event.result = result;
                }
                return;
            } else if is_exit_syscall(number) {
                finish_tool_exit(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    self.stats,
                    ToolExitContext {
                        tid,
                        pid,
                        number,
                        args,
                    },
                );
            } else if let Some(error) = injected_syscall_guard(number, args) {
                event.result = -i64::from(error.into_raw());
                return;
            }
            event.result = unsafe { raw_syscall6(number, args) };
            return;
        }
        let args = guest.event.args.map(|arg| arg as usize);
        let syscall = Syscall::from_raw(
            number,
            SyscallArgs::new(args[0], args[1], args[2], args[3], args[4], args[5]),
        );

        // Drive the Tool handler to a terminal outcome. The shared driver owns
        // the wait4/ERESTARTSYS restart protocol (Reverie #362) so it cannot
        // drift between the in-guest backends; this host maps each terminal
        // outcome onto its own per-thread lifecycle (exit/fork-child) state.
        match drive_tool_syscall(tool, &mut guest, syscall, number, &tail) {
            DrivenSyscall::Result(value) => {
                guest.event.result = value;
            }
            DrivenSyscall::Exit { number, args } => {
                finish_tool_exit(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    self.stats,
                    ToolExitContext {
                        tid,
                        pid,
                        number,
                        args,
                    },
                );
                event.result = unsafe { raw_syscall6(number, args) };
            }
            DrivenSyscall::ForkChild {
                parent_tid,
                parent_pid,
                child_tid,
                child_pid,
            } => {
                finish_fork_child(
                    &mut tool_slot,
                    &mut states,
                    &self.rpc,
                    self.stats,
                    event,
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
}

fn finish_fork_child<T: Tool>(
    tool_slot: &mut Option<T>,
    states: &mut HashMap<i32, T::ThreadState>,
    rpc: &CoordinatorRpc<T::GlobalState>,
    stats: crate::stats::GuestStatsHooks,
    event: &mut SyscallEvent,
    context: ForkChildContext,
) {
    let ForkChildContext {
        parent_tid,
        parent_pid,
        child_tid,
        child_pid,
    } = context;
    let parent_state = states
        .remove(&parent_tid.as_raw())
        .unwrap_or_else(|| fatal(126));
    let child_tool = T::new(child_pid, rpc.config());
    let child_state = child_tool.init_thread_state(child_tid, Some((parent_tid, &parent_state)));
    states.clear();
    states.insert(child_tid.as_raw(), child_state);
    *tool_slot = Some(child_tool);
    runtime::reset_fallback_observability();
    stats.reset_after_fork();
    if event.context != 0 {
        runtime::record_fork_child_direct_hook(event.instruction_pointer);
    }

    let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
    let state = states
        .get_mut(&child_tid.as_raw())
        .unwrap_or_else(|| fatal(126));
    let child_tail = TailResult::default();
    let mut child_guest = LiteinstGuest::<T> {
        event,
        tid: child_tid,
        pid: child_pid,
        ppid: Some(parent_pid),
        state,
        rpc,
        tail: &child_tail,
    };
    if let Err(error) = drive_ready(tool.handle_thread_start(&mut child_guest)) {
        tool_fatal(124, &error);
    }
    child_guest.event.result = 0;
}

struct ForkChildContext {
    parent_tid: Pid,
    parent_pid: Pid,
    child_tid: Pid,
    child_pid: Pid,
}

// TODO-HUMAN-REVIEW(PR-143): Review single-process Tool exit lifecycle.
fn finish_tool_exit<T: Tool>(
    tool_slot: &mut Option<T>,
    states: &mut HashMap<i32, T::ThreadState>,
    rpc: &CoordinatorRpc<T::GlobalState>,
    stats: crate::stats::GuestStatsHooks,
    context: ToolExitContext,
) {
    let ToolExitContext {
        tid,
        pid,
        number,
        args,
    } = context;
    let state = states
        .remove(&tid.as_raw())
        .expect("LiteInst thread state disappeared before exit");
    let status = reverie::ExitStatus::Exited((args[0] & 0xff) as i32);
    let tool = tool_slot.as_ref().unwrap_or_else(|| fatal(126));
    if let Err(error) = drive_ready(tool.on_exit_thread(tid, rpc, state, status)) {
        tool_fatal(125, &error);
    }
    if is_process_exit(number, tid, pid) {
        let tool = tool_slot.take().unwrap_or_else(|| fatal(126));
        if let Err(error) = drive_ready(tool.on_exit_process(pid, rpc, status)) {
            tool_fatal(125, &error);
        }
        if stats.is_enabled()
            && let Err(error) = runtime::submit_process_stats(tid, stats)
        {
            tool_fatal(125, &Error::from(error));
        }
    }
}

struct ToolExitContext {
    tid: Pid,
    pid: Pid,
    number: i64,
    args: [u64; 6],
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

struct LiteinstGuest<'a, T: Tool> {
    event: &'a mut SyscallEvent,
    tid: Pid,
    pid: Pid,
    ppid: Option<Pid>,
    state: &'a mut T::ThreadState,
    rpc: &'a CoordinatorRpc<T::GlobalState>,
    tail: &'a TailResult,
}

#[reverie::tool]
impl<T: Tool> GlobalRPC<T::GlobalState> for LiteinstGuest<'_, T> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        self.rpc.send_rpc(message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.rpc.config()
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-326): Review the plain-fork injection boundary.
fn is_plain_fork(number: i64, args: [u64; 6]) -> bool {
    if number == libc::SYS_fork {
        return true;
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

// TODO-HUMAN-REVIEW(PR-127): Review injected process/signal safety policy.
fn injected_syscall_guard(number: i64, args: [u64; 6]) -> Option<Errno> {
    let unsupported_process =
        // AUTONOMOUS-BOT-IMPLEMENTED
        matches!(number, libc::SYS_clone3 | libc::SYS_vfork)
            || (number == libc::SYS_clone && !is_plain_fork(number, args))
        // AUTONOMOUS-BOT-IMPLEMENTED
        || matches!(number, libc::SYS_execve | libc::SYS_execveat);
    let protected_signal =
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-133): Review fail-closed guest signal-handler policy.
        !runtime::signal_action_supported(number, args)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (number == libc::SYS_sigaltstack && args[0] != 0)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (number == libc::SYS_rt_sigprocmask && args[1] != 0);

    if unsupported_process {
        Some(Errno::EOPNOTSUPP)
    } else if protected_signal {
        Some(Errno::EPERM)
    } else {
        None
    }
}

#[reverie::tool]
impl<T: Tool> Guest<T> for LiteinstGuest<'_, T> {
    type Memory = LocalMemory;
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

    fn memory(&self) -> Self::Memory {
        LocalMemory::new()
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
            let context =
                unsafe { &*(self.event.context as *const liteinst2::trampoline::HookContext) };
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
        self.event.number = regs.rax as i64;
        self.event.args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
        if self.event.context != 0 {
            let context =
                unsafe { &mut *(self.event.context as *mut liteinst2::trampoline::HookContext) };
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

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
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

        if is_plain_fork(number, raw_args) {
            let parent_tid = self.tid;
            let parent_pid = self.pid;
            let result = unsafe { raw_syscall6(number, raw_args) };
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
        if let Some(error) = injected_syscall_guard(number, raw_args) {
            return Err(error);
        }
        if is_exit_syscall(number) {
            self.tail.set_exit(number, raw_args);
            return std::future::pending().await;
        }
        let kernel_signal_mask =
            (number == libc::SYS_rt_sigprocmask && raw_args[1] != 0).then(|| {
                let requested = unsafe { (raw_args[1] as *const u64).read_unaligned() };
                requested & !(1_u64 << (libc::SIGSYS - 1))
            });
        if let Some(mask) = kernel_signal_mask.as_ref() {
            raw_args[1] = mask as *const u64 as u64;
        }

        let result = unsafe { raw_syscall6(number, raw_args) };
        Errno::from_ret(result as usize).map(|value| value as i64)
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
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
        if is_plain_fork(number, args) {
            let parent_tid = self.tid;
            let parent_pid = self.pid;
            let result = unsafe { raw_syscall6(number, args) };
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
        } else if let Some(error) = injected_syscall_guard(number, args) {
            self.tail.set_result(-i64::from(error.into_raw()));
        } else if is_exit_syscall(number) {
            self.tail.set_exit(number, args);
        } else {
            let value = unsafe { raw_syscall6(number, args) };
            self.tail.set_result(value);
        }
        std::future::pending().await
    }

    // TODO-HUMAN-REVIEW(PR-326): Review the coarse
    // syscall-boundary clock until the minimal ptrace supervisor wires PMU delivery.
    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        // Every intercepted syscall remains a deterministic scheduling boundary,
        // but a CPU-bound thread cannot yet be preempted between syscalls.
        Ok(())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        // Same coarse boundary as set_timer; never synthesize host time.
        Ok(())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        // DBI likewise exposes a boundary sample rather than a continuously
        // advancing PMU clock. LiteInst has no sample yet, so zero is the honest
        // deterministic lower bound. Detcore separately charges syscall time.
        Ok(0)
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

    fn allocate<'stack, V>(&mut self, value: V) -> AddrMut<'stack, V> {
        let align = core::mem::align_of::<V>();
        let base = self.arena.as_ptr() as usize;
        let start = (base + self.offset + align - 1) & !(align - 1);
        let offset = start - base;
        let end = offset + core::mem::size_of::<V>();
        assert!(end <= self.arena.len(), "LiteInst guest stack overflow");
        let pointer = unsafe { self.arena.as_mut_ptr().add(offset).cast::<V>() };
        unsafe { pointer.write(value) };
        self.offset = end;
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
        let value = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        self.allocate(value)
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(LocalStackGuard {
            arena: Some(self.arena),
        })
    }
}

fn tool_fatal(status: i32, error: &Error) -> ! {
    let message = format!("reverie-liteinst tool error: {error:?}\n");
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
