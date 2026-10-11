//! Installs a Reverie Tool in this guest on reverie-inguest's Tool host
//! ([`reverie_inguest::guest::host::ToolHost`]) and supplies LiteInst's
//! runtime services to it.

use std::io;
use std::path::Path;

use liteinst2::trampoline::HookContext;
use reverie::GlobalRPC;
use reverie::Pid;
use reverie::Tool;
use reverie_inguest::guest::context::RegisterContext;
use reverie_inguest::guest::host::HostRuntime;
use reverie_inguest::guest::host::ToolHost;
use reverie_inguest::trap::raw_syscall6;

use crate::rpc::CoordinatorRpc;
use crate::runtime;
use crate::runtime::SyscallEvent;

trait ToolHandler: Send + Sync {
    fn dispatch(&self, event: &mut SyscallEvent);
    fn dispatch_instruction(&self, kind: runtime::InstructionEventKind, context: &mut HookContext);
    /// The installed Tool's coordinator connection, as a
    /// `CoordinatorRpc<T::GlobalState>`; see [`blocking_global_rpc`].
    fn rpc(&self) -> &dyn std::any::Any;
}

impl<T: Tool + 'static> ToolHandler for ToolHost<T, LiteinstRuntime> {
    fn dispatch(&self, event: &mut SyscallEvent) {
        // SAFETY: the runtime calls this only from a guest thread's trap, hook
        // or continuation path, with `event.context` either 0 or the address
        // of the HookContext that path saved on its own stack (same layout as
        // RegisterContext, checked below), live and unshared for the call.
        // The Tool is the one install_tool installed, and its injections act
        // on the guest it instruments.
        unsafe { ToolHost::dispatch(self, event) };
    }

    fn dispatch_instruction(&self, kind: runtime::InstructionEventKind, context: &mut HookContext) {
        // SAFETY: HookContext and RegisterContext have the same layout
        // (checked below), and the reference is unique for the call. The
        // runtime calls this only from the hook or continuation that
        // intercepted the instruction, with its saved registers; the Tool is
        // the one install_tool installed, and its injections act on the guest
        // it instruments.
        let context = unsafe { &mut *(context as *mut HookContext).cast::<RegisterContext>() };
        unsafe { ToolHost::dispatch_instruction(self, kind, context) };
    }

    fn rpc(&self) -> &dyn std::any::Any {
        ToolHost::rpc(self)
    }
}

// The trampolines and the fallback continuation save a HookContext; the host
// reads it as a RegisterContext.
const _: () = {
    use core::mem::align_of;
    use core::mem::offset_of;
    use core::mem::size_of;
    assert!(size_of::<HookContext>() == size_of::<RegisterContext>());
    assert!(align_of::<HookContext>() == align_of::<RegisterContext>());
    assert!(
        offset_of!(HookContext, instruction_pointer)
            == offset_of!(RegisterContext, instruction_pointer)
    );
    assert!(offset_of!(HookContext, stack_pointer) == offset_of!(RegisterContext, stack_pointer));
    assert!(offset_of!(HookContext, r15) == offset_of!(RegisterContext, r15));
    assert!(offset_of!(HookContext, r14) == offset_of!(RegisterContext, r14));
    assert!(offset_of!(HookContext, r13) == offset_of!(RegisterContext, r13));
    assert!(offset_of!(HookContext, r12) == offset_of!(RegisterContext, r12));
    assert!(offset_of!(HookContext, r11) == offset_of!(RegisterContext, r11));
    assert!(offset_of!(HookContext, r10) == offset_of!(RegisterContext, r10));
    assert!(offset_of!(HookContext, r9) == offset_of!(RegisterContext, r9));
    assert!(offset_of!(HookContext, r8) == offset_of!(RegisterContext, r8));
    assert!(offset_of!(HookContext, rdi) == offset_of!(RegisterContext, rdi));
    assert!(offset_of!(HookContext, rsi) == offset_of!(RegisterContext, rsi));
    assert!(offset_of!(HookContext, rbp) == offset_of!(RegisterContext, rbp));
    assert!(offset_of!(HookContext, rbx) == offset_of!(RegisterContext, rbx));
    assert!(offset_of!(HookContext, rdx) == offset_of!(RegisterContext, rdx));
    assert!(offset_of!(HookContext, rcx) == offset_of!(RegisterContext, rcx));
    assert!(offset_of!(HookContext, rax) == offset_of!(RegisterContext, rax));
    assert!(offset_of!(HookContext, rflags) == offset_of!(RegisterContext, rflags));
};

/// LiteInst's services for the in-guest Tool host.
struct LiteinstRuntime {
    stats: crate::stats::GuestStatsHooks,
}

impl HostRuntime for LiteinstRuntime {
    fn fork_child_rebind(&self) {
        crate::syscall_fallback::rebind_fork_child();
    }

    fn emit_stage(&self, stage: &[u8]) {
        runtime::emit_in_guest_stage(stage);
    }

    fn fork_child_reset(&self, event: &SyscallEvent) {
        runtime::reset_fallback_observability();
        self.stats.reset_after_fork();
        runtime::record_fork_child_dispatch(event, self.stats);
    }

    fn cpuid_interception_enabled(&self) -> bool {
        runtime::cpuid_interception_enabled()
    }

    fn exit_process_stats(&self, tid: Pid) -> io::Result<()> {
        if self.stats.is_enabled() {
            runtime::submit_process_stats(tid, self.stats)
        } else {
            Ok(())
        }
    }

    fn read_clock(&self) -> io::Result<u64> {
        runtime::read_guest_rcb_clock()
    }

    fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
        runtime::signal_action_supported(number, args)
    }

    fn reserved_signal_mask(&self) -> u64 {
        runtime::reserved_signal_mask()
    }
}

static HANDLER: std::sync::OnceLock<Box<dyn ToolHandler>> = std::sync::OnceLock::new();

// TODO-HUMAN-REVIEW(PR-127): Review generic in-guest Tool hosting.
/// Install a concrete Reverie tool in this guest and connect it to its coordinator.
///
/// The caller is normally a tool-specific preload DSO. It must invoke this
/// before application threads start and before any seccomp filter is active.
/// Use [`crate::declare_fixed_tool_allocator!`] in a true preload root, after
/// authenticated fixed-region startup, or an explicit legacy allocator
/// declaration for an embedded Tool. Missing or duplicate per-image backing
/// declarations are link errors. Fixed backing not yet published returns
/// `EAGAIN` before any compiler allocation. The shared core is allocator
/// neutral. A compiler-selected allocator that does not own the
/// dispatch preflight allocation is refused with `EOPNOTSUPP` before any Tool,
/// coordinator connection or filter is installed; exhaustion returns `ENOMEM`.
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
/// The root must use the fixed or legacy allocator declaration described by
/// [`install_tool`]; the same pre-activation allocator check and
/// errors as [`install_tool`] apply.
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
/// The root must use the fixed or legacy allocator declaration described by
/// [`install_tool`]; the same pre-activation allocator check and
/// errors as [`install_tool`] apply.
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
    // Everything installation allocates (the coordinator's configuration,
    // the Tool, the runtime's /proc/self/maps snapshots and site tables)
    // lives in the runtime's private Tool heap, never in the guest's own
    // malloc heap, where it would stay before `main` runs. Its sizes follow
    // host state, such as the number of mounts the configuration lists, so
    // the guest's heap layout, and every heap address its syscalls pass,
    // would otherwise differ between two runs of one program. The Tool heap
    // is anonymous memory, so the entry census of the object that links this
    // runtime does not read the Tool's state as code addresses either.
    let _private_allocations = reverie_inguest::guest::alloc::enter_dispatch();
    crate::patch_alloc::preflight_allocator()?;
    crate::syscall_fallback::initialize()?;
    let rpc =
        CoordinatorRpc::<T::GlobalState>::connect(coordinator, runtime::replace_coordinator_fd)?;
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
    // Complete the new fixed callback pool and route publication before the
    // guest counter starts. Later installation consumes only this proof;
    // allocating the pool there would charge Tool setup to guest progress.
    let prepared_callbacks = runtime::prepare_installed_callbacks()?;
    runtime::initialize_rcb_clock()?;
    // The raw syscall, not libc's interposable getpid.
    let pid = Pid::from_raw(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) } as i32);
    let subscriptions = T::subscriptions(rpc.config());
    let instruction_subscriptions = runtime::InstructionSubscriptions {
        cpuid: subscriptions.has_cpuid(),
        rdtsc: subscriptions.has_rdtsc(),
    };
    runtime::preflight_instruction_faulting(instruction_subscriptions)?;
    let site_patching = runtime::site_patching_from_env_value(
        std::env::var_os(runtime::SITE_PATCHING_ENV).as_deref(),
    )?;
    // With site patching off, the vDSO gets ptrace's full trapping stubs and no
    // hooks, so its fast paths reach the Tool through the SIGSYS fallback too.
    let vdso_sites = if site_patching {
        reverie_ptrace::patch_current_vdso(&subscriptions)
    } else {
        reverie_ptrace::patch_current_vdso_trapping(&subscriptions).map(|()| Vec::new())
    }
    .map_err(|error| {
        io::Error::other(reverie_inguest::guest::host::describe_reverie_error(&error))
    })?;
    let _signal_state = runtime::prepare_guest_signal_state(instruction_subscriptions)?;
    let syscall_subscriptions = subscriptions.iter_syscalls().collect();
    if remove_legacy_environment {
        // SAFETY: legacy tool installation runs before application-created threads.
        unsafe { std::env::remove_var(crate::backend::COORDINATOR_ENV) };
    }
    let tool = T::new(pid, rpc.config());
    HANDLER
        .set(Box::new(ToolHost::<T, LiteinstRuntime>::new(
            tool,
            rpc,
            pid,
            syscall_subscriptions,
            instruction_subscriptions.cpuid,
            LiteinstRuntime { stats },
        )))
        .map_err(|_| {
            io::Error::new(io::ErrorKind::AlreadyExists, "Reverie tool installed twice")
        })?;
    runtime::initialize_reverie_tool(
        stats,
        publication,
        instruction_subscriptions,
        site_patching,
        &vdso_sites,
        prepared_callbacks,
    )
}

/// Sends `request` to the coordinator's global state and waits for its
/// response, from the installed Tool's own synchronous code running inside a
/// Tool callback but outside the callback's own `send_rpc`: for example from
/// a synchronous method a callback calls, where no [`reverie::Guest`] is at
/// hand. Inside a callback the runtime's own syscalls are not intercepted.
/// Guest code outside a callback cannot use this: its syscalls on the
/// coordinator connection are guest syscalls, which the runtime refuses. It uses the process's one existing
/// coordinator connection, so it reconnects after a fork exactly as callbacks
/// do, and it adds no descriptor.
///
/// Fails, without sending, when no Tool is installed in this process, when
/// `G` is not the installed Tool's global state, or when another request of
/// this process is in flight on the connection (re-entry, which waiting would
/// deadlock). It also fails, with ESRCH, while the running callback has
/// staged an injection that ends the guest (an exit, or a SIGKILL of the
/// guest itself) and goes on regardless, as every effect of such a callback
/// is refused; the exit callbacks that follow can use it.
pub fn blocking_global_rpc<G: reverie::GlobalTool + 'static>(
    request: G::Request,
) -> io::Result<G::Response> {
    if reverie_inguest::guest::host::callback_ending_staged() {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    let handler = HANDLER
        .get()
        .ok_or_else(|| io::Error::other("no in-guest Tool is installed in this process"))?;
    let rpc = handler
        .rpc()
        .downcast_ref::<CoordinatorRpc<G>>()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the requested global state is not the installed Tool's",
            )
        })?;
    rpc.send_blocking_unless_in_flight(request).map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "another coordinator request of this process is in flight",
        )
    })
}

pub(crate) fn dispatch(event: &mut SyscallEvent) {
    match HANDLER.get() {
        Some(handler) => handler.dispatch(event),
        None => event.result = -i64::from(libc::ENOSYS),
    }
}

pub(crate) fn dispatch_instruction(kind: runtime::InstructionEventKind, context: &mut HookContext) {
    match HANDLER.get() {
        Some(handler) => handler.dispatch_instruction(kind, context),
        None => fatal(126),
    }
}

fn fatal(status: i32) -> ! {
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}
