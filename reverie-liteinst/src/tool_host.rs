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
use reverie_inguest::guest::installed_tool;
use reverie_inguest::trap::raw_syscall6;

use crate::rpc::CoordinatorRpc;
use crate::runtime;
use crate::runtime::SyscallEvent;

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
            #[cfg(feature = "exec-private-init")]
            None,
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
            #[cfg(feature = "exec-private-init")]
            None,
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
            #[cfg(feature = "exec-private-init")]
            None,
        )
    }
}

/// Authenticated client and one native control prepared before Detcore setup.
/// This affine owner must be consumed by the actual Tool installer.
#[cfg(feature = "exec-private-init")]
pub struct PreparedInitialImage<T: Tool> {
    // Fields drop in declaration order: abandon before any generic Config or
    // client destructor can run, allocate, block, or panic.
    fatal: reverie_inguest::guest::exec_private::InitialImageAbortGuard,
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState>,
    control: reverie_inguest::guest::exec_private::InitialImageControl,
}

/// Installed InitialImage, retaining fatal ownership through eager lifecycle.
#[cfg(feature = "exec-private-init")]
pub struct InstalledInitialImage {
    fatal: reverie_inguest::guest::exec_private::InitialImageAbortGuard,
    control: reverie_inguest::guest::exec_private::InitialImageControl,
}

#[cfg(feature = "exec-private-init")]
impl InstalledInitialImage {
    /// Complete all existing native frontend and lifecycle checks exactly once.
    /// Any error terminates the owned image; successful return permits only the
    /// native runner's existing handover, not an independent Guest entry.
    pub fn finish(self) -> io::Result<()> {
        self.fatal.finish(&self.control)
    }
}

/// Prepare authenticated fixed gates before caller-context Detcore setup.
/// Ordinary preload initialization does not use this entry.
///
/// # Safety
/// The consumed client must have redeemed the launching coordinator's one-use
/// authorization for this exact watched image/filter lineage. Native control,
/// private loader and mapping provenance must satisfy
/// `publish_authenticated_control`. No guest code may have run. The Tool's
/// config must not require RCB time, preemption, threads, forks or exec yet.
#[cfg(feature = "exec-private-init")]
pub unsafe fn prepare_tool_initial_image<T: Tool>(
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
) -> io::Result<PreparedInitialImage<T>> {
    let fatal = unsafe { reverie_inguest::guest::exec_private::InitialImageAbortGuard::arm() };
    let control =
        unsafe { reverie_inguest::guest::exec_private::publish_authenticated_control(native)? };
    Ok(PreparedInitialImage {
        client,
        control,
        fatal,
    })
}

/// Install the actual Tool using the same authenticated client and native owner.
/// The caller must finish DETLOG/OFD setup, run
/// [`initialize_initial_image_lifecycle`], then consume the installed owner's
/// `finish` before the runner can resume the guest. No second adoption occurs.
///
/// # Safety
/// The prepared native image must still be in its exclusive initialization
/// phase on the private Tool FS/stack. No Guest code may have run.
#[cfg(feature = "exec-private-init")]
pub unsafe fn install_tool_initial_image<T>(
    coordinator: impl AsRef<Path>,
    prepared: PreparedInitialImage<T>,
) -> io::Result<InstalledInitialImage>
where
    T: Tool + 'static,
{
    let PreparedInitialImage {
        client,
        control,
        fatal,
    } = prepared;
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            false,
            runtime::PatchPublication::Quiescent,
            Some((client, &control, &fatal)),
        )?;
    }
    Ok(InstalledInitialImage { control, fatal })
}

/// Run genuine eager lifecycle on the actual installed InitialImage Tool.
/// Call after DETLOG/shared-OFD setup and before `InitialImageControl::finish`.
/// An error permanently refuses this initialization; the explicit native
/// initializer must terminate instead of resuming guest code. This does not
/// enter Guest, authenticate a new image or create another coordinator client.
#[cfg(feature = "exec-private-init")]
pub fn initialize_initial_image_lifecycle(image: &InstalledInitialImage) -> io::Result<()> {
    // SAFETY: these borrows belong to the same private affine installed owner.
    // Its live fatal guard spans the already bound host/frontend and this real
    // eager lifecycle; the caller completes DETLOG/OFD setup before finish.
    unsafe { installed_tool::initialize_initial_image_lifecycle(&image.control, &image.fatal) }
}

#[cfg(feature = "exec-private-init")]
fn initial_vdso_mprotect_result(result: i64, restoring: bool) -> Result<(), reverie::Errno> {
    if result == 0 {
        return Ok(());
    }
    if restoring {
        // RX restoration failed while the actual kernel vDSO is NX. Do not
        // allocate, format, log or unwind before the owned fixed terminal gate.
        unsafe {
            reverie_inguest::guest::exec_private::initialization_failed(core::ptr::null_mut())
        }
    }
    Err(reverie::Errno::new(result.wrapping_neg() as i32))
}

#[cfg(feature = "exec-private-init")]
unsafe fn patch_initial_image_vdso(
    subscriptions: &reverie::Subscription,
    control: &reverie_inguest::guest::exec_private::InitialImageControl,
) -> Result<(), reverie::Error> {
    control.check_initial_vdso_context()?;
    let mut owned_extent = None;
    let mut step = 0_u8;
    // SAFETY: the same authenticated control/fatal owner spans this call.
    // Guest has not run; bootstrap blocks asynchronous signals. The callback
    // admits only the qualified immutable extent and the RW -> RX sequence,
    // through the already adopted Tool raw gate, and cannot unwind under NX.
    unsafe {
        reverie::vdso::patch_current_vdso_trapping_owned(
            subscriptions,
            |address, len, protection| {
                let restoring = step == 1;
                if step == 0
                    && owned_extent.is_none()
                    && protection == libc::PROT_READ | libc::PROT_WRITE
                {
                    owned_extent = Some((address, len));
                } else if !restoring
                    || owned_extent != Some((address, len))
                    || protection != libc::PROT_READ | libc::PROT_EXEC
                {
                    reverie_inguest::guest::exec_private::initialization_failed(
                        core::ptr::null_mut(),
                    );
                }
                let result = raw_syscall6(
                    libc::SYS_mprotect,
                    [address as u64, len as u64, protection as u64, 0, 0, 0],
                );
                initial_vdso_mprotect_result(result, restoring)?;
                step = if restoring { 2 } else { 1 };
                Ok(())
            },
        )?;
    }
    control.check_initial_vdso_context()?;
    Ok(())
}

#[cfg(all(test, feature = "exec-private-init"))]
mod initial_vdso_tests {
    use super::*;

    #[test]
    fn failed_initial_vdso_rx_terminates_before_owner_drop_or_error_formatting() {
        // A component fixture owns an actual fixed terminal gate and actual
        // kernel vDSO. It does not redeem InitialImage authorization or prove a
        // native frontend. Shared progress proves RW succeeded and RX was
        // attempted; a returned error or panic must exit 94, not pass via Drop.
        let progress = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        assert_ne!(progress, libc::MAP_FAILED);
        let progress = progress.cast::<u64>();
        unsafe { progress.write_volatile(0) };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if unsafe { reverie_inguest::trap::prepare_fixed_gates() }.is_err() {
                unsafe { libc::_exit(95) };
            }
            let _fatal =
                unsafe { reverie_inguest::guest::exec_private::InitialImageAbortGuard::arm() };
            // The fatal guard is outside catch_unwind: a panic cannot turn
            // into the expected terminal status by unwinding this owner.
            let _ = std::panic::catch_unwind(|| unsafe {
                reverie::vdso::patch_current_vdso_trapping_owned(
                    &reverie::Subscription::all(),
                    |address, len, protection| {
                        if protection == libc::PROT_READ | libc::PROT_EXEC {
                            progress.write_volatile(2);
                            initial_vdso_mprotect_result(-(libc::EIO as i64), true)
                        } else {
                            let result = raw_syscall6(
                                libc::SYS_mprotect,
                                [address as u64, len as u64, protection as u64, 0, 0, 0],
                            );
                            initial_vdso_mprotect_result(result, false)?;
                            progress.write_volatile(1);
                            Ok(())
                        }
                    },
                )
            });
            // Never drop the owner here. Only the production result helper's
            // direct fixed terminal call may produce the expected exit 127.
            unsafe { libc::_exit(94) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let reached = unsafe { progress.read_volatile() };
        assert_eq!(unsafe { libc::munmap(progress.cast(), 4096) }, 0);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), 127);
        assert_eq!(reached, 2);
    }
}

unsafe fn install_tool_inner<T>(
    coordinator: &Path,
    remove_legacy_environment: bool,
    publication: runtime::PatchPublication,
    #[cfg(feature = "exec-private-init")] initial: Option<(
        reverie_rpc_transport::InitialImageClient<T::GlobalState>,
        &reverie_inguest::guest::exec_private::InitialImageControl,
        &reverie_inguest::guest::exec_private::InitialImageAbortGuard,
    )>,
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
    #[cfg(feature = "exec-private-init")]
    let private_initial = initial.is_some();
    #[cfg(not(feature = "exec-private-init"))]
    let private_initial = false;

    #[cfg(feature = "fixed-syscall-gates")]
    let mut fixed_install = FixedGateInstallation { complete: false };
    #[cfg(feature = "fixed-syscall-gates")]
    unsafe {
        if !private_initial && reverie_inguest::guest::sigalrm::seccomp_filter_count() != Some(0) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fixed syscall gates refuse an inherited or unreadable seccomp filter state",
            ));
        }
        // All runtime signal actions and their filter must select the same
        // fixed page. Prepare it before any callback or handler is published.
        if !private_initial {
            reverie_inguest::trap::prepare_fixed_gates()?;
        }
    }
    crate::syscall_fallback::initialize()?;
    #[cfg(feature = "exec-private-init")]
    let (rpc, initial_owner) = match initial {
        Some((client, control, fatal)) => (
            CoordinatorRpc::<T::GlobalState>::from_live_client(
                coordinator,
                client.into_client(),
                runtime::replace_coordinator_fd,
            )?,
            Some((control, fatal)),
        ),
        None => (
            CoordinatorRpc::<T::GlobalState>::connect(
                coordinator,
                runtime::replace_coordinator_fd,
            )?,
            None,
        ),
    };
    #[cfg(feature = "exec-private-init")]
    let initial_control = initial_owner.map(|(control, _fatal)| control);
    #[cfg(not(feature = "exec-private-init"))]
    let rpc =
        CoordinatorRpc::<T::GlobalState>::connect(coordinator, runtime::replace_coordinator_fd)?;
    runtime::reserve_coordinator_fd(rpc.raw_fd())?;
    let stats = if private_initial {
        #[cfg(feature = "exec-private-init")]
        {
            let control = initial_control.ok_or_else(|| {
                io::Error::other("InitialImage statistics requires authenticated control")
            })?;
            // The existing narrow context check requires this same published
            // control, initial thread, Tool FS, phase 2 and installation 0.
            // The caller retains its fatal owner across collector setup.
            control.check_initial_vdso_context()?;
            let endpoint = crate::initial_image_stats::initial_image_stats_endpoint(coordinator)?;
            let stats = crate::stats::initialize_guest_stats(&endpoint)?;
            control.check_initial_vdso_context()?;
            stats
        }
        #[cfg(not(feature = "exec-private-init"))]
        {
            crate::stats::GuestStatsHooks::DISABLED
        }
    } else {
        if let Some(stats_coordinator) = std::env::var_os(crate::backend::STATS_COORDINATOR_ENV) {
            let stats = crate::stats::initialize_guest_stats(Path::new(&stats_coordinator))?;
            // SAFETY: tool installation runs before application-created threads.
            unsafe { std::env::remove_var(crate::backend::STATS_COORDINATOR_ENV) };
            stats
        } else {
            crate::stats::GuestStatsHooks::DISABLED
        }
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
    let site_patching = if private_initial {
        false
    } else {
        runtime::site_patching_from_env_value(
            std::env::var_os(runtime::SITE_PATCHING_ENV).as_deref(),
        )?
    };
    // With site patching off, the vDSO gets ptrace's full trapping stubs and no
    // hooks, so its fast paths reach the Tool through the SIGSYS fallback too.
    #[cfg(feature = "exec-private-init")]
    let initial_vdso =
        initial_control.map(|control| unsafe { patch_initial_image_vdso(&subscriptions, control) });
    #[cfg(not(feature = "exec-private-init"))]
    let initial_vdso: Option<Result<(), reverie::Error>> = None;
    let vdso_sites = if let Some(result) = initial_vdso {
        result.map(|()| Vec::new())
    } else if site_patching {
        reverie::vdso::patch_current_vdso(&subscriptions)
    } else {
        reverie::vdso::patch_current_vdso_trapping(&subscriptions).map(|()| Vec::new())
    }
    .map_err(|error| {
        io::Error::other(reverie_inguest::guest::host::describe_reverie_error(&error))
    })?;
    #[cfg(feature = "exec-private-init")]
    let _signal_state = if let Some(control) = initial_control {
        control.prepare_signal_state(instruction_subscriptions)?;
        None
    } else {
        Some(runtime::prepare_guest_signal_state(
            instruction_subscriptions,
        )?)
    };
    #[cfg(not(feature = "exec-private-init"))]
    let _signal_state = runtime::prepare_guest_signal_state(instruction_subscriptions)?;
    let syscall_subscriptions = subscriptions.iter_syscalls().collect();
    if remove_legacy_environment {
        // SAFETY: legacy tool installation runs before application-created threads.
        unsafe { std::env::remove_var(crate::backend::COORDINATOR_ENV) };
    }
    let tool = T::new(pid, rpc.config());
    let host = ToolHost::<T, LiteinstRuntime>::new(
        tool,
        rpc,
        pid,
        syscall_subscriptions,
        instruction_subscriptions.cpuid,
        LiteinstRuntime { stats },
    );
    // SAFETY: this is the same installer publication point, after actual
    // allocator/setup/client/subscription admission and before activation.
    #[cfg(feature = "exec-private-init")]
    unsafe {
        if let Some((control, fatal)) = initial_owner {
            installed_tool::publish_initial_tool(host, control, fatal)?;
        } else {
            installed_tool::publish_tool(host)?;
        }
    }
    #[cfg(not(feature = "exec-private-init"))]
    unsafe {
        installed_tool::publish_tool(host)?;
    }
    let result = runtime::initialize_reverie_tool(
        stats,
        publication,
        instruction_subscriptions,
        site_patching,
        &vdso_sites,
        prepared_callbacks,
        #[cfg(feature = "exec-private-init")]
        initial_control,
    );
    #[cfg(feature = "fixed-syscall-gates")]
    {
        fixed_install.complete = result.is_ok();
    }
    result
}

/// A published fixed gate cannot be rolled back while an installed action or
/// filter can still name it. A failed install must not resume guest code.
#[cfg(feature = "fixed-syscall-gates")]
struct FixedGateInstallation {
    complete: bool,
}

#[cfg(feature = "fixed-syscall-gates")]
impl Drop for FixedGateInstallation {
    fn drop(&mut self) {
        if !self.complete && reverie_inguest::trap::fixed_gates_published() {
            unsafe {
                // Even stderr may be a full blocking pipe. Publication has
                // made returning unsafe, so diagnostics cannot precede exit.
                raw_syscall6(libc::SYS_exit_group, [127, 0, 0, 0, 0, 0]);
                core::arch::asm!("ud2", options(noreturn));
            }
        }
    }
}

pub use installed_tool::blocking_global_rpc;

pub(crate) fn dispatch(event: &mut SyscallEvent) {
    // SAFETY: only LI's genuine intercepted paths reach this private wrapper,
    // retaining their actual event/frame, rights, RCB and callback protection.
    unsafe { installed_tool::dispatch(event) };
}

pub(crate) fn dispatch_instruction(kind: runtime::InstructionEventKind, context: &mut HookContext) {
    // SAFETY: HookContext and RegisterContext have identical layout (all
    // fields checked above). LI supplies the unique saved frame of this actual
    // intercepted instruction under its existing native/accounting guards.
    let context = unsafe { &mut *(context as *mut HookContext).cast::<RegisterContext>() };
    unsafe { installed_tool::dispatch_instruction(kind, context) };
}
