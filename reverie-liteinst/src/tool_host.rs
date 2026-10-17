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
#[cfg(feature = "exec-private-init")]
use reverie_inguest::guest::rpc::GuestRpcStream;
use reverie_inguest::trap::raw_syscall6;

use crate::rpc::CoordinatorRpc;
use crate::runtime;
use crate::runtime::SyscallEvent;

// Patched trampolines save HookContext; the shared entry reads RegisterContext.
// The shared fallback continuation already owns RegisterContext.
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
    #[cfg(feature = "exec-native-injection")]
    no_rcb: bool,
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
        #[cfg(feature = "exec-native-injection")]
        if self.no_rcb {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native first-domain RCB clock is unsupported",
            ));
        }
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
            #[cfg(feature = "exec-native-injection")]
            None,
            #[cfg(feature = "exec-native-injection")]
            false,
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
            #[cfg(feature = "exec-native-injection")]
            None,
            #[cfg(feature = "exec-native-injection")]
            false,
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
            #[cfg(feature = "exec-native-injection")]
            None,
            #[cfg(feature = "exec-native-injection")]
            false,
        )
    }
}

#[cfg(feature = "exec-private-init")]
#[derive(Clone, Copy)]
pub(crate) enum PrivateImageControl<'a> {
    Initial(&'a reverie_inguest::guest::exec_private::InitialImageControl),
    #[cfg(feature = "exec-native-injection")]
    Successor(&'a reverie_inguest::guest::exec_private::SuccessorImageControl),
}

#[cfg(feature = "exec-private-init")]
impl PrivateImageControl<'_> {
    fn check_vdso_context(self) -> io::Result<()> {
        match self {
            Self::Initial(control) => control.check_initial_vdso_context(),
            #[cfg(feature = "exec-native-injection")]
            Self::Successor(control) => control.check_successor_vdso_context(),
        }
    }

    fn prepare_signal_state(
        self,
        instructions: runtime::InstructionSubscriptions,
    ) -> io::Result<()> {
        match self {
            Self::Initial(control) => control.prepare_signal_state(instructions),
            #[cfg(feature = "exec-native-injection")]
            Self::Successor(control) => control.prepare_signal_state(instructions),
        }
    }
}

#[cfg(feature = "exec-private-init")]
enum ImageInstall<'a, T: Tool> {
    Initial(
        reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
        &'a reverie_inguest::guest::exec_private::InitialImageControl,
        &'a reverie_inguest::guest::exec_private::InitialImageAbortGuard,
    ),
    #[cfg(feature = "exec-native-injection")]
    Successor {
        client: reverie_rpc_transport::BlockingRpcClient<T::GlobalState, GuestRpcStream>,
        control: &'a reverie_inguest::guest::exec_private::SuccessorImageControl,
        tool: T,
        state: T::ThreadState,
        consumer: &'a mut dyn NativeSuccessorConsumer<T>,
    },
}

/// Authenticated client and one native control prepared before Detcore setup.
/// This affine owner must be consumed by the actual Tool installer.
#[cfg(feature = "exec-private-init")]
pub struct PreparedInitialImage<T: Tool> {
    // Fields drop in declaration order: abandon before any generic Config or
    // client destructor can run, allocate, block, or panic.
    fatal: reverie_inguest::guest::exec_private::InitialImageAbortGuard,
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
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
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
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
            Some(ImageInstall::Initial(client, &control, &fatal)),
            #[cfg(feature = "exec-native-injection")]
            None,
            #[cfg(feature = "exec-native-injection")]
            false,
        )?;
    }
    Ok(InstalledInitialImage { control, fatal })
}

/// Trusted consumer for an actual admitted native successor image.
///
/// # Safety
/// The implementation must retain real watched-birth/Issued/kernel-exec and
/// immutable bootstrap/allocator/Config/source-closure authority. Qualification
/// must inspect the same actual Config and reject every PMU/RCB/preemption/time,
/// thread/fork, guest-handler or site-patching requirement outside this first
/// domain; skipping PMU setup never disables a requested feature. Decode must
/// consume the full bounded authenticated composite exactly, validate every
/// Tool/thread/runtime/Config/cut identity, and return the actual saved Tool and
/// thread state. Neither digests nor request IDs create capability.
/// Restore must use actual fresh collectors and checked sequence once, refuse
/// existing activity, and prove the genuine DETLOG cut before any observer or
/// guest work. Complete must send the real typed CompleteNativeExec on the
/// provided installed RPC, retain consumption on error, and return only the
/// exact received response binding. No local matching value or boolean is ACK.
/// Trusted qualification, decode/restore and Tool setup must not unwind or
/// permit guest/observer work. Tool/Config/state teardown during failed native
/// setup must not mutate physical/runtime ownership or unwind; ordinary Tool
/// installation contracts remain unchanged. Explicit returned failures take
/// the fixed terminal edge before installer-owned teardown.
/// Destruction after successful finish must not invalidate retained mappings,
/// FDs, frontend or launch authority; hand off such ownership before returning.
#[cfg(feature = "exec-native-injection")]
pub unsafe trait NativeSuccessorConsumer<T: Tool>: Send {
    fn qualify_config(
        &self,
        config: &<T::GlobalState as reverie::GlobalTool>::Config,
    ) -> io::Result<()>;

    fn decode_verified(
        &mut self,
        config: &<T::GlobalState as reverie::GlobalTool>::Config,
        state: &reverie_rpc_transport::successor::VerifiedSuccessorState,
        binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    ) -> io::Result<(T, T::ThreadState)>;

    fn restore_fresh_runtime(
        &mut self,
        binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    ) -> io::Result<()>;

    fn complete(
        &mut self,
        rpc: &CoordinatorRpc<T::GlobalState>,
        binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    ) -> io::Result<reverie_inguest::guest::exec_private::SuccessorBinding>;
}

#[cfg(feature = "exec-native-injection")]
fn require_native_success<V>(result: io::Result<V>) -> V {
    match result {
        Ok(value) => value,
        Err(_) => unsafe {
            // Native initialization cannot return to generic owned teardown
            // after a failed authenticated operation. The fixed terminal gate
            // is owned before these explicit entry points are invoked.
            reverie_inguest::guest::exec_private::initialization_failed(core::ptr::null_mut())
        },
    }
}

#[cfg(feature = "exec-native-injection")]
struct SuccessorAbortGuard {
    active: bool,
}

#[cfg(feature = "exec-native-injection")]
impl Drop for SuccessorAbortGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: only authenticated native preparation constructs this
            // guard, owning the actual inherited fixed terminal gate.
            unsafe {
                reverie_inguest::guest::exec_private::initialization_failed(core::ptr::null_mut())
            }
        }
    }
}

/// One affine authenticated successor, with its complete decoded Tool/state.
#[cfg(feature = "exec-native-injection")]
pub struct PreparedSuccessorImage<T: Tool> {
    // Terminal before generic client, Tool/state, consumer or control drops.
    fatal: SuccessorAbortGuard,
    client: reverie_rpc_transport::BlockingRpcClient<T::GlobalState, GuestRpcStream>,
    tool: T,
    state: T::ThreadState,
    consumer: Box<dyn NativeSuccessorConsumer<T>>,
    control: reverie_inguest::guest::exec_private::SuccessorImageControl,
}

/// Actual installed successor retaining fatal ownership until exact completion.
#[cfg(feature = "exec-native-injection")]
pub struct InstalledSuccessorImage<T: Tool> {
    fatal: SuccessorAbortGuard,
    consumer: Box<dyn NativeSuccessorConsumer<T>>,
    control: reverie_inguest::guest::exec_private::SuccessorImageControl,
}

#[cfg(feature = "exec-native-injection")]
impl<T: Tool + 'static> InstalledSuccessorImage<T> {
    /// Run the real post-exec once on actual restored Tool/state. Guest/observer
    /// work remains forbidden; the entry must be the actual native resume.
    pub fn run_post_exec_before_loader(
        &self,
        entry: &mut reverie_inguest::guest::exec_private::ImageGuestEntry,
    ) -> io::Result<()> {
        // SAFETY: this affine installed successor retains the actual control,
        // entry/fatal ownership and exclusive pre-loader interval.
        unsafe { installed_tool::run_successor_post_exec(entry, &self.control) }
    }

    /// Consume after the real lifecycle and exact received completion ACK.
    /// Existing physical control checks run before and after the exchange.
    ///
    /// # Safety
    /// Retain the native bootstrap/leases and exclude guest/observer work until
    /// successful return and the runner's existing native handover. The unsafe
    /// consumer must satisfy its real completion and resource-handoff contract.
    pub unsafe fn finish(mut self) -> io::Result<()> {
        unsafe {
            installed_tool::finish_successor_image::<T::GlobalState>(
                &self.control,
                |rpc, binding| self.consumer.complete(rpc, binding),
            )?;
        }
        self.fatal.active = false;
        Ok(())
    }
}

#[cfg(feature = "exec-native-injection")]
fn check_successor_binding(
    state: &reverie_rpc_transport::successor::VerifiedSuccessorState,
    binding: reverie_inguest::guest::exec_private::SuccessorBinding,
) -> io::Result<()> {
    if binding.generation == 0
        || binding.ticket == [0; 32]
        || binding.state == [0; 32]
        || binding.config == [0; 32]
        || state.ticket_digest() != binding.ticket
        || state.expected().state != binding.state
        || state.expected().config != binding.config
    {
        return Err(io::Error::other(
            "successor admitted transport binding differs",
        ));
    }
    Ok(())
}

/// Decode a genuinely redeemed successor before publishing its native control.
///
/// # Safety
/// The actual SuccessorClient and independent binding must name this genuine
/// successful kernel exec and retained watched birth. The inherited fixed
/// terminal gate, private loader/Tool FS/control extents and fresh allocator
/// must already be authenticated; no guest code may have run. The consumer
/// must uphold every unsafe trait contract. Errors or abandonment are terminal.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn prepare_tool_successor_image<T: Tool + 'static>(
    client: reverie_rpc_transport::SuccessorClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
    binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    mut consumer: Box<dyn NativeSuccessorConsumer<T>>,
) -> io::Result<PreparedSuccessorImage<T>> {
    let fatal = SuccessorAbortGuard { active: true };
    let _private_allocations = reverie_inguest::guest::alloc::enter_dispatch();
    require_native_success(crate::patch_alloc::preflight_allocator());
    require_native_success(check_successor_binding(client.state(), binding));
    require_native_success(consumer.qualify_config(client.config()));
    let (tool, state) =
        require_native_success(consumer.decode_verified(client.config(), client.state(), binding));
    let control = require_native_success(unsafe {
        reverie_inguest::guest::exec_private::publish_authenticated_successor_control(
            native, binding,
        )
    });
    let (client, verified) = client.into_parts();
    drop(verified);
    Ok(PreparedSuccessorImage {
        fatal,
        client,
        tool,
        state,
        consumer,
        control,
    })
}

/// Install the actual native successor Tool/frontend from the prepared image.
/// Real post-exec and finish remain mandatory before loader entry.
///
/// # Safety
/// Keep the authenticated exclusive private Tool FS/stack/bootstrap interval;
/// no guest, handler or observer work may run. The driver must retain genuine
/// native authority and satisfy its unsafe contracts, without reacquiring the
/// host's Tool/state locks. The runtime consumer owns exact fresh restoration.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn install_tool_successor_image<T: Tool + 'static>(
    coordinator: impl AsRef<Path>,
    prepared: PreparedSuccessorImage<T>,
    driver: std::sync::Arc<dyn reverie_inguest::guest::native_exec::NativeExecDriver<T>>,
) -> io::Result<InstalledSuccessorImage<T>> {
    // Keep the affine prepared owner intact while trusted qualification runs.
    let _private_allocations = reverie_inguest::guest::alloc::enter_dispatch();
    require_native_success(prepared.consumer.qualify_config(prepared.client.config()));
    let PreparedSuccessorImage {
        fatal,
        client,
        tool,
        state,
        mut consumer,
        control,
    } = prepared;
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            false,
            runtime::PatchPublication::Quiescent,
            Some(ImageInstall::Successor {
                client,
                control: &control,
                tool,
                state,
                consumer: &mut *consumer,
            }),
            Some(driver),
            true,
        )?;
    }
    Ok(InstalledSuccessorImage {
        fatal,
        consumer,
        control,
    })
}

/// Install an authenticated initial image with its concrete native exec driver
/// before the first dispatch. Ordinary InitialImage installation is unchanged.
///
/// # Safety
/// All InitialImage and NativeExecDriver contracts apply. `qualify` must inspect
/// this same actual Config and explicitly reject unsupported PMU/RCB/time,
/// preemption, threads/forks, guest handlers and site-patching requirements
/// before PMU initialization is skipped. It must not disable requested features
/// or accept a synthetic Config. Retain real native birth/launch authority.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn install_tool_initial_image_with_native_exec<T: Tool + 'static>(
    coordinator: impl AsRef<Path>,
    prepared: PreparedInitialImage<T>,
    driver: std::sync::Arc<dyn reverie_inguest::guest::native_exec::NativeExecDriver<T>>,
    qualify: impl FnOnce(&<T::GlobalState as reverie::GlobalTool>::Config) -> io::Result<()>,
) -> io::Result<InstalledInitialImage> {
    let PreparedInitialImage {
        fatal,
        client,
        control,
    } = prepared;
    let _private_allocations = reverie_inguest::guest::alloc::enter_dispatch();
    require_native_success(qualify(client.config()));
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            false,
            runtime::PatchPublication::Quiescent,
            Some(ImageInstall::Initial(client, &control, &fatal)),
            Some(driver),
            true,
        )?;
    }
    Ok(InstalledInitialImage { fatal, control })
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
    control: PrivateImageControl<'_>,
) -> Result<(), reverie::Error> {
    control.check_vdso_context()?;
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
    control.check_vdso_context()?;
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
    #[cfg(feature = "exec-private-init")] initial: Option<ImageInstall<'_, T>>,
    #[cfg(feature = "exec-native-injection")] native_driver: Option<
        std::sync::Arc<dyn reverie_inguest::guest::native_exec::NativeExecDriver<T>>,
    >,
    #[cfg(feature = "exec-native-injection")] skip_pmu: bool,
) -> io::Result<()>
where
    T: Tool + 'static,
{
    macro_rules! install_try {
        ($operation:expr) => {
            match $operation {
                Ok(value) => value,
                Err(error) => {
                    #[cfg(feature = "exec-native-injection")]
                    if skip_pmu {
                        require_native_success::<()>(Err(error));
                        unreachable!();
                    }
                    return Err(error);
                }
            }
        };
    }
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
    install_try!(crate::patch_alloc::preflight_allocator());
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
            install_try!(reverie_inguest::trap::prepare_fixed_gates());
        }
    }
    install_try!(crate::syscall_fallback::initialize());
    #[cfg(feature = "exec-native-injection")]
    let mut restored_tool = None;
    #[cfg(feature = "exec-native-injection")]
    let mut restored_state = None;
    #[cfg(feature = "exec-native-injection")]
    let mut runtime_restore: Option<Box<dyn FnOnce() -> io::Result<()> + '_>> = None;
    #[cfg(feature = "exec-private-init")]
    let (rpc, initial_control, initial_fatal) = match initial {
        Some(ImageInstall::Initial(client, control, fatal)) => (
            install_try!(CoordinatorRpc::<T::GlobalState>::from_live_client(
                coordinator,
                client.into_client(),
                runtime::replace_coordinator_fd,
            )),
            Some(PrivateImageControl::Initial(control)),
            Some(fatal),
        ),
        #[cfg(feature = "exec-native-injection")]
        Some(ImageInstall::Successor {
            client,
            control,
            tool,
            state,
            consumer,
        }) => {
            let binding = control.binding();
            restored_tool = Some(tool);
            restored_state = Some(state);
            runtime_restore = Some(Box::new(move || consumer.restore_fresh_runtime(binding)));
            (
                install_try!(CoordinatorRpc::<T::GlobalState>::from_live_client(
                    coordinator,
                    client,
                    runtime::replace_coordinator_fd,
                )),
                Some(PrivateImageControl::Successor(control)),
                None,
            )
        }
        None => (
            install_try!(CoordinatorRpc::<T::GlobalState>::connect(
                coordinator,
                runtime::replace_coordinator_fd,
            )),
            None,
            None,
        ),
    };
    #[cfg(not(feature = "exec-private-init"))]
    let rpc = install_try!(CoordinatorRpc::<T::GlobalState>::connect(
        coordinator,
        runtime::replace_coordinator_fd
    ));
    install_try!(runtime::reserve_coordinator_fd(rpc.raw_fd()));
    let stats = if private_initial {
        #[cfg(feature = "exec-private-init")]
        {
            let control = install_try!(initial_control.ok_or_else(|| {
                io::Error::other("InitialImage statistics requires authenticated control")
            }));
            // The existing narrow context check requires this same published
            // control, initial thread, Tool FS, phase 2 and installation 0.
            // The caller retains its fatal owner across collector setup.
            install_try!(control.check_vdso_context());
            let endpoint = install_try!(crate::initial_image_stats::initial_image_stats_endpoint(
                coordinator
            ));
            let stats = install_try!(crate::stats::initialize_guest_stats(&endpoint));
            install_try!(control.check_vdso_context());
            stats
        }
        #[cfg(not(feature = "exec-private-init"))]
        {
            crate::stats::GuestStatsHooks::DISABLED
        }
    } else {
        if let Some(stats_coordinator) = reverie_inguest::bootstrap::bootstrap_stats_coordinator() {
            install_try!(crate::stats::initialize_guest_stats(stats_coordinator))
        } else if let Some(stats_coordinator) =
            std::env::var_os(crate::backend::STATS_COORDINATOR_ENV)
        {
            let stats = install_try!(crate::stats::initialize_guest_stats(Path::new(
                &stats_coordinator
            )));
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
    let prepared_callbacks = install_try!(runtime::prepare_installed_callbacks());
    #[cfg(feature = "exec-native-injection")]
    if !skip_pmu {
        install_try!(runtime::initialize_rcb_clock());
    }
    #[cfg(not(feature = "exec-native-injection"))]
    install_try!(runtime::initialize_rcb_clock());
    // The raw syscall, not libc's interposable getpid.
    let pid = Pid::from_raw(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) } as i32);
    let subscriptions = T::subscriptions(rpc.config());
    let instruction_subscriptions = runtime::InstructionSubscriptions {
        cpuid: subscriptions.has_cpuid(),
        rdtsc: subscriptions.has_rdtsc(),
    };
    install_try!(runtime::preflight_instruction_faulting(
        instruction_subscriptions
    ));
    // A launcher that sends tool data puts the selection in the bootstrap,
    // which guest code cannot change; the environment is the selector for
    // launchers that do not.
    let site_patching = if private_initial {
        false
    } else if let Some(site_patching) = reverie_inguest::bootstrap::bootstrap_site_patching() {
        site_patching
    } else {
        install_try!(runtime::site_patching_from_env_value(
            std::env::var_os(runtime::SITE_PATCHING_ENV).as_deref(),
        ))
    };
    // With site patching off, the vDSO gets ptrace's full trapping stubs and no
    // hooks, so its fast paths reach the Tool through the SIGSYS fallback too.
    #[cfg(feature = "exec-private-init")]
    let initial_vdso =
        initial_control.map(|control| unsafe { patch_initial_image_vdso(&subscriptions, control) });
    #[cfg(not(feature = "exec-private-init"))]
    let initial_vdso: Option<Result<(), reverie::Error>> = None;
    let vdso_sites = install_try!(
        (if let Some(result) = initial_vdso {
            result.map(|()| Vec::new())
        } else if site_patching {
            reverie::vdso::patch_current_vdso(&subscriptions)
        } else {
            reverie::vdso::patch_current_vdso_trapping(&subscriptions).map(|()| Vec::new())
        })
        .map_err(|error| {
            io::Error::other(reverie_inguest::guest::host::describe_reverie_error(&error))
        })
    );
    #[cfg(feature = "exec-private-init")]
    let _signal_state = if let Some(control) = initial_control {
        install_try!(control.prepare_signal_state(instruction_subscriptions));
        None
    } else {
        Some(install_try!(runtime::prepare_guest_signal_state(
            instruction_subscriptions,
        )))
    };
    #[cfg(not(feature = "exec-private-init"))]
    let _signal_state = install_try!(runtime::prepare_guest_signal_state(
        instruction_subscriptions
    ));
    let syscall_subscriptions = subscriptions.iter_syscalls().collect();
    if remove_legacy_environment {
        // SAFETY: legacy tool installation runs before application-created threads.
        unsafe { std::env::remove_var(crate::backend::COORDINATOR_ENV) };
    }
    #[cfg(feature = "exec-native-injection")]
    let tool = match restored_tool {
        Some(tool) => tool,
        None => T::new(pid, rpc.config()),
    };
    #[cfg(not(feature = "exec-native-injection"))]
    let tool = T::new(pid, rpc.config());
    let host = ToolHost::<T, LiteinstRuntime>::new(
        tool,
        rpc,
        pid,
        syscall_subscriptions,
        instruction_subscriptions.cpuid,
        LiteinstRuntime {
            stats,
            #[cfg(feature = "exec-native-injection")]
            no_rcb: skip_pmu,
        },
    );
    #[cfg(feature = "exec-native-injection")]
    let host = {
        let mut host = host;
        if let Some(driver) = native_driver {
            // SAFETY: only the explicitly authenticated native entry supplies
            // this concrete driver, before publication or any dispatch.
            unsafe {
                install_try!(host.install_native_exec_driver(driver));
            }
        }
        host
    };
    // SAFETY: preserve one shared installed owner and the actual same private
    // control/client/fatal lineage; ordinary publication arity is unchanged.
    #[cfg(feature = "exec-private-init")]
    unsafe {
        match initial_control {
            Some(PrivateImageControl::Initial(control)) => {
                let fatal = install_try!(initial_fatal.ok_or_else(|| io::Error::other(
                    "InitialImage installer lacks its fatal owner"
                )));
                install_try!(installed_tool::publish_initial_tool(host, control, fatal));
            }
            #[cfg(feature = "exec-native-injection")]
            Some(PrivateImageControl::Successor(control)) => {
                let state = install_try!(restored_state.take().ok_or_else(|| io::Error::other(
                    "successor installer lacks authenticated pending Tool state"
                )));
                install_try!(installed_tool::publish_successor_tool(host, state, control));
            }
            None => {
                install_try!(installed_tool::publish_tool(host));
            }
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
        initial_control.map(|control| runtime::PrivateRuntimeImage {
            control,
            #[cfg(feature = "exec-native-injection")]
            preparation: if skip_pmu {
                // The native entry has qualified the actual private image and
                // its no-patching Config. Ordinary/legacy installation retains
                // all existing patcher preparation, even in feature-on builds.
                runtime::InstrumentationPreparation::NativeTrapOnly
            } else {
                runtime::InstrumentationPreparation::Patcher
            },
            #[cfg(feature = "exec-native-injection")]
            before_frontend: runtime_restore,
        }),
    );
    #[cfg(feature = "fixed-syscall-gates")]
    {
        fixed_install.complete = result.is_ok();
    }
    #[cfg(feature = "exec-native-injection")]
    if skip_pmu {
        require_native_success(result);
        return Ok(());
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
