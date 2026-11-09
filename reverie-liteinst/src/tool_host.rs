//! Installs a Reverie Tool in this guest on reverie-inguest's Tool host
//! ([`reverie_inguest::guest::host::ToolHost`]) and supplies LiteInst's
//! runtime services to it.

use std::io;
use std::path::Path;

#[cfg(all(feature = "liteinst", target_arch = "x86_64"))]
use liteinst::trampoline::HookContext;
#[cfg(feature = "exec-private-init")]
use reverie::GlobalRPC;
use reverie::Pid;
use reverie::Tool;
#[cfg(all(feature = "liteinst", target_arch = "x86_64"))]
use reverie_inguest::guest::context::RegisterContext;
use reverie_inguest::guest::host::HostRuntime;
#[cfg(feature = "exec-private-init")]
use reverie_inguest::guest::host::ToolHost;
use reverie_inguest::guest::installed_tool;
#[cfg(feature = "exec-private-init")]
use reverie_inguest::guest::rpc::GuestRpcStream;
#[cfg(feature = "exec-private-init")]
use reverie_inguest::trap::raw_syscall6;

#[cfg(feature = "exec-private-init")]
use crate::rpc::CoordinatorRpc;
use crate::runtime;
use crate::runtime::SyscallEvent;

/// Named aarch64 refusal for the serving entry points below (L0 of the
/// aarch64 LiteInst port): the serving tails are not compiled on aarch64,
/// and each public installer refuses here before touching any
/// process-global state. One signature exists per installer on both
/// architectures (the refusal is a cfg arm inside the single fn item), so
/// signature drift between serving and refusing shapes is impossible by
/// construction. L1 flips surfaces to real trap serving one by one.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn aarch64_unsupported(surface: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{surface}: in-guest LiteInst runtime is not supported on aarch64"),
    )
}

// Patched trampolines save HookContext; the shared entry reads RegisterContext.
// The shared fallback continuation already owns RegisterContext.
#[cfg(all(feature = "liteinst", target_arch = "x86_64"))]
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
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) struct LiteinstRuntime {
    stats: crate::stats::GuestStatsHooks,
    /// Armed external exec watch (see `HostRuntime::exec_watch_armed`).
    /// No in-tree liteinst launcher seizes guests under a supervisor
    /// yet, so every current construction sets this `false`; the
    /// seized-launcher composition will set it at construction.
    exec_watch: bool,
    #[cfg(feature = "exec-private-init")]
    no_rcb: bool,
}

impl LiteinstRuntime {
    /// The services of an ordinary installation.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) fn new(stats: crate::stats::GuestStatsHooks) -> Self {
        Self {
            stats,
            exec_watch: false,
            #[cfg(feature = "exec-private-init")]
            no_rcb: false,
        }
    }
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
        #[cfg(feature = "exec-private-init")]
        if self.no_rcb {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private no-RCB image clock is unsupported",
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

    fn exec_watch_armed(&self) -> bool {
        self.exec_watch
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
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = &coordinator;
        Err(aarch64_unsupported("install_tool"))
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        reverie_inguest::guest::tool_install::install_tool_with::<T, _>(
            coordinator.as_ref(),
            true,
            runtime::LiteinstPatchHost::new(runtime::PatchPublication::Concurrent),
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
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = &coordinator;
        Err(aarch64_unsupported("install_tool_quiescent"))
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        reverie_inguest::guest::tool_install::install_tool_with::<T, _>(
            coordinator.as_ref(),
            true,
            runtime::LiteinstPatchHost::new(runtime::PatchPublication::Quiescent),
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
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = &coordinator;
        Err(aarch64_unsupported("install_tool_from_bootstrap"))
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        reverie_inguest::guest::tool_install::install_tool_with::<T, _>(
            coordinator.as_ref(),
            false,
            runtime::LiteinstPatchHost::new(runtime::PatchPublication::Concurrent),
        )
    }
}

/// Install an ordinary bootstrap Tool using a caller-owned concrete runtime.
///
/// The projection receives this mechanism's real services, allocated inside
/// the shared installer's private allocation scope. The runtime and Tool stay
/// in the same linked image; the boxed Rust trait is not an external ABI.
/// Private initial/successor installation does not use this entry.
///
/// # Safety
///
/// All [`install_tool_from_bootstrap`] and
/// [`reverie_inguest::guest::tool_install::install_tool_with_runtime`]
/// preconditions apply. `project` must preserve every supplied service and
/// retain it for the installed host's lifetime.
pub unsafe fn install_tool_from_bootstrap_with_runtime<T, R>(
    coordinator: impl AsRef<Path>,
    project: impl FnOnce(Box<dyn HostRuntime>) -> R,
) -> io::Result<()>
where
    T: Tool + 'static,
    R: HostRuntime,
{
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = &coordinator;
        let _ = &project;
        Err(aarch64_unsupported(
            "install_tool_from_bootstrap_with_runtime",
        ))
    }
    // SAFETY: the caller retains the original installation and service
    // projection obligations. No private image owner is created here.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        reverie_inguest::guest::tool_install::install_tool_with_runtime::<T, _, R, _>(
            coordinator.as_ref(),
            false,
            runtime::LiteinstPatchHost::new(runtime::PatchPublication::Concurrent),
            |services| project(Box::new(services)),
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
        reverie_rpc_transport::BlockingRpcClient<T::GlobalState, GuestRpcStream>,
        &'a reverie_inguest::guest::exec_private::InitialImageControl,
        &'a reverie_inguest::guest::exec_private::InitialImageAbortGuard,
        Option<(T, T::ThreadState)>,
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

/// Parse the straddler selector from the runner's environ block
/// directly: no getenv interposition and no allocation unless the
/// parse constructs its error.
#[cfg(all(
    feature = "exec-private-init",
    not(all(feature = "liteinst", target_arch = "x86_64"))
))]
fn validated_straddler_staleness() -> io::Result<Option<crate::runtime::StalenessBudget>> {
    Ok(Some(()))
}

#[cfg(all(
    feature = "exec-private-init",
    all(feature = "liteinst", target_arch = "x86_64")
))]
fn validated_straddler_staleness() -> io::Result<Option<crate::runtime::StalenessBudget>> {
    use std::os::unix::ffi::OsStrExt;
    let value = reverie_inguest::guest::support::environment_value(
        crate::straddler::STRADDLER_STALENESS_TICKS_ENV.as_bytes(),
    );
    crate::straddler::straddler_staleness_from_env_value(value.map(std::ffi::OsStr::from_bytes))
}

/// The straddler budget validated before any private prepare entry
/// takes ownership. Only [`validate_straddler_selector`] constructs
/// one, so reaching a prepare entry proves the parse already passed.
#[cfg(feature = "exec-private-init")]
pub struct ValidatedStraddlerStaleness {
    budget: Option<crate::runtime::StalenessBudget>,
}

/// Validate `REVERIE_LITEINST_STRADDLER_STALENESS_TICKS` and capture
/// its budget for a private prepare entry.
///
/// Call this FIRST in the private initialization sequence, before
/// redeeming or constructing the admitted client, configuration,
/// stream or successor consumer. The token type proves validation
/// ran, not that it ran first: that temporal order remains the
/// caller's obligation. A malformed value then returns as a
/// plain named error while the caller still owns nothing admitted,
/// instead of failing after gate adoption where only the silent
/// terminal path remains.
#[cfg(feature = "exec-private-init")]
pub fn validate_straddler_selector() -> io::Result<ValidatedStraddlerStaleness> {
    Ok(ValidatedStraddlerStaleness {
        budget: validated_straddler_staleness()?,
    })
}

/// Authenticated client and one native control prepared before Detcore setup.
/// This affine owner must be consumed by the actual Tool installer.
#[cfg(feature = "exec-private-init")]
pub struct PreparedInitialImage<T: Tool> {
    // Fields drop in declaration order: abandon before any generic Config or
    // client destructor can run, allocate, block, or panic.
    fatal: reverie_inguest::guest::exec_private::InitialImageAbortGuard,
    client: reverie_rpc_transport::BlockingRpcClient<T::GlobalState, GuestRpcStream>,
    control: reverie_inguest::guest::exec_private::InitialImageControl,
    selected: Option<(T, T::ThreadState)>,
    straddler_staleness: Option<Option<crate::runtime::StalenessBudget>>,
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

/// Verified digests supplied by whichever already-admitted
/// carrier delivered the selected state. This seam does not
/// construct or name that carrier's scalar-5 client.
///
/// The fields are private: outside this module the only
/// constructor is the `From<&VerifiedSuccessorState>`
/// conversion below, so both digests always come from the
/// transport-verified successor state, never from the packet.
#[cfg(feature = "loader-private-runtime")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedSuccessorVerifiedDigests {
    /// SHA-256 of the exact delivered opaque state bytes.
    state: [u8; 32],
    /// SHA-256 of the exact one-use ticket/redemption bytes.
    ticket: [u8; 32],
}

#[cfg(feature = "loader-private-runtime")]
impl MappedSuccessorVerifiedDigests {
    /// SHA-256 of the exact delivered opaque state bytes.
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// SHA-256 of the exact one-use ticket/redemption bytes.
    pub fn ticket(&self) -> [u8; 32] {
        self.ticket
    }
}

#[cfg(feature = "loader-private-runtime")]
impl From<&reverie_rpc_transport::successor::VerifiedSuccessorState>
    for MappedSuccessorVerifiedDigests
{
    fn from(verified: &reverie_rpc_transport::successor::VerifiedSuccessorState) -> Self {
        Self {
            state: verified.expected().state,
            ticket: verified.ticket_digest(),
        }
    }
}

#[cfg(all(feature = "loader-private-runtime", any(test, target_env = "musl")))]
fn mapped_successor_binding_digests<C: serde::Serialize>(
    config: &C,
    redemption: &[u8],
) -> io::Result<([u8; 32], [u8; 32])> {
    let config_bytes = reverie_rpc_transport::codec::encode(config)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok((
        reverie_rpc_transport::initial_image::config_digest(&config_bytes),
        reverie_rpc_transport::initial_image::config_digest(redemption),
    ))
}

#[cfg(all(feature = "loader-private-runtime", any(test, target_env = "musl")))]
fn check_mapped_successor_binding(
    client_config_digest: [u8; 32],
    packet_config_digest: [u8; 32],
    packet_state_digest: [u8; 32],
    packet_ticket_digest: [u8; 32],
    verified: &MappedSuccessorVerifiedDigests,
) -> io::Result<()> {
    if client_config_digest != packet_config_digest {
        return Err(io::Error::other(
            "mapped successor packet config digest mismatch",
        ));
    }
    if verified.state != packet_state_digest {
        return Err(io::Error::other(
            "mapped successor packet state digest mismatch",
        ));
    }
    if packet_ticket_digest != verified.ticket {
        return Err(io::Error::other(
            "mapped successor packet ticket digest mismatch",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "loader-private-runtime", any(test, target_env = "musl")))]
fn publish_after_mapped_successor_binding<P>(
    client_config_digest: [u8; 32],
    packet_config_digest: [u8; 32],
    packet_state_digest: [u8; 32],
    packet_ticket_digest: [u8; 32],
    verified: &MappedSuccessorVerifiedDigests,
    publish: impl FnOnce() -> io::Result<P>,
) -> io::Result<P> {
    check_mapped_successor_binding(
        client_config_digest,
        packet_config_digest,
        packet_state_digest,
        packet_ticket_digest,
        verified,
    )?;
    publish()
}

#[cfg(feature = "exec-private-init")]
fn route_selected_initial_publication<H, S>(
    host: H,
    selected: Option<S>,
    mapped_successor: impl FnOnce(H, S) -> io::Result<()>,
    initial: impl FnOnce(H) -> io::Result<()>,
) -> io::Result<()> {
    match selected {
        Some(state) => mapped_successor(host, state),
        None => initial(host),
    }
}

/// Already-admitted mapped successor inputs for selected
/// construction. The live RPC client is the common blocking
/// client transferred from whichever carrier the caller used;
/// this preparation constructs neither carrier client.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub struct MappedSuccessorPreparation<T: Tool> {
    /// Same live connection transferred from the admitted client.
    pub client: reverie_rpc_transport::BlockingRpcClient<T::GlobalState, GuestRpcStream>,
    /// Captured/adopted mapped prelude for this exact launch.
    pub mapped: reverie_inguest::guest::exec_private::mapped_initial::MappedToolPrelude,
    /// Tool decoded from the delivered selected state.
    pub tool: T,
    /// Root thread state decoded from that same selected state.
    pub state: T::ThreadState,
    /// Independent delivered-state and ticket digests to bind
    /// against the successor packet before publication.
    pub verified: MappedSuccessorVerifiedDigests,
}

/// Mapped successor prepared for selected Tool installation.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub struct PreparedMappedSuccessorImage<T: Tool> {
    initial: PreparedInitialImage<T>,
    entry: reverie_inguest::guest::exec_private::MappedSuccessorEntry,
}

/// Installed mapped successor retaining fatal ownership through
/// its restored-root lifecycle and frontend finish.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub struct InstalledMappedSuccessorImage {
    initial: InstalledInitialImage,
    entry: reverie_inguest::guest::exec_private::MappedSuccessorEntry,
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
impl InstalledMappedSuccessorImage {
    /// Complete frontend/lifecycle checks exactly once through
    /// the retained mapped initial-image owner.
    pub fn finish(self) -> io::Result<()> {
        self.initial.finish()
    }
}

/// Legacy initial-image preparation without caller-side straddler
/// validation. Byte-compatible with the original entry for existing
/// callers.
///
/// Known hazard (dh-6u6dq): on this entry the straddler selector is
/// still parsed after gate adoption during installation, so a
/// malformed value terminates silently instead of returning its
/// diagnostic. Prefer [`prepare_tool_initial_image_validated`] with a
/// [`validate_straddler_selector`] token obtained first; this entry
/// remains only until existing callers migrate.
///
/// # Safety
/// Every `prepare_tool_initial_image_validated` obligation applies.
#[cfg(feature = "exec-private-init")]
pub unsafe fn prepare_tool_initial_image<T: Tool>(
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
) -> io::Result<PreparedInitialImage<T>> {
    unsafe { prepare_tool_initial_image_with_budget(client, native, None) }
}

/// Prepare authenticated fixed gates before caller-context Detcore setup.
/// Ordinary preload initialization does not use this entry.
///
/// # Safety
/// The consumed client must have redeemed the launching coordinator's one-use
/// authorization for this exact watched image/filter lineage. Native control,
/// private loader and mapping provenance must satisfy
/// `publish_authenticated_control`. Obtain `straddler` from
/// [`validate_straddler_selector`] before redeeming the client, so a
/// malformed selector refuses while the caller owns nothing admitted.
/// No guest code may have run. The Tool's
/// config must not require RCB time, preemption, threads, forks or exec yet.
#[cfg(feature = "exec-private-init")]
pub unsafe fn prepare_tool_initial_image_validated<T: Tool>(
    straddler: ValidatedStraddlerStaleness,
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
) -> io::Result<PreparedInitialImage<T>> {
    unsafe { prepare_tool_initial_image_with_budget(client, native, Some(straddler.budget)) }
}

#[cfg(feature = "exec-private-init")]
unsafe fn prepare_tool_initial_image_with_budget<T: Tool>(
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
    straddler_staleness: Option<Option<crate::runtime::StalenessBudget>>,
) -> io::Result<PreparedInitialImage<T>> {
    let fatal = unsafe { reverie_inguest::guest::exec_private::InitialImageAbortGuard::arm() };
    let control =
        unsafe { reverie_inguest::guest::exec_private::publish_authenticated_control(native)? };
    Ok(PreparedInitialImage {
        client: client.into_client(),
        control,
        fatal,
        selected: None,
        straddler_staleness,
    })
}

/// Legacy mapped initial-image preparation without caller-side
/// straddler validation. Byte-compatible with the original entry.
///
/// Known hazard (dh-6u6dq): same late straddler parse as the legacy
/// initial entry. Prefer [`prepare_tool_mapped_initial_image_validated`];
/// note the mapped prelude's own gate adoption precedes both entries,
/// so the caller validates before creating the prelude as well.
///
/// # Safety
/// Every `prepare_tool_mapped_initial_image_validated` obligation applies.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub unsafe fn prepare_tool_mapped_initial_image<T: Tool>(
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
    mapped: reverie_inguest::guest::exec_private::mapped_initial::MappedToolPrelude,
) -> io::Result<PreparedInitialImage<T>> {
    unsafe { prepare_tool_mapped_initial_image_with_budget(client, mapped, None) }
}

/// Converge the mapped first image on the existing prepared InitialImage owner.
/// This consumes the actual one-use coordinator client; no alternate ACK,
/// Config, installed host, lifecycle or readiness mechanism is introduced.
///
/// # Safety
/// The client redeemed the exact watched physical launch bound by `mapped`.
/// Its genuine schema/Config checks and the ordinary InitialImage domain checks
/// completed on that same stream. The caller retains the host mapping/terminal
/// owner and all `MappedToolPrelude::publish_authenticated` obligations. Guest
/// has not run; all errors remain terminal under the original retained owner.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub unsafe fn prepare_tool_mapped_initial_image_validated<T: Tool>(
    straddler: ValidatedStraddlerStaleness,
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
    mapped: reverie_inguest::guest::exec_private::mapped_initial::MappedToolPrelude,
) -> io::Result<PreparedInitialImage<T>> {
    unsafe { prepare_tool_mapped_initial_image_with_budget(client, mapped, Some(straddler.budget)) }
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
unsafe fn prepare_tool_mapped_initial_image_with_budget<T: Tool>(
    client: reverie_rpc_transport::InitialImageClient<T::GlobalState, GuestRpcStream>,
    mapped: reverie_inguest::guest::exec_private::mapped_initial::MappedToolPrelude,
    straddler_staleness: Option<Option<crate::runtime::StalenessBudget>>,
) -> io::Result<PreparedInitialImage<T>> {
    let fatal = unsafe { reverie_inguest::guest::exec_private::InitialImageAbortGuard::arm() };
    // SAFETY: actual admitted client and physical producer contract above.
    let control = unsafe { mapped.publish_authenticated()? };
    Ok(PreparedInitialImage {
        fatal,
        client: client.into_client(),
        control,
        selected: None,
        straddler_staleness,
    })
}

/// Bind and prepare a mapped successor before the one
/// authenticated mapped publication. The successor packet is
/// decoded through the prelude's shared trait delegate and all
/// three packet/client digests must match before
/// `publish_authenticated` runs.
///
/// # Safety
/// Every `prepare_tool_mapped_initial_image_validated`
/// obligation applies to the transferred live client and mapped
/// prelude, regardless of which carrier constructed that client
/// before this call. `tool` and `state` must be the exact pair
/// decoded from the delivered bytes whose SHA-256 and ticket
/// digest are in `verified`; matching digests alone do not prove
/// that decode. Obtain `straddler` before constructing or
/// redeeming any admitted owner. No guest code may have run.
///
/// Every `Err` from this function that returns before the
/// fatal guard is armed can be named; the caller must still
/// treat it as terminal. It must not resume guest code or
/// reuse the consumed preparation after one.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub unsafe fn prepare_tool_mapped_successor_image_validated<T: Tool>(
    straddler: ValidatedStraddlerStaleness,
    preparation: MappedSuccessorPreparation<T>,
) -> io::Result<PreparedMappedSuccessorImage<T>> {
    use reverie_inguest::guest::exec_private::mapped_initial::mapped_scalar::SuccessorPacketSource as _;

    let MappedSuccessorPreparation {
        client,
        mapped,
        tool,
        state,
        verified,
    } = preparation;
    let entry = mapped.successor_entry();
    let packet = mapped
        .successor_init_packet()
        .map_err(|error| io::Error::other(error.name()))?;
    let packet_config_digest = packet.expected_config_digest();
    let packet_state_digest = packet.expected_state_digest();
    let (client_config_digest, packet_ticket_digest) =
        mapped_successor_binding_digests(client.config(), packet.redemption())?;
    let mut initial = publish_after_mapped_successor_binding(
        client_config_digest,
        packet_config_digest,
        packet_state_digest,
        packet_ticket_digest,
        &verified,
        || {
            let fatal =
                unsafe { reverie_inguest::guest::exec_private::InitialImageAbortGuard::arm() };
            // SAFETY: packet/client binding above and the caller's
            // mapped-prelude publication obligations apply.
            let control = unsafe { mapped.publish_authenticated()? };
            Ok(PreparedInitialImage {
                fatal,
                client,
                control,
                selected: None,
                straddler_staleness: Some(straddler.budget),
            })
        },
    )?;
    initial.selected = Some((tool, state));
    Ok(PreparedMappedSuccessorImage { initial, entry })
}

/// Install the selected mapped successor Tool/state using the
/// same transferred live client and authenticated mapped
/// control. The caller must run
/// [`initialize_mapped_successor_lifecycle`], complete its
/// existing setup, then consume the installed owner's `finish`
/// before the runner can resume the guest.
///
/// # Safety
/// Every `install_tool_initial_image` obligation applies. The
/// selected Tool/state in `prepared` must be the exact pair
/// bound to its successor packet by
/// `prepare_tool_mapped_successor_image_validated`.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub unsafe fn install_tool_mapped_successor_image<T>(
    coordinator: impl AsRef<Path>,
    prepared: PreparedMappedSuccessorImage<T>,
) -> io::Result<InstalledMappedSuccessorImage>
where
    T: Tool + 'static,
{
    Ok(InstalledMappedSuccessorImage {
        initial: unsafe { install_prepared_initial_image(coordinator, prepared.initial)? },
        entry: prepared.entry,
    })
}

/// Run the installed mapped successor's restored-root lifecycle
/// with the native successor's callback order: the native
/// driver bind when present, post-exec only, then publish that
/// same state. It calls neither `on_initial_image_attached`,
/// `init_thread_state`, nor `handle_thread_start`. Only the
/// callback order and published state are parity; the mapped
/// lifecycle guest provides guarded injection and the verified
/// mapped resume registers/PKRU under its selected-restore
/// permit.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub fn initialize_mapped_successor_lifecycle(
    image: &InstalledMappedSuccessorImage,
) -> io::Result<()> {
    // SAFETY: the wrapper retains the same private affine
    // installed owner and its live fatal guard.
    unsafe {
        installed_tool::initialize_mapped_successor_lifecycle(
            &image.initial.control,
            &image.initial.fatal,
            &image.entry,
        )
    }
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
    unsafe { install_prepared_initial_image(coordinator, prepared) }
}

#[cfg(feature = "exec-private-init")]
unsafe fn install_prepared_initial_image<T>(
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
        selected,
        straddler_staleness,
    } = prepared;
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            false,
            runtime::PatchPublication::Quiescent,
            Some(ImageInstall::Initial(client, &control, &fatal, selected)),
            #[cfg(feature = "exec-native-injection")]
            None,
            true,
            straddler_staleness,
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
    straddler_staleness: Option<Option<crate::runtime::StalenessBudget>>,
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

/// Legacy successor preparation without caller-side straddler
/// validation. Byte-compatible with the original entry.
///
/// Known hazard (dh-6u6dq): same late straddler parse as the legacy
/// initial entry. Prefer [`prepare_tool_successor_image_validated`].
///
/// # Safety
/// Every `prepare_tool_successor_image_validated` obligation applies.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn prepare_tool_successor_image<T: Tool + 'static>(
    client: reverie_rpc_transport::SuccessorClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
    binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    consumer: Box<dyn NativeSuccessorConsumer<T>>,
) -> io::Result<PreparedSuccessorImage<T>> {
    unsafe { prepare_tool_successor_image_with_budget(client, native, binding, consumer, None) }
}

/// Decode a genuinely redeemed successor before publishing its native control.
///
/// # Safety
/// The actual SuccessorClient and independent binding must name this genuine
/// successful kernel exec and retained watched birth. The inherited fixed
/// terminal gate, private loader/Tool FS/control extents and fresh allocator
/// must already be authenticated; no guest code may have run. The consumer
/// must uphold every unsafe trait contract. Errors or abandonment are terminal.
/// Obtain `straddler` from [`validate_straddler_selector`] before
/// constructing the client or consumer it is passed beside.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn prepare_tool_successor_image_validated<T: Tool + 'static>(
    straddler: ValidatedStraddlerStaleness,
    client: reverie_rpc_transport::SuccessorClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
    binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    consumer: Box<dyn NativeSuccessorConsumer<T>>,
) -> io::Result<PreparedSuccessorImage<T>> {
    unsafe {
        prepare_tool_successor_image_with_budget(
            client,
            native,
            binding,
            consumer,
            Some(straddler.budget),
        )
    }
}

#[cfg(feature = "exec-native-injection")]
unsafe fn prepare_tool_successor_image_with_budget<T: Tool + 'static>(
    client: reverie_rpc_transport::SuccessorClient<T::GlobalState, GuestRpcStream>,
    native: *mut reverie_inguest::guest::exec_private::NativeControl,
    binding: reverie_inguest::guest::exec_private::SuccessorBinding,
    mut consumer: Box<dyn NativeSuccessorConsumer<T>>,
    straddler_staleness: Option<Option<crate::runtime::StalenessBudget>>,
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
        straddler_staleness,
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
        straddler_staleness,
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
            Some((driver, false)),
            true,
            straddler_staleness,
        )?;
    }
    Ok(InstalledSuccessorImage {
        fatal,
        consumer,
        control,
    })
}

/// Install an authenticated initial image with its concrete native exec driver
/// before the first dispatch, without admitting the native exec/clone route:
/// exec keeps its typed refusal unless an exec watch is armed, and
/// thread creation keeps its typed refusal. Ordinary
/// InitialImage installation is unchanged.
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
    // SAFETY: forwarded verbatim; all contracts of this entry apply.
    unsafe {
        install_tool_initial_image_with_native_exec_admission(
            coordinator,
            prepared,
            driver,
            qualify,
            false,
        )
    }
}

/// As [`install_tool_initial_image_with_native_exec`], and additionally
/// admit the native exec/clone route (the embedder opt-in): the host
/// consults the driver for exec, and thread/vfork creation takes the
/// admitted route's final-step typed refusal until thread arming exists.
///
/// # Safety
/// All contracts of [`install_tool_initial_image_with_native_exec`] and
/// of host native-exec admission apply.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn install_tool_initial_image_with_admitted_native_exec<T: Tool + 'static>(
    coordinator: impl AsRef<Path>,
    prepared: PreparedInitialImage<T>,
    driver: std::sync::Arc<dyn reverie_inguest::guest::native_exec::NativeExecDriver<T>>,
    qualify: impl FnOnce(&<T::GlobalState as reverie::GlobalTool>::Config) -> io::Result<()>,
) -> io::Result<InstalledInitialImage> {
    // SAFETY: forwarded verbatim; all contracts of this entry apply.
    unsafe {
        install_tool_initial_image_with_native_exec_admission(
            coordinator,
            prepared,
            driver,
            qualify,
            true,
        )
    }
}

#[cfg(feature = "exec-native-injection")]
unsafe fn install_tool_initial_image_with_native_exec_admission<T: Tool + 'static>(
    coordinator: impl AsRef<Path>,
    prepared: PreparedInitialImage<T>,
    driver: std::sync::Arc<dyn reverie_inguest::guest::native_exec::NativeExecDriver<T>>,
    qualify: impl FnOnce(&<T::GlobalState as reverie::GlobalTool>::Config) -> io::Result<()>,
    admit_native_exec: bool,
) -> io::Result<InstalledInitialImage> {
    let PreparedInitialImage {
        fatal,
        client,
        control,
        selected,
        straddler_staleness,
    } = prepared;
    let _private_allocations = reverie_inguest::guest::alloc::enter_dispatch();
    require_native_success(qualify(client.config()));
    unsafe {
        install_tool_inner::<T>(
            coordinator.as_ref(),
            false,
            runtime::PatchPublication::Quiescent,
            Some(ImageInstall::Initial(client, &control, &fatal, selected)),
            Some((driver, admit_native_exec)),
            true,
            straddler_staleness,
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

// Private initialization has an authenticated fatal owner outside this stack
// frame. It must terminate before local RPC/Tool owners are dropped: their
// descriptors may already be protected and their frontend partly installed.
#[cfg(feature = "exec-private-init")]
fn private_install_result<V>(result: io::Result<V>, private_initial: bool) -> io::Result<V> {
    match result {
        Err(_error) if private_initial => unsafe {
            // SAFETY: install_tool_inner receives an authenticated Initial or
            // Successor owner. Its existing fixed terminal gate is retained;
            // no teardown, diagnostic I/O or guest continuation may intervene.
            reverie_inguest::guest::exec_private::initialization_failed(core::ptr::null_mut())
        },
        result => result,
    }
}

#[cfg(all(test, feature = "exec-private-init"))]
mod private_install_result_tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn ordinary_failure_preserves_real_errno() {
        let error =
            private_install_result::<()>(Err(io::Error::from_raw_os_error(libc::EIO)), false)
                .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn private_success_is_unchanged() {
        assert_eq!(private_install_result(Ok(17), true).unwrap(), 17);
    }

    #[test]
    fn invalid_initial_endpoint_terminates_before_reserved_socket_owner_drop() {
        let progress = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
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
            struct SocketOwner {
                socket: UnixStream,
                progress: *mut u64,
            }
            impl Drop for SocketOwner {
                fn drop(&mut self) {
                    // SAFETY: retained shared mapping spans this child.
                    unsafe { self.progress.write_volatile(2) };
                }
            }
            let (socket, _peer) = UnixStream::pair().unwrap();
            let owner = SocketOwner { socket, progress };
            runtime::reserve_coordinator_fd(owner.socket.as_raw_fd()).unwrap();
            unsafe { progress.write_volatile(1) };
            let error = crate::initial_image_stats::initial_image_stats_endpoint(Path::new(
                "/owned/a.sock",
            ));
            assert_eq!(
                error.as_ref().unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            // Do not arm an outer fatal Drop guard: only the actual helper's
            // immediate terminal edge may yield the expected status 127.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                private_install_result(error, true)
            }));
            drop(owner);
            unsafe { libc::_exit(94) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let observed = unsafe { progress.read_volatile() };
        assert_eq!(unsafe { libc::munmap(progress.cast(), 4096) }, 0);
        assert!(libc::WIFEXITED(status), "child status {status}");
        assert_eq!(libc::WEXITSTATUS(status), 127);
        assert_eq!(
            observed, 1,
            "reserved RPC owner was dropped before terminal"
        );
    }
}

// The private-image installer; ordinary installation is the shared
// `reverie_inguest::guest::tool_install::install_tool_with`.
#[cfg(feature = "exec-private-init")]
unsafe fn install_tool_inner<T>(
    coordinator: &Path,
    remove_legacy_environment: bool,
    publication: runtime::PatchPublication,
    #[cfg(feature = "exec-private-init")] initial: Option<ImageInstall<'_, T>>,
    #[cfg(feature = "exec-native-injection")] native_exec: Option<(
        std::sync::Arc<dyn reverie_inguest::guest::native_exec::NativeExecDriver<T>>,
        bool,
    )>,
    #[cfg(feature = "exec-private-init")] skip_pmu: bool,
    #[cfg(feature = "exec-private-init")] straddler_staleness: Option<
        Option<crate::runtime::StalenessBudget>,
    >,
) -> io::Result<()>
where
    T: Tool + 'static,
{
    let private_initial = initial.is_some();
    macro_rules! install_try {
        ($operation:expr) => {
            match private_install_result($operation, private_initial) {
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
    #[cfg(feature = "exec-private-init")]
    let mut restored_tool = None;
    #[cfg(feature = "exec-private-init")]
    let mut selected_initial_state = None;
    #[cfg(feature = "exec-native-injection")]
    let mut restored_state = None;
    #[cfg(feature = "exec-native-injection")]
    let mut runtime_restore: Option<Box<dyn FnOnce() -> io::Result<()> + '_>> = None;
    #[cfg(feature = "exec-private-init")]
    let (rpc, initial_control, initial_fatal) = match initial {
        Some(ImageInstall::Initial(client, control, fatal, selected)) => {
            if let Some((tool, state)) = selected {
                restored_tool = Some(tool);
                selected_initial_state = Some(state);
            }
            (
                install_try!(CoordinatorRpc::<T::GlobalState>::from_live_client(
                    coordinator,
                    client,
                    runtime::replace_coordinator_fd,
                )),
                Some(PrivateImageControl::Initial(control)),
                Some(fatal),
            )
        }
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
    // The typed launcher is the pre-spawn guard; this is an image-side defense.
    install_try!(T::facility_admission(rpc.config()).map_err(io::Error::other));
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
    // SAFETY: this private installer is called only with the authenticated
    // no-RCB image contract when skip_pmu is true; no Guest or callback is active.
    install_try!(unsafe { runtime::prepare_private_rcb_clock(skip_pmu) });
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
        install_try!(runtime::validate_site_patching(site_patching))
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
    #[cfg(feature = "exec-private-init")]
    let tool = match restored_tool {
        Some(tool) => tool,
        None => T::new(pid, rpc.config()),
    };
    #[cfg(not(feature = "exec-private-init"))]
    let tool = T::new(pid, rpc.config());
    let host = ToolHost::<T, LiteinstRuntime>::new(
        tool,
        rpc,
        pid,
        syscall_subscriptions,
        instruction_subscriptions.cpuid,
        LiteinstRuntime {
            stats,
            exec_watch: false,
            #[cfg(feature = "exec-private-init")]
            no_rcb: skip_pmu,
        },
    );
    #[cfg(feature = "exec-native-injection")]
    let host = {
        let mut host = host;
        if let Some((driver, admit_native_exec)) = native_exec {
            // SAFETY: only the explicitly authenticated native entry supplies
            // this concrete driver, before publication or any dispatch.
            unsafe {
                install_try!(host.install_native_exec_driver(driver));
            }
            if admit_native_exec {
                // SAFETY: same authenticated entry and pre-dispatch point
                // as the driver installation above; admission is the
                // embedder opt-in this entry was explicitly given.
                unsafe {
                    install_try!(host.admit_native_exec());
                }
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
                install_try!(route_selected_initial_publication(
                    host,
                    selected_initial_state.take(),
                    |host, state| installed_tool::publish_mapped_successor_tool(
                        host, state, control, fatal
                    ),
                    |host| installed_tool::publish_initial_tool(host, control, fatal),
                ));
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
            straddler_staleness,
            preparation: if skip_pmu {
                // The authenticated entry requires a no-RCB/no-patching image.
                // Ordinary/legacy installation retains
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
#[cfg(all(feature = "fixed-syscall-gates", feature = "exec-private-init"))]
struct FixedGateInstallation {
    complete: bool,
}

#[cfg(all(feature = "fixed-syscall-gates", feature = "exec-private-init"))]
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

#[cfg(all(test, feature = "loader-private-runtime"))]
mod mapped_successor_binding_tests {
    use super::*;

    fn binding() -> (u64, [u8; 32], [u8; 32], MappedSuccessorVerifiedDigests) {
        let config = 901_u64;
        let config_bytes = reverie_rpc_transport::codec::encode(&config).unwrap();
        let packet_config = reverie_rpc_transport::initial_image::config_digest(&config_bytes);
        let packet_state = [0x33; 32];
        let verified = MappedSuccessorVerifiedDigests {
            state: packet_state,
            ticket: reverie_rpc_transport::initial_image::config_digest(b"birth-nonce"),
        };
        (config, packet_config, packet_state, verified)
    }

    #[test]
    fn mapped_successor_binding_requires_all_three_digests() {
        let (config, packet_config, packet_state, verified) = binding();
        let (client_config_digest, packet_ticket) =
            mapped_successor_binding_digests(&config, b"birth-nonce").unwrap();
        assert_eq!(client_config_digest, packet_config);
        assert_eq!(packet_ticket, verified.ticket);
        let (wrong_config_digest, _) =
            mapped_successor_binding_digests(&902_u64, b"birth-nonce").unwrap();
        check_mapped_successor_binding(
            client_config_digest,
            packet_config,
            packet_state,
            packet_ticket,
            &verified,
        )
        .unwrap();

        let error = check_mapped_successor_binding(
            wrong_config_digest,
            packet_config,
            packet_state,
            packet_ticket,
            &verified,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "mapped successor packet config digest mismatch"
        );

        let error = check_mapped_successor_binding(
            client_config_digest,
            packet_config,
            packet_state,
            packet_ticket,
            &MappedSuccessorVerifiedDigests {
                state: [0x44; 32],
                ..verified
            },
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "mapped successor packet state digest mismatch"
        );

        let (_, wrong_ticket_digest) =
            mapped_successor_binding_digests(&config, b"wrong-nonce").unwrap();
        let error = check_mapped_successor_binding(
            client_config_digest,
            packet_config,
            packet_state,
            wrong_ticket_digest,
            &verified,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "mapped successor packet ticket digest mismatch"
        );

        // A zeroed verified ticket never binds, even against the
        // genuine packet ticket digest.
        let error = check_mapped_successor_binding(
            client_config_digest,
            packet_config,
            packet_state,
            packet_ticket,
            &MappedSuccessorVerifiedDigests {
                ticket: [0; 32],
                ..verified
            },
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "mapped successor packet ticket digest mismatch"
        );
    }

    #[test]
    fn mapped_digests_from_verified_state_are_faithful() {
        use reverie_rpc_transport::initial_image::config_digest;
        use reverie_rpc_transport::successor::ExpectedSuccessor;
        use reverie_rpc_transport::successor::SuccessorRequest;
        use reverie_rpc_transport::successor::VerifiedSuccessorState;

        let bytes = b"selected-state-bytes".to_vec();
        let expected = ExpectedSuccessor {
            config: config_digest(b"config-bytes"),
            state: config_digest(&bytes),
        };
        let verified = VerifiedSuccessorState::from_checked_frame_for_test(
            SuccessorRequest {
                ticket: b"birth-nonce",
                expected,
            },
            bytes,
        )
        .unwrap();
        let digests = MappedSuccessorVerifiedDigests::from(&verified);
        assert_eq!(digests.state(), verified.expected().state);
        assert_eq!(digests.ticket(), verified.ticket_digest());
        assert_eq!(digests.ticket(), config_digest(b"birth-nonce"));
        assert_ne!(digests.ticket(), [0; 32]);
    }

    #[test]
    fn mapped_successor_publication_waits_for_binding() {
        let (config, packet_config, packet_state, verified) = binding();
        let (client_config_digest, packet_ticket) =
            mapped_successor_binding_digests(&config, b"birth-nonce").unwrap();
        let (wrong_config_digest, _) =
            mapped_successor_binding_digests(&902_u64, b"birth-nonce").unwrap();
        let published = std::cell::Cell::new(false);
        let error = publish_after_mapped_successor_binding(
            wrong_config_digest,
            packet_config,
            packet_state,
            packet_ticket,
            &verified,
            || {
                published.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "mapped successor packet config digest mismatch"
        );
        assert!(!published.get());

        publish_after_mapped_successor_binding(
            client_config_digest,
            packet_config,
            packet_state,
            packet_ticket,
            &verified,
            || {
                published.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(published.get());
    }

    #[test]
    fn selected_initial_publication_routes_only_selected_state_to_mapped() {
        let route = std::cell::Cell::new("");
        route_selected_initial_publication(
            "host",
            Some(7_u64),
            |host, state| {
                assert_eq!(host, "host");
                assert_eq!(state, 7);
                route.set("mapped");
                Ok(())
            },
            |_host| {
                route.set("initial");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(route.get(), "mapped");

        route_selected_initial_publication(
            "host",
            None,
            |_host, _state: u64| {
                route.set("mapped");
                Ok(())
            },
            |host| {
                assert_eq!(host, "host");
                route.set("initial");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(route.get(), "initial");
    }
}
