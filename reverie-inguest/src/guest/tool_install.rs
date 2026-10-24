/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shared typed installation of a Reverie Tool in this guest.
//!
//! [`install_tool_with`] connects to the coordinator, publishes the Tool on
//! the shared [`ToolHost`], and activates the shared runtime: the SIGSYS
//! dispatcher over [`RuntimeSeam`], the instruction-fault bridge, the
//! runtime's seccomp filter, and SIGALRM admission. A [`PatchHost`] supplies
//! what differs between backends: its patcher and the steps that prepare it,
//! its runtime services, and its runtime option selectors. [`TrapHost`] has no
//! patcher: every trapped syscall runs through the fallback continuation, the
//! vDSO gets the trapping stubs, and CPUID/RDTSC are emulated, with no
//! liteinst2 code in the process.
//!
//! The order of the steps below is LiteInst's installation order, which the
//! corpus gate holds identical; a step a host does not need is a no-op.

use std::io;
use std::path::Path;
use std::sync::OnceLock;

use reverie::GlobalRPC;
use reverie::Pid;
use reverie::Tool;

use crate::guest::context::RegisterContext;
use crate::guest::continuation;
use crate::guest::event::InstructionEventKind;
use crate::guest::event::SyscallDispatch;
use crate::guest::event::SyscallEvent;
use crate::guest::host::HostRuntime;
use crate::guest::host::ToolHost;
use crate::guest::installed_tool;
use crate::guest::instruction::InstructionSubscriptions;
use crate::guest::rpc::CoordinatorRpc;
use crate::guest::runtime_seam::PatcherRef;
use crate::guest::runtime_seam::RuntimeSeam;
use crate::guest::runtime_seam::install_instruction_handler;
use crate::guest::runtime_seam::observe_registered_mapping;
use crate::guest::runtime_seam::process_tool_syscall_callback;
use crate::guest::runtime_seam::registered_patcher;
use crate::guest::tool_region::StackBacking;
use crate::guest::tool_region::ToolRegion;
use crate::guest::trap_dispatch::InGuestDispatcher;
use crate::lifecycle::InProcessSeccomp;
use crate::lifecycle::RuntimeConfig;
use crate::stats::GuestStatsHooks;
use crate::trap::raw_syscall6;

/// A backend's part in [`install_tool_with`]: its patcher, the steps that
/// prepare it, its runtime services and its option selectors, called on the
/// installing thread before application threads start. The steps from
/// [`Self::preflight`] to [`Self::runtime_config`] run once each, in the order
/// listed; [`Self::patcher`] and [`Self::runtime`] are asked when needed.
///
/// # Safety
///
/// [`Self::patcher`] must keep the [`crate::guest::patcher::Patcher`]
/// contract. Every step runs before the runtime is active and must not run
/// guest code or install a seccomp filter. A signal handler a step installs
/// (such as LiteInst's SIGTRAP guard router) must use the runtime's raw
/// signal operations and return through its private restorer.
pub unsafe trait PatchHost {
    /// The runtime services the Tool host uses.
    type Runtime: HostRuntime;

    /// The patcher the runtime asks about sites, mappings and accounting.
    fn patcher(&self) -> &'static PatcherRef;

    /// Before anything is connected or published, with Tool-heap allocation
    /// selected: checks the backend's own allocation preconditions.
    fn preflight(&self) -> io::Result<()> {
        Ok(())
    }

    /// Registers the fallback continuation's handlers and prepares this
    /// thread's continuation. The default registers the shared handlers,
    /// which run a continued syscall through
    /// [`process_tool_syscall_callback`].
    fn initialize_continuation(&self) -> io::Result<()> {
        initialize_shared_continuation()
    }

    /// After the coordinator and statistics are connected and before the
    /// guest clock starts: prepares the patcher's hook entries.
    fn prepare_entries(&self) -> io::Result<()> {
        Ok(())
    }

    /// Whether syscall sites (and the vDSO) are patched. With `false` the
    /// vDSO gets the trapping stubs, so its fast paths reach the Tool through
    /// the fallback continuation.
    fn site_patching(&self) -> io::Result<bool> {
        Ok(false)
    }

    /// Whether lifecycle stages go to the diagnostic stream.
    fn stage_stream(&self) -> io::Result<bool>;

    /// Whether the guest may create processes.
    fn process_forks_allowed(&self) -> io::Result<bool>;

    /// Whether guest SIGALRM handlers are requested (signal phase 1).
    fn sigalrm_handlers(&self) -> io::Result<bool>;

    /// After the Tool is published, before SIGALRM admission: records the
    /// selected patching mode in the patcher.
    fn select(&self, _site_patching: bool) {}

    /// After the runtime's Tool region is reserved, before the instruction
    /// handler: prepares the patcher (and hooks the vDSO's syscall sites, when
    /// site patching is on).
    fn prepare_patcher(&self, _vdso_sites: &[reverie::vdso::VdsoSyscallSite]) -> io::Result<()> {
        Ok(())
    }

    /// The runtime's signal configuration.
    fn runtime_config(&self) -> io::Result<RuntimeConfig>;

    /// The runtime services for this process's Tool host.
    fn runtime(&self, stats: GuestStatsHooks) -> Self::Runtime;
}

/// Installs a concrete Reverie Tool in this guest, connected to its
/// coordinator at `coordinator`, on the shared runtime with `host`'s patcher.
/// With `remove_coordinator_environment`, the legacy coordinator variable
/// ([`crate::bootstrap::COORDINATOR_ENV`]) is removed from the environment.
///
/// # Safety
///
/// Installs process-global signal, seccomp and instrumentation state. Call
/// once, before application threads start and before any seccomp filter is
/// active.
pub unsafe fn install_tool_with<T, H>(
    coordinator: &Path,
    remove_coordinator_environment: bool,
    host: H,
) -> io::Result<()>
where
    T: Tool + 'static,
    H: PatchHost,
{
    // Everything installation allocates lives in the runtime's private Tool
    // heap, never in the guest's own malloc heap; see LiteInst's installer.
    let _private_allocations = crate::guest::alloc::enter_dispatch();
    host.preflight()?;
    #[cfg(feature = "fixed-syscall-gates")]
    let mut fixed_install = FixedGateInstallation { complete: false };
    #[cfg(feature = "fixed-syscall-gates")]
    unsafe {
        if crate::guest::sigalrm::seccomp_filter_count() != Some(0) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "fixed syscall gates refuse an inherited or unreadable seccomp filter state",
            ));
        }
        // All runtime signal actions and their filter must select the same
        // fixed page. Prepare it before any callback or handler is published.
        crate::trap::prepare_fixed_gates()?;
    }
    host.initialize_continuation()?;
    let rpc = CoordinatorRpc::<T::GlobalState>::connect(
        coordinator,
        crate::guest::protect::replace_coordinator_fd,
    )?;
    crate::guest::protect::reserve_coordinator_fd(rpc.raw_fd())?;
    let stats = if let Some(stats_coordinator) = crate::bootstrap::bootstrap_stats_coordinator() {
        crate::stats::initialize_guest_stats(stats_coordinator)?
    } else if let Some(stats_coordinator) =
        std::env::var_os(crate::bootstrap::STATS_COORDINATOR_ENV)
    {
        let stats = crate::stats::initialize_guest_stats(Path::new(&stats_coordinator))?;
        // SAFETY: tool installation runs before application-created threads.
        unsafe { std::env::remove_var(crate::bootstrap::STATS_COORDINATOR_ENV) };
        stats
    } else {
        GuestStatsHooks::DISABLED
    };
    // Complete the patcher's entries before the guest counter starts, so
    // their setup is not charged to guest progress.
    host.prepare_entries()?;
    crate::guest::clock::initialize_rcb_clock()?;
    // The raw syscall, not libc's interposable getpid.
    let pid = Pid::from_raw(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) } as i32);
    let subscriptions = T::subscriptions(rpc.config());
    let instruction_subscriptions = InstructionSubscriptions {
        cpuid: subscriptions.has_cpuid(),
        rdtsc: subscriptions.has_rdtsc(),
    };
    crate::guest::instruction::preflight_instruction_faulting(instruction_subscriptions)?;
    let site_patching = host.site_patching()?;
    let vdso_sites = if site_patching {
        reverie::vdso::patch_current_vdso(&subscriptions)
    } else {
        reverie::vdso::patch_current_vdso_trapping(&subscriptions).map(|()| Vec::new())
    }
    .map_err(|error| io::Error::other(crate::guest::host::describe_reverie_error(&error)))?;
    let _signal_state =
        crate::guest::signal::prepare_guest_signal_state(instruction_subscriptions)?;
    let syscall_subscriptions = subscriptions.iter_syscalls().collect();
    if remove_coordinator_environment {
        // SAFETY: tool installation runs before application-created threads.
        unsafe { std::env::remove_var(crate::bootstrap::COORDINATOR_ENV) };
    }
    let tool = T::new(pid, rpc.config());
    let tool_host = ToolHost::<T, H::Runtime>::new(
        tool,
        rpc,
        pid,
        syscall_subscriptions,
        instruction_subscriptions.cpuid,
        host.runtime(stats),
    );
    // SAFETY: the one installing thread publishes the one host, before any
    // dispatch or controller activation.
    unsafe { installed_tool::publish_tool(tool_host)? };
    let result = activate_runtime(
        &host,
        stats,
        instruction_subscriptions,
        site_patching,
        &vdso_sites,
    );
    #[cfg(feature = "fixed-syscall-gates")]
    {
        fixed_install.complete = result.is_ok();
    }
    result
}

/// The runtime's activation once the Tool is published: option selection,
/// SIGALRM admission, the patcher's preparation, the instruction handler, the
/// dispatcher and filter, and instruction faulting.
fn activate_runtime(
    host: &impl PatchHost,
    stats: GuestStatsHooks,
    instructions: InstructionSubscriptions,
    site_patching: bool,
    vdso_sites: &[reverie::vdso::VdsoSyscallSite],
) -> io::Result<()> {
    crate::guest::support::set_stage_stream(host.stage_stream()?);
    crate::guest::protect::set_process_forks_allowed(host.process_forks_allowed()?);
    let sigalrm_handlers = host.sigalrm_handlers()?;
    debug_assert!(site_patching || vdso_sites.is_empty());
    host.select(site_patching);
    // Design section 6: phase 1 runs handlers in fallback-only processes. A
    // seccomp filter inherited from before the runtime could make the
    // runtime's own signal calls report success without running; with
    // handlers admitted the guest cannot add one later (see
    // record_filter_baseline). So admit handlers only in a process with none,
    // and only in one whose memory all has protection key 0.
    let admitted = sigalrm_handlers
        && !site_patching
        && unsafe { crate::guest::sigalrm::seccomp_filter_count() } == Some(0)
        && unsafe { crate::guest::sigalrm::protection_keys_in_use() } == Some(false);
    if admitted {
        // In ordinary context, before any guest call: the restorer check
        // compares against this.
        crate::guest::restorer::record_libc_identity()?;
    }
    crate::guest::sigalrm::set_admitted(admitted);
    #[cfg(feature = "fixed-syscall-gates")]
    if !crate::trap::fixed_gates_published() {
        return Err(io::Error::other(
            "FullTool fixed syscall gates are not prepared",
        ));
    }
    // Reserve before any instruction, guard or SIGSYS handler is installed.
    let region = ToolRegion::reserve()?;
    let controller = InProcessSeccomp::with_stack_backing(StackBacking::ToolRegion(region));
    host.prepare_patcher(vdso_sites)?;
    let config = host.runtime_config()?;
    let patcher = host.patcher();
    // SAFETY: installation runs before application threads; the patcher keeps
    // the Patcher contract (PatchHost's safety promise).
    unsafe { install_instruction_handler(patcher, instructions, config.use_alt_stack) }?;
    // SAFETY: as above; the seam's site questions go to the same patcher.
    let dispatcher =
        Box::new(unsafe { InGuestDispatcher::new(RuntimeSeam::new(patcher.0, stats)) });
    // SAFETY: once, before application threads start.
    unsafe { crate::install(dispatcher, &controller, &config)? };
    crate::guest::instruction::enable_instruction_faulting(instructions)?;
    if admitted {
        // Once the runtime's own filter is in place: see
        // record_filter_baseline.
        crate::guest::sigalrm::record_filter_baseline()?;
        // And its alternate stack: see check_entry_frame.
        crate::guest::sigalrm::record_runtime_stack()?;
    }
    Ok(())
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
        if !self.complete && crate::trap::fixed_gates_published() {
            unsafe {
                // Even stderr may be a full blocking pipe. Publication has
                // made returning unsafe, so diagnostics cannot precede exit.
                raw_syscall6(libc::SYS_exit_group, [127, 0, 0, 0, 0, 0]);
                core::arch::asm!("ud2", options(noreturn));
            }
        }
    }
}

/// The shared continuation's one registration of its handlers, kept so that
/// a retried installation reuses it while a registration by another backend
/// is still refused.
static SHARED_REGISTRATION: OnceLock<Result<(), io::ErrorKind>> = OnceLock::new();

/// Registers the shared continuation handlers (once per process) and prepares
/// this thread's continuation: a continued syscall runs through
/// [`process_tool_syscall_callback`] with the registered patcher's mapping
/// observation, and a continued instruction through the installed Tool.
pub fn initialize_shared_continuation() -> io::Result<()> {
    let region = ToolRegion::reserve()?;
    // SAFETY: this one cache always denotes these same handlers, which use
    // the continuation's genuine saved register block and interrupted PKRU
    // synchronously, as the shared entry requires.
    unsafe {
        continuation::initialize_registered(
            &SHARED_REGISTRATION,
            continuation::ContinuationHandlers {
                syscall: continue_syscall,
                instruction: continue_instruction,
            },
            StackBacking::ToolRegion(region),
        )
    }
}

unsafe fn continue_syscall(context: *mut RegisterContext, pkru: &mut Option<u32>) {
    // SAFETY: the continuation passes its genuine saved frame and the guest's
    // interrupted PKRU; the callbacks are this runtime's own.
    unsafe {
        installed_tool::dispatch_saved_syscall(
            context,
            None,
            SyscallDispatch::Fallback,
            Some(pkru),
            process_tool_syscall_callback,
            observe_registered_mapping,
            None,
        )
    };
}

unsafe fn continue_instruction(context: *mut RegisterContext, kind: InstructionEventKind) {
    // SAFETY: as for continue_syscall.
    unsafe { installed_tool::dispatch_saved_instruction(context, kind) };
}

/// The runtime options of a [`TrapHost`] installation.
#[derive(Clone, Copy, Debug)]
pub struct TrapOptions {
    /// Lifecycle stages go to the diagnostic stream.
    pub stage_stream: bool,
    /// The guest may create processes.
    pub process_forks_allowed: bool,
    /// Guest SIGALRM handlers are requested (signal phase 1).
    pub sigalrm_handlers: bool,
    /// The runtime's signal configuration.
    pub config: RuntimeConfig,
}

impl Default for TrapOptions {
    /// LiteInst's defaults when none of its option variables is set.
    fn default() -> Self {
        Self {
            stage_stream: false,
            process_forks_allowed: true,
            sigalrm_handlers: false,
            config: RuntimeConfig {
                restrict_signal_return: true,
                ..RuntimeConfig::default()
            },
        }
    }
}

/// The host with no patcher: every trapped syscall runs through the fallback
/// continuation, the vDSO gets the trapping stubs, and CPUID/RDTSC are
/// emulated through the continuation.
///
/// It has no allocator preflight. LiteInst's refuses (`EOPNOTSUPP`) a global
/// allocator that does not own the runtime's dispatch-scoped allocations, so
/// installation state could land in the guest's own heap and move its
/// layout between runs. A caller of `TrapHost` must select such an allocator
/// itself; Hermit's trap artifact gets this check when it moves onto
/// `TrapHost` (in-guest layering step 3).
pub struct TrapHost {
    options: TrapOptions,
}

impl TrapHost {
    /// A host with these runtime options.
    pub fn new(options: TrapOptions) -> Self {
        Self { options }
    }
}

static TRAP_PATCHER: PatcherRef = PatcherRef(&crate::guest::patcher::NoPatcher);

// SAFETY: NoPatcher declines everything, and no step below runs guest code or
// installs a handler or filter.
unsafe impl PatchHost for TrapHost {
    type Runtime = TrapRuntime;

    fn patcher(&self) -> &'static PatcherRef {
        &TRAP_PATCHER
    }

    fn stage_stream(&self) -> io::Result<bool> {
        Ok(self.options.stage_stream)
    }

    fn process_forks_allowed(&self) -> io::Result<bool> {
        Ok(self.options.process_forks_allowed)
    }

    fn sigalrm_handlers(&self) -> io::Result<bool> {
        Ok(self.options.sigalrm_handlers)
    }

    fn runtime_config(&self) -> io::Result<RuntimeConfig> {
        Ok(self.options.config)
    }

    fn runtime(&self, stats: GuestStatsHooks) -> TrapRuntime {
        TrapRuntime { stats }
    }
}

/// The shared runtime's services for a Tool host with no patcher.
pub struct TrapRuntime {
    stats: GuestStatsHooks,
}

impl HostRuntime for TrapRuntime {
    fn fork_child_rebind(&self) {
        continuation::rebind_fork_child();
    }

    fn emit_stage(&self, stage: &[u8]) {
        crate::guest::support::emit_in_guest_stage(stage);
    }

    fn fork_child_reset(&self, event: &SyscallEvent) {
        self.stats.reset_after_fork();
        // The child's first event entered through the fallback continuation
        // or a trap; with no patcher there is no hook to account.
        if let SyscallDispatch::Fallback = event.dispatch {
            let patcher = registered_patcher();
            patcher.record_fallback(event.number);
            self.stats
                .record_path(crate::stats::LiteinstDispatchPath::InGuestSigsys);
            self.stats
                .record_inherited_entry(crate::stats::InheritedEntry::Sigsys);
            if self.stats.is_enabled() {
                self.stats
                    .record_path(patcher.fallback_path(event.instruction_pointer));
            }
        }
    }

    fn cpuid_interception_enabled(&self) -> bool {
        crate::guest::instruction::cpuid_interception_enabled()
    }

    fn exit_process_stats(&self, tid: Pid) -> io::Result<()> {
        if self.stats.is_enabled() {
            self.stats.submit(tid, 0, Vec::new())
        } else {
            Ok(())
        }
    }

    fn read_clock(&self) -> io::Result<u64> {
        crate::guest::clock::read_guest_rcb_clock()
    }

    fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
        crate::guest::signal::signal_action_supported(number, args)
    }

    fn reserved_signal_mask(&self) -> u64 {
        crate::guest::signal::reserved_signal_mask()
    }
}
