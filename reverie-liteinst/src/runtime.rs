use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::ffi::CStr;
use std::ffi::OsStr;
use std::io;
use std::ptr;
use std::sync::OnceLock;

use liteinst2::patcher::GuardSignalAction;
use liteinst2::patcher::GuardSignalHandler;
use liteinst2::patcher::GuardSignalRuntime;
use liteinst2::patcher::JumpPatchPlan;
use liteinst2::patcher::PatchError;
use liteinst2::patcher::prepare_live_patching_with_signal_runtime;
use liteinst2::scanner::InstructionScanner;
use liteinst2::scanner::ScanResult;
use liteinst2::trampoline::ExecutableTrampoline;
use liteinst2::trampoline::HookContext;
use liteinst2::trampoline::HookSite;
use liteinst2::trampoline::InstalledHook;
use liteinst2::trampoline::TrampolineArena;
use liteinst2::trampoline::TrampolineError;
use liteinst2::trampoline::TrampolinePlan;
use reverie_inguest::BuiltinTool;
use reverie_inguest::dispatch::SyscallEvent as PreloadSyscallEvent;
use reverie_inguest::dispatch::is_fork_like;
use reverie_inguest::fork::ForkHook;
use reverie_inguest::guest::context::RegisterContext;
use reverie_inguest::lifecycle::InProcessSeccomp;
use reverie_inguest::lifecycle::RuntimeConfig;
use reverie_inguest::trap::raw_syscall6;

use crate::COMPAT_EVENT_COOKIE_ENV;
use crate::COMPAT_EVENT_FD_ENV;
use crate::interior_entry::Census;
use crate::interior_entry::CensusError;
use crate::interior_entry::ObjectImage;
use crate::interior_entry::Refusal;
use crate::interior_entry::prove;

#[path = "installed_entries.rs"]
mod installed_entries;
pub(crate) use installed_entries::PreparedCallbacks;
pub(crate) use installed_entries::prepare as prepare_installed_callbacks;

const fn const_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const UNSET_RESULT: i64 = i64::MIN;
const TOOL_STRACE: u8 = 1;
const TOOL_COMPAT: u8 = 2;
const TOOL_REVERIE: u8 = 3;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared reverie-inguest built-in tool selection.
/// `REVERIE_LITEINST_TOOL` value selecting the shared passthrough built-in.
pub const TOOL_PASSTHROUGH: &str = "passthrough";
/// `REVERIE_LITEINST_TOOL` value selecting the shared getpid-spoofing built-in.
pub const TOOL_SPOOF_GETPID: &str = "spoof-getpid";
const EVENT_CHANNEL_IDENTITY_FAILURE_STATUS: i32 = 120;
const EVENT_CHANNEL_WRITE_FAILURE_STATUS: i32 = 121;
/// Enables fail-closed, allocation-free in-guest lifecycle stage markers on stderr.
pub const IN_GUEST_STAGE_STREAM_ENV: &str = "REVERIE_LITEINST_IN_GUEST_STAGE_STREAM";
const MAX_PATCH_SITES: usize = 4096;
const ARENA_SLOTS: usize = 128;
const PATCH_SNAPSHOT_BYTES: usize = 64;
const SITE_INSTALLING: u8 = 1;
const SITE_ACTIVE: u8 = 2;
const SITE_FALLBACK: u8 = 3;
const SITE_STALE: u8 = 4;
/// The hook was refused, under the installation lock, after the site's bytes
/// were re-read and found intact and before the runtime changed any page
/// protection or byte there; no other site's published patch covers it, and
/// no later patch may cover it (see [`check_neighbours`]). Execution therefore
/// resumes after the instruction on the original code. Only the
/// instruction-fault path records this state; every other caller records
/// `SITE_FALLBACK` for any refusal.
const SITE_UNPATCHABLE: u8 = 5;
/// A signal-deferred exact-syscall adapter. No source jump was published;
/// every entry must recheck its number and retained source admission.
const SITE_UNPUBLISHED: u8 = 6;

static TOOL_MODE: AtomicU8 = AtomicU8::new(0);
static EVENT_FD: AtomicI32 = AtomicI32::new(libc::STDERR_FILENO);
static EVENT_COOKIE: AtomicU64 = AtomicU64::new(0);
static EVENT_DEVICE: AtomicU64 = AtomicU64::new(0);
static EVENT_INODE: AtomicU64 = AtomicU64::new(0);

static ARENAS: OnceLock<Vec<RuntimeArena>> = OnceLock::new();
static SITES: OnceLock<Box<[SiteSlot]>> = OnceLock::new();
static PAGE_SIZE: AtomicU64 = AtomicU64::new(0);
static INSTALL_HELD: AtomicBool = AtomicBool::new(false);
static PATCH_PUBLICATION: AtomicU8 = AtomicU8::new(PatchPublication::Concurrent as u8);
static SITE_PATCHING_ENABLED: AtomicBool = AtomicBool::new(true);

pub(crate) use reverie_inguest::guest::clock::enter_rcb_handler;
pub(crate) use reverie_inguest::guest::clock::initialize_rcb_clock;
pub(crate) use reverie_inguest::guest::clock::leave_rcb_handler;
pub(crate) use reverie_inguest::guest::clock::read_guest_rcb_clock;
pub(crate) use reverie_inguest::guest::event::InstructionEventKind;
use reverie_inguest::guest::instruction::FaultSite;
use reverie_inguest::guest::instruction::InstructionFaultSeam;
pub(crate) use reverie_inguest::guest::instruction::InstructionSubscriptions;
use reverie_inguest::guest::instruction::PatchOutcome;
pub(crate) use reverie_inguest::guest::instruction::cpuid_interception_enabled;
use reverie_inguest::guest::instruction::decode_instruction;
use reverie_inguest::guest::instruction::deliver_default_sigsegv;
use reverie_inguest::guest::instruction::enable_instruction_faulting;
use reverie_inguest::guest::instruction::execute_native_instruction;
use reverie_inguest::guest::instruction::install_instruction_signal_handler;
pub(crate) use reverie_inguest::guest::instruction::preflight_instruction_faulting;
use reverie_inguest::guest::instruction::set_all_instruction_native;
use reverie_inguest::guest::instruction::set_instruction_native;
use reverie_inguest::guest::protect::close_range_preserving_fds;
use reverie_inguest::guest::protect::fd_arg;
use reverie_inguest::guest::protect::protect_runtime_control;
use reverie_inguest::guest::protect::protect_runtime_descriptors_before_tool;
pub(crate) use reverie_inguest::guest::protect::replace_coordinator_fd;
pub(crate) use reverie_inguest::guest::protect::reserve_coordinator_fd;
pub use reverie_inguest::guest::protect::reserve_tool_output_fd;
use reverie_inguest::guest::protect::set_process_forks_allowed;
use reverie_inguest::guest::protect::syscall_targets_event_fd;
pub use reverie_inguest::guest::protect::tool_output_fd;
pub(crate) use reverie_inguest::guest::signal::prepare_guest_signal_state;
pub(crate) use reverie_inguest::guest::signal::reserved_signal_mask;
pub(crate) use reverie_inguest::guest::signal::signal_action_supported;
use reverie_inguest::guest::support::IN_GUEST_STAGE_WRITE_FAILURE_STATUS;
pub(crate) use reverie_inguest::guest::support::StackLine;
pub(crate) use reverie_inguest::guest::support::ToolCallbackGuard;
pub(crate) use reverie_inguest::guest::support::emit_in_guest_stage;
pub(crate) use reverie_inguest::guest::support::exit_now;
pub(crate) use reverie_inguest::guest::support::read_own_bytes;
pub(crate) use reverie_inguest::guest::support::scan_own_maps;
pub(crate) use reverie_inguest::guest::support::tool_callback_active;
use reverie_inguest::guest::trap_dispatch::InGuestDispatcher;
use reverie_inguest::guest::trap_dispatch::SitePatch;
use reverie_inguest::guest::trap_dispatch::TrapPath;
use reverie_inguest::guest::trap_dispatch::TrapSeam;
use reverie_inguest::guest::trap_dispatch::forward_nested_tool_syscall;

struct RuntimeArena {
    mapping_start: u64,
    mapping_end: u64,
    mapping_name: Box<str>,
    arena: TrampolineArena,
    /// The object that owned this executable mapping at initialization, or
    /// `None` for an anonymous mapping or one whose object cannot be identified.
    image: Option<ObjectImage>,
    /// Built by the first installation that needs it; see [`Self::census`].
    census: OnceLock<Result<Census, CensusError>>,
    /// An adapter may never use this load-time object's census after a
    /// mapping change overlaps its retained inputs, even at another site.
    adapter_mapping_replaced: AtomicBool,
}

impl RuntimeArena {
    /// Returns the entry census of this arena's executable mapping, building it
    /// on first use (<https://github.com/rrnewton/reverie/issues/812>).
    ///
    /// Call only while holding the installation lock inside a patch allocation
    /// scope: the build allocates, and the census is kept for the life of the
    /// process.
    fn census(&self) -> Result<&Census, Refusal> {
        self.census
            .get_or_init(|| {
                let image = self.image.as_ref().ok_or(NO_OBJECT_IMAGE)?;
                // SAFETY: the image records the readable mappings of the object
                // that mapped this arena's text when LiteInst initialized.
                // Those are the executable and its load-time libraries, which
                // the dynamic loader never unmaps. arena_for already relies on
                // the text mapping itself staying in place.
                unsafe { image.census((self.mapping_start, self.mapping_end)) }
            })
            .as_ref()
            .map_err(|error| Refusal::NoCensus(*error))
    }
}

const NO_OBJECT_IMAGE: CensusError =
    CensusError("the executable mapping belongs to no identifiable object");

/// Whether an installation must first prove that no known control transfer
/// enters the bytes its patch displaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryProof {
    /// A `syscall` site in an object's code: the census must prove it.
    Required,
    /// A site the census does not list. vDSO stubs are written by reverie
    /// itself and have no object image. CPUID, RDTSC and RDTSCP sites are not
    /// `syscall` instructions, so the census has no record of them.
    NotListed,
}

struct SiteHookPolicy {
    publication: PatchPublication,
    entry_proof: EntryProof,
    unpublished_read_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeMap {
    start: u64,
    end: u64,
    offset: u64,
    device: String,
    inode: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    shared: bool,
}

struct SiteSlot {
    address: AtomicU64,
    state: AtomicU8,
    hook: AtomicPtr<InstalledHook>,
    adapter: AtomicPtr<UnpublishedSyscall>,
    mapping_end: AtomicU64,
    trap_count: AtomicU64,
    hook_count: AtomicU64,
    instruction_len: AtomicU8,
    straddle_prefix: AtomicU8,
    /// Set, and never cleared, once this runtime first changes the site's
    /// protection to publish a patch there.
    publication_attempted: AtomicBool,
    /// The eight bytes at the site before, and after, the latest completed
    /// publication; valid only while `words_recorded` is set. Cleared when a
    /// new attempt starts, which happens only after the earlier patch was
    /// proved gone (see [`earlier_patch_survives`]).
    original_word: AtomicU64,
    published_word: AtomicU64,
    words_recorded: AtomicBool,
}

impl SiteSlot {
    fn new() -> Self {
        Self {
            address: AtomicU64::new(0),
            state: AtomicU8::new(0),
            hook: AtomicPtr::new(ptr::null_mut()),
            adapter: AtomicPtr::new(ptr::null_mut()),
            mapping_end: AtomicU64::new(0),
            trap_count: AtomicU64::new(0),
            hook_count: AtomicU64::new(0),
            instruction_len: AtomicU8::new(0),
            straddle_prefix: AtomicU8::new(0),
            publication_attempted: AtomicBool::new(false),
            original_word: AtomicU64::new(0),
            published_word: AtomicU64::new(0),
            words_recorded: AtomicBool::new(false),
        }
    }
}

/// Retained for process lifetime, including after mapping invalidation and
/// across in-flight guest signal handlers. The source snapshot controls only
/// future admission; the trampoline always returns to the live source + 2.
struct UnpublishedSyscall {
    trampoline: ExecutableTrampoline,
    source: Box<[u8]>,
}

pub(crate) use reverie_inguest::guest::event::SyscallDispatch;
pub(crate) use reverie_inguest::guest::event::SyscallEvent;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared reverie-inguest built-in tool parser.
/// Parses a shared `reverie-inguest` [`BuiltinTool`] from a `REVERIE_LITEINST_TOOL`
/// value, returning `None` for the LiteInst-native `strace`/`compat` modes and
/// any other value.
///
/// This is the LiteInst analog of e9patch's `builtin_tool_from_env_value`: it
/// lets the single `REVERIE_LITEINST_TOOL` selector name a shared built-in
/// installed verbatim through [`reverie_inguest::install_builtin`], bypassing the
/// LiteInst patching dispatcher.
pub fn builtin_tool_from_env_value(value: &OsStr) -> Option<BuiltinTool> {
    match value.to_str()? {
        TOOL_PASSTHROUGH => Some(BuiltinTool::Passthrough),
        TOOL_SPOOF_GETPID => Some(BuiltinTool::SpoofGetpid),
        _ => None,
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared built-in installation entry point.
/// Installs a shared `reverie-inguest` built-in tool verbatim.
///
/// Unlike [`install_runtime`], this does NOT prepare LiteInst instrumentation:
/// the shared built-ins install their own SIGSYS handler and seccomp filter via
/// [`reverie_inguest::install_builtin`] and do not patch syscall sites. This
/// proves the LiteInst fallback/trap path can service and MUTATE a syscall
/// result (for example `getpid` -> `SPOOF_PID`), matching e9patch's
/// `install_builtin_runtime`.
///
/// # Safety
///
/// The dynamic loader must call this exactly once before application threads
/// start; it installs process-wide, irreversible seccomp state.
pub(crate) unsafe fn install_builtin_runtime(tool: BuiltinTool) -> io::Result<()> {
    #[cfg(feature = "fixed-syscall-gates")]
    require_fixed_gate_full_tool(false)?;
    let region = reverie_inguest::guest::tool_region::ToolRegion::reserve()?;
    unsafe {
        reverie_inguest::install_builtin_with_stack_backing(
            tool,
            reverie_inguest::guest::tool_region::StackBacking::ToolRegion(region),
        )
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review launcher-selected shared RuntimeConfig alt-stack knob.
/// Environment variable selecting the shared [`RuntimeConfig::use_alt_stack`]
/// knob for the in-guest runtime's `SIGSYS` handler.
///
/// The [`RuntimeConfig`] and the controller that honors it live in
/// `reverie-inguest` and are reviewed exactly once; both ld-preload backends
/// install through that same shared seam. Only the env-var spelling is
/// LiteInst's, exactly as with `REVERIE_LITEINST_TOOL`. This is the LiteInst
/// analog of e9patch's `REVERIE_E9PATCH_ALT_STACK`.
///
/// When unset the shared default applies ([`RuntimeConfig::default`], alt stack
/// **on**). It applies to the LiteInst-dispatcher install path
/// (`install_runtime`, used by the `strace`/`compat`/Detcore modes); a shared
/// [`BuiltinTool`] runs through `install_builtin`, which uses the shared default.
pub const ALT_STACK_ENV: &str = "REVERIE_LITEINST_ALT_STACK";
/// Allows a caller to keep fork-family syscalls fail-closed while integrating
/// a Tool whose process lifecycle is not ready for the direct backend.
pub const PROCESS_FORK_ENV: &str = "REVERIE_LITEINST_PROCESS_FORK";
/// Selects whether an in-guest Reverie Tool patches trapping syscall sites.
///
/// Unset or `1` keeps site patching on. `0` turns it off for syscall sites: no
/// syscall site is claimed or patched, and every trapping syscall runs the Tool
/// through the in-guest `SIGSYS` fallback (`crate::syscall_fallback`). That
/// includes subscribed vDSO fast paths: they get ptrace's whole
/// `mov $nr, %eax; syscall; ret` stubs with no hook
/// ([`reverie_ptrace::patch_current_vdso_trapping`]) instead of hooked bare
/// `syscall`s. Subscribed `cpuid`, `rdtsc`, and `rdtscp` instructions are
/// covered too: no instruction site is claimed or patched, and each one is
/// emulated through the same fallback continuation, as for late code.
/// Any other value is rejected. The variable is not removed, so the guest can
/// read it in its environment. Only an in-guest Reverie Tool (the
/// `install_tool` family) honors `0`. When the runtime is selected from the
/// environment, the built-in, `strace`, and `compat` runtimes do not take
/// this selector (the built-ins never patch syscall sites; the others always
/// do), so they refuse to start when this variable holds anything but `1`.
pub const SITE_PATCHING_ENV: &str = "REVERIE_LITEINST_SITE_PATCHING";
/// [`SITE_PATCHING_ENV`] for the non-allocating constructor check.
const SITE_PATCHING_ENV_C: &CStr = c"REVERIE_LITEINST_SITE_PATCHING";
const _: () = assert!(const_bytes_eq(
    SITE_PATCHING_ENV_C.to_bytes(),
    SITE_PATCHING_ENV.as_bytes()
));

/// Parses a [`SITE_PATCHING_ENV`] value into the site-patching boolean.
///
/// `None` (unset) and `1` select patching; `0` disables it. Any other value,
/// including surrounding whitespace, is rejected, matching the strict
/// [`PROCESS_FORK_ENV`] parse.
pub fn site_patching_from_env_value(value: Option<&OsStr>) -> io::Result<bool> {
    match value {
        None => Ok(true),
        Some(value) if value == OsStr::new("1") => Ok(true),
        Some(value) if value == OsStr::new("0") => Ok(false),
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {SITE_PATCHING_ENV} value {value:?}"),
        )),
    }
}

/// Whether this process image's runtime patches syscall sites: the value
/// [`SITE_PATCHING_ENV`] held when the in-guest Tool host read it during
/// installation (the `install_tool` family), which is what every later
/// patching decision in this image loads. It is the runtime's captured
/// setting, not the environment now: guest code can change the environment
/// after the runtime read it, but not this.
///
/// Meaningful once the Tool's installation has returned. Before that it is the
/// default, `true`, which is also what a runtime installed without an in-guest
/// Tool (the built-in, `strace` and `compat` runtimes, which never take the
/// selector) reports.
pub fn site_patching_enabled() -> bool {
    SITE_PATCHING_ENABLED.load(Ordering::Acquire)
}

/// Refuses to start a runtime that does not take [`SITE_PATCHING_ENV`] when the
/// variable holds anything but the default `1`. Reads with `getenv` so the
/// accepted case does not allocate before the constructor window.
fn require_site_patching(runtime: &str) -> io::Result<()> {
    // SAFETY: the loader runs constructors before application threads start,
    // so nothing mutates the environment concurrently; the name is NUL-terminated.
    // Read from the environment block itself, not through libc's
    // interposable getenv.
    let value = reverie_inguest::guest::support::environment_value(SITE_PATCHING_ENV_C.to_bytes());
    if value.is_none_or(|value| value == b"1") {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{SITE_PATCHING_ENV} is honored only by an in-guest Reverie Tool; \
             the {runtime} runtime does not take it"
        ),
    ))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review alt-stack env parse/reject contract.
/// Parses an [`ALT_STACK_ENV`] value into the `use_alt_stack` boolean.
///
/// `None` (unset) yields the shared default. Accepts `1`/`0`, `true`/`false`,
/// `on`/`off`, and `yes`/`no` (case-insensitive, surrounding whitespace
/// trimmed). Any other value is rejected. Kept pure so the parse/reject contract
/// is unit-testable without touching process-global state, matching
/// [`builtin_tool_from_env_value`] and e9patch's `alt_stack_from_env_value`.
pub fn alt_stack_from_env_value(value: Option<&OsStr>) -> io::Result<bool> {
    let Some(value) = value else {
        return Ok(RuntimeConfig::default().use_alt_stack);
    };
    let text = value.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ALT_STACK_ENV} must be valid UTF-8"),
        )
    })?;
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {ALT_STACK_ENV} value {value:?}"),
        )),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review launcher-selected RuntimeConfig assembly.
/// Builds the shared [`RuntimeConfig`] the launcher selected via [`ALT_STACK_ENV`].
///
/// Reads the process environment once; the parse itself is delegated to the pure
/// [`alt_stack_from_env_value`].
fn runtime_config_from_env() -> io::Result<RuntimeConfig> {
    let use_alt_stack = alt_stack_from_env_value(std::env::var_os(ALT_STACK_ENV).as_deref())?;
    // Signal phase 1: in the Tool mode every signal handler in the process is
    // the runtime's own and returns through its private restorer, so the
    // filter admits `rt_sigreturn` there alone.
    Ok(RuntimeConfig {
        use_alt_stack,
        restrict_signal_return: TOOL_MODE.load(Ordering::Acquire) == TOOL_REVERIE,
    })
}

pub(crate) fn initialize_from_environment() -> io::Result<()> {
    let tool_value = std::env::var_os("REVERIE_LITEINST_TOOL");
    initialize_from_selected_value(tool_value.as_deref())
}

// Both acquisition paths own the selected value across initialization. The
// actual standalone leaf reads the same raw environment vector as its native
// activation prefix; generic embeddings retain std::env/getenv acquisition.
pub(crate) fn initialize_from_selected_value(tool_value: Option<&OsStr>) -> io::Result<()> {
    // The experimental artifact has only a FullTool contract. Refuse before
    // reserving its page or changing a handler, rather than silently changing
    // the compatibility/built-in signal-return policy.
    #[cfg(feature = "fixed-syscall-gates")]
    if tool_value.is_some() {
        require_fixed_gate_full_tool(false)?;
    }
    // Prefer a shared reverie-inguest built-in when the selector names one, so a
    // single env var is a superset of the LiteInst-native strace/compat modes
    // (matches e9patch's single TOOL_ENV selecting shared built-ins).
    if let Some(value) = tool_value
        && let Some(tool) = builtin_tool_from_env_value(value)
    {
        require_site_patching("built-in Tool")?;
        // SAFETY: the loader calls this once before application threads start.
        return unsafe { install_builtin_runtime(tool) };
    }
    let mode = match tool_value {
        None => return Ok(()),
        Some(value) if value == OsStr::new("strace") => TOOL_STRACE,
        Some(value) if value == OsStr::new("compat") => TOOL_COMPAT,
        Some(value) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported REVERIE_LITEINST_TOOL value {value:?}"),
            ));
        }
    };
    require_site_patching(if mode == TOOL_COMPAT {
        "compat"
    } else {
        "strace"
    })?;
    TOOL_MODE.store(mode, Ordering::Release);
    let event_channel = if mode == TOOL_COMPAT {
        compatibility_event_channel()?
    } else {
        None
    };
    let event_fd = event_channel
        .as_ref()
        .map_or(libc::STDERR_FILENO, |channel| channel.fd);
    EVENT_FD.store(event_fd, Ordering::Release);
    if let Some(channel) = event_channel {
        EVENT_COOKIE.store(channel.cookie, Ordering::Release);
        EVENT_DEVICE.store(channel.device, Ordering::Release);
        EVENT_INODE.store(channel.inode, Ordering::Release);
        // SAFETY: initialization runs before application threads start.
        unsafe {
            std::env::remove_var(COMPAT_EVENT_FD_ENV);
            std::env::remove_var(COMPAT_EVENT_COOKIE_ENV);
        }
    }

    install_runtime(
        crate::stats::GuestStatsHooks::DISABLED,
        PatchPublication::Concurrent,
        InstructionSubscriptions::default(),
        &[],
        None,
    )
}

pub(crate) fn initialize_reverie_tool(
    stats: crate::stats::GuestStatsHooks,
    publication: PatchPublication,
    instructions: InstructionSubscriptions,
    site_patching: bool,
    vdso_sites: &[reverie_ptrace::VdsoSyscallSite],
    prepared_callbacks: PreparedCallbacks,
) -> io::Result<()> {
    let stage_stream = match std::env::var_os(IN_GUEST_STAGE_STREAM_ENV).as_deref() {
        None => false,
        Some(value) if value == OsStr::new("0") => false,
        Some(value) if value == OsStr::new("1") => true,
        Some(value) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported {IN_GUEST_STAGE_STREAM_ENV} value {value:?}"),
            ));
        }
    };
    reverie_inguest::guest::support::set_stage_stream(stage_stream);
    let process_forks_allowed = match std::env::var_os(PROCESS_FORK_ENV).as_deref() {
        None => true,
        Some(value) if value == OsStr::new("1") => true,
        Some(value) if value == OsStr::new("0") => false,
        Some(value) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported {PROCESS_FORK_ENV} value {value:?}"),
            ));
        }
    };
    set_process_forks_allowed(process_forks_allowed);
    let sigalrm_handlers =
        sigalrm_handlers_from_env_value(std::env::var_os(SIGALRM_HANDLERS_ENV).as_deref())?;
    debug_assert!(site_patching || vdso_sites.is_empty());
    SITE_PATCHING_ENABLED.store(site_patching, Ordering::Release);
    TOOL_MODE.store(TOOL_REVERIE, Ordering::Release);
    // Design section 6: phase 1 runs handlers in fallback-only processes.
    // A seccomp filter inherited from before the runtime could make the
    // runtime's own signal calls report success without running; with
    // handlers admitted the guest cannot add one later (see
    // record_filter_baseline). So admit handlers only in a process with none.
    // And only in a process whose memory all has protection key 0, whose
    // rights the runtime applies itself; from then on no other key can be
    // assigned (see injected_syscall_guard). A key the process allocated but
    // has not assigned can no longer be assigned either.
    let admitted = sigalrm_handlers
        && !site_patching
        && unsafe { reverie_inguest::guest::sigalrm::seccomp_filter_count() } == Some(0)
        && unsafe { reverie_inguest::guest::sigalrm::protection_keys_in_use() } == Some(false);
    if admitted {
        // In ordinary context, before any guest call: the restorer check
        // compares against this.
        reverie_inguest::guest::restorer::record_libc_identity()?;
    }
    reverie_inguest::guest::sigalrm::set_admitted(admitted);
    install_runtime(
        stats,
        publication,
        instructions,
        vdso_sites,
        Some(prepared_callbacks),
    )?;
    if admitted {
        // Once the runtime's own filter is in place: see
        // record_filter_baseline.
        reverie_inguest::guest::sigalrm::record_filter_baseline()?;
        // And its alternate stack: see check_entry_frame.
        reverie_inguest::guest::sigalrm::record_runtime_stack()?;
    }
    Ok(())
}

/// Opts the Tool mode into guest SIGALRM handlers (signal phase 1), `1` or
/// `0`. Off by default: until the runtime delivers a SIGALRM to an admitted
/// handler (step I4), a run that installs one ends at its first SIGALRM.
pub const SIGALRM_HANDLERS_ENV: &str = "REVERIE_LITEINST_SIGALRM_HANDLERS";

/// Parse [`SIGALRM_HANDLERS_ENV`]: absent or `0` is off, `1` is on.
pub fn sigalrm_handlers_from_env_value(value: Option<&OsStr>) -> io::Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == OsStr::new("0") => Ok(false),
        Some(value) if value == OsStr::new("1") => Ok(true),
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {SIGALRM_HANDLERS_ENV} value {value:?}"),
        )),
    }
}

fn install_runtime(
    stats: crate::stats::GuestStatsHooks,
    publication: PatchPublication,
    instructions: InstructionSubscriptions,
    vdso_sites: &[reverie_ptrace::VdsoSyscallSite],
    _prepared_callbacks: Option<PreparedCallbacks>,
) -> io::Result<()> {
    #[cfg(feature = "fixed-syscall-gates")]
    {
        require_fixed_gate_full_tool(TOOL_MODE.load(Ordering::Acquire) == TOOL_REVERIE)?;
        if !reverie_inguest::trap::fixed_gates_published() {
            return Err(io::Error::other(
                "FullTool fixed syscall gates are not prepared",
            ));
        }
    }
    // Active LiteInst only: inert compatibility loads never reserve this
    // range, and generic e9patch/SaBRe callers keep their existing backing.
    // Reserve before any instruction/guard/SIGSYS handler is installed.
    let region = reverie_inguest::guest::tool_region::ToolRegion::reserve()?;
    let controller = InProcessSeccomp::with_stack_backing(
        reverie_inguest::guest::tool_region::StackBacking::ToolRegion(region),
    );
    PATCH_PUBLICATION.store(publication as u8, Ordering::Release);
    prepare_instrumentation()?;
    install_vdso_sites(vdso_sites)?;
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-254): Review launcher-selected RuntimeConfig at the install seam.
    let config = runtime_config_from_env()?;
    // SAFETY: LiteInst's seam functions are the code this runtime's own
    // SIGSEGV handler ran before the handler moved to reverie-inguest: they
    // read the arenas and site table recorded at startup and patch a claimed
    // site, with raw syscalls and no allocation.
    unsafe {
        install_instruction_signal_handler(
            &INSTRUCTION_FAULT_SEAM,
            instructions,
            config.use_alt_stack,
        )
    }?;
    unsafe {
        reverie_inguest::install(
            // SAFETY (InGuestDispatcher::new): registered only through this
            // install, whose SIGSYS handler hands it genuine trapped events;
            // LiteInst never passes trap events to it any other way.
            Box::new(InGuestDispatcher::new(LiteinstSeam::new(
                stats,
                publication,
            ))),
            &controller,
            &config,
        )
    }?;
    enable_instruction_faulting(instructions)
}

#[cfg(feature = "fixed-syscall-gates")]
fn require_fixed_gate_full_tool(full_tool: bool) -> io::Result<()> {
    if full_tool {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed syscall gates require the in-guest FullTool installation route",
        ))
    }
}

struct CompatibilityEventChannel {
    fd: libc::c_int,
    cookie: u64,
    device: u64,
    inode: u64,
}

fn compatibility_event_channel() -> io::Result<Option<CompatibilityEventChannel>> {
    let Some(value) = std::env::var_os(COMPAT_EVENT_FD_ENV) else {
        if std::env::var_os(COMPAT_EVENT_COOKIE_ENV).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{COMPAT_EVENT_COOKIE_ENV} requires {COMPAT_EVENT_FD_ENV}"),
            ));
        }
        return Ok(None);
    };
    let value = value.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} must be valid UTF-8"),
        )
    })?;
    let fd = value.parse::<libc::c_int>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} must be a non-negative descriptor"),
        )
    })?;
    let flags = if fd < 0 {
        -1
    } else {
        // Raw syscalls here and below, not libc's interposable wrappers.
        let flags = unsafe {
            raw_syscall6(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
            )
        };
        flags as libc::c_int
    };
    if flags < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} does not name an open descriptor"),
        ));
    }
    if flags & libc::O_ACCMODE == libc::O_RDONLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} must name a writable descriptor"),
        ));
    }
    let cookie = std::env::var(COMPAT_EVENT_COOKIE_ENV)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{COMPAT_EVENT_COOKIE_ENV} is required with {COMPAT_EVENT_FD_ENV}"),
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{COMPAT_EVENT_COOKIE_ENV} must be a nonzero decimal u64"),
            )
        })?;
    if cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_COOKIE_ENV} must be a nonzero decimal u64"),
        ));
    }

    let mut metadata: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe {
        raw_syscall6(
            libc::SYS_fstat,
            [fd as u64, (&raw mut metadata) as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} metadata could not be read"),
        ));
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} must name a pipe"),
        ));
    }
    if unsafe {
        raw_syscall6(
            libc::SYS_fcntl,
            [
                fd as u64,
                libc::F_SETFL as u64,
                (flags | libc::O_NONBLOCK) as u64,
                0,
                0,
                0,
            ],
        )
    } < 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{COMPAT_EVENT_FD_ENV} could not be made nonblocking"),
        ));
    }

    Ok(Some(CompatibilityEventChannel {
        fd,
        cookie,
        device: metadata.st_dev,
        inode: metadata.st_ino,
    }))
}

fn read_runtime_maps() -> io::Result<Vec<RuntimeMap>> {
    Ok(parse_runtime_maps(&std::fs::read_to_string(
        "/proc/self/maps",
    )?))
}

fn parse_runtime_maps(maps: &str) -> Vec<RuntimeMap> {
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (range, permissions, offset, device, inode) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            let (start, end) = range.split_once('-')?;
            let permissions = permissions.as_bytes();
            Some(RuntimeMap {
                start: u64::from_str_radix(start, 16).ok()?,
                end: u64::from_str_radix(end, 16).ok()?,
                offset: u64::from_str_radix(offset, 16).ok()?,
                device: device.to_owned(),
                inode: inode.parse().ok()?,
                readable: permissions.first() == Some(&b'r'),
                writable: permissions.get(1) == Some(&b'w'),
                executable: permissions.get(2) == Some(&b'x'),
                shared: permissions.get(3) == Some(&b's'),
            })
        })
        .collect()
}

/// Returns the readable mappings of the file that `maps` maps executable at
/// `[text_start, text_end)`, with the address of its ELF header.
///
/// Mappings belong to one object when they share the text mapping's device and
/// inode. The header is the single such mapping at file offset zero. A file
/// that is mapped twice has two, so it gets no image, and neither does an
/// anonymous mapping.
fn object_image(maps: &[RuntimeMap], text_start: u64, text_end: u64) -> Option<ObjectImage> {
    let text = maps
        .iter()
        .find(|map| map.start == text_start && map.end == text_end && map.executable)?;
    if text.inode == 0 {
        return None;
    }
    let object = maps
        .iter()
        .filter(|map| map.readable && map.device == text.device && map.inode == text.inode);
    let mut headers = object.clone().filter(|map| map.offset == 0);
    let header = match (headers.next(), headers.next()) {
        (Some(header), None) => header.start,
        _ => return None,
    };
    let ranges = object
        .map(|map| (map.start, map.end, map.executable))
        .collect();
    Some(ObjectImage::new(header, ranges))
}

fn discover_arena_aliases(
    before: &[RuntimeMap],
    after: &[RuntimeMap],
) -> io::Result<(RuntimeMap, RuntimeMap)> {
    let expected_len = (ARENA_SLOTS * 4096) as u64;
    let new_maps = after
        .iter()
        .filter(|mapping| {
            !before
                .iter()
                .any(|old| old.start == mapping.start && old.end == mapping.end)
                && mapping.end.checked_sub(mapping.start) == Some(expected_len)
                && mapping.offset == 0
                && mapping.inode != 0
                && mapping.shared
                && mapping.readable
        })
        .collect::<Vec<_>>();
    let pairs = new_maps
        .iter()
        .filter_map(|writable| {
            (writable.writable && !writable.executable).then_some(())?;
            let executable = new_maps.iter().find(|executable| {
                !executable.writable
                    && executable.executable
                    && executable.device == writable.device
                    && executable.inode == writable.inode
            })?;
            Some(((*writable).clone(), (**executable).clone()))
        })
        .collect::<Vec<_>>();
    match pairs.as_slice() {
        [(writable, executable)] => Ok((writable.clone(), executable.clone())),
        _ => Err(io::Error::other(format!(
            "LiteInst arena allocation produced {} identity-matched alias pairs",
            pairs.len()
        ))),
    }
}

fn prepare_instrumentation() -> io::Result<()> {
    crate::straddler::initialize_from_environment()?;
    // Initialization retains the guard router for modes that may publish
    // concurrently. Its SIGTRAP handler is installed through the runtime's
    // raw signal operations so that it, like the SIGSYS and SIGSEGV handlers,
    // returns through the runtime's private restorer.
    // SAFETY: preparation runs single-threaded, before the syscall filter is
    // installed, and the callbacks below meet `GuardSignalRuntime`'s contract.
    unsafe { prepare_live_patching_with_signal_runtime(GUARD_SIGNAL_RUNTIME) }
        .map_err(|error| io::Error::other(error.to_string()))?;
    prepare_instrumentation_state()
}

/// LiteInst2's guard-router signal operations, done with the runtime's raw
/// signal syscalls and its private restorer.
const GUARD_SIGNAL_RUNTIME: GuardSignalRuntime = GuardSignalRuntime {
    install_blocked: install_guard_handler_blocked,
    restore_mask: restore_guard_signal_mask,
    restore_default: restore_guard_default_action,
};

/// The calling thread's mask before [`install_guard_handler_blocked`] blocked
/// SIGTRAP, held until [`restore_guard_signal_mask`] puts it back.
static GUARD_PRIOR_MASK: AtomicU64 = AtomicU64::new(0);
static GUARD_PRIOR_MASK_HELD: AtomicBool = AtomicBool::new(false);
/// False also covers uninitialized/failed installation. An ignored SIGTRAP
/// routed through a returning caught handler can interrupt timeout I/O, so
/// only a successfully captured default profile admits the new adapter.
static GUARD_PRIOR_DEFAULT: AtomicBool = AtomicBool::new(false);

/// Block SIGTRAP, refuse a prior custom handler, report the prior action, and
/// install the guard router returning through the runtime's restorer; SIGTRAP
/// stays blocked until [`restore_guard_signal_mask`].
unsafe fn install_guard_handler_blocked(
    signal: libc::c_int,
    handler: GuardSignalHandler,
    flags: libc::c_int,
    previous: *mut GuardSignalAction,
) -> Result<(), i32> {
    use reverie_inguest::signal::KernelSigaction;
    use reverie_inguest::signal::raw_sigaction;
    use reverie_inguest::signal::raw_sigprocmask;

    if signal != libc::SIGTRAP || previous.is_null() {
        return Err(libc::EINVAL);
    }
    if GUARD_PRIOR_MASK_HELD.load(Ordering::Acquire) {
        return Err(libc::EALREADY);
    }
    let blocked = 1_u64 << (signal - 1);
    let mut prior_mask = 0_u64;
    unsafe { raw_sigprocmask(libc::SIG_BLOCK, Some(&blocked), Some(&mut prior_mask)) }?;
    let restore = |error: i32| {
        let _ = unsafe { raw_sigprocmask(libc::SIG_SETMASK, Some(&prior_mask), None) };
        Err(error)
    };
    let mut prior = KernelSigaction::default();
    if let Err(error) = unsafe { raw_sigaction(signal, None, Some(&mut prior)) } {
        return restore(error);
    }
    if prior.handler != libc::SIG_DFL as u64 && prior.handler != libc::SIG_IGN as u64 {
        return restore(libc::EPERM);
    }
    let action = KernelSigaction {
        handler: handler as *const () as u64,
        flags: (flags | reverie_inguest::signal::SA_RESTORER) as u64,
        restorer: reverie_inguest::signal::signal_restorer(),
        mask: 0,
    };
    if let Err(error) = unsafe { raw_sigaction(signal, Some(&action), None) } {
        return restore(error);
    }
    GUARD_PRIOR_DEFAULT.store(prior.handler == libc::SIG_DFL as u64, Ordering::Release);
    // The router gives every SIGTRAP that is not one of the runtime's own
    // breakpoints the action it replaced (`prior`, reported below and kept by
    // LiteInst2 as the action it chains to), so that is the guest's own action
    // while the router is installed: a guest's `raise(SIGTRAP)` under SIG_DFL
    // ends the process, and the in-guest host must judge it so.
    reverie_inguest::guest::signal::register_routing_handler(signal, action.handler, prior.handler);
    GUARD_PRIOR_MASK.store(prior_mask, Ordering::Relaxed);
    GUARD_PRIOR_MASK_HELD.store(true, Ordering::Release);
    // SAFETY: the caller passed a non-null output, written once on success.
    unsafe {
        previous.write(GuardSignalAction {
            handler: prior.handler as usize,
            flags: prior.flags,
            restorer: prior.restorer as usize,
            mask: prior.mask,
        })
    };
    Ok(())
}

/// Put back the mask [`install_guard_handler_blocked`] held.
unsafe fn restore_guard_signal_mask(signal: libc::c_int) -> Result<(), i32> {
    if signal != libc::SIGTRAP || !GUARD_PRIOR_MASK_HELD.swap(false, Ordering::AcqRel) {
        return Err(libc::EINVAL);
    }
    let prior_mask = GUARD_PRIOR_MASK.load(Ordering::Relaxed);
    unsafe { reverie_inguest::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&prior_mask), None) }
}

/// From the guard router's signal context: restore the prior default action
/// and send the signal again, with raw syscalls only. It stays pending until
/// the router returns.
unsafe fn restore_guard_default_action(
    signal: libc::c_int,
    previous: &GuardSignalAction,
) -> Result<(), i32> {
    let action = reverie_inguest::signal::KernelSigaction {
        handler: previous.handler as u64,
        flags: previous.flags,
        restorer: previous.restorer as u64,
        mask: previous.mask,
    };
    unsafe { reverie_inguest::signal::raw_sigaction(signal, Some(&action), None) }?;
    unsafe { reverie_inguest::signal::raw_raise(signal) }
}

fn prepare_instrumentation_state() -> io::Result<()> {
    let page_size = reverie_inguest::guest::support::page_size()?;
    PAGE_SIZE.store(page_size, Ordering::Release);

    let sites = (0..MAX_PATCH_SITES)
        .map(|_| SiteSlot::new())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    SITES
        .set(sites)
        .map_err(|_| io::Error::other("LiteInst site registry initialized twice"))?;

    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let objects = parse_runtime_maps(&maps);
    let mut arenas = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(permissions) = fields.next() else {
            continue;
        };
        let mapping_name = fields
            .nth(3)
            .unwrap_or("[anonymous]")
            .rsplit('/')
            .next()
            .unwrap_or("[anonymous]")
            .to_owned()
            .into_boxed_str();
        if !permissions
            .as_bytes()
            .get(2)
            .is_some_and(|byte| *byte == b'x')
        {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let Ok(mapping_start) = u64::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(mapping_end) = u64::from_str_radix(end, 16) else {
            continue;
        };
        if mapping_start >= mapping_end {
            continue;
        }
        let before = read_runtime_maps()?;
        let Ok(arena) = TrampolineArena::allocate_near(mapping_start, ARENA_SLOTS) else {
            continue;
        };
        let after = read_runtime_maps()?;
        // The allocation must add exactly one identity-matched writable and
        // executable alias pair; anything else fails closed.
        discover_arena_aliases(&before, &after)?;
        arenas.push(RuntimeArena {
            mapping_start,
            mapping_end,
            mapping_name,
            arena,
            image: object_image(&objects, mapping_start, mapping_end),
            census: OnceLock::new(),
            adapter_mapping_replaced: AtomicBool::new(false),
        });
    }
    if arenas.is_empty() {
        return Err(io::Error::other(
            "could not allocate a LiteInst arena near any executable mapping",
        ));
    }
    ARENAS
        .set(arenas)
        .map_err(|_| io::Error::other("LiteInst arenas initialized twice"))
}

fn site_hash(address: u64, len: usize) -> usize {
    ((address >> 1).wrapping_mul(0x9E37_79B9_7F4A_7C15) as usize) % len
}

fn find_site(address: u64) -> Option<&'static SiteSlot> {
    let sites = SITES.get()?;
    let start = site_hash(address, sites.len());
    for offset in 0..sites.len() {
        let slot = &sites[(start + offset) % sites.len()];
        match slot.address.load(Ordering::Acquire) {
            observed if observed == address => return Some(slot),
            0 => return None,
            _ => {}
        }
    }
    None
}

fn claim_existing_site(slot: &'static SiteSlot) -> (&'static SiteSlot, bool) {
    loop {
        let state = slot.state.load(Ordering::Acquire);
        if state == 0 {
            core::hint::spin_loop();
            continue;
        }
        if state == SITE_STALE {
            match slot.state.compare_exchange(
                SITE_STALE,
                SITE_INSTALLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return (slot, true),
                Err(_) => continue,
            }
        }
        return (slot, false);
    }
}

fn claim_site(address: u64) -> Option<(&'static SiteSlot, bool)> {
    let sites = SITES.get()?;
    let start = site_hash(address, sites.len());
    for offset in 0..sites.len() {
        let slot = &sites[(start + offset) % sites.len()];
        let observed = slot.address.load(Ordering::Acquire);
        if observed == address {
            return Some(claim_existing_site(slot));
        }
        if observed == 0 {
            match slot
                .address
                .compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    slot.state.store(SITE_INSTALLING, Ordering::Release);
                    return Some((slot, true));
                }
                Err(raced) if raced == address => return Some(claim_existing_site(slot)),
                Err(_) => {}
            }
        }
    }
    None
}

fn mark_site_range_stale(start: u64, len: u64, replacement_end: u64) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    invalidate_adapter_mappings(start, end);
    let Some(sites) = SITES.get() else {
        return;
    };
    for site in sites {
        let address = site.address.load(Ordering::Acquire);
        if start <= address && address < end {
            site.mapping_end.store(replacement_end, Ordering::Release);
            let state = site.state.load(Ordering::Acquire);
            // SITE_UNPATCHABLE and SITE_UNPUBLISHED keep their reservation:
            // existing in-flight activations still return to original code.
            // An unpublished adapter separately loses admission when any of
            // its object's retained census inputs was replaced.
            if matches!(state, SITE_ACTIVE | SITE_FALLBACK) {
                site.state.store(SITE_STALE, Ordering::Release);
            }
        }
    }
}

fn invalidate_adapter_mappings(start: u64, end: u64) {
    if start >= end {
        return;
    }
    if let Some(arenas) = ARENAS.get() {
        for arena in arenas {
            if (start < arena.mapping_end && arena.mapping_start < end)
                || arena
                    .image
                    .as_ref()
                    .is_some_and(|image| image.overlaps(start, end))
            {
                arena
                    .adapter_mapping_replaced
                    .store(true, Ordering::Release);
            }
        }
    }
}

// TODO-HUMAN-REVIEW(PR-127): Review executable mapping-generation tracking.
fn observe_mapping_generation(event: &SyscallEvent) {
    if event.result < 0 {
        return;
    }
    match event.number {
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_mmap => {
            let start = event.result as u64;
            mark_site_range_stale(start, event.args[1], start.saturating_add(event.args[1]));
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_munmap => mark_site_range_stale(event.args[0], event.args[1], 0),
        // AUTONOMOUS-BOT-IMPLEMENTED
        libc::SYS_mremap => {
            mark_site_range_stale(event.args[0], event.args[1], 0);
            let start = event.result as u64;
            mark_site_range_stale(start, event.args[2], start.saturating_add(event.args[2]));
        }
        // A later census must not dereference object metadata whose read
        // access was revoked. Restoring permission does not revive its proof.
        libc::SYS_mprotect if event.args[2] & libc::PROT_READ as u64 == 0 => {
            invalidate_adapter_mappings(event.args[0], event.args[0].saturating_add(event.args[1]));
        }
        // PROT_READ alone does not establish access through a newly assigned
        // protection key. Conservatively discard the retained admission on
        // every successful key assignment, including a return to key zero.
        libc::SYS_pkey_mprotect => {
            invalidate_adapter_mappings(event.args[0], event.args[0].saturating_add(event.args[1]));
        }
        _ => {}
    }
}

pub(crate) fn site_counts(address: u64) -> (u64, u64) {
    find_site(address).map_or((0, 0), |site| {
        (
            site.trap_count.load(Ordering::Acquire),
            site.hook_count.load(Ordering::Acquire),
        )
    })
}

/// Distinct syscall numbers broken out individually by the fallback counters.
///
/// x86-64 syscall numbers currently top out well under this bound; a number at
/// or above it (or negative) is still counted in the process-wide total but is
/// not tracked per-number. Sized to cover the whole current table with headroom.
const TRACKED_SYSCALLS: usize = 512;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-249): Review public fallback-surface observability counters.
/// Total and per-syscall counts for trapped sites without an installed hook
/// (`SITE_FALLBACK` or an unclaimable site), including successful typed Tool
/// dispatch after signal return.
struct FallbackCounters {
    total: AtomicU64,
    by_number: [AtomicU64; TRACKED_SYSCALLS],
}

impl FallbackCounters {
    const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            by_number: [const { AtomicU64::new(0) }; TRACKED_SYSCALLS],
        }
    }

    fn record(&self, number: i64) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if let Ok(index) = usize::try_from(number)
            && index < TRACKED_SYSCALLS
        {
            self.by_number[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    fn by_number(&self, number: i64) -> u64 {
        match usize::try_from(number) {
            Ok(index) if index < TRACKED_SYSCALLS => self.by_number[index].load(Ordering::Relaxed),
            _ => 0,
        }
    }

    fn reset(&self) {
        self.total.store(0, Ordering::Relaxed);
        for slot in &self.by_number {
            slot.store(0, Ordering::Relaxed);
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-249): Review public fallback-surface observability counters.
/// Process-wide counters used by the installed runtime.
static FALLBACK_COUNTERS: FallbackCounters = FallbackCounters::new();
static FALLBACK_REFUSALS: FallbackCounters = FallbackCounters::new();

/// Record that one syscall reached fallback dispatch without an installed hook.
///
/// Typed Tool mode can service these calls after signal return. This is the
/// by-syscall-number analog of the per-site
/// `trap`/`hook` counters ([`site_counts`]) and the direct counterpart of
/// reverie-e9patch's `record_fallback_dispatch` (round 4), keyed the same way so
/// the two ld-preload backends expose a symmetric fallback-surface metric.
///
/// Async-signal-safe: only relaxed atomic increments, so it is safe to call from
/// the `SIGSYS` dispatch path. It does not change the forwarding decision.
pub(crate) fn record_fallback_dispatch(number: i64) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_COUNTERS.record(number);
}

/// Total syscalls that reached fallback dispatch.
///
/// Includes successful typed Tool calls; this counter alone does not identify
/// unsupported syscalls or establish determinism coverage.
pub(crate) fn fallback_dispatch_count() -> u64 {
    FALLBACK_COUNTERS.total()
}

/// Number of times syscall `number` reached the escape surface.
///
/// Returns `0` for a negative number or one at or above [`TRACKED_SYSCALLS`],
/// which are only ever reflected in [`fallback_dispatch_count`].
pub(crate) fn fallback_syscall_count(number: i64) -> u64 {
    FALLBACK_COUNTERS.by_number(number)
}

pub(crate) fn fallback_refusal_count() -> u64 {
    FALLBACK_REFUSALS.total()
}

pub(crate) fn fallback_syscall_refusal_count(number: i64) -> u64 {
    FALLBACK_REFUSALS.by_number(number)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-260): Review the fork-child per-process observability reset.
/// Reset every fallback-surface counter to zero for the current process.
///
/// LiteInst's process-wide [`FALLBACK_COUNTERS`] and each patch site's per-site
/// `trap`/`hook` counts ([`site_counts`]) are inherited by a `fork`/`clone`
/// child copy-on-write, so without a
/// reset the child would report the parent's residual surface and hook activity
/// as its own. This is the same per-process runtime state the shared
/// [`ForkHook`] seam ([`reverie_inguest::fork`]) exists to re-establish in the
/// child — the exact mechanism reverie-e9patch uses for its per-process fallback
/// counters (round 7). Only the *observability* fields are cleared; the site
/// registry's functional patch state (`address`/`state`/`hook`/`mapping_end`) is
/// left intact because the child COW-inherits the installed hooks and the same
/// executable mappings, so its instrumentation must keep working.
///
/// Signature is `fn()` so it can be wrapped in a [`ForkHook`]. Async-signal-safe:
/// only relaxed atomic stores plus one lock-free [`OnceLock::get`], no allocation
/// and no locks, so it is safe to run in the child from inside the `SIGSYS`
/// handler.
fn reset_site_observability(sites: &[SiteSlot]) {
    for site in sites {
        site.trap_count.store(0, Ordering::Relaxed);
        site.hook_count.store(0, Ordering::Relaxed);
    }
}

pub(crate) fn reset_fallback_observability() {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_COUNTERS.reset();
    FALLBACK_REFUSALS.reset();
    if let Some(sites) = SITES.get() {
        reset_site_observability(sites);
    }
}

pub(crate) fn submit_process_stats(
    tid: reverie::Tid,
    stats: crate::stats::GuestStatsHooks,
) -> io::Result<()> {
    let mut direct_hooks = 0_u64;
    let sites = SITES
        .get()
        .into_iter()
        .flatten()
        .filter_map(|site| {
            let trap_hits = site.trap_count.load(Ordering::Relaxed);
            let hook_hits = site.hook_count.load(Ordering::Relaxed);
            direct_hooks += hook_hits;
            (trap_hits != 0 || hook_hits != 0).then(|| crate::stats::LiteinstProcessSiteStats {
                rip: site.address.load(Ordering::Relaxed),
                patched: site.state.load(Ordering::Relaxed) == SITE_ACTIVE,
                instruction_length: site.instruction_len.load(Ordering::Relaxed),
                straddle_after: site.straddle_prefix.load(Ordering::Relaxed),
            })
        })
        .collect();
    stats.submit(tid, direct_hooks, sites)
}

pub(crate) fn record_fork_child_dispatch(
    event: &SyscallEvent,
    stats: crate::stats::GuestStatsHooks,
) {
    match event.dispatch {
        SyscallDispatch::InstalledHook => {
            // Only offset an entry the site's hook count actually re-counted.
            if let Some(site) = find_site(event.instruction_pointer) {
                site.hook_count.fetch_add(1, Ordering::Relaxed);
                stats.record_inherited_entry(crate::stats::InheritedEntry::Hook);
            }
        }
        SyscallDispatch::Fallback => {
            if let Some(site) = find_site(event.instruction_pointer) {
                site.trap_count.fetch_add(1, Ordering::Relaxed);
            }
            record_fallback_dispatch(event.number);
            stats.record_path(crate::LiteinstDispatchPath::InGuestSigsys);
            stats.record_inherited_entry(crate::stats::InheritedEntry::Sigsys);
            if stats.is_enabled() {
                record_enabled_fallback_stats(stats, event.instruction_pointer);
            }
        }
        SyscallDispatch::Trap => {}
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-260): Review the shared fork-following seam reuse.
/// The shared fork-following hook: in the child of a successful fork-like
/// syscall, reset this process's fallback observability (see
/// [`reset_fallback_observability`]).
///
/// LiteInst hosts its own `SIGSYS` dispatcher rather than the shared
/// [`PassthroughDispatcher`](reverie_inguest::dispatch::PassthroughDispatcher),
/// so it invokes this hook itself from [`process_syscall`] after forwarding a
/// fork-like syscall — but it reuses the *same* reviewed-once
/// [`ForkHook`]/[`is_fork_like`] seam e9patch does, rather than a private
/// fork-detection path.
static FORK_HOOK: ForkHook = ForkHook::new(reset_fallback_observability);

fn arena_for(address: u64) -> Option<&'static RuntimeArena> {
    ARENAS.get()?.iter().find(|entry| {
        entry.mapping_start <= address
            && address < entry.mapping_end
            && entry.arena.can_reach(address)
    })
}

unsafe fn set_text_protection(address: u64, protection: i32) -> io::Result<()> {
    let page_size = PAGE_SIZE.load(Ordering::Acquire);
    if page_size == 0 {
        return Err(io::Error::other("LiteInst page size is not initialized"));
    }
    let page_start = address & !(page_size - 1);
    let patch_end = address
        .checked_add(liteinst2::patcher::WORD_PATCH_BYTES as u64)
        .ok_or_else(|| io::Error::other("patch address overflow"))?;
    let page_end = patch_end
        .checked_add(page_size - 1)
        .map(|value| value & !(page_size - 1))
        .ok_or_else(|| io::Error::other("patch page range overflow"))?;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_mprotect,
            [
                page_start,
                page_end - page_start,
                protection as u64,
                0,
                0,
                0,
            ],
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error((-result) as i32));
    }
    Ok(())
}

unsafe fn set_mapping_protection(start: u64, len: u64, protection: i32) -> io::Result<()> {
    let result =
        unsafe { raw_syscall6(libc::SYS_mprotect, [start, len, protection as u64, 0, 0, 0]) };
    if result < 0 {
        return Err(io::Error::from_raw_os_error((-result) as i32));
    }
    Ok(())
}

struct InstallGuard;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum PatchPublication {
    /// No other application thread can fetch the site during publication.
    Quiescent,
    /// Other application threads may fetch the site during publication.
    Concurrent,
}

fn patch_publication() -> PatchPublication {
    if PATCH_PUBLICATION.load(Ordering::Acquire) == PatchPublication::Quiescent as u8 {
        PatchPublication::Quiescent
    } else {
        PatchPublication::Concurrent
    }
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        INSTALL_HELD.store(false, Ordering::Release);
    }
}

fn lock_installation() -> io::Result<InstallGuard> {
    INSTALL_HELD
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map(|_| InstallGuard)
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "LiteInst installation is busy"))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review the untouched-code boundary.
/// Why [`install_site_hook`] installed no hook.
struct InstallFailure {
    error: io::Error,
    /// True only for a refusal that proves the site's code is the original:
    /// reached under the installation lock, after the expected bytes were
    /// re-read and [`check_neighbours`] found no published patch over the
    /// instruction or the point after it, and before the runtime changed any
    /// page protection or wrote any byte. A busy lock, a missing arena, a
    /// byte mismatch (another thread may have just published a jump there),
    /// and every failure from the protection change onward count as touched,
    /// even where nothing may have been written.
    code_untouched: bool,
}

impl InstallFailure {
    fn untouched(error: io::Error) -> Self {
        Self {
            error,
            code_untouched: true,
        }
    }

    fn touched(error: io::Error) -> Self {
        Self {
            error,
            code_untouched: false,
        }
    }
}

impl From<InstallFailure> for io::Error {
    fn from(failure: InstallFailure) -> Self {
        failure.error
    }
}

/// How a proposed patch relates to one other claimed site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NeighbourConflict {
    /// The proposed site's instruction, or the point after it, lies inside
    /// the other site's published (or possibly partly published) jump, so
    /// its bytes are not known to be the original.
    InsidePublishedPatch,
    /// The proposed patch would overwrite the start of another site's jump.
    OverlapsPublishedPatch,
    /// The proposed patch would cover a site that a thread may be executing
    /// through the continuation (or is deciding about), which resumes after
    /// that instruction.
    CoversContinuationSite,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review the neighbour-overlap rules.
/// Classify a proposed word patch at `address`, whose instruction is
/// `instruction_len` bytes long, against another site at `other` in `state`.
/// `other_len` is that site's instruction length, or 0 when not yet recorded
/// (then the longest emulated instruction, 3 bytes, is assumed). `footprint`
/// says the other site's eight-byte window may hold bytes this runtime
/// published ([`site_footprint`]); a site INSTALLING, UNPATCHABLE, STALE or
/// FALLBACK also reserves its instruction and resume point for the
/// continuation.
fn neighbour_conflict(
    address: u64,
    instruction_len: u64,
    other: u64,
    state: u8,
    other_len: u64,
    footprint: bool,
) -> Option<NeighbourConflict> {
    if other == 0 || other == address {
        return None;
    }
    let word = liteinst2::patcher::WORD_PATCH_BYTES as u64;
    let patch_end = address.saturating_add(word);
    let mut conflict = None;
    if footprint {
        let other_end = other.saturating_add(word);
        if other < address.saturating_add(instruction_len) && other_end > address {
            return Some(NeighbourConflict::InsidePublishedPatch);
        }
        if other < patch_end && other_end > address {
            conflict = Some(NeighbourConflict::OverlapsPublishedPatch);
        }
    }
    // FALLBACK and STALE sites keep the reservation too: a FALLBACK syscall
    // refused before any publication leaves no footprint but is executed
    // through the SIGSYS continuation, and a STALE site was ACTIVE or
    // FALLBACK.
    if matches!(
        state,
        SITE_INSTALLING | SITE_UNPATCHABLE | SITE_STALE | SITE_FALLBACK | SITE_UNPUBLISHED
    ) {
        let other_len = if other_len == 0 { 3 } else { other_len };
        // Starting exactly at the other site's resume point is safe.
        if address < other.saturating_add(other_len) && patch_end > other {
            conflict.get_or_insert(NeighbourConflict::CoversContinuationSite);
        }
    }
    conflict
}

/// The conflict that decides a proposed patch against every other site in
/// `sites` (address, state, recorded instruction length, footprint). Every site is
/// examined: [`NeighbourConflict::InsidePublishedPatch`] dominates, because a
/// refusal is untouched only if no published jump covers the site, whatever
/// order the site table yields its entries in.
fn neighbours_conflict(
    address: u64,
    instruction_len: u64,
    sites: impl IntoIterator<Item = (u64, u8, u64, bool)>,
) -> Option<NeighbourConflict> {
    let mut found = None;
    for (other, state, other_len, footprint) in sites {
        match neighbour_conflict(address, instruction_len, other, state, other_len, footprint) {
            Some(NeighbourConflict::InsidePublishedPatch) => {
                return Some(NeighbourConflict::InsidePublishedPatch);
            }
            Some(conflict) => {
                found.get_or_insert(conflict);
            }
            None => {}
        }
    }
    found
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review the stale-jump survival rule.
/// Whether any byte this runtime wrote at a site may still be there.
/// `words` is the site's (original, published) eight-byte pair, `None` when
/// none was recorded (a failed or partial publication); `current` is the
/// site's eight bytes now, `None` unless all eight were readable. A byte
/// survives when it differs from the original and equals the published byte,
/// or when it is an INT3 that was not in the original (a cross-line guard:
/// liteinst2 guards every front-fragment byte, changed or not). Only when
/// no byte survives is the old patch provably gone, whatever part of its
/// window a mapping change replaced.
fn stale_jump_survives(words: Option<(u64, u64)>, current: Option<[u8; 8]>) -> bool {
    let (Some((original, published)), Some(current)) = (words, current) else {
        return true;
    };
    let (original, published) = (original.to_le_bytes(), published.to_le_bytes());
    (0..8).any(|offset| {
        let byte = current[offset];
        (published[offset] != original[offset] && byte == published[offset])
            || (byte == liteinst2::patcher::BREAKPOINT_OPCODE
                && original[offset] != liteinst2::patcher::BREAKPOINT_OPCODE)
    })
}

/// Whether bytes from an earlier publication at a site may still be there,
/// whatever the site's state (a STALE site reclaimed for reinstallation is
/// INSTALLING, and its old jump may survive a partial mapping change). False
/// only if no publication was ever attempted, or the latest one completed and
/// [`stale_jump_survives`] proves every byte it wrote is gone; an attempt that
/// did not complete leaves no record and so counts as surviving.
fn earlier_patch_survives(
    publication_attempted: bool,
    words: Option<(u64, u64)>,
    current: Option<[u8; 8]>,
) -> bool {
    publication_attempted && stale_jump_survives(words, current)
}

/// Whether a site's eight-byte window may hold bytes this runtime published:
/// always for ACTIVE, otherwise when [`earlier_patch_survives`]. A FALLBACK
/// whose publication failed after the protection change has no completed
/// record and so survives; one refused before any change (a syscall the
/// census or the cross-line budget refused) wrote nothing and keeps only
/// its continuation reservation.
fn site_footprint(state: u8, survives: bool) -> bool {
    state == SITE_ACTIVE || survives
}

/// [`earlier_patch_survives`] for `slot` at `address`, reading the window
/// without risking a fault: part or all of its mapping may be gone.
fn slot_patch_survives(slot: &SiteSlot, address: u64) -> bool {
    if !slot.publication_attempted.load(Ordering::Acquire) {
        return false;
    }
    let words = slot.words_recorded.load(Ordering::Acquire).then(|| {
        (
            slot.original_word.load(Ordering::Acquire),
            slot.published_word.load(Ordering::Acquire),
        )
    });
    let mut bytes = [0_u8; 8];
    let current = (unsafe { read_own_bytes(address, &mut bytes) } == bytes.len()).then_some(bytes);
    earlier_patch_survives(true, words, current)
}

/// Refuse a patch at `address` that conflicts with another claimed site.
/// Called with the installation lock held, so no other patch is being
/// published concurrently, and before any protection change or write.
fn check_neighbours(address: u64, instruction_len: u64) -> Result<(), InstallFailure> {
    let Some(sites) = SITES.get() else {
        return Ok(());
    };
    let conflict = neighbours_conflict(
        address,
        instruction_len,
        sites.iter().map(|slot| {
            let other = slot.address.load(Ordering::Acquire);
            let state = slot.state.load(Ordering::Acquire);
            let survives = other != 0
                && other != address
                && state != SITE_ACTIVE
                && slot_patch_survives(slot, other);
            (
                other,
                state,
                u64::from(slot.instruction_len.load(Ordering::Acquire)),
                site_footprint(state, survives),
            )
        }),
    );
    match conflict {
        None => Ok(()),
        Some(NeighbourConflict::InsidePublishedPatch) => Err(InstallFailure::touched(
            io::Error::other("site lies inside another site's published LiteInst patch"),
        )),
        Some(NeighbourConflict::OverlapsPublishedPatch) => Err(InstallFailure::untouched(
            io::Error::other("LiteInst patch would overlap another site's patch"),
        )),
        Some(NeighbourConflict::CoversContinuationSite) => Err(InstallFailure::untouched(
            io::Error::other("LiteInst patch would cover a site executed through the continuation"),
        )),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review blocking asynchronous signals across installation.
/// Blocks every blockable signal for its lifetime and then restores the
/// thread's exact previous mask. Installation runs in signal context, and in
/// the raw strace and compatibility modes the guest may own handlers, for
/// any signal number (a guest timer can deliver SIGILL as easily as SIGUSR1);
/// a handler running between the eligibility checks (bytes, footprints,
/// private mapping) and the completed publication could, for example,
/// replace the checked private mapping with a shared one, so that the
/// publication changed shared code. The fault signals are blocked too: a
/// fault that installation itself raises (the scanner or the entry census
/// reading guest memory that a guest made unreadable) then ends the process,
/// as the kernel does for a blocked synchronous fault, instead of running a
/// guest handler in the middle of an installation. The instruction-fault
/// path already installs with SIGSEGV blocked.
struct AsyncSignalsBlocked {
    previous: u64,
}

impl AsyncSignalsBlocked {
    fn new() -> io::Result<Self> {
        let bit = |signal: libc::c_int| 1_u64 << (signal - 1);
        // SIGKILL and SIGSTOP cannot be blocked; leave them out explicitly.
        let keep = bit(libc::SIGKILL) | bit(libc::SIGSTOP);
        let block = !keep;
        let mut previous = 0_u64;
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_BLOCK as u64,
                    (&raw const block) as u64,
                    (&raw mut previous) as u64,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error((-result) as i32));
        }
        Ok(Self { previous })
    }
}

impl Drop for AsyncSignalsBlocked {
    fn drop(&mut self) {
        let _ = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const self.previous) as u64,
                    0,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
    }
}

fn unpublished_read_write_allowed(number: i64) -> bool {
    TOOL_MODE.load(Ordering::Acquire) == TOOL_STRACE
        && GUARD_PRIOR_DEFAULT.load(Ordering::Acquire)
        && matches!(number, libc::SYS_read | libc::SYS_write)
}

/// The caller holds the installation lock and blocks asynchronous signals.
/// All ordinary source admission has passed except the missing split-word
/// calibration. Preserve the later bind validator too, without binding a
/// source patch or changing its protection.
fn install_unpublished_syscall(
    address: u64,
    slot: &'static SiteSlot,
    arena: &'static RuntimeArena,
    scanner: &InstructionScanner,
    scan: &ScanResult,
) -> Result<(), InstallFailure> {
    let failure =
        |error: TrampolineError| InstallFailure::untouched(io::Error::other(error.to_string()));
    let reference =
        TrampolinePlan::from_scan_replacing_first(scan, address, unpublished_syscall_hook)
            .map_err(failure)?;
    let plan =
        TrampolinePlan::from_scan_replacing_exact_syscall(scan, address, unpublished_syscall_hook)
            .map_err(failure)?;
    let trampoline = arena.arena.allocate(&plan).map_err(failure)?;
    let patch = JumpPatchPlan::from_scan(
        scanner,
        scan,
        scan.snapshot(),
        address,
        address,
        trampoline.address(),
    )
    .map_err(|error| failure(error.into()))?;
    if patch.displaced_len() != reference.displaced_len() {
        return Err(failure(PatchError::RegionMismatch { address }.into()));
    }
    let adapter = Box::new(UnpublishedSyscall {
        trampoline,
        source: scan.snapshot().into(),
    });
    adapter.trampoline.publish_program_counter_mappings();
    slot.adapter
        .store(Box::into_raw(adapter), Ordering::Release);
    slot.state.store(SITE_UNPUBLISHED, Ordering::Release);
    Ok(())
}

/// Revalidate each genuine trap, including a polymorphic site's number. No
/// copied tail is executed: the retained bytes authenticate current admission
/// only, and a later guest handler's tail changes are seen at original + 2.
fn unpublished_syscall_entry(address: u64, slot: &SiteSlot, number: i64) -> Option<u64> {
    if !unpublished_read_write_allowed(number) {
        return None;
    }
    let _signals_blocked = AsyncSignalsBlocked::new().ok()?;
    let _install_guard = lock_installation().ok()?;
    if slot.state.load(Ordering::Acquire) != SITE_UNPUBLISHED {
        return None;
    }
    let arena = arena_for(address)?;
    if arena.adapter_mapping_replaced.load(Ordering::Acquire)
        || slot_patch_survives(slot, address)
        || check_neighbours(address, 2).is_err()
    {
        return None;
    }
    let pointer = slot.adapter.load(Ordering::Acquire);
    // SAFETY: the release-published adapter and its arena are never reclaimed.
    let adapter = unsafe { pointer.as_ref() }?;
    let len = adapter.source.len();
    if len == 0 || len > PATCH_SNAPSHOT_BYTES {
        return None;
    }
    let last = address.checked_add(len as u64 - 1)?;
    // SAFETY: maps are read through the bounded runtime reader, not through
    // a possibly unmapped code pointer.
    let protection = unsafe { private_span_protection(address, last) }?;
    if protection & libc::PROT_EXEC == 0 {
        return None;
    }
    for (index, expected) in adapter.source.chunks(8).enumerate() {
        let mut current = [0_u8; 8];
        let chunk_address = address.checked_add((index * 8) as u64)?;
        // SAFETY: read_own_bytes reports a failed/partial read without a guest
        // fault. The last chunk need only cover the saved source prefix.
        if unsafe { read_own_bytes(chunk_address, &mut current) } < expected.len()
            || current[..expected.len()] != *expected
        {
            return None;
        }
    }
    Some(adapter.trampoline.address())
}

unsafe fn install_site_hook(
    address: u64,
    slot: &'static SiteSlot,
    callback: liteinst2::trampoline::HookCallback,
    policy: SiteHookPolicy,
    expected_instruction: &[u8],
    manage_protection: bool,
) -> Result<(), InstallFailure> {
    // No guest code may run from the first check below to the completed
    // publication, whatever signal arrives; see AsyncSignalsBlocked.
    let _signals_blocked = AsyncSignalsBlocked::new().map_err(InstallFailure::touched)?;
    // Nothing below proves the site's bytes are the original until they are
    // re-read under the lock, so the busy and no-arena refusals are touched.
    let _install_guard = lock_installation().map_err(InstallFailure::touched)?;
    let _allocation_scope = crate::patch_alloc::enter();
    let arena = arena_for(address)
        .ok_or_else(|| io::Error::other("no reachable LiteInst arena for syscall site"))
        .map_err(InstallFailure::touched)?;
    if policy.unpublished_read_write && arena.adapter_mapping_replaced.load(Ordering::Acquire) {
        // The original bytes and any older publication are not yet checked.
        return Err(InstallFailure::touched(io::Error::other(
            "unpublished syscall admission lost its original object mapping",
        )));
    }
    let mut mapping_end = slot.mapping_end.load(Ordering::Acquire);
    if mapping_end <= address {
        mapping_end = arena.mapping_end;
        slot.mapping_end.store(mapping_end, Ordering::Release);
    }
    let available = usize::try_from(mapping_end - address)
        .unwrap_or(0)
        .min(PATCH_SNAPSHOT_BYTES);
    // SAFETY: arena_for proved this byte range lies in a live executable VMA.
    let candidate =
        unsafe { core::slice::from_raw_parts(address as usize as *const u8, available) };
    if candidate.get(..expected_instruction.len()) != Some(expected_instruction) {
        // The bytes changed since the fault decoded them: another thread may
        // have published a jump over this site.
        return Err(InstallFailure::touched(io::Error::other(
            "fault site does not contain the expected x86-64 instruction",
        )));
    }
    slot.instruction_len
        .store(expected_instruction.len() as u8, Ordering::Release);
    // A reclaimed site's own earlier jump may survive past the bytes just
    // checked (a partial mapping change can restore only its first bytes).
    if slot_patch_survives(slot, address) {
        return Err(InstallFailure::touched(io::Error::other(
            "an earlier LiteInst patch at this site may survive",
        )));
    }
    check_neighbours(address, expected_instruction.len() as u64)?;
    if available < liteinst2::patcher::WORD_PATCH_BYTES {
        return Err(InstallFailure::untouched(io::Error::other(
            "syscall site is too close to its executable mapping end",
        )));
    }
    // Publish only into private mappings, where the write copies the page
    // for this process alone. A write through a shared mapping would change
    // the page cache that every other process and every alias of the same
    // backing executes, including clean private aliases, behind their site
    // tables. Never writing there keeps every continuation's bytes free of
    // LiteInst jumps that this process's footprints cannot see.
    let window_last = address + liteinst2::patcher::WORD_PATCH_BYTES as u64 - 1;
    if unsafe { private_span_protection(address, window_last) }.is_none() {
        return Err(InstallFailure::untouched(io::Error::other(
            "LiteInst publishes only into a private executable mapping",
        )));
    }
    let scanner = InstructionScanner::default();
    let scan = scanner
        .scan_prefix(candidate, address, liteinst2::patcher::WORD_PATCH_BYTES)
        .map_err(|error| InstallFailure::untouched(io::Error::other(error.to_string())))?;
    let proof = match policy.entry_proof {
        EntryProof::Required => arena
            .census()
            .and_then(|census| prove(census, address, scan.instructions())),
        EntryProof::NotListed => Ok(()),
    };
    proof.map_err(|refusal| InstallFailure::untouched(io::Error::other(refusal.to_string())))?;
    let instruction_len = scan
        .instructions()
        .first()
        .expect("a successful prefix scan contains an instruction")
        .len();
    let straddle_prefix = scanner
        .cache_line_size()
        .split_offset(
            address as usize,
            instruction_len.min(liteinst2::patcher::NEAR_JUMP_BYTES),
        )
        .unwrap_or(0);

    slot.instruction_len
        .store(instruction_len as u8, Ordering::Release);
    slot.straddle_prefix
        .store(straddle_prefix as u8, Ordering::Release);
    let staleness = match policy.publication {
        PatchPublication::Quiescent => None,
        PatchPublication::Concurrent => {
            match crate::straddler::budget_for_patch(address as usize, scanner.cache_line_size()) {
                Ok(budget) => Some(budget),
                Err(crate::straddler::BudgetRefusal::UncalibratedSplit)
                    if policy.unpublished_read_write =>
                {
                    return install_unpublished_syscall(address, slot, arena, &scanner, &scan);
                }
                Err(refusal) => return Err(InstallFailure::untouched(refusal.into())),
            }
        }
    };
    let code = scan.snapshot();
    // `available` is at least WORD_PATCH_BYTES here, and the bytes were just
    // verified, so these are the site's original eight bytes.
    let original_word = u64::from_le_bytes(
        candidate[..liteinst2::patcher::WORD_PATCH_BYTES]
            .try_into()
            .expect("the patch window is eight bytes"),
    );
    // Any earlier patch here was just proved gone. From now until this
    // publication completes, the site counts as possibly published.
    slot.publication_attempted.store(true, Ordering::Release);
    slot.words_recorded.store(false, Ordering::Release);

    // Every failure from here on may follow a protection change or a write to
    // the guest's code. Record SITE_FALLBACK while the lock is still held, so
    // no later installer's neighbour check sees this site as merely
    // INSTALLING when part of a jump may already be published.
    let published_failure = |error: io::Error| {
        slot.state.store(SITE_FALLBACK, Ordering::Release);
        InstallFailure::touched(error)
    };
    if manage_protection {
        unsafe {
            set_text_protection(
                address,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            )
            .map_err(published_failure)?;
        }
    }
    // A guarded cross-line plan rejects a trampoline displacement containing
    // the temporary INT3 byte at another instruction head. Arena slots have
    // distinct rel32 displacements, so retry a bounded number of fresh slots;
    // this changes no guest bytes and preserves the same patch mechanism.
    let mut attempts = 0;
    let installed = loop {
        attempts += 1;
        let site = HookSite::new(
            &scanner,
            &scan,
            code,
            address,
            address,
            address as usize as *mut u8,
        );
        let candidate = match policy.publication {
            PatchPublication::Quiescent => unsafe {
                InstalledHook::install_replacing_first_in_arena_quiescent(
                    site,
                    callback,
                    &arena.arena,
                )
            },
            PatchPublication::Concurrent => unsafe {
                InstalledHook::install_replacing_first_in_arena(
                    site,
                    callback,
                    staleness.expect("concurrent publication has a staleness budget"),
                    &arena.arena,
                )
            },
        };
        match candidate {
            Ok(installed) => break Ok(installed),
            Err(TrampolineError::Patch(PatchError::GuardByteConflict { .. })) if attempts < 16 => {
                continue;
            }
            Err(error) => break Err(error),
        }
    };
    let installed = match installed {
        Ok(installed) => installed,
        Err(error) => {
            if manage_protection {
                let _ = unsafe { set_text_protection(address, libc::PROT_READ | libc::PROT_EXEC) };
            }
            return Err(published_failure(io::Error::other(error.to_string())));
        }
    };
    let activation = match policy.publication {
        PatchPublication::Concurrent => installed.activate(),
        // SAFETY: quiescent publication is selected only at initialization,
        // before application threads start, or by `install_tool_quiescent`,
        // whose caller (Hermit, which schedules one guest thread at a time)
        // asserts that no other thread can fetch the site.
        PatchPublication::Quiescent => unsafe { installed.activate_quiescent() },
    };
    if let Err(error) = activation {
        if manage_protection {
            let _ = unsafe { set_text_protection(address, libc::PROT_READ | libc::PROT_EXEC) };
        }
        return Err(published_failure(io::Error::other(error.to_string())));
    }
    if manage_protection {
        unsafe {
            set_text_protection(address, libc::PROT_READ | libc::PROT_EXEC)
                .map_err(published_failure)?;
        }
    }

    // SAFETY: the window lies in this live executable mapping, which the
    // installation lock keeps from being patched concurrently.
    let published_word = unsafe { core::ptr::read_unaligned(address as usize as *const u64) };
    slot.original_word.store(original_word, Ordering::Release);
    slot.published_word.store(published_word, Ordering::Release);
    slot.words_recorded.store(true, Ordering::Release);
    let installed = Box::into_raw(Box::new(installed));
    slot.hook.store(installed, Ordering::Release);
    slot.instruction_len
        .store(instruction_len as u8, Ordering::Release);
    slot.straddle_prefix
        .store(straddle_prefix as u8, Ordering::Release);
    slot.state.store(SITE_ACTIVE, Ordering::Release);
    Ok(())
}

fn install_vdso_sites(sites: &[reverie_ptrace::VdsoSyscallSite]) -> io::Result<()> {
    for site_info in sites {
        let address = site_info.address;
        let (site, claimed) = claim_site(address)
            .ok_or_else(|| io::Error::other("LiteInst vDSO site table is full"))?;
        if !claimed {
            return Err(io::Error::other("LiteInst vDSO site was claimed twice"));
        }
        unsafe {
            set_mapping_protection(
                site_info.mapping_start,
                site_info.mapping_len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            )?;
            install_site_hook(
                address,
                site,
                vdso_callback(site_info.number)?,
                SiteHookPolicy {
                    publication: PatchPublication::Quiescent,
                    entry_proof: EntryProof::NotListed,
                    unpublished_read_write: false,
                },
                &[0x0f, 0x05],
                false,
            )
        }
        .map_err(|failure| {
            site.state.store(SITE_FALLBACK, Ordering::Release);
            io::Error::other(format!(
                "failed to install LiteInst vDSO hook: {}",
                failure.error
            ))
        })?;
        unsafe {
            set_mapping_protection(
                site_info.mapping_start,
                site_info.mapping_len,
                libc::PROT_READ | libc::PROT_EXEC,
            )?;
        }
    }
    Ok(())
}

fn vdso_callback(number: i64) -> io::Result<liteinst2::trampoline::HookCallback> {
    let callbacks = installed_entries::selected();
    match number {
        libc::SYS_time => Ok(callbacks.time),
        libc::SYS_clock_gettime => Ok(callbacks.clock_gettime),
        libc::SYS_getcpu => Ok(callbacks.getcpu),
        libc::SYS_gettimeofday => Ok(callbacks.gettimeofday),
        libc::SYS_clock_getres => Ok(callbacks.clock_getres),
        libc::SYS_getrandom => Ok(callbacks.getrandom),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported LiteInst vDSO syscall number {number}"),
        )),
    }
}

fn instruction_at(address: u64) -> Option<(InstructionEventKind, &'static [u8])> {
    let arena = arena_for(address)?;
    let available = usize::try_from(arena.mapping_end.checked_sub(address)?)
        .ok()?
        .min(3);
    if available < 2 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(address as usize as *const u8, available) };
    decode_instruction(bytes)
}

fn instruction_callback(kind: InstructionEventKind) -> liteinst2::trampoline::HookCallback {
    let callbacks = installed_entries::selected();
    match kind {
        InstructionEventKind::Cpuid => callbacks.cpuid,
        InstructionEventKind::Rdtsc => callbacks.rdtsc,
        InstructionEventKind::Rdtscp => callbacks.rdtscp,
    }
}

// LiteInst's half of the shared instruction fault handler
// (reverie_inguest::guest::instruction): where the fault lies relative to the
// arenas recorded at startup.
unsafe fn locate_instruction_fault(
    address: u64,
    info: *const libc::siginfo_t,
    context: *const libc::ucontext_t,
) -> FaultSite {
    // With site patching off, no instruction site is patched either: every
    // CPUID, RDTSC and RDTSCP is emulated through the continuation, as for
    // code without an arena.
    if !SITE_PATCHING_ENABLED.load(Ordering::Relaxed) {
        return FaultSite::Unpatchable;
    }
    if let Some((kind, encoding)) = instruction_at(address) {
        return FaultSite::Patchable { kind, encoding };
    }
    if let Some(arena) = arena_for(address) {
        let context = unsafe { &*context };
        let available = usize::try_from(arena.mapping_end.saturating_sub(address))
            .unwrap_or(0)
            .min(8);
        let bytes =
            unsafe { core::slice::from_raw_parts(address as usize as *const u8, available) };
        let fault_address = if info.is_null() {
            0
        } else {
            unsafe { (*info).si_addr() as usize as u64 }
        };
        emit_instruction_refusal_stage(
            b"instruction-sigsegv-unrecognized-bytes",
            address.saturating_sub(arena.mapping_start),
            fault_address,
            context.uc_mcontext.gregs[libc::REG_RSP as usize] as u64,
            arena.mapping_name.as_bytes(),
            arena.mapping_end.saturating_sub(arena.mapping_start),
            bytes,
        );
        return FaultSite::Refused;
    }
    // Code mapped after the runtime started (a dlopen'd library's
    // constructor, JIT output) has no arena and can never be patched.
    FaultSite::Unpatchable
}

// The other half of LiteInst's seam: patch a subscribed instruction's site so
// it and every later execution jump to its hook. Runs in the SIGSEGV handler,
// outside any Tool callback.
unsafe fn patch_instruction_fault(
    address: u64,
    kind: InstructionEventKind,
    encoding: &'static [u8],
) -> PatchOutcome {
    let Some((site, claimed)) = claim_site(address) else {
        emit_in_guest_stage(b"instruction-sigsegv-site-table-full");
        return PatchOutcome::Emulate;
    };
    site.trap_count.fetch_add(1, Ordering::Relaxed);
    if unsafe { set_all_instruction_native(true) }.is_err() {
        emit_in_guest_stage(b"instruction-sigsegv-enable-native-failed");
        unsafe { deliver_default_sigsegv() };
    }
    if claimed
        && let Err(failure) = unsafe {
            install_site_hook(
                address,
                site,
                instruction_callback(kind),
                SiteHookPolicy {
                    publication: patch_publication(),
                    entry_proof: EntryProof::NotListed,
                    unpublished_read_write: false,
                },
                encoding,
                true,
            )
        }
    {
        let unpatchable = failure.code_untouched;
        site.state.store(
            if unpatchable {
                SITE_UNPATCHABLE
            } else {
                SITE_FALLBACK
            },
            Ordering::Release,
        );
    }
    if unsafe { set_all_instruction_native(false) }.is_err() {
        emit_in_guest_stage(b"instruction-sigsegv-disable-native-failed");
        unsafe { deliver_default_sigsegv() };
    }
    while matches!(site.state.load(Ordering::Acquire), 0 | SITE_INSTALLING) {
        core::hint::spin_loop();
    }
    match site.state.load(Ordering::Acquire) {
        SITE_ACTIVE => {}
        // The hook was refused before anything at the site changed (for
        // example, a word patch that would cross a cache line while
        // cross-line publication is disabled), so the instruction and the
        // code after it are the original bytes. Emulate it through the
        // continuation, as for code without an arena; every later execution
        // of this site traps and takes the same path.
        SITE_UNPATCHABLE => return PatchOutcome::Emulate,
        _ => {
            // A failed installation may already have published part or all
            // of the jump (for example, when restoring the page's
            // permissions fails after the patch is written), so the bytes
            // after this instruction are no longer known to be the original
            // code. Resuming past the instruction could execute the jump's
            // displacement; end the guest.
            emit_in_guest_stage(b"instruction-sigsegv-site-install-failed");
            return PatchOutcome::Failed;
        }
    }
    let hook = site.hook.load(Ordering::Acquire);
    if hook.is_null() {
        emit_in_guest_stage(b"instruction-sigsegv-hook-missing");
        return PatchOutcome::Failed;
    }
    PatchOutcome::Resume(unsafe { (*hook).trampoline().address() })
}

static INSTRUCTION_FAULT_SEAM: InstructionFaultSeam = InstructionFaultSeam {
    locate: locate_instruction_fault,
    patch: patch_instruction_fault,
};

unsafe fn installed_instruction_hook(context: *mut HookContext, kind: InstructionEventKind) {
    if let Some(context) = unsafe { context.as_ref() }
        && let Some(site) = find_site(context.instruction_pointer)
    {
        record_hook_entry(site);
    }
    unsafe { dispatch_instruction_context(context, kind) };
}

/// Run the Tool's callback for a CPUID/RDTSC/RDTSCP whose fault had no
/// patchable site, from the owned fallback continuation in ordinary context.
/// It is the installed hook's dispatch without a site hook entry to count;
/// the continuation advances RIP past the instruction on completion.
pub(crate) unsafe fn dispatch_fallback_instruction(
    context: *mut HookContext,
    kind: InstructionEventKind,
) {
    unsafe { dispatch_instruction_context(context, kind) };
}

unsafe fn dispatch_instruction_context(context: *mut HookContext, kind: InstructionEventKind) {
    if context.is_null() || enter_rcb_handler().is_err() {
        unsafe { exit_now(122) };
    }
    let context = unsafe { &mut *context };
    if unsafe { set_instruction_native(kind, true) }.is_err() {
        unsafe { exit_now(122) };
    }
    // A previously patched instruction still jumps here while native faulting
    // is enabled. Re-entering the Tool would deadlock on its already-held lock,
    // so execute the instruction at a private, never-patched site instead.
    if tool_callback_active() {
        emit_in_guest_stage(match kind {
            InstructionEventKind::Cpuid => b"nested-instruction-native-cpuid",
            InstructionEventKind::Rdtsc => b"nested-instruction-native-rdtsc",
            InstructionEventKind::Rdtscp => b"nested-instruction-native-rdtscp",
        });
        // HookContext and RegisterContext have the same layout (checked in
        // tool_host.rs).
        unsafe {
            execute_native_instruction(kind, &mut *ptr::from_mut(context).cast::<RegisterContext>())
        };
        if unsafe { set_instruction_native(kind, false) }.is_err() || leave_rcb_handler().is_err() {
            unsafe { exit_now(122) };
        }
        return;
    }
    {
        let _tool_callback = ToolCallbackGuard::enter();
        crate::tool_host::dispatch_instruction(kind, context);
    }
    if unsafe { set_instruction_native(kind, false) }.is_err() || leave_rcb_handler().is_err() {
        unsafe { exit_now(122) };
    }
}

unsafe extern "C" fn installed_cpuid_hook(context: *mut HookContext) {
    unsafe { installed_instruction_hook(context, InstructionEventKind::Cpuid) }
}

unsafe extern "C" fn installed_rdtsc_hook(context: *mut HookContext) {
    unsafe { installed_instruction_hook(context, InstructionEventKind::Rdtsc) }
}

unsafe extern "C" fn installed_rdtscp_hook(context: *mut HookContext) {
    unsafe { installed_instruction_hook(context, InstructionEventKind::Rdtscp) }
}

unsafe fn installed_syscall_hook_for(context: *mut HookContext, number: Option<i64>) {
    if let Some(context) = unsafe { context.as_ref() }
        && let Some(site) = find_site(context.instruction_pointer)
    {
        record_hook_entry(site);
    }
    unsafe { dispatch_syscall_context(context, number, SyscallDispatch::InstalledHook, None) };
}

/// Counts one entry through a patched site's hook. An entry the Tool's own
/// syscall or instruction made during a callback is also counted alone, so
/// the guest's own entries can be told apart from the Tool's.
fn record_hook_entry(site: &SiteSlot) {
    site.hook_count.fetch_add(1, Ordering::Relaxed);
    if tool_callback_active() {
        crate::stats::GuestStatsHooks::current()
            .record_path(crate::LiteinstDispatchPath::InGuestNestedHook);
    }
}

pub(crate) unsafe fn dispatch_fallback_context(context: *mut HookContext, pkru: &mut Option<u32>) {
    unsafe { dispatch_syscall_context(context, None, SyscallDispatch::Fallback, Some(pkru)) };
}

unsafe fn dispatch_syscall_context(
    context: *mut HookContext,
    number: Option<i64>,
    dispatch: SyscallDispatch,
    guest_pkru: Option<&mut Option<u32>>,
) {
    if context.is_null() {
        unsafe {
            exit_now(122);
        }
    }
    if enter_rcb_handler().is_err() {
        unsafe { exit_now(122) };
    }
    // SAFETY: generated LiteInst code passes a unique mutable saved frame.
    let context_pointer = context as usize;
    let context = unsafe { &mut *context };
    let mut event = SyscallEvent {
        number: number.unwrap_or(context.rax as i64),
        args: [
            context.rdi,
            context.rsi,
            context.rdx,
            context.r10,
            context.r8,
            context.r9,
        ],
        instruction_pointer: context.instruction_pointer,
        result: UNSET_RESULT,
        context: context_pointer,
        dispatch,
        // Fallback supplies its owned genuine entry. Installed hooks still
        // need independent provenance; never borrow a stale signal's rights.
        guest_pkru: guest_pkru.as_ref().and_then(|value| **value),
    };
    #[cfg(feature = "allocator-fixture")]
    if matches!(dispatch, SyscallDispatch::Fallback) {
        // The RCB handler boundary above has already excluded Tool work.
        // Observe this real dispatch only; the fixture cannot prepare one.
        crate::stack_fixture::record_fallback(
            event.number as usize,
            event.instruction_pointer as usize,
        );
    }
    // A site patched for another syscall (glibc's `syscall()` wrapper) can
    // carry the guest's own `rt_sigreturn` here without a trap; refuse it as
    // the SIGSYS handler does a trapped one.
    if reverie_inguest::trap::is_rt_sigreturn(event.number)
        && reverie_inguest::trap::signal_return_restricted()
    {
        unsafe { reverie_inguest::trap::refuse_guest_signal_return() };
    }
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-133): Review guarded installed-hook bypass for Tool-internal syscalls.
    if tool_callback_active() {
        // SAFETY: a genuine hook entry made while a Tool callback is active on
        // this thread: the callback's own syscall, which may run natively.
        unsafe { forward_nested_tool_syscall(&mut event, observe_mapping_generation) };
        context.rax = event.result as u64;
        context.rcx = context.instruction_pointer.saturating_add(2);
        context.r11 = context.rflags;
        if let Some(output) = guest_pkru {
            *output = event.guest_pkru;
        }
        if leave_rcb_handler().is_err() {
            unsafe { exit_now(122) };
        }
        return;
    }
    {
        let _tool_callback = ToolCallbackGuard::enter();
        // SAFETY: this unique local event remains live until the synchronous
        // trampoline returns; the trampoline does not retain its pointer.
        unsafe { tool_trampoline((&raw mut event).cast::<core::ffi::c_void>()) };
    }
    if event.result == UNSET_RESULT {
        event.result = -i64::from(libc::ENOSYS);
    }
    context.rax = event.result as u64;
    context.rcx = context.instruction_pointer.saturating_add(2);
    context.r11 = context.rflags;
    if let Some(output) = guest_pkru {
        *output = event.guest_pkru;
    }
    if leave_rcb_handler().is_err() {
        unsafe { exit_now(122) };
    }
}

unsafe extern "C" fn installed_syscall_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, None) }
}

/// Ordinary context after genuine SIGSYS return, with guest mask and PKRU
/// restored. Unlike an installed Tool hook, this callback must not mark guest
/// handlers as Tool-internal while the kernel read/write can block.
unsafe extern "C" fn unpublished_syscall_hook(context: *mut HookContext) {
    if context.is_null() || enter_rcb_handler().is_err() {
        unsafe { exit_now(122) };
    }
    // SAFETY: the exact-syscall trampoline owns this live saved frame.
    let context_pointer = context as usize;
    let context = unsafe { &mut *context };
    let mut event = SyscallEvent {
        number: context.rax as i64,
        args: [
            context.rdi,
            context.rsi,
            context.rdx,
            context.r10,
            context.r8,
            context.r9,
        ],
        instruction_pointer: context.instruction_pointer,
        result: UNSET_RESULT,
        context: context_pointer,
        dispatch: SyscallDispatch::Fallback,
        // The real sigreturn restored the guest's live permissions; do not
        // open a key or borrow a saved permission value for the operation.
        guest_pkru: None,
    };
    // Classification is after the RCB exclusion sample. This is an unpatched
    // signal entry, never an installed-hook count.
    record_fallback_dispatch(event.number);
    let stats = crate::stats::GuestStatsHooks::current();
    if stats.is_enabled() {
        record_enabled_fallback_stats(stats, event.instruction_pointer);
    }
    if unpublished_read_write_allowed(event.number) {
        // No ToolCallbackGuard spans guest I/O: a nested guest handler's own
        // syscalls must still traverse their guest path.
        unsafe { process_syscall(&mut event) };
    } else {
        FALLBACK_REFUSALS.record(event.number);
        event.result = -i64::from(libc::EOPNOTSUPP);
    }
    context.rax = event.result as u64;
    context.rcx = context.instruction_pointer.saturating_add(2);
    context.r11 = context.rflags;
    if leave_rcb_handler().is_err() {
        unsafe { exit_now(122) };
    }
}

unsafe extern "C" fn installed_vdso_time_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, Some(libc::SYS_time)) }
}

unsafe extern "C" fn installed_vdso_clock_gettime_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, Some(libc::SYS_clock_gettime)) }
}

unsafe extern "C" fn installed_vdso_getcpu_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, Some(libc::SYS_getcpu)) }
}

unsafe extern "C" fn installed_vdso_gettimeofday_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, Some(libc::SYS_gettimeofday)) }
}

unsafe extern "C" fn installed_vdso_clock_getres_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, Some(libc::SYS_clock_getres)) }
}

unsafe extern "C" fn installed_vdso_getrandom_hook(context: *mut HookContext) {
    unsafe { installed_syscall_hook_for(context, Some(libc::SYS_getrandom)) }
}

unsafe fn locate_syscall_site(resume_address: u64) -> Option<u64> {
    let candidates = [resume_address.checked_sub(2), Some(resume_address)];
    for address in candidates.into_iter().flatten() {
        let Some(arena) = arena_for(address) else {
            continue;
        };
        if address.checked_add(2)? > arena.mapping_end {
            continue;
        }
        // SAFETY: the candidate lies inside a live executable mapping.
        let bytes = unsafe { core::slice::from_raw_parts(address as usize as *const u8, 2) };
        if bytes == [0x0F, 0x05] {
            return Some(address);
        }
    }
    None
}

type RecordFallbackStats = fn(crate::stats::GuestStatsHooks, u64);

struct LiteinstSeam {
    stats: crate::stats::GuestStatsHooks,
    record_fallback_stats: RecordFallbackStats,
    publication: PatchPublication,
}

impl LiteinstSeam {
    fn new(stats: crate::stats::GuestStatsHooks, publication: PatchPublication) -> Self {
        Self {
            stats,
            record_fallback_stats: if stats.is_enabled() {
                record_enabled_fallback_stats
            } else {
                record_disabled_fallback_stats
            },
            publication,
        }
    }
}

// LiteInst's part of the shared SIGSYS dispatcher
// (reverie_inguest::guest::trap_dispatch): its compatibility Tools' fork and
// wait fallbacks, the arena-based location of the syscall instruction, site
// patching, and its counters and statistics.
// SAFETY: intercept runs the event's syscall (through process_syscall) only
// when it returns true; when it returns false it has run nothing.
unsafe impl TrapSeam for LiteinstSeam {
    fn record_path(&self, path: TrapPath) {
        self.stats.record_path(match path {
            TrapPath::NestedSigsys => crate::LiteinstDispatchPath::InGuestNestedSigsys,
            TrapPath::Sigsys => crate::LiteinstDispatchPath::InGuestSigsys,
            TrapPath::PhysicalSigsys => crate::LiteinstDispatchPath::InGuestPhysicalSigsys,
            TrapPath::FallbackCompletion => crate::LiteinstDispatchPath::FallbackCompletionSigsys,
            TrapPath::FallbackRefusal => crate::LiteinstDispatchPath::FallbackRefusal,
        });
    }

    fn observe_nested(&self, event: &SyscallEvent) {
        observe_mapping_generation(event);
    }

    fn intercept(&self, event: &mut PreloadSyscallEvent) -> bool {
        let mode = TOOL_MODE.load(Ordering::Relaxed);
        let args = event.args();
        let compatibility_trap_fallback =
            // AUTONOMOUS-BOT-IMPLEMENTED
            (event.number() == libc::SYS_clone && clone_is_fork_like(args[0], args[1]))
            // AUTONOMOUS-BOT-IMPLEMENTED
            || event.number() == libc::SYS_wait4;
        // TODO-HUMAN-REVIEW(PR-127): Review fork and wait libc-wrapper trap fallbacks.
        if mode != TOOL_REVERIE && compatibility_trap_fallback {
            let mut trapped = SyscallEvent {
                number: event.number(),
                args,
                instruction_pointer: event.instruction_pointer(),
                result: UNSET_RESULT,
                context: 0,
                dispatch: SyscallDispatch::Trap,
                guest_pkru: event.guest_pkru(),
            };
            // SAFETY: process_syscall traces the event for the compatibility Tool
            // and runs its syscall natively, as the safe
            // reverie_inguest::dispatch::SyscallEvent::forward may for any event.
            unsafe {
                process_syscall(&mut trapped);
            }
            event.set_native_result(reverie_inguest::trap::NativeSyscallResult {
                result: trapped.result,
                pkru: trapped.guest_pkru,
            });
            return true;
        }
        false
    }

    unsafe fn syscall_site(&self, resume_address: u64) -> u64 {
        // SAFETY: a SIGSYS-delivered trap's arrival resume address follows code
        // that was just executing (the seam's contract); locate_syscall_site
        // reads only inside a recorded arena.
        unsafe { locate_syscall_site(resume_address) }.unwrap_or(resume_address.saturating_sub(2))
    }

    unsafe fn patch_syscall_site(&self, instruction_pointer: u64, number: i64) -> SitePatch {
        if SITE_PATCHING_ENABLED.load(Ordering::Relaxed)
            && let Some((site, claimed)) = claim_site(instruction_pointer)
        {
            site.trap_count.fetch_add(1, Ordering::Relaxed);
            if claimed {
                // SAFETY: not a memory-safety matter. Faulting is turned back on
                // just below; if that fails, the site is marked fallback and the
                // trap refused, and this thread's CPUID/RDTSC may then run
                // natively, unobserved, as before this change.
                let native = unsafe { set_all_instruction_native(true) };
                let installed = native.and_then(|()| {
                    // SAFETY: the address is a genuine trap's syscall instruction
                    // (the seam's contract), in executing code; install_site_hook
                    // re-checks, under its lock, the arena, the syscall bytes, the
                    // neighbours and that no jump enters the patch window.
                    unsafe {
                        install_site_hook(
                            instruction_pointer,
                            site,
                            installed_entries::selected().syscall,
                            SiteHookPolicy {
                                publication: self.publication,
                                entry_proof: EntryProof::Required,
                                unpublished_read_write: unpublished_read_write_allowed(number),
                            },
                            &[0x0f, 0x05],
                            true,
                        )
                    }
                    .map_err(io::Error::from)
                });
                let restored = unsafe { set_all_instruction_native(false) };
                if restored.is_err() {
                    site.state.store(SITE_FALLBACK, Ordering::Release);
                    return SitePatch::Refuse;
                }
                if installed.is_err() {
                    site.state.store(SITE_FALLBACK, Ordering::Release);
                }
            }
            while matches!(site.state.load(Ordering::Acquire), 0 | SITE_INSTALLING) {
                core::hint::spin_loop();
            }
            if site.state.load(Ordering::Acquire) == SITE_ACTIVE {
                let hook = site.hook.load(Ordering::Acquire);
                if !hook.is_null() {
                    // SAFETY: active sites retain their InstalledHook for process lifetime.
                    return SitePatch::Defer(unsafe { (*hook).trampoline().address() });
                }
            }
            if site.state.load(Ordering::Acquire) == SITE_UNPUBLISHED {
                return unpublished_syscall_entry(instruction_pointer, site, number)
                    .map_or(SitePatch::Refuse, SitePatch::Defer);
            }
        }
        SitePatch::NotPatched
    }

    fn continuation_allowed(&self) -> bool {
        TOOL_MODE.load(Ordering::Relaxed) == TOOL_REVERIE
    }

    fn record_fallback(&self, number: i64) {
        // AUTONOMOUS-BOT-IMPLEMENTED
        record_fallback_dispatch(number);
    }

    fn record_continuation(&self, instruction_pointer: u64) {
        (self.record_fallback_stats)(self.stats, instruction_pointer);
    }

    fn record_refusal(&self, number: i64) {
        FALLBACK_REFUSALS.record(number);
    }
}

fn record_disabled_fallback_stats(_stats: crate::stats::GuestStatsHooks, _address: u64) {}

#[cfg(test)]
static ENABLED_FALLBACK_CLASSIFICATIONS: AtomicU64 = AtomicU64::new(0);

fn record_enabled_fallback_stats(stats: crate::stats::GuestStatsHooks, address: u64) {
    #[cfg(test)]
    ENABLED_FALLBACK_CLASSIFICATIONS.fetch_add(1, Ordering::Relaxed);
    if !SITE_PATCHING_ENABLED.load(Ordering::Relaxed) {
        stats.record_path(crate::LiteinstDispatchPath::PatchingDisabledFallback);
        return;
    }
    let straddler =
        find_site(address).is_some_and(|site| site.straddle_prefix.load(Ordering::Relaxed) != 0);
    stats.record_path(if straddler {
        crate::LiteinstDispatchPath::CachelineStraddlerFallback
    } else {
        crate::LiteinstDispatchPath::UnpatchableOrOtherFallback
    });
}

unsafe extern "C" fn tool_trampoline(event: *mut core::ffi::c_void) {
    let event = event.cast::<SyscallEvent>();
    if event.is_null() {
        unsafe {
            exit_now(123);
        }
    }
    // SAFETY: the sole caller supplies its unique live local SyscallEvent for
    // this synchronous call, and process_syscall does not retain the reference.
    unsafe {
        process_syscall(&mut *event);
    }
}

unsafe fn process_syscall(event: &mut SyscallEvent) {
    let tool_mode = TOOL_MODE.load(Ordering::Relaxed);
    // AUTONOMOUS-BOT-IMPLEMENTED
    if matches!(event.number, libc::SYS_execve | libc::SYS_execveat) {
        event.result = -i64::from(libc::ENOTSUP);
        if tool_mode != TOOL_REVERIE {
            unsafe {
                trace_event(event, Some(event.result));
            }
        }
        return;
    }
    if tool_mode == TOOL_REVERIE && protect_runtime_control(event) {
        return;
    }
    if tool_mode == TOOL_REVERIE && unsafe { protect_runtime_descriptors_before_tool(event) } {
        return;
    }
    if TOOL_MODE.load(Ordering::Relaxed) == TOOL_REVERIE {
        crate::tool_host::dispatch(event);
        observe_mapping_generation(event);
        return;
    }
    if TOOL_MODE.load(Ordering::Relaxed) == TOOL_COMPAT
        && EVENT_COOKIE.load(Ordering::Relaxed) != 0
        && unsafe { protect_compatibility_event_channel(event) }
    {
        return;
    }

    if TOOL_MODE.load(Ordering::Relaxed) == TOOL_COMPAT
        && matches!(
            event.number,
            libc::SYS_setpgid | libc::SYS_setsid | libc::SYS_setns | libc::SYS_unshare
        )
    {
        event.result = -i64::from(libc::EPERM);
        unsafe {
            trace_event(event, Some(event.result));
        }
        return;
    }

    if let Some(errno) = refused_process_creation(event.number, event.args, tool_mode) {
        event.result = -i64::from(errno);
        unsafe {
            trace_event(event, Some(event.result));
        }
        return;
    }

    if event.number == libc::SYS_exit || event.number == libc::SYS_exit_group {
        unsafe {
            trace_event(event, None);
        }
    }

    let compatibility_fork = TOOL_MODE.load(Ordering::Relaxed) == TOOL_COMPAT
        && matches!(event.number, libc::SYS_clone | libc::SYS_fork);
    if compatibility_fork {
        unsafe {
            trace_event(event, None);
        }
    }
    event.result = match reverie_inguest::guest::restorer::owner_mapping_change_result(
        event.number,
        event.args,
    ) {
        Some(result) => result,
        None => unsafe { event.forward() },
    };
    observe_mapping_generation(event);

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-260): Review the fork-following observability reset call.
    // In the child of a successful fork-like syscall (`result == 0`), the
    // COW-inherited observability counters describe the parent, not this child.
    // Reset them through the shared ForkHook seam so per-process attribution
    // starts clean. Gating on a zero result is sufficient and mirrors
    // e9patch's child-side reset.
    if is_fork_like(event.number) && event.result == 0 {
        FORK_HOOK.run_in_child();
    }

    if event.number != libc::SYS_exit && event.number != libc::SYS_exit_group && !compatibility_fork
    {
        unsafe {
            trace_event(event, Some(event.result));
        }
    }
}

/// Errno for process creation that the strace and compatibility modes refuse
/// before forwarding, or `None` when `process_syscall` may forward it.
///
/// These modes forward from runtime frames below the interrupted syscall
/// site: those of an installed hook's trampoline, on the guest's stack, or
/// those of the SIGSYS handler, which runs on the alternate signal stack
/// unless `RuntimeConfig::use_alt_stack` is false. The handler never forwards
/// a `vfork` or `clone3` itself: it hands one to the site's trampoline, or
/// refuses it without a trace record when the site has no installed hook.
/// Only a child with its own copy of those frames can return through
/// them. That means bare `fork` and the `clone` that [`clone_is_fork_like`]
/// accepts: a null child stack, `SIGCHLD` as the exit signal, and no flags
/// other than `CLONE_CHILD_CLEARTID`, `CLONE_CHILD_SETTID` and
/// `CLONE_PARENT_SETTID`. glibc's `fork` passes that shape: `SIGCHLD`,
/// `CLONE_CHILD_SETTID` and `CLONE_CHILD_CLEARTID`. Any other `clone` is
/// refused with the mode-specific errno it already had.
///
/// A `vfork` child runs on the parent's stack while the parent is suspended
/// inside those frames. It returns through them, then overwrites them before
/// the parent resumes. A `clone3` child with its own stack starts right after
/// the syscall instruction inside the forwarding code, with none of the frames
/// it would return through. A thread-creating `clone3` would also bypass the
/// thread `clone` refusal. The decision uses only the syscall number, so
/// `clone_args` is never read. The shared preload dispatcher refuses both for
/// the same reason. See <https://github.com/rrnewton/reverie/issues/758>.
///
/// Both are refused with `ENOTSUP` in both modes. This matches the preload
/// dispatcher and Tool mode's nested and injected syscall guards. `ENOSYS` was
/// the alternative. Seccomp sandboxes conventionally deny with `ENOSYS` so that
/// libc falls back to an older syscall (the containers-common 5.8 seccomp
/// profile's default errno is `ENOSYS`), and glibc does retry a failed clone3
/// as clone. That does not help here. In glibc 2.34 and 2.42 on x86-64,
/// pthread_create goes through `__clone_internal`, which retries only on
/// `ENOSYS`. posix_spawn also uses `__clone_internal` in 2.34; in 2.42 it calls
/// clone3 itself and, unless a cgroup was requested, retries on `ENOSYS` or
/// `EINVAL`. Every one of these callers passes a child stack, so the guard
/// above would refuse the retried clone (EPERM in compat, ENOTSUP in strace)
/// and the call would still fail. It would just take a second refused syscall,
/// and the errno would depend on the mode. glibc's `fork` uses clone, not
/// clone3, and its `vfork` issues the raw syscall with no fallback. Other glibc
/// versions and other libcs were not checked. The cost is that a fork-shaped
/// clone3 caller that falls back only on `ENOSYS` fails here; Tool mode admits
/// that shape through the Tool host's plain-fork check
/// (`reverie_inguest::guest::host`).
fn refused_process_creation(number: i64, args: [u64; 6], tool_mode: u8) -> Option<i32> {
    match number {
        libc::SYS_clone if !clone_is_fork_like(args[0], args[1]) => {
            Some(if tool_mode == TOOL_COMPAT {
                libc::EPERM
            } else {
                libc::ENOTSUP
            })
        }
        libc::SYS_clone3 | libc::SYS_vfork => Some(libc::ENOTSUP),
        _ => None,
    }
}

fn clone_is_fork_like(flags: u64, child_stack: u64) -> bool {
    const SIGNAL_MASK: u64 = 0xff;
    let allowed_flags =
        (libc::CLONE_CHILD_CLEARTID | libc::CLONE_CHILD_SETTID | libc::CLONE_PARENT_SETTID) as u64;
    child_stack == 0
        && flags & SIGNAL_MASK == libc::SIGCHLD as u64
        && flags & !(SIGNAL_MASK | allowed_flags) == 0
}

unsafe fn protect_compatibility_event_channel(event: &mut SyscallEvent) -> bool {
    let event_fd = EVENT_FD.load(Ordering::Acquire) as u64;

    if event.number == libc::SYS_close && fd_arg(event, 0) == event_fd {
        // The descriptor is controller-owned and intentionally invisible to
        // guest descriptor lifecycle management.
        event.result = 0;
    } else if event.number == libc::SYS_close_range
        && fd_arg(event, 0) <= event_fd
        && event_fd <= fd_arg(event, 1)
    {
        event.result = unsafe { close_range_preserving_event_fd(event, event_fd) };
    } else if syscall_targets_event_fd(event, event_fd) {
        event.result = -i64::from(libc::EBADF);
    } else {
        return false;
    }

    unsafe {
        trace_event(event, Some(event.result));
    }
    true
}

unsafe fn close_range_preserving_event_fd(event: &SyscallEvent, event_fd: u64) -> i64 {
    unsafe { close_range_preserving_fds(event, &[event_fd]) }
}

unsafe fn compatibility_event_channel_is_intact(output_fd: libc::c_int) -> bool {
    let mut metadata: libc::stat = unsafe { core::mem::zeroed() };
    let result = unsafe {
        raw_syscall6(
            libc::SYS_fstat,
            [output_fd as u64, (&raw mut metadata) as u64, 0, 0, 0, 0],
        )
    };
    result == 0
        && metadata.st_dev == EVENT_DEVICE.load(Ordering::Acquire)
        && metadata.st_ino == EVENT_INODE.load(Ordering::Acquire)
}

unsafe fn write_compatibility_event(output_fd: libc::c_int, bytes: &[u8]) {
    const MAX_BACKPRESSURE_RETRIES: usize = 20;
    const BACKPRESSURE_POLL_MILLISECONDS: u64 = 100;

    if unsafe { !compatibility_event_channel_is_intact(output_fd) } {
        unsafe {
            exit_now(EVENT_CHANNEL_IDENTITY_FAILURE_STATUS);
        }
    }
    for attempt in 0..=MAX_BACKPRESSURE_RETRIES {
        let written = unsafe {
            raw_syscall6(
                libc::SYS_write,
                [
                    output_fd as u64,
                    bytes.as_ptr() as u64,
                    bytes.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if written == bytes.len() as i64 {
            return;
        }
        if written != -i64::from(libc::EAGAIN) && written != -i64::from(libc::EINTR) {
            break;
        }
        if attempt == MAX_BACKPRESSURE_RETRIES {
            break;
        }
        let mut descriptor = libc::pollfd {
            fd: output_fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let _ = unsafe {
            raw_syscall6(
                libc::SYS_poll,
                [
                    (&raw mut descriptor) as u64,
                    1,
                    BACKPRESSURE_POLL_MILLISECONDS,
                    0,
                    0,
                    0,
                ],
            )
        };
    }
    unsafe {
        exit_now(EVENT_CHANNEL_WRITE_FAILURE_STATUS);
    }
}

unsafe fn trace_event(event: &SyscallEvent, result: Option<i64>) {
    let mode = TOOL_MODE.load(Ordering::Relaxed);
    let output_fd;
    let mut line = StackLine::new();
    if mode == TOOL_COMPAT {
        output_fd = EVENT_FD.load(Ordering::Acquire);
        line.push_bytes(b"reverie-liteinst: tool=compat");
        let cookie = EVENT_COOKIE.load(Ordering::Acquire);
        if cookie != 0 {
            line.push_bytes(b" cookie=");
            line.push_unsigned(cookie);
            line.push_bytes(b" pid=");
            line.push_signed(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) });
        }
        line.push_bytes(b" syscall=");
        line.push_signed(event.number);
    } else if mode == TOOL_STRACE {
        output_fd = libc::STDERR_FILENO;
        let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
        line.push_bytes(b"[liteinst strace pid ");
        line.push_signed(pid);
        line.push_bytes(b"] syscall(");
        line.push_signed(event.number);
        line.push_bytes(b", ip=0x");
        line.push_hex(event.instruction_pointer);
        line.push_bytes(b") = ");
        match result {
            Some(result) => line.push_signed(result),
            None => line.push_bytes(b"?"),
        }
    } else {
        return;
    }
    line.push_bytes(b"\n");

    if mode == TOOL_COMPAT && EVENT_COOKIE.load(Ordering::Relaxed) != 0 {
        unsafe {
            write_compatibility_event(output_fd, line.as_bytes());
        }
    } else {
        let _ = unsafe {
            raw_syscall6(
                libc::SYS_write,
                [
                    output_fd as u64,
                    line.as_bytes().as_ptr() as u64,
                    line.as_bytes().len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review the private-mapping gate.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review the private-only publication rule.
/// The protection of the one private mapping of `/proc/self/maps` that holds
/// `address` through `last` (inclusive), or `None` when that mapping is
/// shared, `last` lies in another mapping, no line contains `address`, or the
/// file cannot be read. Usable in signal context, like [`mapping_name_at`].
unsafe fn private_span_protection(address: u64, last: u64) -> Option<i32> {
    unsafe { scan_own_maps(|line| maps_line_private(line, address)) }
        .and_then(|(private, end, protection)| (private && last < end).then_some(protection))
}

/// Parse one `/proc/self/maps` line; when its range contains `address`,
/// return whether its permissions mark it private (`p`, not shared `s`), the
/// end of its range, and its protection as `PROT_*` bits.
fn maps_line_private(line: &[u8], address: u64) -> Option<(bool, u64, i32)> {
    let mut fields = line
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty());
    let range = fields.next()?;
    let permissions = fields.next()?;
    let dash = range.iter().position(|byte| *byte == b'-')?;
    let parse = |bytes: &[u8]| {
        (!bytes.is_empty() && bytes.len() <= 16)
            .then(|| core::str::from_utf8(bytes).ok())
            .flatten()
            .and_then(|text| u64::from_str_radix(text, 16).ok())
    };
    let (start, end) = (parse(&range[..dash])?, parse(&range[dash + 1..])?);
    let protection = [
        (0, b'r', libc::PROT_READ),
        (1, b'w', libc::PROT_WRITE),
        (2, b'x', libc::PROT_EXEC),
    ]
    .into_iter()
    .filter(|(index, flag, _)| permissions.get(*index) == Some(flag))
    .fold(0, |bits, (_, _, bit)| bits | bit);
    (start <= address && address < end)
        .then(|| (permissions.get(3) == Some(&b'p'), end, protection))
}

fn emit_instruction_refusal_stage(
    stage: &[u8],
    rip_offset: u64,
    fault_address: u64,
    stack_pointer: u64,
    mapping_name: &[u8],
    mapping_len: u64,
    bytes: &[u8],
) {
    if !reverie_inguest::guest::support::stage_stream_enabled() {
        return;
    }
    let mut line = StackLine::new();
    line.push_bytes(b"INFO reverie_liteinst::tool_host: [in-guest pid=");
    line.push_signed(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) });
    line.push_bytes(b" tid=");
    line.push_signed(unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) });
    line.push_bytes(b"] stage=");
    line.push_bytes(stage);
    line.push_bytes(b" rip-offset=0x");
    line.push_hex(rip_offset);
    line.push_bytes(b" fault=0x");
    line.push_hex(fault_address);
    line.push_bytes(b" rsp=0x");
    line.push_hex(stack_pointer);
    line.push_bytes(b" map=");
    line.push_bytes(mapping_name);
    line.push_bytes(b" map-len=0x");
    line.push_hex(mapping_len);
    line.push_bytes(b" bytes=");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            line.push_bytes(b"-");
        }
        line.push_hex_byte(*byte);
    }
    line.push_bytes(b"\n");
    let written = unsafe {
        raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                line.as_bytes().as_ptr() as u64,
                line.as_bytes().len() as u64,
                0,
                0,
                0,
            ],
        )
    };
    if written != line.as_bytes().len() as i64 {
        unsafe { exit_now(IN_GUEST_STAGE_WRITE_FAILURE_STATUS) };
    }
}

#[cfg(test)]
mod tests {

    use core::sync::atomic::Ordering;
    use std::ffi::OsStr;

    use super::SITE_PATCHING_ENABLED;
    use super::site_patching_enabled;

    #[test]
    fn site_patching_enabled_reports_the_captured_setting() {
        let previous = SITE_PATCHING_ENABLED.load(Ordering::Acquire);
        // What the installation stored is what the getter reports, whatever
        // the environment holds afterwards (it is not read again).
        SITE_PATCHING_ENABLED.store(false, Ordering::Release);
        assert!(!site_patching_enabled());
        SITE_PATCHING_ENABLED.store(true, Ordering::Release);
        assert!(site_patching_enabled());
        SITE_PATCHING_ENABLED.store(previous, Ordering::Release);
    }
    use reverie_inguest::BuiltinTool;

    use super::ALT_STACK_ENV;
    use super::AsyncSignalsBlocked;
    use super::ENABLED_FALLBACK_CLASSIFICATIONS;
    use super::FORK_HOOK;
    use super::FallbackCounters;
    use super::LiteinstSeam;
    use super::MAX_PATCH_SITES;
    use super::NeighbourConflict;
    use super::ObjectImage;
    use super::SITE_ACTIVE;
    use super::SITE_FALLBACK;
    use super::SITE_INSTALLING;
    use super::SITE_STALE;
    use super::SITE_UNPATCHABLE;
    use super::SITE_UNPUBLISHED;
    use super::SITES;
    use super::SiteSlot;
    use super::TOOL_PASSTHROUGH;
    use super::TOOL_SPOOF_GETPID;
    use super::alt_stack_from_env_value;
    use super::builtin_tool_from_env_value;
    use super::claim_site;
    use super::clone_is_fork_like;
    use super::earlier_patch_survives;
    use super::fallback_dispatch_count;
    use super::fallback_syscall_count;
    use super::maps_line_private;
    use super::mark_site_range_stale;
    use super::neighbour_conflict;
    use super::neighbours_conflict;
    use super::object_image;
    use super::parse_runtime_maps;
    use super::record_fallback_dispatch;
    use super::refused_process_creation;
    use super::reset_site_observability;
    use super::site_footprint;
    use super::stale_jump_survives;

    #[test]
    fn disabled_dispatch_does_not_classify_fallback_sites() {
        let before = ENABLED_FALLBACK_CLASSIFICATIONS.load(Ordering::Relaxed);
        let seam = LiteinstSeam::new(
            crate::stats::GuestStatsHooks::DISABLED,
            super::PatchPublication::Concurrent,
        );

        (seam.record_fallback_stats)(seam.stats, 0xdead_beef);

        assert_eq!(
            ENABLED_FALLBACK_CLASSIFICATIONS.load(Ordering::Relaxed),
            before
        );
    }

    #[test]
    fn builtin_tool_selector_maps_shared_values_only() {
        assert_eq!(
            builtin_tool_from_env_value(OsStr::new(TOOL_PASSTHROUGH)),
            Some(BuiltinTool::Passthrough)
        );
        assert_eq!(
            builtin_tool_from_env_value(OsStr::new(TOOL_SPOOF_GETPID)),
            Some(BuiltinTool::SpoofGetpid)
        );
        // LiteInst-native modes and unknown values are not shared built-ins.
        assert_eq!(builtin_tool_from_env_value(OsStr::new("strace")), None);
        assert_eq!(builtin_tool_from_env_value(OsStr::new("compat")), None);
        assert_eq!(builtin_tool_from_env_value(OsStr::new("bogus")), None);
    }

    #[test]
    fn alt_stack_defaults_to_the_shared_default_when_unset() {
        // Unset must reproduce the shared reverie-inguest default verbatim, so
        // the launcher-selected knob is a no-op by default (zero behavior change).
        use reverie_inguest::lifecycle::RuntimeConfig;
        assert_eq!(
            alt_stack_from_env_value(None).unwrap(),
            RuntimeConfig::default().use_alt_stack
        );
    }

    #[test]
    fn alt_stack_parses_truthy_and_falsy_spellings() {
        for on in ["1", "true", "TRUE", "on", "On", "yes", "  yes  "] {
            assert!(
                alt_stack_from_env_value(Some(OsStr::new(on))).unwrap(),
                "{on:?} should parse as alt-stack on"
            );
        }
        for off in ["0", "false", "FALSE", "off", "Off", "no", "  no  "] {
            assert!(
                !alt_stack_from_env_value(Some(OsStr::new(off))).unwrap(),
                "{off:?} should parse as alt-stack off"
            );
        }
    }

    #[test]
    fn alt_stack_rejects_unknown_values() {
        for bad in ["maybe", "2", "", "onoff"] {
            assert!(
                alt_stack_from_env_value(Some(OsStr::new(bad))).is_err(),
                "{bad:?} must be rejected, not silently defaulted"
            );
        }
    }

    #[test]
    fn alt_stack_env_is_distinct_from_the_other_selectors() {
        // The alt-stack knob is orthogonal to the tool selector; a shared
        // build-time typo that aliased them would defeat launcher control.
        assert_eq!(ALT_STACK_ENV, "REVERIE_LITEINST_ALT_STACK");
        assert_ne!(ALT_STACK_ENV, "REVERIE_LITEINST_TOOL");
    }

    #[test]
    fn recording_a_fallback_bumps_total_and_the_matching_syscall() {
        let counters = FallbackCounters::new();
        let number: i64 = 402;

        counters.record(number);

        assert_eq!(counters.by_number(number), 1);
        assert_eq!(counters.total(), 1);
    }

    #[test]
    fn out_of_range_syscall_numbers_count_in_the_total_only() {
        let counters = FallbackCounters::new();
        // Above the tracked bound: total advances, per-number stays zero.
        let huge = i64::from(i32::MAX);
        counters.record(huge);
        assert_eq!(counters.by_number(huge), 0);
        assert_eq!(counters.total(), 1);

        // Negative numbers are never used to index the per-number table.
        counters.record(-1);
        assert_eq!(counters.by_number(-1), 0);
        assert_eq!(counters.total(), 2);
    }

    #[test]
    fn fallback_counter_reset_zeroes_total_and_per_number_counts() {
        let counters = FallbackCounters::new();
        let number: i64 = 404;
        counters.record(number);
        assert_eq!(counters.total(), 1);
        assert_eq!(counters.by_number(number), 1);

        counters.reset();

        assert_eq!(counters.total(), 0);
        assert_eq!(counters.by_number(number), 0);
    }

    #[test]
    fn fork_child_reset_zeroes_per_site_counts_but_preserves_patch_state() {
        // The per-site trap/hook counts are observability; the site's address and
        // state are functional patch metadata the COW-inherited child must keep.
        // Reset must clear the former without disturbing the latter.
        let site = SiteSlot::new();
        let address = 0x4321_9000;
        site.address.store(address, Ordering::Release);
        site.state.store(SITE_ACTIVE, Ordering::Release);
        site.trap_count.store(7, Ordering::Release);
        site.hook_count.store(11, Ordering::Release);
        assert_eq!(site.trap_count.load(Ordering::Acquire), 7);
        assert_eq!(site.hook_count.load(Ordering::Acquire), 11);

        reset_site_observability(std::slice::from_ref(&site));

        // Observability cleared...
        assert_eq!(site.trap_count.load(Ordering::Acquire), 0);
        assert_eq!(site.hook_count.load(Ordering::Acquire), 0);
        // ...but the functional patch state is intact, so the child's inherited
        // instrumentation keeps working.
        assert_eq!(site.address.load(Ordering::Acquire), address);
        assert_eq!(site.state.load(Ordering::Acquire), SITE_ACTIVE);
    }

    #[test]
    fn fork_hook_runs_the_observability_reset() {
        // The static FORK_HOOK must wrap `reset_fallback_observability`, so
        // invoking it (as `process_syscall` does in the fork child) clears both
        // process-global and per-site counters — proving the shared ForkHook seam
        // is wired to the complete production reset rather than a private path.
        SITES.get_or_init(|| {
            (0..MAX_PATCH_SITES)
                .map(|_| SiteSlot::new())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        let address = 0x7654_3000;
        let (site, claimed) = claim_site(address).unwrap();
        assert!(claimed);
        site.state.store(SITE_ACTIVE, Ordering::Release);
        site.trap_count.store(7, Ordering::Release);
        site.hook_count.store(11, Ordering::Release);
        record_fallback_dispatch(405);
        super::FALLBACK_REFUSALS.record(405);
        assert!(fallback_dispatch_count() > 0);
        assert!(super::fallback_refusal_count() > 0);

        FORK_HOOK.run_in_child();

        assert_eq!(fallback_dispatch_count(), 0);
        assert_eq!(super::fallback_refusal_count(), 0);
        assert_eq!(super::fallback_syscall_refusal_count(405), 0);
        assert_eq!(site.trap_count.load(Ordering::Acquire), 0);
        assert_eq!(site.hook_count.load(Ordering::Acquire), 0);
        assert_eq!(site.address.load(Ordering::Acquire), address);
        assert_eq!(site.state.load(Ordering::Acquire), SITE_ACTIVE);
        assert_eq!(fallback_syscall_count(405), 0);
    }

    #[test]
    fn reused_address_claims_a_new_site_generation() {
        SITES.get_or_init(|| {
            (0..MAX_PATCH_SITES)
                .map(|_| SiteSlot::new())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        let address = 0x1234_5000;
        let (site, claimed) = claim_site(address).unwrap();
        assert!(claimed);
        assert_eq!(site.state.load(Ordering::Acquire), SITE_INSTALLING);
        site.state.store(SITE_ACTIVE, Ordering::Release);

        mark_site_range_stale(address - 0x100, 0x200, address + 0x100);
        assert_eq!(site.state.load(Ordering::Acquire), SITE_STALE);
        assert_eq!(site.mapping_end.load(Ordering::Acquire), address + 0x100);

        let (same_site, claimed) = claim_site(address).unwrap();
        assert!(core::ptr::eq(site, same_site));
        assert!(claimed);
        assert_eq!(site.state.load(Ordering::Acquire), SITE_INSTALLING);
        site.state.store(SITE_FALLBACK, Ordering::Release);
    }

    #[test]
    fn clone_accepts_only_fork_like_flags() {
        let bookkeeping = (libc::CLONE_CHILD_CLEARTID
            | libc::CLONE_CHILD_SETTID
            | libc::CLONE_PARENT_SETTID) as u64;
        assert!(clone_is_fork_like(libc::SIGCHLD as u64, 0));
        assert!(clone_is_fork_like(libc::SIGCHLD as u64 | bookkeeping, 0));
        assert!(!clone_is_fork_like(libc::SIGCHLD as u64, 1));
        assert!(!clone_is_fork_like(0, 0));
        assert!(!clone_is_fork_like(libc::SIGUSR1 as u64, 0));

        for rejected in [
            libc::CLONE_VM,
            libc::CLONE_VFORK,
            libc::CLONE_THREAD,
            libc::CLONE_SETTLS,
            libc::CLONE_SIGHAND,
            libc::CLONE_FILES,
            libc::CLONE_FS,
            libc::CLONE_PARENT,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWUTS,
        ] {
            assert!(
                !clone_is_fork_like(libc::SIGCHLD as u64 | rejected as u64, 0),
                "accepted unsafe clone flag {rejected:#x}"
            );
        }
    }

    /// The census reads an object through the mappings recorded at
    /// initialization (https://github.com/rrnewton/reverie/issues/812), so
    /// those must be exactly the readable mappings of the text mapping's file.
    #[test]
    fn object_image_records_the_readable_mappings_of_the_text_file() {
        let maps = parse_runtime_maps(concat!(
            "555555554000-555555556000 r--p 00000000 00:1f 11 /usr/bin/guest\n",
            "555555556000-555555558000 r-xp 00002000 00:1f 11 /usr/bin/guest\n",
            "555555558000-55555555a000 rw-p 00004000 00:1f 11 /usr/bin/guest\n",
            "55555555a000-55555557b000 rw-p 00000000 00:00 0 [heap]\n",
            "7ffff7c00000-7ffff7c28000 r--p 00000000 00:1f 22 /usr/lib64/libc.so.6\n",
            "7ffff7c28000-7ffff7db0000 r-xp 00028000 00:1f 22 /usr/lib64/libc.so.6\n",
            "7ffff7db0000-7ffff7dff000 r--p 001b0000 00:1f 22 /usr/lib64/libc.so.6\n",
            "7ffff7dff000-7ffff7e00000 ---p 001ff000 00:1f 22 /usr/lib64/libc.so.6\n",
            "7ffff7e00000-7ffff7e04000 r--p 001ff000 00:1f 22 /usr/lib64/libc.so.6\n",
            "7ffff7e04000-7ffff7e06000 rw-p 00203000 00:1f 22 /usr/lib64/libc.so.6\n",
            "7ffff7e06000-7ffff7e13000 rw-p 00000000 00:00 0\n",
            "7ffff7f00000-7ffff7f01000 r-xp 00000000 00:00 0\n",
            "7ffff7f10000-7ffff7f11000 r--p 00000000 00:2a 22 /other/device/same-inode\n",
            "7ffff7f20000-7ffff7f21000 r--p 00000000 00:1f 33 /twice.so\n",
            "7ffff7f21000-7ffff7f22000 r-xp 00001000 00:1f 33 /twice.so\n",
            "7ffff7f30000-7ffff7f31000 r--p 00000000 00:1f 33 /twice.so\n",
        ));

        // The gap mapping (---p), the anonymous .bss continuation and the
        // mapping of another device's inode 22 are all left out.
        assert_eq!(
            object_image(&maps, 0x7fff_f7c2_8000, 0x7fff_f7db_0000),
            Some(ObjectImage::new(
                0x7fff_f7c0_0000,
                vec![
                    (0x7fff_f7c0_0000, 0x7fff_f7c2_8000, false),
                    (0x7fff_f7c2_8000, 0x7fff_f7db_0000, true),
                    (0x7fff_f7db_0000, 0x7fff_f7df_f000, false),
                    (0x7fff_f7e0_0000, 0x7fff_f7e0_4000, false),
                    (0x7fff_f7e0_4000, 0x7fff_f7e0_6000, false),
                ]
                .into_boxed_slice(),
            ))
        );
        assert_eq!(
            object_image(&maps, 0x5555_5555_6000, 0x5555_5555_8000),
            Some(ObjectImage::new(
                0x5555_5555_4000,
                vec![
                    (0x5555_5555_4000, 0x5555_5555_6000, false),
                    (0x5555_5555_6000, 0x5555_5555_8000, true),
                    (0x5555_5555_8000, 0x5555_5555_a000, false),
                ]
                .into_boxed_slice(),
            ))
        );
        // Anonymous text, a file mapped twice (two headers), and a range that
        // is not an executable mapping have no image.
        assert_eq!(
            object_image(&maps, 0x7fff_f7f0_0000, 0x7fff_f7f0_1000),
            None
        );
        assert_eq!(
            object_image(&maps, 0x7fff_f7f2_1000, 0x7fff_f7f2_2000),
            None
        );
        assert_eq!(
            object_image(&maps, 0x7fff_f7c0_0000, 0x7fff_f7c2_8000),
            None
        );
        assert_eq!(
            object_image(&maps, 0x7fff_f7c2_8000, 0x7fff_f7d0_0000),
            None
        );
    }

    // https://github.com/rrnewton/reverie/issues/758
    #[test]
    fn strace_and_compat_refuse_vfork_and_clone3_by_number() {
        let bookkeeping = (libc::CLONE_CHILD_CLEARTID
            | libc::CLONE_CHILD_SETTID
            | libc::CLONE_PARENT_SETTID) as u64;
        for mode in [super::TOOL_STRACE, super::TOOL_COMPAT] {
            let clone_errno = if mode == super::TOOL_COMPAT {
                libc::EPERM
            } else {
                libc::ENOTSUP
            };
            for (number, args, expected) in [
                // Refused by number, whatever the clone_args pointer and size.
                (libc::SYS_vfork, [0; 6], Some(libc::ENOTSUP)),
                (libc::SYS_clone3, [0; 6], Some(libc::ENOTSUP)),
                (libc::SYS_clone3, [u64::MAX; 6], Some(libc::ENOTSUP)),
                (
                    libc::SYS_clone,
                    [libc::CLONE_VM as u64 | libc::SIGCHLD as u64, 0, 0, 0, 0, 0],
                    Some(clone_errno),
                ),
                (
                    libc::SYS_clone,
                    [libc::SIGCHLD as u64, 1, 0, 0, 0, 0],
                    Some(clone_errno),
                ),
                (libc::SYS_fork, [0; 6], None),
                (
                    libc::SYS_clone,
                    [libc::SIGCHLD as u64 | bookkeeping, 0, 0, 0, 0, 0],
                    None,
                ),
                (libc::SYS_getpid, [0; 6], None),
            ] {
                assert_eq!(
                    refused_process_creation(number, args, mode),
                    expected,
                    "mode {mode} syscall {number} args {args:?}"
                );
            }
        }
    }

    #[test]
    fn neighbour_conflicts_protect_published_patches_and_continuation_sites() {
        use NeighbourConflict::CoversContinuationSite as Covers;
        use NeighbourConflict::InsidePublishedPatch as Inside;
        use NeighbourConflict::OverlapsPublishedPatch as Overlaps;
        const A: u64 = 0x1000;
        // (other site, its state, its recorded length, expected conflict for a
        // 2-byte instruction at A whose word patch is [A, A + 8)).
        let cases = [
            (A, SITE_ACTIVE, 2, None),
            (0, SITE_ACTIVE, 2, None),
            // A published jump that covers A or the resume point A + 2.
            (A - 7, SITE_ACTIVE, 2, Some(Inside)),
            (A - 1, SITE_FALLBACK, 2, Some(Inside)),
            (A + 1, SITE_ACTIVE, 2, Some(Inside)),
            // A published jump starting at or after the resume point, inside
            // the proposed patch: resuming is safe, patching is not.
            (A + 2, SITE_ACTIVE, 2, Some(Overlaps)),
            (A + 7, SITE_FALLBACK, 2, Some(Overlaps)),
            (A + 8, SITE_ACTIVE, 2, None),
            (A - 8, SITE_ACTIVE, 2, None),
            // A site executing through the continuation, or being decided.
            (A + 4, SITE_UNPATCHABLE, 2, Some(Covers)),
            (A + 7, SITE_INSTALLING, 0, Some(Covers)),
            (A + 8, SITE_UNPATCHABLE, 2, None),
            // Unpublished adapters reserve the original instruction too.
            (A + 4, SITE_UNPUBLISHED, 2, Some(Covers)),
            (A + 8, SITE_UNPUBLISHED, 2, None),
            (A - 1, SITE_UNPUBLISHED, 2, Some(Covers)),
            (A - 2, SITE_UNPUBLISHED, 2, None),
            // The proposed patch may start exactly at its resume point...
            (A - 2, SITE_UNPATCHABLE, 2, None),
            (A - 3, SITE_UNPATCHABLE, 3, None),
            // ...but not inside it; an unrecorded length is taken as 3.
            (A - 2, SITE_UNPATCHABLE, 3, Some(Covers)),
            (A - 2, SITE_INSTALLING, 0, Some(Covers)),
            (A - 3, SITE_INSTALLING, 0, None),
            // Unclaimed sites constrain nothing; a stale site keeps its
            // continuation reservation even without a footprint.
            (A + 4, 0, 2, None),
            (A + 4, SITE_STALE, 2, Some(Covers)),
            (A + 8, SITE_STALE, 2, None),
        ];
        for (other, state, other_len, expected) in cases {
            assert_eq!(
                neighbour_conflict(
                    A,
                    2,
                    other,
                    state,
                    other_len,
                    matches!(state, SITE_ACTIVE | SITE_FALLBACK),
                ),
                expected,
                "other={other:#x} state={state} len={other_len}"
            );
        }
    }
    #[test]
    fn a_covering_published_patch_dominates_whatever_the_table_order() {
        use NeighbourConflict::InsidePublishedPatch as Inside;
        use NeighbourConflict::OverlapsPublishedPatch as Overlaps;
        const A: u64 = 0x1000;
        // Codex's arrangement: a FALLBACK syscall at A + 4 (untouched overlap)
        // and an ACTIVE jump at A - 2 that covers A (touched), in both orders.
        let overlap = (A + 4, SITE_FALLBACK, 2, true);
        let covering = (A - 2, SITE_ACTIVE, 2, true);
        assert_eq!(neighbours_conflict(A, 2, [overlap, covering]), Some(Inside));
        assert_eq!(neighbours_conflict(A, 2, [covering, overlap]), Some(Inside));
        assert_eq!(neighbours_conflict(A, 2, [overlap]), Some(Overlaps));
        assert_eq!(
            neighbours_conflict(A, 2, [(A + 8, SITE_ACTIVE, 2, true)]),
            None
        );
    }
    #[test]
    fn a_stale_site_counts_as_published_unless_its_jump_is_provably_gone() {
        use NeighbourConflict::InsidePublishedPatch as Inside;
        let word = |bytes: [u8; 8]| u64::from_le_bytes(bytes);
        // Codex's arrangement: a cross-line jump at P = page end - 2.
        let original = [0x0f, 0xa2, 0x0f, 0xa2, 0x90, 0xf8, 0x90, 0x90];
        let published = [0xe9, 0xfd, 0x0f, 0xa2, 0xff, 0xf8, 0x90, 0x90];
        let words = Some((word(original), word(published)));
        // All of it in place (a no-op mremap): survives.
        assert!(stale_jump_survives(words, Some(published)));
        // The first page replaced with its original contents, the second
        // still holding the displacement's high bytes: survives.
        let partial = [0x0f, 0xa2, 0x0f, 0xa2, 0xff, 0xf8, 0x90, 0x90];
        assert!(stale_jump_survives(words, Some(partial)));
        // A surviving INT3 guard, even where the patch kept the byte: survives.
        let guarded = [0xcc, 0xcc, 0x0f, 0xa2, 0x90, 0xf8, 0x90, 0x90];
        assert!(stale_jump_survives(words, Some(guarded)));
        let guard_on_unchanged_byte = [0x0f, 0xa2, 0xcc, 0xa2, 0x90, 0xf8, 0x90, 0x90];
        assert!(stale_jump_survives(words, Some(guard_on_unchanged_byte)));
        // Nothing recorded, or not all eight bytes readable: survives.
        assert!(stale_jump_survives(None, Some(original)));
        assert!(stale_jump_survives(words, None));
        // Fully restored, or replaced by unrelated code: gone.
        assert!(!stale_jump_survives(words, Some(original)));
        let unrelated = [0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3, 0x90];
        assert!(!stale_jump_survives(words, Some(unrelated)));

        // Never published: nothing can survive, whatever the bytes.
        assert!(!earlier_patch_survives(false, None, Some(published)));
        assert!(earlier_patch_survives(true, words, Some(partial)));
        assert!(earlier_patch_survives(true, None, Some(original)));
        assert!(!earlier_patch_survives(true, words, Some(original)));
        assert!(site_footprint(SITE_ACTIVE, false));
        // A FALLBACK refused before any change wrote nothing.
        for state in [
            0,
            SITE_INSTALLING,
            SITE_STALE,
            SITE_UNPATCHABLE,
            SITE_FALLBACK,
        ] {
            assert!(site_footprint(state, true));
            assert!(!site_footprint(state, false));
        }
        // The partially replaced jump at P still refuses a CPUID at P + 2 as
        // touched, whether P is STALE or was reclaimed (INSTALLING) after the
        // restored CPUID at P executed first; once provably gone, a STALE P
        // constrains nothing.
        const P: u64 = 0x1000_0ffe;
        let survives = earlier_patch_survives(true, words, Some(partial));
        for state in [SITE_STALE, SITE_INSTALLING, SITE_UNPATCHABLE] {
            let site = (P, state, 2, site_footprint(state, survives));
            assert_eq!(
                neighbours_conflict(P + 2, 2, [site]),
                Some(Inside),
                "state={state}"
            );
        }
        let gone = earlier_patch_survives(true, words, Some(original));
        let site = (P, SITE_STALE, 2, site_footprint(SITE_STALE, gone));
        assert_eq!(neighbours_conflict(P + 2, 2, [site]), None);
    }
    #[test]
    fn maps_line_private_reads_the_sharing_flag_of_the_containing_mapping() {
        let private = b"55c2c6466000-55c2c6467000 r-xp 00017000 00:2f 1234      /bin/coreutils";
        let shared = b"7f0000000000-7f0000001000 r-xs 00000000 00:05 99   /memfd:jit (deleted)";
        assert_eq!(
            maps_line_private(private, 0x55c2_c646_6d3a),
            Some((true, 0x55c2_c646_7000, libc::PROT_READ | libc::PROT_EXEC))
        );
        assert_eq!(
            maps_line_private(shared, 0x7f00_0000_0010),
            Some((false, 0x7f00_0000_1000, libc::PROT_READ | libc::PROT_EXEC))
        );
        assert_eq!(maps_line_private(private, 0x55c2_c646_7000), None);
        assert_eq!(maps_line_private(b"garbage", 0), None);
    }
    #[test]
    fn installation_blocks_every_blockable_signal_and_restores_the_mask() {
        let current = || {
            let mut mask = 0_u64;
            let result = unsafe {
                libc::syscall(
                    libc::SYS_rt_sigprocmask,
                    libc::SIG_BLOCK,
                    core::ptr::null::<u64>(),
                    &raw mut mask,
                    core::mem::size_of::<u64>(),
                )
            };
            assert_eq!(result, 0);
            mask
        };
        let bit = |signal: libc::c_int| 1_u64 << (signal - 1);
        let before = current();
        {
            let _blocked = AsyncSignalsBlocked::new().unwrap();
            let during = current();
            // Every number a guest handler could be installed for, the fault
            // signals included (a guest timer can deliver SIGILL).
            for signal in (1..=64).filter(|signal| ![libc::SIGKILL, libc::SIGSTOP].contains(signal))
            {
                assert_ne!(during & bit(signal), 0, "signal {signal} must be blocked");
            }
        }
        assert_eq!(
            current(),
            before,
            "the previous mask must be restored exactly"
        );
    }

    #[cfg(feature = "fixed-syscall-gates")]
    #[test]
    fn fixed_gate_artifact_refuses_non_fulltool_before_publication() {
        assert!(!reverie_inguest::trap::fixed_gates_published());
        assert!(super::initialize_from_selected_value(None).is_ok());
        for mode in ["compat", "strace", "noop", "getpid"] {
            let error = super::initialize_from_selected_value(Some(OsStr::new(mode))).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported, "{mode}");
            assert!(!reverie_inguest::trap::fixed_gates_published());
        }
    }
}
