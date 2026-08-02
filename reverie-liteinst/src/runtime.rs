use core::arch::global_asm;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::ffi::OsStr;
use std::io;
use std::ptr;
use std::sync::OnceLock;

use liteinst2::patcher::prepare_live_patching;
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::HookContext;
use liteinst2::trampoline::HookSite;
use liteinst2::trampoline::InstalledHook;
use liteinst2::trampoline::TrampolineArena;
use reverie_preload::BuiltinTool;
use reverie_preload::dispatch::SyscallDispatcher;
use reverie_preload::dispatch::SyscallEvent as PreloadSyscallEvent;
use reverie_preload::dispatch::is_fork_like;
use reverie_preload::fork::ForkHook;
use reverie_preload::lifecycle::InProcessSeccomp;
use reverie_preload::lifecycle::RuntimeConfig;
use reverie_preload::trap::raw_syscall6;

use crate::COMPAT_EVENT_COOKIE_ENV;
use crate::COMPAT_EVENT_FD_ENV;

pub(crate) const HOST_RUNTIME_ENV: &str = "REVERIE_LITEINST_HOST_RUNTIME";
pub(crate) const HOST_BEGIN_MARKER: u64 = 0x7265_766c_6900_0001;
pub(crate) const HOST_READY_MARKER: u64 = 0x7265_766c_6900_0002;
pub(crate) const HOST_HELPER_RETURN_MARKER: u64 = 0x7265_766c_6900_0003;
pub(crate) const HOST_SYSCALL_MARKER: u64 = 0x7265_766c_6900_0004;
const HOST_HANDSHAKE_VERSION: u64 = 4;
const HOST_INSTALL_RESULT_VERSION: u64 = 2;
const HOST_HELPER_STACK_BYTES: usize = 256 * 1024;

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_host_begin
    .type reverie_liteinst_host_begin,@function
reverie_liteinst_host_begin:
    mov rax, 0x7265766c69000001
    int3
    .global reverie_liteinst_host_begin_rip
reverie_liteinst_host_begin_rip:
    ret
    .size reverie_liteinst_host_begin, .-reverie_liteinst_host_begin

    .p2align 4
    .global reverie_liteinst_host_ready
    .type reverie_liteinst_host_ready,@function
reverie_liteinst_host_ready:
    mov rax, 0x7265766c69000002
    int3
    .global reverie_liteinst_host_ready_rip
reverie_liteinst_host_ready_rip:
    ret
    .size reverie_liteinst_host_ready, .-reverie_liteinst_host_ready

    .p2align 4
    .global reverie_liteinst_host_helper_return
    .type reverie_liteinst_host_helper_return,@function
reverie_liteinst_host_helper_return:
    mov r10, 0x7265766c69000003
    int3
    .global reverie_liteinst_host_helper_return_rip
reverie_liteinst_host_helper_return_rip:
    ret
    .size reverie_liteinst_host_helper_return, .-reverie_liteinst_host_helper_return

    .p2align 4
    .global reverie_liteinst_host_syscall_trap
    .type reverie_liteinst_host_syscall_trap,@function
reverie_liteinst_host_syscall_trap:
    mov rax, 0x7265766c69000004
    int3
    .global reverie_liteinst_host_syscall_trap_rip
reverie_liteinst_host_syscall_trap_rip:
    ret
    .size reverie_liteinst_host_syscall_trap, .-reverie_liteinst_host_syscall_trap

    .p2align 4
    .global reverie_liteinst_host_syscall_trap_call
    .hidden reverie_liteinst_host_syscall_trap_call
    .type reverie_liteinst_host_syscall_trap_call,@function
reverie_liteinst_host_syscall_trap_call:
    call reverie_liteinst_host_syscall_trap
    .global reverie_liteinst_host_syscall_trap_return_rip
reverie_liteinst_host_syscall_trap_return_rip:
    ret
    .size reverie_liteinst_host_syscall_trap_call, .-reverie_liteinst_host_syscall_trap_call
"#
);

unsafe extern "C" {
    fn reverie_liteinst_host_begin(frame: *const HostHandshakeFrame);
    static reverie_liteinst_host_begin_rip: u8;
    fn reverie_liteinst_host_ready(frame: *const HostHandshakeFrame);
    static reverie_liteinst_host_ready_rip: u8;
    fn reverie_liteinst_host_helper_return();
    static reverie_liteinst_host_helper_return_rip: u8;
    fn reverie_liteinst_host_syscall_trap_call(frame: *mut HostSyscallFrame);
    fn reverie_liteinst_host_syscall_trap(frame: *mut HostSyscallFrame);
    static reverie_liteinst_host_syscall_trap_rip: u8;
    static reverie_liteinst_host_syscall_trap_return_rip: u8;
}

// TODO-HUMAN-REVIEW(PR-270): Review raw hot-trap test/provenance ABI. This
// exposes an address for negative testing; caller validation, not secrecy, is
// the accidental-collision boundary.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_host_syscall_trap_address() -> *const libc::c_void {
    reverie_liteinst_host_syscall_trap as *const libc::c_void
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct HostHandshakeFrame {
    version: u64,
    begin_rip: u64,
    ready_rip: u64,
    install_helper: u64,
    helper_stack_top: u64,
    helper_return: u64,
    helper_return_rip: u64,
    syscall_trap_rip: u64,
    syscall_trap_return_rip: u64,
    install_result: u64,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct HostInstallResult {
    version: u64,
    site_start: u64,
    site_len: u64,
    relocated_tail: u64,
    trampoline_start: u64,
    trampoline_len: u64,
    arena_writable_start: u64,
    arena_writable_len: u64,
    arena_executable_start: u64,
    arena_executable_len: u64,
    instruction_len: u64,
    straddle_prefix: u64,
    complete: u64,
}

#[repr(align(16))]
struct HostHelperStack([u8; HOST_HELPER_STACK_BYTES]);

static mut HOST_HELPER_STACK: HostHelperStack = HostHelperStack([0; HOST_HELPER_STACK_BYTES]);
static mut HOST_INSTALL_RESULT: HostInstallResult = HostInstallResult {
    version: 0,
    site_start: 0,
    site_len: 0,
    relocated_tail: 0,
    trampoline_start: 0,
    trampoline_len: 0,
    arena_writable_start: 0,
    arena_writable_len: 0,
    arena_executable_start: 0,
    arena_executable_len: 0,
    instruction_len: 0,
    straddle_prefix: 0,
    complete: 0,
};

const UNSET_RESULT: i64 = i64::MIN;
const SYS_IO_PGETEVENTS: i64 = 333;
const TOOL_STRACE: u8 = 1;
const TOOL_COMPAT: u8 = 2;
const TOOL_REVERIE: u8 = 3;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared reverie-preload built-in tool selection.
/// `REVERIE_LITEINST_TOOL` value selecting the shared passthrough built-in.
pub const TOOL_PASSTHROUGH: &str = "passthrough";
/// `REVERIE_LITEINST_TOOL` value selecting the shared getpid-spoofing built-in.
pub const TOOL_SPOOF_GETPID: &str = "spoof-getpid";
const EVENT_CHANNEL_IDENTITY_FAILURE_STATUS: i32 = 120;
const EVENT_CHANNEL_WRITE_FAILURE_STATUS: i32 = 121;
const MAX_PATCH_SITES: usize = 4096;
const ARENA_SLOTS: usize = 128;
const PATCH_SNAPSHOT_BYTES: usize = 64;
const SITE_INSTALLING: u8 = 1;
const SITE_ACTIVE: u8 = 2;
const SITE_FALLBACK: u8 = 3;
const SITE_STALE: u8 = 4;

static TOOL_MODE: AtomicU8 = AtomicU8::new(0);
static EVENT_FD: AtomicI32 = AtomicI32::new(libc::STDERR_FILENO);
static COORDINATOR_FD: AtomicI32 = AtomicI32::new(-1);
static EVENT_COOKIE: AtomicU64 = AtomicU64::new(0);
static EVENT_DEVICE: AtomicU64 = AtomicU64::new(0);
static EVENT_INODE: AtomicU64 = AtomicU64::new(0);

#[thread_local]
static mut CURRENT_EVENT: *mut SyscallEvent = ptr::null_mut();

static ARENAS: OnceLock<Vec<RuntimeArena>> = OnceLock::new();
static SITES: OnceLock<Box<[SiteSlot]>> = OnceLock::new();
static PAGE_SIZE: AtomicU64 = AtomicU64::new(0);
static INSTALL_HELD: AtomicBool = AtomicBool::new(false);

pub(crate) fn reserve_coordinator_fd(fd: libc::c_int) -> io::Result<()> {
    COORDINATOR_FD
        .compare_exchange(-1, fd, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "coordinator FD reserved twice",
            )
        })
}

struct RuntimeArena {
    mapping_start: u64,
    mapping_end: u64,
    writable_start: u64,
    writable_end: u64,
    executable_start: u64,
    executable_end: u64,
    arena: TrampolineArena,
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
    mapping_end: AtomicU64,
    trap_count: AtomicU64,
    hook_count: AtomicU64,
    instruction_len: AtomicU8,
    straddle_prefix: AtomicU8,
}

impl SiteSlot {
    fn new() -> Self {
        Self {
            address: AtomicU64::new(0),
            state: AtomicU8::new(0),
            hook: AtomicPtr::new(ptr::null_mut()),
            mapping_end: AtomicU64::new(0),
            trap_count: AtomicU64::new(0),
            hook_count: AtomicU64::new(0),
            instruction_len: AtomicU8::new(0),
            straddle_prefix: AtomicU8::new(0),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SyscallEvent {
    pub(crate) number: i64,
    pub(crate) args: [u64; 6],
    pub(crate) instruction_pointer: u64,
    pub(crate) result: i64,
    pub(crate) context: usize,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared reverie-preload built-in tool parser.
/// Parses a shared `reverie-preload` [`BuiltinTool`] from a `REVERIE_LITEINST_TOOL`
/// value, returning `None` for the LiteInst-native `strace`/`compat` modes and
/// any other value.
///
/// This is the LiteInst analog of e9patch's `builtin_tool_from_env_value`: it
/// lets the single `REVERIE_LITEINST_TOOL` selector name a shared built-in
/// installed verbatim through [`reverie_preload::install_builtin`], bypassing the
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
/// Installs a shared `reverie-preload` built-in tool verbatim.
///
/// Unlike [`install_runtime`], this does NOT prepare LiteInst instrumentation:
/// the shared built-ins install their own SIGSYS handler and seccomp filter via
/// [`reverie_preload::install_builtin`] and do not patch syscall sites. This
/// proves the LiteInst fallback/trap path can service and MUTATE a syscall
/// result (for example `getpid` -> `SPOOF_PID`), matching e9patch's
/// `install_builtin_runtime`.
///
/// # Safety
///
/// The dynamic loader must call this exactly once before application threads
/// start; it installs process-wide, irreversible seccomp state.
pub(crate) unsafe fn install_builtin_runtime(tool: BuiltinTool) -> io::Result<()> {
    unsafe { reverie_preload::install_builtin(tool) }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review launcher-selected shared RuntimeConfig alt-stack knob.
/// Environment variable selecting the shared [`RuntimeConfig::use_alt_stack`]
/// knob for the in-guest runtime's `SIGSYS` handler.
///
/// The [`RuntimeConfig`] and the controller that honors it live in
/// `reverie-preload` and are reviewed exactly once; both ld-preload backends
/// install through that same shared seam. Only the env-var spelling is
/// LiteInst's, exactly as with `REVERIE_LITEINST_TOOL`. This is the LiteInst
/// analog of e9patch's `REVERIE_E9PATCH_ALT_STACK`.
///
/// When unset the shared default applies ([`RuntimeConfig::default`], alt stack
/// **on**). It applies to the LiteInst-dispatcher install path
/// ([`install_runtime`], used by the `strace`/`compat`/Detcore modes); a shared
/// [`BuiltinTool`] runs through `install_builtin`, which uses the shared default.
pub const ALT_STACK_ENV: &str = "REVERIE_LITEINST_ALT_STACK";

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
    Ok(RuntimeConfig { use_alt_stack })
}

pub(crate) fn initialize_from_environment() -> io::Result<()> {
    if std::env::var_os(HOST_RUNTIME_ENV).as_deref() == Some(OsStr::new("1")) {
        return initialize_host_runtime();
    }
    let tool_value = std::env::var_os("REVERIE_LITEINST_TOOL");
    // Prefer a shared reverie-preload built-in when the selector names one, so a
    // single env var is a superset of the LiteInst-native strace/compat modes
    // (matches e9patch's single TOOL_ENV selecting shared built-ins).
    if let Some(value) = tool_value.as_deref()
        && let Some(tool) = builtin_tool_from_env_value(value)
    {
        // SAFETY: the loader calls this once before application threads start.
        return unsafe { install_builtin_runtime(tool) };
    }
    let mode = match tool_value.as_deref() {
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

    install_runtime()
}

fn host_handshake_frame() -> HostHandshakeFrame {
    // SAFETY: this only forms the address of the dedicated static helper stack;
    // it neither reads nor creates a Rust reference to its mutable contents.
    let stack_start = unsafe { core::ptr::addr_of_mut!(HOST_HELPER_STACK.0) as *mut u8 as usize };
    HostHandshakeFrame {
        version: HOST_HANDSHAKE_VERSION,
        begin_rip: core::ptr::addr_of!(reverie_liteinst_host_begin_rip) as usize as u64,
        ready_rip: core::ptr::addr_of!(reverie_liteinst_host_ready_rip) as usize as u64,
        install_helper: reverie_liteinst_install_site_for_ptrace as *const () as usize as u64,
        helper_stack_top: (stack_start + HOST_HELPER_STACK_BYTES) as u64,
        helper_return: reverie_liteinst_host_helper_return as *const () as usize as u64,
        helper_return_rip: core::ptr::addr_of!(reverie_liteinst_host_helper_return_rip) as usize
            as u64,
        syscall_trap_rip: core::ptr::addr_of!(reverie_liteinst_host_syscall_trap_rip) as usize
            as u64,
        syscall_trap_return_rip: core::ptr::addr_of!(reverie_liteinst_host_syscall_trap_return_rip)
            as usize as u64,
        install_result: core::ptr::addr_of!(HOST_INSTALL_RESULT) as usize as u64,
    }
}

fn initialize_host_runtime() -> io::Result<()> {
    let frame = host_handshake_frame();
    // SAFETY: the launcher validates this exact DSO/RIP/frame before suppressing
    // the trap. The function returns normally after ptrace resumes the tracee.
    unsafe { reverie_liteinst_host_begin(&frame) };
    prepare_instrumentation()?;
    // SAFETY: identical handshake contract; all helper state is now published.
    unsafe { reverie_liteinst_host_ready(&frame) };
    Ok(())
}

pub(crate) fn initialize_reverie_tool() -> io::Result<()> {
    TOOL_MODE.store(TOOL_REVERIE, Ordering::Release);
    install_runtime()
}

fn install_runtime() -> io::Result<()> {
    prepare_instrumentation()?;
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-254): Review launcher-selected RuntimeConfig at the install seam.
    let config = runtime_config_from_env()?;
    unsafe { reverie_preload::install(Box::new(LiteinstDispatcher), &InProcessSeccomp, &config) }
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
        unsafe { libc::fcntl(fd, libc::F_GETFL) }
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
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
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
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
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
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    Ok(maps
        .lines()
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
        .collect())
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
    prepare_live_patching().map_err(|error| io::Error::other(error.to_string()))?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = u64::try_from(page_size)
        .ok()
        .filter(|size| size.is_power_of_two())
        .ok_or_else(|| io::Error::other("invalid operating-system page size"))?;
    PAGE_SIZE.store(page_size, Ordering::Release);

    let sites = (0..MAX_PATCH_SITES)
        .map(|_| SiteSlot::new())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    SITES
        .set(sites)
        .map_err(|_| io::Error::other("LiteInst site registry initialized twice"))?;

    let maps = std::fs::read_to_string("/proc/self/maps")?;
    let mut arenas = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some(permissions) = fields.next() else {
            continue;
        };
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
        let (writable, executable) = discover_arena_aliases(&before, &after)?;
        arenas.push(RuntimeArena {
            mapping_start,
            mapping_end,
            writable_start: writable.start,
            writable_end: writable.end,
            executable_start: executable.start,
            executable_end: executable.end,
            arena,
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
    let Some(sites) = SITES.get() else {
        return;
    };
    for site in sites {
        let address = site.address.load(Ordering::Acquire);
        if start <= address && address < end {
            site.mapping_end.store(replacement_end, Ordering::Release);
            let state = site.state.load(Ordering::Acquire);
            if matches!(state, SITE_ACTIVE | SITE_FALLBACK) {
                site.state.store(SITE_STALE, Ordering::Release);
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
/// Total number of syscalls that reached [`LiteinstDispatcher`]'s escape surface
/// — a trapped site the runtime could not route to the Tool (un-patchable
/// `SITE_FALLBACK`, or an unclaimable site) and therefore failed closed with
/// `EOPNOTSUPP`.
static FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-249): Review public fallback-surface observability counters.
/// Per-syscall-number escape counts, indexed by syscall number.
static FALLBACK_BY_NUMBER: [AtomicU64; TRACKED_SYSCALLS] =
    [const { AtomicU64::new(0) }; TRACKED_SYSCALLS];

/// Record that one syscall reached the fail-closed escape surface.
///
/// Anything reaching this point is, by construction, a trapped syscall the
/// runtime could not route to the Tool, so this counts the size of LiteInst's
/// residual escape surface. It is the by-syscall-number analog of the per-site
/// `trap`/`hook` counters ([`site_counts`]) and the direct counterpart of
/// reverie-e9patch's `record_fallback_dispatch` (round 4), keyed the same way so
/// the two ld-preload backends expose a symmetric fallback-surface metric.
///
/// Async-signal-safe: only relaxed atomic increments, so it is safe to call from
/// the `SIGSYS` dispatch path. It does not change the forwarding decision.
pub(crate) fn record_fallback_dispatch(number: i64) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
    if let Ok(index) = usize::try_from(number)
        && index < TRACKED_SYSCALLS
    {
        FALLBACK_BY_NUMBER[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// Total syscalls that failed closed on the escape surface.
///
/// A large value relative to the guest's total syscall count indicates a large
/// residual escape surface — trapped sites the runtime could not route to the
/// Tool. For Detcore (`TOOL_REVERIE`) this directly bounds the set of syscalls
/// (e.g. a libc-internal `getrandom`) that bypass determinism, so a nonzero
/// count is a determinism-completeness signal, not merely a perf one.
pub(crate) fn fallback_dispatch_count() -> u64 {
    FALLBACK_TOTAL.load(Ordering::Relaxed)
}

/// Number of times syscall `number` reached the escape surface.
///
/// Returns `0` for a negative number or one at or above [`TRACKED_SYSCALLS`],
/// which are only ever reflected in [`fallback_dispatch_count`].
pub(crate) fn fallback_syscall_count(number: i64) -> u64 {
    match usize::try_from(number) {
        Ok(index) if index < TRACKED_SYSCALLS => FALLBACK_BY_NUMBER[index].load(Ordering::Relaxed),
        _ => 0,
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-260): Review the fork-child per-process observability reset.
/// Reset every fallback-surface counter to zero for the current process.
///
/// LiteInst's observability counters — the process-wide [`FALLBACK_TOTAL`], the
/// per-syscall-number [`FALLBACK_BY_NUMBER`], and each patch site's per-site
/// `trap`/`hook` counts ([`site_counts`]) — are process-global. A `fork`/`clone`
/// child copy-on-write inherits the parent's accumulated values, so without a
/// reset the child would report the parent's residual surface and hook activity
/// as its own. This is the same per-process runtime state the shared
/// [`ForkHook`] seam ([`reverie_preload::fork`]) exists to re-establish in the
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
pub(crate) fn reset_fallback_observability() {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_TOTAL.store(0, Ordering::Relaxed);
    for slot in &FALLBACK_BY_NUMBER {
        slot.store(0, Ordering::Relaxed);
    }
    if let Some(sites) = SITES.get() {
        for site in sites {
            site.trap_count.store(0, Ordering::Relaxed);
            site.hook_count.store(0, Ordering::Relaxed);
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-260): Review the shared fork-following seam reuse.
/// The shared fork-following hook: in the child of a successful fork-like
/// syscall, reset this process's fallback observability (see
/// [`reset_fallback_observability`]).
///
/// LiteInst hosts its own `SIGSYS` dispatcher rather than the shared
/// [`PassthroughDispatcher`](reverie_preload::dispatch::PassthroughDispatcher),
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

struct InstallGuard;

#[derive(Clone, Copy)]
enum PatchPublication {
    /// The stopped-tracee helper is the only thread able to reach live code.
    Quiescent,
    /// Other application threads may fetch the site during publication.
    Concurrent,
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

unsafe fn install_site_hook(
    address: u64,
    slot: &'static SiteSlot,
    callback: liteinst2::trampoline::HookCallback,
    publication: PatchPublication,
) -> io::Result<HostInstallResult> {
    let _install_guard = lock_installation()?;
    let _allocation_scope = crate::patch_alloc::enter();
    let arena = arena_for(address)
        .ok_or_else(|| io::Error::other("no reachable LiteInst arena for syscall site"))?;
    let mut mapping_end = slot.mapping_end.load(Ordering::Acquire);
    if mapping_end <= address {
        mapping_end = arena.mapping_end;
        slot.mapping_end.store(mapping_end, Ordering::Release);
    }
    let available = usize::try_from(mapping_end - address)
        .unwrap_or(0)
        .min(PATCH_SNAPSHOT_BYTES);
    if available < liteinst2::patcher::WORD_PATCH_BYTES {
        return Err(io::Error::other(
            "syscall site is too close to its executable mapping end",
        ));
    }
    // SAFETY: arena_for proved this byte range lies in a live executable VMA.
    let candidate =
        unsafe { core::slice::from_raw_parts(address as usize as *const u8, available) };
    if candidate.get(..2) != Some(&[0x0F, 0x05]) {
        return Err(io::Error::other("SIGSYS site is not an x86-64 syscall"));
    }
    let scanner = InstructionScanner::default();
    let scan = scanner
        .scan_prefix(candidate, address, liteinst2::patcher::WORD_PATCH_BYTES)
        .map_err(|error| io::Error::other(error.to_string()))?;
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

    // Publish candidate metadata before installation so a failed helper can
    // still classify its explicit ptrace fallback branch.
    let candidate_result = HostInstallResult {
        version: HOST_INSTALL_RESULT_VERSION,
        site_start: address,
        site_len: liteinst2::patcher::WORD_PATCH_BYTES as u64,
        instruction_len: instruction_len as u64,
        straddle_prefix: straddle_prefix as u64,
        ..HostInstallResult::default()
    };
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(HOST_INSTALL_RESULT),
            candidate_result,
        );
    }
    slot.instruction_len
        .store(instruction_len as u8, Ordering::Release);
    slot.straddle_prefix
        .store(straddle_prefix as u8, Ordering::Release);
    let staleness = match publication {
        PatchPublication::Quiescent => None,
        PatchPublication::Concurrent => Some(crate::straddler::budget_for_patch(
            address as usize,
            scanner.cache_line_size(),
        )?),
    };
    let code = scan.snapshot();

    unsafe {
        set_text_protection(
            address,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;
    }
    let site = HookSite::new(
        &scanner,
        &scan,
        code,
        address,
        address,
        address as usize as *mut u8,
    );
    let installed = match publication {
        PatchPublication::Quiescent => unsafe {
            InstalledHook::install_replacing_first_in_arena_quiescent(site, callback, &arena.arena)
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
    let installed = match installed {
        Ok(installed) => installed,
        Err(error) => {
            let _ = unsafe { set_text_protection(address, libc::PROT_READ | libc::PROT_EXEC) };
            return Err(io::Error::other(error.to_string()));
        }
    };
    let activation = match publication {
        PatchPublication::Concurrent => installed.activate(),
        // SAFETY: the ptrace controller serializes this helper while every
        // other tracee thread is stopped. Hermit likewise schedules only one
        // guest thread at a time, so no other thread can fetch the site.
        PatchPublication::Quiescent => unsafe { installed.activate_quiescent() },
    };
    if let Err(error) = activation {
        let _ = unsafe { set_text_protection(address, libc::PROT_READ | libc::PROT_EXEC) };
        return Err(io::Error::other(error.to_string()));
    }
    unsafe {
        set_text_protection(address, libc::PROT_READ | libc::PROT_EXEC)?;
    }

    let relocated_tail = installed.trampoline().relocated_tail_address();
    let trampoline_start = installed.trampoline().address();
    let trampoline_len = installed.trampoline().allocation_len() as u64;
    let result = HostInstallResult {
        version: HOST_INSTALL_RESULT_VERSION,
        site_start: address,
        site_len: liteinst2::patcher::WORD_PATCH_BYTES as u64,
        relocated_tail,
        trampoline_start,
        trampoline_len,
        arena_writable_start: arena.writable_start,
        arena_writable_len: arena.writable_end - arena.writable_start,
        arena_executable_start: arena.executable_start,
        arena_executable_len: arena.executable_end - arena.executable_start,
        instruction_len: instruction_len as u64,
        straddle_prefix: straddle_prefix as u64,
        complete: 1,
    };
    let installed = Box::into_raw(Box::new(installed));
    slot.hook.store(installed, Ordering::Release);
    slot.instruction_len
        .store(instruction_len as u8, Ordering::Release);
    slot.straddle_prefix
        .store(straddle_prefix as u8, Ordering::Release);
    slot.state.store(SITE_ACTIVE, Ordering::Release);
    Ok(result)
}

// TODO-HUMAN-REVIEW(PR-270): Review stopped-tracee patch helper ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_liteinst_install_site_for_ptrace(address: u64) -> i64 {
    // SAFETY: the ptrace helper is serialized and the controller reads this
    // fixed-size record only after the helper-return trap.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(HOST_INSTALL_RESULT),
            HostInstallResult::default(),
        );
    }
    if let Some(site) = find_site(address) {
        // The controller calls this helper only after observing the original
        // syscall bytes at the address. If a prior generation is still marked
        // active, its mapping was replaced and the old hook is no longer
        // installed. Transition it to STALE so claim_site installs a new hook
        // rather than returning the prior generation's relocated tail.
        let instruction = unsafe { core::ptr::read_unaligned(address as usize as *const u16) };
        if instruction == 0x050f
            && matches!(
                site.state.load(Ordering::Acquire),
                SITE_ACTIVE | SITE_FALLBACK
            )
        {
            site.state.store(SITE_STALE, Ordering::Release);
        }
    }
    let Some((site, claimed)) = claim_site(address) else {
        return -i64::from(libc::ENOSPC);
    };
    site.trap_count.fetch_add(1, Ordering::Relaxed);
    let mut install_result = None;
    if claimed {
        match unsafe {
            install_site_hook(
                address,
                site,
                host_syscall_hook,
                PatchPublication::Quiescent,
            )
        } {
            Ok(result) => install_result = Some(result),
            Err(_) => site.state.store(SITE_FALLBACK, Ordering::Release),
        }
    }
    while matches!(site.state.load(Ordering::Acquire), 0 | SITE_INSTALLING) {
        core::hint::spin_loop();
    }
    if site.state.load(Ordering::Acquire) == SITE_ACTIVE {
        let result = install_result.or_else(|| {
            let hook = site.hook.load(Ordering::Acquire);
            if hook.is_null() {
                return None;
            }
            let hook = unsafe { &*hook };
            let arena = arena_for(address)?;
            Some(HostInstallResult {
                version: HOST_INSTALL_RESULT_VERSION,
                site_start: address,
                site_len: liteinst2::patcher::WORD_PATCH_BYTES as u64,
                relocated_tail: hook.trampoline().relocated_tail_address(),
                trampoline_start: hook.trampoline().address(),
                trampoline_len: hook.trampoline().allocation_len() as u64,
                arena_writable_start: arena.writable_start,
                arena_writable_len: arena.writable_end - arena.writable_start,
                arena_executable_start: arena.executable_start,
                arena_executable_len: arena.executable_end - arena.executable_start,
                instruction_len: u64::from(site.instruction_len.load(Ordering::Acquire)),
                straddle_prefix: u64::from(site.straddle_prefix.load(Ordering::Acquire)),
                complete: 1,
            })
        });
        if let Some(result) = result {
            // SAFETY: see the reset above. Publishing `complete` is part of the
            // same stopped-helper call and the host validates every field.
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(HOST_INSTALL_RESULT), result);
            }
        }
        result
            .and_then(|result| i64::try_from(result.relocated_tail).ok())
            .unwrap_or(-i64::from(libc::EOVERFLOW))
    } else {
        -i64::from(libc::EOPNOTSUPP)
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review nested Tool syscall guards and raw forwarding.
#[repr(C)]
#[derive(Default)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

pub(crate) struct SignalInstallGuard {
    restore_mask: u64,
}

impl Drop for SignalInstallGuard {
    fn drop(&mut self) {
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const self.restore_mask) as u64,
                    0,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            unsafe { exit_now(126) };
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review atomic signal-state preparation.
pub(crate) fn prepare_guest_signal_state() -> io::Result<SignalInstallGuard> {
    let sigsys = 1_u64 << (libc::SIGSYS - 1);
    let install_mask = u64::MAX;
    let mut previous_mask = 0_u64;
    let result = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_SETMASK as u64,
                (&raw const install_mask) as u64,
                (&raw mut previous_mask) as u64,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    if result < 0 {
        return Err(io::Error::from_raw_os_error((-result) as i32));
    }
    let guard = SignalInstallGuard {
        restore_mask: previous_mask & !sigsys,
    };

    for signal in 1..=64 {
        if matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
            continue;
        }
        let mut action = KernelSigaction::default();
        let result = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigaction,
                [
                    signal as u64,
                    0,
                    (&raw mut action) as u64,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error((-result) as i32));
        }
        if action.handler != libc::SIG_DFL as u64 && action.handler != libc::SIG_IGN as u64 {
            let default_action = KernelSigaction::default();
            let result = unsafe {
                raw_syscall6(
                    libc::SYS_rt_sigaction,
                    [
                        signal as u64,
                        (&raw const default_action) as u64,
                        0,
                        core::mem::size_of::<u64>() as u64,
                        0,
                        0,
                    ],
                )
            };
            if result < 0 {
                return Err(io::Error::from_raw_os_error((-result) as i32));
            }
        }
    }
    Ok(guard)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review fault-safe guest signal-action decoding.
pub(crate) fn signal_action_supported(number: i64, args: [u64; 6]) -> bool {
    if number != libc::SYS_rt_sigaction || args[1] == 0 {
        return true;
    }
    if args[0] == libc::SIGSYS as u64 {
        return false;
    }

    let mut handler = 0_u64;
    let local = libc::iovec {
        iov_base: (&raw mut handler).cast(),
        iov_len: core::mem::size_of::<u64>(),
    };
    let remote = libc::iovec {
        iov_base: args[1] as usize as *mut libc::c_void,
        iov_len: core::mem::size_of::<u64>(),
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
    read == core::mem::size_of::<u64>() as i64
        && matches!(handler, value if value == libc::SIG_DFL as u64 || value == libc::SIG_IGN as u64)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-133): Review nested Tool syscall guards and raw forwarding.
fn forward_nested_tool_syscall(event: &mut SyscallEvent) {
    let unsupported_process =
        // AUTONOMOUS-BOT-IMPLEMENTED
        event.number == libc::SYS_clone
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_clone3
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_fork
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_vfork
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_execve
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_execveat;
    let unsupported_signal_state =
        // AUTONOMOUS-BOT-IMPLEMENTED
        event.number == libc::SYS_rt_sigaction
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_rt_sigprocmask
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_sigaltstack
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_rt_sigsuspend
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_pselect6
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_ppoll
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_epoll_pwait
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == libc::SYS_epoll_pwait2
        // AUTONOMOUS-BOT-IMPLEMENTED
        || event.number == SYS_IO_PGETEVENTS;
    if unsupported_process {
        event.result = -i64::from(libc::ENOTSUP);
    } else if unsupported_signal_state {
        event.result = -i64::from(libc::EPERM);
    } else if !(protect_runtime_control(event) || unsafe { protect_coordinator_channel(event) }) {
        event.result = unsafe { raw_syscall6(event.number, event.args) };
        observe_mapping_generation(event);
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct HostSyscallFrame {
    flags: u64,
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    rsp: u64,
    rip: u64,
}

impl HostSyscallFrame {
    const FLAGS_OF: u64 = 0x0001;
    const FLAGS_CF: u64 = 0x0100;
    const FLAGS_PF: u64 = 0x0400;
    const FLAGS_AF: u64 = 0x1000;
    const FLAGS_ZF: u64 = 0x4000;
    const FLAGS_SF: u64 = 0x8000;
    const STATUS_RFLAGS: u64 = 0x0001 | 0x0004 | 0x0010 | 0x0040 | 0x0080 | 0x0800;

    fn from_context(context: &HookContext) -> Self {
        Self {
            flags: Self::encode_flags(context.rflags),
            r15: context.r15,
            r14: context.r14,
            r13: context.r13,
            r12: context.r12,
            r11: context.r11,
            r10: context.r10,
            r9: context.r9,
            r8: context.r8,
            rdi: context.rdi,
            rsi: context.rsi,
            rbp: context.rbp,
            rbx: context.rbx,
            rdx: context.rdx,
            rcx: context.rcx,
            rax: context.rax,
            rsp: context.stack_pointer,
            rip: context.instruction_pointer,
        }
    }

    fn copy_to_context(self, context: &mut HookContext, original_rflags: u64) {
        context.r15 = self.r15;
        context.r14 = self.r14;
        context.r13 = self.r13;
        context.r12 = self.r12;
        context.r11 = self.r11;
        context.r10 = self.r10;
        context.r9 = self.r9;
        context.r8 = self.r8;
        context.rdi = self.rdi;
        context.rsi = self.rsi;
        context.rbp = self.rbp;
        context.rbx = self.rbx;
        context.rdx = self.rdx;
        context.rcx = self.rcx;
        context.rax = self.rax;
        context.rflags = (original_rflags & !Self::STATUS_RFLAGS) | Self::decode_flags(self.flags);
    }

    fn encode_flags(flags: u64) -> u64 {
        let mut encoded = 0;
        for (native, e9) in [
            (0x0001, Self::FLAGS_CF),
            (0x0004, Self::FLAGS_PF),
            (0x0010, Self::FLAGS_AF),
            (0x0040, Self::FLAGS_ZF),
            (0x0080, Self::FLAGS_SF),
            (0x0800, Self::FLAGS_OF),
        ] {
            if flags & native != 0 {
                encoded |= e9;
            }
        }
        encoded
    }

    fn decode_flags(flags: u64) -> u64 {
        let mut native = 0;
        for (e9, bit) in [
            (Self::FLAGS_CF, 0x0001),
            (Self::FLAGS_PF, 0x0004),
            (Self::FLAGS_AF, 0x0010),
            (Self::FLAGS_ZF, 0x0040),
            (Self::FLAGS_SF, 0x0080),
            (Self::FLAGS_OF, 0x0800),
        ] {
            if flags & e9 != 0 {
                native |= bit;
            }
        }
        native
    }
}

unsafe extern "C" fn host_syscall_hook(context: *mut HookContext) {
    if context.is_null() {
        unsafe { exit_now(122) };
    }
    let context = unsafe { &mut *context };
    let original_rflags = context.rflags;
    if let Some(site) = find_site(context.instruction_pointer) {
        site.hook_count.fetch_add(1, Ordering::Relaxed);
    }
    let mut frame = HostSyscallFrame::from_context(context);
    // SAFETY: the host validates the configured marker, exact trap/caller RIPs,
    // readable frame, stack relationship, and current patched-site provenance
    // before dispatch. These checks resist accidental collisions; same-process
    // arbitrary code remains outside the threat model.
    unsafe { reverie_liteinst_host_syscall_trap_call(&mut frame) };
    frame.copy_to_context(context, original_rflags);
}

unsafe extern "C" fn installed_syscall_hook(context: *mut HookContext) {
    if context.is_null() {
        unsafe {
            exit_now(122);
        }
    }
    // SAFETY: generated LiteInst code passes a unique mutable saved frame.
    let context_pointer = context as usize;
    let context = unsafe { &mut *context };
    if let Some(site) = find_site(context.instruction_pointer) {
        site.hook_count.fetch_add(1, Ordering::Relaxed);
    }
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
    };
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-133): Review guarded installed-hook bypass for Tool-internal syscalls.
    if unsafe { !CURRENT_EVENT.is_null() } {
        forward_nested_tool_syscall(&mut event);
        context.rax = event.result as u64;
        context.rcx = context.instruction_pointer.saturating_add(2);
        context.r11 = context.rflags;
        return;
    }
    unsafe {
        CURRENT_EVENT = &mut event;
        tool_trampoline();
        CURRENT_EVENT = ptr::null_mut();
    }
    if event.result == UNSET_RESULT {
        event.result = -i64::from(libc::ENOSYS);
    }
    context.rax = event.result as u64;
    context.rcx = context.instruction_pointer.saturating_add(2);
    context.r11 = context.rflags;
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

struct LiteinstDispatcher;

impl SyscallDispatcher for LiteinstDispatcher {
    fn dispatch(&self, event: &mut PreloadSyscallEvent) {
        if unsafe { !CURRENT_EVENT.is_null() } {
            let mut nested = SyscallEvent {
                number: event.number(),
                args: event.args(),
                instruction_pointer: event.instruction_pointer(),
                result: UNSET_RESULT,
                context: 0,
            };
            forward_nested_tool_syscall(&mut nested);
            event.set_result(nested.result);
            return;
        }
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
            };
            unsafe {
                process_syscall(&mut trapped);
            }
            event.set_result(trapped.result);
            return;
        }

        let resume_address = event.instruction_pointer();
        let instruction_pointer =
            unsafe { locate_syscall_site(resume_address) }.unwrap_or(resume_address);

        if let Some((site, claimed)) = claim_site(instruction_pointer) {
            site.trap_count.fetch_add(1, Ordering::Relaxed);
            if claimed
                && unsafe {
                    install_site_hook(
                        instruction_pointer,
                        site,
                        installed_syscall_hook,
                        PatchPublication::Concurrent,
                    )
                }
                .is_err()
            {
                site.state.store(SITE_FALLBACK, Ordering::Release);
            }
            while matches!(site.state.load(Ordering::Acquire), 0 | SITE_INSTALLING) {
                core::hint::spin_loop();
            }
            if site.state.load(Ordering::Acquire) == SITE_ACTIVE {
                let hook = site.hook.load(Ordering::Acquire);
                if !hook.is_null() {
                    // SAFETY: active sites retain their InstalledHook for process lifetime.
                    event.defer_to(unsafe { (*hook).trampoline().address() });
                    return;
                }
            }
        }

        // Generic Tool execution may allocate, lock, and block on coordinator
        // I/O, so it cannot run as a fallback inside the SIGSYS handler.
        //
        // AUTONOMOUS-BOT-IMPLEMENTED
        // Record the escape before failing closed so the residual fallback
        // surface is observable by syscall number. Counting does not change the
        // forwarding decision (still `EOPNOTSUPP`), so the dispatch path is
        // unchanged; this is the by-number analog of e9patch's round-4 counter.
        record_fallback_dispatch(event.number());
        event.fail(libc::EOPNOTSUPP);
    }
}

unsafe extern "C" fn tool_trampoline() {
    let event = unsafe { CURRENT_EVENT };
    if event.is_null() {
        unsafe {
            exit_now(123);
        }
    }
    unsafe {
        process_syscall(&mut *event);
    }
}

// TODO-HUMAN-REVIEW(PR-127): Review process-global preload safety guards.
fn protect_runtime_control(event: &mut SyscallEvent) -> bool {
    let unsupported_control =
        // AUTONOMOUS-BOT-IMPLEMENTED
        matches!(event.number, libc::SYS_clone3 | libc::SYS_vfork);
    let protected_signal =
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-133): Review fail-closed guest signal-handler policy.
        !signal_action_supported(event.number, event.args)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (event.number == libc::SYS_sigaltstack && event.args[0] != 0)
        // AUTONOMOUS-BOT-IMPLEMENTED
        || (event.number == libc::SYS_rt_sigprocmask && event.args[1] != 0);

    if unsupported_control {
        event.result = -i64::from(libc::ENOTSUP);
    } else if protected_signal {
        event.result = -i64::from(libc::EPERM);
    } else {
        return false;
    }
    true
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
    if tool_mode == TOOL_REVERIE && unsafe { protect_coordinator_channel(event) } {
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

    if event.number == libc::SYS_clone && !clone_is_fork_like(event.args[0], event.args[1]) {
        event.result = if TOOL_MODE.load(Ordering::Relaxed) == TOOL_COMPAT {
            -i64::from(libc::EPERM)
        } else {
            -i64::from(libc::ENOTSUP)
        };
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
    event.result = unsafe { raw_syscall6(event.number, event.args) };
    observe_mapping_generation(event);

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-260): Review the fork-following observability reset call.
    // In the child of a successful fork-like syscall (`result == 0`), the
    // COW-inherited observability counters describe the parent, not this child.
    // Reset them through the shared ForkHook seam so per-process attribution
    // starts clean. `is_fork_like` also matches clone3/vfork, but those never
    // reach a successful forward here (both fail closed earlier), so gating on a
    // zero result is sufficient and mirrors e9patch's child-side reset.
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

fn clone_is_fork_like(flags: u64, child_stack: u64) -> bool {
    const SIGNAL_MASK: u64 = 0xff;
    let allowed_flags =
        (libc::CLONE_CHILD_CLEARTID | libc::CLONE_CHILD_SETTID | libc::CLONE_PARENT_SETTID) as u64;
    child_stack == 0
        && flags & SIGNAL_MASK == libc::SIGCHLD as u64
        && flags & !(SIGNAL_MASK | allowed_flags) == 0
}

unsafe fn protect_coordinator_channel(event: &mut SyscallEvent) -> bool {
    let fd = COORDINATOR_FD.load(Ordering::Acquire);
    if fd < 0 {
        return false;
    }
    let fd = fd as u64;
    if event.number == libc::SYS_close && event.args[0] == fd {
        event.result = 0;
    } else if event.number == libc::SYS_close_range && event.args[0] <= fd && fd <= event.args[1] {
        event.result = unsafe { close_range_preserving_event_fd(event, fd) };
    } else if syscall_targets_event_fd(event, fd) {
        event.result = -i64::from(libc::EBADF);
    } else {
        return false;
    }
    true
}

unsafe fn protect_compatibility_event_channel(event: &mut SyscallEvent) -> bool {
    let event_fd = EVENT_FD.load(Ordering::Acquire) as u64;

    if event.number == libc::SYS_close && event.args[0] == event_fd {
        // The descriptor is controller-owned and intentionally invisible to
        // guest descriptor lifecycle management.
        event.result = 0;
    } else if event.number == libc::SYS_close_range
        && event.args[0] <= event_fd
        && event_fd <= event.args[1]
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
    const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;

    let first = event.args[0];
    let last = event.args[1];
    let mut flags = event.args[2];
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return -i64::from(libc::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        let result =
            unsafe { raw_syscall6(libc::SYS_unshare, [libc::CLONE_FILES as u64, 0, 0, 0, 0, 0]) };
        if result < 0 {
            return result;
        }
        flags &= !CLOSE_RANGE_UNSHARE;
    }

    if first < event_fd {
        let result =
            unsafe { raw_syscall6(libc::SYS_close_range, [first, event_fd - 1, flags, 0, 0, 0]) };
        if result < 0 {
            return result;
        }
    }
    if event_fd < last {
        let result =
            unsafe { raw_syscall6(libc::SYS_close_range, [event_fd + 1, last, flags, 0, 0, 0]) };
        if result < 0 {
            return result;
        }
    }
    0
}

fn syscall_targets_event_fd(event: &SyscallEvent, event_fd: u64) -> bool {
    match event.number {
        libc::SYS_read
        | libc::SYS_readv
        | libc::SYS_pread64
        | libc::SYS_preadv
        | libc::SYS_preadv2
        | libc::SYS_write
        | libc::SYS_writev
        | libc::SYS_pwrite64
        | libc::SYS_pwritev
        | libc::SYS_pwritev2
        | libc::SYS_vmsplice
        | libc::SYS_sendfile
        | libc::SYS_fcntl
        | libc::SYS_ioctl
        | libc::SYS_dup => event.args[0] == event_fd,
        libc::SYS_dup2 | libc::SYS_dup3 => event.args[0] == event_fd || event.args[1] == event_fd,
        libc::SYS_splice | libc::SYS_copy_file_range => {
            event.args[0] == event_fd || event.args[2] == event_fd
        }
        libc::SYS_tee => event.args[0] == event_fd || event.args[1] == event_fd,
        _ => false,
    }
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
            write_compatibility_event(output_fd, &line.bytes[..line.len]);
        }
    } else {
        let _ = unsafe {
            raw_syscall6(
                libc::SYS_write,
                [
                    output_fd as u64,
                    line.bytes.as_ptr() as u64,
                    line.len as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
    }
}

unsafe fn exit_now(code: i32) -> ! {
    let _ = unsafe { raw_syscall6(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop();
    }
}

struct StackLine {
    bytes: [u8; 192],
    len: usize,
}

impl StackLine {
    const fn new() -> Self {
        Self {
            bytes: [0; 192],
            len: 0,
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        let available = self.bytes.len().saturating_sub(self.len);
        let count = available.min(bytes.len());
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }

    fn push_signed(&mut self, value: i64) {
        if value < 0 {
            self.push_bytes(b"-");
        }
        self.push_unsigned(value.unsigned_abs());
    }

    fn push_unsigned(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(&digits[cursor..]);
    }

    fn push_hex(&mut self, mut value: u64) {
        let mut digits = [0_u8; 16];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            let digit = (value & 0xf) as u8;
            digits[cursor] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            value >>= 4;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(&digits[cursor..]);
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;
    use std::ffi::OsStr;

    use reverie_preload::BuiltinTool;

    use super::ALT_STACK_ENV;
    use super::FORK_HOOK;
    use super::MAX_PATCH_SITES;
    use super::SITE_ACTIVE;
    use super::SITE_FALLBACK;
    use super::SITE_INSTALLING;
    use super::SITE_STALE;
    use super::SITES;
    use super::SiteSlot;
    use super::StackLine;
    use super::TOOL_PASSTHROUGH;
    use super::TOOL_SPOOF_GETPID;
    use super::alt_stack_from_env_value;
    use super::builtin_tool_from_env_value;
    use super::claim_site;
    use super::clone_is_fork_like;
    use super::fallback_dispatch_count;
    use super::fallback_syscall_count;
    use super::mark_site_range_stale;
    use super::record_fallback_dispatch;
    use super::reset_fallback_observability;
    use super::site_counts;

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
        // Unset must reproduce the shared reverie-preload default verbatim, so
        // the launcher-selected knob is a no-op by default (zero behavior change).
        use reverie_preload::lifecycle::RuntimeConfig;
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
        // A syscall number unique to this test, so the per-number assertion is
        // exact even if the process-global counters are touched concurrently.
        let number: i64 = 402;
        let per_before = fallback_syscall_count(number);
        let total_before = fallback_dispatch_count();

        record_fallback_dispatch(number);

        assert_eq!(fallback_syscall_count(number), per_before + 1);
        assert!(
            fallback_dispatch_count() > total_before,
            "total must advance by at least this recording"
        );
    }

    #[test]
    fn out_of_range_syscall_numbers_count_in_the_total_only() {
        // Above the tracked bound: total advances, per-number stays zero.
        let huge = i64::from(i32::MAX);
        let total_before = fallback_dispatch_count();
        record_fallback_dispatch(huge);
        assert_eq!(fallback_syscall_count(huge), 0);
        assert!(fallback_dispatch_count() > total_before);

        // Negative numbers are never used to index the per-number table.
        let total_before = fallback_dispatch_count();
        record_fallback_dispatch(-1);
        assert_eq!(fallback_syscall_count(-1), 0);
        assert!(fallback_dispatch_count() > total_before);
    }

    #[test]
    fn fork_child_reset_zeroes_the_process_global_fallback_counters() {
        // Serial (`--test-threads=1`), so resetting the process-global counters
        // does not race other tests. Record on both counter families, then prove
        // the fork-child reset clears them. This is the by-number/total analog of
        // reverie-e9patch's round-7 `resetting_observability_zeroes_...` test.
        let number: i64 = 404;
        record_fallback_dispatch(number);
        assert!(fallback_dispatch_count() > 0);
        assert!(fallback_syscall_count(number) > 0);

        reset_fallback_observability();

        assert_eq!(fallback_dispatch_count(), 0);
        assert_eq!(fallback_syscall_count(number), 0);
    }

    #[test]
    fn fork_child_reset_zeroes_per_site_counts_but_preserves_patch_state() {
        // The per-site trap/hook counts are observability; the site's address and
        // state are functional patch metadata the COW-inherited child must keep.
        // Reset must clear the former without disturbing the latter.
        SITES.get_or_init(|| {
            (0..MAX_PATCH_SITES)
                .map(|_| SiteSlot::new())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        let address = 0x4321_9000;
        let (site, claimed) = claim_site(address).unwrap();
        assert!(claimed);
        site.state.store(SITE_ACTIVE, Ordering::Release);
        site.trap_count.store(7, Ordering::Release);
        site.hook_count.store(11, Ordering::Release);
        assert_eq!(site_counts(address), (7, 11));

        reset_fallback_observability();

        // Observability cleared...
        assert_eq!(site_counts(address), (0, 0));
        // ...but the functional patch state is intact, so the child's inherited
        // instrumentation keeps working.
        assert_eq!(site.address.load(Ordering::Acquire), address);
        assert_eq!(site.state.load(Ordering::Acquire), SITE_ACTIVE);
    }

    #[test]
    fn fork_hook_runs_the_observability_reset() {
        // The static FORK_HOOK must wrap `reset_fallback_observability`, so
        // invoking it (as `process_syscall` does in the fork child) clears the
        // process-global counters — proving the shared ForkHook seam is wired to
        // the reset rather than a private path.
        record_fallback_dispatch(405);
        assert!(fallback_dispatch_count() > 0);

        FORK_HOOK.run_in_child();

        assert_eq!(fallback_dispatch_count(), 0);
        assert_eq!(fallback_syscall_count(405), 0);
    }

    #[test]
    fn stack_line_formats_signed_and_hex_values() {
        let mut line = StackLine::new();
        line.push_signed(-123);
        line.push_bytes(b" ");
        line.push_hex(0xdead_beef);
        assert_eq!(&line.bytes[..line.len], b"-123 deadbeef");
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
}
