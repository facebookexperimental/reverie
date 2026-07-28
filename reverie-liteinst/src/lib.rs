#![feature(thread_local)]
#![forbid(unsafe_op_in_unsafe_fn)]

use std::env;
use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::process::Command;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("reverie-liteinst requires Linux x86-64");

mod backend;
mod patch_alloc;

pub use backend::COORDINATOR_ENV;
pub use backend::LiteinstBackend;
pub use backend::PreloadBootstrap;
pub use backend::TOOL_PRELOAD_ENV;
pub use backend::take_preload_bootstrap;
pub mod rpc;
mod runtime;
mod tool_host;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared reverie-preload built-in re-exports.
/// Shared `reverie-preload` built-in tool enum and getpid spoof constant.
///
/// These are re-exported verbatim so LiteInst and e9patch present the same
/// built-in surface; the same [`BuiltinTool`] value installs the same dispatcher
/// in both backends via `reverie_preload::install_builtin`.
pub use reverie_preload::BuiltinTool;
pub use reverie_preload::SPOOF_PID;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review shared RuntimeConfig alt-stack re-exports.
/// `REVERIE_LITEINST_ALT_STACK` selector and parser for the shared
/// `reverie-preload` `RuntimeConfig` alt-stack knob.
pub use runtime::ALT_STACK_ENV;
/// `REVERIE_LITEINST_TOOL` values and parser for shared built-in selection.
pub use runtime::TOOL_PASSTHROUGH;
pub use runtime::TOOL_SPOOF_GETPID;
pub use runtime::alt_stack_from_env_value;
pub use runtime::builtin_tool_from_env_value;
pub use tool_host::install_tool;
pub use tool_host::install_tool_from_bootstrap;

#[global_allocator]
static PATCH_ALLOCATOR: patch_alloc::PatchAllocator = patch_alloc::PatchAllocator;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-87): Review the inherited compatibility event channel.
/// Environment variable selecting an inherited descriptor for compatibility events.
///
/// When unset, compatibility events retain their standalone behavior and use
/// standard error.
pub const COMPAT_EVENT_FD_ENV: &str = "REVERIE_LITEINST_EVENT_FD";

/// Environment variable selecting a per-launch compatibility-event cookie.
///
/// A controller that sets [`COMPAT_EVENT_FD_ENV`] must also set this to a
/// nonzero decimal `u64`. The runtime removes both variables before guest code
/// starts and includes the cookie in every dedicated-channel record.
pub const COMPAT_EVENT_COOKIE_ENV: &str = "REVERIE_LITEINST_EVENT_COOKIE";

/// Built-in synchronous tool executed by the preload runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreloadTool {
    /// Emit one detailed line for every trapped syscall.
    Strace,
    /// Emit stable syscall-number markers for external comparison.
    Compatibility,
}

impl PreloadTool {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Strace => "strace",
            Self::Compatibility => "compat",
        }
    }
}

/// Locates the preload runtime produced beside the current executable.
pub fn preload_library_path() -> io::Result<PathBuf> {
    if let Some(path) = env::var_os("REVERIE_LITEINST_PRELOAD") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "REVERIE_LITEINST_PRELOAD does not name a file",
            )
        });
    }

    let executable = env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "current executable has no parent")
    })?;
    [
        parent.join("libreverie_liteinst.so"),
        parent.join("deps/libreverie_liteinst.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_liteinst.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot find libreverie_liteinst.so beside {}",
                executable.display()
            ),
        )
    })
}

/// Configures a guest command to load the runtime and select a built-in tool.
pub fn configure_command(command: &mut Command, tool: PreloadTool) -> io::Result<()> {
    let mut preload = preload_library_path()?.into_os_string();
    if let Some(existing) = env::var_os("LD_PRELOAD").filter(|value| !value.is_empty()) {
        preload.push(OsStr::new(":"));
        preload.push(existing);
    }
    command
        .env("LD_PRELOAD", preload)
        .env("REVERIE_LITEINST_TOOL", tool.as_str());
    Ok(())
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared built-in command configuration.
/// Maps a shared [`BuiltinTool`] to its `REVERIE_LITEINST_TOOL` selector value.
fn builtin_tool_env_value(tool: BuiltinTool) -> &'static str {
    match tool {
        BuiltinTool::Passthrough => TOOL_PASSTHROUGH,
        BuiltinTool::SpoofGetpid => TOOL_SPOOF_GETPID,
    }
}

/// Configures a guest command to load the runtime and select a shared built-in.
///
/// This is the built-in analog of [`configure_command`]: it sets `LD_PRELOAD`
/// and `REVERIE_LITEINST_TOOL` to a shared `reverie-preload` [`BuiltinTool`]
/// selector, so the runtime installs the built-in verbatim through
/// `reverie_preload::install_builtin` (no LiteInst patching). It mirrors
/// e9patch's launcher-side built-in configuration.
pub fn configure_command_builtin(command: &mut Command, tool: BuiltinTool) -> io::Result<()> {
    let mut preload = preload_library_path()?.into_os_string();
    if let Some(existing) = env::var_os("LD_PRELOAD").filter(|value| !value.is_empty()) {
        preload.push(OsStr::new(":"));
        preload.push(existing);
    }
    command
        .env("LD_PRELOAD", preload)
        .env("REVERIE_LITEINST_TOOL", builtin_tool_env_value(tool));
    Ok(())
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review launcher-side shared RuntimeConfig alt-stack selector.
/// Selects the shared `reverie-preload` `RuntimeConfig` alt-stack knob for a guest.
///
/// Sets [`ALT_STACK_ENV`] so the in-guest runtime installs its `SIGSYS` handler
/// with or without an alternate signal stack (`RuntimeConfig::use_alt_stack`).
/// The `RuntimeConfig` and the controller honoring it are shared with e9patch in
/// `reverie-preload`; only the env-var spelling is LiteInst's. Leaving this
/// unset preserves the shared default (alt stack on). It composes with
/// [`configure_command`] and [`configure_command_builtin`]; the written value
/// round-trips through [`alt_stack_from_env_value`].
pub fn set_guest_alt_stack(command: &mut Command, use_alt_stack: bool) {
    command.env(ALT_STACK_ENV, if use_alt_stack { "1" } else { "0" });
}

// TODO-HUMAN-REVIEW(#61): this constructor installs process-wide signal and seccomp state.
/// Initializes the preload runtime when selected by the launcher environment.
///
/// # Safety
///
/// The dynamic loader must call this exactly once before application threads
/// start. Calling it again would stack an irreversible seccomp filter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_liteinst_initialize() {
    if let Err(error) = runtime::initialize_from_environment() {
        eprintln!("reverie-liteinst initialization failed: {error}");
        unsafe {
            libc::_exit(127);
        }
    }
}

// TODO-HUMAN-REVIEW(PR-127): Review public per-site instrumentation counters.
/// Returns the number of SIGSYS deliveries observed at one syscall instruction.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_site_trap_count(address: u64) -> u64 {
    runtime::site_counts(address).0
}

/// Returns the number of installed-hook callbacks observed at one syscall instruction.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_site_hook_count(address: u64) -> u64 {
    runtime::site_counts(address).1
}

// TODO-HUMAN-REVIEW(PR-249): Review public fallback-surface observability counters.
/// Total syscalls that reached LiteInst's fail-closed escape surface.
///
/// The escape surface is the dispatch path for a trapped site the runtime could
/// not route to the Tool (un-patchable `SITE_FALLBACK`, or an unclaimable site),
/// which fails closed with `EOPNOTSUPP`. For Detcore this counts syscalls that
/// bypass the determinism tool, so it is the by-syscall-number analog of the
/// per-site `reverie_liteinst_site_trap_count`/`_hook_count` exports and the
/// direct counterpart of `reverie_e9patch_fallback_dispatch_count` (round 4).
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_fallback_dispatch_count() -> u64 {
    runtime::fallback_dispatch_count()
}

// TODO-HUMAN-REVIEW(PR-249): Review public fallback-surface observability counters.
/// Number of times syscall `number` reached LiteInst's fail-closed escape surface.
///
/// The per-syscall-number analog of the per-site counters, keyed by syscall
/// number to match `reverie_e9patch_fallback_syscall_count`. Returns `0` for a
/// negative number or one outside the tracked table; those are only reflected in
/// [`reverie_liteinst_fallback_dispatch_count`].
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_fallback_syscall_count(number: i64) -> u64 {
    runtime::fallback_syscall_count(number)
}

#[cfg(feature = "preload-constructor")]
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_LITEINST_INIT: unsafe extern "C" fn() = reverie_liteinst_initialize;

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::process::Command;

    use super::ALT_STACK_ENV;
    use super::alt_stack_from_env_value;
    use super::set_guest_alt_stack;

    /// The value the launcher writes must parse back to the same boolean it
    /// selected, for both polarities. This closes the loop between the setter
    /// (`set_guest_alt_stack`) and the runtime-side parser
    /// (`alt_stack_from_env_value`).
    #[test]
    fn alt_stack_setter_round_trips_through_the_parser() {
        for use_alt_stack in [true, false] {
            let mut command = Command::new("/bin/true");
            set_guest_alt_stack(&mut command, use_alt_stack);
            let written = command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(ALT_STACK_ENV))
                .and_then(|(_, value)| value)
                .expect("set_guest_alt_stack must set ALT_STACK_ENV")
                .to_owned();
            assert_eq!(
                alt_stack_from_env_value(Some(written.as_os_str())).unwrap(),
                use_alt_stack,
                "written value must parse back to the selected boolean"
            );
        }
    }
}
