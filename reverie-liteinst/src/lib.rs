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

#[cfg(feature = "preload-constructor")]
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_LITEINST_INIT: unsafe extern "C" fn() = reverie_liteinst_initialize;
