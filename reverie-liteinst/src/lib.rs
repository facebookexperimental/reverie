#![forbid(unsafe_op_in_unsafe_fn)]

use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Command;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("reverie-liteinst requires Linux x86-64");

mod allocator_backing;
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub mod allocator_fixture;
mod backend;
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub mod fixed_arena_fixture;
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub mod generic_fixture;
#[cfg(feature = "exec-private-init")]
mod initial_image_stats;
mod interior_entry;
mod liteinst_census;
#[cfg(feature = "native-exec-state")]
pub mod native_exec_state;
mod patch_alloc;
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub mod stack_fixture;
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub mod standalone_fixture;
mod stats;
mod straddler;
mod syscall_fallback;

pub use backend::COORDINATOR_ENV;
#[cfg(feature = "exec-private-init")]
pub use backend::InitialImageStatsCollector;
#[cfg(feature = "exec-private-init")]
pub use backend::InitialImageStatsServer;
pub use backend::LiteinstBackend;
pub use backend::PreloadBootstrap;
pub use backend::STATS_COORDINATOR_ENV;
pub use backend::TOOL_PRELOAD_ENV;
pub use backend::take_preload_bootstrap;
pub use stats::InheritedEntries;
pub use stats::LiteinstBackendStatsSnapshot;
pub use stats::LiteinstBackendStatsSource;
pub use stats::LiteinstDispatchPath;
pub use stats::LiteinstPatchDecision;
pub use stats::guest_stats_enabled;
pub mod rpc;
mod runtime;
mod tool_host;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared reverie-inguest built-in re-exports.
#[doc(hidden)]
pub use allocator_backing::AllocatorBackingDescriptor;
pub use patch_alloc::FixedPrivatePatchAllocator as FixedToolAllocator;
pub use patch_alloc::PatchAllocator as ScopedToolAllocator;
pub use patch_alloc::PrivatePatchAllocator as PrivateToolAllocator;
/// Shared `reverie-inguest` built-in tool enum and getpid spoof constant.
///
/// These are re-exported verbatim so LiteInst and e9patch present the same
/// built-in surface; the same [`BuiltinTool`] value installs the same dispatcher
/// in both backends via `reverie_inguest::install_builtin`.
pub use reverie_inguest::BuiltinTool;
pub use reverie_inguest::SPOOF_PID;
pub use reverie_inguest::guest::host::CreationHookError;
pub use reverie_inguest::guest::host::CreationRefusal;
pub use reverie_inguest::guest::host::PhysicalCreation;
pub use reverie_inguest::guest::host::PhysicalCreationHook;
pub use reverie_inguest::guest::host::RefusedChild;
pub use reverie_inguest::guest::host::set_physical_creation_hook;
/// Native fixed-stack entry used by the owned standalone leaf.
#[doc(hidden)]
pub use reverie_inguest::guest::tool_region::constructor_entry;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-254): Review shared RuntimeConfig alt-stack re-exports.
/// `REVERIE_LITEINST_ALT_STACK` selector and parser for the shared
/// `reverie-inguest` `RuntimeConfig` alt-stack knob.
pub use runtime::ALT_STACK_ENV;
pub use runtime::IN_GUEST_STAGE_STREAM_ENV;
pub use runtime::PROCESS_FORK_ENV;
pub use runtime::SIGALRM_HANDLERS_ENV;
pub use runtime::SITE_PATCHING_ENV;
/// `REVERIE_LITEINST_TOOL` values and parser for shared built-in selection.
pub use runtime::TOOL_PASSTHROUGH;
pub use runtime::TOOL_SPOOF_GETPID;
pub use runtime::alt_stack_from_env_value;
pub use runtime::builtin_tool_from_env_value;
pub use runtime::reserve_tool_output_fd;
pub use runtime::site_patching_enabled;
pub use runtime::site_patching_from_env_value;
pub use runtime::tool_output_fd;
pub use straddler::STRADDLER_STALENESS_TICKS_ENV;
pub use straddler::straddler_staleness_from_env_value;
#[cfg(feature = "exec-private-init")]
pub use tool_host::InstalledInitialImage;
#[cfg(feature = "exec-native-injection")]
pub use tool_host::InstalledSuccessorImage;
#[cfg(feature = "exec-native-injection")]
pub use tool_host::NativeSuccessorConsumer;
#[cfg(feature = "exec-private-init")]
pub use tool_host::PreparedInitialImage;
#[cfg(feature = "exec-native-injection")]
pub use tool_host::PreparedSuccessorImage;
pub use tool_host::blocking_global_rpc;
#[cfg(feature = "exec-private-init")]
pub use tool_host::initialize_initial_image_lifecycle;
pub use tool_host::install_tool;
pub use tool_host::install_tool_from_bootstrap;
#[cfg(feature = "exec-private-init")]
pub use tool_host::install_tool_initial_image;
#[cfg(feature = "exec-native-injection")]
pub use tool_host::install_tool_initial_image_with_native_exec;
pub use tool_host::install_tool_quiescent;
#[cfg(feature = "exec-native-injection")]
pub use tool_host::install_tool_successor_image;
pub use tool_host::install_tool_with_root_initializer;
#[cfg(feature = "exec-private-init")]
pub use tool_host::prepare_tool_initial_image;
#[cfg(feature = "exec-native-injection")]
pub use tool_host::prepare_tool_successor_image;

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

    preload_library_beside(&env::current_exe()?)
}

fn preload_library_beside(executable: &std::path::Path) -> io::Result<PathBuf> {
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "current executable has no parent")
    })?;
    [
        parent.join("libreverie_liteinst_preload.so"),
        parent.join("deps/libreverie_liteinst_preload.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_liteinst_preload.so"),
        // A warm pre-split Cargo tree may retain the old core cdylib under this
        // canonical installed name. Prefer every new leaf before that fallback.
        parent.join("libreverie_liteinst.so"),
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
/// and `REVERIE_LITEINST_TOOL` to a shared `reverie-inguest` [`BuiltinTool`]
/// selector, so the runtime installs the built-in verbatim through
/// `reverie_inguest::install_builtin` (no LiteInst patching). It mirrors
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
/// Selects the shared `reverie-inguest` `RuntimeConfig` alt-stack knob for a guest.
///
/// Sets [`ALT_STACK_ENV`] so the in-guest runtime installs its `SIGSYS` handler
/// with or without an alternate signal stack (`RuntimeConfig::use_alt_stack`).
/// The `RuntimeConfig` and the controller honoring it are shared with e9patch in
/// `reverie-inguest`; only the env-var spelling is LiteInst's. Leaving this
/// unset preserves the shared default (alt stack on). It composes with
/// [`configure_command`] and [`configure_command_builtin`]; the written value
/// round-trips through [`alt_stack_from_env_value`].
pub fn set_guest_alt_stack(command: &mut Command, use_alt_stack: bool) {
    command.env(ALT_STACK_ENV, if use_alt_stack { "1" } else { "0" });
}

/// Select whether the direct runtime may forward process-creation syscalls.
///
/// This does not add support for thread-style clone. It lets a consumer retain
/// the existing fail-closed boundary until its Tool lifecycle has a positive
/// fork bracket.
pub fn set_guest_process_forks(command: &mut Command, allowed: bool) {
    command.env(PROCESS_FORK_ENV, if allowed { "1" } else { "0" });
}

/// Select whether an in-guest Reverie Tool patches trapping syscall sites.
///
/// With `enabled == false` every trapping syscall runs the Tool through the
/// in-guest `SIGSYS` fallback and no syscall site is patched; subscribed
/// `cpuid`, `rdtsc`, and `rdtscp` instruction sites still are. See
/// [`SITE_PATCHING_ENV`].
/// The written value round-trips through [`site_patching_from_env_value`].
pub fn set_guest_site_patching(command: &mut Command, enabled: bool) {
    command.env(SITE_PATCHING_ENV, if enabled { "1" } else { "0" });
}

// TODO-HUMAN-REVIEW(#61): this constructor installs process-wide signal and seccomp state.
/// Initializes the preload runtime when selected by the launcher environment.
///
/// The actual preload leaf owns the constructor and uses
/// [`declare_fixed_tool_allocator!`]. An embedded legacy root uses
/// [`declare_legacy_scoped_tool_allocator!`] or
/// [`declare_legacy_private_tool_allocator!`] for its existing policy. Each
/// declaration couples the compiler allocator with its immutable backing
/// contract; a missing or duplicate declaration is a link error. The core
/// installs neither a default allocator nor its own
/// LiteInst constructor. The independent legacy `reverie-inguest` constructor
/// can still be enabled by that dependency's `preload-constructor` feature.
/// A caller whose allocator does not own the dispatch preflight allocation is
/// refused before runtime activation. This explicit call first reserves a fixed
/// guarded scalar stack, even when its environment getter selects no Tool. Such
/// a call returns with that reservation retained and without runtime activation.
/// A repeated call, or an already-owned/colliding region, refuses before a
/// second getter/body invocation. The selector-absent standalone constructor
/// remains a separate inert path and does not call this entry.
///
/// # Safety
///
/// Call once during trusted single-threaded startup, with clear DF and no
/// active runtime filter. Repeated calls refuse before reading the selector
/// or installing another runtime.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_liteinst_initialize() {
    core::arch::naked_asm!(
        "endbr64",
        "lea rdi, [rip + {body}]",
        "jmp {entry}",
        body = sym reverie_liteinst_generic_body,
        entry = sym reverie_inguest::guest::tool_region::generic_entry,
    );
}

// Distinct local Rust body: the existing dispatch/preflight/getter order stays
// intact, and only the native entry may supply this body to its fresh bootstrap.
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn reverie_liteinst_generic_body() {
    let _scope = reverie_inguest::guest::alloc::enter_dispatch();
    initialization_or_exit(
        patch_alloc::preflight_allocator().and_then(|()| runtime::initialize_from_environment()),
    );
}

core::arch::global_asm!(".hidden reverie_liteinst_generic_body");

/// Establish an ordinary region owner for the explicit-entry refusal control.
/// This setup operation is separate from all read-only placement queries.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
#[unsafe(no_mangle)]
pub extern "C" fn m4_generic_ordinary_owner_setup() -> i32 {
    match reverie_inguest::guest::tool_region::ToolRegion::reserve() {
        Ok(_) => 0,
        Err(error) => -error.raw_os_error().unwrap_or(libc::EIO),
    }
}

/// Initialize the actual standalone leaf after native fixed-stack adoption.
///
/// This private leaf control reads the first exact selector from the current
/// `environ` vector. It deliberately does not consult an interposed `getenv`;
/// [`reverie_liteinst_initialize`] retains that generic embedding behavior.
/// The owned value is copied before initialization calls other providers.
///
/// # Safety
///
/// Call once from the actual leaf's authenticated constructor body, before
/// application threads start. The environment must remain valid and stable
/// from the native selector scan through this copy. No active runtime may
/// precede this initialization. The caller invokes its compatibility resolver
/// only after this function returns and its dispatch scope has been dropped.
#[doc(hidden)]
#[inline(never)]
#[unsafe(export_name = "reverie_liteinst_standalone_initialize")]
pub unsafe extern "C" fn initialize_standalone() {
    let _scope = reverie_inguest::guest::alloc::enter_dispatch();
    let result = patch_alloc::preflight_allocator().and_then(|()| {
        let selected = reverie_inguest::guest::support::environment_value(b"REVERIE_LITEINST_TOOL")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REVERIE_LITEINST_TOOL disappeared during standalone initialization",
                )
            })?;
        let selected = OsString::from_vec(selected.to_vec());
        runtime::initialize_from_selected_value(Some(&selected))
    });
    initialization_or_exit(result);
}

// The actual leaf cannot be redirected through another object's initializer.
// This does not change the separately exported generic initializer.
core::arch::global_asm!(".hidden reverie_liteinst_standalone_initialize");

fn initialization_or_exit(result: io::Result<()>) {
    if let Err(error) = result {
        eprintln!("reverie-liteinst initialization failed: {error}");
        // libc's _exit, not a raw exit_group from this library: an exit_group
        // issued from the runtime's own code bypasses the runtime's exit path,
        // so an installed runtime would not report the process's statistics
        // to the coordinator. The process ends here, so an interposed _exit
        // can change only a heap that is about to disappear.
        unsafe { libc::_exit(127) };
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
/// Total syscalls that reached LiteInst's fallback dispatch path.
///
/// These sites have no installed hook. Typed Tool mode can dispatch them after
/// signal return, so the count includes successful Tool calls and is not a
/// syscall-failure count. The per-syscall-number breakdown uses the same keys
/// as `reverie_e9patch_fallback_dispatch_count`.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_fallback_dispatch_count() -> u64 {
    runtime::fallback_dispatch_count()
}

// TODO-HUMAN-REVIEW(PR-249): Review public fallback-surface observability counters.
/// Number of times syscall `number` reached LiteInst's fallback dispatch path.
///
/// The per-syscall-number analog of the per-site counters, keyed by syscall
/// number to match `reverie_e9patch_fallback_syscall_count`. Returns `0` for a
/// negative number or one outside the tracked table; those are only reflected in
/// [`reverie_liteinst_fallback_dispatch_count`].
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_fallback_syscall_count(number: i64) -> u64 {
    runtime::fallback_syscall_count(number)
}

/// Fallback attempts refused by the runtime before ordinary Tool dispatch.
///
/// This is a subset of [`reverie_liteinst_fallback_dispatch_count`]. Errors
/// returned by a successfully invoked Tool are not runtime refusals.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_fallback_refusal_count() -> u64 {
    runtime::fallback_refusal_count()
}

/// Per-syscall breakdown of [`reverie_liteinst_fallback_refusal_count`].
/// Numbers outside the tracked table contribute only to the total.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_fallback_syscall_refusal_count(number: i64) -> u64 {
    runtime::fallback_syscall_refusal_count(number)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::process::Command;

    use super::ALT_STACK_ENV;
    use super::SITE_PATCHING_ENV;
    use super::alt_stack_from_env_value;
    use super::set_guest_alt_stack;
    use super::set_guest_site_patching;
    use super::site_patching_from_env_value;

    #[test]
    fn generated_preload_leaves_precede_a_stale_canonical_artifact() {
        let root = tempfile::tempdir().unwrap();
        let debug = root.path().join("debug");
        let deps = debug.join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        let executable = debug.join("reverie-liteinst-strace");
        let installed = debug.join("libreverie_liteinst.so");
        std::fs::write(&installed, b"old core artifact or installed runtime").unwrap();
        // Canonical installation still works when there is no generated leaf.
        assert_eq!(
            super::preload_library_beside(&executable).unwrap(),
            installed
        );
        // Reproduce a warm Cargo tree after the package split: the old core
        // artifact must not hide the newly produced private-allocator leaf.
        let generated = deps.join("libreverie_liteinst_preload.so");
        std::fs::write(&generated, b"fresh preload leaf").unwrap();
        assert_eq!(
            super::preload_library_beside(&executable).unwrap(),
            generated
        );
        std::fs::remove_file(&generated).unwrap();
        // A test executable under deps must also prefer the new parent leaf
        // over a legacy artifact beside that executable.
        let test_executable = deps.join("strace-test");
        std::fs::write(deps.join("libreverie_liteinst.so"), b"stale core").unwrap();
        let parent_leaf = debug.join("libreverie_liteinst_preload.so");
        std::fs::write(&parent_leaf, b"fresh preload leaf").unwrap();
        assert_eq!(
            super::preload_library_beside(&test_executable).unwrap(),
            parent_leaf
        );
    }

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

    #[test]
    fn site_patching_setter_round_trips_through_the_parser() {
        for enabled in [true, false] {
            let mut command = Command::new("/bin/true");
            set_guest_site_patching(&mut command, enabled);
            let written = command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(SITE_PATCHING_ENV))
                .and_then(|(_, value)| value)
                .expect("set_guest_site_patching must set SITE_PATCHING_ENV")
                .to_owned();
            assert_eq!(
                site_patching_from_env_value(Some(written.as_os_str())).unwrap(),
                enabled,
                "written value must parse back to the selected boolean"
            );
        }
    }

    #[test]
    fn site_patching_parser_defaults_on_and_rejects_other_values() {
        assert!(site_patching_from_env_value(None).unwrap());
        for rejected in ["", " 0", "0 ", "off", "false", "2", "yes"] {
            let error = site_patching_from_env_value(Some(OsStr::new(rejected)))
                .expect_err("only unset, 1, and 0 are accepted");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "{rejected:?}"
            );
        }
    }
}

/// Bounded spare-lease diagnostics for the separate mapping integrity fixture.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub mod mapping_integrity_fixture;
