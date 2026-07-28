/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie integration for the e9patch static binary rewriter.
//!
//! This crate validates e9patch preprocessing, replaces recovered syscall
//! instructions with event trampolines, and supplies a correctness-first
//! hybrid `reverie::Backend`. Ptrace remains the lifecycle and `Guest`
//! controller while events from rewritten root-ELF sites originate in e9patch.
//!
//! # Relationship to LiteInst (`reverie-liteinst`)
//!
//! e9patch is a sibling of the LiteInst backend, deliberately kept **closely
//! matched** to it. Both are ld-preload backends built on the shared
//! `reverie-preload` runtime, which owns the seccomp filter, the `SIGSYS`
//! handler, the trusted syscall gate, the fork/signal policy, and the
//! [`SyscallDispatcher`](reverie_preload::dispatch::SyscallDispatcher) seam.
//! Both register a dispatcher and install the same
//! [`InProcessSeccomp`](reverie_preload::lifecycle::InProcessSeccomp)
//! controller via [`runtime::install_runtime`], and both fall back to the
//! ptrace lifecycle owner for full `Guest` semantics.
//!
//! The **only** intended differences are:
//!
//! 1. **When patching happens.** e9patch rewrites syscall sites *ahead of time*
//!    with `e9tool`; LiteInst rewrites them *at runtime* on the first `SIGSYS`.
//! 2. **Trampoline placement.** e9patch's trampolines are materialized by
//!    `e9tool` into the rewritten ELF; LiteInst allocates them at runtime in a
//!    reachable arena.
//!
//! Everything else — the ld-preload injection substrate, the fail-closed guard
//! policy, and the fallback ptracer — is shared. See [`dispatch`] and
//! [`runtime`].

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Command;

mod backend;
pub mod dispatch;
mod rewrite;
pub mod runtime;

pub use backend::E9patchBackend;
pub use dispatch::E9patchDispatcher;
// Re-exported from the shared crate so a consumer selecting an e9patch built-in
// tool imports the *same* enum both ld-preload backends use. The tool is shared,
// not e9patch-private (only the env-var spelling differs).
pub use reverie_preload::BuiltinTool;
pub use reverie_preload::SPOOF_PID;
pub use rewrite::E9PATCH_BACKEND_ENV;
pub use rewrite::E9TOOL_ENV;
pub use rewrite::E9patchRewriter;
pub use rewrite::PreparedBinary;
pub use rewrite::RewriteReport;
pub use runtime::ALT_STACK_ENV;
pub use runtime::RUNTIME_ENV;
pub use runtime::RUNTIME_FALLBACK;
pub use runtime::RUNTIME_HYBRID;
pub use runtime::RuntimeMode;
pub use runtime::TOOL_ENV;
pub use runtime::TOOL_PASSTHROUGH;
pub use runtime::TOOL_SPOOF_GETPID;
pub use runtime::alt_stack_from_env_value;
pub use runtime::builtin_tool_from_env_value;

/// Environment variable overriding the located e9patch preload library path.
///
/// Mirrors LiteInst's `REVERIE_LITEINST_PRELOAD` and `reverie-preload`'s
/// `REVERIE_PRELOAD_LIB` contract.
pub const PRELOAD_LIB_ENV: &str = "REVERIE_E9PATCH_PRELOAD";

/// Locates the e9patch preload cdylib produced beside the current executable.
///
/// The search order mirrors LiteInst's `preload_library_path` exactly so the
/// two ld-preload backends resolve their runtime `.so` identically.
pub fn preload_library_path() -> io::Result<PathBuf> {
    if let Some(path) = env::var_os(PRELOAD_LIB_ENV) {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{PRELOAD_LIB_ENV} does not name a file"),
            )
        });
    }

    let executable = env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "current executable has no parent")
    })?;
    [
        parent.join("libreverie_e9patch.so"),
        parent.join("deps/libreverie_e9patch.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_e9patch.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot find libreverie_e9patch.so beside {}",
                executable.display()
            ),
        )
    })
}

/// Prepends `preload` to any inherited `LD_PRELOAD`, preserving order.
///
/// Pure so the ordering contract (our cdylib first, existing entries after) is
/// unit-testable without touching the process environment or spawning a guest.
fn compose_ld_preload(preload: PathBuf, inherited: Option<OsString>) -> OsString {
    let mut value = preload.into_os_string();
    if let Some(existing) = inherited.filter(|existing| !existing.is_empty()) {
        value.push(OsStr::new(":"));
        value.push(existing);
    }
    value
}

/// Configures a `std::process::Command` guest to load the e9patch preload
/// runtime in the self-contained in-process fallback mode.
///
/// Prepends the located cdylib to `LD_PRELOAD` and arms the runtime via
/// [`RUNTIME_ENV`]. This is the *same* ld-preload injection LiteInst performs;
/// only the library name and env-var spelling differ.
pub fn configure_command(command: &mut Command) -> io::Result<()> {
    let value = compose_ld_preload(preload_library_path()?, env::var_os("LD_PRELOAD"));
    command
        .env("LD_PRELOAD", value)
        .env(RUNTIME_ENV, RUNTIME_FALLBACK);
    Ok(())
}

/// Arms a `reverie::process::Command` guest with the shared e9patch preload
/// runtime under the requested [`RuntimeMode`].
///
/// This is the launcher-side half of the shared ld-preload injection — the
/// analog of LiteInst's `configure_command`/`launch` env wiring, but for the
/// `reverie::process::Command` the [`E9patchBackend`] spawns. It prepends the
/// located cdylib to any `LD_PRELOAD` already on the command (falling back to
/// the launcher's own environment) and selects the controller via
/// [`RuntimeMode::env_value`]. Injection is *the same mechanism* LiteInst uses;
/// only the AOT-vs-runtime patch timing and trampoline placement differ.
pub fn configure_guest_command(
    command: &mut reverie::process::Command,
    mode: RuntimeMode,
) -> io::Result<()> {
    let inherited = command
        .get_env("LD_PRELOAD")
        .map(|value| value.into_owned())
        .or_else(|| env::var_os("LD_PRELOAD"));
    let value = compose_ld_preload(preload_library_path()?, inherited);
    command
        .env("LD_PRELOAD", value)
        .env(RUNTIME_ENV, mode.env_value());
    Ok(())
}

/// Arms a `reverie::process::Command` guest with a **shared** [`BuiltinTool`].
///
/// This is the launcher-side half of built-in-tool selection — the direct analog
/// of LiteInst's `configure_command(command, PreloadTool)`, differing only in
/// that the tool is one of reverie-preload's shared built-ins (installed via the
/// shared `install_builtin`) rather than a backend-private one. It prepends the
/// located cdylib to any inherited `LD_PRELOAD` and sets [`TOOL_ENV`], which the
/// in-guest constructor reads with priority over the controller-mode
/// [`RUNTIME_ENV`]. Built-in tools run under the shared isolated in-process
/// controller (the demo/testing path); the arbitrary-`Tool` production path
/// remains ptrace-hosted.
pub fn configure_guest_builtin(
    command: &mut reverie::process::Command,
    tool: BuiltinTool,
) -> io::Result<()> {
    let inherited = command
        .get_env("LD_PRELOAD")
        .map(|value| value.into_owned())
        .or_else(|| env::var_os("LD_PRELOAD"));
    let value = compose_ld_preload(preload_library_path()?, inherited);
    command
        .env("LD_PRELOAD", value)
        .env(TOOL_ENV, builtin_tool_env_value(tool));
    Ok(())
}

/// Selects the shared [`RuntimeConfig`](reverie_preload::lifecycle::RuntimeConfig)
/// `use_alt_stack` knob on a guest command via [`ALT_STACK_ENV`].
///
/// Additive to [`configure_guest_command`]/[`configure_guest_builtin`]: those arm
/// the runtime, while this tunes the shared config the controller-mode install
/// paths honor. The value is spelled so the in-guest [`alt_stack_from_env_value`]
/// parser round-trips it. The config struct and the controller that honors it are
/// shared reverie-preload code, reviewed once; only this env spelling is
/// e9patch's — the same shared-vs-local split as tool and controller selection.
// TODO-HUMAN-REVIEW(PR-250): Review launcher-side alt-stack config setter.
pub fn set_guest_alt_stack(command: &mut reverie::process::Command, use_alt_stack: bool) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    command.env(ALT_STACK_ENV, if use_alt_stack { "1" } else { "0" });
}

/// The canonical [`TOOL_ENV`] string for a shared [`BuiltinTool`].
///
/// Kept beside [`configure_guest_builtin`] so the launcher and the in-guest
/// [`builtin_tool_from_env_value`] parser agree on the exact spelling.
fn builtin_tool_env_value(tool: BuiltinTool) -> &'static str {
    // Exhaustive on purpose: if reverie-preload adds a built-in, e9patch must map
    // it here rather than silently arming an unintended tool.
    match tool {
        BuiltinTool::Passthrough => TOOL_PASSTHROUGH,
        BuiltinTool::SpoofGetpid => TOOL_SPOOF_GETPID,
    }
}

// TODO-HUMAN-REVIEW(PR-104): Review the e9patch preload constructor that installs
// process-wide signal and seccomp state.
/// Initializes the e9patch preload runtime when armed by the launcher
/// environment.
///
/// # Safety
///
/// The dynamic loader must call this exactly once before application threads
/// start. Calling it again would stack an irreversible seccomp filter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_e9patch_initialize() {
    // SAFETY: invoked from `.init_array` before application threads start; the
    // runtime is inert unless RUNTIME_ENV arms it.
    if let Err(error) = unsafe { runtime::initialize_from_environment() } {
        eprintln!("reverie-e9patch initialization failed: {error}");
        unsafe {
            libc::_exit(127);
        }
    }
}

#[cfg(feature = "preload-constructor")]
#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_E9PATCH_INIT: unsafe extern "C" fn() = reverie_e9patch_initialize;

// TODO-HUMAN-REVIEW(PR-246): Review public fallback-surface observability counters.
/// Total syscalls serviced by e9patch's shared `SIGSYS` fallback dispatcher.
///
/// This is the e9patch analog of LiteInst's `reverie_liteinst_site_trap_count`:
/// a C-ABI counter that makes the instrumentation surface observable from the
/// guest. Because AOT-rewritten sites never trap, this counts exactly the
/// residual, un-rewritten fallback surface (loader/startup, vDSO, uncovered or
/// JIT-emitted sites). A value near zero confirms e9tool's ahead-of-time
/// coverage is carrying the syscall load.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_e9patch_fallback_dispatch_count() -> u64 {
    dispatch::fallback_dispatch_count()
}

// TODO-HUMAN-REVIEW(PR-246): Review public fallback-surface observability counters.
/// Number of times syscall `number` reached the shared fallback dispatcher.
///
/// The per-number analog of the LiteInst per-site counters, keyed by syscall
/// number because e9patch has no runtime sites to key on. Returns `0` for a
/// negative number or one outside the tracked range; such syscalls are still
/// reflected in [`reverie_e9patch_fallback_dispatch_count`].
#[unsafe(no_mangle)]
pub extern "C" fn reverie_e9patch_fallback_syscall_count(number: i64) -> u64 {
    dispatch::fallback_syscall_count(number)
}

// TODO-HUMAN-REVIEW(PR-253): Review public per-site fallback-surface observability.
/// Number of times the fallback dispatcher serviced a syscall issued at the
/// un-rewritten site `address`.
///
/// This is the **address-keyed** analog of LiteInst's
/// `reverie_liteinst_site_trap_count`, closing the round-4 gap where the e9patch
/// fallback was observable only by syscall number: it localizes the residual
/// fallback surface to the exact instruction addresses `e9tool` could not rewrite
/// ahead of time (loader/startup, vDSO, uncovered or JIT-emitted sites). There is
/// no `hook`-count analog — the fallback never installs a runtime hook (that is
/// the AOT-vs-runtime difference), so every execution of an un-rewritten site
/// traps, making this the direct analog of LiteInst's *trap* count specifically.
/// Returns `0` for a never-seen site or one displaced by
/// [`reverie_e9patch_fallback_site_overflow`].
#[unsafe(no_mangle)]
pub extern "C" fn reverie_e9patch_fallback_site_count(address: u64) -> u64 {
    dispatch::fallback_site_count(address)
}

// TODO-HUMAN-REVIEW(PR-253): Review public per-site fallback-surface observability.
/// Fallback services that could not be attributed to a per-site slot because the
/// bounded site table was full.
///
/// A nonzero value means per-site localization via
/// [`reverie_e9patch_fallback_site_count`] is incomplete; the process-wide totals
/// from [`reverie_e9patch_fallback_dispatch_count`] and
/// [`reverie_e9patch_fallback_syscall_count`] remain exact. Reported explicitly
/// so a bounded table never masquerades as full coverage.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_e9patch_fallback_site_overflow() -> u64 {
    dispatch::fallback_site_overflow()
}

/// Magic RAX value identifying an e9patch replacement-syscall trap.
// TODO-HUMAN-REVIEW(PR-102): Review the public injected-event ABI marker.
pub const E9PATCH_SYSCALL_TRAP_MARKER: u64 = 0x7265_7665_3965_3970;

/// Continuation RIP immediately after the e9patch payload's `int3`.
// TODO-HUMAN-REVIEW(PR-103): Review the fixed e9patch payload trap address.
pub const E9PATCH_SYSCALL_TRAP_RIP: u64 = 0x7000_100b;

// TODO-HUMAN-REVIEW(PR-95): Review the public e9patch source identity API.
/// Git revision of the e9patch source pinned in `third-party/e9patch`.
pub const E9PATCH_SOURCE_REVISION: &str = "6c2c03c1da74b14daf1788a9f8dccfa354ce04a6";

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::ALT_STACK_ENV;
    use super::BuiltinTool;
    use super::E9PATCH_SOURCE_REVISION;
    use super::alt_stack_from_env_value;
    use super::builtin_tool_env_value;
    use super::builtin_tool_from_env_value;
    use super::compose_ld_preload;
    use super::set_guest_alt_stack;

    #[test]
    fn pinned_revision_is_a_full_git_object_id() {
        assert_eq!(E9PATCH_SOURCE_REVISION.len(), 40);
        assert!(
            E9PATCH_SOURCE_REVISION
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[test]
    fn ld_preload_puts_our_library_first() {
        let composed = compose_ld_preload(
            PathBuf::from("/opt/libreverie_e9patch.so"),
            Some(OsString::from("/lib/a.so:/lib/b.so")),
        );
        assert_eq!(
            composed,
            OsString::from("/opt/libreverie_e9patch.so:/lib/a.so:/lib/b.so")
        );
    }

    #[test]
    fn ld_preload_without_inherited_is_just_our_library() {
        assert_eq!(
            compose_ld_preload(PathBuf::from("/opt/x.so"), None),
            OsString::from("/opt/x.so")
        );
        // An empty inherited value must not produce a trailing separator.
        assert_eq!(
            compose_ld_preload(PathBuf::from("/opt/x.so"), Some(OsString::new())),
            OsString::from("/opt/x.so")
        );
    }

    #[test]
    fn builtin_tool_env_value_round_trips_through_the_parser() {
        // The launcher-side spelling and the in-guest parser must agree for every
        // shared built-in, so a guest armed by `configure_guest_builtin` installs
        // exactly the tool the launcher selected.
        for tool in [BuiltinTool::Passthrough, BuiltinTool::SpoofGetpid] {
            let spelling = builtin_tool_env_value(tool);
            assert_eq!(
                builtin_tool_from_env_value(std::ffi::OsStr::new(spelling)),
                Some(tool),
                "round-trip failed for {tool:?}"
            );
        }
    }

    #[test]
    fn alt_stack_setter_round_trips_through_the_parser() {
        // The launcher-side setter and the in-guest parser must agree, so a guest
        // armed by `set_guest_alt_stack` installs exactly the config selected.
        for value in [true, false] {
            let mut command = reverie::process::Command::new("/bin/true");
            set_guest_alt_stack(&mut command, value);
            let raw = command
                .get_env(ALT_STACK_ENV)
                .expect("alt-stack env should be set")
                .into_owned();
            assert_eq!(
                alt_stack_from_env_value(Some(raw.as_os_str())).unwrap(),
                value,
                "round-trip failed for use_alt_stack={value}"
            );
        }
    }
}
