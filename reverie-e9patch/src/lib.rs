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
pub use rewrite::E9PATCH_BACKEND_ENV;
pub use rewrite::E9TOOL_ENV;
pub use rewrite::E9patchRewriter;
pub use rewrite::PreparedBinary;
pub use rewrite::RewriteReport;
pub use runtime::RUNTIME_ENV;
pub use runtime::RUNTIME_FALLBACK;
pub use runtime::RUNTIME_HYBRID;
pub use runtime::RuntimeMode;

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

    use super::E9PATCH_SOURCE_REVISION;
    use super::compose_ld_preload;

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
}
