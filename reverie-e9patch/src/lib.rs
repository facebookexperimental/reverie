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

/// Configures a guest command to load the e9patch preload runtime.
///
/// Prepends the located cdylib to `LD_PRELOAD` and arms the runtime via
/// [`RUNTIME_ENV`]. This is the *same* ld-preload injection LiteInst performs;
/// only the library name and env-var spelling differ.
pub fn configure_command(command: &mut Command) -> io::Result<()> {
    let mut preload = preload_library_path()?.into_os_string();
    if let Some(existing) = env::var_os("LD_PRELOAD").filter(|value| !value.is_empty()) {
        preload.push(OsStr::new(":"));
        preload.push(existing);
    }
    command
        .env("LD_PRELOAD", preload)
        .env(RUNTIME_ENV, RUNTIME_FALLBACK);
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
    use super::E9PATCH_SOURCE_REVISION;

    #[test]
    fn pinned_revision_is_a_full_git_object_id() {
        assert_eq!(E9PATCH_SOURCE_REVISION.len(), 40);
        assert!(
            E9PATCH_SOURCE_REVISION
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }
}
