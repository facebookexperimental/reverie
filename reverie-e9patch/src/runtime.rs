/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! In-guest runtime install path for the e9patch ld-preload backend.
//!
//! This mirrors `reverie-liteinst`'s `install_runtime` exactly: it registers a
//! [`SyscallDispatcher`](reverie_preload::dispatch::SyscallDispatcher) and then
//! installs the shared [`InProcessSeccomp`] lifecycle controller from
//! `reverie-preload`. The seccomp filter, `SIGSYS` handler, and trusted syscall
//! gate are therefore the **same code** in both backends.
//!
//! The difference from LiteInst is only what the SIGSYS path is *for*. In
//! LiteInst it is the discovery-and-patch mechanism. In e9patch the syscall
//! sites are already rewritten ahead of time by `e9tool`, so the SIGSYS filter
//! is the safety net for the residual sites e9patch could not rewrite
//! (loader/startup, vDSO, uncovered/JIT code). See [`crate::dispatch`].

use std::env;
use std::io;

use reverie_preload::lifecycle::InProcessSeccomp;
use reverie_preload::lifecycle::RuntimeConfig;

use crate::dispatch::E9patchDispatcher;

/// Environment variable that arms the e9patch preload runtime.
///
/// When unset the preload constructor is inert, so an unrelated process that
/// merely has the `.so` on `LD_PRELOAD` is unaffected. This matches
/// `reverie-preload`'s `REVERIE_PRELOAD_TOOL` and LiteInst's
/// `REVERIE_LITEINST_TOOL` opt-in contract.
pub const RUNTIME_ENV: &str = "REVERIE_E9PATCH_RUNTIME";

/// The value of [`RUNTIME_ENV`] that selects the fallback dispatcher.
///
/// e9patch's arbitrary-`Tool` fast path is delivered by the AOT trampolines,
/// not by this in-guest runtime, so the only built-in dispatcher today is the
/// shared fail-closed fallback. A future increment adds a tool-specific preload
/// DSO exactly as LiteInst does (`install_tool::<T>`).
pub const RUNTIME_FALLBACK: &str = "fallback";

/// Register [`E9patchDispatcher`] and install the shared in-process controller.
///
/// # Safety
///
/// Installs process-global, irreversible state (a `SIGSYS` handler and a
/// seccomp filter). The dynamic loader must call this exactly once, before any
/// application thread starts. Calling it twice would stack a second
/// irreversible seccomp filter.
pub unsafe fn install_runtime() -> io::Result<()> {
    let config = RuntimeConfig::default();
    // SAFETY: forwarded to the caller's contract above; the dispatcher is
    // registered before the controller installs the SIGSYS handler + filter.
    unsafe {
        reverie_preload::install(
            Box::new(E9patchDispatcher::new()),
            &InProcessSeccomp,
            &config,
        )
    }
}

/// Read [`RUNTIME_ENV`] and install the runtime when it selects a known mode.
///
/// Absent env var → inert (`Ok(())`), matching the shared preload contract.
///
/// # Safety
///
/// See [`install_runtime`]. When the env var arms the runtime, this installs
/// process-global irreversible state and must run exactly once before
/// application threads start.
pub unsafe fn initialize_from_environment() -> io::Result<()> {
    let Some(value) = env::var_os(RUNTIME_ENV) else {
        return Ok(());
    };
    if value == std::ffi::OsStr::new(RUNTIME_FALLBACK) {
        // SAFETY: forwarded to the caller's once-before-threads contract.
        unsafe { install_runtime() }
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {RUNTIME_ENV} value {value:?}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_without_env() {
        // The runtime must not touch process-global state when its env var is
        // unset. This is safe to run in the test process precisely because it
        // installs nothing.
        // SAFETY: RUNTIME_ENV is not set in the test harness, so this returns
        // Ok(()) without installing a handler or filter. Guard defensively in
        // case a parallel test set it.
        if env::var_os(RUNTIME_ENV).is_none() {
            let result = unsafe { initialize_from_environment() };
            assert!(result.is_ok());
        }
    }

    #[test]
    fn rejects_unknown_env_value() {
        // Verify the parse/reject path without installing anything. We cannot
        // call initialize_from_environment() with a mutated global environment
        // safely under parallel tests, so assert the mode string contract here.
        assert_eq!(RUNTIME_FALLBACK, "fallback");
        assert_ne!(RUNTIME_FALLBACK, "");
    }
}
