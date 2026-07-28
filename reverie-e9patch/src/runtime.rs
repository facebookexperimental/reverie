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
use std::ffi::OsStr;
use std::io;

use reverie_preload::lifecycle::HybridPtrace;
use reverie_preload::lifecycle::InProcessSeccomp;
use reverie_preload::lifecycle::LifecycleController;
use reverie_preload::lifecycle::RuntimeConfig;

use crate::dispatch::E9patchDispatcher;

/// Environment variable that arms the e9patch preload runtime.
///
/// When unset the preload constructor is inert, so an unrelated process that
/// merely has the `.so` on `LD_PRELOAD` is unaffected. This matches
/// `reverie-preload`'s `REVERIE_PRELOAD_TOOL` and LiteInst's
/// `REVERIE_LITEINST_TOOL` opt-in contract.
pub const RUNTIME_ENV: &str = "REVERIE_E9PATCH_RUNTIME";

/// [`RUNTIME_ENV`] value selecting the self-contained in-process controller.
///
/// e9patch's arbitrary-`Tool` fast path is delivered by the AOT trampolines,
/// not by this in-guest runtime, so the only built-in dispatcher today is the
/// shared fail-closed fallback. A future increment adds a tool-specific preload
/// DSO exactly as LiteInst does (`install_tool::<T>`).
pub const RUNTIME_FALLBACK: &str = "fallback";

/// [`RUNTIME_ENV`] value selecting the ptrace-hosted hybrid controller.
///
/// This is e9patch's *production* mode: the shared fallback ptracer owns
/// process lifecycle while the in-process `SIGSYS` trap covers residual
/// un-rewritten sites. See [`RuntimeMode::HybridPtrace`].
pub const RUNTIME_HYBRID: &str = "hybrid";

/// Which shared `reverie-preload` lifecycle controller the in-guest runtime
/// installs.
///
/// # Shared with LiteInst
///
/// Both ld-preload backends share reverie-preload's
/// [`LifecycleController`] seam
/// **and** the same [`E9patchDispatcher`]/`PassthroughDispatcher` policy.
/// Selecting a controller is therefore a *config choice on one shared seam*,
/// not a mechanism fork — exactly as `reverie-preload` documents ("select it via
/// config; the dispatcher, seccomp filter, trap handler, and RPC client are
/// unchanged").
///
/// # Different from LiteInst
///
/// The controller a backend *selects* reflects who owns lifecycle:
///
/// * **LiteInst** runs standalone in-process, so it selects
///   [`InProcessFallback`](Self::InProcessFallback)
///   ([`InProcessSeccomp`]).
/// * **e9patch** runs the guest under the shared fallback ptracer, which owns
///   pre-`main` setup, `exec`/`clone` stops, and vDSO patching, so its
///   production controller is [`HybridPtrace`](Self::HybridPtrace)
///   ([`reverie_preload::lifecycle::HybridPtrace`]). This is *the same fallback
///   ptracer* the two backends share, expressed through the shared seam — not a
///   third architectural difference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    /// Self-contained in-process seccomp + `SIGSYS`. Matches LiteInst standalone.
    InProcessFallback,
    /// In-process `SIGSYS` hot path with the shared ptracer owning lifecycle.
    HybridPtrace,
}

impl RuntimeMode {
    /// Parse a [`RUNTIME_ENV`] value into a mode, or `None` if unrecognized.
    pub fn from_env_value(value: &OsStr) -> Option<Self> {
        if value == OsStr::new(RUNTIME_FALLBACK) {
            Some(Self::InProcessFallback)
        } else if value == OsStr::new(RUNTIME_HYBRID) {
            Some(Self::HybridPtrace)
        } else {
            None
        }
    }

    /// The canonical [`RUNTIME_ENV`] string for this mode.
    pub fn env_value(self) -> &'static str {
        match self {
            Self::InProcessFallback => RUNTIME_FALLBACK,
            Self::HybridPtrace => RUNTIME_HYBRID,
        }
    }

    /// The shared controller's diagnostic name (from `reverie-preload`).
    pub fn controller_name(self) -> &'static str {
        match self {
            Self::InProcessFallback => InProcessSeccomp.name(),
            Self::HybridPtrace => HybridPtrace.name(),
        }
    }
}

/// Register [`E9patchDispatcher`] and install the self-contained in-process
/// controller ([`InProcessSeccomp`]).
///
/// This is the isolated, ptrace-free mode; it matches LiteInst's standalone
/// `install_runtime`. e9patch's production mode is [`install_hybrid_runtime`].
///
/// # Safety
///
/// Installs process-global, irreversible state (a `SIGSYS` handler and a
/// seccomp filter). The dynamic loader must call this exactly once, before any
/// application thread starts. Calling it twice would stack a second
/// irreversible seccomp filter.
pub unsafe fn install_runtime() -> io::Result<()> {
    // SAFETY: forwarded to the caller's once-before-threads contract.
    unsafe { install_with_controller(&InProcessSeccomp) }
}

/// Register [`E9patchDispatcher`] and install the ptrace-hosted hybrid
/// controller ([`HybridPtrace`]).
///
/// This is e9patch's production controller: the shared fallback ptracer owns
/// lifecycle while the in-process `SIGSYS` trap serves residual un-rewritten
/// sites. The shared `HybridPtrace` controller is presently a documented
/// skeleton (see `reverie-preload`), so this returns [`io::ErrorKind::Unsupported`]
/// until that lifecycle owner lands — which is correct today, because e9patch's
/// in-guest fast path is not yet active and ptrace performs all event handling.
///
/// # Safety
///
/// See [`install_runtime`].
pub unsafe fn install_hybrid_runtime() -> io::Result<()> {
    // SAFETY: forwarded to the caller's once-before-threads contract.
    unsafe { install_with_controller(&HybridPtrace) }
}

/// Register the shared dispatcher and install the given shared controller.
///
/// # Safety
///
/// See [`install_runtime`].
unsafe fn install_with_controller(controller: &dyn LifecycleController) -> io::Result<()> {
    let config = RuntimeConfig::default();
    // SAFETY: the dispatcher is registered before the controller installs the
    // SIGSYS handler + filter; forwarded to the caller's contract above.
    unsafe { reverie_preload::install(Box::new(E9patchDispatcher::new()), controller, &config) }
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
    match RuntimeMode::from_env_value(&value) {
        // SAFETY: forwarded to the caller's once-before-threads contract.
        Some(RuntimeMode::InProcessFallback) => unsafe { install_runtime() },
        // SAFETY: forwarded to the caller's once-before-threads contract.
        Some(RuntimeMode::HybridPtrace) => unsafe { install_hybrid_runtime() },
        None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {RUNTIME_ENV} value {value:?}"),
        )),
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
        assert_eq!(RUNTIME_HYBRID, "hybrid");
        assert_ne!(RUNTIME_FALLBACK, "");
        assert!(RuntimeMode::from_env_value(OsStr::new("bogus")).is_none());
    }

    #[test]
    fn mode_env_values_round_trip() {
        for mode in [RuntimeMode::InProcessFallback, RuntimeMode::HybridPtrace] {
            let parsed = RuntimeMode::from_env_value(OsStr::new(mode.env_value()));
            assert_eq!(parsed, Some(mode));
        }
        assert_eq!(
            RuntimeMode::from_env_value(OsStr::new(RUNTIME_FALLBACK)),
            Some(RuntimeMode::InProcessFallback)
        );
        assert_eq!(
            RuntimeMode::from_env_value(OsStr::new(RUNTIME_HYBRID)),
            Some(RuntimeMode::HybridPtrace)
        );
    }

    #[test]
    fn controller_names_match_the_shared_crate() {
        // Each mode names the *same* shared reverie-preload controller both
        // ld-preload backends select from; no e9patch-private mechanism.
        assert_eq!(
            RuntimeMode::InProcessFallback.controller_name(),
            InProcessSeccomp.name()
        );
        assert_eq!(
            RuntimeMode::HybridPtrace.controller_name(),
            HybridPtrace.name()
        );
        assert_eq!(RuntimeMode::HybridPtrace.controller_name(), "hybrid-ptrace");
    }
}
