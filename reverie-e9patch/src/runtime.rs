/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! In-guest runtime install path for the e9patch ld-preload backend.
//!
//! The controller-mode path registers [`E9patchDispatcher`] and installs the
//! shared [`InProcessSeccomp`] lifecycle controller from `reverie-preload`. The
//! seccomp filter, `SIGSYS` handler, and trusted syscall gate are therefore the
//! **same code** in both backends. It intentionally does not publish the direct
//! AOT callback: generic `T: Tool` events remain owned by ptrace. Shared
//! [`BuiltinTool`] mode publishes that callback through
//! [`install_builtin_runtime`].
//!
//! The difference from LiteInst is only what the SIGSYS path is *for*. In
//! LiteInst it is the discovery-and-patch mechanism. In e9patch the syscall
//! sites are already rewritten ahead of time by `e9tool`, so the SIGSYS filter
//! is the safety net for the residual sites e9patch could not rewrite
//! (loader/startup, vDSO, uncovered/JIT code). See [`crate::dispatch`].

use std::env;
use std::ffi::OsStr;
use std::io;

use reverie_preload::BuiltinTool;
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

/// [`RUNTIME_ENV`] value selecting the in-process residual controller.
///
/// This installs only the residual `SIGSYS` controller. It deliberately leaves
/// the direct AOT callback unpublished so rewritten sites retain their ptrace
/// trap and cannot bypass the generic `T: Tool` selected by [`crate::E9patchBackend`].
/// Use [`TOOL_ENV`] (or [`crate::configure_command`]) for a standalone shared
/// built-in that publishes direct AOT dispatch.
pub const RUNTIME_FALLBACK: &str = "fallback";

/// [`RUNTIME_ENV`] value selecting the ptrace-hosted hybrid controller.
///
/// This selects the hybrid controller identity for the guest half. It installs
/// the in-process `SIGSYS` trap for residual un-rewritten sites; the caller
/// separately selects and validates any ptrace lifecycle owner. See
/// [`RuntimeMode::HybridPtrace`].
pub const RUNTIME_HYBRID: &str = "hybrid";

/// Environment variable selecting a **shared** built-in tool for the in-guest
/// runtime.
///
/// This is the direct analog of LiteInst's `REVERIE_LITEINST_TOOL` and
/// reverie-preload's [`TOOL_ENV`](reverie_preload::TOOL_ENV). The difference is
/// where the tool lives: LiteInst's built-ins (`strace`/`compat`) are
/// LiteInst-private, whereas e9patch selects reverie-preload's
/// [`BuiltinTool`]s **verbatim** — so the dispatcher code (including the
/// *mutating* `SpoofGetpid` demo) is written and reviewed exactly once in the
/// shared crate. Only the env-var spelling is e9patch's.
///
/// When set, this takes precedence over [`RUNTIME_ENV`]: a built-in tool runs
/// under the shared isolated in-process controller (exactly like
/// reverie-preload's standalone cdylib), which is the demo/testing path. The
/// arbitrary-`Tool` production path remains ptrace-hosted; see
/// [`crate::E9patchBackend`].
pub const TOOL_ENV: &str = "REVERIE_E9PATCH_TOOL";

/// [`TOOL_ENV`] value selecting the shared fail-closed pass-through tool.
///
/// Matches [`BuiltinTool::Passthrough`]: forward every syscall through the
/// trusted gate with the shared guards, altering no guest behavior. Proves the
/// direct AOT path and residual signal fallback end to end.
pub const TOOL_PASSTHROUGH: &str = "passthrough";

/// [`TOOL_ENV`] value selecting the shared `getpid`-spoofing demo tool.
///
/// Matches [`BuiltinTool::SpoofGetpid`]: forward everything except `getpid`,
/// which returns [`reverie_preload::SPOOF_PID`]. Proves the e9patch fallback
/// AOT path can *mutate* a syscall result, not merely forward it — the
/// capability the shared crate demonstrates via `install_builtin`.
pub const TOOL_SPOOF_GETPID: &str = "spoof-getpid";

/// Parse a [`TOOL_ENV`] value into a shared [`BuiltinTool`], or `None` when the
/// value is unrecognized.
///
/// The variants map to reverie-preload's public enum so the selected dispatcher
/// is shared-crate code, not an e9patch reimplementation. Kept pure so the
/// parse contract is unit-testable without touching process-global state.
pub fn builtin_tool_from_env_value(value: &OsStr) -> Option<BuiltinTool> {
    if value == OsStr::new(TOOL_PASSTHROUGH) {
        Some(BuiltinTool::Passthrough)
    } else if value == OsStr::new(TOOL_SPOOF_GETPID) {
        Some(BuiltinTool::SpoofGetpid)
    } else {
        None
    }
}

/// Environment variable selecting the shared [`RuntimeConfig::use_alt_stack`]
/// knob for the in-guest runtime's `SIGSYS` handler.
///
/// The [`RuntimeConfig`] and the controller that honors it live in
/// `reverie-preload` and are reviewed exactly once; both ld-preload backends
/// install through that same shared seam. Only the env-var spelling is
/// e9patch's, exactly as with [`TOOL_ENV`] and [`RUNTIME_ENV`].
///
/// When unset the shared default applies ([`RuntimeConfig::default`], alt stack
/// **on**). It applies to the controller-mode install paths
/// ([`install_runtime`]/[`install_hybrid_runtime`]); a [`TOOL_ENV`] built-in
/// runs through the shared `install_builtin`, which uses the shared default.
// TODO-HUMAN-REVIEW(PR-250): Review launcher-selected shared RuntimeConfig alt-stack knob.
pub const ALT_STACK_ENV: &str = "REVERIE_E9PATCH_ALT_STACK";

/// Parse an [`ALT_STACK_ENV`] value into the `use_alt_stack` boolean.
///
/// `None` (unset) yields the shared default. Accepts `1`/`0`, `true`/`false`,
/// `on`/`off`, and `yes`/`no` (case-insensitive, surrounding whitespace
/// trimmed). Any other value is rejected. Kept pure so the parse/reject contract
/// is unit-testable without touching process-global state, matching
/// [`builtin_tool_from_env_value`].
// TODO-HUMAN-REVIEW(PR-250): Review alt-stack env parse/reject contract.
pub fn alt_stack_from_env_value(value: Option<&OsStr>) -> io::Result<bool> {
    // AUTONOMOUS-BOT-IMPLEMENTED
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

/// Build the shared [`RuntimeConfig`] the launcher selected via [`ALT_STACK_ENV`].
///
/// Reads the process environment once; the parse itself is delegated to the pure
/// [`alt_stack_from_env_value`].
pub(crate) fn runtime_config_from_env() -> io::Result<RuntimeConfig> {
    // AUTONOMOUS-BOT-IMPLEMENTED
    let use_alt_stack = alt_stack_from_env_value(env::var_os(ALT_STACK_ENV).as_deref())?;
    Ok(RuntimeConfig { use_alt_stack })
}

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
/// * **e9patch** may pair the guest runtime with a ptrace lifecycle owner, so its
///   hybrid controller identity is [`HybridPtrace`](Self::HybridPtrace)
///   ([`reverie_preload::lifecycle::HybridPtrace`]). The controller value selects
///   only the guest-half trap; it neither constructs nor proves the launcher's
///   subscription, loader-window, or vDSO behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    /// In-process residual seccomp + `SIGSYS`; AOT sites retain the ptrace trap.
    InProcessFallback,
    /// In-process `SIGSYS` guest half intended for a separately selected ptrace
    /// lifecycle owner.
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

/// Register [`E9patchDispatcher`] and install the in-process residual controller
/// ([`InProcessSeccomp`]).
///
/// This controller services un-rewritten `SIGSYS` sites only. It does **not**
/// publish the AOT callback, so a rewritten binary still needs its ptrace owner.
/// For ptrace-free shared built-ins, use [`install_builtin_runtime`]. E9patch's
/// generic production mode is [`install_hybrid_runtime`].
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
/// This installs only the guest half of e9patch's hybrid controller: the same
/// in-process `SIGSYS` handler + trusted-gate seccomp filter as
/// [`InProcessSeccomp`]. Launcher ownership is selected separately and is not
/// encoded or verified by [`HybridPtrace`]. The direct-tool environment path
/// pairs this guest mechanism (through `install_tool`) with a
/// `reverie_ptrace::TracerBuilder::<()>` lifecycle reaper; the ptrace-hosted
/// `E9patchBackend` fallback path instead retains its generic host Tool.
///
/// # Safety
///
/// See [`install_runtime`].
pub unsafe fn install_hybrid_runtime() -> io::Result<()> {
    // SAFETY: forwarded to the caller's once-before-threads contract.
    unsafe { install_with_controller(&HybridPtrace) }
}

/// Install one of reverie-preload's **shared** [`BuiltinTool`]s under the shared
/// isolated in-process controller.
///
/// This forwards directly to [`reverie_preload::install_builtin`], so the
/// dispatcher (including the *mutating* [`BuiltinTool::SpoofGetpid`]), the
/// seccomp filter, the `SIGSYS` handler, and the trusted gate are the exact
/// shared code both ld-preload backends rely on. It is the e9patch analog of
/// LiteInst's built-in `strace`/`compat` selection, differing only in that the
/// tool itself is shared rather than backend-private.
///
/// Built-in tools run under [`InProcessSeccomp`] (the isolated demo/testing
/// path, matching reverie-preload's standalone cdylib), not the ptrace-hosted
/// production controller. e9patch's arbitrary-`Tool` production events still go
/// through ptrace; see [`crate::E9patchBackend`].
///
/// # Safety
///
/// See [`install_runtime`].
pub unsafe fn install_builtin_runtime(tool: BuiltinTool) -> io::Result<()> {
    let dispatch_page = crate::aot::PendingDispatchPage::prepare()?;
    // SAFETY: forwarded to the caller's once-before-threads contract; the shared
    // installer registers the dispatcher before installing the filter/handler.
    let result = unsafe { reverie_preload::install_builtin(tool) };
    if result.is_ok() {
        dispatch_page.commit();
    }
    result
}

/// Register the shared dispatcher and install the given shared controller.
///
/// # Safety
///
/// See [`install_runtime`].
unsafe fn install_with_controller(controller: &dyn LifecycleController) -> io::Result<()> {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // Honor the launcher-selected shared config (ALT_STACK_ENV) instead of an
    // unconditional default, so the same shared RuntimeConfig knob reverie-preload
    // exposes is reachable from the e9patch launcher. Unset => shared default.
    let config = runtime_config_from_env()?;
    // AUTONOMOUS-BOT-IMPLEMENTED
    // Use the fork-following dispatcher so each fork/clone child resets its
    // per-process fallback observability via the shared ForkHook seam (the same
    // per-process-reset mechanism LiteInst uses); COW-inherited parent counts
    // would otherwise mis-attribute the child's residual surface.
    // SAFETY: the dispatcher is registered before the controller installs the
    // SIGSYS handler + filter; forwarded to the caller's contract above.
    unsafe {
        reverie_preload::install(
            Box::new(E9patchDispatcher::with_fork_reset()),
            controller,
            &config,
        )
    }
}

/// Read the launcher environment and install the in-guest runtime it selects.
///
/// Precedence:
///
/// 1. [`TOOL_ENV`] (a shared [`BuiltinTool`]) takes priority. It installs the
///    shared built-in dispatcher under the isolated in-process controller — the
///    demo/testing path, matching reverie-preload's standalone cdylib.
/// 2. Otherwise [`RUNTIME_ENV`] selects the controller the e9patch fail-closed
///    dispatcher runs under (see [`RuntimeMode`]).
/// 3. With neither set the preload is inert (`Ok(())`), matching the shared
///    preload contract, so an unrelated process that merely has the `.so` on
///    `LD_PRELOAD` is unaffected.
///
/// # Safety
///
/// See [`install_runtime`]. When an env var arms the runtime, this installs
/// process-global irreversible state and must run exactly once before
/// application threads start.
pub unsafe fn initialize_from_environment() -> io::Result<()> {
    if let Some(value) = env::var_os(TOOL_ENV) {
        let tool = builtin_tool_from_env_value(&value).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported {TOOL_ENV} value {value:?}"),
            )
        })?;
        // SAFETY: forwarded to the caller's once-before-threads contract.
        return unsafe { install_builtin_runtime(tool) };
    }

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
    fn builtin_tool_env_values_map_to_the_shared_enum() {
        // e9patch selects reverie-preload's built-in tools *verbatim*; only the
        // env-var spelling is local. Assert the mapping and reject unknowns
        // without installing anything.
        assert_eq!(
            builtin_tool_from_env_value(OsStr::new(TOOL_PASSTHROUGH)),
            Some(BuiltinTool::Passthrough)
        );
        assert_eq!(
            builtin_tool_from_env_value(OsStr::new(TOOL_SPOOF_GETPID)),
            Some(BuiltinTool::SpoofGetpid)
        );
        assert_eq!(TOOL_PASSTHROUGH, "passthrough");
        assert_eq!(TOOL_SPOOF_GETPID, "spoof-getpid");
        assert!(builtin_tool_from_env_value(OsStr::new("bogus")).is_none());
        assert!(builtin_tool_from_env_value(OsStr::new("")).is_none());
    }

    #[test]
    fn tool_env_is_distinct_from_controller_env() {
        // The built-in-tool selector and the controller-mode selector are
        // separate knobs; TOOL_ENV takes precedence in initialize_from_environment.
        assert_eq!(TOOL_ENV, "REVERIE_E9PATCH_TOOL");
        assert_ne!(TOOL_ENV, RUNTIME_ENV);
    }

    #[test]
    fn alt_stack_defaults_to_the_shared_default_when_unset() {
        // Unset must reproduce reverie-preload's shared default exactly, so an
        // e9patch launcher that never sets the knob behaves identically to the
        // shared crate.
        assert_eq!(
            alt_stack_from_env_value(None).unwrap(),
            RuntimeConfig::default().use_alt_stack
        );
    }

    #[test]
    fn alt_stack_parses_truthy_and_falsy_spellings() {
        for truthy in ["1", "true", "TRUE", "on", "Yes", " yes ", "\tON\n"] {
            assert!(
                alt_stack_from_env_value(Some(OsStr::new(truthy))).unwrap(),
                "{truthy:?} should parse as alt-stack on"
            );
        }
        for falsy in ["0", "false", "FALSE", "off", "No", " no ", "\toff\n"] {
            assert!(
                !alt_stack_from_env_value(Some(OsStr::new(falsy))).unwrap(),
                "{falsy:?} should parse as alt-stack off"
            );
        }
    }

    #[test]
    fn alt_stack_rejects_unknown_values() {
        for bogus in ["", "maybe", "2", "enable"] {
            assert!(
                alt_stack_from_env_value(Some(OsStr::new(bogus))).is_err(),
                "{bogus:?} should be rejected"
            );
        }
    }

    #[test]
    fn alt_stack_env_is_distinct_from_the_other_selectors() {
        // The config knob is a separate axis from tool selection and controller
        // selection; all three env vars must be distinct.
        assert_eq!(ALT_STACK_ENV, "REVERIE_E9PATCH_ALT_STACK");
        assert_ne!(ALT_STACK_ENV, TOOL_ENV);
        assert_ne!(ALT_STACK_ENV, RUNTIME_ENV);
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
