/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The lifecycle-controller seam.
//!
//! The runtime keeps *policy* (the [`SyscallDispatcher`](crate::dispatch)) apart
//! from the guest-half trap mechanism. [`LifecycleController`] installs that
//! guest-half mechanism only; startup, `exec`, thread creation, and reaping are
//! launcher responsibilities outside this trait.
//!
//! [`InProcessSeccomp`] and [`HybridPtrace`] both install seccomp + SIGSYS
//! entirely in-process. The `research-ldpreload-derisking` task showed that this
//! guest-half mechanism cannot cover the ~40 loader/startup syscalls before the
//! constructor, vDSO fast paths, or `exec` rebootstrap. `HybridPtrace` names an
//! intended pairing with a separately constructed ptrace lifecycle owner; it
//! does not construct or verify that launcher.
//!
//! Because both share this trait and the same [`RuntimeConfig`]/dispatcher, that
//! switch is *additive*: implement a new controller, select it via config; the
//! dispatcher, seccomp filter, trap handler, and RPC client are unchanged. Both
//! controllers install the identical guest-half in-process trap (see
//! [`install_in_process_trap`]); launcher selection is a separate caller
//! responsibility. See [`HybridPtrace`] for the precise boundary.

use std::io;

use crate::seccomp::SeccompFilter;
use crate::trap;

/// How the runtime installs its guest-half syscall trap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// Run the SIGSYS handler on an alternate signal stack.
    pub use_alt_stack: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            use_alt_stack: true,
        }
    }
}

/// The mechanism seam. A dispatcher is registered separately via
/// [`trap::set_dispatcher`] before `install`.
pub trait LifecycleController {
    /// A short name for diagnostics.
    fn name(&self) -> &'static str;

    /// Install the trap mechanism. On return, the guest's syscalls are being
    /// routed to the registered dispatcher.
    ///
    /// # Safety
    ///
    /// Installs process-global, largely irreversible state (signal handler,
    /// seccomp filter). Call exactly once, after the dispatcher is registered.
    unsafe fn install(&self, config: &RuntimeConfig) -> io::Result<()>;
}

/// In-process seccomp + SIGSYS. The default controller.
#[derive(Debug, Default, Clone, Copy)]
pub struct InProcessSeccomp;

impl LifecycleController for InProcessSeccomp {
    fn name(&self) -> &'static str {
        "in-process-seccomp"
    }

    unsafe fn install(&self, config: &RuntimeConfig) -> io::Result<()> {
        // SAFETY: forwarded to the caller's once-after-dispatcher-registered
        // contract; this controller adds no launcher, so the in-process trap is
        // the whole mechanism.
        unsafe { install_in_process_trap(config) }
    }
}

/// Build (but do not install) the trap-everything-but-the-trusted-gate seccomp
/// filter that every controller installs on the guest hot path.
///
/// Kept separate from [`install_in_process_trap`] so the buildable precondition
/// is unit-testable without installing irreversible process-global state.
fn build_trap_filter() -> io::Result<SeccompFilter> {
    SeccompFilter::for_trusted_gate(trap::trusted_gate())
}

/// Install the shared **guest-half** in-process syscall trap: the `SIGSYS`
/// handler first, then the trusted-gate seccomp filter that whitelists it.
///
/// This is the exact guest-half mechanism both [`InProcessSeccomp`] and
/// [`HybridPtrace`] put on the syscall path; neither type encodes a launcher.
/// Syscalls trap to the in-process handler. If the caller separately runs the
/// guest under ptrace, a residual `SIGSYS` is still visible as a signal-delivery
/// stop before reinjection.
///
/// # Safety
///
/// Installs process-global, largely irreversible state (signal handler, seccomp
/// filter). Call exactly once, after the dispatcher is registered. Ordering is
/// load-bearing: the handler must be in place before the filter starts trapping,
/// and the filter must whitelist the trusted gate.
unsafe fn install_in_process_trap(config: &RuntimeConfig) -> io::Result<()> {
    unsafe { trap::install_handler(config.use_alt_stack)? };
    let mut filter = build_trap_filter()?;
    unsafe { filter.install() }
}

/// The guest half of a hybrid in-process-trap + ptrace-lifecycle arrangement.
///
/// This is the guest half of a two-part backend. When paired with a unit-tool
/// tracer, rewritten hot-path sites add no `PTRACE_EVENT_SECCOMP` round trip:
///
/// * **This call (guest half, run in the `LD_PRELOAD` constructor)** installs the
///   exact same in-process `SIGSYS` trap as [`InProcessSeccomp`] — the handler,
///   then the trusted-gate seccomp filter — via [`install_in_process_trap`].
///   Rewritten sites therefore stay on the in-process hot path, and a tool such
///   as Detcore can run entirely in-guest. Un-instrumented / fail-closed sites
///   resolve through the in-guest `SIGSYS` handler; under a ptrace launcher the
///   signal is still observed as a signal-delivery stop before reinjection.
/// * **A launcher half (parent process, not this crate)** may use
///   `reverie_ptrace::TracerBuilder::<()>` as a unit-tool lifecycle reaper. Its
///   empty subscription set adds no `PTRACE_EVENT_SECCOMP` syscall action; it
///   follows/reaps the process tree and forwards signal-delivery stops. The
///   launcher does not close the dynamic-loader window before this preload
///   constructor runs, and a residual `SIGSYS` remains ptrace-visible as signal
///   delivery even though the in-guest handler, not a host Tool, services it.
///
/// This type installs no lifecycle owner and does not bind or inspect whichever
/// launcher the caller selected. A caller that pairs it with a unit-tool tracer
/// gets the disjoint arrangement above; other callers must reason about their
/// launcher's subscription/filter behavior separately. Because the guest-half
/// mechanism is identical to [`InProcessSeccomp`], the type itself does not
/// create a second syscall-interception mechanism.
#[derive(Debug, Default, Clone, Copy)]
pub struct HybridPtrace;

impl LifecycleController for HybridPtrace {
    fn name(&self) -> &'static str {
        "hybrid-ptrace"
    }

    unsafe fn install(&self, config: &RuntimeConfig) -> io::Result<()> {
        // The guest half installs the same in-process SIGSYS trap as
        // InProcessSeccomp. Launcher selection and its ptrace subscriptions are
        // separate caller responsibilities.
        // SAFETY: forwarded to the caller's once-after-dispatcher-registered
        // contract.
        unsafe { install_in_process_trap(config) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controllers_report_distinct_names() {
        assert_eq!(InProcessSeccomp.name(), "in-process-seccomp");
        assert_eq!(HybridPtrace.name(), "hybrid-ptrace");
    }

    #[test]
    fn hybrid_guest_half_builds_the_shared_in_process_trap_filter() {
        // HybridPtrace's guest half installs the exact same in-process SIGSYS
        // trap as InProcessSeccomp (handler, then trusted-gate filter); it
        // differs only by the controller identity selected by its caller.
        // `install()` itself installs irreversible, all-trapping
        // process-global state and cannot run inside the shared test binary, so
        // assert the previously-absent mechanism now exists: the trap filter
        // both controllers install builds for the live trusted gate and is
        // non-empty. When HybridPtrace was a stub this path returned
        // io::ErrorKind::Unsupported and built nothing.
        let filter = build_trap_filter().expect("shared trap filter builds for the live gate");
        assert!(!filter.is_empty());
    }

    #[test]
    fn default_config_uses_alt_stack() {
        assert!(RuntimeConfig::default().use_alt_stack);
    }
}
