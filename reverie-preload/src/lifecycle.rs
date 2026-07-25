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
//! from *mechanism* (how a syscall gets trapped and how process lifecycle events
//! — startup, `exec`, thread creation — are covered). [`LifecycleController`] is
//! the mechanism seam.
//!
//! Today the only controller is [`InProcessSeccomp`]: seccomp + SIGSYS entirely
//! in-process. The `research-ldpreload-derisking` task showed this cannot cover
//! the ~40 loader/startup syscalls before the constructor, vDSO fast paths, or
//! `exec`. The intended remedy is a **hybrid** controller that keeps in-process
//! trapping on the hot path but adds a minimal ptrace/launcher lifecycle owner
//! (SaBRe-style) for pre-`main` setup, vDSO patching, and exec/clone stops.
//!
//! Because both share this trait and the same [`RuntimeConfig`]/dispatcher, that
//! switch is *additive*: implement a new controller, select it via config; the
//! dispatcher, seccomp filter, trap handler, and RPC client are unchanged. See
//! [`HybridPtrace`] for the documented skeleton.

use std::io;

use crate::seccomp::SeccompFilter;
use crate::trap;

/// How the runtime is told to trap and cover the guest.
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
        // Order matters: the handler must be in place before the filter starts
        // trapping, and the filter must whitelist the trusted gate.
        unsafe { trap::install_handler(config.use_alt_stack)? };
        let mut filter = SeccompFilter::for_trusted_gate(trap::trusted_gate())?;
        unsafe { filter.install() }
    }
}

/// Documented skeleton for the hybrid in-process-trap + ptrace-lifecycle backend.
///
/// This is intentionally not yet functional: building the ptrace lifecycle owner
/// is a separate task (see the SaBRe real-backend work). It exists here to pin
/// the seam so the switch is a drop-in. A real implementation would:
///
/// * launch the guest under a thin ptrace controller that installs a pre-`exec`
///   seccomp filter (closing the loader/startup gap and covering static/`exec`);
/// * keep this crate's in-process SIGSYS trap on the hot path for ordinary
///   syscalls (no ptrace stop per syscall);
/// * let the controller handle `exec`/`clone`/`vfork` stops and vDSO patching,
///   which the in-process filter cannot.
#[derive(Debug, Default, Clone, Copy)]
pub struct HybridPtrace;

impl LifecycleController for HybridPtrace {
    fn name(&self) -> &'static str {
        "hybrid-ptrace"
    }

    unsafe fn install(&self, _config: &RuntimeConfig) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hybrid-ptrace lifecycle controller is not yet implemented; \
             use InProcessSeccomp or the SaBRe real backend",
        ))
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
    fn hybrid_is_not_yet_installable() {
        let config = RuntimeConfig::default();
        let err = unsafe { HybridPtrace.install(&config) }.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn default_config_uses_alt_stack() {
        assert!(RuntimeConfig::default().use_alt_stack);
    }
}
