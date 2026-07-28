/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The e9patch in-guest dispatcher, built on the shared `reverie-preload`
//! runtime that LiteInst also uses.
//!
//! # Shared with LiteInst
//!
//! e9patch and LiteInst plug into the *same* seam:
//! [`reverie_preload::dispatch::SyscallDispatcher`]. The `reverie-preload`
//! crate owns the seccomp filter, the `SIGSYS` handler, the trusted syscall
//! gate, and the fail-closed guard policy
//! ([`reverie_preload::dispatch::PassthroughDispatcher`]). Both backends reuse
//! that policy rather than reimplementing it, so the correctness-critical
//! boundaries (`execve` cannot cross an inherited filter, `SIGSYS` stays
//! reserved, non-null `clone` stacks are refused, …) are written and reviewed
//! exactly once.
//!
//! # Different from LiteInst
//!
//! The *only* architectural differences are **when** syscall sites are patched
//! and **where** the resulting trampoline lives:
//!
//! * **LiteInst** patches at *runtime*: the first execution of a syscall site
//!   traps to `SIGSYS`, and its dispatcher publishes a replacement trampoline
//!   in a reachable arena and
//!   [`defer_to`](reverie_preload::dispatch::SyscallEvent::defer_to)s it so the
//!   tool callback runs later in ordinary guest context. Every subsequent
//!   execution of that site is a near-native trampoline call.
//! * **e9patch** patches *ahead of time*: `e9tool` rewrites every recovered
//!   syscall instruction into a freestanding call trampoline *before* the guest
//!   ever runs. Those AOT trampolines are the fast path from the very first
//!   execution, so [`E9patchDispatcher`] never has to publish a runtime hook.
//!
//! Because AOT-rewritten sites do not trap, the `SIGSYS` dispatcher below is
//! only reached by sites e9patch could *not* rewrite ahead of time — the
//! dynamic loader and startup code, the vDSO fast paths, and any uncovered or
//! JIT-emitted site. For those, the shared fail-closed passthrough policy is
//! exactly the right behavior, and the ptrace lifecycle controller (see
//! [`crate::E9patchBackend`]) remains the correctness-first fallback owner for
//! the full `Guest` semantics an arbitrary tool needs.

use reverie_preload::dispatch::PassthroughDispatcher;
use reverie_preload::dispatch::SyscallDispatcher;
use reverie_preload::dispatch::SyscallEvent;

/// e9patch's `SIGSYS` dispatcher for sites that were **not** rewritten ahead of
/// time by `e9tool`.
///
/// AOT-rewritten sites reach the tool through their e9patch trampoline and never
/// trap, so this dispatcher governs only the fallback surface: loader/startup
/// syscalls before instrumentation, the vDSO, and any instruction e9patch's
/// static coverage missed. It reuses LiteInst's shared fail-closed
/// [`PassthroughDispatcher`] verbatim — the same Reverie hooks — forwarding each
/// such syscall through the trusted gate after applying the shared guards.
#[derive(Debug, Default)]
pub struct E9patchDispatcher {
    // The shared, reviewed-once policy. Held by value so e9patch reuses the
    // exact guard set LiteInst relies on instead of duplicating it.
    passthrough: PassthroughDispatcher,
}

impl E9patchDispatcher {
    /// A dispatcher that forwards every fallback syscall through the shared
    /// trusted gate, applying the shared fail-closed guards.
    pub const fn new() -> Self {
        Self {
            passthrough: PassthroughDispatcher::new(),
        }
    }
}

impl SyscallDispatcher for E9patchDispatcher {
    fn dispatch(&self, event: &mut SyscallEvent) {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // e9patch's fast path is the AOT trampoline, which never enters this
        // handler. Anything that *does* trap here is an un-rewritten fallback
        // site, so defer entirely to the shared, reviewed-once policy that
        // LiteInst also uses. This keeps the SIGSYS path identical across the
        // two ld-preload backends; only patch timing and trampoline placement
        // differ.
        self.passthrough.dispatch(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_is_a_syscall_dispatcher() {
        // Compile-time proof that e9patch plugs into the shared seam exactly
        // like LiteInst does.
        fn assert_dispatcher<T: SyscallDispatcher>(_: &T) {}
        let dispatcher = E9patchDispatcher::new();
        assert_dispatcher(&dispatcher);
    }

    #[test]
    fn dispatcher_is_constructible_in_const_context() {
        static _DISPATCHER: E9patchDispatcher = E9patchDispatcher::new();
    }
}
