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

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use reverie_preload::dispatch::PassthroughDispatcher;
use reverie_preload::dispatch::SyscallDispatcher;
use reverie_preload::dispatch::SyscallEvent;

/// Distinct syscall numbers broken out individually by the fallback counters.
///
/// x86-64 syscall numbers currently top out well under this bound; a number at
/// or above it (or negative) is still counted in the process-wide total but is
/// not tracked per-number. Sized to cover the whole current table with headroom.
const TRACKED_SYSCALLS: usize = 512;

// TODO-HUMAN-REVIEW(PR-246): Review public fallback-surface observability counters.
/// Total number of syscalls serviced by the shared `SIGSYS` fallback dispatcher.
static FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);

// TODO-HUMAN-REVIEW(PR-246): Review public fallback-surface observability counters.
/// Per-syscall-number fallback service counts, indexed by syscall number.
static FALLBACK_BY_NUMBER: [AtomicU64; TRACKED_SYSCALLS] =
    [const { AtomicU64::new(0) }; TRACKED_SYSCALLS];

/// Record that the shared fallback dispatcher serviced one syscall.
///
/// Anything reaching the fallback dispatcher is, by construction, a residual
/// un-rewritten site (see [`E9patchDispatcher`]), so this counts the size of
/// e9patch's residual fallback surface. It is the e9patch analog of LiteInst's
/// per-site `trap`/`hook` counters — but keyed by syscall number rather than
/// site address, because e9patch has no runtime sites to key on.
///
/// Async-signal-safe: only relaxed atomic increments, so it is safe to call
/// from inside the `SIGSYS` handler.
pub(crate) fn record_fallback_dispatch(number: i64) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
    if let Ok(index) = usize::try_from(number)
        && index < TRACKED_SYSCALLS
    {
        FALLBACK_BY_NUMBER[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// Total syscalls e9patch has serviced through the shared fallback dispatcher.
///
/// A large value relative to the guest's total syscall count indicates a large
/// residual (un-rewritten) surface, i.e. e9tool's ahead-of-time coverage missed
/// many sites; a small value confirms the AOT fast path handles the bulk.
pub(crate) fn fallback_dispatch_count() -> u64 {
    FALLBACK_TOTAL.load(Ordering::Relaxed)
}

/// Number of times syscall `number` reached the shared fallback dispatcher.
///
/// Returns `0` for a negative number or one at or above [`TRACKED_SYSCALLS`],
/// which are only ever reflected in [`fallback_dispatch_count`].
pub(crate) fn fallback_syscall_count(number: i64) -> u64 {
    match usize::try_from(number) {
        Ok(index) if index < TRACKED_SYSCALLS => FALLBACK_BY_NUMBER[index].load(Ordering::Relaxed),
        _ => 0,
    }
}

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
        // site, so record it for observability, then defer entirely to the
        // shared, reviewed-once policy that LiteInst also uses. Counting does
        // not change the forwarding decision, so the SIGSYS path stays identical
        // across the two ld-preload backends; only patch timing and trampoline
        // placement differ.
        record_fallback_dispatch(event.number());
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

    #[test]
    fn recording_a_fallback_bumps_total_and_the_matching_syscall() {
        // A syscall number unique to this test, so the per-number assertion is
        // exact even if the process-global counters are touched concurrently.
        let number: i64 = 401;
        let per_before = fallback_syscall_count(number);
        let total_before = fallback_dispatch_count();

        record_fallback_dispatch(number);

        assert_eq!(fallback_syscall_count(number), per_before + 1);
        assert!(
            fallback_dispatch_count() > total_before,
            "total must advance by at least this recording"
        );
    }

    #[test]
    fn out_of_range_syscall_numbers_count_in_the_total_only() {
        // Above the tracked bound: total advances, per-number stays zero.
        let huge = i64::from(i32::MAX);
        let total_before = fallback_dispatch_count();
        record_fallback_dispatch(huge);
        assert_eq!(fallback_syscall_count(huge), 0);
        assert!(fallback_dispatch_count() > total_before);

        // Negative numbers are never used to index the per-number table.
        let total_before = fallback_dispatch_count();
        record_fallback_dispatch(-1);
        assert_eq!(fallback_syscall_count(-1), 0);
        assert!(fallback_dispatch_count() > total_before);
    }
}
