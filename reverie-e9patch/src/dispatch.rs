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
use reverie_preload::fork::ForkHook;

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

/// Distinct un-rewritten syscall *sites* (instruction addresses) tracked
/// individually by the per-site fallback counters.
///
/// e9patch's residual fallback surface is small by construction — the dynamic
/// loader/startup code, the vDSO, and any site `e9tool` could not rewrite ahead
/// of time — so a bounded open-addressing table covers it without allocation.
/// Sites beyond this bound are still reflected in [`fallback_dispatch_count`] and
/// tallied in [`fallback_site_overflow`], never silently dropped.
const TRACKED_SITES: usize = 256;

/// A bounded, async-signal-safe open-addressing table mapping an un-rewritten
/// syscall *site* (instruction address) to how many times it reached the shared
/// fallback dispatcher.
///
/// Fixed capacity `N`, no allocation, no locks: [`record`](Self::record) is a
/// bounded linear probe using only relaxed atomics plus one `compare_exchange`
/// to claim an empty slot, so it is safe to call from inside the `SIGSYS`
/// handler. Slots are never freed, so a placed site's probe chain never regains
/// an empty slot — which is exactly what lets [`count`](Self::count) stop at the
/// first empty slot. A service that cannot claim a slot is tallied in `overflow`
/// rather than dropped, so per-site data can be honestly reported as incomplete
/// without ever losing the exact total.
struct SiteTable<const N: usize> {
    /// Instruction address occupying each slot (`0` == empty).
    addr: [AtomicU64; N],
    /// Fallback-service count for the site in the matching [`Self::addr`] slot.
    count: [AtomicU64; N],
    /// Services that could not be attributed to a slot (table full).
    overflow: AtomicU64,
}

impl<const N: usize> SiteTable<N> {
    const fn new() -> Self {
        Self {
            addr: [const { AtomicU64::new(0) }; N],
            count: [const { AtomicU64::new(0) }; N],
            overflow: AtomicU64::new(0),
        }
    }

    /// Multiplicative (Fibonacci) hash. Instruction addresses vary in their low
    /// bits per site, so spreading the high bits of the product avoids clustering
    /// adjacent syscall instructions into one probe chain.
    fn hash(address: u64) -> usize {
        const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
        (address.wrapping_mul(GOLDEN) >> 40) as usize % N
    }

    /// Record one fallback service for the site at `address`.
    fn record(&self, address: u64) {
        // Address 0 is never a mapped executable site and doubles as the
        // empty-slot sentinel, so route it to overflow instead of corrupting the
        // sentinel. In practice a trapping syscall instruction is never at 0.
        if address == 0 {
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let start = Self::hash(address);
        for step in 0..N {
            let index = (start + step) % N;
            let current = self.addr[index].load(Ordering::Relaxed);
            if current == address {
                self.count[index].fetch_add(1, Ordering::Relaxed);
                return;
            }
            if current == 0 {
                match self.addr[index].compare_exchange(
                    0,
                    address,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    // Claimed the empty slot for this address.
                    Ok(_) => {
                        self.count[index].fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Lost the race but the winner took it for *our* address.
                    Err(winner) if winner == address => {
                        self.count[index].fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Lost to a different address; keep probing.
                    Err(_) => {}
                }
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
    }

    /// Fallback-service count recorded for the site at `address`.
    ///
    /// Returns `0` for `address == 0`, a never-seen site, or a site displaced by
    /// overflow. Correct despite concurrent recording: slots only transition
    /// empty→occupied, so stopping at the first empty slot never skips a site
    /// that was already placed earlier in the same probe chain.
    fn count(&self, address: u64) -> u64 {
        if address == 0 {
            return 0;
        }
        let start = Self::hash(address);
        for step in 0..N {
            let index = (start + step) % N;
            let current = self.addr[index].load(Ordering::Relaxed);
            if current == address {
                return self.count[index].load(Ordering::Relaxed);
            }
            if current == 0 {
                return 0;
            }
        }
        0
    }

    /// Services that could not be attributed to a per-site slot.
    fn overflow_count(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }

    /// Clear every slot and the overflow tally back to the empty state.
    ///
    /// Async-signal-safe: only relaxed atomic stores, no allocation or locks, so
    /// it is safe to call from the fork child inside the `SIGSYS` handler. This
    /// re-empties the table (address `0` is the empty sentinel), so a child that
    /// COW-inherited the parent's occupied slots starts attribution from zero.
    fn reset(&self) {
        for slot in &self.addr {
            slot.store(0, Ordering::Relaxed);
        }
        for slot in &self.count {
            slot.store(0, Ordering::Relaxed);
        }
        self.overflow.store(0, Ordering::Relaxed);
    }
}

// TODO-HUMAN-REVIEW(PR-253): Review public per-site fallback-surface observability.
/// Per-site fallback counts, keyed by the un-rewritten site's instruction
/// address (the address-keyed analog of LiteInst's per-site trap counter).
static FALLBACK_SITES: SiteTable<TRACKED_SITES> = SiteTable::new();

/// Record that the shared fallback dispatcher serviced a syscall issued at
/// `address` (an un-rewritten site's instruction pointer).
///
/// Async-signal-safe (see [`SiteTable`]), so it is safe to call from inside the
/// `SIGSYS` handler alongside [`record_fallback_dispatch`].
pub(crate) fn record_fallback_site(address: u64) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_SITES.record(address);
}

/// Number of times the fallback dispatcher serviced a syscall issued at the
/// un-rewritten site `address`.
///
/// This is the address-keyed analog of LiteInst's per-site trap count: it
/// localizes the residual fallback surface to the exact instruction addresses
/// `e9tool` could not rewrite ahead of time, complementing the by-syscall-number
/// view from [`fallback_syscall_count`].
pub(crate) fn fallback_site_count(address: u64) -> u64 {
    FALLBACK_SITES.count(address)
}

/// Fallback services that could not be attributed to a per-site slot because the
/// bounded [`SiteTable`] was full.
///
/// Nonzero means per-site localization is incomplete; the totals from
/// [`fallback_dispatch_count`] and [`fallback_syscall_count`] stay exact.
pub(crate) fn fallback_site_overflow() -> u64 {
    FALLBACK_SITES.overflow_count()
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

// TODO-HUMAN-REVIEW(PR-256): Review the fork-child per-process observability reset.
/// Reset every fallback-surface counter to zero for the current process.
///
/// The fallback counters ([`FALLBACK_TOTAL`], [`FALLBACK_BY_NUMBER`],
/// [`FALLBACK_SITES`]) are process-global statics. A `fork`/`clone` child
/// copy-on-write inherits the parent's accumulated values, so without a reset the
/// child would report the parent's residual surface as its own. This is the
/// per-process runtime state that the shared [`ForkHook`] seam
/// ([`reverie_preload::fork`]) exists to re-establish in the child — the same
/// mechanism LiteInst uses (there, to open a fresh coordinator connection). Here
/// the per-process state is observability, so the child's fallback attribution
/// starts clean.
///
/// Signature is `fn()` so it can be wrapped in a [`ForkHook`]. Async-signal-safe
/// (only relaxed atomic stores), so it is safe to run in the child from inside
/// the `SIGSYS` handler.
pub(crate) fn reset_fallback_observability() {
    // AUTONOMOUS-BOT-IMPLEMENTED
    FALLBACK_TOTAL.store(0, Ordering::Relaxed);
    for slot in &FALLBACK_BY_NUMBER {
        slot.store(0, Ordering::Relaxed);
    }
    FALLBACK_SITES.reset();
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

    // TODO-HUMAN-REVIEW(PR-256): Review the fork-following observability reset wiring.
    /// The production dispatcher: like [`new`](Self::new), but additionally arms
    /// the shared [`ForkHook`] so each `fork`/`clone` child resets its
    /// per-process fallback observability (see `reset_fallback_observability`).
    ///
    /// This mirrors the shared API shape exactly — [`PassthroughDispatcher::new`]
    /// (hook-less) plus [`PassthroughDispatcher::with_fork_hook`] (opt-in) — so
    /// e9patch re-uses the *same* fork-following seam LiteInst does rather than
    /// reimplementing per-process reset. Only the per-process state each backend
    /// re-establishes differs (LiteInst: a fresh coordinator connection; e9patch:
    /// the fallback counters), which is a consequence of what each keeps, not a
    /// second mechanism.
    pub fn with_fork_reset() -> Self {
        // AUTONOMOUS-BOT-IMPLEMENTED
        Self {
            passthrough: PassthroughDispatcher::new()
                .with_fork_hook(ForkHook::new(reset_fallback_observability)),
        }
    }
}

impl SyscallDispatcher for E9patchDispatcher {
    fn dispatch(&self, event: &mut SyscallEvent) {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // e9patch's fast path is the AOT trampoline, which never enters this
        // handler. Anything that *does* trap here is an un-rewritten fallback
        // site, so record it for observability — both by syscall number and by
        // the un-rewritten site's instruction address — then defer entirely to
        // the shared, reviewed-once policy that LiteInst also uses. Counting does
        // not change the forwarding decision, so the SIGSYS path stays identical
        // across the two ld-preload backends; only patch timing and trampoline
        // placement differ.
        record_fallback_dispatch(event.number());
        record_fallback_site(event.instruction_pointer());
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
    fn recording_a_fallback_site_bumps_only_that_sites_count() {
        // A private table keeps this assertion exact regardless of the
        // process-global counters other tests touch.
        let table = SiteTable::<8>::new();
        let site: u64 = 0x4000_1234;
        assert_eq!(table.count(site), 0);
        for expected in 1..=5 {
            table.record(site);
            assert_eq!(table.count(site), expected);
        }
        // A different, never-recorded site stays at zero.
        assert_eq!(table.count(0x4000_9999), 0);
        assert_eq!(table.overflow_count(), 0);
    }

    #[test]
    fn distinct_sites_are_counted_independently() {
        let table = SiteTable::<8>::new();
        let a: u64 = 0x1000;
        let b: u64 = 0x2000;
        table.record(a);
        table.record(b);
        table.record(b);
        assert_eq!(table.count(a), 1);
        assert_eq!(table.count(b), 2);
    }

    #[test]
    fn zero_address_is_routed_to_overflow_not_the_table() {
        // Address 0 doubles as the empty-slot sentinel, so it must never claim a
        // real slot; it is counted only in overflow.
        let table = SiteTable::<4>::new();
        table.record(0);
        assert_eq!(table.count(0), 0);
        assert_eq!(table.overflow_count(), 1);
    }

    #[test]
    fn full_table_overflows_without_dropping_known_sites() {
        // Fill every slot with a distinct site, then prove a brand-new site
        // overflows while an already-tracked site still increments.
        let table = SiteTable::<4>::new();
        let sites: [u64; 4] = [0x1000, 0x2000, 0x3000, 0x4000];
        for site in sites {
            table.record(site);
        }
        for site in sites {
            assert_eq!(table.count(site), 1);
        }
        // A fifth distinct site cannot claim a slot: counted in overflow, not the
        // table, and its per-site count reads back as zero.
        let overflow_site: u64 = 0x5000;
        table.record(overflow_site);
        assert_eq!(table.count(overflow_site), 0);
        assert_eq!(table.overflow_count(), 1);
        // An already-tracked site still increments even with the table full.
        table.record(sites[0]);
        assert_eq!(table.count(sites[0]), 2);
        assert_eq!(table.overflow_count(), 1);
    }

    #[test]
    fn global_site_recording_bumps_the_matching_site() {
        // Exercise the process-global path the SIGSYS handler uses, with an
        // address unique to this test so the assertion is exact under concurrency.
        let site: u64 = 0x7f00_dead_0001;
        let before = fallback_site_count(site);
        record_fallback_site(site);
        assert_eq!(fallback_site_count(site), before + 1);
        assert_eq!(fallback_site_count(0), 0);
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

    #[test]
    fn site_table_reset_clears_slots_and_overflow() {
        // Private table so the assertion is exact regardless of the
        // process-global counters other tests touch.
        let table = SiteTable::<4>::new();
        for site in [0x1000_u64, 0x2000, 0x3000, 0x4000] {
            table.record(site);
        }
        table.record(0x5000); // overflows the full table
        assert_eq!(table.count(0x1000), 1);
        assert_eq!(table.overflow_count(), 1);

        table.reset();

        // Every slot is empty again and the table can be re-populated cleanly.
        for site in [0x1000_u64, 0x2000, 0x3000, 0x4000, 0x5000] {
            assert_eq!(table.count(site), 0);
        }
        assert_eq!(table.overflow_count(), 0);
        table.record(0x5000);
        assert_eq!(table.count(0x5000), 1);
    }

    #[test]
    fn resetting_observability_zeroes_the_process_global_counters() {
        // Serial (`--test-threads=1`), so resetting the process-global counters
        // does not race other tests. Record on all three counter families, then
        // prove the shared fork-child reset clears them.
        let number: i64 = 402;
        let site: u64 = 0x7f00_dead_0002;
        record_fallback_dispatch(number);
        record_fallback_site(site);
        assert!(fallback_dispatch_count() > 0);
        assert!(fallback_syscall_count(number) > 0);
        assert!(fallback_site_count(site) > 0);

        reset_fallback_observability();

        assert_eq!(fallback_dispatch_count(), 0);
        assert_eq!(fallback_syscall_count(number), 0);
        assert_eq!(fallback_site_count(site), 0);
        assert_eq!(fallback_site_overflow(), 0);
    }

    #[test]
    fn fork_reset_dispatcher_is_a_syscall_dispatcher() {
        // The production constructor still yields the shared dispatcher seam;
        // it differs from `new` only by arming the shared ForkHook.
        fn assert_dispatcher<T: SyscallDispatcher>(_: &T) {}
        let dispatcher = E9patchDispatcher::with_fork_reset();
        assert_dispatcher(&dispatcher);
    }
}
