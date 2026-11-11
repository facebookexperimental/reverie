/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Per-thread Tool state with lease (checkout/checkin) discipline for the
//! ordinary in-guest dispatch path.
//!
//! The registry lock is held only while moving one thread's state into or
//! out of a lease. No registry guard reaches Tool code, coordinator RPC,
//! or any blocking call: a dispatch owns its thread's state outright for
//! the whole dispatch, so dispatches for *different* guest threads run
//! concurrently. This mirrors the lease discipline of
//! [`super::native_state::NativeThreads`] without its native-admission
//! identity machinery; the two registries stay separate because native
//! callbacks carry admission authority ordinary dispatch must not inherit.

use std::collections::HashMap;

use crate::sync::SpinMutex;

enum Slot<S> {
    Available(S),
    /// Checked out by the dispatch currently running on that thread.
    Leased,
}

/// Registry of per-thread state, keyed by guest tid (raw).
pub(super) struct ThreadStates<S> {
    slots: SpinMutex<HashMap<i32, Slot<S>>>,
}

/// One thread's state, checked out for a single dispatch. Dropping the
/// lease returns the state; [`Lease::retire`] consumes it instead.
pub(super) struct Lease<'a, S> {
    states: &'a ThreadStates<S>,
    tid: i32,
    state: Option<S>,
    is_new: bool,
}

impl<S> ThreadStates<S> {
    pub(super) fn new() -> Self {
        Self {
            slots: SpinMutex::new(HashMap::new()),
        }
    }

    #[cfg(any(
        test,
        feature = "rcb-clock",
        feature = "exec-native-injection",
        feature = "exec-private-successor",
        all(feature = "exec-private-init", feature = "coordinator-rpc")
    ))]
    pub(super) fn is_empty(&self) -> bool {
        self.slots.lock().is_empty()
    }

    // Only the initial-image lifecycle (and tests) probe membership;
    // ordinary dispatch always goes through checkout.
    #[cfg(any(test, feature = "exec-private-init"))]
    pub(super) fn contains(&self, tid: i32) -> bool {
        self.slots.lock().contains_key(&tid)
    }

    /// Whether any state is currently checked out.
    #[cfg(test)]
    pub(super) fn any_leased(&self) -> bool {
        self.slots
            .lock()
            .values()
            .any(|slot| matches!(slot, Slot::Leased))
    }

    /// Read `tid`'s available state under a brief lock. A leased slot
    /// reads as `None` (its state is owned by the running dispatch).
    #[cfg(test)]
    pub(super) fn with_state<R>(&self, tid: i32, f: impl FnOnce(Option<&S>) -> R) -> R {
        let slots = self.slots.lock();
        f(match slots.get(&tid) {
            Some(Slot::Available(state)) => Some(state),
            _ => None,
        })
    }

    /// Check out `tid`'s state, creating it with `init` on first sight.
    /// Returns `None` when the state is already leased (a re-entrant
    /// dispatch for the same thread, which the caller treats as the
    /// invariant break it is today).
    ///
    /// `init` runs Tool code (`init_thread_state`), so it runs *outside*
    /// the registry lock: the slot is reserved as `Leased` first, the lock
    /// is dropped, and only then is the state created. The brief-lock
    /// claim for this registry therefore covers creation too.
    pub(super) fn checkout(&self, tid: i32, init: impl FnOnce() -> S) -> Option<Lease<'_, S>> {
        let mut slots = self.slots.lock();
        match slots.get_mut(&tid) {
            None => {
                slots.insert(tid, Slot::Leased);
                drop(slots);
                Some(Lease {
                    states: self,
                    tid,
                    state: Some(init()),
                    is_new: true,
                })
            }
            Some(Slot::Leased) => None,
            Some(slot) => {
                let Slot::Available(state) = core::mem::replace(slot, Slot::Leased) else {
                    unreachable!("slot phase checked above")
                };
                Some(Lease {
                    states: self,
                    tid,
                    state: Some(state),
                    is_new: false,
                })
            }
        }
    }

    /// Check out `tid`'s existing state. `None` when absent or leased.
    pub(super) fn checkout_existing(&self, tid: i32) -> Option<Lease<'_, S>> {
        let mut slots = self.slots.lock();
        match slots.get_mut(&tid) {
            Some(slot @ Slot::Available(_)) => {
                let Slot::Available(state) = core::mem::replace(slot, Slot::Leased) else {
                    unreachable!("slot phase checked above")
                };
                Some(Lease {
                    states: self,
                    tid,
                    state: Some(state),
                    is_new: false,
                })
            }
            _ => None,
        }
    }

    /// Publish `state` for `tid` without leasing it (initial-image
    /// installation). Refuses, returning the state back, when a slot for
    /// `tid` already exists in any phase.
    pub(super) fn try_publish(&self, tid: i32, state: S) -> Result<(), S> {
        let mut slots = self.slots.lock();
        if slots.contains_key(&tid) {
            return Err(state);
        }
        slots.insert(tid, Slot::Available(state));
        Ok(())
    }

    /// Publish `state` for `tid`, replacing any available slot. The
    /// caller has already established that no lease is outstanding (the
    /// initial-image flows check emptiness first); a leased slot keeps
    /// its state and the new one is returned.
    // Only the successor restore flow publishes over an available slot.
    #[cfg(feature = "exec-private-successor")]
    pub(super) fn publish(&self, tid: i32, state: S) -> Result<(), S> {
        let mut slots = self.slots.lock();
        match slots.get_mut(&tid) {
            Some(Slot::Leased) => Err(state),
            Some(slot) => {
                *slot = Slot::Available(state);
                Ok(())
            }
            None => {
                slots.insert(tid, Slot::Available(state));
                Ok(())
            }
        }
    }

    /// Remove `tid`'s available state, if any. A leased slot is untouched
    /// and yields `None`.
    // Only the initial-image lifecycle (and tests) remove available
    // state; ordinary thread exit goes through `Lease::retire`.
    #[cfg(any(test, feature = "exec-private-init"))]
    pub(super) fn remove(&self, tid: i32) -> Option<S> {
        let mut slots = self.slots.lock();
        match slots.get(&tid) {
            Some(Slot::Available(_)) => match slots.remove(&tid) {
                Some(Slot::Available(state)) => Some(state),
                _ => unreachable!("slot phase checked above"),
            },
            _ => None,
        }
    }

    /// Force the registry lock open in a fork child whose copy of it
    /// may have been made mid-hold by a sibling thread that does not
    /// exist here. Must precede the first registry use in the child
    /// (the parent lease's retire, `reset_to`).
    ///
    /// # Safety
    ///
    /// Same contract as [`SpinMutex::force_unlock`]: no live holder
    /// can exist in this process and no stale guard will drop. The
    /// host calls this from its fork-child reinit, before the child
    /// creates any thread, on the surviving forking thread, which
    /// holds no registry guard at that point.
    pub(super) unsafe fn force_unlock_slots(&self) {
        // SAFETY: the caller establishes the force-unlock contract.
        unsafe { self.slots.force_unlock() }
    }

    /// Fork-child reset: this process copy starts over with exactly the
    /// child's state. Any slot leased in the parent copy is abandoned
    /// with the parent's address space; the child's own lease (parent's,
    /// inherited by fork) must be abandoned by the caller via
    /// [`Lease::abandon`], never checked in here.
    ///
    /// The copied map is leak-replaced, never cleared or dropped: a
    /// sibling dispatch may have been mid-insert (mid-rehash) at the
    /// fork instant, so the copied buckets cannot be traversed, and a
    /// sibling's state value cannot be dropped mid-mutation either.
    /// Forgetting the old map leaks its buckets and the dead threads'
    /// states in the child only; the parent's originals are untouched.
    pub(super) fn reset_to(&self, tid: i32, state: S) {
        let mut slots = self.slots.lock();
        // Reuse the copied map's hasher (fixed at construction):
        // a fresh RandomState would issue getrandom through libc,
        // outside the trusted gate, in the fork child.
        let hasher = slots.hasher().clone();
        let copied = core::mem::replace(&mut *slots, HashMap::with_hasher(hasher));
        core::mem::forget(copied);
        slots.insert(tid, Slot::Available(state));
    }

    /// Test stand-in for a sibling thread that held the registry lock
    /// at the fork instant and does not exist in the child.
    #[cfg(test)]
    pub(super) fn forget_lock_guard_for_test(&self) {
        core::mem::forget(self.slots.lock());
    }
}

impl<'a, S> Lease<'a, S> {
    pub(super) fn is_new(&self) -> bool {
        self.is_new
    }

    pub(super) fn state_mut(&mut self) -> &mut S {
        self.state.as_mut().expect("lease state taken twice")
    }

    /// Consume the lease, removing the slot and returning the state
    /// (thread exit).
    pub(super) fn retire(mut self) -> S {
        let state = self.state.take().expect("lease state taken twice");
        self.states.slots.lock().remove(&self.tid);
        state
    }

    /// Take the state out without touching the registry map (fork
    /// child: the copied map must not be traversed before
    /// [`ThreadStates::reset_to`] leak-replaces it, and this lease's
    /// slot belongs to the parent's copy in any case). With the state
    /// taken, the lease's own drop is a no-op.
    pub(super) fn abandon(mut self) -> S {
        self.state.take().expect("lease state taken twice")
    }
}

impl<S> Drop for Lease<'_, S> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let mut slots = self.states.slots.lock();
            // The slot is `Leased` by construction; a fork-child reset may
            // have replaced the whole map, in which case reinserting would
            // resurrect a parent thread in the child. `forget` exists for
            // that path and is used there; if the slot is gone or no
            // longer leased, dropping the state is the only safe answer.
            match slots.get_mut(&self.tid) {
                Some(slot @ Slot::Leased) => *slot = Slot::Available(state),
                _ => drop(state),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;

    #[test]
    fn checkout_creates_once_then_reuses() {
        let states = ThreadStates::<u32>::new();
        {
            let mut lease = states.checkout(7, || 40).unwrap();
            assert!(lease.is_new());
            *lease.state_mut() += 2;
        }
        let lease = states.checkout(7, || 0).unwrap();
        assert!(!lease.is_new());
        assert_eq!(*lease.state.as_ref().unwrap(), 42);
    }

    #[test]
    fn second_checkout_of_live_lease_is_refused() {
        let states = ThreadStates::<u32>::new();
        let _lease = states.checkout(7, || 1).unwrap();
        assert!(states.checkout(7, || 2).is_none());
        // A different tid is unaffected.
        assert!(states.checkout(8, || 3).is_some());
    }

    #[test]
    fn retire_removes_and_retire_of_leased_remove_is_none() {
        let states = ThreadStates::<u32>::new();
        let lease = states.checkout(7, || 5).unwrap();
        assert_eq!(states.remove(7), None);
        assert_eq!(lease.retire(), 5);
        assert!(states.is_empty());
    }

    #[test]
    fn reset_to_replaces_everything() {
        let states = ThreadStates::<u32>::new();
        drop(states.checkout(1, || 10).unwrap());
        drop(states.checkout(2, || 20).unwrap());
        states.reset_to(3, 30);
        assert_eq!(states.remove(3), Some(30));
        assert!(states.is_empty());
    }

    #[test]
    fn force_unlock_slots_recovers_a_copied_locked_registry() {
        // A sibling thread was inside the registry at the fork instant:
        // the child's copy of the lock is held by a thread that does not
        // exist here, and a slot it had leased stays Leased. Leaking the
        // guard stands in for that dead holder.
        let states = ThreadStates::<u32>::new();
        let mut leased = states.checkout(7, || 70).unwrap();
        *leased.state_mut() += 1;
        core::mem::forget(leased);
        let copied = states.slots.lock();
        core::mem::forget(copied);
        assert!(states.slots.try_lock().is_none());
        // SAFETY: the leaked guards above stand in for dead holders;
        // nothing will ever drop them (the fork-child contract).
        unsafe { states.force_unlock_slots() };
        // The dead sibling's leased slot is forgotten with the
        // copied map by the reset (leaked, never dropped), and the
        // child's own tid is reusable at once.
        states.reset_to(3, 30);
        let mut own = states.checkout_existing(3).expect("reset state present");
        assert_eq!(*own.state_mut(), 30);
        drop(own);
        let mut reused = states.checkout(7, || 71).expect("dead tid reusable");
        assert_eq!(*reused.state_mut(), 71);
    }

    #[test]
    fn concurrent_checkouts_of_distinct_tids_do_not_block() {
        let states = Arc::new(ThreadStates::<u32>::new());
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [11, 22]
            .into_iter()
            .map(|tid| {
                let states = Arc::clone(&states);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut lease = states.checkout(tid, || tid as u32).unwrap();
                    *lease.state_mut() += 1;
                    // Both leases are live at once; a process-wide lock
                    // held across the dispatch would deadlock here.
                    barrier.wait();
                    *lease.state_mut()
                })
            })
            .collect();
        let results: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results, vec![12, 23]);
    }
}
