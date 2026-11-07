/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Async-signal-safe synchronization primitives for the in-guest tool hosts.
//!
//! The e9patch and liteinst in-guest hosts run their coordinator-RPC and
//! per-thread state behind a lock that must be safe to acquire from the
//! `SIGSYS` handler, where the allocator and `std::sync::Mutex` (which may
//! park via a futex syscall) are both unusable. [`SpinMutex`] is an
//! allocation-free spinlock with a `const` constructor so it can back a
//! `static`. It was previously copied byte-for-byte into each backend's
//! `rpc.rs`; it now lives here so it is written and reviewed once.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

fn current_owner() -> usize {
    // pthread_self is async-signal-safe and identifies the live thread
    // without issuing a syscall that could re-enter the SIGSYS handler.
    // The low bit keeps the owner word nonzero (pthread_t is an aligned
    // control-block address on glibc and musl), so 0 unambiguously means
    // free even if a thread pointer were ever null. Each thread must run
    // on its own libc thread pointer, as DynamoRIO's private control block
    // and the private runtime's genuine-private-FS contract provide.
    unsafe { libc::pthread_self() as usize | 1 }
}

/// An allocation-free spinlock usable from async-signal context.
pub struct SpinMutex<T> {
    owner: AtomicUsize,
    value: UnsafeCell<T>,
}

impl<T> SpinMutex<T> {
    /// Create a new `SpinMutex`. `const` so it can initialize a `static`.
    pub const fn new(value: T) -> Self {
        Self {
            owner: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, spinning until it is free.
    pub fn lock(&self) -> SpinGuard<'_, T> {
        let owner = current_owner();
        while self
            .owner
            .compare_exchange_weak(0, owner, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard { mutex: self }
    }

    /// Acquire the lock only if it is free now.
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        self.owner
            .compare_exchange(0, current_owner(), Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
            // Lazily: a guard built for a failed attempt would release the
            // lock its real owner still holds when it is dropped.
            .then(|| SpinGuard { mutex: self })
    }

    /// Spin on contention from another thread, but refuse same-thread
    /// re-entry. Cross-thread critical sections are short and contain no
    /// Tool code or I/O, while waiting on our own lock would deadlock if a
    /// signal interrupted the thread already holding it.
    pub fn lock_unless_reentered(&self) -> Option<SpinGuard<'_, T>> {
        let owner = current_owner();
        loop {
            match self
                .owner
                .compare_exchange_weak(0, owner, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(SpinGuard { mutex: self }),
                Err(current) if current == owner => return None,
                Err(_) => core::hint::spin_loop(),
            }
        }
    }
}

// SAFETY: access to the inner value is serialized by the spinlock.
unsafe impl<T: Send> Sync for SpinMutex<T> {}

/// RAII guard that releases the [`SpinMutex`] on drop.
pub struct SpinGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> core::ops::Deref for SpinGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard holds the spin lock for its full lifetime.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> core::ops::DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the guard holds the spin lock exclusively.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.owner.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_lock_fails_only_while_the_lock_is_held() {
        let mutex = SpinMutex::new(1);
        let held = mutex.try_lock().expect("a free lock is acquired");
        // Every failed attempt must leave the lock held: a failed attempt
        // that released it would let the next one in.
        for attempt in 0..3 {
            assert!(
                mutex.try_lock().is_none(),
                "a held lock was acquired twice (attempt {attempt})"
            );
        }
        assert_ne!(
            mutex.owner.load(Ordering::Relaxed),
            0,
            "a failed attempt released the lock"
        );
        drop(held);
        let mut again = mutex.try_lock().expect("a released lock is acquired");
        *again += 1;
        drop(again);
        assert_eq!(*mutex.lock(), 2);
    }

    #[test]
    fn lock_unless_reentered_refuses_only_the_owning_thread() {
        // Same-thread refusal, with the outer hold taken through the same
        // method production uses. Run it on a detached thread reporting by
        // channel so a mutant that spins on re-entry fails by timeout
        // assertion instead of hanging this test process.
        static REENTRY_MUTEX: SpinMutex<u8> = SpinMutex::new(1);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _held = REENTRY_MUTEX.lock_unless_reentered().unwrap();
            tx.send(REENTRY_MUTEX.lock_unless_reentered().is_none())
                .unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            "same-thread re-entry through lock_unless_reentered was not refused"
        );

        // Two racing holders must exclude each other: the child must not
        // acquire while the outer lock_unless_reentered hold is live, and
        // must acquire once it is dropped.
        let mutex = SpinMutex::new(1);
        let held = mutex.lock_unless_reentered().unwrap();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let waited = std::thread::scope(|scope| {
            let child = scope.spawn(|| {
                let guard = mutex.lock_unless_reentered().unwrap();
                acquired_tx.send(()).unwrap();
                *guard
            });
            assert!(
                acquired_rx
                    .recv_timeout(std::time::Duration::from_millis(50))
                    .is_err(),
                "a second lock_unless_reentered holder acquired concurrently"
            );
            drop(held);
            acquired_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            child.join().unwrap()
        });
        assert_eq!(waited, 1);
    }
}
