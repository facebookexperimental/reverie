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
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

/// An allocation-free spinlock usable from async-signal context.
pub struct SpinMutex<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> SpinMutex<T> {
    /// Create a new `SpinMutex`. `const` so it can initialize a `static`.
    pub const fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, spinning until it is free.
    pub fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard { mutex: self }
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
        self.mutex.held.store(false, Ordering::Release);
    }
}
