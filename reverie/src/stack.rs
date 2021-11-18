/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A simple arena allocator using tracee's stack
//!
//! Allocation is done on stack, all allocated memory will (1) become usable after
//! `commit`, and (2) be released when `StackGuard' is subsequently dropped.

use reverie_syscalls::{Addr, AddrMut, Errno};

/// A low-level stack which stores untyped (but Sized) values
pub trait Stack {
    /// A guard which should be kept alive while accessing the memory allocated with this interface.
    type StackGuard: Drop + Send;

    /// Get the current stack size allocated by `push` and `reserve` operations (initially zero).
    fn size(&self) -> usize;

    /// Get stack capacity, i.e. the maximum that can be allocated.
    fn capacity(&self) -> usize;

    /// Allocate from stack with given `size', return a `Addr`
    /// that points to the stack, panics if no space is available.
    /// Copies the raw bits of the provided value into the allocated space.
    ///
    /// This returns results as pointers into guest mememory. *However*, the data is not
    /// guaranteed to be written through to the guest until flushed by a `commit`.  Thus
    /// the returned `Addr` is implicitly invalid until the `commit`.
    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T>;

    /// Allocates like `push` but fills the allocated area with zeroes instead.
    /// Like `push`, the results are not available until the next `commit`.
    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T>;

    /// Commit all allocations, writing data through to the guest.  This allows certain
    /// optimizations, and forces the `Stack' value to released, returning a `StackGuard`
    /// instead.
    fn commit(self) -> Result<Self::StackGuard, Errno>;
}
