/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Fork-following.
//!
//! The seccomp filter is inherited by `fork`/`clone` children *atomically in
//! the kernel* (proven by `research-ldpreload-derisking`: the child returns
//! from the trapped syscall already filtered, with the handler and mappings
//! copied). So, unlike ptrace, there is **no attach round-trip and no
//! filter-install race** — the child's very first syscall is already covered.
//!
//! What a child still needs is fresh *per-process* runtime state: most
//! importantly a private connection to the coordinator, because a socket fd
//! shared with the parent must not be used by two processes. [`ForkHook`] is the
//! callback the [`PassthroughDispatcher`](crate::dispatch::PassthroughDispatcher)
//! invokes in the child immediately after a fork-like syscall returns `0`.
//!
//! # Async-signal safety
//!
//! The hook runs inside the SIGSYS handler in the just-created child. It must be
//! async-signal-safe: reconnect using raw syscalls only, do not allocate on a
//! shared allocator, and do not touch locks the vanished parent threads may have
//! held.

/// A child-side callback run once per fork-like syscall, in the child.
#[derive(Clone, Copy)]
pub struct ForkHook {
    callback: fn(),
}

impl core::fmt::Debug for ForkHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ForkHook(..)")
    }
}

impl ForkHook {
    /// Wrap a plain function pointer. Must be async-signal-safe (see module
    /// docs).
    pub const fn new(callback: fn()) -> Self {
        Self { callback }
    }

    /// Invoke the hook (called by the dispatcher in the child).
    pub fn run_in_child(&self) {
        (self.callback)();
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;

    use super::*;

    static CALLS: AtomicUsize = AtomicUsize::new(0);

    fn bump() {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn hook_runs_its_callback() {
        CALLS.store(0, Ordering::SeqCst);
        let hook = ForkHook::new(bump);
        hook.run_in_child();
        hook.run_in_child();
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    }
}
