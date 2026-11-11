/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Process creation for the lib tests, kept out of each other's pipes.
//!
//! The lib's tests run in parallel in one process. A test that spawns a
//! subprocess with piped output reads those pipes until end-of-file, and its
//! process holds the pipes' write ends from their creation until the spawn
//! returns. A raw `fork` (or `clone`, `clone3`) by another test inside that
//! window copies them into a child that never execs, so they are never
//! closed: the pipe then stays open for as long as that child lives, and the
//! spawning test waits for an end-of-file that comes only when it exits
//! (<https://github.com/rrnewton/reverie/issues/1452>).
//!
//! A spawn that std cannot hand to `posix_spawn` (one with a `pre_exec`
//! closure, for example) forks and then waits, before returning, until the
//! child's exec closes a close-on-exec socket. A raw child that copies that
//! socket blocks the spawn itself until the raw child exits.
//!
//! So every raw process creation in the test process holds [`SPAWN_FORK`]
//! exclusively for the creating call, and every spawn holds it shared. No
//! raw child can then be created while a spawn's pipes or socket are open
//! in this process. A child created under the exclusive hold drops its copy of the
//! guard as the call returns, so its own nested forks proceed normally.
//!
//! Only the lib's own unit tests (`cfg(test)`) use this; production code and
//! other crates are unchanged. The spawning tests, and the `libc::fork`
//! callers, are all `notifier` tests.

#[cfg(feature = "notifier")]
use std::io;
#[cfg(feature = "notifier")]
use std::process::Child;
#[cfg(feature = "notifier")]
use std::process::Command;
use std::sync::PoisonError;
use std::sync::RwLock;

/// Held shared by a spawn, exclusively by a raw process creation.
static SPAWN_FORK: RwLock<()> = RwLock::new(());

/// Runs `create`, a raw process creation (a `fork`, `clone` or `clone3`
/// call and nothing else), holding [`SPAWN_FORK`] exclusively. In the
/// child, the guard is dropped as this returns.
pub(crate) fn exclusive<T>(create: impl FnOnce() -> T) -> T {
    let _exclusive = SPAWN_FORK.write().unwrap_or_else(PoisonError::into_inner);
    create()
}

/// `nix::unistd::fork`, holding [`SPAWN_FORK`] exclusively.
///
/// # Safety
///
/// As for `nix::unistd::fork`.
pub(crate) unsafe fn fork() -> nix::Result<nix::unistd::ForkResult> {
    exclusive(|| unsafe { nix::unistd::fork() })
}

/// `libc::fork`, holding [`SPAWN_FORK`] exclusively.
///
/// # Safety
///
/// As for `libc::fork`.
#[cfg(feature = "notifier")]
pub(crate) unsafe fn libc_fork() -> libc::pid_t {
    exclusive(|| unsafe { libc::fork() })
}

/// `command.spawn()`, holding [`SPAWN_FORK`] shared until the spawn has
/// closed this process's copies of the child's pipe ends.
#[cfg(feature = "notifier")]
pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    let _shared = SPAWN_FORK.read().unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}
