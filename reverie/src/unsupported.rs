/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed refusals of operations that a backend cannot perform.

use crate::Errno;

/// An operation that Linux defines and a backend may decline to perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum UnsupportedOperation {
    /// `execve` or `execveat` from a thread that is not its thread group's
    /// leader. Linux makes the caller the new leader while it tears down
    /// every other thread of the group. A backend that refuses it ran none of
    /// the new image and left every thread of the group, the old image and
    /// the address space in place.
    NonLeaderExec,
    /// The installed in-guest native exec route declined its owned dispatch,
    /// original operation, live cut or controlled successor launch chain.
    /// No replacement image ran; ordinary exec preparation can roll back.
    NativeExec,
    /// `clone`, `clone3` or `vfork` that would create a thread or a vfork
    /// child, on a backend that runs one thread of the guest and cannot add
    /// another. No child was created and the caller runs on unchanged.
    ThreadCreation,
    /// Every valid `flock(2)` operation (`LOCK_SH`, `LOCK_EX` or `LOCK_UN`,
    /// with or without `LOCK_NB`). A backend that refuses it took no lock and
    /// released none. A backend refuses when it cannot keep the host open file
    /// description behind a guest descriptor identical in identity and
    /// lifetime to the guest's description, so that a forwarded host lock
    /// would be held or released at the wrong time.
    Flock,
    /// A signal delivery (`kill`, `tkill`, `tgkill`, `rt_sigqueueinfo` or
    /// `rt_tgsigqueueinfo`) the backend cannot perform, for example to
    /// another process. A backend that refuses it queued no signal and
    /// changed no signal state; the refusal's diagnostic names the reason.
    Signal,
    /// `setsid` or `setpgid`, on a backend that keeps no process groups or
    /// sessions a guest can change. A backend that refuses changed none. A
    /// tool that models process groups itself may keep its own answer, as no
    /// kernel state is left to disagree with it.
    ProcessGroups,
}

/// A backend's refusal of an injected syscall that it cannot perform, as
/// distinct from a failure that Linux itself would report with the same
/// errno.
///
/// A backend records one when it refuses an operation that it does not
/// implement, and [`Guest::take_unsupported_refusal`](crate::Guest::take_unsupported_refusal)
/// reports it to the tool after the injection returns the refusal's errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct UnsupportedRefusal {
    /// The operation the backend refused.
    pub operation: UnsupportedOperation,
    /// The errno the refused injection returned.
    pub errno: Errno,
    /// The backend's one-line description of the refusal, naming the backend,
    /// for the tool's diagnostics.
    pub diagnostic: &'static str,
}

impl UnsupportedRefusal {
    /// A refusal of `operation`, returned to the injecting tool as `errno`.
    pub const fn new(
        operation: UnsupportedOperation,
        errno: Errno,
        diagnostic: &'static str,
    ) -> Self {
        Self {
            operation,
            errno,
            diagnostic,
        }
    }
}
