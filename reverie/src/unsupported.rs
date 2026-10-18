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
    /// `execve` or `execveat` on a backend that cannot replace the process
    /// image at all. No replacement image ran; the caller runs on unchanged.
    Exec,
    /// A scheduling, priority or I/O-priority call (`setpriority`,
    /// `getpriority`, the `sched_set*` and `sched_get*` calls that name a
    /// task, `ioprio_set` or `ioprio_get`) for a task other than the caller,
    /// a process group or a user, on a backend that can perform it only for
    /// the calling task. A backend that refuses it changed no scheduling
    /// state and read none.
    Scheduling,
    /// `rt_sigaction` installing a handler, or `SIG_IGN`, for a signal the
    /// backend reserves for its own use, so the guest's disposition could not
    /// take effect. A backend that refuses changed no disposition; resetting
    /// the signal to `SIG_DFL` is not refused. The refusal's diagnostic names
    /// the signal and its use.
    ReservedSignal,
    /// Delivering a caught signal that the tool selected and approved
    /// ([`crate::Guest::deliver_signal`]), on a backend that does not deliver
    /// signals that way. Nothing was delivered or changed; the backend's own
    /// delivery path is unchanged.
    SignalDelivery,
}

/// A backend's refusal of an injected syscall, or of a `Guest` operation,
/// that it cannot perform, as distinct from a failure that Linux itself would
/// report with the same errno.
///
/// A backend records one when it refuses an operation that it does not
/// implement, and [`Guest::take_unsupported_refusal`](crate::Guest::take_unsupported_refusal)
/// reports it to the tool after the injection returns the refusal's errno. A
/// `Guest` operation that answers with a refusal directly, such as
/// [`Guest::deliver_signal`](crate::Guest::deliver_signal), returns it
/// instead, and its `errno` is the one the operation stands for (`ENOSYS`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct UnsupportedRefusal {
    /// The operation the backend refused.
    pub operation: UnsupportedOperation,
    /// The errno the refused injection returned, or the one a refused `Guest`
    /// operation stands for.
    pub errno: Errno,
    /// The backend's one-line description of the refusal, naming the backend
    /// or, for a default trait method, the operation, for the tool's
    /// diagnostics.
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
