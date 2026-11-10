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
    /// A backend running under an external exec watcher (a supervisor that
    /// catches the kernel exec event and re-bootstraps the successor)
    /// forwards the exec instead and records no refusal: this name covers
    /// only the unwatched configuration.
    Exec,
    /// A scheduling, priority or I/O-priority call (`setpriority`,
    /// `getpriority`, the `sched_set*` and `sched_get*` calls that name a
    /// task, `ioprio_set` or `ioprio_get`) for a task other than the caller,
    /// a process group or a user, on a backend that can perform it only for
    /// the calling task. A backend that refuses it changed no scheduling
    /// state and read none. No backend currently records it.
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
    /// A call whose answer the tool decides on every backend, on a backend
    /// that therefore keeps no copy of that answer: for example the CPU,
    /// scheduling and priority queries and changes, `prlimit64`, the user
    /// and group id calls, `seccomp` or `getpgrp`. A backend that refuses one
    /// performed none of the call's own effects. A tool that answers the call
    /// itself never sees this refusal.
    ToolDecided,
    /// `madvise(2)` advice whose effect a program can observe, such as what a
    /// fork copies or a core dump holds, on a backend that does not implement
    /// that advice. A backend that refuses it changed no mapping and no page;
    /// the refusal's diagnostic names the advice.
    MemoryAdvice,
    /// An operation on a `signalfd(2)` descriptor that the backend does not
    /// model, such as a read that would wait for a signal, or creating a
    /// process that inherits the descriptor. A backend that refuses it read no
    /// signal, created nothing and registered nothing; the refusal's
    /// diagnostic names the operation.
    Signalfd,
    /// `clone` or `clone3` asking for a child the backend cannot create: flags,
    /// an exit signal or `struct clone_args` fields it does not implement,
    /// such as `CLONE_VM` for a new process without `CLONE_VFORK`, or
    /// `CLONE_THREAD` without `CLONE_FS` or `CLONE_FILES`. The backend does
    /// not check every rule by which Linux refuses a clone, so a tool that
    /// gives Linux's answers to those first sees this only for clones Linux
    /// would perform. A backend that refuses one created no child and the
    /// caller runs on unchanged; the refusal's diagnostic names the case.
    Clone,
    /// `pkey_alloc`, `pkey_mprotect` or `pkey_free`, on a backend that does
    /// not implement memory protection keys. A backend that refuses one
    /// allocated, applied and freed no key and changed no mapping.
    ProtectionKeys,
    /// `userfaultfd(2)`, on a backend that does not implement it. A backend
    /// that refuses it created no descriptor.
    Userfaultfd,
    /// An operation Linux would perform for the guest, which the backend could
    /// not carry out because a host resource of its own ran out: for example
    /// host address space, when the host refuses the memory the backend
    /// reserves for an `execve` under the supervisor's `RLIMIT_AS`. The guest's
    /// request was valid, and the errno says nothing Linux would report for
    /// the guest's own reasons. A backend that refuses it performed none of
    /// the operation: an exec ran none of the new image and left the old
    /// image, its threads and its address space in place. The refusal's
    /// diagnostic names the resource, the request and the limit.
    HostResources,
    /// `prctl(PR_SET_PDEATHSIG)` arming a signal the backend cannot send when
    /// the caller's parent thread exits, such as a stop signal on a backend
    /// with no stopped state, a real-time signal on one whose signal queues
    /// hold standard signals only, or `SIGCHLD` on one whose queues carry it
    /// only for a child's exit. Linux accepts every signal from 1 to 64. A
    /// backend that refuses it armed nothing and kept the caller's previous
    /// parent-death signal; the refusal's diagnostic names the reason.
    ParentDeathSignal,
    /// An operation on a pidfd that the backend does not model, such as
    /// sending a pidfd for a process of the run in an `SCM_RIGHTS` message,
    /// or adding one to an epoll set where the backend cannot tell open file
    /// descriptions apart, or to an epoll set that came from outside the run,
    /// where a process the backend cannot see may hold it. It also names the
    /// refusal of an epoll set, whose pidfd registrations the backend keeps,
    /// in an `SCM_RIGHTS` message that may leave the run, where the backend
    /// could not follow its lifetime, and of a Unix socket in such a message
    /// while an epoll set sent in the run may be queued in it. A backend that
    /// refuses one changed nothing; the refusal's diagnostic names the
    /// operation.
    Pidfd,
    /// A receive that takes a record from a Unix datagram or seqpacket socket
    /// into a buffer that is not all writable, on a backend that must see
    /// every right such a receive takes, and whose own receive, like Linux's,
    /// would free the record with its rights unseen where the copy faults.
    /// The refusal is conservative: it also covers receives that Linux
    /// completes, such as of a record that fits the writable part, and the
    /// refusal's diagnostic names when the backend makes it. A backend that
    /// refuses one received nothing.
    UnwritableRecordBuffer,
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
