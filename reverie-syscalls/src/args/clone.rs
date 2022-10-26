/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::fmt;

use serde::Deserialize;
use serde::Serialize;

use crate::Displayable;
use crate::FromToRaw;
use crate::MemoryAccess;

bitflags::bitflags! {
    /// Flags used with the `clone`, `clone3`, or `unshare` syscalls.
    #[derive(Serialize, Deserialize)]
    pub struct CloneFlags: u64 {
        /// set if VM shared between processes
        const CLONE_VM = libc::CLONE_VM as u64;
        /// set if fs info shared between processes
        const CLONE_FS = libc::CLONE_FS as u64;
        /// set if open files shared between processes
        const CLONE_FILES = libc::CLONE_FILES as u64;
        /// set if signal handlers and blocked signals shared
        const CLONE_SIGHAND = libc::CLONE_SIGHAND as u64;
        /// set if we want to let tracing continue on the child too
        const CLONE_PTRACE = libc::CLONE_PTRACE as u64;
        /// set if the parent wants the child to wake it up on mm_release
        const CLONE_VFORK = libc::CLONE_VFORK as u64;
        /// set if we want to have the same parent as the cloner
        const CLONE_PARENT = libc::CLONE_PARENT as u64;
        /// Same thread group?
        const CLONE_THREAD = libc::CLONE_THREAD as u64;
        /// New mount namespace group
        const CLONE_NEWNS = libc::CLONE_NEWNS as u64;
        /// share system V SEM_UNDO semantics
        const CLONE_SYSVSEM = libc::CLONE_SYSVSEM as u64;
        /// create a new TLS for the child
        const CLONE_SETTLS = libc::CLONE_SETTLS as u64;
        /// set the TID in the parent
        const CLONE_PARENT_SETTID = libc::CLONE_PARENT_SETTID as u64;
        /// clear the TID in the child
        const CLONE_CHILD_CLEARTID = libc::CLONE_CHILD_CLEARTID as u64;
        /// Unused, ignored
        const CLONE_DETACHED = libc::CLONE_DETACHED as u64;
        /// set if the tracing process can't force CLONE_PTRACE on this clone
        const CLONE_UNTRACED = libc::CLONE_UNTRACED as u64;
        /// set the TID in the child
        const CLONE_CHILD_SETTID = libc::CLONE_CHILD_SETTID as u64;
        /// New cgroup namespace
        const CLONE_NEWCGROUP = libc::CLONE_NEWCGROUP as u64;
        /// New utsname namnespace
        const CLONE_NEWUTS = libc::CLONE_NEWUTS as u64;
        /// New ipc namespace
        const CLONE_NEWIPC = libc::CLONE_NEWIPC as u64;
        /// New user namespace
        const CLONE_NEWUSER = libc::CLONE_NEWUSER as u64;
        /// New pid namespace
        const CLONE_NEWPID = libc::CLONE_NEWPID as u64;
        /// New network namespace
        const CLONE_NEWNET = libc::CLONE_NEWNET as u64;
        /// Clone io context
        const CLONE_IO = libc::CLONE_IO as u64;
        /// Set if a pidfd should be placed in parent.
        const CLONE_PIDFD = 0x00001000;
        /// Clear any signal handler and reset to SIG_DFL. Only used with clone3.
        const CLONE_CLEAR_SIGHAND = 0x100000000;
        /// Clone into a specific cgroup given the right permissions. Only used with clone3.
        const CLONE_INTO_CGROUP = 0x200000000;
        /// New time namespace
        const CLONE_NEWTIME	= 0x00000080;
        /// Get signaled when the child exits.
        const SIGCHLD = libc::SIGCHLD as u64;
    }
}

impl Displayable for CloneFlags {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl FromToRaw for CloneFlags {
    fn from_raw(raw: usize) -> Self {
        unsafe { Self::from_bits_unchecked(raw as u64) }
    }

    fn into_raw(self) -> usize {
        self.bits() as usize
    }
}

impl From<nix::sched::CloneFlags> for CloneFlags {
    fn from(flags: nix::sched::CloneFlags) -> Self {
        unsafe { CloneFlags::from_bits_unchecked(flags.bits() as u64) }
    }
}

/// libc does not contain the definition of `clone_args`.
///
/// See `linux/include/uapi/linux/sched.h`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(C, align(8))]
pub struct CloneArgs {
    /// Flags for the new process as listed above. All flags are valid except
    /// for CSIGNAL and CLONE_DETACHED.
    pub flags: CloneFlags,
    /// If CLONE_PIDFD is set, a pidfd will be returned in this argument.
    pub pidfd: u64,
    /// If CLONE_CHILD_SETTID is set, the TID of the child process will be
    /// returned in the child's memory.
    pub child_tid: u64,
    /// If CLONE_PARENT_SETTID is set, the TID of the child process will be
    /// returned in the parent's memory.
    pub parent_tid: u64,
    /// The exit_signal the parent process will be sent when the child exits.
    pub exit_signal: u64,
    /// Specify the location of the stack for the child process. Note, @stack is
    /// expected to point to the lowest address. The stack direction will be
    /// determined by the kernel and set up appropriately based on @stack_size.
    pub stack: u64,
    /// The size of the stack for the child process.
    pub stack_size: u64,
    /// If CLONE_SETTLS is set, the tls descriptor is set to tls.
    pub tls: u64,
    /// Pointer to an array of type *pid_t. The size of the array is defined
    /// using @set_tid_size. This array is used to select PIDs/TIDs for newly
    /// created processes. The first element in this defines the PID in the most
    /// nested PID namespace. Each additional element in the array defines the
    /// PID in the parent PID namespace of the original PID namespace. If the
    /// array has less entries than the number of currently nested PID
    /// namespaces only the PIDs in the corresponding namespaces are set.
    pub set_tid: u64,
    /// This defines the size of the array referenced in @set_tid. This cannot
    /// be larger than the kernel's limit of nested PID namespaces.
    pub set_tid_size: u64,
    /// If CLONE_INTO_CGROUP is specified set this to a file descriptor for the
    /// cgroup.
    pub cgroup: u64,
    // This struct is versioned by size and may grow in the future.
}

impl Displayable for CloneArgs {
    fn fmt<M: MemoryAccess>(
        &self,
        _memory: &M,
        _outputs: bool,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_size() {
        // Make sure our struct is packed and aligned correctly.
        // size_of = #fields * alignment
        assert_eq!(core::mem::size_of::<CloneArgs>(), 11 * 8);
        assert_eq!(core::mem::align_of::<CloneArgs>(), 8);
    }
}
