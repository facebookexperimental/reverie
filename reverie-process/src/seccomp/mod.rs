/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Provides helpers for constructing a [`seccomp`][seccomp] filter. This is a
//! pure Rust implementation and does not require libseccomp.
//!
//! # Seccomp Background
//!
//! [`seccomp(2)`][seccomp] is a powerful tool for changing how a process tree
//! behaves when a syscall happens. Seccomp can be used to install a filter that
//! applies to every child process in a process tree. Since filters cannot be
//! removed, they can only get more restrictive. The language used for filters is
//! called `seccomp-bpf`. It is a subset of the BPF byte code language.
//!
//! Some of the restrictions include:
//!  - Only being able to JMP forward and never backward. This prevents loops and
//!    ensures seccomp-bpf filters always terminate. This is also true of BPF.
//!  - Cannot call libbpf functions.
//!  - Cannot operate on 64-bit integers, only 32-bit integers.
//!
//! [seccomp]: https://man7.org/linux/man-pages/man2/seccomp.2.html
//!
//! You can think of a seccomp-bpf program as a little function that gets
//! executed for every syscall:
//!
//! ```no_compile
//! // NOTE: seccomp-bpf programs are actually written in byte code, but if a
//! // high-level language could be compiled to BPF byte code, this is what it'd
//! // look like.
//! fn my_program(data: seccomp_data) -> Action {
//!     if data.nr == 2 {
//!         return Action::Trace;
//!     }
//!
//!     if data.nr == 3 {
//!         return Action::KillProcess;
//!     }
//!
//!     // Allow the syscall by default.
//!     Action::Allow
//! }
//! ```
//!
//! where `seccomp_data` is defined as:
//!
//! ```no_compile
//! struct seccomp_data {
//!     // The syscall number.
//!     nr: u32,
//!     // The architecture.
//!     arch: u32,
//!     // Instruction pointer.
//!     ip: u64,
//!     // The 6 syscall arguments.
//!     args: [u64; 6],
//! }
//! ```
//!
//! This is the only input available to the seccomp filter and is the only bit of
//! data available to make a decision about a syscall (i.e., an "action"). An
//! action might be nothing (i.e., allow the syscall through), kill the
//! process/thread with `SIGSYS`, forward the syscall to ptrace, or return an
//! error code.

#[macro_use]
mod bpf;

#[allow(unused)]
mod notif;

use bpf::*;

use syscalls::Errno;
use syscalls::Sysno;

pub use bpf::Filter;
pub use notif::*;

use std::collections::BTreeMap;

/// Builder for creating seccomp filters.
#[derive(Clone)]
pub struct FilterBuilder {
    /// The target architecture.
    target_arch: TargetArch,

    /// The action to take if there are no matches.
    default_action: Action,

    /// The action to take for each syscall.
    syscalls: BTreeMap<Sysno, Action>,

    /// Ranges of instruction pointer values.
    ip_ranges: Vec<(u64, u64, Action)>,
}

/// The target architecture.
#[allow(non_camel_case_types, missing_docs)]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum TargetArch {
    x86 = AUDIT_ARCH_X86,
    x86_64 = AUDIT_ARCH_X86_64,
    mips = AUDIT_ARCH_MIPS,
    powerpc = AUDIT_ARCH_PPC,
    powerpc64 = AUDIT_ARCH_PPC64,
    arm = AUDIT_ARCH_ARM,
    aarch64 = AUDIT_ARCH_AARCH64,
}

/// The action to take if the conditions of a rule all match.
#[derive(Debug, Copy, Clone)]
pub enum Action {
    /// Allows the syscallto be executed.
    Allow,

    /// Returns the specified error instead of executing the syscall.
    Errno(Errno),

    /// Prevents the syscall from being executed and the kernel will kill the
    /// calling thread with `SIGSYS`.
    KillThread,

    /// Prevents the syscall from being executed and the kernel will kill the
    /// calling process with `SIGSYS`.
    KillProcess,

    /// Same as [`Action::Allow`] but logs the call.
    Log,

    /// If the thread is being ptraced and the tracing process specified
    /// `PTRACE_O_SECCOMP`, the tracing process will be notified via
    /// `PTRACE_EVENT_SECCOMP` and the value provided can be retrieved using
    /// `PTRACE_GETEVENTMSG`.
    Trace(u16),

    /// Disallow and raise a SIGSYS in the calling process.
    Trap,

    /// Notifies userspace.
    Notify,
}

impl From<Action> for u32 {
    fn from(action: Action) -> u32 {
        match action {
            Action::Allow => libc::SECCOMP_RET_ALLOW,
            Action::Errno(x) => {
                libc::SECCOMP_RET_ERRNO | (x.into_raw() as u32 & libc::SECCOMP_RET_DATA)
            }
            Action::KillThread => libc::SECCOMP_RET_KILL_THREAD,
            Action::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
            Action::Log => libc::SECCOMP_RET_LOG,
            Action::Trace(x) => libc::SECCOMP_RET_TRACE | (x as u32 & libc::SECCOMP_RET_DATA),
            Action::Trap => libc::SECCOMP_RET_TRAP,
            Action::Notify => 0x7fc00000u32,
        }
    }
}

impl From<Action> for sock_filter {
    fn from(action: Action) -> sock_filter {
        BPF_STMT(BPF_RET + BPF_K, u32::from(action))
    }
}

impl TargetArch {
    #![allow(missing_docs)]

    #[cfg(target_arch = "x86")]
    pub const CURRENT: TargetArch = Self::x86;

    #[cfg(target_arch = "x86_64")]
    pub const CURRENT: TargetArch = Self::x86_64;

    #[cfg(target_arch = "mips")]
    pub const CURRENT: TargetArch = Self::mips;

    #[cfg(target_arch = "powerpc")]
    pub const CURRENT: TargetArch = Self::powerpc;

    #[cfg(target_arch = "powerpc64")]
    pub const CURRENT: TargetArch = Self::powerpc64;

    #[cfg(target_arch = "arm")]
    pub const CURRENT: TargetArch = Self::arm;

    #[cfg(target_arch = "aarch64")]
    pub const CURRENT: TargetArch = Self::aarch64;
}

impl Default for TargetArch {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl Default for FilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterBuilder {
    /// Creates the seccomp filter builder.
    pub fn new() -> Self {
        Self {
            target_arch: TargetArch::default(),
            default_action: Action::KillThread,
            syscalls: Default::default(),
            ip_ranges: Default::default(),
        }
    }

    /// Sets the target architecture. If this doesn't match the architecture of
    /// the process, then the process is killed. This is the first step in the
    /// seccomp filter and ensures that we're working with the right syscall
    /// table. Each architecture has a slightly different syscall table and we
    /// need to make sure the syscall numbers we're using are the right ones for
    /// the architecture.
    ///
    /// By default, the target architecture is set to the architecture of the
    /// current program (i.e., `TargetArch::CURRENT`).
    pub fn target_arch(&mut self, target_arch: TargetArch) -> &mut Self {
        self.target_arch = target_arch;
        self
    }

    /// The default action to take if there are no matches. By default, the
    /// default action is to kill the current thread (i.e., the filter becomes an
    /// allowlist).
    ///
    /// When using an allowlist of syscalls, this should be set to
    /// `Action::KillThread` or `Action::KillProcess`.
    ///
    /// When using a blocklist of syscalls, this should be set to
    /// `Action::Allow`.
    pub fn default_action(&mut self, action: Action) -> &mut Self {
        self.default_action = action;
        self
    }

    /// Sets the action to take for the given syscall.
    pub fn syscall(&mut self, syscall: Sysno, action: Action) -> &mut Self {
        self.syscalls.insert(syscall, action);
        self
    }

    /// Sets the action to take for a set of syscalls.
    pub fn syscalls<I>(&mut self, table: I) -> &mut Self
    where
        I: IntoIterator<Item = (Sysno, Action)>,
    {
        self.syscalls.extend(table);
        self
    }

    /// Take an action if the instruction pointer `ip >= begin && ip < end`.
    ///
    /// This is useful in conjunction with `mmap`. For example, we can use this
    /// to deny any syscalls made outside of `ld.so` or `libc.so`. It can also be
    /// used to avoid tracing syscalls injected with ptrace.
    ///
    /// Multiple ranges can be added and are checked in sequence.
    pub fn ip_range(&mut self, begin: u64, end: u64, action: Action) -> &mut Self {
        self.ip_ranges.push((begin, end, action));
        self
    }

    /// Adds multiple IP ranges. This is equivalent to calling
    /// [`FilterBuilder::ip_range`] multiple times.
    pub fn ip_ranges<I>(&mut self, ranges: I) -> &mut Self
    where
        I: IntoIterator<Item = (u64, u64, Action)>,
    {
        self.ip_ranges.extend(ranges);
        self
    }

    /// Generates the byte code for the filter.
    pub fn build(&self) -> Filter {
        let mut filter = Filter::new();

        // This should be the first step for every seccomp-bpf filter.
        VALIDATE_ARCH(self.target_arch as u32).into_bpf(&mut filter);

        if !self.ip_ranges.is_empty() {
            LOAD_SYSCALL_IP().into_bpf(&mut filter);

            for (begin, end, action) in &self.ip_ranges {
                IP_RANGE(*begin, *end, (*action).into()).into_bpf(&mut filter);
            }
        }

        if !self.syscalls.is_empty() {
            // Load the syscall number.
            LOAD_SYSCALL_NR.into_bpf(&mut filter);

            for (syscall, action) in &self.syscalls {
                SYSCALL(*syscall, (*action).into()).into_bpf(&mut filter);
            }
        }

        // The default action is always performed last.
        sock_filter::from(self.default_action).into_bpf(&mut filter);

        filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        assert_eq!(
            FilterBuilder::new()
                .default_action(Action::Allow)
                .target_arch(TargetArch::x86_64)
                .syscalls([
                    (Sysno::read, Action::KillThread),
                    (Sysno::write, Action::KillThread),
                    (Sysno::open, Action::KillThread),
                    (Sysno::close, Action::KillThread),
                    (Sysno::write, Action::KillThread),
                ])
                .build(),
            seccomp_bpf![
                VALIDATE_ARCH(AUDIT_ARCH_X86_64),
                LOAD_SYSCALL_NR,
                SYSCALL(Sysno::read, DENY),
                SYSCALL(Sysno::write, DENY),
                SYSCALL(Sysno::open, DENY),
                SYSCALL(Sysno::close, DENY),
                ALLOW,
            ]
        );
    }
}
