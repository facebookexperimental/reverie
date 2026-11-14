/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bitflags::bitflags;
use reverie_syscalls::Sysno;
use syscalls::SysnoSet;

bitflags! {
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    struct Instructions: u32 {
        const CPUID = 1;
        const RDTSC = 2;
    }
}

/// What a backend does with a guest syscall whose number the `syscalls`
/// crate's table cannot name: a number with no [`Sysno`], carried to the
/// Tool as a `RawSyscall` when it is reported at all.
///
/// The policy applies *only* to such unknown numbers. A syscall the table
/// knows but the Tool did not subscribe to keeps its legacy routing under
/// every variant (on the ptrace backend it runs natively, untraced).
///
/// "Unknown" is a property of the table Reverie was built with, not of the
/// running kernel, which may implement the number. `ENOSYS` below is what
/// Linux itself returns for a number it does not implement.
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UnknownSyscallPolicy {
    /// The backend's legacy behavior, unchanged. This is the default, so
    /// Tools that never choose a policy see no change.
    ///
    /// On the ptrace backend the seccomp filter allows the call and the
    /// host kernel executes it (returning `-ENOSYS` itself if it does not
    /// implement the number either). No stop is generated, so the call is
    /// not observable; if the guest's own filter nevertheless traces it,
    /// the tracer keeps its legacy behavior of failing the stop with an
    /// error. On the KVM backend the number fails to decode and the run
    /// aborts, as it did before this policy existed.
    #[default]
    AllowNative,

    /// The guest receives `-ENOSYS` and the call never executes in the
    /// kernel. The backend handles it without a Tool callback.
    ///
    /// The call is still intercepted: on the ptrace backend it arrives as
    /// a seccomp trace stop the backend answers itself, so the stop is
    /// observable to anything watching stops, but the Tool receives no
    /// event for it.
    Enosys,

    /// The guest receives `-ENOSYS`, resolved without stopping the guest
    /// where the backend can: on the ptrace backend the seccomp filter's
    /// default action is `SECCOMP_RET_ERRNO` with `ENOSYS`, so the kernel
    /// answers inline. There is no tracer round-trip and the call is not
    /// observable as a stop. A backend with no such in-kernel filter (KVM)
    /// behaves exactly as [`UnknownSyscallPolicy::Enosys`]; the guest
    /// cannot tell the two apart.
    EnosysFast,

    /// The backend stops the guest and calls `Tool::handle_unknown_syscall`
    /// for each such call; the value it returns is the call's result. The
    /// call is observable by definition, and costs the same interception
    /// as a subscribed syscall.
    TrapToTool,
}

/// A set of events to subscribe to.
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Subscription {
    instructions: Instructions,
    syscalls: SysnoSet,
    unknown_syscall_policy: UnknownSyscallPolicy,
}

impl Subscription {
    /// Don't receive any events.
    pub fn none() -> Self {
        Subscription {
            instructions: Instructions::empty(),
            syscalls: SysnoSet::empty(),
            unknown_syscall_policy: UnknownSyscallPolicy::AllowNative,
        }
    }

    /// Subscribe to all events.
    pub fn all() -> Self {
        Subscription {
            instructions: Instructions::CPUID | Instructions::RDTSC,
            syscalls: SysnoSet::all(),
            unknown_syscall_policy: UnknownSyscallPolicy::AllowNative,
        }
    }

    /// Subscribe to all sycall events (but not instruction events).
    pub fn all_syscalls() -> Self {
        Subscription {
            instructions: Instructions::empty(),
            syscalls: SysnoSet::all(),
            unknown_syscall_policy: UnknownSyscallPolicy::AllowNative,
        }
    }

    /// Enable interception of the `rdtsc` instruction.
    #[inline]
    pub fn rdtsc(&mut self) -> &mut Self {
        self.instructions.insert(Instructions::RDTSC);
        self
    }

    /// Enable interception of the `cpuid` instruction.
    #[inline]
    pub fn cpuid(&mut self) -> &mut Self {
        self.instructions.insert(Instructions::CPUID);
        self
    }

    /// Returns true if we're subscribed to RDTSC events.
    #[inline]
    pub fn has_rdtsc(&self) -> bool {
        self.instructions.contains(Instructions::RDTSC)
    }

    /// Returns true if we're subscribed to CPUID events.
    #[inline]
    pub fn has_cpuid(&self) -> bool {
        self.instructions.contains(Instructions::CPUID)
    }

    /// Enables or disables a single syscall.
    #[inline]
    pub fn set(&mut self, syscall: Sysno, enabled: bool) -> &mut Self {
        if enabled {
            self.syscalls.insert(syscall);
        } else {
            self.syscalls.remove(syscall);
        }
        self
    }

    /// Enables a single syscall.
    #[inline]
    pub fn syscall(&mut self, syscall: Sysno) -> &mut Self {
        self.syscalls.insert(syscall);
        self
    }

    /// Enables multiple syscalls.
    pub fn syscalls<I>(&mut self, syscalls: I) -> &mut Self
    where
        I: IntoIterator<Item = Sysno>,
    {
        for syscall in syscalls {
            self.syscall(syscall);
        }

        self
    }

    /// Disables a single syscall.
    #[inline]
    pub fn disable_syscall(&mut self, syscall: Sysno) -> &mut Self {
        self.syscalls.remove(syscall);
        self
    }

    /// Disables multiple syscalls.
    pub fn disable_syscalls<I>(&mut self, syscalls: I) -> &mut Self
    where
        I: IntoIterator<Item = Sysno>,
    {
        for syscall in syscalls {
            self.disable_syscall(syscall);
        }

        self
    }

    /// Iterates over the set of syscalls that are enabled.
    pub fn iter_syscalls(&self) -> impl Iterator<Item = Sysno> + '_ {
        self.syscalls.iter()
    }

    /// Sets what a backend does with a syscall number the syscall table
    /// cannot name. See [`UnknownSyscallPolicy`]; the default is
    /// [`UnknownSyscallPolicy::AllowNative`], the legacy behavior.
    #[inline]
    pub fn set_unknown_syscall_policy(&mut self, policy: UnknownSyscallPolicy) -> &mut Self {
        self.unknown_syscall_policy = policy;
        self
    }

    /// What a backend does with a syscall number the syscall table cannot
    /// name, as set by [`Subscription::set_unknown_syscall_policy`].
    #[inline]
    pub fn unknown_syscall_policy(&self) -> UnknownSyscallPolicy {
        self.unknown_syscall_policy
    }
}

impl core::ops::BitOr for Subscription {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl core::ops::BitOrAssign for Subscription {
    fn bitor_assign(&mut self, rhs: Self) {
        self.instructions |= rhs.instructions;
        self.syscalls |= rhs.syscalls;
        // A merge keeps an explicitly chosen unknown-syscall policy: the
        // right-hand side wins when it chose one, so merging in a
        // subscription that never set a policy cannot silently restore
        // the legacy default.
        if rhs.unknown_syscall_policy != UnknownSyscallPolicy::AllowNative {
            self.unknown_syscall_policy = rhs.unknown_syscall_policy;
        }
    }
}

impl core::ops::BitOrAssign<Sysno> for Subscription {
    fn bitor_assign(&mut self, syscall: Sysno) {
        self.syscalls.insert(syscall);
    }
}

impl Extend<Sysno> for Subscription {
    fn extend<I: IntoIterator<Item = Sysno>>(&mut self, iter: I) {
        for syscall in iter {
            *self |= syscall;
        }
    }
}

impl FromIterator<Sysno> for Subscription {
    fn from_iter<I: IntoIterator<Item = Sysno>>(iter: I) -> Self {
        let mut s = Self::none();
        s.extend(iter);
        s
    }
}

impl core::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let syscalls: Vec<_> = self.iter_syscalls().collect();

        f.debug_struct("Subscription")
            .field("instructions", &self.instructions)
            .field("syscalls", &syscalls)
            .field("unknown_syscall_policy", &self.unknown_syscall_policy)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let mut s1: Subscription = [Sysno::openat, Sysno::read, Sysno::write]
            .iter()
            .copied()
            .collect();
        s1 |= Sysno::openat;

        // NOTE: Different architectures may order syscalls differently.
        let union: Vec<_> = s1.iter_syscalls().collect();
        assert_eq!(union.len(), 3);
        assert!(union.contains(&Sysno::read));
        assert!(union.contains(&Sysno::write));
        assert!(union.contains(&Sysno::openat));

        let mut s2 = Subscription::none();
        s2 |= s1.clone();
        s2 |= Sysno::openat;

        let union: Vec<_> = s2.iter_syscalls().collect();
        assert_eq!(union.len(), 3);
        assert!(union.contains(&Sysno::read));
        assert!(union.contains(&Sysno::write));
        assert!(union.contains(&Sysno::openat));
    }

    #[test]
    fn unknown_syscall_policy_defaults_and_merges() {
        // Every constructor keeps the legacy default.
        for s in [
            Subscription::none(),
            Subscription::all(),
            Subscription::all_syscalls(),
            Subscription::default(),
        ] {
            assert_eq!(
                s.unknown_syscall_policy(),
                UnknownSyscallPolicy::AllowNative
            );
        }

        let mut chosen = Subscription::none();
        chosen.set_unknown_syscall_policy(UnknownSyscallPolicy::Enosys);
        assert_eq!(
            chosen.unknown_syscall_policy(),
            UnknownSyscallPolicy::Enosys
        );

        // Merging in a subscription that never chose keeps the choice;
        // merging in one that did takes its choice.
        let kept = chosen.clone() | Subscription::all();
        assert_eq!(kept.unknown_syscall_policy(), UnknownSyscallPolicy::Enosys);
        let mut fast = Subscription::none();
        fast.set_unknown_syscall_policy(UnknownSyscallPolicy::EnosysFast);
        let replaced = chosen | fast;
        assert_eq!(
            replaced.unknown_syscall_policy(),
            UnknownSyscallPolicy::EnosysFast
        );
    }

    #[test]
    fn compose() {
        let a = Subscription::from_iter([Sysno::openat, Sysno::read]);
        let b = Subscription::from_iter([Sysno::read, Sysno::close]);
        let c = a | b;

        let union: Vec<_> = c.iter_syscalls().collect();

        assert_eq!(union.len(), 3);
        assert!(union.contains(&Sysno::read));
        assert!(union.contains(&Sysno::openat));
        assert!(union.contains(&Sysno::close));
    }
}
