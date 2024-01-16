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

/// A set of events to subscribe to.
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Subscription {
    instructions: Instructions,
    syscalls: SysnoSet,
}

impl Subscription {
    /// Don't receive any events.
    pub fn none() -> Self {
        Subscription {
            instructions: Instructions::empty(),
            syscalls: SysnoSet::empty(),
        }
    }

    /// Subscribe to all events.
    pub fn all() -> Self {
        Subscription {
            instructions: Instructions::CPUID | Instructions::RDTSC,
            syscalls: SysnoSet::all(),
        }
    }

    /// Subscribe to all sycall events (but not instruction events).
    pub fn all_syscalls() -> Self {
        Subscription {
            instructions: Instructions::empty(),
            syscalls: SysnoSet::all(),
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
