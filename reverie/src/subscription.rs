/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use reverie_syscalls::Sysno;

use bitflags::bitflags;
use bitvec::bitvec;
use bitvec::vec::BitVec;

// The maximum number of syscalls to hold in our bitvec.
//
// FIXME: This should come from the `syscall` crate instead.
const MAX_SYSCALLS: usize = 512;

bitflags! {
    #[derive(Default)]
    struct Instructions: u32 {
        const CPUID = 1;
        const RDTSC = 2;
    }
}

/// A set of events to subscribe to.
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Subscription {
    instructions: Instructions,
    // TODO: Use a BitArray with bitvec >=0.18
    syscalls: BitVec,
}

impl Subscription {
    /// Don't receive any events.
    pub fn none() -> Self {
        Subscription {
            instructions: Instructions::empty(),
            syscalls: bitvec![0; MAX_SYSCALLS],
        }
    }

    /// Subscribe to all events.
    pub fn all() -> Self {
        Subscription {
            instructions: Instructions::CPUID | Instructions::RDTSC,
            syscalls: bitvec![1; MAX_SYSCALLS],
        }
    }

    /// Subscribe to all sycall events (but not instruction events).
    pub fn all_syscalls() -> Self {
        Subscription {
            instructions: Instructions::empty(),
            syscalls: bitvec![1; MAX_SYSCALLS],
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
        self.syscalls.set(syscall as i32 as usize, enabled);
        self
    }

    /// Enables a single syscall.
    #[inline]
    pub fn syscall(&mut self, syscall: Sysno) -> &mut Self {
        self.set(syscall, true)
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
        self.set(syscall, false)
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
        // With bitvec >=0.20, this becomes a lot simpler:
        //self.syscalls.iter_ones().filter_map(Sysno::new)

        self.syscalls.iter().enumerate().filter_map(
            |(i, is_set)| {
                if *is_set { Sysno::new(i) } else { None }
            },
        )
    }

    /// Iterates over the set of syscalls that are disabled.
    pub fn iter_disabled_syscalls(&self) -> impl Iterator<Item = Sysno> + '_ {
        // With bitvec >=0.20, this becomes a lot simpler:
        //self.syscalls.iter_zeros().filter_map(Sysno::new)

        self.syscalls.iter().enumerate().filter_map(
            |(i, is_set)| {
                if !*is_set { Sysno::new(i) } else { None }
            },
        )
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
        self.syscalls.set(syscall as i32 as usize, true);
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
        let mut s1: Subscription = [Sysno::open, Sysno::read, Sysno::write]
            .iter()
            .copied()
            .collect();
        s1 |= Sysno::open;

        let mut s2 = Subscription::none();
        s2 |= s1.clone();
        s2 |= Sysno::open;

        assert_eq!(
            s1.iter_syscalls().collect::<Vec<_>>(),
            [Sysno::read, Sysno::write, Sysno::open,]
        );

        assert_eq!(
            s2.iter_syscalls().collect::<Vec<_>>(),
            [Sysno::read, Sysno::write, Sysno::open,]
        );
    }

    #[test]
    fn disabled_syscalls() {
        let mut sub = Subscription::all();

        assert!(sub.iter_disabled_syscalls().next().is_none());

        sub.set(Sysno::open, false);
        sub.set(Sysno::read, false);

        assert_eq!(
            sub.iter_disabled_syscalls().collect::<Vec<_>>(),
            [Sysno::read, Sysno::open]
        );
    }

    #[test]
    fn compose() {
        let a = Subscription::from_iter([Sysno::open, Sysno::read]);
        let b = Subscription::from_iter([Sysno::read, Sysno::close]);
        let c = a | b;

        assert_eq!(
            c.iter_syscalls().collect::<Vec<_>>(),
            [Sysno::read, Sysno::open, Sysno::close]
        );
    }
}
