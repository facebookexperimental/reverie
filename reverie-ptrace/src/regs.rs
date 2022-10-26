/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// A single register.
#[cfg(target_pointer_width = "64")]
pub type Reg = u64;

/// A single register.
#[cfg(target_pointer_width = "32")]
pub type Reg = u32;

/// The arguments to a syscall.
pub type ArgRegs = (Reg, Reg, Reg, Reg, Reg, Reg);

/// This trait enables architecture-independent access to general purpose
/// registers.
pub trait RegAccess {
    /// Returns the value of the instruction pointer (aka the program counter).
    fn ip(&self) -> Reg;

    /// Mutable access to the instruction pointer (aka the program counter).
    fn ip_mut(&mut self) -> &mut Reg;

    /// Returns the value of the register where the syscall number is stored.
    ///
    /// NOTE: Depending on the context, this may not actually be a syscall
    /// number.
    fn syscall(&self) -> Reg;

    /// Mutable access to the register where the syscall number is stored.
    ///
    /// NOTE: Depending on the context, this may not actually be a syscall
    /// number.
    fn syscall_mut(&mut self) -> &mut Reg;

    /// This is like [`RegAccess::syscall`] except that it is guaranteed to be
    /// available after the syscall has executed. On x86-64, the syscall number
    /// is clobbered by the return value when a syscall is executed.
    ///
    /// NOTE: Depending on the context, this may not actually be a syscall
    /// number.
    fn orig_syscall(&self) -> Reg;

    /// Mutable access to the register where the syscall number is stored.
    ///
    /// NOTE: Depending on the context, this may not actually be a syscall
    /// number.
    fn orig_syscall_mut(&mut self) -> &mut Reg;

    /// Returns the value of the register where the syscall return value is
    /// stored.
    fn ret(&self) -> Reg;

    /// Mutable access to the register where the syscall return value is stored.
    fn ret_mut(&mut self) -> &mut Reg;

    /// Returns the set of 6 arguments that are used by the syscall instruction.
    fn args(&self) -> ArgRegs;

    /// Mutable access to the appropriate registers for the syscall arguments.
    fn set_args(&mut self, args: ArgRegs);
}

#[cfg(target_arch = "x86_64")]
impl RegAccess for libc::user_regs_struct {
    fn ip(&self) -> Reg {
        self.rip
    }

    fn ip_mut(&mut self) -> &mut Reg {
        &mut self.rip
    }

    fn syscall(&self) -> Reg {
        self.rax
    }

    fn syscall_mut(&mut self) -> &mut Reg {
        &mut self.rax
    }

    fn orig_syscall(&self) -> Reg {
        // Note that we use orig_rax here because it is still available even
        // after the syscall has executed.
        self.orig_rax
    }

    fn orig_syscall_mut(&mut self) -> &mut Reg {
        &mut self.orig_rax
    }

    fn ret(&self) -> Reg {
        self.rax
    }

    fn ret_mut(&mut self) -> &mut Reg {
        &mut self.rax
    }

    fn args(&self) -> ArgRegs {
        (self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9)
    }

    fn set_args(&mut self, args: ArgRegs) {
        self.rdi = args.0;
        self.rsi = args.1;
        self.rdx = args.2;
        self.r10 = args.3;
        self.r8 = args.4;
        self.r9 = args.5;
    }
}

#[cfg(target_arch = "aarch64")]
impl RegAccess for libc::user_regs_struct {
    fn ip(&self) -> Reg {
        self.pc
    }

    fn ip_mut(&mut self) -> &mut Reg {
        &mut self.pc
    }

    fn syscall(&self) -> Reg {
        self.regs[8]
    }

    fn syscall_mut(&mut self) -> &mut Reg {
        &mut self.regs[8]
    }

    fn orig_syscall(&self) -> Reg {
        self.regs[8]
    }

    fn orig_syscall_mut(&mut self) -> &mut Reg {
        &mut self.regs[8]
    }

    fn ret(&self) -> Reg {
        self.regs[0]
    }

    fn ret_mut(&mut self) -> &mut Reg {
        &mut self.regs[0]
    }

    fn args(&self) -> ArgRegs {
        (
            self.regs[0],
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4],
            self.regs[5],
        )
    }

    fn set_args(&mut self, args: ArgRegs) {
        self.regs[0] = args.0;
        self.regs[1] = args.1;
        self.regs[2] = args.2;
        self.regs[3] = args.3;
        self.regs[4] = args.4;
        self.regs[5] = args.5;
    }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use super::*;

    #[test]
    fn basic() {
        let mut regs = unsafe { MaybeUninit::<libc::user_regs_struct>::zeroed().assume_init() };

        assert_eq!(regs.ip(), 0);

        *regs.ip_mut() = 42;

        assert_eq!(regs.ip(), 42);
    }
}
