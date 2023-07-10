/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Common code associated with ['libc::user_regs_struct']

/// Trait providing reusable display formatting for registers
pub trait RegDisplay {
    /// Returns a display object associated with a trait implementor
    fn display(&self) -> Display<'_> {
        self.display_with_options(Default::default())
    }

    /// Return a display object associated with a trait implementor.
    /// Additionally specifis ['RegDisplayOptions'] structure to adjust formatting
    fn display_with_options(&self, options: RegDisplayOptions) -> Display<'_>;
}

impl RegDisplay for libc::user_regs_struct {
    fn display_with_options(&self, options: RegDisplayOptions) -> Display<'_> {
        Display {
            options,
            regs: self,
        }
    }
}

/// Options for how [`libc::user_regs_struct`] can be formatted for the
/// [`std::fmt::Display`] implementation.
#[derive(Default)]
pub struct RegDisplayOptions {
    /// whether to display registers in a single line or format on multiple lines
    pub multiline: bool,
}

/// A wrapper defers and implements [`std::fmt::Display`] for
/// [`libc::user_regs_struct`] according to the options represented by
/// [`RegDisplayOptions`].
pub struct Display<'a> {
    options: RegDisplayOptions,
    regs: &'a libc::user_regs_struct,
}

impl<'a> Display<'a> {
    #[cfg(target_arch = "x86_64")]
    fn fmt_single_line_x86(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rax {:#01x} rbx {:#01x} rcx {:#01x} rdx {:#01x}",
            self.regs.rax, self.regs.rbx, self.regs.rcx, self.regs.rdx
        )?;
        write!(
            f,
            " rsi {:#01x} rdi {:#01x} rbp {:#01x} rsp {:#01x}",
            self.regs.rsi, self.regs.rdi, self.regs.rbp, self.regs.rsp
        )?;
        write!(
            f,
            " r8 {:#01x}  r9 {:#01x} r10 {:#01x} r11 {:#01x}",
            self.regs.r8, self.regs.r9, self.regs.r10, self.regs.r11
        )?;
        write!(
            f,
            " r12 {:#01x} r13 {:#01x} r14 {:#01x} r15 {:#01x}",
            self.regs.r12, self.regs.r13, self.regs.r14, self.regs.r15
        )?;
        write!(
            f,
            " rip {:#01x} eflags {:#01x}",
            self.regs.rip, self.regs.eflags
        )?;
        write!(
            f,
            " cs {:#01x} ss {:#01x} ds {:#01x} es {:#01x}",
            self.regs.cs, self.regs.ss, self.regs.ds, self.regs.es,
        )?;
        write!(f, " fs {:#01x} gs {:#01x}", self.regs.fs, self.regs.gs)
    }
    #[cfg(target_arch = "x86_64")]
    fn fmt_multi_line_x86(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            " rax {:#16x} rbx {:#16x} rcx {:#16x} rdx {:#16x}",
            self.regs.rax, self.regs.rbx, self.regs.rcx, self.regs.rdx
        )?;
        writeln!(
            f,
            " rsi {:#16x} rdi {:#16x} rbp {:#16x} rsp {:#16x}",
            self.regs.rsi, self.regs.rdi, self.regs.rbp, self.regs.rsp
        )?;
        writeln!(
            f,
            " r8 {:#16x}  r9 {:#16x} r10 {:#16x} r11 {:#16x}",
            self.regs.r8, self.regs.r9, self.regs.r10, self.regs.r11
        )?;
        writeln!(
            f,
            " r12 {:#16x} r13 {:#16x} r14 {:#16x} r15 {:#16x}",
            self.regs.r12, self.regs.r13, self.regs.r14, self.regs.r15
        )?;
        writeln!(
            f,
            " rip {:#16x} eflags {:#16x}",
            self.regs.rip, self.regs.eflags
        )?;
        writeln!(
            f,
            " cs {:#16x} ss {:#16x} ds {:#16x} es {:#16x}",
            self.regs.cs, self.regs.ss, self.regs.ds, self.regs.es,
        )?;
        writeln!(f, " fs {:#16x} gs {:#16x}", self.regs.fs, self.regs.gs)
    }
}

#[cfg(target_arch = "x86_64")]
impl<'a> std::fmt::Display for Display<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.options.multiline {
            self.fmt_multi_line_x86(f)
        } else {
            self.fmt_single_line_x86(f)
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl<'a> std::fmt::Display for Display<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.regs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_single_line_x86() {
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.rax = 255;
        let result = format!("{}", regs.display());
        assert_eq!(
            result,
            "rax 0xff rbx 0x0 rcx 0x0 rdx 0x0 rsi 0x0 rdi 0x0 rbp 0x0 rsp 0x0 r8 0x0  r9 0x0 r10 0x0 r11 0x0 r12 0x0 r13 0x0 r14 0x0 r15 0x0 rip 0x0 eflags 0x0 cs 0x0 ss 0x0 ds 0x0 es 0x0 fs 0x0 gs 0x0"
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_multi_line_x86() {
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.rax = 255;
        let result = format!(
            "{}",
            regs.display_with_options(RegDisplayOptions {
                multiline: true,
                ..Default::default()
            })
        );
        let lines = vec![
            " rax             0xff rbx              0x0 rcx              0x0 rdx              0x0",
            " rsi              0x0 rdi              0x0 rbp              0x0 rsp              0x0",
            " r8              0x0  r9              0x0 r10              0x0 r11              0x0",
            " r12              0x0 r13              0x0 r14              0x0 r15              0x0",
            " rip              0x0 eflags              0x0",
            " cs              0x0 ss              0x0 ds              0x0 es              0x0",
            " fs              0x0 gs              0x0",
        ];

        assert_eq!(result.lines().into_iter().collect::<Vec<&str>>(), lines);
    }
}
