/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Linux x86-64 signal frame construction and `rt_sigreturn` restore.
//!
//! Moved verbatim from `reverie_linuxemu::signal` (the KVM backend's
//! builder) so every backend shares one frame builder. These codecs
//! deliberately avoid `repr(C)` transmutation. Every byte offset is part
//! of Linux's userspace ABI and is encoded explicitly, which also keeps
//! padding initialized and makes malformed `rt_sigreturn` frames
//! rejectable.

#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::OnceLock;

use kvm_bindings::kvm_regs;
use kvm_bindings::kvm_xsave;
use thiserror::Error;

pub const KERNEL_SIGSET_SIZE: usize = 8;
pub const KERNEL_SIGACTION_SIZE: usize = 32;
pub const SIGINFO_SIZE: usize = crate::SIGNAL_INFO_SIZE;
pub const SIGCONTEXT_SIZE: usize = 256;
pub const UCONTEXT_SIZE: usize = 304;
pub const LEGACY_FPSTATE_SIZE: usize = 512;
pub const RT_SIGFRAME_SIZE: usize = 8 + UCONTEXT_SIZE + SIGINFO_SIZE;
pub const RT_SIGRETURN_SIZE: usize = 8 + UCONTEXT_SIZE;
pub const XSAVE_SIZE: usize = 832;
pub const XSAVE_SIGNAL_SIZE: usize = XSAVE_SIZE + 4;

pub const SIGNAL_RED_ZONE: u64 = 128;
pub const SIGNAL_STACK_ALIGNMENT: u64 = 16;
pub const XSAVE_ALIGNMENT: u64 = 64;

pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SS_AUTODISARM: i32 = i32::MIN;
pub const USER_CODE_SELECTOR: u16 = 0x23;
pub const USER_DATA_SELECTOR: u16 = 0x1b;
pub const SEGV_MAPERR: i32 = 1;
/// `si_code` Linux reports for a #UD (`do_error_trap(..., SIGILL, ILL_ILLOPN, ...)`).
pub const ILL_ILLOPN: i32 = 2;
/// `si_code` Linux reports for a #DE (`do_error_trap(..., SIGFPE, FPE_INTDIV, ...)`).
pub const FPE_INTDIV: i32 = 1;

const UC_FP_XSTATE: u64 = 0x1;
const UC_SIGCONTEXT_SS: u64 = 0x2;
const UC_STRICT_RESTORE_SS: u64 = 0x4;
pub const SIGNAL_UCONTEXT_FLAGS: u64 = UC_FP_XSTATE | UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;

const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
const XFEATURE_X87: u64 = 1 << 0;
const XFEATURE_SSE: u64 = 1 << 1;
const XFEATURE_YMM: u64 = 1 << 2;
// arch/x86/include/asm/sighandling.h in Linux v7.1, lines 11-14.
const FIX_EFLAGS: u64 = (1 << 18)
    | (1 << 16)
    | (1 << 11)
    | (1 << 10)
    | (1 << 8)
    | (1 << 7)
    | (1 << 6)
    | (1 << 4)
    | (1 << 2)
    | (1 << 0);
pub const FIXED_XFEATURES: u64 = XFEATURE_X87 | XFEATURE_SSE | XFEATURE_YMM;
/// The MXCSR feature mask Linux uses when the CPU's FXSAVE image reports none:
/// every bit but DAZ (`fpu__init_system_mxcsr`, arch/x86/kernel/fpu/init.c).
const DEFAULT_MXCSR_FEATURE_MASK: u32 = 0x0000_ffbf;

const MXCSR_MASK_OFFSET: usize = 28;
const XMM_OFFSET: usize = 160;
const XMM_END: usize = XMM_OFFSET + 16 * 16;
const FP_SW_RESERVED_OFFSET: usize = 464;
const XSTATE_BV_OFFSET: usize = 512;
const XCOMP_BV_OFFSET: usize = 520;
const XSTATE_RESERVED_OFFSET: usize = 528;
const XSTATE_RESERVED_END: usize = 576;

/// A malformed signal frame or unsupported XSAVE feature set.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignalFrameError {
    #[error("signal stack address overflow")]
    AddressOverflow,
    #[error("signal frame has an invalid user code or stack selector")]
    InvalidSelectors,
    #[error("signal frame has a non-canonical address")]
    InvalidAddress,
    #[error("signal XSAVE software metadata is invalid")]
    InvalidXsaveMetadata,
    #[error("signal XSAVE feature mask is unsupported")]
    InvalidXsaveFeatures,
    #[error("signal XSAVE reserved fields are nonzero")]
    InvalidXsaveReserved,
    #[error("signal XSAVE MXCSR contains unsupported bits")]
    InvalidMxcsr,
}

/// The eight-byte signal set used by the x86-64 kernel syscall ABI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelSigset([u8; KERNEL_SIGSET_SIZE]);

impl KernelSigset {
    pub const fn from_bytes(bytes: [u8; KERNEL_SIGSET_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn to_bytes(self) -> [u8; KERNEL_SIGSET_SIZE] {
        self.0
    }

    pub fn contains(self, signal: i32) -> bool {
        signal_bit(signal).is_some_and(|(byte, bit)| self.0[byte] & bit != 0)
    }

    pub fn insert(&mut self, signal: i32) {
        if let Some((byte, bit)) = signal_bit(signal) {
            self.0[byte] |= bit;
        }
    }

    pub fn remove(&mut self, signal: i32) {
        if let Some((byte, bit)) = signal_bit(signal) {
            self.0[byte] &= !bit;
        }
    }

    pub fn union_with(&mut self, other: Self) {
        for (current, requested) in self.0.iter_mut().zip(other.0) {
            *current |= requested;
        }
    }

    pub fn remove_all(&mut self, other: Self) {
        for (current, requested) in self.0.iter_mut().zip(other.0) {
            *current &= !requested;
        }
    }

    pub fn intersect_with(&mut self, other: Self) {
        for (current, requested) in self.0.iter_mut().zip(other.0) {
            *current &= requested;
        }
    }

    pub fn clear_unmaskable(&mut self) {
        self.remove(libc::SIGKILL);
        self.remove(libc::SIGSTOP);
    }
}

fn signal_bit(signal: i32) -> Option<(usize, u8)> {
    if !(1..=64).contains(&signal) {
        return None;
    }
    let bit = (signal - 1) as usize;
    Some((bit / 8, 1 << (bit % 8)))
}

/// The kernel layout accepted by x86-64 `rt_sigaction`.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KernelSigaction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: KernelSigset,
}

impl KernelSigaction {
    pub fn decode(bytes: [u8; KERNEL_SIGACTION_SIZE]) -> Self {
        Self {
            handler: read_u64(&bytes, 0),
            flags: read_u64(&bytes, 8),
            restorer: read_u64(&bytes, 16),
            mask: KernelSigset::from_bytes(bytes[24..32].try_into().expect("sigset bytes")),
        }
    }

    pub fn encode(self) -> [u8; KERNEL_SIGACTION_SIZE] {
        let mut bytes = [0; KERNEL_SIGACTION_SIZE];
        write_u64(&mut bytes, 0, self.handler);
        write_u64(&mut bytes, 8, self.flags);
        write_u64(&mut bytes, 16, self.restorer);
        bytes[24..32].copy_from_slice(&self.mask.to_bytes());
        bytes
    }

    pub const fn is_ignored(self) -> bool {
        self.handler == libc::SIG_IGN as u64
    }
}

/// The kernel `stack_t` layout embedded in `ucontext` and used by
/// `sigaltstack`.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GuestStack {
    pub sp: u64,
    pub flags: i32,
    pub size: u64,
}

impl GuestStack {
    pub const SIZE: usize = 24;

    pub fn decode(bytes: [u8; Self::SIZE]) -> Self {
        Self {
            sp: read_u64(&bytes, 0),
            flags: read_i32(&bytes, 8),
            size: read_u64(&bytes, 16),
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        write_u64(&mut bytes, 0, self.sp);
        write_i32(&mut bytes, 8, self.flags);
        write_u64(&mut bytes, 16, self.size);
        bytes
    }

    pub fn contains(self, stack_pointer: u64) -> bool {
        self.flags & (libc::SS_DISABLE | SS_AUTODISARM) == 0
            && stack_pointer > self.sp
            && stack_pointer - self.sp <= self.size
    }
}

/// The x86-64 kernel `sigcontext` embedded in `ucontext`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sigcontext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: u64,
    pub reserved: [u64; 8],
}

impl Sigcontext {
    pub fn from_kvm(registers: kvm_regs, fpstate: u64, oldmask: KernelSigset) -> Self {
        Self {
            r8: registers.r8,
            r9: registers.r9,
            r10: registers.r10,
            r11: registers.r11,
            r12: registers.r12,
            r13: registers.r13,
            r14: registers.r14,
            r15: registers.r15,
            rdi: registers.rdi,
            rsi: registers.rsi,
            rbp: registers.rbp,
            rbx: registers.rbx,
            rdx: registers.rdx,
            rax: registers.rax,
            rcx: registers.rcx,
            rsp: registers.rsp,
            rip: registers.rip,
            rflags: registers.rflags,
            cs: USER_CODE_SELECTOR,
            gs: 0,
            fs: 0,
            ss: USER_DATA_SELECTOR,
            err: 0,
            trapno: 0,
            oldmask: u64::from_le_bytes(oldmask.to_bytes()),
            cr2: 0,
            fpstate,
            reserved: [0; 8],
        }
    }

    pub fn encode(self) -> [u8; SIGCONTEXT_SIZE] {
        let mut bytes = [0; SIGCONTEXT_SIZE];
        for (index, value) in [
            self.r8,
            self.r9,
            self.r10,
            self.r11,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            self.rdi,
            self.rsi,
            self.rbp,
            self.rbx,
            self.rdx,
            self.rax,
            self.rcx,
            self.rsp,
            self.rip,
            self.rflags,
        ]
        .into_iter()
        .enumerate()
        {
            write_u64(&mut bytes, index * 8, value);
        }
        write_u16(&mut bytes, 144, self.cs);
        write_u16(&mut bytes, 146, self.gs);
        write_u16(&mut bytes, 148, self.fs);
        write_u16(&mut bytes, 150, self.ss);
        for (index, value) in [self.err, self.trapno, self.oldmask, self.cr2, self.fpstate]
            .into_iter()
            .enumerate()
        {
            write_u64(&mut bytes, 152 + index * 8, value);
        }
        for (index, value) in self.reserved.into_iter().enumerate() {
            write_u64(&mut bytes, 192 + index * 8, value);
        }
        bytes
    }

    pub fn decode(bytes: [u8; SIGCONTEXT_SIZE]) -> Self {
        let mut words = [0; 18];
        for (index, word) in words.iter_mut().enumerate() {
            *word = read_u64(&bytes, index * 8);
        }
        let mut reserved = [0; 8];
        for (index, word) in reserved.iter_mut().enumerate() {
            *word = read_u64(&bytes, 192 + index * 8);
        }
        Self {
            r8: words[0],
            r9: words[1],
            r10: words[2],
            r11: words[3],
            r12: words[4],
            r13: words[5],
            r14: words[6],
            r15: words[7],
            rdi: words[8],
            rsi: words[9],
            rbp: words[10],
            rbx: words[11],
            rdx: words[12],
            rax: words[13],
            rcx: words[14],
            rsp: words[15],
            rip: words[16],
            rflags: words[17],
            cs: read_u16(&bytes, 144),
            gs: read_u16(&bytes, 146),
            fs: read_u16(&bytes, 148),
            ss: read_u16(&bytes, 150),
            err: read_u64(&bytes, 152),
            trapno: read_u64(&bytes, 160),
            oldmask: read_u64(&bytes, 168),
            cr2: read_u64(&bytes, 176),
            fpstate: read_u64(&bytes, 184),
            reserved,
        }
    }

    pub fn validate_for_restore(self) -> Result<(), SignalFrameError> {
        if self.cs != USER_CODE_SELECTOR
            || ![USER_DATA_SELECTOR, USER_DATA_SELECTOR & !3].contains(&self.ss)
        {
            return Err(SignalFrameError::InvalidSelectors);
        }
        if !is_canonical_user_address(self.rip)
            || !is_canonical_user_address(self.rsp)
            || self.fpstate != 0 && !is_canonical_user_address(self.fpstate)
        {
            return Err(SignalFrameError::InvalidAddress);
        }
        Ok(())
    }

    pub fn restore_kvm(self, registers: &mut kvm_regs) {
        registers.r8 = self.r8;
        registers.r9 = self.r9;
        registers.r10 = self.r10;
        registers.r11 = self.r11;
        registers.r12 = self.r12;
        registers.r13 = self.r13;
        registers.r14 = self.r14;
        registers.r15 = self.r15;
        registers.rdi = self.rdi;
        registers.rsi = self.rsi;
        registers.rbp = self.rbp;
        registers.rbx = self.rbx;
        registers.rdx = self.rdx;
        registers.rax = self.rax;
        registers.rcx = self.rcx;
        registers.rsp = self.rsp;
        registers.rip = self.rip;
        // Linux v7.1 arch/x86/kernel/signal_64.c:84 lets the frame control only
        // FIX_EFLAGS and retains every other bit from the live register state.
        registers.rflags = (registers.rflags & !FIX_EFLAGS) | (self.rflags & FIX_EFLAGS);
    }
}

/// The 304-byte kernel `ucontext` used in an x86-64 `rt_sigframe`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ucontext {
    pub flags: u64,
    pub link: u64,
    pub stack: GuestStack,
    pub mcontext: Sigcontext,
    pub sigmask: KernelSigset,
}

impl Ucontext {
    pub fn encode(self) -> [u8; UCONTEXT_SIZE] {
        let mut bytes = [0; UCONTEXT_SIZE];
        write_u64(&mut bytes, 0, self.flags);
        write_u64(&mut bytes, 8, self.link);
        bytes[16..40].copy_from_slice(&self.stack.encode());
        bytes[40..296].copy_from_slice(&self.mcontext.encode());
        bytes[296..304].copy_from_slice(&self.sigmask.to_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; UCONTEXT_SIZE]) -> Self {
        Self {
            flags: read_u64(&bytes, 0),
            link: read_u64(&bytes, 8),
            stack: GuestStack::decode(bytes[16..40].try_into().expect("stack bytes")),
            mcontext: Sigcontext::decode(bytes[40..296].try_into().expect("sigcontext bytes")),
            sigmask: KernelSigset::from_bytes(bytes[296..304].try_into().expect("sigset bytes")),
        }
    }
}

/// The fixed prefix of Linux's x86-64 `rt_sigframe`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtSigframe {
    pub pretcode: u64,
    pub ucontext: Ucontext,
    pub siginfo: [u8; SIGINFO_SIZE],
}

impl RtSigframe {
    pub fn encode(self) -> [u8; RT_SIGFRAME_SIZE] {
        let mut bytes = [0; RT_SIGFRAME_SIZE];
        write_u64(&mut bytes, 0, self.pretcode);
        bytes[8..312].copy_from_slice(&self.ucontext.encode());
        bytes[312..440].copy_from_slice(&self.siginfo);
        bytes
    }

    pub fn decode(bytes: [u8; RT_SIGFRAME_SIZE]) -> Self {
        Self {
            pretcode: read_u64(&bytes, 0),
            ucontext: Ucontext::decode(bytes[8..312].try_into().expect("ucontext bytes")),
            siginfo: bytes[312..440].try_into().expect("siginfo bytes"),
        }
    }
}

/// Guest addresses selected for an `rt_sigframe` and its aligned XSAVE image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalFrameLayout {
    pub frame_address: u64,
    pub xsave_address: u64,
}

impl SignalFrameLayout {
    pub fn below(stack_top: u64, reserve_red_zone: bool) -> Result<Self, SignalFrameError> {
        let ceiling = stack_top
            .checked_sub(if reserve_red_zone { SIGNAL_RED_ZONE } else { 0 })
            .ok_or(SignalFrameError::AddressOverflow)?;
        // Linux discards the interrupted stack's red-zone reservation when it
        // switches to a fresh alternate stack, but reserves it for an ordinary
        // or nested signal frame. Pack the XSAVE image from the actual ceiling
        // so an exactly-sized alternate stack is not rejected by padding that
        // the ABI does not require.
        let xsave_address = align_down(
            ceiling
                .checked_sub(XSAVE_SIGNAL_SIZE as u64)
                .ok_or(SignalFrameError::AddressOverflow)?,
            XSAVE_ALIGNMENT,
        );
        // Linux x86-64 get_sigframe rounds the end of the rt_sigframe down
        // to a 16-byte boundary and then subtracts 8. With an XSAVE address
        // aligned to 64 bytes and a 440-byte rt_sigframe, that is 16 bytes
        // below the first 8-mod-16 address at or below the XSAVE prefix end.
        let frame_address = align_down(
            xsave_address
                .checked_sub(RT_SIGFRAME_SIZE as u64)
                .ok_or(SignalFrameError::AddressOverflow)?,
            SIGNAL_STACK_ALIGNMENT,
        )
        .checked_sub(8)
        .ok_or(SignalFrameError::AddressOverflow)?;
        Ok(Self {
            frame_address,
            xsave_address,
        })
    }

    /// Whether the frame lies on an alternate stack whose base is
    /// `lower_bound`. Linux's get_sigframe refuses a frame on, or switched
    /// to, the alternate stack unless `__on_sig_stack` holds for it, which
    /// for a stack that grows down means strictly above the base: the stack
    /// is (base, base + size]
    /// (<https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/signal.c#L150-L158>,
    /// <https://github.com/gregkh/linux/blob/v7.1.3/include/linux/sched/signal.h#L574-L583>).
    pub fn fits_above(self, lower_bound: u64) -> bool {
        self.frame_address > lower_bound
    }
}

/// The MXCSR_MASK field of this CPU's FXSAVE image, read once. Linux's initial
/// FPU state carries it (`setup_init_fpu_buf` takes the legacy area from an
/// FXSAVE), XSAVE writes it into every signal frame, and a KVM guest's own
/// FXSAVE reports it too.
fn hardware_mxcsr_mask() -> u32 {
    static MASK: OnceLock<u32> = OnceLock::new();
    *MASK.get_or_init(|| {
        #[repr(C, align(16))]
        struct FxsaveArea([u8; LEGACY_FPSTATE_SIZE]);
        let mut area = FxsaveArea([0; LEGACY_FPSTATE_SIZE]);
        // SAFETY: FXSAVE writes exactly this 512-byte, 16-byte-aligned area,
        // and FXSR is part of the x86-64 baseline.
        unsafe { std::arch::x86_64::_fxsave64(area.0.as_mut_ptr()) };
        read_u32(&area.0, MXCSR_MASK_OFFSET)
    })
}

/// The MXCSR bits a signal frame may set: Linux's `mxcsr_feature_mask`, the
/// hardware mask, which includes DAZ wherever the CPU supports it.
fn mxcsr_feature_mask() -> u32 {
    match hardware_mxcsr_mask() {
        0 => DEFAULT_MXCSR_FEATURE_MASK,
        mask => mask,
    }
}

/// Fixed x87/SSE/YMM signal-frame representation of KVM's XSAVE state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XsaveImage([u8; XSAVE_SIGNAL_SIZE]);

impl XsaveImage {
    /// The signal-frame image of `xsave`. Its XSTATE_BV marks x87 and SSE
    /// state present even when the vCPU had them in their initial state, as
    /// Linux's `save_xstate_epilog` does, so that rt_sigreturn applies a
    /// handler's edits to the saved control word, MXCSR or XMM registers.
    pub fn from_kvm(xsave: &kvm_xsave, compacted: bool) -> Self {
        let mut bytes = [0; XSAVE_SIGNAL_SIZE];
        for (index, word) in xsave.region[..XSAVE_SIZE / 4].iter().copied().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let xstate_bv = read_u64(&bytes, XSTATE_BV_OFFSET);
        // On a host whose vCPU state is saved in compacted form (XSAVEC or
        // XSAVES, CPUID 0xD.1), a component in its initial state was not
        // written to the save area, so KVM_GET_XSAVE's standard-format
        // image can hold stale bytes for it. The sharp case is MXCSR: the
        // kernel's conversion copies it when SSE or YMM is in use, but the
        // compacted save skipped the legacy region while SSE was initial,
        // so with YMM in use and SSE initial the copied MXCSR is stale. A
        // component the header reports initial is in architectural initial
        // state by definition; write those values instead, preserving
        // MXCSR only where SSE is in use, and the MXCSR mask, which is not
        // state. On a host without compacted saves the standard-format
        // image's legacy region always holds the guest's real values, so
        // nothing is rewritten there.
        if compacted {
            let mxcsr = read_u32(&bytes, 24);
            let mxcsr_mask = read_u32(&bytes, MXCSR_MASK_OFFSET);
            if xstate_bv & XFEATURE_X87 == 0 {
                bytes[..XMM_OFFSET].fill(0);
                write_u32(&mut bytes, 0, 0x37f);
                if xstate_bv & XFEATURE_SSE != 0 {
                    write_u32(&mut bytes, 24, mxcsr);
                }
                write_u32(&mut bytes, MXCSR_MASK_OFFSET, mxcsr_mask);
            }
            if xstate_bv & XFEATURE_SSE == 0 {
                bytes[XMM_OFFSET..XMM_END].fill(0);
                write_u32(&mut bytes, 24, 0x1f80);
                write_u32(&mut bytes, MXCSR_MASK_OFFSET, mxcsr_mask);
            }
            if xstate_bv & XFEATURE_YMM == 0 {
                bytes[XSTATE_RESERVED_END..XSAVE_SIZE].fill(0);
            }
        }
        write_u64(
            &mut bytes,
            XSTATE_BV_OFFSET,
            xstate_bv | XFEATURE_X87 | XFEATURE_SSE,
        );

        write_u32(&mut bytes, FP_SW_RESERVED_OFFSET, FP_XSTATE_MAGIC1);
        write_u32(
            &mut bytes,
            FP_SW_RESERVED_OFFSET + 4,
            XSAVE_SIGNAL_SIZE as u32,
        );
        write_u64(&mut bytes, FP_SW_RESERVED_OFFSET + 8, FIXED_XFEATURES);
        write_u32(&mut bytes, FP_SW_RESERVED_OFFSET + 16, XSAVE_SIZE as u32);
        bytes[FP_SW_RESERVED_OFFSET + 20..512].fill(0);
        bytes[XSTATE_RESERVED_OFFSET..XSTATE_RESERVED_END].fill(0);
        write_u32(&mut bytes, XSAVE_SIZE, FP_XSTATE_MAGIC2);
        Self(bytes)
    }

    /// Linux's initial user FPU state, which `fpu__clear_user_states`
    /// installs for a signal handler and for an rt_sigreturn whose
    /// uc_mcontext.fpregs is NULL: x87 control word 0x37f, an empty x87
    /// stack, MXCSR 0x1f80, and zero x87, XMM and YMM registers, with the
    /// CPU's MXCSR_MASK, which KVM then reports in the next signal frame.
    ///
    /// XSTATE_BV marks x87 and SSE state present with these values and leaves
    /// YMM state initial, as the next frame Linux builds says: its header
    /// marks x87 and SSE present (`save_xstate_epilog`) and YMM only once
    /// used. KVM_SET_XSAVE copies a component only when its bit is set, and
    /// copies MXCSR with any of x87, SSE or YMM (`copy_uabi_to_xstate`); the
    /// vCPU initializes a component whose bit is clear. With x87 and SSE
    /// clear too, the vCPU's previous MXCSR would stay in place, and a host
    /// that keeps guest state in the standard (uncompacted) format, one with
    /// neither XSAVEC nor XSAVES, would restore it: the standard form of
    /// XRSTOR loads MXCSR whenever SSE or AVX state is requested, whatever
    /// XSTATE_BV says (Intel SDM Vol. 1, Section 13.8.1).
    pub fn initialized_kvm() -> kvm_xsave {
        let mut xsave = kvm_xsave::default();
        xsave.region[0] = 0x037f;
        xsave.region[6] = 0x1f80;
        xsave.region[MXCSR_MASK_OFFSET / 4] = hardware_mxcsr_mask();
        xsave.region[XSTATE_BV_OFFSET / 4] = (XFEATURE_X87 | XFEATURE_SSE) as u32;
        xsave
    }

    /// Returns the signal-frame FP image size advertised by its 512-byte
    /// legacy prefix. A zero magic word is Linux's accepted legacy FXSAVE form.
    pub fn restore_size(prefix: &[u8; LEGACY_FPSTATE_SIZE]) -> Result<usize, SignalFrameError> {
        match read_u32(prefix, FP_SW_RESERVED_OFFSET) {
            0 => Ok(LEGACY_FPSTATE_SIZE),
            FP_XSTATE_MAGIC1 => {
                let extended_size = read_u32(prefix, FP_SW_RESERVED_OFFSET + 4) as usize;
                let xstate_size = read_u32(prefix, FP_SW_RESERVED_OFFSET + 16) as usize;
                if extended_size != xstate_size.saturating_add(4)
                    || !(XSTATE_RESERVED_END..=XSAVE_SIZE).contains(&xstate_size)
                    || extended_size > XSAVE_SIGNAL_SIZE
                {
                    return Err(SignalFrameError::InvalidXsaveMetadata);
                }
                Ok(extended_size)
            }
            _ => Err(SignalFrameError::InvalidXsaveMetadata),
        }
    }

    /// Restores a signal frame's FP state as Linux's 64-bit rt_sigreturn
    /// does: a bounded standard-format XSAVE image containing a supported
    /// x87/SSE/YMM feature subset, or a legacy FXSAVE image, which Linux also
    /// restores for an XSAVE frame without FP_XSTATE_MAGIC2 after its
    /// xstate_size bytes (`check_xstate_in_sigframe`).
    ///
    /// For an XSAVE image Linux runs the standard form of XRSTOR with the
    /// frame's software xfeatures as the requested features, and then
    /// initializes the guest's other features (`__restore_fpregs_from_user`).
    /// XRSTOR faults on an XSTATE_BV bit outside the guest's XCR0 and on
    /// nonzero header bytes 8 to 23 (XCOMP_BV and the eight after it); it
    /// loads each requested component that XSTATE_BV marks present and
    /// initializes the other requested ones, whatever XSTATE_BV says about
    /// the rest; and it loads MXCSR, faulting on a bit outside the CPU's
    /// MXCSR_MASK (DAZ is inside it wherever the CPU has DAZ), whenever SSE or
    /// YMM state is requested, also when XSTATE_BV leaves SSE initial (Intel
    /// SDM Vol. 1, 13.8.1). Initializing SSE state afterwards sets MXCSR to
    /// 0x1f80. The frame's MXCSR_MASK field is not state: XRSTOR ignores it,
    /// and the CPU writes its own mask into the next frame.
    ///
    /// Some frames Linux accepts are refused
    /// (<https://github.com/rrnewton/reverie/issues/1191>): those whose
    /// metadata [`Self::restore_size`] refuses, and those with nonzero header
    /// bytes 24 to 63, software xfeatures outside XCR0, or YMM requested in
    /// fewer than 832 bytes.
    pub fn restore_from_signal(bytes: &[u8]) -> Result<kvm_xsave, SignalFrameError> {
        if bytes.len() < LEGACY_FPSTATE_SIZE {
            return Err(SignalFrameError::InvalidXsaveMetadata);
        }
        let expected = Self::restore_size(
            bytes[..LEGACY_FPSTATE_SIZE]
                .try_into()
                .expect("checked legacy FP prefix"),
        )?;
        if bytes.len() != expected {
            return Err(SignalFrameError::InvalidXsaveMetadata);
        }
        let xstate_size = expected - 4;
        if expected == LEGACY_FPSTATE_SIZE || read_u32(bytes, xstate_size) != FP_XSTATE_MAGIC2 {
            return Self::restore_legacy(&bytes[..LEGACY_FPSTATE_SIZE]);
        }

        let xfeatures = read_u64(bytes, FP_SW_RESERVED_OFFSET + 8);
        if xfeatures & !FIXED_XFEATURES != 0
            || xfeatures & XFEATURE_YMM != 0 && xstate_size < XSAVE_SIZE
        {
            return Err(SignalFrameError::InvalidXsaveFeatures);
        }
        let xstate_bv = read_u64(bytes, XSTATE_BV_OFFSET);
        if xstate_bv & !FIXED_XFEATURES != 0 {
            return Err(SignalFrameError::InvalidXsaveFeatures);
        }
        if read_u64(bytes, XCOMP_BV_OFFSET) != 0
            || bytes[XSTATE_RESERVED_OFFSET..XSTATE_RESERVED_END]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(SignalFrameError::InvalidXsaveReserved);
        }
        if xfeatures & (XFEATURE_SSE | XFEATURE_YMM) != 0
            && read_u32(bytes, 24) & !mxcsr_feature_mask() != 0
        {
            return Err(SignalFrameError::InvalidMxcsr);
        }
        let mut xsave = Self::initialized_kvm();
        for (index, chunk) in bytes[..xstate_size].as_chunks::<4>().0.iter().enumerate() {
            xsave.region[index] = u32::from_le_bytes(*chunk);
        }
        xsave.region[FP_SW_RESERVED_OFFSET / 4..LEGACY_FPSTATE_SIZE / 4].fill(0);
        // Only the requested components can come from the frame. Without
        // SSE among them, Linux initializes SSE state after the XRSTOR; with
        // SSE initial in XSTATE_BV, XRSTOR zeroes the XMM registers but loads
        // MXCSR from the frame. KVM_SET_XSAVE leaves a component whose bit is
        // clear to be initialized, which is right for the others, but copies
        // MXCSR only with one of x87, SSE or YMM present, so mark SSE present
        // with those values.
        let present = xstate_bv & xfeatures;
        if present & XFEATURE_SSE == 0 {
            xsave.region[XMM_OFFSET / 4..XMM_END / 4].fill(0);
        }
        if xfeatures & XFEATURE_SSE == 0 {
            xsave.region[6] = 0x1f80;
        }
        xsave.region[XSTATE_BV_OFFSET / 4] = (present | XFEATURE_SSE) as u32;
        xsave.region[MXCSR_MASK_OFFSET / 4] = hardware_mxcsr_mask();
        Ok(xsave)
    }

    /// Linux's legacy restore: FXRSTOR of the 512-byte image, which loads x87
    /// and SSE state and faults on an MXCSR bit outside the CPU's mask, and
    /// then the initialization of YMM state.
    fn restore_legacy(bytes: &[u8]) -> Result<kvm_xsave, SignalFrameError> {
        if read_u32(bytes, 24) & !mxcsr_feature_mask() != 0 {
            return Err(SignalFrameError::InvalidMxcsr);
        }
        let mut xsave = Self::initialized_kvm();
        for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
            xsave.region[index] = u32::from_le_bytes(*chunk);
        }
        xsave.region[FP_SW_RESERVED_OFFSET / 4..LEGACY_FPSTATE_SIZE / 4].fill(0);
        xsave.region[XSTATE_BV_OFFSET / 4] = (XFEATURE_X87 | XFEATURE_SSE) as u32;
        xsave.region[MXCSR_MASK_OFFSET / 4] = hardware_mxcsr_mask();
        Ok(xsave)
    }

    #[cfg(test)]
    pub fn decode(bytes: [u8; XSAVE_SIGNAL_SIZE]) -> Result<Self, SignalFrameError> {
        if read_u32(&bytes, FP_SW_RESERVED_OFFSET) != FP_XSTATE_MAGIC1
            || read_u32(&bytes, FP_SW_RESERVED_OFFSET + 4) != XSAVE_SIGNAL_SIZE as u32
            || read_u64(&bytes, FP_SW_RESERVED_OFFSET + 8) != FIXED_XFEATURES
            || read_u32(&bytes, FP_SW_RESERVED_OFFSET + 16) != XSAVE_SIZE as u32
            || read_u32(&bytes, XSAVE_SIZE) != FP_XSTATE_MAGIC2
        {
            return Err(SignalFrameError::InvalidXsaveMetadata);
        }
        if bytes[FP_SW_RESERVED_OFFSET + 20..512]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(SignalFrameError::InvalidXsaveReserved);
        }
        let xstate_bv = read_u64(&bytes, XSTATE_BV_OFFSET);
        if xstate_bv & !FIXED_XFEATURES != 0 {
            return Err(SignalFrameError::InvalidXsaveFeatures);
        }
        if read_u64(&bytes, XCOMP_BV_OFFSET) != 0
            || bytes[XSTATE_RESERVED_OFFSET..XSTATE_RESERVED_END]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(SignalFrameError::InvalidXsaveReserved);
        }
        if read_u32(&bytes, 24) & !mxcsr_feature_mask() != 0 {
            return Err(SignalFrameError::InvalidMxcsr);
        }
        Ok(Self(bytes))
    }

    pub const fn bytes(&self) -> &[u8; XSAVE_SIGNAL_SIZE] {
        &self.0
    }

    #[cfg(test)]
    pub fn to_kvm(&self) -> Result<kvm_xsave, SignalFrameError> {
        Self::decode(self.0)?;
        let mut bytes = self.0;
        bytes[FP_SW_RESERVED_OFFSET..512].fill(0);
        let mut xsave = kvm_xsave::default();
        for (index, chunk) in bytes[..XSAVE_SIZE].as_chunks::<4>().0.iter().enumerate() {
            xsave.region[index] = u32::from_le_bytes(*chunk);
        }
        Ok(xsave)
    }
}

pub fn signal_info_user(signal: i32, pid: i32, uid: u32, code: i32) -> [u8; SIGINFO_SIZE] {
    let mut info = [0; SIGINFO_SIZE];
    write_i32(&mut info, 0, signal);
    write_i32(&mut info, 8, code);
    write_i32(&mut info, 16, pid);
    write_u32(&mut info, 20, uid);
    info
}

fn is_canonical_user_address(address: u64) -> bool {
    address < (1_u64 << 47)
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 bytes"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 bytes"))
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("i32 bytes"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 bytes"))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_sigaction_codec_pins_every_field_offset() {
        let mut mask = KernelSigset::default();
        mask.insert(libc::SIGUSR1);
        mask.insert(libc::SIGUSR2);
        let action = KernelSigaction {
            handler: 0x1111_2222_3333_4444,
            flags: 0x5555_6666_7777_8888,
            restorer: 0x9999_aaaa_bbbb_cccc,
            mask,
        };
        let bytes = action.encode();

        assert_eq!(read_u64(&bytes, 0), action.handler);
        assert_eq!(read_u64(&bytes, 8), action.flags);
        assert_eq!(read_u64(&bytes, 16), action.restorer);
        assert_eq!(&bytes[24..32], &mask.to_bytes());
        assert_eq!(KernelSigaction::decode(bytes), action);
    }

    #[test]
    fn signal_context_and_frame_offsets_round_trip() {
        let mut context = Sigcontext {
            r8: 0x08,
            rdi: 0x10,
            rsp: 0x1234_5000,
            rip: 0x2345_6000,
            rflags: 0x202,
            cs: USER_CODE_SELECTOR,
            ss: USER_DATA_SELECTOR,
            fpstate: 0x3456_7000,
            ..Default::default()
        };
        context.reserved[7] = 0xfeed_face;
        let context_bytes = context.encode();
        assert_eq!(read_u64(&context_bytes, 0), context.r8);
        assert_eq!(read_u64(&context_bytes, 64), context.rdi);
        assert_eq!(read_u64(&context_bytes, 120), context.rsp);
        assert_eq!(read_u64(&context_bytes, 128), context.rip);
        assert_eq!(read_u16(&context_bytes, 144), USER_CODE_SELECTOR);
        assert_eq!(read_u16(&context_bytes, 150), USER_DATA_SELECTOR);
        assert_eq!(read_u64(&context_bytes, 184), context.fpstate);
        assert_eq!(read_u64(&context_bytes, 248), 0xfeed_face);
        assert_eq!(Sigcontext::decode(context_bytes), context);

        let mut mask = KernelSigset::default();
        mask.insert(libc::SIGUSR1);
        let ucontext = Ucontext {
            flags: SIGNAL_UCONTEXT_FLAGS,
            link: 0,
            stack: GuestStack {
                sp: 0x4000,
                flags: libc::SS_ONSTACK,
                size: 0x2000,
            },
            mcontext: context,
            sigmask: mask,
        };
        let mut info = [0; SIGINFO_SIZE];
        info[0..4].copy_from_slice(&libc::SIGUSR1.to_le_bytes());
        info[127] = 0xa5;
        let frame = RtSigframe {
            pretcode: 0x4567_8000,
            ucontext,
            siginfo: info,
        };
        let bytes = frame.encode();
        assert_eq!(read_u64(&bytes, 0), frame.pretcode);
        assert_eq!(read_u64(&bytes, 8), SIGNAL_UCONTEXT_FLAGS);
        assert_eq!(read_u64(&bytes, 8 + 40 + 128), context.rip);
        assert_eq!(&bytes[8 + 296..8 + 304], &mask.to_bytes());
        assert_eq!(&bytes[312..440], &info);
        assert_eq!(RtSigframe::decode(bytes), frame);
    }

    #[test]
    fn frame_layout_reserves_red_zone_and_aligns_both_abis() {
        let stack_top = 0x7fff_ffff_f000;
        let layout = SignalFrameLayout::below(stack_top, true).unwrap();
        assert_eq!(layout.frame_address % SIGNAL_STACK_ALIGNMENT, 8);
        assert_eq!(layout.xsave_address % XSAVE_ALIGNMENT, 0);
        assert!(layout.xsave_address >= layout.frame_address + RT_SIGFRAME_SIZE as u64);
        assert!(layout.xsave_address + XSAVE_SIGNAL_SIZE as u64 <= stack_top - SIGNAL_RED_ZONE);

        let fresh = SignalFrameLayout::below(stack_top, false).unwrap();
        assert!(fresh.frame_address > layout.frame_address);
        assert!(
            fresh.xsave_address + XSAVE_SIGNAL_SIZE as u64 > stack_top - SIGNAL_RED_ZONE,
            "an aligned fresh altstack uses its top without an invented red zone",
        );
        assert!(fresh.xsave_address + XSAVE_SIGNAL_SIZE as u64 <= stack_top);

        // Linux's __on_sig_stack puts a stack's base outside it: a frame fits
        // on an alternate stack only strictly above its base, so the lowest
        // base that holds the frame is one byte below it.
        let lowest_base = fresh.frame_address - 1;
        assert!(fresh.fits_above(lowest_base));
        assert!(
            !fresh.fits_above(fresh.frame_address),
            "a frame that starts exactly at the alternate stack's base is off the stack",
        );
        assert!(
            !fresh.fits_above(fresh.frame_address + 1),
            "one-byte alternate-stack underflow must be rejected even when adjacent memory is mapped",
        );
        let nested = SignalFrameLayout::below(stack_top, true).unwrap();
        assert!(nested.frame_address < fresh.frame_address);
        assert!(nested.fits_above(nested.frame_address - 1));
        assert!(!nested.fits_above(nested.frame_address));
        assert!(!nested.fits_above(nested.frame_address + 1));
    }

    #[test]
    fn frame_layout_uses_linux_get_sigframe_placement_at_altstack_boundary() {
        // Seat boundary case (dh-nx4otc): alternate-stack base 0x10000 and
        // nested stack pointer 0x10590. Linux x86-64 get_sigframe places
        // the rt_sigframe at round_down(xsave_address - 440, 16) - 8, not
        // at the first 8-mod-16 address at or below xsave_address - 440.
        let layout = SignalFrameLayout::below(0x1_0590, true).unwrap();
        assert_eq!(layout.xsave_address, 0x1_01c0);
        assert_eq!(layout.frame_address, 0xfff8);
        assert_eq!(
            layout.xsave_address - (layout.frame_address + RT_SIGFRAME_SIZE as u64),
            16,
        );
        assert!(
            !layout.fits_above(0x1_0000),
            "Linux placement puts this boundary frame below the alternate stack base",
        );
    }

    #[test]
    fn rt_sigreturn_fpstate_accepts_legacy_and_bounded_feature_subsets() {
        let mut legacy = [0u8; LEGACY_FPSTATE_SIZE];
        write_u32(&mut legacy, 0, 0x077f);
        write_u32(&mut legacy, 24, 0x1f80);
        legacy[FP_SW_RESERVED_OFFSET + 4..].fill(0xa5);
        assert_eq!(read_u32(&legacy, FP_SW_RESERVED_OFFSET), 0);
        assert_eq!(XsaveImage::restore_size(&legacy), Ok(LEGACY_FPSTATE_SIZE));
        let restored = XsaveImage::restore_from_signal(&legacy).unwrap();
        assert_eq!(restored.region[0], 0x077f);
        assert_eq!(restored.region[6], 0x1f80);
        assert!(
            restored.region[FP_SW_RESERVED_OFFSET / 4..LEGACY_FPSTATE_SIZE / 4]
                .iter()
                .all(|word| *word == 0),
        );
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4] as u64,
            XFEATURE_X87 | XFEATURE_SSE,
        );

        let full = valid_xsave_bytes();
        let subset_size = XSTATE_RESERVED_END;
        let mut subset = full[..subset_size + 4].to_vec();
        write_u32(
            &mut subset,
            FP_SW_RESERVED_OFFSET + 4,
            (subset_size + 4) as u32,
        );
        write_u64(
            &mut subset,
            FP_SW_RESERVED_OFFSET + 8,
            XFEATURE_X87 | XFEATURE_SSE,
        );
        write_u32(&mut subset, FP_SW_RESERVED_OFFSET + 16, subset_size as u32);
        write_u64(&mut subset, XSTATE_BV_OFFSET, XFEATURE_X87 | XFEATURE_SSE);
        write_u32(&mut subset, subset_size, FP_XSTATE_MAGIC2);
        let restored = XsaveImage::restore_from_signal(&subset).unwrap();
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4] as u64,
            XFEATURE_X87 | XFEATURE_SSE,
        );

        let mut oversized = full;
        write_u32(
            &mut oversized,
            FP_SW_RESERVED_OFFSET + 4,
            (XSAVE_SIGNAL_SIZE + 4) as u32,
        );
        let prefix = oversized[..LEGACY_FPSTATE_SIZE].try_into().unwrap();
        assert_eq!(
            XsaveImage::restore_size(&prefix),
            Err(SignalFrameError::InvalidXsaveMetadata),
        );
    }

    fn valid_xsave_bytes() -> [u8; XSAVE_SIGNAL_SIZE] {
        let mut raw = kvm_xsave::default();
        raw.region[0] = 0x37f;
        raw.region[6] = 0x0000_1f80;
        raw.region[32] = 0x1111_2222;
        raw.region[144] = 0x3333_4444;
        raw.region[XSTATE_BV_OFFSET / 4] = FIXED_XFEATURES as u32;
        *XsaveImage::from_kvm(&raw, true).bytes()
    }

    #[test]
    fn xsave_codec_round_trips_x87_sse_and_ymm_without_4096_byte_copy() {
        let bytes = valid_xsave_bytes();
        assert_eq!(bytes.len(), XSAVE_SIGNAL_SIZE);
        assert_eq!(read_u32(&bytes, 0), 0x37f);
        assert_eq!(read_u32(&bytes, 128), 0x1111_2222);
        assert_eq!(read_u32(&bytes, 576), 0x3333_4444);
        assert_eq!(read_u32(&bytes, FP_SW_RESERVED_OFFSET), FP_XSTATE_MAGIC1);
        assert_eq!(read_u32(&bytes, XSAVE_SIZE), FP_XSTATE_MAGIC2);

        let decoded = XsaveImage::decode(bytes).unwrap();
        let restored = decoded.to_kvm().unwrap();
        assert_eq!(restored.region[0], 0x37f);
        assert_eq!(restored.region[32], 0x1111_2222);
        assert_eq!(restored.region[144], 0x3333_4444);
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4],
            FIXED_XFEATURES as u32
        );
        assert!(
            restored.region[XSAVE_SIZE / 4..]
                .iter()
                .all(|word| *word == 0)
        );
    }

    #[test]
    fn signal_frames_mark_x87_and_sse_present_as_linux_does() {
        // KVM reports components in their initial state as absent; the frame
        // marks x87 and SSE present anyway, so rt_sigreturn applies a
        // handler's edits to them.
        for (reported, framed) in [
            (0, XFEATURE_X87 | XFEATURE_SSE),
            (XFEATURE_YMM, FIXED_XFEATURES),
            (FIXED_XFEATURES, FIXED_XFEATURES),
        ] {
            let mut raw = kvm_xsave::default();
            raw.region[XSTATE_BV_OFFSET / 4] = reported as u32;
            let bytes = *XsaveImage::from_kvm(&raw, true).bytes();
            assert_eq!(read_u64(&bytes, XSTATE_BV_OFFSET), framed, "{reported:#x}");
            let restored = XsaveImage::restore_from_signal(&bytes).unwrap();
            assert_eq!(restored.region[XSTATE_BV_OFFSET / 4] as u64, framed);
        }
    }

    #[test]
    fn signal_frames_initialize_components_the_vcpu_reports_initial() {
        // KVM_GET_XSAVE can leave the save area of a component in its
        // initial state holding stale bytes from before it was initialized
        // (measured for MXCSR on AMD Zen 5 in the signal spike for
        // https://github.com/rrnewton/hermit/issues/5476: the guest's
        // plain XSAVE read MXCSR 0x1f80 while the signal frame
        // built from the same stopped vCPU carried the stale 0x3f80). Linux
        // writes architectural initial values for those components, so the
        // frame must not copy those bytes through.
        let mut raw = kvm_xsave::default();
        raw.region[0] = 0xdead_beef;
        raw.region[6] = 0x0000_3f80;
        raw.region[XMM_OFFSET / 4] = 0x1111_2222;
        raw.region[XSTATE_RESERVED_END / 4] = 0x3333_4444;
        raw.region[XSTATE_BV_OFFSET / 4] = 0;
        let bytes = *XsaveImage::from_kvm(&raw, true).bytes();
        assert_eq!(read_u32(&bytes, 0), 0x37f, "x87 control word");
        assert_eq!(read_u32(&bytes, 24), 0x1f80, "MXCSR");
        assert_eq!(read_u32(&bytes, XMM_OFFSET), 0, "XMM0");
        assert_eq!(read_u32(&bytes, XSTATE_RESERVED_END), 0, "YMM upper");
        assert_eq!(
            read_u64(&bytes, XSTATE_BV_OFFSET),
            XFEATURE_X87 | XFEATURE_SSE
        );

        // With SSE present its MXCSR and XMM state are the frame's, while
        // x87 and YMM still initialize.
        raw.region[XSTATE_BV_OFFSET / 4] = XFEATURE_SSE as u32;
        let bytes = *XsaveImage::from_kvm(&raw, true).bytes();
        assert_eq!(read_u32(&bytes, 0), 0x37f, "x87 control word");
        assert_eq!(read_u32(&bytes, 24), 0x3f80, "MXCSR");
        assert_eq!(read_u32(&bytes, XMM_OFFSET), 0x1111_2222, "XMM0");
        assert_eq!(read_u32(&bytes, XSTATE_RESERVED_END), 0, "YMM upper");

        // The stale-MXCSR trigger itself: YMM in use with SSE initial. The
        // kernel's KVM_GET_XSAVE conversion copies MXCSR when SSE or YMM
        // is in use, but a compacted save skipped the legacy region while
        // SSE was initial, so the stale 0x3f80 must not reach the frame.
        for bv in [XFEATURE_YMM, XFEATURE_X87 | XFEATURE_YMM] {
            raw.region[XSTATE_BV_OFFSET / 4] = bv as u32;
            let bytes = *XsaveImage::from_kvm(&raw, true).bytes();
            assert_eq!(read_u32(&bytes, 24), 0x1f80, "MXCSR bv={bv:#x}");
            assert_eq!(read_u32(&bytes, XMM_OFFSET), 0, "XMM0 bv={bv:#x}");
            assert_eq!(
                read_u32(&bytes, XSTATE_RESERVED_END),
                0x3333_4444,
                "YMM upper bv={bv:#x}"
            );
        }

        // Without compacted saves the standard-format image always wrote
        // the legacy region, so its MXCSR is the guest's real value and
        // passes through even with SSE initial.
        raw.region[XSTATE_BV_OFFSET / 4] = XFEATURE_YMM as u32;
        let bytes = *XsaveImage::from_kvm(&raw, false).bytes();
        assert_eq!(
            read_u32(&bytes, 24),
            0x3f80,
            "MXCSR without compacted saves"
        );
    }

    #[test]
    fn rt_sigreturn_takes_mxcsr_from_a_frame_whose_sse_state_is_initial() {
        // XSTATE_BV without SSE: the XMM registers return to zero, and MXCSR
        // comes from the frame, as the standard form of XRSTOR loads it.
        let mut bytes = valid_xsave_bytes();
        write_u32(&mut bytes, 24, 0x5f80);
        write_u32(&mut bytes, XMM_OFFSET + 5 * 16, 0x5555_5555);
        for header in [0, XFEATURE_X87, XFEATURE_YMM] {
            write_u64(&mut bytes, XSTATE_BV_OFFSET, header);
            let restored = XsaveImage::restore_from_signal(&bytes).unwrap();
            assert_eq!(restored.region[6], 0x5f80, "{header:#x}");
            assert!(
                restored.region[XMM_OFFSET / 4..XMM_END / 4]
                    .iter()
                    .all(|word| *word == 0),
                "{header:#x}"
            );
            assert_eq!(
                restored.region[XSTATE_BV_OFFSET / 4] as u64,
                header | XFEATURE_SSE
            );
        }
        // A frame whose features leave SSE out gets SSE's initial MXCSR, as
        // Linux initializes those features after the XRSTOR.
        let mut x87_only = bytes[..XSTATE_RESERVED_END + 4].to_vec();
        write_u32(
            &mut x87_only,
            FP_SW_RESERVED_OFFSET + 4,
            (XSTATE_RESERVED_END + 4) as u32,
        );
        write_u64(&mut x87_only, FP_SW_RESERVED_OFFSET + 8, XFEATURE_X87);
        write_u32(
            &mut x87_only,
            FP_SW_RESERVED_OFFSET + 16,
            XSTATE_RESERVED_END as u32,
        );
        write_u64(&mut x87_only, XSTATE_BV_OFFSET, XFEATURE_X87);
        write_u32(&mut x87_only, XSTATE_RESERVED_END, FP_XSTATE_MAGIC2);
        let restored = XsaveImage::restore_from_signal(&x87_only).unwrap();
        assert_eq!(restored.region[6], 0x1f80);
    }

    #[test]
    fn rt_sigreturn_accepts_the_cpus_mxcsr_bits_and_reports_its_mask() {
        let mask = hardware_mxcsr_mask();
        let mut bytes = valid_xsave_bytes();
        // DAZ (bit 6), which -ffast-math sets at startup, wherever the CPU
        // has it; a bit outside the CPU's mask is refused, as XRSTOR faults.
        write_u32(&mut bytes, 24, 0x1fc0);
        write_u32(&mut bytes, MXCSR_MASK_OFFSET, 0xffbf);
        let restored = XsaveImage::restore_from_signal(&bytes);
        if mask & 0x40 != 0 {
            let restored = restored.unwrap();
            assert_eq!(restored.region[6], 0x1fc0);
            assert_eq!(restored.region[MXCSR_MASK_OFFSET / 4], mask);
        } else {
            assert_eq!(restored.err(), Some(SignalFrameError::InvalidMxcsr));
        }
        write_u32(&mut bytes, 24, 0x1f80 | 1 << 31);
        assert_eq!(
            XsaveImage::restore_from_signal(&bytes).err(),
            Some(SignalFrameError::InvalidMxcsr)
        );
        assert_eq!(
            XsaveImage::initialized_kvm().region[MXCSR_MASK_OFFSET / 4],
            mask
        );
    }

    #[test]
    fn the_initial_image_leaves_ymm_state_initial() {
        // After fpu__clear_user_states, Linux's next frame marks x87 and SSE
        // present and YMM absent; KVM reports the image's XSTATE_BV in the
        // frame of a signal delivered before the guest runs again.
        let image = XsaveImage::initialized_kvm();
        assert_eq!(
            image.region[XSTATE_BV_OFFSET / 4] as u64
                | (image.region[XSTATE_BV_OFFSET / 4 + 1] as u64) << 32,
            XFEATURE_X87 | XFEATURE_SSE
        );
        assert_eq!((image.region[0], image.region[6]), (0x037f, 0x1f80));
        let bytes = *XsaveImage::from_kvm(&image, true).bytes();
        assert_eq!(
            read_u64(&bytes, XSTATE_BV_OFFSET),
            XFEATURE_X87 | XFEATURE_SSE
        );
    }

    /// [`valid_xsave_bytes`] with software xfeatures `features`, XSTATE_BV
    /// `header`, MXCSR `mxcsr` and a nonzero XMM5.
    fn xsave_frame(features: u64, header: u64, mxcsr: u32) -> [u8; XSAVE_SIGNAL_SIZE] {
        let mut bytes = valid_xsave_bytes();
        write_u64(&mut bytes, FP_SW_RESERVED_OFFSET + 8, features);
        write_u64(&mut bytes, XSTATE_BV_OFFSET, header);
        write_u32(&mut bytes, 24, mxcsr);
        write_u32(&mut bytes, XMM_OFFSET + 5 * 16, 0x5555_5555);
        bytes
    }

    fn xmm_registers_are_zero(xsave: &kvm_xsave) -> bool {
        xsave.region[XMM_OFFSET / 4..XMM_END / 4]
            .iter()
            .all(|word| *word == 0)
    }

    #[test]
    fn rt_sigreturn_checks_mxcsr_only_where_linux_loads_it() {
        for reserved in [1 << 16, 1 << 31] {
            let mxcsr = 0x1f80 | reserved;
            // XRSTOR loads MXCSR only when the frame's features request SSE
            // or YMM state. Without SSE among them, Linux then initializes
            // SSE state: MXCSR 0x1f80 and zero XMM registers.
            for features in [XFEATURE_X87, 0] {
                let context = format!("features {features:#x}, MXCSR {mxcsr:#x}");
                let restored =
                    XsaveImage::restore_from_signal(&xsave_frame(features, features, mxcsr))
                        .expect(&context);
                assert_eq!(restored.region[6], 0x1f80, "{context}");
                assert!(xmm_registers_are_zero(&restored), "{context}");
                assert_eq!(
                    restored.region[XSTATE_BV_OFFSET / 4] as u64,
                    features | XFEATURE_SSE,
                    "{context}"
                );
            }
            for features in [XFEATURE_X87 | XFEATURE_YMM, XFEATURE_SSE, FIXED_XFEATURES] {
                assert_eq!(
                    XsaveImage::restore_from_signal(&xsave_frame(features, features, mxcsr)).err(),
                    Some(SignalFrameError::InvalidMxcsr),
                    "features {features:#x}, MXCSR {mxcsr:#x}"
                );
            }
            // FXRSTOR always loads it.
            let mut legacy = [0u8; LEGACY_FPSTATE_SIZE];
            write_u32(&mut legacy, 24, mxcsr);
            assert_eq!(
                XsaveImage::restore_from_signal(&legacy).err(),
                Some(SignalFrameError::InvalidMxcsr),
                "legacy, MXCSR {mxcsr:#x}"
            );
        }
    }

    #[test]
    fn rt_sigreturn_initializes_components_outside_the_frames_features() {
        // An XSTATE_BV bit within XCR0 that the frame's features leave out is
        // ignored by XRSTOR, and Linux initializes that component afterwards.
        let restored = XsaveImage::restore_from_signal(&xsave_frame(
            XFEATURE_X87 | XFEATURE_SSE,
            FIXED_XFEATURES,
            0x5f80,
        ))
        .unwrap();
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4] as u64,
            XFEATURE_X87 | XFEATURE_SSE
        );
        assert_eq!(restored.region[6], 0x5f80);
        assert_eq!(restored.region[(XMM_OFFSET + 5 * 16) / 4], 0x5555_5555);
        let restored =
            XsaveImage::restore_from_signal(&xsave_frame(XFEATURE_X87, FIXED_XFEATURES, 0x5f80))
                .unwrap();
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4] as u64,
            XFEATURE_X87 | XFEATURE_SSE
        );
        assert_eq!(restored.region[6], 0x1f80);
        assert!(xmm_registers_are_zero(&restored));
        // A bit outside XCR0 makes XRSTOR fault.
        assert_eq!(
            XsaveImage::restore_from_signal(&xsave_frame(
                FIXED_XFEATURES,
                FIXED_XFEATURES | 1 << 3,
                0x1f80
            ))
            .err(),
            Some(SignalFrameError::InvalidXsaveFeatures)
        );
    }

    #[test]
    fn rt_sigreturn_restores_a_frame_without_magic2_as_legacy_state() {
        // check_xstate_in_sigframe: without FP_XSTATE_MAGIC2 after the frame's
        // xstate_size bytes, Linux restores the legacy image with FXRSTOR,
        // which loads x87 and SSE state and MXCSR, and initializes YMM state.
        let mut bytes = xsave_frame(FIXED_XFEATURES, FIXED_XFEATURES, 0x5f80);
        write_u32(&mut bytes, XSAVE_SIZE, 0);
        let restored = XsaveImage::restore_from_signal(&bytes).unwrap();
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4] as u64,
            XFEATURE_X87 | XFEATURE_SSE
        );
        assert_eq!((restored.region[0], restored.region[6]), (0x37f, 0x5f80));
        assert_eq!(restored.region[(XMM_OFFSET + 5 * 16) / 4], 0x5555_5555);
        assert!(
            restored.region[XSTATE_RESERVED_END / 4..XSAVE_SIZE / 4]
                .iter()
                .all(|word| *word == 0)
        );
        write_u32(&mut bytes, 24, 0x1f80 | 1 << 31);
        assert_eq!(
            XsaveImage::restore_from_signal(&bytes).err(),
            Some(SignalFrameError::InvalidMxcsr)
        );
    }

    #[test]
    fn rt_sigreturn_ignores_the_software_reserved_padding() {
        // Linux reads magic1, extended_size, xfeatures and xstate_size from
        // the software-reserved bytes and nothing after them.
        let mut bytes = valid_xsave_bytes();
        bytes[FP_SW_RESERVED_OFFSET + 20..LEGACY_FPSTATE_SIZE].fill(0xa5);
        let restored = XsaveImage::restore_from_signal(&bytes).unwrap();
        assert_eq!(
            restored.region[XSTATE_BV_OFFSET / 4] as u64,
            FIXED_XFEATURES
        );
        assert!(
            restored.region[FP_SW_RESERVED_OFFSET / 4..LEGACY_FPSTATE_SIZE / 4]
                .iter()
                .all(|word| *word == 0)
        );
    }

    #[test]
    fn xsave_decoder_rejects_each_corrupted_control_field() {
        let valid = valid_xsave_bytes();
        let mutations: &[(usize, u8, SignalFrameError)] = &[
            (
                FP_SW_RESERVED_OFFSET,
                0,
                SignalFrameError::InvalidXsaveMetadata,
            ),
            (
                FP_SW_RESERVED_OFFSET + 4,
                0,
                SignalFrameError::InvalidXsaveMetadata,
            ),
            (
                FP_SW_RESERVED_OFFSET + 8,
                0,
                SignalFrameError::InvalidXsaveMetadata,
            ),
            (
                FP_SW_RESERVED_OFFSET + 16,
                0,
                SignalFrameError::InvalidXsaveMetadata,
            ),
            (
                FP_SW_RESERVED_OFFSET + 20,
                1,
                SignalFrameError::InvalidXsaveReserved,
            ),
            (
                XSTATE_BV_OFFSET + 1,
                0x80,
                SignalFrameError::InvalidXsaveFeatures,
            ),
            (XCOMP_BV_OFFSET, 1, SignalFrameError::InvalidXsaveReserved),
            (
                XSTATE_RESERVED_OFFSET,
                1,
                SignalFrameError::InvalidXsaveReserved,
            ),
            (27, 0x80, SignalFrameError::InvalidMxcsr),
            (XSAVE_SIZE, 0, SignalFrameError::InvalidXsaveMetadata),
        ];

        for &(offset, value, expected) in mutations {
            let mut changed = valid;
            changed[offset] = value;
            assert_eq!(
                XsaveImage::decode(changed),
                Err(expected),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn sigcontext_restore_validates_selectors_and_addresses_before_fp_decode() {
        let valid = Sigcontext {
            rsp: 0x7fff_0000,
            rip: 0x400000,
            rflags: 0x202,
            cs: USER_CODE_SELECTOR,
            ss: USER_DATA_SELECTOR,
            fpstate: 0x7ffe_f000,
            ..Default::default()
        };
        assert_eq!(valid.validate_for_restore(), Ok(()));
        assert_eq!(
            Sigcontext {
                fpstate: 0,
                ..valid
            }
            .validate_for_restore(),
            Ok(())
        );

        let mut changed = valid;
        changed.cs = 0;
        assert_eq!(
            changed.validate_for_restore(),
            Err(SignalFrameError::InvalidSelectors)
        );
        changed = valid;
        changed.rip = u64::MAX;
        assert_eq!(
            changed.validate_for_restore(),
            Err(SignalFrameError::InvalidAddress)
        );
        changed = valid;
        changed.fpstate += 1;
        assert_eq!(changed.validate_for_restore(), Ok(()));
        assert!(!changed.fpstate.is_multiple_of(XSAVE_ALIGNMENT));
    }

    #[test]
    fn sigcontext_restore_accepts_captured_sysret_stack_selector() {
        let context = Sigcontext {
            rsp: 0x7fff_0000,
            rip: 0x400000,
            rflags: 0x10202,
            cs: USER_CODE_SELECTOR,
            ss: USER_DATA_SELECTOR & !3,
            ..Default::default()
        };
        assert_eq!(context.validate_for_restore(), Ok(()));
        for selector in [0, 0x10, 0x19, 0x1a, 0x20, 0x2b] {
            assert_eq!(
                Sigcontext {
                    ss: selector,
                    ..context
                }
                .validate_for_restore(),
                Err(SignalFrameError::InvalidSelectors)
            );
        }
    }

    #[test]
    fn sigcontext_restore_changes_only_linux_fix_eflags_bits() {
        const IOPL: u64 = 3 << 12;
        const ID: u64 = 1 << 21;
        const IF: u64 = 1 << 9;
        const RESERVED_ONE: u64 = 1 << 1;
        const CF: u64 = 1 << 0;
        const DF: u64 = 1 << 10;

        let context = Sigcontext {
            rflags: IOPL | CF | DF,
            ..Default::default()
        };
        let mut registers = kvm_regs {
            rflags: RESERVED_ONE | IF | ID,
            ..Default::default()
        };
        context.restore_kvm(&mut registers);
        assert_eq!(registers.rflags, RESERVED_ONE | IF | ID | CF | DF);
        assert_eq!(registers.rflags & IOPL, 0, "frame must not grant IOPL");
    }

    fn c_abi_source(name: &str) -> std::path::PathBuf {
        // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the fbsource
        // BUCK rule set. The compile-time value is a relative fbsource
        // path in buck builds and resolves only from an fbcode cwd
        // so also walk the cwd and exe ancestors through
        // the known layouts. A candidate wins only when the fixture
        // file itself exists; partial absence keeps failing loudly at
        // the compile below.
        let file = format!("signal_abi_{name}.c");
        let layouts = [
            "",
            "fbcode/hermetic_infra/reverie/reverie-signal",
            "hermetic_infra/reverie/reverie-signal",
            "reverie/reverie-signal",
            "reverie-signal",
        ];
        let mut starts: Vec<std::path::PathBuf> = Vec::new();
        if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
            starts.push(std::path::PathBuf::from(dir));
        }
        starts.push(std::path::PathBuf::from(
            option_env!("CARGO_MANIFEST_DIR").unwrap_or("reverie-signal"),
        ));
        if let Ok(cwd) = std::env::current_dir() {
            starts.extend(cwd.ancestors().map(|path| path.to_path_buf()));
        }
        if let Ok(exe) = std::env::current_exe() {
            starts.extend(exe.ancestors().map(|path| path.to_path_buf()));
        }
        for start in &starts {
            for layout in layouts {
                let candidate = start.join(layout).join("tests/fixtures").join(&file);
                if candidate.exists() {
                    return candidate;
                }
            }
        }
        starts[0].join("tests/fixtures").join(file)
    }

    fn run_c_abi_probe(name: &str) -> BTreeMap<String, usize> {
        let source = c_abi_source(name);
        let binary =
            std::env::temp_dir().join(format!("reverie-signal-abi-{name}-{}", std::process::id()));
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let compile = std::process::Command::new(compiler)
            .args(["-std=c11", "-Wall", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .expect("launch C compiler for signal ABI probe");
        assert!(
            compile.status.success(),
            "C signal ABI probe did not compile:\n{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let output = std::process::Command::new(&binary)
            .output()
            .expect("run compiled signal ABI probe");
        let _ = std::fs::remove_file(&binary);
        assert!(
            output.status.success(),
            "C signal ABI probe exited with {}",
            output.status
        );
        String::from_utf8(output.stdout)
            .expect("C signal ABI probe emitted UTF-8")
            .lines()
            .map(|line| {
                let (key, value) = line.split_once('=').expect("key=value ABI probe line");
                (
                    key.to_owned(),
                    value.parse::<usize>().expect("numeric ABI probe value"),
                )
            })
            .collect()
    }

    #[test]
    fn kernel_headers_independently_pin_signal_frame_layout() {
        let kernel = run_c_abi_probe("kernel");
        assert_eq!(kernel["kernel_sigset_size"], KERNEL_SIGSET_SIZE);
        assert_eq!(kernel["stack_size"], GuestStack::SIZE);
        assert_eq!(kernel["sigcontext_size"], SIGCONTEXT_SIZE);
        assert_eq!(kernel["sigcontext_r8"], 0);
        assert_eq!(kernel["sigcontext_rdi"], 64);
        assert_eq!(kernel["sigcontext_rsp"], 120);
        assert_eq!(kernel["sigcontext_rip"], 128);
        assert_eq!(kernel["sigcontext_eflags"], 136);
        assert_eq!(kernel["sigcontext_cs"], 144);
        assert_eq!(kernel["sigcontext_ss"], 150);
        assert_eq!(kernel["sigcontext_fpstate"], 184);
        assert_eq!(kernel["sigcontext_reserved1"], 192);
        assert_eq!(kernel["ucontext_size"], UCONTEXT_SIZE);
        assert_eq!(kernel["ucontext_stack"], 16);
        assert_eq!(kernel["ucontext_mcontext"], 40);
        assert_eq!(kernel["ucontext_sigmask"], 296);
        assert_eq!(kernel["rt_sigframe_size"], RT_SIGFRAME_SIZE);
        assert_eq!(kernel["rt_sigframe_ucontext"], 8);
        assert_eq!(kernel["rt_sigframe_siginfo"], 312);
        assert_eq!(kernel["xstate_size"], XSAVE_SIZE);
        assert_eq!(kernel["xstate_sw_reserved"], FP_SW_RESERVED_OFFSET);
        assert_eq!(kernel["xstate_header"], XSTATE_BV_OFFSET);
        assert_eq!(kernel["xstate_ymmh"], 576);

        let libc = run_c_abi_probe("libc");
        assert_eq!(libc["libc_ucontext_sigmask"], 296);
        assert!(libc["libc_ucontext_size"] > UCONTEXT_SIZE);
        assert!(libc["libc_sigset_size"] > KERNEL_SIGSET_SIZE);
        assert_eq!(
            KERNEL_SIGSET_SIZE, 8,
            "rt_sig* syscalls use the kernel mask"
        );
    }
}
