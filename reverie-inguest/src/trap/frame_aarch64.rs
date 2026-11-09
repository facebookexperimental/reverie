/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Scoped access to genuine Linux aarch64 signal frames.
//!
//! The kernel `sigcontext` is fault_address, x0-x30, sp, pc, pstate, then
//! a 4096-byte `__reserved` area holding magic-headed records (FPSIMD,
//! SVE, ESR, ... terminated by a zero header, with at most one
//! extra_context chain leaving the reserved area). The offsets and the
//! `svc` return-site relations used here are pinned by the maintained
//! trap probe's hardware measurements. Capture copies the in-reserved
//! chain verbatim and refuses frames whose records leave it, rather
//! than truncate state the kernel would read back at `rt_sigreturn`.

use core::marker::PhantomData;
use std::io;

/// `AUDIT_ARCH_AARCH64` the SIGSYS provenance check requires.
const AUDIT_ARCH: u32 = 0xc000_00b7;
/// Offset of `__reserved` inside `sigcontext` (probe-measured).
const RESERVED_OFFSET: usize = 288;
const RESERVED_BYTES: usize = 4096;
const EXTRA_MAGIC: u32 = 0x4558_5401;
const SVE_MAGIC: u32 = 0x5356_4501;
const ZA_MAGIC: u32 = 0x5436_6345;
/// SVE_SIG_FLAG_SM: the SVE record describes streaming-mode state, a
/// different vector domain from the non-streaming one at the same VL.
const SVE_SIG_FLAG_SM: u16 = 0x1;
/// Architectural registers this frame addresses: x0-x30, then sp, pc,
/// pstate, in sigcontext order.
const REGISTERS: usize = 34;
const REG_SP: usize = 31;
pub(crate) const REG_PC: usize = 32;
const REG_PSTATE: usize = 33;

/// A malformed or incompatible architectural signal-frame image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameError;

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid signal-frame state")
    }
}

impl std::error::Error for FrameError {}

/// No CPU-described layout needs discovering on this architecture: the
/// sigcontext layout and the reserved area size are UAPI constants.
pub fn initialize() -> io::Result<()> {
    Ok(())
}

/// Result of validating one frame's reserved record chain.
#[derive(Clone, Copy)]
struct ReservedChain {
    /// Bytes from the first record through the terminator, inclusive.
    used: usize,
    /// Whether an extra_context record points outside the reserved area.
    has_extra: bool,
    /// The SVE vector length recorded in the frame, when an SVE record
    /// is present. Admission is a fixed-VL envelope: restore refuses a
    /// mismatch instead of copying state across a VL change.
    sve_vl: Option<u16>,
    /// Whether the SVE record describes streaming-mode state.
    sve_streaming: bool,
    /// The SME ZA vector length, when a ZA record is present. Linux
    /// requires it to match the task SME VL independently of SVE.
    za_vl: Option<u16>,
}

/// Walk the `_aarch64_ctx` record chain in `__reserved`, requiring every
/// record to lie inside the area and a zero terminator to be present.
/// Unknown magics are tolerated (capture copies records verbatim); only
/// their sizes must be sane.
///
/// # Safety
/// `reserved` must point at a genuine frame's 4096-byte reserved area.
unsafe fn validate_reserved(reserved: *const u8) -> Result<ReservedChain, FrameError> {
    let mut offset = 0usize;
    let mut has_extra = false;
    let mut sve_vl = None;
    let mut sve_streaming = false;
    let mut za_vl = None;
    loop {
        if offset + 8 > RESERVED_BYTES {
            return Err(FrameError);
        }
        // SAFETY: bounds just checked against the reserved area.
        let (magic, size) = unsafe {
            (
                reserved.add(offset).cast::<u32>().read_unaligned(),
                reserved.add(offset + 4).cast::<u32>().read_unaligned() as usize,
            )
        };
        if magic == 0 && size == 0 {
            return Ok(ReservedChain {
                used: offset + 8,
                has_extra,
                sve_vl,
                sve_streaming,
                za_vl,
            });
        }
        if size < 16 || size % 8 != 0 || offset + size > RESERVED_BYTES {
            return Err(FrameError);
        }
        if magic == SVE_MAGIC {
            if sve_vl.is_some() {
                return Err(FrameError);
            }
            // SAFETY: an SVE record body starts with its vl/flags words.
            let (vl, flags) = unsafe {
                (
                    reserved.add(offset + 8).cast::<u16>().read_unaligned(),
                    reserved.add(offset + 10).cast::<u16>().read_unaligned(),
                )
            };
            sve_vl = Some(vl);
            sve_streaming = flags & SVE_SIG_FLAG_SM != 0;
        }
        if magic == ZA_MAGIC {
            if za_vl.is_some() || size < 16 {
                return Err(FrameError);
            }
            // SAFETY: a ZA record body starts with its vl word.
            za_vl = Some(unsafe { reserved.add(offset + 8).cast::<u16>().read_unaligned() });
        }
        if magic == EXTRA_MAGIC {
            if size < 32 {
                return Err(FrameError);
            }
            // SAFETY: the extra_context body lies within the checked size.
            let datap = unsafe { reserved.add(offset + 8).cast::<u64>().read_unaligned() };
            if datap != 0 {
                has_extra = true;
            }
        }
        offset += size;
    }
}

#[repr(C, align(16))]
#[derive(Clone)]
struct Block([u8; 64]);

/// An owned architectural image, allocated before signal handling begins.
/// It contains no pointer or borrow into the original kernel signal frame.
pub struct SavedState {
    /// x0-x30 in sigcontext order.
    pub registers: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    storage: Box<[Block]>,
    reserved_used: usize,
    sve_vl: Option<u16>,
    sve_streaming: bool,
    za_vl: Option<u16>,
}

impl SavedState {
    /// Allocate the fixed reserved-area capacity in ordinary context.
    pub fn new() -> io::Result<Self> {
        let count = RESERVED_BYTES / 64;
        let mut storage = Vec::new();
        storage.try_reserve_exact(count).map_err(io::Error::other)?;
        storage.resize(count, Block([0; 64]));
        Ok(Self {
            registers: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            storage: storage.into_boxed_slice(),
            reserved_used: 0,
            sve_vl: None,
            sve_streaming: false,
            za_vl: None,
        })
    }

    /// This implementation saves no protection-key rights yet; the
    /// POE record is copied verbatim with the rest of the chain, and
    /// permission observation is its own stage.
    pub fn pkru(&self) -> Option<u32> {
        None
    }

    pub fn set_pkru(&mut self, value: Option<u32>) -> Result<(), FrameError> {
        match value {
            None => Ok(()),
            Some(_) => Err(FrameError),
        }
    }
}

/// Exclusive access to one genuine kernel frame, valid only during its
/// handler.
pub struct SignalFrame<'signal> {
    context: *mut u8,
    chain: ReservedChain,
    _borrow: PhantomData<&'signal mut ()>,
}

impl<'signal> SignalFrame<'signal> {
    fn mcontext(&self) -> *mut u8 {
        // SAFETY: context is a genuine ucontext from from_kernel_frame;
        // uc_mcontext's offset comes from the libc type shared with the
        // kernel's userspace layout.
        unsafe {
            self.context
                .add(core::mem::offset_of!(libc::ucontext_t, uc_mcontext))
        }
    }

    fn reserved(&self) -> *mut u8 {
        // SAFETY: see mcontext; RESERVED_OFFSET is the UAPI layout.
        unsafe { self.mcontext().add(RESERVED_OFFSET) }
    }

    /// # Safety
    /// The pointers must come directly from this invocation's
    /// kernel-created aarch64 SA_SIGINFO frame. No other references may
    /// alias the context while the returned frame is alive.
    pub(super) unsafe fn from_raw(
        context: *mut libc::c_void,
        info: *const libc::siginfo_t,
    ) -> Result<Self, FrameError> {
        let frame = unsafe { Self::from_kernel_frame(context)? };
        // siginfo's SIGSYS union follows its 16-byte fixed header on every
        // architecture using the asm-generic layout.
        // SAFETY: info is the kernel's siginfo for this delivery.
        let (call, number, arch) = unsafe {
            (
                info.cast::<u8>().add(16).cast::<u64>().read_unaligned(),
                info.cast::<u8>().add(24).cast::<i32>().read_unaligned(),
                info.cast::<u8>().add(28).cast::<u32>().read_unaligned(),
            )
        };
        if arch != AUDIT_ARCH
            || call != frame.register(REG_PC) as u64
            || number != frame.register(8) as i32
        {
            return Err(FrameError);
        }
        Ok(frame)
    }

    /// Borrow the frame of a kernel-forced `SIGSEGV` (`SI_KERNEL` only,
    /// mirroring the x86-64 provenance rule).
    ///
    /// # Safety
    /// As [`Self::from_raw`].
    pub unsafe fn from_instruction_fault(
        context: *mut libc::c_void,
        info: *const libc::siginfo_t,
    ) -> Result<Self, FrameError> {
        if info.is_null() {
            return Err(FrameError);
        }
        // SAFETY: the caller upholds the from_raw contract for info.
        let (signal, code) = unsafe { ((*info).si_signo, (*info).si_code) };
        if signal != libc::SIGSEGV || code != libc::SI_KERNEL {
            return Err(FrameError);
        }
        unsafe { Self::from_kernel_frame(context) }
    }

    unsafe fn from_kernel_frame(context: *mut libc::c_void) -> Result<Self, FrameError> {
        let address = context as usize;
        if address & 7 != 0 {
            return Err(FrameError);
        }
        let context = context.cast::<u8>();
        // SAFETY: caller guarantees a genuine kernel frame at context.
        let chain = unsafe {
            validate_reserved(
                context
                    .add(core::mem::offset_of!(libc::ucontext_t, uc_mcontext))
                    .add(RESERVED_OFFSET),
            )?
        };
        Ok(Self {
            context,
            chain,
            _borrow: PhantomData,
        })
    }

    fn register_ptr(&self, index: usize) -> *mut u64 {
        assert!(index < REGISTERS);
        // sigcontext: fault_address(0), regs[31] at 8, sp 256, pc 264,
        // pstate 272 — the four tail fields are contiguous words.
        let offset = if index < 31 {
            8 + index * 8
        } else {
            256 + (index - 31) * 8
        };
        // SAFETY: mcontext is the genuine frame's sigcontext.
        unsafe { self.mcontext().add(offset).cast::<u64>() }
    }

    /// Read an architectural register by sigcontext order: 0-30 are
    /// x0-x30, then sp (31), pc (32), pstate (33).
    pub fn register(&self, index: usize) -> i64 {
        // SAFETY: register_ptr bounds the index to the sigcontext words.
        unsafe { self.register_ptr(index).read_unaligned() as i64 }
    }

    /// Write an architectural register; kernel-owned mask/stack metadata
    /// is untouched (see the dedicated accessors).
    pub fn set_register(&mut self, index: usize, value: i64) {
        // SAFETY: register_ptr bounds the index to the sigcontext words.
        unsafe { self.register_ptr(index).write_unaligned(value as u64) };
    }

    fn sigmask_word(&self) -> *mut u64 {
        // SAFETY: uc_sigmask offset comes from the shared libc layout.
        unsafe {
            self.context
                .add(core::mem::offset_of!(libc::ucontext_t, uc_sigmask))
                .cast::<u64>()
        }
    }

    /// The frame's `uc_sigmask` first word: the mask Linux installs when
    /// the frame returns.
    pub fn signal_mask(&self) -> u64 {
        // SAFETY: sigmask_word points at the frame's mask word.
        unsafe { self.sigmask_word().read_unaligned() }
    }

    pub fn set_signal_mask(&mut self, mask: u64) {
        // SAFETY: sigmask_word points at the frame's mask word.
        unsafe { self.sigmask_word().write_unaligned(mask) };
    }

    /// The frame's `uc_stack`, as the kernel wrote it.
    pub fn signal_stack(&self) -> [u8; 24] {
        // SAFETY: uc_stack offset comes from the shared libc layout.
        unsafe {
            self.context
                .add(core::mem::offset_of!(libc::ucontext_t, uc_stack))
                .cast::<[u8; 24]>()
                .read_unaligned()
        }
    }

    /// This implementation observes no protection-key rights yet
    /// (the POE record, when present, is preserved verbatim by capture).
    pub fn pkru(&self) -> Result<Option<u32>, FrameError> {
        Ok(None)
    }

    pub fn set_pkru(&mut self, value: Option<u32>) -> Result<(), FrameError> {
        match value {
            None => Ok(()),
            Some(_) => Err(FrameError),
        }
    }

    /// Capture into preallocated owned storage. No frame pointer escapes.
    /// Refuses frames whose records leave the reserved area (an
    /// extra_context chain), rather than capture a prefix the kernel
    /// would read past at `rt_sigreturn`.
    pub fn capture(&self, saved: &mut SavedState) -> Result<(), FrameError> {
        if self.chain.has_extra {
            return Err(FrameError);
        }
        for index in 0..31 {
            saved.registers[index] = self.register(index) as u64;
        }
        saved.sp = self.register(REG_SP) as u64;
        saved.pc = self.register(REG_PC) as u64;
        saved.pstate = self.register(REG_PSTATE) as u64;
        // SAFETY: both ranges are the validated reserved area and the
        // owned storage of exactly RESERVED_BYTES, used <= that.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.reserved(),
                saved.storage.as_mut_ptr().cast::<u8>(),
                self.chain.used,
            )
        };
        saved.reserved_used = self.chain.used;
        saved.sve_vl = self.chain.sve_vl;
        saved.sve_streaming = self.chain.sve_streaming;
        saved.za_vl = self.chain.za_vl;
        Ok(())
    }

    /// Install owned state into this fresh frame, retaining its Linux
    /// metadata (mask, stack, links) exactly as the kernel wrote them.
    pub fn restore(&mut self, saved: &SavedState) -> Result<(), FrameError> {
        if saved.reserved_used == 0 || saved.reserved_used > RESERVED_BYTES {
            return Err(FrameError);
        }
        if self.chain.has_extra {
            return Err(FrameError);
        }
        // Fixed-VL admission envelope: never copy SVE state into a frame
        // whose task runs at a different vector length (the fresh frame's
        // own SVE header names the current VL). A saved frame with no SVE
        // record restores as FPSIMD state, which the kernel defines for
        // any current VL.
        match (saved.sve_vl, self.chain.sve_vl) {
            (Some(saved_vl), Some(current_vl)) if saved_vl == current_vl => {}
            (None, _) => {}
            _ => return Err(FrameError),
        }
        // Every copied VL domain is authenticated before the first write:
        // streaming mode is a separate domain at the same SVE VL, and ZA
        // has its own SME VL that Linux requires to match the task's.
        if saved.sve_vl.is_some()
            && self.chain.sve_vl.is_some()
            && saved.sve_streaming != self.chain.sve_streaming
        {
            return Err(FrameError);
        }
        match (saved.za_vl, self.chain.za_vl) {
            (Some(saved_za), Some(current_za)) if saved_za == current_za => {}
            (None, None) => {}
            _ => return Err(FrameError),
        }
        // SAFETY: reserved areas on both sides are RESERVED_BYTES; the
        // captured chain (terminator included) replaces this frame's.
        unsafe {
            core::ptr::copy_nonoverlapping(
                saved.storage.as_ptr().cast::<u8>(),
                self.reserved(),
                saved.reserved_used,
            )
        };
        // Bytes past the captured terminator are never read by the
        // kernel; re-validate so this frame's chain view stays exact.
        // SAFETY: self.reserved() is this frame's reserved area.
        self.chain = unsafe { validate_reserved(self.reserved())? };
        for (index, value) in saved.registers.iter().copied().enumerate() {
            self.set_register(index, value as i64);
        }
        self.set_register(REG_SP, saved.sp as i64);
        self.set_register(REG_PC, saved.pc as i64);
        self.set_register(REG_PSTATE, saved.pstate as i64);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_bytes(records: &[(u32, u32)]) -> [u8; RESERVED_BYTES] {
        let mut bytes = [0u8; RESERVED_BYTES];
        let mut offset = 0;
        for (magic, size) in records {
            if offset + 8 > RESERVED_BYTES {
                break;
            }
            bytes[offset..offset + 4].copy_from_slice(&magic.to_ne_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&size.to_ne_bytes());
            offset += *size as usize;
        }
        bytes
    }

    #[test]
    fn reserved_chain_validation_accepts_only_terminated_in_bands() {
        // FPSIMD (528) + header-only SVE (16) + terminator: the metal shape.
        let bytes = chain_bytes(&[(0x4650_8001, 528), (0x5356_4501, 16), (0, 0)]);
        let chain = unsafe { validate_reserved(bytes.as_ptr()) }.unwrap();
        assert_eq!(chain.used, 528 + 16 + 8);
        assert!(!chain.has_extra);
        // No terminator within the area (tail filled with a nonzero
        // pattern, since zero fill would itself read as a terminator).
        let mut bytes = chain_bytes(&[(0x4650_8001, 528)]);
        bytes[528..].fill(0xa5);
        assert!(unsafe { validate_reserved(bytes.as_ptr()) }.is_err());
        // Record running past the area, unaligned size, undersized record.
        for bad in [(0x4650_8001, 8192), (0x4650_8001, 20), (0x4650_8001, 8)] {
            let bytes = chain_bytes(&[bad, (0, 0)]);
            assert!(
                unsafe { validate_reserved(bytes.as_ptr()) }.is_err(),
                "{bad:?}"
            );
        }
    }

    fn synthetic_frame(sve_vl: Option<u16>) -> (Box<libc::ucontext_t>, SignalFrame<'static>) {
        let mut uc = Box::new(unsafe { core::mem::zeroed::<libc::ucontext_t>() });
        let records: &[(u32, u32)] = match sve_vl {
            Some(_) => &[(0x4650_8001, 528), (SVE_MAGIC, 16), (0, 0)],
            None => &[(0x4650_8001, 528), (0, 0)],
        };
        let bytes = chain_bytes(records);
        // SAFETY: the box outlives the frame in these tests by construction.
        let reserved = unsafe {
            core::ptr::addr_of_mut!(uc.uc_mcontext)
                .cast::<u8>()
                .add(RESERVED_OFFSET)
        };
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), reserved, RESERVED_BYTES) };
        if let Some(vl) = sve_vl {
            // SVE record follows the 528-byte FPSIMD record; vl at +8.
            unsafe { reserved.add(528 + 8).cast::<u16>().write_unaligned(vl) };
        }
        let chain = unsafe { validate_reserved(reserved) }.unwrap();
        let frame = SignalFrame {
            context: core::ptr::addr_of_mut!(*uc).cast::<u8>(),
            chain,
            _borrow: PhantomData,
        };
        (uc, frame)
    }

    fn synthetic_frame_za(
        sve_vl: u16,
        za_vl: u16,
    ) -> (Box<libc::ucontext_t>, SignalFrame<'static>) {
        let mut uc = Box::new(unsafe { core::mem::zeroed::<libc::ucontext_t>() });
        let mut bytes = chain_bytes(&[(SVE_MAGIC, 16), (0x5436_6345, 16), (0, 0)]);
        bytes[8..10].copy_from_slice(&sve_vl.to_ne_bytes());
        bytes[16 + 8..16 + 10].copy_from_slice(&za_vl.to_ne_bytes());
        let reserved = unsafe {
            core::ptr::addr_of_mut!(uc.uc_mcontext)
                .cast::<u8>()
                .add(RESERVED_OFFSET)
        };
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), reserved, RESERVED_BYTES) };
        let chain = unsafe { validate_reserved(reserved) }.unwrap();
        let frame = SignalFrame {
            context: core::ptr::addr_of_mut!(*uc).cast::<u8>(),
            chain,
            _borrow: PhantomData,
        };
        (uc, frame)
    }

    #[test]
    fn restore_refuses_za_vl_mismatch_with_equal_sve_vl() {
        // Astra witness shape: SVE VL16 on both sides, ZA VL32 into ZA
        // VL16 must refuse, never copy across.
        let (_uc_a, frame_a) = synthetic_frame_za(16, 32);
        let mut saved = SavedState::new().unwrap();
        frame_a.capture(&mut saved).unwrap();
        let (_uc_b, mut frame_b) = synthetic_frame_za(16, 16);
        assert!(frame_b.restore(&saved).is_err());
    }

    #[test]
    fn restore_refuses_sve_vl_mismatch_and_accepts_equal_or_absent() {
        let (_uc_a, frame_a) = synthetic_frame(Some(32));
        let mut saved = SavedState::new().unwrap();
        frame_a.capture(&mut saved).unwrap();
        assert_eq!(saved.sve_vl, Some(32));
        // Different current VL: refuse, never copy across the change.
        let (_uc_b, mut frame_b) = synthetic_frame(Some(16));
        assert!(frame_b.restore(&saved).is_err());
        // SVE record vanished entirely: also a mismatch.
        let (_uc_c, mut frame_c) = synthetic_frame(None);
        assert!(frame_c.restore(&saved).is_err());
        // Equal VL restores; a saved frame without SVE restores anywhere.
        let (_uc_d, mut frame_d) = synthetic_frame(Some(32));
        frame_d.restore(&saved).unwrap();
        let (_uc_e, frame_e) = synthetic_frame(None);
        let mut saved_plain = SavedState::new().unwrap();
        frame_e.capture(&mut saved_plain).unwrap();
        let (_uc_f, mut frame_f) = synthetic_frame(Some(16));
        frame_f.restore(&saved_plain).unwrap();
    }

    #[test]
    fn extra_context_is_detected_and_capture_refuses_it() {
        let mut bytes = chain_bytes(&[(EXTRA_MAGIC, 32), (0, 0)]);
        bytes[8..16].copy_from_slice(&0x1000u64.to_ne_bytes()); // datap != 0
        let chain = unsafe { validate_reserved(bytes.as_ptr()) }.unwrap();
        assert!(chain.has_extra);
        let frame = SignalFrame {
            context: core::ptr::null_mut(),
            chain,
            _borrow: PhantomData,
        };
        let mut saved = SavedState::new().unwrap();
        assert!(frame.capture(&mut saved).is_err());
    }
}
