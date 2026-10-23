/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Scoped access to genuine Linux x86-64 signal frames.
//!
//! Linux supplies a 304-byte ucontext prefix, not libc's larger userspace
//! ucontext_t. Never borrow that larger object together with its FP storage.

use core::marker::PhantomData;
use std::io;
use std::sync::OnceLock;

const CONTEXT_BYTES: usize = 304;
const GREG_OFFSET: usize = 40;
const FP_POINTER_OFFSET: usize = 224;
const SIGMASK_OFFSET: usize = 296;
const STACK_OFFSET: usize = 16;
const LEGACY_BYTES: usize = 512;
const SW_OFFSET: usize = 464;
const HEADER_OFFSET: usize = 512;
const HEADER_END: usize = 576;
const MAGIC1: u32 = 0x4650_5853;
const MAGIC2: u32 = 0x4650_5845;
const PKRU_BIT: u64 = 1 << 9;

/// A malformed or incompatible architectural signal-frame image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameError;

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid signal-frame state")
    }
}

impl std::error::Error for FrameError {}

#[derive(Clone, Copy, Default)]
struct Component {
    offset: usize,
    size: usize,
}

struct Layout {
    maximum: usize,
    enabled: u64,
    components: [Component; 64],
    pkru: Option<usize>,
}

static LAYOUT: OnceLock<Layout> = OnceLock::new();

/// Prepare all layout information in ordinary context, before CPUID faulting.
pub fn initialize() -> io::Result<()> {
    if LAYOUT.get().is_some() {
        return Ok(());
    }
    let layout = detect()?;
    let _ = LAYOUT.set(layout);
    Ok(())
}

fn detect() -> io::Result<Layout> {
    use core::arch::x86_64::__cpuid;
    use core::arch::x86_64::__cpuid_count;
    use core::arch::x86_64::_xgetbv;
    let invalid = || io::Error::other("invalid signal XSAVE layout");
    let mut layout = Layout {
        maximum: LEGACY_BYTES,
        enabled: 3,
        components: [Component::default(); 64],
        pkru: None,
    };
    let maximum_leaf = __cpuid(0).eax;
    if __cpuid(1).ecx & ((1 << 26) | (1 << 27)) != ((1 << 26) | (1 << 27)) {
        return Ok(layout);
    }
    if maximum_leaf < 0xd {
        return Err(invalid());
    }
    let enabled = unsafe { _xgetbv(0) };
    let area = __cpuid_count(0xd, 0);
    let supported = u64::from(area.eax) | (u64::from(area.edx) << 32);
    if enabled & 3 != 3 || enabled & !supported != 0 || area.ebx < HEADER_END as u32 {
        return Err(invalid());
    }
    layout.maximum = area.ebx as usize;
    layout.enabled = enabled;
    for index in 2..64 {
        if enabled & (1 << index) != 0 {
            let leaf = __cpuid_count(0xd, index as u32);
            let component = Component {
                offset: leaf.ebx as usize,
                size: leaf.eax as usize,
            };
            if leaf.ecx & 1 != 0
                || component.size == 0
                || component.offset < HEADER_END
                || component
                    .offset
                    .checked_add(component.size)
                    .is_none_or(|end| end > layout.maximum)
            {
                return Err(invalid());
            }
            layout.components[index] = component;
        }
    }
    if maximum_leaf >= 7 && __cpuid_count(7, 0).ecx & (1 << 4) != 0 {
        if enabled & PKRU_BIT == 0 || layout.components[9].size != 8 {
            return Err(invalid());
        }
        layout.pkru = Some(layout.components[9].offset);
    }
    Ok(layout)
}

#[derive(Clone, Copy)]
enum FpKind {
    Absent,
    Legacy,
    Xsave {
        bytes: usize,
        features: u64,
        present: u64,
    },
}

#[repr(C, align(64))]
#[derive(Clone)]
struct Block([u8; 64]);

/// An owned architectural image, allocated before signal handling begins.
/// It contains no pointer or borrow into the original kernel signal frame.
pub struct SavedState {
    /// The nineteen architectural gregs through CSGSFS, excluding trap metadata.
    pub registers: [i64; 19],
    storage: Box<[Block]>,
    kind: FpKind,
    pkru: Option<u32>,
    restorer: usize,
}

impl SavedState {
    /// Allocate full CPU-described capacity in ordinary context.
    pub fn new() -> io::Result<Self> {
        initialize()?;
        let layout = LAYOUT
            .get()
            .ok_or_else(|| io::Error::other("missing signal layout"))?;
        let count = layout
            .maximum
            .checked_add(63)
            .ok_or_else(|| io::Error::other("signal image overflow"))?
            / 64;
        let mut storage = Vec::new();
        storage.try_reserve_exact(count).map_err(io::Error::other)?;
        storage.resize(count, Block([0; 64]));
        Ok(Self {
            registers: [0; 19],
            storage: storage.into_boxed_slice(),
            kind: FpKind::Absent,
            pkru: None,
            restorer: 0,
        })
    }

    /// Current guest permissions, distinct from the live runtime's permissions.
    pub fn pkru(&self) -> Option<u32> {
        self.pkru
    }

    /// Retain a typed physical guest effect, including one accompanying errno.
    pub fn set_pkru(&mut self, value: Option<u32>) -> Result<(), FrameError> {
        if self.pkru.is_some() != value.is_some() {
            return Err(FrameError);
        }
        self.pkru = value;
        Ok(())
    }
}

/// Exclusive access to one genuine kernel frame, valid only during its handler.
pub struct SignalFrame<'signal> {
    context: *mut u8,
    fp: *mut u8,
    kind: FpKind,
    layout: &'static Layout,
    _borrow: PhantomData<&'signal mut ()>,
}

impl<'signal> SignalFrame<'signal> {
    /// # Safety
    /// The pointers must come directly from this invocation's kernel-created
    /// x86-64 SA_SIGINFO frame. Runtime memory access must already be enabled.
    /// No other references may alias the context prefix or its FP allocation.
    pub(super) unsafe fn from_raw(
        context: *mut libc::c_void,
        info: *const libc::siginfo_t,
    ) -> Result<Self, FrameError> {
        let frame = unsafe { Self::from_kernel_frame(context, info)? };
        // siginfo's x86-64 SIGSYS union follows its 16-byte fixed header.
        let call = unsafe { info.cast::<u8>().add(16).cast::<u64>().read_unaligned() };
        let number = unsafe { info.cast::<u8>().add(24).cast::<i32>().read_unaligned() };
        let arch = unsafe { info.cast::<u8>().add(28).cast::<u32>().read_unaligned() };
        if arch != 0xc000_003e
            || call != frame.register(libc::REG_RIP as usize) as u64
            || number != frame.register(libc::REG_RAX as usize) as i32
        {
            return Err(FrameError);
        }
        Ok(frame)
    }

    /// Test-only access to the same genuine SIGSYS frame validator.
    /// # Safety
    /// Exactly the from_raw contract: actual kernel-created SA_SIGINFO pointers,
    /// exclusive context/FP access and enabled runtime memory permissions.
    #[cfg(all(test, feature = "exec-native-injection"))]
    pub(crate) unsafe fn native_exec_test_sigsys_frame(
        context: *mut libc::c_void,
        info: *const libc::siginfo_t,
    ) -> Result<Self, FrameError> {
        unsafe { Self::from_raw(context, info) }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(liteinst-late-code-cpuid): Review the kernel-fault frame provenance check.
    /// Borrow the frame of a kernel-forced `SIGSEGV`, such as the general
    /// protection fault that CPUID faulting or `PR_TSC_SIGSEGV` raises.
    ///
    /// Accepts only `si_signo == SIGSEGV` with `si_code == SI_KERNEL`: the
    /// kernel sends that for a #GP raised by an instruction it had already
    /// fetched, and never for a user-sent `kill`/`tgkill`/`sigqueue`, whose
    /// `si_code` is `SI_USER` or negative.
    ///
    /// # Safety
    /// The pointers must come directly from this invocation's kernel-created
    /// x86-64 SA_SIGINFO frame. Runtime memory access must already be enabled.
    /// No other references may alias the context prefix or its FP allocation
    /// while the returned frame is alive.
    pub unsafe fn from_instruction_fault(
        context: *mut libc::c_void,
        info: *const libc::siginfo_t,
    ) -> Result<Self, FrameError> {
        if info.is_null() {
            return Err(FrameError);
        }
        let (signal, code) = unsafe { ((*info).si_signo, (*info).si_code) };
        if signal != libc::SIGSEGV || code != libc::SI_KERNEL {
            return Err(FrameError);
        }
        unsafe { Self::from_kernel_frame(context, info) }
    }

    /// Validate the parts every kernel `rt_sigframe` shares: the ucontext
    /// prefix is immediately followed by siginfo, and the FP image decodes.
    unsafe fn from_kernel_frame(
        context: *mut libc::c_void,
        info: *const libc::siginfo_t,
    ) -> Result<Self, FrameError> {
        let layout = LAYOUT.get().ok_or(FrameError)?;
        let address = context as usize;
        if address < 8
            || address & 7 != 0
            || address.checked_add(CONTEXT_BYTES) != Some(info as usize)
        {
            return Err(FrameError);
        }
        let context = context.cast::<u8>();
        let fp = unsafe {
            context
                .add(FP_POINTER_OFFSET)
                .cast::<*mut u8>()
                .read_unaligned()
        };
        let kind = unsafe { decode_fp(fp, layout)? };
        if !fp.is_null() {
            let bytes = match kind {
                FpKind::Absent => 0,
                FpKind::Legacy => LEGACY_BYTES,
                FpKind::Xsave { bytes, .. } => bytes.checked_add(4).ok_or(FrameError)?,
            };
            let end = (fp as usize).checked_add(bytes).ok_or(FrameError)?;
            // The fixed rt_sigframe extends eight bytes before uc and 128
            // bytes after the prefix. Keep architectural and FP views disjoint.
            let frame_end = address.checked_add(CONTEXT_BYTES + 128).ok_or(FrameError)?;
            if (fp as usize) < frame_end && end > address - 8 {
                return Err(FrameError);
            }
        }
        Ok(Self {
            context,
            fp,
            kind,
            layout,
            _borrow: PhantomData,
        })
    }

    // Additional ownership check for an already genuine parsed frame. This
    // neither accepts synthetic frames nor exports their raw addresses.
    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    pub(crate) fn on_owned_signal_stack(&self, lo: usize, hi: usize, restorer: usize) -> bool {
        let address = self.context as usize;
        if lo >= hi
            || address.checked_sub(8).is_none_or(|start| start < lo)
            || address
                .checked_add(CONTEXT_BYTES + 128)
                .is_none_or(|end| end > hi)
        {
            return false;
        }
        // SAFETY: from_kernel_frame owns this genuine kernel frame prefix.
        if unsafe { self.context.sub(8).cast::<usize>().read_unaligned() } != restorer {
            return false;
        }
        let bytes = match self.kind {
            FpKind::Absent => return true,
            FpKind::Legacy => LEGACY_BYTES,
            FpKind::Xsave { bytes, .. } => match bytes.checked_add(4) {
                Some(bytes) => bytes,
                None => return false,
            },
        };
        let fp = self.fp as usize;
        fp >= lo && fp.checked_add(bytes).is_some_and(|end| end <= hi)
    }

    /// Read an architectural greg, without borrowing libc's oversized context.
    pub fn register(&self, index: usize) -> i64 {
        assert!(index < 19);
        unsafe {
            self.context
                .add(GREG_OFFSET + index * 8)
                .cast::<i64>()
                .read_unaligned()
        }
    }

    /// Write an architectural greg; Linux-owned trap/mask metadata is untouched.
    pub fn set_register(&mut self, index: usize, value: i64) {
        assert!(index < 19);
        unsafe {
            self.context
                .add(GREG_OFFSET + index * 8)
                .cast::<i64>()
                .write_unaligned(value)
        };
    }

    /// Set the frame's `uc_sigmask`: the mask Linux installs when the frame
    /// returns.
    pub fn set_signal_mask(&mut self, mask: u64) {
        unsafe {
            self.context
                .add(SIGMASK_OFFSET)
                .cast::<u64>()
                .write_unaligned(mask)
        };
    }

    /// The frame's `uc_sigmask`.
    pub fn signal_mask(&self) -> u64 {
        unsafe {
            self.context
                .add(SIGMASK_OFFSET)
                .cast::<u64>()
                .read_unaligned()
        }
    }

    /// The frame's `uc_stack`, as the kernel wrote it.
    pub fn signal_stack(&self) -> [u8; 24] {
        unsafe {
            self.context
                .add(STACK_OFFSET)
                .cast::<[u8; 24]>()
                .read_unaligned()
        }
    }

    /// Interrupted rights from the actual frame, including init-state PKRU.
    pub fn pkru(&self) -> Result<Option<u32>, FrameError> {
        let Some(_) = self.layout.pkru else {
            return Ok(None);
        };
        match self.kind {
            // Preserve the existing OSPKE decoder's refusal: a null pointer
            // supplies no authenticated interrupted PKRU value.
            FpKind::Absent => Err(FrameError),
            FpKind::Xsave { features, .. } if features & PKRU_BIT != 0 => unsafe {
                super::pkru::from_signal_frame(self.fp.cast()).map_err(|()| FrameError)
            },
            _ => Err(FrameError),
        }
    }

    /// Update permissions only in this frame, preserving its metadata/padding.
    pub fn set_pkru(&mut self, value: Option<u32>) -> Result<(), FrameError> {
        match (self.layout.pkru, value, self.kind) {
            (None, None, _) => Ok(()),
            (
                Some(offset),
                Some(value),
                FpKind::Xsave {
                    bytes,
                    features,
                    present,
                },
            ) if features & PKRU_BIT != 0 => {
                unsafe {
                    self.fp.add(offset).cast::<u32>().write_unaligned(value);
                    self.fp
                        .add(HEADER_OFFSET)
                        .cast::<u64>()
                        .write_unaligned(present | PKRU_BIT);
                }
                self.kind = FpKind::Xsave {
                    bytes,
                    features,
                    present: present | PKRU_BIT,
                };
                Ok(())
            }
            _ => Err(FrameError),
        }
    }

    /// Capture into preallocated owned storage. No frame pointer escapes.
    pub fn capture(&self, saved: &mut SavedState) -> Result<(), FrameError> {
        for (index, value) in saved.registers.iter_mut().enumerate() {
            *value = self.register(index);
        }
        let bytes = match self.kind {
            FpKind::Absent => 0,
            FpKind::Legacy => LEGACY_BYTES,
            FpKind::Xsave { bytes, .. } => bytes,
        };
        if bytes > saved.storage.len() * 64 {
            return Err(FrameError);
        }
        if bytes != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.fp,
                    saved.storage.as_mut_ptr().cast::<u8>(),
                    bytes,
                )
            };
        }
        saved.kind = self.kind;
        saved.pkru = self.pkru()?;
        saved.restorer = unsafe { self.context.sub(8).cast::<usize>().read_unaligned() };
        Ok(())
    }

    /// Install owned state into this fresh frame, retaining all Linux metadata.
    pub fn restore(&mut self, saved: &SavedState) -> Result<(), FrameError> {
        if unsafe { self.context.sub(8).cast::<usize>().read_unaligned() } != saved.restorer {
            return Err(FrameError);
        }
        let source = saved.storage.as_ptr().cast::<u8>();
        match (saved.kind, self.kind) {
            (FpKind::Absent, FpKind::Absent) => {}
            (FpKind::Absent, _) => {
                // Architectural initial legacy payload; leave all fresh Linux
                // software/reserved bytes alone. Extended init uses BV = 0.
                unsafe {
                    initialize_legacy_payload(self.fp);
                    self.fp.cast::<u16>().write_unaligned(0x037f);
                    self.fp.add(24).cast::<u32>().write_unaligned(0x1f80);
                }
                if let FpKind::Xsave {
                    bytes, features, ..
                } = self.kind
                {
                    unsafe { self.fp.add(HEADER_OFFSET).cast::<u64>().write_unaligned(0) };
                    self.kind = FpKind::Xsave {
                        bytes,
                        features,
                        present: 0,
                    };
                }
            }
            (FpKind::Legacy, FpKind::Legacy) => unsafe {
                copy_legacy_payload(source, self.fp);
            },
            (
                FpKind::Xsave { present, .. },
                FpKind::Xsave {
                    bytes, features, ..
                },
            ) if present & !features == 0 => {
                unsafe { copy_legacy_payload(source, self.fp) };
                for index in 2..64 {
                    // PKRU's upper four bytes are padding, not guest state.
                    // Its actual u32 is installed by set_pkru below.
                    if index != 9 && present & (1 << index) != 0 {
                        let component = self.layout.components[index];
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                source.add(component.offset),
                                self.fp.add(component.offset),
                                component.size,
                            )
                        };
                    }
                }
                unsafe {
                    self.fp
                        .add(HEADER_OFFSET)
                        .cast::<u64>()
                        .write_unaligned(present)
                };
                self.kind = FpKind::Xsave {
                    bytes,
                    features,
                    present,
                };
            }
            _ => return Err(FrameError),
        }
        self.set_pkru(saved.pkru)?;
        for (index, value) in saved.registers.iter().copied().enumerate() {
            self.set_register(index, value);
        }
        Ok(())
    }
}

unsafe fn copy_legacy_payload(source: *const u8, destination: *mut u8) {
    // FXSAVE byte 5, MXCSR_MASK, x87 slot padding and bytes 416..512 are
    // reserved/capability/software data. Keep them from the fresh frame.
    unsafe {
        core::ptr::copy_nonoverlapping(source, destination, 5);
        core::ptr::copy_nonoverlapping(source.add(6), destination.add(6), 22);
        for register in 0..8 {
            let offset = 32 + register * 16;
            core::ptr::copy_nonoverlapping(source.add(offset), destination.add(offset), 10);
        }
        core::ptr::copy_nonoverlapping(source.add(160), destination.add(160), 256);
    }
}

unsafe fn initialize_legacy_payload(destination: *mut u8) {
    // Initial architectural state without stamping over fresh kernel padding.
    unsafe {
        core::ptr::write_bytes(destination, 0, 5);
        core::ptr::write_bytes(destination.add(6), 0, 22);
        for register in 0..8 {
            core::ptr::write_bytes(destination.add(32 + register * 16), 0, 10);
        }
        core::ptr::write_bytes(destination.add(160), 0, 256);
    }
}

unsafe fn decode_fp(fp: *const u8, layout: &Layout) -> Result<FpKind, FrameError> {
    if fp.is_null() {
        return Ok(FpKind::Absent);
    }
    if fp as usize & 15 != 0
        || layout
            .maximum
            .checked_add(4)
            .and_then(|bytes| (fp as usize).checked_add(bytes))
            .is_none()
    {
        return Err(FrameError);
    }
    let read32 = |offset| unsafe { fp.add(offset).cast::<u32>().read_unaligned() };
    let read64 = |offset| unsafe { fp.add(offset).cast::<u64>().read_unaligned() };
    if read32(SW_OFFSET) != MAGIC1 {
        return Ok(FpKind::Legacy);
    }
    let bytes = read32(SW_OFFSET + 16) as usize;
    let features = read64(SW_OFFSET + 8);
    if fp as usize & 63 != 0
        || bytes < HEADER_END
        || bytes > layout.maximum
        || bytes.checked_add(4) != Some(read32(SW_OFFSET + 4) as usize)
        || features & !layout.enabled != 0
    {
        return Err(FrameError);
    }
    for index in 2..64 {
        if features & (1 << index) != 0 {
            let component = layout.components[index];
            if component.size == 0
                || component
                    .offset
                    .checked_add(component.size)
                    .is_none_or(|end| end > bytes)
            {
                return Err(FrameError);
            }
        }
    }
    let present = read64(HEADER_OFFSET);
    if present & !features != 0
        || read64(HEADER_OFFSET + 8) != 0
        || (HEADER_OFFSET + 16..HEADER_END)
            .step_by(8)
            .any(|offset| read64(offset) != 0)
        || read32(bytes) != MAGIC2
    {
        return Err(FrameError);
    }
    Ok(FpKind::Xsave {
        bytes,
        features,
        present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn architectural_legacy_byte(offset: usize) -> bool {
        offset < 5
            || (6..28).contains(&offset)
            || (32..160).contains(&offset) && (offset - 32) % 16 < 10
            || (160..416).contains(&offset)
    }

    #[test]
    fn legacy_copy_preserves_every_reserved_and_capability_byte() {
        let source = [0xa5; LEGACY_BYTES];
        let mut fresh = [0x5a; LEGACY_BYTES];
        unsafe { copy_legacy_payload(source.as_ptr(), fresh.as_mut_ptr()) };
        for (offset, value) in fresh.into_iter().enumerate() {
            assert_eq!(
                value,
                if architectural_legacy_byte(offset) {
                    0xa5
                } else {
                    0x5a
                },
                "byte {offset}"
            );
        }
    }

    #[test]
    fn restoring_pkru_does_not_copy_old_padding_or_linux_metadata() {
        let mut components = [Component::default(); 64];
        components[9] = Component {
            offset: 600,
            size: 8,
        };
        let layout = Box::leak(Box::new(Layout {
            maximum: 640,
            enabled: 0x203,
            components,
            pkru: Some(600),
        }));
        let saved = SavedState {
            registers: core::array::from_fn(|index| index as i64 + 100),
            storage: vec![Block([0xa5; 64]); 10].into_boxed_slice(),
            kind: FpKind::Xsave {
                bytes: 640,
                features: 0x203,
                present: 0x203,
            },
            pkru: Some(3),
            restorer: 0,
        };
        let mut context = [0u64; 56];
        let original_context = context;
        let mut fp = vec![Block([0x5a; 64]); 11];
        let pointer = fp.as_mut_ptr().cast::<u8>();
        let mut frame = SignalFrame {
            context: unsafe { context.as_mut_ptr().cast::<u8>().add(8) },
            fp: pointer,
            kind: FpKind::Xsave {
                bytes: 640,
                features: 0x203,
                present: 3,
            },
            layout,
            _borrow: PhantomData,
        };
        frame.restore(&saved).unwrap();
        let bytes = unsafe { core::slice::from_raw_parts(pointer, 644) };
        for (offset, value) in bytes.iter().copied().enumerate() {
            let expected = if architectural_legacy_byte(offset) {
                0xa5
            } else if (512..520).contains(&offset) {
                0x203u64.to_ne_bytes()[offset - 512]
            } else if (600..604).contains(&offset) {
                3u32.to_ne_bytes()[offset - 600]
            } else {
                0x5a
            };
            assert_eq!(value, expected, "FP byte {offset}");
        }
        for (index, value) in context.iter().copied().enumerate() {
            assert_eq!(
                value,
                if (6..25).contains(&index) {
                    saved.registers[index - 6] as u64
                } else {
                    original_context[index]
                },
                "context word {index}"
            );
        }
    }

    #[test]
    fn null_fp_is_not_an_authenticated_pkru_value() {
        let layout = Box::leak(Box::new(Layout {
            maximum: 640,
            enabled: 0x203,
            components: [Component::default(); 64],
            pkru: Some(600),
        }));
        let frame = SignalFrame {
            context: core::ptr::null_mut(),
            fp: core::ptr::null_mut(),
            kind: FpKind::Absent,
            layout,
            _borrow: PhantomData,
        };
        assert_eq!(frame.pkru(), Err(FrameError));
    }

    #[test]
    fn no_ospke_legacy_frame_has_no_permission_requirement() {
        let layout = Box::leak(Box::new(Layout {
            maximum: 512,
            enabled: 3,
            components: [Component::default(); 64],
            pkru: None,
        }));
        let mut frame = SignalFrame {
            context: core::ptr::null_mut(),
            fp: core::ptr::null_mut(),
            kind: FpKind::Absent,
            layout,
            _borrow: PhantomData,
        };
        assert_eq!(frame.pkru(), Ok(None));
        assert_eq!(frame.set_pkru(None), Ok(()));
        assert_eq!(frame.set_pkru(Some(0)), Err(FrameError));
    }
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(crate) struct BootstrapPrefix<'a> {
    context: *mut u8,
    _borrow: core::marker::PhantomData<&'a mut ()>,
}
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
impl<'a> BootstrapPrefix<'a> {
    /// # Safety
    /// Exclusive actual kernel SA_SIGINFO pointers for this invocation; complete
    /// frame/FP backing remains kernel-owned and live within the qualified
    /// bootstrap altstack. Memory access is enabled before any Rust entry.
    pub(crate) unsafe fn from_bootstrap_raw(
        context: *mut core::ffi::c_void,
        info: *const core::ffi::c_void,
        stack_lo: usize,
        stack_hi: usize,
        expected_restorer: usize,
        expected_mask: u64,
    ) -> Result<Self, FrameError> {
        let c = context as usize;
        if c & 7 != 0
            || c.checked_sub(8).is_none_or(|n| n < stack_lo)
            || c.checked_add(CONTEXT_BYTES) != Some(info as usize)
            || c.checked_add(CONTEXT_BYTES + 128)
                .is_none_or(|n| n > stack_hi)
        {
            return Err(FrameError);
        }
        let context = context.cast::<u8>();
        let info = info.cast::<u8>();
        // SAFETY: genuine pointers and checked owned prefix/info interval.
        unsafe {
            if context.sub(8).cast::<usize>().read_unaligned() != expected_restorer
                || info.cast::<i32>().read_unaligned() != libc::SIGSYS
                || info.add(4).cast::<i32>().read_unaligned() != 0
                || info.add(8).cast::<i32>().read_unaligned() != 1 // SYS_SECCOMP
                || info.add(28).cast::<u32>().read_unaligned() != 0xc000_003e
                || context.add(SIGMASK_OFFSET).cast::<u64>().read_unaligned() != expected_mask
            {
                return Err(FrameError);
            }
            let f = Self {
                context,
                _borrow: core::marker::PhantomData,
            };
            if info.add(16).cast::<u64>().read_unaligned() != f.rip()
                || f.rax() != info.add(24).cast::<i32>().read_unaligned() as u64
            {
                return Err(FrameError);
            }
            // uc_stack is the real installed owned alternate stack descriptor.
            if context.add(STACK_OFFSET).cast::<usize>().read_unaligned() != stack_lo
                || context.add(STACK_OFFSET + 8).cast::<i32>().read_unaligned() != 0
                || context
                    .add(STACK_OFFSET + 16)
                    .cast::<usize>()
                    .read_unaligned()
                    != stack_hi - stack_lo
            {
                return Err(FrameError);
            }
            Ok(f)
        }
    }
    fn greg(&self, index: usize) -> u64 {
        // Only fixed internal register constants call this; no index assertion
        // or potential panic path belongs in the pre-TLS handler.
        unsafe {
            self.context
                .add(GREG_OFFSET + index * 8)
                .cast::<u64>()
                .read_unaligned()
        }
    }
    pub(crate) fn rip(&self) -> u64 {
        self.greg(libc::REG_RIP as usize)
    }
    pub(crate) fn rax(&self) -> u64 {
        self.greg(libc::REG_RAX as usize)
    }
    pub(crate) fn rsp(&self) -> u64 {
        self.greg(libc::REG_RSP as usize)
    }
    pub(crate) fn args(&self) -> [u64; 6] {
        [
            self.greg(libc::REG_RDI as usize),
            self.greg(libc::REG_RSI as usize),
            self.greg(libc::REG_RDX as usize),
            self.greg(libc::REG_R10 as usize),
            self.greg(libc::REG_R8 as usize),
            self.greg(libc::REG_R9 as usize),
        ]
    }
    pub(crate) fn set_post_setfs_selector(&mut self, selector: u16) {
        let old = self.greg(libc::REG_CSGSFS as usize);
        let updated = (old & !(0xffff_u64 << 32)) | (u64::from(selector) << 32);
        // FS is the third packed 16-bit selector. Actual successful SET_FS
        // changes it; retaining a stale interrupted selector could destroy the
        // new base during signal return. CS/GS/SS and all other state stay put.
        unsafe {
            self.context
                .add(GREG_OFFSET + libc::REG_CSGSFS as usize * 8)
                .cast::<u64>()
                .write_unaligned(updated)
        }
    }
    pub(crate) fn set_result(&mut self, result: i64) {
        // SAFETY: exclusive genuine context prefix; no FP/mask/FS mutation.
        unsafe {
            self.context
                .add(GREG_OFFSET + libc::REG_RAX as usize * 8)
                .cast::<i64>()
                .write_unaligned(result)
        }
    }
}

// The host observer reuses the SAME prefix constants as SignalFrame. These
// copied bytes grant no kernel-frame provenance and never borrow FP memory.
#[cfg(all(feature = "loader-private-runtime", feature = "exec-stop"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RemoteKernelPrefix {
    pub(crate) registers: [u64; 19],
    pub(crate) mask: u64,
    pub(crate) fp_pointer: u64,
    pub(crate) stack: (u64, u64, u32),
}
#[cfg(all(feature = "loader-private-runtime", feature = "exec-stop"))]
pub(crate) const REMOTE_KERNEL_FRAME_BYTES: usize = 8 + CONTEXT_BYTES + 128;
#[cfg(all(feature = "loader-private-runtime", feature = "exec-stop"))]
impl RemoteKernelPrefix {
    // Linux x86-64 rt_sigreturn takes frame = rsp - sizeof(long); the
    // existing runtime's return pops that pretcode word, so uc starts at rsp.
    // Caller has an actual rt_sigreturn ENTRY stop at the bound restorer.
    pub(crate) fn decode(
        bytes: &[u8; REMOTE_KERNEL_FRAME_BYTES],
        context_address: u64,
        expected_restorer: u64,
        expected_info: &[u8; 128],
    ) -> Result<Self, FrameError> {
        let word =
            |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let frame_lo = context_address.checked_sub(8).ok_or(FrameError)?;
        let frame_hi = context_address
            .checked_add((CONTEXT_BYTES + 128) as u64)
            .ok_or(FrameError)?;
        if context_address & 7 != 0
            || frame_hi >= (1_u64 << 47)
            || word(0) != expected_restorer
            || &bytes[8 + CONTEXT_BYTES..] != expected_info
        {
            return Err(FrameError);
        }
        let stack_lo = word(8 + STACK_OFFSET);
        let flags = u32::from_le_bytes(
            bytes[8 + STACK_OFFSET + 8..8 + STACK_OFFSET + 12]
                .try_into()
                .unwrap(),
        );
        let size = word(8 + STACK_OFFSET + 16);
        let stack_hi = stack_lo.checked_add(size).ok_or(FrameError)?;
        // This finite experiment admits only the actual installed alternate
        // stack form, not nested/on-stack, disabled or autodisarmed contexts.
        if flags != 0 || size == 0 || stack_lo > frame_lo || frame_hi > stack_hi {
            return Err(FrameError);
        }
        let fp = word(8 + FP_POINTER_OFFSET);
        if fp == 0 || fp & 15 != 0 || fp < frame_hi || fp >= stack_hi {
            return Err(FrameError);
        }
        Ok(Self {
            registers: core::array::from_fn(|index| word(8 + GREG_OFFSET + index * 8)),
            mask: word(8 + SIGMASK_OFFSET),
            fp_pointer: fp,
            stack: (stack_lo, stack_hi, flags),
        })
    }
}
#[cfg(all(test, feature = "loader-private-runtime", feature = "exec-stop"))]
mod remote_prefix_tests {
    use super::*;
    fn valid() -> ([u8; REMOTE_KERNEL_FRAME_BYTES], [u8; 128]) {
        let mut b = [0; REMOTE_KERNEL_FRAME_BYTES];
        let i = [0x35; 128];
        b[0..8].copy_from_slice(&0x1234_u64.to_le_bytes());
        b[8 + STACK_OFFSET..16 + STACK_OFFSET].copy_from_slice(&0x1000_u64.to_le_bytes());
        b[24 + STACK_OFFSET..32 + STACK_OFFSET].copy_from_slice(&0x10000_u64.to_le_bytes());
        b[8 + FP_POINTER_OFFSET..16 + FP_POINTER_OFFSET].copy_from_slice(&0x3000_u64.to_le_bytes());
        b[8 + CONTEXT_BYTES..].copy_from_slice(&i);
        (b, i)
    }
    #[test]
    fn bounded_prefix_uses_actual_kernel_layout_without_following_fp() {
        let (b, i) = valid();
        let p = RemoteKernelPrefix::decode(&b, 0x2000, 0x1234, &i).unwrap();
        assert_eq!(p.stack, (0x1000, 0x11000, 0));
        assert_eq!(p.fp_pointer, 0x3000);
    }
    #[test]
    fn wrong_restorer_info_stack_and_fp_are_refused() {
        let (b, i) = valid();
        assert!(RemoteKernelPrefix::decode(&b, 0x2000, 0x1235, &i).is_err());
        assert!(RemoteKernelPrefix::decode(&b, 0x2001, 0x1234, &i).is_err());
        let mut info = i;
        info[0] ^= 1;
        assert!(RemoteKernelPrefix::decode(&b, 0x2000, 0x1234, &info).is_err());
        for (offset, value) in [
            (8 + STACK_OFFSET + 8, 1_u64),
            (8 + STACK_OFFSET, 0x2100),
            (8 + FP_POINTER_OFFSET, 0x2000),
        ] {
            let mut bad = b;
            bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(RemoteKernelPrefix::decode(&bad, 0x2000, 0x1234, &i).is_err());
        }
    }
}
