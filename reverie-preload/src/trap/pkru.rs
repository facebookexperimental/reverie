/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Installation-time PKRU discovery and read-only Linux signal-frame decoding.

use std::io;
use std::sync::OnceLock;

const PKRU_BIT: u64 = 1 << 9;
const HEADER_OFFSET: usize = 512;
const HEADER_END: usize = 576;
const SW_OFFSET: usize = 464;
const MAGIC1: u32 = 0x4650_5853;
const MAGIC2: u32 = 0x4650_5845;

#[derive(Clone, Copy)]
struct Layout {
    offset: usize,
    maximum_size: usize,
    enabled: u64,
}

// Populated before the handler is installed. Signal context only performs a
// nonblocking read, never lazy initialization or CPUID (which may then fault).
static LAYOUT: OnceLock<Option<Layout>> = OnceLock::new();

pub(super) fn initialize() -> io::Result<bool> {
    let layout = detect()?;
    let present = layout.is_some();
    let _ = LAYOUT.set(layout);
    Ok(present)
}

fn detect() -> io::Result<Option<Layout>> {
    use core::arch::x86_64::__cpuid;
    use core::arch::x86_64::__cpuid_count;
    use core::arch::x86_64::_xgetbv;
    let maximum_leaf = __cpuid(0).eax;
    if maximum_leaf < 7 || __cpuid_count(7, 0).ecx & (1 << 4) == 0 {
        return Ok(None);
    }
    let invalid = || io::Error::other("OSPKE requires a valid standard PKRU XSAVE layout");
    let xsave_bits = (1 << 26) | (1 << 27);
    if maximum_leaf < 0xd || __cpuid(1).ecx & xsave_bits != xsave_bits {
        return Err(invalid());
    }
    // SAFETY: actual OSXSAVE was checked before XGETBV.
    let enabled = unsafe { _xgetbv(0) };
    let area = __cpuid_count(0xd, 0);
    let supported = u64::from(area.eax) | (u64::from(area.edx) << 32);
    let component = __cpuid_count(0xd, 9);
    let offset = component.ebx as usize;
    let maximum_size = area.ebx as usize;
    if enabled & PKRU_BIT == 0
        || supported & PKRU_BIT == 0
        || component.eax != 8
        || component.ecx & 1 != 0
        || offset < HEADER_END
        || offset.checked_add(8).is_none_or(|end| end > maximum_size)
    {
        return Err(invalid());
    }
    Ok(Some(Layout {
        offset,
        maximum_size,
        enabled,
    }))
}

/// Decode only a real kernel-created x86-64 signal frame, after provenance
/// checks and after the entry prefix has made the whole signal stack readable.
/// The original image remains untouched for the kernel's rt_sigreturn.
pub(super) unsafe fn from_signal_frame(
    fpstate: *const libc::_libc_fpstate,
) -> Result<Option<u32>, ()> {
    let Some(layout) = LAYOUT.get().ok_or(())? else {
        return Ok(None);
    };
    if fpstate.is_null() {
        return Err(());
    }
    unsafe { decode(fpstate.cast(), *layout).map(Some) }
}

unsafe fn decode(base: *const u8, layout: Layout) -> Result<u32, ()> {
    // The fixed 512-byte FXSAVE area is part of the kernel-provided fpstate.
    // Linux's _fpx_sw_bytes describes the following standard XSAVE image.
    let read32 = |offset| unsafe { base.add(offset).cast::<u32>().read_unaligned() };
    let read64 = |offset| unsafe { base.add(offset).cast::<u64>().read_unaligned() };
    let size = read32(SW_OFFSET + 16) as usize;
    let extended = read32(SW_OFFSET + 4) as usize;
    let features = read64(SW_OFFSET + 8);
    if read32(SW_OFFSET) != MAGIC1
        || size < layout.offset + 8
        || size > layout.maximum_size
        || size.checked_add(4) != Some(extended)
        || features & PKRU_BIT == 0
        || features & !layout.enabled != 0
    {
        return Err(());
    }
    // Bound the variable trailing read before checking the second Linux magic.
    // Per-thread AMX permission can make this frame smaller than CPUID's full
    // XCR0-enabled size; equality with that maximum would reject valid frames.
    if read32(size) != MAGIC2 || read64(HEADER_OFFSET + 8) != 0 {
        return Err(());
    }
    let present = read64(HEADER_OFFSET);
    if present & !features != 0
        || (HEADER_OFFSET + 16..HEADER_END)
            .step_by(8)
            .any(|offset| read64(offset) != 0)
    {
        return Err(());
    }
    // XSAVE init-state components need not have their payload written. Do not
    // interpret stale bytes when the PKRU bit is absent from XSTATE_BV.
    if present & PKRU_BIT == 0 {
        return Ok(0);
    }
    // Linux's update_pkru_in_sigframe stores the interrupted u32 PKRU itself
    // after XSAVE. The component's remaining four padding bytes
    // can retain prior signal-stack contents; they are not permission bits.
    Ok(read32(layout.offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(present: bool, value: u64) -> (Vec<u8>, Layout) {
        let layout = Layout {
            offset: 600,
            maximum_size: 640,
            enabled: 0x203,
        };
        let mut bytes = vec![0; 644];
        bytes[SW_OFFSET..SW_OFFSET + 4].copy_from_slice(&MAGIC1.to_ne_bytes());
        bytes[SW_OFFSET + 4..SW_OFFSET + 8].copy_from_slice(&644u32.to_ne_bytes());
        bytes[SW_OFFSET + 8..SW_OFFSET + 16].copy_from_slice(&0x203u64.to_ne_bytes());
        bytes[SW_OFFSET + 16..SW_OFFSET + 20].copy_from_slice(&640u32.to_ne_bytes());
        bytes[512..520].copy_from_slice(&(if present { 0x203u64 } else { 3 }).to_ne_bytes());
        bytes[600..608].copy_from_slice(&value.to_ne_bytes());
        bytes[640..644].copy_from_slice(&MAGIC2.to_ne_bytes());
        (bytes, layout)
    }

    #[test]
    fn decodes_present_and_init_pkru_without_changing_frame() {
        for (present, payload, expected) in [
            (true, 1, 1),
            (true, 0, 0),
            (true, 0x0000_7fff_5555_5540, 0x5555_5540),
            (false, u64::MAX, 0),
        ] {
            let (bytes, layout) = frame(present, payload);
            let original = bytes.clone();
            assert_eq!(unsafe { decode(bytes.as_ptr(), layout) }, Ok(expected));
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn rejects_invalid_metadata_and_reserved_state() {
        for offset in [464, 468, 472, 480, 512, 520, 528, 640] {
            let (mut bytes, layout) = frame(true, 1);
            bytes[offset] ^= 0x80;
            assert!(
                unsafe { decode(bytes.as_ptr(), layout) }.is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn accepts_smaller_per_thread_frame_with_complete_pkru() {
        let (bytes, mut layout) = frame(true, 1);
        layout.maximum_size = 11008;
        assert_eq!(unsafe { decode(bytes.as_ptr(), layout) }, Ok(1));
    }
}
