/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */
//! Read-only PKRU projection from the complete stopped-task XSAVE regset.

use super::XState;

const PKRU: u64 = 1 << 9;
const COMPACTED: u64 = 1 << 63;
const HEADER: usize = 512;
const EXTENDED: usize = 576;

/// Why the opaque stopped-task state cannot yield a checked PKRU projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum XStatePkruError {
    /// The running host does not expose the required enabled user PKRU layout.
    #[error("stopped PKRU requires enabled host XSAVE/OSPKE and a valid user PKRU layout")]
    Unsupported,
    /// Header, masks, layout or reserved fields violate the admitted XSAVE ABI.
    #[error("invalid stopped XSAVE header or component layout")]
    Invalid,
    /// A represented component or the complete PKRU component is outside storage.
    #[error("stopped XSAVE component exceeds the retained regset")]
    Truncated,
    /// A compacted save omitted PKRU entirely, so it did not capture its value.
    #[error("compacted stopped XSAVE did not capture PKRU")]
    Omitted,
}

#[derive(Clone, Copy, Default)]
struct Component {
    bytes: usize,
    standard: usize,
    align64: bool,
}

struct Layout {
    enabled: u64,
    compacted: bool,
    components: [Component; 64],
}

impl Layout {
    // Only called after the public caller establishes capture/CPU-layout
    // compatibility. Never queries a stopped task's *current* PKRU register.
    fn detect() -> Result<Self, XStatePkruError> {
        use core::arch::x86_64::__cpuid;
        use core::arch::x86_64::__cpuid_count;
        use core::arch::x86_64::_xgetbv;
        let required = (1 << 26) | (1 << 27);
        if __cpuid(0).eax < 0xd
            || __cpuid(1).ecx & required != required
            || __cpuid_count(7, 0).ecx & ((1 << 3) | (1 << 4)) != ((1 << 3) | (1 << 4))
        {
            return Err(XStatePkruError::Unsupported);
        }
        let area = __cpuid_count(0xd, 0);
        let supported = u64::from(area.eax) | (u64::from(area.edx) << 32);
        // SAFETY: OSXSAVE was checked before XGETBV. This is the host's
        // enabled-component layout mask, not its permission-register value.
        let enabled = unsafe { _xgetbv(0) };
        if enabled & PKRU == 0 || enabled & !supported != 0 || supported & COMPACTED != 0 {
            return Err(XStatePkruError::Unsupported);
        }
        let mut components = [Component::default(); 64];
        for (index, slot) in components.iter_mut().enumerate().take(63).skip(2) {
            if enabled & (1_u64 << index) == 0 {
                continue;
            }
            let part = __cpuid_count(0xd, index as u32);
            let bytes = part.eax as usize;
            let standard = part.ebx as usize;
            if bytes == 0
                || part.ecx & 1 != 0
                || standard < EXTENDED
                || standard
                    .checked_add(bytes)
                    .is_none_or(|end| end > area.ecx as usize)
            {
                return Err(XStatePkruError::Unsupported);
            }
            *slot = Component {
                bytes,
                standard,
                align64: part.ecx & 2 != 0,
            };
        }
        if components[9].bytes != 8 {
            return Err(XStatePkruError::Unsupported);
        }
        let compacted = __cpuid_count(0xd, 1).eax & ((1 << 1) | (1 << 3)) != 0;
        Ok(Self {
            enabled,
            compacted,
            components,
        })
    }
}

impl XState {
    /// Read the stopped task's captured PKRU, retaining all opaque state intact.
    ///
    /// Supports standard and user-component compacted XSAVE. An absent PKRU
    /// XSTATE_BV bit means architectural initial PKRU (zero) only after complete
    /// layout/extent validation. Compacted omission from XCOMP_BV is refused,
    /// rather than confused with captured initial state. No host RDPKRU, ptrace
    /// write, allocation or mutable byte accessor is used.
    ///
    /// # Safety
    /// This value must be the complete unchanged NT_X86_XSTATE returned by
    /// getxstate for the retained stopped task/generation. The caller must prove
    /// that the host CPU's CPUID leaf 0xD user component layout and XCR0 mask
    /// match that capture and remain stable through this call (including across
    /// migration); use a homogeneous/pinned compatible CPU domain. The host must
    /// permit CPUID/XGETBV. A foreign-CPU, fabricated, partial or different-task
    /// image cannot be qualified by this parser. This scalar supplies neither
    /// task ownership nor permission to restore/resume it. Keep the entire
    /// original XState host-owned for later same-generation restoration.
    pub unsafe fn pkru(&self) -> Result<u32, XStatePkruError> {
        decode(&self.0, &Layout::detect()?)
    }
}

fn word(bytes: &[u8], at: usize) -> u64 {
    // Callers have bounded the complete XSAVE header before these reads.
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn extent(start: usize, size: usize, limit: usize) -> Result<usize, XStatePkruError> {
    start
        .checked_add(size)
        .filter(|end| *end <= limit)
        .ok_or(XStatePkruError::Truncated)
}

fn decode(bytes: &[u8], layout: &Layout) -> Result<u32, XStatePkruError> {
    if bytes.len() < EXTENDED {
        return Err(XStatePkruError::Truncated);
    }
    let present = word(bytes, HEADER);
    let format = word(bytes, HEADER + 8);
    if layout.enabled & PKRU == 0
        || layout.components[9].bytes != 8
        || present & !layout.enabled != 0
        || bytes[HEADER + 16..EXTENDED].iter().any(|b| *b != 0)
    {
        return Err(XStatePkruError::Invalid);
    }
    let offset = if format & COMPACTED == 0 {
        if format != 0 {
            return Err(XStatePkruError::Invalid);
        }
        // Validate active user extents and a complete PKRU slot even for init
        // state. Per-thread AMX permission need not fill CPUID's maximum area.
        for (index, component) in layout.components.iter().enumerate().take(63).skip(2) {
            if (present | PKRU) & (1_u64 << index) == 0 {
                continue;
            }
            if component.bytes == 0 || component.standard < EXTENDED {
                return Err(XStatePkruError::Invalid);
            }
            extent(component.standard, component.bytes, bytes.len())?;
        }
        layout.components[9].standard
    } else {
        if !layout.compacted {
            return Err(XStatePkruError::Unsupported);
        }
        let packed = format & !COMPACTED;
        if packed & !layout.enabled != 0 || present & !packed != 0 {
            return Err(XStatePkruError::Invalid);
        }
        if packed & PKRU == 0 {
            return Err(XStatePkruError::Omitted);
        }
        let mut next = EXTENDED;
        let mut pkru = None;
        // Layout includes all requested components, even those in init state.
        // CPUID bit 1 rounds each component's start to a 64-byte boundary.
        for (index, component) in layout.components.iter().enumerate().take(63).skip(2) {
            if packed & (1_u64 << index) == 0 {
                continue;
            }
            if component.bytes == 0 {
                return Err(XStatePkruError::Invalid);
            }
            if component.align64 {
                next = next.checked_add(63).ok_or(XStatePkruError::Invalid)? & !63;
            }
            if index == 9 {
                pkru = Some(next);
            }
            next = extent(next, component.bytes, bytes.len())?;
        }
        pkru.ok_or(XStatePkruError::Invalid)?
    };
    if present & PKRU == 0 {
        return Ok(0);
    }
    // Only low 32 bits are PKRU. The component's upper four bytes are not
    // permission bits and are never used to replace the original opaque bytes.
    Ok(u32::from_le_bytes(
        bytes[offset..offset + 4].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        let mut components = [Component::default(); 64];
        components[2] = Component {
            bytes: 17,
            standard: 576,
            align64: false,
        };
        components[5] = Component {
            bytes: 80,
            standard: 640,
            align64: true,
        };
        components[9] = Component {
            bytes: 8,
            standard: 832,
            align64: false,
        };
        Layout {
            enabled: 3 | (1 << 2) | (1 << 5) | PKRU,
            compacted: true,
            components,
        }
    }

    fn image(format: u64, present: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        bytes[512..520].copy_from_slice(&present.to_le_bytes());
        bytes[520..528].copy_from_slice(&format.to_le_bytes());
        bytes
    }

    #[test]
    fn standard_value_high_bits_and_opaque_bytes_preserved() {
        let mut bytes = image(0, PKRU | 3, 840);
        bytes[832..840].copy_from_slice(&0xa5a5_a5a5_fedc_ba98_u64.to_le_bytes());
        let original = XState(bytes);
        let before = original.clone();
        assert_eq!(decode(&original.0, &layout()), Ok(0xfedc_ba98));
        assert_eq!(original, before);
    }

    #[test]
    fn standard_init_ignores_stale_payload_but_requires_full_slot() {
        let mut bytes = image(0, 3, 840);
        bytes[832..840].fill(0xff);
        assert_eq!(decode(&bytes, &layout()), Ok(0));
        bytes.pop();
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Truncated));
    }

    #[test]
    fn compacted_alignment_and_init_components_shift_actual_slot() {
        // 2:576..593, 5:init but still consumes 640..720, 9:720..728.
        let mask = 3 | (1 << 2) | (1 << 5) | PKRU;
        let mut bytes = image(COMPACTED | mask, PKRU | 3, 728);
        bytes[720..728].copy_from_slice(&0xdead_beef_1234_5678_u64.to_le_bytes());
        assert_eq!(decode(&bytes, &layout()), Ok(0x1234_5678));
        bytes[512..520].copy_from_slice(&3_u64.to_le_bytes());
        assert_eq!(decode(&bytes, &layout()), Ok(0));
    }

    #[test]
    fn compacted_pkru_own_alignment_and_legacy_mask_do_not_add_bytes() {
        let mut config = layout();
        config.components[9].align64 = true;
        let mut bytes = image(COMPACTED | 3 | (1 << 2) | PKRU, PKRU, 648);
        bytes[640..644].copy_from_slice(&0x8000_0001_u32.to_le_bytes());
        assert_eq!(decode(&bytes, &config), Ok(0x8000_0001));
    }

    #[test]
    fn compacted_omission_is_not_fabricated_initial_pkru() {
        let bytes = image(COMPACTED | 3, 3, 576);
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Omitted));
    }

    #[test]
    fn malformed_masks_header_and_reserved_bytes_refused() {
        let mut bytes = image(1, PKRU, 840);
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Invalid));
        bytes[520..528].copy_from_slice(&0_u64.to_le_bytes());
        bytes[528] = 1;
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Invalid));
        bytes[528] = 0;
        bytes[512..520].copy_from_slice(&(PKRU | (1_u64 << 62)).to_le_bytes());
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Invalid));
        bytes[512..520].copy_from_slice(&PKRU.to_le_bytes());
        bytes[520..528].copy_from_slice(&(COMPACTED | 3).to_le_bytes());
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Invalid));
    }

    #[test]
    fn compacted_unknown_or_missing_metadata_and_truncation_refused() {
        let mask = COMPACTED | 3 | (1 << 2) | (1 << 5) | PKRU;
        let bytes = image(mask, PKRU, 727);
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Truncated));
        let mut bytes = image(mask | (1 << 62), PKRU, 840);
        assert_eq!(decode(&bytes, &layout()), Err(XStatePkruError::Invalid));
        bytes[520..528].copy_from_slice(&mask.to_le_bytes());
        let mut config = layout();
        config.components[5].bytes = 0;
        assert_eq!(decode(&bytes, &config), Err(XStatePkruError::Invalid));
    }

    #[test]
    fn unqualified_compacted_format_and_checked_extent_overflow_refused() {
        let bytes = image(COMPACTED | 3 | PKRU, PKRU, 840);
        let mut config = layout();
        config.compacted = false;
        assert_eq!(decode(&bytes, &config), Err(XStatePkruError::Unsupported));
        config.compacted = true;
        config.components[9].bytes = 8;
        config.components[9].standard = usize::MAX - 3;
        let standard = image(0, PKRU, 840);
        assert_eq!(decode(&standard, &config), Err(XStatePkruError::Truncated));
        config.components[2].bytes = usize::MAX;
        let packed = image(COMPACTED | 3 | (1 << 2) | PKRU, PKRU, 840);
        assert_eq!(decode(&packed, &config), Err(XStatePkruError::Truncated));
    }

    #[test]
    fn short_headers_and_invalid_pkru_layout_refused() {
        assert_eq!(
            decode(&[0; 575], &layout()),
            Err(XStatePkruError::Truncated)
        );
        let bytes = image(0, PKRU, 840);
        let mut config = layout();
        config.components[9].bytes = 4;
        assert_eq!(decode(&bytes, &config), Err(XStatePkruError::Invalid));
        config.components[9].bytes = 8;
        config.components[9].standard = 568;
        assert_eq!(decode(&bytes, &config), Err(XStatePkruError::Invalid));
    }
}
