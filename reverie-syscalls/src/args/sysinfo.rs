/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Serialization support for sysinfo struct

use serde::Deserialize;
use serde::Serialize;

/// Type safe structure representing 'sysinfo' system call argument
///
/// This mirrors the ABI fields of `libc::sysinfo` but deliberately does *not*
/// mirror its padding, so the two types must be converted field by field
/// rather than transmuted. See the `From` impls below.
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[repr(C)]
pub struct SysInfo {
    /// Seconds since boot
    pub uptime: u64,
    /// 1 minute load averages
    pub loads_1: u64,
    /// 5 minute load averages
    pub loads_5: u64,
    /// 15 minute load average
    pub loads_15: u64,
    /// Total usable main memory size
    pub total_ram: u64,
    /// Available memory size
    pub free_ram: u64,
    /// Amount of shared memory
    pub shared_ram: u64,
    /// Memory used by buffers
    pub buffer_ram: u64,
    /// Total swap space size
    pub total_swap: u64,
    /// Swap space still available
    pub free_swap: u64,
    /// Number of current processes
    pub procs: u16,
    /// Total high memory size
    pub total_high: u64,
    /// Available high memory size
    pub free_high: u64,
    /// Memory unit size in bytes
    pub mem_unit: u32,
}

impl SysInfo {
    /// Serialize the complete Linux LP64 sysinfo output image.
    ///
    /// Every byte is initialized, including ABI padding. Write this array
    /// directly; a returned C struct does not preserve padding initialization.
    /// Uptime keeps the existing signed two's-complement field conversion.
    pub fn to_kernel_bytes(self) -> [u8; 112] {
        use crate::linux_abi::KernelSysinfo;
        let mut bytes = [0u8; 112];
        macro_rules! put {
            ($field:ident, $value:expr) => {{
                let value = $value;
                let offset = core::mem::offset_of!(KernelSysinfo, $field);
                bytes[offset..offset + value.len()].copy_from_slice(&value);
            }};
        }
        put!(uptime, (self.uptime as i64).to_ne_bytes());
        put!(totalram, self.total_ram.to_ne_bytes());
        put!(freeram, self.free_ram.to_ne_bytes());
        put!(sharedram, self.shared_ram.to_ne_bytes());
        put!(bufferram, self.buffer_ram.to_ne_bytes());
        put!(totalswap, self.total_swap.to_ne_bytes());
        put!(freeswap, self.free_swap.to_ne_bytes());
        put!(procs, self.procs.to_ne_bytes());
        put!(totalhigh, self.total_high.to_ne_bytes());
        put!(freehigh, self.free_high.to_ne_bytes());
        put!(mem_unit, self.mem_unit.to_ne_bytes());
        let loads = [self.loads_1, self.loads_5, self.loads_15];
        let load_offset = core::mem::offset_of!(KernelSysinfo, loads);
        for (index, load) in loads.into_iter().enumerate() {
            let offset = load_offset + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&load.to_ne_bytes());
        }
        bytes
    }
}

// Generated UAPI owns offsets. Compile-time field types and exact LP64 layout
// keep this serializer from silently accepting host-libc or compat32 layouts.
const _: () = {
    use crate::linux_abi::KernelSysinfo;
    assert!(core::mem::size_of::<KernelSysinfo>() == 112);
    assert!(core::mem::align_of::<KernelSysinfo>() == 8);
    // SAFETY: integer fields and a zero-sized marker. Used for compile-time
    // field type checking only; no padding bytes are read or serialized.
    let layout: KernelSysinfo = unsafe { core::mem::zeroed() };
    let _: i64 = layout.uptime;
    assert!(core::mem::offset_of!(KernelSysinfo, uptime) == 0);
    let _: [u64; 3] = layout.loads;
    assert!(core::mem::offset_of!(KernelSysinfo, loads) == 8);
    let _: u64 = layout.totalram;
    assert!(core::mem::offset_of!(KernelSysinfo, totalram) == 32);
    let _: u64 = layout.freeram;
    assert!(core::mem::offset_of!(KernelSysinfo, freeram) == 40);
    let _: u64 = layout.sharedram;
    assert!(core::mem::offset_of!(KernelSysinfo, sharedram) == 48);
    let _: u64 = layout.bufferram;
    assert!(core::mem::offset_of!(KernelSysinfo, bufferram) == 56);
    let _: u64 = layout.totalswap;
    assert!(core::mem::offset_of!(KernelSysinfo, totalswap) == 64);
    let _: u64 = layout.freeswap;
    assert!(core::mem::offset_of!(KernelSysinfo, freeswap) == 72);
    let _: u16 = layout.procs;
    assert!(core::mem::offset_of!(KernelSysinfo, procs) == 80);
    let _: u16 = layout.pad;
    assert!(core::mem::offset_of!(KernelSysinfo, pad) == 82);
    let _: u64 = layout.totalhigh;
    assert!(core::mem::offset_of!(KernelSysinfo, totalhigh) == 88);
    let _: u64 = layout.freehigh;
    assert!(core::mem::offset_of!(KernelSysinfo, freehigh) == 96);
    let _: u32 = layout.mem_unit;
    assert!(core::mem::offset_of!(KernelSysinfo, mem_unit) == 104);
};

impl From<SysInfo> for libc::sysinfo {
    /// Convert named fields into a host-libc value, not a guest byte image.
    /// Rust typed moves need not preserve implicit padding initialization.
    /// Use SysInfo::to_kernel_bytes for syscall output serialization.
    fn from(sys_info: SysInfo) -> libc::sysinfo {
        // SAFETY: `libc::sysinfo` is a plain-old-data C struct of integers; the
        // all-zero bit pattern is a valid value for every field.
        let mut out: libc::sysinfo = unsafe { std::mem::zeroed() };
        out.uptime = sys_info.uptime as _;
        out.loads = [sys_info.loads_1, sys_info.loads_5, sys_info.loads_15];
        out.totalram = sys_info.total_ram;
        out.freeram = sys_info.free_ram;
        out.sharedram = sys_info.shared_ram;
        out.bufferram = sys_info.buffer_ram;
        out.totalswap = sys_info.total_swap;
        out.freeswap = sys_info.free_swap;
        out.procs = sys_info.procs;
        out.totalhigh = sys_info.total_high;
        out.freehigh = sys_info.free_high;
        out.mem_unit = sys_info.mem_unit;
        out
    }
}

impl From<libc::sysinfo> for SysInfo {
    /// Convert named host-libc fields without interpreting padding.
    fn from(sys_info: libc::sysinfo) -> SysInfo {
        // GNU uptime is signed; musl libc uses unsigned uptime and an
        // extended wrapper struct. This is a host-libc adapter, not the
        // kernel wire layout used by typed syscall arguments.
        // The remaining fields are c_ulong, which is u64 on every target this
        // crate builds for; if that ever stops holding, this stops compiling
        // rather than silently truncating.
        SysInfo {
            uptime: sys_info.uptime as u64,
            loads_1: sys_info.loads[0],
            loads_5: sys_info.loads[1],
            loads_15: sys_info.loads[2],
            total_ram: sys_info.totalram,
            free_ram: sys_info.freeram,
            shared_ram: sys_info.sharedram,
            buffer_ram: sys_info.bufferram,
            total_swap: sys_info.totalswap,
            free_swap: sys_info.freeswap,
            procs: sys_info.procs,
            total_high: sys_info.totalhigh,
            free_high: sys_info.freehigh,
            mem_unit: sys_info.mem_unit,
        }
    }
}

// On musl, typed syscall buffers use generated Linux UAPI, not libc.
// Value adapters preserve fields, not implicit padding bytes.
#[cfg(target_env = "musl")]
impl From<SysInfo> for crate::linux_abi::KernelSysinfo {
    fn from(sys_info: SysInfo) -> crate::linux_abi::KernelSysinfo {
        // SAFETY: generated Linux sysinfo consists entirely of integer fields.
        let mut out: crate::linux_abi::KernelSysinfo = unsafe { std::mem::zeroed() };
        out.uptime = sys_info.uptime as _;
        out.loads = [sys_info.loads_1, sys_info.loads_5, sys_info.loads_15];
        out.totalram = sys_info.total_ram;
        out.freeram = sys_info.free_ram;
        out.sharedram = sys_info.shared_ram;
        out.bufferram = sys_info.buffer_ram;
        out.totalswap = sys_info.total_swap;
        out.freeswap = sys_info.free_swap;
        out.procs = sys_info.procs;
        out.totalhigh = sys_info.total_high;
        out.freehigh = sys_info.free_high;
        out.mem_unit = sys_info.mem_unit;
        out
    }
}

#[cfg(target_env = "musl")]
impl From<crate::linux_abi::KernelSysinfo> for SysInfo {
    fn from(sys_info: crate::linux_abi::KernelSysinfo) -> SysInfo {
        SysInfo {
            uptime: sys_info.uptime as u64,
            loads_1: sys_info.loads[0],
            loads_5: sys_info.loads[1],
            loads_15: sys_info.loads[2],
            total_ram: sys_info.totalram,
            free_ram: sys_info.freeram,
            shared_ram: sys_info.sharedram,
            buffer_ram: sys_info.bufferram,
            total_swap: sys_info.totalswap,
            free_swap: sys_info.freeswap,
            procs: sys_info.procs,
            total_high: sys_info.totalhigh,
            free_high: sys_info.freehigh,
            mem_unit: sys_info.mem_unit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn sample() -> SysInfo {
        SysInfo {
            uptime: 120,
            loads_1: 1,
            loads_5: 2,
            loads_15: 3,
            total_ram: 1_000_000_000,
            free_ram: 999_000_000,
            shared_ram: 4096,
            buffer_ram: 4096,
            total_swap: 0,
            free_swap: 0,
            procs: 1,
            total_high: 0,
            free_high: 0,
            mem_unit: 1,
        }
    }

    /// Exercise the actual byte serializer after unrelated stack contents.
    /// Its byte array must define all padding regardless of prior contents.
    #[inline(never)]
    fn convert_over_dirty_stack(fill: u8) -> [u8; 112] {
        #[inline(never)]
        fn dirty(fill: u8) -> u64 {
            let mut scratch = [0u8; 4096];
            for (i, b) in scratch.iter_mut().enumerate() {
                *b = fill ^ (i as u8);
            }
            // Keep the writes from being optimized away.
            scratch.iter().map(|b| *b as u64).sum()
        }
        let acc = dirty(fill);
        assert!(acc > 0);
        sample().to_kernel_bytes()
    }

    #[test]
    fn conversion_defines_every_byte_including_padding() {
        // Both conversions use the final serializer, also used by Detcore's
        // handler. No by-value C-struct padding is interpreted as bytes.
        let a = convert_over_dirty_stack(0xAA);
        let b = convert_over_dirty_stack(0x55);
        assert_eq!(a, b, "kernel sysinfo image depends on prior stack contents");
    }

    #[test]
    fn padding_windows_are_zero() {
        // x86_64 struct sysinfo is 112 bytes:
        //   80..82  procs
        //   82..84  pad (an ABI field Linux always zeroes)
        //   84..88  implicit alignment hole before totalhigh
        //   104..108 mem_unit
        //   108..112 trailing hole
        // Linux's do_sysinfo() zeroes all of these; so must we.
        assert_eq!(sample().to_kernel_bytes().len(), 112);
        // Check under BOTH dirty-stack patterns. One pattern alone can leave
        // zeros in a window by luck and make this assertion inert.
        for fill in [0xAAu8, 0x55, 0xFF, 0x0F] {
            let bytes = convert_over_dirty_stack(fill);
            assert_eq!(
                &bytes[82..88],
                &[0u8; 6],
                "padding at 82..88 is not zero (stack fill {fill:#04x})"
            );
            assert_eq!(
                &bytes[108..112],
                &[0u8; 4],
                "padding at 108..112 is not zero (stack fill {fill:#04x})"
            );
        }
    }

    #[test]
    fn round_trip_preserves_abi_fields() {
        let original = sample();
        let round_tripped: SysInfo = libc::sysinfo::from(original).into();
        assert_eq!(original, round_tripped);
    }
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod kernel_wire_tests {
    use super::*;
    use crate::AddrMut;
    use crate::LocalMemory;
    use crate::MemoryAccess;

    #[repr(C)]
    struct Guarded {
        before: [u8; 16],
        result: core::mem::MaybeUninit<crate::linux_abi::Sysinfo>,
        after: [u8; 16],
    }

    #[test]
    fn typed_sysinfo_copy_writes_only_kernel_width_and_zero_padding() {
        assert_eq!(core::mem::size_of::<crate::linux_abi::KernelSysinfo>(), 112);
        assert_eq!(core::mem::size_of::<crate::linux_abi::Sysinfo>(), 112);
        assert_eq!(core::mem::align_of::<crate::linux_abi::Sysinfo>(), 8);
        assert_eq!(
            core::mem::offset_of!(crate::linux_abi::Sysinfo, mem_unit),
            104
        );
        let sample = super::tests::sample();
        for fill in [0x55u8, 0xaa, 0xff, 0x0f] {
            let mut guarded = Guarded {
                before: [fill; 16],
                result: core::mem::MaybeUninit::uninit(),
                after: [fill; 16],
            };
            let address = AddrMut::from_ptr(guarded.result.as_mut_ptr()).unwrap();
            let call = crate::Sysinfo::new().with_info(Some(address));
            let bytes = sample.to_kernel_bytes();
            LocalMemory::new()
                .write_exact(call.info().unwrap().cast::<u8>(), &bytes)
                .unwrap();
            assert_eq!(guarded.before, [fill; 16]);
            assert_eq!(guarded.after, [fill; 16]);
            let mut actual = [0u8; 112];
            LocalMemory::new()
                .read_exact(address.cast::<u8>(), &mut actual)
                .unwrap();
            assert_eq!(&actual[82..88], &[0u8; 6]);
            assert_eq!(&actual[108..112], &[0u8; 4]);
            assert_eq!(&actual[0..8], &120i64.to_ne_bytes());
            assert_eq!(actual, bytes);
            // SAFETY: successful exact byte write initialized all kernel fields.
            let written = unsafe { guarded.result.assume_init() };
            assert_eq!(SysInfo::from(written), sample);
        }
    }

    #[test]
    fn serializer_preserves_signed_uptime_and_integer_extremes() {
        for uptime in [0, i64::MAX as u64, 1u64 << 63, u64::MAX] {
            let mut sample = super::tests::sample();
            sample.uptime = uptime;
            sample.loads_1 = u64::MAX;
            sample.loads_5 = 1u64 << 63;
            sample.total_ram = u64::MAX;
            sample.procs = u16::MAX;
            sample.mem_unit = u32::MAX;
            let bytes = sample.to_kernel_bytes();
            assert_eq!(&bytes[0..8], &(uptime as i64).to_ne_bytes());
            assert_eq!(&bytes[8..16], &u64::MAX.to_ne_bytes());
            assert_eq!(&bytes[16..24], &(1u64 << 63).to_ne_bytes());
            assert_eq!(&bytes[32..40], &u64::MAX.to_ne_bytes());
            assert_eq!(&bytes[80..82], &u16::MAX.to_ne_bytes());
            assert_eq!(&bytes[104..108], &u32::MAX.to_ne_bytes());
            assert_eq!(&bytes[82..88], &[0u8; 6]);
            assert_eq!(&bytes[108..112], &[0u8; 4]);
        }
    }

    #[test]
    fn real_kernel_sysinfo_preserves_adjacent_guard_bytes() {
        assert_eq!(core::mem::size_of::<crate::linux_abi::Sysinfo>(), 112);
        let mut guarded = Guarded {
            before: [0x5a; 16],
            result: core::mem::MaybeUninit::zeroed(),
            after: [0xa5; 16],
        };
        // SAFETY: the typed buffer is writable for the entire generated kernel
        // ABI, with separate guards on both sides and no concurrent accesses.
        let result = unsafe { libc::syscall(libc::SYS_sysinfo, guarded.result.as_mut_ptr()) };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(guarded.before, [0x5a; 16]);
        assert_eq!(guarded.after, [0xa5; 16]);
        // SAFETY: the successful kernel call initialized the ABI fields.
        let written = unsafe { guarded.result.assume_init() };
        assert!(written.mem_unit > 0);
        assert!(written.totalram > 0);
    }
}
