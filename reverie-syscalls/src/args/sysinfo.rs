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

impl From<SysInfo> for libc::sysinfo {
    /// Convert field by field into a zeroed `libc::sysinfo`.
    ///
    /// This must not be a `transmute`. `SysInfo` and `libc::sysinfo` have the
    /// same size but *different padding*: `SysInfo` has a six-byte implicit
    /// hole after `procs` and a four-byte trailing hole, whereas
    /// `libc::sysinfo` spends the first two of those six bytes on its named
    /// `pad` field. A transmute copies `SysInfo`'s uninitialized padding
    /// verbatim, and callers write the whole `size_of::<libc::sysinfo>()`
    /// byte image into guest memory (see `reverie-memory`'s
    /// `MemoryAccess::write_value`), so those ten bytes reach the guest as
    /// whatever happened to be on the supervisor's stack.
    ///
    /// That is observable to the guest and is not what Linux does: the
    /// kernel's `do_sysinfo()` builds the struct from a zeroed local, so a
    /// guest is entitled to read zeros in every padding byte and to get the
    /// same image from two calls with identical inputs.
    ///
    /// Starting from `zeroed()` and assigning only the ABI fields defines
    /// every byte of the result, including `pad` and both implicit holes.
    fn from(sys_info: SysInfo) -> libc::sysinfo {
        // SAFETY: `libc::sysinfo` is a plain-old-data C struct of integers; the
        // all-zero bit pattern is a valid value for every field.
        let mut out: libc::sysinfo = unsafe { std::mem::zeroed() };
        out.uptime = sys_info.uptime as libc::c_long;
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
    /// Convert field by field, for the same padding-mismatch reason as the
    /// forward direction. This direction is not guest-visible, but a
    /// transmute here would copy `libc::sysinfo`'s `pad` field into
    /// `SysInfo`'s implicit padding, where it is unnameable and would be
    /// silently re-emitted by the forward conversion.
    fn from(sys_info: libc::sysinfo) -> SysInfo {
        // `uptime` is the only sign change: libc::sysinfo::uptime is c_long.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SysInfo {
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

    fn image(value: &libc::sysinfo) -> [u8; std::mem::size_of::<libc::sysinfo>()] {
        // SAFETY: reading a POD struct as bytes; every byte is initialized
        // because `From<SysInfo>` starts from `zeroed()`. That is exactly the
        // property under test, and it is also what `write_value` does when it
        // copies the struct into guest memory.
        let mut bytes = [0u8; std::mem::size_of::<libc::sysinfo>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                value as *const libc::sysinfo as *const u8,
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        bytes
    }

    /// Build a `SysInfo` in a stack slot that has been dirtied with `fill`
    /// first, so that any padding the conversion fails to define carries
    /// `fill` through into the result.
    #[inline(never)]
    fn convert_over_dirty_stack(fill: u8) -> libc::sysinfo {
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
        libc::sysinfo::from(sample())
    }

    #[test]
    fn conversion_defines_every_byte_including_padding() {
        // Two conversions run over stacks dirtied with different patterns must
        // produce byte-identical images. Before this was a field-by-field
        // conversion the two differed in the padding windows, and detcore
        // copied that difference into guest memory on every sysinfo(2).
        let a = image(&convert_over_dirty_stack(0xAA));
        let b = image(&convert_over_dirty_stack(0x55));
        assert_eq!(
            a, b,
            "libc::sysinfo image depends on prior stack contents: padding is uninitialized"
        );
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
        if std::mem::size_of::<libc::sysinfo>() != 112 {
            return; // non-x86_64 layout; the differential test still applies
        }
        // Check under BOTH dirty-stack patterns. One pattern alone can leave
        // zeros in a window by luck and make this assertion inert.
        for fill in [0xAAu8, 0x55, 0xFF, 0x0F] {
            let bytes = image(&convert_over_dirty_stack(fill));
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
