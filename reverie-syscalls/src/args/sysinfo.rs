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
    fn from(sys_info: SysInfo) -> libc::sysinfo {
        unsafe { std::mem::transmute(sys_info) }
    }
}

impl From<libc::sysinfo> for SysInfo {
    fn from(sys_info: libc::sysinfo) -> SysInfo {
        unsafe { std::mem::transmute(sys_info) }
    }
}
