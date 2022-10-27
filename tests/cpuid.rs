/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests cpuid interception

// cpuid interception is only available on x86_64
#![cfg(target_arch = "x86_64")]

use raw_cpuid::CpuIdResult;
use reverie::Errno;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct GlobalState {
    clock: u64,
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = ();
    type Response = u64;

    // Just get the current time.
    async fn receive_rpc(&self, _from: Pid, _request: ()) -> u64 {
        // This could be turned into a logical clock by incrementing this.
        self.clock
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState {}

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = GlobalState;

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut s = Subscription::none();
        s.cpuid();
        s
    }

    async fn handle_cpuid_event<T: Guest<Self>>(
        &self,
        _guest: &mut T,
        eax: u32,
        _ecx: u32,
    ) -> Result<CpuIdResult, Errno> {
        let intercepted = InterceptedCpuid::new();
        Ok(intercepted.cpuid(eax).unwrap())
    }
}

trait Cpuid {
    fn cpuid(&self, index: u32) -> Option<CpuIdResult>;
}

#[derive(Debug, Clone, Copy)]
struct InterceptedCpuid();

impl InterceptedCpuid {
    pub fn new() -> Self {
        InterceptedCpuid()
    }
}

impl Cpuid for InterceptedCpuid {
    fn cpuid(&self, index: u32) -> Option<CpuIdResult> {
        let request = index as usize;
        if request >= 0x80000000 && request < 0x80000000 + EXTENDED_CPUIDS.len() {
            Some(EXTENDED_CPUIDS[request - 0x80000000])
        } else if request < CPUIDS.len() {
            Some(CPUIDS[request])
        } else {
            None
        }
    }
}

const fn cpuid_result(eax: u32, ebx: u32, ecx: u32, edx: u32) -> CpuIdResult {
    CpuIdResult { eax, ebx, ecx, edx }
}

// CPUID output from older CPU (broadwell?), with some features like RDRAND
// masked off to prevent non-determinism.
const CPUIDS: &[CpuIdResult] = &[
    cpuid_result(0x0000000D, 0x756E6547, 0x6C65746E, 0x49656E69),
    cpuid_result(0x00000663, 0x00000800, 0x80202001, 0x078BFBFD),
    cpuid_result(0x00000001, 0x00000000, 0x0000004D, 0x002C307D),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000120, 0x01C0003F, 0x0000003F, 0x00000001),
    cpuid_result(0x00000000, 0x00000000, 0x00000003, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000001, 0x00000100, 0x00000001),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
];

const EXTENDED_CPUIDS: &[CpuIdResult] = &[
    cpuid_result(0x8000000A, 0x756E6547, 0x6C65746E, 0x49656E69),
    cpuid_result(0x00000663, 0x00000000, 0x00000001, 0x20100800),
    cpuid_result(0x554D4551, 0x72695620, 0x6C617574, 0x55504320),
    cpuid_result(0x72657620, 0x6E6F6973, 0x352E3220, 0x0000002B),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x01FF01FF, 0x01FF01FF, 0x40020140, 0x40020140),
    cpuid_result(0x00000000, 0x42004200, 0x02008140, 0x00808140),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00003028, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    cpuid_result(0x00000000, 0x00000000, 0x00000000, 0x00000000),
];

#[test]
fn cpuid_leaf_count() {
    assert_eq!(1 + CPUIDS[0].eax as usize, CPUIDS.len());
    assert_eq!(
        1 + (EXTENDED_CPUIDS[0].eax as usize & !0x80000000usize),
        EXTENDED_CPUIDS.len()
    );
}

#[cfg(not(sanitized))]
#[cfg(test)]
mod tests {
    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[test]
    fn run_guest_func_cpuid_intercepted_test() {
        check_fn::<LocalState, _>(|| {
            let cpuid = raw_cpuid::CpuId::new();
            let feature = cpuid.get_feature_info();
            assert!(feature.is_some());
            let feature = feature.unwrap();
            assert!(!feature.has_rdrand());
        });
    }
}
