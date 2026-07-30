/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Regression coverage for the x86-64 legacy-vsyscall interception path.

use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;

const FIXED_TIME: libc::time_t = 1_234_567_890;

#[derive(Debug, Default, Clone)]
struct TimeTool;

#[reverie::tool]
impl Tool for TimeTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Time(call) => {
                if let Some(tloc) = call.tloc() {
                    guest.memory().write_value(tloc, &FIXED_TIME)?;
                }
                Ok(FIXED_TIME)
            }
            otherwise => guest.tail_inject(otherwise).await,
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn suppressed_legacy_vsyscall_returns_to_caller() {
    // Kernels booted with `vsyscall=none` deliberately provide no legacy
    // entry point. The return-path behavior under test exists only when the
    // synthetic mapping is enabled.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    if !maps.lines().any(|line| line.ends_with("[vsyscall]")) {
        eprintln!("skipping legacy-vsyscall test: host has no [vsyscall] mapping");
        return;
    }

    reverie_ptrace::testing::check_fn::<TimeTool, _>(|| {
        const VSYSCALL_TIME: usize = 0xffff_ffff_ff60_0400;
        let time_fn: unsafe extern "C" fn(*mut libc::time_t) -> libc::time_t =
            unsafe { std::mem::transmute(VSYSCALL_TIME) };

        let mut stored = 0;
        let returned = unsafe { time_fn(&mut stored) };
        assert_eq!(returned, FIXED_TIME);
        assert_eq!(stored, FIXED_TIME);
    });
}
