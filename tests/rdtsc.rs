/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// rdtsc interception is only available on x86_64
#![cfg(target_arch = "x86_64")]

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default)]
struct GlobalState {
    tsc: AtomicUsize,
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = Rdtsc;
    type Response = RdtscResult;

    async fn init_global_state(_: &Self::Config) -> Self {
        GlobalState {
            tsc: AtomicUsize::new(19200),
        }
    }

    async fn receive_rpc(&self, _from: Tid, args: Rdtsc) -> RdtscResult {
        let tsc = self.tsc.load(Ordering::Relaxed);
        self.tsc.store(1 + tsc, Ordering::Relaxed);
        match args {
            Rdtsc::Tsc => RdtscResult {
                tsc: tsc as u64,
                aux: None,
            },
            Rdtsc::Tscp => RdtscResult {
                tsc: tsc as u64,
                aux: Some(0),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState {}

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = GlobalState;

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut s = Subscription::none();
        s.rdtsc();
        s
    }

    async fn handle_rdtsc_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        let tsc = guest.send_rpc(request).await;
        println!("handle_rdtsc: returned {:?}", tsc);
        Ok(tsc)
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[allow(unused_mut)]
    #[inline(never)]
    unsafe fn rdtscp() -> (u64, u32) {
        let mut aux_val = core::mem::MaybeUninit::uninit();
        let tsc = core::arch::x86_64::__rdtscp(aux_val.as_mut_ptr());
        (tsc, aux_val.assume_init())
    }

    #[test]
    fn run_guest_func_rdtsc_intercepted_test() {
        let state = check_fn::<LocalState, _>(|| {
            let tsc1 = unsafe { core::arch::x86_64::_rdtsc() };
            let tsc2 = unsafe { core::arch::x86_64::_rdtsc() };
            assert_eq!(1 + tsc1, tsc2);
        });
        assert_ne!(state.tsc.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn run_guest_func_rdtscp_intercepted_test() {
        let state = check_fn::<LocalState, _>(move || {
            let (tsc1, _) = unsafe { rdtscp() };
            let (tsc2, _) = unsafe { rdtscp() };
            assert_eq!(1 + tsc1, tsc2);
        });
        assert_ne!(state.tsc.load(Ordering::Relaxed), 0);
    }
}
