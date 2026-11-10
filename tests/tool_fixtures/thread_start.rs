/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared returning thread-start Tool and its post-assertion RPC witness.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls;

#[derive(Debug, Default)]
pub struct StartupObserved {
    pub observed: AtomicBool,
}

#[reverie::global_tool]
impl GlobalTool for StartupObserved {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, (): ()) -> Self::Response {
        self.observed.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug, Default)]
pub struct TestTool;

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = StartupObserved;
    type ThreadState = ();

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        let ret = guest.inject(syscalls::Getpid::new()).await?;
        assert_eq!(Pid::from_raw(ret as i32), guest.pid());
        guest.send_rpc(()).await;
        Ok(())
    }
}
