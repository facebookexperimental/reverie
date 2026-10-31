/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The unchanged original startup tail-injection Tool.

use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls;

#[derive(Debug, Default)]
pub struct TestTool;

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        guest.tail_inject(syscalls::Getpid::new()).await
    }
}
