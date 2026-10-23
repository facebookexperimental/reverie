/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Displayable;
use reverie::syscalls::Syscall;

// TODO-HUMAN-REVIEW(PR-193): Review reuse of the minimal strace tool in the LiteInst preload.
#[derive(Default)]
pub(crate) struct StraceTool {}

#[reverie::tool]
impl Tool for StraceTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        eprintln!(
            "[pid {}] {} = ?",
            guest.tid(),
            syscall.display_with_outputs(&guest.memory()),
        );
        guest.tail_inject(syscall).await
    }
}
