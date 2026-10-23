/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This instrumentation tool does nothing except acting as a gdbserver.

use reverie::Subscription;
use reverie::Tool;

// TODO-HUMAN-REVIEW(PR-193): Review reuse of the ptrace GDB tool from the LiteInst parity launcher.
#[derive(Debug, Default)]
pub(crate) struct DebugTool;
impl Tool for DebugTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }
}
