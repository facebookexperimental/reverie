/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use reverie::{GlobalTool, Pid};

use crate::config::Config;

#[derive(Debug, Default)]
pub struct GlobalState;

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = ();
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, _pid: Pid, _req: Self::Request) {}
}
