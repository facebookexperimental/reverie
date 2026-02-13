/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This instrumentation tool intercepts events but does nothing with them. It is
//! useful for observing the overhead of interception, and as a starting point.

use clap::Parser;
use reverie::Error;
use reverie::Subscription;
use reverie::Tool;
use reverie_util::CommonToolArguments;

#[derive(Debug, Default)]
struct NoopTool;

#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::parse();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<NoopTool>::new(args.into())
        .spawn()
        .await?;
    let (status, _global_state) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
