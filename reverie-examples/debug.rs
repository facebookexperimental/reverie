/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This instrumentation tool does nothing except acting as a gdbserver.

use reverie::{Error, Subscription, Tool};
use reverie_util::CommonToolArguments;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Debug, Default, Serialize, Deserialize)]
struct DebugTool;
impl Tool for DebugTool {
    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }
}

/// A tool that acts as a GDB server. The process will start in a stopped state,
/// waiting for a GDB client to connect. Once the connection is complete,
/// execution of the guest process will continue.
#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(flatten)]
    common_opts: CommonToolArguments,

    #[structopt(long, default_value = "1234", help = "launch gdbserver on given port")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::from_args();
    let port = args.port;
    let log_guard = args.common_opts.init_tracing();
    eprintln!("Listening on port {}", port);
    let tracer = reverie_ptrace::TracerBuilder::<DebugTool>::new(args.common_opts.into())
        .gdbserver(port)
        .spawn()
        .await?;
    let (status, _global_state) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
