/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use reverie::{
    syscalls::{Displayable, Syscall},
    Error, Guest, Tool,
};
use reverie_util::CommonToolArguments;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Serialize, Deserialize, Default)]
struct StraceTool {}

#[reverie::tool]
impl Tool for StraceTool {
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

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::from_args();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<StraceTool>::new(args.into())
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
