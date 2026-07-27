/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use clap::Parser;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Displayable;
use reverie::syscalls::Syscall;
use reverie_util::CommonToolArguments;

#[path = "src/kvm_runner.rs"]
mod kvm_runner;

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

#[derive(Debug, Parser)]
struct Args {
    // TODO-HUMAN-REVIEW(PR-195): Review minimal strace runner selection.
    /// Execution runner; KVM selects the prototype KvmGuest host.
    #[clap(long, value_enum, default_value = "ptrace")]
    runner: kvm_runner::Runner,

    #[clap(flatten)]
    common: CommonToolArguments,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let stdin = match args.runner {
        kvm_runner::Runner::Ptrace => None,
        kvm_runner::Runner::Kvm => kvm_runner::reserve_stdin()?,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_main(args, stdin))
}

async fn run_main(args: Args, stdin: Option<std::fs::File>) -> anyhow::Result<()> {
    let log_guard = args.common.init_tracing();
    let (status, _) = match args.runner {
        kvm_runner::Runner::Ptrace => {
            let tracer =
                reverie_ptrace::TracerBuilder::<StraceTool>::new(args.common.clone().into())
                    .spawn()
                    .await?;
            tracer.wait().await?
        }
        kvm_runner::Runner::Kvm => {
            let result = kvm_runner::run::<StraceTool>(&args.common, (), stdin).await?;
            (
                reverie::ExitStatus::Exited(result.exit_code),
                result.global_state,
            )
        }
    };
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
