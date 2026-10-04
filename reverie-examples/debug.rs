/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This instrumentation tool does nothing except acting as a gdbserver.

#[path = "src/kvm_runner.rs"]
mod kvm_runner;

use clap::Parser;
use reverie::ExitStatus;
use reverie::Subscription;
use reverie::Tool;
use reverie_util::CommonToolArguments;

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

/// A tool that acts as a GDB server. The process will start in a stopped state,
/// waiting for a GDB client to connect. Once the connection is complete,
/// execution of the guest process will continue.
#[derive(Debug, Parser)]
struct Args {
    // TODO-HUMAN-REVIEW(PR-195): Review debug runner selection.
    /// Execution runner; KVM executes DebugTool without the ptrace GDB server.
    #[clap(long, value_enum, default_value = "ptrace")]
    runner: kvm_runner::Runner,

    #[clap(flatten)]
    common_opts: CommonToolArguments,

    /// Launch the ptrace gdbserver on a given port.
    #[clap(long, default_value = "1234")]
    port: u16,
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
    let log_guard = args.common_opts.init_tracing();
    let (status, _global_state) = match args.runner {
        kvm_runner::Runner::Ptrace => {
            eprintln!("Listening on port {}", args.port);
            let tracer =
                reverie_ptrace::TracerBuilder::<DebugTool>::new(args.common_opts.clone().into())
                    .gdbserver(args.port)
                    .spawn()
                    .await?;
            tracer.wait().await?
        }
        kvm_runner::Runner::Kvm => {
            let result = kvm_runner::run::<DebugTool>(&args.common_opts, (), stdin).await?;
            (ExitStatus::Exited(result.exit_code), result.global_state)
        }
    };
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
