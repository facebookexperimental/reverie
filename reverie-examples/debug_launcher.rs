/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The `debug` binary: the tool in `debug.rs`, run on any Reverie backend
//! through the shared runner (`backend.rs`). The tool's file holds only the
//! tool, so the SaBRe plugin and the example preload can include it.

#[path = "backend.rs"]
mod backend;
#[path = "debug.rs"]
mod debug;

use clap::Parser;
use debug::*;
use reverie_util::CommonToolArguments;

/// A tool that acts as a GDB server. The process will start in a stopped state,
/// waiting for a GDB client to connect. Once the connection is complete,
/// execution of the guest process will continue.
#[derive(Debug, Parser)]
struct Args {
    // TODO-HUMAN-REVIEW(PR-195): Review debug runner selection.
    /// The Reverie backend: ptrace runs the GDB server; KVM runs DebugTool
    /// without it (`--runner` is accepted). Other backends refuse by name.
    #[clap(long, value_enum, default_value = "ptrace", alias = "runner")]
    backend: backend::BackendKind,

    #[clap(flatten)]
    common_opts: CommonToolArguments,

    /// Launch the ptrace gdbserver on a given port.
    #[clap(long, default_value = "1234")]
    port: u16,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.backend {
        backend::BackendKind::Ptrace => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(run_gdbserver(args))
        }
        backend::BackendKind::Kvm => {
            let log_guard = args.common_opts.init_tracing();
            let run = backend::run_blocking::<DebugTool>(
                args.backend,
                &args.common_opts,
                (),
                "debug",
                None,
            )?;
            drop(log_guard); // Flush logs before exiting.
            run.status.raise_or_exit()
        }
        backend => anyhow::bail!(
            "REFUSED: the debug example runs on ptrace (its GDB server) or KVM, not {backend:?}"
        ),
    }
}

/// The ptrace run with its GDB server.
async fn run_gdbserver(args: Args) -> anyhow::Result<()> {
    let log_guard = args.common_opts.init_tracing();
    let (status, _global_state) = {
        eprintln!("Listening on port {}", args.port);
        let tracer =
            reverie_ptrace::TracerBuilder::<DebugTool>::new(args.common_opts.clone().into())
                .gdbserver(args.port)
                .spawn()
                .await?;
        tracer.wait().await?
    };
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
