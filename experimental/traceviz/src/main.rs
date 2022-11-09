/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod global_state;

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use fbinit::FacebookInit;
use global_state::GlobalState;
use reverie_process::Command;
use reverie_process::ExitStatus;
use tracer::TraceStartParams;
use tracer::Tracer;
use traceviz_rpc::MyService;
use tracing_artillery::ArtillerySubscriber;

/// A super fast strace.
#[derive(Subcommand)]
enum TracevizRunMode {
    Run {
        /// Path to the sabre binary used to launch the plugin.
        #[clap(long, env = "SABRE_PATH")]
        sabre: Option<PathBuf>,

        /// Path to the plugin.
        #[clap(long, env = "SABRE_PLUGIN")]
        plugin: Option<PathBuf>,

        /// The program and arguments.
        #[clap(required = true, multiple_values = true)]
        command_from_terminal: Vec<String>,

        /// The path to write out the Chrome trace JSON file.
        #[clap(long)]
        chrome_out: Option<PathBuf>,

        /// The path to a file for storing serialized generic event data.
        #[clap(long)]
        trace_out: Option<PathBuf>,
    },
    Upload {
        /// The name of the Artillery tracing policy for sending traces. By
        /// default, we are using the traceviz policy
        /// (https://www.internalfb.com/intern/artillery/policies/traceviz/)
        #[clap(long, default_value = "traceviz")]
        tracing_policy: String,

        /// The path to a file for reading in deserialized generic trace
        /// event data.
        #[clap(long, required = true)]
        trace_in: PathBuf,
    },
}

#[derive(Parser)]
#[clap(trailing_var_arg = true)]
struct Args {
    #[clap(subcommand)]
    run_mode: TracevizRunMode,
}

impl Args {
    async fn run(self, fb: FacebookInit) -> Result<ExitStatus> {
        let global_state = Arc::new(GlobalState::new().serve());
        match self.run_mode {
            TracevizRunMode::Run {
                sabre,
                plugin,
                command_from_terminal,
                chrome_out,
                trace_out,
            } => {
                let mut command = Command::new(&command_from_terminal[0]);
                command.args(&command_from_terminal[1..]);

                let mut child = reverie_host::TracerBuilder::new(command)
                    .plugin(plugin)
                    .sabre(sabre)
                    .global_state(global_state.clone())
                    .spawn()?;

                let exit_status = child.wait().await?;

                if let Some(path) = chrome_out {
                    let mut f = io::BufWriter::new(fs::File::create(path)?);
                    global_state.generate_chrome_trace(&mut f)?;
                }

                if let Some(trace_out_path) = trace_out {
                    let mut f = io::BufWriter::new(fs::File::create(trace_out_path)?);
                    global_state.generate_traceviz_output(&mut f)?;
                }

                Ok(exit_status)
            }
            TracevizRunMode::Upload {
                tracing_policy,
                trace_in,
            } => {
                let f = io::BufReader::new(fs::File::open(trace_in)?);
                global_state.read_traceviz_input(f)?;

                {
                    let _trace_guard = {
                        let _init = tracer::trace_start_init(fb);

                        let mut tracer = Tracer::new(fb, &tracing_policy);
                        match tracer.start_managed_trace(&TraceStartParams::new()) {
                            Ok(guard) => {
                                if let Some(trace) = ArtillerySubscriber::current_trace(fb) {
                                    eprintln!(
                                        "Trace ID {0}; Please wait 3-5 minutes for the Trace to propagate through the Artillery backend, before viewing it here: https://www.internalfb.com/intern/tracery/?loader=ArtilleryRemote&artillery_remote_trace_id={0}",
                                        trace.get_id()
                                    );
                                    global_state.upload_artillery_traces(trace);
                                } else {
                                    eprintln!("No current trace");
                                }
                                Some(guard)
                            }
                            Err(err) => {
                                eprintln!("Failed to init tracing: {}", err);
                                None
                            }
                        }
                    };
                }

                Ok(ExitStatus::Exited(0))
            }
        }
    }
}

#[fbinit::main]
fn main(fb: FacebookInit) {
    #[tokio::main]
    async fn _main(fb: FacebookInit) -> ExitStatus {
        match Args::parse().run(fb).await {
            Ok(exit_status) => exit_status,
            Err(err) => {
                eprintln!("{:?}", err);
                ExitStatus::Exited(1)
            }
        }
    }

    // Make sure the tokio runtime exits before propagating the exit status.
    // This ensures that any Drop code gets a chance to run.
    //
    // TODO: Add a proc macro that does this instead.
    _main(fb).raise_or_exit()
}
