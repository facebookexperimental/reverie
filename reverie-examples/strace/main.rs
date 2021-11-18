/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

mod config;
mod filter;
mod global_state;
mod tool;

use config::Config;
use filter::Filter;
use tool::Strace;

use structopt::StructOpt;

use reverie::Error;
use reverie_util::CommonToolArguments;

/// A tool to trace system calls.
#[derive(StructOpt, Debug)]
struct Opts {
    #[structopt(flatten)]
    common: CommonToolArguments,

    /// The set of syscalls to trace. By default, all syscalls are traced. If
    /// this is used, then only the specified syscalls are traced. By limiting
    /// the set of traced syscalls, we can reduce the overhead of the tracer.
    #[structopt(long)]
    trace: Vec<Filter>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Opts::from_args();

    let config = Config {
        filters: args.trace,
    };

    let log_guard = args.common.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<Strace>::new(args.common.into())
        .config(config)
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
