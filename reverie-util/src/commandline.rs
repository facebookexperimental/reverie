/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Common support for building the CLI interface to each Reverie tool.
//! Each tool with this backend is a standalone executable, and thus
//! needs its own CLI.

use chrono::Local;
use std::path::Path;
use std::{error::Error, ffi::OsStr, fmt::Display, io, path::PathBuf, str::FromStr};
use structopt::StructOpt;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use reverie::process::Command;

/// Parses an environment variable command-line argument.
pub fn parse_env<T, U>(s: &str) -> Result<(T, U), Box<dyn Error>>
where
    T: FromStr,
    T::Err: Error + 'static,
    U: FromStr,
    U::Err: Error + 'static,
{
    let mut iter = s.splitn(2, '=');

    let key = iter.next().ok_or("Invalid KEY=VALUE: string is empty")?;

    let value = match iter.next() {
        Some(value) => value.parse()?,
        None => std::env::var(key)?.parse()?,
    };

    Ok((key.parse()?, value))
}

// Arguments that are shared by most Reverie tools, including which program to
// run and how to run it. Using StructOpt, this is designed to be set from CLI
// args, or to be extended by the tool to form CLI args.
//
// NOTE: Do not change this to a doc comment due to this bug:
// https://github.com/TeXitoi/structopt/issues/333
#[allow(missing_docs)]
#[derive(Debug, Clone, StructOpt)]
pub struct CommonToolArguments {
    /// Direct logging to a file.  This can also be set with the RUST_LOG_FILE environment
    /// variable, but the CLI flag takes precedence.
    #[structopt(long = "log-file", value_name = "PATH", env = "RUST_LOG_FILE")]
    pub log_file: Option<PathBuf>,

    /// Do not pass-through host's environment variables, instead providing a
    /// minimal PATH only (/bin:/usr/bin). The default is to pass through the
    /// host environment.
    #[structopt(long = "no-host-envs")]
    pub no_host_envs: bool,

    /// Sets an environment variable. Can be used multiple times.
    #[structopt(
        long = "env",
        short = "e",
        value_name = "ENV[=VALUE]",
        parse(try_from_str = parse_env),
        number_of_values = 1
    )]
    pub envs: Vec<(String, String)>,

    /// Path of the program to trace.
    #[structopt(value_name = "PROGRAM")]
    pub program: String,

    /// Arguments to the program to trace.
    #[structopt(value_name = "ARGS")]
    pub program_args: Vec<String>,
}

impl CommonToolArguments {
    /// Create a new configuration to run the given program.
    pub fn new<S: AsRef<OsStr> + Clone>(prog: S) -> CommonToolArguments {
        // Dirty, dirty hack.  The first argument is ignored in this process:
        CommonToolArguments::from_iter_safe(&[prog.clone(), prog])
            .expect("CommonToolArguments::new has an internal error that prevented it from constructing an instance.")
    }

    /// Add an argument, similar to Command::arg.  (Consuming builder.)
    pub fn arg<S: AsRef<OsStr> + Display>(&mut self, s: S) -> &mut CommonToolArguments {
        self.program_args
            .push(s.as_ref().to_str().expect("CommonToolArguments::arg internal error.  This OsStr to str conversion should have worked.").to_string());
        self
    }

    pub fn init_tracing(&self) -> Option<WorkerGuard> {
        fn set_subscriber_with_writer<
            T: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
        >(
            writer: T,
        ) {
            // TODO: There is currently no support for async tracing.
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_writer(writer)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("Unable to set global default subscriber");
        }

        self.log_file
            .as_ref()
            .and_then(|lf| {
                let parent = lf.parent()?;
                let orig_filename = lf.file_name()?.to_os_string();
                let mut filename = orig_filename.clone();

                for _ in 0..100 {
                    if Path::new(parent).join(&filename).exists() {
                        filename = orig_filename.clone();
                        filename.push(format!("{}", Local::now().format(".%Y%m%d.%H%M%S.%f")));
                    } else {
                        break;
                    }
                }

                if Path::new(parent).join(&filename).exists() {
                    eprintln!(
                        " [reverie] WARNING: could not open log file, falling back to stderr"
                    );
                    None
                } else {
                    let file_writer = tracing_appender::rolling::never(parent, &filename);
                    // TODO: Is this async logging?
                    let (file_writer, guard) = tracing_appender::non_blocking(file_writer);

                    eprintln!(" [reverie] Logging to file at {:?}", parent.join(&filename));
                    set_subscriber_with_writer(file_writer);
                    Some(guard)
                }
            })
            .or_else(|| {
                set_subscriber_with_writer(io::stderr);
                None
            })
    }
}

impl From<CommonToolArguments> for Command {
    fn from(args: CommonToolArguments) -> Self {
        let mut cmd = Command::new(args.program);
        cmd.args(args.program_args);

        if args.no_host_envs {
            cmd.env_clear();
            cmd.env("PATH", "/bin/:/usr/bin");
        }

        cmd.envs(args.envs);
        cmd
    }
}
