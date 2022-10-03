/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs;
use std::io;
use std::io::BufRead;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitStatus;

use anyhow::bail;
use anyhow::Error;
use clap::Parser;
use futures::future;
use reverie::process::Output;
use tempfile::TempDir;

mod client;
mod server;

pub use client::*;
pub use server::*;

/// A remote gdb session with a hermit gdbserver and gdb.
struct RemoteGdbSession {
    program_to_debug: PathBuf,
    program_args: Vec<String>,
    gdb_client: PathBuf,

    // Temporary directory where the socket file lives.
    tempdir: TempDir,
}

impl RemoteGdbSession {
    pub fn new<A, P1, P2, S>(path_to_gdb: P1, program_to_debug: P2, program_args: A) -> Self
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        A: IntoIterator<Item = S> + Send,
        S: AsRef<str>,
    {
        // Need a tempdir for the socket file to get created in. We can't create
        // a tempfile and use that as a socket since it cannot exist when we
        // bind to it.
        let tempdir = tempfile::Builder::new()
            .prefix("reverie-gdb-")
            .tempdir()
            .unwrap();

        RemoteGdbSession {
            program_to_debug: PathBuf::from(program_to_debug.as_ref()),
            program_args: program_args
                .into_iter()
                .map(|s| String::from(s.as_ref()))
                .collect(),
            gdb_client: path_to_gdb.as_ref().into(),
            tempdir,
        }
    }

    pub async fn run_server(&self) -> Result<Output, Error> {
        let path = self.tempdir.path().join("sock");

        let server = GdbServerCommand::new(
            &self.program_to_debug,
            self.program_args.clone(),
            path.into(),
        );
        let output =
            tokio::time::timeout(tokio::time::Duration::from_secs(60), server.output()).await??;
        Ok(output)
    }

    pub async fn run_client<P, S>(&self, iex: P, ex: P) -> Result<ExitStatus, Error>
    where
        P: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut client = GdbClientCommand::new(&self.gdb_client, &self.program_to_debug);

        // Connect to remote gdbserver via a Unix domain socket.
        client.command(format!(
            "target remote {}",
            self.tempdir.path().join("sock").display()
        ));
        client.commands(iex);
        client.commands(ex);
        // Final disconnect. this is not really necessary with `--batch`
        // but we still keep it as-is.
        client.command("q");

        let client_status = tokio::time::timeout(
            tokio::time::Duration::from_secs(60),
            tokio::task::spawn_blocking(move || client.status()),
        )
        .await???; // Nani???

        Ok(client_status)
    }

    pub async fn run<P1, P2, S>(self, gdb_iex: P1, gdb_ex: P2) -> Result<Output, Error>
    where
        P1: IntoIterator<Item = S> + Send,
        P2: IntoIterator<Item = S> + Send,
        S: AsRef<str>,
    {
        let gdb_iex: Vec<String> = gdb_iex
            .into_iter()
            .map(|s| String::from(s.as_ref()))
            .collect();
        let gdb_ex: Vec<String> = gdb_ex
            .into_iter()
            .map(|s| String::from(s.as_ref()))
            .collect();
        let (server_output, client_exit_status) =
            future::try_join(self.run_server(), self.run_client(gdb_iex, gdb_ex)).await?;
        if !client_exit_status.success() {
            bail!("gdb client exited with {}", client_exit_status);
        }
        Ok(server_output)
    }
}

#[derive(Parser, Debug, Clone)]
struct GdbServerHelperArgs {
    /// The binary to run.
    #[clap()]
    test_binary: PathBuf,

    /// The arguments to pass to the binary.
    #[clap()]
    test_binary_args: Vec<String>,

    /// Path to the GDB binary.
    #[clap(long, default_value = "gdb")]
    gdb: PathBuf,

    /// Path to a file containing GDB commands to execute before loading the
    /// inferior.
    #[clap(long)]
    iex: Option<PathBuf>,

    /// Path to a file containing GDB commands to execute.
    #[clap(long)]
    ex: Option<PathBuf>,

    /// The expected exit code.
    #[clap(long)]
    exit_code: i32,

    /// Path to the expected stderr.
    #[clap(long)]
    stderr: Option<PathBuf>,

    /// Path to the expected stdout.
    #[clap(long)]
    stdout: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let args = GdbServerHelperArgs::from_args();

    let session = RemoteGdbSession::new(args.gdb, args.test_binary, args.test_binary_args);

    // TODO: Provide a way to pass file paths to gdb instead.
    let iex = if let Some(iex) = args.iex {
        let iex_file = io::BufReader::new(fs::File::open(iex)?);
        iex_file.lines().collect::<io::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    let ex = if let Some(ex) = args.ex {
        let ex_file = io::BufReader::new(fs::File::open(ex)?);
        ex_file.lines().collect::<io::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    let output = session.run(iex, ex).await?;

    if let Some(stderr) = args.stderr {
        // TODO: Display a diff if these don't match.
        let stderr = fs::read(stderr)?;
        assert_eq!(
            String::from_utf8(stderr)?,
            String::from_utf8(output.stderr)?
        );
    }

    if let Some(stdout) = args.stdout {
        // TODO: Display a diff if these don't match.
        let stdout = fs::read(stdout)?;
        assert_eq!(
            String::from_utf8(stdout)?,
            String::from_utf8(output.stdout)?
        );
    }

    assert_eq!(ExitStatus::from_raw(args.exit_code), output.status.into());
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    const NO_ARGS: &[&str] = &[];

    #[tokio::test(flavor = "current_thread")]
    async fn debug_ls_b_main_detach() {
        let session = RemoteGdbSession::new("gdb", "/bin/ls", NO_ARGS);
        assert!(
            session
                .run([], &["b main", "c", "detach"])
                .await
                .unwrap()
                .status
                .success()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn debug_ls_with_b_main_kill() {
        let session = RemoteGdbSession::new("gdb", "/bin/ls", NO_ARGS);
        assert_eq!(
            session
                .run([], &["b main", "c", "kill inferiors 1"])
                .await
                .unwrap()
                .status
                .signal(),
            Some(9),
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn debug_ls_with_b_main_continue() {
        let session = RemoteGdbSession::new("gdb", "/bin/ls", NO_ARGS);
        assert!(
            session
                .run([], &["b main", "c", "c"])
                .await
                .unwrap()
                .status
                .success()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn debug_uname_with_b_main_continue() {
        let session = RemoteGdbSession::new("gdb", "/bin/uname", vec!["-s"]);
        assert_eq!(
            session.run([], &["b main", "c", "c"]).await.unwrap().stdout,
            b"Linux\n",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn debug_file_does_not_exist_with_b_main_continue() {
        let session = RemoteGdbSession::new("gdb", "/this_file/does/not/exist!", NO_ARGS);
        assert!(session.run(None, &["b main", "c", "c"]).await.is_err());
    }
}
