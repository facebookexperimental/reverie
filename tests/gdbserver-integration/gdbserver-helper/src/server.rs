/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use anyhow::Error;
use reverie::process::{Command, Mount, Namespace, Output, Stdio};
use reverie::Subscription;
use reverie::Tool;
use reverie_ptrace::GdbConnection;
use serde::Deserialize;
use serde::Serialize;
use std::path::PathBuf;

pub struct GdbServerCommand {
    // NB: ideally we could also attach to a existing pid, but this is not
    // supported by reverie yet..
    program_to_run: PathBuf,
    program_args: Vec<String>,
    connection: GdbConnection,
}

#[derive(Serialize, Deserialize, Default)]
struct TestTool;

impl Tool for TestTool {
    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::all()
    }
}

async fn run(command: Command, connection: GdbConnection) -> Result<Output, Error> {
    let (output, _global_state) = reverie_ptrace::TracerBuilder::<TestTool>::new(command)
        .gdbserver(connection)
        .spawn()
        .await?
        .wait_with_output()
        .await?;
    Ok(output)
}

impl GdbServerCommand {
    pub fn new<A, P, S>(program_to_run: P, program_args: A, connection: GdbConnection) -> Self
    where
        P: Into<PathBuf>,
        A: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        GdbServerCommand {
            program_to_run: program_to_run.into(),
            program_args: program_args
                .into_iter()
                .map(|s| String::from(s.as_ref()))
                .collect(),
            connection,
        }
    }

    /// run gdbserver under namespace
    pub async fn output(self) -> Result<Output, Error> {
        let mut command = Command::new(&self.program_to_run);
        command.args(&self.program_args);
        command
            .unshare(Namespace::PID)
            .map_root()
            .hostname("hermetic-container.local")
            .domainname("local")
            .mount(Mount::proc())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        run(command, self.connection).await
    }
}
