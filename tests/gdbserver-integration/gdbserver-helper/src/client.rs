/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;

pub struct GdbClientCommand {
    gdb: PathBuf,
    program_to_run: PathBuf,
    init_command_to_queue: Vec<String>,
    command_to_queue: Vec<String>,
}

impl GdbClientCommand {
    pub fn new<P: Into<PathBuf>>(gdb_client: P, program_to_run: P) -> Self {
        GdbClientCommand {
            gdb: gdb_client.into(),
            program_to_run: program_to_run.into(),
            command_to_queue: Vec::new(),
            init_command_to_queue: Vec::new(),
        }
    }
    pub fn init_command<P: Into<String>>(&mut self, command: P) -> &mut Self {
        self.init_command_to_queue.push(command.into());
        self
    }
    pub fn init_commands<P, S>(&mut self, commands: P) -> &mut Self
    where
        P: IntoIterator<Item = S>,
        S: Into<String>,
    {
        commands.into_iter().for_each(|ex| {
            self.init_command_to_queue.push(ex.into());
        });
        self
    }
    pub fn command<P: Into<String>>(&mut self, command: P) -> &mut Self {
        self.command_to_queue.push(command.into());
        self
    }
    pub fn commands<P, S>(&mut self, commands: P) -> &mut Self
    where
        P: IntoIterator<Item = S>,
        S: Into<String>,
    {
        commands.into_iter().for_each(|ex| {
            self.command_to_queue.push(ex.into());
        });
        self
    }

    pub fn status(&mut self) -> io::Result<ExitStatus> {
        let mut command = Command::new(&self.gdb);
        command.arg(&self.program_to_run);
        command.arg("-nh");
        command.arg("--batch");
        command.arg("-q");
        command.arg("-l");
        command.arg("2");
        command.arg("-iex");
        command.arg("set debug remote 1");
        command.arg("-iex");
        // NB: host io generates tons of packets which are not interesting,
        // try not to get our remote (debug) packets too cluttered.
        command.arg("set remote hostio-open-packet 0");
        self.init_command_to_queue.iter().for_each(|iex| {
            command.arg("-iex");
            command.arg(format!("{}", iex));
        });
        self.command_to_queue.iter().for_each(|ex| {
            command.arg("-ex");
            command.arg(format!("{}", ex));
        });
        command.status()
    }
}
