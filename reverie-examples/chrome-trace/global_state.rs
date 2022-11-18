/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use reverie::GlobalTool;
use reverie::Pid;
use serde::Deserialize;
use serde::Serialize;

use crate::event::ThreadExit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    /// The path to the program.
    name: PathBuf,

    /// The program arguments.
    args: Vec<String>,
}

#[derive(Debug)]
pub struct GlobalState {
    epoch: SystemTime,
    events: Mutex<Vec<ThreadExit>>,
}

impl Default for GlobalState {
    fn default() -> Self {
        Self {
            epoch: SystemTime::now(),
            events: Default::default(),
        }
    }
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = ThreadExit;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _pid: Pid, event: ThreadExit) {
        let mut events = self.events.lock().unwrap();
        events.push(event);
    }
}

impl GlobalState {
    /// Writes out a chrome trace file to the given writer.
    pub fn chrome_trace<W: io::Write>(&self, writer: &mut W) -> serde_json::Result<()> {
        let events = self.events.lock().unwrap();
        let mut json: Vec<serde_json::Value> = Vec::new();

        for event in events.iter() {
            event.trace_event(self.epoch, &mut json);
        }

        let json = serde_json::Value::Array(json);

        serde_json::to_writer(writer, &json)
    }
}
