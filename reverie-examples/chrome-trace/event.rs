/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::path::PathBuf;
use std::time::SystemTime;

use reverie::syscalls::Sysno;
use reverie::Errno;
use reverie::ExitStatus;
use reverie::Pid;
use reverie::Tid;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;

/// A message sent to the global state whenever a thread shuts down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadExit {
    /// Process ID.
    pub pid: Pid,

    /// Thread ID.
    pub tid: Tid,

    /// The start time of the thread.
    pub start: SystemTime,

    /// The end time of the thread.
    pub end: SystemTime,

    /// The series of events from this thread.
    pub events: Vec<Event>,

    /// The final exit status of this thread.
    pub exit_status: ExitStatus,
}

// TODO: Handle signal, rdtsc, and cpuid events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// A syscall event. Happens whenever a syscall happens.
    Syscall {
        /// The time at which the syscall started.
        start: SystemTime,

        /// The time at which the syscall completed.
        end: SystemTime,

        /// The syscall number.
        sysno: Sysno,

        /// The formatted syscall with all of its arguments.
        pretty: String,

        /// The result of the syscall.
        result: Result<i64, Errno>,
    },

    /// A successful execve event.
    Exec {
        /// The time at which the execve syscall was executed.
        timestamp: SystemTime,

        /// The program being executed.
        program: Program,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    /// The path to the program.
    pub name: PathBuf,

    /// The program arguments.
    pub args: Vec<String>,
}

impl Program {
    pub fn new(name: PathBuf, args: Vec<String>) -> Self {
        Self { name, args }
    }
}

impl ThreadExit {
    pub fn trace_event(&self, epoch: SystemTime, events: &mut Vec<serde_json::Value>) {
        let thread_name = format!("TID {}", self.tid);

        // Record the thread/process start.
        {
            let ts = self.start.duration_since(epoch).unwrap().as_micros() as u64;

            events.push(json!({
                "name": thread_name,
                "cat": "process",
                "ph": "B",
                "ts": ts,
                "pid": self.pid,
                "tid": self.tid,
            }));
        }

        for event in &self.events {
            match event {
                Event::Syscall {
                    start,
                    end,
                    sysno,
                    pretty,
                    result,
                } => {
                    let ts = start.duration_since(epoch).unwrap().as_micros() as u64;
                    let duration = end.duration_since(*start).unwrap().as_micros() as u64;

                    events.push(json!({
                        "name": sysno.to_string(),
                        "cat": "syscall",
                        "ph": "X",
                        "ts": ts,
                        "dur": duration,
                        "pid": self.pid,
                        "tid": self.tid,
                        "args": {
                            "pretty": pretty,
                            "result": format!("{:?}", result),
                        },
                    }));
                }
                Event::Exec { timestamp, program } => {
                    let ts = timestamp.duration_since(epoch).unwrap().as_micros() as u64;

                    // FIXME: This shouldn't be an "instant" event. We should be
                    // able to determine the duration of the execve call.
                    events.push(json!({
                        "name": "execve",
                        "cat": "syscall",
                        "ph": "i",
                        "ts": ts,
                        "pid": self.pid,
                        "tid": self.tid,
                        "args": {
                            "program": program,
                        }
                    }));
                }
            }
        }

        // Record the thread/process exit.
        {
            let ts = self.end.duration_since(epoch).unwrap().as_micros() as u64;

            events.push(json!({
                "name": thread_name,
                "cat": "process",
                "ph": "E",
                "ts": ts,
                "pid": self.pid,
                "tid": self.tid,
                "args": {
                    "exit_status": self.exit_status,
                }
            }));
        }
    }
}
