/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io::Write;

use reverie::GlobalTool;
use reverie::Pid;
use serde::Deserialize;
use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Default)]
pub struct GlobalState;

/// A complete Tool diagnostic, formatted while its guest context is live.
///
/// The controller owns the output stream: the application may close or replace
/// its own stderr before a consuming exit hook runs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OutputEvent {
    Syscall(String),
    Signal(String),
    ThreadExit(String),
    ProcessExit(String),
}

fn write_output(writer: &mut impl Write, event: OutputEvent) -> std::io::Result<()> {
    let line = match event {
        OutputEvent::Syscall(line)
        | OutputEvent::Signal(line)
        | OutputEvent::ThreadExit(line)
        | OutputEvent::ProcessExit(line) => line,
    };
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = OutputEvent;
    type Response = Result<(), String>;
    type Config = Config;

    async fn receive_rpc(&self, _pid: Pid, event: Self::Request) -> Self::Response {
        // Complete the write and flush before acknowledging this event. Exit
        // hooks await this response before the runtime finishes their lifetime.
        write_output(&mut std::io::stderr().lock(), event).map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Output {
        bytes: Vec<u8>,
        flushes: usize,
        fail_write: bool,
        fail_flush: bool,
    }

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                return Err(std::io::Error::other("controller write failed"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                Err(std::io::Error::other("controller flush failed"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn output_is_complete_and_flushed_before_acknowledgement() {
        let mut output = Output::default();
        for event in [
            OutputEvent::Syscall("[pid 17] write(1, payload, 6) = 6".into()),
            OutputEvent::Signal("[pid 17] Received signal: SIGUSR1".into()),
            OutputEvent::ThreadExit("Thread 17 exited with status Exited(23)".into()),
            OutputEvent::ProcessExit("Process 17 exited with status Exited(23)".into()),
        ] {
            write_output(&mut output, event).unwrap();
        }
        assert_eq!(output.bytes, b"[pid 17] write(1, payload, 6) = 6\n[pid 17] Received signal: SIGUSR1\nThread 17 exited with status Exited(23)\nProcess 17 exited with status Exited(23)\n");
        assert_eq!(output.flushes, 4);
    }

    #[test]
    fn controller_write_or_flush_failure_is_not_acknowledged_as_success() {
        let mut write_failure = Output {
            fail_write: true,
            ..Output::default()
        };
        let result = write_output(&mut write_failure, OutputEvent::ThreadExit("thread".into()));
        assert_eq!(result.unwrap_err().to_string(), "controller write failed");
        assert!(write_failure.bytes.is_empty());
        assert_eq!(write_failure.flushes, 0);

        let mut flush_failure = Output {
            fail_flush: true,
            ..Output::default()
        };
        let result = write_output(
            &mut flush_failure,
            OutputEvent::ProcessExit("process".into()),
        );
        assert_eq!(result.unwrap_err().to_string(), "controller flush failed");
        assert_eq!(flush_failure.bytes, b"process\n");
        assert_eq!(flush_failure.flushes, 1);
    }
}
