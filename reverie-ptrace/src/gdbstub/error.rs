/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;

use reverie::Pid;
use safeptrace::Error as TraceError;
use thiserror::Error;

use super::commands::CommandParseError;
use super::hex::GdbHexError;
use super::packet::PacketParseError;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("gdb server not started yet")]
    GdbServerNotStarted,
    #[error("Failed waiting for gdb client to connect")]
    WaitForGdbConnect {
        #[source]
        source: io::Error,
    },
    #[error("Connection reset")]
    ConnReset,
    #[error("gdb session not started")]
    SessionNotStarted,
    #[error(transparent)]
    PacketError(PacketParseError),
    #[error("No inferior attached")]
    Detached,
    #[error(transparent)]
    TraceError(TraceError),
    #[error("Failed to send gdb request over tx channel")]
    GdbRequestSendError,
    #[error("Failed to receive reply from gdb request")]
    GdbRequestRecvError,
    #[error("gdbserver failed to resume/step")]
    GdbResumeError,
    #[error("gdbserver failed to forward gdb packet")]
    GdbServerSendPacketError,
    #[error("No threadid is being specified")]
    ThreadIdNotSpecified,
    #[error("Unknown thread {0}")]
    UnknownThread(Pid),
    #[error("gdbserver failed to receive stop event")]
    GdbServerStopEventRecvError,
}

impl From<CommandParseError> for PacketParseError {
    fn from(err: CommandParseError) -> Self {
        PacketParseError::CommandError(err)
    }
}

impl From<PacketParseError> for Error {
    fn from(err: PacketParseError) -> Self {
        Error::PacketError(err)
    }
}

impl From<CommandParseError> for Error {
    fn from(err: CommandParseError) -> Self {
        Error::PacketError(err.into())
    }
}

impl From<GdbHexError> for Error {
    fn from(err: GdbHexError) -> Self {
        Error::PacketError(err.into())
    }
}

impl From<TraceError> for Error {
    fn from(err: TraceError) -> Self {
        Error::TraceError(err)
    }
}
