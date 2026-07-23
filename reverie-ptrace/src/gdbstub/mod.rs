/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Work-in-progress gdbstub server for `hermit --gdbserver`. Some protocol
//! helper types and encoders are implemented ahead of being wired into the
//! command dispatch, so dead-code is allowed across this subsystem rather than
//! deleting scaffolding that the remaining protocol work will use.
#![allow(dead_code)]

mod breakpoint;
mod commands;
mod error;
mod hex;
mod inferior;
mod logger;
mod packet;
mod request;
mod server;
mod session;

mod regs;

use logger::PacketLogger;
use packet::Packet;

pub mod response;

pub use breakpoint::Breakpoint;
pub use breakpoint::BreakpointType;
pub use commands::ResumeAction;
pub use commands::StopEvent;
pub use commands::StopReason;
pub use error::Error;
pub use inferior::Inferior;
pub use inferior::InferiorThreadId;
pub use inferior::ResumeInferior;
pub use inferior::StoppedInferior;
pub use regs::CoreRegs;
pub use request::GdbRequest;
pub use server::GdbServer;
