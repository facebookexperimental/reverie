/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::Amd64CoreRegs;
use super::Breakpoint;
use crate::trace::Error as TraceError;
use tokio::sync::oneshot;

/// gdb request send to reverie.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum GdbRequest {
    /// Set a breakpoint.
    SetBreakpoint(Breakpoint, oneshot::Sender<Result<(), TraceError>>),
    /// Remove a breakpoint.
    RemoveBreakpoint(Breakpoint, oneshot::Sender<Result<(), TraceError>>),
    /// Read inferior memory. Note the memory requested could contain
    /// software breakpoint, in such case, `ReadInferiorMemory` should
    /// return the original contents (excluding the breakpoint insn).
    ReadInferiorMemory(u64, usize, oneshot::Sender<Result<Vec<u8>, TraceError>>),
    /// Write inferior memory
    WriteInferiorMemory(u64, usize, Vec<u8>, oneshot::Sender<Result<(), TraceError>>),
    /// Read registers
    ReadRegisters(oneshot::Sender<Result<Amd64CoreRegs, TraceError>>),
    /// Write registers
    WriteRegisters(Amd64CoreRegs, oneshot::Sender<Result<(), TraceError>>),
}
