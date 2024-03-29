/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use safeptrace::Error as TraceError;
use tokio::sync::oneshot;

use super::Breakpoint;
use super::CoreRegs;

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
    ReadRegisters(oneshot::Sender<Result<CoreRegs, TraceError>>),
    /// Write registers
    WriteRegisters(CoreRegs, oneshot::Sender<Result<(), TraceError>>),
}
