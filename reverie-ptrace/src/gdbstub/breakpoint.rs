/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Breakpoint type, in its GDB remote protocol numbering (`Z`/`z`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BreakpointType {
    /// Software breakpoint (0)
    Software,
    /// Hardware breakpoint (1)
    Hardware,
    /// Write watchpoint (2)
    WriteWatch,
    /// Read watchpoint (3)
    ReadWatch,
    /// Access watchpoint (4): read or write
    AccessWatch,
}

impl BreakpointType {
    pub fn new(ty: i32) -> Option<Self> {
        match ty {
            0 => Some(BreakpointType::Software),
            1 => Some(BreakpointType::Hardware),
            2 => Some(BreakpointType::WriteWatch),
            3 => Some(BreakpointType::ReadWatch),
            4 => Some(BreakpointType::AccessWatch),
            _ => None,
        }
    }

    /// Whether this is a watchpoint type (2, 3 or 4).
    pub fn is_watchpoint(self) -> bool {
        matches!(
            self,
            BreakpointType::WriteWatch | BreakpointType::ReadWatch | BreakpointType::AccessWatch
        )
    }
}

/// Breakpoint.
#[derive(PartialEq, Debug)]
pub struct Breakpoint {
    /// Breakpoint type.
    pub ty: BreakpointType,
    /// Address to set breakpoint.
    pub addr: u64,
    /// The `kind` field of the `Z`/`z` packet: for a watchpoint, how many
    /// bytes it watches. Unused for a breakpoint.
    pub kind: u64,
    /// Additional expression used to implement conditional breakpoints
    /// See https://sourceware.org/gdb/current/onlinedocs/gdb/Bytecode-Descriptions.html.
    pub bytecode: Option<Vec<u8>>,
}
