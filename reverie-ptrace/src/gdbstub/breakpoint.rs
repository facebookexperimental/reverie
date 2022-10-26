/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Breakpoint type
#[derive(PartialEq, Debug)]
pub enum BreakpointType {
    /// Software breakpoint
    Software,
    /// Hardware breakpoint
    Hardware,
    /// Read watchpoint
    ReadWatch,
    /// Write watchpoint
    WriteWatch,
}

impl BreakpointType {
    pub fn new(ty: i32) -> Option<Self> {
        match ty {
            0 => Some(BreakpointType::Software),
            1 => Some(BreakpointType::Hardware),
            2 => Some(BreakpointType::ReadWatch),
            3 => Some(BreakpointType::WriteWatch),
            _ => None,
        }
    }
}

/// Breakpoint.
#[derive(PartialEq, Debug)]
pub struct Breakpoint {
    /// Breakpoint type.
    pub ty: BreakpointType,
    /// Address to set breakpoint.
    pub addr: u64,
    /// Additional expression used to implement conditional breakpoints
    /// See https://sourceware.org/gdb/current/onlinedocs/gdb/Bytecode-Descriptions.html.
    pub bytecode: Option<Vec<u8>>,
}
