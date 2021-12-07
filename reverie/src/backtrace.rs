/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use core::fmt;
use serde::{Deserialize, Serialize};

/// A stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// The value of the instruction pointer.
    pub ip: u64,
    /// True if this frame is inside of a signal handler.
    pub is_signal: bool,
    /// The symbol associated with this frame (if known).
    pub symbol: Option<Symbol>,
}

/// A symbol from a frame.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Name of the symbol.
    pub name: String,
    /// Offset of the symbol.
    pub offset: u64,
    /// Address of the symbol.
    pub address: u64,
    /// Size of the symbol.
    pub size: u64,
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.symbol {
            Some(symbol) => write!(f, "{:#016x}: {}", self.ip, symbol)?,
            None => write!(f, "{:#016x}: ???", self.ip)?,
        }

        if self.is_signal {
            write!(f, " (in signal handler)")?;
        }

        Ok(())
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} + {:#x}", self.name, self.offset)
    }
}
