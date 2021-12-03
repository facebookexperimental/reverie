/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// A stack frame.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The value of the instruction pointer.
    pub ip: u64,
    /// The symbol associated with this frame (if known).
    pub symbol: Option<Symbol>,
}

/// A symbol from a frame.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Name of the symbol.
    name: String,
    /// Offset of the symbol.
    offset: u64,
    /// Address of the symbol.
    address: u64,
    /// Size of the symbol.
    size: u64,
}
