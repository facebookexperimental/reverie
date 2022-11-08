/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Routines for tracing and decoding instructions to a particular architecture
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Formatter;
use iced_x86::IntelFormatter;
use reverie::syscalls::MemoryAccess;

use crate::regs::RegAccess;

/// Decodes an instruction on top of the rip
pub fn decode_instruction(task: &safeptrace::Stopped) -> Result<String, safeptrace::Error> {
    let mut code = [0u8; 16];
    let regs = task.getregs()?;
    task.read_exact(regs.ip() as usize, &mut code)?;
    let mut decoder = Decoder::with_ip(64, &code, regs.ip(), DecoderOptions::NONE);
    let instruction = decoder.decode();
    let mut formatter = IntelFormatter::new();
    let mut output = String::new();
    formatter.format(&instruction, &mut output);
    Ok(output)
}
