/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The kernel maps this image inside ToolRegion, before the real NOREPLACE call.
#![no_std]
#![no_main]

// SAFETY: a successful refusal never executes this literal first opcode. If a
// broken launcher does hand over, UD2 fails rather than falsely completing.
core::arch::global_asm!(
    r#"
    .section .text.entry,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    ud2
    .size _start, .-_start
"#
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
