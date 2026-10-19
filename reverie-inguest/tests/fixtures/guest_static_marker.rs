/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Two literal guest syscalls: a marker write followed by exit0.
#![no_std]
#![no_main]

// SAFETY: this no-libc entry uses only an immutable in-image message and Linux
// x86-64's write/exit ABI. It never returns to an absent caller.
core::arch::global_asm!(
    r#"
    .section .text.entry,"ax",@progbits
    .global _start
    .type _start,@function
_start:
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + .Lmarker]
    mov edx, {message_bytes}
    syscall
    mov eax, 60
    xor edi, edi
    syscall
    ud2
    .size _start, .-_start
    .section .rodata,"a",@progbits
.Lmarker:
    .ascii "STATIC_GUEST_OK\n"
.Lmarker_end:
"#,
    message_bytes = const b"STATIC_GUEST_OK\n".len(),
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
