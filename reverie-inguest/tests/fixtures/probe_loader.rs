/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Test-only loader image. The parent starts it on the fixed probe stack with
//! RDI pointing at ProbeControlV1. It calls only the independently checked
//! runtime image, performs the deliberately trapped gate gettid, and stops at
//! the authenticated ready INT3. It never transfers to guest code itself.

#![no_std]
#![no_main]

#[path = "probe_protocol.rs"]
mod protocol;

use core::arch::global_asm;
use core::mem::offset_of;

use protocol::*;

// SAFETY (assembly contract): the parent has checked and mapped both fixed
// images and the initialized control page, and starts this entry on its owned
// writable Tool stack. Runtime entry follows the C ABI and preserves R12;
// stack alignment here satisfies that ABI at each call. The kernel entry image
// is held by the parent, which alone may restore it after the ready marker.
// The gettid stub preserves SysV callee-saved registers. Actual linked RX bytes
// must pass the syscall opcode audit before any of this assembly executes.
global_asm!(
    ".section .gate,\"ax\",@progbits",
    ".global probe_loader_gettid",
    ".type probe_loader_gettid,@function",
    "probe_loader_gettid:",
    "mov eax, 186",
    "syscall",
    "ret",
    ".size probe_loader_gettid, .-probe_loader_gettid",
    ".section .ready,\"ax\",@progbits",
    ".global probe_loader_ready",
    ".type probe_loader_ready,@function",
    "probe_loader_ready:",
    "int3",
    "ud2",
    ".size probe_loader_ready, .-probe_loader_ready",
    ".section .text.start,\"ax\",@progbits",
    ".global _start",
    ".type _start,@function",
    "_start:",
    "cld",
    // The guest's actual kernel RSP is untouched in the parent's snapshot.
    "and rsp, -16",
    "mov r12, rdi",
    "mov rax, {control}",
    "cmp r12, rax",
    "jne 9f",
    "mov rax, {control_magic}",
    "cmp [r12 + {magic}], rax",
    "jne 9f",
    "mov rax, [r12 + {runtime_entry}]",
    "mov rdi, r12",
    "call rax",
    "test rax, rax",
    "jne 9f",
    // The filter specifically traps this syscall from the loader gate.
    "xor edi, edi",
    "xor esi, esi",
    "xor edx, edx",
    "xor r10d, r10d",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "call probe_loader_gettid",
    "test rax, rax",
    "jle 9f",
    "cmp dword ptr [r12 + {phase}], {ready_phase}",
    "jne 9f",
    "cmp dword ptr [r12 + {error}], 0",
    "jne 9f",
    "cmp qword ptr [r12 + {controls}], {required}",
    "jne 9f",
    "mov rax, [r12 + {nonce}]",
    "cmp rax, [r12 + {ready_nonce}]",
    "jne 9f",
    "mov rax, [r12 + {nonce} + 8]",
    "cmp rax, [r12 + {ready_nonce} + 8]",
    "jne 9f",
    "mov rax, {ready_magic}",
    "jmp probe_loader_ready",
    "9:",
    // No fallback to the guest or to a C start-up path on any failure.
    "ud2",
    ".size _start, .-_start",
    control = const CONTROL_ADDRESS,
    control_magic = const CONTROL_MAGIC,
    magic = const offset_of!(ProbeControlV1, magic),
    runtime_entry = const offset_of!(ProbeControlV1, runtime_entry),
    phase = const offset_of!(ProbeControlV1, phase),
    error = const offset_of!(ProbeControlV1, error),
    controls = const offset_of!(ProbeControlV1, controls),
    nonce = const offset_of!(ProbeControlV1, nonce),
    ready_nonce = const offset_of!(ProbeControlV1, ready_nonce),
    ready_phase = const PHASE_TEST_CONTROLS_READY,
    required = const REQUIRED_CONTROLS,
    ready_magic = const READY_MAGIC,
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // This image has no Rust control path or returning panic path.
    loop {
        core::hint::spin_loop();
    }
}
