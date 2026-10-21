/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Dynamic std startup followed by a real thread-creation request. Avoid
//! pthread_create's earlier signal-control changes: those are a separate row.
//! If clone3 is forwarded, its child has a valid private stack and emits an
//! unmistakable failure marker without entering Rust.
use std::io::Write;

core::arch::global_asm!(
    r#"
    .text
    .global request_thread
    .type request_thread,@function
request_thread:
    mov eax, 435
    syscall
    test rax, rax
    jz .Lunexpected_child
    ret
.Lunexpected_child:
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + .Lunexpected]
    mov edx, {message_bytes}
    syscall
    mov eax, 60
    xor edi, edi
    syscall
    ud2
    .size request_thread, .-request_thread
    .section .rodata,"a",@progbits
.Lunexpected:
    .ascii "UNEXPECTED_GUEST_THREAD_RAN\n"
.Lunexpected_end:
"#,
    message_bytes = const b"UNEXPECTED_GUEST_THREAD_RAN\n".len(),
);

unsafe extern "C" {
    fn request_thread(args: *const u64, bytes: usize) -> i64;
}

fn main() {
    println!("DIRECT_CLONE3_REQUEST");
    std::io::stdout().flush().unwrap();
    let mut stack = vec![0_u8; 64 * 1024];
    // Linux clone_args v0..v2, 11 u64 fields. CLONE_VM|FS|FILES|SIGHAND|
    // THREAD|SYSVSEM requests a real thread; exit_signal is zero.
    let mut args = [0_u64; 11];
    args[0] = 0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000;
    args[5] = stack.as_mut_ptr() as u64;
    args[6] = stack.len() as u64;
    // SAFETY: args and the writable child stack stay live across the call.
    // The assembly child path uses no Rust/TLS and exits the child thread.
    let result = unsafe { request_thread(args.as_ptr(), core::mem::size_of_val(&args)) };
    assert_eq!(result, -95, "clone3 was not refused with EOPNOTSUPP");
    println!("DIRECT_CLONE3_REFUSED");
    std::io::stdout().flush().unwrap();
    std::process::exit(125);
}
