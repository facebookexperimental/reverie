/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The native private-gate seam needs no caller-stack scratch or C arguments.
//! These are real kernel calls with an assembly observer, not a second gate.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;

const WATCH_BYTES: usize = 256;
const RBX_VALUE: u64 = 0x1234_5678_9abc_def0;
const RBP_VALUE: u64 = 0x1357_9bdf_2468_ace0;
const R12_VALUE: u64 = 0xfedc_ba98_7654_3210;

#[repr(C)]
struct Observation {
    result: i64,
    continuation: u64,
    entry_rsp: u64,
    expected_continuation: u64,
    // RBX, R12 before native caller restoration, R13, R14, R15, RBP.
    registers: [u64; 6],
    restored_r12: u64,
    before: [u8; WATCH_BYTES],
    after: [u8; WATCH_BYTES],
}

const _: () = {
    assert!(std::mem::offset_of!(Observation, registers) == 32);
    assert!(std::mem::offset_of!(Observation, restored_r12) == 80);
    assert!(std::mem::offset_of!(Observation, before) == 88);
    assert!(std::mem::offset_of!(Observation, after) == 344);
};

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .hidden m2_native_gate_observe
    .global m2_native_gate_observe
    .type m2_native_gate_observe,@function
m2_native_gate_observe:
    // A genuine SysV entry: preserve the Rust caller even on the old gate.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 304
    mov r14, rdi
    mov r15, rsi
    mov r13, rdx
    movabs rbx, 0x123456789abcdef0
    movabs rbp, 0x13579bdf2468ace0
    movabs r12, 0xfedcba9876543210
    movq xmm15, r12
    mov rdi, rsp
    mov ecx, 32
    movabs rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rsi, rsp
    lea rdi, [r15 + 88]
    mov ecx, 256
    rep movsb
    lea rax, [rsp + 256]
    mov [r15 + 16], rax
    lea rax, [rip + .Lm2_native_continuation]
    mov [r15 + 24], rax
    mov qword ptr [r15 + 8], 0
    // The genuine CALL return slot is immediately ABOVE all 256 watched bytes.
    // The C seventh argument has its own slot above that, outside the watch.
    add rsp, 264
    cmp r13, 2
    je .Lm2_c_call
    mov rax, [r14]
    mov rdi, [r14 + 8]
    mov rsi, [r14 + 16]
    mov rdx, [r14 + 24]
    mov r10, [r14 + 32]
    mov r8, [r14 + 40]
    mov r9, [r14 + 48]
    test r13, r13
    jne .Lm2_writing_call
    call .Lm2_register_entry
    jmp .Lm2_native_returned
.Lm2_writing_call:
    call .Lm2_writing_entry
.Lm2_native_returned:
    mov [r15 + 40], r12
    // Native callers own R12. Restore it even if the old RET skipped our marker.
    movq r12, xmm15
    jmp .Lm2_observe_return
.Lm2_c_call:
    mov rax, [r14 + 48]
    mov [rsp], rax
    mov rdi, [r14]
    mov rsi, [r14 + 8]
    mov rdx, [r14 + 16]
    mov rcx, [r14 + 24]
    mov r8, [r14 + 32]
    mov r9, [r14 + 40]
    call reverie_inguest_trusted_syscall
    mov [r15 + 40], r12
.Lm2_observe_return:
    mov [r15], rax
    mov [r15 + 32], rbx
    mov [r15 + 48], r13
    mov [r15 + 56], r14
    mov [r15 + 64], r15
    mov [r15 + 72], rbp
    mov [r15 + 80], r12
    sub rsp, 264
    mov rsi, rsp
    lea rdi, [r15 + 344]
    mov ecx, 256
    rep movsb
    add rsp, 304
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.Lm2_writing_entry:
    // Positive corruption control: same observed bytes, no observer exemption.
    mov byte ptr [rsp - 1], 0x11
.Lm2_register_entry:
    lea r12, [rip + .Lm2_native_continuation]
    jmp reverie_inguest_trusted_syscall_ip
.Lm2_native_continuation:
    endbr64
    mov qword ptr [r15 + 8], 1
    // Both old and candidate paths discharge the SAME genuine CALL/RET pair.
    ret
    .size m2_native_gate_observe, .-m2_native_gate_observe
"#
);

unsafe extern "C" {
    fn m2_native_gate_observe(arguments: *const u64, observation: *mut Observation, mode: u64);
}

fn observe(number: i64, args: [u64; 6], mode: u64) -> Observation {
    let arguments = [
        number as u64,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5],
    ];
    let mut observed = Observation {
        result: i64::MIN,
        continuation: u64::MAX,
        entry_rsp: 0,
        expected_continuation: 0,
        registers: [0; 6],
        restored_r12: 0,
        before: [0; WATCH_BYTES],
        after: [0; WATCH_BYTES],
    };
    let input_address = arguments.as_ptr() as u64;
    let output_address = (&raw mut observed) as u64;
    // SAFETY: the observer preserves SysV state and owns its bounded stack
    // storage; these synchronous scalar syscalls do not replace its stack.
    unsafe { m2_native_gate_observe(arguments.as_ptr(), &raw mut observed, mode) };
    let changed = observed
        .before
        .iter()
        .zip(&observed.after)
        .filter(|(a, b)| a != b)
        .count();
    println!(
        "mode={mode} result={} continuation={} rsp={:#x} registers={:x?} restored_r12={:#x} watched={WATCH_BYTES} changed={changed}",
        observed.result,
        observed.continuation,
        observed.entry_rsp,
        observed.registers,
        observed.restored_r12,
    );
    assert_eq!(observed.before, [0xa5; WATCH_BYTES]);
    assert_eq!(observed.registers[0], RBX_VALUE);
    assert_eq!(
        observed.registers[2..],
        [mode, input_address, output_address, RBP_VALUE]
    );
    assert_eq!(observed.restored_r12, R12_VALUE);
    assert_eq!(
        observed.registers[1],
        if mode == 2 {
            R12_VALUE
        } else {
            observed.expected_continuation
        },
    );
    assert_eq!(observed.entry_rsp % 16, 8);
    observed
}

fn pristine(observed: &Observation) -> Result<(), &'static str> {
    if observed.before == observed.after {
        Ok(())
    } else {
        Err("native gate changed watched stack bytes")
    }
}

#[test]
fn native_gate_returns_by_register_without_stack_writes() {
    let observed = observe(libc::SYS_close, [u64::MAX, 0, 0, 0, 0, 0], 0);
    assert_eq!(observed.result, -i64::from(libc::EBADF));
    pristine(&observed).unwrap();
    assert_eq!(
        observed.continuation, 1,
        "the requested native continuation was bypassed"
    );
    let gate = reverie_inguest::trap::trusted_gate();
    assert_eq!(gate.return_ip, gate.syscall_ip + 2);
}

fn second_page(mode: u64) {
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    assert!(page > 0);
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"m2-gate".as_ptr(),
            libc::MFD_CLOEXEC,
        )
    };
    assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    // SAFETY: a fresh owned descriptor from memfd_create.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
    file.write_all(&vec![0x39; page]).unwrap();
    let expected: Vec<u8> = (0..page)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(17))
        .collect();
    file.write_all(&expected).unwrap();
    let observed = observe(
        libc::SYS_mmap,
        [
            0,
            page as u64,
            libc::PROT_READ as u64,
            libc::MAP_PRIVATE as u64,
            file.as_raw_fd() as u64,
            page as u64,
        ],
        mode,
    );
    assert!(observed.result > 0, "mmap result {}", observed.result);
    // Copy before unmapping so every later assertion has already cleaned up.
    let actual = unsafe { std::slice::from_raw_parts(observed.result as *const u8, page) }.to_vec();
    assert_eq!(
        unsafe {
            reverie_inguest::trap::raw_syscall6(
                libc::SYS_munmap,
                [observed.result as u64, page as u64, 0, 0, 0, 0],
            )
        },
        0
    );
    assert_eq!(
        actual, expected,
        "the exact second file page must be mapped"
    );
    if mode == 0 {
        pristine(&observed).unwrap();
        assert_eq!(
            observed.continuation, 1,
            "the requested native continuation was bypassed"
        );
    } else {
        assert_eq!(
            observed.continuation, 0,
            "ordinary C return must not enter the native continuation"
        );
    }
}

#[test]
fn native_gate_keeps_all_six_mmap_arguments() {
    second_page(0);
}

#[test]
fn ordinary_gate_keeps_all_six_arguments_and_callee_saved_registers() {
    second_page(2);
}

#[test]
fn stack_write_control_is_detected_by_the_unchanged_observer() {
    let observed = observe(libc::SYS_close, [u64::MAX, 0, 0, 0, 0, 0], 1);
    assert_eq!(observed.result, -i64::from(libc::EBADF));
    assert_eq!(
        pristine(&observed),
        Err("native gate changed watched stack bytes")
    );
    assert_eq!(
        observed
            .before
            .iter()
            .zip(&observed.after)
            .filter(|(a, b)| a != b)
            .count(),
        1
    );
    assert_eq!(observed.after[WATCH_BYTES - 1], 0x11);
}
