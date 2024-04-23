/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use syscalls::Sysno;

use super::syscall_stackframe;

extern "C" {
    // ffi_returns_twice is required here due to a miscompilation bug in release
    // mode. Otherwise, stack variables of the parent can get corrupted due to
    // compiler optimizations. Because of this, vfork *must* be implemented in
    // raw assembly. It can't be safely implemented in Rust inline asm. For more
    // information, see: https://github.com/rust-lang/libc/issues/1596
    pub fn vfork_syscall() -> usize;
}

pub unsafe fn clone_syscall(
    clone_flags: usize,             // rdi
    child_stack: *mut libc::c_void, // rsi
    parent_tidptr: *mut i32,        // rdx
    child_tidptr: *mut i32,         // rcx
    tls: usize,                     // r8
    ret_addr: *const libc::c_void,  // r9
) -> usize {
    let mut ret: usize = Sysno::clone as usize;

    core::arch::asm! {
        "syscall",

        // Both child and parent return here.
        "test rax, rax",
        "jnz 1f",

        // Child
        "push rdi",
        "push rsi",
        "push rdx",
        "push r10", // rcx
        "push r8",
        "push r9",
        "call qword ptr [rip + exit_plugin@GOTPCREL]",
        "pop r9",
        "pop r8",
        "pop r10",
        "pop rdx",
        "pop rsi",
        "pop rdi",

        // The child always returns 0
        "mov rax, 0",

        // Add redzone to our stack because jumping back to the trampoline
        // removes it.
        "sub rsp, 0x80",

        // Jump back to our trampoline.
        "jmp r9",

        // Parent
        "1:",

        inlateout("rax") ret,
        in("rdi") clone_flags,
        in("rsi") child_stack,
        in("rdx") parent_tidptr,
        in("r10") child_tidptr,
        in("r8") tls,
        in("r9") ret_addr,
        // syscall instructions clobber rcx and r11
        lateout("rcx") _,
        lateout("r11") _,
    }

    ret
}

pub unsafe fn clone3_syscall(
    arg1: usize,                 // rdi
    arg2: usize,                 // rsi
    arg3: usize,                 // rdx
    unused: usize,               // rcx
    arg5: usize,                 // r8
    ret_addr: *mut libc::c_void, // r9
) -> usize {
    let mut ret: usize = Sysno::clone3 as usize;

    core::arch::asm! {
        "syscall",

        // Both child and parent return here.
        "test rax, rax",
        "jnz 1f",

        // Child
        "push rdi",
        "push rsi",
        "push rdx",
        "push r8",
        "push r9",
        "call qword ptr [rip + exit_plugin@GOTPCREL]",
        "pop r9",
        "pop r8",
        "pop rdx",
        "pop rsi",
        "pop rdi",

        // The child always returns 0
        "mov rax, 0",

        // Add redzone to our stack because jumping back to the trampoline
        // removes it.
        "sub rsp, 0x80",

        // Jump back to our trampoline.
        "jmp r9",

        // Parent
        "1:",

        inlateout("rax") ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") unused,
        in("r8") arg5,
        in("r9") ret_addr,
        // syscall instructions clobber rcx and r11
        lateout("rcx") _,
        lateout("r11") _,

    }

    ret
}

/// This restores the stack frame pointer, restores the registers from when the
/// syscall was first intercepted, and finally jumps back to the next
/// instruction after the syscall.
///
/// This function never actually returns from the perspective of the caller.
pub unsafe extern "C" fn vfork_return_from_child(wrapper_sp: *const syscall_stackframe) -> ! {
    super::exit_plugin();

    core::arch::asm! {
        // Load registers from the syscall_stackframe struct. These are all
        // offsets into the struct.
        //
        // FIXME: Don't hard code these struct field offsets.
        "mov r15, qword ptr [rdi + 0x8]",
        "mov r14, qword ptr [rdi + 0x10]",
        "mov r13, qword ptr [rdi + 0x18]",
        "mov r12, qword ptr [rdi + 0x20]",
        "mov r11, qword ptr [rdi + 0x28]",
        "mov r10, qword ptr [rdi + 0x30]",
        "mov r9, qword ptr [rdi + 0x38]",
        "mov r8, qword ptr [rdi + 0x40]",
        // Skip rdi because we are reading it for the pointer offset.
        "mov rsi, qword ptr [rdi + 0x50]",
        "mov rdx, qword ptr [rdi + 0x58]",
        "mov rcx, qword ptr [rdi + 0x60]",
        "mov rbx, qword ptr [rdi + 0x68]",
        "mov rbp, qword ptr [rdi + 0x70]",

        // Its safe to clobber r11 to load *ret.
        "mov r11, qword ptr [rdi + 0x80]",

        // Finally, set rdi.
        "mov rdi, qword ptr [rdi + 0x48]",

        // The child always returns 0.
        "mov rax, 0",

        "sub rsp, 0x80",

        // Jump back to the client.
        "jmp r11",

        in("rdi") wrapper_sp,

        options(noreturn),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfork() {
        // The libc::vfork function has miscompilation problems. See
        // https://github.com/rust-lang/libc/issues/1596
        //
        // Test to see if our own vfork has the same issue or not.
        use core::hint::black_box;
        use core::ptr::read_volatile;

        unsafe {
            let a0 = read_volatile(&1234);
            let a1 = read_volatile(&1234);
            let a2 = read_volatile(&1234);
            let a3 = read_volatile(&1234);
            let a4 = read_volatile(&1234);
            let a5 = read_volatile(&1234);
            let a6 = read_volatile(&1234);
            let a7 = read_volatile(&1234);
            let a8 = read_volatile(&1234);
            let a9 = read_volatile(&1234);
            let a10 = read_volatile(&1234);
            let a11 = read_volatile(&1234);
            let a12 = read_volatile(&1234);
            let a13 = read_volatile(&1234);
            let a14 = read_volatile(&1234);
            let a15 = read_volatile(&1234);
            let a16 = read_volatile(&1234);
            let a17 = read_volatile(&1234);
            let a18 = read_volatile(&1234);
            let a19 = read_volatile(&1234);
            if vfork_syscall() == 0 {
                let b0 = read_volatile(&5678);
                let b1 = read_volatile(&5678);
                let b2 = read_volatile(&5678);
                let b3 = read_volatile(&5678);
                let b4 = read_volatile(&5678);
                let b5 = read_volatile(&5678);
                let b6 = read_volatile(&5678);
                let b7 = read_volatile(&5678);
                let b8 = read_volatile(&5678);
                let b9 = read_volatile(&5678);
                let b10 = read_volatile(&5678);
                let b11 = read_volatile(&5678);
                let b12 = read_volatile(&5678);
                let b13 = read_volatile(&5678);
                let b14 = read_volatile(&5678);
                let b15 = read_volatile(&5678);
                let b16 = read_volatile(&5678);
                let b17 = read_volatile(&5678);
                let b18 = read_volatile(&5678);
                let b19 = read_volatile(&5678);
                black_box(b0);
                black_box(b1);
                black_box(b2);
                black_box(b3);
                black_box(b4);
                black_box(b5);
                black_box(b6);
                black_box(b7);
                black_box(b8);
                black_box(b9);
                black_box(b10);
                black_box(b11);
                black_box(b12);
                black_box(b13);
                black_box(b14);
                black_box(b15);
                black_box(b16);
                black_box(b17);
                black_box(b18);
                black_box(b19);
                // When the vforked child exits, the parent can resume.
                libc::_exit(0);
            }

            // None of the items pushed onto the child stack should have leaked into the
            // parent stack.
            assert_eq!(a0, 1234);
            assert_eq!(a1, 1234);
            assert_eq!(a2, 1234);
            assert_eq!(a3, 1234);
            assert_eq!(a4, 1234);
            assert_eq!(a5, 1234);
            assert_eq!(a6, 1234);
            assert_eq!(a7, 1234);
            assert_eq!(a8, 1234);
            assert_eq!(a9, 1234);
            assert_eq!(a10, 1234);
            assert_eq!(a11, 1234);
            assert_eq!(a12, 1234);
            assert_eq!(a13, 1234);
            assert_eq!(a14, 1234);
            assert_eq!(a15, 1234);
            assert_eq!(a16, 1234);
            assert_eq!(a17, 1234);
            assert_eq!(a18, 1234);
            assert_eq!(a19, 1234);
        }
    }
}
