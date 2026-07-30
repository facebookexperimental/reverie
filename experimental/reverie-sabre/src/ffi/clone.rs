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

/// Executes `clone(2)` while preserving the trampoline return path.
///
/// # Safety
///
/// All pointers and the return address must be valid for the kernel ABI and
/// SaBRe trampoline used by the current guest thread.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-214): Review eager child-start callback ABI.
// TODO-HUMAN-REVIEW(PR-226): Review removal of the pre-pthread child callback.
pub unsafe fn clone_syscall(
    clone_flags: usize,             // rdi
    child_stack: *mut libc::c_void, // rsi
    parent_tidptr: *mut i32,        // rdx
    child_tidptr: *mut i32,         // rcx
    tls: usize,                     // r8
    ret_addr: *const libc::c_void,  // r9
    vfork_slot: u64,                // xmm0 (preserved by syscall)
) -> usize {
    let mut ret: usize = Sysno::clone as usize;

    core::arch::asm! {
        "syscall",

        // Both child and parent return here.
        "test rax, rax",
        "jnz 2f",

        // Child
        "push rdi",
        "push rsi",
        "push rdx",
        "push r10", // rcx
        "push r8",
        "push r9",
        "mov rdi, qword ptr [rsp + 0x28]", // clone_flags saved by first push
        "mov rax, rdi",
        "test rax, {clone_vm}",
        "jz 3f",
        "and rax, {vfork_flags}",
        "cmp rax, {vfork_flags}",
        "jne 4f",
        "3:",
        "movq rsi, xmm0",
        "call qword ptr [rip + reverie_sabre_after_clone_child@GOTPCREL]",
        "4:",
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
        "2:",

        inlateout("rax") ret,
        in("rdi") clone_flags,
        in("rsi") child_stack,
        in("rdx") parent_tidptr,
        in("r10") child_tidptr,
        in("r8") tls,
        in("r9") ret_addr,
        in("xmm0") vfork_slot,
        clone_vm = const libc::CLONE_VM,
        vfork_flags = const (libc::CLONE_VM | libc::CLONE_VFORK),
        // syscall instructions clobber rcx and r11
        lateout("rcx") _,
        lateout("r11") _,
    }

    ret
}

/// Executes a `fork`-style `clone(2)` (no new child stack) and resumes the
/// child on the guest's ORIGINAL stack.
///
/// [`clone_syscall`] starts a new thread on a caller-supplied `child_stack`, so
/// the kernel sets the child's `%rsp` to that stack and its `jmp r9` shortcut is
/// correct. A forked child (`child_stack == NULL`) instead shares the parent's
/// stack layout, so the kernel leaves the child's `%rsp` pointing deep inside
/// the plugin's own call frames (SaBRe runs `handle_syscall` on the guest
/// stack). Jumping straight back to the guest from there resumes guest code on
/// the wrong stack and later faults on a mismatched `ret`.
///
/// This routine instead reproduces SaBRe's normal `handle_syscall` epilogue for
/// the child: it restores the guest's saved general-purpose registers and its
/// original `%rsp` (`wrapper_sp + 0x88`) from the syscall frame, then jumps to
/// the saved return address with `%rax = 0`.
///
/// # Safety
///
/// `wrapper_sp` must point to the live SaBRe syscall frame for the current guest
/// thread, and the flag/pointer arguments must satisfy `clone(2)`.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-128): Review the fork-child stack/register restore trampoline.
pub unsafe fn fork_syscall(
    clone_flags: usize,      // rdi
    parent_tidptr: *mut i32, // rdx
    child_tidptr: *mut i32,  // r10
    tls: usize,              // r8
    wrapper_sp: *const syscall_stackframe,
    vfork_slot: u64, // xmm0 (preserved by syscall)
) -> usize {
    let mut ret: usize = Sysno::clone as usize;

    core::arch::asm! {
        "syscall",

        // Both child and parent return here.
        "test rax, rax",
        "jnz 2f",

        // ---- Child: never returns through Rust. ----
        // `wrapper_sp` is preserved across the clone in r12.
        "mov rax, rdi",
        "test rax, {clone_vm}",
        "jz 3f",
        "and rax, {vfork_flags}",
        "cmp rax, {vfork_flags}",
        "jne 4f",
        "3:",
        "movq rsi, xmm0",
        "call qword ptr [rip + reverie_sabre_after_clone_child@GOTPCREL]",
        "4:",
        "call qword ptr [rip + exit_plugin@GOTPCREL]",
        "mov rdi, r12",                     // rdi = wrapper_sp (frame base)
        // Restore the guest's saved registers from the frame, mirroring the
        // pops in SaBRe's handle_syscall.S epilogue. rcx/r11 were clobbered by
        // the guest's own syscall, and r11 is reused below as the jump target.
        "mov r15, qword ptr [rdi + 0x8]",
        "mov r14, qword ptr [rdi + 0x10]",
        "mov r13, qword ptr [rdi + 0x18]",
        "mov r10, qword ptr [rdi + 0x30]",
        "mov r9,  qword ptr [rdi + 0x38]",
        "mov r8,  qword ptr [rdi + 0x40]",
        "mov rsi, qword ptr [rdi + 0x50]",
        "mov rdx, qword ptr [rdi + 0x58]",
        "mov rcx, qword ptr [rdi + 0x60]",
        "mov rbx, qword ptr [rdi + 0x68]",
        "mov rbp, qword ptr [rdi + 0x70]",
        "mov r12, qword ptr [rdi + 0x20]",  // restore guest r12 (held wrapper_sp)
        "mov r11, qword ptr [rdi + 0x80]",  // guest return RIP -> jump target
        "lea rsp, [rdi + 0x88]",            // guest's original %rsp
        "mov rdi, qword ptr [rdi + 0x48]",  // guest rdi (final use of frame base)
        "xor eax, eax",                     // fork/clone returns 0 in the child
        "jmp r11",

        // ---- Parent ----
        "2:",

        inlateout("rax") ret,
        in("rdi") clone_flags,
        in("rsi") 0usize,           // child_stack == NULL selects fork semantics
        in("rdx") parent_tidptr,
        in("r10") child_tidptr,
        in("r8") tls,
        in("r12") wrapper_sp,
        in("xmm0") vfork_slot,
        clone_vm = const libc::CLONE_VM,
        vfork_flags = const (libc::CLONE_VM | libc::CLONE_VFORK),
        // syscall instructions clobber rcx and r11
        lateout("rcx") _,
        lateout("r11") _,
    }

    ret
}

/// Executes `clone3(2)` while preserving the trampoline return path.
///
/// # Safety
///
/// All pointers and the return address must be valid for the kernel ABI and
/// SaBRe trampoline used by the current guest thread.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-214): Review eager child-start callback ABI.
// TODO-HUMAN-REVIEW(PR-226): Review removal of the pre-pthread child callback.
#[allow(clippy::too_many_arguments)]
pub unsafe fn clone3_syscall(
    arg1: usize,                 // rdi
    arg2: usize,                 // rsi
    arg3: usize,                 // rdx
    unused: usize,               // rcx
    arg5: usize,                 // r8
    ret_addr: *mut libc::c_void, // r9
    clone_flags: u64,            // xmm0 (preserved by syscall)
    vfork_slot: u64,             // xmm1 (preserved by syscall)
) -> usize {
    let mut ret: usize = Sysno::clone3 as usize;

    core::arch::asm! {
        "syscall",

        // Both child and parent return here.
        "test rax, rax",
        "jnz 2f",

        // Child
        "push rdi",
        "push rsi",
        "push rdx",
        "push r10",
        "push r8",
        "push r9",
        "movq rdi, xmm0", // captured clone_args.flags
        "mov rax, rdi",
        "test rax, {clone_vm}",
        "jz 3f",
        "and rax, {vfork_flags}",
        "cmp rax, {vfork_flags}",
        "jne 4f",
        "3:",
        "movq rsi, xmm1",
        "call qword ptr [rip + reverie_sabre_after_clone_child@GOTPCREL]",
        "4:",
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
        "2:",

        inlateout("rax") ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") unused,
        in("r8") arg5,
        in("r9") ret_addr,
        in("xmm0") clone_flags,
        in("xmm1") vfork_slot,
        clone_vm = const libc::CLONE_VM,
        vfork_flags = const (libc::CLONE_VM | libc::CLONE_VFORK),
        // syscall instructions clobber rcx and r11
        lateout("rcx") _,
        lateout("r11") _,

    }

    ret
}

/// Executes a stackless `clone3(2)` and resumes the child on the guest stack.
///
/// This is the clone3 counterpart of [`fork_syscall`]. A zero `clone_args.stack`
/// leaves the child on the plugin call stack, so the child must restore the
/// original SaBRe syscall frame rather than jumping through a trampoline return
/// address on that stack.
///
/// # Safety
///
/// `arg1` must point to the kernel-validated clone arguments and `wrapper_sp`
/// must point to the live SaBRe syscall frame.
#[allow(clippy::too_many_arguments)]
pub unsafe fn clone3_fork_syscall(
    arg1: usize,   // rdi
    arg2: usize,   // rsi
    arg3: usize,   // rdx
    unused: usize, // rcx
    arg5: usize,   // r8
    wrapper_sp: *const syscall_stackframe,
    clone_flags: u64, // xmm0 (preserved by syscall)
    vfork_slot: u64,  // xmm1 (preserved by syscall)
) -> usize {
    let mut ret: usize = Sysno::clone3 as usize;

    core::arch::asm! {
        "syscall",

        // Both child and parent return here.
        "test rax, rax",
        "jnz 2f",

        // ---- Child: never returns through Rust. ----
        "movq rdi, xmm0",
        "mov rax, rdi",
        "test rax, {clone_vm}",
        "jz 3f",
        "and rax, {vfork_flags}",
        "cmp rax, {vfork_flags}",
        "jne 4f",
        "3:",
        "movq rsi, xmm1",
        "call qword ptr [rip + reverie_sabre_after_clone_child@GOTPCREL]",
        "4:",
        "call qword ptr [rip + exit_plugin@GOTPCREL]",
        "mov rdi, r12",                     // rdi = wrapper_sp (frame base)
        "mov r15, qword ptr [rdi + 0x8]",
        "mov r14, qword ptr [rdi + 0x10]",
        "mov r13, qword ptr [rdi + 0x18]",
        "mov r10, qword ptr [rdi + 0x30]",
        "mov r9,  qword ptr [rdi + 0x38]",
        "mov r8,  qword ptr [rdi + 0x40]",
        "mov rsi, qword ptr [rdi + 0x50]",
        "mov rdx, qword ptr [rdi + 0x58]",
        "mov rcx, qword ptr [rdi + 0x60]",
        "mov rbx, qword ptr [rdi + 0x68]",
        "mov rbp, qword ptr [rdi + 0x70]",
        "mov r12, qword ptr [rdi + 0x20]",
        "mov r11, qword ptr [rdi + 0x80]",
        "lea rsp, [rdi + 0x88]",
        "mov rdi, qword ptr [rdi + 0x48]",
        "xor eax, eax",
        "jmp r11",

        // ---- Parent ----
        "2:",

        inlateout("rax") ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") unused,
        in("r8") arg5,
        in("r12") wrapper_sp,
        in("xmm0") clone_flags,
        in("xmm1") vfork_slot,
        clone_vm = const libc::CLONE_VM,
        vfork_flags = const (libc::CLONE_VM | libc::CLONE_VFORK),
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
///
/// # Safety
///
/// `wrapper_sp` must point to the live syscall frame created by SaBRe for the
/// current guest thread.
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
