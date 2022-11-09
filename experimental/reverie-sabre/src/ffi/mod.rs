/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![allow(non_camel_case_types)]

mod clone;

pub use clone::clone3_syscall;
pub use clone::clone_syscall;
pub use clone::vfork_return_from_child;
pub use clone::vfork_syscall;

extern "C" {
    pub fn calling_from_plugin() -> bool;
    pub fn enter_plugin();
    pub fn exit_plugin();
    pub fn is_vdso_ready() -> bool;
}

pub type vdso_clock_gettime_fn =
    extern "C" fn(clockid: libc::clockid_t, tp: *mut libc::timespec) -> i32;
pub type vdso_getcpu_fn = extern "C" fn(cpu: *mut u32, node: *mut u32, _unused: usize) -> i32;
pub type vdso_gettimeofday_fn =
    extern "C" fn(tv: *mut libc::timeval, tz: *mut libc::timezone) -> i32;
pub type vdso_time_fn = extern "C" fn(tloc: *mut libc::time_t) -> i32;

pub extern "C" fn vdso_clock_gettime_stub(
    _clockid: libc::clockid_t,
    _tp: *mut libc::timespec,
) -> i32 {
    // HACK: These are never called, but referencing these functions ensures
    // they get linked into our binary. These are actually used by the loader.
    unsafe { calling_from_plugin() };
    unsafe { enter_plugin() };
    unsafe { exit_plugin() };
    unsafe { is_vdso_ready() };

    -libc::EFAULT
}

pub extern "C" fn vdso_getcpu_stub(_cpu: *mut u32, _node: *mut u32, _unused: usize) -> i32 {
    -libc::EFAULT
}

pub extern "C" fn vdso_gettimeofday_stub(_tv: *mut libc::timeval, _tz: *mut libc::timezone) -> i32 {
    -libc::EFAULT
}

pub extern "C" fn vdso_time_stub(_tloc: *mut libc::time_t) -> i32 {
    -libc::EFAULT
}

pub type void_void_fn = unsafe extern "C" fn() -> *mut libc::c_void;

#[repr(C)]
pub struct fn_icept {
    pub lib_name: *const libc::c_char,
    pub fn_name: *const libc::c_char,
    pub icept_callback: extern "C" fn(void_void_fn) -> void_void_fn,
}

pub type icept_reg_fn = extern "C" fn(*const fn_icept);

unsafe impl Send for fn_icept {}
unsafe impl Sync for fn_icept {}
#[repr(C)]
pub struct syscall_stackframe {
    pub rbp_stackalign: *mut libc::c_void,
    pub r15: *mut libc::c_void,
    pub r14: *mut libc::c_void,
    pub r13: *mut libc::c_void,
    pub r12: *mut libc::c_void,
    pub r11: *mut libc::c_void,
    pub r10: *mut libc::c_void,
    pub r9: *mut libc::c_void,
    pub r8: *mut libc::c_void,
    pub rdi: *mut libc::c_void,
    pub rsi: *mut libc::c_void,
    pub rdx: *mut libc::c_void,
    pub rcx: *mut libc::c_void,
    pub rbx: *mut libc::c_void,
    pub rbp_prologue: *mut libc::c_void,
    // trampoline
    pub fake_ret: *mut libc::c_void,
    /// Syscall return address. This is where execution should continue after a
    /// syscall has been handled.
    pub ret: *mut libc::c_void,
}

pub type handle_syscall_fn = extern "C" fn(
    syscall: isize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    wrapper_sp: *mut syscall_stackframe,
) -> usize;

pub type handle_vdso_fn =
    extern "C" fn(syscall: isize, actual_fn: void_void_fn) -> Option<void_void_fn>;

pub type handle_rdtsc_fn = extern "C" fn() -> u64;

pub type post_load_fn = extern "C" fn(bool);

/// A struct of arguments for the clone3 syscall.
#[derive(Debug)]
#[repr(C)]
pub struct clone_args {
    // Flags bit mask
    pub flags: u64,
    // Where to store PID file descriptor (int *)
    pub pidfd: u64,
    // Where to store child TID, in child's memory (pid_t *)
    pub child_tid: u64,
    // Where to store child TID, in parent's memory (pid_t *)
    pub parent_tid: u64,
    // Signal to deliver to parent on child termination
    pub exit_signal: u64,
    // Pointer to lowest byte of stack
    pub stack: u64,
    // Size of stack
    pub stack_size: u64,
    // Location of new TLS
    pub tls: u64,
    // Pointer to a pid_t array (since Linux 5.5)
    pub set_tid: u64,
    // Number of elements in set_tid (since Linux 5.5)
    pub set_tid_size: u64,
    // File descriptor for target cgroup of child (since Linux 5.7)
    pub cgroup: u64,
}
