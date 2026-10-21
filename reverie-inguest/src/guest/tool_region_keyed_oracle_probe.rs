/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Observer and literal MOVs stay on key zero, outside the SUT reservation.

use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use super::Observation;
use super::Span;
use super::raw;
use super::raw_exit;

core::arch::global_asm!(include_str!("tool_region_keyed_oracle_probe.S"));

unsafe extern "C" {
    fn reverie_keyed_oracle_load(target: usize, rights: u32, restored: *mut u32) -> u8;
    fn reverie_keyed_oracle_store(target: usize, rights: u32, byte: u32, restored: *mut u32);
    static reverie_keyed_oracle_load_mov: u8;
    static reverie_keyed_oracle_store_mov: u8;
    fn reverie_keyed_oracle_sigreturn();
}

static CURRENT: AtomicPtr<Observation> = AtomicPtr::new(core::ptr::null_mut());

pub(super) fn supported() -> bool {
    // Native x86-64 CPUID is available before any PKRU instruction.
    core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) != 0
}

pub(super) fn rights() -> u32 {
    let value: u32;
    // SAFETY: all callers first check native OSPKE. Read has no memory access.
    unsafe {
        core::arch::asm!("rdpkru", in("ecx") 0_u32, out("eax") value,
            out("edx") _, options(nostack, preserves_flags));
    }
    value
}

pub(super) fn instruction(write: bool) -> usize {
    // These linked assembly symbols name bytes, not Rust objects.
    if write {
        core::ptr::addr_of!(reverie_keyed_oracle_store_mov) as usize
    } else {
        core::ptr::addr_of!(reverie_keyed_oracle_load_mov) as usize
    }
}

#[repr(C)]
struct KernelAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

extern "C" fn observe(signal: i32, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let record = CURRENT.load(Ordering::Relaxed);
    if record.is_null() || info.is_null() || context.is_null() {
        raw_exit(92);
    }
    // SAFETY: Linux delivered SA_SIGINFO buffers. All record storage is the
    // separately mapped key-zero shared report; no protected owner is read.
    unsafe {
        let frame = context.cast::<libc::ucontext_t>();
        core::ptr::addr_of_mut!((*record).signal).write_volatile(signal);
        core::ptr::addr_of_mut!((*record).code).write_volatile((*info).si_code);
        core::ptr::addr_of_mut!((*record).address).write_volatile((*info).si_addr() as usize);
        core::ptr::addr_of_mut!((*record).rip)
            .write_volatile((*frame).uc_mcontext.gregs[libc::REG_RIP as usize] as usize);
        core::ptr::addr_of_mut!((*record).kind).write_volatile(2);
    }
    raw_exit(0);
}

fn install(record: *mut Observation, stack: Span) -> i64 {
    CURRENT.store(record, Ordering::Relaxed);
    let action = KernelAction {
        handler: observe as *const () as usize,
        flags: (libc::SA_SIGINFO | libc::SA_ONSTACK) as usize | 0x0400_0000,
        restorer: reverie_keyed_oracle_sigreturn as *const () as usize,
        mask: 0,
    };
    let alternate = libc::stack_t {
        ss_sp: stack.bottom as *mut libc::c_void,
        ss_flags: 0,
        ss_size: stack.top - stack.bottom,
    };
    let mask = 0_u64;
    for (number, args) in [
        (
            libc::SYS_sigaltstack,
            [&alternate as *const libc::stack_t as u64, 0, 0, 0, 0, 0],
        ),
        (
            libc::SYS_rt_sigaction,
            [
                libc::SIGSEGV as u64,
                &action as *const KernelAction as u64,
                0,
                8,
                0,
                0,
            ],
        ),
        (
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_SETMASK as u64,
                &mask as *const u64 as u64,
                0,
                8,
                0,
                0,
            ],
        ),
    ] {
        let result = raw(number, args);
        if result != 0 {
            return result;
        }
    }
    0
}

pub(super) fn child(
    record: *mut Observation,
    stack: Span,
    target: usize,
    mask: u32,
    write: bool,
    original: u8,
) -> ! {
    let prepared = install(record, stack);
    if prepared != 0 {
        // SAFETY: this child's key-zero shared record is live until wait4.
        unsafe {
            core::ptr::addr_of_mut!((*record).setup_errno).write_volatile(-prepared as i32);
            core::ptr::addr_of_mut!((*record).kind).write_volatile(4);
        }
        raw_exit(91);
    }
    let before = rights();
    let mut restored = 0_u32;
    // SAFETY: only this disposable child probes the verified literal target.
    // The single target MOV is assembly, never an invalid Rust reference.
    let value = unsafe {
        if write {
            reverie_keyed_oracle_store(target, mask, u32::from(original), &mut restored);
            core::ptr::read_volatile(target as *const u8)
        } else {
            reverie_keyed_oracle_load(target, mask, &mut restored)
        }
    };
    // SAFETY: this record is outside every target and remains on key zero.
    unsafe {
        core::ptr::addr_of_mut!((*record).pkru_before).write_volatile(before);
        core::ptr::addr_of_mut!((*record).pkru_after).write_volatile(restored);
        core::ptr::addr_of_mut!((*record).byte_observed).write_volatile(value);
        core::ptr::addr_of_mut!((*record).byte_after)
            .write_volatile(core::ptr::read_volatile(target as *const u8));
        core::ptr::addr_of_mut!((*record).kind).write_volatile(1);
    }
    raw_exit(0);
}
