/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests of the machine's bootstrap (reverie-kvm-core's `bootstrap`) that
//! check it against LinuxEmu's signal frame and memory layout.

use reverie_kvm_core::bootstrap::*;
use reverie_kvm_core::syscall::RETURN_FLAGS_WORD;
use reverie_kvm_core::syscall::RETURN_RIP_WORD;
use reverie_kvm_core::syscall::SAVED_RBX_WORD;

use crate::GuestMemory;
use crate::SyscallRequest;

#[test]
fn signal_context_uses_transport_frame_not_poisoned_trampoline_registers() {
    const FRAME: u64 = 0x1000;
    let mut memory = GuestMemory::new(0, 0x4000).unwrap();
    let request = SyscallRequest::new(libc::SYS_kill as u64, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    request.write_to(&mut memory, FRAME).unwrap();
    memory
        .write_raw(
            frame_word_address_u64(FRAME, RETURN_RIP_WORD),
            &0x1234_5678_u64.to_le_bytes(),
        )
        .unwrap();
    memory
        .write_raw(
            frame_word_address_u64(FRAME, RETURN_FLAGS_WORD),
            &0x202_u64.to_le_bytes(),
        )
        .unwrap();
    memory
        .write_raw(
            frame_word_address_u64(FRAME, SAVED_RBX_WORD),
            &0x7777_u64.to_le_bytes(),
        )
        .unwrap();
    let live = kvm_bindings::kvm_regs {
        rax: u64::MAX,
        rbx: u64::MAX,
        rcx: u64::MAX,
        rdx: u64::MAX,
        rsi: u64::MAX,
        r12: 0x1212,
        rsp: 0x7fff_f000,
        ..Default::default()
    };
    let restored = process_syscall_return_registers(&memory, live, FRAME, 0, None).unwrap();
    let context = crate::signal::Sigcontext::from_kvm(
        restored,
        0x7fff_e000,
        crate::signal::KernelSigset::default(),
    );
    assert_eq!(
        (context.rax, context.rdi, context.rsi, context.rdx),
        (0, 0x11, 0x22, 0x33)
    );
    assert_eq!((context.r10, context.r8, context.r9), (0x44, 0x55, 0x66));
    assert_eq!(
        (context.rbx, context.rip, context.rflags),
        (0x7777, 0x1234_5678, 0x202)
    );
}

/// The guest-physical address the page tables map `address` to, walking
/// them as the CPU does.
fn walk(memory: &GuestMemory, address: u64) -> Option<u64> {
    const MASK: u64 = 0x000f_ffff_ffff_f000;
    let index = |shift: u32| ((address >> shift) & 511) * 8;
    let pml4 = read_u64(memory, PML4_ADDRESS + index(39)).unwrap();
    if pml4 & 1 == 0 {
        return None;
    }
    let pdpt = read_u64(memory, (pml4 & MASK) + index(30)).unwrap();
    if pdpt & 1 == 0 {
        return None;
    }
    let directory = read_u64(memory, (pdpt & MASK) + index(21)).unwrap();
    if directory & 1 == 0 {
        return None;
    }
    if directory & 0x80 != 0 {
        return Some(
            (directory & MASK & !(LARGE_PAGE_SIZE - 1)) | (address & (LARGE_PAGE_SIZE - 1)),
        );
    }
    let table = read_u64(memory, (directory & MASK) + index(12)).unwrap();
    (table & 1 != 0).then_some((table & MASK) | (address & (PAGE_SIZE - 1)))
}

/// A new layout's page tables replace the old one's whole: an identity end
/// raised by a larger image maps the identity pages the old window held,
/// and lowering it again unmaps them.
#[test]
fn page_tables_follow_an_identity_end_that_moves_both_ways() {
    const MIB: u64 = 1024 * 1024;
    let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
    write_page_tables(&mut memory).unwrap();
    for main_end in [3 * MIB, 48 * MIB, 3 * MIB] {
        memory.clear_user_layout();
        crate::elf::establish_linux_layout(&mut memory, main_end, MIB, None)
            .unwrap()
            .unwrap();
        map_user_stack_window(&mut memory, 8 * MIB).unwrap();
        let (windows, identity_end) = memory.user_layout();
        assert_eq!(windows.len(), 2);
        for address in (PAGE_SIZE..identity_end).step_by(PAGE_SIZE as usize) {
            assert_eq!(walk(&memory, address), Some(address), "{address:#x}");
        }
        for address in (identity_end..memory.guest_end()).step_by(PAGE_SIZE as usize) {
            assert_eq!(walk(&memory, address), None, "{address:#x}");
        }
        for window in &windows {
            for user in (window.user_start..window.user_end).step_by(PAGE_SIZE as usize) {
                assert_eq!(walk(&memory, user), Some(window.physical(user)));
            }
        }
    }
}
