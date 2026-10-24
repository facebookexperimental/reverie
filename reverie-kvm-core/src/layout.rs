/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The fixed guest-physical address map of the KVM guest and its user
//! address limit: the boot area (page tables, descriptor tables, syscall
//! transports, the vDSO page and Tool scratch pages) below
//! [`BOOT_RESERVED_END`], and [`GUEST_USER_ADDRESS_LIMIT`]. Moved unchanged
//! from reverie-kvm's bootstrap and executor modules (step U6b-1 of the
//! provider seam), so that the guest arena and the Linux syscall emulator can
//! later move below reverie-kvm and still share one address map with it.

pub const PAGE_SIZE: u64 = 4096;
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
pub const PAGE_DIRECTORY_SPAN: u64 = 1024 * 1024 * 1024;
pub const PAGE_DIRECTORY_ADDRESSES: [u64; 3] = [0x4000, 0x9000, 0xe000];
pub const FIRST_PAGE_TABLE_ADDRESS: u64 = 0;
pub const MAX_IDENTITY_MAP: u64 = PAGE_DIRECTORY_SPAN * PAGE_DIRECTORY_ADDRESSES.len() as u64;

pub const GDT_ADDRESS: u64 = 0x1000;
pub const PML4_ADDRESS: u64 = 0x2000;
pub const PDPT_ADDRESS: u64 = 0x3000;
pub const SYSCALL_TRAMPOLINE_ADDRESS: u64 = 0x5000;
pub const SYSCALL_FRAME_ADDRESS: u64 = 0x6000;
pub const PROGRAM_HEADERS_ADDRESS: u64 = 0x7000;
pub const TSS_ADDRESS: u64 = 0x8000;
pub const IDT_ADDRESS: u64 = 0xa000;
pub const EXCEPTION_STUB_ADDRESS: u64 = 0xb000;
pub const EXCEPTION_STACK_BOTTOM: u64 = 0xc000;
pub const EXCEPTION_STACK_TOP: u64 = 0xd000;
pub const TOOL_STACK_TOP: u64 = 0xe000;
pub const TOOL_STACK_SIZE: u64 = PAGE_SIZE;
// Includes the 0xe000..0xf000 third page directory and 160 private
// trampoline/frame pairs used by concurrent KVM guest threads.
// AUTONOMOUS-BOT-IMPLEMENTED: Reserve transport slots for savevm worker pools.
// TODO-HUMAN-REVIEW(PR-173): Review the bounded per-thread transport layout.
pub const THREAD_SYSCALL_AREA_START: u64 = 0xf000;
pub const THREAD_SYSCALL_AREA_STRIDE: u64 = 2 * PAGE_SIZE;
pub const MAX_GUEST_THREADS: u64 = 160;
// AUTONOMOUS-BOT-IMPLEMENTED: Provide a kernel-note vDSO for glibc os-version discovery.
// TODO-HUMAN-REVIEW(PR-266): Review the guest vDSO placement and note contents.
// A single read-only page holding the canonical vDSO
// (`reverie::vdso::canonical_vdso_image`), the image every backend maps in
// place of the host kernel's. glibc's loader reaches it through
// `AT_SYSINFO_EHDR`, reads its kernel-version note (`_dl_discover_osversion`)
// instead of calling `uname(2)`, and looks up its functions, each a stub that
// issues the syscall. The page sits inside the boot-reserved region (below
// `BOOT_RESERVED_END`), so guest brk/mmap never allocate over it and the
// user-memory zeroing leaves it intact. It is covered by the identity map
// (present + user, executable), so the guest reads and runs it directly
// without an executor round-trip.
pub const VDSO_ADDRESS: u64 =
    THREAD_SYSCALL_AREA_START + THREAD_SYSCALL_AREA_STRIDE * MAX_GUEST_THREADS;
// Keep the established syscall-transport and vDSO addresses unchanged. Each
// worker gets one Tool scratch page after the vDSO, indexed by the same slot
// that owns its private syscall transport.
pub const THREAD_TOOL_STACK_AREA_START: u64 = VDSO_ADDRESS + PAGE_SIZE;
// The pool of page-table pages that map the user windows (`install_user_windows`):
// the stack window below TASK_SIZE, the mmap window below mmap_base, a PIE
// main image's window at ELF_ET_DYN_BASE, and the split of an identity large
// page that straddles the identity limit. 15 pages keep BOOT_RESERVED_END below
// 2 MiB, where images load.
pub const WINDOW_TABLE_POOL_ADDRESS: u64 =
    THREAD_TOOL_STACK_AREA_START + TOOL_STACK_SIZE * MAX_GUEST_THREADS;
pub const WINDOW_TABLE_POOL_PAGES: u64 = 15;
pub const BOOT_RESERVED_END: u64 = WINDOW_TABLE_POOL_ADDRESS + WINDOW_TABLE_POOL_PAGES * PAGE_SIZE;
const _: () = {
    assert!(TOOL_STACK_TOP <= THREAD_SYSCALL_AREA_START);
    assert!(
        THREAD_SYSCALL_AREA_START + THREAD_SYSCALL_AREA_STRIDE * MAX_GUEST_THREADS <= VDSO_ADDRESS
    );
    assert!(VDSO_ADDRESS + PAGE_SIZE <= THREAD_TOOL_STACK_AREA_START);
    assert!(VDSO_ADDRESS == reverie::vdso::CANONICAL_VDSO_ADDRESS);
    assert!(reverie::vdso::CANONICAL_VDSO_SIZE <= PAGE_SIZE);
};

/// The guest's user address limit, which the executor's range checks
/// enforce.
pub const X86_64_GUEST_USER_LIMIT: u64 = (1_u64 << 47) - PAGE_SIZE;
/// The range rule `KvmGuest` reports as `Guest::user_address_limit`: the
/// executor's limit, and its vectored-I/O import (`decode_guest_iovecs`)
/// shortens a lone vector to `MAX_RW_COUNT` before checking it.
pub const GUEST_USER_ADDRESS_LIMIT: reverie::UserAddressLimit = reverie::UserAddressLimit {
    max_end: X86_64_GUEST_USER_LIMIT,
    caps_single_vector: true,
};
