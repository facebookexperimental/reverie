/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Protection keys: `pkey_alloc(2)`, `pkey_free(2)` and `pkey_mprotect(2)`,
//! answered as Linux answers them on an x86-64 CPU without protection keys.
//!
//! The KVM backend's vCPU is such a CPU, whatever CPUID the Tool reports: it
//! runs with CR4.PKE clear, so OSPKE is clear, and with no PKRU state in
//! XCR0, so `RDPKRU` raises `#UD` (asserted in reverie-kvm's
//! `vm/initial_fpu_state_tests.rs`). Linux there has `arch_max_pkey()` of 1
//! (arch/x86/include/asm/pkeys.h) and marks no key allocated in a new
//! address space: `init_new_context` marks key 0 only with OSPKE
//! (arch/x86/include/asm/mmu_context.h), and `mm_alloc` zeroes the rest of
//! the context, `execute_only_pkey` included (kernel/fork.c). So:
//! - `pkey_alloc` refuses a flag, or an `init_val` bit outside
//!   `PKEY_ACCESS_MASK` (EINVAL). Otherwise `mm_pkey_alloc` takes key 0, the
//!   PKRU setup refuses it (`arch_set_user_pkey_access`, EINVAL,
//!   arch/x86/kernel/fpu/xstate.c), and the free that would undo the take
//!   fails, because key 0 equals the zeroed `execute_only_pkey`, which
//!   `mm_pkey_is_allocated` treats as not allocated. The first such call
//!   therefore answers EINVAL and leaves key 0 taken, and every later one
//!   finds every key taken (ENOSPC). Fork copies that state; exec starts
//!   without it ([`crate::elf::LoadedStaticElf::pkey_zero_claimed`]).
//! - `pkey_free` answers EINVAL for every key: none is allocated.
//! - `pkey_mprotect` with key -1 is `mprotect(2)`, as Linux's is
//!   `do_mprotect_pkey(start, len, prot, -1)`: this executor's mprotect,
//!   which makes Linux's checks in Linux's order and differs from Linux only
//!   where reverie-kvm's README says (a `PROT_GROWSDOWN` change of the
//!   stack, and a range with a hole, refused whole). With any other key it
//!   fails with EINVAL, after the checks `do_mprotect_pkey` makes first:
//!   both `PROT_GROWSDOWN` and `PROT_GROWSUP`, or a start that is not
//!   page-aligned (EINVAL); a zero length (0); a range that wraps (ENOMEM);
//!   a `prot` bit `arch_validate_prot` refuses (EINVAL); and only then the
//!   key, which no address space here has allocated (EINVAL)
//!   (mm/mprotect.c).
//!
//! No key ever exists, so no page here carries one, and nothing the guest
//! can do makes a protection key withhold memory from it.

use super::*;

/// `PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE`, the bits `pkey_alloc` accepts
/// in `init_val` on x86 (include/uapi/asm-generic/mman-common.h).
const PKEY_ACCESS_MASK: u64 = 0x3;

/// `pkey_alloc(flags, init_val)` without protection keys.
pub(super) fn pkey_alloc(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // TODO-HUMAN-REVIEW(PR-id): Review the answers of a CPU without protection keys.
    let (flags, init_val) = (args[0], args[1]);
    if flags != 0 || init_val & !PKEY_ACCESS_MASK != 0 {
        return negative_errno(libc::EINVAL);
    }
    // `mm_pkey_alloc` finds key 0 free once per address space; the PKRU
    // setup then refuses it, and it stays taken.
    if state.pkey_zero_claimed.swap(true, Ordering::SeqCst) {
        negative_errno(libc::ENOSPC)
    } else {
        negative_errno(libc::EINVAL)
    }
}

/// `pkey_free(pkey)` without protection keys: no key is allocated.
pub(super) fn pkey_free(_args: &[u64; 6]) -> i64 {
    // TODO-HUMAN-REVIEW(PR-id): Review the answers of a CPU without protection keys.
    negative_errno(libc::EINVAL)
}

/// `pkey_mprotect(start, len, prot, pkey)` without protection keys.
pub(super) fn pkey_mprotect(memory: &ProviderMemory<'_>, args: &[u64; 6]) -> i64 {
    // TODO-HUMAN-REVIEW(PR-id): Review the answers of a CPU without protection keys.
    // The key is an `int`: Linux reads the register's low 32 bits.
    if args[3] as u32 as i32 == -1 {
        return mprotect(memory, args);
    }
    let (start, len, prot) = (args[0], args[1], args[2]);
    let grows = (libc::PROT_GROWSDOWN | libc::PROT_GROWSUP) as u64;
    if prot & grows == grows || !start.is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    if len == 0 {
        return 0;
    }
    // `PAGE_ALIGN(len)` and `start + len`, both modulo 2^64.
    let end = start.wrapping_add(len.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1));
    if end <= start {
        return negative_errno(libc::ENOMEM);
    }
    // `arch_validate_prot` refuses a bit other than `PROT_READ`, `PROT_WRITE`,
    // `PROT_EXEC` and `PROT_SEM` (EINVAL), and the key, never allocated here,
    // is refused next (EINVAL): either way the call fails with EINVAL.
    negative_errno(libc::EINVAL)
}
