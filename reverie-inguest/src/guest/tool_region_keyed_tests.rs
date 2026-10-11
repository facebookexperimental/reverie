/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Lifetime/failure regressions, separate from the frozen physical oracle.
//! Setup happens in raw-fork process leaders. They use raw syscalls/scalars,
//! never the test harness, libc allocation or unwinding. Only the enclosing
//! exact self-reexec test asserts and reports their bounded exit statuses.

use core::cell::Cell;

use super::super::keyed;
use super::super::keyed::NativeCalls;
use super::*;

fn leader(body: fn() -> Result<(), i32>) {
    // Own every known waitable PID even if the launcher inherited SIG_IGN or
    // SA_NOCLDWAIT. No unrelated child can consume these statuses.
    let action = KernelAction {
        handler: libc::SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    assert_eq!(
        raw(
            libc::SYS_rt_sigaction,
            [libc::SIGCHLD as u64, &action as *const _ as u64, 0, 8, 0, 0]
        ),
        0
    );
    let child = raw(libc::SYS_fork, [0; 6]);
    assert!(child >= 0, "leader fork failed: {child}");
    if child == 0 {
        prepare_fault_child();
        let code = match body() {
            Ok(()) => 0,
            Err(code) => code,
        };
        raw_exit(code);
    }
    let status = wait_raw(child);
    assert!(libc::WIFEXITED(status), "leader faulted: {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), 0, "leader failure code");
}

fn check(condition: bool, code: i32) -> Result<(), i32> {
    if condition { Ok(()) } else { Err(code) }
}

fn owner() -> Result<&'static KeyedToolRegion, i32> {
    // Unsupported/ENOSPC/setup errors fail this selected hardware case; none
    // is a skipped regression or physical-denial qualification.
    unsafe { KeyedToolRegion::reserve_native() }.map_err(|_| 91)
}

fn lease(owner: &'static KeyedToolRegion, bytes: usize) -> Result<KeyedStackLease, i32> {
    unsafe { owner.lease_stack(bytes) }.map_err(|_| 92)
}

fn rights() -> u32 {
    let value;
    unsafe {
        core::arch::asm!("rdpkru", in("ecx") 0_u32, out("eax") value, out("edx") _, options(nostack, preserves_flags))
    };
    value
}

fn set_rights(value: u32) {
    unsafe {
        core::arch::asm!("wrpkru", "lfence", in("eax") value, in("ecx") 0_u32, in("edx") 0_u32, options(nostack, preserves_flags))
    };
}

fn now() -> Result<u64, i32> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    check(
        raw(
            libc::SYS_clock_gettime,
            [
                libc::CLOCK_MONOTONIC as u64,
                &mut time as *mut _ as u64,
                0,
                0,
                0,
                0,
            ],
        ) == 0,
        93,
    )?;
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

fn bounded_wait(pid: i64) -> Result<i32, i32> {
    let deadline = now()? + 3_000_000_000;
    let mut killed = false;
    let mut cleanup_deadline = deadline;
    loop {
        let mut status = 0_i32;
        let result = raw(
            libc::SYS_wait4,
            [
                pid as u64,
                &mut status as *mut _ as u64,
                libc::WNOHANG as u64,
                0,
                0,
                0,
            ],
        );
        if result == pid {
            return if killed { Err(94) } else { Ok(status) };
        }
        check(result == 0 || result == -i64::from(libc::EINTR), 95)?;
        let time = now()?;
        if !killed && time >= deadline {
            check(
                raw(
                    libc::SYS_kill,
                    [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
                ) == 0,
                96,
            )?;
            killed = true;
            cleanup_deadline = time + 3_000_000_000;
        }
        check(!killed || time < cleanup_deadline, 97)?;
        let pause = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        let result = raw(
            libc::SYS_nanosleep,
            [&pause as *const _ as u64, 0, 0, 0, 0, 0],
        );
        check(result == 0 || result == -i64::from(libc::EINTR), 98)?;
    }
}

fn child_ok(pid: i64) -> Result<(), i32> {
    check(pid > 0, 99)?;
    let status = bounded_wait(pid)?;
    check(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        100,
    )
}

fn free_key(key: u32) -> Result<(), i32> {
    check(
        raw(libc::SYS_pkey_free, [u64::from(key), 0, 0, 0, 0, 0]) == 0,
        101,
    )
}

fn keys() -> Result<([u32; 15], usize), i32> {
    check(keyed::Native.ospke(), 102)?;
    let mut result = [0; 15];
    let mut count = 0;
    loop {
        let key = raw(libc::SYS_pkey_alloc, [0; 6]);
        if key == -i64::from(libc::ENOSPC) {
            return Ok((result, count));
        }
        check((1..=15).contains(&key) && count < result.len(), 103)?;
        check(!result[..count].contains(&(key as u32)), 104)?;
        result[count] = key as u32;
        count += 1;
    }
}

fn held_key_stays_owned(key: u32) -> Result<(), i32> {
    let entry = rights();
    let (allocated, count) = keys()?;
    check(!allocated[..count].contains(&key), 105)?;
    for &number in &allocated[..count] {
        free_key(number)?;
    }
    set_rights(entry);
    Ok(())
}

fn anonymous_at(address: usize, bytes: usize) -> i64 {
    raw(
        libc::SYS_mmap,
        [
            address as u64,
            bytes as u64,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
            u64::MAX,
            0,
        ],
    )
}

fn hex(bytes: &[u8]) -> Option<usize> {
    let mut result = 0_usize;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return None,
        };
        result = result.checked_mul(16)?.checked_add(usize::from(digit))?;
    }
    Some(result)
}

// Complete bounded smaps observation, supplemental to the unchanged hardware
// oracle. No returned Rust label is used to establish reset guard keys.
fn vma(address: usize) -> Result<(bool, u32), i32> {
    let path = b"/proc/self/smaps\0";
    let fd = raw(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as u64,
            path.as_ptr() as u64,
            (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            0,
            0,
            0,
        ],
    );
    check(fd >= 0, 106)?;
    let mut input = [0_u8; 4096];
    let mut line = [0_u8; 1024];
    let mut length = 0;
    let mut consumed = 0;
    let mut matched = false;
    let mut writable = false;
    let mut observed = None;
    let result = (|| {
        loop {
            let count = raw(
                libc::SYS_read,
                [
                    fd as u64,
                    input.as_mut_ptr() as u64,
                    input.len() as u64,
                    0,
                    0,
                    0,
                ],
            );
            if count == -i64::from(libc::EINTR) {
                continue;
            }
            check(count >= 0, 107)?;
            if count == 0 {
                break;
            }
            consumed += count as usize;
            check(consumed <= 8 * 1024 * 1024, 108)?;
            for &byte in &input[..count as usize] {
                if byte != b'\n' {
                    check(length < line.len(), 109)?;
                    line[length] = byte;
                    length += 1;
                    continue;
                }
                let text = &line[..length];
                if let Some(dash) = text.iter().position(|&c| c == b'-')
                    && let Some(low) = hex(&text[..dash])
                {
                    let space = text.iter().position(|&c| c == b' ').ok_or(110)?;
                    let high = hex(&text[dash + 1..space]).ok_or(111)?;
                    check(!matched || observed.is_some(), 112)?;
                    matched = low <= address && address < high;
                    if matched {
                        check(space + 4 < text.len(), 113)?;
                        writable = &text[space + 1..space + 4] == b"rw-";
                        check(writable || &text[space + 1..space + 4] == b"---", 114)?;
                    }
                }
                if matched && text.starts_with(b"ProtectionKey:") {
                    let mut value = 0_u32;
                    let mut digits = 0;
                    for &c in &text[b"ProtectionKey:".len()..] {
                        if c == b' ' || c == b'\t' {
                            continue;
                        }
                        check(c.is_ascii_digit(), 115)?;
                        value = value
                            .checked_mul(10)
                            .and_then(|v| v.checked_add(u32::from(c - b'0')))
                            .ok_or(116)?;
                        digits += 1;
                    }
                    check(digits != 0 && observed.is_none(), 117)?;
                    observed = Some((writable, value));
                }
                length = 0;
            }
        }
        check(length == 0, 118)?;
        observed.ok_or(119)
    })();
    check(raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) == 0, 120)?;
    result
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn collision_preserves_occupant_and_retains_failure() {
    isolated(
        "keyed_owner::collision_preserves_occupant_and_retains_failure",
        || {
            leader(|| {
                check(keyed::Native.ospke(), 1)?;
                let entry = rights();
                let (before, capacity) = keys()?;
                check(capacity > 0, 2)?;
                for &key in &before[..capacity] {
                    free_key(key)?;
                }
                set_rights(entry);
                check(anonymous_at(BASE + PAGE, PAGE) == (BASE + PAGE) as i64, 3)?;
                unsafe { (BASE as *mut u8).add(PAGE).write_volatile(0x73) };
                let error = unsafe { KeyedToolRegion::reserve_native() }
                    .err()
                    .ok_or(4)?;
                check(
                    error.kind == KeyedPrepareKind::Native
                        && error.errno == libc::EEXIST
                        && error.cleanup_errno.is_none()
                        && error.quarantine.is_none(),
                    5,
                )?;
                check(
                    rights() == entry
                        && unsafe { ((BASE + PAGE) as *const u8).read_volatile() } == 0x73,
                    6,
                )?;
                check(vma(BASE + PAGE)? == (true, 0), 7)?;
                let (after, count) = keys()?;
                check(count == capacity, 8)?;
                for &key in &after[..count] {
                    free_key(key)?;
                }
                set_rights(entry);
                check(
                    raw(
                        libc::SYS_munmap,
                        [(BASE + PAGE) as u64, PAGE as u64, 0, 0, 0, 0],
                    ) == 0,
                    9,
                )?;
                check(
                    unsafe { KeyedToolRegion::reserve_native() }.err() == Some(error),
                    10,
                )?;
                check(resident_query(BASE + PAGE) == -i64::from(libc::ENOMEM), 11)
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn actual_key_exhaustion_is_retained_without_mapping() {
    isolated(
        "keyed_owner::actual_key_exhaustion_is_retained_without_mapping",
        || {
            leader(|| {
                check(keyed::Native.ospke(), 1)?;
                let entry = rights();
                let (allocated, count) = keys()?;
                check(count > 0, 2)?;
                set_rights(entry);
                let error = unsafe { KeyedToolRegion::reserve_native() }
                    .err()
                    .ok_or(3)?;
                check(
                    error.kind == KeyedPrepareKind::KeyExhausted
                        && error.errno == libc::ENOSPC
                        && error.quarantine.is_none(),
                    4,
                )?;
                check(
                    rights() == entry && resident_query(BASE + PAGE) == -i64::from(libc::ENOMEM),
                    5,
                )?;
                for &key in &allocated[..count] {
                    free_key(key)?;
                }
                check(
                    unsafe { KeyedToolRegion::reserve_native() }.err() == Some(error),
                    6,
                )
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn reuse_resets_keys_and_retention_keeps_owner_key() {
    isolated(
        "keyed_owner::reuse_resets_keys_and_retention_keeps_owner_key",
        || {
            leader(|| {
                let owner = owner()?;
                check(
                    published_owner().is_none() && fixed_arena_backing().is_none(),
                    1,
                )?;
                check(
                    unsafe { owner.lease_stack(0) }
                        .err()
                        .is_some_and(|e| e.errno == libc::EINVAL),
                    2,
                )?;
                check(
                    unsafe { owner.lease_stack(usize::MAX) }
                        .err()
                        .is_some_and(|e| e.errno == libc::EINVAL),
                    3,
                )?;
                let large = lease(owner, 4 * PAGE)?;
                let base = large.base();
                for offset in 0..large.usable_bytes() {
                    unsafe { ((base + offset) as *mut u8).write_volatile(0x4d) };
                }
                drop(large);
                let small = lease(owner, PAGE)?;
                check(small.belongs_to(owner) && small.base() == base, 4)?;
                for offset in 0..PAGE {
                    check(
                        unsafe { ((base + offset) as *const u8).read_volatile() } == 0,
                        5,
                    )?;
                }
                check(vma(base)? == (true, owner.key_descriptor().value()), 6)?;
                for guard in [base - PAGE, small.top(), base + 3 * PAGE] {
                    check(vma(guard)? == (false, 0), 7)?;
                }
                unsafe { (small.base() as *mut u8).write_volatile(0x35) };
                let retained = small.retain();
                let next = lease(owner, 2 * PAGE)?;
                check(
                    retained.belongs_to(owner) && next.base() - PAGE >= retained.top() + PAGE,
                    8,
                )?;
                drop(next);
                held_key_stays_owned(owner.key_descriptor().value())?;
                check(
                    unsafe { (retained.base() as *const u8).read_volatile() } == 0x35,
                    9,
                )
            })
        },
    );
}

fn deny_discard() -> Result<(), i32> {
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_madvise as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    check(
        raw(
            libc::SYS_prctl,
            [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0],
        ) == 0,
        121,
    )?;
    check(
        raw(
            libc::SYS_seccomp,
            [
                libc::SECCOMP_SET_MODE_FILTER as u64,
                0,
                &program as *const _ as u64,
                0,
                0,
                0,
            ],
        ) == 0,
        122,
    )
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn actual_reset_and_discard_failures_quarantine_extents() {
    isolated(
        "keyed_owner::actual_reset_and_discard_failures_quarantine_extents",
        || {
            leader(|| {
                let owner = owner()?;
                let reset = lease(owner, 2 * PAGE)?;
                let reset_base = reset.base();
                let reset_top = reset.top();
                check(
                    raw(
                        libc::SYS_munmap,
                        [reset_base as u64, PAGE as u64, 0, 0, 0, 0],
                    ) == 0,
                    1,
                )?;
                let error = unsafe { reset.release() }.err().ok_or(2)?;
                check(
                    error.stage == KeyedLeaseStage::Reset
                        && error.errno == libc::ENOMEM
                        && error.quarantined,
                    3,
                )?;
                let discard = lease(owner, 2 * PAGE)?;
                check(discard.base() - PAGE >= reset_top + PAGE, 4)?;
                let discard_base = discard.base();
                let discard_top = discard.top();
                unsafe { (discard_base as *mut u8).write_volatile(0x64) };
                deny_discard()?;
                check(
                    raw(
                        libc::SYS_madvise,
                        [
                            discard_base as u64,
                            PAGE as u64,
                            libc::MADV_DONTNEED as u64,
                            0,
                            0,
                            0,
                        ],
                    ) == -i64::from(libc::EPERM),
                    5,
                )?;
                let error = unsafe { discard.release() }.err().ok_or(6)?;
                check(
                    error.stage == KeyedLeaseStage::Discard
                        && error.errno == libc::EPERM
                        && error.quarantined,
                    7,
                )?;
                check(vma(discard_base)? == (false, 0), 8)?;
                let next = lease(owner, PAGE)?;
                check(next.base() - PAGE >= discard_top + PAGE, 9)?;
                let _retained = next.retain();
                held_key_stays_owned(owner.key_descriptor().value())
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn actual_unmapped_interior_quarantines_failed_lease_rollback() {
    isolated(
        "keyed_owner::actual_unmapped_interior_quarantines_failed_lease_rollback",
        || {
            leader(|| {
                let owner = owner()?;
                let first = BASE + CONTROL_BYTES + PAGE;
                check(
                    raw(libc::SYS_munmap, [first as u64, PAGE as u64, 0, 0, 0, 0]) == 0,
                    1,
                )?;
                let error = unsafe { owner.lease_stack(PAGE) }.err().ok_or(2)?;
                check(
                    error.stage == KeyedLeaseStage::MakeWritable
                        && error.errno == libc::ENOMEM
                        && error.cleanup_errno == Some(libc::ENOMEM)
                        && error.quarantined,
                    3,
                )?;
                let next = lease(owner, PAGE)?;
                check(next.base() == first + 3 * PAGE, 4)?;
                let _retained = next.retain();
                held_key_stays_owned(owner.key_descriptor().value())
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn closed_key_descriptors_never_read_control() {
    isolated(
        "keyed_owner::closed_key_descriptors_never_read_control",
        || {
            leader(|| {
                let owner = owner()?;
                let retained = lease(owner, PAGE)?.retain();
                let spans = owner.spans();
                let key = owner.key_descriptor();
                let base = retained.base();
                let top = retained.top();
                let entry = rights();
                set_rights(entry | (3 << (2 * key.value())));
                let correct = owner.spans() == spans
                    && owner.key_descriptor() == key
                    && retained.base() == base
                    && retained.top() == top
                    && retained.belongs_to(owner);
                let refusal = unsafe { owner.lease_stack(PAGE) }.err().is_some_and(|e| {
                    e.stage == KeyedLeaseStage::ClosedKey && e.errno == libc::EACCES
                });
                set_rights(entry);
                check(correct && refusal, 1)
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn ready_fork_preserves_cow_occupied_stack_and_key() {
    isolated(
        "keyed_owner::ready_fork_preserves_cow_occupied_stack_and_key",
        || {
            leader(|| {
                let owner = owner()?;
                let retained = lease(owner, PAGE)?.retain();
                let base = retained.base();
                let key = owner.key_descriptor();
                let entry = rights();
                unsafe { (base as *mut u8).write_volatile(0x19) };
                let child = raw(libc::SYS_fork, [0; 6]);
                if child == 0 {
                    let result = (|| {
                        let inherited = self::owner()?;
                        check(
                            core::ptr::eq(owner, inherited)
                                && inherited.key_descriptor() == key
                                && rights() == entry,
                            1,
                        )?;
                        check(unsafe { (base as *const u8).read_volatile() } == 0x19, 2)?;
                        unsafe { (base as *mut u8).write_volatile(0xe8) };
                        let next = lease(inherited, PAGE)?;
                        check(next.base() == base + 3 * PAGE, 3)?;
                        let _retained = next.retain();
                        held_key_stays_owned(key.value())
                    })();
                    raw_exit(result.err().unwrap_or(0));
                }
                child_ok(child)?;
                check(unsafe { (base as *const u8).read_volatile() } == 0x19, 4)?;
                let next = lease(owner, PAGE)?;
                check(next.base() == base + 3 * PAGE, 5)?;
                drop(next);
                held_key_stays_owned(key.value())
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn inherited_preparing_gate_never_resets_in_child() {
    isolated(
        "keyed_owner::inherited_preparing_gate_never_resets_in_child",
        || {
            leader(|| {
                let gate = keyed::fixture_hold_preparing().map_err(|_| 1)?;
                let child = raw(libc::SYS_fork, [0; 6]);
                if child == 0 {
                    let error = unsafe { KeyedToolRegion::reserve_native() }.err();
                    raw_exit(
                        if error.is_some_and(|e| {
                            e.kind == KeyedPrepareKind::Busy && e.errno == libc::EAGAIN
                        }) && keyed::fixture_state() == 1
                            && resident_query(BASE + PAGE) == -i64::from(libc::ENOMEM)
                        {
                            0
                        } else {
                            2
                        },
                    );
                }
                child_ok(child)?;
                check(keyed::fixture_state() == 1, 3)?;
                drop(gate);
                let _owner = owner()?;
                check(keyed::fixture_state() == 2, 4)
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn inherited_allocation_gate_refuses_and_drop_quarantines() {
    isolated(
        "keyed_owner::inherited_allocation_gate_refuses_and_drop_quarantines",
        || {
            leader(|| {
                let owner = owner()?;
                let pending = lease(owner, 2 * PAGE)?;
                let old_top = pending.top();
                let guard = keyed::fixture_hold_allocation(owner).map_err(|_| 1)?;
                let child = raw(libc::SYS_fork, [0; 6]);
                if child == 0 {
                    raw_exit(
                        if unsafe { owner.lease_stack(PAGE) }.err().is_some_and(|e| {
                            e.stage == KeyedLeaseStage::Claim && e.errno == libc::EAGAIN
                        }) {
                            0
                        } else {
                            2
                        },
                    );
                }
                child_ok(child)?;
                let error = unsafe { pending.release() }.err().ok_or(3)?;
                check(
                    error.stage == KeyedLeaseStage::ReleaseBitmap
                        && error.errno == libc::EAGAIN
                        && error.quarantined,
                    4,
                )?;
                drop(guard);
                let next = lease(owner, PAGE)?;
                check(next.base() - PAGE >= old_top + PAGE, 5)?;
                let _retained = next.retain();
                held_key_stays_owned(owner.key_descriptor().value())
            })
        },
    );
}

enum Fault {
    Control,
    TaggedUnmap,
    Free,
    Relocated,
}

struct FaultCalls {
    fault: Fault,
    actual_mapping: Cell<usize>,
}

impl NativeCalls for FaultCalls {
    unsafe fn syscall(&self, number: i64, mut args: [u64; 6]) -> i64 {
        if number == libc::SYS_pkey_mprotect && args[0] == (BASE + PAGE) as u64 {
            match self.fault {
                Fault::Control | Fault::Free => return -i64::from(libc::EACCES),
                Fault::TaggedUnmap => {
                    let result = unsafe { keyed::Native.syscall(number, args) };
                    return if result == 0 {
                        -i64::from(libc::EIO)
                    } else {
                        result
                    };
                }
                Fault::Relocated => {}
            }
        }
        if number == libc::SYS_munmap && matches!(self.fault, Fault::TaggedUnmap) {
            return -i64::from(libc::EACCES);
        }
        if number == libc::SYS_pkey_free && matches!(self.fault, Fault::Free) {
            return -i64::from(libc::EPERM);
        }
        if number == libc::SYS_mmap
            && args[0] == BASE as u64
            && matches!(self.fault, Fault::Relocated)
        {
            args[0] = 0;
            args[3] = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
            let result = unsafe { keyed::Native.syscall(number, args) };
            if result > 0 {
                self.actual_mapping.set(result as usize);
            }
            return result;
        }
        unsafe { keyed::Native.syscall(number, args) }
    }
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn failed_control_tagging_precedes_every_typed_write() {
    isolated(
        "keyed_owner::failed_control_tagging_precedes_every_typed_write",
        || {
            leader(|| {
                check(keyed::Native.ospke(), 1)?;
                let entry = rights();
                let calls = FaultCalls {
                    fault: Fault::Control,
                    actual_mapping: Cell::new(0),
                };
                // Actual Control stays PROT_NONE. A typed write before the injected
                // error would fault, rather than making this negative case pass.
                let error = unsafe { keyed::reserve_with(&calls) }.err().ok_or(2)?;
                check(
                    error.errno == libc::EACCES
                        && error.cleanup_errno.is_none()
                        && error.quarantine.is_none(),
                    3,
                )?;
                check(
                    rights() == entry && resident_query(BASE + PAGE) == -i64::from(libc::ENOMEM),
                    4,
                )?;
                check(
                    unsafe { KeyedToolRegion::reserve_native() }.err() == Some(error),
                    5,
                )
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn uncertain_tagged_cleanup_keeps_mapping_and_key() {
    isolated(
        "keyed_owner::uncertain_tagged_cleanup_keeps_mapping_and_key",
        || {
            leader(|| {
                check(keyed::Native.ospke(), 1)?;
                let entry = rights();
                let calls = FaultCalls {
                    fault: Fault::TaggedUnmap,
                    actual_mapping: Cell::new(0),
                };
                let error = unsafe { keyed::reserve_with(&calls) }.err().ok_or(2)?;
                let quarantine = error.quarantine.ok_or(3)?;
                let key = quarantine.key.ok_or(4)?;
                check(
                    error.errno == libc::EIO
                        && error.cleanup_errno == Some(libc::EACCES)
                        && quarantine.mapping
                            == Some(KeyedSpan {
                                bottom: BASE,
                                top: END,
                            })
                        && quarantine.possibly_tagged,
                    5,
                )?;
                check(rights() == entry && resident_query(BASE + PAGE) == 0, 6)?;
                check(vma(BASE + PAGE)? == (true, key.value()), 7)?;
                held_key_stays_owned(key.value())?;
                check(
                    unsafe { KeyedToolRegion::reserve_native() }.err() == Some(error),
                    8,
                )
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn key_free_failure_retains_key_after_complete_unmap() {
    isolated(
        "keyed_owner::key_free_failure_retains_key_after_complete_unmap",
        || {
            leader(|| {
                check(keyed::Native.ospke(), 1)?;
                let entry = rights();
                let calls = FaultCalls {
                    fault: Fault::Free,
                    actual_mapping: Cell::new(0),
                };
                let error = unsafe { keyed::reserve_with(&calls) }.err().ok_or(2)?;
                let quarantine = error.quarantine.ok_or(3)?;
                check(
                    error.errno == libc::EACCES
                        && error.cleanup_errno == Some(libc::EPERM)
                        && quarantine.mapping.is_none(),
                    4,
                )?;
                check(
                    rights() == entry && resident_query(BASE + PAGE) == -i64::from(libc::ENOMEM),
                    5,
                )?;
                held_key_stays_owned(quarantine.key.ok_or(6)?.value())
            })
        },
    );
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn relocated_return_cleanup_never_unmaps_requested_occupant() {
    isolated(
        "keyed_owner::relocated_return_cleanup_never_unmaps_requested_occupant",
        || {
            leader(|| {
                check(keyed::Native.ospke(), 1)?;
                let entry = rights();
                check(anonymous_at(BASE + PAGE, PAGE) == (BASE + PAGE) as i64, 2)?;
                unsafe { ((BASE + PAGE) as *mut u8).write_volatile(0x37) };
                let calls = FaultCalls {
                    fault: Fault::Relocated,
                    actual_mapping: Cell::new(0),
                };
                let error = unsafe { keyed::reserve_with(&calls) }.err().ok_or(3)?;
                let actual = calls.actual_mapping.get();
                check(
                    actual != 0
                        && actual != BASE
                        && error.errno == libc::EOPNOTSUPP
                        && error.cleanup_errno.is_none()
                        && error.quarantine.is_none(),
                    4,
                )?;
                check(
                    resident_query(actual) == -i64::from(libc::ENOMEM) && rights() == entry,
                    5,
                )?;
                check(
                    unsafe { ((BASE + PAGE) as *const u8).read_volatile() } == 0x37
                        && vma(BASE + PAGE)? == (true, 0),
                    6,
                )
            })
        },
    );
}

struct ForkCalls {
    child: Cell<i64>,
}

impl NativeCalls for ForkCalls {
    unsafe fn syscall(&self, number: i64, args: [u64; 6]) -> i64 {
        unsafe { keyed::Native.syscall(number, args) }
    }
    fn before_publish(&self) {
        self.child.set(raw(libc::SYS_fork, [0; 6]));
    }
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn copied_builder_cannot_publish_or_clean_inherited_resources() {
    isolated(
        "keyed_owner::copied_builder_cannot_publish_or_clean_inherited_resources",
        || {
            leader(|| {
                let calls = ForkCalls {
                    child: Cell::new(-1),
                };
                let result = unsafe { keyed::reserve_with(&calls) };
                if calls.child.get() == 0 {
                    let result = (|| {
                        let error = result.err().ok_or(1)?;
                        let quarantine = error.quarantine.ok_or(2)?;
                        check(
                            error.kind == KeyedPrepareKind::CreatorChanged
                                && error.errno == libc::ECHILD
                                && quarantine.mapping
                                    == Some(KeyedSpan {
                                        bottom: BASE,
                                        top: END,
                                    })
                                && quarantine.possibly_tagged,
                            3,
                        )?;
                        check(
                            resident_query(BASE + PAGE) == 0 && keyed::fixture_state() == 3,
                            4,
                        )?;
                        held_key_stays_owned(quarantine.key.ok_or(5)?.value())?;
                        check(
                            unsafe { KeyedToolRegion::reserve_native() }.err() == Some(error),
                            6,
                        )
                    })();
                    raw_exit(result.err().unwrap_or(0));
                }
                let owner = result.map_err(|_| 7)?;
                child_ok(calls.child.get())?;
                check(
                    keyed::fixture_state() == 2 && core::ptr::eq(owner, self::owner()?),
                    8,
                )?;
                let next = lease(owner, PAGE)?;
                let _retained = next.retain();
                held_key_stays_owned(owner.key_descriptor().value())
            })
        },
    );
}

struct UnsupportedCalls {
    forbidden: Cell<usize>,
}

impl NativeCalls for UnsupportedCalls {
    fn ospke(&self) -> bool {
        false
    }
    unsafe fn syscall(&self, number: i64, args: [u64; 6]) -> i64 {
        if matches!(
            number,
            libc::SYS_pkey_alloc | libc::SYS_pkey_mprotect | libc::SYS_pkey_free | libc::SYS_mmap
        ) {
            self.forbidden.set(self.forbidden.get() + 1);
            return -i64::from(libc::EIO);
        }
        unsafe { keyed::Native.syscall(number, args) }
    }
}

#[test]
fn unsupported_is_terminal_without_key_or_mapping_attempt() {
    isolated(
        "keyed_owner::unsupported_is_terminal_without_key_or_mapping_attempt",
        || {
            leader(|| {
                let calls = UnsupportedCalls {
                    forbidden: Cell::new(0),
                };
                let error = unsafe { keyed::reserve_with(&calls) }.err().ok_or(1)?;
                check(
                    error.kind == KeyedPrepareKind::Unsupported
                        && error.errno == libc::EOPNOTSUPP
                        && error.quarantine.is_none(),
                    2,
                )?;
                check(
                    calls.forbidden.get() == 0
                        && resident_query(BASE + PAGE) == -i64::from(libc::ENOMEM),
                    3,
                )?;
                check(
                    unsafe { KeyedToolRegion::reserve_native() }.err() == Some(error),
                    4,
                )
            })
        },
    );
}
