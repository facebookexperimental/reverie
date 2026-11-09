/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Clocks, sleeps and scheduling queries (gVisor: pkg/sentry/syscalls/linux/sys_time.go, sys_sched.go).

use super::*;

// TODO-HUMAN-REVIEW(PR-110): Review scheduler policy priority bounds.
// TODO-HUMAN-REVIEW(PR-119): Review modern policy-bound compatibility.
/// `sched_get_priority_min(2)` or `sched_get_priority_max(2)` from the host.
/// Detcore passes both through, so the host kernel's answer is the guest's.
pub(super) fn sched_priority_bound(number: libc::c_long, policy: u64) -> i64 {
    // SAFETY: neither call takes a pointer.
    let result = unsafe { libc::syscall(number, policy as usize) };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result
    }
}

// The time family goes to the host clock and host sleeps, as Linux answers the
// guest's host process. Detcore answers all of it on every backend: with
// virtual time it never injects these calls, and without it, it injects
// gettimeofday, time and clock_gettime to read the host clock, which is what
// these forwards return (ai_docs/2026-10-16-a2-kvm-keep-in-detcore-proof.md in
// the dev-hermit workspace).

/// Whether `clock_id` names a clock by itself, rather than a process, thread or
/// descriptor by its host-side number, which is not the guest's: a negative
/// id encodes a pid (CPU-time clocks) or a descriptor (posix clocks), and is
/// refused with Linux's answer for a clock id that names nothing.
fn host_clock_id(clock_id: libc::clockid_t) -> Result<libc::clockid_t, i64> {
    if clock_id < 0 {
        Err(negative_errno(libc::EINVAL))
    } else {
        Ok(clock_id)
    }
}

pub(super) fn nanosleep<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    host_sleep(memory, None, 0, args[0], args[1])
}

pub(super) fn clock_nanosleep<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    let clock_id = match host_clock_id(args[0] as libc::clockid_t) {
        Ok(clock_id) => clock_id,
        Err(error) => return error,
    };
    host_sleep(
        memory,
        Some(clock_id),
        args[1] as libc::c_int,
        args[2],
        args[3],
    )
}

/// `nanosleep(2)` (no clock) or `clock_nanosleep(2)` on the host. The request
/// is read from the guest first (EFAULT if it cannot be); the remainder is
/// stored only where Linux stores it, after an interrupted relative sleep.
fn host_sleep<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    clock_id: Option<libc::clockid_t>,
    flags: libc::c_int,
    request_address: u64,
    remainder_address: u64,
) -> i64 {
    if request_address == 0 {
        return negative_errno(libc::EFAULT);
    }
    let request = match read_guest_struct::<libc::timespec>(memory, request_address) {
        Ok(request) => request,
        Err(error) => return error,
    };
    let mut remainder = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: both pointers name live host timespecs for the call's duration.
    let result = unsafe {
        match clock_id {
            None => libc::syscall(libc::SYS_nanosleep, &request, &mut remainder),
            Some(clock_id) => libc::syscall(
                libc::SYS_clock_nanosleep,
                clock_id,
                flags,
                &request,
                &mut remainder,
            ),
        }
    };
    if result == 0 {
        return 0;
    }
    let error = std::io::Error::last_os_error();
    let interrupted_relative = error.raw_os_error() == Some(libc::EINTR)
        && flags & libc::TIMER_ABSTIME == 0
        && remainder_address != 0;
    if interrupted_relative && write_struct(memory, remainder_address, &remainder) != 0 {
        return negative_errno(libc::EFAULT);
    }
    io_error(error)
}

pub(super) fn clock_gettime<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    let clock_id = match host_clock_id(args[0] as libc::clockid_t) {
        Ok(clock_id) => clock_id,
        Err(error) => return error,
    };
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the pointer names a live host timespec.
    if unsafe { libc::clock_gettime(clock_id, &mut time) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    write_struct(memory, args[1], &time)
}

/// `gettimeofday(2)` from the host. As Linux, `tv_sec` and then `tv_usec` are
/// each stored with `put_user` (all eight bytes or none, writable pages only,
/// shared-file pages included), and the first failed store returns EFAULT,
/// leaving an already stored `tv_sec` in place. `tz` is then copied with
/// `copy_to_user`, which stores the writable prefix before it faults.
pub(super) fn gettimeofday<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    const TV_USEC_OFFSET: u64 = std::mem::offset_of!(libc::timeval, tv_usec) as u64;
    let mut time = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut zone = [0 as libc::c_int; 2];
    // SAFETY: both pointers name live host storage of the kernel's layouts.
    if unsafe { libc::syscall(libc::SYS_gettimeofday, &mut time, zone.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    if args[0] != 0 {
        let stored = memory.put_user_u64(args[0], time.tv_sec as u64).is_ok()
            && args[0]
                .checked_add(TV_USEC_OFFSET)
                .is_some_and(|tv_usec| memory.put_user_u64(tv_usec, time.tv_usec as u64).is_ok());
        if !stored {
            return negative_errno(libc::EFAULT);
        }
    }
    if args[1] != 0 {
        let zone = [zone[0].to_ne_bytes(), zone[1].to_ne_bytes()].concat();
        if memory.copy_to_user(args[1], &zone).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    0
}

/// `time(2)` from the host clock, also stored at `tloc` when it is not null.
/// As Linux's `put_user`, the store writes all eight bytes or none, only to
/// writable pages (shared-file pages included), and a failed store returns
/// EFAULT.
pub(super) fn time<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    // SAFETY: a null tloc asks only for the value.
    let seconds = unsafe { libc::time(std::ptr::null_mut()) };
    if args[0] != 0 && memory.put_user_u64(args[0], seconds as u64).is_err() {
        return negative_errno(libc::EFAULT);
    }
    seconds as i64
}
