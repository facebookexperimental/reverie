/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! getrandom (gVisor: pkg/sentry/syscalls/linux/sys_random.go).

use super::*;

/// The most bytes one host call fills before they are copied to the guest.
const CHUNK: usize = 1 << 20;

// TODO-HUMAN-REVIEW(rrnewton/reverie#1255): Review the getrandom host forward.
/// `getrandom(2)`, forwarded to the host: every byte, flag check, readiness
/// wait and error is the host kernel's own, made by the host call with the
/// guest's flags into a host buffer. This executor decides nothing about the
/// bytes; a Tool that wants other bytes answers the call itself.
///
/// As Linux (`getrandom` in drivers/char/random.c), the flags are checked and
/// the pool's readiness is awaited (or EAGAIN returned under GRND_NONBLOCK)
/// before the buffer is looked at, which the first host call does, a
/// zero-length one included. Then the length is shortened to `MAX_RW_COUNT`
/// and the range must pass `access_ok`, even when it is empty. The bytes are
/// copied with `copy_to_user`, which stores the writable prefix: the result
/// is the number of bytes stored, or EFAULT when none could be.
///
/// A request longer than one chunk is filled by several host calls. A later
/// one that stops short (Linux's own fill stops at a page boundary when a
/// signal is pending) or fails ends the call with the bytes already stored.
pub(super) fn getrandom<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    address: u64,
    length: u64,
    flags: u64,
) -> i64 {
    let flags = flags as libc::c_uint;
    let total = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(MAX_RW_COUNT);
    let mut chunk = vec![0u8; total.min(CHUNK)];
    let mut done = 0;
    loop {
        let request = (total - done).min(chunk.len());
        // SAFETY: the pointer names `request` writable bytes of `chunk`.
        let got = unsafe { libc::getrandom(chunk.as_mut_ptr().cast(), request, flags) };
        if got < 0 {
            return if done > 0 {
                done as i64
            } else {
                io_error(std::io::Error::last_os_error())
            };
        }
        if done == 0
            && let Err(error) = validate_guest_iovec_address(address, total)
        {
            return error;
        }
        let got = got as usize;
        let stored = if got == 0 {
            0
        } else {
            memory
                .copy_to_user_prefix(address + done as u64, &chunk[..got])
                .unwrap_or(0)
        };
        if got > 0 && stored == 0 && done == 0 {
            return negative_errno(libc::EFAULT);
        }
        done += stored;
        if done == total || stored < request {
            return done as i64;
        }
    }
}
