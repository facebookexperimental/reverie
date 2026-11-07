/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! ioctl and terminal control (gVisor: pkg/sentry/syscalls/linux/sys_ioctl.go, pkg/sentry/kernel/tty.go).

use super::*;

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn ioctl(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    // ioctl looks its descriptor up with fdget, which refuses an O_PATH
    // descriptor, so every command (FIOCLEX and FIONCLEX included) fails with
    // EBADF there before any descriptor flag changes.
    match fd_status_flags(host_fd) {
        Ok(flags) if flags & libc::O_PATH != 0 => return negative_errno(libc::EBADF),
        Ok(_) => {}
        Err(error) => return error,
    }
    // Linux ioctl takes an unsigned-int command even on the 64-bit syscall ABI.
    // Keep this limited support independent of the other ioctl dispatch arms.
    if args[1] as u32 == libc::FIONREAD as u32 {
        return pipe_fionread(
            &ProviderMemory(memory),
            state,
            guest_fd,
            host_fd,
            args[2],
            capture_output,
        );
    }
    if args[1] as u32 == libc::FIONBIO as u32 {
        return fionbio(memory, state, guest_fd, host_fd, args[2]);
    }
    match args[1] as libc::c_ulong {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-229): Review virtual FIOCLEX/FIONCLEX descriptor flags.
        libc::FIOCLEX => {
            state.cloexec_fds.insert(guest_fd);
            0
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-229): Review virtual FIOCLEX/FIONCLEX descriptor flags.
        libc::FIONCLEX => {
            state.cloexec_fds.remove(&guest_fd);
            0
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-230): Review the no-guest-NIC ioctl model.
        SIOCETHTOOL => negative_errno(libc::ENODEV),
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-332): Report real terminal state to the guest.
        // The executor's inherited standard descriptors are the real host fds, so
        // forward the terminal-query ioctls to them (matching what the ptrace
        // backend's syscall injection does against the real tty). This makes
        // `isatty()` (a TCGETS probe) return the true answer: success on a
        // terminal, ENOTTY on a pipe/file. Detcore then canonicalizes the
        // returned geometry/attributes to a fixed terminal, so the guest's view
        // is both faithful to tty-ness and deterministic across hosts/backends.
        libc::TCGETS => {
            forward_terminal_ioctl(memory, host_fd, libc::TCGETS, args[2], KERNEL_TERMIOS_SIZE)
        }
        libc::TIOCGWINSZ => forward_terminal_ioctl(
            memory,
            host_fd,
            libc::TIOCGWINSZ,
            args[2],
            std::mem::size_of::<libc::winsize>(),
        ),
        libc::TIOCGPGRP => forward_terminal_ioctl(
            memory,
            host_fd,
            libc::TIOCGPGRP,
            args[2],
            std::mem::size_of::<libc::pid_t>(),
        ),
        _ => negative_errno(libc::ENOTTY),
    }
}

fn fionbio(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
    host_fd: RawFd,
    address: u64,
) -> i64 {
    // Linux rejects O_PATH before copying the one input int.
    let flags = match fd_status_flags(host_fd) {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    if flags & libc::O_PATH != 0 {
        return negative_errno(libc::EBADF);
    }
    let value = match read_guest_struct::<libc::c_int>(&ProviderMemory(memory), address) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if let Some(carrier) = signalfd_carrier(state, guest_fd) {
        // As F_SETFL: the mode is the guest description's, and the host
        // keeper stays nonblocking.
        carrier.set_guest_blocking(value == 0);
        return 0;
    }
    if value == 0 {
        // Keep F_SETFL's inotify policy for the same reason.
        match host_fd_is_inotify(host_fd) {
            Ok(true) => return negative_errno(libc::ENOSYS),
            Ok(false) => {}
            Err(error) => return error,
        }
    }
    if let Some(owner) = state.pipe_owners.get(&guest_fd) {
        owner.set_nonblocking(host_fd, value)
    } else {
        set_fd_nonblocking(host_fd, value)
    }
}

pub(super) fn set_fd_nonblocking(host_fd: RawFd, value: libc::c_int) -> i64 {
    // SAFETY: host_fd is pinned by the caller's file-table transaction, and
    // value is readable supervisor storage for one int. Native FIONBIO changes
    // only O_NONBLOCK atomically, preserving other shared-description flags.
    zero_or_errno(unsafe { libc::ioctl(host_fd, libc::FIONBIO, &value) })
}

/// Size of the kernel `struct termios` returned by `TCGETS`: four 4-byte mode
/// flags, the one-byte line discipline, and `c_cc[NCCS]` with `NCCS == 19`.
/// This is the kernel ABI layout, which differs from the larger libc `termios`.
pub(super) const KERNEL_TERMIOS_SIZE: usize = 4 * 4 + 1 + 19;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-332): Review forwarding fixed-size terminal-query
// ioctls to the real host descriptor.
fn forward_terminal_ioctl(
    memory: &mut GuestMemory,
    host_fd: RawFd,
    request: libc::c_ulong,
    out_addr: u64,
    out_len: usize,
) -> i64 {
    let mut buf = vec![0u8; out_len];
    // SAFETY: `buf` is `out_len` bytes long, and each of these fixed-size
    // terminal-query ioctls writes at most that many bytes into the buffer.
    let ret = unsafe { libc::ioctl(host_fd, request, buf.as_mut_ptr()) };
    if ret < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    write_bytes(&mut ProviderMemory(memory), out_addr, &buf)
}
