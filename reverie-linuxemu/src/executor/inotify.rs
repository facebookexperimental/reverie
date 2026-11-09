/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// TODO-HUMAN-REVIEW(PR-1015): Review host-backed KVM inotify semantics.
//
// An inotify instance is an ordinary host inotify descriptor in the guest file
// table, as eventfd and timerfd are. Its events come only from the host kernel
// observing filesystem operations, and every filesystem operation the guest
// performs is a host syscall issued synchronously by this executor, so the
// queue is a function of the guest's own operation order. The host kernel
// applies Linux's queueing, coalescing, ordering, read sizing, EINVAL and EFAULT
// rules itself:
//
// - reads go through the same staged host buffers as readv, whose inaccessible
//   guest suffix is PROT_NONE, so the kernel stops and faults at the guest's own
//   boundary and an event that does not fit the count is refused natively; the
//   bytes the kernel wrote reach the guest exactly as it wrote them, rename
//   cookies and the bytes of an event a fault cut short included (the copy-back
//   in read_write.rs, which also publishes the events a vectored read copies
//   into the iovec after its count before a fault there);
// - FIONREAD is the host instance's own count of queued bytes;
// - watches attach to the inode selected by one guest-namespace lookup (held as
//   O_PATH), never to a second lookup of the pathname.
//
// Rename cookies are the host kernel's. Linux draws IN_MOVED_FROM/IN_MOVED_TO
// cookies from one host-wide counter that every process's renames advance;
// what the guest sees of them is the Tool's decision, as on every other
// backend, so this executor neither renumbers a cookie nor restores any byte
// of an event.
//
// One thing is not left to the host: waiting. Every host instance this
// executor makes is nonblocking, whatever mode the guest asks for, and F_SETFL
// and FIONBIO never clear that (file.rs, ioctl.rs), so no read of one waits in
// the host, where the Tool could neither see nor order the wait. A read that
// finds nothing queued answers EAGAIN, a nonblocking read's answer, in either
// mode: for a blocking descriptor that is the report that the read would
// block, and whether the guest then waits, and until when, is the Tool's
// decision. The descriptor's blocking mode is the Tool's to keep as well: a
// Tool that makes its guest wait for such a read itself can ask for a
// nonblocking instance and present the guest's mode through the guest's
// F_GETFL and FIONBIO, while this executor's F_GETFL reports the host
// instance's flags, O_NONBLOCK included. A Tool that passes a blocking read
// through unchanged gets EAGAIN when nothing is queued, where Linux would wait.
//
// An instance whose host description is blocking cannot come from this
// executor; it came from outside the guest (received over SCM_RIGHTS, or
// inherited), and keeps the mode its sender gave it, as any other received
// descriptor does. A read of one would wait in the host, so a read, readv or
// preadv2 of it is refused by name before any host call (BlockingInotifyRead,
// `refuse_blocking_inotify_read`). A zero-count read of any inotify instance
// into an address the host would accept is refused as well (read_write.rs,
// `admit_host_read_zero`): its O_NONBLOCK can be cleared through an alias
// outside the guest, so the executor cannot show that the host read returns
// at once.

pub(super) fn host_fd_is_inotify(host_fd: RawFd) -> Result<bool, i64> {
    host_fd_mode_is_inotify(host_fd, fd_mode(host_fd)?)
}

/// [`host_fd_is_inotify`] with the descriptor's mode already in hand.
pub(super) fn host_fd_mode_is_inotify(host_fd: RawFd, mode: libc::mode_t) -> Result<bool, i64> {
    // Anonymous-inode descriptors have no file type bits. Only those need the
    // name check, so ordinary files pay one fstat.
    if mode & libc::S_IFMT != 0 {
        return Ok(false);
    }
    let target = canonical_fd_path(host_fd)?;
    Ok(target.as_os_str().as_bytes() == b"anon_inode:inotify")
}

/// Refuse, before any host call, a read of the inotify instance `host_fd`
/// (guest descriptor `guest_fd`) whose host description is blocking: the read
/// would wait in the host for an event (see the top of this file). A
/// description whose flags cannot be read is left to the read, which reports
/// that descriptor's own error.
pub(super) fn refuse_blocking_inotify_read(
    host_fd: RawFd,
    guest_fd: libc::c_int,
) -> crate::Result<()> {
    match fd_status_flags(host_fd) {
        Ok(flags) if flags & libc::O_NONBLOCK == 0 => {
            Err(crate::Error::BlockingInotifyRead { fd: guest_fd })
        }
        _ => Ok(()),
    }
}

/// [`refuse_blocking_inotify_read`] for a readv, or a preadv2 that reads at
/// the current position as readv does (offset -1, no flag but RWF_HIPRI),
/// of guest descriptor `args[0]`; any other call is left alone, as are
/// descriptors that are no inotify instance. An anonymous inode is the only
/// kind that can be one, so other descriptors pay only the file type the
/// entry already records.
pub(super) fn blocking_inotify_vectored_read(
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> Option<crate::Error> {
    if number == libc::SYS_preadv2 as u64
        && (args[3] as i64 != -1 || (args[5] as libc::c_int) & !libc::RWF_HIPRI != 0)
    {
        return None;
    }
    // Linux consumes only the low 32-bit descriptor word.
    let guest_fd = args[0] as libc::c_int;
    let host = host_fd(state, guest_fd)?;
    let mode = match state.fd_entry_ids.get(&guest_fd) {
        Some(entry) => entry.file_type(|| fd_mode(host)),
        None => fd_mode(host),
    }
    .ok()?;
    if !host_fd_mode_is_inotify(host, mode).ok()? {
        return None;
    }
    refuse_blocking_inotify_read(host, guest_fd).err()
}

/// The bytes queued on the host inotify instance `host_fd`, as FIONREAD there
/// reports them: the size of every queued event, as a read that took them all
/// would return them (`inotify_ioctl`, fs/notify/inotify/inotify_user.c).
pub(super) fn host_inotify_queued(host_fd: RawFd) -> Result<libc::c_int, i64> {
    let mut count: libc::c_int = 0;
    // SAFETY: count is supervisor storage for one int, and FIONREAD on an
    // inotify instance only sums the sizes of its queued events.
    if unsafe { libc::ioctl(host_fd, libc::FIONREAD, &mut count) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(count)
}

// TODO-HUMAN-REVIEW(https://github.com/rrnewton/hermit/issues/4793): Review
// forwarding FIONREAD on an inotify descriptor to the host instance.
/// FIONREAD on a guest inotify descriptor: the host instance's count, stored
/// as an int. `do_vfs_ioctl` (fs/ioctl.c) hands FIONREAD on an anonymous-inode
/// file to `inotify_ioctl`, which stores the count with `put_user`, so a
/// destination the guest cannot write is EFAULT.
pub(super) fn inotify_fionread<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    host_fd: RawFd,
    address: u64,
) -> i64 {
    let count = match host_inotify_queued(host_fd) {
        Ok(count) => count,
        Err(error) => return error,
    };
    if memory.put_user_i32(address, count).is_err() {
        return negative_errno(libc::EFAULT);
    }
    0
}

pub(super) fn inotify_init1(state: &mut LoadedStaticElf, raw_flags: u64) -> i64 {
    // SYSCALL_DEFINE1(inotify_init1, int, flags) consumes the low int word.
    let flags = raw_flags as libc::c_int;
    if flags & !(libc::IN_CLOEXEC | libc::IN_NONBLOCK) != 0 {
        return negative_errno(libc::EINVAL);
    }
    // The host instance is nonblocking whatever the guest asked for (see the
    // top of this file), and the supervisor descriptor stays private: guest
    // CLOEXEC is modeled separately in the guest file table.
    // SAFETY: inotify_init1 takes only flags and returns a new descriptor.
    let host_fd = unsafe { libc::inotify_init1(flags | libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: inotify_init1 returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, flags & libc::IN_CLOEXEC != 0, None)
}

/// The host kernel's verdict for an inotify_add_watch operand that cannot name
/// a file. Linux checks the mask, then the descriptor and its type, before it
/// copies the pathname, so an empty pathname reaches ENOENT only when both are
/// valid. Nothing is attached.
fn inotify_add_watch_preflight(host_fd: RawFd, mask: u32, valid: libc::c_int) -> Result<(), i64> {
    // SAFETY: the pathname is a live NUL-terminated empty string.
    let result = unsafe { libc::inotify_add_watch(host_fd, c"".as_ptr(), mask) };
    if result >= 0 {
        // An empty pathname never resolves. Do not keep an unexpected watch.
        // SAFETY: result is the watch descriptor just returned for host_fd.
        unsafe { libc::inotify_rm_watch(host_fd, result) };
        return Err(negative_errno(libc::EIO));
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(errno) if errno == valid => Ok(()),
        Some(errno) => Err(negative_errno(errno)),
        None => Err(negative_errno(libc::EIO)),
    }
}

pub(super) fn inotify_add_watch(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    let mask = args[2] as u32;
    // The mask is validated before the descriptor. Use the host kernel's exact
    // mask rules: with fd -1, a valid mask reaches EBADF.
    if let Err(error) = inotify_add_watch_preflight(-1, mask, libc::EBADF) {
        return error;
    }
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    // A non-inotify descriptor is EINVAL and an O_PATH descriptor EBADF, both
    // before the pathname is read.
    if let Err(error) = inotify_add_watch_preflight(host_fd, mask, libc::ENOENT) {
        return error;
    }
    let path = match read_c_string(&ProviderMemory(memory), args[1], libc::PATH_MAX as usize) {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => return negative_errno(libc::ENOENT),
        Err(error) => return read_c_string_errno(error),
    };
    // One guest-namespace lookup selects the inode, honoring the guest cwd,
    // IN_DONT_FOLLOW for the final component and the procfs restriction shared
    // by the other metadata operations.
    let held = match open_metadata_path(
        state,
        libc::AT_FDCWD,
        &path,
        mask & libc::IN_DONT_FOLLOW != 0,
    ) {
        Ok(file) => file,
        Err(error) => return error,
    };
    // Attach through the held descriptor's proc link: the kernel's lookup jumps
    // to exactly the held object (the symlink itself under IN_DONT_FOLLOW) and
    // stops there, so a concurrent rename cannot substitute another inode.
    // IN_DONT_FOLLOW would instead select the proc link, so it is not passed.
    // IN_ONLYDIR and the read-permission check still apply to the held object.
    let target = CString::new(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .expect("host descriptor path has no NUL");
    // SAFETY: target is NUL-terminated and resolves only the held descriptor.
    let watch =
        unsafe { libc::inotify_add_watch(host_fd, target.as_ptr(), mask & !libc::IN_DONT_FOLLOW) };
    if watch < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        i64::from(watch)
    }
}

pub(super) fn inotify_rm_watch(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    // The kernel validates the descriptor type and the instance-local watch.
    // SAFETY: host_fd is pinned by the caller's file-table snapshot.
    zero_or_errno(unsafe { libc::inotify_rm_watch(host_fd, args[1] as libc::c_int) })
}
