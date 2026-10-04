/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Private random descriptors retain an immutable, read-only carrier. Guest
// permissions/status belong to the shared description, never to that carrier.
impl RandomDeviceDescription {
    fn readable(&self) -> bool {
        matches!(self.access, libc::O_RDONLY | libc::O_RDWR)
    }

    fn writable(&self) -> bool {
        matches!(self.access, libc::O_WRONLY | libc::O_RDWR)
    }

    fn status_lock(&self) -> crate::Result<std::sync::MutexGuard<'_, bool>> {
        self.async_set.lock().map_err(|_| {
            crate::Error::HostIo(std::io::Error::other(
                "KVM random-device status lock poisoned",
            ))
        })
    }

    fn get_flags(&self, host: RawFd) -> crate::Result<i64> {
        let async_set = self.status_lock()?;
        let flags = match fd_status_flags(host) {
            Ok(flags) => flags,
            Err(error) => return Ok(error),
        };
        Ok(i64::from(
            (flags & !(libc::O_ACCMODE | libc::O_ASYNC))
                | self.access
                | if self.nofollow { libc::O_NOFOLLOW } else { 0 }
                | if self.async_opened || *async_set {
                    libc::O_ASYNC
                } else {
                    0
                },
        ))
    }

    fn set_flags(&self, host: RawFd, requested: i32) -> crate::Result<i64> {
        if self.access == libc::O_PATH {
            return Ok(negative_errno(libc::EBADF));
        }
        // Linux random devices lack FMODE_CAN_ODIRECT. Reject before changing
        // any shared flags, regardless of the private tmpfs carrier's support.
        if requested & libc::O_DIRECT != 0 {
            return Ok(negative_errno(libc::EINVAL));
        }
        let mut async_set = self.status_lock()?;
        let flags = requested & (libc::O_APPEND | libc::O_NONBLOCK | libc::O_NOATIME);
        // No host fasync or signal delivery. Commit virtual flags on success.
        let result = zero_or_errno(unsafe { libc::fcntl(host, libc::F_SETFL, flags) });
        if result == 0 {
            *async_set = requested & libc::O_ASYNC != 0;
        }
        Ok(result)
    }
}

fn random_device_early(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    number: libc::c_long,
    args: &[u64; 6],
) -> Option<crate::Result<i64>> {
    let description = state.random_device_descriptions.get(&(args[0] as i32))?;
    let host = host_fd(state, args[0] as i32).expect("marked random descriptor is owned");
    let path = description.access == libc::O_PATH;
    let answer = match number {
        libc::SYS_write
        | libc::SYS_writev
        | libc::SYS_pwrite64
        | libc::SYS_pwritev
        | libc::SYS_pwritev2 => {
            return Some(random_device_write(memory, description, number, args));
        }
        libc::SYS_pread64 if (args[3] as i64) < 0 => negative_errno(libc::EINVAL),
        libc::SYS_preadv | libc::SYS_preadv2
            if validate_positioned_vectored_offset(number, args).is_err() =>
        {
            negative_errno(libc::EINVAL)
        }
        libc::SYS_read
        | libc::SYS_readv
        | libc::SYS_pread64
        | libc::SYS_preadv
        | libc::SYS_preadv2
            if !description.readable() =>
        {
            negative_errno(libc::EBADF)
        }
        libc::SYS_fcntl => {
            let command = args[1] as i32;
            if path
                && !matches!(
                    command,
                    libc::F_DUPFD
                        | libc::F_DUPFD_CLOEXEC
                        | libc::F_GETFD
                        | libc::F_SETFD
                        | libc::F_GETFL
                        | 1027 // F_DUPFD_QUERY: permitted, but unsupported here.
                        | 1028 // F_CREATED_QUERY: likewise.
                )
            {
                negative_errno(libc::EBADF)
            } else if command == libc::F_GETFL {
                return Some(description.get_flags(host));
            } else if command == libc::F_SETFL {
                return Some(description.set_flags(host, args[2] as i32));
            } else if matches!(
                command,
                libc::F_SETLK | libc::F_SETLKW | libc::F_OFD_SETLK | libc::F_OFD_SETLKW
            ) {
                return Some(random_device_lock(memory, description, command, args[2]));
            } else {
                return None;
            }
        }
        libc::SYS_fgetxattr | libc::SYS_fsetxattr | libc::SYS_fremovexattr if path => {
            return Some(random_path_xattr(memory, number, args));
        }
        libc::SYS_lseek
        | libc::SYS_fchmod
        | libc::SYS_fchown
        | libc::SYS_flock
        | libc::SYS_ioctl
        | libc::SYS_flistxattr
            if path =>
        {
            negative_errno(libc::EBADF)
        }
        libc::SYS_ftruncate => {
            if (args[1] as i64) < 0 {
                negative_errno(libc::EINVAL)
            } else if path {
                negative_errno(libc::EBADF)
            } else {
                negative_errno(libc::EINVAL)
            }
        }
        libc::SYS_fallocate => {
            if path {
                negative_errno(libc::EBADF)
            } else if (args[2] as i64) < 0 || (args[3] as i64) <= 0 {
                negative_errno(libc::EINVAL)
            } else if !FALLOCATE_VALID_MODES.contains(&(args[1] as i32)) {
                negative_errno(libc::EOPNOTSUPP)
            } else if !description.writable() {
                negative_errno(libc::EBADF)
            } else {
                negative_errno(libc::ENODEV)
            }
        }
        libc::SYS_fsync | libc::SYS_fdatasync => {
            negative_errno(if path { libc::EBADF } else { libc::EINVAL })
        }
        libc::SYS_readahead => negative_errno(if description.readable() {
            libc::EINVAL
        } else {
            libc::EBADF
        }),
        libc::SYS_sync_file_range => {
            let allowed = libc::SYNC_FILE_RANGE_WAIT_BEFORE
                | libc::SYNC_FILE_RANGE_WRITE
                | libc::SYNC_FILE_RANGE_WAIT_AFTER;
            if path {
                negative_errno(libc::EBADF)
            } else if (args[1] as i64) < 0
                || (args[2] as i64) < 0
                || (args[1] as i64).checked_add(args[2] as i64).is_none()
                || args[3] as u32 & !allowed != 0
            {
                negative_errno(libc::EINVAL)
            } else {
                negative_errno(libc::ESPIPE)
            }
        }
        _ => return None,
    };
    Some(Ok(answer))
}

fn random_device_lock(
    memory: &GuestMemory,
    description: &RandomDeviceDescription,
    command: i32,
    address: u64,
) -> crate::Result<i64> {
    let imported = read_guest_struct::<libc::flock>(memory, address);
    check_random_copy_failure(memory)?;
    let lock = match imported {
        Ok(lock) => lock,
        Err(errno) => return Ok(errno),
    };
    // Native random noop_llseek leaves both SEEK_CUR and SEEK_END at zero.
    if !matches!(
        i32::from(lock.l_whence),
        libc::SEEK_SET | libc::SEEK_CUR | libc::SEEK_END
    ) || lock.l_start < 0
    {
        return Ok(negative_errno(libc::EINVAL));
    }
    if lock.l_len < 0 {
        if lock
            .l_start
            .checked_add(lock.l_len)
            .is_none_or(|start| start < 0)
        {
            return Ok(negative_errno(libc::EINVAL));
        }
    } else if lock.l_len > 0 && lock.l_start.checked_add(lock.l_len - 1).is_none() {
        return Ok(negative_errno(libc::EOVERFLOW));
    }
    if !matches!(
        i32::from(lock.l_type),
        libc::F_RDLCK | libc::F_WRLCK | libc::F_UNLCK
    ) {
        return Ok(negative_errno(libc::EINVAL));
    }
    if (i32::from(lock.l_type) == libc::F_RDLCK && !description.readable())
        || (i32::from(lock.l_type) == libc::F_WRLCK && !description.writable())
    {
        return Ok(negative_errno(libc::EBADF));
    }
    if matches!(command, libc::F_OFD_SETLK | libc::F_OFD_SETLKW) && lock.l_pid != 0 {
        return Ok(negative_errno(libc::EINVAL));
    }
    // Never install a host lock or wait on host lock ownership. No installed
    // lock exists to remove, so validated unlock is an effect-free success.
    Ok(if i32::from(lock.l_type) == libc::F_UNLCK {
        0
    } else {
        negative_errno(libc::ENOSYS)
    })
}

fn prepare_random_write(
    memory: &GuestMemory,
    description: &RandomDeviceDescription,
    number: libc::c_long,
    args: &[u64; 6],
) -> Result<Vec<GuestIoVec>, i64> {
    let scalar = matches!(number, libc::SYS_write | libc::SYS_pwrite64);
    let positioned = !matches!(number, libc::SYS_write | libc::SYS_writev);
    if positioned {
        if scalar {
            if (args[3] as i64) < 0 {
                return Err(negative_errno(libc::EINVAL));
            }
        } else {
            validate_positioned_vectored_offset(number, args)?;
        }
    }
    if !description.writable() {
        return Err(negative_errno(libc::EBADF));
    }
    let (vectors, total, kernel_total) = if scalar {
        let count = args[2] as usize;
        validate_guest_iovec_address(args[1], count)?;
        (
            vec![GuestIoVec {
                base: args[1],
                length: count.min(MAX_HOST_IO),
            }],
            count.min(MAX_HOST_IO),
            count,
        )
    } else {
        decode_guest_iovecs(memory, args[1], u64::from(args[2] as u32))?
    };
    // Writes never consume the synthetic read position. Linux random ki_pos
    // stays zero; only explicit nonnegative positioned offsets affect admission.
    let offset = if positioned && args[3] as i64 >= 0 {
        args[3] as i64
    } else {
        0
    };
    if (scalar || total != 0)
        && (kernel_total > i64::MAX as usize || offset.checked_add(kernel_total as i64).is_none())
    {
        return Err(negative_errno(libc::EINVAL));
    }
    if !scalar && total != 0 {
        validate_positioned_vectored_flags(number, args, total)?;
        if number == libc::SYS_pwritev2
            && args[5] as i32 & (libc::RWF_ATOMIC | libc::RWF_DONTCACHE) != 0
        {
            return Err(negative_errno(libc::EOPNOTSUPP));
        }
    }
    Ok(vectors)
}

fn random_device_write(
    memory: &GuestMemory,
    description: &RandomDeviceDescription,
    number: libc::c_long,
    args: &[u64; 6],
) -> crate::Result<i64> {
    let prepared = prepare_random_write(memory, description, number, args);
    check_random_copy_failure(memory)?;
    let vectors = match prepared {
        Ok(vectors) => vectors,
        Err(errno) => return Ok(errno),
    };
    let total: usize = vectors.iter().map(|v| v.length).sum();
    let mut copied = 0;
    let mut chunk = [0u8; 4096];
    'vectors: for vector in vectors {
        let mut offset = 0;
        while offset < vector.length {
            let count = (vector.length - offset).min(chunk.len());
            let read = match memory
                .user()
                .copy_from_user_prefix(vector.base + offset as u64, &mut chunk[..count])
            {
                Ok(read) => read,
                Err(
                    crate::Error::InvalidGuestAddress { .. }
                    | crate::Error::GuestMemoryAccessDenied { .. },
                ) => break 'vectors,
                Err(error) => return Err(error),
            };
            #[cfg(test)]
            description.consumed_input.fetch_add(read, Ordering::SeqCst);
            copied += read;
            offset += read;
            #[cfg(test)]
            if let Some(cause) = description.poison_after_copy.lock().unwrap().take() {
                memory
                    .entry_gate()
                    .poison(None, crate::Error::SharedFailure(cause));
            }
            check_random_copy_failure(memory)?;
            if read < count {
                break 'vectors;
            }
        }
    }
    check_random_copy_failure(memory)?;
    Ok(if copied == 0 && total != 0 {
        negative_errno(libc::EFAULT)
    } else {
        copied as i64
    })
}

fn random_device_mmap(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    description: &RandomDeviceDescription,
) -> i64 {
    if !args[5].is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    if description.access == libc::O_PATH {
        return negative_errno(libc::EBADF);
    }
    let flags = args[3] as i32;
    // ksys_mmap_pgoff rejects a non-hugetlbfs file before entering do_mmap,
    // including its address, length, overlap and file-offset validation.
    if flags & libc::MAP_HUGETLB != 0 {
        return negative_errno(libc::EINVAL);
    }
    if args[1] == 0 {
        return negative_errno(libc::EINVAL);
    }
    let Some(length) = align_up(args[1], PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    let kind = flags & libc::MAP_TYPE;
    let fixed = flags & (libc::MAP_FIXED | libc::MAP_FIXED_NOREPLACE) != 0;
    let address = if fixed {
        args[0]
    } else {
        match find_mmap_address(memory, state, length) {
            Some(address) => address,
            None => return negative_errno(libc::ENOMEM),
        }
    };
    // Check the modeled Linux user-address bound before fixed alignment.
    // The finite backing and reserved lower range are separate restrictions;
    // neither may hide EINVAL for an otherwise valid misaligned address.
    let Some(end) = address.checked_add(length) else {
        return negative_errno(libc::ENOMEM);
    };
    if end > X86_64_GUEST_USER_LIMIT {
        return negative_errno(libc::ENOMEM);
    }
    if fixed && !address.is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    if address < BOOT_RESERVED_END || end > state.mmap_limit {
        return negative_errno(libc::ENOMEM);
    }
    if flags & libc::MAP_FIXED_NOREPLACE != 0
        && (address..address + length)
            .step_by(PAGE_SIZE as usize)
            .any(|page| memory.user_range_is_mapped(page, PAGE_SIZE))
    {
        return negative_errno(libc::EEXIST);
    }
    if args[5].checked_add(length).is_none() {
        return negative_errno(libc::EOVERFLOW);
    }
    if !matches!(
        kind,
        libc::MAP_PRIVATE | libc::MAP_SHARED | libc::MAP_SHARED_VALIDATE
    ) {
        return negative_errno(libc::EINVAL);
    }
    // Linux v6.18 include/linux/mman.h LEGACY_MAP_MASK with x86 UAPI values.
    // NOREPLACE is deliberately absent: its overlap check precedes this mask,
    // but SHARED_VALIDATE still rejects it on a free range. Hugepage selectors
    // are individual allowed bits even when MAP_HUGETLB is absent.
    const MAP_ABOVE4G: i32 = 0x80;
    const MAP_UNINITIALIZED: i32 = 0x04000000;
    const LEGACY: i32 = libc::MAP_SHARED
        | libc::MAP_PRIVATE
        | libc::MAP_FIXED
        | libc::MAP_ANONYMOUS
        | libc::MAP_DENYWRITE
        | libc::MAP_EXECUTABLE
        | MAP_UNINITIALIZED
        | libc::MAP_GROWSDOWN
        | libc::MAP_LOCKED
        | libc::MAP_NORESERVE
        | libc::MAP_POPULATE
        | libc::MAP_NONBLOCK
        | libc::MAP_STACK
        | libc::MAP_HUGETLB
        | libc::MAP_32BIT
        | MAP_ABOVE4G
        | libc::MAP_HUGE_2MB
        | libc::MAP_HUGE_1GB;
    // x86-64 SYS_mmap takes unsigned long flags. Validate the original word,
    // zero-extending the low-word mask so unknown high bits cannot disappear.
    if kind == libc::MAP_SHARED_VALIDATE && args[3] & !u64::from(LEGACY as u32) != 0 {
        return negative_errno(libc::EOPNOTSUPP);
    }
    if !description.readable()
        || (kind != libc::MAP_PRIVATE
            && args[2] & libc::PROT_WRITE as u64 != 0
            && !description.writable())
    {
        return negative_errno(libc::EACCES);
    }
    // Reject before reservation, MAP_FIXED replacement, zeroing or file reads.
    negative_errno(libc::ENODEV)
}

// xattr syscalls import names (and set values) before their fd lookup. An
// O_PATH handle must not expose the private carrier's no-xattr personality.
fn random_path_xattr(
    memory: &GuestMemory,
    number: libc::c_long,
    args: &[u64; 6],
) -> crate::Result<i64> {
    let setting = number == libc::SYS_fsetxattr;
    if setting && args[4] as i32 & !(libc::XATTR_CREATE | libc::XATTR_REPLACE) != 0 {
        return Ok(negative_errno(libc::EINVAL));
    }
    let imported = read_c_string(memory, args[1], 256);
    check_random_copy_failure(memory)?;
    match imported {
        Ok(name) if name.is_empty() => return Ok(negative_errno(libc::ERANGE)),
        Ok(_) => {}
        Err(ReadCStringError::Fault) => return Ok(negative_errno(libc::EFAULT)),
        Err(ReadCStringError::NameTooLong) => return Ok(negative_errno(libc::ERANGE)),
    }
    if setting && args[3] != 0 {
        if args[3] > 65536 {
            return Ok(negative_errno(libc::E2BIG));
        }
        let mut value = vec![0; args[3] as usize];
        let copied = memory.user().read(args[2], &mut value);
        check_random_copy_failure(memory)?;
        if copied.is_err() {
            return Ok(negative_errno(libc::EFAULT));
        }
    }
    Ok(negative_errno(libc::EBADF))
}
