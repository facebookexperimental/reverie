/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::fd::AsFd;

use super::*;
use crate::memory::AllocationGuard;
use crate::memory::PrivateRangePlan;
use crate::memory::SharedFileRangePlan;

fn unsupported_mmap(reason: &'static str) -> crate::Error {
    crate::Error::SharedFileCapability {
        operation: "mmap",
        reason,
    }
}

/// A reserved name only denies an unsupported private object; it never proves
/// that an object is an authenticated carrier or an ordinary filesystem file.
fn classify_shared_mmap_file(
    state: &LoadedStaticElf,
    fd: libc::c_int,
    file: &std::fs::File,
    capture_output: bool,
) -> crate::Result<()> {
    if state.proc_files.contains_key(&fd)
        || state.fdinfo_files.contains_key(&fd)
        || state.random_device_fds.contains(&fd)
        || (capture_output && output_alias(state, fd).is_some())
    {
        return Err(unsupported_mmap("synthetic or captured backing"));
    }
    let path = canonical_fd_path(file.as_raw_fd())
        .map_err(|_| unsupported_mmap("cannot classify retained file backing"))?;
    // Same deny-only predicate as ordinary syncfs. This also catches received
    // private descriptions whose side-table identity was lost. It does not adopt the authentication protocol of PR610.
    // https://github.com/rrnewton/reverie/pull/610
    if syncfs_private_memfd_name(path.as_os_str().as_bytes()) {
        return Err(unsupported_mmap("reserved private memfd backing"));
    }
    if capture_output {
        let target = host_file_key(file.as_raw_fd())
            .map_err(|_| unsupported_mmap("cannot identify retained output backing"))?;
        for standard in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            match host_file_key(standard) {
                Ok(key) if key != target => {}
                _ => {
                    return Err(unsupported_mmap(
                        "captured output backing or unknown identity",
                    ));
                }
            }
        }
    }
    Ok(())
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-911): Review ordinary-file publication.
// https://github.com/rrnewton/reverie/issues/891
pub(super) fn mmap_with_shared_files(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
    allocation: AllocationGuard<'_>,
) -> crate::Result<i64> {
    // x86-64's sys_mmap refuses an unaligned offset before anything else,
    // for an anonymous mapping too.
    if !args[5].is_multiple_of(PAGE_SIZE) {
        return Ok(negative_errno(libc::EINVAL));
    }
    // Preserve the random device's earlier ABI checks. Its existing mmap path
    // always refuses before reservation/zeroing, including MAP_FIXED; calling
    // it cannot overwrite a currently shared ordinary file.
    if args[3] & libc::MAP_ANONYMOUS as u64 == 0
        && let Some(random) = state.random_device_descriptions.get(&(args[4] as i32))
    {
        return Ok(random_device_mmap(memory, state, args, random));
    }
    if let Some(error) = super::non_regular_mmap_early_refusal(state, args) {
        return Ok(error);
    }
    if args[1] == 0 {
        return Ok(negative_errno(libc::EINVAL));
    }
    let flags = args[3];
    let is_anonymous = flags & libc::MAP_ANONYMOUS as u64 != 0;
    let is_private = flags & libc::MAP_PRIVATE as u64 != 0;
    let is_shared = flags & libc::MAP_SHARED as u64 != 0;
    // mmap ignores protection bits other than read, write and execute.
    let prot = args[2] & super::MMAP_PROT_BITS;
    let Some(length) = align_up(args[1], PAGE_SIZE) else {
        return Ok(negative_errno(libc::ENOMEM));
    };
    // MAP_FIXED_NOREPLACE places as MAP_FIXED does and refuses an occupied
    // range (EEXIST) rather than replace it.
    let noreplace = flags & libc::MAP_FIXED_NOREPLACE as u64 != 0;
    let fixed = flags & libc::MAP_FIXED as u64 != 0 || noreplace;
    if let Some(errno) = super::fixed_mapping_address_error(fixed, args[0], length) {
        return Ok(negative_errno(errno));
    }
    if !is_anonymous && signalfd_mask(state, args[4] as libc::c_int).is_some() {
        return Ok(negative_errno(libc::ENODEV));
    }
    let kind = if is_anonymous {
        super::MappingKind::Anonymous
    } else {
        match state
            .files
            .get(&(args[4] as libc::c_int))
            .map(std::fs::File::metadata)
        {
            Some(Ok(metadata)) if metadata.is_file() => super::MappingKind::RegularFile(args[5]),
            _ => super::MappingKind::Other,
        }
    };
    // A MAP_FIXED address is a user address; the bookkeeping below is by
    // physical address, and the result is the user address.
    let address = if fixed {
        let Some(address) = memory.user_range_to_guest(args[0], length) else {
            return Ok(negative_errno(libc::ENOMEM));
        };
        address
    } else {
        let map_32bit = args[3] & libc::MAP_32BIT as u64 != 0;
        let Some(address) = super::place_mapping(memory, state, length, args[0], kind, map_32bit)
        else {
            return Ok(negative_errno(libc::ENOMEM));
        };
        address
    };
    let Some(end) = address.checked_add(length) else {
        return Ok(negative_errno(libc::ENOMEM));
    };
    if noreplace && let Some(errno) = super::noreplace_error(memory, state, args, address, end) {
        return Ok(negative_errno(errno));
    }
    if address < BOOT_RESERVED_END || end > state.mmap_limit {
        return Ok(negative_errno(libc::ENOMEM));
    }
    // An unknown mapping type is refused only after placement, as in do_mmap;
    // for an object that is not a regular file the object probe answers it.
    if !matches!(kind, super::MappingKind::Other) && !is_private && !is_shared {
        return Ok(negative_errno(libc::EINVAL));
    }
    let Ok(length) = usize::try_from(length) else {
        return Ok(negative_errno(libc::ENOMEM));
    };
    let ordinary_shared = !is_anonymous && is_shared;
    if is_anonymous && is_shared && memory.range_contains_shared_file(address, length) {
        // Retiring the last ordinary file releases its single-vCPU domain.
        // This bounded path does not establish that replacing a file view by
        // shared anonymous memory preserves every guarantee of that domain.
        return Err(unsupported_mmap(
            "shared anonymous replacement requires independent fork-sharing ownership",
        ));
    }
    // Replacing a fork-shared anonymous view by shared anonymous memory gets
    // fresh private backing marked shared; the next fork moves it into its own
    // shmem object, as for a new shared anonymous mapping (see
    // `GuestMemory::share_anonymous_memory_for_fork`).
    let replaces_file = memory.range_contains_retained_shared(address, length);
    if !ordinary_shared && !replaces_file {
        // This branch cannot zero an outgoing file view. Keep the existing
        // private/anonymous personality, including its flag and errno rules.
        let result = mmap(memory, state, args);
        memory.set_allocation_cursors(AllocationCursors::from_elf(state));
        drop(allocation);
        return Ok(result);
    }

    // These ignored compatibility flags require no extra VM semantics, and
    // MAP_FIXED_NOREPLACE's range is vacant by now, so it maps as MAP_FIXED.
    // Other flags (locking, population, huge pages, grows-down, and so on)
    // require their own faithful implementation before file-view replacement.
    let supported_flags = (libc::MAP_PRIVATE
        | libc::MAP_SHARED
        | libc::MAP_FIXED
        | libc::MAP_FIXED_NOREPLACE
        | libc::MAP_ANONYMOUS
        | libc::MAP_DENYWRITE
        | libc::MAP_EXECUTABLE) as u64;
    let writable = prot & libc::PROT_WRITE as u64 != 0;
    let mut cursors = AllocationCursors::from_elf(state);
    if !fixed {
        cursors.mmap_next = cursors.mmap_next.max(end);
    }

    if ordinary_shared {
        let fd = args[4] as libc::c_int;
        let Some(file) = state.files.get(&fd) else {
            return Ok(negative_errno(libc::EBADF));
        };
        let status = match file_status_flags(file) {
            Ok(status) => status,
            Err(error) => return Ok(error),
        };
        if status & libc::O_PATH != 0 {
            return Ok(negative_errno(libc::EBADF));
        }
        let mode = match file_mode(file) {
            Ok(mode) => mode,
            Err(error) => return Ok(error),
        };
        if mode & libc::S_IFMT != libc::S_IFREG {
            // The object's own refusal (mapping type and flag validation,
            // access mode, a missing mmap operation) is the host kernel's, in
            // its order. One the kernel maps is beyond this path, which shares
            // only regular files: it ends the run with the capability refusal,
            // and the probe's mapping is already gone.
            if let Some(error) = super::host_mmap_probe(file.as_raw_fd(), args) {
                return Ok(error);
            }
            return Err(unsupported_mmap(
                "only ordinary regular files are supported",
            ));
        }
        if !matches!(status & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR)
            || (writable && status & libc::O_ACCMODE != libc::O_RDWR)
        {
            return Ok(negative_errno(libc::EACCES));
        }
        // A write seal forbids a writable shared view; a readonly view remains
        // valid but must never gain write permission through later mprotect.
        // SAFETY: file retains a live descriptor and F_GET_SEALS has no input pointer.
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Ok(io_error(error));
            }
        }
        let sealed_write =
            seals >= 0 && seals & (libc::F_SEAL_WRITE | libc::F_SEAL_FUTURE_WRITE) != 0;
        if writable && sealed_write {
            return Ok(negative_errno(libc::EPERM));
        }
        classify_shared_mmap_file(state, fd, file, capture_output)?;
        if flags & !supported_flags != 0 {
            return Err(unsupported_mmap(
                "mapping flags need unsupported file-view semantics",
            ));
        }
        if prot & libc::PROT_EXEC as u64 != 0 {
            return Err(unsupported_mmap(
                "executable file views require host noexec validation",
            ));
        }
        if args[5]
            .checked_add(length as u64)
            .is_none_or(|end| libc::off_t::try_from(end).is_err())
        {
            return Err(unsupported_mmap(
                "file-view extent exceeds nonnegative host off_t",
            ));
        }
        let file = match file.as_fd().try_clone_to_owned() {
            Ok(file) => file,
            Err(error) => return Ok(io_error(error)),
        };
        memory.publish_shared_file_range(
            allocation,
            SharedFileRangePlan {
                address,
                length,
                file,
                offset: args[5],
                readable: prot != libc::PROT_NONE as u64,
                writable,
                max_writable: status & libc::O_ACCMODE == libc::O_RDWR && !sealed_write,
                cursors: Some(cursors),
            },
        )?;
    } else {
        // The target overlaps an ordinary-file view. Prepare the private
        // replacement's contents without writing or zeroing that old view.
        let file_bytes = if !is_anonymous {
            let Some(file) = state.files.get(&(args[4] as libc::c_int)) else {
                return Ok(negative_errno(libc::EBADF));
            };
            if !matches!(kind, super::MappingKind::RegularFile(_))
                && let Some(error) = super::host_mmap_probe(file.as_raw_fd(), args)
            {
                return Ok(error);
            }
            let mut bytes = vec![0; length];
            let mut count = 0;
            while count < length {
                #[cfg(test)]
                entry_host_wait_tests::observe_mmap_file_read();
                match file.read_at(&mut bytes[count..], args[5].saturating_add(count as u64)) {
                    Ok(0) => break,
                    Ok(read) => count += read,
                    Err(error) => return Ok(io_error(error)),
                }
            }
            Some(bytes)
        } else if args[4] as i32 != -1 {
            return Ok(negative_errno(libc::EINVAL));
        } else {
            None
        };
        if flags & !supported_flags != 0 {
            return Err(unsupported_mmap(
                "replacement flags need unsupported file-view semantics",
            ));
        }
        memory.publish_private_range(
            allocation,
            PrivateRangePlan {
                address,
                length,
                contents: file_bytes.as_deref(),
                permissions: Some((prot != libc::PROT_NONE as u64, writable)),
                cursors: Some(cursors),
            },
        )?;
    }
    memory.record_page_backing(
        address,
        length as u64,
        kind.file_offset(),
        is_anonymous && is_shared,
    );
    state.mmap_next = cursors.mmap_next;
    Ok(memory.physical_to_user(address).unwrap_or(address) as i64)
}

/// Preserve legacy invalid-argument precedence before a valid file history
/// reaches the explicit unsupported remap boundary. No read or copy occurs.
pub(super) fn remap_requires_shared_capability(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    contains: fn(&GuestMemory, u64, usize) -> bool,
) -> bool {
    let Some(old_length) = align_up(args[1], PAGE_SIZE) else {
        return false;
    };
    let Some(new_length) = align_up(args[2], PAGE_SIZE) else {
        return false;
    };
    let flags = args[3];
    let allowed = (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64;
    let fixed = flags & libc::MREMAP_FIXED as u64 != 0;
    if old_length == 0
        || new_length == 0
        || !args[0].is_multiple_of(PAGE_SIZE)
        || flags & !allowed != 0
        || (fixed && flags & libc::MREMAP_MAYMOVE as u64 == 0)
        || !range_is_valid(&ProviderMemory(memory), args[0], old_length)
    {
        return false;
    }
    // The source and destination are user addresses (a window's, in Linux's
    // layout); the mapping metadata below is by physical address.
    let Some(source) = memory.user_range_to_guest(args[0], old_length) else {
        return false;
    };
    if !memory.user_range_is_mapped(source, old_length) {
        return false;
    }
    let mut destination = None;
    if fixed {
        if !args[4].is_multiple_of(PAGE_SIZE) {
            return false;
        }
        let Some(start) = memory.user_range_to_guest(args[4], new_length) else {
            return false;
        };
        let end = start + new_length;
        if start < BOOT_RESERVED_END
            || end > state.mmap_limit
            || (start < source + old_length && source < end)
        {
            return false;
        }
        destination = Some(start);
    }
    contains(memory, source, old_length as usize)
        || destination.is_some_and(|start| contains(memory, start, new_length as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backing(name: &CStr) -> std::fs::File {
        // SAFETY: name is terminated and the successful descriptor is owned below.
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        assert!(
            fd >= 0,
            "memfd setup failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: memfd_create returned this newly owned descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.set_len(4 * PAGE_SIZE).unwrap();
        file
    }

    fn setup() -> (GuestMemory, LoadedStaticElf) {
        let mut state = native_loaded_state(std::path::Path::new("/"));
        state.mmap_limit = BOOT_RESERVED_END + 8 * PAGE_SIZE;
        let memory = GuestMemory::new(0, state.mmap_limit as usize).unwrap();
        (memory, state)
    }

    fn call(
        memory: &mut GuestMemory,
        state: &mut LoadedStaticElf,
        args: [u64; 6],
        capture: bool,
    ) -> crate::Result<i64> {
        let owner = memory.clone();
        let allocation = owner.allocation_guard();
        mmap_with_shared_files(memory, state, &args, capture, allocation)
    }

    fn bytes(memory: &GuestMemory, address: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        memory.read(address, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn shared_mmap_fd_coherence_survives_close_reuse_and_partial_private_replacement() {
        let (mut memory, mut state) = setup();
        let original = backing(c"shared-map-original");
        original.write_all_at(b"first!", 0).unwrap();
        original.write_all_at(b"tail!!", PAGE_SIZE).unwrap();
        state.files.insert(3, original.try_clone().unwrap());
        let address = call(
            &mut memory,
            &mut state,
            [
                0,
                2 * PAGE_SIZE,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                libc::MAP_SHARED as u64,
                3,
                0,
            ],
            false,
        )
        .unwrap();
        assert!(address > 0);
        let address = address as u64;
        assert_eq!(bytes(&memory, address, 6), b"first!");
        memory.write(address, b"mapped").unwrap();
        let mut observed = [0; 6];
        original.read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(&observed, b"mapped");
        original.write_all_at(b"fdedit", 0).unwrap();
        assert_eq!(bytes(&memory, address, 6), b"fdedit");

        let overlapping = call(
            &mut memory,
            &mut state,
            [
                0,
                PAGE_SIZE,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                libc::MAP_SHARED as u64,
                3,
                PAGE_SIZE,
            ],
            false,
        )
        .unwrap();
        assert!(overlapping > 0);
        assert_ne!(overlapping as u64, address + PAGE_SIZE);
        memory.write(overlapping as u64, b"alias!").unwrap();
        assert_eq!(bytes(&memory, address + PAGE_SIZE, 6), b"alias!");

        let replacement_fd = backing(c"shared-map-reused-fd");
        replacement_fd.write_all_at(b"other!", 0).unwrap();
        state.files.insert(3, replacement_fd.try_clone().unwrap());
        memory.write(address, b"oldofd").unwrap();
        original.read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(&observed, b"oldofd");
        replacement_fd.read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(&observed, b"other!");

        assert_eq!(
            call(
                &mut memory,
                &mut state,
                [
                    address,
                    PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64,
                    u64::MAX,
                    0
                ],
                false,
            )
            .unwrap(),
            address as i64
        );
        assert_eq!(
            bytes(&memory, address, PAGE_SIZE as usize),
            vec![0; PAGE_SIZE as usize]
        );
        original.read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(&observed, b"oldofd", "replacement zeroed the outgoing file");
        assert_eq!(bytes(&memory, address + PAGE_SIZE, 6), b"alias!");
        memory.write(address, b"privat").unwrap();
        original.read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(&observed, b"oldofd");
        memory.write(address + PAGE_SIZE, b"shared").unwrap();
        original.read_exact_at(&mut observed, PAGE_SIZE).unwrap();
        assert_eq!(&observed, b"shared");
        assert_eq!(bytes(&memory, overlapping as u64, 6), b"shared");
    }

    #[test]
    fn shared_mmap_write_seals_preserve_native_refusal_and_allow_readonly_views() {
        for seal in [libc::F_SEAL_WRITE, libc::F_SEAL_FUTURE_WRITE] {
            let (mut memory, mut state) = setup();
            let file = backing(c"shared-map-sealed");
            file.write_all_at(b"sealed", 0).unwrap();
            // SAFETY: file owns a sealable memfd and the argument is a seal bit.
            assert_eq!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seal) },
                0
            );
            // The failure oracle uses the same live sealed object and requested
            // protection. No host mapping may succeed in this control.
            let native = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE_SIZE as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            let native_errno = std::io::Error::last_os_error().raw_os_error();
            assert_eq!(native, libc::MAP_FAILED);
            assert_eq!(native_errno, Some(libc::EPERM));
            state.files.insert(3, file);
            let address = state.mmap_base;
            memory.write(address, &[0xa5; 16]).unwrap();
            let before = memory.allocation_cursors();
            assert_eq!(
                call(
                    &mut memory,
                    &mut state,
                    [
                        address,
                        PAGE_SIZE,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        (libc::MAP_SHARED | libc::MAP_FIXED) as u64,
                        3,
                        0
                    ],
                    false,
                )
                .unwrap(),
                negative_errno(libc::EPERM)
            );
            assert_eq!(bytes(&memory, address, 16), [0xa5; 16]);
            assert_eq!(memory.allocation_cursors(), before);
            assert!(!memory.contains_shared_file());
            assert_eq!(
                call(
                    &mut memory,
                    &mut state,
                    [
                        address,
                        PAGE_SIZE,
                        libc::PROT_READ as u64,
                        (libc::MAP_SHARED | libc::MAP_FIXED) as u64,
                        3,
                        0
                    ],
                    false,
                )
                .unwrap(),
                address as i64
            );
            assert_eq!(bytes(&memory, address, 6), b"sealed");
            assert!(!memory.file_write_permitted(address, PAGE_SIZE as usize));
        }
    }

    #[test]
    fn shared_mmap_capability_refusals_preserve_target_and_descriptor_precedence() {
        let (mut memory, mut state) = setup();
        state.files.insert(3, backing(c"reverie-kvm-virtual"));
        state.files.insert(4, backing(c"shared-map-ordinary"));
        let address = state.mmap_base;
        memory.write(address, &[0x5a; 32]).unwrap();
        let base = [
            address,
            PAGE_SIZE,
            libc::PROT_READ as u64,
            (libc::MAP_SHARED | libc::MAP_FIXED) as u64,
            3,
            0,
        ];
        for (fd, flags, protection, offset) in [
            (3, base[3], base[2], 0),
            (4, base[3] | libc::MAP_LOCKED as u64, base[2], 0),
            (4, base[3], (libc::PROT_READ | libc::PROT_EXEC) as u64, 0),
            (4, base[3], base[2], 1_u64 << 63),
        ] {
            let mut args = base;
            args[2] = protection;
            args[3] = flags;
            args[4] = fd;
            args[5] = offset;
            let before = memory.allocation_cursors();
            assert!(matches!(
                call(&mut memory, &mut state, args, false),
                Err(crate::Error::SharedFileCapability { .. })
            ));
            assert_eq!(bytes(&memory, address, 32), [0x5a; 32]);
            assert_eq!(memory.allocation_cursors(), before);
            assert!(!memory.contains_shared_file());
        }
        let mut invalid = base;
        invalid[4] = u64::MAX;
        invalid[3] |= libc::MAP_LOCKED as u64;
        assert_eq!(
            call(&mut memory, &mut state, invalid, false).unwrap(),
            negative_errno(libc::EBADF)
        );
        invalid[1] = 0;
        assert_eq!(
            call(&mut memory, &mut state, invalid, false).unwrap(),
            negative_errno(libc::EINVAL)
        );
        state.stdout_alias_fds.insert(4);
        let mut captured = base;
        captured[4] = 4;
        assert!(matches!(
            call(&mut memory, &mut state, captured, true),
            Err(crate::Error::SharedFileCapability { .. })
        ));
        assert_eq!(bytes(&memory, address, 32), [0x5a; 32]);
    }

    /// What the host kernel answers when `path`, opened with `open_flags`, is
    /// mapped natively: zero for a mapping, or the negative errno of its
    /// refusal.
    fn native_mmap_result(
        path: &str,
        open_flags: libc::c_int,
        length: u64,
        flags: libc::c_int,
    ) -> i64 {
        let name = CString::new(path).unwrap();
        // SAFETY: name is NUL-terminated; the descriptor is closed below.
        let fd = unsafe { libc::open(name.as_ptr(), open_flags | libc::O_CLOEXEC) };
        assert!(fd >= 0, "{path}");
        // SAFETY: a kernel-placed mapping of a live descriptor, unmapped below.
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length as usize,
                libc::PROT_READ,
                flags,
                fd,
                0,
            )
        };
        let result = if mapped == libc::MAP_FAILED {
            io_error(std::io::Error::last_os_error())
        } else {
            // SAFETY: the mapping above is `length` bytes and is not used again.
            assert_eq!(unsafe { libc::munmap(mapped, length as usize) }, 0);
            0
        };
        // SAFETY: fd is owned here.
        unsafe { libc::close(fd) };
        result
    }

    /// The executor copies a mapped file's bytes into guest memory, which
    /// would succeed for any object read(2) reads. For an object that is not a
    /// regular file, every refusal is the host kernel's, in its order: the
    /// O_PATH lookup (EBADF, even for a zero length), MAP_HUGETLB outside
    /// hugetlbfs (EINVAL), MAP_SHARED_VALIDATE's unknown flags (EOPNOTSUPP),
    /// the access mode (EACCES) and a missing mmap operation (ENODEV). A
    /// refusal leaves guest memory and the mmap cursor unchanged, MAP_FIXED
    /// included. An accepted private mapping keeps the copy (zeros, for
    /// /dev/zero); an accepted shared one remains the named capability
    /// refusal.
    #[test]
    fn non_regular_file_mmap_follows_the_host_kernel() {
        // Linux's random devices have no mmap operation.
        assert_eq!(
            native_mmap_result("/dev/urandom", libc::O_RDONLY, PAGE_SIZE, libc::MAP_PRIVATE),
            negative_errno(libc::ENODEV)
        );
        let cases = [
            (libc::O_RDONLY, libc::MAP_PRIVATE, PAGE_SIZE),
            (libc::O_RDONLY, libc::MAP_SHARED, PAGE_SIZE),
            (
                libc::O_RDONLY,
                libc::MAP_PRIVATE | libc::MAP_HUGETLB,
                PAGE_SIZE,
            ),
            (
                libc::O_RDONLY,
                libc::MAP_SHARED_VALIDATE | libc::MAP_SYNC,
                PAGE_SIZE,
            ),
            (libc::O_WRONLY, libc::MAP_PRIVATE, PAGE_SIZE),
            (libc::O_WRONLY, libc::MAP_SHARED, PAGE_SIZE),
            (libc::O_PATH, libc::MAP_PRIVATE, PAGE_SIZE),
            (libc::O_PATH, libc::MAP_PRIVATE, 0),
        ];
        for path in ["/dev/urandom", "/dev/random", "/dev/null", "/dev/zero", "/"] {
            for (open_flags, flags, length) in cases {
                if path == "/" && open_flags == libc::O_WRONLY {
                    continue;
                }
                let (mut memory, mut state) = setup();
                let name = CString::new(path).unwrap();
                // SAFETY: name is NUL-terminated; the File owns the descriptor.
                let fd = unsafe { libc::open(name.as_ptr(), open_flags | libc::O_CLOEXEC) };
                assert!(fd >= 0, "{path}");
                // SAFETY: open returned this newly owned descriptor.
                state
                    .files
                    .insert(3, unsafe { std::fs::File::from_raw_fd(fd) });
                let address = state.mmap_base;
                memory.write(address, &[0x5a; 32]).unwrap();
                let before = state.mmap_next;
                let args = [0, length, libc::PROT_READ as u64, flags as u64, 3, 0];
                let result = call(&mut memory, &mut state, args, false);
                let native = native_mmap_result(path, open_flags, length, flags);
                let label = format!("{path} open={open_flags:#x} flags={flags:#x} length={length}");
                if native < 0 {
                    assert_eq!(result.unwrap(), native, "{label}");
                    assert_eq!(bytes(&memory, address, 32), [0x5a; 32], "{label}");
                    assert_eq!(state.mmap_next, before, "{label}");
                } else if flags & libc::MAP_TYPE == libc::MAP_PRIVATE {
                    let mapped = result.unwrap();
                    assert!(mapped > 0, "{label}: {mapped}");
                    let mapped = memory
                        .user_range_to_guest(mapped as u64, PAGE_SIZE)
                        .unwrap();
                    assert_eq!(bytes(&memory, mapped, 32), [0; 32], "{label}");
                } else {
                    assert!(
                        matches!(result, Err(crate::Error::SharedFileCapability { .. })),
                        "{label}"
                    );
                }
                assert!(!memory.contains_shared_file(), "{label}");
            }
        }
        // A refused MAP_FIXED mapping leaves the bytes it would have replaced.
        for flags in [libc::MAP_PRIVATE, libc::MAP_SHARED] {
            let (mut memory, mut state) = setup();
            state
                .files
                .insert(3, std::fs::File::open("/dev/urandom").unwrap());
            let address = state.mmap_base;
            memory.write(address, &[0x5a; 32]).unwrap();
            let args = [
                address,
                PAGE_SIZE,
                libc::PROT_READ as u64,
                (flags | libc::MAP_FIXED) as u64,
                3,
                0,
            ];
            assert_eq!(
                call(&mut memory, &mut state, args, false).unwrap(),
                negative_errno(libc::ENODEV),
                "flags={flags:#x}"
            );
            assert_eq!(bytes(&memory, address, 32), [0x5a; 32], "flags={flags:#x}");
        }
    }
}
