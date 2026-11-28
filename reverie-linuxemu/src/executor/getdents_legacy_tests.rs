/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests, beside the getdents64 tests: x86_64's legacy
// getdents, which the executor answers with the host kernel's own
// `struct linux_dirent` records (fs/readdir.c serves both calls from one
// directory iterator).
mod getdents_legacy_tests {
    use super::*;

    const PATH_ADDRESS: u64 = 0x100;
    const DIRENTS_ADDRESS: u64 = 0x1000;
    const DIRENTS_CAPACITY: usize = 0x4000;

    /// The name and type of each `struct linux_dirent` record in `bytes`.
    /// x86_64's legacy layout is `d_ino` (8 bytes), `d_off` (8), `d_reclen`
    /// (2), the terminated name, padding, and `d_type` in the record's last
    /// byte (fs/readdir.c `filldir`).
    fn legacy_dirents(bytes: &[u8]) -> Vec<(Vec<u8>, u8)> {
        const NAME_OFFSET: usize = 18;
        let mut records = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            assert!(offset + NAME_OFFSET + 2 <= bytes.len(), "truncated record");
            let length = usize::from(u16::from_ne_bytes([bytes[offset + 16], bytes[offset + 17]]));
            assert!(
                length >= NAME_OFFSET + 2 && length % std::mem::size_of::<u64>() == 0,
                "record length {length}"
            );
            assert!(offset + length <= bytes.len(), "record overruns the result");
            let name = &bytes[offset + NAME_OFFSET..offset + length - 1];
            let end = name.iter().position(|byte| *byte == 0).expect("terminated");
            records.push((name[..end].to_vec(), bytes[offset + length - 1]));
            offset += length;
        }
        records.sort();
        records
    }

    /// The host kernel's own legacy records for `path`, from a descriptor
    /// opened here, outside the executor.
    fn host_legacy_dirents(path: &Path) -> Vec<(Vec<u8>, u8)> {
        let directory = std::fs::File::open(path).unwrap();
        let mut buffer = vec![0_u8; DIRENTS_CAPACITY];
        // SAFETY: the buffer is writable for its stated length, and the
        // descriptor is live for the call.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents,
                directory.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        assert!(count > 0, "host getdents: {count}");
        legacy_dirents(&buffer[..count as usize])
    }

    fn open_at(
        memory: &mut GuestMemory,
        state: &mut LoadedStaticElf,
        path: &[u8],
        flags: libc::c_int,
    ) -> i64 {
        assert_eq!(path.last(), Some(&0), "terminated path");
        memory.write(PATH_ADDRESS, path).unwrap();
        syscall_result(
            memory,
            state,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, PATH_ADDRESS, flags as u64, 0, 0, 0],
        )
    }

    fn legacy_getdents(
        memory: &mut GuestMemory,
        state: &mut LoadedStaticElf,
        fd: i64,
        count: u64,
    ) -> i64 {
        syscall_result(
            memory,
            state,
            libc::SYS_getdents,
            [fd as u64, DIRENTS_ADDRESS, count, 0, 0, 0],
        )
    }

    #[test]
    fn legacy_getdents_returns_the_host_kernels_linux_dirent_records() {
        let root = TestDir::new();
        std::fs::write(root.0.join("alpha"), b"a").unwrap();
        std::fs::write(root.0.join("beta"), b"b").unwrap();
        std::fs::create_dir(root.0.join("gamma")).unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x8000).unwrap();

        let fd = open_at(
            &mut memory,
            &mut state,
            b".\0",
            libc::O_RDONLY | libc::O_DIRECTORY,
        );
        assert!(fd >= 0, "openat: {fd}");
        let count = legacy_getdents(&mut memory, &mut state, fd, DIRENTS_CAPACITY as u64);
        assert!(count > 0, "getdents: {count}");
        let mut bytes = vec![0; count as usize];
        memory.read(DIRENTS_ADDRESS, &mut bytes).unwrap();
        let records = legacy_dirents(&bytes);

        // The guest sees exactly what Linux gives a native caller, names and
        // types alike, ...
        assert_eq!(records, host_legacy_dirents(&root.0));
        // ... and that is the whole directory, not an empty agreement.
        let names: Vec<&[u8]> = records.iter().map(|(name, _)| name.as_slice()).collect();
        assert_eq!(names, [&b"."[..], b"..", b"alpha", b"beta", b"gamma"]);

        // The directory is now exhausted, and the cursor belongs to the open
        // description: getdents64 on the same descriptor sees the same end.
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, fd, DIRENTS_CAPACITY as u64),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_getdents64,
                [fd as u64, DIRENTS_ADDRESS, DIRENTS_CAPACITY as u64, 0, 0, 0],
            ),
            0
        );
    }

    #[test]
    fn legacy_getdents_answers_linux_errors() {
        let root = TestDir::new();
        std::fs::write(root.0.join("file"), b"f").unwrap();
        std::fs::create_dir(root.0.join("dir")).unwrap();
        std::fs::write(root.0.join("dir").join("entry"), b"e").unwrap();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 0x8000).unwrap();

        // A descriptor that is not open.
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, 99, 256),
            negative_errno(libc::EBADF)
        );
        // A regular file is not a directory.
        let file = open_at(&mut memory, &mut state, b"file\0", libc::O_RDONLY);
        assert!(file >= 0, "openat file: {file}");
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, file, 256),
            negative_errno(libc::ENOTDIR)
        );
        // O_PATH descriptors, of a file and of a directory, cannot be read.
        let path_file = open_at(&mut memory, &mut state, b"file\0", libc::O_PATH);
        assert!(path_file >= 0, "openat O_PATH file: {path_file}");
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, path_file, 256),
            negative_errno(libc::EBADF)
        );
        let path_dir = open_at(
            &mut memory,
            &mut state,
            b"dir\0",
            libc::O_PATH | libc::O_DIRECTORY,
        );
        assert!(path_dir >= 0, "openat O_PATH dir: {path_dir}");
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, path_dir, 256),
            negative_errno(libc::EBADF)
        );
        // A buffer too small for the next record is EINVAL while entries
        // remain: zero bytes, and one byte.
        let dir = open_at(
            &mut memory,
            &mut state,
            b"dir\0",
            libc::O_RDONLY | libc::O_DIRECTORY,
        );
        assert!(dir >= 0, "openat dir: {dir}");
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, dir, 0),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            legacy_getdents(&mut memory, &mut state, dir, 1),
            negative_errno(libc::EINVAL)
        );
    }
}
