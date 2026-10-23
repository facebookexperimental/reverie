/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests: FileTableState is private to this module.
mod file_table_publish_tests {
    use super::*;

    /// Whether two host descriptors of this process share one open file
    /// description.
    fn same_description(left: RawFd, right: RawFd) -> bool {
        const KCMP_FILE: libc::c_int = 0;
        // SAFETY: kcmp only compares this process's own descriptors.
        let pid = unsafe { libc::getpid() };
        let answer = unsafe { libc::syscall(libc::SYS_kcmp, pid, pid, KCMP_FILE, left, right) };
        assert!(answer >= 0, "kcmp failed");
        answer == 0
    }

    /// Publishing a changed descriptor table clones only the entries that
    /// changed. An unchanged entry keeps the host descriptor already published
    /// for it; a new or replaced entry gets a clone of its new description;
    /// a removed one leaves the table.
    #[test]
    fn publishing_clones_only_changed_entries() {
        let root = TestDir::new();
        let path = |name: &str| root.0.join(name);
        for name in ["kept", "replaced", "replacement", "removed", "added"] {
            std::fs::write(path(name), name).unwrap();
        }
        let mut state = test_state(&root.0);
        for (fd, name) in [(3, "kept"), (4, "replaced"), (5, "removed")] {
            assert!(
                state
                    .insert_file(fd, std::fs::File::open(path(name)).unwrap())
                    .is_empty()
            );
        }
        let mut table = FileTableState::try_from_elf(&state).unwrap();
        let published = |table: &FileTableState, fd: i32| table.files[&fd].as_raw_fd();
        let kept = published(&table, 3);
        let replaced = published(&table, 4);
        assert!(same_description(kept, state.files[&3].as_raw_fd()));

        let retired = state.insert_file(4, std::fs::File::open(path("replacement")).unwrap());
        assert_eq!(retired.len(), 1);
        assert!(state.remove_file(5).is_some());
        assert!(
            state
                .insert_file(6, std::fs::File::open(path("added")).unwrap())
                .is_empty()
        );
        table.update_from_elf(&state).unwrap();

        assert_eq!(published(&table, 3), kept, "an unchanged entry is not cloned again");
        assert!(same_description(published(&table, 3), state.files[&3].as_raw_fd()));
        assert!(same_description(published(&table, 4), state.files[&4].as_raw_fd()));
        assert!(!same_description(published(&table, 4), retired[0].as_raw_fd()));
        assert_ne!(published(&table, 4), replaced);
        assert!(same_description(published(&table, 6), state.files[&6].as_raw_fd()));
        assert!(!table.files.contains_key(&5));
        assert_eq!(
            table.files.keys().copied().collect::<Vec<_>>(),
            state.files.keys().copied().collect::<Vec<_>>()
        );
        for fd in [3, 4, 6] {
            assert!(Arc::ptr_eq(&table.fd_entry_ids[&fd], &state.fd_entry_ids[&fd]));
        }
    }

    /// A clone that fails partway through a publication that also keeps
    /// entries leaves the published table exactly as it was: the same
    /// entries, host descriptors and identities.
    #[test]
    fn a_failed_clone_leaves_the_published_table_intact() {
        let root = TestDir::new();
        let path = |name: &str| root.0.join(name);
        for name in ["kept", "replaced", "replacement", "added", "second"] {
            std::fs::write(path(name), name).unwrap();
        }
        let mut state = test_state(&root.0);
        for (fd, name) in [(3, "kept"), (4, "replaced")] {
            assert!(
                state
                    .insert_file(fd, std::fs::File::open(path(name)).unwrap())
                    .is_empty()
            );
        }
        let mut table = FileTableState::try_from_elf(&state).unwrap();
        let snapshot = |table: &FileTableState| {
            table
                .files
                .iter()
                .map(|(&fd, file)| (fd, file.as_raw_fd(), Arc::as_ptr(&table.fd_entry_ids[&fd])))
                .collect::<Vec<_>>()
        };
        let before = snapshot(&table);

        let _ = state.insert_file(4, std::fs::File::open(path("replacement")).unwrap());
        assert!(
            state
                .insert_file(5, std::fs::File::open(path("added")).unwrap())
                .is_empty()
        );
        assert!(
            state
                .insert_file(6, std::fs::File::open(path("second")).unwrap())
                .is_empty()
        );
        // Three entries changed and one is kept; the second needed clone fails.
        state.file_retirement.fail_clone_after(Some(1));
        let error = table.update_from_elf(&state).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
        state.file_retirement.fail_clone_after(None);
        assert_eq!(snapshot(&table), before, "a failed publication changes nothing");

        table.update_from_elf(&state).unwrap();
        assert_eq!(table.files[&3].as_raw_fd(), before[0].1, "the kept entry is still reused");
        assert_eq!(
            table.files.keys().copied().collect::<Vec<_>>(),
            vec![3, 4, 5, 6]
        );
    }
}
