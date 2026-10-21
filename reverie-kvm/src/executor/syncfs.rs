// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(kvm-syncfs-ordinary): Review the ordinary-filesystem scope.
// https://github.com/rrnewton/reverie/issues/838
//
// This is deliberately independent of the authenticated synthetic-filesystem
// contract in https://github.com/rrnewton/reverie/pull/610. Ordinary host files,
// directories, pipes, sockets and nonreserved memfds use Linux syncfs, including
// its exact writeback errno. Private synthetic storage and captured output stay
// unsupported (ENOSYS); their host filesystem is not the guest filesystem.
fn sync_filesystem(state: &LoadedStaticElf, raw_fd: u64, capture_output: bool) -> i64 {
    // fs/sync.c's SYSCALL_DEFINE1(syncfs, int, fd) consumes the low int word;
    // fdget excludes O_PATH before performing any filesystem operation.
    let fd = raw_fd as libc::c_int;
    let Some(host) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let flags = match fd_status_flags(host) {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    if flags & libc::O_PATH != 0 {
        return negative_errno(libc::EBADF);
    }
    if state.proc_files.contains_key(&fd)
        || state.fdinfo_files.contains_key(&fd)
        || state.random_device_fds.contains(&fd)
        || signalfd_mask(state, fd).is_some()
        || (capture_output && output_alias(state, fd).is_some())
    {
        return negative_errno(libc::ENOSYS);
    }

    // Fixed proc SCM_RIGHTS transfers lose proc_files, and open_virtual_file
    // (including loginuid) has no identity side table. Read the actual object's
    // immutable memfd name, not its payload, guest pathname, seals or mode.
    // A name is ONLY a deny predicate: colliding/forged names are unsupported,
    // never authenticated. Ordinary same-content memfds still reach the host.
    let path = match canonical_fd_path(host) {
        Ok(path) => path,
        Err(_) => return negative_errno(libc::ENOSYS),
    };
    if syncfs_private_memfd_name(path.as_os_str().as_bytes(), state.host_metadata_timestamps) {
        return negative_errno(libc::ENOSYS);
    }

    if capture_output {
        // SCM_RIGHTS also loses output_alias. Compare the live objects for ALL
        // host backing types (regular files and sockets as well as pipes).
        // Inability to inspect either retained host stream is a refusal, not
        // evidence that the target is unrelated. Guest close/dup/exec never
        // closes these supervisor descriptors. As with pipe_fionread, external
        // replacement of supervisor stdio while a captured run lives is outside
        // the backend's supported host lifetime contract.
        let target = match host_file_key(host) {
            Ok(key) => key,
            Err(_) => return negative_errno(libc::ENOSYS),
        };
        for standard in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            match host_file_key(standard) {
                Ok(key) if key != target => {}
                _ => return negative_errno(libc::ENOSYS),
            }
        }
    }

    // FileTableState::install retains owned Files in this LoadedStaticElf,
    // cloning changed entries while holding the shared table lock. This
    // immutable state borrow keeps each File alive through classification AND
    // the syscall, even when a sibling closes/reuses its guest slot after the
    // table lock is released.
    // Implicit stdin is likewise owned; noncaptured host stdout/stderr use the
    // existing supervisor-stdio lifetime contract described above.
    if raw_host_syncfs(host) == 0 {
        0
    } else {
        // Capture errno immediately, with no second call or retry.
        io_error(std::io::Error::last_os_error())
    }
}

fn syncfs_private_memfd_name(path: &[u8], host_metadata_timestamps: bool) -> bool {
    let Some(name) = path
        .strip_prefix(b"/memfd:")
        .and_then(|name| name.strip_suffix(b" (deleted)"))
    else {
        return false;
    };
    // Current creation sites: open_synthetic_proc (also process stat/status and
    // fdinfo), open_virtual_file/open_random_device, and create_memory_backing.
    // Guest RAM is not exported, but must not become ordinary if imported.
    // The last two are reserved carrier shapes from the preserved PR610
    // implementation. Refusing them does not implement its EBADMSG/auth rules.
    // open_virtual_file names its memfd reverie-kvm-virtual-file only in a run
    // that reports host metadata timestamps. In any other run the backend never
    // creates that name, so a guest memfd carrying it stays ordinary.
    matches!(
        name,
        b"reverie-kvm-proc" | b"reverie-kvm-virtual" | b"reverie-kvm-guest-memory"
    ) || (host_metadata_timestamps && name == b"reverie-kvm-virtual-file")
        || name.starts_with(b"reverie-kvm.proc-carrier.v1")
        || name.starts_with(b"reverie-kvm.capture-transfer.v1")
}

#[cfg(test)]
type SyncfsTestHook = Box<dyn FnMut(RawFd) -> libc::c_int>;

#[cfg(test)]
std::thread_local! {
    static SYNCFS_TEST_HOOK: std::cell::RefCell<Option<SyncfsTestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
struct SyncfsTestHookGuard;

#[cfg(test)]
impl Drop for SyncfsTestHookGuard {
    fn drop(&mut self) {
        SYNCFS_TEST_HOOK.with(|slot| {
            assert!(slot.borrow_mut().take().is_some(), "syncfs hook lost");
        });
    }
}

#[cfg(test)]
fn install_syncfs_test_hook(
    hook: impl FnMut(RawFd) -> libc::c_int + 'static,
) -> SyncfsTestHookGuard {
    SYNCFS_TEST_HOOK.with(|slot| {
        assert!(slot.borrow().is_none(), "nested syncfs hook");
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    SyncfsTestHookGuard
}

fn raw_host_syncfs(host: RawFd) -> libc::c_int {
    #[cfg(test)]
    if let Some(result) =
        SYNCFS_TEST_HOOK.with(|slot| slot.borrow_mut().as_mut().map(|hook| hook(host)))
    {
        return result;
    }
    // SAFETY: the caller retains the translated descriptor through this call;
    // syncfs has no user pointers. Linux validates the actual filesystem.
    unsafe { libc::syncfs(host) }
}
