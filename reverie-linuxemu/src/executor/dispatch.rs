/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Syscall dispatch (gVisor: pkg/sentry/syscalls/linux, linux64.go).

use super::*;

// Retain the audited process-syscall classification even though the root
// dispatcher no longer excludes these syscalls from Reverie tools.
#[allow(dead_code)]
pub(crate) fn is_process_syscall(number: u64) -> bool {
    number == libc::SYS_fork as u64
        || number == libc::SYS_vfork as u64
        || number == libc::SYS_clone as u64
        || number == libc::SYS_clone3 as u64
        || number == libc::SYS_execve as u64
        || number == libc::SYS_execveat as u64
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-92): Review wait4 process-action classification.
        || number == libc::SYS_wait4 as u64
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review waitid process-action classification.
        || number == libc::SYS_waitid as u64
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-216): Review direct-worker classification for CLONE_THREAD.
// CLONE_THREAD is no longer treated as backend-owned (workers now run through
// the Tool loop; see runtime.rs), so this classifier is retained only for the
// clone-flag decoding regression tests below.
#[cfg(test)]
pub(crate) fn is_thread_clone_request(request: &SyscallRequest, memory: &GuestMemory) -> bool {
    if request.number() == libc::SYS_clone as u64 {
        return request.args()[0] & libc::CLONE_THREAD as u64 != 0;
    }
    if request.number() == libc::SYS_clone3 as u64 {
        let args = request.args();
        return read_clone3(&ProviderMemory(memory), args[0], args[1])
            .is_ok_and(|clone| clone.flags & libc::CLONE_THREAD as u64 != 0);
    }
    false
}

#[cfg(test)]
pub(crate) fn execute_basic_syscall(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
) -> SyscallAction {
    execute_basic_syscall_with_output(memory, state, request, None, None)
}

#[cfg(test)]
pub(super) fn execute_basic_syscall_with_output(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
    current_user_stack_pointer: Option<u64>,
    output: Option<&mut CapturedOutput>,
) -> SyscallAction {
    execute_basic_syscall_with_read_context(
        memory,
        state,
        request,
        current_user_stack_pointer,
        output,
        None,
    )
}

pub(super) fn execute_basic_syscall_with_read_context(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
    current_user_stack_pointer: Option<u64>,
    output: Option<&mut CapturedOutput>,
    terminal_read: Option<(
        &mut crate::terminal_read::ReadContext,
        reverie::SignalTaskIdentity,
    )>,
) -> SyscallAction {
    let action = execute_basic_syscall_dispatch(
        memory,
        state,
        request,
        current_user_stack_pointer,
        output,
        terminal_read,
    );
    let action = match action {
        SyscallAction::Failure(error) => {
            SyscallAction::Failure(memory.capture_shared_file_error(error))
        }
        action => action,
    };
    // Direct dispatch has released its allocation and copy guards. Checked
    // dispatch separately defers notifications only while its actual shared
    // descriptor-table guard remains held.
    if let Some(failure) = memory.entry_gate().pending_failure() {
        return SyscallAction::Failure(failure.error());
    }
    action
}

fn execute_basic_syscall_dispatch(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
    current_user_stack_pointer: Option<u64>,
    output: Option<&mut CapturedOutput>,
    terminal_read: Option<(
        &mut crate::terminal_read::ReadContext,
        reverie::SignalTaskIdentity,
    )>,
) -> SyscallAction {
    // madvise counts: MADV_DONTNEED classifies pages and then zeroes them, and
    // a mapping replaced between the two (by a host-owned worker's executor)
    // must not have its new contents erased.
    let mutates_layout = matches!(request.number(), number if
        number == libc::SYS_brk as u64 || number == libc::SYS_mmap as u64
        || number == libc::SYS_mremap as u64 || number == libc::SYS_munmap as u64
        || number == libc::SYS_mprotect as u64 || number == libc::SYS_madvise as u64);
    if !mutates_layout {
        return execute_basic_syscall_inner(
            memory,
            state,
            request,
            current_user_stack_pointer,
            output,
            terminal_read,
        );
    }
    let owner = memory.clone();
    // Lock order: allocation transaction -> address-space state -> backing.
    // Individual copy/policy methods take state themselves, so holding state
    // here would recursively lock it. General I/O and futex waits do not hold
    // it; mmap file population retains the existing serialized allocation scope.
    let transaction = owner.allocation_guard();
    let cursors = owner
        .allocation_cursors()
        .unwrap_or_else(|| AllocationCursors::from_elf(state));
    state.program_break = cursors.program_break;
    state.mmap_base = cursors.mmap_base;
    state.mmap_next = cursors.mmap_next;
    state.mmap_limit = cursors.mmap_limit;
    let number = request.number();
    let args = request.args();
    let new_shared_file = number == libc::SYS_mmap as u64
        && args[3] & libc::MAP_ANONYMOUS as u64 == 0
        && args[3] & libc::MAP_SHARED as u64 != 0;
    if number == libc::SYS_mmap as u64 && (new_shared_file || owner.contains_retained_shared()) {
        return match mmap_with_shared_files(memory, state, args, output.is_some(), transaction) {
            Ok(result) => continue_with(result),
            Err(error) => SyscallAction::Failure(error),
        };
    }
    // The shared-view metadata is by physical address; the munmap range is a
    // user address (a window's, in Linux's layout).
    if number == libc::SYS_munmap as u64
        && owner.user_range_contains_retained_shared(args[0], args[1])
    {
        return match munmap_shared_file(&owner, args[0], args[1], transaction) {
            Ok(result) => continue_with(result),
            Err(error) => SyscallAction::Failure(error),
        };
    }
    // Each check runs once for any retained shared view and once for an
    // ordinary file alone, which names the refusal.
    let touches_remap = |contains: fn(&GuestMemory, u64, usize) -> bool| {
        number == libc::SYS_mremap as u64
            && shared_file::remap_requires_shared_capability(&owner, state, args, contains)
    };
    // Growth needs no check here: brk refuses growth that reaches any
    // mapping, a shared file view included, before it changes anything, and
    // returns the old break as Linux does.
    let touches_brk = |contains: fn(&GuestMemory, u64, usize) -> bool| {
        number == libc::SYS_brk as u64
            && args[0] >= BOOT_RESERVED_END.max(state.min_break)
            && args[0] < state.program_break
            && {
                // Shrinking retires mappings. Check the exact page-rounded
                // interval used by brk, before its legacy errno adapter could
                // hide a shared-file capability refusal as the old break value.
                match (
                    align_up(args[0], PAGE_SIZE),
                    align_up(state.program_break, PAGE_SIZE),
                ) {
                    (Some(start), Some(end)) if end > start => owner
                        .user_range_to_guest(start, end - start)
                        .is_some_and(|physical| {
                            contains(
                                &owner,
                                physical,
                                (end - start).try_into().unwrap_or(usize::MAX),
                            )
                        }),
                    _ => false,
                }
            }
    };
    let touches_file_remap = touches_remap(GuestMemory::range_contains_retained_shared);
    let touches_file_brk = touches_brk(GuestMemory::range_contains_retained_shared);
    if touches_file_remap || touches_file_brk {
        let ordinary_file = touches_remap(GuestMemory::range_contains_shared_file)
            || touches_brk(GuestMemory::range_contains_shared_file);
        drop(transaction);
        return SyscallAction::Failure(crate::Error::SharedFileCapability {
            operation: if touches_file_remap { "mremap" } else { "brk" },
            reason: if ordinary_file {
                "this layout operation intersects an ordinary shared-file view"
            } else {
                "this layout operation intersects a fork-shared anonymous view"
            },
        });
    }
    let action = execute_basic_syscall_inner(
        memory,
        state,
        request,
        current_user_stack_pointer,
        output,
        terminal_read,
    );
    owner.set_allocation_cursors(AllocationCursors::from_elf(state));
    drop(transaction);
    action
}

fn execute_basic_syscall_inner(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    request: &SyscallRequest,
    current_user_stack_pointer: Option<u64>,
    output: Option<&mut CapturedOutput>,
    terminal_read: Option<(
        &mut crate::terminal_read::ReadContext,
        reverie::SignalTaskIdentity,
    )>,
) -> SyscallAction {
    let args = request.args();
    let number = request.number();
    let capture_output = output.is_some();
    let capture_metadata = output.as_ref().map(|output| output.metadata());

    if number == libc::SYS_exit as u64 || number == libc::SYS_exit_group as u64 {
        return SyscallAction::Exit(ExitStatus::Exited((args[0] as i32) & 0xff));
    }
    if let Some(error) = fdinfo_private_carrier_error(state, number, args) {
        return continue_with(error);
    }
    if let Some(error) = virtual_signalfd_write_error(state, number, args) {
        return continue_with(error);
    }
    if let Some(error) = captured_output_socket_error(state, number, args, capture_output) {
        return continue_with(error);
    }

    let result = if number == libc::SYS_write as u64 {
        write(memory, state, args, output)
    } else if number == libc::SYS_read as u64 {
        match read(memory, state, request, terminal_read) {
            Ok(result) => result,
            Err(error) => return SyscallAction::Failure(error),
        }
    } else if number == libc::SYS_writev as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        vectored_io(memory, state, args, libc::SYS_writev, output)
    } else if number == libc::SYS_readv as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        vectored_io(memory, state, args, libc::SYS_readv, output)
    } else if number == libc::SYS_preadv as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        vectored_io(memory, state, args, libc::SYS_preadv, output)
    } else if number == libc::SYS_preadv2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        vectored_io(memory, state, args, libc::SYS_preadv2, output)
    } else if number == libc::SYS_pwritev as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        vectored_io(memory, state, args, libc::SYS_pwritev, output)
    } else if number == libc::SYS_pwritev2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        vectored_io(memory, state, args, libc::SYS_pwritev2, output)
    } else if number == libc::SYS_pread64 as u64 {
        pread64(&mut ProviderMemory(memory), state, args)
    } else if number == libc::SYS_pwrite64 as u64 {
        pwrite64(memory, state, args)
    } else if number == libc::SYS_sendfile as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sendfile(memory, state, args, output)
    } else if number == libc::SYS_lseek as u64 {
        lseek(state, args, capture_output)
    } else if number == libc::SYS_ftruncate as u64 {
        ftruncate(state, args)
    } else if number == libc::SYS_truncate as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        truncate(memory, state, args)
    } else if number == libc::SYS_fallocate as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fallocate(state, args)
    } else if number == libc::SYS_fsync as u64 {
        sync_file(state, args[0], false)
    } else if number == libc::SYS_fdatasync as u64 {
        sync_file(state, args[0], true)
    } else if number == libc::SYS_syncfs as u64 {
        sync_filesystem(state, args[0], capture_output)
    } else if number == libc::SYS_readahead as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review translated host readahead semantics.
        readahead(state, args)
    } else if number == libc::SYS_sync_file_range as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review translated host range-sync semantics.
        sync_file_range(state, args)
    } else if number == libc::SYS_pipe as u64 {
        pipe2(memory, state, args[0], 0)
    } else if number == libc::SYS_pipe2 as u64 {
        pipe2(memory, state, args[0], args[1])
    } else if number == libc::SYS_select as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        select(memory, state, args)
    } else if number == libc::SYS_pselect6 as u64 {
        pselect6(memory, state, args, capture_output)
    } else if number == libc::SYS_poll as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        poll(memory, state, args)
    } else if number == libc::SYS_ppoll as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        ppoll(memory, state, args)
    } else if number == libc::SYS_epoll_create1 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_create1(state, args[0])
    } else if number == libc::SYS_epoll_ctl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_ctl(memory, state, args)
    } else if number == libc::SYS_epoll_wait as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_wait(memory, state, args, false)
    } else if number == libc::SYS_epoll_pwait as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        epoll_wait(memory, state, args, true)
    } else if number == libc::SYS_epoll_pwait2 as u64 {
        let result = epoll_pwait2(&ProviderMemory(memory), state, args);
        // Alias infrastructure failure is terminal, even after successful
        // kernel I/O. Forward the already-published cause without poisoning a
        // second time or presenting its transport errno as a guest result.
        if let Some(failure) = memory.entry_gate().pending_failure() {
            return SyscallAction::Failure(failure.error());
        }
        result
    } else if number == libc::SYS_eventfd as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        eventfd2(state, args[0], 0)
    } else if number == libc::SYS_eventfd2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        eventfd2(state, args[0], args[1])
    } else if number == libc::SYS_signalfd as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        signalfd(memory, state, args, 0)
    } else if number == libc::SYS_signalfd4 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        signalfd(memory, state, args, args[3])
    } else if number == libc::SYS_timerfd_create as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        timerfd_create(state, args[0], args[1])
    } else if number == libc::SYS_timerfd_settime as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        timerfd_settime(memory, state, args)
    } else if number == libc::SYS_timerfd_gettime as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        timerfd_gettime(memory, state, args)
    } else if number == libc::SYS_inotify_init as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        inotify_init1(state, 0)
    } else if number == libc::SYS_inotify_init1 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        inotify_init1(state, args[0])
    } else if number == libc::SYS_inotify_add_watch as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        inotify_add_watch(memory, state, args)
    } else if number == libc::SYS_inotify_rm_watch as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        inotify_rm_watch(state, args)
    } else if number == libc::SYS_pidfd_open as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-235): Review self-only virtual pidfd translation.
        pidfd_open(state, args)
    } else if number == libc::SYS_socket as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        socket(state, args)
    } else if number == libc::SYS_setsockopt as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        setsockopt(memory, state, args)
    } else if number == libc::SYS_getsockopt as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-230): Review bounded SO_TYPE copy-out semantics.
        getsockopt(memory, state, args)
    } else if number == libc::SYS_bind as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        bind(memory, state, args)
    } else if number == libc::SYS_listen as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        listen(state, args)
    } else if number == libc::SYS_getsockname as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        getsockname(memory, state, args)
    } else if number == libc::SYS_getpeername as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(kvm-socket-parity): Review bounded socket-name copyout.
        getpeername(memory, state, args)
    } else if number == libc::SYS_socketpair as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        socketpair(memory, state, args)
    } else if number == libc::SYS_connect as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        connect(memory, state, args)
    } else if number == libc::SYS_shutdown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        shutdown(state, args)
    } else if number == libc::SYS_sendto as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sendto(memory, state, args)
    } else if number == libc::SYS_recvfrom as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        recvfrom(&mut ProviderMemory(memory), state, args)
    } else if number == libc::SYS_sendmsg as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sendmsg(memory, state, args)
    } else if number == libc::SYS_recvmsg as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        recvmsg(memory, state, args)
    } else if number == libc::SYS_recvmmsg as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        recvmmsg(memory, state, args)
    } else if number == libc::SYS_ioctl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        ioctl(memory, state, args, capture_output)
    } else if number == libc::SYS_dup as u64 {
        duplicate_fd(state, args[0], None, 0, false)
    } else if number == libc::SYS_dup2 as u64 {
        duplicate_fd(state, args[0], Some(args[1]), 0, false)
    } else if number == libc::SYS_dup3 as u64 {
        duplicate_fd(state, args[0], Some(args[1]), args[2], true)
    } else if number == libc::SYS_fcntl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fcntl(memory, state, args)
    } else if number == libc::SYS_open as u64 {
        open(memory, state, args, capture_output)
    } else if number == libc::SYS_openat as u64 {
        openat(memory, state, args, capture_output)
    } else if number == libc::SYS_creat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        creat(memory, state, args, capture_output)
    } else if number == libc::SYS_memfd_create as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        memfd_create(memory, state, args)
    } else if number == libc::SYS_fstat as u64 {
        fstat(memory, state, args, capture_metadata)
    } else if number == libc::SYS_stat as u64 {
        path_stat(memory, state, args, 0, capture_metadata)
    } else if number == libc::SYS_lstat as u64 {
        path_stat(
            memory,
            state,
            args,
            libc::AT_SYMLINK_NOFOLLOW,
            capture_metadata,
        )
    } else if number == libc::SYS_newfstatat as u64 {
        newfstatat(memory, state, args, capture_metadata)
    } else if number == libc::SYS_statx as u64 {
        statx(memory, state, args, capture_metadata)
    } else if number == libc::SYS_statfs as u64 {
        statfs(memory, state, args)
    } else if number == libc::SYS_fstatfs as u64 {
        fstatfs(memory, state, args)
    } else if number == libc::SYS_access as u64 {
        access(memory, state, args)
    } else if number == libc::SYS_faccessat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        faccessat(memory, state, args)
    } else if number == libc::SYS_faccessat2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        faccessat2(memory, state, args)
    } else if number == libc::SYS_mkdir as u64 {
        mkdir_at(memory, state, libc::AT_FDCWD, args[0], args[1])
    } else if number == libc::SYS_mkdirat as u64 {
        mkdir_at(memory, state, args[0] as libc::c_int, args[1], args[2])
    } else if number == libc::SYS_unlink as u64 {
        unlink_at(memory, state, libc::AT_FDCWD, args[0], 0)
    } else if number == libc::SYS_rmdir as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-111): Review rmdir->unlinkat(AT_REMOVEDIR) mapping.
        // rmdir(path) is unlinkat(AT_FDCWD, path, AT_REMOVEDIR). Without this
        // arm the guest's bare rmdir(2) fell through to ENOSYS, so coreutils
        // `rmdir` (and `mktemp -d` cleanup) failed under the KVM backend even
        // though `rm -rf`, which uses unlinkat(AT_REMOVEDIR), worked.
        unlink_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_REMOVEDIR as u64,
        )
    } else if number == libc::SYS_unlinkat as u64 {
        unlink_at(memory, state, args[0] as libc::c_int, args[1], args[2])
    } else if number == libc::SYS_rename as u64 {
        rename_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            0,
        )
    } else if number == libc::SYS_renameat as u64 {
        rename_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            0,
        )
    } else if number == libc::SYS_renameat2 as u64 {
        rename_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            args[4],
        )
    } else if number == libc::SYS_link as u64 {
        link_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            0,
        )
    } else if number == libc::SYS_linkat as u64 {
        link_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            args[4],
        )
    } else if number == libc::SYS_symlink as u64 {
        symlink_at(memory, state, args[0], libc::AT_FDCWD, args[1])
    } else if number == libc::SYS_symlinkat as u64 {
        symlink_at(memory, state, args[0], args[1] as libc::c_int, args[2])
    } else if number == libc::SYS_getcwd as u64 {
        getcwd(memory, state, args)
    } else if number == libc::SYS_chdir as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        chdir(memory, state, args)
    } else if number == libc::SYS_fchdir as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchdir(state, args)
    } else if number == libc::SYS_getdents64 as u64 {
        getdents64(&mut ProviderMemory(memory), state, args)
    } else if number == libc::SYS_getpid as u64 {
        i64::from(state.pid)
    } else if number == libc::SYS_gettid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-132): Review distinct KVM thread IDs.
        i64::from(state.tid)
    } else if number == libc::SYS_getppid as u64 {
        i64::from(state.guest_parent_pid())
    } else if number == libc::SYS_wait4 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        return match wait4_result(memory, state, args) {
            Ok(result) => continue_with(result),
            Err(error) => SyscallAction::Failure(error),
        };
    } else if number == libc::SYS_waitid as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review serialized-child waitid emulation.
        return match waitid_result(memory, state, args) {
            Ok(result) => continue_with(result),
            Err(error) => SyscallAction::Failure(error),
        };
    } else if number == libc::SYS_getgroups as u64 {
        getgroups(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_capget as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        capget(&mut ProviderMemory(memory), state, args)
    } else if number == libc::SYS_capset as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        capset(&ProviderMemory(memory), state, args)
    } else if number == libc::SYS_flock as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        flock(state, args)
    } else if number == libc::SYS_fchown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchown(state, args[0])
    } else if number == libc::SYS_chown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchownat(memory, state, libc::AT_FDCWD, args[0], 0)
    } else if number == libc::SYS_lchown as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchownat(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } else if number == libc::SYS_fchownat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchownat(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[4] as libc::c_int,
        )
    } else if number == libc::SYS_listxattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        path_xattr_list(state, memory, args, false)
    } else if number == libc::SYS_llistxattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        path_xattr_list(state, memory, args, true)
    } else if number == libc::SYS_flistxattr as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fd_xattr_list(memory, state, args)
    } else if number == libc::SYS_umask as u64 {
        let previous = state.umask;
        state.umask = args[0] as libc::mode_t & 0o777;
        i64::from(previous)
    } else if number == libc::SYS_fchmod as u64 {
        fchmod(state, args)
    } else if number == libc::SYS_chmod as u64 {
        fchmodat(memory, state, libc::AT_FDCWD, args[0], args[1], 0)
    } else if number == libc::SYS_fchmodat as u64 {
        // SYS_fchmodat has three arguments; r10 is unspecified guest state.
        fchmodat(memory, state, args[0] as libc::c_int, args[1], args[2], 0)
    } else if number == libc::SYS_fchmodat2 as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        fchmodat(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2],
            args[3],
        )
    } else if number == libc::SYS_mknod as u64 {
        mknod_at(memory, state, libc::AT_FDCWD, args[0], args[1], args[2])
    } else if number == libc::SYS_mknodat as u64 {
        mknod_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2],
            args[3],
        )
    } else if number == libc::SYS_utimensat as u64 {
        utimensat(memory, state, args)
    } else if number == libc::SYS_arch_prctl as u64 {
        return arch_prctl(memory, state, args);
    } else if number == libc::SYS_prctl as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        prctl(&mut ProviderMemory(memory), state, args)
    } else if number == libc::SYS_getxattr as u64
        || number == libc::SYS_lgetxattr as u64
        || number == libc::SYS_fgetxattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        getxattr(memory, state, number, args)
    } else if number == libc::SYS_setxattr as u64
        || number == libc::SYS_lsetxattr as u64
        || number == libc::SYS_fsetxattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review deterministic xattr mutation refusal.
        setxattr(memory, state, number, args)
    } else if number == libc::SYS_removexattr as u64
        || number == libc::SYS_lremovexattr as u64
        || number == libc::SYS_fremovexattr as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-227): Review deterministic xattr removal result.
        removexattr(memory, state, number, args)
    } else if number == libc::SYS_brk as u64 {
        brk(memory, state, args[0])
    } else if number == libc::SYS_mmap as u64 {
        mmap(memory, state, args)
    } else if number == libc::SYS_munmap as u64 {
        munmap(&mut ProviderMemory(memory), args[0], args[1])
    } else if number == libc::SYS_msync as u64 {
        match msync(memory, args) {
            Ok(result) => result,
            Err(error) => return SyscallAction::Failure(error),
        }
    } else if number == libc::SYS_mremap as u64 {
        mremap(memory, state, args)
    } else if number == libc::SYS_mprotect as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        mprotect(&ProviderMemory(memory), args)
    } else if number == libc::SYS_madvise as u64 {
        madvise(&ProviderMemory(memory), args)
    } else if number == libc::SYS_munlock as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        munlock_guest_range(&ProviderMemory(memory), args[0], args[1])
    } else if number == libc::SYS_munlockall as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-145): Review the deterministic no-op unlock-all model.
        0
    } else if number == libc::SYS_mincore as u64 {
        mincore(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_sched_get_priority_min as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_priority_bound(libc::SYS_sched_get_priority_min, args[0])
    } else if number == libc::SYS_sched_get_priority_max as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        sched_priority_bound(libc::SYS_sched_get_priority_max, args[0])
    } else if number == libc::SYS_clock_gettime as u64 {
        clock_gettime(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_nanosleep as u64 {
        nanosleep(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_clock_nanosleep as u64 {
        clock_nanosleep(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_gettimeofday as u64 {
        gettimeofday(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_time as u64 {
        time(&mut ProviderMemory(memory), args)
    } else if number == libc::SYS_readlink as u64 {
        readlink(memory, state, args, capture_metadata)
    } else if number == libc::SYS_readlinkat as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        readlinkat(memory, state, args, capture_metadata)
    } else if number == libc::SYS_personality as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        personality(state, args[0])
    } else if number == libc::SYS_uname as u64 {
        uname(&mut ProviderMemory(memory), args[0])
    } else if number == libc::SYS_rt_sigaction as u64 {
        rt_sigaction(memory, state, args)
    } else if number == libc::SYS_rt_sigprocmask as u64 {
        rt_sigprocmask(memory, state, args)
    } else if number == libc::SYS_rt_sigpending as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        rt_sigpending(memory, state, args)
    } else if number == libc::SYS_sigaltstack as u64 {
        sigaltstack(memory, state, current_user_stack_pointer, args)
    } else if number == libc::SYS_rt_sigtimedwait as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        rt_sigtimedwait(memory, state, args)
    } else if number == libc::SYS_rt_sigsuspend as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        rt_sigsuspend(memory, state, args)
    } else if number == libc::SYS_kill as u64
        || number == libc::SYS_tkill as u64
        || number == libc::SYS_tgkill as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        return kill_signal(state, number, args);
    } else if number == libc::SYS_rt_sigqueueinfo as u64
        || number == libc::SYS_rt_tgsigqueueinfo as u64
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        return sigqueueinfo(memory, state, number, args);
    } else if number == libc::SYS_close as u64 {
        close(state, args[0])
    } else if number == libc::SYS_close_range as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        close_range(state, args)
    } else if number == libc::SYS_futex as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        futex(&ProviderMemory(memory), args)
    } else if number == libc::SYS_rseq as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-172): Review deterministic rseq feature refusal.
        negative_errno(libc::ENOSYS)
    } else if number == libc::SYS_get_robust_list as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list queries.
        get_robust_list(memory, state, args)
    } else if number == libc::SYS_set_robust_list as u64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list registration.
        set_robust_list(state, args)
    } else {
        // Includes every call in `TOOL_DECIDED_SYSCALLS`, whose ENOSYS the
        // checked dispatch reports as the typed refusal `ToolDecided`.
        negative_errno(libc::ENOSYS)
    };

    continue_with(result)
}

impl ElfExecutor {
    /// Execute one static-ELF guest syscall. Backend invariants are typed run
    /// failures: callers must terminate the run rather than encode them as a
    /// Linux syscall errno.
    pub fn execute_checked(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> crate::Result<i64> {
        self.execute_checked_inner(request, memory, None)
    }

    pub fn execute_checked_with_read_context(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
        terminal_read: &mut crate::terminal_read::ReadContext,
    ) -> crate::Result<i64> {
        self.execute_checked_inner(request, memory, Some(terminal_read))
    }

    fn execute_checked_inner(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
        terminal_read: Option<&mut crate::terminal_read::ReadContext>,
    ) -> crate::Result<i64> {
        // A refusal describes the syscall that produced it. A caller that
        // executes without reading it (the unsubscribed direct path) must not
        // leave it for the next caller's injection to report.
        self.unsupported_refusal = None;
        self.state.signal_refusal = None;
        let result = self
            .execute_checked_dispatch(request, memory, terminal_read)
            .map_err(|error| memory.capture_shared_file_error(error));
        if let Some(failure) = memory.entry_gate().pending_failure() {
            return Err(failure.error());
        }
        result
    }

    fn execute_checked_dispatch(
        &mut self,
        request: &SyscallRequest,
        memory: &GuestMemory,
        terminal_read: Option<&mut crate::terminal_read::ReadContext>,
    ) -> crate::Result<i64> {
        #[cfg(any(test, feature = "test-support"))]
        memory.observe_test_syscall_dispatch(request);
        if let Some(receipt) = self.state.consumed_child_wait.as_ref() {
            return Err(crate::Error::ChildWaitLedgerEffectPending {
                parent: self.admitted_signal_identity().process,
                child_pid: receipt.child_pid(),
            });
        }
        self.check_parent_death_failure()?;
        self.bind_address_space(memory);
        self.parent_death_injection_preflight(request)?;
        // A fork gets a separate arena/gate and inherits the real shared VMAs.
        // CLONE_VM still creates another owner of this arena and is refused
        // before task-ID allocation, child copyout or ProcessAction.
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-919): Review shared-file fork admission.
        if memory.entry_gate().single_member_domain_active() {
            let number = request.number();
            let args = request.args();
            let refusal = || crate::Error::SharedFileCapability {
                operation: "CLONE_VM/thread creation",
                reason: "ordinary shared-file views require one vCPU per address space",
            };
            if number == libc::SYS_vfork as u64
                || (number == libc::SYS_clone as u64
                    && args[0] & (libc::CLONE_VM | libc::CLONE_THREAD) as u64 != 0)
            {
                return Err(refusal());
            }
            if number == libc::SYS_clone3 as u64 {
                // Read once: the checked flags must be the flags actually used
                // to create the ProcessAction, not a second mutable copyin.
                let clone = match read_clone3(&ProviderMemory(memory), args[0], args[1]) {
                    Ok(clone) => clone,
                    Err(error) => return Ok(error),
                };
                if clone.flags & (libc::CLONE_VM | libc::CLONE_THREAD) as u64 != 0 {
                    return Err(refusal());
                }
                if let Err(error) = validate_process_clone_flags(clone.flags) {
                    return Ok(error);
                }
                if clone.flags & PROCESS_CLONE_TID_FLAGS != 0
                    || clone.parent_tid.is_some()
                    || clone.child_tid.is_some()
                {
                    return Ok(negative_errno(libc::ENOTSUP));
                }
                return Ok(self.prepare_fork(
                    clone.child_stack,
                    None,
                    None,
                    None,
                    clone.flags & CLONE_CLEAR_SIGHAND != 0,
                    false,
                ));
            }
        }
        if request.number() == libc::SYS_prctl as u64
            && request.args()[0] as i32 == libc::PR_SET_PDEATHSIG
            && (1..=64).contains(&request.args()[1])
            && self.terminal_cleanup.is_none()
        {
            return Ok(negative_errno(libc::ENOSYS));
        }
        let _retirement = self.state.file_retirement.hold();
        if let Some(result) = self.execute_child_wait(request, memory) {
            return result;
        }
        if let Some(result) = self.execute_accept(request, memory) {
            return Ok(result);
        }
        // TODO-HUMAN-REVIEW(PR-172): Review CLONE_FILES descriptor-table sharing.
        // Thread children retain private executor state, but synchronize their
        // descriptor mappings through this shared table before every syscall.
        // Descriptor-creating and descriptor-closing operations hold the lock
        // through the update; potentially blocking I/O releases it after the
        // snapshot so QEMU AIO workers can continue to make progress.
        let file_table = self.file_table.clone();
        // Tie notification deferral to the lock that requires it, rather than
        // to the whole syscall. Register before taking the table lock so even
        // a concurrently published first shared-file view is covered. Copies
        // after the snapshot unlock keep their ordinary notification order.
        let mut notifications = Some(memory.defer_notifications());
        let mut shared_files = Some(file_table.lock().expect("KVM file-table lock poisoned"));
        if let Err(error) = shared_files
            .as_ref()
            .expect("file-table guard disappeared")
            .install(&mut self.state)
        {
            return Ok(io_error(error));
        }
        // install cloned every fdinfo description Arc while holding the
        // current table. Scalar dispatch below therefore retains its entry
        // description even if another thread closes/reuses that guest fd after
        // the release. It may then lock seq and its ONE original target table.
        let mutating_file_table = mutates_file_table(request.number());
        if !mutating_file_table {
            shared_files.take();
            drop(notifications.take());
            self.state.file_retirement.drain_unlocked();
        }
        if self.parent_death_enrolled()
            && matches!(
                request.number() as libc::c_long,
                libc::SYS_execve | libc::SYS_execveat
            )
        {
            let retained = self.take_parent_death_exec(request)?;
            return Ok(self.prepare_exec(memory, request, Some(retained)));
        }
        if let Some(result) = self.execute_process_action(request, memory) {
            return Ok(result);
        }
        // Clones share the underlying MAP_SHARED mapping, so writes through this
        // handle reach the guest; `execute_basic_syscall` needs `&mut` access.
        let mut memory = memory.clone();
        let sigchld_action_before = (request.number() == libc::SYS_rt_sigaction as u64
            && request.args()[0] as libc::c_int == libc::SIGCHLD
            && request.args()[1] != 0)
            .then(|| installed_signal_action(&self.state, libc::SIGCHLD));
        let identity = self.admitted_signal_identity();
        let action = execute_basic_syscall_with_read_context(
            &mut memory,
            &mut self.state,
            request,
            self.current_user_stack_pointer,
            self.output.as_mut(),
            terminal_read.map(|context| (context, identity)),
        );
        if let Some(before) = sigchld_action_before {
            let after = installed_signal_action(&self.state, libc::SIGCHLD);
            if after != before {
                self.sigchld_auto_reap
                    .store(sigchld_auto_reaps(&self.state), Ordering::SeqCst);
            }
        }
        if let Some(mut shared_files) = shared_files {
            shared_files
                .update_from_elf(&self.state)
                .expect("clone updated KVM file table");
        }
        // The mutating path has now updated and released its table guard.
        // Accounting retired at each copy; callbacks may run only now.
        drop(notifications);
        match action {
            SyscallAction::Failure(error) => Err(error),
            SyscallAction::Continue { result, segment } => {
                if segment.is_some() {
                    self.pending_segment = segment;
                }
                let consumed_child = self.state.consumed_child_wait.take();
                if let Some(child) = consumed_child {
                    self.state.children.acknowledge(child)?;
                }
                if let Some(refusal) = flock_refusal(request, result)
                    .or_else(|| process_group_refusal(request, result))
                    .or_else(|| tool_decided_refusal(request, result))
                    .or_else(|| madvise_refusal(request, result))
                    .or_else(|| signalfd_refusal(&self.state, request, result))
                {
                    self.unsupported_refusal = Some(refusal);
                }
                if let Some(refusal) =
                    signal_refusal_record(self.state.signal_refusal.take(), result)
                {
                    self.unsupported_refusal = Some(refusal);
                }
                Ok(result)
            }
            SyscallAction::Exit(code) => {
                self.exit_status = Some(code);
                self.exit_group = request.number() != libc::SYS_exit as u64;
                Ok(0)
            }
        }
    }
}

// Unit tests historically exercise the concrete executor as a raw Linux
// syscall function. Keep that concise surface while production dispatch uses
// the fallible trait method and cannot turn a backend invariant into an errno.
#[cfg(any(test, feature = "test-support"))]
impl ElfExecutor {
    pub fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        self.execute_checked(request, memory)
            .expect("unit-test syscall dispatch returned a backend failure")
    }
}
