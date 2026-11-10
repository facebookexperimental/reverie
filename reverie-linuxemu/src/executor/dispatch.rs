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

/// Why a vfork child may not move its program break before it execs
/// ([`vfork_child_moves_break`]).
pub(super) const VFORK_CHILD_BREAK_REASON: &str = concat!(
    "a vfork child shares its parent's address space until it execs or exits, and runs on ",
    "a copy here whose changes to private memory go back to the parent, but whose program ",
    "break cannot: on Linux this call would move the parent's break too"
);

/// Whether this call is a `brk` by which a vfork child's copy of its parent's
/// address space ([`GuestMemory::shares_parent_address_space`]) would move
/// the program break before the child execs. The break is the address
/// space's, so on Linux the parent's moves too, even by less than a page,
/// which changes no mapping; the copy cannot carry it back. `brk(0)`, and a
/// request below the minimum break, which Linux answers with the old break,
/// go on. The copy's other mapping changes are checked when its window ends
/// (`GuestMemory::return_vfork_changes`), so a mapping the child creates and
/// removes in between, as a tool's scratch page is, goes on.
pub(super) fn vfork_child_moves_break(
    owner: &GuestMemory,
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> bool {
    owner.shares_parent_address_space()
        && number == libc::SYS_brk as u64
        && args[0] >= state.mm.min_break
        && args[0] != state.mm.program_break
}

/// Why a vfork child may not create a thread before it execs
/// ([`vfork_child_creates_thread`]).
pub(super) const VFORK_CHILD_THREAD_REASON: &str = concat!(
    "a vfork child shares its parent's address space until it execs or exits, and runs on ",
    "a copy here whose changes go back to the parent when its window ends; Linux ends that ",
    "window when the creating task execs or exits, whatever threads of the child still run, ",
    "and a copy cannot go back while another thread still changes it"
);

/// Whether this call creates a thread (`CLONE_THREAD`) in a vfork child's
/// copy of its parent's address space
/// ([`GuestMemory::shares_parent_address_space`]) before the child execs.
/// The window ends, on Linux, at the creating task's exec or exit
/// (`mm_release()` completes the vfork whatever other users of the mm
/// remain), while here the copy's changes can go back only once nothing
/// else runs in it, so the thread is refused before task-ID allocation,
/// child copyout or any process action. A multithreaded parent is not
/// affected, and a nested vfork-style child (`CLONE_VM|CLONE_VFORK`) goes on.
/// `clone3`'s flags are read here and again by the call itself: nothing else
/// runs in the copy, whose only thread is this caller, so the two reads agree.
pub(super) fn vfork_child_creates_thread(
    memory: &GuestMemory,
    number: u64,
    args: &[u64; 6],
) -> bool {
    if !memory.shares_parent_address_space() {
        return false;
    }
    let flags = if number == libc::SYS_clone as u64 {
        args[0]
    } else if number == libc::SYS_clone3 as u64 {
        match read_clone3(&ProviderMemory(memory), args[0], args[1]) {
            Ok(clone) => clone.flags,
            // The call itself answers a bad argument.
            Err(_) => return false,
        }
    } else {
        return false;
    };
    flags & libc::CLONE_THREAD as u64 != 0
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

/// The syscalls that change the address space's layout, which dispatch
/// serializes under the memory's allocation transaction
/// ([`execute_basic_syscall_dispatch`]), and before which it keeps the guard
/// flag on every page of each line a split may cut
/// (`mapping_list::spread_guard_marks`, at the addresses
/// [`layout_edit_boundaries`] names). madvise counts: MADV_DONTNEED
/// classifies pages and then zeroes them, and a mapping replaced between the
/// two (by a host-owned worker's executor) must not have its new contents
/// erased; and its flag changes split lines.
/// munlock and munlockall count: they take `FLAG_LOCKED` from the mappings
/// they unlock, which splits a line munlock covers part of.
pub(super) const LAYOUT_SYSCALLS: [libc::c_long; 9] = [
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_mremap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_pkey_mprotect,
    libc::SYS_munlock,
    libc::SYS_munlockall,
];

/// Whether syscall `number` is one of [`LAYOUT_SYSCALLS`].
pub(super) fn mutates_layout(number: u64) -> bool {
    LAYOUT_SYSCALLS
        .iter()
        .any(|layout| *layout as u64 == number)
}

/// The user addresses at which layout syscall `number` with `args` may split
/// a line (a mapping as Linux lists it): the ends of each range it may
/// change, maps over, unmaps or moves, rounded to pages; `None` for a
/// syscall not in [`LAYOUT_SYSCALLS`]. Generous: an address that splits
/// nothing costs a lookup. `state` gives the program break.
pub(super) fn layout_edit_boundaries(
    number: u64,
    args: &[u64; 6],
    state: &LoadedStaticElf,
) -> Option<Vec<u64>> {
    let page_down = |address: u64| address & !(PAGE_SIZE - 1);
    let page_up = |address: u64| address.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let range =
        |start: u64, length: u64| vec![page_down(start), page_up(start.saturating_add(length))];
    let number = number as libc::c_long;
    Some(match number {
        libc::SYS_mmap => {
            // Only a fixed mapping can replace part of a line;
            // MAP_FIXED_NOREPLACE maps nothing over one.
            if args[3] & libc::MAP_FIXED as u64 != 0 {
                range(args[0], args[1])
            } else {
                Vec::new()
            }
        }
        libc::SYS_munmap
        | libc::SYS_mprotect
        | libc::SYS_pkey_mprotect
        | libc::SYS_madvise
        | libc::SYS_munlock => range(args[0], args[1]),
        // Unlocking every mapping whole splits none.
        libc::SYS_munlockall => Vec::new(),
        libc::SYS_mremap => {
            // The source's ends, where a shrink cuts it, and a fixed
            // destination's ends.
            let mut boundaries = range(args[0], args[1]);
            boundaries.push(page_up(args[0].saturating_add(args[2])));
            if args[3] & libc::MREMAP_FIXED as u64 != 0 {
                boundaries.extend(range(args[4], args[2]));
            }
            boundaries
        }
        // A break that shrinks unmaps from the new break's page up to the
        // old break's page end.
        libc::SYS_brk => vec![page_up(args[0]), page_up(state.mm.program_break)],
        _ => return None,
    })
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
    if !mutates_layout(request.number()) {
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
    state.mm.program_break = cursors.program_break;
    state.mm.mmap_base = cursors.mmap_base;
    state.mm.mmap_next = cursors.mmap_next;
    state.mm.mmap_limit = cursors.mmap_limit;
    let number = request.number();
    let args = request.args();
    // Before any path below can split a line, under the allocation
    // transaction, which every change to the layout holds.
    super::mapping_list::spread_guard_marks(
        &owner,
        &super::mapping_list::ImageMapFacts::of(state),
        &layout_edit_boundaries(number, args, state).unwrap_or_default(),
    );
    if vfork_child_moves_break(&owner, state, number, args) {
        drop(transaction);
        return SyscallAction::Failure(crate::Error::VforkChildCapability {
            operation: "brk in a vfork child",
            reason: VFORK_CHILD_BREAK_REASON,
        });
    }
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
            && args[0] >= BOOT_RESERVED_END.max(state.mm.min_break)
            && args[0] < state.mm.program_break
            && {
                // Shrinking retires mappings. Check the exact page-rounded
                // interval used by brk, before its legacy errno adapter could
                // hide a shared-file capability refusal as the old break value.
                match (
                    align_up(args[0], PAGE_SIZE),
                    align_up(state.mm.program_break, PAGE_SIZE),
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

    let result = match number {
        _ if number == libc::SYS_write as u64 => write(memory, state, args, output),
        _ if number == libc::SYS_read as u64 => match read(memory, state, request, terminal_read) {
            Ok(result) => result,
            Err(error) => return SyscallAction::Failure(error),
        },
        _ if number == libc::SYS_writev as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            vectored_io(memory, state, args, libc::SYS_writev, output)
        }
        _ if number == libc::SYS_readv as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // A blocking inotify instance is refused before any host call: its
            // read would wait in the host (inotify.rs).
            if let Some(error) = blocking_inotify_vectored_read(state, number, args) {
                return SyscallAction::Failure(error);
            }
            vectored_io(memory, state, args, libc::SYS_readv, output)
        }
        _ if number == libc::SYS_preadv as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            vectored_io(memory, state, args, libc::SYS_preadv, output)
        }
        _ if number == libc::SYS_preadv2 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            if let Some(error) = blocking_inotify_vectored_read(state, number, args) {
                return SyscallAction::Failure(error);
            }
            vectored_io(memory, state, args, libc::SYS_preadv2, output)
        }
        _ if number == libc::SYS_pwritev as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            vectored_io(memory, state, args, libc::SYS_pwritev, output)
        }
        _ if number == libc::SYS_pwritev2 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            vectored_io(memory, state, args, libc::SYS_pwritev2, output)
        }
        _ if number == libc::SYS_pread64 as u64 => {
            pread64(&mut ProviderMemory(memory), state, args)
        }
        _ if number == libc::SYS_pwrite64 as u64 => pwrite64(memory, state, args),
        _ if number == libc::SYS_sendfile as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            sendfile(memory, state, args, output)
        }
        _ if number == libc::SYS_lseek as u64 => lseek(state, args, capture_output),
        _ if number == libc::SYS_ftruncate as u64 => ftruncate(state, args),
        _ if number == libc::SYS_truncate as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            truncate(memory, state, args)
        }
        _ if number == libc::SYS_fallocate as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fallocate(state, args)
        }
        _ if number == libc::SYS_fsync as u64 => sync_file(state, args[0], false),
        _ if number == libc::SYS_fdatasync as u64 => sync_file(state, args[0], true),
        _ if number == libc::SYS_syncfs as u64 => sync_filesystem(state, args[0], capture_output),
        _ if number == libc::SYS_readahead as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-227): Review translated host readahead semantics.
            readahead(state, args)
        }
        _ if number == libc::SYS_sync_file_range as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-227): Review translated host range-sync semantics.
            sync_file_range(state, args)
        }
        _ if number == libc::SYS_pipe as u64 => pipe2(memory, state, args[0], 0),
        _ if number == libc::SYS_pipe2 as u64 => pipe2(memory, state, args[0], args[1]),
        _ if number == libc::SYS_select as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            select(memory, state, args)
        }
        _ if number == libc::SYS_pselect6 as u64 => pselect6(memory, state, args, capture_output),
        _ if number == libc::SYS_poll as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            poll(memory, state, args)
        }
        _ if number == libc::SYS_ppoll as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            ppoll(memory, state, args)
        }
        _ if number == libc::SYS_epoll_create1 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            epoll_create1(state, args[0])
        }
        _ if number == libc::SYS_epoll_ctl as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            epoll_ctl(memory, state, args)
        }
        _ if number == libc::SYS_epoll_wait as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            epoll_wait(memory, state, args, false)
        }
        _ if number == libc::SYS_epoll_pwait as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            epoll_wait(memory, state, args, true)
        }
        _ if number == libc::SYS_epoll_pwait2 as u64 => {
            let result = epoll_pwait2(&ProviderMemory(memory), state, args);
            // Alias infrastructure failure is terminal, even after successful
            // kernel I/O. Forward the already-published cause without poisoning a
            // second time or presenting its transport errno as a guest result.
            if let Some(failure) = memory.entry_gate().pending_failure() {
                return SyscallAction::Failure(failure.error());
            }
            result
        }
        _ if number == libc::SYS_eventfd as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            eventfd2(state, args[0], 0)
        }
        _ if number == libc::SYS_eventfd2 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            eventfd2(state, args[0], args[1])
        }
        _ if number == libc::SYS_signalfd as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            signalfd(memory, state, args, 0)
        }
        _ if number == libc::SYS_signalfd4 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            signalfd(memory, state, args, args[3])
        }
        _ if number == libc::SYS_timerfd_create as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            timerfd_create(state, args[0], args[1])
        }
        _ if number == libc::SYS_timerfd_settime as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            timerfd_settime(memory, state, args)
        }
        _ if number == libc::SYS_timerfd_gettime as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            timerfd_gettime(memory, state, args)
        }
        _ if number == libc::SYS_inotify_init as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            inotify_init1(state, 0)
        }
        _ if number == libc::SYS_inotify_init1 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            inotify_init1(state, args[0])
        }
        _ if number == libc::SYS_inotify_add_watch as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            inotify_add_watch(memory, state, args)
        }
        _ if number == libc::SYS_inotify_rm_watch as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            inotify_rm_watch(state, args)
        }
        _ if number == libc::SYS_pidfd_open as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-235): Review self-only virtual pidfd translation.
            pidfd_open(state, args)
        }
        _ if number == libc::SYS_socket as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            socket(state, args)
        }
        _ if number == libc::SYS_setsockopt as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            setsockopt(memory, state, args)
        }
        _ if number == libc::SYS_getsockopt as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-230): Review bounded SO_TYPE copy-out semantics.
            getsockopt(memory, state, args)
        }
        _ if number == libc::SYS_bind as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            bind(memory, state, args)
        }
        _ if number == libc::SYS_listen as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            listen(state, args)
        }
        _ if number == libc::SYS_getsockname as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            getsockname(memory, state, args)
        }
        _ if number == libc::SYS_getpeername as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(kvm-socket-parity): Review bounded socket-name copyout.
            getpeername(memory, state, args)
        }
        _ if number == libc::SYS_socketpair as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            socketpair(memory, state, args)
        }
        _ if number == libc::SYS_connect as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            connect(memory, state, args)
        }
        _ if number == libc::SYS_shutdown as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            shutdown(state, args)
        }
        _ if number == libc::SYS_sendto as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            sendto(memory, state, args)
        }
        _ if number == libc::SYS_recvfrom as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            recvfrom(&mut ProviderMemory(memory), state, args)
        }
        _ if number == libc::SYS_sendmsg as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            sendmsg(memory, state, args)
        }
        _ if number == libc::SYS_recvmsg as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            recvmsg(memory, state, args)
        }
        _ if number == libc::SYS_recvmmsg as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            recvmmsg(memory, state, args)
        }
        _ if number == libc::SYS_ioctl as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            ioctl(memory, state, args, capture_output)
        }
        _ if number == libc::SYS_dup as u64 => duplicate_fd(state, args[0], None, 0, false),
        _ if number == libc::SYS_dup2 as u64 => {
            duplicate_fd(state, args[0], Some(args[1]), 0, false)
        }
        _ if number == libc::SYS_dup3 as u64 => {
            duplicate_fd(state, args[0], Some(args[1]), args[2], true)
        }
        _ if number == libc::SYS_fcntl as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fcntl(memory, state, args)
        }
        _ if number == libc::SYS_open as u64 => open(memory, state, args),
        _ if number == libc::SYS_openat as u64 => openat(memory, state, args),
        _ if number == libc::SYS_creat as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            creat(memory, state, args)
        }
        _ if number == libc::SYS_memfd_create as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            memfd_create(memory, state, args)
        }
        _ if number == libc::SYS_fstat as u64 => fstat(memory, state, args, capture_metadata),
        _ if number == libc::SYS_stat as u64 => path_stat(memory, state, args, 0, capture_metadata),
        _ if number == libc::SYS_lstat as u64 => path_stat(
            memory,
            state,
            args,
            libc::AT_SYMLINK_NOFOLLOW,
            capture_metadata,
        ),
        _ if number == libc::SYS_newfstatat as u64 => {
            newfstatat(memory, state, args, capture_metadata)
        }
        _ if number == libc::SYS_statx as u64 => statx(memory, state, args, capture_metadata),
        _ if number == libc::SYS_statfs as u64 => statfs(memory, state, args),
        _ if number == libc::SYS_fstatfs as u64 => fstatfs(memory, state, args),
        _ if number == libc::SYS_access as u64 => access(memory, state, args),
        _ if number == libc::SYS_faccessat as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            faccessat(memory, state, args)
        }
        _ if number == libc::SYS_faccessat2 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            faccessat2(memory, state, args)
        }
        _ if number == libc::SYS_mkdir as u64 => {
            mkdir_at(memory, state, libc::AT_FDCWD, args[0], args[1])
        }
        _ if number == libc::SYS_mkdirat as u64 => {
            mkdir_at(memory, state, args[0] as libc::c_int, args[1], args[2])
        }
        _ if number == libc::SYS_unlink as u64 => {
            unlink_at(memory, state, libc::AT_FDCWD, args[0], 0)
        }
        _ if number == libc::SYS_rmdir as u64 => {
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
        }
        _ if number == libc::SYS_unlinkat as u64 => {
            unlink_at(memory, state, args[0] as libc::c_int, args[1], args[2])
        }
        _ if number == libc::SYS_rename as u64 => rename_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            0,
        ),
        _ if number == libc::SYS_renameat as u64 => rename_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            0,
        ),
        _ if number == libc::SYS_renameat2 as u64 => rename_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            args[4],
        ),
        _ if number == libc::SYS_link as u64 => link_at(
            memory,
            state,
            libc::AT_FDCWD,
            args[0],
            libc::AT_FDCWD,
            args[1],
            0,
        ),
        _ if number == libc::SYS_linkat as u64 => link_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2] as libc::c_int,
            args[3],
            args[4],
        ),
        _ if number == libc::SYS_symlink as u64 => {
            symlink_at(memory, state, args[0], libc::AT_FDCWD, args[1])
        }
        _ if number == libc::SYS_symlinkat as u64 => {
            symlink_at(memory, state, args[0], args[1] as libc::c_int, args[2])
        }
        _ if number == libc::SYS_getcwd as u64 => getcwd(memory, state, args),
        _ if number == libc::SYS_chdir as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            chdir(memory, state, args)
        }
        _ if number == libc::SYS_fchdir as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fchdir(state, args)
        }
        _ if number == libc::SYS_getdents64 as u64 => {
            getdents64(&mut ProviderMemory(memory), state, args)
        }
        _ if number == libc::SYS_getpid as u64 => i64::from(state.pid),
        _ if number == libc::SYS_gettid as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-132): Review distinct KVM thread IDs.
            i64::from(state.tid)
        }
        _ if number == libc::SYS_getppid as u64 => i64::from(state.guest_parent_pid()),
        _ if number == libc::SYS_wait4 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            return match wait4_result(memory, state, args) {
                Ok(result) => continue_with(result),
                Err(error) => SyscallAction::Failure(error),
            };
        }
        _ if number == libc::SYS_waitid as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-227): Review serialized-child waitid emulation.
            return match waitid_result(memory, state, args) {
                Ok(result) => continue_with(result),
                Err(error) => SyscallAction::Failure(error),
            };
        }
        _ if number == libc::SYS_getgroups as u64 => getgroups(&mut ProviderMemory(memory), args),
        _ if number == libc::SYS_capget as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            capget(&mut ProviderMemory(memory), state, args)
        }
        _ if number == libc::SYS_capset as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            capset(&ProviderMemory(memory), state, args)
        }
        _ if number == libc::SYS_flock as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            flock(state, args)
        }
        _ if number == libc::SYS_fchown as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fchown(state, args[0])
        }
        _ if number == libc::SYS_chown as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fchownat(memory, state, libc::AT_FDCWD, args[0], 0)
        }
        _ if number == libc::SYS_lchown as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fchownat(
                memory,
                state,
                libc::AT_FDCWD,
                args[0],
                libc::AT_SYMLINK_NOFOLLOW,
            )
        }
        _ if number == libc::SYS_fchownat as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fchownat(
                memory,
                state,
                args[0] as libc::c_int,
                args[1],
                args[4] as libc::c_int,
            )
        }
        _ if number == libc::SYS_listxattr as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            path_xattr_list(state, memory, args, false)
        }
        _ if number == libc::SYS_llistxattr as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            path_xattr_list(state, memory, args, true)
        }
        _ if number == libc::SYS_flistxattr as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fd_xattr_list(memory, state, args)
        }
        _ if number == libc::SYS_umask as u64 => {
            let previous = state.fs_context.umask;
            state.fs_context.umask = args[0] as libc::mode_t & 0o777;
            i64::from(previous)
        }
        _ if number == libc::SYS_fchmod as u64 => fchmod(state, args),
        _ if number == libc::SYS_chmod as u64 => {
            fchmodat(memory, state, libc::AT_FDCWD, args[0], args[1], 0)
        }
        _ if number == libc::SYS_fchmodat as u64 => {
            // SYS_fchmodat has three arguments; r10 is unspecified guest state.
            fchmodat(memory, state, args[0] as libc::c_int, args[1], args[2], 0)
        }
        _ if number == libc::SYS_fchmodat2 as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            fchmodat(
                memory,
                state,
                args[0] as libc::c_int,
                args[1],
                args[2],
                args[3],
            )
        }
        _ if number == libc::SYS_mknod as u64 => {
            mknod_at(memory, state, libc::AT_FDCWD, args[0], args[1], args[2])
        }
        _ if number == libc::SYS_mknodat as u64 => mknod_at(
            memory,
            state,
            args[0] as libc::c_int,
            args[1],
            args[2],
            args[3],
        ),
        _ if number == libc::SYS_utimensat as u64 => utimensat(memory, state, args),
        _ if number == libc::SYS_arch_prctl as u64 => {
            return arch_prctl(memory, state, args);
        }
        _ if number == libc::SYS_prctl as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            prctl(&mut ProviderMemory(memory), state, args)
        }
        _ if number == libc::SYS_getxattr as u64
            || number == libc::SYS_lgetxattr as u64
            || number == libc::SYS_fgetxattr as u64 =>
        {
            // AUTONOMOUS-BOT-IMPLEMENTED
            getxattr(memory, state, number, args)
        }
        _ if number == libc::SYS_setxattr as u64
            || number == libc::SYS_lsetxattr as u64
            || number == libc::SYS_fsetxattr as u64 =>
        {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-227): Review deterministic xattr mutation refusal.
            setxattr(memory, state, number, args)
        }
        _ if number == libc::SYS_removexattr as u64
            || number == libc::SYS_lremovexattr as u64
            || number == libc::SYS_fremovexattr as u64 =>
        {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-227): Review deterministic xattr removal result.
            removexattr(memory, state, number, args)
        }
        _ if number == libc::SYS_brk as u64 => brk(memory, state, args[0]),
        _ if number == libc::SYS_mmap as u64 => mmap(memory, state, args),
        _ if number == libc::SYS_munmap as u64 => {
            munmap(&mut ProviderMemory(memory), args[0], args[1])
        }
        _ if number == libc::SYS_msync as u64 => match msync(memory, args) {
            Ok(result) => result,
            Err(error) => return SyscallAction::Failure(error),
        },
        _ if number == libc::SYS_mremap as u64 => mremap(memory, state, args),
        _ if number == libc::SYS_mprotect as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            let result = mprotect(&ProviderMemory(memory), args);
            account_protection_change(memory, result, args);
            result
        }
        _ if number == libc::SYS_pkey_mprotect as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            let result = pkey_mprotect(&ProviderMemory(memory), args);
            account_protection_change(memory, result, args);
            result
        }
        _ if number == libc::SYS_pkey_alloc as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            pkey_alloc(state, args)
        }
        _ if number == libc::SYS_pkey_free as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            pkey_free(args)
        }
        _ if number == libc::SYS_madvise as u64 => {
            // Advice answered as a hint that changes the flags Linux keeps on the
            // mappings it covers: the pages keep them (`DeclaredMapping::flags`).
            if let Some((start, length, set, clear)) = madvise_flag_change(args) {
                memory.flag_user_range(start, length, set, clear);
                memory.edit_user_declared(start, length, |declared, shared| {
                    crate::memory::DeclaredMapping {
                        flags: declared.flags & !clear | advised_flags(set, shared),
                        ..declared
                    }
                });
            }
            let result = madvise(&ProviderMemory(memory), args);
            // A guard installed, over a range with holes too: Linux marks
            // each mapping the range touches, whole (`VM_MAYBE_GUARD`).
            if args[2] as libc::c_int == MADV_GUARD_INSTALL
                && (result == 0 || result == negative_errno(libc::ENOMEM))
            {
                super::mapping_list::mark_guarded_lines(
                    memory,
                    &super::mapping_list::ImageMapFacts::of(state),
                    args[0],
                    args[1].saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1),
                );
            }
            result
        }
        _ if number == libc::SYS_munlock as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            let result = munlock_guest_range(&ProviderMemory(memory), args[0], args[1]);
            // Linux checks the arguments (EINVAL) before it changes anything,
            // but unlocks the mappings before a hole and only then fails
            // there (ENOMEM): its unlocked prefix stays unlocked.
            if result != negative_errno(libc::EINVAL) {
                unlock_mappings(memory, args[0], args[1]);
            }
            result
        }
        _ if number == libc::SYS_munlockall as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-145): Review the deterministic no-op unlock-all model.
            unlock_all_mappings(memory);
            0
        }
        _ if number == libc::SYS_mincore as u64 => mincore(&mut ProviderMemory(memory), args),
        _ if number == libc::SYS_sched_get_priority_min as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            sched_priority_bound(libc::SYS_sched_get_priority_min, args[0])
        }
        _ if number == libc::SYS_sched_get_priority_max as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            sched_priority_bound(libc::SYS_sched_get_priority_max, args[0])
        }
        _ if number == libc::SYS_getrandom as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            getrandom(&mut ProviderMemory(memory), args[0], args[1], args[2])
        }
        _ if number == libc::SYS_clock_gettime as u64 => {
            clock_gettime(&mut ProviderMemory(memory), args)
        }
        _ if number == libc::SYS_nanosleep as u64 => nanosleep(&mut ProviderMemory(memory), args),
        _ if number == libc::SYS_clock_nanosleep as u64 => {
            clock_nanosleep(&mut ProviderMemory(memory), args)
        }
        _ if number == libc::SYS_gettimeofday as u64 => {
            gettimeofday(&mut ProviderMemory(memory), args)
        }
        _ if number == libc::SYS_time as u64 => time(&mut ProviderMemory(memory), args),
        _ if number == libc::SYS_readlink as u64 => readlink(memory, state, args),
        _ if number == libc::SYS_readlinkat as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            readlinkat(memory, state, args)
        }
        _ if number == libc::SYS_personality as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            personality(state, args[0])
        }
        _ if number == libc::SYS_uname as u64 => uname(&mut ProviderMemory(memory), args[0]),
        _ if number == libc::SYS_rt_sigaction as u64 => rt_sigaction(memory, state, args),
        _ if number == libc::SYS_rt_sigprocmask as u64 => rt_sigprocmask(memory, state, args),
        _ if number == libc::SYS_rt_sigpending as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            rt_sigpending(memory, state, args)
        }
        _ if number == libc::SYS_sigaltstack as u64 => {
            sigaltstack(memory, state, current_user_stack_pointer, args)
        }
        _ if number == libc::SYS_rt_sigtimedwait as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            rt_sigtimedwait(memory, state, args)
        }
        _ if number == libc::SYS_rt_sigsuspend as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            rt_sigsuspend(memory, state, args)
        }
        _ if number == libc::SYS_kill as u64
            || number == libc::SYS_tkill as u64
            || number == libc::SYS_tgkill as u64 =>
        {
            // AUTONOMOUS-BOT-IMPLEMENTED
            return kill_signal(state, number, args);
        }
        _ if number == libc::SYS_rt_sigqueueinfo as u64
            || number == libc::SYS_rt_tgsigqueueinfo as u64 =>
        {
            // AUTONOMOUS-BOT-IMPLEMENTED
            return sigqueueinfo(memory, state, number, args);
        }
        _ if number == libc::SYS_close as u64 => close(state, args[0]),
        _ if number == libc::SYS_close_range as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            close_range(state, args)
        }
        _ if number == libc::SYS_futex as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            futex(&ProviderMemory(memory), args)
        }
        _ if number == libc::SYS_rseq as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-172): Review deterministic rseq feature refusal.
            negative_errno(libc::ENOSYS)
        }
        _ if number == libc::SYS_get_robust_list as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list queries.
            get_robust_list(memory, state, args)
        }
        _ if number == libc::SYS_set_robust_list as u64 => {
            // AUTONOMOUS-BOT-IMPLEMENTED
            // TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list registration.
            set_robust_list(state, args)
        }
        _ => {
            // Includes every call in `TOOL_DECIDED_SYSCALLS`, whose ENOSYS the
            // checked dispatch reports as the typed refusal `ToolDecided`.
            negative_errno(libc::ENOSYS)
        }
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
        self.state.pidfd_refusal = None;
        // The copies this call reaches stay its own until it returns, and
        // any whose entries another thread retired meanwhile are replaced
        // then, before the guest continues (`PrivateCopies`); a replacement
        // that fails there ends the run by name (`CallScope::end`).
        let call = self.state.private_copy_gate.call_scope();
        let result = self
            .execute_checked_dispatch(request, memory, terminal_read)
            .map_err(|error| memory.capture_shared_file_error(error));
        let ended = call.end(self.state.tid);
        if let Some(failure) = memory.entry_gate().pending_failure() {
            return Err(failure.error());
        }
        let value = result?;
        ended?;
        Ok(value)
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
        // A vfork child's copy may not create a thread (see
        // `vfork_child_creates_thread`).
        if vfork_child_creates_thread(memory, request.number(), request.args()) {
            return Err(crate::Error::VforkChildCapability {
                operation: "thread creation in a vfork child",
                reason: VFORK_CHILD_THREAD_REASON,
            });
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-919): Review shared-file fork admission.
        // Ordinary shared-file views restrict no clone here. A thread runs in
        // this arena beside the caller, and a later publication closes
        // admission for every vCPU of the arena before it changes a view
        // (`EntryGate::close_blocking`). A fork gets a separate arena and gate
        // and inherits the real shared VMAs, which its snapshot refuses by
        // name while another vCPU of this arena runs. So does a vfork-style
        // child (vfork, or a process clone with CLONE_VM|CLONE_VFORK): it runs
        // on a copy of this arena with a gate of its own
        // (`GuestMemory::snapshot_sharing_address_space`), which refuses
        // changes to the inherited views until the child execs. A CLONE_VM
        // process without CLONE_VFORK is refused like any other process clone
        // (`validate_process_clone_flags`).
        if request.number() == libc::SYS_prctl as u64
            && request.args()[0] as i32 == libc::PR_SET_PDEATHSIG
            && (1..=64).contains(&request.args()[1])
            && self.terminal_cleanup.is_none()
        {
            self.unsupported_refusal = Some(parent_death_signal_refusal(request.args()[1]));
            return Ok(negative_errno(libc::ENOSYS));
        }
        let _retirement = self.state.file_retirement.hold();
        if let Some(result) = self.execute_child_wait(request, memory) {
            return result;
        }
        if let Some(result) = self.execute_accept(request, memory) {
            return result;
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
            .as_mut()
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
            #[cfg(test)]
            run_one_shot_test_hook(&TABLE_RELEASED_TEST_HOOK);
        }
        if self.parent_death_enrolled()
            && matches!(
                request.number() as libc::c_long,
                libc::SYS_execve | libc::SYS_execveat
            )
        {
            return Ok(match self.take_parent_death_exec(request)? {
                Ok(retained) => self.prepare_exec(memory, request, Some(retained)),
                Err(refusal) => {
                    self.unsupported_refusal = Some(refusal);
                    negative_errno(libc::ENOMEM)
                }
            });
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
            shared_files.update_from_elf(&self.state)?;
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
                    .or_else(|| userfaultfd_refusal(request, result))
                {
                    self.unsupported_refusal = Some(refusal);
                }
                if let Some(refusal) =
                    signal_refusal_record(self.state.signal_refusal.take(), result)
                {
                    self.unsupported_refusal = Some(refusal);
                }
                if let Some(refusal) = pidfd_refusal_record(self.state.pidfd_refusal.take(), result)
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

/// After a `munlock(2)` of `[address, address + length)` whose arguments
/// Linux accepts (no EINVAL), whether it then succeeded or failed with
/// ENOMEM: takes `FLAG_LOCKED` from the mappings it unlocked, as
/// `apply_vma_lock_flags` clears `VM_LOCKED_MASK` (`mm/mlock.c`), mapping
/// by mapping, in address order: the pages of the range, rounded to whole
/// pages as Linux rounds it, from its start up to the first page no mapping
/// holds, where Linux stops and fails with ENOMEM. (This backend's
/// validation reports that ENOMEM for a range that leaves the user address
/// space, not for a hole inside it, see `munlock_guest_range`; either way
/// the prefix is unlocked.) A mapping it covers part of is split there, and
/// a part left with the flags of its neighbour merges with it, as
/// `mlock_fixup` merges them; the list of mappings finds both from the
/// pages.
fn unlock_mappings(memory: &GuestMemory, address: u64, length: u64) {
    if memory.flagged_pages(FLAG_LOCKED) == 0 {
        return;
    }
    let Some((start, length)) = munlock_range(address, length) else {
        return;
    };
    let mut end = start;
    for run in memory.user_mapping_runs_in(start, length).runs {
        if run.start != end {
            break;
        }
        end = run.end;
    }
    clear_locked(memory, start, end - start);
}

/// After `munlockall(2)`: takes `FLAG_LOCKED` from every mapping, as
/// `apply_mlockall_flags` clears `VM_LOCKED_MASK` from each (`mm/mlock.c`).
fn unlock_all_mappings(memory: &GuestMemory) {
    if memory.flagged_pages(FLAG_LOCKED) != 0 {
        clear_locked(memory, 0, crate::memory::USER_ADDRESS_END);
    }
}

/// Clears `FLAG_LOCKED` on the declared pages of the user range
/// `[start, start + length)`. No page of the stack window has it.
fn clear_locked(memory: &GuestMemory, start: u64, length: u64) {
    memory.edit_user_declared(start, length, |declared, _| {
        crate::memory::DeclaredMapping {
            flags: declared.flags & !FLAG_LOCKED,
            ..declared
        }
    });
}

/// The provider flags advice that sets `set` sets on a page that is shared
/// or not: all of them, but `FLAG_MERGEABLE` on a shared page. Linux accepts
/// `MADV_MERGEABLE` there and leaves the mapping as it was: `ksm_madvise`
/// returns without `VM_MERGEABLE` for a mapping that `ksm_compatible`
/// rejects, as it does every `VM_SHARED` or `VM_MAYSHARE` one
/// (`mm/ksm.c`). Every other flag the advice this backend accepts sets is
/// set on any mapping. (The stack window, which the window's own editor
/// flags, is private.)
fn advised_flags(set: u16, shared: bool) -> u16 {
    if shared { set & !FLAG_MERGEABLE } else { set }
}

/// After a successful `mprotect(2)` or `pkey_mprotect(2)` (`result`, of
/// `args`), the charge of each private page of the range, for the list of
/// mappings (`mapping_list`), as `mprotect_fixup` (`mm/mprotect.c`) changes
/// `VM_ACCOUNT`:
/// - made writable: charged (`FLAG_ACCOUNT`), unless it is `MAP_NORESERVE`
///   or `MAP_HUGETLB` memory, and known to be (`FLAG_ACCOUNT_UNKNOWN`
///   cleared);
/// - otherwise, a charged page may have lost its charge: Linux takes it back
///   from an anonymous mapping with no `anon_vma`, which depends on whether
///   the mapping was written, which the pages do not say, so it gets
///   `FLAG_ACCOUNT_UNKNOWN` and keeps `FLAG_ACCOUNT`. Not a guarded page:
///   installing a guard prepared its mapping's `anon_vma`
///   (`madvise_guard_install`), so the charge stays. A file mapping never
///   loses it, which the list of mappings reads from the line's backing.
///
/// Shared pages are never charged. The protection change was applied to the
/// whole range or to none of it (`ProviderMemory::protect` refuses the range
/// before it changes any page), so a success names every page it changed.
fn account_protection_change(memory: &GuestMemory, result: i64, args: &[u64; 6]) {
    if result != 0 {
        return;
    }
    let writable = args[2] & libc::PROT_WRITE as u64 != 0;
    memory.edit_user_declared(args[0], args[1], |declared, shared| {
        let flags = declared.flags;
        let flags = if shared {
            flags
        } else if writable {
            if flags & (FLAG_NORESERVE | FLAG_HUGETLB) != 0 {
                flags
            } else {
                flags & !FLAG_ACCOUNT_UNKNOWN | FLAG_ACCOUNT
            }
        } else if flags & FLAG_ACCOUNT != 0 && flags & FLAG_MAYBE_GUARD == 0 {
            flags | FLAG_ACCOUNT_UNKNOWN
        } else {
            flags
        };
        crate::memory::DeclaredMapping { flags, ..declared }
    });
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

#[cfg(test)]
mod routing_tests {
    use super::*;

    fn probe(number: u64, args: [u64; 6]) -> SyscallAction {
        let dir = std::env::temp_dir().join(format!("r3-routing-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let mut state = test_state(&dir);
        execute_basic_syscall(&mut memory, &mut state, &SyscallRequest::new(number, args))
    }

    fn continued(action: SyscallAction) -> i64 {
        match action {
            SyscallAction::Continue { result, .. } => result,
            _other => panic!("expected Continue, got a different action"),
        }
    }

    // Routing semantics, not membership: each probe distinguishes its arm
    // from the ENOSYS fallback and from neighbouring arms.
    #[test]
    fn exit_arms_return_exit_action_before_fallback() {
        assert!(matches!(
            probe(libc::SYS_exit as u64, [7, 0, 0, 0, 0, 0]),
            SyscallAction::Exit(ExitStatus::Exited(7))
        ));
        assert!(matches!(
            probe(libc::SYS_exit_group as u64, [3, 0, 0, 0, 0, 0]),
            SyscallAction::Exit(ExitStatus::Exited(3))
        ));
    }

    #[test]
    fn fallback_and_refusal_arms_keep_existing_pairs() {
        // Unknown number: fallback ENOSYS.
        assert_eq!(continued(probe(9999, [0; 6])), negative_errno(libc::ENOSYS));
        // rseq: explicit arm, still ENOSYS (refusal pair preserved, R7 separate).
        assert_eq!(
            continued(probe(libc::SYS_rseq as u64, [0; 6])),
            negative_errno(libc::ENOSYS)
        );
        // ToolDecided sample: no arm, ENOSYS via fallback.
        assert_eq!(
            continued(probe(libc::SYS_getuid as u64, [0; 6])),
            negative_errno(libc::ENOSYS)
        );
    }

    #[test]
    fn handler_arms_route_to_their_handlers() {
        // getpid answers from task state, never ENOSYS.
        assert!(continued(probe(libc::SYS_getpid as u64, [0; 6])) > 0);
        // close of an unopened fd: EBADF from the close handler.
        assert_eq!(
            continued(probe(libc::SYS_close as u64, [99, 0, 0, 0, 0, 0])),
            negative_errno(libc::EBADF)
        );
        // kill of a nonexistent pid: ESRCH from the signal handler arm.
        assert_eq!(
            continued(probe(libc::SYS_kill as u64, [999_999, 0, 0, 0, 0, 0])),
            negative_errno(libc::ESRCH)
        );
        // futex at an unmapped address: EFAULT, not the fallback ENOSYS.
        assert_eq!(
            continued(probe(libc::SYS_futex as u64, [0x1_0000, 0, 0, 0, 0, 0])),
            negative_errno(libc::EFAULT)
        );
    }

    // Frozen dispatch inventory (from the pre-R3 chain at the R3 baseline):
    // every guarded syscall name must still guard an arm. Catches a dropped
    // or renamed arm that the 9 routing probes above cannot sample.
    const FROZEN_DISPATCHED: &[&str] = &[
        "SYS_access",
        "SYS_arch_prctl",
        "SYS_bind",
        "SYS_brk",
        "SYS_capget",
        "SYS_capset",
        "SYS_chdir",
        "SYS_chmod",
        "SYS_chown",
        "SYS_clock_gettime",
        "SYS_clock_nanosleep",
        "SYS_close",
        "SYS_close_range",
        "SYS_connect",
        "SYS_creat",
        "SYS_dup",
        "SYS_dup2",
        "SYS_dup3",
        "SYS_epoll_create1",
        "SYS_epoll_ctl",
        "SYS_epoll_pwait",
        "SYS_epoll_pwait2",
        "SYS_epoll_wait",
        "SYS_eventfd",
        "SYS_eventfd2",
        "SYS_exit",
        "SYS_exit_group",
        "SYS_faccessat",
        "SYS_faccessat2",
        "SYS_fallocate",
        "SYS_fchdir",
        "SYS_fchmod",
        "SYS_fchmodat",
        "SYS_fchmodat2",
        "SYS_fchown",
        "SYS_fchownat",
        "SYS_fcntl",
        "SYS_fdatasync",
        "SYS_fgetxattr",
        "SYS_flistxattr",
        "SYS_flock",
        "SYS_fremovexattr",
        "SYS_fsetxattr",
        "SYS_fstat",
        "SYS_fstatfs",
        "SYS_fsync",
        "SYS_ftruncate",
        "SYS_futex",
        "SYS_getcwd",
        "SYS_getdents64",
        "SYS_getgroups",
        "SYS_getpeername",
        "SYS_getpid",
        "SYS_getppid",
        "SYS_getrandom",
        "SYS_get_robust_list",
        "SYS_getsockname",
        "SYS_getsockopt",
        "SYS_gettid",
        "SYS_gettimeofday",
        "SYS_getxattr",
        "SYS_inotify_add_watch",
        "SYS_inotify_init",
        "SYS_inotify_init1",
        "SYS_inotify_rm_watch",
        "SYS_ioctl",
        "SYS_kill",
        "SYS_lchown",
        "SYS_lgetxattr",
        "SYS_link",
        "SYS_linkat",
        "SYS_listen",
        "SYS_listxattr",
        "SYS_llistxattr",
        "SYS_lremovexattr",
        "SYS_lseek",
        "SYS_lsetxattr",
        "SYS_lstat",
        "SYS_madvise",
        "SYS_memfd_create",
        "SYS_mincore",
        "SYS_mkdir",
        "SYS_mkdirat",
        "SYS_mknod",
        "SYS_mknodat",
        "SYS_mmap",
        "SYS_mprotect",
        "SYS_mremap",
        "SYS_msync",
        "SYS_munlock",
        "SYS_munlockall",
        "SYS_munmap",
        "SYS_nanosleep",
        "SYS_newfstatat",
        "SYS_open",
        "SYS_openat",
        "SYS_personality",
        "SYS_pidfd_open",
        "SYS_pipe",
        "SYS_pipe2",
        "SYS_pkey_alloc",
        "SYS_pkey_free",
        "SYS_pkey_mprotect",
        "SYS_poll",
        "SYS_ppoll",
        "SYS_prctl",
        "SYS_pread64",
        "SYS_preadv",
        "SYS_preadv2",
        "SYS_pselect6",
        "SYS_pwrite64",
        "SYS_pwritev",
        "SYS_pwritev2",
        "SYS_read",
        "SYS_readahead",
        "SYS_readlink",
        "SYS_readlinkat",
        "SYS_readv",
        "SYS_recvfrom",
        "SYS_recvmmsg",
        "SYS_recvmsg",
        "SYS_removexattr",
        "SYS_rename",
        "SYS_renameat",
        "SYS_renameat2",
        "SYS_rmdir",
        "SYS_rseq",
        "SYS_rt_sigaction",
        "SYS_rt_sigpending",
        "SYS_rt_sigprocmask",
        "SYS_rt_sigqueueinfo",
        "SYS_rt_sigsuspend",
        "SYS_rt_sigtimedwait",
        "SYS_rt_tgsigqueueinfo",
        "SYS_sched_get_priority_max",
        "SYS_sched_get_priority_min",
        "SYS_select",
        "SYS_sendfile",
        "SYS_sendmsg",
        "SYS_sendto",
        "SYS_set_robust_list",
        "SYS_setsockopt",
        "SYS_setxattr",
        "SYS_shutdown",
        "SYS_sigaltstack",
        "SYS_signalfd",
        "SYS_signalfd4",
        "SYS_socket",
        "SYS_socketpair",
        "SYS_stat",
        "SYS_statfs",
        "SYS_statx",
        "SYS_symlink",
        "SYS_symlinkat",
        "SYS_sync_file_range",
        "SYS_syncfs",
        "SYS_tgkill",
        "SYS_time",
        "SYS_timerfd_create",
        "SYS_timerfd_gettime",
        "SYS_timerfd_settime",
        "SYS_tkill",
        "SYS_truncate",
        "SYS_umask",
        "SYS_uname",
        "SYS_unlink",
        "SYS_unlinkat",
        "SYS_utimensat",
        "SYS_wait4",
        "SYS_waitid",
        "SYS_write",
        "SYS_writev",
    ];

    #[test]
    fn frozen_inventory_still_dispatches_every_name() {
        let src = include_str!("dispatch.rs");
        let inner = src
            .split("fn execute_basic_syscall_inner")
            .nth(1)
            .expect("dispatch function present")
            .split("mod routing_tests")
            .next()
            .expect("dispatch function precedes the tests");
        for name in FROZEN_DISPATCHED {
            let guard = format!("number == libc::{name} as u64");
            let found = inner.contains(&format!("{guard} =>"))
                || inner.contains(&format!("{guard} ||"))
                || inner.contains(&format!("{guard} {{"))
                || inner.contains(&format!("{guard}\n"));
            assert!(found, "dispatch guard lost for {name}");
        }
    }
}
