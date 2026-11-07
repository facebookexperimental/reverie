/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! select, poll and epoll (gVisor: pkg/sentry/syscalls/linux/sys_poll.go, sys_epoll.go, pkg/sentry/vfs/epoll.go).

use std::time::Duration;
use std::time::Instant;

use super::*;
use crate::signal::SignalFdWaiter;

/// Positive provenance is minted only by the corresponding native creator.
/// In particular, a virtual signalfd's eventfd carrier is not NativeEventFd.
#[derive(Clone, Debug)]
pub(crate) enum NativePollDescription {
    EventFd(Arc<NativeEventFd>),
    Epoll(Arc<()>),
}

/// Export can hand an eventfd writer to an untracked actor. This one-way bit
/// follows the open description through every dup/fork, so exporting any
/// alias removes admission from existing and future interest sets alike.
#[derive(Debug, Default)]
pub(crate) struct NativeEventFd {
    pub(super) escaped: AtomicBool,
}

/// Shared table identity, including histories that this backend does not
/// model. A later creator must not erase an earlier unsupported table split.
#[derive(Debug, Default)]
pub(crate) struct NativePollTable {
    pub(super) unsafe_history: AtomicBool,
}

impl NativePollTable {
    pub(crate) fn fork_identity(&self) -> Arc<Self> {
        // A fork has a new table, but cannot certify a snapshot descended from
        // an unmodeled split. CLONE_FILES keeps the original shared identity.
        Arc::new(Self {
            unsafe_history: AtomicBool::new(self.unsafe_history.load(Ordering::SeqCst)),
        })
    }
}

/// One logical descriptor entry, shared by CLONE_FILES snapshots. Its File
/// may outlive a guest close in a stale snapshot, so Arc liveness alone does
/// not establish that this binding is still part of the guest file table.
#[derive(Debug)]
pub(crate) struct NativePollBinding {
    pub(super) description: NativePollDescription,
    pub(super) live: AtomicBool,
}

impl NativePollBinding {
    fn new(description: NativePollDescription) -> Arc<Self> {
        Arc::new(Self {
            description,
            live: AtomicBool::new(true),
        })
    }

    pub(crate) fn fork_binding(&self) -> Arc<Self> {
        Self::new(self.description.clone())
    }

    /// Caller holds the family's epoll domain, serializing retirement with a
    /// zero-time wait. This token never becomes live again.
    pub(crate) fn retire(&self) {
        self.live.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub(super) struct EpollRegistration {
    pub(super) binding: std::sync::Weak<NativePollBinding>,
    pub(super) eventfd: Arc<NativeEventFd>,
    pub(super) host_key: RawFd,
}

#[derive(Debug)]
pub(super) struct EpollProof {
    pub(super) owner: std::sync::Weak<()>,
    pub(super) table: std::sync::Weak<NativePollTable>,
    pub(super) unsafe_history: bool,
    pub(super) registrations: std::collections::BTreeMap<i32, EpollRegistration>,
}

/// A leaf lock shared only within one guest family, not globally. Never hold
/// it while acquiring other locks, calling guest-memory APIs that can notify
/// or reenter, retiring a File, or constructing/finishing a writable alias.
/// Kernel copyout through an already-retained alias is allowed. The records contain no File,
/// memory, entry gate or callback, so their destruction cannot notify/reenter.
#[derive(Debug, Default)]
pub(crate) struct EpollDomain {
    pub(super) proofs: std::collections::BTreeMap<usize, EpollProof>,
}

pub(super) fn epoll_identity_key(identity: &Arc<()>) -> usize {
    // The record's Weak keeps this allocation from being reused until removal.
    // This private token is unrelated to a host fd or anonymous inode number.
    Arc::as_ptr(identity) as usize
}

pub(super) fn native_poll_description(
    state: &LoadedStaticElf,
    fd: i32,
) -> Option<NativePollDescription> {
    state
        .native_poll_fds
        .get(&fd)
        .map(|binding| binding.description.clone())
}

pub(super) fn install_native_poll_description(
    state: &mut LoadedStaticElf,
    fd: i32,
    description: NativePollDescription,
) {
    state
        .native_poll_fds
        .insert(fd, NativePollBinding::new(description));
}

impl EpollProof {
    fn admitted(&self, state: &LoadedStaticElf) -> bool {
        !self.unsafe_history
            && !state.poll_table_id.unsafe_history.load(Ordering::SeqCst)
            && self.table.ptr_eq(&Arc::downgrade(&state.poll_table_id))
            && self.registrations.values().all(|registration| {
                registration.binding.upgrade().is_some_and(|binding| {
                    binding.live.load(Ordering::SeqCst)
                        && !registration.eventfd.escaped.load(Ordering::SeqCst)
                        && matches!(&binding.description, NativePollDescription::EventFd(id)
                            if Arc::ptr_eq(id, &registration.eventfd))
                })
            })
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct Pselect6SigmaskArg {
    pub(super) sigmask: u64,
    pub(super) sigsetsize: u64,
}

/// Queries the current guest signal generations without dequeuing, acquiring a
/// delivery permit, or changing a mask. Keep the process-before-thread lock
/// order shared with the ordinary return-to-user signal boundary.
pub(super) fn has_eligible_pending_signal(state: &LoadedStaticElf) -> bool {
    let process_signals = state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let generations = &process_signals.pending_generations;
    let thread_signals = state.thread_signals.lock();
    let blocked = thread_signals.blocked;
    thread_signals.pending.any_eligible(blocked, generations)
        || process_signals
            .shared_pending
            .any_eligible(blocked, generations)
}

/// Implements one instantaneous, one-word pselect6 readiness probe, with or
/// without a temporary signal mask. Detcore owns retries and guest time. All
/// other valid execution forms remain explicitly unsupported, after Linux's
/// original argument-validation order.
pub(super) fn pselect6(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    capture_output: bool,
) -> i64 {
    // Linux first copies the complete outer { sigmask, sigsetsize } wrapper.
    let sigmask_argument = if args[5] == 0 {
        None
    } else {
        match read_guest_struct::<Pselect6SigmaskArg>(&ProviderMemory(memory), args[5]) {
            Ok(argument) => Some(argument),
            Err(error) => return error,
        }
    };

    // do_pselect reads and validates the timeout before inspecting the inner
    // signal-mask pointer or size. NULL means an unsupported infinite wait.
    let zero_timeout = if args[4] != 0 {
        let timeout = match read_guest_struct::<libc::timespec>(&ProviderMemory(memory), args[4]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000_000).contains(&timeout.tv_nsec) {
            return negative_errno(libc::EINVAL);
        }
        timeout.tv_sec == 0 && timeout.tv_nsec == 0
    } else {
        false
    };

    // set_user_sigmask ignores sigsetsize when the inner pointer is NULL.
    let mut temporary_mask = None;
    if let Some(argument) = sigmask_argument
        && argument.sigmask != 0
    {
        if argument.sigsetsize != KERNEL_SIGSET_SIZE as u64 {
            return negative_errno(libc::EINVAL);
        }
        let mut mask = [0; KERNEL_SIGSET_SIZE];
        if memory.user().read(argument.sigmask, &mut mask).is_err() {
            return negative_errno(libc::EFAULT);
        }
        let mut mask = KernelSigset::from_bytes(mask);
        mask.clear_unmaskable();
        temporary_mask = Some(mask);
    }

    // The raw syscall argument is an int; Linux observes its signed low word.
    let nfds = args[0] as libc::c_int;
    if nfds < 0 {
        return negative_errno(libc::EINVAL);
    }
    // Linux clamps to the live fd-table capacity. One machine word is exact
    // even for its initial table; do not guess the size of a grown guest table.
    if nfds > u64::BITS as libc::c_int {
        return negative_errno(libc::ENOSYS);
    }
    let mut sets = [0_u64; 3];
    if nfds != 0 {
        // Snapshot every input before descriptor checks or any output, including
        // aliases. The n == 0 exemption must not inspect any fd-set pointer.
        for (word, &address) in sets.iter_mut().zip(&args[1..4]) {
            if address != 0 {
                let mut bytes = [0; 8];
                if memory.user().read(address, &mut bytes).is_err() {
                    return negative_errno(libc::EFAULT);
                }
                *word = u64::from_ne_bytes(bytes);
            }
        }
    }
    if !zero_timeout {
        return negative_errno(libc::ENOSYS);
    }

    // fs/select.c POLLIN_SET/POLLOUT_SET/POLLEX_SET include normal/band bits
    // and NVAL. An absent guest fd is EBADF, but poll's NVAL for an existing
    // O_PATH description is readiness in all requested sets, as in Linux.
    // https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/select.c#L459
    const READ: libc::c_short = libc::POLLIN
        | libc::POLLRDNORM
        | libc::POLLRDBAND
        | libc::POLLHUP
        | libc::POLLERR
        | libc::POLLNVAL;
    const WRITE: libc::c_short =
        libc::POLLOUT | libc::POLLWRNORM | libc::POLLWRBAND | libc::POLLERR | libc::POLLNVAL;
    const EXCEPT: libc::c_short = libc::POLLPRI | libc::POLLNVAL;
    let mut poll_fds = Vec::new();
    let mut requested = Vec::new();
    let mut captured_alias_selected = false;
    for fd in 0..nfds {
        let bit = 1_u64 << fd;
        let membership = sets.map(|word| word & bit != 0);
        if !membership.into_iter().any(|present| present) {
            continue;
        }
        let Some(host_fd) = host_fd(state, fd) else {
            return negative_errno(libc::EBADF);
        };
        captured_alias_selected |= capture_output && output_alias(state, fd).is_some();
        let signalfd = signalfd_mask(state, fd);
        let events = if signalfd.is_some() {
            if membership[0] { libc::POLLIN } else { 0 }
        } else {
            // Linux includes the exception mask in its poll key unconditionally.
            EXCEPT | if membership[0] { READ } else { 0 } | if membership[1] { WRITE } else { 0 }
        };
        poll_fds.push(libc::pollfd {
            fd: host_fd,
            events,
            revents: 0,
        });
        requested.push((bit, membership, signalfd));
    }
    // Captured output lives in memory, not in the retained host carrier (or
    // ambient host stdout/stderr). Its readiness is not modeled yet. Validate
    // every selected fd first so a later absent fd still wins with EBADF, then
    // refuse before host polling or any guest copyout, including O_PATH aliases.
    if captured_alias_selected {
        return negative_errno(libc::ENOSYS);
    }
    // SAFETY: poll sees only initialized host-owned storage and a zero timeout;
    // it never sees a guest pointer or changes the host signal mask.
    if unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, 0) } < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let mut output = [0_u64; 3];
    let mut ready_count = 0;
    for (entry, (bit, membership, signalfd)) in poll_fds.iter().zip(requested) {
        let readiness = if let Some(mask) = signalfd {
            // Readable from this thread's queues, never the eventfd keeper's
            // always-writable bit.
            [signalfd_readable(state, *mask), false, false]
        } else {
            [READ, WRITE, EXCEPT].map(|mask| entry.revents & mask != 0)
        };
        for index in 0..3 {
            if membership[index] && readiness[index] {
                output[index] |= bit;
                ready_count += 1;
            }
        }
    }
    // Linux checks pending signals only after a zero-readiness sample and before
    // copyout (core_sys_select): a signal that the call's mask (the temporary one,
    // else the thread's own) does not block ends it with ERESTARTNOHAND and no
    // copyout. Positive readiness wins even with an eligible signal, and then, as
    // on a zero result, Linux restores the thread's own mask before the call
    // returns (poll_select_finish), so no temporary mask is installed at all.
    if ready_count == 0 {
        // TODO-HUMAN-REVIEW(PR-1014)
        // ERESTARTNOHAND becomes EINTR when the return boundary runs a handler
        // or the process dies, which is what this returns; for a temporary mask
        // the thread's own mask is saved for that delivery's frame. A signal
        // Linux would discard or stop on leaves a restart that a scalar return
        // cannot express, so that completion stays refused, without dequeuing.
        let transaction = state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let mask = temporary_mask.unwrap_or_else(|| state.thread_signals.lock().blocked);
        match temporary_mask_signal(state, mask) {
            TemporaryMaskSignal::None => {}
            TemporaryMaskSignal::Interrupts => {
                if let Some(mask) = temporary_mask {
                    install_temporary_mask_for_delivery(state, mask);
                }
                return negative_errno(libc::EINTR);
            }
            TemporaryMaskSignal::Unrepresentable => return negative_errno(libc::ENOSYS),
        }
    }
    if nfds != 0 {
        for (&address, word) in args[1..4].iter().zip(output) {
            if address != 0
                && memory
                    .user()
                    .copy_to_user(address, &word.to_ne_bytes())
                    .is_err()
            {
                return negative_errno(libc::EFAULT);
            }
        }
    }
    // poll_select_finish takes its no-update path for an initially zero timeout,
    // on success AND failure. Even rewriting zero would wrongly fault on RO pages
    // or overwrite an aliased fd-set result. Never write this timespec here.
    ready_count
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-205): Review deterministic select readiness and timeout semantics.
pub(super) fn select(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(nfds) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EINVAL);
    };
    if !(0..=GUEST_NOFILE_LIMIT).contains(&nfds) {
        return negative_errno(libc::EINVAL);
    }
    let word_count = (nfds as usize).div_ceil(u64::BITS as usize);
    let byte_length = word_count * std::mem::size_of::<u64>();
    if byte_length > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    let mut sets = [Vec::new(), Vec::new(), Vec::new()];
    for (set, address) in sets.iter_mut().zip(&args[1..4]) {
        *set = vec![0_u64; word_count];
        if *address != 0 && byte_length != 0 {
            // SAFETY: the vector contains initialized u64 words and the byte
            // view is exactly bounded to its allocation.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(set.as_mut_ptr().cast::<u8>(), byte_length)
            };
            if memory.user().read(*address, bytes).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
    }

    if args[4] != 0 {
        let timeout = match read_guest_struct::<libc::timeval>(&ProviderMemory(memory), args[4]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000).contains(&timeout.tv_usec) {
            return negative_errno(libc::EINVAL);
        }
    }

    let mut poll_fds = Vec::new();
    let mut requested = Vec::new();
    for guest_fd in 0..nfds {
        let membership = sets.each_ref().map(|set| fd_set_contains(set, guest_fd));
        if !membership.into_iter().any(|present| present) {
            continue;
        }
        let Some(host_fd) = host_fd(state, guest_fd) else {
            return negative_errno(libc::EBADF);
        };
        let signalfd = signalfd_mask(state, guest_fd);
        let mut events = 0;
        if membership[0] {
            events |= libc::POLLIN;
        }
        if membership[1] && signalfd.is_none() {
            events |= libc::POLLOUT;
        }
        if membership[2] && signalfd.is_none() {
            events |= libc::POLLPRI;
        }
        poll_fds.push(libc::pollfd {
            fd: host_fd,
            events,
            revents: 0,
        });
        requested.push((guest_fd, membership, signalfd));
    }

    // Detcore owns guest time. Preserve readiness that exists now without
    // blocking the supervisor on host wall time for a guest timeout.
    let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as libc::nfds_t, 0) };
    if ready < 0 {
        return io_error(std::io::Error::last_os_error());
    }

    let mut ready_sets = [
        vec![0_u64; word_count],
        vec![0_u64; word_count],
        vec![0_u64; word_count],
    ];
    let mut ready_count = 0_i64;
    for (poll_fd, (guest_fd, membership, signalfd)) in poll_fds.iter().zip(requested) {
        let ready = if let Some(mask) = signalfd {
            // Readable from this thread's queues. A Linux signalfd is
            // read-only and never reports the eventfd keeper's unconditional
            // POLLOUT readiness.
            [signalfd_readable(state, *mask), false, false]
        } else {
            [
                poll_fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0,
                poll_fd.revents & (libc::POLLOUT | libc::POLLERR) != 0,
                poll_fd.revents & libc::POLLPRI != 0,
            ]
        };
        for index in 0..ready_sets.len() {
            if membership[index] && ready[index] {
                fd_set_insert(&mut ready_sets[index], guest_fd);
                ready_count += 1;
            }
        }
    }

    for (address, ready_set) in args[1..4].iter().zip(&ready_sets) {
        if *address == 0 || byte_length == 0 {
            continue;
        }
        // SAFETY: the vector contains initialized u64 words and the byte view
        // is exactly bounded to its allocation.
        let bytes =
            unsafe { std::slice::from_raw_parts(ready_set.as_ptr().cast::<u8>(), byte_length) };
        if memory.user().write(*address, bytes).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    if args[4] != 0 {
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        if write_struct(&mut ProviderMemory(memory), args[4], &timeout) != 0 {
            return negative_errno(libc::EFAULT);
        }
    }
    ready_count
}

fn fd_set_contains(set: &[u64], fd: libc::c_int) -> bool {
    let fd = fd as usize;
    set.get(fd / u64::BITS as usize)
        .is_some_and(|word| word & (1_u64 << (fd % u64::BITS as usize)) != 0)
}

fn fd_set_insert(set: &mut [u64], fd: libc::c_int) {
    let fd = fd as usize;
    set[fd / u64::BITS as usize] |= 1_u64 << (fd % u64::BITS as usize);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review guest descriptor translation and deterministic nonblocking poll semantics.
pub(super) fn poll(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    poll_with_timeout(&mut ProviderMemory(memory), state, args, 0)
}

// TODO-HUMAN-REVIEW(PR-172): Review host-blocking KVM ppoll timeout and signal-mask semantics.
pub(super) fn ppoll(memory: &mut GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // Validate the timeout up front for every ppoll, mirroring detcore's
    // handle_ppoll (hermit detcore/src/syscalls/io.rs:824-828): the kernel
    // rejects a malformed timeout (bad pointer or out-of-range nanoseconds)
    // regardless of whether a signal mask is present.
    let timeout = if args[2] == 0 {
        -1
    } else {
        let timeout = match read_guest_struct::<libc::timespec>(&ProviderMemory(memory), args[2]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000_000).contains(&timeout.tv_nsec) {
            return negative_errno(libc::EINVAL);
        }
        let milliseconds = (timeout.tv_sec as u128)
            .saturating_mul(1_000)
            .saturating_add((timeout.tv_nsec as u128).div_ceil(1_000_000));
        milliseconds.min(libc::c_int::MAX as u128) as libc::c_int
    };
    if args[3] != 0 {
        if args[4] != KERNEL_SIGSET_SIZE as u64 {
            return negative_errno(libc::EINVAL);
        }
        // The kernel copies the signal mask out of user space (copy_from_user)
        // before it polls, so an unreadable mask pointer must fault with EFAULT
        // rather than return a readiness result. Detcore's golden
        // prepare_ppoll_probe does the same via read_value(signal_mask)? (hermit
        // detcore/src/syscalls/io.rs:874-892). Observe the mask here to
        // reproduce that fault semantics; its value is deliberately not applied
        // across the wait (see the note below), but a bogus pointer can never be
        // serviced as ready.
        let mut signal_mask = [0u8; KERNEL_SIGSET_SIZE];
        if memory.user().read(args[3], &mut signal_mask).is_err() {
            return negative_errno(libc::EFAULT);
        }
        // A masked ppoll mirrors detcore's handle_internal_ppoll (hermit
        // detcore/src/syscalls/io.rs:922-939): a zero-timeout probe can honor a
        // temporary signal mask atomically, but keeping the mask active across a
        // parked wait would require scheduler-level pending-signal state. So
        // probe non-blocking and fail closed with ENOSYS only when the call
        // would have blocked (nothing ready). The mask cannot affect an
        // instantaneous poll, so a plain non-blocking poll reproduces the kernel
        // result: a ready descriptor returns its count exactly as the unmasked
        // path would, and a poll/read error propagates unchanged.
        let ready = poll_with_timeout(&mut ProviderMemory(memory), state, args, 0);
        if ready == 0 {
            return negative_errno(libc::ENOSYS);
        }
        return ready;
    }
    poll_with_timeout(&mut ProviderMemory(memory), state, args, timeout)
}

fn poll_with_timeout<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    timeout: libc::c_int,
) -> i64 {
    // Both Linux syscall entrypoints declare nfds as unsigned int, even on
    // x86-64 where the raw syscall register and host nfds_t are wider.
    let count = args[1] as u32 as usize;
    if count > GUEST_NOFILE_LIMIT as usize {
        return negative_errno(libc::EINVAL);
    }
    let Some(byte_length) = count.checked_mul(std::mem::size_of::<libc::pollfd>()) else {
        return negative_errno(libc::EINVAL);
    };
    if byte_length > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    let mut poll_fds = vec![
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        };
        count
    ];
    {
        // SAFETY: poll_fds is initialized plain ABI data and the byte view is
        // exactly bounded to the vector allocation.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(poll_fds.as_mut_ptr().cast::<u8>(), byte_length)
        };
        if memory.read_exact(args[0], bytes).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }

    let guest_fds = poll_fds
        .iter()
        .map(|poll_fd| poll_fd.fd)
        .collect::<Vec<_>>();
    let guest_events = poll_fds
        .iter()
        .map(|poll_fd| poll_fd.events)
        .collect::<Vec<_>>();
    let signalfds = guest_fds
        .iter()
        .map(|fd| (*fd >= 0).then(|| signalfd_mask(state, *fd)).flatten())
        .collect::<Vec<_>>();
    let mut invalid = vec![false; count];
    for (index, poll_fd) in poll_fds.iter_mut().enumerate() {
        poll_fd.revents = 0;
        if poll_fd.fd < 0 {
            continue;
        }
        if signalfds[index].is_some() {
            // A signalfd is only ever readable. Its eventfd keeper's POLLIN
            // shows the shared queue, which wakes a wait below.
            poll_fd.events &= libc::POLLIN;
        }
        match host_fd(state, poll_fd.fd) {
            Some(host_fd) => poll_fd.fd = host_fd,
            None => {
                poll_fd.fd = -1;
                invalid[index] = true;
            }
        }
    }
    // The signals of every signalfd asked for POLLIN, the only readiness a
    // signalfd reports: a signal for one asked only for POLLOUT ends no wait.
    let mut signal_mask = KernelSigset::default();
    let mut polls_signalfds = false;
    for (mask, events) in signalfds.iter().zip(&guest_events) {
        if let Some(mask) = mask
            && events & libc::POLLIN != 0
        {
            signal_mask.union_with(**mask);
            polls_signalfds = true;
        }
    }

    // SYS_poll remains nonblocking for deterministic personality calls. The
    // concurrent KVM ppoll path may block in the host so QEMU's root event loop
    // can wait for worker eventfds without spinning on virtual clock reads.
    // A missing guest descriptor is already ready with POLLNVAL. Still probe
    // the other descriptors, but never wait for them before reporting it.
    let deadline = u64::try_from(timeout)
        .ok()
        .map(|milliseconds| Instant::now() + Duration::from_millis(milliseconds));
    let mut first = true;
    let ready_count = loop {
        // A signalfd already readable by this thread ends the call at once,
        // as an already-ready descriptor ends Linux's do_poll.
        let waits = timeout != 0
            && !invalid.iter().any(|invalid| *invalid)
            && !(polls_signalfds && signalfd_readable(state, signal_mask));
        let waiter = if waits && polls_signalfds {
            match SignalFdWait::register(state, signal_mask) {
                Ok(Some(waiter)) => Some(waiter),
                // A covered signal arrived since the check above.
                Ok(None) => continue,
                Err(error) => return io_error(error),
            }
        } else {
            None
        };
        let host_timeout = match (waits, first, deadline) {
            (false, _, _) => 0,
            (true, true, _) | (true, false, None) => timeout,
            (true, false, Some(deadline)) => remaining_milliseconds(deadline),
        };
        first = false;
        let mut host_fds = poll_fds.clone();
        if let Some(waiter) = &waiter {
            host_fds.push(libc::pollfd {
                fd: waiter.fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: poll sees only initialized host-owned storage.
        let ready = unsafe {
            libc::poll(
                host_fds.as_mut_ptr(),
                host_fds.len() as libc::nfds_t,
                host_timeout,
            )
        };
        let error = std::io::Error::last_os_error();
        drop(waiter);
        if ready < 0 {
            return io_error(error);
        }
        for (index, poll_fd) in poll_fds.iter_mut().enumerate() {
            poll_fd.revents = host_fds[index].revents;
            if invalid[index] {
                poll_fd.revents = libc::POLLNVAL;
            } else if let Some(mask) = &signalfds[index] {
                // Readable from this thread's queues (fs/signalfd.c,
                // signalfd_poll), never from the keeper alone, which another
                // thread's read may already have emptied.
                poll_fd.revents = if signalfd_readable(state, **mask) {
                    libc::POLLIN & guest_events[index]
                } else {
                    0
                };
            }
        }
        let ready_count = poll_fds
            .iter()
            .filter(|poll_fd| poll_fd.revents != 0)
            .count() as libc::c_int;
        // A wake for a signal that another thread took, or that an ignored
        // disposition discarded, waits again for the time left.
        if ready_count == 0
            && waits
            && polls_signalfds
            && deadline.is_none_or(|deadline| Instant::now() < deadline)
        {
            continue;
        }
        break ready_count;
    };
    for (index, poll_fd) in poll_fds.iter_mut().enumerate() {
        poll_fd.fd = guest_fds[index];
        poll_fd.events = guest_events[index];
    }
    // Linux writes only revents, one field at a time in array order. The
    // caller may change fd/events while a host-owned wait is blocked, and a
    // later output fault must retain earlier successful field stores.
    for (index, poll_fd) in poll_fds.iter().enumerate() {
        let offset = index * std::mem::size_of::<libc::pollfd>()
            + std::mem::offset_of!(libc::pollfd, revents);
        let Some(address) = args[0].checked_add(offset as u64) else {
            return negative_errno(libc::EFAULT);
        };
        if memory.put_user_i16(address, poll_fd.revents).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    i64::from(ready_count)
}

/// The milliseconds from now until `deadline`, rounded up, for a host poll.
fn remaining_milliseconds(deadline: Instant) -> libc::c_int {
    let left = deadline.saturating_duration_since(Instant::now());
    left.as_nanos()
        .div_ceil(1_000_000)
        .min(libc::c_int::MAX as u128) as libc::c_int
}

/// This thread's registration as a signalfd waiter for one host poll
/// ([`SignalFdWaiter`]). Dropping it ends the registration.
struct SignalFdWait<'a> {
    state: &'a LoadedStaticElf,
    waiter: SignalFdWaiter,
}

impl<'a> SignalFdWait<'a> {
    /// Registers this thread as waiting for a signal in `mask`, unless one is
    /// already pending for it or its process. Both are checked under the
    /// signal transaction and the thread's own lock, the lock a sender holds
    /// while it queues a private signal and wakes the waiter, so no signal
    /// queued after the check is missed. The transaction also keeps the
    /// keepers' shared readiness consistent with the queues at the check.
    fn register(state: &'a LoadedStaticElf, mask: KernelSigset) -> std::io::Result<Option<Self>> {
        let waiter = SignalFdWaiter::new(mask)?;
        let transaction = state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let process = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut thread = state.thread_signals.lock();
        if thread
            .pending
            .any_matching(mask, &process.pending_generations)
            || shared_queue_covers(&process, mask)
        {
            return Ok(None);
        }
        thread.signalfd_waiter = Some(waiter.clone());
        Ok(Some(Self { state, waiter }))
    }

    fn fd(&self) -> RawFd {
        self.waiter.file().as_raw_fd()
    }
}

impl Drop for SignalFdWait<'_> {
    fn drop(&mut self) {
        self.state.thread_signals.lock().signalfd_waiter = None;
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-92): Review deterministic event-loop and AF_UNIX syscall boundaries.
pub(super) fn epoll_create1(state: &mut LoadedStaticElf, raw_flags: u64) -> i64 {
    let flags = raw_flags as libc::c_int;
    if flags & !libc::EPOLL_CLOEXEC != 0 {
        return negative_errno(libc::EINVAL);
    }
    // Keep the supervisor descriptor private even when the guest did not ask
    // for close-on-exec; guest descriptor flags are modeled separately.
    let host_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: epoll_create1 returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    let fd = insert_file_with_flags(state, file, flags & libc::EPOLL_CLOEXEC != 0, None);
    if fd >= 0 {
        let identity = Arc::new(());
        {
            let mut domain = state
                .epoll_domain
                .lock()
                .expect("KVM epoll provenance lock poisoned");
            domain
                .proofs
                .retain(|_, proof| proof.owner.strong_count() != 0);
            domain.proofs.insert(
                epoll_identity_key(&identity),
                EpollProof {
                    owner: Arc::downgrade(&identity),
                    table: Arc::downgrade(&state.poll_table_id),
                    unsafe_history: false,
                    registrations: Default::default(),
                },
            );
        }
        install_native_poll_description(state, fd as i32, NativePollDescription::Epoll(identity));
    }
    fd
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn epoll_ctl(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(epoll_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Some(target_fd) = host_fd(state, args[2] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let operation = args[1] as libc::c_int;
    let mut event = if operation == libc::EPOLL_CTL_DEL {
        libc::epoll_event { events: 0, u64: 0 }
    } else {
        match read_guest_struct::<libc::epoll_event>(&ProviderMemory(memory), args[3]) {
            Ok(event) => event,
            Err(error) => return error,
        }
    };
    if matches!(operation, libc::EPOLL_CTL_ADD | libc::EPOLL_CTL_MOD)
        && signalfd_mask(state, args[2] as libc::c_int).is_some()
    {
        // Otherwise a blocking ppoll of this epoll descriptor could wait on
        // virtual signal readiness without carrying signalfd metadata itself.
        return negative_errno(libc::ENOSYS);
    }
    // Complete guest copies and signal/capture classification before taking
    // the leaf domain lock. Existing ctl outcomes remain native; unsafe
    // histories only remove admission to the newly supported syscall 441.
    let epoll_identity = match native_poll_description(state, args[0] as i32) {
        Some(NativePollDescription::Epoll(identity)) => Some(identity),
        _ => None,
    };
    let target_binding = state.native_poll_fds.get(&(args[2] as i32)).cloned();
    let captured = output_alias(state, args[2] as i32).is_some();
    let mut domain = state
        .epoll_domain
        .lock()
        .expect("KVM epoll provenance lock poisoned");
    let proof = epoll_identity
        .as_ref()
        .and_then(|identity| domain.proofs.get_mut(&epoll_identity_key(identity)));
    let target_eventfd = target_binding
        .as_ref()
        .and_then(|binding| match &binding.description {
            NativePollDescription::EventFd(identity)
                if binding.live.load(Ordering::SeqCst)
                    && !identity.escaped.load(Ordering::SeqCst)
                    && !captured =>
            {
                Some(identity.clone())
            }
            _ => None,
        });
    let guest_target = args[2] as i32;
    let mut proof = proof;
    if let Some(proof) = proof.as_mut()
        && matches!(
            operation,
            libc::EPOLL_CTL_ADD | libc::EPOLL_CTL_MOD | libc::EPOLL_CTL_DEL
        )
    {
        let same_key = proof
            .registrations
            .get(&guest_target)
            .is_none_or(|registered| {
                target_binding.as_ref().is_some_and(|binding| {
                    registered.binding.ptr_eq(&Arc::downgrade(binding))
                        && registered.host_key == target_fd
                })
            });
        if !proof.admitted(state) || target_eventfd.is_none() || !same_key {
            proof.unsafe_history = true;
        }
    }
    // SAFETY: both descriptors were translated from live snapshot Files;
    // event is initialized and Linux validates the requested operation.
    let result =
        zero_or_errno(unsafe { libc::epoll_ctl(epoll_fd, operation, target_fd, &mut event) });
    if result == 0
        && let Some(proof) = proof
        && !proof.unsafe_history
    {
        match operation {
            libc::EPOLL_CTL_ADD => {
                let registration = EpollRegistration {
                    binding: Arc::downgrade(target_binding.as_ref().unwrap()),
                    eventfd: target_eventfd.unwrap(),
                    host_key: target_fd,
                };
                if proof
                    .registrations
                    .insert(guest_target, registration)
                    .is_some()
                {
                    proof.unsafe_history = true;
                }
            }
            libc::EPOLL_CTL_DEL => {
                if proof.registrations.remove(&guest_target).is_none() {
                    proof.unsafe_history = true;
                }
            }
            libc::EPOLL_CTL_MOD => {
                if !proof.registrations.contains_key(&guest_target) {
                    proof.unsafe_history = true;
                }
            }
            _ => proof.unsafe_history = true,
        }
    }
    result
}

fn epoll_pwait2_bound(
    domain: &EpollDomain,
    state: &LoadedStaticElf,
    binding: &NativePollBinding,
) -> Option<usize> {
    if !binding.live.load(Ordering::SeqCst) {
        return None;
    }
    let NativePollDescription::Epoll(identity) = &binding.description else {
        return None;
    };
    let proof = domain.proofs.get(&epoll_identity_key(identity))?;
    proof.admitted(state).then_some(proof.registrations.len())
}

// Linux 6.1/6.6 validate count/range before fdget; 6.18 validates the fd
// first. Delegate only an absent guest fd through a guaranteed-invalid host
// descriptor, preserving that host ABI without touching any epoll object.
// do_epoll_wait primary sources:
// https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/fs/eventpoll.c#L2221
// https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/fs/eventpoll.c#L2451
pub(super) fn epoll_pwait2_missing_fd_with_host(
    output: u64,
    raw_count: u64,
    invoke_host: impl FnOnce(
        libc::c_int,
        usize,
        libc::c_int,
        &libc::timespec,
        usize,
        usize,
    ) -> std::io::Result<libc::c_long>,
) -> i64 {
    let count = raw_count as libc::c_int;
    // Even INT_MAX * 12 fits in x86-64 usize. Preserve oversized counts for
    // the kernel's count check; never shorten the ORIGINAL guest array here.
    let valid_range = count <= 0
        || (count as usize)
            .checked_mul(std::mem::size_of::<libc::epoll_event>())
            .is_some_and(|length| validate_guest_iovec_address(output, length).is_ok());
    let host_output = if valid_range { 0 } else { usize::MAX };
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Neither representative can be dereferenced: fd=-1 fails before ep_poll
    // on both orders. NULL mask and zero timeout cannot install a host mask,
    // wait, consume events, or write guest/output memory.
    match invoke_host(-1, host_output, count, &zero, 0, 0) {
        Err(error) => io_error(error),
        // A nonnegative result cannot describe Linux's invalid-fd path. Refuse
        // an unsupported host result rather than fabricate readiness success.
        Ok(_) => negative_errno(libc::ENOSYS),
    }
}

fn epoll_pwait2_missing_fd(output: u64, raw_count: u64) -> i64 {
    epoll_pwait2_missing_fd_with_host(
        output,
        raw_count,
        |fd, host_output, count, timeout, mask, mask_size| {
            // SAFETY: fd is -1, so no epoll or output memory can be accessed;
            // timeout is initialized input and the signal mask is NULL.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_epoll_pwait2,
                    fd,
                    host_output,
                    count,
                    timeout,
                    mask,
                    mask_size,
                )
            };
            if result < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(result)
            }
        },
    )
}

/// Immediate, unmasked readiness for a proven native eventfd interest set.
/// Unknown/imported/nested/escaped descriptions and changed registration
/// bindings remain unsupported; this is not general epoll virtualization.
pub(super) fn epoll_pwait2<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    // Linux fs/eventpoll.c copies/validates timeout before mask and descriptors.
    let zero_timeout = if args[3] == 0 {
        false
    } else {
        let timeout = match read_guest_struct::<libc::timespec>(memory, args[3]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000_000).contains(&timeout.tv_nsec) {
            return negative_errno(libc::EINVAL);
        }
        timeout.tv_sec == 0 && timeout.tv_nsec == 0
    };
    if args[4] != 0 {
        if args[5] != KERNEL_SIGSET_SIZE as u64 {
            return negative_errno(libc::EINVAL);
        }
        let mut mask = [0; KERNEL_SIGSET_SIZE];
        if memory.read_exact(args[4], &mut mask).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    if !zero_timeout || args[4] != 0 {
        return negative_errno(libc::ENOSYS);
    }
    let guest_fd = args[0] as libc::c_int;
    let Some(fd) = host_fd(state, guest_fd) else {
        return epoll_pwait2_missing_fd(args[1], args[2]);
    };
    let count = args[2] as libc::c_int;
    let event_size = std::mem::size_of::<libc::epoll_event>();
    if count <= 0 || count as usize > i32::MAX as usize / event_size {
        return negative_errno(libc::EINVAL);
    }
    // Preserve access_ok on the FULL original request before bounding the
    // alias by proven membership. This is numeric-only, not a mapping probe.
    if let Err(error) = validate_guest_iovec_address(args[1], count as usize * event_size) {
        return error;
    }
    let Some(binding) = state.native_poll_fds.get(&guest_fd) else {
        return negative_errno(libc::ENOSYS);
    };
    if matches!(binding.description, NativePollDescription::EventFd(_)) {
        return negative_errno(libc::EINVAL);
    }
    let capacity = {
        let domain = state
            .epoll_domain
            .lock()
            .expect("KVM epoll provenance lock poisoned");
        let Some(bound) = epoll_pwait2_bound(&domain, state, binding) else {
            return negative_errno(libc::ENOSYS);
        };
        (count as usize).min(bound).max(1)
    };
    // Construction and finalization can notify reentrant wakers. Neither may
    // run under the provenance domain or an outer file-table transaction.
    let alias = match memory.lend_mut(args[1], capacity * event_size) {
        Ok(alias) => alias,
        Err(_) => return negative_errno(libc::EFAULT),
    };
    let result = {
        let domain = state
            .epoll_domain
            .lock()
            .expect("KVM epoll provenance lock poisoned");
        match epoll_pwait2_bound(&domain, state, binding) {
            Some(bound) if (count as usize).min(bound).max(1) <= capacity => {
                let host_count = (count as usize).min(bound).max(1);
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                // Linux ep_send_events writes each mask/data field before
                // committing that event's one-shot state. Direct alias copyout
                // preserves partial effects and leaves a faulting event queued.
                // A zero timeout returns before the ordinary pending-signal
                // check; do not dequeue guest signals or install a host mask.
                // SAFETY: alias owns a protected kernel operand of this size;
                // snapshot fd is live and timeout is initialized/read-only.
                let ready = unsafe {
                    libc::syscall(
                        libc::SYS_epoll_pwait2,
                        fd,
                        alias.host_pointer(),
                        host_count as libc::c_int,
                        &timeout,
                        std::ptr::null::<libc::sigset_t>(),
                        0usize,
                    )
                };
                if ready < 0 {
                    io_error(std::io::Error::last_os_error())
                } else {
                    ready as i64
                }
            }
            _ => negative_errno(libc::ENOSYS),
        }
    };
    // The domain guard drops before alias cleanup and notification, including
    // on unwind. A cleanup failure remains a sticky backend failure.
    if alias.finish().is_err() {
        return negative_errno(libc::EFAULT);
    }
    result
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn epoll_wait(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    pwait: bool,
) -> i64 {
    if pwait && args[4] != 0 {
        if args[5] != KERNEL_SIGSET_SIZE as u64 {
            return negative_errno(libc::EINVAL);
        }
        let mut signal_mask = [0; KERNEL_SIGSET_SIZE];
        if memory.user().read(args[4], &mut signal_mask).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    let Some(epoll_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(max_events) = libc::c_int::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if max_events <= 0 {
        return negative_errno(libc::EINVAL);
    }
    let Ok(count) = usize::try_from(max_events) else {
        return negative_errno(libc::EINVAL);
    };
    let Some(byte_length) = count.checked_mul(std::mem::size_of::<libc::epoll_event>()) else {
        return negative_errno(libc::EINVAL);
    };
    if byte_length > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; count];
    // A real-time host timeout is not a deterministic guest clock. Readiness
    // for already-available descriptor events is preserved with a zero timeout.
    // Guest signal masks are modeled in guest state and must not alter the
    // supervisor thread. With a zero timeout there is no guest blocking window.
    // SAFETY: the event array is writable for max_events entries.
    let ready = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), max_events, 0) };
    if ready < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let ready = ready as usize;
    if ready == 0 {
        return 0;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            events.as_ptr().cast::<u8>(),
            ready * std::mem::size_of::<libc::epoll_event>(),
        )
    };
    match memory.user().write(args[1], bytes) {
        Ok(()) => ready as i64,
        Err(_) => negative_errno(libc::EFAULT),
    }
}
