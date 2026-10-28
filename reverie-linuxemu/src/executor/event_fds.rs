/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! eventfd, signalfd and timerfd (gVisor: pkg/sentry/fsimpl/eventfd, fsimpl/signalfd, fsimpl/timerfd).
//!
//! Debt: this backend keeps the guest's pending signal queues itself, because
//! its guest threads are not host tasks that the host kernel queues signals
//! for, and its signalfd answers from them as Linux would: a probe reads the
//! polling thread's own queue and its process's (`signalfd_readable`), and a
//! host wait is woken by a covered signal (`SignalFdWaiter`). That is Linux's
//! signal semantics carried in a backend. It goes when a Tool can own the
//! queues and decide readiness from them; do not extend it.

use super::*;

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
pub(super) fn eventfd2(state: &mut LoadedStaticElf, initial: u64, raw_flags: u64) -> i64 {
    let flags = raw_flags as libc::c_int;
    let allowed = libc::EFD_CLOEXEC | libc::EFD_NONBLOCK | libc::EFD_SEMAPHORE;
    if flags & !allowed != 0 || initial > u64::from(u32::MAX) {
        return negative_errno(libc::EINVAL);
    }
    let host_fd = unsafe { libc::eventfd(initial as libc::c_uint, flags | libc::EFD_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: eventfd returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    let fd = insert_file_with_flags(state, file, flags & libc::EFD_CLOEXEC != 0, None);
    if fd >= 0 {
        install_native_poll_description(
            state,
            fd as i32,
            NativePollDescription::EventFd(Arc::new(NativeEventFd::default())),
        );
    }
    fd
}

pub(super) fn set_signalfd_ready(file: &std::fs::File, ready: bool) -> Result<(), i64> {
    let mut poll_fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll_fd points to one initialized descriptor and timeout zero
    // never blocks the supervisor.
    let poll_result = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if poll_result < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    if poll_result > 0 && poll_fd.revents & libc::POLLIN != 0 {
        let mut counter = 0u64;
        // SAFETY: counter is writable and eventfd reads exactly one u64.
        if unsafe {
            libc::read(
                file.as_raw_fd(),
                std::ptr::from_mut(&mut counter).cast::<libc::c_void>(),
                std::mem::size_of::<u64>(),
            )
        } < 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
    }
    if ready {
        let counter = 1u64;
        // SAFETY: counter is readable and eventfd writes exactly one u64.
        if unsafe {
            libc::write(
                file.as_raw_fd(),
                std::ptr::from_ref(&counter).cast::<libc::c_void>(),
                std::mem::size_of::<u64>(),
            )
        } < 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

// TODO-HUMAN-REVIEW(PR-235): Review virtual signalfd creation and mask updates.
pub(super) fn signalfd(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
    raw_flags: u64,
) -> i64 {
    let _retirement = state.file_retirement.hold();
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    if args[2] != KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    let mut mask = match read_guest_bytes::<KERNEL_SIGSET_SIZE>(&ProviderMemory(memory), args[1]) {
        Ok(mask) => KernelSigset::from_bytes(mask),
        Err(error) => return error,
    };
    mask.clear_unmaskable();
    let Ok(flags) = libc::c_int::try_from(raw_flags) else {
        return negative_errno(libc::EINVAL);
    };
    let allowed = libc::SFD_CLOEXEC | libc::SFD_NONBLOCK;
    if flags & !allowed != 0 {
        return negative_errno(libc::EINVAL);
    }

    let requested_fd = args[0] as libc::c_int;

    let update_aliases = if requested_fd != -1 {
        if flags != 0 {
            return negative_errno(libc::EINVAL);
        }
        let process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(description) = process_signals.signalfd_masks.get(&requested_fd).cloned() else {
            return negative_errno(libc::EINVAL);
        };
        if !state.files.contains_key(&requested_fd) {
            return negative_errno(libc::EINVAL);
        }
        // A signalfd mask belongs to the open file description. Descriptor
        // aliases share this exact Arc, while independently created signalfds
        // receive distinct Arcs even when their masks happen to be equal.
        Some(
            process_signals
                .signalfd_masks
                .iter()
                .filter_map(|(&fd, candidate)| Arc::ptr_eq(candidate, &description).then_some(fd))
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };

    if let Some(alias_fds) = update_aliases {
        let ready = {
            let mut process_signals = state
                .process_signals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let description = Arc::new(mask);
            for &fd in &alias_fds {
                process_signals
                    .signalfd_masks
                    .insert(fd, description.clone());
            }
            shared_queue_covers(&process_signals, mask)
        };
        for fd in alias_fds {
            let file = state
                .files
                .get(&fd)
                .expect("signalfd alias disappeared during mask update");
            if let Err(error) = set_signalfd_ready(file, ready) {
                return error;
            }
        }
        return i64::from(requested_fd);
    }

    let (guest_fd, carrier) = if requested_fd == -1 {
        // The host eventfd is nonblocking even for a blocking signalfd: the
        // guest's mode lives on the keeper, and a read that would wait is
        // refused rather than left to block a host thread.
        // SAFETY: eventfd validates its bounded flags and returns a new owned fd.
        let host_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if host_fd < 0 {
            return io_error(std::io::Error::last_os_error());
        }
        // SAFETY: eventfd returned a new owned descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
        // Stage the only extra host descriptor before either guest-table or
        // signal-state insertion. Failure leaves no guest-visible descriptor.
        let carrier = match crate::signal::SignalFdCarrier::pin_eventfd(&file) {
            Ok(carrier) => carrier,
            Err(error) => {
                state.file_retirement.retire([file]);
                return io_error(error);
            }
        };
        carrier.set_guest_blocking(flags & libc::SFD_NONBLOCK == 0);
        let guest_fd = insert_file_with_flags(state, file, flags & libc::SFD_CLOEXEC != 0, None);
        if guest_fd < 0 {
            return guest_fd;
        }
        (guest_fd as libc::c_int, carrier)
    } else {
        unreachable!("existing signalfd updates return above")
    };

    let ready = {
        let mut process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        process_signals.signalfd_carriers.insert(guest_fd, carrier);
        process_signals
            .signalfd_masks
            .insert(guest_fd, Arc::new(mask));
        shared_queue_covers(&process_signals, mask)
    };
    let file = state
        .files
        .get(&guest_fd)
        .expect("virtual signalfd disappeared after insertion");
    match set_signalfd_ready(file, ready) {
        Ok(()) => i64::from(guest_fd),
        Err(error) => error,
    }
}

pub(super) fn queue_signal_event(
    state: &mut LoadedStaticElf,
    event: reverie::SignalEvent,
    process_directed: bool,
) -> Result<(), i64> {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    queue_signal_event_locked(state, event, process_directed)
}

pub(super) fn queue_signal_event_locked(
    state: &mut LoadedStaticElf,
    event: reverie::SignalEvent,
    process_directed: bool,
) -> Result<(), i64> {
    let signal = event.signal();
    let matching_fds = {
        // Queue insertion and disposition-driven generation changes share this
        // lock. A sibling therefore cannot invalidate a private entry between
        // reading its generation and publishing it.
        let mut process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = process_signals.pending_generation(signal);
        let inserted = if process_directed {
            process_signals.shared_pending.enqueue(event, generation)
        } else {
            state
                .thread_signals
                .lock()
                .pending
                .enqueue(event, generation)
        }
        .map_err(|errno| negative_errno(errno.into_raw()))?;
        if !inserted {
            return Ok(());
        }

        // A keeper shows only the shared queue. Only the receiving thread
        // queues a private event here, so it is not waiting in a poll, and its
        // next probe reads its own queue (`signalfd_readable`).
        if process_directed {
            process_signals
                .signalfd_masks
                .iter()
                .filter_map(|(&fd, mask)| mask.contains(signal).then_some(fd))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    };
    for fd in matching_fds {
        let Some(file) = state.files.get(&fd) else {
            continue;
        };
        set_signalfd_ready(file, true)?;
    }
    Ok(())
}

pub(super) const SIGNALFD_RECORD_SIZE: usize = std::mem::size_of::<libc::signalfd_siginfo>();
pub(super) struct GuestWriteCursor<'a> {
    pub(super) vectors: &'a [GuestIoVec],
    pub(super) index: usize,
    pub(super) offset: usize,
}

impl GuestWriteCursor<'_> {
    fn write(&mut self, memory: &mut GuestMemory, mut bytes: &[u8]) -> Result<(), ()> {
        while !bytes.is_empty() {
            while self.index < self.vectors.len() && self.offset == self.vectors[self.index].length
            {
                self.index += 1;
                self.offset = 0;
            }
            let vector = self.vectors.get(self.index).ok_or(())?;
            let count = bytes.len().min(vector.length - self.offset);
            let address = vector.base + self.offset as u64;
            let writable = memory
                .user()
                .user_writable_prefix(address, count)
                .map_err(|_| ())?;
            if writable != 0 {
                memory
                    .user()
                    .write(address, &bytes[..writable])
                    .map_err(|_| ())?;
                self.offset += writable;
                bytes = &bytes[writable..];
            }
            if writable < count {
                return Err(());
            }
        }
        Ok(())
    }
}

pub(super) fn encode_signalfd_siginfo(event: reverie::SignalEvent) -> [u8; SIGNALFD_RECORD_SIZE] {
    // SAFETY: signalfd_siginfo is a plain Linux ABI structure and zero is a
    // valid value for every field not populated by this process-local model.
    let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
    let raw = event.siginfo();
    info.ssi_signo = event.signal() as u32;
    info.ssi_errno = i32::from_ne_bytes(raw[4..8].try_into().expect("siginfo errno"));
    info.ssi_code = i32::from_ne_bytes(raw[8..12].try_into().expect("siginfo code"));
    if info.ssi_code == libc::SI_TIMER {
        info.ssi_tid = u32::from_ne_bytes(raw[16..20].try_into().expect("siginfo timer id"));
        info.ssi_overrun =
            u32::from_ne_bytes(raw[20..24].try_into().expect("siginfo timer overrun"));
        let value = u64::from_ne_bytes(raw[24..32].try_into().expect("siginfo timer value"));
        info.ssi_ptr = value;
        info.ssi_int = value as i32;
    } else if info.ssi_signo == libc::SIGCHLD as u32
        && matches!(
            info.ssi_code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        )
    {
        info.ssi_pid = u32::from_ne_bytes(raw[16..20].try_into().expect("siginfo child pid"));
        info.ssi_uid = u32::from_ne_bytes(raw[20..24].try_into().expect("siginfo child uid"));
        info.ssi_status = i32::from_ne_bytes(raw[24..28].try_into().expect("siginfo child status"));
        info.ssi_utime = u64::from_ne_bytes(raw[32..40].try_into().expect("siginfo child utime"));
        info.ssi_stime = u64::from_ne_bytes(raw[40..48].try_into().expect("siginfo child stime"));
    } else if info.ssi_code < 0 && !matches!(info.ssi_code, libc::SI_TKILL | libc::SI_SIGIO) {
        // Linux's SIL_RT layout, which sigqueue(3) and rt_sigqueueinfo use:
        // the sender's pid and uid, then the sigval (signalfd_copyinfo).
        info.ssi_pid = u32::from_ne_bytes(raw[16..20].try_into().expect("siginfo pid"));
        info.ssi_uid = u32::from_ne_bytes(raw[20..24].try_into().expect("siginfo uid"));
        let value = u64::from_ne_bytes(raw[24..32].try_into().expect("siginfo value"));
        info.ssi_ptr = value;
        info.ssi_int = value as i32;
    } else {
        // SI_USER, SI_TKILL, and the accepted SIGALRM/SI_KERNEL producer use
        // the kill-style pid/uid arm of siginfo_t.
        info.ssi_pid = u32::from_ne_bytes(raw[16..20].try_into().expect("siginfo pid"));
        info.ssi_uid = u32::from_ne_bytes(raw[20..24].try_into().expect("siginfo uid"));
    }
    let mut bytes = [0; SIGNALFD_RECORD_SIZE];
    // SAFETY: both objects are live for exactly the size of signalfd_siginfo.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(&info).cast::<u8>(),
            bytes.as_mut_ptr(),
            SIGNALFD_RECORD_SIZE,
        );
    }
    bytes
}

/// Whether the process's shared queue holds a signal `mask` covers: what a
/// signalfd's eventfd keeper shows. One keeper serves every thread, so it
/// cannot show a thread's own queue as well.
pub(super) fn shared_queue_covers(
    process: &crate::signal::ProcessSignalState,
    mask: KernelSigset,
) -> bool {
    process
        .shared_pending
        .any_matching(mask, &process.pending_generations)
}

/// Whether a signalfd for `mask` is readable by the calling thread: a covered
/// signal is pending for it alone or for its whole process. Linux's
/// signalfd_poll checks exactly these two queues of the polling task
/// (fs/signalfd.c), and a read takes from them in that order.
pub(super) fn signalfd_readable(state: &LoadedStaticElf, mask: KernelSigset) -> bool {
    let process = state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state
        .thread_signals
        .lock()
        .pending
        .any_matching(mask, &process.pending_generations)
        || shared_queue_covers(&process, mask)
}

pub(super) fn refresh_all_signalfd_readiness_locked(state: &LoadedStaticElf) -> Result<(), i64> {
    refresh_signalfd_readiness_for_signal_locked(state, None)
}

pub(super) fn refresh_signalfd_readiness_for_signal_locked(
    state: &LoadedStaticElf,
    signal: Option<i32>,
) -> Result<(), i64> {
    refresh_signalfd_readiness_from_files_locked(state, signal, &state.files)
}

fn refresh_signalfd_readiness_from_files_locked(
    state: &LoadedStaticElf,
    signal: Option<i32>,
    files: &std::collections::BTreeMap<i32, std::fs::File>,
) -> Result<(), i64> {
    let readiness = {
        let process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        process_signals
            .signalfd_masks
            .iter()
            .filter(|(_, mask)| signal.is_none_or(|signal| mask.contains(signal)))
            .map(|(&fd, mask)| (fd, shared_queue_covers(&process_signals, **mask)))
            .collect::<Vec<_>>()
    };
    for (fd, ready) in readiness {
        let file = files.get(&fd).ok_or_else(|| negative_errno(libc::EBADF))?;
        set_signalfd_ready(file, ready)?;
    }
    Ok(())
}

/// Requires the process signal transaction. Only dedicated eventfd keepers
/// cross this boundary, so no authoritative file-table acquisition or ordinary
/// last-owner descriptor destruction can block a scheduler-selected return.
pub(super) fn refresh_signalfd_readiness_from_carriers_locked(
    state: &LoadedStaticElf,
    signal: Option<i32>,
) -> Result<(), i64> {
    let readiness = {
        let process = state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        process
            .signalfd_masks
            .iter()
            .filter(|(_, mask)| signal.is_none_or(|signal| mask.contains(signal)))
            .map(|(fd, mask)| {
                let carrier = process
                    .signalfd_carriers
                    .get(fd)
                    .cloned()
                    .ok_or_else(|| negative_errno(libc::EBADF))?;
                Ok((carrier, shared_queue_covers(&process, **mask)))
            })
            .collect::<Result<Vec<_>, i64>>()?
    };
    for (carrier, ready) in readiness {
        set_signalfd_ready(carrier.file(), ready)?;
    }
    Ok(())
}

/// Each real consumer selects under the same lifecycle -> process -> thread locks.
/// Reserve the journal slot and sequence before mutating either pending set.
pub(super) enum SignalSelection {
    Delivery,
    SignalFd(KernelSigset),
    TimedWait(KernelSigset),
}

#[cfg(test)]
pub(super) fn take_signal_event(
    state: &mut LoadedStaticElf,
    selection: SignalSelection,
) -> Result<Option<PendingSignal>, reverie::syscalls::Errno> {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    take_signal_event_locked(state, selection)
}

pub(super) fn take_signal_event_locked(
    state: &mut LoadedStaticElf,
    selection: SignalSelection,
) -> Result<Option<PendingSignal>, reverie::syscalls::Errno> {
    use reverie::syscalls::Errno;
    if let Some(errno) = state.signal_dequeue_failure {
        return Err(errno);
    }
    let lifecycle = state
        .task_lifecycle
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut process = state
        .process_signals
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut thread = state.thread_signals.lock();
    let generations = process.pending_generations;
    let blocked = thread.blocked;
    let eligible = |pending: &crate::signal::StandardPendingSignals| match selection {
        SignalSelection::Delivery => pending.any_eligible(blocked, &generations),
        SignalSelection::SignalFd(mask) | SignalSelection::TimedWait(mask) => {
            pending.any_matching(mask, &generations)
        }
    };
    if !eligible(&thread.pending) && !eligible(&process.shared_pending) {
        return Ok(None);
    }
    let identity = if process.dequeue_enabled {
        let admission = (|| {
            let admitted = thread.dequeue_identity.ok_or(Errno::ESRCH)?;
            let task = lifecycle.get(state.tid).ok_or(Errno::ESRCH)?;
            if task.tgid != state.pid
                || admitted.tid.as_raw() != state.tid
                || admitted.process.tgid.as_raw() != state.pid
                || task.generation != admitted.task_generation
                || task.process_generation != admitted.process.generation
            {
                return Err(Errno::ESRCH);
            }
            if process.dequeue_journal.len() == 64 {
                return Err(Errno::EOVERFLOW);
            }
            process
                .dequeue_sequence
                .checked_add(1)
                .ok_or(Errno::EOVERFLOW)?;
            process
                .dequeue_journal
                .try_reserve(1)
                .map_err(|_| Errno::ENOMEM)?;
            Ok(admitted)
        })();
        match admission {
            Ok(admitted) => Some(admitted),
            Err(errno) => {
                // Raw syscall helpers have an i64 interface. Keep the actual
                // internal refusal separately: both injected and unsubscribed
                // execution must flush this typed failure before resuming any
                // Tool or guest with the intermediate raw result. In particular,
                // a partial signalfd read cannot hide a later bookkeeping fault.
                state.signal_dequeue_failure = Some(errno);
                return Err(errno);
            }
        }
    } else {
        None
    };
    let take = |pending: &mut crate::signal::StandardPendingSignals| match selection {
        SignalSelection::Delivery => pending.take_eligible(blocked, &generations),
        SignalSelection::SignalFd(mask) => pending.take_signalfd_matching(mask, &generations),
        SignalSelection::TimedWait(mask) => pending.take_matching(mask, &generations),
    };
    let pending = if let Some(event) = take(&mut thread.pending) {
        PendingSignal {
            event,
            domain: PendingSignalDomain::Thread,
        }
    } else if let Some(event) = take(&mut process.shared_pending) {
        PendingSignal {
            event,
            domain: PendingSignalDomain::Process,
        }
    } else {
        return Ok(None);
    };
    if let Some(identity) = identity {
        process.dequeue_sequence += 1;
        let sequence = process.dequeue_sequence;
        process
            .dequeue_journal
            .push_back(crate::signal::OwnedSignalDequeue {
                owner: identity,
                wake: thread.dequeue_wake.clone(),
                effect: reverie::SignalDequeue {
                    process: identity.process,
                    sequence,
                    consumer: match selection {
                        SignalSelection::Delivery => reverie::SignalConsumer::ReturnToUser,
                        SignalSelection::SignalFd(_) => reverie::SignalConsumer::SignalFd,
                        SignalSelection::TimedWait(_) => reverie::SignalConsumer::SignalTimedWait,
                    },
                    domain: match pending.domain {
                        PendingSignalDomain::Thread => reverie::PendingDomain::Thread,
                        PendingSignalDomain::Process => reverie::PendingDomain::Process,
                    },
                    event: pending.event,
                },
            });
    }
    Ok(Some(pending))
}

fn take_signalfd_event(
    state: &mut LoadedStaticElf,
    mask: KernelSigset,
) -> Result<Option<reverie::SignalEvent>, i64> {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    let pending = take_signal_event_locked(state, SignalSelection::SignalFd(mask))
        .map_err(|errno| -(i64::from(errno.into_raw())))?;
    refresh_all_signalfd_readiness_locked(state)?;
    Ok(pending.map(|pending| pending.event))
}

pub(super) fn signalfd_read_stream(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    fd: libc::c_int,
    vectors: &[GuestIoVec],
    vector_zero_semantics: bool,
    force_nonblocking: bool,
) -> Option<i64> {
    let mask = state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .signalfd_masks
        .get(&fd)
        .map(|mask| **mask)?;
    let file = state.files.get(&fd)?;
    if let Err(error) = ensure_read_capable(file).and_then(|()| ensure_readable(file)) {
        return Some(error);
    }
    let blocking = !force_nonblocking && signalfd_carrier(state, fd)?.guest_blocking();
    let total = vectors
        .iter()
        .try_fold(0usize, |total, vector| total.checked_add(vector.length));
    let Some(total) = total else {
        return Some(negative_errno(libc::EINVAL));
    };
    if total == 0 && vector_zero_semantics {
        return Some(0);
    }
    if total < SIGNALFD_RECORD_SIZE {
        return Some(negative_errno(libc::EINVAL));
    }
    let capacity = total / SIGNALFD_RECORD_SIZE;
    let mut cursor = GuestWriteCursor {
        vectors,
        index: 0,
        offset: 0,
    };
    let mut completed = 0usize;
    loop {
        let event = match take_signalfd_event(state, mask) {
            Ok(event) => event,
            Err(error) => {
                return Some(if completed == 0 {
                    error
                } else {
                    (completed * SIGNALFD_RECORD_SIZE) as i64
                });
            }
        };
        let Some(event) = event else {
            if completed != 0 {
                return Some((completed * SIGNALFD_RECORD_SIZE) as i64);
            }
            // A blocking read with nothing pending would wait for a signal.
            // A host wait would escape Detcore's scheduler and race the
            // readiness publication, and a scheduler-owned wait is not
            // modeled, so that one case is refused.
            return Some(negative_errno(if blocking {
                libc::ENOSYS
            } else {
                libc::EAGAIN
            }));
        };
        let record = encode_signalfd_siginfo(event);
        if cursor.write(memory, &record).is_err() {
            return Some(if completed == 0 {
                negative_errno(libc::EFAULT)
            } else {
                (completed * SIGNALFD_RECORD_SIZE) as i64
            });
        }
        completed += 1;
        if completed == capacity {
            return Some((completed * SIGNALFD_RECORD_SIZE) as i64);
        }
    }
}

// TODO-HUMAN-REVIEW(PR-235): Review virtual signalfd aggregate dequeue semantics.
pub(super) fn signalfd_read(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    fd: libc::c_int,

    address: u64,
    length: usize,
) -> Option<i64> {
    signalfd_read_stream(
        memory,
        state,
        fd,
        &[GuestIoVec {
            base: address,
            length,
        }],
        false,
        false,
    )
}
// TODO-HUMAN-REVIEW(PR-235): Review host-backed KVM timerfd creation semantics.
pub(super) fn timerfd_create(
    state: &mut LoadedStaticElf,
    raw_clock_id: u64,
    raw_flags: u64,
) -> i64 {
    let Ok(clock_id) = libc::c_int::try_from(raw_clock_id) else {
        return negative_errno(libc::EINVAL);
    };
    let Ok(flags) = libc::c_int::try_from(raw_flags) else {
        return negative_errno(libc::EINVAL);
    };
    let allowed = libc::TFD_CLOEXEC | libc::TFD_NONBLOCK;
    if flags & !allowed != 0 {
        return negative_errno(libc::EINVAL);
    }

    // Keep the supervisor descriptor private even if the guest did not request
    // CLOEXEC; guest descriptor flags are modeled separately.
    let host_fd = unsafe { libc::timerfd_create(clock_id, flags | libc::TFD_CLOEXEC) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: timerfd_create returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, flags & libc::TFD_CLOEXEC != 0, None)
}

// TODO-HUMAN-REVIEW(PR-235): Review host-backed KVM timerfd control semantics.
pub(super) fn timerfd_settime(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(flags) = libc::c_int::try_from(args[1]) else {
        return negative_errno(libc::EINVAL);
    };
    let new_value = match read_guest_struct::<libc::itimerspec>(&ProviderMemory(memory), args[2]) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut old_value = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let old_value_ptr = if args[3] == 0 {
        std::ptr::null_mut()
    } else {
        &mut old_value
    };
    // SAFETY: host_fd is live, new_value is initialized, and old_value_ptr is
    // either null or points to writable local storage.
    if unsafe { libc::timerfd_settime(host_fd, flags, &new_value, old_value_ptr) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    if args[3] != 0 {
        return write_struct(&mut ProviderMemory(memory), args[3], &old_value);
    }
    0
}

// TODO-HUMAN-REVIEW(PR-235): Review host-backed KVM timerfd query semantics.
pub(super) fn timerfd_gettime(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let mut current = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    // SAFETY: host_fd is live and current points to writable local storage.
    if unsafe { libc::timerfd_gettime(host_fd, &mut current) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    write_struct(&mut ProviderMemory(memory), args[1], &current)
}
