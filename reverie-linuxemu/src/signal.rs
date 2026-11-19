/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Linux x86-64 signal state for the KVM backend.
//!
//! Frame construction and `rt_sigreturn` restore live in
//! `reverie_signal::frame`, shared by every backend; this module keeps
//! the pending-queue machine and re-exports the frame types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::SignalEvent;
use reverie::SignalTarget;
use reverie::syscalls::Errno;
pub use reverie_signal::frame::*;

/// The trap fields of a thread's signal frames: the number, error code and
/// fault address of the last CPU exception that raised a signal in the
/// thread. Linux keeps them in the task (`thread.trap_nr`,
/// `thread.error_code` and `thread.cr2`), sets them when a trap handler
/// raises its signal (`do_trap_no_signal` in arch/x86/kernel/traps.c,
/// `set_signal_archinfo` in arch/x86/mm/fault.c; only a page fault sets
/// `cr2`), and writes them into the `sigcontext` of every frame it builds
/// afterwards (`__unsafe_setup_sigcontext` in arch/x86/kernel/signal_64.c),
/// whatever signal the frame is for. Nothing clears them: fork and clone copy
/// them with the task (`arch_dup_task_struct`), and exec keeps them
/// (`flush_thread`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalTrapFields {
    /// `sigcontext.trapno`: the exception vector.
    pub trapno: u64,
    /// `sigcontext.err`: the exception's error code.
    pub error_code: u64,
    /// `sigcontext.cr2`: the address of the last page fault.
    pub cr2: u64,
}

const PENDING_SIGNAL_GENERATION_COUNT: usize = 65;
pub(crate) type PendingSignalGenerations = [u64; PENDING_SIGNAL_GENERATION_COUNT];

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "test-support"), derive(Eq, PartialEq))]
struct QueuedStandardSignal {
    event: SignalEvent,
    generation: u64,
}

/// One coalescing standard-signal pending domain.
#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "test-support"), derive(Eq, PartialEq))]
pub(crate) struct StandardPendingSignals(BTreeMap<i32, QueuedStandardSignal>);

impl StandardPendingSignals {
    /// Enqueues a standard signal once. The first siginfo is retained when a
    /// second instance coalesces, matching Linux's standard-signal rule.
    pub(crate) fn enqueue(&mut self, event: SignalEvent, generation: u64) -> Result<bool, Errno> {
        if event.signal() > 31 {
            return Err(Errno::ENOSYS);
        }
        match self.0.entry(event.signal()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(QueuedStandardSignal { event, generation });
                Ok(true)
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if entry.get().generation != generation =>
            {
                entry.insert(QueuedStandardSignal { event, generation });
                Ok(true)
            }
            std::collections::btree_map::Entry::Occupied(_) => Ok(false),
        }
    }

    pub(crate) fn remove(&mut self, signal: i32) -> Option<SignalEvent> {
        self.0.remove(&signal).map(|pending| pending.event)
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, signal: i32) -> bool {
        self.0.contains_key(&signal)
    }

    pub(crate) fn take_eligible(
        &mut self,
        blocked: KernelSigset,
        generations: &PendingSignalGenerations,
    ) -> Option<SignalEvent> {
        let signal = self.next_matching(generations, |signal| !blocked.contains(signal))?;
        self.remove(signal)
    }

    pub(crate) fn take_matching(
        &mut self,
        selected: KernelSigset,
        generations: &PendingSignalGenerations,
    ) -> Option<SignalEvent> {
        let signal = self.next_matching(generations, |signal| selected.contains(signal))?;
        self.remove(signal)
    }

    pub(crate) fn take_signalfd_matching(
        &mut self,
        selected: KernelSigset,
        generations: &PendingSignalGenerations,
    ) -> Option<SignalEvent> {
        let signal = self.next_matching(generations, |signal| selected.contains(signal))?;
        self.remove(signal)
    }

    /// Matches Linux next_signal(): synchronous-number priority first, then
    /// ascending signal number within each class. This ordering applies to
    /// ordinary delivery, sigtimedwait, and signalfd dequeue alike.
    fn next_matching(
        &self,
        generations: &PendingSignalGenerations,
        mut selected: impl FnMut(i32) -> bool,
    ) -> Option<i32> {
        const SYNCHRONOUS: [i32; 6] = [
            libc::SIGILL,
            libc::SIGTRAP,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGSEGV,
            libc::SIGSYS,
        ];
        let synchronous = SYNCHRONOUS
            .into_iter()
            .find(|signal| selected(*signal) && self.is_current(*signal, generations));
        synchronous.or_else(|| {
            self.0
                .keys()
                .copied()
                .find(|signal| selected(*signal) && self.is_current(*signal, generations))
        })
    }

    fn is_current(&self, signal: i32, generations: &PendingSignalGenerations) -> bool {
        self.0.get(&signal).is_some_and(|pending| {
            pending.generation == generations[usize::try_from(signal).expect("positive signal")]
        })
    }

    pub(crate) fn any_matching(
        &self,
        selected: KernelSigset,
        generations: &PendingSignalGenerations,
    ) -> bool {
        self.0
            .keys()
            .any(|signal| selected.contains(*signal) && self.is_current(*signal, generations))
    }

    pub(crate) fn any_eligible(
        &self,
        blocked: KernelSigset,
        generations: &PendingSignalGenerations,
    ) -> bool {
        self.0
            .keys()
            .any(|signal| !blocked.contains(*signal) && self.is_current(*signal, generations))
    }

    pub(crate) fn pending_mask(&self, generations: &PendingSignalGenerations) -> KernelSigset {
        let mut mask = KernelSigset::default();
        for signal in self.0.keys().copied() {
            if self.is_current(signal, generations) {
                mask.insert(signal);
            }
        }
        mask
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Stable per-task notification wakeup, also retained after lifecycle retirement.
#[derive(Clone, Debug, Default)]
pub(crate) struct SignalDequeueWake(pub(crate) Arc<futures::task::AtomicWaker>);
#[cfg(any(test, feature = "test-support"))]
impl PartialEq for SignalDequeueWake {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
#[cfg(any(test, feature = "test-support"))]
impl Eq for SignalDequeueWake {}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "test-support"), derive(Eq, PartialEq))]
pub(crate) struct OwnedSignalDequeue {
    pub(crate) owner: reverie::SignalTaskIdentity,
    pub(crate) effect: reverie::SignalDequeue,
    pub(crate) wake: SignalDequeueWake,
}

/// A private nonblocking eventfd keeper, never an ordinary guest file/socket.
/// One keeper is shared by all descriptor aliases of one signalfd. Creation
/// pins it before publishing the guest descriptor; close/exec can drop this
/// bounded eventfd owner under the signal transaction without a blocking close.
///
/// The keeper also holds the description's guest-visible blocking mode
/// (`O_NONBLOCK` clear). Linux keeps that flag on the open file description,
/// so dup aliases and a forked child share it, as they share this keeper. The
/// host eventfd itself stays nonblocking whatever the guest asks: no host
/// read of it can ever wait outside the scheduler.
#[derive(Clone, Debug)]
pub(crate) struct SignalFdCarrier(Arc<std::fs::File>, Arc<AtomicBool>);
impl SignalFdCarrier {
    /// Whether the guest's description is in blocking mode.
    pub(crate) fn guest_blocking(&self) -> bool {
        self.1.load(Ordering::SeqCst)
    }
    pub(crate) fn set_guest_blocking(&self, blocking: bool) {
        self.1.store(blocking, Ordering::SeqCst);
    }
    pub(crate) fn pin_eventfd(file: &std::fs::File) -> std::io::Result<Self> {
        // The only production caller owns a freshly created EFD_NONBLOCK fd.
        // Existing signalfd F_SETFL/SCM_RIGHTS/proc-reopen guards preserve it.
        use std::os::fd::AsRawFd;
        use std::os::fd::FromRawFd;
        // Keep private descriptors out of host standard slots as well.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returns a newly owned descriptor.
        Ok(Self(
            Arc::new(unsafe { std::fs::File::from_raw_fd(fd) }),
            Arc::new(AtomicBool::new(false)),
        ))
    }
    pub(crate) fn file(&self) -> &std::fs::File {
        &self.0
    }
    #[cfg(test)]
    pub(crate) fn downgrade(&self) -> std::sync::Weak<std::fs::File> {
        Arc::downgrade(&self.0)
    }
}
impl PartialEq for SignalFdCarrier {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for SignalFdCarrier {}

/// A thread waiting in a host poll that includes signalfds. Their eventfd
/// keepers show only the process's shared queue, so a covered signal queued
/// for this thread alone wakes the wait through `wake` instead.
#[derive(Clone, Debug)]
pub(crate) struct SignalFdWaiter {
    /// The signals of every signalfd the poll waits on.
    mask: KernelSigset,
    wake: Arc<std::fs::File>,
}

impl SignalFdWaiter {
    /// A waiter for `mask` with a fresh nonblocking eventfd, kept out of the
    /// host's standard descriptor slots.
    pub(crate) fn new(mask: KernelSigset) -> std::io::Result<Self> {
        use std::os::fd::FromRawFd;
        // SAFETY: eventfd validates its constant flags and returns a new fd.
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: eventfd returned a new owned descriptor.
        let created = unsafe { std::fs::File::from_raw_fd(raw) };
        let wake = SignalFdCarrier::pin_eventfd(&created)?.0;
        Ok(Self { mask, wake })
    }

    pub(crate) fn file(&self) -> &std::fs::File {
        &self.wake
    }

    /// Wakes the wait if it covers `signal`. The eventfd write never blocks.
    pub(crate) fn wake_for(&self, signal: i32) -> std::io::Result<()> {
        use std::io::Write;
        if self.mask.contains(signal) {
            (&*self.wake).write_all(&1u64.to_ne_bytes())?;
        }
        Ok(())
    }
}

impl PartialEq for SignalFdWaiter {
    fn eq(&self, other: &Self) -> bool {
        self.mask == other.mask && Arc::ptr_eq(&self.wake, &other.wake)
    }
}
impl Eq for SignalFdWaiter {}

/// Signal state shared by all threads in one guest process.
#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "test-support"), derive(Eq, PartialEq))]
pub struct ProcessSignalState {
    pub(crate) dispositions: BTreeMap<i32, KernelSigaction>,
    pub(crate) shared_pending: StandardPendingSignals,
    pub(crate) signalfd_masks: BTreeMap<i32, Arc<KernelSigset>>,
    pub(crate) signalfd_carriers: BTreeMap<i32, SignalFdCarrier>,
    pub(crate) pending_generations: PendingSignalGenerations,
    pub(crate) dequeue_enabled: bool,
    pub dequeue_sequence: u64,
    pub(crate) dequeue_journal: std::collections::VecDeque<OwnedSignalDequeue>,
    pub(crate) dequeue_acknowledged: Option<reverie::SignalDequeue>,
    pub(crate) dequeue_acknowledged_owner: Option<reverie::SignalTaskIdentity>,
    pub dequeue_failed: bool,
}

impl Default for ProcessSignalState {
    fn default() -> Self {
        Self {
            dispositions: BTreeMap::new(),
            shared_pending: StandardPendingSignals::default(),
            signalfd_masks: BTreeMap::new(),
            signalfd_carriers: BTreeMap::new(),
            pending_generations: [0; PENDING_SIGNAL_GENERATION_COUNT],
            dequeue_enabled: false,
            dequeue_sequence: 0,
            dequeue_journal: std::collections::VecDeque::new(),
            dequeue_acknowledged: None,
            dequeue_acknowledged_owner: None,
            dequeue_failed: false,
        }
    }
}

impl ProcessSignalState {
    pub(crate) fn pending_generation(&self, signal: i32) -> u64 {
        self.pending_generations[usize::try_from(signal).expect("positive signal")]
    }

    pub(crate) fn advance_pending_generation(&mut self, signal: i32) -> Result<(), Errno> {
        let generation =
            &mut self.pending_generations[usize::try_from(signal).expect("positive signal")];
        *generation = generation.checked_add(1).ok_or(Errno::EOVERFLOW)?;
        Ok(())
    }
    pub(crate) fn for_fork(&self) -> Self {
        Self {
            dispositions: self.dispositions.clone(),
            shared_pending: StandardPendingSignals::default(),
            signalfd_masks: self.signalfd_masks.clone(),
            signalfd_carriers: self.signalfd_carriers.clone(),
            pending_generations: self.pending_generations,
            dequeue_enabled: self.dequeue_enabled,
            dequeue_sequence: 0,
            dequeue_journal: std::collections::VecDeque::new(),
            dequeue_acknowledged: None,
            dequeue_acknowledged_owner: None,
            dequeue_failed: false,
        }
    }

    pub(crate) fn after_exec(&self) -> Self {
        Self {
            dispositions: self
                .dispositions
                .iter()
                .filter_map(|(&signal, &action)| {
                    action.is_ignored().then_some((
                        signal,
                        KernelSigaction {
                            handler: libc::SIG_IGN as u64,
                            ..KernelSigaction::default()
                        },
                    ))
                })
                .collect(),
            shared_pending: self.shared_pending.clone(),
            signalfd_masks: self.signalfd_masks.clone(),
            signalfd_carriers: self.signalfd_carriers.clone(),
            pending_generations: self.pending_generations,
            dequeue_enabled: self.dequeue_enabled,
            dequeue_sequence: self.dequeue_sequence,
            dequeue_journal: self.dequeue_journal.clone(),
            dequeue_acknowledged: self.dequeue_acknowledged,
            dequeue_acknowledged_owner: self.dequeue_acknowledged_owner,
            dequeue_failed: self.dequeue_failed,
        }
    }
}

/// Signal state private to one guest thread.
#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "test-support"), derive(Eq, PartialEq))]
pub(crate) struct ThreadSignalState {
    pub(crate) blocked: KernelSigset,
    /// The alternate stack as Linux's task holds it (`sas_ss_sp`,
    /// `sas_ss_flags` and `sas_ss_size`), with `None` for the disabled stack
    /// Linux starts with and resets to: no address or size and SS_DISABLE.
    pub(crate) altstack: Option<GuestStack>,
    pub(crate) pending: StandardPendingSignals,
    /// A Tool observes eligible ignored signals before the final disposition,
    /// just as a ptrace signal-delivery stop does. Plain execution discards an
    /// unblocked ignored signal when it is generated.
    pub(crate) observe_ignored: bool,
    /// Linux's `saved_sigmask` with `TIF_RESTORE_SIGMASK`: the thread's own
    /// mask while a call that installed a temporary one (`rt_sigsuspend`, a
    /// masked `pselect6`) returns to deliver a signal under it. The signal
    /// frame saves this mask, so `rt_sigreturn` restores it; a boundary that
    /// delivers no handler restores it directly.
    pub(crate) saved_sigmask: Option<KernelSigset>,
    /// Admission identity, never reconstructed from a possibly reused numeric TID.
    pub(crate) dequeue_identity: Option<reverie::SignalTaskIdentity>,
    pub(crate) dequeue_wake: SignalDequeueWake,
    /// Set only while this thread waits in a host poll that includes
    /// signalfds; a sender that queues a covered signal for it wakes it.
    pub(crate) signalfd_waiter: Option<SignalFdWaiter>,
    /// The trap fields every signal frame of this thread saves.
    pub(crate) trap: SignalTrapFields,
}

impl ThreadSignalState {
    pub(crate) fn for_fork(&self) -> Self {
        Self {
            blocked: self.blocked,
            altstack: self.altstack,
            pending: StandardPendingSignals::default(),
            observe_ignored: self.observe_ignored,
            saved_sigmask: None,
            dequeue_identity: None,
            dequeue_wake: SignalDequeueWake::default(),
            signalfd_waiter: None,
            trap: self.trap,
        }
    }

    pub(crate) fn for_clone_thread(&self) -> Self {
        Self {
            blocked: self.blocked,
            altstack: None,
            pending: StandardPendingSignals::default(),
            observe_ignored: self.observe_ignored,
            saved_sigmask: None,
            dequeue_identity: None,
            dequeue_wake: SignalDequeueWake::default(),
            signalfd_waiter: None,
            trap: self.trap,
        }
    }

    pub(crate) fn after_exec(&self) -> Self {
        Self {
            blocked: self.blocked,
            // Linux's begin_new_exec clears the stack's address and size and
            // keeps its flags, which later frames save in uc_stack; with no
            // size, the stack stays disabled.
            altstack: self.altstack.map(|stack| GuestStack {
                sp: 0,
                size: 0,
                ..stack
            }),
            pending: self.pending.clone(),
            observe_ignored: self.observe_ignored,
            saved_sigmask: None,
            dequeue_identity: self.dequeue_identity,
            dequeue_wake: self.dequeue_wake.clone(),
            signalfd_waiter: None,
            trap: self.trap,
        }
    }
}

/// One authoritative mask and pending queue for a guest thread. A lifecycle
/// registration may lend this same state to a sender; it never copies events
/// through a second queue. When both are needed, the process signal lock must
/// be acquired before this lock, and no guard may cross a Tool callback.
#[derive(Clone, Debug, Default)]
pub struct SharedThreadSignalState(Arc<Mutex<ThreadSignalState>>);

impl SharedThreadSignalState {
    pub(crate) fn lock(&self) -> MutexGuard<'_, ThreadSignalState> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn downgrade(&self) -> Weak<Mutex<ThreadSignalState>> {
        Arc::downgrade(&self.0)
    }

    pub(crate) fn upgrade(target: &Weak<Mutex<ThreadSignalState>>) -> Option<Self> {
        target.upgrade().map(Self)
    }

    pub(crate) fn for_fork(&self) -> Self {
        Self(Arc::new(Mutex::new(self.lock().for_fork())))
    }

    pub(crate) fn for_clone_thread(&self) -> Self {
        Self(Arc::new(Mutex::new(self.lock().for_clone_thread())))
    }

    pub(crate) fn after_exec(&self) -> Self {
        Self(Arc::new(Mutex::new(self.lock().after_exec())))
    }
}

/// The five signal sets Linux reports for one thread in its `status` file
/// (`task_sig` in Linux's `fs/proc/array.c`), from the thread's state and its
/// process's, as `reverie::SignalSets` holds them:
///
/// - `SigPnd`: the thread's own queue (`ThreadSignalState::pending`);
/// - `ShdPnd`: its process's shared queue (`ProcessSignalState::shared_pending`);
/// - `SigBlk`: the thread's mask (`ThreadSignalState::blocked`);
/// - `SigIgn` and `SigCgt`: its process's actions, as Linux's
///   `collect_sigign_sigcatch` builds them: `SIG_IGN` is ignored, and any
///   handler but `SIG_DFL` and `SIG_IGN` is caught.
///
/// A queue's set holds only its current entries: an entry queued before an
/// action that discards the signal (`pending_generations`) is no longer
/// pending. The caller holds both states' locks, the process's before the
/// thread's, so the answer is the state between two of its changes. Both
/// `ElfExecutor::signal_sets` (the `reverie::Guest` fact) and the run-scoped
/// `reverie::ProcessSignalControl::signal_sets` answer through this one
/// function, so the two answers cannot drift apart.
pub(crate) fn task_signal_sets(
    process: &ProcessSignalState,
    thread: &ThreadSignalState,
) -> reverie::SignalSets {
    let generations = &process.pending_generations;
    let mut ignored = KernelSigset::default();
    let mut caught = KernelSigset::default();
    for (&signal, action) in &process.dispositions {
        if action.is_ignored() {
            ignored.insert(signal);
        } else if action.handler != libc::SIG_DFL as u64 {
            caught.insert(signal);
        }
    }
    reverie::SignalSets::new(
        signal_set_bits(thread.pending.pending_mask(generations)),
        signal_set_bits(process.shared_pending.pending_mask(generations)),
        signal_set_bits(thread.blocked),
        signal_set_bits(ignored),
        signal_set_bits(caught),
    )
}

/// `set` as `reverie::SignalSets` holds it: signal `n` at bit `n - 1`, the bit
/// `KernelSigset` keeps in byte `(n - 1) / 8`.
fn signal_set_bits(set: KernelSigset) -> u64 {
    u64::from_le_bytes(set.to_bytes())
}

pub(crate) fn event_for_process(signal: i32, pid: i32) -> Result<SignalEvent, Errno> {
    SignalEvent::new(
        signal,
        signal_info_user(signal, pid, 0, libc::SI_USER),
        SignalTarget::Process {
            pid: reverie::Pid::from_raw(pid),
        },
    )
}

pub(crate) fn event_for_thread(signal: i32, pid: i32, tid: i32) -> Result<SignalEvent, Errno> {
    SignalEvent::new(
        signal,
        signal_info_user(signal, pid, 0, libc::SI_TKILL),
        SignalTarget::Thread {
            pid: reverie::Pid::from_raw(pid),
            tid: reverie::Pid::from_raw(tid),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread_event(signal: i32, marker: u8) -> SignalEvent {
        let mut info = signal_info_user(signal, 11, 12, libc::SI_TKILL);
        info[127] = marker;
        SignalEvent::new(
            signal,
            info,
            SignalTarget::Thread {
                pid: reverie::Pid::from_raw(11),
                tid: reverie::Pid::from_raw(13),
            },
        )
        .unwrap()
    }

    #[test]
    fn standard_pending_coalesces_per_domain_and_preserves_first_siginfo() {
        let first = thread_event(libc::SIGUSR1, 0x11);
        let duplicate = thread_event(libc::SIGUSR1, 0x22);
        let mut thread = StandardPendingSignals::default();
        let mut shared = StandardPendingSignals::default();

        assert_eq!(thread.enqueue(first, 0), Ok(true));
        assert_eq!(thread.enqueue(duplicate, 0), Ok(false));
        assert_eq!(shared.enqueue(duplicate, 0), Ok(true));
        assert!(thread.contains(libc::SIGUSR1));
        assert!(shared.contains(libc::SIGUSR1));

        let delivered_thread = thread
            .take_eligible(
                KernelSigset::default(),
                &[0; PENDING_SIGNAL_GENERATION_COUNT],
            )
            .unwrap();
        let delivered_shared = shared
            .take_eligible(
                KernelSigset::default(),
                &[0; PENDING_SIGNAL_GENERATION_COUNT],
            )
            .unwrap();
        assert_eq!(delivered_thread.siginfo()[127], 0x11);
        assert_eq!(delivered_shared.siginfo()[127], 0x22);
    }

    #[test]
    fn pending_generation_hides_stale_entries_from_every_consumer_and_replaces_them() {
        let signal = libc::SIGUSR1;
        let stale = thread_event(signal, 0x11);
        let current = thread_event(signal, 0x22);
        let mut generations = [0; PENDING_SIGNAL_GENERATION_COUNT];
        let mut pending = StandardPendingSignals::default();
        assert_eq!(pending.enqueue(stale, 0), Ok(true));

        generations[signal as usize] = 1;
        let mut selected = KernelSigset::default();
        selected.insert(signal);
        assert!(!pending.any_eligible(KernelSigset::default(), &generations));
        assert!(!pending.any_matching(selected, &generations));
        assert!(!pending.pending_mask(&generations).contains(signal));
        assert_eq!(
            pending
                .clone()
                .take_eligible(KernelSigset::default(), &generations),
            None,
        );
        assert_eq!(pending.clone().take_matching(selected, &generations), None,);
        assert_eq!(
            pending
                .clone()
                .take_signalfd_matching(selected, &generations),
            None,
        );

        let mut priority_generations = [0; PENDING_SIGNAL_GENERATION_COUNT];
        let mut priority = StandardPendingSignals::default();
        priority
            .enqueue(thread_event(libc::SIGSEGV, 0x33), 0)
            .unwrap();
        priority
            .enqueue(thread_event(libc::SIGUSR1, 0x44), 0)
            .unwrap();
        priority_generations[libc::SIGSEGV as usize] = 1;
        let mut both = KernelSigset::default();
        both.insert(libc::SIGSEGV);
        both.insert(libc::SIGUSR1);
        assert_eq!(
            priority
                .clone()
                .take_eligible(KernelSigset::default(), &priority_generations)
                .unwrap()
                .signal(),
            libc::SIGUSR1,
        );
        assert_eq!(
            priority
                .clone()
                .take_matching(both, &priority_generations)
                .unwrap()
                .signal(),
            libc::SIGUSR1,
        );
        assert_eq!(
            priority
                .take_signalfd_matching(both, &priority_generations)
                .unwrap()
                .signal(),
            libc::SIGUSR1,
        );

        assert_eq!(pending.enqueue(current, 1), Ok(true));
        assert_eq!(pending.enqueue(stale, 1), Ok(false));
        let delivered = pending
            .take_eligible(KernelSigset::default(), &generations)
            .unwrap();
        assert_eq!(delivered.siginfo()[127], 0x22);
    }

    #[test]
    fn every_pending_consumer_uses_linux_synchronous_signal_priority() {
        let mut selected = KernelSigset::default();
        selected.insert(libc::SIGUSR1);
        selected.insert(libc::SIGSEGV);
        let mut blocked = KernelSigset::default();
        blocked.insert(libc::SIGUSR2);

        let pending = || {
            let mut pending = StandardPendingSignals::default();
            pending.enqueue(thread_event(libc::SIGUSR1, 1), 0).unwrap();
            pending.enqueue(thread_event(libc::SIGSEGV, 2), 0).unwrap();
            pending
        };

        assert_eq!(
            pending()
                .take_eligible(blocked, &[0; PENDING_SIGNAL_GENERATION_COUNT])
                .unwrap()
                .signal(),
            libc::SIGSEGV,
        );
        assert_eq!(
            pending()
                .take_matching(selected, &[0; PENDING_SIGNAL_GENERATION_COUNT])
                .unwrap()
                .signal(),
            libc::SIGSEGV,
        );
        assert_eq!(
            pending()
                .take_signalfd_matching(selected, &[0; PENDING_SIGNAL_GENERATION_COUNT])
                .unwrap()
                .signal(),
            libc::SIGSEGV,
        );
    }

    #[test]
    fn blocked_pending_signal_remains_queued_and_realtime_is_refused() {
        let mut pending = StandardPendingSignals::default();
        let event = thread_event(libc::SIGUSR2, 1);
        pending.enqueue(event, 0).unwrap();
        let mut mask = KernelSigset::default();
        mask.insert(libc::SIGUSR2);
        assert_eq!(
            pending.take_eligible(mask, &[0; PENDING_SIGNAL_GENERATION_COUNT]),
            None
        );
        assert!(pending.contains(libc::SIGUSR2));
        assert_eq!(pending.enqueue(thread_event(32, 2), 0), Err(Errno::ENOSYS),);
    }

    #[test]
    fn fork_clone_and_exec_signal_state_have_distinct_linux_lifetimes() {
        let event = thread_event(libc::SIGUSR1, 1);
        let mut process = ProcessSignalState::default();
        process.dispositions.insert(
            libc::SIGUSR1,
            KernelSigaction {
                handler: 0x1000,
                ..Default::default()
            },
        );
        process.dispositions.insert(
            libc::SIGUSR2,
            KernelSigaction {
                handler: libc::SIG_IGN as u64,
                ..Default::default()
            },
        );
        process.pending_generations[libc::SIGUSR1 as usize] = 7;
        process.shared_pending.enqueue(event, 7).unwrap();
        let forked = process.for_fork();
        assert_eq!(forked.dispositions.len(), 2);
        assert!(
            !forked
                .shared_pending
                .pending_mask(&forked.pending_generations)
                .contains(libc::SIGUSR1)
        );
        assert_eq!(forked.pending_generation(libc::SIGUSR1), 7);
        let executed = process.after_exec();
        assert!(!executed.dispositions.contains_key(&libc::SIGUSR1));
        assert!(executed.dispositions.contains_key(&libc::SIGUSR2));
        assert!(
            executed
                .shared_pending
                .pending_mask(&executed.pending_generations)
                .contains(libc::SIGUSR1)
        );
        assert_eq!(executed.pending_generation(libc::SIGUSR1), 7);

        let mut thread = ThreadSignalState::default();
        thread.blocked.insert(libc::SIGUSR1);
        thread.altstack = Some(GuestStack {
            sp: 0x8000,
            flags: 0,
            size: 0x2000,
        });
        thread.pending.enqueue(event, 7).unwrap();
        // The last trap's fields live in the task: fork and clone copy them,
        // and exec keeps them.
        thread.trap = SignalTrapFields {
            trapno: 14,
            error_code: 6,
            cr2: 0x10,
        };
        assert_eq!(thread.for_fork().trap, thread.trap);
        assert_eq!(thread.for_clone_thread().trap, thread.trap);
        assert_eq!(thread.after_exec().trap, thread.trap);
        let forked = thread.for_fork();
        assert_eq!(forked.blocked, thread.blocked);
        assert_eq!(forked.altstack, thread.altstack);
        assert!(
            !forked
                .pending
                .pending_mask(&process.pending_generations)
                .contains(libc::SIGUSR1)
        );
        let cloned = thread.for_clone_thread();
        assert_eq!(cloned.blocked, thread.blocked);
        assert_eq!(cloned.altstack, None);
        assert!(
            !cloned
                .pending
                .pending_mask(&process.pending_generations)
                .contains(libc::SIGUSR1)
        );
        let executed = thread.after_exec();
        assert_eq!(executed.blocked, thread.blocked);
        // exec clears the stack's address and size and keeps its flags
        // (begin_new_exec in fs/exec.c).
        assert_eq!(
            executed.altstack,
            Some(GuestStack {
                sp: 0,
                flags: 0,
                size: 0,
            })
        );
        let mut autodisarm = thread.clone();
        autodisarm.altstack = Some(GuestStack {
            flags: SS_AUTODISARM,
            ..thread.altstack.unwrap()
        });
        assert_eq!(
            autodisarm.after_exec().altstack,
            Some(GuestStack {
                sp: 0,
                flags: SS_AUTODISARM,
                size: 0,
            })
        );
        let mut disabled = thread.clone();
        disabled.altstack = None;
        assert_eq!(disabled.after_exec().altstack, None);
        assert!(
            executed
                .pending
                .pending_mask(&process.pending_generations)
                .contains(libc::SIGUSR1)
        );
    }
}
