/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest's signal to another process, which a Tool that selects recipients
//! asked for (`ProcessSignalControl::enable_cross_process_signals`).
//!
//! The sender decides the send under its own transaction, releases it, and
//! then queues the signal under the target's, taking the target's locks in
//! the order a publication does (`ProcessSignalControl::publish`). No sender
//! transaction survives into the target's: a child's exit holds the child's
//! transaction while it takes its parent's (`record_process_exit`), so a
//! parent that kept its own while it took the child's could deadlock with
//! that exit.
//!
//! Like Linux's `do_send_sig_info`, the send chooses no thread and wakes none:
//! a thread of the target takes the signal at a boundary the Tool permits.

use crate::executor::SignalDisposition;
use crate::executor::flush_for_generation;
use crate::executor::flushed_by;
use crate::executor::shared_queue_covers;
use crate::executor::signal_disposition_with_action;

use super::*;

/// The queue a signal to another process goes to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignalDestination {
    /// The process's shared queue: a process-directed send.
    Process(SignalProcessId),
    /// One of its threads' own queue: a thread-directed send.
    Thread(reverie::SignalTaskIdentity),
}

impl SignalDestination {
    fn process(self) -> SignalProcessId {
        match self {
            Self::Process(process) => process,
            Self::Thread(task) => task.process,
        }
    }
}

/// Why a send to another process changed nothing, or what failed once it had
/// queued the signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnsentSignal {
    /// The target exited, or ran exec, after the sender found it. Nothing
    /// changed.
    TargetChanged,
    /// The signal's action at the target is the default stop, which this
    /// backend cannot perform. Nothing changed.
    DefaultStop,
    /// A signalfd of the target has no keeper (nothing changed), or a
    /// readiness update failed after the signal was queued, as a send within
    /// a process reports it.
    Errno(Errno),
}

impl ProcessSignalRegistry {
    /// Queues `event`, a guest's standard signal, at `destination`: a live
    /// process of this run other than the sender's, or one of its threads.
    /// Call with no transaction held.
    ///
    /// Under the target's transaction it revalidates the target the sender
    /// found: the same process lifetime and image, and for a thread the same
    /// task lifetime ([`UnsentSignal::TargetChanged`] otherwise). It refuses a
    /// stop signal whose action is the default before any effect. Then, as
    /// Linux's `__send_signal_locked`, it applies a stop signal's or
    /// SIGCONT's flush (`flush_for_generation`), and queues the signal on the
    /// shared queue or the thread's own, keeping a standard signal's first
    /// siginfo. A thread-directed signal that is ignored, not blocked by its
    /// thread, and not observed by a Tool there is discarded, as Linux
    /// discards it at the send; a process-directed one is queued, as a send
    /// within a process queues it. It readies the keepers of the signalfds
    /// that cover the queued signal, refreshes those of any flushed one, and
    /// wakes the target thread's wait for a signalfd that covers it.
    pub(crate) fn send_to_other_process(
        &self,
        destination: SignalDestination,
        event: SignalEvent,
    ) -> Result<(), UnsentSignal> {
        use UnsentSignal::TargetChanged;
        let process = destination.process();
        let binding = self.lookup(process).ok_or(TargetChanged)?;
        let image = binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        #[cfg(test)]
        run_test_hook(&IMAGE_CLONED_TEST_HOOK);
        let (Some(transaction), Some(lifecycle)) =
            (binding.transaction.upgrade(), binding.lifecycle.upgrade())
        else {
            return Err(TargetChanged);
        };
        // Declared before the transaction's guard, so that it is dropped
        // after the guard, but taken only under it (`current_image_signals`).
        let signals;
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        #[cfg(test)]
        run_test_hook(&TRANSACTION_HELD_TEST_HOOK);
        signals = current_image_signals(&binding, &image).map_err(|_| TargetChanged)?;
        let keepers = {
            let lifecycle = lifecycle.lock().unwrap_or_else(|p| p.into_inner());
            if binding.identity != process
                || !lifecycle.contains_process(process.tgid.as_raw(), process.generation)
            {
                return Err(TargetChanged);
            }
            let thread = match destination {
                SignalDestination::Process(_) => None,
                SignalDestination::Thread(task) => {
                    let live = lifecycle.get(task.tid.as_raw()).is_some_and(|state| {
                        state.generation == task.task_generation
                            && state.tgid == process.tgid.as_raw()
                            && state.process_generation == process.generation
                    });
                    if !live {
                        return Err(TargetChanged);
                    }
                    Some(
                        lifecycle
                            .signal_target(task.tid.as_raw())
                            .ok_or(TargetChanged)?,
                    )
                }
            };
            let mut process_signals = signals.lock().unwrap_or_else(|p| p.into_inner());
            let signal = event.signal();
            let disposition = signal_disposition_with_action(
                process_signals.dispositions.get(&signal).copied(),
                signal,
            );
            if disposition == SignalDisposition::Stop {
                return Err(UnsentSignal::DefaultStop);
            }
            // The keepers this send can change: those of the signalfds that
            // cover a signal it may flush or, for the shared queue, the
            // signal itself. Each is found before any effect.
            let mut changed = flushed_by(signal).to_vec();
            if thread.is_none() {
                changed.push(signal);
            }
            let keepers = process_signals
                .signalfd_masks
                .iter()
                .filter(|(_, mask)| changed.iter().any(|&signal| mask.contains(signal)))
                .map(|(fd, mask)| {
                    process_signals
                        .signalfd_carriers
                        .get(fd)
                        .cloned()
                        .map(|carrier| (carrier, **mask))
                        .ok_or(UnsentSignal::Errno(Errno::EBADF))
                })
                .collect::<Result<Vec<_>, _>>()?;
            flush_for_generation(&lifecycle, process, &mut process_signals, signal);
            let generation = process_signals.pending_generation(signal);
            match thread {
                None => {
                    process_signals
                        .shared_pending
                        .enqueue(event, generation)
                        .map_err(UnsentSignal::Errno)?;
                }
                Some(thread) => {
                    let mut thread = thread.lock();
                    let discarded = disposition == SignalDisposition::Ignore
                        && !thread.blocked.contains(signal)
                        && !thread.observe_ignored;
                    if !discarded {
                        thread
                            .pending
                            .enqueue(event, generation)
                            .map_err(UnsentSignal::Errno)?;
                        if let Some(waiter) = &thread.signalfd_waiter {
                            waiter.wake_for(signal).map_err(|error| {
                                UnsentSignal::Errno(Errno::new(
                                    error.raw_os_error().unwrap_or(libc::EIO),
                                ))
                            })?;
                        }
                    }
                }
            }
            keepers
                .into_iter()
                .map(|(carrier, mask)| {
                    let ready = shared_queue_covers(&process_signals, mask);
                    (carrier, ready)
                })
                .collect::<Vec<_>>()
        };
        // Bounded, nonblocking eventfd readiness I/O, with the lifecycle and
        // process signal locks released and the target's transaction held.
        for (carrier, ready) in keepers {
            set_signalfd_ready(carrier.file(), ready).map_err(|raw| {
                UnsentSignal::Errno(Errno::new(i32::try_from(-raw).unwrap_or(libc::EIO)))
            })?;
        }
        Ok(())
    }
}
