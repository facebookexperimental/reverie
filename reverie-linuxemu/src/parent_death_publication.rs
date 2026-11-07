/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Authenticated, retained parent-death publication at an existing Tool fence.
//! No sender transaction survives into the recipient transaction.
//! AUTONOMOUS-BOT-IMPLEMENTED
//! TODO-HUMAN-REVIEW(PR-925): <https://github.com/rrnewton/reverie/issues/916>.

use reverie::ParentDeathPublication;
use reverie::ParentDeathPublicationResult;
use reverie::ParentDeathSignalPublication;

use super::*;
use crate::elf::parent_death::ParentDeathBatch;
use crate::elf::parent_death::ParentDeathEvent;

#[derive(Clone, Debug)]
pub(super) struct BatchResult {
    boundary: reverie::SignalBoundaryReceipt,
    signals: Vec<ParentDeathSignalPublication>,
    error: Option<Errno>,
    // Exact batch authority, not a numeric task/process lookup. Kept even if
    // the sender binding is dropped between result commit and acknowledgement.
    unpublished: Arc<AtomicBool>,
}

/// Call only after dropping the results guard and every publication guard.
/// Success (including duplicate success) completes all of this boundary's
/// existence markers. A failed prefix must never complete even an earlier
/// marker: the enclosing boundary did not finish.
fn complete_parent_death_publication(
    receipt: ParentDeathPublication,
    unpublished: Vec<Arc<AtomicBool>>,
) -> ParentDeathPublicationResult {
    for marker in unpublished {
        marker.store(false, Ordering::Release);
    }
    ParentDeathPublicationResult::Committed(receipt)
}

fn event(snapshot: ParentDeathEvent) -> Result<SignalEvent, Errno> {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&snapshot.signal.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_USER.to_ne_bytes());
    info[16..20].copy_from_slice(&snapshot.sender.process.tgid.as_raw().to_ne_bytes());
    // The admitted guest credential/user-namespace model is fixed real UID 0.
    // This is never the supervisor's uid; future credential support must supply
    // the sender's real uid as part of the frozen death snapshot.
    info[20..24].copy_from_slice(&0_u32.to_ne_bytes());
    SignalEvent::new(
        snapshot.signal,
        info,
        reverie::SignalTarget::Process {
            pid: snapshot.registered_task.process.tgid,
        },
    )
}

fn effect(
    snapshot: ParentDeathEvent,
    receipt: Option<&PublicationReceipt>,
) -> ParentDeathSignalPublication {
    ParentDeathSignalPublication {
        process: snapshot.registered_task.process,
        signal: snapshot.signal,
        pending_generation: snapshot.pending_generation,
        coalesced: receipt.is_some_and(|r| r.change == PendingChange::Coalesced),
        discarded: receipt.is_none_or(|r| {
            matches!(
                r.change,
                PendingChange::Suppressed | PendingChange::Discarded
            )
        }),
    }
}

impl ProcessSignalRegistry {
    pub(crate) fn retain_parent_death_error(&self, errno: Errno) {
        self.parent_death_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_or_insert(errno);
    }

    pub(crate) fn check_parent_death_failure(&self) -> crate::Result<()> {
        match *self
            .parent_death_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
        {
            Some(errno) => Err(crate::Error::ParentDeathSignal {
                operation: "logical death/publication",
                errno: errno.into_raw(),
            }),
            None => Ok(()),
        }
    }

    fn parent_death_batches(
        &self,
        boundary: reverie::SignalBoundaryReceipt,
    ) -> Result<Vec<ParentDeathBatch>, Errno> {
        let binding = self
            .lookup(boundary.permit.task.process)
            .ok_or(Errno::ESRCH)?;
        let lifecycle = binding.lifecycle.upgrade().ok_or(Errno::ESRCH)?;
        let lifecycle = lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        Ok(lifecycle
            .parent_death
            .batches
            .values()
            .filter(|batch| batch.boundary == Some(boundary))
            .cloned()
            .collect())
    }

    pub(crate) fn parent_death_boundary_finished(
        &self,
        boundary: reverie::SignalBoundaryReceipt,
    ) -> crate::Result<()> {
        self.check_parent_death_failure()?;
        let batches = self.parent_death_batches(boundary).map_err(|errno| {
            crate::Error::ParentDeathSignal {
                operation: "boundary identity",
                errno: errno.into_raw(),
            }
        })?;
        let results = self
            .parent_death_results
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if batches
            .iter()
            .any(|batch| !results.contains_key(&batch.sequence))
        {
            return Err(crate::Error::ParentDeathSignal {
                operation: "consumer released boundary without publishing retained batch",
                errno: libc::ENOSYS,
            });
        }
        Ok(())
    }

    pub(super) fn verify_parent_death_receipt(
        &self,
        receipt: &ParentDeathPublication,
    ) -> Result<(), Errno> {
        let results = self
            .parent_death_results
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut expected = Vec::new();
        let mut expected_batches = Vec::new();
        for (&sequence, result) in results
            .iter()
            .filter(|(_, result)| result.boundary == receipt.boundary)
        {
            expected_batches.push(sequence);
            expected.extend(result.signals.iter().copied());
            if result.error.is_some() {
                break;
            }
        }
        if expected != receipt.signals
            || receipt.batches.is_empty()
            || expected_batches != receipt.batches
        {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

impl ProcessSignalControl {
    pub(super) fn publish_parent_death_boundary(
        &self,
        boundary: reverie::SignalBoundaryReceipt,
    ) -> ParentDeathPublicationResult {
        use ParentDeathPublicationResult as Outcome;
        let Some(registry) = self.0.upgrade() else {
            return Outcome::RejectedBeforeCommit(Errno::ESRCH);
        };
        if !registry.controlled() || !registry.parent_death_adopted.load(Ordering::Acquire) {
            return Outcome::RejectedBeforeCommit(Errno::ENOSYS);
        }
        if !matches!(
            boundary.outcome,
            reverie::SignalBoundaryOutcome::Terminated { .. }
                | reverie::SignalBoundaryOutcome::ImageReplaced
        ) {
            return Outcome::RejectedBeforeCommit(Errno::EINVAL);
        }
        // Completed receipts outlive the sender's process-table binding. They
        // remain exact after task cleanup; never re-open publication or retarget
        // a numeric pid merely to answer an idempotent acknowledgement.
        let completed = {
            let results = registry
                .parent_death_results
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut retained = ParentDeathPublication {
                boundary,
                batches: Vec::new(),
                signals: Vec::new(),
            };
            let mut unpublished = Vec::new();
            for (&sequence, result) in results
                .iter()
                .filter(|(_, result)| result.boundary == boundary)
            {
                retained.batches.push(sequence);
                retained.signals.extend(result.signals.iter().copied());
                unpublished.push(result.unpublished.clone());
                if let Some(errno) = result.error {
                    return Outcome::FailedAfterCommit {
                        receipt: retained,
                        errno,
                    };
                }
            }
            (!retained.batches.is_empty()).then_some((retained, unpublished))
        };
        if let Some((receipt, unpublished)) = completed {
            return complete_parent_death_publication(receipt, unpublished);
        }
        let batches = match registry.parent_death_batches(boundary) {
            Ok(batches) => batches,
            Err(errno) => return Outcome::RejectedBeforeCommit(errno),
        };
        if batches.is_empty() {
            // No producer-retained logical transition authenticates this
            // outcome. In particular, an exec permit is not an exit permit.
            return Outcome::RejectedBeforeCommit(Errno::EINVAL);
        }
        // Exact duplicates remain stable even after permit retirement. Only a
        // retained result may bypass the current owned-permit check.
        let mut results = registry
            .parent_death_results
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let all_retained =
            !batches.is_empty() && batches.iter().all(|b| results.contains_key(&b.sequence));
        if !all_retained && registry.owned_permit(boundary.permit.task) != Some(boundary.permit) {
            return Outcome::RejectedBeforeCommit(Errno::EINVAL);
        }
        let mut combined = ParentDeathPublication {
            boundary,
            batches: Vec::new(),
            signals: Vec::new(),
        };
        let mut unpublished = Vec::new();
        for batch in batches {
            if batch.owner != boundary.permit.task || batch.outcome != boundary.outcome {
                return Outcome::RejectedBeforeCommit(Errno::EINVAL);
            }
            let retained = results.entry(batch.sequence).or_insert_with(|| {
                let mut result = BatchResult {
                    boundary,
                    signals: Vec::new(),
                    error: None,
                    unpublished: batch.unpublished.clone(),
                };
                for snapshot in batch.events {
                    let event = match event(snapshot) {
                        Ok(event) => event,
                        Err(errno) => {
                            result.error = Some(errno);
                            break;
                        }
                    };
                    match self.publish(
                        snapshot.registered_task.process,
                        event,
                        None,
                        true,
                        Some(&snapshot),
                    ) {
                        ProcessPublication::Committed(receipt) => {
                            result.signals.push(effect(snapshot, Some(&receipt)))
                        }
                        ProcessPublication::FailedAfterCommit(failure) => {
                            result
                                .signals
                                .push(effect(snapshot, Some(&failure.receipt)));
                            result.error = Some(failure.errno);
                            break;
                        }
                        // Death or exec of an exact receiver does not retarget
                        // a reused pid. Image replacement retains the same
                        // process; an unexpected image race fails visibly.
                        ProcessPublication::Rejected(PublicationRejection::StaleProcess) => {
                            result.signals.push(effect(snapshot, None))
                        }
                        ProcessPublication::Rejected(reason) => {
                            result.error = Some(match reason {
                                PublicationRejection::Backend(errno) => errno,
                                PublicationRejection::ChangedImage => Errno::EAGAIN,
                                PublicationRejection::Closed => Errno::ESRCH,
                                PublicationRejection::InvalidEvent
                                | PublicationRejection::InvalidCompletion => Errno::EINVAL,
                                PublicationRejection::Terminal => Errno::EIO,
                                PublicationRejection::StaleProcess => unreachable!(),
                            });
                            break;
                        }
                    }
                }
                result
            });
            combined.batches.push(batch.sequence);
            combined.signals.extend(retained.signals.iter().copied());
            unpublished.push(retained.unpublished.clone());
            if let Some(errno) = retained.error {
                registry.retain_parent_death_error(errno);
                return Outcome::FailedAfterCommit {
                    receipt: combined,
                    errno,
                };
            }
        }
        drop(results);
        complete_parent_death_publication(combined, unpublished)
    }
}
