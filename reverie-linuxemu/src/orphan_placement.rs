/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Orphan placement: a Tool that opted in
//! (`ProcessSignalControl::enable_orphan_placement`) names the new parent of
//! each child an exit leaves (`ProcessSignalControl::place_orphans`), as
//! Linux's `forget_original_parent` does with the reaper `find_new_reaper`
//! chose. The backend never chooses one: it moves the family records its
//! waits, child-exit notifications and `getppid` read.

use reverie::ChildExitPublicationEffect;
use reverie::OrphanPlacement;
use reverie::OrphanPlacementReceipt;
use reverie::OrphanPlacementResult;
use reverie::OrphanReaper;
use reverie::PlacedOrphan;
use reverie::PlacedOrphanEffect;

use super::*;

/// The children of one exit, waiting for their new parent, by exact
/// generation: each one's edge state at the exit.
pub(super) type AwaitingOrphans = BTreeMap<ProcessKey, DirectChildState>;

/// What a new parent's `SIGCHLD` action decides for a zombie it adopts
/// (Linux's `do_notify_parent`): whether the zombie stays waitable, and the
/// disposition and pending generation of the announcement.
#[derive(Clone, Copy, Debug)]
struct ReaperSigchld {
    disposition: PublicationDisposition,
    waitable: bool,
    pending_generation: u64,
}

impl ProcessFamilyState {
    /// The exit of `process` with orphan placement enabled: its children wait
    /// for the Tool to name their new parent (`place_orphans`) instead of
    /// going to the namespace init at once
    /// (`reparent_children_to_outside_init`). Its executors still hand live
    /// host children to the run's namespace orphanage, whatever parent the
    /// Tool names: which process joins a host thread is independent of the
    /// child's logical parent. A child whose own exit recorded a typed fatal
    /// result keeps no edge, as there.
    pub(super) fn await_placement(&mut self, process: ProcessKey) {
        self.reparented.insert(process);
        let children = self.direct_children.remove(&process).unwrap_or_default();
        let awaiting: AwaitingOrphans = children
            .into_iter()
            .filter(|(child, state)| match state {
                DirectChildState::Live => !self.terminal.contains_key(child),
                DirectChildState::WaitableZombie => true,
            })
            .collect();
        let previous = self.awaiting_placement.insert(process, awaiting);
        debug_assert!(previous.is_none(), "KVM exit awaited placement twice");
    }
}

/// The publication effect of a zombie's announcement, as a child-exit effect.
fn announcement_effect(change: PendingChange) -> ChildExitPublicationEffect {
    match change {
        PendingChange::Queued => ChildExitPublicationEffect::Queued,
        PendingChange::Coalesced => ChildExitPublicationEffect::Coalesced,
        PendingChange::Suppressed => ChildExitPublicationEffect::SuppressedExplicitIgnore,
        PendingChange::Discarded => ChildExitPublicationEffect::DiscardedByDispositionChange,
    }
}

fn rejection_errno(reason: PublicationRejection) -> Errno {
    match reason {
        PublicationRejection::Backend(errno) => errno,
        PublicationRejection::Closed | PublicationRejection::StaleProcess => Errno::ESRCH,
        PublicationRejection::ChangedImage => Errno::EAGAIN,
        PublicationRejection::InvalidEvent | PublicationRejection::InvalidCompletion => {
            Errno::EINVAL
        }
        PublicationRejection::Terminal => Errno::EIO,
    }
}

impl ProcessSignalRegistry {
    /// [`reverie::ProcessSignalControl::enable_orphan_placement`].
    pub(super) fn enable_orphan_placement(&self) -> Result<(), Errno> {
        if self
            .parent_death_installation_closed
            .load(Ordering::Acquire)
        {
            return Err(Errno::EBUSY);
        }
        self.orphan_placement_adopted.store(true, Ordering::Release);
        Ok(())
    }

    /// The `SIGCHLD` action of live process `reaper` now, as Linux's
    /// `do_notify_parent` reads it when a zombie is re-parented to it.
    fn reaper_sigchld(binding: &ProcessBinding) -> Result<ReaperSigchld, Errno> {
        let image = binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let signals = image.signals.upgrade().ok_or(Errno::ESRCH)?;
        let signals = signals.lock().unwrap_or_else(|p| p.into_inner());
        let action = signals
            .dispositions
            .get(&libc::SIGCHLD)
            .copied()
            .unwrap_or_default();
        let disposition = if action.is_ignored() {
            PublicationDisposition::Ignored
        } else if action.handler == libc::SIG_DFL as u64 {
            PublicationDisposition::Default
        } else {
            PublicationDisposition::Caught
        };
        Ok(ReaperSigchld {
            disposition,
            waitable: !action.is_ignored() && action.flags & libc::SA_NOCLDWAIT as u64 == 0,
            pending_generation: signals.pending_generation(libc::SIGCHLD),
        })
    }

    /// [`reverie::ProcessSignalControl::place_orphans`].
    ///
    /// Lock order: the family, then the binding table and a reaper's image
    /// and signal state, which are leaves here; the zombies' announcements
    /// are published after the family is released, through the ordinary
    /// process publication (`publish`), which takes its own locks.
    pub(super) fn place_orphans(
        self: &Arc<Self>,
        exited: SignalProcessId,
        placements: &[OrphanPlacement],
    ) -> OrphanPlacementResult {
        use OrphanPlacementResult::RejectedBeforeCommit;
        let key = process_key(exited);
        let family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        if !family.orphan_placement {
            return RejectedBeforeCommit(Errno::ENOSYS);
        }
        if let Some((previous, result)) = family.placement_results.get(&key) {
            return if previous.as_slice() == placements {
                result.clone()
            } else {
                RejectedBeforeCommit(Errno::EINVAL)
            };
        }
        if !family.terminal.contains_key(&key) {
            // The exit has not been recorded: nothing waits for a parent yet.
            return RejectedBeforeCommit(Errno::EAGAIN);
        }
        if family
            .unclaimed_child_exits
            .get(&key)
            .is_some_and(|children| !children.is_empty())
        {
            // A child exit recorded for the exited process that no callback
            // claimed: the exit's fence should have published it first.
            return RejectedBeforeCommit(Errno::EINVAL);
        }
        let awaiting = family
            .awaiting_placement
            .get(&key)
            .cloned()
            .unwrap_or_default();
        let mut named = BTreeSet::new();
        let mut reaper: Option<SignalProcessId> = None;
        for placement in placements {
            let child = process_key(placement.child);
            if !awaiting.contains_key(&child) || !named.insert(child) {
                return RejectedBeforeCommit(Errno::EINVAL);
            }
            if awaiting[&child] == DirectChildState::WaitableZombie
                && !matches!(
                    family.terminal.get(&child),
                    Some(ProcessFamilyExit::Child(_))
                )
            {
                return RejectedBeforeCommit(Errno::EINVAL);
            }
            if let OrphanReaper::Process(process) = placement.reaper {
                let candidate = process_key(process);
                // Linux moves every orphan of one exit to the same reaper.
                if candidate == key
                    || candidate == child
                    || reaper.is_some_and(|reaper| reaper != process)
                {
                    return RejectedBeforeCommit(Errno::EINVAL);
                }
                if family.terminal.contains_key(&candidate) {
                    return RejectedBeforeCommit(Errno::ESRCH);
                }
                reaper = Some(process);
            }
        }
        let to_init = placements
            .iter()
            .any(|placement| placement.reaper == OrphanReaper::NamespaceInit)
            || awaiting.len() > placements.len();
        let init_pid = match family.reaper {
            NamespaceReaper::Outside { pid } => pid,
            // Only an init outside the traced tree adopts orphans here
            // (`NamespaceReaper`); the exit itself refuses the others.
            NamespaceReaper::Unknown | NamespaceReaper::TracedRoot if to_init => {
                return RejectedBeforeCommit(Errno::EINVAL);
            }
            NamespaceReaper::Unknown | NamespaceReaper::TracedRoot => 0,
        };
        let reaper = match reaper {
            Some(process) => {
                let Some(binding) = self.lookup(process) else {
                    return RejectedBeforeCommit(Errno::ESRCH);
                };
                let sigchld = match Self::reaper_sigchld(&binding) {
                    Ok(sigchld) => sigchld,
                    Err(errno) => return RejectedBeforeCommit(errno),
                };
                Some((process, binding, sigchld))
            }
            None => None,
        };
        self.commit_placement(family, exited, placements, &awaiting, reaper, init_pid)
    }

    /// Moves the validated children of `exited` under the family lock
    /// (`family`), then announces each zombie that moved to a live reaper.
    fn commit_placement(
        self: &Arc<Self>,
        mut family: std::sync::MutexGuard<'_, ProcessFamilyState>,
        exited: SignalProcessId,
        placements: &[OrphanPlacement],
        awaiting: &AwaitingOrphans,
        reaper: Option<(SignalProcessId, Arc<ProcessBinding>, ReaperSigchld)>,
        init_pid: i32,
    ) -> OrphanPlacementResult {
        let key = process_key(exited);
        family.awaiting_placement.remove(&key);
        // The caller's order, then every child it did not name, to the init.
        let named: BTreeSet<ProcessKey> = placements
            .iter()
            .map(|placement| process_key(placement.child))
            .collect();
        let order: Vec<(ProcessKey, OrphanReaper)> = placements
            .iter()
            .map(|placement| (process_key(placement.child), placement.reaper))
            .chain(
                awaiting
                    .keys()
                    .filter(|child| !named.contains(child))
                    .map(|child| (*child, OrphanReaper::NamespaceInit)),
            )
            .collect();
        let mut placed = Vec::with_capacity(order.len());
        let mut announcements = Vec::new();
        for (child, target) in order {
            let state = awaiting[&child];
            let effect = match (target, state, reaper.as_ref()) {
                (OrphanReaper::Process(process), DirectChildState::Live, Some((_, _, _))) => {
                    let parent = process_key(process);
                    let Some(binding) = self.lookup(process_identity(child)) else {
                        // Never started (`discard_unstarted_child_process`):
                        // it records no exit, so no parent waits for one.
                        continue;
                    };
                    family
                        .direct_children
                        .entry(parent)
                        .or_default()
                        .insert(child, DirectChildState::Live);
                    if let Some(publication) = family.wait_publications.get_mut(&child) {
                        publication.parent = process;
                    }
                    binding.set_parent(Some(process));
                    binding
                        .orphan_reaper_pid
                        .store(process.tgid.as_raw(), Ordering::SeqCst);
                    PlacedOrphanEffect::Live
                }
                (
                    OrphanReaper::Process(process),
                    DirectChildState::WaitableZombie,
                    Some((_, _, sigchld)),
                ) => {
                    let parent = process_key(process);
                    let Some(ProcessFamilyExit::Child(previous)) =
                        family.terminal.get(&child).copied()
                    else {
                        unreachable!("validated KVM zombie orphan keeps its child snapshot");
                    };
                    let completion = reverie::ChildExitCompletion {
                        parent: process,
                        waitable: sigchld.waitable,
                        ..previous.completion
                    };
                    family.terminal.insert(
                        child,
                        ProcessFamilyExit::Child(ChildExitSnapshot {
                            completion,
                            disposition: sigchld.disposition,
                            pending_generation: sigchld.pending_generation,
                        }),
                    );
                    if sigchld.waitable {
                        family
                            .direct_children
                            .entry(parent)
                            .or_default()
                            .insert(child, DirectChildState::WaitableZombie);
                    }
                    if let Some(publication) = family.wait_publications.get_mut(&child) {
                        publication.parent = process;
                        publication.phase = if sigchld.waitable {
                            WaitPhase::Ready
                        } else {
                            WaitPhase::Retired
                        };
                    }
                    if let Some(binding) = self.lookup(process_identity(child)) {
                        binding.set_parent(Some(process));
                        binding
                            .orphan_reaper_pid
                            .store(process.tgid.as_raw(), Ordering::SeqCst);
                    }
                    announcements.push((placed.len(), completion));
                    // Decided below, by the announcement's publication.
                    PlacedOrphanEffect::ZombieUnannounced
                }
                (OrphanReaper::Process(_), _, None) => {
                    unreachable!("validated KVM placement names a live reaper")
                }
                (OrphanReaper::NamespaceInit, DirectChildState::Live, _) => {
                    match self.lookup(process_identity(child)) {
                        Some(binding) => {
                            let inserted = family.namespace_orphans.insert(child);
                            debug_assert!(inserted, "KVM orphan adopted twice");
                            binding.orphan_reaper_pid.store(init_pid, Ordering::SeqCst);
                        }
                        // Never started: no orphan record is kept for it
                        // (`label_orphans`).
                        None => continue,
                    }
                    if let Some(publication) = family.wait_publications.get_mut(&child) {
                        publication.phase = WaitPhase::Retired;
                    }
                    PlacedOrphanEffect::NamespaceInit
                }
                (OrphanReaper::NamespaceInit, DirectChildState::WaitableZombie, _) => {
                    // The init reaps it; no traced process waits for it.
                    if let Some(publication) = family.wait_publications.get_mut(&child) {
                        publication.phase = WaitPhase::Retired;
                    }
                    PlacedOrphanEffect::NamespaceInit
                }
            };
            placed.push(PlacedOrphan {
                child: process_identity(child),
                reaper: target,
                effect,
            });
        }
        // Whatever else still names the exited process as its waiting parent
        // has no reaper: retire it, as an outside init adoption does.
        for publication in family.wait_publications.values_mut() {
            if publication.parent == exited
                && !matches!(publication.phase, WaitPhase::Consumed | WaitPhase::Failed)
            {
                publication.phase = WaitPhase::Retired;
            }
        }
        self.wait_changed.notify_all();
        drop(family);

        // Linux's `reparent_leader` announces each zombie to its new parent
        // with the child's own `SIGCHLD` siginfo; a SIG_IGN reaper generates
        // none (`do_notify_parent`), which the publication's ignored-at-
        // generation rule applies.
        let mut failure = None;
        if let Some((process, _, sigchld)) = reaper.as_ref() {
            for (index, completion) in announcements {
                let event = match child_exit_signal_event(completion) {
                    Ok(event) => event,
                    Err(rejection) => {
                        failure.get_or_insert(rejection_errno(rejection));
                        continue;
                    }
                };
                let effect = |change| {
                    if sigchld.waitable {
                        PlacedOrphanEffect::Zombie(announcement_effect(change))
                    } else {
                        PlacedOrphanEffect::AutoReaped
                    }
                };
                match self.control().publish(*process, event, None, true, None) {
                    ProcessPublication::Committed(receipt) => {
                        placed[index].effect = effect(receipt.change);
                    }
                    ProcessPublication::FailedAfterCommit(committed) => {
                        placed[index].effect = effect(committed.receipt.change);
                        failure.get_or_insert(committed.errno);
                    }
                    ProcessPublication::Rejected(rejection) => {
                        failure.get_or_insert(rejection_errno(rejection));
                    }
                }
            }
        }
        let receipt = OrphanPlacementReceipt { exited, placed };
        let result = match failure {
            None => OrphanPlacementResult::Committed(receipt),
            Some(errno) => OrphanPlacementResult::FailedAfterCommit { receipt, errno },
        };
        self.family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .placement_results
            .insert(key, (placements.to_vec(), result.clone()));
        result
    }
}
