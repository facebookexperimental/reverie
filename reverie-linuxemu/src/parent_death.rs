/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Exact task ancestry and Linux parent-thread-death signal snapshots.
//!
//! This table is guarded by the existing run-wide lifecycle mutex. It is the
//! single ordering point for SET, task creation and real-parent replacement.
//! Signal publication happens later, with no sender/lifecycle lock retained.
//! AUTONOMOUS-BOT-IMPLEMENTED
//! TODO-HUMAN-REVIEW(PR-925): Review <https://github.com/rrnewton/reverie/issues/916>.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::SignalBoundaryOutcome;
use reverie::SignalBoundaryReceipt;
use reverie::SignalProcessId;
use reverie::SignalTaskIdentity;
use reverie::syscalls::Errno;

use super::TaskLifecycleTable;
use crate::signal::ProcessSignalState;

type TaskKey = (i32, u64);
type ProcessKey = (i32, u64);

/// Frozen before reparenting. A later IGNORE -> handler transition cannot
/// resurrect this event: publication compares the retained pending generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParentDeathEvent {
    pub(crate) registered_task: SignalTaskIdentity,
    pub(crate) sender: SignalTaskIdentity,
    pub(crate) signal: i32,
    pub(crate) pending_generation: u64,
    pub(crate) ignored: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ParentDeathBatch {
    pub(crate) sequence: u64,
    pub(crate) owner: SignalTaskIdentity,
    pub(crate) outcome: SignalBoundaryOutcome,
    pub(crate) boundary: Option<SignalBoundaryReceipt>,
    pub(crate) events: Vec<ParentDeathEvent>,
    /// Full incarnations selected at this logical death, including members
    /// whose death generates no signal. Never used for admission or delivery.
    pub(crate) dying: Vec<SignalTaskIdentity>,
    /// Only outward signal-zero existence waits for complete publication.
    /// The result ledger retains this same private marker so acknowledgements
    /// can finish it even after the sender's process binding has disappeared.
    pub(crate) unpublished: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
pub(crate) struct ParentDeathState {
    next_batch: u64,
    pub(crate) controlled: bool,
    pub(crate) adopted: bool,
    pub(crate) signals: BTreeMap<ProcessKey, Weak<Mutex<ProcessSignalState>>>,
    /// Selected once at a logical exit/exec, not once per host cleanup.
    dead: BTreeSet<TaskKey>,
    enrolled: BTreeSet<ProcessKey>,
    pub(crate) batches: BTreeMap<u64, ParentDeathBatch>,
}

/// The generic shared-pending path supports SI_USER including CHLD and PIPE.
/// KILL requires cross-process cancellation of parked owners; CONT and stop
/// signals require a stopped-task protocol. Realtime queues are not modeled.
pub(crate) fn supported_signal(signal: i32) -> bool {
    (1..=31).contains(&signal)
        && !matches!(
            signal,
            libc::SIGKILL
                | libc::SIGCONT
                | libc::SIGSTOP
                | libc::SIGTSTP
                | libc::SIGTTIN
                | libc::SIGTTOU
        )
}

fn identity(tid: i32, task: super::TaskLifecycleState) -> SignalTaskIdentity {
    SignalTaskIdentity {
        process: SignalProcessId {
            tgid: reverie::Pid::from_raw(task.tgid),
            generation: task.process_generation,
        },
        tid: reverie::Pid::from_raw(tid),
        task_generation: task.generation,
    }
}

impl TaskLifecycleTable {
    pub(crate) fn inherit_real_parent(
        &mut self,
        child: i32,
        generation: u64,
        creator: SignalTaskIdentity,
        thread: bool,
    ) -> Result<(), Errno> {
        let parent = self
            .tasks
            .get(&creator.tid.as_raw())
            .copied()
            .ok_or(Errno::ESRCH)?;
        if identity(creator.tid.as_raw(), parent) != creator
            || self
                .parent_death
                .dead
                .contains(&(creator.tid.as_raw(), creator.task_generation))
        {
            return Err(Errno::ESRCH);
        }
        let child = self.tasks.get_mut(&child).ok_or(Errno::ESRCH)?;
        if child.generation != generation {
            return Err(Errno::ESRCH);
        }
        child.real_parent = if thread {
            parent.real_parent
        } else {
            Some(creator)
        };
        // Linux copy_process clears it even for CLONE_THREAD.
        child.parent_death_signal = 0;
        Ok(())
    }

    pub(crate) fn parent_death_signal(&self, caller: SignalTaskIdentity) -> Result<i32, Errno> {
        let task = self
            .tasks
            .get(&caller.tid.as_raw())
            .copied()
            .ok_or(Errno::ESRCH)?;
        if identity(caller.tid.as_raw(), task) != caller
            || self
                .parent_death
                .dead
                .contains(&(caller.tid.as_raw(), caller.task_generation))
        {
            return Err(Errno::ESRCH);
        }
        Ok(task.parent_death_signal)
    }

    pub(crate) fn set_parent_death_signal(
        &mut self,
        caller: SignalTaskIdentity,
        raw: u64,
    ) -> Result<(), Errno> {
        // kernel/sys.c passes unsigned long to valid_signal, not an int cast.
        if raw > 64 {
            return Err(Errno::EINVAL);
        }
        let signal = raw as i32;
        if signal != 0
            && (!supported_signal(signal)
                || !self.parent_death.controlled
                || !self.parent_death.adopted)
        {
            return Err(Errno::ENOSYS);
        }
        let tid = caller.tid.as_raw();
        self.parent_death_signal(caller)?;
        let current = self.tasks.get(&tid).copied().ok_or(Errno::ESRCH)?;
        if signal != 0
            && self
                .tasks
                .values()
                .filter(|task| {
                    task.tgid == current.tgid
                        && task.process_generation == current.process_generation
                })
                .count()
                != 1
        {
            return Err(Errno::ENOSYS);
        }
        let task = self.tasks.get_mut(&tid).ok_or(Errno::ESRCH)?;
        if self.parent_death.dead.contains(&(tid, task.generation)) {
            return Err(Errno::ESRCH);
        }
        task.parent_death_signal = signal;
        if signal != 0 {
            // Sticky across clear/exec: a frozen or already pending death is
            // not undone by a later SET(0). Fork gets a fresh process generation.
            self.parent_death
                .enrolled
                .insert((task.tgid, task.process_generation));
        }
        Ok(())
    }

    pub(crate) fn parent_death_enrolled(&self, process: SignalProcessId) -> bool {
        self.parent_death
            .enrolled
            .contains(&(process.tgid.as_raw(), process.generation))
    }

    /// Signal zero must not report a selected task gone before its exact
    /// authenticated parent-death batch is fully published. This does not
    /// restore a lifecycle row, allocate a TID, or authorize signal delivery.
    /// A live numeric row always wins, including a different TGID/incarnation.
    pub(crate) fn signal_zero_task_exists(&self, tid: i32, tgid: Option<i32>) -> bool {
        if let Some(task) = self.tasks.get(&tid) {
            return tgid.is_none_or(|tgid| tgid == task.tgid);
        }
        self.parent_death.batches.values().any(|batch| {
            batch.unpublished.load(Ordering::Acquire)
                && batch.dying.iter().any(|task| {
                    task.tid.as_raw() == tid
                        && tgid.is_none_or(|tgid| tgid == task.process.tgid.as_raw())
                })
        })
    }

    pub(crate) fn reset_parent_death_after_exec(&mut self, tid: i32, gains_permitted: bool) {
        if gains_permitted && let Some(task) = self.tasks.get_mut(&tid) {
            // kernel/cred.c commit_creds: clearing follows a gain, not merely
            // a reduction of the permitted set. Ordinary equal-cred exec keeps it.
            task.parent_death_signal = 0;
        }
    }

    /// Freeze a complete logical death set while all members still exist.
    /// Exec excludes its surviving issuer; exit_group includes every member.
    /// A repeated physical retirement of any selected member emits no event.
    pub(crate) fn freeze_parent_death(
        &mut self,
        owner: SignalTaskIdentity,
        outcome: SignalBoundaryOutcome,
        boundary: Option<SignalBoundaryReceipt>,
    ) -> Result<Option<u64>, Errno> {
        let Some(owner_task) = self.tasks.get(&owner.tid.as_raw()).copied() else {
            return Ok(None);
        };
        if identity(owner.tid.as_raw(), owner_task) != owner {
            return Err(Errno::ESRCH);
        }
        let dying: BTreeSet<TaskKey> = self
            .tasks
            .iter()
            .filter_map(|(&tid, &task)| {
                let selected = match outcome {
                    SignalBoundaryOutcome::Terminated { group: true, .. } => {
                        task.tgid == owner_task.tgid
                            && task.process_generation == owner_task.process_generation
                    }
                    SignalBoundaryOutcome::Terminated { group: false, .. } => {
                        tid == owner.tid.as_raw()
                    }
                    SignalBoundaryOutcome::ImageReplaced => {
                        tid != owner.tid.as_raw()
                            && task.tgid == owner_task.tgid
                            && task.process_generation == owner_task.process_generation
                    }
                    _ => false,
                };
                (selected && !self.parent_death.dead.contains(&(tid, task.generation)))
                    .then_some((tid, task.generation))
            })
            .collect();
        // Retain even an empty real terminal/exec boundary for an opted-in
        // consumer. An owned permit alone is not proof that its claimed
        // outcome happened; otherwise a fabricated Terminated could consume
        // an actual ImageReplaced boundary without publishing its events.
        let retain_boundary = self.parent_death.controlled && self.parent_death.adopted;
        if retain_boundary {
            let supplied = boundary.ok_or(Errno::ENOSYS)?;
            if supplied.permit.task != owner || supplied.outcome != outcome {
                return Err(Errno::EINVAL);
            }
            if let Some(batch) = self
                .parent_death
                .batches
                .values()
                .find(|batch| batch.boundary == Some(supplied))
            {
                return Ok(Some(batch.sequence));
            }
        }
        if dying.is_empty() && !retain_boundary {
            return Ok(None);
        }
        let mut changes = Vec::new();
        let mut events = Vec::new();
        for (&tid, &child) in &self.tasks {
            let Some(parent) = child.real_parent else {
                continue;
            };
            if !dying.contains(&(parent.tid.as_raw(), parent.task_generation))
                || dying.contains(&(tid, child.generation))
                || self.parent_death.dead.contains(&(tid, child.generation))
            {
                continue;
            }
            let reaper = self.tasks.iter().find_map(|(&candidate, &task)| {
                (task.tgid == parent.process.tgid.as_raw()
                    && task.process_generation == parent.process.generation
                    && !dying.contains(&(candidate, task.generation))
                    && !self
                        .parent_death
                        .dead
                        .contains(&(candidate, task.generation)))
                .then(|| identity(candidate, task))
            });
            changes.push((tid, reaper));
            if child.parent_death_signal != 0 {
                let signals = self
                    .parent_death
                    .signals
                    .get(&(child.tgid, child.process_generation))
                    .and_then(Weak::upgrade)
                    .ok_or(Errno::ESRCH)?;
                let signals = signals.lock().unwrap_or_else(|p| p.into_inner());
                // Lifecycle ownership fixes the receiver incarnation. Signal
                // generation follows the existing process -> thread lock order;
                // do not acquire its transaction beneath the sender's locks.
                let target = self.signal_target(tid).ok_or(Errno::ESRCH)?;
                let target = target.lock();
                let signal = child.parent_death_signal;
                let disposition = crate::executor::signal_disposition_with_action(
                    signals.dispositions.get(&signal).copied(),
                    signal,
                );
                let ignored = disposition == crate::executor::SignalDisposition::Ignore
                    && !target.blocked.contains(signal)
                    && !target.observe_ignored;
                events.push(ParentDeathEvent {
                    registered_task: identity(tid, child),
                    sender: parent,
                    signal,
                    pending_generation: signals.pending_generation(signal),
                    ignored,
                });
            }
        }
        let sequence = if events.is_empty() && !retain_boundary {
            None
        } else {
            Some(
                self.parent_death
                    .next_batch
                    .checked_add(1)
                    .ok_or(Errno::EOVERFLOW)?,
            )
        };
        let dying_identities = dying
            .iter()
            .map(|&(tid, _)| identity(tid, self.tasks[&tid]))
            .collect();
        // All fallible snapshot work precedes ancestry/dead-set mutation.
        for (tid, reaper) in changes {
            self.tasks
                .get_mut(&tid)
                .expect("locked child exists")
                .real_parent = reaper;
        }
        self.parent_death.dead.extend(dying);
        if let Some(sequence) = sequence {
            self.parent_death.next_batch = sequence;
            self.parent_death.batches.insert(
                sequence,
                ParentDeathBatch {
                    sequence,
                    owner,
                    outcome,
                    boundary,
                    events,
                    dying: dying_identities,
                    unpublished: Arc::new(AtomicBool::new(retain_boundary)),
                },
            );
        }
        Ok(sequence)
    }
}
