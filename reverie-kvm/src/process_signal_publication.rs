/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run-scoped callback-independent process publication and recipient permits.
//!
//! Installation precedes guest startup. A permit authorizes one actual task
//! continuation, not a host wake or an unrelated borrowed Guest. Generation-
//! bound child completion is published through this same run-scoped control.
//!
//! Active publication uses only transaction -> lifecycle -> run failure ->
//! process signals and pinned private eventfd carriers. It never acquires or
//! pins the ordinary file table. The retained inactive alarm test endpoint
//! additionally takes file table first, preserving its negative controls.
//! Image validation briefly reacquires image below transaction;
//! child lookup briefly reacquires registry below lifecycle. Those guards are
//! released before failure/process acquisition. The run failure guard remains
//! held through readiness I/O after process/lifecycle guards are released,
//! serializing publications across
//! processes in this run. Existing executor process/thread locks remain below
//! the transaction. No registry or retirement mutex is held during host closes.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use reverie::SignalEvent;
use reverie::SignalProcessId;
use reverie::syscalls::Errno;

use super::FileTableState;
use super::LoadedStaticElf;
use super::set_signalfd_ready;
use crate::elf::TaskLifecycleTable;
use crate::signal::ProcessSignalState;

#[path = "child_wait.rs"]
mod child_wait;
use std::sync::Condvar;

pub(crate) use child_wait::ChildWaitContext;
pub(crate) use child_wait::ChildWaitReceipt;
pub(crate) use child_wait::ChildWaitSelection;
#[cfg(test)]
pub(crate) use child_wait::TestChildCompletion;
use child_wait::WaitPhase;
use child_wait::WaitPublication;

type ProcessKey = (i32, u64);

fn process_key(process: SignalProcessId) -> ProcessKey {
    (process.tgid.as_raw(), process.generation)
}

fn process_identity((tgid, generation): ProcessKey) -> SignalProcessId {
    SignalProcessId {
        tgid: reverie::Pid::from_raw(tgid),
        generation,
    }
}

#[derive(Clone, Debug)]
struct ImageRevision(Arc<()>);

impl PartialEq for ImageRevision {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ImageRevision {}

#[derive(Clone)]
struct CurrentImage {
    revision: ImageRevision,
    files: Weak<Mutex<FileTableState>>,
    signals: Weak<Mutex<ProcessSignalState>>,
}

/// Executors own this binding; the run registry never owns a process or image.
/// Threads share it, fork registers a fresh binding, and exec replaces `image`.
pub(super) struct ProcessBinding {
    identity: SignalProcessId,
    parent: Option<SignalProcessId>,
    transaction: Weak<Mutex<()>>,
    lifecycle: Weak<Mutex<TaskLifecycleTable>>,
    image: Mutex<CurrentImage>,
    // Shared with every thread and exec image of this exact generation.
    orphan_reaper_pid: Arc<AtomicI32>,
}

impl ProcessBinding {
    pub(super) fn rebind(&self, state: &LoadedStaticElf, files: &Arc<Mutex<FileTableState>>) {
        // Caller holds the authoritative file table and process transaction.
        *self.image.lock().unwrap_or_else(|p| p.into_inner()) = CurrentImage {
            revision: ImageRevision(Arc::new(())),
            files: Arc::downgrade(files),
            signals: Arc::downgrade(&state.process_signals),
        };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectChildState {
    Live,
    WaitableZombie,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildExitSnapshot {
    pub(crate) completion: reverie::ChildExitCompletion,
    disposition: PublicationDisposition,
    pending_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessFamilyExit {
    Root,
    Child(ChildExitSnapshot),
    Failed,
    RunTeardownChild {
        status: reverie::ExitStatus,
    },
    /// This exact generation was orphaned while live and adopted by a
    /// namespace init outside the traced tree. That init reaps it; no traced
    /// process observes a wait status or `SIGCHLD`.
    ReapedByNamespaceInit {
        status: reverie::ExitStatus,
    },
    DescendantReparentingUnsupported {
        child: SignalProcessId,
    },
    ParentGenerationUnavailable {
        parent: SignalProcessId,
    },
    ParentChildRelationUnavailable {
        parent: SignalProcessId,
    },
    AncestryCycle {
        ancestor: SignalProcessId,
    },
    MultipleParents {
        child: SignalProcessId,
        first_parent: SignalProcessId,
        second_parent: SignalProcessId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessFamilyAncestryError {
    Cycle {
        ancestor: ProcessKey,
    },
    MultipleParents {
        child: ProcessKey,
        first_parent: ProcessKey,
        second_parent: ProcessKey,
    },
}

/// Linux `find_new_reaper` without a same-group survivor (family exits are
/// whole-process) and without subreapers: `PR_SET_CHILD_SUBREAPER` is not
/// modeled, so the orphan's PID-namespace init is always its new parent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum NamespaceReaper {
    /// No traced root has declared its namespace; orphaning fails closed.
    #[default]
    Unknown,
    /// The traced root is itself PID-namespace init. Adopting a live child or
    /// zombie would move host wait ownership and Tool child state into the
    /// root's executor, which this backend does not implement.
    TracedRoot,
    /// Namespace init is outside the traced tree, as under the ptrace backend
    /// (root PID 3 beneath init PID 1). It reaps every orphan it adopts.
    Outside { pid: i32 },
}

#[derive(Default)]
struct ProcessFamilyState {
    direct_children: BTreeMap<ProcessKey, BTreeMap<ProcessKey, DirectChildState>>,
    terminal: BTreeMap<ProcessKey, ProcessFamilyExit>,
    wait_publications: BTreeMap<ProcessKey, WaitPublication>,
    wait_receipts: BTreeMap<(ProcessKey, ProcessKey), ChildWaitReceipt>,
    wait_failed: bool,
    wait_failure_notified: bool,
    #[cfg(test)]
    waiters: usize,
    reaper: NamespaceReaper,
    // Live exact generations adopted by an outside namespace init. An entry is
    // removed only by that generation's own exit or failure.
    namespace_orphans: BTreeSet<ProcessKey>,
    // Child exits recorded for a live parent whose runtime has not yet claimed
    // them for a Tool callback, keyed by that parent. On Linux the parent
    // notification is part of the exit itself; here it is deferred to the
    // claim, so a parent exit that reparents first retires the claim instead.
    unclaimed_child_exits: BTreeMap<ProcessKey, BTreeSet<ProcessKey>>,
    // Exact generations whose exit transferred their children to an outside
    // namespace init. Their executors hand live host children to the run's
    // namespace orphanage instead of joining them.
    reparented: BTreeSet<ProcessKey>,
}

impl ProcessFamilyState {
    /// Linux `forget_original_parent` for an outside namespace reaper, applied
    /// in the family critical section that makes `process` terminal. Each exact
    /// child edge moves once: a live child becomes a namespace orphan, and an
    /// already-published zombie is reaped by init, retiring the exiting
    /// parent's claim on its status. Returns the adopted live children.
    fn reparent_children_to_outside_init(&mut self, process: ProcessKey) -> Vec<ProcessKey> {
        self.reparented.insert(process);
        for publication in self.wait_publications.values_mut() {
            if process_key(publication.parent) == process
                && !matches!(publication.phase, WaitPhase::Consumed | WaitPhase::Failed)
            {
                publication.phase = WaitPhase::Retired;
            }
        }
        // An exit recorded for a live parent but not yet claimed has not been
        // announced to anyone. The parent's exit, not a later callback to the
        // now-terminal parent, decides that status: init reaps it.
        for child in self
            .unclaimed_child_exits
            .remove(&process)
            .unwrap_or_default()
        {
            if let Some(ProcessFamilyExit::Child(snapshot)) = self.terminal.get(&child).copied() {
                self.terminal.insert(
                    child,
                    ProcessFamilyExit::ReapedByNamespaceInit {
                        status: snapshot.completion.status,
                    },
                );
            }
        }
        let Some(children) = self.direct_children.remove(&process) else {
            return Vec::new();
        };
        let mut adopted = Vec::new();
        for (child, state) in children {
            match state {
                // A child whose own exit already recorded a typed fatal
                // result keeps its edge but will never exit again.
                DirectChildState::Live if self.terminal.contains_key(&child) => {}
                DirectChildState::Live => {
                    let inserted = self.namespace_orphans.insert(child);
                    debug_assert!(inserted, "KVM orphan adopted twice");
                    adopted.push(child);
                }
                DirectChildState::WaitableZombie => {}
            }
        }
        adopted
    }

    fn has_terminal_ancestor(
        &self,
        mut ancestor: ProcessKey,
    ) -> Result<bool, ProcessFamilyAncestryError> {
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(ancestor) {
                return Err(ProcessFamilyAncestryError::Cycle { ancestor });
            }
            if self.terminal.contains_key(&ancestor) {
                return Ok(true);
            }
            let mut parents = self
                .direct_children
                .iter()
                .filter(|(_, children)| children.contains_key(&ancestor))
                .map(|(parent, _)| *parent);
            let Some(parent) = parents.next() else {
                return Ok(false);
            };
            if let Some(second_parent) = parents.next() {
                return Err(ProcessFamilyAncestryError::MultipleParents {
                    child: ancestor,
                    first_parent: parent,
                    second_parent,
                });
            }
            ancestor = parent;
        }
    }
}

#[derive(Default)]
pub(crate) struct ProcessSignalRegistry {
    processes: Mutex<BTreeMap<(i32, u64), Weak<ProcessBinding>>>,
    // Logical process ancestry is independent of host join-handle placement.
    // It is retained by exact generation until a wait consumes a zombie, an
    // exit-time auto-reap decision removes it, or the parent's exit reparents
    // it to an outside namespace init. Reparenting to an in-tree init fails
    // closed.
    family: Mutex<ProcessFamilyState>,
    wait_changed: Condvar,
    // Run-scoped at-most-once admission. Standard-signal coalescing is not an
    // operation ledger: after dequeue, the same child could otherwise enqueue
    // a second SIGCHLD. Retain exact generations until the run ends.
    child_publications: Mutex<BTreeMap<(i32, u64), ChildPublicationRecord>>,
    // No callbacks or G references. An eventual owner must make its own run
    // terminal after saving FailedAfterCommit. This latch refuses further
    // publication; it is not a substitute for that owner transition.
    failure: Mutex<Option<PublicationFailure>>,
    controlled: AtomicBool,
    permits: Mutex<BTreeMap<(i32, u64, i32, u64), RegisteredPermit>>,
    completed_permits: Mutex<BTreeMap<(i32, u64, i32, u64), reverie::SignalDeliveryPermit>>,
    run_failure: Mutex<Weak<crate::failure::RunFailure>>,
    reported_failure: Mutex<Option<crate::Error>>,
    failure_forwarded: AtomicBool,
}

impl ProcessSignalRegistry {
    pub(super) fn register(
        &self,
        state: &LoadedStaticElf,
        files: &Arc<Mutex<FileTableState>>,
        generation: u64,
        parent: Option<SignalProcessId>,
    ) -> Result<Arc<ProcessBinding>, SignalProcessId> {
        let identity = SignalProcessId {
            tgid: reverie::Pid::from_raw(state.pid),
            generation,
        };
        // Successful exec and same-process executor reconstruction retain the
        // process generation; they are not a fork edge and cannot make a
        // process its own child.
        let parent = parent.filter(|candidate| *candidate != identity);
        let binding = Arc::new(ProcessBinding {
            identity,
            parent,
            transaction: Arc::downgrade(&state.signal_transaction),
            lifecycle: Arc::downgrade(&state.task_lifecycle),
            image: Mutex::new(CurrentImage {
                revision: ImageRevision(Arc::new(())),
                files: Arc::downgrade(files),
                signals: Arc::downgrade(&state.process_signals),
            }),
            orphan_reaper_pid: state.orphan_reaper_pid.clone(),
        });
        if let Some(parent) = parent {
            let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
            let parent_key = process_key(parent);
            if family.terminal.contains_key(&parent_key) {
                return Err(parent);
            }
            let previous = family
                .direct_children
                .entry(parent_key)
                .or_default()
                .insert(process_key(binding.identity), DirectChildState::Live);
            debug_assert!(previous.is_none(), "duplicate KVM child process generation");
            let previous = family.wait_publications.insert(
                process_key(identity),
                WaitPublication {
                    parent,
                    phase: WaitPhase::Pending,
                },
            );
            assert!(
                previous.is_none(),
                "duplicate exact KVM child wait generation"
            );
            self.wait_changed.notify_all();
        }
        let mut processes = self.processes.lock().unwrap_or_else(|p| p.into_inner());
        processes.retain(|_, process| process.strong_count() != 0);
        processes.insert((state.pid, generation), Arc::downgrade(&binding));
        Ok(binding)
    }

    /// Declare the traced root's PID namespace. A root with no guest-visible
    /// parent is itself namespace init (see `vm::root_parent_pid`); otherwise
    /// its guest-visible parent is the outside init that adopts orphans. An
    /// executor built from any other state leaves the reaper unknown, which
    /// keeps reparenting fail-closed.
    pub(super) fn install_namespace_reaper(&self, root: &LoadedStaticElf) {
        if !root.is_traced_tree_root {
            return;
        }
        self.family.lock().unwrap_or_else(|p| p.into_inner()).reaper = if root.ppid == 0 {
            NamespaceReaper::TracedRoot
        } else {
            NamespaceReaper::Outside { pid: root.ppid }
        };
    }

    fn lookup(&self, identity: SignalProcessId) -> Option<Arc<ProcessBinding>> {
        self.processes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(identity.tgid.as_raw(), identity.generation))?
            .upgrade()
    }

    /// Freeze the exact process generation at its first exact task failure.
    /// Descendants may still finish successfully while the runtime unwinds,
    /// but their completion is teardown rather than a new logical child-exit
    /// publication to the failed parent. A failure is a run abort rather than
    /// a guest exit, so it does not itself reparent live children to an
    /// outside namespace init; children already adopted by an earlier
    /// successful exit of this generation stay adopted.
    pub(super) fn record_process_failure(&self, process: SignalProcessId) {
        let parent = self.lookup(process).and_then(|binding| binding.parent);
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let process_family_key = process_key(process);
        let replace_success = matches!(
            family.terminal.get(&process_family_key),
            None | Some(
                ProcessFamilyExit::Root
                    | ProcessFamilyExit::Child(_)
                    | ProcessFamilyExit::RunTeardownChild { .. }
                    | ProcessFamilyExit::ReapedByNamespaceInit { .. }
            )
        );
        if !replace_success {
            // Preserve the first typed fatal family invariant instead of
            // replacing its actionable cause with a generic peer failure.
            return;
        }
        family
            .terminal
            .insert(process_family_key, ProcessFamilyExit::Failed);
        family.namespace_orphans.remove(&process_family_key);
        if let Some(publication) = family.wait_publications.get_mut(&process_family_key)
            && publication.phase != WaitPhase::Consumed
        {
            publication.phase = WaitPhase::Failed;
        }
        self.wait_changed.notify_all();
        if let Some(parent) = parent {
            let parent_key = process_key(parent);
            if let Some(children) = family.direct_children.get_mut(&parent_key) {
                children.remove(&process_family_key);
                if children.is_empty() {
                    family.direct_children.remove(&parent_key);
                }
            }
        }
    }

    /// Freeze one process's terminal parent/wait policy at the authoritative
    /// lifecycle transition. Host join completion and the later Tool callback
    /// only consume this snapshot; they cannot resample a parent's newer
    /// SIGCHLD disposition.
    pub(super) fn record_process_exit(
        &self,
        process: SignalProcessId,
        status: reverie::ExitStatus,
    ) -> ProcessFamilyExit {
        if let Some(exit) = self
            .family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .terminal
            .get(&process_key(process))
            .copied()
        {
            return exit;
        }

        let binding = self.lookup(process);
        let parent_identity = binding.as_ref().and_then(|binding| binding.parent);
        let is_root = parent_identity.is_none();
        let parent_binding = parent_identity.and_then(|parent| self.lookup(parent));
        let parent_transaction = parent_binding
            .as_ref()
            .and_then(|binding| binding.transaction.upgrade());
        let _parent_transaction = parent_transaction
            .as_ref()
            .map(|transaction| transaction.lock().unwrap_or_else(|p| p.into_inner()));
        let parent_snapshot = parent_binding.as_ref().and_then(|parent_binding| {
            let parent = parent_identity?;
            let lifecycle = parent_binding.lifecycle.upgrade()?;
            let lifecycle = lifecycle.lock().unwrap_or_else(|p| p.into_inner());
            if !lifecycle.contains_process(parent.tgid.as_raw(), parent.generation) {
                return None;
            }
            let image = parent_binding
                .image
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let signals = image.signals.upgrade()?;
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
            let waitable = !action.is_ignored() && action.flags & libc::SA_NOCLDWAIT as u64 == 0;
            let pending_generation = signals.pending_generation(libc::SIGCHLD);
            Some((parent, disposition, waitable, pending_generation))
        });

        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(exit) = family.terminal.get(&process_key(process)).copied() {
            return exit;
        }
        if family.namespace_orphans.remove(&process_key(process)) {
            // The original parent's exit already transferred this exact
            // generation to the outside init. Its fork-time parent binding is
            // history; neither it nor a later process reusing its PID owns
            // this status.
            let exit = ProcessFamilyExit::ReapedByNamespaceInit { status };
            family.terminal.insert(process_key(process), exit);
            self.wait_changed.notify_all();
            let adopted = family.reparent_children_to_outside_init(process_key(process));
            self.label_orphans(&mut family, &adopted);
            return exit;
        }
        let blocking_descendant = family
            .direct_children
            .get(&process_key(process))
            .and_then(|children| children.keys().next().copied())
            .map(process_identity);
        let parent_is_terminal = match parent_identity {
            Some(parent) => match family.has_terminal_ancestor(process_key(parent)) {
                Ok(_) => family.terminal.contains_key(&process_key(parent)),
                Err(ProcessFamilyAncestryError::Cycle { ancestor }) => {
                    let exit = ProcessFamilyExit::AncestryCycle {
                        ancestor: process_identity(ancestor),
                    };
                    family.terminal.insert(process_key(process), exit);
                    self.wait_changed.notify_all();
                    return exit;
                }
                Err(ProcessFamilyAncestryError::MultipleParents {
                    child,
                    first_parent,
                    second_parent,
                }) => {
                    let exit = ProcessFamilyExit::MultipleParents {
                        child: process_identity(child),
                        first_parent: process_identity(first_parent),
                        second_parent: process_identity(second_parent),
                    };
                    family.terminal.insert(process_key(process), exit);
                    self.wait_changed.notify_all();
                    return exit;
                }
            },
            None => false,
        };
        let exit = if is_root {
            ProcessFamilyExit::Root
        } else if parent_is_terminal {
            // The direct parent's logical transition, rather than a transitive
            // ancestor's host teardown, decides whether this child still has a
            // live reaper. Both exits serialize through the direct parent's
            // transaction: child-first retains normal waitability, while
            // parent-first is consuming run teardown. A terminal root alone
            // cannot silently auto-reap a grandchild from its still-live parent.
            if let Some(parent) = parent_identity {
                let parent_key = process_key(parent);
                if let Some(children) = family.direct_children.get_mut(&parent_key) {
                    children.remove(&process_key(process));
                    if children.is_empty() {
                        family.direct_children.remove(&parent_key);
                    }
                }
            }
            // No process that is itself terminal can subsequently reap an
            // already-published zombie or a still-running direct child. Retire
            // those exact edges as part of this consuming teardown transition;
            // each later child still recognizes the terminal direct parent by
            // generation and takes this same branch.
            family.direct_children.remove(&process_key(process));
            ProcessFamilyExit::RunTeardownChild { status }
        } else if let (Some(child), NamespaceReaper::Unknown | NamespaceReaper::TracedRoot) =
            (blocking_descendant, family.reaper)
        {
            ProcessFamilyExit::DescendantReparentingUnsupported { child }
        } else if let Some((parent, disposition, waitable, pending_generation)) = parent_snapshot {
            let completion = reverie::ChildExitCompletion {
                parent,
                child: process,
                status,
                waitable,
                uid: 0,
                user_ticks: 0,
                system_ticks: 0,
            };
            let parent_key = process_key(parent);
            let child_key = process_key(process);
            let relation_exists = family
                .direct_children
                .get(&parent_key)
                .is_some_and(|children| children.contains_key(&child_key));
            if !relation_exists {
                let exit = ProcessFamilyExit::ParentChildRelationUnavailable { parent };
                family.terminal.insert(process_key(process), exit);
                self.wait_changed.notify_all();
                return exit;
            }
            if waitable {
                let relation = family
                    .direct_children
                    .get_mut(&parent_key)
                    .and_then(|children| children.get_mut(&child_key))
                    .expect("validated KVM direct-child relation remains present");
                *relation = DirectChildState::WaitableZombie;
            } else {
                let children = family
                    .direct_children
                    .get_mut(&parent_key)
                    .expect("validated KVM parent relation remains present");
                children.remove(&child_key);
                if children.is_empty() {
                    family.direct_children.remove(&parent_key);
                }
            }
            family
                .unclaimed_child_exits
                .entry(parent_key)
                .or_default()
                .insert(child_key);
            ProcessFamilyExit::Child(ChildExitSnapshot {
                completion,
                disposition,
                pending_generation,
            })
        } else {
            ProcessFamilyExit::ParentGenerationUnavailable {
                parent: parent_identity.expect("non-root KVM process retains a parent identity"),
            }
        };
        family.terminal.insert(process_key(process), exit);
        self.wait_changed.notify_all();
        if matches!(exit, ProcessFamilyExit::Root | ProcessFamilyExit::Child(_))
            && matches!(family.reaper, NamespaceReaper::Outside { .. })
        {
            let adopted = family.reparent_children_to_outside_init(process_key(process));
            self.label_orphans(&mut family, &adopted);
        }
        exit
    }

    /// Publish each adoption to its exact generation's guest-visible parent
    /// before the family critical section ends. Lock order: family, then the
    /// binding table.
    ///
    /// Every started child holds its binding until its exit is recorded. A
    /// live edge without one belongs to a child discarded before it started
    /// (`discard_unstarted_child_process`), which will never record an exit,
    /// so no orphan record is kept for it.
    fn label_orphans(&self, family: &mut ProcessFamilyState, adopted: &[ProcessKey]) {
        let NamespaceReaper::Outside { pid } = family.reaper else {
            debug_assert!(adopted.is_empty());
            return;
        };
        for child in adopted {
            match self.lookup(process_identity(*child)) {
                Some(binding) => binding.orphan_reaper_pid.store(pid, Ordering::SeqCst),
                None => {
                    family.namespace_orphans.remove(child);
                }
            }
        }
    }

    pub(super) fn process_family_exit(
        &self,
        process: SignalProcessId,
    ) -> Option<ProcessFamilyExit> {
        self.family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .terminal
            .get(&process_key(process))
            .copied()
    }

    /// Take this exact generation's terminal family result for its exit
    /// completion. A `Child` result is claimed exactly once, atomically with
    /// respect to the parent's exit: once claimed, a reparenting parent exit
    /// no longer rewrites it, and once rewritten, no callback targets the
    /// terminal parent.
    ///
    /// Which of the two comes first decides the reported parent, the Tool
    /// callback, and whether the old parent can wait for the child or gets its
    /// SIGCHLD. Reverie-KVM alone leaves that to the host threads of the two
    /// exits; a deterministic embedder must order them. Hermit does: detcore's
    /// child exit reservation is a control barrier that holds every other
    /// scheduler turn until the child's exit is published.
    pub(super) fn claim_child_exit(&self, process: SignalProcessId) -> Option<ProcessFamilyExit> {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let exit = family.terminal.get(&process_key(process)).copied()?;
        if let ProcessFamilyExit::Child(snapshot) = exit {
            let parent_key = process_key(snapshot.completion.parent);
            if let Some(children) = family.unclaimed_child_exits.get_mut(&parent_key) {
                children.remove(&process_key(process));
                if children.is_empty() {
                    family.unclaimed_child_exits.remove(&parent_key);
                }
            }
        }
        Some(exit)
    }

    /// Whether this exact generation's exit transferred its children to an
    /// outside namespace init, so it no longer owns their host completion.
    pub(super) fn transferred_children_to_namespace_init(&self, process: SignalProcessId) -> bool {
        self.family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reparented
            .contains(&process_key(process))
    }

    #[cfg(test)]
    pub(super) fn consume_child_wait(&self, parent: SignalProcessId, child_pid: i32) -> bool {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let parent_key = process_key(parent);
        let Some(children) = family.direct_children.get_mut(&parent_key) else {
            return false;
        };
        let child = children.iter().find_map(|(key, state)| {
            (key.0 == child_pid && *state == DirectChildState::WaitableZombie).then_some(*key)
        });
        let Some(child) = child else {
            return false;
        };
        children.remove(&child);
        if children.is_empty() {
            family.direct_children.remove(&parent_key);
        }
        true
    }

    pub(super) fn control(self: &Arc<Self>) -> ProcessSignalControl {
        ProcessSignalControl(Arc::downgrade(self))
    }
}

/// Retaining a control does not retain executors, descriptors, or GlobalState.
pub(super) struct ProcessSignalControl(Weak<ProcessSignalRegistry>);

impl std::fmt::Debug for ProcessSignalControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessSignalControl")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct RegisteredPermit {
    permit: reverie::SignalDeliveryPermit,
    image: ImageRevision,
}

fn task_key(task: reverie::SignalTaskIdentity) -> (i32, u64, i32, u64) {
    (
        task.process.tgid.as_raw(),
        task.process.generation,
        task.tid.as_raw(),
        task.task_generation,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationRejection {
    Closed,
    StaleProcess,
    ChangedImage,
    InvalidEvent,
    InvalidCompletion,
    Backend(Errno),
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationDisposition {
    Ignored,
    Default,
    Caught,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingChange {
    Queued,
    Coalesced,
    Suppressed,
    Discarded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublicationReceipt {
    process: SignalProcessId,
    image: ImageRevision,
    signal: i32,
    pending_generation: u64,
    change: PendingChange,
    disposition: PublicationDisposition,
    child_completion: Option<reverie::ChildExitCompletion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PublicationFailure {
    receipt: PublicationReceipt,
    errno: Errno,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ProcessPublication {
    Rejected(PublicationRejection),
    Committed(PublicationReceipt),
    FailedAfterCommit(PublicationFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ChildPublicationRecord {
    Committed(PublicationReceipt),
    Failed(PublicationFailure),
}

impl ChildPublicationRecord {
    fn completion(&self) -> reverie::ChildExitCompletion {
        match self {
            Self::Committed(receipt) => receipt,
            Self::Failed(failure) => &failure.receipt,
        }
        .child_completion
        .expect("child ledger contains a child completion")
    }

    fn replay(&self) -> ProcessPublication {
        match self {
            Self::Committed(receipt) => ProcessPublication::Committed(receipt.clone()),
            Self::Failed(failure) => ProcessPublication::FailedAfterCommit(failure.clone()),
        }
    }
}

impl ProcessSignalControl {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained inactive private endpoint; active facade uses independent carriers"
        )
    )]
    pub(super) fn publish_alarm(
        &self,
        target: SignalProcessId,
        event: SignalEvent,
    ) -> ProcessPublication {
        let mut expected = [0; reverie::SIGNAL_INFO_SIZE];
        expected[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
        expected[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
        if event.signal() != libc::SIGALRM
            || event.siginfo() != expected
            || event.target() != (reverie::SignalTarget::Process { pid: target.tgid })
        {
            return ProcessPublication::Rejected(PublicationRejection::InvalidEvent);
        }
        self.publish(target, event, None, false)
    }

    fn publish_active_alarm(
        &self,
        target: SignalProcessId,
        event: SignalEvent,
    ) -> ProcessPublication {
        let mut expected = [0; reverie::SIGNAL_INFO_SIZE];
        expected[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
        expected[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
        if event.signal() != libc::SIGALRM
            || event.siginfo() != expected
            || event.target() != (reverie::SignalTarget::Process { pid: target.tgid })
        {
            return ProcessPublication::Rejected(PublicationRejection::InvalidEvent);
        }
        self.publish(target, event, None, true)
    }

    fn publish_child_completion(
        &self,
        completion: reverie::ChildExitCompletion,
    ) -> ProcessPublication {
        let event = match child_exit_signal_event(completion) {
            Ok(event) => event,
            Err(rejection) => return ProcessPublication::Rejected(rejection),
        };
        self.publish(completion.parent, event, Some(&completion), true)
    }

    fn publish(
        &self,
        target: SignalProcessId,
        event: SignalEvent,
        completion: Option<&reverie::ChildExitCompletion>,
        independent_carriers: bool,
    ) -> ProcessPublication {
        use ProcessPublication::Rejected;
        use PublicationRejection::*;
        let Some(registry) = self.0.upgrade() else {
            return Rejected(Closed);
        };
        // A committed result is a stable acknowledgement, not permission to
        // repeat the effect. Consult it before liveness validation so an exact
        // duplicate remains idempotent after the child executor retires.
        if let Some(completion) = completion
            && let Some(record) = registry
                .child_publications
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&(completion.child.tgid.as_raw(), completion.child.generation))
                .cloned()
        {
            return if record.completion() == *completion {
                record.replay()
            } else {
                Rejected(InvalidCompletion)
            };
        }
        let Some(binding) = registry.lookup(target) else {
            return Rejected(StaleProcess);
        };
        let image = binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let (Some(transaction), Some(lifecycle), Some(signals)) = (
            binding.transaction.upgrade(),
            binding.lifecycle.upgrade(),
            image.signals.upgrade(),
        ) else {
            return Rejected(StaleProcess);
        };
        // The active path neither acquires nor pins an ordinary file table:
        // even dropping its final Arc could close an unrelated blocking socket
        // while the Tool holds its scheduler mutex. Only the inactive private
        // endpoint retains its historical table preflight and corruption checks.
        let files_owner = if independent_carriers {
            None
        } else {
            let Some(files) = image.files.upgrade() else {
                return Rejected(StaleProcess);
            };
            Some(files)
        };
        let files = match files_owner.as_ref() {
            Some(files) => match files.lock() {
                Ok(files) => Some(files),
                Err(_) => return Rejected(Backend(Errno::EIO)),
            },
            None => None,
        };
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        if binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revision
            != image.revision
        {
            return Rejected(ChangedImage);
        }
        let lifecycle = lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        if binding.identity != target
            || !lifecycle.contains_process(target.tgid.as_raw(), target.generation)
        {
            return Rejected(StaleProcess);
        }
        let child_snapshot = match completion {
            Some(completion) => match registry.process_family_exit(completion.child) {
                Some(ProcessFamilyExit::Child(snapshot)) if snapshot.completion == *completion => {
                    Some(snapshot)
                }
                _ => return Rejected(InvalidCompletion),
            },
            None => None,
        };
        if let Some(completion) = completion {
            let Some(child) = registry.lookup(completion.child) else {
                return Rejected(InvalidCompletion);
            };
            if child.parent != Some(target)
                || lifecycle.process_exit_status(
                    completion.child.tgid.as_raw(),
                    completion.child.generation,
                ) != Some(completion.status)
            {
                return Rejected(InvalidCompletion);
            }
        }
        // Serialize the run-local terminal latch through the entire commit.
        // This also prevents a different process from publishing after the
        // first failed readiness transaction. No Tool call can occur here.
        let mut failure = registry.failure.lock().unwrap_or_else(|p| p.into_inner());
        if failure.is_some() {
            return Rejected(Terminal);
        }
        // Keep this guard through the complete mutation and readiness phase.
        // A concurrent duplicate cannot pass the check before the first
        // operation records its irreversible commit.
        let mut child_publications = completion.map(|_| {
            registry
                .child_publications
                .lock()
                .unwrap_or_else(|p| p.into_inner())
        });
        if let (Some(completion), Some(publications)) = (completion, child_publications.as_ref())
            && let Some(previous) =
                publications.get(&(completion.child.tgid.as_raw(), completion.child.generation))
        {
            return if previous.completion() == *completion {
                previous.replay()
            } else {
                Rejected(InvalidCompletion)
            };
        }
        let mut process = signals.lock().unwrap_or_else(|p| p.into_inner());
        let signal = event.signal();
        let action = process
            .dispositions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        let disposition = child_snapshot.map_or_else(
            || {
                if action.is_ignored() {
                    PublicationDisposition::Ignored
                } else if action.handler == libc::SIG_DFL as u64 {
                    PublicationDisposition::Default
                } else {
                    PublicationDisposition::Caught
                }
            },
            |snapshot| snapshot.disposition,
        );
        let pending_generation = child_snapshot.map_or_else(
            || process.pending_generation(signal),
            |snapshot| snapshot.pending_generation,
        );
        let mut receipt = PublicationReceipt {
            process: target,
            image: image.revision,
            signal,
            pending_generation,
            change: PendingChange::Suppressed,
            disposition,
            child_completion: completion.copied(),
        };
        if signal == libc::SIGCHLD && disposition == PublicationDisposition::Ignored {
            if let (Some(completion), Some(publications)) =
                (completion, child_publications.as_mut())
            {
                let previous = publications.insert(
                    (completion.child.tgid.as_raw(), completion.child.generation),
                    ChildPublicationRecord::Committed(receipt.clone()),
                );
                debug_assert!(previous.is_none());
            }
            return ProcessPublication::Committed(receipt);
        }
        if let Some(snapshot) = child_snapshot
            && process.pending_generation(signal) != snapshot.pending_generation
        {
            receipt.change = PendingChange::Discarded;
            if let (Some(completion), Some(publications)) =
                (completion, child_publications.as_mut())
            {
                let previous = publications.insert(
                    (completion.child.tgid.as_raw(), completion.child.generation),
                    ChildPublicationRecord::Committed(receipt.clone()),
                );
                debug_assert!(previous.is_none());
            }
            return ProcessPublication::Committed(receipt);
        }
        let matching = process
            .signalfd_masks
            .iter()
            .filter_map(|(&fd, mask)| mask.contains(signal).then_some(fd))
            .collect::<Vec<_>>();
        let carriers = if independent_carriers {
            let Some(carriers) = matching
                .iter()
                .map(|fd| process.signalfd_carriers.get(fd).cloned())
                .collect::<Option<Vec<_>>>()
            else {
                return Rejected(Backend(Errno::EBADF));
            };
            carriers
        } else {
            if matching.iter().any(|fd| {
                !files
                    .as_ref()
                    .expect("private endpoint owns table")
                    .files
                    .contains_key(fd)
            }) {
                return Rejected(Backend(Errno::EBADF));
            }
            Vec::new()
        };
        receipt.change = match process
            .shared_pending
            .enqueue(event, receipt.pending_generation)
        {
            Ok(true) => PendingChange::Queued,
            Ok(false) => PendingChange::Coalesced,
            Err(errno) => return Rejected(Backend(errno)),
        };
        // Release queue/lifecycle locks, retaining descriptor+transaction
        // ownership across only bounded, nonblocking eventfd readiness I/O.
        drop(process);
        drop(lifecycle);
        for (index, fd) in matching.into_iter().enumerate() {
            let file = if independent_carriers {
                carriers[index].file()
            } else {
                &files.as_ref().expect("private endpoint owns table").files[&fd]
            };
            if let Err(raw) = set_signalfd_ready(file, true) {
                let committed = PublicationFailure {
                    receipt,
                    errno: Errno::new(i32::try_from(-raw).unwrap_or(libc::EIO)),
                };
                if let (Some(completion), Some(publications)) =
                    (completion, child_publications.as_mut())
                {
                    let previous = publications.insert(
                        (completion.child.tgid.as_raw(), completion.child.generation),
                        ChildPublicationRecord::Failed(committed.clone()),
                    );
                    debug_assert!(previous.is_none());
                }
                *failure = Some(committed.clone());
                return ProcessPublication::FailedAfterCommit(committed);
            }
        }
        if let (Some(completion), Some(publications)) = (completion, child_publications.as_mut()) {
            let previous = publications.insert(
                (completion.child.tgid.as_raw(), completion.child.generation),
                ChildPublicationRecord::Committed(receipt.clone()),
            );
            debug_assert!(previous.is_none());
        }
        ProcessPublication::Committed(receipt)
    }
}

fn child_exit_signal_event(
    completion: reverie::ChildExitCompletion,
) -> Result<SignalEvent, PublicationRejection> {
    if completion.user_ticks < 0 || completion.system_ticks < 0 {
        return Err(PublicationRejection::InvalidCompletion);
    }
    let (code, status) = match completion.status {
        reverie::ExitStatus::Exited(status) if (0..=i32::from(u8::MAX)).contains(&status) => {
            (libc::CLD_EXITED, status)
        }
        reverie::ExitStatus::Exited(_) => {
            return Err(PublicationRejection::InvalidCompletion);
        }
        reverie::ExitStatus::Signaled(signal, true) => (libc::CLD_DUMPED, signal as libc::c_int),
        reverie::ExitStatus::Signaled(signal, false) => (libc::CLD_KILLED, signal as libc::c_int),
    };
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGCHLD.to_ne_bytes());
    info[8..12].copy_from_slice(&code.to_ne_bytes());
    info[16..20].copy_from_slice(&completion.child.tgid.as_raw().to_ne_bytes());
    info[20..24].copy_from_slice(&completion.uid.to_ne_bytes());
    info[24..28].copy_from_slice(&status.to_ne_bytes());
    info[32..40].copy_from_slice(&completion.user_ticks.to_ne_bytes());
    info[40..48].copy_from_slice(&completion.system_ticks.to_ne_bytes());
    let event = SignalEvent::new(
        libc::SIGCHLD,
        info,
        reverie::SignalTarget::Process {
            pid: completion.parent.tgid,
        },
    );
    event.map_err(|_| PublicationRejection::InvalidCompletion)
}

impl ProcessSignalRegistry {
    pub(super) fn install(
        &self,
        mode: reverie::BackendSignalControlMode,
        failure: &Arc<crate::failure::RunFailure>,
    ) {
        *self.run_failure.lock().unwrap_or_else(|p| p.into_inner()) = Arc::downgrade(failure);
        self.controlled.store(
            mode == reverie::BackendSignalControlMode::ToolControlled,
            Ordering::Release,
        );
    }

    pub(super) fn controlled(&self) -> bool {
        self.controlled.load(Ordering::Acquire)
    }

    pub(super) fn permit(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Option<reverie::SignalDeliveryPermit> {
        let binding = self.lookup(task.process)?;
        let image = binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revision
            .clone();
        self.permits
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&task_key(task))
            .filter(|registered| registered.image == image)
            .map(|registered| registered.permit)
    }

    pub(super) fn take_reported_failure(&self) -> Option<crate::Error> {
        self.reported_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    pub(super) fn owned_permit(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Option<reverie::SignalDeliveryPermit> {
        self.permits
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&task_key(task))
            .map(|p| p.permit)
    }

    pub(super) fn retire_task(&self, task: reverie::SignalTaskIdentity) {
        self.permits
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&task_key(task));
        self.completed_permits
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&task_key(task));
    }
}

fn public_receipt(receipt: &PublicationReceipt) -> reverie::ProcessSignalPublication {
    debug_assert!(receipt.child_completion.is_none());
    reverie::ProcessSignalPublication {
        process: receipt.process,
        pending_generation: receipt.pending_generation,
        coalesced: receipt.change == PendingChange::Coalesced,
        disposition: match receipt.disposition {
            PublicationDisposition::Ignored => reverie::ProcessAlarmSignalDisposition::Ignored,
            PublicationDisposition::Caught => reverie::ProcessAlarmSignalDisposition::Caught,
            PublicationDisposition::Default => reverie::ProcessAlarmSignalDisposition::DefaultFatal,
        },
    }
}

fn public_child_receipt(receipt: &PublicationReceipt) -> reverie::ChildExitPublication {
    reverie::ChildExitPublication {
        completion: receipt
            .child_completion
            .expect("child publication retained its completion"),
        pending_generation: receipt.pending_generation,
        effect: match receipt.change {
            PendingChange::Queued => reverie::ChildExitPublicationEffect::Queued,
            PendingChange::Coalesced => reverie::ChildExitPublicationEffect::Coalesced,
            PendingChange::Suppressed => {
                reverie::ChildExitPublicationEffect::SuppressedExplicitIgnore
            }
            PendingChange::Discarded => {
                reverie::ChildExitPublicationEffect::DiscardedByDispositionChange
            }
        },
    }
}

fn report_publication_failure(
    registry: &ProcessSignalRegistry,
    process: SignalProcessId,
    phase: &'static str,
    error: crate::Error,
) -> Result<(), Errno> {
    let run = registry
        .run_failure
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .upgrade()
        .ok_or(Errno::ESRCH)?;
    if registry.failure_forwarded.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    // No scheduler, registry, image or signal lock survives this call.
    let context = crate::failure::FailureContext::new(run, process.tgid, process.tgid);
    let published = context.publish(phase, error);
    // The first run cause may be a concurrent independent failure. Keep this
    // returned Error too, so root completion retains the committed publication
    // receipt as secondary cleanup rather than losing it.
    registry
        .reported_failure
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert(published);
    Ok(())
}

impl reverie::ProcessSignalControl for ProcessSignalControl {
    fn publish_alarm(
        &self,
        process: SignalProcessId,
        event: SignalEvent,
    ) -> reverie::ProcessSignalPublicationResult {
        use reverie::ProcessSignalPublicationResult as Outcome;
        match self.publish_active_alarm(process, event) {
            ProcessPublication::Committed(receipt) => Outcome::Committed(public_receipt(&receipt)),
            ProcessPublication::FailedAfterCommit(failure) => Outcome::FailedAfterCommit {
                receipt: public_receipt(&failure.receipt),
                errno: failure.errno,
            },
            ProcessPublication::Rejected(reason) => Outcome::RejectedBeforeCommit(match reason {
                PublicationRejection::Backend(errno) => errno,
                PublicationRejection::Closed | PublicationRejection::StaleProcess => Errno::ESRCH,
                PublicationRejection::ChangedImage => Errno::EAGAIN,
                PublicationRejection::InvalidEvent | PublicationRejection::InvalidCompletion => {
                    Errno::EINVAL
                }
                PublicationRejection::Terminal => Errno::EIO,
            }),
        }
    }

    fn publish_child_exit(
        &self,
        completion: reverie::ChildExitCompletion,
    ) -> reverie::ChildExitPublicationResult {
        use reverie::ChildExitPublicationResult as Outcome;
        match self.publish_child_completion(completion) {
            ProcessPublication::Committed(receipt) => {
                Outcome::Committed(public_child_receipt(&receipt))
            }
            ProcessPublication::FailedAfterCommit(failure) => Outcome::FailedAfterCommit {
                receipt: public_child_receipt(&failure.receipt),
                errno: failure.errno,
            },
            ProcessPublication::Rejected(reason) => Outcome::RejectedBeforeCommit(match reason {
                PublicationRejection::Backend(errno) => errno,
                PublicationRejection::Closed | PublicationRejection::StaleProcess => Errno::ESRCH,
                PublicationRejection::ChangedImage => Errno::EAGAIN,
                PublicationRejection::InvalidEvent | PublicationRejection::InvalidCompletion => {
                    Errno::EINVAL
                }
                PublicationRejection::Terminal => Errno::EIO,
            }),
        }
    }

    fn signal_recipients(
        &self,
        process: SignalProcessId,
        signal: i32,
    ) -> Result<Vec<reverie::SignalRecipient>, Errno> {
        if !(1..=64).contains(&signal) {
            return Err(Errno::EINVAL);
        }
        let registry = self.0.upgrade().ok_or(Errno::ESRCH)?;
        let binding = registry.lookup(process).ok_or(Errno::ESRCH)?;
        let image = binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let transaction = binding.transaction.upgrade().ok_or(Errno::ESRCH)?;
        let lifecycle = binding.lifecycle.upgrade().ok_or(Errno::ESRCH)?;
        let signals = image.signals.upgrade().ok_or(Errno::ESRCH)?;
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        if binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revision
            != image.revision
        {
            return Err(Errno::EAGAIN);
        }
        let lifecycle = lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        let signals = signals.lock().unwrap_or_else(|p| p.into_inner());
        let mut signal_mask = crate::signal::KernelSigset::default();
        signal_mask.insert(signal);
        if !signals
            .shared_pending
            .any_matching(signal_mask, &signals.pending_generations)
        {
            return Ok(Vec::new());
        }
        let mut recipients = Vec::new();
        for task in lifecycle.signal_process_tasks(process) {
            let Some(thread) = lifecycle.signal_target(task.tid.as_raw()) else {
                continue;
            };
            if !thread.lock().blocked.contains(signal) {
                recipients.push(reverie::SignalRecipient { task });
            }
        }
        recipients.sort_by_key(|recipient| recipient.task.tid);
        Ok(recipients)
    }

    fn alarm_recipients(
        &self,
        process: SignalProcessId,
    ) -> Result<Vec<reverie::SignalRecipient>, Errno> {
        <Self as reverie::ProcessSignalControl>::signal_recipients(self, process, libc::SIGALRM)
    }

    fn reserve_delivery(&self, permit: reverie::SignalDeliveryPermit) -> Result<(), Errno> {
        let registry = self.0.upgrade().ok_or(Errno::ESRCH)?;
        let binding = registry.lookup(permit.task.process).ok_or(Errno::ESRCH)?;
        let transaction = binding.transaction.upgrade().ok_or(Errno::ESRCH)?;
        let lifecycle = binding.lifecycle.upgrade().ok_or(Errno::ESRCH)?;
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let lifecycle = lifecycle.lock().unwrap_or_else(|p| p.into_inner());
        let task = lifecycle
            .get(permit.task.tid.as_raw())
            .ok_or(Errno::ESRCH)?;
        if task.generation != permit.task.task_generation
            || task.process_generation != permit.task.process.generation
            || task.tgid != permit.task.process.tgid.as_raw()
            || permit.site.is_some_and(|site| {
                site.process != permit.task.process
                    || site.tid != permit.task.tid
                    || site.task_generation != permit.task.task_generation
            })
        {
            return Err(Errno::EINVAL);
        }
        let image = binding
            .image
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revision
            .clone();
        let mut permits = registry.permits.lock().unwrap_or_else(|p| p.into_inner());
        if permits.contains_key(&task_key(permit.task)) {
            return Err(Errno::EBUSY);
        }
        permits.insert(task_key(permit.task), RegisteredPermit { permit, image });
        Ok(())
    }

    fn release_delivery(&self, permit: reverie::SignalDeliveryPermit) -> Result<(), Errno> {
        let registry = self.0.upgrade().ok_or(Errno::ESRCH)?;
        let mut permits = registry.permits.lock().unwrap_or_else(|p| p.into_inner());
        let mut completed = registry
            .completed_permits
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let key = task_key(permit.task);
        match permits.get(&key) {
            Some(current) if current.permit == permit => {
                permits.remove(&key);
                completed.insert(key, permit);
                Ok(())
            }
            None if completed.get(&key) == Some(&permit) => Ok(()),
            _ => Err(Errno::EINVAL),
        }
    }

    fn finish_publication_failure(&self, process: SignalProcessId) -> Result<(), Errno> {
        let registry = self.0.upgrade().ok_or(Errno::ESRCH)?;
        let failure = registry
            .failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or(Errno::EINVAL)?;
        if failure.receipt.process != process || failure.receipt.child_completion.is_some() {
            return Err(Errno::EINVAL);
        }
        report_publication_failure(
            &registry,
            process,
            "process signal publication",
            crate::Error::ProcessSignalPublication {
                receipt: public_receipt(&failure.receipt),
                errno: failure.errno,
            },
        )
    }

    fn finish_child_exit_publication_failure(
        &self,
        receipt: reverie::ChildExitPublication,
    ) -> Result<(), Errno> {
        let registry = self.0.upgrade().ok_or(Errno::ESRCH)?;
        let failure = registry
            .failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or(Errno::EINVAL)?;
        if failure.receipt.child_completion.is_none()
            || public_child_receipt(&failure.receipt) != receipt
        {
            return Err(Errno::EINVAL);
        }
        report_publication_failure(
            &registry,
            receipt.completion.parent,
            "child-exit signal publication",
            crate::Error::ChildExitPublication {
                receipt,
                errno: failure.errno,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::super::ElfExecutor;
    use super::super::native_loaded_state;
    use super::*;
    use crate::GuestMemory;
    use crate::SyscallRequest;
    use crate::signal::KernelSigaction;
    use crate::signal::KernelSigset;

    fn executor() -> ElfExecutor {
        ElfExecutor::new(native_loaded_state(std::path::Path::new("/tmp")), false)
    }

    fn identity(executor: &ElfExecutor) -> SignalProcessId {
        executor.signal_task_identity().unwrap().process
    }

    fn alarm(target: SignalProcessId) -> SignalEvent {
        let mut info = [0; reverie::SIGNAL_INFO_SIZE];
        info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
        info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
        SignalEvent::new(
            libc::SIGALRM,
            info,
            reverie::SignalTarget::Process { pid: target.tgid },
        )
        .unwrap()
    }

    fn call(executor: &mut ElfExecutor, memory: &GuestMemory, number: i64, args: [u64; 6]) -> i64 {
        executor.execute(&SyscallRequest::new(number as u64, args), memory)
    }

    fn read_struct<T>(memory: &GuestMemory, address: u64) -> T {
        let mut value = std::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: value is writable for exactly size_of::<T>() bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                value.as_mut_ptr().cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        };
        memory.read(address, bytes).unwrap();
        // SAFETY: zeroed storage was fully initialized by memory.read.
        unsafe { value.assume_init() }
    }

    fn signalfd(executor: &mut ElfExecutor, memory: &mut GuestMemory) -> i32 {
        signalfd_for(executor, memory, libc::SIGALRM)
    }

    fn signalfd_for(executor: &mut ElfExecutor, memory: &mut GuestMemory, signal: i32) -> i32 {
        let mut mask = KernelSigset::default();
        mask.insert(signal);
        memory.write(0x80, &mask.to_bytes()).unwrap();
        let fd = call(
            executor,
            memory,
            libc::SYS_signalfd4,
            [u64::MAX, 0x80, 8, libc::SFD_NONBLOCK as u64, 0, 0],
        );
        assert!(fd >= 3, "signalfd setup: {fd}");
        fd as i32
    }

    fn ready(executor: &ElfExecutor, fd: i32) -> bool {
        let files = executor.file_table.lock().unwrap();
        let mut poll = libc::pollfd {
            fd: files.files[&fd].as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut poll, 1, 0) } >= 0);
        poll.revents & libc::POLLIN != 0
    }

    fn receipt(outcome: ProcessPublication) -> PublicationReceipt {
        match outcome {
            ProcessPublication::Committed(receipt) => receipt,
            other => panic!("publication did not commit: {other:?}"),
        }
    }

    fn child_completion(
        parent: SignalProcessId,
        child: SignalProcessId,
        status: reverie::ExitStatus,
        waitable: bool,
    ) -> reverie::ChildExitCompletion {
        reverie::ChildExitCompletion {
            parent,
            child,
            status,
            waitable,
            uid: 0,
            user_ticks: 0,
            system_ticks: 0,
        }
    }

    fn child_receipt(
        outcome: reverie::ChildExitPublicationResult,
    ) -> reverie::ChildExitPublication {
        match outcome {
            reverie::ChildExitPublicationResult::Committed(receipt) => receipt,
            other => panic!("child publication did not commit: {other:?}"),
        }
    }

    #[test]
    fn active_publication_and_dequeue_complete_while_file_table_is_held() {
        let mut executor = executor();
        let process = identity(&executor);
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd(&mut executor, &mut memory);
        let alias = call(
            &mut executor,
            &memory,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        );
        assert!(alias > i64::from(fd));
        executor
            .signal_registry
            .controlled
            .store(true, Ordering::Release);
        let control = executor.backend_signal_control().process;
        let permit = reverie::SignalDeliveryPermit {
            task: executor.signal_task_identity().unwrap(),
            sequence: 1,
            site: None,
        };
        control.reserve_delivery(permit).unwrap();
        let table = executor.file_table.clone();
        let held = table.lock().unwrap();
        // The predecessor deadlocks here. This is a structural native control,
        // not a claim that arbitrary guest blocking reads are interruptible.
        assert!(matches!(
            control.publish_alarm(process, alarm(process)),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        let ready = |fd: i32| {
            let mut poll = libc::pollfd {
                fd: held.files[&fd].as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert!(unsafe { libc::poll(&mut poll, 1, 0) } >= 0);
            poll.revents & libc::POLLIN != 0
        };
        assert!(ready(fd) && ready(alias as i32));
        assert_eq!(
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(process)
        );
        assert!(!ready(fd) && !ready(alias as i32));
        assert!(
            table.try_lock().is_err(),
            "the real table guard still belongs to this control"
        );
        control.release_delivery(permit).unwrap();
        drop(held);
    }

    #[test]
    fn active_carrier_alias_exec_close_and_process_lifetimes_are_exact() {
        let mut parent = executor();
        let child = parent.fork_child(2, false, false).unwrap();
        let parent_id = identity(&parent);
        let child_id = identity(&child);
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd(&mut parent, &mut memory);
        let alias = call(
            &mut parent,
            &memory,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        ) as i32;
        assert!(alias > fd);
        let keeper = {
            let signals = parent.state.process_signals.lock().unwrap();
            assert_eq!(
                signals.signalfd_carriers[&fd],
                signals.signalfd_carriers[&alias]
            );
            signals.signalfd_carriers[&fd].downgrade()
        };
        assert!(
            child
                .state
                .process_signals
                .lock()
                .unwrap()
                .signalfd_carriers
                .is_empty()
        );
        assert!(
            parent.fork_child(3, false, false).is_err(),
            "existing signalfd/fork limitation remains explicit"
        );
        assert_eq!(
            call(
                &mut parent,
                &memory,
                libc::SYS_fcntl,
                [
                    fd as u64,
                    libc::F_SETFD as u64,
                    libc::FD_CLOEXEC as u64,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        let control = parent.backend_signal_control().process;
        assert!(matches!(
            control.publish_alarm(child_id, alarm(child_id)),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        assert!(
            !ready(&parent, alias),
            "another process cannot publish to this carrier"
        );
        parent.replace_after_exec(native_loaded_state(std::path::Path::new("/tmp")));
        assert_eq!(identity(&parent), parent_id);
        assert_eq!(
            parent
                .state
                .process_signals
                .lock()
                .unwrap()
                .signalfd_carriers
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![alias]
        );
        assert!(
            keeper.upgrade().is_some(),
            "non-CLOEXEC alias retains the same description"
        );
        assert!(matches!(
            control.publish_alarm(parent_id, alarm(parent_id)),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        assert!(ready(&parent, alias));
        assert_eq!(
            call(
                &mut parent,
                &memory,
                libc::SYS_close,
                [alias as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        assert!(
            keeper.upgrade().is_none(),
            "last guest alias releases the sole private keeper"
        );
        assert!(
            parent
                .state
                .process_signals
                .lock()
                .unwrap()
                .signalfd_carriers
                .is_empty()
        );
        assert!(
            parent
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .contains(libc::SIGALRM),
            "close is not signal consumption"
        );
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(
            control.publish_alarm(parent_id, alarm(parent_id)),
            reverie::ProcessSignalPublicationResult::RejectedBeforeCommit(Errno::ESRCH)
        );
        assert!(
            child
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .contains(libc::SIGALRM)
        );
    }

    #[test]
    fn active_carrier_preparation_emfile_has_no_guest_descriptor_effect() {
        use std::os::fd::FromRawFd;
        const TEST: &str = "executor::process_signal_publication::tests::active_carrier_preparation_emfile_has_no_guest_descriptor_effect";
        const ENV: &str = "REVERIE_SIGNALFD_KEEPER_EMFILE_CHILD";
        const COMPLETE: &str = "signalfd keeper EMFILE control completed";
        fn limit() -> libc::rlimit {
            let mut r = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) }, 0);
            r
        }
        if std::env::var(ENV).as_deref() != Ok(TEST) {
            assert!(std::env::var_os(ENV).is_none());
            let before = limit();
            let output = std::process::Command::new("/usr/bin/timeout")
                .args(["--kill-after=2s", "10s"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                .env(ENV, TEST)
                .output()
                .unwrap();
            let after = limit();
            assert_eq!(
                (after.rlim_cur, after.rlim_max),
                (before.rlim_cur, before.rlim_max)
            );
            eprintln!(
                "signalfd keeper child status={}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success());
            assert_eq!(
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .filter(|line| *line == COMPLETE)
                    .count(),
                1
            );
            return;
        }
        let mut executor = executor();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let mut mask = KernelSigset::default();
        mask.insert(libc::SIGALRM);
        memory.write(0x80, &mask.to_bytes()).unwrap();
        let original = limit();
        let reduced = libc::rlimit {
            rlim_cur: original.rlim_cur.min(256),
            rlim_max: original.rlim_max,
        };
        let source = std::fs::File::open("/dev/null").unwrap();
        let keys = executor.state.files.keys().copied().collect::<Vec<_>>();
        let mut fillers = Vec::with_capacity(257);
        let mut exhausted = None;
        let mut observed = None;
        let lowered = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &reduced) };
        if lowered == 0 {
            for _ in 0..=256 {
                let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
                if raw < 0 {
                    exhausted = std::io::Error::last_os_error().raw_os_error();
                    break;
                }
                fillers.push(unsafe { std::fs::File::from_raw_fd(raw) });
            }
            if exhausted == Some(libc::EMFILE) && !fillers.is_empty() {
                drop(fillers.pop());
                // Prove an actual eventfd fits but its simultaneous keeper does
                // not. Then restore the same one-slot boundary for execute().
                let probe = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
                if probe >= 0 {
                    let probe = unsafe { std::fs::File::from_raw_fd(probe) };
                    let clone_error = probe.try_clone().err().and_then(|e| e.raw_os_error());
                    drop(probe);
                    let raw = call(
                        &mut executor,
                        &memory,
                        libc::SYS_signalfd4,
                        [u64::MAX, 0x80, 8, libc::SFD_NONBLOCK as u64, 0, 0],
                    );
                    observed = Some((clone_error, raw));
                }
            }
        }
        let restored = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) };
        drop(fillers);
        assert_eq!(restored, 0);
        assert_eq!(lowered, 0);
        assert_eq!(exhausted, Some(libc::EMFILE));
        assert_eq!(
            observed,
            Some((Some(libc::EMFILE), -i64::from(libc::EMFILE)))
        );
        assert_eq!(
            executor.state.files.keys().copied().collect::<Vec<_>>(),
            keys
        );
        assert_eq!(
            executor
                .file_table
                .lock()
                .unwrap()
                .files
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            keys
        );
        let signals = executor.state.process_signals.lock().unwrap();
        assert!(signals.signalfd_masks.is_empty() && signals.signalfd_carriers.is_empty());
        assert!(signals.shared_pending.is_empty());
        drop(signals);
        let fd = signalfd(&mut executor, &mut memory);
        assert!(fd >= 3, "unconstrained creation still works");
        eprintln!("{COMPLETE}");
    }

    #[test]
    fn active_publication_failure_retains_receipt_beside_prior_run_cause() {
        let mut executor = executor();
        let process = identity(&executor);
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        executor
            .signal_registry
            .install(reverie::BackendSignalControlMode::ToolControlled, &run);
        let context = crate::failure::FailureContext::new(run.clone(), process.tgid, process.tgid);
        let _first = context.publish(
            "prior cause",
            crate::Error::GuestClock("prior clock cause".into()),
        );
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd(&mut executor, &mut memory);
        // Real post-commit carrier failure, identical to the existing private
        // negative control: queue insertion succeeds, eventfd write gets EBADF.
        let carrier = executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers
            .insert(
                fd,
                crate::signal::SignalFdCarrier::pin_eventfd(
                    &std::fs::File::open("/dev/null").unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let control = executor.backend_signal_control().process;
        let reverie::ProcessSignalPublicationResult::FailedAfterCommit { receipt, errno } =
            control.publish_alarm(process, alarm(process))
        else {
            panic!("missing committed failure")
        };
        assert_eq!(errno, Errno::EBADF);
        control.finish_publication_failure(process).unwrap();
        let retained = executor
            .take_process_publication_failure()
            .expect("root-owned error receipt");
        assert!(
            matches!(retained.primary(), crate::Error::ProcessSignalPublication { receipt: actual, errno: Errno::EBADF } if *actual == receipt)
        );
        let completed = run.complete::<()>(Err(retained)).unwrap_err();
        assert!(
            matches!(completed.primary(), crate::Error::GuestClock(message) if message == "prior clock cause")
        );
        assert!(
            completed
                .to_string()
                .contains("process signal publication committed")
        );
        assert!(executor.take_process_publication_failure().is_none());
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers
            .insert(fd, carrier);
    }

    #[test]
    fn controlled_pending_alarm_does_not_reject_or_preselect_a_new_thread() {
        let leader = executor();
        leader
            .signal_registry
            .controlled
            .store(true, Ordering::Release);
        let control = leader.backend_signal_control().process;
        let process = identity(&leader);
        assert!(matches!(
            control.publish_alarm(process, alarm(process)),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        let mut worker = leader.thread_child(2).unwrap();
        assert!(worker.take_pending_signal_for_delivery().unwrap().is_none());
        assert_eq!(worker.delivery_permit(), None);
        let permit = reverie::SignalDeliveryPermit {
            task: worker.signal_task_identity().unwrap(),
            sequence: 1,
            site: None,
        };
        control.reserve_delivery(permit).unwrap();
        assert_eq!(
            worker
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(process)
        );
        control.release_delivery(permit).unwrap();
    }

    #[test]
    fn controlled_alarm_selects_unblocked_worker_and_requires_its_permit() {
        let mut leader = executor();
        let mut worker = leader.thread_child(2).unwrap();
        let process = identity(&leader);
        leader
            .signal_registry
            .controlled
            .store(true, Ordering::Release);
        leader
            .state
            .thread_signals
            .lock()
            .blocked
            .insert(libc::SIGALRM);
        let control = leader.backend_signal_control().process;
        assert!(matches!(
            control.publish_alarm(process, alarm(process)),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        assert_eq!(
            control.alarm_recipients(process).unwrap(),
            vec![reverie::SignalRecipient {
                task: worker.signal_task_identity().unwrap()
            }]
        );
        assert!(leader.take_pending_signal_for_delivery().unwrap().is_none());
        assert!(worker.take_pending_signal_for_delivery().unwrap().is_none());
        let permit = reverie::SignalDeliveryPermit {
            task: worker.signal_task_identity().unwrap(),
            sequence: 1,
            site: None,
        };
        control.reserve_delivery(permit).unwrap();
        assert_eq!(
            worker
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(process)
        );
        control.release_delivery(permit).unwrap();
        control.release_delivery(permit).unwrap();
        assert!(
            control
                .release_delivery(reverie::SignalDeliveryPermit {
                    sequence: 2,
                    ..permit
                })
                .is_err()
        );
        assert!(control.alarm_recipients(process).unwrap().is_empty());
    }

    #[test]
    fn controlled_permit_is_bound_to_image_and_old_owner_can_settle_after_exec() {
        let mut executor = executor();
        let process = identity(&executor);
        executor
            .signal_registry
            .controlled
            .store(true, Ordering::Release);
        let control = executor.backend_signal_control().process;
        let permit = reverie::SignalDeliveryPermit {
            task: executor.signal_task_identity().unwrap(),
            sequence: 1,
            site: None,
        };
        control.reserve_delivery(permit).unwrap();
        assert_eq!(executor.delivery_permit(), Some(permit));
        executor.replace_after_exec(native_loaded_state(std::path::Path::new("/tmp")));
        assert_eq!(executor.delivery_permit(), None);
        assert_eq!(executor.owned_delivery_permit(), Some(permit));
        assert!(matches!(
            control.publish_alarm(process, alarm(process)),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        assert!(
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .is_none()
        );
        control.release_delivery(permit).unwrap();
        let fresh = reverie::SignalDeliveryPermit {
            sequence: 2,
            ..permit
        };
        control.reserve_delivery(fresh).unwrap();
        assert_eq!(
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(process)
        );
        control.release_delivery(fresh).unwrap();
    }

    #[test]
    fn controlled_parked_lease_does_not_borrow_another_permit_or_callback() {
        let mut executor = executor();
        executor.enable_signal_dequeues();
        executor
            .signal_registry
            .controlled
            .store(true, Ordering::Release);
        let site = executor.begin_signal_callback().unwrap();
        let control = executor.backend_signal_control().process;
        let permit = reverie::SignalDeliveryPermit {
            task: executor.signal_task_identity().unwrap(),
            sequence: 7,
            site: Some(site),
        };
        control.reserve_delivery(permit).unwrap();
        assert_eq!(
            executor.admit_signal_observation(site, reverie::ParkedObservationLease { nonce: 8 }),
            Err(Errno::EINVAL)
        );
        executor
            .admit_signal_observation(site, reverie::ParkedObservationLease { nonce: 7 })
            .unwrap();
        assert_eq!(
            executor.admit_signal_observation(site, reverie::ParkedObservationLease { nonce: 7 }),
            Err(Errno::EINVAL)
        );
        control.release_delivery(permit).unwrap();
    }

    #[test]
    fn inactive_publication_refuses_poisoned_file_table_without_effects() {
        let executor = executor();
        let id = identity(&executor);
        let control = executor.signal_registry.control();
        let files = executor.file_table.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = files.lock().unwrap();
                panic!("controlled authoritative-table poison");
            })
            .join()
            .is_err()
        );
        for _ in 0..2 {
            assert!(matches!(
                control.publish_alarm(id, alarm(id)),
                ProcessPublication::Rejected(PublicationRejection::Backend(errno))
                    if errno == Errno::EIO
            ));
        }
        let process = executor.state.process_signals.lock().unwrap();
        assert_eq!(
            process
                .shared_pending
                .pending_mask(&process.pending_generations)
                .to_bytes(),
            KernelSigset::default().to_bytes()
        );
        assert!(executor.signal_registry.failure.lock().unwrap().is_none());
        assert!(executor.file_table.is_poisoned());
    }

    #[test]
    fn inactive_publication_alarm_preserves_masks_dispositions_and_coalesces() {
        for handler in [libc::SIG_DFL as u64, libc::SIG_IGN as u64, 0x1234] {
            for blocked in [false, true] {
                let executor = executor();
                let id = identity(&executor);
                let control = executor.signal_registry.control();
                executor
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .dispositions
                    .insert(
                        libc::SIGALRM,
                        KernelSigaction {
                            handler,
                            ..Default::default()
                        },
                    );
                if blocked {
                    executor
                        .state
                        .thread_signals
                        .lock()
                        .blocked
                        .insert(libc::SIGALRM);
                }
                let before_thread = executor.state.thread_signals.lock().clone();
                let first = receipt(control.publish_alarm(id, alarm(id)));
                assert_eq!(first.change, PendingChange::Queued);
                let second = receipt(control.publish_alarm(id, alarm(id)));
                assert_eq!(second.change, PendingChange::Coalesced);
                assert_eq!(first.image, second.image);
                assert_eq!(first.pending_generation, 0);
                assert_eq!(
                    first.disposition,
                    match handler {
                        0 => PublicationDisposition::Default,
                        1 => PublicationDisposition::Ignored,
                        _ => PublicationDisposition::Caught,
                    }
                );
                assert_eq!(*executor.state.thread_signals.lock(), before_thread);
                assert_eq!(executor.state.logical_clock_ns, 0);
                assert_eq!(
                    executor
                        .state
                        .process_signals
                        .lock()
                        .unwrap()
                        .shared_pending
                        .take_matching(
                            {
                                let mut mask = KernelSigset::default();
                                mask.insert(libc::SIGALRM);
                                mask
                            },
                            &[0; 65]
                        ),
                    Some(alarm(id))
                );
            }
        }
    }

    #[test]
    fn inactive_publication_rejects_bad_event_reused_process_and_closed_run() {
        let mut executor = executor();
        let id = identity(&executor);
        let control = executor.signal_registry.control();
        let mut info = alarm(id).siginfo();
        info[127] = 1;
        let invalid = SignalEvent::new(
            libc::SIGALRM,
            info,
            reverie::SignalTarget::Process { pid: id.tgid },
        )
        .unwrap();
        assert_eq!(
            control.publish_alarm(id, invalid),
            ProcessPublication::Rejected(PublicationRejection::InvalidEvent)
        );
        assert!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .is_empty()
        );
        executor.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        // Numeric reuse in the same lifecycle cannot revive the old generation.
        executor
            .state
            .task_lifecycle
            .lock()
            .unwrap()
            .register(1, 1, 1, true);
        assert_eq!(
            control.publish_alarm(id, alarm(id)),
            ProcessPublication::Rejected(PublicationRejection::StaleProcess)
        );
        let signals = Arc::downgrade(&executor.state.process_signals);
        let files = Arc::downgrade(&executor.file_table);
        drop(executor);
        assert!(signals.upgrade().is_none());
        assert!(files.upgrade().is_none());
        assert_eq!(
            control.publish_alarm(id, alarm(id)),
            ProcessPublication::Rejected(PublicationRejection::Closed)
        );
    }

    #[test]
    fn inactive_publication_resolves_current_exec_image_and_surviving_thread() {
        let mut leader = executor();
        let mut worker = leader.thread_child(2).unwrap();
        let id = identity(&leader);
        let control = leader.signal_registry.control();
        leader.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        leader.release_files_on_exit();
        drop(leader);
        receipt(control.publish_alarm(id, alarm(id)));
        assert_eq!(
            worker
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(id)
        );
        worker.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(
            control.publish_alarm(id, alarm(id)),
            ProcessPublication::Rejected(PublicationRejection::StaleProcess)
        );
        drop(worker);

        let mut executor = executor();
        let control = executor.signal_registry.control();
        let id = identity(&executor);
        let first = receipt(control.publish_alarm(id, alarm(id)));
        let old = executor.state.process_signals.clone();
        executor.replace_after_exec(native_loaded_state(std::path::Path::new("/tmp")));
        // Exec preserves pending SIGALRM but resets the image binding.
        let second = receipt(control.publish_alarm(id, alarm(id)));
        assert_ne!(first.image, second.image);
        assert_eq!(second.change, PendingChange::Coalesced);
        assert_eq!(identity(&executor), id);
        assert!(!Arc::ptr_eq(&old, &executor.state.process_signals));
        assert_eq!(
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(id)
        );
        receipt(control.publish_alarm(id, alarm(id)));
        assert!(old.lock().unwrap().shared_pending.contains(libc::SIGALRM));
        assert_eq!(
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            alarm(id)
        );
    }

    #[test]
    fn inactive_publication_aliases_all_consumers_and_ignore_update_readiness() {
        let mut executor = executor();
        let id = identity(&executor);
        let control = executor.signal_registry.control();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let original = signalfd(&mut executor, &mut memory);
        let duplicate = call(
            &mut executor,
            &memory,
            libc::SYS_dup,
            [original as u64, 0, 0, 0, 0, 0],
        ) as i32;
        assert!(duplicate > original);
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_close,
                [original as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        for consumer in 0..3 {
            receipt(control.publish_alarm(id, alarm(id)));
            assert!(ready(&executor, duplicate));
            match consumer {
                0 => assert_eq!(
                    executor
                        .take_pending_signal_for_delivery()
                        .unwrap()
                        .unwrap()
                        .event,
                    alarm(id)
                ),
                1 => {
                    assert_eq!(
                        call(
                            &mut executor,
                            &memory,
                            libc::SYS_read,
                            [duplicate as u64, 0x100, 128, 0, 0, 0]
                        ),
                        128
                    );
                    let mut signo = [0; 4];
                    memory.read(0x100, &mut signo).unwrap();
                    assert_eq!(i32::from_ne_bytes(signo), libc::SIGALRM);
                }
                _ => assert_eq!(
                    call(
                        &mut executor,
                        &memory,
                        libc::SYS_rt_sigtimedwait,
                        [0x80, 0x100, 0, 8, 0, 0]
                    ),
                    i64::from(libc::SIGALRM)
                ),
            }
            assert!(!ready(&executor, duplicate));
        }
        receipt(control.publish_alarm(id, alarm(id)));
        let ignored = KernelSigaction {
            handler: libc::SIG_IGN as u64,
            ..Default::default()
        };
        memory.write(0x200, &ignored.encode()).unwrap();
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_rt_sigaction,
                [libc::SIGALRM as u64, 0x200, 0, 8, 0, 0]
            ),
            0
        );
        assert!(!ready(&executor, duplicate));
        assert!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .is_empty()
        );
        let later = receipt(control.publish_alarm(id, alarm(id)));
        assert_eq!(later.pending_generation, 1);
        assert!(ready(&executor, duplicate));
        // Closing an alias must not cause the private publisher to use its old
        // local descriptor snapshot or to write into a subsequently reused fd.
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_close,
                [duplicate as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        receipt(control.publish_alarm(id, alarm(id)));
        assert!(executor.file_table.lock().unwrap().files.is_empty());
    }

    #[test]
    fn inactive_publication_preflight_and_postcommit_failure_are_distinct() {
        let mut executor = executor();
        let id = identity(&executor);
        let control = executor.signal_registry.control();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd(&mut executor, &mut memory);
        let carrier = executor
            .file_table
            .lock()
            .unwrap()
            .files
            .remove(&fd)
            .unwrap();
        assert_eq!(
            control.publish_alarm(id, alarm(id)),
            ProcessPublication::Rejected(PublicationRejection::Backend(Errno::EBADF))
        );
        assert!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .is_empty()
        );
        // Deliberate backing-carrier corruption: real readiness write fails
        // EBADF after queue insertion. No production mutator installs this.
        executor
            .file_table
            .lock()
            .unwrap()
            .files
            .insert(fd, std::fs::File::open("/dev/null").unwrap());
        let ProcessPublication::FailedAfterCommit(failure) = control.publish_alarm(id, alarm(id))
        else {
            panic!("missing postcommit failure")
        };
        assert_eq!(failure.errno, Errno::EBADF);
        assert_eq!(failure.receipt.change, PendingChange::Queued);
        assert!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .contains(libc::SIGALRM)
        );
        assert_eq!(
            *executor.signal_registry.failure.lock().unwrap(),
            Some(failure)
        );
        executor
            .file_table
            .lock()
            .unwrap()
            .files
            .insert(fd, carrier);
        assert_eq!(
            control.publish_alarm(id, alarm(id)),
            ProcessPublication::Rejected(PublicationRejection::Terminal)
        );
    }

    #[test]
    fn inactive_publication_concurrent_dequeue_keeps_readiness_equal_to_pending() {
        let mut executor = executor();
        let id = identity(&executor);
        let control = executor.signal_registry.control();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd(&mut executor, &mut memory);
        for _ in 0..64 {
            receipt(control.publish_alarm(id, alarm(id)));
            let start = std::sync::Barrier::new(2);
            let (published, removed) = std::thread::scope(|scope| {
                let publisher = scope.spawn(|| {
                    start.wait();
                    receipt(control.publish_alarm(id, alarm(id)))
                });
                let consumer = scope.spawn(|| {
                    start.wait();
                    executor
                        .take_pending_signal_for_delivery()
                        .unwrap()
                        .unwrap()
                });
                (publisher.join().unwrap(), consumer.join().unwrap())
            });
            assert_eq!(removed.event, alarm(id));
            let queued_after_remove = published.change == PendingChange::Queued;
            assert_eq!(
                executor
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .shared_pending
                    .contains(libc::SIGALRM),
                queued_after_remove
            );
            assert_eq!(ready(&executor, fd), queued_after_remove);
            if queued_after_remove {
                assert_eq!(
                    executor
                        .take_pending_signal_for_delivery()
                        .unwrap()
                        .unwrap()
                        .event,
                    alarm(id)
                );
            }
            assert!(!ready(&executor, fd));
        }
    }

    #[test]
    fn child_publication_requires_exact_generation_parent_status_and_waitability() {
        use reverie::ChildExitPublicationResult::RejectedBeforeCommit;

        let mut parent = executor();
        let parent_id = identity(&parent);
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        let wrong_parent = parent.fork_child(3, false, false).unwrap();
        let wrong_parent_id = identity(&wrong_parent);
        let control = parent.backend_signal_control().process;
        let completion =
            child_completion(parent_id, child_id, reverie::ExitStatus::Exited(23), true);

        assert_eq!(
            control.publish_child_exit(completion),
            RejectedBeforeCommit(Errno::EINVAL),
            "a live child has no committed terminal status"
        );
        child.retire_current_thread(reverie::ExitStatus::Exited(23), false);

        for (wrong, expected) in [
            (
                reverie::ChildExitCompletion {
                    child: SignalProcessId {
                        generation: child_id.generation + 1,
                        ..child_id
                    },
                    ..completion
                },
                Errno::EINVAL,
            ),
            (
                reverie::ChildExitCompletion {
                    parent: SignalProcessId {
                        generation: parent_id.generation + 1,
                        ..parent_id
                    },
                    ..completion
                },
                Errno::ESRCH,
            ),
            (
                reverie::ChildExitCompletion {
                    parent: wrong_parent_id,
                    ..completion
                },
                Errno::EINVAL,
            ),
            (
                reverie::ChildExitCompletion {
                    status: reverie::ExitStatus::Exited(24),
                    ..completion
                },
                Errno::EINVAL,
            ),
            (
                reverie::ChildExitCompletion {
                    waitable: false,
                    ..completion
                },
                Errno::EINVAL,
            ),
            (
                reverie::ChildExitCompletion {
                    status: reverie::ExitStatus::Exited(256),
                    ..completion
                },
                Errno::EINVAL,
            ),
            (
                reverie::ChildExitCompletion {
                    user_ticks: -1,
                    ..completion
                },
                Errno::EINVAL,
            ),
            (
                reverie::ChildExitCompletion {
                    system_ticks: -1,
                    ..completion
                },
                Errno::EINVAL,
            ),
        ] {
            assert_eq!(
                control.publish_child_exit(wrong),
                RejectedBeforeCommit(expected)
            );
        }

        let receipt = child_receipt(control.publish_child_exit(completion));
        assert_eq!(receipt.completion, completion);
        assert_eq!(receipt.effect, reverie::ChildExitPublicationEffect::Queued);
        let event = parent
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap()
            .event;
        let info = event.siginfo();
        assert_eq!(event.signal(), libc::SIGCHLD);
        assert_eq!(i32::from_ne_bytes(info[16..20].try_into().unwrap()), 2);
        assert_eq!(u32::from_ne_bytes(info[20..24].try_into().unwrap()), 0);
        assert_eq!(i64::from_ne_bytes(info[32..40].try_into().unwrap()), 0);
        assert_eq!(i64::from_ne_bytes(info[40..48].try_into().unwrap()), 0);

        assert_eq!(
            child_receipt(control.publish_child_exit(completion)),
            receipt,
            "an exact duplicate returns the retained acknowledgement"
        );
        assert!(
            parent.take_pending_signal_for_delivery().unwrap().is_none(),
            "an acknowledged duplicate must not enqueue a second SIGCHLD"
        );
        assert_eq!(
            control.publish_child_exit(reverie::ChildExitCompletion {
                uid: completion.uid + 1,
                ..completion
            }),
            RejectedBeforeCommit(Errno::EINVAL),
            "conflicting data for one child generation must fail before mutation"
        );

        drop(child);
        drop(wrong_parent);
        let replacement = parent.fork_child(2, false, false).unwrap();
        assert_ne!(identity(&replacement).generation, child_id.generation);
        assert_eq!(
            child_receipt(control.publish_child_exit(completion)),
            receipt,
            "the exact acknowledgement survives executor retirement and numeric PID reuse"
        );
        assert!(parent.state.children.is_empty());
    }

    #[test]
    fn process_registry_keeps_reused_numeric_pids_generation_distinct() {
        let parent = executor();
        let mut old = parent.fork_child(2, false, false).unwrap();
        let old_id = identity(&old);
        old.retire_current_thread(reverie::ExitStatus::Exited(23), false);
        let replacement = parent.fork_child(2, false, false).unwrap();
        let replacement_id = identity(&replacement);
        assert_ne!(old_id.generation, replacement_id.generation);
        assert_eq!(
            parent.signal_registry.lookup(old_id).unwrap().identity,
            old_id
        );
        assert_eq!(
            parent
                .signal_registry
                .lookup(replacement_id)
                .unwrap()
                .identity,
            replacement_id
        );
        drop(old);
        assert!(parent.signal_registry.lookup(old_id).is_none());
        assert!(parent.signal_registry.lookup(replacement_id).is_some());
    }

    #[test]
    fn child_publication_encodes_exited_killed_and_core_statuses() {
        for (status, expected_code, expected_status) in [
            (reverie::ExitStatus::Exited(37), libc::CLD_EXITED, 37),
            (
                reverie::ExitStatus::Signaled(reverie::Signal::SIGTERM, false),
                libc::CLD_KILLED,
                libc::SIGTERM,
            ),
            (
                reverie::ExitStatus::Signaled(reverie::Signal::SIGABRT, true),
                libc::CLD_DUMPED,
                libc::SIGABRT,
            ),
        ] {
            let mut parent = executor();
            let mut child = parent.fork_child(2, false, false).unwrap();
            let completion = child_completion(identity(&parent), identity(&child), status, true);
            child.retire_current_thread(status, false);
            let receipt = child_receipt(
                parent
                    .backend_signal_control()
                    .process
                    .publish_child_exit(completion),
            );
            assert_eq!(receipt.completion.status, status);
            let event = parent
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event;
            let info = event.siginfo();
            assert_eq!(
                i32::from_ne_bytes(info[8..12].try_into().unwrap()),
                expected_code
            );
            assert_eq!(
                i32::from_ne_bytes(info[24..28].try_into().unwrap()),
                expected_status
            );
        }
    }

    #[test]
    fn child_publication_distinguishes_explicit_ignore_from_no_cldwait() {
        for (action, expected_effect, pending) in [
            (
                KernelSigaction {
                    handler: libc::SIG_IGN as u64,
                    ..Default::default()
                },
                reverie::ChildExitPublicationEffect::SuppressedExplicitIgnore,
                false,
            ),
            (
                KernelSigaction {
                    handler: libc::SIG_DFL as u64,
                    flags: libc::SA_NOCLDWAIT as u64,
                    ..Default::default()
                },
                reverie::ChildExitPublicationEffect::Queued,
                true,
            ),
        ] {
            let parent = executor();
            parent
                .state
                .process_signals
                .lock()
                .unwrap()
                .dispositions
                .insert(libc::SIGCHLD, action);
            let mut child = parent.fork_child(2, false, false).unwrap();
            let completion = child_completion(
                identity(&parent),
                identity(&child),
                reverie::ExitStatus::Exited(7),
                false,
            );
            child.retire_current_thread(completion.status, false);
            let control = parent.backend_signal_control().process;
            let receipt = child_receipt(control.publish_child_exit(completion));
            assert_eq!(receipt.effect, expected_effect);
            assert_eq!(
                child_receipt(control.publish_child_exit(completion)),
                receipt,
                "an exact duplicate must retain the original suppression/queue receipt"
            );
            assert_eq!(
                parent
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .shared_pending
                    .contains(libc::SIGCHLD),
                pending
            );
        }
    }

    #[test]
    fn child_publication_uses_exit_time_disposition_after_parent_policy_changes() {
        let install = |parent: &mut ElfExecutor, action: KernelSigaction| {
            let mut memory = GuestMemory::new(0, 4096).unwrap();
            memory.write(0x100, &action.encode()).unwrap();
            assert_eq!(
                call(
                    parent,
                    &memory,
                    libc::SYS_rt_sigaction,
                    [libc::SIGCHLD as u64, 0x100, 0, 8, 0, 0],
                ),
                0,
            );
        };

        let mut parent = executor();
        let mut child = parent.fork_child(2, false, false).unwrap();
        let completion = child_completion(
            identity(&parent),
            identity(&child),
            reverie::ExitStatus::Exited(7),
            true,
        );
        child.retire_current_thread(completion.status, false);
        let exit_generation = match child
            .signal_registry
            .process_family_exit(completion.child)
            .unwrap()
        {
            ProcessFamilyExit::Child(snapshot) => snapshot.pending_generation,
            other => panic!("unexpected child family exit: {other:?}"),
        };
        install(
            &mut parent,
            KernelSigaction {
                handler: libc::SIG_IGN as u64,
                ..Default::default()
            },
        );
        let receipt = child_receipt(
            parent
                .backend_signal_control()
                .process
                .publish_child_exit(completion),
        );
        assert_eq!(receipt.completion, completion);
        assert_eq!(receipt.pending_generation, exit_generation);
        assert_eq!(
            receipt.effect,
            reverie::ChildExitPublicationEffect::DiscardedByDispositionChange
        );
        assert!(
            !parent
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .contains(libc::SIGCHLD),
            "a delayed child event cannot resurrect the discarded generation",
        );

        for (action, expected_effect) in [
            (
                KernelSigaction {
                    handler: libc::SIG_IGN as u64,
                    ..Default::default()
                },
                reverie::ChildExitPublicationEffect::SuppressedExplicitIgnore,
            ),
            (
                KernelSigaction {
                    handler: libc::SIG_DFL as u64,
                    flags: libc::SA_NOCLDWAIT as u64,
                    ..Default::default()
                },
                reverie::ChildExitPublicationEffect::DiscardedByDispositionChange,
            ),
        ] {
            let mut parent = executor();
            install(&mut parent, action);
            let mut child = parent.fork_child(2, false, false).unwrap();
            let completion = child_completion(
                identity(&parent),
                identity(&child),
                reverie::ExitStatus::Exited(9),
                false,
            );
            child.retire_current_thread(completion.status, false);
            install(&mut parent, KernelSigaction::default());
            let receipt = child_receipt(
                parent
                    .backend_signal_control()
                    .process
                    .publish_child_exit(completion),
            );
            assert_eq!(receipt.completion, completion);
            assert_eq!(receipt.effect, expected_effect);
        }
    }

    #[test]
    fn process_family_fails_closed_until_direct_children_are_reaped_or_auto_reaped() {
        let parent = executor();
        let mut live_owner = parent.fork_child(2, false, false).unwrap();
        let live_descendant = live_owner.fork_child(3, false, false).unwrap();
        let live_owner_id = identity(&live_owner);
        let live_descendant_id = identity(&live_descendant);
        live_owner.retire_current_thread(reverie::ExitStatus::Exited(7), false);
        assert_eq!(
            live_owner
                .signal_registry
                .process_family_exit(live_owner_id),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported {
                child: live_descendant_id,
            })
        );

        let parent = executor();
        let mut zombie_owner = parent.fork_child(2, false, false).unwrap();
        let mut zombie = zombie_owner.fork_child(3, false, false).unwrap();
        let zombie_owner_id = identity(&zombie_owner);
        let zombie_id = identity(&zombie);
        zombie.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        zombie_owner.retire_current_thread(reverie::ExitStatus::Exited(7), false);
        assert!(matches!(
            zombie_owner
                .signal_registry
                .process_family_exit(zombie_owner_id),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported { child })
                if child == zombie_id
        ));

        let parent = executor();
        let mut reaping_owner = parent.fork_child(2, false, false).unwrap();
        let mut reaped = reaping_owner.fork_child(3, false, false).unwrap();
        let reaping_owner_id = identity(&reaping_owner);
        reaped.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        assert!(
            reaping_owner
                .signal_registry
                .consume_child_wait(reaping_owner_id, 3)
        );
        reaping_owner.retire_current_thread(reverie::ExitStatus::Exited(7), false);
        assert!(matches!(
            reaping_owner
                .signal_registry
                .process_family_exit(reaping_owner_id),
            Some(ProcessFamilyExit::Child(_))
        ));

        for action in [
            KernelSigaction {
                handler: libc::SIG_IGN as u64,
                ..Default::default()
            },
            KernelSigaction {
                handler: libc::SIG_DFL as u64,
                flags: libc::SA_NOCLDWAIT as u64,
                ..Default::default()
            },
        ] {
            let parent = executor();
            let mut owner = parent.fork_child(2, false, false).unwrap();
            owner
                .state
                .process_signals
                .lock()
                .unwrap()
                .dispositions
                .insert(libc::SIGCHLD, action);
            let mut auto_reaped = owner.fork_child(3, false, false).unwrap();
            let owner_id = identity(&owner);
            auto_reaped.retire_current_thread(reverie::ExitStatus::Exited(9), false);
            owner.retire_current_thread(reverie::ExitStatus::Exited(7), false);
            assert!(matches!(
                owner.signal_registry.process_family_exit(owner_id),
                Some(ProcessFamilyExit::Child(_))
            ));
        }
    }

    #[test]
    fn terminal_root_preserves_a_live_parent_wait_before_direct_parent_teardown() {
        const INFO: u64 = 0x100;
        const STATUS: u64 = 0x200;

        let mut root = executor();
        let mut child = root.fork_child(2, false, false).unwrap();
        let mut grandchild = child.fork_child(3, false, false).unwrap();
        let root_id = identity(&root);
        let child_id = identity(&child);
        let grandchild_id = identity(&grandchild);

        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        assert_eq!(
            root.signal_registry.process_family_exit(root_id),
            Some(ProcessFamilyExit::Root),
        );
        grandchild.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        let completion = match grandchild
            .signal_registry
            .process_family_exit(grandchild_id)
            .unwrap()
        {
            ProcessFamilyExit::Child(snapshot) => snapshot.completion,
            other => panic!("live direct parent lost its waitable child: {other:?}"),
        };
        assert_eq!(completion.parent, child_id);
        assert_eq!(completion.child, grandchild_id);
        assert_eq!(completion.status, reverie::ExitStatus::Exited(3));
        assert!(completion.waitable);
        child
            .record_child_completion(
                grandchild_id,
                crate::executor::ChildCompletion::from_waitability(
                    completion.status,
                    completion.waitable,
                ),
            )
            .unwrap();

        let memory = GuestMemory::new(0, 4096).unwrap();
        assert_eq!(
            child.execute(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [
                        libc::P_PID as u64,
                        3,
                        INFO,
                        (libc::WEXITED | libc::WNOWAIT | libc::WNOHANG) as u64,
                        0,
                        0,
                    ],
                ),
                &memory,
            ),
            0,
        );
        let info: libc::siginfo_t = read_struct(&memory, INFO);
        // SAFETY: waitid writes the SIGCHLD variant of siginfo_t.
        unsafe {
            assert_eq!(info.si_pid(), 3);
            assert_eq!(info.si_status(), 3);
        }
        assert!(
            child
                .signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .direct_children
                .get(&process_key(child_id))
                .is_some_and(|children| children.get(&process_key(grandchild_id))
                    == Some(&DirectChildState::WaitableZombie)),
            "WNOWAIT must preserve the exact waitable family edge",
        );
        assert_eq!(
            child.execute(
                &SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [3, STATUS, libc::WNOHANG as u64, 0, 0, 0],
                ),
                &memory,
            ),
            3,
        );
        let mut status = [0; std::mem::size_of::<libc::c_int>()];
        memory.read(STATUS, &mut status).unwrap();
        assert_eq!(libc::c_int::from_le_bytes(status), 3 << 8);

        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(2),
            }),
        );
        assert!(
            root.signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .direct_children
                .is_empty(),
            "direct-parent teardown must retire every exact child edge",
        );
    }

    #[test]
    fn terminal_direct_parent_tears_down_a_later_child_without_publication() {
        let mut root = executor();
        let mut child = root.fork_child(2, false, false).unwrap();
        let mut grandchild = child.fork_child(3, false, false).unwrap();
        let child_id = identity(&child);
        let grandchild_id = identity(&grandchild);

        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(2),
            }),
        );
        grandchild.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            grandchild
                .signal_registry
                .process_family_exit(grandchild_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(3),
            }),
        );
        assert!(
            root.signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .direct_children
                .is_empty(),
        );
    }

    #[test]
    fn live_root_refuses_but_terminal_root_consumes_the_same_unreaped_family_shape() {
        let root = executor();
        let mut child = root.fork_child(2, false, false).unwrap();
        let grandchild = child.fork_child(3, false, false).unwrap();
        let child_id = identity(&child);
        let grandchild_id = identity(&grandchild);

        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported {
                child: grandchild_id,
            }),
            "a middle process that exits under a live root still requires unsupported reparenting",
        );

        let mut root = executor();
        let mut child = root.fork_child(2, false, false).unwrap();
        let mut grandchild = child.fork_child(3, false, false).unwrap();
        let root_id = identity(&root);
        let child_id = identity(&child);
        let grandchild_id = identity(&grandchild);

        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        assert_eq!(
            root.signal_registry.process_family_exit(root_id),
            Some(ProcessFamilyExit::Root),
        );
        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(2),
            }),
            "after the root becomes terminal, the same middle exit belongs to whole-run teardown",
        );
        grandchild.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            grandchild
                .signal_registry
                .process_family_exit(grandchild_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(3),
            }),
        );
        assert!(
            root.signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .direct_children
                .is_empty(),
            "terminal-root consumption must retire the same family's exact edges",
        );
    }

    /// A traced root beneath an outside PID-namespace init, as Hermit runs KVM
    /// (root PID 3, `getppid() == 1`). `executor()` is instead itself init.
    fn outside_init_root() -> ElfExecutor {
        let mut state = native_loaded_state(std::path::Path::new("/tmp"));
        state.pid = 3;
        state.pgid = 3;
        state.tid = 3;
        state.ppid = 1;
        state.task_lifecycle = Arc::new(Mutex::new(TaskLifecycleTable::with_root(3, 3, 3, true)));
        ElfExecutor::new(state, false)
    }

    fn getppid(executor: &mut ElfExecutor) -> i64 {
        let memory = GuestMemory::new(0, 4096).unwrap();
        call(executor, &memory, libc::SYS_getppid, [0; 6])
    }

    fn family_snapshot(
        executor: &ElfExecutor,
    ) -> (
        BTreeMap<ProcessKey, BTreeMap<ProcessKey, DirectChildState>>,
        BTreeSet<ProcessKey>,
    ) {
        let family = executor
            .signal_registry
            .family
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (
            family.direct_children.clone(),
            family.namespace_orphans.clone(),
        )
    }

    #[test]
    fn outside_init_adopts_live_and_zombie_orphans_by_exact_generation() {
        let root = outside_init_root();
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        let mut orphan_thread = orphan.thread_child(10).unwrap();
        let mut zombie = parent.fork_child(8, false, false).unwrap();
        let zombie_id = identity(&zombie);
        assert_eq!(getppid(&mut orphan), 6);
        assert_eq!(getppid(&mut orphan_thread), 6);

        zombie.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        assert!(matches!(
            zombie.signal_registry.process_family_exit(zombie_id),
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.parent == parent_id && snapshot.completion.waitable
        ));

        // The failing Hermit shape: a middle process exits under its live
        // parent while it still has a running child and an unreaped zombie.
        parent.retire_current_thread(reverie::ExitStatus::Exited(4), false);
        assert!(matches!(
            parent.signal_registry.process_family_exit(parent_id),
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.parent == root_id
                    && snapshot.completion.child == parent_id
                    && snapshot.completion.status == reverie::ExitStatus::Exited(4)
                    && snapshot.completion.waitable
        ));
        let (edges, orphans) = family_snapshot(&root);
        assert_eq!(
            edges,
            BTreeMap::from([(
                process_key(root_id),
                BTreeMap::from([(process_key(parent_id), DirectChildState::WaitableZombie)]),
            )]),
            "the exiting parent keeps only its own wait edge; its children moved atomically",
        );
        assert_eq!(orphans, BTreeSet::from([process_key(orphan_id)]));
        assert!(
            !root.signal_registry.consume_child_wait(parent_id, 8),
            "init reaped the zombie; its former parent cannot reap it again",
        );
        assert_eq!(
            zombie.signal_registry.process_family_exit(zombie_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(9),
            }),
            "no callback may name the zombie's terminal parent",
        );
        assert_eq!(getppid(&mut orphan), 1);
        assert_eq!(
            getppid(&mut orphan_thread),
            1,
            "threads share the process parent"
        );
        assert_eq!(
            orphan.parent_pid(),
            Some(reverie::Pid::from_raw(6)),
            "the traced-tree parent stays the fork-time parent, as under ptrace",
        );

        // An adopted orphan's own children are reparented when it exits.
        let mut grandchild = orphan.fork_child(9, false, false).unwrap();
        let grandchild_id = identity(&grandchild);
        assert_eq!(getppid(&mut grandchild), 7);
        orphan_thread.retire_current_thread(reverie::ExitStatus::Exited(5), true);
        orphan.retire_current_thread(reverie::ExitStatus::Exited(5), false);
        assert_eq!(
            orphan.signal_registry.process_family_exit(orphan_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(5),
            }),
        );
        assert_eq!(
            family_snapshot(&root).1,
            BTreeSet::from([process_key(grandchild_id)])
        );
        assert_eq!(getppid(&mut grandchild), 1);
        grandchild.retire_current_thread(
            reverie::ExitStatus::Signaled(reverie::Signal::SIGTERM, false),
            false,
        );
        assert_eq!(
            grandchild
                .signal_registry
                .process_family_exit(grandchild_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Signaled(reverie::Signal::SIGTERM, false),
            }),
        );

        assert!(root.signal_registry.consume_child_wait(root_id, 6));
        assert!(!root.signal_registry.consume_child_wait(root_id, 6));
        let (edges, orphans) = family_snapshot(&root);
        assert!(edges.is_empty(), "no stale family edge survives: {edges:?}");
        assert!(orphans.is_empty(), "no stale orphan survives: {orphans:?}");
    }

    #[test]
    fn outside_init_adopts_a_terminal_roots_children() {
        let mut root = outside_init_root();
        let root_id = identity(&root);
        let mut child = root.fork_child(6, false, false).unwrap();
        let child_id = identity(&child);
        let mut zombie = root.fork_child(7, false, false).unwrap();
        zombie.retire_current_thread(reverie::ExitStatus::Exited(2), false);

        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        assert_eq!(
            root.signal_registry.process_family_exit(root_id),
            Some(ProcessFamilyExit::Root),
        );
        assert_eq!(
            family_snapshot(&root),
            (BTreeMap::new(), BTreeSet::from([process_key(child_id)])),
        );
        assert_eq!(getppid(&mut child), 1);
        child.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(3),
            }),
        );
        assert_eq!(family_snapshot(&root), (BTreeMap::new(), BTreeSet::new()));
    }

    #[test]
    fn outside_init_orphan_is_not_claimed_by_a_process_reusing_its_parent_pid() {
        let root = outside_init_root();
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert!(root.signal_registry.consume_child_wait(root_id, 6));
        drop(parent);

        let mut reused = root.fork_child(6, false, false).unwrap();
        let reused_id = identity(&reused);
        assert_ne!(reused_id, parent_id);
        assert_eq!(reused_id.tgid, parent_id.tgid);

        orphan.retire_current_thread(reverie::ExitStatus::Exited(7), false);
        assert_eq!(
            orphan.signal_registry.process_family_exit(orphan_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(7),
            }),
        );
        assert!(
            !root.signal_registry.consume_child_wait(reused_id, 7),
            "a reused parent PID never inherits the orphan's status",
        );
        reused.retire_current_thread(reverie::ExitStatus::Exited(8), false);
        assert!(matches!(
            reused.signal_registry.process_family_exit(reused_id),
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.parent == root_id && snapshot.completion.child == reused_id
        ));
        assert_eq!(
            family_snapshot(&root),
            (
                BTreeMap::from([(
                    process_key(root_id),
                    BTreeMap::from([(process_key(reused_id), DirectChildState::WaitableZombie)]),
                )]),
                BTreeSet::new(),
            ),
        );
    }

    #[test]
    fn outside_init_orphan_record_never_classifies_another_generation_of_its_pid() {
        // Ledger-level PID-reuse control: two generations share numeric PID 7.
        // Only the exact generation that was orphaned belongs to init; the
        // other remains the live root's waitable child with its own parent.
        let root = outside_init_root();
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(
            family_snapshot(&root).1,
            BTreeSet::from([process_key(orphan_id)])
        );

        let mut same_pid = root.fork_child(7, false, false).unwrap();
        let same_pid_id = identity(&same_pid);
        assert_eq!(same_pid_id.tgid, orphan_id.tgid);
        assert_ne!(same_pid_id.generation, orphan_id.generation);
        assert_eq!(getppid(&mut same_pid), 3);
        same_pid.retire_current_thread(reverie::ExitStatus::Exited(5), false);
        assert!(matches!(
            same_pid.signal_registry.process_family_exit(same_pid_id),
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.parent == root_id
                    && snapshot.completion.child == same_pid_id
                    && snapshot.completion.waitable
        ));
        assert_eq!(
            family_snapshot(&root).1,
            BTreeSet::from([process_key(orphan_id)]),
            "the orphan record belongs to its exact generation only",
        );
        assert_eq!(orphan.state.orphan_reaper_pid.load(Ordering::SeqCst), 1);
        assert_eq!(same_pid.state.orphan_reaper_pid.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn outside_init_reparenting_and_child_exit_serialize_exactly_once() {
        let run = |parent_first: Option<bool>| {
            let root = outside_init_root();
            let root_id = identity(&root);
            let mut parent = root.fork_child(6, false, false).unwrap();
            let parent_id = identity(&parent);
            let mut child = parent.fork_child(7, false, false).unwrap();
            let child_id = identity(&child);
            match parent_first {
                Some(true) => {
                    parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
                    child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
                }
                Some(false) => {
                    child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
                    parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
                }
                None => {
                    let barrier = std::sync::Barrier::new(2);
                    std::thread::scope(|scope| {
                        scope.spawn(|| {
                            barrier.wait();
                            parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
                        });
                        scope.spawn(|| {
                            barrier.wait();
                            child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
                        });
                    });
                }
            }
            assert!(matches!(
                parent.signal_registry.process_family_exit(parent_id),
                Some(ProcessFamilyExit::Child(snapshot)) if snapshot.completion.parent == root_id
            ));
            let child_exit = child.signal_registry.process_family_exit(child_id).unwrap();
            let reaper = child.state.orphan_reaper_pid.load(Ordering::SeqCst);
            // Nothing claimed the child's exit for a parent callback, so in
            // both orders init reaps it and the parent is never notified.
            assert_eq!(
                child_exit,
                ProcessFamilyExit::ReapedByNamespaceInit {
                    status: reverie::ExitStatus::Exited(2),
                },
                "child exit lost its single owner",
            );
            let child_first = match reaper {
                // Child first: the parent's exit retired the unclaimed zombie
                // and its edge. The dead child was never relabeled.
                0 => true,
                // Parent first: init adopted the live child and reaps it.
                1 => false,
                other => panic!("unexpected reaper label {other}"),
            };
            assert_eq!(
                family_snapshot(&root),
                (
                    BTreeMap::from([(
                        process_key(root_id),
                        BTreeMap::from([(
                            process_key(parent_id),
                            DirectChildState::WaitableZombie
                        )]),
                    )]),
                    BTreeSet::new(),
                ),
            );
            child_first
        };
        assert!(!run(Some(true)));
        assert!(run(Some(false)));
        for _ in 0..64 {
            run(None);
        }
    }

    #[test]
    fn unclaimed_zombie_status_passes_to_namespace_init_when_its_parent_exits() {
        let root = outside_init_root();
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut child = parent.fork_child(7, false, false).unwrap();
        let child_id = identity(&child);
        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        assert!(matches!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::Child(snapshot)) if snapshot.completion.parent == parent_id
        ));

        // The parent exits before the child's runtime claims its callback. A
        // later callback would name a terminal parent; init reaps it instead.
        parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        let reaped = ProcessFamilyExit::ReapedByNamespaceInit {
            status: reverie::ExitStatus::Exited(2),
        };
        assert_eq!(
            child.signal_registry.claim_child_exit(child_id),
            Some(reaped)
        );
        assert_eq!(child.claim_process_family_exit().unwrap(), reaped);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(reaped)
        );
        assert!(!root.signal_registry.consume_child_wait(parent_id, 7));
        assert_eq!(
            child.state.orphan_reaper_pid.load(Ordering::SeqCst),
            0,
            "an already-dead child is never relabeled",
        );
        assert_eq!(
            family_snapshot(&root),
            (
                BTreeMap::from([(
                    process_key(root_id),
                    BTreeMap::from([(process_key(parent_id), DirectChildState::WaitableZombie)]),
                )]),
                BTreeSet::new(),
            ),
        );
    }

    #[test]
    fn claimed_child_exit_keeps_its_parent_callback_when_the_parent_then_exits() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut child = parent.fork_child(7, false, false).unwrap();
        let child_id = identity(&child);
        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        let claimed = child.claim_process_family_exit().unwrap();
        assert!(matches!(
            claimed,
            ProcessFamilyExit::Child(snapshot)
                if snapshot.completion.parent == parent_id
                    && snapshot.completion.status == reverie::ExitStatus::Exited(2)
        ));

        // Once claimed, the callback is the Tool's to fence; the parent's
        // exit no longer changes the result the runtime already acted on.
        parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(claimed)
        );
        assert_eq!(
            child.signal_registry.claim_child_exit(child_id),
            Some(claimed)
        );
        assert!(
            !root.signal_registry.consume_child_wait(parent_id, 7),
            "the parent's exit still retires the zombie's wait edge",
        );
    }

    #[test]
    fn child_exit_claim_and_parent_reparenting_serialize() {
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Order {
            ClaimFirst,
            ReparentFirst,
            Raced,
        }
        // Returns which of the two outcomes the claim observed.
        let run = |order: Order| {
            let root = outside_init_root();
            let mut parent = root.fork_child(6, false, false).unwrap();
            let parent_id = identity(&parent);
            let mut child = parent.fork_child(7, false, false).unwrap();
            let child_id = identity(&child);
            child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
            let claimed = match order {
                Order::ClaimFirst => {
                    let claimed = child.signal_registry.claim_child_exit(child_id);
                    parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
                    claimed
                }
                Order::ReparentFirst => {
                    parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
                    child.signal_registry.claim_child_exit(child_id)
                }
                Order::Raced => {
                    let barrier = std::sync::Barrier::new(2);
                    std::thread::scope(|scope| {
                        let claim = scope.spawn(|| {
                            barrier.wait();
                            child.signal_registry.claim_child_exit(child_id)
                        });
                        scope.spawn(|| {
                            barrier.wait();
                            parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
                        });
                        claim.join().unwrap()
                    })
                }
            };
            assert_eq!(
                claimed,
                child.signal_registry.process_family_exit(child_id),
                "a claimed family result is final",
            );
            match claimed {
                Some(ProcessFamilyExit::Child(snapshot)) => {
                    assert_eq!(snapshot.completion.parent, parent_id);
                    Order::ClaimFirst
                }
                Some(ProcessFamilyExit::ReapedByNamespaceInit { status }) => {
                    assert_eq!(status, reverie::ExitStatus::Exited(2));
                    Order::ReparentFirst
                }
                other => panic!("child exit lost its single owner: {other:?}"),
            }
        };
        // Each order has exactly one outcome.
        assert_eq!(run(Order::ClaimFirst), Order::ClaimFirst);
        assert_eq!(run(Order::ReparentFirst), Order::ReparentFirst);
        // Racing host threads may produce either one; `run` panics on any
        // other. The embedder, not this ledger, fixes which.
        for _ in 0..64 {
            run(Order::Raced);
        }
    }

    #[test]
    fn namespace_init_reaping_never_rewrites_a_failed_child() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut child = parent.fork_child(7, false, false).unwrap();
        let child_id = identity(&child);
        let mut peer = child.thread_child(8).unwrap();
        peer.retire_current_thread(reverie::ExitStatus::Exited(3), true);
        assert!(matches!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::Child(_))
        ));
        child.retire_failed_thread();
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::Failed)
        );
        parent.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::Failed),
            "reaping an unclaimed exit never masks a process failure",
        );
    }

    fn open_proc(
        executor: &mut ElfExecutor,
        memory: &mut GuestMemory,
        path: &str,
        flags: i32,
    ) -> i64 {
        memory.write(0x100, format!("{path}\0").as_bytes()).unwrap();
        call(
            executor,
            memory,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, 0x100, flags as u64, 0, 0, 0],
        )
    }

    /// One guest read of at most `count` bytes from `fd`'s current position.
    fn read_proc_once(
        executor: &mut ElfExecutor,
        memory: &GuestMemory,
        fd: i64,
        count: u64,
    ) -> String {
        let count = call(
            executor,
            memory,
            libc::SYS_read,
            [fd as u64, 0x400, count, 0, 0, 0],
        );
        assert!(count >= 0, "read failed: {count}");
        let mut bytes = vec![0; count as usize];
        memory.read(0x400, &mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    /// Read `fd` from its current position to EOF in `chunk`-byte reads.
    fn read_proc(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i64, chunk: u64) -> String {
        let mut content = String::new();
        loop {
            let bytes = read_proc_once(executor, memory, fd, chunk);
            if bytes.is_empty() {
                return content;
            }
            content.push_str(&bytes);
        }
    }

    #[test]
    fn proc_stat_and_status_opened_before_reparenting_report_the_new_parent() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut child = parent.fork_child(7, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let stat = open_proc(&mut child, &mut memory, "/proc/self/stat", libc::O_RDONLY);
        let status = open_proc(&mut child, &mut memory, "/proc/7/status", libc::O_RDONLY);
        let restarted = open_proc(&mut child, &mut memory, "/proc/self/status", libc::O_RDONLY);
        let partial = open_proc(&mut child, &mut memory, "/proc/self/stat", libc::O_RDONLY);
        assert!(stat >= 0 && status >= 0 && restarted >= 0 && partial >= 0);
        // Linux renders the whole single record when a read starts the
        // sequence, and later reads drain that buffer.
        assert!(read_proc(&mut child, &memory, restarted, 64).contains("\nPPid:\t6\n"));
        let head = read_proc_once(&mut child, &memory, partial, 4);
        assert_eq!(head, "7 (t");

        parent.retire_current_thread(reverie::ExitStatus::Exited(0), false);
        assert_eq!(getppid(&mut child), 1);
        let stat_text = read_proc(&mut child, &memory, stat, 64);
        assert!(
            stat_text.starts_with("7 (test) R 1 0 0 0 -1 0 "),
            "{stat_text}"
        );
        let status_text = read_proc(&mut child, &memory, status, 64);
        assert!(
            status_text.contains("\nPid:\t7\nPPid:\t1\n"),
            "{status_text}"
        );

        // A drained sequence stays at EOF until it restarts at offset zero.
        assert_eq!(read_proc(&mut child, &memory, restarted, 64), "");
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_lseek,
                [restarted as u64, 0, libc::SEEK_SET as u64, 0, 0, 0]
            ),
            0
        );
        assert!(read_proc(&mut child, &memory, restarted, 64).contains("\nPPid:\t1\n"));
        let tail = read_proc(&mut child, &memory, partial, 64);
        assert!(
            format!("{head}{tail}").starts_with("7 (test) R 6 "),
            "a started sequence keeps the record it rendered: {head}{tail}",
        );
        let count = call(
            &mut child,
            &memory,
            libc::SYS_pread64,
            [partial as u64, 0x400, 64, 0, 0, 0],
        );
        assert!(count > 0);
        let mut bytes = vec![0; count as usize];
        memory.read(0x400, &mut bytes).unwrap();
        assert!(
            bytes.starts_with(b"7 (test) R 1 "),
            "{:?}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn proc_stat_and_status_descriptors_expose_no_stale_backing() {
        let root = outside_init_root();
        let mut child = root.fork_child(6, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        for (name, path) in [("stat", "/proc/self/stat"), ("status", "/proc/6/status")] {
            let fd = open_proc(&mut child, &mut memory, path, libc::O_RDONLY);
            assert!(fd >= 0);
            assert_eq!(
                call(
                    &mut child,
                    &memory,
                    libc::SYS_fstat,
                    [fd as u64, 0x800, 0, 0, 0, 0]
                ),
                0
            );
            let described: libc::stat = read_struct(&memory, 0x800);
            memory.write(0x100, format!("{path}\0").as_bytes()).unwrap();
            assert_eq!(
                call(
                    &mut child,
                    &memory,
                    libc::SYS_newfstatat,
                    [libc::AT_FDCWD as u64, 0x100, 0x800, 0, 0, 0]
                ),
                0
            );
            let named: libc::stat = read_struct(&memory, 0x800);
            assert_eq!(
                (described.st_size, named.st_size),
                (0, 0),
                "{name}: Linux reports size zero"
            );
            assert_eq!(described.st_ino, named.st_ino);
            memory
                .write(0x100, format!("/proc/self/fd/{fd}\0").as_bytes())
                .unwrap();
            let length = call(
                &mut child,
                &memory,
                libc::SYS_readlink,
                [0x100, 0x400, 64, 0, 0, 0],
            );
            assert!(length > 0);
            let mut target = vec![0; length as usize];
            memory.read(0x400, &mut target).unwrap();
            assert_eq!(target, format!("/proc/6/{name}").into_bytes());
            // The empty backing memfd is never content: kernel transfers and
            // mappings are refused, and an invalid output keeps its EBADF.
            assert_eq!(
                call(
                    &mut child,
                    &memory,
                    libc::SYS_sendfile,
                    [1, fd as u64, 0, 1, 0, 0]
                ),
                -i64::from(libc::ENOSYS)
            );
            assert_eq!(
                call(
                    &mut child,
                    &memory,
                    libc::SYS_sendfile,
                    [999, fd as u64, 0, 1, 0, 0]
                ),
                -i64::from(libc::EBADF)
            );
            assert_eq!(
                call(
                    &mut child,
                    &memory,
                    libc::SYS_mmap,
                    [
                        0,
                        4096,
                        libc::PROT_READ as u64,
                        libc::MAP_PRIVATE as u64,
                        fd as u64,
                        0
                    ],
                ),
                -i64::from(libc::ENOSYS)
            );
            // Neither a readable nor an O_PATH handle reopens as its backing.
            let path_only = open_proc(&mut child, &mut memory, path, libc::O_PATH);
            assert!(path_only >= 0);
            for source in [fd, path_only] {
                assert_eq!(
                    open_proc(
                        &mut child,
                        &mut memory,
                        &format!("/proc/self/fd/{source}"),
                        libc::O_RDONLY
                    ),
                    -i64::from(libc::ENOSYS),
                    "{name}: reopening fd {source}",
                );
            }
        }
    }

    const RIGHTS_HEADER: u64 = 0x2000;
    const RIGHTS_IOV: u64 = 0x2100;
    const RIGHTS_BYTE: u64 = 0x2300;
    // Room for SCM_MAX_FD rights below the end of a 0x4000-byte guest.
    const RIGHTS_CONTROL: u64 = 0x3000;

    fn write_rights_header(memory: &mut GuestMemory, control_length: usize) {
        let iov = libc::iovec {
            iov_base: RIGHTS_BYTE as *mut libc::c_void,
            iov_len: 1,
        };
        assert_eq!(super::super::write_struct(memory, RIGHTS_IOV, &iov), 0);
        // SAFETY: an all-zero msghdr is a valid empty header.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = RIGHTS_IOV as *mut libc::iovec;
        header.msg_iovlen = 1;
        header.msg_control = RIGHTS_CONTROL as *mut libc::c_void;
        header.msg_controllen = control_length;
        assert_eq!(
            super::super::write_struct(memory, RIGHTS_HEADER, &header),
            0
        );
    }

    /// Sends one byte carrying `fd` as a single SCM_RIGHTS descriptor.
    fn send_right(
        executor: &mut ElfExecutor,
        memory: &mut GuestMemory,
        socket: i64,
        fd: i64,
    ) -> i64 {
        send_rights(executor, memory, socket, &[fd])
    }

    /// Sends one byte carrying all of `fds` in one SCM_RIGHTS message.
    fn send_rights(
        executor: &mut ElfExecutor,
        memory: &mut GuestMemory,
        socket: i64,
        fds: &[i64],
    ) -> i64 {
        let bytes = (fds.len() * 4) as u32;
        // SAFETY: CMSG_* only compute sizes.
        let (space, length) = unsafe {
            (
                libc::CMSG_SPACE(bytes) as usize,
                libc::CMSG_LEN(bytes) as usize,
            )
        };
        let mut control = vec![0u8; space];
        // SAFETY: an all-zero cmsghdr is valid plain data.
        let mut header: libc::cmsghdr = unsafe { std::mem::zeroed() };
        header.cmsg_len = length;
        header.cmsg_level = libc::SOL_SOCKET;
        header.cmsg_type = libc::SCM_RIGHTS;
        let header_size = std::mem::size_of::<libc::cmsghdr>();
        // SAFETY: control holds at least one cmsghdr.
        unsafe { std::ptr::write_unaligned(control.as_mut_ptr().cast(), header) };
        for (index, fd) in fds.iter().enumerate() {
            let start = header_size + index * 4;
            control[start..start + 4].copy_from_slice(&(*fd as i32).to_ne_bytes());
        }
        memory.write(RIGHTS_CONTROL, &control).unwrap();
        memory.write(RIGHTS_BYTE, b"R").unwrap();
        write_rights_header(memory, space);
        call(
            executor,
            memory,
            libc::SYS_sendmsg,
            [socket as u64, RIGHTS_HEADER, 0, 0, 0, 0],
        )
    }

    /// Receives one byte and returns its single SCM_RIGHTS descriptor.
    fn receive_right(
        executor: &mut ElfExecutor,
        memory: &mut GuestMemory,
        socket: i64,
        flags: i32,
    ) -> i64 {
        let fds = receive_rights(executor, memory, socket, flags, 1);
        assert_eq!(fds.len(), 1);
        fds[0]
    }

    /// Receives one byte with room for `capacity` SCM_RIGHTS descriptors.
    fn receive_rights(
        executor: &mut ElfExecutor,
        memory: &mut GuestMemory,
        socket: i64,
        flags: i32,
        capacity: usize,
    ) -> Vec<i64> {
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE((capacity * 4) as u32) } as usize;
        memory.write(RIGHTS_CONTROL, &vec![0; space]).unwrap();
        write_rights_header(memory, space);
        assert_eq!(
            call(
                executor,
                memory,
                libc::SYS_recvmsg,
                [socket as u64, RIGHTS_HEADER, flags as u64, 0, 0, 0],
            ),
            1
        );
        let header: libc::cmsghdr = read_struct(memory, RIGHTS_CONTROL);
        assert_eq!(
            (header.cmsg_level, header.cmsg_type),
            (libc::SOL_SOCKET, libc::SCM_RIGHTS)
        );
        // SAFETY: CMSG_LEN only computes a size.
        let empty = unsafe { libc::CMSG_LEN(0) } as usize;
        let mut fds = vec![0; header.cmsg_len - empty];
        memory
            .read(
                RIGHTS_CONTROL + std::mem::size_of::<libc::cmsghdr>() as u64,
                &mut fds,
            )
            .unwrap();
        fds.as_chunks::<4>()
            .0
            .iter()
            .map(|fd| i64::from(i32::from_ne_bytes(*fd)))
            .collect()
    }

    fn proc_transfers_in_flight(executor: &ElfExecutor) -> Vec<usize> {
        executor
            .state
            .file_identity_table
            .lock()
            .unwrap()
            .proc_transfers
            .values()
            .map(|transfer| transfer.in_flight)
            .collect()
    }

    #[test]
    fn proc_stat_and_status_sent_with_scm_rights_keep_one_read_time_description() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut child = parent.fork_child(7, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    libc::SOCK_STREAM as u64,
                    0,
                    0x2400,
                    0,
                    0
                ],
            ),
            0
        );
        let sockets: [i32; 2] = read_struct(&memory, 0x2400);
        let (sender, receiver) = (i64::from(sockets[0]), i64::from(sockets[1]));
        let stat = open_proc(&mut child, &mut memory, "/proc/self/stat", libc::O_RDONLY);
        let status = open_proc(&mut child, &mut memory, "/proc/7/status", libc::O_RDONLY);
        assert!(stat >= 0 && status >= 0);
        let head = read_proc_once(&mut child, &memory, stat, 4);
        assert_eq!(head, "7 (t");
        assert_eq!(send_right(&mut child, &mut memory, sender, stat), 1);
        assert_eq!(send_right(&mut child, &mut memory, sender, status), 1);
        assert_eq!(proc_transfers_in_flight(&child), [1, 1]);
        // The queued rights alone keep both descriptions alive.
        for fd in [stat, status] {
            assert_eq!(
                call(
                    &mut child,
                    &memory,
                    libc::SYS_close,
                    [fd as u64, 0, 0, 0, 0, 0]
                ),
                0
            );
        }
        // A peeked right is installed but stays queued for the real receive.
        let peeked = receive_right(&mut child, &mut memory, receiver, libc::MSG_PEEK);
        assert_eq!(proc_transfers_in_flight(&child), [1, 1]);
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_close,
                [peeked as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        let received_stat = receive_right(&mut child, &mut memory, receiver, 0);
        let received_status = receive_right(&mut child, &mut memory, receiver, 0);
        assert_eq!(proc_transfers_in_flight(&child), Vec::<usize>::new());

        parent.retire_current_thread(reverie::ExitStatus::Exited(0), false);
        assert_eq!(getppid(&mut child), 1);
        // The received stat shares the sender's started sequence and position.
        let tail = read_proc(&mut child, &memory, received_stat, 64);
        assert!(
            format!("{head}{tail}").starts_with("7 (test) R 6 "),
            "{head}{tail}"
        );
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_lseek,
                [received_stat as u64, 0, libc::SEEK_SET as u64, 0, 0, 0]
            ),
            0
        );
        let restarted = read_proc(&mut child, &memory, received_stat, 64);
        assert!(restarted.starts_with("7 (test) R 1 "), "{restarted}");
        // Status was opened before reparenting and first read after it.
        let status_text = read_proc(&mut child, &memory, received_status, 64);
        assert!(
            status_text.contains("\nPid:\t7\nPPid:\t1\n"),
            "{status_text}"
        );
        memory
            .write(
                0x100,
                format!("/proc/self/fd/{received_status}\0").as_bytes(),
            )
            .unwrap();
        let length = call(
            &mut child,
            &memory,
            libc::SYS_readlink,
            [0x100, 0x400, 64, 0, 0, 0],
        );
        assert!(length > 0);
        let mut target = vec![0; length as usize];
        memory.read(0x400, &mut target).unwrap();
        assert_eq!(target, b"/proc/7/status");
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_ioctl,
                [received_status as u64, libc::FIONREAD, 0x800, 0, 0, 0]
            ),
            -i64::from(libc::ENOTTY)
        );

        // A send the host refuses leaves nothing registered. Shut down the
        // socket itself: closing the peer is not enough while a concurrent
        // test's fork still holds a copy of the host descriptor before exec.
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_shutdown,
                [sender as u64, libc::SHUT_WR as u64, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            send_right(&mut child, &mut memory, sender, received_status),
            -i64::from(libc::EPIPE)
        );
        assert_eq!(proc_transfers_in_flight(&child), Vec::<usize>::new());
    }

    #[test]
    fn proc_rights_in_flight_are_bounded_until_received() {
        const SCM_MAX_FD: usize = 253;
        let limit = super::super::PROC_TRANSFER_LIMIT;
        let root = outside_init_root();
        let mut child = root.fork_child(6, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    libc::SOCK_STREAM as u64,
                    0,
                    0x2400,
                    0,
                    0
                ],
            ),
            0
        );
        let sockets: [i32; 2] = read_struct(&memory, 0x2400);
        let (sender, receiver) = (i64::from(sockets[0]), i64::from(sockets[1]));
        let stat = open_proc(&mut child, &mut memory, "/proc/self/stat", libc::O_RDONLY);
        assert!(stat >= 0);
        let mut queued = 0;
        while queued < limit - 1 {
            let count = SCM_MAX_FD.min(limit - 1 - queued);
            assert_eq!(
                send_rights(&mut child, &mut memory, sender, &vec![stat; count]),
                1
            );
            queued += count;
        }
        assert_eq!(proc_transfers_in_flight(&child), [limit - 1]);
        // A message crossing the bound is refused whole.
        assert_eq!(
            send_rights(&mut child, &mut memory, sender, &[stat, stat]),
            -i64::from(libc::ETOOMANYREFS)
        );
        assert_eq!(proc_transfers_in_flight(&child), [limit - 1]);
        assert_eq!(send_right(&mut child, &mut memory, sender, stat), 1);
        assert_eq!(
            send_right(&mut child, &mut memory, sender, stat),
            -i64::from(libc::ETOOMANYREFS)
        );
        assert_eq!(proc_transfers_in_flight(&child), [limit]);
        // Receiving the first message returns its capacity.
        let received = receive_rights(&mut child, &mut memory, receiver, 0, SCM_MAX_FD);
        assert_eq!(received.len(), SCM_MAX_FD);
        assert_eq!(proc_transfers_in_flight(&child), [limit - SCM_MAX_FD]);
        assert_eq!(send_right(&mut child, &mut memory, sender, stat), 1);
        assert_eq!(proc_transfers_in_flight(&child), [limit - SCM_MAX_FD + 1]);
    }

    #[test]
    fn proc_rights_dropped_by_a_failed_install_leave_the_in_flight_bound() {
        let root = outside_init_root();
        let mut child = root.fork_child(6, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        assert_eq!(
            call(
                &mut child,
                &memory,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    libc::SOCK_STREAM as u64,
                    0,
                    0x2400,
                    0,
                    0
                ],
            ),
            0
        );
        let sockets: [i32; 2] = read_struct(&memory, 0x2400);
        let sender = i64::from(sockets[0]);
        let stat = open_proc(&mut child, &mut memory, "/proc/self/stat", libc::O_RDONLY);
        assert!(stat >= 0);
        assert_eq!(send_rights(&mut child, &mut memory, sender, &[stat; 3]), 1);
        assert_eq!(proc_transfers_in_flight(&child), [3]);
        let open_before: Vec<_> = child.state.files.keys().copied().collect();

        // Install the dequeued message's three rights into an 8-byte control
        // buffer: the first fits, the second's slot is out of range, and the
        // third is never reached. The host delivers the sender's open
        // description, as a dup does.
        let host = super::super::host_fd(&child.state, stat as i32).unwrap();
        // SAFETY: the guest's stat descriptor keeps `host` open.
        let host = unsafe { std::os::fd::BorrowedFd::borrow_raw(host) };
        let install = |child: &mut ElfExecutor, peek: bool| {
            let rights = [0, 8, 4]
                .map(|control_offset| super::super::PendingReceivedRight {
                    control_offset,
                    file: host.try_clone_to_owned().unwrap().into(),
                })
                .into();
            super::super::install_received_rights(
                &mut child.state,
                &mut [0; 8],
                rights,
                false,
                peek,
            )
        };
        // A failed peek leaves every right queued.
        assert_eq!(install(&mut child, true), Err(-i64::from(libc::EINVAL)));
        assert_eq!(proc_transfers_in_flight(&child), [3]);
        // A failed consuming receive drops all three, including the unreached one.
        assert_eq!(install(&mut child, false), Err(-i64::from(libc::EINVAL)));
        assert_eq!(proc_transfers_in_flight(&child), []);
        assert_eq!(
            child.state.files.keys().copied().collect::<Vec<_>>(),
            open_before
        );
    }

    /// A host thread standing in for a started child's vCPU. It publishes
    /// `completion` (or nothing) and returns `result` once `release` fires.
    fn adopted_child_thread(
        completion: Option<super::super::ChildCompletion>,
        result: crate::Result<()>,
    ) -> (
        super::super::ChildStartGate,
        Arc<super::super::ChildCompletionSlot>,
        super::super::ChildThread,
        std::sync::mpsc::Sender<()>,
    ) {
        let (start, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let slot = Arc::new(super::super::ChildCompletionSlot::default());
        let published = slot.clone();
        let handle = super::super::ChildThread::spawn(move || {
            assert_eq!(
                started.recv().unwrap(),
                super::super::ChildStartCommand::Start
            );
            released.recv().unwrap();
            if let Some(completion) = completion {
                assert!(published.publish(completion));
            }
            result
        });
        (
            super::super::ChildStartGate::new(start),
            slot,
            handle,
            release,
        )
    }

    #[test]
    fn reparented_leader_hands_adopted_children_to_the_traced_root() {
        let mut root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut orphan = parent.fork_child(7, false, false).unwrap();
        let (gate, slot, handle, release) = adopted_child_thread(
            Some(super::super::ChildCompletion::AutoReaped(
                reverie::ExitStatus::Exited(5),
            )),
            Ok(()),
        );
        parent.register_child_process_with_gate(7, gate, slot, handle);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);

        // Linux never makes an exiting parent wait for a child that init
        // adopted. The orphan is still running when the parent finishes.
        let (joined, parent_joined) = std::sync::mpsc::channel();
        let parent_thread = std::thread::spawn(move || {
            let result = parent.join_all_child_processes();
            joined.send(()).unwrap();
            result
        });
        let timely = parent_joined
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        if !timely {
            release.send(()).unwrap();
        }
        parent_thread.join().unwrap().unwrap();
        assert!(timely, "the exiting parent waited for its adopted child");
        assert_eq!(
            root.namespace_orphanage
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![7],
            "the traced root owns the adopted child's host completion",
        );

        orphan.retire_current_thread(reverie::ExitStatus::Exited(5), false);
        release.send(()).unwrap();
        root.join_all_child_processes().unwrap();
        assert!(root.namespace_orphanage.lock().unwrap().is_empty());
        assert!(root.state.children.is_empty(), "no traced process reaps it");
    }

    #[test]
    fn traced_root_reports_adopted_children_that_fail_or_publish_nothing() {
        for (completion, result, expected) in [
            (
                None,
                Ok(()),
                "KVM orphan process 7 exited without publishing its status",
            ),
            (
                None,
                Err(crate::Error::GuestClock("adopted child failed".to_owned())),
                "adopted child failed",
            ),
        ] {
            let mut root = outside_init_root();
            let mut parent = root.fork_child(6, false, false).unwrap();
            let _orphan = parent.fork_child(7, false, false).unwrap();
            let (gate, slot, handle, release) = adopted_child_thread(completion, result);
            parent.register_child_process_with_gate(7, gate, slot, handle);
            parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
            parent.join_all_child_processes().unwrap();
            release.send(()).unwrap();
            let error = root.join_child_processes_after_failure().unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert!(root.namespace_orphanage.lock().unwrap().is_empty());
        }
    }

    type TurnRequests =
        futures::channel::mpsc::UnboundedSender<futures::channel::oneshot::Sender<()>>;

    /// When a child's teardown needs its turn: in its closure, or in a
    /// thread-local destructor, which runs after the closure has returned and
    /// published its result.
    #[derive(Clone, Copy, Debug)]
    enum TurnNeeded {
        Closure,
        ThreadLocalTeardown,
    }

    struct TeardownTurn(Option<Box<dyn FnOnce()>>);
    impl Drop for TeardownTurn {
        fn drop(&mut self) {
            if let Some(turn) = self.0.take() {
                turn();
            }
        }
    }
    thread_local! {
        static TEARDOWN_TURN: std::cell::RefCell<Option<TeardownTurn>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Retire the actual fork generation at this fixture's publication boundary.
    /// Host-thread ownership remains live until the existing turn/release/TLS
    /// protocol completes; family readiness alone never proves physical join.
    fn publish_owned_fixture_child(
        child: &Arc<Mutex<ElfExecutor>>,
        slot: &super::super::ChildCompletionSlot,
    ) {
        let mut child = child.lock().unwrap();
        let child_id = child.retired_process_identity();
        let status = child
            .retire_current_thread(reverie::ExitStatus::Exited(3), false)
            .status;
        assert!(child.signal_task_identity().is_none());
        assert_eq!(status, reverie::ExitStatus::Exited(3));
        child
            .fixture_child_wait_context()
            .publish_fixture_owner(status, slot)
            .unwrap();
        assert_eq!(child.retired_process_identity(), child_id);
    }

    /// A child whose remaining work, like a Tool exit hook, needs a turn from
    /// a scheduler that only the exiting root's own executor polls, as Hermit's
    /// is. It needs the turn whether its gate starts or cancels it, and before
    /// or after publishing its status.
    /// The thread holds `lifetime` until its turn is granted.
    fn co_scheduled_child_thread(
        child: Arc<Mutex<ElfExecutor>>,
        turns: TurnRequests,
        published_first: Option<std::sync::mpsc::Sender<()>>,
        lifetime: Arc<()>,
        needed: TurnNeeded,
    ) -> (
        super::super::ChildStartGate,
        Arc<super::super::ChildCompletionSlot>,
        super::super::ChildThread,
    ) {
        let (start, started) = std::sync::mpsc::channel();
        let slot = Arc::new(super::super::ChildCompletionSlot::default());
        let published = slot.clone();
        let handle = super::super::ChildThread::spawn(move || {
            started.recv().unwrap();
            let publish = || publish_owned_fixture_child(&child, &published);
            if let Some(announce) = &published_first {
                publish();
                announce.send(()).unwrap();
            }
            let turn = move || {
                let (turn, granted) = futures::channel::oneshot::channel();
                turns.unbounded_send(turn).unwrap();
                drop(turns);
                futures::executor::block_on(granted).unwrap();
                drop(lifetime);
            };
            match needed {
                TurnNeeded::Closure => turn(),
                TurnNeeded::ThreadLocalTeardown => TEARDOWN_TURN.with(|teardown| {
                    *teardown.borrow_mut() = Some(TeardownTurn(Some(Box::new(turn))));
                }),
            }
            if published_first.is_none() {
                publish();
            }
            Ok(())
        });
        (super::super::ChildStartGate::new(start), slot, handle)
    }

    #[derive(Clone, Copy, Debug)]
    enum RootChild {
        None,
        Pending,
        // Collected by a nonblocking wait while its thread still runs.
        Collected,
    }

    #[test]
    fn traced_root_exit_does_not_starve_the_scheduler_its_children_need() {
        // Without a direct child, the root reaches the orphan drain before the
        // scheduler has ever run, so each drain is exposed on its own.
        for direct in [RootChild::Pending, RootChild::Collected, RootChild::None] {
            for failed in [false, true] {
                // Host threads can be refused (EAGAIN, ENOMEM). The exit
                // join must neither need one nor fall back to blocking.
                for refuse_threads in [false, true] {
                    // A reaped thread has finished even thread-local
                    // destructors that embedder code may have installed.
                    for needed in [TurnNeeded::Closure, TurnNeeded::ThreadLocalTeardown] {
                        root_exit_join_case(direct, failed, refuse_threads, needed);
                    }
                }
            }
        }
    }

    fn root_exit_join_case(
        direct: RootChild,
        failed: bool,
        refuse_threads: bool,
        needed: TurnNeeded,
    ) {
        let (turns, mut requests) = futures::channel::mpsc::unbounded();
        let lifetime = Arc::new(());
        let mut root = outside_init_root();
        let mut children = Vec::new();
        if !matches!(direct, RootChild::None) {
            children.push(Arc::new(Mutex::new(
                root.fork_child(6, false, false).unwrap(),
            )));
            let (announce, announced) = std::sync::mpsc::channel();
            let collected = matches!(direct, RootChild::Collected);
            let (gate, slot, handle) = co_scheduled_child_thread(
                children.last().unwrap().clone(),
                turns.clone(),
                collected.then_some(announce),
                lifetime.clone(),
                needed,
            );
            root.register_child_process_with_gate(6, gate, slot, handle);
            if collected {
                root.start_pending_child_processes().unwrap();
                announced.recv().unwrap();
                assert!(root.collect_child_process(6, false).unwrap());
                assert_eq!(root.completed_processes.len(), 1);
            }
        }
        let mut parent = root.fork_child(7, false, false).unwrap();
        children.push(Arc::new(Mutex::new(
            parent.fork_child(8, false, false).unwrap(),
        )));
        let (gate, slot, handle) = co_scheduled_child_thread(
            children.last().unwrap().clone(),
            turns,
            None,
            lifetime.clone(),
            needed,
        );
        parent.register_child_process_with_gate(8, gate, slot, handle);

        // The reparenting parent hands its child over although no scheduler
        // turn has been granted yet.
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        parent.join_all_child_processes().unwrap();
        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);

        // One thread polls both the root's exit join and the scheduler. A
        // blocking join never lets it grant the turns.
        let (joined, root_joined) = std::sync::mpsc::channel();
        let joined_owners = Arc::downgrade(&lifetime);
        let root_thread = std::thread::spawn(move || {
            let refusal = refuse_threads.then(|| {
                let probe = Arc::new(crate::failure::spawn_refusal::Probe::default());
                let guard = crate::failure::spawn_refusal::Guard::arm(probe.clone());
                (probe, guard)
            });
            let scheduler = async {
                let mut granted = 0;
                while let Some(turn) = futures::StreamExt::next(&mut requests).await {
                    turn.send(()).unwrap();
                    granted += 1;
                }
                granted
            };
            // The scheduler ends once every child has dropped its turn sender,
            // which it holds until it exits.
            let ((result, owners_at_join), granted) = futures::executor::block_on(async {
                let join = async {
                    let result = if failed {
                        root.join_child_processes_after_failure_async().await
                    } else {
                        root.join_all_child_processes_async().await
                    };
                    // Sampled before the scheduler can grant another turn.
                    (result, joined_owners.strong_count())
                };
                futures::future::join(join, scheduler).await
            });
            joined.send(()).unwrap();
            let result = result.map(|()| owners_at_join);
            let join_spawned = refusal
                .as_ref()
                .is_some_and(|_| !crate::failure::spawn_refusal::is_armed());
            if let Some((probe, _guard)) = refusal.filter(|_| !join_spawned) {
                // Spend the refusal on a child spawn instead: its state returns
                // to the caller, so no thread or exit notice is left owning it.
                let state = Arc::new(());
                let Err((_, returned)) = super::super::ChildThread::spawn_owned(
                    std::thread::Builder::new(),
                    state.clone(),
                    |_| unreachable!("a refused child thread ran"),
                ) else {
                    panic!("the armed refusal admitted a child thread");
                };
                assert!(Arc::ptr_eq(&state, &returned));
                assert!(probe.error().is_some());
                drop(returned);
                assert_eq!(Arc::strong_count(&state), 1);
            }
            (root, result, granted, join_spawned)
        });
        assert!(
            root_joined
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok(),
            "{direct:?} direct child, failed {failed}, threads refused {refuse_threads}, \
             turn needed in {needed:?}: the traced root's exit join starved the \
             scheduler its children need",
        );
        let (root, result, granted, join_spawned) = root_thread.join().unwrap();
        assert!(!join_spawned, "the exit join spawned a host thread");
        // Every child's turn and return, including thread-local teardown,
        // preceded the join's return: only this test still owns `lifetime`.
        assert_eq!(
            result.unwrap(),
            1,
            "{direct:?} direct child, failed {failed}, threads refused {refuse_threads}, \
             turn needed in {needed:?}: the join returned before a child's host thread ended",
        );
        assert_eq!(granted, children.len(), "every child got exactly one turn");
        assert!(root.namespace_orphanage.lock().unwrap().is_empty());
        assert!(root.completed_processes.is_empty());
        assert!(root.pending_processes.is_empty());
        assert_eq!(Arc::strong_count(&lifetime), 1);
    }

    /// A child that runs until `release` fires, whether its gate starts or
    /// cancels it, holding `lifetime` until then and through the thread-local
    /// teardown that follows.
    fn released_child_thread(
        child: Arc<Mutex<ElfExecutor>>,
        published_first: Option<std::sync::mpsc::Sender<()>>,
        lifetime: Arc<()>,
    ) -> (
        super::super::ChildStartGate,
        Arc<super::super::ChildCompletionSlot>,
        super::super::ChildThread,
        std::sync::mpsc::Sender<()>,
    ) {
        let (start, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let slot = Arc::new(super::super::ChildCompletionSlot::default());
        let published = slot.clone();
        let handle = super::super::ChildThread::spawn(move || {
            started.recv().unwrap();
            let publish = || publish_owned_fixture_child(&child, &published);
            if let Some(announce) = &published_first {
                publish();
                announce.send(()).unwrap();
            }
            released.recv().unwrap();
            // An owner that joins this thread returns only after `lifetime`
            // is released; one that detached it returns while it sleeps.
            TEARDOWN_TURN.with(|teardown| {
                *teardown.borrow_mut() = Some(TeardownTurn(Some(Box::new(move || {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    drop(lifetime);
                }))));
            });
            if published_first.is_none() {
                publish();
            }
            Ok(())
        });
        (
            super::super::ChildStartGate::new(start),
            slot,
            handle,
            release,
        )
    }

    /// The kind of child the root's exit join is waiting for when dropped.
    #[derive(Clone, Copy, Debug)]
    enum AwaitedChild {
        Pending,
        Collected,
        Orphan,
    }

    #[test]
    fn dropped_root_exit_join_keeps_every_child_it_has_not_reaped() {
        for awaited in [
            AwaitedChild::Pending,
            AwaitedChild::Collected,
            AwaitedChild::Orphan,
        ] {
            for failed in [false, true] {
                dropped_root_exit_join_case(awaited, failed);
            }
        }
    }

    fn dropped_root_exit_join_case(awaited: AwaitedChild, failed: bool) {
        let lifetime = Arc::new(());
        let mut releases = Vec::new();
        let mut root = outside_init_root();
        let mut children = Vec::new();
        // The join reaps pending children, then collected ones, then orphans.
        // It first waits for the `awaited` kind; every later kind also waits.
        if !matches!(awaited, AwaitedChild::Orphan) {
            children.push(Arc::new(Mutex::new(
                root.fork_child(9, false, false).unwrap(),
            )));
            let (announce, announced) = std::sync::mpsc::channel();
            let (gate, slot, handle, release) = released_child_thread(
                children.last().unwrap().clone(),
                Some(announce),
                lifetime.clone(),
            );
            root.register_child_process_with_gate(9, gate, slot, handle);
            root.start_pending_child_processes().unwrap();
            announced.recv().unwrap();
            assert!(root.collect_child_process(9, false).unwrap());
            releases.push(release);
        }
        if matches!(awaited, AwaitedChild::Pending) {
            children.push(Arc::new(Mutex::new(
                root.fork_child(6, false, false).unwrap(),
            )));
            let (gate, slot, handle, release) =
                released_child_thread(children.last().unwrap().clone(), None, lifetime.clone());
            root.register_child_process_with_gate(6, gate, slot, handle);
            releases.push(release);
        }
        let mut parent = root.fork_child(7, false, false).unwrap();
        children.push(Arc::new(Mutex::new(
            parent.fork_child(8, false, false).unwrap(),
        )));
        let (gate, slot, handle, release) =
            released_child_thread(children.last().unwrap().clone(), None, lifetime.clone());
        parent.register_child_process_with_gate(8, gate, slot, handle);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        parent.join_all_child_processes().unwrap();
        releases.push(release);
        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);

        async fn join(root: &mut ElfExecutor, failed: bool) -> crate::Result<()> {
            if failed {
                root.join_child_processes_after_failure_async().await
            } else {
                root.join_all_child_processes_async().await
            }
        }
        let runs = Arc::new(Mutex::new(super::super::AbandonedRuns::default()));
        let root_alive = Arc::downgrade(&root.transferred_processes);
        {
            // An embedder may drop the run's future, and the root executor it
            // owns, at any await point.
            let admission = super::super::RunAdmission::begin(&runs).unwrap();
            let mut running = admission.root(root);
            let mut dropped = Box::pin(async move { join(&mut running, failed).await });
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(dropped.as_mut().poll(&mut cx).is_pending());
        }
        let case = format!("{awaited:?} child awaited, failed {failed}");
        assert!(
            matches!(
                super::super::AbandonedRuns::admit(&runs),
                Err(crate::Error::AbandonedRunNotRetired)
            ),
            "{case}: a backend with a dropped run admitted another"
        );
        {
            let parked = runs.lock().unwrap();
            assert_eq!(
                parked.roots.len(),
                1,
                "{case}: the dropped run's root was not parked"
            );
            let root = &parked.roots[0];
            assert_eq!(
                root.pending_processes.keys().copied().collect::<Vec<_>>(),
                if matches!(awaited, AwaitedChild::Pending) {
                    vec![6]
                } else {
                    vec![]
                },
                "{case}: the dropped join lost a pending child",
            );
            assert_eq!(
                root.completed_processes.len(),
                usize::from(!matches!(awaited, AwaitedChild::Orphan)),
                "{case}: the dropped join lost a collected child",
            );
            assert_eq!(
                root.namespace_orphanage
                    .lock()
                    .unwrap()
                    .keys()
                    .copied()
                    .collect::<Vec<_>>(),
                vec![8],
                "{case}: the dropped join lost an orphan",
            );
        }

        // The backend's drop hands the parked root to the reaper without
        // waiting, before any child can exit.
        assert!(super::super::AbandonedRuns::retire(
            &runs,
            &Arc::new(crate::vm::GuestThreadGroup::default())
        ));
        assert!(runs.lock().unwrap().roots.is_empty(), "{case}");
        assert_eq!(
            Arc::strong_count(&lifetime),
            1 + releases.len(),
            "{case}: a child ended before its release",
        );
        assert!(root_alive.upgrade().is_some(), "{case}");
        for release in releases {
            release.send(()).unwrap();
        }
        // The reaper drops the root only after joining every child it owns.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while root_alive.upgrade().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "{case}: the reaper never joined the dropped run's children"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(Arc::strong_count(&lifetime), 1, "{case}");
    }

    #[test]
    fn failed_child_thread_join_keeps_the_pthread_it_owns() {
        // No live joinable pthread with a unique owner can produce these, but
        // if one were reported, the handle must still own, and so still reap,
        // the thread.
        for status in [libc::EINVAL, libc::ESRCH, libc::EDEADLK] {
            let (release, released) = std::sync::mpsc::channel::<()>();
            let mut thread = super::super::ChildThread::spawn(move || {
                released.recv().unwrap();
                Ok(())
            });
            let owned = thread.pthread;
            let reported = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = thread.joined(status);
            }));
            assert!(reported.is_err(), "status {status} was accepted as a join");
            assert_eq!(
                thread.pthread, owned,
                "status {status} released the pthread"
            );
            release.send(()).unwrap();
            thread.join_blocking().unwrap().unwrap();
            assert_eq!(thread.pthread, None);
        }
    }

    #[test]
    fn a_refused_reaper_spawn_refuses_the_run_before_it_starts() {
        use crate::failure::spawn_refusal;
        let runs = Arc::new(Mutex::new(super::super::AbandonedRuns::default()));
        let probe = Arc::new(spawn_refusal::Probe::default());
        let refused = {
            let _refusal = spawn_refusal::Guard::arm(probe.clone());
            super::super::RunAdmission::begin(&runs).map(|_| ())
        };
        let Err(crate::Error::Cleanup { phase, error }) = refused else {
            panic!("a run was admitted without a reaper: {refused:?}");
        };
        assert_eq!(phase, "dropped-run reaper spawn");
        let crate::Error::HostIo(error) = &*error else {
            panic!("the reaper's spawn error was replaced: {error:?}");
        };
        assert_eq!(
            Some(spawn_refusal::ObservedError::read(error)),
            probe.error()
        );
        // The refused run never started, so it abandoned nothing.
        assert!(!runs.lock().unwrap().abandoned);
        super::super::RunAdmission::begin(&runs)
            .unwrap()
            .finish(&crate::vm::GuestThreadGroup::default());
        assert!(!runs.lock().unwrap().abandoned);
    }

    #[test]
    fn a_run_returning_before_joining_its_workers_leaves_them_to_its_reaper() {
        let runs = Arc::new(Mutex::new(super::super::AbandonedRuns::default()));
        let group = Arc::new(crate::vm::GuestThreadGroup::default());
        let lifetime = Arc::new(());
        let (release, held) = std::sync::mpsc::channel::<()>();
        let worker = {
            let lifetime = lifetime.clone();
            std::thread::spawn(move || {
                let _lifetime = lifetime;
                let _ = held.recv();
                Ok((reverie::ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            })
        };
        group.add_worker_handle(4, worker);

        // An error returned the run before it joined worker 4.
        super::super::RunAdmission::begin(&runs)
            .unwrap()
            .finish(&group);
        assert!(
            matches!(
                super::super::AbandonedRuns::admit(&runs),
                Err(crate::Error::AbandonedRunNotRetired)
            ),
            "a backend whose returned run left a worker running admitted another"
        );

        // The backend's drop hands the worker to the run's reaper and does
        // not wait for it.
        let dropping = std::time::Instant::now();
        assert!(super::super::AbandonedRuns::retire(&runs, &group));
        assert!(dropping.elapsed() < std::time::Duration::from_secs(5));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(group.has_unjoined_workers());
        assert_eq!(
            Arc::strong_count(&lifetime),
            2,
            "the worker ended while held"
        );
        assert_eq!(
            Arc::strong_count(&group),
            2,
            "the reaper let go of the worker before joining it"
        );

        release.send(()).unwrap();
        wait_until("the reaper never joined the worker", || {
            Arc::strong_count(&group) == 1
        });
        assert!(!group.has_unjoined_workers());
        assert_eq!(Arc::strong_count(&lifetime), 1);
    }

    #[test]
    fn a_reaper_retries_a_panicking_retirement_without_dropping_its_root() {
        let lifetime = Arc::new(());
        let (root, root_alive, release) = root_with_held_child(&lifetime);
        // Three root joins panic before the fourth attempt starts waiting.
        let (reaper, reaping) = retire_roots(vec![root], 3);
        let assert_root_kept = |when: &str| {
            assert!(
                root_alive.upgrade().is_some(),
                "the reaper dropped its root {when}"
            );
            assert_eq!(
                Arc::strong_count(&lifetime),
                2,
                "the root's child was released {when}"
            );
            assert!(
                !reaping.is_finished(),
                "the reaper stopped holding its root {when}"
            );
        };
        wait_until("the reaper never attempted its retirement", || {
            assert_root_kept("while its retirement panicked");
            reaper.lock().attempts >= 1
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Each panic kept the root, which kept its child; nothing detached it.
        assert_root_kept("after its retirement panicked");
        release.send(()).unwrap();
        wait_until("the reaper never retired the root", || {
            root_alive.upgrade().is_none()
        });
        wait_until("the reaper never stopped", || reaping.is_finished());
        reaping.join().unwrap();
        // The root was dropped only after its child, and its teardown, ended.
        assert_eq!(Arc::strong_count(&lifetime), 1);
        assert_eq!(reaper.lock().attempts, 4);
    }

    #[test]
    fn a_reaper_keeps_an_orphan_whose_join_panicked() {
        let lifetime = Arc::new(());
        let mut root = outside_init_root();
        let mut parent = root.fork_child(7, false, false).unwrap();
        let orphan = Arc::new(Mutex::new(parent.fork_child(8, false, false).unwrap()));
        let (gate, slot, mut handle, release) =
            released_child_thread(orphan.clone(), None, lifetime.clone());
        // Two blocking joins of the orphan panic before the third waits.
        handle.failed_joins = 2;
        parent.register_child_process_with_gate(8, gate, slot, handle);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        parent.join_all_child_processes().unwrap();
        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        assert_eq!(
            root.namespace_orphanage
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![8]
        );
        let root_alive = Arc::downgrade(&root.transferred_processes);

        let (reaper, reaping) = retire_roots(vec![root], 0);
        let assert_orphan_kept = |when: &str| {
            assert!(
                root_alive.upgrade().is_some(),
                "the reaper dropped its root {when}"
            );
            assert_eq!(
                Arc::strong_count(&lifetime),
                2,
                "the orphan was released {when}"
            );
            assert!(!reaping.is_finished(), "the reaper stopped {when}");
        };
        wait_until("the reaper never retried the orphan's join", || {
            assert_orphan_kept("while the orphan's join panicked");
            reaper.lock().attempts >= 3
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_orphan_kept("after the orphan's join panicked");
        release.send(()).unwrap();
        wait_until("the reaper never retired the root", || {
            root_alive.upgrade().is_none()
        });
        wait_until("the reaper never stopped", || reaping.is_finished());
        reaping.join().unwrap();
        assert_eq!(Arc::strong_count(&lifetime), 1);
        assert_eq!(reaper.lock().attempts, 3);
    }

    #[test]
    fn a_reaper_retires_an_orphan_handed_over_through_a_poisoned_orphanage() {
        let lifetime = Arc::new(());
        let mut root = outside_init_root();
        let mut parent = root.fork_child(7, false, false).unwrap();
        let orphan = Arc::new(Mutex::new(parent.fork_child(8, false, false).unwrap()));
        let (gate, slot, handle, release) =
            released_child_thread(orphan.clone(), None, lifetime.clone());
        parent.register_child_process_with_gate(8, gate, slot, handle);
        // An earlier panic poisoned the orphanage the parent's exit hands 8 to.
        {
            let orphanage = root.namespace_orphanage.clone();
            std::thread::spawn(move || {
                let _held = orphanage.lock().unwrap();
                panic!("poisoning the namespace orphanage");
            })
            .join()
            .unwrap_err();
        }
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        let handoff = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            parent.join_all_child_processes()
        }));
        assert!(
            matches!(handoff, Ok(Ok(()))),
            "a poisoned orphanage broke the exiting parent's handoff"
        );
        drop(parent);
        assert_eq!(
            root.namespace_orphanage
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![8]
        );
        assert_eq!(Arc::strong_count(&lifetime), 2, "the orphan was released");
        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        let root_alive = Arc::downgrade(&root.transferred_processes);

        let (reaper, reaping) = retire_roots(vec![root], 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            root_alive.upgrade().is_some(),
            "the reaper dropped a root whose orphan was held"
        );
        assert_eq!(Arc::strong_count(&lifetime), 2, "the orphan was detached");
        assert!(!reaping.is_finished());
        release.send(()).unwrap();
        wait_until("the reaper never retired the root", || {
            reaping.is_finished()
        });
        reaping.join().unwrap();
        assert!(root_alive.upgrade().is_none());
        assert_eq!(Arc::strong_count(&lifetime), 1);
        assert_eq!(reaper.lock().attempts, 1);
    }

    #[test]
    fn a_reaper_retires_a_root_whose_locks_an_earlier_panic_poisoned() {
        fn poison<T: Send + 'static>(lock: Arc<Mutex<T>>) {
            std::thread::spawn(move || {
                let _held = lock.lock().unwrap();
                panic!("poisoning a dropped run's lock");
            })
            .join()
            .unwrap_err();
        }
        let lifetime = Arc::new(());
        let (root, root_alive, release) = root_with_held_child(&lifetime);
        poison(root.transferred_processes.clone());
        poison(root.namespace_orphanage.clone());
        let (reaper, reaping) = retire_roots(vec![root], 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(root_alive.upgrade().is_some());
        assert_eq!(Arc::strong_count(&lifetime), 2);
        release.send(()).unwrap();
        wait_until("the reaper never retired the poisoned root", || {
            reaping.is_finished()
        });
        reaping.join().unwrap();
        assert!(root_alive.upgrade().is_none());
        assert_eq!(Arc::strong_count(&lifetime), 1);
        // The poisoned locks broke no step.
        assert_eq!(reaper.lock().attempts, 1);
    }

    #[test]
    fn a_reaper_joins_every_adopted_root_before_it_stops() {
        let lifetime = Arc::new(());
        let (first, first_alive, release_first) = root_with_held_child(&lifetime);
        let (second, second_alive, release_second) = root_with_held_child(&lifetime);
        // No handle remains, so the reaper stops once it has retired both.
        let (_, reaping) = retire_roots(vec![first, second], 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!reaping.is_finished());
        assert!(first_alive.upgrade().is_some());
        assert_eq!(Arc::strong_count(&lifetime), 3);
        release_second.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
        // Roots retire in order: the second waits behind the first's child.
        assert!(!reaping.is_finished());
        assert!(first_alive.upgrade().is_some());
        assert!(second_alive.upgrade().is_some());
        release_first.send(()).unwrap();
        wait_until("the reaper never stopped", || reaping.is_finished());
        reaping.join().unwrap();
        assert!(first_alive.upgrade().is_none());
        assert!(second_alive.upgrade().is_none());
        assert_eq!(Arc::strong_count(&lifetime), 1);
    }

    /// A root with one child that runs, holding `lifetime`, until the returned
    /// sender releases it, and holds it through a thread-local teardown after.
    #[allow(clippy::type_complexity)]
    fn root_with_held_child(
        lifetime: &Arc<()>,
    ) -> (
        ElfExecutor,
        std::sync::Weak<
            Mutex<std::collections::BTreeMap<i32, Vec<super::super::OwnedChildProcesses>>>,
        >,
        std::sync::mpsc::Sender<()>,
    ) {
        let mut root = outside_init_root();
        let child = Arc::new(Mutex::new(root.fork_child(6, false, false).unwrap()));
        let (gate, slot, handle, release) = released_child_thread(child, None, lifetime.clone());
        root.register_child_process_with_gate(6, gate, slot, handle);
        let root_alive = Arc::downgrade(&root.transferred_processes);
        (root, root_alive, release)
    }

    /// Hands `roots` to a reaper of their own, whose first `inject_panics`
    /// root joins panic, and releases its only handle.
    fn retire_roots(
        roots: Vec<ElfExecutor>,
        inject_panics: usize,
    ) -> (Arc<super::super::ReaperShared>, std::thread::JoinHandle<()>) {
        let (reaper, reaping) = super::super::DroppedRunReaper::spawn().unwrap();
        let shared = reaper.shared.clone();
        shared.lock().inject_panics = inject_panics;
        reaper.adopt(super::super::Retirement {
            workers: None,
            roots,
        });
        drop(reaper);
        (shared, reaping)
    }

    fn wait_until(failure: &str, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{failure}");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn failed_adopted_orphan_leaves_no_namespace_orphan_record() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        let mut worker = orphan.thread_child(8).unwrap();
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(
            family_snapshot(&root).1,
            BTreeSet::from([process_key(orphan_id)])
        );

        worker.retire_failed_thread();
        orphan.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(
            orphan.signal_registry.process_family_exit(orphan_id),
            Some(ProcessFamilyExit::Failed),
            "adoption never replaces an exact process failure",
        );
        assert!(family_snapshot(&root).1.is_empty());
    }

    #[test]
    fn failed_parent_aborts_the_run_without_reparenting_its_children() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut child = parent.fork_child(7, false, false).unwrap();
        let child_id = identity(&child);
        parent.retire_failed_thread();
        assert!(matches!(
            parent.process_family_exit(),
            Err(crate::Error::RunAborted)
        ));
        assert_eq!(getppid(&mut child), 6);
        assert!(family_snapshot(&root).1.is_empty());
        child.retire_current_thread(reverie::ExitStatus::Exited(4), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(4),
            }),
        );

        // A later peer failure replaces an exit_group success with an abort,
        // but cannot undo the adoption that success already published.
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut peer = parent.thread_child(8).unwrap();
        let mut child = parent.fork_child(7, false, false).unwrap();
        let child_id = identity(&child);
        peer.retire_current_thread(reverie::ExitStatus::SUCCESS, true);
        assert_eq!(getppid(&mut child), 1);
        parent.retire_failed_thread();
        assert!(matches!(
            parent.process_family_exit(),
            Err(crate::Error::RunAborted)
        ));
        assert_eq!(getppid(&mut child), 1);
        child.retire_current_thread(reverie::ExitStatus::Exited(4), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(4),
            }),
        );
        assert!(family_snapshot(&root).1.is_empty());
    }

    #[test]
    fn proc_stat_and_status_opened_before_exec_report_the_new_image_name() {
        let root = outside_init_root();
        let mut child = root.fork_child(7, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        let stat = open_proc(&mut child, &mut memory, "/proc/self/stat", libc::O_RDONLY);
        let status = open_proc(&mut child, &mut memory, "/proc/self/status", libc::O_RDONLY);
        assert!(stat >= 0 && status >= 0);
        // As exec_static_elf names the new image before it inherits the process.
        let mut replacement = native_loaded_state(std::path::Path::new("/"));
        replacement.thread_name =
            crate::elf::initial_thread_name(std::path::Path::new("/bin/exec-image"));
        *replacement.thread_group_leader_name.lock().unwrap() = replacement.thread_name;
        let previous = std::mem::replace(&mut child.state, replacement);
        child.state.inherit_process_state(previous);
        let stat_text = read_proc(&mut child, &memory, stat, 64);
        assert!(stat_text.starts_with("7 (exec-image) "), "{stat_text}");
        let status_text = read_proc(&mut child, &memory, status, 64);
        assert!(
            status_text.starts_with("Name:\texec-image\n"),
            "{status_text}"
        );
    }

    #[test]
    fn outside_init_orphan_keeps_its_reaper_across_exec() {
        fn exec(executor: &mut ElfExecutor) {
            let replacement = native_loaded_state(std::path::Path::new("/tmp"));
            let previous = std::mem::replace(&mut executor.state, replacement);
            executor.state.inherit_process_state(previous);
        }
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let mut orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        // Exec before adoption: the later label must reach the new image.
        exec(&mut orphan);
        assert_eq!(getppid(&mut orphan), 6);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(getppid(&mut orphan), 1);
        // Exec after adoption: the new image still reports the reaper.
        exec(&mut orphan);
        assert_eq!(getppid(&mut orphan), 1);
        orphan.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            orphan.signal_registry.process_family_exit(orphan_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(3),
            }),
        );
        assert!(family_snapshot(&root).1.is_empty());
    }

    #[test]
    fn outside_init_adopts_only_children_that_can_still_exit() {
        let root = outside_init_root();
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let live = parent.fork_child(7, false, false).unwrap();
        let live_id = identity(&live);
        let fatal = parent.fork_child(8, false, false).unwrap();
        let fatal_id = identity(&fatal);
        let unstarted = parent.fork_child(9, false, false).unwrap();
        let unstarted_id = identity(&unstarted);
        // A child discarded before it started drops its only binding and
        // never records an exit.
        drop(unstarted);
        {
            // A child whose own exit recorded a typed fatal family result
            // keeps its live edge but will never exit again.
            let mut family = root
                .signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            family.terminal.insert(
                process_key(fatal_id),
                ProcessFamilyExit::AncestryCycle {
                    ancestor: parent_id,
                },
            );
            assert_eq!(
                family.direct_children[&process_key(parent_id)].get(&process_key(unstarted_id)),
                Some(&DirectChildState::Live),
            );
        }

        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert!(matches!(
            parent.signal_registry.process_family_exit(parent_id),
            Some(ProcessFamilyExit::Child(_))
        ));
        assert_eq!(
            family_snapshot(&root).1,
            BTreeSet::from([process_key(live_id)]),
            "only a child that will still record an exit has an orphan record",
        );
        assert_eq!(live.state.orphan_reaper_pid.load(Ordering::SeqCst), 1);
        assert_eq!(fatal.state.orphan_reaper_pid.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn executor_built_from_a_non_root_state_keeps_reparenting_fail_closed() {
        let mut state = native_loaded_state(std::path::Path::new("/tmp"));
        state.pid = 6;
        state.pgid = 6;
        state.tid = 6;
        state.ppid = 3;
        state.is_traced_tree_root = false;
        let executor = ElfExecutor::new(state, false);
        let reaper = executor
            .signal_registry
            .family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reaper;
        assert!(
            matches!(reaper, NamespaceReaper::Unknown),
            "a non-root state must not name its parent as the namespace reaper: {reaper:?}",
        );
    }

    #[test]
    fn traced_root_init_still_refuses_to_adopt_orphans() {
        // `executor()` is PID 1 and therefore namespace init itself. Adoption
        // would move host wait ownership into its executor, which is refused.
        let root = executor();
        let mut parent = root.fork_child(2, false, false).unwrap();
        let mut child = parent.fork_child(3, false, false).unwrap();
        let parent_id = identity(&parent);
        let child_id = identity(&child);
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
        assert_eq!(
            parent.signal_registry.process_family_exit(parent_id),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported { child: child_id }),
        );
        assert_eq!(getppid(&mut child), 2);
        assert!(family_snapshot(&root).1.is_empty());
    }

    #[test]
    fn child_subreapers_remain_unmodeled_so_namespace_init_is_the_reaper() {
        let mut root = outside_init_root();
        let memory = GuestMemory::new(0, 4096).unwrap();
        assert_eq!(
            call(
                &mut root,
                &memory,
                libc::SYS_prctl,
                [libc::PR_SET_CHILD_SUBREAPER as u64, 1, 0, 0, 0, 0],
            ),
            -i64::from(libc::ENOSYS),
            "modeling subreapers requires find_new_reaper to consult them",
        );
    }

    #[test]
    fn child_exit_distinguishes_lost_parent_generation_from_lost_family_edge() {
        let parent = executor();
        let parent_id = identity(&parent);
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        drop(parent);

        child.retire_current_thread(reverie::ExitStatus::Exited(7), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::ParentGenerationUnavailable { parent: parent_id }),
        );
        assert!(matches!(
            child.process_family_exit(),
            Err(crate::Error::ParentGenerationUnavailable { process, parent })
                if process == child_id && parent == parent_id
        ));
        child.signal_registry.record_process_failure(child_id);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::ParentGenerationUnavailable { parent: parent_id }),
            "a later generic failure must preserve the missing-generation cause",
        );

        let parent = executor();
        let parent_id = identity(&parent);
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        {
            let mut family = parent
                .signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let children = family
                .direct_children
                .get_mut(&process_key(parent_id))
                .expect("fork registered an exact parent family edge");
            assert_eq!(
                children.remove(&process_key(child_id)),
                Some(DirectChildState::Live)
            );
            if children.is_empty() {
                family.direct_children.remove(&process_key(parent_id));
            }
        }

        child.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::ParentChildRelationUnavailable { parent: parent_id }),
        );
        assert!(matches!(
            child.process_family_exit(),
            Err(crate::Error::ParentChildRelationUnavailable { process, parent })
                if process == child_id && parent == parent_id
        ));
        child.signal_registry.record_process_failure(child_id);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::ParentChildRelationUnavailable { parent: parent_id }),
            "a later generic failure must preserve the missing-relation cause",
        );
    }

    #[test]
    fn wait4_read_only_outputs_consume_only_the_selected_family_child() {
        const STATUS: u64 = 0x100;
        const USAGE: u64 = 0x1100;
        for status_fault in [true, false] {
            let mut parent = executor();
            let parent_id = identity(&parent);
            let mut child = parent.fork_child(2, false, false).unwrap();
            let child_id = identity(&child);
            let mut sibling = parent.fork_child(3, false, false).unwrap();
            let sibling_id = identity(&sibling);
            child.retire_current_thread(reverie::ExitStatus::Exited(9), false);
            sibling.retire_current_thread(reverie::ExitStatus::Exited(11), false);
            parent
                .state
                .children
                .insert(2, reverie::ExitStatus::Exited(9));
            parent
                .state
                .children
                .insert(3, reverie::ExitStatus::Exited(11));
            parent
                .signal_registry
                .controlled
                .store(true, Ordering::Release);
            let memory = GuestMemory::new(0, 8192).unwrap();
            memory.map_user_permissions(0, 8192, true, true).unwrap();
            memory
                .map_user_permissions(if status_fault { 0 } else { 4096 }, 4096, true, false)
                .unwrap();
            memory.enable_user_access();
            memory.write_raw(0, &[0xa5; 8192]).unwrap();
            let request = SyscallRequest::new(
                libc::SYS_wait4 as u64,
                [2, STATUS, libc::WUNTRACED as u64, USAGE, 0, 0],
            );
            assert_eq!(
                parent.execute_checked(&request, &memory).unwrap(),
                -i64::from(libc::EFAULT)
            );
            assert!(parent.state.consumed_child_wait.is_none());
            assert_eq!(parent.state.children.len(), 1);
            assert_eq!(
                parent.state.children.get(&3),
                Some(reverie::ExitStatus::Exited(11))
            );
            {
                let family = parent.signal_registry.family.lock().unwrap();
                let children = &family.direct_children[&process_key(parent_id)];
                assert_eq!(children.len(), 1);
                assert!(!children.contains_key(&process_key(child_id)));
                assert!(children.contains_key(&process_key(sibling_id)));
            }
            assert_eq!(
                parent.execute_checked(&request, &memory).unwrap(),
                -i64::from(libc::ECHILD)
            );
            let mut expected = [0xa5; 8192];
            if !status_fault {
                expected[STATUS as usize..STATUS as usize + 4]
                    .copy_from_slice(&(9_i32 << 8).to_ne_bytes());
            }
            let mut actual = [0; 8192];
            memory.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                parent
                    .execute_checked(
                        &SyscallRequest::new(libc::SYS_wait4 as u64, [3, 0, 0, 0, 0, 0]),
                        &memory,
                    )
                    .unwrap(),
                3
            );
            assert!(parent.state.children.is_empty());
            assert!(parent.state.consumed_child_wait.is_none());
            assert!(
                !parent
                    .signal_registry
                    .family
                    .lock()
                    .unwrap()
                    .direct_children
                    .contains_key(&process_key(parent_id))
            );
        }
    }

    #[test]
    fn wait4_copy_fault_consumes_the_exact_family_child_once() {
        const STATUS: u64 = 0x100;
        const USAGE: u64 = 0x200;
        const INVALID: u64 = 0x10000;
        for options in [
            0,
            libc::WUNTRACED as u64,
            (libc::WUNTRACED | libc::WNOHANG) as u64,
            (0xdead_beef_u64 << 32) | libc::WUNTRACED as u64,
        ] {
            for status_fault in [true, false] {
                let mut parent = executor();
                let parent_id = identity(&parent);
                let mut child = parent.fork_child(2, false, false).unwrap();
                child.retire_current_thread(reverie::ExitStatus::Exited(9), false);
                parent
                    .state
                    .children
                    .insert(2, reverie::ExitStatus::Exited(9));
                parent
                    .signal_registry
                    .controlled
                    .store(true, Ordering::Release);
                let mut memory = GuestMemory::new(0, 4096).unwrap();
                memory.write(0, &[0xa5; 4096]).unwrap();
                let request = SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [
                        2,
                        if status_fault { INVALID } else { STATUS },
                        options,
                        if status_fault { USAGE } else { INVALID },
                        0,
                        0,
                    ],
                );
                assert_eq!(
                    parent.execute_checked(&request, &memory).unwrap(),
                    -i64::from(libc::EFAULT)
                );
                assert!(parent.state.children.is_empty());
                assert!(parent.state.consumed_child_wait.is_none());
                assert!(
                    !parent
                        .signal_registry
                        .family
                        .lock()
                        .unwrap()
                        .direct_children
                        .contains_key(&process_key(parent_id)),
                    "an output fault must consume the exact family edge as well as the numeric child"
                );
                assert_eq!(
                    parent.execute_checked(&request, &memory).unwrap(),
                    -i64::from(libc::ECHILD)
                );
                let mut expected = [0xa5; 4096];
                if !status_fault {
                    // Linux writes status before attempting the rusage copy.
                    expected[STATUS as usize..STATUS as usize + 4]
                        .copy_from_slice(&(9_i32 << 8).to_le_bytes());
                }
                let mut actual = [0; 4096];
                memory.read(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn waitid_copy_fault_consumes_only_the_selected_family_child() {
        const INFO: u64 = 0x100;
        const USAGE: u64 = 0x1100;
        for info_fault in [true, false] {
            for accessible in [true, false] {
                for keep in [0, libc::WNOWAIT] {
                    let mut parent = executor();
                    let parent_id = identity(&parent);
                    let mut child = parent.fork_child(2, false, false).unwrap();
                    let child_id = identity(&child);
                    let mut sibling = parent.fork_child(3, false, false).unwrap();
                    let sibling_id = identity(&sibling);
                    child.retire_current_thread(reverie::ExitStatus::Exited(9), false);
                    sibling.retire_current_thread(reverie::ExitStatus::Exited(11), false);
                    parent
                        .state
                        .children
                        .insert(2, reverie::ExitStatus::Exited(9));
                    parent
                        .state
                        .children
                        .insert(3, reverie::ExitStatus::Exited(11));
                    parent
                        .signal_registry
                        .controlled
                        .store(true, Ordering::Release);
                    let memory = GuestMemory::new(0, 8192).unwrap();
                    memory.map_user_permissions(0, 8192, true, true).unwrap();
                    memory
                        .map_user_permissions(
                            if info_fault { 0 } else { 4096 },
                            4096,
                            accessible,
                            false,
                        )
                        .unwrap();
                    memory.enable_user_access();
                    memory.write_raw(0, &[0xa5; 8192]).unwrap();
                    let args = [
                        libc::P_PID as u64,
                        2,
                        INFO,
                        (libc::WEXITED | keep) as u64,
                        USAGE,
                        0,
                    ];
                    assert_eq!(
                        parent
                            .execute_checked(
                                &SyscallRequest::new(libc::SYS_waitid as u64, args),
                                &memory,
                            )
                            .unwrap(),
                        -i64::from(libc::EFAULT)
                    );
                    assert!(parent.state.consumed_child_wait.is_none());
                    assert_eq!(parent.state.children.len(), if keep == 0 { 1 } else { 2 });
                    assert_eq!(parent.state.children.contains_key(&2), keep != 0);
                    assert_eq!(
                        parent.state.children.get(&3),
                        Some(reverie::ExitStatus::Exited(11))
                    );
                    {
                        let family = parent.signal_registry.family.lock().unwrap();
                        let children = &family.direct_children[&process_key(parent_id)];
                        assert_eq!(children.len(), if keep == 0 { 1 } else { 2 });
                        assert_eq!(children.contains_key(&process_key(child_id)), keep != 0);
                        assert!(children.contains_key(&process_key(sibling_id)));
                    }
                    let mut expected = [0xa5; 8192];
                    if info_fault {
                        // Rusage succeeds before siginfo faults; KVM accounting
                        // remains zero. A rusage fault leaves every info byte.
                        expected
                            [USAGE as usize..USAGE as usize + std::mem::size_of::<libc::rusage>()]
                            .fill(0);
                    }
                    let mut actual = [0; 8192];
                    memory.read_raw(0, &mut actual).unwrap();
                    assert_eq!(actual, expected);
                    if keep != 0 {
                        // Do not infer retention from another protected EFAULT:
                        // an info fault can override an underlying ECHILD.
                        assert_eq!(
                            parent
                                .execute_checked(
                                    &SyscallRequest::new(
                                        libc::SYS_waitid as u64,
                                        [
                                            libc::P_PID as u64,
                                            2,
                                            0,
                                            (libc::WEXITED | libc::WNOWAIT) as u64,
                                            0,
                                            0,
                                        ],
                                    ),
                                    &memory,
                                )
                                .unwrap(),
                            0
                        );
                        assert!(parent.state.consumed_child_wait.is_none());
                        let mut consume = args;
                        consume[3] = libc::WEXITED as u64;
                        assert_eq!(
                            parent
                                .execute_checked(
                                    &SyscallRequest::new(libc::SYS_waitid as u64, consume),
                                    &memory,
                                )
                                .unwrap(),
                            -i64::from(libc::EFAULT)
                        );
                    }
                    assert!(parent.state.consumed_child_wait.is_none());
                    assert!(!parent.state.children.contains_key(&2));
                    {
                        let family = parent.signal_registry.family.lock().unwrap();
                        let children = &family.direct_children[&process_key(parent_id)];
                        assert_eq!(children.len(), 1);
                        assert!(!children.contains_key(&process_key(child_id)));
                        assert!(children.contains_key(&process_key(sibling_id)));
                    }
                    assert_eq!(
                        parent
                            .execute_checked(
                                &SyscallRequest::new(
                                    libc::SYS_waitid as u64,
                                    [libc::P_PID as u64, 2, 0, libc::WEXITED as u64, 0, 0],
                                ),
                                &memory,
                            )
                            .unwrap(),
                        -i64::from(libc::ECHILD)
                    );
                    assert!(parent.state.consumed_child_wait.is_none());
                    memory.read_raw(0, &mut actual).unwrap();
                    assert_eq!(actual, expected);
                    assert_eq!(
                        parent
                            .execute_checked(
                                &SyscallRequest::new(
                                    libc::SYS_waitid as u64,
                                    [libc::P_PID as u64, 3, 0, libc::WEXITED as u64, 0, 0],
                                ),
                                &memory,
                            )
                            .unwrap(),
                        0
                    );
                    assert!(parent.state.children.is_empty());
                    assert!(parent.state.consumed_child_wait.is_none());
                    assert!(
                        !parent
                            .signal_registry
                            .family
                            .lock()
                            .unwrap()
                            .direct_children
                            .contains_key(&process_key(parent_id))
                    );
                    memory.read_raw(0, &mut actual).unwrap();
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn child_wait_consumes_the_exact_family_child_selected_by_the_backend() {
        const INFO: u64 = 0x100;

        for mode in 0..6 {
            let mut parent = executor();
            let parent_id = identity(&parent);
            let mut low = parent.fork_child(2, false, false).unwrap();
            let mut high = parent.fork_child(3, false, false).unwrap();
            let low_id = identity(&low);
            let high_id = identity(&high);
            low.retire_current_thread(reverie::ExitStatus::Exited(2), false);
            high.retire_current_thread(reverie::ExitStatus::Exited(3), false);
            parent
                .state
                .children
                .insert(2, reverie::ExitStatus::Exited(2));
            parent
                .state
                .children
                .insert(3, reverie::ExitStatus::Exited(3));

            let (id_type, id, expected, consume, use_wait4) = match mode {
                0 => (libc::P_ALL, 0, low_id, true, false),
                1 => (libc::P_PGID, parent.state.pgid, low_id, true, false),
                2 => (libc::P_PID, high_id.tgid.as_raw(), high_id, true, false),
                3 => (libc::P_ALL, 0, low_id, false, false),
                4 => (libc::P_ALL, 0, low_id, true, true),
                5 => (libc::P_ALL, 0, low_id, true, true),
                _ => unreachable!(),
            };
            let memory = GuestMemory::new(0, 4096).unwrap();
            let selected = if use_wait4 {
                let selected = call(
                    &mut parent,
                    &memory,
                    libc::SYS_wait4,
                    [
                        u64::from(u32::MAX),
                        INFO,
                        (libc::WNOHANG | if mode == 5 { libc::WUNTRACED } else { 0 }) as u64,
                        0,
                        0,
                        0,
                    ],
                );
                libc::pid_t::try_from(selected).expect("wait4 returned the selected child pid")
            } else {
                let flags = libc::WEXITED | libc::WNOHANG | if consume { 0 } else { libc::WNOWAIT };
                assert_eq!(
                    call(
                        &mut parent,
                        &memory,
                        libc::SYS_waitid,
                        [id_type as u64, id as u64, INFO, flags as u64, 0, 0],
                    ),
                    0,
                );
                let info: libc::siginfo_t = read_struct(&memory, INFO);
                // SAFETY: waitid wrote the SIGCHLD variant of siginfo_t.
                unsafe { info.si_pid() }
            };
            assert_eq!(selected, expected.tgid.as_raw());

            let remaining = [low_id, high_id]
                .map(|child| parent.state.children.contains_key(&child.tgid.as_raw()));
            let family = parent
                .signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let children = family
                .direct_children
                .get(&process_key(parent_id))
                .expect("at least one waitable child remains");
            for (index, child) in [low_id, high_id].into_iter().enumerate() {
                let remains = !consume || child != expected;
                assert_eq!(
                    children.get(&process_key(child)).copied(),
                    remains.then_some(DirectChildState::WaitableZombie),
                    "family-ledger removal must follow the pid actually returned by the backend wait",
                );
                assert_eq!(
                    remaining[index], remains,
                    "backend wait state and exact-generation family state must change together",
                );
            }
        }
    }

    #[test]
    fn controlled_child_wait_fails_closed_without_an_exact_family_zombie() {
        let mut parent = executor();
        let parent_id = identity(&parent);
        parent
            .signal_registry
            .controlled
            .store(true, Ordering::Release);
        parent
            .state
            .children
            .insert(2, reverie::ExitStatus::Exited(2));
        // Explicitly corrupt the only eligibility ledger after a valid fixture
        // publication. No numeric status table may authorize this reap.
        parent
            .signal_registry
            .family
            .lock()
            .unwrap()
            .direct_children
            .remove(&process_key(parent_id));
        let memory = GuestMemory::new(0, 4096).unwrap();
        let error = parent
            .execute_checked(
                &SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [u64::from(u32::MAX), 0, libc::WNOHANG as u64, 0, 0, 0],
                ),
                &memory,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            crate::Error::FamilyWaitLedgerMismatch {
                parent,
                child_pid: 2,
            } if parent == parent_id
        ));
        assert!(
            !parent.state.children.contains_key(&2),
            "a corrupt family edge must not remain eligible after the typed refusal",
        );
        assert!(parent.state.consumed_child_wait.is_none());
    }

    #[test]
    fn stale_child_wait_effect_refuses_before_another_syscall_dispatch() {
        let mut parent = executor();
        let parent_id = identity(&parent);
        parent
            .state
            .children
            .insert(17, reverie::ExitStatus::Exited(17));
        let ChildWaitSelection::Ready(selected) =
            parent.state.children.select(Some(17), true, true).unwrap()
        else {
            panic!("ready fixture child");
        };
        parent.state.consumed_child_wait = selected.receipt;
        let memory = GuestMemory::new(0, 4096).unwrap();
        let error = parent
            .execute_checked(
                &SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
                &memory,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            crate::Error::ChildWaitLedgerEffectPending {
                parent,
                child_pid: 17,
            } if parent == parent_id
        ));
        assert_eq!(
            parent
                .state
                .consumed_child_wait
                .as_ref()
                .map(|receipt| receipt.child_pid()),
            Some(17)
        );
    }

    #[test]
    fn corrupt_family_ancestry_is_typed_instead_of_panicking_or_choosing_a_parent() {
        let root = executor();
        let parent = root.fork_child(2, false, false).unwrap();
        let mut child = parent.fork_child(3, false, false).unwrap();
        let root_id = identity(&root);
        let parent_id = identity(&parent);
        let child_id = identity(&child);
        parent
            .signal_registry
            .family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .direct_children
            .get_mut(&process_key(parent_id))
            .expect("parent owns its real child edge")
            .insert(process_key(root_id), DirectChildState::Live);

        child.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::AncestryCycle {
                ancestor: parent_id,
            }),
        );
        assert!(matches!(
            child.process_family_exit(),
            Err(crate::Error::ProcessFamilyAncestryCycle { process, ancestor })
                if process == child_id && ancestor == parent_id
        ));

        let root = executor();
        let parent = root.fork_child(2, false, false).unwrap();
        let mut child = parent.fork_child(3, false, false).unwrap();
        let root_id = identity(&root);
        let parent_id = identity(&parent);
        let child_id = identity(&child);
        let alternate_parent = SignalProcessId {
            tgid: reverie::Pid::from_raw(99),
            generation: 99,
        };
        parent
            .signal_registry
            .family
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .direct_children
            .entry(process_key(alternate_parent))
            .or_default()
            .insert(process_key(parent_id), DirectChildState::Live);

        child.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::MultipleParents {
                child: parent_id,
                first_parent: root_id,
                second_parent: alternate_parent,
            }),
        );
        assert!(matches!(
            child.process_family_exit(),
            Err(crate::Error::ProcessFamilyMultipleParents {
                process,
                child,
                first_parent,
                second_parent,
            }) if process == child_id
                && child == parent_id
                && first_parent == root_id
                && second_parent == alternate_parent
        ));
    }

    #[test]
    fn group_exit_records_family_order_before_peer_host_retirement() {
        let actions = [
            KernelSigaction {
                handler: libc::SIG_IGN as u64,
                ..Default::default()
            },
            KernelSigaction {
                handler: libc::SIG_DFL as u64,
                flags: libc::SA_NOCLDWAIT as u64,
                ..Default::default()
            },
        ];

        for action in actions {
            for owner_finishes_first in [false, true] {
                let parent = executor();
                let mut owner = parent.fork_child(2, false, false).unwrap();
                owner
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .dispositions
                    .insert(libc::SIGCHLD, action);
                let mut owner_peer = owner.thread_child(4).unwrap();
                let mut descendant = owner.fork_child(3, false, false).unwrap();
                let owner_id = identity(&owner);
                let descendant_id = identity(&descendant);

                owner_peer.retire_current_thread(reverie::ExitStatus::Exited(7), true);
                assert_eq!(
                    owner.signal_registry.process_family_exit(owner_id),
                    Some(ProcessFamilyExit::DescendantReparentingUnsupported {
                        child: descendant_id,
                    }),
                    "the ordered exit_group transition must not wait for peer host cancellation",
                );
                assert!(
                    owner.fork_child(6, false, false).is_err(),
                    "a peer cannot admit a new process after the family exit is frozen",
                );
                assert!(
                    !owner
                        .state
                        .task_lifecycle
                        .lock()
                        .unwrap()
                        .processes()
                        .any(|(tgid, _)| tgid == 6),
                    "refused late registration must retire its provisional lifecycle entry",
                );

                if owner_finishes_first {
                    owner.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
                    descendant.retire_current_thread(reverie::ExitStatus::Exited(9), false);
                } else {
                    descendant.retire_current_thread(reverie::ExitStatus::Exited(9), false);
                    owner.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
                }
                assert_eq!(
                    descendant
                        .signal_registry
                        .process_family_exit(descendant_id),
                    Some(ProcessFamilyExit::RunTeardownChild {
                        status: reverie::ExitStatus::Exited(9),
                    }),
                );
                assert_eq!(
                    owner.signal_registry.process_family_exit(owner_id),
                    Some(ProcessFamilyExit::DescendantReparentingUnsupported {
                        child: descendant_id,
                    }),
                    "physical peer order cannot replace the ordered family outcome",
                );
            }

            for owner_finishes_first in [false, true] {
                let parent = executor();
                let mut owner = parent.fork_child(2, false, false).unwrap();
                owner
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .dispositions
                    .insert(libc::SIGCHLD, action);
                let mut owner_peer = owner.thread_child(4).unwrap();
                let mut descendant = owner.fork_child(3, false, false).unwrap();
                let mut descendant_peer = descendant.thread_child(5).unwrap();
                let owner_id = identity(&owner);
                let descendant_id = identity(&descendant);

                descendant_peer.retire_current_thread(reverie::ExitStatus::Exited(9), true);
                assert!(matches!(
                    descendant
                        .signal_registry
                        .process_family_exit(descendant_id),
                    Some(ProcessFamilyExit::Child(ChildExitSnapshot {
                        completion: reverie::ChildExitCompletion {
                            waitable: false,
                            ..
                        },
                        ..
                    }))
                ));

                owner_peer.retire_current_thread(reverie::ExitStatus::Exited(7), true);
                assert!(matches!(
                    owner.signal_registry.process_family_exit(owner_id),
                    Some(ProcessFamilyExit::Child(_))
                ));

                if owner_finishes_first {
                    owner.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
                    descendant.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
                } else {
                    descendant.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
                    owner.retire_current_thread(reverie::ExitStatus::SUCCESS, false);
                }
                assert!(matches!(
                    descendant
                        .signal_registry
                        .process_family_exit(descendant_id),
                    Some(ProcessFamilyExit::Child(_))
                ));
                assert!(matches!(
                    owner.signal_registry.process_family_exit(owner_id),
                    Some(ProcessFamilyExit::Child(_))
                ));
            }
        }
    }

    #[test]
    fn failed_process_family_is_monotonic_across_peer_retirement_orders() {
        for leader_first in [false, true] {
            for leader_group_exit in [false, true] {
                let parent = executor();
                let mut owner = parent.fork_child(2, false, false).unwrap();
                let mut worker = owner.thread_child(4).unwrap();
                let mut descendant = owner.fork_child(3, false, false).unwrap();
                let owner_id = identity(&owner);
                let descendant_id = identity(&descendant);

                if leader_first {
                    owner.retire_current_thread(reverie::ExitStatus::Exited(7), false);
                    assert_eq!(
                        owner.signal_registry.process_family_exit(owner_id),
                        None,
                        "a surviving peer keeps the process logically live",
                    );
                    worker.retire_failed_thread();
                } else {
                    worker.retire_failed_thread();
                    owner.retire_current_thread(reverie::ExitStatus::Exited(7), leader_group_exit);
                }

                assert_eq!(
                    owner.signal_registry.process_family_exit(owner_id),
                    Some(ProcessFamilyExit::Failed),
                    "later success or exit_group cannot replace exact failure",
                );
                assert!(
                    owner.fork_child(6, false, false).is_err(),
                    "a failed process cannot admit another child",
                );
                descendant.retire_current_thread(reverie::ExitStatus::Exited(9), false);
                assert_eq!(
                    descendant
                        .signal_registry
                        .process_family_exit(descendant_id),
                    Some(ProcessFamilyExit::RunTeardownChild {
                        status: reverie::ExitStatus::Exited(9),
                    }),
                );
            }
        }

        let parent = executor();
        let mut owner = parent.fork_child(2, false, false).unwrap();
        let mut peer = owner.thread_child(4).unwrap();
        let owner_id = identity(&owner);
        peer.retire_current_thread(reverie::ExitStatus::Exited(7), true);
        assert!(matches!(
            owner.signal_registry.process_family_exit(owner_id),
            Some(ProcessFamilyExit::Child(_)),
        ));
        owner.retire_failed_thread();
        assert_eq!(
            owner.signal_registry.process_family_exit(owner_id),
            Some(ProcessFamilyExit::Failed),
            "a peer failure must override an optimistic exit_group family success",
        );
        assert!(
            parent
                .signal_registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .direct_children
                .get(&process_key(identity(&parent)))
                .is_none_or(|children| !children.contains_key(&process_key(owner_id))),
            "the failed process cannot remain as a waitable successful child",
        );

        let mut root = executor();
        let mut root_peer = root.thread_child(4).unwrap();
        let root_id = identity(&root);
        root_peer.retire_current_thread(reverie::ExitStatus::Exited(7), true);
        assert_eq!(
            root.signal_registry.process_family_exit(root_id),
            Some(ProcessFamilyExit::Root),
        );
        root.retire_failed_thread();
        assert_eq!(
            root.signal_registry.process_family_exit(root_id),
            Some(ProcessFamilyExit::Failed),
            "a peer failure must override an optimistic root exit_group success",
        );

        let mut root = executor();
        let mut child = root.fork_child(2, false, false).unwrap();
        let mut child_peer = child.thread_child(4).unwrap();
        let child_id = identity(&child);
        root.retire_current_thread(reverie::ExitStatus::Exited(1), false);
        child_peer.retire_current_thread(reverie::ExitStatus::Exited(7), true);
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(7),
            }),
        );
        child.retire_failed_thread();
        assert_eq!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::Failed),
            "a peer failure must override an optimistic run-teardown exit_group success",
        );

        let parent = executor();
        let mut owner = parent.fork_child(2, false, false).unwrap();
        let mut peer = owner.thread_child(4).unwrap();
        let descendant = owner.fork_child(3, false, false).unwrap();
        let owner_id = identity(&owner);
        let descendant_id = identity(&descendant);
        peer.retire_current_thread(reverie::ExitStatus::Exited(7), true);
        assert_eq!(
            owner.signal_registry.process_family_exit(owner_id),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported {
                child: descendant_id,
            }),
        );
        owner.retire_failed_thread();
        assert_eq!(
            owner.signal_registry.process_family_exit(owner_id),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported {
                child: descendant_id,
            }),
            "a generic peer failure must not erase an earlier typed fatal invariant",
        );
    }

    #[test]
    fn child_siginfo_encoder_and_coalescing_retain_first_nonzero_metadata() {
        let mut parent = executor();
        let parent_id = identity(&parent);
        let first = reverie::ChildExitCompletion {
            parent: parent_id,
            child: SignalProcessId {
                tgid: reverie::Pid::from_raw(2),
                generation: 41,
            },
            status: reverie::ExitStatus::Exited(7),
            waitable: true,
            uid: 1001,
            user_ticks: 17,
            system_ticks: 23,
        };
        let second = reverie::ChildExitCompletion {
            child: SignalProcessId {
                tgid: reverie::Pid::from_raw(3),
                generation: 42,
            },
            status: reverie::ExitStatus::Exited(9),
            uid: 1002,
            user_ticks: 29,
            system_ticks: 31,
            ..first
        };
        let first_event = child_exit_signal_event(first).unwrap();
        let second_event = child_exit_signal_event(second).unwrap();
        for (event, completion) in [(first_event, first), (second_event, second)] {
            let info = event.siginfo();
            assert_eq!(
                i32::from_ne_bytes(info[16..20].try_into().unwrap()),
                completion.child.tgid.as_raw()
            );
            assert_eq!(
                u32::from_ne_bytes(info[20..24].try_into().unwrap()),
                completion.uid
            );
            assert_eq!(
                i64::from_ne_bytes(info[32..40].try_into().unwrap()),
                completion.user_ticks
            );
            assert_eq!(
                i64::from_ne_bytes(info[40..48].try_into().unwrap()),
                completion.system_ticks
            );
        }

        let control = parent.signal_registry.control();
        assert_eq!(
            receipt(control.publish(parent_id, first_event, None, true)).change,
            PendingChange::Queued
        );
        assert_eq!(
            receipt(control.publish(parent_id, second_event, None, true)).change,
            PendingChange::Coalesced
        );
        assert_eq!(
            parent
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            first_event,
            "standard-signal coalescing must retain the first complete siginfo",
        );
    }

    #[test]
    fn child_publication_coalesces_and_retains_first_complete_siginfo() {
        let mut parent = executor();
        let parent_id = identity(&parent);
        let mut first = parent.fork_child(2, false, false).unwrap();
        let mut second = parent.fork_child(3, false, false).unwrap();
        let first_completion = child_completion(
            parent_id,
            identity(&first),
            reverie::ExitStatus::Exited(7),
            true,
        );
        let second_completion = child_completion(
            parent_id,
            identity(&second),
            reverie::ExitStatus::Exited(9),
            true,
        );
        first.retire_current_thread(first_completion.status, false);
        second.retire_current_thread(second_completion.status, false);
        let control = parent.backend_signal_control().process;
        assert_eq!(
            child_receipt(control.publish_child_exit(first_completion)).effect,
            reverie::ChildExitPublicationEffect::Queued
        );
        let second_receipt = child_receipt(control.publish_child_exit(second_completion));
        assert_eq!(
            second_receipt.effect,
            reverie::ChildExitPublicationEffect::Coalesced
        );
        assert_eq!(
            child_receipt(control.publish_child_exit(second_completion)),
            second_receipt,
            "an exact duplicate must retain the original coalesced receipt"
        );
        let info = parent
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap()
            .event
            .siginfo();
        assert_eq!(i32::from_ne_bytes(info[16..20].try_into().unwrap()), 2);
        assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(info[20..24].try_into().unwrap()), 0);
        assert_eq!(i64::from_ne_bytes(info[32..40].try_into().unwrap()), 0);
        assert_eq!(i64::from_ne_bytes(info[40..48].try_into().unwrap()), 0);
    }

    #[test]
    fn concurrent_exact_child_publications_commit_one_effect() {
        let mut parent = executor();
        let mut child = parent.fork_child(2, false, false).unwrap();
        let completion = child_completion(
            identity(&parent),
            identity(&child),
            reverie::ExitStatus::Exited(7),
            true,
        );
        child.retire_current_thread(completion.status, false);
        let control = parent.backend_signal_control().process;
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let control = control.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                control.publish_child_exit(completion)
            }));
        }
        barrier.wait();
        let first = workers.remove(0).join().unwrap();
        let second = workers.remove(0).join().unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            first,
            reverie::ChildExitPublicationResult::Committed(_)
        ));
        assert!(parent.take_pending_signal_for_delivery().unwrap().is_some());
        assert!(parent.take_pending_signal_for_delivery().unwrap().is_none());
    }

    #[test]
    fn generic_recipients_are_sorted_live_and_mask_aware() {
        let parent = executor();
        let high = parent.thread_child(9).unwrap();
        let low = parent.thread_child(3).unwrap();
        parent
            .state
            .thread_signals
            .lock()
            .blocked
            .insert(libc::SIGCHLD);
        let mut child = parent.fork_child(2, false, false).unwrap();
        let completion = child_completion(
            identity(&parent),
            identity(&child),
            reverie::ExitStatus::Exited(7),
            true,
        );
        child.retire_current_thread(completion.status, false);
        let control = parent.backend_signal_control().process;
        child_receipt(control.publish_child_exit(completion));
        assert_eq!(
            control
                .signal_recipients(completion.parent, libc::SIGCHLD)
                .unwrap()
                .into_iter()
                .map(|recipient| recipient.task.tid.as_raw())
                .collect::<Vec<_>>(),
            vec![3, 9]
        );
        high.state
            .thread_signals
            .lock()
            .blocked
            .insert(libc::SIGCHLD);
        assert_eq!(
            control
                .signal_recipients(completion.parent, libc::SIGCHLD)
                .unwrap()
                .into_iter()
                .map(|recipient| recipient.task.tid.as_raw())
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(
            control.signal_recipients(completion.parent, 0),
            Err(Errno::EINVAL)
        );
        drop(low);
        assert!(
            control
                .signal_recipients(completion.parent, libc::SIGCHLD)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn child_publication_uses_independent_carriers_and_refuses_a_missing_one() {
        let mut parent = executor();
        let mut child = parent.fork_child(2, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd_for(&mut parent, &mut memory, libc::SIGCHLD);
        let alias = call(
            &mut parent,
            &memory,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        ) as i32;
        assert!(alias > fd);
        let completion = child_completion(
            identity(&parent),
            identity(&child),
            reverie::ExitStatus::Exited(7),
            true,
        );
        child.retire_current_thread(completion.status, false);
        let control = parent.backend_signal_control().process;
        let table = parent.file_table.clone();
        let held = table.lock().unwrap();
        assert_eq!(
            child_receipt(control.publish_child_exit(completion)).effect,
            reverie::ChildExitPublicationEffect::Queued,
            "publication must not acquire the ordinary file table"
        );
        drop(held);
        assert!(ready(&parent, fd));

        let mut other_parent = executor();
        let mut other_child = other_parent.fork_child(2, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd_for(&mut other_parent, &mut memory, libc::SIGCHLD);
        let other_completion = child_completion(
            identity(&other_parent),
            identity(&other_child),
            reverie::ExitStatus::Exited(8),
            true,
        );
        other_child.retire_current_thread(other_completion.status, false);
        let carrier = other_parent
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers
            .remove(&fd)
            .unwrap();
        assert_eq!(
            other_parent
                .backend_signal_control()
                .process
                .publish_child_exit(other_completion),
            reverie::ChildExitPublicationResult::RejectedBeforeCommit(Errno::EBADF)
        );
        assert!(
            other_parent
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .is_empty()
        );
        drop(carrier);
    }

    #[test]
    fn child_signalfd_failure_retains_exact_receipt_and_is_not_retryable() {
        let mut parent = executor();
        let parent_id = identity(&parent);
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        parent
            .signal_registry
            .install(reverie::BackendSignalControlMode::ToolControlled, &run);
        let mut child = parent.fork_child(2, false, false).unwrap();
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let fd = signalfd_for(&mut parent, &mut memory, libc::SIGCHLD);
        let alias = call(
            &mut parent,
            &memory,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        ) as i32;
        assert!(alias > fd);
        let completion = child_completion(
            parent_id,
            identity(&child),
            reverie::ExitStatus::Signaled(reverie::Signal::SIGABRT, true),
            true,
        );
        child.retire_current_thread(completion.status, false);
        parent
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers
            .insert(
                alias,
                crate::signal::SignalFdCarrier::pin_eventfd(
                    &std::fs::File::open("/dev/null").unwrap(),
                )
                .unwrap(),
            );
        let committed_carrier = parent
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers[&fd]
            .clone();
        let control = parent.backend_signal_control().process;
        let reverie::ChildExitPublicationResult::FailedAfterCommit { receipt, errno } =
            control.publish_child_exit(completion)
        else {
            panic!("missing child post-commit failure")
        };
        assert_eq!(errno, Errno::EBADF);
        assert_eq!(receipt.completion, completion);
        assert_eq!(receipt.effect, reverie::ChildExitPublicationEffect::Queued);
        assert!(
            ready(&parent, fd) && ready(&parent, alias),
            "the lower-fd carrier must commit readiness before the higher-fd carrier fails"
        );
        set_signalfd_ready(committed_carrier.file(), false).unwrap();
        assert!(!ready(&parent, fd) && !ready(&parent, alias));
        assert_eq!(
            control.publish_child_exit(completion),
            reverie::ChildExitPublicationResult::FailedAfterCommit { receipt, errno },
            "an exact duplicate returns the retained failure without retrying the effect"
        );
        assert!(
            !ready(&parent, fd) && !ready(&parent, alias),
            "replaying a retained failure must not reapply the already committed lower carrier"
        );
        assert_eq!(
            control.finish_publication_failure(parent_id),
            Err(Errno::EINVAL),
            "the alarm-shaped finisher must not acknowledge a child receipt"
        );
        assert_eq!(
            control.finish_child_exit_publication_failure(reverie::ChildExitPublication {
                pending_generation: receipt.pending_generation + 1,
                ..receipt
            }),
            Err(Errno::EINVAL),
            "failure forwarding is bound to the exact retained receipt"
        );
        control
            .finish_child_exit_publication_failure(receipt)
            .unwrap();
        control
            .finish_child_exit_publication_failure(receipt)
            .expect("exact failure acknowledgement is idempotent");
        let retained = parent
            .take_process_publication_failure()
            .expect("root-owned child publication failure");
        assert!(
            matches!(retained.primary(), crate::Error::ChildExitPublication { receipt: actual, errno: Errno::EBADF } if *actual == receipt)
        );
    }

    #[test]
    fn process_binding_guard_retains_exact_generation_until_ack_scope_ends() {
        let parent = executor();
        let process = identity(&parent);
        let registry = parent.signal_registry.clone();
        let guard = parent.retain_signal_process_binding();
        drop(parent);
        assert!(
            registry.lookup(process).is_some(),
            "the callback guard must retain the exact weak registry binding"
        );
        drop(guard);
        assert!(registry.lookup(process).is_none());
    }
    include!("process_child_wait_tests.rs");
    include!("process_child_wait_guest_tests.rs");
}
