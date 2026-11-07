/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Process-wide guest wait authority. Physical child handles never enter this module.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WaitPhase {
    Pending,
    PublicationFenced,
    Ready,
    Consumed,
    Retired,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct WaitPublication {
    pub(super) parent: SignalProcessId,
    pub(super) phase: WaitPhase,
}

/// Proof of an already committed reap, retained across faulting copyout.
#[derive(Clone, Debug)]
pub(crate) struct ChildWaitReceipt {
    parent: SignalProcessId,
    child: SignalProcessId,
    consumer: reverie::SignalTaskIdentity,
    token: Arc<()>,
}

impl ChildWaitReceipt {
    pub(crate) fn child_pid(&self) -> i32 {
        self.child.tgid.as_raw()
    }
}

/// A bound view of the one run family ledger, not a second status table.
#[derive(Clone, Default)]
pub(crate) struct ChildWaitContext {
    registry: Option<Arc<ProcessSignalRegistry>>,
    identity: Option<reverie::SignalTaskIdentity>,
}

impl std::fmt::Debug for ChildWaitContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildWaitContext")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

pub(crate) enum ChildWaitSelection {
    Ready(SelectedChildWait),
    Pending,
    NoChild,
    // The executor must validate its still-live identity and committed group status.
    ParentTerminated,
}

pub(crate) struct SelectedChildWait {
    pub(crate) status: reverie::ExitStatus,
    pub(crate) child: SignalProcessId,
    pub(crate) receipt: Option<ChildWaitReceipt>,
}

impl ChildWaitContext {
    pub(crate) fn bind(
        registry: Arc<ProcessSignalRegistry>,
        identity: reverie::SignalTaskIdentity,
    ) -> Self {
        Self {
            registry: Some(registry),
            identity: Some(identity),
        }
    }

    fn bound(&self) -> crate::Result<(&Arc<ProcessSignalRegistry>, reverie::SignalTaskIdentity)> {
        self.registry.as_ref().zip(self.identity).ok_or_else(|| {
            crate::Error::UnexpectedVcpuExit(
                "KVM wait has no exact process-family context".to_owned(),
            )
        })
    }

    pub(crate) fn task_identity(&self) -> crate::Result<reverie::SignalTaskIdentity> {
        self.bound().map(|(_, identity)| identity)
    }

    pub(crate) fn select(
        &self,
        requested: Option<i32>,
        consume: bool,
        nonblocking: bool,
    ) -> crate::Result<ChildWaitSelection> {
        let (registry, identity) = self.bound()?;
        registry.select_child_wait(identity, requested, consume, nonblocking)
    }

    pub(crate) fn has_ready(&self, requested: Option<i32>) -> crate::Result<bool> {
        let (registry, identity) = self.bound()?;
        let family = registry.family.lock().unwrap_or_else(|p| p.into_inner());
        Ok(family.wait_publications.iter().any(|(child, publication)| {
            publication.parent == identity.process
                && publication.phase == WaitPhase::Ready
                && requested.is_none_or(|pid| pid == child.0)
        }))
    }

    pub(crate) fn acknowledge(&self, receipt: ChildWaitReceipt) -> crate::Result<()> {
        let (registry, identity) = self.bound()?;
        registry.acknowledge_child_wait(identity, receipt)
    }

    #[cfg(any(test, feature = "native-test-support"))]
    pub(crate) fn publish_fixture_owner(
        &self,
        status: reverie::ExitStatus,
        slot: &super::super::ChildCompletionSlot,
    ) -> crate::Result<()> {
        let (registry, identity) = self.bound()?;
        let completion = match registry.claim_child_exit(identity.process) {
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.child == identity.process
                    && snapshot.completion.status == status =>
            {
                super::super::ChildCompletion::from_waitability(
                    status,
                    snapshot.completion.waitable,
                )
            }
            Some(
                ProcessFamilyExit::RunTeardownChild { status: frozen }
                | ProcessFamilyExit::ReapedByNamespaceInit { status: frozen },
            ) if frozen == status => super::super::ChildCompletion::AutoReaped(status),
            family => {
                return Err(crate::Error::UnexpectedVcpuExit(format!(
                    "native fixture child {:?} completion {status:?} disagrees with frozen family {family:?}",
                    identity.process,
                )));
            }
        };
        registry.publish_wait_boundary(identity.process, completion, slot, false)
    }

    #[cfg(test)]
    pub(crate) fn test_root() -> Self {
        Self::bind(
            Arc::new(ProcessSignalRegistry::default()),
            reverie::SignalTaskIdentity {
                process: SignalProcessId {
                    tgid: reverie::Pid::from_raw(1),
                    generation: 1,
                },
                tid: reverie::Pid::from_raw(1),
                task_generation: 1,
            },
        )
    }

    pub(crate) fn registry(&self) -> Option<Arc<ProcessSignalRegistry>> {
        self.registry.clone()
    }

    /// Explicit raw-scalar fixture registration: create the exact family edge,
    /// frozen terminal policy and ready publication together. Production never
    /// imports an unregistered numeric status through this helper.
    #[cfg(test)]
    pub(crate) fn insert(&self, pid: i32, status: reverie::ExitStatus) {
        let (registry, identity) = self.bound().expect("raw wait fixture has a family context");
        registry.seed_wait_test_child(identity.process, pid, status);
    }

    #[cfg(test)]
    pub(crate) fn get(&self, pid: &i32) -> Option<reverie::ExitStatus> {
        let (registry, identity) = self.bound().expect("wait fixture has a family context");
        let family = registry.family.lock().unwrap();
        family
            .wait_publications
            .iter()
            .find_map(|(child, publication)| {
                (publication.parent == identity.process
                    && child.0 == *pid
                    && publication.phase == WaitPhase::Ready
                    && family
                        .direct_children
                        .get(&process_key(identity.process))
                        .and_then(|children| children.get(child))
                        == Some(&DirectChildState::WaitableZombie))
                .then(|| match family.terminal.get(child) {
                    Some(ProcessFamilyExit::Child(snapshot)) => Some(snapshot.completion.status),
                    _ => None,
                })
                .flatten()
            })
    }

    #[cfg(test)]
    pub(crate) fn assert_namespace_reaped_child_for_test(
        &self,
        child: SignalProcessId,
        status: reverie::ExitStatus,
    ) {
        let (registry, identity) = self.bound().expect("orphan fixture has a family context");
        let family = registry.family.lock().unwrap();
        let parent_key = process_key(identity.process);
        let child_key = process_key(child);
        assert_eq!(
            family
                .wait_publications
                .get(&child_key)
                .map(|publication| (publication.parent, publication.phase,)),
            Some((identity.process, WaitPhase::Retired)),
        );
        assert_eq!(
            family.terminal.get(&child_key),
            Some(&ProcessFamilyExit::ReapedByNamespaceInit { status }),
        );
        assert!(
            !family
                .direct_children
                .get(&parent_key)
                .is_some_and(|children| { children.contains_key(&child_key) }),
            "outside init adoption must remove the former parent's exact child edge",
        );
        assert!(
            !family.wait_receipts.contains_key(&(parent_key, child_key)),
            "outside init reaping must not fabricate a traced wait receipt",
        );
    }

    #[cfg(test)]
    pub(crate) fn remove(&self, pid: &i32) -> Option<reverie::ExitStatus> {
        match self
            .select(Some(*pid), true, true)
            .expect("coherent test child")
        {
            ChildWaitSelection::Ready(selected) => {
                self.acknowledge(selected.receipt.expect("consuming test wait"))
                    .unwrap();
                Some(selected.status)
            }
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, pid: &i32) -> bool {
        self.get(pid).is_some()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        let (registry, identity) = self.bound().expect("wait fixture has a family context");
        registry
            .family
            .lock()
            .unwrap()
            .wait_publications
            .values()
            .filter(|publication| {
                publication.parent == identity.process && publication.phase == WaitPhase::Ready
            })
            .count()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Adapt the existing run-failure subscription to the family predicate. This
/// uses no polling thread or timeout. Taking the same lock before notification
/// prevents a failure between the final predicate check and condvar sleep.
struct WaitFailureWake(Weak<ProcessSignalRegistry>);
impl std::task::Wake for WaitFailureWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(registry) = self.0.upgrade() {
            registry
                .family
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .wait_failure_notified = true;
            registry.wait_changed.notify_all();
        }
    }
}

impl ProcessSignalRegistry {
    fn wait_error(parent: SignalProcessId, child_pid: i32) -> crate::Error {
        crate::Error::FamilyWaitLedgerMismatch { parent, child_pid }
    }

    fn publication_phase(
        family: &ProcessFamilyState,
        child: SignalProcessId,
        completion: super::super::ChildCompletion,
    ) -> crate::Result<WaitPhase> {
        let key = process_key(child);
        let publication = family.wait_publications.get(&key).ok_or_else(|| {
            crate::Error::UnexpectedVcpuExit(
                "KVM child completion has no exact wait registration".to_owned(),
            )
        })?;
        if publication.phase == WaitPhase::Retired {
            return Ok(WaitPhase::Retired);
        }
        if !matches!(
            publication.phase,
            WaitPhase::Pending | WaitPhase::PublicationFenced
        ) {
            return Err(Self::wait_error(publication.parent, child.tgid.as_raw()));
        }
        match (family.terminal.get(&key), completion) {
            (
                Some(ProcessFamilyExit::Child(snapshot)),
                super::super::ChildCompletion::Waitable(status),
            ) if snapshot.completion.parent == publication.parent
                && snapshot.completion.child == child
                && snapshot.completion.status == status
                && snapshot.completion.waitable
                && family
                    .direct_children
                    .get(&process_key(publication.parent))
                    .and_then(|children| children.get(&key))
                    == Some(&DirectChildState::WaitableZombie) =>
            {
                Ok(WaitPhase::Ready)
            }
            (
                Some(ProcessFamilyExit::Child(snapshot)),
                super::super::ChildCompletion::AutoReaped(status),
            ) if snapshot.completion.parent == publication.parent
                && snapshot.completion.child == child
                && snapshot.completion.status == status
                && !snapshot.completion.waitable =>
            {
                Ok(WaitPhase::Retired)
            }
            (
                Some(
                    ProcessFamilyExit::ReapedByNamespaceInit { status }
                    | ProcessFamilyExit::RunTeardownChild { status },
                ),
                super::super::ChildCompletion::AutoReaped(actual),
            ) if *status == actual => Ok(WaitPhase::Retired),
            _ => Err(Self::wait_error(publication.parent, child.tgid.as_raw())),
        }
    }

    /// Lock order is family -> physical slot. Neither lock survives the Tool
    /// callback. A waiter sees either Pending or the complete publication fence.
    pub(crate) fn begin_wait_boundary(
        &self,
        child: SignalProcessId,
        slot: &super::super::ChildCompletionSlot,
    ) -> crate::Result<()> {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let publication = family
            .wait_publications
            .get_mut(&process_key(child))
            .ok_or_else(|| {
                crate::Error::UnexpectedVcpuExit(
                    "KVM wait fence has no child generation".to_owned(),
                )
            })?;
        if !matches!(publication.phase, WaitPhase::Pending | WaitPhase::Retired)
            || !slot.begin_publication()
        {
            return Err(Self::wait_error(publication.parent, child.tgid.as_raw()));
        }
        if publication.phase != WaitPhase::Retired {
            publication.phase = WaitPhase::PublicationFenced;
        }
        Ok(())
    }

    pub(crate) fn publish_wait_boundary(
        &self,
        child: SignalProcessId,
        completion: super::super::ChildCompletion,
        slot: &super::super::ChildCompletionSlot,
        fenced: bool,
    ) -> crate::Result<()> {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let phase = Self::publication_phase(&family, child, completion)?;
        let published = if fenced {
            slot.publish_after_fence(completion)
        } else {
            slot.publish(completion)
        };
        if !published {
            return Err(Self::wait_error(
                family.wait_publications[&process_key(child)].parent,
                child.tgid.as_raw(),
            ));
        }
        family
            .wait_publications
            .get_mut(&process_key(child))
            .unwrap()
            .phase = phase;
        self.wait_changed.notify_all();
        Ok(())
    }

    /// Resolve once when the unique physical owner is registered. A retained
    /// old generation cannot bind a new handle after guest consumption.
    pub(crate) fn registered_child_wait(
        &self,
        parent: SignalProcessId,
        pid: i32,
    ) -> Option<SignalProcessId> {
        let family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let mut candidates = family
            .wait_publications
            .iter()
            .filter(|(child, publication)| {
                child.0 == pid
                    && publication.parent == parent
                    && publication.phase != WaitPhase::Consumed
            });
        let (child, _) = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        Some(process_identity(*child))
    }

    pub(crate) fn publish_direct_child_wait(
        &self,
        child: SignalProcessId,
        completion: super::super::ChildCompletion,
    ) -> crate::Result<()> {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let phase = Self::publication_phase(&family, child, completion)?;
        family
            .wait_publications
            .get_mut(&process_key(child))
            .unwrap()
            .phase = phase;
        self.wait_changed.notify_all();
        Ok(())
    }

    /// Physical owners may finish after any sibling consumed the status. They
    /// validate their frozen result but must never reinsert wait eligibility.
    pub(crate) fn validate_owned_child_wait(
        &self,
        parent: SignalProcessId,
        child: SignalProcessId,
        completion: super::super::ChildCompletion,
    ) -> crate::Result<()> {
        let family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let actual = match completion {
            super::super::ChildCompletion::Waitable(s)
            | super::super::ChildCompletion::AutoReaped(s) => s,
        };
        let valid = match family.terminal.get(&process_key(child)) {
            Some(ProcessFamilyExit::Child(snapshot)) => {
                snapshot.completion.status == actual && snapshot.completion.parent == parent
            }
            Some(
                ProcessFamilyExit::RunTeardownChild { status }
                | ProcessFamilyExit::ReapedByNamespaceInit { status },
            ) => *status == actual,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Self::wait_error(parent, child.tgid.as_raw()))
        }
    }

    fn select_child_wait(
        self: &Arc<Self>,
        identity: reverie::SignalTaskIdentity,
        requested: Option<i32>,
        consume: bool,
        nonblocking: bool,
    ) -> crate::Result<ChildWaitSelection> {
        let parent = identity.process;
        let run = self
            .run_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .upgrade();
        let mut failure = run.map(|run| Box::pin(run.subscribe()));
        let waker = std::task::Waker::from(Arc::new(WaitFailureWake(Arc::downgrade(self))));
        let poll_failure =
            |failure: &mut Option<std::pin::Pin<Box<crate::failure::FailureSubscription>>>| {
                failure.as_mut().is_some_and(|failure| {
                    std::future::Future::poll(
                        failure.as_mut(),
                        &mut std::task::Context::from_waker(&waker),
                    )
                    .is_ready()
                })
            };
        let already_failed = poll_failure(&mut failure);
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        if already_failed {
            family.wait_failed = true;
            self.wait_changed.notify_all();
        }
        loop {
            if family.wait_failed {
                return Err(crate::Error::RunAborted);
            }
            if family.wait_failure_notified {
                // A waker is a hint, not a terminal result. Poll without any
                // family lock (including a possible inline wake), then rescan
                // every family predicate before deciding to sleep again.
                family.wait_failure_notified = false;
                drop(family);
                let failed = poll_failure(&mut failure);
                family = self.family.lock().unwrap_or_else(|p| p.into_inner());
                if failed {
                    family.wait_failed = true;
                    self.wait_changed.notify_all();
                }
                continue;
            }
            if let Some(exit) = family.terminal.get(&process_key(parent)) {
                if !matches!(
                    exit,
                    ProcessFamilyExit::Root
                        | ProcessFamilyExit::Child(_)
                        | ProcessFamilyExit::RunTeardownChild { .. }
                        | ProcessFamilyExit::ReapedByNamespaceInit { .. }
                ) {
                    return Err(crate::Error::RunAborted);
                }
                // A clean parent exit does not erase an already committed
                // child publication/family failure. Check all relevant children
                // before returning terminal control, even if one was ready.
                for (child, publication) in &family.wait_publications {
                    if publication.parent != parent || requested.is_some_and(|pid| pid != child.0) {
                        continue;
                    }
                    if publication.phase == WaitPhase::Failed
                        || family.terminal.get(child).is_some_and(|exit| {
                            !matches!(
                                exit,
                                ProcessFamilyExit::Child(_)
                                    | ProcessFamilyExit::RunTeardownChild { .. }
                                    | ProcessFamilyExit::ReapedByNamespaceInit { .. }
                            )
                        })
                    {
                        return Err(crate::Error::RunAborted);
                    }
                }
                return Ok(ChildWaitSelection::ParentTerminated);
            }
            let mut pending = false;
            let mut fenced = false;
            let mut ready = None;
            for (child, publication) in &family.wait_publications {
                if publication.parent != parent || requested.is_some_and(|pid| pid != child.0) {
                    continue;
                }
                if family.terminal.get(child).is_some_and(|exit| {
                    !matches!(
                        exit,
                        ProcessFamilyExit::Child(_)
                            | ProcessFamilyExit::RunTeardownChild { .. }
                            | ProcessFamilyExit::ReapedByNamespaceInit { .. }
                    )
                }) {
                    return Err(crate::Error::RunAborted);
                }
                match publication.phase {
                    WaitPhase::Pending => pending = true,
                    WaitPhase::PublicationFenced => fenced = true,
                    WaitPhase::Ready => {
                        // Keep the first ready child, but inspect every matching
                        // publication for a committed failure before consuming.
                        ready.get_or_insert(*child);
                    }
                    WaitPhase::Failed => return Err(crate::Error::RunAborted),
                    WaitPhase::Consumed | WaitPhase::Retired => {}
                }
            }
            if let Some(child) = ready {
                let snapshot = match family.terminal.get(&child) {
                    Some(ProcessFamilyExit::Child(snapshot))
                        if snapshot.completion.parent == parent && snapshot.completion.waitable =>
                    {
                        *snapshot
                    }
                    _ => return Err(Self::wait_error(parent, child.0)),
                };
                if family
                    .direct_children
                    .get(&process_key(parent))
                    .and_then(|children| children.get(&child))
                    != Some(&DirectChildState::WaitableZombie)
                {
                    return Err(Self::wait_error(parent, child.0));
                }
                let receipt = if consume {
                    let receipt = ChildWaitReceipt {
                        parent,
                        child: process_identity(child),
                        consumer: identity,
                        token: Arc::new(()),
                    };
                    let children = family
                        .direct_children
                        .get_mut(&process_key(parent))
                        .unwrap();
                    children.remove(&child);
                    if children.is_empty() {
                        family.direct_children.remove(&process_key(parent));
                    }
                    family.wait_publications.get_mut(&child).unwrap().phase = WaitPhase::Consumed;
                    let old = family
                        .wait_receipts
                        .insert((process_key(parent), child), receipt.clone());
                    assert!(old.is_none(), "KVM child consumed twice");
                    self.wait_changed.notify_all();
                    Some(receipt)
                } else {
                    None
                };
                return Ok(ChildWaitSelection::Ready(SelectedChildWait {
                    status: snapshot.completion.status,
                    child: process_identity(child),
                    receipt,
                }));
            }
            if !pending && !fenced {
                return Ok(ChildWaitSelection::NoChild);
            }
            if nonblocking && !fenced {
                return Ok(ChildWaitSelection::Pending);
            }
            #[cfg(test)]
            {
                family.waiters += 1;
                self.wait_changed.notify_all();
            }
            family = self
                .wait_changed
                .wait(family)
                .unwrap_or_else(|p| p.into_inner());
            #[cfg(test)]
            {
                family.waiters -= 1;
            }
        }
    }

    fn acknowledge_child_wait(
        &self,
        identity: reverie::SignalTaskIdentity,
        receipt: ChildWaitReceipt,
    ) -> crate::Result<()> {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        let key = (process_key(receipt.parent), process_key(receipt.child));
        let valid = identity == receipt.consumer
            && identity.process == receipt.parent
            && family.wait_receipts.get(&key).is_some_and(|actual| {
                Arc::ptr_eq(&actual.token, &receipt.token) && actual.consumer == identity
            });
        if !valid {
            return Err(Self::wait_error(identity.process, receipt.child_pid()));
        }
        family.wait_receipts.remove(&key);
        Ok(())
    }

    pub(crate) fn fail_child_wait(&self, child: SignalProcessId) {
        let mut family = self.family.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(publication) = family.wait_publications.get_mut(&process_key(child))
            && !matches!(publication.phase, WaitPhase::Consumed | WaitPhase::Retired)
        {
            publication.phase = WaitPhase::Failed;
        }
        self.wait_changed.notify_all();
    }

    #[cfg(test)]
    pub(super) fn wait_for_guest_waiter(&self) -> bool {
        let family = self.family.lock().unwrap();
        let (family, timed_out) = self
            .wait_changed
            .wait_timeout_while(family, std::time::Duration::from_secs(5), |family| {
                family.waiters == 0
            })
            .unwrap();
        !timed_out.timed_out() && family.waiters != 0
    }

    #[cfg(test)]
    pub(super) fn seed_wait_test_child(
        &self,
        parent: SignalProcessId,
        pid: i32,
        status: reverie::ExitStatus,
    ) {
        let mut family = self.family.lock().unwrap();
        if let Some(child) = family
            .wait_publications
            .iter()
            .find_map(|(child, publication)| {
                (publication.parent == parent
                    && child.0 == pid
                    && publication.phase == WaitPhase::Pending)
                    .then_some(*child)
            })
        {
            let Some(ProcessFamilyExit::Child(snapshot)) = family.terminal.get(&child) else {
                panic!("fixture must record the real child exit before publication");
            };
            assert_eq!(snapshot.completion.status, status);
            assert!(snapshot.completion.waitable);
            family.wait_publications.get_mut(&child).unwrap().phase = WaitPhase::Ready;
            self.wait_changed.notify_all();
            return;
        }
        let child = SignalProcessId {
            tgid: reverie::Pid::from_raw(pid),
            generation: u64::try_from(pid).unwrap(),
        };
        let key = process_key(child);
        assert!(
            !family.wait_publications.contains_key(&key),
            "duplicate test child"
        );
        family
            .direct_children
            .entry(process_key(parent))
            .or_default()
            .insert(key, DirectChildState::WaitableZombie);
        family.terminal.insert(
            key,
            ProcessFamilyExit::Child(ChildExitSnapshot {
                completion: reverie::ChildExitCompletion {
                    parent,
                    child,
                    status,
                    waitable: true,
                    uid: 0,
                    user_ticks: 0,
                    system_ticks: 0,
                },
                disposition: PublicationDisposition::Default,
                pending_generation: 0,
            }),
        );
        family.wait_publications.insert(
            key,
            WaitPublication {
                parent,
                phase: WaitPhase::Ready,
            },
        );
    }
}

/// Explicit unit-fixture producer. It supplies the family exit that a real
/// child records in take_exit; no production registration or wait path repairs
/// a missing family entry from an untrusted numeric completion.
#[cfg(test)]
pub(crate) struct TestChildCompletion {
    pub(crate) slot: Arc<super::super::ChildCompletionSlot>,
    registry: Arc<ProcessSignalRegistry>,
    parent: SignalProcessId,
    child: SignalProcessId,
}

#[cfg(test)]
impl std::ops::Deref for TestChildCompletion {
    type Target = super::super::ChildCompletionSlot;
    fn deref(&self) -> &Self::Target {
        &self.slot
    }
}

#[cfg(test)]
impl TestChildCompletion {
    pub(crate) fn new(context: &ChildWaitContext, pid: i32) -> Self {
        let (registry, identity) = context.bound().expect("mock parent has an exact family");
        let child = SignalProcessId {
            tgid: reverie::Pid::from_raw(pid),
            generation: pid as u64,
        };
        let mut family = registry.family.lock().unwrap();
        assert!(
            family
                .wait_publications
                .insert(
                    process_key(child),
                    WaitPublication {
                        parent: identity.process,
                        phase: WaitPhase::Pending
                    }
                )
                .is_none(),
            "duplicate mock child generation"
        );
        family
            .direct_children
            .entry(process_key(identity.process))
            .or_default()
            .insert(process_key(child), DirectChildState::Live);
        drop(family);
        Self {
            slot: Arc::default(),
            registry: registry.clone(),
            parent: identity.process,
            child,
        }
    }

    fn record_exit(&self, completion: super::super::ChildCompletion) {
        let (status, waitable) = match completion {
            super::super::ChildCompletion::Waitable(status) => (status, true),
            super::super::ChildCompletion::AutoReaped(status) => (status, false),
        };
        let mut family = self.registry.family.lock().unwrap();
        let key = process_key(self.child);
        assert!(
            !family.terminal.contains_key(&key),
            "mock child exit repeated"
        );
        family.terminal.insert(
            key,
            ProcessFamilyExit::Child(ChildExitSnapshot {
                completion: reverie::ChildExitCompletion {
                    parent: self.parent,
                    child: self.child,
                    status,
                    waitable,
                    uid: 0,
                    user_ticks: 0,
                    system_ticks: 0,
                },
                disposition: PublicationDisposition::Default,
                pending_generation: 0,
            }),
        );
        let children = family
            .direct_children
            .get_mut(&process_key(self.parent))
            .expect("mock child has parent edge");
        if waitable {
            children.insert(key, DirectChildState::WaitableZombie);
        } else {
            children.remove(&key);
        }
    }

    pub(crate) fn begin_publication(&self) -> bool {
        self.registry
            .begin_wait_boundary(self.child, &self.slot)
            .is_ok()
    }

    pub(crate) fn publish_after_fence(&self, completion: super::super::ChildCompletion) -> bool {
        self.record_exit(completion);
        self.registry
            .publish_wait_boundary(self.child, completion, &self.slot, true)
            .is_ok()
    }

    pub(crate) fn publish(&self, completion: super::super::ChildCompletion) -> bool {
        self.record_exit(completion);
        self.registry
            .publish_wait_boundary(self.child, completion, &self.slot, false)
            .is_ok()
    }

    pub(crate) fn fail_if_pending(&self) -> bool {
        let failed = self.slot.fail_if_pending();
        self.registry.fail_child_wait(self.child);
        failed
    }
}
