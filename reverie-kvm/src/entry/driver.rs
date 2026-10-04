/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Driver-side interruption and completion. None of these operations invokes
//! a Tool. The existing outer driver still owns effects and publication.

use std::sync::Arc;

use futures::FutureExt;
use futures::future::Either;
use futures::future::select;

use super::EntryGate;
use super::PendingFailure;
use super::owner::DriverLifecycle;
use super::owner::DriverOwner;
use super::owner::DriverScope;
use crate::Error;
use crate::Result;
use crate::failure::references_shared_error;
use crate::vm::KvmBackend;

/// Invocation-scoped observations of real public worker boundaries. An entry
/// is keyed by the actual host thread (the join target for physical joins).
/// Observers run after the registry lock is released and must not block.
#[cfg(test)]
pub(crate) mod test_observation {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread::ThreadId;

    use crate::entry::EntryGate;
    use crate::entry::EntryOrigin;
    use crate::entry::PendingFailure;

    #[derive(Clone)]
    pub(crate) enum Event {
        Copy(Arc<EntryGate>, EntryOrigin),
        ForeignPending(Arc<PendingFailure>),
        JoinStarted {
            target: ThreadId,
            joiner: ThreadId,
            process: bool,
        },
        JoinReturned {
            target: ThreadId,
            joiner: ThreadId,
            process: bool,
        },
    }
    type Observer = Arc<dyn Fn(Event) + Send + Sync>;
    static OBSERVERS: Mutex<Vec<(ThreadId, Observer)>> = Mutex::new(Vec::new());

    pub(crate) struct Guard(ThreadId);
    impl Guard {
        pub(crate) fn current(observer: Observer) -> Self {
            let thread = std::thread::current().id();
            let mut observers = OBSERVERS.lock().unwrap();
            assert!(!observers.iter().any(|(id, _)| *id == thread));
            observers.push((thread, observer));
            Self(thread)
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            OBSERVERS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|(id, _)| *id != self.0);
        }
    }
    pub(crate) fn emit(target: ThreadId, event: Event) {
        let observer = OBSERVERS
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| *id == target)
            .map(|(_, observer)| observer.clone());
        if let Some(observer) = observer {
            observer(event);
        }
    }
    pub(crate) fn current(event: Event) {
        emit(std::thread::current().id(), event);
    }
    pub(crate) fn join(target: ThreadId, process: bool, returned: bool) {
        let joiner = std::thread::current().id();
        let event = if returned {
            Event::JoinReturned {
                target,
                joiner,
                process,
            }
        } else {
            Event::JoinStarted {
                target,
                joiner,
                process,
            }
        };
        emit(target, event);
    }
}

fn protocol(operation: &'static str) -> Error {
    Error::EntryControl {
        operation,
        source: std::io::Error::other(operation),
    }
}

/// The watch owns neither the callback nor its publisher. It can therefore be
/// polled while the callback borrows its backend and executor mutably.
#[derive(Clone)]
pub(crate) struct EntryDriverWatch {
    owner: Option<DriverOwner>,
    gate: Arc<EntryGate>,
}

impl EntryDriverWatch {
    /// A callback may retain a view of a different mapping owned by this same
    /// driver. Observe that owner's obligations as well as this mapping's gate.
    pub(crate) fn for_memory(memory: &crate::GuestMemory) -> Self {
        let operation = memory.entry_origin().operation;
        Self {
            owner: operation.as_ref().and_then(|origin| origin.driver_owner()),
            gate: memory.entry_gate(),
        }
    }

    /// A retained operation view can outlive the owner allocation. Keep its
    /// weak retirement witness in the caller instead of inventing an owner.
    pub(crate) fn check_operation(
        &self,
        operation: Option<&super::owner::OperationOrigin>,
    ) -> Result<()> {
        let result = self.check();
        if self.owner.is_none()
            && operation.is_some_and(|operation| operation.lifecycle() != DriverLifecycle::Active)
        {
            combine_pending(
                result,
                Err(protocol("operation after driver registration closed")),
            )
        } else {
            result
        }
    }

    pub(crate) fn check(&self) -> Result<()> {
        let owned = self
            .owner
            .as_ref()
            .map(DriverOwner::pending)
            .unwrap_or_default();
        let result = fold_causes(Ok(()), owned.iter().flat_map(|failure| failure.causes()));
        let result = match self.gate.pending_failure() {
            Some(failure) => fold_causes(result, failure.causes()),
            None => result,
        };
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.lifecycle() != DriverLifecycle::Active)
        {
            combine_pending(
                result,
                Err(protocol("operation after driver registration closed")),
            )
        } else {
            result
        }
    }

    pub(crate) async fn wait(&self) {
        loop {
            // Both subscriptions precede the state checks. A callback drop or
            // unrelated gate reopening only rotates this loop; it is not a
            // fatal event and is never a publication receipt.
            let gate = self.gate.subscribe();
            let owner = self.owner.as_ref().map(DriverOwner::subscribe);
            if self.check().is_err() {
                return;
            }
            match owner {
                Some(owner) => {
                    let _ = select(gate, owner).await;
                }
                None => {
                    let _ = gate.await;
                }
            }
        }
    }
}

/// Append shared causes once by identity. A private cause must survive a
/// competing terminal notification, without discarding cancellation effects.
pub(crate) fn fold_causes<R>(
    mut result: Result<R>,
    causes: impl IntoIterator<Item = Arc<Error>>,
) -> Result<R> {
    for cause in causes {
        if result
            .as_ref()
            .err()
            .is_some_and(|error| references_shared_error(error, &cause))
        {
            continue;
        }
        let extra = Error::SharedFailure(cause);
        result = Err(match result {
            Ok(_) => extra,
            Err(error)
                if matches!(error.primary(), Error::RunAborted)
                    && !matches!(extra.primary(), Error::RunAborted) =>
            {
                extra.with_cleanup(vec![error])
            }
            Err(error) => error.with_cleanup(vec![extra]),
        });
    }
    result.map_err(|error| promote_independent(&error).unwrap_or(error))
}

pub(crate) fn combine_pending<R>(result: Result<R>, check: Result<()>) -> Result<R> {
    match check {
        Ok(()) => result,
        Err(Error::SharedFailure(cause)) => fold_causes(result, [cause]),
        Err(Error::WithCleanup { primary, cleanup }) => {
            fold_causes(result, std::iter::once(primary).chain(cleanup))
        }
        Err(error) => fold_causes(result, [Arc::new(error)]),
    }
}

fn replaced_shared(error: &Arc<Error>, foreign: &[Arc<Error>]) -> Option<Arc<Error>> {
    if foreign.iter().any(|cause| Arc::ptr_eq(cause, error)) {
        Some(Arc::new(Error::RunAborted))
    } else {
        replace_foreign(error, foreign).map(Arc::new)
    }
}

/// Remove only references owned by the foreign driver. Reproduce wrappers
/// only along affected paths, retaining the peer's exact ledgers and opaque
/// error Arcs. Do not flatten away a partially completed signal operation.
fn replace_foreign(error: &Error, foreign: &[Arc<Error>]) -> Option<Error> {
    match error {
        Error::SharedFailure(error) => replaced_shared(error, foreign).map(Error::SharedFailure),
        Error::WorkerFailure { tid, error } => {
            replaced_shared(error, foreign).map(|error| Error::WorkerFailure { tid: *tid, error })
        }
        Error::Cleanup { phase, error } => {
            replaced_shared(error, foreign).map(|error| Error::Cleanup { phase, error })
        }
        Error::ExecWorkerTeardown(error) => {
            replace_foreign(error, foreign).map(|error| Error::ExecWorkerTeardown(Box::new(error)))
        }
        Error::WithCleanup { primary, cleanup } => {
            let next_primary = replaced_shared(primary, foreign);
            let next_cleanup: Vec<_> = cleanup
                .iter()
                .map(|error| replaced_shared(error, foreign))
                .collect();
            if next_primary.is_none() && next_cleanup.iter().all(Option::is_none) {
                return None;
            }
            Some(Error::WithCleanup {
                primary: next_primary.unwrap_or_else(|| primary.clone()),
                cleanup: cleanup
                    .iter()
                    .zip(next_cleanup)
                    .map(|(old, next)| next.unwrap_or_else(|| old.clone()))
                    .collect(),
            })
        }
        Error::SignalEffects {
            cause,
            dequeues,
            acknowledged_through,
            publications,
            raw_result,
            context,
        } => replaced_shared(cause, foreign).map(|cause| Error::SignalEffects {
            cause,
            dequeues: dequeues.clone(),
            acknowledged_through: *acknowledged_through,
            publications: publications.clone(),
            raw_result: *raw_result,
            context: context.clone(),
        }),
        _ => None,
    }
}

/// Promote a peer's own failure in place, without copying a diagnostic or
/// effect ledger into a second branch of the completed error tree.
fn promote_independent(error: &Error) -> Option<Error> {
    if !matches!(error.primary(), Error::RunAborted) {
        return None;
    }
    let promote = |error: &Arc<Error>| promote_independent(error).map(Arc::new);
    match error {
        Error::WithCleanup { primary, cleanup } => {
            if let Some(primary) = promote(primary) {
                return Some(Error::WithCleanup {
                    primary,
                    cleanup: cleanup.clone(),
                });
            }
            for (index, candidate) in cleanup.iter().enumerate() {
                let candidate = promote(candidate).unwrap_or_else(|| candidate.clone());
                if !matches!(candidate.primary(), Error::RunAborted) {
                    let mut retained = vec![primary.clone()];
                    retained.extend(
                        cleanup
                            .iter()
                            .enumerate()
                            .filter(|(other, _)| *other != index)
                            .map(|(_, error)| error.clone()),
                    );
                    return Some(Error::WithCleanup {
                        primary: candidate,
                        cleanup: retained,
                    });
                }
            }
            None
        }
        Error::SharedFailure(error) => promote(error).map(Error::SharedFailure),
        Error::WorkerFailure { tid, error } => {
            promote(error).map(|error| Error::WorkerFailure { tid: *tid, error })
        }
        Error::Cleanup { phase, error } => {
            promote(error).map(|error| Error::Cleanup { phase, error })
        }
        Error::ExecWorkerTeardown(error) => {
            promote_independent(error).map(|error| Error::ExecWorkerTeardown(Box::new(error)))
        }
        Error::SignalEffects {
            cause,
            dequeues,
            acknowledged_through,
            publications,
            raw_result,
            context,
        } => promote(cause).map(|cause| Error::SignalEffects {
            cause,
            dequeues: dequeues.clone(),
            acknowledged_through: *acknowledged_through,
            publications: publications.clone(),
            raw_result: *raw_result,
            context: context.clone(),
        }),
        _ => None,
    }
}

async fn route_foreign<R>(result: Result<R>, failure: &Arc<PendingFailure>) -> Result<R> {
    let operation = failure
        .operation
        .as_ref()
        .expect("foreign cause has origin");
    let lost =
        || !failure.owner_registered() || operation.lifecycle() == DriverLifecycle::Abandoned;
    if lost() {
        // This may be a new operation through an obsolete view after an
        // unrelated earlier publication. No owner ever accepted the new cause,
        // or its lifetime was abandoned. Keep it even if a notification is
        // already ready or this peer has an independent error.
        let retained = fold_causes(result, failure.causes())
            .err()
            .expect("a rejected owner retains a typed failure");
        return Err(
            protocol("entry failure has no completed owner transfer").with_cleanup(vec![retained])
        );
    }
    let foreign = failure.causes();
    let result = match result {
        Ok(_) => Error::RunAborted,
        Err(error) => replace_foreign(&error, &foreign).unwrap_or(error),
    };
    let result = promote_independent(&result).unwrap_or(result);
    let result = Arc::new(result);
    if !matches!(result.primary(), Error::RunAborted) {
        // This peer has a separate real cause. Its valid outer publication is
        // not ordered behind a different driver's incomplete callback.
        return Err(Error::SharedFailure(result));
    }
    loop {
        let changed = operation.subscribe();
        let terminal = failure.origin.as_ref().map(|origin| origin.subscribe());
        if lost() {
            return Err(protocol("entry failure owner abandoned its captured cause")
                .with_cleanup(vec![Error::SharedFailure(result), failure.error()]));
        }
        if let Some(terminal) = &terminal
            && let Some(receipt) = terminal.clone().now_or_never()
        {
            return match receipt {
                Ok(()) => Err(Error::SharedFailure(result)),
                Err(_) => Err(
                    protocol("failure notification disconnected before publication")
                        .with_cleanup(vec![Error::SharedFailure(result), failure.error()]),
                ),
            };
        }
        if operation.lifecycle() != DriverLifecycle::Active || changed.is_none() {
            // No obsolete FailureContext is called and no lost owner is
            // counted as successful cleanup. This is a new local observation
            // of an incomplete owner protocol, retaining the original cause.
            return Err(
                protocol("entry failure owner ended before terminal notification")
                    .with_cleanup(vec![Error::SharedFailure(result), failure.error()]),
            );
        }
        let Some(terminal) = terminal else {
            // Direct invocations do not share a RunFailure. They cannot lend
            // another driver a publisher, even if a retained view survives.
            operation.wait_callback_drop().await?;
            return Err(
                protocol("foreign entry failure has no terminal notification")
                    .with_cleanup(vec![Error::SharedFailure(result), failure.error()]),
            );
        };
        #[cfg(not(test))]
        let selected = select(terminal, changed.unwrap()).await;
        #[cfg(test)]
        let selected = {
            let mut waiting = Box::pin(select(terminal, changed.unwrap()));
            std::future::poll_fn(|cx| {
                let result = std::future::Future::poll(waiting.as_mut(), cx);
                if result.is_pending() {
                    test_observation::current(test_observation::Event::ForeignPending(
                        failure.clone(),
                    ));
                }
                result
            })
            .await
        };
        match selected {
            // Ownership may have changed during suspension even when the
            // terminal future wins the select. Recheck it before deriving.
            Either::Left((Ok(()), _)) => continue,
            Either::Left((Err(_), _)) => {
                return Err(
                    protocol("failure notification disconnected before publication")
                        .with_cleanup(vec![Error::SharedFailure(result), failure.error()]),
                );
            }
            Either::Right(_) => {}
        }
    }
}

impl KvmBackend {
    pub(crate) fn entry_driver_watch(&self) -> EntryDriverWatch {
        EntryDriverWatch {
            owner: self.entry_driver_owner(),
            gate: self.memory.entry_gate(),
        }
    }

    pub(crate) fn check_entry_owner(&self) -> Result<()> {
        self.entry_driver_watch().check()
    }

    /// Call only after this driver's ordinary callback borrow scope ended.
    /// This yields for foreign publication; it never waits for physical joins
    /// or runs another driver's effects, hook, or publisher.
    pub(crate) async fn route_entry_outcome<R>(&self, result: Result<R>) -> Result<R> {
        let owner = self.entry_driver_owner();
        let owned = owner.as_ref().map(DriverOwner::pending).unwrap_or_default();
        for failure in &owned {
            if let Some(operation) = &failure.operation {
                operation.wait_callback_drop().await?;
            }
        }
        let result = fold_causes(result, owned.iter().flat_map(|failure| failure.causes()));
        let Some(failure) = self.memory.entry_gate().pending_failure() else {
            return result;
        };
        if failure.operation.as_ref().is_none_or(|origin| {
            owner
                .as_ref()
                .is_some_and(|owner| origin.same_driver(&owner.origin()))
        }) {
            return fold_causes(result, failure.causes());
        }
        route_foreign(result, &failure).await
    }

    /// Close registration after the last owned operation and route. Retain
    /// live causes in RunFailure until all worker cleanup has completed.
    pub(crate) fn finish_entry_driver<R>(
        &mut self,
        scope: DriverScope,
        result: Result<R>,
    ) -> Result<R> {
        let retirement = scope.retire();
        let result = fold_causes(
            result,
            retirement
                .pending
                .iter()
                .flat_map(|failure| failure.causes()),
        );
        if let Some(context) = &self.tool_failure {
            for failure in retirement.pending {
                context.run.retain_entry_failure(failure);
            }
        }
        let result = combine_pending(result, retirement.result);
        debug_assert!(matches!(
            retirement.lifecycle,
            DriverLifecycle::Retired | DriverLifecycle::Abandoned
        ));
        retirement.notification.notify();
        self.entry_driver = None;
        self.set_operation_origin(None);
        result
    }
}

#[cfg(test)]
mod tests;
