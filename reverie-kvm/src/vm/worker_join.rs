/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One group-owned physical joiner for interruptible Exec callbacks. A returned
//! main closure is eligible for a job, but neither it nor this helper may be
//! physically joined by the callback: both can still run TLS destructors.

use std::collections::BTreeMap;
use std::sync::Condvar;
use std::sync::MutexGuard;
use std::thread::ThreadId;

use super::*;

type JoinedWorker = std::thread::Result<GuestWorkerResult>;

pub(super) struct WorkerFlight {
    target: ThreadId,
    joiner: ThreadId,
}

enum HelperJob {
    Queued(GuestWorkerHandle),
    Joining,
    Ready(i32, JoinedWorker),
    Collecting,
}

#[derive(Default)]
pub(super) struct JoinLedger {
    pub(super) active: BTreeMap<i32, WorkerFlight>,
    job: Option<HelperJob>,
    handle: Option<std::thread::JoinHandle<()>>,
    launching: bool,
    ready: bool,
    exited: bool,
    stopping: bool,
    reaping: bool,
    draining: Option<ThreadId>,
    failure: Option<Arc<Error>>,
    errors: Vec<Arc<Error>>,
    // These payloads are never dropped on the callback, helper, or join stack.
    // Final group destruction retains its existing payload-destructor limits.
    payloads: Vec<crate::failure::owned_future::PanicPayload>,
}

#[derive(Default)]
pub(super) struct WorkerJoins {
    state: Mutex<JoinLedger>,
    changed: Condvar,
    wake: Mutex<CancellationWake>,
}

// The owning leader backend must call join_workers on terminal teardown. Its
// Drop implementation does so even when an Exec future is dropped. An idle
// helper retains this ledger; Arc ownership alone is not a shutdown protocol.

impl WorkerJoins {
    pub(super) fn lock(&self) -> MutexGuard<'_, JoinLedger> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(super) fn subscribe(&self) -> GuestCancellationSubscription {
        self.wake
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .receiver
            .clone()
    }

    pub(super) fn notify(&self) {
        self.changed.notify_all();
        let previous =
            { std::mem::take(&mut *self.wake.lock().unwrap_or_else(|error| error.into_inner())) };
        let _ = previous.sender.send(());
    }

    pub(super) fn errors(&self) -> Vec<Arc<Error>> {
        self.lock().errors.clone()
    }

    /// Keep the first helper-control failure as the terminal ledger cause.
    /// Later control failures do not replace or append to it: spawn refusal,
    /// bootstrap destruction and launch rollback can describe one failure.
    /// Guest worker errors and opaque panic payloads are retained separately;
    /// this first-cause policy applies only to this helper-control ledger.
    /// A recursive drain also keeps the earlier cause: its inner call must
    /// return to avoid waiting on itself, while the same thread's outer drain
    /// still owns physical collection. The original failure remains terminal;
    /// this ledger does not promise a record of every later protocol violation.
    fn fail(state: &mut JoinLedger, error: Error) -> Arc<Error> {
        if let Some(error) = &state.failure {
            return error.clone();
        }
        let error = Arc::new(error);
        state.errors.push(error.clone());
        state.failure = Some(error.clone());
        error
    }

    fn wait<'a>(&self, state: MutexGuard<'a, JoinLedger>) -> MutexGuard<'a, JoinLedger> {
        self.changed
            .wait(state)
            .unwrap_or_else(|error| error.into_inner())
    }
}

/// Constructed before spawn, so dropping an uncalled closure after an inherited
/// child spawn-hook panic still reports that the body never became ready.
struct Bootstrap {
    joins: Arc<WorkerJoins>,
    entered: bool,
}

impl Drop for Bootstrap {
    fn drop(&mut self) {
        {
            let mut state = self.joins.lock();
            state.ready = false;
            state.exited = true;
            if !state.stopping {
                let phase = if self.entered {
                    "worker join helper"
                } else {
                    "worker join helper startup"
                };
                WorkerJoins::fail(&mut state, Error::GuestWorkerPanic.cleanup(phase));
            }
        }
        self.joins.notify();
    }
}

/// Parent-side spawn hooks can unwind before returning any handle. Originals
/// have not moved, and this transaction cannot leave a permanent Launching bit.
struct Launch<'a> {
    joins: &'a WorkerJoins,
    committed: bool,
}

impl Drop for Launch<'_> {
    fn drop(&mut self) {
        if !self.committed {
            {
                let mut state = self.joins.lock();
                state.launching = false;
                WorkerJoins::fail(
                    &mut state,
                    Error::GuestWorkerPanic.cleanup("worker join helper launch"),
                );
            }
            self.joins.notify();
        }
    }
}

fn run_helper(mut bootstrap: Bootstrap, before_ready: impl FnOnce()) {
    // Empty in production; the startup control uses this marker to prove an
    // inherited child spawn-hook panic prevented the body from being entered.
    before_ready();
    bootstrap.entered = true;
    let joins = bootstrap.joins.clone();
    {
        let mut state = joins.lock();
        state.ready = true;
    }
    joins.notify();
    loop {
        let worker = {
            let mut state = joins.lock();
            loop {
                if matches!(state.job, Some(HelperJob::Queued(_))) {
                    let Some(HelperJob::Queued(worker)) = state.job.replace(HelperJob::Joining)
                    else {
                        unreachable!();
                    };
                    break worker;
                }
                if state.stopping {
                    return;
                }
                state = joins.wait(state);
            }
        };
        let tid = worker.tid;
        // No registry lock is held here. The group owns our exact handle and
        // the active entry throughout the worker's real pthread termination.
        let result = worker.handle.join();
        {
            let mut state = joins.lock();
            debug_assert!(matches!(state.job, Some(HelperJob::Joining)));
            state.job = Some(HelperJob::Ready(tid, result));
        }
        joins.notify();
    }
}

struct Drain<'a>(&'a WorkerJoins);

impl Drop for Drain<'_> {
    fn drop(&mut self) {
        self.0.lock().draining = None;
        self.0.notify();
    }
}

impl GuestThreadGroup {
    #[cfg(test)]
    pub(super) fn has_owned_worker_joins(&self) -> bool {
        let state = self.worker_joins.lock();
        !state.active.is_empty()
            || !self
                .worker_handles
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
    }

    /// Observe transfer of this exact target to this exact joiner. Unlike the
    /// all-owned predicate, this can become true while its physical join waits.
    #[cfg(test)]
    pub(crate) fn worker_join_owns_target(
        &self,
        tid: i32,
        target: ThreadId,
        joiner: ThreadId,
    ) -> bool {
        let state = self.worker_joins.lock();
        let handles = self
            .worker_handles
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state
            .active
            .get(&tid)
            .is_some_and(|flight| flight.target == target && flight.joiner == joiner)
            && !handles.iter().any(|worker| worker.tid == tid)
    }

    fn start_worker_join_helper(&self) -> Result<()> {
        self.start_worker_join_helper_with(
            std::thread::Builder::new().name("reverie-kvm-join".into()),
            || {},
        )
    }

    pub(super) fn start_worker_join_helper_with(
        &self,
        builder: std::thread::Builder,
        before_ready: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        {
            let mut state = self.worker_joins.lock();
            if let Some(error) = &state.failure {
                return Err(Error::SharedFailure(error.clone()));
            }
            if state.handle.is_some()
                || state.launching
                || state.reaping
                || state.draining.is_some()
            {
                return Ok(());
            }
            state.launching = true;
            state.ready = false;
            state.exited = false;
            state.stopping = false;
        }
        let mut launch = Launch {
            joins: &self.worker_joins,
            committed: false,
        };
        let bootstrap = Bootstrap {
            joins: self.worker_joins.clone(),
            entered: false,
        };
        // No originals are transferred until both Ready and this exact handle
        // are in the ledger. Refusal returns the bootstrap owner to this scope.
        match crate::failure::spawn_owned(builder, bootstrap, move |bootstrap| {
            run_helper(bootstrap, before_ready)
        }) {
            Ok(handle) => {
                let mut state = self.worker_joins.lock();
                state.handle = Some(handle);
                state.launching = false;
                launch.committed = true;
            }
            Err((error, bootstrap)) => {
                let error = {
                    let mut state = self.worker_joins.lock();
                    state.launching = false;
                    launch.committed = true;
                    WorkerJoins::fail(
                        &mut state,
                        Error::from(error).cleanup("worker join helper spawn"),
                    )
                };
                drop(bootstrap);
                self.worker_joins.notify();
                return Err(Error::SharedFailure(error));
            }
        }
        self.worker_joins.notify();
        Ok(())
    }

    /// Collect exactly once outside every ledger lock, retaining real errors
    /// and opaque panic payloads through the same caches as direct teardown.
    fn collect_worker_join(&self, tid: i32, joined: JoinedWorker, cache: bool) -> Result<()> {
        enum JoinedError {
            Returned(Error),
            Panicked(Arc<Error>),
        }
        let error = match joined {
            Ok(result) => result.err().map(JoinedError::Returned),
            Err(payload) => Some(JoinedError::Panicked(
                self.retain_joined_worker_panic(tid, payload),
            )),
        };
        let gate = {
            self.worker_start_gates
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&tid)
        };
        drop(gate);
        let result = match (cache, error) {
            (_, None) => Ok(()),
            (true, Some(error)) => {
                let error = match error {
                    JoinedError::Returned(error) => Arc::new(error),
                    // Preserve the exact published Arc, including the direct
                    // WorkerFailure identity required by existing controls.
                    JoinedError::Panicked(error) => error,
                };
                self.worker_errors
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .entry(tid)
                    .or_default()
                    .push(error);
                Ok(())
            }
            (false, Some(JoinedError::Returned(error))) => Err(error),
            (false, Some(JoinedError::Panicked(error))) => Err(Error::SharedFailure(error)),
        };
        self.worker_joins.lock().active.remove(&tid);
        self.worker_joins.notify();
        result
    }

    fn collect_helper_result(&self) -> bool {
        let ready = {
            let mut state = self.worker_joins.lock();
            if !matches!(state.job, Some(HelperJob::Ready(..))) {
                return false;
            }
            let Some(HelperJob::Ready(tid, result)) = state.job.replace(HelperJob::Collecting)
            else {
                unreachable!();
            };
            (tid, result)
        };
        let _ = self.collect_worker_join(ready.0, ready.1, true);
        self.worker_joins.lock().job = None;
        self.worker_joins.notify();
        true
    }

    #[cfg(test)]
    pub(super) fn worker_join_helper_state(&self) -> (Option<ThreadId>, bool) {
        let state = self.worker_joins.lock();
        (
            state.handle.as_ref().map(|handle| handle.thread().id()),
            matches!(state.job, Some(HelperJob::Joining)),
        )
    }

    #[cfg(test)]
    pub(super) fn worker_join_helper_payload_addresses(&self) -> Vec<usize> {
        self.worker_joins
            .lock()
            .payloads
            .iter()
            .map(|payload| (&**payload as *const dyn std::any::Any as *const ()) as usize)
            .collect()
    }

    /// No physical join is performed by this method. The sole helper slot
    /// prevents nested discard from queuing a child behind its enclosing worker.
    pub(super) fn advance_worker_joins_for_exec(&self) -> Result<(bool, bool)> {
        self.collect_helper_result();
        let mut state = self.worker_joins.lock();
        if let Some(error) = &state.failure {
            return Err(Error::SharedFailure(error.clone()));
        }
        if state.draining.is_some() || state.reaping {
            return Ok((false, false));
        }
        let mut handles = self
            .worker_handles
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if handles.is_empty()
            && state.active.is_empty()
            && state.job.is_none()
            && !state.launching
            && (state.handle.is_none() || state.ready)
        {
            return Ok((true, false));
        }
        let eligible = handles
            .iter()
            .position(|worker| worker.handle.is_finished());
        let returning = handles.iter().any(|worker| {
            !worker.handle.is_finished()
                && worker
                    .returning
                    .as_ref()
                    .is_none_or(|returning| returning.load(Ordering::Acquire))
        });
        if state.job.is_none()
            && let Some(index) = eligible
        {
            if handles[index].handle.thread().id() == std::thread::current().id() {
                return Err(Error::UnexpectedVcpuExit(
                    "Exec cannot join its own worker".into(),
                ));
            }
            if state.handle.is_none() && !state.launching {
                drop(handles);
                drop(state);
                self.start_worker_join_helper()?;
                return Ok((false, true));
            }
            if state.ready
                && let Some(helper) = state.handle.as_ref()
            {
                let joiner = helper.thread().id();
                let worker = handles.remove(index);
                state.active.insert(
                    worker.tid,
                    WorkerFlight {
                        target: worker.handle.thread().id(),
                        joiner,
                    },
                );
                state.job = Some(HelperJob::Queued(worker));
                drop(handles);
                drop(state);
                self.worker_joins.notify();
                return Ok((false, returning));
            }
        }
        Ok((false, returning))
    }

    /// Claim only this registered cancelled child. Another direct/helper join
    /// retains it if it has already moved; the caller verifies the exact gate.
    pub(super) fn discard_unstarted_worker(&self, tid: i32) -> Result<bool> {
        let worker = {
            let mut state = self.worker_joins.lock();
            let mut handles = self
                .worker_handles
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(index) = handles.iter().position(|worker| {
                worker.tid == tid
                    && worker
                        .start
                        .as_ref()
                        .is_some_and(ChildStartGate::is_cancelled)
            }) else {
                return Ok(false);
            };
            let joiner = std::thread::current().id();
            if handles[index].handle.thread().id() == joiner {
                return Err(Error::UnexpectedVcpuExit(
                    "worker cannot discard itself".into(),
                ));
            }
            let worker = handles.swap_remove(index);
            state.active.insert(
                tid,
                WorkerFlight {
                    target: worker.handle.thread().id(),
                    joiner,
                },
            );
            worker
        };
        let result = worker.handle.join();
        self.collect_worker_join(tid, result, false)?;
        Ok(true)
    }

    /// Whether `join_workers` would still wait for a worker or the join
    /// helper. A run that returns with this set did not join its workers, so
    /// it is retired like a dropped run instead of by its backend's drop.
    pub(crate) fn has_unjoined_workers(&self) -> bool {
        let state = self.worker_joins.lock();
        let handles = self
            .worker_handles
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        !handles.is_empty()
            || !state.active.is_empty()
            || state.job.is_some()
            || state.launching
            || state.handle.is_some()
    }

    /// Terminal boundary only: the callback has ended and the caller has
    /// published any failure before waiting for physical worker/helper exit.
    pub(crate) fn join_workers(&self) {
        let current = std::thread::current().id();
        {
            let mut state = self.worker_joins.lock();
            while let Some(owner) = state.draining {
                if owner == current {
                    WorkerJoins::fail(
                        &mut state,
                        Error::UnexpectedVcpuExit("recursive worker drain".into()),
                    );
                    return;
                }
                state = self.worker_joins.wait(state);
            }
            state.draining = Some(current);
        }
        let _drain = Drain(&self.worker_joins);
        loop {
            self.collect_helper_result();
            let mut state = self.worker_joins.lock();
            let mut handles = self
                .worker_handles
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // A pre-body failure cannot own a job; a later helper unwind can
            // still leave a queued job untouched. Recover that original before
            // waiting for the failed helper, without dropping its handle.
            if state.exited && matches!(state.job, Some(HelperJob::Queued(_))) {
                let Some(HelperJob::Queued(worker)) = state.job.take() else {
                    unreachable!();
                };
                state.active.remove(&worker.tid);
                handles.push(worker);
            }
            if let Some(worker) = handles.first() {
                if worker.handle.thread().id() == current {
                    WorkerJoins::fail(
                        &mut state,
                        Error::UnexpectedVcpuExit("worker cannot drain itself".into()),
                    );
                    return;
                }
                let worker = handles.remove(0);
                state.active.insert(
                    worker.tid,
                    WorkerFlight {
                        target: worker.handle.thread().id(),
                        joiner: current,
                    },
                );
                drop(handles);
                drop(state);
                if self.cancelled.load(Ordering::Acquire) {
                    self.cancel_pending_worker_gates(std::slice::from_ref(&worker));
                }
                let tid = worker.tid;
                #[cfg(test)]
                let target = worker.handle.thread().id();
                #[cfg(test)]
                crate::entry::driver::test_observation::join(target, false, false);
                let result = worker.handle.join();
                #[cfg(test)]
                crate::entry::driver::test_observation::join(target, false, true);
                let _ = self.collect_worker_join(tid, result, true);
                continue;
            }
            drop(handles);
            if matches!(state.job, Some(HelperJob::Ready(..))) {
                drop(state);
                continue;
            }
            if !state.active.is_empty() || state.job.is_some() || state.launching {
                if state
                    .active
                    .values()
                    .any(|flight| flight.target == current || flight.joiner == current)
                {
                    WorkerJoins::fail(
                        &mut state,
                        Error::UnexpectedVcpuExit("worker drain depends on itself".into()),
                    );
                    return;
                }
                // The state check and condvar handoff share this lock. Every
                // result/registration transition is committed before its wake.
                drop(self.worker_joins.wait(state));
                continue;
            }
            let Some(handle) = state.handle.take() else {
                return;
            };
            state.stopping = true;
            state.reaping = true;
            drop(state);
            self.worker_joins.notify();
            // Never reached by advance_worker_joins_for_exec, even when the
            // helper main closure has returned: helper TLS is user-extensible.
            let result = handle.join();
            {
                let mut state = self.worker_joins.lock();
                if let Err(payload) = result {
                    WorkerJoins::fail(
                        &mut state,
                        Error::GuestWorkerPanic.cleanup("worker join helper"),
                    );
                    state.payloads.push(payload);
                }
                state.reaping = false;
                state.ready = false;
                state.stopping = false;
                state.exited = false;
            }
            self.worker_joins.notify();
        }
    }
}
