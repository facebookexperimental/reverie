/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Terminal descriptor retirement through an owned native-exit service.
//!
//! One prestarted service belongs to one guest task. Its native worker is ready
//! before guest admission. Submission transfers real owners, not fd numbers;
//! dropping a waiter neither cancels cleanup nor destroys pending sockets.
//! Normal task death waits for actual native cleanup; an infrastructure failure
//! never becomes an authentic successful terminal receipt.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use futures::task::AtomicWaker;

use crate::executor::AbandonedRuns;
use crate::executor::ChildThread;
use crate::executor::DroppedRunReaper;
use crate::native_exit_broker::BrokerClient;
use crate::native_exit_broker::CoreError;
use crate::native_exit_broker::EmptyCancellationProgress;
use crate::native_exit_broker::JobProgress;
use crate::native_exit_broker::NativeExitJob;
use crate::native_exit_broker::ReservationProgress;
use crate::native_exit_broker::SocketReference;
use crate::native_exit_broker::is_socket_file;

#[derive(Default)]
struct State {
    ready: bool,
    submitted: bool,
    batch: Option<Vec<SocketReference>>,
    result: Option<Result<(), CoreError>>,
    failure: Option<CoreError>,
    owner_gone: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    waker: AtomicWaker,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn fail(&self, error: CoreError) {
        let mut state = self.lock();
        if state.failure.is_none() {
            state.failure = Some(error);
        }
        drop(state);
        // The driver separately catches arbitrary user-waker panics while it
        // still retains every File owner outside the unwind boundary.
    }
}

#[derive(Clone)]
pub(crate) struct CleanupFactory {
    client: BrokerClient,
    runs: Arc<Mutex<AbandonedRuns>>,
    reaper: DroppedRunReaper,
}

impl CleanupFactory {
    pub(crate) fn new(
        client: BrokerClient,
        runs: Arc<Mutex<AbandonedRuns>>,
        reaper: DroppedRunReaper,
    ) -> Self {
        Self {
            client,
            runs,
            reaper,
        }
    }

    pub(crate) fn spawn(&self) -> crate::Result<TaskCleanup> {
        TaskCleanup::spawn(self.client.clone(), self.runs.clone(), self.reaper.clone())
    }
}

/// A pending service retains every job, socket, and native wait owner outside
/// any unwind catch. Its run reaper receives the actual host join handle if the
/// guest's waiter disappears before completion.
pub(crate) struct TaskCleanup {
    shared: Arc<Shared>,
    thread: Option<ChildThread>,
    runs: Arc<Mutex<AbandonedRuns>>,
    reaper: DroppedRunReaper,
}

impl TaskCleanup {
    fn spawn(
        client: BrokerClient,
        runs: Arc<Mutex<AbandonedRuns>>,
        reaper: DroppedRunReaper,
    ) -> crate::Result<Self> {
        let shared = Arc::new(Shared::default());
        let drive = Driver {
            shared: shared.clone(),
            client,
            job: None,
            pending: VecDeque::new(),
            sockets: Vec::new(),
            batch_received: false,
            first_reservation: true,
            reservation_ready: false,
            cancelling_empty: false,
            group_loaded: false,
            panics: Vec::new(),
        };
        let thread = ChildThread::spawn_owned(
            std::thread::Builder::new().name("kvm-task-file-exit".into()),
            drive,
            Driver::run,
        )
        .map_err(|(error, _empty_driver)| {
            crate::Error::from(error).cleanup("terminal-file service spawn")
        })?;
        Ok(Self {
            shared,
            thread: Some(thread),
            runs,
            reaper,
        })
    }

    /// Before any guest callback/effect. The worker reports readiness from its
    /// own private protocol; a spawned host thread alone is not readiness.
    pub(crate) async fn ready(&mut self) -> crate::Result<()> {
        std::future::poll_fn(|cx| {
            self.shared.waker.register(cx.waker());
            let state = self.shared.lock();
            if let Some(error) = &state.failure {
                Poll::Ready(Err(as_error(error)))
            } else if state.ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Submission cannot fail: the prestarted service retains Shared until it
    /// has consumed the single batch or receives this owner's empty cancellation.
    /// Call exactly once after all of this task's terminal owners are extracted.
    pub(crate) fn submit(&mut self, files: Vec<SocketReference>) {
        let mut state = self.shared.lock();
        assert!(!state.submitted, "terminal file owners submitted twice");
        state.submitted = true;
        state.batch = Some(files);
        drop(state);
        self.shared.changed.notify_all();
    }

    pub(crate) fn is_submitted(&self) -> bool {
        self.shared.lock().submitted
    }

    pub(crate) async fn finish(&mut self) -> crate::Result<()> {
        std::future::poll_fn(|cx| self.poll_finish(cx)).await
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        self.shared.waker.register(cx.waker());
        {
            let state = self.shared.lock();
            if let Some(error) = &state.failure {
                // Failure is visible, but the pending driver remains retained.
                // Drop below gives the actual join owner to the run's reaper.
                return Poll::Ready(Err(as_error(error)));
            }
            if state.result.is_none() {
                return Poll::Pending;
            }
        }
        let Some(thread) = self.thread.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match thread.poll_reap(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => {
                self.thread = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(payload)) => {
                // Driver catches internally with owners outside the catch.
                // Retain the original payload in this run's reaper, rather
                // than discard it while replacing the cause with a message.
                self.reaper.retain_panic(payload);
                self.thread = None;
                Poll::Ready(Err(crate::Error::UnexpectedVcpuExit(
                    "terminal file service panicked outside retained driver".into(),
                )))
            }
        }
    }
}

impl Drop for TaskCleanup {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.owner_gone = true;
            if !state.submitted {
                state.submitted = true;
                state.batch = Some(Vec::new());
            }
        }
        self.shared.changed.notify_all();
        if let Some(thread) = self.thread.take() {
            // Integration must fence this run's future admission and retain the
            // handle in the prestarted reaper, not detach or block this Drop.
            AbandonedRuns::retain_terminal_service(&self.runs, &self.reaper, thread);
        }
    }
}

fn as_error(error: &CoreError) -> crate::Error {
    crate::Error::TerminalFileRetirement {
        operation: error.operation,
        errno: error.errno,
    }
}

struct Driver {
    shared: Arc<Shared>,
    client: BrokerClient,
    job: Option<NativeExitJob>,
    pending: VecDeque<SocketReference>,
    sockets: Vec<SocketReference>,
    batch_received: bool,
    first_reservation: bool,
    reservation_ready: bool,
    cancelling_empty: bool,
    group_loaded: bool,
    panics: Vec<Box<dyn std::any::Any + Send>>,
}

impl Driver {
    fn run(mut this: Self) -> crate::Result<()> {
        // No ownership-bearing local is consumed by the catch. A panic or an
        // irrecoverable infrastructure error leaves all remaining resources in
        // this driver, and no successful terminal receipt is ever published.
        loop {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| this.advance())) {
                Ok(Ok(true)) => {
                    this.shared.lock().result = Some(Ok(()));
                    this.shared.waker.wake();
                    return Ok(());
                }
                Ok(Ok(false)) => {}
                Ok(Err(error)) => {
                    this.publish_failure(error.clone());
                    if !this.panics.is_empty() {
                        this.retain_failed();
                    }
                    return this.settle_failed_setup(error);
                }
                Err(payload) => {
                    this.panics.push(payload);
                    this.publish_failure(CoreError {
                        operation: "retirement driver panic",
                        errno: libc::EIO,
                    });
                    this.retain_failed();
                }
            }
        }
    }

    /// A broken private protocol or destroyed broker cannot justify a fallback
    /// ordinary close. Retain the concrete driver and diagnostic until host
    /// process termination. Recoverable resource failures are handled inside the
    /// core's abort/actual-wait/retransmit state and do not enter this state.
    fn retain_failed(&self) -> ! {
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    }

    fn publish_failure(&mut self, error: CoreError) {
        self.shared.fail(error);
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.shared.waker.wake();
        })) {
            self.panics.push(payload);
        }
    }

    fn advance(&mut self) -> Result<bool, CoreError> {
        if self.job.is_none() {
            // Cancellation before any request has no native child to reap.
            // Consume the real submitted batch before trying another resource
            // allocation; an empty/ordinary-only batch needs no native worker.
            if !self.batch_received && self.shared.lock().owner_gone {
                self.receive_batch();
            }
            if self.batch_received && !self.group_loaded {
                self.load_group()?;
                if self.sockets.is_empty() && self.pending.is_empty() {
                    return Ok(true);
                }
            }
        }
        if self.job.is_none() {
            match self.client.reserve_worker() {
                Ok(job) => self.job = Some(job),
                Err(error) if resource_error(error.errno) => {
                    std::thread::sleep(Duration::from_millis(100));
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        if !self.reservation_ready {
            // An owner cancelled before admission may submit no resources.
            // Settle the actual empty reservation instead of waiting forever
            // for an admission that no caller is awaiting any more.
            if self.cancelling_empty || (self.shared.lock().owner_gone && !self.batch_received) {
                if !self.batch_received {
                    self.receive_batch();
                }
                if self.pending.is_empty() {
                    self.cancelling_empty = true;
                    return match self.job.as_mut().unwrap().poll_cancel_empty()? {
                        EmptyCancellationProgress::Pending => {
                            self.wait_protocol();
                            Ok(false)
                        }
                        EmptyCancellationProgress::Complete(_) => {
                            self.job = None;
                            Ok(true)
                        }
                    };
                }
            }
            match self.job.as_mut().unwrap().advance_reservation()? {
                ReservationProgress::Pending => {
                    self.wait_protocol();
                    return Ok(false);
                }
                ReservationProgress::Ready => {
                    self.reservation_ready = true;
                    if self.first_reservation {
                        self.first_reservation = false;
                        self.shared.lock().ready = true;
                        self.shared.waker.wake();
                    }
                }
            }
        }
        if !self.batch_received {
            self.receive_batch();
        }
        // Preserve the preexisting retirement sequence. Combining sockets on
        // opposite sides of a device/FUSE close could add a dependency if that
        // close waits for EOF from the earlier socket. Each contiguous socket
        // group gets its own native worker; non-socket destruction stays ordinary.
        if !self.group_loaded {
            self.load_group()?;
        }
        let job = self.job.as_mut().unwrap();
        match job.advance(&mut self.sockets)? {
            JobProgress::Pending => {
                self.wait_protocol();
                Ok(false)
            }
            JobProgress::Complete(_) => {
                self.job = None;
                self.reservation_ready = false;
                self.group_loaded = false;
                assert!(
                    self.sockets.is_empty(),
                    "native cleanup left original socket owners"
                );
                Ok(self.pending.is_empty())
            }
        }
    }

    fn load_group(&mut self) -> Result<(), CoreError> {
        while let Some(file) = self.pending.front() {
            use std::os::fd::AsRawFd;
            if is_socket_file(file.as_raw_fd())? {
                break;
            }
            drop(self.pending.pop_front());
        }
        while let Some(file) = self.pending.front() {
            use std::os::fd::AsRawFd;
            if !is_socket_file(file.as_raw_fd())? {
                break;
            }
            self.sockets.push(self.pending.pop_front().unwrap());
        }
        self.group_loaded = true;
        Ok(())
    }

    fn receive_batch(&mut self) {
        let mut state = self.shared.lock();
        while state.batch.is_none() {
            state = self
                .shared
                .changed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
        self.pending = state.batch.take().unwrap().into();
        self.batch_received = true;
    }

    fn settle_failed_setup(&mut self, error: CoreError) -> crate::Result<()> {
        // Failure wakes the admission waiter. Keep this service alive until
        // the executor transfers its real owners; an early return here would
        // later destroy Shared.batch on the cancelling thread.
        if !self.batch_received {
            self.receive_batch();
        }
        if !self.group_loaded && self.sockets.is_empty() {
            use std::os::fd::AsRawFd;
            while let Some(file) = self.pending.front() {
                match is_socket_file(file.as_raw_fd()) {
                    Ok(false) => {
                        drop(self.pending.pop_front());
                    }
                    Ok(true) | Err(_) => self.retain_failed(),
                }
            }
            // No guest socket has entered this reservation, and no remaining
            // original owner can become an ordinary socket close. Require an
            // actual empty-worker wait (or proof START was never sent).
            if let Some(job) = self.job.as_mut() {
                loop {
                    match job.poll_cancel_empty() {
                        Ok(EmptyCancellationProgress::Complete(_)) => break,
                        Ok(EmptyCancellationProgress::Pending) => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(cause) if resource_error(cause.errno) => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(_) => self.retain_failed(),
                    }
                }
            }
            self.job = None;
            self.shared.lock().result = Some(Err(error.clone()));
            self.shared.waker.wake();
            return Err(as_error(&error));
        }
        self.retain_failed()
    }

    fn wait_protocol(&self) {
        let job = self.job.as_ref().unwrap();
        let mut interests = job.poll_interests();
        let delay = job.retry_after().unwrap_or(Duration::from_millis(100));
        let millis = delay.as_millis().clamp(1, 1000) as libc::c_int;
        // Internal descriptors only. Poll supplies no guest scheduling authority
        // or timeout success: only the core's actual native wait completes.
        let rc = unsafe {
            libc::poll(
                interests.as_mut_ptr(),
                interests.len() as libc::nfds_t,
                millis,
            )
        };
        if rc < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn resource_error(errno: i32) -> bool {
    matches!(
        errno,
        libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ETOOMANYREFS | libc::EAGAIN
    )
}

#[cfg(test)]
mod tests {
    include!("../tests/support/terminal_cleanup_tests.rs");
}
