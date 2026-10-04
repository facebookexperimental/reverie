/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Terminal disposal of zero-byte reads on owned host descriptors.
//!
//! The original Rust worker stays synchronous. Only a C entry/cleanup stack is
//! canceled; a Canceled outcome has unknown kernel progress and is never a
//! guest result. The descriptor is moved, not duplicated, into the operation
//! until the C thread is joined. Failed joins retain ownership permanently.

use std::collections::BTreeMap;
use std::fs::File;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;

use futures::future::BoxFuture;
use reverie::ExitStatus;
use reverie::SignalTaskIdentity;

use crate::Error;
use crate::Result;
use crate::SyscallRequest;
use crate::entry::driver::EntryDriverWatch;
use crate::failure::owned_future::CaughtFuture;
use crate::failure::owned_future::PanicPayload;
use crate::failure::tool_panics::ToolPanics;

#[repr(C)]
struct CRead {
    _private: [u8; 0],
}

// Keep this layout and constants paired with terminal_read.h. The C snapshot
// copies every field under its own synchronization, never exposing a pthread_t.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct Snapshot {
    result: i64,
    senders: u64,
    outcome: u32,
    state: u32,
    terminal: u32,
    handle_published: u32,
    read_errno: i32,
    error_phase: u32,
    error_number: i32,
}

const PENDING: u32 = 0;
const RETURNED: u32 = 1;
const JOINED: u32 = 5;
const NO_THREAD: u32 = 7;

unsafe extern "C" {
    fn rvk_read_new(fd: i32, address: usize, count: usize, error: *mut i32) -> *mut CRead;
    fn rvk_read_start(op: *mut CRead) -> i32;
    fn rvk_read_request_cancel(op: *mut CRead) -> i32;
    fn rvk_read_snapshot(op: *mut CRead, snapshot: *mut Snapshot) -> i32;
    fn rvk_read_epoch(op: *mut CRead) -> u64;
    fn rvk_read_wake(op: *mut CRead) -> i32;
    fn rvk_read_wait(op: *mut CRead, epoch: u64) -> i32;
    fn rvk_read_finish(op: *mut CRead) -> i32;
    fn rvk_read_destroy(op: *mut CRead) -> i32;
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A Rust unwind must still be able to cancel and join its C reader.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Debug)]
enum Terminal {
    Exit(ExitStatus),
    WorkerCancelled,
    Failure(Arc<Error>),
}

impl Terminal {
    fn error(&self) -> Error {
        match self {
            Self::Exit(_) | Self::WorkerCancelled => Error::TerminalReadCancelled,
            Self::Failure(error) => Error::SharedFailure(error.clone()),
        }
    }

    fn exit(&self) -> Option<ExitStatus> {
        match self {
            Self::Exit(status) => Some(*status),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Retained correlation identity, including failed joins.
struct Identity {
    generation: u64,
    image_generation: u64,
    task: SignalTaskIdentity,
    request: SyscallRequest,
    host_fd: i32,
    host_address: usize,
    host_count: usize,
    worker: bool,
}

struct Operation {
    native: NonNull<CRead>,
    identity: Identity,
    endpoint: Mutex<Option<File>>,
    terminal: Mutex<Option<Arc<Terminal>>>,
    cancel_requested: AtomicBool,
}

// C synchronizes every shared operation field. start/finish have one Rust
// lexical owner; other Arc holders may only cancel, snapshot or wake. No Rust
// reference or callback is passed to the C reader.
unsafe impl Send for Operation {}
unsafe impl Sync for Operation {}

impl Operation {
    fn snapshot(&self) -> Snapshot {
        let mut snapshot = Snapshot::default();
        // SAFETY: this Arc pins the initialized C allocation and snapshot is
        // writable. The C function serializes its own state.
        let error = unsafe { rvk_read_snapshot(self.native.as_ptr(), &mut snapshot) };
        if error == 0 {
            snapshot
        } else {
            // No state was authenticated. In particular, this cannot prove
            // that creation failed or that the child was physically joined.
            Snapshot {
                state: u32::MAX,
                error_phase: 6,
                error_number: error,
                ..Snapshot::default()
            }
        }
    }

    fn mark_terminal(&self, terminal: Arc<Terminal>) {
        lock(&self.terminal).get_or_insert(terminal);
    }

    fn cancel(&self) {
        if self.cancel_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        // SAFETY: the Arc pins C storage. C admits a counted sender, calls
        // pthread_cancel outside its lock, and releases the lease only after
        // the actual call returns. A failure remains in the C snapshot.
        unsafe { rvk_read_request_cancel(self.native.as_ptr()) };
    }

    fn terminal(&self) -> Option<Arc<Terminal>> {
        lock(&self.terminal).clone()
    }

    fn control_error(&self, snapshot: Snapshot) -> Option<Error> {
        if snapshot.error_number == 0 {
            return None;
        }
        let operation = match snapshot.error_phase {
            1 => "pthread_create",
            2 => "pthread_cancel",
            3 => "pthread_join (ownership retained)",
            4 => "pthread_setcancelstate",
            5 => "pthread_setcanceltype",
            _ => "C synchronization",
        };
        Some(Error::TerminalReadControl {
            operation,
            source: std::io::Error::from_raw_os_error(snapshot.error_number),
            terminal_exit: self.terminal().as_deref().and_then(Terminal::exit),
        })
    }
}

/// A failed physical join cannot be retried, detached or treated as success.
/// This process-lifetime ledger owns both the C allocation and actual File if
/// its group is dropped. It intentionally has no cleanup that could free live
/// storage. Such a run is a backend failure, never successful retirement.
#[allow(dead_code)]
struct RetainedRead {
    allocation: usize,
    endpoint: Option<File>,
    identity: Identity,
    snapshot: Snapshot,
}

static RETAINED: OnceLock<Mutex<Vec<RetainedRead>>> = OnceLock::new();

impl Drop for Operation {
    fn drop(&mut self) {
        let snapshot = self.snapshot();
        if matches!(snapshot.state, JOINED | NO_THREAD)
            // SAFETY: the last Arc is gone, so no waker or sender can call C.
            && unsafe { rvk_read_destroy(self.native.as_ptr()) } == 0
        {
            return;
        }
        lock(RETAINED.get_or_init(Mutex::default)).push(RetainedRead {
            allocation: self.native.as_ptr() as usize,
            endpoint: lock(&self.endpoint).take(),
            identity: self.identity.clone(),
            snapshot,
        });
    }
}

struct ReadWake(Arc<Operation>);

impl Wake for ReadWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // SAFETY: the waker retains the allocation even after physical join.
        // This only changes the C wait epoch; a wake is not terminal evidence.
        unsafe { rvk_read_wake(self.0.native.as_ptr()) };
    }
}

#[derive(Default)]
struct RegistryState {
    next: u64,
    image_generation: u64,
    root_terminal: Option<Arc<Terminal>>,
    worker_terminal: Option<Arc<Terminal>>,
    operations: BTreeMap<u64, Arc<Operation>>,
    errors: BTreeMap<u64, Arc<Error>>,
    observer_errors: Vec<Arc<Error>>,
}

/// One registry per actual guest thread group; forks receive a separate one.
#[derive(Default)]
pub(crate) struct ReadRegistry {
    state: Mutex<RegistryState>,
}

// A destructor cannot return a diagnostic. Keep a failed group's exact typed
// errors and first terminal causes even if no public finalizer collected them.
// Its still-registered operations also retain their actual endpoint/storage;
// no destructor, cancel send, or join runs while this ledger is locked.
static RETAINED_REGISTRIES: OnceLock<Mutex<Vec<RegistryState>>> = OnceLock::new();

impl Drop for ReadRegistry {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.operations.is_empty()
            && state.errors.is_empty()
            && state.observer_errors.is_empty()
        {
            return;
        }
        let retained = std::mem::take(state);
        lock(RETAINED_REGISTRIES.get_or_init(Mutex::default)).push(retained);
    }
}

impl ReadRegistry {
    fn terminal_exit(&self, worker: bool) -> Option<ExitStatus> {
        let state = lock(&self.state);
        let terminal = if worker {
            &state.worker_terminal
        } else {
            &state.root_terminal
        };
        terminal.as_deref().and_then(Terminal::exit)
    }

    pub(crate) fn request_exit_group(&self, status: ExitStatus) {
        self.cancel(false, Arc::new(Terminal::Exit(status)));
    }

    pub(crate) fn cancel_workers(&self) {
        self.cancel(true, Arc::new(Terminal::WorkerCancelled));
    }

    fn cancel(&self, workers_only: bool, cause: Arc<Terminal>) {
        let operations = {
            let mut state = lock(&self.state);
            if !workers_only {
                state.root_terminal.get_or_insert_with(|| cause.clone());
            }
            state.worker_terminal.get_or_insert_with(|| cause.clone());
            state
                .operations
                .values()
                .filter(|operation| !workers_only || operation.identity.worker)
                .map(|operation| {
                    operation.mark_terminal(cause.clone());
                    operation.clone()
                })
                .collect::<Vec<_>>()
        };
        // No registry/group/operation lock surrounds the actual cancel sends.
        // Physical C joins are exclusively the original worker's obligation.
        for operation in operations {
            operation.cancel();
        }
    }

    pub(crate) fn rearm_after_exec(&self) {
        let mut state = lock(&self.state);
        assert!(
            state.operations.is_empty(),
            "exec retained an unjoined stdin reader"
        );
        state.image_generation = state
            .image_generation
            .checked_add(1)
            .expect("stdin read image generation exhausted");
        state.root_terminal = None;
        state.worker_terminal = None;
        // The monotonically increasing operation generation is never reset.
    }

    pub(crate) fn teardown_result(&self) -> Result<()> {
        let state = lock(&self.state);
        Error::combine(
            state
                .errors
                .values()
                .cloned()
                .chain(state.observer_errors.iter().cloned())
                .map(Error::SharedFailure)
                .collect(),
        )
    }

    fn record_error(&self, operation: &Operation, error: Error) -> Arc<Error> {
        let error = Arc::new(error);
        let recorded = {
            let mut state = lock(&self.state);
            state
                .errors
                .entry(operation.identity.generation)
                .or_insert_with(|| error.clone())
                .clone()
        };
        // A discarded later error may own an opaque host-error destructor.
        // Drop that value only after releasing the registry lock.
        recorded
    }
}

pub(crate) struct NativeReturn {
    pub(crate) count: isize,
    pub(crate) errno: i32,
}

/// The only futures polled while the Rust worker waits describe already
/// terminal state. They do not poll a guest callback, readiness or scheduler.
pub(crate) struct ReadContext {
    registry: Arc<ReadRegistry>,
    worker: bool,
    watch: EntryDriverWatch,
    failure: Option<BoxFuture<'static, ()>>,
    panics: Arc<ToolPanics>,
    tool_worker: bool,
}

/// Polling never owns the observer allocation: an observer poll panic cannot
/// unwind through its destructor. Its separate disposal follows local helper
/// retirement, while the native result and every original payload stay owned.
struct TerminalObserver {
    future: Option<BoxFuture<'static, ()>>,
    stopped: bool,
    payloads: Vec<PanicPayload>,
    panics: Arc<ToolPanics>,
    tool_worker: bool,
    registry: Arc<ReadRegistry>,
}

impl TerminalObserver {
    fn poll(&mut self, context: &mut Context<'_>) -> Option<Error> {
        if self.stopped {
            return None;
        }
        let future = self.future.as_mut()?;
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Pending) => None,
            Ok(Poll::Ready(())) => {
                self.stopped = true;
                Some(Error::RunAborted)
            }
            Err(payload) => {
                self.stopped = true;
                self.payloads.push(payload);
                Some(Error::GuestWorkerPanic)
            }
        }
    }

    fn dispose(&mut self) {
        if let Some(future) = self.future.take()
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(future)))
        {
            self.payloads.push(payload);
        }
    }

    fn retain_panics<R>(&mut self, output: Option<Result<R>>) -> Result<R> {
        let caught = CaughtFuture {
            output,
            panics: std::mem::take(&mut self.payloads),
        };
        let result = if self.tool_worker {
            self.panics
                .finish_worker_execution(caught, "stdin terminal observer")
        } else {
            self.panics.finish(caught, "stdin terminal observer")
        };
        let error = Arc::new(result.err().expect("observer panic became success"));
        // This retains a cause without publishing through a Tool hook while
        // its ordinary callback may still be on the original Rust stack.
        lock(&self.registry.state)
            .observer_errors
            .push(error.clone());
        Err(Error::SharedFailure(error))
    }

    fn finish(mut self, result: Result<NativeReturn>) -> Result<NativeReturn> {
        self.dispose();
        if self.payloads.is_empty() {
            return result;
        }
        // Graceful cancellation is not the primary cause of a real observer
        // panic. Typed native/entry errors, including their cleanup, are kept.
        let output = match result {
            Err(Error::TerminalReadCancelled) => None,
            result => Some(result),
        };
        self.retain_panics(output)
    }
}

impl Drop for TerminalObserver {
    fn drop(&mut self) {
        self.dispose();
        if !self.payloads.is_empty() {
            // An unexpected outer unwind still joins through ReadOwner first.
            // Do not resume a second panic or destroy any payload in that
            // unwind: the concrete Tool owner retains all of them for cleanup.
            let _ = self.retain_panics::<()>(None);
        }
    }
}

impl ReadContext {
    pub(crate) fn new(
        registry: Arc<ReadRegistry>,
        worker: bool,
        watch: EntryDriverWatch,
        failure: Option<BoxFuture<'static, ()>>,
        panics: Arc<ToolPanics>,
        tool_worker: bool,
    ) -> Self {
        Self {
            registry,
            worker,
            watch,
            failure,
            panics,
            tool_worker,
        }
    }

    pub(crate) fn read(
        &mut self,
        endpoint: &mut Option<File>,
        task: SignalTaskIdentity,
        request: SyscallRequest,
        address: usize,
        count: usize,
    ) -> Result<NativeReturn> {
        let mut observer = self.take_observer();
        let result = self.read_inner(endpoint, task, request, (address, count), &mut observer);
        observer.finish(result)
    }

    fn take_observer(&mut self) -> TerminalObserver {
        TerminalObserver {
            future: self.failure.take(),
            stopped: false,
            payloads: Vec::new(),
            panics: self.panics.clone(),
            tool_worker: self.tool_worker,
            registry: self.registry.clone(),
        }
    }

    fn read_inner(
        &mut self,
        endpoint: &mut Option<File>,
        task: SignalTaskIdentity,
        request: SyscallRequest,
        host_buffer: (usize, usize),
        observer: &mut TerminalObserver,
    ) -> Result<NativeReturn> {
        let (address, count) = host_buffer;
        assert_eq!(count, 0, "terminal helper is only for zero-count reads");
        let fd = endpoint
            .as_ref()
            .expect("prechecked read endpoint disappeared")
            .as_raw_fd();
        let mut error = 0;
        // SAFETY: all arguments are scalar and count is zero. The numeric
        // address owns no allocation or Rust reference; the host read validates
        // it without copying through it.
        let native = NonNull::new(unsafe { rvk_read_new(fd, address, count, &mut error) })
            .ok_or_else(|| Error::TerminalReadControl {
                operation: "prepare C reader",
                source: std::io::Error::from_raw_os_error(error),
                terminal_exit: self.registry.terminal_exit(self.worker),
            })?;
        let operation = {
            let mut state = lock(&self.registry.state);
            let Some(generation) = state.next.checked_add(1) else {
                // No thread or concurrent user exists yet.
                unsafe {
                    rvk_read_finish(native.as_ptr());
                    rvk_read_destroy(native.as_ptr());
                }
                return Err(Error::TerminalReadControl {
                    operation: "operation generation exhausted",
                    source: std::io::Error::other("stdin operation generation exhausted"),
                    terminal_exit: if self.worker {
                        &state.worker_terminal
                    } else {
                        &state.root_terminal
                    }
                    .as_deref()
                    .and_then(Terminal::exit),
                });
            };
            state.next = generation;
            let terminal = if self.worker {
                &state.worker_terminal
            } else {
                &state.root_terminal
            };
            let operation = Arc::new(Operation {
                native,
                identity: Identity {
                    generation,
                    image_generation: state.image_generation,
                    task,
                    request,
                    host_fd: fd,
                    host_address: address,
                    host_count: count,
                    worker: self.worker,
                },
                endpoint: Mutex::new(endpoint.take()),
                terminal: Mutex::new(terminal.clone()),
                cancel_requested: AtomicBool::new(false),
            });
            state.operations.insert(generation, operation.clone());
            operation
        };
        let mut owner = ReadOwner {
            operation: operation.clone(),
            registry: self.registry.clone(),
            endpoint,
            finished: false,
        };
        let waker = Waker::from(Arc::new(ReadWake(operation.clone())));
        let mut context = Context::from_waker(&waker);
        let watch = self.watch.clone();
        let mut changed = std::pin::pin!(watch.wait());
        let mut observe_terminal = |context: &mut Context<'_>| {
            if operation.terminal().is_some() {
                operation.cancel();
                return;
            }
            let _ = changed.as_mut().poll(context);
            let cause = match self.watch.check() {
                Err(error) => Some(error),
                Ok(()) => observer.poll(context),
            };
            if let Some(cause) = cause {
                // Serialize a newly observed terminal obligation with this
                // operation's registration/removal, just like group disposal.
                let _state = lock(&self.registry.state);
                operation.mark_terminal(Arc::new(Terminal::Failure(Arc::new(cause))));
            }
            if operation.terminal().is_some() {
                operation.cancel();
            }
        };
        observe_terminal(&mut context);
        // SAFETY: owner is the sole creator/retirement owner. Early C outcome
        // and pre-publication cancellation are serialized inside C start.
        let start_error = unsafe { rvk_read_start(operation.native.as_ptr()) };
        if start_error != 0 {
            let snapshot = operation.snapshot();
            if snapshot.outcome == PENDING && snapshot.handle_published == 0 {
                // A synchronization failure can follow successful creation
                // but precede handle publication. Absence of a public handle
                // is not proof that no C thread exists. Keep the entire owned
                // operation in the registry; never attempt an early join,
                // release its File, or fall back to the old Rust read.
                return Err(
                    owner.retain_unretired("C start publication (ownership retained)", start_error)
                );
            }
        }
        loop {
            // Arm before polling/checking. Either C outcome or a terminal
            // future's wake advances this epoch, including before wait begins.
            let epoch = unsafe { rvk_read_epoch(operation.native.as_ptr()) };
            observe_terminal(&mut context);
            let snapshot = operation.snapshot();
            if snapshot.state == u32::MAX {
                return Err(owner
                    .retain_unretired("C snapshot (ownership retained)", snapshot.error_number));
            }
            if snapshot.outcome != PENDING {
                break;
            }
            if let Some(error) = operation.control_error(snapshot) {
                // A failed cancel may leave the public read blocked forever.
                // Its wake is an error notification, not eventual completion.
                // Report the first control failure without an early join or
                // another send; the registry keeps the live endpoint/storage.
                return Err(owner.retain_error(error));
            }
            // SAFETY: the lexical owner and waker both pin C storage. This
            // sleeps without any Rust registry or operation lock held.
            let error = unsafe { rvk_read_wait(operation.native.as_ptr(), epoch) };
            if error != 0 {
                return Err(owner.retain_unretired("C wait (ownership retained)", error));
            }
        }
        owner.finish()
    }
}

impl Drop for ReadContext {
    fn drop(&mut self) {
        // A preflight refusal may leave the observer unpolled; an unexpected
        // outer unwind may drop the context before read() takes ownership.
        // User destruction still runs outside registry/operation locks and
        // has its own catch, never an automatic second unwind.
        drop(self.take_observer());
    }
}

/// This guard is created before starting C. Rust future polling can unwind;
/// the guard cancels, waits for outcome, disarms/drains and joins locally before
/// the executor's descriptor retirement guard can end.
struct ReadOwner<'a> {
    operation: Arc<Operation>,
    registry: Arc<ReadRegistry>,
    endpoint: &'a mut Option<File>,
    finished: bool,
}

impl ReadOwner<'_> {
    fn retain_unretired(&mut self, operation: &'static str, error: i32) -> Error {
        let error = Error::TerminalReadControl {
            operation,
            source: std::io::Error::from_raw_os_error(error),
            terminal_exit: self
                .operation
                .terminal()
                .as_deref()
                .and_then(Terminal::exit),
        };
        self.retain_error(error)
    }

    fn retain_error(&mut self, error: Error) -> Error {
        self.finished = true;
        let cause = self.operation.terminal();
        let error = Error::SharedFailure(self.registry.record_error(&self.operation, error));
        match cause.as_deref() {
            Some(Terminal::Failure(primary)) => {
                Error::SharedFailure(primary.clone()).with_cleanup(vec![error])
            }
            _ => error,
        }
    }

    fn finish(&mut self) -> Result<NativeReturn> {
        // SAFETY: this is the sole retirement owner. The C implementation
        // disarms/drains before join, and never holds its locks across join.
        let finish_error = unsafe { rvk_read_finish(self.operation.native.as_ptr()) };
        self.finished = true;
        let snapshot = self.operation.snapshot();
        let cause = {
            let mut state = lock(&self.registry.state);
            let cause = self.operation.terminal();
            if matches!(snapshot.state, JOINED | NO_THREAD) {
                *self.endpoint = lock(&self.operation.endpoint).take();
                state.operations.remove(&self.operation.identity.generation);
            }
            cause
        };
        let mut control = self.operation.control_error(snapshot);
        if finish_error != 0 && (snapshot.error_phase != 3 || snapshot.error_number != finish_error)
        {
            let retirement = Error::TerminalReadControl {
                operation: "physical retirement (ownership retained)",
                source: std::io::Error::from_raw_os_error(finish_error),
                terminal_exit: cause.as_deref().and_then(Terminal::exit),
            };
            control = Some(match control {
                Some(first) => first.with_cleanup(vec![retirement]),
                None => retirement,
            });
        }
        if let Some(error) = control {
            let error = Error::SharedFailure(self.registry.record_error(&self.operation, error));
            return Err(match cause.as_deref() {
                Some(Terminal::Failure(primary)) => {
                    Error::SharedFailure(primary.clone()).with_cleanup(vec![error])
                }
                _ => error,
            });
        }
        if let Some(cause) = cause {
            return Err(cause.error());
        }
        if snapshot.outcome != RETURNED {
            let error = Error::TerminalReadControl {
                operation: "outcome without a terminal cause",
                source: std::io::Error::other("C reader canceled without terminal authority"),
                terminal_exit: None,
            };
            return Err(Error::SharedFailure(
                self.registry.record_error(&self.operation, error),
            ));
        }
        Ok(NativeReturn {
            count: snapshot.result as isize,
            errno: snapshot.read_errno,
        })
    }
}

impl Drop for ReadOwner<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.operation
            .mark_terminal(Arc::new(Terminal::Failure(Arc::new(Error::HostIo(
                std::io::Error::other("stdin read owner unwound"),
            )))));
        self.operation.cancel();
        loop {
            let epoch = unsafe { rvk_read_epoch(self.operation.native.as_ptr()) };
            let snapshot = self.operation.snapshot();
            if snapshot.state == u32::MAX {
                let _ = self.retain_unretired(
                    "C unwind snapshot (ownership retained)",
                    snapshot.error_number,
                );
                return;
            }
            if snapshot.outcome != PENDING || snapshot.handle_published == 0 {
                break;
            }
            if let Some(error) = self.operation.control_error(snapshot) {
                let _ = self.retain_error(error);
                return;
            }
            // No Rust or group lock is held. This does not promise bounded
            // retirement for an uninterruptible kernel driver.
            let error = unsafe { rvk_read_wait(self.operation.native.as_ptr(), epoch) };
            if error != 0 {
                let _ = self.retain_unretired("C unwind wait (ownership retained)", error);
                return;
            }
        }
        // Errors are retained in the registry; never panic a second time or
        // detach an unjoined helper during Rust unwinding.
        let _ = self.finish();
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    /// Kept until after dispatch returns so both physical join and disappearance
    /// of the exact observed Linux thread generation can be asserted.
    pub(crate) struct BlockedRead {
        operation: Arc<Operation>,
        tid: u32,
        start_time: u64,
    }

    fn start_time(tid: u32) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
        stat[stat.rfind(')')? + 1..]
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }

    impl ReadRegistry {
        /// A dispatcher refusal must happen before a reader is registered or
        /// launched. An empty live map alone could hide a completed operation;
        /// the monotonic generation must also still be zero.
        pub(crate) fn assert_no_test_read_started(&self) {
            let state = lock(&self.state);
            assert_eq!(state.next, 0, "refused read created a reader operation");
            assert!(state.operations.is_empty());
            assert!(state.errors.is_empty());
        }

        pub(crate) fn exhaust_test_generations(&self) {
            lock(&self.state).next = u64::MAX;
        }

        pub(crate) fn observe_blocked_test_read(
            &self,
            task: SignalTaskIdentity,
            request: SyscallRequest,
            host_fd: i32,
        ) -> BlockedRead {
            let operation = {
                let state = lock(&self.state);
                assert_eq!(state.operations.len(), 1);
                state.operations.values().next().unwrap().clone()
            };
            assert_eq!(operation.identity.task, task);
            assert_eq!(operation.identity.request, request);
            assert_eq!(operation.identity.host_fd, host_fd);
            assert_eq!(operation.identity.host_address, request.args()[1] as usize);
            assert_eq!(operation.identity.host_count, 0);
            assert_eq!(
                lock(&operation.endpoint).as_ref().unwrap().as_raw_fd(),
                host_fd
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let snapshot = operation.snapshot();
                assert_eq!(snapshot.outcome, PENDING);
                assert_eq!(snapshot.handle_published, 1);
                assert_eq!(snapshot.error_number, 0);
                assert!(operation.terminal().is_none());
                for entry in std::fs::read_dir("/proc/self/task").unwrap() {
                    let entry = entry.unwrap();
                    let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                        continue;
                    };
                    let Some(before) = start_time(tid) else {
                        continue;
                    };
                    let Ok(syscall) = std::fs::read_to_string(entry.path().join("syscall")) else {
                        continue;
                    };
                    let fields: Vec<_> = syscall.split_whitespace().collect();
                    let hex = |index: usize| {
                        fields.get(index).and_then(|word| {
                            u64::from_str_radix(word.trim_start_matches("0x"), 16).ok()
                        })
                    };
                    if fields.first().and_then(|number| number.parse::<i64>().ok())
                        == Some(libc::SYS_read)
                        && hex(1) == Some(host_fd as u64)
                        && hex(2) == Some(request.args()[1])
                        && hex(3) == Some(0)
                        && start_time(tid) == Some(before)
                    {
                        // Entry is proved by a kernel syscall snapshot, not by
                        // elapsed time, a published pthread handle, or a poll.
                        assert_eq!(operation.snapshot().outcome, PENDING);
                        println!(
                            "BLOCKED_ZERO_READ operation={} image={} task={task:?} request={request:?} host_fd={host_fd} tid={tid} start_time={before} syscall={}",
                            operation.identity.generation,
                            operation.identity.image_generation,
                            syscall.trim()
                        );
                        return BlockedRead {
                            operation,
                            tid,
                            start_time: before,
                        };
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "no matching kernel read entry observed"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl BlockedRead {
        pub(crate) fn assert_retired(self, registry: &ReadRegistry) {
            let snapshot = self.operation.snapshot();
            assert_eq!(snapshot.state, JOINED);
            assert_eq!(
                snapshot.outcome, 2,
                "blocked reader did not publish CANCELED"
            );
            assert_eq!(snapshot.senders, 0);
            assert_eq!(snapshot.error_number, 0);
            assert!(lock(&self.operation.endpoint).is_none());
            assert!(lock(&registry.state).operations.is_empty());
            let deadline = Instant::now() + Duration::from_secs(30);
            while start_time(self.tid) == Some(self.start_time) {
                assert!(
                    Instant::now() < deadline,
                    "joined helper's Linux task remains"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            println!(
                "RETIRED_ZERO_READ operation={} tid={} start_time={} state={} senders={}",
                self.operation.identity.generation,
                self.tid,
                self.start_time,
                snapshot.state,
                snapshot.senders
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd;
    use std::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;
    use std::sync::atomic::AtomicUsize;
    use std::task::Poll;

    use super::*;

    fn task(worker: bool) -> SignalTaskIdentity {
        SignalTaskIdentity {
            process: reverie::SignalProcessId {
                tgid: reverie::Pid::from_raw(11),
                generation: 12,
            },
            tid: reverie::Pid::from_raw(if worker { 13 } else { 11 }),
            task_generation: 14,
        }
    }

    fn context(
        registry: Arc<ReadRegistry>,
        worker: bool,
        failure: Option<BoxFuture<'static, ()>>,
    ) -> ReadContext {
        let memory = crate::GuestMemory::new(0, 4096).unwrap();
        ReadContext::new(
            registry,
            worker,
            EntryDriverWatch::for_memory(&memory),
            failure,
            Arc::new(ToolPanics::default()),
            worker,
        )
    }

    fn read(context: &mut ReadContext, fd: &mut Option<File>) -> Result<NativeReturn> {
        let mut bytes = Vec::<u8>::new();
        context.read(
            fd,
            task(context.worker),
            SyscallRequest::new(libc::SYS_read as u64, [0, 0x100, 0, 0, 0, 0]),
            bytes.as_mut_ptr() as usize,
            0,
        )
    }

    fn inotify() -> File {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: successful inotify_init1 transfers a new owned descriptor.
        unsafe { File::from_raw_fd(fd) }
    }

    #[test]
    fn terminal_before_registration_keeps_first_exit_and_endpoint() {
        let registry = Arc::new(ReadRegistry::default());
        registry.request_exit_group(ExitStatus::Exited(37));
        registry.request_exit_group(ExitStatus::Exited(99));
        let mut context = context(
            registry.clone(),
            false,
            Some(Box::pin(async {
                panic!("already-terminal registration polled an unrelated future");
            })),
        );
        let mut fd = Some(inotify());
        let original = fd.as_ref().unwrap().as_raw_fd();
        assert!(matches!(
            read(&mut context, &mut fd),
            Err(Error::TerminalReadCancelled)
        ));
        assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
        assert!(lock(&registry.state).operations.is_empty());
        assert!(matches!(
            lock(&registry.state).root_terminal.as_deref(),
            Some(Terminal::Exit(ExitStatus::Exited(37)))
        ));
        assert!(registry.teardown_result().is_ok());
    }

    #[test]
    fn generation_refusal_keeps_preexisting_first_exit_and_endpoint() {
        let registry = Arc::new(ReadRegistry::default());
        registry.request_exit_group(ExitStatus::Exited(37));
        registry.request_exit_group(ExitStatus::Exited(99));
        lock(&registry.state).next = u64::MAX;
        let mut context = context(registry.clone(), false, None);
        let mut fd = Some(inotify());
        let original = fd.as_ref().unwrap().as_raw_fd();
        assert!(matches!(
            read(&mut context, &mut fd),
            Err(Error::TerminalReadControl {
                operation: "operation generation exhausted",
                terminal_exit: Some(ExitStatus::Exited(37)),
                ..
            })
        ));
        assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
        assert!(unsafe { libc::fcntl(original, libc::F_GETFD) } >= 0);
        assert!(lock(&registry.state).operations.is_empty());
        assert_eq!(lock(&registry.state).next, u64::MAX);
    }

    #[test]
    fn failed_registry_drop_retains_exact_diagnostics_causes_and_owned_storage() {
        let (control, observer, terminal, operation, original) = {
            let registry = Arc::new(ReadRegistry::default());
            registry.request_exit_group(ExitStatus::Exited(37));
            registry.request_exit_group(ExitStatus::Exited(99));
            let terminal = lock(&registry.state).root_terminal.clone().unwrap();
            let file = inotify();
            let original = file.as_raw_fd();
            let mut bytes = Vec::<u8>::new();
            let address = bytes.as_mut_ptr() as usize;
            let mut errno = 0;
            let native = NonNull::new(unsafe { rvk_read_new(original, address, 0, &mut errno) })
                .expect("retention control could not allocate C storage");
            assert_eq!(errno, 0);
            // Prepared storage only: this test neither starts a helper nor
            // claims that a real pthread_join returned the controlled error.
            let operation = Arc::new(Operation {
                native,
                identity: Identity {
                    generation: 1,
                    image_generation: 0,
                    task: task(false),
                    request: SyscallRequest::new(libc::SYS_read as u64, [0, 0x100, 0, 0, 0, 0]),
                    host_fd: original,
                    host_address: address,
                    host_count: 0,
                    worker: false,
                },
                endpoint: Mutex::new(Some(file)),
                terminal: Mutex::new(Some(terminal.clone())),
                cancel_requested: AtomicBool::new(false),
            });
            let control = Arc::new(Error::TerminalReadControl {
                operation: "test-controlled retained diagnostic",
                source: std::io::Error::from_raw_os_error(libc::EDEADLK),
                terminal_exit: Some(ExitStatus::Exited(37)),
            });
            let observer = Arc::new(Error::GuestWorkerPanic);
            {
                let mut state = lock(&registry.state);
                state.next = 1;
                state.operations.insert(1, operation.clone());
                state.observer_errors.push(observer.clone());
            }
            registry.record_error(&operation, Error::SharedFailure(control.clone()));
            let returned = registry.teardown_result().unwrap_err();
            assert!(crate::failure::references_shared_error(&returned, &control));
            assert!(crate::failure::references_shared_error(
                &returned, &observer
            ));
            drop(returned);
            let witnesses = (
                Arc::downgrade(&control),
                Arc::downgrade(&observer),
                Arc::downgrade(&terminal),
                Arc::downgrade(&operation),
                original,
            );
            drop(control);
            drop(observer);
            drop(terminal);
            drop(operation);
            drop(registry);
            witnesses
        };
        let control = control
            .upgrade()
            .expect("registry Drop lost the typed error");
        assert!(matches!(
            control.as_ref(),
            Error::TerminalReadControl {
                source,
                terminal_exit: Some(ExitStatus::Exited(37)),
                ..
            } if source.raw_os_error() == Some(libc::EDEADLK)
        ));
        assert!(matches!(
            observer.upgrade().unwrap().as_ref(),
            Error::GuestWorkerPanic
        ));
        assert!(matches!(
            terminal.upgrade().unwrap().as_ref(),
            Terminal::Exit(ExitStatus::Exited(37))
        ));
        let operation = operation
            .upgrade()
            .expect("registry Drop lost operation ownership");
        let snapshot = operation.snapshot();
        assert_eq!(
            snapshot.state, 0,
            "prepared storage unexpectedly changed state"
        );
        assert_eq!(snapshot.outcome, PENDING);
        assert_eq!(snapshot.handle_published, 0);
        assert_eq!(snapshot.senders, 0);
        assert_eq!(
            lock(&operation.endpoint).as_ref().unwrap().as_raw_fd(),
            original
        );
        assert!(unsafe { libc::fcntl(original, libc::F_GETFD) } >= 0);
    }

    #[test]
    fn healthy_empty_registry_drop_does_not_retain_a_terminal_cause() {
        let terminal = {
            let registry = ReadRegistry::default();
            registry.request_exit_group(ExitStatus::Exited(37));
            let terminal = Arc::downgrade(lock(&registry.state).root_terminal.as_ref().unwrap());
            drop(registry);
            terminal
        };
        assert!(terminal.upgrade().is_none());
    }

    #[test]
    fn worker_cancellation_excludes_root_and_rearm_keeps_generations() {
        let registry = Arc::new(ReadRegistry::default());
        registry.cancel_workers();
        let mut root = context(registry.clone(), false, None);
        let mut fd = Some(File::open("/dev/null").unwrap());
        assert_eq!(read(&mut root, &mut fd).unwrap().count, 0);
        let mut worker = context(registry.clone(), true, None);
        assert!(matches!(
            read(&mut worker, &mut fd),
            Err(Error::TerminalReadCancelled)
        ));
        assert_eq!(lock(&registry.state).next, 2);
        registry.rearm_after_exec();
        assert_eq!(lock(&registry.state).image_generation, 1);
        assert_eq!(read(&mut worker, &mut fd).unwrap().count, 0);
        assert_eq!(lock(&registry.state).next, 3);
        assert!(lock(&registry.state).operations.is_empty());
    }

    #[test]
    fn registered_helper_observes_group_stop_without_a_guest_result() {
        let registry = Arc::new(ReadRegistry::default());
        let stop = registry.clone();
        let mut polls = 0;
        let failure = Box::pin(std::future::poll_fn(move |_| {
            polls += 1;
            if polls == 2 {
                // Second poll follows successful C handle publication. The
                // empty endpoint cannot complete normally before cancellation.
                assert_eq!(lock(&stop.state).operations.len(), 1);
                stop.request_exit_group(ExitStatus::Exited(37));
            }
            Poll::Pending
        }));
        let mut context = context(registry.clone(), true, Some(failure));
        let mut fd = Some(inotify());
        let flags = unsafe { libc::fcntl(fd.as_ref().unwrap().as_raw_fd(), libc::F_GETFL) };
        assert!(matches!(
            read(&mut context, &mut fd),
            Err(Error::TerminalReadCancelled)
        ));
        assert_eq!(
            unsafe { libc::fcntl(fd.as_ref().unwrap().as_raw_fd(), libc::F_GETFL) },
            flags
        );
        assert!(lock(&registry.state).operations.is_empty());
        assert!(registry.teardown_result().is_ok());
    }

    #[test]
    fn terminal_future_unwind_joins_before_releasing_the_endpoint() {
        let registry = Arc::new(ReadRegistry::default());
        let mut polls = 0;
        let failure = Box::pin(std::future::poll_fn(move |_| {
            polls += 1;
            if polls == 2 {
                std::panic::resume_unwind(Box::new("terminal observer poll"));
            }
            Poll::Pending
        }));
        let mut context = context(registry.clone(), true, Some(failure));
        let mut fd = Some(inotify());
        let original = fd.as_ref().unwrap().as_raw_fd();
        // Polling is now caught before it can unwind through user Drop. The
        // stronger contract retains the exact payload and a fatal typed result
        // after physical join; the concrete backend resumes it after cleanup.
        let caught = catch_unwind(AssertUnwindSafe(|| read(&mut context, &mut fd)));
        let Err(error) = caught.expect("observer panic escaped its owned catch") else {
            panic!("observer panic produced a guest result");
        };
        assert!(matches!(error.primary(), Error::GuestWorkerPanic));
        let payloads = context.panics.take();
        assert_eq!(payloads.len(), 1);
        assert_eq!(
            payloads[0].downcast_ref::<&str>(),
            Some(&"terminal observer poll")
        );
        assert!(context.panics.worker_execution_panicked());
        assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
        assert!(unsafe { libc::fcntl(original, libc::F_GETFD) } >= 0);
        assert!(lock(&registry.state).operations.is_empty());
        assert!(matches!(
            registry.teardown_result().unwrap_err().primary(),
            Error::GuestWorkerPanic
        ));
    }

    struct ObserverBomb {
        registry: Arc<ReadRegistry>,
        fd: i32,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        panic_on_second_poll: bool,
    }

    impl Future for ObserverBomb {
        type Output = ();

        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            if self.polls.fetch_add(1, Ordering::SeqCst) == 1 && self.panic_on_second_poll {
                std::panic::resume_unwind(Box::new("terminal observer poll"));
            }
            Poll::Pending
        }
    }

    impl Drop for ObserverBomb {
        fn drop(&mut self) {
            // Removal requires a joined/no-thread C snapshot. The endpoint
            // must still exist when user destruction runs after that point.
            assert!(lock(&self.registry.state).operations.is_empty());
            assert!(unsafe { libc::fcntl(self.fd, libc::F_GETFD) } >= 0);
            self.drops.fetch_add(1, Ordering::SeqCst);
            std::panic::resume_unwind(Box::new("terminal observer drop"));
        }
    }

    #[test]
    fn observer_poll_and_drop_panics_preserve_both_payloads_after_join() {
        let registry = Arc::new(ReadRegistry::default());
        let mut fd = Some(inotify());
        let original = fd.as_ref().unwrap().as_raw_fd();
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let future = ObserverBomb {
            registry: registry.clone(),
            fd: original,
            polls: polls.clone(),
            drops: drops.clone(),
            panic_on_second_poll: true,
        };
        let mut context = context(registry.clone(), true, Some(Box::pin(future)));
        let Err(error) = read(&mut context, &mut fd) else {
            panic!("observer panics produced a guest result");
        };
        assert!(matches!(error.primary(), Error::GuestWorkerPanic));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "panicked observer was repolled"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let payloads = context.panics.take();
        assert_eq!(payloads.len(), 2);
        assert_eq!(
            payloads[0].downcast_ref::<&str>(),
            Some(&"terminal observer poll")
        );
        assert_eq!(
            payloads[1].downcast_ref::<&str>(),
            Some(&"terminal observer drop")
        );
        assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
        assert!(registry.teardown_result().is_err());
        assert!(lock(&registry.state).operations.is_empty());
    }

    #[derive(Clone, Copy, Default)]
    enum FactoryTrigger {
        #[default]
        LocalFailure,
        ToolReady,
        PollPanic,
    }

    #[derive(Default)]
    struct FactoryGlobal {
        registry: Arc<ReadRegistry>,
        fd: i32,
        trigger: FactoryTrigger,
        drop_panic: bool,
        failure: Mutex<Option<crate::failure::FailureContext>>,
        polls: AtomicUsize,
        drops: AtomicUsize,
        dropped_after_join: AtomicBool,
        dropped_with_live_fd: AtomicBool,
    }

    struct FactoryWait<'a>(&'a FactoryGlobal);

    impl Future for FactoryWait<'_> {
        type Output = ();

        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            let global = self.0;
            if global.polls.fetch_add(1, Ordering::SeqCst) == 1 {
                match global.trigger {
                    FactoryTrigger::LocalFailure => {
                        lock(&global.failure).as_ref().unwrap().publish(
                            "terminal factory regression",
                            Error::GuestClock("factory local failure".to_owned()),
                        );
                    }
                    FactoryTrigger::ToolReady => return Poll::Ready(()),
                    FactoryTrigger::PollPanic => {
                        std::panic::resume_unwind(Box::new("factory observer poll"));
                    }
                }
            }
            Poll::Pending
        }
    }

    impl Drop for FactoryWait<'_> {
        fn drop(&mut self) {
            let global = self.0;
            let joined = lock(&global.registry.state).operations.is_empty();
            let live = unsafe { libc::fcntl(global.fd, libc::F_GETFD) } >= 0;
            global.dropped_after_join.store(joined, Ordering::SeqCst);
            global.dropped_with_live_fd.store(live, Ordering::SeqCst);
            global.drops.fetch_add(1, Ordering::SeqCst);
            // Wrong ordering is asserted below. Avoid a process abort in that
            // negative case if an implementation drops this during poll unwind;
            // the exact two-payload assertion also requires this panic to occur.
            if global.drop_panic && joined && live {
                std::panic::resume_unwind(Box::new("factory observer drop"));
            }
        }
    }

    // Spell the async-trait ABI directly so the owned Tool future itself has
    // controlled poll/Drop behavior; an extra async test wrapper would introduce
    // another independent destructor boundary and hide the factory contract.
    impl reverie::GlobalTool for FactoryGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        fn receive_rpc<'life0, 'async_trait>(
            &'life0 self,
            _: reverie::Pid,
            _: (),
        ) -> BoxFuture<'async_trait, ()>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async {})
        }

        fn wait_for_backend_failure<'life0, 'async_trait>(
            &'life0 self,
        ) -> BoxFuture<'async_trait, ()>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(FactoryWait(self))
        }
    }

    #[test]
    fn actual_factory_retains_tool_observer_until_join_on_local_and_global_terminal() {
        for trigger in [FactoryTrigger::LocalFailure, FactoryTrigger::ToolReady] {
            let registry = Arc::new(ReadRegistry::default());
            let mut fd = Some(inotify());
            let original = fd.as_ref().unwrap().as_raw_fd();
            let global = Arc::new(FactoryGlobal {
                registry: registry.clone(),
                fd: original,
                trigger,
                ..FactoryGlobal::default()
            });
            let run = crate::failure::RunFailure::new(&global);
            let failure = crate::failure::FailureContext::new(
                run.clone(),
                reverie::Pid::from_raw(11),
                reverie::Pid::from_raw(11),
            );
            *lock(&global.failure) = Some(failure.clone());
            let mut context = context(registry.clone(), false, Some(failure.terminal_wait(true)));
            let Err(error) = read(&mut context, &mut fd) else {
                panic!("terminal factory produced a guest result");
            };
            assert!(matches!(error.primary(), Error::RunAborted));
            assert_eq!(global.polls.load(Ordering::SeqCst), 2);
            assert_eq!(global.drops.load(Ordering::SeqCst), 1);
            assert!(global.dropped_after_join.load(Ordering::SeqCst));
            assert!(global.dropped_with_live_fd.load(Ordering::SeqCst));
            assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
            assert!(context.panics.take().is_empty());
            assert!(lock(&registry.state).operations.is_empty());
            match trigger {
                FactoryTrigger::LocalFailure => assert!(matches!(
                    run.primary().unwrap().primary(),
                    Error::GuestClock(message) if message == "factory local failure"
                )),
                FactoryTrigger::ToolReady => assert!(run.primary().is_none()),
                FactoryTrigger::PollPanic => unreachable!(),
            }
            assert_eq!(Arc::strong_count(&global), 1);
        }
    }

    #[test]
    fn actual_factory_preserves_poll_and_post_join_drop_panic_payloads() {
        let registry = Arc::new(ReadRegistry::default());
        let mut fd = Some(inotify());
        let original = fd.as_ref().unwrap().as_raw_fd();
        let global = Arc::new(FactoryGlobal {
            registry: registry.clone(),
            fd: original,
            trigger: FactoryTrigger::PollPanic,
            drop_panic: true,
            ..FactoryGlobal::default()
        });
        let run = crate::failure::RunFailure::new(&global);
        let failure = crate::failure::FailureContext::new(
            run,
            reverie::Pid::from_raw(11),
            reverie::Pid::from_raw(11),
        );
        let mut context = context(registry.clone(), true, Some(failure.terminal_wait(true)));
        let Err(error) = read(&mut context, &mut fd) else {
            panic!("panicking factory produced a guest result");
        };
        assert!(matches!(error.primary(), Error::GuestWorkerPanic));
        assert_eq!(global.polls.load(Ordering::SeqCst), 2);
        assert_eq!(global.drops.load(Ordering::SeqCst), 1);
        assert!(global.dropped_after_join.load(Ordering::SeqCst));
        assert!(global.dropped_with_live_fd.load(Ordering::SeqCst));
        let payloads = context.panics.take();
        assert_eq!(payloads.len(), 2);
        assert_eq!(
            payloads[0].downcast_ref::<&str>(),
            Some(&"factory observer poll")
        );
        assert_eq!(
            payloads[1].downcast_ref::<&str>(),
            Some(&"factory observer drop")
        );
        assert!(context.panics.worker_execution_panicked());
        assert!(registry.teardown_result().is_err());
        assert!(lock(&registry.state).operations.is_empty());
        assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
        assert_eq!(Arc::strong_count(&global), 1);
    }

    #[test]
    fn no_thread_control_error_survives_observer_drop_panic() {
        let registry = Arc::new(ReadRegistry::default());
        lock(&registry.state).next = u64::MAX;
        let mut fd = Some(File::open("/dev/null").unwrap());
        let original = fd.as_ref().unwrap().as_raw_fd();
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let future = ObserverBomb {
            registry: registry.clone(),
            fd: original,
            polls: polls.clone(),
            drops: drops.clone(),
            panic_on_second_poll: false,
        };
        let mut context = context(registry.clone(), false, Some(Box::pin(future)));
        let Err(error) = read(&mut context, &mut fd) else {
            panic!("control error and destructor panic produced a guest result");
        };
        assert!(matches!(
            error.primary(),
            Error::TerminalReadControl {
                operation: "operation generation exhausted",
                ..
            }
        ));
        assert!(matches!(
            registry.teardown_result().unwrap_err().primary(),
            Error::TerminalReadControl {
                operation: "operation generation exhausted",
                ..
            }
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let payloads = context.panics.take();
        assert_eq!(payloads.len(), 1);
        assert_eq!(
            payloads[0].downcast_ref::<&str>(),
            Some(&"terminal observer drop")
        );
        assert_eq!(fd.as_ref().unwrap().as_raw_fd(), original);
        assert!(lock(&registry.state).operations.is_empty());
    }

    #[test]
    fn context_drop_during_outer_unwind_retains_observer_panic_separately() {
        let registry = Arc::new(ReadRegistry::default());
        let fd = File::open("/dev/null").unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let future = ObserverBomb {
            registry: registry.clone(),
            fd: fd.as_raw_fd(),
            polls: Arc::new(AtomicUsize::new(0)),
            drops: drops.clone(),
            panic_on_second_poll: false,
        };
        let context = context(registry.clone(), false, Some(Box::pin(future)));
        let panics = context.panics.clone();
        let outer = catch_unwind(AssertUnwindSafe(move || {
            let _context = context;
            std::panic::resume_unwind(Box::new("outer unwind"));
        }))
        .expect_err("outer unwind was suppressed");
        assert_eq!(outer.downcast_ref::<&str>(), Some(&"outer unwind"));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let payloads = panics.take();
        assert_eq!(payloads.len(), 1);
        assert_eq!(
            payloads[0].downcast_ref::<&str>(),
            Some(&"terminal observer drop")
        );
        assert!(matches!(
            registry.teardown_result().unwrap_err().primary(),
            Error::GuestWorkerPanic
        ));
    }

    #[test]
    fn spurious_terminal_wake_does_not_cancel_normal_completion() {
        let registry = Arc::new(ReadRegistry::default());
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let failure = Box::pin(std::future::poll_fn(move |context| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                context.waker().wake_by_ref();
            }
            Poll::Pending
        }));
        let mut context = context(registry.clone(), false, Some(failure));
        let mut fd = Some(File::open("/dev/null").unwrap());
        assert_eq!(read(&mut context, &mut fd).unwrap().count, 0);
        assert!(polls.load(Ordering::SeqCst) >= 1);
        assert!(lock(&registry.state).root_terminal.is_none());
        assert!(lock(&registry.state).operations.is_empty());
    }
}
