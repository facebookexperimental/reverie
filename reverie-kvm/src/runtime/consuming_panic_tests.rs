/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Actual Tool exit-hook futures, including a returned error followed by Drop panic.

use std::cell::Cell;
use std::fmt;
use std::panic::resume_unwind;
use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Waker;

use futures::channel::oneshot;

use super::*;
use crate::failure::owned_future::PanicPayload;
use crate::failure::tool_panics::ToolPanics;

#[derive(Default)]
struct Counts {
    constructed: AtomicUsize,
    polls: AtomicUsize,
    drops: AtomicUsize,
}

struct HookState {
    outcome: Option<std::result::Result<(), reverie::Error>>,
    release: Option<oneshot::Receiver<()>>,
    poll_panic: Option<PanicPayload>,
    drop_panic: Option<PanicPayload>,
    thread_state: Option<u64>,
}

#[derive(Default)]
struct HookGlobal {
    thread: Mutex<Option<HookState>>,
    process: Mutex<Option<HookState>>,
    thread_counts: Counts,
    process_counts: Counts,
    failures: Mutex<Vec<reverie::BackendFailure>>,
    thread_failure_expected: AtomicBool,
}

#[reverie::global_tool]
impl GlobalTool for HookGlobal {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _: Pid, _: ()) {}

    fn report_backend_failure(&self, failure: reverie::BackendFailure) {
        self.failures.lock().unwrap().push(failure);
    }
}

struct HookFuture {
    global: Arc<HookGlobal>,
    process: bool,
    state: HookState,
}

impl HookFuture {
    fn counts(&self) -> &Counts {
        if self.process {
            &self.global.process_counts
        } else {
            &self.global.thread_counts
        }
    }
}

impl Future for HookFuture {
    type Output = std::result::Result<(), reverie::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.counts().polls.fetch_add(1, Ordering::SeqCst);
        if this.process {
            assert_eq!(this.global.thread_counts.drops.load(Ordering::SeqCst), 1);
            let failures = this.global.failures.lock().unwrap();
            if this.global.thread_failure_expected.load(Ordering::SeqCst) {
                assert_eq!(
                    failures.len(),
                    1,
                    "process hook preceded thread failure publication"
                );
                assert_eq!(failures[0].phase, "thread exit hook");
            } else {
                assert!(failures.is_empty());
            }
        }
        if let Some(payload) = this.state.poll_panic.take() {
            resume_unwind(payload);
        }
        if let Some(release) = this.state.release.as_mut() {
            match Pin::new(release).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => panic!("hook release was dropped"),
            }
        }
        this.state.release.take();
        Poll::Ready(
            this.state
                .outcome
                .take()
                .expect("completed consuming hook was repolled"),
        )
    }
}

impl Drop for HookFuture {
    fn drop(&mut self) {
        assert_eq!(self.counts().drops.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(self.state.thread_state, (!self.process).then_some(41));
        if let Some(payload) = self.state.drop_panic.take() {
            resume_unwind(payload);
        }
    }
}

#[derive(Default)]
struct HookTool {
    global: Option<Arc<HookGlobal>>,
}

// Spell the existing async_trait ABI explicitly so the actual returned hook
// future can yield Ready(Err) and independently panic on later destruction.
// An async fn local destructor would instead panic before returning Ready.
impl Tool for HookTool {
    type GlobalState = HookGlobal;
    type ThreadState = u64;

    fn on_exit_thread<'life0, 'life1, 'async_trait, G>(
        &'life0 self,
        tid: Pid,
        _global: &'life1 G,
        thread_state: u64,
        status: ExitStatus,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), reverie::Error>> + Send + 'async_trait>>
    where
        G: GlobalRPC<HookGlobal> + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        assert_eq!(tid, Pid::from_raw(19));
        assert_eq!(thread_state, 41);
        assert_eq!(status, ExitStatus::Exited(13));
        let global = self.global.as_ref().unwrap().clone();
        assert_eq!(
            global
                .thread_counts
                .constructed
                .fetch_add(1, Ordering::SeqCst),
            0
        );
        let mut state = global.thread.lock().unwrap().take().unwrap();
        state.thread_state = Some(thread_state);
        Box::pin(HookFuture {
            global,
            process: false,
            state,
        })
    }

    fn on_exit_process<'life0, 'async_trait, G>(
        self,
        pid: Pid,
        _global: &'life0 G,
        status: ExitStatus,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), reverie::Error>> + Send + 'async_trait>>
    where
        G: GlobalRPC<HookGlobal> + 'async_trait,
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        assert_eq!(pid, Pid::from_raw(19));
        assert_eq!(status, ExitStatus::Exited(13));
        let global = self.global.unwrap();
        assert_eq!(
            global
                .process_counts
                .constructed
                .fetch_add(1, Ordering::SeqCst),
            0
        );
        let state = global.process.lock().unwrap().take().unwrap();
        Box::pin(HookFuture {
            global,
            process: true,
            state,
        })
    }
}

#[derive(Debug)]
struct IoCause(&'static str);

impl fmt::Display for IoCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for IoCause {}

fn typed_error(label: &'static str) -> (reverie::Error, usize) {
    let cause = Box::new(IoCause(label));
    let address = std::ptr::from_ref(cause.as_ref()) as usize;
    let cause: Box<dyn std::error::Error + Send + Sync> = cause;
    (reverie::Error::Io(std::io::Error::other(cause)), address)
}

struct Payload {
    label: &'static str,
    drops: Arc<AtomicUsize>,
    _send_only: Cell<u8>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn payload(label: &'static str) -> (PanicPayload, usize, Arc<AtomicUsize>) {
    let drops = Arc::new(AtomicUsize::new(0));
    let payload = Box::new(Payload {
        label,
        drops: drops.clone(),
        _send_only: Cell::new(7),
    });
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    (payload, address, drops)
}

fn inspect(error: &Error, causes: &mut Vec<(usize, &'static str)>, panics: &mut Vec<&'static str>) {
    match error {
        Error::Reverie(reverie::Error::Io(error)) => {
            let cause = error.get_ref().unwrap().downcast_ref::<IoCause>().unwrap();
            causes.push((std::ptr::from_ref(cause) as usize, cause.0));
        }
        Error::SharedFailure(error) | Error::WorkerFailure { error, .. } => {
            inspect(error, causes, panics)
        }
        Error::WithCleanup { primary, cleanup } => {
            inspect(primary, causes, panics);
            for error in cleanup {
                inspect(error, causes, panics);
            }
        }
        Error::Cleanup { phase, error } if matches!(error.as_ref(), Error::GuestWorkerPanic) => {
            panics.push(phase)
        }
        _ => panic!("unexpected or flattened consuming-hook error: {error:?}"),
    }
}

fn check_hooks(pending_error: bool, poll_panics: bool, with_failure: bool) {
    let global = Arc::new(HookGlobal::default());
    let failed = pending_error || poll_panics;
    global
        .thread_failure_expected
        .store(failed, Ordering::SeqCst);
    let mut expected_errors = Vec::new();
    let mut expected_payloads = Vec::new();
    let mut expected_phases = Vec::new();
    let (release, wait) = oneshot::channel();
    let mut wait = Some(wait);
    for process in [false, true] {
        let phase = if process {
            "process exit hook"
        } else {
            "thread exit hook"
        };
        let label = if process {
            "process error"
        } else {
            "thread error"
        };
        let outcome = if pending_error {
            let (error, address) = typed_error(label);
            expected_errors.push((address, label));
            Err(error)
        } else {
            Ok(())
        };
        let mut make_payload = |enabled: bool, label: &'static str| {
            enabled.then(|| {
                let (payload, address, drops) = payload(label);
                expected_payloads.push((address, label, drops));
                expected_phases.push(phase);
                payload
            })
        };
        let state = HookState {
            outcome: Some(outcome),
            release: if pending_error && !process {
                wait.take()
            } else {
                None
            },
            poll_panic: make_payload(
                poll_panics,
                if process {
                    "process poll"
                } else {
                    "thread poll"
                },
            ),
            drop_panic: make_payload(
                failed,
                if process {
                    "process drop"
                } else {
                    "thread drop"
                },
            ),
            thread_state: None,
        };
        if process {
            *global.process.lock().unwrap() = Some(state);
        } else {
            *global.thread.lock().unwrap() = Some(state);
        }
    }
    let run = RunFailure::new(&global);
    let failure = FailureContext::new(run.clone(), Pid::from_raw(19), Pid::from_raw(19));
    let panics = ToolPanics::default();
    let mut notify = Box::pin(notify_tool_exit_with_panics(
        Arc::new(HookTool {
            global: Some(global.clone()),
        }),
        Pid::from_raw(19),
        Pid::from_raw(19),
        global.as_ref(),
        &(),
        41,
        ToolExit {
            status: ExitStatus::Exited(13),
            process_exited: true,
        },
        with_failure.then_some(&failure),
        &panics,
    ));
    fn require_send<T: Send>(_: &T) {}
    require_send(&notify);
    let mut cx = Context::from_waker(Waker::noop());
    if pending_error {
        assert!(notify.as_mut().poll(&mut cx).is_pending());
        assert_eq!(global.thread_counts.constructed.load(Ordering::SeqCst), 1);
        assert_eq!(global.thread_counts.polls.load(Ordering::SeqCst), 1);
        assert_eq!(global.thread_counts.drops.load(Ordering::SeqCst), 0);
        assert_eq!(global.process_counts.constructed.load(Ordering::SeqCst), 0);
        assert!(global.failures.lock().unwrap().is_empty());
        for (_, _, drops) in &expected_payloads {
            assert_eq!(drops.load(Ordering::SeqCst), 0);
        }
        release.send(()).unwrap();
    }
    let Poll::Ready(result) = notify.as_mut().poll(&mut cx) else {
        panic!("released consuming hooks remained pending");
    };
    drop(notify);
    assert_eq!(
        global.thread_counts.polls.load(Ordering::SeqCst),
        if pending_error { 2 } else { 1 }
    );
    assert_eq!(global.process_counts.polls.load(Ordering::SeqCst), 1);
    for counts in [&global.thread_counts, &global.process_counts] {
        assert_eq!(counts.constructed.load(Ordering::SeqCst), 1);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    }
    let failures = global.failures.lock().unwrap();
    if failed {
        assert_eq!(
            failures.iter().map(|event| event.phase).collect::<Vec<_>>(),
            vec!["thread exit hook", "process exit hook"]
        );
        let error = result.unwrap_err();
        let mut actual_errors = Vec::new();
        let mut actual_phases = Vec::new();
        inspect(&error, &mut actual_errors, &mut actual_phases);
        assert_eq!(actual_errors, expected_errors);
        assert_eq!(actual_phases, expected_phases);
        if with_failure {
            let first = run.published_primary().unwrap();
            assert!(error.retains_primary(&first));
        }
    } else {
        result.unwrap();
        assert!(failures.is_empty());
        assert!(run.published_primary().is_none());
    }
    let payloads = panics.take();
    assert_eq!(payloads.len(), expected_payloads.len());
    assert!(panics.take().is_empty());
    for (actual, (address, label, drops)) in payloads.iter().zip(&expected_payloads) {
        let actual = actual.downcast_ref::<Payload>().unwrap();
        assert_eq!(std::ptr::from_ref(actual) as usize, *address);
        assert_eq!(actual.label, *label);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(payloads);
    for (_, _, drops) in expected_payloads {
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn pending_thread_error_and_destructor_panic_preserve_process_error_and_panic() {
    for with_failure in [false, true] {
        check_hooks(true, false, with_failure);
    }
}

#[test]
fn thread_poll_and_drop_panics_do_not_skip_process_poll_and_drop_panics() {
    for with_failure in [false, true] {
        check_hooks(false, true, with_failure);
    }
}

#[test]
fn successful_consuming_hooks_keep_normal_order_without_failure_publication() {
    for with_failure in [false, true] {
        check_hooks(false, false, with_failure);
    }
}

// These methods panic before returning a BoxFuture. Keep this fixture separate
// so the original polling/destruction controls and assertions stay unchanged.
#[derive(Default)]
struct ConstructorTool {
    global: Option<Arc<HookGlobal>>,
    thread_constructor_panic: Mutex<Option<PanicPayload>>,
    process_constructor_panic: Mutex<Option<PanicPayload>>,
}

struct ProcessAfterConstructorFuture {
    global: Arc<HookGlobal>,
}

impl Future for ProcessAfterConstructorFuture {
    type Output = std::result::Result<(), reverie::Error>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(
            self.global
                .process_counts
                .polls
                .fetch_add(1, Ordering::SeqCst),
            0
        );
        let failures = self.global.failures.lock().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].phase, "thread exit hook");
        Poll::Ready(Ok(()))
    }
}

impl Drop for ProcessAfterConstructorFuture {
    fn drop(&mut self) {
        assert_eq!(self.global.process_counts.polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.global
                .process_counts
                .drops
                .fetch_add(1, Ordering::SeqCst),
            0
        );
    }
}

impl Tool for ConstructorTool {
    type GlobalState = HookGlobal;
    type ThreadState = u64;

    fn on_exit_thread<'life0, 'life1, 'async_trait, G>(
        &'life0 self,
        tid: Pid,
        _global: &'life1 G,
        thread_state: u64,
        status: ExitStatus,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), reverie::Error>> + Send + 'async_trait>>
    where
        G: GlobalRPC<HookGlobal> + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        assert_eq!(tid, Pid::from_raw(19));
        assert_eq!(thread_state, 41);
        assert_eq!(status, ExitStatus::Exited(13));
        let global = self.global.as_ref().unwrap().clone();
        assert_eq!(
            global
                .thread_counts
                .constructed
                .fetch_add(1, Ordering::SeqCst),
            0
        );
        assert!(global.failures.lock().unwrap().is_empty());
        let panic = self.thread_constructor_panic.lock().unwrap().take();
        if let Some(payload) = panic {
            resume_unwind(payload);
        }
        let mut state = global.thread.lock().unwrap().take().unwrap();
        state.thread_state = Some(thread_state);
        Box::pin(HookFuture {
            global,
            process: false,
            state,
        })
    }

    fn on_exit_process<'life0, 'async_trait, G>(
        self,
        pid: Pid,
        _global: &'life0 G,
        status: ExitStatus,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), reverie::Error>> + Send + 'async_trait>>
    where
        G: GlobalRPC<HookGlobal> + 'async_trait,
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        assert_eq!(pid, Pid::from_raw(19));
        assert_eq!(status, ExitStatus::Exited(13));
        let global = self.global.unwrap();
        assert_eq!(
            global
                .process_counts
                .constructed
                .fetch_add(1, Ordering::SeqCst),
            0
        );
        {
            let failures = global.failures.lock().unwrap();
            assert_eq!(
                failures.len(),
                1,
                "process construction preceded thread failure publication"
            );
            assert_eq!(failures[0].phase, "thread exit hook");
        }
        let panic = self.process_constructor_panic.lock().unwrap().take();
        if let Some(payload) = panic {
            assert_eq!(global.thread_counts.polls.load(Ordering::SeqCst), 1);
            assert_eq!(global.thread_counts.drops.load(Ordering::SeqCst), 1);
            resume_unwind(payload);
        }
        assert_eq!(global.thread_counts.polls.load(Ordering::SeqCst), 0);
        assert_eq!(global.thread_counts.drops.load(Ordering::SeqCst), 0);
        Box::pin(ProcessAfterConstructorFuture { global })
    }
}

fn check_constructor_panic(thread_constructor: bool, with_failure: bool) {
    let global = Arc::new(HookGlobal::default());
    let mut expected_errors = Vec::new();
    let mut expected_payloads = Vec::new();
    let mut make_payload = |label: &'static str| {
        let (payload, address, drops) = payload(label);
        expected_payloads.push((address, label, drops));
        payload
    };
    let (thread_panic, process_panic) = if thread_constructor {
        (Some(make_payload("thread constructor")), None)
    } else {
        let (error, address) = typed_error("thread error before process constructor");
        expected_errors.push((address, "thread error before process constructor"));
        *global.thread.lock().unwrap() = Some(HookState {
            outcome: Some(Err(error)),
            release: None,
            poll_panic: None,
            drop_panic: Some(make_payload("thread drop before process constructor")),
            thread_state: None,
        });
        (None, Some(make_payload("process constructor")))
    };
    let run = RunFailure::new(&global);
    let failure = FailureContext::new(run.clone(), Pid::from_raw(19), Pid::from_raw(19));
    let panics = ToolPanics::default();
    let mut notify = Box::pin(notify_tool_exit_with_panics(
        Arc::new(ConstructorTool {
            global: Some(global.clone()),
            thread_constructor_panic: Mutex::new(thread_panic),
            process_constructor_panic: Mutex::new(process_panic),
        }),
        Pid::from_raw(19),
        Pid::from_raw(19),
        global.as_ref(),
        &(),
        41,
        ToolExit {
            status: ExitStatus::Exited(13),
            process_exited: true,
        },
        with_failure.then_some(&failure),
        &panics,
    ));
    fn require_send<T: Send>(_: &T) {}
    require_send(&notify);
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(result) = notify.as_mut().poll(&mut cx) else {
        panic!("finite constructor controls stayed pending");
    };
    drop(notify);
    let error = result.unwrap_err();
    assert_eq!(global.thread_counts.constructed.load(Ordering::SeqCst), 1);
    assert_eq!(global.process_counts.constructed.load(Ordering::SeqCst), 1);
    let (thread_futures, process_futures) = if thread_constructor { (0, 1) } else { (1, 0) };
    assert_eq!(
        global.thread_counts.polls.load(Ordering::SeqCst),
        thread_futures
    );
    assert_eq!(
        global.thread_counts.drops.load(Ordering::SeqCst),
        thread_futures
    );
    assert_eq!(
        global.process_counts.polls.load(Ordering::SeqCst),
        process_futures
    );
    assert_eq!(
        global.process_counts.drops.load(Ordering::SeqCst),
        process_futures
    );
    assert!(global.thread.lock().unwrap().is_none());
    assert!(global.process.lock().unwrap().is_none());

    let expected_phases = if thread_constructor {
        vec!["thread exit hook"]
    } else {
        vec!["thread exit hook", "process exit hook"]
    };
    let failures = global.failures.lock().unwrap();
    assert_eq!(
        failures.iter().map(|event| event.phase).collect::<Vec<_>>(),
        expected_phases
    );
    for event in failures.iter() {
        assert_eq!(event.pid, Pid::from_raw(19));
        assert_eq!(event.tid, Pid::from_raw(19));
    }
    let mut actual_errors = Vec::new();
    let mut actual_phases = Vec::new();
    inspect(&error, &mut actual_errors, &mut actual_phases);
    assert_eq!(actual_errors, expected_errors);
    assert_eq!(actual_phases, expected_phases);
    if with_failure {
        let first = run.published_primary().unwrap();
        assert!(error.retains_primary(&first));
        let mut first_errors = Vec::new();
        let mut first_phases = Vec::new();
        inspect(&first, &mut first_errors, &mut first_phases);
        assert_eq!(first_errors, expected_errors);
        assert_eq!(first_phases, vec!["thread exit hook"]);
    } else {
        assert!(run.published_primary().is_none());
    }

    let payloads = panics.take();
    assert_eq!(payloads.len(), expected_payloads.len());
    assert!(panics.take().is_empty());
    for (actual, (address, label, drops)) in payloads.iter().zip(&expected_payloads) {
        let actual = actual.downcast_ref::<Payload>().unwrap();
        assert_eq!(std::ptr::from_ref(actual) as usize, *address);
        assert_eq!(actual.label, *label);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(payloads);
    for (_, _, drops) in expected_payloads {
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn thread_constructor_panic_is_published_before_process_hook_runs() {
    for with_failure in [false, true] {
        check_constructor_panic(true, with_failure);
    }
}

#[test]
fn process_constructor_panic_retains_prior_thread_error_and_drop_payload() {
    for with_failure in [false, true] {
        check_constructor_panic(false, with_failure);
    }
}
