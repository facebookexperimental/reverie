/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Host controls for worker owner consumption after local execution panic.
//! The existing leader_exit integration exercises the actual KVM worker path.

use std::cell::Cell;
use std::sync::atomic::AtomicUsize;

use super::*;
use crate::failure::owned_future::CaughtFuture;
use crate::failure::owned_future::PanicPayload;
use crate::failure::tool_panics::ToolPanics;

#[derive(Default)]
struct Observed {
    hooks: AtomicUsize,
    state_drops: AtomicUsize,
    tool_drops: AtomicUsize,
    hook_panic: Mutex<Option<PanicPayload>>,
    state_panic: Mutex<Option<PanicPayload>>,
    tool_panic: Mutex<Option<PanicPayload>>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct State {
    #[serde(skip)]
    observed: Arc<Observed>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.observed.state_drops.fetch_add(1, Ordering::SeqCst);
        let payload = self.observed.state_panic.lock().unwrap().take();
        if let Some(payload) = payload {
            std::panic::resume_unwind(payload);
        }
    }
}

#[derive(Default)]
struct WorkerTool(Arc<Observed>);

impl Drop for WorkerTool {
    fn drop(&mut self) {
        self.0.tool_drops.fetch_add(1, Ordering::SeqCst);
        let payload = self.0.tool_panic.lock().unwrap().take();
        if let Some(payload) = payload {
            std::panic::resume_unwind(payload);
        }
    }
}

#[reverie::tool]
impl Tool for WorkerTool {
    type GlobalState = ();
    type ThreadState = State;

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Pid,
        _: &G,
        _: State,
        _: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        self.0.hooks.fetch_add(1, Ordering::SeqCst);
        let payload = self.0.hook_panic.lock().unwrap().take();
        if let Some(payload) = payload {
            std::panic::resume_unwind(payload);
        }
        Ok(())
    }
}

struct Payload {
    drops: Arc<AtomicUsize>,
    _send_only: Cell<u8>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn payload(expected: &mut Vec<(usize, Arc<AtomicUsize>)>) -> PanicPayload {
    let drops = Arc::new(AtomicUsize::new(0));
    let value = Box::new(Payload {
        drops: drops.clone(),
        _send_only: Cell::new(19),
    });
    expected.push((std::ptr::from_ref(value.as_ref()) as usize, drops));
    value
}

async fn panicked_execution(payload: PanicPayload) -> Result<()> {
    std::panic::resume_unwind(payload)
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Execution,
    ReturnedError,
    PeerCancellation,
    TransferredPanic,
    ExitHookPanic,
}

fn check_worker(case: Case, destructor_panics: bool) {
    let panics = Arc::new(ToolPanics::default());
    let observed = Arc::new(Observed::default());
    let mut expected = Vec::new();
    let execution_panic = matches!(case, Case::Execution);
    let original = match case {
        Case::Execution => {
            let original = payload(&mut expected);
            let caught: CaughtFuture<Result<()>> = futures::executor::block_on(
                crate::failure::owned_future::catch_owned_future(panicked_execution(original)),
            );
            panics
                .finish_worker_execution(caught, "Tool callback")
                .unwrap_err()
        }
        Case::ReturnedError => Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)),
        Case::PeerCancellation => Error::RunAborted,
        Case::TransferredPanic => {
            panics.append(vec![payload(&mut expected)]);
            Error::RunAborted
        }
        Case::ExitHookPanic => {
            *observed.hook_panic.lock().unwrap() = Some(payload(&mut expected));
            Error::RunAborted
        }
    };
    assert_eq!(panics.worker_execution_panicked(), execution_panic);
    if destructor_panics {
        *observed.state_panic.lock().unwrap() = Some(payload(&mut expected));
        *observed.tool_panic.lock().unwrap() = Some(payload(&mut expected));
    }

    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let failure = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let original = failure.publish("Tool callback", original);
    let first = run.primary();
    let leader = ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new("/")),
        false,
    );
    let mut executor = leader.thread_child(2).unwrap();
    executor.retire_failed_thread();

    // A separately retained child must still consume its own state even when
    // the panicked worker's own hook is bypassed.
    let child = Arc::new(Observed::default());
    let child_observed = child.clone();
    executor.retain_unstarted_tool_cleanup(Box::pin(async move {
        let child_panics = ToolPanics::default();
        notify_tool_exit_with_panics(
            Arc::new(WorkerTool(child_observed.clone())),
            Pid::from_raw(1),
            Pid::from_raw(3),
            &(),
            &(),
            State {
                observed: child_observed,
            },
            ToolExit {
                status: ExitStatus::Exited(255),
                process_exited: false,
            },
            None,
            &child_panics,
        )
        .await
    }));
    futures::executor::block_on(finish_unstarted_tool_cleanups_with_panics(
        &mut executor,
        &panics,
    ))
    .unwrap();
    assert_eq!(child.hooks.load(Ordering::SeqCst), 1);
    assert_eq!(child.state_drops.load(Ordering::SeqCst), 1);
    assert_eq!(child.tool_drops.load(Ordering::SeqCst), 1);

    let result = futures::executor::block_on(finish_tool_process_after_workers_with_panics(
        &mut executor,
        Arc::new(WorkerTool(observed.clone())),
        (Pid::from_raw(1), Pid::from_raw(2)),
        global.as_ref(),
        &(),
        State {
            observed: observed.clone(),
        },
        Err(original),
        None,
        Ok(()),
        Some(&failure),
        &panics,
        None,
        None,
        false,
    ));
    let error = run.complete(result).unwrap_err();
    if let Some(first) = first {
        assert!(error.retains_primary(&first), "{case:?}: {error:?}");
    }
    if execution_panic {
        assert!(matches!(error.primary(), Error::GuestWorkerPanic));
    } else if matches!(case, Case::ReturnedError) {
        assert!(
            matches!(error.primary(), Error::HostIo(error) if error.raw_os_error() == Some(libc::EIO))
        );
    }
    assert_eq!(panics.worker_execution_panicked(), execution_panic);
    assert_eq!(
        observed.hooks.load(Ordering::SeqCst),
        usize::from(!execution_panic)
    );
    assert_eq!(observed.state_drops.load(Ordering::SeqCst), 1);
    assert_eq!(observed.tool_drops.load(Ordering::SeqCst), 1);
    let retained = panics.take();
    assert_eq!(retained.len(), expected.len());
    for (actual, (address, drops)) in retained.iter().zip(&expected) {
        let actual = actual
            .downcast_ref::<Payload>()
            .expect("original payload type");
        assert_eq!(std::ptr::from_ref(actual) as usize, *address);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(retained);
    for (_, drops) in expected {
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn local_execution_panic_skips_only_its_own_hook_and_retains_child_cleanup() {
    for destructor_panics in [false, true] {
        check_worker(Case::Execution, destructor_panics);
    }
}

#[test]
fn returned_peer_transferred_and_exit_hook_failures_keep_consuming_hooks() {
    for case in [
        Case::ReturnedError,
        Case::PeerCancellation,
        Case::TransferredPanic,
        Case::ExitHookPanic,
    ] {
        check_worker(case, false);
    }
}
