/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The synchronous starts of a syscall-return signal boundary, which the
//! ordinary return site runs without building the boundary's futures.

use std::sync::atomic::AtomicU64;

use super::*;

/// A Tool's global state that may let the backend skip empty boundaries and
/// that counts the authorizations it is asked for, declining each.
#[derive(Default)]
struct StartGlobal {
    skip: bool,
    authorized: AtomicU64,
}

impl StartGlobal {
    fn new(skip: bool) -> Self {
        Self {
            skip,
            authorized: AtomicU64::new(0),
        }
    }

    fn authorized(&self) -> u64 {
        self.authorized.load(Ordering::SeqCst)
    }
}

#[reverie::global_tool]
impl GlobalTool for StartGlobal {
    type Request = ();
    type Response = ();
    type Config = bool;

    async fn init_global_state(skip: &bool) -> Self {
        Self::new(*skip)
    }

    async fn receive_rpc(&self, _from: Pid, _: ()) {}

    fn skip_empty_signal_boundaries(&self) -> bool {
        self.skip
    }

    fn authorize_backend_signal_boundary(
        &self,
        _task: reverie::SignalTaskIdentity,
    ) -> std::result::Result<Option<reverie::SignalDeliveryPermit>, reverie::Error> {
        self.authorized.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

fn executor() -> ElfExecutor {
    ElfExecutor::new(
        crate::executor::native_loaded_state(&std::env::temp_dir()),
        true,
    )
}

fn control(executor: &ElfExecutor) -> Arc<crate::failure::RunFailure> {
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    executor.install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &run);
    run
}

/// The identity check runs before the skip, exactly as in the selection
/// future: a stale task generation is an error even at a boundary the Tool
/// would let the backend skip, and no Tool is asked.
#[test]
fn a_lost_task_generation_fails_before_the_skip() {
    for skip in [false, true] {
        let mut executor = executor();
        let _run = control(&executor);
        executor.lose_task_generation_for_test();
        assert!(executor.signal_controlled());
        assert_eq!(executor.delivery_permit(), None);
        assert_eq!(executor.signal_task_identity(), None);
        assert!(executor.signal_boundary_is_empty());
        let global = StartGlobal::new(skip);
        let result = signal_selection_start(&executor, &global);
        assert!(
            matches!(
                &result,
                Err(Error::UnexpectedVcpuExit(message))
                    if message == "signal return lost task generation"
            ),
            "{result:?}"
        );
        assert_eq!(global.authorized(), 0);
    }
}

/// Without backend signal control nothing is skipped or asked: selection
/// runs, as it did inside the future.
#[test]
fn an_uncontrolled_boundary_selects_without_asking() {
    let executor = executor();
    for skip in [false, true] {
        let global = StartGlobal::new(skip);
        assert_eq!(
            signal_selection_start(&executor, &global).unwrap(),
            SignalSelectionStart::Select
        );
        assert_eq!(global.authorized(), 0);
    }
}

/// A controlled empty boundary is skipped only for a Tool that opts in; a
/// Tool that keeps the default is asked and declines.
#[test]
fn a_controlled_empty_boundary_is_skipped_only_for_a_tool_that_opts_in() {
    let executor = executor();
    let _run = control(&executor);
    let skipping = StartGlobal::new(true);
    assert_eq!(
        signal_selection_start(&executor, &skipping).unwrap(),
        SignalSelectionStart::Skipped { mask_saved: false }
    );
    assert_eq!(skipping.authorized(), 0);
    let asking = StartGlobal::new(false);
    assert_eq!(
        signal_selection_start(&executor, &asking).unwrap(),
        SignalSelectionStart::Declined
    );
    assert_eq!(asking.authorized(), 1);
}

/// The receipt start checks for a recorded parent-death failure before it
/// reads the permit, so the failure is returned with and without a permit,
/// and with no failure it returns exactly the owned permit.
#[test]
fn the_receipt_start_returns_a_parent_death_failure_with_and_without_a_permit() {
    let executor = executor();
    let _run = control(&executor);
    let control = executor.backend_signal_control().process;
    assert!(matches!(
        signal_boundary_receipt_permit(&executor),
        Ok(None)
    ));
    let permit = reverie::SignalDeliveryPermit {
        task: executor.signal_task_identity().unwrap(),
        sequence: 1,
        site: None,
    };
    control.reserve_delivery(permit).unwrap();
    assert_eq!(executor.owned_delivery_permit(), Some(permit));
    assert!(matches!(
        signal_boundary_receipt_permit(&executor),
        Ok(Some(owned)) if owned == permit
    ));

    executor.retain_parent_death_error_for_test(Errno::EIO);
    let failed = |result: Result<Option<reverie::SignalDeliveryPermit>>| {
        matches!(
            result,
            Err(Error::ParentDeathSignal { errno, .. }) if errno == libc::EIO
        )
    };
    assert!(failed(signal_boundary_receipt_permit(&executor)));
    control.release_delivery(permit).unwrap();
    assert_eq!(executor.owned_delivery_permit(), None);
    assert!(failed(signal_boundary_receipt_permit(&executor)));
}
