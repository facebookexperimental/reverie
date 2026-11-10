// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Characterization of the retention frame and its retirement helpers, as
//! they behave before they move into Reverie unchanged. The bodies below
//! use only what is the same on both sides of that move: the frame's
//! methods, never its fields. After the move the same bodies must pass
//! there, and only the `use` lines may differ.

use std::fs::File;
use std::os::fd::AsFd;

use crate::launcher::exec_stop::CleanupReceipt;
use crate::launcher::exec_stop::ExecStop;
use crate::launcher::exec_stop::PreparedExec;
use crate::launcher::exec_stop::physical::Preparation;
use reverie_loader::handoff::Extent;

use super::RetainedPhysical;
use super::RetirementStep;
use super::cleanup_all;
use super::guarded_retirement;
use super::retain_unwind;

fn true_request<'fd>() -> PreparedExec<'fd> {
    PreparedExec::new(
        std::path::Path::new("/bin/true"),
        &["retention".into()],
        &[],
        None,
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn an_empty_frame_holds_no_capability_and_names_each_absence() {
    let mut frame = RetainedPhysical::empty(CleanupReceipt::default());
    assert!(!frame.has_cleanup_capability());
    assert_eq!(
        frame.initial().err().map(|error| error.to_string()),
        Some("actual initial stop absent".to_owned())
    );
    assert_eq!(
        frame.mapped().err().map(|error| error.to_string()),
        Some("actual prepared mapping absent".to_owned())
    );
    frame.retire_once();
    assert!(!frame.has_cleanup_capability());
}

#[test]
#[allow(unsafe_code)]
fn preparing_without_an_initial_stop_refuses_by_name() {
    let null = File::open("/dev/null").unwrap();
    let mut frame = RetainedPhysical::empty(CleanupReceipt::default());
    // SAFETY: the frame holds no initial stop, so prepare refuses before it
    // reads any input; no child exists.
    let refused = unsafe {
        frame.prepare(Preparation {
            runtime_fd: null.as_fd(),
            runtime_bytes: b"",
            layout_address: 0,
            handoff_fd: null.as_fd(),
            handoff_bytes: b"",
            handoff_address: 0,
            input_fd: null.as_fd(),
            free_band: Extent { start: 0, end: 0 },
            filter_scratch: 0,
        })
    };
    assert_eq!(
        refused.err().map(|error| error.to_string()),
        Some("actual initial stop absent".to_owned())
    );
    assert!(!frame.has_cleanup_capability());
}

#[test]
fn a_real_initial_stop_is_retained_then_retired_once_with_its_reap_confirmed() {
    let receipt = CleanupReceipt::default();
    let mut frame = RetainedPhysical::empty(receipt.clone());
    frame.retain_spawn(ExecStop::spawn(true_request(), receipt.clone()));
    assert!(frame.initial().is_ok());
    assert!(frame.has_cleanup_capability());
    assert_eq!(
        frame.mapped().err().map(|error| error.to_string()),
        Some("actual prepared mapping absent".to_owned())
    );
    let state = receipt.snapshot();
    assert!(state.child_created);
    assert!(!state.confirmed);

    frame.retire_once();
    let state = receipt.snapshot();
    assert!(state.confirmed);
    assert!(!frame.has_cleanup_capability());
    assert_eq!(
        frame.initial().err().map(|error| error.to_string()),
        Some("actual initial stop absent".to_owned())
    );
    // A second retirement finds nothing left to retire.
    frame.retire_once();
    assert!(!frame.has_cleanup_capability());
    assert!(receipt.snapshot().confirmed);
}

#[test]
fn a_launch_failure_is_retained_named_and_never_released_by_retirement() {
    let receipt = CleanupReceipt::default();
    let mut first = RetainedPhysical::empty(receipt.clone());
    first.retain_spawn(ExecStop::spawn(true_request(), receipt.clone()));
    assert!(first.initial().is_ok());

    // The same receipt cannot launch twice: a real LaunchFailure.
    let failure = match ExecStop::spawn(true_request(), receipt.clone()) {
        Ok(_) => panic!("a used receipt must refuse the launch"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.error.to_string(),
        "exec-stop cleanup receipt already used"
    );
    let mut refused = RetainedPhysical::empty(CleanupReceipt::default());
    refused.retain_spawn(Err(failure));
    assert!(refused.has_cleanup_capability());
    // The whole message, literally: the prefix, then the retained failure's
    // Debug form, which carries the shared receipt's snapshot (the first stop
    // is alive, so created and not confirmed).
    assert_eq!(
        refused.initial().err().map(|error| error.to_string()),
        Some(
            "actual launch refused: LaunchFailure { error: \"exec-stop cleanup receipt \
             already used\", cleanup: CleanupState { child_created: true, owner: Ptracer, \
             confirmed: false, confirmation: None, kill_requested: false, kill_errno: None, \
             wait_error: None, terminal_status: None, child_detach_error: None } }"
                .to_owned()
        )
    );
    assert_eq!(
        refused.mapped().err().map(|error| error.to_string()),
        Some("actual prepared mapping absent".to_owned())
    );
    refused.retire_once();
    assert!(refused.has_cleanup_capability());

    first.retire_once();
    assert!(receipt.snapshot().confirmed);
    assert!(!first.has_cleanup_capability());
}

#[test]
#[allow(unsafe_code)]
fn a_refused_preparation_is_retained_named_and_never_released_by_retirement() {
    let null = File::open("/dev/null").unwrap();
    let receipt = CleanupReceipt::default();
    let mut frame = RetainedPhysical::empty(receipt.clone());
    // No inherited descriptors, so the real stop refuses the preparation.
    frame.retain_spawn(ExecStop::spawn(true_request(), receipt.clone()));
    assert!(frame.initial().is_ok());
    // SAFETY: original ptracer thread; the descriptors are not the stop's
    // inherited ones, so the preparation refuses before mapping anything and
    // retires the child.
    let refused = unsafe {
        frame.prepare(Preparation {
            runtime_fd: null.as_fd(),
            runtime_bytes: b"",
            layout_address: 0,
            handoff_fd: null.as_fd(),
            handoff_bytes: b"",
            handoff_address: 0,
            input_fd: null.as_fd(),
            free_band: Extent { start: 0, end: 0 },
            filter_scratch: 0,
        })
    };
    assert_eq!(
        refused.err().map(|error| error.to_string()),
        Some("actual mapping refused: mapped_preparation_descriptor_not_inherited".to_owned())
    );
    assert!(receipt.snapshot().confirmed);
    assert!(frame.has_cleanup_capability());
    assert_eq!(
        frame.initial().err().map(|error| error.to_string()),
        Some("actual initial stop absent".to_owned())
    );
    assert_eq!(
        frame.mapped().err().map(|error| error.to_string()),
        Some("actual prepared mapping absent".to_owned())
    );
    frame.retire_once();
    assert!(frame.has_cleanup_capability());
    assert!(receipt.snapshot().confirmed);
}

#[test]
#[allow(unsafe_code, unused_unsafe)]
fn cleanup_all_retires_two_real_frames_and_returns() {
    // cleanup_all never returns if a retirement can neither confirm nor
    // retain; run it on its own thread (which also owns the stops, as their
    // ptracer) so a hang is reported as one, not as a stuck test.
    let (done, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let first_receipt = CleanupReceipt::default();
        let second_receipt = CleanupReceipt::default();
        let mut first = RetainedPhysical::empty(first_receipt.clone());
        let mut second = RetainedPhysical::empty(second_receipt.clone());
        first.retain_spawn(ExecStop::spawn(true_request(), first_receipt.clone()));
        second.retain_spawn(ExecStop::spawn(true_request(), second_receipt.clone()));
        let mut payload = None;
        // SAFETY: test containment: the frames hold only /bin/true stops that
        // this thread spawned and retires.
        unsafe { cleanup_all(&mut first, &mut second, &mut payload) };
        let _ = done.send((
            first_receipt.snapshot().confirmed,
            second_receipt.snapshot().confirmed,
            first.has_cleanup_capability(),
            second.has_cleanup_capability(),
            payload.is_none(),
        ));
    });
    match outcome.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(state) => assert_eq!(state, (true, true, false, false, true)),
        Err(_) => panic!("HANG: cleanup_all did not return within 60 s"),
    }
}

#[test]
fn a_real_frames_retirement_step_completes_once_its_reap_is_confirmed() {
    let receipt = CleanupReceipt::default();
    let mut frame = RetainedPhysical::empty(receipt.clone());
    frame.retain_spawn(ExecStop::spawn(true_request(), receipt.clone()));
    let mut first = None;
    let step = guarded_retirement(
        &mut frame,
        &mut first,
        |root| root.retire_once(),
        |root| {
            let state = receipt.snapshot();
            (
                state.child_created,
                state.confirmed,
                root.has_cleanup_capability(),
            )
        },
    );
    assert_eq!(step, RetirementStep::Complete);
    assert!(first.is_none());
    assert!(receipt.snapshot().confirmed);
    assert!(!frame.has_cleanup_capability());
}

#[test]
fn retain_unwind_returns_the_value_and_keeps_only_the_first_payload() {
    let mut first = None;
    assert_eq!(retain_unwind(&mut first, || 7), Some(7));
    assert!(first.is_none());
    assert_eq!(
        retain_unwind(&mut first, || -> u32 { std::panic::panic_any("first") }),
        None
    );
    assert_eq!(
        retain_unwind(&mut first, || -> u32 { std::panic::panic_any("second") }),
        None
    );
    assert_eq!(retain_unwind(&mut first, || 8), Some(8));
    let payload = first.expect("the first payload is retained");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"first"));
}
