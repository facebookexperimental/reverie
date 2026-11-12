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
    assert!(
        frame
            .retain_spawn(ExecStop::spawn(true_request(), receipt.clone()))
            .is_ok()
    );
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
    assert!(
        first
            .retain_spawn(ExecStop::spawn(true_request(), receipt.clone()))
            .is_ok()
    );
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
    // A frame retains only a capability of its own receipt, so the refusal is
    // held by a frame on the same shared receipt.
    let mut refused = RetainedPhysical::empty(receipt.clone());
    assert!(refused.retain_spawn(Err(failure)).is_ok());
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
    assert!(
        frame
            .retain_spawn(ExecStop::spawn(true_request(), receipt.clone()))
            .is_ok()
    );
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

/// Re-exec marker: `cleanup_all_retires_two_real_frames_and_returns` runs its
/// body in a fresh exact-test process, in its own process group.
const CLEANUP_COMPONENT: &str = "REVERIE_MAPPED_LAUNCH_CLEANUP_COMPONENT";
const CLEANUP_COMPLETE: &[u8] = b"mapped-launch-cleanup-all-complete";

#[test]
#[allow(unsafe_code, unused_unsafe)]
fn cleanup_all_retires_two_real_frames_and_returns() {
    // cleanup_all never returns if a retirement can neither confirm nor
    // retain, and its contract requires whole-subtree containment. The body
    // therefore runs in a re-exec'd exact-test process in its own process
    // group: the stops are its children (ExecStop never changes their process
    // group, and each is traced with PTRACE_O_EXITKILL), so killing the group
    // ends the whole subtree. On the bound that group is killed and reaped and
    // the test fails.
    if std::env::var_os(CLEANUP_COMPONENT).is_none() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "launcher::exec_stop::mapped_launch::retention_tests::\
                 cleanup_all_retires_two_real_frames_and_returns",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CLEANUP_COMPONENT, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let out = loop {
            if child.try_wait().unwrap().is_some() {
                break child.wait_with_output().unwrap();
            }
            if std::time::Instant::now() >= deadline {
                // pgid == child pid under process_group(0).
                // SAFETY: plain kill(2) of the group this test created.
                unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                let pgid = child.id();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "HANG: cleanup_all did not return within 60 s; killed process group {pgid}: \
                     {}; stdout={}; stderr={}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            out.status.success(),
            "isolated cleanup failed: {}; stdout={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout
                .windows(CLEANUP_COMPLETE.len())
                .filter(|item| *item == CLEANUP_COMPLETE)
                .count(),
            1,
            "exact-test child must print the completion marker exactly once: stdout={}",
            String::from_utf8_lossy(&out.stdout)
        );
        return;
    }
    let first_receipt = CleanupReceipt::default();
    let second_receipt = CleanupReceipt::default();
    let mut first = RetainedPhysical::empty(first_receipt.clone());
    let mut second = RetainedPhysical::empty(second_receipt.clone());
    assert!(
        first
            .retain_spawn(ExecStop::spawn(true_request(), first_receipt.clone()))
            .is_ok()
    );
    assert!(
        second
            .retain_spawn(ExecStop::spawn(true_request(), second_receipt.clone()))
            .is_ok()
    );
    let mut payload = None;
    // SAFETY: the parent test bounds this whole process group and kills it
    // on the bound; the frames hold only /bin/true stops this thread spawned.
    unsafe { cleanup_all(&mut first, &mut second, &mut payload) };
    assert_eq!(
        (
            first_receipt.snapshot().confirmed,
            second_receipt.snapshot().confirmed,
            first.has_cleanup_capability(),
            second.has_cleanup_capability(),
            payload.is_none(),
        ),
        (true, true, false, false, true)
    );
    println!("{}", String::from_utf8_lossy(CLEANUP_COMPLETE));
}

#[test]
fn a_spawn_with_another_receipt_is_handed_back_unretained() {
    let receipt = CleanupReceipt::default();
    let mut frame = RetainedPhysical::empty(receipt.clone());
    let other = CleanupReceipt::default();
    let stop = match frame.retain_spawn(ExecStop::spawn(true_request(), other.clone())) {
        Ok(()) => panic!("a stop spawned with another receipt must be handed back"),
        Err(handed_back) => match *handed_back {
            Ok(stop) => stop,
            Err(failure) => panic!("the launch itself failed: {failure}"),
        },
    };
    assert!(!frame.has_cleanup_capability());
    assert!(!receipt.snapshot().child_created);
    // The caller still holds the actual stop and retires it through its owner.
    assert!(stop.cancel().is_ok());
    assert!(other.snapshot().confirmed);
    // A launch failure of another receipt is handed back the same way.
    match frame.retain_spawn(ExecStop::spawn(true_request(), other.clone())) {
        Ok(()) => panic!("a refusal of another receipt must be handed back"),
        Err(handed_back) => match *handed_back {
            Err(failure) => assert_eq!(
                failure.error.to_string(),
                "exec-stop cleanup receipt already used"
            ),
            Ok(_) => panic!("a used receipt cannot launch"),
        },
    }
    assert!(!frame.has_cleanup_capability());
    assert!(!receipt.snapshot().child_created);
}

#[test]
fn a_retained_launch_failure_is_never_overwritten() {
    let receipt = CleanupReceipt::default();
    let mut frame = RetainedPhysical::empty(receipt.clone());
    assert!(
        frame
            .retain_spawn(ExecStop::spawn(true_request(), receipt.clone()))
            .is_ok()
    );
    // The used receipt refuses again: the first refusal is retained, and the
    // second is handed back rather than replacing it.
    assert!(
        frame
            .retain_spawn(ExecStop::spawn(true_request(), receipt.clone()))
            .is_ok()
    );
    match frame.retain_spawn(ExecStop::spawn(true_request(), receipt.clone())) {
        Ok(()) => panic!("an occupied launch-failure slot must not be overwritten"),
        Err(handed_back) => match *handed_back {
            Err(failure) => assert_eq!(
                failure.error.to_string(),
                "exec-stop cleanup receipt already used"
            ),
            Ok(_) => panic!("a used receipt cannot launch"),
        },
    }
    frame.retire_once();
    assert!(receipt.snapshot().confirmed);
    // The retained refusal is never released by retirement.
    assert!(frame.has_cleanup_capability());
}

#[test]
fn a_real_frames_retirement_step_completes_once_its_reap_is_confirmed() {
    let receipt = CleanupReceipt::default();
    let mut frame = RetainedPhysical::empty(receipt.clone());
    assert!(
        frame
            .retain_spawn(ExecStop::spawn(true_request(), receipt.clone()))
            .is_ok()
    );
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
