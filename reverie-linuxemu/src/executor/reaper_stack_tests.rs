/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A run's reaper destroys whatever Tool state a dropped run left behind, and
//! a Tool destructor can be as deep as a Tool callback, so the reaper thread
//! needs a supervisor thread's stack even when `RUST_MIN_STACK` is unset.
//!
//! The test retains a cleanup future in the run's root executor, through the
//! same `retain_unstarted_tool_cleanup` a refused child spawn uses for the
//! child's Tool and thread state, and then drops the run. The root is parked,
//! retired to the run's reaper as a backend's drop retires it, and dropped on
//! the reaper thread. It runs in a re-executed copy of this test binary with
//! `RUST_MIN_STACK` removed, because a test runner may set that variable.

use std::sync::Arc;
use std::sync::Mutex;

use super::AbandonedRuns;
use super::ElfExecutor;
use super::RunAdmission;
use super::native_loaded_state;

const TEST: &str = concat!(
    "executor::reaper_stack_tests::",
    "a_dropped_runs_reaper_destroys_deep_tool_state_without_rust_min_stack"
);

/// Set in the re-executed child, which runs the dropped run.
const CHILD_ENV: &str = "REVERIE_LINUXEMU_REAPER_STACK_CHILD";

/// The stack the retained state's destructor uses: more than Rust's 2 MiB
/// default for a spawned thread, as a deep Tool destructor could.
const DEEP_DROP_STACK_BYTES: usize = 4 << 20;

/// Tool state whose destructor uses [`DEEP_DROP_STACK_BYTES`] of stack, and
/// records the name of the thread that dropped it.
struct DeepDrop(Arc<Mutex<Option<String>>>);

impl Drop for DeepDrop {
    fn drop(&mut self) {
        std::hint::black_box(use_stack(DEEP_DROP_STACK_BYTES));
        *self.0.lock().unwrap() =
            Some(std::thread::current().name().unwrap_or_default().to_owned());
    }
}

/// Uses `bytes` of stack through a chain of 64 KiB frames.
#[inline(never)]
fn use_stack(bytes: usize) -> u8 {
    const FRAME: usize = 64 * 1024;
    let mut frame = [0u8; FRAME];
    std::hint::black_box(&mut frame);
    let below = if bytes > FRAME {
        use_stack(bytes - FRAME)
    } else {
        0
    };
    std::hint::black_box(frame[usize::from(below) % FRAME]) ^ below
}

/// The child's half: drops a run whose root still retains deep Tool state, and
/// retires it as a backend's drop would.
fn drop_a_run_with_deep_tool_state() {
    let runs = Arc::new(Mutex::new(AbandonedRuns::default()));
    let admission = RunAdmission::begin(&runs).unwrap();
    let dropped_on = Arc::new(Mutex::new(None));
    {
        let mut root = admission.root(ElfExecutor::new(
            native_loaded_state(std::path::Path::new("/")),
            false,
        ));
        let state = DeepDrop(dropped_on.clone());
        root.retain_unstarted_tool_cleanup(Box::pin(async move {
            let _state = state;
            Ok::<(), crate::Error>(())
        }));
        // The run's future is dropped here, before it drained the cleanup.
    }
    assert_eq!(
        runs.lock().unwrap().roots.len(),
        1,
        "the dropped run did not park its root"
    );
    assert!(
        dropped_on.lock().unwrap().is_none(),
        "parking destroyed the retained state"
    );
    // A backend's drop retires the parked root to the run's reaper, which
    // drops it; this joins the reaper.
    admission.finish_fixture_cleanup();
    assert_eq!(
        dropped_on.lock().unwrap().as_deref(),
        Some("reverie-kvm-reaper"),
        "the reaper did not destroy the retained state"
    );
}

/// Removes the parent's libtest log directory, whatever the child did.
struct LogDirectory(std::path::PathBuf);

impl Drop for LogDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_dropped_runs_reaper_destroys_deep_tool_state_without_rust_min_stack() {
    if std::env::var_os(CHILD_ENV).is_some() {
        drop_a_run_with_deep_tool_state();
        return;
    }
    // libtest's log shows the child really ran this one test, and passed.
    let directory = LogDirectory(std::env::temp_dir().join(format!(
        "reverie-linuxemu-reaper-stack-{}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let log = directory.0.join("libtest.log");
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=5s", "60s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--logfile"])
        .arg(&log)
        .env(CHILD_ENV, "1")
        .env_remove("RUST_MIN_STACK")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child without RUST_MIN_STACK failed: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        format!("ok {TEST}\n"),
        "the child did not run exactly this test\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
