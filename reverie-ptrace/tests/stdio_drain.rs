/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Regression coverage for stdio draining on the discard-output wait path.
//!
//! `Tracer::wait` deliberately never touches the guest's pipes, so a caller
//! that pipes stdout/stderr and then waits without reading them deadlocks as
//! soon as the guest fills the pipe buffer. `Tracer::wait_discarding_output`
//! is the drain-and-discard wait such callers must use; this test observes the
//! drain against a guest that writes far more than one pipe buffer.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use reverie::ExitStatus;
use reverie_ptrace::spawn_fn_with_config;
use reverie_ptrace::testing::run_tokio_test;

/// Chunk size and count for the guest's output burst. 128 * 16 KiB = 2 MiB per
/// stream, far above the 64 KiB default pipe capacity, so an undrained pipe is
/// guaranteed to block the guest in `write(2)` rather than merely being racy.
const CHUNK_BYTES: usize = 16 * 1024;
const CHUNK_COUNT: usize = 128;

/// Bound on the whole spawn+wait. A drained run finishes in well under a
/// second; the undrained regression never finishes at all, so the timeout is
/// what turns a hang into a reported failure.
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Guest body: write `CHUNK_COUNT * CHUNK_BYTES` bytes to each of stdout and
/// stderr, interleaved so neither stream can be drained only after the other
/// has completed.
fn write_burst() {
    use std::io::Write;

    let chunk = vec![b'x'; CHUNK_BYTES];
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    for _ in 0..CHUNK_COUNT {
        stdout.write_all(&chunk).expect("guest stdout write failed");
        stderr.write_all(&chunk).expect("guest stderr write failed");
    }
    stdout.flush().expect("guest stdout flush failed");
    stderr.flush().expect("guest stderr flush failed");
}

#[test]
fn wait_discarding_output_drains_piped_stdio() {
    // The guest is forked by `spawn_fn_with_config`, and a regression leaves it
    // blocked in `write(2)` forever, so the wait runs on its own thread and the
    // assertion is made against a bounded `recv_timeout`. Reporting the hang as
    // a failure is the point: a bare `#[test]` body would simply never return.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = run_tokio_test(async move {
            // The unit tool `()` subscribes to no syscalls, so this exercises
            // the wait/drain path itself with no interception in the way.
            // `capture_output = true` pipes both guest streams into the tracer,
            // which is the precondition the drain exists for.
            let tracer = spawn_fn_with_config::<(), _>(write_burst, (), true).await?;
            tracer.wait_discarding_output().await
        });
        // A closed receiver means the test already timed out and failed.
        let _ = tx.send(result.map(|(status, ())| status));
    });

    match rx.recv_timeout(WAIT_TIMEOUT) {
        Ok(Ok(status)) => assert_eq!(status, ExitStatus::Exited(0)),
        Ok(Err(error)) => panic!("tracer failed: {error}"),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "wait_discarding_output did not return within {WAIT_TIMEOUT:?}: the guest wrote \
             {} bytes to each of stdout and stderr and the pipes were not drained",
            CHUNK_BYTES * CHUNK_COUNT
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("tracer thread panicked"),
    }
}
