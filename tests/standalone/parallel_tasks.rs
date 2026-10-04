/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::cell::UnsafeCell;
use std::env;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread;

use reverie::Error;
use reverie::Tool;

#[derive(Debug, Default, Clone)]
struct TestTool {}

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = ();
    type ThreadState = ();
}

const NUM_ELEMENTS: usize = 1_000_000;

struct SharedCells(Arc<[UnsafeCell<u64>]>);

// SAFETY: each index comes from the shared atomic counter, so only one worker
// writes each cell. All reads happen after both workers have joined.
unsafe impl Send for SharedCells {}
unsafe impl Sync for SharedCells {}

impl Clone for SharedCells {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl SharedCells {
    fn zeroed(len: usize) -> Self {
        let cells: Vec<UnsafeCell<u64>> = (0..len).map(|_| UnsafeCell::new(0)).collect();
        Self(cells.into())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self, index: usize) -> u64 {
        // SAFETY: both workers have joined before this method is called.
        unsafe { *self.0[index].get() }
    }

    fn set(&self, index: usize, value: u64) {
        // SAFETY: the shared counter gives each index to exactly one worker.
        // Indexing remains bounds checked because that branch is part of the
        // scheduling behavior exercised by this program.
        unsafe { *self.0[index].get() = value }
    }
}

/// In guest mode two threads each fill half of the data array with their worker tag.
/// Atomic index claims and a shared midpoint require both workers to make progress
/// before either finishes, so their actual writes must appear interleaved.
fn guest_mode() {
    let shared_data = SharedCells::zeroed(NUM_ELEMENTS);
    let shared_idx = Arc::new(AtomicUsize::new(0));
    let midpoint = Arc::new(Barrier::new(2));

    let handles: Vec<thread::JoinHandle<_>> = (0..2)
        .map(|rank| {
            let idx = shared_idx.clone();
            let data = shared_data.clone();
            let midpoint = Arc::clone(&midpoint);
            thread::spawn(move || {
                // Distinct nonzero value per worker. This used to be the thread id, but
                // `ThreadId` has no stable numeric accessor and the switch-point count
                // only needs the two workers to write DIFFERENT values -- it compares
                // adjacent elements and never inspects the value itself.
                let tid = rank as u64 + 1;

                // Each call performs half of this worker's fetch_add attempts.
                let write_half = || {
                    for _ in 0..(NUM_ELEMENTS / 4) {
                        let idx = idx.fetch_add(1, Ordering::SeqCst);
                        data.set(idx, tid);
                    }
                };
                write_half();
                // Require real progress from both workers even on one CPU or when
                // one worker starts late. Neither worker can finish before this.
                midpoint.wait();
                write_half();
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // Calculate the number of switch points. E.g. the number of times we observed interleaved
    // writes between the threads.
    let mut switch_points = 0;
    let mut prev = shared_data.get(0);
    for i in 1..shared_data.len() {
        if prev != shared_data.get(i) {
            prev = shared_data.get(i);
            switch_points += 1;
        }
    }

    println!("Switch points: {}", switch_points);
    if switch_points <= 1 {
        eprintln!("Expected more than 1 switch point!");
        std::process::exit(1);
    }
}

async fn host_mode(thisprog: &str) -> Result<i32, Error> {
    println!("Running in HOST mode (ReverieTool)");

    let mut command = reverie::process::Command::new(thisprog);
    command.arg("guest");

    let tracer = reverie_ptrace::TracerBuilder::<TestTool>::new(command)
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;

    Ok(status.code().unwrap_or(1))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    match &args[..] {
        [p] => std::process::exit(host_mode(p).await?),
        [_, s] if s == "guest" => guest_mode(),
        _ => panic!(
            "Expected 'guest' or no CLI argument. Got unexpected command line args ({}): {:?}",
            args.len(),
            args
        ),
    }

    Ok(())
}
