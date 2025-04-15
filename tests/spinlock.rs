/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Tool;

#[derive(Debug, Default, Clone)]
struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = ();
    type ThreadState = ();
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time;

    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[test]
    fn run_guest_spinlock_test() {
        check_fn::<LocalState, _>(move || {
            let lock = Arc::new(AtomicUsize::new(0));
            let mut handles: Vec<_> = (0..10)
                .map(|_| {
                    let lock = lock.clone();
                    thread::spawn(move || while lock.load(Ordering::Acquire) != 10 {})
                })
                .collect();
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    lock.fetch_add(1, Ordering::Release);
                    let dur = time::Duration::from_millis(10);
                    thread::sleep(dur);
                }
            }));
            for h in handles {
                let _ = h.join();
            }
        });
    }
}
