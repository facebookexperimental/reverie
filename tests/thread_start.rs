/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(not(sanitized))]

use reverie::Error;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls;

#[test]
fn thread_start_inject() {
    #[derive(Debug, Default)]
    struct TestTool;

    #[reverie::tool]
    impl Tool for TestTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
            let ret = guest.inject(syscalls::Getpid::new()).await?;
            assert_eq!(Pid::from_raw(ret as i32), guest.pid());
            Ok(())
        }
    }

    reverie_ptrace::testing::check_fn::<TestTool, _>(|| {});
}

#[test]
fn thread_start_tail_inject() {
    #[derive(Debug, Default)]
    struct TestTool;

    #[reverie::tool]
    impl Tool for TestTool {
        type GlobalState = ();
        type ThreadState = ();

        async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
            guest.tail_inject(syscalls::Getpid::new()).await;
            unreachable!()
        }
    }

    reverie_ptrace::testing::check_fn::<TestTool, _>(|| {});
}
