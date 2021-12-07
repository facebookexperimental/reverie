/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests for getting backtraces from the guest.

#![cfg(not(sanitized))]

use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::ExitStatus;
use reverie::Guest;
use reverie::Tool;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct TestTool;

#[reverie::tool]
impl Tool for TestTool {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::Getpid(_) = &syscall {
            let frames = guest
                .backtrace()
                .expect("failed to get backtrace from guest");

            assert!(frames.len() > 0);

            // There's no guarantee our function is at the top of the stack, so
            // we simply assert that it is *somewhere* in the stack.
            assert!(
                frames.iter().any(|frame| {
                    if let Some(symbol) = &frame.symbol {
                        // Due to name mangling, there won't be an exact match.
                        symbol.name.contains("funky_function")
                    } else {
                        false
                    }
                }),
                "guest backtrace did not contain our expected function:\n{:#?}",
                frames
            );
        }

        Ok(guest.inject(syscall).await?)
    }
}

#[inline(never)]
fn funky_function() {
    let _ = unsafe { libc::getpid() };
}

#[test]
fn smoke() {
    use reverie_ptrace::testing::test_fn;

    let (output, _) = test_fn::<TestTool, _>(funky_function).unwrap();

    assert_eq!(output.status, ExitStatus::Exited(0));
}
