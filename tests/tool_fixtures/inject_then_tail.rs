/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Displayable;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use tracing::warn;

#[derive(Debug, Default, Clone)]
pub struct TestTool {}

pub type Dupcount = u64;

#[reverie::global_tool]
impl GlobalTool for TestTool {
    type Request = ();
    type Response = ();
    type Config = Dupcount;

    async fn receive_rpc(&self, _from: Pid, _message: ()) {}
}

#[path = "inject_then_tail_constants.rs"]
mod constants;

pub use constants::RAND_SIZE;

/// How many times to DUPLICATE select system calls that are intercepted.
pub const NUM_REPS: Dupcount = 3;

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = TestTool;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        let reps = *guest.config();
        match call {
            Syscall::Gettid(_)
            | Syscall::Getgid(_)
            | Syscall::Getsid(_)
            | Syscall::Getppid(_)
            | Syscall::Getpgid(_)
            | Syscall::Getpid(_) => {
                for i in 1..=reps {
                    let syscall_ret = guest.inject(call).await;
                    warn!(
                        "[pid {}] Duplicated syscall ({}/{})! {} = {}",
                        guest.tid(),
                        i,
                        reps,
                        call.display_with_outputs(&guest.memory()),
                        syscall_ret.unwrap_or_else(|errno| errno.into_raw() as i64)
                    );
                }
            }
            Syscall::Getrandom(r) => {
                if r.buflen() < RAND_SIZE {
                    warn!(
                        "[pid {}] not touching getrandom, buflen too small.",
                        guest.tid()
                    );
                } else {
                    for i in 1..=reps {
                        let syscall_ret = guest.inject(call).await;
                        let bufaddr = r.buf().unwrap();
                        let mut buf: [u8; RAND_SIZE] = [0; RAND_SIZE];
                        guest.memory().read_exact(bufaddr, &mut buf).unwrap();
                        let rand_word: u64 = u64::from_le_bytes(buf);
                        warn!(
                            "[pid {}] Duplicated getrandom syscall ({}/{}): {}, returned {}, first word {}",
                            guest.tid(),
                            i,
                            reps,
                            call.display_with_outputs(&guest.memory()),
                            syscall_ret.unwrap_or_else(|errno| errno.into_raw() as i64),
                            rand_word
                        );
                    }
                }
            }
            _ => {}
        }
        // Irrespective of above, run a tail_inject at the end:
        guest.tail_inject(call).await
    }
}
