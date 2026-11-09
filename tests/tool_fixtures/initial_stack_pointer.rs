/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Original initial-stack memory reads, with typed returned observations instead
//! of the ptrace reference's process-local SEEN. The reference stays unchanged.

use std::sync::Mutex;

use reverie::Errno;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub pid: i32,
    pub tid: i32,
    pub reported: Option<u64>,
    pub rsp: u64,
    pub arguments: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Observations {
    seen: Mutex<Vec<(i32, Observation)>>,
}

impl Observations {
    pub fn into_seen(self) -> Vec<(i32, Observation)> {
        self.seen.into_inner().unwrap()
    }
}

#[reverie::global_tool]
impl GlobalTool for Observations {
    type Config = ();
    type Request = Observation;
    type Response = ();

    async fn receive_rpc(&self, from: Pid, observation: Observation) {
        assert_eq!(from.as_raw(), observation.tid, "actual RPC sender");
        assert_eq!(observation.tid, observation.pid, "initial process leader");
        let mut seen = self.seen.lock().unwrap();
        assert!(seen.is_empty(), "exactly one post-exec observation");
        seen.push((from.as_raw(), observation));
    }
}

#[derive(Debug, Default, Clone)]
pub struct StackTool;

fn read_string<T: Guest<StackTool>>(guest: &T, address: u64) -> Result<String, Errno> {
    let mut bytes = Vec::new();
    loop {
        let at = Addr::<u8>::from_raw(address as usize + bytes.len()).ok_or(Errno::EFAULT)?;
        let byte: u8 = guest.memory().read_value(at)?;
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
}

#[reverie::tool]
impl Tool for StackTool {
    type GlobalState = Observations;
    type ThreadState = ();

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        let reported = guest.initial_stack_pointer();
        let rsp = guest.regs().await.rsp;
        let mut arguments = Vec::new();
        if let Some(stack) = reported {
            let word = |at: u64| -> Result<u64, Errno> {
                guest
                    .memory()
                    .read_value(Addr::<u64>::from_raw(at as usize).ok_or(Errno::EFAULT)?)
            };
            let argc = word(stack)?;
            for index in 0..argc {
                arguments.push(read_string(guest, word(stack + 8 * (1 + index))?)?);
            }
            assert_eq!(word(stack + 8 * (1 + argc))?, 0, "argv ends with NULL");
        }
        guest
            .send_rpc(Observation {
                pid: guest.pid().as_raw(),
                tid: guest.tid().as_raw(),
                reported,
                rsp,
                arguments,
            })
            .await;
        Ok(())
    }
}
