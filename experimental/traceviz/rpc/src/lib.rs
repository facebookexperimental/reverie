/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// reverie_rpc::service requires GATs.
#![feature(generic_associated_types)]

//! This contains the RPC protocol for the guest and host. That is, how the host
//! and guest should talk to each other.

use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;
use syscalls::Errno;
use syscalls::Sysno;

/// Our service definition. The request and response enums are derived from this
/// interface. This also derives the client implementation.
#[reverie_rpc::service]
pub trait MyService {
    #[rpc(no_response)]
    fn print(thread_id: usize, s: &str);

    fn send_syscall_event(syscall_event: SyscallEvent) -> u64;
}

/// Our RPC message struct. This contains information that will be sent from the
/// guest process to Global State. The message should be serializable (from the client)
/// and deserializable (once it reaches the server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub syscall_num: Sysno,
    pub process_id: i32,
    pub thread_id: i32,
    pub event_id: u64,
    pub parent_event_id: Option<u64>,
    pub syscall_start: SystemTime,
    pub syscall_end: SystemTime,
    pub syscall_result: Result<usize, Errno>,
    pub args: String,
}

impl Default for SyscallEvent {
    fn default() -> Self {
        Self {
            syscall_num: Sysno::read,
            process_id: 0,
            thread_id: 0,
            event_id: 0,
            parent_event_id: None,
            syscall_start: SystemTime::now(),
            syscall_end: SystemTime::now(),
            syscall_result: Ok(0),
            args: String::new(),
        }
    }
}
