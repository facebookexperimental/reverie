/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `io_uring` struct definitions.
//!
//! See also `<linux/io_uring.h>`.

use serde::Deserialize;
use serde::Serialize;

/// `io_uring_params`
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[allow(missing_docs)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}

/// `io_sqring_offsets`
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[allow(missing_docs)]
pub struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv: [u32; 3],
}

/// `io_cqring_offsets`
#[derive(Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Debug)]
#[allow(missing_docs)]
pub struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv: [u32; 3],
}
