/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This contains the RPC protocol for the guest and host. That is, how the host
//! and guest should talk to each other.

use serde::Deserialize;
use serde::Serialize;
use syscalls::Errno;

/// Configuration options that adjust the behavior of the tool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Only log syscalls that failed.
    pub only_failures: bool,

    /// Don't print anything.
    pub quiet: bool,
}

/// Our service definition. The request and response enums are derived from this
/// interface. This also derives the client implementation.
#[reverie_rpc::service]
pub trait MyService {
    /// Get the current configuration.
    fn config() -> Config;

    /// Increment the count of syscalls.
    #[rpc(no_response)]
    fn count(count: usize);

    #[rpc(no_response)]
    fn pretty_print(thread_id: u32, pretty: &str, result: Option<Result<usize, Errno>>);
}
