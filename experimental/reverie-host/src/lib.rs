/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This crate does two main things:
//!  * Handles launching the root child process.
//!  * Provides an interface for managing global state for in-guest backends,
//!    held by the launcher ([`run_with_global_state`]).

mod codec;
mod global_state;
mod server;
mod tracer;

pub use global_state::*;
pub use server::*;
pub use tracer::*;
