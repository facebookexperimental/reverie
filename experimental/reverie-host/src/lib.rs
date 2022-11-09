/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This crate does two main things:
//!  * Handles launching the root child process.
//!  * Provides an interface for managing global state for in-guest backends.

mod codec;
mod server;
mod tracer;

pub use server::*;
pub use tracer::*;
