/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![feature(ffi_returns_twice)]

//! This library provides an ergonomic interface writing SaBRe plugins with
//! Rust.

mod callbacks;
pub mod ffi;
#[doc(hidden)]
pub mod internal;
mod paths;
mod protected_files;
mod rpc;
mod signal;
mod slot_map;
mod thread;
mod tool;
mod utils;
pub mod vdso;

pub use nostd_print::*;
pub use paths::*;
pub use reverie_sabre_macros::tool;
pub use tool::*;

// Tracing programs that use jemalloc will hang if we allocate when jemalloc
// calls readlinkat. Using a different allocator works around this problem.
//
// NOTE: Even though we set the global allocator here, anything that depends on
// this library will use this global allocator. Thus, it will apply to all
// tools/plugins automatically.
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;
