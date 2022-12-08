/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This crate wraps raw `u64` syscall arguments in stronger Rust types. This
//! has a number of useful side effects:
//! 1. Syscalls and their arguments can be easily displayed for debugging
//!    purposes.
//! 2. When intercepting syscalls, the Rust type can be accessed more safely.
//! 3. When injecting syscalls, it is easier and clearer to set the arguments
//!    using the `with_*` builder methods.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg(target_os = "linux")]

#[macro_use]
mod macros;

mod args;
mod display;
mod raw;
mod syscalls;

// Re-export the only things that might be needed from the syscalls crate
pub use ::reverie_memory::*;
pub use ::syscalls::Errno;
pub use ::syscalls::SyscallArgs;
pub use ::syscalls::Sysno;

pub use crate::args::*;
pub use crate::display::*;
pub use crate::raw::*;
pub use crate::syscalls::*;
