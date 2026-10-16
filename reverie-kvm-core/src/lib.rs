/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The lowest layer of Reverie's KVM backend: the backend's error type
//! ([`Error`]) and the fixed guest address map ([`layout`]).
//!
//! Step U6b-1 of the provider seam
//! (<https://github.com/rrnewton/hermit/issues/4485>, epic
//! <https://github.com/rrnewton/hermit/issues/4492>) moved these out of
//! reverie-kvm unchanged. The guest arena and the Linux syscall emulator will
//! move below reverie-kvm in later steps; both need this error type and
//! address map, so they come first. It is an internal building block of
//! reverie-kvm, which re-exports [`Error`] unchanged; it is not part of
//! Reverie's `Tool`, `Guest` or backend contract.

#![cfg(target_arch = "x86_64")]

pub mod error;
pub mod layout;

pub use error::Error;
