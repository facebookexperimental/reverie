/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Hermit's in-guest loader (dev-hermit
//! `ai_docs/2026-10-18-inguest-first-instruction-design.md`, stage 1a).
//!
//! The loader maps Hermit's runtime into a new process image at fixed
//! addresses and arms Detcore's controls before the image's first
//! instruction runs. This crate holds the parts that need no `unsafe`:
//!
//! - [`image`] validates a loader or runtime image against the narrow shape
//!   the loader accepts: a fixed-address `ET_EXEC` x86-64 image with no
//!   interpreter, no dynamic section (so no dynamic relocations), W^X,
//!   page-aligned non-overlapping segments inside an allowed window, and
//!   optionally no TLS.
//! - [`audit`] confines `syscall` instructions in an image's executable
//!   segments to declared gate ranges.
//! - [`artifact`] fixes where the loader and runtime images live and checks
//!   a built image (validation plus audit) before it may be mapped.
//! - [`stage`] names the loader's initialization stages as types, so a step
//!   can only follow the step before it.
//!
//! It is `no_std` so the loader itself can use it.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod artifact;
pub mod audit;
pub mod handoff;
pub mod image;
pub mod mapped_inputs;
pub mod musl_tls;
pub mod stage;
