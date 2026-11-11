/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie's in-guest loader (stage 1a).
//!
//! The loader maps a Reverie tool runtime into a new process image at
//! fixed addresses and arms the tool's controls before the image's first
//! instruction runs. This crate holds the parts that need no `unsafe`:
//!
//! - [`manifest`] is what a tool provides, as data only: its runtime
//!   image's policy, its declared syscall gate ranges, the controls it
//!   asks the loader to arm, and its init contract. It names no product.
//! - [`image`] validates a loader or runtime image against the narrow shape
//!   the loader accepts: a fixed-address `ET_EXEC` x86-64 image with no
//!   interpreter, no dynamic section (so no dynamic relocations), W^X,
//!   page-aligned non-overlapping segments inside an allowed window, and
//!   optionally no TLS.
//! - [`audit`] confines `syscall` instructions in an image's executable
//!   segments to declared gate ranges.
//! - [`artifact`] fixes where the loader and runtime images live and checks
//!   a built image (validation plus audit) before it may be mapped,
//!   against a manifest via [`artifact::check_image`] or through the
//!   fixed loader/runtime wrappers.
//! - [`stage`] names the loader's initialization stages as types that
//!   carry the stopped task, so a launcher can only take each step
//!   after the one before it.
//!
//! Isolation obligations (G5): tool windows live inside
//! [`artifact::TOOL_REGION`] and guest mappings there are refused by
//! the in-guest runtime, but hiding tool pages and descriptors from
//! `/proc` and probing is a tool obligation the loader cannot itself
//! discharge. ToolRegion protection is a cooperative-guest boundary,
//! not automatically a hostile-code sandbox.
//!
//! It is `no_std` so the loader itself can use it.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod artifact;
pub mod audit;
pub mod handoff;
pub mod image;
pub mod init_packet;
pub mod manifest;
pub mod mapped_inputs;
pub mod musl_tls;
pub mod stage;

pub use manifest::Control;
pub use manifest::Controls;
pub use manifest::GateRange;
pub use manifest::ImageSpec;
pub use manifest::InitContract;
pub use manifest::InitRefusal;
pub use manifest::ManifestError;
pub use manifest::ToolManifest;
