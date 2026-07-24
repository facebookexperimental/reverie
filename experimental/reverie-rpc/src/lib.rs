/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This crate provides the protocol that is to be used when communicating with
//! global state. This crate is meant to be shared between the guest and host
//! processes.
//!
//! The RPC protocol is simply a mapping between a Request and Response. That
//! is, for each item in the Request enum, there is a corresponding item in the
//! Response enum.

mod channel;
mod codec;
mod service;

#[doc(hidden)]
pub use async_trait;
pub use channel::*;
pub use codec::*;
pub use reverie_rpc_macros::service;
#[doc(hidden)]
pub use serde;
pub use service::*;
