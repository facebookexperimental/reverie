/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The on-the-wire request envelope.

use reverie::Tid;
use serde::Deserialize;
use serde::Serialize;

/// A request as it travels from a guest to the coordinator.
///
/// [`GlobalTool::receive_rpc`](reverie::GlobalTool::receive_rpc) needs to know
/// which thread a request came from. In the in-process backends that `from`
/// tid is supplied by the wrapper that holds the tid; across a socket we must
/// carry it explicitly in each frame. `Tid` already derives `Serialize` /
/// `Deserialize`, so it goes on the wire directly.
///
/// The response travels back bare (just `G::Response`): each connection has a
/// single request in flight, so there is nothing to correlate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope<Req> {
    /// The originating guest thread id.
    pub from: Tid,
    /// The tool-specific request payload (for Detcore this is
    /// `(DetTime, GlobalRequest)`).
    pub request: Req,
}
