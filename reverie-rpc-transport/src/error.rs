/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Error type shared by the codec, server, and client.

use std::io;

/// Errors that can occur while framing, transporting, or (de)serializing an
/// RPC message.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// The peer closed the connection cleanly at a frame boundary. Callers
    /// distinguish this from an unexpected mid-frame EOF so a server accept
    /// loop can treat it as a normal disconnect.
    #[error("peer closed the connection")]
    Closed,

    /// An underlying I/O error on the socket.
    #[error("rpc i/o error: {0}")]
    Io(#[from] io::Error),

    /// A frame declared a payload larger than the configured maximum. This
    /// guards against a corrupt or hostile length prefix causing an unbounded
    /// allocation.
    #[error("rpc frame too large: {len} bytes exceeds maximum of {max} bytes")]
    FrameTooLarge {
        /// The declared length in the frame header.
        len: usize,
        /// The configured maximum frame size.
        max: usize,
    },

    /// bincode failed to serialize a value.
    #[error("rpc encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    /// bincode failed to deserialize a value.
    #[error("rpc decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}
