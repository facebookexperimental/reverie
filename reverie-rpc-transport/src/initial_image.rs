/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Explicit InitialImage redemption before the configuration handshake.
//!
//! This module supplies framing and ordering, not an authorization policy.
//! The launcher must validate and permanently consume its coordinator-held
//! one-use launch authorization against the already watched process birth.
//! Request bytes, tokens and file seals are never authority by themselves.

use std::io;
use std::os::fd::OwnedFd;

use sha2::Digest;
use sha2::Sha256;

use crate::Admitted;
pub use crate::InitialImageClient;
use crate::RpcError;

/// SHA-256 of the exact canonical `codec::encode` configuration bytes.
pub type ConfigDigest = [u8; 32];
/// Upper bound for either pre-configuration protocol frame.
pub const MAX_FRAME_LEN: usize = 4096;
/// Upper bound for launcher-defined redemption data, excluding the header.
pub const MAX_REDEMPTION_LEN: usize = 256;
/// InitialImage request magic, followed by a big-endian u16 version.
pub const REQUEST_MAGIC: [u8; 8] = *b"RVINITRQ";
/// InitialImage acknowledgement magic, followed by a big-endian u16 version.
pub const ACK_MAGIC: [u8; 8] = *b"RVINITAK";
/// Only this version is accepted; no automatic protocol fallback occurs.
pub const VERSION: u16 = 1;
const HEADER_LEN: usize = 10;

/// Launcher-owned redemption on a connection already admitted and watched.
///
/// The pidfd is obtained from the same accepted socket as the watcher's pidfd.
/// `admitted` is the watcher's result, not a guest claim. An implementation must
/// bind these to its immutable launch instance and consume authorization once,
/// retaining consumed state even if the socket subsequently disconnects.
/// Return an error on every mismatch; successful transport does not establish
/// that an implementation meets those policy obligations.
pub trait InitialImageAdmission: Send + Sync {
    /// Consume authorization before any acknowledgement or config is sent.
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        redemption: &[u8],
        config_digest: ConfigDigest,
    ) -> io::Result<()>;
}

/// Hash exact configuration bytes before any client deserialization.
pub fn config_digest(bytes: &[u8]) -> ConfigDigest {
    Sha256::digest(bytes).into()
}

/// Encode bounded launcher data without invoking guest deserialization.
pub fn encode_redemption(redemption: &[u8]) -> Result<Vec<u8>, RpcError> {
    if redemption.is_empty() || redemption.len() > MAX_REDEMPTION_LEN {
        return Err(invalid("InitialImage redemption length is invalid"));
    }
    let mut bytes = Vec::with_capacity(HEADER_LEN + redemption.len());
    bytes.extend_from_slice(&REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(redemption);
    Ok(bytes)
}

pub(crate) fn decode_redemption(bytes: &[u8]) -> Result<&[u8], RpcError> {
    check_header(bytes, &REQUEST_MAGIC)?;
    let redemption = &bytes[HEADER_LEN..];
    if redemption.is_empty() || redemption.len() > MAX_REDEMPTION_LEN {
        return Err(invalid("InitialImage redemption length is invalid"));
    }
    Ok(redemption)
}

pub(crate) fn encode_ack(digest: ConfigDigest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + digest.len());
    bytes.extend_from_slice(&ACK_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes
}

pub(crate) fn check_ack(bytes: &[u8], expected: ConfigDigest) -> Result<(), RpcError> {
    check_header(bytes, &ACK_MAGIC)?;
    if bytes.len() != HEADER_LEN + expected.len() || bytes[HEADER_LEN..] != expected {
        return Err(invalid(
            "InitialImage acknowledgement config digest mismatch",
        ));
    }
    Ok(())
}

fn check_header(bytes: &[u8], magic: &[u8; 8]) -> Result<(), RpcError> {
    if bytes.len() < HEADER_LEN
        || bytes[..8] != *magic
        || bytes[8..HEADER_LEN] != VERSION.to_be_bytes()
    {
        return Err(invalid("InitialImage magic or version mismatch"));
    }
    Ok(())
}

pub(crate) fn invalid(message: &'static str) -> RpcError {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
