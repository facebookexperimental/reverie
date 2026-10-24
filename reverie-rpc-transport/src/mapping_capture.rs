/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One pre-park authorization exchange on an existing primary RPC connection.
//! Ordinary config and Tool request/reply framing is unchanged. The reserved
//! prefix starts with an invalid negative Tid and is never a Tool request.

use reverie::MappingCaptureToken;

use crate::RpcError;

const REQUEST: [u8; 8] = [255, 255, 255, 255, b'M', b'C', 1, 0];
const ACK: [u8; 8] = [255, 255, 255, 255, b'M', b'C', 1, 1];
const TOKEN_BYTES: usize = 72;

/// Encode an unframed control payload; the existing transport length prefix
/// still encloses these bytes. Encoding alone grants no capture authority.
pub fn encode_request(token: reverie::MappingCaptureToken) -> Result<Vec<u8>, RpcError> {
    let body = crate::codec::encode(&token)?;
    if body.len() != TOKEN_BYTES {
        return Err(std::io::Error::other("mapping capture token layout changed").into());
    }
    let mut request = Vec::with_capacity(REQUEST.len() + TOKEN_BYTES);
    request.extend_from_slice(&REQUEST);
    request.extend_from_slice(&body);
    Ok(request)
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<Option<MappingCaptureToken>, RpcError> {
    if !bytes.starts_with(&REQUEST) {
        return Ok(None);
    }
    if bytes.len() != REQUEST.len() + TOKEN_BYTES {
        return Err(std::io::Error::other("mapping capture control length mismatched").into());
    }
    crate::codec::decode_exact(&bytes[REQUEST.len()..]).map(Some)
}

pub(crate) fn reply(request: &[u8], authorized: bool) -> Vec<u8> {
    let mut response = vec![0; REQUEST.len() + TOKEN_BYTES];
    if authorized {
        response[..ACK.len()].copy_from_slice(&ACK);
        response[ACK.len()..].copy_from_slice(&request[REQUEST.len()..]);
    }
    response
}

/// Accept only an exact acknowledgment of this request's entire token.
pub fn is_ack(request: &[u8], response: &[u8]) -> bool {
    request.len() == REQUEST.len() + TOKEN_BYTES
        && request.starts_with(&REQUEST)
        && response.len() == request.len()
        && response.starts_with(&ACK)
        && response[ACK.len()..] == request[REQUEST.len()..]
}

#[cfg(test)]
mod tests;
