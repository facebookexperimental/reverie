/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Explicit, bounded successor-image redemption. Framing is not exec authority.
//!
//! The installed hook must own the watched birth and the one-use transition.
//! A token, digest, PID or successful transport exchange is not kernel proof
//! that an exec occurred. Ordinary and InitialImage-only connections never use
//! this protocol or fall back to it.

use std::io;
use std::os::fd::OwnedFd;

use crate::Admitted;
use crate::RpcError;
use crate::initial_image::ConfigDigest;
use crate::initial_image::config_digest;

/// Hash of the exact opaque, versioned successor state bytes.
pub type StateDigest = [u8; 32];
/// Maximum complete control frame, separately bounded from state.
pub const MAX_CONTROL_LEN: usize = 4096;
/// Maximum opaque one-use ticket size.
pub const MAX_TICKET_LEN: usize = 256;
/// Maximum complete state payload, before any typed deserialization.
pub const MAX_STATE_LEN: usize = 1024 * 1024;
/// Explicit successor request magic.
pub const REQUEST_MAGIC: [u8; 8] = *b"RVSUCCRQ";
/// Explicit successor acknowledgement magic.
pub const ACK_MAGIC: [u8; 8] = *b"RVSUCCAK";
/// Only version one is accepted.
pub const VERSION: u16 = 1;
const REQUEST_HEADER_LEN: usize = 76;
const ACK_LEN: usize = 106;

/// Digests independently supplied by the protected successor input.
///
/// Do not populate these from the acknowledgement or received payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedSuccessor {
    /// Exact unchanged canonical Config bytes.
    pub config: ConfigDigest,
    /// Exact opaque composite state bytes.
    pub state: StateDigest,
}

/// Borrowed request, completely shape-checked before admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessorRequest<'a> {
    /// Opaque authority lookup key, not authority by itself.
    pub ticket: &'a [u8],
    /// Digests the old image's protected input supplied to this initializer.
    pub expected: ExpectedSuccessor,
}

/// The image redemption parsed and accepted on this exact native stream.
/// This is a connection tag, never exec authority. The host must resolve it
/// against retained same-birth incarnation history, including delayed EOF.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeImageConnection {
    /// The actual accepted initial-image redemption on this connection.
    Initial,
    /// The exact bounded ticket consumed by this stream's successor redemption.
    Successor {
        /// Opaque lookup bytes retained from the validated request.
        ticket: Vec<u8>,
    },
}

/// Launcher-owned, one-use successor admission on an already watched socket.
///
/// The hook must bind the socket's actual pidfd and watcher result to its
/// retained Issued transition, validate the ticket and both digests, and
/// consume it before returning. It must retain consumption on every later
/// transport failure and reject replay, early redemption, cancellation and
/// the wrong watched birth. Returned state is opaque: no host-side Tool runs.
pub trait SuccessorAdmission: Send + Sync {
    /// Consume the exact transition before any Config, state or ACK is sent.
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        request: SuccessorRequest<'_>,
    ) -> io::Result<Vec<u8>>;

    /// Validate a real native-image stream's clean EOF against retained state.
    /// Resolve this exact stream incarnation against genuine later Issue
    /// history or terminal physical watch state. A delayed old EOF may follow
    /// redemption/completion; another incarnation's ticket is not permission.
    /// Idle RPC is never physical completion.
    /// The default refuses; an inactive hook does not supply this authority.
    fn connection_closed(
        &self,
        _admitted: Admitted,
        _image: &NativeImageConnection,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native stream closure has no retained lifecycle admission",
        ))
    }
}

/// A state frame received on the same live, acknowledged successor stream.
///
/// Private fields preserve the transport checks. This is not a claim about
/// the installed admission hook's policy or a kernel exec attestation.
pub struct VerifiedSuccessorState {
    expected: ExpectedSuccessor,
    ticket_digest: [u8; 32],
    bytes: Vec<u8>,
}

impl VerifiedSuccessorState {
    /// The independently expected digests checked by this exchange.
    pub fn expected(&self) -> ExpectedSuccessor {
        self.expected
    }

    /// Hash of the exact opaque ticket sent by this connection.
    pub fn ticket_digest(&self) -> [u8; 32] {
        self.ticket_digest
    }

    /// Authenticated raw bytes; the caller must still decode exactly and bound
    /// allocations, then validate its typed state against independent inputs.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the checked frame without copying or reconnecting.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn from_checked_frame(
        request: SuccessorRequest<'_>,
        bytes: Vec<u8>,
    ) -> Result<Self, RpcError> {
        check_state(&bytes, request.expected.state)?;
        Ok(Self {
            expected: request.expected,
            ticket_digest: config_digest(request.ticket),
            bytes,
        })
    }
}

/// Encode only the explicit bounded successor request.
pub fn encode_redemption(request: SuccessorRequest<'_>) -> Result<Vec<u8>, RpcError> {
    if !(1..=MAX_TICKET_LEN).contains(&request.ticket.len()) {
        return Err(invalid("successor ticket length is invalid"));
    }
    let mut bytes = Vec::with_capacity(REQUEST_HEADER_LEN + request.ticket.len());
    bytes.extend_from_slice(&REQUEST_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&(request.ticket.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&request.expected.config);
    bytes.extend_from_slice(&request.expected.state);
    bytes.extend_from_slice(request.ticket);
    Ok(bytes)
}

pub(crate) fn decode_redemption(bytes: &[u8]) -> Result<SuccessorRequest<'_>, RpcError> {
    if !(REQUEST_HEADER_LEN + 1..=REQUEST_HEADER_LEN + MAX_TICKET_LEN).contains(&bytes.len()) {
        return Err(invalid("successor request length is invalid"));
    }
    check_header(bytes, &REQUEST_MAGIC)?;
    let length = usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
    if length == 0 || length > MAX_TICKET_LEN || REQUEST_HEADER_LEN + length != bytes.len() {
        return Err(invalid("successor ticket does not consume its frame"));
    }
    let config = bytes[12..44].try_into().unwrap();
    let state = bytes[44..76].try_into().unwrap();
    Ok(SuccessorRequest {
        ticket: &bytes[REQUEST_HEADER_LEN..],
        expected: ExpectedSuccessor { config, state },
    })
}

pub(crate) fn encode_ack(request: SuccessorRequest<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ACK_LEN);
    bytes.extend_from_slice(&ACK_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&request.expected.config);
    bytes.extend_from_slice(&request.expected.state);
    bytes.extend_from_slice(&config_digest(request.ticket));
    bytes
}

pub(crate) fn check_ack(bytes: &[u8], request: SuccessorRequest<'_>) -> Result<(), RpcError> {
    if bytes.len() != ACK_LEN {
        return Err(invalid("successor acknowledgement length is invalid"));
    }
    check_header(bytes, &ACK_MAGIC)?;
    if bytes[10..42] != request.expected.config
        || bytes[42..74] != request.expected.state
        || bytes[74..106] != config_digest(request.ticket)
    {
        return Err(invalid("successor acknowledgement binding differs"));
    }
    Ok(())
}

pub(crate) fn check_state(bytes: &[u8], expected: StateDigest) -> Result<(), RpcError> {
    if !(1..=MAX_STATE_LEN).contains(&bytes.len()) {
        return Err(invalid("successor state length is invalid"));
    }
    if config_digest(bytes) != expected {
        return Err(invalid("successor raw state digest differs"));
    }
    Ok(())
}

fn check_header(bytes: &[u8], magic: &[u8; 8]) -> Result<(), RpcError> {
    if bytes.len() < 10 || bytes[..8] != *magic || bytes[8..10] != VERSION.to_be_bytes() {
        return Err(invalid("successor magic or version differs"));
    }
    Ok(())
}

pub(crate) fn invalid(message: &'static str) -> RpcError {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SuccessorRequest<'static> {
        SuccessorRequest {
            ticket: b"one-use-ticket",
            expected: ExpectedSuccessor {
                config: [17; 32],
                state: [29; 32],
            },
        }
    }

    #[test]
    fn exact_request_roundtrip_and_every_truncated_prefix() {
        let request = request();
        let bytes = encode_redemption(request).unwrap();
        assert_eq!(decode_redemption(&bytes).unwrap(), request);
        assert_eq!(
            decode_redemption(&bytes).unwrap().ticket.as_ptr(),
            bytes[REQUEST_HEADER_LEN..].as_ptr()
        );
        for end in 0..bytes.len() {
            assert!(decode_redemption(&bytes[..end]).is_err(), "{end}");
        }
        for index in [0, 8, 9, 10, 11] {
            let mut wrong = bytes.clone();
            wrong[index] ^= 1;
            assert!(decode_redemption(&wrong).is_err(), "{index}");
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_redemption(&trailing).is_err());
    }

    #[test]
    fn request_bounds_and_no_initial_image_fallback() {
        let mut request = request();
        request.ticket = b"";
        assert!(encode_redemption(request).is_err());
        let maximum = [0x5a; MAX_TICKET_LEN];
        request.ticket = &maximum;
        let bytes = encode_redemption(request).unwrap();
        assert_eq!(bytes.len(), REQUEST_HEADER_LEN + MAX_TICKET_LEN);
        assert!(bytes.len() <= MAX_CONTROL_LEN);
        assert_eq!(decode_redemption(&bytes).unwrap(), request);
        request.ticket = &[0x5a; MAX_TICKET_LEN + 1];
        assert!(encode_redemption(request).is_err());
        assert!(
            decode_redemption(&crate::initial_image::encode_redemption(b"ticket").unwrap())
                .is_err()
        );
        assert!(crate::initial_image::decode_redemption(&bytes).is_err());
    }

    #[test]
    fn acknowledgement_checks_every_byte_and_exact_ticket() {
        let request = request();
        let bytes = encode_ack(request);
        assert_eq!(bytes.len(), ACK_LEN);
        check_ack(&bytes, request).unwrap();
        for index in 0..bytes.len() {
            let mut wrong = bytes.clone();
            wrong[index] ^= 1;
            assert!(check_ack(&wrong, request).is_err(), "{index}");
        }
        for end in 0..bytes.len() {
            assert!(check_ack(&bytes[..end], request).is_err());
        }
        let mut wrong_ticket = request;
        wrong_ticket.ticket = b"different-ticket";
        assert!(check_ack(&bytes, wrong_ticket).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(check_ack(&trailing, request).is_err());
    }

    #[test]
    fn checked_state_is_exact_and_bounded_before_typed_decode() {
        let bytes = vec![0x7d; MAX_STATE_LEN];
        let expected = config_digest(&bytes);
        check_state(&bytes, expected).unwrap();
        assert!(check_state(&[], config_digest(&[])).is_err());
        assert!(check_state(&vec![0x7d; MAX_STATE_LEN + 1], expected).is_err());
        assert!(check_state(&bytes, [0; 32]).is_err());
        let mut request = request();
        request.expected.state = expected;
        let state = VerifiedSuccessorState::from_checked_frame(request, bytes.clone()).unwrap();
        assert_eq!(state.bytes(), bytes);
        assert_eq!(state.expected(), request.expected);
        assert_eq!(state.ticket_digest(), config_digest(request.ticket));
        assert_eq!(state.into_bytes(), bytes);
    }
}
