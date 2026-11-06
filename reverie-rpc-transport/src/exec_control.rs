/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Guest-callable native-exec control seam (W6b N1, musegate conditions).
//!
//! Dedicated control frames over a dedicated stream — never GlobalTool
//! request variants. The server accepts control frames only on a
//! control connection it issued at launch; there is no
//! unauthenticated listener. Issue returns the opaque
//! [`ExecTicket`] itself (no separate transition handle).
//!
//! Caller map: prepare/seal/issue/cancel = guest driver (sync, safe
//! from `PreparedNativeExec` with no async runtime); redeem =
//! RpcServer successor admission; complete = launcher after successor
//! Tool installation; failed/died = coordinator/watcher feeds only.

use std::io;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::codec::DEFAULT_MAX_FRAME_LEN;
use crate::exec_ticket::ExecControlError;
use crate::exec_ticket::ExecTicket;
use crate::exec_ticket::ExecTicketRegistry;
use crate::exec_ticket::TicketBinding;
use crate::exec_ticket::TicketProof;

/// Synchronous issuer usable from prepared-native-exec driver code.
/// No async runtime is assumed on any method.
pub trait ExecIssuer<B: TicketBinding> {
    /// Mint a ticket for a prepared exec (snapshot digest-checked).
    fn prepare(
        &mut self,
        binding: B,
        snapshot: Vec<u8>,
        snapshot_digest: [u8; 32],
    ) -> Result<ExecTicket, ExecControlError>;
    /// Seal runtime bytes exactly once; returns the state digest.
    fn seal(
        &mut self,
        ticket: ExecTicket,
        runtime_digest: [u8; 32],
        runtime: &[u8],
    ) -> Result<[u8; 32], ExecControlError>;
    /// Record provision delivery (required before issue).
    fn mark_provision_delivered(&mut self, ticket: ExecTicket) -> Result<(), ExecControlError>;
    /// Last old-image edge; returns the same opaque ticket.
    fn issue(
        &mut self,
        ticket: ExecTicket,
        digest: [u8; 32],
    ) -> Result<ExecTicket, ExecControlError>;
    /// Best-effort pre-redemption cancel (safe from cancel paths).
    fn cancel(&mut self, ticket: ExecTicket) -> Result<(), ExecControlError>;
}

#[derive(Debug, Serialize, Deserialize)]
enum ControlRequest<B> {
    Prepare {
        binding: B,
        snapshot: Vec<u8>,
        snapshot_digest: [u8; 32],
    },
    Seal {
        ticket: ExecTicket,
        runtime_digest: [u8; 32],
        runtime: Vec<u8>,
    },
    MarkDelivered {
        ticket: ExecTicket,
    },
    Issue {
        ticket: ExecTicket,
        digest: [u8; 32],
    },
    Cancel {
        ticket: ExecTicket,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum ControlResponse {
    Ticket(ExecTicket),
    Sealed([u8; 32]),
    Unit,
    Refused(ExecControlError),
}

fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "exec control frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > DEFAULT_MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exec control frame exceeds bound",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Blocking control client over any sync stream (socket today;
/// mapped guest streams reuse the same client in the guest).
pub struct ExecControlClient<S, B> {
    stream: S,
    _binding: std::marker::PhantomData<fn() -> B>,
}

impl<S: Read + Write, B: TicketBinding + Serialize> ExecControlClient<S, B> {
    /// Wrap an already-connected control stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            _binding: std::marker::PhantomData,
        }
    }

    fn exchange(
        &mut self,
        request: &ControlRequest<B>,
    ) -> Result<ControlResponse, ExecControlError> {
        let payload = crate::codec::encode(request).map_err(|_| ExecControlError::Bounds)?;
        write_frame(&mut self.stream, &payload).map_err(|_| ExecControlError::Dead)?;
        let reply = read_frame(&mut self.stream).map_err(|_| ExecControlError::Dead)?;
        crate::codec::decode(&reply).map_err(|_| ExecControlError::Bounds)
    }
}

impl<B, S> ExecIssuer<B> for ExecControlClient<S, B>
where
    B: TicketBinding + Serialize + DeserializeOwned,
    S: Read + Write,
{
    fn prepare(
        &mut self,
        binding: B,
        snapshot: Vec<u8>,
        snapshot_digest: [u8; 32],
    ) -> Result<ExecTicket, ExecControlError> {
        match self.exchange(&ControlRequest::Prepare {
            binding,
            snapshot,
            snapshot_digest,
        })? {
            ControlResponse::Ticket(ticket) => Ok(ticket),
            ControlResponse::Refused(error) => Err(error),
            _ => Err(ExecControlError::Bounds),
        }
    }

    fn seal(
        &mut self,
        ticket: ExecTicket,
        runtime_digest: [u8; 32],
        runtime: &[u8],
    ) -> Result<[u8; 32], ExecControlError> {
        match self.exchange(&ControlRequest::Seal {
            ticket,
            runtime_digest,
            runtime: runtime.to_vec(),
        })? {
            ControlResponse::Sealed(digest) => Ok(digest),
            ControlResponse::Refused(error) => Err(error),
            _ => Err(ExecControlError::Bounds),
        }
    }

    fn mark_provision_delivered(&mut self, ticket: ExecTicket) -> Result<(), ExecControlError> {
        match self.exchange(&ControlRequest::MarkDelivered { ticket })? {
            ControlResponse::Unit => Ok(()),
            ControlResponse::Refused(error) => Err(error),
            _ => Err(ExecControlError::Bounds),
        }
    }

    fn issue(
        &mut self,
        ticket: ExecTicket,
        digest: [u8; 32],
    ) -> Result<ExecTicket, ExecControlError> {
        match self.exchange(&ControlRequest::Issue { ticket, digest })? {
            ControlResponse::Ticket(issued) => Ok(issued),
            ControlResponse::Refused(error) => Err(error),
            _ => Err(ExecControlError::Bounds),
        }
    }

    fn cancel(&mut self, ticket: ExecTicket) -> Result<(), ExecControlError> {
        match self.exchange(&ControlRequest::Cancel { ticket })? {
            ControlResponse::Unit => Ok(()),
            ControlResponse::Refused(error) => Err(error),
            _ => Err(ExecControlError::Bounds),
        }
    }
}

/// Serve control frames on one admitted control stream until EOF.
pub fn serve_exec_control<P, B, S>(
    mut stream: S,
    registry: &Arc<Mutex<ExecTicketRegistry<P, B>>>,
) -> io::Result<()>
where
    B: TicketBinding + DeserializeOwned + Serialize,
    P: TicketProof<B>,
    S: Read + Write,
{
    loop {
        let payload = match read_frame(&mut stream) {
            Ok(payload) => payload,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let request: ControlRequest<B> = match crate::codec::decode(&payload) {
            Ok(request) => request,
            Err(_) => return Ok(()), // malformed control frame: close, never panic
        };
        let owner = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .proof_owner();
        let response = {
            let mut registry = registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match request {
                ControlRequest::Prepare {
                    binding,
                    snapshot,
                    snapshot_digest,
                } => match registry.prepare(owner, binding, snapshot, snapshot_digest) {
                    Ok(ticket) => ControlResponse::Ticket(ticket),
                    Err(error) => ControlResponse::Refused(error),
                },
                ControlRequest::Seal {
                    ticket,
                    runtime_digest,
                    runtime,
                } => match registry.seal(owner, ticket, runtime_digest, &runtime) {
                    Ok(digest) => ControlResponse::Sealed(digest),
                    Err(error) => ControlResponse::Refused(error),
                },
                ControlRequest::MarkDelivered { ticket } => {
                    match registry.mark_provision_delivered(owner, ticket) {
                        Ok(()) => ControlResponse::Unit,
                        Err(error) => ControlResponse::Refused(error),
                    }
                }
                ControlRequest::Issue { ticket, digest } => {
                    match registry.issue(owner, ticket, digest) {
                        Ok(()) => ControlResponse::Ticket(ticket),
                        Err(error) => ControlResponse::Refused(error),
                    }
                }
                ControlRequest::Cancel { ticket } => match registry.cancel(owner, ticket) {
                    Ok(()) => ControlResponse::Unit,
                    Err(error) => ControlResponse::Refused(error),
                },
            }
        };
        let payload = crate::codec::encode(&response)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "exec control encode"))?;
        write_frame(&mut stream, &payload)?;
    }
}
