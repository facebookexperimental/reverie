/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! One-agent-day D1/D3 spike: one serialized per-birth authority.
//!
//! This module combines, under one mutex, the one-use InitialImage
//! fact, the predecessor's one-slot snapshot mailbox, and the
//! [`ExecTicketRegistry`]. It is deliberately not wired to a guest
//! exec-control surface: the only guest-callable protocol here can
//! stage or invalidate a snapshot and returns no ticket. Prepare,
//! seal, mark, issue, complete, watch death, and close resolution
//! are host-side methods on the authority.
//!
//! Scalar-5 claim scope for this spike: this implements the
//! transport authority consumed through the existing RpcServer
//! native-image hooks and a synchronous stage service whose birth
//! key is supplied by the server from its admitted connection. The
//! launcher supervisor that reports the kernel stop and the mapped
//! selected-construction seam remain their existing owners.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::sync::Mutex;
use std::sync::MutexGuard;

use serde::Deserialize;
use serde::Serialize;

use crate::Admitted;
use crate::RpcError;
use crate::codec::decode as codec_decode;
use crate::codec::encode as codec_encode;
use crate::exec_ticket::ExecControlError;
use crate::exec_ticket::ExecStage;
use crate::exec_ticket::ExecTicket;
use crate::exec_ticket::ExecTicketRegistry;
use crate::exec_ticket::MAX_STATE_BYTES;
use crate::exec_ticket::TicketBinding;
use crate::exec_ticket::TicketProof;
use crate::initial_image::ConfigDigest;
use crate::initial_image::InitialImageAdmission;
use crate::initial_image::config_digest;
use crate::successor::ExpectedSuccessor;
use crate::successor::NativeImageConnection;
use crate::successor::SuccessorAdmission;
use crate::successor::SuccessorRequest;
use crate::successor::VerifiedSuccessorState;

/// Total successor state budget (`4 + ExecState + 128`).
pub const MAX_COMPOSITE_STATE_LEN: usize = MAX_STATE_BYTES;
/// Fixed ExecBoundaryRuntimeV1 suffix length.
pub const EXEC_BOUNDARY_RUNTIME_LEN: usize = 128;
const RUNTIME_MAGIC: &[u8; 8] = b"RVEXBD01";
const RUNTIME_VERSION: u16 = 1;
const RUNTIME_FLAG_KERNEL_STOP: u32 = 1;
const MAX_STAGE_FRAME_LEN: usize = MAX_STATE_BYTES + 4096;

/// Frame `ExecState` bytes as `[u32 LE len][bytes]`, enforcing the
/// combined budget at capture/stage time with `E2BIG`.
pub fn frame_tool_state(exec_state: &[u8]) -> io::Result<Vec<u8>> {
    let total = 4usize
        .checked_add(exec_state.len())
        .and_then(|n| n.checked_add(EXEC_BOUNDARY_RUNTIME_LEN))
        .ok_or_else(e2big)?;
    if total > MAX_COMPOSITE_STATE_LEN {
        return Err(e2big());
    }
    let len = u32::try_from(exec_state.len()).map_err(|_| e2big())?;
    let mut framed = Vec::with_capacity(4 + exec_state.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(exec_state);
    Ok(framed)
}

fn e2big() -> io::Error {
    io::Error::from_raw_os_error(libc::E2BIG)
}

fn check_framed_tool_budget(framed: &[u8]) -> Result<(), ExecControlError> {
    if framed.len() < 4 {
        return Err(ExecControlError::Bounds);
    }
    let declared = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
    if declared != framed.len() - 4 {
        return Err(ExecControlError::Bounds);
    }
    if framed.len() + EXEC_BOUNDARY_RUNTIME_LEN > MAX_COMPOSITE_STATE_LEN {
        return Err(ExecControlError::Bounds);
    }
    Ok(())
}

/// Fixed canonical runtime receipt sealed as the composite suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecBoundaryRuntimeV1 {
    pub flags: u32,
    pub exec_ordinal: u64,
    pub config_digest: [u8; 32],
    pub tool_digest: [u8; 32],
    pub ticket_digest: [u8; 32],
}

impl ExecBoundaryRuntimeV1 {
    pub fn encode(&self, framed_tool: &[u8]) -> [u8; EXEC_BOUNDARY_RUNTIME_LEN] {
        let mut out = [0u8; EXEC_BOUNDARY_RUNTIME_LEN];
        out[0..8].copy_from_slice(RUNTIME_MAGIC);
        out[8..10].copy_from_slice(&RUNTIME_VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(EXEC_BOUNDARY_RUNTIME_LEN as u16).to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..20].copy_from_slice(&(framed_tool.len() as u32).to_le_bytes());
        out[24..32].copy_from_slice(&self.exec_ordinal.to_le_bytes());
        out[32..64].copy_from_slice(&self.config_digest);
        out[64..96].copy_from_slice(&self.tool_digest);
        out[96..128].copy_from_slice(&self.ticket_digest);
        out
    }

    fn parse_exact(bytes: &[u8]) -> Result<(Self, usize), RpcError> {
        if bytes.len() != EXEC_BOUNDARY_RUNTIME_LEN
            || &bytes[0..8] != RUNTIME_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != RUNTIME_VERSION
            || u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize
                != EXEC_BOUNDARY_RUNTIME_LEN
        {
            return Err(runtime_invalid(
                "ExecBoundaryRuntimeV1 magic/version/length differs",
            ));
        }
        let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        if flags != RUNTIME_FLAG_KERNEL_STOP {
            return Err(runtime_invalid("ExecBoundaryRuntimeV1 flags differ"));
        }
        if bytes[20..24] != [0; 4] {
            return Err(runtime_invalid(
                "ExecBoundaryRuntimeV1 reserved field is nonzero",
            ));
        }
        let framed_tool_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let exec_ordinal = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        if exec_ordinal == 0 {
            return Err(runtime_invalid("ExecBoundaryRuntimeV1 ordinal is zero"));
        }
        Ok((
            Self {
                flags,
                exec_ordinal,
                config_digest: bytes[32..64].try_into().unwrap(),
                tool_digest: bytes[64..96].try_into().unwrap(),
                ticket_digest: bytes[96..128].try_into().unwrap(),
            },
            framed_tool_len,
        ))
    }
}

fn runtime_invalid(message: &'static str) -> RpcError {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

/// Verify the runtime suffix and return only the framed tool bytes.
///
/// This is the required successor-side order: every binding below
/// is checked here, before any caller-side `ExecState` decode of
/// the returned frame's contents.
pub fn verify_and_split_runtime(
    composite: &[u8],
    expected_config_digest: [u8; 32],
    expected_ticket_digest: [u8; 32],
) -> Result<(ExecBoundaryRuntimeV1, Vec<u8>), RpcError> {
    if composite.len() > MAX_COMPOSITE_STATE_LEN || composite.len() < 4 + EXEC_BOUNDARY_RUNTIME_LEN
    {
        return Err(runtime_invalid(
            "ExecBoundaryRuntimeV1 composite length differs",
        ));
    }
    let split = composite.len() - EXEC_BOUNDARY_RUNTIME_LEN;
    let (framed, suffix) = composite.split_at(split);
    let (runtime, framed_tool_len) = ExecBoundaryRuntimeV1::parse_exact(suffix)?;
    if framed_tool_len != framed.len() {
        return Err(runtime_invalid(
            "ExecBoundaryRuntimeV1 framed length differs",
        ));
    }
    let declared = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
    if declared != framed.len() - 4 {
        return Err(runtime_invalid("framed tool length differs from frame"));
    }
    if runtime.config_digest != expected_config_digest {
        return Err(runtime_invalid(
            "ExecBoundaryRuntimeV1 config digest differs",
        ));
    }
    if runtime.tool_digest != config_digest(framed) {
        return Err(runtime_invalid("ExecBoundaryRuntimeV1 tool digest differs"));
    }
    if runtime.ticket_digest != expected_ticket_digest {
        return Err(runtime_invalid(
            "ExecBoundaryRuntimeV1 ticket digest differs",
        ));
    }
    Ok((runtime, framed.to_vec()))
}

/// Verify/split first; only then invoke `decode` on the ExecState bytes.
pub fn verify_split_and_decode<T>(
    verified: &VerifiedSuccessorState,
    packet_expected: ExpectedSuccessor,
    decode: impl FnOnce(&[u8]) -> Result<T, RpcError>,
) -> Result<(ExecBoundaryRuntimeV1, T), RpcError> {
    if verified.expected().config != packet_expected.config
        || verified.expected().state != packet_expected.state
    {
        return Err(runtime_invalid(
            "packet ExpectedSuccessor differs from verified state",
        ));
    }
    let (runtime, framed) = verify_and_split_runtime(
        verified.bytes(),
        packet_expected.config,
        verified.ticket_digest(),
    )?;
    let decoded = decode(&framed[4..])?;
    Ok((runtime, decoded))
}

/// Server-derived birth key. Only the authority's constructor and
/// its host-side stop recording can mint/advance its incarnation;
/// a guest-supplied pid or key is never accepted as this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BirthKey {
    /// Watched leader admitted on the first image connection.
    pub process_id: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpikeBinding {
    owner: i32,
    config: [u8; 32],
    exec_ordinal: u64,
}

impl TicketBinding for SpikeBinding {
    type Owner = i32;
    fn owner(&self) -> i32 {
        self.owner
    }
    fn config_digest(&self) -> [u8; 32] {
        self.config
    }
}

#[derive(Default)]
struct ProofState {
    stop_process_id: Option<i32>,
    expected_runtime: Option<[u8; EXEC_BOUNDARY_RUNTIME_LEN]>,
}

#[derive(Clone)]
struct SpikeProof {
    owner: i32,
    config_digest: [u8; 32],
    state: std::sync::Arc<Mutex<ProofState>>,
}

impl TicketProof<SpikeBinding> for SpikeProof {
    fn owner(&self) -> i32 {
        self.owner
    }

    fn matches_peer(&self, peer: &OwnedFd) -> bool {
        let Some(stop_pid) = self.state.lock().unwrap().stop_process_id else {
            return false;
        };
        matches!(crate::peer_identity::peer_process_id(peer), Ok(Some(pid)) if pid == stop_pid)
            && stop_pid == self.owner
    }

    fn qualify_prepare(&self, binding: &SpikeBinding, snapshot: &[u8]) -> bool {
        binding.owner == self.owner
            && binding.config_digest() == self.config_digest
            && binding.exec_ordinal != 0
            && check_framed_tool_budget(snapshot).is_ok()
    }

    fn qualify_runtime(&self, runtime: &[u8]) -> bool {
        self.state
            .lock()
            .unwrap()
            .expected_runtime
            .as_ref()
            .map(|v| v.as_slice())
            == Some(runtime)
    }

    fn qualify_completion(&self, _ticket: ExecTicket, binding: &SpikeBinding) -> bool {
        binding.owner == self.owner && binding.config_digest() == self.config_digest
    }
}

/// Packet-only expected values produced by the host stamp callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StampedPacket {
    pub expected: ExpectedSuccessor,
    pub redemption: Vec<u8>,
}

/// Host-only action at a recorded kernel SuccessorStop.
pub struct SuccessorStop {
    birth: BirthKey,
    exec_ordinal: u64,
}

struct StopRecord {
    exec_ordinal: u64,
    ticket: Option<ExecTicket>,
}

struct Inner {
    initial_used: bool,
    initial_redemption: Vec<u8>,
    config_digest: [u8; 32],
    mailbox: Option<Vec<u8>>,
    registry: ExecTicketRegistry<SpikeProof, SpikeBinding>,
    stops: Vec<StopRecord>,
    watch_terminal: bool,
    closed: Vec<NativeImageConnection>,
}

/// The one serialized authority for one watched birth.
pub struct BirthAuthority {
    key: BirthKey,
    proof_state: std::sync::Arc<Mutex<ProofState>>,
    inner: Mutex<Inner>,
}

impl BirthAuthority {
    pub fn new(
        admitted: Admitted,
        config_digest_value: [u8; 32],
        initial_redemption: Vec<u8>,
        registry_nonce: [u8; 32],
    ) -> Result<Self, ExecControlError> {
        let proof_state = std::sync::Arc::new(Mutex::new(ProofState {
            stop_process_id: Some(admitted.process_id),
            ..ProofState::default()
        }));
        let proof = SpikeProof {
            owner: admitted.process_id,
            config_digest: config_digest_value,
            state: proof_state.clone(),
        };
        Ok(Self {
            key: BirthKey {
                process_id: admitted.process_id,
            },
            proof_state,
            inner: Mutex::new(Inner {
                initial_used: false,
                initial_redemption,
                config_digest: config_digest_value,
                mailbox: None,
                registry: ExecTicketRegistry::new(proof, registry_nonce)?,
                stops: Vec::new(),
                watch_terminal: false,
                closed: Vec::new(),
            }),
        })
    }

    pub fn birth_key(&self) -> BirthKey {
        self.key
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn check_admitted(&self, admitted: Admitted) -> Result<(), ExecControlError> {
        if admitted.process_id != self.key.process_id {
            return Err(ExecControlError::Identity);
        }
        Ok(())
    }

    /// Host-side record that this birth's initial image was also
    /// consumed by the mapped route, without an InitialImage RPC.
    pub fn record_initial_consumed(&self, admitted: Admitted) -> Result<(), ExecControlError> {
        self.check_admitted(admitted)?;
        let mut inner = self.lock();
        if inner.initial_used {
            return Err(ExecControlError::Transition);
        }
        inner.initial_used = true;
        Ok(())
    }

    /// Stage one framed snapshot for the server-derived birth.
    /// This is the operation behind the stage-only guest protocol;
    /// it takes no key from the guest and returns no ticket.
    pub fn stage_snapshot(
        &self,
        admitted: Admitted,
        framed_tool: Vec<u8>,
    ) -> Result<(), ExecControlError> {
        self.check_admitted(admitted)?;
        check_framed_tool_budget(&framed_tool)?;
        let mut inner = self.lock();
        if !inner.initial_used {
            return Err(ExecControlError::Transition);
        }
        inner.mailbox = Some(framed_tool);
        Ok(())
    }

    /// Explicit invalidation preferred on the failed-exec return path.
    pub fn invalidate_mailbox(&self, admitted: Admitted) -> Result<(), ExecControlError> {
        self.check_admitted(admitted)?;
        self.lock().mailbox = None;
        Ok(())
    }

    /// Record a kernel successor stop for this exact admitted peer.
    /// Only host code that owns the physical watch may call this;
    /// `peer` must be that stop incarnation's pidfd.
    pub fn record_successor_stop(
        &self,
        admitted: Admitted,
        peer: &OwnedFd,
    ) -> Result<SuccessorStop, ExecControlError> {
        self.check_admitted(admitted)?;
        if !matches!(crate::peer_identity::peer_process_id(peer), Ok(Some(pid)) if pid == admitted.process_id)
        {
            return Err(ExecControlError::Identity);
        }
        let mut inner = self.lock();
        if !inner.initial_used || inner.watch_terminal {
            return Err(ExecControlError::Transition);
        }
        let ordinal = inner.stops.len() as u64 + 1;
        inner.stops.push(StopRecord {
            exec_ordinal: ordinal,
            ticket: None,
        });
        Ok(SuccessorStop {
            birth: self.key,
            exec_ordinal: ordinal,
        })
    }

    /// At a recorded SuccessorStop: take mailbox once, then prepare,
    /// seal the canonical runtime, run the host stamp callback,
    /// mark delivered, and issue. The stamp callback is host-side;
    /// it receives the ticket solely to stamp the packet.
    pub fn at_successor_stop(
        &self,
        stop: SuccessorStop,
        stamp: impl FnOnce(ExecTicket, [u8; 32]) -> Result<StampedPacket, ExecControlError>,
    ) -> Result<ExpectedSuccessor, ExecControlError> {
        if stop.birth != self.key {
            return Err(ExecControlError::Identity);
        }
        let mut inner = self.lock();
        let stop_index = inner
            .stops
            .iter()
            .position(|record| record.exec_ordinal == stop.exec_ordinal)
            .ok_or(ExecControlError::Identity)?;
        if inner.stops[stop_index].ticket.is_some() {
            return Err(ExecControlError::Transition);
        }
        let framed = inner.mailbox.take().ok_or(ExecControlError::Unavailable)?;
        let binding = SpikeBinding {
            owner: self.key.process_id,
            config: inner.config_digest,
            exec_ordinal: stop.exec_ordinal,
        };
        let digest = config_digest(&framed);
        let ticket =
            inner
                .registry
                .prepare(self.key.process_id, binding, framed.clone(), digest)?;
        inner.stops[stop_index].ticket = Some(ticket);
        let runtime = ExecBoundaryRuntimeV1 {
            flags: RUNTIME_FLAG_KERNEL_STOP,
            exec_ordinal: stop.exec_ordinal,
            config_digest: inner.config_digest,
            tool_digest: digest,
            ticket_digest: config_digest(&ticket.0),
        }
        .encode(&framed);
        {
            let mut proof = self.proof_state.lock().unwrap();
            proof.expected_runtime = Some(runtime);
        }
        let result = (|| {
            let sealed = inner.registry.seal(
                self.key.process_id,
                ticket,
                config_digest(&runtime),
                &runtime,
            )?;
            let packet = stamp(ticket, sealed)?;
            if packet.expected.config != inner.config_digest
                || packet.expected.state != sealed
                || packet.redemption.as_slice() != ticket.0.as_slice()
                || config_digest(&packet.redemption) != config_digest(&ticket.0)
            {
                return Err(ExecControlError::Digest);
            }
            inner
                .registry
                .mark_provision_delivered(self.key.process_id, ticket)?;
            inner.registry.issue(self.key.process_id, ticket, sealed)?;
            Ok(packet.expected)
        })();
        self.proof_state.lock().unwrap().expected_runtime = None;
        match result {
            Ok(expected) => Ok(expected),
            Err(error) => {
                if inner.registry.cancel(self.key.process_id, ticket).is_err() {
                    let _ = inner.registry.failed(ticket);
                }
                Err(error)
            }
        }
    }

    /// Host-only completion at verified Ready.
    pub fn complete(&self, ticket: ExecTicket) -> Result<(), ExecControlError> {
        self.lock().registry.complete(self.key.process_id, ticket)
    }

    /// Recorded actual watch death/exit. Never call this on EOF.
    pub fn record_watch_terminal(&self) {
        let mut inner = self.lock();
        inner.watch_terminal = true;
        inner.registry.died();
    }

    /// Retained stage for host/test evidence.
    pub fn stage(&self, ticket: ExecTicket) -> Option<ExecStage> {
        self.lock().registry.stage(ticket)
    }
}

impl InitialImageAdmission for BirthAuthority {
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        redemption: &[u8],
        digest: ConfigDigest,
    ) -> io::Result<()> {
        self.check_admitted(admitted).map_err(io::Error::other)?;
        if !matches!(crate::peer_identity::peer_process_id(&peer), Ok(Some(pid)) if pid == admitted.process_id)
        {
            return Err(io::Error::other(
                "birth authority InitialImage peer differs",
            ));
        }
        let mut inner = self.lock();
        if inner.initial_used
            || !inner.stops.is_empty()
            || redemption != inner.initial_redemption.as_slice()
            || digest != inner.config_digest
        {
            return Err(io::Error::other("birth authority InitialImage refused"));
        }
        inner.initial_used = true;
        Ok(())
    }
}

impl SuccessorAdmission for BirthAuthority {
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        request: SuccessorRequest<'_>,
    ) -> io::Result<Vec<u8>> {
        self.check_admitted(admitted).map_err(io::Error::other)?;
        let mut inner = self.lock();
        if !inner.initial_used {
            return Err(io::Error::other(
                "successor before InitialImage in birth authority",
            ));
        }
        inner
            .registry
            .redeem(
                &peer,
                ExecTicket(request.ticket.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "exec ticket length")
                })?),
                request.expected.config,
                request.expected.state,
            )
            .map_err(io::Error::other)
    }

    fn connection_closed(
        &self,
        admitted: Admitted,
        image: &NativeImageConnection,
    ) -> io::Result<()> {
        self.check_admitted(admitted).map_err(io::Error::other)?;
        let mut inner = self.lock();
        if inner.closed.contains(image) {
            return Err(io::Error::other("birth authority duplicate EOF"));
        }
        let accepted = match image {
            NativeImageConnection::Initial => {
                inner.watch_terminal
                    || inner.stops.iter().any(|stop| {
                        stop.ticket.is_some_and(|ticket| {
                            matches!(
                                inner.registry.stage(ticket),
                                Some(
                                    ExecStage::Issued | ExecStage::Redeemed | ExecStage::Completed
                                )
                            )
                        })
                    })
            }
            NativeImageConnection::Successor { ticket } => {
                let Ok(ticket) = <[u8; 32]>::try_from(ticket.as_slice()) else {
                    return Err(io::Error::other("birth authority EOF ticket shape"));
                };
                matches!(
                    inner.registry.stage(ExecTicket(ticket)),
                    Some(
                        ExecStage::Redeemed
                            | ExecStage::Completed
                            | ExecStage::Failed
                            | ExecStage::Dead
                    )
                )
            }
        };
        if !accepted {
            return Err(io::Error::other("birth authority EOF refused"));
        }
        inner.closed.push(image.clone());
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum StageRequest {
    StageSnapshot { framed_tool: Vec<u8> },
    Invalidate,
}

#[derive(Debug, Serialize, Deserialize)]
enum StageResponse {
    Unit,
    Refused(ExecControlError),
}

fn write_stage_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stage frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn read_stage_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_STAGE_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stage frame exceeds bound",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Guest-side stage client. It intentionally has no prepare, seal,
/// mark, issue, redeem, or ticket-returning operation.
pub struct StageClient<S> {
    stream: S,
}

impl<S: Read + Write> StageClient<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    fn exchange(&mut self, request: &StageRequest) -> Result<(), ExecControlError> {
        let payload = codec_encode(request).map_err(|_| ExecControlError::Bounds)?;
        write_stage_frame(&mut self.stream, &payload).map_err(|_| ExecControlError::Dead)?;
        let reply = read_stage_frame(&mut self.stream).map_err(|_| ExecControlError::Dead)?;
        match codec_decode::<StageResponse>(&reply).map_err(|_| ExecControlError::Bounds)? {
            StageResponse::Unit => Ok(()),
            StageResponse::Refused(error) => Err(error),
        }
    }

    pub fn stage_snapshot(&mut self, framed_tool: Vec<u8>) -> Result<(), ExecControlError> {
        if framed_tool.len() + EXEC_BOUNDARY_RUNTIME_LEN > MAX_COMPOSITE_STATE_LEN {
            return Err(ExecControlError::Bounds);
        }
        self.exchange(&StageRequest::StageSnapshot { framed_tool })
    }

    pub fn invalidate(&mut self) -> Result<(), ExecControlError> {
        self.exchange(&StageRequest::Invalidate)
    }
}

/// Serve stage requests until EOF. `admitted` is supplied only by
/// the server that admitted this connection; frames carry no key.
pub fn serve_stage_snapshot(
    mut stream: impl Read + Write,
    authority: &BirthAuthority,
    admitted: Admitted,
) -> io::Result<()> {
    loop {
        let payload = match read_stage_frame(&mut stream) {
            Ok(payload) => payload,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let request: StageRequest = match codec_decode(&payload) {
            Ok(request) => request,
            Err(_) => return Ok(()),
        };
        let response = match request {
            StageRequest::StageSnapshot { framed_tool } => {
                match authority.stage_snapshot(admitted, framed_tool) {
                    Ok(()) => StageResponse::Unit,
                    Err(error) => StageResponse::Refused(error),
                }
            }
            StageRequest::Invalidate => match authority.invalidate_mailbox(admitted) {
                Ok(()) => StageResponse::Unit,
                Err(error) => StageResponse::Refused(error),
            },
        };
        let payload = codec_encode(&response)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stage encode"))?;
        write_stage_frame(&mut stream, &payload)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    fn composite() -> (Vec<u8>, [u8; 32], ExecTicket) {
        let framed = frame_tool_state(b"exec-state-bytes").unwrap();
        let ticket = ExecTicket([9u8; 32]);
        let config = [3u8; 32];
        let runtime = ExecBoundaryRuntimeV1 {
            flags: RUNTIME_FLAG_KERNEL_STOP,
            exec_ordinal: 1,
            config_digest: config,
            tool_digest: config_digest(&framed),
            ticket_digest: config_digest(&ticket.0),
        }
        .encode(&framed);
        let mut bytes = framed;
        bytes.extend_from_slice(&runtime);
        (bytes, config, ticket)
    }

    #[test]
    fn frame_budget_e2big_boundary() {
        let exact = vec![0u8; MAX_COMPOSITE_STATE_LEN - 4 - EXEC_BOUNDARY_RUNTIME_LEN];
        assert!(frame_tool_state(&exact).is_ok());
        let over = vec![0u8; exact.len() + 1];
        let error = frame_tool_state(&over).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::E2BIG));
    }

    #[test]
    fn runtime_split_verify_mutants_refuse_before_decode() {
        let (bytes, config, ticket) = composite();
        let calls = AtomicUsize::new(0);
        for index in [
            bytes.len() - 128,      // magic
            bytes.len() - 128 + 8,  // version
            bytes.len() - 128 + 12, // flags
            bytes.len() - 128 + 16, // framed len
            bytes.len() - 128 + 20, // reserved
            bytes.len() - 128 + 24, // ordinal
            bytes.len() - 128 + 32, // config digest
            bytes.len() - 128 + 64, // tool digest
            bytes.len() - 128 + 96, // ticket digest
            0,                      // frame len
            6,                      // tool bytes (tool digest mismatch)
        ] {
            let mut mutant = bytes.clone();
            mutant[index] ^= 1;
            assert!(
                verify_and_split_runtime(
                    &mutant,
                    config,
                    crate::initial_image::config_digest(&ticket.0),
                )
                .is_err(),
                "byte {index}"
            );
        }
        // The split helper must not invoke decode on a bad frame.
        let mut bad = bytes.clone();
        bad[bytes.len() - 128] ^= 1;
        let request = SuccessorRequest {
            ticket: &ticket.0,
            expected: ExpectedSuccessor {
                config,
                state: config_digest(&bad),
            },
        };
        let verified = VerifiedSuccessorState::from_checked_frame(request, bad).unwrap();
        let packet = ExpectedSuccessor {
            config,
            state: verified.expected().state,
        };
        assert!(
            verify_split_and_decode(&verified, packet, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // Good frame decodes exactly once, after verification.
        let request = SuccessorRequest {
            ticket: &ticket.0,
            expected: ExpectedSuccessor {
                config,
                state: config_digest(&bytes),
            },
        };
        let verified = VerifiedSuccessorState::from_checked_frame(request, bytes).unwrap();
        let (_runtime, decoded) = verify_split_and_decode(
            &verified,
            ExpectedSuccessor {
                config,
                state: verified.expected().state,
            },
            |exec_state| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(exec_state.to_vec())
            },
        )
        .unwrap();
        assert_eq!(decoded, b"exec-state-bytes");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
