/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Explicit Tool lifecycle receipts on an existing configuration-bearing RPC stream.
//!
//! These reserved control frames never invoke a GlobalTool request. The launcher
//! binds its actual child before serving Config and must separately join the
//! completed receipt with that child's actual waited status. This is provenance
//! for a cooperating runtime, not authentication of hostile in-process code.

use std::sync::Arc;
use std::sync::Mutex;

use crate::RpcError;
use crate::initial_image::ConfigDigest;

/// Exact V2 payload size, excluding the existing big-endian u32 frame header.
pub const FRAME_LEN: usize = 48;
const PREFIX: [u8; 4] = [0xff; 4];

/// Native terminal operation whose consuming hooks completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitScope {
    /// `exit(2)` (syscall 60 on x86-64).
    Exit,
    /// `exit_group(2)` (syscall 231 on x86-64).
    ExitGroup,
}

/// Whether the terminal operation was the original or a deferred operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitOrigin {
    /// Original intercepted terminal operation.
    Original,
    /// Terminal operation explicitly deferred by the Tool.
    Deferred,
}

/// Finite, validated explicit normal-exit fact. This does not prove kernel exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinishedReceipt {
    code: u8,
    scope: ExitScope,
    origin: ExitOrigin,
}

impl FinishedReceipt {
    /// Construct an explicit normal-exit receipt from a supported native syscall.
    pub fn explicit_exit(code: u8, syscall: i64, origin: ExitOrigin) -> Result<Self, RpcError> {
        let scope = match syscall {
            60 => ExitScope::Exit,
            231 => ExitScope::ExitGroup,
            _ => return Err(invalid("Tool Finished requires exit or exit_group")),
        };
        Ok(Self {
            code,
            scope,
            origin,
        })
    }

    /// Exit code after the normal Linux eight-bit mask.
    pub fn exit_code(self) -> u8 {
        self.code
    }

    /// Scope of the actual terminal operation.
    pub fn scope(self) -> ExitScope {
        self.scope
    }

    /// Origin of the actual terminal operation.
    pub fn origin(self) -> ExitOrigin {
        self.origin
    }

    /// x86-64 Linux syscall number matching the encoded scope.
    pub fn syscall(self) -> i64 {
        match self.scope {
            ExitScope::Exit => 60,
            ExitScope::ExitGroup => 231,
        }
    }

    fn trailer(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[0] = 1; // Exited only; signal status is never fabricated.
        bytes[1] = self.code;
        bytes[2] = match self.scope {
            ExitScope::Exit => 1,
            ExitScope::ExitGroup => 2,
        };
        bytes[3] = match self.origin {
            ExitOrigin::Original => 1,
            ExitOrigin::Deferred => 2,
        };
        bytes[4..].copy_from_slice(&(self.syscall() as u32).to_be_bytes());
        bytes
    }

    fn from_trailer(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.len() != 8 || bytes[0] != 1 {
            return Err(invalid("invalid Tool Finished status"));
        }
        let scope = match bytes[2] {
            1 => ExitScope::Exit,
            2 => ExitScope::ExitGroup,
            _ => return Err(invalid("invalid Tool Finished scope")),
        };
        let origin = match bytes[3] {
            1 => ExitOrigin::Original,
            2 => ExitOrigin::Deferred,
            _ => return Err(invalid("invalid Tool Finished origin")),
        };
        let syscall = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as i64;
        let receipt = Self::explicit_exit(bytes[1], syscall, origin)?;
        if receipt.scope != scope {
            return Err(invalid("Tool Finished scope and syscall differ"));
        }
        Ok(receipt)
    }
}

/// Role controls sent on the exclusively borrowed, Config-consumed primary stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolControl {
    /// Claim the one primary connection from the launcher's bound physical root.
    Claim {
        /// Digest of the exact Config payload received on this connection.
        digest: ConfigDigest,
    },
    /// Tool installation and startup hooks completed before guest execution.
    Started {
        /// Same exact Config digest as Claim.
        digest: ConfigDigest,
    },
    /// Both consuming hooks completed before forwarding the terminal operation.
    Finished {
        /// Same exact Config digest as Claim.
        digest: ConfigDigest,
        /// Explicit normal-exit fact, still requiring the launcher's actual wait.
        receipt: FinishedReceipt,
    },
}

impl ToolControl {
    fn digest(self) -> ConfigDigest {
        match self {
            Self::Claim { digest } | Self::Started { digest } | Self::Finished { digest, .. } => {
                digest
            }
        }
    }

    pub(crate) fn encode(self) -> [u8; FRAME_LEN] {
        let mut bytes = [0; FRAME_LEN];
        bytes[..4].copy_from_slice(&PREFIX);
        bytes[4..7].copy_from_slice(b"TA\x02");
        bytes[7] = match self {
            Self::Claim { .. } => 1,
            Self::Started { .. } => 3,
            Self::Finished { receipt, .. } => {
                bytes[40..].copy_from_slice(&receipt.trailer());
                5
            }
        };
        bytes[8..40].copy_from_slice(&self.digest());
        bytes
    }

    pub(crate) fn acknowledgement(self) -> [u8; FRAME_LEN] {
        let mut bytes = self.encode();
        bytes[7] += 1;
        bytes
    }

    pub(crate) fn check_ack(self, bytes: &[u8]) -> Result<(), RpcError> {
        if bytes != self.acknowledgement().as_slice() {
            return Err(invalid(
                "Tool control acknowledgement is not the exact V2 echo",
            ));
        }
        Ok(())
    }
}

/// Detect the reserved family before any application envelope decoding. Even
/// malformed/unknown versions in the family must never become a unit request.
pub(crate) fn decode_request(bytes: &[u8]) -> Result<Option<ToolControl>, RpcError> {
    if !bytes.starts_with(&PREFIX) {
        return Ok(None);
    }
    if bytes.len() != FRAME_LEN || &bytes[4..7] != b"TA\x02" {
        return Err(invalid("invalid Tool control V2 header or length"));
    }
    let digest = bytes[8..40].try_into().unwrap();
    let control = match bytes[7] {
        1 | 3 if bytes[40..] != [0; 8] => {
            return Err(invalid("nonterminal Tool control has a trailer"));
        }
        1 => ToolControl::Claim { digest },
        3 => ToolControl::Started { digest },
        5 => ToolControl::Finished {
            digest,
            receipt: FinishedReceipt::from_trailer(&bytes[40..])?,
        },
        _ => return Err(invalid("invalid Tool control request kind")),
    };
    Ok(Some(control))
}

pub(crate) fn invalid(message: &'static str) -> RpcError {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Primary {
    connection: usize,
    digest: ConfigDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    AwaitingRoot,
    AwaitingClaim,
    Pending {
        primary: Primary,
        control: ToolControl,
    },
    Claimed(Primary),
    StartedAckCommitted(Primary),
    FinishedAckCommitted(Primary, FinishedReceipt),
    Failed(&'static str),
}

struct RunState {
    root: Option<i32>,
    next_connection: usize,
    applications: usize,
    phase: Phase,
}

impl RunState {
    fn fail(&mut self, message: &'static str) -> RpcError {
        let message = match self.phase {
            Phase::Failed(first) => first,
            _ => {
                self.phase = Phase::Failed(message);
                message
            }
        };
        invalid(message)
    }

    fn primary(&self) -> Option<Primary> {
        match self.phase {
            Phase::Pending { primary, .. }
            | Phase::Claimed(primary)
            | Phase::StartedAckCommitted(primary)
            | Phase::FinishedAckCommitted(primary, _) => Some(primary),
            _ => None,
        }
    }
}

/// Launcher-owned, cloneable observation of one explicitly bound Tool lifecycle.
#[derive(Clone)]
pub struct ActivationRun {
    state: Arc<Mutex<RunState>>,
}

impl Default for ActivationRun {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivationRun {
    /// Begin an unbound run. No Config may be served until `bind_root` succeeds.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RunState {
                root: None,
                next_connection: 0,
                applications: 0,
                phase: Phase::AwaitingRoot,
            })),
        }
    }

    /// Bind the actual launcher child once, before serving any Config.
    pub fn bind_root(&self, pid: i32) -> Result<(), RpcError> {
        let mut state = self.state.lock().unwrap();
        if pid <= 0 || state.root.is_some() || state.phase != Phase::AwaitingRoot {
            return Err(state.fail("Tool activation root must be bound exactly once before Config"));
        }
        state.root = Some(pid);
        state.phase = Phase::AwaitingClaim;
        Ok(())
    }

    /// Return immediately with a receipt only after both complete ack writes.
    /// The launcher must still compare its actual waited normal exit and code.
    pub fn completed(&self) -> Result<FinishedReceipt, RpcError> {
        match self.state.lock().unwrap().phase {
            Phase::FinishedAckCommitted(_, receipt) => Ok(receipt),
            Phase::Failed(message) => Err(invalid(message)),
            _ => Err(invalid(
                "Tool activation lacks committed Started and Finished acknowledgements",
            )),
        }
    }

    pub(crate) fn fail(&self, message: &'static str) {
        self.state.lock().unwrap().fail(message);
    }

    // Called only with the kernel peer PID from the actual accepted socket.
    pub(crate) fn accepted(&self, peer: i32) -> Result<ActivationConnection, RpcError> {
        let mut state = self.state.lock().unwrap();
        match state.phase {
            Phase::AwaitingRoot => {
                return Err(state.fail("Tool activation Config before root binding"));
            }
            Phase::FinishedAckCommitted(..) => {
                return Err(state.fail("Tool connection after Finished"));
            }
            Phase::Failed(message) => return Err(invalid(message)),
            _ => {}
        }
        let Some(connection) = state.next_connection.checked_add(1) else {
            return Err(state.fail("Tool connection identity exhausted"));
        };
        state.next_connection = connection;
        Ok(ActivationConnection {
            run: self.clone(),
            connection,
            peer,
            digest: None,
            closed_cleanly: false,
        })
    }
}

pub(crate) struct ActivationConnection {
    run: ActivationRun,
    connection: usize,
    peer: i32,
    digest: Option<ConfigDigest>,
    closed_cleanly: bool,
}

impl ActivationConnection {
    pub(crate) fn config(&mut self, bytes: &[u8]) {
        self.digest = Some(crate::initial_image::config_digest(bytes));
    }

    pub(crate) fn fail(&self) {
        self.run
            .fail("Tool activation connection protocol, I/O or cancellation failure");
    }

    pub(crate) fn closed(&mut self) -> Result<(), RpcError> {
        let mut state = self.run.state.lock().unwrap();
        if let Phase::Failed(message) = state.phase {
            return Err(invalid(message));
        }
        if state
            .primary()
            .is_some_and(|p| p.connection == self.connection)
            && !matches!(state.phase, Phase::FinishedAckCommitted(..))
        {
            return Err(state.fail("claimed Tool primary closed before FinishedAck committed"));
        }
        self.closed_cleanly = true;
        Ok(())
    }

    pub(crate) fn before_application(&self) -> Result<(), RpcError> {
        let mut state = self.run.state.lock().unwrap();
        match state.phase {
            Phase::FinishedAckCommitted(..)
            | Phase::Pending {
                control: ToolControl::Finished { .. },
                ..
            } => Err(state.fail("application request after Tool Finished")),
            Phase::Failed(message) => Err(invalid(message)),
            _ => Ok(()),
        }
    }

    pub(crate) fn application(&self, sender: i32) -> Result<ApplicationDispatch, RpcError> {
        let mut state = self.run.state.lock().unwrap();
        match state.phase {
            Phase::FinishedAckCommitted(..)
            | Phase::Pending {
                control: ToolControl::Finished { .. },
                ..
            } => {
                return Err(state.fail("application dispatch after Tool Finished"));
            }
            Phase::Failed(message) => return Err(invalid(message)),
            _ => {}
        }
        if state
            .primary()
            .is_some_and(|p| p.connection == self.connection)
            && state.root != Some(sender)
        {
            return Err(state.fail("Tool primary application sender differs from bound root"));
        }
        let Some(applications) = state.applications.checked_add(1) else {
            return Err(state.fail("Tool application dispatch count exhausted"));
        };
        state.applications = applications;
        Ok(ApplicationDispatch(self.run.clone()))
    }

    pub(crate) fn stage(&self, control: ToolControl) -> Result<PendingAck, RpcError> {
        let mut state = self.run.state.lock().unwrap();
        if let Phase::Failed(message) = state.phase {
            return Err(invalid(message));
        }
        if state.root != Some(self.peer) || self.digest != Some(control.digest()) {
            return Err(state.fail("Tool control physical root or exact Config digest mismatch"));
        }
        if matches!(control, ToolControl::Finished { .. }) && state.applications != 0 {
            return Err(state.fail("Tool Finished while an application RPC remains in flight"));
        }
        let primary = Primary {
            connection: self.connection,
            digest: control.digest(),
        };
        let valid = match (state.phase, control) {
            (Phase::AwaitingClaim, ToolControl::Claim { .. }) => true,
            (Phase::Claimed(current), ToolControl::Started { .. })
            | (Phase::StartedAckCommitted(current), ToolControl::Finished { .. }) => {
                current == primary
            }
            _ => false,
        };
        if !valid {
            return Err(state.fail("duplicate, wrong-stream or out-of-order Tool control"));
        }
        state.phase = Phase::Pending { primary, control };
        Ok(PendingAck {
            run: self.run.clone(),
            primary,
            control,
            committed: false,
        })
    }
}

impl Drop for ActivationConnection {
    fn drop(&mut self) {
        let mut state = self.run.state.lock().unwrap();
        if !self.closed_cleanly && !matches!(state.phase, Phase::FinishedAckCommitted(..)) {
            state.fail("Tool connection dropped without clean protocol completion");
        }
    }
}

// Reserve dispatch under the same state lock as Finished. This prevents an
// already-read request on another socket from entering G after FinishedAck.
pub(crate) struct ApplicationDispatch(ActivationRun);

impl Drop for ApplicationDispatch {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.applications -= 1;
    }
}

pub(crate) struct PendingAck {
    run: ActivationRun,
    primary: Primary,
    control: ToolControl,
    committed: bool,
}

impl PendingAck {
    pub(crate) fn commit(mut self) -> Result<(), RpcError> {
        let mut state = self.run.state.lock().unwrap();
        if state.phase
            != (Phase::Pending {
                primary: self.primary,
                control: self.control,
            })
        {
            return Err(state.fail("Tool acknowledgement cannot commit after protocol failure"));
        }
        state.phase = match self.control {
            ToolControl::Claim { .. } => Phase::Claimed(self.primary),
            ToolControl::Started { .. } => Phase::StartedAckCommitted(self.primary),
            ToolControl::Finished { receipt, .. } => {
                Phase::FinishedAckCommitted(self.primary, receipt)
            }
        };
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingAck {
    fn drop(&mut self) {
        if !self.committed {
            self.run
                .fail("Tool acknowledgement write did not commit completely");
        }
    }
}
