/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Tool-agnostic native-exec ticket registry (W6b N1).
//!
//! Generalized from Hermit's Detcore ticket registry
//! (`detcore/src/tool_global/native_exec.rs`, read at a433ca4fd0):
//! same lifecycle (prepare → seal → issue → redeem → complete, with
//! cancel/failed/died terminals), same single-live-transition and
//! consume-before-send rules, new ticket domain so generic and
//! Detcore tickets can never collide. Identity/policy specifics
//! (mm/files generations, catalog qualification, determinism
//! receipts) stay with the embedder behind [`TicketProof`] and the
//! retained binding payload `B`.
//!
//! The coordinator must serialize registry calls (Hermit's contract:
//! same mutex for RPC, admission, and watcher callbacks). No socket
//! EOF calls [`ExecTicketRegistry::died`]: actual death only.

use std::collections::BTreeMap;
use std::fmt;
use std::os::fd::OwnedFd;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

/// Maximum retained transactions (Hermit parity).
pub const MAX_TRANSITIONS: usize = 1024;
/// Maximum tool snapshot bytes retained at prepare.
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
/// Maximum sealed state bytes (header + tool + runtime).
pub const MAX_STATE_BYTES: usize = 1024 * 1024 + 4096;
const TICKET_DOMAIN: &[u8] = b"Reverie native exec ticket v1\0";

/// A protected single-use exec token. Carries no guest-visible data.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ExecTicket(pub [u8; 32]);

impl fmt::Debug for ExecTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExecTicket(<private>)")
    }
}

/// A native control refusal, never a replacement for a kernel errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExecControlError {
    /// No watched native authority was installed.
    Unavailable,
    /// Sender, watched birth, or image incarnation disagrees.
    Identity,
    /// Payload bounds or wire version disagree.
    Bounds,
    /// Actual bytes disagree with a supplied digest.
    Digest,
    /// The requested edge is not legal from the retained state.
    Transition,
    /// A physical death or terminal transport failure was observed.
    Dead,
    /// The bounded retained history cannot accept another transaction.
    Capacity,
    /// Proof/policy qualification was refused.
    Qualification,
}

impl fmt::Display for ExecControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exec control refused: {self:?}")
    }
}
impl std::error::Error for ExecControlError {}

/// Retained transaction stage. Terminal records cannot replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecStage {
    Prepared,
    Issued,
    Redeemed,
    Completed,
    Cancelled,
    Dead,
    Failed,
}

impl ExecStage {
    fn live(self) -> bool {
        matches!(self, Self::Prepared | Self::Issued | Self::Redeemed)
    }
}

/// What the registry retains under a ticket, supplied by the embedder.
pub trait TicketBinding: Clone {
    /// Owner identity (tool/thread-defined, compared by equality).
    type Owner: Copy + Eq;
    /// The transaction owner.
    fn owner(&self) -> Self::Owner;
    /// Digest of the unchanged canonical tool Config.
    fn config_digest(&self) -> [u8; 32];
}

/// Embedder proof hooks (Detcore: physical ids, catalog, receipts).
pub trait TicketProof<B: TicketBinding> {
    /// The single watched owner this registry serves.
    fn owner(&self) -> B::Owner;
    /// The accepted successor stream is the watched birth's peer.
    fn matches_peer(&self, peer: &OwnedFd) -> bool;
    /// Qualify a prepare request (target/catalog policy).
    fn qualify_prepare(&self, binding: &B, snapshot: &[u8]) -> bool;
    /// Qualify sealed runtime bytes.
    fn qualify_runtime(&self, runtime: &[u8]) -> bool;
    /// Qualify completion after redemption.
    fn qualify_completion(&self, ticket: ExecTicket, binding: &B) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProvisionState {
    Fresh,
    Delivered,
}

struct Transition<B> {
    binding: B,
    stage: ExecStage,
    provision: ProvisionState,
    tool: Vec<u8>,
    state: Vec<u8>,
    state_digest: Option<[u8; 32]>,
}

/// Serial retained store for one watched native process birth.
pub struct ExecTicketRegistry<P, B> {
    proof: P,
    nonce: [u8; 32],
    next_ticket: u64,
    transitions: BTreeMap<ExecTicket, Transition<B>>,
    dead: bool,
    terminal_failure: bool,
}

impl<P, B> ExecTicketRegistry<P, B>
where
    B: TicketBinding,
    P: TicketProof<B>,
{
    /// New registry for one watched birth. `nonce` is a secret run
    /// nonce; it never touches deterministic guest state.
    pub fn new(proof: P, nonce: [u8; 32]) -> Self {
        Self {
            proof,
            nonce,
            next_ticket: 0,
            transitions: BTreeMap::new(),
            dead: false,
            terminal_failure: false,
        }
    }

    fn check_owner(&self, owner: B::Owner) -> Result<(), ExecControlError> {
        if self.dead {
            return Err(ExecControlError::Dead);
        }
        if self.terminal_failure {
            return Err(ExecControlError::Unavailable);
        }
        if owner != self.proof.owner() {
            return Err(ExecControlError::Identity);
        }
        Ok(())
    }

    fn transaction(
        &mut self,
        owner: B::Owner,
        ticket: ExecTicket,
    ) -> Result<&mut Transition<B>, ExecControlError> {
        self.check_owner(owner)?;
        let entry = self
            .transitions
            .get_mut(&ticket)
            .ok_or(ExecControlError::Identity)?;
        if entry.binding.owner() != owner {
            return Err(ExecControlError::Identity);
        }
        Ok(entry)
    }

    /// Mint a ticket for a prepared exec. Retains the tool snapshot
    /// (digest-checked) under the ticket; single live transition rule.
    pub fn prepare(
        &mut self,
        owner: B::Owner,
        binding: B,
        snapshot: Vec<u8>,
        snapshot_digest: [u8; 32],
    ) -> Result<ExecTicket, ExecControlError> {
        self.check_owner(owner)?;
        if binding.owner() != owner {
            return Err(ExecControlError::Identity);
        }
        if self.transitions.values().any(|entry| entry.stage.live()) {
            return Err(ExecControlError::Transition);
        }
        if self.transitions.len() >= MAX_TRANSITIONS {
            return Err(ExecControlError::Capacity);
        }
        if snapshot.is_empty() || snapshot.len() > MAX_SNAPSHOT_BYTES {
            return Err(ExecControlError::Bounds);
        }
        if <[u8; 32]>::from(Sha256::digest(&snapshot)) != snapshot_digest {
            return Err(ExecControlError::Digest);
        }
        if !self.proof.qualify_prepare(&binding, &snapshot) {
            return Err(ExecControlError::Qualification);
        }
        let mut hash = Sha256::new();
        hash.update(TICKET_DOMAIN);
        hash.update(self.nonce);
        hash.update(self.next_ticket.to_le_bytes());
        let ticket = ExecTicket(hash.finalize().into());
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(ExecControlError::Capacity)?;
        if self.transitions.contains_key(&ticket) {
            return Err(ExecControlError::Transition);
        }
        self.transitions.insert(
            ticket,
            Transition {
                binding,
                stage: ExecStage::Prepared,
                provision: ProvisionState::Fresh,
                tool: snapshot,
                state: Vec::new(),
                state_digest: None,
            },
        );
        Ok(ticket)
    }

    /// Seal runtime bytes with the retained tool bytes exactly once.
    /// State layout: `tool || runtime` (embedders frame inside tool).
    pub fn seal(
        &mut self,
        owner: B::Owner,
        ticket: ExecTicket,
        runtime_digest: [u8; 32],
        runtime: &[u8],
    ) -> Result<[u8; 32], ExecControlError> {
        self.check_owner(owner)?;
        if runtime.is_empty() || runtime.len() > MAX_STATE_BYTES {
            return Err(ExecControlError::Bounds);
        }
        if <[u8; 32]>::from(Sha256::digest(runtime)) != runtime_digest {
            return Err(ExecControlError::Digest);
        }
        if !self.proof.qualify_runtime(runtime) {
            return Err(ExecControlError::Qualification);
        }
        let entry = self.transaction(owner, ticket)?;
        if entry.stage != ExecStage::Prepared || entry.state_digest.is_some() {
            return Err(ExecControlError::Transition);
        }
        let length = entry
            .tool
            .len()
            .checked_add(runtime.len())
            .ok_or(ExecControlError::Bounds)?;
        if length > MAX_STATE_BYTES {
            return Err(ExecControlError::Bounds);
        }
        let mut state = Vec::with_capacity(length);
        state.extend_from_slice(&entry.tool);
        state.extend_from_slice(runtime);
        let digest: [u8; 32] = Sha256::digest(&state).into();
        entry.tool = Vec::new();
        entry.state = state;
        entry.state_digest = Some(digest);
        Ok(digest)
    }

    /// Mark provision delivered (issue requires it). Hermit's affine
    /// provision object is embedder policy; the registry only needs
    /// the delivered fact, recorded before issue.
    pub fn mark_provision_delivered(
        &mut self,
        owner: B::Owner,
        ticket: ExecTicket,
    ) -> Result<(), ExecControlError> {
        let entry = self.transaction(owner, ticket)?;
        if entry.stage != ExecStage::Prepared {
            return Err(ExecControlError::Transition);
        }
        entry.provision = ProvisionState::Delivered;
        Ok(())
    }

    /// Last old-image edge: sealed + delivered Prepared -> Issued.
    pub fn issue(
        &mut self,
        owner: B::Owner,
        ticket: ExecTicket,
        digest: [u8; 32],
    ) -> Result<(), ExecControlError> {
        let entry = self.transaction(owner, ticket)?;
        if entry.stage != ExecStage::Prepared
            || entry.state_digest != Some(digest)
            || entry.provision != ProvisionState::Delivered
        {
            return Err(ExecControlError::Transition);
        }
        entry.stage = ExecStage::Issued;
        Ok(())
    }

    /// Successor-side view of an issued ticket's binding (no consume).
    pub fn issued_binding(
        &mut self,
        peer: &OwnedFd,
        ticket: ExecTicket,
    ) -> Result<B, ExecControlError> {
        self.check_owner(self.proof.owner())?;
        if !self.proof.matches_peer(peer) {
            return Err(ExecControlError::Identity);
        }
        let entry = self
            .transitions
            .get(&ticket)
            .ok_or(ExecControlError::Identity)?;
        if entry.stage != ExecStage::Issued {
            return Err(ExecControlError::Transition);
        }
        Ok(entry.binding.clone())
    }

    /// Redeem against the accepted successor peer. Consume first:
    /// failed delivery can never make this ticket redeemable again.
    pub fn redeem(
        &mut self,
        peer: &OwnedFd,
        ticket: ExecTicket,
        config_digest: [u8; 32],
        state_digest: [u8; 32],
    ) -> Result<Vec<u8>, ExecControlError> {
        self.check_owner(self.proof.owner())?;
        if !self.proof.matches_peer(peer) {
            return Err(ExecControlError::Identity);
        }
        let entry = self
            .transitions
            .get_mut(&ticket)
            .ok_or(ExecControlError::Identity)?;
        if entry.stage != ExecStage::Issued {
            return Err(ExecControlError::Transition);
        }
        if entry.binding.config_digest() != config_digest
            || entry.state_digest != Some(state_digest)
        {
            return Err(ExecControlError::Digest);
        }
        entry.stage = ExecStage::Redeemed;
        Ok(std::mem::take(&mut entry.state))
    }

    /// Pre-redemption cancellation only.
    pub fn cancel(&mut self, owner: B::Owner, ticket: ExecTicket) -> Result<(), ExecControlError> {
        let entry = self.transaction(owner, ticket)?;
        if !matches!(entry.stage, ExecStage::Prepared | ExecStage::Issued) {
            return Err(ExecControlError::Transition);
        }
        entry.stage = ExecStage::Cancelled;
        entry.tool = Vec::new();
        entry.state = Vec::new();
        Ok(())
    }

    /// Successor reports completed lifecycle/frontend verification.
    pub fn complete(
        &mut self,
        owner: B::Owner,
        ticket: ExecTicket,
    ) -> Result<(), ExecControlError> {
        let binding = {
            let entry = self.transaction(owner, ticket)?;
            if entry.stage != ExecStage::Redeemed {
                return Err(ExecControlError::Transition);
            }
            entry.binding.clone()
        };
        if !self.proof.qualify_completion(ticket, &binding) {
            self.failed(ticket)?;
            return Err(ExecControlError::Qualification);
        }
        self.transitions
            .get_mut(&ticket)
            .expect("retained Redeemed record")
            .stage = ExecStage::Completed;
        Ok(())
    }

    /// Permanently fail this transaction, retaining the tombstone.
    pub fn failed(&mut self, ticket: ExecTicket) -> Result<(), ExecControlError> {
        let entry = self
            .transitions
            .get_mut(&ticket)
            .ok_or(ExecControlError::Identity)?;
        if !entry.stage.live() {
            return Err(ExecControlError::Transition);
        }
        entry.stage = ExecStage::Failed;
        entry.tool = Vec::new();
        entry.state = Vec::new();
        self.terminal_failure = true;
        Ok(())
    }

    /// Called only by actual birth-watch death, never by EOF.
    pub fn died(&mut self) {
        self.dead = true;
        for entry in self.transitions.values_mut().filter(|e| e.stage.live()) {
            entry.stage = ExecStage::Dead;
            entry.tool = Vec::new();
            entry.state = Vec::new();
        }
    }

    /// Retained stage, without mutating anything.
    pub fn stage(&self, ticket: ExecTicket) -> Option<ExecStage> {
        self.transitions.get(&ticket).map(|entry| entry.stage)
    }
}

/// Production [`crate::successor::SuccessorAdmission`] over a shared
/// registry (the exactly-once owner musegate's S-B consumes; launchers
/// must not grow a second ticket store).
pub struct RegistrySuccessorAdmission<P, B> {
    registry: std::sync::Arc<std::sync::Mutex<ExecTicketRegistry<P, B>>>,
}

impl<P, B> RegistrySuccessorAdmission<P, B> {
    /// Wrap the coordinator-owned registry.
    pub fn new(registry: std::sync::Arc<std::sync::Mutex<ExecTicketRegistry<P, B>>>) -> Self {
        Self { registry }
    }
}

impl<P, B> crate::successor::SuccessorAdmission for RegistrySuccessorAdmission<P, B>
where
    B: TicketBinding + Send,
    P: TicketProof<B> + Send,
{
    fn redeem(
        &self,
        peer: OwnedFd,
        _admitted: crate::Admitted,
        request: crate::successor::SuccessorRequest<'_>,
    ) -> std::io::Result<Vec<u8>> {
        let ticket_bytes: [u8; 32] = request.ticket.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "exec ticket length")
        })?;
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .redeem(
                &peer,
                ExecTicket(ticket_bytes),
                request.expected.config,
                request.expected.state,
            )
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
