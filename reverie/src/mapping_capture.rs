/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Completion ownership for a contained mapping observation.
//!
//! This object does not stop or kill a task. The launcher retains its real
//! unreaped child and performs its existing whole-run cleanup before checking
//! completion. Controllers authenticate task, incarnation, address space and
//! procfs authority independently before registering an observation here.

use std::io;
use std::process::Child;
use std::sync::Arc;
use std::sync::Mutex;

use serde::Deserialize;
use serde::Serialize;

use crate::RuntimePrivateMemorySnapshot;

/// A synchronous observation request prepared outside the backend's excluded
/// interval. It is consumed once; the controller token must name the same
/// ownership snapshot used by the shared projection.
pub struct PreparedMappingCapture<Request> {
    token: MappingCaptureToken,
    private: RuntimePrivateMemorySnapshot,
    request: Request,
}

impl<Request> PreparedMappingCapture<Request> {
    /// Bind a controller-authorized request to its exact private owner. This
    /// validates equality only; the backend/controller must authenticate the
    /// installed token and current opened target independently.
    pub fn new(
        token: MappingCaptureToken,
        private: RuntimePrivateMemorySnapshot,
        request: Request,
    ) -> Result<Self, MappingCaptureError> {
        if token.nonce == 0
            || token.identity.private_owner != private.owner
            || token.identity.private_version != private.version
        {
            return Err(MappingCaptureError::Identity);
        }
        Ok(Self {
            token,
            private,
            request,
        })
    }

    /// Consume the prepared request for a backend's fixed native operation.
    pub fn into_parts(self) -> (MappingCaptureToken, RuntimePrivateMemorySnapshot, Request) {
        (self.token, self.private, self.request)
    }
}

/// Capture failure, never a guest Linux errno or an accepted partial view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MappingCaptureError {
    /// Backend, Tool, target or native executor domain is not supported.
    #[error("coherent mapping capture is unavailable for this runtime domain")]
    Unavailable,
    /// The prepared identity or ownership fact does not match.
    #[error("mapping capture identity or private ownership changed")]
    Identity,
    /// Existing protected primary connection cannot be borrowed safely.
    #[error("mapping capture primary connection is unavailable")]
    Connection,
    /// Complete request/reply cannot fit or decode under the existing codec.
    #[error("mapping capture framing or capacity validation failed")]
    Frame,
    /// The actual backend control channel did not authorize this Pending token.
    #[error("mapping capture pre-park authorization was refused")]
    Authorization,
    /// Native acquire/exchange deadline expired; no data was accepted.
    #[error("mapping capture exceeded its native failure deadline")]
    Timeout,
    /// Native transport failed after safe restoration.
    #[error("mapping capture native transport failed")]
    Transport,
}

/// Equality bindings supplied by the authenticated controller, not authority
/// reconstructed from numeric process IDs or addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingCaptureIdentity {
    /// Physical root process, authenticated against the launcher's child.
    pub process: i32,
    /// Physical invoking task; the first capture domain requires the root task.
    pub thread: i32,
    /// Controller's task/address-space incarnation, opaque to the launcher.
    pub address_space: [u64; 2],
    /// Backend's current private-memory owner.
    pub private_owner: [u64; 4],
    /// Revision of that owner's authority.
    pub private_version: u64,
}

/// One registered operation. Serialization carries equality bindings only:
/// possession of these fields does not create a launcher or controller grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingCaptureToken {
    /// Non-reused operation number within this installed run object.
    pub nonce: u64,
    /// Exact identity registered for the operation.
    pub identity: MappingCaptureIdentity,
}

#[derive(Debug, Default)]
struct State {
    containment_enabled: bool,
    root: Option<u32>,
    next_nonce: u64,
    pending: Option<MappingCaptureToken>,
    observed: bool,
    authorized: bool,
    failed: bool,
    rejected_view: Option<String>,
    rejected_preparation: Option<String>,
    finished: bool,
}

/// Controller-side capture accounting, with a separately enabled containment
/// capability.
///
/// This must only be installed on the external controller. A guest-local global
/// state must not receive it. A bare runner may install disabled accounting so
/// a refused request remains a run failure, but cannot prepare or authorize a
/// capture. It owns no process and provides no process-signaling interface.
#[derive(Debug, Clone)]
pub struct MappingCaptureRun(Arc<Mutex<State>>);

/// Launcher-owned completion check. The launcher must retain the actual child
/// identity through its normal wait and any enabled whole-run cleanup and call
/// [`Self::finish`] before returning a guest status. Dropping this owner
/// invalidates the controller capability.
#[derive(Debug)]
pub struct MappingCaptureRunOwner(Arc<Mutex<State>>);

impl MappingCaptureRunOwner {
    /// Create a run object only after selecting enabled containment that cannot
    /// be escaped by the observed guest. This operation does not enable cleanup.
    pub fn new() -> (Self, MappingCaptureRun) {
        Self::with_containment(true)
    }

    /// Retain capture refusals without enabling containment or native capture.
    /// Ordinary runs that never request a capture remain ordinary guest exits.
    pub fn disabled() -> (Self, MappingCaptureRun) {
        Self::with_containment(false)
    }

    fn with_containment(containment_enabled: bool) -> (Self, MappingCaptureRun) {
        let state = Arc::new(Mutex::new(State {
            containment_enabled,
            ..State::default()
        }));
        (Self(Arc::clone(&state)), MappingCaptureRun(state))
    }

    /// Bind the actual spawned child before releasing configuration readiness.
    /// The caller must keep this child unreaped until its existing cleanup has
    /// used that identity. A second binding is a run failure.
    pub fn bind_root(&self, child: &Child) -> io::Result<()> {
        let mut state = self.0.lock().map_err(|_| capture_failed())?;
        if state.root.is_some() || state.finished || child.id() == 0 {
            state.failed = true;
            return Err(capture_failed());
        }
        state.root = Some(child.id());
        Ok(())
    }

    /// Check after the real child wait and any enabled owned-tree cleanup. A
    /// Pending/Failed observation is a backend failure even when its numeric
    /// exit status is otherwise permitted by the guest's contract.
    pub fn finish(&self) -> io::Result<()> {
        let mut state = self.0.lock().map_err(|_| capture_failed())?;
        let valid = !state.finished && !state.failed && state.pending.is_none();
        state.finished = true;
        state.root = None;
        if valid {
            Ok(())
        } else if let Some(reason) = &state.rejected_preparation {
            Err(io::Error::other(format!(
                "mapping capture was refused before preparation: {reason}"
            )))
        } else if let Some(reason) = &state.rejected_view {
            Err(io::Error::other(format!(
                "contained mapping capture view was rejected after restoration: {reason}"
            )))
        } else {
            Err(io::Error::other(format!(
                "contained mapping capture did not complete restoration (phase={})",
                if state.observed {
                    "controller-read"
                } else {
                    "prepared"
                }
            )))
        }
    }
}

impl Drop for MappingCaptureRunOwner {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.finished = true;
            state.root = None;
        }
    }
}

impl MappingCaptureRun {
    /// Whether the launcher installed actual containment authority. Disabled
    /// accounting never grants permission to prepare or park an executor.
    pub fn containment_enabled(&self) -> bool {
        self.0.lock().is_ok_and(|state| state.containment_enabled)
    }

    /// Preserve the controller's first pre-Prepare refusal independently of a
    /// later guest exit code. This records failure only; it grants no authority.
    pub fn reject_preparation(&self, reason: &str) {
        if let Ok(mut state) = self.0.lock() {
            state.failed = true;
            state
                .rejected_preparation
                .get_or_insert_with(|| reason.to_owned());
        }
    }

    /// Register an operation after the controller has authenticated its caller
    /// and retained the existing serial grant. The initial domain is the exact
    /// launch-root task, never a foreign/non-root address space.
    pub fn prepare(&self, identity: MappingCaptureIdentity) -> Option<MappingCaptureToken> {
        let mut state = self.0.lock().ok()?;
        if !state.containment_enabled
            || state.finished
            || state.failed
            || state.pending.is_some()
            || identity.process <= 0
            || identity.thread != identity.process
            || state.root != Some(identity.process as u32)
        {
            return None;
        }
        let Some(nonce) = state.next_nonce.checked_add(1) else {
            state.failed = true;
            return None;
        };
        state.next_nonce = nonce;
        let token = MappingCaptureToken { nonce, identity };
        state.pending = Some(token);
        state.observed = false;
        state.authorized = false;
        Some(token)
    }

    /// Validate a pending request under the controller's separate current-task
    /// and address-space checks. This is not a replacement for those checks.
    pub fn is_pending(&self, token: MappingCaptureToken) -> bool {
        self.0
            .lock()
            .is_ok_and(|state| !state.finished && !state.failed && state.pending == Some(token))
    }

    /// Authorize once on the backend-owned control channel before any native
    /// park. `peer` is the kernel-authenticated connecting process in the same
    /// namespace as the launcher's retained Child, never a request's sender ID.
    pub fn authorize(&self, token: MappingCaptureToken, peer: i32) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if !state.containment_enabled
            || state.finished
            || state.failed
            || state.pending != Some(token)
            || state.authorized
            || state.observed
            || peer <= 0
            || state.root != Some(peer as u32)
            || token.identity.process != peer
        {
            return false;
        }
        state.authorized = true;
        true
    }

    /// Mark the exact first controller read while the backend's synchronous
    /// interval is active. This provides a failure phase, not an exclusion
    /// certificate; the controller must still validate the opened target.
    pub fn begin_observation(&self, token: MappingCaptureToken) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if state.finished
            || state.failed
            || state.pending != Some(token)
            || state.observed
            || !state.authorized
        {
            return false;
        }
        state.observed = true;
        true
    }

    /// Complete only after native restoration, transport release and caller
    /// mask restoration succeeded. A failed/stale completion poisons the run;
    /// it cannot clear another request or turn failure into a successful exit.
    pub fn complete(&self, token: MappingCaptureToken, restored: bool) -> bool {
        self.complete_observation(token, restored, None)
    }

    /// Record a view/projection refusal after the backend has restored its
    /// executors, released transport and restored the caller's mask. This is
    /// still a backend failure, but not a claim that restoration failed.
    /// `reason` must be a controller/projector diagnostic, never captured bytes.
    pub fn reject_restored(&self, token: MappingCaptureToken, reason: &str) -> bool {
        self.complete_observation(token, true, Some(reason))
    }

    fn complete_observation(
        &self,
        token: MappingCaptureToken,
        restored: bool,
        rejection: Option<&str>,
    ) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if state.finished
            || state.failed
            || state.pending != Some(token)
            || !state.observed
            || !restored
        {
            state.failed = true;
            return false;
        }
        state.pending = None;
        if let Some(reason) = rejection {
            state.failed = true;
            state.rejected_view = Some(reason.to_owned());
        }
        true
    }
}

fn capture_failed() -> io::Error {
    io::Error::other("contained mapping capture did not complete restoration")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> (
        MappingCaptureRunOwner,
        MappingCaptureRun,
        MappingCaptureIdentity,
    ) {
        let (owner, controller) = MappingCaptureRunOwner::new();
        // This unit exercises completion accounting, not native containment.
        owner.0.lock().unwrap().root = Some(42);
        let identity = MappingCaptureIdentity {
            process: 42,
            thread: 42,
            address_space: [3, 1],
            private_owner: [1, 2, 3, 4],
            private_version: 1,
        };
        (owner, controller, identity)
    }

    #[test]
    fn disabled_accounting_never_authorizes_a_capture_or_changes_an_unused_run() {
        let (_, _, identity) = bound();
        let (owner, controller) = MappingCaptureRunOwner::disabled();
        owner.0.lock().unwrap().root = Some(42);
        assert!(!controller.containment_enabled());
        assert!(controller.prepare(identity).is_none());
        let forged = MappingCaptureToken { nonce: 1, identity };
        assert!(!controller.authorize(forged, 42));
        assert!(!controller.is_pending(forged));
        assert!(owner.finish().is_ok());
    }

    #[test]
    fn preparation_refusal_is_retained_without_a_pending_capture() {
        for enabled in [false, true] {
            let (owner, controller) = MappingCaptureRunOwner::with_containment(enabled);
            controller.reject_preparation("first preparation refusal");
            controller.reject_preparation("later refusal");
            assert_eq!(
                owner.finish().unwrap_err().to_string(),
                "mapping capture was refused before preparation: first preparation refusal"
            );
        }
    }

    #[test]
    fn pending_capture_cannot_become_a_successful_guest_exit() {
        let (owner, controller, identity) = bound();
        assert!(controller.prepare(identity).is_some());
        assert!(owner.finish().is_err());
    }

    #[test]
    fn rejected_view_remains_a_failure_after_successful_restoration() {
        let (owner, controller, identity) = bound();
        let token = controller.prepare(identity).unwrap();
        assert!(controller.authorize(token, 42));
        assert!(controller.begin_observation(token));
        assert!(controller.reject_restored(token, "reader root differs"));
        assert!(!controller.is_pending(token));
        assert!(controller.prepare(identity).is_none());
        assert_eq!(
            owner.finish().unwrap_err().to_string(),
            "contained mapping capture view was rejected after restoration: reader root differs"
        );
    }

    #[test]
    fn completion_requires_the_exact_restored_operation() {
        let (owner, controller, identity) = bound();
        let first = controller.prepare(identity).unwrap();
        assert!(!controller.begin_observation(first));
        assert!(controller.authorize(first, 42));
        assert!(!controller.authorize(first, 42));
        assert!(controller.begin_observation(first));
        assert!(!controller.begin_observation(first));
        assert!(controller.complete(first, true));
        let second = controller.prepare(identity).unwrap();
        assert_ne!(first.nonce, second.nonce);
        assert!(!controller.complete(first, true));
        assert!(!controller.complete(second, true));
        assert!(owner.finish().is_err());
    }

    #[test]
    fn unavailable_foreign_and_finished_roots_do_not_register() {
        let (owner, controller, mut identity) = bound();
        identity.process = 43;
        identity.thread = 43;
        assert!(controller.prepare(identity).is_none());
        identity.process = 42;
        identity.thread = 42;
        let token = controller.prepare(identity).unwrap();
        assert!(controller.is_pending(token));
        assert!(controller.authorize(token, 42));
        assert!(controller.begin_observation(token));
        assert!(controller.complete(token, true));
        assert!(owner.finish().is_ok());
        assert!(controller.prepare(identity).is_none());
    }
}
