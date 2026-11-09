// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Supervisor bridge between the exec-stop watched supervisor and
//! the coordinator-side
//! [`BirthAuthority`](reverie_rpc_transport::birth_authority::BirthAuthority).
//!
//! The bridge owns the sequencing the authority cannot see: a
//! caught exec stop becomes an authority stop record with that
//! incarnation's retained birth pidfd, stamping and issue happen
//! while the successor is still stopped, and the terminal verdict
//! (`record_watch_terminal` + `finish`, each exactly once) is
//! taken on every exit path. It never synthesizes a stop from
//! EOF, RPC, or a timer: only `WatchedStep::Exec` records one.
//!
//! Physical preparation (copied inputs, mapping, filters) stays
//! the caller's hook work on the retained stop; this module does
//! not seal, map, admit, or resume anything by itself.

use std::sync::Arc;

use reverie_rpc_transport::Admitted;
use reverie_rpc_transport::birth_authority::BirthAuthority;
use reverie_rpc_transport::birth_authority::StampedPacket;
use reverie_rpc_transport::birth_authority::SuccessorStop as BirthStop;
use reverie_rpc_transport::exec_ticket::ExecControlError;
use reverie_rpc_transport::exec_ticket::ExecTicket;
use reverie_rpc_transport::successor::ExpectedSuccessor;

use super::ChildOwner;
use super::CleanupReceipt;
use super::CleanupState;
use super::LaunchFailure;
use super::child::PreparedExec;
use super::physical::BootstrapEntryCoordinates;
use super::physical::EntryCoordinates;
use super::supervisor::DetachedSupervisor;
use super::supervisor::SuccessorStop;
use super::supervisor::Supervisor;
use super::supervisor::WatchedOutcome;
use super::supervisor::WatchedStep;
use super::supervisor::WatchedSupervisor;

/// How this birth's initial image is consumed. The two paths are
/// mutually exclusive for one birth: whichever happens first sets
/// the authority's one-use initial fact, and the other then
/// refuses with a transition error. The choice is part of the
/// bridge configuration so a launch states its single path at
/// construction.
#[derive(Clone, Debug)]
pub enum InitialMode {
    /// The first image redeems through the ordinary InitialImage
    /// RPC with exactly these issued redemption bytes;
    /// `record_mapped_initial_consumed` refuses by name on this
    /// route.
    RpcRedeemed {
        /// Exact initial redemption bytes issued for the first image.
        initial_redemption: Vec<u8>,
    },
    /// No InitialImage RPC occurs; the host calls
    /// `record_mapped_initial_consumed` exactly once after
    /// verified first-image admission. The bridge generates a
    /// never-issued internal redemption so no Initial RPC can
    /// consume first.
    HostConsumed,
}

impl InitialMode {
    fn is_host_consumed(&self) -> bool {
        matches!(self, Self::HostConsumed)
    }
}

/// Birth-authority construction inputs known before spawn. The
/// watched child's pid (and therefore `Admitted`) exists only
/// after `spawn_watched`, so the bridge constructs the authority
/// itself from these inputs plus the seized child's identity.
/// `config_digest` must be
/// `reverie_rpc_transport::initial_image::config_digest` of the
/// exact encoded config of the `RpcServer` that will call
/// `set_birth_authority`; a mismatch fails closed at redeem.
#[derive(Clone, Debug)]
pub struct BridgeConfig {
    /// Digest of the server's canonical config bytes.
    pub config_digest: [u8; 32],
    /// Per-birth registry nonce; must be nonzero.
    pub registry_nonce: [u8; 32],
    /// Which single path consumes the initial image.
    pub initial: InitialMode,
}

/// Bridge failure: either the supervisor's own launch failure
/// (child cleanup authority retained inside it), or a terminal
/// outcome whose birth verdict failed.
#[derive(Debug)]
pub enum BridgeError<'fd> {
    /// Supervisor-side failure; cleanup authority is retained in
    /// the launch failure when retirement is unconfirmed.
    Launch(LaunchFailure<'fd>),
    /// The watched run finished, but the birth verdict
    /// (record_watch_terminal + finish) failed. The outcome is
    /// retained; the launch must be treated as failed.
    Verdict {
        /// The retained terminal outcome.
        outcome: WatchedOutcome,
        /// The first verdict error.
        error: ExecControlError,
    },
}

impl std::fmt::Display for BridgeError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Launch(failure) => failure.error.fmt(f),
            Self::Verdict { error, .. } => {
                write!(f, "birth verdict failed after terminal outcome: {error}")
            }
        }
    }
}

impl std::error::Error for BridgeError<'_> {}

struct BridgeCore {
    authority: Arc<BirthAuthority>,
    admitted: Admitted,
    config_digest: [u8; 32],
    initial: InitialMode,
    receipt: CleanupReceipt,
}

impl BridgeCore {
    /// Terminal fact established: record it, then take the
    /// finish verdict. Both run exactly once on this path; the
    /// first error wins.
    fn verdict_terminal(&self) -> Result<(), ExecControlError> {
        let recorded = self.authority.record_watch_terminal();
        let finished = self.authority.finish();
        recorded.and(finished)
    }

    /// No terminal fact was established: only the finish verdict
    /// runs, so still-pending EOFs refuse visibly.
    fn verdict_without_terminal(&self) -> Result<(), ExecControlError> {
        self.authority.finish()
    }

    fn record_mapped_initial_consumed(&self) -> Result<(), ExecControlError> {
        if !self.initial.is_host_consumed() {
            return Err(ExecControlError::Transition);
        }
        self.authority.record_initial_consumed(self.admitted)
    }

    /// Verdict for an error path, chosen by whether cleanup
    /// confirmed the child's death.
    fn verdict_for_cleanup(&self, confirmed: bool) -> Result<(), ExecControlError> {
        if confirmed {
            self.verdict_terminal()
        } else {
            self.verdict_without_terminal()
        }
    }

    fn launch_failure<'fd>(
        &self,
        error: Box<dyn std::error::Error>,
        owner: Option<Box<ChildOwner<'fd>>>,
        parent_stdio: Option<reverie::process::ParentStdio>,
    ) -> BridgeError<'fd> {
        BridgeError::Launch(LaunchFailure {
            error,
            receipt: self.receipt.clone(),
            owner,
            pending: None,
            parent_stdio,
        })
    }

    /// Chain a verdict attempt onto an existing launch failure:
    /// run the verdict for the failure's cleanup state and fold
    /// any verdict error into the message, first error first.
    fn chain_verdict<'fd>(&self, mut failure: LaunchFailure<'fd>) -> BridgeError<'fd> {
        let confirmed = failure.cleanup().confirmed;
        if let Err(verdict) = self.verdict_for_cleanup(confirmed) {
            failure.error =
                format!("{}; birth verdict also failed: {verdict}", failure.error).into();
        }
        BridgeError::Launch(failure)
    }

    /// Cancel a retained stop after an authority-side failure and
    /// take the verdict for its cleanup state. The successor is
    /// never released on this path.
    fn fail_stop<'fd>(
        &self,
        mut stop: SuccessorStop<'fd>,
        primary: Box<dyn std::error::Error>,
    ) -> BridgeError<'fd> {
        let parent_stdio = stop.take_parent_stdio();
        let (confirmed, owner) = match stop.cancel() {
            Ok(state) => (state.confirmed, None),
            Err(owner) => (false, Some(owner)),
        };
        match self.verdict_for_cleanup(confirmed) {
            Ok(()) => self.launch_failure(primary, owner, parent_stdio),
            Err(verdict) => self.launch_failure(
                format!("{primary}; birth verdict also failed: {verdict}").into(),
                owner,
                parent_stdio,
            ),
        }
    }
}

/// The exactly-once terminal verdict duty after a detached
/// release. Its three consuming methods are
/// `record_detached_outcome`, `record_released_status` (both
/// only on a confirmed terminal wait), and
/// `record_failed_launch` (the wait failed or was abandoned).
/// A wait failure retains its owner for retry outside this
/// handle and is never convertible into a finish success.
/// Dropping the handle is only a `must_use` warning, not
/// drop-proof exactly-once: the consuming outcome methods are
/// the enforceable part.
#[must_use = "record the terminal verdict exactly once after the detached wait"]
pub struct BridgeVerdict {
    core: BridgeCore,
}

impl BridgeVerdict {
    /// Consume a detached supervisor's confirmed terminal
    /// outcome: record the watch terminal fact, then finish,
    /// each exactly once, and return the outcome on success.
    /// Pass only the value the real wait returned; a hand-built
    /// outcome is outside the bridge contract. Ok means the
    /// verdict passed, not that the launch succeeded: the
    /// harness must confirm every issued ticket reached
    /// `Completed` (see `BirthBridge::complete`) before calling
    /// the launch successful; that completion gate belongs to
    /// the slice-4 harness. A verdict error is a launch failure
    /// even though the guest already exited.
    pub fn record_detached_outcome(
        self,
        outcome: super::supervisor::SupervisorOutcome,
    ) -> Result<super::supervisor::SupervisorOutcome, ExecControlError> {
        self.core.verdict_terminal()?;
        Ok(outcome)
    }

    /// Consume a released prepared outcome's confirmed terminal
    /// status the same way, returning the status on success.
    /// Pass only the status the real wait returned. As with
    /// `record_detached_outcome`, Ok means the verdict passed,
    /// not that the launch succeeded.
    pub fn record_released_status(
        self,
        status: safeptrace::ExitStatus,
    ) -> Result<safeptrace::ExitStatus, ExecControlError> {
        self.core.verdict_terminal()?;
        Ok(status)
    }

    /// The detached/released wait itself failed (or the raw
    /// stop was cancelled after `into_successor_stop`): take
    /// the verdict for the retained cleanup state exactly once
    /// and return the verdict error if any. The launch failed
    /// either way; this returns nothing success-shaped, and a
    /// later retry that confirms retirement cannot record the
    /// terminal after the fact (the verdict is exactly-once and
    /// already taken).
    #[must_use = "the verdict error is the launch failure; handle it"]
    pub fn record_failed_launch(self, cleanup: &CleanupState) -> Option<ExecControlError> {
        self.core.verdict_for_cleanup(cleanup.confirmed).err()
    }
}

/// One watched birth under bridge control, before its next exec
/// event. Retain through [`BirthBridge::wait_next`], `abandon`,
/// or `cancel`.
#[must_use = "retain the birth bridge through its terminal verdict or abandonment"]
pub struct BirthBridge<'fd> {
    watched: WatchedSupervisor<'fd>,
    core: BridgeCore,
    initial_seen: bool,
}

/// One step of a bridged watched run.
pub enum BridgeStep<'fd> {
    /// The first image's exec stop. No authority stop has been
    /// recorded for it.
    InitialExec(Box<BridgeInitialStop<'fd>>),
    /// A successor exec stop already recorded with the
    /// authority; issue it before any release.
    SuccessorExec(Box<BridgeRecordedStop<'fd>>),
    /// Terminal outcome; the verdict has already been taken and
    /// passed, or this step would be a `Verdict` error. This
    /// outcome does not by itself mean the launch succeeded:
    /// the harness must confirm every issued ticket reached
    /// `Completed` (via `BirthBridge::complete` at its verified
    /// Ready point) before treating the launch as successful.
    Finished(WatchedOutcome),
}

impl<'fd> BirthBridge<'fd> {
    /// Spawn the watched supervisor for one birth and construct
    /// its authority from the seized child's identity.
    ///
    /// With `config: None` this refuses by name **before** any
    /// child is created: the selected native-exec route requires
    /// a configured birth authority. The receipt is returned
    /// unclaimed inside the failure.
    pub fn spawn_watched(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
        config: Option<BridgeConfig>,
    ) -> Result<Self, BridgeError<'fd>> {
        let Some(config) = config else {
            return Err(BridgeError::Launch(LaunchFailure {
                error: "native-exec route requires a configured birth authority".into(),
                receipt,
                owner: None,
                pending: None,
                parent_stdio: None,
            }));
        };
        // Validate before spawn so an invalid config creates no
        // child.
        let invalid: Option<&str> = if config.registry_nonce == [0; 32] {
            Some("birth bridge registry nonce must be nonzero")
        } else if let InitialMode::RpcRedeemed { initial_redemption } = &config.initial {
            (initial_redemption.is_empty()
                || initial_redemption.len()
                    > reverie_rpc_transport::initial_image::MAX_REDEMPTION_LEN)
                .then_some("birth bridge initial redemption length is invalid")
        } else {
            None
        };
        if let Some(message) = invalid {
            return Err(BridgeError::Launch(LaunchFailure {
                error: message.into(),
                receipt,
                owner: None,
                pending: None,
                parent_stdio: None,
            }));
        }
        let retained_receipt = receipt.clone();
        let watched = Supervisor::spawn_watched(request, receipt).map_err(BridgeError::Launch)?;
        let admitted = Admitted {
            process_id: watched.pid().as_raw(),
        };
        // On the host-consumed route the authority's stored
        // redemption is a bridge-internal never-issued value, so
        // no Initial RPC can consume the initial image first.
        let initial_redemption = match &config.initial {
            InitialMode::RpcRedeemed { initial_redemption } => initial_redemption.clone(),
            InitialMode::HostConsumed => match never_issued_redemption() {
                Ok(bytes) => bytes,
                Err(error) => {
                    let owner = watched.cancel().err();
                    return Err(BridgeError::Launch(LaunchFailure {
                        error: error.to_string().into(),
                        receipt: retained_receipt,
                        owner,
                        pending: None,
                        parent_stdio: None,
                    }));
                }
            },
        };
        let authority = match BirthAuthority::new(
            admitted,
            config.config_digest,
            initial_redemption,
            config.registry_nonce,
        ) {
            Ok(authority) => Arc::new(authority),
            Err(error) => {
                let owner = watched.cancel().err();
                return Err(BridgeError::Launch(LaunchFailure {
                    error: error.to_string().into(),
                    receipt: retained_receipt,
                    owner,
                    pending: None,
                    parent_stdio: None,
                }));
            }
        };
        Ok(Self {
            watched,
            core: BridgeCore {
                authority,
                admitted,
                config_digest: config.config_digest,
                initial: config.initial,
                receipt: retained_receipt,
            },
            initial_seen: false,
        })
    }

    /// The seized child's identity.
    pub fn pid(&self) -> safeptrace::Pid {
        self.watched.pid()
    }

    /// The birth authority, for installing on the coordinator
    /// `RpcServer` before the first `wait_next` resumes anything.
    pub fn authority(&self) -> Arc<BirthAuthority> {
        self.core.authority.clone()
    }

    /// The watcher-derived admitted identity for this birth.
    pub fn admitted(&self) -> Admitted {
        self.core.admitted
    }

    /// Record the mapped first image as consumed, exactly once.
    /// Only exposed on the `HostConsumed` path; on the
    /// `RpcRedeemed` path this refuses with a transition error
    /// so the two consumption paths cannot both run. Until one
    /// of them happens, staging refuses fail-closed. This bridge
    /// method is the sanctioned host-consumption path: trusted
    /// harness code holding `authority()` could call the
    /// authority directly, which is outside the bridge contract;
    /// the authority's exactly-once transition check remains
    /// the fail-closed backstop either way.
    pub fn record_mapped_initial_consumed(&self) -> Result<(), ExecControlError> {
        if !self.initial_seen {
            return Err(ExecControlError::Transition);
        }
        self.core.record_mapped_initial_consumed()
    }

    /// Mark an issued ticket complete after the harness verified
    /// the successor's Ready point. The terminal verdict still
    /// belongs to the bridge's finished/verdict paths.
    pub fn complete(&self, ticket: ExecTicket) -> Result<(), ExecControlError> {
        self.core.authority.complete(ticket)
    }

    /// Run until the next exec stop or the terminal outcome. A
    /// successor stop is recorded with the authority (retained
    /// birth pidfd, watcher admitted) before it is handed out;
    /// the initial exec is not recorded.
    pub fn wait_next(self) -> Result<BridgeStep<'fd>, BridgeError<'fd>> {
        let Self {
            watched,
            core,
            initial_seen,
        } = self;
        match watched.wait_next() {
            Ok(WatchedStep::Finished(outcome)) => match core.verdict_terminal() {
                Ok(()) => Ok(BridgeStep::Finished(outcome)),
                Err(error) => Err(BridgeError::Verdict { outcome, error }),
            },
            Ok(WatchedStep::Exec(stop)) if !initial_seen => {
                Ok(BridgeStep::InitialExec(Box::new(BridgeInitialStop {
                    stop: *stop,
                    core,
                })))
            }
            Ok(WatchedStep::Exec(stop)) => {
                let stop = *stop;
                match stop.duplicate_birth_pidfd() {
                    Err(error) => Err(core.fail_stop(stop, error)),
                    Ok(pidfd) => {
                        match core.authority.record_successor_stop(core.admitted, &pidfd) {
                            Ok(birth_stop) => {
                                Ok(BridgeStep::SuccessorExec(Box::new(BridgeRecordedStop {
                                    stop,
                                    core,
                                    birth_stop,
                                })))
                            }
                            Err(error) => Err(core.fail_stop(stop, error.to_string().into())),
                        }
                    }
                }
            }
            Err(failure) => Err(core.chain_verdict(failure)),
        }
    }

    /// Abandon the launch before any terminal outcome: take the
    /// finish verdict first (still-pending EOFs refuse visibly;
    /// no terminal fact is synthesized), then cancel the child.
    /// The verdict error, if any, is the failure surfaced.
    pub fn abandon(self) -> Result<CleanupState, BridgeError<'fd>> {
        let Self { watched, core, .. } = self;
        let verdict = core.verdict_without_terminal();
        match watched.cancel() {
            Ok(state) => match verdict {
                Ok(()) => Ok(state),
                Err(error) => Err(core.launch_failure(error.to_string().into(), None, None)),
            },
            Err(owner) => {
                let message = match verdict {
                    Ok(()) => "bridge abandon cleanup unconfirmed".to_string(),
                    Err(error) => {
                        format!("birth verdict failed: {error}; abandon cleanup unconfirmed")
                    }
                };
                Err(core.launch_failure(message.into(), Some(owner), None))
            }
        }
    }

    /// Cancel while seized, then take the verdict for the
    /// resulting cleanup state (terminal verdict only when the
    /// cancellation confirmed retirement).
    pub fn cancel(self) -> Result<CleanupState, BridgeError<'fd>> {
        let Self { watched, core, .. } = self;
        match watched.cancel() {
            Ok(state) => match core.verdict_for_cleanup(state.confirmed) {
                Ok(()) => Ok(state),
                Err(error) => Err(core.launch_failure(error.to_string().into(), None, None)),
            },
            Err(owner) => {
                let message = match core.verdict_without_terminal() {
                    Ok(()) => "bridge cancel cleanup unconfirmed".to_string(),
                    Err(error) => {
                        format!("birth verdict failed: {error}; cancel cleanup unconfirmed")
                    }
                };
                Err(core.launch_failure(message.into(), Some(owner), None))
            }
        }
    }
}

/// Read bridge-internal randomness for a never-issued redemption.
/// The value is stored only inside the authority and never
/// leaves the host.
fn never_issued_redemption() -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The first image's exec stop under bridge control. No
/// authority stop has been recorded for it.
#[must_use = "retain the initial stop through re-arm, release, or cancellation"]
pub struct BridgeInitialStop<'fd> {
    stop: SuccessorStop<'fd>,
    core: BridgeCore,
}

impl<'fd> BridgeInitialStop<'fd> {
    /// The retained physical stop (capture/prepare accessors).
    pub fn stop(&self) -> &SuccessorStop<'fd> {
        &self.stop
    }

    /// Mutable retained stop access (stdio takeover, hooks).
    pub fn stop_mut(&mut self) -> &mut SuccessorStop<'fd> {
        &mut self.stop
    }

    /// Entry coordinates for this stop: always the pair's
    /// first-image member. Generation comes from this stop's
    /// type, never from packet bytes or a caller flag.
    pub fn entry_coordinates(&self, pair: &EntryCoordinates) -> BootstrapEntryCoordinates {
        pair.first()
    }

    /// Record the mapped first image as consumed, exactly once,
    /// while this initial stop is outstanding (the verified
    /// first-image admission point). Same mode guard as
    /// [`BirthBridge::record_mapped_initial_consumed`].
    pub fn record_mapped_initial_consumed(&self) -> Result<(), ExecControlError> {
        self.core.record_mapped_initial_consumed()
    }

    /// Run the caller's first-image hook, restore the exact
    /// entry context, and resume still seized for the next exec.
    pub fn rearm_and_resume<F>(self, hook: F) -> Result<BirthBridge<'fd>, BridgeError<'fd>>
    where
        F: FnOnce(
            safeptrace::Stopped,
            &super::EntryContext,
            &super::ExecBoundary,
        ) -> super::Result<safeptrace::Stopped>,
    {
        let Self { stop, core } = self;
        match stop.rearm_and_resume(hook) {
            Ok(watched) => Ok(BirthBridge {
                watched,
                core,
                initial_seen: true,
            }),
            Err(failure) => Err(core.chain_verdict(failure)),
        }
    }

    /// Run the caller's hook and detach at the kernel entry.
    /// This is a terminal choice for the launch: no later exec
    /// stops are observed. The returned verdict handle must be
    /// consumed after the detached terminal wait.
    pub fn release_detached<F>(
        self,
        hook: F,
    ) -> Result<(DetachedSupervisor<'fd>, BridgeVerdict), BridgeError<'fd>>
    where
        F: FnOnce(
            safeptrace::Stopped,
            &super::EntryContext,
            &super::ExecBoundary,
        ) -> super::Result<safeptrace::Stopped>,
    {
        let Self { stop, core } = self;
        match stop.release_detached(hook) {
            Ok(detached) => Ok((detached, BridgeVerdict { core })),
            Err(failure) => Err(core.chain_verdict(failure)),
        }
    }

    /// Consume this stop into its physical parts plus the
    /// verdict duty, for mapped physical preparation
    /// (`SuccessorStop::prepare_mapping`). The verdict handle
    /// must still be consumed after the released outcome's
    /// confirmed terminal wait.
    pub fn into_successor_stop(self) -> (SuccessorStop<'fd>, BridgeVerdict) {
        (self.stop, BridgeVerdict { core: self.core })
    }

    /// Cancel the stopped child and take the verdict for its
    /// cleanup state.
    pub fn cancel(self) -> Result<CleanupState, BridgeError<'fd>> {
        let Self { stop, core } = self;
        cancel_stop(&core, stop)
    }
}

/// A successor exec stop already recorded with the authority.
/// It must be issued (stamped) before any release.
#[must_use = "retain the recorded stop through issue or cancellation"]
pub struct BridgeRecordedStop<'fd> {
    stop: SuccessorStop<'fd>,
    core: BridgeCore,
    birth_stop: BirthStop,
}

impl<'fd> BridgeRecordedStop<'fd> {
    /// The retained physical stop (capture/prepare accessors).
    pub fn stop(&self) -> &SuccessorStop<'fd> {
        &self.stop
    }

    /// Mutable retained stop access (stdio takeover, hooks).
    pub fn stop_mut(&mut self) -> &mut SuccessorStop<'fd> {
        &mut self.stop
    }

    /// Take the mailbox snapshot, seal it, run the caller's
    /// stamp hook (which writes the init packet and returns the
    /// exact redemption bytes), mark delivered, and issue. All
    /// of this happens while the successor is still stopped.
    /// On any error the stop is cancelled — never released
    /// half-stamped — and the verdict is taken.
    ///
    /// The stamp hook runs while `at_successor_stop` holds the
    /// `BirthAuthority` lock across prepare/seal/stamp/issue:
    /// it must not call any `BirthAuthority` method (that
    /// self-deadlocks), must not block on the RPC server or the
    /// guest, and must be bounded pure packet-byte work. This
    /// method has already consumed the stop when the hook runs,
    /// so a hook panic unwinds through the stop's drop (the
    /// child owner sends SIGKILL and waits at most 2 s); no
    /// verdict is taken, the ticket stays `Prepared`, and the
    /// registry proof's expected runtime stays set. There is
    /// no stop left for the caller to cancel after a panic.
    pub fn issue<F>(self, stamp: F) -> Result<BridgeIssuedStop<'fd>, BridgeError<'fd>>
    where
        F: FnOnce(ExecTicket, [u8; 32]) -> Result<Vec<u8>, ExecControlError>,
    {
        let Self {
            stop,
            core,
            birth_stop,
        } = self;
        let config_digest = core.config_digest;
        let mut issued_ticket = None;
        let issued = core
            .authority
            .at_successor_stop(birth_stop, |ticket, sealed| {
                issued_ticket = Some(ticket);
                let redemption = stamp(ticket, sealed)?;
                Ok(StampedPacket {
                    expected: ExpectedSuccessor {
                        config: config_digest,
                        state: sealed,
                    },
                    redemption,
                })
            });
        match issued {
            Ok(expected) => Ok(BridgeIssuedStop {
                stop,
                core,
                expected,
                ticket: issued_ticket.expect("stamp callback ran on issue"),
            }),
            Err(error) => Err(core.fail_stop(stop, error.to_string().into())),
        }
    }

    /// Cancel without issuing and take the verdict.
    pub fn cancel(self) -> Result<CleanupState, BridgeError<'fd>> {
        let Self { stop, core, .. } = self;
        cancel_stop(&core, stop)
    }
}

/// A successor stop whose ticket has been stamped and issued.
/// It may now be rearmed, released, or consumed by mapped
/// physical preparation.
#[must_use = "retain the issued stop through re-arm, release, or cancellation"]
pub struct BridgeIssuedStop<'fd> {
    stop: SuccessorStop<'fd>,
    core: BridgeCore,
    expected: ExpectedSuccessor,
    ticket: ExecTicket,
}

impl<'fd> BridgeIssuedStop<'fd> {
    /// The retained physical stop (capture/prepare accessors).
    pub fn stop(&self) -> &SuccessorStop<'fd> {
        &self.stop
    }

    /// Mutable retained stop access (stdio takeover, hooks).
    pub fn stop_mut(&mut self) -> &mut SuccessorStop<'fd> {
        &mut self.stop
    }

    /// The exact issued ticket for this stop.
    pub fn ticket(&self) -> ExecTicket {
        self.ticket
    }

    /// Entry coordinates for this stop: always the pair's
    /// successor member. Generation comes from this stop's
    /// type, never from packet bytes or a caller flag.
    pub fn entry_coordinates(&self, pair: &EntryCoordinates) -> BootstrapEntryCoordinates {
        pair.successor()
    }

    /// The sealed successor expectation (config + state digests).
    pub fn expected(&self) -> ExpectedSuccessor {
        self.expected
    }

    /// Run the caller's re-arm hook, restore the exact entry
    /// context, and resume still seized for the next exec.
    pub fn rearm_and_resume<F>(self, hook: F) -> Result<BirthBridge<'fd>, BridgeError<'fd>>
    where
        F: FnOnce(
            safeptrace::Stopped,
            &super::EntryContext,
            &super::ExecBoundary,
        ) -> super::Result<safeptrace::Stopped>,
    {
        let Self { stop, core, .. } = self;
        match stop.rearm_and_resume(hook) {
            Ok(watched) => Ok(BirthBridge {
                watched,
                core,
                initial_seen: true,
            }),
            Err(failure) => Err(core.chain_verdict(failure)),
        }
    }

    /// Run the caller's hook and detach at the kernel entry.
    /// This is a terminal choice for the launch: no later exec
    /// stops are observed. The returned verdict handle must be
    /// consumed after the detached terminal wait.
    pub fn release_detached<F>(
        self,
        hook: F,
    ) -> Result<(DetachedSupervisor<'fd>, BridgeVerdict), BridgeError<'fd>>
    where
        F: FnOnce(
            safeptrace::Stopped,
            &super::EntryContext,
            &super::ExecBoundary,
        ) -> super::Result<safeptrace::Stopped>,
    {
        let Self { stop, core, .. } = self;
        match stop.release_detached(hook) {
            Ok(detached) => Ok((detached, BridgeVerdict { core })),
            Err(failure) => Err(core.chain_verdict(failure)),
        }
    }

    /// Consume this stop into its physical parts plus the
    /// verdict duty, for mapped physical preparation
    /// (`SuccessorStop::prepare_mapping`). The verdict handle
    /// must still be consumed after the released outcome's
    /// confirmed terminal wait.
    pub fn into_successor_stop(self) -> (SuccessorStop<'fd>, BridgeVerdict) {
        (self.stop, BridgeVerdict { core: self.core })
    }

    /// Cancel the issued stop without releasing it and take the
    /// verdict.
    pub fn cancel(self) -> Result<CleanupState, BridgeError<'fd>> {
        let Self { stop, core, .. } = self;
        cancel_stop(&core, stop)
    }
}

fn cancel_stop<'fd>(
    core: &BridgeCore,
    mut stop: SuccessorStop<'fd>,
) -> Result<CleanupState, BridgeError<'fd>> {
    let parent_stdio = stop.take_parent_stdio();
    match stop.cancel() {
        Ok(state) => match core.verdict_for_cleanup(state.confirmed) {
            Ok(()) => Ok(state),
            Err(error) => Err(core.launch_failure(error.to_string().into(), None, parent_stdio)),
        },
        Err(owner) => {
            let message = match core.verdict_without_terminal() {
                Ok(()) => "bridge stop cancel cleanup unconfirmed".to_string(),
                Err(error) => {
                    format!("birth verdict failed: {error}; stop cancel cleanup unconfirmed")
                }
            };
            Err(core.launch_failure(message.into(), Some(owner), parent_stdio))
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::ffi::OsString;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    use reverie_rpc_transport::birth_authority::frame_tool_state;
    use reverie_rpc_transport::birth_authority::verify_and_split_runtime;
    use reverie_rpc_transport::exec_ticket::ExecStage;
    use reverie_rpc_transport::initial_image::InitialImageAdmission;
    use reverie_rpc_transport::successor::NativeImageConnection;
    use reverie_rpc_transport::successor::SuccessorAdmission;
    use reverie_rpc_transport::successor::SuccessorRequest;

    use super::*;
    use crate::launcher::exec_stop::CleanupReceipt;

    fn request(program: &str, arguments: &[&str]) -> PreparedExec<'static> {
        let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        PreparedExec::new(Path::new(program), &arguments, &[], None, Vec::new()).unwrap()
    }

    fn host_config() -> BridgeConfig {
        BridgeConfig {
            config_digest: [3u8; 32],
            registry_nonce: [7u8; 32],
            initial: InitialMode::HostConsumed,
        }
    }

    fn rpc_config() -> BridgeConfig {
        BridgeConfig {
            config_digest: [3u8; 32],
            registry_nonce: [7u8; 32],
            initial: InitialMode::RpcRedeemed {
                initial_redemption: b"initial-only".to_vec(),
            },
        }
    }

    fn own_pidfd() -> OwnedFd {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id() as i32, 0) };
        assert!(
            raw >= 0,
            "pidfd_open(self): {}",
            std::io::Error::last_os_error()
        );
        unsafe { OwnedFd::from_raw_fd(raw as i32) }
    }

    fn spawn_bridge(config: BridgeConfig) -> BirthBridge<'static> {
        spawn_bridge_req(config, request("/bin/sh", &["sh", "-c", "exec /bin/true"]))
    }

    fn spawn_bridge_req(config: BridgeConfig, req: PreparedExec<'static>) -> BirthBridge<'static> {
        BirthBridge::spawn_watched(req, CleanupReceipt::default(), Some(config)).unwrap()
    }

    /// Fixture whose successor writes a marker file if it is
    /// ever released to run: initial sh exec, then exec to an
    /// inner sh that writes the marker.
    fn marker_request() -> (PreparedExec<'static>, PathBuf) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rv-bridge-marker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("released");
        let command = format!("exec /bin/sh -c 'echo released > {}'", marker.display());
        let req = request(
            "/bin/sh",
            &["sh", "-c", Box::leak(command.into_boxed_str())],
        );
        (req, marker)
    }

    fn expect_initial(step: BridgeStep<'static>) -> BridgeInitialStop<'static> {
        match step {
            BridgeStep::InitialExec(stop) => *stop,
            BridgeStep::SuccessorExec(_) => panic!("expected initial exec, got successor exec"),
            BridgeStep::Finished(outcome) => panic!("expected initial exec, got {outcome:?}"),
        }
    }

    fn expect_successor(step: BridgeStep<'static>) -> BridgeRecordedStop<'static> {
        match step {
            BridgeStep::SuccessorExec(stop) => *stop,
            BridgeStep::InitialExec(_) => panic!("expected successor exec, got initial exec"),
            BridgeStep::Finished(outcome) => panic!("expected successor exec, got {outcome:?}"),
        }
    }

    #[test]
    fn nb1_refuses_without_authority_before_spawn() {
        let receipt = CleanupReceipt::default();
        let failure = match BirthBridge::spawn_watched(
            request("/bin/true", &["true"]),
            receipt.clone(),
            None,
        ) {
            Ok(_) => panic!("route without authority must refuse"),
            Err(error) => error,
        };
        let BridgeError::Launch(failure) = failure else {
            panic!("expected launch refusal");
        };
        assert!(
            failure
                .error
                .to_string()
                .contains("native-exec route requires a configured birth authority"),
            "unexpected refusal: {}",
            failure.error
        );
        assert!(!receipt.snapshot().child_created);
        assert!(!failure.cleanup().child_created);

        // Invalid configs also create no child, each refused by
        // its own name.
        for (config, expected) in [
            (
                BridgeConfig {
                    registry_nonce: [0u8; 32],
                    ..host_config()
                },
                "registry nonce must be nonzero",
            ),
            (
                BridgeConfig {
                    initial: InitialMode::RpcRedeemed {
                        initial_redemption: Vec::new(),
                    },
                    ..host_config()
                },
                "initial redemption length is invalid",
            ),
            (
                BridgeConfig {
                    initial: InitialMode::RpcRedeemed {
                        initial_redemption: vec![
                            0xEE;
                            reverie_rpc_transport::initial_image::MAX_REDEMPTION_LEN
                                + 1
                        ],
                    },
                    ..host_config()
                },
                "initial redemption length is invalid",
            ),
        ] {
            let receipt = CleanupReceipt::default();
            let failure = match BirthBridge::spawn_watched(
                request("/bin/true", &["true"]),
                receipt.clone(),
                Some(config),
            ) {
                Ok(_) => panic!("invalid bridge config must refuse"),
                Err(error) => error,
            };
            let BridgeError::Launch(failure) = failure else {
                panic!("expected launch refusal");
            };
            assert!(
                failure.error.to_string().contains(expected),
                "unexpected refusal: {}",
                failure.error
            );
            assert!(!receipt.snapshot().child_created);
        }
    }

    #[test]
    fn cross_path_initial_modes_are_mutually_exclusive() {
        // RpcRedeemed: the bridge record call refuses by name
        // before touching the authority; the Initial RPC still
        // redeems exactly once, and a second consumption via
        // either path is a transition error.
        let bridge = spawn_bridge(rpc_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let pid = bridge.pid();
        assert!(matches!(
            bridge.record_mapped_initial_consumed(),
            Err(ExecControlError::Transition)
        ));
        let pidfd = {
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
            assert!(raw >= 0);
            unsafe { OwnedFd::from_raw_fd(raw as i32) }
        };
        InitialImageAdmission::redeem(
            &*authority,
            pidfd.try_clone().unwrap(),
            admitted,
            b"initial-only",
            [3u8; 32],
        )
        .unwrap();
        assert!(
            InitialImageAdmission::redeem(&*authority, pidfd, admitted, b"initial-only", [3u8; 32])
                .is_err()
        );
        assert!(matches!(
            authority.record_initial_consumed(admitted),
            Err(ExecControlError::Transition)
        ));
        bridge.cancel().unwrap();
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-cancel").unwrap()),
            Err(ExecControlError::Transition)
        ));

        // HostConsumed: an Initial RPC attempt with any guessed
        // redemption refuses (the stored redemption is a
        // never-issued internal value); the host record then
        // succeeds exactly once.
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let pidfd = {
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, bridge.pid().as_raw(), 0) };
            assert!(raw >= 0);
            unsafe { OwnedFd::from_raw_fd(raw as i32) }
        };
        assert!(
            InitialImageAdmission::redeem(&*authority, pidfd, admitted, b"initial-only", [3u8; 32])
                .is_err()
        );
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        assert!(matches!(
            initial.record_mapped_initial_consumed(),
            Err(ExecControlError::Transition)
        ));
        initial.cancel().unwrap();
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-cancel").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn happy_path_initial_then_successor_with_ordinal_one() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();

        let initial = expect_initial(bridge.wait_next().unwrap());
        // Typed generation choice: each stop type yields only
        // its own pair member, with identical packet bytes.
        let pair = EntryCoordinates::from_qualified_symbols((0x1111, 0x2222), (0x3333, 0x4444));
        assert_eq!(initial.entry_coordinates(&pair), pair.first());
        assert_ne!(initial.entry_coordinates(&pair), pair.successor());
        // Staging refuses until the single consumption path runs.
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"early").unwrap()),
            Err(ExecControlError::Transition)
        ));
        initial.record_mapped_initial_consumed().unwrap();
        let order_rearm = order.clone();
        let bridge = initial
            .rearm_and_resume(move |task, _entry, _boundary| {
                order_rearm.lock().unwrap().push("initial-rearm");
                Ok(task)
            })
            .unwrap();

        // A wrong-pidfd record attempt refuses Identity and
        // records no stop (the bridge stop below is ordinal 1).
        assert!(matches!(
            authority.record_successor_stop(admitted, &own_pidfd()),
            Err(ExecControlError::Identity)
        ));

        authority
            .stage_snapshot(admitted, frame_tool_state(b"bridge-state").unwrap())
            .unwrap();
        let recorded = expect_successor(bridge.wait_next().unwrap());
        let order_stamp = order.clone();
        let issued = recorded
            .issue(move |_ticket, _sealed| {
                // The stamp hook runs mid-issue, before any
                // rearm/release: only the initial rearm may be
                // recorded so far. (No authority call here:
                // at_successor_stop holds the authority lock
                // across the stamp callback by design.)
                assert_eq!(order_stamp.lock().unwrap().as_slice(), ["initial-rearm"]);
                order_stamp.lock().unwrap().push("stamp");
                Ok(_ticket.0.to_vec())
            })
            .unwrap();
        assert_eq!(issued.entry_coordinates(&pair), pair.successor());
        assert_ne!(issued.entry_coordinates(&pair), pair.first());
        let ticket = issued.ticket();
        let expected = issued.expected();
        assert_eq!(authority.stage(ticket), Some(ExecStage::Issued));
        let pidfd = issued.stop().duplicate_birth_pidfd().unwrap();
        let state = SuccessorAdmission::redeem(
            &*authority,
            pidfd,
            admitted,
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
        let (runtime, tool) = verify_and_split_runtime(
            &state,
            [3u8; 32],
            reverie_rpc_transport::initial_image::config_digest(&ticket.0),
        )
        .unwrap();
        assert_eq!(runtime.exec_ordinal, 1);
        assert_eq!(&tool[4..], b"bridge-state");
        bridge_complete(&authority, ticket);
        let order_rearm2 = order.clone();
        let bridge = issued
            .rearm_and_resume(move |task, _entry, _boundary| {
                order_rearm2.lock().unwrap().push("successor-rearm");
                Ok(task)
            })
            .unwrap();
        match bridge.wait_next().unwrap() {
            BridgeStep::Finished(outcome) => {
                assert_eq!(outcome.status, safeptrace::ExitStatus::Exited(0));
                assert_eq!(outcome.execs_seen, 2);
                assert!(outcome.cleanup.confirmed);
            }
            BridgeStep::InitialExec(_) | BridgeStep::SuccessorExec(_) => {
                panic!("expected finished outcome")
            }
        }
        assert_eq!(
            order.lock().unwrap().as_slice(),
            ["initial-rearm", "stamp", "successor-rearm"]
        );
        assert_eq!(authority.stage(ticket), Some(ExecStage::Completed));
    }

    fn bridge_complete(authority: &BirthAuthority, ticket: ExecTicket) {
        authority.complete(ticket).unwrap();
    }

    #[test]
    fn stop_without_stage_is_unavailable_and_cancels() {
        let (req, marker) = marker_request();
        let bridge = spawn_bridge_req(host_config(), req);
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let pid = bridge.pid();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        let recorded = expect_successor(bridge.wait_next().unwrap());
        let failure = match recorded.issue(|ticket, _sealed| Ok(ticket.0.to_vec())) {
            Ok(_) => panic!("unstaged stop must not issue"),
            Err(error) => error,
        };
        let BridgeError::Launch(failure) = failure else {
            panic!("expected launch failure");
        };
        assert!(
            failure.error.to_string().contains("Unavailable"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
        assert!(
            !marker.exists(),
            "successor ran after a failed issue: marker written"
        );
        std::fs::remove_dir_all(marker.parent().unwrap()).unwrap();
        // The verdict ran on this error path: staging is closed.
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-failure").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn stamp_failure_cancels_ticket_and_never_releases() {
        let (req, marker) = marker_request();
        let bridge = spawn_bridge_req(host_config(), req);
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let pid = bridge.pid();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"doomed").unwrap())
            .unwrap();
        let recorded = expect_successor(bridge.wait_next().unwrap());
        let captured = Arc::new(Mutex::new(None));
        let captured_stamp = captured.clone();
        let failure = match recorded.issue(move |ticket, _sealed| {
            *captured_stamp.lock().unwrap() = Some(ticket);
            Err(ExecControlError::Digest)
        }) {
            Ok(_) => panic!("failing stamp must not issue"),
            Err(error) => error,
        };
        let ticket = captured.lock().unwrap().unwrap();
        assert_eq!(authority.stage(ticket), Some(ExecStage::Cancelled));
        let BridgeError::Launch(failure) = failure else {
            panic!("expected launch failure");
        };
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
        assert!(
            !marker.exists(),
            "successor ran after a failed stamp: marker written"
        );
        std::fs::remove_dir_all(marker.parent().unwrap()).unwrap();
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-failure").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn pending_initial_eof_abandon_refuses_visibly() {
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        // A clean Initial EOF with no staged mailbox, no recorded
        // stop and no terminal fact stays pending.
        authority
            .connection_closed(admitted, &NativeImageConnection::Initial)
            .unwrap();
        assert_eq!(authority.pending_eof_count(), 1);
        let failure = match bridge.abandon() {
            Ok(state) => panic!("abandon must surface the refused verdict, got {state:?}"),
            Err(error) => error,
        };
        assert_eq!(authority.refused_eof_count(), 1);
        let BridgeError::Launch(failure) = failure else {
            panic!("expected launch failure");
        };
        assert!(
            failure.error.to_string().contains("Transition"),
            "unexpected failure: {}",
            failure.error
        );
    }

    #[test]
    fn finished_verdict_records_watch_terminal() {
        // The terminal verdict is record_watch_terminal + finish,
        // not finish alone: after a Finished outcome the registry
        // is died (live tickets are Dead) and staged snapshots
        // refuse fail-closed. finish() alone sets neither.
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"terminal-state").unwrap())
            .unwrap();
        let recorded = expect_successor(bridge.wait_next().unwrap());
        let issued = recorded
            .issue(|ticket, _sealed| Ok(ticket.0.to_vec()))
            .unwrap();
        let ticket = issued.ticket();
        assert_eq!(authority.stage(ticket), Some(ExecStage::Issued));
        // Deliberately no redeem/complete: the ticket stays live
        // across the terminal outcome.
        let bridge = issued
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        match bridge.wait_next().unwrap() {
            BridgeStep::Finished(outcome) => {
                assert_eq!(outcome.status, safeptrace::ExitStatus::Exited(0));
            }
            BridgeStep::InitialExec(_) | BridgeStep::SuccessorExec(_) => {
                panic!("expected finished outcome")
            }
        }
        assert_eq!(authority.stage(ticket), Some(ExecStage::Dead));
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"too-late").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn sigkill_before_successor_stop_accepts_pending_initial_eof_at_terminal() {
        let bridge = spawn_bridge_req(
            host_config(),
            request("/bin/sh", &["sh", "-c", "kill -KILL $$"]),
        );
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        // Pending Initial EOF with no mailbox and no recorded stop.
        authority
            .connection_closed(admitted, &NativeImageConnection::Initial)
            .unwrap();
        assert_eq!(authority.pending_eof_count(), 1);
        match bridge.wait_next().unwrap() {
            BridgeStep::Finished(outcome) => {
                assert!(
                    matches!(
                        outcome.status,
                        safeptrace::ExitStatus::Signaled(safeptrace::Signal::SIGKILL, _)
                    ),
                    "unexpected status: {:?}",
                    outcome.status
                );
            }
            BridgeStep::InitialExec(_) | BridgeStep::SuccessorExec(_) => {
                panic!("expected finished outcome")
            }
        }
        assert_eq!(authority.accepted_eof_count(), 1);
        assert_eq!(authority.refused_eof_count(), 0);
        assert_eq!(authority.pending_eof_count(), 0);
    }

    #[test]
    fn issued_stop_cancel_records_terminal_and_kills_ticket() {
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"cancel-state").unwrap())
            .unwrap();
        let recorded = expect_successor(bridge.wait_next().unwrap());
        let issued = recorded
            .issue(|ticket, _sealed| Ok(ticket.0.to_vec()))
            .unwrap();
        let ticket = issued.ticket();
        issued.cancel().unwrap();
        assert_eq!(authority.stage(ticket), Some(ExecStage::Dead));
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-cancel").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn release_detached_then_record_outcome_runs_verdict() {
        let bridge = spawn_bridge_req(host_config(), request("/bin/true", &["true"]));
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"detached-state").unwrap())
            .unwrap();
        let (detached, verdict) = initial
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        // Before the verdict, staging is still open.
        authority
            .stage_snapshot(admitted, frame_tool_state(b"detached-state-2").unwrap())
            .unwrap();
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, safeptrace::ExitStatus::Exited(0));
        let outcome = verdict.record_detached_outcome(outcome).unwrap();
        assert_eq!(outcome.status, safeptrace::ExitStatus::Exited(0));
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-verdict").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn into_successor_stop_cancel_then_failed_launch_verdict() {
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"into-parts-state").unwrap())
            .unwrap();
        let recorded = expect_successor(bridge.wait_next().unwrap());
        let issued = recorded
            .issue(|ticket, _sealed| Ok(ticket.0.to_vec()))
            .unwrap();
        let ticket = issued.ticket();
        let (stop, verdict) = issued.into_successor_stop();
        let cleanup = stop.cancel().unwrap();
        assert!(cleanup.confirmed);
        assert_eq!(verdict.record_failed_launch(&cleanup), None);
        assert_eq!(authority.stage(ticket), Some(ExecStage::Dead));
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-failed").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn release_detached_then_released_status_runs_verdict() {
        // Same detached flow as the outcome variant, consumed
        // through record_released_status: its verdict call is
        // pinned, not just the shared helper behind it.
        let bridge = spawn_bridge_req(host_config(), request("/bin/sh", &["sh", "-c", "exit 3"]));
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        initial.record_mapped_initial_consumed().unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"status-state").unwrap())
            .unwrap();
        let (detached, verdict) = initial
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"status-state-2").unwrap())
            .unwrap();
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, safeptrace::ExitStatus::Exited(3));
        let status = verdict.record_released_status(outcome.status).unwrap();
        assert_eq!(status, safeptrace::ExitStatus::Exited(3));
        assert!(matches!(
            authority.stage_snapshot(admitted, frame_tool_state(b"after-verdict").unwrap()),
            Err(ExecControlError::Transition)
        ));
    }

    #[test]
    fn failed_launch_unconfirmed_cleanup_refuses_pending_eof() {
        // Unconfirmed cleanup arm: the verdict finishes without
        // recording a terminal fact, so a pending Initial EOF is
        // visibly refused and returned as the verdict error. The
        // pending EOF is recorded while no stop has been
        // recorded and no mailbox is staged, so nothing accepts
        // it early.
        let bridge = spawn_bridge(host_config());
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        let (stop, verdict) = initial.into_successor_stop();
        stop.cancel().unwrap();
        authority
            .connection_closed(admitted, &NativeImageConnection::Initial)
            .unwrap();
        assert_eq!(authority.pending_eof_count(), 1);
        let unconfirmed = CleanupState {
            confirmed: false,
            ..Default::default()
        };
        assert_eq!(
            verdict.record_failed_launch(&unconfirmed),
            Some(ExecControlError::Transition)
        );
        assert_eq!(authority.refused_eof_count(), 1);
        assert_eq!(authority.pending_eof_count(), 0);
    }

    #[test]
    fn record_consumed_requires_initial_exec_seen() {
        // Before the initial exec is seen, the bridge-level
        // record refuses; after the initial stop is rearmed it
        // succeeds and staging opens.
        let bridge = spawn_bridge(host_config());
        assert!(matches!(
            bridge.record_mapped_initial_consumed(),
            Err(ExecControlError::Transition)
        ));
        let authority = bridge.authority();
        let admitted = bridge.admitted();
        let initial = expect_initial(bridge.wait_next().unwrap());
        let bridge = initial
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        bridge.record_mapped_initial_consumed().unwrap();
        authority
            .stage_snapshot(admitted, frame_tool_state(b"after-rearm").unwrap())
            .unwrap();
        bridge.cancel().unwrap();
    }
}
