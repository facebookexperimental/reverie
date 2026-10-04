/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Backend-neutral signal delivery metadata.

use serde::Deserialize;
use serde::Serialize;

use crate::Pid;
use crate::Tid;
use crate::error::Errno;

/// Size of Linux's userspace `siginfo_t` representation on supported targets.
pub const SIGNAL_INFO_SIZE: usize = 128;

/// Receiver state after accepting one process-directed child-exit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChildExitSignalDisposition {
    /// Explicit `SIG_IGN` suppressed generation; no event was inserted.
    Ignored,
    /// The event is pending and currently blocked by the receiver's mask.
    PendingBlocked,
    /// The event is eligible at the receiver's signal-delivery boundary.
    ///
    /// The Tool hook and current disposition still determine whether a guest
    /// handler runs. This is not a promise of handler execution or `EINTR`.
    PendingEligible,
}

/// Why a child-exit event was refused before changing backend state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChildExitSignalErrorKind {
    /// This backend, execution context, or producer class is unsupported.
    Unsupported,
    /// Metadata or the current receiver identity is invalid.
    Invalid,
    /// An internal backend operation failed before publication.
    Backend,
}

/// Complete result of a backend's child-exit pending-state operation.
///
/// A caller must distinguish refusal before publication from failure after
/// publication. Retrying a post-publication failure may lose the first siginfo
/// or report a delivery that never reached the receiver. Neither failure is an
/// ordinary guest syscall result. These generations identify the signal's
/// disposition generation, not a scheduler operation or delivery identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChildExitSignalOutcome {
    /// The bounded receiver operation completed successfully.
    Accepted {
        /// Whether generation was suppressed, blocked, or eligible.
        disposition: ChildExitSignalDisposition,
        /// The signal's disposition/pending generation at this operation.
        pending_generation: u64,
        /// An already pending standard signal retained its original siginfo.
        coalesced: bool,
    },
    /// Neither pending state nor signalfd readiness changed.
    RejectedBeforeCommit {
        /// Machine-readable failure class, independent of diagnostic text.
        kind: ChildExitSignalErrorKind,
        /// The original errno.
        errno: Errno,
    },
    /// Insertion or coalescing committed before a readiness update failed.
    FailedAfterCommit {
        /// The original readiness-update errno.
        errno: Errno,
        /// The generation under which insertion or coalescing committed.
        pending_generation: u64,
    },
}

/// Current disposition of a process-pending alarm, before Tool filtering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessAlarmSignalDisposition {
    /// The Tool may observe the signal, but this disposition runs no handler.
    Ignored,
    /// A caught disposition; delivery and interruption have not occurred.
    Caught,
    /// The default SIGALRM action terminates the process when delivered.
    DefaultFatal,
}

/// State captured when a process-alarm pending operation commits.
///
/// This is a publication receipt, not a dequeue identity, timer rearm, Tool
/// observation, handler execution, or authorization to return `EINTR`. A later
/// mask or disposition change may invalidate this eligibility snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessAlarmSignalReceipt {
    /// Whether the sole receiver currently blocks SIGALRM.
    pub blocked: bool,
    /// The disposition at publication, independently of the receiver's mask.
    pub disposition: ProcessAlarmSignalDisposition,
    /// The SIGALRM disposition/pending generation, not a delivery counter.
    pub pending_generation: u64,
    /// An existing shared standard signal retained its first complete siginfo.
    pub coalesced: bool,
}

/// Why a process-alarm operation was refused without changing backend state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessAlarmSignalErrorKind {
    /// This backend, callback, receiver configuration or producer is unsupported.
    Unsupported,
    /// The complete metadata or current receiver identity is invalid.
    Invalid,
    /// A backend operation failed before publication.
    Backend,
}

/// Complete result of publishing a process-pending SIGALRM.
///
/// Accepted alarms always belong to the shared process pending set, including
/// blocked or ignored alarms. A Tool still observes eligible ignored signals.
/// Retrying a failure after publication as if it were a refusal is incorrect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessAlarmSignalOutcome {
    /// Shared pending state and its signalfd readiness were published.
    Accepted(ProcessAlarmSignalReceipt),
    /// Neither pending state nor signalfd readiness changed.
    RejectedBeforeCommit {
        /// Failure class independent of diagnostic text.
        kind: ProcessAlarmSignalErrorKind,
        /// Original errno.
        errno: Errno,
    },
    /// Shared insertion/coalescing committed before a readiness update failed.
    FailedAfterCommit {
        /// Original readiness-update errno.
        errno: Errno,
        /// The published state; some readiness updates may also have completed.
        receipt: ProcessAlarmSignalReceipt,
    },
}

/// Identifies both the selected guest task and whether a signal was originally
/// process-directed or thread-directed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SignalTarget {
    /// A process-directed signal. The backend or determinizing tool selected a
    /// concrete thread in `pid` before deferring the event to that guest.
    Process {
        /// The destination thread group.
        pid: Pid,
    },
    /// A signal directed to one exact thread.
    Thread {
        /// The destination thread group.
        pid: Pid,
        /// The destination thread.
        tid: Tid,
    },
}

/// A signal selected for deterministic delivery to one stopped guest thread.
///
/// Unlike [`nix::sys::signal::Signal`], this representation retains Linux's
/// raw signal numbers 1 through 64, the complete 128-byte `siginfo_t`, and the
/// process-versus-thread provenance needed by an out-of-process backend. It is
/// intentionally an event selected by the caller, not a request for a backend
/// to perform process-wide target selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SignalEventWire", into = "SignalEventWire")]
pub struct SignalEvent {
    signal: u8,
    siginfo: [u8; SIGNAL_INFO_SIZE],
    target: SignalTarget,
}

#[derive(Serialize, Deserialize)]
struct SignalEventWire {
    signal: i32,
    siginfo: Vec<u8>,
    target: SignalTarget,
}

impl From<SignalEvent> for SignalEventWire {
    fn from(event: SignalEvent) -> Self {
        Self {
            signal: event.signal(),
            siginfo: event.siginfo().to_vec(),
            target: event.target(),
        }
    }
}

impl TryFrom<SignalEventWire> for SignalEvent {
    type Error = Errno;
    fn try_from(wire: SignalEventWire) -> Result<Self, Self::Error> {
        let info = wire.siginfo.try_into().map_err(|_| Errno::EINVAL)?;
        Self::new(wire.signal, info, wire.target)
    }
}

impl SignalEvent {
    /// Creates a coherent signal event, rejecting numbers outside Linux's 1
    /// through 64 signal namespace and a `siginfo_t` whose `si_signo` differs
    /// from the separately supplied signal number.
    pub fn new(
        signal: i32,
        siginfo: [u8; SIGNAL_INFO_SIZE],
        target: SignalTarget,
    ) -> Result<Self, Errno> {
        if !(1..=64).contains(&signal)
            || i32::from_ne_bytes(siginfo[0..4].try_into().expect("siginfo signo bytes")) != signal
        {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            signal: signal as u8,
            siginfo,
            target,
        })
    }

    /// Returns the raw Linux signal number.
    pub const fn signal(self) -> i32 {
        self.signal as i32
    }

    /// Returns the complete Linux `siginfo_t` bytes.
    pub const fn siginfo(self) -> [u8; SIGNAL_INFO_SIZE] {
        self.siginfo
    }

    /// Returns the target and original direction of the event.
    pub const fn target(self) -> SignalTarget {
        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn siginfo(signal: i32) -> [u8; SIGNAL_INFO_SIZE] {
        let mut info = [0; SIGNAL_INFO_SIZE];
        info[0..4].copy_from_slice(&signal.to_ne_bytes());
        info
    }

    #[test]
    fn signal_event_preserves_raw_realtime_number_payload_and_target() {
        let mut info = siginfo(64);
        for (index, byte) in info[4..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let target = SignalTarget::Thread {
            pid: Pid::from_raw(41),
            tid: Pid::from_raw(42),
        };
        let event = SignalEvent::new(64, info, target).unwrap();

        assert_eq!(event.signal(), 64);
        assert_eq!(event.siginfo(), info);
        assert_eq!(event.target(), target);
    }

    #[test]
    fn signal_event_rejects_invalid_or_incoherent_numbers() {
        let target = SignalTarget::Process {
            pid: Pid::from_raw(7),
        };
        for signal in [i32::MIN, -1, 0, 65, i32::MAX] {
            assert_eq!(
                SignalEvent::new(signal, siginfo(libc::SIGUSR1), target),
                Err(Errno::EINVAL),
                "accepted invalid signal {signal}",
            );
        }
        assert_eq!(
            SignalEvent::new(libc::SIGUSR2, siginfo(libc::SIGUSR1), target),
            Err(Errno::EINVAL),
            "accepted an event whose signal and siginfo.si_signo disagree",
        );
    }
}
