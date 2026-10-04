/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Failed ordinary-ptrace runs retain their causes independently of guest status.

use std::fmt;
use std::sync::Arc;

use reverie::BackendFailure;
use reverie::Error;
use reverie::ExitStatus;

/// Bytes actually read from a captured run, without a fabricated guest status.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CapturedPrefix {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl CapturedPrefix {
    /// The exact stdout bytes read before EOF, a reader error, or a pending yield.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// The exact stderr bytes read before EOF, a reader error, or a pending yield.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

/// An actual later error, retained without replacing the run's first cause.
#[derive(Clone, Debug)]
pub struct PtraceCleanupFailure {
    pub(crate) origin: BackendFailure,
    pub(crate) error: Arc<Error>,
}

impl PtraceCleanupFailure {
    /// The task and operation which reported this error.
    pub fn origin(&self) -> BackendFailure {
        self.origin
    }

    /// The original typed error, including a Tool or I/O error's source payload.
    pub fn error(&self) -> &Error {
        &self.error
    }
}

/// A failed backend run. This is not a guest exit status.
#[derive(Debug)]
pub struct PtraceRunFailure {
    pub(crate) primary: Arc<Error>,
    pub(crate) origin: BackendFailure,
    pub(crate) secondary: Vec<PtraceCleanupFailure>,
    pub(crate) captured_prefix: Option<CapturedPrefix>,
}

impl PtraceRunFailure {
    /// The exact first error, available for typed Tool-error downcasts.
    pub fn primary(&self) -> &Error {
        &self.primary
    }

    /// The origin captured atomically with the first error.
    pub fn origin(&self) -> BackendFailure {
        self.origin
    }

    /// Actual subsequent failures in capture order.
    pub fn secondary(&self) -> &[PtraceCleanupFailure] {
        &self.secondary
    }

    /// Captured bytes, including empty buffers when capture was requested.
    ///
    /// Plain and discarding waits return `None`. A pending outcome's prefix is
    /// the prefix at that yield; only completed EOF certifies a complete stream.
    pub fn captured_prefix(&self) -> Option<&CapturedPrefix> {
        self.captured_prefix.as_ref()
    }

    pub(crate) fn snapshot(&self) -> Self {
        Self {
            primary: self.primary.clone(),
            origin: self.origin,
            secondary: self.secondary.clone(),
            captured_prefix: None,
        }
    }

    pub(crate) fn into_legacy_error(self) -> Error {
        let Self {
            primary,
            origin,
            secondary,
            captured_prefix,
        } = self;
        match Arc::try_unwrap(primary) {
            Ok(error) if secondary.is_empty() => error,
            Ok(Error::Tool(error)) => {
                let primary_display = error.to_string();
                Error::Tool(error.context(LegacyCleanupDiagnostics {
                    primary_display,
                    origin,
                    secondary,
                    captured_prefix,
                }))
            }
            Ok(error) => Error::Tool(anyhow::Error::new(LegacyFailureProjection {
                failure: Self {
                    primary: Arc::new(error),
                    origin,
                    secondary,
                    captured_prefix,
                },
            })),
            Err(primary) => Error::Tool(anyhow::Error::new(LegacyFailureProjection {
                failure: Self {
                    primary,
                    origin,
                    secondary,
                    captured_prefix,
                },
            })),
        }
    }
}

/// Typed cleanup context attached to a uniquely owned legacy Tool error.
///
/// The original Anyhow error remains the cause: its direct payload downcasts
/// still work. This context retains the actual later errors in capture order,
/// their origins, and any captured bytes. The primary text is only a display
/// snapshot; it never substitutes for the original typed cause.
#[derive(Debug)]
pub struct LegacyCleanupDiagnostics {
    primary_display: String,
    origin: BackendFailure,
    secondary: Vec<PtraceCleanupFailure>,
    captured_prefix: Option<CapturedPrefix>,
}

impl LegacyCleanupDiagnostics {
    /// The original primary failure's origin.
    pub fn origin(&self) -> BackendFailure {
        self.origin
    }

    /// The original typed subsequent errors, in capture order.
    pub fn secondary(&self) -> &[PtraceCleanupFailure] {
        &self.secondary
    }

    /// The actual captured bytes, if this wait requested capture.
    pub fn captured_prefix(&self) -> Option<&CapturedPrefix> {
        self.captured_prefix.as_ref()
    }
}

impl fmt::Display for LegacyCleanupDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} at pid={}, tid={})",
            self.primary_display, self.origin.phase, self.origin.pid, self.origin.tid
        )?;
        for secondary in &self.secondary {
            write!(f, "; {}: {}", secondary.origin.phase, secondary.error)?;
        }
        Ok(())
    }
}

impl fmt::Display for PtraceRunFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} at pid={}, tid={})",
            self.primary, self.origin.phase, self.origin.pid, self.origin.tid
        )?;
        for secondary in &self.secondary {
            write!(f, "; {}: {}", secondary.origin.phase, secondary.error)?;
        }
        Ok(())
    }
}

impl std::error::Error for PtraceRunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.primary())
    }
}

/// A confirmed failed run could not move its primary into the legacy error.
///
/// This typed diagnostic is returned when another diagnostic still shares the
/// primary, or a non-Tool primary has later cleanup failures. It retains the
/// complete failure, including the primary's original variant and typed cause.
/// Callers downcast to this type and inspect [`Self::failure`]. A unique Tool
/// primary instead keeps its direct payload downcast and carries any later
/// failures in [`LegacyCleanupDiagnostics`].
#[derive(Debug)]
pub struct LegacyFailureProjection {
    failure: PtraceRunFailure,
}

impl LegacyFailureProjection {
    /// The complete original failed run, including its typed primary.
    pub fn failure(&self) -> &PtraceRunFailure {
        &self.failure
    }
}

impl fmt::Display for LegacyFailureProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "legacy ptrace failure projection retained the original failure: {}",
            self.failure
        )
    }
}

impl std::error::Error for LegacyFailureProjection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.failure)
    }
}

/// The actual kernel-derived class of the callback's current held stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtraceCallbackStop {
    /// A signal-delivery stop, containing its signal number.
    Signal(i32),
    /// A ptrace event, containing the Linux PTRACE_EVENT_* number.
    Event(i32),
    /// A TRACESYSGOOD syscall stop.
    Syscall,
    /// A seized/group-stop class; unexpected for the ordinary TRACEME path.
    Stop,
}

/// A typed refusal to resolve a raw callback errno against its held lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PtraceCallbackRefusal {
    /// No current armed stop with the task's original Event generation exists.
    #[error("callback has no matching armed held stop")]
    HeldStop,
    /// Callback observation left the ordinary session's original ptracer thread.
    #[error("callback observation left its original ptracer thread")]
    WrongThread,
    /// The observational handle refused its binding.
    #[error("callback stop observation: {0}")]
    Binding(safeptrace::StopObservationError),
    /// A raw GETSIGINFO error other than the interrupted-stop ESRCH case.
    #[error("callback GETSIGINFO refused: {0}")]
    Query(reverie::Errno),
    /// The exact retained thread-pidfd query failed.
    #[error("callback thread-pidfd observation refused: {0}")]
    Pidfd(reverie::Errno),
    /// A retained proc read or parser refused the bounded record.
    #[error("callback retained proc observation refused: {0}")]
    Proc(safeptrace::ProcStatError),
    /// An expected raw fact is absent or inconsistent with the actual held class.
    #[error("callback stop observation is inconsistent: {0}")]
    Inconsistent(&'static str),
}

/// The decision made when the backend actually received a raw callback errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtraceCallbackDecision {
    /// The live callback's original errno was published as a fatal cause.
    Fatal,
    /// A typed observation refusal accompanied that original fatal cause.
    Refused,
    /// The original lifecycle owner must supply EXIT, terminal or Exec status.
    AwaitingOwner,
    /// Another already-published failure owns cancellation of this callback.
    Cancelled,
}

/// The actual result subsequently obtained by the callback's original owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtraceCallbackOutcome {
    /// An actual terminal wait status, not inferred from an error or flag.
    Exited(ExitStatus),
    /// An actual Exec transfer after the old leader's real EXIT stop.
    Exec {
        /// The former thread named by the kernel's Exec event.
        former: reverie::Pid,
        /// The preceding EXIT event's status, not a fabricated terminal wait.
        exit_stop_status: ExitStatus,
    },
}

/// Original raw callback error and the lifecycle observations that followed it.
///
/// Errno-only APIs erase causal provenance. An AwaitingOwner decision describes
/// cancellation/death precedence, not proof that memory access caused this errno.
#[derive(Clone, Debug)]
pub struct PtraceCallbackDiagnostic {
    pub(crate) origin: BackendFailure,
    pub(crate) errno: reverie::Errno,
    pub(crate) held: Option<PtraceCallbackStop>,
    pub(crate) sample: Option<safeptrace::StopObservationSample>,
    pub(crate) refusal: Option<PtraceCallbackRefusal>,
    pub(crate) decision: PtraceCallbackDecision,
    pub(crate) outcome: Option<PtraceCallbackOutcome>,
    pub(crate) failure_published_at_outcome: bool,
    pub(crate) backend_signalling_at_outcome: bool,
}
impl PtraceCallbackDiagnostic {
    /// The exact callback PID, TID and operation.
    pub fn origin(&self) -> BackendFailure {
        self.origin
    }
    /// The original raw return value, independently of later observations.
    pub fn errno(&self) -> reverie::Errno {
        self.errno
    }
    /// The actual current held class, including changes due to Guest injection.
    pub fn held_stop(&self) -> Option<PtraceCallbackStop> {
        self.held
    }
    /// All attempted raw sample facts, when observation was admitted.
    pub fn sample(&self) -> Option<&safeptrace::StopObservationSample> {
        self.sample.as_ref()
    }
    /// The concrete typed refusal, if observation did not justify a decision.
    pub fn refusal(&self) -> Option<&PtraceCallbackRefusal> {
        self.refusal.as_ref()
    }
    /// The decision at the observed callback return.
    pub fn decision(&self) -> PtraceCallbackDecision {
        self.decision
    }
    /// The original owner's actual result, absent while unresolved.
    pub fn owner_outcome(&self) -> Option<PtraceCallbackOutcome> {
        self.outcome
    }
    /// Failure-publication flag sampled when the sole owner received its actual
    /// result, before any later retirement wait. The two flag reads are separate
    /// monotonic observations, not an atomic multi-field snapshot.
    pub fn failure_published_at_outcome(&self) -> bool {
        self.failure_published_at_outcome
    }
    /// Backend-signalling flag sampled at that same result-receipt boundary,
    /// before any later retirement wait. This is a separate monotonic read.
    /// This is observation ordering, not attribution of this task's death.
    pub fn backend_signalling_at_outcome(&self) -> bool {
        self.backend_signalling_at_outcome
    }
}

/// Confirmed physical and consuming completion, including failed global state.
#[derive(Debug)]
pub struct ToolRunCompletion<G, R = ExitStatus> {
    /// The original global Tool state, after every backend-owned consumer joined.
    pub global_state: G,
    /// A genuine guest result, or a typed failed run with any captured prefixes.
    pub result: Result<R, PtraceRunFailure>,
    pub(crate) callback_diagnostics: Vec<PtraceCallbackDiagnostic>,
}

impl<G, R> ToolRunCompletion<G, R> {
    /// Original Errno-only callback returns, including those cancelled by a real
    /// lifecycle outcome. Legacy successful waits project this collection away.
    pub fn callback_diagnostics(&self) -> &[PtraceCallbackDiagnostic] {
        &self.callback_diagnostics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, thiserror::Error)]
    #[error("non-clone original marker {0}")]
    struct Marker(Box<u64>);

    fn failure() -> PtraceRunFailure {
        PtraceRunFailure {
            primary: Arc::new(Error::Tool(anyhow::Error::new(Marker(Box::new(71))))),
            origin: BackendFailure {
                pid: reverie::Pid::from_raw(17),
                tid: reverie::Pid::from_raw(18),
                phase: "test original",
            },
            secondary: Vec::new(),
            captured_prefix: Some(CapturedPrefix {
                stdout: vec![0, 255, 7],
                stderr: vec![9, 0],
            }),
        }
    }

    #[test]
    fn unique_legacy_projection_preserves_direct_nonclone_marker() {
        let Error::Tool(error) = failure().into_legacy_error() else {
            panic!("lost Tool variant")
        };
        assert_eq!(
            *error
                .downcast_ref::<Marker>()
                .expect("original direct downcast")
                .0,
            71
        );
    }

    #[test]
    fn unique_legacy_projection_preserves_secondary_and_direct_nonclone_marker() {
        let mut failure = failure();
        let Error::Tool(primary) = failure.primary() else {
            panic!("original Tool variant")
        };
        let original = &*primary.downcast_ref::<Marker>().unwrap().0 as *const u64;
        failure.secondary.push(PtraceCleanupFailure {
            origin: BackendFailure {
                pid: reverie::Pid::from_raw(17),
                tid: reverie::Pid::from_raw(18),
                phase: "injected tracee cleanup confirmation",
            },
            error: Arc::new(std::io::Error::from_raw_os_error(libc::EIO).into()),
        });
        let Error::Tool(error) = failure.into_legacy_error() else {
            panic!("lost Tool variant")
        };
        let marker = error
            .downcast_ref::<Marker>()
            .expect("original direct downcast");
        assert_eq!(*marker.0, 71);
        assert_eq!(
            &*marker.0 as *const u64, original,
            "original payload replaced"
        );
        assert!(
            error.to_string().contains("Input/output error"),
            "actual cleanup failure disappeared from legacy diagnostic: {error}"
        );
    }

    #[test]
    fn legacy_cleanup_context_retains_typed_order_origins_and_prefix() {
        let mut failure = failure();
        let origin = failure.origin();
        for (phase, errno) in [("discovery", libc::EIO), ("scan", libc::EBADF)] {
            failure.secondary.push(PtraceCleanupFailure {
                origin: BackendFailure { phase, ..origin },
                error: Arc::new(std::io::Error::from_raw_os_error(errno).into()),
            });
        }
        let Error::Tool(error) = failure.into_legacy_error() else {
            panic!("Tool error")
        };
        assert_eq!(*error.downcast_ref::<Marker>().unwrap().0, 71);
        let context = error.downcast_ref::<LegacyCleanupDiagnostics>().unwrap();
        assert_eq!(context.origin(), origin);
        assert_eq!(context.secondary().len(), 2);
        for (actual, (phase, errno)) in context
            .secondary()
            .iter()
            .zip([("discovery", libc::EIO), ("scan", libc::EBADF)])
        {
            assert_eq!(actual.origin(), BackendFailure { phase, ..origin });
            assert!(
                matches!(actual.error(), Error::Io(error) if error.raw_os_error() == Some(errno))
            );
        }
        assert_eq!(context.captured_prefix().unwrap().stdout(), &[0, 255, 7]);
        assert_eq!(context.captured_prefix().unwrap().stderr(), &[9, 0]);
    }

    #[test]
    fn non_tool_legacy_projection_retains_primary_variant_and_secondary() {
        for primary in [
            Error::Errno(reverie::Errno::ENOTSUPP),
            std::io::Error::from_raw_os_error(libc::EPIPE).into(),
        ] {
            let mut failure = failure();
            failure.primary = Arc::new(primary);
            failure.secondary.push(PtraceCleanupFailure {
                origin: failure.origin(),
                error: Arc::new(std::io::Error::from_raw_os_error(libc::EIO).into()),
            });
            let was_errno = matches!(failure.primary(), Error::Errno(_));
            let Error::Tool(error) = failure.into_legacy_error() else {
                panic!("typed projection")
            };
            let failure = error
                .downcast_ref::<LegacyFailureProjection>()
                .unwrap()
                .failure();
            if was_errno {
                assert!(
                    matches!(failure.primary(), Error::Errno(error) if *error == reverie::Errno::ENOTSUPP)
                );
            } else {
                assert!(
                    matches!(failure.primary(), Error::Io(error) if error.raw_os_error() == Some(libc::EPIPE))
                );
            }
            assert_eq!(failure.secondary().len(), 1);
            assert!(
                matches!(failure.secondary()[0].error(), Error::Io(error) if error.raw_os_error() == Some(libc::EIO))
            );
            assert_eq!(failure.captured_prefix().unwrap().stdout(), &[0, 255, 7]);
            assert!(error.to_string().contains("Input/output error"));
        }
    }

    #[test]
    fn shared_legacy_projection_is_typed_and_keeps_complete_original_failure() {
        let failure = failure();
        let snapshot = failure.snapshot();
        let origin = failure.origin();
        let Error::Tool(error) = failure.into_legacy_error() else {
            panic!("lost projection diagnostic")
        };
        let projection = error
            .downcast_ref::<LegacyFailureProjection>()
            .expect("typed shared-primary refusal");
        assert_eq!(projection.failure().origin(), origin);
        assert_eq!(
            projection.failure().captured_prefix().unwrap().stdout(),
            &[0, 255, 7]
        );
        assert_eq!(
            projection.failure().captured_prefix().unwrap().stderr(),
            &[9, 0]
        );
        let Error::Tool(primary) = projection.failure().primary() else {
            panic!("original Tool cause")
        };
        assert_eq!(*primary.downcast_ref::<Marker>().unwrap().0, 71);
        assert!(Arc::ptr_eq(&projection.failure.primary, &snapshot.primary));
    }
}
