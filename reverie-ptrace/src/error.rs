/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Pid;
use thiserror::Error;

/// The controller operation whose LiteInst activation invariants failed.
///
/// This is internal to the ptrace-owned LiteInst runtime. Keeping it typed lets
/// tests and internal consumers distinguish failure paths without parsing diagnostic
/// text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiteinstActivationOperation {
    ResumeInjectedSyscall,
    ResumeInterceptedInjectedSyscall,
    ResumeAfterSeccompStop,
    WaitForPostExecTrap,
    SkipInterceptedSyscall,
    FinishReinjectedSyscall,
    FinishInjectedSyscall,
}

/// Runtime stage in which a LiteInst activation invariant failed.
///
/// The stage is stored with the failure instead of inferred from its diagnostic
/// or reason. Some reasons, such as a rejected post-start `exec`, are possible
/// both before and after the preload handshake completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiteinstActivationStage {
    PreReady,
    PostReady,
}

impl LiteinstActivationOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ResumeInjectedSyscall => "resume injected syscall",
            Self::ResumeInterceptedInjectedSyscall => "resume intercepted injected syscall",
            Self::ResumeAfterSeccompStop => "resume after seccomp stop",
            Self::WaitForPostExecTrap => "wait for the LiteInst post-exec trap",
            Self::SkipInterceptedSyscall => "skip intercepted syscall",
            Self::FinishReinjectedSyscall => "finish reinjected syscall",
            Self::FinishInjectedSyscall => "finish injected syscall",
        }
    }
}

/// Stable classification for a fail-closed LiteInst activation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiteinstActivationFailureReason {
    UnexpectedPreinitSignal,
    ExecutableEntryBeforeHandshake,
    RestoreExecutableEntryGuard,
    UnexpectedActivationTrap,
    SignalBeforeHandshake(LiteinstActivationOperation),
    UnexpectedControllerProvenance(LiteinstActivationOperation),
    UnexpectedActivationSignal,
    PostStartExec,
    UnexpectedPostExecEvent,
    ExitedBeforePostExecTrap,
    InstallExecutableEntryGuard,
    TerminatedBeforeHandshake,
}

impl LiteinstActivationFailureReason {
    #[cfg(test)]
    const fn operation(self) -> Option<LiteinstActivationOperation> {
        match self {
            Self::SignalBeforeHandshake(operation)
            | Self::UnexpectedControllerProvenance(operation) => Some(operation),
            _ => None,
        }
    }
}

/// Semantic category of a LiteInst activation failure.
///
/// A general activation failure is distinct from a controller-operation
/// failure. For example, a tracee may fail closed before Ready after a valid
/// syscall-skip transition, while a failure attributed to that skip operation
/// means the transition itself was invalid.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiteinstActivationFailureCategory {
    General(LiteinstActivationStage),
    Operation {
        stage: LiteinstActivationStage,
        operation: LiteinstActivationOperation,
    },
}

/// A typed LiteInst activation failure retaining its human-readable diagnostic.
#[derive(Debug, Error)]
#[error("{error}")]
pub(crate) struct LiteinstActivationFailure {
    stage: LiteinstActivationStage,
    reason: LiteinstActivationFailureReason,
    #[source]
    error: Error,
}

impl LiteinstActivationFailure {
    pub(crate) fn new(
        stage: LiteinstActivationStage,
        reason: LiteinstActivationFailureReason,
        error: Error,
    ) -> Self {
        Self {
            stage,
            reason,
            error,
        }
    }

    #[cfg(test)]
    pub(crate) const fn reason(&self) -> LiteinstActivationFailureReason {
        self.reason
    }

    #[cfg(test)]
    pub(crate) const fn category(&self) -> LiteinstActivationFailureCategory {
        match self.reason.operation() {
            Some(operation) => LiteinstActivationFailureCategory::Operation {
                stage: self.stage,
                operation,
            },
            None => LiteinstActivationFailureCategory::General(self.stage),
        }
    }
}

#[cfg(test)]
pub(crate) fn liteinst_activation_failure_reason(
    error: &reverie::Error,
) -> Option<LiteinstActivationFailureReason> {
    let reverie::Error::Tool(error) = error else {
        return None;
    };
    error
        .downcast_ref::<LiteinstActivationFailure>()
        .map(LiteinstActivationFailure::reason)
}

#[cfg(test)]
pub(crate) fn liteinst_activation_failure_category(
    error: &reverie::Error,
) -> Option<LiteinstActivationFailureCategory> {
    let reverie::Error::Tool(error) = error else {
        return None;
    };
    error
        .downcast_ref::<LiteinstActivationFailure>()
        .map(LiteinstActivationFailure::category)
}

/// A reverie-ptrace error. This error type isn't meant to be exposed to the
/// user.
#[derive(Error, Debug)]
pub enum Error {
    /// An internal error that is only ever meant to be used as a reverie-ptrace
    /// implementation detail. None of these errors should make it through to the
    /// user.
    #[error(transparent)]
    Internal(#[from] safeptrace::Error),

    /// A ptrace failure annotated with the operation and tracee that failed.
    #[error("{operation} failed for tracee {pid}: {source}")]
    Tracee {
        /// The high-level ptrace operation that was in progress.
        operation: &'static str,
        /// The tracee on which the operation was attempted.
        pid: Pid,
        /// The underlying ptrace error.
        #[source]
        source: safeptrace::Error,
    },

    /// An internal runtime failure that is not represented by safeptrace.
    #[error("{operation} failed for tracee {pid}: {message}")]
    Runtime {
        /// The runtime operation that was in progress.
        operation: &'static str,
        /// The affected tracee.
        pid: Pid,
        /// Additional diagnostic detail.
        message: String,
    },

    /// A public error.
    #[error(transparent)]
    External(#[from] reverie::Error),
}

impl Error {
    pub(crate) fn runtime(pid: Pid, operation: &'static str, message: impl Into<String>) -> Self {
        Self::Runtime {
            operation,
            pid,
            message: message.into(),
        }
    }
}

impl From<reverie::Errno> for Error {
    fn from(error: reverie::Errno) -> Self {
        Self::Internal(safeptrace::Error::Errno(error))
    }
}

pub(crate) trait TraceResultExt<T> {
    fn tracee_context(self, pid: Pid, operation: &'static str) -> Result<T, Error>;
}

impl<T> TraceResultExt<T> for Result<T, safeptrace::Error> {
    fn tracee_context(self, pid: Pid, operation: &'static str) -> Result<T, Error> {
        self.map_err(|source| Error::Tracee {
            operation,
            pid,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use reverie::Errno;

    use super::*;

    #[test]
    fn tracee_error_includes_operation_and_pid() {
        let error = Err::<(), _>(safeptrace::Error::Errno(Errno::EPERM))
            .tracee_context(Pid::from_raw(42), "resume after seccomp stop")
            .expect_err("the synthetic ptrace operation should fail");

        let message = error.to_string();
        assert!(message.contains("resume after seccomp stop"));
        assert!(message.contains("42"));
        assert!(message.contains("Operation not permitted"));
    }

    fn activation_error(
        stage: LiteinstActivationStage,
        reason: LiteinstActivationFailureReason,
        message: &'static str,
    ) -> reverie::Error {
        anyhow::Error::new(LiteinstActivationFailure::new(
            stage,
            reason,
            Error::runtime(Pid::from_raw(42), "activate LiteInst", message),
        ))
        .into()
    }

    #[test]
    fn liteinst_activation_reason_accepts_the_qualifying_typed_failure() {
        let reason = LiteinstActivationFailureReason::UnexpectedControllerProvenance(
            LiteinstActivationOperation::FinishInjectedSyscall,
        );
        let error = activation_error(
            LiteinstActivationStage::PreReady,
            reason,
            "diagnostic wording is not authoritative",
        );

        assert_eq!(liteinst_activation_failure_reason(&error), Some(reason));
    }

    #[test]
    fn liteinst_activation_category_accepts_general_pre_ready_reasons() {
        for reason in [
            LiteinstActivationFailureReason::ExecutableEntryBeforeHandshake,
            LiteinstActivationFailureReason::UnexpectedActivationSignal,
        ] {
            let error = activation_error(
                LiteinstActivationStage::PreReady,
                reason,
                "diagnostic wording is not authoritative",
            );

            assert_eq!(
                liteinst_activation_failure_category(&error),
                Some(LiteinstActivationFailureCategory::General(
                    LiteinstActivationStage::PreReady,
                ))
            );
        }
    }

    #[test]
    fn liteinst_activation_category_rejects_operation_failures() {
        for (reason, operation) in [
            (
                LiteinstActivationFailureReason::UnexpectedControllerProvenance(
                    LiteinstActivationOperation::SkipInterceptedSyscall,
                ),
                LiteinstActivationOperation::SkipInterceptedSyscall,
            ),
            (
                LiteinstActivationFailureReason::SignalBeforeHandshake(
                    LiteinstActivationOperation::FinishInjectedSyscall,
                ),
                LiteinstActivationOperation::FinishInjectedSyscall,
            ),
        ] {
            let error = activation_error(
                LiteinstActivationStage::PreReady,
                reason,
                "before the required preload handshake completed",
            );

            assert_eq!(
                liteinst_activation_failure_category(&error),
                Some(LiteinstActivationFailureCategory::Operation {
                    stage: LiteinstActivationStage::PreReady,
                    operation,
                })
            );
            assert_ne!(
                liteinst_activation_failure_category(&error),
                Some(LiteinstActivationFailureCategory::General(
                    LiteinstActivationStage::PreReady,
                ))
            );
        }
    }

    #[test]
    fn liteinst_activation_category_rejects_post_ready_tampered_diagnostic() {
        let error = activation_error(
            LiteinstActivationStage::PostReady,
            LiteinstActivationFailureReason::UnexpectedActivationSignal,
            "before the required preload handshake completed",
        );

        assert_eq!(
            liteinst_activation_failure_category(&error),
            Some(LiteinstActivationFailureCategory::General(
                LiteinstActivationStage::PostReady,
            ))
        );
        assert_ne!(
            liteinst_activation_failure_category(&error),
            Some(LiteinstActivationFailureCategory::General(
                LiteinstActivationStage::PreReady,
            ))
        );
    }

    #[test]
    fn liteinst_activation_category_rejects_untyped_lookalike() {
        let error: reverie::Error =
            anyhow::anyhow!("tracee terminated before the required preload handshake completed")
                .into();

        assert_eq!(liteinst_activation_failure_category(&error), None);
    }
}
