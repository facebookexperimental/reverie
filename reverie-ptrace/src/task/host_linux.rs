/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The host kernel as ptrace's [`LinuxProvider`].
//!
//! Every syscall a Tool injects through
//! [`Guest::inject`](reverie::Guest::inject) runs here, through
//! [`LinuxProvider::execute`]. The provider owns no state: the host kernel
//! holds it all, and the stopped tracee is the execution handle
//! ([`LinuxProvider::Context`]). How the tracee runs the call stays in
//! [`TracedTask::inner_inject`], unchanged. That covers resuming the tracee's
//! own pending syscall when the request is that call, skipping the seccomp
//! stop before running a different one, and the injected-trap frame. None of
//! these is Linux semantics, so the provider passes only the request.
//!
//! [`Guest::inject_restartable`](reverie::Guest::inject_restartable) runs
//! through it too. A call that a signal stopped before it ran comes back as
//! [`ProviderOutcome::Interrupted`], and [`restartable`] decides from the
//! outcome whether to run the call again.
//!
//! The provider is zero-sized and built at each call, so the call is
//! dispatched statically. `execute`'s future is still boxed, because the
//! trait is an `async_trait`: dyn compatibility is what lets KVM call its
//! provider as `dyn LinuxProvider`.

use std::convert::Infallible;
use std::marker::PhantomData;

use reverie::Errno;
use reverie::Tid;
use reverie::Tool;
use reverie::provider::LinuxProvider;
use reverie::provider::ProviderOutcome;
use reverie::provider::SyscallRequest;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::Sysno;
use safeptrace::Error as TraceError;

use super::TracedTask;

/// The host kernel, reached by running the call in the stopped tracee.
pub(super) struct HostLinux<L>(PhantomData<fn() -> L>);

impl<L> HostLinux<L> {
    pub(super) fn new() -> Self {
        Self(PhantomData)
    }
}

#[reverie::provider]
impl<L: Tool + 'static> LinuxProvider for HostLinux<L> {
    type Context = TracedTask<L>;
    /// The host kernel carries out fork, clone and exec itself, so there is
    /// never a plan for the backend.
    type Plan = Infallible;
    type Error = TraceError;

    /// Runs `request` in `cx`, the stopped tracee, and reports its outcome:
    /// [`ProviderOutcome::Interrupted`] when a signal stopped the call before
    /// it ran, otherwise its raw Linux result.
    ///
    /// `task` must be the tracee's own tid, as the trait requires of a
    /// provider bound to one task; anything else is a broken backend
    /// invariant and returns `Err`. The only caller passes `cx`'s own tid.
    async fn execute(
        &mut self,
        task: Tid,
        request: &SyscallRequest,
        cx: &mut TracedTask<L>,
    ) -> Result<ProviderOutcome<Infallible>, TraceError> {
        if task != cx.tid {
            tracing::error!(
                "HostLinux was asked to run a call for tid {} in tracee {}",
                task,
                cx.tid
            );
            return Err(Errno::EPROTO.into());
        }
        let (nr, args) = parts(request)?;
        let result = cx.inner_inject(nr, args).await?;
        Ok(classify(result, cx.last_injection_ran))
    }
}

/// The request for an injection of `nr` with `args`.
pub(super) fn request(nr: Sysno, args: SyscallArgs) -> SyscallRequest {
    SyscallRequest::new(
        nr as u64,
        [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ],
    )
}

/// The syscall number and arguments of `request`. The request was built by
/// [`request`] from a valid [`Sysno`], so the number always converts back; a
/// number that does not is a broken invariant, not a guest error.
fn parts(request: &SyscallRequest) -> Result<(Sysno, SyscallArgs), TraceError> {
    let nr = usize::try_from(request.number())
        .ok()
        .and_then(Sysno::new)
        .ok_or_else(|| TraceError::from(Errno::EPROTO))?;
    let args = request.args().map(|arg| arg as usize);
    Ok((nr, SyscallArgs::from(&args)))
}

/// The raw Linux return value of `result`, as the register holds it.
fn encode(result: Result<i64, Errno>) -> i64 {
    match result {
        Ok(value) => value,
        Err(errno) => -i64::from(errno.into_raw()),
    }
}

/// The guest's view of a raw Linux return value, decoded as
/// `status_to_result` decodes the register.
fn decode(raw: i64) -> Result<i64, Errno> {
    Errno::from_ret(raw as usize).map(|value| value as i64)
}

/// The outcome of an injection whose result is `result`, where `ran` is
/// `status_to_result`'s record of whether the syscall ran
/// (`TracedTask::last_injection_ran`, set for this injection).
///
/// `status_to_result` clears `ran` only where it reports a call that a signal
/// stopped before it ran, and then its result is always `ERESTARTSYS`. The
/// only later rewrites of an injection's result, at the two places where
/// `untraced_syscall_with` finds a guest seccomp filter's trap, make it
/// `ENOSYS`, a call that did not run either but was not interrupted. So a
/// result of `ERESTARTSYS` with `ran` clear is exactly an interrupted call.
/// Every other result, including a call that ran and returned `EINTR` or
/// `ERESTARTSYS`, is a `Return`.
fn classify(result: Result<i64, Errno>, ran: bool) -> ProviderOutcome<Infallible> {
    if !ran && result == Err(Errno::ERESTARTSYS) {
        ProviderOutcome::Interrupted
    } else {
        ProviderOutcome::Return(encode(result))
    }
}

/// The `Guest::inject` result for `outcome`. `HostLinux` produces only
/// [`ProviderOutcome::Return`] and [`ProviderOutcome::Interrupted`]. An
/// interrupted call is `ERESTARTSYS`, as `Guest::inject` documents for a call
/// that a signal stopped before it ran. Any other outcome is a broken
/// invariant and ends the run, as a trace error does.
pub(super) fn guest_result(
    outcome: ProviderOutcome<Infallible>,
) -> Result<Result<i64, Errno>, TraceError> {
    match outcome {
        ProviderOutcome::Return(raw) => Ok(decode(raw)),
        ProviderOutcome::Interrupted => Ok(Err(Errno::ERESTARTSYS)),
        _ => Err(Errno::EPROTO.into()),
    }
}

/// What `Guest::inject_restartable` does with one injection's outcome.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Restart {
    /// Inject the call again.
    Retry,
    /// Return this result to the Tool.
    Return(Result<i64, Errno>),
}

/// `Guest::inject_restartable`'s decision for `outcome`, where `held` says
/// whether a signal is held for delivery as the guest resumes
/// (`pending_signal`), read after the injection.
///
/// - An interrupted call did not run, so it is retried.
/// - A call that ran and returned `EINTR` or `ERESTARTSYS` returns that code
///   when a signal is held: Linux restarts the guest's syscall, or fails it
///   with `EINTR`, as the held signal is delivered
///   (<https://github.com/rrnewton/reverie/issues/998>). Without a held
///   signal it is retried.
/// - Every other result is returned.
pub(super) fn restartable(
    outcome: ProviderOutcome<Infallible>,
    held: bool,
) -> Result<Restart, TraceError> {
    Ok(match outcome {
        ProviderOutcome::Interrupted => Restart::Retry,
        ProviderOutcome::Return(raw) => match decode(raw) {
            Err(error @ (Errno::EINTR | Errno::ERESTARTSYS)) if held => Restart::Return(Err(error)),
            Err(Errno::EINTR | Errno::ERESTARTSYS) => Restart::Retry,
            result => Restart::Return(result),
        },
        _ => return Err(Errno::EPROTO.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value `status_to_result` can produce survives the provider's
    /// raw encoding: a success, including one that reads as a large negative
    /// number outside the errno range, and every errno, including the codes
    /// ptrace synthesises (`ERESTARTSYS`, `ENOSYS`) and the largest one.
    #[test]
    fn the_raw_result_encoding_is_lossless() {
        for raw in [0, 1, 4095, 4096, i64::MAX, -4096, i64::MIN] {
            let result = decode(raw);
            assert!(result.is_ok(), "{raw} decodes as a success");
            assert_eq!(encode(result), raw);
        }
        for errno in [
            Errno::EPERM,
            Errno::EINTR,
            Errno::ENOSYS,
            Errno::ERESTARTSYS,
            Errno::new(4095),
        ] {
            assert_eq!(decode(encode(Err(errno))), Err(errno));
        }
        assert_eq!(decode(-1), Err(Errno::EPERM));
        assert_eq!(decode(-512), Err(Errno::ERESTARTSYS));
        assert_eq!(decode(-4095), Err(Errno::new(4095)));
    }

    /// The request round-trips the syscall number and all six arguments,
    /// including arguments with the top bit set.
    #[test]
    fn the_request_round_trips_number_and_arguments() {
        let args = SyscallArgs::new(0, 1, usize::MAX, 0x7fff_ffff_f000, 42, 1 << 63);
        for nr in [
            Sysno::getppid,
            Sysno::read,
            Sysno::execve,
            Sysno::rt_sigreturn,
        ] {
            assert_eq!(parts(&request(nr, args)).unwrap(), (nr, args));
        }
    }

    /// A number that names no syscall is a broken invariant, not a guest
    /// errno.
    #[test]
    fn a_request_with_an_unknown_number_is_refused() {
        assert!(parts(&SyscallRequest::new(u64::MAX, [0; 6])).is_err());
    }

    /// Only `Return` and `Interrupted` are `Guest::inject` results.
    #[test]
    fn only_a_return_or_interrupted_outcome_is_a_guest_result() {
        assert_eq!(
            guest_result(ProviderOutcome::Return(-38)).unwrap(),
            Err(Errno::ENOSYS)
        );
        assert_eq!(
            guest_result(ProviderOutcome::Interrupted).unwrap(),
            Err(Errno::ERESTARTSYS)
        );
        assert!(guest_result(ProviderOutcome::Cancelled).is_err());
        assert!(
            guest_result(ProviderOutcome::ThreadGroupExited {
                status: reverie::ExitStatus::Exited(0),
            })
            .is_err()
        );
        assert!(
            guest_result(ProviderOutcome::SegmentBase {
                result: 0,
                register: reverie::provider::SegmentRegister::Fs,
                base: 0x1000,
            })
            .is_err()
        );
    }

    /// `Guest::inject_restartable`'s decision before provider step E3b,
    /// from the injection's result, `TracedTask::last_injection_ran` and
    /// whether a signal is held. It is copied from the loop it replaced.
    fn decision_before_e3b(result: Result<i64, Errno>, ran: bool, held: bool) -> Restart {
        match result {
            Err(error @ (Errno::EINTR | Errno::ERESTARTSYS)) if ran && held => {
                Restart::Return(Err(error))
            }
            Err(Errno::EINTR) | Err(Errno::ERESTARTSYS) => Restart::Retry,
            result => Restart::Return(result),
        }
    }

    /// Whether `status_to_result` and the seccomp-trap rewrite can produce
    /// `result` with `ran`: a call that did not run reports `ERESTARTSYS`, or
    /// `ENOSYS` after a guest seccomp trap (see `classify`).
    fn reachable(result: Result<i64, Errno>, ran: bool) -> bool {
        ran || result == Err(Errno::ERESTARTSYS) || result == Err(Errno::ENOSYS)
    }

    const RESULTS: [Result<i64, Errno>; 8] = [
        Ok(0),
        Ok(7),
        Ok(i64::MAX),
        Err(Errno::EINTR),
        Err(Errno::ERESTARTSYS),
        Err(Errno::ENOSYS),
        Err(Errno::EAGAIN),
        Err(Errno::ERESTARTNOHAND),
    ];

    /// The decision table of `inject_restartable`, row for row: for every
    /// reachable result, `ran` and held-signal state, the outcome `classify`
    /// reports leads `restartable` to the decision the loop made before E3b
    /// from `last_injection_ran`, and `Guest::inject` returns the same
    /// result as before.
    #[test]
    fn the_restart_decision_table_is_unchanged() {
        let mut rows = 0;
        for result in RESULTS {
            for ran in [false, true] {
                if !reachable(result, ran) {
                    continue;
                }
                let outcome = classify(result, ran);
                assert_eq!(
                    guest_result(outcome).unwrap(),
                    result,
                    "{result:?} ran={ran}"
                );
                for held in [false, true] {
                    assert_eq!(
                        restartable(outcome, held).unwrap(),
                        decision_before_e3b(result, ran, held),
                        "{result:?} ran={ran} held={held}"
                    );
                    rows += 1;
                }
            }
        }
        // 8 results that ran and 2 that did not, each with and without a held signal.
        assert_eq!(rows, 20);
    }

    /// Only an `ERESTARTSYS` from a call that did not run is `Interrupted`.
    /// The same code from a call that ran stays a `Return`, as does the
    /// `ENOSYS` of a call a guest seccomp filter trapped.
    #[test]
    fn only_a_call_that_did_not_run_is_interrupted() {
        assert_eq!(
            classify(Err(Errno::ERESTARTSYS), false),
            ProviderOutcome::Interrupted
        );
        assert_eq!(
            classify(Err(Errno::ERESTARTSYS), true),
            ProviderOutcome::Return(-512)
        );
        assert_eq!(
            classify(Err(Errno::EINTR), true),
            ProviderOutcome::Return(-4)
        );
        assert_eq!(
            classify(Err(Errno::ENOSYS), false),
            ProviderOutcome::Return(-38)
        );
        assert_eq!(classify(Ok(3), true), ProviderOutcome::Return(3));
    }

    /// `restartable` refuses an outcome `HostLinux` never produces.
    #[test]
    fn restartable_refuses_an_outcome_host_linux_never_produces() {
        assert!(restartable(ProviderOutcome::Cancelled, true).is_err());
    }
}
