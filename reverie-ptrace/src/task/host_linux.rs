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

    /// Runs `request` in `cx`, the stopped tracee, and reports its raw Linux
    /// result.
    ///
    /// `task` is the tracee's tid: the only caller passes `cx`'s own tid,
    /// so the two are equal by construction. Debug builds assert it.
    async fn execute(
        &mut self,
        task: Tid,
        request: &SyscallRequest,
        cx: &mut TracedTask<L>,
    ) -> Result<ProviderOutcome<Infallible>, TraceError> {
        debug_assert_eq!(
            task, cx.tid,
            "HostLinux runs only the issuing tracee's calls"
        );
        let (nr, args) = parts(request)?;
        let result = cx.inner_inject(nr, args).await?;
        Ok(ProviderOutcome::Return(encode(result)))
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

/// The `Guest::inject` result for `outcome`. `HostLinux` produces only
/// [`ProviderOutcome::Return`]; any other outcome is a broken invariant and
/// ends the run, as a trace error does.
pub(super) fn guest_result(
    outcome: ProviderOutcome<Infallible>,
) -> Result<Result<i64, Errno>, TraceError> {
    match outcome {
        ProviderOutcome::Return(raw) => Ok(decode(raw)),
        _ => Err(Errno::EPROTO.into()),
    }
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

    /// Only `Return` is a `Guest::inject` result.
    #[test]
    fn only_a_return_outcome_is_a_guest_result() {
        assert_eq!(
            guest_result(ProviderOutcome::Return(-38)).unwrap(),
            Err(Errno::ENOSYS)
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
}
