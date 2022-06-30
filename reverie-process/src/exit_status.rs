/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use std::os::unix::process::ExitStatusExt;

use nix::sys::signal::SigHandler;
use nix::sys::signal::SigSet;
use nix::sys::signal::SigmaskHow;
use nix::sys::signal::Signal;
use nix::sys::signal::{self};

/// Describes the result of a process after it has exited.
///
/// This is similar to `std::process::ExitStatus`, but is easier to match
/// against and provides additional functionality like `raise_or_exit` that
/// helps with propagating an exit status.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum ExitStatus {
    /// Program exited with an exit code.
    Exited(i32),
    /// Program killed by signal, with or without a coredump.
    Signaled(Signal, bool),
}

impl ExitStatus {
    /// A successful exit status.
    pub const SUCCESS: Self = ExitStatus::Exited(0);

    /// Construct an `ExitStatus` from a raw exit code.
    pub fn from_raw(code: i32) -> Self {
        if libc::WIFEXITED(code) {
            ExitStatus::Exited(libc::WEXITSTATUS(code))
        } else {
            ExitStatus::Signaled(
                Signal::try_from(libc::WTERMSIG(code)).unwrap(),
                libc::WCOREDUMP(code),
            )
        }
    }

    /// Converts the exit status into a raw number.
    pub fn into_raw(self) -> i32 {
        match self {
            ExitStatus::Exited(code) => code << 8,
            ExitStatus::Signaled(sig, coredump) => {
                if coredump {
                    (sig as i32 | 0x80) & 0xff
                } else {
                    sig as i32 & 0x7f
                }
            }
        }
    }

    /// If the process was terminated by a signal, returns that signal.
    pub fn signal(&self) -> Option<i32> {
        match self {
            ExitStatus::Exited(_) => None,
            ExitStatus::Signaled(sig, _) => Some(*sig as i32 & 0x7f),
        }
    }

    /// Was termination successful? Signal termination is not considered a
    /// success, and success is defined as a zero exit status.
    pub fn success(&self) -> bool {
        self == &ExitStatus::Exited(0)
    }

    /// Returns the exit code of the process, if any. If the process was
    /// terminated by a signal, this will return `None`.
    pub fn code(&self) -> Option<i32> {
        if let ExitStatus::Exited(code) = *self {
            Some(code)
        } else {
            None
        }
    }

    /// Propagate the exit status such that the current process exits in the same
    /// way that the child process exited.
    pub fn raise_or_exit(self) -> ! {
        match self {
            ExitStatus::Signaled(signal, core_dump) => {
                if core_dump {
                    // Prevent the current process from producing a core dump as
                    // well when the signal is propagated.
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
                }

                // Raise the same signal, which may or may not be fatal.
                let _ = unsafe { signal::signal(signal, SigHandler::SigDfl) };
                let _ = signal::raise(signal);

                // Unblock the signal.
                let mut mask = SigSet::empty();
                mask.add(signal);
                let _ = signal::sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&mask), None);

                // Incase the signal is not fatal:
                std::process::exit(signal as i32 + 128);
            }
            ExitStatus::Exited(code) => std::process::exit(code),
        }
    }
}

impl From<ExitStatus> for std::process::ExitStatus {
    fn from(status: ExitStatus) -> Self {
        Self::from_raw(status.into_raw())
    }
}

impl From<std::process::ExitStatus> for ExitStatus {
    fn from(status: std::process::ExitStatus) -> Self {
        if let Some(sig) = status.signal() {
            ExitStatus::Signaled(Signal::try_from(sig).unwrap(), true)
        } else {
            ExitStatus::Exited(status.code().unwrap_or(255))
        }
    }
}

impl serde::Serialize for ExitStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_i32(self.into_raw())
    }
}

impl<'de> serde::Deserialize<'de> for ExitStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = i32::deserialize(deserializer)?;
        Ok(ExitStatus::from_raw(value))
    }
}

#[cfg(all(test, not(sanitized)))]
mod tests_non_sanitized {
    use super::*;
    use nix::sys::signal::Signal;
    use nix::sys::signal::{self};
    use nix::sys::wait::waitpid;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::fork;
    use nix::unistd::ForkResult;

    // Runs a closure in a forked process and reports the exit status.
    fn run_forked<F>(f: F) -> nix::Result<ExitStatus>
    where
        F: FnOnce() -> nix::Result<()>,
    {
        match unsafe { fork() }? {
            ForkResult::Parent { child, .. } => {
                // Simply wait for the child to exit.
                match waitpid(child, None)? {
                    WaitStatus::Exited(_, code) => Ok(ExitStatus::Exited(code)),
                    WaitStatus::Signaled(_, sig, coredump) => {
                        Ok(ExitStatus::Signaled(sig, coredump))
                    }
                    wait_status => unreachable!("Got unexpected wait status: {:?}", wait_status),
                }
            }
            ForkResult::Child => {
                // Suppress core dumps for testing purposes.
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                unsafe {
                    // restore some sighandlers to default
                    for &sig in &[libc::SIGALRM, libc::SIGINT, libc::SIGVTALRM] {
                        libc::signal(sig, libc::SIG_DFL);
                    }
                    // disable coredump
                    libc::setrlimit(libc::RLIMIT_CORE, &limit)
                };

                // Run the child.
                let code = match f() {
                    Ok(()) => 0,
                    Err(err) => {
                        eprintln!("{}", err);
                        1
                    }
                };

                // The closure should have called `exit` by this point, but just
                // in case it didn't, call it ourselves.
                //
                // Note: We also can't use the normal exit function here because we
                // don't want to call atexit handlers since `execve` was never
                // called.
                unsafe { ::libc::_exit(code) };
            }
        }
    }

    #[test]
    fn normal_exit() {
        assert_eq!(
            run_forked(|| { unsafe { libc::_exit(0) } }),
            Ok(ExitStatus::Exited(0))
        );

        assert_eq!(
            run_forked(|| { unsafe { libc::_exit(42) } }),
            Ok(ExitStatus::Exited(42))
        );

        // Thread exit
        assert_eq!(
            run_forked(|| {
                unsafe { libc::syscall(libc::SYS_exit, 42) };
                unreachable!();
            }),
            Ok(ExitStatus::Exited(42))
        );

        // exit_group. Should be identical to `libc::_exit`.
        assert_eq!(
            run_forked(|| {
                unsafe { libc::syscall(libc::SYS_exit_group, 42) };
                unreachable!();
            }),
            Ok(ExitStatus::Exited(42))
        );
    }

    #[test]
    fn exit_by_signal() {
        assert_eq!(
            run_forked(|| {
                signal::raise(Signal::SIGALRM)?;
                unreachable!();
            }),
            Ok(ExitStatus::Signaled(Signal::SIGALRM, false))
        );

        assert_eq!(
            run_forked(|| {
                signal::raise(Signal::SIGILL)?;
                unreachable!();
            }),
            Ok(ExitStatus::Signaled(Signal::SIGILL, true))
        );
    }

    #[test]
    fn propagate_exit() {
        // NOTE: These tests fail under a sanitized build. ASAN leak detection
        // must be disabled for this to run correctly. To disable ASAN leak
        // detection, set the `ASAN_OPTIONS=detect_leaks=0` environment variable
        // *before* the test starts up. (This is currently done in the TARGETS
        // file.) Alternatively, we *could* bypass the atexit handler that ASAN
        // sets up by calling `libc::_exit`, but that may have unintended
        // consequences for real code.
        assert_eq!(
            run_forked(|| { ExitStatus::Exited(0).raise_or_exit() }),
            Ok(ExitStatus::Exited(0))
        );
        assert_eq!(
            run_forked(|| { ExitStatus::Exited(42).raise_or_exit() }),
            Ok(ExitStatus::Exited(42))
        );
    }

    #[test]
    fn propagate_signal() {
        assert_eq!(
            run_forked(|| { ExitStatus::Signaled(Signal::SIGILL, true).raise_or_exit() }),
            Ok(ExitStatus::Signaled(Signal::SIGILL, true))
        );
        assert_eq!(
            run_forked(|| { ExitStatus::Signaled(Signal::SIGALRM, false).raise_or_exit() }),
            Ok(ExitStatus::Signaled(Signal::SIGALRM, false))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_into_raw() {
        assert_eq!(ExitStatus::Exited(1).into_raw(), 0x1 << 8);
        assert_eq!(
            ExitStatus::Signaled(Signal::SIGINT, false).into_raw(),
            Signal::SIGINT as i32
        );
        assert_eq!(
            ExitStatus::Signaled(Signal::SIGILL, true).into_raw(),
            0x80 | Signal::SIGILL as i32
        );
        assert_ne!(
            ExitStatus::Exited(2).into_raw(),
            ExitStatus::Signaled(Signal::SIGINT, false).into_raw()
        );
    }

    #[test]
    fn exit_status_from_raw() {
        assert_eq!(ExitStatus::from_raw(0x100).code(), Some(1));
        assert_eq!(ExitStatus::from_raw(0x100).signal(), None);
        assert_eq!(ExitStatus::from_raw(0x84).code(), None);
        assert_eq!(ExitStatus::from_raw(0x84).signal(), Some(4));
    }
}
