/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use super::ExitStatus;
use super::Pid;

use super::stdio::{ChildStderr, ChildStdin, ChildStdout, Stdio};
use super::Command;

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use std::io;
use syscalls::Errno;

/// Represents a child process.
///
/// NOTE: The child process is not killed or waited on when `Child` is dropped.
/// If `Child` is not waited on before dropped, the child will continue to run in
/// the background and may become a "zombie" after the parent exits. It is
/// therefore best practice to always wait on child processes.
#[derive(Debug)]
pub struct Child {
    /// The child's process ID.
    pub(super) pid: Pid,

    /// The child's exit status. `Some` if the child has exited already, `None`
    /// otherwise.
    pub(super) exit_status: Option<ExitStatus>,

    /// The handle for writing to the child's standard input (stdin), if it has
    /// been captured.
    pub stdin: Option<ChildStdin>,

    /// The handle for reading from the child's standard output (stdout), if it
    /// has been captured.
    pub stdout: Option<ChildStdout>,

    /// The handle for reading from the child's standard error (stderr), if it
    /// has been captured.
    pub stderr: Option<ChildStderr>,
}

/// The output of a finished process.
#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Output {
    /// The exit status of the process.
    pub status: ExitStatus,
    /// The bytes that the process wrote to stdout.
    pub stdout: Vec<u8>,
    /// The bytes that the process wrote to stderr.
    pub stderr: Vec<u8>,
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let stdout = core::str::from_utf8(&self.stdout);
        let stdout: &dyn fmt::Debug = match stdout {
            Ok(ref s) => s,
            Err(_) => &self.stdout,
        };

        let stderr = core::str::from_utf8(&self.stderr);
        let stderr: &dyn fmt::Debug = match stderr {
            Ok(ref s) => s,
            Err(_) => &self.stderr,
        };

        f.debug_struct("Output")
            .field("status", &self.status)
            .field("stdout", stdout)
            .field("stderr", stderr)
            .finish()
    }
}

impl Child {
    /// Returns the PID of the child.
    pub fn id(&self) -> Pid {
        self.pid
    }

    /// Attempts to collect the exit status of the child if it has already
    /// exited.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.exit_status {
            Some(exit_status) => Ok(Some(exit_status)),
            None => {
                let mut status = 0;
                let ret = Errno::result(unsafe {
                    libc::waitpid(self.pid.as_raw(), &mut status, libc::WNOHANG)
                })?;

                if ret == 0 {
                    Ok(None)
                } else {
                    let exit_status = ExitStatus::from_raw(status);
                    self.exit_status = Some(exit_status);
                    Ok(Some(exit_status))
                }
            }
        }
    }

    /// Waits for the child to exit completely, returning its exit status. This
    /// function will continue to return the same exit status after the child
    /// process has fully exited.
    ///
    /// To avoid deadlocks, the child's stdin handle, if any, will be closed
    /// before waiting. Otherwise, the child could block waiting for input from
    /// the parent while the parent is waiting for the child. To keep the stdin
    /// handle open and control it explicitly, the caller can `.take()` it before
    /// calling `.wait()`.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        // Ensure stdin is closed.
        drop(self.stdin.take());

        WaitForChild::new(self)?.await
    }

    /// Blocks until the child process exits.
    pub fn wait_blocking(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdin.take());

        let mut status = 0;

        let ret = loop {
            match Errno::result(unsafe { libc::waitpid(self.pid.as_raw(), &mut status, 0) }) {
                Ok(ret) => break ret,
                Err(Errno::EINTR) => continue,
                Err(err) => return Err(err.into()),
            }
        };

        debug_assert_ne!(ret, 0);

        Ok(ExitStatus::from_raw(status))
    }

    /// Simultaneously waits for the child to exit and collect all remaining
    /// output on the stdout/stderr handles, returning an `Output` instance.
    ///
    /// To avoid deadlocks, the child's stdin handle, if any, will be closed
    /// before waiting. Otherwise, the child could block waiting for input from
    /// the parent while the parent is waiting for the child.
    ///
    /// By default, stdin, stdout and stderr are inherited from the parent. In
    /// order to capture the output into this `Result<Output>` it is necessary to
    /// create new pipes between parent and child. Use `stdout(Stdio::piped())`
    /// or `stderr(Stdio::piped())`, respectively.
    pub async fn wait_with_output(mut self) -> io::Result<Output> {
        use futures::future::try_join3;
        use tokio::io::{AsyncRead, AsyncReadExt};

        async fn read_to_end<A: AsyncRead + Unpin>(io: Option<A>) -> io::Result<Vec<u8>> {
            let mut vec = Vec::new();
            if let Some(mut io) = io {
                io.read_to_end(&mut vec).await?;
            }
            Ok(vec)
        }

        let stdout_fut = read_to_end(self.stdout.take());
        let stderr_fut = read_to_end(self.stderr.take());

        let (status, stdout, stderr) = try_join3(self.wait(), stdout_fut, stderr_fut).await?;

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    /// Sends a signal to the child. If the child has already been waited on,
    /// this does nothing and returns success.
    pub fn signal(&self, sig: Signal) -> io::Result<()> {
        if self.exit_status.is_none() {
            Errno::result(unsafe { libc::kill(self.pid.as_raw(), sig as i32) })?;
        }

        Ok(())
    }
}

impl Command {
    /// Executes the command, waiting for it to finish and collecting its exit
    /// status.
    pub async fn status(&mut self) -> io::Result<ExitStatus> {
        let mut child = self.spawn()?;

        // Ensure we close any stdio handles so we can't deadlock waiting on the
        // child which may be waiting to read/write to a pipe we're holding.
        drop(child.stdin.take());
        drop(child.stdout.take());
        drop(child.stderr.take());

        child.wait().await
    }

    /// Executes the command, waiting for it to finish while collecting its
    /// stdout and stderr into buffers.
    pub async fn output(&mut self) -> io::Result<Output> {
        self.stdout(Stdio::piped());
        self.stderr(Stdio::piped());

        let child = self.spawn();

        child?.wait_with_output().await
    }
}

struct WaitForChild<'a> {
    /// Signal future. Used to get notified asynchronously of a child exiting.
    signal: tokio::signal::unix::Signal,
    child: &'a mut Child,
}

impl<'a> WaitForChild<'a> {
    fn new(child: &'a mut Child) -> io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};

        Ok(Self {
            signal: signal(SignalKind::child())?,
            child,
        })
    }
}

impl<'a> Future for WaitForChild<'a> {
    type Output = io::Result<ExitStatus>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            // Register an interest in SIGCHLD signals. We can't just call
            // `try_wait` right away. We might miss a signal event if the child
            // hasn't exited yet. Thus, we poll the signal stream to tell Tokio
            // we're interested in signal events.
            let sig = self.signal.poll_recv(cx);

            if let Some(status) = self.child.try_wait()? {
                return Poll::Ready(Ok(status));
            }

            if sig.is_pending() {
                return Poll::Pending;
            }
        }
    }
}
