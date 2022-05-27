/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use super::clone::clone;
use super::error::{Context, Error};
use super::fd::{pipe, Fd};
use super::id_map::make_id_map;
use super::seccomp::SeccompNotif;
use super::stdio::{ChildStderr, ChildStdin, ChildStdout};
use super::util::CStringArray;
use super::util::SharedValue;
use super::Child;
use super::Command;

use super::container::ChildContext;

use std::io;
use std::io::Write;

impl Command {
    /// Executes the command as a child process, returning a handle to it.
    ///
    /// By default, stdin, stdout and stderr are inherited from the parent.
    pub fn spawn(&mut self) -> Result<Child, Error> {
        // Create a pipe to send back errors to the parent process if `execve`
        // fails.
        let (reader, mut writer) = pipe()?;

        let child = self.spawn_with(|err| {
            send_error(&mut writer, err);
            1
        })?;

        // Close the writer end. Otherwise, the following read will hang
        // forever.
        drop(writer);

        recv_error(reader)?;

        Ok(child)
    }

    /// Spawn the child with helper functions. The `onfail` callback runs in the
    /// child process if an error occurs during execution of the process. The
    /// `wait` function can be used to wait for the child to fully start up and
    /// to transform it into another type.
    pub fn spawn_with<F>(&mut self, mut onfail: F) -> Result<Child, Error>
    where
        F: FnMut(Error) -> i32,
    {
        let env = self.container.env.array();

        // Set up IO pipes
        let (stdin, child_stdin) = self.container.stdin.pipes(true)?;
        let (stdout, child_stdout) = self.container.stdout.pipes(false)?;
        let (stderr, child_stderr) = self.container.stdout.pipes(false)?;

        let clone_flags = self.container.namespace.bits() | libc::SIGCHLD;

        let uid_map = &make_id_map(&self.container.uid_map);
        let gid_map = &make_id_map(&self.container.gid_map);

        let seccomp_fd = if self.container.seccomp_notify {
            Some(SharedValue::new(core::sync::atomic::AtomicI32::new(0))?)
        } else {
            None
        };

        let context = ChildContext {
            stdin: child_stdin.as_ref(),
            stdout: child_stdout.as_ref(),
            stderr: child_stderr.as_ref(),
            uid_map,
            gid_map,
            seccomp_fd: seccomp_fd.as_ref().map(|x| x.as_ref()),
        };

        let pid = clone(
            || {
                let code = onfail(self.do_exec(&context, &env).unwrap_err());
                unsafe { libc::_exit(code) }
            },
            clone_flags,
        )?;

        drop(child_stdin);
        drop(child_stdout);
        drop(child_stderr);
        drop(self.container.pty.take());

        let seccomp_notif = match seccomp_fd {
            Some(shared_fd) => {
                use core::sync::atomic::Ordering;

                // Spin until the value changes in the child.
                let mut targetfd = 0;
                while targetfd == 0 {
                    targetfd = shared_fd.as_ref().load(Ordering::Relaxed);
                    std::thread::yield_now();
                }

                // Use pidfd_getfd to copy the file descriptor
                let pidfd = Fd::pidfd_open(pid.into(), 0)?;
                let fd = pidfd.pidfd_getfd(targetfd, 0)?;

                // We've successfully duplicated the file descriptor. Let the
                // child continue on to execve.
                shared_fd.as_ref().store(0, Ordering::Relaxed);

                Some(SeccompNotif::new(fd)?)
            }
            None => None,
        };

        let stdin = stdin.map(ChildStdin::new).transpose()?;
        let stdout = stdout.map(ChildStdout::new).transpose()?;
        let stderr = stderr.map(ChildStderr::new).transpose()?;

        Ok(Child {
            pid,
            exit_status: None,
            seccomp_notif,
            stdin,
            stdout,
            stderr,
        })
    }

    /// Note: This function MUST NOT allocate or deallocate any memory. Doing so
    /// can cause deadlocks.
    fn do_exec(&mut self, context: &ChildContext, env: &CStringArray) -> Result<!, Error> {
        self.container.setup(context, &mut self.pre_exec)?;

        let err = Error::result(
            unsafe { libc::execvpe(self.program.as_ptr(), self.args.as_ptr(), env.as_ptr()) },
            Context::Exec,
        )
        .unwrap_err();

        Err(err)
    }
}

/// Sends an error and closes the pipe. Ignore any errors if this fails.
pub fn send_error(fd: &mut Fd, err: Error) {
    // Writes up to PIPE_BUF (4096) should be atomic. There's also nothing we
    // can do with an error if this fails.
    let bytes: [u8; 8] = err.into();
    let _ = fd.write(&bytes);
}

/// Tries to receive an error code from the pipe. If the other end of the
/// pipe is closed before sending an error, then `Ok(())` is returned.
pub fn recv_error(mut fd: Fd) -> Result<(), Error> {
    use std::io::Read;
    let mut err = [0u8; 8];
    loop {
        match fd.read(&mut err) {
            Ok(0) => return Ok(()),
            Ok(8) => return Err(Error::from(err)),
            Ok(n) => {
                // Sends up to PIPE_BUF (4096) should be atomic.
                panic!("execve pipe: got unexpected number of bytes {}", n);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => {
                panic!("execve pipe: read returned unexpected error {}", err);
            }
        }
    }
}
