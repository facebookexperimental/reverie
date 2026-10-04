/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;
use std::io::Write;

use super::Child;
use super::Command;
use super::clone::clone;
use super::container::ChildContext;
use super::error::Context;
use super::error::Error;
use super::fd::Fd;
use super::fd::pipe;
use super::id_map::make_id_map;
use super::seccomp::SeccompNotif;
use super::stdio::ChildStderr;
use super::stdio::ChildStdin;
use super::stdio::ChildStdout;
use super::util::CStringArray;
use super::util::SharedValue;

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
                let code = onfail(self.do_exec(&context, &env));
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
    ///
    /// Only returns if an error occurs, thus it is only possible for it to
    /// return an error.
    fn do_exec(&mut self, context: &ChildContext, env: &CStringArray) -> Error {
        if let Err(err) = self.container.setup(context, &mut self.pre_exec) {
            return err;
        }

        Error::result(
            unsafe { execvpe_zeroed_tail(&self.program, self.args.as_ptr(), env.as_ptr()) },
            Context::Exec,
        )
        .unwrap_err()
    }
}

/// Issues `execve` with the three argument registers `execve` ignores
/// (arg3..arg5) set to zero.
///
/// `libc::execvpe` reaches the `execve` instruction with whatever the launcher
/// last left in those registers. The kernel ignores them and clears them in the
/// new image, but a ptrace tracer records all six argument registers at the
/// seccomp stop, so leftover launcher state would enter the recorded launch.
/// glibc's `syscall(3)` moves its fifth, sixth and seventh arguments into r10,
/// r8 and r9, so passing explicit zeros defines them.
///
/// Returns -1 with `errno` set, like `execve(2)`.
unsafe fn execve_zeroed_tail(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    let zero: libc::c_long = 0;
    unsafe { libc::syscall(libc::SYS_execve, path, argv, envp, zero, zero, zero) as libc::c_int }
}

/// Behaves like glibc `execvpe(3)`, but issues every `execve` through
/// [`execve_zeroed_tail`]. The `PATH` search and its error precedence follow
/// glibc: `EACCES` is remembered, and `ENOENT`, `ESTALE`, `ENOTDIR`, `ENODEV`
/// and `ETIMEDOUT` move on to the next entry. A candidate that fails with
/// `ENOEXEC` is handed to `libc::execvpe`, which runs it through `/bin/sh`.
///
/// MUST NOT allocate: this runs in the child between `clone` and `execve`.
unsafe fn execvpe_zeroed_tail(
    program: &std::ffi::CStr,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    const NAME_MAX: usize = libc::NAME_MAX as usize;
    const PATH_MAX: usize = libc::PATH_MAX as usize;
    let errno = || io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let set_errno = |value| unsafe { *libc::__errno_location() = value };

    let file = program.to_bytes();
    if file.is_empty() {
        set_errno(libc::ENOENT);
        return -1;
    }
    if file.contains(&b'/') {
        unsafe { execve_zeroed_tail(program.as_ptr(), argv, envp) };
        if errno() == libc::ENOEXEC {
            return unsafe { libc::execvpe(program.as_ptr(), argv, envp) };
        }
        return -1;
    }
    if file.len() > NAME_MAX {
        set_errno(libc::ENAMETOOLONG);
        return -1;
    }

    let path = unsafe { libc::getenv(c"PATH".as_ptr()) };
    let path = if path.is_null() {
        &b"/bin:/usr/bin"[..]
    } else {
        unsafe { std::ffi::CStr::from_ptr(path) }.to_bytes()
    };

    let mut buffer = [0u8; PATH_MAX + NAME_MAX + 2];
    let mut got_eacces = false;
    for dir in path.split(|byte| *byte == b':') {
        if dir.len() >= PATH_MAX {
            continue;
        }
        // An empty entry means the current directory, as in glibc.
        let mut len = dir.len();
        buffer[..len].copy_from_slice(dir);
        if !dir.is_empty() {
            buffer[len] = b'/';
            len += 1;
        }
        buffer[len..len + file.len()].copy_from_slice(file);
        buffer[len + file.len()] = 0;
        let candidate = buffer.as_ptr() as *const libc::c_char;

        unsafe { execve_zeroed_tail(candidate, argv, envp) };
        match errno() {
            libc::ENOEXEC => return unsafe { libc::execvpe(candidate, argv, envp) },
            libc::EACCES => got_eacces = true,
            libc::ENOENT | libc::ESTALE | libc::ENOTDIR | libc::ENODEV | libc::ETIMEDOUT => {}
            _ => return -1,
        }
    }
    if got_eacces {
        set_errno(libc::EACCES);
    }
    -1
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
