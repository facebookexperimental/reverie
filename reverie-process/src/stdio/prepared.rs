/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

use syscalls::Errno;
use syscalls::Sysno;

use super::Stdio;
use crate::fd::Fd;

/// Parent endpoints of prepared standard streams, without wait authority or
/// async-runtime registration.
#[derive(Debug, Default)]
pub struct ParentStdio {
    /// Writes to the child's standard input, when configured as a pipe.
    pub stdin: Option<OwnedFd>,
    /// Reads the child's standard output, when configured as a pipe.
    pub stdout: Option<OwnedFd>,
    /// Reads the child's standard error, when configured as a pipe.
    pub stderr: Option<OwnedFd>,
}

/// Owned standard stream descriptors prepared before a fork.
///
/// Every materialized descriptor is above 2 and has `FD_CLOEXEC`. Fresh pipe
/// endpoints are blocking. Supplied files retain their open-file-description
/// flags and offset, including an intentional `O_NONBLOCK` flag. This type
/// neither creates a process nor applies PTY, container, or `pre_exec` setup.
#[derive(Debug)]
pub struct PreparedStdio {
    child: [Option<OwnedFd>; 3],
    parent: ParentStdio,
}

fn normalize(fd: Fd) -> io::Result<OwnedFd> {
    // Always duplicate, even when the materialized fd is already above 2.
    // F_DUPFD_CLOEXEC changes descriptor flags, never shared OFD flags.
    // SAFETY: fd is live and owned; this fcntl operation takes only an integer.
    let raw = Errno::result(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) })?;
    // SAFETY: fcntl returned a new, uniquely owned descriptor.
    let normalized = unsafe { OwnedFd::from_raw_fd(raw) };
    drop(fd);
    Ok(normalized)
}

fn prepare(config: Stdio, readable: bool) -> io::Result<(Option<OwnedFd>, Option<OwnedFd>)> {
    let (parent, child) = config.into_pipes(readable)?;
    let parent = parent.map(normalize).transpose()?;
    let child = child.map(normalize).transpose()?;
    Ok((parent, child))
}

fn take_raw(fd: &mut Option<OwnedFd>) -> RawFd {
    fd.take().map_or(-1, IntoRawFd::into_raw_fd)
}

impl PreparedStdio {
    /// Materializes all three configurations using the common [`Stdio`]
    /// policy, consuming them even when an operation fails.
    ///
    /// Inherited streams have no owned descriptor. All other child sources and
    /// parent pipe endpoints are duplicated above 2 with `FD_CLOEXEC`, then
    /// their original materialized descriptors are closed. No shared status
    /// flags are changed and no async registration occurs.
    pub fn new(stdin: Stdio, stdout: Stdio, stderr: Stdio) -> io::Result<Self> {
        let (parent_stdin, child_stdin) = prepare(stdin, true)?;
        let (parent_stdout, child_stdout) = prepare(stdout, false)?;
        let (parent_stderr, child_stderr) = prepare(stderr, false)?;
        Ok(Self {
            child: [child_stdin, child_stdout, child_stderr],
            parent: ParentStdio {
                stdin: parent_stdin,
                stdout: parent_stdout,
                stderr: parent_stderr,
            },
        })
    }

    /// Installs configured child sources on 0/1/2 with `FD_CLOEXEC` cleared,
    /// then closes every source and opposite pipe endpoint in this fork copy.
    /// Inherited streams are left untouched. Only fixed raw `dup3` and `close`
    /// operations are performed; no allocation, TLS, locks, or Rust teardown
    /// is required.
    ///
    /// # Safety
    ///
    /// Call exactly once in a new fork child with a separate file table (never
    /// `CLONE_FILES`), before this copy calls `finish_parent`. The descriptors
    /// must still be owned by this plan and must not have been closed or
    /// replaced by other code. Run the common child hook first, including PTY
    /// setup, so explicit streams override it. Never call on the parent's live
    /// plan. After success the child must exec or terminate without Rust
    /// teardown; on any error it must terminate immediately without teardown.
    /// There is deliberately no recovery from a partially installed plan.
    pub unsafe fn install_child(&mut self) -> Result<(), Errno> {
        // Disarm every Rust owner before the first syscall. All sources are
        // distinct and above 2, so none can be clobbered by an earlier dup3.
        let [stdin, stdout, stderr] = &mut self.child;
        let sources = [take_raw(stdin), take_raw(stdout), take_raw(stderr)];
        let parents = [
            take_raw(&mut self.parent.stdin),
            take_raw(&mut self.parent.stdout),
            take_raw(&mut self.parent.stderr),
        ];
        for (target, source) in sources.into_iter().enumerate() {
            if source >= 0 {
                // SAFETY: required separate fork file table and live sources.
                unsafe { syscalls::syscall3(Sysno::dup3, source as usize, target, 0) }?;
            }
        }
        for fd in sources.into_iter().chain(parents) {
            if fd >= 0 {
                // SAFETY: each descriptor is uniquely owned in this fork copy.
                unsafe { syscalls::syscall1(Sysno::close, fd as usize) }?;
            }
        }
        Ok(())
    }

    /// Immediately closes all child source copies in the parent and transfers
    /// its pipe endpoints to the caller. Call immediately after a successful
    /// fork, before any fallible parent registration, to avoid hidden writers
    /// preventing EOF. Subsequent calls return three empty fields.
    ///
    /// This performs no async registration. The caller owns any later fallible
    /// conversion and must retain these endpoints across launch failures.
    pub fn finish_parent(&mut self) -> ParentStdio {
        self.child = [None, None, None];
        std::mem::take(&mut self.parent)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    use super::*;

    fn flags(fd: &OwnedFd) -> libc::c_int {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        flags
    }

    fn check_descriptor(fd: &OwnedFd, access: libc::c_int) {
        assert!(fd.as_raw_fd() > 2);
        assert_eq!(flags(fd) & libc::O_ACCMODE, access);
        assert_eq!(flags(fd) & libc::O_NONBLOCK, 0);
        let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(descriptor_flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    fn transfer(writer: &OwnedFd, reader: &OwnedFd, bytes: &[u8]) {
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) },
            bytes.len() as isize,
        );
        let mut event = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut event, 1, 1000) }, 1);
        let mut actual = [0; 32];
        assert_eq!(
            unsafe { libc::read(reader.as_raw_fd(), actual.as_mut_ptr().cast(), actual.len()) },
            bytes.len() as isize,
        );
        assert_eq!(&actual[..bytes.len()], bytes);
    }

    #[test]
    fn pipes_have_distinct_cloexec_blocking_endpoints_and_correct_orientation() {
        let plan = PreparedStdio::new(Stdio::piped(), Stdio::piped(), Stdio::piped()).unwrap();
        let stdin = plan.child[0].as_ref().unwrap();
        let stdout = plan.child[1].as_ref().unwrap();
        let stderr = plan.child[2].as_ref().unwrap();
        let parent_stdin = plan.parent.stdin.as_ref().unwrap();
        let parent_stdout = plan.parent.stdout.as_ref().unwrap();
        let parent_stderr = plan.parent.stderr.as_ref().unwrap();
        for fd in [stdin, parent_stdout, parent_stderr] {
            check_descriptor(fd, libc::O_RDONLY);
        }
        for fd in [stdout, stderr, parent_stdin] {
            check_descriptor(fd, libc::O_WRONLY);
        }
        let mut fds = [
            stdin,
            stdout,
            stderr,
            parent_stdin,
            parent_stdout,
            parent_stderr,
        ]
        .map(AsRawFd::as_raw_fd);
        fds.sort_unstable();
        assert!(fds.windows(2).all(|pair| pair[0] != pair[1]));
        transfer(parent_stdin, stdin, b"input");
        transfer(stdout, parent_stdout, b"output");
        transfer(stderr, parent_stderr, b"error");
    }

    #[test]
    fn staging_descriptors_are_cloexec_before_normalization() {
        let file = tempfile::tempfile().unwrap();
        assert_ne!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let cases = [
            ("read-null", Stdio::null(), true),
            ("write-null", Stdio::null(), false),
            ("supplied-file", Stdio::from(file), false),
            ("stdin-pipe", Stdio::piped(), true),
            ("output-pipe", Stdio::piped(), false),
        ];
        let mut exposed = Vec::new();
        for (name, config, readable) in cases {
            // Inspect the exact intermediate descriptors, before a later dup
            // can hide a window in which a concurrent exec inherits a writer.
            let (parent, child) = config.into_pipes(readable).unwrap();
            for endpoint in [parent, child].into_iter().flatten() {
                let flags = unsafe { libc::fcntl(endpoint.as_raw_fd(), libc::F_GETFD) };
                assert!(flags >= 0);
                if flags & libc::FD_CLOEXEC == 0 {
                    exposed.push(name);
                }
            }
        }
        assert!(
            exposed.is_empty(),
            "staging descriptors exposed: {exposed:?}"
        );
    }

    #[test]
    fn finish_parent_releases_writers_and_transfers_endpoints_once() {
        let mut plan =
            PreparedStdio::new(Stdio::inherit(), Stdio::piped(), Stdio::inherit()).unwrap();
        let parent = plan.finish_parent();
        let reader = parent.stdout.as_ref().unwrap();
        let mut event = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut event, 1, 1000) }, 1);
        assert_ne!(event.revents & libc::POLLHUP, 0);
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0
        );
        let again = plan.finish_parent();
        assert!(again.stdin.is_none() && again.stdout.is_none() && again.stderr.is_none());
        assert!(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) } >= 0);
        // The plan is deliberately retained through the EOF and repeat checks.
        drop(plan);
    }

    #[test]
    fn supplied_file_preserves_shared_flags_and_offset() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"abc").unwrap();
        file.seek(SeekFrom::Start(1)).unwrap();
        let mut observer = file.try_clone().unwrap();
        let original = file.as_raw_fd();
        let original_flags = unsafe { libc::fcntl(original, libc::F_GETFL) };
        let wanted = original_flags | libc::O_APPEND | libc::O_NONBLOCK;
        assert_eq!(unsafe { libc::fcntl(original, libc::F_SETFL, wanted) }, 0);
        let plan =
            PreparedStdio::new(Stdio::inherit(), Stdio::from(file), Stdio::inherit()).unwrap();
        let source = plan.child[1].as_ref().unwrap();
        assert!(source.as_raw_fd() > 2);
        assert_eq!(flags(source), wanted);
        assert_eq!(
            unsafe { libc::fcntl(observer.as_raw_fd(), libc::F_GETFL) },
            wanted
        );
        assert_eq!(observer.stream_position().unwrap(), 1);
        assert_eq!(unsafe { libc::fcntl(original, libc::F_GETFD) }, -1);
        assert_eq!(
            unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
        );
        assert_eq!(
            unsafe { libc::write(source.as_raw_fd(), b"d".as_ptr().cast(), 1) },
            1
        );
        assert_eq!(observer.stream_position().unwrap(), 4);
        observer.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        observer.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcd");
        assert_eq!(flags(source), wanted);
    }

    #[test]
    fn mixed_streams_and_command_consumption_preserve_inherit() {
        let mut command = crate::Command::new("unused");
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let plan = command.take_prepared_stdio().unwrap();
        assert!(plan.child[0].is_none());
        assert!(plan.parent.stdin.is_none() && plan.parent.stdout.is_none());
        check_descriptor(plan.child[1].as_ref().unwrap(), libc::O_WRONLY);
        check_descriptor(plan.child[2].as_ref().unwrap(), libc::O_WRONLY);
        check_descriptor(plan.parent.stderr.as_ref().unwrap(), libc::O_RDONLY);
        let second = command.take_prepared_stdio().unwrap();
        assert!(second.child.iter().all(Option::is_none));
        assert!(second.parent.stdin.is_none());
        assert!(second.parent.stdout.is_none());
        assert!(second.parent.stderr.is_none());
    }

    struct RestoreStdio([Option<(OwnedFd, libc::c_int)>; 3]);

    impl Drop for RestoreStdio {
        fn drop(&mut self) {
            for (target, saved) in self.0.iter().enumerate() {
                if let Some((fd, flags)) = saved {
                    unsafe {
                        libc::dup2(fd.as_raw_fd(), target as libc::c_int);
                        libc::fcntl(target as libc::c_int, libc::F_SETFD, *flags);
                    }
                }
            }
        }
    }

    #[test]
    fn normalization_works_with_all_standard_descriptors_closed() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let saved = std::array::from_fn(|fd| {
            let flags = unsafe { libc::fcntl(fd as libc::c_int, libc::F_GETFD) };
            if flags < 0 {
                None
            } else {
                let duplicate = unsafe { libc::fcntl(fd as libc::c_int, libc::F_DUPFD_CLOEXEC, 3) };
                assert!(duplicate >= 3);
                Some((unsafe { OwnedFd::from_raw_fd(duplicate) }, flags))
            }
        });
        let restore = RestoreStdio(saved);
        for fd in 0..3 {
            unsafe { libc::close(fd) };
        }
        let result = PreparedStdio::new(Stdio::piped(), Stdio::piped(), Stdio::piped());
        drop(restore);
        let plan = result.unwrap();
        for fd in plan.child.iter().flatten() {
            assert!(fd.as_raw_fd() > 2);
            assert_eq!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC
            );
        }
        check_descriptor(plan.parent.stdin.as_ref().unwrap(), libc::O_WRONLY);
        check_descriptor(plan.parent.stdout.as_ref().unwrap(), libc::O_RDONLY);
        check_descriptor(plan.parent.stderr.as_ref().unwrap(), libc::O_RDONLY);
        transfer(
            plan.parent.stdin.as_ref().unwrap(),
            plan.child[0].as_ref().unwrap(),
            b"input",
        );
    }

    #[test]
    fn partial_materialization_failure_closes_every_new_descriptor() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let max_fd = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse::<RawFd>()
                    .unwrap()
            })
            .max()
            .unwrap();
        // Fill lower-numbered holes so exactly six slots can be made available.
        let mut fillers = Vec::new();
        let last = loop {
            let file = File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();
            fillers.push(file);
            if fd >= max_fd {
                break fd;
            }
        };
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut old) }, 0);
        let limited = libc::rlimit {
            rlim_cur: (last + 7) as libc::rlim_t,
            rlim_max: old.rlim_max,
        };
        assert!(limited.rlim_cur <= old.rlim_cur);
        let count = || {
            (0..last + 7)
                .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
                .count()
        };
        let before = count();
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        // Two pairs fit; the third pair cannot be normalized without a seventh
        // slot. No assertion or allocation is needed before restoring the limit.
        let result = PreparedStdio::new(Stdio::piped(), Stdio::piped(), Stdio::piped());
        let restored = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &old) };
        assert_eq!(restored, 0);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EMFILE));
        assert_eq!(count(), before);
        drop(fillers);
    }
}
