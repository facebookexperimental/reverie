/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! [`reverie::Guest::link_path`] of a traced thread: the kernel's own
//! `readlink(2)` of the `fd/<fd>`, `exe` or `cwd` link of the thread `tid`
//! names, which the tracer reads while the asking thread is stopped in the
//! tool's callback.
//!
//! A traced guest thread is a host task, and the tracer shares the guest's
//! `/proc` view, so the text is the kernel's own for that thread, every byte
//! of it, rendered by `d_path` from the tracer's root, which is the guest's
//! unless a guest thread changed its own root. As for
//! [`reverie::Guest::signal_sets`] (see `crate::signal_sets`), the fact
//! answers for a thread this session traces, in whichever of its processes,
//! and reads no other task's link: it never names `/proc/<tid>` by number,
//! but reads the link with `readlinkat` in the `/proc/<tid>` directory the
//! session retained for the task when it began tracing it
//! (`FatalSession::traced_directories`). That directory names the task it
//! was opened for until the task is reaped, and no task after.
//!
//! The link is read first, then the task's `status` through the same
//! directory, which must show a tracer that is a thread of this process and
//! a task that has not exited (a `State:` other than `Z` or `X`). A task the
//! status shows live was live when its link was read before it, so a link
//! is reported only for a live task; one that exited in between is `ESRCH`,
//! like any exited thread.

use std::ffi::CStr;
use std::ffi::CString;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

use reverie::Errno;
use reverie::FactError;
use reverie::LinkPath;
use reverie::PathLink;
use reverie::Pid;

use crate::signal_sets::NO_THREAD;
use crate::signal_sets::STATUS_LIMIT;
use crate::signal_sets::open_status;
use crate::signal_sets::parse;
use crate::signal_sets::read_bounded;
use crate::signal_sets::read_errno;

/// The buffer `readlinkat` fills: `PATH_MAX` bytes, one more than the
/// longest text Linux's `do_proc_readlink` returns, so a text that fills it
/// is not Linux's ([`LinkPath::from_readlink`] refuses it).
const LINK_BUFFER: usize = libc::PATH_MAX as usize;

/// Reads link `link` of thread `tid` through `directories`, which gives the
/// retained `/proc/<tid>` directories of the tasks the session traces as
/// `tid` (`FatalSession::traced_directories`): none for a number it does not
/// trace. At most one of them names a live task, the one that holds the
/// number now; a directory whose task has been reaped reads as no task, and
/// the next is tried.
pub(crate) fn read<D: AsFd>(
    tid: Pid,
    link: PathLink,
    directories: impl FnOnce(Pid) -> Vec<D>,
) -> Result<LinkPath, FactError> {
    // Linux numbers no task zero or below.
    if tid.as_raw() <= 0 {
        return Err(NO_THREAD);
    }
    let name = link_name(link)?;
    for directory in directories(tid) {
        let (text, status) = {
            // The guard ends before anything else runs.
            let _open = crate::launch_window::TransientOpen::begin();
            let text = read_link_at(directory.as_fd(), &name);
            let status =
                open_status(directory.as_fd()).and_then(|file| read_bounded(file, STATUS_LIMIT));
            (text, status)
        };
        match status {
            Ok(Some(status)) => {
                let status = parse(&status)?;
                let tracer = Pid::from_raw(i32::try_from(status.tracer).unwrap_or(0));
                if status.exited() || !crate::tracer::tracer_is_current(tracer) {
                    continue;
                }
            }
            Ok(None) => return Err(FactError::NotProvided),
            Err(error) => match read_errno(&error) {
                Errno::ESRCH => continue,
                errno => return Err(FactError::Errno(errno)),
            },
        }
        return match text {
            Ok(text) => LinkPath::from_readlink(&text),
            Err(error) => Err(FactError::Errno(link_errno(link, &error))),
        };
    }
    Err(NO_THREAD)
}

/// The name of `link` in a task's `/proc/<tid>` directory. A descriptor
/// below zero gives a name that `fd/` has no entry for, as no descriptor the
/// task does not hold has one.
fn link_name(link: PathLink) -> Result<CString, FactError> {
    let name = match link {
        PathLink::Descriptor(fd) => format!("fd/{fd}"),
        PathLink::Executable => "exe".to_owned(),
        PathLink::WorkingDirectory => "cwd".to_owned(),
        _ => return Err(FactError::NotProvided),
    };
    Ok(CString::new(name).expect("a link name has no NUL byte"))
}

/// `readlinkat` of `name` in the task directory `directory`: the link of the
/// task the directory was opened for, whatever task holds its number now.
/// `ENOENT` once that task has been reaped.
fn read_link_at(directory: BorrowedFd<'_>, name: &CStr) -> std::io::Result<Vec<u8>> {
    let mut text = vec![0u8; LINK_BUFFER];
    // SAFETY: the directory descriptor is open for the call, the name is a
    // NUL-terminated string, and text is writable for its length.
    let count = unsafe {
        libc::readlinkat(
            directory.as_raw_fd(),
            name.as_ptr(),
            text.as_mut_ptr().cast(),
            text.len(),
        )
    };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    text.truncate(count as usize);
    Ok(text)
}

/// What a failed read of a live task's link means. Linux's lookup of
/// `fd/<fd>` answers `ENOENT` for a descriptor the task's table does not hold,
/// and for a name that is not a descriptor's number, such as a negative one
/// (`proc_lookupfd_common` in `fs/proc/fd.c`): `EBADF` here. For `exe` and
/// `cwd`, and any other error, the kernel's answer to the tracer's read is
/// passed on: a task that has begun to exit and has no address space or
/// working directory left gives `ENOENT`, and one whose links Linux does not
/// let the tracer read gives `EACCES`.
fn link_errno(link: PathLink, error: &std::io::Error) -> Errno {
    match (link, error.raw_os_error()) {
        (PathLink::Descriptor(_), Some(libc::ENOENT)) => Errno::EBADF,
        (_, Some(errno)) => Errno::new(errno),
        (_, None) => Errno::EIO,
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    fn this_thread() -> Pid {
        // SAFETY: gettid takes no arguments and cannot fail.
        Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32)
    }

    /// `/proc/<tid>`, opened as the session retains a task's directory.
    fn task_directory(tid: i32) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(format!("/proc/{tid}"))
            .unwrap()
    }

    const ALL: [PathLink; 4] = [
        PathLink::Descriptor(0),
        PathLink::Descriptor(-1),
        PathLink::Executable,
        PathLink::WorkingDirectory,
    ];

    /// The session decides first: a number it gives no directory for is
    /// ESRCH, even where a task holds the number. Zero and below are ESRCH
    /// before the session is asked.
    #[test]
    fn a_number_the_session_does_not_trace_is_esrch() {
        let asked = std::cell::Cell::new(0);
        let untraced = |_| {
            asked.set(asked.get() + 1);
            Vec::<std::fs::File>::new()
        };
        for link in ALL {
            assert_eq!(read(this_thread(), link, untraced), Err(NO_THREAD));
            assert_eq!(read(Pid::from_raw(1), link, untraced), Err(NO_THREAD));
        }
        assert_eq!(asked.get(), 8);
        for tid in [0, -1, i32::MIN] {
            for link in ALL {
                assert_eq!(
                    read(Pid::from_raw(tid), link, untraced),
                    Err(NO_THREAD),
                    "{tid}"
                );
            }
        }
        assert_eq!(asked.get(), 8);
    }

    /// Where the session gives a directory, the task's status read through
    /// it must still show a tracer of this process: this test's own thread
    /// and init are traced by none of ours, so their links are not reported,
    /// though the kernel would let this process read this thread's.
    #[test]
    fn a_task_no_tracer_of_ours_traces_is_esrch() {
        for tid in [this_thread().as_raw(), 1] {
            for link in ALL {
                let directory = task_directory(tid);
                assert_eq!(
                    read(Pid::from_raw(tid), link, |_| vec![directory]),
                    Err(NO_THREAD),
                    "{tid} {link:?}"
                );
            }
        }
    }

    /// A child of this process that this thread traces, and its directory,
    /// opened while it is certainly traced here. It holds every descriptor
    /// this process held when it forked. Dropped unreaped, as when a test
    /// fails, it is killed and reaped.
    struct TracedChild {
        pid: libc::pid_t,
        directory: std::fs::File,
        reaped: bool,
    }

    impl TracedChild {
        fn new() -> Self {
            // SAFETY: the child makes only async-signal-safe calls before it ends.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "{}", std::io::Error::last_os_error());
            if pid == 0 {
                loop {
                    // SAFETY: pause takes no arguments.
                    unsafe { libc::pause() };
                }
            }
            // From here a failed check kills and reaps the child; its
            // directory is opened again once the child is traced, as the
            // session opens one.
            let mut child = Self {
                pid,
                directory: task_directory(pid),
                reaped: false,
            };
            // SAFETY: the child is this process's own; PTRACE_SEIZE leaves it running.
            let seized = unsafe {
                libc::ptrace(
                    libc::PTRACE_SEIZE,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    0 as libc::c_long,
                )
            };
            assert_eq!(seized, 0, "{}", std::io::Error::last_os_error());
            child.directory = task_directory(pid);
            child
        }

        /// The child's directory, as the session would give it.
        fn directory(&self) -> std::fs::File {
            self.directory.try_clone().unwrap()
        }

        fn read(&self, number: Pid, link: PathLink) -> Result<LinkPath, FactError> {
            read(number, link, |_| vec![self.directory()])
        }

        /// Kills the child and waits until it has exited, without reaping it:
        /// a zombie.
        fn kill(&self) {
            // SAFETY: the child is this process's own and not reaped.
            assert_eq!(unsafe { libc::kill(self.pid, libc::SIGKILL) }, 0);
            // SAFETY: siginfo_t is plain data; an all-zero value is valid.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: info is writable.
            let waited = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            assert_eq!(waited, 0);
        }

        /// Reaps the child, which has exited.
        fn reap(&mut self) {
            let mut status = 0;
            // SAFETY: status is writable.
            assert_eq!(unsafe { libc::waitpid(self.pid, &mut status, 0) }, self.pid);
            self.reaped = true;
        }
    }

    impl Drop for TracedChild {
        fn drop(&mut self) {
            if !self.reaped {
                // SAFETY: the child is this process's own and not reaped, so
                // its number is still its own.
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
                let mut status = 0;
                // SAFETY: status is writable.
                unsafe { libc::waitpid(self.pid, &mut status, 0) };
            }
        }
    }

    /// A pipe, as two owned descriptors, made before a child forks so that
    /// the child holds them too.
    fn pipe() -> [std::fs::File; 2] {
        let mut fds = [0; 2];
        // SAFETY: fds has room for two descriptors.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 returned two new descriptors that nothing else owns.
        fds.map(|fd| unsafe { std::fs::File::from_raw_fd(fd) })
    }

    fn inode(file: &std::fs::File) -> u64 {
        std::os::unix::fs::MetadataExt::ino(&file.metadata().unwrap())
    }

    /// A traced child's links are the kernel's texts, each of its kind: a
    /// file it holds, a pipe it holds, its image and its working directory,
    /// which it shares with this process; a descriptor it does not hold,
    /// above every open one or below zero, is EBADF. Once it has exited, a
    /// zombie, every link is ESRCH, and so once it is reaped.
    #[test]
    fn a_traced_childs_links_are_the_kernels_until_it_exits() {
        let directory =
            std::env::temp_dir().join(format!("reverie-ptrace-link-path-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("held");
        let file = std::fs::File::create(&path).unwrap();
        let [reader, _writer] = pipe();
        let mut child = TracedChild::new();
        let number = Pid::from_raw(child.pid);
        let canonical = std::fs::canonicalize(&path).unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        assert_eq!(
            child.read(number, PathLink::Descriptor(fd)),
            Ok(LinkPath::Path(canonical.as_os_str().as_bytes().to_vec()))
        );
        assert_eq!(
            child.read(number, PathLink::Descriptor(reader.as_raw_fd())),
            Ok(LinkPath::Anonymous(
                format!("pipe:[{}]", inode(&reader)).into_bytes()
            ))
        );
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(
            child.read(number, PathLink::Executable),
            Ok(LinkPath::Path(exe.as_os_str().as_bytes().to_vec()))
        );
        let cwd = std::fs::read_link("/proc/self/cwd").unwrap();
        assert_eq!(
            child.read(number, PathLink::WorkingDirectory),
            Ok(LinkPath::Path(cwd.as_os_str().as_bytes().to_vec()))
        );
        // A descriptor the child does not hold.
        for fd in [-1, i32::MIN, 1 << 20] {
            assert_eq!(
                child.read(number, PathLink::Descriptor(fd)),
                Err(FactError::Errno(Errno::EBADF)),
                "{fd}"
            );
        }
        // The file, unlinked: the kernel's text says so.
        std::fs::remove_file(&path).unwrap();
        let mut deleted = canonical.as_os_str().as_bytes().to_vec();
        deleted.extend_from_slice(b" (deleted)");
        assert_eq!(
            child.read(number, PathLink::Descriptor(fd)),
            Ok(LinkPath::Path(deleted))
        );
        child.kill();
        let text = std::fs::read_to_string(format!("/proc/{}/status", child.pid)).unwrap();
        assert!(text.contains("State:\tZ (zombie)\n"), "{text}");
        for link in ALL {
            assert_eq!(child.read(number, link), Err(NO_THREAD), "{link:?}");
        }
        child.reap();
        for link in ALL {
            assert_eq!(child.read(number, link), Err(NO_THREAD), "{link:?}");
        }
        std::fs::remove_dir(&directory).unwrap();
    }

    /// A number taken over, as near as a test comes without waiting for
    /// Linux to hand the same number out again: the directory of a task that
    /// has since been reaped, asked about under a number that a live task
    /// traced by this thread holds. The answer is the reaped task's, none
    /// (ESRCH), never the live task's, which a read of `/proc/<tid>` by
    /// number would give. Given the live task's own directory after the
    /// reaped one, the read passes the reaped one by and answers.
    ///
    /// The same holds between two live tasks: under the number of one, the
    /// directory of another reads the other's descriptor, a file that only
    /// the other holds, never the first one's table.
    #[test]
    fn a_directory_names_its_task_not_whoever_holds_the_number() {
        let mut gone = TracedChild::new();
        gone.kill();
        gone.reap();
        let live = TracedChild::new();
        let number = Pid::from_raw(live.pid);
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        for link in [
            PathLink::Executable,
            PathLink::WorkingDirectory,
            PathLink::Descriptor(0),
        ] {
            assert_eq!(
                read(number, link, |_| vec![gone.directory()]),
                Err(NO_THREAD),
                "{link:?}"
            );
        }
        assert_eq!(
            read(number, PathLink::Executable, |_| vec![
                gone.directory(),
                live.directory()
            ]),
            Ok(LinkPath::Path(exe.as_os_str().as_bytes().to_vec()))
        );
        // A file opened after `live` forked, so that only `holder` holds it.
        let directory = std::env::temp_dir().join(format!(
            "reverie-ptrace-link-path-holder-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("held");
        let file = std::fs::File::create(&path).unwrap();
        let canonical = std::fs::canonicalize(&path).unwrap();
        let holder = TracedChild::new();
        let fd = PathLink::Descriptor(file.as_raw_fd());
        assert_eq!(
            read(number, fd, |_| vec![holder.directory()]),
            Ok(LinkPath::Path(canonical.as_os_str().as_bytes().to_vec()))
        );
        assert_eq!(live.read(number, fd), Err(FactError::Errno(Errno::EBADF)));
        drop(file);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
