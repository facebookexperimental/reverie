/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Protects a set of file descriptors from getting closed.

use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering::AcqRel;
use std::sync::atomic::Ordering::Acquire;

use parking_lot::Mutex;
use syscalls::Sysno;
use syscalls::SysnoSet;

struct ProtectedFiles {
    // We have to use Vec here to ensure `new` can be a const fn, which is
    // required for global static variables. This should be fine, since we don't
    // expect to be protecting more than a handful of file descriptors.
    files: Vec<RawFd>,
}

impl ProtectedFiles {
    pub const fn new() -> Self {
        Self { files: Vec::new() }
    }

    pub fn contains<Fd: AsRawFd>(&self, fd: &Fd) -> bool {
        self.files.contains(&fd.as_raw_fd())
    }

    pub fn insert<Fd: AsRawFd>(&mut self, fd: &Fd) -> bool {
        if self.contains(fd) {
            true
        } else {
            self.files.push(fd.as_raw_fd());
            false
        }
    }

    pub fn remove<Fd: AsRawFd>(&mut self, fd: &Fd) -> bool {
        let fd = fd.as_raw_fd();
        if let Some(index) = self.files.iter().position(|item| item == &fd) {
            self.files.swap_remove(index);
            true
        } else {
            false
        }
    }
}
struct RegistryValue {
    pid: libc::pid_t,
    files: Mutex<ProtectedFiles>,
}

struct ProcessRegistry {
    current: AtomicPtr<RegistryValue>,
}

impl ProcessRegistry {
    const fn new() -> Self {
        Self {
            current: AtomicPtr::new(ptr::null_mut()),
        }
    }

    fn get(&'static self) -> &'static Mutex<ProtectedFiles> {
        let pid = unsafe { libc::getpid() };
        loop {
            let current = self.current.load(Acquire);
            if !current.is_null() && unsafe { (*current).pid == pid } {
                return unsafe { &(*current).files };
            }

            let candidate = Box::into_raw(Box::new(RegistryValue {
                pid,
                files: Mutex::new(ProtectedFiles::new()),
            }));
            match self
                .current
                .compare_exchange(current, candidate, AcqRel, Acquire)
            {
                Ok(_) => return unsafe { &(*candidate).files },
                Err(actual) => {
                    unsafe { drop(Box::from_raw(candidate)) };
                    if !actual.is_null() && unsafe { (*actual).pid == pid } {
                        return unsafe { &(*actual).files };
                    }
                }
            }
        }
    }
}

static PROTECTED_FILES: ProcessRegistry = ProcessRegistry::new();

fn protected_files() -> &'static Mutex<ProtectedFiles> {
    PROTECTED_FILES.get()
}

/// A file descriptor that is internal to the plugin and not visible to the
/// client. These file descriptors cannot be closed by the client.
pub struct ProtectedFd<T: AsRawFd>(T);

impl<T: AsRawFd> Drop for ProtectedFd<T> {
    fn drop(&mut self) {
        protected_files().lock().remove(&self.0);
    }
}

impl<T: AsRawFd> AsRef<T> for ProtectedFd<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: AsRawFd> AsMut<T> for ProtectedFd<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Takes a closure `f` that creates and returns a file descriptor. The file
/// descriptor that is returned is protected from getting closed. This is safe
/// even if another thread is trying to close this same file descriptor.
pub fn protect_with<F, T, E>(f: F) -> Result<ProtectedFd<T>, E>
where
    F: FnOnce() -> Result<T, E>,
    T: AsRawFd,
{
    let mut protected_files = protected_files().lock();

    f().map(|fd| {
        protected_files.insert(&fd);
        ProtectedFd(fd)
    })
}

/// Returns true if a file descriptor is protected and shouldn't be closed.
pub fn is_protected<Fd: AsRawFd>(fd: &Fd) -> bool {
    protected_files().lock().contains(fd)
}

/// All of these syscalls take the input file descriptor as the first argument.
/// Some syscalls, like mmap, don't conform to this pattern and need to be
/// handled in a special way.
static FD_ARG0_SYSCALLS: SysnoSet = SysnoSet::new(&[
    Sysno::close,
    Sysno::dup,
    Sysno::dup2,
    Sysno::openat,
    Sysno::fstat,
    Sysno::read,
    Sysno::write,
    Sysno::lseek,
    Sysno::ioctl,
    Sysno::pread64,
    Sysno::pwrite64,
    Sysno::readv,
    Sysno::writev,
    Sysno::connect,
    Sysno::accept,
    Sysno::sendto,
    Sysno::recvfrom,
    Sysno::sendmsg,
    Sysno::recvmsg,
    Sysno::shutdown,
    Sysno::bind,
    Sysno::listen,
    Sysno::getsockname,
    Sysno::getpeername,
    Sysno::getsockopt,
    Sysno::fcntl,
    Sysno::flock,
    Sysno::fsync,
    Sysno::fdatasync,
    Sysno::ftruncate,
    Sysno::getdents,
    Sysno::getdents64,
    Sysno::fchdir,
    Sysno::fchmod,
    Sysno::fchown,
    Sysno::fstatfs,
    Sysno::readahead,
    Sysno::fsetxattr,
    Sysno::fgetxattr,
    Sysno::flistxattr,
    Sysno::fremovexattr,
    Sysno::fadvise64,
    Sysno::epoll_wait,
    Sysno::epoll_ctl,
    Sysno::inotify_add_watch,
    Sysno::inotify_rm_watch,
    Sysno::mkdirat,
    Sysno::mknodat,
    Sysno::fchownat,
    Sysno::futimesat,
    Sysno::newfstatat,
    Sysno::unlinkat,
    Sysno::renameat,
    Sysno::linkat,
    Sysno::readlinkat,
    Sysno::fchmodat,
    Sysno::faccessat,
    Sysno::sync_file_range,
    Sysno::vmsplice,
    Sysno::utimensat,
    Sysno::epoll_pwait,
    Sysno::signalfd,
    Sysno::fallocate,
    Sysno::timerfd_settime,
    Sysno::timerfd_gettime,
    Sysno::accept4,
    Sysno::signalfd4,
    Sysno::dup3,
    Sysno::preadv,
    Sysno::pwritev,
    Sysno::recvmmsg,
    Sysno::fanotify_mark,
    Sysno::name_to_handle_at,
    Sysno::open_by_handle_at,
    Sysno::syncfs,
    Sysno::sendmmsg,
    Sysno::setns,
    Sysno::finit_module,
    Sysno::renameat2,
    Sysno::kexec_file_load,
    Sysno::execveat,
    Sysno::preadv2,
    Sysno::pwritev2,
    Sysno::statx,
    Sysno::pidfd_send_signal,
    Sysno::io_uring_enter,
    Sysno::io_uring_register,
    Sysno::open_tree,
    Sysno::move_mount,
    Sysno::fsconfig,
    Sysno::fsmount,
    Sysno::fspick,
    Sysno::openat2,
    Sysno::pidfd_getfd,
]);

static FD_ARG1_SYSCALLS: SysnoSet = SysnoSet::new(&[Sysno::dup2, Sysno::dup3]);

/// Returns true if the given syscall operates on a protected file descriptor.
pub fn uses_protected_fd(sysno: Sysno, arg0: usize, arg1: usize) -> bool {
    (FD_ARG0_SYSCALLS.contains(sysno) && is_protected(&(arg0 as i32)))
        || (FD_ARG1_SYSCALLS.contains(sysno) && is_protected(&(arg1 as i32)))
}
#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn fork_child_does_not_reuse_locked_registry() {
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let locker = std::thread::spawn(move || {
            let _guard = protected_files().lock();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        locked_rx.recv().unwrap();

        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::alarm(5) };
            let _ = is_protected(&(-1_i32));
            unsafe { libc::_exit(0) };
        }

        release_tx.send(()).unwrap();
        locker.join().unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
    }
}
