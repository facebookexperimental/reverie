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
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering::AcqRel;
use std::sync::atomic::Ordering::Acquire;

use parking_lot::Mutex;
use syscalls::Sysno;

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

            // A forked child inherits the descriptors marked inherited, and their
            // protection with them (`protect_inherited_raw_fd`).
            let mut files = ProtectedFiles::new();
            for slot in &INHERITED {
                let fd = slot.load(Acquire);
                if fd >= 0 {
                    files.insert(&fd);
                }
            }
            let candidate = Box::into_raw(Box::new(RegistryValue {
                pid,
                files: Mutex::new(files),
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

/// Descriptors that every process of the guest keeps protected: a forked child's
/// registry starts with them. Atomics, not a lock, so a child forked while another
/// thread held a lock can still read them.
static INHERITED: [AtomicI32; 4] = [const { AtomicI32::new(-1) }; 4];

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

pub(crate) fn protect_raw_fd(fd: RawFd) {
    protected_files().lock().insert(&fd);
}

/// Protects `fd` in this process and in every process forked from it later.
/// Returns false, protecting it in this process only, if every inherited slot
/// is taken.
pub(crate) fn protect_inherited_raw_fd(fd: RawFd) -> bool {
    protect_raw_fd(fd);
    INHERITED.iter().any(|slot| {
        slot.load(Acquire) == fd || slot.compare_exchange(-1, fd, AcqRel, Acquire).is_ok()
    })
}

pub(crate) fn protect_raw_pair_with<F, E>(create: F) -> Result<(RawFd, RawFd), E>
where
    F: FnOnce() -> Result<(RawFd, RawFd), E>,
{
    let mut protected = protected_files().lock();
    let pair = create()?;
    protected.insert(&pair.0);
    protected.insert(&pair.1);
    Ok(pair)
}

pub(crate) fn unprotect_raw_fd(fd: RawFd) {
    protected_files().lock().remove(&fd);
}

/// Undoes [`protect_inherited_raw_fd`]: `fd` is no longer protected here, nor
/// in a process forked from this one later.
pub(crate) fn unprotect_inherited_raw_fd(fd: RawFd) {
    for slot in &INHERITED {
        let _ = slot.compare_exchange(fd, -1, AcqRel, Acquire);
    }
    unprotect_raw_fd(fd);
}

/// Runs a guest `close_range` without closing any protected descriptor, by
/// the rule every in-process backend shares
/// ([`reverie_inguest::reserved_fds::close_range_sparing`]). The registry stays
/// locked throughout, so a descriptor pair being created and protected
/// ([`protect_raw_pair_with`]) is either closed whole before it is protected or
/// spared whole.
pub(crate) fn sys_close_range(
    first: usize,
    last: usize,
    flags: usize,
) -> Result<usize, syscalls::Errno> {
    let protected = protected_files().lock();
    let mut reserved: Vec<u64> = protected
        .files
        .iter()
        .filter_map(|fd| u32::try_from(*fd).ok().map(u64::from))
        .collect();
    reserved.sort_unstable();
    let args = [first as u64, last as u64, flags as u64, 0, 0, 0];
    // SAFETY: `args` is the guest's `close_range`, run in its own descriptor
    // table; every protected descriptor is spared.
    let result = unsafe {
        reverie_inguest::reserved_fds::close_range_sparing(&args, &reserved, |number, a| {
            syscalls::raw::syscall6(
                Sysno::from(number as i32),
                a[0] as usize,
                a[1] as usize,
                a[2] as usize,
                a[3] as usize,
                a[4] as usize,
                a[5] as usize,
            ) as i64
        })
    };
    drop(protected);
    if result < 0 {
        Err(syscalls::Errno::new(-result as i32))
    } else {
        Ok(0)
    }
}

/// The result a guest syscall gets when it names a protected descriptor, by
/// the rule every in-process backend shares ([`reverie_inguest::reserved_fds`]):
/// to the guest a protected descriptor is not open, so a `close` of it or any
/// call that names it fails with `EBADF`, after Linux's own `EINVAL` check of
/// `epoll_wait`'s event count. `None` when the call names none. A `*at` call
/// whose path is absolute does not use its directory descriptor, so it is not
/// refused. `close_range` and a `dup2`/`dup3` onto the Tool output socket's
/// number are handled before this is asked.
pub fn protected_fd_result(sysno: Sysno, args: &[u64; 6]) -> Option<i64> {
    use reverie_inguest::reserved_fds;
    let number = i64::from(sysno.id());
    protected_files()
        .lock()
        .files
        .iter()
        .filter_map(|fd| u32::try_from(*fd).ok().map(u64::from))
        .find_map(|fd| {
            if let Some(result) = reserved_fds::epoll_wait_result(number, args, fd) {
                return Some(result);
            }
            let closes = number == libc::SYS_close && reserved_fds::descriptor_arg(args, 0) == fd;
            (closes
                || reserved_fds::names_descriptor(number, args, fd)
                || reserved_fds::socket_call_names_descriptor(number, args, fd))
            .then_some(-i64::from(libc::EBADF))
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// A copy of a protected descriptor through a pidfd (`pidfd_getfd`'s second
    /// argument) is refused like any other use of it.
    #[test]
    fn pidfd_getfd_of_a_protected_descriptor_is_refused() {
        // A fresh process: this test opens, protects and closes descriptors,
        // and the global protection registry is shared with every other test
        // in this process (the adapter tests route their syscalls through it).
        if std::env::var_os("REVERIE_SABRE_PROTECTED_FILES_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "protected_files::tests::pidfd_getfd_of_a_protected_descriptor_is_refused",
                ])
                .env("REVERIE_SABRE_PROTECTED_FILES_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success(), "child test failed with {status}");
            return;
        }
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        protect_raw_fd(fds[0]);
        let ebadf = Some(-i64::from(libc::EBADF));
        assert_eq!(
            protected_fd_result(Sysno::pidfd_getfd, &[u64::MAX, fds[0] as u64, 0, 0, 0, 0]),
            ebadf
        );
        assert_eq!(
            protected_fd_result(Sysno::pidfd_getfd, &[u64::MAX, fds[1] as u64, 0, 0, 0, 0]),
            None
        );
        unprotect_raw_fd(fds[0]);
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    /// A descriptor marked inherited stays protected in a forked child, whose
    /// registry starts empty otherwise; a plainly protected one does not.
    #[test]
    fn inherited_protection_survives_fork() {
        // A fresh process: this test opens, protects and closes descriptors,
        // and the global protection registry is shared with every other test
        // in this process (the adapter tests route their syscalls through it).
        if std::env::var_os("REVERIE_SABRE_PROTECTED_FILES_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "protected_files::tests::inherited_protection_survives_fork",
                ])
                .env("REVERIE_SABRE_PROTECTED_FILES_TEST_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success(), "child test failed with {status}");
            return;
        }
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (inherited, plain) = (fds[0], fds[1]);
        assert!(protect_inherited_raw_fd(inherited));
        protect_raw_fd(plain);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::alarm(5) };
            let ok = is_protected(&inherited) && !is_protected(&plain);
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        for slot in &INHERITED {
            let _ = slot.compare_exchange(inherited, -1, AcqRel, Acquire);
        }
        unprotect_raw_fd(inherited);
        unprotect_raw_fd(plain);
        unsafe {
            libc::close(inherited);
            libc::close(plain);
        }
    }

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

    /// ⚠️ THE DESCRIPTOR MUST STAY OPEN ACROSS THE LAST ASSERTION, AND THAT IS
    /// THE WHOLE REASON THIS TEST IS SHAPED THIS WAY. The registry is keyed on
    /// the descriptor NUMBER, and a number is reusable the instant it is closed.
    ///
    /// Written the obvious way -- protect the `File` itself, so dropping the
    /// guard both deregisters AND closes -- this test was red about half the
    /// time in the full suite and always green in isolation. Measured on reverie
    /// main b181b1bb, 40 runs of `cargo test -p reverie-sabre --lib`:
    /// 21 failed, always here, always `assertion failed: !is_protected(&fd)`.
    ///
    /// Traced by logging every registry insert and remove, one failing run:
    ///
    /// ```text
    ///   insert fd=14 set=[13, 10, 3, 6, 7, 8, 11, 12]
    ///   remove fd=14 set=[13, 10, 3, 6, 7, 8, 11, 12, 14]   <- this guard drops
    ///   insert fd=14 set=[13, 10, 3, 6, 7, 8, 11, 12, 9]    <- SOMEONE ELSE takes 14
    /// ```
    ///
    /// Closing the file released number 14, a concurrently running test was
    /// handed the same number for its own descriptor and protected it, and this
    /// test then asked whether 14 was protected. It was -- correctly, for a
    /// different file. The registry and its lock are not implicated; the reused
    /// identity is.
    ///
    /// So the guard here holds a bare `RawFd`, which has no destructor: dropping
    /// it deregisters WITHOUT closing, `file` keeps the number allocated to this
    /// test until the end, and no other test can be handed it in between. The
    /// property under test is unchanged -- a registration appears with the guard
    /// and is gone after it drops.
    #[test]
    fn protected_guard_hides_descriptor_until_drop() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        let protected = protect_with(|| Ok::<RawFd, std::convert::Infallible>(fd)).unwrap();

        assert!(is_protected(&fd));
        assert_eq!(
            protected_fd_result(Sysno::close, &[fd as u64, 0, 0, 0, 0, 0]),
            Some(-i64::from(libc::EBADF))
        );

        drop(protected);
        assert!(
            !is_protected(&fd),
            "the guard deregistered, so this number must not be protected; \
             `file` still owns it, so nothing else can have taken it"
        );
        drop(file);
    }

    #[test]
    fn close_range_waits_for_atomic_protected_pair_creation() {
        let allow_registration = Arc::new(Barrier::new(2));
        let (created_tx, created_rx) = mpsc::channel();
        let (protected_tx, protected_rx) = mpsc::channel();
        let creator_barrier = allow_registration.clone();
        let creator = std::thread::spawn(move || {
            let pair = protect_raw_pair_with(|| {
                let mut pipe = [-1i32; 2];
                unsafe { syscalls::syscall2(Sysno::pipe2, pipe.as_mut_ptr() as usize, 0) }.unwrap();
                created_tx.send((pipe[0], pipe[1])).unwrap();
                creator_barrier.wait();
                Ok::<_, std::convert::Infallible>((pipe[0], pipe[1]))
            })
            .unwrap();
            protected_tx.send(pair).unwrap();
        });

        let pair = created_rx.recv().unwrap();
        let (closing_tx, closing_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            let first = pair.0.min(pair.1) as usize;
            let last = pair.0.max(pair.1) as usize;
            started_tx.send(()).unwrap();
            let result = sys_close_range(first, last, 1 << 2);
            closing_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(matches!(
            closing_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        allow_registration.wait();
        let pair = protected_rx.recv().unwrap();
        assert_eq!(closing_rx.recv().unwrap(), Ok(0));
        creator.join().unwrap();
        closer.join().unwrap();

        for fd in [pair.0, pair.1] {
            let descriptor_flags =
                unsafe { syscalls::syscall3(Sysno::fcntl, fd as usize, libc::F_GETFD as usize, 0) }
                    .unwrap();
            assert_eq!(descriptor_flags & libc::FD_CLOEXEC as usize, 0);
            unprotect_raw_fd(fd);
            unsafe { syscalls::syscall1(Sysno::close, fd as usize) }.unwrap();
        }
    }
}
