/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! [`reverie::Guest::memory_map`] of a traced thread: the kernel's own `maps`
//! of the address space of the thread `tid` names, which the tracer reads
//! while the asking thread is stopped in the tool's callback.
//!
//! A traced guest thread is a host task, and the tracer shares the guest's
//! `/proc` view, so the text is the kernel's own for that thread's address
//! space, every mapping of it, with each file named by `d_path` from the
//! tracer's root, which is the guest's unless a guest thread changed its own
//! root. The list is therefore complete. As for [`reverie::Guest::link_path`]
//! (see `crate::link_path`), the fact answers for a thread this session
//! traces, in whichever of its processes, and reads no other task's map: it
//! never names `/proc/<tid>` by number, but opens `maps` in the `/proc/<tid>`
//! directory the session retained for the task when it began tracing it
//! (`FatalSession::traced_directories`). That directory names the task it was
//! opened for until the task is reaped, and no task after.
//!
//! The map is read first, then the task's `status` through the same
//! directory, which must show a tracer that is a thread of this process and a
//! task that has not exited (a `State:` other than `Z` or `X`). The task the
//! status shows live was live when the map was read before it, so a map is
//! reported only for a live task; one that exited in between is `ESRCH`, like
//! any exited thread. (A thread that is not its process's leader and calls
//! `execve` takes over the leader's number, and its `/proc` directory, while
//! it does: a read in between can find the leader's map, which is the same
//! process's address space before the exec, or none, beside the status of the
//! thread that took the number over.)
//!
//! Linux prints a map one mapping at a time, under each mapping's own lock
//! (`lock_vma_range` in Linux's `fs/proc/task_mmu.c`, with
//! `CONFIG_PER_VMA_LOCK`), so a read that another thread of the process
//! overlaps with a change to its mappings can list text that no moment of the
//! address space had. The fact refuses such text when it shows: mappings out
//! of order or overlapping are `EIO`, as is any text that is not Linux's
//! format. Not every such read shows: a mapping removed below the point the
//! read has reached and another added above it give ordered text that is
//! still no single moment's. Only a read that no other thread of the process
//! overlaps is a snapshot.
//!
//! The text is the kernel's, with the host's values in it: the devices and
//! inodes of files, where the kernel placed the vDSO's pages, the gate area's
//! `[vsyscall]` and its permissions (the `vsyscall=` boot option), the pages
//! the tracer maps in the guest for its own use, and `[uprobes]`, a page the
//! kernel adds to a process the first time a uprobe that someone on the host
//! installed fires in it (`kernel/events/uprobes.c`), whatever the guest
//! does.

use std::ffi::CStr;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;

use reverie::FactError;
use reverie::MemoryMap;
use reverie::Pid;

use crate::signal_sets::NO_THREAD;
use crate::signal_sets::STATUS_LIMIT;
use crate::signal_sets::open_status;
use crate::signal_sets::parse;
use crate::signal_sets::read_bounded;
use crate::signal_sets::read_errno;

/// The most `maps` text read for one thread: a resource cap, not the
/// longest map Linux can print. A line is 73 columns and the mapping's name,
/// so this is about a kilobyte for each of the 65,530 mappings Linux allows
/// by default (`vm.max_map_count`), and about 870,000 mappings at the 77-byte
/// mean line of the maps on one test host. A host that raises
/// `vm.max_map_count` lets a process map more than that; a text longer than
/// the cap is not provided, never read in part.
const MAPS_LIMIT: u64 = 64 * 1024 * 1024;

/// Reads the map of thread `tid` through `directories`, which gives the
/// retained `/proc/<tid>` directories of the tasks the session traces as
/// `tid` (`FatalSession::traced_directories`): none for a number it does not
/// trace. At most one of them names a live task, the one that holds the
/// number now; a directory whose task has been reaped reads as no task, and
/// the next is tried.
pub(crate) fn read<D: AsFd>(
    tid: Pid,
    directories: impl FnOnce(Pid) -> Vec<D>,
) -> Result<MemoryMap, FactError> {
    read_bounded_map(tid, directories, MAPS_LIMIT)
}

/// [`read`], with `limit` as the most `maps` text read.
fn read_bounded_map<D: AsFd>(
    tid: Pid,
    directories: impl FnOnce(Pid) -> Vec<D>,
    limit: u64,
) -> Result<MemoryMap, FactError> {
    // Linux numbers no task zero or below.
    if tid.as_raw() <= 0 {
        return Err(NO_THREAD);
    }
    for directory in directories(tid) {
        let (text, status) = {
            // The guard ends before anything else runs.
            let _open = crate::launch_window::TransientOpen::begin();
            let text = open_maps(directory.as_fd()).and_then(|file| read_bounded(file, limit));
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
                reverie::Errno::ESRCH => continue,
                errno => return Err(FactError::Errno(errno)),
            },
        }
        // The task is live, so the map's own read failed for another reason,
        // the kernel's answer to the tracer: `EACCES` for a task whose map
        // Linux does not let the tracer read.
        return match text {
            Ok(Some(text)) => MemoryMap::from_maps(&text),
            Ok(None) => Err(FactError::NotProvided),
            Err(error) => Err(FactError::Errno(read_errno(&error))),
        };
    }
    Err(NO_THREAD)
}

/// Opens `maps` read-only in the task directory `directory`: the map of the
/// task the directory was opened for, whatever task holds its number now.
/// `ENOENT` once that task has been reaped. A task that has no address space
/// left, a zombie or a task past the point of its exit where it releases it,
/// has an empty map.
fn open_maps(directory: BorrowedFd<'_>) -> std::io::Result<std::fs::File> {
    const MAPS: &CStr = c"maps";
    // SAFETY: the directory descriptor is open for the call, and the name is
    // a NUL-terminated string.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            MAPS.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;

    use reverie::MappingBacking;

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
        assert_eq!(read(this_thread(), untraced), Err(NO_THREAD));
        assert_eq!(read(Pid::from_raw(1), untraced), Err(NO_THREAD));
        assert_eq!(asked.get(), 2);
        for tid in [0, -1, i32::MIN] {
            assert_eq!(read(Pid::from_raw(tid), untraced), Err(NO_THREAD), "{tid}");
        }
        assert_eq!(asked.get(), 2);
    }

    /// Where the session gives a directory, the task's status read through
    /// it must still show a tracer of this process: this test's own thread
    /// and init are traced by none of ours, so their maps are not reported,
    /// though the kernel would let this process read this thread's.
    #[test]
    fn a_task_no_tracer_of_ours_traces_is_esrch() {
        for tid in [this_thread().as_raw(), 1] {
            let directory = task_directory(tid);
            assert_eq!(
                read(Pid::from_raw(tid), |_| vec![directory]),
                Err(NO_THREAD),
                "{tid}"
            );
        }
    }

    /// A child of this process that this thread traces, and its directory,
    /// opened while it is certainly traced here. It shares nothing with this
    /// process once forked: its address space is the copy it was forked
    /// with, and it changes nothing in it while it pauses. Dropped unreaped,
    /// as when a test fails, it is killed and reaped.
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

        fn read(&self, number: Pid) -> Result<MemoryMap, FactError> {
            read(number, |_| vec![self.directory()])
        }

        /// The child's map as the kernel prints it to this process, read by
        /// number, which no other task can hold while the child is unreaped.
        fn maps(&self) -> MemoryMap {
            let text = std::fs::read(format!("/proc/{}/maps", self.pid)).unwrap();
            MemoryMap::from_maps(&text).unwrap()
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

    /// A mapping of a file of this test's own, which no other mapping names,
    /// unmapped and removed when dropped.
    struct Region {
        path: std::path::PathBuf,
        start: *mut libc::c_void,
    }

    impl Region {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("reverie-ptrace-memory-map-{}", std::process::id()));
            std::fs::write(&path, [0x5a; 4096]).unwrap();
            let file = std::fs::File::open(&path).unwrap();
            // SAFETY: a new private mapping of the file overlaps nothing.
            let start = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(start, libc::MAP_FAILED);
            let path = std::fs::canonicalize(&path).unwrap();
            Self { path, start }
        }

        /// Whether `map` holds this mapping, by the file it names.
        fn in_map(&self, map: &MemoryMap) -> bool {
            map.mappings.iter().any(|mapping| {
                matches!(
                    &mapping.backing,
                    MappingBacking::File { path, .. }
                        if path.as_slice() == self.path.as_os_str().as_encoded_bytes()
                )
            })
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            // SAFETY: the mapping is this region's own.
            unsafe { libc::munmap(self.start, 4096) };
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// A traced child's map is the kernel's, the same list the kernel prints
    /// to this process for it, complete: its stack and the files of its image
    /// among them. Once it has exited, a zombie whose map is empty, it is
    /// ESRCH, and so once it is reaped.
    #[test]
    fn a_traced_childs_map_is_the_kernels_until_it_exits() {
        let mut child = TracedChild::new();
        let number = Pid::from_raw(child.pid);
        let map = child.read(number).unwrap();
        assert!(map.complete);
        assert_eq!(map, child.maps());
        assert!(
            map.mappings
                .iter()
                .any(|mapping| mapping.backing == MappingBacking::Stack),
            "{map:?}"
        );
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        assert!(
            map.mappings.iter().any(|mapping| matches!(
                &mapping.backing,
                MappingBacking::File { path, .. } if path.as_slice() == exe.as_os_str().as_encoded_bytes()
            )),
            "{map:?}"
        );
        child.kill();
        let text = std::fs::read_to_string(format!("/proc/{}/status", child.pid)).unwrap();
        assert!(text.contains("State:\tZ (zombie)\n"), "{text}");
        assert!(
            std::fs::read(format!("/proc/{}/maps", child.pid))
                .unwrap()
                .is_empty()
        );
        assert_eq!(child.read(number), Err(NO_THREAD));
        child.reap();
        assert_eq!(child.read(number), Err(NO_THREAD));
    }

    /// A map longer than the bound is not provided, rather than read in part.
    #[test]
    fn a_map_longer_than_the_bound_is_not_provided() {
        let child = TracedChild::new();
        let number = Pid::from_raw(child.pid);
        let length = std::fs::read(format!("/proc/{}/maps", child.pid))
            .unwrap()
            .len() as u64;
        assert_eq!(
            read_bounded_map(number, |_| vec![child.directory()], length - 1),
            Err(FactError::NotProvided)
        );
        assert_eq!(
            read_bounded_map(number, |_| vec![child.directory()], length),
            Ok(child.maps())
        );
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
    /// directory of another reads the other's map, which alone holds a file
    /// mapped after the first one forked.
    #[test]
    fn a_directory_names_its_task_not_whoever_holds_the_number() {
        let mut gone = TracedChild::new();
        gone.kill();
        gone.reap();
        let live = TracedChild::new();
        let number = Pid::from_raw(live.pid);
        assert_eq!(read(number, |_| vec![gone.directory()]), Err(NO_THREAD));
        assert_eq!(
            read(number, |_| vec![gone.directory(), live.directory()]),
            Ok(live.maps())
        );
        let region = Region::new();
        let holder = TracedChild::new();
        let other = read(number, |_| vec![holder.directory()]).unwrap();
        assert_eq!(other, holder.maps());
        assert!(region.in_map(&other), "{other:?}");
        let own = live.read(number).unwrap();
        assert!(!region.in_map(&own), "{own:?}");
    }
}
