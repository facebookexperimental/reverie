/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// These tests read the live kernel's /proc and make the calls that
// create the objects under test; the library stays pure.
#![cfg(target_os = "linux")]
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Kernel-oracle tests: the running kernel is the ground truth.
//!
//! - `live_proc_inventory` parses every readable per-task file on
//!   the host; a refusal is either a grammar bug or a new kernel
//!   field — both must go red here, never leak silently.
//! - `pr_set_name_population` manufactures comms the live population
//!   may not contain (non-UTF-8, newline, `) `, truncation edge) and
//!   reads back what the kernel actually printed.
//! - `fdinfo_kinds_from_live_objects` creates one object of each
//!   modelled fd kind and round-trips its fdinfo.
//! - `fdinfo_read_racing_a_close_is_counted_not_misparsed` closes an
//!   fd between opening and reading its fdinfo, the race the
//!   inventory meets on a busy host, and checks how the read is
//!   classified.
//! - `read_of_an_exited_task_is_counted_not_misparsed` reaps a child
//!   between opening and reading its /proc entries, the other race
//!   the inventory meets, and checks how those reads are classified.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;

use reverie_proc_grammar::*;

/// The oracle tests share one live `/proc`: the inventory counts
/// this process's own threads and fds, so a sibling test opening
/// fds concurrently can move the thin-population floors mid-scan.
/// Serialize the tests in this binary instead of lowering them.
static ORACLE_SERIAL: Mutex<()> = Mutex::new(());

fn oracle_serial() -> MutexGuard<'static, ()> {
    ORACLE_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The absolute anti-vacuity minimum for a live inventory format:
/// twenty independently attempted tasks. Below that, even a 100%
/// round-trip rate is too small a sample to call the format
/// inventory exercised, so the run fails as too thin instead of
/// passing on a handful of tasks.
const MIN_ATTEMPTED_PER_FORMAT: usize = 20;

/// The scaled successful-round-trip backstop for eligible
/// entries: ~90% at any population, capped at 101. It cannot
/// fire after the hard-fail asserts (every attempted entry has
/// round-tripped there), so coverage in
/// [`inventory_floor_met`] rests on the listed-entry accounting
/// and the absolute attempted minimum, not on this ratio.
fn scaled_floor(eligible: usize) -> usize {
    usize::min(101, eligible * 9 / 10 + 1)
}

/// Whether an inventory format kept listed-entry coverage after
/// only verified exclusions are removed from the listed total.
/// Every eligible entry must have been attempted, the attempted
/// population must reach the absolute minimum, and successful
/// round-trips must clear the scaled backstop.
fn inventory_floor_met(
    listed: usize,
    verified_excluded: usize,
    attempted: usize,
    ok: usize,
) -> bool {
    let eligible = listed.saturating_sub(verified_excluded);
    attempted == eligible && attempted >= MIN_ATTEMPTED_PER_FORMAT && ok >= scaled_floor(eligible)
}

/// Per-format live-read categories. Only successful reads are
/// attempted (parseable-or-refused); tasks that vanished mid-scan
/// (`NotFound`, or `ESRCH` when the task exited between open and
/// read, see [`task_exited`]) or are not visible to this reader
/// (`PermissionDenied`, e.g. hidepid or another user) are counted
/// separately; only the verified causes counted in
/// `listed_not_found` / `listed_permission_denied` /
/// `listed_task_exited` leave the listed-entry coverage denominator.
#[derive(Clone, Default)]
struct ReadCounts {
    attempted: usize,
    ok: usize,
    not_found: usize,
    permission_denied: usize,
    task_exited: usize,
    listed_not_found: usize,
    listed_permission_denied: usize,
    listed_task_exited: usize,
}

/// Whether a `/proc` read failed because its task was gone when the
/// kernel looked the task up. Linux v7.1.3 returns `ESRCH` then from
/// `proc_single_show`, which prints stat, statm, status and io
/// (fs/proc/base.c:808-810), from `sched_show` (:1507-1509) and
/// `comm_show` (:1755-1757), and from `proc_fdinfo_permission`, which
/// guards the fdinfo directory and its entries (fs/proc/fd.c:89-92).
/// No bytes come back, so there is nothing to misparse.
fn task_exited(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

/// The credential facts `__ptrace_may_access` compares, read from
/// a task's `/proc/<pid>/status` plus the gated inode's owner.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AccessFacts {
    uids: [u32; 4],
    gids: [u32; 4],
    cap_prm: u64,
    cap_eff: u64,
    gated_inode_uid: Option<u32>,
}

fn access_facts(status_path: &Path, gated_inode_uid: Option<u32>) -> Option<AccessFacts> {
    let text = fs::read_to_string(status_path).ok()?;
    let mut uids = None;
    let mut gids = None;
    let mut cap_prm = None;
    let mut cap_eff = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first().copied() {
            Some("Uid:") if fields.len() == 5 => {
                uids = Some([
                    fields[1].parse().ok()?,
                    fields[2].parse().ok()?,
                    fields[3].parse().ok()?,
                    fields[4].parse().ok()?,
                ]);
            }
            Some("Gid:") if fields.len() == 5 => {
                gids = Some([
                    fields[1].parse().ok()?,
                    fields[2].parse().ok()?,
                    fields[3].parse().ok()?,
                    fields[4].parse().ok()?,
                ]);
            }
            Some("CapPrm:") if fields.len() == 2 => {
                cap_prm = Some(u64::from_str_radix(fields[1], 16).ok()?);
            }
            Some("CapEff:") if fields.len() == 2 => {
                cap_eff = Some(u64::from_str_radix(fields[1], 16).ok()?);
            }
            _ => {}
        }
    }
    Some(AccessFacts {
        uids: uids?,
        gids: gids?,
        cap_prm: cap_prm?,
        cap_eff: cap_eff?,
        gated_inode_uid,
    })
}

/// The named reason a `PermissionDenied` from a ptrace-gated read
/// (`/proc/<pid>/io` or listing `/proc/<pid>/fdinfo`) is the
/// kernel's access check, following `__ptrace_may_access`
/// (kernel/ptrace.c: reader fsuid/fsgid must equal the target's
/// uid/euid/suid and gid/egid/sgid, and the task must be
/// dumpable) and `cap_ptrace_access_check`
/// (security/commoncap.c: the target's permitted capability set
/// must be a subset of the reader's effective set). A root-owned
/// gated inode (the io/status file, not the task directory) is the kernel's sign of a non-dumpable
/// task. `None` means the denial is unexplained by those facts.
fn ptrace_denial_reason(reader: &AccessFacts, target: &AccessFacts) -> Option<&'static str> {
    // CAP_SYS_PTRACE lets the reader past the id, dumpable and
    // capability-subset checks below, so a denial seen by such a
    // reader is not explained by ptrace access at all.
    if reader.cap_eff & (1 << 19) != 0 {
        None
    } else if target.uids[..3].iter().any(|uid| *uid != reader.uids[3]) {
        Some("target uid/euid/suid differs from reader fsuid")
    } else if target.gids[..3].iter().any(|gid| *gid != reader.gids[3]) {
        Some("target gid/egid/sgid differs from reader fsgid")
    } else if target.cap_prm & !reader.cap_eff != 0 {
        Some("target CapPrm is not a subset of reader CapEff")
    } else if target.gated_inode_uid == Some(0) && reader.uids[3] != 0 {
        Some("target gated io/status inode is root-owned (non-dumpable task)")
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ReadDisposition {
    /// The cause was verified at read time: the task or fd is
    /// gone, it belongs to another user and this reader is not
    /// root, or a ptrace-gated denial carries a named kernel
    /// reason from the target's status facts.
    Excluded,
    /// No verified cause: the read error is an inventory failure.
    Fail,
}

/// Classifies a failed inventory read. `verified_gone` must come
/// from a re-check that the task (or fd entry) no longer exists;
/// `task_uid` is the owner read from `/proc/{pid}` at scan time.
fn classify_read_error(
    kind: io::ErrorKind,
    verified_gone: bool,
    task_uid: Option<u32>,
    my_uid: u32,
    own_tasks_only: bool,
    ptrace_gated: bool,
    ptrace_reason: Option<&'static str>,
) -> ReadDisposition {
    match kind {
        io::ErrorKind::NotFound if verified_gone => ReadDisposition::Excluded,
        // Deliberate ptrace-gated exception (io file and fdinfo
        // directory only, both non-floored paths): a denial the
        // kernel's own access check explains from the target's
        // status facts is not hidden inventory data. The caller
        // supplies ptrace_denial_reason's verdict; no named reason
        // means the denial is unexplained and fails.
        io::ErrorKind::PermissionDenied if ptrace_gated && ptrace_reason.is_some() => {
            ReadDisposition::Excluded
        }
        io::ErrorKind::PermissionDenied
            if !own_tasks_only && my_uid != 0 && task_uid.is_some_and(|uid| uid != my_uid) =>
        {
            ReadDisposition::Excluded
        }
        _ => ReadDisposition::Fail,
    }
}

fn verified_gone(path: &Path) -> bool {
    matches!(path.try_exists(), Ok(false))
}

fn note_excluded_with_reason(
    examples: &mut BTreeMap<(&str, io::ErrorKind), Vec<String>>,
    format: &'static str,
    path: &Path,
    kind: io::ErrorKind,
    reason: Option<&str>,
) {
    let examples = examples.entry((format, kind)).or_default();
    if examples.len() < 3 {
        match reason {
            Some(reason) => examples.push(format!("{} ({kind:?}: {reason})", path.display())),
            None => examples.push(format!("{} ({kind:?})", path.display())),
        }
    }
}

/// Classifies the outcome of reading one inventory file at `path`.
/// Only a verified-vanished `NotFound`, a task that exited between
/// open and read ([`task_exited`]), a foreign-owned task's
/// `PermissionDenied` (for a non-root reader, outside fdinfo's
/// own-task walk), and a ptrace-gated denial with a named kernel
/// reason are excluded; every other outcome is recorded in
/// `failures` and hard-fails the inventory.
#[allow(clippy::too_many_arguments)]
fn read_inventory_file(
    path: &Path,
    read: io::Result<Vec<u8>>,
    verified_gone: impl FnOnce() -> bool,
    task_uid: Option<u32>,
    my_uid: u32,
    own_tasks_only: bool,
    ptrace_reason: Option<&'static str>,
    format: &'static str,
    counts: &mut ReadCounts,
    examples: &mut BTreeMap<(&str, io::ErrorKind), Vec<String>>,
    failures: &mut Vec<String>,
) -> Option<Vec<u8>> {
    match read {
        Ok(bytes) => {
            counts.attempted += 1;
            Some(bytes)
        }
        Err(error) if task_exited(&error) => {
            counts.task_exited += 1;
            counts.listed_task_exited += 1;
            note_excluded_with_reason(examples, format, path, error.kind(), Some("task exited"));
            None
        }
        Err(error) => {
            let kind = error.kind();
            let disposition = classify_read_error(
                kind,
                verified_gone(),
                task_uid,
                my_uid,
                own_tasks_only,
                format == "io",
                ptrace_reason,
            );
            if disposition == ReadDisposition::Excluded {
                match kind {
                    io::ErrorKind::NotFound => {
                        counts.not_found += 1;
                        counts.listed_not_found += 1;
                    }
                    io::ErrorKind::PermissionDenied => {
                        counts.permission_denied += 1;
                        counts.listed_permission_denied += 1;
                    }
                    _ => unreachable!("only the two kinds above can be excluded"),
                }
                note_excluded_with_reason(
                    examples,
                    format,
                    path,
                    kind,
                    if format == "io" { ptrace_reason } else { None },
                );
            } else if failures.len() < 10 {
                failures.push(format!("{}: read failed: {error}", path.display()));
            }
            None
        }
    }
}

/// What `/proc/<pid>/fd/<n>` named at one instant. This symlink
/// resolves to the open file itself, so it tells a reused fd number
/// apart; the `fdinfo/<n>` entry cannot, because it is a regular
/// file whose procfs inode stays valid while the number is closed
/// and reopened (`tid_fd_revalidate`, fs/proc/fd.c).
#[derive(Clone, Debug, PartialEq, Eq)]
enum FdTarget {
    Named(PathBuf),
    /// `NotFound`: no fd with this number, or no such task.
    Absent,
    /// Any other error: the target is unknown.
    Unreadable(io::ErrorKind),
}

fn fd_target(link: &Path) -> FdTarget {
    match fs::read_link(link) {
        Ok(target) => FdTarget::Named(target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => FdTarget::Absent,
        Err(error) => FdTarget::Unreadable(error.kind()),
    }
}

/// Why a listed fdinfo entry's read returned no bytes. A `NotFound`
/// is judged by what `fd/<n>` named before the read and names after
/// it; the `NotFound` alone proves the fd was closed at the read, and
/// this only labels what followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdRace {
    /// `fd/<n>` is absent or unreadable after the read, or was
    /// unreadable before it.
    Closed,
    /// A different target holds the number after the read, or the
    /// number was absent before it and is held after it.
    Reused,
    /// An equal target holds the number before and after: it was
    /// closed at the read and reopened before the second look. An
    /// anonymous-inode kind names every object of that kind alike
    /// (`anon_inode:[eventfd]`), so a reuse by another object of the
    /// same kind lands here too.
    ReopenedSameTarget,
    /// `ESRCH`: the task was gone when the kernel checked access to
    /// the entry ([`task_exited`]).
    TaskExited,
}

/// The outcome of reading one listed `/proc/<pid>/fdinfo/<n>`.
#[derive(Debug)]
enum FdinfoRead {
    /// The kernel printed the fdinfo of whichever file held the
    /// number at the read instant: always a real kernel fdinfo, so
    /// it is always parsed, and a misparse always fails.
    Bytes(Vec<u8>),
    /// `NotFound`: at the read instant the task held no file at that
    /// number, or the task was gone (`seq_show` and
    /// `proc_lookupfd_common`, fs/proc/fd.c). There are no bytes, so
    /// there is nothing to misparse; the caller counts it. The same
    /// holds for `ESRCH` ([`FdRace::TaskExited`]).
    Raced(FdRace),
    /// Any other error. No exclusion applies.
    Failed(io::Error),
}

/// Classifies one fdinfo read. `before` is `fd/<n>` read before the
/// fdinfo read; `after` reads it again and runs only for `NotFound`.
fn classify_fdinfo_read(
    before: &FdTarget,
    read: io::Result<Vec<u8>>,
    after: impl FnOnce() -> FdTarget,
) -> FdinfoRead {
    match read {
        Ok(bytes) => FdinfoRead::Bytes(bytes),
        Err(error) if task_exited(&error) => FdinfoRead::Raced(FdRace::TaskExited),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            FdinfoRead::Raced(match (before, after()) {
                (FdTarget::Named(before), FdTarget::Named(after)) if *before == after => {
                    FdRace::ReopenedSameTarget
                }
                (FdTarget::Named(_) | FdTarget::Absent, FdTarget::Named(_)) => FdRace::Reused,
                _ => FdRace::Closed,
            })
        }
        Err(error) => FdinfoRead::Failed(error),
    }
}

/// Listed fdinfo entries excluded because their read returned no
/// bytes, by [`FdRace`].
#[derive(Debug, Default)]
struct FdRaceCounts {
    closed: usize,
    reused: usize,
    reopened_same_target: usize,
    task_exited: usize,
}

/// Opens one fd of each modelled kind that needs no privilege, for
/// the caller to hold across a scan: eventfd, timerfd, signalfd,
/// pidfd, memfd, both ends of a pipe, an epoll instance watching the
/// pipe, an inotify instance watching `/tmp`, and a unix socket pair.
fn open_held_fds() -> Vec<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    fn own(fd: i32, call: &str) -> OwnedFd {
        assert!(fd >= 0, "{call}: {}", io::Error::last_os_error());
        // SAFETY: the kernel just returned this fd and nothing else
        // owns it.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
    let mut held = Vec::new();
    // SAFETY: each call creates one kernel object with the documented
    // arguments, and every result is checked by `own` or an assert.
    unsafe {
        held.push(own(libc::eventfd(5, libc::EFD_CLOEXEC), "eventfd"));
        held.push(own(
            libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC),
            "timerfd_create",
        ));
        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut set), 0);
        assert_eq!(libc::sigaddset(&mut set, libc::SIGUSR1), 0);
        held.push(own(libc::signalfd(-1, &set, libc::SFD_CLOEXEC), "signalfd"));
        held.push(own(
            libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32,
            "pidfd_open",
        ));
        held.push(own(
            libc::memfd_create(c"proc-grammar-held".as_ptr(), libc::MFD_CLOEXEC),
            "memfd_create",
        ));
        let mut pipefd = [0i32; 2];
        assert_eq!(
            libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC),
            0,
            "pipe2: {}",
            io::Error::last_os_error()
        );
        let read_end = own(pipefd[0], "pipe2");
        let write_end = own(pipefd[1], "pipe2");
        let epoll = own(libc::epoll_create1(libc::EPOLL_CLOEXEC), "epoll_create1");
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0x1234,
        };
        assert_eq!(
            libc::epoll_ctl(
                epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                read_end.as_raw_fd(),
                &mut event
            ),
            0
        );
        let inotify = own(libc::inotify_init1(libc::IN_CLOEXEC), "inotify_init1");
        assert!(
            libc::inotify_add_watch(inotify.as_raw_fd(), c"/tmp".as_ptr(), libc::IN_ALL_EVENTS)
                >= 0
        );
        held.extend([read_end, write_end, epoll, inotify]);
    }
    let (a, b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    held.extend([OwnedFd::from(a), OwnedFd::from(b)]);
    held
}

fn pids() -> Vec<u32> {
    let mut pids: Vec<u32> = fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids
}

/// The live mount table round-trips byte-exactly. It is identical
/// for every task in the namespace, so it is read once here rather
/// than per pid in the inventory below.
#[test]
fn live_mountinfo_round_trips() {
    let _serial = oracle_serial();
    let bytes = fs::read("/proc/self/mountinfo").expect("read live mountinfo");
    let rows = parse_mountinfo(&bytes).expect("live mountinfo refused");
    assert!(!rows.is_empty(), "a live namespace has mounts");
    assert_eq!(render_mountinfo(&rows), bytes);
}

#[test]
fn inventory_floor_requires_an_absolute_attempted_minimum() {
    // Full-host cap is unchanged: with 500 eligible entries the
    // historical >100 volume requirement applies.
    assert_eq!(scaled_floor(500), 101);
    assert!(inventory_floor_met(500, 0, 500, 101));
    assert!(!inventory_floor_met(500, 0, 500, 100));
    // Issue https://github.com/facebookexperimental/reverie/issues/92 after verified
    // exclusions are classified: 63 listed, 10 verified
    // exclusions, and all 53 eligible entries attempted and
    // round-tripped clears the scaled floor (48).
    assert_eq!(scaled_floor(53), 48);
    assert!(inventory_floor_met(63, 10, 53, 53));
    // A majority-excluded population cannot pass on a perfect tiny
    // remainder: 63 listed with 50 verified exclusions leaves 13
    // attempted, below the absolute minimum even at 13/13.
    assert!(!inventory_floor_met(63, 50, 13, 13));
    assert!(!inventory_floor_met(0, 0, 0, 0));
    // Eligible entries that were never attempted do not count as
    // coverage, however good the success ratio among attempts is.
    assert!(!inventory_floor_met(500, 0, 499, 499));
}

#[test]
fn read_error_classification_requires_a_verified_cause() {
    use ReadDisposition::Excluded;
    use ReadDisposition::Fail;

    // A vanished task is the only excluded NotFound.
    assert_eq!(
        classify_read_error(
            io::ErrorKind::NotFound,
            true,
            Some(1000),
            1000,
            false,
            false,
            None
        ),
        Excluded
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::NotFound,
            false,
            Some(1000),
            1000,
            false,
            false,
            None
        ),
        Fail
    );
    // A foreign-owned task denied to a non-root reader is excluded;
    // the same denial on an own-uid task, as root, with no owner
    // evidence, or in fdinfo's own-task walk is a failure.
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1001),
            1000,
            false,
            false,
            None,
        ),
        Excluded
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1000),
            1000,
            false,
            false,
            None,
        ),
        Fail
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1001),
            0,
            false,
            false,
            None,
        ),
        Fail
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            None,
            1000,
            false,
            false,
            None,
        ),
        Fail
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1001),
            1000,
            true,
            false,
            None,
        ),
        Fail
    );
    // Every other read error fails, verified cause or not.
    assert_eq!(
        classify_read_error(
            io::ErrorKind::InvalidData,
            true,
            Some(1001),
            1000,
            false,
            false,
            None
        ),
        Fail
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::Other,
            true,
            Some(1001),
            1000,
            false,
            false,
            None
        ),
        Fail
    );
    // A named ptrace reason does not widen the exemption beyond
    // the gated paths: a floored-format file and a single fd entry
    // in fdinfo's own-task walk still fail with one present.
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1000),
            1000,
            false,
            false,
            Some("target gated io/status inode is root-owned (non-dumpable task)"),
        ),
        Fail
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1000),
            1000,
            true,
            false,
            Some("target gated io/status inode is root-owned (non-dumpable task)"),
        ),
        Fail
    );
    // The deliberate ptrace-gated exception: a same-uid denial is
    // excluded only when the caller verified a named ptrace
    // reason, and still only for PermissionDenied.
    assert_eq!(
        classify_read_error(
            io::ErrorKind::PermissionDenied,
            false,
            Some(1000),
            1000,
            false,
            true,
            Some("target gated io/status inode is root-owned (non-dumpable task)"),
        ),
        Excluded
    );
    assert_eq!(
        classify_read_error(
            io::ErrorKind::Other,
            true,
            Some(1000),
            1000,
            false,
            true,
            Some("target gated io/status inode is root-owned (non-dumpable task)")
        ),
        Fail
    );
}

#[test]
fn ptrace_denial_reason_names_each_kernel_check() {
    // Reader real/saved ids intentionally differ from its fs ids:
    // every comparison below must be judged by the fs ids.
    let reader = AccessFacts {
        uids: [999, 1000, 1000, 1000],
        gids: [99, 100, 100, 100],
        cap_prm: 0,
        cap_eff: 0,
        gated_inode_uid: Some(1000),
    };
    let equal = AccessFacts {
        uids: [1000, 1000, 1000, 1000],
        gids: [100, 100, 100, 100],
        cap_prm: 0,
        cap_eff: 0,
        gated_inode_uid: Some(1000),
    };
    assert_eq!(ptrace_denial_reason(&reader, &equal), None);

    // Each target real/effective/saved uid and gid alone names a
    // reason; a differing target fs id alone does not (the kernel
    // does not compare it).
    for index in 0..3 {
        let mut by_uid = equal.clone();
        by_uid.uids[index] = 1001;
        assert_eq!(
            ptrace_denial_reason(&reader, &by_uid),
            Some("target uid/euid/suid differs from reader fsuid"),
            "uid field {index}"
        );
        let mut by_gid = equal.clone();
        by_gid.gids[index] = 101;
        assert_eq!(
            ptrace_denial_reason(&reader, &by_gid),
            Some("target gid/egid/sgid differs from reader fsgid"),
            "gid field {index}"
        );
    }
    let mut by_fsuid = equal.clone();
    by_fsuid.uids[3] = 1001;
    assert_eq!(ptrace_denial_reason(&reader, &by_fsuid), None);
    let mut by_fsgid = equal.clone();
    by_fsgid.gids[3] = 101;
    assert_eq!(ptrace_denial_reason(&reader, &by_fsgid), None);

    // CapPrm is compared with the reader's effective set, not its
    // permitted set.
    let mut reader_eff = reader.clone();
    reader_eff.cap_eff = 1;
    let mut by_caps = equal.clone();
    by_caps.cap_prm = 1;
    assert_eq!(ptrace_denial_reason(&reader_eff, &by_caps), None);
    let mut reader_prm_only = reader.clone();
    reader_prm_only.cap_prm = 1;
    assert_eq!(
        ptrace_denial_reason(&reader_prm_only, &by_caps),
        Some("target CapPrm is not a subset of reader CapEff")
    );

    // CAP_SYS_PTRACE (bit 19) in the reader's effective set lets
    // it past the id and dumpable checks, so no reason applies.
    let mut privileged = reader.clone();
    privileged.cap_eff = 1 << 19;
    let mut otherwise_denied = equal.clone();
    otherwise_denied.uids[0] = 1001;
    otherwise_denied.gated_inode_uid = Some(0);
    assert_eq!(ptrace_denial_reason(&privileged, &otherwise_denied), None);

    let mut non_dumpable = equal.clone();
    non_dumpable.gated_inode_uid = Some(0);
    assert_eq!(
        ptrace_denial_reason(&reader, &non_dumpable),
        Some("target gated io/status inode is root-owned (non-dumpable task)")
    );
}

#[test]
fn live_proc_inventory() {
    let _serial = oracle_serial();
    let my_uid = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata("/proc/self")
            .expect("stat /proc/self for the reader uid")
            .uid()
    };
    let reader_access = access_facts(
        Path::new("/proc/self/status"),
        fs::metadata("/proc/self/io").ok().map(|metadata| {
            use std::os::unix::fs::MetadataExt;
            metadata.uid()
        }),
    )
    .expect("reader access facts from /proc/self/status");
    let mut reads: BTreeMap<&str, ReadCounts> = BTreeMap::new();
    let mut excluded_examples: BTreeMap<(&str, io::ErrorKind), Vec<String>> = BTreeMap::new();
    let mut refused: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let all_pids = pids();
    let population = all_pids.len();
    // This process cannot exit mid-scan, so each of its own per-task
    // files must round-trip, whatever the exclusions below allow.
    let my_pid = std::process::id();
    let mut own_round_tripped: BTreeSet<&str> = BTreeSet::new();

    for pid in &all_pids {
        let base = format!("/proc/{pid}");
        let task_path = Path::new(&base);
        let task_uid = fs::metadata(task_path).ok().map(|metadata| {
            use std::os::unix::fs::MetadataExt;
            metadata.uid()
        });
        let task_access = access_facts(
            &task_path.join("status"),
            fs::metadata(task_path.join("io")).ok().map(|metadata| {
                use std::os::unix::fs::MetadataExt;
                metadata.uid()
            }),
        );
        let task_ptrace_reason = task_access
            .as_ref()
            .and_then(|target| ptrace_denial_reason(&reader_access, target));
        macro_rules! check {
            ($file:literal, $parse:ident, $render:ident) => {
                let path = format!("{base}/{}", $file);
                if let Some(bytes) = read_inventory_file(
                    Path::new(&path),
                    fs::read(&path),
                    || verified_gone(task_path),
                    task_uid,
                    my_uid,
                    false,
                    task_ptrace_reason,
                    $file,
                    reads.entry($file).or_default(),
                    &mut excluded_examples,
                    &mut failures,
                ) {
                    match $parse(&bytes) {
                        Ok(parsed) => {
                            if $render(&parsed) == bytes {
                                reads.entry($file).or_default().ok += 1;
                                if *pid == my_pid {
                                    own_round_tripped.insert($file);
                                }
                            } else if failures.len() < 10 {
                                failures.push(format!(
                                    "{base}/{}: render(parse(bytes)) != bytes",
                                    $file
                                ));
                            }
                        }
                        Err(error) => {
                            *refused.entry($file).or_default() += 1;
                            if failures.len() < 10 {
                                failures.push(format!("{base}/{}: refused: {error}", $file));
                            }
                        }
                    }
                }
            };
        }
        check!("stat", parse_stat, render_stat);
        check!("comm", parse_comm_file, render_comm_file);
        check!("statm", parse_statm, render_statm);
        check!("sched", parse_sched, render_sched);
        check!("io", parse_process_io, render_process_io);
        // Status additionally fails the inventory on any label the
        // grammar does not know yet: read through the preserving
        // parser so the failure can name the missing labels (the
        // strict default refusing them is unit-tested).
        let status_path = format!("{base}/status");
        if let Some(bytes) = read_inventory_file(
            Path::new(&status_path),
            fs::read(&status_path),
            || verified_gone(task_path),
            task_uid,
            my_uid,
            false,
            task_ptrace_reason,
            "status",
            reads.entry("status").or_default(),
            &mut excluded_examples,
            &mut failures,
        ) {
            match parse_status_preserving_unknown(&bytes) {
                Ok(parsed) => {
                    let unknown: Vec<String> = parsed
                        .unknown_labels()
                        .map(|label| String::from_utf8_lossy(label).into_owned())
                        .collect();
                    if !unknown.is_empty() {
                        if failures.len() < 10 {
                            failures.push(format!(
                                "{base}/status: labels missing from grammar: {}",
                                unknown.join(", ")
                            ));
                        }
                    } else if render_status(&parsed) == bytes {
                        reads.entry("status").or_default().ok += 1;
                        if *pid == my_pid {
                            own_round_tripped.insert("status");
                        }
                    } else if failures.len() < 10 {
                        failures.push(format!("{base}/status: render(parse(bytes)) != bytes"));
                    }
                }
                Err(error) => {
                    *refused.entry("status").or_default() += 1;
                    if failures.len() < 10 {
                        failures.push(format!("{base}/status: refused: {error}"));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "live /proc inventory failed (refusals by format: {refused:?}):\n{}",
        failures.join("\n")
    );
    // Coverage is over listed entries after only verified
    // exclusions: a re-checked-vanished task, a task the kernel
    // reported gone at the read (ESRCH), a foreign-owned
    // task denied to a non-root reader, or a ptrace-gated denial
    // with a named kernel reason. The scaled ratio is a backstop
    // (after the hard-fail asserts every attempted entry has
    // round-tripped); coverage rests on every eligible entry
    // having been attempted plus the absolute minimum.
    // Refusals and render mismatches hard-fail above at any size.
    for (format, counts) in &reads {
        eprintln!(
            "live_proc_inventory {format}: listed {population}, attempted {}, \
             round-tripped {}, excluded not-found {}, permission-denied {}, \
             task exited {}",
            counts.attempted,
            counts.ok,
            counts.not_found,
            counts.permission_denied,
            counts.task_exited,
        );
    }
    for ((format, kind), examples) in &excluded_examples {
        eprintln!(
            "live_proc_inventory excluded {format} {kind:?} examples: {}",
            examples.join(", ")
        );
    }
    for format in ["stat", "status", "comm", "statm", "sched"] {
        let counts = reads.get(format).cloned().unwrap_or_default();
        let verified_excluded =
            counts.listed_not_found + counts.listed_permission_denied + counts.listed_task_exited;
        let eligible = population - verified_excluded;
        assert!(
            inventory_floor_met(population, verified_excluded, counts.attempted, counts.ok),
            "inventory too thin for {format}: {} round-tripped of {} attempted \
             ({population} listed, {eligible} eligible after {} verified-not-found, \
             {} verified-foreign permission-denied and {} task-exited exclusions; \
             floor {} with absolute minimum {MIN_ATTEMPTED_PER_FORMAT}; excluded \
             examples: not-found [{}], permission-denied [{}])",
            counts.ok,
            counts.attempted,
            counts.not_found,
            counts.permission_denied,
            counts.task_exited,
            scaled_floor(eligible),
            excluded_examples
                .get(&(format, io::ErrorKind::NotFound))
                .map(|examples| examples.join(", "))
                .unwrap_or_default(),
            excluded_examples
                .get(&(format, io::ErrorKind::PermissionDenied))
                .map(|examples| examples.join(", "))
                .unwrap_or_default(),
        );
    }
    let own_missing: Vec<&str> = ["stat", "comm", "statm", "sched", "io", "status"]
        .into_iter()
        .filter(|format| !own_round_tripped.contains(format))
        .collect();
    assert!(
        own_missing.is_empty(),
        "this process's own {own_missing:?} did not round-trip (pid {my_pid})"
    );

    // fdinfo of our own processes: accepted files must round-trip
    // byte-exactly. The only tolerated refusals are files whose
    // first kind label names a kind the crate documents as
    // unmodelled (io_uring & friends) — enumerated here, not every
    // UnknownLabel the parser can produce.
    fn unmodelled_first_label(bytes: &[u8]) -> bool {
        const UNMODELLED: &[&[u8]] = &[
            b"SqMask:",      // io_uring
            b"fanotify",     // fanotify marks
            b"userfaultfd:", // userfaultfd
            b"tty-index:",   // tty
            b"perf_event:",  // perf events
        ];
        bytes
            .split(|b| *b == b'\n')
            .skip(4)
            .find(|line| !line.starts_with(b"lock:"))
            .is_some_and(|line| UNMODELLED.iter().any(|label| line.starts_with(label)))
    }
    let mut fdinfo_reads = ReadCounts::default();
    let mut fdinfo_listed = 0usize;
    let mut fdinfo_unmodelled = 0usize;
    let mut fdinfo_races = FdRaceCounts::default();
    let mut fdinfo_bad: Vec<String> = Vec::new();
    // The anchor of the vacuity floor below: fds of modelled kinds
    // this process holds open until the scan ends. Nothing closes
    // them mid-scan, so each must be read and round-trip whatever
    // the rest of the host does.
    let held = open_held_fds();
    let held_fds: BTreeSet<i32> = held
        .iter()
        .map(|fd| {
            use std::os::fd::AsRawFd;
            fd.as_raw_fd()
        })
        .collect();
    let mut held_round_tripped: BTreeSet<i32> = BTreeSet::new();
    for pid in &all_pids {
        let task_uid = fs::metadata(format!("/proc/{pid}")).ok().map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.uid()
        });
        if task_uid != Some(my_uid) {
            continue;
        }
        let task_access = access_facts(
            Path::new(&format!("/proc/{pid}/status")),
            fs::metadata(format!("/proc/{pid}/status"))
                .ok()
                .map(|metadata| {
                    use std::os::unix::fs::MetadataExt;
                    metadata.uid()
                }),
        );
        let task_ptrace_reason = task_access
            .as_ref()
            .and_then(|target| ptrace_denial_reason(&reader_access, target));
        let fdinfo_dir = format!("/proc/{pid}/fdinfo");
        let entries = match fs::read_dir(&fdinfo_dir) {
            Ok(entries) => entries,
            Err(error) if task_exited(&error) => {
                fdinfo_reads.task_exited += 1;
                note_excluded_with_reason(
                    &mut excluded_examples,
                    "fdinfo",
                    Path::new(&fdinfo_dir),
                    error.kind(),
                    Some("task exited"),
                );
                continue;
            }
            Err(error) => {
                let disposition = classify_read_error(
                    error.kind(),
                    verified_gone(Path::new(&format!("/proc/{pid}"))),
                    task_uid,
                    my_uid,
                    true,
                    true,
                    task_ptrace_reason,
                );
                if disposition == ReadDisposition::Excluded {
                    match error.kind() {
                        io::ErrorKind::NotFound => fdinfo_reads.not_found += 1,
                        io::ErrorKind::PermissionDenied => fdinfo_reads.permission_denied += 1,
                        _ => unreachable!("only the two kinds above can be excluded"),
                    }
                    note_excluded_with_reason(
                        &mut excluded_examples,
                        "fdinfo",
                        Path::new(&fdinfo_dir),
                        error.kind(),
                        task_ptrace_reason,
                    );
                } else if fdinfo_bad.len() < 10 {
                    fdinfo_bad.push(format!("{fdinfo_dir}: list failed: {error}"));
                }
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    // A directory-entry error names no fd path to
                    // re-check, so nothing here can verify a
                    // vanished cause; fdinfo also walks only its
                    // reader's own tasks, so PermissionDenied is a
                    // failure too. Both go through the same
                    // classifier with no verified cause.
                    let disposition = classify_read_error(
                        error.kind(),
                        false,
                        task_uid,
                        my_uid,
                        true,
                        false,
                        None,
                    );
                    if disposition == ReadDisposition::Excluded {
                        match error.kind() {
                            io::ErrorKind::NotFound => fdinfo_reads.not_found += 1,
                            io::ErrorKind::PermissionDenied => fdinfo_reads.permission_denied += 1,
                            _ => unreachable!("only the two kinds above can be excluded"),
                        }
                    } else if fdinfo_bad.len() < 10 {
                        fdinfo_bad.push(format!("/proc/{pid}/fdinfo: list failed: {error}"));
                    }
                    continue;
                }
            };
            fdinfo_listed += 1;
            let entry_path = entry.path();
            let held_fd = (*pid == my_pid)
                .then(|| entry.file_name().to_str()?.parse::<i32>().ok())
                .flatten()
                .filter(|fd| held_fds.contains(fd));
            // The fd's identity is what fd/<n> names, read before
            // and, after a NotFound, again after the fdinfo read.
            let fd_link = Path::new(&format!("/proc/{pid}/fd")).join(entry.file_name());
            let before = fd_target(&fd_link);
            let bytes = match classify_fdinfo_read(&before, fs::read(&entry_path), || {
                fd_target(&fd_link)
            }) {
                FdinfoRead::Bytes(bytes) => {
                    fdinfo_reads.attempted += 1;
                    bytes
                }
                FdinfoRead::Raced(race) => {
                    // The fd was closed, or its task gone, at the read
                    // instant: counted, printed, and bounded by the
                    // floors below.
                    match race {
                        FdRace::Closed => fdinfo_races.closed += 1,
                        FdRace::Reused => fdinfo_races.reused += 1,
                        FdRace::ReopenedSameTarget => fdinfo_races.reopened_same_target += 1,
                        FdRace::TaskExited => fdinfo_races.task_exited += 1,
                    }
                    let kind = if race == FdRace::TaskExited {
                        fdinfo_reads.task_exited += 1;
                        fdinfo_reads.listed_task_exited += 1;
                        io::Error::from_raw_os_error(libc::ESRCH).kind()
                    } else {
                        fdinfo_reads.not_found += 1;
                        fdinfo_reads.listed_not_found += 1;
                        io::ErrorKind::NotFound
                    };
                    note_excluded_with_reason(
                        &mut excluded_examples,
                        "fdinfo",
                        &entry_path,
                        kind,
                        Some(&format!("{race:?}")),
                    );
                    continue;
                }
                FdinfoRead::Failed(error) => {
                    // fdinfo walks only its reader's own tasks, so no
                    // other read error is excluded (as before, when
                    // classify_read_error failed every such kind here).
                    if fdinfo_bad.len() < 10 {
                        fdinfo_bad.push(format!("{}: read failed: {error}", entry_path.display()));
                    }
                    continue;
                }
            };
            match parse_fdinfo(&bytes) {
                Ok(parsed) => {
                    if render_fdinfo(&parsed) == bytes {
                        fdinfo_reads.ok += 1;
                        held_round_tripped.extend(held_fd);
                    } else if fdinfo_bad.len() < 10 {
                        fdinfo_bad
                            .push(format!("{:?}: render(parse(bytes)) != bytes", entry.path()));
                    }
                }
                Err(_) if unmodelled_first_label(&bytes) => fdinfo_unmodelled += 1,
                Err(error) => {
                    if fdinfo_bad.len() < 10 {
                        fdinfo_bad.push(format!("{:?}: {error}", entry.path()));
                    }
                }
            }
        }
    }
    assert!(
        fdinfo_bad.is_empty(),
        "modelled fd kinds misparsed (unmodelled tolerated: {fdinfo_unmodelled}; \
         excluded reads without bytes: {fdinfo_races:?}):\n{}",
        fdinfo_bad.join("\n")
    );
    // Same listed-coverage floor as the per-task formats: the
    // listed total is reduced only by verified exclusions (here a
    // NotFound read, which the kernel returns only for a closed fd
    // or a gone task, or an ESRCH for a gone task) and the tolerated
    // unmodelled kinds actually observed.
    let fdinfo_modelled_attempted = fdinfo_reads.attempted - fdinfo_unmodelled;
    let fdinfo_modelled_listed = fdinfo_listed - fdinfo_unmodelled;
    let fdinfo_verified_excluded = fdinfo_reads.listed_not_found
        + fdinfo_reads.listed_permission_denied
        + fdinfo_reads.listed_task_exited;
    eprintln!(
        "live_proc_inventory fdinfo: listed {fdinfo_listed}, attempted {}, \
         modelled attempted {fdinfo_modelled_attempted}, round-tripped {}, \
         excluded not-found {}, permission-denied {}, task exited {}, \
         unmodelled {}; entries read without bytes, by cause: closed {}, \
         reused {}, reopened on the same target {}, task exited {}; held \
         fds round-tripped {} of {}",
        fdinfo_reads.attempted,
        fdinfo_reads.ok,
        fdinfo_reads.not_found,
        fdinfo_reads.permission_denied,
        fdinfo_reads.task_exited,
        fdinfo_unmodelled,
        fdinfo_races.closed,
        fdinfo_races.reused,
        fdinfo_races.reopened_same_target,
        fdinfo_races.task_exited,
        held_round_tripped.len(),
        held_fds.len(),
    );
    for ((_, kind), examples) in excluded_examples
        .iter()
        .filter(|((format, _), _)| *format == "fdinfo")
    {
        eprintln!(
            "live_proc_inventory excluded fdinfo {kind:?} examples: {}",
            examples.join(", ")
        );
    }
    assert!(
        inventory_floor_met(
            fdinfo_modelled_listed,
            fdinfo_verified_excluded,
            fdinfo_modelled_attempted,
            fdinfo_reads.ok,
        ),
        "fdinfo inventory too thin: {} round-tripped of {fdinfo_modelled_attempted} \
         modelled attempted ({fdinfo_modelled_listed} modelled listed, \
         {fdinfo_listed} listed, {} verified-not-found, {} verified \
         permission-denied, {} task-exited, {fdinfo_unmodelled} unmodelled \
         tolerated; floor {} with absolute minimum {MIN_ATTEMPTED_PER_FORMAT}; \
         excluded examples: not-found [{}], permission-denied [{}])",
        fdinfo_reads.ok,
        fdinfo_reads.listed_not_found,
        fdinfo_reads.listed_permission_denied,
        fdinfo_reads.listed_task_exited,
        scaled_floor(fdinfo_modelled_listed.saturating_sub(fdinfo_verified_excluded)),
        excluded_examples
            .get(&("fdinfo", io::ErrorKind::NotFound))
            .map(|examples| examples.join(", "))
            .unwrap_or_default(),
        excluded_examples
            .get(&("fdinfo", io::ErrorKind::PermissionDenied))
            .map(|examples| examples.join(", "))
            .unwrap_or_default(),
    );
    // The vacuity floor for the exclusions of reads without bytes,
    // which shrinks neither with them nor with the host: every held
    // fd must have round-tripped (none can have raced a close, and
    // this task cannot have exited), and at least
    // MIN_ATTEMPTED_PER_FORMAT other entries must have as well.
    let held_missing: Vec<i32> = held_fds.difference(&held_round_tripped).copied().collect();
    assert!(
        held_missing.is_empty(),
        "fdinfo of held fds {held_missing:?} (of {held_fds:?}) did not round-trip \
         (excluded reads without bytes: {fdinfo_races:?})"
    );
    let fdinfo_floor = held_fds.len() + MIN_ATTEMPTED_PER_FORMAT;
    assert!(
        fdinfo_reads.ok >= fdinfo_floor,
        "fdinfo inventory vacuous: {} round-tripped, floor {fdinfo_floor} ({} held \
         fds plus {MIN_ATTEMPTED_PER_FORMAT} others; excluded reads without \
         bytes: {fdinfo_races:?})",
        fdinfo_reads.ok,
        held_fds.len(),
    );
    drop(held);
}

fn stored_comm(name: &[u8]) -> Vec<u8> {
    let end = name
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name.len())
        .min(TASK_COMM_MAX);
    name[..end].to_vec()
}

fn escaped_name(stored: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in stored {
        match byte {
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            other => out.push(*other),
        }
    }
    out
}

#[test]
fn pr_set_name_population() {
    let _serial = oracle_serial();
    let names: &[&[u8]] = &[
        b"a b",
        b"a)b",
        b"a(b",
        b"a\\b",
        b"a\nb",
        b"ab ",
        b")",
        b"(",
        b"x) y",
        b"\xff\xfez",
        b"123456789012345",      // exactly at the limit
        b"12345678901234567890", // truncated to 15 by the kernel
        b"",
    ];
    for name in names {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel::<i64>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let mut kernel_name = name.to_vec();
        kernel_name.push(0);
        let thread = std::thread::spawn(move || {
            // SAFETY: prctl(PR_SET_NAME) reads a NUL-terminated name
            // of at most 16 bytes from the pointer, which outlives
            // the call.
            unsafe {
                libc::prctl(
                    libc::PR_SET_NAME,
                    kernel_name.as_ptr() as libc::c_ulong,
                    0,
                    0,
                    0,
                );
            }
            // SAFETY: gettid takes no arguments.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            tid_tx.send(tid).unwrap();
            go_rx.recv().unwrap();
        });
        let tid = tid_rx.recv().unwrap();
        let base = format!("/proc/self/task/{tid}");
        let expected = stored_comm(name);

        let comm_bytes = fs::read(format!("{base}/comm")).expect("read comm");
        assert_eq!(
            parse_comm_file(&comm_bytes).unwrap(),
            expected,
            "comm file for name {name:?}"
        );

        let stat_bytes = fs::read(format!("{base}/stat")).expect("read stat");
        let stat = parse_stat(&stat_bytes)
            .unwrap_or_else(|e| panic!("stat refused for name {name:?}: {e}"));
        assert_eq!(stat.comm, expected, "stat comm for name {name:?}");
        assert_eq!(render_stat(&stat), stat_bytes);

        let status_bytes = fs::read(format!("{base}/status")).expect("read status");
        let status = parse_status(&status_bytes)
            .unwrap_or_else(|e| panic!("status refused for name {name:?}: {e}"));
        assert_eq!(
            status.get(StatusLabel::Name),
            Some(&StatusValue::Name(escaped_name(&expected))),
            "status Name for name {name:?}"
        );
        assert_eq!(render_status(&status), status_bytes);

        let sched_bytes = fs::read(format!("{base}/sched")).expect("read sched");
        let sched = parse_sched(&sched_bytes)
            .unwrap_or_else(|e| panic!("sched refused for name {name:?}: {e}"));
        assert_eq!(sched.comm, expected, "sched comm for name {name:?}");
        assert_eq!(render_sched(&sched), sched_bytes);

        go_tx.send(()).unwrap();
        thread.join().unwrap();
    }
}

fn live_fdinfo(fd: i32) -> Fdinfo {
    let bytes = fs::read(format!("/proc/self/fdinfo/{fd}"))
        .unwrap_or_else(|e| panic!("read fdinfo for fd {fd}: {e}"));
    let parsed = parse_fdinfo(&bytes).unwrap_or_else(|e| {
        panic!(
            "fdinfo refused for fd {fd}: {e}\n{}",
            String::from_utf8_lossy(&bytes)
        )
    });
    assert_eq!(
        render_fdinfo(&parsed),
        bytes,
        "fdinfo round-trip for fd {fd}"
    );
    parsed
}

#[test]
fn fdinfo_kinds_from_live_objects() {
    let _serial = oracle_serial();
    // SAFETY: each block creates one kernel object with the documented
    // arguments and closes it after the fdinfo read; fds are checked
    // before use.
    unsafe {
        let efd = libc::eventfd(5, 0);
        assert!(efd >= 0);
        assert!(matches!(live_fdinfo(efd).kind, FdinfoKind::Eventfd { .. }));
        libc::close(efd);

        let tfd = libc::timerfd_create(libc::CLOCK_MONOTONIC, 0);
        assert!(tfd >= 0);
        assert!(matches!(live_fdinfo(tfd).kind, FdinfoKind::Timerfd(_)));
        libc::close(tfd);

        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut set), 0);
        assert_eq!(libc::sigaddset(&mut set, libc::SIGUSR1), 0);
        let sfd = libc::signalfd(-1, &set, 0);
        assert!(sfd >= 0, "signalfd: {}", std::io::Error::last_os_error());
        match live_fdinfo(sfd).kind {
            FdinfoKind::Signalfd { sigmask } => {
                assert_eq!(
                    sigmask & (1 << (libc::SIGUSR1 - 1)),
                    1 << (libc::SIGUSR1 - 1)
                );
            }
            other => panic!("signalfd kind: {other:?}"),
        }
        libc::close(sfd);

        let pfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32;
        assert!(pfd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
        assert!(matches!(live_fdinfo(pfd).kind, FdinfoKind::Pidfd { .. }));
        libc::close(pfd);

        let epoll = libc::epoll_create1(0);
        assert!(epoll >= 0);
        let mut pipefd = [0i32; 2];
        assert_eq!(libc::pipe2(pipefd.as_mut_ptr(), 0), 0);
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0x1234,
        };
        assert_eq!(
            libc::epoll_ctl(epoll, libc::EPOLL_CTL_ADD, pipefd[0], &mut event),
            0
        );
        match live_fdinfo(epoll).kind {
            FdinfoKind::Epoll(targets) => assert_eq!(targets.len(), 1),
            other => panic!("epoll kind: {other:?}"),
        }
        libc::close(epoll);
        libc::close(pipefd[0]);
        libc::close(pipefd[1]);

        let ifd = libc::inotify_init1(0);
        assert!(ifd >= 0);
        let tmp = c"/tmp";
        assert!(libc::inotify_add_watch(ifd, tmp.as_ptr(), libc::IN_ALL_EVENTS) >= 0);
        match live_fdinfo(ifd).kind {
            FdinfoKind::Inotify(watches) => assert_eq!(watches.len(), 1),
            other => panic!("inotify kind: {other:?}"),
        }
        libc::close(ifd);

        let name = c"proc-grammar-test";
        let mfd = libc::memfd_create(name.as_ptr(), 0);
        assert!(mfd >= 0);
        assert!(matches!(live_fdinfo(mfd).kind, FdinfoKind::Plain));
        libc::close(mfd);
    }

    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    use std::os::fd::AsRawFd;
    assert!(matches!(
        live_fdinfo(a.as_raw_fd()).kind,
        FdinfoKind::UnixSocket { .. }
    ));
}

/// The race `live_proc_inventory` meets on a busy host, driven with
/// this process's own fds: `fdinfo/<n>` is opened while fd `n` is
/// live and `n` is closed before the read, so the kernel's
/// `seq_show` finds no file and the read returns `NotFound`. Only
/// `fd/<n>` tells what happened next (still closed, reused by
/// another file, or reopened on the same one): the `fdinfo/<n>`
/// entry's procfs inode stays valid through a reuse.
#[test]
fn fdinfo_read_racing_a_close_is_counted_not_misparsed() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    let _serial = oracle_serial();
    let memfd = |name: &std::ffi::CStr| {
        // SAFETY: memfd_create reads a NUL-terminated name; the
        // result is checked before it is owned.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create: {}", io::Error::last_os_error());
        // SAFETY: the kernel just returned this fd and nothing else
        // owns it.
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let a = memfd(c"proc-grammar-race-a");
    let b = memfd(c"proc-grammar-race-b");

    // Parks a duplicate of `a` on a number at or above 512, which a
    // lowest-free allocation elsewhere in this process does not take
    // while it is closed, and opens its fdinfo while it is live.
    // Then closes it before the read when `close_first`, and puts
    // `reopen_with` on the number before the second look at fd/<n>.
    let race = |close_first: bool, reopen_with: Option<&OwnedFd>| {
        // SAFETY: F_DUPFD_CLOEXEC duplicates a valid fd; checked below.
        let n = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 512) };
        assert!(n >= 512, "F_DUPFD_CLOEXEC: {}", io::Error::last_os_error());
        let link = PathBuf::from(format!("/proc/self/fd/{n}"));
        let before = fd_target(&link);
        assert!(
            matches!(before, FdTarget::Named(_)),
            "fd {n} before: {before:?}"
        );
        let mut fdinfo = fs::File::open(format!("/proc/self/fdinfo/{n}"))
            .unwrap_or_else(|e| panic!("open fdinfo of live fd {n}: {e}"));
        if close_first {
            // SAFETY: n was parked above and nothing else uses it.
            assert_eq!(unsafe { libc::close(n) }, 0);
        }
        let mut bytes = Vec::new();
        let read = fdinfo.read_to_end(&mut bytes).map(|_| bytes);
        if let Some(file) = reopen_with {
            // SAFETY: dup3 puts a valid fd on the parked number,
            // which was closed above.
            let reopened = unsafe { libc::dup3(file.as_raw_fd(), n, libc::O_CLOEXEC) };
            assert_eq!(reopened, n, "dup3: {}", io::Error::last_os_error());
        }
        let outcome = classify_fdinfo_read(&before, read, || fd_target(&link));
        if !close_first || reopen_with.is_some() {
            // SAFETY: n holds the parked or reopened fd, owned here.
            assert_eq!(unsafe { libc::close(n) }, 0);
        }
        outcome
    };

    // Held across the read: the kernel's bytes are parsed.
    match race(false, None) {
        FdinfoRead::Bytes(bytes) => {
            let parsed = parse_fdinfo(&bytes).expect("held memfd fdinfo parses");
            assert_eq!(render_fdinfo(&parsed), bytes);
            assert!(matches!(parsed.kind, FdinfoKind::Plain));
        }
        other => panic!("held fd: {other:?}"),
    }
    // Closed at the read and still closed.
    let closed = race(true, None);
    assert!(
        matches!(closed, FdinfoRead::Raced(FdRace::Closed)),
        "closed: {closed:?}"
    );
    // Closed at the read, then the number reused by another file.
    let reused = race(true, Some(&b));
    assert!(
        matches!(reused, FdinfoRead::Raced(FdRace::Reused)),
        "reused: {reused:?}"
    );
    // Closed at the read, then reopened on the same file.
    let reopened = race(true, Some(&a));
    assert!(
        matches!(reopened, FdinfoRead::Raced(FdRace::ReopenedSameTarget)),
        "reopened: {reopened:?}"
    );
}

/// The other race `live_proc_inventory` meets: a task that exits and
/// is reaped between the open and the read, driven with a forked
/// child. A per-task file opened while the child lived reads `ESRCH`
/// once it is reaped (`proc_single_show`), and so does opening an
/// entry through its fdinfo directory, opened while it lived
/// (`proc_fdinfo_permission`). Both are counted as exited tasks; any
/// other read error still fails.
#[test]
fn read_of_an_exited_task_is_counted_not_misparsed() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    let _serial = oracle_serial();
    let my_uid = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata("/proc/self").expect("stat /proc/self").uid()
    };
    let mut pipefd = [0i32; 2];
    // SAFETY: pipe2 writes two new fds into the array; checked.
    assert_eq!(unsafe { libc::pipe2(pipefd.as_mut_ptr(), 0) }, 0);
    // SAFETY: the kernel just returned both fds and nothing else owns
    // them.
    let (read_end, write_end) = unsafe {
        (
            OwnedFd::from_raw_fd(pipefd[0]),
            OwnedFd::from_raw_fd(pipefd[1]),
        )
    };
    // SAFETY: the child calls only close(2), read(2) and _exit(2),
    // which are async-signal-safe, so forking this threaded process
    // is sound.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork: {}", io::Error::last_os_error());
    if child == 0 {
        let mut byte = 0u8;
        // SAFETY: as above; the child waits for the parent to close
        // the write end, then exits without unwinding.
        unsafe {
            libc::close(write_end.as_raw_fd());
            libc::read(read_end.as_raw_fd(), (&raw mut byte).cast(), 1);
            libc::_exit(0);
        }
    }
    drop(read_end);
    let base = format!("/proc/{child}");
    let stat_path = format!("{base}/stat");
    let mut stat = fs::File::open(&stat_path).expect("open a live child's stat");
    let fdinfo_dir = fs::File::open(format!("{base}/fdinfo")).expect("open a live child's fdinfo");
    // Let the child exit, and reap it.
    drop(write_end);
    let mut wait_status = 0;
    // SAFETY: waitpid on this process's own child.
    assert_eq!(unsafe { libc::waitpid(child, &mut wait_status, 0) }, child);

    // A per-task read of the reaped child: ESRCH, counted.
    let mut bytes = Vec::new();
    let read = stat.read_to_end(&mut bytes).map(|_| bytes);
    assert!(
        read.as_ref().is_err_and(task_exited),
        "stat of a reaped task: {read:?}"
    );
    let mut counts = ReadCounts::default();
    let mut examples = BTreeMap::new();
    let mut failures = Vec::new();
    let outcome = read_inventory_file(
        Path::new(&stat_path),
        read,
        || verified_gone(Path::new(&base)),
        Some(my_uid),
        my_uid,
        false,
        None,
        "stat",
        &mut counts,
        &mut examples,
        &mut failures,
    );
    assert_eq!(outcome, None);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
        (
            counts.attempted,
            counts.task_exited,
            counts.listed_task_exited
        ),
        (0, 1, 1)
    );
    // Any other read error of the same file still fails.
    let outcome = read_inventory_file(
        Path::new(&stat_path),
        Err(io::Error::from_raw_os_error(libc::EIO)),
        || verified_gone(Path::new(&base)),
        Some(my_uid),
        my_uid,
        false,
        None,
        "stat",
        &mut counts,
        &mut examples,
        &mut failures,
    );
    assert_eq!(outcome, None);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(counts.task_exited, 1);

    // An fdinfo entry of the reaped child: its open fails ESRCH, an
    // exited task.
    // SAFETY: openat takes a valid directory fd and a NUL-terminated
    // name; a returned fd is closed at once.
    let fd = unsafe {
        libc::openat(
            fdinfo_dir.as_raw_fd(),
            c"0".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: fd was just returned and is owned here.
        unsafe { libc::close(fd) };
        panic!("opened fdinfo/0 of a reaped task");
    }
    let open_error = io::Error::last_os_error();
    assert!(task_exited(&open_error), "fdinfo/0 open: {open_error:?}");
    let outcome = classify_fdinfo_read(&FdTarget::Absent, Err(open_error), || {
        unreachable!("ESRCH needs no second look at fd/<n>")
    });
    assert!(
        matches!(outcome, FdinfoRead::Raced(FdRace::TaskExited)),
        "{outcome:?}"
    );
}
