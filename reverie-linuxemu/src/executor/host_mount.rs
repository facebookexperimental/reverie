/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What the host kernel says about the mount a host descriptor's file is on:
//! the device number of the mount's superblock ([`superblock_device`]), and
//! that and whether the superblock is read-only, as they are now
//! ([`superblock`]).
//!
//! Linux 6.8 and later answer for one mount: `statmount(2)` with
//! `STATMOUNT_SB_BASIC`, given the mount's unique id (`statx(2)`'s
//! `STATX_MNT_ID_UNIQUE`). The answer otherwise is the mount's line in the
//! calling thread's `mountinfo`, and a read of that file formats every mount
//! of the namespace (hundreds on a busy host, with a subvolume path lookup
//! for each btrfs line) and waits behind any mount or unmount there. A
//! mount's superblock device never changes, so where `statmount` is missing
//! or refused, [`MountTable`] keeps each listed mount's device as one read
//! of the file gave it, and reads the file again only after Linux reports a
//! change to the namespace's mounts. A superblock's read-only flag can
//! change with no such report, so that answer reads the file as it is now.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;
use std::sync::PoisonError;

/// The superblock facts of one mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Superblock {
    /// The superblock's device number (`s_dev`), which `maps` and
    /// `mountinfo` print, and which need not be a file's `st_dev` (btrfs
    /// gives each subvolume one of its own).
    pub(crate) device: u64,
    /// Whether the superblock is read-only (`SB_RDONLY`): the file system
    /// itself, not only one mount of it.
    pub(crate) read_only: bool,
}

/// The id `statx(2)` gives for the mount a descriptor's file is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountId {
    /// `STATX_MNT_ID_UNIQUE` (Linux 6.8 and later): an id Linux never gives
    /// a second mount, which `statmount(2)` takes.
    Unique(u64),
    /// `STATX_MNT_ID`: the id `mountinfo` lists, which Linux reuses once the
    /// mount is gone. A kernel before 6.8 gives only this one.
    Listed(u64),
}

/// The id of the mount host descriptor `fd`'s file is on: the unique id
/// where the host kernel gives one, else the listed one.
pub(crate) fn mount_id(fd: libc::c_int) -> std::io::Result<MountId> {
    #[cfg(test)]
    if NO_UNIQUE_MOUNT_ID_TEST_HOOK.with(std::cell::Cell::get) {
        return listed_mount_id(fd).map(MountId::Listed);
    }
    // A kernel before 6.8 does not know STATX_MNT_ID_UNIQUE and answers the
    // listed id, saying so in the mask.
    let status = statx(fd, libc::STATX_MNT_ID_UNIQUE)?;
    if status.stx_mask & libc::STATX_MNT_ID_UNIQUE != 0 {
        Ok(MountId::Unique(status.stx_mnt_id))
    } else if status.stx_mask & libc::STATX_MNT_ID != 0 {
        Ok(MountId::Listed(status.stx_mnt_id))
    } else {
        Err(no_mount_id())
    }
}

/// The superblock of the mount host descriptor `fd`'s file is on, as it is
/// now; `Ok(None)` where that mount is in no namespace this thread sees (an
/// internal mount, such as a memfd's), whose files' `st_dev` is the
/// superblock's.
///
/// Without `statmount(2)`, this reads the calling thread's `mountinfo`
/// whole. No kept [`MountTable`] can answer: a superblock's read-only flag
/// changes with no change to any mount of this namespace where the file
/// system is remounted through a mount in another namespace (`do_remount`
/// reports the change to that mount's namespace only) or reconfigured
/// through `fsconfig(2)` (`vfs_cmd_reconfigure` reports it to none).
pub(crate) fn superblock(fd: libc::c_int) -> std::io::Result<Option<Superblock>> {
    let mount = mount_id(fd)?;
    // Where statmount(2) is missing (ENOSYS, also from a seccomp policy that
    // predates it) or refused, the line in mountinfo answers.
    if let MountId::Unique(id) = mount
        && let Ok(found) = statmount_superblock(id)
    {
        return Ok(found);
    }
    let listed = listed_id(fd, mount)?;
    let (_, rows) = read_mountinfo()?;
    Ok(rows
        .iter()
        .find(|row| row.raw_mount_id == listed)
        .map(|row| Superblock {
            device: row.raw_device,
            // Linux writes "ro" or "rw" first, from the superblock's
            // read-only flag (show_mountinfo).
            read_only: row.super_options.split(|byte| *byte == b',').next()
                == Some(b"ro".as_slice()),
        }))
}

/// The device of the superblock of the mount [`mount_id`] gave as `mount`
/// for host descriptor `fd`; `Ok(None)` where that mount is in no namespace
/// this thread sees. A mount's superblock and that superblock's device
/// never change, so without `statmount(2)` the kept [`MountTable`] answers.
pub(crate) fn superblock_device(fd: libc::c_int, mount: MountId) -> std::io::Result<Option<u64>> {
    if let MountId::Unique(id) = mount
        && let Ok(found) = statmount_superblock(id)
    {
        return Ok(found.map(|superblock| superblock.device));
    }
    MountTable::device(listed_id(fd, mount)?)
}

/// The id `mountinfo` lists for `mount`, the mount of host descriptor
/// `fd`'s file.
fn listed_id(fd: libc::c_int, mount: MountId) -> std::io::Result<u64> {
    match mount {
        MountId::Listed(id) => Ok(id),
        MountId::Unique(_) => listed_mount_id(fd),
    }
}

/// `statmount(2)`'s number, the same on every architecture Reverie builds
/// for (Linux 6.8; the libc crate names it for none of them).
const SYS_STATMOUNT: libc::c_long = 457;
/// `STATMOUNT_SB_BASIC`: the superblock's device, magic and flags.
const STATMOUNT_SB_BASIC: u64 = 0x1;
/// The first published size of `struct mnt_id_req`, which takes a mount
/// and the request mask.
const MNT_ID_REQ_SIZE_VER0: u32 = 24;
/// `SB_RDONLY` in `statmount`'s `sb_flags`.
const SB_RDONLY: u32 = 0x1;

/// `struct mnt_id_req` as first published (`MNT_ID_REQ_SIZE_VER0`).
#[repr(C)]
struct MountIdRequest {
    size: u32,
    spare: u32,
    mount: u64,
    mask: u64,
}

/// The fixed part of `struct statmount` this module reads; the kernel
/// writes no more of it than the buffer it is given holds.
#[repr(C)]
#[derive(Default)]
struct Statmount {
    size: u32,
    mount_options: u32,
    mask: u64,
    device_major: u32,
    device_minor: u32,
    magic: u64,
    flags: u32,
    filesystem_type: u32,
}

/// [`superblock`] by `statmount(2)`, for the mount with unique id `id`:
/// `Ok(None)` where no mount in this thread's namespace has it (`ENOENT`).
fn statmount_superblock(id: u64) -> std::io::Result<Option<Superblock>> {
    #[cfg(test)]
    if NO_STATMOUNT_TEST_HOOK.with(std::cell::Cell::get) {
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    #[cfg(test)]
    STATMOUNT_CALLS.with(|calls| calls.set(calls.get() + 1));
    let request = MountIdRequest {
        size: MNT_ID_REQ_SIZE_VER0,
        spare: 0,
        mount: id,
        mask: STATMOUNT_SB_BASIC,
    };
    let mut status = Statmount::default();
    // SAFETY: statmount(2) reads one request and writes at most the given
    // size into status, which is live and writable.
    let result = unsafe {
        libc::syscall(
            SYS_STATMOUNT,
            &request as *const MountIdRequest,
            &mut status as *mut Statmount,
            std::mem::size_of::<Statmount>(),
            0,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            _ => Err(error),
        };
    }
    if status.mask & STATMOUNT_SB_BASIC == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "statmount reported no superblock (STATMOUNT_SB_BASIC)",
        ));
    }
    Ok(Some(Superblock {
        device: libc::makedev(status.device_major, status.device_minor),
        read_only: status.flags & SB_RDONLY != 0,
    }))
}

/// The id `mountinfo` lists for the mount host descriptor `fd`'s file is
/// on (`STATX_MNT_ID`, Linux 5.8 and later).
fn listed_mount_id(fd: libc::c_int) -> std::io::Result<u64> {
    let status = statx(fd, libc::STATX_MNT_ID)?;
    if status.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(no_mount_id());
    }
    Ok(status.stx_mnt_id)
}

fn no_mount_id() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "statx reports no mount ID (STATX_MNT_ID)",
    )
}

/// `statx(2)` of host descriptor `fd` itself, asking for `mask`.
fn statx(fd: libc::c_int, mask: u32) -> std::io::Result<libc::statx> {
    let mut status = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: statx of the descriptor itself writes at most one statx, read
    // only on success; the path is NUL-terminated.
    if unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            mask,
            status.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: statx succeeded.
    Ok(unsafe { status.assume_init() })
}

/// The calling thread's `mountinfo` as it is now, with the descriptor it
/// was read through.
fn read_mountinfo() -> std::io::Result<(File, Vec<reverie_procfs::MountInfoRow>)> {
    #[cfg(test)]
    MOUNTINFO_READS.with(|reads| reads.set(reads.get() + 1));
    let mut file = File::open("/proc/thread-self/mountinfo")?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let rows = reverie_procfs::parse_mountinfo(&contents).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "/proc/thread-self/mountinfo has a line that does not parse or lists a mount twice",
        )
    })?;
    Ok((file, rows))
}

/// The superblock device of each mount the calling thread's `mountinfo`
/// lists, kept with the descriptor that file was read through, for the
/// mounts `statmount(2)` cannot answer for.
///
/// Linux counts the changes to a mount namespace's mounts: every mount,
/// unmount, move and propagation, and every change of a mount's flags
/// (`ns->event`, which `commit_tree`, `umount_tree`, `set_mount_attributes`,
/// `mount_setattr_commit` and `path_pivot_root` in `fs/namespace.c`
/// advance). `poll(2)` on an open `mountinfo` reports `POLLPRI` once the
/// count has moved since that descriptor last looked (`mounts_poll` in
/// `fs/proc_namespace.c`). A mount's superblock never changes, and the id
/// `mountinfo` lists for a mount goes to another only after the first has
/// left every namespace. So while the kept descriptor reports no `POLLPRI`
/// and the thread is still in the namespace the table was read in, each
/// listed id still names the mount, and the device, that the table holds.
///
/// The table keeps nothing else from the file. Linux prints a mount point,
/// a mount's root and a btrfs mount's `subvol=` from the current names of
/// directories and subvolumes, which a rename changes, and a superblock's
/// options from the superblock, which a remount through a mount in another
/// namespace or a reconfiguration through `fsconfig(2)` changes. None of
/// these changes a mount of this namespace, so no `POLLPRI` would tell that
/// a kept copy is stale. A caller that needs any of them reads `mountinfo`
/// as it is now, as [`superblock`] does.
pub(crate) struct MountTable {
    /// The descriptor the table was read through, kept open for its poll.
    file: File,
    /// The inode of the mount namespace the table was read in.
    namespace: u64,
    /// Each listed mount's superblock device, by the id `mountinfo` lists.
    devices: BTreeMap<u64, u64>,
}

/// The kept table, read on first use.
static MOUNT_TABLE: Mutex<Option<MountTable>> = Mutex::new(None);

impl MountTable {
    /// The superblock device of the mount the calling thread's `mountinfo`
    /// lists as `listed` (`STATX_MNT_ID`), from the kept table; `Ok(None)`
    /// where no line has that id.
    fn device(listed: u64) -> std::io::Result<Option<u64>> {
        let mut table = MOUNT_TABLE.lock().unwrap_or_else(PoisonError::into_inner);
        let current = match table.take() {
            Some(kept) if !kept.stale()? => kept,
            _ => Self::read()?,
        };
        let found = current.devices.get(&listed).copied();
        *table = Some(current);
        Ok(found)
    }

    /// A new table, read through a descriptor kept for later polls.
    fn read() -> std::io::Result<Self> {
        // The namespace is read first: a change of namespace between the two
        // leaves the table keyed to a namespace it does not show, and the
        // next use reads again.
        let namespace = current_namespace()?;
        // The descriptor's poll starts from the namespace's count at open, so
        // a change while the file is read is reported at the next use.
        let (file, rows) = read_mountinfo()?;
        let devices = rows
            .iter()
            .map(|row| (row.raw_mount_id, row.raw_device))
            .collect();
        Ok(Self {
            file,
            namespace,
            devices,
        })
    }

    /// Whether the table may no longer hold the calling thread's mounts:
    /// the thread is in another mount namespace, or Linux reports a change
    /// to the namespace's mounts since the table's descriptor last looked.
    fn stale(&self) -> std::io::Result<bool> {
        if current_namespace()? != self.namespace {
            return Ok(true);
        }
        let mut poll = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: poll reads and writes one live pollfd and does not block
        // (a zero timeout).
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(poll.revents & (libc::POLLPRI | libc::POLLERR) != 0)
    }
}

/// The inode of the calling thread's mount namespace.
fn current_namespace() -> std::io::Result<u64> {
    Ok(std::fs::metadata("/proc/thread-self/ns/mnt")?.ino())
}

#[cfg(test)]
thread_local! {
    /// The times this thread has read `mountinfo` whole
    /// (`read_mountinfo`).
    pub(crate) static MOUNTINFO_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// While set, makes this thread's `mount_id` give the listed id, as on a
    /// kernel before 6.8.
    pub(crate) static NO_UNIQUE_MOUNT_ID_TEST_HOOK: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// While set, makes this thread's `statmount` calls fail with `ENOSYS`,
    /// as a seccomp policy that predates it would.
    pub(crate) static NO_STATMOUNT_TEST_HOOK: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// The times this thread has called `statmount(2)`.
    pub(crate) static STATMOUNT_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    /// An open file of this test's own in `directory`, already unlinked.
    fn scratch_file_in(directory: &std::path::Path, name: &str) -> std::io::Result<File> {
        let path = directory.join(format!("reverie-host-mount-{name}-{}", std::process::id()));
        std::fs::write(&path, b"x")?;
        let file = File::open(&path);
        std::fs::remove_file(&path)?;
        file
    }

    /// `fd`'s superblock with `statmount(2)` kept out of the answer, so
    /// that a read of `mountinfo` as it is now answers.
    fn from_mountinfo(fd: libc::c_int) -> Option<Superblock> {
        NO_STATMOUNT_TEST_HOOK.with(|hook| hook.set(true));
        let found = superblock(fd);
        NO_STATMOUNT_TEST_HOOK.with(|hook| hook.set(false));
        found.unwrap()
    }

    /// `fd`'s superblock device with `statmount(2)` kept out of the
    /// answer, so that the kept table answers.
    fn device_from_table(fd: libc::c_int) -> Option<u64> {
        NO_STATMOUNT_TEST_HOOK.with(|hook| hook.set(true));
        let found = mount_id(fd).and_then(|mount| superblock_device(fd, mount));
        NO_STATMOUNT_TEST_HOOK.with(|hook| hook.set(false));
        found.unwrap()
    }

    /// A memfd, whose file is on an internal mount no namespace lists.
    fn memfd() -> File {
        // SAFETY: the name is NUL-terminated; the descriptor is owned here.
        let fd = unsafe { libc::memfd_create(c"reverie-host-mount".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        // SAFETY: fd is a new descriptor of our own.
        unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) }
    }

    /// `statmount(2)`, the mount's line in `mountinfo` as it is now and the
    /// kept table give the same superblock device, and the first two the
    /// same read-only flag, for files on several mounts: the temporary
    /// directory's, procfs, `/dev/shm` where a file can be made there, and
    /// `/sys` (often read-only in a container). A memfd's mount is in no
    /// namespace, and every answer is `None` for it.
    #[test]
    fn statmount_and_mountinfo_give_the_same_superblock() {
        let mut files = vec![
            scratch_file_in(&std::env::temp_dir(), "agree").unwrap(),
            File::open("/proc/self/status").unwrap(),
        ];
        if let Ok(shm) = scratch_file_in(std::path::Path::new("/dev/shm"), "agree") {
            files.push(shm);
        }
        if let Ok(sys) = File::open("/sys/kernel/mm/transparent_hugepage/enabled") {
            files.push(sys);
        }
        for file in &files {
            let fd = file.as_raw_fd();
            let expected = from_mountinfo(fd);
            assert!(expected.is_some(), "a listed mount: {file:?}");
            assert_eq!(superblock(fd).unwrap(), expected, "{file:?}");
            let device = expected.map(|superblock| superblock.device);
            let mount = mount_id(fd).unwrap();
            assert_eq!(superblock_device(fd, mount).unwrap(), device, "{file:?}");
            assert_eq!(device_from_table(fd), device, "{file:?}");
        }
        let memfd = memfd();
        let fd = memfd.as_raw_fd();
        assert_eq!(from_mountinfo(fd), None);
        assert_eq!(superblock(fd).unwrap(), None);
        assert_eq!(superblock_device(fd, mount_id(fd).unwrap()).unwrap(), None);
        assert_eq!(device_from_table(fd), None);
    }

    /// Where the kernel names mounts uniquely, neither answer reads
    /// `mountinfo`: one `statmount(2)` per question.
    #[test]
    fn statmount_answers_without_reading_mountinfo() {
        let file = scratch_file_in(&std::env::temp_dir(), "statmount").unwrap();
        let fd = file.as_raw_fd();
        let Ok(mount @ MountId::Unique(_)) = mount_id(fd) else {
            eprintln!("skipped: this kernel names no mount uniquely (before Linux 6.8)");
            return;
        };
        let reads = MOUNTINFO_READS.with(std::cell::Cell::get);
        let calls = STATMOUNT_CALLS.with(std::cell::Cell::get);
        assert!(superblock(fd).unwrap().is_some());
        assert!(superblock_device(fd, mount).unwrap().is_some());
        assert_eq!(MOUNTINFO_READS.with(std::cell::Cell::get), reads);
        assert_eq!(STATMOUNT_CALLS.with(std::cell::Cell::get), calls + 2);
    }

    /// Without `statmount(2)`, each question about a superblock's
    /// read-only flag reads `mountinfo` as it is now and none is answered
    /// from the kept table: the flag changes with no mount event in this
    /// namespace where the file system is remounted through another
    /// namespace's mount or reconfigured through `fsconfig(2)`.
    #[test]
    fn without_statmount_the_read_only_flag_is_read_as_it_is_now() {
        let file = scratch_file_in(&std::env::temp_dir(), "flag").unwrap();
        let reads = MOUNTINFO_READS.with(std::cell::Cell::get);
        assert!(from_mountinfo(file.as_raw_fd()).is_some());
        assert!(from_mountinfo(file.as_raw_fd()).is_some());
        assert_eq!(MOUNTINFO_READS.with(std::cell::Cell::get), reads + 2);
    }

    /// The kept table is read again only after a mount event: a second
    /// question asked while a descriptor of our own reports no change to
    /// the namespace's mounts reads nothing. Another process can mount or
    /// unmount at any time, so an attempt whose witness saw a change proves
    /// nothing and is tried again.
    #[test]
    fn a_kept_table_is_read_again_only_after_a_mount_event() {
        let file = scratch_file_in(&std::env::temp_dir(), "kept").unwrap();
        for _ in 0..20 {
            let witness = MountTable::read().unwrap();
            assert!(device_from_table(file.as_raw_fd()).is_some());
            let reads = MOUNTINFO_READS.with(std::cell::Cell::get);
            assert!(device_from_table(file.as_raw_fd()).is_some());
            let read_again = MOUNTINFO_READS.with(std::cell::Cell::get) > reads;
            if witness.stale().unwrap() {
                continue;
            }
            assert!(!read_again, "no mount event, yet the table was read again");
            return;
        }
        panic!("every attempt saw a mount event; nothing was shown");
    }

    /// `fspick(2)` and `fsconfig(2)`, the same on every architecture Reverie
    /// builds for (Linux 5.2), with the `fsconfig` commands and the `fspick`
    /// flag this module's tests use (`include/uapi/linux/mount.h`).
    const SYS_FSCONFIG: libc::c_long = 431;
    const SYS_FSPICK: libc::c_long = 433;
    const FSCONFIG_SET_FLAG: libc::c_uint = 0;
    const FSCONFIG_CMD_RECONFIGURE: libc::c_uint = 7;
    const FSPICK_CLOEXEC: libc::c_uint = 0x1;

    /// Between fork and exec: a new user namespace that maps the caller to
    /// root, and a new mount namespace, in which the test can mount.
    struct OwnMountNamespace {
        uid_map: Vec<u8>,
        gid_map: Vec<u8>,
    }

    impl OwnMountNamespace {
        fn write(path: &std::ffi::CStr, bytes: &[u8]) -> std::io::Result<()> {
            // SAFETY: path is NUL-terminated and bytes is a live buffer of its
            // length; the descriptor is closed before returning.
            unsafe {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
                let error = std::io::Error::last_os_error();
                libc::close(fd);
                if written != bytes.len() as isize {
                    return Err(error);
                }
            }
            Ok(())
        }

        /// Only system calls, and no allocation: this runs in the forked child.
        fn enter(&self) -> std::io::Result<()> {
            // SAFETY: unshare takes no pointers.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Self::write(c"/proc/self/setgroups", b"deny")?;
            Self::write(c"/proc/self/uid_map", &self.uid_map)?;
            Self::write(c"/proc/self/gid_map", &self.gid_map)
        }
    }

    /// Run the calling test, `test`, in a child process of this test binary
    /// that has a user and mount namespace of its own ([`OwnMountNamespace`])
    /// and an empty directory to mount on. In that child, returns the
    /// directory, where the caller runs its body; in the parent, returns
    /// `None` once the child ran exactly that test and it passed.
    fn in_own_mount_namespace(test: &str) -> Option<std::path::PathBuf> {
        const TEST: &str = "REVERIE_LINUXEMU_HOST_MOUNT_TEST";
        const DIRECTORY: &str = "REVERIE_LINUXEMU_HOST_MOUNT_DIRECTORY";
        if std::env::var(TEST).as_deref() == Ok(test) {
            let directory = std::env::var_os(DIRECTORY).expect("the parent names the directory");
            return Some(directory.into());
        }
        let scratch =
            std::env::temp_dir().join(format!("reverie-host-mount-{test}-{}", std::process::id()));
        let directory = scratch.join("mount");
        std::fs::create_dir_all(&directory).unwrap();
        let log = scratch.join("libtest.log");
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, path)| path);
        let name = format!("{module}::{test}");
        // SAFETY: geteuid and getegid have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let namespace = OwnMountNamespace {
            uid_map: format!("0 {uid} 1").into_bytes(),
            gid_map: format!("0 {gid} 1").into_bytes(),
        };
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                &name,
                "--nocapture",
                "--test-threads=1",
                "--logfile",
            ])
            .arg(&log)
            .env(TEST, test)
            .env(DIRECTORY, &directory);
        // SAFETY: enter makes only system calls and allocates nothing.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, move || namespace.enter())
        };
        let output = command.output().unwrap();
        let record = std::fs::read_to_string(&log);
        std::fs::remove_dir_all(&scratch).unwrap();
        assert!(
            output.status.success(),
            "{test} in its namespace: {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Exactly one completed, passing run of this test, and no other.
        assert_eq!(
            record.unwrap(),
            format!("ok {name}\n"),
            "{test}: the child's execution record"
        );
        None
    }

    /// Fails the test, naming `call` and the error, unless `result`, the
    /// return of a system call that answers 0 or -1, is 0.
    fn check(result: libc::c_long, call: &str) {
        assert_eq!(result, 0, "{call}: {}", std::io::Error::last_os_error());
    }

    /// In a mount namespace of its own: a mount is a mount event, which
    /// makes a kept table stale, and the table read after it gives the new
    /// mount's device. Making that mount's superblock read-only through
    /// `fsconfig(2)` is no mount event, so a kept table would not know it,
    /// while `superblock` reports the flag as it is now, from `statmount(2)`
    /// and from `mountinfo`.
    #[test]
    fn a_mount_is_a_mount_event_and_a_reconfiguration_is_not() {
        let Some(directory) =
            in_own_mount_namespace("a_mount_is_a_mount_event_and_a_reconfiguration_is_not")
        else {
            return;
        };
        let path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
            directory.as_os_str(),
        ))
        .unwrap();
        // From here on no mount of the parent namespace propagates into this
        // one, so the test's own mounts are the only events.
        // SAFETY: the strings are NUL-terminated and live for each call.
        check(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            }
            .into(),
            "mount(MS_REC | MS_PRIVATE)",
        );
        let kept = MountTable::read().unwrap();
        assert!(!kept.stale().unwrap(), "nothing has been mounted yet");
        // SAFETY: as above.
        check(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    path.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    std::ptr::null(),
                )
            }
            .into(),
            "mount(tmpfs)",
        );
        assert!(kept.stale().unwrap(), "a mount is a mount event");

        // Linked, not a scratch file: Linux refuses to make a superblock
        // read-only while it holds a file that is open but unlinked
        // (`sb_prepare_remount_readonly`, EBUSY).
        let name = directory.join("file");
        std::fs::write(&name, b"x").unwrap();
        let file = File::open(&name).unwrap();
        let fd = file.as_raw_fd();
        let device = std::fs::metadata(&directory).unwrap().dev();
        let table = MountTable::read().unwrap();
        assert_eq!(
            table.devices.get(&listed_mount_id(fd).unwrap()),
            Some(&device)
        );
        let read_write = Some(Superblock {
            device,
            read_only: false,
        });
        assert_eq!(superblock(fd).unwrap(), read_write);
        assert_eq!(from_mountinfo(fd), read_write);

        // SAFETY: the path is NUL-terminated; the descriptor is owned here.
        let context =
            unsafe { libc::syscall(SYS_FSPICK, libc::AT_FDCWD, path.as_ptr(), FSPICK_CLOEXEC) };
        assert!(context >= 0, "fspick: {}", std::io::Error::last_os_error());
        // SAFETY: fspick returned a new descriptor of our own.
        let context: std::os::fd::OwnedFd =
            unsafe { std::os::fd::FromRawFd::from_raw_fd(context as libc::c_int) };
        // SAFETY: the key is NUL-terminated; the flag takes no value.
        check(
            unsafe {
                libc::syscall(
                    SYS_FSCONFIG,
                    context.as_raw_fd(),
                    FSCONFIG_SET_FLAG,
                    c"ro".as_ptr(),
                    std::ptr::null::<libc::c_void>(),
                    0,
                )
            },
            "fsconfig(FSCONFIG_SET_FLAG, \"ro\")",
        );
        // SAFETY: the command takes no key or value.
        check(
            unsafe {
                libc::syscall(
                    SYS_FSCONFIG,
                    context.as_raw_fd(),
                    FSCONFIG_CMD_RECONFIGURE,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<libc::c_void>(),
                    0,
                )
            },
            "fsconfig(FSCONFIG_CMD_RECONFIGURE)",
        );
        assert!(
            !table.stale().unwrap(),
            "a reconfiguration is no mount event"
        );
        let read_only = Some(Superblock {
            device,
            read_only: true,
        });
        assert_eq!(superblock(fd).unwrap(), read_only);
        assert_eq!(from_mountinfo(fd), read_only);
    }

    /// A table read in another mount namespace is stale whatever its
    /// descriptor reports.
    #[test]
    fn a_table_from_another_namespace_is_stale() {
        let mut table = MountTable::read().unwrap();
        table.namespace = table.namespace.wrapping_add(1);
        assert!(table.stale().unwrap());
    }
}
