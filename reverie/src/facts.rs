/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Facts a backend reports about the kernel state of a guest's threads,
//! which Linux shows as text under `/proc`, and the errors that come with
//! them.
//!
//! A fact is a [`Guest`](crate::Guest) method that returns typed state, such
//! as [`Guest::descriptor_status`](crate::Guest::descriptor_status). Linux
//! shows the same state as text under `/proc`; a fact carries it typed, so a
//! tool can use it without reading, or trusting, a backend's `/proc`. A
//! backend whose guest threads are host tasks reads the host kernel's state
//! for them; a backend that runs the guest's syscalls itself answers from its
//! own records; a backend that can do neither declines with
//! [`FactError::NotProvided`].

use serde::Deserialize;
use serde::Serialize;

use crate::Errno;

/// Why a backend did not report a fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FactError {
    /// The backend does not report this fact, for any object or for this
    /// one: it can neither read the kernel's state for the guest nor answer
    /// from records of its own, or the state is one the fact's type cannot
    /// describe. This is the default of every fact method.
    NotProvided,
    /// The fact could not be read; the errno says why. Each fact method names
    /// the values it returns, such as `EBADF` for a descriptor that is not
    /// open.
    Errno(Errno),
}

/// The class of a lock held through an open file description, as Linux
/// names it in `/proc/locks` and in a descriptor's `fdinfo` `lock:` lines
/// (`lock_get_status` in Linux's `fs/locks.c`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LockClass {
    /// A process-associated record lock (`F_SETLK`), which Linux prints as
    /// `POSIX`.
    Posix,
    /// An open file description lock (`F_OFD_SETLK`), which Linux prints as
    /// `OFDLCK`.
    OpenFileDescription,
    /// A `flock(2)` lock, which Linux prints as `FLOCK`.
    Flock,
    /// A lease (`F_SETLEASE`), which Linux prints as `LEASE`.
    Lease,
}

/// One lock held through a descriptor's open file description, as Linux
/// prints it on one `lock:` line of the descriptor's `fdinfo`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HeldLockFact {
    /// The lock's class.
    pub class: LockClass,
    /// Whether Linux enforces the lock: it printed `MANDATORY` for a `POSIX`
    /// or `OFDLCK` lock on a file with mandatory locking enabled. Linux 5.15
    /// removed mandatory locking, and later kernels print `ADVISORY` for
    /// every lock, so this is false there.
    pub mandatory: bool,
    /// A write (exclusive) lock; false for a read (shared) one. For a lease,
    /// a write lease.
    pub write: bool,
    /// The device of the locked file's file system, as Linux prints it on
    /// the line (the superblock's device number, `i_sb->s_dev`), encoded as
    /// `libc::makedev` encodes it. On btrfs this need not be the file's
    /// `st_dev`, which names its subvolume.
    pub raw_device: u64,
    /// The locked file's inode number.
    pub raw_inode: u64,
    /// The first byte the lock covers. Zero for a `flock(2)` lock or a
    /// lease, which cover the whole file.
    pub start: u64,
    /// The last byte the lock covers, inclusive, or `None` when it extends to
    /// the end of the file, however long it grows (Linux prints `EOF`).
    /// `None` for a `flock(2)` lock or a lease.
    pub end: Option<u64>,
}

/// What Linux reports about one open descriptor that no syscall reads without
/// changing it. Linux shows it in the descriptor's `/proc/<pid>/fdinfo/<fd>`
/// (`seq_show` in Linux's `fs/proc/fd.c`); see
/// [`Guest::descriptor_status`](crate::Guest::descriptor_status).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DescriptorStatus {
    /// An eventfd's counter (`eventfd-count`, from `eventfd_show_fdinfo` in
    /// Linux's `fs/eventfd.c`): reading it with `read(2)` consumes it. `None`
    /// for any other descriptor.
    pub eventfd_count: Option<u64>,
    /// For a Unix domain socket, how many descriptors are queued for it in
    /// `SCM_RIGHTS` messages it has not received yet (`scm_fds`, from
    /// `unix_show_fdinfo` in Linux's `net/unix/af_unix.c`); for a listening
    /// socket, in the messages queued for the connections it has not
    /// accepted. `None` for any other descriptor.
    pub scm_fds: Option<u32>,
    /// The locks held through the descriptor's open file description, in the
    /// order Linux lists them (`show_fd_locks` in Linux's `fs/locks.c`):
    /// `flock(2)` locks, then record locks, then leases. A `POSIX` record
    /// lock is listed only when it belongs to the descriptor table that the
    /// descriptor is read through, the thread's own.
    pub locks: Vec<HeldLockFact>,
}

/// What [`DescriptorStatus::from_fdinfo`] and [`MemoryMap::from_maps`]
/// answer for text that is not Linux's `fdinfo` or `maps` format.
const MALFORMED: FactError = FactError::Errno(Errno::EIO);

/// Why one `lock:` line was not accepted.
enum Refusal {
    /// Not a line Linux prints in `fdinfo`.
    Malformed,
    /// A line Linux prints that [`HeldLockFact`] cannot describe.
    Unrepresentable,
}

impl DescriptorStatus {
    /// Parses the text Linux prints in a descriptor's
    /// `/proc/<pid>/fdinfo/<fd>`, accepting exactly what Linux prints. The
    /// first line is the `pos:` line (`seq_show` in Linux's `fs/proc/fd.c`)
    /// and every line ends with a newline. Of the rest, the `lock:` lines
    /// (`show_fd_locks` and `lock_get_status` in `fs/locks.c`), the
    /// `eventfd-count:` line (`eventfd_show_fdinfo` in `fs/eventfd.c`) and the
    /// `scm_fds:` line (`unix_show_fdinfo` in `net/unix/af_unix.c`) are read.
    /// Each must be exactly as Linux renders it: its separators, column
    /// padding, digits, case and numeric range, with the lock lines numbered
    /// from 1 and printed before either of the other two. Lines that describe
    /// other state (`flags:`, `ino:`, an epoll's `tfd:` lines, and so on) are
    /// skipped.
    ///
    /// Returns `Err(FactError::NotProvided)` when a well-formed line shows a
    /// lock that [`HeldLockFact`] cannot describe: a delegation (`DELEG`), a
    /// lease or delegation being broken (`BREAKING`, whose type Linux prints
    /// as the one it is to become), or a share-mode `flock(2)` lock
    /// (`LOCK_MAND`, printed as `MSNFS`) of Linux 5.15 and earlier. Returns
    /// `Err(FactError::Errno(EIO))` for any other text that is not Linux's
    /// format, a malformed line of one of those kinds included: a malformed
    /// line outweighs an undescribable one.
    pub fn from_fdinfo(text: &[u8]) -> Result<Self, FactError> {
        let body = text.strip_suffix(b"\n").ok_or(MALFORMED)?;
        let mut lines = body.split(|byte| *byte == b'\n');
        // `pos:\t%lli`.
        let position = lines.next().and_then(|line| line.strip_prefix(b"pos:\t"));
        if position.and_then(exact_decimal::<i64>).is_none() {
            return Err(MALFORMED);
        }
        let mut status = Self {
            eventfd_count: None,
            scm_fds: None,
            locks: Vec::new(),
        };
        let mut lock_lines = 0;
        let mut unrepresentable = false;
        for line in lines {
            if let Some(row) = line.strip_prefix(b"lock:") {
                // `lock:\t`; the locks come before the file's own lines.
                let row = row.strip_prefix(b"\t").ok_or(MALFORMED)?;
                if status.eventfd_count.is_some() || status.scm_fds.is_some() {
                    return Err(MALFORMED);
                }
                lock_lines += 1;
                match parse_lock(row, lock_lines) {
                    Ok(lock) => status.locks.push(lock),
                    Err(Refusal::Unrepresentable) => unrepresentable = true,
                    Err(Refusal::Malformed) => return Err(MALFORMED),
                }
            } else if let Some(value) = line.strip_prefix(b"eventfd-count:") {
                // `eventfd-count: %16llx`.
                let count = value
                    .strip_prefix(b" ")
                    .and_then(exact_eventfd_count)
                    .ok_or(MALFORMED)?;
                if status.eventfd_count.replace(count).is_some() || status.scm_fds.is_some() {
                    return Err(MALFORMED);
                }
            } else if let Some(value) = line.strip_prefix(b"scm_fds:") {
                // `scm_fds: %u`.
                let count = value
                    .strip_prefix(b" ")
                    .and_then(exact_decimal::<u32>)
                    .ok_or(MALFORMED)?;
                if status.scm_fds.replace(count).is_some() || status.eventfd_count.is_some() {
                    return Err(MALFORMED);
                }
            }
        }
        if unrepresentable {
            return Err(FactError::NotProvided);
        }
        Ok(status)
    }
}

/// `text` as Linux prints an integer of type `T` with `%d`, `%u`, `%lli`,
/// `%llu` or `%Ld`: the value's own decimal digits, with a minus sign only
/// for a negative value, and no padding, plus sign or leading zero.
fn exact_decimal<T: std::str::FromStr + ToString>(text: &[u8]) -> Option<T> {
    let text = std::str::from_utf8(text).ok()?;
    let value = text.parse::<T>().ok()?;
    (value.to_string() == text).then_some(value)
}

/// The `%16llx` of `eventfd-count`: lowercase hexadecimal digits,
/// right-aligned in 16 columns of spaces, which every `u64` fills exactly.
fn exact_eventfd_count(text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?;
    let digits = text.trim_start_matches(' ');
    if !digits
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let count = u64::from_str_radix(digits, 16).ok()?;
    (format!("{count:16x}") == text).then_some(count)
}

/// What the class columns of a `lock:` row say.
#[derive(Clone, Copy)]
enum RowKind {
    /// A lock [`HeldLockFact`] describes, of this class, mandatory or not.
    Held(LockClass, bool),
    /// An active delegation (`DELEG  ACTIVE`).
    Delegation,
    /// A lease or delegation being broken (`BREAKING`).
    Breaking,
    /// A share-mode `flock(2)` lock (`LOCK_MAND`) of Linux 5.15 and earlier.
    ShareMode,
}

/// The class columns of every row `lock_get_status` prints for a lock held
/// through a descriptor, with the spaces it prints after them. `ACCESS` and
/// `*NOINODE*` are not held locks, and a lease `BREAKER` has no file, so
/// `fdinfo` never lists one.
const ROW_KINDS: [(&str, RowKind); 10] = [
    ("POSIX  ADVISORY  ", RowKind::Held(LockClass::Posix, false)),
    ("POSIX  MANDATORY ", RowKind::Held(LockClass::Posix, true)),
    (
        "OFDLCK ADVISORY  ",
        RowKind::Held(LockClass::OpenFileDescription, false),
    ),
    (
        "OFDLCK MANDATORY ",
        RowKind::Held(LockClass::OpenFileDescription, true),
    ),
    ("FLOCK  ADVISORY  ", RowKind::Held(LockClass::Flock, false)),
    ("LEASE  ACTIVE    ", RowKind::Held(LockClass::Lease, false)),
    ("DELEG  ACTIVE    ", RowKind::Delegation),
    ("LEASE  BREAKING  ", RowKind::Breaking),
    ("DELEG  BREAKING  ", RowKind::Breaking),
    ("FLOCK  MSNFS     ", RowKind::ShareMode),
];

impl RowKind {
    /// The type columns Linux prints after this class, with the space after
    /// them, and whether each is a write lock.
    fn types(self) -> &'static [(&'static str, bool)] {
        match self {
            // A held lock, or an active lease or delegation, reads or writes.
            Self::Held(..) | Self::Delegation => &[("WRITE ", true), ("READ ", false)],
            // `target_leasetype`: the type the lease is being broken to.
            Self::Breaking => &[("UNLCK ", false), ("READ ", false)],
            // The `LOCK_MAND` access column: `%s ` of a five-column word.
            Self::ShareMode => &[
                ("RW    ", true),
                ("READ  ", false),
                ("WRITE ", true),
                ("NONE  ", false),
            ],
        }
    }
}

/// One `lock:` row after its `lock:\t` prefix, exactly as `lock_get_status`
/// prints it for the `number`th lock of a descriptor's `fdinfo`: `%lld: `,
/// the class and type columns, `%d %02x:%02x:%llu ` for the owner's process
/// ID, the device and the inode, then the range: `%Ld %Ld` or `%Ld EOF` for
/// a record lock and `0 EOF` for any other. `fdinfo` prints no waiter rows
/// (`->`).
fn parse_lock(row: &[u8], number: u64) -> Result<HeldLockFact, Refusal> {
    let row = std::str::from_utf8(row).map_err(|_| Refusal::Malformed)?;
    let (id, columns) = row.split_once(": ").ok_or(Refusal::Malformed)?;
    if exact_decimal::<u64>(id.as_bytes()) != Some(number) {
        return Err(Refusal::Malformed);
    }
    let (kind, columns) = ROW_KINDS
        .iter()
        .find_map(|(text, kind)| columns.strip_prefix(text).map(|rest| (*kind, rest)))
        .ok_or(Refusal::Malformed)?;
    let (write, columns) = kind
        .types()
        .iter()
        .find_map(|(text, write)| columns.strip_prefix(text).map(|rest| (*write, rest)))
        .ok_or(Refusal::Malformed)?;
    let mut fields = columns.split(' ');
    let (Some(owner), Some(object), Some(start), Some(end), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(Refusal::Malformed);
    };
    // The owner's process ID: -1 for an OFD lock and 0 for an owner the
    // reader cannot see. It is not part of the fact.
    exact_decimal::<i32>(owner.as_bytes()).ok_or(Refusal::Malformed)?;
    let (raw_device, raw_inode) = parse_object(object).ok_or(Refusal::Malformed)?;
    let (start, end) = match kind {
        RowKind::Held(LockClass::Posix | LockClass::OpenFileDescription, _) => {
            parse_range(start, end).ok_or(Refusal::Malformed)?
        }
        // Linux prints `0 EOF` for every lock that is not a record lock.
        _ if (start, end) == ("0", "EOF") => (0, None),
        _ => return Err(Refusal::Malformed),
    };
    let RowKind::Held(class, mandatory) = kind else {
        return Err(Refusal::Unrepresentable);
    };
    Ok(HeldLockFact {
        class,
        mandatory,
        write,
        raw_device,
        raw_inode,
        start,
        end,
    })
}

/// A record lock's `%Ld %Ld` or `%Ld EOF`: offsets of a `loff_t` that Linux
/// keeps from 0 to `OFFSET_MAX`, the end not before the start, with an end of
/// `OFFSET_MAX` printed as `EOF`.
fn parse_range(start: &str, end: &str) -> Option<(u64, Option<u64>)> {
    let start = u64::try_from(exact_decimal::<i64>(start.as_bytes())?).ok()?;
    if end == "EOF" {
        return Some((start, None));
    }
    let end = exact_decimal::<i64>(end.as_bytes())?;
    let end = u64::try_from(end).ok().filter(|_| end != i64::MAX)?;
    (start <= end).then_some((start, Some(end)))
}

/// The `%02x:%02x:%llu` object column: the superblock device's major and
/// minor numbers, at most 12 and 20 bits as Linux splits a device number,
/// and the inode number. A lock with no inode (`<none>:0`) is never a
/// descriptor's.
fn parse_object(object: &str) -> Option<(u64, u64)> {
    let mut parts = object.split(':');
    let (Some(major), Some(minor), Some(inode), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let major = exact_hex_02(major, 0xfff)?;
    let minor = exact_hex_02(minor, 0xf_ffff)?;
    let inode = exact_decimal::<u64>(inode.as_bytes())?;
    Some((libc::makedev(major, minor), inode))
}

/// `%02x` of a number no larger than `max`: lowercase hexadecimal,
/// zero-padded to two digits and no further.
fn exact_hex_02(text: &str, max: u32) -> Option<u32> {
    if !text
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let value = u32::from_str_radix(text, 16)
        .ok()
        .filter(|value| *value <= max)?;
    (format!("{value:02x}") == text).then_some(value)
}

/// The five signal sets Linux reports for one thread in its `status` file
/// (`/proc/<pid>/task/<tid>/status`; `task_sig` in Linux's
/// `fs/proc/array.c`), in the order Linux prints them. A tool gets them for
/// any live guest thread, whatever its process; see
/// [`Guest::signal_sets`](crate::Guest::signal_sets), or, from code that holds
/// no `Guest`,
/// [`ProcessSignalControl::signal_sets`](crate::ProcessSignalControl::signal_sets).
///
/// Each set holds signal `n`, from 1 to 64, at bit `n - 1`, as the `status`
/// line shows it: sixteen hexadecimal digits, highest-numbered signals
/// first, so the line's digits read as a hexadecimal number are the set. A
/// real-time signal queued more than once is one bit, as in Linux's sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SignalSets {
    /// `SigPnd`: the signals pending for this thread alone
    /// (`task->pending`), such as one sent to it with `tgkill(2)`, that it
    /// has not taken yet.
    pub pending: u64,
    /// `ShdPnd`: the signals pending for its whole thread group
    /// (`signal->shared_pending`), such as one sent with `kill(2)`, that no
    /// thread has taken yet. Every thread of a process has the same set.
    pub shared_pending: u64,
    /// `SigBlk`: the thread's signal mask (`task->blocked`). While a call
    /// that replaces the mask for its duration runs (`rt_sigsuspend`, or
    /// `ppoll`, `pselect6` or `epoll_pwait` given a mask), it is that call's
    /// mask, and while `rt_sigtimedwait` waits, the mask without the signals
    /// it waits for; while a handler runs, it includes the handler's
    /// `sa_mask` and, without `SA_NODEFER`, the handler's own signal. Never
    /// `SIGKILL` or `SIGSTOP`.
    pub blocked: u64,
    /// `SigIgn`: the signals whose action is `SIG_IGN`. A signal that is
    /// ignored only by default, such as `SIGCHLD` under `SIG_DFL`, is not in
    /// it. Never `SIGKILL` or `SIGSTOP`, whose action cannot be changed.
    pub ignored: u64,
    /// `SigCgt`: the signals with a handler, an action that is neither
    /// `SIG_DFL` nor `SIG_IGN`. Never `SIGKILL` or `SIGSTOP`, and never a
    /// signal in [`ignored`](Self::ignored).
    pub caught: u64,
}

impl SignalSets {
    /// The sets in the order Linux prints them: `SigPnd`, `ShdPnd`, `SigBlk`,
    /// `SigIgn` and `SigCgt`.
    pub fn new(pending: u64, shared_pending: u64, blocked: u64, ignored: u64, caught: u64) -> Self {
        Self {
            pending,
            shared_pending,
            blocked,
            ignored,
            caught,
        }
    }
}

/// One of the links to a file that Linux shows in a thread's `/proc`
/// directory, `/proc/<pid>/task/<tid>`, and whose `readlink(2)` names the
/// file: see [`Guest::link_path`](crate::Guest::link_path). The thread's
/// `root` link is not one of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PathLink {
    /// `fd/<fd>`: the file that descriptor `fd` of the thread's descriptor
    /// table refers to (`proc_fd_link` in Linux's `fs/proc/fd.c`).
    Descriptor(i32),
    /// `exe`: the file the thread's process executes, its address space's
    /// executable (`proc_exe_link` in Linux's `fs/proc/base.c`).
    Executable,
    /// `cwd`: the thread's working directory (`proc_cwd_link` in Linux's
    /// `fs/proc/base.c`).
    WorkingDirectory,
}

/// What Linux's `readlink(2)` gives for a [`PathLink`]: the name `d_path`
/// renders for the file the link refers to (`do_proc_readlink` in Linux's
/// `fs/proc/base.c`; `d_path` in `fs/d_path.c`). Linux names a file in one of
/// two ways, which the text's first byte tells apart, so the kind is decided
/// by the text alone. The text is never empty, has no NUL byte and is at most
/// `PATH_MAX - 1` (4,095) bytes long, ` (deleted)` included: `d_path` renders
/// into a buffer of `PATH_MAX` bytes and fails with `ENAMETOOLONG` for a
/// name that does not fit, which a backend reports as that errno.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LinkPath {
    /// A text that begins with `/`: the path of the file from the root of
    /// the task that reads the link, with ` (deleted)` appended once the file
    /// has been unlinked, as `d_path` renders a file of the tree of mounted
    /// file systems (`prepend_path`, which always begins the path with `/`).
    /// Some kernel-internal file systems give their files a name of the same
    /// shape, which Linux renders as the path of a deleted file, such as a
    /// memfd's `/memfd:<name> (deleted)` (`simple_dname`). A file whose own
    /// name ends in ` (deleted)` reads as an unlinked one: Linux's text does
    /// not tell them apart, and neither does this one.
    Path(Vec<u8>),
    /// A text that does not begin with `/`: the name a kernel-internal file
    /// system gives an object that has no path, through the file system's
    /// `d_dname` and `dynamic_dname`, such as `pipe:[<inode>]`,
    /// `socket:[<inode>]`, `anon_inode:[eventfd]` or `anon_inode:inotify`.
    /// `dynamic_dname` refuses a name longer than `NAME_MAX - 1` (254) bytes,
    /// so this text is never longer.
    Anonymous(Vec<u8>),
}

/// Linux's `PATH_MAX` (`include/uapi/linux/limits.h`): `d_path`'s buffer in
/// `do_proc_readlink`, whose last byte is the name's NUL.
const PATH_MAX: usize = 4096;

/// Linux's `NAME_MAX` (`include/uapi/linux/limits.h`): `dynamic_dname`'s
/// bound on a name and its NUL.
const NAME_MAX: usize = 255;

impl LinkPath {
    /// Classifies `text`, the bytes Linux's `readlink(2)` of one of a
    /// thread's `/proc` links returns, as [`LinkPath`] describes: a text that
    /// begins with `/` is a [`LinkPath::Path`], any other a
    /// [`LinkPath::Anonymous`]. Returns `Err(FactError::Errno(EIO))` for
    /// text that Linux never returns for such a link: an empty text, one
    /// longer than `PATH_MAX - 1` bytes, one with a NUL byte, or an anonymous
    /// name longer than `NAME_MAX - 1` bytes.
    pub fn from_readlink(text: &[u8]) -> Result<Self, FactError> {
        let malformed = Err(FactError::Errno(Errno::EIO));
        if text.is_empty() || text.len() >= PATH_MAX || text.contains(&0) {
            return malformed;
        }
        if text[0] == b'/' {
            Ok(Self::Path(text.to_vec()))
        } else if text.len() < NAME_MAX {
            Ok(Self::Anonymous(text.to_vec()))
        } else {
            malformed
        }
    }

    /// The link's text, whichever kind it is.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Path(text) | Self::Anonymous(text) => text,
        }
    }
}

/// The mappings of a thread's address space, as Linux lists them in
/// `/proc/<pid>/task/<tid>/maps` (`show_map_vma` in Linux's
/// `fs/proc/task_mmu.c`), and whether the list is all of them: see
/// [`Guest::memory_map`](crate::Guest::memory_map). Every thread of a process
/// shares its address space, so every thread has the same list.
///
/// [`MemoryMap::new`] and [`MemoryMap::from_maps`] build only a list that
/// [`MemoryMap::validate`] accepts. The fields are public, so a caller that
/// changes them, or a value deserialized with serde, is checked only by
/// calling [`MemoryMap::validate`].
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoryMap {
    /// The mappings, in ascending order of address and not overlapping, as
    /// Linux lists them: the address space's own mappings first, then the
    /// kernel's gate area (such as x86-64's `[vsyscall]`), which lies above
    /// them. Every listed mapping is exactly a line Linux prints for the
    /// backend's own address space, whether or not the list is
    /// [`complete`](Self::complete): its range, permissions, sharing,
    /// offset, device, inode and name are all Linux's for that address space.
    /// A backend that cannot establish every field of a mapping leaves the
    /// mapping out.
    pub mappings: Vec<MappingFact>,
    /// Whether [`mappings`](Self::mappings) is every mapping Linux lists for
    /// the address space. It says how much of the address space the list
    /// covers, nothing about the listed mappings, which are exact either way.
    /// When it is false, the list omits mappings that exist, which the
    /// backend's documentation names: a tool must not infer from a missing
    /// entry that no mapping is there, such as that an address is unmapped,
    /// and a tool that renders the list as a `maps` file must name the
    /// omissions as a difference of the backend.
    pub complete: bool,
}

/// One mapping of an address space, as Linux prints it on one line of
/// `maps` (`show_map_vma` and `show_vma_header_prefix` in Linux's
/// `fs/proc/task_mmu.c`): its range, its permissions, the file offset it
/// starts at, and what backs it, which decides the device, the inode and the
/// name Linux prints.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MappingFact {
    /// The first address of the mapping, page-aligned (`vm_start`).
    pub start: u64,
    /// The address just past the mapping, page-aligned and above
    /// [`start`](Self::start) (`vm_end`).
    pub end: u64,
    /// The access the mapping allows, as `PROT_READ`, `PROT_WRITE` and
    /// `PROT_EXEC` bits (`libc`'s values, 1, 2 and 4) and no other: the first
    /// three permission columns, which Linux prints from the mapping's
    /// `VM_READ`, `VM_WRITE` and `VM_EXEC` flags. Linux keeps them apart, so a
    /// mapping can be writable or executable without being readable, as
    /// `mprotect(2)` leaves it.
    pub prot: u32,
    /// Whether the mapping was made shared, with `MAP_SHARED`
    /// (`VM_MAYSHARE`), which Linux prints as `s` in the last permission
    /// column; `p` (false) for a private one. A shared mapping of a file opened
    /// read-only is shared too.
    pub shared: bool,
    /// For a mapping of a file ([`MappingBacking::File`] or
    /// [`MappingBacking::NamedSharedAnonymous`]), the offset in the file of
    /// the mapping's first byte (`vm_pgoff << PAGE_SHIFT`), a multiple of the
    /// page size; zero for any other mapping, as Linux prints it.
    pub offset: u64,
    /// What backs the mapping, and the name Linux prints for it.
    pub backing: MappingBacking,
    /// Linux's `vm_flags` for the mapping (`include/linux/mm.h`, in the
    /// x86-64 numbering of Linux 7.1, the `VM_*` constants of this module):
    /// the bits `show_smap_vma_flags` prints as `VmFlags` in `smaps`, among
    /// those [`MappingFact::validate`] accepts. `None` where the backend
    /// cannot establish all of them, and on any architecture other than
    /// x86-64, whose numbering differs. Protection-key bits are never set.
    ///
    /// `serde(default)` lets JSON written without the field decode to
    /// `None`; a positional (bincode) carrier of this type would need its own
    /// version bump, and the field must never be skipped when serializing.
    #[serde(default)]
    pub vm_flags: Option<u64>,
    /// Whether `smaps` reports that the mapping may have transparent huge
    /// pages (`THPeligible`, `thp_vma_allowable_orders` in Linux's
    /// `include/linux/huge_mm.h`), as the kernel the backend runs on printed
    /// it, when the list was made, for a mapping of its own of the same
    /// open file description with the same file offset, length, protection
    /// and sharing, at an address with the same offset within a PMD-sized
    /// block (at the same address, for a mapping that ends below one).
    /// `None` where the backend did not ask. It answers for the mapping
    /// alone: whether the address space disabled transparent huge pages
    /// (`PR_SET_THP_DISABLE`), which makes every mapping's 0, is for the
    /// reader to apply.
    ///
    /// `serde(default)` lets JSON written without the field decode to
    /// `None`, as for [`vm_flags`](Self::vm_flags).
    #[serde(default)]
    pub thp_eligible: Option<bool>,
}

/// `VM_READ` (`include/linux/mm.h`, Linux 7.1): `rd` in `smaps`' `VmFlags`.
pub const VM_READ: u64 = 1 << 0;
/// `VM_WRITE`: `wr`.
pub const VM_WRITE: u64 = 1 << 1;
/// `VM_EXEC`: `ex`.
pub const VM_EXEC: u64 = 1 << 2;
/// `VM_SHARED`: `sh`.
pub const VM_SHARED: u64 = 1 << 3;
/// `VM_MAYREAD`: `mr`.
pub const VM_MAYREAD: u64 = 1 << 4;
/// `VM_MAYWRITE`: `mw`.
pub const VM_MAYWRITE: u64 = 1 << 5;
/// `VM_MAYEXEC`: `me`.
pub const VM_MAYEXEC: u64 = 1 << 6;
/// `VM_MAYSHARE`: `ms`.
pub const VM_MAYSHARE: u64 = 1 << 7;
/// `VM_GROWSDOWN`: `gd`.
pub const VM_GROWSDOWN: u64 = 1 << 8;
/// `VM_MAYBE_GUARD`: `gu`, which kernels after 6.17 print.
pub const VM_MAYBE_GUARD: u64 = 1 << 11;
/// `VM_LOCKED`: `lo`.
pub const VM_LOCKED: u64 = 1 << 13;
/// `VM_SEQ_READ`: `sr`.
pub const VM_SEQ_READ: u64 = 1 << 15;
/// `VM_RAND_READ`: `rr`.
pub const VM_RAND_READ: u64 = 1 << 16;
/// `VM_ACCOUNT`: `ac`.
pub const VM_ACCOUNT: u64 = 1 << 20;
/// `VM_NORESERVE`: `nr`.
pub const VM_NORESERVE: u64 = 1 << 21;
/// `VM_SYNC`: `sf`.
pub const VM_SYNC: u64 = 1 << 23;
/// `VM_HUGEPAGE`: `hg`.
pub const VM_HUGEPAGE: u64 = 1 << 29;
/// `VM_NOHUGEPAGE`: `nh`.
pub const VM_NOHUGEPAGE: u64 = 1 << 30;
/// `VM_MERGEABLE`: `mg`.
pub const VM_MERGEABLE: u64 = 1 << 31;
/// Every `VM_*` bit a [`MappingFact::vm_flags`] may hold.
pub const VM_KNOWN_FLAGS: u64 = VM_READ
    | VM_WRITE
    | VM_EXEC
    | VM_SHARED
    | VM_MAYREAD
    | VM_MAYWRITE
    | VM_MAYEXEC
    | VM_MAYSHARE
    | VM_GROWSDOWN
    | VM_MAYBE_GUARD
    | VM_LOCKED
    | VM_SEQ_READ
    | VM_RAND_READ
    | VM_ACCOUNT
    | VM_NORESERVE
    | VM_SYNC
    | VM_HUGEPAGE
    | VM_NOHUGEPAGE
    | VM_MERGEABLE;

impl MappingFact {
    /// A mapping with these fields, in the order Linux prints them, if
    /// [`MappingFact::validate`] accepts them; otherwise
    /// `Err(FactError::Errno(EIO))`.
    pub fn new(
        start: u64,
        end: u64,
        prot: u32,
        shared: bool,
        offset: u64,
        backing: MappingBacking,
    ) -> Result<Self, FactError> {
        let mapping = Self {
            start,
            end,
            prot,
            shared,
            offset,
            backing,
            vm_flags: None,
            thp_eligible: None,
        };
        mapping.validate()?;
        Ok(mapping)
    }

    /// The mapping with [`thp_eligible`](Self::thp_eligible) `eligible`.
    pub fn with_thp_eligible(self, eligible: bool) -> Self {
        Self {
            thp_eligible: Some(eligible),
            ..self
        }
    }

    /// The mapping with [`vm_flags`](Self::vm_flags) `vm_flags`, if
    /// [`MappingFact::validate`] accepts it; otherwise
    /// `Err(FactError::Errno(EIO))`.
    pub fn with_vm_flags(self, vm_flags: u64) -> Result<Self, FactError> {
        let mapping = Self {
            vm_flags: Some(vm_flags),
            ..self
        };
        mapping.validate()?;
        Ok(mapping)
    }

    /// Checks that the mapping is one Linux can print, as each field's
    /// documentation and [`MappingBacking`]'s describe it. Returns
    /// `Err(FactError::Errno(EIO))` unless:
    /// - [`start`](Self::start) and [`end`](Self::end) are multiples of the
    ///   page size, with `start` below `end`;
    /// - [`prot`](Self::prot) holds no bit but `PROT_READ`, `PROT_WRITE` and
    ///   `PROT_EXEC`;
    /// - [`offset`](Self::offset) is a multiple of the page size, and zero
    ///   unless the backing is a file's ([`MappingBacking::File`] or
    ///   [`MappingBacking::NamedSharedAnonymous`]);
    /// - a file's device is a 12-bit major and a 20-bit minor encoded as
    ///   `libc::makedev` encodes them, and not `00:00`, which Linux prints
    ///   for no file;
    /// - a file's path is not empty, holds no NUL and no newline, and begins
    ///   with neither a space nor `[`;
    /// - a [`MappingBacking::Special`] name is in brackets, holds no NUL and
    ///   no newline, and is none of the names that have a variant of their
    ///   own, nor begins `[anon:` or `[anon_shmem:`;
    /// - an anonymous memory name is one `prctl(PR_SET_VMA,
    ///   PR_SET_VMA_ANON_NAME)` accepts;
    /// - [`vm_flags`](Self::vm_flags), where given, holds no bit outside
    ///   [`VM_KNOWN_FLAGS`]; its `VM_READ`, `VM_WRITE` and `VM_EXEC` are
    ///   [`prot`](Self::prot)'s bits, each within the matching `VM_MAY*` bit
    ///   (`VM_MAYREAD >> 4 == VM_READ`, which `mprotect(2)` relies on); its
    ///   `VM_MAYSHARE` is [`shared`](Self::shared); and `VM_SHARED` comes
    ///   only with `VM_MAYSHARE`. `VM_SHARED` without `VM_MAYWRITE` is
    ///   accepted: a shared mapping of a write-sealed memfd has it.
    ///
    /// These are the rules under which [`MemoryMap::from_maps`] reads back
    /// the line Linux prints for the mapping as the same mapping.
    pub fn validate(&self) -> Result<(), FactError> {
        let page_aligned = |value: u64| value.is_multiple_of(MAPS_PAGE_SIZE);
        let any_prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32;
        let valid = page_aligned(self.start)
            && page_aligned(self.end)
            && self.start < self.end
            && self.prot & !any_prot == 0
            && page_aligned(self.offset)
            && (self.offset == 0 || self.backing.has_file())
            && self.backing.is_valid()
            && self
                .vm_flags
                .is_none_or(|flags| self.vm_flags_are_valid(flags));
        if valid { Ok(()) } else { Err(MALFORMED) }
    }

    /// Whether `flags` keeps the rules [`MappingFact::validate`] gives
    /// [`vm_flags`](Self::vm_flags) for this mapping.
    fn vm_flags_are_valid(&self, flags: u64) -> bool {
        let access = VM_READ | VM_WRITE | VM_EXEC;
        let prot = [
            (libc::PROT_READ, VM_READ),
            (libc::PROT_WRITE, VM_WRITE),
            (libc::PROT_EXEC, VM_EXEC),
        ]
        .into_iter()
        .filter(|(bit, _)| self.prot & *bit as u32 != 0)
        .fold(0, |bits, (_, flag)| bits | flag);
        flags & !VM_KNOWN_FLAGS == 0
            && flags & access == prot
            && flags & access & !((flags & (VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)) >> 4) == 0
            && (flags & VM_MAYSHARE != 0) == self.shared
            && (flags & VM_SHARED == 0 || flags & VM_MAYSHARE != 0)
    }
}

/// What backs one mapping of an address space, and the name Linux prints for
/// it after the inode column of `maps` (`get_vma_name` in Linux's
/// `fs/proc/task_mmu.c`). A mapping of a file names the file, or for named
/// shared anonymous memory its name; Linux prints the file's device and inode
/// beside it. Any other mapping is backed by no file, and Linux prints device
/// `00:00` and inode `0` beside the name the kernel gives it, or no name.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MappingBacking {
    /// Memory backed by no file that has no name: nothing follows the inode
    /// column.
    Anonymous,
    /// `[stack]`: the mapping that holds the address the process's first
    /// thread started its stack at (`mm->start_stack`), counting a mapping
    /// that ends or starts at that address (`vma_is_initial_stack` in Linux's
    /// `include/linux/mm.h`). The parts `mprotect(2)` splits from it are
    /// [`MappingBacking::Anonymous`]. Other threads' stacks are named only as
    /// the memory they were made of.
    Stack,
    /// `[heap]`: a mapping that overlaps the program break's area, the
    /// addresses from the initial break (`mm->start_brk`) to the current one
    /// (`mm->brk`), both excluded (`vma_is_initial_heap`): the memory `brk(2)`
    /// added, or each part of it that `mprotect(2)` split off. Linux names it
    /// before any name `prctl(2)` gave it.
    Heap,
    /// `[vdso]`: the kernel's virtual dynamic shared object.
    Vdso,
    /// `[vvar]`: the data pages the vDSO reads.
    Vvar,
    /// `[anon:<name>]`: anonymous memory that a process named with
    /// `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)`. The name, without `[anon:`
    /// and `]`, is at most 79 printable ASCII bytes, without `\`, `` ` ``,
    /// `$`, `[` or `]`, and may be empty (`set_anon_vma_name` in Linux's
    /// `mm/madvise.c`).
    NamedAnonymous(Vec<u8>),
    /// Another name the kernel gives a mapping of its own, as Linux prints
    /// it, brackets included: the mapping's `vm_ops->name`, such as
    /// `[vvar_vclock]`, `[vsyscall]` or `[uprobes]`. Never one of the names
    /// above, nor a name that begins `[anon:` or `[anon_shmem:`.
    Special(Vec<u8>),
    /// A file, such as an executable's segment or a file mapped with
    /// `mmap(2)`, a memfd included, and shared anonymous memory, which Linux
    /// backs with a file of its own (`/dev/zero (deleted)`).
    File {
        /// The device of the file's file system, as Linux prints it (the
        /// superblock's device number, `i_sb->s_dev`), encoded as
        /// `libc::makedev` encodes it. On btrfs this need not be the file's
        /// `st_dev`, which names its subvolume.
        raw_device: u64,
        /// The file's inode number.
        raw_inode: u64,
        /// The file's name, as Linux prints it: `d_path`'s text from the
        /// reader's root (` (deleted)` included once the file is unlinked, or
        /// a name such as `anon_inode:[perf_event]` for a file with no path),
        /// with every newline written as the four characters `\012`
        /// (`seq_path`'s escape), so the text holds no newline. Never empty.
        path: Vec<u8>,
    },
    /// `[anon_shmem:<name>]`: shared anonymous memory (`MAP_SHARED |
    /// MAP_ANONYMOUS`) that a process named as for
    /// [`MappingBacking::NamedAnonymous`], whose name Linux prints in place
    /// of its file's path.
    NamedSharedAnonymous {
        /// The device of the memory's file, as for [`MappingBacking::File`].
        raw_device: u64,
        /// The inode number of the memory's file.
        raw_inode: u64,
        /// The name, without `[anon_shmem:` and `]`, as for
        /// [`MappingBacking::NamedAnonymous`].
        name: Vec<u8>,
    },
}

impl MemoryMap {
    /// A list of `mappings`, [`complete`](Self::complete) or not, if
    /// [`MemoryMap::validate`] accepts it; otherwise
    /// `Err(FactError::Errno(EIO))`.
    pub fn new(mappings: Vec<MappingFact>, complete: bool) -> Result<Self, FactError> {
        let map = Self { mappings, complete };
        map.validate()?;
        Ok(map)
    }

    /// Checks that every mapping passes [`MappingFact::validate`] and that
    /// the mappings ascend without overlapping (adjacent mappings may touch),
    /// as Linux lists them. Returns `Err(FactError::Errno(EIO))` otherwise.
    pub fn validate(&self) -> Result<(), FactError> {
        for mapping in &self.mappings {
            mapping.validate()?;
        }
        if self
            .mappings
            .windows(2)
            .any(|pair| pair[1].start < pair[0].end)
        {
            return Err(MALFORMED);
        }
        Ok(())
    }

    /// Parses the whole text Linux prints in a thread's `maps` into a
    /// complete list. Each line is `show_vma_header_prefix`'s
    /// `%08lx-%08lx`, the four permission characters, `%08llx` for the
    /// offset, `%02x:%02x` for the device and `%llu` for the inode, each
    /// followed by a space, then for a mapping with a name the spaces
    /// `seq_pad` adds to fill the line to 72 columns, one more space and the
    /// name, and a newline (`show_map_vma` in Linux's `fs/proc/task_mmu.c`).
    /// That header and that padding are checked exactly: the numbers must
    /// have Linux's digits, case and padding, and no name may begin with a
    /// space. The mappings must also pass [`MemoryMap::validate`]. An empty
    /// text, the file of a thread that has no address space left, is an
    /// empty list.
    ///
    /// Names are checked by class, not against the list of names the kernel
    /// gives, which drivers extend. With a device and inode of zero there is
    /// no file, and the name is none, `[anon:<name>]` with a name `prctl`
    /// accepts, or any other name in brackets, which is a name the kernel
    /// gives a mapping of its own. With a device there is a file, and the
    /// name is `[anon_shmem:<name>]` or else the file's path. No name holds a
    /// NUL byte, which Linux's C strings cannot. A shared mapping of no file
    /// is accepted. Returns `Err(FactError::Errno(EIO))` for text that is not
    /// Linux's format.
    pub fn from_maps(text: &[u8]) -> Result<Self, FactError> {
        let mut mappings: Vec<MappingFact> = Vec::new();
        if !text.is_empty() {
            let body = text.strip_suffix(b"\n").ok_or(MALFORMED)?;
            for line in body.split(|byte| *byte == b'\n') {
                mappings.push(parse_mapping(line).ok_or(MALFORMED)?);
            }
        }
        Self::new(mappings, true)
    }
}

impl MappingBacking {
    /// Whether the backing is a file's: Linux prints its device, its inode
    /// and the mapping's offset in it.
    fn has_file(&self) -> bool {
        matches!(self, Self::File { .. } | Self::NamedSharedAnonymous { .. })
    }

    /// Whether the backing keeps its documented rules: see
    /// [`MappingFact::validate`].
    fn is_valid(&self) -> bool {
        match self {
            Self::Anonymous | Self::Stack | Self::Heap | Self::Vdso | Self::Vvar => true,
            Self::NamedAnonymous(name) => valid_anon_name(name),
            // The parser's classification gives a name this variant only when
            // it is in brackets and is no other variant's.
            Self::Special(name) => {
                !name.contains(&0)
                    && !name.contains(&b'\n')
                    && unfiled_backing(Some(name)).as_ref() == Some(self)
            }
            Self::File {
                raw_device, path, ..
            } => {
                valid_device(*raw_device)
                    && !path.is_empty()
                    && !path.contains(&0)
                    && !path.contains(&b'\n')
                    && !matches!(path.first(), Some(b' ' | b'['))
            }
            Self::NamedSharedAnonymous {
                raw_device, name, ..
            } => valid_device(*raw_device) && valid_anon_name(name),
        }
    }
}

/// Whether `raw_device`, encoded as `libc::makedev` encodes a device, is one
/// Linux prints for a file: a 12-bit major and a 20-bit minor (`MAJOR` and
/// `MINOR` of a kernel `dev_t`), and not `00:00`.
fn valid_device(raw_device: u64) -> bool {
    raw_device != 0 && libc::major(raw_device) <= 0xfff && libc::minor(raw_device) <= 0xf_ffff
}

/// Whether `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)` accepts `name`: at most
/// [`ANON_NAME_MAX`] bytes of printable ASCII but for `\`, `` ` ``, `$`, `[`
/// and `]` (`is_valid_name_char` in Linux's `mm/madvise.c`).
fn valid_anon_name(name: &[u8]) -> bool {
    let valid = |byte: &u8| (0x20..0x7f).contains(byte) && !b"\\`$[]".contains(byte);
    name.len() <= ANON_NAME_MAX && name.iter().all(valid)
}

/// The width `show_vma_header_prefix` pads a line to before a name, with
/// `seq_setwidth(m, 25 + sizeof(void *) * 6 - 1)` on a 64-bit kernel.
const MAPS_NAME_COLUMN: usize = 25 + 8 * 6 - 1;

/// The page size every mapping's range and every file offset is a multiple
/// of: x86-64's, and the least page size of any Linux architecture Reverie
/// supports.
const MAPS_PAGE_SIZE: u64 = 4096;

/// The longest name `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)` accepts:
/// `ANON_VMA_NAME_MAX_LEN`, 80 bytes, less the NUL.
const ANON_NAME_MAX: usize = 79;

/// One line of `maps`, without its newline: see [`MemoryMap::from_maps`].
/// `None` for a line that is not Linux's.
fn parse_mapping(line: &[u8]) -> Option<MappingFact> {
    let (range, rest) = split_at_byte(line, b' ')?;
    let (start, end) = split_at_byte(range, b'-')?;
    let (start, end) = (exact_hex_at_least(start, 8)?, exact_hex_at_least(end, 8)?);
    let (permissions, rest) = split_at_byte(rest, b' ')?;
    let (offset, rest) = split_at_byte(rest, b' ')?;
    let offset = exact_hex_at_least(offset, 8)?;
    let (device, rest) = split_at_byte(rest, b' ')?;
    // The device's bounds, a 12-bit major and a 20-bit minor, are among the
    // rules `MappingFact::new` checks below.
    let (major, minor) = split_at_byte(device, b':')?;
    let major = exact_hex_02(std::str::from_utf8(major).ok()?, u32::MAX)?;
    let minor = exact_hex_02(std::str::from_utf8(minor).ok()?, u32::MAX)?;
    let (inode, rest) = split_at_byte(rest, b' ')?;
    let inode = exact_decimal::<u64>(inode)?;
    // `seq_pad` fills the line to the name column, then adds one space. No
    // name Linux prints is empty or begins with a space (a path begins with
    // `/`, any other name with a letter or `[`), nor holds a NUL, since Linux
    // prints each from a C string (`seq_path`'s `mangle_path` stops at the
    // NUL): the backing's rules below refuse each, so a space too many is
    // never read as the name's.
    let name = if rest.is_empty() {
        None
    } else {
        let padding = MAPS_NAME_COLUMN.saturating_sub(line.len() - rest.len()) + 1;
        let name = rest.get(padding..)?;
        if !rest[..padding].iter().all(|byte| *byte == b' ') {
            return None;
        }
        Some(name)
    };
    let bit = |column: u8, set: u8, bit: i32| if column == set { bit as u32 } else { 0 };
    let prot = match *permissions {
        [
            read @ (b'r' | b'-'),
            write @ (b'w' | b'-'),
            execute @ (b'x' | b'-'),
            b's' | b'p',
        ] => {
            bit(read, b'r', libc::PROT_READ)
                | bit(write, b'w', libc::PROT_WRITE)
                | bit(execute, b'x', libc::PROT_EXEC)
        }
        _ => return None,
    };
    let shared = permissions[3] == b's';
    let backing = if (major, minor) == (0, 0) {
        // No file: no inode (and, as `MappingFact::new` checks, no offset).
        if inode != 0 {
            return None;
        }
        unfiled_backing(name)?
    } else {
        let raw_device = libc::makedev(major, minor);
        match name? {
            name if name.starts_with(b"[") => MappingBacking::NamedSharedAnonymous {
                raw_device,
                raw_inode: inode,
                name: anon_name(name, b"[anon_shmem:")?,
            },
            path => MappingBacking::File {
                raw_device,
                raw_inode: inode,
                path: path.to_vec(),
            },
        }
    };
    // The range's alignment, the offset's, and an offset only with a file.
    MappingFact::new(start, end, prot, shared, offset, backing).ok()
}

/// The backing of a mapping of no file with name `name`, which
/// `get_vma_name` gives in this order: the mapping's `vm_ops->name`, `[vdso]`
/// for the gate area of a kernel that has no other name for it, `[heap]`,
/// `[stack]`, then `[anon:<name>]`. Every such name the kernel gives is in
/// brackets.
fn unfiled_backing(name: Option<&[u8]>) -> Option<MappingBacking> {
    let Some(name) = name else {
        return Some(MappingBacking::Anonymous);
    };
    Some(match name {
        b"[heap]" => MappingBacking::Heap,
        b"[stack]" => MappingBacking::Stack,
        b"[vdso]" => MappingBacking::Vdso,
        b"[vvar]" => MappingBacking::Vvar,
        _ if name.starts_with(b"[anon:") => {
            MappingBacking::NamedAnonymous(anon_name(name, b"[anon:")?)
        }
        // Only memory backed by a file can carry this name.
        _ if name.starts_with(b"[anon_shmem:") => return None,
        [b'[', .., b']'] => MappingBacking::Special(name.to_vec()),
        _ => return None,
    })
}

/// The name in `text`, which must be `prefix`, a name
/// `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME)` accepts, and `]`.
fn anon_name(text: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    let name = text.strip_prefix(prefix)?.strip_suffix(b"]")?;
    valid_anon_name(name).then(|| name.to_vec())
}

/// `text` split at the first `separator`, which belongs to neither part.
fn split_at_byte(text: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    let at = text.iter().position(|byte| *byte == separator)?;
    Some((&text[..at], &text[at + 1..]))
}

/// `seq_put_hex_ll` with a minimum width of `width`: lowercase hexadecimal
/// digits, zero-padded to `width` and no further. The text must be the
/// value printed that way, so a sign, a capital or a digit too many is not
/// accepted.
fn exact_hex_at_least(text: &[u8], width: usize) -> Option<u64> {
    let value = u64::from_str_radix(std::str::from_utf8(text).ok()?, 16).ok()?;
    (format!("{value:0width$x}").as_bytes() == text).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fdinfo header Linux prints first for every descriptor.
    const HEADER: &str = "pos:\t0\nflags:\t02\nmnt_id:\t15\nino:\t1057\n";

    fn parse(rest: &str) -> Result<DescriptorStatus, FactError> {
        DescriptorStatus::from_fdinfo(format!("{HEADER}{rest}").as_bytes())
    }

    fn lock(row: &str) -> Result<HeldLockFact, FactError> {
        let status = parse(&format!("lock:\t{row}\n"))?;
        assert_eq!(status.locks.len(), 1, "{status:?}");
        assert_eq!((status.eventfd_count, status.scm_fds), (None, None));
        Ok(status.locks[0])
    }

    fn held(
        class: LockClass,
        mandatory: bool,
        write: bool,
        device: (u32, u32),
        raw_inode: u64,
        start: u64,
        end: Option<u64>,
    ) -> HeldLockFact {
        HeldLockFact {
            class,
            mandatory,
            write,
            raw_device: libc::makedev(device.0, device.1),
            raw_inode,
            start,
            end,
        }
    }

    #[test]
    fn a_header_alone_reports_nothing() {
        let status = parse("").unwrap();
        assert_eq!(status.eventfd_count, None);
        assert_eq!(status.scm_fds, None);
        assert!(status.locks.is_empty());
    }

    #[test]
    fn an_eventfd_reports_its_count() {
        // `eventfd_show_fdinfo`: `%16llx`, padded with spaces.
        let status =
            parse("eventfd-count:                7\neventfd-id: 3\neventfd-semaphore: 0\n")
                .unwrap();
        assert_eq!(status.eventfd_count, Some(7));
        assert_eq!(status.scm_fds, None);
        assert!(status.locks.is_empty());
        assert_eq!(
            parse("eventfd-count: fffffffffffffffe\n")
                .unwrap()
                .eventfd_count,
            Some(u64::MAX - 1)
        );
        assert_eq!(
            parse("eventfd-count:                0\n")
                .unwrap()
                .eventfd_count,
            Some(0)
        );
    }

    #[test]
    fn a_unix_socket_reports_its_queued_descriptors() {
        let status = parse("scm_fds: 2\n").unwrap();
        assert_eq!(status.scm_fds, Some(2));
        assert_eq!(status.eventfd_count, None);
        assert_eq!(parse("scm_fds: 0\n").unwrap().scm_fds, Some(0));
        assert_eq!(
            parse("scm_fds: 4294967295\n").unwrap().scm_fds,
            Some(u32::MAX)
        );
    }

    #[test]
    fn each_lock_class_and_mode_is_read() {
        assert_eq!(
            lock("1: POSIX  ADVISORY  WRITE 4242 00:2a:2856949021 0 99"),
            Ok(held(
                LockClass::Posix,
                false,
                true,
                (0, 0x2a),
                2856949021,
                0,
                Some(99)
            ))
        );
        assert_eq!(
            lock("1: POSIX  ADVISORY  READ 4242 08:03:555 100 EOF"),
            Ok(held(LockClass::Posix, false, false, (8, 3), 555, 100, None))
        );
        // Linux 5.14 and earlier, on a file with mandatory locking enabled.
        assert_eq!(
            lock("1: POSIX  MANDATORY WRITE 4242 08:03:555 0 EOF"),
            Ok(held(LockClass::Posix, true, true, (8, 3), 555, 0, None))
        );
        assert_eq!(
            lock("1: OFDLCK ADVISORY  READ -1 00:2a:1234 10 19"),
            Ok(held(
                LockClass::OpenFileDescription,
                false,
                false,
                (0, 0x2a),
                1234,
                10,
                Some(19)
            ))
        );
        assert_eq!(
            lock("1: OFDLCK MANDATORY WRITE -1 00:2a:1234 0 EOF"),
            Ok(held(
                LockClass::OpenFileDescription,
                true,
                true,
                (0, 0x2a),
                1234,
                0,
                None
            ))
        );
        assert_eq!(
            lock("1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 0 EOF"),
            Ok(held(
                LockClass::Flock,
                false,
                true,
                (0, 0x2a),
                1234,
                0,
                None
            ))
        );
        assert_eq!(
            lock("1: FLOCK  ADVISORY  READ 4242 00:2a:1234 0 EOF"),
            Ok(held(
                LockClass::Flock,
                false,
                false,
                (0, 0x2a),
                1234,
                0,
                None
            ))
        );
        assert_eq!(
            lock("1: LEASE  ACTIVE    READ 4242 00:2a:1234 0 EOF"),
            Ok(held(
                LockClass::Lease,
                false,
                false,
                (0, 0x2a),
                1234,
                0,
                None
            ))
        );
        assert_eq!(
            lock("1: LEASE  ACTIVE    WRITE 4242 00:2a:1234 0 EOF"),
            Ok(held(
                LockClass::Lease,
                false,
                true,
                (0, 0x2a),
                1234,
                0,
                None
            ))
        );
    }

    #[test]
    fn device_numbers_wider_than_a_byte_are_read() {
        // `%02x` prints at least two digits; a major is 12 bits and a minor
        // 20 bits wide.
        assert_eq!(
            lock("1: OFDLCK ADVISORY  WRITE -1 103:fffff:7 0 EOF").map(|lock| lock.raw_device),
            Ok(libc::makedev(0x103, 0xfffff))
        );
    }

    #[test]
    fn locks_keep_their_order_beside_other_lines() {
        let status = parse(concat!(
            "lock:\t1: FLOCK  ADVISORY  WRITE 4242 00:2a:9 0 EOF\n",
            "lock:\t2: OFDLCK ADVISORY  READ -1 00:2a:9 0 9\n",
            "lock:\t3: POSIX  ADVISORY  WRITE 4242 00:2a:9 10 EOF\n",
            "lock:\t4: LEASE  ACTIVE    READ 4242 00:2a:9 0 EOF\n",
            "tfd:        5 events:       19 data:                5  pos:0 ino:4e5 sdev:f\n",
        ))
        .unwrap();
        let classes: Vec<_> = status.locks.iter().map(|lock| lock.class).collect();
        assert_eq!(
            classes,
            [
                LockClass::Flock,
                LockClass::OpenFileDescription,
                LockClass::Posix,
                LockClass::Lease
            ]
        );
        assert_eq!(status.locks[1].end, Some(9));
        assert_eq!(status.locks[2].start, 10);
    }

    #[test]
    fn every_value_linux_prints_is_read() {
        // The owner's process ID is a C `int`: -1 for an OFD lock, 0 for an
        // owner the reader cannot see, and any other value Linux prints.
        for owner in ["-1", "0", "1", "2147483647", "-2147483648"] {
            assert_eq!(
                lock(&format!(
                    "1: OFDLCK ADVISORY  READ {owner} 00:2a:1234 0 EOF"
                ))
                .map(|lock| lock.raw_inode),
                Ok(1234),
                "{owner}"
            );
        }
        // The widest device, inode and offsets: a 12-bit major, a 20-bit
        // minor, a 64-bit inode and offsets up to `OFFSET_MAX`.
        assert_eq!(
            lock(
                "1: POSIX  ADVISORY  WRITE 1 fff:fffff:18446744073709551615 9223372036854775807 EOF"
            ),
            Ok(held(
                LockClass::Posix,
                false,
                true,
                (0xfff, 0xfffff),
                u64::MAX,
                i64::MAX as u64,
                None
            ))
        );
        assert_eq!(
            lock("1: POSIX  ADVISORY  READ 1 00:00:0 0 9223372036854775806"),
            Ok(held(
                LockClass::Posix,
                false,
                false,
                (0, 0),
                0,
                0,
                Some(i64::MAX as u64 - 1)
            ))
        );
        // A one-byte lock.
        assert_eq!(
            lock("1: POSIX  ADVISORY  READ 1 00:2a:1234 5 5").map(|lock| (lock.start, lock.end)),
            Ok((5, Some(5)))
        );
    }

    #[test]
    fn locks_this_type_cannot_describe_are_not_provided() {
        for row in [
            "1: DELEG  ACTIVE    READ 4242 00:2a:1234 0 EOF",
            "1: DELEG  ACTIVE    WRITE 4242 00:2a:1234 0 EOF",
            "1: LEASE  BREAKING  UNLCK 4242 00:2a:1234 0 EOF",
            "1: LEASE  BREAKING  READ 4242 00:2a:1234 0 EOF",
            "1: DELEG  BREAKING  UNLCK 4242 00:2a:1234 0 EOF",
            "1: DELEG  BREAKING  READ 4242 00:2a:1234 0 EOF",
            // Linux 5.15 and earlier: `LOCK_MAND`'s access column.
            "1: FLOCK  MSNFS     RW    4242 00:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     READ  4242 00:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     WRITE 4242 00:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     NONE  4242 00:2a:1234 0 EOF",
        ] {
            assert_eq!(lock(row), Err(FactError::NotProvided), "{row}");
        }
        // One undescribable lock withholds the others too.
        assert_eq!(
            parse(concat!(
                "lock:\t1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 0 EOF\n",
                "lock:\t2: LEASE  BREAKING  UNLCK 4242 00:2a:1234 0 EOF\n",
            )),
            Err(FactError::NotProvided)
        );
        // A malformed line outweighs an undescribable one, before or after it.
        assert_eq!(
            parse(concat!(
                "lock:\t1: DELEG  ACTIVE    READ 4242 00:2a:1234 0 EOF\n",
                "lock:\t2: POSIX  ADVISORY  WRITE 4242 00:2a:1234 9 3\n",
            )),
            Err(MALFORMED)
        );
        assert_eq!(
            parse(concat!(
                "lock:\t1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 9 3\n",
                "lock:\t2: DELEG  ACTIVE    READ 4242 00:2a:1234 0 EOF\n",
            )),
            Err(MALFORMED)
        );
    }

    #[test]
    fn malformed_rows_of_undescribable_locks_are_refused() {
        // The whole row is checked before its class withholds the fact.
        for row in [
            "2: DELEG  ACTIVE    READ 4242 00:2a:1234 0 EOF",
            "1: DELEG ACTIVE READ 4242 00:2a:1234 0 EOF",
            "1: DELEG  ACTIVE    UNLCK 4242 00:2a:1234 0 EOF",
            "1: DELEG  ACTIVE    READ x 00:2a:1234 0 EOF",
            "1: DELEG  ACTIVE    READ 4242 00:2a:1234 1 EOF",
            "1: DELEG  ACTIVE    READ 4242 00:2a:1234 0 EOF extra",
            "1: LEASE  BREAKING  WRITE 4242 00:2a:1234 0 EOF",
            "1: LEASE  BREAKING  UNLCK 4242 1000:2a:1234 0 EOF",
            "1: DELEG  BREAKING  READ 4242 0:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     RW 4242 00:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     READ 4242 00:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     UNLCK 4242 00:2a:1234 0 EOF",
            "1: FLOCK  MSNFS     NONE  4242 00:2a:1234 0 99",
            "1: FLOCK  MSNFS     NONE  4242 <none>:0 0 EOF",
        ] {
            assert_eq!(lock(row), Err(MALFORMED), "{row}");
        }
    }

    #[test]
    fn malformed_lock_lines_are_refused() {
        for row in [
            "",
            "POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "x: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "1 POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF extra",
            "1: ACCESS ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "1: POSIX  *NOINODE* WRITE 4242 00:2a:1234 0 EOF",
            "1: UNKNOWN UNKNOWN  WRITE 4242 00:2a:1234 0 EOF",
            "1: LEASE  BREAKER   READ 4242 00:2a:1234 0 EOF",
            "1: FLOCK  MANDATORY WRITE 4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  UNLCK 4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 <none>:0 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234:5 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 0g:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:12x4 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 100000000:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE pid 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 -1 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 9 3",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 18446744073709551616",
            "1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 1 EOF",
            "1: LEASE  ACTIVE    READ 4242 00:2a:1234 0 0",
            "1: -> POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
        ] {
            assert_eq!(lock(row), Err(MALFORMED), "{row}");
        }
    }

    #[test]
    fn lock_lines_need_linux_spacing_digits_and_ranges() {
        for row in [
            // The id: `%lld: `, counting from 1.
            "2: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "01: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "+1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "1:  POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            "1:\tPOSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF",
            // The class and type columns, padded with spaces as Linux pads
            // them, in capitals.
            "1: POSIX ADVISORY WRITE 4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY WRITE 4242 00:2a:1234 0 EOF",
            "1: POSIX\tADVISORY\tWRITE 4242 00:2a:1234 0 EOF",
            "1: posix  advisory  write 4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  write 4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE  4242 00:2a:1234 0 EOF",
            "1: OFDLCK ADVISORY  READ  -1 00:2a:1234 0 EOF",
            // One space between the remaining fields, and none after them.
            "1: POSIX  ADVISORY  WRITE 4242  00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234  0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0  EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF ",
            "1: POSIX  ADVISORY  WRITE 4242\t00:2a:1234 0 EOF",
            // The owner: `%d` of a C `int`.
            "1: POSIX  ADVISORY  WRITE +4242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 04242 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE -0 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 2147483648 00:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE -2147483649 00:2a:1234 0 EOF",
            // The device: `%02x:%02x` of a 12-bit major and a 20-bit minor.
            "1: POSIX  ADVISORY  WRITE 4242 00:2A:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 0:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 000:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:002a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 +0:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 1000:2a:1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:100000:1234 0 EOF",
            // The inode: `%llu`.
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:01234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:+1234 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:-1 0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:18446744073709551616 0 EOF",
            // The range: `%Ld %Ld` or `%Ld EOF`, from 0 to `OFFSET_MAX`, with
            // an end of `OFFSET_MAX` printed as `EOF`.
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 00 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 +0 EOF",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 eof",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 -1",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 09",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 9223372036854775807",
            "1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 9223372036854775808 EOF",
            "1: OFDLCK ADVISORY  WRITE -1 00:2a:1234 10 9",
            "1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 0 99",
            "1: LEASE  ACTIVE    READ 4242 00:2a:1234 00 EOF",
        ] {
            assert_eq!(lock(row), Err(MALFORMED), "{row}");
        }
    }

    #[test]
    fn malformed_records_are_refused() {
        // `eventfd-count: %16llx` of 7.
        const COUNT: &str = "eventfd-count:                7\n";
        const POSIX: &str = "lock:\t1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF\n";
        for text in [
            "".to_string(),
            "\n".to_string(),
            "flags:\t02\npos:\t0\n".to_string(),
            "pos:\t0\nflags:\t02".to_string(),
            // `pos:\t%lli`.
            "pos: 0\n".to_string(),
            "pos:0\n".to_string(),
            "pos:\t\n".to_string(),
            "pos:\t00\n".to_string(),
            "pos:\t+1\n".to_string(),
            "pos:\t1 \n".to_string(),
            "pos:\t9223372036854775808\n".to_string(),
            // `lock:\t`.
            format!("{HEADER}lock: 1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF\n"),
            format!("{HEADER}lock:1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF\n"),
            format!("{HEADER}lock:\t\t1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 EOF\n"),
            format!("{HEADER}lock:\n"),
            // The locks are numbered 1, 2, 3, ... in order.
            format!("{HEADER}{POSIX}{POSIX}"),
            format!("{HEADER}{POSIX}lock:\t3: OFDLCK ADVISORY  READ -1 00:2a:1234 0 EOF\n"),
            // `eventfd-count: %16llx`: lowercase digits right-aligned in 16
            // columns of spaces.
            format!("{HEADER}eventfd-count: \n"),
            format!("{HEADER}eventfd-count:\t               7\n"),
            format!("{HEADER}eventfd-count:               7\n"),
            format!("{HEADER}eventfd-count:                 7\n"),
            format!("{HEADER}eventfd-count: 7\n"),
            format!("{HEADER}eventfd-count: 0000000000000007\n"),
            format!("{HEADER}eventfd-count:                A\n"),
            format!("{HEADER}eventfd-count: FFFFFFFFFFFFFFFE\n"),
            format!("{HEADER}eventfd-count:               +7\n"),
            format!("{HEADER}eventfd-count:               7g\n"),
            format!("{HEADER}eventfd-count:               7 \n"),
            format!("{HEADER}eventfd-count: 10000000000000000\n"),
            format!("{HEADER}{COUNT}{COUNT}"),
            // `scm_fds: %u`.
            format!("{HEADER}scm_fds:2\n"),
            format!("{HEADER}scm_fds:\t2\n"),
            format!("{HEADER}scm_fds:  2\n"),
            format!("{HEADER}scm_fds: 02\n"),
            format!("{HEADER}scm_fds: +2\n"),
            format!("{HEADER}scm_fds: 2 \n"),
            format!("{HEADER}scm_fds: -1\n"),
            format!("{HEADER}scm_fds: 4294967296\n"),
            format!("{HEADER}scm_fds: 1\nscm_fds: 1\n"),
            // An eventfd is not a socket, and the locks come first.
            format!("{HEADER}{COUNT}scm_fds: 1\n"),
            format!("{HEADER}scm_fds: 1\n{COUNT}"),
            format!("{HEADER}{COUNT}{POSIX}"),
            format!("{HEADER}scm_fds: 1\n{POSIX}"),
        ] {
            assert_eq!(
                DescriptorStatus::from_fdinfo(text.as_bytes()),
                Err(MALFORMED),
                "{text:?}"
            );
        }
        let text = b"pos:\t0\nlock:\t1: POSIX  ADVISORY  WRITE 4242 00:2a:1234 0 \xff\n";
        assert_eq!(DescriptorStatus::from_fdinfo(text), Err(MALFORMED));
    }

    #[test]
    fn a_record_reads_every_header_position_linux_prints() {
        // `f_pos` is a `loff_t`, which Linux prints signed.
        for position in ["0", "-1", "9223372036854775807", "-9223372036854775808"] {
            assert_eq!(
                DescriptorStatus::from_fdinfo(format!("pos:\t{position}\n").as_bytes())
                    .map(|status| status.locks.len()),
                Ok(0),
                "{position}"
            );
        }
    }

    #[test]
    fn lines_of_other_state_are_skipped() {
        // An inotify descriptor's watch line, an unknown line, an empty line,
        // and bytes that are not UTF-8 on a line the parser does not read.
        let mut text = HEADER.as_bytes().to_vec();
        text.extend_from_slice(
            b"inotify wd:1 ino:4e5 sdev:2a mask:fff ignored_mask:0 fhandle-bytes:8\n",
        );
        text.extend_from_slice(b"new-line: x\n\nopaque: \xff\xfe\n");
        text.extend_from_slice(b"locks: 1\neventfd-id: 3\nscm_fds_total: 1\n");
        let status = DescriptorStatus::from_fdinfo(&text).unwrap();
        assert_eq!(status.eventfd_count, None);
        assert_eq!(status.scm_fds, None);
        assert!(status.locks.is_empty());
    }
}

#[cfg(test)]
mod signal_sets_tests {
    use super::*;

    /// The bit of signal `signal` in a set.
    fn bit(signal: i32) -> u64 {
        1 << (signal - 1)
    }

    /// The constructor takes the sets in the order Linux prints them, and a
    /// tool passing the fact through its RPC gets the same value back.
    #[test]
    fn the_sets_keep_their_order_and_their_value() {
        let sets = SignalSets::new(
            bit(libc::SIGUSR1),
            bit(libc::SIGUSR2),
            bit(libc::SIGINT) | bit(64),
            bit(libc::SIGHUP),
            bit(libc::SIGTERM) | bit(libc::SIGRTMIN()),
        );
        assert_eq!(sets.pending, 0x200);
        assert_eq!(sets.shared_pending, 0x800);
        assert_eq!(sets.blocked, 0x8000_0000_0000_0002);
        assert_eq!(sets.ignored, 0x1);
        assert_eq!(sets.caught, bit(libc::SIGTERM) | bit(libc::SIGRTMIN()));
        let text = serde_json::to_string(&sets).unwrap();
        assert_eq!(serde_json::from_str::<SignalSets>(&text).unwrap(), sets);
    }
}

#[cfg(test)]
mod link_path_tests {
    use super::*;

    const MALFORMED: Result<LinkPath, FactError> = Err(FactError::Errno(Errno::EIO));

    /// A text that begins with `/` is a path, whatever follows: a file's
    /// path, an unlinked file's, a memfd's and the root's.
    #[test]
    fn a_text_that_begins_with_a_slash_is_a_path() {
        for text in [
            &b"/tmp/work/regular"[..],
            b"/tmp/work/deleted (deleted)",
            b"/memfd:link-path (deleted)",
            b"/dev/null",
            b"/",
            b"/ (deleted)",
            b"/proc/4242/maps",
            b"/dir with spaces/\xff\xfe not UTF-8",
        ] {
            assert_eq!(
                LinkPath::from_readlink(text),
                Ok(LinkPath::Path(text.to_vec())),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// A text that does not begin with `/` is an object's anonymous name.
    #[test]
    fn a_text_that_does_not_begin_with_a_slash_is_anonymous() {
        for text in [
            &b"pipe:[4242]"[..],
            b"socket:[18446744073709551615]",
            b"anon_inode:[eventfd]",
            b"anon_inode:[signalfd]",
            b"anon_inode:inotify",
            b"anon_inode:[pidfd]",
            b"net:[4026531840]",
        ] {
            assert_eq!(
                LinkPath::from_readlink(text),
                Ok(LinkPath::Anonymous(text.to_vec())),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// `d_path`'s whole text, ` (deleted)` included, fits in `PATH_MAX - 1`
    /// bytes, and `dynamic_dname`'s in `NAME_MAX - 1`; a byte more is not
    /// Linux's.
    #[test]
    fn the_bounds_are_linuxs() {
        let longest = [b"/".as_slice(), &vec![b'a'; PATH_MAX - 2]].concat();
        assert_eq!(longest.len(), 4095);
        assert_eq!(
            LinkPath::from_readlink(&longest),
            Ok(LinkPath::Path(longest.clone()))
        );
        assert_eq!(
            LinkPath::from_readlink(&[longest.as_slice(), b"a"].concat()),
            MALFORMED
        );
        let deleted = [&vec![b'/'; PATH_MAX - 11], b" (deleted)".as_slice()].concat();
        assert_eq!(deleted.len(), 4095);
        assert!(matches!(
            LinkPath::from_readlink(&deleted),
            Ok(LinkPath::Path(_))
        ));
        let anonymous = [b"anon_inode:".as_slice(), &vec![b'x'; NAME_MAX - 12]].concat();
        assert_eq!(anonymous.len(), 254);
        assert_eq!(
            LinkPath::from_readlink(&anonymous),
            Ok(LinkPath::Anonymous(anonymous.clone()))
        );
        assert_eq!(
            LinkPath::from_readlink(&[anonymous.as_slice(), b"x"].concat()),
            MALFORMED
        );
    }

    /// An empty text, and one with a NUL byte anywhere, are not Linux's.
    #[test]
    fn an_empty_text_or_a_nul_byte_is_malformed() {
        for text in [
            &b""[..],
            b"\0",
            b"/tmp\0/x",
            b"/tmp/x\0",
            b"pipe:[1]\0",
            b"\0/tmp",
        ] {
            assert_eq!(LinkPath::from_readlink(text), MALFORMED, "{text:?}");
        }
    }

    /// The text comes back whichever kind it is, and the fact survives a
    /// tool's RPC, as the other facts do.
    #[test]
    fn the_text_comes_back_and_survives_a_round_trip() {
        for link in [
            LinkPath::from_readlink(b"/tmp/work/regular").unwrap(),
            LinkPath::from_readlink(b"pipe:[7]").unwrap(),
        ] {
            let text = serde_json::to_string(&link).unwrap();
            assert_eq!(serde_json::from_str::<LinkPath>(&text).unwrap(), link);
        }
        assert_eq!(
            LinkPath::from_readlink(b"/tmp/work/regular")
                .unwrap()
                .as_bytes(),
            b"/tmp/work/regular"
        );
        assert_eq!(
            LinkPath::from_readlink(b"socket:[9]").unwrap().as_bytes(),
            b"socket:[9]"
        );
        for link in [
            PathLink::Descriptor(-1),
            PathLink::Descriptor(3),
            PathLink::Executable,
            PathLink::WorkingDirectory,
        ] {
            let text = serde_json::to_string(&link).unwrap();
            assert_eq!(serde_json::from_str::<PathLink>(&text).unwrap(), link);
        }
    }
}

#[cfg(test)]
mod memory_map_tests {
    use super::*;

    const MALFORMED: Result<MemoryMap, FactError> = Err(FactError::Errno(Errno::EIO));
    const MALFORMED_FACT: FactError = FactError::Errno(Errno::EIO);
    const RW: u32 = (libc::PROT_READ | libc::PROT_WRITE) as u32;

    /// `map` as Linux's `show_map_vma` prints it, written here from Linux's
    /// rules independently of the parser, so that a text the parser read
    /// can be printed again and compared byte for byte.
    fn render(map: &MemoryMap) -> Vec<u8> {
        let mut text = Vec::new();
        for mapping in &map.mappings {
            let (device, inode) = match &mapping.backing {
                MappingBacking::File {
                    raw_device,
                    raw_inode,
                    ..
                }
                | MappingBacking::NamedSharedAnonymous {
                    raw_device,
                    raw_inode,
                    ..
                } => (*raw_device, *raw_inode),
                _ => (0, 0),
            };
            let bit = |bit: i32, set: char| {
                if mapping.prot & bit as u32 != 0 {
                    set
                } else {
                    '-'
                }
            };
            let header = format!(
                "{:08x}-{:08x} {}{}{}{} {:08x} {:02x}:{:02x} {} ",
                mapping.start,
                mapping.end,
                bit(libc::PROT_READ, 'r'),
                bit(libc::PROT_WRITE, 'w'),
                bit(libc::PROT_EXEC, 'x'),
                if mapping.shared { 's' } else { 'p' },
                mapping.offset,
                libc::major(device),
                libc::minor(device),
                inode,
            );
            let name: Option<Vec<u8>> = match &mapping.backing {
                MappingBacking::Anonymous => None,
                MappingBacking::Stack => Some(b"[stack]".to_vec()),
                MappingBacking::Heap => Some(b"[heap]".to_vec()),
                MappingBacking::Vdso => Some(b"[vdso]".to_vec()),
                MappingBacking::Vvar => Some(b"[vvar]".to_vec()),
                MappingBacking::NamedAnonymous(name) => {
                    Some([b"[anon:".as_slice(), name, b"]"].concat())
                }
                MappingBacking::Special(name) => Some(name.clone()),
                MappingBacking::File { path, .. } => Some(path.clone()),
                MappingBacking::NamedSharedAnonymous { name, .. } => {
                    Some([b"[anon_shmem:".as_slice(), name, b"]"].concat())
                }
            };
            text.extend_from_slice(header.as_bytes());
            if let Some(name) = name {
                // `seq_pad`: spaces to column 72, then one more.
                text.resize(text.len() + 72usize.saturating_sub(header.len()) + 1, b' ');
                text.extend_from_slice(&name);
            }
            text.push(b'\n');
        }
        text
    }

    fn mapping(start: u64, end: u64, prot: u32, backing: MappingBacking) -> MappingFact {
        MappingFact::new(start, end, prot, false, 0, backing).unwrap()
    }

    fn file(raw_device: u64, raw_inode: u64, path: &[u8]) -> MappingBacking {
        MappingBacking::File {
            raw_device,
            raw_inode,
            path: path.to_vec(),
        }
    }

    /// The text of one line, parsed alone.
    fn line(text: &str) -> Result<MappingFact, FactError> {
        let map = MemoryMap::from_maps(format!("{text}\n").as_bytes())?;
        assert!(map.complete);
        assert_eq!(map.mappings.len(), 1, "{map:?}");
        Ok(map.mappings[0].clone())
    }

    /// The maps of a real process: a child of this test, forked so that its
    /// address space is this one's and stopped so that nothing changes it
    /// while it is read. Before the fork the test maps a file of its own
    /// whose name is not UTF-8. The text the kernel printed parses, every
    /// line of it, and prints again to the same bytes, compared as bytes;
    /// the file's line has its name's bytes as the kernel printed them. The
    /// text has the kernel's own names, among them the stack, the vDSO's
    /// pages and x86-64's `[vsyscall]`, which lies above the rest.
    #[test]
    fn a_real_maps_text_parses_and_prints_again_byte_for_byte() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;

        let name: &[u8] = b"reverie-maps-\xff\xfe-not-utf8";
        let directory = std::env::temp_dir().join(format!("reverie-maps-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        // The kernel prints the path with every symbolic link resolved.
        let directory = std::fs::canonicalize(&directory).unwrap();
        let path = directory.join(std::ffi::OsStr::from_bytes(name));
        std::fs::write(&path, [0x5a; 4096]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: a fresh private read-only mapping of the whole open file.
        let view = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(
            view,
            libc::MAP_FAILED,
            "{}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the child only pauses until it is killed.
        let child = unsafe { libc::fork() };
        if child == 0 {
            loop {
                // SAFETY: pause takes no arguments.
                unsafe { libc::pause() };
            }
        }
        assert!(child > 0, "{}", std::io::Error::last_os_error());
        let text = std::fs::read(format!("/proc/{child}/maps"));
        // SAFETY: the child is this process's own and not reaped.
        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0;
        // SAFETY: status is writable.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        // SAFETY: view is the mapping made above, unmapped once.
        assert_eq!(unsafe { libc::munmap(view, 4096) }, 0);
        drop(file);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        let text = text.unwrap();
        let map = MemoryMap::from_maps(&text).unwrap();
        assert!(map.complete);
        assert_eq!(map.mappings.len(), text.split(|b| *b == b'\n').count() - 1);
        let printed = render(&map);
        assert!(
            printed == text,
            "printed:\n{}\nread:\n{}",
            String::from_utf8_lossy(&printed),
            String::from_utf8_lossy(&text)
        );
        let path_bytes = path.as_os_str().as_bytes();
        assert!(
            map.mappings.iter().any(|mapping| matches!(
                &mapping.backing,
                MappingBacking::File { path, .. } if path.as_slice() == path_bytes
            )),
            "{map:?}"
        );
        let names: Vec<&MappingBacking> = map.mappings.iter().map(|m| &m.backing).collect();
        assert!(names.contains(&&MappingBacking::Stack), "{map:?}");
        assert!(names.contains(&&MappingBacking::Vdso), "{map:?}");
        assert!(
            names
                .iter()
                .any(|backing| matches!(backing, MappingBacking::File { .. })),
            "{map:?}"
        );
        #[cfg(target_arch = "x86_64")]
        if let Some(last) = map.mappings.last().filter(|last| last.start >> 63 != 0) {
            assert_eq!(
                last.backing,
                MappingBacking::Special(b"[vsyscall]".to_vec())
            );
        }
    }

    /// Each backing, from the name and the device and inode beside it.
    #[test]
    fn each_backing_is_read_from_its_name() {
        for (text, backing) in [
            (
                "7f7110fde000-7f7111000000 rw-p 00000000 00:00 0 ",
                MappingBacking::Anonymous,
            ),
            (
                "557afa72f000-557afa750000 rw-p 00000000 00:00 0                          [heap]",
                MappingBacking::Heap,
            ),
            (
                "7ffe3ffa4000-7ffe3ffc8000 rw-p 00000000 00:00 0                          [stack]",
                MappingBacking::Stack,
            ),
            (
                "7f711128f000-7f7111291000 r-xp 00000000 00:00 0                          [vdso]",
                MappingBacking::Vdso,
            ),
            (
                "7f7111289000-7f711128d000 r--p 00000000 00:00 0                          [vvar]",
                MappingBacking::Vvar,
            ),
            (
                "7f711128d000-7f711128f000 r--p 00000000 00:00 0                          [vvar_vclock]",
                MappingBacking::Special(b"[vvar_vclock]".to_vec()),
            ),
            (
                "7fffffffe000-7ffffffff000 r-xp 00000000 00:00 0                          [uprobes]",
                MappingBacking::Special(b"[uprobes]".to_vec()),
            ),
            (
                "7f0000000000-7f0000001000 rw-p 00000000 00:00 0                          [anon:glibc: malloc arena]",
                MappingBacking::NamedAnonymous(b"glibc: malloc arena".to_vec()),
            ),
            (
                "7f0000000000-7f0000001000 rw-p 00000000 00:00 0                          [anon:]",
                MappingBacking::NamedAnonymous(Vec::new()),
            ),
            (
                "557afa725000-557afa727000 r--p 00000000 00:20 100490                     /usr/bin/cat",
                file(libc::makedev(0, 0x20), 100490, b"/usr/bin/cat"),
            ),
            (
                "7f0000000000-7f0000002000 rw-s 00000000 00:01 4242                       /dev/zero (deleted)",
                file(libc::makedev(0, 1), 4242, b"/dev/zero (deleted)"),
            ),
            (
                "7f0000000000-7f0000002000 rw-s 00000000 00:01 4243                       /memfd:maps (deleted)",
                file(libc::makedev(0, 1), 4243, b"/memfd:maps (deleted)"),
            ),
            (
                "7f0000000000-7f0000009000 rw-s 00000000 00:0f 1057                       anon_inode:[perf_event]",
                file(libc::makedev(0, 0xf), 1057, b"anon_inode:[perf_event]"),
            ),
            (
                "7f0000000000-7f0000001000 r--p 00000000 08:03 555                        /tmp/a\\012b",
                file(libc::makedev(8, 3), 555, b"/tmp/a\\012b"),
            ),
            (
                "7f0000000000-7f0000001000 r--p 00000000 08:03 555                        / with  spaces ",
                file(libc::makedev(8, 3), 555, b"/ with  spaces "),
            ),
            (
                "7f0000000000-7f0000002000 rw-s 00000000 00:01 4244                       [anon_shmem:shared name]",
                MappingBacking::NamedSharedAnonymous {
                    raw_device: libc::makedev(0, 1),
                    raw_inode: 4244,
                    name: b"shared name".to_vec(),
                },
            ),
        ] {
            assert_eq!(line(text).map(|m| m.backing), Ok(backing), "{text}");
        }
        assert_eq!(
            line(
                "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]"
            ),
            Ok(mapping(
                0xffff_ffff_ff60_0000,
                0xffff_ffff_ff60_1000,
                libc::PROT_EXEC as u32,
                MappingBacking::Special(b"[vsyscall]".to_vec())
            ))
        );
    }

    /// The range, permissions, offset, device and inode, at every width
    /// Linux prints them.
    #[test]
    fn every_column_is_read_at_every_width() {
        assert_eq!(
            line("00400000-00401000 r-xp 00000000 08:03 12                                 /bin/x"),
            Ok(MappingFact::new(
                0x40_0000,
                0x40_1000,
                (libc::PROT_READ | libc::PROT_EXEC) as u32,
                false,
                0,
                file(libc::makedev(8, 3), 12, b"/bin/x")
            )
            .unwrap())
        );
        // Every permission column, and a shared mapping.
        for (permissions, prot, shared) in [
            ("---p", 0, false),
            ("r--p", libc::PROT_READ, false),
            ("-w-p", libc::PROT_WRITE, false),
            ("--xp", libc::PROT_EXEC, false),
            (
                "rwxp",
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                false,
            ),
            ("rw-s", libc::PROT_READ | libc::PROT_WRITE, true),
            ("r--s", libc::PROT_READ, true),
            ("---s", 0, true),
        ] {
            let parsed = line(&format!(
                "00001000-00002000 {permissions} 00000000 00:00 0 "
            ))
            .unwrap();
            assert_eq!(
                (parsed.prot, parsed.shared),
                (prot as u32, shared),
                "{permissions}"
            );
        }
        // An offset of more than eight digits, a 12-bit major and a 20-bit
        // minor, and a 64-bit inode: a header longer than the name column,
        // which `seq_pad` follows with one space.
        assert_eq!(
            line(
                "7f0000000000-7f0000001000 r--s 7ffffffffffff000 fff:fffff 18446744073709551615  /f"
            ),
            Ok(MappingFact::new(
                0x7f00_0000_0000,
                0x7f00_0000_1000,
                libc::PROT_READ as u32,
                true,
                0x7fff_ffff_ffff_f000,
                file(libc::makedev(0xfff, 0xfffff), u64::MAX, b"/f")
            )
            .unwrap())
        );
        // The lowest range Linux can print and a range at the top of the
        // address space.
        assert_eq!(
            line("00000000-00001000 r--p 00000000 00:00 0 ").map(|m| (m.start, m.end)),
            Ok((0, 0x1000))
        );
        assert_eq!(
            line("fffffffffffff000-ffffffffffffffff r--p 00000000 00:00 0 ")
                .map(|m| (m.start, m.end)),
            MALFORMED.map(|_| (0, 0))
        );
    }

    /// The name follows exactly the spaces `seq_pad` adds after the header,
    /// whose last column is a space: up to column 72, then one more; after a
    /// header of 72 columns or more, the one alone. A name never begins with
    /// a space, so one space too many is refused, not read as the name's.
    #[test]
    fn the_name_is_at_linuxs_column() {
        // A header of 48 columns: 24 spaces to column 72, then one.
        let header = "7ffe3ffa4000-7ffe3ffc8000 rw-p 00000000 00:00 0 ";
        assert_eq!(header.len(), 48);
        for spaces in [0, 1, 23, 24, 26, 30] {
            assert_eq!(
                MemoryMap::from_maps(format!("{header}{}[stack]\n", " ".repeat(spaces)).as_bytes()),
                MALFORMED,
                "{spaces}"
            );
        }
        assert!(
            MemoryMap::from_maps(format!("{header}{}[stack]\n", " ".repeat(25)).as_bytes()).is_ok()
        );
        // A header of 71 columns needs two spaces, of 72 one, of 73 one.
        for (inode, columns, spaces) in [
            ("1234567890123456", 71, 2),
            ("12345678901234567", 72, 1),
            ("123456789012345678", 73, 1),
        ] {
            let header = format!("7f0000000000-7f0000001000 r--s 7ffffffffffff000 08:03 {inode} ");
            assert_eq!(header.len(), columns);
            let text = format!("{header}{}/f\n", " ".repeat(spaces));
            assert!(MemoryMap::from_maps(text.as_bytes()).is_ok(), "{text}");
            for wrong in [spaces - 1, spaces + 1] {
                let text = format!("{header}{}/f\n", " ".repeat(wrong));
                assert_eq!(MemoryMap::from_maps(text.as_bytes()), MALFORMED, "{text}");
            }
        }
        // A tab is not a space.
        assert_eq!(
            MemoryMap::from_maps(format!("{header}{}\t[stack]\n", " ".repeat(24)).as_bytes()),
            MALFORMED
        );
    }

    /// Ranges are page-aligned and not empty, and mappings ascend without
    /// overlapping; adjacent ones may touch. An empty text is an empty list.
    #[test]
    fn mappings_ascend_apart_and_an_empty_text_is_an_empty_map() {
        assert_eq!(
            MemoryMap::from_maps(b""),
            Ok(MemoryMap::new(Vec::new(), true).unwrap())
        );
        let a = "00400000-00401000 r--p 00000000 00:00 0 \n";
        let b = "00401000-00402000 rw-p 00000000 00:00 0 \n";
        let c = "00400800-00403000 rw-p 00000000 00:00 0 \n";
        let d = "00400000-00401000 r--p 00000000 00:00 0 \n";
        let map = MemoryMap::from_maps(format!("{a}{b}").as_bytes()).unwrap();
        assert_eq!(
            map.mappings,
            [
                mapping(
                    0x40_0000,
                    0x40_1000,
                    libc::PROT_READ as u32,
                    MappingBacking::Anonymous
                ),
                mapping(0x40_1000, 0x40_2000, RW, MappingBacking::Anonymous),
            ]
        );
        for text in [format!("{b}{a}"), format!("{a}{c}"), format!("{a}{d}")] {
            assert_eq!(MemoryMap::from_maps(text.as_bytes()), MALFORMED, "{text}");
        }
    }

    /// A line as Linux prints it from `header`, which ends with the space
    /// after the inode: for a mapping with a name, the spaces `seq_pad` adds
    /// to column 72, one more, and the name.
    fn print(header: &str, name: Option<&str>) -> String {
        match name {
            None => header.to_owned(),
            Some(name) => format!(
                "{header}{}{name}",
                " ".repeat(72usize.saturating_sub(header.len()) + 1)
            ),
        }
    }

    /// Text that is not Linux's: each line is one Linux prints, padded as
    /// Linux pads it, with one thing changed. The lines unchanged are read.
    #[test]
    fn malformed_maps_are_refused() {
        let file = Some("/f");
        for (header, name) in [
            ("00400000-00401000 r--p 00000000 00:00 0 ", None),
            ("00400000-00401000 r--p 00001000 08:03 5 ", file),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:ab]"),
            ),
            (
                "00400000-00401000 rw-s 00000000 00:01 7 ",
                Some("[anon_shmem:ab]"),
            ),
            ("00400000-00401000 rw-p 00000000 00:00 0 ", Some("[heap]")),
        ] {
            let text = print(header, name);
            assert!(line(&text).is_ok(), "{text}");
        }
        for (header, name) in [
            // The range: `%08lx-%08lx`, lowercase, page-aligned, not empty.
            ("0400000-00401000 r--p 00000000 00:00 0 ", None),
            ("00400000-0401000 r--p 00000000 00:00 0 ", None),
            ("000400000-00401000 r--p 00000000 00:00 0 ", None),
            ("0000000000400000-00401000 r--p 00000000 00:00 0 ", None),
            ("00400000-00401000  r--p 00000000 00:00 0 ", None),
            ("7F0000000000-7f0000001000 r--p 00000000 00:00 0 ", None),
            ("+0400000-00401000 r--p 00000000 00:00 0 ", None),
            ("00400000_00401000 r--p 00000000 00:00 0 ", None),
            ("00400000-00401000-00402000 r--p 00000000 00:00 0 ", None),
            ("00400800-00401000 r--p 00000000 00:00 0 ", None),
            ("00400000-00401800 r--p 00000000 00:00 0 ", None),
            ("00401000-00401000 r--p 00000000 00:00 0 ", None),
            ("00402000-00401000 r--p 00000000 00:00 0 ", None),
            (
                "10000000000000000-10000000000001000 r--p 00000000 00:00 0 ",
                None,
            ),
            // The permissions.
            ("00400000-00401000 r--q 00000000 00:00 0 ", None),
            ("00400000-00401000 R--p 00000000 00:00 0 ", None),
            ("00400000-00401000 rw-xp 00000000 00:00 0 ", None),
            ("00400000-00401000 r-p 00000000 00:00 0 ", None),
            ("00400000-00401000 wr-p 00000000 00:00 0 ", None),
            ("00400000-00401000 r-wp 00000000 00:00 0 ", None),
            // The offset: `%08llx`, a multiple of the page size, zero
            // without a file.
            ("00400000-00401000 r--p 0001000 08:03 5 ", file),
            ("00400000-00401000 r--p 000001000 08:03 5 ", file),
            ("00400000-00401000 r--p 0000100A 08:03 5 ", file),
            ("00400000-00401000 r--p +0001000 08:03 5 ", file),
            ("00400000-00401000 r--p 00000800 08:03 5 ", file),
            ("00400000-00401000 r--p 00001000 00:00 0 ", None),
            // The device: `%02x:%02x`, a 12-bit major and a 20-bit minor.
            ("00400000-00401000 r--p 00001000 8:03 5 ", file),
            ("00400000-00401000 r--p 00001000 08:3 5 ", file),
            ("00400000-00401000 r--p 00001000 008:03 5 ", file),
            ("00400000-00401000 r--p 00001000 08:003 5 ", file),
            ("00400000-00401000 r--p 00001000 0A:03 5 ", file),
            ("00400000-00401000 r--p 00001000 +8:03 5 ", file),
            ("00400000-00401000 r--p 00001000 1000:03 5 ", file),
            ("00400000-00401000 r--p 00001000 08:100000 5 ", file),
            ("00400000-00401000 r--p 00001000 0803 5 ", file),
            ("00400000-00401000 r--p 00001000 08:03:00 5 ", file),
            // The inode: `%llu`, and zero without a file.
            ("00400000-00401000 r--p 00001000 08:03 05 ", file),
            ("00400000-00401000 r--p 00001000 08:03 +5 ", file),
            ("00400000-00401000 r--p 00001000 08:03 -5 ", file),
            (
                "00400000-00401000 r--p 00001000 08:03 18446744073709551616 ",
                file,
            ),
            ("00400000-00401000 r--p 00000000 00:00 5 ", None),
            // The space after the inode, and the name of a file.
            ("00400000-00401000 r--p 00000000 00:00 0", None),
            ("00400000-00401000 r--p 00000000 00:00 0  ", None),
            ("00400000-00401000 r--p 00001000 08:03 5 ", None),
            ("00400000-00401000 r--p 00001000 08:03 5", None),
            // Without a file a name is in brackets, and only memory of a
            // file can have `[anon_shmem:...]`; a file's name in brackets is
            // nothing but that.
            ("00400000-00401000 rw-p 00000000 00:00 0 ", Some("heap")),
            ("00400000-00401000 rw-p 00000000 00:00 0 ", file),
            ("00400000-00401000 rw-p 00000000 00:00 0 ", Some("[heap")),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon_shmem:ab]"),
            ),
            ("00400000-00401000 r--p 00001000 08:03 5 ", Some("[heap]")),
            (
                "00400000-00401000 r--p 00001000 08:03 5 ",
                Some("[anon:ab]"),
            ),
            (
                "00400000-00401000 rw-s 00000000 00:01 7 ",
                Some("[anon_shmem:ab"),
            ),
            // Names `prctl(PR_SET_VMA_ANON_NAME)` never gives.
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a$b]"),
            ),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a`b]"),
            ),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a\\b]"),
            ),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a[b]"),
            ),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a]b]"),
            ),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a\x7fb]"),
            ),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a\tb]"),
            ),
            ("00400000-00401000 rw-p 00000000 00:00 0 ", Some("[anon:ab")),
            (
                "00400000-00401000 rw-s 00000000 00:01 7 ",
                Some("[anon_shmem:a$b]"),
            ),
            // A NUL byte in any name: Linux prints names from C strings.
            (
                "00400000-00401000 r--p 00001000 08:03 5 ",
                Some("/f\0suffix"),
            ),
            ("00400000-00401000 r--p 00001000 08:03 5 ", Some("/f\0")),
            (
                "00400000-00401000 r--p 00000000 00:00 0 ",
                Some("[vvar_vclock\0]"),
            ),
            ("00400000-00401000 r--p 00000000 00:00 0 ", Some("[\0]")),
            ("00400000-00401000 rw-p 00000000 00:00 0 ", Some("[heap]\0")),
            (
                "00400000-00401000 rw-p 00000000 00:00 0 ",
                Some("[anon:a\0b]"),
            ),
            (
                "00400000-00401000 rw-s 00000000 00:01 7 ",
                Some("[anon_shmem:a\0b]"),
            ),
        ] {
            let text = print(header, name);
            assert_eq!(
                MemoryMap::from_maps(format!("{text}\n").as_bytes()),
                MALFORMED,
                "{text}"
            );
        }
        // The longest name `prctl` accepts, and one byte more.
        let longest = "n".repeat(79);
        let header = "00400000-00401000 rw-p 00000000 00:00 0 ";
        assert_eq!(
            line(&print(header, Some(&format!("[anon:{longest}]")))).map(|m| m.backing),
            Ok(MappingBacking::NamedAnonymous(longest.clone().into_bytes()))
        );
        assert_eq!(
            MemoryMap::from_maps(
                format!("{}\n", print(header, Some(&format!("[anon:{longest}n]")))).as_bytes()
            ),
            MALFORMED
        );
        // The whole text: newline-terminated lines, none empty.
        for text in [
            &b"00400000-00401000 r--p 00000000 00:00 0 "[..],
            b"\n",
            b"00400000-00401000 r--p 00000000 00:00 0 \n\n",
            b"\n00400000-00401000 r--p 00000000 00:00 0 \n",
            b"00400000-00401000 r--p 00000000 00:00 0 \r\n",
            b"00400000-00401000 r--p 00000000 00:00 0 \n00401000-00402000 \xff--p 00000000 00:00 0 \n",
        ] {
            assert_eq!(MemoryMap::from_maps(text), MALFORMED, "{text:?}");
        }
    }

    /// A mapping's `vm_flags`: none from the constructors and the parser;
    /// accepted where they are a set Linux prints for such a mapping, with
    /// the `VmFlags` lines Linux 7.1.3 printed for them (the design's host
    /// probes, `probe/vmflags.py`, `tmp/probe2.py`, `tmp/probe3.py`), and
    /// refused otherwise; and kept through JSON, from which a fact written
    /// without them reads back as `None`.
    #[test]
    fn vm_flags_are_checked_against_the_mapping_and_survive_json() {
        let base = VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;
        let anonymous = mapping(0x40_0000, 0x40_1000, RW, MappingBacking::Anonymous);
        assert_eq!(anonymous.vm_flags, None);
        assert_eq!(
            line("00400000-00401000 rw-p 00000000 00:00 0 ").map(|m| m.vm_flags),
            Ok(None)
        );
        let shared = |prot: u32| {
            MappingFact::new(
                0x40_0000,
                0x40_1000,
                prot,
                true,
                0,
                file(libc::makedev(0, 1), 5, b"/memfd:sealed (deleted)"),
            )
            .unwrap()
        };
        let read = libc::PROT_READ as u32;
        for (what, mapping, flags) in [
            // `rd wr mr mw me ac`
            (
                "anonymous rw",
                &anonymous,
                VM_READ | VM_WRITE | base | VM_ACCOUNT,
            ),
            // `rd wr mr mw me ac nh`: MAP_STACK.
            (
                "MAP_STACK rw",
                &anonymous,
                VM_READ | VM_WRITE | base | VM_ACCOUNT | VM_NOHUGEPAGE,
            ),
            // `rd wr mr mw me gu lo sf ac nr gd` cannot all come at once, but
            // each of these bits is one Linux prints.
            (
                "every provider bit",
                &anonymous,
                VM_READ
                    | VM_WRITE
                    | base
                    | VM_GROWSDOWN
                    | VM_MAYBE_GUARD
                    | VM_LOCKED
                    | VM_SEQ_READ
                    | VM_RAND_READ
                    | VM_ACCOUNT
                    | VM_NORESERVE
                    | VM_SYNC
                    | VM_HUGEPAGE
                    | VM_NOHUGEPAGE
                    | VM_MERGEABLE,
            ),
            // `rd wr sh mr mw me ms`: shared anonymous memory.
            (
                "shared rw",
                &shared(RW),
                VM_READ | VM_WRITE | VM_SHARED | base | VM_MAYSHARE,
            ),
            // `rd mr me ms`: a shared mapping of a file opened O_RDONLY.
            (
                "shared read-only file",
                &shared(read),
                VM_READ | VM_MAYREAD | VM_MAYEXEC | VM_MAYSHARE,
            ),
            // `rd sh mr me ms`: a write-sealed memfd, shared, read-only.
            (
                "write-sealed memfd",
                &shared(read),
                VM_READ | VM_SHARED | VM_MAYREAD | VM_MAYEXEC | VM_MAYSHARE,
            ),
            // `rd mr mw`: a private mapping on a noexec mount.
            (
                "noexec private",
                &mapping(0x40_0000, 0x40_1000, read, MappingBacking::Anonymous),
                VM_READ | VM_MAYREAD | VM_MAYWRITE,
            ),
        ] {
            let with = mapping.clone().with_vm_flags(flags);
            assert_eq!(with.as_ref().map(|m| m.vm_flags), Ok(Some(flags)), "{what}");
            assert_eq!(with.unwrap().validate(), Ok(()), "{what}");
        }
        let malformed = Err(FactError::Errno(Errno::EIO));
        for (what, mapping, flags) in [
            // `ht`, `sd` and a protection-key bit are not bits a fact holds.
            (
                "VM_HUGETLB",
                &anonymous,
                VM_READ | VM_WRITE | base | 1 << 22,
            ),
            (
                "VM_SOFTDIRTY",
                &anonymous,
                VM_READ | VM_WRITE | base | 1 << 27,
            ),
            (
                "VM_PKEY_BIT0",
                &anonymous,
                VM_READ | VM_WRITE | base | 1 << 32,
            ),
            // The access bits are the protection's.
            ("no wr", &anonymous, VM_READ | base),
            ("ex", &anonymous, VM_READ | VM_WRITE | VM_EXEC | base),
            // Within the VM_MAY* bits.
            (
                "wr without mw",
                &anonymous,
                VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYEXEC,
            ),
            // VM_MAYSHARE is `shared`, and VM_SHARED needs it.
            (
                "ms on a private mapping",
                &anonymous,
                VM_READ | VM_WRITE | base | VM_MAYSHARE,
            ),
            (
                "sh alone",
                &anonymous,
                VM_READ | VM_WRITE | base | VM_SHARED,
            ),
            (
                "no ms on a shared mapping",
                &shared(RW),
                VM_READ | VM_WRITE | VM_SHARED | base,
            ),
        ] {
            assert_eq!(
                mapping.clone().with_vm_flags(flags).map(|m| m.vm_flags),
                malformed,
                "{what}"
            );
            let changed = MappingFact {
                vm_flags: Some(flags),
                ..mapping.clone()
            };
            assert_eq!(changed.validate(), Err(MALFORMED_FACT), "{what}");
        }

        // JSON keeps the flags; JSON written before the field existed reads
        // back as `None`.
        let flagged = anonymous
            .clone()
            .with_vm_flags(VM_READ | VM_WRITE | base | VM_ACCOUNT)
            .unwrap();
        let text = serde_json::to_string(&flagged).unwrap();
        assert!(text.contains("\"vm_flags\":1048691"), "{text}");
        assert_eq!(serde_json::from_str::<MappingFact>(&text).unwrap(), flagged);
        let old = text.replace(",\"vm_flags\":1048691", "");
        assert!(!old.contains("vm_flags"), "{old}");
        assert_eq!(
            serde_json::from_str::<MappingFact>(&old).unwrap(),
            anonymous
        );

        // So does `thp_eligible`, which any mapping may carry.
        let eligible = flagged.clone().with_thp_eligible(true);
        assert_eq!(eligible.thp_eligible, Some(true));
        assert_eq!(eligible.validate(), Ok(()));
        let text = serde_json::to_string(&eligible).unwrap();
        assert!(text.contains("\"thp_eligible\":true"), "{text}");
        assert_eq!(
            serde_json::from_str::<MappingFact>(&text).unwrap(),
            eligible
        );
        let old = text.replace(",\"thp_eligible\":true", "");
        assert!(!old.contains("thp_eligible"), "{old}");
        assert_eq!(serde_json::from_str::<MappingFact>(&old).unwrap(), flagged);
    }

    /// Facts built with the constructors print as Linux would and read back
    /// the same, and survive a tool's RPC, as the other facts do.
    #[test]
    fn constructed_maps_print_parse_and_round_trip() {
        let map = MemoryMap::new(
            vec![
                mapping(0x40_0000, 0x40_3000, RW, MappingBacking::Heap),
                MappingFact::new(
                    0x7f00_0000_0000,
                    0x7f00_0000_4000,
                    (libc::PROT_READ | libc::PROT_EXEC) as u32,
                    false,
                    0x2000,
                    file(libc::makedev(0, 0x20), 73572743, b"/usr/lib64/libc.so.6"),
                )
                .unwrap(),
                MappingFact::new(
                    0x7f00_0000_4000,
                    0x7f00_0000_5000,
                    RW,
                    true,
                    0x1000,
                    MappingBacking::NamedSharedAnonymous {
                        raw_device: libc::makedev(0, 1),
                        raw_inode: 9,
                        name: b"ring".to_vec(),
                    },
                )
                .unwrap(),
                mapping(
                    0x7fff_ff80_0000,
                    0x7fff_ffff_f000,
                    RW,
                    MappingBacking::Stack,
                ),
            ],
            true,
        )
        .unwrap();
        assert_eq!(MemoryMap::from_maps(&render(&map)), Ok(map.clone()));
        let text = serde_json::to_string(&map).unwrap();
        assert_eq!(serde_json::from_str::<MemoryMap>(&text).unwrap(), map);
        let partial = MemoryMap::new(map.mappings.clone(), false).unwrap();
        assert!(!partial.complete);
        let text = serde_json::to_string(&partial).unwrap();
        assert_eq!(serde_json::from_str::<MemoryMap>(&text).unwrap(), partial);
    }

    /// The constructors refuse every mapping that breaks a documented rule,
    /// each of which the parser would also refuse in a line, and accept the
    /// mapping beside it that keeps the rule; `validate` finds the same in a
    /// list whose public fields were changed after it was built.
    #[test]
    fn the_constructors_refuse_what_linux_cannot_print() {
        let new = |start, end, prot, offset, backing| {
            MappingFact::new(start, end, prot, false, offset, backing)
        };
        let anonymous = || MappingBacking::Anonymous;
        let path = |path: &[u8]| file(libc::makedev(8, 3), 5, path);
        let special = |name: &[u8]| MappingBacking::Special(name.to_vec());
        let shmem = |raw_device, name: &[u8]| MappingBacking::NamedSharedAnonymous {
            raw_device,
            raw_inode: 7,
            name: name.to_vec(),
        };
        let rwx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32;
        for (accepted, refused) in [
            // The range: page-aligned, not empty.
            (
                new(0x1000, 0x2000, RW, 0, anonymous()),
                new(0x1800, 0x2000, RW, 0, anonymous()),
            ),
            (
                new(0x1000, 0x2000, RW, 0, anonymous()),
                new(0x1000, 0x2800, RW, 0, anonymous()),
            ),
            (
                new(0x1000, 0x2000, RW, 0, anonymous()),
                new(0x2000, 0x2000, RW, 0, anonymous()),
            ),
            (
                new(0x1000, 0x2000, RW, 0, anonymous()),
                new(0x3000, 0x2000, RW, 0, anonymous()),
            ),
            // The permissions: no bit but read, write and execute.
            (
                new(0x1000, 0x2000, rwx, 0, anonymous()),
                new(0x1000, 0x2000, rwx | 8, 0, anonymous()),
            ),
            // The offset: page-aligned, and only with a file.
            (
                new(0x1000, 0x2000, RW, 0x3000, path(b"/f")),
                new(0x1000, 0x2000, RW, 0x3800, path(b"/f")),
            ),
            (
                new(0x1000, 0x2000, RW, 0x3000, shmem(libc::makedev(0, 1), b"a")),
                new(0x1000, 0x2000, RW, 0x3000, anonymous()),
            ),
            (
                new(0x1000, 0x2000, RW, 0, MappingBacking::Heap),
                new(0x1000, 0x2000, RW, 0x1000, MappingBacking::Heap),
            ),
            // A file's device: Linux's 12-bit major and 20-bit minor, as
            // `makedev` encodes them, and never 00:00.
            (
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    file(libc::makedev(0xfff, 0xf_ffff), 5, b"/f"),
                ),
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    file(libc::makedev(0x1000, 0), 5, b"/f"),
                ),
            ),
            (
                new(0x1000, 0x2000, RW, 0, file(libc::makedev(0, 1), 5, b"/f")),
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    file(libc::makedev(0, 0x10_0000), 5, b"/f"),
                ),
            ),
            (
                new(0x1000, 0x2000, RW, 0, file(libc::makedev(0, 1), 5, b"/f")),
                new(0x1000, 0x2000, RW, 0, file(0, 5, b"/f")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, file(libc::makedev(8, 3), 5, b"/f")),
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    file(libc::makedev(8, 3) | 1 << 63, 5, b"/f"),
                ),
            ),
            (
                new(0x1000, 0x2000, RW, 0, shmem(libc::makedev(0, 1), b"a")),
                new(0x1000, 0x2000, RW, 0, shmem(0, b"a")),
            ),
            // A file's path: not empty, no NUL, no newline, and not
            // beginning with a space or `[`.
            (
                new(0x1000, 0x2000, RW, 0, path(b"x")),
                new(0x1000, 0x2000, RW, 0, path(b"")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, path(b"/f\\012")),
                new(0x1000, 0x2000, RW, 0, path(b"/f\n")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, path(b"/f")),
                new(0x1000, 0x2000, RW, 0, path(b"/f\0")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, path(b"/ f")),
                new(0x1000, 0x2000, RW, 0, path(b" /f")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, path(b"/[f]")),
                new(0x1000, 0x2000, RW, 0, path(b"[f]")),
            ),
            // A kernel's own name: in brackets, no NUL, no newline, and not a
            // name another variant has.
            (
                new(0x1000, 0x2000, RW, 0, special(b"[vvar_vclock]")),
                new(0x1000, 0x2000, RW, 0, special(b"vvar_vclock")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[x]")),
                new(0x1000, 0x2000, RW, 0, special(b"[x\0]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[x]")),
                new(0x1000, 0x2000, RW, 0, special(b"[x\n]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[heapx]")),
                new(0x1000, 0x2000, RW, 0, special(b"[heap]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[stack ]")),
                new(0x1000, 0x2000, RW, 0, special(b"[stack]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[vdso2]")),
                new(0x1000, 0x2000, RW, 0, special(b"[vdso]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[vvar_vclock]")),
                new(0x1000, 0x2000, RW, 0, special(b"[vvar]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[anon]")),
                new(0x1000, 0x2000, RW, 0, special(b"[anon:x]")),
            ),
            (
                new(0x1000, 0x2000, RW, 0, special(b"[anon_shmem]")),
                new(0x1000, 0x2000, RW, 0, special(b"[anon_shmem:x]")),
            ),
            // Anonymous memory names: what `prctl` accepts.
            (
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    MappingBacking::NamedAnonymous(b"a b".to_vec()),
                ),
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    MappingBacking::NamedAnonymous(b"a$b".to_vec()),
                ),
            ),
            (
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    MappingBacking::NamedAnonymous(vec![b'n'; 79]),
                ),
                new(
                    0x1000,
                    0x2000,
                    RW,
                    0,
                    MappingBacking::NamedAnonymous(vec![b'n'; 80]),
                ),
            ),
            (
                new(0x1000, 0x2000, RW, 0, shmem(libc::makedev(0, 1), b"ring")),
                new(0x1000, 0x2000, RW, 0, shmem(libc::makedev(0, 1), b"ri]ng")),
            ),
        ] {
            let accepted = accepted.unwrap();
            assert_eq!(refused, MALFORMED.map(|_| accepted.clone()), "{accepted:?}");
            // Every mapping the constructor accepts prints as a line the
            // parser reads back as the same mapping.
            let alone = MemoryMap::new(vec![accepted.clone()], true).unwrap();
            assert_eq!(MemoryMap::from_maps(&render(&alone)), Ok(alone));
        }
        // The list: ascending, apart; adjacent mappings may touch.
        let a = mapping(0x1000, 0x2000, RW, MappingBacking::Anonymous);
        let b = mapping(0x2000, 0x3000, RW, MappingBacking::Anonymous);
        let c = mapping(0x0180_0000, 0x0180_1000, RW, MappingBacking::Anonymous);
        assert!(MemoryMap::new(vec![a.clone(), b.clone()], false).is_ok());
        assert_eq!(MemoryMap::new(vec![b.clone(), a.clone()], false), MALFORMED);
        assert_eq!(MemoryMap::new(vec![a.clone(), a.clone()], false), MALFORMED);
        let mut map = MemoryMap::new(vec![a.clone(), c], false).unwrap();
        assert_eq!(map.validate(), Ok(()));
        map.mappings[1].start = 0x1800;
        assert_eq!(map.validate(), Err(FactError::Errno(Errno::EIO)));
        map.mappings[1].start = 0x1000;
        assert_eq!(map.validate(), Err(FactError::Errno(Errno::EIO)));
        map.mappings[1] = b.clone();
        map.mappings[1].backing = MappingBacking::Special(b"[heap]".to_vec());
        assert_eq!(map.validate(), Err(FactError::Errno(Errno::EIO)));
        map.mappings[1] = b;
        assert_eq!(map.validate(), Ok(()));
    }
}
