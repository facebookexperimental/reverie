/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Pure helpers for presenting a Linux `/proc` view to a guest program:
//! path classification, file-content formatting, `seq_file` positioning,
//! and synthetic file metadata.
//!
//! Everything here is a pure function over caller-supplied values. The
//! crate holds no process, descriptor, or scheduling state, makes no
//! system calls, and decides no policy: which paths exist, what facts a
//! file reports, and how a call is answered remain the caller's business.
//! Backends and tools that present a `/proc` view share these helpers so
//! the bytes and metadata they produce agree byte for byte.
//!
//! The formatting rules follow Linux's procfs (`fs/proc/`); each helper
//! names the kernel source it matches.

pub mod fdinfo;
pub mod fixed;
pub mod mountinfo;
pub mod sanitize;
pub mod task;

pub use sanitize::render_system_stat;

pub use task::CommName;
pub use task::StatFields;
pub use task::StatusCapabilities;
pub use task::StatusFields;
pub use task::StatusSignals;
pub use task::TASK_COMM_LEN;
pub use task::render_comm;
pub use task::render_stat;
pub use task::render_status;
pub use task::stat_flags;
pub use task::stat_state;

pub use fixed::FixedFile;
pub use fixed::FixedMachine;
pub use fixed::NR_IRQS;
pub use fixed::SOFTIRQS;

pub use fdinfo::Fdinfo;
pub use fdinfo::FdinfoKind;
pub use fdinfo::FdinfoLock;
pub use fdinfo::LockKind;
pub use fdinfo::TimerfdLines;
pub use fdinfo::render as render_fdinfo;

pub use mountinfo::MOUNT_PEER_PREFIXES;
pub use mountinfo::MountInfoRow;
pub use mountinfo::parse_fdinfo_mount_id;
pub use mountinfo::parse_mountinfo;

/// Deterministic inode for a normalized synthetic `/proc` path (FNV-1a).
/// Stable across runs so repeated `stat` results agree.
pub fn path_inode(path: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Keep clear of low, conventionally-reserved inode numbers.
    hash | 0x1000
}

/// The `dev_t` for synthetic device major/minor numbers.
pub fn synthetic_dev(major: u32, minor: u32) -> libc::dev_t {
    libc::makedev(major, minor)
}

/// Overwrite the nondeterministic fields of a `stat` with the stable
/// synthetic identity of a /proc file, keeping the (deterministic) size.
pub fn sanitize_synthetic_stat(stat: &mut libc::stat, dev: libc::dev_t, inode: u64, blksize: u32) {
    stat.st_dev = dev;
    stat.st_ino = inode;
    stat.st_mode = libc::S_IFREG | 0o444;
    stat.st_nlink = 1;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_rdev = 0;
    stat.st_blksize = blksize as libc::blksize_t;
    // 512-byte blocks, rounded up. A shift avoids the still-unstable
    // int_roundings `div_ceil` on the pinned toolchain (512 == 1 << 9).
    stat.st_blocks = (stat.st_size + 511) >> 9;
    stat.st_atime = 0;
    stat.st_atime_nsec = 0;
    stat.st_mtime = 0;
    stat.st_mtime_nsec = 0;
    stat.st_ctime = 0;
    stat.st_ctime_nsec = 0;
}

/// A fully synthetic `stat` for a path-addressed /proc file of `size` bytes.
pub fn synthetic_stat(dev: libc::dev_t, inode: u64, size: usize, blksize: u32) -> libc::stat {
    // SAFETY: libc::stat is plain-old-data; a zeroed value is valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_size = size as libc::off_t;
    sanitize_synthetic_stat(&mut stat, dev, inode, blksize);
    stat
}

/// A synthetic `statx` mirroring [`synthetic_stat`].
pub fn synthetic_statx(
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
    size: u64,
    blksize: u32,
) -> libc::statx {
    // SAFETY: libc::statx is plain-old-data; a zeroed value is valid.
    let mut stx = unsafe { std::mem::zeroed::<libc::statx>() };
    stx.stx_mask = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_GID
        | libc::STATX_INO
        | libc::STATX_SIZE
        | libc::STATX_BLOCKS;
    stx.stx_blksize = blksize;
    stx.stx_nlink = 1;
    stx.stx_uid = 0;
    stx.stx_gid = 0;
    stx.stx_mode = (libc::S_IFREG | 0o444) as u16;
    stx.stx_ino = inode;
    stx.stx_size = size;
    stx.stx_blocks = (stx.stx_size + 511) >> 9;
    stx.stx_dev_major = dev_major;
    stx.stx_dev_minor = dev_minor;
    stx
}

/// One memory mapping as `/proc/<pid>/maps` reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapsEntry<'a> {
    /// First address of the mapping.
    pub start: u64,
    /// First address past the mapping.
    pub end: u64,
    /// The four permission characters, e.g. `rw-p`.
    pub perms: &'a str,
    /// Offset into the backing file, in bytes.
    pub offset: u64,
    /// Backing device major number (0 for anonymous mappings).
    pub dev_major: u32,
    /// Backing device minor number.
    pub dev_minor: u32,
    /// Backing inode number (0 for anonymous mappings).
    pub inode: u64,
    /// Pathname or bracketed name such as `[stack]`, if any.
    pub name: Option<&'a str>,
}

/// One `/proc/<pid>/maps` line, in the layout of Linux's
/// `show_vma_header_prefix` + name (`fs/proc/task_mmu.c`): hex address
/// range, the four permission characters, hex offset, `major:minor`
/// device, decimal inode, and the optional pathname or bracketed name.
///
/// Addresses print with a minimum width of 12 hex digits, matching the
/// callers' established output; Linux's `seq_put_hex_ll` minimum is 8,
/// which agrees for addresses of 12 or more digits.
pub fn format_maps_line(entry: &MapsEntry<'_>) -> Vec<u8> {
    let mut line = format!(
        "{:012x}-{:012x} {} {:08x} {:02x}:{:02x} {}",
        entry.start,
        entry.end,
        entry.perms,
        entry.offset,
        entry.dev_major,
        entry.dev_minor,
        entry.inode
    );
    if let Some(name) = entry.name {
        line.push(' ');
        line.push_str(name);
    }
    line.push('\n');
    line.into_bytes()
}

/// The `Name` field escaping of `/proc/<pid>/status`: Linux renders
/// newline and backslash as two-byte escape sequences there
/// (`proc_task_name` with escaping, `fs/proc/array.c`); `stat` keeps the
/// raw bytes.
pub fn escape_status_name(comm: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(comm.len());
    for byte in comm {
        match byte {
            b'\n' => escaped.extend_from_slice(b"\\n"),
            b'\\' => escaped.extend_from_slice(b"\\\\"),
            _ => escaped.push(*byte),
        }
    }
    escaped
}

/// Rewrite a `/proc/<pid>` path naming `own_pid` to the canonical
/// `/proc/self` form, so both spellings resolve identically. Returns
/// `None` for a path outside `/proc`.
pub fn normalize_self_path(path: &[u8], own_pid: i32) -> Option<Vec<u8>> {
    if path != b"/proc" && !path.starts_with(b"/proc/") {
        return None;
    }
    let pid = format!("/proc/{own_pid}").into_bytes();
    if path == pid.as_slice() {
        return Some(b"/proc/self".to_vec());
    }
    let mut pid_dir = pid;
    pid_dir.push(b'/');
    if let Some(rest) = path.strip_prefix(pid_dir.as_slice()) {
        let mut normalized = b"/proc/self/".to_vec();
        normalized.extend_from_slice(rest);
        return Some(normalized);
    }
    Some(path.to_vec())
}

/// Parse a decimal `/proc` id component (pid, tid, or fd number):
/// nonempty, ASCII digits only, no overflow.
pub fn parse_id(component: &[u8]) -> Option<i32> {
    if component.is_empty() || !component.iter().all(u8::is_ascii_digit) {
        return None;
    }
    component.iter().try_fold(0_i32, |value, digit| {
        value.checked_mul(10)?.checked_add(i32::from(*digit - b'0'))
    })
}

/// The descriptor number a guest fd-link path names, for the exact-link
/// spellings [`parse_fd_link`] classifies as the caller's own (with the
/// thread-group leader as the task: `task/<own_pid>` included). The
/// executor, which knows the calling thread, classifies with
/// `parse_fd_link` directly so sibling-thread spellings are its own too.
pub fn parse_fd_path(path: &[u8], own_pid: i32) -> Option<i32> {
    match parse_fd_link(path, own_pid, own_pid) {
        Some(FdLinkPath::Exact(fd)) => Some(fd),
        _ => None,
    }
}

/// How a guest fd-link spelling relates to the caller's own task, for
/// spellings with a path below the link itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdLinkPath<'a> {
    /// The link itself: `/proc/self/fd/<n>` and its spellings.
    Exact(i32),
    /// A path below the caller's own fd link: resolve `rest` below the
    /// descriptor `fd` the link names (`rest` is empty for a trailing
    /// slash). Native resolution crosses the magic link to the
    /// descriptor's file and continues below it.
    Below { fd: i32, rest: &'a [u8] },
    /// A syntactically valid fd-link spelling naming another task.
    /// Callers must decide it from their own descriptor state (or refuse
    /// it) and never let it reach the host filesystem, where the same
    /// spelling names the supervisor process's descriptors.
    OtherTask,
}

/// A decimal id as the kernel's procfs lookup accepts it: digits only,
/// no leading zero (except the single digit `0` itself).
fn parse_id_strict(component: &[u8]) -> Option<i32> {
    if component.len() > 1 && component[0] == b'0' {
        return None;
    }
    parse_id(component)
}

/// Classify a guest fd-link spelling the way the kernel's path walk
/// would reach it: repeated slashes collapse, `.` and empty components
/// drop, and `..` folds lexically — but only inside the
/// `/proc/<pid|self|thread-self>/[task/<tid>/]fd` prefix. A fold that
/// would pop a symlink component (`self`/`thread-self`, whose kernel
/// resolution is not lexical) is ambiguous and classifies as
/// [`FdLinkPath::OtherTask`], which callers fail closed. Ids are strict
/// decimal (no leading zeros); a non-numeric id is not an fd link.
/// Ownership is by thread group: `task/<tid>` spellings are the
/// caller's own only for its own tid or the group leader (the parser
/// cannot prove a sibling thread is live; native would answer ENOENT
/// for a dead one and the fail-closed answer is the same errno). The
/// returned `rest` never starts with `/`, so resolving it below a
/// descriptor cannot escape that descriptor by being absolute. This is
/// the prefix counterpart of [`parse_fd_path`]; a caller that forwards
/// path spellings to the host must handle every variant here so no
/// spelling is ever resolved against the supervisor's own
/// `/proc/self/fd`.
pub fn parse_fd_link(path: &[u8], own_pid: i32, own_tid: i32) -> Option<FdLinkPath<'_>> {
    if !path.starts_with(b"/") {
        return None;
    }
    // Walk components with their end offsets, folding the prefix. An
    // ambiguous fold (popping a symlink component) poisons the walk:
    // it classifies as OtherTask only if the folded shape still turns
    // out to be an fd link, and as not-an-fd-link otherwise, so
    // ordinary procfs paths containing ".." are unaffected.
    let mut ambiguous_fold = false;
    let mut stack: Vec<&[u8]> = Vec::new();
    let mut rest: Option<&[u8]> = None;
    let mut fd: Option<i32> = None;
    let mut offset = 0usize;
    for component in path.split(|byte| *byte == b'/') {
        let end = offset + component.len();
        offset = end + 1;
        if fd.is_some() {
            // Everything after the fd digits is the raw rest; the host
            // walk below the descriptor collapses it natively.
            rest = Some(&path[end.saturating_sub(component.len())..]);
            break;
        }
        match component {
            b"" | b"." => {}
            b".." => match stack.last() {
                None => {}
                Some(component)
                    if *component == b"self".as_slice()
                        || *component == b"thread-self".as_slice()
                        || *component == b"stdin".as_slice()
                        || *component == b"stdout".as_slice()
                        || *component == b"stderr".as_slice()
                        || (*component == b"fd".as_slice()
                            && stack.first() == Some(&b"dev".as_slice())) =>
                {
                    // `fd` under /dev is a symlink to /proc/self/fd, and
                    // std* are symlinks to single descriptors: popping
                    // any of them with ".." is a symlink fold, not a
                    // lexical one. (The `fd` directory under /proc is a
                    // real directory; popping it folds lexically.)
                    ambiguous_fold = true;
                    stack.pop();
                }
                Some(_) => {
                    stack.pop();
                }
            },
            _ => {
                // The component after a completed `fd` prefix is the
                // descriptor number itself.
                let prefix_complete = matches!(
                    stack.as_slice(),
                    [b"dev", b"fd"] | [b"proc", _, b"fd"] | [b"proc", _, b"task", _, b"fd"]
                );
                if prefix_complete {
                    fd = Some(parse_id_strict(component)?);
                    if end == path.len() {
                        rest = None;
                        break;
                    }
                    // Continue one more step to capture the raw rest.
                    continue;
                }
                stack.push(component);
            }
        }
    }
    let Some(fd) = fd else {
        // A poisoned fold whose remaining spelling still contains an
        // fd-link-shaped suffix (`fd/<digits>` or
        // `task/<digits>/fd/<digits>` after a dev/proc start) is an fd
        // link the walk could not classify safely: fail closed instead
        // of letting the caller forward it literally (for example
        // `/dev/fd/../task/<tid>/fd/<n>/...`, where /dev/fd is a symlink
        // to /proc/self/fd and the kernel resolves the ".." there).
        if ambiguous_fold {
            let parts: Vec<&[u8]> = path
                .split(|byte| *byte == b'/')
                .filter(|part| !part.is_empty() && *part != b".")
                .collect();
            let digits = |part: &[u8]| !part.is_empty() && part.iter().all(u8::is_ascii_digit);
            let starts_dev_or_proc =
                matches!(parts.first(), Some(part) if *part == b"dev" || *part == b"proc");
            let loose_fd_shape = starts_dev_or_proc
                && parts
                    .windows(2)
                    .any(|pair| pair[0] == b"fd" && digits(pair[1]));
            if loose_fd_shape {
                return Some(FdLinkPath::OtherTask);
            }
        }
        return None;
    };
    // The fd digits were the last thing pushed-wise; recompute the
    // matched prefix shape from the stack (the digits never entered it).
    enum Shape {
        Own,
        Other,
    }
    let shape = match stack.as_slice() {
        [b"dev", b"fd"] | [b"proc", b"self", b"fd"] | [b"proc", b"thread-self", b"fd"] => {
            Shape::Own
        }
        [b"proc", group, b"fd"] => {
            if parse_id_strict(group)? == own_pid {
                Shape::Own
            } else {
                Shape::Other
            }
        }
        [b"proc", b"self", b"task", tid, b"fd"] => {
            let tid = parse_id_strict(tid)?;
            if tid == own_tid || tid == own_pid {
                Shape::Own
            } else {
                Shape::Other
            }
        }
        // /proc/thread-self/task/... has no native referent (ENOENT);
        // failing closed as OtherTask gives exactly that errno. It must
        // precede the numeric-group arm, which would reject it as a
        // non-numeric id instead of classifying it.
        [b"proc", b"thread-self", b"task", _tid, b"fd"] => Shape::Other,
        [b"proc", group, b"task", tid, b"fd"] => {
            let tid = parse_id_strict(tid)?;
            if parse_id_strict(group)? == own_pid && (tid == own_tid || tid == own_pid) {
                Shape::Own
            } else {
                Shape::Other
            }
        }
        _ => return None,
    };
    if ambiguous_fold {
        return Some(FdLinkPath::OtherTask);
    }
    match shape {
        Shape::Other => Some(FdLinkPath::OtherTask),
        Shape::Own => Some(match rest {
            None => FdLinkPath::Exact(fd),
            Some(rest) => FdLinkPath::Below {
                fd,
                rest: {
                    let mut rest = rest;
                    while let Some(stripped) = rest.strip_prefix(b"/") {
                        rest = stripped;
                    }
                    rest
                },
            },
        }),
    }
}

/// Classify a procfs executable-link spelling against `live`, the
/// caller's "thread is live in the current process" predicate.
/// `Some(false)` is a syntactically valid guest proc link naming a task
/// outside the current process; callers must refuse it rather than
/// accidentally opening the supervisor's procfs.
pub fn classify_exe_path(path: &[u8], live: &impl Fn(i32) -> bool) -> Option<bool> {
    if path == b"/proc/self/exe" || path == b"/proc/thread-self/exe" {
        return Some(true);
    }
    let components = path
        .strip_prefix(b"/proc/")?
        .split(|byte| *byte == b'/')
        .collect::<Vec<_>>();
    match components.as_slice() {
        [task, b"exe"] => parse_id(task).map(live),
        [b"self", b"task", task, b"exe"] => parse_id(task).map(live),
        [group, b"task", task, b"exe"] => {
            let group = parse_id(group)?;
            let task = parse_id(task)?;
            Some(live(group) && live(task))
        }
        _ => None,
    }
}

/// Linux single-record `seq_file` state (`fs/seq_file.c`: `seq_read`,
/// `seq_lseek`). `read_pos` belongs to the sequence iterator; `file_pos`
/// is the open file description's shared offset. A pread changes the
/// former without changing the latter. Content comes from the caller's
/// `observe` callback, re-rendered whenever the sequence (re)starts, and
/// leaves through the caller's `copy` callback. Errors are negative
/// `errno` values as `i64`.
#[derive(Debug, Default)]
pub struct SingleRecordSeq {
    file_pos: u64,
    read_pos: u64,
    buffer: Vec<u8>,
    from: usize,
    end: bool,
}

impl SingleRecordSeq {
    fn reset(&mut self) {
        self.buffer.clear();
        self.from = 0;
        self.end = false;
    }

    fn traverse(
        &mut self,
        offset: u64,
        observe: &mut impl FnMut() -> Result<Vec<u8>, i64>,
    ) -> Result<(), i64> {
        self.reset();
        if offset != 0 {
            self.buffer = observe()?;
            self.from = offset.min(self.buffer.len() as u64) as usize;
            self.end = true;
        }
        Ok(())
    }

    /// One `read` (or `pread` when `positioned_offset` is set) of at most
    /// `count` bytes. Returns the byte count or a negative errno.
    pub fn read(
        &mut self,
        positioned_offset: Option<u64>,
        count: usize,
        mut observe: impl FnMut() -> Result<Vec<u8>, i64>,
        mut copy: impl FnMut(&[u8]) -> Result<usize, i64>,
    ) -> i64 {
        let offset = positioned_offset.unwrap_or(self.file_pos);
        if offset > i64::MAX as u64 {
            return -i64::from(libc::EINVAL);
        }
        if count == 0 {
            return 0;
        }
        if offset == 0 {
            self.reset();
        }
        if offset != self.read_pos {
            if let Err(error) = self.traverse(offset, &mut observe) {
                self.read_pos = 0;
                self.reset();
                return error;
            }
            self.read_pos = offset;
        }
        if self.from == self.buffer.len() && !self.end {
            match observe() {
                Ok(bytes) => self.buffer = bytes,
                Err(error) => return error,
            }
            self.from = 0;
            self.end = true;
        }
        let available = (self.buffer.len() - self.from).min(count);
        if available == 0 {
            return 0;
        }
        let copied = match copy(&self.buffer[self.from..self.from + available]) {
            Ok(0) => return -i64::from(libc::EFAULT),
            Ok(copied) => copied,
            Err(error) => return error,
        };
        assert!(copied <= available, "seq copy exceeded the offered bytes");
        self.from += copied;
        self.read_pos += copied as u64;
        if positioned_offset.is_none() {
            self.file_pos = self.read_pos;
        }
        copied as i64
    }

    /// One `lseek`. Only `SEEK_SET` and `SEEK_CUR` are admitted, as for
    /// Linux's single-record seq files. Returns the new offset or a
    /// negative errno.
    pub fn seek(
        &mut self,
        offset: i64,
        whence: libc::c_int,
        mut observe: impl FnMut() -> Result<Vec<u8>, i64>,
    ) -> i64 {
        let offset = match whence {
            libc::SEEK_SET => Some(offset),
            libc::SEEK_CUR => (self.file_pos as i64).checked_add(offset),
            _ => None,
        };
        let Some(offset) = offset.filter(|offset| *offset >= 0) else {
            return -i64::from(libc::EINVAL);
        };
        if offset as u64 != self.read_pos {
            if let Err(error) = self.traverse(offset as u64, &mut observe) {
                self.file_pos = 0;
                self.read_pos = 0;
                self.reset();
                return error;
            }
            self.read_pos = offset as u64;
        }
        self.file_pos = offset as u64;
        offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_inode_is_stable_distinct_and_reserved_clear() {
        assert_eq!(
            path_inode(b"/proc/self/status"),
            path_inode(b"/proc/self/status")
        );
        assert_ne!(
            path_inode(b"/proc/self/status"),
            path_inode(b"/proc/self/maps")
        );
        assert_eq!(path_inode(b"/proc/self/status") & 0x1000, 0x1000);
    }

    #[test]
    fn synthetic_stat_fields_and_block_rounding() {
        let dev = synthetic_dev(0, 0xff01);
        for (size, blocks) in [(0usize, 0i64), (1, 1), (512, 1), (513, 2)] {
            let stat = synthetic_stat(dev, 42, size, 4096);
            assert_eq!(stat.st_dev, dev);
            assert_eq!(stat.st_ino, 42);
            assert_eq!(stat.st_mode, libc::S_IFREG | 0o444);
            assert_eq!(stat.st_nlink, 1);
            assert_eq!(stat.st_uid, 0);
            assert_eq!(stat.st_gid, 0);
            assert_eq!(stat.st_size, size as libc::off_t);
            assert_eq!(stat.st_blocks, blocks);
            assert_eq!(stat.st_blksize, 4096);
            assert_eq!(stat.st_atime, 0);
            assert_eq!(stat.st_mtime, 0);
            assert_eq!(stat.st_ctime, 0);
        }
    }

    #[test]
    fn synthetic_statx_mirrors_stat() {
        let stx = synthetic_statx(0, 0xff01, 42, 513, 4096);
        assert_eq!(stx.stx_ino, 42);
        assert_eq!(stx.stx_size, 513);
        assert_eq!(stx.stx_blocks, 2);
        assert_eq!(stx.stx_mode, (libc::S_IFREG | 0o444) as u16);
        assert_eq!(stx.stx_dev_major, 0);
        assert_eq!(stx.stx_dev_minor, 0xff01);
        assert_ne!(stx.stx_mask & libc::STATX_SIZE, 0);
        assert_ne!(stx.stx_mask & libc::STATX_INO, 0);
    }

    #[test]
    fn maps_line_matches_linux_layout() {
        assert_eq!(
            format_maps_line(&MapsEntry {
                start: 0x7fff_e000,
                end: 0x7fff_f000,
                perms: "rw-p",
                offset: 0,
                dev_major: 0,
                dev_minor: 0,
                inode: 0,
                name: Some("[stack]"),
            }),
            b"00007fffe000-00007ffff000 rw-p 00000000 00:00 0 [stack]\n"
        );
        assert_eq!(
            format_maps_line(&MapsEntry {
                start: 0x1000,
                end: 0x2000,
                perms: "r-xp",
                offset: 0x1000,
                dev_major: 0x8,
                dev_minor: 0x1,
                inode: 123,
                name: None,
            }),
            b"000000001000-000000002000 r-xp 00001000 08:01 123\n"
        );
    }

    #[test]
    fn status_name_escaping() {
        assert_eq!(escape_status_name(b"bash"), b"bash");
        assert_eq!(escape_status_name(b"a\nb"), b"a\\nb");
        assert_eq!(escape_status_name(b"a\\b"), b"a\\\\b");
        assert_eq!(escape_status_name(b""), b"");
    }

    #[test]
    fn normalize_self_path_spellings() {
        assert_eq!(
            normalize_self_path(b"/proc/7", 7),
            Some(b"/proc/self".to_vec())
        );
        assert_eq!(
            normalize_self_path(b"/proc/7/status", 7),
            Some(b"/proc/self/status".to_vec())
        );
        assert_eq!(
            normalize_self_path(b"/proc/8/status", 7),
            Some(b"/proc/8/status".to_vec())
        );
        assert_eq!(normalize_self_path(b"/proc", 7), Some(b"/proc".to_vec()));
        assert_eq!(normalize_self_path(b"/etc/passwd", 7), None);
    }

    #[test]
    fn parse_id_and_fd_path() {
        assert_eq!(parse_id(b"0"), Some(0));
        assert_eq!(parse_id(b"42"), Some(42));
        assert_eq!(parse_id(b""), None);
        assert_eq!(parse_id(b"4x"), None);
        assert_eq!(parse_id(b"99999999999999999999"), None);
        assert_eq!(parse_fd_path(b"/proc/self/fd/3", 1), Some(3));
        assert_eq!(parse_fd_path(b"/proc/thread-self/fd/3", 1), Some(3));
        assert_eq!(parse_fd_path(b"/proc/1/fd/3", 1), Some(3));
        assert_eq!(parse_fd_path(b"/proc/2/fd/3", 1), None);
        assert_eq!(parse_fd_path(b"/dev/fd/3", 1), Some(3));
        assert_eq!(parse_fd_path(b"/dev/fd/not-a-fd", 1), None);
        assert_eq!(parse_fd_path(b"/proc/self/fd/", 1), None);
    }

    #[test]
    fn parse_fd_link_spellings() {
        use FdLinkPath::{Below, Exact, OtherTask};
        // Own pid 1, own tid 9 throughout.
        fn parse(path: &[u8]) -> Option<FdLinkPath<'_>> {
            parse_fd_link(path, 1, 9)
        }
        // Exact links, every own spelling.
        for spelling in [
            "/proc/self/fd/3",
            "/proc/thread-self/fd/3",
            "/proc/1/fd/3",
            "/dev/fd/3",
            "/proc/1/task/9/fd/3",
            "/proc/1/task/1/fd/3",
            "/proc/self/task/9/fd/3",
        ] {
            assert_eq!(parse(spelling.as_bytes()), Some(Exact(3)), "{spelling}");
        }
        // Kernel-equivalent spellings classify like the canonical one.
        for spelling in [
            "//proc/self/fd/3/x",
            "/proc//self/fd/3/x",
            "/proc/./self/fd/3/x",
            "/proc/self/./fd/3/x",
            "/proc/self/fd//3/x",
            "/proc/self/fd/./3/x",
            "/proc/self/fd/../fd/3/x",
            "/proc/1/fd/../fd/3/x",
        ] {
            assert_eq!(
                parse(spelling.as_bytes()),
                Some(Below { fd: 3, rest: b"x" }),
                "{spelling}"
            );
        }
        // Below a link of the caller's own descriptor table; `rest`
        // never starts with '/'.
        assert_eq!(
            parse(b"/proc/self/fd/3/marker"),
            Some(Below {
                fd: 3,
                rest: b"marker"
            })
        );
        assert_eq!(
            parse(b"/proc/self/fd/3//marker"),
            Some(Below {
                fd: 3,
                rest: b"marker"
            })
        );
        assert_eq!(
            parse(b"/proc/1/task/9/fd/3/a/b"),
            Some(Below {
                fd: 3,
                rest: b"a/b"
            })
        );
        assert_eq!(parse(b"/proc/self/fd/3/"), Some(Below { fd: 3, rest: b"" }));
        // Another task's spellings, exact and below; spellings with no
        // native referent fail closed the same way.
        for spelling in [
            "/proc/2/fd/3",
            "/proc/2/fd/3/x",
            "/proc/2/task/2/fd/3",
            "/proc/thread-self/task/9/fd/3",
            "/proc/self/../2/fd/3",
            "/dev/fd/../task/9/fd/3",
            "/dev/fd/../task/9/fd/3/x",
            "/dev/stdin/../task/9/fd/3",
            "/proc/1/task/77/fd/3",
        ] {
            assert_eq!(parse(spelling.as_bytes()), Some(OtherTask), "{spelling}");
        }
        // Not fd links: bad ids (leading zeros, non-numeric tid), other
        // proc files, relative spellings.
        for spelling in [
            "/proc/self/status",
            "/proc/self/fd/",
            "/proc/self/fd/3x",
            "/proc/self/fd/03",
            "/proc/self/task/x/fd/3",
            "/proc/self/task/09/fd/3",
            "/etc/fd/3",
            "/srv/fd/../fd/3",
            "proc/self/fd/3",
        ] {
            assert_eq!(parse(spelling.as_bytes()), None, "{spelling}");
        }
        // The widened exact-link helper takes the group leader as task.
        assert_eq!(parse_fd_path(b"/proc/1/task/1/fd/3", 1), Some(3));
        assert_eq!(parse_fd_path(b"/proc/1/task/9/fd/3", 1), None);
    }

    #[test]
    fn classify_exe_path_spellings() {
        let live = |tid: i32| tid == 5;
        assert_eq!(classify_exe_path(b"/proc/self/exe", &live), Some(true));
        assert_eq!(
            classify_exe_path(b"/proc/thread-self/exe", &live),
            Some(true)
        );
        assert_eq!(classify_exe_path(b"/proc/5/exe", &live), Some(true));
        assert_eq!(classify_exe_path(b"/proc/6/exe", &live), Some(false));
        assert_eq!(
            classify_exe_path(b"/proc/self/task/5/exe", &live),
            Some(true)
        );
        assert_eq!(classify_exe_path(b"/proc/5/task/5/exe", &live), Some(true));
        assert_eq!(classify_exe_path(b"/proc/5/task/6/exe", &live), Some(false));
        assert_eq!(classify_exe_path(b"/proc/self/status", &live), None);
        assert_eq!(classify_exe_path(b"/etc/exe", &live), None);
    }

    fn collect(seq: &mut SingleRecordSeq, positioned: Option<u64>, count: usize) -> (i64, Vec<u8>) {
        let mut out = Vec::new();
        let result = seq.read(
            positioned,
            count,
            || Ok(b"hello".to_vec()),
            |bytes| {
                out.extend_from_slice(bytes);
                Ok(bytes.len())
            },
        );
        (result, out)
    }

    #[test]
    fn seq_read_chunks_and_rereads_from_zero() {
        let mut seq = SingleRecordSeq::default();
        assert_eq!(collect(&mut seq, None, 2), (2, b"he".to_vec()));
        assert_eq!(collect(&mut seq, None, 2), (2, b"ll".to_vec()));
        assert_eq!(collect(&mut seq, None, 2), (1, b"o".to_vec()));
        assert_eq!(collect(&mut seq, None, 2), (0, Vec::new()));
        assert_eq!(collect(&mut seq, Some(0), 5), (5, b"hello".to_vec()));
    }

    #[test]
    fn seq_pread_moves_sequence_not_file_position() {
        let mut seq = SingleRecordSeq::default();
        assert_eq!(collect(&mut seq, Some(1), 2), (2, b"el".to_vec()));
        // The plain read position is still 0, and offset 0 restarts.
        assert_eq!(collect(&mut seq, None, 2), (2, b"he".to_vec()));
        assert_eq!(collect(&mut seq, None, 0), (0, Vec::new()));
        assert_eq!(
            collect(&mut seq, Some(u64::MAX), 1).0,
            -i64::from(libc::EINVAL)
        );
    }

    #[test]
    fn seq_seek_set_cur_and_refusals() {
        let mut seq = SingleRecordSeq::default();
        let observe = || Ok(b"hello".to_vec());
        assert_eq!(seq.seek(2, libc::SEEK_SET, observe), 2);
        assert_eq!(collect(&mut seq, None, 2), (2, b"ll".to_vec()));
        assert_eq!(seq.seek(-1, libc::SEEK_CUR, observe), 3);
        assert_eq!(
            seq.seek(0, libc::SEEK_END, observe),
            -i64::from(libc::EINVAL)
        );
        assert_eq!(
            seq.seek(-1, libc::SEEK_SET, observe),
            -i64::from(libc::EINVAL)
        );
    }

    #[test]
    fn seq_copy_fault_and_observe_error() {
        let mut seq = SingleRecordSeq::default();
        let zero_copy = seq.read(None, 2, || Ok(b"hello".to_vec()), |_| Ok(0));
        assert_eq!(zero_copy, -i64::from(libc::EFAULT));
        let mut seq = SingleRecordSeq::default();
        let failed = seq.read(None, 2, || Err(-7), |bytes| Ok(bytes.len()));
        assert_eq!(failed, -7);
    }
}
