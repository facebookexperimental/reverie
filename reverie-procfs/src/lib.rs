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
}
