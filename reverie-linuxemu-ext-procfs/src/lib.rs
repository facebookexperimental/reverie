/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The LinuxEmu procfs extension: synthetic `/proc/self/maps`
//! for standalone compositions, plus the pure `/proc` content
//! helpers it renders with.
//!
//! This crate is an extension crate (renamed from `reverie-procfs`
//! at Slice 2 S2-R4): compositions whose tool serves `/proc`
//! never link it, so they pay zero compile time or binary size
//! for it. [`register`] claims the maps path on a standalone
//! composition's extension table; without a registration the
//! core refuses it by name. (`/proc/self/status` is core
//! mechanics: the core serves its readable seq description
//! unconditionally, so this crate claims maps only.) The
//! rendering itself ([`render`]) is pure functions over the
//! core's facts snapshot.
//!
//! The remaining helpers are likewise pure functions over
//! caller-supplied values. The crate holds no process, descriptor,
//! or scheduling state, makes no system calls, and decides no
//! policy: which paths exist, what facts a file reports, and how a
//! call is answered remain the caller's business.
//!
//! The core mechanics that used to live at this crate's root --
//! synthetic file identities, guest path classification, and
//! single-record `seq_file` positioning -- moved to LinuxEmu core
//! (`reverie_linuxemu::proc_mechanics`, Slice 2's mechanics
//! relocation), their only consumer. What remains here is content:
//! the per-task renderers, the fixed files, fdinfo formatting, the
//! maps/status line spellings below, and mountinfo.
//!
//! The formatting rules follow Linux's procfs (`fs/proc/`); each helper
//! names the kernel source it matches.

pub mod fdinfo;
pub mod fixed;
pub mod mountinfo;
pub mod render;
pub mod sanitize;
pub mod task;

pub use render::extension_table;
pub use render::register;

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

pub use reverie_proc_grammar::escape_status_name;

#[cfg(test)]
mod tests {
    use super::*;

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
