/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One-transition shim over `reverie_proc_grammar::mountinfo`, the
//! grammar owner since Slice 2 (S2-R1). The shim keeps this crate's
//! legacy identity-bearing row shape and `Option` surface so current
//! consumers (detcore-model re-exports, LinuxEmu's host mount
//! capture) change nothing: the grammar's typed refusal maps to
//! `None`, and the legacy `raw_device` is computed here with
//! `libc::makedev`, because `dev_t` encoding is libc ABI, not file
//! grammar. The grammar's canonical-spelling rules are deliberately
//! stricter than the loose decimal reader this replaces: a nonempty
//! snapshot without its final newline, or with a leading-zero
//! decimal, now refuses. Kernel-produced snapshots are always
//! canonical, so no live consumer input changes accept/reject.

pub use reverie_proc_grammar::mountinfo::MOUNT_PEER_PREFIXES;

/// Identity-bearing fields from one Linux `/proc/*/mountinfo` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountInfoRow {
    pub raw_mount_id: u64,
    pub raw_parent_id: u64,
    pub raw_device: u64,
    pub root: Vec<u8>,
    pub raw_peer_groups: Vec<u64>,
    /// The superblock options verbatim (the comma-separated field after
    /// the source, e.g. `ro,relatime`). Callers split on `,`; flags such
    /// as `ro` versus `rw` come from here when `statmount(2)` is
    /// unavailable.
    pub super_options: Vec<u8>,
}

fn from_grammar(row: reverie_proc_grammar::MountInfoRow) -> MountInfoRow {
    let raw_peer_groups = row.peer_groups();
    MountInfoRow {
        raw_mount_id: row.mount_id,
        raw_parent_id: row.parent_id,
        raw_device: libc::makedev(row.device_major, row.device_minor),
        root: row.root,
        raw_peer_groups,
        super_options: row.super_options,
    }
}

/// Strictly parse a Linux `/proc/*/mountinfo` snapshot.
///
/// Empty files are valid empty snapshots. Malformed rows and duplicate mount
/// IDs are rejected so every producer and consumer accepts the same grammar.
pub fn parse_mountinfo(contents: &[u8]) -> Option<Vec<MountInfoRow>> {
    reverie_proc_grammar::parse_mountinfo(contents)
        .ok()
        .map(|rows| rows.into_iter().map(from_grammar).collect())
}

/// Parse the one decimal `mnt_id` field required by Linux fdinfo.
///
/// Missing, duplicate, malformed, signed, or out-of-range values are rejected.
/// Sharing this byte parser prevents a capture path from accepting input a
/// later consumer would refuse.
pub fn parse_fdinfo_mount_id(contents: &[u8]) -> Option<u64> {
    reverie_proc_grammar::parse_fdinfo_mount_id(contents)
}

#[cfg(test)]
mod tests {
    use super::parse_fdinfo_mount_id;
    use super::parse_mountinfo;

    #[test]
    fn fdinfo_mount_id_is_strict_and_unique() {
        assert_eq!(parse_fdinfo_mount_id(b"pos:\t0\nmnt_id:\t37\n"), Some(37));
        assert_eq!(parse_fdinfo_mount_id(b"mnt_id: 0\n"), Some(0));
        for malformed in [
            b"pos:\t0\n".as_slice(),
            b"mnt_id:\tbad\nmnt_id:\t37\n".as_slice(),
            b"mnt_id:\t37\nmnt_id:\t38\n".as_slice(),
            b"mnt_id:\t37 trailing\n".as_slice(),
            b"mnt_id:\t18446744073709551616\n".as_slice(),
            b"mnt_id:37\n".as_slice(),
        ] {
            assert_eq!(parse_fdinfo_mount_id(malformed), None, "{malformed:?}");
        }
    }

    #[test]
    fn mountinfo_parser_accepts_empty_and_refuses_malformed_or_duplicate_rows() {
        assert_eq!(parse_mountinfo(b""), Some(Vec::new()));
        assert_eq!(parse_mountinfo(b"\n"), None);
        let row = b"37 1 8:1 / / rw shared:9 - ext4 /dev/root rw\n";
        let parsed = parse_mountinfo(row).expect("valid mountinfo row");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].raw_mount_id, 37);
        assert_eq!(parsed[0].raw_parent_id, 1);
        assert_eq!(parsed[0].raw_device, libc::makedev(8, 1));
        assert_eq!(parsed[0].root, b"/");
        assert_eq!(parsed[0].raw_peer_groups, [9]);
        assert_eq!(parsed[0].super_options, b"rw");
        let readonly = parse_mountinfo(b"37 1 8:1 / / ro shared:9 - ext4 /dev/root ro,relatime\n")
            .expect("valid readonly mountinfo row");
        assert_eq!(readonly[0].super_options, b"ro,relatime");
        assert!(parse_mountinfo(b"37 1 bad / / rw - ext4 /dev/root rw\n").is_none());
        assert!(
            parse_mountinfo(b"37 1 8:1 / / rw unbindable nosymfollow - ext4 /dev/root rw\n")
                .is_some(),
            "known bare optional flags must remain accepted"
        );
        assert!(
            parse_mountinfo(b"37 1 8:1 / / rw future_peer:19 - ext4 /dev/root rw\n").is_none(),
            "unknown numeric optional fields must fail closed"
        );
        assert!(
            parse_mountinfo(b"37 1 8:1 / / rw future_flag:value - ext4 /dev/root rw\n").is_some(),
            "unknown nonnumeric flags carry no raw numeric identity"
        );
        let duplicate = [row.as_slice(), row.as_slice()].concat();
        assert!(parse_mountinfo(&duplicate).is_none());
    }

    #[test]
    fn mountinfo_shim_applies_grammar_canonical_rules() {
        // Deliberate deltas from the loose reader this shim replaces:
        // the grammar refuses spellings the kernel never prints.
        assert!(
            parse_mountinfo(b"37 1 8:1 / / rw - ext4 /dev/root rw").is_none(),
            "a nonempty snapshot without its final newline refuses"
        );
        assert!(
            parse_mountinfo(b"037 1 8:1 / / rw - ext4 /dev/root rw\n").is_none(),
            "a leading-zero decimal refuses"
        );
        assert!(
            parse_mountinfo(b"37 1 08:1 / / rw - ext4 /dev/root rw\n").is_none(),
            "a leading-zero device major refuses"
        );
    }
}
