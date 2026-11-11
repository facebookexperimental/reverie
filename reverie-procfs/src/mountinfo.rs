/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Strict parsers for Linux `mountinfo` snapshots and the `mnt_id`
//! field of `fdinfo` files, in the grammar of
//! `Documentation/filesystems/proc.rst` (mountinfo) and `fs/proc/fd.c`
//! (fdinfo). Producers and consumers that capture or present mount
//! identities share these so they accept exactly the same input.

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

/// The optional-field prefixes that carry mount peer-group numbers.
pub const MOUNT_PEER_PREFIXES: [&[u8]; 3] = [b"shared:", b"master:", b"propagate_from:"];

fn decimal(field: &[u8]) -> Option<u64> {
    if field.is_empty() || field.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(field).ok()?.parse().ok()
}

fn mount_peer_group(field: &[u8]) -> Option<Option<u64>> {
    for prefix in MOUNT_PEER_PREFIXES {
        if let Some(raw) = field.strip_prefix(prefix) {
            return Some(Some(decimal(raw)?));
        }
    }
    Some(None)
}

fn parse_mountinfo_row(line: &[u8]) -> Option<MountInfoRow> {
    let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
    if fields.iter().any(|field| field.is_empty()) {
        return None;
    }
    let separator = fields.iter().position(|field| *field == b"-")?;
    if separator < 6 || separator + 4 != fields.len() {
        return None;
    }
    let mut device = fields[2].split(|byte| *byte == b':');
    let major = u32::try_from(decimal(device.next()?)?).ok()?;
    let minor = u32::try_from(decimal(device.next()?)?).ok()?;
    if device.next().is_some() {
        return None;
    }
    let mut raw_peer_groups = Vec::new();
    for field in &fields[6..separator] {
        if let Some(raw) = mount_peer_group(field)? {
            raw_peer_groups.push(raw);
        } else if field
            .iter()
            .position(|byte| *byte == b':')
            .is_some_and(|separator| decimal(&field[separator + 1..]).is_some())
        {
            // Unknown numeric optional fields can carry mount-namespace
            // identity just like the peer-group fields above. Passing one
            // through would expose an unmapped host identifier, so refuse
            // until its Linux semantics and deterministic mapping are known.
            return None;
        }
    }
    Some(MountInfoRow {
        raw_mount_id: decimal(fields[0])?,
        raw_parent_id: decimal(fields[1])?,
        raw_device: libc::makedev(major, minor),
        root: fields[3].to_vec(),
        raw_peer_groups,
        super_options: fields[separator + 3].to_vec(),
    })
}

/// Strictly parse a Linux `/proc/*/mountinfo` snapshot.
///
/// Empty files are valid empty snapshots. Malformed rows and duplicate mount
/// IDs are rejected so every producer and consumer accepts the same grammar.
pub fn parse_mountinfo(contents: &[u8]) -> Option<Vec<MountInfoRow>> {
    if contents.is_empty() {
        return Some(Vec::new());
    }
    let body = contents.strip_suffix(b"\n").unwrap_or(contents);
    if body.is_empty() {
        return None;
    }
    let rows = body
        .split(|byte| *byte == b'\n')
        .map(parse_mountinfo_row)
        .collect::<Option<Vec<_>>>()?;
    let mut seen = std::collections::BTreeSet::new();
    rows.iter()
        .all(|row| seen.insert(row.raw_mount_id))
        .then_some(rows)
}

/// Parse the one decimal `mnt_id` field required by Linux fdinfo.
///
/// Missing, duplicate, malformed, signed, or out-of-range values are rejected.
/// Sharing this byte parser prevents a capture path from accepting input a
/// later consumer would refuse.
pub fn parse_fdinfo_mount_id(contents: &[u8]) -> Option<u64> {
    let mut mount_id = None;
    for line in contents.split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(b"mnt_id:") else {
            continue;
        };
        let value = value
            .strip_prefix(b"\t")
            .or_else(|| value.strip_prefix(b" "))?;
        if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) || mount_id.is_some()
        {
            return None;
        }
        let text = std::str::from_utf8(value).ok()?;
        mount_id = Some(text.parse().ok()?);
    }
    mount_id
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
}
