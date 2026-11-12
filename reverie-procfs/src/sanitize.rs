/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Sanitizers for kernel-captured `/proc` snapshots: pure transforms
//! from captured bytes to the bytes a guest may see, with host counters,
//! identities and addresses determinized. Each function documents the
//! Linux format it rewrites. Anything time-, CPU- or identity-shaped
//! arrives as a parameter the caller decided; nothing here reads the
//! host. Sanitizers coupled to caller state (mount snapshots, lock
//! ledgers, signal-delivery policy) deliberately do not live here.

/// Every `smaps`/`smaps_rollup` field that counts pages the host currently
/// holds for the mapping: resident, dirty, swapped, huge-page backed, reclaim
/// pending, or locked. Reclaim, writeback, khugepaged and swap change these
/// without any guest action, so both sanitizers report each one as `0 kB`.
/// The zero `Rss` bounds every field except `Swap` and `SwapPss`, which count
/// swapped-out pages, and `Shared_Hugetlb` and `Private_Hugetlb`, which count
/// hugetlb pages that the kernel keeps out of `Rss`. All zero is still a
/// state Linux reports, for example for an untouched mapping.
const SMAPS_ACCOUNTING_FIELDS: &[&str] = &[
    "Rss",
    "Pss",
    "Pss_Dirty",
    "Pss_Anon",
    "Pss_File",
    "Pss_Shmem",
    "Shared_Clean",
    "Shared_Dirty",
    "Private_Clean",
    // Counts a page as dirty when its page-cache copy is dirty, not only
    // when the guest wrote it, so a freshly written executable reports
    // 4 kB per text mapping until host writeback runs.
    "Private_Dirty",
    "Referenced",
    "Anonymous",
    "KSM",
    "LazyFree",
    "AnonHugePages",
    "ShmemPmdMapped",
    "FilePmdMapped",
    "Shared_Hugetlb",
    "Private_Hugetlb",
    "Swap",
    "SwapPss",
    "Locked",
];

fn sockstat_field(fields: &[String], name: &str) -> Option<String> {
    let index = fields.iter().position(|field| field == name)?;
    fields.get(index + 1).cloned()
}

fn replace_sockstat_field(fields: &mut [String], name: &str, value: &str) {
    let Some(index) = fields.iter().position(|field| field == name) else {
        return;
    };
    let Some(field_value) = fields.get_mut(index + 1) else {
        return;
    };
    *field_value = value.to_owned();
}

/// One row of `/proc/locks`, split into fields:
///     `SEQ: [->] CLASS MODE RW PID MAJOR:MINOR:INODE START END`
#[derive(Clone)]
struct LockLine {
    sequence: String,
    waiter: bool,
    fields: Vec<String>,
    owner_index: usize,
    object_index: usize,
}

/// `line` as a `/proc/locks` row, or `None` when it is not one. The owner is
/// a signed integer and the object has three `:`-separated parts.
fn parse_lock_line(line: &str) -> Option<LockLine> {
    let fields = line
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let waiter = fields.get(1).is_some_and(|field| field == "->");
    let details = usize::from(waiter) + 1;
    let owner_index = details + 3;
    let object_index = details + 4;
    let sequence = fields
        .first()
        .and_then(|field| field.strip_suffix(':'))
        .filter(|field| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()))?
        .to_owned();
    if fields.len() != details + 7
        || fields[owner_index].parse::<i64>().is_err()
        || fields[object_index].split(':').count() != 3
    {
        return None;
    }
    Some(LockLine {
        sequence,
        waiter,
        fields,
        owner_index,
        object_index,
    })
}

use std::collections::BTreeMap;

/// `block`, one CPU's block of `/proc/cpuinfo`, with the fields that differ
/// from CPU to CPU of a machine of single-core sockets set for CPU `cpu`, and
/// its frequency set to the virtual 1 GHz.
fn cpuinfo_block_for(block: &[u8], cpu: u32) -> Vec<u8> {
    let replacement = |key: &[u8]| -> Option<String> {
        Some(match key {
            b"processor" => format!("processor\t: {cpu}"),
            b"cpu MHz" => "cpu MHz\t\t: 1000.000".to_owned(),
            b"physical id" => format!("physical id\t: {cpu}"),
            b"siblings" => "siblings\t: 1".to_owned(),
            b"core id" => "core id\t\t: 0".to_owned(),
            b"cpu cores" => "cpu cores\t: 1".to_owned(),
            b"apicid" => format!("apicid\t\t: {cpu}"),
            b"initial apicid" => format!("initial apicid\t: {cpu}"),
            _ => return None,
        })
    };
    let mut normalized = Vec::with_capacity(block.len());
    for line in block.split_inclusive(|byte| *byte == b'\n') {
        let has_newline = line.last() == Some(&b'\n');
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let key = body
            .split(|byte| *byte == b':')
            .next()
            .unwrap_or_default()
            .trim_ascii_end();
        match replacement(key) {
            Some(replaced) => normalized.extend_from_slice(replaced.as_bytes()),
            None => normalized.extend_from_slice(body),
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

fn unix_socket_fields(line: &str) -> Option<(Vec<&str>, &str)> {
    const FIELD_COUNT: usize = 7;

    let mut fields = Vec::with_capacity(FIELD_COUNT);
    let mut remainder = line;
    while fields.len() < FIELD_COUNT {
        remainder = remainder.trim_start_matches(|character: char| character.is_ascii_whitespace());
        if remainder.is_empty() {
            return None;
        }
        let end = remainder
            .find(|character: char| character.is_ascii_whitespace())
            .unwrap_or(remainder.len());
        fields.push(&remainder[..end]);
        remainder = &remainder[end..];
    }

    Some((
        fields,
        remainder.trim_start_matches(|character: char| character.is_ascii_whitespace()),
    ))
}

fn is_fixed_lower_hex(field: &str, width: usize) -> bool {
    field.len() == width
        && field
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Rewrite the device and inode of one mapping header from the caller-supplied
/// table, preserving every other byte of the line and the COLUMN its pathname
/// starts in.
///
/// A raw pair absent from the table is left ALONE rather than guessed at: the
/// table is built from this same snapshot, so a miss means the pair was not
/// determinizable (an anonymous mapping), and inventing a value here is the
/// precise failure this design exists to avoid.
///
/// ⚠️ PRESERVE THE COLUMN, NOT THE PADDING BYTES. This used to copy the raw
/// whitespace run after the inode verbatim, which silently republished the
/// HOST inode's digit count as line length. The kernel pads the pathname to a
/// fixed column (`seq_setwidth(m, 25 + sizeof(void *) * 6)`, measured at column
/// 73 on x86_64), so that run is `73 - len(host_inode_digits)` characters long.
/// Substituting a short determinized inode into it therefore left a line whose
/// every VISIBLE field was deterministic and whose LENGTH was not.
///
/// Measured 2026-08-26 at hermit `d741307158`: for a LiteInst guest, whose
/// `/memfd:liteinst2-trampoline` mappings take inodes from a host-global
/// counter, `cat /proc/self/maps` under `--backend liteinst --strict` produced
/// TWO distinct outputs in 20 runs (14x one, 6x the other) differing in nothing
/// but one space on each memfd line -- the runs where the host counter had
/// crossed a power of ten. With `--detlog-io-buffers` hashing `read()` payloads
/// that is a hard `--verify` divergence, and `/usr/bin/tail -n 2 <fixture>`
/// under LiteInst failed 10 of 20 verified runs on it.
///
/// Padding to the column the RAW line used keeps this in step with the kernel
/// rather than hard-coding 73, and that column does not depend on the inode.
fn rewrite_mapping_header(line: &str, table: &BTreeMap<(u64, u64), (u64, u64)>) -> String {
    let Some(raw) = mapping_header_identity(line) else {
        return line.to_string();
    };
    let Some((det_dev, det_inode)) = table.get(&raw).copied() else {
        return line.to_string();
    };
    let mut out = String::with_capacity(line.len());
    let mut remaining = line;
    // Copy the first three fields (range, perms, offset) verbatim, whitespace
    // included, then substitute the fourth and fifth.
    for _ in 0..3 {
        let field_end = match remaining.find(char::is_whitespace) {
            Some(index) => index,
            None => return line.to_string(),
        };
        let gap_end = remaining[field_end..]
            .find(|c: char| !c.is_whitespace())
            .map_or(remaining.len(), |offset| field_end + offset);
        out.push_str(&remaining[..gap_end]);
        remaining = &remaining[gap_end..];
    }
    let dev_end = match remaining.find(char::is_whitespace) {
        Some(index) => index,
        None => return line.to_string(),
    };
    let dev_gap = remaining[dev_end..]
        .find(|c: char| !c.is_whitespace())
        .map_or(remaining.len(), |offset| dev_end + offset);
    out.push_str(&format!(
        "{:02x}:{:02x}",
        libc::major(det_dev),
        libc::minor(det_dev)
    ));
    out.push_str(&remaining[dev_end..dev_gap]);
    remaining = &remaining[dev_gap..];
    let inode_end = remaining
        .find(char::is_whitespace)
        .unwrap_or(remaining.len());
    let tail = &remaining[inode_end..];
    let pad_len = tail
        .find(|c: char| !c.is_whitespace())
        .unwrap_or(tail.len());
    // Column the pathname starts in on the raw line. `line.len() - remaining.len()`
    // is how much of the line has already been consumed by the first four fields.
    let name_column = (line.len() - remaining.len()) + inode_end + pad_len;
    out.push_str(&det_inode.to_string());
    let name = &tail[pad_len..];
    if name.is_empty() {
        // No pathname, so there is no column to preserve and nothing to pad to.
        // Trailing whitespace here would be pure host-inode-width leakage.
        return out;
    }
    // A determinized inode can in principle be WIDER than the raw one, which
    // leaves no room to pad. One space is what the kernel's `seq_pad` emits in
    // that same situation.
    if out.len() < name_column {
        out.extend(std::iter::repeat_n(' ', name_column - out.len()));
    } else {
        out.push(' ');
    }
    out.push_str(name);
    out
}

/// Parse the DEVICE and INODE from a `maps`/`smaps` mapping header line.
///
/// Layout: `addr-addr perms offset MAJ:MIN INODE [pathname]`, with the device
/// in hex `major:minor` and the inode in decimal. Returns `None` for anything
/// that is not a backed mapping -- anonymous mappings carry `00:00 0`, and
/// there is nothing to determinize about a file that does not exist.
pub(crate) fn mapping_header_identity(line: &str) -> Option<(u64, u64)> {
    let mut fields = line.split_whitespace();
    let _range = fields.next()?;
    let _perms = fields.next()?;
    let _offset = fields.next()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    let inode: u64 = fields.next()?.parse().ok()?;
    if inode == 0 {
        return None;
    }
    Some((libc::makedev(major, minor), inode))
}

fn is_decimal(field: &str) -> bool {
    !field.is_empty()
        && field.bytes().all(|byte| byte.is_ascii_digit())
        && field.parse::<u64>().is_ok()
}

fn is_lower_hex(field: &str, width: usize) -> bool {
    field.len() == width
        && field
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_decimal(field: &str) -> Option<u64> {
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

fn parse_lower_hex(field: &str) -> Option<u64> {
    u64::from_str_radix(field, 16).ok()
}

fn is_smaps_integer_value(value: &str) -> bool {
    let mut fields = value.split_whitespace();
    matches!(
        (fields.next(), fields.next()),
        (Some(number), None) if number.parse::<u64>().is_ok()
    )
}

fn numa_page_accounting_value(field: &str) -> Option<&str> {
    let (name, value) = field.split_once('=')?;
    let fixed_counter = matches!(
        name,
        "active" | "anon" | "dirty" | "mapped" | "mapmax" | "swapcache" | "writeback"
    );
    let node_counter = name
        .strip_prefix('N')
        .is_some_and(|node| !node.is_empty() && node.bytes().all(|byte| byte.is_ascii_digit()));
    (fixed_counter || node_counter).then_some(value)
}

fn is_smaps_mapping_header(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    let Some((start, end)) = fields.next().and_then(|range| range.split_once('-')) else {
        return false;
    };
    let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
    else {
        return false;
    };
    let Some(permissions) = fields.next() else {
        return false;
    };
    let permissions = permissions.as_bytes();
    let valid_permissions = permissions.len() == 4
        && matches!(permissions[0], b'r' | b'-')
        && matches!(permissions[1], b'w' | b'-')
        && matches!(permissions[2], b'x' | b'-')
        && matches!(permissions[3], b'p' | b's');
    let valid_offset = fields
        .next()
        .is_some_and(|offset| u64::from_str_radix(offset, 16).is_ok());
    let valid_device = fields.next().is_some_and(|device| {
        device.split_once(':').is_some_and(|(major, minor)| {
            u64::from_str_radix(major, 16).is_ok() && u64::from_str_radix(minor, 16).is_ok()
        })
    });
    let valid_inode = fields
        .next()
        .is_some_and(|inode| inode.parse::<u64>().is_ok());

    start < end && valid_permissions && valid_offset && valid_device && valid_inode
}

fn is_smaps_kilobyte_value(value: &str) -> bool {
    let mut fields = value.split_whitespace();
    matches!(
        (fields.next(), fields.next(), fields.next()),
        (Some(number), Some("kB"), None) if number.parse::<u64>().is_ok()
    )
}

pub fn sanitize_numeric_lines(contents: &[u8], stable_fields: usize) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(contents.len());
    for line in contents.split_inclusive(|byte| *byte == b'\n') {
        let has_newline = line.last() == Some(&b'\n');
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let fields = body
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let counters = fields.get(stable_fields..).unwrap_or_default();
        if !counters.is_empty()
            && counters
                .iter()
                .all(|field| field.iter().all(u8::is_ascii_digit))
        {
            for (index, field) in fields.iter().take(stable_fields).enumerate() {
                if index > 0 {
                    normalized.push(b' ');
                }
                normalized.extend_from_slice(field);
            }
            for (index, _) in counters.iter().enumerate() {
                if !normalized.is_empty() && normalized.last() != Some(&b'\n') {
                    normalized.push(b' ');
                }
                let value = match index {
                    0 | 4 => 1,
                    2 | 6 => 8,
                    _ => 0,
                };
                normalized.extend_from_slice(value.to_string().as_bytes());
            }
        } else {
            normalized.extend_from_slice(body);
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_stat(contents: &[u8], virtual_identity: Option<(i32, i32)>) -> Vec<u8> {
    const VOLATILE_FIELDS: &[usize] = &[
        10, 11, 12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 39, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    ];

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let Some(comm_start) = text.find(" (") else {
        return contents.to_vec();
    };
    let Some(comm_end) = text.rfind(") ") else {
        return contents.to_vec();
    };
    let comm = &text[comm_start..=comm_end];
    let mut fields = text[comm_end + 2..]
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if fields.len() < 50 {
        return contents.to_vec();
    }

    // `fields` starts with proc stat field 3 (state).
    let pid = if let Some((virtual_pid, virtual_ppid)) = virtual_identity {
        fields[4 - 3] = virtual_ppid.to_string();
        fields[5 - 3] = "0".to_owned();
        fields[6 - 3] = "0".to_owned();
        virtual_pid.to_string()
    } else {
        fields[0] = "S".to_owned();
        text[..comm_start].to_owned()
    };
    for field in VOLATILE_FIELDS {
        fields[*field - 3] = "0".to_owned();
    }
    format!("{pid}{comm} {}\n", fields.join(" ")).into_bytes()
}

pub fn sanitize_statm(contents: &[u8]) -> Vec<u8> {
    let fields = contents
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if fields.len() != 7
        || fields
            .iter()
            .any(|field| !field.iter().all(u8::is_ascii_digit))
    {
        return contents.to_vec();
    }
    b"0 0 0 0 0 0 0\n".to_vec()
}

pub fn sanitize_diskstats(contents: &[u8]) -> Vec<u8> {
    sanitize_numeric_lines(contents, 3)
}

pub fn sanitize_process_io(contents: &[u8]) -> Vec<u8> {
    const COUNTERS: &[&[u8]] = &[
        b"rchar",
        b"wchar",
        b"syscr",
        b"syscw",
        b"read_bytes",
        b"write_bytes",
        b"cancelled_write_bytes",
    ];

    let mut normalized = Vec::with_capacity(contents.len());
    for line in contents.split_inclusive(|byte| *byte == b'\n') {
        let has_newline = line.last() == Some(&b'\n');
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let name_end = body.iter().position(|byte| *byte == b':');
        let name = name_end.map_or(body, |end| &body[..end]);
        if COUNTERS.contains(&name) {
            normalized.extend_from_slice(name);
            normalized.extend_from_slice(b": 0");
        } else {
            normalized.extend_from_slice(body);
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_uptime(contents: &[u8], virtual_uptime_seconds: u64) -> Vec<u8> {
    if contents.is_empty() {
        Vec::new()
    } else {
        format!("{virtual_uptime_seconds}.00 0.00\n").into_bytes()
    }
}

/// `/proc/stat` for a snapshot the kernel's file was captured for (under
/// record and replay, or after a `chroot`): the same bytes the caller renders
/// for its own open ([`render_system_stat`]), so that the file has one layout
/// whichever opened it. Nothing of the capture is kept but whether it was
/// empty: the host's lines, such as its `intr` line with a field per host
/// interrupt number, would show the host.
pub fn sanitize_system_stat(
    contents: &[u8],
    virtual_uptime_seconds: u64,
    virtual_boot_time_seconds: i64,
    cpus: u32,
) -> Vec<u8> {
    if contents.is_empty() {
        Vec::new()
    } else {
        render_system_stat(virtual_uptime_seconds, virtual_boot_time_seconds, cpus)
    }
}

/// The kernel-shaped bytes a rendered `/proc/stat` snapshot starts from:
/// [`render_system_stat`] at uptime 0 and boot time 0 on one CPU.
pub const SYSTEM_STAT_TEMPLATE: &[u8] = b"cpu  0 0 0 0 0 0 0 0 0 0\n\
cpu0 0 0 0 0 0 0 0 0 0 0\n\
intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
ctxt 0\n\
btime 0\n\
processes 0\n\
procs_running 0\n\
procs_blocked 0\n\
softirq 0 0 0 0 0 0 0 0 0 0 0\n";

/// `/proc/stat` in the layout of Linux's `show_stat` (`fs/proc/stat.c`), for
/// a machine of `cpus` CPUs whose uptime is `virtual_uptime_seconds` and whose
/// boot instant is `virtual_boot_time_seconds`:
///
/// - the aggregate line, spelled `cpu` and two spaces as Linux spells it, and
///   a `cpuN` line per CPU, each with Linux's ten columns in USER_HZ (100)
///   ticks. Every CPU spent the whole uptime in the first column (user),
///   none of it idle, as `/proc/uptime`'s idle time of 0 says; the aggregate
///   is their sum.
/// - `intr`, the total and one count per interrupt number, for the
///   [`crate::fixed::NR_IRQS`] numbers every x86 kernel has (`/proc/interrupts`
///   lists lines below it); `ctxt`; `btime`, the boot instant, which is fixed
///   for the run; `processes`, `procs_running` and `procs_blocked`; and
///   `softirq`, the total and one count per softirq ([`crate::fixed::SOFTIRQS`],
///   Linux's `NR_SOFTIRQS`). Every count is 0, as `/proc/interrupts` and
///   `/proc/softirqs` show.
///
/// Nothing here comes from the host, so every backend renders the same bytes.
pub fn render_system_stat(
    virtual_uptime_seconds: u64,
    virtual_boot_time_seconds: i64,
    cpus: u32,
) -> Vec<u8> {
    // USER_HZ.
    let per_cpu = virtual_uptime_seconds.saturating_mul(100);
    let total = per_cpu.saturating_mul(u64::from(cpus));
    let idle_columns = " 0".repeat(9);
    let mut out = format!("cpu  {total}{idle_columns}\n");
    for cpu in 0..cpus {
        out += &format!("cpu{cpu} {per_cpu}{idle_columns}\n");
    }
    out += &format!("intr 0{}\n", " 0".repeat(crate::fixed::NR_IRQS));
    out += &format!(
        "ctxt 0\nbtime {virtual_boot_time_seconds}\nprocesses 0\nprocs_running 0\nprocs_blocked 0\n"
    );
    out += &format!("softirq 0{}\n", " 0".repeat(crate::fixed::SOFTIRQS.len()));
    out.into_bytes()
}

pub fn sanitize_pty_nr(contents: &[u8], virtual_count: usize) -> Vec<u8> {
    let Ok(value) = std::str::from_utf8(contents) else {
        return Vec::new();
    };
    if value.trim().parse::<u64>().is_err() {
        return Vec::new();
    }
    format!("{virtual_count}\n").into_bytes()
}

pub fn sanitize_sockstat(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let mut fields = body
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        match fields.first().map(String::as_str) {
            Some("TCP:") => {
                let inuse = sockstat_field(&fields, "inuse").unwrap_or_else(|| "0".to_owned());
                replace_sockstat_field(&mut fields, "orphan", "0");
                replace_sockstat_field(&mut fields, "alloc", &inuse);
                replace_sockstat_field(&mut fields, "mem", "0");
            }
            Some("UDP:") => replace_sockstat_field(&mut fields, "mem", "0"),
            _ => {}
        }

        normalized.extend_from_slice(fields.join(" ").as_bytes());
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_self_sched(contents: &[u8]) -> Vec<u8> {
    const FLOAT_FIELDS: &[&str] = &["se.exec_start", "se.vruntime", "se.sum_exec_runtime"];
    const INTEGER_FIELDS: &[&str] = &[
        "se.nr_migrations",
        "nr_switches",
        "nr_voluntary_switches",
        "nr_involuntary_switches",
        "se.avg.load_sum",
        "se.avg.runnable_sum",
        "se.avg.util_sum",
        "se.avg.load_avg",
        "se.avg.runnable_avg",
        "se.avg.util_avg",
        "se.avg.last_update_time",
        "se.avg.util_est",
        "clock-delta",
    ];
    const STABLE_INTEGER_FIELDS: &[&str] = &[
        "se.load.weight",
        "policy",
        "prio",
        "se.slice",
        "ext.enabled",
        "uclamp.min",
        "uclamp.max",
        "effective uclamp.min",
        "effective uclamp.max",
    ];
    const UCLAMP_FIELDS: &[(&str, &str)] = &[
        ("uclamp.min", "0"),
        ("uclamp.max", "1024"),
        ("effective uclamp.min", "0"),
        ("effective uclamp.max", "1024"),
    ];
    // NUMA balancing's lines, with its `current_node=` line and a
    // `numa_faults` line per node, which a kernel built without NUMA does
    // not print (`sched_show_numa`, kernel/sched/debug.c:1250-1262 at v7.1,
    // under `CONFIG_NUMA_BALANCING`, which depends on `CONFIG_NUMA`): each is
    // checked as the others are and left out, as is how many nodes the host
    // has.
    const NUMA_BALANCING_FIELDS: &[&str] = &[
        "mm->numa_scan_seq",
        "numa_pages_migrated",
        "numa_preferred_nid",
        "total_numa_faults",
    ];

    let Ok(text) = std::str::from_utf8(contents) else {
        return Vec::new();
    };
    let mut normalized = Vec::with_capacity(contents.len());
    let mut core_fields_seen = [false; 3];
    let mut header_seen = false;

    for (line_index, line) in text.split_inclusive('\n').enumerate() {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        if line_index == 0 {
            let Some((name, details)) = body.rsplit_once(" (") else {
                return Vec::new();
            };
            let Some(details) = details.strip_suffix(')') else {
                return Vec::new();
            };
            let Some((pid, threads)) = details.split_once(", #threads: ") else {
                return Vec::new();
            };
            if pid.parse::<i32>().is_err() || threads.parse::<u64>().is_err() {
                return Vec::new();
            }
            normalized.extend_from_slice(format!("{name} (0, #threads: 1)").as_bytes());
            if has_newline {
                normalized.push(b'\n');
            }
            header_seen = true;
            continue;
        }
        let Some((left, right)) = body.split_once(':') else {
            if !body.is_empty() && body.bytes().all(|byte| byte == b'-') {
                normalized.extend_from_slice(body.as_bytes());
            } else if body.starts_with("current_node=") {
                let fields = body
                    .replace(',', "")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if fields.len() != 2
                    || !fields.iter().all(|field| {
                        field.split_once('=').is_some_and(|(name, value)| {
                            matches!(name, "current_node" | "numa_group_id")
                                && value.parse::<i64>().is_ok()
                        })
                    })
                {
                    return Vec::new();
                }
                continue;
            } else if body.starts_with("numa_faults ") {
                let fields = body.split_whitespace().skip(1).collect::<Vec<_>>();
                let expected = [
                    "node",
                    "task_private",
                    "task_shared",
                    "group_private",
                    "group_shared",
                ];
                if fields.len() != expected.len()
                    || !fields.iter().zip(expected).all(|(field, expected)| {
                        field.split_once('=').is_some_and(|(name, value)| {
                            name == expected && value.parse::<u64>().is_ok()
                        })
                    })
                {
                    return Vec::new();
                }
                continue;
            } else {
                return Vec::new();
            }
            if has_newline {
                normalized.push(b'\n');
            }
            continue;
        };
        let label = left.trim();
        if NUMA_BALANCING_FIELDS.contains(&label) {
            if right.trim().parse::<i128>().is_err() {
                return Vec::new();
            }
            continue;
        }
        let replacement = if let Some(index) = FLOAT_FIELDS.iter().position(|field| *field == label)
        {
            let Ok(value) = right.trim().parse::<f64>() else {
                return Vec::new();
            };
            if !value.is_finite() || value.is_sign_negative() {
                return Vec::new();
            }
            core_fields_seen[index] = true;
            Some("0.000000")
        } else if let Some((_, replacement)) =
            UCLAMP_FIELDS.iter().find(|(field, _)| *field == label)
        {
            if right.trim().parse::<u128>().is_err() {
                return Vec::new();
            }
            Some(*replacement)
        } else if INTEGER_FIELDS.contains(&label) {
            if right.trim().parse::<u128>().is_err() {
                return Vec::new();
            }
            Some("0")
        } else if STABLE_INTEGER_FIELDS.contains(&label) {
            if right.trim().parse::<i128>().is_err() {
                return Vec::new();
            }
            None
        } else if right.trim().parse::<u128>().is_ok() {
            // New kernels may append observational scheduler counters. Keep
            // forward-compatible numeric telemetry deterministic without
            // accepting malformed or negative unknown fields.
            Some("0")
        } else if right
            .trim()
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && !value.is_sign_negative())
            && right.trim().contains('.')
        {
            // With kernel.sched_schedstats=1 the kernel adds nanosecond fields
            // printed as milliseconds with six decimals (sum_sleep_runtime,
            // wait_max, avg_atom, ...; kernel/sched/debug.c,
            // proc_sched_show_task). They are host timing, so they become
            // zero; refusing them emptied the whole file for the guest.
            Some("0.000000")
        } else {
            return Vec::new();
        };

        if let Some(value) = replacement {
            normalized.extend_from_slice(left.as_bytes());
            normalized.extend_from_slice(b": ");
            normalized.extend_from_slice(value.as_bytes());
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }

    if header_seen && core_fields_seen.iter().all(|seen| *seen) {
        normalized
    } else {
        Vec::new()
    }
}

pub fn sanitize_fdinfo(contents: &[u8], identity: Option<(u64, i32, u64, u64)>) -> Vec<u8> {
    let Some((virtual_inode, logical_flags, virtual_open_file, virtual_mount_id)) = identity else {
        return Vec::new();
    };
    let Ok(text) = std::str::from_utf8(contents) else {
        return Vec::new();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        if body.starts_with("mnt_id:") {
            normalized.extend_from_slice(format!("mnt_id:\t{virtual_mount_id}").as_bytes());
        } else if body.starts_with("ino:") {
            normalized.extend_from_slice(format!("ino:\t{virtual_inode}").as_bytes());
        } else if body.starts_with("flags:") {
            normalized.extend_from_slice(format!("flags:\t{logical_flags:07o}").as_bytes());
        } else if body.starts_with("eventfd-id:") {
            normalized.extend_from_slice(format!("eventfd-id: {virtual_open_file}").as_bytes());
        } else if body.starts_with("Pid:") {
            normalized.extend_from_slice(b"Pid:\t1");
        } else if body.starts_with("NSpid:") {
            normalized.extend_from_slice(b"NSpid:\t1");
        } else if body.starts_with("tfd:")
            || body.starts_with("inotify ")
            || body.starts_with("lock:")
        {
            return Vec::new();
        } else {
            let allowed = body.split_once(':').is_some_and(|(label, _)| {
                matches!(
                    label,
                    "pos"
                        | "eventfd-count"
                        | "eventfd-semaphore"
                        | "sigmask"
                        | "clockid"
                        | "ticks"
                        | "settime flags"
                        | "it_value"
                        | "it_interval"
                        | "seals"
                        // Linux reports the number of descriptors currently
                        // queued on this socket. It is socket state, not a
                        // host-assigned identity, so preserve it verbatim.
                        | "scm_fds"
                )
            });
            if !allowed {
                return Vec::new();
            }
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_smaps_rollup(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let accounting_label = body.split_once(':').and_then(|(label, value)| {
            let mut fields = value.split_whitespace();
            let amount = fields.next()?;
            (amount.parse::<u64>().is_ok()
                && fields.next() == Some("kB")
                && fields.next().is_none())
            .then_some(label)
        });
        if let Some(label) =
            accounting_label.filter(|label| SMAPS_ACCOUNTING_FIELDS.contains(label))
        {
            normalized.extend_from_slice(label.as_bytes());
            normalized.extend_from_slice(b":\t0 kB");
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

/// A process's cgroup, as for a process in the root cgroup: every
/// `hierarchy-ID:controllers:path` line keeps its ID and controllers and gets
/// the path `/`. That agrees with the guest's other views, which are the
/// initial cgroup namespace's (`/proc/self/ns/cgroup`) and the host's
/// `/sys/fs/cgroup`. The host's path names whatever launched Hermit, such as a
/// systemd unit named after its start time, so two separately launched runs
/// read different bytes, and Go, which reads this file at every process start
/// to size GOMAXPROCS from its cgroup's `cpu.max`, then took different
/// branches, ran for different virtual times and wrote different timestamps
/// into its build cache (https://github.com/rrnewton/hermit/issues/4378).
/// With the path `/`, Go reads `/sys/fs/cgroup/cpu.max` instead: absent on a
/// host's real root cgroup, but the launcher's quota at the root of a private
/// cgroup namespace (a container), so launchers with different quotas can
/// still differ (https://github.com/rrnewton/hermit/issues/4388).
///
/// Split on bytes: a cgroup directory name may hold any byte but `/` and NUL,
/// and a name that is not UTF-8 must not pass through.
pub fn sanitize_process_cgroup(contents: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(contents.len());
    for line in contents.split_inclusive(|&byte| byte == b'\n') {
        let has_newline = line.ends_with(b"\n");
        let body = line.strip_suffix(b"\n").unwrap_or(line);
        let mut fields = body.splitn(3, |&byte| byte == b':');
        match (fields.next(), fields.next(), fields.next()) {
            (Some(hierarchy), Some(controllers), Some(_path)) => {
                normalized.extend_from_slice(hierarchy);
                normalized.push(b':');
                normalized.extend_from_slice(controllers);
                normalized.extend_from_slice(b":/");
            }
            _ => normalized.extend_from_slice(body),
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_arch_status(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        // The kernel prints -1 for a task that has never used AVX-512
        // (arch/x86/kernel/fpu/xstate.c, avx512_status), so whether a guest
        // sees -1 or a time depends on whether the host's libraries chose
        // AVX-512 code. Both become 0, the same on every host.
        let elapsed = body
            .strip_prefix("AVX512_elapsed_ms:")
            .map(str::trim)
            .filter(|value| *value == "-1" || value.parse::<u64>().is_ok());
        if elapsed.is_some() {
            normalized.extend_from_slice(b"AVX512_elapsed_ms:\t0");
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

pub fn sanitize_pressure(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let fields = body
            .split_whitespace()
            .map(|field| {
                let Some((name, _)) = field.split_once('=') else {
                    return field.to_owned();
                };
                match name {
                    "avg10" | "avg60" | "avg300" => format!("{name}=0.00"),
                    "total" => "total=0".to_owned(),
                    _ => field.to_owned(),
                }
            })
            .collect::<Vec<_>>();

        normalized.extend_from_slice(fields.join(" ").as_bytes());
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

/// A task's `schedstat` (`proc_pid_schedstat`, fs/proc/base.c:511-523 at
/// v6.16): its runtime, `runtime` (`se.sum_exec_runtime`, in nanoseconds),
/// where the caller knows it, else 0; and 0 for the time it waited on a run
/// queue and the times it ran (`sched_info.run_delay`, `pcount`), which
/// callers of this crate do not model, as `getrusage`'s context-switch counts stay 0.
pub fn sanitize_task_schedstat(contents: &[u8], runtime_nanos: Option<u64>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|field| field.parse::<u64>().is_err()) {
        return contents.to_vec();
    }
    let runtime = runtime_nanos.unwrap_or(0);
    let newline = if text.ends_with('\n') { "\n" } else { "" };
    format!("{runtime} 0 0{newline}").into_bytes()
}

/// Exposes the virtual CPUs, `cpus` of them, and hides host CPU count,
/// hotplug state, CPU identifiers, and live network backlog counters: one
/// idle row per CPU, whose thirteenth column is the CPU's number, as
/// `softnet_seq_show` prints it.
pub fn sanitize_softnet_stat(cpus: u32) -> Vec<u8> {
    (0..cpus)
        .map(|cpu| format!("{}{cpu:08x} 00000000 00000000\n", "00000000 ".repeat(12)))
        .collect::<String>()
        .into_bytes()
}

pub fn sanitize_protocols(contents: &[u8]) -> Vec<u8> {
    const HEADER: &[&str] = &[
        "protocol", "size", "sockets", "memory", "press", "maxhdr", "slab", "module",
    ];

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return contents.to_vec();
    };
    let header_fields = header.split_whitespace().collect::<Vec<_>>();
    if !header_fields.starts_with(HEADER) {
        return contents.to_vec();
    }

    let mut normalized = Vec::new();
    normalized.push(header.to_owned());
    for line in lines {
        let mut fields = line
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if fields.len() != header_fields.len()
            || fields[1].parse::<u64>().is_err()
            || fields[2].parse::<u64>().is_err()
            || (fields[3] != "-1" && fields[3].parse::<u64>().is_err())
        {
            return contents.to_vec();
        }

        fields[2] = "0".to_owned();
        if fields[3] != "-1" {
            fields[3] = "0".to_owned();
        }
        normalized.push(fields.join(" "));
    }
    if normalized.len() == 1 {
        return contents.to_vec();
    }

    let mut output = normalized.join("\n").into_bytes();
    if text.ends_with('\n') {
        output.push(b'\n');
    }
    output
}

pub fn sanitize_random_uuid(contents: &[u8], mut random: [u8; 16]) -> Vec<u8> {
    const HYPHENS: &[usize] = &[8, 13, 18, 23];

    if contents.len() != 37 || contents[36] != b'\n' {
        return contents.to_vec();
    }
    for (index, byte) in contents[..36].iter().copied().enumerate() {
        if HYPHENS.contains(&index) {
            if byte != b'-' {
                return contents.to_vec();
            }
        } else if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
            return contents.to_vec();
        }
    }
    if contents[14] != b'4' || !matches!(contents[19], b'8' | b'9' | b'a' | b'b') {
        return contents.to_vec();
    }

    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n",
        random[0],
        random[1],
        random[2],
        random[3],
        random[4],
        random[5],
        random[6],
        random[7],
        random[8],
        random[9],
        random[10],
        random[11],
        random[12],
        random[13],
        random[14],
        random[15]
    )
    .into_bytes()
}

/// Reports `/proc/cpuinfo` for the virtual CPUs, `cpus` of them, the ones
/// `sched_getaffinity` returns, where CPUID is the host's. The kernel prints
/// one block per online CPU, separated by blank lines; the first block is
/// kept, once per virtual CPU, so the processor count no longer follows the
/// host's. Each block's topology fields describe CPU N of a machine of
/// single-core sockets: a one-core, one-thread package numbered N, whose
/// APIC ID is N; its frequency is the virtual 1 GHz.
pub fn sanitize_cpuinfo(contents: &[u8], cpus: u32) -> Vec<u8> {
    let mut first_block = Vec::with_capacity(contents.len());
    let mut seen_processor = false;
    for line in contents.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"processor") {
            if seen_processor {
                // The second CPU's block: the blank line that ended the first
                // one has already been copied, as the kernel's file ends.
                break;
            }
            seen_processor = true;
        }
        first_block.extend_from_slice(line);
    }
    (0..cpus)
        .flat_map(|cpu| cpuinfo_block_for(&first_block, cpu))
        .collect()
}

pub fn sanitize_unix_sockets(contents: &[u8]) -> Vec<u8> {
    const HEADER: [&str; 8] = [
        "Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path",
    ];
    const ZERO_NUM: &str = "0000000000000000:";

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let Some(body) = text.strip_suffix('\n') else {
        return contents.to_vec();
    };
    let mut lines = body.split('\n');
    let Some(header) = lines.next() else {
        return contents.to_vec();
    };
    if !header.split_whitespace().eq(HEADER) {
        return contents.to_vec();
    }

    let mut rows = Vec::new();
    for line in lines {
        let Some((mut fields, path)) = unix_socket_fields(line) else {
            return contents.to_vec();
        };
        let Some(num) = fields[0].strip_suffix(':') else {
            return contents.to_vec();
        };
        if !is_fixed_lower_hex(num, 16)
            || !is_fixed_lower_hex(fields[1], 8)
            || !is_fixed_lower_hex(fields[2], 8)
            || !is_fixed_lower_hex(fields[3], 8)
            || !is_fixed_lower_hex(fields[4], 4)
            || !is_fixed_lower_hex(fields[5], 2)
            || !is_decimal(fields[6])
        {
            return contents.to_vec();
        }

        fields[0] = ZERO_NUM;
        fields[6] = "0";
        let mut row = fields.join(" ");
        if !path.is_empty() {
            row.push(' ');
            row.push_str(path);
        }
        rows.push(row);
    }
    rows.sort_unstable();

    let mut normalized = String::with_capacity(text.len());
    normalized.push_str(header);
    normalized.push('\n');
    for row in rows {
        normalized.push_str(&row);
        normalized.push('\n');
    }
    normalized.into_bytes()
}

pub fn sanitize_netlink_sockets(contents: &[u8]) -> Vec<u8> {
    const HEADER: [&str; 10] = [
        "sk", "Eth", "Pid", "Groups", "Rmem", "Wmem", "Dump", "Locks", "Drops", "Inode",
    ];
    const ZERO_POINTER: &str = "0000000000000000";

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let Some(body) = text.strip_suffix('\n') else {
        return contents.to_vec();
    };
    let mut lines = body.split('\n');
    let Some(header) = lines.next() else {
        return contents.to_vec();
    };
    if !header.split_whitespace().eq(HEADER) {
        return contents.to_vec();
    }

    let mut rows = Vec::new();
    for line in lines {
        let mut fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != HEADER.len()
            || !is_lower_hex(fields[0], 16)
            || !is_lower_hex(fields[3], 8)
        {
            return contents.to_vec();
        }

        let Some(key) = [
            parse_decimal(fields[1]),
            parse_decimal(fields[2]),
            parse_lower_hex(fields[3]),
            parse_decimal(fields[4]),
            parse_decimal(fields[5]),
            parse_decimal(fields[6]),
            parse_decimal(fields[7]),
            parse_decimal(fields[8]),
        ]
        .into_iter()
        .collect::<Option<Vec<_>>>() else {
            return contents.to_vec();
        };
        if parse_decimal(fields[9]).is_none() {
            return contents.to_vec();
        }

        fields[0] = ZERO_POINTER;
        fields[9] = "0";
        rows.push((key, fields.join(" ")));
    }
    rows.sort_unstable();

    let mut normalized = String::with_capacity(text.len());
    normalized.push_str(header);
    normalized.push('\n');
    for (_, row) in rows {
        normalized.push_str(&row);
        normalized.push('\n');
    }
    normalized.into_bytes()
}

/// Zero the host-assigned identities in `/proc/net/tcp{,6}` and
/// `/proc/net/udp{,6}`.
///
/// Two columns carry host state and both differ on every run. Measured under
/// `hermit run --strict`, two runs of a guest binding two listeners:
///
/// ```text
/// run 1  ... 0 3066787052 1 0000000042a27170 100 ...
/// run 2  ... 0 3071433840 1 000000005b1c887b 100 ...
/// ```
///
/// `inode` is a host-global counter and `pointer` is the kernel socket address.
/// This mirrors `sanitize_netlink_sockets`, which zeroes the same two kinds of
/// field, and it is the text half of the `AF_INET`/`AF_INET6` work in
/// the caller's sock_diag view: the binary and text views of this table agreed before
/// (both leaking) and must still agree after.
///
/// Zero is in range for `inode` rather than a substitute chosen here. The
/// kernel emits it itself for sockets with no owning file -- on the host that
/// developed this, `/proc/net/tcp` carried 176 rows of which 12 had inode 0,
/// all in state 06 (`TCP_TIME_WAIT`).
///
/// Row ORDER also varies and is canonicalized here, which zeroing alone does
/// not fix. Measured after the two columns above were already zeroed, six runs
/// of the same guest binding ports 8000 and 8001: port 8000 appeared in row 0
/// on four runs and in row 1 on the other two. The kernel walks a hash table,
/// so the order depends on host-side bucket state. Rows are therefore sorted on
/// their content with `sl` excluded, and `sl` is then renumbered to match --
/// sorting without renumbering would leave a positional index contradicting its
/// own position.
///
/// Fail-open on any unexpected shape, like the other sanitizers.
pub fn sanitize_inet_sockets(contents: &[u8]) -> Vec<u8> {
    /// `inode`, counting from zero.
    const INODE_FIELD: usize = 9;
    /// The kernel socket pointer, printed `%pK` as 16 lower-hex digits.
    const POINTER_FIELD: usize = 11;
    /// `udp`/`udp6` rows are 13 fields, `tcp`/`tcp6` 17. Both put the two
    /// host-state columns at the same index, so only the shorter is required.
    const MIN_FIELDS: usize = 13;
    const ZERO_POINTER: &str = "0000000000000000";

    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let Some(body) = text.strip_suffix('\n') else {
        return contents.to_vec();
    };
    let mut lines = body.split('\n');
    let Some(header) = lines.next() else {
        return contents.to_vec();
    };
    // The four files have four different headers, so this checks the shape
    // rather than an exact string: first column `sl`, and an `inode` column.
    let header_fields = header.split_whitespace().collect::<Vec<_>>();
    if header_fields.first() != Some(&"sl") || !header_fields.contains(&"inode") {
        return contents.to_vec();
    }

    let mut rows = Vec::new();
    for line in lines {
        let mut fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < MIN_FIELDS {
            return contents.to_vec();
        }
        if parse_decimal(fields[INODE_FIELD]).is_none() || !is_lower_hex(fields[POINTER_FIELD], 16)
        {
            return contents.to_vec();
        }
        fields[INODE_FIELD] = "0";
        fields[POINTER_FIELD] = ZERO_POINTER;
        // Sort on everything but the index, then reassign the index, so the
        // ordering key cannot be perturbed by the very column it decides.
        rows.push(fields[1..].join(" "));
    }
    rows.sort_unstable();

    let mut normalized = String::with_capacity(text.len());
    normalized.push_str(header);
    normalized.push('\n');
    for (index, row) in rows.iter().enumerate() {
        normalized.push_str(&format!("{index}: {row}\n"));
    }
    normalized.into_bytes()
}

pub fn sanitize_numa_maps(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let mut normalized = Vec::with_capacity(contents.len());
    let mut row_count = 0;

    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let fields = body.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 2 || u64::from_str_radix(fields[0], 16).is_err() {
            return contents.to_vec();
        }

        let mut kept = Vec::with_capacity(fields.len());
        for field in fields {
            if let Some(value) = numa_page_accounting_value(field) {
                if value.parse::<u64>().is_err() {
                    return contents.to_vec();
                }
            } else {
                kept.push(field);
            }
        }
        normalized.extend_from_slice(kept.join(" ").as_bytes());
        if has_newline {
            normalized.push(b'\n');
        }
        row_count += 1;
    }

    if row_count == 0 {
        contents.to_vec()
    } else {
        normalized
    }
}

pub fn sanitize_smaps(contents: &[u8], table: &BTreeMap<(u64, u64), (u64, u64)>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let mut normalized = Vec::with_capacity(contents.len());
    let mut mapping_count = 0;
    let mut accounting_count = 0;

    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);

        if is_smaps_mapping_header(body) {
            mapping_count += 1;
            // Was passed through verbatim, which left smaps carrying the same
            // raw device and inode as maps while appearing sanitized.
            normalized.extend_from_slice(rewrite_mapping_header(body, table).as_bytes());
        } else {
            if mapping_count == 0 {
                return contents.to_vec();
            }
            let Some((label, value)) = body.split_once(':') else {
                return contents.to_vec();
            };

            if SMAPS_ACCOUNTING_FIELDS.contains(&label) {
                if !is_smaps_kilobyte_value(value) {
                    return contents.to_vec();
                }
                normalized.extend_from_slice(label.as_bytes());
                normalized.extend_from_slice(b":\t0 kB");
                accounting_count += 1;
            } else {
                let valid_static_field = match label {
                    "Size" | "KernelPageSize" | "MMUPageSize" => is_smaps_kilobyte_value(value),
                    "THPeligible" | "ProtectionKey" => is_smaps_integer_value(value),
                    "VmFlags" => value
                        .split_whitespace()
                        .all(|flag| flag.bytes().all(|byte| byte.is_ascii_alphanumeric())),
                    _ => false,
                };
                if !valid_static_field {
                    return contents.to_vec();
                }
                normalized.extend_from_slice(body.as_bytes());
            }
        }

        if has_newline {
            normalized.push(b'\n');
        }
    }

    if mapping_count == 0 || accounting_count == 0 {
        contents.to_vec()
    } else {
        normalized
    }
}

/// `/proc/*/maps`: rewrite only the device and inode columns.
pub fn sanitize_maps(contents: &[u8], table: &BTreeMap<(u64, u64), (u64, u64)>) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        out.push_str(&rewrite_mapping_header(body, table));
        if has_newline {
            out.push('\n');
        }
    }
    out.into_bytes()
}

pub fn sanitize_rtc(contents: &[u8], rtc_time: &str, rtc_date: &str) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return contents.to_vec();
    };

    let mut normalized = Vec::with_capacity(contents.len());
    for line in text.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let body = line.strip_suffix('\n').unwrap_or(line);
        let replacement = body.split_once(':').and_then(|(key, _)| {
            let value = match key.trim() {
                "rtc_time" => rtc_time,
                "rtc_date" => rtc_date,
                "alrm_time" => "00:00:00",
                "alrm_date" => rtc_date,
                "alarm_IRQ"
                | "alrm_pending"
                | "update IRQ enabled"
                | "periodic IRQ enabled"
                | "periodic_IRQ"
                | "update_IRQ" => "no",
                "periodic IRQ frequency" | "max user IRQ frequency" | "periodic_freq" => "0",
                _ => return None,
            };
            Some(format!("{key}: {value}"))
        });
        if let Some(replacement) = replacement {
            normalized.extend_from_slice(replacement.as_bytes());
        } else {
            normalized.extend_from_slice(body.as_bytes());
        }
        if has_newline {
            normalized.push(b'\n');
        }
    }
    normalized
}

//
// `/proc/locks` rows have the shape
//     `SEQ: [->] CLASS MODE RW PID MAJOR:MINOR:INODE START END`
// where the leading `SEQ:` is a kernel-global lock counter, `PID` is the owner
// task, and `MAJOR:MINOR:INODE` identifies the backing object. All three are
// host-specific and vary run-to-run, and the kernel emits rows in an internal
// order. A granted lock and the blocked waiters queued behind it share one
// `SEQ`, and a waiter row is marked with `->`.
//
// Rather than collapse every identity to a single constant, derive dense IDs
// from stable lock semantics. Equal raw values remain equal, distinct objects
// stay distinct, holder/waiter groups stay adjacent, and raw ID renumbering or
// row reordering does not change the resulting snapshot. An unknown format
// fails the complete snapshot closed instead of leaking any raw identities.
//
// The rows reaching this function are the guest's own: the caller has already
// dropped every other process's rows (`locks::keep_lock_rows`), so a lock
// outside the container neither adds a row nor shifts the numbering of the
// guest's rows.
pub fn sanitize_locks(contents: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else {
        return Vec::new();
    };
    if text.is_empty() {
        return Vec::new();
    }

    let mut rows: Vec<LockLine> = Vec::new();
    for line in text.lines() {
        let Some(row) = parse_lock_line(line) else {
            return Vec::new();
        };
        rows.push(row);
    }

    let mut object_signatures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in &rows {
        let mut signature = row.fields.clone();
        signature[0] = if row.waiter { "waiter" } else { "holder" }.to_owned();
        signature[row.owner_index] = "owner".to_owned();
        signature[row.object_index] = "object".to_owned();
        object_signatures
            .entry(row.fields[row.object_index].clone())
            .or_default()
            .push(signature.join(" "));
    }
    let mut objects = object_signatures.into_iter().collect::<Vec<_>>();
    for (_, signatures) in &mut objects {
        signatures.sort_unstable();
    }
    objects.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    let object_ids = objects
        .into_iter()
        .enumerate()
        .map(|(index, (object, _))| (object, index + 1))
        .collect::<BTreeMap<_, _>>();
    for row in &mut rows {
        let object_id = object_ids[&row.fields[row.object_index]];
        row.fields[row.object_index] = format!("00:00:{object_id}");
    }

    let mut owner_signatures: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for row in &rows {
        let owner = row.fields[row.owner_index]
            .parse::<i64>()
            .expect("owner was validated above");
        if owner == -1 {
            continue;
        }
        let mut signature = row.fields.clone();
        signature[0] = if row.waiter { "waiter" } else { "holder" }.to_owned();
        signature[row.owner_index] = "owner".to_owned();
        owner_signatures
            .entry(owner)
            .or_default()
            .push(signature.join(" "));
    }
    let mut owners = owner_signatures.into_iter().collect::<Vec<_>>();
    for (_, signatures) in &mut owners {
        signatures.sort_unstable();
    }
    owners.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    let owner_ids = owners
        .into_iter()
        .enumerate()
        .map(|(index, (owner, _))| (owner, index + 1))
        .collect::<BTreeMap<_, _>>();
    for row in &mut rows {
        let owner = row.fields[row.owner_index]
            .parse::<i64>()
            .expect("owner was validated above");
        if owner != -1 {
            row.fields[row.owner_index] = owner_ids[&owner].to_string();
        }
    }

    let mut groups: BTreeMap<String, Vec<LockLine>> = BTreeMap::new();
    for row in rows {
        groups.entry(row.sequence.clone()).or_default().push(row);
    }
    let mut groups = groups.into_values().collect::<Vec<_>>();
    for rows in &mut groups {
        rows.sort_by(|left, right| {
            left.waiter
                .cmp(&right.waiter)
                .then_with(|| left.fields.cmp(&right.fields))
        });
    }
    groups.sort_by_key(|rows| {
        rows.iter()
            .map(|row| {
                let mut fields = row.fields.clone();
                fields[0] = "sequence:".to_owned();
                fields.join(" ")
            })
            .collect::<Vec<_>>()
    });

    let normalized_rows = groups
        .into_iter()
        .enumerate()
        .flat_map(|(sequence, rows)| {
            rows.into_iter().map(move |mut row| {
                row.fields[0] = format!("{}:", sequence + 1);
                row.fields.join(" ")
            })
        })
        .collect::<Vec<_>>();
    let mut normalized = normalized_rows.join("\n").into_bytes();
    if text.ends_with('\n') {
        normalized.push(b'\n');
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_normalizes_runtime_counters() {
        let input = b"3 (name with spaces) R 1 0 0 0 -1 0 89 0 1 2 3 4 5 6 20 0 1 7 520343512 2879488 123 18446744073709551615 100 200 300 0 0 0 0 3145728 0 0 0 0 17 114 0 0 9 10 11 400 500 600 700 800 900 1000 0\n";
        let output = String::from_utf8(sanitize_stat(input, Some((3, 1)))).unwrap();
        let comm_end = output.rfind(") ").unwrap();
        let fields = output[comm_end + 2..]
            .split_whitespace()
            .collect::<Vec<_>>();
        for field in [
            10, 11, 12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36, 37, 39, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
        ] {
            assert_eq!(fields[field - 3], "0", "field {field} was not normalized");
        }
        assert!(output.starts_with("3 (name with spaces) R 1 0 0 "));
    }

    #[test]
    fn softnet_stat_synthesizes_one_idle_row_per_virtual_cpu() {
        let row = |cpu: &str| {
            format!(
                "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \
                 00000000 00000000 00000000 00000000 {cpu} 00000000 00000000\n"
            )
        };
        assert_eq!(
            String::from_utf8(sanitize_softnet_stat(1)).unwrap(),
            row("00000000")
        );
        assert_eq!(
            String::from_utf8(sanitize_softnet_stat(3)).unwrap(),
            row("00000000") + &row("00000001") + &row("00000002")
        );
    }

    #[test]
    fn system_stat_uses_virtual_uptime_and_boot_time() {
        // Linux's layout (`show_stat`): `cpu` and two spaces, ten columns, a
        // count per interrupt number below NR_IRQS, and the ten softirqs.
        let expected: &[u8] = b"cpu  12000 0 0 0 0 0 0 0 0 0\n\
cpu0 12000 0 0 0 0 0 0 0 0 0\n\
intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
ctxt 0\n\
btime 1767225480\n\
processes 0\n\
procs_running 0\n\
procs_blocked 0\n\
softirq 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(render_system_stat(120, 1_767_225_480, 1), expected);
        for host in [
            &b"cpu  1 2 3 4 5 6 7 8 9 10\ncpu0 1 2 3 4 5 6 7 8 9 10\nintr 9 8 7\nbtime 1234\nprocesses 55\n"[..],
            b"cpu  1 2 3\ncpu0 1 2 3\ncpu1 4 5 6\nintr 400 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20\nctxt 99\nbtime 7\nsoftirq 5 1 1 1 1 1\n",
            b"x",
        ] {
            assert_eq!(
                sanitize_system_stat(host, 120, 1_767_225_480, 1),
                expected,
                "{}",
                String::from_utf8_lossy(host)
            );
        }
        assert_eq!(sanitize_system_stat(b"", 120, 1_767_225_480, 1), b"");
        let two = String::from_utf8(render_system_stat(120, -5, 2)).unwrap();
        assert!(
            two.starts_with(
                "cpu  24000 0 0 0 0 0 0 0 0 0\ncpu0 12000 0 0 0 0 0 0 0 0 0\n\
                 cpu1 12000 0 0 0 0 0 0 0 0 0\nintr 0"
            ),
            "{two}"
        );
        assert!(two.contains("\nbtime -5\n"), "{two}");
        let huge = String::from_utf8(render_system_stat(u64::MAX / 10, 0, 1)).unwrap();
        assert!(huge.starts_with(&format!("cpu  {} 0", u64::MAX)), "{huge}");
    }

    #[test]
    fn io_accounting_counters_use_synthetic_values() {
        assert_eq!(
            sanitize_diskstats(b"259 0 nvme0n1 100 2 300 4 500 6 700 8 9 10 11\n"),
            b"259 0 nvme0n1 1 0 8 0 1 0 8 0 0 0 0\n"
        );
        // The origin's block_stat assertion, the stable_fields = 0
        // exercise of sanitize_numeric_lines (sanitize_block_stat
        // itself stays caller-side as a /sys transform).
        assert_eq!(
            sanitize_numeric_lines(b"100 2 300 4 500 6 700 8 9 10 11\n", 0),
            b"1 0 8 0 1 0 8 0 0 0 0\n"
        );
        assert_eq!(
            sanitize_process_io(
                b"rchar: 100\nwchar: 200\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\ncancelled_write_bytes: 7\n"
            ),
            b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n"
        );
    }

    #[test]
    fn uptime_uses_the_virtual_value() {
        assert_eq!(
            sanitize_uptime(b"156980.56 37990755.08\n", 120),
            b"120.00 0.00\n"
        );
    }

    #[test]
    fn pty_nr_hides_host_global_allocations() {
        assert_eq!(sanitize_pty_nr(b"107\n", 2), b"2\n");
        assert!(sanitize_pty_nr(b"", 2).is_empty());
    }

    #[test]
    fn sockstat_hides_host_global_allocation_and_memory_counters() {
        let contents = b"sockets: used 41\n\
TCP: inuse 3 orphan 2 tw 7 alloc 100 mem 200\n\
UDP: inuse 4 mem 99\n\
RAW: inuse 5\n";
        assert_eq!(
            sanitize_sockstat(contents),
            b"sockets: used 41\n\
TCP: inuse 3 orphan 0 tw 7 alloc 3 mem 0\n\
UDP: inuse 4 mem 0\n\
RAW: inuse 5\n"
        );
    }

    #[test]
    fn pressure_hides_host_stall_averages_and_totals() {
        let contents = b"some avg10=12.34 avg60=23.45 avg300=34.56 total=123456\n\
full avg10=1.23 avg60=2.34 avg300=3.45 total=654321\n";
        assert_eq!(
            sanitize_pressure(contents),
            b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\
full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        );
    }

    #[test]
    fn protocols_hides_live_socket_and_memory_counters() {
        let contents = b"protocol size sockets memory press maxhdr slab module cl co\n\
TCP 2304 17 12309 no 256 yes kernel y y\n\
RAW 1008 4 -1 NI 0 yes kernel y y\n";
        assert_eq!(
            sanitize_protocols(contents),
            b"protocol size sockets memory press maxhdr slab module cl co\n\
TCP 2304 0 0 no 256 yes kernel y y\n\
RAW 1008 0 -1 NI 0 yes kernel y y\n"
        );
        let missing_column = b"protocol size sockets press\nTCP 2304 17 no\n";
        assert_eq!(sanitize_protocols(missing_column), missing_column);
        let invalid_counter = b"protocol size sockets memory press maxhdr slab module\n\
TCP 2304 many 12309 no 256 yes kernel\n";
        assert_eq!(sanitize_protocols(invalid_counter), invalid_counter);
    }

    #[test]
    fn task_schedstat_hides_host_scheduler_accounting() {
        assert_eq!(
            sanitize_task_schedstat(b"3029609 1559338 150\n", None),
            b"0 0 0\n"
        );
        assert_eq!(
            sanitize_task_schedstat(b"3029609 1559338 150", None),
            b"0 0 0"
        );
    }

    /// The runtime is the task's CPU time in nanoseconds, where the
    /// caller knows it; the run-queue wait and the run count stay 0.
    #[test]
    fn task_schedstat_shows_the_tasks_runtime() {
        let runtime = Some(41_250_370);
        assert_eq!(
            sanitize_task_schedstat(b"3029609 1559338 150\n", runtime),
            b"41250370 0 0\n"
        );
        assert_eq!(sanitize_task_schedstat(b"0 0 0", runtime), b"41250370 0 0");
    }

    #[test]
    fn task_schedstat_leaves_unknown_formats_untouched() {
        let runtime = Some(7);
        let extra_field = b"3029609 1559338 150 4\n";
        assert_eq!(sanitize_task_schedstat(extra_field, runtime), extra_field);
        let invalid_counter = b"3029609 waiting 150\n";
        assert_eq!(
            sanitize_task_schedstat(invalid_counter, runtime),
            invalid_counter
        );
    }

    #[test]
    fn fdinfo_hides_backing_identity_only() {
        let contents = b"pos:\t1\n\
flags:\t0100002\n\
mnt_id:\t16368\n\
ino:\t47761541\n\
eventfd-count: 0000000000000007\n\
scm_fds: 2\n";
        assert_eq!(
            sanitize_fdinfo(contents, Some((9007, 0o100002, 42, 7))),
            b"pos:\t1\n\
flags:\t0100002\n\
mnt_id:\t7\n\
ino:\t9007\n\
eventfd-count: 0000000000000007\n\
scm_fds: 2\n"
        );
        assert!(
            sanitize_fdinfo(
                b"pos:\t1\nflags:\t02\nmnt_id:\t7\nino:\t8\nunknown-field: 9\n",
                Some((9007, 2, 42, 7))
            )
            .is_empty(),
            "an unknown fdinfo field must continue to refuse normalization"
        );
    }
    /// A process's cgroup reads as a cgroup namespace rooted at it shows it:
    /// the host's path, which names whatever launched Hermit, becomes `/` on
    /// every line, cgroup v1 or v2 (https://github.com/rrnewton/hermit/issues/4378).
    #[test]
    fn a_process_cgroup_reads_as_the_root_cgroup() {
        assert_eq!(
            sanitize_process_cgroup(
                b"0::/user.slice/user-1.slice/app.slice/safehermit-20261015T004318Z-183710.service\n"
            ),
            b"0::/\n"
        );
        assert_eq!(
            sanitize_process_cgroup(
                b"12:pids:/user.slice\n11:cpu,cpuacct:/user.slice/x\n0::/a/b\n"
            ),
            b"12:pids:/\n11:cpu,cpuacct:/\n0::/\n"
        );
        assert_eq!(
            sanitize_process_cgroup(b"not a cgroup line"),
            b"not a cgroup line"
        );
        // A directory name that is not UTF-8 is replaced too.
        assert_eq!(
            sanitize_process_cgroup(b"0::/user.slice/\xff\xfe.scope\n"),
            b"0::/\n"
        );
    }

    #[test]
    fn arch_status_uses_logical_avx512_elapsed_time() {
        let contents = b"AVX512_elapsed_ms:\t48\n\
x86_Thread_features:\t\tshstk\n\
x86_Thread_features_locked:\t\n";

        assert_eq!(
            sanitize_arch_status(contents),
            b"AVX512_elapsed_ms:\t0\n\
x86_Thread_features:\t\tshstk\n\
x86_Thread_features_locked:\t\n"
        );
        assert_eq!(
            sanitize_arch_status(b"AVX512_elapsed_ms:\tunknown\n"),
            b"AVX512_elapsed_ms:\tunknown\n"
        );
        // A task that never used AVX-512 reads -1; it becomes 0 too.
        assert_eq!(
            sanitize_arch_status(b"AVX512_elapsed_ms:\t-1\n"),
            b"AVX512_elapsed_ms:\t0\n"
        );
        // Any other negative value is not the kernel's format: left alone.
        assert_eq!(
            sanitize_arch_status(b"AVX512_elapsed_ms:\t-2\n"),
            b"AVX512_elapsed_ms:\t-2\n"
        );
    }

    #[test]
    fn random_uuid_uses_deterministic_v4_bytes_or_fails_open() {
        let kernel_uuid = b"24e63f35-232a-43e2-8799-b151e9833f45\n";
        assert_eq!(
            sanitize_random_uuid(kernel_uuid, [0; 16]),
            b"00000000-0000-4000-8000-000000000000\n"
        );
        assert_eq!(
            sanitize_random_uuid(kernel_uuid, [0xff; 16]),
            b"ffffffff-ffff-4fff-bfff-ffffffffffff\n"
        );

        for malformed in [
            b"24e63f35-232a-1e32-8799-b151e9833f45\n".as_slice(),
            b"24e63f35-232a-4e32-c799-b151e9833f45\n",
            b"24E63F35-232A-4E32-8799-B151E9833F45\n",
            b"24e63f35-232a-4e32-8799-b151e9833f45",
            b"not-a-uuid\n",
        ] {
            assert_eq!(sanitize_random_uuid(malformed, [0; 16]), malformed);
        }
    }

    #[test]
    fn self_sched_hides_host_scheduler_accounting() {
        let contents = b"cat (3, #threads: 7)\n\
se.exec_start : 377650149.445644\n\
se.vruntime : 133948666.432951\n\
se.sum_exec_runtime : 3.637972\n\
nr_switches : 149\n\
se.avg.load_avg : 749\n\
uclamp.min : 128\n\
uclamp.max : 768\n\
effective uclamp.min : 256\n\
effective uclamp.max : 512\n\
policy : 0\n\
uclamp.max : 1024\n\
new.kernel.counter : 55\n\
current_node=7, numa_group_id=91\n\
numa_faults node=7 task_private=8 task_shared=9 group_private=10 group_shared=11\n";

        assert_eq!(
            sanitize_self_sched(contents),
            b"cat (0, #threads: 1)\n\
se.exec_start : 0.000000\n\
se.vruntime : 0.000000\n\
se.sum_exec_runtime : 0.000000\n\
nr_switches : 0\n\
se.avg.load_avg : 0\n\
uclamp.min : 0\n\
uclamp.max : 1024\n\
effective uclamp.min : 0\n\
effective uclamp.max : 1024\n\
policy : 0\n\
uclamp.max : 1024\n\
new.kernel.counter : 0\n"
        );
    }

    /// A kernel built without NUMA prints none of NUMA balancing's lines
    /// (kernel/sched/debug.c:1239-1262 at v7.1), so they are left out, the
    /// one `numa_faults` line per host node with them; a malformed one still
    /// leaves the guest nothing, as any malformed line does.
    #[test]
    fn self_sched_leaves_out_numa_balancing() {
        let core = "cat (3, #threads: 1)\n\
se.exec_start : 377650149.445644\n\
se.vruntime : 133948666.432951\n\
se.sum_exec_runtime : 3.637972\n";
        let numa = "mm->numa_scan_seq                            :                    4\n\
numa_pages_migrated                          :                    5\n\
numa_preferred_nid                           :                   -1\n\
total_numa_faults                            :                    6\n\
current_node=1, numa_group_id=0\n\
numa_faults node=0 task_private=0 task_shared=0 group_private=0 group_shared=0\n\
numa_faults node=1 task_private=7 task_shared=0 group_private=0 group_shared=0\n";
        let expected = sanitize_self_sched(core.as_bytes());
        assert!(expected.starts_with(b"cat (0, #threads: 1)\n"));
        assert_eq!(
            sanitize_self_sched(format!("{core}{numa}").as_bytes()),
            expected
        );
        for malformed in [
            "numa_preferred_nid : none\n",
            "current_node=1\n",
            "numa_faults node=1 task_private=x task_shared=0 group_private=0 group_shared=0\n",
        ] {
            assert!(
                sanitize_self_sched(format!("{core}{malformed}").as_bytes()).is_empty(),
                "{malformed:?}"
            );
        }
    }

    // With kernel.sched_schedstats=1 the kernel adds these lines, printed with
    // "%-45s:%14Ld.%06ld" and "%-45s:%21Ld" (kernel/sched/debug.c,
    // proc_sched_show_task); avg_atom prints -1 as 0.000001. Each value
    // becomes zero, and the file still reaches the guest.
    #[test]
    fn self_sched_hides_schedstats_fields() {
        let core = "cat (3, #threads: 1)\n\
se.exec_start : 377650149.445644\n\
se.vruntime : 133948666.432951\n\
se.sum_exec_runtime : 3.637972\n";
        let decimal = |label: &str, value: &str| format!("{label:<45}:{value:>21}\n");
        let mut contents = core.to_owned();
        let mut expected = "cat (0, #threads: 1)\n\
se.exec_start : 0.000000\n\
se.vruntime : 0.000000\n\
se.sum_exec_runtime : 0.000000\n"
            .to_owned();
        for (label, value, zero) in [
            ("sum_sleep_runtime", "1234.567890", "0.000000"),
            ("wait_max", "2.500000", "0.000000"),
            ("wait_count", "7", "0"),
            ("avg_atom", "0.000001", "0.000000"),
        ] {
            contents.push_str(&decimal(label, value));
            expected.push_str(&format!("{label:<45}: {zero}\n"));
        }
        assert_eq!(
            String::from_utf8(sanitize_self_sched(contents.as_bytes())).unwrap(),
            expected
        );

        // A negative or non-finite unknown field still fails closed.
        for value in ["-1.500000", "inf"] {
            let refused = format!("{core}{}", decimal("wait_max", value));
            assert!(
                sanitize_self_sched(refused.as_bytes()).is_empty(),
                "{value}"
            );
        }
    }

    #[test]
    fn self_sched_fails_closed_on_unknown_formats() {
        let missing_core_field = b"se.exec_start : 1.0\nse.vruntime : 2.0\n";
        assert!(sanitize_self_sched(missing_core_field).is_empty());

        let invalid_counter = b"se.exec_start : NaN\n\
se.vruntime : 2.0\n\
se.sum_exec_runtime : 3.0\n";
        assert!(sanitize_self_sched(invalid_counter).is_empty());

        let negative_counter = b"se.exec_start : 1.0\n\
se.vruntime : 2.0\n\
se.sum_exec_runtime : 3.0\n\
nr_switches : -1\n";
        assert!(sanitize_self_sched(negative_counter).is_empty());
    }

    #[test]
    fn smaps_rollup_hides_physical_page_accounting() {
        let contents = b"71000000-7ffffffff000 ---p 00000000 00:00 0 [rollup]\n\
Rss:                2216 kB\n\
Pss:                 311 kB\n\
Pss_File:            131 kB\n\
Locked:                12 kB\n\
Swap:                   8 kB\n\
THPeligible:    0\n";

        assert_eq!(
            sanitize_smaps_rollup(contents),
            b"71000000-7ffffffff000 ---p 00000000 00:00 0 [rollup]\n\
Rss:\t0 kB\n\
Pss:\t0 kB\n\
Pss_File:\t0 kB\n\
Locked:\t0 kB\n\
Swap:\t0 kB\n\
THPeligible:    0\n"
        );
    }
    #[test]
    fn maps_rewrites_both_the_device_and_the_inode() {
        let raw =
            b"7f0000000000-7f0000001000 r-xp 00000000 08:02 1234567 /lib/libc.so.6\n" as &[u8];
        let table = BTreeMap::from([(
            (libc::makedev(0x08, 0x02), 1_234_567u64),
            (libc::makedev(0x00, 0x2a), 99u64),
        )]);
        let out = String::from_utf8(sanitize_maps(raw, &table)).unwrap();
        assert!(out.contains(" 00:2a 99 "), "both columns rewritten: {out}");
        assert!(!out.contains("08:02"), "raw device must not survive: {out}");
        assert!(
            !out.contains("1234567"),
            "raw inode must not survive: {out}"
        );
        assert!(
            out.ends_with("/lib/libc.so.6\n"),
            "pathname preserved: {out}"
        );
    }

    #[test]
    fn maps_padding_does_not_republish_the_host_inode_width() {
        // Everything up to and including the space before the inode.
        const HEAD: &str = "70f80000-71000000 r-xs 00000000 00:06 ";
        const NAME: &str = "/memfd:liteinst2-trampoline (deleted)";
        // `seq_setwidth(m, 25 + sizeof(void *) * 6)` in the kernel's
        // `show_map_vma`; measured at 73 on x86_64.
        const PATHNAME_COLUMN: usize = 73;

        let kernel_line = |inode: u64| {
            let prefix = format!("{HEAD}{inode}");
            let pad = PATHNAME_COLUMN - prefix.len();
            format!("{prefix}{}{NAME}\n", " ".repeat(pad))
        };
        let table = |inode: u64| {
            BTreeMap::from([(
                (libc::makedev(0x00, 0x06), inode),
                (libc::makedev(0x00, 0x06), 8u64),
            )])
        };

        let four_digit = sanitize_maps(kernel_line(9_999).as_bytes(), &table(9_999));
        let five_digit = sanitize_maps(kernel_line(10_000).as_bytes(), &table(10_000));
        assert_eq!(
            String::from_utf8(four_digit.clone()).unwrap(),
            String::from_utf8(five_digit).unwrap(),
            "the host inode's digit count must not survive as line length",
        );

        // And the surviving line is still a well-formed maps line: same
        // pathname, at the column the kernel put it in.
        let out = String::from_utf8(four_digit).unwrap();
        let body = out.strip_suffix('\n').unwrap();
        assert_eq!(
            body.find('/'),
            Some(PATHNAME_COLUMN),
            "pathname column preserved: {out:?}",
        );
        assert!(body.ends_with(NAME), "pathname preserved: {out:?}");
        // Read the inode COLUMN rather than substring-searching the line: the
        // address range `70f80000-71000000` itself contains "10000", so a
        // `contains` check here passes for the wrong reason on one input and
        // fails for the wrong reason on the other.
        assert_eq!(
            body.split_whitespace().nth(4),
            Some("8"),
            "raw inode must not survive in the inode column: {out:?}",
        );
    }

    #[test]
    fn maps_leaves_anonymous_mappings_alone() {
        let raw = b"7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]\n" as &[u8];
        assert_eq!(
            mapping_header_identity(std::str::from_utf8(raw).unwrap().trim_end()),
            None
        );
        assert_eq!(sanitize_maps(raw, &BTreeMap::new()), raw.to_vec());
    }

    #[test]
    fn maps_never_invents_an_identity_for_an_untabled_mapping() {
        let raw =
            b"7f0000000000-7f0000001000 r-xp 00000000 08:02 1234567 /lib/libc.so.6\n" as &[u8];
        assert_eq!(sanitize_maps(raw, &BTreeMap::new()), raw.to_vec());
    }

    #[test]
    fn smaps_header_is_rewritten_like_maps() {
        let raw = b"7f0000000000-7f0000001000 r-xp 00000000 08:02 1234567 /lib/libc.so.6\n\
Size:                  4 kB\n\
Rss:                   4 kB\n" as &[u8];
        let table = BTreeMap::from([(
            (libc::makedev(0x08, 0x02), 1_234_567u64),
            (libc::makedev(0x00, 0x2a), 99u64),
        )]);
        let out = String::from_utf8(sanitize_smaps(raw, &table)).unwrap();
        assert!(out.contains(" 00:2a 99 "), "smaps header rewritten: {out}");
        assert!(
            !out.contains("1234567"),
            "raw inode must not survive smaps: {out}"
        );
    }

    #[test]
    fn cpuinfo_normalizes_frequency() {
        let input = b"processor\t: 0\ncpu MHz\t\t: 2994.183\ncache size\t: 1024 KB\n";
        assert_eq!(
            sanitize_cpuinfo(input, 1),
            b"processor\t: 0\ncpu MHz\t\t: 1000.000\ncache size\t: 1024 KB\n"
        );
    }

    #[test]
    fn cpuinfo_reports_one_virtual_cpu() {
        let block = |n: u32| {
            format!(
                "processor\t: {n}\nmodel name\t: Example CPU\ncpu MHz\t\t: 2994.183\n\
                 physical id\t: 1\nsiblings\t: 8\ncore id\t\t: {n}\ncpu cores\t: 4\n\
                 apicid\t\t: {n}\ninitial apicid\t: {n}\nflags\t\t: fpu sse2\n\n"
            )
        };
        let host = format!("{}{}{}", block(0), block(1), block(2));
        let virtual_block = |n: u32| {
            format!(
                "processor\t: {n}\nmodel name\t: Example CPU\ncpu MHz\t\t: 1000.000\n\
                 physical id\t: {n}\nsiblings\t: 1\ncore id\t\t: 0\ncpu cores\t: 1\n\
                 apicid\t\t: {n}\ninitial apicid\t: {n}\nflags\t\t: fpu sse2\n\n"
            )
        };
        assert_eq!(
            String::from_utf8(sanitize_cpuinfo(host.as_bytes(), 1)).unwrap(),
            virtual_block(0)
        );
        // A single-CPU host's file is already the virtual shape.
        assert_eq!(
            sanitize_cpuinfo(b"processor\t: 0\ncpu cores\t: 1\n\n", 1),
            b"processor\t: 0\ncpu cores\t: 1\n\n"
        );
        // Under --virtual-cpus, the first block once per virtual CPU, each a
        // single-core socket of its own: more CPUs than the host shows too.
        assert_eq!(
            String::from_utf8(sanitize_cpuinfo(host.as_bytes(), 4)).unwrap(),
            (0..4).map(virtual_block).collect::<String>()
        );
    }

    #[test]
    fn smaps_hides_host_memory_accounting_but_preserves_mapping_metadata() {
        let contents = b"71000000-71001000 r-xp 00000000 00:00 0\n\
Size:                  4 kB\n\
KernelPageSize:        4 kB\n\
MMUPageSize:           4 kB\n\
Rss:                   4 kB\n\
Pss:                   3 kB\n\
Shared_Clean:          4 kB\n\
Private_Dirty:         0 kB\n\
THPeligible:           0\n\
ProtectionKey:         0\n\
VmFlags: rd ex mr mw me ac\n";

        assert_eq!(
            sanitize_smaps(contents, &BTreeMap::new()),
            b"71000000-71001000 r-xp 00000000 00:00 0\n\
Size:                  4 kB\n\
KernelPageSize:        4 kB\n\
MMUPageSize:           4 kB\n\
Rss:\t0 kB\n\
Pss:\t0 kB\n\
Shared_Clean:\t0 kB\n\
Private_Dirty:\t0 kB\n\
THPeligible:           0\n\
ProtectionKey:         0\n\
VmFlags: rd ex mr mw me ac\n"
        );
    }

    #[test]
    fn smaps_hides_page_cache_dirty_state() {
        let dirty = b"00400000-00401000 r--p 00000000 00:2a 99 /guest\n\
Size:                  4 kB\n\
Rss:                   4 kB\n\
Private_Dirty:         4 kB\n\
VmFlags: rd mr mw me\n";
        let clean = b"00400000-00401000 r--p 00000000 00:2a 99 /guest\n\
Size:                  4 kB\n\
Rss:                   4 kB\n\
Private_Dirty:         0 kB\n\
VmFlags: rd mr mw me\n";

        let expected = b"00400000-00401000 r--p 00000000 00:2a 99 /guest\n\
Size:                  4 kB\n\
Rss:\t0 kB\n\
Private_Dirty:\t0 kB\n\
VmFlags: rd mr mw me\n";
        assert_eq!(sanitize_smaps(dirty, &BTreeMap::new()), expected);
        assert_eq!(sanitize_smaps(clean, &BTreeMap::new()), expected);
        assert_eq!(
            sanitize_smaps_rollup(b"Private_Dirty:        12 kB\n"),
            b"Private_Dirty:\t0 kB\n"
        );
    }

    /// Every host page-accounting field, in the order this kernel prints them.
    /// Deliberately a separate literal rather than `SMAPS_ACCOUNTING_FIELDS`, so
    /// dropping a field from the sanitizer's list fails here.
    const KERNEL_SMAPS_ACCOUNTING_LABELS: &[&str] = &[
        "Rss",
        "Pss",
        "Pss_Dirty",
        "Pss_Anon",
        "Pss_File",
        "Pss_Shmem",
        "Shared_Clean",
        "Shared_Dirty",
        "Private_Clean",
        "Private_Dirty",
        "Referenced",
        "Anonymous",
        "KSM",
        "LazyFree",
        "AnonHugePages",
        "ShmemPmdMapped",
        "FilePmdMapped",
        "Shared_Hugetlb",
        "Private_Hugetlb",
        "Swap",
        "SwapPss",
        "Locked",
    ];

    #[test]
    fn smaps_hides_every_host_page_accounting_field() {
        let block = |seed: u64| {
            let mut block = String::from(
                "00400000-00600000 rw-p 00000000 00:00 0\nSize:               2048 kB\n",
            );
            for (index, label) in KERNEL_SMAPS_ACCOUNTING_LABELS.iter().enumerate() {
                let value = seed * (index as u64 + 1);
                block.push_str(&format!("{:<16}{value:>8} kB\n", format!("{label}:")));
            }
            block.push_str("THPeligible:    1\nVmFlags: rd wr mr mw me ac\n");
            block
        };
        let idle = block(0);
        let busy = block(4);
        let mut expected =
            String::from("00400000-00600000 rw-p 00000000 00:00 0\nSize:               2048 kB\n");
        for label in KERNEL_SMAPS_ACCOUNTING_LABELS {
            expected.push_str(&format!("{label}:\t0 kB\n"));
        }
        expected.push_str("THPeligible:    1\nVmFlags: rd wr mr mw me ac\n");

        for input in [&idle, &busy] {
            let smaps = sanitize_smaps(input.as_bytes(), &BTreeMap::new());
            assert_eq!(String::from_utf8(smaps).unwrap(), expected);
        }

        let rollup = |block: &str| {
            let block = block.replace("00400000-00600000 rw-p", "00400000-7ffffffff000 ---p");
            let body: String = block
                .lines()
                .filter(|line| {
                    !line.starts_with("Size:")
                        && !line.starts_with("THPeligible:")
                        && !line.starts_with("VmFlags:")
                })
                .map(|line| format!("{line}\n"))
                .collect();
            String::from_utf8(sanitize_smaps_rollup(body.as_bytes())).unwrap()
        };
        let idle_rollup = rollup(&idle);
        assert_eq!(idle_rollup, rollup(&busy));
        for label in KERNEL_SMAPS_ACCOUNTING_LABELS {
            assert!(
                idle_rollup.contains(&format!("\n{label}:\t0 kB\n")),
                "rollup left {label} unsanitized: {idle_rollup}"
            );
        }
    }

    #[test]
    fn smaps_leaves_unknown_or_malformed_formats_untouched() {
        let invalid_counter = b"71000000-71001000 r-xp 00000000 00:00 0\nPss: many kB\n";
        assert_eq!(
            sanitize_smaps(invalid_counter, &BTreeMap::new()),
            invalid_counter
        );

        let unknown_field = b"71000000-71001000 r-xp 00000000 00:00 0\nMystery: 1 kB\n";
        assert_eq!(
            sanitize_smaps(unknown_field, &BTreeMap::new()),
            unknown_field
        );

        let invalid_header = b"not-a-range r-xp 00000000 00:00 0\nPss: 3 kB\n";
        assert_eq!(
            sanitize_smaps(invalid_header, &BTreeMap::new()),
            invalid_header
        );
    }

    #[test]
    fn rtc_uses_the_virtual_clock_and_hides_alarm_state() {
        let contents = b"rtc_time\t: 10:07:42\n\
rtc_date\t: 2026-07-27\n\
alrm_time\t: 00:50:12\n\
alrm_date\t: 2026-07-28\n\
alarm_IRQ\t: yes\n\
periodic IRQ enabled\t: yes\n\
periodic IRQ frequency\t: 1024\n\
24hr\t\t: yes\n";

        assert_eq!(
            sanitize_rtc(contents, "23:59:59", "2000-12-31"),
            b"rtc_time\t: 23:59:59\n\
rtc_date\t: 2000-12-31\n\
alrm_time\t: 00:00:00\n\
alrm_date\t: 2000-12-31\n\
alarm_IRQ\t: no\n\
periodic IRQ enabled\t: no\n\
periodic IRQ frequency\t: 0\n\
24hr\t\t: yes\n"
        );
    }

    #[test]
    fn locks_virtualize_identities_but_preserve_equivalences() {
        // A holder (seq 74) with a waiter blocked behind it on the same object,
        // a second lock by the same owner (PID 480) on a *different* object,
        // and a third lock by a different owner on the *first* object.
        let contents = b"74: POSIX  ADVISORY  WRITE 480 08:02:1111 0 EOF\n\
74: -> POSIX  ADVISORY  WRITE 481 08:02:1111 0 EOF\n\
9: OFDLCK ADVISORY  WRITE 480 08:02:2222 0 EOF\n\
21: FLOCK ADVISORY  WRITE 999 08:02:1111 0 EOF\n";

        let out = String::from_utf8(sanitize_locks(contents)).unwrap();
        let lines: Vec<&str> = out.lines().collect();

        // No host-specific sequence, PID, or device:inode magnitude survives.
        assert!(!out.contains("74"), "raw sequence leaked: {out}");
        assert!(!out.contains("480") && !out.contains("481") && !out.contains("999"));
        assert!(!out.contains("1111") && !out.contains("2222"));

        // The holder and its `->` waiter keep a shared virtual sequence and stay
        // adjacent (grouping preserved rather than scattered by a global sort).
        let holder = lines
            .iter()
            .position(|l| l.contains("POSIX") && !l.contains("->"));
        let waiter = lines.iter().position(|l| l.contains("->"));
        let (holder, waiter) = (holder.unwrap(), waiter.unwrap());
        assert_eq!(waiter, holder + 1, "waiter must immediately follow holder");
        let seq_of = |l: &str| l.split(':').next().unwrap().to_owned();
        assert_eq!(seq_of(lines[holder]), seq_of(lines[waiter]));

        // The two locks on object 08:02:1111 (holder + FLOCK) share one virtual
        // object id; the lock on 08:02:2222 keeps a *distinct* one.
        let obj_of = |l: &str| l.split_whitespace().nth_back(2).unwrap().to_owned();
        let flock = lines.iter().find(|l| l.contains("FLOCK")).unwrap();
        let ofd = lines.iter().find(|l| l.contains("OFDLCK")).unwrap();
        assert_eq!(
            obj_of(lines[holder]),
            obj_of(flock),
            "same object must match"
        );
        assert_ne!(
            obj_of(lines[holder]),
            obj_of(ofd),
            "distinct objects must differ"
        );

        // Same raw owner (PID 480) on two different objects keeps one virtual
        // owner; the other owners stay distinct.
        let pid_of = |l: &str| l.split_whitespace().nth_back(3).unwrap().to_owned();
        assert_eq!(pid_of(lines[holder]), pid_of(ofd), "same owner must match");
        assert_ne!(pid_of(lines[holder]), pid_of(lines[waiter]));
        assert_ne!(pid_of(lines[holder]), pid_of(flock));

        let renumbered_and_reordered = b"800: FLOCK ADVISORY WRITE 9000 00:fe:9001 0 EOF\n\
700: OFDLCK ADVISORY WRITE 8000 00:fe:9002 0 EOF\n\
900: -> POSIX ADVISORY WRITE 7000 00:fe:9001 0 EOF\n\
900: POSIX ADVISORY WRITE 8000 00:fe:9001 0 EOF\n";
        assert_eq!(
            sanitize_locks(contents),
            sanitize_locks(renumbered_and_reordered),
            "raw ID renumbering and row order changed the virtual graph"
        );

        // Fail closed, not open: one unclassifiable row suppresses the entire
        // snapshot instead of mixing a sentinel with partially trusted data.
        assert!(sanitize_locks(b"malformed row\n").is_empty());
        assert!(
            sanitize_locks(b"74: POSIX ADVISORY WRITE 480 08:02:1111 0 EOF\nmalformed\n")
                .is_empty()
        );
        assert!(sanitize_locks(&[0xff, 0xfe]).is_empty());
        assert!(sanitize_locks(b"").is_empty());
    }

    #[test]
    fn unix_sockets_hide_kernel_identities_and_sort_semantic_rows() {
        let contents = b"Num RefCount Protocol Flags Type St Inode Path\n\
00000000fedcba98: 00000003 00000000 00010000 0002 01 12346 /run/socket two\n\
000000001234abcd: 00000002 00000000 00000000 0001 03 12345\n";

        assert_eq!(
            sanitize_unix_sockets(contents),
            b"Num RefCount Protocol Flags Type St Inode Path\n\
0000000000000000: 00000002 00000000 00000000 0001 03 0\n\
0000000000000000: 00000003 00000000 00010000 0002 01 0 /run/socket two\n"
        );
    }

    #[test]
    fn unix_sockets_fail_open_on_unknown_schemas() {
        for malformed in [
            b"".as_slice(),
            b"Num RefCount Protocol Flags Type St Inode Path",
            b"Num RefCount Protocol Flags Type St Inode Path Extra\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n1234: 00000003 00000000 00000000 0001 03 12345\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n000000001234abcd: 0000000G 00000000 00000000 0001 03 12345\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n000000001234abcd: 00000003 00000000 00000000 0001 03 inode\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n000000001234abcd: 00000003 00000000 00000000 0001 03 18446744073709551616\n",
            b"Num RefCount Protocol Flags Type St Inode Path\n000000001234abcd: 00000003 00000000 00000000 0001\n",
        ] {
            assert_eq!(sanitize_unix_sockets(malformed), malformed);
        }
    }

    #[test]
    fn netlink_sockets_hide_kernel_identities_and_sort_semantic_rows() {
        let contents = b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n\
00000000fedcba98 10 20 00000002 3 4 5 6 7 12346\n\
000000001234abcd 4 10 00000001 0 0 0 2 0 12345\n";

        assert_eq!(
            sanitize_netlink_sockets(contents),
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n\
0000000000000000 4 10 00000001 0 0 0 2 0 0\n\
0000000000000000 10 20 00000002 3 4 5 6 7 0\n"
        );
    }

    #[test]
    fn inet_sockets_zero_both_host_identities_and_canonicalize_row_order() {
        // Two rows deliberately given in the order the kernel happened to
        // produce on one run; a later run produced them the other way round.
        let contents = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:8001 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 3066787053 1 00000000703938cf 100 0 0 10 0\n   1: 0100007F:8000 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 3066787052 1 0000000042a27170 100 0 0 10 0\n"
            .as_slice();
        // Same rows, opposite order, different host inodes and pointers: a
        // second run of the same guest. Both must normalize to one answer.
        let swapped = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:8000 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 3071433840 1 000000005b1c887b 100 0 0 10 0\n   1: 0100007F:8001 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 3071433841 1 00000000ab7b588a 100 0 0 10 0\n"
            .as_slice();

        let first = sanitize_inet_sockets(contents);
        assert_eq!(
            first,
            sanitize_inet_sockets(swapped),
            "two runs differing only in host identity and row order must agree"
        );

        let text = String::from_utf8(first).unwrap();
        for row in text.lines().skip(1) {
            let fields = row.split_whitespace().collect::<Vec<_>>();
            assert_eq!(fields[9], "0", "inode must be zeroed: {row}");
            assert_eq!(
                fields[11], "0000000000000000",
                "pointer must be zeroed: {row}"
            );
        }
        // `sl` is renumbered to match the sorted order, not left contradicting it.
        let indices = text
            .lines()
            .skip(1)
            .map(|row| row.split_whitespace().next().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(indices, vec!["0:", "1:"]);
        // And sorted on content: port 8000 sorts before 8001.
        assert!(text.lines().nth(1).unwrap().contains(":8000"));
    }

    #[test]
    fn inet_sockets_fail_open_on_unknown_schemas() {
        for malformed in [
            b"".as_slice(),
            // No trailing newline.
            b"  sl  local_address rem_address st inode",
            // Header is not this table.
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n",
            // Too few columns for the two host-state fields to exist.
            b"  sl  local_address inode\n   0: 0100007F:8000 12345\n",
            // Inode column not decimal.
            b"  sl  a b c d e f g h inode j pointer\n   0: 1 2 3 4 5 6 7 8 zero 1 0000000042a27170\n",
        ] {
            assert_eq!(sanitize_inet_sockets(malformed), malformed);
        }
    }

    #[test]
    fn netlink_sockets_fail_open_on_unknown_schemas() {
        for malformed in [
            b"".as_slice(),
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode",
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode Extra\n",
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n1234 4 10 00000001 0 0 0 2 0 12345\n",
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n000000001234abcd 4 10 00000001 0 0 0 2 zero 12345\n",
            b"sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n000000001234abcd 4 10 00000001 0 0 0 2 0 12345 extra\n",
        ] {
            assert_eq!(sanitize_netlink_sockets(malformed), malformed);
        }
    }
}
