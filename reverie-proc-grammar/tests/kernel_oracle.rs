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

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
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
/// (`NotFound`) or are not visible to this reader
/// (`PermissionDenied`, e.g. hidepid or another user) are counted
/// separately; only the verified causes counted in
/// `listed_not_found` / `listed_permission_denied` leave the
/// listed-entry coverage denominator.
#[derive(Clone, Default)]
struct ReadCounts {
    attempted: usize,
    ok: usize,
    not_found: usize,
    permission_denied: usize,
    listed_not_found: usize,
    listed_permission_denied: usize,
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

/// Reads one inventory file, classifying the outcome. Only a
/// verified-vanished `NotFound`, a foreign-owned task's
/// `PermissionDenied` (for a non-root reader, outside fdinfo's
/// own-task walk), and a ptrace-gated denial with a named kernel
/// reason are excluded; every other outcome is recorded in
/// `failures` and hard-fails the inventory.
#[allow(clippy::too_many_arguments)]
fn read_inventory_file(
    path: &Path,
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
    match fs::read(path) {
        Ok(bytes) => {
            counts.attempted += 1;
            Some(bytes)
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
    use ReadDisposition::{Excluded, Fail};

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
                if let Some(bytes) = read_inventory_file(
                    Path::new(&format!("{base}/{}", $file)),
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
        if let Some(bytes) = read_inventory_file(
            Path::new(&format!("{base}/status")),
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
    // exclusions: a re-checked-vanished task, a foreign-owned
    // task denied to a non-root reader, or a ptrace-gated denial
    // with a named kernel reason. The scaled ratio is a backstop
    // (after the hard-fail asserts every attempted entry has
    // round-tripped); coverage rests on every eligible entry
    // having been attempted plus the absolute minimum.
    // Refusals and render mismatches hard-fail above at any size.
    for (format, counts) in &reads {
        eprintln!(
            "live_proc_inventory {format}: listed {population}, attempted {}, \
             round-tripped {}, excluded not-found {}, permission-denied {}",
            counts.attempted, counts.ok, counts.not_found, counts.permission_denied,
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
        let verified_excluded = counts.listed_not_found + counts.listed_permission_denied;
        let eligible = population - verified_excluded;
        assert!(
            inventory_floor_met(population, verified_excluded, counts.attempted, counts.ok),
            "inventory too thin for {format}: {} round-tripped of {} attempted \
             ({population} listed, {eligible} eligible after {} verified-not-found \
             and {} verified-foreign permission-denied exclusions; floor {} with \
             absolute minimum {MIN_ATTEMPTED_PER_FORMAT}; excluded examples: \
             not-found [{}], permission-denied [{}])",
            counts.ok,
            counts.attempted,
            counts.not_found,
            counts.permission_denied,
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
    let mut fdinfo_bad: Vec<String> = Vec::new();
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
            let entry_identity = fs::symlink_metadata(&entry_path).ok().map(|metadata| {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    fs::read_link(&entry_path).ok(),
                )
            });
            let entry_recheck = entry_path.clone();
            let Some(bytes) = read_inventory_file(
                &entry_path,
                move || {
                    if verified_gone(&entry_recheck) {
                        return true;
                    }
                    let current = fs::symlink_metadata(&entry_recheck).ok().map(|metadata| {
                        use std::os::unix::fs::MetadataExt;
                        (
                            metadata.dev(),
                            metadata.ino(),
                            fs::read_link(&entry_recheck).ok(),
                        )
                    });
                    entry_identity.is_some() && current != entry_identity
                },
                task_uid,
                my_uid,
                true,
                task_ptrace_reason,
                "fdinfo",
                &mut fdinfo_reads,
                &mut excluded_examples,
                &mut fdinfo_bad,
            ) else {
                continue;
            };
            match parse_fdinfo(&bytes) {
                Ok(parsed) => {
                    if render_fdinfo(&parsed) == bytes {
                        fdinfo_reads.ok += 1;
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
        "modelled fd kinds misparsed (unmodelled tolerated: {fdinfo_unmodelled}):\n{}",
        fdinfo_bad.join("\n")
    );
    // Same listed-coverage floor as the per-task formats: the
    // listed total is reduced only by verified exclusions and the
    // tolerated unmodelled kinds actually observed.
    let fdinfo_modelled_attempted = fdinfo_reads.attempted - fdinfo_unmodelled;
    let fdinfo_modelled_listed = fdinfo_listed - fdinfo_unmodelled;
    let fdinfo_verified_excluded =
        fdinfo_reads.listed_not_found + fdinfo_reads.listed_permission_denied;
    eprintln!(
        "live_proc_inventory fdinfo: listed {fdinfo_listed}, attempted {}, \
         modelled attempted {fdinfo_modelled_attempted}, round-tripped {}, \
         excluded not-found {}, permission-denied {}, unmodelled {}",
        fdinfo_reads.attempted,
        fdinfo_reads.ok,
        fdinfo_reads.not_found,
        fdinfo_reads.permission_denied,
        fdinfo_unmodelled,
    );
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
         permission-denied, {fdinfo_unmodelled} unmodelled tolerated; floor {} \
         with absolute minimum {MIN_ATTEMPTED_PER_FORMAT}; excluded examples: \
         not-found [{}], permission-denied [{}])",
        fdinfo_reads.ok,
        fdinfo_reads.listed_not_found,
        fdinfo_reads.listed_permission_denied,
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
