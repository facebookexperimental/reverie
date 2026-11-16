/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The collector's whole job is filesystem access; the clippy.toml
// purity rules govern the library, not this dev tool.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

//! Collect a shape-representative `/proc` corpus for the grammar
//! tests.
//!
//! Usage: `cargo run --example collect-corpus -- <output-dir>`
//!
//! Reads `stat`, `status`, `comm`, `statm`, `io`, and `sched` for
//! every readable PID, plus `fdinfo/*` for our own processes, and
//! writes a capped, deduplicated-by-shape fixture set plus a
//! `MANIFEST` recording the kernel and the scan counts. Files whose
//! bytes the grammar refuses are counted and reported, never written:
//! a refusal during collection is a grammar bug (or a new kernel
//! field) to fix, and the checked-in corpus must parse clean.
//!
//! Only per-task metadata files are read — never `cmdline` or
//! `environ`. Process names are anonymized before writing (length
//! and separator classes preserved, letters/digits replaced), so no
//! host's process names land in the checked-in corpus, and the
//! MANIFEST records only the kernel version number, not any local
//! build suffix. Fixtures use the `.bytes` extension because their
//! tabs and trailing spaces are kernel data, not text to lint.
//! Re-run on kernel bumps and diff the output; label-set changes
//! show up as new fixture shapes.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use reverie_proc_grammar::Format;
use reverie_proc_grammar::StatusLabel;
use reverie_proc_grammar::StatusLine;
use reverie_proc_grammar::StatusValue;
use reverie_proc_grammar::parse_comm_file;
use reverie_proc_grammar::parse_fdinfo;
use reverie_proc_grammar::parse_process_io;
use reverie_proc_grammar::parse_sched;
use reverie_proc_grammar::parse_stat;
use reverie_proc_grammar::parse_statm;
use reverie_proc_grammar::parse_status;
use reverie_proc_grammar::render_comm_file;
use reverie_proc_grammar::render_sched;
use reverie_proc_grammar::render_stat;
use reverie_proc_grammar::render_status;

/// Largest fixture the collector keeps. A single epoll instance can
/// watch hundreds of thousands of descriptors (a 19 MB fdinfo was
/// observed on the collection host); one small representative of the
/// shape is worth more than the giant.
const MAX_FIXTURE_BYTES: usize = 8192;

struct Collector {
    kept: BTreeMap<(Format, String), Vec<Vec<u8>>>,
    scanned: BTreeMap<Format, usize>,
    refused: BTreeMap<Format, usize>,
    cap: usize,
}

impl Collector {
    fn offer(&mut self, format: Format, shape: String, bytes: Vec<u8>, ok: bool) {
        *self.scanned.entry(format).or_default() += 1;
        if !ok {
            *self.refused.entry(format).or_default() += 1;
            return;
        }
        if bytes.len() > MAX_FIXTURE_BYTES {
            return;
        }
        let bucket = self.kept.entry((format, shape)).or_default();
        if bucket.len() < self.cap && !bucket.contains(&bytes) {
            bucket.push(bytes);
        }
    }
}

/// Replace every ASCII letter/digit with `a`, preserving length and
/// every separator/edge byte, so a fixture keeps its comm shape
/// class without recording any host process name.
fn anonymize_name(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|b| if b.is_ascii_alphanumeric() { b'a' } else { *b })
        .collect()
}

/// [`anonymize_name`] for a status `Name` printed form: escape pairs
/// (`\\`, `\n`) are preserved as pairs.
fn anonymize_printed_name(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        if name[i] == b'\\' && i + 1 < name.len() {
            out.extend_from_slice(&name[i..i + 2]);
            i += 2;
        } else if name[i].is_ascii_alphanumeric() {
            out.push(b'a');
            i += 1;
        } else {
            out.push(name[i]);
            i += 1;
        }
    }
    out
}

fn comm_shape(comm: &[u8]) -> String {
    let mut flags = Vec::new();
    if comm.contains(&b' ') {
        flags.push("space");
    }
    if comm.contains(&b')') || comm.contains(&b'(') {
        flags.push("paren");
    }
    if comm.contains(&b'\\') {
        flags.push("backslash");
    }
    if comm.contains(&b'\n') {
        flags.push("newline");
    }
    if comm.len() >= 15 {
        flags.push("len15");
    }
    if std::str::from_utf8(comm).is_err() {
        flags.push("nonutf8");
    }
    if flags.is_empty() {
        "plain".to_string()
    } else {
        flags.join("+")
    }
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: collect-corpus <output-dir>");
    let mut collector = Collector {
        kept: BTreeMap::new(),
        scanned: BTreeMap::new(),
        refused: BTreeMap::new(),
        cap: 8,
    };
    let mut pids: Vec<u32> = fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();

    for pid in &pids {
        let base = format!("/proc/{pid}");
        if let Ok(bytes) = fs::read(format!("{base}/stat")) {
            let (shape, bytes, ok) = match parse_stat(&bytes) {
                Ok(mut stat) => {
                    let shape = comm_shape(&stat.comm);
                    stat.comm = anonymize_name(&stat.comm);
                    (shape, render_stat(&stat), true)
                }
                Err(_) => ("refused".to_string(), bytes, false),
            };
            collector.offer(Format::Stat, shape, bytes, ok);
        }
        if let Ok(bytes) = fs::read(format!("{base}/status")) {
            let (shape, bytes, ok) = match parse_status(&bytes) {
                Ok(mut status) => {
                    let labels: Vec<String> = status
                        .lines
                        .iter()
                        .map(|line| match line {
                            StatusLine::Known { label, .. } => label.name().to_string(),
                            StatusLine::Unknown { label, .. } => {
                                String::from_utf8_lossy(label).into_owned()
                            }
                        })
                        .collect();
                    if let Some(StatusValue::Name(printed)) = status.get(StatusLabel::Name).cloned()
                    {
                        status.set(
                            StatusLabel::Name,
                            StatusValue::Name(anonymize_printed_name(&printed)),
                        );
                    }
                    (labels.join(","), render_status(&status), true)
                }
                Err(_) => ("refused".to_string(), bytes, false),
            };
            collector.offer(Format::Status, shape, bytes, ok);
        }
        if let Ok(bytes) = fs::read(format!("{base}/comm")) {
            let (shape, bytes, ok) = match parse_comm_file(&bytes) {
                Ok(name) => {
                    let shape = comm_shape(&name);
                    (shape, render_comm_file(&anonymize_name(&name)), true)
                }
                Err(_) => ("refused".to_string(), bytes, false),
            };
            collector.offer(Format::Comm, shape, bytes, ok);
        }
        if let Ok(bytes) = fs::read(format!("{base}/statm")) {
            let ok = parse_statm(&bytes).is_ok();
            collector.offer(Format::Statm, "only".to_string(), bytes, ok);
        }
        if let Ok(bytes) = fs::read(format!("{base}/io")) {
            let ok = parse_process_io(&bytes).is_ok();
            collector.offer(Format::ProcessIo, "only".to_string(), bytes, ok);
        }
        if let Ok(bytes) = fs::read(format!("{base}/sched")) {
            let (shape, bytes, ok) = match parse_sched(&bytes) {
                Ok(mut sched) => {
                    let labels: Vec<String> = sched
                        .entries
                        .iter()
                        .filter_map(|e| match e {
                            reverie_proc_grammar::SchedEntry::Field { label, .. } => {
                                Some(String::from_utf8_lossy(label).into_owned())
                            }
                            _ => None,
                        })
                        .collect();
                    sched.comm = anonymize_name(&sched.comm);
                    (labels.join(","), render_sched(&sched), true)
                }
                Err(_) => ("refused".to_string(), bytes, false),
            };
            collector.offer(Format::Sched, shape, bytes, ok);
        }
        // fdinfo is only readable for our own processes without
        // ptrace privilege; unreadable directories are simply skipped.
        if let Ok(fds) = fs::read_dir(format!("{base}/fdinfo")) {
            for entry in fds.flatten() {
                if let Ok(bytes) = fs::read(entry.path()) {
                    let (shape, ok) = match parse_fdinfo(&bytes) {
                        Ok(fdinfo) => {
                            let kind = match fdinfo.kind {
                                reverie_proc_grammar::FdinfoKind::Plain => "plain",
                                reverie_proc_grammar::FdinfoKind::Eventfd { .. } => "eventfd",
                                reverie_proc_grammar::FdinfoKind::Signalfd { .. } => "signalfd",
                                reverie_proc_grammar::FdinfoKind::Timerfd(_) => "timerfd",
                                reverie_proc_grammar::FdinfoKind::UnixSocket { .. } => "unix",
                                reverie_proc_grammar::FdinfoKind::Pidfd { .. } => "pidfd",
                                reverie_proc_grammar::FdinfoKind::Epoll(_) => "epoll",
                                reverie_proc_grammar::FdinfoKind::Inotify(_) => "inotify",
                                reverie_proc_grammar::FdinfoKind::Fuse { .. } => "fuse",
                                _ => "other",
                            };
                            let locks = if fdinfo.locks.is_empty() {
                                ""
                            } else {
                                "+locks"
                            };
                            (format!("{kind}{locks}"), true)
                        }
                        Err(_) => ("refused".to_string(), false),
                    };
                    collector.offer(Format::Fdinfo, shape, bytes, ok);
                }
            }
        }
    }

    fs::create_dir_all(&out).expect("create output dir");
    // Only the version number: local build suffixes are not corpus data.
    let kernel =
        fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_else(|_| "unknown".to_string());
    let kernel = kernel.trim().split('-').next().unwrap_or("unknown");
    let mut manifest = format!(
        "# collected by examples/collect-corpus.rs\nkernel: {kernel}\npids-scanned: {}\n",
        pids.len()
    );
    let mut counters: BTreeMap<Format, usize> = BTreeMap::new();
    for ((format, shape), files) in &collector.kept {
        let dir = out.join(format.name());
        fs::create_dir_all(&dir).expect("create format dir");
        for bytes in files {
            let n = counters.entry(*format).or_default();
            *n += 1;
            let name = format!("{:03}.bytes", *n);
            fs::write(dir.join(&name), bytes).expect("write fixture");
            manifest.push_str(&format!("{}/{} shape={}\n", format.name(), name, shape));
        }
    }
    for format in [
        Format::Stat,
        Format::Status,
        Format::Comm,
        Format::Statm,
        Format::ProcessIo,
        Format::Sched,
        Format::Fdinfo,
    ] {
        manifest.push_str(&format!(
            "scanned {}: {} (refused {})\n",
            format.name(),
            collector.scanned.get(&format).copied().unwrap_or(0),
            collector.refused.get(&format).copied().unwrap_or(0)
        ));
    }
    fs::write(out.join("MANIFEST"), manifest).expect("write manifest");
    let kept: usize = counters.values().sum();
    let refused: usize = collector.refused.values().sum();
    println!(
        "kept {kept} fixtures from {} pids; refused {refused} files (see MANIFEST)",
        pids.len()
    );
}
