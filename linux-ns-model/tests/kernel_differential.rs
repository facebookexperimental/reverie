/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The child half of this test makes real system calls; the library
// stays pure. `allow`, not `expect`: Buck test targets do not load
// this crate's clippy.toml, so the bans never fire there and an
// expectation would go unfulfilled (a land-blocking warning).
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the child half makes real system calls and process/filesystem accesses as the kernel oracle"
)]

//! Kernel differential test (one test function): the same
//! bind/unmount sequences run on the real kernel (in a rootless
//! user namespace, the design's fixture R) and on the model,
//! compared after every step through identifier mappings:
//! equality and parentage of mount IDs, device numbers, and peer
//! groups must agree, every other `mountinfo` field must be
//! byte-equal, and `mounts` rows must match exactly. The kernel
//! is the arbiter — where the model and this test disagree, the
//! model is wrong.
//!
//! The child process is this test binary re-run with an
//! environment flag. It performs the shared script (below) with
//! real `mount(2)`/`umount2(2)` calls and prints each result and
//! the resulting `mountinfo` rows under its tmpfs sandbox. The
//! parent seeds the model from the kernel's own snapshot at each
//! seed point (setup steps the model does not cover yet, like
//! `MS_SHARED` propagation changes, happen only there), then
//! replays each bind/unmount step through admit/commit, using
//! snapshot diffs as the performer's observations.
//!
//! The test assumes unprivileged user namespaces are available;
//! where they are not, it fails loudly rather than passing on
//! nothing.

mod common;

use std::collections::BTreeMap;
use std::io::Write as _;

use common::*;
use linux_ns_model::*;

#[derive(Clone, Debug)]
enum Step {
    /// Child finishes setup and prints a snapshot; parent seeds a
    /// fresh model from it.
    Seed(&'static str),
    Bind {
        tag: &'static str,
        src: &'static str,
        src_type: FileType,
        tgt: &'static str,
        tgt_type: FileType,
    },
    Umount {
        tag: &'static str,
        tgt: &'static str,
        flags: u64,
    },
    /// A bind the kernel refuses and admission must refuse with
    /// the same errno (no perform).
    RefusedBind {
        tag: &'static str,
        src: &'static str,
        src_type: FileType,
        tgt: &'static str,
        tgt_type: FileType,
        flags: u64,
    },
    RefusedUmount {
        tag: &'static str,
        tgt: &'static str,
        flags: u64,
    },
    /// An unmount Linux accepts but the model refuses by name
    /// (`MNT_EXPIRE`): the kernel runs it (first expiry call:
    /// `EAGAIN`), admission must refuse `EPERM` Unsupported, and
    /// neither side changes state.
    UnsupportedUmount {
        tag: &'static str,
        tgt: &'static str,
        flags: u64,
    },
}

fn script() -> Vec<Step> {
    use FileType::*;
    vec![
        Step::Seed("setup-basic"),
        Step::Bind {
            tag: "bind-dir",
            src: "/a",
            src_type: Directory,
            tgt: "/b",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-b",
            tgt: "/b",
            flags: 0,
        },
        Step::Bind {
            tag: "bind-file",
            src: "/f1",
            src_type: RegularFile,
            tgt: "/f2",
            tgt_type: RegularFile,
        },
        Step::Umount {
            tag: "umount-f2",
            tgt: "/f2",
            flags: 0,
        },
        Step::RefusedBind {
            tag: "bind-dir-onto-file",
            src: "/a",
            src_type: Directory,
            tgt: "/f1",
            tgt_type: RegularFile,
            flags: MS_BIND,
        },
        Step::RefusedBind {
            tag: "bind-high-flag-bit",
            src: "/a",
            src_type: Directory,
            tgt: "/b",
            tgt_type: Directory,
            flags: MS_BIND | (1 << 40),
        },
        Step::RefusedUmount {
            tag: "umount-nonmountpoint",
            tgt: "/a",
            flags: 0,
        },
        Step::RefusedUmount {
            tag: "umount-bad-flag",
            tgt: "/b",
            flags: 0x100,
        },
        Step::Seed("setup-propagation"),
        Step::Bind {
            tag: "bind-private-src-under-shared",
            src: "/priv",
            src_type: Directory,
            tgt: "/m1/dst",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-propagated",
            tgt: "/m1/dst",
            flags: 0,
        },
        Step::Bind {
            tag: "bind-under-lone-shared",
            src: "/a",
            src_type: Directory,
            tgt: "/lone/dst",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-lone-shared",
            tgt: "/lone/dst",
            flags: 0,
        },
        Step::Bind {
            tag: "bind-shared-src",
            src: "/m1/src",
            src_type: Directory,
            tgt: "/b",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-shared-src",
            tgt: "/b",
            flags: 0,
        },
        Step::Bind {
            tag: "bind-for-detach",
            src: "/a",
            src_type: Directory,
            tgt: "/b",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-detach-with-open-fd",
            tgt: "/b",
            flags: MNT_DETACH,
        },
        Step::Bind {
            tag: "bind-for-busy",
            src: "/a",
            src_type: Directory,
            tgt: "/b",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-busy-open-fd",
            tgt: "/b",
            flags: 0,
        },
        Step::Umount {
            tag: "umount-after-close",
            tgt: "/b",
            flags: 0,
        },
        Step::Seed("setup-slave-src"),
        Step::Bind {
            tag: "bind-slave-src-under-shared",
            src: "/ss2",
            src_type: Directory,
            tgt: "/m1/dst",
            tgt_type: Directory,
        },
        Step::Umount {
            tag: "umount-slave-src",
            tgt: "/m1/dst",
            flags: 0,
        },
        Step::UnsupportedUmount {
            tag: "umount-expire",
            tgt: "/ss",
            flags: MNT_EXPIRE,
        },
        Step::RefusedUmount {
            tag: "umount-expire-force",
            tgt: "/ss",
            flags: MNT_EXPIRE | MNT_FORCE,
        },
    ]
}

// ------------------------------------------------------------------
// Child half: real kernel calls in a rootless user namespace.

#[cfg(target_os = "linux")]
mod child {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::RawFd;

    const CLONE_NEWNS: i32 = 0x0002_0000;
    const CLONE_NEWUSER: i32 = 0x1000_0000;
    const MS_REC: u64 = 16384;
    const MS_PRIVATE: u64 = 262144;
    const MS_SHARED: u64 = 1048576;
    const MS_SLAVE: u64 = 524288;
    const MS_BIND: u64 = 4096;
    const MNT_DETACH: i32 = 2;

    fn mount(src: &str, tgt: &str, fstype: Option<&str>, flags: u64) -> Result<(), i32> {
        let src = CString::new(src).unwrap();
        let tgt = CString::new(tgt).unwrap();
        let fs = fstype.map(|f| CString::new(f).unwrap());
        // SAFETY: `src`, `tgt`, and `fs` are NUL-terminated and live
        // until the call returns; `mount(2)` copies the strings and
        // retains no pointers. The null data pointer is valid for
        // the bind and propagation calls made here.
        let r = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fs.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
                flags as libc::c_ulong,
                std::ptr::null(),
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
        }
    }

    fn umount2(tgt: &str, flags: i32) -> Result<(), i32> {
        let tgt = CString::new(tgt).unwrap();
        // SAFETY: `tgt` is NUL-terminated and live until the call
        // returns; `umount2(2)` copies the path and retains no pointer.
        let r = unsafe { libc::umount2(tgt.as_ptr(), flags) };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
        }
    }

    fn snap(out: &mut impl Write, sandbox: &str, tag: &str) {
        writeln!(out, "SNAP {tag}").unwrap();
        let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        for line in text.lines() {
            let mnt = line.split(' ').nth(4).unwrap_or("");
            if mnt == sandbox || mnt.starts_with(&format!("{sandbox}/")) {
                writeln!(out, "{line}").unwrap();
            }
        }
        writeln!(out, "END").unwrap();
        writeln!(out, "MOUNTS").unwrap();
        let text = std::fs::read_to_string("/proc/self/mounts").unwrap();
        for line in text.lines() {
            let mnt = line.split(' ').nth(1).unwrap_or("");
            if mnt == sandbox || mnt.starts_with(&format!("{sandbox}/")) {
                writeln!(out, "{line}").unwrap();
            }
        }
        writeln!(out, "MEND").unwrap();
        out.flush().unwrap();
    }

    fn result(out: &mut impl Write, tag: &str, r: Result<(), i32>) {
        match r {
            Ok(()) => writeln!(out, "RESULT {tag} OK"),
            Err(e) => writeln!(out, "RESULT {tag} ERR {e}"),
        }
        .unwrap();
        out.flush().unwrap();
    }

    /// Writes the protocol with raw `write(2)` to its own file
    /// (never stdout: the harness banner shares it and would glue
    /// lines together). Safe in the forked grandchild — no std
    /// locks are carried across the fork.
    struct FdOut(RawFd);
    impl Write for FdOut {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // SAFETY: `self.0` is the protocol descriptor opened in
            // `grandchild` (or stderr on failure) and remains open
            // here; `buf` is a valid readable slice for `buf.len()`
            // bytes, and `write(2)` does not retain its pointer.
            let n = unsafe { libc::write(self.0, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn main() -> i32 {
        // `unshare(CLONE_NEWUSER)` requires a single-threaded
        // process; the test harness runs tests on a thread. Fork:
        // the grandchild is single-threaded and does the work, the
        // child just waits for it.
        // SAFETY: `fork` has no pointer preconditions. The child
        // branch runs only `grandchild` and then `_exit`; its
        // protocol output uses raw `write(2)` rather than std
        // buffered streams, so no parent lock is reused there.
        match unsafe { libc::fork() } {
            0 => {
                let code = grandchild();
                // SAFETY: `_exit` terminates this fork child without
                // running destructors or flushing std buffers; the
                // protocol descriptor uses unbuffered raw writes.
                unsafe { libc::_exit(code) };
            }
            pid if pid > 0 => {
                let mut status = 0;
                // SAFETY: `pid` is this process's child from the
                // fork above, and `status` is a writable local.
                unsafe { libc::waitpid(pid, &mut status, 0) };
                if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    4
                }
            }
            _ => 4,
        }
    }

    fn grandchild() -> i32 {
        let sandbox = std::env::var("NSDIFF_SANDBOX").unwrap_or_default();
        let out_path = CString::new(std::env::var("NSDIFF_OUT").unwrap_or_default()).unwrap();
        // SAFETY: `out_path` is NUL-terminated and live until the
        // call returns; the returned descriptor is owned by this
        // grandchild and checked before use.
        let fd = unsafe {
            libc::open(
                out_path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o644,
            )
        };
        let mut out = FdOut(if fd >= 0 { fd } else { 2 });
        // SAFETY: `getuid` and `getgid` take no arguments and have
        // no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        // SAFETY: this grandchild is the sole thread copied by the
        // fork in `main`, satisfying the single-thread requirement
        // for creating a user namespace with `unshare`.
        if unsafe { libc::unshare(CLONE_NEWUSER | CLONE_NEWNS) } != 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            writeln!(out, "CHILD-FAIL unshare errno {e}").unwrap();
            return 3;
        }
        let _ = std::fs::write("/proc/self/setgroups", "deny");
        let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"));
        let _ = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
        // SAFETY: both calls take only scalar credentials for this
        // process after its ID maps are written; failures are
        // deliberately ignored because the namespace creator's
        // capabilities, checked by later mounts, are what matter.
        unsafe {
            libc::setresgid(0, 0, 0);
            libc::setresuid(0, 0, 0);
        }
        if let Err(e) = mount("", "/", None, MS_REC | MS_PRIVATE) {
            writeln!(out, "CHILD-FAIL make-rprivate errno {e}").unwrap();
            return 3;
        }
        if let Err(e) = mount("tmpfs", &sandbox, Some("tmpfs"), 0) {
            writeln!(out, "CHILD-FAIL sandbox tmpfs errno {e}").unwrap();
            return 3;
        }
        let p = |rel: &str| format!("{sandbox}{rel}");
        let mut held_fd: Option<RawFd> = None;
        for step in super::script() {
            match &step {
                super::Step::Seed(tag) => {
                    match *tag {
                        "setup-basic" => {
                            for d in ["/a", "/b"] {
                                std::fs::create_dir_all(p(d)).unwrap();
                            }
                            for f in ["/f1", "/f2"] {
                                std::fs::write(p(f), b"x").unwrap();
                            }
                        }
                        "setup-propagation" => {
                            for d in ["/m1", "/m2", "/m3", "/priv", "/lone"] {
                                std::fs::create_dir_all(p(d)).unwrap();
                            }
                            mount("tmpfs", &p("/m1"), Some("tmpfs"), 0).unwrap();
                            mount("", &p("/m1"), None, MS_SHARED).unwrap();
                            mount(&p("/m1"), &p("/m2"), None, MS_BIND).unwrap();
                            // /m3: a slave receiver of /m1's group,
                            // so bind/umount steps under /m1 also
                            // exercise the slave-copy branch.
                            mount(&p("/m1"), &p("/m3"), None, MS_BIND).unwrap();
                            mount("", &p("/m3"), None, MS_SLAVE).unwrap();
                            std::fs::create_dir_all(p("/m1/src")).unwrap();
                            std::fs::create_dir_all(p("/m1/dst")).unwrap();
                            mount("tmpfs", &p("/priv"), Some("tmpfs"), 0).unwrap();
                            mount("tmpfs", &p("/lone"), Some("tmpfs"), 0).unwrap();
                            mount("", &p("/lone"), None, MS_SHARED).unwrap();
                            std::fs::create_dir_all(p("/lone/dst")).unwrap();
                        }
                        "setup-slave-src" => {
                            for d in ["/ss", "/ss2"] {
                                std::fs::create_dir_all(p(d)).unwrap();
                            }
                            mount("tmpfs", &p("/ss"), Some("tmpfs"), 0).unwrap();
                            mount("", &p("/ss"), None, MS_SHARED).unwrap();
                            mount(&p("/ss"), &p("/ss2"), None, MS_BIND).unwrap();
                            mount("", &p("/ss2"), None, MS_SLAVE).unwrap();
                        }
                        other => panic!("unknown seed {other}"),
                    }
                    snap(&mut out, &sandbox, tag);
                }
                super::Step::Bind { tag, src, tgt, .. } => {
                    result(&mut out, tag, mount(&p(src), &p(tgt), None, MS_BIND));
                    snap(&mut out, &sandbox, tag);
                }
                super::Step::RefusedBind {
                    tag,
                    src,
                    tgt,
                    flags,
                    ..
                } => {
                    result(&mut out, tag, mount(&p(src), &p(tgt), None, *flags));
                    snap(&mut out, &sandbox, tag);
                }
                super::Step::Umount { tag, tgt, flags }
                | super::Step::RefusedUmount { tag, tgt, flags }
                | super::Step::UnsupportedUmount { tag, tgt, flags } => {
                    if *tag == "umount-after-close"
                        && let Some(fd) = held_fd.take()
                    {
                        // SAFETY: `fd` was returned by the checked
                        // `open` below and `take()` closes it once.
                        unsafe { libc::close(fd) };
                    }
                    if *tag == "umount-detach-with-open-fd" || *tag == "umount-busy-open-fd" {
                        let c = CString::new(p(tgt)).unwrap();
                        // SAFETY: `c` is NUL-terminated and live
                        // until the call returns; a nonnegative
                        // result is an owned descriptor stored in
                        // `held_fd` and closed exactly once.
                        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
                        assert!(fd >= 0, "open for held fd");
                        held_fd = Some(fd);
                    }
                    let flg = if *flags == super::MNT_DETACH {
                        MNT_DETACH
                    } else {
                        *flags as i32
                    };
                    result(&mut out, tag, umount2(&p(tgt), flg));
                    snap(&mut out, &sandbox, tag);
                    if *tag == "umount-detach-with-open-fd"
                        && let Some(fd) = held_fd.take()
                    {
                        // SAFETY: `fd` was returned by the checked
                        // `open` above and `take()` closes it once.
                        unsafe { libc::close(fd) };
                    }
                }
            }
        }
        writeln!(out, "DONE").unwrap();
        0
    }
}

// ------------------------------------------------------------------
// Parent half: seed from the kernel's snapshots, replay through
// the model, and compare field by field.

#[derive(Clone, Debug)]
struct KRow {
    id: u64,
    parent: u64,
    dev: String,
    root: String,
    mnt: String, // sandbox-relative ("/", "/a", ...)
    opts: String,
    optional: Vec<String>,
    fstype: String,
    source: String,
    superopts: String,
}

fn parse_row(line: &str, sandbox: &str) -> KRow {
    let f: Vec<&str> = line.split(' ').collect();
    let dash = f.iter().position(|x| *x == "-").expect("mountinfo dash");
    let mnt_abs = f[4];
    let mnt = if mnt_abs == sandbox {
        "/".to_string()
    } else {
        mnt_abs[sandbox.len()..].to_string()
    };
    KRow {
        id: f[0].parse().unwrap(),
        parent: f[1].parse().unwrap(),
        dev: f[2].to_string(),
        root: f[3].to_string(),
        mnt,
        opts: f[5].to_string(),
        optional: f[6..dash].iter().map(|s| s.to_string()).collect(),
        fstype: f[dash + 1].to_string(),
        source: f[dash + 2].to_string(),
        superopts: f[dash + 3].to_string(),
    }
}

fn parse_model_row(line: &str) -> KRow {
    // Model rows are already sandbox-relative; reuse the parser
    // with an empty prefix by faking an absolute path.
    let mut row = parse_row(line, "");
    if row.mnt.is_empty() {
        row.mnt = "/".to_string();
    }
    row
}

/// One `/proc/self/mounts` row (target sandbox-relative).
#[derive(Clone, Debug)]
struct MRow {
    source: String,
    target: String,
    fstype: String,
    opts: String,
}

fn parse_mounts_row(line: &str, sandbox: &str) -> MRow {
    let f: Vec<&str> = line.split(' ').collect();
    let target = if f[1] == sandbox {
        "/".to_string()
    } else if sandbox.is_empty() {
        f[1].to_string()
    } else {
        f[1][sandbox.len()..].to_string()
    };
    MRow {
        source: f[0].to_string(),
        target,
        fstype: f[2].to_string(),
        opts: f[3].to_string(),
    }
}

enum Event {
    Snap(String, Vec<KRow>, Vec<MRow>),
    Result(String, Result<(), i32>),
}

fn parse_child_output(text: &str, sandbox: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if let Some(tag) = line.strip_prefix("SNAP ") {
            let mut rows = Vec::new();
            for l in lines.by_ref() {
                if l == "END" {
                    break;
                }
                rows.push(parse_row(l, sandbox));
            }
            let mut mrows = Vec::new();
            match lines.next() {
                Some("MOUNTS") => {
                    for l in lines.by_ref() {
                        if l == "MEND" {
                            break;
                        }
                        mrows.push(parse_mounts_row(l, sandbox));
                    }
                }
                other => panic!("expected MOUNTS block, got {other:?}"),
            }
            events.push(Event::Snap(tag.to_string(), rows, mrows));
        } else if let Some(rest) = line.strip_prefix("RESULT ") {
            let mut parts = rest.splitn(3, ' ');
            let tag = parts.next().unwrap().to_string();
            let r = match parts.next() {
                Some("OK") => Ok(()),
                Some("ERR") => Err(parts.next().unwrap().parse().unwrap()),
                other => panic!("bad RESULT {other:?}"),
            };
            events.push(Event::Result(tag, r));
        } else if line.starts_with("CHILD-FAIL") {
            panic!("differential child could not run here: {line}");
        }
    }
    events
}

fn propagation_of(optional: &[String]) -> Propagation {
    let mut shared = None;
    let mut master = None;
    let mut unbindable = false;
    for f in optional {
        if let Some(v) = f.strip_prefix("shared:") {
            shared = Some(v.parse().unwrap());
        } else if let Some(v) = f.strip_prefix("master:") {
            master = Some(v.parse().unwrap());
        } else if let Some(v) = f.strip_prefix("propagate_from:") {
            master = Some(v.parse().unwrap());
        } else if f == "unbindable" {
            unbindable = true;
        }
    }
    match (shared, master, unbindable) {
        (_, _, true) => Propagation::Unbindable,
        (Some(p), m, _) if m.is_some() => Propagation::SharedSlave { peer: p, master: m },
        (Some(p), None, _) => Propagation::Shared(p),
        (None, m, _) if m.is_some() => Propagation::Slave(m),
        _ => Propagation::Private,
    }
}

fn seed_from(rows: &[KRow]) -> (Model, NsId, CounterIds) {
    let mut model = Model::new();
    let mut ids = CounterIds::default();
    let user = model.add_namespace(NsKind::User, None, None, &mut ids);
    let ns = model.add_namespace(NsKind::Mount, None, Some(user), &mut ids);
    let by_id: BTreeMap<u64, &KRow> = rows.iter().map(|r| (r.id, r)).collect();
    let mut sb_labels: BTreeMap<(String, String, String, String), u64> = BTreeMap::new();
    let mut seeds = Vec::new();
    for row in rows {
        let key = (
            row.dev.clone(),
            row.fstype.clone(),
            row.source.clone(),
            row.superopts.clone(),
        );
        let next = sb_labels.len() as u64 + 1;
        let label = *sb_labels.entry(key).or_insert(next);
        let is_root = row.mnt == "/";
        let (parent, at) = if is_root {
            (None, Vec::new())
        } else {
            let prow = by_id[&row.parent];
            let rel = if prow.mnt == "/" {
                row.mnt[1..].to_string()
            } else if prow.mnt == row.mnt {
                String::new()
            } else {
                row.mnt[prow.mnt.len() + 1..].to_string()
            };
            (Some(row.parent), rel.into_bytes())
        };
        seeds.push(SeedMount {
            kernel_mount_id: row.id,
            parent_kernel_mount_id: parent,
            mountpoint_in_parent: at,
            root: row.root.clone().into_bytes(),
            mount_options: row.opts.clone().into_bytes(),
            propagation: propagation_of(&row.optional),
            superblock: label,
            fs: FsFacts {
                fs_type: row.fstype.clone().into_bytes(),
                source: row.source.clone().into_bytes(),
                super_options: row.superopts.clone().into_bytes(),
                magic: 0x0102_1994,
                dev_major: row.dev.split(':').next().unwrap().parse().unwrap(),
                block_size: 4096,
                name_max: 255,
            },
            created: Timespec {
                sec: 1_800_000_000,
                nsec: 0,
            },
        });
    }
    model.seed_mounts(ns, &seeds, &mut ids).expect("seed");
    (model, ns, ids)
}

/// `mountinfo` field 1 IDs are recycled once a mount dies (the
/// kernel's `mnt_id` allocator reuses them); the model's
/// performer contract correlates through *unique* mount IDs
/// (the `statx`/`statmount` kind), which never repeat. Translate
/// snapshot IDs into lifetime-unique synthetic ones before the
/// model ever sees them: an ID present in consecutive snapshots
/// keeps its translation, an ID that vanished and reappears is a
/// new mount.
struct UniqueIds {
    next: u64,
    live: BTreeMap<u64, u64>,
    next_peer: u64,
    live_peers: BTreeMap<String, String>,
}

impl UniqueIds {
    fn new() -> Self {
        Self {
            next: 500_000,
            live: BTreeMap::new(),
            next_peer: 800_000,
            live_peers: BTreeMap::new(),
        }
    }

    fn translate(&mut self, rows: &[KRow]) -> Vec<KRow> {
        let present: std::collections::BTreeSet<u64> = rows.iter().map(|r| r.id).collect();
        self.live.retain(|k, _| present.contains(k));
        for row in rows {
            if !self.live.contains_key(&row.id) {
                self.next += 1;
                self.live.insert(row.id, self.next);
            }
        }
        // Peer-group numbers recycle exactly like mount IDs (a
        // group whose last member unmounts frees its number), so
        // give them the same lifetime treatment: a value absent
        // from one snapshot and present in the next is a new
        // group.
        let peer_values: std::collections::BTreeSet<String> = rows
            .iter()
            .flat_map(|r| r.optional.iter())
            .filter_map(|f| f.split_once(':').map(|(_, v)| v.to_string()))
            .collect();
        self.live_peers.retain(|k, _| peer_values.contains(k));
        for v in &peer_values {
            if !self.live_peers.contains_key(v) {
                self.next_peer += 1;
                self.live_peers
                    .insert(v.clone(), self.next_peer.to_string());
            }
        }
        rows.iter()
            .map(|r| {
                let mut r = r.clone();
                r.id = self.live[&r.id];
                if let Some(p) = self.live.get(&r.parent) {
                    r.parent = *p;
                }
                r.optional = r
                    .optional
                    .iter()
                    .map(|f| match f.split_once(':') {
                        Some((name, v)) => format!("{name}:{}", self.live_peers[v]),
                        None => f.clone(),
                    })
                    .collect();
                r
            })
            .collect()
    }
}

/// Emulate `Performer::identify` from a kernel snapshot: the
/// topmost mount whose visible path contains `path`.
fn identify(rows: &[KRow], path: &str, ty: FileType) -> IdentifiedPath {
    let parent_of: BTreeMap<u64, u64> = rows.iter().map(|r| (r.id, r.parent)).collect();
    let depth = |mut id: u64| {
        let mut d = 0;
        while let Some(p) = parent_of.get(&id) {
            if *p == id {
                break;
            }
            id = *p;
            d += 1;
        }
        d
    };
    let contains = |mnt: &str| mnt == "/" || path == mnt || path.starts_with(&format!("{mnt}/"));
    let best = rows
        .iter()
        .filter(|r| contains(&r.mnt))
        .max_by_key(|r| (r.mnt.len(), depth(r.id)))
        .expect("a containing mount");
    let below = if best.mnt == "/" {
        path[1..].to_string()
    } else if path == best.mnt {
        String::new()
    } else {
        path[best.mnt.len() + 1..].to_string()
    };
    let is_root = below.is_empty();
    IdentifiedPath {
        kernel_mount_id: best.id,
        below_mount_root: below.into_bytes(),
        file_type: ty,
        is_mount_root: is_root,
        final_is_symlink: false,
    }
}

#[derive(Default)]
struct Mappings {
    k2m_id: BTreeMap<u64, u64>,
    m2k_id: BTreeMap<u64, u64>,
    k2m_dev: BTreeMap<String, String>,
    m2k_dev: BTreeMap<String, String>,
    k2m_peer: BTreeMap<String, String>,
    m2k_peer: BTreeMap<String, String>,
}

impl Mappings {
    fn link(
        map: &mut BTreeMap<String, String>,
        rev: &mut BTreeMap<String, String>,
        k: &str,
        m: &str,
        what: &str,
    ) {
        if let Some(prev) = map.get(k) {
            assert_eq!(prev, m, "{what}: kernel {k} mapped to both {prev} and {m}");
        }
        if let Some(prev) = rev.get(m) {
            assert_eq!(prev, k, "{what}: model {m} mapped from both {prev} and {k}");
        }
        map.insert(k.to_string(), m.to_string());
        rev.insert(m.to_string(), k.to_string());
    }

    fn peer_of(optional: &[String]) -> Vec<String> {
        optional
            .iter()
            .filter(|f| f.contains(':'))
            .map(|f| f.to_string())
            .collect()
    }

    /// Compare the model's rendering with the kernel snapshot.
    /// Identifiers are compared through bijections built on first
    /// sight; the caller keeps one `Mappings` per seed segment
    /// (a fresh model mints fresh IDs after each re-seed).
    fn compare(&mut self, model_text: &str, kernel: &[KRow], tag: &str) {
        let model_rows: Vec<KRow> = model_text.lines().map(parse_model_row).collect();
        assert_eq!(
            model_rows.len(),
            kernel.len(),
            "{tag}: row counts differ\nmodel:\n{model_text}\nkernel rows: {}",
            kernel.len()
        );
        // Stacked mounts share a mount point; this script avoids
        // ambiguous stacks, so (mnt, root) pairs identify rows.
        let by_key: BTreeMap<(String, String), &KRow> = model_rows
            .iter()
            .map(|r| ((r.mnt.clone(), r.root.clone()), r))
            .collect();
        for k in kernel {
            let m = by_key
                .get(&(k.mnt.clone(), k.root.clone()))
                .unwrap_or_else(|| panic!("{tag}: no model row for {} root {}", k.mnt, k.root));
            assert_eq!(m.opts, k.opts, "{tag} {} opts", k.mnt);
            assert_eq!(m.fstype, k.fstype, "{tag} {} fstype", k.mnt);
            assert_eq!(m.source, k.source, "{tag} {} source", k.mnt);
            assert_eq!(m.superopts, k.superopts, "{tag} {} super options", k.mnt);
            // Parentage and identifiers through the mapping.
            Self::link(&mut self.k2m_dev, &mut self.m2k_dev, &k.dev, &m.dev, "dev");
            let kid = k.id.to_string();
            let mid = m.id.to_string();
            if let Some(prev) = self.k2m_id.insert(k.id, m.id) {
                assert_eq!(prev, m.id, "{tag}: kernel id remapped");
            }
            if let Some(prev) = self.m2k_id.insert(m.id, k.id) {
                assert_eq!(prev, k.id, "{tag}: model id remapped");
            }
            let _ = (kid, mid);
            let kp = Self::peer_of(&k.optional);
            let mp = Self::peer_of(&m.optional);
            let kunbind = k.optional.iter().any(|f| f == "unbindable");
            let munbind = m.optional.iter().any(|f| f == "unbindable");
            assert_eq!(kunbind, munbind, "{tag} {} unbindable", k.mnt);
            assert_eq!(
                kp.len(),
                mp.len(),
                "{tag} {} peer fields {kp:?} vs {mp:?}",
                k.mnt
            );
            for (kf, mf) in kp.iter().zip(&mp) {
                let (kname, kval) = kf.split_once(':').unwrap();
                let (mname, mval) = mf.split_once(':').unwrap();
                assert_eq!(kname, mname, "{tag} {} peer field kind", k.mnt);
                Self::link(&mut self.k2m_peer, &mut self.m2k_peer, kval, mval, "peer");
            }
        }
        // Parentage: mapped parents must agree for every row
        // whose kernel parent is in the snapshot.
        let model_by_id: BTreeMap<u64, &KRow> = model_rows.iter().map(|r| (r.id, r)).collect();
        for k in kernel {
            if let Some(mp) = self.k2m_id.get(&k.parent) {
                let m = model_by_id[&self.k2m_id[&k.id]];
                assert_eq!(m.parent, *mp, "{tag} {} parentage", k.mnt);
            }
        }
    }
}

fn mounts_text(model: &Model, ns: NsId) -> String {
    let root = model.namespace(ns).expect("ns").root_mount.expect("seeded");
    // The differential script's paths are ASCII; raw non-UTF-8
    // byte fidelity is covered in bind_umount_cases.
    String::from_utf8(model.render_mounts(
        ns,
        &PathInNs {
            mount: root,
            below_root: Vec::new(),
        },
    ))
    .expect("differential paths are UTF-8")
}

/// Compare `render_mounts` with the kernel's `/proc/self/mounts`
/// rows exactly (source, fstype, and the merged options string,
/// per target). No identifiers appear in this format, so no
/// mapping is involved.
fn compare_mounts(model_text: &str, kernel: &[MRow], tag: &str) {
    let model_rows: Vec<MRow> = model_text
        .lines()
        .map(|l| parse_mounts_row(l, ""))
        .collect();
    assert_eq!(
        model_rows.len(),
        kernel.len(),
        "{tag}: mounts row counts differ\nmodel:\n{model_text}"
    );
    let by_target: BTreeMap<&str, &MRow> =
        model_rows.iter().map(|r| (r.target.as_str(), r)).collect();
    for k in kernel {
        let m = by_target
            .get(k.target.as_str())
            .unwrap_or_else(|| panic!("{tag}: no model mounts row for {}", k.target));
        assert_eq!(m.source, k.source, "{tag} {} mounts source", k.target);
        assert_eq!(m.fstype, k.fstype, "{tag} {} mounts fstype", k.target);
        assert_eq!(m.opts, k.opts, "{tag} {} mounts options", k.target);
    }
}

fn caller_at(model: &Model, ns: NsId) -> CallerContext {
    caller(model, ns, true)
}

#[cfg(target_os = "linux")]
#[test]
fn differential_bind_umount() {
    if std::env::var_os("NSDIFF_CHILD").is_some() {
        std::process::exit(child::main());
    }
    let sandbox = std::env::temp_dir().join(format!("nsdiff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    std::fs::create_dir_all(&sandbox).unwrap();
    let sandbox_str = sandbox.to_string_lossy().into_owned();
    let out_file = std::env::temp_dir().join(format!("nsdiff-{}.out", std::process::id()));
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "differential_bind_umount",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("NSDIFF_CHILD", "1")
        .env("NSDIFF_SANDBOX", &sandbox_str)
        .env("NSDIFF_OUT", &out_file)
        .output()
        .expect("spawn differential child");
    let stdout =
        std::fs::read_to_string(&out_file).unwrap_or_else(|e| format!("<no protocol file: {e}>"));
    assert!(
        output.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut uniq = UniqueIds::new();
    let mut events = parse_child_output(&stdout, &sandbox_str)
        .into_iter()
        .map(|e| match e {
            Event::Snap(tag, rows, mrows) => Event::Snap(tag, uniq.translate(&rows), mrows),
            other => other,
        })
        .collect::<Vec<_>>()
        .into_iter();

    let mut state: Option<(Model, NsId, CounterIds, Vec<KRow>, Mappings)> = None;
    let mut checked_steps = 0usize;
    for step in script() {
        match &step {
            Step::Seed(tag) => {
                let Event::Snap(t, rows, mrows) = events.next().expect("snap") else {
                    panic!("expected SNAP for {tag}");
                };
                assert_eq!(&t, tag);
                let (model, ns, ids) = seed_from(&rows);
                let mut maps = Mappings::default();
                // The seed itself must render back to the kernel's
                // table before any step runs.
                let text = mountinfo(&model, ns);
                maps.compare(&text, &rows, tag);
                compare_mounts(&mounts_text(&model, ns), &mrows, tag);
                state = Some((model, ns, ids, rows, maps));
            }
            Step::Bind { .. } | Step::RefusedBind { .. } => {
                let (tag, src, src_type, tgt, tgt_type, step_flags, refused) = match &step {
                    Step::Bind {
                        tag,
                        src,
                        src_type,
                        tgt,
                        tgt_type,
                    } => (*tag, *src, *src_type, *tgt, *tgt_type, MS_BIND, false),
                    Step::RefusedBind {
                        tag,
                        src,
                        src_type,
                        tgt,
                        tgt_type,
                        flags,
                    } => (*tag, *src, *src_type, *tgt, *tgt_type, *flags, true),
                    _ => unreachable!(),
                };
                let (model, ns, ids, before, maps) = state.as_mut().expect("seeded");
                let Event::Result(t, kernel_result) = events.next().expect("result") else {
                    panic!("expected RESULT for {tag}");
                };
                assert_eq!(&t, tag);
                let Event::Snap(t2, after, after_m) = events.next().expect("snap") else {
                    panic!("expected SNAP for {tag}");
                };
                assert_eq!(&t2, tag);
                let caller = caller_at(model, *ns);
                let req = Request::Bind(BindRequest {
                    source: src.as_bytes().to_vec(),
                    target: tgt.as_bytes().to_vec(),
                    flags: step_flags,
                });
                let facts = [
                    identify(before, src, src_type),
                    identify(before, tgt, tgt_type),
                ];
                match model.admit(&caller, &req, &facts).expect("divergence") {
                    Decision::Refuse(r) => {
                        assert!(refused, "{tag}: model refused but kernel was performed");
                        assert_eq!(
                            kernel_result,
                            Err(r.errno.code()),
                            "{tag}: refusal errno vs kernel"
                        );
                    }
                    Decision::Admit(p) => {
                        assert!(!refused, "{tag}: model admitted a refused case");
                        let observed = match &kernel_result {
                            Ok(()) => {
                                let new: Vec<ObservedMount> = after
                                    .iter()
                                    .filter(|r| !before.iter().any(|b| b.id == r.id))
                                    .map(|r| ObservedMount {
                                        kernel_mount_id: r.id,
                                        parent_kernel_mount_id: r.parent,
                                        root: r.root.clone().into_bytes(),
                                        mount_point: r.mnt.clone().into_bytes(),
                                    })
                                    .collect();
                                Observed::Bind { created: new }
                            }
                            Err(e) => Observed::Failed(Errno::from_raw(*e)),
                        };
                        let done = p
                            .commit(observed, ids, &mut FixedClock)
                            .unwrap_or_else(|d| panic!("{tag}: {d}"));
                        assert_eq!(
                            done.guest.map_err(|e| e.code()),
                            kernel_result,
                            "{tag}: guest result"
                        );
                    }
                }
                let text = mountinfo(model, *ns);
                maps.compare(&text, &after, tag);
                compare_mounts(&mounts_text(model, *ns), &after_m, tag);
                *before = after;
                checked_steps += 1;
            }
            Step::Umount { tag, tgt, flags }
            | Step::RefusedUmount { tag, tgt, flags }
            | Step::UnsupportedUmount { tag, tgt, flags } => {
                #[derive(PartialEq)]
                enum Kind {
                    Normal,
                    Refused,
                    Unsupported,
                }
                let kind = match &step {
                    Step::RefusedUmount { .. } => Kind::Refused,
                    Step::UnsupportedUmount { .. } => Kind::Unsupported,
                    _ => Kind::Normal,
                };
                let (model, ns, ids, before, maps) = state.as_mut().expect("seeded");
                let Event::Result(t, kernel_result) = events.next().expect("result") else {
                    panic!("expected RESULT for {tag}");
                };
                assert_eq!(&t, tag);
                let Event::Snap(t2, after, after_m) = events.next().expect("snap") else {
                    panic!("expected SNAP for {tag}");
                };
                assert_eq!(&t2, tag);
                let caller = caller_at(model, *ns);
                let req = Request::Umount(UmountRequest {
                    target: tgt.as_bytes().to_vec(),
                    flags: *flags,
                });
                let facts = [identify(before, tgt, FileType::Directory)];
                match model.admit(&caller, &req, &facts).expect("divergence") {
                    Decision::Refuse(r) => {
                        assert!(
                            kind != Kind::Normal,
                            "{tag}: model refused but kernel was performed"
                        );
                        if kind == Kind::Unsupported {
                            // Refused by name: model EPERM, kernel
                            // ran the call (first MNT_EXPIRE call
                            // answers EAGAIN and changes nothing).
                            assert_eq!(r.errno, errno::EPERM, "{tag}: unsupported errno");
                            assert!(r.reason.is_unsupported(), "{tag}: reason");
                            assert_eq!(kernel_result, Err(11), "{tag}: kernel EAGAIN");
                        } else {
                            assert_eq!(kernel_result, Err(r.errno.code()), "{tag}: errno");
                        }
                    }
                    Decision::Admit(p) => {
                        assert!(kind == Kind::Normal, "{tag}: model admitted a refused case");
                        let observed = match &kernel_result {
                            Ok(()) => Observed::Umount {
                                removed_kernel_ids: before
                                    .iter()
                                    .filter(|b| !after.iter().any(|r| r.id == b.id))
                                    .map(|b| b.id)
                                    .collect(),
                            },
                            Err(e) => Observed::Failed(Errno::from_raw(*e)),
                        };
                        let done = p
                            .commit(observed, ids, &mut FixedClock)
                            .unwrap_or_else(|d| panic!("{tag}: {d}"));
                        assert_eq!(
                            done.guest.map_err(|e| e.code()),
                            kernel_result,
                            "{tag}: guest result"
                        );
                    }
                }
                let text = mountinfo(model, *ns);
                maps.compare(&text, &after, tag);
                compare_mounts(&mounts_text(model, *ns), &after_m, tag);
                *before = after;
                checked_steps += 1;
            }
        }
    }
    // Anti-vacuity: every non-seed step was really compared.
    let non_seed = script()
        .iter()
        .filter(|s| !matches!(s, Step::Seed(_)))
        .count();
    assert_eq!(checked_steps, non_seed);
    assert!(checked_steps >= 23, "script shrank: {checked_steps}");
    let _ = std::fs::remove_dir_all(&sandbox);
    let _ = std::io::stdout().flush();
}
