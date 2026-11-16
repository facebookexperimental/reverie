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

use reverie_proc_grammar::*;

fn pids() -> Vec<u32> {
    let mut pids: Vec<u32> = fs::read_dir("/proc")
        .expect("read /proc")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids
}

#[test]
fn live_proc_inventory() {
    let mut ok: BTreeMap<&str, usize> = BTreeMap::new();
    let mut refused: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    let my_uid = unsafe { libc::getuid() };
    let all_pids = pids();
    let population = all_pids.len();

    for pid in &all_pids {
        let base = format!("/proc/{pid}");
        macro_rules! check {
            ($file:literal, $parse:ident, $render:ident) => {
                if let Ok(bytes) = fs::read(format!("{base}/{}", $file)) {
                    match $parse(&bytes) {
                        Ok(parsed) => {
                            if $render(&parsed) == bytes {
                                *ok.entry($file).or_default() += 1;
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
        if let Ok(bytes) = fs::read(format!("{base}/status")) {
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
                        *ok.entry("status").or_default() += 1;
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
    // The anti-vacuity floor scales with the population the host
    // actually has: a big host must still produce >100 round-trips
    // per format, while a small PID namespace (a CI container may
    // hold only dozens of tasks) must round-trip ~all of its tasks.
    // Refusals and render mismatches above hard-fail at any size.
    let floor = usize::min(101, population * 9 / 10 + 1);
    for format in ["stat", "status", "comm", "statm", "sched"] {
        let count = ok.get(format).copied().unwrap_or(0);
        assert!(
            count >= floor,
            "inventory too thin for {format}: {count} of {population} tasks (floor {floor})"
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
    let mut fdinfo_ok = 0usize;
    let mut fdinfo_listed = 0usize;
    let mut fdinfo_unmodelled = 0usize;
    let mut fdinfo_bad: Vec<String> = Vec::new();
    for pid in &all_pids {
        let uid = fs::metadata(format!("/proc/{pid}")).map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.uid()
        });
        if uid.ok() != Some(my_uid) {
            continue;
        }
        let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fdinfo")) else {
            continue;
        };
        for entry in entries.flatten() {
            fdinfo_listed += 1;
            let Ok(bytes) = fs::read(entry.path()) else {
                continue;
            };
            match parse_fdinfo(&bytes) {
                Ok(parsed) => {
                    if render_fdinfo(&parsed) == bytes {
                        fdinfo_ok += 1;
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
    // Same scaled anti-vacuity floor as the per-task formats, but
    // with the denominator counted from the directory listing:
    // every enumerated fdinfo entry counts, including ones that
    // vanished or could not be read, minus the tolerated
    // unmodelled kinds actually observed. (Counting only entries
    // that already round-tripped would make the floor vacuous
    // next to the fdinfo_bad assert above.)
    let fdinfo_modelled_listed = fdinfo_listed - fdinfo_unmodelled;
    let fdinfo_floor = usize::min(101, fdinfo_modelled_listed * 9 / 10 + 1);
    assert!(
        fdinfo_listed > 0 && fdinfo_ok >= fdinfo_floor,
        "fdinfo inventory too thin: {fdinfo_ok} round-tripped of {fdinfo_listed} listed \
         ({fdinfo_unmodelled} unmodelled tolerated, floor {fdinfo_floor})"
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
