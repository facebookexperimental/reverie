/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::link_path` on a traced guest is the kernel's own `readlink(2)` of
//! the named thread's `fd/<fd>`, `exe` and `cwd` links, in any process the
//! tracer traces: the C guest of the KVM backend's test, run natively and
//! under the tracer, at the same points. Every link a live guest thread has
//! is Linux's text, a sibling thread's and a child process's included; a
//! closed descriptor and a negative one are `EBADF`; and an exited child, as
//! a zombie and once reaped, the guest's parent (the tracer's process), a
//! number no task has, zero and a negative number are `ESRCH`, and so is a
//! task this process traces outside the session.
//!
//! The guest asks at numbered points with `tuxcall`, which Linux does not
//! implement; the tool answers it, and records the fact it read then.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;

use reverie::Errno;
use reverie::Error;
use reverie::FactError;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::LinkPath;
use reverie::PathLink;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

/// The first argument of a guest's `tuxcall` that asks for a fact.
const ASK: u64 = 0x6c69_6e6b_7061_7468;

// The fixture's numbered points.
const REGULAR: u64 = 1;
const PIPE: u64 = 3;
const SOCKET: u64 = 4;
const STDOUT: u64 = 9;
const STDOUT_DUP: u64 = 10;
const CLOSED: u64 = 12;
const NEGATIVE_FD: u64 = 13;
const PROC_FILE: u64 = 18;
const SIBLING_FD: u64 = 22;
const CHILD_FD: u64 = 25;
const ZOMBIE_CHILD: u64 = 28;
const REAPED_CHILD: u64 = 29;
const HOST_PARENT: u64 = 30;
const NO_TASK: u64 = 31;
const ZERO: u64 = 32;
const NEGATIVE: u64 = 33;
const POINTS: u64 = 35;
/// A task this process traces outside the session
/// (`a_task_traced_outside_the_session_is_esrch`).
const BYSTANDER: u64 = 36;

type Fact = Result<LinkPath, FactError>;

/// The facts the tool read, by the guest's point number.
#[derive(Default)]
struct FactLog(Mutex<BTreeMap<u64, (i32, PathLink, Fact)>>);

#[reverie::global_tool]
impl GlobalTool for FactLog {
    type Request = (u64, i32, PathLink, Fact);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) {
        let (point, tid, link, fact) = request;
        let previous = self.0.lock().unwrap().insert(point, (tid, link, fact));
        assert!(previous.is_none(), "point {point} asked twice");
    }
}

#[derive(Default)]
struct FactTool;

#[reverie::tool]
impl Tool for FactTool {
    type GlobalState = FactLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::tuxcall].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (_, args) = syscall.into_parts();
        if args.arg0 as u64 != ASK {
            return Ok(guest.inject(syscall).await?);
        }
        let (tid, point) = (args.arg1 as i32, args.arg2 as u64);
        let link = match args.arg3 {
            0 => PathLink::Descriptor(args.arg4 as i32),
            1 => PathLink::Executable,
            _ => PathLink::WorkingDirectory,
        };
        let fact = guest.link_path(Pid::from_raw(tid), link);
        guest.send_rpc((point, tid, link, fact)).await;
        Ok(0)
    }
}

/// A fresh directory under the temporary directory, removed when dropped.
struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "reverie-ptrace-link-path-test-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// What one run of the fixture listed: the native run's link texts or
/// errnos (`None` for a run under the tool, which only asks), the inodes
/// the guest's `fstat` reported, and its process IDs, in order.
#[derive(Debug, Default)]
struct Listing {
    points: BTreeMap<u64, Option<Result<Vec<u8>, i32>>>,
    inodes: BTreeMap<u64, u64>,
    pids: Vec<i32>,
}

fn listing(stdout: &str) -> Listing {
    let mut listing = Listing::default();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields[..] {
            ["pid", pid] => listing.pids.push(pid.parse().unwrap()),
            ["inode", point, inode] => {
                listing
                    .inodes
                    .insert(point.parse().unwrap(), inode.parse().unwrap());
            }
            ["point", point, "asked"] => {
                listing.points.insert(point.parse().unwrap(), None);
            }
            ["point", point, "errno", errno] => {
                listing
                    .points
                    .insert(point.parse().unwrap(), Some(Err(errno.parse().unwrap())));
            }
            ["point", point, "text", hex] => {
                let text = (0..hex.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
                    .collect();
                listing
                    .points
                    .insert(point.parse().unwrap(), Some(Ok(text)));
            }
            _ => panic!("fixture line {line:?}"),
        }
    }
    listing
}

/// `text` with the inode in its `kind:[<inode>]` name replaced by `INODE`,
/// after checking it is `inode`, the one the guest's `fstat` reported.
fn without_inode(text: &[u8], inode: u64) -> String {
    let text = std::str::from_utf8(text).unwrap();
    let (kind, rest) = text.split_once(":[").unwrap();
    assert_eq!(rest, format!("{inode}]"), "{text}");
    format!("{kind}:[INODE]")
}

#[test]
fn a_traced_guest_reports_the_links_linux_shows() {
    let directory = Directory::new();
    let source = directory.0.join("link_path.c");
    let executable = directory.0.join("link_path");
    // The KVM backend's guest, so that both backends answer the same points.
    std::fs::write(
        &source,
        include_str!("../../reverie-kvm/tests/fixtures/link_path.c"),
    )
    .unwrap();
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let compiled = std::process::Command::new(&compiler)
        .args(["-O2", "-std=c11", "-pthread", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap_or_else(|error| panic!("invoke {compiler:?}: {error}"));
    assert!(
        compiled.status.success(),
        "{compiler:?}: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let work = directory.0.join("work");
    std::fs::create_dir(&work).unwrap();
    let work_arg = work.to_str().unwrap();
    let program = executable.to_str().unwrap();

    let native = std::process::Command::new(&executable)
        .args(["native", work_arg])
        .output()
        .unwrap();
    assert!(native.status.success(), "native: {native:?}");
    let native = listing(&String::from_utf8(native.stdout).unwrap());
    assert_eq!(native.points.len() as u64, POINTS, "{native:?}");

    let (output, log) =
        reverie_ptrace::testing::test_cmd::<FactTool>(program, &["tool", work_arg]).unwrap();
    assert_eq!(
        output.status,
        reverie::ExitStatus::Exited(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let traced = listing(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(traced.points.len() as u64, POINTS, "{traced:?}");
    assert!(std::fs::read_dir(&work).unwrap().next().is_none());
    let facts = log.0.into_inner().unwrap();
    assert_eq!(facts.len() as u64, POINTS, "{facts:?}");
    let fact = |point: u64| &facts[&point].2;

    let not_linuxs = [
        PIPE,
        SOCKET,
        STDOUT,
        STDOUT_DUP,
        CLOSED,
        NEGATIVE_FD,
        PROC_FILE,
        ZOMBIE_CHILD,
        REAPED_CHILD,
        HOST_PARENT,
        NO_TASK,
        ZERO,
        NEGATIVE,
    ];
    // Every other point is Linux's text, byte for byte, of its kind: the
    // files, objects, images and working directories of the guest's
    // threads, its sibling's and its child's included.
    for point in (1..=POINTS).filter(|point| !not_linuxs.contains(point)) {
        let Some(Ok(text)) = &native.points[&point] else {
            panic!("native point {point}: {:?}", native.points[&point]);
        };
        assert_eq!(
            fact(point),
            &LinkPath::from_readlink(text),
            "point {point}: Linux's {:?}",
            String::from_utf8_lossy(text)
        );
    }
    // A pipe, a socket, and standard output and a descriptor made of it:
    // each the object its fstat describes, in each run.
    for point in [PIPE, SOCKET, STDOUT, STDOUT_DUP] {
        let (Ok(LinkPath::Anonymous(text)), Some(Ok(linux))) =
            (fact(point), &native.points[&point])
        else {
            panic!("point {point}: {:?}", fact(point));
        };
        assert_eq!(
            without_inode(text, traced.inodes[&point]),
            without_inode(linux, native.inodes[&point]),
            "point {point}"
        );
    }
    // A /proc file names the process it was opened for, in each run.
    assert_eq!(
        native.points[&PROC_FILE],
        Some(Ok(format!("/proc/{}/maps", native.pids[0]).into_bytes()))
    );
    assert_eq!(
        fact(PROC_FILE),
        &Ok(LinkPath::Path(
            format!("/proc/{}/maps", traced.pids[0]).into_bytes()
        ))
    );
    // A descriptor the thread does not hold: Linux finds no such entry
    // (ENOENT); the fact is EBADF.
    for point in [CLOSED, NEGATIVE_FD] {
        assert_eq!(
            native.points[&point],
            Some(Err(libc::ENOENT)),
            "point {point}"
        );
        assert_eq!(
            fact(point),
            &Err(FactError::Errno(Errno::EBADF)),
            "point {point}"
        );
    }
    // Numbers that name no live guest thread.
    for point in [
        ZOMBIE_CHILD,
        REAPED_CHILD,
        HOST_PARENT,
        NO_TASK,
        ZERO,
        NEGATIVE,
    ] {
        assert_eq!(
            fact(point),
            &Err(FactError::Errno(Errno::ESRCH)),
            "point {point}"
        );
    }
    for point in [ZOMBIE_CHILD, REAPED_CHILD, NO_TASK, ZERO, NEGATIVE] {
        assert_eq!(
            native.points[&point],
            Some(Err(libc::ENOENT)),
            "point {point}"
        );
    }
    // The guest's parent is the tracer's process, a host task that exists.
    assert_eq!(facts[&HOST_PARENT].0, std::process::id() as i32);
    // The sibling's and the child's links were asked about by the leader.
    let tid = facts[&REGULAR].0;
    assert_ne!(facts[&SIBLING_FD].0, tid);
    assert_ne!(facts[&CHILD_FD].0, tid);
    assert_eq!(facts[&ZOMBIE_CHILD].0, facts[&CHILD_FD].0);
}

/// A task a thread of this process traces, but that is no guest of the
/// session, is ESRCH for every link: the session's own record of its tasks
/// decides, not only the kernel's word that a tracer of ours traces the
/// task. The bystander is a child of this test process that this thread
/// traces.
#[test]
fn a_task_traced_outside_the_session_is_esrch() {
    // SAFETY: the child only pauses until it is killed.
    let bystander = unsafe { libc::fork() };
    if bystander == 0 {
        loop {
            // SAFETY: pause takes no arguments.
            unsafe { libc::pause() };
        }
    }
    assert!(bystander > 0, "fork: {}", std::io::Error::last_os_error());
    // SAFETY: the bystander is this process's own child; PTRACE_SEIZE leaves
    // it running.
    let seized = unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            bystander,
            std::ptr::null_mut::<libc::c_void>(),
            0 as libc::c_long,
        )
    };
    let log = (seized == 0).then(|| {
        reverie_ptrace::testing::check_fn::<FactTool, _>(move || {
            for (offset, kind) in [0, 1, 2].into_iter().enumerate() {
                // SAFETY: tuxcall takes no pointers; only the tool answers it.
                unsafe {
                    libc::syscall(
                        libc::SYS_tuxcall,
                        ASK,
                        bystander as libc::c_long,
                        (BYSTANDER + offset as u64) as libc::c_long,
                        kind as libc::c_long,
                        0 as libc::c_long,
                    )
                };
            }
        })
    });
    // SAFETY: the bystander is this process's own child.
    unsafe { libc::kill(bystander, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: status is writable.
    let reaped = unsafe { libc::waitpid(bystander, &mut status, 0) };
    assert_eq!(
        seized,
        0,
        "PTRACE_SEIZE: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(reaped, bystander);
    let facts = log.unwrap().0.into_inner().unwrap();
    assert_eq!(facts.len(), 3, "{facts:?}");
    for (point, (tid, link, fact)) in facts {
        assert_eq!(tid, bystander, "point {point}");
        assert_eq!(
            fact,
            Err(FactError::Errno(Errno::ESRCH)),
            "point {point} {link:?}"
        );
    }
}
