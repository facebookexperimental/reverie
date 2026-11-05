/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::link_path` on a KVM guest names what Linux's `readlink(2)` names
//! for a thread's `fd/<fd>`, `exe` and `cwd` links: the same C guest, run
//! natively, reads `/proc/<tid>/...` at the points where the KVM run asks the
//! Tool. The points cover a file, an unlinked file, a pipe, a socket, an
//! eventfd, a signalfd, a memfd, `/dev/null`, captured standard output and a
//! descriptor made of it, a file received through `SCM_RIGHTS`, a pidfd, a
//! timerfd and an epoll; the image, also after an exec through a hard link
//! and once that link is unlinked; the working directory, also a
//! subdirectory once it is removed; a sibling thread's descriptor and
//! image; and a child process's descriptor and image. A closed descriptor and a negative one are `EBADF`, and an exited
//! child, as a zombie and once reaped, the guest's parent, a number no task
//! has, zero and a negative number are `ESRCH`. The executor's limits show as
//! named differences: a `/proc` file the executor makes itself, a sibling's
//! working directory, and another process's working directory are not
//! provided.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
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
use reverie_kvm::KvmBackend;

/// The first argument of the guest's `tuxcall` that asks for a fact
/// (`ASK` in the fixture).
const ASK: u64 = 0x6c69_6e6b_7061_7468;

// The fixture's numbered points.
const REGULAR: u64 = 1;
const DELETED: u64 = 2;
const PIPE: u64 = 3;
const SOCKET: u64 = 4;
const EVENTFD: u64 = 5;
const SIGNALFD: u64 = 6;
const MEMFD: u64 = 7;
const DEV_NULL: u64 = 8;
const STDOUT: u64 = 9;
const STDOUT_DUP: u64 = 10;
const RECEIVED: u64 = 11;
const CLOSED: u64 = 12;
const NEGATIVE_FD: u64 = 13;
const EXE: u64 = 14;
const CWD: u64 = 15;
const SUBDIR_CWD: u64 = 16;
const REMOVED_CWD: u64 = 17;
const PROC_FILE: u64 = 18;
const PIDFD: u64 = 19;
const TIMERFD: u64 = 20;
const EPOLL: u64 = 21;
const SIBLING_FD: u64 = 22;
const SIBLING_EXE: u64 = 23;
const SIBLING_CWD: u64 = 24;
const CHILD_FD: u64 = 25;
const CHILD_EXE: u64 = 26;
const CHILD_CWD: u64 = 27;
const ZOMBIE_CHILD: u64 = 28;
const REAPED_CHILD: u64 = 29;
const HOST_PARENT: u64 = 30;
const NO_TASK: u64 = 31;
const ZERO: u64 = 32;
const NEGATIVE: u64 = 33;
const EXEC_EXE: u64 = 34;
const EXEC_DELETED_EXE: u64 = 35;
const POINTS: u64 = 35;

type Fact = Result<LinkPath, FactError>;

/// The facts the Tool read, by the guest's point number.
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

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-kvm-link-path-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
/// errnos (`None` for a run under the Tool, which only asks), the inodes
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
fn a_kvm_guest_reports_the_links_linux_shows() {
    Kvm::new().expect("link path test requires usable /dev/kvm");
    let directory = Directory::new();
    let source = directory.0.join("link_path.c");
    let executable = directory.0.join("link_path");
    std::fs::write(&source, include_str!("fixtures/link_path.c")).unwrap();
    let compiled = std::process::Command::new("/usr/bin/gcc")
        .args(["-O2", "-std=c11", "-pthread", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "gcc: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let work = directory.0.join("work");
    std::fs::create_dir(&work).unwrap();
    let work_arg = work.to_str().unwrap();

    let native = std::process::Command::new(&executable)
        .args(["native", work_arg])
        .output()
        .unwrap();
    assert!(native.status.success(), "native: {native:?}");
    let native = listing(&String::from_utf8(native.stdout).unwrap());
    assert_eq!(native.points.len() as u64, POINTS, "{native:?}");

    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap(), "tool", work_arg],
            &[],
            &work,
        )
        .unwrap();
    let (log, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<FactTool>((), true))
            .unwrap();
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    let kvm = listing(&String::from_utf8(stdout).unwrap());
    assert_eq!(kvm.points.len() as u64, POINTS, "{kvm:?}");
    assert!(kvm.points.values().all(Option::is_none), "{kvm:?}");
    assert!(std::fs::read_dir(&work).unwrap().next().is_none());
    let facts = log.0.into_inner().unwrap();
    assert_eq!(facts.len() as u64, POINTS, "{facts:?}");
    let linux = |point: u64| match &native.points[&point] {
        Some(Ok(text)) => text.clone(),
        other => panic!("native point {point}: {other:?}"),
    };
    let fact = |point: u64| &facts[&point].2;

    // Where the executor holds what Linux holds, the fact is Linux's text,
    // byte for byte, of the same kind.
    for point in [
        REGULAR,
        DELETED,
        EVENTFD,
        SIGNALFD,
        MEMFD,
        DEV_NULL,
        RECEIVED,
        EXE,
        CWD,
        SUBDIR_CWD,
        REMOVED_CWD,
        PIDFD,
        TIMERFD,
        EPOLL,
        SIBLING_FD,
        SIBLING_EXE,
        CHILD_FD,
        CHILD_EXE,
        EXEC_EXE,
        EXEC_DELETED_EXE,
    ] {
        assert_eq!(
            fact(point),
            &LinkPath::from_readlink(&linux(point)),
            "point {point}: Linux's {:?}",
            String::from_utf8_lossy(&linux(point))
        );
    }
    // A pipe, a socket, and captured standard output and a descriptor made
    // of it: each the object its fstat describes, of Linux's kind.
    for point in [PIPE, SOCKET, STDOUT, STDOUT_DUP] {
        let Ok(LinkPath::Anonymous(text)) = fact(point) else {
            panic!("point {point}: {:?}", fact(point));
        };
        assert_eq!(
            without_inode(text, kvm.inodes[&point]),
            without_inode(&linux(point), native.inodes[&point]),
            "point {point}"
        );
    }
    // The texts those points show, spelled out.
    let path = |text: &[u8]| Ok(LinkPath::Path(text.to_vec()));
    let anonymous = |text: &str| Ok(LinkPath::Anonymous(text.as_bytes().to_vec()));
    let work = std::fs::canonicalize(&work).unwrap();
    let under = |name: &str| work.join(name).into_os_string().into_encoded_bytes();
    let deleted = |name: &str| [under(name).as_slice(), b" (deleted)"].concat();
    let image = std::fs::canonicalize(&executable)
        .unwrap()
        .into_os_string()
        .into_encoded_bytes();
    assert_eq!(fact(REGULAR), &path(&under("regular")));
    assert_eq!(fact(DELETED), &path(&deleted("deleted")));
    assert_eq!(fact(EVENTFD), &anonymous("anon_inode:[eventfd]"));
    assert_eq!(fact(SIGNALFD), &anonymous("anon_inode:[signalfd]"));
    assert_eq!(fact(MEMFD), &path(b"/memfd:link-path-memfd (deleted)"));
    assert_eq!(fact(DEV_NULL), &path(b"/dev/null"));
    assert_eq!(fact(RECEIVED), &path(&under("received")));
    assert_eq!(fact(EXE), &path(&image));
    assert_eq!(fact(CWD), &path(work.as_os_str().as_encoded_bytes()));
    assert_eq!(fact(SUBDIR_CWD), &path(&under("subdir")));
    assert_eq!(fact(REMOVED_CWD), &path(&deleted("subdir")));
    assert_eq!(fact(PIDFD), &anonymous("anon_inode:[pidfd]"));
    assert_eq!(fact(TIMERFD), &anonymous("anon_inode:[timerfd]"));
    assert_eq!(fact(EPOLL), &anonymous("anon_inode:[eventpoll]"));
    assert_eq!(fact(SIBLING_FD), &path(&under("regular")));
    assert_eq!(fact(SIBLING_EXE), &path(&image));
    assert_eq!(fact(CHILD_FD), &path(&under("child-file")));
    assert_eq!(fact(CHILD_EXE), &path(&image));
    assert_eq!(fact(EXEC_EXE), &path(&under("relinked")));
    assert_eq!(fact(EXEC_DELETED_EXE), &path(&deleted("relinked")));
    assert!(matches!(fact(STDOUT), Ok(LinkPath::Anonymous(text)) if text.starts_with(b"pipe:[")));
    assert_eq!(fact(STDOUT_DUP), fact(STDOUT));
    // The sibling's links were asked about by the leader, the child's by
    // its parent, and the image after the exec by the same thread.
    let tid = facts[&REGULAR].0;
    assert_ne!(facts[&SIBLING_FD].0, tid);
    assert_eq!(facts[&SIBLING_EXE].0, facts[&SIBLING_FD].0);
    assert_eq!(facts[&EXEC_EXE].0, tid);
    assert_eq!(kvm.pids.len(), 2);
    assert_eq!(kvm.pids[0], kvm.pids[1]);

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
    assert_eq!(facts[&NEGATIVE_FD].1, PathLink::Descriptor(-1));

    // Numbers that name no live guest thread: an exited child, as a zombie
    // (whose links Linux no longer has, ENOENT) and once reaped, the guest's
    // parent, whose image Linux shows, a number no task has, zero and -1.
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
    assert!(matches!(native.points[&HOST_PARENT], Some(Ok(_))));
    assert_eq!(
        [facts[&NO_TASK].0, facts[&ZERO].0, facts[&NEGATIVE].0],
        [i32::MAX, 0, -1]
    );

    // The executor's limits, each against Linux's answer. A /proc file the
    // executor makes itself is not provided; Linux names the file.
    assert_eq!(
        linux(PROC_FILE),
        format!("/proc/{}/maps", native.pids[0]).into_bytes()
    );
    assert_eq!(fact(PROC_FILE), &Err(FactError::NotProvided));
    // The executor keeps a working directory per thread, out of another
    // thread's reach: a sibling's is not provided, where Linux shows the one
    // the threads share.
    assert_eq!(linux(SIBLING_CWD), work.as_os_str().as_encoded_bytes());
    assert_eq!(fact(SIBLING_CWD), &Err(FactError::NotProvided));
    // Another process's working directory is not provided, where Linux
    // shows its own. Its descriptors and image are the run's records of
    // them, named above.
    assert_eq!(linux(CHILD_CWD), under("childdir"));
    assert_eq!(fact(CHILD_CWD), &Err(FactError::NotProvided));
    assert_ne!(facts[&CHILD_FD].0, tid);
    assert_eq!(facts[&ZOMBIE_CHILD].0, facts[&CHILD_FD].0);
}
