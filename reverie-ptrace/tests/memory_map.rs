/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::memory_map` on a traced guest is the kernel's own `maps` of the
//! named thread's address space, complete, in any process the tracer traces:
//! a C guest (`fixtures/memory_map.c`) that changes its program break and its
//! stack one step at a time, run under the tracer, reads
//! `/proc/<tid>/maps` itself at each point, and the tool reads the fact at
//! the same point, before the guest runs again. At every point that names a
//! live guest thread, the guest's own, a sibling thread's and a child
//! process's, the fact is the text the guest read, mapping for mapping; an
//! exited child, as a zombie (whose map Linux prints empty) and once reaped,
//! the guest's parent (the tracer's process), a number no task has, zero and
//! a negative number are `ESRCH`, and so is a task this process traces
//! outside the session.
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
use reverie::MappingBacking;
use reverie::MemoryMap;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

/// The first argument of a guest's `tuxcall` that asks for a fact.
const ASK: u64 = 0x6d65_6d6f_7279_6d61;

// The fixture's numbered points.
const START: u64 = 1;
const HEAP_READ_ONLY: u64 = 3;
const STACK_GUARD: u64 = 8;
const SIBLING_LEADER: u64 = 11;
const SIBLING: u64 = 12;
const SIBLING_SELF: u64 = 13;
const CHILD: u64 = 14;
const ZOMBIE_CHILD: u64 = 15;
const REAPED_CHILD: u64 = 16;
const HOST_PARENT: u64 = 17;
const NO_TASK: u64 = 18;
const ZERO: u64 = 19;
const NEGATIVE: u64 = 20;
const POINTS: u64 = 20;
/// A task this process traces outside the session
/// (`a_task_traced_outside_the_session_is_esrch`).
const BYSTANDER: u64 = 21;

type Fact = Result<MemoryMap, FactError>;

/// The facts the tool read, by the guest's point number.
#[derive(Default)]
struct FactLog(Mutex<BTreeMap<u64, (i32, Fact)>>);

#[reverie::global_tool]
impl GlobalTool for FactLog {
    type Request = (u64, i32, Fact);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) {
        let (point, tid, fact) = request;
        let previous = self.0.lock().unwrap().insert(point, (tid, fact));
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
        let fact = guest.memory_map(Pid::from_raw(tid));
        guest.send_rpc((point, tid, fact)).await;
        Ok(0)
    }
}

/// A fresh directory under the temporary directory, removed when dropped.
struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "reverie-ptrace-memory-map-test-{}",
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

/// What the run of the fixture listed: each point's thread, and the text or
/// errno of its own read of that thread's `maps`.
#[derive(Debug, Default)]
struct Listing {
    tids: BTreeMap<u64, i64>,
    reads: BTreeMap<u64, Result<Vec<u8>, i32>>,
    asked: usize,
}

fn listing(stdout: &str) -> Listing {
    let mut listing = Listing::default();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields[..] {
            ["heap", _] | ["guard", _] => {}
            ["tid", point, tid] => {
                listing
                    .tids
                    .insert(point.parse().unwrap(), tid.parse().unwrap());
            }
            ["point", _, "asked"] => listing.asked += 1,
            ["point", point, "errno", errno] => {
                listing
                    .reads
                    .insert(point.parse().unwrap(), Err(errno.parse().unwrap()));
            }
            ["point", point, "text", hex] => {
                let text = (0..hex.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
                    .collect();
                listing.reads.insert(point.parse().unwrap(), Ok(text));
            }
            _ => panic!("fixture line {line:?}"),
        }
    }
    listing
}

#[test]
fn a_traced_guest_reports_the_maps_linux_shows() {
    let directory = Directory::new();
    let source = directory.0.join("memory_map.c");
    let executable = directory.0.join("memory_map");
    std::fs::write(&source, include_str!("fixtures/memory_map.c")).unwrap();
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
    let (output, log) =
        reverie_ptrace::testing::test_cmd::<FactTool>(executable.to_str().unwrap(), &["tool"])
            .unwrap();
    assert_eq!(
        output.status,
        reverie::ExitStatus::Exited(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let traced = listing(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(traced.reads.len() as u64, POINTS, "{traced:?}");
    assert_eq!(traced.asked as u64, POINTS);
    let facts = log.0.into_inner().unwrap();
    assert_eq!(facts.len() as u64, POINTS, "{facts:?}");
    for (point, (tid, _)) in &facts {
        assert_eq!(i64::from(*tid), traced.tids[point], "point {point}");
    }

    // Every point that names a live guest thread: the fact is the map the
    // guest read itself just before, complete, mapping for mapping. Its own,
    // through each change; a sibling thread's, asked by either thread; and
    // the child's, whose address space is its own.
    for point in (START..=CHILD).filter(|point| ![ZOMBIE_CHILD].contains(point)) {
        let Ok(text) = &traced.reads[&point] else {
            panic!("point {point}: {:?}", traced.reads[&point]);
        };
        let linux = MemoryMap::from_maps(text).unwrap();
        assert_eq!(facts[&point].1, Ok(linux.clone()), "point {point}");
        assert!(linux.complete);
        assert!(
            linux
                .mappings
                .iter()
                .any(|mapping| mapping.backing == MappingBacking::Stack),
            "point {point}"
        );
    }
    // The points show what they changed.
    let heap = |point: u64| match &facts[&point].1 {
        Ok(map) => map
            .mappings
            .iter()
            .filter(|mapping| mapping.backing == MappingBacking::Heap)
            .map(|mapping| mapping.prot)
            .collect::<Vec<_>>(),
        other => panic!("point {point}: {other:?}"),
    };
    let rw = (libc::PROT_READ | libc::PROT_WRITE) as u32;
    assert!(heap(START).is_empty());
    assert_eq!(heap(HEAP_READ_ONLY), [rw, libc::PROT_READ as u32, rw]);
    let Ok(guarded) = &facts[&STACK_GUARD].1 else {
        panic!("{:?}", facts[&STACK_GUARD]);
    };
    assert!(
        guarded
            .mappings
            .iter()
            .any(|mapping| mapping.prot == 0 && mapping.backing == MappingBacking::Anonymous)
    );
    assert_eq!(facts[&SIBLING].1, facts[&SIBLING_LEADER].1);
    assert_eq!(facts[&SIBLING_SELF].1, facts[&SIBLING_LEADER].1);
    assert_ne!(facts[&SIBLING].0, facts[&SIBLING_LEADER].0);
    // The child's map is its own: its break is a page above its parent's.
    assert_ne!(facts[&CHILD].0, facts[&START].0);
    let heap_end = |point: u64| match &facts[&point].1 {
        Ok(map) => map
            .mappings
            .iter()
            .rfind(|mapping| mapping.backing == MappingBacking::Heap)
            .map(|mapping| mapping.end),
        other => panic!("point {point}: {other:?}"),
    };
    assert_eq!(
        heap_end(CHILD),
        heap_end(SIBLING_LEADER).map(|end| end + 4096)
    );

    // Numbers that name no live guest thread: the exited child, as a zombie,
    // whose map Linux prints empty, and once reaped; the guest's parent, the
    // tracer's process, a host task that exists; a number no task has, zero
    // and -1.
    for point in [
        ZOMBIE_CHILD,
        REAPED_CHILD,
        HOST_PARENT,
        NO_TASK,
        ZERO,
        NEGATIVE,
    ] {
        assert_eq!(
            facts[&point].1,
            Err(FactError::Errno(Errno::ESRCH)),
            "point {point}"
        );
    }
    assert_eq!(traced.reads[&ZOMBIE_CHILD], Ok(Vec::new()));
    for point in [REAPED_CHILD, NO_TASK, ZERO, NEGATIVE] {
        assert_eq!(traced.reads[&point], Err(libc::ENOENT), "point {point}");
    }
    assert_eq!(facts[&HOST_PARENT].0, std::process::id() as i32);
    assert_eq!(facts[&ZOMBIE_CHILD].0, facts[&CHILD].0);
}

/// A task a thread of this process traces, but that is no guest of the
/// session, is ESRCH: the session's own record of its tasks decides, not
/// only the kernel's word that a tracer of ours traces the task. The
/// bystander is a child of this test process that this thread traces.
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
            // SAFETY: tuxcall takes no pointers; only the tool answers it.
            unsafe {
                libc::syscall(
                    libc::SYS_tuxcall,
                    ASK,
                    bystander as libc::c_long,
                    BYSTANDER as libc::c_long,
                )
            };
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
    assert_eq!(
        facts.into_iter().collect::<Vec<_>>(),
        [(BYSTANDER, (bystander, Err(FactError::Errno(Errno::ESRCH))))]
    );
}
