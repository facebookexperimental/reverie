/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::memory_map` on a KVM guest lists every mapping of the address
//! space and says that the list is complete; these tests check its mappings
//! of the stack window, the process's `[stack]` and the parts a split left
//! of it, against Linux's. The same C guest
//! (`fixtures/memory_map.c`), run natively without address randomization and
//! with an empty environment (the layout and the environment the backend
//! gives every guest), reads `/proc/<tid>/maps` at the points where the KVM
//! run asks the Tool, and where the main thread of a process asks about
//! itself, what `pthread_getattr_np` answers for it.
//!
//! The listed mappings are Linux's stack lines field by field, but for where
//! the lowest starts: the backend maps the whole window at load, where Linux
//! maps the stack's arguments and 128 KiB below them and grows the stack on
//! demand. That holds as the process starts and after each change it makes
//! to its own stack: a page made read-only, a guard zone made inaccessible
//! and an executable range, each split and then merged back when set back;
//! madvise hints that split the stack and an undo that merges it; munlock; a
//! page unmapped; in a forked child, a vfork child and a new image; and in a
//! forked child that sets back a guard zone its parent made, which stays a
//! mapping of its own there, as each mapping a child inherits does on Linux.
//! And
//! glibc's answer for the main thread's stack, computed from the listed
//! mappings as `pthread_getattr_np` computes it from the maps file (it ends
//! the stack at the line before `[stack]`), is Linux's answer. The list is
//! empty after an mprotect that fails part way, which Linux applies to the
//! mappings before the hole and the backend refuses whole, and in a vfork
//! child after its parent's sibling thread changed the parent's stack, which
//! the child's copy lacks. A child sharing the address space (vfork, and
//! clone or clone3 with CLONE_VM|CLONE_VFORK) that stores into the stack
//! leaves the store to its parent and the map as it was; such a child that
//! leaves a page of the stack protected when it exits, which Linux leaves to
//! its parent, is refused by name. A call the backend refuses where Linux
//! applies it (MADV_DONTFORK,
//! and a MAP_FIXED mapping in the window) leaves the list as it was, and mlock,
//! which it refuses too, is compared with Linux's stack without the mlock.
//! Another process's map is not provided, and a number no task has is ESRCH.
//! For an image whose `PT_GNU_STACK` asks for an executable stack the entry
//! is executable, as Linux maps that stack.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
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
use reverie::MappingBacking;
use reverie::MappingFact;
use reverie::MemoryMap;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_kvm::KvmBackend;

/// The first argument of the guest's `tuxcall` that asks for a fact
/// (`ASK` in the fixture).
const ASK: u64 = 0x6d65_6d6f_7279_6d61;

// The fixture's numbered points.
const START: u64 = 1;
const KEPT: u64 = 2;
const PROTECTED: u64 = 3;
const PROTECTED_BACK: u64 = 4;
const GUARDED: u64 = 5;
const GUARDED_BACK: u64 = 6;
const EXECUTABLE: u64 = 7;
const ADVISED: u64 = 8;
const ADVISED_BACK: u64 = 9;
const HUGE: u64 = 10;
const NOHUGE: u64 = 11;
const REFUSED_HINT: u64 = 12;
const MLOCKED: u64 = 13;
const MUNLOCKED: u64 = 14;
const UNMAPPED: u64 = 15;
const REMAPPED: u64 = 16;
const FORKED: u64 = 17;
const EXECUTED: u64 = 18;
const FORK_AFTER: u64 = 19;
const VFORK_AFTER: u64 = 20;
const VFORK_PARENT_AFTER: u64 = 21;
const PARTIAL: u64 = 22;
const VFORKED: u64 = 23;
const CLONED: u64 = 24;
const CLONED3: u64 = 25;
const VFORK_SEES: u64 = 26;
const SPAWNED: u64 = 27;
const SPAWN_PARENT: u64 = 28;
const PARENT_AGAIN: u64 = 29;
const SIBLING: u64 = 30;
const SIBLING_CHANGED: u64 = 31;
const CHILD: u64 = 32;
const NO_TASK: u64 = 33;
const POINTS: u64 = 33;

/// The top of the user address space with four-level paging, where both
/// Linux without randomization and the backend end the stack.
const TOP: u64 = 0x7fff_ffff_f000;
/// The start of the backend's stack window: 8 MiB below the end of the user
/// address space.
const WINDOW_START: u64 = 0x7fff_ff80_0000;
const RW: u32 = (libc::PROT_READ | libc::PROT_WRITE) as u32;
const RWX: u32 = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32;

type Fact = Result<MemoryMap, FactError>;

/// The facts the Tool read, by the guest's point number.
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

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-kvm-memory-map-{}-{}",
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

/// What one run of the fixture listed: each point's thread and the text or
/// errno of its read of that thread's `maps`, the points it asked at, and
/// the results it printed.
#[derive(Debug, Default)]
struct Listing {
    tids: BTreeMap<u64, i64>,
    reads: BTreeMap<u64, Result<Vec<u8>, i32>>,
    asked: Vec<u64>,
    results: BTreeMap<u64, (i64, i32)>,
    stacks: BTreeMap<u64, MainStack>,
}

/// What `pthread_getattr_np` answered for the main thread at a point (its
/// return value, and the stack's top and size), and what glibc computes it
/// from: `__libc_stack_end` and the stack's rlimit.
#[derive(Clone, Copy, Debug)]
struct MainStack {
    ret: i32,
    top: u64,
    size: u64,
    stack_end: u64,
    limit: u64,
}

impl Listing {
    fn map(&self, point: u64) -> MemoryMap {
        match &self.reads[&point] {
            Ok(text) => MemoryMap::from_maps(text).unwrap(),
            other => panic!("point {point}: {other:?}"),
        }
    }
}

fn listing(stdout: &str) -> Listing {
    let mut listing = Listing::default();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields[..] {
            ["tid", point, tid] => {
                listing
                    .tids
                    .insert(point.parse().unwrap(), tid.parse().unwrap());
            }
            ["result", point, rc, errno] => {
                listing.results.insert(
                    point.parse().unwrap(),
                    (rc.parse().unwrap(), errno.parse().unwrap()),
                );
            }
            ["point", point, "asked"] => listing.asked.push(point.parse().unwrap()),
            ["stack", point, ret, top, size, stack_end, limit] => {
                let hex = |field: &str| u64::from_str_radix(field, 16).unwrap();
                listing.stacks.insert(
                    point.parse().unwrap(),
                    MainStack {
                        ret: ret.parse().unwrap(),
                        top: hex(top),
                        size: hex(size),
                        stack_end: hex(stack_end),
                        limit: hex(limit),
                    },
                );
            }
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

/// The mappings of `map` in the backend's stack window: the stack, and the
/// parts a change split from it. Without randomization Linux places no other
/// mapping there.
fn stack_area(map: &MemoryMap) -> Vec<MappingFact> {
    map.mappings
        .iter()
        .filter(|mapping| WINDOW_START <= mapping.start && mapping.end <= TOP)
        .cloned()
        .collect()
}

/// A mapping as the two runs' stacks are compared: everything but its start.
fn without_start(mapping: &MappingFact) -> (u64, u32, bool, u64, MappingBacking) {
    (
        mapping.end,
        mapping.prot,
        mapping.shared,
        mapping.offset,
        mapping.backing.clone(),
    )
}

/// The backend's list while the window is unchanged: the window, `prot`.
fn stack(prot: u32) -> MemoryMap {
    MemoryMap::new(
        vec![MappingFact::new(WINDOW_START, TOP, prot, false, 0, MappingBacking::Stack).unwrap()],
        false,
    )
    .unwrap()
}

/// The fixture `fixtures/memory_map.c`.
const MEMORY_MAP_C: &str = include_str!("fixtures/memory_map.c");

/// Compiles the C source `source` into `directory` as `name`, with `flags`.
fn compile(directory: &Directory, name: &str, source: &str, flags: &[&str]) -> PathBuf {
    let executable = directory.0.join(name);
    let source_path = directory.0.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let source = source_path;
    let compiled = std::process::Command::new("/usr/bin/gcc")
        .args(["-O2", "-std=c11", "-pthread", "-Wall", "-Wextra", "-Werror"])
        .args(flags)
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
    executable
}

/// Runs `executable` natively, as the backend runs the guest: without
/// address randomization, with an empty environment, and with the stack's
/// soft rlimit at 8 MiB (no more than its hard limit), whatever the runner's
/// is: the limit the test applies to the backend's list too, since the
/// backend's guest cannot read its own here, and one that keeps Linux's
/// usual top-down layout, which an unlimited stack changes.
fn native(executable: &Path, args: &[&str]) -> Listing {
    let mut command = std::process::Command::new(executable);
    command.args(args).env_clear();
    // SAFETY: personality(2), getrlimit(2) and setrlimit(2) change only the
    // child about to exec, and are async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_STACK, &mut limit) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            limit.rlim_cur = limit.rlim_max.min(8 << 20);
            if libc::setrlimit(libc::RLIMIT_STACK, &limit) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let run = command.output().unwrap();
    assert!(run.status.success(), "native: {run:?}");
    let native = listing(&String::from_utf8(run.stdout).unwrap());
    assert!(native.asked.is_empty());
    native
}

/// Runs `executable` in a KVM VM under [`FactTool`]: what it listed, and the
/// facts the Tool read, by point.
fn kvm(directory: &Directory, executable: &Path, args: &[&str]) -> (Listing, BTreeMap<u64, Fact>) {
    let argv: Vec<&str> = std::iter::once(executable.to_str().unwrap())
        .chain(args.iter().copied())
        .collect();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(executable).unwrap(),
            &argv,
            &[],
            &directory.0,
        )
        .unwrap();
    let (log, code, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<FactTool>((), true))
            .unwrap();
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    let kvm = listing(&String::from_utf8(stdout).unwrap());
    let facts = log.0.into_inner().unwrap();
    for (point, (tid, _)) in &facts {
        assert_eq!(i64::from(*tid), kvm.tids[point], "point {point}");
    }
    let facts = facts
        .into_iter()
        .map(|(point, (_, fact))| (point, fact))
        .collect();
    (kvm, facts)
}

/// Checks that `fact` lists Linux's mappings of the stack window in
/// `linux`, `[stack]` and the parts a split left of it, field by field but
/// for where the lowest starts.
fn assert_window(point: u64, fact: &MemoryMap, linux: &MemoryMap) {
    assert!(fact.complete, "point {point}: {fact:?}");
    let fact = MemoryMap::new(stack_area(fact), false).unwrap();
    let linux = stack_area(linux);
    assert_eq!(
        fact.mappings.len(),
        linux.len(),
        "point {point}: {fact:?} {linux:?}"
    );
    assert!(!linux.is_empty(), "point {point}");
    for (ours, theirs) in fact.mappings.iter().zip(&linux) {
        assert_eq!(without_start(ours), without_start(theirs), "point {point}");
    }
    for (ours, theirs) in fact.mappings.iter().zip(&linux).skip(1) {
        assert_eq!(ours.start, theirs.start, "point {point}");
    }
    // Named difference: the window's start, below Linux's.
    assert_eq!(fact.mappings[0].start, WINDOW_START, "point {point}");
    assert!(linux[0].start > WINDOW_START, "point {point}: {linux:?}");
}

/// The stack's top and size that glibc's `pthread_getattr_np` computes for
/// the main thread from a maps file listing `mappings`, with
/// `__libc_stack_end` at `stack_end` and the stack's rlimit `limit`
/// (nptl/pthread_getattr_np.c, the same in glibc 2.34 and 2.42): the top is
/// the end of the page that holds `stack_end`; the size is the limit less
/// the part of the `[stack]` line above that page, rounded down to a page,
/// and no more than reaches the end of the line before it. `None` when no
/// line holds `stack_end`, where glibc answers ENOENT.
fn glibc_main_stack(mappings: &[MappingFact], stack_end: u64, limit: u64) -> Option<(u64, u64)> {
    let page = 4096_u64;
    let top = (stack_end & !(page - 1)) + page;
    let mut last_to = 0;
    for mapping in mappings {
        if mapping.start <= stack_end && stack_end < mapping.end {
            let size = limit.wrapping_sub(mapping.end - top) & !(page - 1);
            return Some((top, size.min(top - last_to)));
        }
        last_to = mapping.end;
    }
    None
}

/// Checks that glibc's answer for the main thread's stack computed from the
/// fact, with `__libc_stack_end` as the KVM guest has it and the rlimit the
/// native run had, is `pthread_getattr_np`'s native answer, after checking
/// that the same computation from the native maps text gives that answer.
fn assert_main_stack(point: u64, fact: &MemoryMap, native: &Listing, kvm: &Listing) {
    let linux = native.stacks[&point];
    assert_eq!(linux.ret, 0, "point {point}: {linux:?}");
    assert_eq!(
        glibc_main_stack(&native.map(point).mappings, linux.stack_end, linux.limit),
        Some((linux.top, linux.size)),
        "point {point}: the computation is glibc's"
    );
    let guest = kvm.stacks[&point];
    assert_eq!(
        glibc_main_stack(&fact.mappings, guest.stack_end, linux.limit),
        Some((linux.top, linux.size)),
        "point {point}: {fact:?}"
    );
}

#[test]
fn a_kvm_guest_lists_its_stack_window_as_linux_does() {
    Kvm::new().expect("memory map test requires usable /dev/kvm");
    let directory = Directory::new();
    let executable = compile(&directory, "memory_map", MEMORY_MAP_C, &[]);
    let native = native(&executable, &["native"]);
    assert_eq!(native.reads.len() as u64, POINTS, "{native:?}");
    let (kvm, facts) = kvm(&directory, &executable, &["tool"]);
    assert_eq!(kvm.asked, (START..=NO_TASK).collect::<Vec<_>>());
    assert_eq!(facts.len() as u64, POINTS, "{facts:?}");
    let fact = |point: u64| match &facts[&point] {
        Ok(map) => map.clone(),
        other => panic!("point {point}: {other:?}"),
    };

    // Exact: the window's mappings are Linux's stack lines, and glibc's
    // answer for the main thread's stack is Linux's. As the process started;
    // after advice that keeps the mapping's flags; around a page made
    // read-only (three lines: the window below it, the page, `[stack]`), and
    // as one line again once it is read-write; around a guard zone of four
    // inaccessible pages, which ends glibc's stack at the zone, and merged
    // again; around two pages made executable; around a page advised
    // MADV_RANDOM, and merged by MADV_NORMAL; around a page advised
    // MADV_HUGEPAGE, and then MADV_NOHUGEPAGE; after an mlock the backend
    // refuses (ENOSYS), compared with Linux's stack without the mlock, and
    // after munlock; with a page unmapped (two lines); in a grandchild forked
    // after its parent set a page back, and in the image it executed; in a
    // grandchild forked after a page was made read-only, and in a vfork child
    // made after that, and its parent once it exited; as the image a
    // posix_spawn child executed starts, and in its parent afterwards; in the
    // process once its children are done; and once a sibling thread set a
    // page of the leader's stack back.
    for point in [
        START,
        KEPT,
        PROTECTED,
        PROTECTED_BACK,
        GUARDED,
        GUARDED_BACK,
        EXECUTABLE,
        ADVISED,
        ADVISED_BACK,
        HUGE,
        NOHUGE,
        MLOCKED,
        MUNLOCKED,
        UNMAPPED,
        FORKED,
        EXECUTED,
        FORK_AFTER,
        VFORK_AFTER,
        VFORK_PARENT_AFTER,
        SPAWNED,
        SPAWN_PARENT,
        PARENT_AGAIN,
        SIBLING_CHANGED,
    ] {
        let fact = fact(point);
        assert_window(point, &fact, &native.map(point));
        assert_main_stack(point, &fact, &native, &kvm);
    }
    // Asked by a sibling thread about the leader, before it changes anything.
    assert_window(SIBLING, &fact(SIBLING), &native.map(SIBLING));
    assert_eq!(stack_area(&fact(START)), stack(RW).mappings);
    // The guard zone ends glibc's stack: on Linux the stack then reaches
    // only down to the zone.
    let guarded = native.stacks[&GUARDED];
    assert_eq!(
        guarded.top - guarded.size,
        stack_area(&fact(GUARDED))[1].end
    );
    assert!(guarded.size < native.stacks[&START].size);
    assert_eq!(kvm.results[&MLOCKED], (-1, libc::ENOSYS));
    assert!(!native.results.contains_key(&MLOCKED), "{native:?}");
    // The guest's own read on KVM is the executor's one synthetic line
    // today, the same range and protection as the stack as it started.
    assert_eq!(
        kvm.reads[&START],
        Ok(format!("{WINDOW_START:012x}-{TOP:012x} rw-p 00000000 00:00 0 [stack]\n").into_bytes())
    );

    // Refused: a call Linux applies and the backend refuses leaves the
    // backend's list as it was. MADV_DONTFORK (ENOSYS), where Linux splits
    // the stack in three; a MAP_FIXED mapping where a page was unmapped
    // (ENOMEM), where Linux maps a third line in the hole.
    assert_eq!(stack_area(&fact(REFUSED_HINT)), stack(RW).mappings);
    assert_eq!(kvm.results[&REFUSED_HINT], (-1, libc::ENOSYS));
    assert_eq!(native.results[&REFUSED_HINT], (0, 0));
    assert_eq!(stack_area(&native.map(REFUSED_HINT)).len(), 3);
    assert_eq!(fact(REMAPPED), fact(UNMAPPED));
    assert_eq!(kvm.results[&REMAPPED], (-1, libc::ENOMEM));
    assert_eq!(native.results[&REMAPPED], (0, 0));
    assert_eq!(stack_area(&native.map(REMAPPED)).len(), 3);

    // A child sharing the address space, made with vfork, with clone and
    // with clone3, stored into a page of the stack: its parent sees the
    // store once the child exited, and the map as it was.
    for point in [VFORKED, CLONED, CLONED3] {
        assert_window(point, &fact(point), &native.map(point));
        assert_eq!(kvm.results[&point], (0, 0), "point {point}");
        assert_eq!(native.results[&point], (0, 0), "point {point}");
    }

    // Unknown: nothing is listed where the backend's pages do not hold what
    // Linux did. An mprotect of the top page and the page past it, which
    // fails on both with ENOMEM after Linux protected the top page (two
    // lines); in a vfork child, around the page a sibling thread of its
    // parent made executable (three lines).
    for (point, linux_parts) in [(PARTIAL, 2), (VFORK_SEES, 3)] {
        assert_eq!(
            fact(point),
            MemoryMap::new(Vec::new(), false).unwrap(),
            "point {point}"
        );
        assert_eq!(
            stack_area(&native.map(point)).len(),
            linux_parts,
            "point {point}: {:?}",
            native.map(point)
        );
    }
    assert_eq!(kvm.results[&PARTIAL], (-1, libc::ENOMEM));
    assert_eq!(native.results[&PARTIAL], (-1, libc::ENOMEM));
    // The vfork child asked about itself; the posix_spawn child's image did.
    for point in [VFORK_SEES, VFORK_AFTER, SPAWNED] {
        assert_ne!(kvm.tids[&point], kvm.tids[&START], "point {point}");
        assert_ne!(native.tids[&point], native.tids[&START], "point {point}");
    }

    // Another process's address space is its own, as the run recorded it:
    // the child's window is Linux's child's; no task has the last number
    // (natively the child's map is readable, and the number's is not).
    assert_window(CHILD, &fact(CHILD), &native.map(CHILD));
    assert!(native.reads[&CHILD].is_ok());
    assert_eq!(facts[&NO_TASK], Err(FactError::Errno(Errno::ESRCH)));
    assert_eq!(native.reads[&NO_TASK], Err(libc::ENOENT));
}

/// A child sharing the address space (vfork, and clone or clone3 with
/// CLONE_VM|CLONE_VFORK) protects a page of the stack, executable as well,
/// and exits. On Linux the change is its parent's: the parent's stack is
/// split around that page. The child runs on a copy here, which carries back
/// contents, not mappings, so a mapping change still in place when the
/// child's window ends is refused by name, for each of the three, rather
/// than lost.
#[test]
fn a_child_sharing_the_address_space_cannot_leave_the_stack_protected() {
    Kvm::new().expect("memory map test requires usable /dev/kvm");
    let directory = Directory::new();
    let executable = compile(&directory, "memory_map", MEMORY_MAP_C, &[]);
    for (family, point) in [("vfork", VFORKED), ("clone", CLONED), ("clone3", CLONED3)] {
        let run = std::process::Command::new(&executable)
            .args(["native", "protect", family])
            .env_clear()
            .output()
            .unwrap();
        assert!(run.status.success(), "{family} native: {run:?}");
        assert_eq!(
            String::from_utf8_lossy(&run.stdout),
            format!("protected {point}\n"),
            "{family} native"
        );
        let argv = [executable.to_str().unwrap(), "tool", "protect", family];
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &argv,
                &[],
                &directory.0,
            )
            .unwrap();
        let error = match futures::executor::block_on(
            backend.run_static_elf_with_tool::<FactTool>((), true),
        ) {
            Ok((_, code, stdout, stderr)) => panic!(
                "{family}: expected the refusal, got code={code} stdout={stdout:?} \
                 stderr={stderr:?}"
            ),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(
                "unsupported KVM vfork child operation vfork write-back: the vfork child left \
                 a mapping changed"
            ),
            "{family}: {error:?}"
        );
    }
}

/// An image whose `PT_GNU_STACK` header has `PF_X`: Linux maps its stack
/// executable, and the entry says so.
#[test]
fn a_kvm_guest_with_an_executable_stack_reports_it() {
    Kvm::new().expect("memory map test requires usable /dev/kvm");
    let directory = Directory::new();
    let executable = compile(
        &directory,
        "memory_map_execstack",
        MEMORY_MAP_C,
        &["-z", "execstack"],
    );
    let native = native(&executable, &["native", "start"]);
    let (kvm, facts) = kvm(&directory, &executable, &["tool", "start"]);
    assert_eq!(kvm.asked, [START]);
    let started = facts[&START].as_ref().unwrap();
    assert_eq!(stack_area(started), stack(RWX).mappings);
    assert_window(START, started, &native.map(START));
}

/// A program that keeps a guard zone on its main thread's stack, as a JVM
/// does (`fixtures/guard_zone.c`), run with a 32 KiB argument: before the
/// zone, with it, after running down to it, and after removing it, the
/// listed mappings are Linux's, and glibc's answer for the main thread's
/// stack computed from them is Linux's, which with the zone ends at the
/// zone. So in a child forked with the zone, which removes its copy of the
/// zone: on Linux the zone stays a mapping of its own there, each mapping
/// the child inherited having an anon_vma of its own, and glibc still ends
/// the child's stack at it; and in the parent once it removes its own zone,
/// which merges again.
///
/// Then at the stack's rlimit: at a limit of one page, less than the
/// arguments above the stack's first page (glibc's subtraction wraps), at
/// 256 MiB, more than the distance to the mapping below, and with no limit,
/// natively the stack ends at the mapping below it, and so it does from the
/// list, which lists the mappings below the window as Linux lists them below
/// the stack. (Before the list held every mapping, it had no line before
/// `[stack]` there, and glibc's answer from it was larger than Linux's.)
#[test]
fn a_kvm_guest_with_a_guard_zone_on_its_stack_reads_it_as_linux_does() {
    const BEFORE: u64 = 1;
    const GUARDED: u64 = 2;
    const USED: u64 = 3;
    const UNGUARDED: u64 = 4;
    const CHILD_UNGUARDED: u64 = 5;
    const PARENT_UNGUARDED: u64 = 6;
    const LOWERED: u64 = 7;
    const RAISED: u64 = 8;
    const UNLIMITED: u64 = 9;
    const UNLIMITED_GUARDED: u64 = 10;
    const AGREEING: [u64; 7] = [
        BEFORE,
        GUARDED,
        USED,
        UNGUARDED,
        CHILD_UNGUARDED,
        PARENT_UNGUARDED,
        UNLIMITED_GUARDED,
    ];
    Kvm::new().expect("memory map test requires usable /dev/kvm");
    let directory = Directory::new();
    let executable = compile(
        &directory,
        "guard_zone",
        include_str!("fixtures/guard_zone.c"),
        &[],
    );
    let argument = "x".repeat(32 * 1024);
    let native = native(&executable, &["native", &argument]);
    let (kvm, facts) = kvm(&directory, &executable, &["tool", &argument]);
    assert_eq!(kvm.asked, (BEFORE..=UNLIMITED_GUARDED).collect::<Vec<_>>());
    for step in AGREEING {
        let fact = facts[&step].as_ref().unwrap();
        assert_window(step, fact, &native.map(step));
        assert_main_stack(step, fact, &native, &kvm);
    }
    assert_eq!(native.stacks[&BEFORE].limit, 8 << 20);
    assert_eq!(native.stacks[&LOWERED].limit, 4096);
    assert_eq!(native.stacks[&RAISED].limit, 256 << 20);
    assert_eq!(
        native.stacks[&UNLIMITED].limit,
        u64::MAX,
        "the unlimited step needs an unlimited hard RLIMIT_STACK"
    );
    for step in [LOWERED, RAISED, UNLIMITED] {
        let fact = facts[&step].as_ref().unwrap();
        assert_window(step, fact, &native.map(step));
        let linux = native.stacks[&step];
        assert_eq!(linux.ret, 0, "step {step}: {linux:?}");
        // The arguments above the stack's first page exceed one page.
        assert!(TOP - linux.top > 4096, "step {step}: {linux:?}");
        assert_eq!(
            glibc_main_stack(&native.map(step).mappings, linux.stack_end, linux.limit),
            Some((linux.top, linux.size)),
            "step {step}: the computation is glibc's"
        );
        // Natively the stack ends at the mapping below it, about 128 MiB
        // below its top.
        let below = native
            .map(step)
            .mappings
            .iter()
            .filter(|mapping| mapping.end <= WINDOW_START)
            .map(|mapping| mapping.end)
            .max()
            .unwrap();
        assert_eq!(linux.size, linux.top - below, "step {step}");
        // From the list, which has the mappings below the window as Linux's
        // has them below the stack, the same.
        let guest = kvm.stacks[&step];
        assert_eq!(
            glibc_main_stack(&fact.mappings, guest.stack_end, linux.limit),
            Some((linux.top, linux.size)),
            "step {step}: {fact:?}"
        );
    }
    let guarded = stack_area(facts[&GUARDED].as_ref().unwrap());
    assert_eq!(guarded.len(), 3);
    assert_eq!(guarded[1].prot, 0);
    for step in [GUARDED, USED] {
        let linux = native.stacks[&step];
        assert_eq!(linux.top - linux.size, guarded[1].end, "step {step}");
    }
    assert_eq!(native.stacks[&BEFORE].size, native.stacks[&UNGUARDED].size);
    assert!(native.stacks[&GUARDED].size < native.stacks[&BEFORE].size);
    // The child's zone, accessible again, is still a mapping of its own,
    // and the child's stack still ends at it; the parent's merges again.
    let child = stack_area(facts[&CHILD_UNGUARDED].as_ref().unwrap());
    assert_eq!(child.len(), 3);
    assert!(child.iter().all(|mapping| mapping.prot == RW));
    assert_eq!(
        native.stacks[&CHILD_UNGUARDED].size,
        native.stacks[&GUARDED].size
    );
    assert_ne!(kvm.tids[&CHILD_UNGUARDED], kvm.tids[&BEFORE]);
    assert_ne!(native.tids[&CHILD_UNGUARDED], native.tids[&BEFORE]);
    assert_eq!(
        stack_area(facts[&PARENT_UNGUARDED].as_ref().unwrap()),
        stack(RW).mappings
    );
    assert_eq!(
        native.stacks[&PARENT_UNGUARDED].size,
        native.stacks[&BEFORE].size
    );
}
