/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The LiteInst host runtime's constructor must leave the guest heap exactly
//! as a native run does at `main`, and its own constructor heap must survive a
//! guest with many executable mappings (https://github.com/rrnewton/reverie/issues/750).

use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Stdio;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_liteinst::LiteinstBackend;
use reverie_ptrace::TracerBuilder;

/// What every correct run of `host_heap_untouched.c` prints: the program break
/// has not moved and glibc's main arena and mmap accounting are empty.
const UNTOUCHED_HEAP: &str = "brk_delta=0 arena=0 mmapped=0\n";

/// Number of generated shared objects in the many-mapping test.  Each adds one
/// executable mapping and one syscall site that needs its own arena.
const HEAP_DSO_COUNT: usize = 24;

/// Upper bound on the constructor heap's high-water mark, in bytes, for the
/// many-mapping guest.  The peak live set is one 2 MiB maps buffer (liteinst2
/// reserves exactly 2,097,152 bytes per arena allocation and frees it), the
/// 196,608-byte site registry (a 256 KiB size-class block) and small objects.
/// A constructor heap that stopped reclaiming the per-mapping maps buffer
/// would need at least one 2 MiB block per executable mapping.
const INIT_HEAP_HIGH_WATER_CEILING: u64 = 4 << 20;

#[derive(Debug, Default)]
struct HeapSyscalls {
    brk: AtomicU64,
    getpid: AtomicU64,
}

const BRK_EVENT: u64 = 1;
const GETPID_EVENT: u64 = 2;

#[reverie::global_tool]
impl GlobalTool for HeapSyscalls {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, event: u64) {
        match event {
            BRK_EVENT => self.brk.fetch_add(1, Ordering::SeqCst),
            GETPID_EVENT => self.getpid.fetch_add(1, Ordering::SeqCst),
            other => panic!("unexpected heap syscall event {other}"),
        };
    }
}

/// Counts the brk and getpid syscalls delivered to the Tool, then injects them
/// unchanged.
#[derive(Default)]
struct CountHeapSyscalls;

#[reverie::tool]
impl Tool for CountHeapSyscalls {
    type GlobalState = HeapSyscalls;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::brk, Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let event = match syscall.number() {
            Sysno::brk => BRK_EVENT,
            Sysno::getpid => GETPID_EVENT,
            other => panic!("subscribed only to brk and getpid, got {other:?}"),
        };
        guest.send_rpc(event).await;
        Ok(guest.inject(syscall).await?)
    }
}

/// The preload DSO built with this test.  `deps/` comes first: `cargo test`
/// rebuilds the cdylib there, while the copy next to the binaries is refreshed
/// only by `cargo build` and can be a stale runtime from an earlier build.
fn preload_path() -> PathBuf {
    let launcher = PathBuf::from(env!("CARGO_BIN_EXE_reverie-liteinst-strace"));
    let target = launcher.parent().unwrap();
    [
        target.join("deps/libreverie_liteinst.so"),
        target.join("libreverie_liteinst.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build the LiteInst preload cdylib")
}

fn fixture_source(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run_compiler(arguments: &[OsString]) {
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(&compiler)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{compiler:?} {arguments:?} failed:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn compile_program(directory: &Path, name: &str, extra: &[OsString]) -> PathBuf {
    let output = directory.join(name.trim_end_matches(".c"));
    let mut arguments = ["-std=gnu11", "-O0", "-fno-pie", "-no-pie"]
        .map(OsString::from)
        .to_vec();
    arguments.push(fixture_source(name).into_os_string());
    arguments.extend_from_slice(extra);
    arguments.push("-o".into());
    arguments.push(output.clone().into_os_string());
    run_compiler(&arguments);
    output
}

/// Builds `HEAP_DSO_COUNT` copies of host_heap_dso.c and a program that is
/// linked against all of them.
fn compile_many_dso_program(directory: &Path) -> PathBuf {
    let mut link = vec![
        OsString::from(format!("-DHEAP_DSO_COUNT={HEAP_DSO_COUNT}")),
        OsString::from("-Wl,--no-as-needed"),
        OsString::from(format!("-L{}", directory.display())),
        OsString::from(format!("-Wl,-rpath,{}", directory.display())),
    ];
    for index in 0..HEAP_DSO_COUNT {
        let library = directory.join(format!("libhostheap{index}.so"));
        run_compiler(&[
            "-std=gnu11".into(),
            "-O0".into(),
            "-shared".into(),
            "-fPIC".into(),
            format!("-DHEAP_DSO_INDEX={index}").into(),
            fixture_source("host_heap_dso.c").into_os_string(),
            "-o".into(),
            library.into_os_string(),
        ]);
        link.push(format!("-lhostheap{index}").into());
    }
    link.push("-ldl".into());
    compile_program(directory, "host_heap_many_dsos.c", &link)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test(flavor = "current_thread")]
async fn host_constructor_leaves_guest_heap_uninitialised() {
    let directory = tempfile::tempdir().unwrap();
    let guest = compile_program(directory.path(), "host_heap_untouched.c", &[]);

    // Admission control 1: natively, nothing allocates before main.  If this
    // fails, the fixture or the host's C runtime is wrong, not LiteInst.
    let native = ProcessCommand::new(&guest).output().unwrap();
    assert!(native.status.success(), "native fixture failed: {native:?}");
    assert_eq!(
        text(&native.stdout),
        UNTOUCHED_HEAP,
        "admission control failed: the fixture does not see an untouched heap natively"
    );

    // Admission control 2: plain reverie-ptrace injects nothing into the guest.
    let mut command = Command::new(&guest);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let (ptrace_output, ptrace_counts) = tokio::time::timeout(Duration::from_secs(30), async {
        TracerBuilder::<CountHeapSyscalls>::new(command)
            .spawn()
            .await?
            .wait_with_output()
            .await
    })
    .await
    .expect("plain ptrace run timed out")
    .expect("plain ptrace run failed");
    assert!(
        ptrace_output.status.success(),
        "plain ptrace fixture failed: {ptrace_output:?}"
    );
    assert_eq!(
        text(&ptrace_output.stdout),
        UNTOUCHED_HEAP,
        "admission control failed: the fixture does not see an untouched heap under plain ptrace"
    );

    // The LiteInst host runtime's preload constructor has run before main.
    let (output, counts) = tokio::time::timeout(
        Duration::from_secs(30),
        LiteinstBackend::run_host_with_output_and_preload::<CountHeapSyscalls>(
            Command::new(&guest),
            (),
            preload_path(),
        ),
    )
    .await
    .expect("LiteInst host run timed out")
    .expect("LiteInst host run failed");
    assert_eq!(
        text(&output.stdout),
        UNTOUCHED_HEAP,
        "the LiteInst constructor touched the guest heap before main: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");

    // The guest's own brk calls (the fixture's probe and stdio's first
    // allocation after it) reach the Tool exactly as under plain ptrace; the
    // constructor adds none of its own.
    eprintln!(
        "brk delivered: liteinst={} ptrace={}",
        counts.brk.load(Ordering::SeqCst),
        ptrace_counts.brk.load(Ordering::SeqCst)
    );
    assert_eq!(
        counts.brk.load(Ordering::SeqCst),
        ptrace_counts.brk.load(Ordering::SeqCst),
        "brk syscalls delivered to the Tool differ from plain ptrace: {output:?}"
    );
}

fn field(line: &str, key: &str) -> u64 {
    line.split_whitespace()
        .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("missing {key}= in {line:?}"))
        .parse()
        .unwrap_or_else(|error| panic!("bad {key}= in {line:?}: {error}"))
}

#[tokio::test(flavor = "current_thread")]
async fn host_constructor_heap_serves_many_executable_mappings() {
    let directory = tempfile::tempdir().unwrap();
    let guest = compile_many_dso_program(directory.path());

    let (output, counts) = tokio::time::timeout(
        Duration::from_secs(60),
        LiteinstBackend::run_host_with_output_and_preload::<CountHeapSyscalls>(
            Command::new(&guest),
            (),
            preload_path(),
        ),
    )
    .await
    .expect("LiteInst host run timed out")
    .expect("LiteInst host run failed");
    assert!(output.status.success(), "{output:?}");
    let stdout = text(&output.stdout);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "{output:?}");
    eprintln!("{stdout}");

    // Every generated object's site took one discovery trap and was then
    // hooked, which needs a trampoline arena near that object's mapping.  An
    // arena the constructor failed to allocate leaves its site trapping.
    let count = HEAP_DSO_COUNT;
    assert_eq!(
        lines[0],
        format!(
            "dsos={count} calls={} traps={count} hooks={} dsos_hooked={count}",
            4 * count,
            3 * count
        ),
        "{output:?}"
    );
    assert_eq!(
        counts.getpid.load(Ordering::SeqCst),
        4 * count as u64,
        "{output:?}"
    );

    // One arena per eligible executable mapping, none dropped.  [vsyscall]
    // is excluded by the fixture: no arena can be placed near it.  The
    // fixture counts contiguous executable VMAs of one file once, because
    // patching splits libc's text after the constructor has run.
    let exec_mappings = field(lines[1], "exec_mappings");
    let trampoline_arenas = field(lines[1], "trampoline_arenas");
    assert!(
        exec_mappings >= count as u64 + 3,
        "the generated objects, the program, libc and the loader must all be mapped: {output:?}"
    );
    assert_eq!(
        trampoline_arenas, exec_mappings,
        "the constructor dropped trampoline arenas: {output:?}"
    );

    let high_water = field(lines[2], "init_heap_high_water");
    assert!(
        high_water > 0 && high_water <= INIT_HEAP_HIGH_WATER_CEILING,
        "constructor heap high-water mark {high_water} outside (0, {INIT_HEAP_HIGH_WATER_CEILING}]: {output:?}"
    );
}
