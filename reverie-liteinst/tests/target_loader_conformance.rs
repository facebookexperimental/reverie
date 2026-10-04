/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Native conformance for resolving the real release LiteInst runtime.
//!
//! This deliberately refuses Cargo's implicit debug cdylib. Run it through
//! `tests/run_target_loader_conformance.sh`, which binds the canonical path and
//! SHA-256 of a freshly built release/no-default-feature artifact.

#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::ChildStderr;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use reverie_ptrace::target_loader::TargetHostInitializer;
use reverie_ptrace::target_loader::resolve_host_initializer;
use safeptrace::Event;
use safeptrace::Options;
use safeptrace::Pid;
use safeptrace::Signal;
use safeptrace::Wait;
use sha2::Digest;
use sha2::Sha256;

const MAX_RUNTIME_FILE: usize = 64 * 1024 * 1024;
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    major: u64,
    minor: u64,
    inode: u64,
    length: u64,
}

impl FileIdentity {
    fn read(path: &Path) -> Self {
        let metadata = path.metadata().expect("stat bound runtime");
        assert!(metadata.is_file(), "bound runtime is not a regular file");
        Self {
            major: libc::major(metadata.dev()) as u64,
            minor: libc::minor(metadata.dev()) as u64,
            inode: metadata.ino(),
            length: metadata.len(),
        }
    }

    fn resolver_tuple(self) -> (u64, u64, u64) {
        (self.major, self.minor, self.inode)
    }
}

struct Artifact {
    path: PathBuf,
    bytes: Vec<u8>,
    digest: String,
    identity: FileIdentity,
}

impl Artifact {
    fn bound() -> Self {
        let supplied = PathBuf::from(
            std::env::var_os("REVERIE_LITEINST_CONFORMANCE_DSO")
                .expect("run tests/run_target_loader_conformance.sh: missing DSO path"),
        );
        assert!(supplied.is_absolute(), "DSO path must be absolute");
        let path = supplied.canonicalize().expect("canonicalize bound runtime");
        assert_eq!(supplied, path, "DSO path itself must already be canonical");

        let digest = std::env::var("REVERIE_LITEINST_CONFORMANCE_SHA256")
            .expect("run tests/run_target_loader_conformance.sh: missing DSO SHA-256");
        assert_eq!(
            digest.len(),
            64,
            "SHA-256 must contain exactly 64 hex digits"
        );
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "SHA-256 must be lowercase hexadecimal"
        );

        let bytes = fs::read(&path).expect("read bound runtime");
        assert!(
            !bytes.is_empty() && bytes.len() <= MAX_RUNTIME_FILE,
            "release runtime must be nonempty and at most 64 MiB"
        );
        assert_eq!(sha256(&bytes), digest, "bound runtime SHA-256 changed");
        let identity = FileIdentity::read(&path);
        assert_eq!(identity.length, bytes.len() as u64);
        Self {
            path,
            bytes,
            digest,
            identity,
        }
    }

    fn assert_unchanged(&self) {
        assert_eq!(FileIdentity::read(&self.path), self.identity);
        let current = fs::read(&self.path).expect("re-read bound runtime");
        assert_eq!(sha256(&current), self.digest);
        assert_eq!(current, self.bytes, "bound runtime bytes changed");
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug)]
struct NativeReport {
    symbol: u64,
    dlinfo_map: u64,
    dlinfo_addr: u64,
    dlinfo_ld: u64,
    iterate_addr: u64,
    iterate_matches: u64,
    dladdr_map: u64,
    dladdr_addr: u64,
    dladdr_ld: u64,
    dladdr_fbase: u64,
    dladdr_symbol: u64,
    at_phdr: u64,
    stat_major: u64,
    stat_minor: u64,
    stat_inode: u64,
    map_major: u64,
    map_minor: u64,
    map_inode: u64,
    namespace: u64,
}

impl NativeReport {
    fn parse(line: &str) -> Self {
        let mut fields = BTreeMap::new();
        for field in line.split_ascii_whitespace() {
            let (name, value) = field.split_once('=').expect("malformed report field");
            assert!(
                fields.insert(name, value).is_none(),
                "duplicate report field {name}"
            );
        }
        let mut take = |name| {
            u64::from_str_radix(fields.remove(name).expect("missing report field"), 16)
                .expect("non-hexadecimal report field")
        };
        let report = Self {
            symbol: take("symbol"),
            dlinfo_map: take("dlinfo_map"),
            dlinfo_addr: take("dlinfo_addr"),
            dlinfo_ld: take("dlinfo_ld"),
            iterate_addr: take("iterate_addr"),
            iterate_matches: take("iterate_matches"),
            dladdr_map: take("dladdr_map"),
            dladdr_addr: take("dladdr_addr"),
            dladdr_ld: take("dladdr_ld"),
            dladdr_fbase: take("dladdr_fbase"),
            dladdr_symbol: take("dladdr_symbol"),
            at_phdr: take("at_phdr"),
            stat_major: take("dev_major"),
            stat_minor: take("dev_minor"),
            stat_inode: take("stat_inode"),
            map_major: take("map_major"),
            map_minor: take("map_minor"),
            map_inode: take("map_inode"),
            namespace: take("namespace"),
        };
        assert!(fields.is_empty(), "unexpected report fields: {fields:?}");
        report
    }
}

#[derive(Debug)]
struct RuntimeLayout {
    dynamic_vaddr: u64,
    symbol_file_offset: usize,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn runtime_layout(bytes: &[u8], report: &NativeReport) -> RuntimeLayout {
    assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(u16_at(bytes, 16), 3, "runtime must be ET_DYN");
    let phoff = usize::try_from(u64_at(bytes, 32)).expect("program-header offset overflow");
    assert_eq!(u16_at(bytes, 54), 56);
    let phnum = usize::from(u16_at(bytes, 56));
    let symbol_vaddr = report
        .symbol
        .checked_sub(report.dlinfo_addr)
        .expect("native symbol precedes load bias");
    let mut dynamic_vaddr = None;
    let mut symbol_file_offset = None;

    for index in 0..phnum {
        let at = phoff
            .checked_add(index * 56)
            .expect("program-header overflow");
        assert!(at + 56 <= bytes.len(), "truncated program-header table");
        let kind = u32_at(bytes, at);
        let flags = u32_at(bytes, at + 4);
        let offset = u64_at(bytes, at + 8);
        let vaddr = u64_at(bytes, at + 16);
        let filesz = u64_at(bytes, at + 32);
        if kind == 2 {
            assert!(
                dynamic_vaddr.replace(vaddr).is_none(),
                "multiple PT_DYNAMIC"
            );
        }
        if kind == 1 && symbol_vaddr >= vaddr && symbol_vaddr < vaddr + filesz {
            assert_eq!(flags & 7, 5, "initializer must be in exact R-X bytes");
            let file_offset = offset + (symbol_vaddr - vaddr);
            let file_offset = usize::try_from(file_offset).expect("symbol offset overflow");
            assert!(
                file_offset < bytes.len(),
                "initializer outside runtime file"
            );
            assert!(
                symbol_file_offset.replace(file_offset).is_none(),
                "initializer occurs in overlapping PT_LOADs"
            );
        }
    }

    RuntimeLayout {
        dynamic_vaddr: dynamic_vaddr.expect("missing PT_DYNAMIC"),
        symbol_file_offset: symbol_file_offset.expect("initializer outside PT_LOAD"),
    }
}

fn compile_fixture(directory: &Path) -> PathBuf {
    let fixture = directory.join("target-loader-conformance");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/target_loader_conformance.c");
    let compiler: OsString = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = Command::new(compiler)
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
        ])
        .arg(source)
        .arg("-ldl")
        .arg("-o")
        .arg(&fixture)
        .output()
        .expect("run C compiler");
    assert!(
        output.status.success(),
        "compile native fixture: status={:?}, stdout={:?}, stderr={:?}",
        output.status,
        output.stdout,
        output.stderr
    );
    fixture
}

struct Cleanup {
    pid: libc::pid_t,
    reaped: bool,
}

impl Cleanup {
    fn disarm(&mut self) {
        self.reaped = true;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let mut status = 0;
            let result =
                unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) };
            if result == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.reaped = true;
                return;
            }
            if result == self.pid {
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
                continue;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                self.reaped = true;
                return;
            }
            if result == -1 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        eprintln!("timed out reaping failed tracee {}", self.pid);
    }
}

fn wait_bounded(pid: libc::pid_t) -> io::Result<i32> {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        let mut status = 0;
        let result = unsafe {
            libc::waitpid(
                pid,
                &mut status,
                libc::WNOHANG | libc::WUNTRACED | libc::__WALL,
            )
        };
        if result == pid {
            return Ok(status);
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tracee wait timed out",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn reap_bounded(child: &mut std::process::Child) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tracee reap timed out",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn read_failure(stderr: &mut ChildStderr) -> String {
    let mut bytes = Vec::new();
    stderr.read_to_end(&mut bytes).expect("read fixture stderr");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn start_ticks_and_state(pid: libc::pid_t) -> (u64, u8) {
    let stat = fs::read(format!("/proc/{pid}/stat")).expect("read tracee stat");
    let close = stat
        .windows(2)
        .rposition(|bytes| bytes == b") ")
        .expect("malformed tracee stat");
    let fields: Vec<_> = stat[close + 2..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    assert!(fields.len() > 19, "truncated tracee stat");
    let ticks = std::str::from_utf8(fields[19])
        .unwrap()
        .parse()
        .expect("malformed start ticks");
    (ticks, fields[0][0])
}

fn assert_single_stopped_task(pid: libc::pid_t) {
    let tasks: Vec<_> = fs::read_dir(format!("/proc/{pid}/task"))
        .expect("read tracee tasks")
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(tasks, [OsString::from(pid.to_string())]);
    assert_eq!(
        start_ticks_and_state(pid).1,
        b't',
        "tracee must remain in a ptrace stop"
    );
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) },
        0,
        "tracee produced an unexpected wait event"
    );
}

fn register_words(regs: &safeptrace::Regs) -> [u64; 27] {
    [
        regs.r15,
        regs.r14,
        regs.r13,
        regs.r12,
        regs.rbp,
        regs.rbx,
        regs.r11,
        regs.r10,
        regs.r9,
        regs.r8,
        regs.rax,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.orig_rax,
        regs.rip,
        regs.cs,
        regs.eflags,
        regs.rsp,
        regs.ss,
        regs.fs_base,
        regs.gs_base,
        regs.ds,
        regs.es,
        regs.fs,
        regs.gs,
    ]
}

fn verify_native_report(
    report: &NativeReport,
    artifact: &Artifact,
    base_namespace: bool,
) -> RuntimeLayout {
    assert_ne!(report.symbol, 0);
    assert_ne!(report.dlinfo_map, 0);
    assert_eq!(report.dlinfo_map, report.dladdr_map);
    assert_eq!(report.dlinfo_addr, report.dladdr_addr);
    assert_eq!(report.dlinfo_ld, report.dladdr_ld);
    assert_eq!(report.dlinfo_addr, report.dladdr_fbase);
    assert_eq!(report.symbol, report.dladdr_symbol);
    assert_ne!(report.at_phdr, 0);
    assert_eq!(
        (report.stat_major, report.stat_minor, report.stat_inode),
        artifact.identity.resolver_tuple()
    );
    assert_eq!(report.map_inode, report.stat_inode);
    if base_namespace {
        assert_eq!(report.namespace, 0);
        assert_eq!(report.iterate_matches, 1);
        assert_eq!(report.iterate_addr, report.dlinfo_addr);
    } else {
        assert_ne!(report.namespace, 0);
        // This call originates in the base namespace; dl_iterate_phdr must not
        // report a runtime loaded only in the new dlmopen namespace.
        assert_eq!(report.iterate_matches, 0);
        assert_eq!(report.iterate_addr, 0);
    }

    let layout = runtime_layout(&artifact.bytes, report);
    assert_eq!(
        report.dlinfo_ld,
        report
            .dlinfo_addr
            .checked_add(layout.dynamic_vaddr)
            .expect("native dynamic address overflow")
    );
    layout
}

fn compare_resolved(
    resolved: &TargetHostInitializer,
    report: &NativeReport,
    pid: libc::pid_t,
    start_ticks: u64,
) {
    assert_eq!(resolved.tid, pid);
    assert_eq!(resolved.start_ticks, start_ticks);
    assert_eq!(resolved.executable_phdr, report.at_phdr);
    assert_eq!(resolved.link_map, report.dlinfo_map);
    assert_eq!(resolved.load_bias, report.dlinfo_addr);
    assert_eq!(resolved.address, report.symbol);
    assert_eq!(
        resolved.mapping_identity,
        (report.map_major, report.map_minor, report.map_inode)
    );
}

fn assert_absent_from_default_namespace(error: io::Error) {
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "expected provider is absent from default link map"
    );
}

fn run_stopped_fixture(fixture: &Path, artifact: &Artifact, mode: &str, expect_resolution: bool) {
    let mut child = Command::new(fixture)
        .arg(mode)
        .arg(&artifact.path)
        .env_remove("LD_AUDIT")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .env_remove("GLIBC_TUNABLES")
        .env_remove("REVERIE_LITEINST_HOST_RUNTIME")
        .env_remove("REVERIE_LITEINST_TOOL")
        .env_remove("REVERIE_PRELOAD_TOOL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("exec native fixture");
    let pid = i32::try_from(child.id()).expect("child PID overflow");
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let mut cleanup = Cleanup { pid, reaped: false };

    let status = wait_bounded(pid).expect("wait for fixture stop");
    if !libc::WIFSTOPPED(status) {
        cleanup.disarm();
        panic!(
            "fixture exited before ptrace stop: status={status:#x}, stderr={:?}",
            read_failure(&mut stderr)
        );
    }
    let (stopped, event) = Wait::from_raw(Pid::from_raw(pid), status)
        .expect("decode fixture stop")
        .assume_stopped();
    assert_eq!(event, Event::Signal(Signal::SIGSTOP));
    stopped
        .setoptions(Options::PTRACE_O_EXITKILL)
        .expect("set EXITKILL");

    let mut line = String::new();
    stdout.read_line(&mut line).expect("read native report");
    assert!(line.ends_with('\n'), "unterminated native report");
    let report = NativeReport::parse(&line);
    let layout = verify_native_report(&report, artifact, mode == "base");
    let (start_ticks, _) = start_ticks_and_state(pid);
    assert_single_stopped_task(pid);
    artifact.assert_unchanged();

    let registers = register_words(&stopped.getregs().expect("read initial registers"));
    let result = resolve_host_initializer(&stopped, &artifact.bytes);
    assert_eq!(
        register_words(&stopped.getregs().expect("read post-resolution registers")),
        registers,
        "resolver changed target registers"
    );
    assert_single_stopped_task(pid);
    if expect_resolution {
        compare_resolved(
            &result.expect("resolve real runtime"),
            &report,
            pid,
            start_ticks,
        );

        let mut changed = artifact.bytes.clone();
        changed[layout.symbol_file_offset] ^= 1;
        assert_absent_from_default_namespace(
            resolve_host_initializer(&stopped, &changed)
                .expect_err("resolver accepted changed non-writable initializer bytes"),
        );
        assert_eq!(
            register_words(&stopped.getregs().expect("read post-refusal registers")),
            registers,
            "refusal changed target registers"
        );
        assert_single_stopped_task(pid);
    } else {
        assert_absent_from_default_namespace(
            result.expect_err("resolver accepted a runtime outside the default namespace"),
        );
    }
    artifact.assert_unchanged();

    let running = stopped.resume(None).expect("resume fixture exactly once");
    let terminal = reap_bounded(&mut child).expect("bounded fixture reap");
    drop(running);
    cleanup.disarm();
    assert_eq!(terminal.code(), Some(0));

    let mut remainder = String::new();
    stdout
        .read_to_string(&mut remainder)
        .expect("read fixture completion");
    assert_eq!(remainder, "resumed\n");
    assert_eq!(read_failure(&mut stderr), "");
    artifact.assert_unchanged();
}

#[cfg(debug_assertions)]
fn require_release_profile() {
    panic!("target-loader conformance must use Cargo's release profile");
}

#[cfg(not(debug_assertions))]
fn require_release_profile() {}

#[cfg(feature = "preload-constructor")]
fn require_disabled_preload_constructor() {
    panic!("target-loader conformance requires the preload constructor to be disabled");
}

#[cfg(not(feature = "preload-constructor"))]
fn require_disabled_preload_constructor() {}

#[test]
#[ignore = "requires an explicitly bound release/no-default-feature cdylib"]
fn real_release_runtime_matches_native_loader_oracles_while_stopped() {
    require_release_profile();
    require_disabled_preload_constructor();
    let artifact = Artifact::bound();
    let directory = tempfile::tempdir().unwrap();
    let fixture = compile_fixture(directory.path());

    run_stopped_fixture(&fixture, &artifact, "base", true);
    run_stopped_fixture(&fixture, &artifact, "new", false);
}
