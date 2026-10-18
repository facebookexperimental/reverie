/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real-exec CPUID entry and fail-closed arming tests. The literal-entry
//! sentinel is the same source and linker script used by the loader tests.
//! The entry test alone is not expected to distinguish a synthetic step trap
//! from a checked exec-return boundary; errno denials cover fail-open arming.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use reverie::BackendFailure;
use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Stdio;
use reverie_ptrace::PtraceRunFailure;
use reverie_ptrace::ToolRunOutcome;
use reverie_ptrace::TracerBuilder;
use reverie_ptrace::testing::run_tokio_test;

const CONTROL_EAX: u32 = 0x4000_00ff;
const CONTROL_ECX: u32 = 0x2a;
const REPLY: [u32; 4] = [0xa1b2_c3d4, 0x1526_3748, 0x90ab_cdef, 0x7654_3210];
const MARKER: &[u8] = b"FIRST_CPUID_OK\n";
const TIMEOUT: Duration = Duration::from_secs(30);
const ARCH_GET_CPUID: u32 = 0x1011;
const ARCH_SET_CPUID: u32 = 0x1012;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "reverie-ptrace-first-cpuid-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("create private CPUID fixture directory");
        Self(directory)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove this test's private fixture directory");
    }
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn compile(directory: &Path, source: &Path, name: &str) -> PathBuf {
    let output = directory.join(name);
    let stdout_path = directory.join(format!("{name}.rustc.stdout"));
    let stderr_path = directory.join(format!("{name}.rustc.stderr"));
    let linker = root().join("reverie-loader/tests/fixtures/guest_static.ld");
    let mut child =
        std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args([
                "--edition=2024",
                "--crate-type=bin",
                "-O",
                "-C",
                "panic=abort",
                "-C",
                "relocation-model=static",
                "-C",
                "code-model=large",
                "-C",
                "no-redzone=yes",
                "-C",
                "link-arg=-nostartfiles",
                "-C",
                "link-arg=-nostdlib",
                "-C",
                "link-arg=-static",
                "-C",
                "link-arg=-Wl,--build-id=none",
                "-C",
            ])
            .arg(format!("link-arg=-T{}", linker.display()))
            .arg("-o")
            .arg(&output)
            .arg(source)
            .stdout(File::create(stdout_path).unwrap())
            .stderr(File::create(&stderr_path).unwrap())
            .spawn()
            .expect("compile a standalone no_std CPUID test fixture");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(120) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CPUID fixture compiler exceeded 120 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "CPUID fixture compilation failed: {}",
        fs::read_to_string(stderr_path).unwrap()
    );
    output
}

struct Fixture {
    _scratch: Scratch,
    image: PathBuf,
    replacement_launcher: PathBuf,
    cpuid_ip: u64,
}

fn fixture(first_instruction: bool) -> Fixture {
    let scratch = Scratch::new();
    let landed_source = root().join("reverie-loader/tests/fixtures/guest_cpuid.rs");
    let source = if first_instruction {
        // Compile the exact landed sentinel, without another checked-in copy.
        landed_source
    } else {
        let original = fs::read_to_string(landed_source).unwrap();
        assert_eq!(original.matches("    cpuid\n").count(), 1);
        let control = original.replacen(
            "    cpuid\n",
            "    nop\n    mov eax, 0x400000ff\n    mov ecx, 0x2a\n    cpuid\n",
            1,
        );
        let source = scratch.0.join("guest_cpuid_control.rs");
        fs::write(&source, control).unwrap();
        source
    };
    let image = compile(&scratch.0, &source, "guest_cpuid");
    let replacement_launcher = compile(
        &scratch.0,
        &root().join("tests/fixtures/ptrace-first-cpuid/exec_with_cpuid_filter.rs"),
        "exec_with_cpuid_filter",
    );
    let bytes = fs::read(&image).unwrap();
    assert_eq!(&bytes[..8], b"\x7fELF\x02\x01\x01\x00");
    let u16_at = |at| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    let u64_at = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    assert_eq!(u16_at(16), 2, "sentinel must be ET_EXEC");
    assert_eq!(u16_at(18), 62, "sentinel must be EM_X86_64");
    let entry = u64_at(24);
    let phoff = usize::try_from(u64_at(32)).unwrap();
    let phsize = usize::from(u16_at(54));
    assert_eq!(phsize, 56);
    let mut entry_offset = None;
    for index in 0..usize::from(u16_at(56)) {
        let at = phoff + phsize * index;
        let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_ne!(kind, 3, "sentinel must have no PT_INTERP");
        let flags = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
        let address = u64_at(at + 16);
        let file_bytes = u64_at(at + 32);
        if kind == 1 && flags & 1 != 0 && entry >= address && entry < address + file_bytes {
            entry_offset = Some(usize::try_from(u64_at(at + 8) + entry - address).unwrap());
        }
    }
    let offset = entry_offset.expect("ELF entry must be in a file-backed executable PT_LOAD");
    let cpuid_ip = if first_instruction {
        assert_eq!(&bytes[offset..offset + 2], [0x0f, 0xa2]);
        entry
    } else {
        let mut prefix = vec![0x90, 0xb8]; // NOP; MOV EAX, leaf; MOV ECX, subleaf.
        prefix.extend(CONTROL_EAX.to_le_bytes());
        prefix.push(0xb9);
        prefix.extend(CONTROL_ECX.to_le_bytes());
        assert_eq!(&bytes[offset..offset + prefix.len()], prefix);
        assert_eq!(
            &bytes[offset + prefix.len()..offset + prefix.len() + 2],
            [0x0f, 0xa2]
        );
        entry + prefix.len() as u64
    };
    Fixture {
        _scratch: scratch,
        image,
        replacement_launcher,
        cpuid_ip,
    }
}

fn memfd() -> File {
    // SAFETY: the name is NUL-terminated; a successful creation transfers one fd.
    let fd = unsafe { libc::memfd_create(c"ptrace-cpuid-test".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create: {}", Errno::last());
    // SAFETY: this newly created descriptor has exactly one owner.
    unsafe { File::from_raw_fd(fd) }
}

fn contents(file: &mut File) -> Vec<u8> {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

/// Host-owned evidence survives either spawn or wait refusal.
#[derive(Default)]
struct CallbackLog(i32);

#[reverie::global_tool]
impl GlobalTool for CallbackLog {
    type Config = (i32, bool);
    type Request = (u64, u32, u32);
    type Response = ();

    async fn init_global_state(config: &Self::Config) -> Self {
        Self(config.0)
    }

    async fn receive_rpc(&self, _from: Pid, (ip, eax, ecx): Self::Request) {
        let mut record = [0; 16];
        record[..8].copy_from_slice(&ip.to_le_bytes());
        record[8..12].copy_from_slice(&eax.to_le_bytes());
        record[12..].copy_from_slice(&ecx.to_le_bytes());
        // SAFETY: the test owns this writable fd until all tracer work ends.
        assert_eq!(
            unsafe { libc::write(self.0, record.as_ptr().cast(), record.len()) },
            16
        );
    }
}

#[derive(Default)]
struct CpuidTool;

#[reverie::tool]
impl Tool for CpuidTool {
    type GlobalState = CallbackLog;
    type ThreadState = ();

    fn subscriptions(config: &(i32, bool)) -> Subscription {
        let mut events = Subscription::none();
        if config.1 {
            events.cpuid();
        }
        events
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<raw_cpuid::CpuIdResult, Errno> {
        let ip = guest.regs().await.rip;
        guest.send_rpc((ip, eax, ecx)).await;
        Ok(raw_cpuid::CpuIdResult {
            eax: REPLY[0],
            ebx: REPLY[1],
            ecx: REPLY[2],
            edx: REPLY[3],
        })
    }
}

#[derive(Clone, Copy)]
enum Deny {
    Get,
    Set,
}

impl Deny {
    fn command(self) -> u32 {
        match self {
            Self::Get => ARCH_GET_CPUID,
            Self::Set => ARCH_SET_CPUID,
        }
    }

    fn argument(self) -> &'static str {
        match self {
            Self::Get => "g",
            Self::Set => "s",
        }
    }

    fn operation(self) -> &'static str {
        match self {
            Self::Get => "initial-get",
            Self::Set => "set-disabled",
        }
    }
}

/// The exact same eight BPF instructions as the replacement-exec fixture.
/// Other arch_prctl requests, particularly FS/TLS setup, remain allowed.
fn denial_filter(deny: Deny) -> [libc::sock_filter; 8] {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    [
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 5, libc::SYS_arch_prctl as u32),
        instruction(0x20, 0, 0, 20),
        instruction(0x15, 0, 3, 0),
        instruction(0x20, 0, 0, 16),
        instruction(0x15, 0, 1, deny.command()),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

struct Identity {
    pid: libc::pid_t,
    pidfd: File,
}

impl Identity {
    fn assert_reaped(&self) {
        let mut event = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized, owned descriptor.
        assert_eq!(
            unsafe { libc::poll(&mut event, 1, 0) },
            1,
            "root pidfd is not terminal"
        );
        assert_ne!(event.revents & libc::POLLIN, 0);
        let mut status = 0;
        // SAFETY: this PID was acquired while its child was blocked before
        // TRACEME. The retained pidfd pins that same identity through cleanup.
        assert_eq!(
            unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG | libc::__WALL) },
            -1
        );
        assert_eq!(
            Errno::last(),
            Errno::ECHILD,
            "root terminal status was not reaped by its owner"
        );
    }
}

/// Acquire a stable child identity before allowing ptrace initialization.
/// The watcher is separate because the launcher's synchronous fork window
/// must not depend on progress from the async executor's current thread.
fn witness(command: &mut Command, deny: Option<Deny>) -> std::thread::JoinHandle<Identity> {
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent.set_read_timeout(Some(TIMEOUT)).unwrap();
    parent.set_write_timeout(Some(TIMEOUT)).unwrap();
    child.set_read_timeout(Some(TIMEOUT)).unwrap();
    child.set_write_timeout(Some(TIMEOUT)).unwrap();
    let watcher = std::thread::spawn(move || {
        let mut bytes = [0; 4];
        parent.read_exact(&mut bytes).expect("receive launcher PID");
        let pid = i32::from_ne_bytes(bytes);
        assert!(pid > 0);
        // SAFETY: the child waits for this thread's ACK, so it cannot exit or
        // lose its identity before the pidfd has been opened.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "open launcher pidfd: {}", Errno::last());
        // SAFETY: the successful pidfd_open transfers exactly one descriptor.
        let pidfd = unsafe { File::from_raw_fd(fd as i32) };
        parent
            .write_all(&[1])
            .expect("release the identified launcher");
        Identity { pid, pidfd }
    });
    let filter = deny.map(denial_filter);
    // SAFETY: child setup uses only raw syscalls and preallocated memory. The
    // descriptor remains owned by the captured stream throughout this hook.
    unsafe {
        command.pre_exec(move || {
            let bytes = libc::getpid().to_ne_bytes();
            if libc::write(child.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) != 4 {
                return Err(Errno::EIO);
            }
            let mut ack = 0_u8;
            if libc::read(child.as_raw_fd(), (&mut ack as *mut u8).cast(), 1) != 1 || ack != 1 {
                return Err(Errno::EIO);
            }
            if let Some(filter) = &filter {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(Errno::last());
                }
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr() as *mut libc::sock_filter,
                };
                if libc::syscall(libc::SYS_seccomp, 1, 0, &program) != 0 {
                    return Err(Errno::last());
                }
            }
            Ok(())
        });
    }
    watcher
}

struct Observation {
    result: Result<ExitStatus, PtraceRunFailure>,
    pid: Pid,
    output: Vec<u8>,
    callbacks: Vec<u8>,
}

fn observe(
    fixture: &Fixture,
    subscribed: bool,
    replacement: bool,
    deny: Option<Deny>,
) -> Observation {
    let mut output = memfd();
    let mut callbacks = memfd();
    let mut command = Command::new(if replacement {
        &fixture.replacement_launcher
    } else {
        &fixture.image
    });
    if replacement {
        command
            .arg(&fixture.image)
            .arg(deny.map_or("n", Deny::argument));
    }
    command
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::null());
    let identity = witness(&mut command, if replacement { None } else { deny });
    let config = (callbacks.as_raw_fd(), subscribed);
    let result = run_tokio_test(async {
        tokio::time::timeout(TIMEOUT, async {
            let tracer = TracerBuilder::<CpuidTool>::new(command)
                .config(config)
                .spawn()
                .await?;
            Ok::<_, Error>(tracer.wait_completion().await)
        })
        .await
    });
    let identity = identity.join().expect("launcher identity watcher failed");
    identity.assert_reaped();
    let outcome = result
        .expect("CPUID test exceeded its 30-second execution bound")
        .expect("CPUID tracer must spawn successfully");
    let completion = match outcome {
        ToolRunOutcome::Complete(completion) => completion,
        ToolRunOutcome::CleanupPending(_) => panic!("CPUID cleanup must complete"),
        ToolRunOutcome::UnsupportedBackend(_) => panic!("CPUID completion must be supported"),
    };
    Observation {
        result: completion.result,
        pid: Pid::from_raw(identity.pid),
        output: contents(&mut output),
        callbacks: contents(&mut callbacks),
    }
}

fn expected_reply() -> Vec<u8> {
    let mut bytes = Vec::new();
    for register in REPLY {
        // The shared sentinel pushes full 64-bit registers. Each Tool reply
        // must zero the high half as well as supply the exact low word.
        bytes.extend(u64::from(register).to_le_bytes());
    }
    bytes.extend(MARKER);
    bytes
}

fn check_interception(first_instruction: bool, replacement: bool) {
    let fixture = fixture(first_instruction);
    let observation = observe(&fixture, true, replacement, None);
    assert_eq!(
        observation.result.expect("CPUID tracer failed"),
        ExitStatus::Exited(0)
    );
    assert_eq!(observation.output, expected_reply());
    assert_eq!(
        observation.callbacks.len(),
        16,
        "exactly one CPUID callback"
    );
    let call = &observation.callbacks;
    assert_eq!(
        u64::from_le_bytes(call[..8].try_into().unwrap()),
        fixture.cpuid_ip
    );
    assert_eq!(
        u32::from_le_bytes(call[8..12].try_into().unwrap()),
        if first_instruction { 0 } else { CONTROL_EAX },
        "original CPUID leaf at the literal instruction"
    );
    assert_eq!(
        u32::from_le_bytes(call[12..16].try_into().unwrap()),
        if first_instruction { 0 } else { CONTROL_ECX },
        "original CPUID subleaf at the literal instruction on native x86-64 Linux"
    );
}

fn check_denial(deny: Deny, replacement: bool) {
    let fixture = fixture(true);
    let observation = observe(&fixture, true, replacement, Some(deny));
    let failure = observation
        .result
        .expect_err("subscribed arming denial must fail closed");
    let error = match failure.primary() {
        Error::Tool(error) => error,
        error => panic!("named primary Tool failure required: {error}"),
    };
    let phase = if replacement { "AtExec" } else { "BeforeExec" };
    assert_eq!(
        error.to_string(),
        format!(
            "ptrace-cpuid-faulting-unavailable: phase={phase} operation={} errno=1",
            deny.operation()
        )
    );
    assert_eq!(
        failure.origin(),
        BackendFailure {
            pid: observation.pid,
            tid: observation.pid,
            phase: "ptrace CPUID initialization",
        }
    );
    if replacement {
        assert_eq!(
            failure.secondary().len(),
            1,
            "replacement refusal must retain exactly its exec callback cancellation"
        );
        let secondary = &failure.secondary()[0];
        assert_eq!(
            secondary.origin(),
            BackendFailure {
                pid: observation.pid,
                tid: observation.pid,
                phase: "ptrace task callback",
            }
        );
        let error = match secondary.error() {
            Error::Tool(error) => error,
            error => panic!("exec callback Tool failure required: {error}"),
        };
        assert_eq!(
            error.to_string(),
            format!(
                "handle exec stop failed for tracee {}: {}",
                observation.pid,
                Errno::ECANCELED
            )
        );
    } else {
        assert!(
            failure.secondary().is_empty(),
            "initial refusal must not fabricate a later failure"
        );
    }
    assert!(
        observation.callbacks.is_empty(),
        "no CPUID callback may follow failed arming"
    );
    assert!(
        observation.output.is_empty(),
        "no sentinel registers or marker may follow failed arming"
    );
}

fn check_unsubscribed(deny: Deny, replacement: bool) {
    let fixture = fixture(true);
    let observation = observe(&fixture, false, replacement, Some(deny));
    assert_eq!(
        observation
            .result
            .expect("unsubscribed filter control failed"),
        ExitStatus::Exited(0)
    );
    assert!(observation.callbacks.is_empty());
    // Physical CPUID values are host-dependent. Demand the full register
    // payload and marker; exact synthetic values belong to subscribed tests.
    assert_eq!(observation.output.len(), 32 + MARKER.len());
    assert_eq!(&observation.output[32..], MARKER);
}

#[test]
fn first_instruction_cpuid_is_intercepted() {
    check_interception(true, false);
}

#[test]
fn nonfirst_instruction_cpuid_control_is_intercepted() {
    check_interception(false, false);
}

#[test]
fn replacement_exec_first_instruction_cpuid_is_intercepted() {
    check_interception(true, true);
}

#[test]
fn initial_get_cpuid_denial_fails_closed_before_exec() {
    check_denial(Deny::Get, false);
}

#[test]
fn initial_set_cpuid_denial_fails_closed_before_exec() {
    check_denial(Deny::Set, false);
}

#[test]
fn replacement_exec_get_cpuid_denial_fails_closed_at_exec() {
    check_denial(Deny::Get, true);
}

#[test]
fn replacement_exec_set_cpuid_denial_fails_closed_at_exec() {
    check_denial(Deny::Set, true);
}

#[test]
fn unsubscribed_initial_get_cpuid_denial_control() {
    check_unsubscribed(Deny::Get, false);
}

#[test]
fn unsubscribed_initial_set_cpuid_denial_control() {
    check_unsubscribed(Deny::Set, false);
}

#[test]
fn unsubscribed_replacement_exec_get_cpuid_denial_control() {
    check_unsubscribed(Deny::Get, true);
}

#[test]
fn unsubscribed_replacement_exec_set_cpuid_denial_control() {
    check_unsubscribed(Deny::Set, true);
}
