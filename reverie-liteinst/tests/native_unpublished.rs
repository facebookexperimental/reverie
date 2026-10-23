//! Native Strace exact-syscall trampoline contract. Calibration is absent.
//! The separately ignored installed-hook pkey_alloc regression remains a loss,
//! not a passing part of this deliberately bounded read/write capability.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use reverie_liteinst::PreloadTool;
use reverie_liteinst::configure_command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod runtime;

const C_SOURCE: &[u8] = include_bytes!("fixtures/native_unpublished.c");
const ASM_SOURCE: &[u8] = include_bytes!("fixtures/native_unpublished.S");
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const CHILD_WALL: Duration = Duration::from_secs(20);
const READY_MAGIC: u64 = 0x554e505542525731;
const ORIGINAL: &str = "0f0531c931d29090c390909090909090909090909090909090";

struct Fixture {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    gate_file_offsets: Vec<u64>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let qualified =
            runtime::required_runtime().expect("official genuine leaf producer required");
        let evidence = runtime::evidence_directory("native-unpublished-build").unwrap();
        let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        assert_eq!(
            fs::read(sources.join("native_unpublished.c")).unwrap(),
            C_SOURCE
        );
        assert_eq!(
            fs::read(sources.join("native_unpublished.S")).unwrap(),
            ASM_SOURCE
        );
        let binary = evidence.join("native-unpublished");
        let held = runtime::held_environment(b"native-unpublished C/asm compiler".to_vec());
        let mut compiler = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
        compiler
            .args([
                "-std=gnu11",
                "-O0",
                "-fno-pie",
                "-no-pie",
                "-fno-builtin",
                "-fno-lto",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,--export-dynamic",
                "-Wl,-z,now",
            ])
            .arg(sources.join("native_unpublished.c"))
            .arg(sources.join("native_unpublished.S"))
            .arg("-o")
            .arg(&binary)
            .current_dir(&evidence);
        let compiled = runtime::contract::run_without_input(compiler, &held).unwrap();
        runtime::retain_capture(&evidence, "compiler", &compiled).unwrap();
        assert!(
            compiled.status.is_some_and(|status| status.success()),
            "compiler evidence {}",
            evidence.display()
        );
        let bytes = fs::read(&qualified.path).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        assert_eq!(elf.header.e_type, goblin::elf::header::ET_DYN);
        let mut gate_file_offsets = Vec::new();
        for name in [
            "reverie_inguest_trusted_syscall_return_ip",
            "reverie_inguest_guest_syscall_return_ip",
        ] {
            let values: Vec<_> = elf
                .syms
                .iter()
                .filter(|s| elf.strtab.get_at(s.st_name) == Some(name))
                .collect();
            assert_eq!(
                values.len(),
                1,
                "qualified leaf must independently identify {name}"
            );
            let address = values[0].st_value;
            let segment = elf
                .program_headers
                .iter()
                .find(|p| {
                    p.p_type == goblin::elf::program_header::PT_LOAD
                        && p.p_flags & goblin::elf::program_header::PF_X != 0
                        && address >= p.p_vaddr + 2
                        && address < p.p_vaddr + p.p_filesz
                })
                .unwrap();
            let offset = usize::try_from(segment.p_offset + address - segment.p_vaddr - 2).unwrap();
            assert_eq!(
                &bytes[offset..offset + 2],
                &[0x0f, 0x05],
                "exact gate post-syscall address"
            );
            // A maps entry's start-file_offset equals load bias only when the
            // ELF load's vaddr=file_offset. Preserve the exact load translation
            // instead of assuming that convention for a future qualified leaf.
            gate_file_offsets.push(address - segment.p_vaddr + segment.p_offset);
        }
        let mut environment: BTreeMap<_, _> =
            runtime::held_environment(b"native-unpublished fixed guest".to_vec())
                .environment
                .into_iter()
                .collect();
        environment.retain(|key, _| {
            key != "LD_PRELOAD" && !key.to_string_lossy().starts_with("REVERIE_LITEINST_")
        });
        assert!(
            std::env::var_os("LD_PRELOAD").is_none_or(|value| value.is_empty()),
            "public launcher must not append an ambient preload"
        );
        let identity = serde_json::json!({"c_sha256":runtime::artifact::sha256(C_SOURCE),
            "asm_sha256":runtime::artifact::sha256(ASM_SOURCE),
            "binary":runtime::artifact::FileIdentity::read(&binary).unwrap(),
            "runtime":qualified.path,"runtime_receipt":qualified.receipt_path,
            "source":qualified.source,"gate_file_offsets":gate_file_offsets,
            "environment_names":environment.keys().collect::<Vec<_>>()});
        runtime::artifact::write_new(
            &evidence.join("identity.json"),
            &serde_json::to_vec_pretty(&identity).unwrap(),
        )
        .unwrap();
        Fixture {
            binary,
            environment,
            gate_file_offsets,
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Native,
    Strace,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    None,
    Signal(i32),
    Restart,
    Partial,
    Tail,
    Frame,
    Sigpipe,
}

impl Action {
    fn asynchronous(self) -> bool {
        !matches!(self, Self::None)
    }
}

struct Capture {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    blocked: bool,
    delivered: bool,
    handler: Vec<u8>,
    live_windows: BTreeMap<String, String>,
    evidence: PathBuf,
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut pair = [-1; 2];
    // SAFETY: the array contains two writable descriptor slots.
    assert_eq!(
        unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) }
}

fn duplicate(fd: RawFd) -> OwnedFd {
    // SAFETY: fcntl duplicates a valid descriptor without borrowing its lifetime.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 20) };
    assert!(copy >= 20);
    // SAFETY: copy is a fresh successful descriptor owned by this function.
    unsafe { OwnedFd::from_raw_fd(copy) }
}

fn reader(mut file: impl Read, total: Arc<AtomicUsize>, truncated: Arc<AtomicBool>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("capture read: {e}"),
        };
        let previous = total.fetch_add(count, Ordering::Relaxed);
        let allowed = OUTPUT_LIMIT.saturating_sub(previous).min(count);
        bytes.extend_from_slice(&chunk[..allowed]);
        if allowed != count {
            truncated.store(true, Ordering::Release);
            break;
        }
    }
    bytes
}

fn exited(pid: libc::pid_t) -> bool {
    // SAFETY: waitid writes only this initialized siginfo; WNOWAIT retains PID
    // ownership until the group is cleaned and Child::wait reaps it.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        assert_eq!(
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT
            ),
            0
        );
        info.si_pid() != 0
    }
}

fn kill_group(pid: libc::pid_t) {
    // SAFETY: this group was created from the still-owned child PID.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

struct ChildGroupGuard(Option<libc::pid_t>);

impl Drop for ChildGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            kill_group(pid);
            // SAFETY: the guard owns this unreaped direct child. WNOWAIT in
            // the observer retained its identity; panic cleanup must reap it
            // as well as kill its process group. Normal Child::wait disarms us.
            unsafe {
                let mut status = 0;
                while libc::waitpid(pid, &mut status, 0) < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                }
            }
        }
    }
}

fn live_source_windows(
    pid: libc::pid_t,
    binary: &Path,
) -> Result<BTreeMap<String, String>, std::io::Error> {
    let bytes = fs::read(binary)?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let symbol = |name: &str| {
        elf.syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
            .map(|s| s.st_value)
            .ok_or_else(|| std::io::Error::other(format!("missing fixture symbol {name}")))
    };
    let mut memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut windows = BTreeMap::new();
    for label in ["split", "contrast"] {
        let address = symbol(&format!("{label}_site"))?;
        let end = symbol(&format!("{label}_end"))?;
        let length = end
            .checked_sub(address)
            .filter(|length| *length == 25)
            .ok_or_else(|| {
                std::io::Error::other("fixture source window is not exactly 25 bytes")
            })?;
        let mut bytes = vec![0; length as usize];
        memory.seek(SeekFrom::Start(address))?;
        memory.read_exact(&mut bytes)?;
        windows.insert(
            label.to_owned(),
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
    }
    Ok(windows)
}

fn field(text: &str, name: &str) -> u64 {
    let value = text
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&format!("{name}=0x")))
        .unwrap();
    u64::from_str_radix(value, 16).unwrap()
}

fn source_windows(text: &str, suffix: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("BYTES name=")?;
            let (name, value) = rest.split_once(" value=")?;
            let label = name.strip_suffix(suffix)?;
            (["split", "contrast"].contains(&label)).then(|| (label.to_owned(), value.to_owned()))
        })
        .collect()
}

fn blocked_observation(
    pid: libc::pid_t,
    ready: [u64; 6],
    role: Role,
    fixture: &Fixture,
) -> Result<Option<serde_json::Value>, std::io::Error> {
    let raw = fs::read_to_string(format!("/proc/{pid}/syscall"))?;
    let columns: Vec<_> = raw.split_whitespace().collect();
    if columns.len() != 9 {
        return Ok(None);
    }
    let nr = columns[0].parse::<i64>().ok();
    let value =
        |index: usize| u64::from_str_radix(columns[index].trim_start_matches("0x"), 16).ok();
    if nr != Some(ready[1] as i64)
        || value(1) != Some(ready[2])
        || value(2) != Some(ready[3])
        || value(3) != Some(ready[4])
    {
        return Ok(None);
    }
    let ip = value(8).unwrap();
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let allowed = if role == Role::Native {
        ip == ready[5] + 2
    } else {
        let qualified = runtime::required_runtime().unwrap();
        maps.lines().any(|line| {
            let cols: Vec<_> = line.split_whitespace().collect();
            if cols.len() != 6 || Path::new(cols[5]) != qualified.path || !cols[1].contains('x') {
                return false;
            }
            let (left, right) = cols[0].split_once('-').unwrap();
            let start = u64::from_str_radix(left, 16).unwrap();
            let end = u64::from_str_radix(right, 16).unwrap();
            let offset = u64::from_str_radix(cols[2], 16).unwrap();
            ip >= start
                && ip < end
                && fixture
                    .gate_file_offsets
                    .iter()
                    .any(|gate| start - offset + gate == ip)
        })
    };
    Ok(allowed.then(|| serde_json::json!({"syscall":raw,"maps":maps,"original_site":ready[5]})))
}

fn run(role: Role, case: &str, action: Action) -> Capture {
    let fixture = fixture();
    let qualified = runtime::required_runtime().unwrap();
    let evidence =
        runtime::evidence_directory(&format!("native-unpublished-{role:?}-{case}")).unwrap();
    let before = runtime::current_source(&evidence, "before").unwrap();
    assert_eq!(before, qualified.source);
    let mut command = Command::new(&fixture.binary);
    command
        .arg(case)
        .current_dir(fixture.binary.parent().unwrap())
        .env_clear()
        .envs(&fixture.environment);
    if role == Role::Strace {
        configure_command(&mut command, PreloadTool::Strace).unwrap();
    }
    let actual_environment: BTreeMap<_, _> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_owned(),
                value.expect("fixed child environment").to_owned(),
            )
        })
        .collect();
    assert!(!actual_environment.keys().any(|key| {
        key.to_string_lossy().starts_with("REVERIE_LITEINST_") && key != "REVERIE_LITEINST_TOOL"
    }));
    if role == Role::Strace {
        assert_eq!(
            actual_environment[&OsString::from("LD_PRELOAD")],
            qualified.path.as_os_str()
        );
        assert_eq!(
            actual_environment[&OsString::from("REVERIE_LITEINST_TOOL")],
            "strace"
        );
    } else {
        assert!(!actual_environment.contains_key(&OsString::from("LD_PRELOAD")));
    }
    let (data_read, data_write) = pipe();
    let (ready_read, ready_write) = pipe();
    let (handler_read, handler_write) = pipe();
    let write = matches!(action, Action::Partial | Action::Sigpipe);
    if write {
        // SAFETY: this is this test's owned pipe and a fixed bounded capacity.
        assert_eq!(
            unsafe { libc::fcntl(data_write.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
            4096
        );
    }
    if matches!(action, Action::Sigpipe) {
        // Fill the pipe without dropping its last reader. The guest write must
        // block before the parent closes that reader to deliver genuine SIGPIPE.
        let full = [b'F'; 4096];
        // SAFETY: both descriptor and buffer are live and owned.
        assert_eq!(
            unsafe { libc::write(data_write.as_raw_fd(), full.as_ptr().cast(), full.len()) },
            4096
        );
    }
    let sources = [
        duplicate(if write {
            data_write.as_raw_fd()
        } else {
            data_read.as_raw_fd()
        }),
        duplicate(ready_write.as_raw_fd()),
        duplicate(handler_write.as_raw_fd()),
    ];
    let raw = sources.each_ref().map(AsRawFd::as_raw_fd);
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: after fork this hook uses only raw descriptor/limit syscalls,
    // fixed integers and error construction; no locks or allocation.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 1,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (source, target) in raw.into_iter().zip([3, 4, 5]) {
                if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for source in raw {
                libc::close(source);
            }
            Ok(())
        });
    }
    let launch = serde_json::json!({"role":format!("{role:?}"),"case":case,"program":fixture.binary,
        "cwd":fixture.binary.parent(),"environment_names":actual_environment.keys().collect::<Vec<_>>(),
        "environment_sha256":runtime::artifact::sha256(&serde_json::to_vec(&actual_environment.iter().collect::<Vec<_>>()).unwrap()),
        "runtime":qualified.path,"runtime_receipt":qualified.receipt_path,
        "core_limit":[0,1],"wall_seconds":CHILD_WALL.as_secs(),"combined_output_cap":OUTPUT_LIMIT});
    let start = Instant::now();
    let mut child = command.spawn().unwrap();
    let pid = child.id() as libc::pid_t;
    let mut cleanup = ChildGroupGuard(Some(pid));
    drop(sources);
    drop(ready_write);
    drop(handler_write);
    let mut parent_read = Some(data_read);
    let mut parent_write = Some(data_write);
    if write {
        drop(parent_write.take());
    } else {
        drop(parent_read.take());
    }
    let total = Arc::new(AtomicUsize::new(0));
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = {
        let total = Arc::clone(&total);
        let truncated = Arc::clone(&truncated);
        thread::spawn(move || reader(stdout, total, truncated))
    };
    let err = {
        let total = Arc::clone(&total);
        let truncated = Arc::clone(&truncated);
        thread::spawn(move || reader(stderr, total, truncated))
    };
    let (tx, rx) = mpsc::channel();
    let ready_thread = thread::spawn(move || {
        let mut file = File::from(ready_read);
        let mut bytes = [0u8; 48];
        let result = file.read_exact(&mut bytes).map(|()| {
            std::array::from_fn::<_, 6, _>(|i| {
                u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
            })
        });
        let _ = tx.send(result);
    });
    // Notification pipe is nonblocking; each byte is bounded separately.
    // SAFETY: F_GETFL/F_SETFL act on this still-owned descriptor.
    unsafe {
        let flags = libc::fcntl(handler_read.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(
            libc::fcntl(
                handler_read.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK
            ),
            0
        );
    }
    let mut readiness = None;
    let mut handler = Vec::new();
    let mut events = Vec::new();
    let mut blocked = false;
    let mut delivered = false;
    let mut release = false;
    let mut refusal = None;
    let mut live_windows = BTreeMap::new();
    while !exited(pid) {
        if start.elapsed() > CHILD_WALL || truncated.load(Ordering::Acquire) {
            refusal = Some("wall/output bound".to_owned());
            kill_group(pid);
            break;
        }
        if readiness.is_none() {
            match rx.try_recv() {
                Ok(Ok(value)) => {
                    assert_eq!(value[0], READY_MAGIC);
                    readiness = Some(value);
                }
                Ok(Err(e)) => events.push(serde_json::json!({"readiness_error":e.to_string()})),
                Err(_) => {}
            }
        }
        let mut bytes = [0u8; 32];
        // SAFETY: reads at most this initialized fixed buffer from a valid pipe.
        let count = unsafe {
            libc::read(
                handler_read.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count > 0 {
            handler.extend_from_slice(&bytes[..count as usize]);
            assert!(handler.len() <= 32);
        }
        if action.asynchronous()
            && !delivered
            && let Some(ready) = readiness
        {
            match blocked_observation(pid, ready, role, fixture) {
                Ok(Some(observation)) => {
                    let queued = if matches!(action, Action::Partial) {
                        let mut queued = 0;
                        // SAFETY: ioctl writes this integer; the parent owns the pipe.
                        assert_eq!(
                            unsafe {
                                libc::ioctl(
                                    parent_read.as_ref().unwrap().as_raw_fd(),
                                    libc::FIONREAD,
                                    &mut queued,
                                )
                            },
                            0
                        );
                        queued
                    } else {
                        4096
                    };
                    if queued == 4096 {
                        events.push(observation);
                        // Capture actual full original windows while the call is
                        // blocked, including terminal signal cases that cannot
                        // print an after-window.
                        match live_source_windows(pid, &fixture.binary) {
                            Ok(windows) => live_windows = windows,
                            Err(error) => {
                                events.push(serde_json::json!({"memory_observation_error":error.to_string(),"errno":error.raw_os_error(),"exited_after_read":exited(pid),
                                    "stat":fs::read_to_string(format!("/proc/{pid}/stat")).ok(),
                                    "status":fs::read_to_string(format!("/proc/{pid}/status")).ok()}));
                                refusal = Some(
                                    "live-byte observation denied; asynchronous path unproved"
                                        .to_owned(),
                                );
                                break;
                            }
                        }
                        blocked = true;
                        if matches!(action, Action::Sigpipe) {
                            drop(parent_read.take());
                            delivered = true;
                            events.push(serde_json::json!({"close_last_reader":true}));
                        } else {
                            let signal = if let Action::Signal(signal) = action {
                                signal
                            } else {
                                libc::SIGUSR1
                            };
                            // SAFETY: owned unreaped child PID, known signal.
                            assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
                            delivered = true;
                            events.push(serde_json::json!({"signal_sent":signal}));
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    // Exit-mm teardown can make an owner-only proc file deny
                    // access before waitid exposes a zombie. Preserve identity,
                    // never call it blocked, and only continue waiting for exit.
                    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
                        .unwrap_or_else(|e| e.to_string());
                    let status = fs::read_to_string(format!("/proc/{pid}/status"))
                        .unwrap_or_else(|e| e.to_string());
                    events.push(serde_json::json!({"observation_error":error.to_string(),"errno":error.raw_os_error(),"exited_after_read":exited(pid),"stat":stat,"status":status}));
                    refusal = Some("observer denied; asynchronous path unproved".to_owned());
                    break;
                }
            }
        }
        if delivered
            && !release
            && matches!(action, Action::Restart | Action::Tail | Action::Frame)
            && handler == b"H"
        {
            // SAFETY: fixed byte and this test's owned data writer.
            assert_eq!(
                unsafe {
                    libc::write(
                        parent_write.as_ref().unwrap().as_raw_fd(),
                        b"R".as_ptr().cast(),
                        1,
                    )
                },
                1
            );
            release = true;
        }
        thread::sleep(Duration::from_millis(1));
    }
    // A denied observer gets a bounded chance to expose its actual exit. No
    // new query, signal, permission override, or blocked-IO credit is attempted.
    while !exited(pid) && start.elapsed() < CHILD_WALL {
        thread::sleep(Duration::from_millis(1));
    }
    kill_group(pid);
    let status = child.wait().unwrap();
    cleanup.0 = None;
    // The handler may write its notification after the loop's last read and
    // exit before its next iteration. Drain the still-owned nonblocking pipe
    // after reaping, rather than losing a successful final handler write.
    let mut notification_drained = false;
    for _ in 0..64 {
        let mut bytes = [0u8; 32];
        // SAFETY: this valid owned pipe writes at most the fixed buffer length.
        let count = unsafe {
            libc::read(
                handler_read.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count > 0 {
            handler.extend_from_slice(&bytes[..count as usize]);
            assert!(handler.len() <= 32, "handler notification output bound");
        } else if count == 0 {
            notification_drained = true;
            break;
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::WouldBlock,
                "final handler notification capture: {error}"
            );
            // No intended writer survives Child::wait. A retained writer is
            // not EOF; exhaust the same bounded calls and fail if it persists.
        }
    }
    assert!(notification_drained, "final notification drain call bound");
    drop(parent_read);
    drop(parent_write);
    ready_thread.join().unwrap();
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    let mut record = launch;
    record["pid"] = pid.into();
    record["code"] = status.code().into();
    record["signal"] = status.signal().into();
    record["events"] = events.into();
    record["blocked"] = blocked.into();
    record["delivered"] = delivered.into();
    record["handler_notification"] = handler.clone().into();
    record["refusal"] = refusal.clone().into();
    record["elapsed_ms"] = (start.elapsed().as_millis() as u64).into();
    runtime::artifact::write_new(&evidence.join("stdout"), &stdout).unwrap();
    runtime::artifact::write_new(&evidence.join("stderr"), &stderr).unwrap();
    runtime::artifact::write_new(
        &evidence.join("capture.json"),
        &serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let after = runtime::current_source(&evidence, "after").unwrap();
    assert_eq!(before, after, "source changed during actual fixture");
    assert!(
        !truncated.load(Ordering::Acquire),
        "output cap, raw evidence {}",
        evidence.display()
    );
    assert!(
        refusal.is_none(),
        "{refusal:?}; actual status={status}, raw evidence {}",
        evidence.display()
    );
    Capture {
        status,
        stdout,
        stderr,
        blocked,
        delivered,
        handler,
        live_windows,
        evidence,
    }
}

fn traces(capture: &Capture, site: u64) -> Vec<(i64, i64)> {
    let text = String::from_utf8_lossy(&capture.stderr);
    text.lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once("] syscall(")?;
            let (number, rest) = rest.split_once(", ip=0x")?;
            let (address, result) = rest.split_once(") = ")?;
            (u64::from_str_radix(address, 16).ok()? == site)
                .then(|| (number.parse().unwrap(), result.parse().unwrap()))
        })
        .collect()
}

fn complete(capture: &Capture, role: Role, expected: &[(i64, i64)], observations: usize) {
    let text = String::from_utf8(capture.stdout.clone()).unwrap();
    assert!(
        capture.status.success(),
        "actual native syscall oracle failed: {}; raw evidence {}\n{text}",
        capture.status,
        capture.evidence.display()
    );
    assert!(
        text.ends_with("END errors=0\n"),
        "incomplete/failed observations: {text}"
    );
    let observed: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("OBS name="))
        .collect();
    assert_eq!(
        observed.len(),
        observations,
        "required observations missing: {text}"
    );
    for line in observed {
        let (_, rest) = line.split_once(" result=").unwrap();
        let (actual, expected) = rest.split_once(" expected=").unwrap();
        assert_eq!(actual, expected, "{line}");
    }
    if text.contains("CASE data\n") {
        assert!(text.contains("BYTES name=read value=616263646566cccc\n"));
    }
    if text.contains("CASE partial-read\n") {
        assert!(text.contains("BYTES name=read value=616263cccccccccc\n"));
    }
    let before = source_windows(&text, "-before");
    let after = source_windows(&text, "-after");
    assert_eq!(before.len(), 2);
    assert_eq!(before, after);
    assert!(before.values().all(|v| v == ORIGINAL));
    let site = field(
        text.lines().find(|line| line.starts_with("SITE ")).unwrap(),
        "split",
    );
    assert_eq!(
        traces(capture, site),
        if role == Role::Strace { expected } else { &[] }
    );
    let contrast = field(
        text.lines().find(|line| line.starts_with("SITE ")).unwrap(),
        "contrast",
    );
    assert!(
        traces(capture, contrast).is_empty(),
        "entry refusal acquired execution"
    );
}

fn pair(case: &str, action: Action, expected: &[(i64, i64)], observations: usize) {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, case, action);
        complete(&capture, role, expected, observations);
        if action.asynchronous() {
            assert!(capture.blocked && capture.delivered);
            assert_eq!(capture.handler, b"H");
        }
    }
}

#[test]
fn native_unpublished_data_and_error_semantics() {
    for (case, expected, count) in [
        ("data", vec![(0, 6), (0, 0), (0, 0)], 4),
        ("eof", vec![(0, 0)], 3),
        ("zero", vec![(0, 0), (1, 0)], 6),
        ("partial-read", vec![(0, 3), (0, 0), (0, 0)], 4),
        ("partial-write", vec![(1, 4096)], 4),
        ("eagain-read", vec![(0, -11)], 2),
        ("eagain-write", vec![(1, -11)], 2),
        ("ebadf", vec![(0, -9), (1, -9)], 3),
        ("efault", vec![(0, -14), (1, -14)], 6),
    ] {
        pair(case, Action::None, &expected, count);
    }
}

#[test]
fn native_unpublished_guest_pkey_permissions() {
    pair(
        "pkru-explicit-rights",
        Action::None,
        &[(0, -14), (1, -14), (0, 1), (1, 1)],
        14,
    );
}

#[test]
fn native_unpublished_other_number_is_refused() {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, "other-number", Action::None);
        complete(&capture, role, &[(0, 1)], 3);
        let text = String::from_utf8(capture.stdout.clone()).unwrap();
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix("POLICY name=same-site-getpid result="))
            .unwrap()
            .parse::<i64>()
            .unwrap();
        if role == Role::Strace {
            assert_eq!(value, -95);
        } else {
            assert!(value > 0);
        }
    }
}

#[test]
fn native_unpublished_interior_entry_is_refused() {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, "contrast", Action::None);
        complete(
            &capture,
            role,
            &[],
            if role == Role::Native { 2 } else { 3 },
        );
        let text = String::from_utf8(capture.stdout.clone()).unwrap();
        assert!(text.contains(if role == Role::Native {
            "POLICY name=contrast-read result=1\n"
        } else {
            "POLICY name=contrast-read result=-95\n"
        }));
    }
}

#[test]
fn native_unpublished_original_nondefault_sigtrap_is_refused() {
    // These are executed named refusal controls. They are never reported as
    // admitted native-I/O parity, and neither original disposition is changed.
    for case in ["prior-ignore", "prior-unknown"] {
        for role in [Role::Native, Role::Strace] {
            let capture = run(role, case, Action::None);
            if case == "prior-unknown" && role == Role::Strace {
                // The unchanged constructor refuses an original custom
                // SIGTRAP handler before main. This is startup refusal, not
                // initialized syscall refusal or admitted native-I/O parity.
                assert_eq!(capture.status.code(), Some(127));
                assert!(capture.stdout.is_empty());
                assert_eq!(
                    capture.stderr,
                    b"reverie-liteinst initialization failed: failed to install SIGTRAP handler: errno 1\n"
                );
                assert!(!capture.blocked && !capture.delivered);
                assert!(capture.handler.is_empty() && capture.live_windows.is_empty());
                continue;
            }
            complete(
                &capture,
                role,
                &[],
                if role == Role::Native { 3 } else { 4 },
            );
            let text = String::from_utf8(capture.stdout.clone()).unwrap();
            assert!(text.contains(if role == Role::Native {
                "POLICY name=prior-profile-read result=1\n"
            } else {
                "POLICY name=prior-profile-read result=-95\n"
            }));
        }
    }
}

#[test]
fn native_unpublished_eintr_and_handler_trace() {
    pair(
        "handler-eintr",
        Action::Signal(libc::SIGUSR1),
        &[(1, 1), (0, -4)],
        4,
    );
}
#[test]
fn native_unpublished_restart_and_handler_trace() {
    pair("handler-restart", Action::Restart, &[(1, 1), (0, 1)], 5);
}
#[test]
fn native_unpublished_partial_write_and_handler_trace() {
    pair("handler-partial", Action::Partial, &[(1, 1), (1, 4096)], 4);
}

#[test]
fn native_unpublished_current_tail_is_executed() {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, "live-tail", Action::Tail);
        complete(&capture, role, &[(1, 1)], 6);
        assert!(capture.blocked && capture.delivered);
        assert_eq!(capture.handler, b"H");
        let text = String::from_utf8(capture.stdout.clone()).unwrap();
        let before = text
            .lines()
            .find_map(|v| v.strip_prefix("BYTES name=tail-before value="))
            .unwrap();
        let after = text
            .lines()
            .find_map(|v| v.strip_prefix("BYTES name=tail-after value="))
            .unwrap();
        assert_eq!(before.len(), after.len());
        assert_eq!(&before[..6], &after[..6]);
        assert_eq!(&before[6..8], "11");
        assert_eq!(&after[6..8], "22");
        assert_eq!(&before[8..], &after[8..]);
        // The main read ran at the distinct tail site; the handler's write ran
        // at split_site. Require both genuine original-IP events independently.
        let fixture = fixture();
        let bytes = fs::read(&fixture.binary).unwrap();
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let site = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("tail_site"))
            .unwrap()
            .st_value;
        assert_eq!(
            traces(&capture, site),
            if role == Role::Strace {
                vec![(0, 1)]
            } else {
                vec![]
            }
        );
    }
}

#[test]
fn native_unpublished_signal_frame_pkru_survives() {
    pair("saved-frame-pkru", Action::Frame, &[(1, 1), (0, 1)], 10);
}

fn cached_refusal(case: &str, changed: bool, extra_observations: usize) {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, case, Action::None);
        complete(
            &capture,
            role,
            &[],
            if role == Role::Native { 8 } else { 11 } + extra_observations,
        );
        let text = String::from_utf8(capture.stdout.clone()).unwrap();
        assert!(text.contains(if role == Role::Native {
            "POLICY name=cached-after-change result=1\n"
        } else {
            "POLICY name=cached-after-change result=-95\n"
        }));
        assert!(text.contains("OBS name=cache-initial-read result=1 expected=1\n"));
        assert!(text.contains("OBS name=cache-initial-literal result=70 expected=70\n"));
        assert!(text.contains("OBS name=cache-second-read result=1 expected=1\n"));
        assert!(text.contains("OBS name=cache-second-literal result=66 expected=66\n"));
        assert!(text.contains(if role == Role::Strace {
            "COUNTS present=1 trap=2 hook=0\n"
        } else {
            "COUNTS present=0\n"
        }));
        let before = text
            .lines()
            .find_map(|line| line.strip_prefix("BYTES name=cache-before value="))
            .unwrap();
        let after = text
            .lines()
            .find_map(|line| line.strip_prefix("BYTES name=cache-after value="))
            .unwrap();
        assert_eq!(before, ORIGINAL);
        let mut expected = ORIGINAL.to_owned();
        if changed {
            expected.replace_range(6..8, "d2");
        }
        assert_eq!(after, expected);
        let site = field(
            text.lines()
                .find(|line| line.starts_with("CACHE "))
                .unwrap(),
            "site",
        );
        assert_eq!(
            traces(&capture, site),
            if role == Role::Strace {
                vec![(0, 1), (0, 1)]
            } else {
                vec![]
            }
        );
        if case == "boundary-replace" {
            let changed_start = field(
                text.lines()
                    .find(|line| line.starts_with("CHANGED "))
                    .unwrap(),
                "start",
            );
            assert_eq!(site & 4095, 4094);
            assert_eq!(changed_start, site + 2);
            assert!(site < changed_start);
            // Thus the syscall bytes themselves are outside the actual mmap
            // range, while original+2 and four saved admission bytes overlap.
            assert!(site + 6 > changed_start);
        }
        if matches!(case, "metadata-replace" | "metadata-read-restored") {
            let cache = text
                .lines()
                .find(|line| line.starts_with("CACHE "))
                .unwrap();
            let metadata = field(cache, "metadata");
            let start = field(
                text.lines()
                    .find(|line| line.starts_with("CHANGED "))
                    .unwrap(),
                "start",
            );
            assert_eq!(start, metadata & !4095);
            assert!(site < start || site >= start + 4096);
            assert!(text.contains(if case == "metadata-replace" {
                "OBS name=replacement-full-page result=0 expected=0\n"
            } else {
                "OBS name=restored-full-page result=0 expected=0\n"
            }));
        }
    }
}

#[test]
fn native_unpublished_cached_source_mutation_is_refused() {
    cached_refusal("cache-mutate", true, 0);
}

#[test]
fn native_unpublished_replaced_source_mapping_is_refused() {
    cached_refusal("mapping-replace", true, 1);
}

#[test]
fn native_unpublished_replaced_census_metadata_is_refused() {
    cached_refusal("metadata-replace", false, 1);
}

#[test]
fn native_unpublished_restored_metadata_read_access_stays_refused() {
    cached_refusal("metadata-read-restored", false, 3);
}

#[test]
fn native_unpublished_original_return_page_overlap_is_refused() {
    cached_refusal("boundary-replace", true, 1);
}

#[test]
fn native_unpublished_key_reassignment_is_refused() {
    // Success is required; an unsupported kernel is an actual fixture failure,
    // never credited as exercised invalidation or silently skipped.
    cached_refusal("pkey-overlap", false, 1);
}

#[test]
fn native_unpublished_fork_retains_parent_image_and_child_cache() {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, "fork-cache", Action::None);
        complete(
            &capture,
            role,
            &[],
            if role == Role::Native { 14 } else { 15 },
        );
        let text = String::from_utf8(capture.stdout.clone()).unwrap();
        assert!(text.contains(if role == Role::Native {
            "POLICY name=fork-child-after-change result=1\n"
        } else {
            "POLICY name=fork-child-after-change result=-95\n"
        }));
        let mut changed = ORIGINAL.to_owned();
        changed.replace_range(6..8, "d2");
        assert!(text.contains(&format!("BYTES name=fork-child-cache value={changed}\n")));
        for label in ["cache-before", "cache-after"] {
            assert!(text.contains(&format!("BYTES name={label} value={ORIGINAL}\n")));
        }
        let site = field(
            text.lines()
                .find(|line| line.starts_with("CACHE "))
                .unwrap(),
            "site",
        );
        assert_eq!(
            traces(&capture, site),
            if role == Role::Strace {
                vec![(0, 1), (0, 1), (0, 1)]
            } else {
                vec![]
            }
        );
        assert!(text.contains("OBS name=fork-child-cached-read result=1 expected=1\n"));
        assert!(text.contains("OBS name=fork-parent-read result=1 expected=1\n"));
    }
}

fn terminal(case: &str, action: Action, signal: i32) {
    for role in [Role::Native, Role::Strace] {
        let capture = run(role, case, action);
        assert_eq!(
            capture.status.signal(),
            Some(signal),
            "raw evidence {}",
            capture.evidence.display()
        );
        assert!(
            capture.blocked && capture.delivered,
            "terminal signal was not observed at intended blocked IO"
        );
        let text = String::from_utf8(capture.stdout.clone()).unwrap();
        let before = source_windows(&text, "-before");
        assert_eq!(before.len(), 2);
        assert_eq!(before, capture.live_windows);
        assert!(before.values().all(|v| v == ORIGINAL));
        assert!(!text.contains("END errors="));
    }
}

#[test]
fn native_unpublished_sigpipe_default_and_ignore() {
    pair("sigpipe-ignore", Action::None, &[(1, -32)], 2);
    terminal("sigpipe-default", Action::Sigpipe, libc::SIGPIPE);
}

#[test]
fn native_unpublished_sigtrap_default_behavior() {
    terminal("trap-default", Action::Signal(libc::SIGTRAP), libc::SIGTRAP);
}

#[test]
#[ignore = "Known legacy aligned installed-hook pkey_alloc loses its native PKRU side effect (actual baseline SIGSEGV); not repaired or credited by the exact2 read/write slice. Run explicitly as a separately labelled failing loss diagnostic."]
fn native_installed_pkey_alloc_preserves_permissions() {
    // Preserve the actual native assertions; never expect the defective result
    // as a PASS. Related capability: https://github.com/rrnewton/hermit/issues/3520.
    pair(
        "pkru",
        Action::None,
        &[(0, -14), (1, -14), (0, 1), (1, 1)],
        13,
    );
}
