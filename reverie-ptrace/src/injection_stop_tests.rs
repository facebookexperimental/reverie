/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Guest;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::process::Stdio;
use reverie::syscalls::Addr;
use reverie::syscalls::Close;
use reverie::syscalls::Exit;
use reverie::syscalls::Getpid;
use reverie::syscalls::Getppid;
use reverie::syscalls::MapFlags;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mmap;
use reverie::syscalls::OFlag;
use reverie::syscalls::Openat;
use reverie::syscalls::PathPtr;
use reverie::syscalls::ProtFlags;
use reverie::syscalls::Syscall;
use reverie::syscalls::Write as WriteCall;
use serde::Deserialize;
use serde::Serialize;

use super::*;

const ENTRY: u64 = 0x401000;
const WORD: usize = 0x402000;
const ORIGINAL: usize = WORD + 8;
const REPLACEMENT: usize = WORD + 9;
const EMULATED_RESULT: usize = WORD + 16;
const SHARED_PATH: usize = WORD + 64;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
enum Mode {
    #[default]
    PostExec,
    Replace,
    SameThenPrivate,
    TailSame,
    TailOther,
    PostExecTail,
    Emulate,
    EmulateErrno,
}

impl Mode {
    fn emulates(self) -> bool {
        matches!(self, Self::Emulate | Self::EmulateErrno)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Config {
    mode: Mode,
    timestamp_rip: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Observation {
    PostExec,
    Write,
    Emulated,
    Timestamp,
    Boundary(u64),
}

#[derive(Default)]
struct Log(Mutex<Vec<Observation>>);

#[reverie::global_tool]
impl GlobalTool for Log {
    type Config = Config;
    type Request = Observation;
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, observation: Observation) {
        self.0.lock().unwrap().push(observation);
    }
}

#[derive(Default)]
struct StopTool;

fn word<G: Guest<StopTool>>(guest: &G, address: usize) -> u64 {
    guest
        .memory()
        .read_value(Addr::<u64>::from_raw(address).unwrap())
        .unwrap()
}

fn replacement() -> WriteCall {
    WriteCall::default()
        .with_fd(1)
        .with_buf(Addr::from_raw(REPLACEMENT))
        .with_len(1)
}

#[reverie::tool]
impl Tool for StopTool {
    type GlobalState = Log;
    type ThreadState = u8;

    fn subscriptions(_config: &Config) -> Subscription {
        let mut events = Subscription::none();
        events.syscalls([Sysno::getpid, Sysno::write]).rdtsc();
        events
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let mode = guest.config().mode;
        assert_eq!(guest.regs().await.rip, ENTRY);
        assert_eq!(word(guest, WORD), 0, "backend preinit executed guest entry");
        guest.send_rpc(Observation::PostExec).await;
        if mode == Mode::PostExec {
            for _ in 0..2 {
                assert!(guest.inject(Getpid::default()).await? > 0);
                assert_eq!(guest.regs().await.rip, ENTRY);
                assert_eq!(word(guest, WORD), 0, "injection replayed guest entry");
            }
            assert_eq!(
                guest.inject(Close::default().with_fd(-1)).await,
                Err(Errno::EBADF)
            );
            assert_eq!(guest.regs().await.rip, ENTRY);
            assert_eq!(word(guest, WORD), 0, "failed injection replayed entry");
        } else if mode == Mode::PostExecTail {
            // Keep the entry's word observable after Exit. Private ELF data
            // alone would lose an erroneous final step when the guest dies.
            let fd = guest
                .inject(
                    Openat::default()
                        .with_dirfd(libc::AT_FDCWD)
                        .with_path(PathPtr::from_ptr(SHARED_PATH as *const libc::c_char))
                        .with_flags(OFlag::O_RDWR),
                )
                .await?;
            let fd = i32::try_from(fd).unwrap();
            assert_eq!(
                guest
                    .inject(
                        Mmap::default()
                            .with_addr(Addr::from_raw(WORD))
                            .with_len(4096)
                            .with_prot(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
                            .with_flags(MapFlags::MAP_SHARED | MapFlags::MAP_FIXED)
                            .with_fd(fd)
                            .with_offset(0)
                    )
                    .await?,
                WORD as i64
            );
            assert_eq!(guest.inject(Close::default().with_fd(fd)).await?, 0);
            assert_eq!(guest.inject(replacement()).await?, 1);
            assert_eq!(guest.regs().await.rip, ENTRY);
            assert_eq!(word(guest, WORD), 0);
            guest.tail_inject(Exit::default().with_status(27)).await
        }
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let mode = guest.config().mode;
        match call {
            Syscall::Write(original) => {
                assert_eq!(original.fd(), 1);
                assert_eq!(original.buf(), Addr::from_raw(ORIGINAL));
                assert_eq!(original.len(), 1);
                assert_eq!(word(guest, WORD), 1);
                guest.send_rpc(Observation::Write).await;
                let rip = guest.regs().await.rip;
                let result = match mode {
                    Mode::Replace => guest.inject(replacement()).await?,
                    Mode::SameThenPrivate => {
                        assert_eq!(guest.inject(original).await?, 1);
                        assert_eq!(guest.regs().await.rip, rip);
                        assert_eq!(word(guest, WORD), 1);
                        assert_eq!(guest.inject(replacement()).await?, 1);
                        assert_eq!(
                            guest.inject(Close::default().with_fd(-1)).await,
                            Err(Errno::EBADF)
                        );
                        1
                    }
                    Mode::TailSame => guest.tail_inject(original).await,
                    Mode::TailOther => guest.tail_inject(replacement()).await,
                    other => panic!("unexpected write in {other:?}"),
                };
                assert_eq!(result, 1);
                assert_eq!(guest.regs().await.rip, rip);
                assert_eq!(
                    word(guest, WORD),
                    1,
                    "next guest instruction ran in injection"
                );
                Ok(result)
            }
            Syscall::Getpid(original) => {
                if mode.emulates() && *guest.thread_state() == 0 {
                    *guest.thread_state_mut() = 1;
                    assert_eq!(word(guest, WORD), 1);
                    guest.send_rpc(Observation::Emulated).await;
                    // Return without injecting. The ordinary callback epilogue
                    // must consume the original kernel entry before RDTSC.
                    return if mode == Mode::EmulateErrno {
                        Err(Errno::EPERM.into())
                    } else {
                        Ok(123)
                    };
                }
                let expected = if mode == Mode::PostExec { 1 } else { 2 };
                assert_eq!(word(guest, WORD), expected);
                guest.send_rpc(Observation::Boundary(expected)).await;
                Ok(guest.inject(original).await?)
            }
            other => panic!("unexpected intercepted syscall {other:?}"),
        }
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        let mode = guest.config().mode;
        assert!(mode.emulates());
        assert_eq!(request, Rdtsc::Tsc);
        assert_eq!(*guest.thread_state(), 1);
        let rip = guest.regs().await.rip;
        assert_eq!(rip, guest.config().timestamp_rip);
        assert_eq!(word(guest, WORD), 1);
        let expected = if mode == Mode::EmulateErrno {
            -(libc::EPERM as i64)
        } else {
            123
        };
        assert_eq!(word(guest, EMULATED_RESULT), expected as u64);
        // Getppid differs from the previously emulated Getpid. A stale Some
        // must not send this actual instruction-trap stop through syscall skip.
        assert!(guest.inject(Getppid::default()).await? > 0);
        assert_eq!(guest.regs().await.rip, rip);
        assert_eq!(word(guest, WORD), 1);
        assert_eq!(word(guest, EMULATED_RESULT), expected as u64);
        guest.send_rpc(Observation::Timestamp).await;
        Ok(RdtscResult { tsc: 17, aux: None })
    }
}

struct Fixture {
    path: PathBuf,
    shared: Option<PathBuf>,
    timestamp_rip: u64,
}

impl Fixture {
    fn new(mode: Mode) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-injection-stop-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fn memory_instruction(code: &mut Vec<u8>, opcode: &[u8], address: usize) {
            let next = ENTRY + code.len() as u64 + opcode.len() as u64 + 4;
            let displacement = i32::try_from(address as i64 - next as i64).unwrap();
            code.extend_from_slice(opcode);
            code.extend_from_slice(&displacement.to_le_bytes());
        }
        fn getpid(code: &mut Vec<u8>) {
            code.extend_from_slice(&[0xb8, 39, 0, 0, 0, 0x0f, 0x05]);
        }
        let mut code = Vec::new();
        memory_instruction(&mut code, &[0x48, 0xff, 0x05], WORD); // inc qword [rip+disp32]
        let mut timestamp_rip = 0;
        if mode.emulates() {
            getpid(&mut code);
            memory_instruction(&mut code, &[0x48, 0x89, 0x05], EMULATED_RESULT); // mov [rip+disp32],rax
            timestamp_rip = ENTRY + code.len() as u64;
            code.extend_from_slice(&[0x0f, 0x31]); // rdtsc, after real emulated-return resume
            memory_instruction(&mut code, &[0x48, 0xff, 0x05], WORD);
        } else if mode != Mode::PostExec && mode != Mode::PostExecTail {
            code.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe]); // write, stdout, buf
            code.extend_from_slice(&(ORIGINAL as u32).to_le_bytes());
            code.extend_from_slice(&[0xba, 1, 0, 0, 0, 0x0f, 0x05]);
            memory_instruction(&mut code, &[0x48, 0xff, 0x05], WORD);
        }
        getpid(&mut code);
        code.extend_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
        let mut elf = vec![0u8; 0x3000];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&ENTRY.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (header, flags, offset, address, length) in [
            (64, 5u32, 0u64, 0x400000u64, 0x1000 + code.len() as u64),
            (120, 6u32, 0x2000u64, WORD as u64, 0x1000),
        ] {
            elf[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
            elf[header + 4..header + 8].copy_from_slice(&flags.to_le_bytes());
            elf[header + 8..header + 16].copy_from_slice(&offset.to_le_bytes());
            elf[header + 16..header + 24].copy_from_slice(&address.to_le_bytes());
            elf[header + 24..header + 32].copy_from_slice(&address.to_le_bytes());
            elf[header + 32..header + 40].copy_from_slice(&length.to_le_bytes());
            elf[header + 40..header + 48].copy_from_slice(&length.to_le_bytes());
            elf[header + 48..header + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        elf[0x1000..0x1000 + code.len()].copy_from_slice(&code);
        elf[0x2008..0x200a].copy_from_slice(b"OR");
        let shared = if mode == Mode::PostExecTail {
            let shared = path.with_extension("shared-word");
            let mut data = vec![0u8; 4096];
            data[8..10].copy_from_slice(b"OR");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&shared)
                .unwrap();
            file.write_all(&data).unwrap();
            drop(file);
            let name = shared.as_os_str().as_bytes();
            assert!(name.len() + 65 < 4096);
            elf[0x2040..0x2040 + name.len()].copy_from_slice(name);
            Some(shared)
        } else {
            None
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&elf).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .unwrap();
        drop(file);
        Self {
            path,
            shared,
            timestamp_rip,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
        if let Some(path) = &self.shared {
            std::fs::remove_file(path).unwrap();
        }
    }
}

async fn run(mode: Mode) {
    let fixture = Fixture::new(mode);
    let mut command = Command::new(&fixture.path);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let tracer = TracerBuilder::<StopTool>::new(command)
        .config(Config {
            mode,
            timestamp_rip: fixture.timestamp_rip,
        })
        .spawn()
        .await
        .unwrap();
    let (output, log) = tokio::time::timeout(Duration::from_secs(5), tracer.wait_with_output())
        .await
        .expect("injection stop control hung")
        .unwrap();
    assert_eq!(
        output.status,
        ExitStatus::Exited(if mode == Mode::PostExecTail { 27 } else { 0 })
    );
    let expected_stdout: &[u8] = match mode {
        Mode::Replace | Mode::TailOther | Mode::PostExecTail => b"R",
        Mode::SameThenPrivate => b"OR",
        Mode::TailSame => b"O",
        _ => b"",
    };
    assert_eq!(output.stdout, expected_stdout);
    if let Some(path) = &fixture.shared {
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(bytes.len(), 4096);
        assert_eq!(
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            0,
            "tail injection executed entry before exiting"
        );
        assert_eq!(&bytes[8..10], b"OR");
    }
    assert!(
        output.stderr.is_empty(),
        "guest stderr: {:?}",
        output.stderr
    );
    let expected = match mode {
        Mode::PostExec => vec![Observation::PostExec, Observation::Boundary(1)],
        Mode::PostExecTail => vec![Observation::PostExec],
        Mode::Emulate | Mode::EmulateErrno => vec![
            Observation::PostExec,
            Observation::Emulated,
            Observation::Timestamp,
            Observation::Boundary(2),
        ],
        _ => vec![
            Observation::PostExec,
            Observation::Write,
            Observation::Boundary(2),
        ],
    };
    assert_eq!(log.0.into_inner().unwrap(), expected);
    eprintln!("INJECTION_STOP_COMPLETE {mode:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn post_exec_injections_leave_entry_memory_untouched() {
    run(Mode::PostExec).await;
}

#[tokio::test(flavor = "current_thread")]
async fn seccomp_replacement_suppresses_original_write_once() {
    run(Mode::Replace).await;
}

#[tokio::test(flavor = "current_thread")]
async fn same_reinjection_then_private_injection_does_not_step_guest() {
    run(Mode::SameThenPrivate).await;
}

#[tokio::test(flavor = "current_thread")]
async fn same_tail_injection_preserves_original_kernel_call() {
    run(Mode::TailSame).await;
}

#[tokio::test(flavor = "current_thread")]
async fn different_tail_injection_replaces_original_once() {
    run(Mode::TailOther).await;
}

#[tokio::test(flavor = "current_thread")]
async fn post_exec_tail_exit_leaves_entry_unexecuted() {
    run(Mode::PostExecTail).await;
}

#[tokio::test(flavor = "current_thread")]
async fn emulated_return_consumes_stop_before_instruction_callback() {
    run(Mode::Emulate).await;
    run(Mode::EmulateErrno).await;
}
