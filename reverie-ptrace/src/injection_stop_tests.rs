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
use reverie::Stack as _;
use reverie::process::Stdio;
use reverie::syscalls::Addr;
use reverie::syscalls::Close;
use reverie::syscalls::Exit;
use reverie::syscalls::Futex;
use reverie::syscalls::Getpid;
use reverie::syscalls::Getppid;
use reverie::syscalls::MapFlags;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mmap;
use reverie::syscalls::OFlag;
use reverie::syscalls::Openat;
use reverie::syscalls::PathPtr;
use reverie::syscalls::ProtFlags;
use reverie::syscalls::Quotactl;
use reverie::syscalls::RtSigprocmask;
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
const HANDLED: usize = WORD + 24;
const SHARED_PATH: usize = WORD + 64;
const SIGACT: usize = WORD + 128;
const SIGSET: usize = WORD + 160;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
enum Mode {
    #[default]
    PostExec,
    Replace,
    ReplaceNumber,
    ReplaceThenPrivate,
    ReplaceWithPendingSignal,
    ReplaceInterruptedRestart,
    InheritedTrapRewrite,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Observation {
    PostExec,
    Write,
    Emulated,
    Timestamp,
    Boundary(u64),
    /// Register frame at the boundary stop, in `frame_of` order with
    /// rcx/r11 omitted (the syscall clobbers, whose native values
    /// legitimately differ between the in-place and stepped
    /// transports). Compared across transports, never against a
    /// literal.
    Frame(Vec<u64>),
}

/// The register frame compared across transports: every
/// `user_regs_struct` field except rcx and r11.
#[cfg(target_arch = "x86_64")]
fn frame_of(regs: &libc::user_regs_struct) -> Vec<u64> {
    vec![
        regs.r15,
        regs.r14,
        regs.r13,
        regs.r12,
        regs.rbp,
        regs.rbx,
        regs.r10,
        regs.r9,
        regs.r8,
        regs.rax,
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
                    Mode::ReplaceNumber => {
                        // A different syscall number, run in place as
                        // the pending call: the kernel runs close, the
                        // guest's write never happens, and the callback
                        // still reports one byte written.
                        assert_eq!(
                            guest.inject(Close::default().with_fd(-1)).await,
                            Err(Errno::EBADF)
                        );
                        1
                    }
                    Mode::ReplaceThenPrivate => {
                        // First injection rewrites the pending call in
                        // place; the second has no pending call left and
                        // takes the private page. Output is R then O.
                        assert_eq!(guest.inject(replacement()).await?, 1);
                        assert_eq!(guest.regs().await.rip, rip);
                        assert_eq!(word(guest, WORD), 1);
                        assert_eq!(guest.inject(original).await?, 1);
                        1
                    }
                    Mode::ReplaceWithPendingSignal => {
                        // SIGUSR1 is blocked and pending in the kernel
                        // at this stop. The divergent write runs in
                        // place; unblocking (a second, private
                        // injection) must not deliver it early: the
                        // handler runs only once the guest resumes.
                        assert_eq!(word(guest, HANDLED), 0);
                        assert_eq!(guest.inject(replacement()).await?, 1);
                        let mut stack = guest.stack().await;
                        let set = stack.push(1u64 << (libc::SIGUSR1 - 1));
                        let _guard = stack.commit()?;
                        guest
                            .inject(
                                RtSigprocmask::new()
                                    .with_how(libc::SIG_UNBLOCK)
                                    .with_set(Some(set.cast()))
                                    .with_oldset(None)
                                    .with_sigsetsize(8),
                            )
                            .await?;
                        assert_eq!(
                            word(guest, HANDLED),
                            0,
                            "pending signal delivered while still stopped"
                        );
                        1
                    }
                    Mode::ReplaceInterruptedRestart => {
                        if *guest.thread_state() != 0 {
                            // The restarted guest write itself: run it.
                            // (tail_inject diverges: it cancels this
                            // callback, so there is no value to return.)
                            guest.tail_inject(original).await
                        }
                        *guest.thread_state_mut() = 1;
                        // The rewritten call blocks in a futex wait
                        // until the guest's interval timer interrupts
                        // it. The result the Tool returns for the
                        // guest's write is that ERESTARTSYS, so at the
                        // final resume the handler runs and sigreturn
                        // must restart the guest's write (its restored
                        // orig/args), never the futex.
                        let mut stack = guest.stack().await;
                        let word: reverie::syscalls::AddrMut<i32> = stack.reserve();
                        guest.memory().write_value(word, &0i32)?;
                        let _guard = stack.commit()?;
                        match guest
                            .inject(
                                Futex::new()
                                    .with_uaddr(Some(word))
                                    .with_futex_op(libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG)
                                    .with_val(0)
                                    .with_timeout(None)
                                    .with_uaddr2(None)
                                    .with_val3(0),
                            )
                            .await
                        {
                            Err(Errno::ERESTARTSYS) => {
                                return Err(Errno::ERESTARTSYS.into());
                            }
                            other => panic!("interrupted futex returned {other:?}"),
                        }
                    }
                    Mode::InheritedTrapRewrite => {
                        // An inherited RET_TRAP filter traps quotactl
                        // (getppid and uname are called by the spawn and tracer
                        // paths themselves, so neither can be the trapped
                        // number here).
                        // Admission must refuse in place (baseline
                        // above one), so the private transport reports
                        // the trapped call as ENOSYS; run in place it
                        // would report the rolled-back number as a
                        // successful result. Deleting the baseline
                        // gate call turns this red.
                        match guest.inject(Quotactl::default()).await {
                            Err(Errno::ENOSYS) => {
                                return Err(Errno::ENOSYS.into());
                            }
                            other => panic!("inherited trap rewrite returned {other:?}"),
                        }
                    }
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
                if mode == Mode::ReplaceWithPendingSignal || mode == Mode::ReplaceInterruptedRestart
                {
                    assert_eq!(
                        word(guest, HANDLED),
                        1,
                        "pending SIGUSR1 was not delivered after the write callback"
                    );
                }
                guest.send_rpc(Observation::Boundary(expected)).await;
                let frame = frame_of(&guest.regs().await);
                guest.send_rpc(Observation::Frame(frame)).await;
                Ok(guest.inject(original).await?)
            }
            other => panic!("unexpected intercepted syscall {other:?}"),
        }
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, Errno> {
        // The inherited-trap witness's trapped injection leaves its
        // SIGSYS held; dropping it at its report is what lets the
        // guest survive to the boundary on the private transport.
        if guest.config().mode == Mode::InheritedTrapRewrite && signal == reverie::Signal::SIGSYS {
            return Ok(None);
        }
        Ok(Some(signal))
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
        let mut handler_addr = 0u64;
        let mut restorer_addr = 0u64;
        if mode == Mode::ReplaceWithPendingSignal {
            // rt_sigaction(SIGUSR1, SIGACT, NULL, 8); the action and
            // set words are patched into the data page below, once the
            // handler/restorer addresses at the end of the code are known.
            code.extend_from_slice(&[0xb8, 13, 0, 0, 0, 0xbf, 10, 0, 0, 0, 0xbe]);
            code.extend_from_slice(&(SIGACT as u32).to_le_bytes());
            code.extend_from_slice(&[0x31, 0xd2, 0x41, 0xba, 8, 0, 0, 0, 0x0f, 0x05]);
            // rt_sigprocmask(SIG_BLOCK, SIGSET, NULL, 8): block SIGUSR1.
            code.extend_from_slice(&[0xb8, 14, 0, 0, 0, 0x31, 0xff, 0xbe]);
            code.extend_from_slice(&(SIGSET as u32).to_le_bytes());
            code.extend_from_slice(&[0x31, 0xd2, 0x41, 0xba, 8, 0, 0, 0, 0x0f, 0x05]);
            // tgkill(gettid(), gettid(), SIGUSR1): queue it blocked.
            code.extend_from_slice(&[
                0xb8, 186, 0, 0, 0, 0x0f, 0x05, 0x89, 0xc7, 0x89, 0xc6, 0xba, 10, 0, 0, 0, 0xb8,
                234, 0, 0, 0, 0x0f, 0x05,
            ]);
        }
        if mode == Mode::ReplaceInterruptedRestart {
            // rt_sigaction(SIGALRM, SIGACT, NULL, 8) with SA_RESTART
            // (patched below), then alarm(1)
            // so SIGALRM interrupts the Tool's divergent futex wait.
            code.extend_from_slice(&[0xb8, 13, 0, 0, 0, 0xbf, 14, 0, 0, 0, 0xbe]);
            code.extend_from_slice(&(SIGACT as u32).to_le_bytes());
            code.extend_from_slice(&[0x31, 0xd2, 0x41, 0xba, 8, 0, 0, 0, 0x0f, 0x05]);
            // alarm(1): SIGALRM interrupts the Tool's futex wait.
            code.extend_from_slice(&[0xb8, 37, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05]);
        }
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
        if mode == Mode::ReplaceWithPendingSignal || mode == Mode::ReplaceInterruptedRestart {
            handler_addr = ENTRY + code.len() as u64;
            memory_instruction(&mut code, &[0x48, 0xff, 0x05], HANDLED); // inc qword [rip+disp32]
            code.push(0xc3); // ret to the restorer
            restorer_addr = ENTRY + code.len() as u64;
            code.extend_from_slice(&[0xb8, 15, 0, 0, 0, 0x0f, 0x05]); // rt_sigreturn
        }
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
        if mode == Mode::ReplaceWithPendingSignal || mode == Mode::ReplaceInterruptedRestart {
            // struct kernel_sigaction at SIGACT: handler, flags,
            // restorer, empty mask.
            let flags: u64 = if mode == Mode::ReplaceInterruptedRestart {
                0x1400_0000 // SA_RESTART | SA_RESTORER
            } else {
                0x0400_0000 // SA_RESTORER
            };
            elf[0x2080..0x2088].copy_from_slice(&handler_addr.to_le_bytes());
            elf[0x2088..0x2090].copy_from_slice(&flags.to_le_bytes());
            elf[0x2090..0x2098].copy_from_slice(&restorer_addr.to_le_bytes());
        }
        if mode == Mode::ReplaceWithPendingSignal {
            // Blocked set at SIGSET: SIGUSR1 only.
            elf[0x20a0..0x20a8].copy_from_slice(&(1u64 << (10 - 1)).to_le_bytes());
        }
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

/// Private-page injections of `nr` on this thread so far, both
/// transports summed (`PRIVATE_TRANSPORTS_FOR_TEST`).
fn private_transports(nr: Sysno) -> u64 {
    crate::task::private_transports_for_test(nr, true)
        + crate::task::private_transports_for_test(nr, false)
}

/// Forces divergent first injections onto the stepped transports for
/// one run; restored when dropped. The reference transport for the
/// cross-transport comparison in `run`.
struct ForceStepped;

impl ForceStepped {
    fn new() -> Self {
        crate::task::NO_IN_PLACE_REWRITE_FOR_TEST.with(|none| none.set(true));
        Self
    }
}

impl Drop for ForceStepped {
    fn drop(&mut self) {
        crate::task::NO_IN_PLACE_REWRITE_FOR_TEST.with(|none| none.set(false));
    }
}

/// (guest status, stdout, observation log) of one run.
type RunOutcome = (
    reverie::ExitStatus,
    Vec<u8>,
    Vec<Observation>,
    (u64, u64, u64),
);

async fn run_once(mode: Mode, force_stepped: bool) -> RunOutcome {
    let _stepped = force_stepped.then(ForceStepped::new);
    let transports_before = (
        private_transports(Sysno::write),
        private_transports(Sysno::close),
        private_transports(Sysno::rt_sigprocmask),
    );
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
        Mode::Replace | Mode::TailOther | Mode::PostExecTail | Mode::ReplaceWithPendingSignal => {
            b"R"
        }
        Mode::SameThenPrivate => b"OR",
        Mode::ReplaceThenPrivate => b"RO",
        Mode::ReplaceInterruptedRestart => b"O",
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
    let log = log.0.into_inner().unwrap();
    // Shape check: the frame payload is compared across transports in
    // `run`, never against a literal, so normalize it away here.
    let shape: Vec<Observation> = log
        .iter()
        .map(|observation| match observation {
            Observation::Frame(_) => Observation::Frame(Vec::new()),
            other => other.clone(),
        })
        .collect();
    let frame = Observation::Frame(Vec::new());
    let expected = match mode {
        Mode::PostExec => vec![
            Observation::PostExec,
            Observation::Boundary(1),
            frame.clone(),
        ],
        Mode::PostExecTail => vec![Observation::PostExec],
        Mode::Emulate | Mode::EmulateErrno => vec![
            Observation::PostExec,
            Observation::Emulated,
            Observation::Timestamp,
            Observation::Boundary(2),
            frame,
        ],
        Mode::ReplaceInterruptedRestart => vec![
            Observation::PostExec,
            Observation::Write,
            Observation::Write,
            Observation::Boundary(2),
            frame,
        ],
        _ => vec![
            Observation::PostExec,
            Observation::Write,
            Observation::Boundary(2),
            frame,
        ],
    };
    assert_eq!(shape, expected);
    let transports = (
        private_transports(Sysno::write) - transports_before.0,
        private_transports(Sysno::close) - transports_before.1,
        private_transports(Sysno::rt_sigprocmask) - transports_before.2,
    );
    (output.status, output.stdout, log, transports)
}

/// Runs `mode` on both transports — divergent first injections in
/// place at their seccomp stop, then forced onto the stepped
/// transports — and requires identical guest-visible outcomes:
/// status, stdout, the full observation log including the register
/// frame at the boundary stop (minus rcx/r11, see `Observation::Frame`),
/// and so the restart behaviour the frame determines. Only the
/// private-transport counts may differ, pinned per transport below.
async fn run(mode: Mode) {
    let in_place = run_once(mode, false).await;
    let stepped = run_once(mode, true).await;
    assert_eq!(
        (in_place.0, &in_place.1, &in_place.2),
        (stepped.0, &stepped.1, &stepped.2),
        "{mode:?} differs between in-place and stepped transports"
    );
    // (writes, closes, sigprocmasks) on the private page, per transport.
    let expected_transports = match mode {
        Mode::Replace => ((0, 0, 0), (1, 0, 0)),
        Mode::ReplaceNumber => ((0, 0, 0), (0, 1, 0)),
        Mode::ReplaceThenPrivate => ((1, 0, 0), (2, 0, 0)),
        Mode::ReplaceWithPendingSignal => ((0, 0, 1), (1, 0, 1)),
        Mode::SameThenPrivate => ((1, 1, 0), (1, 1, 0)),
        // A divergent tail injection has no exit stop to restore at,
        // so it takes the private page on both transports.
        Mode::TailOther => ((1, 0, 0), (1, 0, 0)),
        Mode::TailSame | Mode::ReplaceInterruptedRestart | Mode::InheritedTrapRewrite => {
            ((0, 0, 0), (0, 0, 0))
        }
        Mode::PostExec => ((0, 1, 0), (0, 1, 0)),
        Mode::PostExecTail => ((1, 1, 0), (1, 1, 0)),
        Mode::Emulate | Mode::EmulateErrno => ((0, 0, 0), (0, 0, 0)),
    };
    assert_eq!(
        (in_place.3, stepped.3),
        expected_transports,
        "{mode:?} private transports (in-place, stepped)"
    );
    eprintln!("INJECTION_STOP_COMPLETE {mode:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn divergent_inject_interrupted_restarts_the_guest_call() {
    run(Mode::ReplaceInterruptedRestart).await;
}

/// Witness for the inherited-filter refusal: a dedicated thread
/// installs a RET_TRAP filter on uname (inherited by the guest it
/// then traces on that same thread, so the seccomp baseline is 2),
/// and the Tool rewrites the guest's write to quotactl. On both
/// transports the Tool must see Err(ENOSYS) and the guest -38, as
/// on main; deleting the baseline gate call lets it run in place
/// and report Ok(110) instead.
#[cfg(target_arch = "x86_64")]
#[test]
fn inherited_ret_trap_rewrite_reports_enosys_on_both_transports() {
    std::thread::spawn(|| {
        unsafe {
            let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
                code: code as u16,
                jt,
                jf,
                k,
            };
            let filter = [
                statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
                statement(
                    libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                    libc::SYS_quotactl as u32,
                    0,
                    1,
                ),
                statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_TRAP, 0, 0),
                statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW, 0, 0),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr() as *mut libc::sock_filter,
            };
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &program as *const libc::sock_fprog
                ),
                0
            );
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let in_place = run_once(Mode::InheritedTrapRewrite, false).await;
            let stepped = run_once(Mode::InheritedTrapRewrite, true).await;
            assert_eq!(
                (in_place.0, &in_place.1, &in_place.2),
                (stepped.0, &stepped.1, &stepped.2),
                "inherited trap rewrite differs between transports"
            );
        });
    })
    .join()
    .unwrap();
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
async fn divergent_number_runs_in_place_and_suppresses_original() {
    run(Mode::ReplaceNumber).await;
}

#[tokio::test(flavor = "current_thread")]
async fn divergent_first_inject_in_place_then_private() {
    run(Mode::ReplaceThenPrivate).await;
}

#[tokio::test(flavor = "current_thread")]
async fn divergent_inject_with_pending_signal_delivers_after_resume() {
    run(Mode::ReplaceWithPendingSignal).await;
}

#[tokio::test(flavor = "current_thread")]
async fn emulated_return_consumes_stop_before_instruction_callback() {
    run(Mode::Emulate).await;
    run(Mode::EmulateErrno).await;
}
