/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Additive fixed-entry witness; the original tail Tool is a separate fixture.

use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::Sysno;

/// Mode, legacy writable byte address and ELF entry (both zero for returning modes).
pub type Config = (u8, u64, u64);
/// RAX through R15, RFLAGS, PC. RSP is retained as an actual within-run value.
pub type Frame = [u64; 18];
/// Phase (before/after), actual guest PID, frame, dropped startup future count.
pub type Record = (u8, i32, Frame, u64);

pub const GETPID: u8 = 0;
pub const WRITE: u8 = 1;
pub const BAD_FD: u8 = 2;
pub const NO_EFFECT: u8 = 3;
pub const BYTE: u8 = b'T';

pub const START_GETPID: u8 = 4;
pub const START_ERRNO: u8 = 5;
pub const START_SEQUENCE: u8 = 6;
pub const POST_SEQUENCE: u8 = 7;
pub const START_NO_EFFECT: u8 = 8;
pub const POST_NO_EFFECT: u8 = 9;
pub const STARTUP: u8 = 0;
pub const POST_EXEC: u8 = 1;
pub const BEGIN: u8 = 0;
pub const CALL: u8 = 1;
pub const MUTATION: u8 = 2;
pub const END: u8 = 3;

/// All 27 x86_64 Guest register fields, in user_regs_struct order.
pub type ReturningFrame = [u64; 27];
pub type ReturningFrames = (ReturningFrame, ReturningFrame);
/// Address, original byte, staged byte, post-call byte, restored byte.
pub type ByteRecord = (u64, u8, u8, u8, u8);
type ByteWitness = (ByteRecord, ReturningFrames);
/// Callback, kind, record/call ordinals, actual PID/Tid, actual call/result,
/// immediate before/after frames, and optional checked byte cleanup evidence.
pub type ReturningRecord = (
    u8,
    u8,
    u8,
    Option<u8>,
    Pid,
    Pid,
    Option<(Sysno, Result<i64, Errno>)>,
    Option<ReturningFrames>,
    Option<ByteRecord>,
);

// Infer the register type so every existing includer needs only Reverie.
macro_rules! returning_frame {
    ($regs:expr) => {{
        let regs = $regs;
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
    }};
}

#[derive(Debug, Default)]
pub struct Witness {
    pub rows: Mutex<Vec<(Pid, Record)>>,
    pub returning_rows: Mutex<Vec<(Pid, ReturningRecord)>>,
}

#[reverie::global_tool]
impl GlobalTool for Witness {
    type Config = Config;
    type Request = (Option<Record>, Option<ReturningRecord>);
    type Response = ();

    async fn receive_rpc(&self, from: Pid, request: Self::Request) {
        match request {
            (Some(record), None) => {
                let mut rows = self.rows.lock().unwrap();
                assert!(rows.len() < 2, "duplicate startup witness RPC");
                rows.push((from, record));
            }
            (None, Some(record)) => {
                let mut rows = self.returning_rows.lock().unwrap();
                assert!(rows.len() < 8, "duplicate returning witness RPC");
                assert_eq!(usize::from(record.2), rows.len(), "returning record order");
                rows.push((from, record));
            }
            _ => panic!("expected exactly one startup witness RPC branch"),
        }
    }
}

#[derive(Debug, Default)]
pub struct TestTool {
    dropped: AtomicU64,
}

struct StartupDrop<'a>(&'a AtomicU64);
impl Drop for StartupDrop<'_> {
    fn drop(&mut self) {
        assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), 0);
    }
}

impl TestTool {
    async fn returning_record<T: Guest<Self>>(
        &self,
        guest: &mut T,
        phase: u8,
        kind: u8,
        call: Option<(Sysno, Result<i64, Errno>)>,
        frames: Option<ReturningFrames>,
        byte: Option<ByteRecord>,
    ) {
        let counters = guest.thread_state_mut();
        let ordinal = counters.0;
        counters.0 = counters.0.checked_add(1).unwrap();
        let call_ordinal = call.map(|_| {
            let ordinal = counters.1;
            counters.1 = counters.1.checked_add(1).unwrap();
            ordinal
        });
        let record = (
            phase,
            kind,
            ordinal,
            call_ordinal,
            guest.pid(),
            guest.tid(),
            call,
            frames,
            byte,
        );
        guest.send_rpc((None, Some(record))).await;
    }

    async fn returning_call<T: Guest<Self>>(&self, guest: &mut T, phase: u8, syscall: Sysno) {
        let args = match syscall {
            Sysno::getpid => SyscallArgs::new(0, 0, 0, 0, 0, 0),
            Sysno::close => SyscallArgs::new(usize::MAX, 0, 0, 0, 0, 0),
            _ => unreachable!(),
        };
        let before = returning_frame!(guest.regs().await);
        let result = guest.inject(Syscall::from_raw(syscall, args)).await;
        let after = returning_frame!(guest.regs().await);
        self.returning_record(
            guest,
            phase,
            CALL,
            Some((syscall, result)),
            Some((before, after)),
            None,
        )
        .await;
    }

    async fn returning_byte<T: Guest<Self>>(
        &self,
        guest: &mut T,
        phase: u8,
        write: bool,
    ) -> Option<ByteWitness> {
        let before_regs = guest.regs().await;
        let raw_address = before_regs.rsp.checked_sub(128 + 16).unwrap();
        let address = AddrMut::<u8>::from_raw(usize::try_from(raw_address).unwrap()).unwrap();
        let original = guest.memory().read_value(Addr::from(address)).unwrap();
        guest.memory().write_value(address, &BYTE).unwrap();
        let staged = guest.memory().read_value(Addr::from(address)).unwrap();
        assert_eq!(staged, BYTE);
        let before = returning_frame!(guest.regs().await);
        assert_eq!(before[19], before_regs.rsp, "byte staging changed RSP");
        let result = if write {
            Some(
                guest
                    .inject(Syscall::from_raw(
                        Sysno::write,
                        SyscallArgs::new(1, raw_address as usize, 1, 0, 0, 0),
                    ))
                    .await,
            )
        } else {
            None
        };
        let after = returning_frame!(guest.regs().await);
        // Restore even when the returning syscall reports an errno. Never send
        // another RPC or release the callback with our temporary byte present.
        let post_call = guest.memory().read_value(Addr::from(address));
        guest.memory().write_value(address, &original).unwrap();
        let restored = guest.memory().read_value(Addr::from(address)).unwrap();
        let post_call = post_call.unwrap();
        assert_eq!(post_call, BYTE);
        assert_eq!(restored, original);
        let byte = (raw_address, original, staged, post_call, restored);
        if let Some(result) = result {
            self.returning_record(
                guest,
                phase,
                CALL,
                Some((Sysno::write, result)),
                Some((before, after)),
                Some(byte),
            )
            .await;
            None
        } else {
            assert_eq!(before, after, "NoEffect changed the register frame");
            Some((byte, (before, after)))
        }
    }

    async fn returning_callback<T: Guest<Self>>(&self, guest: &mut T, phase: u8) {
        let (mode, address, entry) = *guest.config();
        assert!((START_GETPID..=POST_NO_EFFECT).contains(&mode));
        assert_eq!((address, entry), (0, 0));
        self.returning_record(guest, phase, BEGIN, None, None, None)
            .await;
        let selected = if matches!(mode, POST_SEQUENCE | POST_NO_EFFECT) {
            POST_EXEC
        } else {
            STARTUP
        };
        let mut byte = None;
        if phase == selected {
            if mode == START_ERRNO {
                self.returning_call(guest, phase, Sysno::close).await;
            } else {
                self.returning_call(guest, phase, Sysno::getpid).await;
            }
            if matches!(
                mode,
                START_SEQUENCE | POST_SEQUENCE | START_NO_EFFECT | POST_NO_EFFECT
            ) {
                let mut regs = guest.regs().await;
                let before = returning_frame!(regs);
                regs.rax = if regs.rax == 0x5a5a_0101 {
                    0x5a5a_0102
                } else {
                    0x5a5a_0101
                };
                guest
                    .set_regs(regs)
                    .await
                    .expect("explicit returning witness Tool write");
                let after = returning_frame!(guest.regs().await);
                self.returning_record(guest, phase, MUTATION, None, Some((before, after)), None)
                    .await;
                self.returning_call(guest, phase, Sysno::close).await;
                byte = self
                    .returning_byte(guest, phase, matches!(mode, START_SEQUENCE | POST_SEQUENCE))
                    .await;
            }
        }
        let (byte, frames) = match byte {
            Some((byte, frames)) => (Some(byte), Some(frames)),
            None => (None, None),
        };
        self.returning_record(guest, phase, END, None, frames, byte)
            .await;
    }
}

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = Witness;
    type ThreadState = (u8, u8);

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        let (mode, byte_address, entry) = *guest.config();
        if mode >= START_GETPID {
            self.returning_callback(guest, STARTUP).await;
            return Ok(());
        }
        assert!(mode <= NO_EFFECT);
        let mut regs = guest.regs().await;
        assert_eq!(regs.rip, entry, "hook must precede the actual ELF entry");
        assert_ne!(regs.rsp, 0);
        let address = AddrMut::<u8>::from_raw(byte_address as usize).unwrap();
        assert_eq!(guest.memory().read_value(Addr::from(address)).unwrap(), 0);
        guest.memory().write_value(address, &BYTE).unwrap();

        // Leave the actual stack/segment bases/entry untouched. Distinct seeds
        // expose syscall clobbers, including RCX/R11, at the first instruction.
        regs.rax = 0x101;
        regs.rbx = 0x102;
        regs.rcx = 0x103;
        regs.rdx = 0x104;
        regs.rsi = 0x105;
        regs.rdi = 0x106;
        regs.rbp = 0x107;
        regs.r8 = 0x108;
        regs.r9 = 0x109;
        regs.r10 = 0x10a;
        regs.r11 = 0x10b;
        regs.r12 = 0x10c;
        regs.r13 = 0x10d;
        regs.r14 = 0x10e;
        regs.r15 = 0x10f;
        regs.eflags = 0x202;
        guest.set_regs(regs).await?;
        let before = guest.regs().await;
        let frame = [
            before.rax,
            before.rbx,
            before.rcx,
            before.rdx,
            before.rsi,
            before.rdi,
            before.rbp,
            before.rsp,
            before.r8,
            before.r9,
            before.r10,
            before.r11,
            before.r12,
            before.r13,
            before.r14,
            before.r15,
            before.eflags,
            before.rip,
        ];
        guest
            .send_rpc((Some((0, guest.pid().as_raw(), frame, 0)), None))
            .await;
        if mode == NO_EFFECT {
            return Ok(());
        }
        let _drop = StartupDrop(&self.dropped);
        let call = match mode {
            GETPID => Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0)),
            WRITE => Syscall::from_raw(
                Sysno::write,
                SyscallArgs::new(1, byte_address as usize, 1, 0, 0, 0),
            ),
            BAD_FD => Syscall::from_raw(
                Sysno::write,
                SyscallArgs::new(usize::MAX, byte_address as usize, 1, 0, 0, 0),
            ),
            _ => unreachable!(),
        };
        let mut tail = Box::pin(guest.tail_inject(call));
        let mut polled = false;
        std::future::poll_fn(|cx| {
            assert!(!polled, "completed startup tail was polled again");
            polled = true;
            tail.as_mut().poll(cx)
        })
        .await
    }

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        if guest.config().0 >= START_GETPID {
            self.returning_callback(guest, POST_EXEC).await;
            return Ok(());
        }
        let regs = guest.regs().await;
        let frame = [
            regs.rax,
            regs.rbx,
            regs.rcx,
            regs.rdx,
            regs.rsi,
            regs.rdi,
            regs.rbp,
            regs.rsp,
            regs.r8,
            regs.r9,
            regs.r10,
            regs.r11,
            regs.r12,
            regs.r13,
            regs.r14,
            regs.r15,
            regs.eflags,
            regs.rip,
        ];
        guest
            .send_rpc((
                Some((
                    1,
                    guest.pid().as_raw(),
                    frame,
                    self.dropped.load(Ordering::SeqCst),
                )),
                None,
            ))
            .await;
        Ok(())
    }
}
