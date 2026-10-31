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

/// Mode, writable byte address, ELF entry. Only the authenticated test ELF is used.
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

#[derive(Debug, Default)]
pub struct Witness {
    pub rows: Mutex<Vec<(Pid, Record)>>,
}

#[reverie::global_tool]
impl GlobalTool for Witness {
    type Config = Config;
    type Request = Record;
    type Response = ();

    async fn receive_rpc(&self, from: Pid, record: Record) {
        let mut rows = self.rows.lock().unwrap();
        assert!(rows.len() < 2, "duplicate startup witness RPC");
        rows.push((from, record));
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

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = Witness;
    type ThreadState = ();

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        let (mode, byte_address, entry) = *guest.config();
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
        guest.send_rpc((0, guest.pid().as_raw(), frame, 0)).await;
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
                1,
                guest.pid().as_raw(),
                frame,
                self.dropped.load(Ordering::SeqCst),
            ))
            .await;
        Ok(())
    }
}
