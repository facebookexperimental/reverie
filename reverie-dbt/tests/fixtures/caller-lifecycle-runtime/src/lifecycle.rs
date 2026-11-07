/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Syscall and expected-lifecycle helpers shared by the native Tool and its
//! lifecycle test. The transport-failure host needs only the protocol module.

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

use super::protocol::Config;
use super::protocol::LifecycleGlobal;
use super::protocol::Mode;
use super::protocol::NO_APPLICATION_RPC_REQUESTS;
use super::protocol::RawCall;
use super::protocol::Terminal;

pub const LATER_EXIT_CODE: i32 = 31;

impl Mode {
    pub fn guest_argument(self) -> &'static str {
        match self {
            Self::Invalid => panic!("invalid fixture mode"),
            Self::SelectedTail => "1",
            Self::OriginalExit | Self::NoApplicationRpc => "2",
            Self::SuppressOnce => "3",
            Self::RewriteAway => "4",
            Self::RewriteToTerminal => "5",
            Self::RpcDisconnect => "6",
        }
    }

    pub fn has_terminal_attempt(self) -> bool {
        matches!(
            self,
            Self::SelectedTail | Self::SuppressOnce | Self::RewriteAway | Self::RewriteToTerminal
        )
    }
}

impl Terminal {
    pub fn number(self) -> Sysno {
        match self {
            Self::Exit => Sysno::exit,
            Self::ExitGroup => Sysno::exit_group,
        }
    }
}

impl Config {
    pub fn without_application_rpc(witness: PathBuf) -> Self {
        let mut config = Self::new(Mode::OriginalExit, Terminal::ExitGroup, 23);
        config.mode = Mode::NoApplicationRpc;
        config.witness = Some(witness);
        config.validate();
        config
    }

    pub fn exit_code(&self) -> i32 {
        if self.mode.continues() {
            LATER_EXIT_CODE
        } else {
            (self.args[0] & 0xff) as i32
        }
    }

    pub fn terminal_call(&self) -> Syscall {
        call(self.terminal.number(), self.args)
    }

    pub fn trigger_call(&self) -> Syscall {
        call(
            if self.mode == Mode::RewriteToTerminal {
                Sysno::getpid
            } else {
                self.terminal.number()
            },
            self.args,
        )
    }

    pub fn replacement(&self) -> Option<Syscall> {
        match self.mode {
            Mode::SelectedTail | Mode::RewriteToTerminal => Some(self.terminal_call()),
            Mode::RewriteAway => Some(call(Sysno::getpid, [0; 6])),
            Mode::SuppressOnce => None,
            Mode::OriginalExit | Mode::NoApplicationRpc | Mode::RpcDisconnect | Mode::Invalid => {
                panic!("mode has no selected trigger")
            }
        }
    }
}

fn call(number: Sysno, args: [u64; 6]) -> Syscall {
    Syscall::from_raw(
        number,
        SyscallArgs::new(
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
            args[5] as usize,
        ),
    )
}

pub fn raw_call(syscall: Syscall) -> RawCall {
    let (number, args) = syscall.into_parts();
    RawCall {
        number: number.id() as i64,
        args: [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ],
    }
}

impl LifecycleGlobal {
    /// Host-only count of actual receive_rpc calls for the no-request mode.
    pub fn no_application_rpc_requests() -> usize {
        NO_APPLICATION_RPC_REQUESTS.load(Ordering::SeqCst)
    }
}
