// @lint-ignore LICENSELINT
/*
 * MIT License
 *
 * Copyright (c) 2021 Daniel Prilik
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#![allow(non_snake_case, non_camel_case_types, dead_code, unused_imports)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use bytes::Bytes;
use bytes::BytesMut;
use paste::paste;
use reverie::ExitStatus;
use reverie::Pid;
use reverie::Signal;
use safeptrace::ChildOp;
use safeptrace::Stopped;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::gdbstub::hex::*;
use crate::gdbstub::request::*;
use crate::gdbstub::response::*;
use crate::gdbstub::BreakpointType;
use crate::gdbstub::Inferior;
use crate::gdbstub::InferiorThreadId;
use crate::gdbstub::ResumeInferior;
use crate::gdbstub::StoppedInferior;
use crate::regs::RegAccess;

mod base;
mod extended_mode;
mod monitor_cmd;
mod section_offsets;

pub use base::*;
pub use extended_mode::*;
pub use monitor_cmd::*;
pub use section_offsets::*;

trait ParseCommand: Sized {
    fn parse(buff: BytesMut) -> Option<Self>;
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum IdKind {
    // all threads: `-1'.
    All,
    // any thread: `0'.
    Any,
    Id(Pid),
}

impl IdKind {
    pub fn from_raw(pid: i32) -> Self {
        match pid {
            -1 => IdKind::All,
            0 => IdKind::Any,
            _ => IdKind::Id(Pid::from_raw(pid)),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn into_raw(&self) -> i32 {
        match self {
            IdKind::All => -1,
            IdKind::Any => 0,
            IdKind::Id(pid) => pid.as_raw(),
        }
    }

    pub fn matches(&self, other: &IdKind) -> bool {
        match (self, &other) {
            (IdKind::All, _) => true,
            (IdKind::Any, _) => true,
            (IdKind::Id(pid1), IdKind::Id(pid2)) => pid1 == pid2,
            (IdKind::Id(_), _) => other.matches(self),
        }
    }
}

impl WriteResponse for IdKind {
    fn write_response(&self, writer: &mut ResponseWriter) {
        match self {
            IdKind::All => writer.put_str("-1"),
            IdKind::Any => writer.put_str("0"),
            IdKind::Id(pid) => writer.put_num(pid.as_raw()),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum ThreadOp {
    c, // step and continue, deprecated because of `vCont'
    g, // Other operations
    G,
    m,
    M,
}

/// Gdb ThreadId. See https://sourceware.org/gdb/onlinedocs/gdb/Packets.html#thread_002did-syntax
/// for more details.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct ThreadId {
    pub pid: IdKind,
    pub tid: IdKind,
}

impl ThreadId {
    pub fn all() -> Self {
        ThreadId {
            tid: IdKind::All,
            pid: IdKind::All,
        }
    }

    pub fn any() -> Self {
        ThreadId {
            tid: IdKind::All,
            pid: IdKind::Any,
        }
    }

    pub fn pid(pid: i32) -> Self {
        ThreadId {
            tid: IdKind::All,
            pid: IdKind::from_raw(pid),
        }
    }

    pub fn pid_tid(pid: i32, tid: i32) -> Self {
        ThreadId {
            pid: IdKind::from_raw(pid),
            tid: IdKind::from_raw(tid),
        }
    }

    // NB: Specifying just a process, as ‘ppid’, is equivalent to ‘ppid.-1’.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if !bytes.starts_with(b"p") {
            return None;
        }
        let mut iter = bytes[1..].split(|c| *c == b'.');
        let p = iter.next().and_then(|x| decode_hex(x).ok())?;
        Some(
            match iter.next().and_then(|x| {
                if x == &b"-1"[..] {
                    Some(-1)
                } else {
                    decode_hex(x).ok()
                }
            }) {
                Some(t) => ThreadId::pid_tid(p, t),
                None => ThreadId::pid(p),
            },
        )
    }

    /// Check if `tid` matches `ThreadId`.
    pub fn matches(&self, other: &ThreadId) -> bool {
        self.pid.matches(&other.pid) && self.tid.matches(&other.tid)
    }

    pub fn getpid(&self) -> Option<Pid> {
        let id = self.pid.into_raw();
        if id > 0 {
            Some(Pid::from_raw(id))
        } else {
            None
        }
    }

    pub fn gettid(&self) -> Option<Pid> {
        let id = self.tid.into_raw();
        if id > 0 {
            Some(Pid::from_raw(id))
        } else {
            None
        }
    }
}

impl WriteResponse for ThreadId {
    fn write_response(&self, writer: &mut ResponseWriter) {
        writer.put_str("p");
        self.pid.write_response(writer);
        writer.put_str(".");
        self.tid.write_response(writer);
    }
}

macro_rules! commands {
    (
        $(#[$attrs:meta])*
        $vis:vis enum $Name:ident {
            $(
                $(#[$ext_attrs:meta])*
                $ext:ident {
                    $($name:literal => $command:ident,)*
                }
            )*
        }
    ) => {paste! {
        $(
            #[allow(non_camel_case_types)]
            #[derive(PartialEq, Debug)]
            $(#[$ext_attrs])*
            $vis enum [<$ext:camel>] {
                $($command(self::$ext::$command),)*
            }
        )*

        /// GDB commands
        $(#[$attrs])*
        $vis enum $Name {
            $(
                [<$ext:camel>]([<$ext:camel>]),
            )*
            Unknown(Bytes),
        }

        impl Command {
            pub fn try_parse(
                mut buf: BytesMut
            ) -> Result<Command, CommandParseError> {
                if buf.is_empty() {
                    return Err(CommandParseError::Empty);
                }

                let body = buf.as_ref();

                $(
                    match body {
                        $(_ if body.starts_with($name.as_bytes()) => {
                            let nb = $name.as_bytes().len();
                            let cmd = self::$ext::$command::parse(buf.split_off(nb))
                                .ok_or(CommandParseError::MalformedCommand(String::from(concat!($name))))?;

                            return Ok(
                                Command::[<$ext:camel>](
                                    [<$ext:camel>]::$command(cmd)
                                )
                            )
                        })*
                        _ => {},
                    }
                )*

                Ok(Command::Unknown(buf.freeze()))
            }
        }
    }};
}

/// Command parse error
#[derive(Debug, PartialEq, Error)]
pub enum CommandParseError {
    /// Command is empty
    #[error("Command is empty")]
    Empty,

    /// Malformed command
    #[error("Malformed command: {}", .0)]
    MalformedCommand(String),

    #[error("Malformed registers found from g/G packet")]
    MalformedRegisters,
}

commands! {
    #[derive(PartialEq, Debug)]
    pub enum Command {
        base {
            "?" => QuestionMark,
            "D" => D,
            "g" => g,
            "G" => G,
            "H" => H,
            "m" => m,
            "M" => M,
            "qAttached" => qAttached,
            "QThreadEvents" => QThreadEvents,
            "qC" => qC,
            "qfThreadInfo" => qfThreadInfo,
            "QStartNoAckMode" => QStartNoAckMode,
            "qsThreadInfo" => qsThreadInfo,
            "qSupported" => qSupported,
            "qXfer" => qXfer,
            "vCont" => vCont,
            "vKill" => vKill,
            "z" => z,
            "Z" => Z,
            "X" => X,
            /* host i/o commands */
            "vFile" => vFile,
        }

        extended_mode {
            "!" => ExclamationMark,
            "QDisableRandomization" => QDisableRandomization,
        }

        monitor_cmd {
            "qRcmd" => qRcmd,
        }

        section_offsets {
            "qOffsets" => qOffsets,
        }
    }
}

/// Resume actions set by vCont.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ResumeAction {
    /// signal step, with optional signal.
    Step(Option<Signal>),
    /// cointinue, with optional signal.
    Continue(Option<Signal>),
    /// Stop, not sure what it means exactly.
    Stop,
    /// Keep stepping until rip doesn't belong to start..=end.
    StepUntil(u64, u64),
}

/// Replay log used by reverse debugging.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ReplayLog {
    /// Relay log reached the beginning.
    Begin,
    /// Replay log reached the end.
    End,
}

/// Expediated registers. Stop reply packets (as to vCont) can have extra
/// registers, so that gdb doesn't have to read registers unless necessary.
/// On amd64, they're %rbp, %rsp and %rip.
#[derive(PartialEq, Clone, Debug)]
pub struct ExpediatedRegs(BTreeMap<usize, u64>);

impl From<libc::user_regs_struct> for ExpediatedRegs {
    fn from(regs: libc::user_regs_struct) -> Self {
        let mut exp_regs = BTreeMap::new();
        exp_regs.insert(6, regs.frame_ptr());
        exp_regs.insert(7, regs.stack_ptr());
        exp_regs.insert(0x10, regs.ip());
        ExpediatedRegs(exp_regs)
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum StopEvent {
    /// Stopped by signal.
    Signal(Signal),
    /// Stopped by softwrae breakpoint.
    SwBreak,
    /// Stopped due to vforkdone event.
    Vforkdone,
    /// Replay reached either begin or end.
    ReplayDone(ReplayLog),
    /// Stopped due to exec event.
    Exec(PathBuf),
}

#[derive(Debug, Clone)]
pub struct StoppedTask {
    /// Pid of the event (SYS_gettid)
    pub pid: Pid,
    /// Thread Group id of the event (SYS_getpid)
    pub tgid: Pid,
    /// Stop event
    pub event: StopEvent,
    /// Expediated registers specified by gdb remote protocol
    pub regs: ExpediatedRegs,
}

#[derive(Debug)]
pub struct NewTask {
    /// Pid of the event (SYS_gettid)
    pub pid: Pid,
    /// Thread Group id of the event (SYS_getpid)
    pub tgid: Pid,
    /// New child Pid
    pub child: Pid,
    /// Expediated registers specified by gdb remote protocol
    pub regs: ExpediatedRegs,
    /// Clone type
    pub op: ChildOp,
    /// channel to send gdb request
    pub request_tx: Option<mpsc::Sender<GdbRequest>>,
    /// channel to send gdb resume request
    pub resume_tx: Option<mpsc::Sender<ResumeInferior>>,
    /// channel to receive new gdb stop event
    pub stop_rx: Option<mpsc::Receiver<StoppedInferior>>,
}

/// Reasons why inferior has stopped, reported to gdb (client).
/// See section ["Stop Reply Packets"]
/// (https://sourceware.org/gdb/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets)
/// for more details.
#[derive(Debug)]
pub enum StopReason {
    Stopped(StoppedTask),
    NewTask(NewTask),
    Exited(Pid, ExitStatus),
    ThreadExited(Pid, Pid, ExitStatus),
}

impl StopReason {
    pub fn stopped(pid: Pid, tgid: Pid, event: StopEvent, regs: ExpediatedRegs) -> Self {
        StopReason::Stopped(StoppedTask {
            pid,
            tgid,
            event,
            regs,
        })
    }

    // FIXME: Reduce number of arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn new_task(
        pid: Pid,
        tgid: Pid,
        child: Pid,
        regs: ExpediatedRegs,
        op: ChildOp,
        request_tx: Option<mpsc::Sender<GdbRequest>>,
        resume_tx: Option<mpsc::Sender<ResumeInferior>>,
        stop_rx: Option<mpsc::Receiver<StoppedInferior>>,
    ) -> Self {
        StopReason::NewTask(NewTask {
            pid,
            tgid,
            child,
            regs,
            op,
            request_tx,
            resume_tx,
            stop_rx,
        })
    }

    pub fn thread_exited(pid: Pid, tgid: Pid, exit_status: ExitStatus) -> Self {
        StopReason::ThreadExited(pid, tgid, exit_status)
    }

    pub fn exit(pid: Pid, exit_status: ExitStatus) -> Self {
        StopReason::Exited(pid, exit_status)
    }
}

impl WriteResponse for StopReason {
    fn write_response(&self, writer: &mut ResponseWriter) {
        match self {
            StopReason::NewTask(new_task) => {
                writer.put_str("T05");
                match new_task.op {
                    ChildOp::Fork => {
                        // T05fork:p21feb6.21feb6;06:30dcffffff7f0000;07:10dcffffff7f0000;10:37c2ecf7ff7f0000;thread:p21f994.21f994;core:10;
                        let thread_id = ThreadId {
                            pid: IdKind::from_raw(new_task.child.as_raw()),
                            tid: IdKind::from_raw(new_task.child.as_raw()),
                        };
                        writer.put_str("fork:");
                        thread_id.write_response(writer);
                        writer.put_str(";");
                    }
                    ChildOp::Vfork => {
                        let thread_id = ThreadId {
                            pid: IdKind::from_raw(new_task.child.as_raw()),
                            tid: IdKind::from_raw(new_task.child.as_raw()),
                        };
                        writer.put_str("vfork:");
                        thread_id.write_response(writer);
                        writer.put_str(";");
                    }
                    ChildOp::Clone => {
                        let thread_id = ThreadId {
                            pid: IdKind::from_raw(new_task.tgid.as_raw()),
                            tid: IdKind::from_raw(new_task.child.as_raw()),
                        };
                        writer.put_str("create:");
                        thread_id.write_response(writer);
                        writer.put_str(";");
                    }
                }
                for (regno, regval) in &new_task.regs.0 {
                    writer.put_num(*regno);
                    writer.put_str(":");
                    writer.put_hex_encoded(&regval.to_ne_bytes());
                    writer.put_str(";");
                }
                let thread_id = ThreadId::pid_tid(new_task.tgid.as_raw(), new_task.pid.as_raw());
                writer.put_str("thread:");
                thread_id.write_response(writer);
                writer.put_str(";");
            }
            StopReason::Stopped(stopped) => {
                writer.put_str("T05");
                match &stopped.event {
                    StopEvent::Signal(_) => {}
                    StopEvent::SwBreak => {
                        writer.put_str("swbreak:;");
                    }
                    StopEvent::Vforkdone => {
                        writer.put_str("vforkdone:;");
                    }
                    StopEvent::Exec(p) => {
                        // T05exec:2f746d702f6631;06:0000000000000000;07:80ddffffff7f0000;10:9030fdf7ff7f0000;thread:p350ad8.350ad8;core:9;
                        writer.put_str("exec:");
                        if let Some(p) = p.to_str() {
                            writer.put_hex_encoded(p.as_bytes());
                        }
                        writer.put_str(";");
                    }
                    StopEvent::ReplayDone(log) => match log {
                        ReplayLog::Begin => writer.put_str("replaylog:begin;"),
                        ReplayLog::End => writer.put_str("replaylog:end;"),
                    },
                }
                for (regno, regval) in &stopped.regs.0 {
                    writer.put_num(*regno);
                    writer.put_str(":");
                    writer.put_hex_encoded(&regval.to_ne_bytes());
                    writer.put_str(";");
                }
                let thread_id = ThreadId::pid_tid(stopped.tgid.as_raw(), stopped.pid.as_raw());
                writer.put_str("thread:");
                thread_id.write_response(writer);
                writer.put_str(";");
            }
            StopReason::Exited(pid, exit_status) => {
                match exit_status {
                    ExitStatus::Exited(code) => {
                        writer.put_str("W");
                        writer.put_hex_encoded(&[*code as u8]);
                    }
                    ExitStatus::Signaled(sig, _) => {
                        writer.put_str("X");
                        writer.put_hex_encoded(&[(*sig as u8) | 0x80]);
                    }
                }
                writer.put_str(";process:");
                writer.put_num(pid.as_raw());
            }
            StopReason::ThreadExited(pid, tgid, exit_status) => {
                match exit_status {
                    ExitStatus::Exited(code) => {
                        writer.put_str("w");
                        writer.put_hex_encoded(&[*code as u8]);
                    }
                    ExitStatus::Signaled(_, _) => unreachable!(),
                }
                writer.put_str(";");
                let threadid = ThreadId::pid_tid(tgid.as_raw(), pid.as_raw());
                threadid.write_response(writer);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_vcont_test() {
        let mut packet = BytesMut::from("$vCont;s:p3e86d3.3e86d3;c:p3e86d3.-1#3b");
        let vcont = vCont::parse(packet.split());
        assert!(vcont.is_some());

        let vcont = vCont::parse(BytesMut::from("$vCont;c:p2.-1#10"));
        assert!(vcont.is_some());
    }

    #[test]
    fn unknown_command() {
        let mut packet = BytesMut::from("just,an,unknown,command#3b");
        let cmd = Command::try_parse(packet.split());
        assert!(cmd.is_ok());
        assert!(matches!(cmd.unwrap(), Command::Unknown(_)));
    }

    #[test]
    fn malformed_command() {
        let mut packet = BytesMut::from("vCont,Just a bad command;c:1.-1#fe");
        let cmd = Command::try_parse(packet.split());
        assert_eq!(
            cmd,
            Err::<Command, CommandParseError>(CommandParseError::MalformedCommand(String::from(
                "vCont"
            )))
        );
    }
}
