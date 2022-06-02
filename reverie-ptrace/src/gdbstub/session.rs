/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::{Bytes, BytesMut};
use futures::future::Future;
use futures::stream::{FuturesUnordered, StreamExt};
use nix::fcntl;
use nix::fcntl::OFlag;
use nix::sys::signal::Signal;
use nix::sys::stat::{self, Mode};
use nix::sys::uio;
use nix::unistd;
use reverie::Pid;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::MappedMutexGuard;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use crate::trace::ChildOp;

use super::commands::{self, *};
use super::regs::Amd64CoreRegs;
use super::response::*;
use super::Breakpoint;
use super::BreakpointType;
use super::Error;
use super::GdbRequest;
use super::Inferior;
use super::InferiorThreadId;
use super::Packet;
use super::ResumeInferior;
use super::StoppedInferior;

use std::collections::BTreeMap;

type BoxWriter = Box<dyn AsyncWrite + Unpin + Send + Sync + 'static>;

/// Gdb session manager.
/// recv commands over tcp stream
/// recv request from Tracee (new task, reap orphans, etc..)
/// Session ends when client disconnect from tcp stream.
/// (gdb) detach semantics?
pub struct Session {
    /// No-ACK mode, set by gdb client.
    pub no_ack_mode: bool,

    /// Stream to send reply to.
    pub stream_tx: BoxWriter,

    /// buffer use to send data over to tcp stream
    pub tx_buf: BytesMut,

    /// Gdb remote protocol command notifier.
    pub pkt_rx: Option<mpsc::Receiver<Packet>>,

    /// buffer used by hostio.
    pub bufsiz: usize,

    /// Current pid used by vFile (hostio).
    pub hostio_pid: Option<Pid>,

    /// Inferiors managed by this session.
    pub inferiors: Arc<Mutex<BTreeMap<Pid, Inferior>>>,

    /// Current thread
    pub current: Option<InferiorThreadId>,

    /// Channel to report stop event.
    // NB: even though we could use a single `gdb_stop_rx` to receive all
    // stop events (mpsc), we use a `stop_rx` channel for each `inferior`
    // instead, this is because `vCont;p<pid>:-1` could resume multiple
    // threads hence there are could be multiple threads reporting stop
    // event at the same time, causing de-sync issue. This can be mitigated
    // if each inferior has its own `stop_rx` channel. As a result,
    // `gdb_stop_rx` is moved after initial gdb attach, once we can create
    // the first inferior.
    pub gdb_stop_rx: Option<mpsc::Receiver<StoppedInferior>>,
}

struct VcontResumeResult {
    /// stop reason
    reason: StopReason,
    /// A new inferior was created.
    new_inferior: Option<Inferior>,
    /// ptids must be removed, due to some tasks are exited.
    ptid_to_remove: Vec<ThreadId>,
    /// Switch to a new task
    //
    // NB: This is possible when supporting multi-threaded programs. See
    // Below examples.
    //
    // Sending packet: $vCont;c:p2.-1#10...Packet received: T05create:p02.12;06:70d9ffffff7f0000;07:28d9ffffff7f0000;10:1138eef7ff7f0000;thread:p02.02;
    // Sending packet: $vCont;c:p2.-1#10...Packet received: T05swbreak:;06:201e5cf5ff7f0000;07:f01d5cf5ff7f0000;10:0e14400000000000;thread:p02.10;
    // Sending packet: $qfThreadInfo#bb...Packet received: mp02.02,p02.06,p02.08,p02.0a,p02.0c,p02.0e,p02.10,p02.12,
    // Sending packet: $qsThreadInfo#c8...Packet received: l
    // [New Thread 2.18]
    // [Switching to Thread 2.16]
    // Sending packet: $z0,40140e,1#91...Packet received: OK
    // Sending packet: $z0,7ffff7fe3340,1#ce...Packet received: OK
    //
    // Even though gdb (client) said `[Switching to Thread 2.16]`, No packets
    // was sent to the server side (such as `Hgp2.16`) hence the server side
    // was completely unaware of the switching. Presumably gdb (client)
    // assumed *any* thread in the same process group and read/write memory,
    // but it is not necessarily true for us because we use different
    // channels to communicate between gdbstub <-> reverie. As a result
    // we switch current to thread `switch_to`, to simulate gdb's (client)
    // (mis)behavior.
    switch_to: Option<InferiorThreadId>,
}

enum HandleVcontResume {
    /// vCont resume not handled, this is possible because vCont can encode
    /// multiple actions, only the left-most action is used if it matches
    /// a given ptid.
    NotHandled,
    /// vCont matches a `ptid`.
    Handled(VcontResumeResult),
}

impl Session {
    /// Create a new session from root task.
    pub fn new(
        stream_tx: BoxWriter,
        pkt_rx: mpsc::Receiver<Packet>,
        gdb_stop_rx: mpsc::Receiver<StoppedInferior>,
    ) -> Self {
        Session {
            no_ack_mode: false,
            stream_tx,
            tx_buf: BytesMut::with_capacity(0x8000),
            pkt_rx: Some(pkt_rx),
            hostio_pid: None,
            bufsiz: 0x8000,
            inferiors: Arc::new(Mutex::new(BTreeMap::new())),
            current: None,
            gdb_stop_rx: Some(gdb_stop_rx),
        }
    }

    /// Get current inferior. GDB can select current inferior by `Hg<thread-id>`.
    async fn with_inferior<'a, F, Fut>(&'a self, threadid: ThreadId, f: F) -> Fut::Output
    where
        F: FnOnce(MappedMutexGuard<'a, Inferior>) -> Fut + 'a,
        Fut: Future + 'a,
    {
        let tid = threadid
            .gettid()
            .unwrap_or_else(|| threadid.getpid().unwrap());
        let inferiors = self.inferiors.lock().await;
        let inferior = MutexGuard::map(inferiors, |inferiors| inferiors.get_mut(&tid).unwrap());
        f(inferior).await
    }

    /// Get current inferior. GDB can select current inferior by `Hg<thread-id>`.
    async fn with_current_inferior<'a, F, Fut>(&'a self, f: F) -> Fut::Output
    where
        F: FnOnce(MappedMutexGuard<'a, Inferior>) -> Fut + 'a,
        Fut: Future + 'a,
    {
        let threadid: ThreadId = self.current.unwrap().into();
        self.with_inferior(threadid, f).await
    }

    /// create a new response writer
    fn response(&self, mut tx: BytesMut) -> ResponseWriter {
        ResponseWriter::new(tx.split(), self.no_ack_mode)
    }

    /// Detach or Kill all threads matching `threadid`.
    async fn detach_or_kill(&self, threadid: ThreadId, kill: bool) -> Result<(), Error> {
        let mut inferiors = self.inferiors.lock().await;
        let resume = ResumeInferior {
            action: if kill {
                ResumeAction::Continue(Some(Signal::SIGKILL))
            } else {
                ResumeAction::Continue(None)
            },
            detach: true,
        };
        for (_, inferior) in inferiors.iter_mut() {
            if inferior.matches(&threadid) {
                inferior.notify_resume(resume).await?;
            }
        }
        inferiors.retain(|_, inferior| !inferior.matches(&threadid));
        Ok(())
    }

    /// handle vCont resume
    async fn vcont_resume(
        &self,
        threadid: ThreadId,
        resume: ResumeInferior,
    ) -> Result<HandleVcontResume, Error> {
        let mut inferiors_to_resume: Vec<&mut Inferior> = Vec::new();
        let mut inferiors = self.inferiors.lock().await;

        match threadid.tid {
            // vCont a specific ptid, such as $vCont;c:p2.2#..
            IdKind::Id(tid) => {
                let inferior = inferiors.get_mut(&tid).ok_or(Error::UnknownThread(tid))?;
                inferiors_to_resume.push(inferior);
            }
            // Invalid vCont
            IdKind::Any => {
                return Err(Error::ThreadIdNotSpecified);
            }
            // vCont all threads, such as $vCont;c:p2.-1#10
            IdKind::All => match threadid.pid {
                IdKind::Id(pid) => {
                    for (_, inferior) in inferiors.iter_mut() {
                        if inferior.getpid() == pid {
                            inferiors_to_resume.push(inferior);
                        }
                    }
                }
                _ => return Err(Error::ThreadIdNotSpecified),
            },
        }

        if inferiors_to_resume.is_empty() {
            return Ok(HandleVcontResume::NotHandled);
        }

        let mut new_inferior: Option<Inferior> = None;
        let mut ptid_to_remove: Vec<ThreadId> = Vec::new();
        let mut switch_to: Option<InferiorThreadId> = None;
        let mut inferiors_to_wait = FuturesUnordered::new();

        for inferior in inferiors_to_resume {
            inferior.notify_resume(resume).await?;
            inferiors_to_wait.push(inferior.wait_for_stop());
        }

        let mut reason: Option<StopReason> = None;
        while let Some(stop_reason) = inferiors_to_wait.next().await {
            let mut stop_reason = stop_reason?;
            match &mut stop_reason {
                StopReason::ThreadExited(pid, tgid, _exit_status) => {
                    ptid_to_remove.push(ThreadId::pid_tid(tgid.as_raw(), pid.as_raw()));
                    // The thread exit event `w XX; ptid is not reported
                    continue;
                }
                StopReason::Exited(pid, _exit_staus) => {
                    ptid_to_remove.push(ThreadId::pid(pid.as_raw()));
                }
                StopReason::NewTask(new_task) => {
                    new_inferior = Some(match new_task.op {
                        ChildOp::Fork => Inferior {
                            id: InferiorThreadId::new(new_task.child, new_task.child),
                            resume_tx: new_task.resume_tx.take(),
                            request_tx: new_task.request_tx.take(),
                            stop_rx: new_task.stop_rx.take(),
                            resume_pending: false,
                        },
                        ChildOp::Vfork => Inferior {
                            id: InferiorThreadId::new(new_task.child, new_task.child),
                            resume_tx: new_task.resume_tx.take(),
                            request_tx: new_task.request_tx.take(),
                            stop_rx: new_task.stop_rx.take(),
                            resume_pending: false,
                        },
                        ChildOp::Clone => Inferior {
                            id: InferiorThreadId::new(new_task.child, new_task.tgid),
                            resume_tx: new_task.resume_tx.take(),
                            request_tx: new_task.request_tx.take(),
                            stop_rx: new_task.stop_rx.take(),
                            resume_pending: false,
                        },
                    });
                }

                StopReason::Stopped(stopped) => {
                    switch_to = Some(InferiorThreadId::new(stopped.pid, stopped.tgid));
                }
            }
            reason = Some(stop_reason);
            break;
        }
        Ok(HandleVcontResume::Handled(VcontResumeResult {
            reason: reason.unwrap(),
            new_inferior,
            ptid_to_remove,
            switch_to,
        }))
    }

    /// handle gdb remote base command
    async fn handle_base(&mut self, cmd: Base, writer: &mut ResponseWriter) -> Result<(), Error> {
        match cmd {
            Base::QuestionMark(_) => {
                writer.put_str("S05");
            }
            Base::QStartNoAckMode(_) => {
                self.no_ack_mode = true;
                writer.put_str("OK");
            }
            Base::qSupported(_) => {
                writer.put_str("PacketSize=8000;vContSupported+;multiprocess+;exec-events+;fork-events+;vfork-events+;QThreadEvents+;QStartNoAckMode+;swbreak+;qXfer:features:read+;qXfer:auxv:read+;");
            }
            Base::qXfer(request) => match request {
                qXfer::FeaturesRead { offset: _, len: _ } => {
                    // gdb/64bit-sse.xml
                    writer.put_str("l<target version=\"1.0\"><architecture>i386:x86-64</architecture><feature name=\"org.gnu.gdb.i386.sse\"></feature></target>");
                }
                qXfer::AuxvRead { offset, len } => {
                    if let Some(id) = self.current {
                        let buffer_size = std::cmp::min(self.bufsiz, len);
                        let mut auxv: Vec<u8> = vec![0; buffer_size];
                        if let Ok(nb) = fcntl::open(
                            format!("/proc/{}/auxv", id.pid).as_str(),
                            OFlag::O_RDONLY,
                            Mode::from_bits_truncate(0o644),
                        )
                        .and_then(|fd| {
                            let nb = uio::pread(fd, &mut auxv, offset as libc::off_t)?;
                            let _ = unistd::close(fd);
                            Ok(nb)
                        }) {
                            writer.put_str("l");
                            writer.put_binary_encoded(&auxv[..nb]);
                        }
                    }
                }
            },
            Base::qfThreadInfo(_) => {
                writer.put_str("m");
                for task in self.inferiors.lock().await.values() {
                    let threadid: ThreadId = task.id.into();
                    threadid.write_response(writer);
                    writer.put_str(",");
                }
            }
            Base::qsThreadInfo(_) => {
                writer.put_str("l");
            }
            Base::qAttached(_pid) => {
                writer.put_str("0");
            }
            Base::QThreadEvents(_thread_events) => {
                // NB: This should toggle reporting thread event, such as
                // `T05Create`, but I couldn't find any examples even with
                // vanilla gdbserver debugging threaded programs. gdb client
                // never send this command, even after I tried to run
                // `set remote thread-events on`, as described in gdb remote
                // protocol doc.
                writer.put_str("OK");
            }
            Base::qC(_) => {
                if let Some(id) = self.current {
                    let thread_id: ThreadId = id.into();
                    writer.put_str("QC");
                    thread_id.write_response(writer);
                }
            }
            Base::H(h) => {
                match h.op {
                    ThreadOp::g => {
                        // qeury or set current threadid.
                        if h.id.pid == IdKind::Any && h.id.tid == IdKind::Any {
                            ResponseOk.write_response(writer);
                        } else {
                            h.id.try_into()
                                .map(|id| {
                                    self.current = Some(id);
                                    ResponseOk
                                })
                                .write_response(writer)
                        }
                    }
                    _ => {
                        // Hc is deprecated, others not supported.
                        writer.put_str("E01");
                    }
                }
            }
            Base::g(_) => self
                .read_registers()
                .await
                .map(ResponseAsHex)
                .write_response(writer),
            Base::G(regs) => self
                .write_registers(regs.vals)
                .await
                .map(|_| ResponseOk)
                .write_response(writer),
            Base::m(m) => self
                .read_inferior_memory(m.addr, m.length)
                .await
                .map(ResponseAsHex)
                .write_response(writer),
            Base::M(mem) => self
                .write_inferior_memory(mem.addr, mem.length, mem.vals)
                .await
                .map(|_| ResponseOk)
                .write_response(writer),
            Base::X(mem) => self
                .write_inferior_memory(mem.addr, mem.length, mem.vals)
                .await
                .map(|_| ResponseOk)
                .write_response(writer),
            // NB: detach is a resume, but we don't care about receiving
            // further (gdb) stop events.
            Base::D(pid) => {
                let pid = pid.pid;
                let threadid = pid.map_or_else(ThreadId::all, |pid| ThreadId::pid(pid.as_raw()));
                self.detach_or_kill(threadid, false)
                    .await
                    .map(|_| ResponseOk)
                    .write_response(writer);
            }
            Base::z(bkpt) => {
                if bkpt.ty == BreakpointType::Software {
                    let bkpt = Breakpoint {
                        ty: BreakpointType::Software,
                        addr: bkpt.addr,
                        bytecode: None,
                    };
                    self.remove_breakpoint(bkpt)
                        .await
                        .map(|_| ResponseOk)
                        .write_response(writer);
                }
            }
            Base::Z(bkpt) => {
                if bkpt.ty == BreakpointType::Software {
                    let bkpt = Breakpoint {
                        ty: BreakpointType::Software,
                        addr: bkpt.addr,
                        bytecode: None,
                    };
                    self.set_breakpoint(bkpt)
                        .await
                        .map(|_| ResponseOk)
                        .write_response(writer);
                }
            }
            // NB: kill is a resume(SIGKILL), but we don't care about
            // receiving further (gdb) stop events.
            Base::vKill(pid) => {
                let threadid = ThreadId::pid(pid.pid.as_raw());
                self.detach_or_kill(threadid, true)
                    .await
                    .map(|_| ResponseOk)
                    .write_response(writer);
            }
            Base::vCont(vcont) => match vcont {
                vCont::Query => {
                    writer.put_str("vCont;c;C;s;S");
                }
                vCont::Actions(actions) => {
                    // `vCont` can encode multiple actions, but we should
                    // resume only one matching ptid only (left-most).
                    while let Some((action, threadid)) = actions.first() {
                        let resume = match action {
                            ResumeAction::Step(step) => ResumeInferior {
                                action: ResumeAction::Step(*step),
                                detach: false,
                            },
                            ResumeAction::Continue(cont) => ResumeInferior {
                                action: ResumeAction::Continue(*cont),
                                detach: false,
                            },
                            not_supported => {
                                // Shouldn't reach here because only `c;C;s:S` are advertised.
                                panic!("Unsupported vCont command: {:?}", not_supported);
                            }
                        };
                        match self.vcont_resume(*threadid, resume).await? {
                            HandleVcontResume::NotHandled => {}
                            HandleVcontResume::Handled(VcontResumeResult {
                                reason,
                                new_inferior,
                                ptid_to_remove,
                                switch_to,
                            }) => {
                                let mut inferiors = self.inferiors.lock().await;
                                for ptid in ptid_to_remove {
                                    if let Some(tid) = ptid.gettid() {
                                        let _ = inferiors.remove(&tid);
                                    } else {
                                        inferiors.retain(|_, inferior| !inferior.matches(&ptid));
                                    }
                                }
                                if let Some(new_inferior) = new_inferior {
                                    inferiors.insert(new_inferior.gettid(), new_inferior);
                                }
                                if let Some(switch_to) = switch_to {
                                    self.current = Some(switch_to);
                                }
                                reason.write_response(writer);
                                break;
                            }
                        }
                    }
                }
            },
            // TODO T92309086: implement ACL for hostio.
            Base::vFile(hostio) => match hostio {
                vFile::Setfs(pid) => {
                    match pid {
                        Some(pid) => {
                            self.hostio_pid = Some(Pid::from_raw(pid));
                        }
                        None => {
                            self.hostio_pid = self.current.as_ref().map(|x| x.pid);
                        }
                    }
                    writer.put_str("F0");
                }
                vFile::Open(fname, flags, mode) => {
                    let oflag = OFlag::from_bits_truncate(flags);
                    let mode = Mode::from_bits_truncate(mode);
                    writer.put_str("F");
                    match fcntl::open(&fname, oflag, mode) {
                        Ok(fd) => writer.put_num(fd),
                        Err(_) => writer.put_str("-1"),
                    }
                }
                vFile::Close(fd) => {
                    writer.put_str(unistd::close(fd).map_or("F-1", |_| "F0"));
                }
                vFile::Pread(fd, count, offset) => {
                    let count = std::cmp::min(count as usize, self.bufsiz);
                    let mut buf: Vec<u8> = vec![0; count];
                    match uio::pread(fd, &mut buf, offset as i64) {
                        Ok(nb) => {
                            writer.put_str("F");
                            writer.put_num(nb);
                            writer.put_str(";");
                            writer.put_binary_encoded(&buf[..nb]);
                        }
                        Err(_) => {
                            writer.put_str("F-1");
                        }
                    }
                }
                vFile::Pwrite(fd, offset, data) => match uio::pwrite(fd, &data, offset as i64) {
                    Ok(nb) => {
                        writer.put_str("F");
                        writer.put_num(nb);
                    }
                    Err(_) => {
                        writer.put_str("F-1");
                    }
                },
                vFile::Unlink(fname) => {
                    writer.put_str(unistd::unlink(&fname).map_or("F-1", |_| "F0"));
                }
                vFile::Readlink(fname) => {
                    match fcntl::readlink(&fname)
                        .ok()
                        .and_then(|s| s.to_str().map(|s| s.as_bytes().to_vec()))
                    {
                        Some(bytes) => {
                            writer.put_str("F");
                            writer.put_num(bytes.len());
                            writer.put_str(";");
                            writer.put_binary_encoded(&bytes)
                        }
                        None => {
                            writer.put_str("F-1");
                        }
                    }
                }
                vFile::Fstat(fd) => {
                    // NB: HostioStat is not the same as FileStat.
                    const STAT_SIZE: usize = std::mem::size_of::<HostioStat>();
                    match stat::fstat(fd).ok().map(|st| {
                        let st: HostioStat = st.into();
                        let bytes: [u8; STAT_SIZE] = unsafe { std::mem::transmute(st) };
                        bytes
                    }) {
                        Some(bytes) => {
                            writer.put_str("F");
                            writer.put_num(STAT_SIZE);
                            writer.put_str(";");
                            writer.put_binary_encoded(&bytes);
                        }
                        None => {
                            writer.put_str("F-1");
                        }
                    }
                }
            },
        }
        Ok(())
    }

    /// handle gdb remote extended mode command
    async fn handle_extended_mode(
        &mut self,
        cmd: ExtendedMode,
        writer: &mut ResponseWriter,
    ) -> Result<(), Error> {
        match cmd {
            ExtendedMode::ExclamationMark(_) => {
                writer.put_str("OK");
            }
            ExtendedMode::QDisableRandomization(disable_aslr) => {
                // ASLR is always disabled by reverie.
                if disable_aslr.val {
                    writer.put_str("OK");
                } else {
                    writer.put_str("E22");
                }
            }
        }
        Ok(())
    }

    /// handle gdb remote monitor command
    async fn handle_monitor_cmd(
        &mut self,
        cmd: MonitorCmd,
        _writer: &mut ResponseWriter,
    ) -> Result<(), Error> {
        match cmd {
            MonitorCmd::qRcmd(_) => {
                unimplemented!()
            }
        }
    }

    /// handle gdb remote section offset command
    async fn handle_section_offsets(
        &mut self,
        cmd: SectionOffsets,
        writer: &mut ResponseWriter,
    ) -> Result<(), Error> {
        match cmd {
            // should use libraries-svr4:read instead
            SectionOffsets::qOffsets(_) => {
                writer.put_str("");
            }
        }
        Ok(())
    }

    /// handle gdb remote command
    async fn handle_command(
        &mut self,
        cmd: commands::Command,
        resp: BytesMut,
    ) -> Result<Bytes, Error> {
        let mut writer = self.response(resp);
        match cmd {
            Command::Unknown(cmd) => {
                tracing::info!("Unknown command: {:?}", cmd);
            }
            Command::Base(cmd) => self.handle_base(cmd, &mut writer).await?,
            Command::ExtendedMode(cmd) => self.handle_extended_mode(cmd, &mut writer).await?,
            Command::MonitorCmd(cmd) => self.handle_monitor_cmd(cmd, &mut writer).await?,
            Command::SectionOffsets(cmd) => self.handle_section_offsets(cmd, &mut writer).await?,
        };
        Ok(writer.finish())
    }

    /// Handle incoming request sent over tcp stream
    pub async fn run(&mut self) -> Result<(), Error> {
        let cmd_rx = self.pkt_rx.take().unwrap();

        let mut gdb_stop_rx = self.gdb_stop_rx.take().ok_or(Error::Detached)?;
        let stop_reason = gdb_stop_rx.recv().await.ok_or(Error::Detached)?;

        // set initial task as current attached task.
        match stop_reason.reason {
            StopReason::Stopped(stopped) => {
                let id = InferiorThreadId::new(stopped.pid, stopped.tgid);
                self.current = Some(id);
                let mut inferior = Inferior::new(id);
                inferior.request_tx = Some(stop_reason.request_tx);
                inferior.resume_tx = Some(stop_reason.resume_tx);
                inferior.stop_rx = Some(gdb_stop_rx);
                self.inferiors.lock().await.insert(id.tid, inferior);
            }
            _ => unreachable!(),
        }

        self.handle_gdb_commands(cmd_rx).await
    }

    async fn handle_gdb_commands(
        &mut self,
        mut cmd_rx: mpsc::Receiver<Packet>,
    ) -> Result<(), Error> {
        let mut tx_buf = BytesMut::with_capacity(0x8000);

        while let Some(pkt) = cmd_rx.recv().await {
            match pkt {
                Packet::Ack => {}
                Packet::Nack => {
                    panic!("client send Nack")
                }
                // handle interrupt
                Packet::Interrupt => {}
                Packet::Command(cmd) => {
                    tx_buf.clear();
                    let resp = self.handle_command(cmd, tx_buf.clone()).await?;
                    self.stream_tx.write_all(&resp).await.unwrap();
                }
            }
        }
        Ok(())
    }

    /// Set a breakpoint. must have an active inferior.
    async fn set_breakpoint(&self, bkpt: Breakpoint) -> Result<(), Error> {
        self.with_current_inferior(async move |inferior| {
            let request_tx = inferior
                .request_tx
                .as_ref()
                .ok_or(Error::SessionNotStarted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            let request = GdbRequest::SetBreakpoint(
                Breakpoint {
                    ty: BreakpointType::Software,
                    addr: bkpt.addr,
                    bytecode: None,
                },
                reply_tx,
            );
            let _ = request_tx
                .send(request)
                .await
                .map_err(|_| Error::GdbRequestSendError)?;
            let reply = reply_rx.await.map_err(|_| Error::GdbRequestRecvError)??;
            Ok(reply)
        })
        .await
    }

    async fn remove_breakpoint(&self, bkpt: Breakpoint) -> Result<(), Error> {
        self.with_current_inferior(async move |inferior| {
            let request_tx = inferior
                .request_tx
                .as_ref()
                .ok_or(Error::SessionNotStarted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            let request = GdbRequest::RemoveBreakpoint(
                Breakpoint {
                    ty: BreakpointType::Software,
                    addr: bkpt.addr,
                    bytecode: None,
                },
                reply_tx,
            );
            request_tx
                .send(request)
                .await
                .map_err(|_| Error::GdbRequestSendError)?;
            let reply = reply_rx.await.map_err(|_| Error::GdbRequestRecvError)??;

            Ok(reply)
        })
        .await
    }

    async fn read_inferior_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, Error> {
        self.with_current_inferior(async move |inferior| {
            let request_tx = inferior
                .request_tx
                .as_ref()
                .ok_or(Error::SessionNotStarted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            let request = GdbRequest::ReadInferiorMemory(addr, size, reply_tx);
            let _ = request_tx
                .send(request)
                .await
                .map_err(|_| Error::GdbRequestSendError)?;
            let reply = reply_rx.await.map_err(|_| Error::GdbRequestRecvError)??;
            Ok(reply)
        })
        .await
    }

    async fn write_inferior_memory(
        &self,
        addr: u64,
        size: usize,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let data = data.clone();
        self.with_current_inferior(async move |inferior| {
            let request_tx = inferior
                .request_tx
                .as_ref()
                .ok_or(Error::SessionNotStarted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            let request = GdbRequest::WriteInferiorMemory(addr, size, data, reply_tx);
            let _ = request_tx
                .send(request)
                .await
                .map_err(|_| Error::GdbRequestSendError)?;
            let reply = reply_rx.await.map_err(|_| Error::GdbRequestRecvError)??;
            Ok(reply)
        })
        .await
    }

    async fn read_registers(&self) -> Result<Amd64CoreRegs, Error> {
        self.with_current_inferior(async move |inferior| {
            let request_tx = inferior
                .request_tx
                .as_ref()
                .ok_or(Error::SessionNotStarted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            let request = GdbRequest::ReadRegisters(reply_tx);
            let _ = request_tx
                .send(request)
                .await
                .map_err(|_| Error::GdbRequestSendError)?;
            let reply = reply_rx.await.map_err(|_| Error::GdbRequestRecvError)??;
            Ok(reply)
        })
        .await
    }

    async fn write_registers(&self, regs: Vec<u8>) -> Result<(), Error> {
        self.with_current_inferior(async move |inferior| {
            let regs = regs.as_slice();
            let request_tx = inferior
                .request_tx
                .as_ref()
                .ok_or(Error::SessionNotStarted)?;
            let (reply_tx, reply_rx) = oneshot::channel();
            let core_regs: Amd64CoreRegs =
                bincode::deserialize(regs).map_err(|_| CommandParseError::MalformedRegisters)?;
            let request = GdbRequest::WriteRegisters(core_regs, reply_tx);
            let _ = request_tx
                .send(request)
                .await
                .map_err(|_| Error::GdbRequestSendError)?;
            let reply = reply_rx.await.map_err(|_| Error::GdbRequestRecvError)??;
            Ok(reply)
        })
        .await
    }
}
