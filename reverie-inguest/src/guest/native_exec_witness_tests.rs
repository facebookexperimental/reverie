/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! S2a-1 physical failed-exec witness (dual advance ruling, Muse
//! C1-C5 + Astra conditions): a genuine SIGSYS receipt enters the
//! admitted ToolHost's normal dispatch, preparation uses the real
//! collectors and FD leases, a real failable final check runs, and
//! the real leaf issues the exact original exec against a missing
//! path. The guest receives the kernel's untagged ENOENT and its
//! next subscribed syscall is physically intercepted by the same
//! Tool. Ticket/Issue authority is MODELED locally (one-use record,
//! never guest-visible, never redeemed — no successor is born on
//! this path); this witness claims only those three observables and
//! no coordinator, ticket-security, or successor behavior. The
//! driver and issue activation in this file are test-only; the
//! production final refusal is untouched (see native_exec.rs).

use std::collections::HashSet;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use super::*;
use crate::guest::context::RegisterContext;
use crate::guest::continuation;
use crate::guest::event::InstructionEventKind;
use crate::guest::exec_private;
use crate::guest::native_exec::ExecCut;
use crate::guest::native_exec::NativeExecDriver;
use crate::guest::native_exec::NativeExecFailure;
use crate::guest::native_exec::NativeExecSession;
use crate::guest::native_exec::PreparedNativeExec;
use crate::guest::native_exec::ReturnedNativeExec;
use crate::guest::native_exec::TerminalExecFailure;
use crate::guest::native_exec_arguments::ArgumentImage;
use crate::guest::native_exec_arguments::ArgumentQuiescence;
use crate::guest::native_exec_arguments::ArgumentRange;
use crate::guest::native_exec_arguments::OriginalExecArguments;
use crate::guest::native_exec_arguments::ReadCapture;
use crate::guest::native_exec_fds::BootstrapFdLease;
use crate::guest::native_exec_fds::FdIdentity;
use crate::guest::native_exec_fds::NativeExecSocketBindings;
use crate::guest::native_exec_fds::NativeSocket;
use crate::guest::native_exec_mappings::ExecutableMappings;
use crate::trap::frame::SignalFrame;

const SENTINEL_PID: i64 = 424_242;
const CONFIG: u64 = 903;
const RESUME_MASK: u64 = 1_u64 << (libc::SIGUSR1 - 1);
const CHILD_ENV: &str = "REVERIE_NATIVE_EXEC_WITNESS";
const MODE_ENV: &str = "REVERIE_NATIVE_EXEC_WITNESS_MODE";

static HOST_PTR: AtomicUsize = AtomicUsize::new(0);
static SEQ: [AtomicI64; 8] = [const { AtomicI64::new(0) }; 8];
static SEQ_COUNT: AtomicU64 = AtomicU64::new(0);
static EXEC_ERRNO: AtomicI64 = AtomicI64::new(0);
/// -2 unset, -1 none (genuine errno), else UnsupportedOperation code.
static EXEC_REFUSAL: AtomicI64 = AtomicI64::new(-2);
static ISSUED: AtomicU64 = AtomicU64::new(0);
static THREADS_PREPARE: AtomicU64 = AtomicU64::new(0);
static THREADS_FINAL: AtomicU64 = AtomicU64::new(0);
static LIFECYCLE: AtomicU64 = AtomicU64::new(0);
static TAMPER: AtomicU64 = AtomicU64::new(0); // 1 digest, 2 sequence

const TAMPER_DIGEST: u64 = 1;
const TAMPER_SEQUENCE: u64 = 2;
const TAMPER_PREPARE_SOURCES: u64 = 3;
const TAMPER_PKRU: u64 = 4;
const TAMPER_ROLLBACK: u64 = 5;

fn refusal_code(operation: reverie::UnsupportedOperation) -> i64 {
    match operation {
        reverie::UnsupportedOperation::Exec => 1,
        reverie::UnsupportedOperation::NativeExec => 2,
        reverie::UnsupportedOperation::ThreadCreation => 3,
        _ => 9,
    }
}

#[derive(Default)]
struct WitnessGlobal;
#[reverie::tool]
impl GlobalTool for WitnessGlobal {
    type Request = u64;
    type Response = u64;
    type Config = u64;
    async fn receive_rpc(&self, _from: Pid, message: u64) -> u64 {
        message
    }
}

#[derive(Default)]
struct WitnessTool;
#[reverie::tool]
impl Tool for WitnessTool {
    type GlobalState = WitnessGlobal;
    type ThreadState = (u64, u64);
    fn init_thread_state(&self, _tid: Pid, _parent: Option<(Pid, &(u64, u64))>) -> (u64, u64) {
        (3, 1)
    }
    async fn handle_thread_start<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Error> {
        LIFECYCLE.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, _guest: &mut G) -> Result<(), Errno> {
        LIFECYCLE.fetch_add(10, Ordering::Relaxed);
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let (number, args) = call.into_parts();
        let index = SEQ_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
        if index < SEQ.len() {
            SEQ[index].store(number.id() as i64, Ordering::Relaxed);
        }
        if number == Sysno::getpid {
            // Directly observe the old Tool tuple at this genuine
            // next callback (restored (3,1) after a correct rollback).
            let observed = *guest.thread_state();
            STATE_AT_NEXT_0.store(observed.0, Ordering::Relaxed);
            STATE_AT_NEXT_1.store(observed.1, Ordering::Relaxed);
            // Observable Tool effect: raw passthrough would return the
            // real pid; only genuine Tool mediation yields the sentinel.
            return Ok(SENTINEL_PID);
        }
        // Model prepared replacement, as the mock battery does: the
        // driver binds its prepared-state digest to exactly this.
        *guest.thread_state_mut() = (4, 2);
        let mut injected = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        if number == Sysno::execve {
            injected = [
                libc::AT_FDCWD as i64 as u64,
                injected[0],
                injected[1],
                injected[2],
                0,
                0,
            ];
        }
        let normalized = Syscall::from_raw(
            Sysno::execveat,
            SyscallArgs::new(
                injected[0] as usize,
                injected[1] as usize,
                injected[2] as usize,
                injected[3] as usize,
                injected[4] as usize,
                injected[5] as usize,
            ),
        );
        let errno = guest.inject(normalized).await.unwrap_err();
        let refusal = guest.take_unsupported_refusal();
        if let Some(refusal) = &refusal {
            // Direct stderr diagnostic (raw gate): which leg refused.
            let diag = refusal.diagnostic.as_bytes();
            unsafe {
                crate::trap::raw_syscall6(
                    libc::SYS_write,
                    [2, b"WITNESS-DIAG ".as_ptr() as u64, 13, 0, 0, 0],
                );
                crate::trap::raw_syscall6(
                    libc::SYS_write,
                    [2, diag.as_ptr() as u64, diag.len() as u64, 0, 0, 0],
                );
                crate::trap::raw_syscall6(libc::SYS_write, [2, b"\n".as_ptr() as u64, 1, 0, 0, 0]);
            }
        }
        EXEC_ERRNO.store(errno.into_raw() as i64, Ordering::Relaxed);
        EXEC_REFUSAL.store(
            refusal.map_or(-1, |r| refusal_code(r.operation)),
            Ordering::Relaxed,
        );
        if TAMPER.load(Ordering::Relaxed) != TAMPER_ROLLBACK {
            *guest.thread_state_mut() = (3, 1);
        }
        Ok(-i64::from(errno.into_raw()))
    }
}

/// Runtime copied from the mock battery: no clock, no fork support.
struct WitnessRuntime;
impl HostRuntime for WitnessRuntime {
    fn fork_child_rebind(&self) {
        panic!("witness does not fork inside the guest")
    }
    fn emit_stage(&self, _stage: &[u8]) {}
    fn fork_child_reset(&self, _event: &SyscallEvent) {
        panic!("witness does not fork inside the guest")
    }
    fn cpuid_interception_enabled(&self) -> bool {
        false
    }
    fn exit_process_stats(&self, _tid: Pid) -> io::Result<()> {
        Ok(())
    }
    fn read_clock(&self) -> io::Result<u64> {
        panic!("witness observes no clock")
    }
    fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
        crate::guest::signal::signal_action_supported(number, args)
    }
    fn reserved_signal_mask(&self) -> u64 {
        1_u64 << (libc::SIGSYS - 1)
    }
}

fn named(text: &'static str) -> reverie::UnsupportedRefusal {
    reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::NativeExec,
        Errno::EOPNOTSUPP,
        text,
    )
}
fn refused(text: &'static str) -> NativeExecFailure {
    NativeExecFailure::Refused(named(text))
}
fn terminal(text: &'static str) -> NativeExecFailure {
    NativeExecFailure::Terminal(TerminalExecFailure { diagnostic: text })
}

/// Thread count from /proc/self/status through the gated raw path:
/// the quiescence witness. Stack buffers only, no allocation.
fn thread_count() -> u64 {
    let path = b"/proc/self/status\0";
    let fd = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as i64 as u64,
                path.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return 0;
    }
    let mut buffer = [0_u8; 2048];
    let read = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_read,
            [
                fd as u64,
                buffer.as_mut_ptr() as u64,
                buffer.len() as u64,
                0,
                0,
                0,
            ],
        )
    };
    unsafe { crate::trap::raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    if read <= 0 {
        return 0;
    }
    let text = &buffer[..read as usize];
    let needle = b"Threads:";
    for window in text.windows(needle.len()) {
        if window == needle {
            let mut value = 0_u64;
            for byte in &text[needle.len() + (window.as_ptr() as usize - text.as_ptr() as usize)..]
            {
                match byte {
                    b'0'..=b'9' => value = value * 10 + u64::from(*byte - b'0'),
                    b'\n' => return value,
                    _ => {}
                }
            }
            return value;
        }
    }
    0
}

fn state_digest(state: &(u64, u64), cut: &ExecCut, ticket: &[u8; 32], sequence: u64) -> [u8; 32] {
    let original = cut.original();
    let mut bytes = [0_u8; 8 * 11 + 32];
    let fields = [
        state.0,
        state.1,
        CONFIG,
        original.number() as u64,
        original.args()[0],
        original.args()[1],
        original.args()[2],
        original.args()[3],
        original.args()[4],
        original.args()[5],
        sequence,
    ];
    for (index, field) in fields.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&field.to_be_bytes());
    }
    bytes[88..].copy_from_slice(ticket);
    reverie_rpc_transport::initial_image::config_digest(&bytes)
}

/// Retained driver authority for the witness (leaked to 'static in the
/// fixture process; the genuine installer owns this in production).
struct Authority {
    protected: Vec<ArgumentRange>,
    expected_detlog: (u64, u64),
    expected_observer: (u64, u64),
    catalog: Option<ExecutableMappings>,
}

struct WitnessDriver {
    authority: &'static Authority,
    sequence: &'static AtomicU64,
}

struct WitnessSession {
    sequence: &'static AtomicU64,
    cut: ExecCut,
    captured_sequence: u64,
    arguments: Mutex<OriginalExecArguments<'static>>,
    sockets: NativeExecSocketBindings,
}

struct WitnessTransaction<'a> {
    session: &'a mut WitnessSession,
    lease: BootstrapFdLease,
    ticket: Option<[u8; 32]>,
    digest: [u8; 32],
    issued: bool,
    cancelled: bool,
}

impl Drop for WitnessTransaction<'_> {
    fn drop(&mut self) {
        // Host PreparedAttempt terminates on abandonment before this
        // can matter; a live lease here means test-driver misuse.
        assert!(self.cancelled, "witness transaction dropped uncancelled");
    }
}

impl WitnessSession {
    fn check_arguments(&self, cut: &ExecCut) -> Result<(), NativeExecFailure> {
        let mut arguments = self
            .arguments
            .try_lock()
            .map_err(|_| terminal("witness argument receipt is busy"))?;
        arguments
            .recheck(cut.original())
            .map_err(|_| terminal("witness original argument mappings or bytes changed"))?;
        if arguments.image().physical_tid != cut.native().native_tid
            || arguments.image().mm_id != (cut.native().native_tid, 1)
        {
            return Err(terminal("witness original image binding changed"));
        }
        Ok(())
    }
    fn final_check(
        &self,
        state: &(u64, u64),
        cut: &ExecCut,
        lease: &BootstrapFdLease,
        ticket: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<(), NativeExecFailure> {
        if cut != &self.cut || *state != (4, 2) {
            return Err(refused("witness final cut or prepared state changed"));
        }
        self.check_arguments(cut)?;
        lease
            .revalidate()
            .map_err(|_| terminal("witness final bootstrap ownership changed"))?;
        if self.sequence.load(Ordering::Acquire) != self.captured_sequence {
            return Err(refused("witness final dispatch sequence changed"));
        }
        if state_digest(state, cut, ticket, self.captured_sequence) != *digest {
            return Err(refused("witness final exact prepared-state digest changed"));
        }
        Ok(())
    }
}

// SAFETY: test-only driver for the S2a-1 witness fixture. It runs in
// the fixture's own respawned process under the genuine quiescent
// cut; ticket authority is modeled locally (see module header) and
// no production installer can reach this type.
unsafe impl NativeExecDriver<WitnessTool> for WitnessDriver {
    fn bind_initial_state(
        &self,
        _tool: &WitnessTool,
        state: &mut (u64, u64),
        physical_tid: i32,
    ) -> std::io::Result<()> {
        if physical_tid != raw_pid(libc::SYS_gettid).as_raw() || *state != (3, 1) {
            return Err(io::Error::other("witness initial physical state differs"));
        }
        Ok(())
    }

    fn bind_post_exec_state(
        &self,
        state: &mut (u64, u64),
        mode: reverie::BackendSignalControlMode,
        actual: Option<reverie::SignalTaskIdentity>,
    ) -> std::io::Result<()> {
        // Fresh-image binding only: the InitialImage lifecycle guest
        // offers no backend signal control and no task identity, and
        // the just-initialized state must still be the initial tuple.
        if *state != (3, 1)
            || mode != reverie::BackendSignalControlMode::Unchanged
            || actual.is_some_and(|identity| identity.tid != raw_pid(libc::SYS_gettid))
        {
            return Err(std::io::Error::other(
                "witness fresh signal-state binding differs",
            ));
        }
        Ok(())
    }

    fn check_mapping(
        &self,
        number: i64,
        args: [u64; 6],
    ) -> Result<(), reverie::UnsupportedRefusal> {
        match &self.authority.catalog {
            Some(catalog) => catalog.check(number, args).map_err(named),
            None => {
                if matches!(
                    number,
                    libc::SYS_mmap
                        | libc::SYS_mprotect
                        | libc::SYS_pkey_mprotect
                        | libc::SYS_shmat
                        | libc::SYS_remap_file_pages
                        | libc::SYS_personality
                ) {
                    Err(named("witness executable mapping catalog is absent"))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn capture_old<'owner>(
        &'owner self,
        _tool: &WitnessTool,
        state: &(u64, u64),
        cut: &ExecCut,
        rpc: &CoordinatorRpc<WitnessGlobal>,
    ) -> Result<Box<dyn NativeExecSession<WitnessTool> + 'owner>, reverie::UnsupportedRefusal> {
        if *rpc.config() != CONFIG || *state != (3, 1) || !cut.is_fallback() {
            return Err(named("witness old state, Config or frontend differs"));
        }
        let image = ArgumentImage {
            physical_pid: cut.native().native_tid,
            physical_tid: cut.native().native_tid,
            mm_id: (cut.native().native_tid, 1),
            image_epoch: 1,
        };
        let read_capture = match cut.original().pkru() {
            Some(value) if value & 1 == 0 => ReadCapture::SavedPkru,
            None => ReadCapture::ScalarFrontendWithoutPkru,
            _ => return Err(named("witness original PKRU has no read rights")),
        };
        // SAFETY: fixture owner token; the leaked Authority outlives
        // the session, protected ranges name this fixture's actual
        // host/control/driver storage, and the respawned process is
        // single-threaded with no guest handler or mapping mutation
        // outside dispatch (asserted again in prepare).
        let lease = unsafe {
            ArgumentQuiescence::new(
                image,
                &self.authority.protected,
                read_capture,
                self.authority,
            )
        }
        .map_err(|_| named("witness argument owner or read rights differ"))?;
        let arguments = OriginalExecArguments::capture(cut.original(), lease)
            .map_err(|_| named("witness original argument memory is unsupported"))?;
        // Deliberate divergence from the Detcore catalog: no declared
        // target set. Shape qualification only; existence is the
        // kernel's decision at the leaf (that is the witness).
        let declared_ptr = DECLARED_PTR.load(Ordering::Acquire);
        let declared_len = DECLARED_LEN.load(Ordering::Relaxed) as usize;
        if declared_ptr == 0 || declared_len == 0 {
            return Err(named("witness has no declared target"));
        }
        // SAFETY: the fixture leaked exactly these bytes before
        // arming and never frees or mutates them.
        let declared =
            unsafe { core::slice::from_raw_parts(declared_ptr as *const u8, declared_len) };
        if arguments.path() != declared {
            return Err(named("witness original path is not the declared target"));
        }
        if arguments.envp().any(|entry| {
            let name = entry.split(|byte| *byte == b'=').next().unwrap_or(entry);
            name.starts_with(b"LD_") || name == b"GLIBC_TUNABLES"
        }) {
            return Err(named(
                "witness loader-sensitive environment is outside the domain",
            ));
        }
        let sockets = NativeExecSocketBindings::capture(
            self.authority.expected_detlog,
            self.authority.expected_observer,
        )
        .map_err(|_| named("witness protected socket bindings differ"))?;
        let captured_sequence = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
        Ok(Box::new(WitnessSession {
            sequence: self.sequence,
            cut: *cut,
            captured_sequence,
            arguments: Mutex::new(arguments),
            sockets,
        }))
    }
}

// SAFETY: session retains the real capture receipt and lease owner;
// every phase rechecks live state, as in the production template.
unsafe impl NativeExecSession<WitnessTool> for WitnessSession {
    fn prepare<'a>(
        &'a mut self,
        _tool: &WitnessTool,
        state: &(u64, u64),
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<WitnessGlobal>,
    ) -> Result<Box<dyn PreparedNativeExec<WitnessTool> + 'a>, NativeExecFailure> {
        if cut != &self.cut || *state != (4, 2) {
            return Err(refused("witness prepared state differs from capture"));
        }
        self.check_arguments(cut)?;
        self.sockets
            .revalidate_original()
            .map_err(|_| refused("witness protected sockets changed before reservation"))?;
        let threads = thread_count();
        THREADS_PREPARE.store(threads, Ordering::Relaxed);
        if threads != 1 {
            return Err(refused("witness dispatch is not exclusively quiescent"));
        }
        // SAFETY: exclusive quiescent leader callback (asserted
        // single-threaded above); fixed raw gates are installed.
        let mut lease = unsafe { BootstrapFdLease::reserve() }
            .map_err(|_| refused("witness bootstrap descriptors cannot be reserved"))?;
        lease
            .prepare_socket_inheritance(self.sockets)
            .map_err(|_| terminal("witness protected socket inheritance failed"))?;
        // Bootstrap sources: five distinct CLOEXEC regular files.
        // Source 0 carries the exact prepared-state encoding; the
        // kernel never consumes them on the failed-exec path. Every
        // error exit below closes exactly the sources created so
        // far (single cleanup site after the labeled block).
        let mut sources = [0_i32; 5];
        let mut created = 0_usize;
        let sources_result = 'sources: {
            for index in 0..sources.len() {
                let forced = TAMPER.load(Ordering::Relaxed) == TAMPER_PREPARE_SOURCES && index == 2;
                let fd = if forced {
                    -1
                } else {
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_memfd_create,
                            [c"w".as_ptr() as u64, libc::MFD_CLOEXEC as u64, 0, 0, 0, 0],
                        )
                    }
                };
                if fd < 0 {
                    break 'sources Err(refused("witness bootstrap source cannot be created"));
                }
                sources[index] = fd as i32;
                created += 1;
                if index == 0 {
                    let mut encoded = [0_u8; 24];
                    encoded[0..8].copy_from_slice(&state.0.to_be_bytes());
                    encoded[8..16].copy_from_slice(&state.1.to_be_bytes());
                    encoded[16..24].copy_from_slice(&self.captured_sequence.to_be_bytes());
                    let written = unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_write,
                            [
                                sources[0] as u64,
                                encoded.as_ptr() as u64,
                                encoded.len() as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    };
                    if written != encoded.len() as i64 {
                        break 'sources Err(refused("witness bootstrap source cannot be written"));
                    }
                }
            }
            Ok(())
        };
        if let Err(error) = sources_result {
            for source in &sources[..created] {
                unsafe {
                    crate::trap::raw_syscall6(libc::SYS_close, [*source as u64, 0, 0, 0, 0, 0])
                };
            }
            lease
                .cancel()
                .map_err(|_| terminal("witness source cleanup failed"))?;
            return Err(error);
        }
        // SAFETY: distinct owned CLOEXEC regular sources just created
        // above; none aliases a reserved descriptor.
        let installed = unsafe { lease.install(sources) };
        for source in sources {
            unsafe { crate::trap::raw_syscall6(libc::SYS_close, [source as u64, 0, 0, 0, 0, 0]) };
        }
        if installed.is_err() {
            lease
                .cancel()
                .map_err(|_| terminal("witness install cleanup failed"))?;
            return Err(refused("witness bootstrap sources cannot be installed"));
        }
        // Modeled one-use ticket: locally generated, bound into the
        // exact-state digest, never guest-visible, never redeemed.
        let mut ticket = [0_u8; 32];
        let drawn = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_getrandom,
                [ticket.as_mut_ptr() as u64, ticket.len() as u64, 0, 0, 0, 0],
            )
        };
        if drawn != ticket.len() as i64 || ticket == [0; 32] {
            lease
                .cancel()
                .map_err(|_| terminal("witness ticket cleanup failed"))?;
            return Err(refused("witness ticket cannot be generated"));
        }
        let mut digest = state_digest(state, cut, &ticket, self.captured_sequence);
        if TAMPER.load(Ordering::Relaxed) == TAMPER_DIGEST {
            digest[0] ^= 1;
        }
        if TAMPER.load(Ordering::Relaxed) == TAMPER_SEQUENCE {
            self.sequence.fetch_add(1, Ordering::AcqRel);
        }
        Ok(Box::new(WitnessTransaction {
            session: self,
            lease,
            ticket: Some(ticket),
            digest,
            issued: false,
            cancelled: false,
        }))
    }
}

// SAFETY: modeled local Issue only; the physical leaf and all
// collector/lease effects are real (see module header).
unsafe impl PreparedNativeExec<WitnessTool> for WitnessTransaction<'_> {
    fn revalidate(
        &mut self,
        _tool: &WitnessTool,
        state: &(u64, u64),
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<WitnessGlobal>,
    ) -> Result<(), NativeExecFailure> {
        THREADS_FINAL.store(thread_count(), Ordering::Relaxed);
        let ticket = self
            .ticket
            .ok_or_else(|| terminal("witness ticket already consumed"))?;
        self.session
            .final_check(state, cut, &self.lease, &ticket, &self.digest)
    }

    unsafe fn issue_and_call(
        &mut self,
        _tool: &WitnessTool,
        state: &(u64, u64),
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<WitnessGlobal>,
    ) -> Result<ReturnedNativeExec, NativeExecFailure> {
        if core::mem::replace(&mut self.issued, true) {
            return Err(terminal("witness Issue attempted twice"));
        }
        let ticket = self
            .ticket
            .ok_or_else(|| terminal("witness ticket already consumed"))?;
        self.session
            .final_check(state, cut, &self.lease, &ticket, &self.digest)?;
        // Modeled Issue transition: consume the one-use ticket locally.
        // No coordinator is contacted and nothing is guest-visible.
        self.ticket = None;
        ISSUED.fetch_add(1, Ordering::Relaxed);
        // SAFETY: genuine one-use local Issue over this exact session;
        // all after_issue obligations are the fixture's (see header).
        let leaf = unsafe { exec_private::IssuedNativeExecLeaf::after_issue(cut)? };
        let mut returned = unsafe {
            leaf.call(|| {
                self.session
                    .final_check(state, cut, &self.lease, &ticket, &self.digest)
            })
        }?;
        if TAMPER.load(Ordering::Relaxed) == TAMPER_PKRU {
            // Negative control, selected here independently of the
            // sampling guard it tests: this path runs only for the
            // admitted exec issue, so the drift is exec-only even if
            // observation sampling regresses to unconditional. The
            // genuine leaf already returned; only the reported
            // permission value handed back to the host is flipped.
            returned.pkru = Some(returned.pkru.unwrap_or(0) ^ 4);
        }
        Ok(returned)
    }

    fn cancel(
        mut self: Box<Self>,
        _rpc: &CoordinatorRpc<WitnessGlobal>,
    ) -> Result<(), TerminalExecFailure> {
        self.ticket = None;
        self.lease.cancel().map_err(|_| TerminalExecFailure {
            diagnostic: "witness lease cancellation failed",
        })?;
        self.cancelled = true;
        Ok(())
    }
}

static EXEC_PKRU_PRE: AtomicU64 = AtomicU64::new(u64::MAX);
static EXEC_PKRU_POST: AtomicU64 = AtomicU64::new(u64::MAX);
static EXEC_PKRU_SAMPLED: AtomicU64 = AtomicU64::new(0);
static EXEC_PKRU_SAMPLE_COUNT: AtomicU64 = AtomicU64::new(0);
static STATE_AT_NEXT_0: AtomicU64 = AtomicU64::new(u64::MAX);
static STATE_AT_NEXT_1: AtomicU64 = AtomicU64::new(u64::MAX);
static DECLARED_PTR: AtomicUsize = AtomicUsize::new(0);
static DECLARED_LEN: AtomicU64 = AtomicU64::new(0);
static FD_COUNT_PRE: AtomicU64 = AtomicU64::new(0);
static DECLARED_DIR_PTR: AtomicUsize = AtomicUsize::new(0);

unsafe fn witness_syscall(context: *mut RegisterContext, pkru: &mut Option<u32>) {
    let host = unsafe {
        &*(HOST_PTR.load(Ordering::Acquire) as *const ToolHost<WitnessTool, WitnessRuntime>)
    };
    let c = unsafe { &mut *context };
    let is_exec = matches!(c.rax as i64, libc::SYS_execve | libc::SYS_execveat);
    if is_exec {
        EXEC_PKRU_PRE.store(pkru.map_or(u64::MAX, u64::from), Ordering::Relaxed);
    }
    let mut event = SyscallEvent {
        number: c.rax as i64,
        args: [c.rdi, c.rsi, c.rdx, c.r10, c.r8, c.r9],
        instruction_pointer: c.instruction_pointer,
        result: 0,
        context: context as usize,
        dispatch: SyscallDispatch::Fallback,
        guest_pkru: *pkru,
        unsupported_refusal: None,
    };
    unsafe { host.dispatch(&mut event) };
    c.rax = event.result as u64;
    *pkru = event.guest_pkru;
    if is_exec {
        EXEC_PKRU_POST.store(pkru.map_or(u64::MAX, u64::from), Ordering::Relaxed);
        EXEC_PKRU_SAMPLED.store(1, Ordering::Relaxed);
        EXEC_PKRU_SAMPLE_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe fn no_instruction(_: *mut RegisterContext, _: InstructionEventKind) {
    panic!("witness never dispatches an instruction");
}

unsafe extern "C" fn kernel_signal(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    assert_eq!(signal, libc::SIGSYS);
    assert_eq!(unsafe { (*info).si_code }, 1); // SYS_SECCOMP
    let mut frame = unsafe { SignalFrame::native_exec_test_sigsys_frame(context, info) }.unwrap();
    if continuation::complete(&mut frame).unwrap() {
        return;
    }
    let number = frame.register(libc::REG_RAX as usize);
    if matches!(
        number,
        libc::SYS_execve | libc::SYS_execveat | libc::SYS_getpid
    ) {
        let instruction = (frame.register(libc::REG_RIP as usize) as u64)
            .checked_sub(2)
            .unwrap();
        let entry = unsafe { continuation::prepare_signal(instruction, &mut frame) }
            .unwrap()
            .unwrap();
        frame.set_register(libc::REG_RIP as usize, entry as i64);
    } else {
        // Fixture setup/assertion calls (collectors included) use the
        // exact private gate, as in the leaf component test.
        let args = [
            libc::REG_RDI,
            libc::REG_RSI,
            libc::REG_RDX,
            libc::REG_R10,
            libc::REG_R8,
            libc::REG_R9,
        ]
        .map(|r| frame.register(r as usize) as u64);
        let result = unsafe { crate::trap::raw_syscall6(number, args) };
        frame.set_register(libc::REG_RAX as usize, result);
    }
}

unsafe fn guest_syscall(number: i64, args: [u64; 6]) -> i64 {
    let result;
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") number => result,
        in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
        in("r10") args[3], in("r8") args[4], in("r9") args[5],
        lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
}

/// Best-effort real catalog from this process's executable file
/// mappings (pre-filter, std allowed). Backing honesty: plain files
/// are neither sealed memfds nor frozen-root copies, so most objects
/// will fail shape checks and the driver falls back to the trait
/// default refusal list; that fallback is disclosed, not hidden.
/// Open-descriptor count via gated raw getdents64 (stack buffer only).
/// The transient directory descriptor is open during both snapshots,
/// so pre/post counts are directly comparable.
fn open_fd_count() -> u64 {
    let dir = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as i64 as u64,
                c"/proc/self/fd".as_ptr() as u64,
                (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if dir < 0 {
        return u64::MAX;
    }
    let mut count = 0_u64;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_getdents64,
                [
                    dir as u64,
                    buffer.as_mut_ptr() as u64,
                    buffer.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if read < 0 {
            unsafe { crate::trap::raw_syscall6(libc::SYS_close, [dir as u64, 0, 0, 0, 0, 0]) };
            return u64::MAX;
        }
        if read == 0 {
            break;
        }
        let mut offset = 0_usize;
        while offset + 19 < read as usize {
            let reclen = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if reclen == 0 {
                break;
            }
            if buffer[offset + 19].is_ascii_digit() {
                count += 1;
            }
            offset += reclen;
        }
    }
    unsafe { crate::trap::raw_syscall6(libc::SYS_close, [dir as u64, 0, 0, 0, 0, 0]) };
    count
}

fn build_catalog() -> Option<ExecutableMappings> {
    use std::os::unix::fs::MetadataExt;
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut by_object: Vec<(
        u64,
        u64,
        u64,
        Vec<crate::guest::native_exec_mappings::ExecutableExtent>,
    )> = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next()?;
        let perms = fields.next()?;
        if !perms.starts_with("r-x") {
            continue;
        }
        let offset = u64::from_str_radix(fields.next()?, 16).ok()?;
        let _dev = fields.next()?;
        let _inode = fields.next()?;
        let Some(path) = fields.next() else { continue };
        if !path.starts_with('/') {
            continue;
        }
        let (start, end) = range.split_once('-')?;
        let start = u64::from_str_radix(start, 16).ok()?;
        let end = u64::from_str_radix(end, 16).ok()?;
        let metadata = std::fs::metadata(path).ok()?;
        let key = (metadata.dev(), metadata.ino(), metadata.len());
        let extent = crate::guest::native_exec_mappings::ExecutableExtent {
            start: offset,
            end: offset + (end - start),
        };
        match by_object
            .iter_mut()
            .find(|entry| (entry.0, entry.1, entry.2) == key)
        {
            Some(entry) => entry.3.push(extent),
            None => by_object.push((key.0, key.1, key.2, vec![extent])),
        }
    }
    if by_object.is_empty() {
        return None;
    }
    let objects: Vec<crate::guest::native_exec_mappings::ExecutableObject> = by_object
        .into_iter()
        .map(|(device, inode, size, extents)| {
            crate::guest::native_exec_mappings::ExecutableObject {
                device,
                inode,
                size,
                backing: crate::guest::native_exec_mappings::ExecutableBacking::Sealed,
                extents: extents.into_boxed_slice(),
            }
        })
        .collect();
    // SAFETY: test-fixture catalog over this process's own genuine
    // mappings; used only for check_mapping decisions in this
    // witness, which injects no mapping operations. Backing is
    // labeled Sealed for shape validity inside the fixture only and
    // is never presented as production admission authority.
    unsafe { ExecutableMappings::new(objects.into_boxed_slice(), Box::new([])) }.ok()
}

fn object_of(identity: FdIdentity) -> (u64, u64) {
    (identity.device, identity.inode)
}

fn run_witness(mode: &str) {
    // Fork first: the lone surviving thread has tid == pid, which the
    // InitialImage owner checks require. A setup panic must then exit
    // promptly: unwinding through the partly installed host/RPC state
    // can block in destructors, which would hang the spawning parent
    // test instead of failing it.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let status =
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_witness_inner(mode)))
                .is_ok()
            {
                0
            } else {
                125
            };
        unsafe { libc::_exit(status) }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "child wait status {status}");
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

fn run_witness_inner(mode: &str) {
    use std::os::fd::IntoRawFd;
    TAMPER.store(
        match mode {
            "tamper-digest" => TAMPER_DIGEST,
            "tamper-sequence" => TAMPER_SEQUENCE,
            "tamper-prepare-sources" => TAMPER_PREPARE_SOURCES,
            "tamper-pkru" => TAMPER_PKRU,
            "tamper-rollback" => TAMPER_ROLLBACK,
            _ => 0,
        },
        Ordering::Relaxed,
    );
    // Owned absent target: a private mkdtemp namespace whose target
    // is proven absent here and again immediately before the filter
    // installs, so this witness cannot pass via a file that happens
    // to exist on some host. The driver qualifies exactly this path.
    let mut template = std::env::temp_dir()
        .join("s2a1-witness-XXXXXX")
        .into_os_string()
        .into_string()
        .unwrap()
        .into_bytes();
    template.push(0);
    let dir_ptr = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
    assert!(!dir_ptr.is_null());
    let dir_bytes = unsafe { core::ffi::CStr::from_ptr(dir_ptr) }
        .to_bytes()
        .to_vec();
    let mut target = dir_bytes.clone();
    target.extend_from_slice(b"/absent-target");
    let declared_len = target.len() as u64;
    target.push(0);
    let declared: &'static [u8] = Box::leak(target.into_boxed_slice());
    let mut dir_z = dir_bytes.clone();
    dir_z.push(0);
    let declared_dir: &'static [u8] = Box::leak(dir_z.into_boxed_slice());
    DECLARED_PTR.store(declared.as_ptr() as usize, Ordering::Release);
    DECLARED_LEN.store(declared_len, Ordering::Relaxed);
    DECLARED_DIR_PTR.store(declared_dir.as_ptr() as usize, Ordering::Release);
    assert_eq!(
        unsafe { libc::access(declared.as_ptr().cast(), libc::F_OK) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOENT)
    );

    // --- Protected sockets + coordinator (pre-filter, no threads). ---
    let (rpc_client, mut rpc_peer) = UnixStream::pair().unwrap();
    let (detlog_sock, detlog_peer) = UnixStream::pair().unwrap();
    let (observer_sock, observer_peer) = UnixStream::pair().unwrap();
    let (provider_sock, provider_peer) = UnixStream::pair().unwrap();
    let rpc_fd = rpc_client.as_raw_fd();
    crate::guest::protect::reserve_coordinator_fd(rpc_fd).unwrap();
    // SAFETY: still single-threaded (asserted again in prepare).
    let detlog_fd = unsafe {
        crate::guest::protect::reserve_tool_output_fd(detlog_sock.into_raw_fd(), b"witness\0")
    }
    .unwrap();
    let observer_fd = unsafe {
        crate::guest::native_exec_fds::reserve_socket(
            NativeSocket::Observer,
            observer_sock.into_raw_fd(),
        )
    }
    .unwrap();
    let _provider_fd = unsafe {
        crate::guest::native_exec_fds::reserve_socket(
            NativeSocket::Provider,
            provider_sock.into_raw_fd(),
        )
    }
    .unwrap();
    // Handshake frame pre-written by this same thread: no worker.
    write_frame(
        &mut rpc_peer,
        &reverie_rpc_transport::codec::encode(&CONFIG).unwrap(),
    );
    let client = reverie_rpc_transport::BlockingRpcClient::from_connected_stream(
        crate::guest::rpc::GuestRpcStream::from(rpc_client),
        raw_pid(libc::SYS_gettid),
    )
    .unwrap();
    let rpc = CoordinatorRpc::from_live_client("unused-witness", client, |_, _| {
        panic!("witness must retain its original connection")
    })
    .unwrap();
    let detlog_before = FdIdentity::read(detlog_fd).unwrap();
    let observer_before = FdIdentity::read(observer_fd).unwrap();
    let expected_detlog = object_of(detlog_before);
    let expected_observer = object_of(observer_before);
    let real_pid = raw_pid(libc::SYS_getpid).as_raw() as i64;

    // --- Host, controls, ranges, then driver + lifecycle. ---
    let catalog = build_catalog();
    let authority: &'static mut Authority = Box::leak(Box::new(Authority {
        protected: Vec::new(),
        expected_detlog,
        expected_observer,
        catalog,
    }));
    let mut host = Box::new(ToolHost::new(
        WitnessTool,
        rpc,
        raw_pid(libc::SYS_getpid),
        HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid]),
        false,
        WitnessRuntime,
    ));
    let (mut lifecycle_control, owner) = exec_private::lifecycle_test_owner();
    let clear = Box::new(std::sync::atomic::AtomicI32::new(1));
    let mut robust = Box::new([0_usize; 3]);
    robust[0] = robust.as_ptr() as usize;
    // Kernel registrations via physical_syscall run later, once the
    // control is callback-ready (the private guest call requires
    // phase 4); issuing them at lifecycle phase 2 exits terminally.
    // Protected ranges: this fixture's actual host/control/driver
    // storage. Guest argument pointers (statics + main stack) are
    // deliberately outside every range.
    let range = |ptr: usize, len: usize| ArgumentRange {
        start: ptr,
        end: ptr + len,
    };
    authority.protected = vec![
        range(&*host as *const _ as usize, core::mem::size_of_val(&*host)),
        range(
            &*lifecycle_control as *const _ as usize,
            core::mem::size_of_val(&*lifecycle_control),
        ),
        range(
            authority as *const Authority as usize,
            core::mem::size_of::<Authority>(),
        ),
    ];
    // Ranges are final before the driver takes its shared borrow.
    let driver = Arc::new(WitnessDriver {
        authority,
        sequence: Box::leak(Box::new(AtomicU64::new(0))),
    });
    unsafe { host.install_native_exec_driver(driver) }.unwrap();
    unsafe { host.admit_native_exec() }.unwrap();
    HOST_PTR.store(&*host as *const _ as usize, Ordering::Release);
    unsafe { host.bind_initial_image_control(&owner) }.unwrap();
    exec_private::mark_lifecycle_test_frontend_installed(&owner);
    host.initialize_initial_image_lifecycle(&owner).unwrap();
    assert_eq!(LIFECYCLE.load(Ordering::Relaxed), 11);
    // Same stable control transitions to callback-ready; the global
    // control pointer already names it (lifecycle owner published it).
    exec_private::native_exec_test_make_callback_ready(&mut lifecycle_control);
    assert_eq!(
        unsafe {
            exec_private::physical_syscall(
                libc::SYS_set_tid_address,
                [(&*clear as *const _) as u64, 0, 0, 0, 0, 0],
                None,
            )
        }
        .result,
        i64::from(raw_pid(libc::SYS_gettid).as_raw())
    );
    assert_eq!(
        unsafe {
            exec_private::physical_syscall(
                libc::SYS_set_robust_list,
                [
                    robust.as_ptr() as u64,
                    core::mem::size_of_val(&*robust) as u64,
                    0,
                    0,
                    0,
                    0,
                ],
                None,
            )
        }
        .result,
        0
    );
    assert!(exec_private::callback_kernel_registrations().is_some());

    // --- Frontend: continuation, handler, mask, filter. ---
    crate::trap::prepare_private_signal_features().unwrap();
    unsafe {
        continuation::register_handlers(continuation::ContinuationHandlers {
            syscall: witness_syscall,
            instruction: no_instruction,
        })
    }
    .unwrap();
    continuation::initialize().unwrap();
    let action = crate::signal::KernelSigaction {
        handler: kernel_signal as *const () as u64,
        flags: (libc::SA_SIGINFO | crate::signal::SA_RESTORER) as u64,
        restorer: crate::signal::signal_restorer(),
        mask: 1_u64 << (libc::SIGUSR2 - 1),
    };
    unsafe { crate::signal::raw_sigaction(libc::SIGSYS, Some(&action), None) }.unwrap();
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&RESUME_MASK), None) }.unwrap();
    exec_private::native_exec_test_enter_guest(&mut lifecycle_control);
    crate::guest::native_exec::arm_test_issue();
    let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates_with_signal_return(
        crate::trap::trusted_gate(),
        crate::trap::guest_syscall_gate(),
        Some(crate::signal::signal_restorer_return_ip()),
    )
    .unwrap();
    unsafe { filter.install() }.unwrap();

    // --- Guest: failed exec, then subscribed getpid. ---
    // Re-prove absence with the filter about to install, and take
    // the fd-table baseline the postconditions compare against.
    let declared_ptr = DECLARED_PTR.load(Ordering::Acquire) as *const u8;
    assert_eq!(unsafe { libc::access(declared_ptr.cast(), libc::F_OK) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOENT)
    );
    FD_COUNT_PRE.store(open_fd_count(), Ordering::Relaxed);
    let argv = [declared_ptr as u64, 0];
    let envp = [0_u64];
    let exec_result = unsafe {
        guest_syscall(
            libc::SYS_execveat,
            [
                libc::AT_FDCWD as i64 as u64,
                declared_ptr as u64,
                argv.as_ptr() as u64,
                envp.as_ptr() as u64,
                0,
                0,
            ],
        )
    };
    let pid_result = unsafe { guest_syscall(libc::SYS_getpid, [0; 6]) };

    // --- Post-conditions (raw gate only where practical). ---
    let tamper = TAMPER.load(Ordering::Relaxed);
    let refused_before_issue = matches!(
        tamper,
        TAMPER_DIGEST | TAMPER_SEQUENCE | TAMPER_PREPARE_SOURCES
    );
    if refused_before_issue {
        assert_eq!(exec_result, -i64::from(libc::EOPNOTSUPP));
        assert_eq!(EXEC_REFUSAL.load(Ordering::Relaxed), 2);
        assert_eq!(ISSUED.load(Ordering::Relaxed), 0);
    } else {
        assert_eq!(exec_result, -i64::from(libc::ENOENT));
        assert_eq!(EXEC_REFUSAL.load(Ordering::Relaxed), -1);
        assert_eq!(ISSUED.load(Ordering::Relaxed), 1);
    }
    assert_eq!(pid_result, SENTINEL_PID);
    assert_ne!(SENTINEL_PID, real_pid);
    assert_eq!(SEQ_COUNT.load(Ordering::Relaxed), 2);
    assert_eq!(SEQ[0].load(Ordering::Relaxed), libc::SYS_execveat);
    assert_eq!(SEQ[1].load(Ordering::Relaxed), libc::SYS_getpid);
    // Restored old Tool state directly observed at the genuine next
    // callback, not inferred from interception alone.
    assert_eq!(STATE_AT_NEXT_0.load(Ordering::Relaxed), 3);
    assert_eq!(STATE_AT_NEXT_1.load(Ordering::Relaxed), 1);
    assert_eq!(THREADS_PREPARE.load(Ordering::Relaxed), 1);
    if tamper != TAMPER_PREPARE_SOURCES {
        assert_eq!(THREADS_FINAL.load(Ordering::Relaxed), 1);
    }
    // PKRU samples bound to the exec dispatch itself; the later
    // getpid callback cannot overwrite them.
    assert_eq!(EXEC_PKRU_SAMPLED.load(Ordering::Relaxed), 1);
    // Exactly one sample: an unconditional-sampling regression would
    // record the getpid callback too and fail here even though its
    // overwritten pre/post pair would compare equal.
    assert_eq!(EXEC_PKRU_SAMPLE_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(
        EXEC_PKRU_PRE.load(Ordering::Relaxed),
        EXEC_PKRU_POST.load(Ordering::Relaxed)
    );
    // Open-fd cardinality intact across the failed exec (all modes);
    // named protected-FD identities are asserted separately below.
    // A query failure (MAX sentinel) on either snapshot fails here
    // rather than comparing equal by accident.
    let fd_pre = FD_COUNT_PRE.load(Ordering::Relaxed);
    let fd_post = open_fd_count();
    assert_ne!(fd_pre, u64::MAX);
    assert_eq!(fd_post, fd_pre);
    for index in 0..5 {
        let fd = 198 + index;
        let queried = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
            )
        };
        assert_eq!(
            queried,
            -i64::from(libc::EBADF),
            "lease slot {fd} still open"
        );
    }
    assert_eq!(FdIdentity::read(detlog_fd).unwrap(), detlog_before);
    assert_eq!(FdIdentity::read(observer_fd).unwrap(), observer_before);
    // Coordinator peer received nothing: modeled mint never RPCs.
    let mut pollfd = libc::pollfd {
        fd: rpc_peer.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let polled = unsafe {
        crate::trap::raw_syscall6(libc::SYS_poll, [(&raw mut pollfd) as u64, 1, 0, 0, 0, 0])
    };
    assert_eq!(polled, 0);
    // Best-effort removal of the owned empty target directory.
    unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_unlinkat,
            [
                libc::AT_FDCWD as i64 as u64,
                DECLARED_DIR_PTR.load(Ordering::Relaxed) as u64,
                libc::AT_REMOVEDIR as u64,
                0,
                0,
                0,
            ],
        );
    }
    let marker: &[u8] = if tamper == 0 {
        b"NATIVE_EXEC_WITNESS_OK\n"
    } else {
        b"NATIVE_EXEC_WITNESS_TAMPER_OK\n"
    };
    unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_write,
            [1, marker.as_ptr() as u64, marker.len() as u64, 0, 0, 0],
        );
    }
    Box::leak(clear);
    Box::leak(robust);
    Box::leak(lifecycle_control);
    core::mem::forget(host);
    core::mem::forget((rpc_peer, detlog_peer, observer_peer, provider_peer));
    unsafe { libc::_exit(0) }
}

fn spawn_witness(mode: &'static str, test_name: &str, marker: &str, expect_success: bool) {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness(mode);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env(MODE_ENV, mode)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    if expect_success {
        assert!(
            output.status.success() && stdout.contains(marker),
            "witness child failed: {}; stdout={stdout}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        // Negative control: the causal assertion inside the child
        // must fire (nonzero exit, success marker absent).
        assert!(
            !output.status.success()
                && !stdout.contains(marker)
                && String::from_utf8_lossy(&output.stderr)
                    .contains("panicked at reverie-inguest/src/guest/native_exec_witness_tests.rs"),
            "negative-control child did not fail at its own assertion: {}; stdout={stdout}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn physical_failed_exec_witness() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness("ok");
        return;
    }
    spawn_witness(
        "ok",
        "guest::host::native_exec_witness_tests::physical_failed_exec_witness",
        "NATIVE_EXEC_WITNESS_OK",
        true,
    );
}

#[test]
fn physical_failed_exec_witness_tampered_digest_refuses_before_issue() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness("tamper-digest");
        return;
    }
    spawn_witness(
        "tamper-digest",
        "guest::host::native_exec_witness_tests::physical_failed_exec_witness_tampered_digest_refuses_before_issue",
        "NATIVE_EXEC_WITNESS_TAMPER_OK",
        true,
    );
}

#[test]
fn physical_failed_exec_witness_tampered_sequence_refuses_before_issue() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness("tamper-sequence");
        return;
    }
    spawn_witness(
        "tamper-sequence",
        "guest::host::native_exec_witness_tests::physical_failed_exec_witness_tampered_sequence_refuses_before_issue",
        "NATIVE_EXEC_WITNESS_TAMPER_OK",
        true,
    );
}

#[test]
fn physical_failed_exec_witness_prepare_error_closes_exactly_owned_sources() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness("tamper-prepare-sources");
        return;
    }
    spawn_witness(
        "tamper-prepare-sources",
        "guest::host::native_exec_witness_tests::physical_failed_exec_witness_prepare_error_closes_exactly_owned_sources",
        "NATIVE_EXEC_WITNESS_TAMPER_OK",
        true,
    );
}

#[test]
fn physical_failed_exec_witness_exec_pkru_drift_is_caught() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness("tamper-pkru");
        return;
    }
    // Negative control: simulated exec-only PKRU drift must fail
    // the exec-bound equality even though getpid preserves it.
    spawn_witness(
        "tamper-pkru",
        "guest::host::native_exec_witness_tests::physical_failed_exec_witness_exec_pkru_drift_is_caught",
        "NATIVE_EXEC_WITNESS_OK",
        false,
    );
}

#[test]
fn physical_failed_exec_witness_omitted_rollback_is_caught() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_witness("tamper-rollback");
        return;
    }
    // Negative control: omitting the Tool-owned rollback leaves the
    // prepared tuple observable at the next genuine callback.
    spawn_witness(
        "tamper-rollback",
        "guest::host::native_exec_witness_tests::physical_failed_exec_witness_omitted_rollback_is_caught",
        "NATIVE_EXEC_WITNESS_OK",
        false,
    );
}
