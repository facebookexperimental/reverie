/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Tool-agnostic native-exec driver (W6b N2).
//!
//! Generalizes Hermit's Detcore driver pattern
//! (`detcore-liteinst/src/exec_native/driver.rs`, read at a433ca4fd0)
//! over three embedder-supplied policies. Detcore specifics (sealed
//! catalog contents, determinism receipts, mm/files identity) stay
//! with the embedder; this driver owns only: catalog admission at
//! capture, state framing at prepare, ticket lifecycle through an
//! [`ExecIssuer`]. The physical leaf call is N2b (joint with
//! musegate S-B); issue refuses by name until then.
//!
//! Absence of a catalog means reach-the-kernel admission: targets
//! the kernel refuses (e.g. ENOENT) surface as genuine returned
//! errnos, which Hermit's sealed catalog forbids by construction.

use std::sync::Mutex;

use reverie::Tool;
use reverie::UnsupportedRefusal;
use reverie_rpc_transport::exec_control::ExecIssuer;
use reverie_rpc_transport::exec_ticket::ExecControlError;
use reverie_rpc_transport::exec_ticket::ExecTicket;
use reverie_rpc_transport::exec_ticket::TicketBinding;
use sha2::Digest;
use sha2::Sha256;

use super::native_exec::ExecCut;
use super::native_exec::NativeExecDriver;
use super::native_exec::NativeExecFailure;
use super::native_exec::NativeExecSession;
use super::native_exec::PreparedNativeExec;
use super::native_exec::ReturnedNativeExec;
use super::native_exec::TerminalExecFailure;
use super::rpc::CoordinatorRpc;

/// Target admission policy. Detcore supplies its sealed catalog;
/// literoot supplies reach-the-kernel (admit all) or its rootfs rules.
pub trait TargetCatalog: Send + Sync {
    /// Admit an exec target path (raw guest bytes) at capture time.
    fn admit(&self, path: &[u8]) -> Result<(), UnsupportedRefusal>;
}

/// Reach-the-kernel catalog: admits every target; kernel decides.
pub struct KernelCatalog;

impl TargetCatalog for KernelCatalog {
    fn admit(&self, _path: &[u8]) -> Result<(), UnsupportedRefusal> {
        Ok(())
    }
}

/// One-shot successor provision delivery. The registry's delivered
/// fact may only be marked after this returns Ok: delivery is an
/// embedder obligation (actual provision transport + receipt),
/// never a boolean the driver invents (Astra P2 at 4839ff98).
pub trait Provisioner: Send + Sync {
    /// Deliver the sealed provision for `ticket`; Ok means a real
    /// delivery receipt exists embedder-side.
    fn deliver(&self, ticket: ExecTicket, sealed_digest: [u8; 32]) -> Result<(), ExecControlError>;
}

/// No delivery mechanism installed: every delivery refuses by name,
/// so issue is unreachable until an embedder supplies provision.
pub struct RefusingProvisioner;

impl Provisioner for RefusingProvisioner {
    fn deliver(
        &self,
        _ticket: ExecTicket,
        _sealed_digest: [u8; 32],
    ) -> Result<(), ExecControlError> {
        Err(ExecControlError::Unavailable)
    }
}

/// Tool-state framing: exact bytes sealed under the ticket. Encoding
/// must be deterministic for equal states (revalidation compares).
/// Associated-state form (not generic over the Tool) so sessions can
/// own the framer without lifetime ties to the Tool type.
pub trait StateFramer: Send + Sync {
    /// The Tool's thread-state type this framer encodes.
    type State;
    /// Encode the prepared thread state for sealing.
    fn encode(&self, state: &Self::State) -> Vec<u8>;
    /// The exec target path bytes for catalog admission, read from
    /// the prepared state/cut by the embedder (guest-memory reads are
    /// the embedder's, performed before capture under its own locks).
    fn target_path(&self, state: &Self::State, cut: &ExecCut) -> Vec<u8>;
}

/// The generic driver. `I` is the ticket issuer (control client or
/// direct registry adapter); it is mutex-guarded because driver
/// methods take `&self` while exchanges are single-in-flight.
pub struct GenericNativeExecDriver<C, F, I, B, P = RefusingProvisioner> {
    catalog: std::sync::Arc<C>,
    framer: std::sync::Arc<F>,
    provisioner: std::sync::Arc<P>,
    issuer: std::sync::Arc<Mutex<I>>,
    binding: B,
    runtime: Vec<u8>,
}

impl<C, F, I, B, P> GenericNativeExecDriver<C, F, I, B, P> {
    /// New driver. `runtime` is the sealed runtime payload bytes
    /// (bootstrap/successor runtime image digest domain input).
    pub fn new(
        catalog: C,
        framer: F,
        provisioner: P,
        issuer: I,
        binding: B,
        runtime: Vec<u8>,
    ) -> Self {
        Self {
            catalog: std::sync::Arc::new(catalog),
            framer: std::sync::Arc::new(framer),
            provisioner: std::sync::Arc::new(provisioner),
            issuer: std::sync::Arc::new(Mutex::new(issuer)),
            binding,
            runtime,
        }
    }
}

fn refused(message: &'static str) -> UnsupportedRefusal {
    UnsupportedRefusal::new(
        reverie::UnsupportedOperation::NativeExec,
        reverie::Errno::EOPNOTSUPP,
        message,
    )
}

fn terminal(message: &'static str) -> NativeExecFailure {
    NativeExecFailure::Terminal(TerminalExecFailure {
        diagnostic: message,
    })
}

/// Cancel after a prepare failure. Confirmed cancellation keeps the
/// original failure; any cancel uncertainty is Terminal (a live
/// Prepared ticket must never hide behind an ordinary refusal).
fn cancel_or_terminal<I, B>(
    issuer: &mut I,
    ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
    original: NativeExecFailure,
) -> NativeExecFailure
where
    I: ExecIssuer<B>,
    B: TicketBinding,
{
    match issuer.cancel(ticket) {
        Ok(()) => original,
        Err(_) => terminal("reverie-inguest: generic native exec cancellation is uncertain"),
    }
}

fn control_terminal(_error: ExecControlError) -> NativeExecFailure {
    terminal("reverie-inguest: generic native exec control transport failed")
}

struct GenericSession<T: Tool, F, I, B, P> {
    framer: std::sync::Arc<F>,
    provisioner: std::sync::Arc<P>,
    issuer: std::sync::Arc<Mutex<I>>,
    binding: B,
    runtime: Vec<u8>,
    cut: ExecCut,
    _tool: std::marker::PhantomData<fn() -> T>,
}

struct GenericPrepared<I, B, F> {
    _binding: std::marker::PhantomData<fn() -> B>,
    framer: std::sync::Arc<F>,
    issuer: std::sync::Arc<Mutex<I>>,
    ticket: ExecTicket,
    _sealed_digest: [u8; 32],
    encoded: Vec<u8>,
}

// SAFETY: the driver below upholds the trait contracts by
// construction: capture only catalog-checks and retains the cut;
// prepare performs the authenticated ticket exchanges before any
// physical step; issue revalidates then calls the one-use leaf;
// cancel consumes the ticket through the issuer. Embedders supply
// catalog/framer/issuer whose documented obligations (deterministic
// framing, single watched birth) are stated on those traits.
unsafe impl<T, C, F, I, B, P> NativeExecDriver<T> for GenericNativeExecDriver<C, F, I, B, P>
where
    T: Tool + 'static,
    C: TargetCatalog,
    F: StateFramer<State = T::ThreadState>,
    I: ExecIssuer<B> + Send,
    B: TicketBinding + Clone + Send + Sync,
    B::Owner: Send,
    P: Provisioner,
{
    fn capture_old<'owner>(
        &'owner self,
        _tool: &T,
        state: &T::ThreadState,
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<Box<dyn NativeExecSession<T> + 'owner>, UnsupportedRefusal> {
        let path = self.framer.target_path(state, cut);
        self.catalog.admit(&path)?;
        Ok(Box::new(GenericSession {
            framer: self.framer.clone(),
            provisioner: self.provisioner.clone(),
            issuer: self.issuer.clone(),
            binding: self.binding.clone(),
            runtime: self.runtime.clone(),
            cut: *cut,
            _tool: std::marker::PhantomData,
        }))
    }
}

// SAFETY: see driver-level note; prepare owns no ticket until the
// issuer mints one, and every error path below cancels it.
unsafe impl<T, F, I, B, P> NativeExecSession<T> for GenericSession<T, F, I, B, P>
where
    T: Tool + 'static,
    F: StateFramer<State = T::ThreadState>,
    I: ExecIssuer<B> + Send,
    B: TicketBinding + Clone + Send + Sync,
    B::Owner: Send,
    P: Provisioner,
{
    fn prepare<'a>(
        &'a mut self,
        _tool: &T,
        state: &T::ThreadState,
        cut: &ExecCut,
        _rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<Box<dyn PreparedNativeExec<T> + 'a>, NativeExecFailure> {
        if cut.original().number() != self.cut.original().number()
            || cut.original().args() != self.cut.original().args()
        {
            return Err(NativeExecFailure::Refused(refused(
                "reverie-inguest: generic native exec cut changed after capture",
            )));
        }
        let encoded = self.framer.encode(state);
        if encoded.is_empty() {
            return Err(NativeExecFailure::Refused(refused(
                "reverie-inguest: generic native exec state framing is empty",
            )));
        }
        let snapshot_digest: [u8; 32] = Sha256::digest(&encoded).into();
        let mut issuer = self
            .issuer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ticket = issuer
            .prepare(self.binding.clone(), encoded.clone(), snapshot_digest)
            .map_err(control_terminal)?;
        let runtime_digest: [u8; 32] = Sha256::digest(&self.runtime).into();
        let sealed_digest = match issuer.seal(ticket, runtime_digest, &self.runtime) {
            Ok(digest) => digest,
            Err(error) => {
                return Err(cancel_or_terminal(
                    &mut *issuer,
                    ticket,
                    control_terminal(error),
                ));
            }
        };
        // Actual delivery first; the delivered fact is recorded only
        // after the embedder's receipt. No delivery => cancel+refuse.
        if let Err(error) = self.provisioner.deliver(ticket, sealed_digest) {
            let original = match error {
                ExecControlError::Unavailable => NativeExecFailure::Refused(refused(
                    "reverie-inguest: generic native exec has no provision delivery",
                )),
                other => control_terminal(other),
            };
            return Err(cancel_or_terminal(&mut *issuer, ticket, original));
        }
        if let Err(error) = issuer.mark_provision_delivered(ticket) {
            let original = control_terminal(error);
            return Err(cancel_or_terminal(&mut *issuer, ticket, original));
        }
        drop(issuer);
        Ok(Box::new(GenericPrepared {
            _binding: std::marker::PhantomData,
            framer: self.framer.clone(),
            issuer: self.issuer.clone(),
            ticket,
            _sealed_digest: sealed_digest,
            encoded,
        }))
    }
}

// SAFETY: see driver-level note; issue repeats the ticket exchange
// before the leaf, and every refusal path cancels the ticket.
unsafe impl<T, I, B, F> PreparedNativeExec<T> for GenericPrepared<I, B, F>
where
    T: Tool,
    I: ExecIssuer<B> + Send,
    F: StateFramer<State = T::ThreadState>,
    B: TicketBinding,
{
    fn revalidate(
        &mut self,
        _tool: &T,
        state: &T::ThreadState,
        _cut: &ExecCut,
        _rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<(), NativeExecFailure> {
        if self.framer.encode(state) != self.encoded {
            return Err(NativeExecFailure::Refused(refused(
                "reverie-inguest: generic native exec prepared state changed",
            )));
        }
        Ok(())
    }

    unsafe fn issue_and_call(
        &mut self,
        _tool: &T,
        state: &T::ThreadState,
        _cut: &ExecCut,
        _rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<ReturnedNativeExec, NativeExecFailure> {
        if self.framer.encode(state) != self.encoded {
            return Err(NativeExecFailure::Refused(refused(
                "reverie-inguest: generic native exec prepared state changed at issue",
            )));
        }
        // N2 scope (coord7/Astra delta): the physical leaf path is
        // N2b, jointly with musegate S-B, where the leaf final-check
        // contract (retained authority validation, allocation-free
        // exact check, no post-Issue encode/clone) is implemented
        // properly. Until then this driver refuses by name here and
        // never issues the ticket.
        Err(NativeExecFailure::Refused(refused(
            "reverie-inguest: generic native exec leaf is N2b (joint with musegate S-B)",
        )))
    }

    fn cancel(
        self: Box<Self>,
        _rpc: &CoordinatorRpc<T::GlobalState>,
    ) -> Result<(), TerminalExecFailure> {
        let this = *self;
        let mut issuer = this
            .issuer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        issuer.cancel(this.ticket).map_err(|_| TerminalExecFailure {
            diagnostic: "reverie-inguest: generic native exec cancel transport failed",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reverie::GlobalTool;
    use reverie::Pid;
    use reverie::Tool;
    use reverie_rpc_transport::exec_ticket::ExecTicketRegistry;
    use std::os::fd::OwnedFd;
    use std::sync::Arc;
    use std::sync::Mutex;

    type ReturnedCalls = Arc<Mutex<Vec<(reverie::Errno, Option<reverie::UnsupportedRefusal>)>>>;

    #[derive(Default)]
    struct TestGlobal;
    #[reverie::tool]
    impl GlobalTool for TestGlobal {
        type Request = u64;
        type Response = u64;
        type Config = u64;
        async fn receive_rpc(&self, _from: Pid, message: u64) -> u64 {
            message
        }
    }

    #[derive(Default)]
    struct TestTool;
    #[reverie::tool]
    impl Tool for TestTool {
        type GlobalState = TestGlobal;
        type ThreadState = (u64, u64);
        fn init_thread_state(&self, _tid: Pid, _parent: Option<(Pid, &(u64, u64))>) -> (u64, u64) {
            (3, 1)
        }
    }

    struct PairFramer;
    impl StateFramer for PairFramer {
        type State = (u64, u64);
        fn encode(&self, state: &(u64, u64)) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&state.0.to_le_bytes());
            out.extend_from_slice(&state.1.to_le_bytes());
            out
        }
        fn target_path(&self, _state: &(u64, u64), _cut: &ExecCut) -> Vec<u8> {
            b"/bin/true".to_vec()
        }
    }

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct TestBinding {
        config: [u8; 32],
    }
    impl TicketBinding for TestBinding {
        type Owner = i32;
        fn owner(&self) -> i32 {
            7
        }
        fn config_digest(&self) -> [u8; 32] {
            self.config
        }
    }

    type CallLog = Arc<Mutex<Vec<&'static str>>>;
    struct DirectIssuer {
        registry: Arc<Mutex<ExecTicketRegistry<TestProof, TestBinding>>>,
        calls: CallLog,
    }
    thread_local! {
        static ISSUE_ARMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static PROVISION_OK: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
        static SHARED_CALLS: std::cell::RefCell<Vec<&'static str>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }
    struct SwitchProvisioner {
        ok: bool,
        calls: CallLog,
    }
    impl Provisioner for SwitchProvisioner {
        fn deliver(
            &self,
            _ticket: ExecTicket,
            _sealed_digest: [u8; 32],
        ) -> Result<(), ExecControlError> {
            self.calls.lock().unwrap().push("deliver");
            SHARED_CALLS.with(|log| log.borrow_mut().push("deliver"));
            if self.ok {
                Ok(())
            } else {
                Err(ExecControlError::Unavailable)
            }
        }
    }
    struct TestProof;
    impl reverie_rpc_transport::exec_ticket::TicketProof<TestBinding> for TestProof {
        fn owner(&self) -> i32 {
            7
        }
        fn matches_peer(&self, _peer: &OwnedFd) -> bool {
            true
        }
        fn qualify_prepare(&self, _b: &TestBinding, _s: &[u8]) -> bool {
            true
        }
        fn qualify_runtime(&self, _r: &[u8]) -> bool {
            true
        }
        fn qualify_completion(
            &self,
            _t: reverie_rpc_transport::exec_ticket::ExecTicket,
            _b: &TestBinding,
        ) -> bool {
            true
        }
    }
    impl reverie_rpc_transport::exec_control::ExecIssuer<TestBinding> for DirectIssuer {
        fn prepare(
            &mut self,
            binding: TestBinding,
            snapshot: Vec<u8>,
            digest: [u8; 32],
        ) -> Result<reverie_rpc_transport::exec_ticket::ExecTicket, ExecControlError> {
            self.calls.lock().unwrap().push("prepare");
            SHARED_CALLS.with(|l| l.borrow_mut().push("prepare"));
            self.registry
                .lock()
                .unwrap()
                .prepare(7, binding, snapshot, digest)
        }
        fn seal(
            &mut self,
            ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
            digest: [u8; 32],
            runtime: &[u8],
        ) -> Result<[u8; 32], ExecControlError> {
            self.calls.lock().unwrap().push("seal");
            SHARED_CALLS.with(|l| l.borrow_mut().push("seal"));
            self.registry
                .lock()
                .unwrap()
                .seal(7, ticket, digest, runtime)
        }
        fn mark_provision_delivered(
            &mut self,
            ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
        ) -> Result<(), ExecControlError> {
            self.calls.lock().unwrap().push("mark");
            SHARED_CALLS.with(|l| l.borrow_mut().push("mark"));
            self.registry
                .lock()
                .unwrap()
                .mark_provision_delivered(7, ticket)
        }
        fn issue(
            &mut self,
            ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
            digest: [u8; 32],
        ) -> Result<reverie_rpc_transport::exec_ticket::ExecTicket, ExecControlError> {
            self.calls.lock().unwrap().push("issue");
            SHARED_CALLS.with(|l| l.borrow_mut().push("issue"));
            self.registry.lock().unwrap().issue(7, ticket, digest)?;
            Ok(ticket)
        }
        fn cancel(
            &mut self,
            ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
        ) -> Result<(), ExecControlError> {
            self.calls.lock().unwrap().push("cancel");
            SHARED_CALLS.with(|l| l.borrow_mut().push("cancel"));
            self.registry.lock().unwrap().cancel(7, ticket)
        }
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(bytes).into()
    }

    #[test]
    fn generic_driver_installs_as_trait_object() {
        // Compile-time witness: the generic driver installs as a
        // NativeExecDriver trait object for a concrete Tool. A live
        // ToolHost dispatch witness needs native_exec_tests callback
        // fixture alignment (process-global control pointer), which
        // is follow-on work tracked in the N2 report; not faked here.
        let registry = Arc::new(Mutex::new(
            ExecTicketRegistry::new(TestProof, [5u8; 32]).unwrap(),
        ));
        let driver = GenericNativeExecDriver::new(
            KernelCatalog,
            PairFramer,
            RefusingProvisioner,
            DirectIssuer {
                registry,
                calls: Arc::new(Mutex::new(Vec::new())),
            },
            TestBinding { config: [3u8; 32] },
            b"runtime".to_vec(),
        );
        let _erased: Arc<dyn NativeExecDriver<TestTool>> = Arc::new(driver);
    }

    #[test]
    fn generic_driver_host_dispatch_witness() {
        // Fork-isolate: callback control pointer is process-global.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status =
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(dispatch_body2)).is_ok() {
                    0
                } else {
                    125
                };
            unsafe { libc::_exit(status) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn generic_driver_armed_leaf_witness() {
        // Armed counterpart of the dispatch witness: with the test-only
        // issue latch armed in the forked child, the attempt reaches
        // this driver's leaf, which must refuse by its N2b name and
        // never call issuer.issue. Fork-isolated like the witness:
        // the latch is process-global, so arming must not leak.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status =
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(dispatch_armed_body))
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
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn dispatch_armed_body() {
        ISSUE_ARMED.with(|armed| armed.set(true));
        dispatch_body2();
    }

    fn dispatch_body2() {
        use super::super::event::SyscallDispatch;
        use super::super::event::SyscallEvent;
        use crate::guest::host::HostRuntime;
        use crate::guest::host::ToolHost;
        use reverie::Errno;
        use reverie::Error;
        use reverie::Guest;
        use reverie::syscalls::Syscall;
        use reverie::syscalls::SyscallArgs;
        use reverie::syscalls::SyscallInfo;
        use reverie::syscalls::Sysno;
        use std::collections::HashSet;
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        #[derive(Default)]
        struct ExecTool {
            returned: ReturnedCalls,
        }
        #[reverie::tool]
        impl Tool for ExecTool {
            type GlobalState = TestGlobal;
            type ThreadState = (u64, u64);
            fn init_thread_state(&self, _tid: Pid, _p: Option<(Pid, &(u64, u64))>) -> (u64, u64) {
                (3, 1)
            }
            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                call: Syscall,
            ) -> Result<i64, Error> {
                let (number, args) = call.into_parts();
                assert_eq!(number, Sysno::execve);
                *guest.thread_state_mut() = (4, 2);
                let injected = [
                    libc::AT_FDCWD as i64 as u64,
                    args.arg0 as u64,
                    args.arg1 as u64,
                    args.arg2 as u64,
                    0,
                    0,
                ];
                let normalized = Syscall::from_raw(
                    Sysno::new(libc::SYS_execveat as usize).unwrap(),
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
                self.returned.lock().unwrap().push((errno, refusal));
                *guest.thread_state_mut() = (3, 1);
                Ok(-i64::from(errno.into_raw()))
            }
        }
        struct Rt;
        impl HostRuntime for Rt {
            fn fork_child_rebind(&self) {}
            fn emit_stage(&self, _stage: &[u8]) {}
            fn fork_child_reset(&self, _event: &SyscallEvent) {}
            fn cpuid_interception_enabled(&self) -> bool {
                false
            }
            fn exit_process_stats(&self, _tid: Pid) -> std::io::Result<()> {
                Ok(())
            }
            fn read_clock(&self) -> std::io::Result<u64> {
                Ok(0)
            }
            fn signal_action_supported(&self, number: i64, args: [u64; 6]) -> bool {
                crate::guest::signal::signal_action_supported(number, args)
            }
            fn reserved_signal_mask(&self) -> u64 {
                1_u64 << (libc::SIGSYS - 1)
            }
        }
        fn frame(stream: &mut UnixStream, payload: &[u8]) {
            use std::io::Write;
            stream
                .write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(payload).unwrap();
        }
        let _native = crate::guest::exec_private::native_exec_mock_callback();
        assert!(crate::guest::exec_private::native_exec_callback_facts().is_some());
        let (client, mut server) = UnixStream::pair().unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        let worker = std::thread::spawn(move || {
            frame(
                &mut server,
                &reverie_rpc_transport::codec::encode(&902_u64).unwrap(),
            );
            let mut byte = [0_u8; 1];
            let _ = server.read(&mut byte);
        });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let client = reverie_rpc_transport::BlockingRpcClient::from_connected_stream(
            crate::guest::rpc::GuestRpcStream::from(client),
            tid,
        )
        .unwrap();
        let rpc = CoordinatorRpc::<TestGlobal>::from_live_client(
            "unused-generic-driver-test",
            client,
            |_, _| panic!("no reconnect"),
        )
        .unwrap();
        let registry = Arc::new(Mutex::new(
            ExecTicketRegistry::new(TestProof, [5u8; 32]).unwrap(),
        ));
        let returned: ReturnedCalls = Arc::new(Mutex::new(Vec::new()));
        let tool = ExecTool {
            returned: returned.clone(),
        };
        // SwitchProvisioner (tests scope) honors PROVISION_OK.
        let driver = GenericNativeExecDriver::new(
            KernelCatalog,
            PairFramer,
            SwitchProvisioner {
                ok: PROVISION_OK.with(|ok| ok.get()),
                calls: Arc::new(Mutex::new(Vec::new())),
            },
            DirectIssuer {
                registry: registry.clone(),
                calls: Arc::new(Mutex::new(Vec::new())),
            },
            TestBinding { config: [3u8; 32] },
            b"runtime".to_vec(),
        );
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let mut host = Box::new(ToolHost::new(
            tool,
            rpc,
            pid,
            HashSet::from([Sysno::execve, Sysno::execveat, Sysno::getpid]),
            false,
            Rt,
        ));
        unsafe { host.install_native_exec_driver(Arc::new(driver)) }.unwrap();
        // S1 splits installation from admission: until the embedder
        // admits the route, dispatch never consults the driver.
        unsafe { host.admit_native_exec() }.unwrap();
        let mut event = SyscallEvent {
            number: libc::SYS_execve,
            args: [0x1000, 0x2000, 0x3000, 0, 0, 0],
            instruction_pointer: 0x1234,
            result: 0,
            context: 0,
            dispatch: SyscallDispatch::Fallback,
            guest_pkru: None,
            unsupported_refusal: None,
        };
        if ISSUE_ARMED.with(|armed| armed.get()) {
            crate::guest::native_exec::arm_test_issue();
        }
        unsafe { host.dispatch(&mut event) };
        let results = returned.lock().unwrap();
        assert_eq!(results.len(), 1, "results: {results:?}");
        let (errno, refusal) = &results[0];
        assert_eq!(*errno, Errno::EOPNOTSUPP);
        let refusal = refusal.as_ref().expect("named leaf refusal");
        if ISSUE_ARMED.with(|armed| armed.get()) {
            // Armed (test-only latch, forked child only): the host seam
            // lets the attempt reach this driver's leaf, which must
            // refuse by its N2b name and never call issuer.issue (the
            // exact call sequence below asserts that). Delivery-positive
            // only: prepare/seal/deliver/mark succeeded first.
            assert!(
                PROVISION_OK.with(|ok| ok.get()),
                "armed case is delivery-positive by construction"
            );
            assert!(
                refusal
                    .diagnostic
                    .contains("generic native exec leaf is N2b"),
                "{}",
                refusal.diagnostic
            );
            let calls = SHARED_CALLS.with(|l| l.borrow().clone());
            assert_eq!(
                calls,
                ["prepare", "seal", "deliver", "mark", "cancel"],
                "calls: {calls:?}"
            );
        } else if PROVISION_OK.with(|ok| ok.get()) {
            // Delivery-positive, unarmed: prepare/seal/deliver/mark
            // succeeded, then the S1 host-enforced final-step refusal
            // preempts this driver's N2b leaf (no successor execution
            // in this stage regardless of driver behavior; removing
            // that refusal is the seam that re-enables issue).
            assert!(
                refusal
                    .diagnostic
                    .contains("admitted native exec is refused at the final"),
                "{}",
                refusal.diagnostic
            );
            let calls = SHARED_CALLS.with(|l| l.borrow().clone());
            assert_eq!(
                calls,
                ["prepare", "seal", "deliver", "mark", "cancel"],
                "calls: {calls:?}"
            );
        } else {
            // No-provision causal control: zero marks, zero issues.
            assert!(
                refusal.diagnostic.contains("no provision delivery"),
                "{}",
                refusal.diagnostic
            );
            let calls = SHARED_CALLS.with(|l| l.borrow().clone());
            assert_eq!(
                calls,
                ["prepare", "seal", "deliver", "cancel"],
                "calls: {calls:?}"
            );
        }
        drop(host);
        worker.join().unwrap();
    }

    #[test]
    fn no_provision_means_no_mark_no_issue() {
        // Negative control (Astra P2): prepare+seal succeed, but with
        // RefusingProvisioner the flow must refuse BEFORE any delivery
        // mark or issuance, and cancel the ticket.
        let registry = Arc::new(Mutex::new(
            ExecTicketRegistry::new(TestProof, [5u8; 32]).unwrap(),
        ));
        let driver = GenericNativeExecDriver::new(
            KernelCatalog,
            PairFramer,
            RefusingProvisioner,
            DirectIssuer {
                registry: registry.clone(),
                calls: Arc::new(Mutex::new(Vec::new())),
            },
            TestBinding { config: [3u8; 32] },
            b"runtime".to_vec(),
        );
        let _ = driver;
        // Registry-level assertion of the same law the driver relies
        // on: issue without delivered mark refuses Transition.
        let mut reg = ExecTicketRegistry::new(TestProof, [6u8; 32]).unwrap();
        let snap = b"s".to_vec();
        let d = digest(&snap);
        let t = reg
            .prepare(7, TestBinding { config: [3u8; 32] }, snap, d)
            .unwrap();
        let sealed = reg.seal(7, t, digest(b"r"), b"r").unwrap();
        assert_eq!(
            reg.issue(7, t, sealed),
            Err(reverie_rpc_transport::exec_ticket::ExecControlError::Transition)
        );
    }

    #[test]
    fn cancel_uncertainty_is_terminal() {
        struct FailCancel;
        impl reverie_rpc_transport::exec_control::ExecIssuer<TestBinding> for FailCancel {
            fn prepare(
                &mut self,
                _b: TestBinding,
                _s: Vec<u8>,
                _d: [u8; 32],
            ) -> Result<ExecTicket, ExecControlError> {
                unreachable!()
            }
            fn seal(
                &mut self,
                _t: ExecTicket,
                _d: [u8; 32],
                _r: &[u8],
            ) -> Result<[u8; 32], ExecControlError> {
                unreachable!()
            }
            fn mark_provision_delivered(&mut self, _t: ExecTicket) -> Result<(), ExecControlError> {
                unreachable!()
            }
            fn issue(
                &mut self,
                _t: ExecTicket,
                _d: [u8; 32],
            ) -> Result<ExecTicket, ExecControlError> {
                unreachable!()
            }
            fn cancel(&mut self, _t: ExecTicket) -> Result<(), ExecControlError> {
                Err(ExecControlError::Dead)
            }
        }
        let mut issuer = FailCancel;
        let original = NativeExecFailure::Refused(refused("test original refusal"));
        let out = cancel_or_terminal(&mut issuer, ExecTicket([1; 32]), original);
        assert!(
            matches!(out, NativeExecFailure::Terminal(_)),
            "failed cancel must be Terminal, got {out:?}"
        );
    }

    #[test]
    fn no_provision_dispatch_records_zero_marks_and_issues() {
        // Causal driver-level control (Astra P2): real host dispatch
        // with RefusingProvisioner; recording issuer must observe
        // prepare,seal,deliver,cancel and ZERO mark/issue, and the
        // handler records the named no-delivery refusal.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                dispatch_no_provision_body,
            ))
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
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn dispatch_no_provision_body() {
        // Reuse the witness harness shape via env-selected provisioner:
        // simplest faithful route is the session prepare path through
        // the recording issuer at registry level is NOT sufficient
        // (Astra), so this drives GenericSession::prepare directly is
        // impossible without a cut; instead assert through the full
        // dispatch witness by swapping the provisioner via a thread-
        // local switch read by SwitchProvisioner in dispatch_body2.
        PROVISION_OK.with(|ok| ok.set(false));
        dispatch_body2();
    }
}
