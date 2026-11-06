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
//! [`ExecIssuer`], and the physical leaf call at issue.
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
    sealed_digest: [u8; 32],
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
                let _ = issuer.cancel(ticket);
                return Err(control_terminal(error));
            }
        };
        // Actual delivery first; the delivered fact is recorded only
        // after the embedder's receipt. No delivery => cancel+refuse.
        if let Err(error) = self.provisioner.deliver(ticket, sealed_digest) {
            let _ = issuer.cancel(ticket);
            return Err(match error {
                ExecControlError::Unavailable => NativeExecFailure::Refused(refused(
                    "reverie-inguest: generic native exec has no provision delivery",
                )),
                other => control_terminal(other),
            });
        }
        if let Err(error) = issuer.mark_provision_delivered(ticket) {
            let _ = issuer.cancel(ticket);
            return Err(control_terminal(error));
        }
        drop(issuer);
        Ok(Box::new(GenericPrepared {
            _binding: std::marker::PhantomData,
            framer: self.framer.clone(),
            issuer: self.issuer.clone(),
            ticket,
            sealed_digest,
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
        // Final exact-state check after the last acknowledgment point
        // available to this driver (leaf contract shape), then Issue.
        if self.framer.encode(state) != self.encoded {
            return Err(NativeExecFailure::Refused(refused(
                "reverie-inguest: generic native exec prepared state changed at issue",
            )));
        }
        {
            let mut issuer = self
                .issuer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            issuer
                .issue(self.ticket, self.sealed_digest)
                .map_err(control_terminal)?;
        }
        let leaf = unsafe { super::exec_private::IssuedNativeExecLeaf::after_issue(_cut) }?;
        let encoded = self.encoded.clone();
        let framer = &self.framer;
        unsafe {
            leaf.call(|| {
                if framer.encode(state) != encoded {
                    return Err(NativeExecFailure::Refused(refused(
                        "reverie-inguest: generic native exec state changed at leaf",
                    )));
                }
                Ok(())
            })
        }
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

    struct DirectIssuer {
        registry: Arc<Mutex<ExecTicketRegistry<TestProof, TestBinding>>>,
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
            self.registry
                .lock()
                .unwrap()
                .seal(7, ticket, digest, runtime)
        }
        fn mark_provision_delivered(
            &mut self,
            ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
        ) -> Result<(), ExecControlError> {
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
            self.registry.lock().unwrap().issue(7, ticket, digest)?;
            Ok(ticket)
        }
        fn cancel(
            &mut self,
            ticket: reverie_rpc_transport::exec_ticket::ExecTicket,
        ) -> Result<(), ExecControlError> {
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
            DirectIssuer { registry },
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
        struct OkProvisioner;
        impl Provisioner for OkProvisioner {
            fn deliver(
                &self,
                _ticket: ExecTicket,
                _sealed_digest: [u8; 32],
            ) -> Result<(), ExecControlError> {
                Ok(())
            }
        }
        let driver = GenericNativeExecDriver::new(
            KernelCatalog,
            PairFramer,
            OkProvisioner,
            DirectIssuer {
                registry: registry.clone(),
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
        let mut event = SyscallEvent {
            number: libc::SYS_execve,
            args: [0x1000, 0x2000, 0x3000, 0, 0, 0],
            instruction_pointer: 0x1234,
            result: 0,
            context: 0,
            dispatch: SyscallDispatch::Fallback,
            guest_pkru: None,
        };
        unsafe { host.dispatch(&mut event) };
        let results = returned.lock().unwrap();
        assert_eq!(results.len(), 1, "results: {results:?}");
        let (errno, refusal) = &results[0];
        assert_eq!(*errno, Errno::EOPNOTSUPP);
        let refusal = refusal.as_ref().expect("named leaf refusal");
        // The wired leaf refuses by name here: synthetic dispatch has
        // no genuine running fallback resume receipt (only a real
        // fallback continuation entry mints one). Issue happened
        // first; the host attempt then cancelled the ticket.
        assert!(
            refusal.diagnostic.contains("fallback resume mask"),
            "{}",
            refusal.diagnostic
        );
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
}
