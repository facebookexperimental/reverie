/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The host kernel as the in-guest backend's [`LinuxProvider`].
//!
//! The final forward of every syscall a Tool injects through
//! [`Guest::inject`](reverie::Guest::inject) or
//! [`Guest::tail_inject`](reverie::Guest::tail_inject) that the backend has
//! admitted runs here, through [`LinuxProvider::execute`]. The Tool
//! runs on the guest thread itself, so the call is that thread issuing the
//! syscall through the runtime's trusted gate. The provider owns no state:
//! the host kernel holds it all, and the gate token is the execution handle
//! ([`LinuxProvider::Context`]).
//!
//! The backend's filters stay in `InGuest`, before the token exists. They
//! protect what the runtime shares with the guest (its mappings, reserved
//! descriptors and signals, protection keys, staged endings and the private
//! loader), and none of them is Linux semantics. So are the calls the backend
//! answers or carries out itself, which still reach Linux directly: a plain
//! fork, native exec, `pkey_alloc`, the `brk(0)` probe and the `close_range`
//! split that protect the runtime's mappings and descriptors, and the
//! syscalls of the virtual signal calls. The provider receives only a call
//! the backend has admitted, and runs it unchanged.
//!
//! The provider produces only [`ProviderOutcome::Return`]. The call is a real
//! `syscall` instruction in the guest's own thread, so Linux restarts it or
//! returns `-EINTR` as for any thread, and both are results of a call that
//! ran: there is no stop before the instruction at which a signal could leave
//! it unrun ([`ProviderOutcome::Interrupted`]). Exits are staged before the
//! forward, nothing blocks in a cancellable way, and the host kernel creates
//! children and replaces images itself, so no other outcome arises.
//!
//! The provider is zero-sized and built at each call, so the call is
//! dispatched statically. `execute`'s future is still boxed, because the
//! trait is an `async_trait`: one small allocation from the Tool heap per
//! forwarded call, freed when the call returns. `execute` never awaits, so
//! [`forward`] polls that future once, synchronously, and the backend's
//! injection does not await it. Nothing the injection holds is therefore
//! kept across a suspension point: the runtime's scratch operands, such as
//! the stripped `rt_sigprocmask` set whose address is the call's second
//! argument, stay on the callback stack, where a guest seccomp filter that
//! inspects arguments saw them before the provider existed.
//!
//! The gate's tid is the caller's, copied in, not observed from the running
//! thread, so `execute`'s tid check is a guard on the contract, not a
//! detection: it cannot catch a call issued on the wrong thread.

use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::Tid;
use reverie::provider::LinuxProvider;
use reverie::provider::ProviderOutcome;
use reverie::provider::SyscallRequest;

use super::Error;
use super::Pid;
use super::io;
use super::tool_fatal;

/// The host kernel, reached through a backend gate.
pub(super) struct HostLinux<G>(PhantomData<fn() -> G>);

impl<G> HostLinux<G> {
    pub(super) fn new() -> Self {
        Self(PhantomData)
    }
}

/// How the backend reaches the host kernel for one admitted call.
///
/// A value is the proof that the backend's admission filters have run on the
/// call it is lent for; see each implementation's constructor.
pub(super) trait PhysicalGate: Send {
    /// A gate failure. It is a broken invariant, never a guest errno.
    type Error: Send;
    /// The guest thread on which the gate issues the call.
    fn tid(&self) -> Pid;
    /// Issues `number(args)` and returns Linux's raw result: a nonnegative
    /// value, or `-errno`.
    fn syscall(&mut self, number: i64, args: [u64; 6]) -> Result<i64, Self::Error>;
}

/// A broken backend invariant reported by [`LinuxProvider::execute`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum GateError<E> {
    /// `execute` was asked to run a call for a thread other than the gate's.
    WrongTask {
        /// The tid `execute` was given.
        task: Tid,
        /// The gate's own tid.
        gate: Pid,
    },
    /// The gate failed.
    Gate(E),
}

#[reverie::provider]
impl<G: PhysicalGate> LinuxProvider for HostLinux<G> {
    type Context = G;
    /// The host kernel creates children and replaces images itself, so there
    /// is never a plan for the backend.
    type Plan = Infallible;
    type Error = GateError<G::Error>;

    /// Runs `request` through `cx`, the gate, and returns Linux's raw result
    /// unchanged as [`ProviderOutcome::Return`].
    ///
    /// `task` must be the gate's own tid, as the trait requires of a provider
    /// bound to one task; anything else is a broken backend invariant and
    /// returns `Err` without issuing the call. The gate's tid is the one it
    /// was built with, so this guards the contract; it does not observe which
    /// thread runs the call.
    async fn execute(
        &mut self,
        task: Tid,
        request: &SyscallRequest,
        cx: &mut G,
    ) -> Result<ProviderOutcome<Infallible>, GateError<G::Error>> {
        if task != cx.tid() {
            return Err(GateError::WrongTask {
                task,
                gate: cx.tid(),
            });
        }
        let (number, args) = parts(request);
        cx.syscall(number, args)
            .map(ProviderOutcome::Return)
            .map_err(GateError::Gate)
    }
}

/// The request for a call of `number` with `args`. The number is carried bit
/// for bit, so [`parts`] gives back every `i64`.
fn request(number: i64, args: [u64; 6]) -> SyscallRequest {
    SyscallRequest::new(number as u64, args)
}

/// The syscall number and arguments of a request built by [`request`].
fn parts(request: &SyscallRequest) -> (i64, [u64; 6]) {
    (request.number() as i64, *request.args())
}

/// The raw result in `outcome`, if it is one `HostLinux` produces: only
/// [`ProviderOutcome::Return`] carries one.
fn raw_result(outcome: ProviderOutcome<Infallible>) -> Option<i64> {
    match outcome {
        ProviderOutcome::Return(raw) => Some(raw),
        _ => None,
    }
}

/// The trusted guest gate (`physical_guest_syscall6` without a protection-key
/// image), on the calling guest thread.
struct GuestGate {
    tid: Pid,
}

impl GuestGate {
    /// # Safety
    ///
    /// The gate is lent to exactly one [`LinuxProvider::execute`] call, on the
    /// guest thread `tid`, in its own syscall turn. Before that call, the
    /// backend's admission filters have run on exactly the request it is
    /// given, so that every obligation of
    /// [`physical_guest_syscall6`](crate::trap::physical_guest_syscall6) with
    /// `pkru` `None` holds for it.
    unsafe fn new(tid: Pid) -> Self {
        Self { tid }
    }
}

impl PhysicalGate for GuestGate {
    type Error = Infallible;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn syscall(&mut self, number: i64, args: [u64; 6]) -> Result<i64, Infallible> {
        #[cfg(test)]
        tests::GUEST_GATE_CALLS.with(|calls| calls.borrow_mut().push((number, args)));
        // SAFETY: `GuestGate::new`'s caller admitted this call.
        Ok(unsafe { crate::trap::physical_guest_syscall6(number, args, None) }.result)
    }
}

/// Polls `future` once, with a waker that does nothing, and returns its
/// output if it is ready. A future that is not ready is dropped.
fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

/// Forwards `number(args)` for the guest thread `tid` to the host kernel,
/// through [`HostLinux`] over the trusted guest gate, and returns Linux's raw
/// result.
///
/// The call is synchronous: `execute`'s future is polled once, here, and
/// completes on that poll because `execute` never awaits. So the caller does
/// not await, and nothing it holds moves into its own boxed future.
///
/// A broken invariant (`execute` not completing on its first poll, refusing
/// the call, or an outcome other than `Return`) ends the process with status
/// 125, as the backend's other broken invariants do; it is never a guest
/// errno. None can happen: `execute` has no await point, and the gate and the
/// request are built here for the same `tid`.
///
/// # Safety
///
/// `tid` is the calling guest thread, in its own syscall turn, and every
/// admission filter of the backend has run on exactly `number` and `args`, as
/// for [`physical_guest_syscall6`](crate::trap::physical_guest_syscall6) with
/// `pkru` `None`.
pub(super) unsafe fn forward(tid: Pid, number: i64, args: [u64; 6]) -> i64 {
    // SAFETY: the caller admitted `number(args)` on `tid`, and the gate is
    // lent to this one call.
    let mut gate = unsafe { GuestGate::new(tid) };
    let request = request(number, args);
    let outcome = poll_once(HostLinux::<GuestGate>::new().execute(tid, &request, &mut gate));
    let broken = match outcome {
        None => format!("HostLinux did not complete syscall {number} on its first poll"),
        Some(Ok(outcome)) => match raw_result(outcome) {
            Some(raw) => return raw,
            None => format!("HostLinux produced {outcome:?} for syscall {number}"),
        },
        Some(Err(GateError::WrongTask { task, gate })) => {
            format!("HostLinux was asked to run syscall {number} for tid {task} on tid {gate}")
        }
        Some(Err(GateError::Gate(never))) => match never {},
    };
    tool_fatal(125, &Error::Tool(io::Error::other(broken).into()))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Write;

    use reverie::Guest;
    use reverie::syscalls::Syscall;
    use reverie::syscalls::SyscallArgs;
    use reverie::syscalls::Sysno;

    use super::super::HostRuntime;
    use super::super::InGuest;
    use super::*;
    use crate::guest::event::SyscallDispatch;
    use crate::guest::event::SyscallEvent;
    use crate::guest::rpc::CoordinatorRpc;
    use crate::guest::rpc::GuestRpcStream;
    use crate::tool_host::SyscallOutcome;
    use crate::tool_host::TailResult;
    use crate::tool_host::drive_ready;
    use crate::tool_host::drive_syscall;

    thread_local! {
        /// Every call `GuestGate` issued on this thread, in order.
        pub(super) static GUEST_GATE_CALLS: RefCell<Vec<(i64, [u64; 6])>> =
            const { RefCell::new(Vec::new()) };
    }

    fn take_guest_gate_calls() -> Vec<(i64, [u64; 6])> {
        GUEST_GATE_CALLS.with(|calls| calls.take())
    }

    /// A gate that records every call and answers each with `result`.
    struct MockGate {
        tid: Pid,
        result: Result<i64, &'static str>,
        calls: Vec<(i64, [u64; 6])>,
    }

    impl MockGate {
        fn new(tid: i32, result: Result<i64, &'static str>) -> Self {
            Self {
                tid: Pid::from_raw(tid),
                result,
                calls: Vec::new(),
            }
        }
    }

    impl PhysicalGate for MockGate {
        type Error = &'static str;

        fn tid(&self) -> Pid {
            self.tid
        }

        fn syscall(&mut self, number: i64, args: [u64; 6]) -> Result<i64, &'static str> {
            self.calls.push((number, args));
            self.result
        }
    }

    fn execute(
        task: i32,
        number: i64,
        args: [u64; 6],
        gate: &mut MockGate,
    ) -> Result<ProviderOutcome<Infallible>, GateError<&'static str>> {
        drive_ready(HostLinux::<MockGate>::new().execute(
            Pid::from_raw(task),
            &request(number, args),
            gate,
        ))
    }

    const ARGS: [u64; 6] = [0, 1, u64::MAX, 0x7fff_ffff_f000, 42, 1 << 63];

    /// The provider and the guest gate carry no state of their own.
    #[test]
    fn the_provider_is_zero_sized() {
        assert_eq!(size_of::<HostLinux<GuestGate>>(), 0);
        assert_eq!(size_of::<HostLinux<MockGate>>(), 0);
    }

    /// The gate receives the request's number and all six arguments
    /// unchanged, including arguments with the top bit set and numbers
    /// outside the syscall table, and is called exactly once.
    #[test]
    fn the_request_reaches_the_gate_unchanged() {
        for number in [
            libc::SYS_getppid,
            libc::SYS_read,
            libc::SYS_rt_sigprocmask,
            0,
            -1,
            i64::MAX,
            i64::MIN,
        ] {
            assert_eq!(parts(&request(number, ARGS)), (number, ARGS));
            let mut gate = MockGate::new(7, Ok(0));
            execute(7, number, ARGS, &mut gate).unwrap();
            assert_eq!(gate.calls, [(number, ARGS)]);
        }
    }

    /// Linux's raw result comes back as `Return`, bit for bit: a success, a
    /// success that reads as a large negative number outside the errno
    /// range, and every errno from the smallest to the largest.
    #[test]
    fn the_raw_result_is_returned_unchanged() {
        for raw in [0, 1, -1, -4, -512, -4095, -4096, i64::MAX, i64::MIN] {
            let mut gate = MockGate::new(7, Ok(raw));
            assert_eq!(
                execute(7, libc::SYS_getppid, ARGS, &mut gate),
                Ok(ProviderOutcome::Return(raw))
            );
            assert_eq!(raw_result(ProviderOutcome::Return(raw)), Some(raw));
        }
    }

    /// A call for a thread other than the gate's is refused as a broken
    /// invariant, and the gate is never called.
    #[test]
    fn a_call_for_another_thread_is_refused_without_running() {
        let mut gate = MockGate::new(7, Ok(0));
        assert_eq!(
            execute(8, libc::SYS_getppid, ARGS, &mut gate),
            Err(GateError::WrongTask {
                task: Pid::from_raw(8),
                gate: Pid::from_raw(7),
            })
        );
        assert!(gate.calls.is_empty());
    }

    /// A gate failure is a broken invariant, not a guest errno.
    #[test]
    fn a_gate_failure_is_an_error_not_a_result() {
        let mut gate = MockGate::new(7, Err("permit lost"));
        assert_eq!(
            execute(7, libc::SYS_getppid, ARGS, &mut gate),
            Err(GateError::Gate("permit lost"))
        );
    }

    /// Only `Return` carries a raw result. Every other outcome is one
    /// `HostLinux` never produces, which `forward` treats as a broken
    /// invariant.
    #[test]
    fn only_a_return_outcome_carries_a_raw_result() {
        assert_eq!(raw_result(ProviderOutcome::Interrupted), None);
        assert_eq!(raw_result(ProviderOutcome::Cancelled), None);
        assert_eq!(
            raw_result(ProviderOutcome::ThreadGroupExited {
                status: reverie::ExitStatus::Exited(0),
            }),
            None
        );
        assert_eq!(
            raw_result(ProviderOutcome::SegmentBase {
                result: 0,
                register: reverie::provider::SegmentRegister::Fs,
                base: 0x1000,
            }),
            None
        );
    }

    /// The guest gate, over a real `getppid`, returns what the kernel
    /// returns, through the provider. Outside an installed runtime the
    /// trusted gate is an ordinary `syscall` instruction.
    #[test]
    fn the_guest_gate_runs_the_call_on_the_host() {
        let tid = Pid::from_raw(unsafe { libc::gettid() });
        take_guest_gate_calls();
        let raw = unsafe { forward(tid, libc::SYS_getppid, [0; 6]) };
        assert_eq!(raw, i64::from(unsafe { libc::getppid() }));
        assert_eq!(take_guest_gate_calls(), [(libc::SYS_getppid, [0; 6])]);
    }

    /// `forward` takes a result only from a future that is ready on its
    /// first poll; one that is not is dropped, which `forward` treats as a
    /// broken invariant.
    #[test]
    fn only_a_future_ready_on_its_first_poll_gives_a_result() {
        assert_eq!(poll_once(async { 7 }), Some(7));
        assert_eq!(poll_once(std::future::pending::<i64>()), None);
    }

    /// The boxed `execute` future, the one allocation `forward` adds, is
    /// small. Its size is printed for the record.
    #[test]
    fn the_execute_future_is_one_small_box() {
        let tid = Pid::from_raw(unsafe { libc::gettid() });
        // SAFETY: the gate is never polled, so it issues no call.
        let mut gate = unsafe { GuestGate::new(tid) };
        let request = request(libc::SYS_getppid, [0; 6]);
        let mut provider = HostLinux::<GuestGate>::new();
        let future = provider.execute(tid, &request, &mut gate);
        let size = size_of_val(&*future);
        println!("HostLinux<GuestGate>::execute future: {size} bytes");
        assert!(size <= 64, "{size} bytes");
    }

    /// The services an `InGuest` needs to forward a call: none is used
    /// except the reserved signals, which are SIGSYS.
    struct ForwardRuntime;

    impl HostRuntime for ForwardRuntime {
        fn fork_child_rebind(&self) {
            panic!("test does not fork")
        }
        fn emit_stage(&self, _stage: &[u8]) {}
        fn fork_child_reset(&self, _event: &SyscallEvent) {
            panic!("test does not fork")
        }
        fn cpuid_interception_enabled(&self) -> bool {
            false
        }
        fn exit_process_stats(&self, _tid: Pid) -> io::Result<()> {
            panic!("test does not exit")
        }
        fn read_clock(&self) -> io::Result<u64> {
            panic!("test does not read a clock")
        }
        fn signal_action_supported(&self, _number: i64, _args: [u64; 6]) -> bool {
            true
        }
        fn reserved_signal_mask(&self) -> u64 {
            1 << (libc::SIGSYS - 1)
        }
    }

    /// A coordinator connection that is never used, and the peer end that
    /// keeps it open.
    fn coordinator() -> (CoordinatorRpc<()>, std::os::unix::net::UnixStream) {
        let (client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let config = reverie_rpc_transport::codec::encode(&()).unwrap();
        peer.write_all(&(config.len() as u32).to_be_bytes())
            .unwrap();
        peer.write_all(&config).unwrap();
        let tid = Pid::from_raw(unsafe { libc::gettid() });
        let client = reverie_rpc_transport::BlockingRpcClient::<(), _>::from_connected_stream(
            GuestRpcStream::from(client),
            tid,
        )
        .unwrap();
        let rpc = CoordinatorRpc::from_live_client("unused-host-linux-test", client, |_, _| {
            panic!("the forwarding test must not reconnect")
        })
        .unwrap();
        (rpc, peer)
    }

    /// The `rt_sigprocmask(SIG_BLOCK, set, old, 8)` call a Tool injects, with
    /// the guest's set and old set in `set` and `old`.
    fn block(set: &u64, old: &mut u64) -> Syscall {
        Syscall::from_raw(
            Sysno::rt_sigprocmask,
            SyscallArgs::new(
                libc::SIG_BLOCK as usize,
                set as *const u64 as usize,
                old as *mut u64 as usize,
                size_of::<u64>(),
                0,
                0,
            ),
        )
    }

    /// The calling thread's stack.
    fn thread_stack() -> std::ops::Range<u64> {
        unsafe {
            let mut attr: libc::pthread_attr_t = core::mem::zeroed();
            assert_eq!(libc::pthread_getattr_np(libc::pthread_self(), &mut attr), 0);
            let mut base = core::ptr::null_mut();
            let mut size = 0;
            assert_eq!(libc::pthread_attr_getstack(&attr, &mut base, &mut size), 0);
            assert_eq!(libc::pthread_attr_destroy(&mut attr), 0);
            base as u64..base as u64 + size as u64
        }
    }

    fn signal_bit(signal: i32) -> u64 {
        1 << (signal - 1)
    }

    /// Runs `inject` (or `tail_inject`, from a syscall handler) of a guest
    /// `rt_sigprocmask` that blocks SIGUSR2 and the reserved SIGSYS, and
    /// checks what reached the gate: one call, with the guest's old-set
    /// pointer and, in place of the guest's set, the runtime's stripped copy
    /// on this thread's stack. That is where it was before the provider: a
    /// guest seccomp filter that inspects arguments sees the same kind of
    /// address. Had the copy been held across an await it would live in the
    /// injection's boxed future, on the heap.
    fn the_stripped_set_reaches_the_gate_from_the_stack(tail_inject: bool) {
        let (rpc, _peer) = coordinator();
        let mut event = SyscallEvent {
            number: libc::SYS_rt_sigprocmask,
            args: [0; 6],
            instruction_pointer: 0,
            result: 0,
            context: 0,
            dispatch: SyscallDispatch::InstalledHook,
            guest_pkru: None,
        };
        let tail = TailResult::default();
        let mut state = ();
        let tid = Pid::from_raw(unsafe { libc::gettid() });
        let mut guest = InGuest::<(), ForwardRuntime> {
            event: &mut event,
            tid,
            pid: Pid::from_raw(unsafe { libc::getpid() }),
            ppid: None,
            state: &mut state,
            rpc: &rpc,
            tail: &tail,
            cpuid_interception: false,
            fork_parent_state: None,
            runtime: &ForwardRuntime,
            staged_signals: Vec::new(),
            staged_signal_delivery: false,
            in_syscall_handler: tail_inject,
            #[cfg(feature = "exec-native-injection")]
            exec: None,
            #[cfg(feature = "exec-native-injection")]
            mapping_driver: None,
            unsupported_refusal: None,
        };
        // The guest's sets are on the heap, so the only stack address that
        // can reach the gate is the runtime's copy.
        let set = Box::new(signal_bit(libc::SIGUSR2) | signal_bit(libc::SIGSYS));
        let mut old = Box::new(0_u64);
        let call = block(&set, &mut old);
        take_guest_gate_calls();
        let result = if tail_inject {
            // tail_inject parks once it has stored the result.
            assert!(poll_once(guest.tail_inject(call)).is_none());
            match drive_syscall(std::future::pending::<Result<i64, Error>>(), &tail) {
                SyscallOutcome::Return(result) => result.map_err(|error| format!("{error:?}")),
                _ => Err("tail_inject did not park a result".to_owned()),
            }
        } else {
            drive_ready(guest.inject(call)).map_err(|errno| format!("{errno:?}"))
        };
        let calls = take_guest_gate_calls();
        // Read the mask Linux installed, then restore the guest's old one.
        let mut installed = 0_u64;
        let restored = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const *old) as u64,
                    (&raw mut installed) as u64,
                    size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        assert_eq!(restored, 0);
        assert_eq!(result, Ok(0));
        assert_eq!(
            installed & signal_bit(libc::SIGUSR2),
            signal_bit(libc::SIGUSR2)
        );
        assert_eq!(
            installed & signal_bit(libc::SIGSYS),
            *old & signal_bit(libc::SIGSYS)
        );
        let [(number, args)] = calls[..] else {
            panic!("expected one forwarded call, got {calls:?}");
        };
        assert_eq!(number, libc::SYS_rt_sigprocmask);
        assert_eq!(args[0], libc::SIG_BLOCK as u64);
        assert_eq!(args[2], (&raw const *old) as u64);
        assert_eq!(args[3], size_of::<u64>() as u64);
        assert_ne!(
            args[1],
            (&raw const *set) as u64,
            "the set was not stripped"
        );
        let stack = thread_stack();
        assert!(
            stack.contains(&args[1]),
            "the stripped set at {:#x} is not on the callback stack {:#x}..{:#x}",
            args[1],
            stack.start,
            stack.end
        );
    }

    #[test]
    fn an_injected_stripped_set_reaches_the_gate_from_the_stack() {
        the_stripped_set_reaches_the_gate_from_the_stack(false);
    }

    #[test]
    fn a_tail_injected_stripped_set_reaches_the_gate_from_the_stack() {
        the_stripped_set_reaches_the_gate_from_the_stack(true);
    }
}
