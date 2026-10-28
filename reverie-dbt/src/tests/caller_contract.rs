/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use super::*;
use crate::caller_abi::TerminalFact;
use crate::caller_effects::CallerEffects;

struct Remote;
impl Default for Remote {
    fn default() -> Self {
        panic!("no local GlobalState is constructed")
    }
}
#[reverie::global_tool]
impl GlobalTool for Remote {
    type Config = u64;
    type Request = Vec<u8>;
    type Response = u64;
    async fn receive_rpc(&self, _: Pid, _: Vec<u8>) -> u64 {
        panic!("no local fallback")
    }
}
struct Endpoint {
    config: u64,
    sent: AtomicUsize,
}
#[reverie::tool]
impl GlobalRPC<Remote> for Endpoint {
    async fn send_rpc(&self, message: Vec<u8>) -> u64 {
        assert_eq!(message, [71]);
        self.sent.fetch_add(1, Ordering::SeqCst);
        83
    }
    fn try_send_rpc_sync(&self, message: Vec<u8>) -> Result<u64, Vec<u8>> {
        assert_eq!(message, [71]);
        self.sent.fetch_add(1, Ordering::SeqCst);
        Ok(83)
    }
    fn config(&self) -> &u64 {
        &self.config
    }
}
#[derive(Default)]
struct Probe {
    mode: u64,
    attempts: AtomicUsize,
    drops: AtomicUsize,
}
struct Attempt<'a>(&'a AtomicUsize);
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[reverie::tool]
impl Tool for Probe {
    type GlobalState = Remote;
    type ThreadState = u64;
    fn new(pid: Pid, config: &u64) -> Self {
        assert_eq!(pid.as_raw(), 41);
        Self {
            mode: *config,
            ..Self::default()
        }
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        let _drop = Attempt(&self.drops);
        assert_eq!(*guest.config(), self.mode);
        match self.mode {
            1 if attempt == 0 => Err(Errno::ERESTARTSYS.into()),
            2 => Err(Errno::EACCES.into()),
            3 => Err(std::io::Error::other("actual fatal Tool error").into()),
            4 => guest.tail_inject(syscall).await,
            5 | 6 => {
                let tail_drops = AtomicUsize::new(0);
                let future = guest.tail_inject(syscall);
                let mut tail = Box::pin(async {
                    let _drop = Attempt(&tail_drops);
                    future.await
                });
                assert!(
                    tail.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                assert_eq!(tail_drops.load(Ordering::SeqCst), 0);
                drop(tail);
                // Drop the owned future (and its real tail-injection future),
                // not only a temporary Pin<&mut _>, before returning Ready.
                assert_eq!(tail_drops.load(Ordering::SeqCst), 1);
                Ok(19)
            }
            _ => {
                let answer = guest.send_rpc(vec![71]).await;
                *guest.thread_state_mut() += answer;
                Ok(guest.inject(syscall).await?)
            }
        }
    }
}
#[derive(Default)]
struct Native {
    invoked: AtomicUsize,
    registers: AtomicUsize,
    admitted: AtomicUsize,
}
unsafe extern "C" fn native(context: usize, _: i64, _: *const u64, _: u32) -> i64 {
    unsafe { &*(context as *const Native) }
        .invoked
        .fetch_add(1, Ordering::SeqCst);
    317
}
unsafe extern "C" fn registers(context: usize, _: *mut libc::user_regs_struct) -> i32 {
    unsafe { &*(context as *const Native) }
        .registers
        .fetch_add(1, Ordering::SeqCst);
    0
}
unsafe extern "C" fn set_registers(context: usize, _: *const libc::user_regs_struct) -> i32 {
    unsafe { &*(context as *const Native) }
        .registers
        .fetch_add(1, Ordering::SeqCst);
    0
}
unsafe extern "C" fn admit(
    context: usize,
    number: i64,
    args: *const u64,
    out: *mut TerminalFact,
) -> i32 {
    unsafe { &*(context as *const Native) }
        .admitted
        .fetch_add(1, Ordering::SeqCst);
    unsafe {
        out.write(TerminalFact {
            size: std::mem::size_of::<TerminalFact>() as u32,
            kind: 1,
            image: 7,
            context: context as u64,
            pid: 41,
            tid: 43,
            sysno: number,
            args: *args.cast::<[u64; 6]>(),
            cookie: 11,
            origin: 2,
            reserved: 0,
        });
    }
    1
}
fn call(number: Sysno, first: usize) -> Syscall {
    Syscall::from_raw(number, SyscallArgs::new(first, 0, 0, 0, 0, 0))
}
fn pending<F: Future>(future: F) {
    let mut future = pin!(future);
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}
fn guest<'a>(
    native_state: &'a Native,
    state: &'a mut u64,
    rpc: &'a Endpoint,
    effects: Arc<CallerEffects>,
) -> DbtGuest<'a, Probe> {
    DbtGuest::new_with_rpc(
        native_state as *const Native as usize,
        Pid::from_raw(43),
        Pid::from_raw(41),
        None,
        29,
        state,
        rpc,
        native,
        registers,
        set_registers,
    )
    .with_caller_effects(effects, true)
}
fn effects(native_state: &Native) -> Arc<CallerEffects> {
    Arc::new(CallerEffects::new(
        native_state as *const Native as usize,
        41,
        43,
        7,
        admit,
    ))
}

#[test]
fn established_ending_closes_old_handles_and_effects_without_disabling_exit_rpc() {
    let native_state = Native::default();
    let rpc = Endpoint {
        config: 71,
        sent: AtomicUsize::new(0),
    };
    let ending = effects(&native_state);
    let mut state = 0;
    let mut guest = guest(&native_state, &mut state, &rpc, Arc::clone(&ending));
    let mut memory = guest.memory();
    let mut source = [3_u8, 5, 7, 11];
    let address = AddrMut::from_raw(source.as_mut_ptr() as usize).unwrap();
    let mut output = [0_u8; 4];
    assert_eq!(memory.read(address, &mut output), Ok(4));
    assert_eq!(output, source);
    pending(guest.tail_inject(call(Sysno::exit_group, 42)));
    let fact = ending.ending().unwrap();
    assert_eq!(fact.args, [42, 0, 0, 0, 0, 0]);
    assert_eq!(native_state.admitted.load(Ordering::SeqCst), 1);

    output.fill(99);
    assert_eq!(memory.read(address, &mut output), Err(Errno::ESRCH));
    assert_eq!(memory.read_exact(address, &mut []), Err(Errno::ESRCH));
    assert_eq!(
        memory.read_exact_with_user_access(address, &mut output),
        Err(Errno::ESRCH)
    );
    assert_eq!(memory.write(address, &[17; 4]), Err(Errno::ESRCH));
    assert_eq!(memory.write_exact(address, &[]), Err(Errno::ESRCH));
    assert_eq!(
        memory.write_with_user_access(address, &[17]),
        Err(Errno::ESRCH)
    );
    assert_eq!(
        memory.write_native_user_vectored(43, &[], &[]),
        Err(Errno::ESRCH)
    );
    assert_eq!(memory.read_vectored(&[], &mut []), Err(Errno::ESRCH));
    assert_eq!(memory.write_vectored(&[], &mut []), Err(Errno::ESRCH));
    assert_eq!(
        memory.compare_exchange_u32(address.cast(), 0, 1),
        Err(Errno::ESRCH)
    );
    assert_eq!(source, [3, 5, 7, 11]);
    assert_eq!(output, [99; 4]);
    let message = vec![71];
    let allocation = message.as_ptr();
    let refused = guest.try_send_rpc_sync(message).unwrap_err();
    assert_eq!(refused.as_ptr(), allocation);
    pending(guest.send_rpc(vec![71]));
    pending(guest.inject(call(Sysno::write, 1)));
    pending(guest.tail_inject(call(Sysno::getpid, 0)));
    pending(guest.set_regs(unsafe { std::mem::zeroed() }));
    pending(guest.regs());
    assert_eq!(
        guest.set_signal_info([0; reverie::SIGNAL_INFO_SIZE]),
        Err(Errno::ESRCH)
    );
    ending.refuse("a later unsupported effect cannot replace ending");
    assert_eq!(ending.ending(), Some(fact));
    assert_eq!(ending.refusal(), None);
    assert_eq!(native_state.invoked.load(Ordering::SeqCst), 0);
    assert_eq!(native_state.registers.load(Ordering::SeqCst), 0);
    assert_eq!(rpc.sent.load(Ordering::SeqCst), 0);
    drop(guest);
    assert_eq!(memory.read(address, &mut output), Err(Errno::ESRCH));
    // Consuming hooks receive the live endpoint directly, after Guest borrows.
    assert_eq!(
        run_ready(rpc.send_rpc(vec![71]), &TailInjectResult::default()),
        Some(83)
    );
    assert_eq!(rpc.sent.load(Ordering::SeqCst), 1);
}

#[test]
fn caller_shared_driver_preserves_restart_errno_fatal_and_tail_facts() {
    for mode in 0..=6 {
        let native_state = Native::default();
        let rpc = Endpoint {
            config: mode,
            sent: AtomicUsize::new(0),
        };
        let configuration = reverie::ToolConfiguration::<Probe>::select(Arc::new(mode));
        let process = reverie::ToolProcess::adopt_selected(
            configuration.new_process(Pid::from_raw(41)),
            configuration,
        );
        let ending = effects(&native_state);
        let mut state = 0;
        let call = if mode == 6 {
            call(Sysno::exit_group, 42)
        } else {
            call(Sysno::getpid, 0)
        };
        let result = run_caller_syscall_with_guest(
            &process,
            guest(&native_state, &mut state, &rpc, Arc::clone(&ending)),
            call,
        );
        match mode {
            0 | 1 => {
                assert!(matches!(result, Ok(CallerSyscallOutcome::Suppress(317))));
                assert_eq!(native_state.invoked.load(Ordering::SeqCst), 1);
                assert_eq!(rpc.sent.load(Ordering::SeqCst), 1);
                assert_eq!(state, 83);
            }
            2 => assert!(matches!(result, Ok(CallerSyscallOutcome::Suppress(-13)))),
            3 => assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("actual fatal Tool error")
            ),
            4 => assert!(
                matches!(result, Ok(CallerSyscallOutcome::ExecuteOriginal(actual)) if actual == call)
            ),
            5 => assert!(matches!(result, Ok(CallerSyscallOutcome::Suppress(19)))),
            6 => assert!(matches!(result, Ok(CallerSyscallOutcome::Terminal(fact))
                if fact == ending.ending().unwrap() && fact.args[0] == 42)),
            _ => unreachable!(),
        }
        let expected_attempts = if mode == 1 { 2 } else { 1 };
        let tool = process.as_ref().unwrap();
        assert_eq!(tool.attempts.load(Ordering::SeqCst), expected_attempts);
        assert_eq!(tool.drops.load(Ordering::SeqCst), expected_attempts);
        if mode >= 2 {
            assert_eq!(native_state.invoked.load(Ordering::SeqCst), 0);
            assert_eq!(rpc.sent.load(Ordering::SeqCst), 0);
        }
    }
}
