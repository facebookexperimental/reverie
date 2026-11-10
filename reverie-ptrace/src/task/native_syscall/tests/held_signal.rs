/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

use reverie::Stack;

use super::*;

const CLOSE_ARGS: [u64; 6] = [(-1i64) as u64, 11, 13, 17, 19, 23];
static SIGNAL_HITS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn caught_signal(_: i32) {
    SIGNAL_HITS.fetch_add(1, Ordering::SeqCst);
}

#[derive(Default)]
struct HeldSignalTool;

#[reverie::tool]
impl Tool for HeldSignalTool {
    type GlobalState = NativeGlobal;
    type ThreadState = ();

    fn new(_: Pid, _: &Mode) -> Self {
        Self
    }

    fn subscriptions(_: &Mode) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    fn enforces_serialized_execution(_: &Mode) -> bool {
        true
    }

    fn reserved_input_requirement(_: &Mode) -> Option<ReservedInputRequirement> {
        Some(ReservedInputRequirement::sealed_page())
    }

    fn observes_native_syscalls(_: &Mode) -> bool {
        true
    }

    fn observe_native_syscall(
        &self,
        _: &(),
        _: &dyn NativeSyscallFacts,
        call: &NativeSyscallCall,
    ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error> {
        if call.purpose != NativeSyscallPurpose::Application {
            return Ok(None);
        }
        Ok(Some(Arc::new(Cookie {
            operation: false,
            evidence: evidence(),
        })))
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(call.into_parts().0, Sysno::getpid);
        // The existing temporary-mask helper owns distinct scratch and is
        // prepared before binding or release of the intended close request.
        let mut stack = guest.stack().await;
        let timeout_addr = stack.push([0u64; 2]);
        let empty_addr = stack.push(0u64);
        let _guard = stack.commit()?;
        let ppoll = reverie::syscalls::Ppoll::new()
            .with_fds(None)
            .with_nfds(0)
            .with_timeout(reverie::syscalls::AddrMut::from_raw(timeout_addr.as_raw()))
            .with_sigmask(Some(empty_addr.cast()))
            .with_sigsetsize(8);
        let intended = Syscall::from_raw(
            Sysno::close,
            SyscallArgs::new(
                CLOSE_ARGS[0] as usize,
                CLOSE_ARGS[1] as usize,
                CLOSE_ARGS[2] as usize,
                CLOSE_ARGS[3] as usize,
                CLOSE_ARGS[4] as usize,
                CLOSE_ARGS[5] as usize,
            ),
        );
        let control = guest.reserved_input_control().unwrap();
        let task = guest.reserved_input_task().unwrap();
        control
            .grant(task, InputGrantKind::Ordinary)
            .map_err(anyhow::Error::new)?;
        let operation = NativeOperation::new(Arc::new(Operation(evidence())));
        let _close = CloseOperation {
            operation: operation.clone(),
            evidence: evidence(),
        };
        let constrained = guest.bind_native_request(&operation, intended)?;
        control.invalidate_operation(task);
        // This is a real pending signal and an actual native ppoll restart
        // result, not a test write to the backend's held-signal state.
        assert_eq!(guest.inject(ppoll).await, Err(Errno::ERESTARTNOHAND));
        let mut bound = NativeOperationGuest::<_, Self>::new(guest, constrained)?;
        assert_eq!(
            bound.inject_with_retry(intended).await,
            Err(Errno::EBADF),
            "held-signal preparation must restore the exact intended request"
        );
        operation.close();
        assert!(operation.effects_complete());
        Ok(45)
    }
}

fn guest_with_pending_signal() {
    unsafe {
        let signal = libc::SIGRTMIN() + 2;
        SIGNAL_HITS.store(0, Ordering::SeqCst);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = caught_signal as *const () as usize;
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        assert_ne!(libc::signal(libc::SIGTRAP, libc::SIG_DFL), libc::SIG_ERR);
        let mut trap: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut trap), 0);
        assert_eq!(libc::sigaddset(&mut trap, libc::SIGTRAP), 0);
        assert_eq!(
            libc::sigprocmask(libc::SIG_UNBLOCK, &trap, std::ptr::null_mut()),
            0
        );
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut blocked), 0);
        assert_eq!(libc::sigaddset(&mut blocked, signal), 0);
        let mut expected: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut expected),
            0
        );
        assert_eq!(libc::sigaddset(&mut expected, signal), 0);
        let tid = libc::syscall(libc::SYS_gettid);
        assert!(tid > 0);
        assert_eq!(libc::syscall(libc::SYS_tgkill, tid, tid, signal), 0);
        let mut pending: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut pending), 0);
        assert_eq!(libc::sigismember(&pending, signal), 1);
        assert_eq!(SIGNAL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(libc::syscall(libc::SYS_getpid), 45);
        let mut current: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut current),
            0
        );
        assert_eq!(libc::sigismember(&current, signal), 1);
        for candidate in 1..=64 {
            let expected_member = libc::sigismember(&expected, candidate);
            let current_member = libc::sigismember(&current, candidate);
            assert!(matches!(expected_member, 0 | 1));
            assert!(matches!(current_member, 0 | 1));
            assert_eq!(
                current_member, expected_member,
                "held-signal preparation changed mask membership for signal {candidate}"
            );
        }
        assert_eq!(SIGNAL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(
            libc::sigprocmask(libc::SIG_UNBLOCK, &blocked, std::ptr::null_mut()),
            0
        );
        assert_eq!(SIGNAL_HITS.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn a_bound_private_request_survives_real_held_signal_preparation() {
    EVIDENCE.with(|value| *value.borrow_mut() = Arc::default());
    let (output, _) = crate::testing::run_tokio_test(async {
        let tracer = crate::tracer::spawn_fn_with_config::<HeldSignalTool, _>(
            guest_with_pending_signal,
            Mode::Request,
            true,
        )
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tracer.wait_with_output(),
        )
        .await
        .expect("held-signal bound request timed out")
    })
    .expect("held-signal preparation keeps the bound native request");
    assert!(output.status.success(), "{output:?}");
    let events = evidence().lock().unwrap().events.clone();
    let helper = events
        .iter()
        .filter(|event| event.call.number == Sysno::ppoll as u64)
        .collect::<Vec<_>>();
    assert_eq!(helper.len(), 2, "{events:?}");
    assert_eq!(helper[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(
        helper[1].event,
        NativeSyscallEvent::NativeResult(Err(Errno::ERESTARTNOHAND))
    );
    assert_eq!(helper[0].call.id, helper[1].call.id);
    assert!(
        helper
            .iter()
            .all(|event| !event.call.operation_bound && !event.operation)
    );
    let owned = events
        .iter()
        .filter(|event| event.operation)
        .collect::<Vec<_>>();
    // ppoll's step stop precedes delivery of the pending realtime signal.
    // It stops the first close before the instruction; inject_with_retry
    // then issues a second physical attempt after the signal is held.
    assert_eq!(owned.len(), 4, "{events:?}");
    assert_eq!(owned[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(owned[1].event, NativeSyscallEvent::ProvedNotRun);
    assert_eq!(owned[2].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(
        owned[3].event,
        NativeSyscallEvent::NativeResult(Err(Errno::EBADF))
    );
    assert_eq!(owned[0].call.id, owned[1].call.id);
    assert_eq!(owned[2].call.id, owned[3].call.id);
    assert_ne!(owned[0].call.id, owned[2].call.id);
    assert_ne!(owned[0].call.id, helper[0].call.id);
    assert_ne!(owned[2].call.id, helper[0].call.id);
    for event in owned {
        assert!(event.call.operation_bound);
        assert_eq!(event.call.purpose, NativeSyscallPurpose::Application);
        assert_eq!(event.call.number, Sysno::close as u64);
        assert_eq!(event.call.args, CLOSE_ARGS);
        assert_eq!(
            event.call.abi,
            NativeSyscallAbi::Linux {
                #[cfg(target_arch = "x86_64")]
                audit_arch: 0xc000_003e,
                #[cfg(target_arch = "aarch64")]
                audit_arch: 0xc000_00b7,
            }
        );
    }
    assert!(
        evidence()
            .lock()
            .unwrap()
            .completion
            .as_ref()
            .unwrap()
            .effects_complete()
    );
}
