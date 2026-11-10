/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests, for the timer-boundary test hook.
mod timer_signal_deferral_tests {
    use std::process::Command;

    use reverie::Guest;
    use reverie::syscalls::SyscallInfo;

    use super::*;
    use crate::runtime::timer_signal_observation;

    /// The precise request: stepped from the request on, so its boundary is
    /// exactly the one right after this branch, which is the instruction
    /// under test.
    const TICKS: u64 = 100;

    /// The event the Tool logs for an RDTSC callback.
    const RDTSC: i32 = -1;

    /// The Tool's events: the signal (0 for the timer event, RDTSC for an
    /// RDTSC callback) and the clock.
    #[derive(Default)]
    struct DeferralLog(Mutex<Vec<(i32, u64)>>);

    #[reverie::global_tool]
    impl GlobalTool for DeferralLog {
        type Request = (i32, u64);
        type Response = ();
        /// Subscribe to RDTSC.
        type Config = bool;

        async fn receive_rpc(&self, _from: Pid, event: (i32, u64)) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[derive(Default)]
    struct DeferralTool;

    #[reverie::tool]
    impl Tool for DeferralTool {
        type GlobalState = DeferralLog;
        type ThreadState = ();

        fn subscriptions(rdtsc: &bool) -> reverie::Subscription {
            let mut subscription = reverie::Subscription::all_syscalls();
            if *rdtsc {
                subscription.rdtsc();
            }
            subscription
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: reverie::syscalls::Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            if syscall.number() == reverie::syscalls::Sysno::getppid {
                guest
                    .set_timer_precise(reverie::TimerSchedule::Rcbs(TICKS))
                    .unwrap();
            }
            guest.tail_inject(syscall).await
        }

        async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
            let clock = guest.read_clock().unwrap();
            guest.send_rpc((0, clock)).await;
        }

        async fn handle_rdtsc_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            request: reverie::Rdtsc,
        ) -> std::result::Result<reverie::RdtscResult, reverie::syscalls::Errno> {
            let clock = guest.read_clock().unwrap();
            guest.send_rpc((RDTSC, clock)).await;
            Ok(reverie::RdtscResult::new(request))
        }

        async fn handle_signal_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            signal: reverie::Signal,
        ) -> std::result::Result<Option<reverie::Signal>, reverie::syscalls::Errno> {
            let clock = guest.read_clock().unwrap();
            guest.send_rpc((signal as i32, clock)).await;
            Ok(Some(signal))
        }
    }

    /// The guest: SIGILL and SIGUSR1 handlers, the marker (getppid), where
    /// the request is made, TICKS branches, then `instruction` at the
    /// boundary. SIGILL's handler records whether SIGUSR1's handler ran before
    /// it, and steps past the ud2; SIGUSR1's records where it interrupted the
    /// guest. The guest writes its record: that flag, SIGUSR1's interrupted
    /// rip, how many times SIGUSR1's handler ran, and `expected`'s address.
    fn program(instruction: &str, expected: &str) -> String {
        format!(
            ".global _start\n.text\n_start:\n\
             lea {expected}(%rip),%rax\nmov %rax,record+24(%rip)\n\
             mov $4,%edi\nlea ill_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
             mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
             mov $110,%eax\nsyscall\nmov ${TICKS},%ecx\n1: dec %ecx\njnz 1b\n{instruction}\n\
             after: mov $1,%edi\nlea record(%rip),%rsi\nmov $32,%edx\nmov $1,%eax\nsyscall\n\
             xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n\
             ill: movzbq flag(%rip),%rax\nmov %rax,record(%rip)\naddq $2,168(%rdx)\nret\n\
             usr1: movb $1,flag(%rip)\nmov 168(%rdx),%rax\nmov %rax,record+8(%rip)\nincq record+16(%rip)\nret\n\
             restorer: mov $15,%eax\nsyscall\nud2\n\
             .data\n.balign 8\n\
             ill_action: .quad ill, 0x4000004, restorer, 0\n\
             usr1_action: .quad usr1, 0x4000004, restorer, 0\n\
             record: .quad 0,0,0,0\nflag: .byte 0\n"
        )
    }

    /// Runs the guest of [`program`] under [`DeferralTool`], with the hook
    /// that, at the first timer boundary, queues SIGUSR1 for the thread (a
    /// sibling's tgkill while the callback ran) and leaves `vector` (with
    /// `error_code`, if any) for KVM to inject (a host interrupt that ended
    /// the entry while the CPU delivered the instruction's exception).
    /// Returns the Tool's events and the guest's record.
    fn run(
        source: &str,
        rdtsc: bool,
        vector: u8,
        error_code: Option<u32>,
    ) -> (Vec<(i32, u64)>, Vec<u64>) {
        let directory = std::env::temp_dir().join(format!(
            "reverie-timer-signal-deferral-{}-{vector}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("guest.S");
        let executable = directory.join("guest");
        std::fs::write(&path, source).unwrap();
        let output = Command::new("/usr/bin/gcc")
            .args(["-nostdlib", "-static", "-Wl,--build-id=none"])
            .arg(&path)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(output.status.success(), "gcc failed: {output:?}");
        let image = std::fs::read(&executable).unwrap();
        let mut injected = false;
        let _scope = timer_signal_observation::Scope::new(Box::new(move |vcpu, executor| {
            if std::mem::replace(&mut injected, true) {
                return;
            }
            let tid = reverie::Pid::from_raw(executor.task_tid());
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
            let target = reverie::SignalTarget::Thread { pid: tid, tid };
            let event = reverie::SignalEvent::new(libc::SIGUSR1, info, target).unwrap();
            executor.defer_signal_delivery(event).unwrap();
            let mut events = vcpu.get_vcpu_events().unwrap();
            events.exception.injected = 1;
            events.exception.nr = vector;
            events.exception.has_error_code = u8::from(error_code.is_some());
            events.exception.error_code = error_code.unwrap_or(0);
            vcpu.set_vcpu_events(&events).unwrap();
        }));
        let mut backend = KvmBackend::new(16 * 1024 * 1024).expect("this test requires /dev/kvm");
        let program = executable.to_str().unwrap();
        backend
            .install_static_elf_with_context(&image, &[program], &[], &directory)
            .unwrap();
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<DeferralTool>(rdtsc, true));
        let _ = std::fs::remove_dir_all(&directory);
        let (log, status, stdout, stderr) = result.unwrap();
        let events = log.0.into_inner().unwrap();
        assert_eq!(
            (status, stdout.len()),
            (0, 32),
            "{events:?} {}",
            String::from_utf8_lossy(&stderr)
        );
        let record = stdout
            .chunks(8)
            .map(|quad| u64::from_ne_bytes(quad.try_into().unwrap()))
            .collect();
        (events, record)
    }

    /// A signal that a timer boundary deferred, because KVM still had a
    /// fault's exception (the ud2's #UD) to inject there, is delivered right
    /// after that fault's own signal, before the guest runs on: SIGILL's frame
    /// first, then SIGUSR1's on top of it, so that SIGUSR1's handler runs
    /// first and interrupts SIGILL's at its first instruction, as on Linux.
    /// Left behind SIGILL's handler, it would wait for the next syscall's
    /// return, and SIGILL's handler would run first.
    #[test]
    fn a_signal_deferred_by_a_pending_fault_follows_the_fault_signal() {
        let (events, record) = run(&program("ud2", "ill"), false, 6, None);
        let context = format!("{events:?} {record:x?}");
        let signals: Vec<i32> = events.iter().map(|(signal, _)| *signal).collect();
        assert_eq!(signals, [0, libc::SIGILL, libc::SIGUSR1], "{context}");
        assert!(events.iter().all(|(_, clock)| *clock == events[0].1), "{context}");
        assert_eq!(record[0], 1, "SIGILL's handler ran first: {context}");
        assert_eq!((record[1], record[2]), (record[3], 1), "{context}");
    }

    /// The same deferral when the exception is the #GP of an RDTSC the Tool
    /// intercepts: the signal is delivered right after the RDTSC callback,
    /// with the instruction after the RDTSC as its interrupted rip.
    #[test]
    fn a_signal_deferred_by_a_pending_rdtsc_follows_the_rdtsc_callback() {
        let (events, record) = run(&program("rdtsc", "after"), true, 13, Some(0));
        let context = format!("{events:?} {record:x?}");
        let signals: Vec<i32> = events.iter().map(|(signal, _)| *signal).collect();
        assert_eq!(signals, [0, RDTSC, libc::SIGUSR1], "{context}");
        assert!(events.iter().all(|(_, clock)| *clock == events[0].1), "{context}");
        assert_eq!((record[1], record[2]), (record[3], 1), "{context}");
    }
}
