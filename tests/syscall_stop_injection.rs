/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A Tool's injected `ppoll` that swaps in a temporary signal mask, run from
//! Reverie's private page (its arguments differ from the guest's) and
//! interrupted by a realtime signal the temporary mask lets through. The
//! injection runs between a syscall-entry and a syscall-exit stop, so the
//! Tool gets the call's own result, `-ERESTARTNOHAND`, and the signal stays
//! queued in the kernel: it reaches the Tool at its own signal-delivery stop
//! when the guest resumes, and the guest's handler runs once. A Tool that
//! reads the guest's registers around such an injection reads the same ones,
//! and a second injection in the same callback, which the still-pending
//! signal meets before its `svc`, is not restarted by the kernel as the
//! interrupted one, whatever its first argument.

#[cfg(all(not(sanitized), test))]
use std::sync::Mutex;
#[cfg(all(not(sanitized), test))]
use std::time::Duration;

#[cfg(all(not(sanitized), test))]
use reverie::Errno;
#[cfg(all(not(sanitized), test))]
use reverie::Error;
#[cfg(all(not(sanitized), test))]
use reverie::GlobalTool;
#[cfg(all(not(sanitized), test))]
use reverie::Guest;
#[cfg(all(not(sanitized), test))]
use reverie::Pid;
#[cfg(all(not(sanitized), test))]
use reverie::Tool;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Syscall;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallArgs;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallInfo;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Sysno;
#[cfg(all(not(sanitized), test))]
use serde::Deserialize;
#[cfg(all(not(sanitized), test))]
use serde::Serialize;

/// The realtime signal that interrupts the injection: SIGRTMIN+1, the one
/// glibc leaves to programs first.
#[cfg(all(not(sanitized), test))]
const INTERRUPTING: i32 = 35;

/// What the Tool saw, in order.
#[cfg(all(not(sanitized), test))]
#[derive(Default)]
struct Log {
    seen: Mutex<Vec<String>>,
}

#[cfg(all(not(sanitized), test))]
#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = String;
    type Response = ();
    type Config = Mode;

    async fn receive_rpc(&self, _from: Pid, seen: String) {
        self.seen.lock().unwrap().push(seen);
    }
}

/// What the Tool does with the guest's `ppoll`.
#[cfg(all(not(sanitized), test))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Mode {
    /// Injects it from the private page, interrupted by `INTERRUPTING`.
    #[default]
    Interrupt,
    /// Compares the guest's registers around an uninterrupted injection.
    CompareRegisters,
    /// As `Interrupt`, then, in the same callback, injects `close` with this
    /// first argument.
    SecondInjection(i64),
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Serialize, Deserialize)]
struct ThreadState {
    injected: bool,
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Clone)]
struct InterruptedInjection;

#[cfg(all(not(sanitized), test))]
#[reverie::tool]
impl Tool for InterruptedInjection {
    type GlobalState = Log;
    type ThreadState = ThreadState;

    /// The guest has one thread, so no guest code runs while Reverie stops
    /// it, and the backend keeps SIGTRAP's state across its own steps, which
    /// the syscall-stop transport needs.
    fn enforces_serialized_execution(_config: &Mode) -> bool {
        true
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() != Sysno::ppoll || guest.thread_state().injected {
            return guest.tail_inject(syscall).await;
        }
        guest.thread_state_mut().injected = true;
        let (nr, args) = syscall.into_parts();
        let mode = *guest.config();
        if mode == Mode::CompareRegisters {
            // An uninterrupted injection (the guest's timeout is zero): the
            // registers the Tool reads after it are the ones it read before,
            // but for the result.
            let before = guest.regs().await;
            let injected = guest
                .inject(Syscall::from_raw(
                    nr,
                    SyscallArgs::new(0, 0, args.arg2, args.arg3, args.arg4, args.arg5),
                ))
                .await;
            let after = guest.regs().await;
            guest.send_rpc(format!("injected {injected:?}")).await;
            guest
                .send_rpc(format!("changed {:?}", changed_registers(&before, &after)))
                .await;
            return injected.map_err(Into::into);
        }
        let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
        let sender = std::thread::spawn(move || {
            // Long enough for the injected call to block.
            std::thread::sleep(Duration::from_millis(200));
            // SAFETY: tgkill takes three integers and touches no memory.
            unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, INTERRUPTING) }
        });
        // No descriptors: the call differs from the guest's, so it runs from
        // the private page, under the guest's timeout and temporary mask.
        let injected = guest
            .inject(Syscall::from_raw(
                nr,
                SyscallArgs::new(0, 0, args.arg2, args.arg3, args.arg4, args.arg5),
            ))
            .await;
        assert_eq!(sender.join().unwrap(), 0, "tgkill from the tracer");
        guest.send_rpc(format!("injected {injected:?}")).await;
        if let Mode::SecondInjection(first_argument) = mode {
            // The interrupting signal is still pending, so it meets this
            // injection before its `svc`.
            let second = guest
                .inject(Syscall::from_raw(
                    Sysno::close,
                    SyscallArgs::new(first_argument as usize, 0, 0, 0, 0, 0),
                ))
                .await;
            guest.send_rpc(format!("second {second:?}")).await;
        }
        Err(Errno::EINTR.into())
    }

    async fn handle_raw_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: i32,
    ) -> Result<Option<i32>, Errno> {
        guest.send_rpc(format!("signal {signal}")).await;
        Ok(Some(signal))
    }
}

/// The registers other than the result and the instruction pointer that
/// differ between `before` and `after`, by name.
#[cfg(all(not(sanitized), test))]
fn changed_registers(before: &libc::user_regs_struct, after: &libc::user_regs_struct) -> Vec<String> {
    #[cfg(target_arch = "aarch64")]
    let pairs: Vec<(String, u64, u64)> = (1..31)
        .map(|n| (format!("x{n}"), before.regs[n], after.regs[n]))
        .chain([("sp".to_owned(), before.sp, after.sp)])
        .collect();
    #[cfg(target_arch = "x86_64")]
    let pairs: Vec<(String, u64, u64)> = [
        ("rbx", before.rbx, after.rbx),
        ("rcx", before.rcx, after.rcx),
        ("rdx", before.rdx, after.rdx),
        ("rsi", before.rsi, after.rsi),
        ("rdi", before.rdi, after.rdi),
        ("rbp", before.rbp, after.rbp),
        ("rsp", before.rsp, after.rsp),
        ("r8", before.r8, after.r8),
        ("r9", before.r9, after.r9),
        ("r10", before.r10, after.r10),
        ("r11", before.r11, after.r11),
        ("r12", before.r12, after.r12),
        ("r13", before.r13, after.r13),
        ("r14", before.r14, after.r14),
        ("r15", before.r15, after.r15),
    ]
    .into_iter()
    .map(|(name, b, a)| (name.to_owned(), b, a))
    .collect();
    pairs
        .into_iter()
        .filter(|(_, b, a)| b != a)
        .map(|(name, _, _)| name)
        .collect()
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use test_case::test_case;

    use super::*;

    static HANDLED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn on_signal(_: libc::c_int) {
        HANDLED.fetch_add(1, Ordering::SeqCst);
    }

    fn bit(signal: i32) -> u64 {
        1 << (signal - 1)
    }

    /// The thread's mask, read with a raw `rt_sigprocmask`, which shows the
    /// realtime signals glibc's own calls hide.
    fn thread_mask() -> u64 {
        let mut mask = 0u64;
        // SAFETY: rt_sigprocmask writes the 8-byte set.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                std::ptr::null::<u64>(),
                &mut mask as *mut u64,
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(ret, 0, "read the mask");
        mask
    }

    /// The guest: `INTERRUPTING` has a handler and is blocked, and a raw
    /// `ppoll` of one ignored descriptor waits 10 s under a temporary mask
    /// that lets it through.
    fn guest() {
        // SAFETY: the action is fully initialized; the handler increments
        // an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(INTERRUPTING, &action, std::ptr::null_mut()),
                0
            );
        }
        let block = bit(INTERRUPTING);
        // SAFETY: rt_sigprocmask reads the 8-byte set.
        let blocked = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                &block as *const u64,
                std::ptr::null_mut::<u64>(),
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(blocked, 0, "block the signal");
        let mut ignored = libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        let lets_it_through = 0u64;
        // SAFETY: ppoll reads one descriptor entry, the timeout and the mask.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut ignored as *mut libc::pollfd,
                1,
                &timeout as *const libc::timespec,
                &lets_it_through as *const u64,
                std::mem::size_of::<u64>(),
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((ret, errno), (-1, Some(libc::EINTR)), "the Tool's answer");
        assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
        assert_ne!(thread_mask() & block, 0, "the signal is blocked again");
    }

    #[test]
    fn an_interrupted_mask_swapping_injection_reports_its_result_and_leaves_the_signal_queued() {
        let (output, log) =
            reverie_ptrace::testing::test_fn::<InterruptedInjection, _>(guest).unwrap();
        assert!(
            output.status.success(),
            "the guest failed: {:?}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            *log.seen.lock().unwrap(),
            [
                format!("injected {:?}", Err::<i64, _>(Errno::ERESTARTNOHAND)),
                format!("signal {INTERRUPTING}"),
            ],
            "the injection's own result, then the signal at its own stop"
        );
    }

    /// A value the guest leaves in a register its `ppoll` does not use (x7
    /// on aarch64, which the kernel's syscall stops report as their
    /// direction).
    const MARKER: u64 = 0x5245_5645_5249_4537;

    /// The guest: a raw `ppoll` of one ignored descriptor with a zero
    /// timeout under a temporary mask, with `MARKER` in x7 on aarch64.
    fn guest_with_a_marker() {
        let mut ignored = libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mask = 0u64;
        #[cfg(target_arch = "aarch64")]
        let ret: i64 = {
            let ret;
            // SAFETY: ppoll reads one descriptor entry, the timeout and the
            // mask; x7 is not an argument.
            unsafe {
                std::arch::asm!(
                    "svc 0",
                    in("x8") libc::SYS_ppoll,
                    inlateout("x0") &mut ignored as *mut libc::pollfd => ret,
                    in("x1") 1usize,
                    in("x2") &zero as *const libc::timespec,
                    in("x3") &mask as *const u64,
                    in("x4") std::mem::size_of::<u64>(),
                    in("x7") MARKER,
                    options(nostack),
                );
            }
            ret
        };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: as above.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut ignored as *mut libc::pollfd,
                1,
                &zero as *const libc::timespec,
                &mask as *const u64,
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(ret, 0, "the Tool's answer, the injection's own");
    }

    #[test]
    fn a_tool_reads_the_same_registers_around_a_mask_swapping_injection() {
        let (output, log) = reverie_ptrace::testing::test_fn_with_config::<InterruptedInjection, _>(
            guest_with_a_marker,
            Mode::CompareRegisters,
            true,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "the guest failed: {:?}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            *log.seen.lock().unwrap(),
            ["injected Ok(0)", "changed []"],
            "the injection's result, and no register but the result changed"
        );
    }

    /// After the interrupted injection, the Tool injects `close` whose first
    /// argument reads as a restart code. The interrupting signal, still
    /// pending, meets the second injection before its `svc`, in a
    /// `do_signal` that must not take the interrupted call for the thread's
    /// syscall: it would rewind `pc` before the private page and put back
    /// the first injection's first argument. The second injection is
    /// reported as stopped before it ran, the signal is held for the
    /// guest's resume, and the guest's handler runs once.
    #[test_case(-512; "erestartsys")]
    #[test_case(-513; "erestartnointr")]
    #[test_case(-514; "erestartnohand")]
    #[test_case(-516; "erestart_restartblock")]
    fn a_second_injection_after_an_interrupted_one_is_not_restarted_by_the_kernel(
        first_argument: i64,
    ) {
        let (output, log) = reverie_ptrace::testing::test_fn_with_config::<InterruptedInjection, _>(
            guest,
            Mode::SecondInjection(first_argument),
            true,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "the guest failed: {:?}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let seen = log.seen.lock().unwrap();
        assert_eq!(
            seen[..2],
            [
                format!("injected {:?}", Err::<i64, _>(Errno::ERESTARTNOHAND)),
                format!("second {:?}", Err::<i64, _>(Errno::ERESTARTSYS)),
            ],
            "the interrupted injection's result, then the second's: {seen:?}"
        );
    }
}
