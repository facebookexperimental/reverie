//! Narrow same-owner handover after an actual initializer terminal observation.
//! No numeric constructor, returned observation or ready word authorizes entry.

use super::*;
use crate::launcher::exec_stop::trace;

const NATIVE_BYTES: [u8; 9] = [0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x05, 0x41, 0xff, 0xe4];

impl PreparedMapping<'_> {
    /// Restore registrations/context, detach once and await the original child.
    /// This borrows the complete outer owner; cancellation retains every stop,
    /// returned event and wait driver in it. It does not create a Ready value.
    ///
    /// # Safety
    /// The caller must independently establish genuine successful shared Detcore
    /// initialization, installed frontend/lifecycle/dispatcher, retired input,
    /// source-bound fixed native gate/observer, and the SAME runtime's actual
    /// Guest phase3 and callback phase4 routing. This is NOT supplied by the
    /// observer's scalar checks or any static observation receipt. In particular
    /// the current runtime needs the separately reviewed phase4 routing change
    /// before using this path. No alternate runtime/unknown control ABI is allowed.
    ///
    /// The original synchronous ptracer root retains this mapping, source,
    /// inherited FD/backing leases, admission/watch and DETLOG outside ALL
    /// futures. It polls this method and the EXISTING RPC/services concurrently
    /// on the original OS thread. No new RPC server or waiter is created here.
    /// Unexpected signals/events, timeout, error, panic or future drop require
    /// confirmed original-owner retirement before releasing any resources. A
    /// dropped handover cannot be restarted. No general clone/exec is supported.
    /// The host CPU XSAVE component layout/XCR0 must match the retained capture
    /// and remain stable (compatible pinned/homogeneous CPU domain) through the
    /// existing read-only PKRU projection used here.
    /// The caller must qualify initializer writes to guest stack/AT_RANDOM; this
    /// path preserves them, rather than restoring a historical stack snapshot.
    pub async unsafe fn handover_and_wait(&mut self, deadline: Instant) -> Result<ExitStatus> {
        // SAFETY: this finite wrapper has the same complete caller contract.
        unsafe {
            self.handover_and_wait_with_live_deadline(deadline, Some(deadline))
                .await
        }
    }

    /// Restore and detach under a finite operation bound, then await this Guest.
    /// `None` removes only the detached Guest execution deadline. Restoration,
    /// native gate calls and detach still use `operation_deadline` unchanged.
    /// Cancellation retains the same wait driver; it never acknowledges reap.
    ///
    /// # Safety
    /// The complete contract of [`Self::handover_and_wait`] applies. The caller
    /// keeps the original owner and services alive through unbounded execution
    /// and performs original-owner retirement on error, panic or future drop.
    pub async unsafe fn handover_and_wait_with_live_deadline(
        &mut self,
        operation_deadline: Instant,
        live_deadline: Option<Instant>,
    ) -> Result<ExitStatus> {
        let result = self.handover_inner(operation_deadline, live_deadline).await;
        if result.is_err() {
            self.entry.failed = true;
        }
        result
    }

    async fn handover_inner(
        &mut self,
        operation_deadline: Instant,
        live_deadline: Option<Instant>,
    ) -> Result<ExitStatus> {
        self.restore_guest_for_release(operation_deadline).await?;
        self.detach_restored_guest(operation_deadline, live_deadline)
            .await
    }

    // Shared real restoration only. The observational successor retains the
    // exact stopped task here instead of detaching it. No await owner moves.
    pub(super) async fn restore_guest_for_release(&mut self, deadline: Instant) -> Result<()> {
        self.entry_thread()?;
        let (terminal_ip, reserved) = self
            .entry
            .initialized_stop
            .ok_or("mapped_handover_no_initializer_observation")?;
        if self.entry.failed
            || self.entry.handover_started
            || self.entry.wait.is_some()
            || self.entry.terminal.is_some()
            || Instant::now() >= deadline
        {
            return Err("mapped_handover_spent_or_failed".into());
        }
        // Latch before the first physical change and before any await.
        self.entry.handover_started = true;
        let view = View::parse(self._inputs.handoff_bytes, self._inputs.handoff_address)
            .map_err(|e| format!("mapped_handover_wire: {e:?}"))?;
        let task = self.task.as_ref().ok_or("mapped_handover_missing_stop")?;
        self.check_entry_generation(task)?;
        if !matches!(self.entry.event, Some(Event::Signal(Signal::SIGTRAP)))
            || !terminal(&task.getsiginfo_bytes()?, task.getregs()?.rip, terminal_ip)
        {
            return Err("mapped_handover_not_initializer_trap".into());
        }
        self.verify_tool_init_stop(task, view, &task.getregs()?, reserved, 1)?;
        let control = view
            .scalar(1)
            .map_err(|e| format!("mapped_handover_control: {e:?}"))?;
        let prefix = read_control(task, view)?;
        let guest_mask = control_word(&prefix, 44);
        // SAFETY: outer method requires this exact retained capture and stable
        // matching host XSAVE layout. No replacement state is manufactured.
        let guest_pkru = unsafe { self.context.xstate().pkru()? } as u64;
        if view
            .scalar(6)
            .map_err(|e| format!("mapped_handover_pkru: {e:?}"))?
            != guest_pkru
            || control_word(&prefix, 45) != guest_pkru
        {
            return Err("mapped_handover_pkru_snapshot".into());
        }
        if !restoration_facts(&prefix, self.context.signal_mask(), reserved) {
            return Err("mapped_handover_registration_snapshot".into());
        }
        let mut tsc_bytes = [0; 16];
        exact(
            task,
            control
                .checked_add(3456)
                .ok_or("mapped_handover_overflow")?,
            &mut tsc_bytes,
        )?;
        let captured_tsc = u64::from_ne_bytes(tsc_bytes[..8].try_into().unwrap());
        let guest_tsc = u64::from_ne_bytes(tsc_bytes[8..].try_into().unwrap());
        if !matches!(captured_tsc, 1 | 2) || !matches!(guest_tsc, 1 | 2) {
            return Err("mapped_handover_tsc_snapshot".into());
        }
        // Descriptor and gate were bound to immutable mapped source bytes by
        // preparation and the unsafe entry contract; re-read the actual bytes.
        let mut descriptor = [0; 96];
        exact(task, self._inputs.layout_address, &mut descriptor)?;
        let layout = super::super::decode_target_layout(&descriptor)?;
        super::super::target_recipe(layout.gate)?;
        let native = layout
            .gate
            .checked_add(0x7c)
            .ok_or("mapped_handover_overflow")?;
        let mut gate = [0; 9];
        exact(task, native, &mut gate)?;
        if gate != NATIVE_BYTES || !in_code(view, terminal_ip)? {
            return Err("mapped_handover_gate_or_terminal".into());
        }
        let mut trap_byte = [0];
        exact(task, terminal_ip, &mut trap_byte)?;
        if trap_byte != [0xcc] {
            return Err("mapped_handover_terminal_byte".into());
        }
        // Existing disjoint State filter staging is no longer consumed by the
        // kernel after installation. It is outside NativeControl/RelayStorage.
        // The preparation contract owns the complete original staging extent.
        let scratch = self._inputs.filter_scratch;
        scratch
            .checked_add(16)
            .ok_or("mapped_handover_scratch_overflow")?;
        let mut saved_scratch = [0; 16];
        exact(task, scratch, &mut saved_scratch)?;
        let tid = control_word(&prefix, 15);
        let head = control_word(&prefix, 11);
        let len = control_word(&prefix, 12);
        let calls = [
            (libc::SYS_set_tid_address, [0, 0, 0, 0, 0, 0], tid),
            (libc::SYS_set_robust_list, [head, len, 0, 0, 0, 0], 0),
            (
                libc::SYS_get_robust_list,
                [0, scratch, scratch + 8, 0, 0, 0],
                0,
            ),
            (libc::SYS_gettid, [0; 6], tid),
            (libc::SYS_brk, [0; 6], control_word(&prefix, 14)),
        ];
        for (nr, args, expected) in calls {
            let actual = self
                .handover_gate(nr as u64, args, native, terminal_ip, reserved, deadline)
                .await?;
            if actual != expected {
                return Err(format!("mapped_handover_kernel_return nr={nr} actual={actual:#x} expected={expected:#x}").into());
            }
            if nr == libc::SYS_get_robust_list {
                let mut actual = [0; 16];
                exact(
                    self.task.as_ref().ok_or("mapped_handover_missing_stop")?,
                    scratch,
                    &mut actual,
                )?;
                if u64::from_ne_bytes(actual[..8].try_into().unwrap()) != head
                    || u64::from_ne_bytes(actual[8..].try_into().unwrap()) != len
                {
                    return Err("mapped_handover_robust_readback".into());
                }
            }
        }
        // Match private_restore_kernel_state: TSC is the last policy change.
        // No Tool Rust instruction runs after it, only the raw gate + INT3.
        for (option, argument) in [(libc::PR_SET_TSC, guest_tsc), (libc::PR_GET_TSC, scratch)] {
            if self
                .handover_gate(
                    libc::SYS_prctl as u64,
                    [option as u64, argument, 0, 0, 0, 0],
                    native,
                    terminal_ip,
                    reserved,
                    deadline,
                )
                .await?
                != 0
            {
                return Err("mapped_handover_tsc_return".into());
            }
        }
        let task = self.task.as_mut().ok_or("mapped_handover_missing_stop")?;
        let mut actual_tsc = [0; 4];
        exact(task, scratch, &mut actual_tsc)?;
        if u32::from_ne_bytes(actual_tsc) as u64 != guest_tsc {
            return Err("mapped_handover_tsc_readback".into());
        }
        trace::write(task, scratch, &saved_scratch)?;
        let mut restored_scratch = [0; 16];
        exact(task, scratch, &mut restored_scratch)?;
        if restored_scratch != saved_scratch {
            return Err("mapped_handover_scratch_readback".into());
        }
        // Actual success-only registration ledger, then captured|restored=3.
        // No ready/input value is written by the host.
        for (index, value) in [(37_u64, 0_u64), (38, head), (39, len), (46, 3), (2, 3)] {
            let address = control
                .checked_add(index * 8)
                .ok_or("mapped_handover_overflow")?;
            trace::write(task, address, &value.to_ne_bytes())?;
            let mut actual = [0; 8];
            exact(task, address, &mut actual)?;
            if actual != value.to_ne_bytes() {
                return Err("mapped_handover_control_publication".into());
            }
        }
        self.context.restore_after_initializer(task, guest_mask)?;
        self.entry_thread()?;
        Ok(())
    }

    async fn detach_restored_guest(
        &mut self,
        deadline: Instant,
        live_deadline: Option<Instant>,
    ) -> Result<ExitStatus> {
        self.entry_thread()?;
        if Instant::now() >= deadline {
            return Err("mapped_handover_deadline_before_detach".into());
        }
        let task = self.task.take().ok_or("mapped_handover_missing_stop")?;
        match task.detach_retaining(None) {
            Ok(running) => {
                // Driver stored synchronously BEFORE any cancellable await.
                self.entry.wait = Some(running.wait_owned_on_ptracer_thread().into_driver());
                self.entry.event = None;
            }
            Err((task, error)) => {
                self.task = Some(task);
                return Err(error.into());
            }
        }
        self.handover_wait_next_with_deadline(live_deadline).await?;
        match self.entry.terminal {
            Some(status) => {
                self.owner.record_detached_terminal(status);
                Ok(status)
            }
            None => Err("mapped_handover_unexpected_post_detach_stop_retained".into()),
        }
    }

    // Private closed call set at the call sites above; no public remote syscall
    // API or injected Guest-PC instructions. Unexpected SIGSYS is NOT delivered.
    async fn handover_gate(
        &mut self,
        nr: u64,
        args: [u64; 6],
        native: u64,
        terminal_ip: u64,
        reserved: u64,
        deadline: Instant,
    ) -> Result<u64> {
        self.entry_thread()?;
        let task = self.task.as_ref().ok_or("mapped_handover_missing_stop")?;
        self.check_entry_generation(task)?;
        let mut regs = task.getregs()?;
        let saved_rsp = regs.rsp;
        let saved_fs = regs.fs_base;
        let saved_gs = regs.gs_base;
        let saved_xstate = task.getxstate()?;
        let mask = task.getsigmask()?;
        if !tool_init_terminal_mask(mask, reserved) {
            return Err("mapped_handover_gate_mask".into());
        }
        regs.rip = native;
        regs.r12 = terminal_ip;
        regs.rax = nr;
        regs.orig_rax = u64::MAX;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        task.setregs(&regs)?;
        if super::super::super::register_words(&task.getregs()?)
            != super::super::super::register_words(&regs)
        {
            return Err("mapped_handover_gate_launch_readback".into());
        }
        self.resume_entry(None, deadline)?;
        self.handover_wait_next(deadline).await?;
        let task = self.task.as_ref().ok_or("mapped_handover_gate_exited")?;
        self.check_entry_generation(task)?;
        let result = task.getregs()?;
        if !matches!(self.entry.event, Some(Event::Signal(Signal::SIGTRAP)))
            || !terminal(&task.getsiginfo_bytes()?, result.rip, terminal_ip)
            || result.rsp != saved_rsp
            || result.fs_base != saved_fs
            || result.gs_base != saved_gs
            || task.getsigmask()? != mask
            || task.getxstate()? != saved_xstate
        {
            return Err("mapped_handover_gate_return_state".into());
        }
        Ok(result.rax)
    }

    pub(super) async fn handover_wait_next(&mut self, deadline: Instant) -> Result<()> {
        self.handover_wait_next_with_deadline(Some(deadline)).await
    }

    async fn handover_wait_next_with_deadline(&mut self, deadline: Option<Instant>) -> Result<()> {
        let waited = wait_retained_driver(
            &mut self.entry.wait,
            deadline,
            "mapped_handover_wait_deadline",
        )
        .await?;
        match waited {
            Wait::Stopped(task, event) => {
                self.task = Some(task);
                self.entry.event = Some(event); // retain NewChild before refusal
                self.entry.wait = None;
            }
            Wait::Exited(pid, status) => {
                self.entry.terminal = Some(status);
                self.entry.wait = None;
                if pid != self.owner.generation.pid() {
                    return Err("mapped_handover_foreign_terminal".into());
                }
            }
        }
        self.entry_thread()?;
        Ok(())
    }
}

// Only borrows the original driver. No event/generation is recaptured and a
// timeout, wait error or dropped future leaves that driver in its caller.
// Once Ready, the caller stores the actual returned task/event synchronously.
pub(super) async fn wait_retained_driver(
    driver: &mut Option<PtracerWaitDriver>,
    deadline: Option<Instant>,
    timeout_error: &'static str,
) -> Result<Wait> {
    let wait = poll_fn(|cx| match driver.as_mut() {
        Some(driver) => driver.poll_on_ptracer_thread(cx),
        None => std::task::Poll::Ready(Err(safeptrace::OwnedWaitError::Completed)),
    });
    Ok(match deadline {
        Some(deadline) => tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), wait)
            .await
            .map_err(|_| timeout_error)??,
        None => wait.await?,
    })
}

fn restoration_facts(control: &[u8; 384], original_mask: u64, reserved: u64) -> bool {
    qualified_reserved_set(reserved)
        && control_word(control, 10) == original_mask
        && control_word(control, 44) == (original_mask & !reserved)
        // Exact source capture accepted only pristine first-exec registrations.
        && control_word(control, 11) == 0
        && control_word(control, 12) == 24
        && control_word(control, 13) == 0
        && control_word(control, 40) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    fn facts() -> ([u8; 384], u64, u64) {
        let mut bytes = [0; 384];
        let mask = 1_u64 << (libc::SIGUSR1 - 1);
        let reserved = 1_u64 << (libc::SIGSYS - 1);
        for (i, value) in [(10, mask), (12, 24), (44, mask & !reserved)] {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_ne_bytes());
        }
        (bytes, mask, reserved)
    }
    #[test]
    fn resume_mask_is_exact_selected_mask_not_tool_delivery_mask() {
        let (mut c, mask, reserved) = facts();
        assert!(restoration_facts(&c, mask, reserved));
        c[44 * 8..45 * 8].copy_from_slice(&RUNTIME_BOOTSTRAP_MASK.to_ne_bytes());
        assert!(!restoration_facts(&c, mask, reserved));
    }
    #[test]
    fn pristine_registration_and_failure_fields_are_required() {
        let (c, mask, reserved) = facts();
        for (i, value) in [(11, 1_u64), (12, 0), (13, 1), (40, 1)] {
            let mut changed = c;
            changed[i * 8..i * 8 + 8].copy_from_slice(&value.to_ne_bytes());
            assert!(!restoration_facts(&changed, mask, reserved), "field {i}");
        }
        assert!(!restoration_facts(&c, mask, 0));
    }
    // A real direct child held by its stdin pipe, with exactly one retained
    // safeptrace driver. std::process never waits after that driver is created.
    // These controls exercise the shared poll mechanism, not recovery/restart
    // of a failed PreparedMapping: its public finite API still latches failure.
    struct HeldChild {
        stdin: Option<std::process::ChildStdin>,
        cleanup: safeptrace::PtracerTerminalCleanup,
        retired: bool,
    }

    impl HeldChild {
        fn spawn() -> (Self, Option<PtracerWaitDriver>) {
            use std::process::Command;
            use std::process::Stdio;
            let mut child = Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn held wait fixture");
            let running = match safeptrace::Running::new_on_ptracer_thread(
                safeptrace::Pid::from_raw(child.id() as i32),
            ) {
                Ok(running) => running,
                Err(error) => {
                    // No original driver exists yet; the spawning owner still
                    // owns this setup-failure cleanup.
                    drop(child.stdin.take());
                    let signal = child.kill();
                    let deadline = Instant::now() + std::time::Duration::from_secs(2);
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) => break,
                            Ok(None) if Instant::now() < deadline => {
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                            result => panic!(
                                "capture held fixture: {error}; setup cleanup: {signal:?}, {result:?}"
                            ),
                        }
                    }
                    panic!("capture held fixture: {error}");
                }
            };
            let held = Self {
                stdin: child.stdin.take(),
                cleanup: running.terminal_cleanup_on_ptracer_thread(),
                retired: false,
            };
            let driver = Some(running.wait_owned_on_ptracer_thread().into_driver());
            drop(child);
            (held, driver)
        }

        fn confirm_reap(&mut self) {
            assert!(
                self.cleanup
                    .wait(std::time::Duration::from_secs(2))
                    .unwrap(),
                "original cleanup did not confirm retirement"
            );
            self.retired = true;
        }
    }

    impl Drop for HeldChild {
        fn drop(&mut self) {
            if !self.retired {
                // Descriptor-directed cancellation and original-owner progress;
                // no numeric recapture or second std::process wait/reaper.
                let signal = self.cleanup.shared().request_sigkill();
                let reaped = self.cleanup.wait(std::time::Duration::from_secs(2));
                if std::thread::panicking() {
                    if reaped != Ok(true) {
                        eprintln!(
                            "held fixture cleanup failed: signal={signal:?}, reap={reaped:?}"
                        );
                    }
                } else {
                    assert!(signal.is_ok() || signal == Err(syscalls::Errno::ESRCH));
                    assert_eq!(reaped, Ok(true), "fixture cleanup did not retire");
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finite_wait_expires_but_live_wait_retains_same_driver_past_that_deadline() {
        use std::time::Duration;
        let (mut held, mut driver) = HeldChild::spawn();
        let generation = driver.as_ref().unwrap().generation().unwrap();
        let deadline = Instant::now() + Duration::from_millis(20);
        let error =
            wait_retained_driver(&mut driver, Some(deadline), "mapped_handover_wait_deadline")
                .await
                .unwrap_err();
        assert_eq!(error.to_string(), "mapped_handover_wait_deadline");
        assert_eq!(
            driver.as_ref().unwrap().generation(),
            Some(generation.clone())
        );
        assert!(Instant::now() >= deadline);
        {
            let live = wait_retained_driver(&mut driver, None, "unused_live_deadline");
            tokio::pin!(live);
            tokio::select! {
                result = &mut live => panic!("held live child returned early: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        } // Cancel only the borrowed future, keeping its exact original driver.
        assert_eq!(
            driver.as_ref().unwrap().generation(),
            Some(generation.clone())
        );
        drop(held.stdin.take());
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            wait_retained_driver(&mut driver, None, "unused_live_deadline"),
        )
        .await
        .expect("outer fixture bound")
        .unwrap();
        let (pid, status) = event.assume_exited();
        assert_eq!(pid, generation.pid());
        assert_eq!(status, ExitStatus::SUCCESS);
        held.confirm_reap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_live_wait_keeps_original_kill_reap_and_terminal_status() {
        use std::time::Duration;
        let (mut held, mut driver) = HeldChild::spawn();
        let generation = driver.as_ref().unwrap().generation().unwrap();
        {
            let live = wait_retained_driver(&mut driver, None, "unused_live_deadline");
            tokio::pin!(live);
            tokio::select! {
                result = &mut live => panic!("held live child returned early: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        assert_eq!(
            driver.as_ref().unwrap().generation(),
            Some(generation.clone())
        );
        held.cleanup.shared().request_sigkill().unwrap();
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            wait_retained_driver(&mut driver, None, "unused_live_deadline"),
        )
        .await
        .expect("outer fixture bound")
        .unwrap();
        let (pid, status) = event.assume_exited();
        assert_eq!(pid, generation.pid());
        assert_eq!(status, ExitStatus::Signaled(Signal::SIGKILL, false));
        held.confirm_reap();
    }
}
