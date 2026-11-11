/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Signal syscalls and per-task signal delivery state (gVisor: pkg/sentry/syscalls/linux/sys_signal.go, pkg/sentry/kernel/task_signals.go).

use super::*;

#[cfg(test)]
std::thread_local! {
    /// Runs in `prepare_captured_trap` on this thread between its two changes,
    /// the signal unblocked and its action not yet reset.
    pub(super) static CAPTURED_TRAP_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

impl ElfExecutor {
    // TODO-HUMAN-REVIEW(PR-132): Review cooperative KVM thread context updates.
    /// Queues a backend-neutral event selected for this exact guest task.
    pub fn defer_signal_delivery(
        &mut self,
        event: reverie::SignalEvent,
    ) -> Result<(), reverie::syscalls::Errno> {
        self.validate_deferred_signal_event(event, false)?;
        // A Process target records provenance, while this API is called on the
        // concrete thread already selected by the scheduler. Keep it in that
        // thread's queue; direct guest kill(2) separately uses shared pending.
        queue_signal_event(&mut self.state, event, false)
            .map_err(|raw| reverie::syscalls::Errno::new(i32::try_from(-raw).unwrap_or(libc::EIO)))
    }

    /// `delivery_hook`: the event is the one a Tool's signal hook returned
    /// for a delivery boundary (`prepare_filtered_signal_delivery`), rather
    /// than one a Tool asks to queue (`defer_signal_delivery`).
    fn validate_deferred_signal_event(
        &self,
        event: reverie::SignalEvent,
        delivery_hook: bool,
    ) -> Result<(), reverie::syscalls::Errno> {
        let signal = event.signal();
        let info = event.siginfo();
        let code = i32::from_ne_bytes(info[8..12].try_into().expect("siginfo code"));
        let supported_provenance = match (code, event.target()) {
            (libc::SI_USER, reverie::SignalTarget::Process { .. })
            | (libc::SI_TKILL, reverie::SignalTarget::Thread { .. })
            | (libc::SI_TIMER, reverie::SignalTarget::Process { .. }) => true,
            (libc::SI_KERNEL, reverie::SignalTarget::Process { .. }) => signal == libc::SIGALRM,
            // The SIGPIPE a failed pipe or socket write raises in its writer
            // (`raise_guest_sigpipe`).
            (libc::SI_USER, reverie::SignalTarget::Thread { .. }) => signal == libc::SIGPIPE,
            // A caller-supplied rt_sigqueueinfo/rt_tgsigqueueinfo record
            // (Linux's SIL_RT layout, e.g. SI_QUEUE), which `sigqueueinfo`
            // checked against Linux's rules when the guest queued it.
            (code, _) if code < 0 && !matches!(code, libc::SI_TKILL | libc::SI_TIMER) => true,
            _ => false,
        };
        // A process-directed SIGKILL a Tool published with `SI_USER` (a
        // parent-death signal, `publish_parent_death_signal`) reaches the
        // delivery hook as itself, and is delivered by its default action,
        // which no handler, mask or ignored disposition changes on Linux. A
        // Tool still cannot queue a SIGKILL itself (`defer_signal_delivery`).
        let published_sigkill = delivery_hook
            && signal == libc::SIGKILL
            && code == libc::SI_USER
            && matches!(event.target(), reverie::SignalTarget::Process { .. });
        if signal > 31
            || (matches!(signal, libc::SIGKILL | libc::SIGSTOP | libc::SIGCHLD)
                && !published_sigkill)
            || !supported_provenance
        {
            return Err(reverie::syscalls::Errno::ENOSYS);
        }
        match event.target() {
            reverie::SignalTarget::Process { pid } => {
                if pid.as_raw() != self.state.pid {
                    return Err(reverie::syscalls::Errno::ESRCH);
                }
            }
            reverie::SignalTarget::Thread { pid, tid } => {
                if pid.as_raw() != self.state.pid {
                    return Err(reverie::syscalls::Errno::ESRCH);
                }
                if tid.as_raw() != self.state.tid {
                    let sibling = self
                        .state
                        .task_lifecycle
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(tid.as_raw())
                        .is_some_and(|task| task.tgid == self.state.pid);
                    return Err(if sibling {
                        reverie::syscalls::Errno::ENOSYS
                    } else {
                        reverie::syscalls::Errno::ESRCH
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_child_exit_signal_event(
        &self,
        event: reverie::SignalEvent,
    ) -> Result<(), (reverie::ChildExitSignalErrorKind, reverie::syscalls::Errno)> {
        use reverie::ChildExitSignalErrorKind::Invalid;
        use reverie::ChildExitSignalErrorKind::Unsupported;
        use reverie::syscalls::Errno;

        let info = event.siginfo();
        let code = i32::from_ne_bytes(info[8..12].try_into().expect("siginfo code"));
        if event.signal() != libc::SIGCHLD
            || !matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
        {
            return Err((Unsupported, Errno::ENOSYS));
        }
        let reverie::SignalTarget::Process { pid } = event.target() else {
            return Err((Unsupported, Errno::ENOSYS));
        };
        if pid.as_raw() <= 0 || pid.as_raw() != self.state.pid {
            return Err((Invalid, Errno::ESRCH));
        }
        let errno = i32::from_ne_bytes(info[4..8].try_into().expect("siginfo errno"));
        let child = i32::from_ne_bytes(info[16..20].try_into().expect("siginfo child pid"));
        let status = i32::from_ne_bytes(info[24..28].try_into().expect("siginfo child status"));
        let user_time = i64::from_ne_bytes(info[32..40].try_into().expect("siginfo child utime"));
        let system_time = i64::from_ne_bytes(info[40..48].try_into().expect("siginfo child stime"));
        // Linux stores an unsigned exit byte for CLD_EXITED and the raw signal
        // number for CLD_KILLED/CLD_DUMPED. Keep those domains distinct: a
        // status that is coherent for one class must not validate another.
        let valid_status = match code {
            libc::CLD_EXITED => (0..=i32::from(u8::MAX)).contains(&status),
            libc::CLD_KILLED => {
                (1..=64).contains(&status)
                    && default_signal_disposition(status) == SignalDisposition::Terminate
            }
            libc::CLD_DUMPED => crate::core_dump::default_action_dumps_core(status),
            _ => false,
        };
        if errno != 0 || child <= 0 || !valid_status || user_time < 0 || system_time < 0 {
            return Err((Invalid, Errno::EINVAL));
        }
        Ok(())
    }

    /// Publishes a Tool-selected terminal child event into its process's pending
    /// set. The Tool owns child identity/status provenance; the backend owns
    /// receiver validation, coalescing, and the later delivery boundary.
    pub fn queue_child_exit_signal(
        &mut self,
        event: reverie::SignalEvent,
    ) -> reverie::ChildExitSignalOutcome {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        use reverie::ChildExitSignalDisposition::Ignored;
        use reverie::ChildExitSignalDisposition::PendingBlocked;
        use reverie::ChildExitSignalDisposition::PendingEligible;
        use reverie::ChildExitSignalErrorKind::Backend;
        use reverie::ChildExitSignalErrorKind::Invalid;
        use reverie::ChildExitSignalErrorKind::Unsupported;
        use reverie::ChildExitSignalOutcome::Accepted;
        use reverie::ChildExitSignalOutcome::FailedAfterCommit;
        use reverie::ChildExitSignalOutcome::RejectedBeforeCommit;
        use reverie::syscalls::Errno;

        if self.signal_controlled() {
            return RejectedBeforeCommit {
                kind: Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        if let Err((kind, errno)) = self.validate_child_exit_signal_event(event) {
            return RejectedBeforeCommit { kind, errno };
        }
        if self.has_pending_exit() {
            return RejectedBeforeCommit {
                kind: Invalid,
                errno: Errno::ESRCH,
            };
        }
        let (disposition, pending_generation, coalesced, matching_fds) = {
            // Keep lifecycle -> process signal -> thread signal lock order.
            // No task retirement or sibling registration may cross publication.
            let lifecycle = self
                .state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !lifecycle.get(self.state.tid).is_some_and(|task| {
                task.generation == self.task_generation && task.tgid == self.state.pid
            }) {
                return RejectedBeforeCommit {
                    kind: Invalid,
                    errno: Errno::ESRCH,
                };
            }
            if !self.is_thread_group_leader()
                || lifecycle.has_live_sibling(self.state.tid, self.state.pid)
                || matches!(&self.process_action, Some(ProcessAction::Thread { .. }))
            {
                return RejectedBeforeCommit {
                    kind: Unsupported,
                    errno: Errno::ENOSYS,
                };
            }
            let mut process = self
                .state
                .process_signals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let generation = process.pending_generation(libc::SIGCHLD);
            if process
                .dispositions
                .get(&libc::SIGCHLD)
                .is_some_and(|action| action.is_ignored())
            {
                // Linux do_notify_parent suppresses explicit SIG_IGN even
                // when blocked. SIG_DFL and SA_NOCLDWAIT do not do so.
                return Accepted {
                    disposition: Ignored,
                    pending_generation: generation,
                    coalesced: false,
                };
            }
            let blocked = self
                .state
                .thread_signals
                .lock()
                .blocked
                .contains(libc::SIGCHLD);
            let matching_fds = process
                .signalfd_masks
                .iter()
                .filter_map(|(&fd, mask)| mask.contains(libc::SIGCHLD).then_some(fd))
                .collect::<Vec<_>>();
            if matching_fds
                .iter()
                .any(|fd| !self.state.files.contains_key(fd))
            {
                return RejectedBeforeCommit {
                    kind: Backend,
                    errno: Errno::EBADF,
                };
            }
            let inserted = match process.shared_pending.enqueue(event, generation) {
                Ok(inserted) => inserted,
                Err(errno) => {
                    return RejectedBeforeCommit {
                        kind: Backend,
                        errno,
                    };
                }
            };
            (
                if blocked {
                    PendingBlocked
                } else {
                    PendingEligible
                },
                generation,
                !inserted,
                matching_fds,
            )
        };
        // The pending operation has committed. Keep all state locks released
        // over bounded eventfd I/O and preserve this distinction on failure.
        for fd in matching_fds {
            let file = self
                .state
                .files
                .get(&fd)
                .expect("preflighted signalfd disappeared");
            if let Err(error) = set_signalfd_ready(file, true) {
                return FailedAfterCommit {
                    errno: Errno::new(i32::try_from(-error).unwrap_or(libc::EIO)),
                    pending_generation,
                };
            }
        }
        Accepted {
            disposition,
            pending_generation,
            coalesced,
        }
    }

    /// Publishes only the normal Linux ITIMER_REAL process-alarm payload.
    /// The runtime adapter separately owns the transported boundary witness.
    pub fn queue_process_alarm_signal(
        &mut self,
        event: reverie::SignalEvent,
    ) -> reverie::ProcessAlarmSignalOutcome {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        use reverie::ProcessAlarmSignalDisposition;
        use reverie::ProcessAlarmSignalErrorKind::Backend;
        use reverie::ProcessAlarmSignalErrorKind::Invalid;
        use reverie::ProcessAlarmSignalErrorKind::Unsupported;
        use reverie::ProcessAlarmSignalOutcome::Accepted;
        use reverie::ProcessAlarmSignalOutcome::FailedAfterCommit;
        use reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit;
        use reverie::ProcessAlarmSignalReceipt;
        use reverie::syscalls::Errno;

        let info = event.siginfo();
        let code = i32::from_ne_bytes(info[8..12].try_into().expect("siginfo code"));
        if event.signal() != libc::SIGALRM || code != libc::SI_KERNEL {
            return RejectedBeforeCommit {
                kind: Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        let reverie::SignalTarget::Process { pid } = event.target() else {
            return RejectedBeforeCommit {
                kind: Unsupported,
                errno: Errno::ENOSYS,
            };
        };
        if pid.as_raw() <= 0 || pid.as_raw() != self.state.pid {
            return RejectedBeforeCommit {
                kind: Invalid,
                errno: Errno::ESRCH,
            };
        }
        // SEND_SIG_PRIV clears the complete siginfo before setting these two
        // fields. Reject nonzero errno, pid/uid, padding and expansion bytes.
        let mut expected = [0; reverie::SIGNAL_INFO_SIZE];
        expected[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
        expected[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
        if info != expected {
            return RejectedBeforeCommit {
                kind: Invalid,
                errno: Errno::EINVAL,
            };
        }
        if self.has_pending_exit() {
            return RejectedBeforeCommit {
                kind: Invalid,
                errno: Errno::ESRCH,
            };
        }
        // A pending exec has no return to the original image, and a pending
        // fork/thread action has not finished establishing its receivers.
        if self.process_action.is_some() {
            return RejectedBeforeCommit {
                kind: Unsupported,
                errno: Errno::ENOSYS,
            };
        }
        let (receipt, matching_fds) = {
            // Retirement, reuse and sibling creation cannot cross publication.
            // Keep lifecycle -> process signal -> thread signal lock order.
            let lifecycle = self
                .state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !lifecycle.get(self.state.tid).is_some_and(|task| {
                task.generation == self.task_generation
                    && task.process_generation == self.process_generation
                    && task.tgid == self.state.pid
            }) {
                return RejectedBeforeCommit {
                    kind: Invalid,
                    errno: Errno::ESRCH,
                };
            }
            if !self.is_thread_group_leader()
                || lifecycle.has_live_sibling(self.state.tid, self.state.pid)
            {
                return RejectedBeforeCommit {
                    kind: Unsupported,
                    errno: Errno::ENOSYS,
                };
            }
            let mut process = self
                .state
                .process_signals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let thread = self.state.thread_signals.lock();
            let pending_generation = process.pending_generation(libc::SIGALRM);
            let action = process
                .dispositions
                .get(&libc::SIGALRM)
                .copied()
                .unwrap_or_default();
            let disposition = if action.is_ignored() {
                ProcessAlarmSignalDisposition::Ignored
            } else if action.handler == libc::SIG_DFL as u64 {
                ProcessAlarmSignalDisposition::DefaultFatal
            } else {
                ProcessAlarmSignalDisposition::Caught
            };
            let matching_fds = process
                .signalfd_masks
                .iter()
                .filter_map(|(&fd, mask)| mask.contains(libc::SIGALRM).then_some(fd))
                .collect::<Vec<_>>();
            if matching_fds
                .iter()
                .any(|fd| !self.state.files.contains_key(fd))
            {
                return RejectedBeforeCommit {
                    kind: Backend,
                    errno: Errno::EBADF,
                };
            }
            // Unlike child-exit generation, SIG_IGN does not suppress this
            // Tool-observable alarm. In particular blocked+ignored is pending.
            let inserted = match process.shared_pending.enqueue(event, pending_generation) {
                Ok(inserted) => inserted,
                Err(errno) => {
                    // Defensive: enqueue currently rejects only nonstandard
                    // signals, but this path has already validated SIGALRM.
                    return RejectedBeforeCommit {
                        kind: Backend,
                        errno,
                    };
                }
            };
            (
                ProcessAlarmSignalReceipt {
                    blocked: thread.blocked.contains(libc::SIGALRM),
                    disposition,
                    pending_generation,
                    coalesced: !inserted,
                },
                matching_fds,
            )
        };
        // Publication is final before bounded eventfd I/O. A readiness error
        // must never be represented as permission to retry an uncommitted send.
        // Also refresh after coalescing: setting ready is idempotent, and a
        // caller retrying after a prior readiness failure can repair readiness
        // without replacing the first siginfo or publishing another signal.
        for fd in matching_fds {
            let file = self
                .state
                .files
                .get(&fd)
                .expect("preflighted signalfd disappeared");
            if let Err(error) = set_signalfd_ready(file, true) {
                return FailedAfterCommit {
                    errno: Errno::new(i32::try_from(-error).unwrap_or(libc::EIO)),
                    receipt,
                };
            }
        }
        Accepted(receipt)
    }

    /// Resolves the exact event returned by a Tool hook for this boundary.
    ///
    /// If the replacement is blocked, preserve its thread or process pending
    /// ownership and end the boundary. Otherwise return it directly so the
    /// delivery path cannot accidentally dequeue a different unfiltered event.
    /// The original domain also applies to a SIGCHLD replacement of a private
    /// signal or fault; replacement provenance does not change queue ownership.
    /// Linux's dequeue_signal/get_signal pass the original type to ptrace_signal,
    /// which uses that type when a tracer replacement is reblocked:
    /// <https://github.com/gregkh/linux/blob/199c9959d3a9b53f346c221757fc7ac507fbac50/kernel/signal.c#L2734>
    pub fn prepare_filtered_signal_delivery(
        &mut self,
        event: reverie::SignalEvent,
        domain: PendingSignalDomain,
    ) -> Result<Option<PendingSignal>, reverie::syscalls::Errno> {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let child_exit = event.signal() == libc::SIGCHLD;
        if child_exit {
            self.validate_child_exit_signal_event(event)
                .map_err(|(_, errno)| errno)?;
        } else {
            self.validate_deferred_signal_event(event, true)?;
        }
        if signal_is_blocked(&self.state, event.signal()) {
            queue_signal_event_locked(
                &mut self.state,
                event,
                domain == PendingSignalDomain::Process,
            )
            .map_err(|raw| {
                reverie::syscalls::Errno::new(i32::try_from(-raw).unwrap_or(libc::EIO))
            })?;
            return Ok(None);
        }
        Ok(Some(PendingSignal { event, domain }))
    }

    /// Removes the next eligible event, preferring the caller's thread queue
    /// over the process-shared queue as Linux does.
    #[cfg(test)]
    pub(crate) fn take_pending_signal(&mut self) -> Option<PendingSignal> {
        take_signal_event(&mut self.state, SignalSelection::Delivery)
            .expect("test pending selection failed")
    }

    pub fn begin_signal_callback(&mut self) -> Option<reverie::CallbackSignalSite> {
        // Called at a callback boundary with no file-table/recipient guard.
        // Release the private snapshot lock before dropping its retained file.
        // Almost always there is no snapshot: test before `take`, which
        // would copy the whole (empty) slot out on every callback.
        let slot = self
            .parent_death_exec
            .get_mut()
            .unwrap_or_else(|p| p.into_inner());
        if slot.is_some() {
            let obsolete = slot.take();
            drop(obsolete);
        }
        let identity = self.signal_task_identity()?;
        self.signal_callback_nonce = self.signal_callback_nonce.checked_add(1)?;
        Some(reverie::CallbackSignalSite {
            process: identity.process,
            tid: identity.tid,
            task_generation: identity.task_generation,
            callback_nonce: self.signal_callback_nonce,
            boundary_nonce: self.signal_callback_nonce,
        })
    }

    pub fn backend_signal_control(&self) -> reverie::BackendSignalControl {
        reverie::BackendSignalControl {
            process: Arc::new(self.signal_registry.control()),
        }
    }

    pub fn install_signal_control(
        &self,
        mode: reverie::BackendSignalControlMode,
        failure: &Arc<crate::failure::RunFailure>,
    ) {
        self.signal_registry.install(mode, failure);
    }

    /// Defense for direct Tool injection. Scheduler-side admission must also
    /// reject unsupported waits BEFORE parking (injection might never occur).
    /// Enrollment is sticky and recipient creation is refused, so this check
    /// cannot race another task's SET or mask change in the recipient process.
    pub(super) fn parent_death_injection_preflight(
        &self,
        request: &SyscallRequest,
    ) -> crate::Result<()> {
        if !self.parent_death_enrolled() {
            return Ok(());
        }
        self.parent_death_operation_preflight(request, false)
    }

    /// Original-call proof with no guest-visible effect. Retained-image exec
    /// stages private authority for this callback only; other operations stage
    /// no authority. The immediate result is never a reusable injection permit.
    pub fn parent_death_original_syscall_preflight(
        &self,
        site: reverie::CallbackSignalSite,
        request: &SyscallRequest,
        original: Option<SyscallRequest>,
        parked_protocol: bool,
    ) -> crate::Result<reverie::ParentDeathSyscallAdmission> {
        let enrolled = {
            let lifecycle = self
                .state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let identity = reverie::SignalTaskIdentity {
                process: site.process,
                tid: site.tid,
                task_generation: site.task_generation,
            };
            if site.callback_nonce != self.signal_callback_nonce
                || site.boundary_nonce != site.callback_nonce
                || identity != self.admitted_signal_identity()
                || lifecycle.parent_death_signal(identity).is_err()
            {
                return Err(crate::Error::ParentDeathSignal {
                    operation: "stale original-call identity",
                    errno: libc::ESRCH,
                });
            }
            lifecycle.parent_death_enrolled(identity.process)
        };
        // The callback's full identity is live even for the root's synthetic
        // initial exec. Absence of an original call is NEVER an unenrolled proof.
        if !enrolled {
            return Ok(reverie::ParentDeathSyscallAdmission::Unenrolled);
        }
        if original != Some(*request) {
            return Err(crate::Error::ParentDeathSignal {
                operation: "original-call operands or context mismatch",
                errno: libc::ENOSYS,
            });
        }
        if matches!(
            request.number() as libc::c_long,
            libc::SYS_execve | libc::SYS_execveat
        ) {
            self.stage_parent_death_exec(site, request)?;
        }
        self.parent_death_operation_preflight(request, parked_protocol)?;
        Ok(reverie::ParentDeathSyscallAdmission::Admitted)
    }

    fn parent_death_exec_error(operation: &'static str) -> crate::Error {
        crate::Error::ParentDeathSignal {
            operation,
            errno: libc::ENOSYS,
        }
    }

    fn stage_parent_death_exec(
        &self,
        site: reverie::CallbackSignalSite,
        request: &SyscallRequest,
    ) -> crate::Result<()> {
        {
            let staged = self
                .parent_death_exec
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(staged) = staged.as_ref() {
                if staged.site == site && staged.original == *request && !staged.consumed {
                    // In particular, do NOT refresh the alias from guest
                    // memory on repeated preflight in this same callback.
                    return Ok(());
                }
                return Err(Self::parent_death_exec_error(
                    "retained exec callback already staged or consumed",
                ));
            }
        }
        self.parent_death_exec_close_preflight()?;
        let args = request.args();
        let path_address = match request.number() as libc::c_long {
            libc::SYS_execve => args[0],
            libc::SYS_execveat if args[0] as i32 == libc::AT_FDCWD && args[4] == 0 => args[1],
            _ => {
                return Err(Self::parent_death_exec_error(
                    "unsupported enrolled exec form",
                ));
            }
        };
        let memory = self.address_space.as_ref().ok_or_else(|| {
            Self::parent_death_exec_error("enrolled exec has no bound address space")
        })?;
        let alias = read_c_string(&ProviderMemory(memory), path_address, 4096)
            .map_err(|_| Self::parent_death_exec_error("enrolled exec alias is not readable"))?;
        if guest_proc_exe_path(&self.state, &alias) != Some(true) {
            return Err(Self::parent_death_exec_error(
                "enrolled exec requires retained current-image authority",
            ));
        }
        let file = self.state.executable_file.as_ref().ok_or_else(|| {
            Self::parent_death_exec_error("enrolled exec has no retained executable file")
        })?;
        if file_mode(file)
            .map_err(|_| Self::parent_death_exec_error("enrolled exec file inspection failed"))?
            & libc::S_IFMT
            != libc::S_IFREG
        {
            return Err(Self::parent_death_exec_error(
                "enrolled exec requires a retained regular file",
            ));
        }
        let image = &self.state.executable_image;
        let elf = crate::elf::parse_elf(image).map_err(|_| {
            Self::parent_death_exec_error("enrolled exec requires a retained static ELF")
        })?;
        if elf
            .program_headers
            .iter()
            .any(|header| header.p_type == goblin::elf::program_header::PT_INTERP)
        {
            return Err(Self::parent_death_exec_error(
                "enrolled exec cannot resolve an interpreter",
            ));
        }
        let staged = ParentDeathExecSnapshot {
            site,
            original: *request,
            alias,
            file: file.clone(),
            image: image.clone(),
            consumed: false,
        };
        let mut slot = self
            .parent_death_exec
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // The exclusive callback cannot concurrently change its identity.
        // Still never overwrite prior authority if a future caller violates
        // that assumption; owned locals drop only after this guard releases.
        if slot.is_some() {
            return Err(Self::parent_death_exec_error(
                "retained exec staging raced another preflight",
            ));
        }
        *slot = Some(staged);
        Ok(())
    }

    fn parent_death_exec_matches(
        &self,
        staged: &ParentDeathExecSnapshot,
        request: &SyscallRequest,
    ) -> bool {
        if staged.consumed
            || !self.signal_site_is_current(staged.site)
            || !self
                .state
                .executable_file
                .as_ref()
                .is_some_and(|file| Arc::ptr_eq(file, &staged.file))
            || !Arc::ptr_eq(&self.state.executable_image, &staged.image)
        {
            return false;
        }
        if *request == staged.original {
            return true;
        }
        if staged.original.number() != libc::SYS_execve as u64 {
            return false;
        }
        // This is exactly reverie-syscalls' From<Execve> for Execveat,
        // including preserved raw arg5. No rewritten target/argv/envp or
        // recorder O_PATH preamble receives this private authority.
        let original = staged.original.args();
        *request
            == SyscallRequest::new(
                libc::SYS_execveat as u64,
                [
                    libc::AT_FDCWD as u64,
                    original[0],
                    original[1],
                    original[2],
                    0,
                    original[5],
                ],
            )
    }

    fn parent_death_exec_close_preflight(&self) -> crate::Result<()> {
        let close_set: Vec<i32> = self
            .file_table
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cloexec_fds
            .iter()
            .copied()
            .collect();
        // Enrollment fixes a single live recipient task, and process clones
        // do not share this descriptor table. No guest sibling can add a
        // lingering endpoint during Tool scheduling. Injection checks again
        // so a Tool's own intervening descriptor mutations grant no authority.
        for fd in close_set {
            self.parent_death_io_preflight(fd, true, true)?;
        }
        Ok(())
    }

    fn check_parent_death_exec(&self, request: &SyscallRequest) -> crate::Result<()> {
        self.parent_death_exec_close_preflight()?;
        let slot = self
            .parent_death_exec
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if slot
            .as_ref()
            .is_some_and(|staged| self.parent_death_exec_matches(staged, request))
        {
            Ok(())
        } else {
            Err(Self::parent_death_exec_error(
                "enrolled exec lacks exact unconsumed callback authority",
            ))
        }
    }

    pub fn retire_parent_death_exec(&self, site: reverie::CallbackSignalSite) {
        let mut slot = self
            .parent_death_exec
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(staged) = slot.as_mut().filter(|staged| staged.site == site) {
            // Revoke authority even when a Tool returns before injection or its
            // callback future is cancelled. Keep ownership until an unlocked
            // callback boundary/owner drop, never close the last file here.
            staged.consumed = true;
        }
    }

    /// Takes the staged authority of the enrolled exec `request`, with a copy
    /// of the retained image for the exec to load. The copy is as large as
    /// the image, so its buffer is allocated fallibly: one this process
    /// cannot allocate is the inner error, the typed refusal of host
    /// resources, which the exec answers ENOMEM, and the authority stays
    /// unspent, as for any other exec that does not run.
    pub(super) fn take_parent_death_exec(
        &self,
        request: &SyscallRequest,
    ) -> crate::Result<std::result::Result<ResolvedExecutable, reverie::UnsupportedRefusal>> {
        let mut slot = self
            .parent_death_exec
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let staged = slot
            .as_mut()
            .filter(|staged| self.parent_death_exec_matches(staged, request))
            .ok_or_else(|| {
                Self::parent_death_exec_error("retained exec authority is stale or consumed")
            })?;
        // Copied before the authority is spent: an exec the host cannot
        // give the copy's memory to is refused with the authority unspent.
        let mut copy = Vec::new();
        if copy.try_reserve_exact(staged.image.len()).is_err() {
            return Ok(Err(exec_allocation_refusal(
                staged.image.len(),
                "a copy of the running program's retained image",
            )));
        }
        copy.extend_from_slice(&staged.image);
        staged.consumed = true;
        Ok(Ok(ResolvedExecutable {
            path: std::path::PathBuf::from(std::ffi::OsString::from_vec(staged.alias.clone())),
            file: Some(staged.file.clone()),
            image: copy,
        }))
    }

    fn parent_death_operation_preflight(
        &self,
        request: &SyscallRequest,
        parked_protocol: bool,
    ) -> crate::Result<()> {
        let number = request.number() as libc::c_long;
        let args = request.args();
        let refusal = |operation| crate::Error::ParentDeathSignal {
            operation,
            errno: libc::ENOSYS,
        };
        match number {
            libc::SYS_close => return self.parent_death_io_preflight(args[0] as i32, true, true),
            libc::SYS_close_range => {
                return Err(refusal(
                    "unsupported enrolled range close or CLOEXEC mutation",
                ));
            }
            libc::SYS_dup2 | libc::SYS_dup3 if args[0] as i32 != args[1] as i32 => {
                // Replacing a descriptor implicitly closes its old endpoint.
                self.parent_death_io_preflight(args[1] as i32, true, true)?;
            }
            libc::SYS_execve | libc::SYS_execveat => return self.check_parent_death_exec(request),
            libc::SYS_vfork => {
                return Err(refusal(
                    "unsupported enrolled shared-address-space child wait",
                ));
            }
            libc::SYS_clone if args[0] & (libc::CLONE_VM | libc::CLONE_THREAD) as u64 != 0 => {
                return Err(refusal(
                    "unsupported enrolled shared-address-space or thread creation",
                ));
            }
            libc::SYS_clone3 => {
                // clone3's pointed-to flags can change during Tool work. This
                // first increment admits scalar clone/fork only, rather than
                // let a later rejection follow consumer metadata effects.
                return Err(refusal(
                    "unsupported enrolled clone3 without an immutable request snapshot",
                ));
            }
            libc::SYS_futex
                if matches!(
                    args[1] as i32 & libc::FUTEX_CMD_MASK,
                    libc::FUTEX_WAIT
                        | libc::FUTEX_WAIT_BITSET
                        | libc::FUTEX_WAIT_REQUEUE_PI
                        | libc::FUTEX_LOCK_PI
                        | libc::FUTEX_LOCK_PI2
                ) =>
            {
                return Err(refusal("unsupported enrolled futex wait"));
            }
            libc::SYS_wait4 if args[2] as i32 & libc::WNOHANG == 0 => {
                return Err(refusal("unsupported enrolled blocking child wait"));
            }
            libc::SYS_waitid if args[3] as i32 & libc::WNOHANG == 0 => {
                return Err(refusal("unsupported enrolled blocking child wait"));
            }
            libc::SYS_fcntl if matches!(args[1] as i32, libc::F_SETLKW | libc::F_OFD_SETLKW) => {
                return Err(refusal("unsupported enrolled blocking record lock"));
            }
            // No flock reaches a host lock on this backend: every valid lock
            // operation is refused with the typed Flock refusal and nothing
            // else touches a description, so none can wait (see `flock`).
            libc::SYS_open | libc::SYS_openat | libc::SYS_creat => {
                return Err(refusal(
                    "unsupported enrolled open without a nonblocking per-call capability",
                ));
            }
            // These waits are completed by the opted-in Tool's authenticated
            // pause/nanosleep protocol, never injected as a host wait.
            libc::SYS_nanosleep | libc::SYS_clock_nanosleep | libc::SYS_pause
                if !parked_protocol =>
            {
                return Err(refusal(
                    "enrolled sleep requires the authenticated parked protocol",
                ));
            }
            libc::SYS_connect
            | libc::SYS_accept
            | libc::SYS_accept4
            | libc::SYS_sendto
            | libc::SYS_sendmsg
            | libc::SYS_sendmmsg
            | libc::SYS_recvmmsg
            | libc::SYS_recvfrom
            | libc::SYS_recvmsg => return Err(refusal("unsupported enrolled socket I/O")),
            // A sampled descriptor flag or a later retry conversion is not
            // authority to enter an external wait before its first effect.
            libc::SYS_poll if args[2] as i32 != 0 => {
                return Err(refusal("unsupported enrolled readiness wait"));
            }
            libc::SYS_epoll_wait | libc::SYS_epoll_pwait if args[3] as i32 != 0 => {
                return Err(refusal("unsupported enrolled readiness wait"));
            }
            libc::SYS_ppoll | libc::SYS_select | libc::SYS_pselect6 | libc::SYS_epoll_pwait2 => {
                // A zero pointee is not immutable authority: another process
                // can change shared timeout storage after first-handler
                // admission, or between injection's check and its second read.
                // Refuse before copying any pointee in both admission routes.
                // Scalar-zero poll/epoll_wait/epoll_pwait remain admitted.
                return Err(refusal(
                    "unsupported enrolled mutable-timeout readiness wait",
                ));
            }
            _ => {}
        }
        if matches!(
            number,
            libc::SYS_fsync
                | libc::SYS_fdatasync
                | libc::SYS_syncfs
                | libc::SYS_sync_file_range
                | libc::SYS_fallocate
                | libc::SYS_ftruncate
                | libc::SYS_readahead
        ) {
            // Ordinary filesystem completion is admitted; an arbitrary device
            // driver or imported socket is not a storage-completion authority.
            return self.parent_death_io_preflight(args[0] as i32, false, false);
        }
        if number == libc::SYS_mmap && args[3] as i32 & libc::MAP_ANONYMOUS == 0 {
            return self.parent_death_io_preflight(args[4] as i32, false, false);
        }
        if number == libc::SYS_sendfile {
            self.parent_death_io_preflight(args[1] as i32, false, false)?;
            // sendfile's table-owned output takes the host fast path even for
            // a captured alias. Only its bare standard-output fallback uses
            // capture; an aliased pipe must still be rejected before transfer.
            return self.parent_death_io_preflight(args[0] as i32, true, false);
        }
        let io = matches!(
            number,
            libc::SYS_read
                | libc::SYS_readv
                | libc::SYS_pread64
                | libc::SYS_preadv
                | libc::SYS_preadv2
                | libc::SYS_write
                | libc::SYS_writev
                | libc::SYS_pwrite64
                | libc::SYS_pwritev
                | libc::SYS_pwritev2
        );
        if !io {
            // Finite opt-in domain: in-memory operations, bounded descriptor
            // queries/creation, ordinary filesystem operations, and the wait
            // forms checked above. Existing host-filesystem completion remains
            // an assumption; this does not promise interruptible storage I/O.
            // A newly implemented syscall requires an explicit domain audit.
            return if matches!(
                number,
                libc::SYS_access
                    | libc::SYS_arch_prctl
                    | libc::SYS_bind
                    | libc::SYS_brk
                    | libc::SYS_capget
                    | libc::SYS_capset
                    | libc::SYS_chdir
                    | libc::SYS_chmod
                    | libc::SYS_chown
                    | libc::SYS_clock_gettime
                    | libc::SYS_clock_nanosleep
                    | libc::SYS_close
                    | libc::SYS_close_range
                    | libc::SYS_dup
                    | libc::SYS_dup2
                    | libc::SYS_dup3
                    | libc::SYS_epoll_create1
                    | libc::SYS_epoll_ctl
                    | libc::SYS_epoll_pwait
                    | libc::SYS_epoll_pwait2
                    | libc::SYS_epoll_wait
                    | libc::SYS_eventfd
                    | libc::SYS_eventfd2
                    | libc::SYS_exit
                    | libc::SYS_exit_group
                    | libc::SYS_faccessat
                    | libc::SYS_faccessat2
                    | libc::SYS_fallocate
                    | libc::SYS_fchdir
                    | libc::SYS_fchmod
                    | libc::SYS_fchmodat
                    | libc::SYS_fchmodat2
                    | libc::SYS_fchown
                    | libc::SYS_fchownat
                    | libc::SYS_fcntl
                    | libc::SYS_fdatasync
                    | libc::SYS_fgetxattr
                    | libc::SYS_flistxattr
                    | libc::SYS_flock
                    | libc::SYS_fremovexattr
                    | libc::SYS_fsetxattr
                    | libc::SYS_fstat
                    | libc::SYS_fstatfs
                    | libc::SYS_fsync
                    | libc::SYS_ftruncate
                    | libc::SYS_futex
                    | libc::SYS_get_robust_list
                    | libc::SYS_getcpu
                    | libc::SYS_getcwd
                    | libc::SYS_getdents64
                    | libc::SYS_getegid
                    | libc::SYS_geteuid
                    | libc::SYS_getgid
                    | libc::SYS_getgroups
                    | libc::SYS_getpeername
                    | libc::SYS_getpgrp
                    | libc::SYS_getpid
                    | libc::SYS_getppid
                    | libc::SYS_getpriority
                    | libc::SYS_getrandom
                    | libc::SYS_getresgid
                    | libc::SYS_getresuid
                    | libc::SYS_getsockname
                    | libc::SYS_getsockopt
                    | libc::SYS_gettid
                    | libc::SYS_gettimeofday
                    | libc::SYS_getuid
                    | libc::SYS_getxattr
                    | libc::SYS_ioctl
                    | libc::SYS_ioprio_get
                    | libc::SYS_ioprio_set
                    | libc::SYS_kill
                    | libc::SYS_lchown
                    | libc::SYS_lgetxattr
                    | libc::SYS_link
                    | libc::SYS_linkat
                    | libc::SYS_listen
                    | libc::SYS_listxattr
                    | libc::SYS_llistxattr
                    | libc::SYS_lremovexattr
                    | libc::SYS_lseek
                    | libc::SYS_lsetxattr
                    | libc::SYS_lstat
                    | libc::SYS_madvise
                    | libc::SYS_membarrier
                    | libc::SYS_memfd_create
                    | libc::SYS_mincore
                    | libc::SYS_mkdir
                    | libc::SYS_mkdirat
                    | libc::SYS_mknod
                    | libc::SYS_mknodat
                    | libc::SYS_mmap
                    | libc::SYS_mprotect
                    | libc::SYS_mremap
                    | libc::SYS_msync
                    | libc::SYS_munlock
                    | libc::SYS_munlockall
                    | libc::SYS_munmap
                    | libc::SYS_nanosleep
                    | libc::SYS_newfstatat
                    | libc::SYS_pidfd_open
                    | libc::SYS_pipe
                    | libc::SYS_pipe2
                    // In-memory, and they never wait (`executor/pkeys.rs`).
                    | libc::SYS_pkey_alloc
                    | libc::SYS_pkey_free
                    | libc::SYS_pkey_mprotect
                    | libc::SYS_poll
                    | libc::SYS_ppoll
                    | libc::SYS_prctl
                    | libc::SYS_prlimit64
                    | libc::SYS_pselect6
                    | libc::SYS_readahead
                    | libc::SYS_readlink
                    | libc::SYS_readlinkat
                    | libc::SYS_removexattr
                    | libc::SYS_rename
                    | libc::SYS_renameat
                    | libc::SYS_renameat2
                    | libc::SYS_rmdir
                    | libc::SYS_rseq
                    | libc::SYS_rt_sigaction
                    | libc::SYS_rt_sigpending
                    | libc::SYS_rt_sigprocmask
                    | libc::SYS_rt_sigtimedwait
                    | libc::SYS_sched_get_priority_max
                    | libc::SYS_sched_get_priority_min
                    | libc::SYS_sched_getaffinity
                    | libc::SYS_sched_getattr
                    | libc::SYS_sched_getparam
                    | libc::SYS_sched_getscheduler
                    | libc::SYS_sched_setattr
                    | libc::SYS_sched_setparam
                    | libc::SYS_sched_setscheduler
                    | libc::SYS_sched_yield
                    | libc::SYS_seccomp
                    | libc::SYS_select
                    | libc::SYS_set_robust_list
                    | libc::SYS_setpriority
                    | libc::SYS_setsockopt
                    | libc::SYS_setxattr
                    | libc::SYS_shutdown
                    | libc::SYS_sigaltstack
                    | libc::SYS_signalfd
                    | libc::SYS_signalfd4
                    | libc::SYS_socket
                    | libc::SYS_socketpair
                    | libc::SYS_stat
                    | libc::SYS_statfs
                    | libc::SYS_statx
                    | libc::SYS_symlink
                    | libc::SYS_symlinkat
                    | libc::SYS_sync_file_range
                    | libc::SYS_syncfs
                    | libc::SYS_tgkill
                    | libc::SYS_rt_sigqueueinfo
                    | libc::SYS_rt_tgsigqueueinfo
                    | libc::SYS_time
                    | libc::SYS_timerfd_create
                    | libc::SYS_timerfd_gettime
                    | libc::SYS_timerfd_settime
                    | libc::SYS_tkill
                    | libc::SYS_truncate
                    | libc::SYS_umask
                    | libc::SYS_personality
                    | libc::SYS_uname
                    | libc::SYS_unlink
                    | libc::SYS_unlinkat
                    | libc::SYS_utimensat
                    | libc::SYS_wait4
                    | libc::SYS_waitid
                    | libc::SYS_fork
                    | libc::SYS_clone
                    | libc::SYS_set_tid_address
                    | libc::SYS_rt_sigreturn
                    | libc::SYS_pause
                    | libc::SYS_setuid
                    | libc::SYS_setgid
                    | libc::SYS_setresuid
                    | libc::SYS_setresgid
                    | libc::SYS_setreuid
                    | libc::SYS_setregid
                    | libc::SYS_setgroups
                    | libc::SYS_setfsuid
                    | libc::SYS_setfsgid
            ) {
                Ok(())
            } else {
                Err(refusal(
                    "operation is outside the enrolled parent-death delivery domain",
                ))
            };
        }
        self.parent_death_io_preflight(
            args[0] as i32,
            matches!(number, libc::SYS_write | libc::SYS_writev),
            true,
        )
    }

    fn parent_death_io_preflight(
        &self,
        fd: i32,
        captures_output: bool,
        captures_aliases: bool,
    ) -> crate::Result<()> {
        let refusal = |operation| crate::Error::ParentDeathSignal {
            operation,
            errno: libc::ENOSYS,
        };
        let table = self.file_table.lock().unwrap_or_else(|p| p.into_inner());
        let standard = (fd == 1 || fd == 2)
            && !table.closed_standard_fds.contains(&fd)
            && !table.files.contains_key(&fd);
        if captures_output
            && (standard || captures_aliases)
            && self.output.is_some()
            && output_alias_from_sets(
                fd,
                &table.stdout_alias_fds,
                &table.stderr_alias_fds,
                standard,
            )
            .is_some()
        {
            return Ok(());
        }
        let file = table.files.get(&fd).or_else(|| {
            (fd == 0 && !table.closed_standard_fds.contains(&fd))
                .then_some(table.stdin.as_ref())
                .flatten()
        });
        let Some(file) = file else {
            if standard {
                return Err(refusal("unsupported enrolled ambient output I/O"));
            }
            // Preserve the real EBADF for an absent descriptor.
            return Ok(());
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: the owned table pins this file; stat points to writable storage.
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(refusal("cannot establish enrolled I/O backing"));
        }
        // SAFETY: successful fstat initialized every field read here.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(refusal(
                "unsupported enrolled nonregular I/O; no pre-attempt nonblocking authority",
            ));
        }
        Ok(())
    }

    pub fn parent_death_enrolled(&self) -> bool {
        self.state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .parent_death_enrolled(self.admitted_signal_identity().process)
    }

    pub fn signal_controlled(&self) -> bool {
        self.signal_registry.controlled()
    }

    /// The mode installed for this run, as the Tool returned it.
    pub fn signal_control_mode(&self) -> reverie::BackendSignalControlMode {
        if self.signal_controlled() {
            reverie::BackendSignalControlMode::ToolControlled
        } else {
            reverie::BackendSignalControlMode::Unchanged
        }
    }

    pub fn delivery_permit(&self) -> Option<reverie::SignalDeliveryPermit> {
        self.signal_registry.permit(self.admitted_signal_identity())
    }

    pub fn take_process_publication_failure(&self) -> Option<crate::Error> {
        self.signal_registry.take_reported_failure()
    }

    pub fn owned_delivery_permit(&self) -> Option<reverie::SignalDeliveryPermit> {
        self.signal_registry
            .owned_permit(self.admitted_signal_identity())
    }

    pub fn signal_dequeues_enabled(&self) -> bool {
        self.state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .dequeue_enabled
    }

    pub fn retain_parked_effects(
        &mut self,
        site: reverie::CallbackSignalSite,
    ) -> Result<(), reverie::syscalls::Errno> {
        use reverie::syscalls::Errno;
        if !self.signal_site_is_current(site)
            || self
                .parked_signals
                .as_ref()
                .is_some_and(|state| state.site != site)
        {
            return Err(Errno::EINVAL);
        }
        if self.parked_signals.is_none() {
            let mut effects = Vec::new();
            effects
                .try_reserve(self.completed_signal_effects.len() + 64)
                .map_err(|_| Errno::ENOMEM)?;
            effects.extend_from_slice(&self.completed_signal_effects);
            let acknowledged = self
                .state
                .process_signals
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .dequeue_acknowledged
                .map_or(0, |effect| effect.sequence);
            self.parked_signals = Some(ParkedSignalState {
                site,
                observations: Vec::new(),
                context: Box::new(reverie::ParkedSignalFailureContext {
                    site,
                    ledger_nonce: site.boundary_nonce,
                }),
                effects,
                acknowledged,
                publications: Vec::new(),
                prepared: None,
            });
        }
        self.reserve_signal_effects(64)
    }

    pub fn reserve_signal_effects(&mut self, count: usize) -> Result<(), reverie::syscalls::Errno> {
        use reverie::syscalls::Errno;
        if self.signal_dequeues_enabled() {
            self.completed_signal_effects
                .try_reserve(count)
                .map_err(|_| Errno::ENOMEM)?;
        }
        if let Some(state) = &mut self.parked_signals {
            if state.effects.len().saturating_add(count) > MAX_PARKED_SIGNAL_EFFECTS
                || state.publications.len() >= MAX_PARKED_SIGNAL_EFFECTS
            {
                return Err(Errno::EOVERFLOW);
            }
            state
                .effects
                .try_reserve(count)
                .map_err(|_| Errno::ENOMEM)?;
            state
                .publications
                .try_reserve(1)
                .map_err(|_| Errno::ENOMEM)?;
        }
        Ok(())
    }

    pub fn retain_signal_dequeue(&mut self, effect: reverie::SignalDequeue) {
        if self.completed_signal_effects.last() != Some(&effect) {
            self.completed_signal_effects.push(effect);
        }
        if let Some(state) = &mut self.parked_signals
            && state
                .effects
                .last()
                .is_none_or(|last| last.sequence < effect.sequence)
        {
            state.effects.push(effect);
        }
    }

    pub fn retain_signal_publication(&mut self, receipt: reverie::ProcessAlarmSignalOutcome) {
        if let Some(state) = &mut self.parked_signals {
            state.publications.push(receipt);
        }
    }

    pub fn mark_signal_dequeue_acknowledged(&mut self, sequence: u64) {
        if let Some(state) = &mut self.parked_signals {
            state.acknowledged = sequence;
        }
    }

    pub fn signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
        self.parked_signals.as_ref().map(|state| *state.context)
    }

    pub fn captured_write_site(
        &self,
        site: reverie::CallbackSignalSite,
        fd: libc::c_int,
    ) -> Option<reverie::CallbackSignalSite> {
        if self.output.is_none() || !self.signal_site_is_current(site) {
            return None;
        }
        // execute() installs this authoritative table before dispatch. A
        // sibling that has since exited may have changed it while this
        // executor's local snapshot still names an older output alias.
        let table = self.file_table.lock().ok()?;
        let standard = (fd == libc::STDOUT_FILENO || fd == libc::STDERR_FILENO)
            && !table.closed_standard_fds.contains(&fd)
            && !table.files.contains_key(&fd);
        if !standard && !table.files.contains_key(&fd) {
            return None;
        }
        output_alias_from_sets(
            fd,
            &table.stdout_alias_fds,
            &table.stderr_alias_fds,
            standard,
        )
        .map(|_| site)
    }

    fn signal_site_is_current(&self, site: reverie::CallbackSignalSite) -> bool {
        site.callback_nonce == self.signal_callback_nonce
            && site.boundary_nonce == site.callback_nonce
            && self.signal_task_identity().is_some_and(|identity| {
                identity.process == site.process
                    && identity.tid == site.tid
                    && identity.task_generation == site.task_generation
            })
    }

    pub fn signal_failure_context_is_current(
        &self,
        context: reverie::ParkedSignalFailureContext,
    ) -> bool {
        self.signal_failure_context() == Some(context) && self.signal_site_is_current(context.site)
    }

    /// Retirement cannot convert an unacknowledged removal or a stale image's
    /// ledger into success. Keep all evidence owned until the driver's exact
    /// boundary receipt is acknowledged; refusal transfers it through normal
    /// with_signal_effects cleanup.
    pub fn validate_signal_retirement(
        &self,
        context: Option<reverie::ParkedSignalFailureContext>,
    ) -> crate::Result<()> {
        let fail = || {
            crate::Error::UnexpectedVcpuExit(
                "thread retirement has stale or unacknowledged signal effects".to_owned(),
            )
        };
        if self.signal_failure_context() != context
            || context.is_some_and(|context| !self.signal_failure_context_is_current(context))
            || self.signal_dequeue_failure().is_some()
        {
            return Err(fail());
        }
        let owner = self.admitted_signal_identity();
        let owned = self.owned_delivery_permit();
        if owned != self.delivery_permit()
            || owned.is_some_and(|permit| permit.task != owner)
            || (self.signal_controlled()
                && self.parked_signals.as_ref().is_some_and(|state| {
                    !state.observations.is_empty()
                        && owned.is_none_or(|permit| {
                            permit.site != Some(state.site)
                                || !state
                                    .observations
                                    .iter()
                                    .any(|lease| lease.nonce == permit.sequence)
                        })
                }))
        {
            return Err(fail());
        }
        let process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if process.dequeue_failed
            || process
                .dequeue_journal
                .iter()
                .any(|entry| entry.owner == owner)
        {
            return Err(fail());
        }
        let acknowledged = process
            .dequeue_acknowledged
            .map_or(0, |effect| effect.sequence);
        if self
            .completed_signal_effects
            .iter()
            .any(|effect| effect.sequence > acknowledged)
            || self.parked_signals.as_ref().is_some_and(|state| {
                state
                    .effects
                    .iter()
                    .any(|effect| effect.sequence > state.acknowledged)
            })
        {
            return Err(fail());
        }
        Ok(())
    }

    pub fn admit_signal_observation(
        &mut self,
        site: reverie::CallbackSignalSite,
        lease: reverie::ParkedObservationLease,
    ) -> Result<(), reverie::syscalls::Errno> {
        use reverie::syscalls::Errno;
        if !self.signal_site_is_current(site)
            || (self.signal_controlled()
                && self.delivery_permit().is_none_or(|permit| {
                    permit.site != Some(site) || permit.sequence != lease.nonce
                }))
            || self.parked_signals.as_ref().is_some_and(|state| {
                state.site != site
                    || state.prepared.is_some()
                    || state.observations.contains(&lease)
            })
        {
            return Err(Errno::EINVAL);
        }
        self.retain_parked_effects(site)?;
        let state = self
            .parked_signals
            .as_mut()
            .expect("retained observation ledger");
        if state.observations.len() == MAX_PARKED_SIGNAL_EFFECTS {
            return Err(Errno::EOVERFLOW);
        }
        state
            .observations
            .try_reserve(1)
            .map_err(|_| Errno::ENOMEM)?;
        state.observations.push(lease);
        Ok(())
    }

    pub fn reserve_signal_delivery(
        &mut self,
        pending: PendingSignal,
        id: reverie::DequeueId,
        fatal: bool,
    ) -> Result<reverie::PreparedSignalToken, reverie::syscalls::Errno> {
        let site = self
            .parked_signals
            .as_ref()
            .ok_or(reverie::syscalls::Errno::EINVAL)?
            .site;
        if !self.signal_site_is_current(site) || site.process != id.process {
            return Err(reverie::syscalls::Errno::EINVAL);
        }
        let state = self
            .parked_signals
            .as_mut()
            .expect("validated selection ledger");
        if state.prepared.is_some() {
            return Err(reverie::syscalls::Errno::EBUSY);
        }
        let token = reverie::PreparedSignalToken {
            site: state.site,
            selection_nonce: id.sequence,
        };
        state.prepared = Some((token, pending, fatal));
        Ok(token)
    }

    pub fn prepared_signal_is_fatal(&self, token: reverie::PreparedSignalToken) -> bool {
        self.signal_site_is_current(token.site)
            && self
                .parked_signals
                .as_ref()
                .and_then(|state| state.prepared)
                .is_some_and(|(current, _, fatal)| current == token && fatal)
    }

    pub fn take_prepared_signal(
        &mut self,
    ) -> Result<Option<PendingSignal>, reverie::syscalls::Errno> {
        let Some((token, _, _)) = self
            .parked_signals
            .as_ref()
            .and_then(|state| state.prepared)
        else {
            return Ok(None);
        };
        if !self.signal_site_is_current(token.site) {
            return Err(reverie::syscalls::Errno::EINVAL);
        }
        Ok(self
            .parked_signals
            .as_mut()
            .expect("validated selection ledger")
            .prepared
            .take()
            .map(|(_, pending, _)| pending))
    }

    pub fn prepared_signal_number(&self) -> Option<i32> {
        self.parked_signals
            .as_ref()?
            .prepared
            .map(|(_, pending, _)| pending.event.signal())
    }

    pub fn retain_signal_effect_result(&mut self, raw: Option<i64>) {
        self.signal_effect_raw_result = raw;
    }

    /// Takes the typed refusal recorded by the last syscall this executor
    /// declined as unsupported, clearing it.
    pub fn take_unsupported_refusal(&mut self) -> Option<reverie::UnsupportedRefusal> {
        self.unsupported_refusal.take()
    }

    pub fn finish_parked_delivery(&mut self) {
        self.parked_signals = None;
        self.completed_signal_effects.clear();
        self.signal_effect_raw_result = None;
    }

    /// Transfer this owner's irreversible effects, stopping the shared stream
    /// only when a ledger is transferred. An error without local effects is
    /// unchanged; run-wide termination is published by the failure owner.
    pub fn with_signal_effects(
        &mut self,
        cause: crate::Error,
        raw_result: Option<i64>,
    ) -> crate::Error {
        let owner = self.admitted_signal_identity();
        let mut process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let acknowledged = process
            .dequeue_acknowledged
            .map_or(0, |effect| effect.sequence);
        let has_pending = process
            .dequeue_journal
            .iter()
            .any(|entry| entry.owner == owner);
        let raw_result = raw_result.or(self.signal_effect_raw_result.take());
        let state = self.parked_signals.take();
        let completed = std::mem::take(&mut self.completed_signal_effects);
        if !has_pending && state.is_none() && completed.is_empty() {
            return cause;
        }
        // Terminal ownership transfer does not acknowledge or roll back any
        // removal. Stop later notification and wake all queued owners into
        // their own consuming cleanup; never steal a sibling's journal.
        process.dequeue_failed = true;
        for entry in &process.dequeue_journal {
            entry.wake.0.wake();
        }

        // Move the pre-reserved buffer. Error reporting must not need a fresh
        // dequeue allocation after the irreversible removal it describes.
        let (mut dequeues, acknowledged_through, publications, context) = match state {
            Some(state) => (
                state.effects,
                state.acknowledged,
                state.publications,
                Some(state.context),
            ),
            None => (completed, acknowledged, Vec::new(), None),
        };
        process.dequeue_journal.retain(|entry| {
            if entry.owner != owner {
                return true;
            }
            if !dequeues.iter().any(|old| old.id() == entry.effect.id()) {
                dequeues.push(entry.effect);
            }
            false
        });
        drop(process);
        crate::Error::SignalEffects {
            cause: Arc::new(cause),
            dequeues,
            acknowledged_through,
            publications,
            raw_result,
            context,
        }
    }

    pub fn has_prepared_signal(&self) -> bool {
        self.parked_signals
            .as_ref()
            .is_some_and(|state| state.prepared.is_some())
    }

    pub fn enable_signal_dequeues(&self) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let mut process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut thread = self.state.thread_signals.lock();
        thread.dequeue_identity = Some(reverie::SignalTaskIdentity {
            process: reverie::SignalProcessId {
                tgid: reverie::Pid::from_raw(self.state.pid),
                generation: self.process_generation,
            },
            tid: reverie::Pid::from_raw(self.state.tid),
            task_generation: self.task_generation,
        });
        process.dequeue_enabled = true;
    }

    pub fn signal_task_identity(&self) -> Option<reverie::SignalTaskIdentity> {
        let lifecycle = self
            .state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let task = lifecycle.get(self.state.tid)?;
        (task.generation == self.task_generation
            && task.process_generation == self.process_generation
            && task.tgid == self.state.pid)
            .then_some(reverie::SignalTaskIdentity {
                process: reverie::SignalProcessId {
                    tgid: reverie::Pid::from_raw(task.tgid),
                    generation: task.process_generation,
                },
                tid: reverie::Pid::from_raw(self.state.tid),
                task_generation: task.generation,
            })
    }

    /// Retain this process generation through an asynchronous Tool
    /// acknowledgement. Lifecycle validation remains authoritative; this guard
    /// only prevents the weak run registry binding from disappearing early.
    pub fn retain_signal_process_binding(&self) -> ProcessSignalBindingGuard {
        ProcessSignalBindingGuard {
            _binding: self.signal_binding.clone(),
        }
    }

    pub fn process_family_exit(&self) -> crate::Result<ProcessFamilyExit> {
        let process = self.admitted_signal_identity().process;
        Self::family_exit_result(process, self.signal_registry.process_family_exit(process))
    }

    /// Stable identity for cleanup after the final live task left the table.
    pub fn retired_process_identity(&self) -> reverie::SignalProcessId {
        self.admitted_signal_identity().process
    }

    /// Like [`Self::process_family_exit`], but claims a `Child` result for this
    /// process's exit completion. See `ProcessSignalRegistry::claim_child_exit`.
    pub fn claim_process_family_exit(&self) -> crate::Result<ProcessFamilyExit> {
        let process = self.admitted_signal_identity().process;
        Self::family_exit_result(process, self.signal_registry.claim_child_exit(process))
    }

    fn family_exit_result(
        process: reverie::SignalProcessId,
        exit: Option<ProcessFamilyExit>,
    ) -> crate::Result<ProcessFamilyExit> {
        match exit {
            Some(exit @ ProcessFamilyExit::Root)
            | Some(exit @ ProcessFamilyExit::Child(_))
            | Some(exit @ ProcessFamilyExit::RunTeardownChild { .. })
            | Some(exit @ ProcessFamilyExit::ReapedByNamespaceInit { .. }) => Ok(exit),
            Some(ProcessFamilyExit::Failed) => Err(crate::Error::RunAborted),
            Some(ProcessFamilyExit::DescendantReparentingUnsupported { child }) => {
                Err(crate::Error::DescendantReparentingUnsupported { process, child })
            }
            Some(ProcessFamilyExit::ParentGenerationUnavailable { parent }) => {
                Err(crate::Error::ParentGenerationUnavailable { process, parent })
            }
            Some(ProcessFamilyExit::ParentChildRelationUnavailable { parent }) => {
                Err(crate::Error::ParentChildRelationUnavailable { process, parent })
            }
            Some(ProcessFamilyExit::AncestryCycle { ancestor }) => {
                Err(crate::Error::ProcessFamilyAncestryCycle { process, ancestor })
            }
            Some(ProcessFamilyExit::MultipleParents {
                child,
                first_parent,
                second_parent,
            }) => Err(crate::Error::ProcessFamilyMultipleParents {
                process,
                child,
                first_parent,
                second_parent,
            }),
            None => Err(crate::Error::UnexpectedVcpuExit(format!(
                "KVM process {} lost its terminal family transition",
                process.tgid.as_raw()
            ))),
        }
    }

    pub fn sole_signal_receiver(&self) -> bool {
        let lifecycle = self
            .state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.is_thread_group_leader()
            && !lifecycle.has_live_sibling(self.state.tid, self.state.pid)
            && lifecycle.get(self.state.tid).is_some_and(|task| {
                task.generation == self.task_generation
                    && task.process_generation == self.process_generation
                    && task.tgid == self.state.pid
            })
            && !self.has_pending_exit()
            && self.process_action.is_none()
    }

    pub(super) fn admitted_signal_identity(&self) -> reverie::SignalTaskIdentity {
        reverie::SignalTaskIdentity {
            process: reverie::SignalProcessId {
                tgid: reverie::Pid::from_raw(self.state.pid),
                generation: self.process_generation,
            },
            tid: reverie::Pid::from_raw(self.state.tid),
            task_generation: self.task_generation,
        }
    }

    /// First removal owned by this executor, even when a predecessor must ack.
    pub fn signal_dequeue_front(&self) -> Option<reverie::SignalDequeue> {
        let owner = self.admitted_signal_identity();
        self.state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .dequeue_journal
            .iter()
            .find(|entry| entry.owner == owner)
            .map(|entry| entry.effect)
    }

    /// Reports that the injection-completion flush (KvmGuest's
    /// complete_signal_effects) has nothing to do: no stored dequeue failure,
    /// a journal that has not failed, and no journaled dequeue owned by this
    /// executor. That flush would then take signal_dequeue_front (None, so no
    /// result is retained) and one poll_signal_dequeue (Ok(None)), and return
    /// Ok(None) having notified no Tool and changed no state. This reads the
    /// same inputs under one process_signals lock instead of two.
    ///
    /// The stored failure is this executor's own field. Journal entries are
    /// added only by this executor's own dequeues, so none of this owner's can
    /// appear between the two locks. Only `dequeue_failed` can be set by
    /// another thread (terminal ownership transfer after a failure), and a
    /// flag set after this read is the execution the two-lock code also had
    /// when the flag was set after its second lock.
    pub fn signal_effects_settled(&self) -> bool {
        if self.signal_dequeue_failure().is_some() {
            return false;
        }
        let owner = self.admitted_signal_identity();
        let process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        !process.dequeue_failed
            && !process
                .dequeue_journal
                .iter()
                .any(|entry| entry.owner == owner)
    }

    /// A refusal by the observation bookkeeping, never a guest syscall errno.
    pub fn signal_dequeue_failure(&self) -> Option<reverie::syscalls::Errno> {
        self.state.signal_dequeue_failure
    }

    pub fn poll_signal_dequeue(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<crate::Result<Option<reverie::SignalDequeue>>> {
        use std::task::Poll;
        if let Some(errno) = self.signal_dequeue_failure() {
            return Poll::Ready(Err(crate::Error::Reverie(errno.into())));
        }
        let owner = self.admitted_signal_identity();
        let process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if process.dequeue_failed {
            return Poll::Ready(Err(crate::Error::RunAborted));
        }
        let Some(entry) = process
            .dequeue_journal
            .iter()
            .find(|entry| entry.owner == owner)
        else {
            return Poll::Ready(Ok(None));
        };
        if process
            .dequeue_journal
            .front()
            .is_some_and(|front| front.owner == owner)
        {
            Poll::Ready(Ok(Some(entry.effect)))
        } else {
            // Registration and the predicate share the journal lock, avoiding a
            // lost ack wakeup. No lock survives the pending return or Tool await.
            entry.wake.0.register(cx.waker());
            Poll::Pending
        }
    }

    pub fn acknowledge_signal_dequeue(
        &self,
        effect: reverie::SignalDequeue,
    ) -> Result<(), reverie::syscalls::Errno> {
        let owner = self.admitted_signal_identity();
        let mut process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if process.dequeue_failed {
            return Err(reverie::syscalls::Errno::EINVAL);
        }
        if process.dequeue_acknowledged == Some(effect)
            && process.dequeue_acknowledged_owner == Some(owner)
        {
            return Ok(());
        }
        if !process
            .dequeue_journal
            .front()
            .is_some_and(|entry| entry.owner == owner && entry.effect == effect)
        {
            return Err(reverie::syscalls::Errno::EINVAL);
        }
        process.dequeue_journal.pop_front();
        process.dequeue_acknowledged = Some(effect);
        process.dequeue_acknowledged_owner = Some(owner);
        let wake = process
            .dequeue_journal
            .front()
            .map(|entry| entry.wake.clone());
        drop(process);
        if let Some(wake) = wake {
            wake.0.wake();
        }
        Ok(())
    }

    /// Selects one event for a return-to-user delivery boundary and updates
    /// every signalfd alias before the Tool hook or disposition is evaluated.
    /// Ordinary syscall returns and rt_sigreturn continuations share this path.
    pub fn take_pending_signal_for_delivery(
        &mut self,
    ) -> Result<Option<PendingSignal>, reverie::syscalls::Errno> {
        if self.signal_controlled() && self.delivery_permit().is_none() {
            return Ok(None);
        }
        // Process-owned eventfd keepers remove the ordinary descriptor-table
        // dependency. A sibling FIFO open or recvmsg may retain that table indefinitely.
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        self.take_pending_signal_locked()
    }

    /// [`Self::take_pending_signal_for_delivery`] for a task whose thread
    /// group may be exiting: once that group's exit has committed (a peer's
    /// exit_group, or a signal's group exit), it selects nothing, changes
    /// nothing, and returns the committed status. Every task exit commits
    /// under the signal transaction lock that this selection holds from that
    /// test through its dequeue, so no group exit can commit between the two,
    /// as Linux's get_signal tests SIGNAL_GROUP_EXIT under siglock before
    /// every dequeue
    /// (<https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c#L2865-L2918>).
    pub fn take_pending_signal_for_delivery_unless_group_exit(
        &mut self,
    ) -> Result<GuardedSignal, reverie::syscalls::Errno> {
        if self.signal_controlled() && self.delivery_permit().is_none() {
            return Ok(GuardedSignal::Nothing);
        }
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        // The lifecycle lock comes after the transaction's, in the ordinary
        // order, and is released before the dequeue takes the process and
        // thread locks.
        if let Some(status) = wait_group_exit_status(&self.state) {
            return Ok(GuardedSignal::GroupExit(status));
        }
        Ok(match self.take_pending_signal_locked()? {
            Some(pending) => GuardedSignal::Selected(pending),
            None => GuardedSignal::Nothing,
        })
    }

    /// Admits `pending`, a signal the backend raised for this task's own
    /// fault rather than one it dequeued, under the same rule: once the task's
    /// thread group has committed its exit, the fault's signal is not
    /// delivered either, and the committed status is returned. The test holds
    /// the signal transaction lock under which every task exit commits, so
    /// the admission is ordered with each commit, as Linux's get_signal takes
    /// the group exit before it dequeues even a synchronous signal
    /// (<https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c#L2865-L2918>).
    pub fn admit_signal_unless_group_exit(&self, pending: PendingSignal) -> GuardedSignal {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        match wait_group_exit_status(&self.state) {
            Some(status) => GuardedSignal::GroupExit(status),
            None => GuardedSignal::Selected(pending),
        }
    }

    /// The exit status of this task's thread group once that group's exit
    /// has committed, while this task is still live; `None` otherwise.
    pub fn committed_group_exit_status(&self) -> Option<ExitStatus> {
        wait_group_exit_status(&self.state)
    }

    /// The dequeue of a delivery selection, with the caller holding the
    /// signal transaction lock.
    fn take_pending_signal_locked(
        &mut self,
    ) -> Result<Option<PendingSignal>, reverie::syscalls::Errno> {
        self.reserve_signal_effects(1)?;
        let pending = take_signal_event_locked(&mut self.state, SignalSelection::Delivery)?;
        refresh_signalfd_readiness_from_carriers_locked(&self.state, None).map_err(|raw| {
            reverie::syscalls::Errno::new(i32::try_from(-raw).unwrap_or(libc::EIO))
        })?;
        Ok(pending)
    }

    /// Test-only: whether signal_boundary_emptiness reports an empty boundary.
    #[cfg(any(test, feature = "test-support"))]
    pub fn signal_boundary_is_empty(&self) -> bool {
        matches!(
            self.signal_boundary_emptiness(),
            SignalBoundaryEmptiness::Empty { .. }
        )
    }

    /// Reports whether this thread's next signal boundary is empty: it can
    /// neither select a signal nor fail nor change signal state. There is no
    /// stored dequeue failure, no parked ledger whose effect reservation could
    /// refuse, no
    /// signalfd whose readiness the boundary would refresh, no journaled
    /// dequeue of this thread's to flush, and no pending signal that the
    /// current mask leaves unblocked. Then take_pending_signal_for_delivery
    /// returns no signal and leaves every signal structure as it found it, and
    /// a delivery permit authorized only for that call would be consumed with
    /// no effect, so the caller may skip the whole boundary.
    ///
    /// Every input is this thread's own state or state that other tasks change
    /// only during their own serial turns, so the answer is the one the full
    /// boundary would reach at this point of the same turn.
    ///
    /// When the boundary is empty, also reports whether a temporary-mask call
    /// left a saved mask for the boundary to restore, read under the thread
    /// lock the answer already holds. Only this thread's own executor writes
    /// the saved mask (installing a temporary mask in its own call,
    /// delivering, rt_sigreturn, and the restore itself).
    pub fn signal_boundary_emptiness(&self) -> SignalBoundaryEmptiness {
        if self.state.signal_dequeue_failure.is_some() || self.parked_signals.is_some() {
            return SignalBoundaryEmptiness::NotEmpty;
        }
        let owner = self.admitted_signal_identity();
        let process = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !process.signalfd_masks.is_empty()
            || process
                .dequeue_journal
                .iter()
                .any(|entry| entry.owner == owner)
        {
            return SignalBoundaryEmptiness::NotEmpty;
        }
        let generations = &process.pending_generations;
        let thread = self.state.thread_signals.lock();
        let blocked = thread.blocked;
        if !thread.pending.any_eligible(blocked, generations)
            && !process.shared_pending.any_eligible(blocked, generations)
        {
            SignalBoundaryEmptiness::Empty {
                mask_saved: thread.saved_sigmask.is_some(),
            }
        } else {
            SignalBoundaryEmptiness::NotEmpty
        }
    }

    /// Test-only: adds `signal` to this thread's mask, as a Tool's injected
    /// rt_sigprocmask would.
    #[cfg(any(test, feature = "test-support"))]
    pub fn block_signal_for_test(&self, signal: libc::c_int) {
        self.state.thread_signals.lock().blocked.insert(signal);
    }

    /// Test-only: makes this executor's admitted task generation stale, as
    /// after the task it was admitted for was replaced.
    #[cfg(any(test, feature = "test-support"))]
    pub fn lose_task_generation_for_test(&mut self) {
        self.task_generation += 1;
    }

    /// Test-only: records a parent-death publication failure, as a failed
    /// publication does.
    #[cfg(any(test, feature = "test-support"))]
    pub fn retain_parent_death_error_for_test(&self, errno: reverie::syscalls::Errno) {
        self.signal_registry.retain_parent_death_error(errno);
    }

    /// Reports current unblocked pending state without selecting a signal or
    /// requiring a delivery permit.
    pub fn has_eligible_pending_signal(&self) -> bool {
        has_eligible_pending_signal(&self.state)
    }

    /// Preflights a post-exec signal-mask injection. Lifecycle callbacks have
    /// no stopped userspace return frame, so making an exec-preserved pending
    /// signal eligible here must fail before the mask or old-mask output is
    /// changed and before the new image executes.
    ///
    /// Returns `None` when the request may run, its own `-EINVAL` or `-EFAULT`
    /// when its arguments are invalid, and `-ENOSYS` only when a valid mask
    /// change would make a pending signal eligible, so a caller can tell that
    /// refusal from an argument error by its errno.
    pub fn lifecycle_signal_mask_preflight(
        &self,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Option<i64> {
        if request.number() != libc::SYS_rt_sigprocmask as u64 {
            return None;
        }
        let blocked = self.state.thread_signals.lock().blocked;
        let next = match prospective_sigprocmask(memory, blocked, request.args()) {
            Ok(Some(next)) => next,
            Ok(None) => return None,
            Err(error) => return Some(error),
        };
        let process_signals = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generations = &process_signals.pending_generations;
        let eligible = self
            .state
            .thread_signals
            .lock()
            .pending
            .any_eligible(next, generations)
            || process_signals
                .shared_pending
                .any_eligible(next, generations);
        eligible.then_some(negative_errno(libc::ENOSYS))
    }

    pub(super) fn has_shared_pending_signal(&self) -> bool {
        let process_signals = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        process_signals.shared_pending.any_eligible(
            KernelSigset::default(),
            &process_signals.pending_generations,
        )
    }

    pub fn caught_signal_restarts_syscall(&self, pending: PendingSignal) -> bool {
        self.signal_disposition(pending.event.signal()) == SignalDisposition::Handled
            && self.signal_action(pending.event.signal()).flags & libc::SA_RESTART as u64 != 0
    }

    pub fn signal_disposition(&self, signal: libc::c_int) -> SignalDisposition {
        signal_disposition(&self.state, signal)
    }

    pub fn signal_action(&self, signal: libc::c_int) -> KernelSigaction {
        installed_signal_action(&self.state, signal).unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn signal_mask(&self) -> KernelSigset {
        self.state.thread_signals.lock().blocked
    }

    /// The mask a signal frame saves for `rt_sigreturn` (Linux's
    /// `sigmask_to_save`): the thread's own mask saved by a call that
    /// installed a temporary one, or else the current mask.
    pub fn frame_signal_mask(&self) -> KernelSigset {
        let thread_signals = self.state.thread_signals.lock();
        thread_signals
            .saved_sigmask
            .unwrap_or(thread_signals.blocked)
    }

    /// Linux's `restore_saved_sigmask`: a return boundary that runs no handler
    /// puts back the mask a temporary-mask call saved.
    pub fn restore_saved_signal_mask(&mut self) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let mut thread_signals = self.state.thread_signals.lock();
        if let Some(saved) = thread_signals.saved_sigmask.take() {
            thread_signals.blocked = saved;
        }
    }

    pub fn observe_ignored_signals_with_tool(&self) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        self.state.thread_signals.lock().observe_ignored = true;
    }

    #[cfg(test)]
    pub(crate) fn page_zero_fault_event(&self, address: u64) -> reverie::SignalEvent {
        self.trap_signal_event(libc::SIGSEGV, crate::signal::SEGV_MAPERR, address)
    }

    /// The thread-directed `siginfo_t` Linux's `force_sig_fault` builds for a
    /// synchronous CPU exception: `si_signo`, `si_code`, and `si_addr`.
    pub fn trap_signal_event(
        &self,
        signal: libc::c_int,
        code: i32,
        address: u64,
    ) -> reverie::SignalEvent {
        let mut info = [0; reverie::SIGNAL_INFO_SIZE];
        info[..4].copy_from_slice(&signal.to_ne_bytes());
        info[8..12].copy_from_slice(&code.to_ne_bytes());
        info[16..24].copy_from_slice(&address.to_ne_bytes());
        reverie::SignalEvent::new(
            signal,
            info,
            reverie::SignalTarget::Thread {
                pid: reverie::Pid::from_raw(self.state.pid),
                tid: reverie::Pid::from_raw(self.state.tid),
            },
        )
        .expect("captured CPU exception has coherent signal information")
    }

    /// Applies Linux `force_sig_info_to_task` to a captured CPU exception's
    /// signal: when the signal is blocked or ignored, it is unblocked and its
    /// action is reset to the default, so the fault can neither be deferred nor
    /// discarded. A handled, unblocked signal keeps its handler.
    pub fn prepare_captured_trap(&mut self, signal: libc::c_int) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        // Linux unblocks the signal and resets its action under one siglock
        // (`force_sig_info_to_task`), which a reader of the thread's signal
        // state holds too (`task_sig`). Hold the process's and the thread's
        // signal locks together, in the order every signal path takes them,
        // so that no reader sees one change without the other.
        let mut process_signals = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut thread_signals = self.state.thread_signals.lock();
        let action = process_signals.dispositions.get(&signal).copied();
        if thread_signals.blocked.contains(signal)
            || signal_disposition_with_action(action, signal) == SignalDisposition::Ignore
        {
            thread_signals.blocked.remove(signal);
            #[cfg(test)]
            CAPTURED_TRAP_TEST_HOOK.with(|hook| {
                if let Some(hook) = hook.borrow_mut().as_mut() {
                    hook();
                }
            });
            process_signals.dispositions.remove(&signal);
        }
    }

    /// Records a CPU exception that raises a signal in this thread's trap
    /// fields, as Linux's trap handlers do before they raise it: the vector
    /// and error code always, and `fault_address`, a page fault's CR2, only
    /// when there is one. Every later frame of the thread saves them; see
    /// [`SignalTrapFields`].
    pub fn record_user_trap(&mut self, trapno: u64, error_code: u64, fault_address: Option<u64>) {
        let mut thread_signals = self.state.thread_signals.lock();
        thread_signals.trap.trapno = trapno;
        thread_signals.trap.error_code = error_code;
        if let Some(address) = fault_address {
            thread_signals.trap.cr2 = address;
        }
    }

    /// The trap fields this thread's next signal frame saves.
    pub fn signal_trap_fields(&self) -> SignalTrapFields {
        self.state.thread_signals.lock().trap
    }

    /// The `uc_stack` a signal frame saves: the alternate stack as
    /// `sigaltstack` installed it, with the flags it was given (after an exec,
    /// or SS_DISABLE with SS_AUTODISARM, with no address or size and those
    /// flags), or `SS_DISABLE` and no stack when there is none. Linux writes
    /// the task's own `sas_ss_flags` there (`unsafe_save_altstack`,
    /// include/linux/signal.h): SS_ONSTACK only when a caller gave it as the
    /// mode, never for running on the stack, which only `sigaltstack`'s report
    /// adds.
    pub fn signal_altstack(&self) -> GuestStack {
        self.state
            .thread_signals
            .lock()
            .altstack
            .unwrap_or(DISABLED_ALTSTACK)
    }

    pub fn signal_stack_top(
        &self,
        action: KernelSigaction,
        stack_pointer: u64,
    ) -> Result<(u64, Option<u64>, bool), reverie::syscalls::Errno> {
        // A stack with no size, as exec or SS_DISABLE with SS_AUTODISARM
        // leaves one, is disabled: Linux's sas_ss_flags reports SS_DISABLE
        // for it, whatever its flags.
        let Some(stack) = self
            .state
            .thread_signals
            .lock()
            .altstack
            .filter(|stack| stack.size != 0)
        else {
            return Ok((stack_pointer, None, true));
        };
        // Linux's get_sigframe (arch/x86/kernel/signal.c) first subtracts the
        // interrupted stack's red zone, and switches an SA_ONSTACK handler to
        // the top of the alternate stack only when that adjusted rsp is not
        // on the stack (`sas_ss_flags(sp) == 0`). So an rsp up to 128 bytes
        // above the stack's top gets its frame below its red zone, inside the
        // stack, with no switch, and one on the stack within 128 bytes of its
        // base gets a frame at the top again. No red zone is subtracted from
        // the fresh stack, and the frame must fit on it.
        let red_zone_base = stack_pointer.wrapping_sub(crate::signal::SIGNAL_RED_ZONE);
        if action.flags & libc::SA_ONSTACK as u64 != 0 && !stack.contains(red_zone_base) {
            return Ok((stack.sp.wrapping_add(stack.size), Some(stack.sp), false));
        }
        // Otherwise the frame goes below the red zone. A nested delivery, one
        // whose interrupted rsp itself is on the stack (`on_sig_stack`), must
        // not underflow the configured lower bound even when adjacent memory
        // is mapped.
        let nested = stack.contains(stack_pointer);
        Ok((stack_pointer, nested.then_some(stack.sp), true))
    }

    pub fn enter_signal_handler(&mut self, pending: PendingSignal, action: KernelSigaction) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let signal = pending.event.signal();
        let mut process_signals = self
            .state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut thread_signals = self.state.thread_signals.lock();
        // The frame already saved any mask a temporary-mask call saved
        // (`frame_signal_mask`); the handler runs under the temporary mask
        // widened by its action, as Linux's `signal_delivered` does.
        thread_signals.saved_sigmask = None;
        thread_signals.blocked.union_with(action.mask);
        if action.flags & libc::SA_NODEFER as u64 == 0 {
            thread_signals.blocked.insert(signal);
        }
        thread_signals.blocked.clear_unmaskable();
        if action.flags & libc::SA_RESETHAND as u64 != 0 {
            process_signals.dispositions.remove(&signal);
        }
        // Linux's signal_delivered disarms an SS_AUTODISARM stack after every
        // delivery (sas_ss_reset), whichever stack the frame went on, so a
        // handler that does not run on it finds it disabled too. The frame
        // already saved the stack as it was.
        if thread_signals
            .altstack
            .is_some_and(|stack| stack.flags & SS_AUTODISARM != 0)
        {
            thread_signals.altstack = None;
        }
    }

    pub fn restore_signal_thread_state(
        &mut self,
        mut blocked: KernelSigset,
        stack: GuestStack,
        restorer_stack_pointer: u64,
    ) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        blocked.clear_unmaskable();
        let mut thread_signals = self.state.thread_signals.lock();
        thread_signals.blocked = blocked;
        thread_signals.saved_sigmask = None;
        if let Ok(restored) =
            validate_altstack_update(thread_signals.altstack, Some(restorer_stack_pointer), stack)
        {
            thread_signals.altstack = restored;
        }
        // Linux ignores restore_altstack() failures while still restoring the
        // mask, registers and FP state. In particular, a handler cannot replace
        // an active alternate stack through its ucontext.
    }

    pub fn force_signal_exit(&mut self, signal: libc::c_int) {
        self.exit_status = terminating_signal_status(signal, self.current_dumpable());
        self.exit_group = true;
    }

    pub fn set_current_user_stack_pointer(&mut self, stack_pointer: u64) {
        self.current_user_stack_pointer = Some(stack_pointer);
    }

    pub fn set_thread_context(&mut self, tid: i32, fs_base: u64, gs_base: u64) {
        self.state.tid = tid;
        self.state.fs_base = fs_base;
        self.state.gs_base = gs_base;
    }

    /// Returns and clears a pending FS/GS base update requested via `arch_prctl`.
    pub fn take_segment(&mut self) -> Option<(SegmentBase, u64)> {
        self.pending_segment.take()
    }

    /// Returns and clears a pending thread-local or group-wide exit.
    pub fn take_exit(&mut self) -> Option<ProcessExit> {
        self.take_exit_with_parent_death(true)
    }

    fn take_exit_with_parent_death(&mut self, guest_death: bool) -> Option<ProcessExit> {
        // The syscall loop asks after every guest syscall, and there is
        // almost never an exit. The status is this executor's own field, so
        // it can be read without the signal transaction; when there is none,
        // the locked path below would return None without changing anything.
        self.exit_status?;
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let mut status = self.exit_status.take()?;
        let mut group = std::mem::take(&mut self.exit_group);
        let (status, process_status, group_started) = {
            let mut lifecycle = self
                .state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // A SIGKILL keeps its group exit: complete_signal starts that
            // group exit without looking at group_exec_task
            // (https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c#L1003-L1025),
            // and de_thread then fails the exec, so the whole process dies
            // (https://github.com/gregkh/linux/blob/v7.1.3/fs/exec.c#L927-L932).
            // The exec here does not stop for it yet
            // (https://github.com/rrnewton/reverie/issues/1210). Other fatal
            // signals start a group exit there only in an untraced process; a
            // Tool's signal hook stands where a tracer's signal-delivery stop
            // does, and a traced thread's fatal signal reaches do_group_exit
            // through get_signal.
            if group
                && !matches!(status, ExitStatus::Signaled(reverie::Signal::SIGKILL, _))
                && lifecycle.exec_froze_live_task(self.admitted_signal_identity())
            {
                // An exec by another thread of this group froze this live
                // task's death (prepare_parent_death_exec) before the task's
                // own exit committed, and no group exit has committed: Linux's
                // do_group_exit, finding group_exec_task, starts no group exit
                // and ends the thread with status 0
                // (https://github.com/gregkh/linux/blob/v7.1.3/kernel/exit.c#L1093-L1121).
                // A group exit committed here would instead mark the exec's
                // surviving issuer dead and end its process. The retirement
                // of a task whose exit was already taken is not a new exit.
                group = false;
                status = ExitStatus::SUCCESS;
            }
            if guest_death {
                // A previously committed exit_group owns the status even if a
                // later task requests a different exit. Freeze that winner
                // while this same lifecycle lock still holds every death-set
                // identity; exit() below cannot choose a different winner.
                let winning_status = lifecycle
                    .live_task_group_exit_status(self.admitted_signal_identity())
                    .unwrap_or(status);
                let outcome = reverie::SignalBoundaryOutcome::Terminated {
                    group,
                    wait_status: winning_status.into_raw(),
                };
                let boundary = self
                    .owned_delivery_permit()
                    .map(|permit| reverie::SignalBoundaryReceipt { permit, outcome });
                if let Err(errno) = lifecycle.freeze_parent_death(
                    self.admitted_signal_identity(),
                    outcome,
                    boundary,
                ) {
                    self.signal_registry.retain_parent_death_error(errno);
                }
            }
            let (status, group_started) =
                lifecycle.exit(self.state.tid, self.task_generation, status, group);
            let process_status =
                lifecycle.process_exit_status(self.state.pid, self.process_generation);
            (status, process_status, group_started)
        };
        // A group exit is the logical process-exit transition even while host
        // cancellation is still retiring peer task handles. Record it at the
        // initiating task's ordered exit point; otherwise a descendant given a
        // later scheduler turn could race the final peer's host retirement and
        // change success into an unsupported-reparenting error.
        let family_status = process_status.or(group_started.then_some(status));
        if let Some(process_status) = family_status {
            // Keep the exact process transaction held across both the final
            // lifecycle removal and its family-ledger transition. A direct
            // child samples this transaction before inspecting the parent's
            // lifecycle, so it cannot observe a dead parent generation before
            // `record_process_exit` makes the corresponding terminal state
            // visible.
            self.signal_registry
                .record_process_exit(self.admitted_signal_identity().process, process_status);
        }
        Some(ProcessExit { status, group })
    }

    /// Completes a Tool-authorized terminal thread without executing a guest
    /// syscall. An already established fatal or group exit keeps its status.
    pub fn cancel_current_thread(&mut self) -> ProcessExit {
        self.retire_current_thread(ExitStatus::SUCCESS, false)
    }

    pub fn retire_current_thread(&mut self, status: ExitStatus, group: bool) -> ProcessExit {
        self.exit_status.get_or_insert(status);
        self.exit_group |= group;
        // Cleanup/cancellation is not a new guest death. Genuine group and
        // exec sibling deaths were frozen by their logical initiating task.
        self.take_exit_with_parent_death(false)
            .expect("terminal thread has an exit status")
    }

    pub fn retire_guest_thread(&mut self, status: ExitStatus, group: bool) -> ProcessExit {
        self.exit_status.get_or_insert(status);
        self.exit_group |= group;
        self.take_exit().expect("guest exit has a status")
    }

    pub fn prepare_parent_death_exec(&self) -> crate::Result<()> {
        let outcome = reverie::SignalBoundaryOutcome::ImageReplaced;
        let boundary = self
            .owned_delivery_permit()
            .map(|permit| reverie::SignalBoundaryReceipt { permit, outcome });
        let result = self
            .state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .freeze_parent_death(self.admitted_signal_identity(), outcome, boundary);
        result
            .map(|_| ())
            .map_err(|errno| crate::Error::ParentDeathSignal {
                operation: "exec sibling death admission",
                errno: errno.into_raw(),
            })
    }

    pub fn check_parent_death_failure(&self) -> crate::Result<()> {
        self.signal_registry.check_parent_death_failure()
    }

    pub fn check_parent_death_boundary(
        &self,
        boundary: reverie::SignalBoundaryReceipt,
    ) -> crate::Result<()> {
        self.signal_registry
            .parent_death_boundary_finished(boundary)
    }

    pub fn retire_failed_thread(&mut self) {
        let transaction = self.state.signal_transaction.clone();
        let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
        let task_failed = {
            let mut lifecycle = self
                .state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            lifecycle.fail(self.state.tid, self.task_generation)
        };
        if task_failed {
            self.signal_registry
                .record_process_failure(self.admitted_signal_identity().process);
        }
    }

    /// Consume only the exact group decision that cancelled this live wait.
    /// The Tool callback may have been destroyed since the initial selection;
    /// stale identity or a newly failed process must still refuse clean exit.
    pub fn validate_child_wait_group_exit(&self, status: ExitStatus) -> crate::Result<()> {
        if wait_group_exit_status(&self.state) == Some(status) {
            Ok(())
        } else {
            Err(crate::Error::RunAborted)
        }
    }

    pub fn retire_child_wait_group_exit(
        &mut self,
        status: ExitStatus,
    ) -> crate::Result<ProcessExit> {
        self.validate_child_wait_group_exit(status)?;
        // The initiating group exit already froze every dying member. A
        // follower with a real permit retains its empty completion while the
        // owner is still live. A follower without one has no publication
        // authority and only performs the existing physical retirement.
        Ok(if self.owned_delivery_permit().is_some() {
            self.retire_guest_thread(status, true)
        } else {
            self.retire_current_thread(status, true)
        })
    }

    pub fn process_exit_status(&self) -> Option<ExitStatus> {
        self.state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .process_exit_status(self.state.pid, self.process_generation)
    }

    pub fn take_output(&mut self) -> (Vec<u8>, Vec<u8>) {
        if self.owns_output {
            self.output
                .as_mut()
                .map(CapturedOutput::take)
                .unwrap_or_default()
        } else {
            (Vec::new(), Vec::new())
        }
    }
}

pub(super) fn rt_sigaction(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    if args[3] != KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    let Ok(signal) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EINVAL);
    };
    if !(1..=64).contains(&signal) {
        return negative_errno(libc::EINVAL);
    }
    let mut action = if args[1] == 0 {
        None
    } else {
        match read_guest_bytes::<KERNEL_SIGACTION_SIZE>(&ProviderMemory(memory), args[1]) {
            Ok(action) => Some(KernelSigaction::decode(action)),
            Err(error) => return error,
        }
    };
    if let Some(action) = &mut action {
        action.mask.clear_unmaskable();
    }
    if action.is_some() && matches!(signal, libc::SIGKILL | libc::SIGSTOP) {
        return negative_errno(libc::EINVAL);
    }
    // Installing a real SIGCHLD handler is ACCEPTED, not refused. Linux implements
    // this call and both the native host and the ptrace backend return 0; hermit's
    // tests/c/kvm_exact_child_waits.c requires success. Recording the action is also
    // harmless for the auto-reap decision below: `sigchld_auto_reaps` matches only
    // SIG_IGN and SA_NOCLDWAIT, so a real handler correctly yields false and the
    // child stays waitable. Whether KVM should additionally DELIVER that handler is
    // a separate, still-open question; accepting the installation does not answer it
    // and does not claim delivery.

    let discards_pending = action.is_some_and(|action| {
        action.handler == libc::SIG_IGN as u64
            || action.handler == libc::SIG_DFL as u64
                && default_signal_disposition(signal) == SignalDisposition::Ignore
    });
    // Linux discards every instance that predates an ignored disposition.
    // A process-shared generation makes old entries in every private queue
    // ineligible atomically without walking and locking each live sibling.
    // A blocked signal generated after this transition uses the new generation
    // and may remain pending if a handler is installed before it is unblocked.
    let (previous, readiness) = {
        let mut process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = process_signals
            .dispositions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        if discards_pending {
            if let Err(error) = process_signals.advance_pending_generation(signal) {
                return negative_errno(error.into_raw());
            }
            state.thread_signals.lock().pending.remove(signal);
            process_signals.shared_pending.remove(signal);
        }
        if let Some(action) = action {
            process_signals.dispositions.insert(signal, action);
        }
        let readiness = if discards_pending {
            process_signals
                .signalfd_masks
                .iter()
                .filter(|(_, mask)| mask.contains(signal))
                .map(|(&fd, mask)| (fd, shared_queue_covers(&process_signals, **mask)))
                .collect()
        } else {
            Vec::new()
        };
        (previous, readiness)
    };
    for (fd, ready) in readiness {
        if let Some(file) = state.files.get(&fd)
            && let Err(error) = set_signalfd_ready(file, ready)
        {
            return error;
        }
    }
    if args[2] != 0 {
        return write_bytes(&mut ProviderMemory(memory), args[2], &previous.encode());
    }
    0
}

fn prospective_sigprocmask(
    memory: &GuestMemory,
    current: KernelSigset,
    args: &[u64; 6],
) -> Result<Option<KernelSigset>, i64> {
    if args[3] != KERNEL_SIGSET_SIZE as u64 {
        return Err(negative_errno(libc::EINVAL));
    }
    if args[1] == 0 {
        return Ok(None);
    }
    let requested = KernelSigset::from_bytes(read_guest_bytes::<KERNEL_SIGSET_SIZE>(
        &ProviderMemory(memory),
        args[1],
    )?);
    let mut next = current;
    match args[0] as libc::c_int {
        libc::SIG_BLOCK => next.union_with(requested),
        libc::SIG_UNBLOCK => next.remove_all(requested),
        libc::SIG_SETMASK => next = requested,
        _ => return Err(negative_errno(libc::EINVAL)),
    }
    next.clear_unmaskable();
    Ok(Some(next))
}

pub(super) fn rt_sigprocmask(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    let previous = state.thread_signals.lock().blocked;
    match prospective_sigprocmask(memory, previous, args) {
        Ok(Some(next)) => state.thread_signals.lock().blocked = next,
        Ok(None) => {}
        Err(error) => return error,
    }
    if args[2] != 0 {
        return write_bytes(&mut ProviderMemory(memory), args[2], &previous.to_bytes());
    }
    0
}

// TODO-HUMAN-REVIEW(PR-543): Review shared/thread pending masks and bounded copyout.
pub(super) fn rt_sigpending(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    if args[1] > KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    if args[1] == 0 {
        return 0;
    }
    let process_signals = state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let generations = &process_signals.pending_generations;
    let mut pending = state
        .thread_signals
        .lock()
        .pending
        .pending_mask(generations);
    pending.union_with(process_signals.shared_pending.pending_mask(generations));
    // Linux reports only signals that are both pending and blocked.
    pending.intersect_with(state.thread_signals.lock().blocked);
    match memory
        .user()
        .copy_to_user(args[0], &pending.to_bytes()[..args[1] as usize])
    {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}

/// Effective action for a signal after honoring any handler installed through
/// `rt_sigaction`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignalDisposition {
    /// Default action terminates the process.
    Terminate,
    /// Signal is ignored (default or `SIG_IGN`).
    Ignore,
    /// Default action stops the process.
    Stop,
    /// A user handler is installed for deferred delivery at a user boundary.
    Handled,
}

/// Emulates `kill`/`tkill`/`tgkill` for the bounded virtual process tree and
/// explicitly refuses delivery that requires cross-process recipient fanout.
///
/// Supported standard signals directed to the current task are queued for the
/// backend's next return-to-user delivery boundary. This lets a Tool inspect,
/// replace, or suppress an event before its current disposition is applied.
/// Blocked signals remain pending. Ignored signals are queued long enough for
/// the Tool hook to observe them, then discarded at that return boundary; an
/// unchanged fatal default disposition terminates with the conventional
/// `128 + signo` status. Stopped-state scheduling, queued real-time siginfo,
/// and cross-process delivery remain unsupported. Same-process thread-directed
/// signals use the named receiver's private queue and return boundary.
// TODO-HUMAN-REVIEW(#95): Review self-signal termination and the default-disposition table.
pub(super) fn kill_signal(
    state: &mut LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> SyscallAction {
    let mut refusal = None;
    let action = send_signal(state, number, args, None, &mut refusal);
    state.signal_refusal = refusal;
    action
}

/// Why this backend refused a signal delivery (`kill`, `tkill`, `tgkill`,
/// `rt_sigqueueinfo`, `rt_tgsigqueueinfo`). Each is the diagnostic of the
/// typed refusal `UnsupportedOperation::Signal`; the refused call queued
/// nothing and changed no signal state.
pub(super) struct SignalRefusal;

impl SignalRefusal {
    pub(super) const OTHER_PROCESS: &'static str =
        "KVM signal delivery refused: KVM cannot deliver a signal to another process";
    const GROUP: &'static str = "KVM signal delivery refused: KVM cannot deliver a signal to \
         a process group with other members";
    pub(super) const ALL: &'static str =
        "KVM signal delivery refused: KVM cannot deliver kill(-1) to other processes";
    const INIT: &'static str = "KVM signal delivery refused: KVM cannot deliver a signal to \
         the synthesized namespace init";
    pub(super) const REALTIME_OR_SIGCHLD: &'static str =
        "KVM signal delivery refused: KVM cannot send real-time signals or SIGCHLD";
    pub(super) const STOP: &'static str =
        "KVM signal delivery refused: KVM cannot send a stop signal";
    pub(super) const THREADED_PROCESS: &'static str = "KVM signal delivery refused: KVM cannot \
         choose the recipient of a process-directed signal in a process with several threads";
    const SIGKILL_SIBLING: &'static str =
        "KVM signal delivery refused: KVM cannot send SIGKILL to a sibling thread";
    const SIBLING_UNAVAILABLE: &'static str = "KVM signal delivery refused: KVM cannot reach \
         the target thread's signal state";
    const EXIT_STATUS: &'static str = "KVM signal delivery refused: KVM cannot represent this \
         signal's terminating status";
}

/// Whether the Tool selects the thread that takes a signal a guest sends to
/// another process, or to its own process while that has another thread
/// (`ProcessSignalRegistry::cross_process_signals`).
fn cross_process_signals(state: &LoadedStaticElf) -> bool {
    state
        .children
        .registry()
        .is_some_and(|registry| registry.cross_process_signals())
}

/// Refuses a signal delivery with ENOSYS, recording why. Linux's signal
/// syscalls never fail with ENOSYS, so the executor reports every such answer
/// as the typed refusal `UnsupportedOperation::Signal` (see
/// `signal_refusal_record`).
fn refuse_signal(refusal: &mut Option<&'static str>, reason: &'static str) -> SyscallAction {
    *refusal = Some(reason);
    continue_with(negative_errno(libc::ENOSYS))
}

/// The size of Linux's `kernel_siginfo`: the part of a caller's `siginfo_t`
/// that `rt_sigqueueinfo` copies in. The rest of the 128-byte record is
/// delivered as zeros.
pub(super) const KERNEL_SIGINFO_SIZE: usize = 48;

// TODO-HUMAN-REVIEW(PR-1018): Review caller-supplied siginfo delivery.
/// Emulates `rt_sigqueueinfo` and `rt_tgsigqueueinfo` on the `kill` and
/// `tgkill` delivery path, carrying the caller's `siginfo_t` instead of the
/// record those calls build. Linux's own checks come first, in its order
/// (`kernel/signal.c`): the record is copied in (`EFAULT`) and its `si_signo`
/// set to the signal argument; `rt_tgsigqueueinfo` needs positive ids
/// (`EINVAL`); and a caller may supply a kernel or `tkill` code
/// (`si_code >= 0` or `SI_TKILL`) only when the id it names is its own tid
/// (`EPERM`). Every delivery `kill_signal` refuses (another process,
/// real-time queues, `SIGCHLD`, stop signals) stays refused.
pub(super) fn sigqueueinfo(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> SyscallAction {
    let thread_directed = number == libc::SYS_rt_tgsigqueueinfo as u64;
    let (signal_argument, info_address) = if thread_directed {
        (args[2], args[3])
    } else {
        (args[1], args[2])
    };
    let copied =
        match read_guest_bytes::<KERNEL_SIGINFO_SIZE>(&ProviderMemory(memory), info_address) {
            Ok(copied) => copied,
            Err(error) => return continue_with(error),
        };
    let mut info = [0; SIGINFO_SIZE];
    info[..KERNEL_SIGINFO_SIZE].copy_from_slice(&copied);
    // The kernel stores the int signal argument over the caller's si_signo.
    info[0..4].copy_from_slice(&(signal_argument as i32).to_ne_bytes());
    let named = if thread_directed {
        let (tgid, tid) = (args[0] as libc::pid_t, args[1] as libc::pid_t);
        if tgid <= 0 || tid <= 0 {
            return continue_with(negative_errno(libc::EINVAL));
        }
        tid
    } else {
        // kill_proc_info looks the pid up as a single process: zero and the
        // negative group forms of kill(2) name nothing here.
        let pid = args[0] as libc::pid_t;
        if pid <= 0 {
            return continue_with(negative_errno(libc::ESRCH));
        }
        pid
    };
    let code = i32::from_ne_bytes(info[8..12].try_into().expect("siginfo code"));
    if (code >= 0 || code == libc::SI_TKILL) && named != state.tid {
        return continue_with(negative_errno(libc::EPERM));
    }
    let (number, args) = if thread_directed {
        (
            libc::SYS_tgkill as u64,
            [args[0], args[1], args[2], 0, 0, 0],
        )
    } else {
        (libc::SYS_kill as u64, [args[0], args[1], 0, 0, 0, 0])
    };
    let mut refusal = None;
    let action = send_signal(state, number, &args, Some(info), &mut refusal);
    state.signal_refusal = refusal;
    action
}

/// `kill_signal`, delivering `info` when given instead of the record `kill`
/// or `tgkill` builds.
fn send_signal(
    state: &mut LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
    info: Option<[u8; SIGINFO_SIZE]>,
    refusal: &mut Option<&'static str>,
) -> SyscallAction {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    let is_kill = number == libc::SYS_kill as u64;
    let is_tgkill = number == libc::SYS_tgkill as u64;

    // ⚠️ DECODE THROUGH SIGNED `pid_t`, NOT `as i64`. The guest passes ids in
    // 64-bit registers but they are 32-bit `pid_t`. A guest that put -1 in a
    // 32-bit register delivers 0x00000000_FFFFFFFF here; widening that to i64
    // yields 4294967295, which is neither -1 nor any live id, so it would fall
    // through the id checks as an ordinary foreign positive. Truncating to
    // `pid_t` reproduces the kernel's own read of the register.
    let (tgid, target, raw_signal) = if is_tgkill {
        (
            Some(args[0] as libc::pid_t),
            args[1] as libc::pid_t,
            args[2],
        )
    } else {
        (None, args[0] as libc::pid_t, args[1])
    };

    let Ok(signal) = libc::c_int::try_from(raw_signal) else {
        return continue_with(negative_errno(libc::EINVAL));
    };
    if !(0..=64).contains(&signal) {
        return continue_with(negative_errno(libc::EINVAL));
    }

    if !is_kill {
        return send_thread_signal(state, tgid, target, signal, info, refusal);
    }

    let targets_self = {
        let (processes, synthesized_init, named_process) = {
            let lifecycle = state
                .task_lifecycle
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let processes: Vec<(i32, i32)> = lifecycle.processes().collect();
            // kill_pid_info_type finds a positive id as any live task's and
            // signals that task's thread group, so a thread's id that is not
            // its process's names its process.
            let named_process = lifecycle.get(target).map(|task| task.tgid);
            (
                processes,
                lifecycle.synthesizes_namespace_init(),
                named_process,
            )
        };
        match target {
            // Process groups are distinct from thread groups. A fork inherits
            // its parent's PGID, so group delivery is supported only when the
            // selected group contains exactly this one process. Refuse a
            // multi-process fanout before mutating any pending set.
            0 => {
                let members: Vec<i32> = processes
                    .iter()
                    .filter_map(|&(tgid, pgid)| (pgid == state.pgid).then_some(tgid))
                    .collect();
                if members.is_empty() {
                    return continue_with(negative_errno(libc::ESRCH));
                }
                if signal == 0 {
                    return continue_with(0);
                }
                if members.as_slice() != [state.pid] {
                    return refuse_signal(refusal, SignalRefusal::GROUP);
                }
                true
            }
            -1 => {
                // Linux kill(-1) excludes both the caller and PID 1. The
                // remaining cross-process fanout is deliberately unsupported.
                let eligible = processes
                    .iter()
                    .filter(|(tgid, _)| *tgid != state.pid && *tgid != 1)
                    .count();
                if eligible == 0 {
                    return continue_with(negative_errno(libc::ESRCH));
                }
                return if signal == 0 {
                    continue_with(0)
                } else {
                    refuse_signal(refusal, SignalRefusal::ALL)
                };
            }
            target if target < -1 => {
                let Some(group) = target.checked_abs() else {
                    return continue_with(negative_errno(libc::ESRCH));
                };
                let members: Vec<i32> = processes
                    .iter()
                    .filter_map(|&(tgid, pgid)| (pgid == group).then_some(tgid))
                    .collect();
                if members.is_empty() {
                    return continue_with(negative_errno(libc::ESRCH));
                }
                if signal == 0 {
                    return continue_with(0);
                }
                if members.as_slice() != [state.pid] {
                    return refuse_signal(refusal, SignalRefusal::GROUP);
                }
                true
            }
            _ if target == state.pid => true,
            // A root guest that is not PID 1 is parented to the synthesized
            // namespace init (`getppid() == 1`), so a liveness probe must find
            // that init. Delivering a signal to it is not modeled.
            crate::elf::CONTAINER_INIT_PID if synthesized_init => {
                return if signal == 0 {
                    continue_with(0)
                } else {
                    refuse_signal(refusal, SignalRefusal::INIT)
                };
            }
            // A live process's id, even once its leader has exited, or a
            // live thread's id, which names that thread's process.
            _ => match processes
                .iter()
                .any(|(tgid, _)| *tgid == target)
                .then_some(target)
                .or(named_process)
            {
                None => return continue_with(negative_errno(libc::ESRCH)),
                Some(tgid) if tgid == state.pid => true,
                Some(_) => {
                    return if signal == 0 {
                        continue_with(0)
                    } else {
                        refuse_signal(refusal, SignalRefusal::OTHER_PROCESS)
                    };
                }
            },
        }
    };
    if !targets_self {
        return continue_with(negative_errno(libc::ESRCH));
    }

    // Signal 0 is a permission/liveness probe that delivers nothing.
    if signal == 0 {
        return continue_with(0);
    }

    // These producer classes require state this first foundation does not yet
    // model. Reject them before mask/disposition handling so a blocked or
    // ignored action cannot turn an unsupported delivery into false success.
    // SIGPIPE is an ordinary signal here, as a broken-pipe write raises it
    // (`raise_guest_sigpipe`).
    if signal > 31 || signal == libc::SIGCHLD {
        return refuse_signal(refusal, SignalRefusal::REALTIME_OR_SIGCHLD);
    }

    // SIGKILL can never be caught, blocked, or ignored.
    if signal == libc::SIGKILL {
        return terminating_signal_status(signal, process_dumpable(state))
            .map(SyscallAction::Exit)
            .unwrap_or_else(|| refuse_signal(refusal, SignalRefusal::EXIT_STATUS));
    }

    match signal_disposition(state, signal) {
        SignalDisposition::Stop => return refuse_signal(refusal, SignalRefusal::STOP),
        SignalDisposition::Ignore | SignalDisposition::Terminate | SignalDisposition::Handled => {}
    }

    // A process-directed signal has no preselected recipient. With more than
    // one live thread, letting whichever host vCPU reaches a boundary first
    // take the shared event would make delivery depend on host scheduling.
    // A Tool that asked for signals to other processes selects that thread
    // (`cross_process_signals`): only a thread it permits takes the event, at
    // its own boundary. Without one, this fails visibly.
    if is_kill
        && !cross_process_signals(state)
        && state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .has_live_sibling(state.tid, state.pid)
    {
        return refuse_signal(refusal, SignalRefusal::THREADED_PROCESS);
    }

    // Queue even an unblocked default-fatal signal. The same return boundary
    // immediately applies its disposition in the plain loop, while the Tool
    // loop first gets exactly one structured hook invocation (as ptrace does
    // at a signal-delivery stop). A blocked event simply remains pending.
    let event = match (info, is_kill) {
        (Some(info), true) => reverie::SignalEvent::new(
            signal,
            info,
            reverie::SignalTarget::Process {
                pid: reverie::Pid::from_raw(state.pid),
            },
        ),
        (None, true) => event_for_process(signal, state.pid),
        (_, false) => event_for_thread(signal, state.pid, state.tid),
    };
    let event = match event {
        Ok(event) => event,
        Err(errno) => return continue_with(negative_errno(errno.into_raw())),
    };
    // prepare_signal's queue effects come before the signal is queued,
    // whatever its action (a default stop was refused above).
    if let Err(error) = flush_for_own_process(state, signal) {
        return continue_with(error);
    }
    match queue_signal_event_locked(state, event, is_kill) {
        Ok(()) => continue_with(0),
        Err(error) => continue_with(error),
    }
}

/// A thread-directed signal is published into the named receiver's one private
/// queue. The lifecycle lock binds publication to the live task incarnation;
/// process dispositions and the receiver mask are then inspected in that order.
pub(super) fn send_thread_signal(
    state: &LoadedStaticElf,
    tgid: Option<libc::pid_t>,
    target: libc::pid_t,
    signal: libc::c_int,
    info: Option<[u8; SIGINFO_SIZE]>,
    refusal: &mut Option<&'static str>,
) -> SyscallAction {
    if target <= 0 || tgid.is_some_and(|tgid| tgid <= 0) {
        return continue_with(negative_errno(libc::EINVAL));
    }
    let (action, flushed) = {
        let lifecycle = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if signal == 0 {
            return continue_with(if lifecycle.signal_zero_task_exists(target, tgid) {
                0
            } else {
                negative_errno(libc::ESRCH)
            });
        }
        let Some(task) = lifecycle.get(target) else {
            return continue_with(negative_errno(libc::ESRCH));
        };
        if tgid.is_some_and(|tgid| tgid != task.tgid) {
            return continue_with(negative_errno(libc::ESRCH));
        }
        if task.tgid != state.pid {
            return refuse_signal(refusal, SignalRefusal::OTHER_PROCESS);
        }
        if signal > 31 || signal == libc::SIGCHLD {
            return refuse_signal(refusal, SignalRefusal::REALTIME_OR_SIGCHLD);
        }
        if signal == libc::SIGKILL {
            // A sibling may be parked outside any return boundary. Queuing
            // SIGKILL there would falsely promise actual group cancellation.
            if target != state.tid {
                return refuse_signal(refusal, SignalRefusal::SIGKILL_SIBLING);
            }
            return terminating_signal_status(signal, task.dumpable)
                .map(SyscallAction::Exit)
                .unwrap_or_else(|| refuse_signal(refusal, SignalRefusal::EXIT_STATUS));
        }
        let target_signals = if target == state.tid {
            // Loader-level self-signal callers need no borrowed sibling handle.
            state.thread_signals.clone()
        } else {
            let Some(target_signals) = lifecycle.signal_target(target) else {
                return refuse_signal(refusal, SignalRefusal::SIBLING_UNAVAILABLE);
            };
            target_signals
        };
        let mut process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let disposition = signal_disposition_with_action(
            process_signals.dispositions.get(&signal).copied(),
            signal,
        );
        if disposition == SignalDisposition::Stop {
            return refuse_signal(refusal, SignalRefusal::STOP);
        }
        let event = match info {
            Some(info) => reverie::SignalEvent::new(
                signal,
                info,
                reverie::SignalTarget::Thread {
                    pid: reverie::Pid::from_raw(state.pid),
                    tid: reverie::Pid::from_raw(target),
                },
            ),
            None => event_for_thread(signal, state.pid, target),
        };
        let event = match event {
            Ok(event) => event,
            Err(errno) => return continue_with(negative_errno(errno.into_raw())),
        };
        // prepare_signal's queue effects come before the test of the
        // signal's action.
        let process = reverie::SignalProcessId {
            tgid: reverie::Pid::from_raw(task.tgid),
            generation: task.process_generation,
        };
        let flushed = flush_for_generation(&lifecycle, process, &mut process_signals, signal);
        (
            queue_thread_signal(&process_signals, &target_signals, event, disposition),
            flushed,
        )
    };
    match refresh_signalfd_keepers(state, &flushed) {
        Ok(()) => action,
        Err(error) => continue_with(error),
    }
}

/// Queues `event`, a thread-directed signal whose action is `disposition`,
/// on `target`'s own queue, where Linux's `__send_signal_locked` queues it,
/// unless that discards it at the send: an ignored signal the thread does
/// not block, where no Tool observes ignored signals. Wakes a wait of the
/// thread's for a signalfd that covers the signal. The caller holds the
/// target process's transaction and its signal lock, `process_signals`.
fn queue_thread_signal(
    process_signals: &crate::signal::ProcessSignalState,
    target: &crate::signal::SharedThreadSignalState,
    event: reverie::SignalEvent,
    disposition: SignalDisposition,
) -> SyscallAction {
    let signal = event.signal();
    let mut target = target.lock();
    if disposition == SignalDisposition::Ignore
        && !target.blocked.contains(signal)
        && !target.observe_ignored
    {
        return continue_with(0);
    }
    if let Err(errno) = target
        .pending
        .enqueue(event, process_signals.pending_generation(signal))
    {
        return continue_with(negative_errno(errno.into_raw()));
    }
    // A signalfd's eventfd keeper shows only the shared queue. A receiver
    // waiting in a host poll for a signalfd that covers this signal is woken
    // here, under the lock it registered its wait with.
    if let Some(waiter) = &target.signalfd_waiter
        && let Err(error) = waiter.wake_for(signal)
    {
        return continue_with(io_error(error));
    }
    continue_with(0)
}

/// The stop signals, whose default action stops the process
/// (`SIG_KERNEL_STOP_MASK`).
const STOP_SIGNALS: [libc::c_int; 4] = [libc::SIGSTOP, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

/// Linux's `prepare_signal` queue effects of generating `signal` for
/// `process`
/// (<https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c#L884-L900>):
/// a stop signal removes SIGCONT from the process's shared queue and from
/// each of its threads' own queues, and SIGCONT removes every stop signal
/// from them, whatever any action is. Returns the signals it removed from
/// the shared queue, whose signalfd keepers must be refreshed
/// ([`refresh_signalfd_keepers`]).
///
/// The caller holds the process's transaction, then `lifecycle` and the
/// process's signal state, `process_signals`; each thread's own lock is
/// taken in turn after them.
pub(crate) fn flush_for_generation(
    lifecycle: &crate::elf::TaskLifecycleTable,
    process: reverie::SignalProcessId,
    process_signals: &mut crate::signal::ProcessSignalState,
    signal: libc::c_int,
) -> Vec<libc::c_int> {
    let flushed: &[libc::c_int] = if STOP_SIGNALS.contains(&signal) {
        &[libc::SIGCONT]
    } else if signal == libc::SIGCONT {
        &STOP_SIGNALS
    } else {
        return Vec::new();
    };
    let removed = flushed
        .iter()
        .copied()
        .filter(|&flushed| process_signals.shared_pending.remove(flushed).is_some())
        .collect();
    for task in lifecycle.signal_process_tasks(process) {
        if let Some(thread) = lifecycle.signal_target(task.tid.as_raw()) {
            let mut thread = thread.lock();
            for &flushed in flushed {
                thread.pending.remove(flushed);
            }
        }
    }
    removed
}

/// [`flush_for_generation`] for a signal the caller sends to its own process,
/// then the refresh of the signalfd keepers it changed. The caller holds its
/// process's transaction.
fn flush_for_own_process(state: &LoadedStaticElf, signal: libc::c_int) -> Result<(), i64> {
    let flushed = {
        let lifecycle = state
            .task_lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(generation) = lifecycle.live_process_generation(state.pid) else {
            return Ok(());
        };
        let process = reverie::SignalProcessId {
            tgid: reverie::Pid::from_raw(state.pid),
            generation,
        };
        let mut process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        flush_for_generation(&lifecycle, process, &mut process_signals, signal)
    };
    refresh_signalfd_keepers(state, &flushed)
}

/// Refreshes the keepers of the caller's process's signalfds that cover a
/// signal in `changed`, which left its shared queue. The caller holds its
/// process's transaction and none of its signal locks.
fn refresh_signalfd_keepers(state: &LoadedStaticElf, changed: &[libc::c_int]) -> Result<(), i64> {
    for &signal in changed {
        refresh_signalfd_readiness_from_carriers_locked(state, Some(signal))?;
    }
    Ok(())
}

pub(super) fn process_dumpable(state: &LoadedStaticElf) -> bool {
    state
        .task_lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(state.tid)
        .map_or(state.dumpable, |task| task.dumpable)
}

/// The status of a death by `signal`, whose core flag says whether Linux
/// would write a core for it (`crate::core_dump::guest_writes_core`).
fn terminating_signal_status(signal: libc::c_int, dumpable: bool) -> Option<ExitStatus> {
    let signal_kind = Signal::try_from(signal).ok()?;
    let core_dumped = crate::core_dump::guest_writes_core(signal, dumpable);
    Some(ExitStatus::Signaled(signal_kind, core_dumped))
}

/// Resolves the effective disposition of `signal`, honoring any installed
/// handler before falling back to the kernel default action.
pub(super) fn installed_signal_action(
    state: &LoadedStaticElf,
    signal: libc::c_int,
) -> Option<KernelSigaction> {
    state
        .process_signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .dispositions
        .get(&signal)
        .copied()
}

pub(super) fn signal_disposition(
    state: &LoadedStaticElf,
    signal: libc::c_int,
) -> SignalDisposition {
    signal_disposition_with_action(installed_signal_action(state, signal), signal)
}

pub(crate) fn signal_disposition_with_action(
    action: Option<KernelSigaction>,
    signal: libc::c_int,
) -> SignalDisposition {
    if let Some(action) = action {
        const SIG_DFL: u64 = 0;
        const SIG_IGN: u64 = 1;
        match action.handler {
            SIG_DFL => {}
            SIG_IGN => return SignalDisposition::Ignore,
            _ => return SignalDisposition::Handled,
        }
    }
    default_signal_disposition(signal)
}

/// Linux discards a child's terminal wait status when the parent explicitly
/// ignores SIGCHLD or installs SA_NOCLDWAIT. The default SIGCHLD disposition is
/// also "ignore", but unlike an explicit SIG_IGN it still leaves a waitable
/// zombie, so inspect the installed action rather than the effective disposition.
pub(super) fn sigchld_auto_reaps(state: &LoadedStaticElf) -> bool {
    installed_signal_action(state, libc::SIGCHLD).is_some_and(|action| {
        action.handler == libc::SIG_IGN as u64 || action.flags & libc::SA_NOCLDWAIT as u64 != 0
    })
}

/// The kernel default action for `signal` when no handler is installed.
pub(super) fn default_signal_disposition(signal: libc::c_int) -> SignalDisposition {
    match signal {
        libc::SIGCHLD | libc::SIGURG | libc::SIGWINCH | libc::SIGCONT => SignalDisposition::Ignore,
        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => SignalDisposition::Stop,
        _ => SignalDisposition::Terminate,
    }
}

/// Reports whether `signal` is currently blocked by the guest's signal mask.
fn signal_is_blocked(state: &LoadedStaticElf, signal: libc::c_int) -> bool {
    state.thread_signals.lock().blocked.contains(signal)
}

/// The alternate stack a thread holds when it has none: Linux's initial and
/// reset state (`sas_ss_reset`), which `ThreadSignalState::altstack` stores as
/// `None`.
const DISABLED_ALTSTACK: GuestStack = GuestStack {
    sp: 0,
    flags: libc::SS_DISABLE,
    size: 0,
};

/// The stack a thread holds after asking for `requested`, as Linux's
/// `do_sigaltstack` (kernel/signal.c) decides it, in its order: EPERM while
/// `current_stack_pointer` runs on the current stack; EINVAL unless the mode,
/// the flags without SS_AUTODISARM, is 0, SS_ONSTACK or SS_DISABLE; no change
/// for a request equal to the stack held; for SS_DISABLE, no address and size
/// and the flags as given; otherwise ENOMEM below MINSIGSTKSZ bytes, else the
/// request as given, flags included.
fn validate_altstack_update(
    current: Option<GuestStack>,
    current_stack_pointer: Option<u64>,
    requested: GuestStack,
) -> Result<Option<GuestStack>, i64> {
    if current.is_some_and(|stack| {
        current_stack_pointer.is_some_and(|stack_pointer| stack.contains(stack_pointer))
    }) {
        return Err(negative_errno(libc::EPERM));
    }
    let mode = requested.flags & !SS_AUTODISARM;
    if mode != 0 && mode != libc::SS_ONSTACK && mode != libc::SS_DISABLE {
        return Err(negative_errno(libc::EINVAL));
    }
    if requested == current.unwrap_or(DISABLED_ALTSTACK) {
        return Ok(current);
    }
    if mode == libc::SS_DISABLE {
        let disabled = GuestStack {
            sp: 0,
            size: 0,
            ..requested
        };
        return Ok((disabled != DISABLED_ALTSTACK).then_some(disabled));
    }
    if requested.size < libc::MINSIGSTKSZ as u64 {
        return Err(negative_errno(libc::ENOMEM));
    }
    Ok(Some(requested))
}

pub(super) fn sigaltstack(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    current_user_stack_pointer: Option<u64>,
    args: &[u64; 6],
) -> i64 {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    let requested = if args[0] == 0 {
        None
    } else {
        let stack = match read_guest_bytes::<24>(&ProviderMemory(memory), args[0]) {
            Ok(stack) => GuestStack::decode(stack),
            Err(error) => return error,
        };
        Some(stack)
    };
    let previous = state.thread_signals.lock().altstack;
    let on_stack = previous.is_some_and(|stack| {
        current_user_stack_pointer.is_some_and(|stack_pointer| stack.contains(stack_pointer))
    });
    if let Some(requested) = requested {
        state.thread_signals.lock().altstack =
            match validate_altstack_update(previous, current_user_stack_pointer, requested) {
                Ok(stack) => stack,
                Err(error) => return error,
            };
    }
    if args[1] != 0 {
        if let Some(mut previous) = previous {
            // As Linux's do_sigaltstack reports it: sas_ss_flags (SS_DISABLE
            // for a stack with no size, as exec or SS_DISABLE with
            // SS_AUTODISARM leaves one, SS_ONSTACK while the caller runs on
            // it) with the stored SS_AUTODISARM.
            let status = if previous.size == 0 {
                libc::SS_DISABLE
            } else if on_stack {
                libc::SS_ONSTACK
            } else {
                0
            };
            previous.flags = status | (previous.flags & SS_AUTODISARM);
            return write_bytes(&mut ProviderMemory(memory), args[1], &previous.encode());
        }
        return write_bytes(
            &mut ProviderMemory(memory),
            args[1],
            &DISABLED_ALTSTACK.encode(),
        );
    }
    0
}

/// Emulates `rt_sigtimedwait(set, info, timeout, sigsetsize)` for the guest.
///
/// Detcore converts every blockable syscall to its zero-timeout non-blocking
/// form before injecting it and then drives blocking and timeout resolution
/// itself against the deterministic virtual clock. This handler is therefore a
/// pure, non-blocking poll of the guest kernel's pending-signal set: it consumes
/// the pending signal that Linux's `next_signal()` ordering selects (the
/// synchronous-number class first, then ascending numbers) and returns its
/// number, or reports `EAGAIN` when nothing matches (which detcore reads as
/// "would have blocked" and reschedules deterministically). Before this route
/// the executor fell through to `ENOSYS`, so a guest that called
/// `sigtimedwait` diverged from the golden ptrace backend (which returns
/// `EAGAIN` for an empty zero-timeout wait). Selection within each pending
/// domain is deterministic.
// TODO-HUMAN-REVIEW(rrnewton/reverie#315): Review virtual rt_sigtimedwait dequeue semantics.
pub(super) fn rt_sigtimedwait(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    if args[3] != KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    let mut set = match read_guest_bytes::<KERNEL_SIGSET_SIZE>(&ProviderMemory(memory), args[0]) {
        Ok(set) => KernelSigset::from_bytes(set),
        Err(error) => return error,
    };
    set.clear_unmaskable();
    let event = match take_signal_event_locked(state, SignalSelection::TimedWait(set)) {
        Ok(pending) => pending.map(|pending| pending.event),
        Err(errno) => return -(i64::from(errno.into_raw())),
    };
    let Some(event) = event else {
        return negative_errno(libc::EAGAIN);
    };
    if let Err(error) = refresh_signalfd_readiness_for_signal_locked(state, Some(event.signal())) {
        return error;
    }
    // Preserve all event metadata rather than synthesizing a second siginfo.
    if args[1] != 0 {
        if !range_is_valid(
            &ProviderMemory(memory),
            args[1],
            reverie::SIGNAL_INFO_SIZE as u64,
        ) {
            return negative_errno(libc::EFAULT);
        }
        let info = event.siginfo();
        let written = write_bytes(&mut ProviderMemory(memory), args[1], &info);
        if written < 0 {
            return written;
        }
    }
    event.signal() as i64
}

/// What signal_boundary_emptiness found at a syscall-return signal boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalBoundaryEmptiness {
    /// The boundary may select a signal, fail, or change signal state.
    NotEmpty,
    /// signal_boundary_is_empty holds. `mask_saved` is whether a
    /// temporary-mask call left the thread's own mask saved for restoring.
    Empty { mask_saved: bool },
}

/// What a pending signal does to a call that waits under `mask` and ends
/// with `ERESTARTNOHAND` when a signal it does not block is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TemporaryMaskSignal {
    /// No pending signal is eligible under the mask.
    None,
    /// Every eligible pending signal is caught or fatal. Linux returns
    /// `ERESTARTNOHAND`, and the delivery at the return boundary makes that
    /// `EINTR` (a handler) or ends the process (a fatal default).
    Interrupts,
    /// An eligible pending signal would be discarded (ignored) or stop the
    /// process. Linux would then restart or stop the call, which this
    /// executor's scalar return cannot represent, so the caller refuses.
    Unrepresentable,
}

/// Classifies the pending signals eligible under `mask` without dequeuing
/// any. The caller holds `signal_transaction`. Lock order is process before
/// thread, as at the ordinary return-to-user boundary.
pub(super) fn temporary_mask_signal(
    state: &LoadedStaticElf,
    mask: KernelSigset,
) -> TemporaryMaskSignal {
    let mut eligible = {
        let process_signals = state
            .process_signals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generations = &process_signals.pending_generations;
        let thread_signals = state.thread_signals.lock();
        let mut eligible = thread_signals.pending.pending_mask(generations);
        eligible.union_with(process_signals.shared_pending.pending_mask(generations));
        eligible
    };
    eligible.remove_all(mask);
    let mut any = false;
    for signal in 1..=64 {
        if !eligible.contains(signal) {
            continue;
        }
        any = true;
        if matches!(
            signal_disposition(state, signal),
            SignalDisposition::Ignore | SignalDisposition::Stop
        ) {
            return TemporaryMaskSignal::Unrepresentable;
        }
    }
    if any {
        TemporaryMaskSignal::Interrupts
    } else {
        TemporaryMaskSignal::None
    }
}

/// Installs `mask` as the thread's mask for a delivery at the coming return
/// boundary and saves the thread's own mask for the signal frame (Linux's
/// `set_restore_sigmask`). The caller holds `signal_transaction`.
pub(super) fn install_temporary_mask_for_delivery(state: &LoadedStaticElf, mut mask: KernelSigset) {
    mask.clear_unmaskable();
    let mut thread_signals = state.thread_signals.lock();
    if thread_signals.saved_sigmask.is_none() {
        thread_signals.saved_sigmask = Some(thread_signals.blocked);
    }
    thread_signals.blocked = mask;
}

/// Emulates `rt_sigsuspend(mask, sigsetsize)` when a pending signal already
/// ends it.
///
/// Linux installs the temporary mask, sleeps until a signal it does not block
/// is pending, and returns `ERESTARTNOHAND` with the thread's own mask saved;
/// the delivery as the call returns runs the handler under the temporary mask
/// (widened by the action), returns `EINTR` to the caller, and the frame's
/// saved mask makes `rt_sigreturn` restore the thread's own mask. Detcore
/// reads the temporary mask in the caller's turn and passes a private copy of
/// it here. When it finds a signal the copy does not block already pending,
/// this returns `EINTR` with the temporary mask installed and the own mask
/// saved, so the return boundary delivers that signal exactly as Linux does.
/// A wait for a signal that is not yet pending needs the scheduler to readmit
/// the waiter when a signal arrives, which it does not model on this backend,
/// so that form stays refused (ENOSYS) rather than parking the vCPU outside
/// the schedule.
// TODO-HUMAN-REVIEW(PR-1014)
pub(super) fn rt_sigsuspend(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[1] != KERNEL_SIGSET_SIZE as u64 {
        return negative_errno(libc::EINVAL);
    }
    let mask = match read_guest_bytes::<KERNEL_SIGSET_SIZE>(&ProviderMemory(memory), args[0]) {
        Ok(mask) => KernelSigset::from_bytes(mask),
        Err(error) => return error,
    };
    let transaction = state.signal_transaction.clone();
    let _transaction = transaction.lock().unwrap_or_else(|p| p.into_inner());
    let mut wait_mask = mask;
    wait_mask.clear_unmaskable();
    match temporary_mask_signal(state, wait_mask) {
        TemporaryMaskSignal::Interrupts => {
            install_temporary_mask_for_delivery(state, wait_mask);
            negative_errno(libc::EINTR)
        }
        TemporaryMaskSignal::None | TemporaryMaskSignal::Unrepresentable => {
            negative_errno(libc::ENOSYS)
        }
    }
}
