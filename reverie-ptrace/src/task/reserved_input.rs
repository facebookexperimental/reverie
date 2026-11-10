/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Native owned-stop mechanisms. Linux access policy belongs to the Tool.

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use reverie::reserved_input::*;

use super::*;

#[cfg(test)]
mod native_tests;

struct NativeInputExitObserver(std::sync::Weak<FatalSession>);

impl std::fmt::Debug for NativeInputExitObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeInputExitObserver")
    }
}

impl InputNativeExitObserver for NativeInputExitObserver {
    fn effects_complete(&self, task: InputTaskId) -> Result<bool, InputUnavailable> {
        let session = self
            .0
            .upgrade()
            .ok_or_else(|| InputUnavailable::new("input-native-session-ended"))?;
        let terminal = session
            .input_generations
            .lock()
            .unwrap()
            .iter()
            .find(|(_, owner)| *owner == task)
            .map(|(terminal, _)| terminal.clone())
            .ok_or_else(|| InputUnavailable::new("input-native-generation-not-retained"))?;
        let complete = terminal.exit_effects_complete().map_err(|error| {
            InputUnavailable::new(format!("input-native-exit-observation:{error}"))
        })?;
        if complete {
            session
                .complete_native_effects(&terminal)
                .map_err(|error| {
                    InputUnavailable::new(format!("input-native-effects-observer:{error}"))
                })?;
        }
        Ok(complete)
    }
}

/// The physical request's local carrier. Preparatory injections use a distinct
/// provider without this value; cancellation leaves its registry entry owned.
pub(super) struct NativeInputCall {
    receipt: PhysicalInjectionReceipt,
    pub(super) image: Option<ReservedInputImage>,
    unavailable: StdMutex<Option<InputUnavailable>>,
}

impl NativeInputCall {
    pub(super) fn id(&self) -> PhysicalInjectionId {
        self.receipt.id()
    }
    pub(super) fn control(&self) -> &ReservedInputControl {
        self.receipt.control()
    }

    /// Read only for backend preparation, never for a Tool's ordinary memory
    /// view. Whole words outside B retain the stopped transport's behavior.
    pub(super) fn preparation_word(&self, task: &Stopped, address: usize) -> Option<u64> {
        let pointer = Addr::<u64>::from_raw(address)?;
        let Some(image) = &self.image else {
            return task.read_value(pointer).ok();
        };
        let mut bytes = [0; 8];
        if image.read(address as u64, &mut bytes) {
            return Some(u64::from_ne_bytes(bytes));
        }
        bytes = task.read_value::<_, u64>(pointer).ok()?.to_ne_bytes();
        for (offset, byte) in bytes.iter_mut().enumerate() {
            let at = (address as u64).checked_add(offset as u64)?;
            let mut future_byte = [0];
            if image.read(at, &mut future_byte) {
                *byte = future_byte[0];
            }
        }
        Some(u64::from_ne_bytes(bytes))
    }

    pub(super) fn future_flags(&self, nr: Sysno, args: &SyscallArgs) -> Option<u64> {
        if nr == Sysno::clone {
            return Some(args.arg0 as u64);
        }
        if nr != Sysno::clone3 {
            return None;
        }
        let mut bytes = [0; 8];
        if let Some(image) = &self.image {
            return image
                .read(args.arg0 as u64, &mut bytes)
                .then(|| u64::from_ne_bytes(bytes));
        }
        match self.control().backend_description(self.id())?.input {
            InputCallInput::Immutable { address, bytes } if address == args.arg0 as u64 => bytes
                .get(..8)
                .map(|v| u64::from_ne_bytes(v.try_into().unwrap())),
            _ => None,
        }
    }
}

fn native_error(operation: &'static str) -> InputNativeError {
    InputNativeError {
        operation,
        errno: std::io::Error::last_os_error().raw_os_error(),
    }
}

fn io_error(operation: &'static str, error: std::io::Error) -> InputNativeError {
    InputNativeError {
        operation,
        errno: error.raw_os_error(),
    }
}

fn native_limit(
    tid: i32,
    resource: libc::__rlimit_resource_t,
) -> Result<InputNativeLimit, InputNativeError> {
    let mut limits = libc::rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Read-only; no limit is ever cleared or raised by the observer.
    if unsafe { libc::prlimit64(tid, resource, std::ptr::null(), &mut limits) } == -1 {
        return Err(native_error("prlimit64"));
    }
    Ok(InputNativeLimit {
        current: limits.rlim_cur,
        maximum: limits.rlim_max,
    })
}

fn inode(path: &str) -> Result<(u64, u64), InputNativeError> {
    std::fs::metadata(path)
        .map(|stat| (stat.dev(), stat.ino()))
        .map_err(|error| io_error("stat", error))
}

#[repr(C)]
#[derive(Default)]
struct NativeOwner {
    kind: i32,
    pid: i32,
}

// Linux UAPI asm-generic/fcntl.h, used by both supported x86_64 and
// aarch64 ABIs: F_GETSIG=11 and F_GETOWN_EX=16. libc does not expose these
// constants on every supported target. F_GETOWN cannot substitute for
// F_GETOWN_EX: it loses the stored PID/TID/process-group owner kind.
const NATIVE_F_GETSIG: libc::c_int = 11;
const NATIVE_F_GETOWN_EX: libc::c_int = 16;

fn fcntl_value(fd: i32, command: i32, name: &'static str) -> Result<i32, InputNativeError> {
    let result = unsafe { libc::fcntl(fd, command) };
    if result == -1 {
        Err(native_error(name))
    } else {
        Ok(result)
    }
}

fn descriptor_facts(
    tid: i32,
    pidfd: &OwnedFd,
    fd: i32,
) -> Result<PinnedInputDescriptor, InputNativeError> {
    let pinned = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    if pinned < 0 {
        return Err(native_error("pidfd_getfd"));
    }
    // The pin is an actual duplicate, not an O_PATH reopen. Drop closes it before
    // the synchronous admission observer can return to a yielding callback.
    let pinned = unsafe { OwnedFd::from_raw_fd(pinned as i32) };
    let same = || {
        let result = unsafe {
            libc::syscall(
                libc::SYS_kcmp,
                tid,
                libc::getpid(),
                0,
                fd as libc::c_ulong,
                pinned.as_raw_fd() as libc::c_ulong,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(native_error("kcmp-file-pin"))
        }
    };
    same()?;
    let native = pinned.as_raw_fd();
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let identity = if unsafe { libc::fstat(native, &mut stat) } == -1 {
        Err(native_error("fstat"))
    } else {
        Ok((stat.st_dev, stat.st_ino, stat.st_mode))
    };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    let filesystem = if unsafe { libc::fstatfs(native, &mut fs) } == -1 {
        Err(native_error("fstatfs"))
    } else {
        Ok(fs.f_type as u64)
    };
    let mut owner = NativeOwner::default();
    let async_owner = if unsafe { libc::fcntl(native, NATIVE_F_GETOWN_EX, &mut owner) } == -1 {
        Err(native_error("F_GETOWN_EX"))
    } else {
        Ok((owner.kind, owner.pid))
    };
    let mut statx: libc::statx = unsafe { std::mem::zeroed() };
    let empty = CString::new("").unwrap();
    let mount_id = if unsafe {
        libc::statx(
            native,
            empty.as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut statx,
        )
    } == -1
    {
        Err(native_error("statx-mount-id"))
    } else if statx.stx_mask & libc::STATX_MNT_ID == 0 {
        Err(InputNativeError {
            operation: "statx-mount-id-missing",
            errno: None,
        })
    } else {
        Ok(statx.stx_mnt_id)
    };
    let path_context = (|| {
        Ok(InputPathContext {
            reader_mount_namespace: inode("/proc/self/ns/mnt")?,
            target_mount_namespace: inode(&format!("/proc/{tid}/ns/mnt"))?,
            reader_cgroup_namespace: inode("/proc/self/ns/cgroup")?,
            target_cgroup_namespace: inode(&format!("/proc/{tid}/ns/cgroup"))?,
            reader_root: inode("/proc/self/root")?,
            target_root: inode(&format!("/proc/{tid}/root"))?,
        })
    })();
    let facts = InputDescriptorFacts {
        fd,
        status_flags: fcntl_value(native, libc::F_GETFL, "F_GETFL"),
        async_signal: fcntl_value(native, NATIVE_F_GETSIG, "F_GETSIG"),
        async_owner,
        identity,
        filesystem,
        mount_id,
        path_context,
        proc_path: std::fs::read_link(format!("/proc/{tid}/fd/{fd}"))
            .map(|path| path.as_os_str().as_bytes().to_vec())
            .map_err(|error| io_error("procfd-readlink", error)),
    };
    same()?;
    Ok(PinnedInputDescriptor::from_native_parts(facts, pinned))
}

fn descriptors(tid: i32) -> Result<Vec<PinnedInputDescriptor>, InputNativeError> {
    // PIDFD_THREAD (O_EXCL) selects this exact task's table, including a
    // nonleader that unshared its files. Failure is uncertainty, not a fallback
    // to the group leader's potentially different descriptor table.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, libc::O_EXCL) };
    if pidfd < 0 {
        return Err(native_error("pidfd_open-thread"));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    let mut numbers = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{tid}/fd"))
        .map_err(|error| io_error("procfd-enumerate", error))?
    {
        let entry = entry.map_err(|error| io_error("procfd-entry", error))?;
        let fd = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or(InputNativeError {
                operation: "procfd-number",
                errno: None,
            })?;
        numbers.push(fd);
    }
    numbers.sort_unstable();
    numbers
        .into_iter()
        .map(|fd| descriptor_facts(tid, &pidfd, fd))
        .collect()
}

fn native_rseq(task: &Stopped) -> Result<InputNativeRseq, InputNativeError> {
    task.rseq_configuration()
        .map(|rseq| InputNativeRseq {
            address: rseq.address,
            length: rseq.length,
            signature: rseq.signature,
            flags: rseq.flags,
        })
        .map_err(|error| InputNativeError {
            operation: "PTRACE_GET_RSEQ_CONFIGURATION",
            errno: Some(error.into_raw()),
        })
}

fn native_facts(
    task: &Stopped,
    identity: InputTaskId,
    phase: InputImagePhase,
) -> Result<InputNativeFacts, TraceError> {
    task.getregs()?; // validates this retained stopped-generation authority
    let tid = task.pid().as_raw();
    let result = InputNativeFacts {
        phase,
        task: identity,
        cpu: native_limit(tid, libc::RLIMIT_CPU),
        realtime: native_limit(tid, libc::RLIMIT_RTTIME),
        rseq: native_rseq(task),
        descriptors: descriptors(tid),
        mountinfo: std::fs::read(format!("/proc/{tid}/mountinfo"))
            .map_err(|error| io_error("mountinfo", error)),
        mount_namespace: inode(&format!("/proc/{tid}/ns/mnt")),
        root: inode(&format!("/proc/{tid}/root")),
    };
    task.getregs()?; // a dead/replaced task cannot lend observations to a new one
    Ok(result)
}

/// Actual native address-space or descriptor-table sharing; None is uncertainty.
pub(super) fn kcmp_relation(parent: i32, child: i32, kind: i32) -> Option<bool> {
    let result = unsafe { libc::syscall(libc::SYS_kcmp, parent, child, kind, 0, 0) };
    if result < 0 { None } else { Some(result == 0) }
}

impl<L: Tool + 'static> TracedTask<L> {
    pub(super) fn input_control(&self) -> Option<ReservedInputControl> {
        self.global_state.fatal_session.reserved_input.clone()
    }

    pub(super) fn input_failure(&self, reason: impl std::fmt::Display) -> TraceError {
        let reason = reason.to_string();
        if let Some(control) = self.input_control() {
            control.backend_fail(reason.clone());
        }
        self.publish_ordinary_failure(
            "ptrace private input",
            reverie::Error::Tool(anyhow::anyhow!(reason)),
        );
        Errno::ECANCELED.into()
    }

    pub(super) async fn do_input_inject(
        &mut self,
        nr: Sysno,
        args: SyscallArgs,
        scope_image: Option<(&InputOperationScope, ReservedInputImage)>,
        receipt: PhysicalInjectionReceipt,
        operation: Option<reverie::native_syscall::NativeOperation>,
    ) -> Result<Result<i64, Errno>, InputInjectionError> {
        use reverie::provider::LinuxProvider;
        let task = self
            .reserved_input_task
            .ok_or_else(|| InputUnavailable::new("input-task-unavailable"))?;
        let request = host_linux::request(nr, args);
        let control = self
            .input_control()
            .ok_or_else(|| InputUnavailable::new("input-backend-unavailable"))?;
        control.backend_bind_injection(&receipt, task, nr as u64, *request.args())?;
        if let Some((scope, image)) = &scope_image
            && let Err(error) = control.backend_begin_preparation(&receipt, scope, image.clone())
        {
            control
                .backend_settled_not_run(receipt.id())
                .map_err(|fatal| {
                    InputInjectionError::Fatal(self.input_failure(fatal).to_string())
                })?;
            return Err(error.into());
        }
        let input = NativeInputCall {
            receipt,
            image: scope_image.map(|(_, image)| image),
            unavailable: StdMutex::new(None),
        };
        let context = NativeCallContext::with_input(input, operation);
        self.injected_syscalls += 1;
        let result = host_linux::HostLinux::<L>::with_input(&context)
            .execute(self.tid, &request, self)
            .await;
        if let Some(error) = context
            .input
            .as_ref()
            .unwrap()
            .unavailable
            .lock()
            .unwrap()
            .take()
        {
            return Err(error.into());
        }
        match result.and_then(host_linux::guest_result) {
            Ok(result) => Ok(result),
            Err(error) => {
                let failure = self.input_failure(error);
                Err(InputInjectionError::Fatal(failure.to_string()))
            }
        }
    }

    /// Final owned stop after preparation. This routine cannot await or call
    /// the Tool. A failed attempted write gets one complete same-image repair.
    pub(super) fn prepare_input_at_stop(
        &self,
        task: &mut Stopped,
        input: Option<&NativeCallContext>,
    ) -> Result<(), InputInjectionError> {
        let Some(input) = input.and_then(|context| context.input.as_ref()) else {
            return Ok(());
        };
        let control = input.control();
        if input.image.is_none() {
            return Ok(());
        }
        let image = control.backend_prepared_stopped(input.id())?;
        authenticate_mapping(task, image.layout())?;
        control.backend_initializing(input.id())?;
        let first = force_transaction_image(task, &image, false)
            .and_then(|()| read_transaction_image(task, image.layout(), false))
            .map_err(|error| InputUnavailable::new(format!("input-image-write:{error}")))
            .and_then(|bytes| control.backend_verified_image(input.id(), &bytes));
        if let Err(error) = first {
            control.backend_normalizing(input.id()).map_err(|error| {
                InputInjectionError::Fatal(self.input_failure(error).to_string())
            })?;
            let normalized = force_transaction_image(task, &image, true)
                .and_then(|()| read_transaction_image(task, image.layout(), true))
                .map_err(|error| InputUnavailable::new(format!("input-normalization:{error}")))
                .and_then(|bytes| control.backend_verified_image(input.id(), &bytes));
            if let Err(fatal) = normalized {
                return Err(InputInjectionError::Fatal(
                    self.input_failure(fatal).to_string(),
                ));
            }
            // The complete B is settled, but this failed attempt must not run.
            return Err(error.into());
        }
        Ok(())
    }

    pub(super) fn recover_input_not_run(
        &self,
        task: &Stopped,
        registers: libc::user_regs_struct,
        context: &NativeCallContext,
        error: InputInjectionError,
    ) -> TraceError {
        let input = context
            .input
            .as_ref()
            .expect("image recovery has an input receipt");
        match error {
            InputInjectionError::Unavailable(reason) => {
                if let Err(error) = self.native_result_at_stop(
                    task,
                    Some(context),
                    Err(Errno::ECANCELED),
                    false,
                    false,
                ) {
                    return error;
                }
                if let Err(error) = task.setregs(&registers) {
                    return self.input_failure(error);
                }
                if let Err(error) = input.control().backend_settled_not_run(input.id()) {
                    return self.input_failure(error);
                }
                *input.unavailable.lock().unwrap() = Some(reason);
                Errno::ECANCELED.into()
            }
            InputInjectionError::Fatal(reason) => self.input_failure(reason),
        }
    }

    pub(super) fn issue_input(&self, input: Option<&NativeCallContext>) -> Result<(), TraceError> {
        if let Some(input) = input.and_then(|context| context.input.as_ref()) {
            input
                .control()
                .backend_issued(input.id())
                .map_err(|e| self.input_failure(e))?;
        }
        Ok(())
    }

    pub(super) fn check_input_debug_write(
        &self,
        address: u64,
        length: usize,
    ) -> Result<(), TraceError> {
        super::gdb_stop::check_reserved_input_write(
            self.input_control().zip(self.reserved_input_task).as_ref(),
            address,
            length,
        )
    }

    pub(super) fn input_continuation(
        &self,
        input: Option<&NativeCallContext>,
    ) -> Result<(), TraceError> {
        if let (Some(control), Some(task)) = (self.input_control(), self.reserved_input_task) {
            control
                .backend_continuation(
                    task,
                    input
                        .and_then(|context| context.input.as_ref())
                        .map(NativeInputCall::id),
                )
                .map_err(|e| self.input_failure(e))?;
        }
        Ok(())
    }

    pub(super) fn input_result(
        &self,
        input: Option<&NativeCallContext>,
        result: &Result<i64, Errno>,
        ran: bool,
        seccomp_trapped: bool,
    ) -> Result<(), TraceError> {
        let Some(input) = input.and_then(|context| context.input.as_ref()) else {
            return Ok(());
        };
        let control = input.control();
        let observation = control
            .injection_observation(input.id())
            .ok_or_else(|| self.input_failure("input-call-missing"))?;
        if matches!(observation.state, PhysicalInjectionState::RetainedBirth(_)) {
            return Ok(());
        }
        let description = control
            .backend_description(input.id())
            .ok_or_else(|| self.input_failure("input-call-missing"))?;
        let settled = if !ran
            || seccomp_trapped
            || result.is_err()
            || !description.expected_sharing.may_create
        {
            control.backend_no_child(input.id())
        } else {
            control.backend_unknown_outcome(input.id())
        };
        settled.map_err(|e| self.input_failure(e))
    }

    pub(crate) fn initialize_reserved_input_root(
        &mut self,
        task: &Stopped,
    ) -> Result<(), TraceError> {
        let Some(control) = self.input_control() else {
            return Ok(());
        };
        control
            .backend_install_exit_observer(Arc::new(NativeInputExitObserver(Arc::downgrade(
                &self.global_state.fatal_session,
            ))))
            .map_err(|error| self.input_failure(error))?;
        let registered = control
            .backend_register_root(task.pid().as_raw(), self.pid.as_raw())
            .map_err(|error| self.input_failure(error))?;
        let registered = control
            .backend_bind_tool_identity(registered.task, self.tid().as_raw(), self.pid().as_raw())
            .map_err(|error| self.input_failure(error))?;
        self.reserved_input_task = Some(registered.task);
        self.global_state
            .fatal_session
            .bind_input_generation(task.generation().terminal_cleanup(), registered.task)?;
        self.global_state
            .gs_ref
            .on_reserved_input_task(registered)
            .map_err(|error| self.input_failure(error))?;
        // Capture before preinit: that existing routine may invoke signal/Tool callbacks.
        let facts = native_facts(
            task,
            registered.task,
            if self.command_bootstrap {
                InputImagePhase::LaunchBootstrap
            } else {
                InputImagePhase::Target
            },
        )?;
        self.reserved_input_initial = Some(
            self.global_state
                .gs_ref
                .admit_reserved_input_initial_state(&facts)
                .map_err(|error| self.input_failure(error))?,
        );
        Ok(())
    }

    /// Bind the actual replacement before the old owner can be retired. The
    /// native stop's generation is retained; only its input image incarnation
    /// changes. A later final wait therefore accounts for the replacement,
    /// while old input identities remain independently available to fences.
    pub(super) fn reserved_input_exec_transfer(
        &mut self,
        task: &Stopped,
        former: Option<InputTaskId>,
    ) -> Result<(), TraceError> {
        let (Some(control), Some(displaced)) = (self.input_control(), self.reserved_input_task)
        else {
            return Ok(());
        };
        let former = former.ok_or_else(|| self.input_failure("input-exec-former-not-retained"))?;
        let old_owners = self
            .fatal_session()
            .input_generations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, identity)| *identity == displaced || *identity == former)
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        for owner in old_owners {
            self.fatal_session()
                .complete_native_effects(&owner)
                .map_err(|error| self.input_failure(error))?;
        }
        let registered = control
            .backend_exec_replacement(displaced, former)
            .map_err(|error| self.input_failure(error))?;
        let registered = control
            .backend_bind_tool_identity(registered.task, self.tid().as_raw(), self.pid().as_raw())
            .map_err(|error| self.input_failure(error))?;
        self.fatal_session()
            .rebind_input_exec_generation(
                &task.generation().terminal_cleanup(),
                displaced,
                registered.task,
            )
            .map_err(|error| self.input_failure(error))?;
        self.reserved_input_task = Some(registered.task);
        self.reserved_input_exec_transferred = true;
        self.global_state
            .gs_ref
            .on_reserved_input_task(registered)
            .map_err(|error| self.input_failure(error))?;
        Ok(())
    }

    pub(super) fn reserved_input_exec_begin(&mut self, task: &Stopped) -> Result<(), TraceError> {
        let Some(identity) = self.reserved_input_task else {
            return Ok(());
        };
        let facts = native_facts(task, identity, InputImagePhase::Target)?;
        self.reserved_input_initial = Some(
            self.global_state
                .gs_ref
                .admit_reserved_input_initial_state(&facts)
                .map_err(|error| self.input_failure(error))?,
        );
        Ok(())
    }

    fn authenticate_native_fact_stop(&self, stop: &Stopped) -> Result<(), InputUnavailable> {
        let retained = self
            .preinit_generation
            .as_ref()
            .cloned()
            .or_else(|| self.ptracer_waits.generation());
        if stop.pid() != self.tid || retained.as_ref() != Some(&stop.generation()) {
            return Err(InputUnavailable::new(
                "native-facts-stop-generation-mismatch",
            ));
        }
        Ok(())
    }

    pub(super) fn inspect_input_descriptors(
        &self,
    ) -> Result<InputDescriptorSnapshot, InputUnavailable> {
        if self.reserved_input_task.is_none() || self.input_control().is_none() {
            return Err(InputUnavailable::new(
                "input-native-descriptors-unsupported",
            ));
        }
        self.inspect_input_descriptors_at(&self.assume_stopped())
    }

    pub(super) fn inspect_input_descriptors_at(
        &self,
        task: &Stopped,
    ) -> Result<InputDescriptorSnapshot, InputUnavailable> {
        self.authenticate_native_fact_stop(task)?;
        task.getregs()
            .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
        let entries = descriptors(self.tid.as_raw())
            .map_err(|e| InputUnavailable::new(format!("input-native-descriptors:{e:?}")))?;
        let mountinfo = std::fs::read(format!("/proc/{}/mountinfo", self.tid))
            .map_err(|e| io_error("mountinfo", e));
        task.getregs()
            .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
        Ok(InputDescriptorSnapshot {
            descriptors: entries,
            mountinfo,
        })
    }

    pub(super) fn inspect_process_exit_signal(&self) -> Result<i32, InputUnavailable> {
        let task = self.assume_stopped();
        task.getregs()
            .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
        let control = self
            .input_control()
            .ok_or_else(|| InputUnavailable::new("input-backend-unavailable"))?;
        let identity = self
            .reserved_input_task
            .ok_or_else(|| InputUnavailable::new("input-task-unavailable"))?;
        let registered = control
            .registration(identity)
            .ok_or_else(|| InputUnavailable::new("input-task-unavailable"))?;
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.tid))
            .map_err(|_| InputUnavailable::new("input-native-group-unavailable"))?;
        let group = status
            .lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .and_then(|v| v.trim().parse::<i32>().ok());
        if group != Some(registered.native_pid) {
            return Err(InputUnavailable::new("input-native-group-mismatch"));
        }
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", registered.native_pid))
            .map_err(|_| InputUnavailable::new("input-native-exit-signal-unavailable"))?;
        let value = stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(35))
            .and_then(|v| v.parse::<i32>().ok())
            .ok_or_else(|| InputUnavailable::new("input-native-exit-signal-unavailable"))?;
        task.getregs()
            .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
        Ok(value)
    }

    pub(super) fn input_cancelled(&self) -> Result<(), TraceError> {
        self.cancel_native_attempts()?;
        if let (Some(control), Some(task)) = (self.input_control(), self.reserved_input_task) {
            control
                .backend_cancel_injections(task)
                .map_err(|e| self.input_failure(e))?;
        }
        Ok(())
    }

    pub(super) fn input_terminal(&self) -> Result<(), TraceError> {
        self.cancel_native_attempts()?;
        if let Some(owner) = self.ptracer_waits.terminal_cleanup() {
            self.fatal_session()
                .complete_native_effects(&owner)
                .map_err(|error| self.input_failure(error))?;
        }
        if let (Some(control), Some(task)) = (self.input_control(), self.reserved_input_task) {
            control
                .backend_terminal(task)
                .map_err(|e| self.input_failure(e))?;
        }
        Ok(())
    }

    pub(super) fn inspect_reserved_input_descriptor(
        &self,
        fd: i32,
    ) -> Result<PinnedInputDescriptor, InputUnavailable> {
        if self.input_control().is_none() || self.reserved_input_task.is_none() {
            return Err(InputUnavailable::new("input-native-descriptor-unsupported"));
        }
        self.inspect_reserved_input_descriptor_at(&self.assume_stopped(), fd)
    }

    pub(super) fn inspect_reserved_input_descriptor_at(
        &self,
        stopped: &Stopped,
        fd: i32,
    ) -> Result<PinnedInputDescriptor, InputUnavailable> {
        self.authenticate_native_fact_stop(stopped)?;
        stopped
            .getregs()
            .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.tid.as_raw(), libc::O_EXCL) };
        if pidfd < 0 {
            return Err(InputUnavailable::new(format!(
                "input-pidfd-unavailable: {:?}",
                native_error("pidfd_open-thread")
            )));
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
        let facts = descriptor_facts(self.tid.as_raw(), &pidfd, fd).map_err(|error| {
            InputUnavailable::new(format!("input-descriptor-unproved: {error:?}"))
        })?;
        stopped
            .getregs()
            .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
        Ok(facts)
    }

    fn input_setup_observation(&self, outcome: InputSetupOutcome) -> Result<(), TraceError> {
        if let Some(task) = self.reserved_input_task {
            self.global_state
                .gs_ref
                .on_reserved_input_setup(InputSetupReceipt { task, outcome })
                .map_err(|error| self.input_failure(error))?;
        }
        Ok(())
    }

    pub(super) async fn setup_reserved_input(
        &mut self,
        mut task: Stopped,
    ) -> Result<Stopped, TraceError> {
        let (Some(control), Some(identity)) = (self.input_control(), self.reserved_input_task)
        else {
            return Ok(task);
        };
        if self.command_bootstrap {
            return Ok(task);
        }
        if let Some(InputAdmission::Unqualified(reason)) = self.reserved_input_initial.clone() {
            self.input_setup_observation(InputSetupOutcome::Unqualified(reason))?;
            return Ok(task);
        }
        if self.reserved_input_initial != Some(InputAdmission::Qualified) {
            self.input_setup_observation(InputSetupOutcome::Unqualified(InputUnavailable::new(
                "input-native-state-not-admitted",
            )))?;
            return Ok(task);
        }
        let page_bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let abi = if cfg!(target_arch = "x86_64") {
            InputAbi::X86_64
        } else {
            InputAbi::Aarch64
        };
        let layout = ReservedInputLayout {
            base: RESERVED_INPUT_BASE,
            page_bytes: page_bytes as usize,
            abi,
        };
        if let Err(reason) = layout.validate() {
            self.input_setup_observation(InputSetupOutcome::Unqualified(reason))?;
            return Ok(task);
        }
        let args = SyscallArgs::new(
            layout.base as usize,
            layout.page_bytes,
            libc::PROT_READ as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as usize,
            usize::MAX,
            0,
        );
        let (next, mapped) = self
            .untraced_syscall_unstepped(task, Sysno::mmap, args)
            .await?;
        task = next;
        if mapped != Ok(layout.base as i64) {
            // An old kernel may ignore NOREPLACE. Remove only the mapping this
            // exact call actually returned; never overwrite the requested range.
            if let Ok(address) = mapped {
                let args = SyscallArgs::new(address as usize, layout.page_bytes, 0, 0, 0, 0);
                let (next, result) = self
                    .untraced_syscall_unstepped(task, Sysno::munmap, args)
                    .await?;
                task = next;
                result.map_err(|error| self.input_failure(error))?;
            }
            self.input_setup_observation(InputSetupOutcome::Unqualified(InputUnavailable::new(
                "input-fixed-mapping-unavailable",
            )))?;
            return Ok(task);
        }
        // Prefault through the same bounded force transport used by transactions.
        // No application bytes or another reserved page are addressed.
        let zero =
            ReservedInputImage::new(layout, &[]).map_err(|error| self.input_failure(error))?;
        force_image(&mut task, &zero).map_err(|error| self.input_failure(error))?;
        let args = SyscallArgs::new(layout.base as usize, layout.page_bytes, 0, 0, 0, 0);
        let (next, sealed) = self
            .untraced_syscall_number_unstepped(task, SYS_MSEAL, args)
            .await?;
        task = next;
        if let Err(error) = sealed {
            let args = SyscallArgs::new(layout.base as usize, layout.page_bytes, 0, 0, 0, 0);
            let (next, unmapped) = self
                .untraced_syscall_unstepped(task, Sysno::munmap, args)
                .await?;
            task = next;
            unmapped.map_err(|error| self.input_failure(error))?;
            self.input_setup_observation(InputSetupOutcome::Unqualified(InputUnavailable::new(
                format!("input-mseal-unavailable: {error}"),
            )))?;
            return Ok(task);
        }
        authenticate_mapping(&task, layout).map_err(|error| self.input_failure(error))?;
        let readback = read_image(&task, layout).map_err(|error| self.input_failure(error))?;
        if readback != zero.bytes() {
            return Err(self.input_failure("input-initial-readback-mismatch"));
        }
        control
            .backend_set_layout(identity, layout)
            .map_err(|error| self.input_failure(error))?;
        #[cfg(test)]
        native_tests::debugger_requests(&mut task, &control, identity);
        self.input_setup_observation(InputSetupOutcome::Qualified(layout))?;
        Ok(task)
    }
}

fn authenticate_mapping(
    task: &Stopped,
    layout: ReservedInputLayout,
) -> Result<(), InputUnavailable> {
    task.getregs()
        .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", task.pid()))
        .map_err(|_| InputUnavailable::new("input-maps-unreadable"))?;
    let expected_end = layout.base + layout.page_bytes as u64;
    let mut found = false;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some((start, end)) = fields.first().and_then(|range| range.split_once('-')) else {
            return Err(InputUnavailable::new("input-maps-malformed"));
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            return Err(InputUnavailable::new("input-maps-malformed"));
        };
        if start < expected_end && end > layout.base {
            if start != layout.base
                || end != expected_end
                || fields.get(1) != Some(&"r--p")
                || fields.get(4) != Some(&"0")
                || fields.len() != 5
            {
                return Err(InputUnavailable::new("input-vma-mismatch"));
            }
            found = true;
        }
    }
    let smaps = std::fs::read_to_string(format!("/proc/{}/smaps", task.pid()))
        .map_err(|_| InputUnavailable::new("input-smaps-unreadable"))?;
    let header = format!("{:x}-{:x}", layout.base, expected_end);
    let mut ours = false;
    let mut sealed = false;
    for line in smaps.lines() {
        if line
            .split_whitespace()
            .next()
            .is_some_and(|first| first.contains('-'))
        {
            ours = line.split_whitespace().next() == Some(header.as_str());
        }
        if ours && line.starts_with("VmFlags:") {
            sealed = line.split_whitespace().any(|flag| flag == "sl");
        }
    }
    if !sealed {
        return Err(InputUnavailable::new("input-vma-not-sealed"));
    }
    task.getregs()
        .map_err(|_| InputUnavailable::new("input-stop-unavailable"))?;
    if found {
        Ok(())
    } else {
        Err(InputUnavailable::new("input-vma-missing"))
    }
}

fn force_image(task: &mut Stopped, image: &ReservedInputImage) -> Result<(), Errno> {
    force_words(task, image, |_, _| Ok(()))
}

/// The production transport is identical for first fill and normalization.
/// Tests may fail a real word request before or after its actual POKEDATA;
/// they never substitute a mock page or a successful write result.
fn force_transaction_image(
    task: &mut Stopped,
    image: &ReservedInputImage,
    _normalizing: bool,
) -> Result<(), Errno> {
    force_words(task, image, |index, after| {
        #[cfg(test)]
        native_tests::write_fault(index, after, _normalizing)?;
        #[cfg(not(test))]
        let _ = (index, after);
        Ok(())
    })
}

fn force_words(
    task: &mut Stopped,
    image: &ReservedInputImage,
    mut boundary: impl FnMut(usize, bool) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let layout = image.layout();
    for (index, word) in image.bytes().as_chunks::<8>().0.iter().enumerate() {
        let address = layout
            .base
            .checked_add((index * 8) as u64)
            .ok_or(Errno::EOVERFLOW)?;
        if address % 8 != 0 || !layout.contains(address, 8) {
            return Err(Errno::EFAULT);
        }
        let address = AddrMut::<u64>::from_raw(address as usize).ok_or(Errno::EFAULT)?;
        boundary(index, false)?;
        // An exact aligned word selects safeptrace's POKEDATA path, whose
        // stopped-generation/ptracer-thread checks wrap each native request.
        task.write_value(address, &u64::from_ne_bytes(*word))?;
        boundary(index, true)?;
    }
    Ok(())
}

fn read_transaction_image(
    task: &Stopped,
    layout: ReservedInputLayout,
    _normalizing: bool,
) -> Result<Vec<u8>, Errno> {
    let bytes = read_image(task, layout)?;
    #[cfg(test)]
    let bytes = native_tests::readback_fault(bytes, _normalizing);
    Ok(bytes)
}

fn read_image(task: &Stopped, layout: ReservedInputLayout) -> Result<Vec<u8>, Errno> {
    let mut bytes = vec![0; layout.page_bytes];
    let address = Addr::<u8>::from_raw(layout.base as usize).ok_or(Errno::EFAULT)?;
    task.read_exact(address, &mut bytes)?;
    Ok(bytes)
}

impl FatalSession {
    fn bind_input_generation(
        &self,
        terminal: safeptrace::TerminalCleanup,
        task: InputTaskId,
    ) -> Result<(), TraceError> {
        let mut generations = self.input_generations.lock().unwrap();
        if let Some((_, existing)) = generations
            .iter()
            .find(|(entry, _)| entry.same_generation(&terminal))
        {
            return if *existing == task {
                Ok(())
            } else {
                Err(Errno::EPROTO.into())
            };
        }
        generations.push((Arc::new(terminal), task));
        Ok(())
    }

    fn rebind_input_exec_generation(
        &self,
        terminal: &safeptrace::TerminalCleanup,
        displaced: InputTaskId,
        replacement: InputTaskId,
    ) -> Result<(), TraceError> {
        let mut generations = self.input_generations.lock().unwrap();
        let (_, owner) = generations
            .iter_mut()
            .find(|(entry, _)| entry.same_generation(terminal))
            .ok_or(Errno::ENODATA)?;
        if *owner != displaced {
            return Err(Errno::EPROTO.into());
        }
        *owner = replacement;
        Ok(())
    }

    /// Actual terminal cleanup can precede Tool initialization for a newborn.
    /// Match the retained native generation, never a newly reused numeric TID.
    pub(super) fn finish_input_generation(&self, terminal: &safeptrace::TerminalCleanup) {
        if let Err(error) = self.complete_native_effects(terminal) {
            self.fail(error);
        }
        let Some(control) = &self.reserved_input else {
            return;
        };
        let task = self
            .input_generations
            .lock()
            .unwrap()
            .iter()
            .find(|(entry, _)| entry.same_generation(terminal))
            .map(|(_, task)| *task);
        if let Some(task) = task
            && let Err(error) = control.backend_terminal(task)
        {
            control.backend_fail(error.to_string());
            let tid = Pid::from_raw(task.native_tid());
            self.fail_at(
                BackendFailure {
                    pid: tid,
                    tid,
                    phase: "ptrace input terminal generation",
                },
                anyhow::Error::new(error).into(),
            );
        }
    }

    pub(super) fn capture_input_birth(&self, parent: Pid, child: &Running) {
        let Some(control) = &self.reserved_input else {
            return;
        };
        let result = (|| -> Result<(), InputUnavailable> {
            let parent_task = control
                .task_identity(parent.as_raw())
                .ok_or_else(|| InputUnavailable::new("input-parent-not-retained"))?;
            let status = std::fs::read_to_string(format!("/proc/{}/status", child.pid()))
                .map_err(|_| InputUnavailable::new("input-child-native-group-unavailable"))?;
            let pid = status
                .lines()
                .find_map(|line| line.strip_prefix("Tgid:"))
                .and_then(|v| v.trim().parse::<i32>().ok())
                .ok_or_else(|| InputUnavailable::new("input-child-native-group-unavailable"))?;
            let memory = kcmp_relation(parent.as_raw(), child.pid().as_raw(), 1);
            let files = kcmp_relation(parent.as_raw(), child.pid().as_raw(), 2);
            let registered = control.backend_register_child(
                parent_task,
                child.pid().as_raw(),
                pid,
                memory,
                files,
            )?;
            self.bind_input_generation(child.generation().terminal_cleanup(), registered.task)
                .map_err(|_| InputUnavailable::new("input-native-generation-mismatch"))?;
            if let Some(id) = control.backend_issued_call(parent_task) {
                control.backend_retained_birth(id, registered.task, memory, files)?;
            } else {
                // Root/bootstrap registration is separate and never passes
                // here. An actual unannotated child is not evidence that the
                // Tool certified its immutable physical inputs or lifecycle.
                control.add_exposure(InputExposure {
                    target: InputTarget::Unknown,
                    cause: "input-unobserved-native-birth".into(),
                })?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            control.backend_fail(error.to_string());
            self.fail_at(
                BackendFailure {
                    pid: parent,
                    tid: child.pid(),
                    phase: "ptrace input birth capture",
                },
                anyhow::Error::new(error).into(),
            );
        }
    }
}
