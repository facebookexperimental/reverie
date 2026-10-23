//! Physical native socket I/O, including the unpublished bootstrap interval.
//! No binding in this module is an admitted image, Tool or lifecycle permit.

use core::marker::PhantomData;
use std::io;
use std::rc::Rc;

use super::NativeControl;

/// Immutable physical binding. It is naturally Send, but every operation is
/// checked on the actual original task; moving it grants no cross-task use.
pub(crate) struct NativeGateIoBinding {
    control: usize,
    tid: i64,
    tool_fs: u64,
}

/// A stack-only same-task scope; it cannot cross an await/thread boundary.
pub(crate) struct NativeGateIoScope<'a> {
    binding: &'a NativeGateIoBinding,
    phase: u64,
    ready: u64,
    _same_task: PhantomData<Rc<()>>,
}

/// Physical abort protection after the shared handshake and before the
/// existing prepared-image owner has armed its admitted abort protection.
/// This guard grants no image, Tool, lifecycle or publication authority.
pub struct NativeInitializationIoGuard {
    binding: NativeGateIoBinding,
    armed: bool,
    _same_task: PhantomData<Rc<()>>,
}

impl NativeInitializationIoGuard {
    /// Retain physical abort protection immediately after the shared handshake.
    /// A failed physical check terminates before the client can be destroyed.
    ///
    /// # Safety
    /// The caller satisfies the inherited page/filter/control and same-task
    /// private FS/stack premises of `GuestRpcStream::connect_native`. The
    /// exact shared Initial/Successor handshake has returned its live client,
    /// and neither admitted publication nor Guest work has occurred. Retain
    /// this guard before any fallible Config, catalog or provider preparation.
    pub unsafe fn arm(control: *mut NativeControl) -> Self {
        let binding = match unsafe { NativeGateIoBinding::bind_bootstrap_io(control) } {
            Ok(binding) => binding,
            Err(_) => unsafe { super::initialization_failed(control) },
        };
        Self {
            binding,
            armed: true,
            _same_task: PhantomData,
        }
    }

    /// Transfer abort protection to the actual existing prepared-image owner.
    ///
    /// # Safety
    /// The same live PreparedInitial/PreparedSuccessor image already owns its
    /// original admitted abort guard. It has genuinely authenticated and
    /// published this exact control and fixed gate, and remains live through
    /// this call and subsequent initialization. This physical check cannot
    /// prove that ownership; no readiness or phase may be written here.
    pub unsafe fn handoff_to_prepared_owner(mut self) {
        if self.binding.check() != (2, 0)
            || super::control_pointer() as usize != self.binding.control
            || !crate::trap::fixed_gates_published()
        {
            self.binding.terminal();
        }
        self.armed = false;
    }
}

impl Drop for NativeInitializationIoGuard {
    fn drop(&mut self) {
        if self.armed {
            self.binding.terminal();
        }
    }
}

impl NativeGateIoBinding {
    /// Bind only the controlled runner's inherited scalar mechanism.
    ///
    /// # Safety
    /// The actual qualified bootstrap/runner owns the exact inherited RX gate
    /// and initial filter, private Tool FS/stack and protected control extent.
    /// No Guest, worker or concurrent mapping/control mutation may exist. The
    /// control remains mapped and protected for every retained stream use.
    /// This is not coordinator admission, and may not publish either owner.
    pub(crate) unsafe fn bind_bootstrap_io(control: *mut NativeControl) -> io::Result<Self> {
        unsafe { super::checked_initial_control(control)? };
        if super::active() || crate::trap::fixed_gates_published() {
            return Err(io::Error::other(
                "native bootstrap I/O is not a fresh image",
            ));
        }
        unsafe { crate::trap::verify_native_io_gate()? };
        let tid = unsafe { crate::trap::native_io_syscall(libc::SYS_gettid, [0; 6]) };
        let tool_fs = unsafe { (&raw const (*control).tool_fs).read_volatile() };
        let binding = Self {
            control: control as usize,
            tid,
            tool_fs,
        };
        // All context queries use the verified fixed page, not a SIGSYS relay.
        binding.scope();
        Ok(binding)
    }

    /// Failure must precede generic errors, allocation and destructor I/O.
    pub(crate) fn terminal(&self) -> ! {
        unsafe { super::initialization_failed(self.control as *mut NativeControl) }
    }

    pub(crate) fn scope(&self) -> NativeGateIoScope<'_> {
        let (phase, ready) = self.check();
        NativeGateIoScope {
            binding: self,
            phase,
            ready,
            _same_task: PhantomData,
        }
    }

    fn check(&self) -> (u64, u64) {
        if self.control != 0x5300_0000_0000 || self.tid <= 0 || self.tool_fs == 0 {
            self.terminal();
        }
        let control = self.control as *const NativeControl;
        let read = |p: *const u64| unsafe { p.read_volatile() };
        let phase = read(unsafe { &raw const (*control).phase });
        let ready = read(unsafe { &raw const (*control).runtime_ready });
        let published_control = super::control_pointer() as usize;
        // Before ACK only the physical bootstrap interval is permitted. After
        // publication, this must still be the same exact admitted control.
        // Phase 6 authority is the caller's existing LifecyclePermit, never this
        // numeric check. No phase is written here.
        let valid_phase = if published_control == 0 {
            !crate::trap::fixed_gates_published() && phase == 2 && ready == 0
        } else {
            published_control == self.control
                && crate::trap::fixed_gates_published()
                && matches!((phase, ready), (2 | 6, 0) | (4, 1))
        };
        // Bootstrap/lifecycle I/O precedes restoration; a ready callback follows
        // the runner's checked CAPTURED(1) -> CAPTURED|RESTORED(3) transition.
        let valid_kernel_state = matches!(
            (
                phase,
                ready,
                read(unsafe { &raw const (*control).native_state })
            ),
            (2 | 6, 0, 1) | (4, 1, 3)
        );
        if read(unsafe { &raw const (*control).abi_version }) != 1
            || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
            || !valid_kernel_state
            || read(unsafe { &raw const (*control).native_tid }) != self.tid as u64
            || read(unsafe { &raw const (*control).tool_fs }) != self.tool_fs
            || !valid_phase
        {
            self.terminal();
        }
        let tid = unsafe { crate::trap::native_io_syscall(libc::SYS_gettid, [0; 6]) };
        let pid = unsafe { crate::trap::native_io_syscall(libc::SYS_getpid, [0; 6]) };
        let mut fs = 0_u64;
        let result = unsafe {
            crate::trap::native_io_syscall(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        };
        if tid != self.tid || pid != tid || result != 0 || fs != self.tool_fs {
            self.terminal();
        }
        (phase, ready)
    }
}

impl NativeGateIoScope<'_> {
    /// One bounded socket primitive, preserving the current original stack.
    ///
    /// # Safety
    /// The descriptor and buffers must remain exclusively owned and valid for
    /// this operation. Connect arguments must be the prebuilt exact endpoint.
    pub(crate) unsafe fn call(&self, number: i64, args: [u64; 6]) -> i64 {
        if !matches!(
            number,
            libc::SYS_socket
                | libc::SYS_connect
                | libc::SYS_sendto
                | libc::SYS_recvfrom
                | libc::SYS_close
        ) {
            self.binding.terminal();
        }
        let result = unsafe { crate::trap::native_io_syscall(number, args) };
        self.validate();
        result
    }

    fn validate(&self) {
        if self.binding.check() != (self.phase, self.ready) {
            self.binding.terminal();
        }
    }
}

impl Drop for NativeGateIoScope<'_> {
    fn drop(&mut self) {
        // No formatting, allocation, libc/TLS query or selector publication.
        self.validate();
    }
}
