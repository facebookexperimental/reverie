//! Default-off test observations and a post-prefix drain gate. Not a log protocol.
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

const MAGIC: u64 = 0x4649585455524533;

#[repr(C)]
pub struct Observations {
    magic: u64,
    gate: AtomicU64,
    pub startup: [AtomicU64; 2],
    pub full: AtomicU64,
    pub wait_enter: AtomicU64,
    pub wait_exit: AtomicU64,
    pub before: AtomicU64,
    pub after: AtomicU64,
    pub result: AtomicU64,
    pub invalid: AtomicU64,
    pub clocks: [AtomicU64; 8],
    pub callbacks: AtomicU64,
    pub verified: AtomicU64,
    pub gate_reached: AtomicU64,
    pub gate_wait_baseline: AtomicU64,
    pub signal_policy: [AtomicU64; 4],
    pub install_result: AtomicU64,
    pub install_error_len: AtomicU64,
    pub install_error_truncated: AtomicU64,
    pub install_error: [AtomicU8; 256],
    pub guest_wait_status: AtomicU64,
    pub guest_reaped: AtomicU64,
    pub v4_pressure: AtomicU64,
    pub v4_gate: AtomicU64,
    pub v4_waits: AtomicU64,
    pub guest_orders: [AtomicU64; 7],
    pub record_failed: AtomicU64,
    pub v4_gate_clocks: [AtomicU64; 2],
}

impl Observations {
    pub fn record_install_result(&self, result: &io::Result<()>) {
        struct Writer<'a> {
            seen: &'a Observations,
            length: usize,
        }
        impl std::fmt::Write for Writer<'_> {
            fn write_str(&mut self, value: &str) -> std::fmt::Result {
                for byte in value.bytes() {
                    if self.length == self.seen.install_error.len() {
                        self.seen
                            .install_error_truncated
                            .store(1, Ordering::Relaxed);
                        return Err(std::fmt::Error);
                    }
                    self.seen.install_error[self.length].store(byte, Ordering::Relaxed);
                    self.length += 1;
                }
                Ok(())
            }
        }
        if let Err(error) = result {
            let mut writer = Writer {
                seen: self,
                length: 0,
            };
            let _ = std::fmt::write(&mut writer, format_args!("{error:?}"));
            self.install_error_len
                .store(writer.length as u64, Ordering::Relaxed);
        }
        self.install_result
            .store(if result.is_ok() { 1 } else { 2 }, Ordering::Release);
    }
}

pub struct Control {
    fd: OwnedFd,
    pointer: NonNull<Observations>,
}
unsafe impl Send for Control {}
unsafe impl Sync for Control {}

impl Control {
    /// Create the default-off observation mapping for cooperating fixture peers.
    ///
    /// # Safety
    /// For the entire lifetime of this Control, all attached Controls and every
    /// borrowed observation reference, the caller must ensure that descriptors,
    /// procfs reopens and other writable aliases are used only by cooperating
    /// fixture peers. Keep initialized non-atomic layout/version fields unchanged
    /// and update observations only through their atomic interfaces. Size seals
    /// prevent resizing, not writes through the exported backing descriptor.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log as g;
    /// fn requires_ownership_contract() {
    ///     let _ = g::fixture::Control::new();
    /// }
    /// ```
    pub unsafe fn new() -> io::Result<Self> {
        let fd = unsafe {
            libc::memfd_create(
                c"guest-log-fixture".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let length = std::mem::size_of::<Observations>();
        if unsafe { libc::ftruncate(fd.as_raw_fd(), length as libc::off_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let control = Self::map(fd)?;
        unsafe {
            control.pointer.as_ptr().write(Observations {
                magic: MAGIC,
                gate: AtomicU64::new(1),
                startup: [const { AtomicU64::new(0) }; 2],
                full: AtomicU64::new(0),
                wait_enter: AtomicU64::new(0),
                wait_exit: AtomicU64::new(0),
                before: AtomicU64::new(0),
                after: AtomicU64::new(0),
                result: AtomicU64::new(0),
                invalid: AtomicU64::new(0),
                clocks: [const { AtomicU64::new(0) }; 8],
                callbacks: AtomicU64::new(0),
                verified: AtomicU64::new(0),
                gate_reached: AtomicU64::new(0),
                gate_wait_baseline: AtomicU64::new(0),
                signal_policy: [const { AtomicU64::new(0) }; 4],
                install_result: AtomicU64::new(0),
                install_error_len: AtomicU64::new(0),
                install_error_truncated: AtomicU64::new(0),
                install_error: [const { AtomicU8::new(0) }; 256],
                guest_wait_status: AtomicU64::new(0),
                guest_reaped: AtomicU64::new(0),
                v4_pressure: AtomicU64::new(0),
                v4_gate: AtomicU64::new(0),
                v4_waits: AtomicU64::new(0),
                guest_orders: [const { AtomicU64::new(0) }; 7],
                record_failed: AtomicU64::new(0),
                v4_gate_clocks: [const { AtomicU64::new(0) }; 2],
            });
        }
        if unsafe {
            libc::fcntl(
                control.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(control)
    }

    /// # Safety
    /// The caller owns the trusted fixture descriptor and its live shared object.
    /// Only this fixture's atomic observation writers may modify the mapping.
    pub unsafe fn attach(fd: i32) -> io::Result<Self> {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.st_size != std::mem::size_of::<Observations>() as i64 {
            return Err(io::Error::other("fixture mapping length"));
        }
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        let needed = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if seals < 0 || seals & needed != needed {
            return Err(io::Error::other("fixture mapping seals"));
        }
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let control = Self::map(unsafe { OwnedFd::from_raw_fd(duplicate) })?;
        if control.observations().magic != MAGIC {
            return Err(io::Error::other("fixture mapping version"));
        }
        Ok(control)
    }

    fn map(fd: OwnedFd) -> io::Result<Self> {
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<Observations>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            pointer: NonNull::new(address.cast()).unwrap(),
        })
    }
    pub fn observations(&self) -> &Observations {
        unsafe { self.pointer.as_ref() }
    }
    pub fn record_guest_status(&self, status: std::process::ExitStatus) {
        use std::os::unix::process::ExitStatusExt;
        self.observations()
            .guest_wait_status
            .store(status.into_raw() as u64, Ordering::Relaxed);
        self.observations().guest_reaped.store(1, Ordering::Release);
    }
    pub fn gated(&self) -> bool {
        self.observations().gate.load(Ordering::Acquire) != 0
    }
    pub fn gate_address(&self) -> *const u32 {
        self.observations().gate.as_ptr().cast()
    }
    pub(super) fn mark_gated(&self) {
        let seen = self.observations();
        if seen.gate_reached.load(Ordering::Relaxed) == 0 {
            seen.gate_wait_baseline
                .store(seen.wait_enter.load(Ordering::Acquire), Ordering::Relaxed);
            seen.gate_reached.store(1, Ordering::Release);
        }
    }
    pub fn release(&self) {
        self.observations().gate.store(0, Ordering::Release);
    }
    pub fn release_on_drop(self: &Arc<Self>) -> Release {
        Release(self.clone())
    }
}
impl AsRawFd for Control {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.pointer.as_ptr().cast(),
                std::mem::size_of::<Observations>(),
            );
        }
    }
}
pub struct Release(Arc<Control>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_install_error_and_actual_exit_status_survive_attach() {
        use std::os::unix::process::ExitStatusExt;
        let control = unsafe { Control::new() }.unwrap();
        let peer = unsafe { Control::attach(control.as_raw_fd()) }.unwrap();
        let error = io::Error::new(io::ErrorKind::Unsupported, "owned signal-mask policy");
        control.observations().record_install_result(&Err(error));
        control.record_guest_status(std::process::ExitStatus::from_raw(42 << 8));
        let seen = peer.observations();
        assert_eq!(seen.install_result.load(Ordering::Acquire), 2);
        let bytes: Vec<_> = seen
            .install_error
            .iter()
            .take(seen.install_error_len.load(Ordering::Acquire) as usize)
            .map(|byte| byte.load(Ordering::Acquire))
            .collect();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "Custom { kind: Unsupported, error: \"owned signal-mask policy\" }"
        );
        assert_eq!(seen.install_error_truncated.load(Ordering::Acquire), 0);
        assert_eq!(seen.guest_reaped.load(Ordering::Acquire), 1);
        assert_eq!(seen.guest_wait_status.load(Ordering::Acquire), 42 << 8);
    }

    #[test]
    fn install_error_capacity_reports_truncation() {
        let control = unsafe { Control::new() }.unwrap();
        control
            .observations()
            .record_install_result(&Err(io::Error::other("x".repeat(512))));
        let seen = control.observations();
        assert_eq!(seen.install_result.load(Ordering::Acquire), 2);
        assert_eq!(seen.install_error_len.load(Ordering::Acquire), 256);
        assert_eq!(seen.install_error_truncated.load(Ordering::Acquire), 1);
        assert_eq!(seen.guest_reaped.load(Ordering::Acquire), 0);
    }

    #[test]
    fn old_fixture_mapping_version_is_refused() {
        let control = unsafe { Control::new() }.unwrap();
        for version in [0x4649585455524531, 0x4649585455524532] {
            unsafe { (*control.pointer.as_ptr()).magic = version };
            assert!(unsafe { Control::attach(control.as_raw_fd()) }.is_err());
        }
    }

    #[test]
    fn v4_observations_are_shared_and_disabled_by_default() {
        let control = unsafe { Control::new() }.unwrap();
        let peer = unsafe { Control::attach(control.as_raw_fd()) }.unwrap();
        let seen = peer.observations();
        assert_eq!(seen.v4_pressure.load(Ordering::Acquire), 0);
        assert_eq!(seen.v4_gate.load(Ordering::Acquire), 0);
        assert_eq!(seen.v4_waits.load(Ordering::Acquire), 0);
        assert!(
            seen.guest_orders
                .iter()
                .all(|order| order.load(Ordering::Acquire) == 0)
        );
        control
            .observations()
            .v4_pressure
            .store(2, Ordering::Release);
        control.observations().guest_orders[0].store(3, Ordering::Release);
        assert_eq!(seen.v4_pressure.load(Ordering::Acquire), 2);
        assert_eq!(seen.guest_orders[0].load(Ordering::Acquire), 3);
        assert!(peer.gated());
        control.release();
        assert!(!peer.gated());
        assert_eq!(seen.full.load(Ordering::Acquire), 0);
        assert_eq!(seen.verified.load(Ordering::Acquire), 0);
    }
}
