/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Inactive native exec descriptor ownership. These mechanisms do not grant
//! launch authority. Temporary regular-file leases must never reach guest code:
//! descriptor guards cannot prevent reopening a file through procfs.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use crate::trap::raw_syscall6;

const FIRST: i32 = 198;
/// Stock guest loader, runner, private Tool loader, sealed input, native config.
pub const BOOTSTRAP_FD_COUNT: usize = 5;
static SOCKETS: [AtomicI32; 2] = [const { AtomicI32::new(-1) }; 2];
static LEASE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Distinct persistent socket roles. Neither shares the real DETLOG endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSocket {
    Observer = 0,
    Provider = 1,
}

/// Bounded ownership error. A live lease still requires cancellation; ownership
/// uncertainty cannot be returned to the guest as a fabricated exec errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFdError(pub &'static str);

fn call(number: i64, args: [u64; 6]) -> Result<i64, NativeFdError> {
    let result = unsafe { raw_syscall6(number, args) };
    if result < 0 {
        Err(NativeFdError("native descriptor syscall failed"))
    } else {
        Ok(result)
    }
}

/// Actual immutable descriptor metadata, including close-on-exec state.
/// File content and role qualification remain the concrete driver's duty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub descriptor_flags: i32,
    pub status_flags: i32,
}
impl FdIdentity {
    /// Query the actual descriptor through the installed raw gate.
    pub fn read(fd: i32) -> Result<Self, NativeFdError> {
        let mut metadata: libc::stat = unsafe { core::mem::zeroed() };
        call(
            libc::SYS_fstat,
            [fd as u64, (&raw mut metadata) as u64, 0, 0, 0, 0],
        )?;
        Ok(Self {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            descriptor_flags: call(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
            )? as i32,
            status_flags: call(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
            )? as i32,
        })
    }
}

/// One observed protected socket. This is data, not descriptor ownership or
/// permission to perform an exec. The installed owner retains the socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExecSocketBinding {
    fd: i32,
    identity: FdIdentity,
}
impl NativeExecSocketBinding {
    /// Actual descriptor number at this cut, including any output relocation.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Exact metadata and flags observed through the installed raw gate.
    pub fn identity(&self) -> FdIdentity {
        self.identity
    }

    fn read(fd: i32) -> Result<Self, NativeFdError> {
        let identity = FdIdentity::read(fd)?;
        if identity.mode & libc::S_IFMT != libc::S_IFSOCK
            || fd <= 2
            || (FIRST..FIRST + BOOTSTRAP_FD_COUNT as i32).contains(&fd)
        {
            return Err(NativeFdError(
                "native inherited role is not a separate socket",
            ));
        }
        Ok(Self { fd, identity })
    }
}

/// Per-cut physical socket observations. Neither this copyable snapshot nor
/// its numeric descriptors supplies native admission or owns another FD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExecSocketBindings {
    detlog: NativeExecSocketBinding,
    observer: NativeExecSocketBinding,
    coordinator: NativeExecSocketBinding,
    provider: NativeExecSocketBinding,
}
impl NativeExecSocketBindings {
    /// Capture current protected roles against independently retained socket
    /// objects. Call only in the driver's quiescent original native exec cut.
    /// The host must independently join these facts to its held socket roles.
    pub fn capture(
        expected_detlog: (u64, u64),
        expected_observer: (u64, u64),
    ) -> Result<Self, NativeFdError> {
        let bindings = Self {
            detlog: NativeExecSocketBinding::read(
                super::protect::tool_output_fd()
                    .ok_or(NativeFdError("native DETLOG owner is absent"))?,
            )?,
            observer: NativeExecSocketBinding::read(
                socket_fd(NativeSocket::Observer)
                    .ok_or(NativeFdError("native observer owner is absent"))?,
            )?,
            coordinator: NativeExecSocketBinding::read(
                super::protect::coordinator_fd()
                    .ok_or(NativeFdError("native coordinator owner is absent"))?,
            )?,
            provider: NativeExecSocketBinding::read(
                socket_fd(NativeSocket::Provider)
                    .ok_or(NativeFdError("native provider owner is absent"))?,
            )?,
        };
        let object =
            |binding: NativeExecSocketBinding| (binding.identity.device, binding.identity.inode);
        if object(bindings.detlog) != expected_detlog
            || object(bindings.observer) != expected_observer
            || bindings.detlog.identity.descriptor_flags & !libc::FD_CLOEXEC != 0
            || bindings.observer.identity.descriptor_flags != 0
        {
            return Err(NativeFdError(
                "native inherited socket object or flags differ",
            ));
        }
        let roles = [
            bindings.detlog,
            bindings.observer,
            bindings.coordinator,
            bindings.provider,
        ];
        for (index, role) in roles.iter().enumerate() {
            if roles[..index]
                .iter()
                .any(|other| role.fd == other.fd || object(*role) == object(*other))
            {
                return Err(NativeFdError("native protected socket roles alias"));
            }
        }
        bindings.revalidate_original()?;
        Ok(bindings)
    }

    /// DETLOG's current number and independently checked object identity.
    pub fn detlog(&self) -> NativeExecSocketBinding {
        self.detlog
    }

    /// Observer's current number and independently checked object identity.
    pub fn observer(&self) -> NativeExecSocketBinding {
        self.observer
    }

    /// Recheck the exact original flags before inheritance is prepared, or
    /// after cancellation restores them. The active lease uses flags zero.
    pub fn revalidate_original(&self) -> Result<(), NativeFdError> {
        self.revalidate_flags(self.detlog.identity.descriptor_flags)
    }

    fn revalidate_flags(&self, detlog_flags: i32) -> Result<(), NativeFdError> {
        if super::protect::tool_output_fd() != Some(self.detlog.fd)
            || socket_fd(NativeSocket::Observer) != Some(self.observer.fd)
            || super::protect::coordinator_fd() != Some(self.coordinator.fd)
            || socket_fd(NativeSocket::Provider) != Some(self.provider.fd)
        {
            return Err(NativeFdError("native protected socket owner changed"));
        }
        let active_detlog = NativeExecSocketBinding {
            identity: FdIdentity {
                descriptor_flags: detlog_flags,
                ..self.detlog.identity
            },
            ..self.detlog
        };
        for expected in [
            active_detlog,
            self.observer,
            self.coordinator,
            self.provider,
        ] {
            if NativeExecSocketBinding::read(expected.fd)? != expected {
                return Err(NativeFdError(
                    "native protected socket identity or flags changed",
                ));
            }
        }
        Ok(())
    }
}

/// Move a real socket into the protected high range before any Guest runs.
/// Success consumes the original descriptor; failure leaves it owned by caller.
/// Observer is inherited across exec, provider is closed and freshly connected.
///
/// # Safety
/// Single-threaded trusted initializer only, before runtime publication. `fd`
/// must be exclusively owned with no Rust owner that will later close it. The
/// actual socket identity and distinct role must be independently authenticated.
/// No caller may hand these numbers back to the guest or mutate their OFDs.
pub unsafe fn reserve_socket(role: NativeSocket, fd: i32) -> Result<i32, NativeFdError> {
    if FdIdentity::read(fd)?.mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(NativeFdError("native control descriptor is not a socket"));
    }
    let slot = &SOCKETS[role as usize];
    if slot.load(Ordering::Acquire) != -1 {
        return Err(NativeFdError("native socket role already installed"));
    }
    let moved = call(
        libc::SYS_fcntl,
        [fd as u64, libc::F_DUPFD_CLOEXEC as u64, 1026, 0, 0, 0],
    )? as i32;
    if role == NativeSocket::Observer
        && call(
            libc::SYS_fcntl,
            [moved as u64, libc::F_SETFD as u64, 0, 0, 0, 0],
        )
        .is_err()
    {
        unsafe {
            raw_syscall6(libc::SYS_close, [moved as u64, 0, 0, 0, 0, 0]);
        }
        return Err(NativeFdError("native observer inheritance failed"));
    }
    if slot
        .compare_exchange(-1, moved, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        unsafe {
            raw_syscall6(libc::SYS_close, [moved as u64, 0, 0, 0, 0, 0]);
        }
        return Err(NativeFdError("native socket role changed"));
    }
    if call(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]).is_err() {
        fatal();
    }
    Ok(moved)
}

/// Current owned socket; descriptors do not silently relocate or retire.
pub fn socket_fd(role: NativeSocket) -> Option<i32> {
    let fd = SOCKETS[role as usize].load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}

pub(super) fn append_protected(output: &mut [u64], count: &mut usize) {
    for slot in &SOCKETS {
        let fd = slot.load(Ordering::Acquire);
        if fd >= 0 {
            output[*count] = fd as u64;
            *count += 1;
        }
    }
    if LEASE_ACTIVE.load(Ordering::Acquire) {
        for index in 0..BOOTSTRAP_FD_COUNT {
            output[*count] = (FIRST + index as i32) as u64;
            *count += 1;
        }
    }
}

/// Affine ownership of all five kernel bootstrap descriptors. The caller owns
/// any SCM_RIGHTS source FDs separately. Drop while armed is a terminal error.
pub struct BootstrapFdLease {
    current: [Option<FdIdentity>; BOOTSTRAP_FD_COUNT],
    sockets: Option<NativeExecSocketBindings>,
    armed: bool,
    installed: bool,
}
impl BootstrapFdLease {
    /// Reserve unused exact numbers before freezing runtime counters.
    ///
    /// # Safety
    /// Caller exclusively owns a quiescent leader callback. No Guest or other
    /// thread can execute until native exec or complete cancellation. These
    /// temporary regular files must never survive a return to Guest. Tool raw
    /// gates must be installed before this is used in a real native callback.
    pub unsafe fn reserve() -> Result<Self, NativeFdError> {
        if LEASE_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(NativeFdError("native bootstrap lease already active"));
        }
        let mut lease = Self {
            current: [None; BOOTSTRAP_FD_COUNT],
            sockets: None,
            armed: true,
            installed: false,
        };
        let result = lease.reserve_inner();
        if let Err(error) = result {
            lease.cancel()?;
            return Err(error);
        }
        Ok(lease)
    }

    fn reserve_inner(&mut self) -> Result<(), NativeFdError> {
        for index in 0..BOOTSTRAP_FD_COUNT {
            let fd = FIRST + index as i32;
            let queried = unsafe {
                raw_syscall6(
                    libc::SYS_fcntl,
                    [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
                )
            };
            if queried != -i64::from(libc::EBADF) {
                return Err(NativeFdError(
                    "native bootstrap number is occupied or unqueryable",
                ));
            }
        }
        let original = call(
            libc::SYS_memfd_create,
            [
                c"native-exec-slot".as_ptr() as u64,
                (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as u64,
                0,
                0,
                0,
                0,
            ],
        )? as i32;
        // Move the placeholder source outside the exact target range even if
        // memfd_create happened to allocate one of those five numbers.
        let moved = call(
            libc::SYS_fcntl,
            [original as u64, libc::F_DUPFD_CLOEXEC as u64, 203, 0, 0, 0],
        );
        if call(libc::SYS_close, [original as u64, 0, 0, 0, 0, 0]).is_err() {
            fatal();
        }
        let source = moved? as i32;
        let result = (|| {
            call(
                libc::SYS_fcntl,
                [
                    source as u64,
                    libc::F_ADD_SEALS as u64,
                    (libc::F_SEAL_SEAL
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_WRITE) as u64,
                    0,
                    0,
                    0,
                ],
            )?;
            let identity = FdIdentity::read(source)?;
            for index in 0..BOOTSTRAP_FD_COUNT {
                let fd = FIRST + index as i32;
                call(
                    libc::SYS_dup3,
                    [source as u64, fd as u64, libc::O_CLOEXEC as u64, 0, 0, 0],
                )?;
                self.current[index] = Some(identity);
            }
            self.revalidate()
        })();
        if call(libc::SYS_close, [source as u64, 0, 0, 0, 0, 0]).is_err() {
            fatal();
        }
        result
    }

    /// Read-only exact comparison; never assumes ownership from FD integers.
    pub fn revalidate(&self) -> Result<(), NativeFdError> {
        if !self.armed || !LEASE_ACTIVE.load(Ordering::Acquire) {
            return Err(NativeFdError("native bootstrap lease is not active"));
        }
        if let Some(sockets) = self.sockets {
            sockets.revalidate_flags(0)?;
        }
        for (index, expected) in self.current.iter().enumerate() {
            if let Some(expected) = expected
                && FdIdentity::read(FIRST + index as i32)? != *expected
            {
                return Err(NativeFdError(
                    "native bootstrap descriptor identity changed",
                ));
            }
        }
        Ok(())
    }

    /// Temporarily make the current DETLOG socket inheritable in this existing
    /// lease. Observer already is inheritable and is never modified. This must
    /// precede runtime counter capture and the coordinator's Prepare request.
    ///
    /// A failure after a flag mutation is attempted leaves this lease armed;
    /// uncertain ownership or failed restoration must never resume Guest.
    pub fn prepare_socket_inheritance(
        &mut self,
        sockets: NativeExecSocketBindings,
    ) -> Result<(), NativeFdError> {
        self.revalidate()?;
        if self.sockets.is_some() {
            return Err(NativeFdError("native socket inheritance already prepared"));
        }
        sockets.revalidate_original()?;
        // Record rollback before any mutation. The same affine owner retains
        // both the five regular slots and these non-owning socket observations.
        self.sockets = Some(sockets);
        if sockets.detlog.identity.descriptor_flags != 0 {
            call(
                libc::SYS_fcntl,
                [sockets.detlog.fd as u64, libc::F_SETFD as u64, 0, 0, 0, 0],
            )?;
        }
        self.revalidate()
    }

    /// Install authenticated provider sources using fixed gates and no heap.
    /// Partial failure retains the exact successfully replaced identities.
    ///
    /// # Safety
    /// The driver independently authenticated every role, held immutable file
    /// contents, flags and required seals. All five `sources` are distinct,
    /// owned CLOEXEC SCM_RIGHTS descriptors; none may change during this call.
    /// Only the separately proved original native exec may consume this lease.
    pub unsafe fn install(
        &mut self,
        sources: [i32; BOOTSTRAP_FD_COUNT],
    ) -> Result<(), NativeFdError> {
        self.revalidate()?;
        if self.installed || self.current.iter().any(Option::is_none) {
            return Err(NativeFdError("native bootstrap lease cannot install twice"));
        }
        let mut identities = [self.current[0].unwrap(); BOOTSTRAP_FD_COUNT];
        for (index, source) in sources.iter().copied().enumerate() {
            if (FIRST..FIRST + BOOTSTRAP_FD_COUNT as i32).contains(&source)
                || sources[..index].contains(&source)
            {
                return Err(NativeFdError(
                    "native provider source aliases reserved descriptor",
                ));
            }
            let identity = FdIdentity::read(source)?;
            if identity.descriptor_flags != libc::FD_CLOEXEC
                || identity.mode & libc::S_IFMT != libc::S_IFREG
            {
                return Err(NativeFdError(
                    "native provider source is not a CLOEXEC regular file",
                ));
            }
            identities[index] = FdIdentity {
                descriptor_flags: 0,
                ..identity
            };
        }
        // Any attempt is one-use, including a partial kernel failure.
        self.installed = true;
        for (index, source) in sources.into_iter().enumerate() {
            call(
                libc::SYS_dup3,
                [source as u64, (FIRST + index as i32) as u64, 0, 0, 0, 0],
            )?;
            self.current[index] = Some(identities[index]);
        }
        self.revalidate()
    }

    /// Reclaim only actual owned entries before returning to the old Guest.
    /// Any error leaves the lease armed and requires terminal failure.
    pub fn cancel(&mut self) -> Result<(), NativeFdError> {
        self.revalidate()?;
        if let Some(sockets) = self.sockets {
            if sockets.detlog.identity.descriptor_flags != 0 {
                call(
                    libc::SYS_fcntl,
                    [
                        sockets.detlog.fd as u64,
                        libc::F_SETFD as u64,
                        sockets.detlog.identity.descriptor_flags as u64,
                        0,
                        0,
                        0,
                    ],
                )?;
            }
            sockets.revalidate_original()?;
            self.sockets = None;
        }
        for index in 0..BOOTSTRAP_FD_COUNT {
            if self.current[index].is_some() {
                call(
                    libc::SYS_close,
                    [(FIRST + index as i32) as u64, 0, 0, 0, 0, 0],
                )?;
                self.current[index] = None;
            }
        }
        self.armed = false;
        LEASE_ACTIVE.store(false, Ordering::Release);
        Ok(())
    }
}
impl Drop for BootstrapFdLease {
    fn drop(&mut self) {
        if self.armed {
            fatal();
        }
    }
}
fn fatal() -> ! {
    unsafe {
        raw_syscall6(libc::SYS_exit_group, [122, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::IntoRawFd;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::panic::AssertUnwindSafe;

    use super::*;
    use crate::guest::event::SyscallDispatch;
    use crate::guest::event::SyscallEvent;

    fn isolated(expected: i32, work: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
                work();
            }));
            unsafe {
                libc::_exit(if result.is_ok() { 0 } else { 125 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "wait status={status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }
    fn memory() -> OwnedFd {
        let fd = unsafe {
            libc::memfd_create(
                c"native-fd-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }
    fn event(number: i64, fd: u64) -> SyscallEvent {
        SyscallEvent {
            number,
            args: [fd, 0, 0, 0, 0, 0],
            instruction_pointer: 0,
            result: 19,
            context: 0,
            dispatch: SyscallDispatch::Fallback,
            guest_pkru: None,
        }
    }

    fn seqpacket() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn object(identity: FdIdentity) -> (u64, u64) {
        (identity.device, identity.inode)
    }

    fn install_sockets(
        detlog: OwnedFd,
        observer: OwnedFd,
    ) -> (NativeExecSocketBindings, [OwnedFd; 2]) {
        let detlog_object = object(FdIdentity::read(detlog.as_raw_fd()).unwrap());
        let observer_object = object(FdIdentity::read(observer.as_raw_fd()).unwrap());
        unsafe { super::super::protect::reserve_tool_output_fd(detlog.into_raw_fd(), b"retired") }
            .unwrap();
        unsafe { reserve_socket(NativeSocket::Observer, observer.into_raw_fd()) }.unwrap();
        let (coordinator, coordinator_peer) = seqpacket();
        super::super::protect::reserve_coordinator_fd(coordinator.into_raw_fd()).unwrap();
        let (provider, provider_peer) = seqpacket();
        unsafe { reserve_socket(NativeSocket::Provider, provider.into_raw_fd()) }.unwrap();
        (
            NativeExecSocketBindings::capture(detlog_object, observer_object).unwrap(),
            [coordinator_peer, provider_peer],
        )
    }

    fn socket_fixture() -> (NativeExecSocketBindings, [OwnedFd; 4]) {
        let (detlog, detlog_peer) = seqpacket();
        let (observer, observer_peer) = seqpacket();
        let (bindings, [coordinator_peer, provider_peer]) = install_sockets(detlog, observer);
        (
            bindings,
            [detlog_peer, observer_peer, coordinator_peer, provider_peer],
        )
    }

    fn check_packet(fd: i32, expected: u8) {
        let mut byte = 0_u8;
        assert_eq!(
            unsafe {
                libc::recv(
                    fd,
                    (&raw mut byte).cast(),
                    1,
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            },
            1
        );
        assert_eq!(byte, expected);
    }

    // An assertion unwind would drop the armed lease and mimic its expected 122.
    fn inheritance_value_or_exit<T, E>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|_| unsafe { libc::_exit(73) })
    }

    fn inheritance_check_or_exit(condition: bool) {
        if !condition {
            unsafe { libc::_exit(73) }
        }
    }

    #[test]
    fn native_socket_inheritance_restores_exact_flags_after_real_exec_failure() {
        for original_flags in [0, libc::FD_CLOEXEC] {
            isolated(0, || {
                let (original, peers) = socket_fixture();
                assert_eq!(
                    original.detlog().identity().descriptor_flags,
                    libc::FD_CLOEXEC
                );
                assert_eq!(original.observer().identity().descriptor_flags, 0);
                assert_eq!(
                    unsafe { libc::fcntl(original.detlog().fd(), libc::F_SETFD, original_flags) },
                    0
                );
                let bindings = NativeExecSocketBindings::capture(
                    object(original.detlog().identity()),
                    object(original.observer().identity()),
                )
                .unwrap();
                let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
                lease.prepare_socket_inheritance(bindings).unwrap();
                assert!(lease.prepare_socket_inheritance(bindings).is_err());
                lease.revalidate().unwrap();
                if original_flags == libc::FD_CLOEXEC {
                    assert!(bindings.revalidate_original().is_err());
                } else {
                    bindings.revalidate_original().unwrap();
                }
                assert_eq!(
                    FdIdentity::read(bindings.detlog().fd())
                        .unwrap()
                        .descriptor_flags,
                    0
                );
                assert_eq!(
                    FdIdentity::read(bindings.observer().fd()).unwrap(),
                    bindings.observer().identity()
                );
                let argv = [c"absent-native-fd-test".as_ptr(), core::ptr::null()];
                let envp = [core::ptr::null::<libc::c_char>()];
                assert_eq!(
                    unsafe {
                        raw_syscall6(
                            libc::SYS_execveat,
                            [
                                libc::AT_FDCWD as i64 as u64,
                                c"/proc/self/fd/-1".as_ptr() as u64,
                                argv.as_ptr() as u64,
                                envp.as_ptr() as u64,
                                0,
                                0,
                            ],
                        )
                    },
                    -i64::from(libc::ENOENT)
                );
                lease.cancel().unwrap();
                bindings.revalidate_original().unwrap();
                assert_eq!(
                    FdIdentity::read(bindings.detlog().fd()).unwrap(),
                    bindings.detlog().identity()
                );
                for (binding, byte, peer) in [
                    (bindings.detlog(), 0xd1_u8, &peers[0]),
                    (bindings.observer(), 0xd2_u8, &peers[1]),
                ] {
                    assert_eq!(
                        unsafe {
                            libc::send(
                                binding.fd(),
                                (&raw const byte).cast(),
                                1,
                                libc::MSG_NOSIGNAL,
                            )
                        },
                        1
                    );
                    check_packet(peer.as_raw_fd(), byte);
                }
                for fd in FIRST..FIRST + BOOTSTRAP_FD_COUNT as i32 {
                    assert!(FdIdentity::read(fd).is_err());
                }
                assert!(!LEASE_ACTIVE.load(Ordering::Acquire));
            });
        }
    }

    #[test]
    fn native_socket_inheritance_survives_real_exec() {
        const CHILD: &str = "REVERIE_NATIVE_SOCKET_INHERITANCE_TEST";
        if let Ok(value) = std::env::var(CHILD) {
            // Re-exec of this exact test, not a native admission fixture. The
            // independent parent supplied the real socket objects and peers.
            let values = value
                .split(',')
                .map(|item| item.parse::<u64>().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(values.len(), 11);
            for (index, byte) in [(0, 0xe1_u8), (5, 0xe2_u8)] {
                let fd = i32::try_from(values[index]).unwrap();
                let identity = FdIdentity::read(fd).unwrap();
                assert_eq!(
                    (
                        identity.device,
                        identity.inode,
                        u64::from(identity.mode),
                        identity.status_flags as u64
                    ),
                    (
                        values[index + 1],
                        values[index + 2],
                        values[index + 3],
                        values[index + 4]
                    )
                );
                assert_eq!(identity.mode & libc::S_IFMT, libc::S_IFSOCK);
                assert_eq!(identity.descriptor_flags, 0);
                assert_eq!(
                    unsafe { libc::send(fd, (&raw const byte).cast(), 1, libc::MSG_NOSIGNAL) },
                    1
                );
            }
            assert_eq!(unsafe { libc::fcntl(values[10] as i32, libc::F_GETFD) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
            for fd in FIRST..FIRST + BOOTSTRAP_FD_COUNT as i32 {
                assert!(FdIdentity::read(fd).is_err());
            }
            return;
        }
        let (detlog, detlog_peer) = seqpacket();
        let (observer, observer_peer) = seqpacket();
        isolated(0, move || {
            let (bindings, _other_peers) = install_sockets(detlog, observer);
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            lease.prepare_socket_inheritance(bindings).unwrap();
            lease.revalidate().unwrap();
            let unrelated = memory();
            let unrelated_high =
                unsafe { libc::fcntl(unrelated.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 1100) };
            assert!(unrelated_high >= 1100);
            let unrelated_high = unsafe { OwnedFd::from_raw_fd(unrelated_high) };
            let d = bindings.detlog();
            let o = bindings.observer();
            let value = format!(
                "{},{},{},{},{},{},{},{},{},{},{}",
                d.fd(),
                d.identity().device,
                d.identity().inode,
                d.identity().mode,
                d.identity().status_flags,
                o.fd(),
                o.identity().device,
                o.identity().inode,
                o.identity().mode,
                o.identity().status_flags,
                unrelated_high.as_raw_fd()
            );
            let error = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "guest::native_exec_fds::tests::native_socket_inheritance_survives_real_exec",
                    "--nocapture",
                ])
                .env(CHILD, value)
                .exec();
            panic!("actual self exec failed: {error}");
        });
        check_packet(detlog_peer.as_raw_fd(), 0xe1);
        check_packet(observer_peer.as_raw_fd(), 0xe2);
    }

    #[test]
    fn native_socket_inheritance_slot_collision_preserves_sockets_and_guest_file() {
        isolated(0, || {
            let (bindings, _peers) = socket_fixture();
            let guest = memory();
            assert_eq!(
                unsafe { libc::dup3(guest.as_raw_fd(), 200, libc::O_CLOEXEC) },
                200
            );
            let guest_identity = FdIdentity::read(200).unwrap();
            assert!(unsafe { BootstrapFdLease::reserve() }.is_err());
            bindings.revalidate_original().unwrap();
            assert_eq!(FdIdentity::read(200).unwrap(), guest_identity);
            assert!(!LEASE_ACTIVE.load(Ordering::Acquire));
            assert_eq!(unsafe { libc::close(200) }, 0);
        });
        isolated(0, || {
            let (socket, _peer) = seqpacket();
            let socket_identity = FdIdentity::read(socket.as_raw_fd()).unwrap();
            let original_flags = unsafe { libc::fcntl(2, libc::F_GETFD) };
            assert!(original_flags >= 0);
            let saved_stderr = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(saved_stderr >= 3);
            assert_eq!(unsafe { libc::dup3(socket.as_raw_fd(), 2, 0) }, 2);
            let before = FdIdentity::read(2).unwrap();
            let refused = NativeExecSocketBinding::read(2).is_err();
            let unchanged = FdIdentity::read(2).unwrap() == before;
            // Restore diagnostics before checking the actual socket-on-stdio result.
            let dup_flags = if original_flags & libc::FD_CLOEXEC != 0 {
                libc::O_CLOEXEC
            } else {
                0
            };
            let restored = unsafe { libc::dup3(saved_stderr, 2, dup_flags) };
            assert_eq!(restored, 2);
            assert_eq!(unsafe { libc::fcntl(2, libc::F_GETFD) }, original_flags);
            assert_eq!(unsafe { libc::close(saved_stderr) }, 0);
            assert!(refused);
            assert!(unchanged);
            assert_eq!(
                FdIdentity::read(socket.as_raw_fd()).unwrap(),
                socket_identity
            );
        });
    }

    #[test]
    fn native_socket_inheritance_rejects_replacement_and_changed_flags_without_closing_them() {
        for mutation in 0..5 {
            let (witness, witness_peer) = seqpacket();
            let witness_byte = 0xf0_u8 + mutation;
            isolated(122, || {
                let (bindings, _peers) = socket_fixture();
                let (replacement, _peer) = seqpacket();
                let mut lease = inheritance_value_or_exit(unsafe { BootstrapFdLease::reserve() });
                inheritance_value_or_exit(lease.prepare_socket_inheritance(bindings));
                match mutation {
                    0 => inheritance_check_or_exit(
                        unsafe { libc::dup3(replacement.as_raw_fd(), bindings.detlog().fd(), 0) }
                            == bindings.detlog().fd(),
                    ),
                    1 => inheritance_check_or_exit(
                        unsafe {
                            libc::fcntl(bindings.detlog().fd(), libc::F_SETFD, libc::FD_CLOEXEC)
                        } == 0,
                    ),
                    2 => inheritance_check_or_exit(
                        unsafe {
                            libc::fcntl(bindings.observer().fd(), libc::F_SETFD, libc::FD_CLOEXEC)
                        } == 0,
                    ),
                    3 => {
                        let flags =
                            inheritance_value_or_exit(FdIdentity::read(bindings.detlog().fd()))
                                .status_flags;
                        inheritance_check_or_exit(
                            unsafe {
                                libc::fcntl(
                                    bindings.detlog().fd(),
                                    libc::F_SETFL,
                                    flags | libc::O_NONBLOCK,
                                )
                            } == 0,
                        );
                    }
                    4 => inheritance_value_or_exit(super::super::protect::replace_coordinator_fd(
                        bindings.coordinator.fd(),
                        replacement.as_raw_fd(),
                    )),
                    _ => unsafe { libc::_exit(73) },
                }
                let changed = inheritance_value_or_exit(FdIdentity::read(bindings.detlog().fd()));
                inheritance_check_or_exit(lease.revalidate().is_err());
                inheritance_check_or_exit(lease.cancel().is_err());
                inheritance_check_or_exit(
                    inheritance_value_or_exit(FdIdentity::read(bindings.detlog().fd())) == changed,
                );
                inheritance_check_or_exit(
                    unsafe {
                        libc::send(
                            witness.as_raw_fd(),
                            (&raw const witness_byte).cast(),
                            1,
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    } == 1,
                );
                drop(lease);
                unsafe { libc::_exit(73) }
            });
            check_packet(witness_peer.as_raw_fd(), witness_byte);
        }
    }

    #[test]
    fn native_socket_inheritance_abandonment_remains_terminal() {
        let (witness, witness_peer) = seqpacket();
        isolated(122, || {
            let (bindings, _peers) = socket_fixture();
            let mut lease = inheritance_value_or_exit(unsafe { BootstrapFdLease::reserve() });
            inheritance_value_or_exit(lease.prepare_socket_inheritance(bindings));
            let witness_byte = 0xf5_u8;
            inheritance_check_or_exit(
                unsafe {
                    libc::send(
                        witness.as_raw_fd(),
                        (&raw const witness_byte).cast(),
                        1,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                } == 1,
            );
            drop(lease);
            unsafe { libc::_exit(73) }
        });
        check_packet(witness_peer.as_raw_fd(), 0xf5);
    }

    #[test]
    fn native_socket_capture_follows_real_protected_output_relocation() {
        isolated(0, || {
            let (bindings, _peers) = socket_fixture();
            assert!(
                NativeExecSocketBindings::capture((0, 0), object(bindings.observer().identity()))
                    .is_err()
            );
            bindings.revalidate_original().unwrap();
            let source = memory();
            let mut duplicate = event(libc::SYS_dup2, source.as_raw_fd() as u64);
            duplicate.args[1] = bindings.detlog().fd() as u64;
            assert!(!unsafe {
                super::super::protect::protect_runtime_descriptors(&mut duplicate, true)
            });
            assert_eq!(
                unsafe { libc::dup2(source.as_raw_fd(), bindings.detlog().fd()) },
                bindings.detlog().fd()
            );
            let guest_identity = FdIdentity::read(bindings.detlog().fd()).unwrap();
            assert!(bindings.revalidate_original().is_err());
            let current = NativeExecSocketBindings::capture(
                object(bindings.detlog().identity()),
                object(bindings.observer().identity()),
            )
            .unwrap();
            assert_ne!(current.detlog().fd(), bindings.detlog().fd());
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            assert!(lease.prepare_socket_inheritance(bindings).is_err());
            lease.prepare_socket_inheritance(current).unwrap();
            lease.cancel().unwrap();
            current.revalidate_original().unwrap();
            assert_eq!(
                FdIdentity::read(bindings.detlog().fd()).unwrap(),
                guest_identity
            );
            assert_eq!(unsafe { libc::close(bindings.detlog().fd()) }, 0);
        });
    }

    #[test]
    fn native_socket_capture_rejects_current_coordinator_alias() {
        isolated(0, || {
            let (detlog, _detlog_peer) = seqpacket();
            let (observer, _observer_peer) = seqpacket();
            let detlog_object = object(FdIdentity::read(detlog.as_raw_fd()).unwrap());
            let observer_object = object(FdIdentity::read(observer.as_raw_fd()).unwrap());
            let output = unsafe {
                super::super::protect::reserve_tool_output_fd(detlog.into_raw_fd(), b"retired")
            }
            .unwrap();
            unsafe { reserve_socket(NativeSocket::Observer, observer.into_raw_fd()) }.unwrap();
            let (provider, _provider_peer) = seqpacket();
            unsafe { reserve_socket(NativeSocket::Provider, provider.into_raw_fd()) }.unwrap();
            super::super::protect::reserve_coordinator_fd(output).unwrap();
            let before = FdIdentity::read(output).unwrap();
            assert!(NativeExecSocketBindings::capture(detlog_object, observer_object).is_err());
            assert_eq!(FdIdentity::read(output).unwrap(), before);
        });
    }

    #[test]
    fn native_fd_socket_roles_are_distinct_protected_and_keep_inheritance_flags() {
        isolated(0, || {
            let (observer, _observer_peer) = UnixStream::pair().unwrap();
            let (provider, _provider_peer) = UnixStream::pair().unwrap();
            let observer =
                unsafe { reserve_socket(NativeSocket::Observer, observer.into_raw_fd()) }.unwrap();
            let provider =
                unsafe { reserve_socket(NativeSocket::Provider, provider.into_raw_fd()) }.unwrap();
            assert_ne!(observer, provider);
            assert_eq!(FdIdentity::read(observer).unwrap().descriptor_flags, 0);
            assert_eq!(
                FdIdentity::read(provider).unwrap().descriptor_flags,
                libc::FD_CLOEXEC
            );
            for fd in [observer, provider] {
                for number in [
                    libc::SYS_read,
                    libc::SYS_write,
                    libc::SYS_sendmsg,
                    libc::SYS_fstat,
                    libc::SYS_fcntl,
                ] {
                    let mut ev = event(number, fd as u64 | (1 << 32));
                    assert!(unsafe {
                        super::super::protect::protect_runtime_descriptors(&mut ev, true)
                    });
                    assert_eq!(ev.result, -i64::from(libc::EBADF));
                }
                let original = FdIdentity::read(fd).unwrap();
                let mut ev = event(libc::SYS_close, fd as u64);
                assert!(unsafe {
                    super::super::protect::protect_runtime_descriptors(&mut ev, true)
                });
                assert_eq!(ev.result, -i64::from(libc::EBADF));
                assert_eq!(FdIdentity::read(fd).unwrap(), original);
            }
            let (extra, _peer) = UnixStream::pair().unwrap();
            assert!(unsafe { reserve_socket(NativeSocket::Observer, extra.as_raw_fd()) }.is_err());
            assert!(FdIdentity::read(extra.as_raw_fd()).is_ok());
            let regular = memory();
            assert!(
                unsafe { reserve_socket(NativeSocket::Provider, regular.as_raw_fd()) }.is_err()
            );
            assert!(FdIdentity::read(regular.as_raw_fd()).is_ok());
        });
    }

    #[test]
    fn native_fd_collision_keeps_guest_file_bytes_flags_and_slots_unchanged() {
        isolated(0, || {
            let guest = memory();
            assert_eq!(
                unsafe { libc::write(guest.as_raw_fd(), b"owned".as_ptr().cast(), 5) },
                5
            );
            assert_eq!(
                unsafe { libc::dup3(guest.as_raw_fd(), 200, libc::O_CLOEXEC) },
                200
            );
            let before = FdIdentity::read(200).unwrap();
            assert!(unsafe { BootstrapFdLease::reserve() }.is_err());
            assert_eq!(FdIdentity::read(200).unwrap(), before);
            let mut bytes = [0u8; 5];
            assert_eq!(
                unsafe { libc::pread(200, bytes.as_mut_ptr().cast(), 5, 0) },
                5
            );
            assert_eq!(&bytes, b"owned");
            assert!(!LEASE_ACTIVE.load(Ordering::Acquire));
            for fd in [198, 199, 201, 202] {
                assert!(FdIdentity::read(fd).is_err());
            }
            assert_eq!(unsafe { libc::close(200) }, 0);
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            lease.cancel().unwrap();
        });
    }

    #[test]
    fn native_fd_exact_install_and_cancellation_preserve_source_ofds() {
        isolated(0, || {
            let sources: [OwnedFd; 5] = std::array::from_fn(|_| memory());
            let fds = std::array::from_fn(|index| sources[index].as_raw_fd());
            let expected: [_; 5] =
                std::array::from_fn(|index| FdIdentity::read(fds[index]).unwrap());
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            assert!(unsafe { BootstrapFdLease::reserve() }.is_err());
            for fd in 198..=202 {
                assert_eq!(
                    FdIdentity::read(fd).unwrap().descriptor_flags,
                    libc::FD_CLOEXEC
                );
                let original = FdIdentity::read(fd).unwrap();
                let mut ev = event(libc::SYS_close, fd as u64);
                assert!(unsafe {
                    super::super::protect::protect_runtime_descriptors(&mut ev, true)
                });
                assert_eq!(ev.result, -i64::from(libc::EBADF));
                assert_eq!(FdIdentity::read(fd).unwrap(), original);
            }
            unsafe { lease.install(fds) }.unwrap();
            lease.revalidate().unwrap();
            for index in 0..5 {
                assert_eq!(
                    FdIdentity::read(198 + index as i32).unwrap(),
                    FdIdentity {
                        descriptor_flags: 0,
                        ..expected[index]
                    }
                );
                assert_eq!(FdIdentity::read(fds[index]).unwrap(), expected[index]);
            }
            assert!(unsafe { lease.install(fds) }.is_err());
            lease.cancel().unwrap();
            assert!(!LEASE_ACTIVE.load(Ordering::Acquire));
            for fd in 198..=202 {
                assert!(FdIdentity::read(fd).is_err());
            }
            for index in 0..5 {
                assert_eq!(FdIdentity::read(fds[index]).unwrap(), expected[index]);
            }
            assert!(lease.cancel().is_err());
        });
    }

    #[test]
    fn native_fd_partial_install_failure_reclaims_exact_owned_entries() {
        isolated(0, || {
            let sources: [OwnedFd; 5] = std::array::from_fn(|_| memory());
            let fds = std::array::from_fn(|index| sources[index].as_raw_fd());
            let expected: [_; 5] =
                std::array::from_fn(|index| FdIdentity::read(fds[index]).unwrap());
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            let placeholders = lease.current;
            // The kernel accepts targets 198..200, then rejects target 201.
            // Already-open descriptors above the limit remain queryable.
            let mut limits: libc::rlimit = unsafe { core::mem::zeroed() };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
                0
            );
            assert!(limits.rlim_cur >= 203);
            limits.rlim_cur = 201;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
            assert!(unsafe { lease.install(fds) }.is_err());
            assert!(lease.installed);
            lease.revalidate().unwrap();
            for index in 0..5 {
                let installed = if index < 3 {
                    FdIdentity {
                        descriptor_flags: 0,
                        ..expected[index]
                    }
                } else {
                    placeholders[index].unwrap()
                };
                assert_eq!(lease.current[index], Some(installed));
                assert_eq!(FdIdentity::read(198 + index as i32).unwrap(), installed);
                assert_eq!(FdIdentity::read(fds[index]).unwrap(), expected[index]);
            }
            let after_failure = lease.current;
            assert!(unsafe { lease.install(fds) }.is_err());
            assert_eq!(lease.current, after_failure);
            lease.cancel().unwrap();
            assert!(!LEASE_ACTIVE.load(Ordering::Acquire));
            for fd in 198..=202 {
                assert!(FdIdentity::read(fd).is_err());
            }
            for index in 0..5 {
                assert_eq!(FdIdentity::read(fds[index]).unwrap(), expected[index]);
            }
        });
    }

    #[test]
    fn native_fd_install_refuses_alias_and_unprotected_source_before_replacement() {
        isolated(0, || {
            let sources: [OwnedFd; 5] = std::array::from_fn(|_| memory());
            let fds = std::array::from_fn(|index| sources[index].as_raw_fd());
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            let before = lease.current;
            let mut alias = fds;
            alias[0] = 198;
            assert!(unsafe { lease.install(alias) }.is_err());
            alias = fds;
            alias[1] = fds[0];
            assert!(unsafe { lease.install(alias) }.is_err());
            assert_eq!(unsafe { libc::fcntl(fds[3], libc::F_SETFD, 0) }, 0);
            assert!(unsafe { lease.install(fds) }.is_err());
            assert_eq!(lease.current, before);
            lease.revalidate().unwrap();
            lease.cancel().unwrap();
        });
    }

    #[test]
    fn native_fd_tampered_identity_is_terminal_and_never_closed_as_owned() {
        isolated(122, || {
            let mut lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            let replacement = memory();
            assert_eq!(
                unsafe { libc::dup3(replacement.as_raw_fd(), 201, libc::O_CLOEXEC) },
                201
            );
            let changed = FdIdentity::read(201).unwrap();
            assert!(lease.revalidate().is_err());
            assert!(lease.cancel().is_err());
            assert_eq!(FdIdentity::read(201).unwrap(), changed);
            drop(lease);
            panic!("armed ownership failure must terminate");
        });
    }

    #[test]
    fn native_fd_abandoned_lease_terminates_instead_of_releasing_to_guest() {
        isolated(122, || {
            let lease = unsafe { BootstrapFdLease::reserve() }.unwrap();
            drop(lease);
            panic!("abandonment must terminate");
        });
    }
}
