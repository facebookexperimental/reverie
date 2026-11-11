/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Native-callback connection ownership over the common blocking transport.
//!
//! A primary connection is moved out under a short owner lock. The returned
//! lease owns its descriptor through I/O; no process lock spans that I/O. A
//! concurrent application callback opens the existing independent connection,
//! rather than waiting for the primary. A cached connection never contains a
//! callback pointer. The published primary descriptor number stays occupied
//! until image/process retirement, including after an unusable capture frame.

use std::io;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RpcError;
use reverie_rpc_transport::RpcRequest;
use reverie_rpc_transport::RpcResponse;
use reverie_rpc_transport::read_config_frame;

use super::host::native_state::NativeThreadIdentity;
use crate::sync::SpinMutex;

/// A synchronous native application syscall, with the original injection
/// purpose in its fourth argument. The context is borrowed for one callback.
pub type NativeInvoker = unsafe extern "C" fn(usize, i64, *const u64, u32) -> i64;

/// Checks the actual live native image/thread before any context operation.
/// This must be safe to call from a different thread and return zero there,
/// without touching that thread's application context or Rust TLS.
pub type NativeCurrent = unsafe extern "C" fn(usize) -> i32;

/// A native invocation context borrowed from its actual image/thread owner.
/// Neither this value nor its pointer is stored in a connection cache.
#[derive(Clone, Copy)]
pub struct NativeInvocation<'callback> {
    context: usize,
    invoke: NativeInvoker,
    current: NativeCurrent,
    identity: NativeThreadIdentity,
    _callback: PhantomData<&'callback ()>,
}

impl<'callback> NativeInvocation<'callback> {
    /// Borrow the original live native callback, not a reconstructed context.
    ///
    /// # Safety
    /// The caller owns the admitted image/thread and must validate the live
    /// service table, image generation and actual physical identities before
    /// entry. `invoke` must synchronously preserve all syscall arguments,
    /// purpose, native bookkeeping and raw Linux result; it must not retain
    /// pointers. The context and its native/TLS/allocator owner must outlive
    /// `'callback`. This grants no initial-image or successor authority.
    pub unsafe fn from_admitted(
        context: usize,
        invoke: NativeInvoker,
        current: NativeCurrent,
        identity: NativeThreadIdentity,
    ) -> Self {
        Self {
            context,
            invoke,
            current,
            identity,
            _callback: PhantomData,
        }
    }

    /// Facts checked by the owner of this actual callback.
    pub fn identity(self) -> NativeThreadIdentity {
        self.identity
    }

    pub(super) fn context(self) -> usize {
        self.context
    }

    /// Check the real native task/image owner, including if a Send future was
    /// accidentally moved. A numeric or serialized thread fact is not enough.
    pub fn ensure_current(self) -> io::Result<()> {
        if unsafe { (self.current)(self.context) } == 1 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::ESTALE))
        }
    }

    /// Issue a Tool-owned operation through the original native mechanism.
    ///
    /// # Safety
    /// All pointed-to operands must remain valid for the native syscall's
    /// synchronous use, and its effects must respect Rust memory invariants.
    pub unsafe fn invoke(
        self,
        number: i64,
        arguments: [u64; 6],
        purpose: reverie::InjectionPurpose,
    ) -> i64 {
        if self.ensure_current().is_err() {
            return -i64::from(libc::ESTALE);
        }
        unsafe { (self.invoke)(self.context, number, arguments.as_ptr(), purpose as u32) }
    }

    fn io(self, number: i64, arguments: [u64; 6]) -> io::Result<i64> {
        let value =
            unsafe { self.invoke(number, arguments, reverie::InjectionPurpose::Application) };
        if value < 0 {
            Err(io::Error::from_raw_os_error((-value) as i32))
        } else {
            Ok(value)
        }
    }
}

struct Connection {
    pid: Pid,
    fd: i32,
    usable: bool,
}

enum Primary {
    Available {
        connection: Option<Connection>,
        // The old mutex-poison recovery replaces the socket after unwinding
        // during a primary exchange. A capture framing failure is different:
        // connection.usable=false is terminal for this image and is not reset.
        recover: bool,
    },
    Leased {
        sequence: u64,
    },
}

struct State {
    next: u64,
    primary: Primary,
}

enum Destination<G: GlobalTool> {
    Coordinator(PathBuf),
    Local(Arc<G>),
}

impl<G: GlobalTool> Destination<G> {
    fn coordinator(&self) -> io::Result<&Path> {
        match self {
            Self::Coordinator(path) => Ok(path),
            Self::Local(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the selected native RPC owner is an in-process GlobalTool",
            )),
        }
    }
}

/// One native image's explicitly selected GlobalTool route.
///
/// The caller supplies the already authenticated configuration and concrete
/// path, or the actual in-process GlobalTool. No environment lookup or route
/// fallback is selected by application callbacks. Local is a launch choice,
/// never recovery from failed coordinator I/O.
pub struct NativeRpc<G: GlobalTool> {
    state: SpinMutex<State>,
    descriptor: AtomicU64,
    destination: Destination<G>,
    config: Arc<G::Config>,
}

impl<G: GlobalTool> NativeRpc<G> {
    /// Retain the concrete coordinator route and its authoritative config.
    pub fn new(path: PathBuf, config: Arc<G::Config>) -> io::Result<Self> {
        let _ = unix_address(&path)?;
        Ok(Self::with_destination(
            Destination::Coordinator(path),
            config,
        ))
    }

    /// The actual standalone image's existing in-process GlobalTool. Its async
    /// receive_rpc is awaited directly; no request is encoded or sent through
    /// an invented descriptor. The launch owner retains the same config Arc.
    pub fn local(global: Arc<G>, config: Arc<G::Config>) -> Self {
        Self::with_destination(Destination::Local(global), config)
    }

    fn with_destination(destination: Destination<G>, config: Arc<G::Config>) -> Self {
        Self {
            state: SpinMutex::new(State {
                next: 1,
                primary: Primary::Available {
                    connection: None,
                    recover: false,
                },
            }),
            descriptor: AtomicU64::new(0),
            destination,
            config,
        }
    }

    /// The same authoritative config allocation retained at construction.
    pub fn shared_config(&self) -> &Arc<G::Config> {
        &self.config
    }

    /// Fresh connection storage for the checked independent copied process.
    /// The caller owns the actual affine returning operation and has checked
    /// its admitted child against `parent`; numeric identities alone do not
    /// establish that boundary. Never acquire the inherited primary lock.
    ///
    /// The original published number remains occupied. The existing prepare
    /// path connects/reads the real configuration frame and dup3-replaces the
    /// inherited stream there before any child Tool callback. It never reads
    /// inherited framing or lets an old Drop close the replacement socket.
    pub(super) fn for_copied_coordinator(
        &self,
        parent: NativeThreadIdentity,
        invocation: NativeInvocation<'_>,
    ) -> io::Result<(Self, super::rpc::CoordinatorRpc<G>)> {
        invocation.ensure_current()?;
        let child = invocation.identity();
        if child.physical_pid() == parent.physical_pid()
            || child.physical_pid() != child.physical_tid()
        {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        // A copied in-process GlobalTool may itself contain inherited locks.
        // It keeps its maintained closed copied-operation path, not a new
        // GlobalTool or a fabricated coordinator fallback.
        let path = self.destination.coordinator()?.to_path_buf();
        let fact = self.descriptor.load(Ordering::Acquire);
        let connection = if fact == 0 {
            None
        } else {
            let fd = fact as u32 as i32;
            if fact >> 32 != parent.physical_pid().as_raw() as u64 || fd < 1024 {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
            Some(Connection {
                pid: parent.physical_pid(),
                fd,
                // No old framing is usable in the child. Its different
                // actual PID drives the existing authenticated reconnect.
                usable: false,
            })
        };
        let cache =
            super::rpc::CoordinatorRpc::from_native_configuration(&path, Arc::clone(&self.config))?;
        let owner = Self {
            state: SpinMutex::new(State {
                next: 1,
                primary: Primary::Available {
                    connection,
                    recover: false,
                },
            }),
            descriptor: AtomicU64::new(fact),
            destination: Destination::Coordinator(path),
            config: Arc::clone(&self.config),
        };
        invocation.ensure_current()?;
        Ok((owner, cache))
    }

    /// The protected live numeric descriptor fact, including while leased.
    pub fn descriptor(&self, physical_pid: Pid) -> Option<i32> {
        let fact = self.descriptor.load(Ordering::Acquire);
        (physical_pid.as_raw() > 0 && fact >> 32 == physical_pid.as_raw() as u64)
            .then_some(fact as u32 as i32)
    }

    /// Existing descriptor protection, independent of whether the primary is
    /// currently leased by another callback. Close requests still reach the
    /// Tool first for its own accounting; the actual injected operation spares
    /// the same reserved descriptor.
    pub fn protect_operation(
        &self,
        invocation: NativeInvocation<'_>,
        number: i64,
        args: &[u64; 6],
        before_tool: bool,
    ) -> Option<i64> {
        use reverie::syscalls::reserved_fds;
        let fd = self.descriptor(invocation.identity.physical_pid())? as u64;
        if before_tool && matches!(number, libc::SYS_close | libc::SYS_close_range) {
            return None;
        }
        if number == libc::SYS_close && reserved_fds::descriptor_arg(args, 0) == fd {
            Some(-i64::from(libc::EBADF))
        } else if number == libc::SYS_close_range && reserved_fds::close_range_covers(args, &[fd]) {
            Some(unsafe {
                reserved_fds::close_range_sparing(args, &[fd], |number, args| {
                    invocation.invoke(number, args, reverie::InjectionPurpose::Application)
                })
            })
        } else if let Some(result) = reserved_fds::epoll_wait_result(number, args, fd) {
            Some(result)
        } else if reserved_fds::names_descriptor(number, args, fd)
            || reserved_fds::socket_call_names_descriptor(number, args, fd)
        {
            Some(-i64::from(libc::EBADF))
        } else {
            None
        }
    }

    /// Borrow this callback's native route. The context is never cached.
    pub fn application<'callback>(
        &'callback self,
        invocation: NativeInvocation<'callback>,
    ) -> NativeApplicationRpc<'callback, G> {
        NativeApplicationRpc {
            owner: self,
            invocation,
        }
    }

    fn take_primary(&self) -> io::Result<Option<PrimaryLease<'_, G>>> {
        let Some(mut state) = self.state.try_lock() else {
            return Ok(None);
        };
        if matches!(state.primary, Primary::Leased { .. }) {
            return Ok(None);
        }
        let sequence = state.next;
        state.next = sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let Primary::Available {
            connection,
            recover,
        } = std::mem::replace(&mut state.primary, Primary::Leased { sequence })
        else {
            unreachable!("available owner checked under this short lock")
        };
        drop(state);
        Ok(Some(PrimaryLease {
            owner: self,
            sequence,
            connection,
            recover,
            finished: false,
        }))
    }

    /// Take the same exclusive primary connection for native mapping capture.
    /// No path lookup, connect, dup, recovery, waiting or fallback occurs here.
    pub fn borrow_mapping_capture_primary(
        &self,
        physical_pid: Pid,
    ) -> Result<MappingCapturePrimary<'_, G>, reverie::MappingCaptureError> {
        if matches!(self.destination, Destination::Local(_)) {
            return Err(reverie::MappingCaptureError::Connection);
        }
        let mut lease = self
            .take_primary()
            .map_err(|_| reverie::MappingCaptureError::Connection)?
            .ok_or(reverie::MappingCaptureError::Connection)?;
        // A refused borrow did not start an exchange or poison framing.
        lease.finished = true;
        let Some(connection) = lease.connection.as_ref() else {
            return Err(reverie::MappingCaptureError::Connection);
        };
        if lease.recover
            || connection.pid != physical_pid
            || !connection.usable
            || self.descriptor(physical_pid) != Some(connection.fd)
        {
            return Err(reverie::MappingCaptureError::Connection);
        }
        Ok(MappingCapturePrimary { lease: Some(lease) })
    }

    /// Prepare the primary before a real admitted Tool entry. If another
    /// callback owns it, preserve the existing independent exchange route.
    pub fn prepare(&self, invocation: NativeInvocation<'_>) -> io::Result<()> {
        invocation.ensure_current()?;
        if matches!(self.destination, Destination::Local(_)) {
            return Ok(());
        }
        let Some(mut primary) = self.take_primary()? else {
            return Ok(());
        };
        primary.ensure(invocation)?;
        primary.finished = true;
        Ok(())
    }
}

struct PrimaryLease<'owner, G: GlobalTool> {
    owner: &'owner NativeRpc<G>,
    sequence: u64,
    connection: Option<Connection>,
    recover: bool,
    finished: bool,
}

impl<G: GlobalTool> PrimaryLease<'_, G> {
    fn ensure(&mut self, invocation: NativeInvocation<'_>) -> io::Result<()> {
        let pid = invocation.identity.physical_pid();
        if self
            .connection
            .as_ref()
            .is_some_and(|c| c.pid == pid && !c.usable)
        {
            return Err(io::Error::other(
                "primary stream retired after mapping capture failure",
            ));
        }
        if self.recover || !self.connection.as_ref().is_some_and(|c| c.pid == pid) {
            let mut replacement = connect(invocation, self.owner.destination.coordinator()?)?;
            if let Some(old) = self.connection.as_ref() {
                // Keep the published number occupied. The unique lease, not
                // an owner mutex across I/O, excludes every primary user.
                let installed = invocation.io(
                    libc::SYS_dup3,
                    [
                        replacement.fd as u64,
                        old.fd as u64,
                        libc::O_CLOEXEC as u64,
                        0,
                        0,
                        0,
                    ],
                );
                close(invocation, replacement.fd);
                installed?;
                replacement.fd = old.fd;
            }
            let fd = replacement.fd;
            self.connection = Some(replacement);
            self.recover = false;
            self.owner.descriptor.store(
                ((pid.as_raw() as u64) << 32) | u64::from(fd as u32),
                Ordering::Release,
            );
        }
        Ok(())
    }
}

impl<G: GlobalTool> Drop for PrimaryLease<'_, G> {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock();
        assert!(
            matches!(state.primary, Primary::Leased { sequence } if sequence == self.sequence),
            "native primary lease no longer owns its original generation"
        );
        state.primary = Primary::Available {
            connection: self.connection.take(),
            recover: self.recover || !self.finished,
        };
    }
}

/// A capture's exclusive primary owner, returned before caller unmasking.
/// The native operation receives only its stack-borrowed release cookie.
pub struct MappingCapturePrimary<'owner, G: GlobalTool> {
    lease: Option<PrimaryLease<'owner, G>>,
}

impl<G: GlobalTool> MappingCapturePrimary<'_, G> {
    /// The original protected descriptor; no duplicate is created.
    pub fn fd(&self) -> i32 {
        self.lease
            .as_ref()
            .expect("live capture lease")
            .connection
            .as_ref()
            .expect("validated capture connection")
            .fd
    }

    /// Whether the real native release callback has consumed this lease.
    pub fn is_released(&self) -> bool {
        self.lease.is_none()
    }

    /// Return ownership exactly once, retiring unusable framing permanently.
    /// This performs no Tool call, close, allocation or deserialization.
    pub fn release(&mut self, usable: bool) {
        if let Some(mut lease) = self.lease.take() {
            if !usable {
                lease
                    .connection
                    .as_mut()
                    .expect("validated capture connection")
                    .usable = false;
            }
            lease.finished = true;
            drop(lease);
        }
    }
}

impl<G: GlobalTool> Drop for MappingCapturePrimary<'_, G> {
    fn drop(&mut self) {
        // Missing native release is not successful framing. Keep its number
        // protected but make later capture/RPC refuse, just like usable=0.
        self.release(false);
    }
}

/// The exact stack-borrowed release callback passed to native capture.
///
/// # Safety
/// `cookie` is the live, uniquely borrowed MappingCapturePrimary supplied to
/// this synchronous native transaction. The native operation calls it once,
/// after restoring helpers and before restoring its caller's signal mask.
pub unsafe extern "C" fn release_mapping_capture_primary<G: GlobalTool>(
    cookie: usize,
    usable: i32,
) {
    let lease = unsafe { &mut *(cookie as *mut MappingCapturePrimary<'_, G>) };
    lease.release(usable == 1);
}

/// A single callback's common GlobalRPC view, using actual native I/O.
pub struct NativeApplicationRpc<'callback, G: GlobalTool> {
    owner: &'callback NativeRpc<G>,
    invocation: NativeInvocation<'callback>,
}

impl<G: GlobalTool> NativeApplicationRpc<'_, G> {
    pub(super) fn owner(&self) -> &NativeRpc<G> {
        self.owner
    }
    pub(super) fn invocation(&self) -> NativeInvocation<'_> {
        self.invocation
    }

    /// Serialize before acquiring the primary, then release/close the actual
    /// connection before any response deserializer can reenter Tool code.
    pub fn exchange(&self, message: G::Request) -> Result<G::Response, RpcError> {
        self.invocation.ensure_current()?;
        let path = self.owner.destination.coordinator()?;
        let request = RpcRequest::<G>::new(self.invocation.identity.tid(), message)?;
        let response = if let Some(mut primary) = self.owner.take_primary()? {
            primary.ensure(self.invocation)?;
            let fd = primary.connection.as_ref().expect("initialized primary").fd;
            let response = round_trip::<G>(self.invocation, fd, &self.owner.config, request);
            if response.is_ok() {
                primary.finished = true;
            }
            drop(primary);
            response
        } else {
            let connection = connect(self.invocation, path)?;
            let response =
                round_trip::<G>(self.invocation, connection.fd, &self.owner.config, request);
            close(self.invocation, connection.fd);
            response
        }?;
        response.decode()
    }
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for NativeApplicationRpc<'_, G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        if let Destination::Local(global) = &self.owner.destination {
            self.invocation
                .ensure_current()
                .expect("native local RPC task changed");
            let response = global
                .receive_rpc(self.invocation.identity.tid(), message)
                .await;
            self.invocation
                .ensure_current()
                .expect("native local RPC task changed");
            response
        } else {
            self.exchange(message)
                .expect("native coordinator round trip failed")
        }
    }
    fn try_send_rpc_sync(&self, message: G::Request) -> Result<G::Response, G::Request> {
        if matches!(self.owner.destination, Destination::Local(_)) {
            // The maintained local GlobalTool route is asynchronous. Do not
            // turn a possibly pending receive_rpc into a claimed sync reply.
            return Err(message);
        }
        Ok(self
            .exchange(message)
            .expect("native coordinator round trip failed"))
    }
    fn config(&self) -> &G::Config {
        &self.owner.config
    }
}

struct NativeIo<'callback> {
    invocation: NativeInvocation<'callback>,
    fd: i32,
}

impl Read for NativeIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.invocation
            .io(
                libc::SYS_read,
                [
                    self.fd as u64,
                    bytes.as_mut_ptr() as u64,
                    bytes.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
            .map(|n| n as usize)
    }
}
impl Write for NativeIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.invocation
            .io(
                libc::SYS_write,
                [
                    self.fd as u64,
                    bytes.as_ptr() as u64,
                    bytes.len() as u64,
                    0,
                    0,
                    0,
                ],
            )
            .map(|n| n as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn round_trip<G: GlobalTool>(
    invocation: NativeInvocation<'_>,
    fd: i32,
    config: &G::Config,
    request: RpcRequest<G>,
) -> Result<RpcResponse<G>, RpcError> {
    let mut stream = NativeIo { invocation, fd };
    BlockingRpcClient::<G>::from_borrowed_stream(&mut stream, invocation.identity.tid(), config)
        .receive_response(request)
}

fn connect(invocation: NativeInvocation<'_>, path: &Path) -> io::Result<Connection> {
    // Validate before acquiring a descriptor; a NUL may not shorten the route.
    let address = unix_address(path)?;
    let length =
        std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.as_os_str().as_bytes().len() + 1;
    let mut fd = invocation.io(
        libc::SYS_socket,
        [
            libc::AF_UNIX as u64,
            (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64,
            0,
            0,
            0,
            0,
        ],
    )? as i32;
    let result = (|| {
        if fd < 1024 {
            let relocated = invocation.io(
                libc::SYS_fcntl,
                [fd as u64, libc::F_DUPFD_CLOEXEC as u64, 1024, 0, 0, 0],
            )? as i32;
            close(invocation, fd);
            fd = relocated;
        }
        invocation.io(
            libc::SYS_connect,
            [
                fd as u64,
                (&address as *const libc::sockaddr_un) as u64,
                length as u64,
                0,
                0,
                0,
            ],
        )?;
        let mut stream = NativeIo { invocation, fd };
        let _config = read_config_frame(&mut stream).map_err(io::Error::other)?;
        Ok(Connection {
            pid: invocation.identity.physical_pid(),
            fd,
            usable: true,
        })
    })();
    if result.is_err() {
        close(invocation, fd);
    }
    result
}

fn close(invocation: NativeInvocation<'_>, fd: i32) {
    let _ = invocation.io(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]);
}

fn unix_address(path: &Path) -> io::Result<libc::sockaddr_un> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordinator socket path is empty, contains NUL, or is too long",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (out, byte) in address.sun_path.iter_mut().zip(bytes) {
        *out = *byte as libc::c_char;
    }
    Ok(address)
}

#[cfg(test)]
#[path = "native_rpc_tests.rs"]
mod tests;

// The discriminants start at 1 so that `None` in `ACTIVE_ROUTE` takes the
// zero niche and the thread-local stays zero-initialized (.tbss). A nonzero
// initializer puts it in .tdata, ahead of every .tbss cell in the in-guest
// runtime, which moves the allocator installation-depth cell that the native
// artifact qualifier reads at a fixed TLS offset.
#[derive(Clone, Copy)]
enum RouteKind {
    Application = 1,
    Background = 2,
}

#[derive(Clone, Copy)]
struct ErasedRoute {
    global: std::any::TypeId,
    client: *const (),
    kind: RouteKind,
    tail: *const crate::tool_host::TailResult,
}

std::thread_local! {
    // No destructor and no connection/policy singleton: the live stack scope
    // borrows this callback's selected primary owner and own ending latch.
    static ACTIVE_ROUTE: std::cell::Cell<Option<ErasedRoute>> = const { std::cell::Cell::new(None) };
}

pub(super) struct NativeRpcScope<'callback> {
    previous: Option<ErasedRoute>,
    _borrow: PhantomData<&'callback ()>,
    _same_thread: PhantomData<*mut ()>,
}

impl<'callback> NativeRpcScope<'callback> {
    pub(super) fn enter<G: GlobalTool + 'static>(
        application: &'callback NativeApplicationRpc<'_, G>,
        tail: &'callback crate::tool_host::TailResult,
    ) -> Self {
        let route = ErasedRoute {
            global: std::any::TypeId::of::<G>(),
            client: (application as *const NativeApplicationRpc<'_, G>).cast(),
            kind: RouteKind::Application,
            tail,
        };
        Self {
            previous: ACTIVE_ROUTE.with(|active| active.replace(Some(route))),
            _borrow: PhantomData,
            _same_thread: PhantomData,
        }
    }

    pub(super) fn enter_background<G: GlobalTool + 'static>(
        background: &'callback NativeBackgroundView<'_, G>,
        tail: &'callback crate::tool_host::TailResult,
    ) -> Self {
        let route = ErasedRoute {
            global: std::any::TypeId::of::<G>(),
            client: (background as *const NativeBackgroundView<'_, G>).cast(),
            kind: RouteKind::Background,
            tail,
        };
        Self {
            previous: ACTIVE_ROUTE.with(|active| active.replace(Some(route))),
            _borrow: PhantomData,
            _same_thread: PhantomData,
        }
    }
}
impl Drop for NativeRpcScope<'_> {
    fn drop(&mut self) {
        ACTIVE_ROUTE.with(|active| active.set(self.previous));
    }
}

pub(super) fn callback_ending_staged() -> Option<bool> {
    ACTIVE_ROUTE.with(|active| active.get().map(|route| unsafe { (&*route.tail).ending() }))
}

pub(super) enum NativeGlobalDispatch<G: GlobalTool> {
    Absent(G::Request),
    Handled(io::Result<G::Response>),
}

pub(super) fn dispatch_global<G: GlobalTool + 'static>(
    request: G::Request,
) -> NativeGlobalDispatch<G> {
    let Some(route) = ACTIVE_ROUTE.with(|active| active.get()) else {
        return NativeGlobalDispatch::Absent(request);
    };
    if route.global != std::any::TypeId::of::<G>() {
        return NativeGlobalDispatch::Handled(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the requested global state is not the native callback's",
        )));
    }
    if unsafe { (&*route.tail).ending() } {
        return NativeGlobalDispatch::Handled(Err(io::Error::from_raw_os_error(libc::ESRCH)));
    }
    // NativeRpcScope owns the exact typed borrow until its same-thread drop;
    // TypeId is checked before this erased pointer is interpreted.
    let result = match route.kind {
        RouteKind::Application => {
            let client = unsafe { &*route.client.cast::<NativeApplicationRpc<'_, G>>() };
            if let Destination::Local(global) = &client.owner.destination {
                let tail = unsafe { &*route.tail };
                let result = (|| {
                    client.invocation.ensure_current()?;
                    let response = match crate::tool_host::drive_native_callback(
                        global.receive_rpc(client.invocation.identity.tid(), request),
                        tail,
                    ) {
                        crate::tool_host::NativeCallbackOutcome::Ready(response) => response,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::Unsupported,
                                "native blocking global RPC cannot transfer a tail continuation",
                            ));
                        }
                    };
                    client.invocation.ensure_current()?;
                    Ok(response)
                })();
                return NativeGlobalDispatch::Handled(result);
            }
            client.exchange(request)
        }
        RouteKind::Background => {
            let client = unsafe { &*route.client.cast::<NativeBackgroundView<'_, G>>() };
            if let Destination::Local(global) = &client.owner.destination {
                let result = (|| {
                    client.ensure_current()?;
                    let response = crate::tool_host::drive_native_ready(
                        global.receive_rpc(client.from, request),
                    );
                    client.ensure_current()?;
                    Ok(response)
                })();
                return NativeGlobalDispatch::Handled(result);
            }
            client.exchange(request)
        }
    };
    NativeGlobalDispatch::Handled(result.map_err(|error| io::Error::other(error.to_string())))
}

struct BackgroundConnection {
    pid: u32,
    stream: std::os::unix::net::UnixStream,
}

/// One admitted background thread's ordinary socket owner. This is not the
/// application route: only a native owner with ordinary Rust FS/TLS/allocator
/// access may construct it. Independent owners have independent connections.
/// No application callback may select it as a fallback for failed native I/O.
///
/// Fork note (W7 review): this `std::sync::Mutex` is only ever locked
/// by the owning background thread itself (`ensure_current`), and its
/// critical sections are socket I/O only — the owner never forks
/// inside one. Guest forks, whose child reinitializes copied locks,
/// exist only on the ordinary dispatch path, which native processes
/// never run (ordinary dispatch fatals when `native_threads` is set,
/// and the private exec domains refuse fork before any ordinary
/// fork-child path). A followed child reusing this owner is created
/// by the native owner's own setup, outside any exchange, and
/// reconnects by the pid check below. The mutex therefore needs no
/// fork-child reset.
pub struct NativeBackgroundRpc<G: GlobalTool> {
    thread: std::thread::ThreadId,
    destination: Destination<G>,
    config: Arc<G::Config>,
    connection: std::sync::Mutex<Option<BackgroundConnection>>,
}

impl<G: GlobalTool> NativeBackgroundRpc<G> {
    /// Retain this actual background thread's authenticated coordinator route.
    ///
    /// # Safety
    /// The native initializer/background-entry owner must already have entered
    /// the engine's ordinary Rust FS/TLS, allocator and stack context, with the
    /// supplied live coordinator and authoritative configuration. Application
    /// callback context, a numeric task ID or a requested phase is insufficient.
    /// A followed child may reuse the inherited owner only after its real
    /// background-entry setup; the PID check then reconnects the socket.
    pub unsafe fn from_admitted(path: PathBuf, config: Arc<G::Config>) -> io::Result<Self> {
        let _ = unix_address(&path)?;
        Ok(Self {
            thread: std::thread::current().id(),
            destination: Destination::Coordinator(path),
            config,
            connection: std::sync::Mutex::new(None),
        })
    }

    /// Select the same real in-process GlobalTool on its genuine background
    /// thread. This has the same native entry/allocator/TLS obligations as
    /// from_admitted; it supplies no ordinary/private entry authority.
    ///
    /// # Safety
    /// The original native owner has established this background thread's
    /// actual Rust entry context, and global/config are its retained owners.
    pub unsafe fn local_from_admitted(global: Arc<G>, config: Arc<G::Config>) -> Self {
        Self {
            thread: std::thread::current().id(),
            destination: Destination::Local(global),
            config,
            connection: std::sync::Mutex::new(None),
        }
    }

    /// The same immutable launch configuration as the application owner.
    pub fn shared_config(&self) -> &Arc<G::Config> {
        &self.config
    }

    /// Refuse accidental use from another actual background thread, before
    /// touching a connection. This does not establish native entry authority.
    pub fn ensure_current(&self) -> io::Result<()> {
        if std::thread::current().id() == self.thread {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(libc::ESTALE))
        }
    }

    /// Select the real Tool-visible caller already established by the native
    /// lifecycle owner. It is an RPC envelope fact, not admission authority.
    pub fn for_thread(&self, from: Pid) -> io::Result<NativeBackgroundView<'_, G>> {
        self.ensure_current()?;
        if from.as_raw() <= 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(NativeBackgroundView { owner: self, from })
    }
}

/// A background callback's borrowed RPC view. Its ordinary socket is never
/// shared with the protected application primary or mapping capture.
pub struct NativeBackgroundView<'owner, G: GlobalTool> {
    owner: &'owner NativeBackgroundRpc<G>,
    from: Pid,
}

impl<G: GlobalTool> NativeBackgroundView<'_, G> {
    pub(super) fn shared_config(&self) -> &Arc<G::Config> {
        &self.owner.config
    }
    pub(super) fn ensure_current(&self) -> io::Result<()> {
        self.owner.ensure_current()
    }
    pub(super) fn from(&self) -> Pid {
        self.from
    }

    /// Preserve the background route's per-thread ownership through ordinary
    /// framing/codec work. Reentry refuses instead of waiting for its own I/O;
    /// a different background owner never waits on this connection's mutex.
    pub fn exchange(&self, request: G::Request) -> Result<G::Response, RpcError> {
        self.ensure_current()?;
        let path = self.owner.destination.coordinator()?;
        let mut slot = match self.owner.connection.try_lock() {
            Ok(slot) => slot,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(io::Error::from_raw_os_error(libc::EBUSY).into());
            }
        };
        let pid = std::process::id();
        if !slot
            .as_ref()
            .is_some_and(|connection| connection.pid == pid)
        {
            let mut stream = std::os::unix::net::UnixStream::connect(path)?;
            let _config = read_config_frame(&mut stream)?;
            *slot = Some(BackgroundConnection { pid, stream });
        }
        let connection = slot.as_mut().expect("background connection initialized");
        BlockingRpcClient::<G>::from_borrowed_stream(
            &mut connection.stream,
            self.from,
            &self.owner.config,
        )
        .try_send_rpc(request)
    }
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for NativeBackgroundView<'_, G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        if let Destination::Local(global) = &self.owner.destination {
            self.ensure_current()
                .expect("native local background RPC task changed");
            let response = global.receive_rpc(self.from, message).await;
            self.ensure_current()
                .expect("native local background RPC task changed");
            response
        } else {
            self.exchange(message)
                .expect("background coordinator round trip failed")
        }
    }
    fn try_send_rpc_sync(&self, message: G::Request) -> Result<G::Response, G::Request> {
        if matches!(self.owner.destination, Destination::Local(_)) {
            return Err(message);
        }
        Ok(self
            .exchange(message)
            .expect("background coordinator round trip failed"))
    }
    fn config(&self) -> &G::Config {
        &self.owner.config
    }
}
