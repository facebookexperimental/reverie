/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! DynamoRIO connection ownership over the shared blocking RPC client.
//!
//! Background callbacks retain a thread-local Unix socket. Application callbacks
//! use the native syscall invoker because ordinary Rust socket/TLS operations
//! are not safe in DynamoRIO's private loader. Both paths borrow
//! [`reverie_rpc_transport::BlockingRpcClient`] for each exchange; envelope,
//! codec, framing, limits and partial-I/O policy live in the shared transport.
//!
//! The current callback supplies its TID and I/O context for that borrow only.
//! Cached connections retain descriptors, process identity and socket path,
//! never a callback context. A fork child reconnects before its first request;
//! inherited contended locks use the existing uncached-connection path.
//!
//! [`read_initial_config`] uses a separate temporary background-owned socket.
//! It requires an exact config payload, sends no request, and retires its FD
//! before returning. It does not adopt an application RPC connection.

use std::cell::RefCell;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::TryLockError;

use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RpcError;
use reverie_rpc_transport::RpcRequest;
use reverie_rpc_transport::RpcResponse;
#[cfg(test)]
use reverie_rpc_transport::codec::DEFAULT_MAX_FRAME_LEN;
use reverie_rpc_transport::codec::decode_exact;
use reverie_rpc_transport::read_config_frame;
#[cfg(test)]
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::SyscallInvoker;

/// Environment variable naming the coordinator's Unix-domain socket path. Set
/// by the coordinator (which hosts the [`reverie_rpc_transport::RpcServer`])
/// before launching the guest. DynamoRIO hides it from the guest and passes it
/// to followed exec children; the client keeps its own copy across `fork`.
pub const RPC_SOCKET_ENV: &str = "HERMIT_DBT_RPC_SOCKET";

#[cfg(test)]
const MAX_FRAME_LEN: usize = DEFAULT_MAX_FRAME_LEN;

/// Primary failure while receiving an authoritative initial configuration.
///
/// Diagnostics name the operation without printing configuration bytes. The
/// original I/O or decoding error remains available for inspection.
#[derive(Debug)]
pub enum InitialConfigFailure {
    /// The filesystem socket address is empty, too long, or contains a NUL.
    Address(io::Error),
    /// Creating the temporary socket failed; no descriptor was acquired.
    Socket(io::Error),
    /// Connecting the owned temporary socket failed.
    Connect(io::Error),
    /// Reading the complete frame header or payload failed.
    Read(io::Error),
    /// The announced frame exceeds the existing 16 MiB transport limit.
    FrameTooLarge,
    /// The complete payload cannot be decoded using the legacy codec.
    Decode(bincode::error::DecodeError),
    /// Decoding left bytes after the configuration in the announced payload.
    TrailingBytes,
}

impl fmt::Display for InitialConfigFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Address(_) => "invalid coordinator socket address",
            Self::Socket(_) => "creating coordinator socket failed",
            Self::Connect(_) => "connecting coordinator socket failed",
            Self::Read(_) => "reading initial configuration frame failed",
            Self::FrameTooLarge => "initial configuration frame exceeds the transport limit",
            Self::Decode(_) => "decoding initial configuration failed",
            Self::TrailingBytes => "initial configuration has trailing bytes",
        })
    }
}

impl std::error::Error for InitialConfigFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Address(error)
            | Self::Socket(error)
            | Self::Connect(error)
            | Self::Read(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::FrameTooLarge | Self::TrailingBytes => None,
        }
    }
}

/// Initial configuration failure and the result of retiring its temporary FD.
///
/// A close failure does not replace an earlier receive failure. A successful
/// receive with a failed close is also an error, so no configuration is
/// returned while retirement remains unqualified.
#[derive(Debug)]
pub struct InitialConfigError {
    /// Original address, socket, connect, read, or decode failure, if any.
    pub primary: Option<InitialConfigFailure>,
    /// Error from the single consumed close attempt, if any.
    pub close: Option<io::Error>,
}

impl fmt::Display for InitialConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.primary {
            Some(primary) => primary.fmt(formatter)?,
            None => formatter.write_str("closing initial configuration socket failed")?,
        }
        if self.primary.is_some() && self.close.is_some() {
            formatter.write_str("; closing its socket also failed")?;
        }
        Ok(())
    }
}

impl std::error::Error for InitialConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.primary
            .as_ref()
            .map(|primary| primary as &(dyn std::error::Error + 'static))
            .or_else(|| self.close.as_ref().map(|error| error as _))
    }
}

impl From<InitialConfigFailure> for InitialConfigError {
    fn from(primary: InitialConfigFailure) -> Self {
        Self {
            primary: Some(primary),
            close: None,
        }
    }
}

/// Receives the existing first coordinator frame on one temporary socket.
///
/// This is intended for a native background initializer with an admitted
/// startup mode. It sends no RPC request and never caches or transfers its FD.
/// The exact legacy-bincode configuration must consume the complete payload.
/// The socket is retired with one close attempt before either result returns;
/// close is not retried, including on Linux `EINTR`.
pub fn read_initial_config<C: DeserializeOwned>(path: &Path) -> Result<C, InitialConfigError> {
    // Validate all address bytes before creating any descriptor. In particular,
    // an embedded NUL must not silently select a different filesystem socket.
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(InitialConfigFailure::Address(io::ErrorKind::InvalidInput.into()).into());
    }
    let address = unix_address(path).map_err(InitialConfigFailure::Address)?;
    let address_len = unix_address_len(path).map_err(InitialConfigFailure::Address)?;
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(InitialConfigFailure::Socket(io::Error::last_os_error()).into());
    }
    // Ownership begins immediately after successful creation. The explicit
    // finish below consumes it before close, so Drop cannot close it again.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stream = UnixStream::from(owned);
    let connected = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            address_len as libc::socklen_t,
        )
    };
    let result = if connected < 0 {
        Err(InitialConfigFailure::Connect(io::Error::last_os_error()))
    } else {
        receive_initial_config(&mut stream)
    };
    finish_initial_config(stream, result, close_initial_socket)
}

fn receive_initial_config<C: DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<C, InitialConfigFailure> {
    let payload = read_config_frame(stream).map_err(|error| match error {
        RpcError::Closed => InitialConfigFailure::Read(io::ErrorKind::UnexpectedEof.into()),
        RpcError::Io(error) => InitialConfigFailure::Read(error),
        RpcError::FrameTooLarge { .. } => InitialConfigFailure::FrameTooLarge,
        error => InitialConfigFailure::Read(io::Error::other(error)),
    })?;
    decode_exact(&payload).map_err(|error| match error {
        RpcError::Decode(error) => InitialConfigFailure::Decode(error),
        RpcError::TrailingBytes { .. } => InitialConfigFailure::TrailingBytes,
        error => InitialConfigFailure::Read(io::Error::other(error)),
    })
}

fn close_initial_socket(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::close(fd) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn finish_initial_config<C>(
    stream: UnixStream,
    result: Result<C, InitialConfigFailure>,
    close: impl FnOnce(RawFd) -> io::Result<()>,
) -> Result<C, InitialConfigError> {
    let fd = stream.into_raw_fd();
    let close = close(fd).err();
    match (result, close) {
        (Ok(config), None) => Ok(config),
        (Ok(_), Some(close)) => Err(InitialConfigError {
            primary: None,
            close: Some(close),
        }),
        (Err(primary), close) => Err(InitialConfigError {
            primary: Some(primary),
            close,
        }),
    }
}

struct Connection {
    pid: u32,
    path: PathBuf,
    stream: UnixStream,
}

impl Connection {
    fn connect(path: &Path, pid: u32) -> Self {
        let mut stream = UnixStream::connect(path).unwrap_or_else(|error| {
            panic!("reverie-dbt sync_rpc: failed to connect to coordinator at {path:?}: {error}")
        });
        // Consume the server's one-shot config handshake frame.
        let _config = read_config_frame(&mut stream).unwrap_or_else(|error| {
            panic!("reverie-dbt sync_rpc: failed to read config handshake: {error}")
        });
        Self {
            pid,
            path: path.to_path_buf(),
            stream,
        }
    }
}

// A connection is intentionally thread-local. DBT callbacks are synchronous,
// and independent connections avoid cross-thread head-of-line blocking. More
// importantly, a fork child inherits only the calling thread's slot: the pid
// check below drops its inherited parent socket and reconnects before sending.
thread_local! {
    static CLIENT: RefCell<Option<Connection>> = const { RefCell::new(None) };
}

/// True when a coordinator socket is configured, i.e. `send_rpc` should route to
/// the shared cross-process `GlobalState` instead of the in-process one.
pub fn is_active() -> bool {
    std::env::var_os(RPC_SOCKET_ENV).is_some()
}

/// Perform one blocking request/response round-trip against the coordinator.
///
/// Panics — like the in-process ptrace path's `.expect()`ed serialization and
/// [`reverie_rpc_transport::RpcClient`]'s `send_rpc` — if the coordinator that
/// owns all shared state is unreachable, since there is no meaningful way to
/// continue a deterministic run without it.
pub fn send_rpc<G: GlobalTool>(from: Tid, config: &G::Config, request: G::Request) -> G::Response {
    let path = PathBuf::from(
        std::env::var_os(RPC_SOCKET_ENV)
            .expect("reverie-dbt sync_rpc: no coordinator socket configured"),
    );
    let pid = std::process::id();

    CLIENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let must_connect = !matches!(
            slot.as_ref(),
            Some(connection) if connection.pid == pid && connection.path == path
        );
        if must_connect {
            *slot = Some(Connection::connect(&path, pid));
        }

        let connection = slot
            .as_mut()
            .expect("reverie-dbt sync_rpc: connection initialization failed");
        BlockingRpcClient::<G>::from_borrowed_stream(&mut connection.stream, from, config)
            .try_send_rpc(request)
            .expect("reverie-dbt: background coordinator round trip failed")
    })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review in-guest UDS syscalls via DynamoRIO.
/// Performs one RPC from a DynamoRIO application callback using guest syscalls.
///
/// Rust's standard Unix socket and TLS implementations are not safe inside
/// DynamoRIO's private loader. The native client supplies `invoke_syscall` so
/// socket I/O can follow the same application-syscall path as tool injection.
pub fn send_rpc_from_guest<G: GlobalTool>(
    context: usize,
    invoke_syscall: SyscallInvoker,
    from: Tid,
    config: &G::Config,
    request: G::Request,
) -> G::Response {
    let path = PathBuf::from(
        std::env::var_os(RPC_SOCKET_ENV)
            .expect("reverie-dbt sync_rpc: no coordinator socket configured"),
    );
    let request = RpcRequest::<G>::new(from, request)
        .expect("reverie-dbt: guest coordinator request encode failed");
    let response = match GUEST_CLIENT.try_lock() {
        Ok(mut slot) => {
            let pid = std::process::id();
            let must_connect = !matches!(
                slot.as_ref(),
                Some(connection) if connection.pid == pid && connection.path == path
            );
            if must_connect {
                if let Some(connection) = slot.take() {
                    close_guest(context, invoke_syscall, connection.fd);
                }
                *slot = Some(
                    connect_guest(context, invoke_syscall, &path, pid)
                        .expect("reverie-dbt sync_rpc: failed to connect guest socket"),
                );
            }
            let connection = slot
                .as_ref()
                .expect("reverie-dbt sync_rpc: guest connection initialization failed");
            guest_round_trip::<G>(
                context,
                invoke_syscall,
                connection.fd,
                from,
                config,
                request,
            )
        }
        Err(TryLockError::Poisoned(poisoned)) => {
            let mut slot = poisoned.into_inner();
            let pid = std::process::id();
            if let Some(connection) = slot.take() {
                close_guest(context, invoke_syscall, connection.fd);
            }
            let connection = connect_guest(context, invoke_syscall, &path, pid)
                .expect("reverie-dbt sync_rpc: failed to recover guest connection");
            let response = guest_round_trip::<G>(
                context,
                invoke_syscall,
                connection.fd,
                from,
                config,
                request,
            );
            *slot = Some(connection);
            response
        }
        Err(TryLockError::WouldBlock) => {
            // A fork child can inherit this mutex while another parent thread
            // owns it. The inherited lock can never be released in that child,
            // so use an uncached connection instead of waiting forever.
            let connection = connect_guest(context, invoke_syscall, &path, std::process::id())
                .expect("reverie-dbt sync_rpc: failed to connect contended guest socket");
            let response = guest_round_trip::<G>(
                context,
                invoke_syscall,
                connection.fd,
                from,
                config,
                request,
            );
            close_guest(context, invoke_syscall, connection.fd);
            response
        }
    }
    .expect("reverie-dbt: guest coordinator round trip failed");
    // Deserialization may run Tool code. Preserve the old boundary: release
    // the cache lease and retire an uncached socket before invoking it.
    response
        .decode()
        .expect("reverie-dbt: guest coordinator response decode failed")
}

struct GuestConnection {
    pid: u32,
    path: PathBuf,
    fd: i32,
}

static GUEST_CLIENT: Mutex<Option<GuestConnection>> = Mutex::new(None);

fn connect_guest(
    context: usize,
    invoke_syscall: SyscallInvoker,
    path: &Path,
    pid: u32,
) -> std::io::Result<GuestConnection> {
    let mut fd = invoke(
        context,
        invoke_syscall,
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
        // The private connection must not occupy a guest's closed stdin,
        // stdout or stderr. Keep CLOEXEC and release that slot before any
        // guest syscall can observe the cached connection.
        if fd <= libc::STDERR_FILENO {
            let relocated = invoke(
                context,
                invoke_syscall,
                libc::SYS_fcntl,
                [fd as u64, libc::F_DUPFD_CLOEXEC as u64, 3, 0, 0, 0],
            )? as i32;
            close_guest(context, invoke_syscall, fd);
            fd = relocated;
        }
        let address = unix_address(path)?;
        invoke(
            context,
            invoke_syscall,
            libc::SYS_connect,
            [
                fd as u64,
                (&address as *const libc::sockaddr_un) as u64,
                unix_address_len(path)? as u64,
                0,
                0,
                0,
            ],
        )?;
        let mut stream = GuestIo {
            context,
            invoke_syscall,
            fd,
        };
        let _config = read_config_frame(&mut stream).map_err(io::Error::other)?;
        Ok(GuestConnection {
            pid,
            path: path.to_path_buf(),
            fd,
        })
    })();
    if result.is_err() {
        close_guest(context, invoke_syscall, fd);
    }
    result
}

fn guest_round_trip<G: GlobalTool>(
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
    from: Tid,
    config: &G::Config,
    request: RpcRequest<G>,
) -> Result<RpcResponse<G>, RpcError> {
    let mut stream = GuestIo {
        context,
        invoke_syscall,
        fd,
    };
    BlockingRpcClient::<G>::from_borrowed_stream(&mut stream, from, config)
        .receive_response(request)
}

// A non-owning stream valid only during the current native callback. Cached
// GuestConnection values never contain this context or an invocation callback.
struct GuestIo {
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
}

impl Read for GuestIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        invoke(
            self.context,
            self.invoke_syscall,
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
        .map(|count| count as usize)
    }
}

impl Write for GuestIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        invoke(
            self.context,
            self.invoke_syscall,
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
        .map(|count| count as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn close_guest(context: usize, invoke_syscall: SyscallInvoker, fd: i32) {
    let _ = invoke(
        context,
        invoke_syscall,
        libc::SYS_close,
        [fd as u64, 0, 0, 0, 0, 0],
    );
}

fn unix_address(path: &Path) -> std::io::Result<libc::sockaddr_un> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reverie-dbt sync_rpc: coordinator socket path is empty or too long",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    Ok(address)
}

fn unix_address_len(path: &Path) -> std::io::Result<usize> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reverie-dbt sync_rpc: coordinator socket path is empty or too long",
        ));
    }
    Ok(std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1)
}

fn invoke(
    context: usize,
    invoke_syscall: SyscallInvoker,
    number: libc::c_long,
    arguments: [u64; 6],
) -> std::io::Result<i64> {
    let result = unsafe { invoke_syscall(context, number, arguments.as_ptr()) };
    if result < 0 {
        Err(std::io::Error::from_raw_os_error((-result) as i32))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod shared_client_tests;

#[cfg(test)]
mod initial_config_tests {
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    use reverie_rpc_transport::codec::encode;
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Config {
        enabled: bool,
        ids: Vec<u64>,
        raw_prefix: Vec<u8>,
    }

    fn config() -> Config {
        Config {
            enabled: true,
            ids: vec![1002, 7, 113],
            raw_prefix: vec![b'/', 0xff, b'\\', 0, b'8'],
        }
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut bytes = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn with_server<C: DeserializeOwned>(bytes: Vec<u8>) -> Result<C, InitialConfigError> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket.write_all(&bytes).unwrap();
            // A malformed frame may need EOF to establish truncation. This
            // preserves the independent read half, which must see no request.
            socket.shutdown(std::net::Shutdown::Write).unwrap();
            let mut request = [0_u8; 1];
            assert_eq!(socket.read(&mut request).unwrap(), 0);
        });
        let result = read_initial_config(&path);
        server.join().unwrap();
        result
    }

    #[test]
    fn exact_config_is_returned_after_close_without_a_request_or_eof_wait() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let expected = config();
        let payload = encode(&expected).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket.write_all(&framed(&payload)).unwrap();
            // Keep the sending half open like the real coordinator waiting
            // for a request. A reader that waits for EOF cannot finish here.
            let mut request = [0_u8; 1];
            assert_eq!(socket.read(&mut request).unwrap(), 0);
        });
        let actual: Config = read_initial_config(&path).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(encode(&actual).unwrap(), encode(&expected).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn strict_initial_frame_rejects_truncation_size_decode_and_trailing_errors() {
        let payload = encode(&config()).unwrap();
        let header_error = with_server::<Config>(vec![0, 0, 0]).unwrap_err();
        assert!(matches!(header_error.primary,
            Some(InitialConfigFailure::Read(ref error))
            if error.kind() == io::ErrorKind::UnexpectedEof));
        assert!(header_error.close.is_none());

        let mut truncated = framed(&payload);
        truncated.pop();
        let body_error = with_server::<Config>(truncated).unwrap_err();
        assert!(matches!(body_error.primary,
            Some(InitialConfigFailure::Read(ref error))
            if error.kind() == io::ErrorKind::UnexpectedEof));
        assert!(body_error.close.is_none());

        let oversized = u32::try_from(MAX_FRAME_LEN + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        let size_error = with_server::<Config>(oversized).unwrap_err();
        assert!(matches!(
            size_error.primary,
            Some(InitialConfigFailure::FrameTooLarge)
        ));
        assert!(size_error.close.is_none());

        let mut malformed = payload.clone();
        malformed[0] = 2; // No valid serde bool has this wire spelling.
        let decode_error = with_server::<Config>(framed(&malformed)).unwrap_err();
        assert!(matches!(
            decode_error.primary,
            Some(InitialConfigFailure::Decode(_))
        ));
        assert!(decode_error.close.is_none());

        let mut trailing = payload;
        trailing.push(0);
        let trailing_error = with_server::<Config>(framed(&trailing)).unwrap_err();
        assert!(matches!(
            trailing_error.primary,
            Some(InitialConfigFailure::TrailingBytes)
        ));
        assert!(trailing_error.close.is_none());

        // A complete announced frame can itself contain a truncated Config.
        trailing.truncate(trailing.len() - 2);
        let truncated_config = with_server::<Config>(framed(&trailing)).unwrap_err();
        assert!(matches!(
            truncated_config.primary,
            Some(InitialConfigFailure::Decode(_))
        ));
        assert!(truncated_config.close.is_none());
    }

    #[test]
    fn address_and_connect_failures_keep_their_original_error_classes() {
        let long_path = "x".repeat(108);
        for path in [
            Path::new(""),
            Path::new(std::ffi::OsStr::from_bytes(b"prefix\0different-socket")),
            Path::new(&long_path),
        ] {
            let error = read_initial_config::<Config>(path).unwrap_err();
            assert!(matches!(error.primary,
                Some(InitialConfigFailure::Address(ref error))
                if error.kind() == io::ErrorKind::InvalidInput));
            assert!(error.close.is_none());
        }
        let directory = tempfile::tempdir().unwrap();
        let error =
            read_initial_config::<Config>(&directory.path().join("missing.sock")).unwrap_err();
        assert!(matches!(error.primary,
            Some(InitialConfigFailure::Connect(ref error))
            if error.raw_os_error() == Some(libc::ENOENT)));
        assert!(error.close.is_none());
    }

    #[test]
    fn close_is_consumed_once_and_preserves_primary_and_secondary_errors() {
        for primary in [false, true] {
            let (stream, _peer) = UnixStream::pair().unwrap();
            let fd = stream.as_raw_fd();
            let mut calls = 0;
            let result = if primary {
                Err(InitialConfigFailure::Read(io::Error::from_raw_os_error(
                    libc::EIO,
                )))
            } else {
                Ok(config())
            };
            let error = finish_initial_config(stream, result, |raw| {
                calls += 1;
                assert_eq!(raw, fd);
                close_initial_socket(raw).unwrap();
                // Model Linux releasing an FD before reporting EINTR. The
                // caller must retain the error without retry or Drop-close.
                Err(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap_err();
            assert_eq!(calls, 1);
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            assert_eq!(error.close.unwrap().raw_os_error(), Some(libc::EINTR));
            if primary {
                assert!(matches!(error.primary,
                    Some(InitialConfigFailure::Read(ref error))
                    if error.raw_os_error() == Some(libc::EIO)));
            } else {
                assert!(error.primary.is_none());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SocketProbe {
        allocated_fd: i32,
        duplicate_result: i64,
        connect_result: i64,
        calls: Vec<(i64, [u64; 6])>,
    }

    impl SocketProbe {
        fn new(allocated_fd: i32) -> Self {
            Self {
                allocated_fd,
                duplicate_result: 9,
                connect_result: 0,
                calls: Vec::new(),
            }
        }

        fn connect(&mut self) -> std::io::Result<GuestConnection> {
            connect_guest(
                self as *mut Self as usize,
                socket_syscall,
                Path::new("/test-coordinator"),
                123,
            )
        }

        fn arguments(&self, number: i64) -> Vec<[u64; 6]> {
            self.calls
                .iter()
                .filter_map(|(call, arguments)| (*call == number).then_some(*arguments))
                .collect()
        }
    }

    unsafe extern "C" fn socket_syscall(context: usize, number: i64, args: *const u64) -> i64 {
        let probe = unsafe { &mut *(context as *mut SocketProbe) };
        let args = unsafe { std::ptr::read(args.cast::<[u64; 6]>()) };
        probe.calls.push((number, args));
        match number {
            libc::SYS_socket => i64::from(probe.allocated_fd),
            libc::SYS_fcntl => probe.duplicate_result,
            libc::SYS_connect => probe.connect_result,
            libc::SYS_close => 0,
            libc::SYS_read => {
                // A zero-length config frame is enough for connect_guest's
                // handshake; no guest memory or real descriptor is involved.
                unsafe { std::ptr::write_bytes(args[1] as *mut u8, 0, args[2] as usize) };
                args[2] as i64
            }
            _ => -i64::from(libc::ENOSYS),
        }
    }

    #[test]
    fn private_rpc_socket_leaves_closed_stdio_available() {
        for allocated_fd in 0..=3 {
            let mut probe = SocketProbe::new(allocated_fd);
            let connection = probe.connect().unwrap();
            let expected_fd = if allocated_fd < 3 { 9 } else { allocated_fd };
            assert_eq!(connection.fd, expected_fd);
            let duplicates = probe.arguments(libc::SYS_fcntl);
            let closes = probe.arguments(libc::SYS_close);
            if allocated_fd < 3 {
                assert_eq!(duplicates.len(), 1);
                assert_eq!(
                    duplicates[0][..3],
                    [allocated_fd as u64, libc::F_DUPFD_CLOEXEC as u64, 3]
                );
                assert_eq!(closes.len(), 1);
                assert_eq!(closes[0][0], allocated_fd as u64);
                assert_eq!(probe.calls[2].0, libc::SYS_close);
                assert_eq!(probe.calls[3].0, libc::SYS_connect);
            } else {
                assert!(duplicates.is_empty());
                assert!(closes.is_empty());
            }
            assert_eq!(probe.arguments(libc::SYS_connect)[0][0], expected_fd as u64);
            assert_eq!(probe.arguments(libc::SYS_read)[0][0], expected_fd as u64);
        }
    }

    #[test]
    fn private_rpc_relocation_failure_closes_the_original_once() {
        let mut probe = SocketProbe::new(0);
        probe.duplicate_result = -i64::from(libc::EMFILE);
        let error = probe.connect().err().expect("duplication must fail");
        assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
        assert!(probe.arguments(libc::SYS_connect).is_empty());
        let closes = probe.arguments(libc::SYS_close);
        assert_eq!(closes.len(), 1);
        assert_eq!(closes[0][0], 0);
    }

    #[test]
    fn private_rpc_connect_failure_closes_original_and_duplicate_once() {
        let mut probe = SocketProbe::new(2);
        probe.connect_result = -i64::from(libc::ECONNREFUSED);
        let error = probe.connect().err().expect("connection must fail");
        assert_eq!(error.raw_os_error(), Some(libc::ECONNREFUSED));
        let closes = probe.arguments(libc::SYS_close);
        assert_eq!(closes.len(), 2);
        assert_eq!(closes[0][0], 2);
        assert_eq!(closes[1][0], 9);
    }
}
