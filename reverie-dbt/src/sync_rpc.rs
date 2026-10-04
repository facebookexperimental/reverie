/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Synchronous Unix-domain-socket client for the GlobalTool RPC.
//!
//! The DBT guest client runs inside the (DynamoRIO-instrumented) guest process
//! and has no async runtime, so it cannot use the tokio-based
//! [`reverie_rpc_transport::RpcClient`]. This module provides a blocking client
//! that is *wire-compatible* with that crate's [`reverie_rpc_transport::RpcServer`]:
//!
//! * each frame is a big-endian `u32` length prefix followed by a
//!   `bincode`(legacy)-encoded payload;
//! * on connect the server sends exactly one `Config` frame, which we read and
//!   discard (the guest carries no config in its address space);
//! * every request is a [`RequestEnvelope`] `{ from, request }` and the
//!   response travels back bare.
//!
//! When [`RPC_SOCKET_ENV`] is set, a coordinator process (e.g. `hermit-cli`)
//! owns the single shared `GlobalState`; every guest process — including every
//! `fork(2)` child, which inherits the environment and re-connects with its own
//! socket — routes [`reverie::GlobalRPC::send_rpc`] here, giving one shared
//! `GlobalState` across the whole process tree. When the variable is unset,
//! callers fall back to the in-process `GlobalState::receive_rpc`.
//!
//! Because the round-trip is fully synchronous, the `async fn send_rpc` that
//! calls it resolves on its first poll, so the DBT driver's `run_ready` never
//! spins waiting on a cross-thread wake for an RPC.

use std::cell::RefCell;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::TryLockError;

use reverie::Tid;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::SyscallInvoker;

/// Environment variable naming the coordinator's Unix-domain socket path. Set
/// by the coordinator (which hosts the [`reverie_rpc_transport::RpcServer`])
/// before launching the guest; inherited across `fork`/`exec`.
pub const RPC_SOCKET_ENV: &str = "HERMIT_DBT_RPC_SOCKET";

/// Mirror of [`reverie_rpc_transport::codec::DEFAULT_MAX_FRAME_LEN`] (16 MiB).
const MAX_FRAME_LEN: usize = 16 * (1 << 20);

/// Local mirror of `reverie_rpc_transport::envelope::RequestEnvelope`, kept here
/// so the injected guest `.so` need not link the transport crate's async
/// runtime. The field order and types match exactly, so the `bincode` encoding
/// is byte-identical and the tokio server decodes it transparently.
#[derive(Serialize)]
struct RequestEnvelope<Req> {
    from: Tid,
    request: Req,
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
        .expect("reverie-dbt sync_rpc: bincode encode failed")
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> T {
    let (value, _consumed) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
        .expect("reverie-dbt sync_rpc: bincode decode failed");
    value
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).expect("reverie-dbt sync_rpc: frame too large");
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    assert!(
        len <= MAX_FRAME_LEN,
        "reverie-dbt sync_rpc: frame length {len} exceeds {MAX_FRAME_LEN}"
    );
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
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
        let _config = read_frame(&mut stream).unwrap_or_else(|error| {
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
pub fn send_rpc<Req, Resp>(from: Tid, request: Req) -> Resp
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
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
        let request_bytes = encode(&RequestEnvelope { from, request });
        write_frame(&mut connection.stream, &request_bytes)
            .expect("reverie-dbt sync_rpc: failed to write request frame");
        let response_bytes = read_frame(&mut connection.stream)
            .expect("reverie-dbt sync_rpc: failed to read response frame");
        decode(&response_bytes)
    })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review in-guest UDS syscalls via DynamoRIO.
/// Performs one RPC from a DynamoRIO application callback using guest syscalls.
///
/// Rust's standard Unix socket and TLS implementations are not safe inside
/// DynamoRIO's private loader. The native client supplies `invoke_syscall` so
/// socket I/O can follow the same application-syscall path as tool injection.
pub fn send_rpc_from_guest<Req, Resp>(
    context: usize,
    invoke_syscall: SyscallInvoker,
    from: Tid,
    request: Req,
) -> Resp
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let path = PathBuf::from(
        std::env::var_os(RPC_SOCKET_ENV)
            .expect("reverie-dbt sync_rpc: no coordinator socket configured"),
    );
    let request_bytes = encode(&RequestEnvelope { from, request });
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
            guest_round_trip(context, invoke_syscall, connection.fd, &request_bytes)
        }
        Err(TryLockError::Poisoned(poisoned)) => {
            let mut slot = poisoned.into_inner();
            let pid = std::process::id();
            if let Some(connection) = slot.take() {
                close_guest(context, invoke_syscall, connection.fd);
            }
            let connection = connect_guest(context, invoke_syscall, &path, pid)
                .expect("reverie-dbt sync_rpc: failed to recover guest connection");
            let response = guest_round_trip(context, invoke_syscall, connection.fd, &request_bytes);
            *slot = Some(connection);
            response
        }
        Err(TryLockError::WouldBlock) => {
            // A fork child can inherit this mutex while another parent thread
            // owns it. The inherited lock can never be released in that child,
            // so use an uncached connection instead of waiting forever.
            let connection = connect_guest(context, invoke_syscall, &path, std::process::id())
                .expect("reverie-dbt sync_rpc: failed to connect contended guest socket");
            let response = guest_round_trip(context, invoke_syscall, connection.fd, &request_bytes);
            close_guest(context, invoke_syscall, connection.fd);
            response
        }
    }
    .expect("reverie-dbt sync_rpc: guest coordinator round trip failed");
    decode(&response)
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
    let fd = invoke(
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
        let _config = read_frame_from_guest(context, invoke_syscall, fd)?;
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

fn guest_round_trip(
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    write_frame_from_guest(context, invoke_syscall, fd, request)?;
    read_frame_from_guest(context, invoke_syscall, fd)
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

fn write_all_from_guest(
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
    mut bytes: &[u8],
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match invoke(
            context,
            invoke_syscall,
            libc::SYS_write,
            [
                fd as u64,
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                0,
                0,
                0,
            ],
        ) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written as usize..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_exact_from_guest(
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
    mut bytes: &mut [u8],
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match invoke(
            context,
            invoke_syscall,
            libc::SYS_read,
            [
                fd as u64,
                bytes.as_mut_ptr() as u64,
                bytes.len() as u64,
                0,
                0,
                0,
            ],
        ) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => {
                let (_, remaining) = bytes.split_at_mut(read as usize);
                bytes = remaining;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_frame_from_guest(
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).expect("reverie-dbt sync_rpc: frame too large");
    write_all_from_guest(context, invoke_syscall, fd, &len.to_be_bytes())?;
    write_all_from_guest(context, invoke_syscall, fd, payload)
}

fn read_frame_from_guest(
    context: usize,
    invoke_syscall: SyscallInvoker,
    fd: i32,
) -> std::io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    read_exact_from_guest(context, invoke_syscall, fd, &mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("reverie-dbt sync_rpc: frame length {len} exceeds {MAX_FRAME_LEN}"),
        ));
    }
    let mut payload = vec![0_u8; len];
    read_exact_from_guest(context, invoke_syscall, fd, &mut payload)?;
    Ok(payload)
}
