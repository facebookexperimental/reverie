/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
//! Allocation-free framing for the final, explicitly authorized exec controls.
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

use reverie::GlobalTool;

use super::CoordinatorRpc;
use super::FORKED_SINCE_LAST_RPC;
use super::RpcConnection;
use crate::sync::SpinGuard;
use crate::trap::raw_syscall6;

const MAX_REQUEST: usize = 1024 * 1024 + 4096;
const MAX_RESPONSE: usize = 4096;

/// A refused or failed native-control exchange. Wire failure is terminal for
/// this connection; it never authorizes an ordinary RPC retry or reconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFrameError {
    /// Request/reply buffer bounds were invalid before any wire byte.
    Bounds,
    /// Another exchange still owns this connection.
    InFlight,
    /// A previous exchange was not completely validated and acknowledged.
    Poisoned,
    /// Fixed gates, the same leader, or the owned descriptor were not present.
    Owner,
    /// A raw socket operation returned this positive Linux errno.
    Kernel(i32),
    /// EOF, a zero-byte write, or an invalid raw transfer length.
    Truncated,
    /// An empty response or a response exceeding the caller's bounded buffer.
    ResponseLength,
}

/// A complete frame whose connection remains locked and poisoned until the
/// trusted driver validates the typed response. Dropping it without accepting
/// the reply permanently disables this connection.
#[must_use]
pub struct NativeFrameReply<'a, G: GlobalTool> {
    owner: &'a CoordinatorRpc<G>,
    _connection: SpinGuard<'a, RpcConnection<G>>,
    length: usize,
}

impl<G: GlobalTool> NativeFrameReply<'_, G> {
    /// Number of initialized response bytes written into the supplied buffer.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Release the connection after validating this exact response.
    ///
    /// # Safety
    /// The driver must decode exactly `length()` bytes without trailing data
    /// (or compare all bytes to an independently encoded complete expected
    /// typed response), verify the expected native response variant and all ticket/mm/digest
    /// fields, and require that no clock update was returned. A malformed,
    /// unexpected or refused response must not be accepted. This does not
    /// replace the final physical exec and counter rechecks.
    pub unsafe fn accept(self) {
        self.owner.native_failed.store(false, Ordering::Release);
    }
}

impl<G: GlobalTool> CoordinatorRpc<G> {
    /// Exchange one pre-encoded native control over the existing owned stream.
    /// This performs no allocation, serialization, reconnect or libc errno
    /// access. All syscalls use the already published fixed gate page.
    ///
    /// # Safety
    /// Only the authorized native-exec driver may call this, with a correct
    /// complete RPC RequestEnvelope for its actual sender/mm and forwarded
    /// count. The request must be one of that driver's neutral native controls;
    /// arbitrary Tool requests are not admitted here. The caller owns the
    /// ready single leader, protects this descriptor from guest access and
    /// excludes concurrent guest/signal activity. Buffers and frame encoding
    /// must be complete before freezing the actual runtime counters. This API
    /// authenticates neither a new image nor an exec ticket. The driver must
    /// still recheck its full sealed state at the physical exec boundary.
    pub unsafe fn exchange_native_frame<'a>(
        &'a self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<NativeFrameReply<'a, G>, NativeFrameError> {
        if self.native_failed.load(Ordering::Acquire) {
            return Err(NativeFrameError::Poisoned);
        }
        if request.is_empty()
            || request.len() > MAX_REQUEST
            || response.is_empty()
            || response.len() > MAX_RESPONSE
        {
            return Err(NativeFrameError::Bounds);
        }
        let connection = self
            .connection
            .try_lock()
            .ok_or(NativeFrameError::InFlight)?;
        if self.native_failed.load(Ordering::Acquire) {
            return Err(NativeFrameError::Poisoned);
        }
        if !crate::trap::fixed_gates_published() || FORKED_SINCE_LAST_RPC.load(Ordering::Acquire) {
            return Err(NativeFrameError::Owner);
        }
        let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
        let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
        let fd = connection.client.as_raw_fd();
        if pid <= 0
            || pid != tid
            || pid != i64::from(connection.pid.as_raw())
            || tid != i64::from(connection.client.tid().as_raw())
            || fd < 0
            || fd != self.fd.load(Ordering::Acquire)
        {
            return Err(NativeFrameError::Owner);
        }
        self.native_failed.store(true, Ordering::Release);
        let length = exchange_frame(fd, request, response)?;
        Ok(NativeFrameReply {
            owner: self,
            _connection: connection,
            length,
        })
    }
}

fn exchange_frame(fd: i32, request: &[u8], response: &mut [u8]) -> Result<usize, NativeFrameError> {
    let prefix = (request.len() as u32).to_be_bytes();
    transfer(fd, prefix.as_ptr() as u64, prefix.len(), true)?;
    transfer(fd, request.as_ptr() as u64, request.len(), true)?;
    let mut header = [0u8; 4];
    transfer(fd, header.as_mut_ptr() as u64, header.len(), false)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > response.len() {
        return Err(NativeFrameError::ResponseLength);
    }
    transfer(fd, response.as_mut_ptr() as u64, length, false)?;
    Ok(length)
}

fn transfer(fd: i32, buffer: u64, length: usize, sending: bool) -> Result<(), NativeFrameError> {
    let mut done = 0;
    while done < length {
        let number = if sending {
            libc::SYS_sendto
        } else {
            libc::SYS_recvfrom
        };
        let result = unsafe {
            raw_syscall6(
                number,
                [
                    fd as u64,
                    buffer + done as u64,
                    (length - done) as u64,
                    if sending {
                        libc::MSG_NOSIGNAL as u64
                    } else {
                        0
                    },
                    0,
                    0,
                ],
            )
        };
        if result == -i64::from(libc::EINTR) {
            continue;
        }
        if result < 0 {
            return Err(NativeFrameError::Kernel((-result) as i32));
        }
        if result == 0 || result as u64 > (length - done) as u64 {
            return Err(NativeFrameError::Truncated);
        }
        done += result as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;

    use reverie::Pid;
    use reverie_rpc_transport::BlockingRpcClient;

    use super::*;

    #[derive(Default)]
    struct WireModel;
    #[reverie::tool]
    impl GlobalTool for WireModel {
        type Request = u64;
        type Response = u64;
        type Config = u64;
        async fn receive_rpc(&self, _: Pid, request: u64) -> u64 {
            request
        }
    }

    // Actual framing/FD/fixed-gate tests. WireModel and its byte payloads are
    // protocol fixtures only, not an exec driver or native admission proof.
    fn fixture(
        fixed: bool,
        child: impl FnOnce(&CoordinatorRpc<WireModel>),
        parent: impl FnOnce(&mut UnixStream),
        expected: i32,
    ) {
        let (client, mut server) = UnixStream::pair().unwrap();
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        // Unchanged BlockingRpcClient's real bincode config handshake.
        server.write_all(&8_u32.to_be_bytes()).unwrap();
        server.write_all(&73_u64.to_le_bytes()).unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(server);
            let status = if std::panic::catch_unwind(AssertUnwindSafe(|| {
                if fixed {
                    unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
                }
                let tid = Pid::from_raw(unsafe { libc::getpid() });
                let client = BlockingRpcClient::from_connected_stream(
                    crate::guest::rpc::GuestRpcStream::from(client),
                    tid,
                )
                .unwrap();
                let rpc =
                    CoordinatorRpc::from_live_client("unused-native-frame", client, |_, _| {
                        panic!("native exchange must never reconnect")
                    })
                    .unwrap();
                child(&rpc);
            }))
            .is_ok()
            {
                0
            } else {
                125
            };
            unsafe { libc::_exit(status) };
        }
        drop(client);
        parent(&mut server);
        drop(server);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }

    fn request(server: &mut UnixStream, expected: &[u8]) {
        let mut prefix = [0; 4];
        server.read_exact(&mut prefix).unwrap();
        assert_eq!(u32::from_be_bytes(prefix) as usize, expected.len());
        let mut bytes = vec![0; expected.len()];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
    }

    fn eof(server: &mut UnixStream) {
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn native_frame_chunked_reply_requires_validation_before_reuse() {
        fixture(
            true,
            |rpc| {
                let fd = rpc.raw_fd();
                for body in [b"seal".as_slice(), b"issue".as_slice()] {
                    let mut reply = [0; MAX_RESPONSE];
                    let received = unsafe { rpc.exchange_native_frame(body, &mut reply) }.unwrap();
                    assert_eq!(received.length(), 3);
                    assert_eq!(&reply[..3], b"yes");
                    assert!(rpc.native_failed.load(Ordering::Acquire));
                    assert!(rpc.connection.try_lock().is_none());
                    unsafe { received.accept() };
                    assert!(!rpc.native_failed.load(Ordering::Acquire));
                    assert_eq!(rpc.raw_fd(), fd);
                }
            },
            |server| {
                for body in [b"seal".as_slice(), b"issue".as_slice()] {
                    request(server, body);
                    for byte in [0, 0, 0, 3, b'y', b'e', b's'] {
                        server.write_all(&[byte]).unwrap();
                    }
                }
                eof(server);
            },
            0,
        );
    }

    #[test]
    fn native_frame_bad_reply_poison_survives_ordinary_rpc_attempt() {
        for (wire, expected) in [
            (&[][..], NativeFrameError::Truncated),
            (&[0, 0][..], NativeFrameError::Truncated),
            (&[0, 0, 0, 0][..], NativeFrameError::ResponseLength),
            (&[0, 0, 16, 1][..], NativeFrameError::ResponseLength),
            (&[0, 0, 0, 4, 1, 2][..], NativeFrameError::Truncated),
        ] {
            fixture(
                true,
                |rpc| {
                    let mut reply = [0; MAX_RESPONSE];
                    assert_eq!(
                        unsafe { rpc.exchange_native_frame(b"issue", &mut reply) }.err(),
                        Some(expected)
                    );
                    assert_eq!(
                        unsafe { rpc.exchange_native_frame(b"retry", &mut reply) }.err(),
                        Some(NativeFrameError::Poisoned)
                    );
                    let _ = rpc.send_blocking_unless_in_flight(1);
                    panic!("ordinary RPC reused a poisoned connection");
                },
                |server| {
                    request(server, b"issue");
                    server.write_all(wire).unwrap();
                    server.shutdown(std::net::Shutdown::Write).unwrap();
                    eof(server);
                },
                123,
            );
        }
    }

    #[test]
    fn native_frame_unvalidated_complete_reply_is_terminal() {
        fixture(
            true,
            |rpc| {
                let mut reply = [0; MAX_RESPONSE];
                let received = unsafe { rpc.exchange_native_frame(b"issue", &mut reply) }.unwrap();
                assert_eq!(received.length(), 1);
                drop(received);
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"retry", &mut reply) }.err(),
                    Some(NativeFrameError::Poisoned)
                );
                let _ = rpc.send_blocking_unless_in_flight(1);
                panic!("ordinary RPC reused an unvalidated connection");
            },
            |server| {
                request(server, b"issue");
                server.write_all(&[0, 0, 0, 1, 7]).unwrap();
                eof(server);
            },
            123,
        );
    }

    #[test]
    fn native_frame_pre_wire_refusals_do_not_send_or_reconnect() {
        fixture(
            true,
            |rpc| {
                let mut reply = [0; MAX_RESPONSE];
                let too_long = vec![0; MAX_REQUEST + 1];
                for body in [b"".as_slice(), too_long.as_slice()] {
                    assert_eq!(
                        unsafe { rpc.exchange_native_frame(body, &mut reply) }.err(),
                        Some(NativeFrameError::Bounds)
                    );
                }
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"seal", &mut []) }.err(),
                    Some(NativeFrameError::Bounds)
                );
                let guard = rpc.connection.lock();
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"seal", &mut reply) }.err(),
                    Some(NativeFrameError::InFlight)
                );
                drop(guard);
                FORKED_SINCE_LAST_RPC.store(true, Ordering::Release);
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"seal", &mut reply) }.err(),
                    Some(NativeFrameError::Owner)
                );
                assert!(FORKED_SINCE_LAST_RPC.load(Ordering::Acquire));
                FORKED_SINCE_LAST_RPC.store(false, Ordering::Release);
                let fd = rpc.fd.swap(-1, Ordering::AcqRel);
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"seal", &mut reply) }.err(),
                    Some(NativeFrameError::Owner)
                );
                rpc.fd.store(fd, Ordering::Release);
                assert!(!rpc.native_failed.load(Ordering::Acquire));
            },
            eof,
            0,
        );
    }

    #[test]
    fn native_frame_requires_published_fixed_gates() {
        fixture(
            false,
            |rpc| {
                let mut reply = [0; MAX_RESPONSE];
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"seal", &mut reply) }.err(),
                    Some(NativeFrameError::Owner)
                );
                assert!(!rpc.native_failed.load(Ordering::Acquire));
            },
            eof,
            0,
        );
    }

    #[test]
    fn native_frame_closed_peer_does_not_raise_sigpipe_or_allow_retry() {
        fixture(
            true,
            |rpc| {
                let mut reply = [0; MAX_RESPONSE];
                // The parent shuts down both directions before this raw exchange.
                // Synchronize by observing read EOF; this uses the same owned fd.
                let mut byte = 0_u8;
                assert_eq!(
                    unsafe {
                        raw_syscall6(
                            libc::SYS_recvfrom,
                            [rpc.raw_fd() as u64, (&raw mut byte) as u64, 1, 0, 0, 0],
                        )
                    },
                    0
                );
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"issue", &mut reply) }.err(),
                    Some(NativeFrameError::Kernel(libc::EPIPE))
                );
                assert_eq!(
                    unsafe { rpc.exchange_native_frame(b"retry", &mut reply) }.err(),
                    Some(NativeFrameError::Poisoned)
                );
            },
            |server| {
                server.shutdown(std::net::Shutdown::Both).unwrap();
            },
            0,
        );
    }
}
