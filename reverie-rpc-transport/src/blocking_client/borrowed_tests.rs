/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

use super::*;

#[derive(Default, Serialize, Deserialize)]
struct Config {
    value: u64,
    #[serde(skip)]
    clones: Arc<AtomicUsize>,
}

impl Clone for Config {
    fn clone(&self) -> Self {
        self.clones.fetch_add(1, Ordering::SeqCst);
        Self {
            value: self.value,
            clones: self.clones.clone(),
        }
    }
}

#[derive(Default)]
struct Echo;

#[async_trait]
impl GlobalTool for Echo {
    type Request = u64;
    type Response = (i32, u64);
    type Config = Config;

    async fn receive_rpc(&self, from: Tid, value: u64) -> Self::Response {
        (from.as_raw(), value)
    }
}

// Force short transfers and one EINTR in each direction on a real socket.
struct Fragmented {
    socket: UnixStream,
    interrupt_read: bool,
    interrupt_write: bool,
}

impl Read for Fragmented {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if std::mem::take(&mut self.interrupt_read) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let len = bytes.len().min(2);
        self.socket.read(&mut bytes[..len])
    }
}

impl Write for Fragmented {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if std::mem::take(&mut self.interrupt_write) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.socket.write(&bytes[..bytes.len().min(2)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[test]
fn borrowed_client_preserves_owner_and_uses_shared_server_through_short_io() {
    let (socket, server) = UnixStream::pair().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                server.set_nonblocking(true).unwrap();
                crate::serve_stream(
                    Arc::new(Echo),
                    Config::default(),
                    tokio::net::UnixStream::from_std(server).unwrap(),
                )
                .await
            })
    });
    let mut stream = Fragmented {
        socket,
        interrupt_read: true,
        interrupt_write: true,
    };
    let _: Config = crate::codec::decode_exact(&read_config_frame(&mut stream).unwrap()).unwrap();
    let config = Config {
        value: 83,
        ..Config::default()
    };
    for tid in [17, 29] {
        let client = BlockingRpcClient::<Echo>::from_borrowed_stream(
            &mut stream,
            Tid::from_raw(tid),
            &config,
        );
        assert!(std::ptr::eq(client.config(), &config));
        let mut future = pin!(client.send_rpc(107));
        assert_eq!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready((tid, 107))
        );
    }
    assert_eq!(config.clones.load(Ordering::SeqCst), 0);
    // Both borrowed clients are gone, but the original descriptor remains live.
    assert!(unsafe { libc::fcntl(stream.socket.as_raw_fd(), libc::F_GETFD) } >= 0);
    drop(stream);
    assert!(server.join().unwrap().is_ok());
}

#[test]
fn borrowed_client_keeps_closed_truncated_and_oversized_response_errors_distinct() {
    for (bytes, expected) in [
        (vec![], "closed"),
        (vec![0, 0], "truncated"),
        (vec![0, 0, 0, 8, 1], "truncated"),
        (
            ((DEFAULT_MAX_FRAME_LEN + 1) as u32).to_be_bytes().to_vec(),
            "oversized",
        ),
    ] {
        let (mut stream, mut peer) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let server = std::thread::spawn(move || {
            let _: RequestEnvelope<u64> =
                decode(&read_message(&mut peer, DEFAULT_MAX_FRAME_LEN).unwrap()).unwrap();
            peer.write_all(&bytes).unwrap();
        });
        let config = Config::default();
        let result =
            BlockingRpcClient::<Echo>::from_borrowed_stream(&mut stream, Tid::from_raw(7), &config)
                .try_send_rpc(3);
        match expected {
            "closed" => assert!(matches!(result, Err(RpcError::Closed))),
            "truncated" => assert!(matches!(result, Err(RpcError::Io(ref error))
                if error.kind() == io::ErrorKind::UnexpectedEof)),
            "oversized" => assert!(matches!(result, Err(RpcError::FrameTooLarge { .. }))),
            _ => unreachable!(),
        }
        server.join().unwrap();
    }
}
