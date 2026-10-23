/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */
//! Supplied-stream transport controls. These real sockets carry test-only
//! admission data; they are not native launch, kernel-exec or mask evidence.
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::*;
use crate::successor::ExpectedSuccessor;
use crate::successor::SuccessorRequest;

#[derive(Default)]
struct Echo;
#[async_trait]
impl GlobalTool for Echo {
    type Config = String;
    type Request = u64;
    type Response = u64;
    async fn receive_rpc(&self, _: Tid, _: u64) -> u64 {
        unreachable!("the test peer checks each actual frame")
    }
}

struct Chopped {
    socket: UnixStream,
    reads: usize,
    writes: usize,
    dropped: Arc<AtomicUsize>,
    write_failure: Option<io::ErrorKind>,
}
impl Read for Chopped {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if matches!(self.reads, 1 | 3) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let len = bytes.len().min(3);
        self.socket.read(&mut bytes[..len])
    }
}
impl Write for Chopped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if let Some(error) = self.write_failure {
            return if error == io::ErrorKind::WriteZero {
                Ok(0)
            } else {
                Err(error.into())
            };
        }
        if matches!(self.writes, 1 | 3) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.socket.write(&bytes[..bytes.len().min(2)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
impl AsRawFd for Chopped {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}
impl Drop for Chopped {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
fn pair() -> (Chopped, UnixStream, Arc<AtomicUsize>) {
    let (socket, peer) = UnixStream::pair().unwrap();
    for fd in [&socket, &peer] {
        fd.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        fd.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    (
        Chopped {
            socket,
            reads: 0,
            writes: 0,
            dropped: dropped.clone(),
            write_failure: None,
        },
        peer,
        dropped,
    )
}
fn state() -> Vec<u8> {
    encode(&(73_u64, "opaque successor test state")).unwrap()
}
fn config() -> Vec<u8> {
    encode(&"retained config".to_owned()).unwrap()
}
fn expected() -> ExpectedSuccessor {
    ExpectedSuccessor {
        config: crate::initial_image::config_digest(&config()),
        state: crate::initial_image::config_digest(&state()),
    }
}
fn request() -> SuccessorRequest<'static> {
    SuccessorRequest {
        ticket: b"one-use-test-ticket",
        expected: expected(),
    }
}
fn wire_request(successor: bool) -> Vec<u8> {
    if successor {
        crate::successor::encode_redemption(request()).unwrap()
    } else {
        crate::initial_image::encode_redemption(b"initial-test-nonce").unwrap()
    }
}
fn acknowledgement(successor: bool) -> Vec<u8> {
    if successor {
        crate::successor::encode_ack(request())
    } else {
        crate::initial_image::encode_ack(expected().config)
    }
}
fn admit(successor: bool, stream: Chopped) -> Result<BlockingRpcClient<Echo, Chopped>, RpcError> {
    let tid = Tid::from_raw(17);
    if successor {
        let admitted = BlockingRpcClient::successor_from_connected_stream(stream, tid, request())?;
        let (client, verified) = admitted.into_parts();
        assert_eq!(verified.expected(), expected());
        assert_eq!(verified.bytes(), state());
        Ok(client)
    } else {
        Ok(BlockingRpcClient::initial_image_from_connected_stream(
            stream,
            tid,
            b"initial-test-nonce",
            expected().config,
        )?
        .into_client())
    }
}
fn socket_identity(fd: RawFd) -> (u64, u64) {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
    (stat.st_dev, stat.st_ino)
}

#[test]
fn supplied_images_keep_one_socket_through_short_interrupted_handshakes_and_rpc() {
    for successor in [false, true] {
        let (stream, mut peer, dropped) = pair();
        let fd = stream.as_raw_fd();
        let identity = socket_identity(fd);
        let server = std::thread::spawn(move || {
            assert_eq!(
                read_message(&mut peer, DEFAULT_MAX_FRAME_LEN).unwrap(),
                wire_request(successor)
            );
            write_message(&mut peer, &acknowledgement(successor)).unwrap();
            write_message(&mut peer, &config()).unwrap();
            if successor {
                write_message(&mut peer, &state()).unwrap();
            }
            let request: RequestEnvelope<u64> =
                decode(&read_message(&mut peer, DEFAULT_MAX_FRAME_LEN).unwrap()).unwrap();
            assert_eq!(request.from, Tid::from_raw(17));
            assert_eq!(request.request, 41);
            write_message(&mut peer, &encode(&42_u64).unwrap()).unwrap();
            assert!(matches!(
                read_message(&mut peer, DEFAULT_MAX_FRAME_LEN),
                Err(RpcError::Closed)
            ));
        });
        let client = admit(successor, stream).unwrap();
        assert_eq!(client.config(), "retained config");
        assert_eq!(client.as_raw_fd(), fd);
        assert_eq!(socket_identity(client.as_raw_fd()), identity);
        assert_eq!(client.try_send_rpc(41).unwrap(), 42);
        let (tid, held_config, stream) = client.into_parts();
        assert_eq!(tid, Tid::from_raw(17));
        assert_eq!(held_config, "retained config");
        assert_eq!(stream.as_raw_fd(), fd);
        assert_eq!(socket_identity(stream.as_raw_fd()), identity);
        assert!(stream.reads > 3 && stream.writes > 3);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(stream);
        server.join().unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn supplied_images_preserve_clean_and_truncated_eof() {
    for successor in [false, true] {
        for reply in [vec![], vec![0, 0, 0], vec![0, 0, 0, 4, 1]] {
            let boundary = reply.is_empty();
            let (stream, mut peer, dropped) = pair();
            let server = std::thread::spawn(move || {
                assert_eq!(
                    read_message(&mut peer, DEFAULT_MAX_FRAME_LEN).unwrap(),
                    wire_request(successor)
                );
                peer.write_all(&reply).unwrap();
            });
            let error = match admit(successor, stream) {
                Ok(_) => panic!("truncated admission accepted"),
                Err(error) => error,
            };
            if boundary {
                assert!(matches!(error, RpcError::Closed));
            } else {
                assert!(
                    matches!(error, RpcError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof)
                );
            }
            server.join().unwrap();
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn supplied_images_reject_wrong_ack_config_and_successor_state() {
    for successor in [false, true] {
        for bad_frame in 0..if successor { 3 } else { 2 } {
            let (stream, mut peer, dropped) = pair();
            let server = std::thread::spawn(move || {
                assert_eq!(
                    read_message(&mut peer, DEFAULT_MAX_FRAME_LEN).unwrap(),
                    wire_request(successor)
                );
                let mut frames = vec![acknowledgement(successor), config()];
                if successor {
                    frames.push(state());
                }
                // Send through the invalid frame only; the client must refuse it.
                frames[bad_frame][0] ^= 1;
                for frame in frames.into_iter().take(bad_frame + 1) {
                    write_message(&mut peer, &frame).unwrap();
                }
            });
            let error = match admit(successor, stream) {
                Ok(_) => panic!("changed authenticated frame accepted"),
                Err(error) => error,
            };
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains(match bad_frame {
                    0 => "magic",
                    1 => "digest",
                    2 => "digest",
                    _ => unreachable!(),
                }),
                "{diagnostic}"
            );
            server.join().unwrap();
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn supplied_images_preserve_write_zero_and_hard_errors() {
    for successor in [false, true] {
        for kind in [io::ErrorKind::WriteZero, io::ErrorKind::BrokenPipe] {
            let (mut stream, _peer, dropped) = pair();
            stream.write_failure = Some(kind);
            let error = match admit(successor, stream) {
                Ok(_) => panic!("failed write accepted"),
                Err(error) => error,
            };
            assert!(matches!(error, RpcError::Io(error) if error.kind() == kind));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn ordinary_image_factories_validate_before_connecting() {
    let absent = "/not-a-real-native-rpc-parent/absent.sock";
    let tid = Tid::from_raw(17);
    let initial =
        BlockingRpcClient::<Echo>::connect_initial_image(absent, tid, b"", expected().config);
    assert!(
        matches!(initial, Err(RpcError::Io(error)) if error.to_string().contains("redemption length"))
    );
    let successor = BlockingRpcClient::<Echo>::connect_successor(
        absent,
        tid,
        SuccessorRequest {
            ticket: b"",
            expected: expected(),
        },
    );
    assert!(
        matches!(successor, Err(RpcError::Io(error)) if error.to_string().contains("ticket length"))
    );
}
