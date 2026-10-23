#![cfg(target_os = "linux")]

use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RequestEnvelope;
use reverie_rpc_transport::RpcError;
use reverie_rpc_transport::codec;
use reverie_rpc_transport::mapped::MappedFailure;
use reverie_rpc_transport::mapped::MappedStream;
use reverie_rpc_transport::serve_stream;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

const LIMIT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Wait,
    Release,
    Large,
    Echo(Vec<u8>),
}
#[derive(Default)]
struct Global {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait]
impl GlobalTool for Global {
    type Request = Request;
    type Response = Vec<u8>;
    type Config = Vec<u8>;
    async fn receive_rpc(&self, _: Tid, request: Request) -> Vec<u8> {
        match request {
            Request::Wait => {
                self.entered.notify_one();
                self.release.notified().await;
                b"released".to_vec()
            }
            Request::Release => {
                self.release.notify_one();
                b"release acknowledged".to_vec()
            }
            Request::Large => {
                self.entered.notify_one();
                vec![0x93; 262_147]
            }
            Request::Echo(bytes) => bytes,
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
}

#[test]
fn independent_pending_rpcs_can_release_each_other() {
    runtime().block_on(async {
        let global = Arc::new(Global::default());
        let (host_a, guest_a) = MappedStream::pair(17).unwrap();
        let (host_b, guest_b) = MappedStream::pair(19).unwrap();
        let a = tokio::spawn(serve_stream(
            global.clone(),
            b"config-a".to_vec(),
            host_a.into_async().unwrap(),
        ));
        let b = tokio::spawn(serve_stream(
            global.clone(),
            b"config-b".to_vec(),
            host_b.into_async().unwrap(),
        ));
        let (done_a, result_a) = tokio::sync::oneshot::channel();
        let client_a = std::thread::spawn(move || {
            let client =
                BlockingRpcClient::<Global, _>::from_connected_stream(guest_a, Tid::from_raw(1))
                    .unwrap();
            assert_eq!(client.config(), b"config-a");
            done_a
                .send(client.try_send_rpc(Request::Wait).unwrap())
                .unwrap();
        });
        tokio::time::timeout(LIMIT, global.entered.notified())
            .await
            .unwrap();
        let (done_b, result_b) = tokio::sync::oneshot::channel();
        let client_b = std::thread::spawn(move || {
            let client =
                BlockingRpcClient::<Global, _>::from_connected_stream(guest_b, Tid::from_raw(2))
                    .unwrap();
            assert_eq!(client.config(), b"config-b");
            done_b
                .send(client.try_send_rpc(Request::Release).unwrap())
                .unwrap();
        });
        assert_eq!(
            tokio::time::timeout(LIMIT, result_b)
                .await
                .expect("B was blocked behind A")
                .unwrap(),
            b"release acknowledged"
        );
        assert_eq!(
            tokio::time::timeout(LIMIT, result_a)
                .await
                .unwrap()
                .unwrap(),
            b"released"
        );
        client_a.join().unwrap();
        client_b.join().unwrap();
        tokio::time::timeout(LIMIT, a)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(LIMIT, b)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    });
}

fn read_frame(stream: &mut MappedStream) -> Vec<u8> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= codec::DEFAULT_MAX_FRAME_LEN);
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}
fn write_frame(stream: &mut MappedStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
    stream.flush().unwrap();
}

#[test]
fn blocked_large_response_leaves_other_connection_and_blocking_pool_available() {
    runtime().block_on(async {
        let global = Arc::new(Global::default());
        let (host_a, mut guest_a) = MappedStream::pair(31).unwrap();
        let (host_b, guest_b) = MappedStream::pair(23).unwrap();
        let a = tokio::spawn(serve_stream(
            global.clone(),
            vec![],
            host_a.into_async().unwrap(),
        ));
        let b = tokio::spawn(serve_stream(
            global.clone(),
            vec![],
            host_b.into_async().unwrap(),
        ));
        let (release, allow_read) = std::sync::mpsc::channel();
        let (done_a, result_a) = tokio::sync::oneshot::channel();
        let client_a = std::thread::spawn(move || {
            assert_eq!(
                codec::decode::<Vec<u8>>(&read_frame(&mut guest_a)).unwrap(),
                Vec::<u8>::new()
            );
            write_frame(
                &mut guest_a,
                &codec::encode(&RequestEnvelope {
                    from: Tid::from_raw(3),
                    request: Request::Large,
                })
                .unwrap(),
            );
            allow_read.recv_timeout(LIMIT).unwrap();
            let response: Vec<u8> = codec::decode(&read_frame(&mut guest_a)).unwrap();
            assert_eq!(
                response,
                vec![0x93; 262_147],
                "large response changed bytes"
            );
            done_a.send(()).unwrap();
        });
        tokio::time::timeout(LIMIT, global.entered.notified())
            .await
            .unwrap();
        let marker = tokio::task::spawn_blocking(|| 42);
        assert_eq!(
            tokio::time::timeout(LIMIT, marker)
                .await
                .expect("mapped response occupied the sole blocking worker")
                .unwrap(),
            42
        );
        let (done_b, result_b) = tokio::sync::oneshot::channel();
        let client_b = std::thread::spawn(move || {
            let client =
                BlockingRpcClient::<Global, _>::from_connected_stream(guest_b, Tid::from_raw(4))
                    .unwrap();
            let sent: Vec<u8> = (0..8193).map(|i| (i * 7) as u8).collect();
            assert_eq!(
                client.try_send_rpc(Request::Echo(sent.clone())).unwrap(),
                sent
            );
            done_b.send(()).unwrap();
        });
        tokio::time::timeout(LIMIT, result_b)
            .await
            .expect("unread A response blocked B")
            .unwrap();
        release.send(()).unwrap();
        tokio::time::timeout(LIMIT, result_a)
            .await
            .unwrap()
            .unwrap();
        client_a.join().unwrap();
        client_b.join().unwrap();
        tokio::time::timeout(LIMIT, a)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(LIMIT, b)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    });
}

#[test]
fn partial_headers_are_failures_and_empty_eof_remains_closed() {
    runtime().block_on(async {
        use tokio::io::AsyncWriteExt;
        for prefix in 0..4 {
            let (mut writer, mut reader) = tokio::io::duplex(8);
            writer.write_all(&[0, 0, 0][..prefix]).await.unwrap(); drop(writer);
            let error = codec::read_message(&mut reader, 1024).await.unwrap_err();
            if prefix == 0 { assert!(matches!(error, RpcError::Closed)); }
            else { assert!(matches!(error, RpcError::Io(ref e) if e.kind() == io::ErrorKind::UnexpectedEof), "partial header {prefix} was accepted as clean closure: {error:?}"); }
        }
        for payload in [b"".as_slice(), b"whole"] {
            let (mut writer, mut reader) = tokio::io::duplex(32);
            codec::write_message(&mut writer, payload).await.unwrap(); drop(writer);
            assert_eq!(codec::read_message(&mut reader, 1024).await.unwrap(), payload);
            assert!(matches!(codec::read_message(&mut reader, 1024).await, Err(RpcError::Closed)));
        }
    });
}

#[test]
fn mapped_partial_request_is_not_a_successful_server_completion() {
    runtime().block_on(async {
        for prefix in 1..4 {
            let (host, mut guest) = MappedStream::pair(32).unwrap();
            let server = tokio::spawn(serve_stream(
                Arc::new(Global::default()),
                vec![],
                host.into_async().unwrap(),
            ));
            let (done, result) = tokio::sync::oneshot::channel();
            let sender = std::thread::spawn(move || {
                read_frame(&mut guest);
                guest.write_all(&[0, 0, 0][..prefix]).unwrap();
                guest.close_write();
                done.send(()).unwrap();
            });
            tokio::time::timeout(LIMIT, result).await.unwrap().unwrap();
            let error = tokio::time::timeout(LIMIT, server)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(
                matches!(error, RpcError::Io(ref e) if e.kind() == io::ErrorKind::UnexpectedEof),
                "partial mapped header {prefix}: {error:?}"
            );
            sender.join().unwrap();
        }
    });
}

#[test]
fn cancellation_wakes_client_waiting_inside_rpc() {
    runtime().block_on(async {
        let global = Arc::new(Global::default());
        let (host, guest) = MappedStream::pair(7).unwrap();
        let abort = host.abort_handle();
        let server = tokio::spawn(serve_stream(global.clone(), vec![], host.into_async().unwrap()));
        let (done, result) = tokio::sync::oneshot::channel();
        let client = std::thread::spawn(move || {
            let client = BlockingRpcClient::<Global, _>::from_connected_stream(guest, Tid::from_raw(5)).unwrap();
            let error = client.try_send_rpc(Request::Wait).unwrap_err();
            assert!(matches!(error, RpcError::Io(ref e) if e.kind() == io::ErrorKind::ConnectionAborted), "{error:?}");
            done.send(()).unwrap();
        });
        tokio::time::timeout(LIMIT, global.entered.notified()).await.unwrap();
        abort.abort(MappedFailure::Cancelled);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        tokio::time::timeout(LIMIT, result).await.unwrap().unwrap(); client.join().unwrap();
    });
}

#[path = "mapped_rpc/process.rs"]
mod process;

#[path = "mapped_rpc/wakers.rs"]
mod wakers;

#[path = "mapped_rpc/late_registration.rs"]
mod late_registration;

#[path = "mapped_rpc/tls_join.rs"]
mod tls_join;

#[path = "mapped_rpc/registration.rs"]
mod registration;
