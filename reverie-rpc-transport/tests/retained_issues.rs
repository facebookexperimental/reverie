use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::ConnectionFailure;
use reverie_rpc_transport::RpcServer;
use tokio::io::AsyncWriteExt;

#[derive(Default)]
struct Panics;
#[async_trait]
impl GlobalTool for Panics {
    type Config = ();
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Tid, _: ()) {
        panic!("retained connection panic");
    }
}

async fn handshake(stream: &mut tokio::net::UnixStream) {
    reverie_rpc_transport::codec::read_message(stream, 1024)
        .await
        .unwrap();
}

#[tokio::test]
async fn actual_mid_frame_error_is_retained_outside_server() {
    let path = format!("/tmp/rli-{}-error", std::process::id());
    let mut server = RpcServer::bind(&path, Arc::new(()), ()).unwrap();
    let monitor = server.retain_connection_issues();
    let task = tokio::spawn(server.serve());
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    handshake(&mut stream).await;
    stream.write_all(&[5, 0]).await.unwrap();
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), monitor.failed())
        .await
        .unwrap();
    monitor.planned_shutdown();
    task.abort();
    let _ = task.await;
    let issues = monitor.snapshot();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].connection, 1);
    let ConnectionFailure::Transport(error) = &issues[0].failure else {
        panic!("{issues:?}");
    };
    assert!(
        matches!(&**error, reverie_rpc_transport::RpcError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
}

#[tokio::test]
async fn actual_tool_panic_and_planned_shutdown_are_distinct() {
    let path = format!("/tmp/rli-{}-panic", std::process::id());
    let mut server = RpcServer::bind(&path, Arc::new(Panics), ()).unwrap();
    let monitor = server.retain_connection_issues();
    let task = tokio::spawn(server.serve());
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    handshake(&mut stream).await;
    let request = reverie_rpc_transport::RequestEnvelope {
        from: Tid::from_raw(1),
        request: (),
    };
    let bytes = reverie_rpc_transport::codec::encode(&request).unwrap();
    reverie_rpc_transport::codec::write_message(&mut stream, &bytes)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), monitor.failed())
        .await
        .unwrap();
    let snapshot = monitor.snapshot();
    let ConnectionFailure::Panicked(payload) = &snapshot[0].failure else {
        panic!("{snapshot:?}");
    };
    assert_eq!(
        payload.0.lock().unwrap().downcast_ref::<&str>(),
        Some(&"retained connection panic")
    );
    monitor.planned_shutdown();
    task.abort();
    let _ = task.await;
    assert_eq!(monitor.snapshot().len(), 1);
}

#[tokio::test]
async fn normal_eof_and_planned_cancellation_do_not_create_rpc_errors() {
    let path = format!("/tmp/rli-{}-clean", std::process::id());
    let mut server = RpcServer::bind(&path, Arc::new(()), ()).unwrap();
    let monitor = server.retain_connection_issues();
    let connections = server.connection_monitor();
    let task = tokio::spawn(server.serve());
    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    handshake(&mut stream).await;
    drop(stream);
    connections.wait_for_idle().await;
    let mut live = tokio::net::UnixStream::connect(&path).await.unwrap();
    handshake(&mut live).await;
    monitor.planned_shutdown();
    task.abort();
    let _ = task.await;
    connections.wait_for_idle().await;
    assert!(monitor.snapshot().is_empty());
}

#[tokio::test]
async fn retained_errors_fill_capacity_without_discarding_any_cause() {
    let path = format!("/tmp/rli-{}-capacity", std::process::id());
    let mut server = RpcServer::bind(&path, Arc::new(()), ()).unwrap();
    let monitor = server.retain_connection_issues();
    let task = tokio::spawn(server.serve());
    for expected in 1..=64 {
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        handshake(&mut stream).await;
        stream.write_all(&[0, 0]).await.unwrap();
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), async {
            while monitor.snapshot().len() < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    let _extra = tokio::net::UnixStream::connect(&path).await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("capacity exhausted"));
    let issues = monitor.snapshot();
    assert_eq!(issues.len(), 64);
    for (index, issue) in issues.iter().enumerate() {
        assert_eq!(issue.connection, index + 1);
        assert!(matches!(issue.failure, ConnectionFailure::Transport(_)));
    }
}
