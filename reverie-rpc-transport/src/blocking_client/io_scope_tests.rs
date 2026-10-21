use std::cell::Cell;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use super::*;

thread_local! {
    static ACTIVE: Cell<i32> = const { Cell::new(-1) };
    static SERIALIZED: Cell<usize> = const { Cell::new(0) };
    static DESERIALIZED: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, PartialEq, Eq)]
struct Value(u8);

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        assert_eq!(ACTIVE.get(), -1, "user Serialize ran inside I/O scope");
        SERIALIZED.set(SERIALIZED.get() + 1);
        assert_ne!(self.0, 255, "deliberate Serialize panic");
        if self.0 == 254 {
            return Err(serde::ser::Error::custom("deliberate Serialize error"));
        }
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        assert_eq!(ACTIVE.get(), -1, "user Deserialize ran inside I/O scope");
        DESERIALIZED.set(DESERIALIZED.get() + 1);
        let value = u8::deserialize(deserializer)?;
        assert_ne!(value, 255, "deliberate Deserialize panic");
        if value == 254 {
            return Err(serde::de::Error::custom("deliberate Deserialize error"));
        }
        Ok(Self(value))
    }
}

#[derive(Default)]
struct Global;

#[async_trait]
impl GlobalTool for Global {
    type Request = Value;
    type Response = Value;
    type Config = ();

    async fn receive_rpc(&self, _: Tid, _: Value) -> Value {
        unreachable!("test peer verifies the actual wire frames")
    }
}

struct Scope {
    previous: i32,
    dropped: Arc<AtomicUsize>,
}

impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.set(self.previous);
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn enter(fd: RawFd, entered: &AtomicUsize, dropped: &Arc<AtomicUsize>) -> Scope {
    assert!(fd >= 0);
    entered.fetch_add(1, Ordering::SeqCst);
    Scope {
        previous: ACTIVE.replace(fd),
        dropped: dropped.clone(),
    }
}

fn pair() -> (BlockingRpcClient<Global>, UnixStream) {
    let (stream, peer) = UnixStream::pair().unwrap();
    for socket in [&stream, &peer] {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
    }
    (
        BlockingRpcClient {
            tid: Tid::from_raw(17),
            config: (),
            stream: Mutex::new(stream),
            _phantom: PhantomData,
        },
        peer,
    )
}

fn receive_request(peer: &mut UnixStream) {
    let bytes = read_message(peer, DEFAULT_MAX_FRAME_LEN).unwrap();
    let request: RequestEnvelope<Value> = decode(&bytes).unwrap();
    assert_eq!(request.from, Tid::from_raw(17));
    assert_eq!(request.request, Value(7));
}

#[test]
fn user_callbacks_run_outside_each_actual_stream_scope() {
    let (client, mut peer) = pair();
    let server = std::thread::spawn(move || {
        receive_request(&mut peer);
        write_message(&mut peer, &encode(&9u8).unwrap()).unwrap();
    });
    let entered = AtomicUsize::new(0);
    let dropped = Arc::new(AtomicUsize::new(0));
    let fd = client.as_raw_fd();
    let response = client
        .try_send_rpc_with_io_scope(Value(7), |actual| {
            assert_eq!(actual, fd);
            assert_eq!(ACTIVE.get(), -1);
            enter(actual, &entered, &dropped)
        })
        .unwrap();
    assert_eq!(response, Value(9));
    assert!(SERIALIZED.get() > 0);
    assert!(DESERIALIZED.get() > 0);
    assert!(entered.load(Ordering::SeqCst) >= 4);
    assert_eq!(
        entered.load(Ordering::SeqCst),
        dropped.load(Ordering::SeqCst)
    );
    assert_eq!(ACTIVE.get(), -1);
    server.join().unwrap();
}

#[test]
fn request_errors_and_panics_never_enter_io_scope() {
    for value in [254, 255] {
        let (client, _peer) = pair();
        let entered = AtomicUsize::new(0);
        let dropped = Arc::new(AtomicUsize::new(0));
        let result = catch_unwind(AssertUnwindSafe(|| {
            client.try_send_rpc_with_io_scope(Value(value), |fd| enter(fd, &entered, &dropped))
        }));
        if value == 254 {
            assert!(result.unwrap().is_err());
        } else {
            assert!(result.is_err());
        }
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(ACTIVE.get(), -1);
    }
}

#[test]
fn response_errors_and_panics_follow_completed_io_scopes() {
    for value in [254u8, 255] {
        let (client, mut peer) = pair();
        let server = std::thread::spawn(move || {
            receive_request(&mut peer);
            write_message(&mut peer, &encode(&value).unwrap()).unwrap();
        });
        let entered = AtomicUsize::new(0);
        let dropped = Arc::new(AtomicUsize::new(0));
        let result = catch_unwind(AssertUnwindSafe(|| {
            client.try_send_rpc_with_io_scope(Value(7), |fd| enter(fd, &entered, &dropped))
        }));
        if value == 254 {
            assert!(result.unwrap().is_err());
        } else {
            assert!(result.is_err());
        }
        assert!(entered.load(Ordering::SeqCst) >= 4);
        assert_eq!(
            entered.load(Ordering::SeqCst),
            dropped.load(Ordering::SeqCst)
        );
        assert_eq!(ACTIVE.get(), -1);
        server.join().unwrap();
    }
}

#[test]
fn stream_errors_drop_the_scope_before_returning() {
    for read_failure in [false, true] {
        let (client, mut peer) = pair();
        let server = read_failure.then(|| std::thread::spawn(move || receive_request(&mut peer)));
        let entered = AtomicUsize::new(0);
        let dropped = Arc::new(AtomicUsize::new(0));
        let result =
            client.try_send_rpc_with_io_scope(Value(7), |fd| enter(fd, &entered, &dropped));
        if read_failure {
            assert!(matches!(result, Err(RpcError::Closed)), "{result:?}");
        } else {
            assert!(matches!(result, Err(RpcError::Io(_))), "{result:?}");
        }
        assert!(entered.load(Ordering::SeqCst) > 0);
        assert_eq!(
            entered.load(Ordering::SeqCst),
            dropped.load(Ordering::SeqCst)
        );
        assert_eq!(ACTIVE.get(), -1);
        if let Some(server) = server {
            server.join().unwrap();
        }
    }
}

#[test]
fn native_blocked_read_holds_scope_until_completion() {
    let (mut stream, mut peer) = UnixStream::pair().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (started, ready) = std::sync::mpsc::sync_channel(0);
    let active = Arc::new(AtomicUsize::new(0));
    let reader_active = active.clone();
    let reader = std::thread::spawn(move || {
        struct Active(Arc<AtomicUsize>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.store(0, Ordering::SeqCst);
            }
        }
        let mut scope = |_| {
            reader_active.store(1, Ordering::SeqCst);
            started.send(()).unwrap();
            Active(reader_active.clone())
        };
        let mut io = ScopedIo {
            stream: &mut stream,
            enter: &mut scope,
        };
        let mut byte = [0];
        assert_eq!(io.read(&mut byte).unwrap(), 1);
        assert_eq!(byte, [91]);
        assert_eq!(reader_active.load(Ordering::SeqCst), 0);
    });
    ready.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 1);
    peer.write_all(&[91]).unwrap();
    reader.join().unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 0);
}
