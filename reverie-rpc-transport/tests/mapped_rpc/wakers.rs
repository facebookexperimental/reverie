use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::task::Context;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use reverie_rpc_transport::mapped::AsyncMappedStream;
use reverie_rpc_transport::mapped::MappedStream;
use reverie_rpc_transport::mapped::MappedWorkerFailure;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

const LIMIT: Duration = Duration::from_secs(3);

fn pending(stream: &mut AsyncMappedStream, waker: &Waker) {
    let mut byte = [0];
    let mut buffer = ReadBuf::new(&mut byte);
    assert!(
        Pin::new(stream)
            .poll_read(&mut Context::from_waker(waker), &mut buffer)
            .is_pending()
    );
}

struct LastOwner {
    stream: Mutex<Option<AsyncMappedStream>>,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    destroyed: mpsc::Sender<()>,
}
impl Wake for LastOwner {
    fn wake(self: Arc<Self>) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(LIMIT).unwrap();
    }
}
impl Drop for LastOwner {
    fn drop(&mut self) {
        self.destroyed.send(()).unwrap();
    }
}

#[test]
fn last_waker_owner_can_destroy_stream_on_notification_worker() {
    let (host, mut peer) = MappedStream::pair(17).unwrap();
    let stream = host.into_async().unwrap();
    let completion = stream.completion();
    let (entered, ready) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let (destroyed, gone) = mpsc::channel();
    let owner = Arc::new(LastOwner {
        stream: Mutex::new(Some(stream)),
        entered,
        release: Mutex::new(wait),
        destroyed,
    });
    let waker = Waker::from(owner.clone());
    pending(owner.stream.lock().unwrap().as_mut().unwrap(), &waker);
    ready.recv_timeout(LIMIT).unwrap();
    drop(waker);
    drop(owner);
    release.send(()).unwrap();
    gone.recv_timeout(LIMIT).unwrap();
    assert_eq!(
        completion.wait_timeout(LIMIT),
        Some(Ok(())),
        "last-owner Waker did not produce joined successful completion"
    );
    assert_eq!(
        peer.read(&mut [0]).unwrap(),
        0,
        "last-owner destruction did not close the peer normally"
    );
    assert_eq!(
        peer.write(b"closed").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

struct TaskLock {
    task: Arc<Mutex<Option<AsyncMappedStream>>>,
    entered: mpsc::Sender<()>,
    acquired: mpsc::Sender<()>,
}
impl Wake for TaskLock {
    fn wake(self: Arc<Self>) {
        self.entered.send(()).unwrap();
        let _guard = self.task.lock().unwrap();
        self.acquired.send(()).unwrap();
    }
}

#[test]
fn cancellation_under_task_lock_does_not_join_its_waker() {
    let (host, mut peer) = MappedStream::pair(17).unwrap();
    let stream = host.into_async().unwrap();
    let completion = stream.completion();
    let task = Arc::new(Mutex::new(Some(stream)));
    let (entered, ready) = mpsc::channel();
    let (acquired, acquired_rx) = mpsc::channel();
    let waker = Waker::from(Arc::new(TaskLock {
        task: task.clone(),
        entered,
        acquired,
    }));
    let (dropped, dropped_rx) = mpsc::channel();
    let (unlock, unlock_rx) = mpsc::channel();
    let canceller = std::thread::spawn(move || {
        let mut guard = task.lock().unwrap();
        pending(guard.as_mut().unwrap(), &waker);
        ready.recv_timeout(LIMIT).unwrap();
        // The worker is inside wake(), waiting for this exact task mutex.
        drop(guard.take());
        dropped.send(()).unwrap();
        unlock_rx.recv_timeout(LIMIT).unwrap();
        drop(guard);
    });
    assert!(
        dropped_rx.recv_timeout(LIMIT).is_ok(),
        "stream Drop waited on a Waker holding the task lock"
    );
    assert_eq!(
        completion.result(),
        None,
        "stop was reported as actual completion while the Waker remained blocked"
    );
    let (other, _other_peer) = MappedStream::pair(7).unwrap();
    let other = other.into_async().unwrap();
    let independent = other.completion();
    drop(other);
    assert_eq!(
        independent.wait_timeout(LIMIT),
        Some(Ok(())),
        "an unfinished Waker stalled independent worker completion"
    );
    unlock.send(()).unwrap();
    acquired_rx.recv_timeout(LIMIT).unwrap();
    canceller.join().unwrap();
    assert_eq!(
        completion.wait_timeout(LIMIT),
        Some(Ok(())),
        "cancelled worker was not joined after its task lock was released"
    );
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    assert_eq!(
        peer.write(b"closed").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

struct Panicking;
impl Wake for Panicking {
    fn wake(self: Arc<Self>) {
        panic!("intentional notification Waker panic");
    }
}

#[test]
fn waker_panic_preserves_failed_completion_and_peer_failure() {
    let (host, mut peer) = MappedStream::pair(7).unwrap();
    let mut stream = host.into_async().unwrap();
    let completion = stream.completion();
    pending(&mut stream, &Waker::from(Arc::new(Panicking)));
    assert_eq!(
        completion.wait_timeout(LIMIT),
        Some(Err(MappedWorkerFailure::Panicked))
    );
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(
        peer.write(b"failed").unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    drop(stream);
    assert_eq!(
        completion.result(),
        Some(Err(MappedWorkerFailure::Panicked))
    );
}

struct Count(mpsc::Sender<Instant>);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.send(Instant::now()).unwrap();
    }
}

#[test]
fn idle_registered_reader_records_timeout_wakes() {
    let (host, _peer) = MappedStream::pair(7).unwrap();
    let mut stream = host.into_async().unwrap();
    let completion = stream.completion();
    let (notify, receive) = mpsc::channel();
    let waker = Waker::from(Arc::new(Count(notify)));
    pending(&mut stream, &waker);
    // Synchronize with the worker's initial loop before measuring idle cycles.
    let first = receive.recv_timeout(LIMIT).unwrap();
    let mut previous = first;
    let mut intervals = Vec::new();
    for _ in 0..10 {
        pending(&mut stream, &waker);
        let now = receive.recv_timeout(LIMIT).unwrap();
        intervals.push(now.duration_since(previous).as_nanos());
        previous = now;
    }
    eprintln!(
        "IDLE_WAKE_MEASUREMENT samples=10 elapsed_ns={} intervals_ns={intervals:?}",
        previous.duration_since(first).as_nanos()
    );
    drop(stream);
    assert_eq!(completion.wait_timeout(LIMIT), Some(Ok(())));
}
