use std::io;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::task::RawWaker;
use std::task::RawWakerVTable;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;

use reverie_rpc_transport::mapped::AsyncMappedStream;
use reverie_rpc_transport::mapped::MappedStream;
use reverie_rpc_transport::mapped::MappedWorkerFailure;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

const LIMIT: Duration = Duration::from_secs(3);
type Task = Arc<Mutex<Option<AsyncMappedStream>>>;

struct FirstWake {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    fail: bool,
}
impl Wake for FirstWake {
    fn wake(self: Arc<Self>) {
        eprintln!("FIRST_WAKE_ENTER {:?}", std::thread::current().id());
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(LIMIT).unwrap();
        if self.fail {
            panic!("controlled first Waker failure");
        }
        eprintln!("FIRST_WAKE_RETURN");
    }
}

struct Late {
    task: Task,
    in_stream_drop: Arc<AtomicBool>,
    normal_stop: bool,
    cloning: mpsc::Sender<()>,
    release_clone: Mutex<mpsc::Receiver<()>>,
    dropping: mpsc::Sender<()>,
    dropped: mpsc::Sender<()>,
}
impl Drop for Late {
    fn drop(&mut self) {
        eprintln!("LATE_OWNER_DROP_ENTER {:?}", std::thread::current().id());
        self.dropping.send(()).unwrap();
        // An ordinary task-owned destructor. The failed-worker ordering leaves
        // this final reference inside the stream being dropped under this lock.
        // Do not turn the fixture's own reference disposal into a production
        // failure. This callback models cleanup requiring the task mutex only
        // during cancellation; ordinary owner disposal needs no such cleanup.
        if self.normal_stop || self.in_stream_drop.load(Ordering::SeqCst) {
            let _guard = self.task.lock().unwrap();
            eprintln!("LATE_OWNER_DROP_ACQUIRED_TASK");
        } else {
            eprintln!("LATE_OWNER_DROP_OUTSIDE_STREAM_DROP");
        }
        self.dropped.send(()).unwrap();
    }
}

// Each raw handle owns exactly one Arc strong reference. The clone callback is
// thread-safe and preserves the original reference; only it adds a reference.
// Wake/drop consume one reference, wake_by_ref preserves it. No product pointer
// or shared-mapping memory is accessed by this vtable.
unsafe fn clone_late(data: *const ()) -> RawWaker {
    let arc = ManuallyDrop::new(unsafe { Arc::<Late>::from_raw(data.cast()) });
    eprintln!("LATE_CLONE_ENTER {:?}", std::thread::current().id());
    arc.cloning.send(()).unwrap();
    arc.release_clone
        .lock()
        .unwrap()
        .recv_timeout(LIMIT)
        .unwrap();
    let copy = Arc::clone(&arc);
    eprintln!("LATE_CLONE_RETURN");
    RawWaker::new(Arc::into_raw(copy).cast(), &LATE_VTABLE)
}
unsafe fn wake_late(data: *const ()) {
    drop(unsafe { Arc::<Late>::from_raw(data.cast()) });
}
unsafe fn wake_late_ref(_: *const ()) {}
unsafe fn drop_late(data: *const ()) {
    drop(unsafe { Arc::<Late>::from_raw(data.cast()) });
}
static LATE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_late, wake_late, wake_late_ref, drop_late);

fn poll(stream: &mut AsyncMappedStream, waker: &Waker) -> Poll<io::Result<()>> {
    let mut byte = [0];
    let mut buffer = ReadBuf::new(&mut byte);
    Pin::new(stream).poll_read(&mut Context::from_waker(waker), &mut buffer)
}

fn scenario(fail: bool) {
    let (host, mut peer) = MappedStream::pair(17).unwrap();
    let stream = host.into_async().unwrap();
    let completion = stream.completion();
    let task = Arc::new(Mutex::new(Some(stream)));
    let (entered, first_entered) = mpsc::channel();
    let (release_first, first_release) = mpsc::channel();
    let first = Waker::from(Arc::new(FirstWake {
        entered,
        release: Mutex::new(first_release),
        fail,
    }));
    assert!(poll(task.lock().unwrap().as_mut().unwrap(), &first).is_pending());
    first_entered.recv_timeout(LIMIT).unwrap();
    drop(first);

    let (cloning, clone_entered) = mpsc::channel();
    let (release_clone, clone_release) = mpsc::channel();
    let (dropping, drop_entered) = mpsc::channel();
    let (late_dropped, late_drop_done) = mpsc::channel();
    let (stream_dropped, stream_drop_done) = mpsc::channel();
    let (unlock, unlocked) = mpsc::channel();
    let cancel_task = task.clone();
    let in_stream_drop = Arc::new(AtomicBool::new(false));
    let canceller = std::thread::spawn(move || {
        let mut guard = cancel_task.lock().unwrap();
        let owner = Arc::new(Late {
            task: cancel_task.clone(),
            in_stream_drop: in_stream_drop.clone(),
            normal_stop: !fail,
            cloning,
            release_clone: Mutex::new(clone_release),
            dropping,
            dropped: late_dropped,
        });
        let late =
            unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(owner).cast(), &LATE_VTABLE)) };
        let result = poll(guard.as_mut().unwrap(), &late);
        eprintln!("LATE_POLL_RESULT {result:?}");
        if fail {
            assert!(
                matches!(result, Poll::Ready(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionReset)
            );
        } else {
            assert!(result.is_pending());
        }
        drop(late);
        eprintln!("STREAM_DROP_ENTER {:?}", std::thread::current().id());
        in_stream_drop.store(true, Ordering::SeqCst);
        drop(guard.take());
        in_stream_drop.store(false, Ordering::SeqCst);
        eprintln!("STREAM_DROP_RETURN");
        stream_dropped.send(()).unwrap();
        unlocked.recv_timeout(LIMIT).unwrap();
        drop(guard);
    });
    clone_entered.recv_timeout(LIMIT).unwrap();
    // Safe normal Drop cannot access this stream while the in-flight poll owns
    // its task guard. In the failing case, worker failure is independent of it.
    assert!(matches!(
        task.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    eprintln!("TASK_GUARD_EXCLUSIVE_DURING_CLONE");
    if fail {
        release_first.send(()).unwrap();
        use std::io::Read;
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            completion.wait_timeout(Duration::from_millis(100)),
            None,
            "worker joined while an admitted Waker clone was still paused"
        );
        eprintln!("FAILED_WORKER_COMPLETION_PENDING_DURING_ADMITTED_CLONE");
    }
    release_clone.send(()).unwrap();
    if fail {
        drop_entered.recv_timeout(LIMIT).unwrap();
    }
    assert!(
        stream_drop_done.recv_timeout(LIMIT).is_ok(),
        "stream Drop consumed a Waker published after failed-worker cleanup and blocked on the task lock"
    );
    if !fail {
        release_first.send(()).unwrap();
        drop_entered.recv_timeout(LIMIT).unwrap();
        assert_eq!(completion.result(), None);
    }
    unlock.send(()).unwrap();
    late_drop_done.recv_timeout(LIMIT).unwrap();
    canceller.join().unwrap();
    assert_eq!(
        completion.wait_timeout(LIMIT),
        Some(if fail {
            Err(MappedWorkerFailure::Panicked)
        } else {
            Ok(())
        })
    );
}

#[test]
fn failed_worker_late_registration_must_not_block_stream_drop() {
    scenario(true);
}
#[test]
fn normal_stop_waits_for_exclusive_poll_and_reaps_registered_waker() {
    scenario(false);
}
