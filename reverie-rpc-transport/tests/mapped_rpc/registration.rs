use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::task::Context;
use std::task::RawWaker;
use std::task::RawWakerVTable;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;

use reverie_rpc_transport::mapped::AsyncMappedStream;
use reverie_rpc_transport::mapped::MappedStream;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

const LIMIT: Duration = Duration::from_secs(3);
fn pending(stream: &mut AsyncMappedStream, waker: &Waker) {
    assert!(
        Pin::new(stream)
            .poll_read(&mut Context::from_waker(waker), &mut ReadBuf::new(&mut [0]))
            .is_pending()
    );
}
struct CloneState {
    panic_next: AtomicBool,
    clones: AtomicUsize,
    consumed: Mutex<Vec<std::thread::ThreadId>>,
    woke: mpsc::Sender<()>,
}
unsafe fn clone(data: *const ()) -> RawWaker {
    let state = ManuallyDrop::new(unsafe { Arc::<CloneState>::from_raw(data.cast()) });
    state.clones.fetch_add(1, Ordering::SeqCst);
    if state.panic_next.swap(false, Ordering::SeqCst) {
        panic!("controlled clone panic before producing a reference");
    }
    RawWaker::new(Arc::into_raw(Arc::clone(&state)).cast(), &VTABLE)
}
unsafe fn consume(data: *const ()) {
    let state = unsafe { Arc::<CloneState>::from_raw(data.cast()) };
    state
        .consumed
        .lock()
        .unwrap()
        .push(std::thread::current().id());
}
unsafe fn wake(data: *const ()) {
    let state = unsafe { Arc::<CloneState>::from_raw(data.cast()) };
    state
        .consumed
        .lock()
        .unwrap()
        .push(std::thread::current().id());
    state.woke.send(()).unwrap();
}
unsafe fn wake_by_ref(data: *const ()) {
    let state = ManuallyDrop::new(unsafe { Arc::<CloneState>::from_raw(data.cast()) });
    state.woke.send(()).unwrap();
}
static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, consume);

#[test]
fn clone_unwind_releases_reservation_without_owning_its_panic_payload() {
    let (host, _peer) = MappedStream::pair(7).unwrap();
    let mut stream = host.into_async().unwrap();
    let completed = stream.completion();
    let (woke, received) = mpsc::channel();
    let state = Arc::new(CloneState {
        panic_next: AtomicBool::new(true),
        clones: AtomicUsize::new(0),
        consumed: Mutex::new(Vec::new()),
        woke,
    });
    // Each raw handle owns one Arc. The failing clone produces no new handle.
    let waker =
        unsafe { Waker::from_raw(RawWaker::new(Arc::into_raw(state.clone()).cast(), &VTABLE)) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pending(&mut stream, &waker)
    }));
    assert_eq!(
        result.unwrap_err().downcast_ref::<&str>(),
        Some(&"controlled clone panic before producing a reference")
    );
    pending(&mut stream, &waker);
    received.recv_timeout(LIMIT).unwrap();
    drop(waker);
    drop(stream);
    assert_eq!(completed.wait_timeout(LIMIT), Some(Ok(())));
    assert_eq!(completed.wait_helper_timeout(LIMIT), Some(Ok(())));
    assert_eq!(state.clones.load(Ordering::SeqCst), 2);
    assert_eq!(Arc::strong_count(&state), 1);
    let consumed = state.consumed.lock().unwrap();
    assert_eq!(consumed.len(), 2);
    assert_eq!(
        consumed
            .iter()
            .filter(|id| **id == std::thread::current().id())
            .count(),
        1
    );
}

struct First {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl Wake for First {
    fn wake(self: Arc<Self>) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(LIMIT).unwrap();
    }
}
struct Replacement {
    task: Arc<Mutex<Option<AsyncMappedStream>>>,
    destroyed: mpsc::Sender<()>,
}
impl Wake for Replacement {
    fn wake(self: Arc<Self>) {
        panic!("a replaced Waker was woken instead of disposed");
    }
}
impl Drop for Replacement {
    fn drop(&mut self) {
        let _guard = self.task.lock().unwrap();
        self.destroyed.send(()).unwrap();
    }
}
#[test]
fn replacement_disposes_the_prior_waker_on_worker_outside_task_lock() {
    let (host, _peer) = MappedStream::pair(7).unwrap();
    let stream = host.into_async().unwrap();
    let completed = stream.completion();
    let task = Arc::new(Mutex::new(Some(stream)));
    let (entered, waiting) = mpsc::channel();
    let (release_first, resume_first) = mpsc::channel();
    let first = Waker::from(Arc::new(First {
        entered,
        release: Mutex::new(resume_first),
    }));
    pending(task.lock().unwrap().as_mut().unwrap(), &first);
    waiting.recv_timeout(LIMIT).unwrap();
    drop(first);
    let (destroyed, destruction) = mpsc::channel();
    let (replaced, replacement) = mpsc::channel();
    let (unlock, wait_unlock) = mpsc::channel();
    let owned_task = task.clone();
    let canceller = std::thread::spawn(move || {
        let mut guard = owned_task.lock().unwrap();
        let waker = Waker::from(Arc::new(Replacement {
            task: owned_task.clone(),
            destroyed,
        }));
        pending(guard.as_mut().unwrap(), &waker);
        drop(waker);
        pending(guard.as_mut().unwrap(), Waker::noop());
        replaced.send(()).unwrap();
        wait_unlock.recv_timeout(LIMIT).unwrap();
        drop(guard.take());
        drop(guard);
    });
    let replaced_without_locking = replacement.recv_timeout(LIMIT).is_ok();
    unlock.send(()).unwrap();
    release_first.send(()).unwrap();
    destruction.recv_timeout(LIMIT).unwrap();
    canceller.join().unwrap();
    assert_eq!(completed.wait_timeout(LIMIT), Some(Ok(())));
    assert_eq!(completed.wait_helper_timeout(LIMIT), Some(Ok(())));
    assert!(
        replaced_without_locking,
        "replacement destroyed the prior Waker under the polling task lock"
    );
}
