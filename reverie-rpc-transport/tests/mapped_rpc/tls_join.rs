use std::cell::RefCell;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::task::Context;
use std::task::Wake;
use std::task::Waker;
use std::time::Duration;

use reverie_rpc_transport::mapped::MappedStream;
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

const LIMIT: Duration = Duration::from_secs(3);
struct Teardown {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    done: mpsc::Sender<()>,
}
impl Drop for Teardown {
    fn drop(&mut self) {
        eprintln!("TLS_DESTRUCTOR_ENTER {:?}", std::thread::current().id());
        self.entered.send(()).unwrap();
        self.release.recv_timeout(LIMIT).unwrap();
        eprintln!("TLS_DESTRUCTOR_RETURN");
        self.done.send(()).unwrap();
    }
}
thread_local! { static EXIT: RefCell<Option<Teardown>> = const { RefCell::new(None) }; }
struct Install {
    state: Mutex<Option<Teardown>>,
    installed: mpsc::Sender<()>,
}
impl Wake for Install {
    fn wake(self: Arc<Self>) {
        let value = self.state.lock().unwrap().take().unwrap();
        EXIT.with(|slot| *slot.borrow_mut() = Some(value));
        self.installed.send(()).unwrap();
        eprintln!("WAKER_RETURN_AFTER_TLS_INSTALL");
    }
}

fn scenario(hold_a: bool) {
    let (a, _peer_a) = MappedStream::pair(7).unwrap();
    let mut a = a.into_async().unwrap();
    let completed_a = a.completion();
    let (entered, at_teardown) = mpsc::channel();
    let (release, wait_release) = mpsc::channel();
    let (done, teardown_done) = mpsc::channel();
    let (installed, is_installed) = mpsc::channel();
    let waker = Waker::from(Arc::new(Install {
        state: Mutex::new(Some(Teardown {
            entered,
            release: wait_release,
            done,
        })),
        installed,
    }));
    let mut byte = [0];
    assert!(
        Pin::new(&mut a)
            .poll_read(
                &mut Context::from_waker(&waker),
                &mut ReadBuf::new(&mut byte)
            )
            .is_pending()
    );
    is_installed.recv_timeout(LIMIT).unwrap();
    drop(waker);
    drop(a);
    at_teardown.recv_timeout(LIMIT).unwrap();
    assert_eq!(completed_a.result(), None);
    eprintln!("A_IN_TLS_TEARDOWN_COMPLETION_PENDING");
    if !hold_a {
        release.send(()).unwrap();
        teardown_done.recv_timeout(LIMIT).unwrap();
        assert_eq!(completed_a.wait_timeout(LIMIT), Some(Ok(())));
        eprintln!("CONTROL_A_JOINED_BEFORE_B");
    }
    let (b, _peer_b) = MappedStream::pair(7).unwrap();
    let mut b = b.into_async().unwrap();
    let completed_b = b.completion();
    let (b_entered, b_teardown) = mpsc::channel();
    let (b_release, b_wait) = mpsc::channel();
    let (b_done, b_done_rx) = mpsc::channel();
    let (b_installed, b_installed_rx) = mpsc::channel();
    b_release.send(()).unwrap();
    let b_waker = Waker::from(Arc::new(Install {
        state: Mutex::new(Some(Teardown {
            entered: b_entered,
            release: b_wait,
            done: b_done,
        })),
        installed: b_installed,
    }));
    assert!(
        Pin::new(&mut b)
            .poll_read(
                &mut Context::from_waker(&b_waker),
                &mut ReadBuf::new(&mut byte)
            )
            .is_pending()
    );
    b_installed_rx.recv_timeout(LIMIT).unwrap();
    drop(b_waker);
    drop(b);
    b_teardown.recv_timeout(LIMIT).unwrap();
    b_done_rx.recv_timeout(LIMIT).unwrap();
    eprintln!("B_USER_TLS_DESTRUCTOR_RETURNED_BEFORE_COMPLETION_WAIT");
    let independent = completed_b.wait_timeout(Duration::from_millis(400));
    eprintln!("B_WHILE_A_TEARDOWN {independent:?}");
    // Always release our own destructor and establish actual joins before the
    // independence assertion, including when the frozen implementation fails.
    if hold_a {
        release.send(()).unwrap();
        teardown_done.recv_timeout(LIMIT).unwrap();
    }
    assert_eq!(completed_a.wait_timeout(LIMIT), Some(Ok(())));
    assert_eq!(completed_b.wait_timeout(LIMIT), Some(Ok(())));
    eprintln!("BOTH_WORKERS_JOINED_SUCCESSFULLY_AFTER_RELEASE");
    assert_eq!(
        independent,
        Some(Ok(())),
        "shared reaper joined a worker still running its TLS destructor and stalled independent completion"
    );
}

#[test]
fn tls_released_control_completes_b_within_same_bound() {
    scenario(false);
}
#[test]
fn held_tls_destructor_must_not_stall_finished_b_completion() {
    scenario(true);
}
