use std::collections::HashMap;
use std::sync::mpsc;

use super::*;

const LIMIT: Duration = Duration::from_secs(3);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Point {
    Reserved,
    HelperSpawn,
    HelperEntry,
    HelperReturned,
    HelperHandedOff,
    ReaperReserved,
    ReaperSpawn,
    ReaperEntry,
    ReaperReturned,
    ReaperHandedOff,
    BeforeWorker,
    WorkerSpawn,
    WorkerEntry,
    WorkerReturned,
    WorkerHandedOff,
    BeforePublication,
    BeforeJoin,
    HelperAfterWorker,
    ReaperExit,
}
#[derive(Default)]
pub(super) struct Hooks {
    actions: Mutex<HashMap<Point, Action>>,
    entries: Mutex<Vec<(Point, i32)>>,
}
enum Action {
    Pause(mpsc::Sender<()>, mpsc::Receiver<()>),
    Panic,
    Error,
    Tls(HeldPayload),
    PanicTls(HeldPayload),
}
impl Hooks {
    pub(super) fn at(&self, point: Point) {
        if matches!(
            point,
            Point::HelperEntry | Point::WorkerEntry | Point::ReaperEntry
        ) {
            self.entries
                .lock()
                .unwrap()
                .push((point, unsafe { libc::gettid() }));
        }
        let action = self.actions.lock().unwrap().remove(&point);
        match action {
            Some(Action::Pause(entered, release)) => {
                entered.send(()).unwrap();
                release.recv_timeout(LIMIT).unwrap();
            }
            Some(Action::Panic) => panic!("controlled {point:?} unwind"),
            Some(Action::Tls(payload)) => {
                HELPER_TLS.with(|slot| *slot.borrow_mut() = Some(payload))
            }
            Some(Action::PanicTls(payload)) => {
                HELPER_TLS.with(|slot| *slot.borrow_mut() = Some(payload));
                panic!("controlled pre-readiness panic with native TLS cleanup");
            }
            Some(Action::Error) => panic!("spawn error hook used as callback"),
            None => {}
        }
    }
    pub(super) fn spawn_error(&self, point: Point) -> io::Result<()> {
        match self.actions.lock().unwrap().remove(&point) {
            Some(Action::Error) => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
            None => Ok(()),
            _ => panic!("non-error action at spawn hook"),
        }
    }
    fn pause(&self, point: Point) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, waiting) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        assert!(
            self.actions
                .lock()
                .unwrap()
                .insert(point, Action::Pause(entered, resume))
                .is_none()
        );
        (waiting, release)
    }
    fn panic(&self, point: Point) {
        self.actions.lock().unwrap().insert(point, Action::Panic);
    }
    fn error(&self, point: Point) {
        self.actions.lock().unwrap().insert(point, Action::Error);
    }
}
fn start(
    registry: &Arc<Registry>,
    work: impl FnOnce() -> Outcome + Send + 'static,
) -> io::Result<MappedCompletion> {
    registry.spawn(
        move |ready| {
            ready.mark();
            work()
        },
        MappedCompletion::new(),
        Arc::new(AtomicBool::new(false)),
        None,
    )
}
fn drain(registry: &Arc<Registry>) {
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        let mut state = registry.state.lock().unwrap();
        // is_finished bounds Rust-body progress only. The actual join below
        // remains responsible for native TLS completion and runs without this lock.
        if state.current.as_ref().unwrap().is_finished() {
            assert_eq!(state.phase, Phase::Idle);
            assert!(state.records.is_empty());
            assert_eq!(state.reservations, 0);
            assert!(state.retiring.is_none());
            assert!(!state.recovering_current && !state.recovering_retiring);
            let handle = state.current.take().unwrap();
            drop(state);
            handle.join().unwrap();
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "registry cleanup remained pending"
        );
        drop(state);
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn completion_retains_io_error_and_unexpected_thread_panic() {
    let registry = Arc::new(Registry::default());
    let io = start(&registry, || {
        Err(io::Error::from_raw_os_error(libc::EINVAL).into())
    })
    .unwrap();
    assert_eq!(
        io.wait_timeout(LIMIT),
        Some(Err(MappedWorkerFailure::Io {
            kind: io::ErrorKind::InvalidInput,
            raw_os_error: Some(libc::EINVAL)
        }))
    );
    let panic = start(&registry, || panic!("intentional uncontained worker panic")).unwrap();
    assert_eq!(
        panic.wait_timeout(LIMIT),
        Some(Err(MappedWorkerFailure::Panicked))
    );
    assert_eq!(io.wait_helper_timeout(LIMIT), Some(Ok(())));
    assert_eq!(panic.wait_helper_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
}
#[test]
fn registration_while_previous_reaper_is_exiting_keeps_all_handles_owned() {
    let registry = Arc::new(Registry::default());
    let (exiting, release) = registry.hooks.pause(Point::ReaperExit);
    let first = start(&registry, || Ok(())).unwrap();
    assert_eq!(first.wait_timeout(LIMIT), Some(Ok(())));
    exiting.recv_timeout(LIMIT).unwrap();
    {
        let state = registry.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Idle);
        assert!(!state.current.as_ref().unwrap().is_finished());
    }
    let (created, received) = mpsc::channel();
    let registering = registry.clone();
    let creator = std::thread::spawn(move || {
        created
            .send(start(&registering, || Ok(())).unwrap())
            .unwrap()
    });
    let second = received
        .recv_timeout(LIMIT)
        .expect("registration joined a still-exiting reaper");
    creator.join().unwrap();
    assert_eq!(second.wait_timeout(LIMIT), Some(Ok(())));
    {
        let state = registry.state.lock().unwrap();
        assert_eq!(
            state.phase,
            Phase::Running,
            "successor retired before joining its predecessor"
        );
        assert!(!state.retiring.as_ref().unwrap().is_finished());
    }
    release.send(()).unwrap();
    drain(&registry);
    assert_eq!(first.helper_result(), Some(Ok(())));
    assert_eq!(second.helper_result(), Some(Ok(())));
}

#[test]
fn every_constructor_unwind_after_spawn_keeps_owned_handles() {
    for point in [
        Point::HelperReturned,
        Point::HelperHandedOff,
        Point::ReaperReserved,
        Point::ReaperReturned,
        Point::ReaperHandedOff,
        Point::BeforeWorker,
        Point::WorkerReturned,
        Point::WorkerHandedOff,
        Point::BeforePublication,
    ] {
        let registry = Arc::new(Registry::default());
        registry.hooks.panic(point);
        let completion = MappedCompletion::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = entered.clone();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            registry.spawn(
                move |ready| {
                    ready.mark();
                    worker_entered.store(true, Ordering::Release);
                    while !stop.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    Ok(())
                },
                completion.clone(),
                stopped,
                None,
            )
        }));
        assert!(attempt.is_err(), "unwind point was not reached: {point:?}");
        let next = start(&registry, || Ok(())).unwrap();
        assert_eq!(next.wait_timeout(LIMIT), Some(Ok(())));
        drain(&registry);
        let spawned = matches!(
            point,
            Point::WorkerReturned | Point::WorkerHandedOff | Point::BeforePublication
        );
        assert_eq!(entered.load(Ordering::Acquire), spawned, "{point:?}");
        assert_eq!(
            completion.result(),
            if spawned { Some(Ok(())) } else { None },
            "{point:?}"
        );
        assert_eq!(
            completion.helper_result(),
            Some(Ok(())),
            "unjoined helper at {point:?}"
        );
    }
}

#[test]
fn spawn_failures_preserve_error_and_leave_no_notification_worker() {
    for (point, stage) in [
        (Point::HelperSpawn, MappedStartStage::HelperSpawn),
        (Point::ReaperSpawn, MappedStartStage::ReaperSpawn),
        (Point::WorkerSpawn, MappedStartStage::WorkerSpawn),
    ] {
        let registry = Arc::new(Registry::default());
        registry.hooks.error(point);
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = entered.clone();
        let error = start(&registry, move || {
            worker_entered.store(true, Ordering::Release);
            Ok(())
        })
        .unwrap_err();
        let source = error
            .get_ref()
            .unwrap()
            .downcast_ref::<MappedStartError>()
            .unwrap();
        assert_eq!(source.stage(), stage);
        assert_eq!(source.cause.raw_os_error(), Some(libc::EAGAIN));
        let observed = source.completion();
        assert_eq!(observed.result(), None);
        let next = start(&registry, || Ok(())).unwrap();
        assert_eq!(next.wait_timeout(LIMIT), Some(Ok(())));
        drain(&registry);
        assert!(!entered.load(Ordering::Acquire));
        assert_eq!(
            observed.helper_result(),
            if point == Point::HelperSpawn {
                None
            } else {
                Some(Ok(()))
            }
        );
    }
}

#[test]
fn failed_helper_readiness_stays_owned_until_later_successful_constructor() {
    let registry = Arc::new(Registry::default());
    registry.hooks.panic(Point::HelperEntry);
    let error = start(&registry, || {
        panic!("worker started before helper readiness")
    })
    .unwrap_err();
    let source = error
        .get_ref()
        .unwrap()
        .downcast_ref::<MappedStartError>()
        .unwrap();
    assert_eq!(source.stage(), MappedStartStage::HelperReadiness);
    let completion = source.completion();
    assert_eq!(completion.result(), None);
    assert_eq!(completion.helper_result(), None);
    {
        let state = registry.state.lock().unwrap();
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.phase, Phase::Idle);
        assert!(state.current.is_none());
    }
    let next = start(&registry, || Ok(())).unwrap();
    assert_eq!(next.wait_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
    assert_eq!(
        completion.helper_result(),
        Some(Err(MappedHelperFailure::Panicked))
    );
}

#[test]
fn pending_helper_readiness_does_not_serialize_another_constructor() {
    let registry = Arc::new(Registry::default());
    let (entered, release) = registry.hooks.pause(Point::HelperEntry);
    let other = registry.clone();
    let (ready, received) = mpsc::channel();
    let constructor =
        std::thread::spawn(move || ready.send(start(&other, || Ok(())).unwrap()).unwrap());
    entered.recv_timeout(LIMIT).unwrap();
    let second = start(&registry, || Ok(())).unwrap();
    let independent = second.wait_timeout(Duration::from_millis(400));
    assert!(received.try_recv().is_err());
    release.send(()).unwrap();
    let first = received.recv_timeout(LIMIT).unwrap();
    constructor.join().unwrap();
    assert_eq!(first.wait_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
    assert_eq!(
        independent,
        Some(Ok(())),
        "another constructor waited for A's helper readiness"
    );
}

#[test]
fn failed_successor_recovery_retains_two_handles_without_retry() {
    let registry = Arc::new(Registry::default());
    let (exiting, release) = registry.hooks.pause(Point::ReaperExit);
    let first = start(&registry, || Ok(())).unwrap();
    assert_eq!(first.wait_timeout(LIMIT), Some(Ok(())));
    exiting.recv_timeout(LIMIT).unwrap();
    registry.hooks.panic(Point::ReaperEntry);
    let error = start(&registry, || {
        panic!("worker started after failed reaper readiness")
    })
    .unwrap_err();
    let source = error
        .get_ref()
        .unwrap()
        .downcast_ref::<MappedStartError>()
        .unwrap();
    assert_eq!(source.stage(), MappedStartStage::ReaperReadiness);
    let failed = source.completion();
    {
        let state = registry.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Recovering);
        assert!(state.current.is_none() && state.retiring.is_none());
        assert!(state.recovering_retiring);
    }
    assert_eq!(failed.result(), None);
    assert_eq!(failed.helper_result(), None);
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + LIMIT;
    loop {
        let state = registry.state.lock().unwrap();
        if state.phase == Phase::Idle {
            assert!(state.current.is_none() && state.retiring.is_none());
            assert!(!state.recovering_current && !state.recovering_retiring);
            assert_eq!(state.records.len(), 1);
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        drop(state);
        std::thread::yield_now();
    }
    assert_eq!(
        failed.helper_result(),
        None,
        "recovery helper was reported joined without a cleanup actor"
    );
    let next = start(&registry, || Ok(())).unwrap();
    assert_eq!(next.wait_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
    assert_eq!(failed.helper_result(), Some(Ok(())));
    assert_eq!(
        failed.reaper_recovery(),
        [MappedReaperCleanup::Panicked, MappedReaperCleanup::Joined]
    );
    assert_eq!(registry.state.lock().unwrap().reaper_panics, 1);
}

#[test]
fn constructor_reservation_prevents_reaper_retirement_during_spawn_handoff() {
    let registry = Arc::new(Registry::default());
    let (finish, finished) = mpsc::channel();
    let first = start(&registry, move || {
        finished.recv_timeout(LIMIT).unwrap();
        Ok(())
    })
    .unwrap();
    let (reserved, release) = registry.hooks.pause(Point::Reserved);
    let other = registry.clone();
    let creator = std::thread::spawn(move || start(&other, || Ok(())).unwrap());
    reserved.recv_timeout(LIMIT).unwrap();
    finish.send(()).unwrap();
    assert_eq!(first.wait_timeout(LIMIT), Some(Ok(())));
    assert_eq!(first.wait_helper_timeout(LIMIT), Some(Ok(())));
    {
        let state = registry.state.lock().unwrap();
        assert_eq!(state.phase, Phase::Running);
        assert_eq!(state.reservations, 1);
        assert!(state.current.is_some());
    }
    release.send(()).unwrap();
    let second = creator.join().unwrap();
    assert_eq!(second.wait_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
}

#[test]
fn helper_pre_join_unwind_restores_then_consumes_exact_worker_handle() {
    let registry = Arc::new(Registry::default());
    registry.hooks.panic(Point::BeforeJoin);
    let completion = start(&registry, || Ok(())).unwrap();
    assert_eq!(completion.wait_timeout(LIMIT), Some(Ok(())));
    assert_eq!(
        completion.wait_helper_timeout(LIMIT),
        Some(Err(MappedHelperFailure::Panicked))
    );
    drain(&registry);
}

struct HeldPayload {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}
impl Drop for HeldPayload {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(LIMIT).unwrap();
    }
}
#[test]
fn worker_result_precedes_helper_payload_cleanup_and_other_worker_join() {
    let registry = Arc::new(Registry::default());
    let (entered, waiting) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = start(&registry, move || {
        std::panic::panic_any(HeldPayload {
            entered,
            release: resume,
        })
    })
    .unwrap();
    waiting.recv_timeout(LIMIT).unwrap();
    assert_eq!(first.result(), Some(Err(MappedWorkerFailure::Panicked)));
    assert_eq!(first.helper_result(), None);
    let second = start(&registry, || Ok(())).unwrap();
    let independent = second.wait_timeout(Duration::from_millis(400));
    release.send(()).unwrap();
    drain(&registry);
    assert_eq!(first.helper_result(), Some(Ok(())));
    assert_eq!(second.helper_result(), Some(Ok(())));
    assert_eq!(
        independent,
        Some(Ok(())),
        "A's helper payload cleanup delayed B's worker join"
    );
}

thread_local! { static HELPER_TLS: std::cell::RefCell<Option<HeldPayload>> = const { std::cell::RefCell::new(None) }; }
#[test]
fn helper_native_tls_keeps_cleanup_pending_without_delaying_other_worker() {
    let registry = Arc::new(Registry::default());
    let (entered, waiting) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    registry.hooks.actions.lock().unwrap().insert(
        Point::HelperAfterWorker,
        Action::Tls(HeldPayload {
            entered,
            release: resume,
        }),
    );
    let first = start(&registry, || Ok(())).unwrap();
    waiting.recv_timeout(LIMIT).unwrap();
    assert_eq!(first.result(), Some(Ok(())));
    assert_eq!(first.helper_result(), None);
    let second = start(&registry, || Ok(())).unwrap();
    let independent = second.wait_timeout(Duration::from_millis(400));
    release.send(()).unwrap();
    drain(&registry);
    assert_eq!(first.helper_result(), Some(Ok(())));
    assert_eq!(second.helper_result(), Some(Ok(())));
    assert_eq!(
        independent,
        Some(Ok(())),
        "held helper native TLS delayed B's notification-worker join"
    );
}

#[test]
fn secondary_payload_panic_is_reported_as_incomplete_reclamation() {
    struct Primary(Arc<std::sync::atomic::AtomicUsize>);
    struct Secondary(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Primary {
        fn drop(&mut self) {
            std::panic::panic_any(Secondary(self.0.clone()));
        }
    }
    impl Drop for Secondary {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("secondary destructor must not run");
        }
    }
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = drops.clone();
    let registry = Arc::new(Registry::default());
    let completion = start(&registry, move || std::panic::panic_any(Primary(drops))).unwrap();
    assert_eq!(
        completion.wait_timeout(LIMIT),
        Some(Err(MappedWorkerFailure::Panicked))
    );
    assert_eq!(
        completion.wait_helper_timeout(LIMIT),
        Some(Err(MappedHelperFailure::PanicPayloadLeaked))
    );
    drain(&registry);
    assert_eq!(observed.load(Ordering::SeqCst), 0);
}

#[test]
fn two_connections_own_two_notification_threads_two_helpers_and_one_reaper() {
    let registry = Arc::new(Registry::default());
    let (release_a, wait_a) = mpsc::channel();
    let (release_b, wait_b) = mpsc::channel();
    let a = start(&registry, move || {
        wait_a.recv_timeout(LIMIT).unwrap();
        Ok(())
    })
    .unwrap();
    let b = start(&registry, move || {
        wait_b.recv_timeout(LIMIT).unwrap();
        Ok(())
    })
    .unwrap();
    let deadline = std::time::Instant::now() + LIMIT;
    let entries = loop {
        let entries = registry.hooks.entries.lock().unwrap().clone();
        if entries.len() == 5 {
            break entries;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    };
    let unique: std::collections::HashSet<_> = entries.iter().map(|(_, tid)| *tid).collect();
    assert_eq!(unique.len(), 5);
    for (point, expected) in [
        (Point::WorkerEntry, 2),
        (Point::HelperEntry, 2),
        (Point::ReaperEntry, 1),
    ] {
        assert_eq!(
            entries.iter().filter(|(p, _)| *p == point).count(),
            expected
        );
    }
    let names: Vec<_> = entries
        .iter()
        .map(|(point, tid)| {
            (
                *point,
                *tid,
                std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")).unwrap(),
            )
        })
        .collect();
    eprintln!(
        "MAPPED_THREAD_RESOURCES connections=2 notification_threads=2 joining_helpers=2 resource_reapers=1 live={names:?}"
    );
    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    assert_eq!(a.wait_timeout(LIMIT), Some(Ok(())));
    assert_eq!(b.wait_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
}

#[test]
fn failed_helper_native_tls_does_not_delay_startup_error_or_b_worker_join() {
    let registry = Arc::new(Registry::default());
    let (entered, waiting) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    registry.hooks.actions.lock().unwrap().insert(
        Point::HelperEntry,
        Action::PanicTls(HeldPayload {
            entered,
            release: resume,
        }),
    );
    let error = start(&registry, || panic!("worker started before readiness")).unwrap_err();
    let source = error
        .get_ref()
        .unwrap()
        .downcast_ref::<MappedStartError>()
        .unwrap();
    assert_eq!(source.stage(), MappedStartStage::HelperReadiness);
    let first = source.completion();
    waiting.recv_timeout(LIMIT).unwrap();
    assert_eq!(first.result(), None);
    assert_eq!(first.helper_result(), None);
    let second = start(&registry, || Ok(())).unwrap();
    let independent = second.wait_timeout(Duration::from_millis(400));
    release.send(()).unwrap();
    drain(&registry);
    assert_eq!(
        first.helper_result(),
        Some(Err(MappedHelperFailure::Panicked))
    );
    assert_eq!(second.helper_result(), Some(Ok(())));
    assert_eq!(
        independent,
        Some(Ok(())),
        "failed helper native TLS delayed B's notification-worker join"
    );
}

#[test]
fn repeated_failed_start_records_have_no_automatic_retries_and_later_drain() {
    let registry = Arc::new(Registry::default());
    let mut completions = Vec::new();
    for point in [
        Point::HelperEntry,
        Point::HelperEntry,
        Point::ReaperEntry,
        Point::ReaperEntry,
    ] {
        registry.hooks.panic(point);
        let error = start(&registry, || {
            panic!("notification worker admitted on failed startup")
        })
        .unwrap_err();
        let completion = error
            .get_ref()
            .unwrap()
            .downcast_ref::<MappedStartError>()
            .unwrap()
            .completion();
        let deadline = std::time::Instant::now() + LIMIT;
        loop {
            let state = registry.state.lock().unwrap();
            if state.phase == Phase::Idle {
                assert_eq!(state.records.len(), completions.len() + 1);
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            drop(state);
            std::thread::yield_now();
        }
        assert_eq!(completion.result(), None);
        assert_eq!(completion.helper_result(), None);
        completions.push(completion);
    }
    let entries = registry.hooks.entries.lock().unwrap().clone();
    assert_eq!(
        entries
            .iter()
            .filter(|(p, _)| *p == Point::ReaperEntry)
            .count(),
        2
    );
    assert_eq!(
        entries
            .iter()
            .filter(|(p, _)| *p == Point::WorkerEntry)
            .count(),
        0
    );
    let next = start(&registry, || Ok(())).unwrap();
    assert_eq!(next.wait_timeout(LIMIT), Some(Ok(())));
    drain(&registry);
    for (index, completion) in completions.iter().enumerate() {
        assert_eq!(
            completion.helper_result(),
            Some(if index < 2 {
                Err(MappedHelperFailure::Panicked)
            } else {
                Ok(())
            })
        );
        assert_eq!(
            completion.reaper_recovery(),
            if index < 2 {
                [MappedReaperCleanup::NotRequired; 2]
            } else {
                [
                    MappedReaperCleanup::Panicked,
                    MappedReaperCleanup::NotRequired,
                ]
            }
        );
    }
}

#[test]
fn failed_notification_entry_keeps_adapter_unpublished_and_preserves_actual_join() {
    let registry = Arc::new(Registry::default());
    let (entered, waiting) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    registry.hooks.actions.lock().unwrap().insert(
        Point::WorkerEntry,
        Action::PanicTls(HeldPayload {
            entered,
            release: resume,
        }),
    );
    let error = start(&registry, || {
        panic!("private notification body ran after its pre-entry panic")
    })
    .unwrap_err();
    let source = error
        .get_ref()
        .unwrap()
        .downcast_ref::<MappedStartError>()
        .unwrap();
    assert_eq!(source.stage(), MappedStartStage::WorkerReadiness);
    let first = source.completion();
    waiting.recv_timeout(LIMIT).unwrap();
    assert_eq!(first.result(), None);
    assert_eq!(first.helper_result(), None);
    let second = start(&registry, || Ok(())).unwrap();
    let independent = second.wait_timeout(Duration::from_millis(400));
    release.send(()).unwrap();
    assert_eq!(
        first.wait_timeout(LIMIT),
        Some(Err(MappedWorkerFailure::Panicked))
    );
    drain(&registry);
    assert_eq!(first.helper_result(), Some(Ok(())));
    assert_eq!(second.helper_result(), Some(Ok(())));
    assert_eq!(
        independent,
        Some(Ok(())),
        "A's failed notification entry delayed B's actual worker join"
    );
}
