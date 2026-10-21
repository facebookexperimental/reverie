use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

type OpenAnchor = Arc<dyn Fn() -> io::Result<File> + Send + Sync>;
type ObserveAnchor = Arc<dyn Fn(&File) -> io::Result<usize> + Send + Sync>;
type ExitBarrier = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

#[derive(Clone, Debug)]
struct ErrorSnapshot {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
    message: String,
}

impl ErrorSnapshot {
    fn new(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }

    fn error(&self) -> io::Error {
        self.raw_os_error
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::new(self.kind, self.message.clone()))
    }
}

#[derive(Clone, Debug)]
enum Startup {
    Starting { attempt: u64 },
    Anchored,
    Failed { attempt: u64, error: ErrorSnapshot },
}

struct State {
    startup: Startup,
    retry: bool,
    anchor: Option<File>,
    detached: bool,
}

struct Inner {
    state: Mutex<State>,
    changed: Condvar,
    open: OpenAnchor,
    observe: ObserveAnchor,
}

/// A generation-bound proc anchor for exactly one successfully spawned worker.
///
/// The worker cannot enter arbitrary capture code until it has opened and
/// validated its own `/proc/thread-self/stat`. The retained file continues to
/// identify that original task even if its numeric TID is later reused.
#[derive(Clone)]
pub(super) struct TaskExit(Arc<Inner>);

#[derive(Debug, Eq, PartialEq)]
enum Poll {
    Pending,
    Detached,
    Fault(String),
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Settlement {
    Complete,
    Pending,
    Fault(String),
}

impl TaskExit {
    pub(super) fn new() -> Self {
        Self::with_operations(Arc::new(open_anchor), Arc::new(observe_anchor))
    }

    fn with_operations(open: OpenAnchor, observe: ObserveAnchor) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                startup: Startup::Starting { attempt: 1 },
                retry: false,
                anchor: None,
                detached: false,
            }),
            changed: Condvar::new(),
            open,
            observe,
        }))
    }

    #[cfg(test)]
    pub(super) fn fail_while(blocked: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self::with_operations(
            Arc::new(move || {
                if blocked.load(std::sync::atomic::Ordering::Acquire) {
                    Err(io::Error::from_raw_os_error(libc::EACCES))
                } else {
                    open_anchor()
                }
            }),
            Arc::new(observe_anchor),
        )
    }

    /// Run the worker body only after its own anchor is safely held. An anchor
    /// error leaves the real worker parked, with its closure and JoinHandle
    /// still owned, until the owner requests a fresh acquisition attempt.
    pub(super) fn run(self, body: Box<dyn FnOnce() + Send>) {
        let mut attempt = 1;
        loop {
            match (self.0.open)() {
                Ok(anchor) => {
                    let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
                    state.anchor = Some(anchor);
                    state.startup = Startup::Anchored;
                    self.0.changed.notify_all();
                    drop(state);
                    body();
                    return;
                }
                Err(error) => {
                    let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
                    state.startup = Startup::Failed {
                        attempt,
                        error: ErrorSnapshot::new(&error),
                    };
                    self.0.changed.notify_all();
                    while !state.retry {
                        state = self
                            .0
                            .changed
                            .wait(state)
                            .unwrap_or_else(|p| p.into_inner());
                    }
                    state.retry = false;
                    attempt = attempt.saturating_add(1);
                    state.startup = Startup::Starting { attempt };
                    self.0.changed.notify_all();
                }
            }
        }
    }

    /// Observe the first acquisition only. Startup must expose a procfs error
    /// rather than silently retrying it behind the owner's finite deadline.
    pub(super) fn initial_until(&self, deadline: Instant) -> io::Result<bool> {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            match &state.startup {
                Startup::Anchored => return Ok(true),
                Startup::Failed { error, .. } => return Err(error.error()),
                Startup::Starting { .. } => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            state = self
                .0
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Request exactly one fresh acquisition after a reported startup error.
    /// A caller can retry the retained owner later without changing the first
    /// failure classification.
    fn recover_once_until(&self, deadline: Instant) -> io::Result<bool> {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        let target_attempt = loop {
            match &state.startup {
                Startup::Anchored => return Ok(true),
                Startup::Failed { attempt, .. } => {
                    let target = attempt.saturating_add(1);
                    state.retry = true;
                    self.0.changed.notify_all();
                    break target;
                }
                Startup::Starting { .. } => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(false);
                    }
                    state = self
                        .0
                        .changed
                        .wait_timeout(state, deadline - now)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
            }
        };
        loop {
            match &state.startup {
                Startup::Anchored => return Ok(true),
                Startup::Failed { attempt, error } if *attempt >= target_attempt => {
                    return Err(error.error());
                }
                Startup::Starting { attempt } if *attempt >= target_attempt => {}
                _ => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            state = self
                .0
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    fn poll(&self) -> Poll {
        let mut state = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.detached {
            return Poll::Detached;
        }
        let Some(anchor) = state.anchor.as_ref() else {
            return Poll::Fault("worker has no validated proc task anchor".into());
        };
        match (self.0.observe)(anchor) {
            Ok(0) => Poll::Fault("proc task anchor returned unexpected EOF".into()),
            Ok(_) => Poll::Pending,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                state.detached = true;
                Poll::Detached
            }
            Err(error) => Poll::Fault(format!("proc task anchor observation failed: {error}")),
        }
    }

    #[cfg(test)]
    pub(super) fn detached_for_test(&self) -> bool {
        self.0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .detached
    }

    #[cfg(test)]
    pub(super) fn startup_attempt_for_test(&self) -> u64 {
        match &self
            .0
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .startup
        {
            Startup::Starting { attempt } | Startup::Failed { attempt, .. } => *attempt,
            Startup::Anchored => u64::MAX,
        }
    }
}

/// The split-only pair of worker identities. Ordinary capture keeps its
/// existing startup and teardown behavior.
pub(super) struct TaskExits {
    pub(super) publication: Option<TaskExit>,
    pub(super) collector: Option<TaskExit>,
    barrier_complete: bool,
    barrier: ExitBarrier,
    #[cfg(test)]
    join_completion_probe: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl Default for TaskExits {
    fn default() -> Self {
        Self {
            publication: None,
            collector: None,
            barrier_complete: false,
            barrier: Arc::new(rusage_self_barrier),
            #[cfg(test)]
            join_completion_probe: None,
        }
    }
}

impl TaskExits {
    #[cfg(test)]
    pub(super) fn install_barrier_probe(&mut self, completed: Arc<std::sync::atomic::AtomicBool>) {
        self.barrier = Arc::new(move || {
            rusage_self_barrier()?;
            completed.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        });
    }

    #[cfg(test)]
    pub(super) fn install_drop_order_probes(
        &mut self,
        joins_completed: Arc<std::sync::atomic::AtomicBool>,
        barrier_completed: Arc<std::sync::atomic::AtomicBool>,
    ) {
        self.join_completion_probe = Some(joins_completed.clone());
        self.barrier = Arc::new(move || {
            assert!(
                joins_completed.load(std::sync::atomic::Ordering::Acquire),
                "task-exit barrier ran before both blocking joins completed"
            );
            rusage_self_barrier()?;
            barrier_completed.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        });
    }

    #[cfg(test)]
    pub(super) fn publish_blocking_joins_for_test(
        &self,
        collector_result: Option<bool>,
        publication_result: Option<bool>,
    ) {
        if collector_result.is_some() && publication_result.is_some() {
            if let Some(completed) = &self.join_completion_probe {
                completed.store(true, std::sync::atomic::Ordering::Release);
            }
        }
    }

    pub(super) fn recover_startup_until(&self, deadline: Instant) -> io::Result<bool> {
        for worker in [&self.publication, &self.collector].into_iter().flatten() {
            if !worker.recover_once_until(deadline)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn recover_startup_blocking(&self) {
        for worker in [&self.publication, &self.collector].into_iter().flatten() {
            loop {
                match worker.recover_once_until(Instant::now() + Duration::from_millis(100)) {
                    Ok(true) => break,
                    Ok(false) | Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        }
    }

    pub(super) fn settle_until(&mut self, deadline: Instant) -> Settlement {
        if self.barrier_complete {
            return Settlement::Complete;
        }
        loop {
            let mut complete = true;
            for worker in [&self.publication, &self.collector].into_iter().flatten() {
                match worker.poll() {
                    Poll::Detached => {}
                    Poll::Pending => complete = false,
                    Poll::Fault(reason) => return Settlement::Fault(reason),
                }
            }
            if complete {
                // Linux 4.4/5.4 serialize getrusage(RUSAGE_SELF) through the
                // sighand lock held across __unhash_process; Linux 6.12 and the
                // audited host use signal->stats_lock, which also encloses the
                // PID detach and thread-node unlink. This is an implementation
                // ordering audit, not a POSIX synchronization guarantee.
                return match (self.barrier)() {
                    Ok(()) => {
                        self.barrier_complete = true;
                        Settlement::Complete
                    }
                    Err(error) => {
                        Settlement::Fault(format!("RUSAGE_SELF task-exit barrier failed: {error}"))
                    }
                };
            }
            if Instant::now() >= deadline {
                return Settlement::Pending;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    pub(super) fn settle_blocking(&mut self) {
        while !self.settle_blocking_step(std::thread::sleep) {}
    }

    fn settle_blocking_step(&mut self, pause: impl FnOnce(Duration)) -> bool {
        if self.settle_until(Instant::now() + Duration::from_millis(100)) == Settlement::Complete {
            true
        } else {
            // Drop deliberately retains all owned resources on a permanent
            // observation fault. The pause prevents an unavailable procfs or
            // broken anchor from becoming an unbounded busy loop.
            pause(Duration::from_millis(10));
            false
        }
    }
}

fn open_anchor() -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/proc/thread-self/stat")?;
    let mut byte = [0u8; 1];
    match file.read_at(&mut byte, 0)? {
        0 => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty /proc/thread-self/stat",
        )),
        _ => Ok(file),
    }
}

fn observe_anchor(file: &File) -> io::Result<usize> {
    let mut byte = [0u8; 1];
    file.read_at(&mut byte, 0)
}

fn rusage_self_barrier() -> io::Result<()> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    use super::*;

    fn anchored_with(observations: Arc<Mutex<VecDeque<io::Result<usize>>>>) -> TaskExit {
        let exit = TaskExit::with_operations(
            Arc::new(open_anchor),
            Arc::new(move |_| {
                observations
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("bounded observation")
            }),
        );
        let worker = exit.clone();
        let thread = std::thread::spawn(move || worker.run(Box::new(|| {})));
        assert!(
            exit.initial_until(Instant::now() + Duration::from_secs(2))
                .unwrap()
        );
        thread.join().unwrap();
        exit
    }

    #[test]
    fn joined_pending_errors_and_barrier_order_are_fail_closed() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let observations = Arc::new(Mutex::new(VecDeque::from([
            Ok(1),
            Err(io::Error::from_raw_os_error(libc::ESRCH)),
        ])));
        let exit = anchored_with(observations);
        let barrier_events = events.clone();
        let mut exits = TaskExits {
            publication: Some(exit),
            collector: None,
            barrier_complete: false,
            barrier: Arc::new(move || {
                barrier_events.lock().unwrap().push("barrier");
                Ok(())
            }),
            join_completion_probe: None,
        };
        assert_eq!(exits.settle_until(Instant::now()), Settlement::Pending);
        events.lock().unwrap().push("after-pending");
        assert_eq!(
            exits.settle_until(Instant::now() + Duration::from_secs(1)),
            Settlement::Complete
        );
        assert_eq!(&*events.lock().unwrap(), &["after-pending", "barrier"]);

        for result in [
            Ok(0),
            Err(io::Error::from_raw_os_error(libc::EIO)),
            Err(io::Error::from_raw_os_error(libc::EINTR)),
        ] {
            let exit = anchored_with(Arc::new(Mutex::new(VecDeque::from([result]))));
            let mut exits = TaskExits {
                publication: Some(exit),
                collector: None,
                barrier_complete: false,
                barrier: Arc::new(|| panic!("fault must not reach barrier")),
                join_completion_probe: None,
            };
            assert!(matches!(
                exits.settle_until(Instant::now() + Duration::from_secs(1)),
                Settlement::Fault(_)
            ));
        }
    }

    #[test]
    fn anchor_failure_parks_body_and_later_recovery_preserves_owner() {
        let blocked = Arc::new(AtomicBool::new(true));
        let ran = Arc::new(AtomicBool::new(false));
        let exit = TaskExit::fail_while(blocked.clone());
        let worker = exit.clone();
        let body_ran = ran.clone();
        let thread = std::thread::spawn(move || {
            worker.run(Box::new(move || body_ran.store(true, Ordering::Release)))
        });
        assert_eq!(
            exit.initial_until(Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert!(!ran.load(Ordering::Acquire));
        assert_eq!(
            exit.recover_once_until(Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert!(!ran.load(Ordering::Acquire));
        blocked.store(false, Ordering::Release);
        assert!(
            exit.recover_once_until(Instant::now() + Duration::from_secs(1))
                .unwrap()
        );
        thread.join().unwrap();
        assert!(ran.load(Ordering::Acquire));
    }

    #[test]
    fn real_join_and_barrier_ignore_an_unrelated_live_worker() {
        let unrelated_stop = Arc::new(AtomicBool::new(false));
        let stop = unrelated_stop.clone();
        let unrelated = std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        });
        let exit = TaskExit::new();
        let worker = exit.clone();
        let tracked = std::thread::spawn(move || worker.run(Box::new(|| {})));
        assert!(
            exit.initial_until(Instant::now() + Duration::from_secs(2))
                .unwrap()
        );
        tracked.join().unwrap();
        let mut exits = TaskExits {
            publication: Some(exit),
            collector: None,
            ..TaskExits::default()
        };
        assert_eq!(
            exits.settle_until(Instant::now() + Duration::from_secs(2)),
            Settlement::Complete
        );
        assert!(!unrelated.is_finished());
        unrelated_stop.store(true, Ordering::Release);
        unrelated.join().unwrap();
    }

    #[test]
    fn panicked_worker_still_requires_and_completes_task_exit_barrier() {
        let exit = TaskExit::new();
        let worker = exit.clone();
        let tracked = std::thread::spawn(move || {
            worker.run(Box::new(|| panic!("injected worker-body panic")))
        });
        assert!(
            exit.initial_until(Instant::now() + Duration::from_secs(2))
                .unwrap()
        );
        assert!(tracked.join().is_err());
        let mut exits = TaskExits {
            publication: None,
            collector: Some(exit),
            ..TaskExits::default()
        };
        assert_eq!(
            exits.settle_until(Instant::now() + Duration::from_secs(2)),
            Settlement::Complete
        );
    }

    #[test]
    fn permanent_fault_blocking_step_retains_resources_and_pauses() {
        struct Retained(Arc<AtomicBool>);
        impl Drop for Retained {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let retained = Retained(dropped.clone());
        let exit = anchored_with(Arc::new(Mutex::new(VecDeque::from([Err(
            io::Error::from_raw_os_error(libc::EIO),
        )]))));
        let mut exits = TaskExits {
            publication: Some(exit),
            collector: None,
            barrier_complete: false,
            barrier: Arc::new(|| panic!("fault must not reach barrier")),
            join_completion_probe: None,
        };
        let pauses = Arc::new(Mutex::new(Vec::new()));
        let observed_pauses = pauses.clone();
        assert!(!exits.settle_blocking_step(move |duration| {
            observed_pauses.lock().unwrap().push(duration);
        }));
        assert_eq!(&*pauses.lock().unwrap(), &[Duration::from_millis(10)]);
        assert!(!dropped.load(Ordering::Acquire));
        drop(retained);
        assert!(dropped.load(Ordering::Acquire));
    }
}
