//! Backend lifecycle controls. These observe real callback ordering, not native
//! selected-file or capability evidence. Native tests require the maintained owner.
use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde::Serialize;

use super::*;

#[derive(Default)]
struct Log {
    ready: SyncMutex<Vec<(i32, usize, usize)>>,
    dispatched: AtomicUsize,
    failures: AtomicUsize,
}
#[derive(Serialize, Deserialize)]
struct Seen {
    pointer: usize,
    phase: usize,
}
#[reverie::global_tool]
impl GlobalTool for Log {
    type Config = ();
    type Request = Seen;
    type Response = ();
    async fn receive_rpc(&self, from: Pid, seen: Seen) {
        assert_eq!(
            self.ready
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|row| row.0 == from.as_raw())
                .copied(),
            Some((from.as_raw(), seen.pointer, seen.phase))
        );
        self.dispatched.fetch_add(1, Ordering::SeqCst);
    }
    fn report_backend_failure(&self, _failure: reverie::BackendFailure) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct ReadyTool;
#[reverie::tool]
impl Tool for ReadyTool {
    type GlobalState = Log;
    type ThreadState = Arc<AtomicUsize>;
    fn subscriptions(_: &()) -> Subscription {
        let mut events = Subscription::none();
        events.syscalls([Sysno::getpgid]);
        events
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        // Deliberately replace the constructor's object: the hook must observe
        // the actual completed Tool state, not a constructor snapshot.
        *guest.thread_state_mut() = Arc::new(AtomicUsize::new(1));
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        *guest.thread_state_mut() = Arc::new(AtomicUsize::new(2));
        Ok(())
    }
    fn on_thread_state_ready(
        &self,
        tid: Tid,
        global: &Log,
        state: &Self::ThreadState,
    ) -> Result<(), reverie::Error> {
        let phase = state.load(Ordering::SeqCst);
        if phase == 99 {
            return Err(reverie::Error::Tool(anyhow::anyhow!(
                "ready callback refused"
            )));
        }
        assert!(phase == 1 || phase == 2);
        global
            .ready
            .lock()
            .unwrap()
            .push((tid.as_raw(), Arc::as_ptr(state) as usize, phase));
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        guest
            .send_rpc(Seen {
                pointer: Arc::as_ptr(guest.thread_state()) as usize,
                phase: guest.thread_state().load(Ordering::SeqCst),
            })
            .await;
        Ok(guest.inject(call).await?)
    }
}

#[test]
fn native_ready_observation_precedes_root_fork_and_clone_files_dispatch() {
    let (output, log) = crate::testing::test_fn::<ReadyTool, _>(|| unsafe {
        assert!(libc::syscall(libc::SYS_getpgid, 0) > 0);
        for shared in [false, true] {
            let child = if shared {
                libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_FILES | libc::SIGCHLD,
                    0usize,
                    0usize,
                    0usize,
                    0usize,
                ) as libc::pid_t
            } else {
                libc::fork()
            };
            assert!(child >= 0);
            if child == 0 {
                let result = libc::syscall(libc::SYS_getpgid, 0);
                libc::_exit(if result > 0 { 0 } else { 31 });
            }
            let mut status = -1;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert_eq!(status, 0);
        }
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    let ready = log.ready.lock().unwrap();
    assert_eq!(ready.len(), 3);
    assert!(ready.iter().all(|row| row.2 == 1));
    let owners: std::collections::BTreeSet<_> = ready.iter().map(|row| row.0).collect();
    assert_eq!(owners.len(), 3);
    assert_eq!(log.dispatched.load(Ordering::SeqCst), 3);
    assert_eq!(log.failures.load(Ordering::SeqCst), 0);
}
#[test]
fn native_ready_observation_uses_post_exec_replacement_object() {
    let (output, log) = crate::testing::test_cmd::<ReadyTool>("/bin/true", &[]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    let ready = log.ready.lock().unwrap();
    assert_eq!(ready.len(), 2);
    assert_eq!((ready[0].2, ready[1].2), (1, 2));
    assert_eq!(ready[0].0, ready[1].0);
    assert_ne!(ready[0].1, ready[1].1);
    assert_eq!(log.failures.load(Ordering::SeqCst), 0);
}
#[test]
fn native_failed_exec_keeps_original_ready_association() {
    let (output, log) = crate::testing::test_fn::<ReadyTool, _>(|| unsafe {
        let path = c"/hermit-ready-control-no-such-executable";
        assert_eq!(
            libc::syscall(
                libc::SYS_execve,
                path.as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>()
            ),
            -1
        );
        assert_eq!(*libc::__errno_location(), libc::ENOENT);
        assert!(libc::syscall(libc::SYS_getpgid, 0) > 0);
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    let ready = log.ready.lock().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].2, 1);
    assert_eq!(log.dispatched.load(Ordering::SeqCst), 1);
    assert_eq!(log.failures.load(Ordering::SeqCst), 0);
}
#[test]
fn ready_callback_failure_returns_eproto_without_dispatch() {
    // Helper-level check only: no native guest or resume is involved. The
    // native tests above cover successful ready-state association and resume
    // ordering; they do not exercise a failing callback's fatal fence.
    let log = Log::default();
    let state = Arc::new(AtomicUsize::new(99));
    assert_eq!(
        observe_ready_thread_state(&ReadyTool, Pid::from_raw(7), Tid::from_raw(8), &log, &state),
        Err(Errno::EPROTO)
    );
    assert_eq!(log.failures.load(Ordering::SeqCst), 1);
    assert!(log.ready.lock().unwrap().is_empty());
    assert_eq!(log.dispatched.load(Ordering::SeqCst), 0);
    assert_eq!(state.load(Ordering::SeqCst), 99);
}
