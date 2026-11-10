/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Ownership and hook invocation for a Tool hosted in an application process.
//!
//! Admission, synchronization, thread state, and RPC remain with the frontend.
//! Adopting a Tool performs no construction or subscription selection.

use crate::Error;
use crate::ExitStatus;
use crate::GlobalRPC;
use crate::GlobalTool;
use crate::Guest;
use crate::Pid;
use crate::Signal;
use crate::Tid;
use crate::Tool;
use crate::ToolConfiguration;
use crate::syscalls::Errno;
use crate::syscalls::Syscall;

enum Construction<T: Tool> {
    Selected(ToolConfiguration<T>),
    Legacy,
}

/// One already-constructed process Tool and its explicit construction policy.
///
/// A selected owner retains the original configuration allocation and event
/// selection across child construction. A legacy owner is explicitly adopted
/// by a frontend restoring or privately constructing a Tool. An absent Tool
/// never changes either policy or causes construction of a replacement.
pub struct ToolProcess<T: Tool> {
    tool: Option<T>,
    construction: Construction<T>,
}

impl<T: Tool> ToolProcess<T> {
    /// Adopt a Tool constructed after preflight from this selected config.
    pub fn adopt_selected(tool: T, configuration: ToolConfiguration<T>) -> Self {
        Self {
            tool: Some(tool),
            construction: Construction::Selected(configuration),
        }
    }

    /// Adopt an existing private or restored Tool with legacy construction.
    pub fn adopt_legacy(tool: T) -> Self {
        Self {
            tool: Some(tool),
            construction: Construction::Legacy,
        }
    }

    /// Borrow the process Tool, or observe that it was already consumed.
    pub fn as_ref(&self) -> Option<&T> {
        self.tool.as_ref()
    }

    /// The retained selection, absent only for an explicitly legacy owner.
    pub fn selected_configuration(&self) -> Option<&ToolConfiguration<T>> {
        match &self.construction {
            Construction::Selected(configuration) => Some(configuration),
            Construction::Legacy => None,
        }
    }

    /// Consume the Tool once, leaving its explicit construction policy intact.
    /// Callers must handle `None` as an ownership invariant failure.
    pub fn take(&mut self) -> Option<T> {
        self.tool.take()
    }

    fn live(&self) -> &T {
        self.as_ref().expect("process Tool was already consumed")
    }

    /// Construct a child process owner using the actual child's PID.
    ///
    /// Only an explicitly legacy owner reads `legacy_config`. Selected owners
    /// share their retained allocation without selecting subscriptions again.
    /// This does not replace or drop the current Tool, or create thread state;
    /// the frontend preserves its own child publication and drop order.
    pub fn new_process(
        &self,
        actual_pid: Pid,
        legacy_config: &<T::GlobalState as GlobalTool>::Config,
    ) -> Self {
        match &self.construction {
            Construction::Selected(configuration) => {
                Self::adopt_selected(configuration.new_process(actual_pid), configuration.clone())
            }
            Construction::Legacy => Self::adopt_legacy(T::new(actual_pid, legacy_config)),
        }
    }

    /// Initialize state for the actual thread, retaining the parent identity
    /// and snapshot supplied by the frontend's creation boundary.
    pub fn init_thread_state(
        &self,
        actual_tid: Tid,
        parent: Option<(Tid, &T::ThreadState)>,
    ) -> T::ThreadState {
        self.live().init_thread_state(actual_tid, parent)
    }

    /// Invoke the thread-start hook with the frontend's real Guest.
    pub async fn handle_thread_start<G: Guest<T>>(&self, guest: &mut G) -> Result<(), Error> {
        self.live().handle_thread_start(guest).await
    }

    /// Invoke the post-exec hook with the frontend's real Guest.
    pub async fn handle_post_exec<G: Guest<T>>(&self, guest: &mut G) -> Result<(), Errno> {
        self.live().handle_post_exec(guest).await
    }

    /// Invoke one syscall attempt. The shared outcome classifier, rather than
    /// this owner, decides whether its result requires a fresh attempt.
    pub async fn handle_syscall_event<G: Guest<T>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        self.live().handle_syscall_event(guest, syscall).await
    }

    /// Invoke the signal hook with the actual staged signal and Guest.
    pub async fn handle_signal_event<G: Guest<T>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        self.live().handle_signal_event(guest, signal).await
    }

    /// Consume thread state through the Tool's exit hook, using the live RPC
    /// endpoint after the callback's Guest borrow has been dropped.
    pub async fn on_exit_thread<R: GlobalRPC<T::GlobalState>>(
        &self,
        tid: Tid,
        rpc: &R,
        state: T::ThreadState,
        status: ExitStatus,
    ) -> Result<(), Error> {
        self.live().on_exit_thread(tid, rpc, state, status).await
    }

    /// Take the process Tool before returning its consuming exit future.
    ///
    /// Calling this twice is an ownership invariant failure, even if the first
    /// future was dropped or its hook failed. This owner never retries cleanup.
    pub fn on_exit_process<'a, R: GlobalRPC<T::GlobalState> + 'a>(
        &mut self,
        pid: Pid,
        rpc: &'a R,
        status: ExitStatus,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + 'a>>
    where
        T: 'a,
    {
        self.take()
            .expect("process Tool was already consumed")
            .on_exit_process(pid, rpc, status)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use super::*;
    use crate::Subscription;

    static EVENTS: Mutex<Vec<(&str, i32, usize)>> = Mutex::new(Vec::new());

    struct Remote;
    impl Default for Remote {
        fn default() -> Self {
            panic!("process owner must not construct a GlobalTool")
        }
    }
    #[crate::global_tool]
    impl GlobalTool for Remote {
        type Config = u64;
        type Request = i32;
        type Response = i32;
        async fn receive_rpc(&self, _: Pid, _: i32) -> i32 {
            panic!("process owner must not host a GlobalTool")
        }
    }

    #[derive(Default)]
    struct Probe(i32);
    impl Drop for Probe {
        fn drop(&mut self) {
            EVENTS.lock().unwrap().push(("drop", self.0, 0));
        }
    }
    #[crate::tool]
    impl Tool for Probe {
        type GlobalState = Remote;
        type ThreadState = (i32, i32, u64);
        fn subscriptions(config: &u64) -> Subscription {
            EVENTS
                .lock()
                .unwrap()
                .push(("select", 0, config as *const u64 as usize));
            Subscription::none()
        }
        fn new(pid: Pid, config: &u64) -> Self {
            assert_eq!(*config, 71);
            EVENTS
                .lock()
                .unwrap()
                .push(("new", pid.as_raw(), config as *const u64 as usize));
            Self(pid.as_raw())
        }
        fn init_thread_state(
            &self,
            tid: Tid,
            parent: Option<(Tid, &Self::ThreadState)>,
        ) -> Self::ThreadState {
            let generation = parent.map_or(0, |(parent_tid, state)| {
                assert_eq!(parent_tid.as_raw(), state.1);
                state.2 + 1
            });
            EVENTS
                .lock()
                .unwrap()
                .push(("state", tid.as_raw(), generation as usize));
            (self.0, tid.as_raw(), generation)
        }
        async fn on_exit_thread<R: GlobalRPC<Remote>>(
            &self,
            tid: Tid,
            rpc: &R,
            state: Self::ThreadState,
            status: ExitStatus,
        ) -> Result<(), Error> {
            assert_eq!(state.0, self.0);
            assert_eq!(state.1, tid.as_raw());
            assert_eq!(status, ExitStatus::Exited(23));
            EVENTS
                .lock()
                .unwrap()
                .push(("thread-exit", tid.as_raw(), 0));
            assert_eq!(rpc.send_rpc(tid.as_raw()).await, tid.as_raw());
            Ok(())
        }
        async fn on_exit_process<R: GlobalRPC<Remote>>(
            self,
            pid: Pid,
            rpc: &R,
            status: ExitStatus,
        ) -> Result<(), Error> {
            assert_eq!(pid.as_raw(), self.0);
            assert_eq!(status, ExitStatus::Exited(23));
            EVENTS.lock().unwrap().push(("process-exit", self.0, 0));
            assert_eq!(rpc.send_rpc(self.0).await, self.0);
            Ok(())
        }
    }

    struct Endpoint(Arc<u64>);
    #[crate::global_tool]
    impl GlobalRPC<Remote> for Endpoint {
        async fn send_rpc(&self, message: i32) -> i32 {
            EVENTS
                .lock()
                .unwrap()
                .push(("rpc", message, Arc::as_ptr(&self.0) as usize));
            message
        }
        fn config(&self) -> &u64 {
            &self.0
        }
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test hook must complete on this poll"),
        }
    }

    #[test]
    fn selected_and_restored_owners_retain_identity_and_consume_once() {
        EVENTS.lock().unwrap().clear();
        let config = Arc::new(71);
        let address = Arc::as_ptr(&config) as usize;
        let pid = Pid::from_raw(std::process::id() as i32);
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let selection = ToolConfiguration::<Probe>::select(Arc::clone(&config));
        let tool = selection.new_process(pid);
        let mut owner = ToolProcess::adopt_selected(tool, selection);
        assert_eq!(
            *EVENTS.lock().unwrap(),
            [("select", 0, address), ("new", pid.as_raw(), address)]
        );
        assert!(Arc::ptr_eq(
            &config,
            &owner.selected_configuration().unwrap().shared_config()
        ));
        let state = owner.init_thread_state(tid, None);
        assert_eq!(state, (pid.as_raw(), tid.as_raw(), 0));
        let child = owner.new_process(Pid::from_raw(41), &999);
        assert!(Arc::ptr_eq(
            &config,
            &child.selected_configuration().unwrap().shared_config()
        ));
        let child_state = child.init_thread_state(Pid::from_raw(43), Some((tid, &state)));
        assert_eq!(child_state, (41, 43, 1));
        assert_eq!(
            EVENTS
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.0 == "select")
                .count(),
            1
        );
        drop(child);

        let rpc = Endpoint(Arc::clone(&config));
        ready(owner.on_exit_thread(tid, &rpc, state, ExitStatus::Exited(23))).unwrap();
        let exit = owner.on_exit_process(pid, &rpc, ExitStatus::Exited(23));
        assert!(
            owner.as_ref().is_none(),
            "take precedes even the first consuming-hook poll"
        );
        assert!(owner.take().is_none());
        ready(exit).unwrap();
        let events = EVENTS.lock().unwrap();
        assert_eq!(
            &events[events.len() - 5..],
            &[
                ("thread-exit", tid.as_raw(), 0),
                ("rpc", tid.as_raw(), address),
                ("process-exit", pid.as_raw(), 0),
                ("rpc", pid.as_raw(), address),
                ("drop", pid.as_raw(), 0),
            ]
        );
        drop(events);

        EVENTS.lock().unwrap().clear();
        let mut restored = ToolProcess::adopt_legacy(Probe(97));
        assert!(EVENTS.lock().unwrap().is_empty());
        assert!(restored.selected_configuration().is_none());
        let legacy_config = 71;
        let child = restored.new_process(Pid::from_raw(101), &legacy_config);
        assert!(child.selected_configuration().is_none());
        assert_eq!(
            *EVENTS.lock().unwrap(),
            [("new", 101, &legacy_config as *const u64 as usize)]
        );
        let old = restored.take().unwrap();
        assert_eq!(old.0, 97);
        assert!(restored.take().is_none());
        drop(old);
        drop(child);
    }
}
