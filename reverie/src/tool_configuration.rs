/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

use std::marker::PhantomData;
use std::sync::Arc;

use crate::GlobalTool;
use crate::Pid;
use crate::Subscription;
use crate::Tool;
use crate::selection::EffectiveRequirements;
use crate::selection::ToolQueries;

/// Retained launch configuration and the Tool's already selected events.
///
/// Select once at the host's existing launch boundary, then share this owner
/// with process constructors and inherited fork state. This type does not
/// transport selection across exec, own a Tool or thread state, or activate a
/// backend. The host remains responsible for those lifetimes and for calling
/// [`Self::new_process`] only after its preflight succeeds.
pub struct ToolConfiguration<T: Tool> {
    config: Arc<<T::GlobalState as GlobalTool>::Config>,
    subscriptions: Subscription,
    requirements: EffectiveRequirements,
    tool: PhantomData<fn() -> T>,
}

impl<T: Tool> ToolConfiguration<T> {
    /// Select events from this exact shared configuration allocation.
    /// This is the only operation on this type that calls `T::subscriptions`.
    ///
    /// [`Tool::requirements`] is read here too, once, and merged into
    /// [`EffectiveRequirements`] beside the subscriptions. Only
    /// query methods with no once-only contract are collected here
    /// (`requires_signal_control`, `observes_sigreturns`,
    /// `may_observe_signal_dequeues`, `reserved_input_requirement`, and
    /// `in_guest_signal_delivery`, whose consumers must read the value
    /// retained here instead of asking again).
    /// `enforces_serialized_execution` is deliberately not collected: a
    /// real tool's implementation of it calls `subscriptions`, whose
    /// contract is once per tree. `thread_ownership` is likewise left to
    /// the backends that resolve it (including caller overrides) at
    /// their documented points. For those two, the retained
    /// [`ToolQueries`] fields keep their defaults; a host running
    /// admission fills the effective values at its own boundary.
    pub fn select(config: Arc<<T::GlobalState as GlobalTool>::Config>) -> Self {
        let subscriptions = T::subscriptions(&config);
        let requirements = EffectiveRequirements::compute(
            T::requirements(&config),
            subscriptions.clone(),
            ToolQueries {
                requires_signal_control: T::requires_signal_control(&config),
                observes_sigreturns: T::observes_sigreturns(&config),
                may_observe_signal_dequeues: T::may_observe_signal_dequeues(&config),
                in_guest_signal_delivery: T::in_guest_signal_delivery(&config),
                enforces_serialized_execution: false,
                reserved_input: T::reserved_input_requirement(&config).is_some(),
                thread_ownership: crate::ThreadOwnership::Tool,
            },
        );
        Self {
            config,
            subscriptions,
            requirements,
            tool: PhantomData,
        }
    }

    /// The retained configuration, without cloning its value.
    pub fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        &self.config
    }

    /// Share the original allocation, rather than cloning the configuration.
    pub fn shared_config(&self) -> Arc<<T::GlobalState as GlobalTool>::Config> {
        Arc::clone(&self.config)
    }

    /// The full event selection made at construction.
    pub fn subscriptions(&self) -> &Subscription {
        &self.subscriptions
    }

    /// The merged requirements computed at construction: the tool's
    /// stated [`Tool::requirements`], its subscriptions, and its
    /// query-method answers, as admission consumes them.
    pub fn requirements(&self) -> &EffectiveRequirements {
        &self.requirements
    }

    /// Construct the Tool for an actual application process, without selecting
    /// events again or creating its thread state.
    pub fn new_process(&self, actual_pid: Pid) -> T {
        T::new(actual_pid, self.config())
    }
}

impl<T: Tool> Clone for ToolConfiguration<T> {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            subscriptions: self.subscriptions.clone(),
            requirements: self.requirements.clone(),
            tool: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::Tid;
    use crate::syscalls::Sysno;

    static EVENTS: Mutex<Vec<(i32, usize)>> = Mutex::new(Vec::new());
    struct Remote;
    impl Default for Remote {
        fn default() -> Self {
            panic!("configuration must not create a GlobalTool")
        }
    }
    #[crate::global_tool]
    impl GlobalTool for Remote {
        type Config = u64;
        type Request = ();
        type Response = ();
        async fn receive_rpc(&self, _: Pid, _: ()) {
            panic!("no RPC in construction")
        }
    }
    #[derive(Default)]
    struct Probe {
        pid: i32,
    }
    #[crate::tool]
    impl Tool for Probe {
        type GlobalState = Remote;
        type ThreadState = (i32, i32, u64);
        fn subscriptions(config: &u64) -> Subscription {
            assert_eq!(*config, 71);
            EVENTS
                .lock()
                .unwrap()
                .push((-1, config as *const u64 as usize));
            let mut selection = Subscription::none();
            selection.syscall(Sysno::write).cpuid().rdtsc();
            selection
        }
        fn new(pid: Pid, config: &u64) -> Self {
            assert_eq!(*config, 71);
            EVENTS
                .lock()
                .unwrap()
                .push((pid.as_raw(), config as *const u64 as usize));
            Self { pid: pid.as_raw() }
        }
        fn init_thread_state(
            &self,
            tid: Tid,
            parent: Option<(Tid, &Self::ThreadState)>,
        ) -> Self::ThreadState {
            assert_eq!(EVENTS.lock().unwrap().last().unwrap().0, self.pid);
            match parent {
                None => (self.pid, tid.as_raw(), 71),
                Some((parent_tid, snapshot)) => {
                    assert_eq!(parent_tid.as_raw(), snapshot.1);
                    (self.pid, tid.as_raw(), snapshot.2 + 1)
                }
            }
        }
    }

    #[test]
    fn retained_configuration_selects_once_and_constructs_processes_before_threads() {
        EVENTS.lock().unwrap().clear();
        let config = Arc::new(71);
        let owner = ToolConfiguration::<Probe>::select(Arc::clone(&config));
        let inherited = owner.clone(); // Probe deliberately is not Clone.
        assert!(Arc::ptr_eq(&config, &owner.shared_config()));
        assert!(Arc::ptr_eq(&config, &inherited.shared_config()));
        assert!(std::ptr::eq(owner.config(), inherited.config()));
        assert_eq!(
            inherited
                .subscriptions()
                .iter_syscalls()
                .collect::<Vec<_>>(),
            [Sysno::write]
        );
        assert!(inherited.subscriptions().has_cpuid());
        assert!(inherited.subscriptions().has_rdtsc());
        assert_eq!(EVENTS.lock().unwrap().len(), 1);
        let root = owner.new_process(Pid::from_raw(31));
        let parent_state = root.init_thread_state(Pid::from_raw(37), None);
        let child = inherited.new_process(Pid::from_raw(41));
        let child_state =
            child.init_thread_state(Pid::from_raw(43), Some((Pid::from_raw(37), &parent_state)));
        assert_eq!(parent_state, (31, 37, 71));
        assert_eq!(child_state, (41, 43, 72));
        let address = Arc::as_ptr(&config) as usize;
        assert_eq!(
            *EVENTS.lock().unwrap(),
            [(-1, address), (31, address), (41, address)]
        );
    }

    /// Review regression (F4): `select` must evaluate a once-contracted
    /// query at most once — and must not evaluate the two queries whose
    /// contracts belong to their backends at all (one real
    /// `enforces_serialized_execution` implementation re-enters
    /// `subscriptions`, so collecting it here would select twice).
    /// Failed on 640a0add, which called all three.
    #[test]
    fn select_evaluates_once_contracted_queries_at_most_once() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        static SUBS: AtomicUsize = AtomicUsize::new(0);
        static REQS: AtomicUsize = AtomicUsize::new(0);
        static IN_GUEST: AtomicUsize = AtomicUsize::new(0);
        static SERIALIZED: AtomicUsize = AtomicUsize::new(0);
        static OWNERSHIP: AtomicUsize = AtomicUsize::new(0);

        #[derive(Default)]
        struct Counting;
        #[crate::global_tool]
        impl GlobalTool for Counting {
            type Config = ();
            type Request = ();
            type Response = ();
            async fn receive_rpc(&self, _: Pid, _: ()) {}
        }
        #[derive(Default)]
        struct CountingTool;
        #[crate::tool]
        impl Tool for CountingTool {
            type GlobalState = Counting;
            type ThreadState = ();
            fn subscriptions(_: &()) -> Subscription {
                SUBS.fetch_add(1, Ordering::SeqCst);
                Subscription::none()
            }
            fn requirements(_: &()) -> crate::selection::ToolRequirements {
                REQS.fetch_add(1, Ordering::SeqCst);
                crate::selection::ToolRequirements::default()
            }
            fn in_guest_signal_delivery(_: &()) -> bool {
                IN_GUEST.fetch_add(1, Ordering::SeqCst);
                true
            }
            fn enforces_serialized_execution(config: &()) -> bool {
                SERIALIZED.fetch_add(1, Ordering::SeqCst);
                // The downstream shape that makes collecting this here a
                // second selection:
                let _ = Self::subscriptions(config);
                true
            }
            fn thread_ownership(_: &()) -> crate::ThreadOwnership {
                OWNERSHIP.fetch_add(1, Ordering::SeqCst);
                crate::ThreadOwnership::Host
            }
        }

        for counter in [&SUBS, &REQS, &IN_GUEST, &SERIALIZED, &OWNERSHIP] {
            counter.store(0, Ordering::SeqCst);
        }
        let owner = ToolConfiguration::<CountingTool>::select(Arc::new(()));
        assert_eq!(
            SUBS.load(Ordering::SeqCst),
            1,
            "subscriptions once per tree"
        );
        assert_eq!(REQS.load(Ordering::SeqCst), 1, "requirements once per tree");
        assert_eq!(
            IN_GUEST.load(Ordering::SeqCst),
            1,
            "in-guest delivery read once, here; consumers use the retained value"
        );
        assert!(owner.requirements().queries.in_guest_signal_delivery);
        assert_eq!(
            SERIALIZED.load(Ordering::SeqCst),
            0,
            "serialized-execution belongs to its backend (it may re-enter subscriptions)"
        );
        assert_eq!(
            OWNERSHIP.load(Ordering::SeqCst),
            0,
            "thread ownership belongs to the resolving backend (once per tree)"
        );
    }
}
