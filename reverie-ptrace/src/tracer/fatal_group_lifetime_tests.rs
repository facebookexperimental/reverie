/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
mod fatal_group_lifetime_tests {
    use super::*;
    thread_local! {
        static SESSION: std::cell::RefCell<Option<Arc<FatalSession>>> = const { std::cell::RefCell::new(None) };
        static SUBSCRIPTION: std::cell::RefCell<Option<crate::task::OrdinaryGroupSubscription>> = const { std::cell::RefCell::new(None) };
    }
    #[derive(Default)]
    struct SubscriptionTool;
    #[reverie::tool]
    impl Tool for SubscriptionTool {
        type GlobalState = FatalLog;
        type ThreadState = ();
        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            let session = SESSION.with(|slot| slot.borrow().as_ref().unwrap().clone());
            FATAL_REAP_OBSERVATIONS.with(|slot| {
                let slot = slot.borrow();
                let owner = slot
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|owner| owner.tid == guest.tid())
                    .unwrap();
                assert!(matches!(owner.terminal.observed_exit_status(), Ok(None)));
                assert!(!owner.terminal.wait(Duration::ZERO));
                let subscription = session.subscribe_group(&owner.terminal).unwrap();
                let foreign = Arc::new(FatalSession::default());
                assert!(matches!(
                    foreign.subscribe_group(&owner.terminal),
                    Err(Errno::ESTALE)
                ));
                assert_eq!(
                    foreign.signal_subscribed_group(&subscription),
                    Err(Errno::ESTALE)
                );
                assert!(matches!(owner.terminal.observed_exit_status(), Ok(None)));
                SUBSCRIPTION.with(|slot| *slot.borrow_mut() = Some(subscription));
            });
            guest.send_rpc((guest.tid(), None)).await;
            Ok(())
        }
        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            _: (),
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((tid, Some(status))).await;
            Ok(())
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn completed_subscription_is_noop_but_unknown_capture_is_refused() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let _observations = FatalReapObservationScope::new();
        let tracer = tokio::time::timeout_at(
            deadline.into(),
            spawn_fn_with_config::<SubscriptionTool, _>(|| unsafe { libc::_exit(23) }, 0, true),
        )
        .await
        .unwrap()
        .unwrap();
        let root = tracer.guest_pid();
        let session = tracer.ordinary_session.clone();
        SESSION.with(|slot| *slot.borrow_mut() = Some(session.clone()));
        let outcome =
            tokio::time::timeout_at(deadline.into(), tracer.wait_with_output_completion())
                .await
                .expect("original shared3s deadline");
        let ToolRunOutcome::Complete(done) = outcome else {
            panic!("ordinary success did not complete");
        };
        assert_eq!(done.result.unwrap().status, ExitStatus::Exited(23));
        assert_eq!(
            *done.global_state.0.lock().unwrap(),
            [(root, None), (root, Some(ExitStatus::Exited(23)))]
        );
        assert_reaped("subscription root", root);
        let subscription = SUBSCRIPTION.with(|slot| slot.borrow_mut().take().unwrap());
        assert_eq!(session.signal_subscribed_group(&subscription), Ok(()));
        assert!(
            !session.ordinary_receipt().backend_signalling,
            "completed subscription attempted another signal"
        );
        FATAL_REAP_OBSERVATIONS.with(|slot| {
            let slot = slot.borrow();
            let owners = slot.as_ref().unwrap();
            assert_eq!(owners.len(), 1);
            let owner = &owners[0];
            assert_eq!(
                owner.terminal.observed_exit_status(),
                Ok(Some(ExitStatus::Exited(23)))
            );
            assert!(owner.terminal.wait(Duration::ZERO));
            assert!(owner.held.lock().unwrap().is_none());
            assert!(
                matches!(session.subscribe_group(&owner.terminal), Err(Errno::ESTALE)),
                "missing capture was incorrectly manufactured as completed"
            );
        });
        eprintln!(
            "group subscription: original capture completed, stale subscription noop without signal, fresh missing and foreign capture ESTALE, actual root23/hook/retirement retained"
        );
        SESSION.with(|slot| *slot.borrow_mut() = None);
        assert!(Instant::now() < deadline);
    }
}
