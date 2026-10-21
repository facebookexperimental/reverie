/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[test]
fn completion_wait_wakes_after_publication_in_check_to_park_window() {
    let event = Arc::new(Event::new());
    assert!(event.try_begin_unstarted_completion());
    let (checked, checked_receiver) = mpsc::sync_channel(1);
    let attempted = Arc::new(AtomicI32::new(0));
    let (published, published_receiver) = mpsc::sync_channel(1);
    // Keep the receiver alive until the publisher has joined, including when
    // the wait wakes before the publisher sends its post-return receipt.
    let probe = Arc::new(WorkerDoneWaitProbe {
        checked,
        publisher_attempted: Arc::clone(&attempted),
        published: Mutex::new(published_receiver),
        observation: Mutex::new(None),
    });
    *event.worker_done_wait_probe.lock() = Some(Arc::clone(&probe));
    let publisher_event = Arc::clone(&event);
    let publisher = thread::spawn(move || -> Result<(), &'static str> {
        checked_receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "waiter did not announce its predicate check")?;
        // SAFETY: gettid(2) has no preconditions and cannot fail.
        let tid = unsafe { libc::gettid() };
        // A plain store, unlike a channel send, cannot sleep, so nothing that
        // can block lies between this announcement and the publication path.
        attempted.store(tid, Ordering::Release);
        publisher_event.mark_worker_done();
        // Returning from the real publication path proves that its DONE store
        // and notification have both completed. There is no publication hook
        // or replacement implementation in this test.
        published
            .send(())
            .map_err(|_| "publication receipt receiver disappeared")?;
        Ok(())
    });

    let timeout = Duration::from_secs(2);
    let prompt_limit = timeout / 2;
    let started = Instant::now();
    let acknowledged = event.wait_worker_done(timeout);
    let elapsed = started.elapsed();
    // wait_worker_done has released its mutex on either return path. All test
    // channel waits are bounded and each send has a private one-entry buffer,
    // so cleanup cannot depend on releasing another test barrier.
    let publisher_result = publisher.join();
    let publisher_completed = matches!(&publisher_result, Ok(Ok(())));
    let observation = probe.observation.lock().take();
    let hook_reached = observation.is_some();
    let check_sent = observation.as_ref().is_some_and(|probe| probe.check_sent);
    let publisher_attempted = observation
        .as_ref()
        .is_some_and(|probe| probe.publisher_attempted);
    let publication_before_park = observation
        .as_ref()
        .is_some_and(|probe| probe.published.is_ok());
    let publication_disconnected = observation
        .as_ref()
        .is_some_and(|probe| matches!(probe.published, Err(mpsc::RecvTimeoutError::Disconnected)));
    let publisher_blocked_in_futex = observation
        .as_ref()
        .is_some_and(|probe| probe.publisher_blocked_in_futex);
    let publisher_syscall_unreadable = observation
        .as_ref()
        .is_some_and(|probe| probe.publisher_syscall_unreadable);
    eprintln!(
        "WORKER_DONE_WAKEUP_RECEIPT hook_reached={hook_reached} check_sent={check_sent} \
         publisher_attempted={publisher_attempted} publication_before_park={publication_before_park} \
         publication_disconnected={publication_disconnected} publisher_completed={publisher_completed} \
         wait_returned={acknowledged} wait_elapsed_us={} wait_timeout_us={} prompt_limit_us={} \
         publisher_blocked_in_futex={publisher_blocked_in_futex} \
         publisher_syscall_unreadable={publisher_syscall_unreadable}",
        elapsed.as_micros(),
        timeout.as_micros(),
        prompt_limit.as_micros(),
    );
    assert!(
        hook_reached,
        "completion waiter did not reach its pre-park hook"
    );
    assert!(
        check_sent,
        "completion waiter check receipt was not delivered"
    );
    assert!(
        publisher_attempted,
        "completion publisher did not attempt during the pre-park window"
    );
    assert!(
        !publication_disconnected,
        "publication channel disconnected before park"
    );
    // Every passing run forced one of two orders before the waiter parked:
    // the publication completed, or the publisher slept in futex(2). The old
    // publisher can do the second only after its notification was lost, so it
    // fails the prompt-wake assertion below in both orders.
    assert!(
        publication_before_park || publisher_blocked_in_futex,
        "pre-park window ended with the publisher neither finished nor asleep in futex(2)"
    );
    assert!(
        publisher_completed,
        "completion publisher did not finish: {publisher_result:?}"
    );
    assert!(acknowledged, "completion wait did not acknowledge DONE");
    assert!(
        elapsed < prompt_limit,
        "completion waiter slept through publication until its deadline"
    );
    // Do not require publication_before_park == false here: a future correct
    // implementation could recheck DONE and return promptly even in that order.
    // An unforced run, whose window saw neither publication nor a futex(2)
    // sleep, is rejected by the forced-order assertion above.
}
