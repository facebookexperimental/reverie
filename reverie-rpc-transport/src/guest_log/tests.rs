use super::*;

#[cfg(feature = "test-guest-log")]
#[tokio::test]
async fn fixture_gate_stop_drains_committed_suffix_without_release() {
    let control = Arc::new(unsafe { fixture::Control::new() }.unwrap());
    let release = control.release_on_drop();
    let attached = unsafe { fixture::Control::attach(control.as_raw_fd()) }.unwrap();
    assert!(attached.gated());
    let (host, guest) = unsafe { channel_pair(options(16)) }.unwrap();
    let mapping = unsafe { SharedBuffer::receive(guest.as_raw_fd()) }.unwrap();
    let (sink, handle) = retained_log_with_drain(options(16), Duration::from_millis(20));
    let reader = unsafe { sink.with_fixture_control(control.clone()).reader(host) }.unwrap();
    let collect = std::thread::spawn(move || reader.run());
    handle.ready().await.unwrap();
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    producer.write_record(&mapping, b"prefix\0", wait).unwrap();
    producer
        .write_record(&mapping, b"suffix\xff", wait)
        .unwrap();
    producer.finish(&mapping, wait).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while handle
            .snapshot()
            .streams
            .first()
            .is_none_or(|stream| stream.bytes.is_empty())
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(handle.snapshot().streams[0].bytes, b"prefix\0");
    assert!(control.gated());
    handle.stop(
        IssueKind::Cancelled,
        "gate must not suppress deadline/drain",
    );
    let report = tokio::time::timeout(Duration::from_secs(2), handle.finished())
        .await
        .unwrap();
    assert_eq!(report.streams[0].bytes, b"prefix\0suffix\xff");
    assert!(report.streams[0].finished);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Cutoff)
    );
    assert!(!report.qualifies());
    assert!(control.gated());
    drop(release);
    assert!(!attached.gated());
    drop(guest);
    collect.join().unwrap();
}

fn options(slots: usize) -> Options {
    Options {
        byte_limit: 100_000,
        producers: 4,
        slots,
    }
}

fn wait(mapping: &SharedBuffer, _: u32) -> Result<(), PublishError> {
    if mapping.stopped() {
        return Err(PublishError::Stopped);
    }
    std::thread::sleep(Duration::from_millis(1));
    Ok(())
}

fn setup(slots: usize) -> (UnixStream, SharedBuffer, LogHandle, Collector) {
    let (host, guest) = unsafe { channel_pair(options(slots)) }.unwrap();
    let mapping = unsafe { SharedBuffer::receive(guest.as_raw_fd()) }.unwrap();
    let (sink, handle) = retained_log_with_drain(options(slots), Duration::from_millis(20));
    let reader = unsafe { sink.reader(host) }.unwrap();
    (guest, mapping, handle, reader)
}

#[test]
fn full_retries_every_frame_and_wraps_without_duplicate_bytes() {
    let (guest, mapping, handle, reader) = setup(1);
    let collect = std::thread::spawn(move || reader.run());
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    let bytes: Vec<u8> = (0..20_000).map(|index| (index % 251) as u8).collect();
    producer.write_record(&mapping, &bytes, wait).unwrap();
    producer
        .write_record(&mapping, b"\0\xffsecond", wait)
        .unwrap();
    producer.finish(&mapping, wait).unwrap();
    assert!(!handle.snapshot().terminal());
    drop(guest);
    handle.run_state(RunState::Succeeded);
    let report = collect.join().unwrap();
    assert!(report.qualifies(), "{report:?}");
    assert_eq!(
        report.streams[0].bytes,
        [bytes.as_slice(), b"\0\xffsecond"].concat()
    );
    assert_eq!(report.streams[0].complete_records, 2);
}

#[test]
fn queued_reader_revocation_does_not_need_worker_execution() {
    let (_guest, mapping, handle, reader) = setup(4);
    handle.stop(IssueKind::Cancelled, "before worker body");
    assert!(handle.snapshot().terminal());
    assert!(mapping.stopped());
    assert_eq!(reader.run().phase, Phase::Incomplete);
    assert!(handle.snapshot().streams.is_empty());
}

#[test]
fn startup_drop_finalizes_without_runtime() {
    let (sink, handle) = retained_log(options(1));
    drop(sink);
    assert_eq!(handle.snapshot().phase, Phase::Incomplete);
    assert_eq!(handle.snapshot().issues[0].kind, IssueKind::Interrupted);
}

#[test]
fn partial_record_retained_when_full_wait_fails() {
    let (guest, mapping, _handle, reader) = setup(2);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    assert_eq!(
        producer.write_record(&mapping, b"prefix", |_, _| Err(PublishError::Stopped)),
        Err(PublishError::Stopped)
    );
    drop(guest);
    let report = reader.run();
    assert_eq!(report.phase, Phase::Incomplete);
    assert_eq!(report.streams[0].fragment, b"prefix");
    assert!(report.streams[0].bytes.is_empty());
    assert_eq!(report.streams[0].fragment_sequence, Some(1));
}

#[test]
fn invalid_end_keeps_committed_fragment() {
    let mut decoder = Decoded::default();
    let mut budget = 10;
    let mut frame = buffer::Frame {
        ordinal: 0,
        kind: buffer::BEGIN,
        length: 0,
        sequence: 1,
        offset: 0,
        total: 3,
        payload: [0; PAYLOAD],
    };
    decoder.accept(frame, &mut budget).unwrap();
    frame.kind = buffer::DATA;
    frame.length = 3;
    frame.payload[..3].copy_from_slice(b"abc");
    decoder.accept(frame, &mut budget).unwrap();
    frame.kind = buffer::END;
    frame.length = 0;
    frame.offset = 2;
    assert!(decoder.accept(frame, &mut budget).is_err());
    assert_eq!(decoder.stream.fragment, b"abc");
    assert!(decoder.stream.bytes.is_empty());
}

#[test]
fn finish_then_sticky_failure_is_not_complete() {
    let (guest, mapping, _handle, reader) = setup(4);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    producer.finish(&mapping, wait).unwrap();
    assert!(producer.write_record(&mapping, b"late", wait).is_err());
    drop(guest);
    let report = reader.run();
    assert_eq!(report.phase, Phase::Incomplete);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Producer)
    );
}

#[test]
fn missing_finish_and_unactivated_child_are_incomplete() {
    let (guest, mapping, _handle, reader) = setup(4);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    let child = mapping.reserve_child(0).unwrap();
    mapping.resolve_fork(child, 456).unwrap();
    producer.write_record(&mapping, b"root", wait).unwrap();
    drop(guest);
    let report = reader.run();
    assert_eq!(report.phase, Phase::Incomplete);
    assert_eq!(report.streams[0].bytes, b"root");
}

#[test]
fn parent_child_registration_orders_and_raw_result_before_wait_error() {
    for child_first in [false, true] {
        let (guest, mapping, _handle, reader) = setup(4);
        let collect = std::thread::spawn(move || reader.run());
        let mut parent = unsafe { mapping.activate(0, 123) }.unwrap();
        let child = mapping.reserve_child(0).unwrap();
        if !child_first {
            mapping.resolve_fork(child, 456).unwrap();
        }
        let mut producer = unsafe { mapping.activate(child, 456) }.unwrap();
        if child_first {
            mapping.resolve_fork(child, 456).unwrap();
        }
        let wait_result = -i64::from(libc::ECHILD);
        assert!(wait_result < 0);
        assert_eq!(
            mapping.channel(child).fork_result.load(Ordering::Acquire),
            456
        );
        let failed = mapping.reserve_child(0).unwrap();
        mapping
            .resolve_fork(failed, -i64::from(libc::EAGAIN))
            .unwrap();
        assert!(unsafe { mapping.activate(failed, 789) }.is_err());
        producer.write_record(&mapping, b"child", wait).unwrap();
        producer.finish(&mapping, wait).unwrap();
        parent.write_record(&mapping, b"parent", wait).unwrap();
        parent.finish(&mapping, wait).unwrap();
        drop(guest);
        let report = collect.join().unwrap();
        assert_eq!(report.phase, Phase::Complete, "{report:?}");
        assert_eq!(report.streams[0].bytes, b"parent");
        assert_eq!(report.streams[1].bytes, b"child");
        assert_eq!(report.streams[1].parent, 1);
    }
}

#[test]
fn lifetime_holder_prevents_finish_from_becoming_eof() {
    let (guest, mapping, handle, reader) = setup(4);
    let holder = guest.try_clone().unwrap();
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    producer.finish(&mapping, wait).unwrap();
    drop(guest);
    let collect = std::thread::spawn(move || reader.run());
    while handle.snapshot().phase == Phase::NotStarted {
        std::thread::yield_now();
    }
    handle.stop(IssueKind::Cancelled, "holder still alive");
    let report = collect.join().unwrap();
    assert!(!report.peer_closed);
    assert_eq!(report.phase, Phase::Incomplete);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Cutoff)
    );
    drop(holder);
    assert_eq!(handle.snapshot().phase, Phase::Incomplete);
}

#[test]
fn empty_control_packet_is_not_peer_close() {
    let (guest, _mapping, _handle, reader) = setup(4);
    assert_eq!(
        unsafe { libc::send(guest.as_raw_fd(), std::ptr::null(), 0, libc::MSG_NOSIGNAL) },
        0
    );
    let report = reader.run();
    assert!(!report.peer_closed);
    assert_eq!(report.phase, Phase::Incomplete);
}

#[test]
fn old_protocol_and_capacity_refuse_explicitly() {
    let (host, guest) = UnixStream::pair().unwrap();
    use std::io::Write;
    (&guest).write_all(b"RLG2").unwrap();
    assert!(unsafe { SharedBuffer::receive(host.as_raw_fd()) }.is_err());
    let (guest, mapping, _handle, reader) = setup(4);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    assert_eq!(
        producer.write_record(&mapping, &vec![0; 100_001], wait),
        Err(PublishError::Capacity)
    );
    drop(guest);
    assert!(
        reader
            .run()
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Truncated)
    );
}

#[test]
fn logical_overflow_and_reservation_reuse_refuse() {
    let (_guest, mapping, _handle, _reader) = setup(4);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    for _ in 0..3 {
        let child = mapping.reserve_child(0).unwrap();
        mapping.resolve_fork(child, -1).unwrap();
    }
    assert_eq!(mapping.reserve_child(0), Err(PublishError::Capacity));
    mapping.channel(0).head.store(u64::MAX, Ordering::Release);
    mapping.channel(0).tail.store(u64::MAX, Ordering::Release);
    assert_eq!(producer.finish(&mapping, wait), Err(PublishError::Overflow));
}

#[test]
fn serialized_threads_share_one_producer_without_mixing_records() {
    let (guest, mapping, _handle, reader) = setup(1);
    let collect = std::thread::spawn(move || reader.run());
    let producer = Mutex::new(unsafe { mapping.activate(0, 123) }.unwrap());
    std::thread::scope(|scope| {
        for value in *b"ab" {
            let mapping = &mapping;
            let producer = &producer;
            scope.spawn(move || {
                producer
                    .lock()
                    .unwrap()
                    .write_record(mapping, &vec![value; 5000], wait)
                    .unwrap();
            });
        }
    });
    producer.lock().unwrap().finish(&mapping, wait).unwrap();
    drop(guest);
    let report = collect.join().unwrap();
    assert_eq!(report.phase, Phase::Complete);
    let bytes = &report.streams[0].bytes;
    assert_eq!(bytes.len(), 10_000);
    assert!(bytes[..5000].iter().all(|value| *value == bytes[0]));
    assert!(bytes[5000..].iter().all(|value| *value == bytes[5000]));
    assert_ne!(bytes[0], bytes[5000]);
}

#[test]
fn publication_retry_retains_unwritten_bytes_without_repeating_prefix() {
    let (guest, mapping, handle, reader) = setup(4);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    producer.write_record(&mapping, b"abcdef", wait).unwrap();
    producer.finish(&mapping, wait).unwrap();
    drop(guest);
    assert_eq!(reader.run().phase, Phase::Complete);
    struct Partial(Vec<u8>);
    impl io::Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.0.is_empty() {
                return Err(io::Error::other("destination full"));
            }
            self.0.extend_from_slice(&bytes[..2]);
            Ok(2)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut cursor = handle.cursor(1);
    let mut destination = Partial(Vec::new());
    assert!(cursor.write_to(&mut destination).is_err());
    assert_eq!(cursor.offset(), 2);
    cursor.write_to(&mut destination.0).unwrap();
    assert_eq!(destination.0, b"abcdef");
    assert_eq!(cursor.write_to(&mut destination.0).unwrap(), 0);
    assert_eq!(handle.snapshot().streams[0].bytes, b"abcdef");
    assert!(
        handle
            .snapshot()
            .issues
            .iter()
            .any(|issue| issue.kind == IssueKind::Publication)
    );
    assert!(!handle.snapshot().qualifies());
}

#[test]
fn saturated_blocking_pool_cannot_delay_revocation_or_append_after_final() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let (ready, started) = std::sync::mpsc::channel();
    let blocker = runtime.spawn_blocking(move || {
        ready.send(()).unwrap();
        blocked.recv().unwrap();
    });
    started.recv().unwrap();
    let (_guest, mapping, handle, reader) = setup(4);
    let queued = runtime.spawn_blocking(move || reader.run());
    handle.stop(IssueKind::Cancelled, "blocking pool unavailable");
    let report = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), handle.finished())
            .await
            .unwrap()
    });
    assert_eq!(report.phase, Phase::Incomplete);
    assert!(report.streams.is_empty());
    assert!(mapping.stopped());
    release.send(()).unwrap();
    runtime.block_on(blocker).unwrap();
    let after = runtime.block_on(queued).unwrap();
    assert_eq!(after.phase, Phase::Incomplete);
    assert!(after.streams.is_empty());
}

#[test]
fn dropping_last_external_handle_does_not_cancel_collection() {
    let (guest, mapping, handle, reader) = setup(4);
    drop(handle);
    let mut producer = unsafe { mapping.activate(0, 123) }.unwrap();
    producer.write_record(&mapping, b"retained", wait).unwrap();
    producer.finish(&mapping, wait).unwrap();
    drop(guest);
    let report = reader.run();
    assert_eq!(report.phase, Phase::Complete);
    assert_eq!(report.streams[0].bytes, b"retained");
}
