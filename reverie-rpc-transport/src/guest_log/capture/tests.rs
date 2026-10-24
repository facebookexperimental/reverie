use std::io::Write;
use std::os::fd::AsRawFd;
use std::sync::Condvar;

use super::*;

// Isolate process/FD observations and native clone controls from other tests.
// This is a transport primitive fixture, not a split CaptureReport or a guest.
fn inert_fixture(name: &str, body: impl FnOnce()) {
    const FIXTURE: &str = "REVERIE_INERT_CAPTURE_NATIVE_FIXTURE";
    if std::env::var(FIXTURE).ok().as_deref() == Some(name) {
        body();
        return;
    }
    let module = module_path!().split_once("::").unwrap().1;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("{module}::{name}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FIXTURE, name)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "native fixture failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
        "the exact native fixture must actually execute: {:?}",
        output.stdout
    );
}

fn inert_resources() -> (usize, usize, usize) {
    (
        std::fs::read_dir("/proc/self/task").unwrap().count(),
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        std::fs::read_to_string("/proc/self/maps")
            .unwrap()
            .lines()
            .filter(|line| line.contains("memfd:reverie-guest-log-v4"))
            .count(),
    )
}

struct InertChild(libc::pid_t);

impl InertChild {
    fn wait(mut self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.0, &mut status, libc::WNOHANG) };
            if result == self.0 {
                self.0 = 0;
                assert!(libc::WIFEXITED(status), "child status: {status}");
                assert_eq!(libc::WEXITSTATUS(status), 0);
                return;
            }
            assert!(
                result == 0 || io::Error::last_os_error().kind() == io::ErrorKind::Interrupted,
                "waitpid: {}",
                io::Error::last_os_error()
            );
            assert!(Instant::now() < deadline, "native child did not terminate");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for InertChild {
    fn drop(&mut self) {
        if self.0 != 0 {
            // Only this fixture's unreaped child, never a supplied/raw foreign PID.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                while libc::waitpid(self.0, std::ptr::null_mut(), 0) < 0
                    && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                {
                }
            }
        }
    }
}

fn inert_child_exit(body: impl FnOnce()) -> ! {
    let status = i32::from(std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_err());
    unsafe { libc::_exit(status) }
}

#[test]
fn inert_plan_has_no_active_resources_and_preserves_one_guest_import() {
    inert_fixture(
        "inert_plan_has_no_active_resources_and_preserves_one_guest_import",
        || {
            let before = inert_resources();
            let plan = unsafe { InertCapturePlan::new(options()) }.unwrap();
            assert_eq!(inert_resources(), (before.0, before.1 + 2, before.2 + 1));
            let (_, buffer, host, guest) = plan.into_local_parts();
            for role in [ordered::Role::Host, ordered::Role::Guest] {
                assert_eq!(
                    buffer.admission(role),
                    ordered::Admission {
                        closed: false,
                        entrants: 0,
                    }
                );
                assert_eq!(buffer.used_bytes(role), 0);
            }
            let duplicate = host.try_clone().unwrap();
            for fd in [host.as_raw_fd(), duplicate.as_raw_fd()] {
                let error = unsafe { ordered::Buffer::receive(fd) }.err().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            }
            drop(duplicate);
            let guest_buffer = unsafe { ordered::Buffer::receive(guest.as_raw_fd()) }.unwrap();
            let error = unsafe { ordered::Buffer::receive(guest.as_raw_fd()) }
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            // Fresh local wrappers can acquire both roles and the collector:
            // none was already acquired by construction.
            let host_buffer = Arc::new(buffer);
            let writer = unsafe { host_buffer.activate(0, i64::from(std::process::id())) }.unwrap();
            let guest_writer =
                unsafe { guest_buffer.activate(1, i64::from(std::process::id())) }.unwrap();
            let mut collector = host_buffer.collector().unwrap();
            assert!(collector.poll().unwrap().is_none());
            drop((writer, guest_writer, collector, host_buffer, guest_buffer));
            drop((host, guest));
            assert_eq!(inert_resources(), before);
        },
    );
}

#[test]
fn inert_plan_invalid_bounds_do_not_leak_descriptors_or_mappings() {
    inert_fixture(
        "inert_plan_invalid_bounds_do_not_leak_descriptors_or_mappings",
        || {
            let before = inert_resources();
            drop(unsafe { InertCapturePlan::new(options()) }.unwrap());
            assert_eq!(inert_resources(), before);
            let mut cases = Vec::new();
            for value in [0, 32 * 1024 * 1024 + 1] {
                let mut invalid = options();
                invalid.limits.diagnostic_bytes = value;
                cases.push(invalid);
            }
            for duration in [Duration::ZERO, Duration::MAX] {
                for field in 0..3 {
                    let mut invalid = options();
                    match field {
                        0 => invalid.timeouts.startup = duration,
                        1 => invalid.timeouts.blocked_publication = duration,
                        _ => invalid.timeouts.final_drain = duration,
                    }
                    cases.push(invalid);
                }
            }
            for slots in [0, usize::MAX, 1024 * 1024] {
                let mut invalid = options();
                invalid.limits.slots_per_producer = slots;
                cases.push(invalid);
            }
            let mut invalid = options();
            invalid.limits.host_pending_bytes = usize::MAX;
            cases.push(invalid);
            let mut invalid = options();
            invalid.limits.producers = 1;
            cases.push(invalid);
            let mut invalid = options();
            invalid.limits.max_record_bytes = 0;
            cases.push(invalid);
            let mut invalid = options();
            invalid.limits.pending_records = 1;
            cases.push(invalid);
            for invalid in cases {
                assert!(
                    unsafe { InertCapturePlan::new(invalid) }.is_err(),
                    "{invalid:?}"
                );
                assert_eq!(inert_resources(), before, "{invalid:?}");
            }
        },
    );
}

#[test]
fn inert_plan_clone_uses_fresh_wrappers_and_keeps_endpoint_aliases_observable() {
    inert_fixture(
        "inert_plan_clone_uses_fresh_wrappers_and_keeps_endpoint_aliases_observable",
        || {
            let mut settings = options();
            settings.limits.slots_per_producer = 8;
            let plan = unsafe { InertCapturePlan::new(settings) }.unwrap();
            let (_, buffer, host, guest) = plan.into_local_parts();
            // There is no Arc, producer, collector, lock or worker before fork.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
            if pid == 0 {
                inert_child_exit(|| {
                    drop((buffer, host));
                    let buffer = unsafe { ordered::Buffer::receive(guest.as_raw_fd()) }.unwrap();
                    let mut writer =
                        unsafe { buffer.activate(1, i64::from(std::process::id())) }.unwrap();
                    assert_eq!(writer.write_record(b"child record", wait).unwrap().order, 1);
                    writer.finish(wait).unwrap();
                    drop((writer, buffer, guest));
                });
            }
            let child = InertChild(pid);
            let alias = guest.try_clone().unwrap();
            drop(guest);
            let buffer = Arc::new(buffer);
            let mut collector = buffer.collector().unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let record = loop {
                if let Some(record) = collector.poll().unwrap() {
                    break record;
                }
                assert!(Instant::now() < deadline, "child record was not published");
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(record.order(), 1);
            assert_eq!(record.bytes(), b"child record");
            record.release().unwrap();
            child.wait();
            // A leftover guest endpoint really prevents EOF; it is not evidence
            // that a producer or child remains alive.
            let mut byte = [0u8; 1];
            assert_eq!(
                unsafe {
                    libc::recv(
                        host.as_raw_fd(),
                        byte.as_mut_ptr().cast(),
                        1,
                        libc::MSG_DONTWAIT,
                    )
                },
                -1
            );
            assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
            drop(alias);
            assert_eq!(
                unsafe {
                    libc::recv(
                        host.as_raw_fd(),
                        byte.as_mut_ptr().cast(),
                        1,
                        libc::MSG_DONTWAIT,
                    )
                },
                0
            );
            assert!(!buffer.order_failed());
        },
    );
}

#[test]
fn inert_plan_parent_drop_does_not_unmap_child_storage() {
    inert_fixture(
        "inert_plan_parent_drop_does_not_unmap_child_storage",
        || {
            use std::io::Read;

            let mut settings = options();
            settings.limits.slots_per_producer = 8;
            let plan = unsafe { InertCapturePlan::new(settings) }.unwrap();
            let (_, buffer, host, guest) = plan.into_local_parts();
            let (mut parent_signal, mut child_signal) = UnixStream::pair().unwrap();
            child_signal
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
            if pid == 0 {
                inert_child_exit(|| {
                    drop((host, parent_signal));
                    let mut ready = [0];
                    child_signal.read_exact(&mut ready).unwrap();
                    assert_eq!(ready, [1]);
                    // Only after the parent's mapping and aliases are gone do we
                    // create this branch's local wrapper and activate its writer.
                    let buffer = Arc::new(buffer);
                    let mut writer =
                        unsafe { buffer.activate(1, i64::from(std::process::id())) }.unwrap();
                    assert_eq!(
                        writer
                            .write_record(b"after parent drop", wait)
                            .unwrap()
                            .order,
                        1
                    );
                    writer.finish(wait).unwrap();
                    assert_eq!(buffer.used_bytes(ordered::Role::Guest), 17);
                    drop((writer, buffer, guest, child_signal));
                });
            }
            let child = InertChild(pid);
            drop((buffer, host, guest, child_signal));
            parent_signal.write_all(&[1]).unwrap();
            child.wait();
        },
    );
}

#[derive(Clone, Default)]
struct Output {
    bytes: Arc<Mutex<Vec<u8>>>,
    progress: DestinationProgress,
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        self.progress.acknowledged_data_bytes += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl CaptureDestination for Output {
    fn progress(&self) -> DestinationProgress {
        self.progress
    }
}

fn options() -> CaptureOptions {
    CaptureOptions {
        limits: CaptureLimits {
            producers: 4,
            slots_per_producer: 1,
            max_record_bytes: 32768,
            host_pending_bytes: 65536,
            guest_pending_bytes: 65536,
            pending_records: 8,
            diagnostic_bytes: 64,
        },
        timeouts: CaptureTimeouts {
            startup: Duration::from_secs(2),
            blocked_publication: Duration::from_secs(2),
            final_drain: Duration::from_millis(30),
        },
    }
}

fn wait(_: &super::super::SharedBuffer, _: u32) -> Result<(), PublishError> {
    std::thread::sleep(Duration::from_millis(1));
    Ok(())
}

fn guest(sink: &mut LogSink) -> (UnixStream, ordered::Writer) {
    let socket = sink.take_prepared_endpoint().unwrap().unwrap();
    let buffer = unsafe { ordered::Buffer::receive(socket.as_raw_fd()) }.unwrap();
    let writer = unsafe { buffer.activate(1, i64::from(std::process::id())) }.unwrap();
    (socket, writer)
}

fn finish(owner: &mut CaptureOwner) -> CaptureReport {
    owner.finish_until(Instant::now() + Duration::from_secs(2))
}

fn until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(Instant::now() < deadline, "capture test gate timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn closed_unfinished_guest_finalization(cancel: bool) {
    let output = Output::default();
    let bytes = output.bytes.clone();
    let mut options = options();
    options.timeouts.final_drain = Duration::from_secs(2);
    let (mut owner, mut sink, host) = unsafe { prepared_capture(options, output) }.unwrap();
    let (socket, writer) = guest(&mut sink);
    let records = [b"init\0".as_slice(), b"daemon\xff", b"drop\n"];
    for record in records {
        host.write_record(record).unwrap();
    }
    drop(writer);
    drop(socket);
    let expected = records.concat();
    let handle = owner.handle();
    until(|| {
        let snapshot = handle.capture_snapshot().unwrap();
        snapshot.guest.peer_closed
            && snapshot.guest.phase == Phase::Incomplete
            && snapshot.publication.progress.acknowledged_data_bytes == expected.len() as u64
    });
    let before = handle.capture_snapshot().unwrap();
    assert!(!before.host.closed);
    assert_eq!(before.guest_admission.entrants, 0);
    assert!(before.guest_admission.closed);
    assert!(!before.streams[1].finished);
    assert_eq!(before.streams[1].complete_records, 0);
    assert_eq!(before.streams[1].unread_frames, 0);
    assert!(before.error.is_none());
    let deadline = Instant::now() + options.timeouts.final_drain;
    if cancel {
        handle.request_guest_stop(GuestStopReason::Cancelled);
    }
    let report = owner.finish_until(deadline);
    assert!(report.error.is_none(), "{report:?}");
    assert!(report.collector_finished && report.commits_observed);
    assert!(report.host.closed && report.guest_admission.closed);
    assert_eq!(report.guest.phase, Phase::Incomplete);
    assert!(!report.qualifies());
    assert!(!report.streams[1].finished);
    assert_eq!(report.streams[1].complete_records, 0);
    assert_eq!(report.streams[1].unread_frames, 0);
    assert!(!report.guest.root_reaped);
    assert_eq!(&*bytes.lock().unwrap(), &expected);
    assert_eq!(
        report.publication.progress.acknowledged_data_bytes,
        expected.len() as u64
    );
    assert_eq!(report.publication.unpublished_bytes, 0);
    assert!(report.publication.error.is_none());
    assert_eq!(report.publication.stability, ArtifactStability::Stable);
    assert!(report.publication.finalized && report.publication.drained);
    assert_eq!(report.guest.issues.len(), usize::from(cancel));
    if cancel {
        assert_eq!(report.guest.issues[0].kind, IssueKind::Cancelled);
    }
}

#[test]
fn closed_unfinished_guest_does_not_wait_for_a_nonexistent_stop_cutoff() {
    closed_unfinished_guest_finalization(false);
}

#[test]
fn closed_unfinished_guest_does_not_race_equal_final_and_stop_deadlines() {
    closed_unfinished_guest_finalization(true);
}

#[test]
fn open_guest_lifetime_keeps_deadline_failure_despite_finish_and_later_closure() {
    let (mut owner, mut sink, host) =
        unsafe { prepared_capture(options(), Output::default()) }.unwrap();
    let (socket, mut writer) = guest(&mut sink);
    writer.finish(wait).unwrap();
    host.write_record(b"cleanup").unwrap();
    let report = finish(&mut owner);
    assert!(report.error.is_some(), "{report:?}");
    assert!(!report.guest.peer_closed);
    assert!(!report.qualifies());
    assert!(!report.guest.root_reaped);
    drop(socket);
    until(|| owner.shared.join_finished());
    let after = finish(&mut owner);
    assert_eq!(after.error, report.error);
    assert_eq!(after.publication.error, report.publication.error);
    assert_eq!(after.guest.phase, Phase::Incomplete);
    assert!(after.streams[1].finished);
    assert_eq!(after.streams[1].complete_records, 0);
    assert!(!after.qualifies());
}

#[test]
fn owner_close_after_burst_delivers_pending_records_before_completing() {
    let output = Output::default();
    let bytes = output.bytes.clone();
    let mut options = options();
    options.limits.slots_per_producer = 16;
    let (mut owner, mut sink, host) = unsafe { prepared_capture(options, output) }.unwrap();
    let (socket, mut writer) = guest(&mut sink);
    owner.handle().root_reaped();
    owner.handle().run_state(RunState::Succeeded);
    {
        let _delayed_collection = owner.shared.state.lock().unwrap();
        for record in [b"first".as_slice(), b"second", b"third", b"fourth"] {
            host.write_record(record).unwrap();
        }
        writer.finish(wait).unwrap();
        drop(socket);
        owner.shared.buffer.close(ordered::Role::Host);
        owner.shared.buffer.close(ordered::Role::Guest);
    }
    let report = finish(&mut owner);
    assert!(report.qualifies(), "{report:?}");
    assert_eq!(&*bytes.lock().unwrap(), b"firstsecondthirdfourth");
    assert_eq!(report.publication.progress.acknowledged_data_bytes, 22);
    assert_eq!(report.publication.unpublished_bytes, 0);
    assert_eq!(owner.shared.buffer.used_bytes(ordered::Role::Host), 0);
}

#[tokio::test]
async fn retained_rpc_failure_disqualifies_an_otherwise_complete_capture() {
    use tokio::io::AsyncWriteExt;

    let output = Output::default();
    let bytes = output.bytes.clone();
    let (mut owner, mut sink, host) = unsafe { prepared_capture(options(), output) }.unwrap();
    let handle = owner.handle();
    let path = format!("/tmp/rli-{}-capture-qualification", std::process::id());
    let mut server = crate::RpcServer::bind(&path, Arc::new(()), ()).unwrap();
    let monitor = server.retain_connection_issues();
    handle.retain_rpc(monitor.clone()).unwrap();
    let duplicate = handle.retain_rpc(monitor.clone()).unwrap_err();
    assert_eq!(duplicate.kind(), io::ErrorKind::Other);
    assert_eq!(duplicate.to_string(), "log RPC monitor already installed");
    let task = tokio::spawn(server.serve());

    let (socket, mut writer) = guest(&mut sink);
    writer.write_record(b"guest record\n", wait).unwrap();
    writer.finish(wait).unwrap();
    drop(writer);
    drop(socket);
    host.write_record(b"host record\n").unwrap();
    handle.root_reaped();
    handle.run_state(RunState::Succeeded);
    let before = finish(&mut owner);
    assert!(before.qualifies(), "{before:?}");
    assert!(before.guest.rpc_issues.is_empty());
    assert_eq!(&*bytes.lock().unwrap(), b"guest record\nhost record\n");

    // Prepared captures intentionally cannot qualify through the legacy view.
    // Exercise Report::qualifies on an actual separate V3 collection instead.
    assert!(!handle.snapshot().qualifies());
    let legacy_options = super::super::Options {
        byte_limit: 4096,
        producers: 1,
        slots: 8,
    };
    let (sink, legacy) = super::super::retained_log(legacy_options);
    legacy.retain_rpc(monitor.clone()).unwrap();
    let (host_socket, guest_socket) =
        unsafe { super::super::channel_pair(legacy_options) }.unwrap();
    let mapping = unsafe { super::super::SharedBuffer::receive(guest_socket.as_raw_fd()) }.unwrap();
    let mut producer = unsafe { mapping.activate(0, i64::from(std::process::id())) }.unwrap();
    let collector = unsafe { sink.reader(host_socket) }.unwrap();
    let collected = std::thread::spawn(move || collector.run());
    producer
        .write_record(&mapping, b"legacy record\n", wait)
        .unwrap();
    producer.finish(&mapping, wait).unwrap();
    drop(guest_socket);
    assert_eq!(collected.join().unwrap().phase, Phase::Complete);
    legacy.run_state(RunState::Succeeded);
    let legacy_before = legacy.snapshot();
    assert!(legacy_before.qualifies(), "{legacy_before:?}");
    assert!(legacy_before.rpc_issues.is_empty());
    assert_eq!(legacy_before.streams[0].bytes, b"legacy record\n");

    let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    crate::codec::read_message(&mut stream, 1024).await.unwrap();
    stream.write_all(&[5, 0]).await.unwrap();
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), monitor.failed())
        .await
        .unwrap();
    monitor.planned_shutdown();
    task.abort();
    let _ = task.await;

    let retained = legacy.snapshot();
    let after = handle.capture_snapshot().unwrap();
    for issues in [&retained.rpc_issues, &after.guest.rpc_issues] {
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].connection, 1);
        let crate::ConnectionFailure::Transport(error) = &issues[0].failure else {
            panic!("{issues:?}");
        };
        assert!(
            matches!(&**error, crate::RpcError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
    assert!(!retained.qualifies());
    assert!(!after.qualifies());
    // Removing only the independently observed RPC issue restores the prior
    // qualifying state; no unrelated incomplete predicate makes this vacuous.
    let mut without_rpc_issue = after.clone();
    without_rpc_issue.guest.rpc_issues.clear();
    assert!(without_rpc_issue.qualifies(), "{after:?}");
    assert_eq!(&*bytes.lock().unwrap(), b"guest record\nhost record\n");
}

struct FailAfterAcknowledgment {
    blocking: Blocking,
    acknowledged: usize,
}

impl Write for FailAfterAcknowledgment {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.blocking.block();
        self.blocking
            .output
            .write(&bytes[..bytes.len().min(self.acknowledged)])?;
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "error after acknowledged prefix",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl CaptureDestination for FailAfterAcknowledgment {
    fn progress(&self) -> DestinationProgress {
        self.blocking.output.progress
    }
}

fn queued_revocation_case(acknowledged: usize) {
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let output = Output::default();
    let bytes = output.bytes.clone();
    let mut settings = options();
    settings.timeouts.blocked_publication = Duration::from_secs(5);
    let (mut owner, mut sink, host) = unsafe {
        prepared_capture(
            settings,
            FailAfterAcknowledgment {
                blocking: Blocking {
                    gate: gate.clone(),
                    output,
                    flush: false,
                },
                acknowledged,
            },
        )
    }
    .unwrap();
    let (socket, mut writer) = guest(&mut sink);
    host.write_record(b"first").unwrap();
    until(|| gate.0.lock().unwrap().0);
    host.write_record(b"queued").unwrap();
    until(|| {
        owner
            .handle()
            .capture_snapshot()
            .unwrap()
            .publication
            .diagnostic_prefix
            == b"firstqueued"
    });
    writer.finish(wait).unwrap();
    drop(socket);
    let handle = owner.handle();
    until(|| handle.capture_snapshot().unwrap().guest.phase == Phase::Complete);
    handle.root_reaped();
    handle.run_state(RunState::Succeeded);
    gate.0.lock().unwrap().1 = true;
    gate.1.notify_all();
    until(|| {
        handle
            .capture_snapshot()
            .unwrap()
            .publication
            .error
            .is_some()
    });
    let report = finish(&mut owner);
    assert_eq!(&*bytes.lock().unwrap(), &b"first"[..acknowledged]);
    assert_eq!(report.publication.stability, ArtifactStability::Stable);
    assert_eq!(
        report.publication.progress.acknowledged_data_bytes,
        acknowledged as u64
    );
    assert_eq!(report.publication.progress.discarded_bytes, 0);
    assert_eq!(report.publication.unpublished_bytes, 6);
    assert_eq!(report.publication.first_unpublished_order, Some(2));
    assert_eq!(report.publication.diagnostic_prefix, b"firstqueued");
    assert_eq!(report.publication.omitted_bytes, 0);
    assert_eq!(
        report.publication.attempt,
        Some(publication::Attempt {
            order: 1,
            acknowledged,
            attempted_end: 5
        })
    );
    assert!(!report.qualifies());
    assert_eq!(owner.shared.buffer.used_bytes(ordered::Role::Host), 0);
    let again = finish(&mut owner);
    assert_eq!(again.publication.unpublished_bytes, 6);
    assert_eq!(again.publication.first_unpublished_order, Some(2));
    assert_eq!(again.publication.progress, report.publication.progress);
}

#[test]
fn queued_records_revoked_after_sink_error_remain_accounted() {
    queued_revocation_case(5);
}

#[test]
fn partial_error_keeps_uncertain_suffix_separate_from_unattempted_queue() {
    queued_revocation_case(2);
}

#[test]
fn queued_and_direct_discard_share_checked_accounting_and_bounded_diagnostics() {
    let mut settings = options();
    settings.limits.slots_per_producer = 16;
    let (socket, _peer) = unsafe { ordered::channel_pair(settings.limits.ordered()) }.unwrap();
    let buffer = unsafe { ordered::Buffer::receive(socket.as_raw_fd()) }.unwrap();
    let mut writer = unsafe { buffer.activate(0, i64::from(std::process::id())) }.unwrap();
    let mut collector = buffer.collector().unwrap();
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let publication = publication::Publication::start(
        Blocking {
            gate: gate.clone(),
            output: Output::default(),
            flush: false,
        },
        8,
        8,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(publication.wait_ready(Instant::now() + Duration::from_secs(2)));
    writer.write_record(b"first", wait).unwrap();
    assert!(
        publication
            .enqueue(collector.poll().unwrap().unwrap())
            .is_ok()
    );
    until(|| gate.0.lock().unwrap().0);
    writer.write_record(b"queued", wait).unwrap();
    assert!(
        publication
            .enqueue(collector.poll().unwrap().unwrap())
            .is_ok()
    );
    writer.write_record(b"later", wait).unwrap();
    publication.discard(collector.poll().unwrap().unwrap());
    let report = publication.finish_until(Instant::now() + Duration::from_millis(30));
    assert_eq!(report.unpublished_bytes, 11);
    assert_eq!(report.first_unpublished_order, Some(2));
    assert_eq!(report.diagnostic_prefix, b"firstque");
    assert_eq!(report.omitted_bytes, 8);
    assert_eq!(report.progress.acknowledged_data_bytes, 0);
    assert_eq!(report.stability, ArtifactStability::MayAppend);
    assert_eq!(buffer.used_bytes(ordered::Role::Host), 11);
    gate.0.lock().unwrap().1 = true;
    gate.1.notify_all();
    until(|| publication.worker_finished());
    let again = publication.finish_until(Instant::now() + Duration::from_secs(2));
    assert_eq!(again.unpublished_bytes, report.unpublished_bytes);
    assert_eq!(
        again.first_unpublished_order,
        report.first_unpublished_order
    );
    assert_eq!(again.progress, report.progress);
    assert_eq!(again.attempt, report.attempt);
    assert_eq!(again.stability, ArtifactStability::MayAppend);
    assert_eq!(buffer.used_bytes(ordered::Role::Host), 0);
}

#[test]
fn empty_record_discard_retains_its_order_without_inventing_bytes() {
    let mut settings = options();
    settings.limits.slots_per_producer = 8;
    let (socket, _peer) = unsafe { ordered::channel_pair(settings.limits.ordered()) }.unwrap();
    let buffer = unsafe { ordered::Buffer::receive(socket.as_raw_fd()) }.unwrap();
    let mut writer = unsafe { buffer.activate(0, i64::from(std::process::id())) }.unwrap();
    let mut collector = buffer.collector().unwrap();
    let publication =
        publication::Publication::start(Output::default(), 8, 8, Duration::from_secs(2)).unwrap();
    writer.write_record(b"", wait).unwrap();
    publication.discard(collector.poll().unwrap().unwrap());
    let report = publication.finish_until(Instant::now() + Duration::from_secs(2));
    assert_eq!(report.unpublished_bytes, 0);
    assert_eq!(report.first_unpublished_order, Some(1));
    assert_eq!(report.progress.acknowledged_data_bytes, 0);
    assert_eq!(buffer.used_bytes(ordered::Role::Host), 0);
}

#[tokio::test]
async fn prepared_before_init_orders_both_domains_and_keeps_cleanup_open() {
    let output = Output::default();
    let bytes = output.bytes.clone();
    let (mut owner, mut sink, host) = unsafe { prepared_capture(options(), output) }.unwrap();
    let handle = owner.handle();
    handle.ready().await.unwrap();
    assert_eq!(host.write_record(b"init\n").unwrap().order, 1);
    let (socket, mut writer) = guest(&mut sink);
    assert_eq!(
        writer
            .write_record(b"guest\nstructured=value\n", wait)
            .unwrap()
            .order,
        2
    );
    writer.finish(wait).unwrap();
    drop(writer);
    drop(socket);
    handle.root_reaped();
    let report = tokio::time::timeout(Duration::from_secs(2), handle.guest_finished())
        .await
        .unwrap();
    assert_eq!(report.phase, Phase::Complete);
    assert!(!handle.capture_snapshot().unwrap().host.closed);
    assert!(!handle.snapshot().qualifies());
    host.write_record(b"cleanup/drop\n").unwrap();
    handle.run_state(RunState::Succeeded);
    let report = finish(&mut owner);
    assert!(report.qualifies(), "{report:?}");
    assert_eq!(
        &*bytes.lock().unwrap(),
        b"init\nguest\nstructured=value\ncleanup/drop\n"
    );
    assert_eq!(host.write_record(b"late"), Err(PublishError::Stopped));
    assert_eq!(handle.capture_snapshot().unwrap().late_host_writes, 1);
    assert!(!handle.capture_snapshot().unwrap().qualifies());
}

#[tokio::test]
async fn unused_sink_cancellation_preserves_host_cleanup_and_failure() {
    let output = Output::default();
    let bytes = output.bytes.clone();
    let (mut owner, sink, host) = unsafe { prepared_capture(options(), output) }.unwrap();
    let handle = owner.handle();
    drop(sink);
    host.write_record(b"cleanup").unwrap();
    let guest = tokio::time::timeout(Duration::from_secs(2), handle.guest_finished())
        .await
        .unwrap();
    assert_eq!(guest.phase, Phase::Incomplete);
    assert!(!guest.issues.is_empty());
    let report = finish(&mut owner);
    assert!(!report.qualifies());
    assert_eq!(report.publication.stability, ArtifactStability::Stable);
    assert_eq!(&*bytes.lock().unwrap(), b"cleanup");
}

#[tokio::test]
async fn cancelled_guest_retains_live_endpoint_fact_and_host_partition() {
    let output = Output::default();
    let (mut owner, mut sink, host) = unsafe { prepared_capture(options(), output) }.unwrap();
    let (socket, mut writer) = guest(&mut sink);
    let handle = owner.handle();
    writer.write_record(b"before", wait).unwrap();
    handle.request_guest_stop(GuestStopReason::Cancelled);
    assert_eq!(
        writer.write_record(b"after", wait),
        Err(PublishError::Stopped)
    );
    host.write_record(b"cleanup").unwrap();
    let guest = handle.guest_finished().await;
    assert!(!guest.peer_closed);
    assert_eq!(guest.phase, Phase::Incomplete);
    let report = finish(&mut owner);
    assert!(!report.qualifies());
    assert_eq!(report.publication.stability, ArtifactStability::Stable);
    drop(socket);
}

#[test]
fn larger_than_ring_recycles_credits_without_cumulative_quota() {
    let output = Output::default();
    let bytes = output.bytes.clone();
    let (mut owner, mut sink, host) = unsafe { prepared_capture(options(), output) }.unwrap();
    let (socket, mut writer) = guest(&mut sink);
    let record = vec![b'x'; 17000];
    for _ in 0..12 {
        host.write_record(&record).unwrap();
        writer.write_record(&record, wait).unwrap();
    }
    writer.finish(wait).unwrap();
    drop(socket);
    owner.handle().root_reaped();
    owner.handle().run_state(RunState::Succeeded);
    let report = finish(&mut owner);
    assert!(report.qualifies(), "{report:?}");
    assert_eq!(bytes.lock().unwrap().len(), record.len() * 24);
    assert_eq!(report.publication.diagnostic_prefix.len(), 64);
    assert_eq!(
        report.publication.omitted_bytes,
        (record.len() * 24 - 64) as u64
    );
    assert_eq!(owner.shared.buffer.used_bytes(ordered::Role::Host), 0);
    assert_eq!(owner.shared.buffer.used_bytes(ordered::Role::Guest), 0);
}

struct Clipped {
    progress: DestinationProgress,
    ceiling: u64,
}
impl Write for Clipped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let kept = (bytes.len() as u64).min(self.ceiling - self.progress.acknowledged_data_bytes);
        self.progress.acknowledged_data_bytes += kept;
        self.progress.discarded_bytes += bytes.len() as u64 - kept;
        self.progress.output_ceiling |= kept < bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl CaptureDestination for Clipped {
    fn progress(&self) -> DestinationProgress {
        self.progress
    }
}

#[test]
fn output_ceiling_does_not_stop_execution_or_exhaust_transport() {
    let (mut owner, mut sink, host) = unsafe {
        prepared_capture(
            options(),
            Clipped {
                progress: DestinationProgress::default(),
                ceiling: 3,
            },
        )
    }
    .unwrap();
    let (socket, mut writer) = guest(&mut sink);
    for _ in 0..40 {
        host.write_record(b"12345").unwrap();
    }
    assert!(!owner.handle().stopped());
    writer.finish(wait).unwrap();
    drop(socket);
    owner.handle().run_state(RunState::Succeeded);
    owner.handle().root_reaped();
    let report = finish(&mut owner);
    assert_eq!(report.publication.progress.acknowledged_data_bytes, 3);
    assert_eq!(report.publication.progress.discarded_bytes, 197);
    assert!(report.publication.error.is_none());
    assert!(!report.qualifies());
}

struct Blocking {
    gate: Arc<(Mutex<(bool, bool)>, Condvar)>,
    output: Output,
    flush: bool,
}
impl Blocking {
    fn block(&self) {
        let mut state = self.gate.0.lock().unwrap();
        state.0 = true;
        self.gate.1.notify_all();
        while !state.1 {
            state = self.gate.1.wait(state).unwrap();
        }
    }
}
impl Write for Blocking {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.flush {
            self.block();
        }
        self.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush {
            self.block();
        }
        Ok(())
    }
}
impl CaptureDestination for Blocking {
    fn progress(&self) -> DestinationProgress {
        self.output.progress
    }
}

fn blocked_finalization(flush: bool) {
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    let output = Output::default();
    let bytes = output.bytes.clone();
    let (mut owner, mut sink, host) = unsafe {
        prepared_capture(
            options(),
            Blocking {
                gate: gate.clone(),
                output,
                flush,
            },
        )
    }
    .unwrap();
    let (socket, mut writer) = guest(&mut sink);
    host.write_record(b"first").unwrap();
    host.write_record(b"queued").unwrap();
    writer.finish(wait).unwrap();
    drop(socket);
    if !flush {
        let state = gate.0.lock().unwrap();
        let (state, timeout) = gate
            .1
            .wait_timeout_while(state, Duration::from_secs(2), |state| !state.0)
            .unwrap();
        assert!(!timeout.timed_out() && state.0);
        drop(state);
        until(|| {
            owner
                .handle()
                .capture_snapshot()
                .unwrap()
                .publication
                .diagnostic_prefix
                == b"firstqueued"
        });
    }
    let start = Instant::now();
    let report = owner.finish_until(start + Duration::from_millis(60));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(report.publication.stability, ArtifactStability::MayAppend);
    assert!(report.publication.error.is_some());
    if !flush {
        assert_eq!(report.publication.attempt.unwrap().acknowledged, 0);
        assert_eq!(report.publication.unpublished_bytes, 6);
        assert_eq!(report.publication.first_unpublished_order, Some(2));
        assert_eq!(report.publication.progress.acknowledged_data_bytes, 0);
    } else {
        assert_eq!(report.publication.unpublished_bytes, 0);
        assert_eq!(report.publication.first_unpublished_order, None);
        assert_eq!(report.publication.progress.acknowledged_data_bytes, 11);
    }
    assert_eq!(report.publication.diagnostic_prefix, b"firstqueued");
    assert_eq!(report.publication.omitted_bytes, 0);
    let repeated = finish(&mut owner);
    assert_eq!(
        repeated.publication.unpublished_bytes,
        report.publication.unpublished_bytes
    );
    assert_eq!(
        repeated.publication.first_unpublished_order,
        report.publication.first_unpublished_order
    );
    let handle = owner.handle();
    handle.request_guest_stop(GuestStopReason::Cancelled);
    assert!(
        handle
            .capture_snapshot()
            .unwrap()
            .publication
            .error
            .is_some()
    );
    {
        gate.0.lock().unwrap().1 = true;
        gate.1.notify_all();
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !owner.shared.publication.worker_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(owner.shared.publication.worker_finished());
    let again = finish(&mut owner);
    assert_eq!(again.publication.stability, ArtifactStability::MayAppend);
    assert_eq!(again.publication.progress, report.publication.progress);
    assert_eq!(
        again.publication.unpublished_bytes,
        report.publication.unpublished_bytes
    );
    assert_eq!(
        again.publication.first_unpublished_order,
        report.publication.first_unpublished_order
    );
    assert_eq!(again.publication.attempt, report.publication.attempt);
    assert_eq!(owner.shared.buffer.used_bytes(ordered::Role::Host), 0);
    if !flush {
        assert_eq!(&*bytes.lock().unwrap(), b"first");
    }
}

#[test]
fn blocked_write_has_bounded_immutable_failure_without_retry() {
    blocked_finalization(false);
}
#[test]
fn blocked_flush_has_bounded_immutable_failure() {
    blocked_finalization(true);
}

#[test]
fn rejects_invalid_options_without_global_subscriber_or_runtime() {
    let mut invalid = options();
    invalid.limits.pending_records = 1;
    assert!(unsafe { prepared_capture(invalid, Output::default()) }.is_err());
    let mut invalid = options();
    invalid.timeouts.startup = Duration::ZERO;
    assert!(unsafe { prepared_capture(invalid, Output::default()) }.is_err());
}

#[test]
fn thread_start_failures_retain_cause_and_close_started_destination() {
    let error = unsafe {
        prepared_capture_with(options(), Output::default(), |_| {
            Err(io::Error::from_raw_os_error(libc::EAGAIN))
        })
    }
    .err()
    .expect("injected collector start failure");
    assert_eq!(error.cause.raw_os_error(), Some(libc::EAGAIN));
    let report = error.handle.unwrap().capture_snapshot().unwrap();
    assert_eq!(report.publication.stability, ArtifactStability::Stable);
    assert_eq!(report.guest.phase, Phase::Incomplete);
    assert!(!report.qualifies());
    let error = publication::Publication::start_with(
        Output::default(),
        8,
        64,
        Duration::from_secs(2),
        |_| Err(io::Error::from_raw_os_error(libc::EAGAIN)),
    )
    .err()
    .expect("injected destination start failure");
    assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
}

#[derive(Clone, Copy)]
enum WriteMode {
    ShortInterrupted,
    MarkerError,
    FlushError,
    FalseProgress,
}
struct Adversarial {
    output: Output,
    mode: WriteMode,
    calls: usize,
}
impl Write for Adversarial {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        match self.mode {
            WriteMode::ShortInterrupted => {
                let count = self.output.write(&bytes[..bytes.len().min(2)])?;
                if self.calls == 1 {
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    Ok(count)
                }
            }
            WriteMode::MarkerError => {
                self.output.write(&bytes[..bytes.len().min(2)])?;
                self.output.progress.marker_bytes = 3;
                self.output.progress.marker_failed = true;
                self.output.progress.output_ceiling = true;
                Err(io::Error::other("marker failed after prefix"))
            }
            WriteMode::FalseProgress => Ok(bytes.len()),
            WriteMode::FlushError => self.output.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if matches!(self.mode, WriteMode::FlushError) {
            Err(io::Error::other("flush failed"))
        } else {
            Ok(())
        }
    }
}
impl CaptureDestination for Adversarial {
    fn progress(&self) -> DestinationProgress {
        self.output.progress
    }
}

fn destination_case(mode: WriteMode) -> (CaptureReport, Vec<u8>) {
    let output = Output::default();
    let bytes = output.bytes.clone();
    let (mut owner, mut sink, host) = unsafe {
        prepared_capture(
            options(),
            Adversarial {
                output,
                mode,
                calls: 0,
            },
        )
    }
    .unwrap();
    let (socket, mut writer) = guest(&mut sink);
    writer.finish(wait).unwrap();
    drop(socket);
    host.write_record(b"abcdef").unwrap();
    owner.handle().root_reaped();
    owner.handle().run_state(RunState::Succeeded);
    let report = finish(&mut owner);
    let bytes = bytes.lock().unwrap().clone();
    (report, bytes)
}

#[test]
fn short_write_and_interrupted_prefix_resume_without_duplication() {
    let (report, bytes) = destination_case(WriteMode::ShortInterrupted);
    assert!(report.qualifies(), "{report:?}");
    assert_eq!(bytes, b"abcdef");
    assert_eq!(report.publication.progress.acknowledged_data_bytes, 6);
}

#[test]
fn marker_failure_keeps_acknowledged_prefix_and_distinct_counters() {
    let (report, bytes) = destination_case(WriteMode::MarkerError);
    assert_eq!(bytes, b"ab");
    assert_eq!(report.publication.progress.acknowledged_data_bytes, 2);
    assert_eq!(report.publication.progress.marker_bytes, 3);
    assert!(report.publication.progress.marker_failed);
    assert!(report.publication.error.is_some());
    assert_eq!(report.publication.attempt.unwrap().acknowledged, 2);
    assert!(!report.qualifies());
}

#[test]
fn flush_failure_preserves_data_without_success_or_retry() {
    let (report, bytes) = destination_case(WriteMode::FlushError);
    assert_eq!(bytes, b"abcdef");
    assert_eq!(report.publication.progress.acknowledged_data_bytes, 6);
    assert_eq!(report.publication.stability, ArtifactStability::Stable);
    assert!(report.publication.error.is_some());
    assert!(!report.qualifies());
}

#[test]
fn unacknowledged_success_is_a_destination_failure() {
    let (report, bytes) = destination_case(WriteMode::FalseProgress);
    assert!(bytes.is_empty());
    assert!(report.publication.error.is_some());
    assert!(!report.qualifies());
}

#[test]
fn oversized_record_is_fatal_transport_failure_not_output_ceiling() {
    let (mut owner, sink, host) =
        unsafe { prepared_capture(options(), Output::default()) }.unwrap();
    assert_eq!(
        host.write_record(&vec![0; 32769]),
        Err(PublishError::Capacity)
    );
    assert!(owner.handle().stopped());
    drop(sink);
    let report = finish(&mut owner);
    assert!(!report.publication.progress.output_ceiling);
    assert!(report.error.is_some());
    assert!(!report.qualifies());
}

#[tokio::test]
async fn legacy_view_finishes_but_cannot_qualify_prepared_capture() {
    let (mut owner, sink, _host) =
        unsafe { prepared_capture(options(), Output::default()) }.unwrap();
    drop(sink);
    finish(&mut owner);
    let handle = owner.handle();
    let legacy = tokio::time::timeout(Duration::from_secs(1), handle.finished())
        .await
        .unwrap();
    assert!(legacy.terminal());
    assert!(!legacy.qualifies());
    assert!(handle.ready().await.is_err());
}

#[test]
fn formatter_failures_are_sticky_without_closing_host_cleanup() {
    for guest_failure in [false, true] {
        let output = Output::default();
        let bytes = output.bytes.clone();
        let (mut owner, mut sink, host) = unsafe { prepared_capture(options(), output) }.unwrap();
        let (socket, mut writer) = guest(&mut sink);
        writer.finish(wait).unwrap();
        if guest_failure {
            owner.shared.buffer.fail_guest();
        } else {
            host.record_failed();
        }
        drop(socket);
        host.write_record(b"cleanup").unwrap();
        owner.handle().run_state(RunState::Succeeded);
        owner.handle().root_reaped();
        let report = finish(&mut owner);
        assert!(!report.qualifies());
        assert!(!report.guest.issues.is_empty());
        assert_eq!(&*bytes.lock().unwrap(), b"cleanup");
    }
}
