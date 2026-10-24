use std::os::fd::AsRawFd;
use std::sync::Barrier;

use super::*;

fn limits(slots: usize) -> Limits {
    Limits {
        producers: 4,
        slots,
        max_record_bytes: PAYLOAD * 4,
        host_pending_bytes: PAYLOAD * 8,
        guest_pending_bytes: PAYLOAD * 8,
        pending_records: 8,
    }
}

fn pair(settings: Limits) -> (UnixStream, UnixStream, Arc<Buffer>, Arc<Buffer>) {
    let (host, guest) = unsafe { channel_pair(settings) }.unwrap();
    let host_buffer = unsafe { Buffer::receive(host.as_raw_fd()) }.unwrap();
    let guest_buffer = unsafe { Buffer::receive(guest.as_raw_fd()) }.unwrap();
    (host, guest, host_buffer, guest_buffer)
}

fn no_wait(_: &SharedBuffer, _: u32) -> Result<(), PublishError> {
    panic!("unexpected capacity wait")
}

fn take(collector: &mut Collector) -> (u64, Vec<u8>) {
    let record = collector.poll().unwrap().unwrap();
    let result = (record.order(), record.bytes().to_vec());
    record.release().unwrap();
    result
}

#[test]
fn closing_with_contiguous_pending_records_is_not_an_order_hole() {
    let (_host_socket, _guest_socket, host, guest) = pair(limits(8));
    let mut writer = unsafe { host.activate(0, i64::from(std::process::id())) }.unwrap();
    let mut collector = host.collector().unwrap();
    writer.write_record(b"first", no_wait).unwrap();
    writer.write_record(b"second", no_wait).unwrap();
    host.close(Role::Host);
    guest.close(Role::Guest);
    assert_eq!(take(&mut collector), (1, b"first".to_vec()));
    assert_eq!(collector.commits_observed(), Ok(false));
    assert!(!host.order_failed());
    assert_eq!(host.used_bytes(Role::Host), 6);
    assert_eq!(take(&mut collector), (2, b"second".to_vec()));
    assert_eq!(collector.commits_observed(), Ok(true));
    assert_eq!(host.used_bytes(Role::Host), 0);
}

#[test]
fn limits_and_mixed_wire_versions_refuse() {
    for settings in [
        Limits {
            producers: 1,
            ..limits(2)
        },
        Limits {
            slots: 0,
            ..limits(2)
        },
        Limits {
            pending_records: 1,
            ..limits(2)
        },
        Limits {
            max_record_bytes: 0,
            ..limits(2)
        },
        Limits {
            guest_pending_bytes: 1,
            ..limits(2)
        },
        Limits {
            host_pending_bytes: usize::MAX,
            ..limits(2)
        },
    ] {
        assert!(unsafe { channel_pair(settings) }.is_err());
    }
    let (host, guest) = unsafe { channel_pair(limits(2)) }.unwrap();
    assert!(unsafe { SharedBuffer::receive(host.as_raw_fd()) }.is_err());
    assert!(unsafe { Buffer::receive(guest.as_raw_fd()) }.is_ok());
    let (host, guest) = unsafe {
        super::super::channel_pair(Options {
            byte_limit: 64,
            producers: 1,
            slots: 2,
        })
    }
    .unwrap();
    assert!(unsafe { Buffer::receive(host.as_raw_fd()) }.is_err());
    assert!(unsafe { SharedBuffer::receive(guest.as_raw_fd()) }.is_ok());
}

#[test]
fn source_order_differs_from_collector_scan_order() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(8));
    let mut host_writer = unsafe { host.activate(0, 11) }.unwrap();
    let mut guest_writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut collector = host.collector().unwrap();
    assert!(guest.collector().is_err());
    assert_eq!(
        guest_writer
            .write_record(b"guest before RPC\n", no_wait)
            .unwrap()
            .order,
        1
    );
    assert_eq!(
        host_writer
            .write_record(b"host response\nsecond line\0\xff", no_wait)
            .unwrap()
            .order,
        2
    );
    assert_eq!(take(&mut collector), (1, b"guest before RPC\n".to_vec()));
    assert_eq!(
        take(&mut collector),
        (2, b"host response\nsecond line\0\xff".to_vec())
    );
    assert_eq!(host.used_bytes(Role::Host), 0);
    assert_eq!(guest.used_bytes(Role::Guest), 0);
    assert!(!collector.commits_observed().unwrap());
    host.close(Role::Host);
    guest.close(Role::Guest);
    assert!(collector.commits_observed().unwrap());
}

#[test]
fn larger_than_ring_retries_all_phases_and_recycles_credit() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(1));
    let mut writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut collector = host.collector().unwrap();
    let bytes: Vec<u8> = (0..PAYLOAD * 3 + 7).map(|index| index as u8).collect();
    let mut waits = 0;
    for order in 1..=12 {
        let commit = writer
            .write_record(&bytes, |_, _| {
                waits += 1;
                assert!(collector.poll()?.is_none());
                Ok(())
            })
            .unwrap();
        assert_eq!(commit.order, order);
        assert_eq!(take(&mut collector), (order, bytes.clone()));
        assert_eq!(guest.used_bytes(Role::Guest), 0);
    }
    assert_eq!(waits, 12 * 5);
}

#[test]
fn zero_length_records_consume_bookkeeping_and_host_has_reserved_capacity() {
    let (_host_fd, _guest_fd, host, guest) = pair(Limits {
        pending_records: 4,
        ..limits(16)
    });
    let mut guest_writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut host_writer = unsafe { host.activate(0, 11) }.unwrap();
    let mut collector = host.collector().unwrap();
    guest_writer.write_record(b"", no_wait).unwrap();
    guest_writer.write_record(b"", no_wait).unwrap();
    assert_eq!(
        host_writer.write_record(b"cleanup", no_wait).unwrap().order,
        3
    );
    let mut waits = 0;
    guest_writer
        .write_record(b"", |_, _| {
            waits += 1;
            assert_eq!(take(&mut collector), (1, Vec::new()));
            Ok(())
        })
        .unwrap();
    assert_eq!(waits, 1);
    assert_eq!(take(&mut collector), (2, Vec::new()));
    assert_eq!(take(&mut collector), (3, b"cleanup".to_vec()));
    assert_eq!(take(&mut collector), (4, Vec::new()));
}

#[test]
fn cancellation_before_end_preserves_host_and_unfinished_guest_credit() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(1));
    let mut guest_writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut host_writer = unsafe { host.activate(0, 11) }.unwrap();
    let mut collector = host.collector().unwrap();
    let result = guest_writer.write_record(b"unfinished", |_, _| {
        guest.close(Role::Guest);
        Ok(())
    });
    assert_eq!(result, Err(PublishError::Stopped));
    assert!(!host.order_failed());
    assert_eq!(guest.used_bytes(Role::Guest), 10);
    assert_eq!(header(&host.mapping).next_order.load(Ordering::Acquire), 1);
    host_writer
        .write_record(b"host cleanup", |_, _| {
            assert!(collector.poll()?.is_none());
            Ok(())
        })
        .unwrap();
    assert_eq!(take(&mut collector), (1, b"host cleanup".to_vec()));
    assert_eq!(guest.used_bytes(Role::Guest), 10);
    assert!(collector.partial[1].is_some());
}

#[test]
fn close_is_linearized_with_entry_and_does_not_clear_entrants() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(2));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let thread = {
        let entered = entered.clone();
        let release = release.clone();
        let guest = guest.clone();
        std::thread::spawn(move || {
            let entrant = guest.enter(Role::Guest).unwrap();
            entered.wait();
            release.wait();
            assert_eq!(guest.check(Role::Guest), Err(PublishError::Stopped));
            drop(entrant);
        })
    };
    entered.wait();
    assert_eq!(
        host.close(Role::Guest),
        Admission {
            closed: true,
            entrants: 1
        }
    );
    assert!(guest.enter(Role::Guest).is_err());
    assert_eq!(host.close(Role::Guest).entrants, 1);
    assert!(!host.admission(Role::Host).closed);
    release.wait();
    thread.join().unwrap();
    assert_eq!(host.admission(Role::Guest).entrants, 0);
}

#[test]
fn missing_ticket_never_skips_to_later_host_record() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(8));
    let mut host_writer = unsafe { host.activate(0, 11) }.unwrap();
    let mut collector = host.collector().unwrap();
    let entrant = guest.enter(Role::Guest).unwrap();
    header(&guest.mapping)
        .next_order
        .fetch_add(1, Ordering::AcqRel);
    host_writer
        .write_record(b"after missing END", no_wait)
        .unwrap();
    host.close(Role::Host);
    guest.close(Role::Guest);
    assert!(collector.poll().unwrap().is_none());
    assert!(!collector.commits_observed().unwrap());
    assert_eq!(guest.admission(Role::Guest).entrants, 1);
    drop(entrant);
    assert_eq!(collector.commits_observed(), Err(PublishError::Invalid));
    assert!(host.order_failed());
    assert_eq!(collector.pending[&2].bytes(), b"after missing END");
    assert!(collector.poll().is_err());
}

#[test]
fn credit_is_released_only_by_consumption_not_by_dropping_record() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(8));
    let mut writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut collector = host.collector().unwrap();
    writer.write_record(b"retained", no_wait).unwrap();
    let record = collector.poll().unwrap().unwrap();
    drop(record);
    assert_eq!(guest.used_bytes(Role::Guest), 8);
    guest.close(Role::Guest);
    assert_eq!(guest.used_bytes(Role::Guest), 8);
}

#[test]
fn stale_credit_cannot_release_reused_generation() {
    let (_host_fd, _guest_fd, host, guest) = pair(Limits {
        pending_records: 2,
        ..limits(8)
    });
    let mut writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut collector = host.collector().unwrap();
    writer.write_record(b"old", no_wait).unwrap();
    let record = collector.poll().unwrap().unwrap();
    let stale = Record {
        buffer: record.buffer.clone(),
        ticket: record.ticket,
        order: record.order,
        producer: record.producer,
        bytes: Vec::new(),
    };
    record.release().unwrap();
    writer.write_record(b"new record", no_wait).unwrap();
    assert_eq!(stale.release(), Err(PublishError::Invalid));
    assert_eq!(guest.used_bytes(Role::Guest), 10);
}

#[test]
fn overflow_and_oversized_records_refuse_without_wrap() {
    for ticket_overflow in [false, true] {
        let (_host_fd, _guest_fd, host, guest) = pair(limits(8));
        let mut writer = unsafe { guest.activate(1, 22) }.unwrap();
        if ticket_overflow {
            header(&host.mapping)
                .next_order
                .store(u64::MAX, Ordering::Relaxed);
        } else {
            let channel = host.mapping.channel(1);
            channel.head.store(u64::MAX, Ordering::Relaxed);
            channel.tail.store(u64::MAX, Ordering::Relaxed);
        }
        assert_eq!(
            writer.write_record(b"x", no_wait),
            Err(PublishError::Overflow)
        );
        assert!(host.order_failed());
    }
    let (_host_fd, _guest_fd, _host, guest) = pair(limits(8));
    let mut writer = unsafe { guest.activate(1, 22) }.unwrap();
    assert_eq!(
        writer.write_record(&vec![0; PAYLOAD * 4 + 1], no_wait),
        Err(PublishError::Capacity)
    );
    assert_eq!(guest.used_bytes(Role::Guest), 0);
}

#[test]
fn guest_roles_keep_distinct_fork_incarnations_and_finish_rules() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(8));
    let _host_writer = unsafe { host.activate(0, 11) }.unwrap();
    let mut guest_writer = unsafe { guest.activate(1, 22) }.unwrap();
    assert!(host.reserve_child(0).is_err());
    assert!(unsafe { host.activate(1, 22) }.is_err());
    let cancelled = guest.reserve_child(1).unwrap();
    guest.resolve_fork(cancelled, -1).unwrap();
    let child = guest.reserve_child(1).unwrap();
    assert!(child > cancelled);
    guest.resolve_fork(child, 33).unwrap();
    let mut child_writer = unsafe { guest.activate(child, 33) }.unwrap();
    child_writer.write_record(b"child", no_wait).unwrap();
    child_writer.finish(no_wait).unwrap();
    assert!(child_writer.write_record(b"late", no_wait).is_err());
    assert!(host.order_failed());
    assert!(guest_writer.finish(no_wait).is_err());
}

#[test]
fn duplicate_order_refuses_and_keeps_rejected_frame() {
    let (_host_fd, _guest_fd, host, guest) = pair(limits(16));
    let mut writer = unsafe { guest.activate(1, 22) }.unwrap();
    let mut collector = host.collector().unwrap();
    writer.write_record(b"one", no_wait).unwrap();
    writer.write_record(b"two", no_wait).unwrap();
    let slot = guest.mapping.slot(1, 5);
    unsafe {
        let mut frame = slot.read();
        frame.payload[16..24].copy_from_slice(&1u64.to_le_bytes());
        let credit = guest.credit(number(&frame, 0) as usize).unwrap();
        credit.order.store(1, Ordering::Relaxed);
        slot.write(frame);
    }
    assert!(collector.poll().is_err());
    assert!(collector.rejected[1].is_some());
    assert_eq!(collector.pending[&1].bytes(), b"one");
}
