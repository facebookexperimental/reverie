use super::*;

thread_local! {
    static PAUSED_VALUE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static PAUSED_RESULT: std::cell::Cell<i64> = const { std::cell::Cell::new(8) };
    static PAUSED_READS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static CHANGE_SEQUENCE: std::cell::Cell<*mut u32> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

unsafe fn paused_read_gate(number: i64, arguments: [u64; 6]) -> i64 {
    assert_eq!(number, libc::SYS_read);
    assert_eq!(arguments[0], 99);
    assert_eq!(arguments[2], 8);
    PAUSED_READS.set(PAUSED_READS.get() + 1);
    if PAUSED_RESULT.get() == 8 {
        unsafe { *(arguments[1] as *mut u64) = PAUSED_VALUE.get() };
    }
    if !CHANGE_SEQUENCE.get().is_null() {
        unsafe { *CHANGE_SEQUENCE.get() = 4 };
    }
    PAUSED_RESULT.get()
}

fn paused_fixture() -> (
    Box<perf::perf_event_mmap_page>,
    std::mem::ManuallyDrop<PerfCounter>,
) {
    PAUSED_VALUE.set(0);
    PAUSED_RESULT.set(8);
    PAUSED_READS.set(0);
    CHANGE_SEQUENCE.set(std::ptr::null_mut());
    let mut page = Box::<perf::perf_event_mmap_page>::default();
    page.lock = 2;
    let counter = std::mem::ManuallyDrop::new(PerfCounter {
        fd: 99,
        mmap: Some(NonNull::from(page.as_mut())),
        records: None,
        raw_syscall: Some(paused_read_gate),
        programmings: std::sync::atomic::AtomicU64::new(0),
        sample_time: false,
        last_sample_time: None,
    });
    (page, counter)
}

#[test]
fn paused_read_preserves_exact_counts_without_retry() {
    let (_page, counter) = paused_fixture();
    for value in [0, 1, 2, (1 << 53) + 1, u64::MAX] {
        PAUSED_VALUE.set(value);
        let previous = PAUSED_READS.get();
        assert_eq!(counter.ctr_value_paused_once(), Ok(value));
        assert_eq!(PAUSED_READS.get(), previous + 1);
    }
}

#[test]
fn paused_read_errors_are_explicit_and_not_retried() {
    let (_page, counter) = paused_fixture();
    for (result, error) in [
        (0, Errno::ENODEV),
        (7, Errno::EIO),
        (9, Errno::EIO),
        (-(libc::EINTR as i64), Errno::EINTR),
        (-(libc::EBADF as i64), Errno::EBADF),
    ] {
        PAUSED_RESULT.set(result);
        let previous = PAUSED_READS.get();
        assert_eq!(counter.ctr_value_paused_once(), Err(error));
        assert_eq!(PAUSED_READS.get(), previous + 1);
    }
}

#[test]
fn paused_read_rejects_active_lost_or_unavailable_state_before_syscall() {
    let (mut page, mut counter) = paused_fixture();
    page.lock = 3;
    assert_eq!(counter.ctr_value_paused_once(), Err(Errno::EAGAIN));
    page.lock = 2;
    page.index = 1;
    assert_eq!(counter.ctr_value_paused_once(), Err(Errno::EBUSY));
    page.index = 0;
    page.time_enabled = 1;
    assert_eq!(counter.ctr_value_paused_once(), Err(Errno::ENODEV));
    page.time_enabled = 0;
    counter.raw_syscall = None;
    assert_eq!(counter.ctr_value_paused_once(), Err(Errno::EOPNOTSUPP));
    counter.raw_syscall = Some(paused_read_gate);
    counter.mmap = None;
    assert_eq!(counter.ctr_value_paused_once(), Err(Errno::EOPNOTSUPP));
    assert_eq!(PAUSED_READS.get(), 0);
}

#[test]
fn paused_read_rejects_changed_metadata_after_one_read() {
    let (mut page, counter) = paused_fixture();
    CHANGE_SEQUENCE.set(&raw mut page.lock);
    assert_eq!(counter.ctr_value_paused_once(), Err(Errno::EAGAIN));
    assert_eq!(PAUSED_READS.get(), 1);
    CHANGE_SEQUENCE.set(std::ptr::null_mut());
}

/// Headers of consecutive records starting at `start`, keyed by position.
fn record_headers(
    start: u64,
    records: &[(u32, u16)],
) -> (
    std::collections::BTreeMap<u64, perf::perf_event_header>,
    u64,
) {
    let mut headers = std::collections::BTreeMap::new();
    let mut position = start;
    for &(type_, size) in records {
        headers.insert(
            position,
            perf::perf_event_header {
                type_,
                misc: 0,
                size,
            },
        );
        position = position.wrapping_add(u64::from(size));
    }
    (headers, position)
}

#[test]
fn only_sample_records_are_counted() {
    // Every record type the timer's buffer can hold, starting past the
    // wrapping point of the positions.
    let start = u64::MAX - 15;
    let (headers, head) = record_headers(
        start,
        &[
            (perf::PERF_RECORD_SAMPLE, 8),
            (perf::PERF_RECORD_THROTTLE, 24),
            (perf::PERF_RECORD_SAMPLE, 8),
            (perf::PERF_RECORD_UNTHROTTLE, 24),
            (perf::PERF_RECORD_LOST, 24),
            (perf::PERF_RECORD_SAMPLE, 8),
        ],
    );
    let read = |position| headers[&position];
    assert_eq!(count_sample_records(start, head, read), 3);
    assert_eq!(count_sample_records(head, head, read), 0);
    // A record the kernel has not finished publishing is not read.
    assert_eq!(count_sample_records(start, head.wrapping_sub(4), read), 2);
}

#[test]
fn malformed_record_ends_the_count() {
    let (headers, head) = record_headers(
        0,
        &[
            (perf::PERF_RECORD_SAMPLE, 8),
            (perf::PERF_RECORD_SAMPLE, 4),
            (perf::PERF_RECORD_SAMPLE, 8),
        ],
    );
    assert_eq!(
        count_sample_records(0, head, |position| headers[&position]),
        1
    );
}

#[test]
fn newest_sample_time_is_that_of_the_last_sample() {
    // Samples with times, among other records, past the wrapping point of
    // the positions.
    let start = u64::MAX - 23;
    let records = [
        (perf::PERF_RECORD_SAMPLE, 16),
        (perf::PERF_RECORD_THROTTLE, 24),
        (perf::PERF_RECORD_SAMPLE, 16),
        (perf::PERF_RECORD_LOST, 24),
    ];
    let (headers, head) = record_headers(start, &records);
    let mut times = std::collections::BTreeMap::new();
    let mut time = 1000;
    for (&position, header) in &headers {
        time += 1;
        times.insert(position.wrapping_add(8), time + u64::from(header.type_));
    }
    let first = start.wrapping_add(8);
    let second = start.wrapping_add(16 + 24 + 8);
    let read = |position| headers[&position];
    let read_time = |position| times[&position];
    assert_eq!(
        scan_sample_records(start, head, read, Some(read_time)),
        SampleScan {
            samples: 2,
            newest_time: Some(times[&second]),
        }
    );
    // A record the kernel has not finished publishing is not read.
    assert_eq!(
        scan_sample_records(start, second.wrapping_sub(4), read, Some(read_time)),
        SampleScan {
            samples: 1,
            newest_time: Some(times[&first]),
        }
    );
    // Without times, none is read.
    assert_eq!(
        scan_sample_records(start, head, read, None::<fn(u64) -> u64>),
        SampleScan {
            samples: 2,
            newest_time: None,
        }
    );
}

#[test]
fn sample_without_room_for_a_time_has_none() {
    let (headers, head) = record_headers(0, &[(perf::PERF_RECORD_SAMPLE, 8)]);
    assert_eq!(
        scan_sample_records(
            0,
            head,
            |position| headers[&position],
            Some(|_| panic!("no time to read"))
        ),
        SampleScan {
            samples: 1,
            newest_time: None,
        }
    );
}
