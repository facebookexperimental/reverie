use std::os::fd::AsFd;
use std::time::Duration;

fn descriptor_identity(fd: i32) -> Option<(u64, u64)> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut stat) } == 0).then_some((stat.st_dev, stat.st_ino))
}

use super::*;

#[test]
fn malformed_lengths_offsets_and_version_are_rejected_before_peer_use() {
    for corrupt in 0..5 {
        // The creator's mapping is destroyed before modifying this fixture.
        let (stream, fd) = unsafe { MappedStream::create(31) }.unwrap();
        drop(stream);
        let setup = Mapping::map(&fd, layout_len(31).unwrap()).unwrap();
        // No endpoint or abort/worker mapping exists during metadata mutation.
        unsafe {
            let header = setup.ptr.as_ptr().cast::<Header>();
            match corrupt {
                0 => (*header).version += 1,
                1 => (*header).offsets[0] += 1,
                2 => (*header).offsets[1] = u64::MAX,
                3 => (*header).mapped_len -= 1,
                _ => (*header).capacity = u64::MAX,
            }
        }
        drop(setup);
        let number = fd.as_raw_fd();
        let identity = descriptor_identity(number);
        let error = unsafe { MappedStream::from_owned_fd(fd) }.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "case {corrupt}");
        assert_ne!(
            descriptor_identity(number),
            identity,
            "failed import retained its descriptor"
        );
    }
}

#[test]
fn setup_descriptor_closes_and_duplicate_peer_is_rejected() {
    // Both descriptors are used only for the imports below, never file writes.
    let (first, fd) = unsafe { MappedStream::create(7) }.unwrap();
    let duplicate = fd.as_fd().try_clone_to_owned().unwrap();
    let number = fd.as_raw_fd();
    let identity = descriptor_identity(number);
    let mut second = unsafe { MappedStream::from_owned_fd(fd) }.unwrap();
    assert_ne!(
        descriptor_identity(number),
        identity,
        "import retained its descriptor"
    );
    assert_eq!(
        unsafe { MappedStream::from_owned_fd(duplicate) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    drop(first);
    assert_eq!(second.read(&mut [0]).unwrap(), 0);
}

#[test]
fn zero_and_overflowing_capacity_are_errors() {
    for size in [0, usize::MAX, isize::MAX as usize] {
        assert_eq!(
            // These invalid capacities return no endpoint or descriptor.
            unsafe { MappedStream::create(size) }.err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn transfer_wraps_and_exceeds_capacity_with_exact_bytes() {
    let (mut first, mut second) = MappedStream::pair(7).unwrap();
    let abort = first.abort_handle();
    let sent: Vec<u8> = (0..65_537).map(|i| (i * 31) as u8).collect();
    let expected = sent.clone();
    let (done, finished) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        first.write_all(&sent).unwrap();
        first.close_write();
        done.send(()).unwrap();
    });
    let reader = std::thread::spawn(move || {
        let mut received = Vec::new();
        second.read_to_end(&mut received).unwrap();
        assert_eq!(received, expected, "mapped transfer changed bytes");
    });
    if finished.recv_timeout(Duration::from_secs(5)).is_err() {
        abort.abort(MappedFailure::Cancelled);
        panic!("large mapped transfer did not complete");
    }
    writer.join().unwrap();
    reader.join().unwrap();
}

#[test]
fn logical_close_drains_bytes_before_eof_and_stops_peer_writes() {
    let (mut first, mut second) = MappedStream::pair(17).unwrap();
    first.write_all(b"last record").unwrap();
    first.close_write();
    let abort = first.abort_handle();
    let (done, finished) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        second.read_to_end(&mut bytes).unwrap();
        assert!(done.send((bytes, second)).is_ok());
    });
    let (bytes, second) = match finished.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(_) => {
            abort.abort(MappedFailure::Cancelled);
            panic!("logical write close did not deliver EOF");
        }
    };
    reader.join().unwrap();
    assert_eq!(
        bytes, b"last record",
        "closed stream changed retained bytes"
    );
    assert_eq!(
        first.write(b"after close").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    drop(second);
    assert_eq!(
        first.write(b"after peer").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn abort_wakes_blocked_read_and_write_and_keeps_first_failure() {
    for writing in [false, true] {
        let (mut first, _second) = MappedStream::pair(1).unwrap();
        if writing {
            first.write_all(b"x").unwrap();
        }
        let abort = first.abort_handle();
        let (ready, started) = std::sync::mpsc::channel();
        let (done, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            ready.send(()).unwrap();
            let error = if writing {
                first.write(b"y").unwrap_err()
            } else {
                first.read(&mut [0]).unwrap_err()
            };
            done.send(error.kind()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            result.recv_timeout(Duration::from_millis(30)).is_err(),
            "operation did not remain blocked"
        );
        abort.abort(MappedFailure::Cancelled);
        abort.abort(MappedFailure::PeerFailed);
        assert_eq!(
            result.recv_timeout(Duration::from_secs(2)).unwrap(),
            io::ErrorKind::ConnectionAborted
        );
        worker.join().unwrap();
    }
}

#[test]
fn impossible_cursors_fail_before_accessing_payload() {
    for (read, written) in [(1, 0), (0, 18), (u64::MAX, 0)] {
        let (mut first, _second) = MappedStream::pair(17).unwrap();
        let queue = &first.mapping.header().queues[0];
        queue.read.store(read, Ordering::Relaxed);
        queue.written.store(written, Ordering::Relaxed);
        assert_eq!(
            first.write(b"a").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            first.mapping.header().failure.load(Ordering::Acquire),
            MappedFailure::Protocol as u32
        );
    }
}

#[test]
fn unsealed_backing_is_rejected_and_closed() {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"invalid-rpc".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    let number = fd.as_raw_fd();
    let identity = descriptor_identity(number);
    assert_eq!(
        unsafe { MappedStream::from_owned_fd(fd) }
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_ne!(
        descriptor_identity(number),
        identity,
        "import retained its descriptor"
    );
}
