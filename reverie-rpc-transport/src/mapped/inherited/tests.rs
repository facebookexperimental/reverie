use std::os::unix::fs::FileExt;

use super::*;

fn identity(address: usize) -> Option<u64> {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next().unwrap().split_once('-').unwrap();
            let range =
                usize::from_str_radix(start, 16).unwrap()..usize::from_str_radix(end, 16).unwrap();
            let inode = fields.nth(3).unwrap().parse().unwrap();
            range.contains(&address).then_some(inode)
        })
}
fn present(address: usize, inode: u64) -> bool {
    identity(address) == Some(inode)
}

// Quiescent local pair with no other user. This unit adapter tests ownership
// and error paths; the main-thread fork fixture proves real inherited release.
fn snapshot(stream: &MappedStream) -> Vec<u8> {
    let mut bytes = vec![0; stream.mapping.len];
    std::fs::File::open("/proc/self/mem")
        .unwrap()
        .read_exact_at(&mut bytes, stream.mapping.ptr.as_ptr() as u64)
        .unwrap();
    bytes
}

#[test]
fn injected_unmap_failure_retains_exact_mapping_and_retries_real_unmap() {
    let (stream, peer) = MappedStream::pair(43).unwrap();
    let address = stream.mapping.ptr.as_ptr() as usize;
    let inode = identity(address).unwrap();
    let len = stream.mapping.len;
    let bytes = snapshot(&peer);
    let error = disarm(stream)
        .release(|ptr, size| {
            assert_eq!(ptr as usize, address);
            assert_eq!(size, len);
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })
        .unwrap_err();
    assert!(
        matches!(error.failure(), InheritedMappingReleaseFailure::Unmap(e) if e.raw_os_error() == Some(libc::EPERM))
    );
    assert_eq!(error.pending.mapping().ptr.as_ptr() as usize, address);
    assert_eq!(error.pending.mapping().len, len);
    assert!(
        present(address, inode),
        "failed release lost the owned mapping"
    );
    assert_eq!(
        snapshot(&peer),
        bytes,
        "failed release changed shared bytes"
    );
    let error = error
        .pending
        .release(|_, _| Err(io::Error::from_raw_os_error(libc::EAGAIN)))
        .unwrap_err();
    assert!(
        matches!(error.failure(), InheritedMappingReleaseFailure::Unmap(e) if e.raw_os_error() == Some(libc::EAGAIN))
    );
    assert_eq!(error.pending.mapping().ptr.as_ptr() as usize, address);
    assert!(
        present(address, inode),
        "retry failure lost the owned mapping"
    );
    // This private call exercises the same release implementation without
    // claiming that this libtest thread is a valid actual post-fork caller.
    error.pending.release(unmap).unwrap();
    assert!(
        !present(address, inode),
        "successful retry left the VMA mapped"
    );
    assert_eq!(snapshot(&peer), bytes);
}

#[test]
fn nonexclusive_error_remains_disarmed_and_owned_through_retry() {
    let (stream, peer) = MappedStream::pair(47).unwrap();
    let alias = stream.abort_handle();
    let address = stream.mapping.ptr.as_ptr() as usize;
    let inode = identity(address).unwrap();
    let bytes = snapshot(&peer);
    let error = disarm(stream).release(unmap).unwrap_err();
    assert!(matches!(
        error.failure(),
        InheritedMappingReleaseFailure::Nonexclusive
    ));
    assert!(present(address, inode));
    assert_eq!(snapshot(&peer), bytes);
    let error = error.pending.release(unmap).unwrap_err();
    assert!(matches!(
        error.failure(),
        InheritedMappingReleaseFailure::Nonexclusive
    ));
    assert!(present(address, inode));
    drop(alias);
    error.pending.release(unmap).unwrap();
    assert!(!present(address, inode));
    assert_eq!(snapshot(&peer), bytes);
}

#[test]
fn error_drop_only_releases_local_ownership_and_never_closes_peer() {
    let (stream, peer) = MappedStream::pair(53).unwrap();
    let alias = stream.abort_handle();
    let address = stream.mapping.ptr.as_ptr() as usize;
    let inode = identity(address).unwrap();
    let bytes = snapshot(&peer);
    let error = disarm(stream).release(unmap).unwrap_err();
    drop(error);
    assert!(
        present(address, inode),
        "remaining alias did not retain the mapping"
    );
    assert_eq!(snapshot(&peer), bytes);
    drop(alias);
    assert!(!present(address, inode));
    assert_eq!(snapshot(&peer), bytes);
}

#[test]
fn failed_unmap_error_drop_is_observed_best_effort_not_explicit_success() {
    let (stream, peer) = MappedStream::pair(59).unwrap();
    let address = stream.mapping.ptr.as_ptr() as usize;
    let inode = identity(address).unwrap();
    let bytes = snapshot(&peer);
    let error = disarm(stream)
        .release(|_, _| Err(io::Error::from_raw_os_error(libc::EPERM)))
        .unwrap_err();
    assert!(present(address, inode));
    drop(error);
    // This observation is specific to the restored real syscall; Drop exposes
    // no result and its general contract remains best effort.
    assert!(!present(address, inode));
    assert_eq!(snapshot(&peer), bytes);
}
