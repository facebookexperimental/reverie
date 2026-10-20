//! One private no-fork control, co-located under resource_startup's test module.

use super::*;

fn directory_identity(fd: &OwnedFd) -> (u64, u64) {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) }, 0);
    assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFDIR);
    (stat.st_dev, stat.st_ino)
}

fn send_raw_rights(socket: &ResourceSocket, bytes: &[u8], owners: &[&OwnedFd]) {
    socket.inner.poll(libc::POLLOUT).unwrap();
    let mut control = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    let (space, length) = startup_rights_lengths(owners.len()).unwrap();
    message.msg_controllen = startup_abi_len(space).unwrap();
    assert!(
        startup_abi_len::<_, usize>(message.msg_controllen).unwrap()
            <= std::mem::size_of_val(&control)
    );
    // SAFETY: two live owners and a sufficient aligned ancillary buffer.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = startup_abi_len(length).unwrap();
        for (index, fd) in owners.iter().enumerate() {
            libc::CMSG_DATA(header)
                .cast::<i32>()
                .add(index)
                .write(fd.as_raw_fd());
        }
        assert_eq!(
            libc::sendmsg(socket.inner.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
            bytes.len() as isize
        );
    }
    socket.inner.close_write().unwrap();
}

#[test]
fn malformed_delivery_retains_received_capability() {
    // No clone, threads, pidfd stand-in, or public fault injection is involved.
    // The command's controlled cwd supplies a real directory capability.
    let original: OwnedFd = std::fs::File::open(".").unwrap().into();
    let second: OwnedFd = std::fs::File::open(".").unwrap().into();
    let original_identity = directory_identity(&original);
    let second_identity = directory_identity(&second);
    for case in 0..3 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let (sender, receiver) = ResourceSocket::pair::<()>(deadline).unwrap();
        assert!(sender.inner.fd.as_raw_fd() >= 3);
        assert!(receiver.inner.fd.as_raw_fd() >= 3);
        assert_eq!(sender.inner.deadline, deadline);
        assert_eq!(receiver.inner.deadline, deadline);
        let mut bytes = [0u8; STARTUP_FRAME_SIZE];
        bytes[..4].copy_from_slice(b"RVS1");
        bytes[4] = PARENT_DIRECTORY;
        let descriptor_count = if case == 0 { 2 } else { 1 };
        bytes[5] = descriptor_count;
        let (length, expected) = match case {
            0 => (8, PARENT_DIRECTORY), // Rights arrive, then incomplete frame EOF.
            1 => {
                bytes[4] = STARTUP_READY; // Wrong phase, plus unexpected rights.
                (STARTUP_FRAME_SIZE, PARENT_DIRECTORY)
            }
            2 => {
                bytes[4] = LEAF_DIRECTORY;
                bytes[6] = LEAF_NAME_SIZE as u8;
                bytes[8..26].copy_from_slice(b"reverie-dbt-abc/de");
                (STARTUP_FRAME_SIZE, LEAF_DIRECTORY)
            }
            _ => unreachable!(),
        };
        let owners = [&original, &second];
        send_raw_rights(
            &sender,
            &bytes[..length],
            &owners[..descriptor_count as usize],
        );
        let mut frame = receiver.receive(Some(expected));
        assert_eq!(frame.descriptors.len(), descriptor_count as usize);
        // Same one-shot slot operation as ParentResourceStartContext::take_fd:
        // own the claimed capability before asking whether the frame is valid.
        let claimed = frame.descriptors[0].take().unwrap();
        assert!(frame.descriptors[0].take().is_none());
        assert!(claimed.as_raw_fd() >= 3);
        let flags = unsafe { libc::fcntl(claimed.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(directory_identity(&claimed), original_identity);
        assert_eq!(frame.validate(Some(expected)), Err(StartupError::Protocol));
        let unclaimed = frame.take_descriptors();
        assert_eq!(unclaimed.len(), usize::from(case == 0));
        assert!(frame.take_descriptors().is_empty());
        drop(frame); // This cannot close either installed owner.
        assert_eq!(directory_identity(&claimed), original_identity);
        for descriptor in &unclaimed {
            assert_eq!(directory_identity(descriptor), second_identity);
            assert!(descriptor.as_raw_fd() >= 3);
            let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
        let eof = receiver.receive(Some(STARTUP_READY));
        assert_eq!(
            eof.validate(Some(STARTUP_READY)),
            Err(StartupError::PeerClosed)
        );
        assert!(eof.descriptors.is_empty()); // EOF grants no work permission.
        let claimed_raw = claimed.as_raw_fd();
        let unclaimed_raw = unclaimed.first().map(AsRawFd::as_raw_fd);
        close_owner(claimed).unwrap();
        for descriptor in unclaimed {
            close_owner(descriptor).unwrap();
        }
        assert_eq!(unsafe { libc::fcntl(claimed_raw, libc::F_GETFD) }, -1);
        assert_eq!(Errno::last(), Errno::EBADF);
        if let Some(raw) = unclaimed_raw {
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
            assert_eq!(Errno::last(), Errno::EBADF);
        }
        assert_eq!(directory_identity(&original), original_identity);
        assert_eq!(directory_identity(&second), second_identity);
        sender.close().unwrap();
        receiver.close().unwrap();
    }
    close_owner(original).unwrap();
    close_owner(second).unwrap();
}
