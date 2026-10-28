/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Sockets (gVisor: pkg/sentry/socket, syscalls/linux/sys_socket.go).

use super::*;

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-213): Review host-backed AF_INET socket creation.
pub(super) fn socket(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let domain = args[0] as libc::c_int;
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-235): Review host-backed AF_INET6 socket creation.
    // TODO-HUMAN-REVIEW(PR-261): Review host-backed AF_NETLINK creation.
    if !matches!(
        domain,
        libc::AF_UNIX | libc::AF_INET | libc::AF_INET6 | libc::AF_NETLINK
    ) {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    let protocol = args[2] as libc::c_int;
    if domain == libc::AF_UNIX && protocol != 0 {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let socket_type = args[1] as libc::c_int;
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    // Detcore's golden handle_socket (hermit detcore/src/syscalls/files.rs:1806)
    // forwards every socket type to the host and lets the kernel validate the
    // (family, type) pair. SOCK_SEQPACKET is a valid AF_UNIX type that takes the
    // exact same socket -> bind(autobind) -> getsockname path as the already
    // supported SOCK_STREAM/SOCK_DGRAM, so accept it here as well. For AF_INET /
    // AF_INET6 the host libc::socket call below rejects SOCK_SEQPACKET with
    // EPROTONOSUPPORT, matching the ptrace backend's forward-to-host result.
    let supported_type = if domain == libc::AF_NETLINK {
        matches!(base_type, libc::SOCK_DGRAM | libc::SOCK_RAW)
    } else {
        matches!(
            base_type,
            libc::SOCK_DGRAM | libc::SOCK_STREAM | libc::SOCK_SEQPACKET
        )
    };
    if !supported_type {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    // SAFETY: domain and type are restricted above; the kernel validates the
    // protocol and returns a new owned descriptor on success.
    let host_fd = unsafe { libc::socket(domain, socket_type | libc::SOCK_CLOEXEC, protocol) };
    if host_fd < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(host_fd) };
    insert_file_with_flags(state, file, socket_type & libc::SOCK_CLOEXEC != 0, None)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(kvm-socket-parity): Review captured-pipe and O_PATH precedence.
pub(super) fn captured_output_socket_error(
    state: &LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
    capture_output: bool,
) -> Option<i64> {
    if !capture_output
        || ![
            libc::SYS_setsockopt as u64,
            libc::SYS_getsockopt as u64,
            libc::SYS_getsockname as u64,
            libc::SYS_getpeername as u64,
        ]
        .contains(&number)
    {
        return None;
    }
    let fd = args[0] as libc::c_int;
    output_alias(state, fd)?;
    // Captured output is a guest pipe even if its inherited host descriptor
    // is a socket. These four calls reject the descriptor before inspecting
    // guest pointers. Do not inspect ambient host fd 1/2 for implicit output.
    // A proc-fd O_PATH reopen retains its alias but must still report EBADF.
    if let Some(file) = state.files.get(&fd) {
        match file_status_flags(file) {
            Ok(flags) if flags & libc::O_PATH != 0 => return Some(negative_errno(libc::EBADF)),
            Err(error) => return Some(error),
            _ => {}
        }
    }
    Some(negative_errno(libc::ENOTSOCK))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(kvm-socket-parity): Review socket error precedence preflight.
fn ensure_host_socket(host_fd: RawFd) -> Result<(), i64> {
    let mut socket_type = 0_i32;
    let mut length = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    // SAFETY: both output pointers name initialized host storage and host_fd is
    // held live by the guest file table for this dispatch.
    if unsafe {
        libc::getsockopt(
            host_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::from_mut(&mut socket_type).cast::<libc::c_void>(),
            &mut length,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io_error(std::io::Error::last_os_error()))
    }
}

// TODO-HUMAN-REVIEW(PR-213): Review bounded guest socket-option translation.
pub(super) fn setsockopt(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_host_socket(host_fd) {
        return error;
    }
    // The syscall ABI consumes a 32-bit socklen_t and ignores higher register
    // bits. A low word above the bounded staging limit is rejected below.
    let length = args[4] as libc::socklen_t;
    let length_usize = length as usize;
    if length_usize > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    let mut value = vec![0; length_usize];
    if length_usize != 0 && memory.user().read(args[3], &mut value).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let value_ptr = if value.is_empty() {
        std::ptr::null()
    } else {
        value.as_ptr().cast::<libc::c_void>()
    };
    // SAFETY: value_ptr is null for an empty option or readable for length
    // bytes; host_fd belongs to the guest descriptor table.
    zero_or_errno(unsafe {
        libc::setsockopt(
            host_fd,
            args[1] as libc::c_int,
            args[2] as libc::c_int,
            value_ptr,
            length,
        )
    })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-230): Review bounded SO_TYPE copy-out semantics.
pub(super) fn getsockopt(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let guest_fd = args[0] as libc::c_int;
    let Some(host_fd) = host_fd(state, guest_fd) else {
        return negative_errno(libc::EBADF);
    };
    if let Err(error) = ensure_host_socket(host_fd) {
        return error;
    }
    if args[4] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok(mut length) = read_guest_struct::<libc::socklen_t>(&ProviderMemory(memory), args[4])
    else {
        return negative_errno(libc::EFAULT);
    };
    let capacity = length as usize;
    if capacity > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    // The host kernel answers every option below, as it does for the ptrace
    // backend. Where its answer is host state (the TCP_INFO counters,
    // SO_COOKIE, SO_NETNS_COOKIE and SO_INCOMING_CPU), a Tool that needs a
    // reproducible value rewrites it after the call, as on every backend.
    // SO_ERROR reads and clears the socket's pending error; a guest polls for
    // a nonblocking connect's completion before asking.
    let level = args[1] as libc::c_int;
    let option = args[2] as libc::c_int;
    let forwarded = match level {
        libc::SOL_SOCKET => matches!(
            option,
            libc::SO_TYPE
                | libc::SO_DOMAIN
                | libc::SO_ACCEPTCONN
                | libc::SO_REUSEADDR
                | libc::SO_KEEPALIVE
                | libc::SO_BROADCAST
                | libc::SO_ERROR
                | libc::SO_COOKIE
                | libc::SO_NETNS_COOKIE
                | libc::SO_INCOMING_CPU
        ),
        libc::IPPROTO_TCP => option == libc::TCP_INFO,
        _ => false,
    };
    if !forwarded {
        return negative_errno(libc::ENOPROTOOPT);
    }
    if capacity != 0 && args[3] == 0 {
        return negative_errno(libc::EFAULT);
    }

    let mut value = vec![0; capacity];
    let value_pointer = if value.is_empty() {
        std::ptr::null_mut()
    } else {
        value.as_mut_ptr().cast::<libc::c_void>()
    };
    // SAFETY: value_pointer is null for a zero-length request or writable for
    // capacity bytes; host_fd belongs to the guest descriptor table.
    if unsafe { libc::getsockopt(host_fd, level, option, value_pointer, &mut length) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let copy_length = capacity.min(length as usize);
    // Linux copies the option bytes and optlen with copy_to_sockptr, which
    // respects guest write permissions and keeps a copied prefix if a later
    // page faults, unlike move_addr_to_user's scalar length store. The order
    // depends on the level: sk_getsockopt copies the value first,
    // https://github.com/torvalds/linux/blob/v6.18/net/core/sock.c#L2159
    // and do_tcp_getsockopt's TCP_INFO publishes optlen first,
    // https://github.com/torvalds/linux/blob/v6.18/net/ipv4/tcp.c#L4494
    let length = length.to_ne_bytes();
    let copies = if level == libc::IPPROTO_TCP {
        [(args[4], &length[..]), (args[3], &value[..copy_length])]
    } else {
        [(args[3], &value[..copy_length]), (args[4], &length[..])]
    };
    for (address, bytes) in copies {
        if memory.user().copy_to_user(address, bytes).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    0
}

// TODO-HUMAN-REVIEW(PR-213): Review bounded host-backed AF_INET bind translation.
// TODO-HUMAN-REVIEW(PR-217): Review filesystem-backed AF_UNIX bind translation.
pub(super) fn bind(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(length) = libc::socklen_t::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length_usize = length as usize;
    if length_usize < std::mem::size_of::<libc::sa_family_t>()
        || length_usize > std::mem::size_of::<libc::sockaddr_storage>()
    {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; length_usize];
    if memory.user().read(args[1], &mut address).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let family = libc::sa_family_t::from_ne_bytes(
        address[..std::mem::size_of::<libc::sa_family_t>()]
            .try_into()
            .expect("family slice has exact size"),
    );
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-261): Review deterministic AF_NETLINK bind forwarding.
    // TODO-HUMAN-REVIEW(PR-349): Review host-backed AF_INET6 bind translation.
    // AF_INET6 is forwarded to the host exactly like AF_INET; Detcore's golden
    // handle_bind determinizes the port for both families
    // (hermit detcore/src/syscalls/files.rs:2175) before the syscall reaches
    // this executor, so the guest-visible port is already deterministic.
    if !matches!(
        family as libc::c_int,
        libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX | libc::AF_NETLINK
    ) {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    // SAFETY: address is readable for length bytes and host_fd belongs to the
    // guest descriptor table. Detcore has already determinized port zero.
    zero_or_errno(unsafe { libc::bind(host_fd, address.as_ptr().cast::<libc::sockaddr>(), length) })
}

// TODO-HUMAN-REVIEW(PR-213): Review host-backed listen translation.
pub(super) fn listen(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    // SAFETY: host_fd belongs to the guest descriptor table; listen validates
    // whether it is a stream socket.
    zero_or_errno(unsafe { libc::listen(host_fd, args[1] as libc::c_int) })
}

// TODO-HUMAN-REVIEW(PR-213): Review bounded getsockname copyback semantics.
pub(super) fn getsockname(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    socket_name(
        &mut ProviderMemory(memory),
        state,
        args,
        SocketNameOperation::Local,
    )
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(kvm-socket-parity): Review peer-name error and copyout ordering.
pub(super) fn getpeername(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    socket_name(
        &mut ProviderMemory(memory),
        state,
        args,
        SocketNameOperation::Peer,
    )
}

#[derive(Clone, Copy)]
pub(super) enum SocketNameOperation {
    Local,
    Peer,
}

fn socket_name<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &mut M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    operation: SocketNameOperation,
) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };

    // Query into fixed host storage before touching guest pointers. Linux gives
    // EBADF, ENOTSOCK, and (for getpeername) ENOTCONN precedence over guest
    // copy faults. A sockaddr_storage covers every admitted socket family.
    // SAFETY: zero is a valid initialization for scratch sockaddr storage.
    let mut address =
        unsafe { std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
    let mut returned_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: both pointers name initialized host storage and host_fd belongs to
    // the guest descriptor table. The selected syscall does not retain them.
    let result = unsafe {
        match operation {
            SocketNameOperation::Local => libc::getsockname(
                host_fd,
                std::ptr::from_mut(&mut address).cast::<libc::sockaddr>(),
                &mut returned_length,
            ),
            SocketNameOperation::Peer => libc::getpeername(
                host_fd,
                std::ptr::from_mut(&mut address).cast::<libc::sockaddr>(),
                &mut returned_length,
            ),
        }
    };
    if result != 0 {
        return io_error(std::io::Error::last_os_error());
    }

    if args[2] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let Ok(capacity) = read_guest_struct::<libc::socklen_t>(memory, args[2]) else {
        return negative_errno(libc::EFAULT);
    };
    // Linux stores socklen_t in a signed kernel int and rejects high-bit input.
    if capacity > libc::c_int::MAX as libc::socklen_t {
        return negative_errno(libc::EINVAL);
    }
    let copy_length = (capacity as usize)
        .min(returned_length as usize)
        .min(std::mem::size_of::<libc::sockaddr_storage>());

    // Linux >= 6.18 publishes the full returned length before copying the
    // bounded address; addr/addrlen overlap and address faults expose the order.
    // move_addr_to_user changed this in the following upstream commit; older
    // kernels copied the address first:
    // https://github.com/torvalds/linux/commit/1fb0e471611dc6a79dee609a7e0037eb1d124400
    // The length is a scalar put_user, followed by a possibly partial
    // copy_to_user. Neither may write through a guest read-only page.
    if memory
        .put_user_i32(args[2], returned_length as i32)
        .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    if copy_length != 0 && args[1] == 0 {
        return negative_errno(libc::EFAULT);
    }
    if copy_length != 0
        && memory
            .copy_to_user(
                args[1],
                // SAFETY: address is initialized and copy_length is bounded by
                // sockaddr_storage above.
                unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::from_ref(&address).cast::<u8>(),
                        copy_length,
                    )
                },
            )
            .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    0
}

// TODO-HUMAN-REVIEW(PR-218): Review blocking accept outside the shared descriptor-table lock.
pub(super) fn accept_socket(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    flags: libc::c_int,
) -> Result<std::fs::File, i64> {
    let allowed_flags = libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    if flags & !allowed_flags != 0 {
        return Err(negative_errno(libc::EINVAL));
    }
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return Err(negative_errno(libc::EBADF));
    };

    // SAFETY: a zeroed sockaddr_storage is valid scratch space for accept4.
    let mut address =
        unsafe { std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let guest_capacity = if args[1] == 0 {
        0
    } else {
        if args[2] == 0 {
            return Err(negative_errno(libc::EFAULT));
        }
        let capacity = read_guest_struct::<libc::socklen_t>(&ProviderMemory(memory), args[2])
            .map_err(|_| negative_errno(libc::EFAULT))?;
        length = length.min(capacity);
        capacity as usize
    };
    let address_pointer = if args[1] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut address).cast::<libc::sockaddr>()
    };
    let length_pointer = if args[1] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut length)
    };

    // SAFETY: host_fd belongs to the guest descriptor table. The optional
    // address and length pointers refer to initialized host storage.
    let accepted_fd = unsafe {
        libc::accept4(
            host_fd,
            address_pointer,
            length_pointer,
            flags | libc::SOCK_CLOEXEC,
        )
    };
    if accepted_fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: accept4 returned a new owned descriptor.
    let accepted = unsafe { std::fs::File::from_raw_fd(accepted_fd) };

    if args[1] != 0 {
        let copy_length = guest_capacity
            .min(length as usize)
            .min(std::mem::size_of::<libc::sockaddr_storage>());
        if copy_length != 0 {
            // SAFETY: address is initialized storage and copy_length is bounded
            // by its size.
            let bytes = unsafe {
                std::slice::from_raw_parts(std::ptr::from_ref(&address).cast::<u8>(), copy_length)
            };
            if memory.user().write(args[1], bytes).is_err() {
                return Err(negative_errno(libc::EFAULT));
            }
        }
        let result = write_struct(&mut ProviderMemory(memory), args[2], &length);
        if result < 0 {
            return Err(result);
        }
    }
    Ok(accepted)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-205): Review AF_UNIX socketpair descriptor ownership.
pub(super) fn socketpair(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let domain = args[0] as libc::c_int;
    let socket_type = args[1] as libc::c_int;
    let protocol = args[2] as libc::c_int;
    if domain != libc::AF_UNIX {
        return negative_errno(libc::EAFNOSUPPORT);
    }
    if protocol != 0 {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    if !matches!(base_type, libc::SOCK_DGRAM | libc::SOCK_STREAM) {
        return negative_errno(libc::EPROTONOSUPPORT);
    }
    let mut host_fds = [-1; 2];
    // SAFETY: host_fds has room for both descriptors and the socket arguments
    // were validated above.
    if unsafe {
        libc::socketpair(
            domain,
            socket_type | libc::SOCK_CLOEXEC,
            protocol,
            host_fds.as_mut_ptr(),
        )
    } != 0
    {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: socketpair initialized both owned descriptors on success.
    let first = unsafe { std::fs::File::from_raw_fd(host_fds[0]) };
    // SAFETY: socketpair initialized both owned descriptors on success.
    let second = unsafe { std::fs::File::from_raw_fd(host_fds[1]) };
    insert_file_pair(
        memory,
        state,
        args[3],
        [first, second],
        socket_type & libc::SOCK_CLOEXEC != 0,
        None,
    )
}

// TODO-HUMAN-REVIEW(PR-92): Review this KVM compatibility implementation.
// TODO-HUMAN-REVIEW(PR-217): Review filesystem-backed AF_UNIX connect translation.
// TODO-HUMAN-REVIEW(PR-349): Review host-backed AF_INET/AF_INET6 connect translation.
pub(super) fn connect(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(length) = libc::socklen_t::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length_usize = length as usize;
    if length_usize < std::mem::size_of::<libc::sa_family_t>()
        || length_usize > std::mem::size_of::<libc::sockaddr_storage>()
    {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; length_usize];
    if memory.user().read(args[1], &mut address).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let family = libc::sa_family_t::from_ne_bytes(
        address[..std::mem::size_of::<libc::sa_family_t>()]
            .try_into()
            .expect("family slice has exact size"),
    );
    match family as libc::c_int {
        libc::AF_UNIX => {
            // AF_UNIX addresses never exceed sockaddr_un; reject a longer buffer
            // exactly as the kernel would before touching the path.
            if length_usize > std::mem::size_of::<libc::sockaddr_un>() {
                return negative_errno(libc::EINVAL);
            }
            let path = &address[std::mem::size_of::<libc::sa_family_t>()..];
            let path = path.split(|byte| *byte == 0).next().unwrap_or(path);
            if path == b"/dev/log" {
                return 0;
            }
        }
        // AF_INET / AF_INET6 connect is forwarded to the host exactly like the
        // already-supported bind/listen/getsockname INET paths. Detcore's golden
        // handle_connect (hermit detcore/src/syscalls/io.rs:1138) performs no
        // address rewriting for connect: it executes the call against the kernel
        // and only records a best-effort loopback-peer scheduling hint. The
        // deterministic endpoint identity for a port-zero bind was already
        // established by handle_bind's RequestPort rewrite
        // (detcore/src/syscalls/files.rs:2158) before the peer's connect reaches
        // this executor, so forwarding here introduces no new nondeterministic
        // surface and matches the ptrace backend's forward-to-host errno.
        libc::AF_INET | libc::AF_INET6 => {}
        _ => return negative_errno(libc::EAFNOSUPPORT),
    }
    // SAFETY: address is readable for length bytes and host_fd belongs to the
    // guest descriptor table. The host kernel validates the sockaddr for its
    // family.
    zero_or_errno(unsafe {
        libc::connect(host_fd, address.as_ptr().cast::<libc::sockaddr>(), length)
    })
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-205): Review host-backed AF_UNIX shutdown semantics.
pub(super) fn shutdown(state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let how = args[1] as libc::c_int;
    if !matches!(how, libc::SHUT_RD | libc::SHUT_WR | libc::SHUT_RDWR) {
        return negative_errno(libc::EINVAL);
    }
    // SAFETY: host_fd is a live guest-owned descriptor; shutdown validates
    // whether it refers to a socket.
    zero_or_errno(unsafe { libc::shutdown(host_fd, how) })
}

// TODO-HUMAN-REVIEW(PR-218): Review bounded guest sendto translation and SIGPIPE suppression.
pub(super) fn sendto(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Ok(fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(flags) = libc::c_int::try_from(args[3]) else {
        return negative_errno(libc::EINVAL);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    let length = requested_length.min(MAX_HOST_IO);
    let mut bytes = vec![0; length];
    if length != 0 && memory.user().read(args[1], &mut bytes).is_err() {
        return negative_errno(libc::EFAULT);
    }

    let Ok(address_length) = libc::socklen_t::try_from(args[5]) else {
        return negative_errno(libc::EINVAL);
    };
    if address_length as usize > std::mem::size_of::<libc::sockaddr_storage>() {
        return negative_errno(libc::EINVAL);
    }
    let mut address = vec![0; address_length as usize];
    if args[4] != 0 && address_length != 0 && memory.user().read(args[4], &mut address).is_err() {
        return negative_errno(libc::EFAULT);
    }
    let address_pointer = if args[4] == 0 {
        std::ptr::null()
    } else {
        address.as_ptr().cast::<libc::sockaddr>()
    };

    // SAFETY: the payload and optional address are readable host buffers and
    // host_fd belongs to the guest descriptor table. MSG_NOSIGNAL keeps a
    // guest EPIPE from delivering SIGPIPE to the supervisor.
    let result = unsafe {
        libc::sendto(
            host_fd,
            bytes.as_ptr().cast::<libc::c_void>(),
            bytes.len(),
            flags | libc::MSG_NOSIGNAL,
            address_pointer,
            address_length,
        )
    };
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result as i64
    }
}

// TODO-HUMAN-REVIEW(PR-218): Review bounded recvfrom buffer and peer-address copyback semantics.
pub(super) fn recvfrom<M: GuestMemoryAccess<Error = crate::Error> + AddressSpace>(
    memory: &mut M,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let Ok(fd) = libc::c_int::try_from(args[0]) else {
        return negative_errno(libc::EBADF);
    };
    let Some(host_fd) = host_fd(state, fd) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(flags) = libc::c_int::try_from(args[3]) else {
        return negative_errno(libc::EINVAL);
    };
    let Ok(requested_length) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if !range_is_valid(memory, args[1], args[2]) {
        return negative_errno(libc::EFAULT);
    }
    let length = requested_length.min(MAX_HOST_IO);
    let Ok(writable) = memory.accessible_prefix(args[1], length, Access::Read) else {
        return negative_errno(libc::EFAULT);
    };
    if writable == 0 && requested_length != 0 {
        return negative_errno(libc::EFAULT);
    }
    let mut bytes = vec![0; writable];

    // SAFETY: a zeroed sockaddr_storage is valid scratch space for recvfrom.
    let mut address =
        unsafe { std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() };
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let guest_address_capacity = if args[4] == 0 {
        0
    } else {
        if args[5] == 0 {
            return negative_errno(libc::EFAULT);
        }
        let capacity = match read_guest_struct::<libc::socklen_t>(memory, args[5]) {
            Ok(capacity) => capacity,
            Err(_) => return negative_errno(libc::EFAULT),
        };
        address_length = address_length.min(capacity);
        capacity as usize
    };
    let address_pointer = if args[4] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut address).cast::<libc::sockaddr>()
    };
    let length_pointer = if args[4] == 0 {
        std::ptr::null_mut()
    } else {
        std::ptr::from_mut(&mut address_length)
    };

    // SAFETY: bytes is writable for its full length, the optional peer address
    // points to initialized host storage, and host_fd is guest-owned.
    let result = unsafe {
        libc::recvfrom(
            host_fd,
            bytes.as_mut_ptr().cast::<libc::c_void>(),
            bytes.len(),
            flags,
            address_pointer,
            length_pointer,
        )
    };
    if result < 0 {
        return io_error(std::io::Error::last_os_error());
    }
    let copy_length = (result as usize).min(bytes.len());
    if copy_length != 0 && memory.write_exact(args[1], &bytes[..copy_length]).is_err() {
        return negative_errno(libc::EFAULT);
    }

    if args[4] != 0 {
        let address_copy_length = guest_address_capacity
            .min(address_length as usize)
            .min(std::mem::size_of::<libc::sockaddr_storage>());
        if address_copy_length != 0 {
            // SAFETY: address is initialized storage and address_copy_length
            // is bounded by its size.
            let address_bytes = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::from_ref(&address).cast::<u8>(),
                    address_copy_length,
                )
            };
            if memory.write_exact(args[4], address_bytes).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
        let copy_result = write_struct(memory, args[5], &address_length);
        if copy_result < 0 {
            return copy_result;
        }
    }
    result as i64
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ControlMessage {
    pub(super) offset: usize,
    pub(super) data_offset: usize,
    pub(super) end: usize,
    pub(super) record_end: usize,
    pub(super) level: libc::c_int,
    pub(super) kind: libc::c_int,
}

pub(super) fn cmsg_align(length: usize) -> Option<usize> {
    let alignment = std::mem::size_of::<usize>();
    length
        .checked_add(alignment - 1)
        .map(|length| length & !(alignment - 1))
}

pub(super) fn control_messages(control: &[u8]) -> Result<Vec<ControlMessage>, i64> {
    let header_size = std::mem::size_of::<libc::cmsghdr>();
    let header_space = cmsg_align(header_size).ok_or_else(|| negative_errno(libc::EINVAL))?;
    let mut messages = Vec::new();
    let mut offset = 0usize;

    while offset < control.len() {
        // A final alignment tail is not another message. Linux's CMSG_NXTHDR
        // makes the same distinction by requiring room for a complete header.
        if control.len() - offset < header_size {
            break;
        }
        // SAFETY: the length check above provides a complete header and
        // read_unaligned accepts byte-buffer alignment.
        let header = unsafe {
            control
                .as_ptr()
                .add(offset)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };
        if header.cmsg_len < header_space {
            return Err(negative_errno(libc::EINVAL));
        }
        let end = offset
            .checked_add(header.cmsg_len)
            .filter(|end| *end <= control.len())
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let aligned_length =
            cmsg_align(header.cmsg_len).ok_or_else(|| negative_errno(libc::EINVAL))?;
        let aligned_end = offset
            .checked_add(aligned_length)
            .ok_or_else(|| negative_errno(libc::EINVAL))?;
        let record_end = aligned_end.min(control.len());
        messages.push(ControlMessage {
            offset,
            data_offset: offset + header_space,
            end,
            record_end,
            level: header.cmsg_level,
            kind: header.cmsg_type,
        });
        if aligned_end >= control.len() {
            break;
        }
        offset = aligned_end;
    }
    Ok(messages)
}

pub(super) fn read_control_fd(control: &[u8], offset: usize) -> Result<libc::c_int, i64> {
    let bytes = control
        .get(offset..offset + std::mem::size_of::<libc::c_int>())
        .ok_or_else(|| negative_errno(libc::EINVAL))?;
    Ok(libc::c_int::from_ne_bytes(
        bytes.try_into().expect("fd slice has exact size"),
    ))
}

fn write_control_fd(control: &mut [u8], offset: usize, fd: libc::c_int) -> Result<(), i64> {
    let destination = control
        .get_mut(offset..offset + std::mem::size_of::<libc::c_int>())
        .ok_or_else(|| negative_errno(libc::EINVAL))?;
    destination.copy_from_slice(&fd.to_ne_bytes());
    Ok(())
}

pub(super) fn is_socket_timestamp_cmsg(message: ControlMessage) -> bool {
    message.level == libc::SOL_SOCKET
        && matches!(
            message.kind,
            SCM_TIMESTAMP_OLD
                | SCM_TIMESTAMPNS_OLD
                | SCM_TIMESTAMPING_OLD
                | SCM_TIMESTAMP_NEW
                | SCM_TIMESTAMPNS_NEW
                | SCM_TIMESTAMPING_NEW
        )
}

/// Returns the process proc transfers registered for `control`. The caller
/// releases them if the host does not queue the message.
pub(super) fn translate_outgoing_control(
    control: &mut [u8],
    state: &LoadedStaticElf,
) -> Result<Vec<(libc::dev_t, libc::ino_t)>, i64> {
    let mut transfers = Vec::new();
    let result = translate_outgoing_rights(control, state, &mut transfers);
    if let Err(error) = result {
        release_proc_transfers(state, &transfers);
        return Err(error);
    }
    Ok(transfers)
}

pub(super) fn translate_outgoing_rights(
    control: &mut [u8],
    state: &LoadedStaticElf,
    transfers: &mut Vec<(libc::dev_t, libc::ino_t)>,
) -> Result<(), i64> {
    for message in control_messages(control)? {
        // SCM_RIGHTS is the only ancillary input whose payload is meaningful in
        // the guest descriptor namespace. Other control inputs (credentials,
        // pidfds, interface selectors, and queue metadata) need their own
        // virtualization rules; fail before sendmsg rather than forwarding
        // guest/host identity bytes under an accidental pass-through policy.
        if message.level != libc::SOL_SOCKET || message.kind != libc::SCM_RIGHTS {
            return Err(negative_errno(libc::EOPNOTSUPP));
        }
        let data_length = message.end - message.data_offset;
        if data_length == 0 || data_length % std::mem::size_of::<libc::c_int>() != 0 {
            return Err(negative_errno(libc::EINVAL));
        }
        for offset in (message.data_offset..message.end).step_by(std::mem::size_of::<libc::c_int>())
        {
            let guest_fd = read_control_fd(control, offset)?;
            let host_fd = host_fd(state, guest_fd).ok_or_else(|| negative_errno(libc::EBADF))?;
            if let Some(owner) = state.pipe_owners.get(&guest_fd) {
                owner.before_export()?;
            }
            if let Some(description) = native_poll_description(state, guest_fd) {
                // Once an untracked receiver might control this description,
                // no known alias can prove its registration set. Invalidate
                // BEFORE host sendmsg, then release the leaf lock. Even a
                // later malformed element/failed send keeps new syscall 441
                // outside admission; the existing send result is unchanged.
                let mut domain = state
                    .epoll_domain
                    .lock()
                    .expect("KVM epoll provenance lock poisoned");
                match description {
                    NativePollDescription::Epoll(identity) => {
                        if let Some(proof) = domain.proofs.get_mut(&epoll_identity_key(&identity)) {
                            proof.unsafe_history = true;
                        }
                    }
                    NativePollDescription::EventFd(identity) => {
                        // A foreign writer controls readiness even when nobody
                        // exports the epoll itself. Never infer determinism
                        // from the native carrier merely being an eventfd.
                        identity.escaped.store(true, Ordering::SeqCst);
                    }
                }
            }
            if state
                .fdinfo_files
                .get(&guest_fd)
                .is_some_and(|description| {
                    matches!(description.source, SeqProcSource::Process { .. })
                })
            {
                // The receiver restores this description from the registry.
                transfers.push(register_proc_transfer(state, guest_fd, host_fd)?);
            } else if state.fdinfo_files.contains_key(&guest_fd)
                || signalfd_mask(state, guest_fd).is_some()
            {
                // The receiver cannot reconstruct private stream/signalfd
                // metadata. Refuse before host sendmsg delivers any payload or
                // descriptors.
                return Err(negative_errno(libc::ENOSYS));
            }
            write_control_fd(control, offset, host_fd)?;
        }
    }
    Ok(())
}

pub(super) struct PendingReceivedRight {
    pub(super) control_offset: usize,
    pub(super) file: std::fs::File,
}

pub(super) struct SanitizedReceivedControl {
    pub(super) bytes: Vec<u8>,
    pub(super) rights: Vec<PendingReceivedRight>,
    pub(super) stripped_unsupported: bool,
}

#[derive(Clone, Copy)]
pub(super) enum ReceivedRawFdKind {
    Right { control_offset: usize },
    Unsupported,
}

fn close_received_raw_fds(raw_fds: &[(libc::c_int, ReceivedRawFdKind)]) {
    let mut closed = std::collections::BTreeSet::new();
    for &(fd, _) in raw_fds {
        if fd >= 0 && closed.insert(fd) {
            // SAFETY: descriptors returned in recvmsg control data belong to
            // this process. This error path has not wrapped them in File yet.
            unsafe { libc::close(fd) };
        }
    }
}

pub(super) fn sanitize_received_control(control: &[u8]) -> Result<SanitizedReceivedControl, i64> {
    let messages = match control_messages(control) {
        Ok(messages) => messages,
        Err(error) => {
            // The host kernel constructs recvmsg control records, so malformed
            // output is not expected. No descriptor can be identified safely
            // without a valid header; fail closed instead of copying bytes.
            return Err(error);
        }
    };
    let mut bytes = Vec::with_capacity(control.len());
    let mut raw_fds = Vec::new();
    let mut stripped_unsupported = false;

    for message in messages {
        if message.level == libc::SOL_SOCKET && message.kind == libc::SCM_RIGHTS {
            let data_length = message.end - message.data_offset;
            if data_length == 0 || data_length % std::mem::size_of::<libc::c_int>() != 0 {
                close_received_raw_fds(&raw_fds);
                return Err(negative_errno(libc::EBADMSG));
            }
            let output_start = bytes.len();
            bytes.resize(output_start + (message.record_end - message.offset), 0);
            bytes[output_start..output_start + (message.end - message.offset)]
                .copy_from_slice(&control[message.offset..message.end]);
            for offset in
                (message.data_offset..message.end).step_by(std::mem::size_of::<libc::c_int>())
            {
                let raw_fd = read_control_fd(control, offset)?;
                if raw_fd < 0 {
                    close_received_raw_fds(&raw_fds);
                    return Err(negative_errno(libc::EBADMSG));
                }
                raw_fds.push((
                    raw_fd,
                    ReceivedRawFdKind::Right {
                        control_offset: output_start + (offset - message.offset),
                    },
                ));
            }
        } else if is_socket_timestamp_cmsg(message) {
            // Detcore canonicalizes these six timestamp ABIs to logical time
            // immediately after the executor returns. Preserve the record but
            // zero alignment padding so stale host bytes never become visible.
            let output_start = bytes.len();
            bytes.resize(output_start + (message.record_end - message.offset), 0);
            bytes[output_start..output_start + (message.end - message.offset)]
                .copy_from_slice(&control[message.offset..message.end]);
        } else {
            stripped_unsupported = true;
            // SCM_PIDFD installs one host descriptor just like SCM_RIGHTS. KVM
            // has no virtual process-fd donation model yet, so close it and
            // report ancillary truncation rather than leaking its host number.
            if message.level == libc::SOL_SOCKET && message.kind == SCM_PIDFD {
                if message.end - message.data_offset != std::mem::size_of::<libc::c_int>() {
                    close_received_raw_fds(&raw_fds);
                    return Err(negative_errno(libc::EBADMSG));
                }
                let raw_fd = read_control_fd(control, message.data_offset)?;
                if raw_fd < 0 {
                    close_received_raw_fds(&raw_fds);
                    return Err(negative_errno(libc::EBADMSG));
                }
                raw_fds.push((raw_fd, ReceivedRawFdKind::Unsupported));
            }
            // Credentials, pidfds, security labels, packet/interface data and
            // queue/error metadata are host identity/state. Until each has a
            // deterministic virtual form, omit it and set MSG_CTRUNC below.
        }
    }

    let mut unique = std::collections::BTreeSet::new();
    if raw_fds.iter().any(|(fd, _)| !unique.insert(*fd)) {
        close_received_raw_fds(&raw_fds);
        return Err(negative_errno(libc::EBADMSG));
    }

    let mut rights = Vec::new();
    for (raw_fd, kind) in raw_fds {
        // SAFETY: recvmsg returned each nonnegative descriptor exactly once and
        // the duplicate check above guarantees unique ownership.
        let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        if let ReceivedRawFdKind::Right { control_offset } = kind {
            rights.push(PendingReceivedRight {
                control_offset,
                file,
            });
        }
        // Unsupported fd-bearing records are closed when `file` drops here.
    }

    Ok(SanitizedReceivedControl {
        bytes,
        rights,
        stripped_unsupported,
    })
}

pub(super) fn available_guest_fds_with_limit(
    state: &LoadedStaticElf,
    count: usize,
    limit: libc::c_int,
) -> Result<Vec<libc::c_int>, i64> {
    let fds = (0..limit)
        .filter(|fd| !is_open_standard(state, *fd) && !state.files.contains_key(fd))
        .take(count)
        .collect::<Vec<_>>();
    if fds.len() == count {
        Ok(fds)
    } else {
        Err(negative_errno(libc::EMFILE))
    }
}

fn rollback_received_rights(state: &mut LoadedStaticElf, guest_fds: &[libc::c_int]) {
    for &fd in guest_fds.iter().rev() {
        let result = close(state, fd as u64);
        debug_assert_eq!(result, 0);
    }
}

pub(super) fn install_received_rights(
    state: &mut LoadedStaticElf,
    control: &mut [u8],
    rights: Vec<PendingReceivedRight>,
    close_on_exec: bool,
    peek: bool,
) -> Result<Vec<libc::c_int>, i64> {
    let rights: Vec<_> = rights
        .into_iter()
        .map(|right| {
            (
                right.control_offset,
                state.file_retirement.stage(right.file),
            )
        })
        .collect();
    let guest_fds = match available_guest_fds_with_limit(state, rights.len(), GUEST_NOFILE_LIMIT) {
        Ok(guest_fds) => guest_fds,
        Err(error) => {
            release_dropped_proc_transfers(
                state,
                rights.iter().map(|(_, file)| file.as_file()),
                peek,
            );
            return Err(error);
        }
    };
    let mut installed = Vec::with_capacity(rights.len());
    let mut pending = rights.into_iter().zip(guest_fds);

    while let Some(((control_offset, file), guest_fd)) = pending.next() {
        // A real procfs right is refused, as every procfs object is.
        let prepared = ensure_not_procfs(file.as_file()).and_then(|()| {
            let timestamps = received_carrier_timestamps(state, file.as_file());
            let object_inode =
                allocate_received_fd_object_inode(state, file.as_file(), timestamps)?;
            let transfer = received_proc_transfer(state, file.as_file(), peek)?;
            Ok((object_inode, transfer))
        });
        let (object_inode, transfer) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                rollback_received_rights(state, &installed);
                let rest: Vec<_> = pending.map(|((_, file), _)| file).collect();
                release_dropped_proc_transfers(
                    state,
                    std::iter::once(&file)
                        .chain(&rest)
                        .map(|file| file.as_file()),
                    peek,
                );
                return Err(error);
            }
        };
        let retired = state.insert_file(guest_fd, file.into_file());
        state.file_retirement.retire(retired);
        state.fd_object_inodes.insert(guest_fd, object_inode);
        state.synthetic_proc_nofollow_fds.remove(&guest_fd);
        if let Some((description, inode, nofollow)) = transfer {
            // The received descriptor shares the sender's open description.
            state.fdinfo_files.insert(guest_fd, description);
            state.proc_files.insert(guest_fd, inode);
            if nofollow {
                state.synthetic_proc_nofollow_fds.insert(guest_fd);
            }
        } else {
            state.fdinfo_files.remove(&guest_fd);
            state.proc_files.remove(&guest_fd);
        }
        if close_on_exec {
            state.cloexec_fds.insert(guest_fd);
        } else {
            state.cloexec_fds.remove(&guest_fd);
        }
        set_output_alias(state, guest_fd, None);
        if let Err(error) = write_control_fd(control, control_offset, guest_fd) {
            installed.push(guest_fd);
            rollback_received_rights(state, &installed);
            let rest: Vec<_> = pending.map(|((_, file), _)| file).collect();
            release_dropped_proc_transfers(state, rest.iter().map(|file| file.as_file()), peek);
            return Err(error);
        }
        installed.push(guest_fd);
    }
    Ok(installed)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-385): Review bounded sendmsg translation, SCM_RIGHTS
// guest-to-host descriptor mapping, and deterministic ancillary policy.
//
// The single-message send sibling of `sendto`/`recvmmsg`. Detcore already
// classifies `sendmsg` as Determinized and drives it through the backend's
// nonblockable-fd path (see hermit detcore/src/lib.rs `handle_sendrecv`), so
// this executor arm only has to translate the guest `msghdr` — gathering the
// iovec payload and name and mapping SCM_RIGHTS descriptors — before forwarding
// it to the host socket.
pub(super) fn sendmsg(memory: &GuestMemory, state: &LoadedStaticElf, args: &[u64; 6]) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    if args[1] == 0 {
        return negative_errno(libc::EFAULT);
    }
    let message: libc::msghdr = match read_guest_struct(&ProviderMemory(memory), args[1]) {
        Ok(message) => message,
        Err(error) => return error,
    };

    let iov_count = message.msg_iovlen;
    if iov_count > libc::UIO_MAXIOV as usize {
        return negative_errno(libc::EMSGSIZE);
    }
    if iov_count != 0 && message.msg_iov.is_null() {
        return negative_errno(libc::EFAULT);
    }
    let guest_iov_address = message.msg_iov as usize as u64;
    let mut payload: Vec<u8> = Vec::new();
    for iov_index in 0..iov_count {
        let Some(iov_address) =
            guest_iov_address.checked_add((iov_index * std::mem::size_of::<libc::iovec>()) as u64)
        else {
            return negative_errno(libc::EFAULT);
        };
        let iov: libc::iovec = match read_guest_struct(&ProviderMemory(memory), iov_address) {
            Ok(iov) => iov,
            Err(error) => return error,
        };
        let Some(next_length) = payload.len().checked_add(iov.iov_len) else {
            return negative_errno(libc::EINVAL);
        };
        if next_length > MAX_HOST_IO {
            return negative_errno(libc::EINVAL);
        }
        if iov.iov_len != 0 {
            let mut segment = vec![0u8; iov.iov_len];
            if memory
                .user()
                .read(iov.iov_base as usize as u64, &mut segment)
                .is_err()
            {
                return negative_errno(libc::EFAULT);
            }
            payload.extend_from_slice(&segment);
        }
    }

    let name_capacity = message.msg_namelen as usize;
    let control_capacity = message.msg_controllen;
    if name_capacity > MAX_HOST_IO || control_capacity > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    if name_capacity != 0 && message.msg_name.is_null() {
        return negative_errno(libc::EFAULT);
    }
    if control_capacity != 0 && message.msg_control.is_null() {
        return negative_errno(libc::EFAULT);
    }
    let mut name = vec![0u8; name_capacity];
    let mut control = vec![0u8; control_capacity];
    if name_capacity != 0
        && memory
            .user()
            .read(message.msg_name as usize as u64, &mut name)
            .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    if control_capacity != 0
        && memory
            .user()
            .read(message.msg_control as usize as u64, &mut control)
            .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    let transfers = match translate_outgoing_control(&mut control, state) {
        Ok(transfers) => transfers,
        Err(error) => return error,
    };

    let mut host_iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let host_header = libc::msghdr {
        msg_name: if name.is_empty() {
            std::ptr::null_mut()
        } else {
            name.as_mut_ptr().cast()
        },
        msg_namelen: name.len() as libc::socklen_t,
        msg_iov: std::ptr::from_mut(&mut host_iov),
        msg_iovlen: usize::from(!payload.is_empty()),
        msg_control: if control.is_empty() {
            std::ptr::null_mut()
        } else {
            control.as_mut_ptr().cast()
        },
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    let flags = args[2] as libc::c_int;
    // SAFETY: payload/name/control are readable host buffers matching the
    // header's declared lengths, and host_fd belongs to the guest descriptor
    // table. The supervisor cannot safely accept a guest SIGPIPE, so KVM's
    // explicit policy is to suppress the host signal and return EPIPE. Guest
    // SIGPIPE synthesis remains a separate signal-delivery capability.
    let result = unsafe {
        libc::sendmsg(
            host_fd,
            std::ptr::from_ref(&host_header),
            flags | libc::MSG_NOSIGNAL,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        // A failed sendmsg queues no rights.
        release_proc_transfers(state, &transfers);
        io_error(error)
    } else {
        result as i64
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-385): Review bounded recvmsg translation, transactional
// SCM_RIGHTS installation, CLOEXEC modeling, and ancillary-data filtering.
//
// The single-message receive form; `recvmmsg` is its multi-message sibling and
// this reuses the same translation shape for exactly one `msghdr`. Detcore
// classifies `recvmsg` as Determinized and canonicalizes any host socket
// timestamps in the ancillary control buffer after this returns (see hermit
// detcore/src/syscalls/io.rs `handle_recvmsg` / `canonicalize_socket_timestamps`),
// so the executor only faithfully performs the host receive and copies the
// control/name bytes back into guest memory for Detcore to sanitize.
pub(super) fn recvmsg(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let message_address = args[1];
    if message_address == 0 {
        return negative_errno(libc::EFAULT);
    }
    let mut message: libc::msghdr =
        match read_guest_struct(&ProviderMemory(memory), message_address) {
            Ok(message) => message,
            Err(error) => return error,
        };
    // Validate the final header copyout before consuming a datagram.
    if write_struct(&mut ProviderMemory(memory), message_address, &message) != 0 {
        return negative_errno(libc::EFAULT);
    }

    let iov_count = message.msg_iovlen;
    if iov_count > libc::UIO_MAXIOV as usize {
        return negative_errno(libc::EMSGSIZE);
    }
    if iov_count != 0 && message.msg_iov.is_null() {
        return negative_errno(libc::EFAULT);
    }
    let guest_iov_address = message.msg_iov as usize as u64;
    let mut guest_iovecs = Vec::with_capacity(iov_count);
    let mut payload_length = 0usize;
    for iov_index in 0..iov_count {
        let Some(iov_address) =
            guest_iov_address.checked_add((iov_index * std::mem::size_of::<libc::iovec>()) as u64)
        else {
            return negative_errno(libc::EFAULT);
        };
        let iov: libc::iovec = match read_guest_struct(&ProviderMemory(memory), iov_address) {
            Ok(iov) => iov,
            Err(error) => return error,
        };
        let Some(next_length) = payload_length.checked_add(iov.iov_len) else {
            return negative_errno(libc::EINVAL);
        };
        if next_length > MAX_HOST_IO {
            return negative_errno(libc::EINVAL);
        }
        if iov.iov_len != 0 {
            let mut probe = vec![0; iov.iov_len];
            if memory
                .user()
                .read(iov.iov_base as usize as u64, &mut probe)
                .is_err()
            {
                return negative_errno(libc::EFAULT);
            }
        }
        payload_length = next_length;
        guest_iovecs.push(iov);
    }

    let name_capacity = message.msg_namelen as usize;
    let control_capacity = message.msg_controllen;
    if name_capacity > MAX_HOST_IO || control_capacity > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }
    if name_capacity != 0 && message.msg_name.is_null() {
        return negative_errno(libc::EFAULT);
    }
    if control_capacity != 0 && message.msg_control.is_null() {
        return negative_errno(libc::EFAULT);
    }
    let mut payload = vec![0u8; payload_length];
    let mut name = vec![0u8; name_capacity];
    let mut control = vec![0u8; control_capacity];
    for (address, length) in [
        (message.msg_name as usize as u64, name_capacity),
        (message.msg_control as usize as u64, control_capacity),
    ] {
        if length != 0 {
            let mut probe = vec![0; length];
            if memory.user().read(address, &mut probe).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
    }

    let mut host_iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut host_header = libc::msghdr {
        msg_name: if name.is_empty() {
            std::ptr::null_mut()
        } else {
            name.as_mut_ptr().cast()
        },
        msg_namelen: name.len() as libc::socklen_t,
        msg_iov: std::ptr::from_mut(&mut host_iov),
        msg_iovlen: usize::from(!payload.is_empty()),
        msg_control: if control.is_empty() {
            std::ptr::null_mut()
        } else {
            control.as_mut_ptr().cast()
        },
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    let flags = args[2] as libc::c_int;
    // Keep the VM executor cooperative: Detcore's scheduler owns blocking and
    // retries EAGAIN, while already-queued datagrams are returned immediately.
    // Always ask the host for CLOEXEC descriptors so a supervisor exec cannot
    // leak them; guest CLOEXEC state is modeled from the caller's original flag.
    let received = unsafe {
        libc::recvmsg(
            host_fd,
            std::ptr::from_mut(&mut host_header),
            flags | libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return io_error(std::io::Error::last_os_error());
    }

    let used_control = host_header.msg_controllen.min(control.len());
    let SanitizedReceivedControl {
        bytes: mut control_bytes,
        rights,
        stripped_unsupported,
    } = match sanitize_received_control(&control[..used_control]) {
        Ok(control) => control,
        Err(error) => return error,
    };

    let copied_length = (received as usize).min(payload.len());
    let mut copied = 0usize;
    for iov in &guest_iovecs {
        let length = iov.iov_len.min(copied_length.saturating_sub(copied));
        if length != 0
            && memory
                .user()
                .write(
                    iov.iov_base as usize as u64,
                    &payload[copied..copied + length],
                )
                .is_err()
        {
            let dropped = rights.iter().map(|right| &right.file);
            release_dropped_proc_transfers(state, dropped, flags & libc::MSG_PEEK != 0);
            return negative_errno(libc::EFAULT);
        }
        copied += length;
    }
    if name_capacity != 0
        && memory
            .user()
            .write(
                message.msg_name as usize as u64,
                &name[..name_capacity.min(host_header.msg_namelen as usize)],
            )
            .is_err()
    {
        let dropped = rights.iter().map(|right| &right.file);
        release_dropped_proc_transfers(state, dropped, flags & libc::MSG_PEEK != 0);
        return negative_errno(libc::EFAULT);
    }

    let installed = match install_received_rights(
        state,
        &mut control_bytes,
        rights,
        flags & libc::MSG_CMSG_CLOEXEC != 0,
        flags & libc::MSG_PEEK != 0,
    ) {
        Ok(installed) => installed,
        Err(error) => return error,
    };
    if control_capacity != 0 {
        // Detcore snapshots the caller's original capacity before injection and
        // rereads that entire region to canonicalize timestamps. Zero the tail
        // so stripped host metadata or stale guest bytes cannot be reparsed as
        // a second control record.
        let mut guest_control = vec![0; control_capacity];
        guest_control[..control_bytes.len()].copy_from_slice(&control_bytes);
        if memory
            .user()
            .write(message.msg_control as usize as u64, &guest_control)
            .is_err()
        {
            rollback_received_rights(state, &installed);
            return negative_errno(libc::EFAULT);
        }
    }
    message.msg_namelen = host_header.msg_namelen;
    message.msg_controllen = control_bytes.len();
    message.msg_flags = host_header.msg_flags;
    if flags & libc::MSG_CMSG_CLOEXEC == 0 {
        message.msg_flags &= !libc::MSG_CMSG_CLOEXEC;
    }
    if stripped_unsupported {
        message.msg_flags |= libc::MSG_CTRUNC;
    }
    if write_struct(&mut ProviderMemory(memory), message_address, &message) != 0 {
        rollback_received_rights(state, &installed);
        return negative_errno(libc::EFAULT);
    }
    received as i64
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-210): Review guest mmsghdr translation and nonblocking receive semantics.
pub(super) fn recvmmsg(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let Some(host_fd) = host_fd(state, args[0] as libc::c_int) else {
        return negative_errno(libc::EBADF);
    };
    let Ok(message_count) = usize::try_from(args[2]) else {
        return negative_errno(libc::EINVAL);
    };
    if message_count == 0 || message_count > libc::UIO_MAXIOV as usize {
        return negative_errno(libc::EINVAL);
    }

    let message_size = std::mem::size_of::<libc::mmsghdr>();
    let Some(total_header_bytes) = message_count.checked_mul(message_size) else {
        return negative_errno(libc::EINVAL);
    };
    if total_header_bytes > MAX_HOST_IO {
        return negative_errno(libc::EINVAL);
    }

    let mut delivered = 0usize;
    for index in 0..message_count {
        let Some(message_address) = args[1].checked_add((index * message_size) as u64) else {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        };
        let mut message: libc::mmsghdr =
            match read_guest_struct(&ProviderMemory(memory), message_address) {
                Ok(message) => message,
                Err(error) => {
                    return if delivered == 0 {
                        error
                    } else {
                        delivered as i64
                    };
                }
            };
        let iov_count = message.msg_hdr.msg_iovlen;
        if iov_count > libc::UIO_MAXIOV as usize {
            return if delivered == 0 {
                negative_errno(libc::EMSGSIZE)
            } else {
                delivered as i64
            };
        }

        let guest_iov_address = message.msg_hdr.msg_iov as usize as u64;
        let mut guest_iovecs = Vec::with_capacity(iov_count);
        let mut payload_length = 0usize;
        for iov_index in 0..iov_count {
            let Some(iov_address) = guest_iov_address
                .checked_add((iov_index * std::mem::size_of::<libc::iovec>()) as u64)
            else {
                return if delivered == 0 {
                    negative_errno(libc::EFAULT)
                } else {
                    delivered as i64
                };
            };
            let iov: libc::iovec = match read_guest_struct(&ProviderMemory(memory), iov_address) {
                Ok(iov) => iov,
                Err(error) => {
                    return if delivered == 0 {
                        error
                    } else {
                        delivered as i64
                    };
                }
            };
            let Some(next_length) = payload_length.checked_add(iov.iov_len) else {
                return if delivered == 0 {
                    negative_errno(libc::EINVAL)
                } else {
                    delivered as i64
                };
            };
            if next_length > MAX_HOST_IO {
                return if delivered == 0 {
                    negative_errno(libc::EINVAL)
                } else {
                    delivered as i64
                };
            }
            if iov.iov_len != 0 {
                let mut probe = vec![0; iov.iov_len];
                if memory
                    .user()
                    .read(iov.iov_base as usize as u64, &mut probe)
                    .is_err()
                {
                    return if delivered == 0 {
                        negative_errno(libc::EFAULT)
                    } else {
                        delivered as i64
                    };
                }
            }
            payload_length = next_length;
            guest_iovecs.push(iov);
        }

        let name_capacity = message.msg_hdr.msg_namelen as usize;
        let control_capacity = message.msg_hdr.msg_controllen;
        if name_capacity > MAX_HOST_IO || control_capacity > MAX_HOST_IO {
            return if delivered == 0 {
                negative_errno(libc::EINVAL)
            } else {
                delivered as i64
            };
        }
        let mut payload = vec![0u8; payload_length];
        let mut name = vec![0u8; name_capacity];
        let mut control = vec![0u8; control_capacity];
        if name_capacity != 0
            && memory
                .user()
                .read(message.msg_hdr.msg_name as usize as u64, &mut name)
                .is_err()
        {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        if control_capacity != 0
            && memory
                .user()
                .read(message.msg_hdr.msg_control as usize as u64, &mut control)
                .is_err()
        {
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }

        let mut host_iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut host_header = libc::msghdr {
            msg_name: if name.is_empty() {
                std::ptr::null_mut()
            } else {
                name.as_mut_ptr().cast()
            },
            msg_namelen: name.len() as libc::socklen_t,
            msg_iov: std::ptr::from_mut(&mut host_iov),
            msg_iovlen: usize::from(!payload.is_empty()),
            msg_control: if control.is_empty() {
                std::ptr::null_mut()
            } else {
                control.as_mut_ptr().cast()
            },
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        let flags = args[3] as libc::c_int & !libc::MSG_WAITFORONE;
        // Keep the VM executor cooperative. Detcore retries EAGAIN through its
        // scheduler, while already queued datagrams are returned immediately.
        let received = unsafe {
            libc::recvmsg(
                host_fd,
                std::ptr::from_mut(&mut host_header),
                flags | libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if received < 0 {
            let error = io_error(std::io::Error::last_os_error());
            return if delivered == 0 {
                error
            } else {
                delivered as i64
            };
        }

        let used_control = host_header.msg_controllen.min(control.len());
        let SanitizedReceivedControl {
            bytes: mut control_bytes,
            rights,
            stripped_unsupported,
        } = match sanitize_received_control(&control[..used_control]) {
            Ok(control) => control,
            Err(error) => {
                return if delivered == 0 {
                    error
                } else {
                    delivered as i64
                };
            }
        };

        let copied_length = (received as usize).min(payload.len());
        let mut copied = 0usize;
        for iov in &guest_iovecs {
            let length = iov.iov_len.min(copied_length.saturating_sub(copied));
            if length != 0
                && memory
                    .user()
                    .write(
                        iov.iov_base as usize as u64,
                        &payload[copied..copied + length],
                    )
                    .is_err()
            {
                let dropped = rights.iter().map(|right| &right.file);
                release_dropped_proc_transfers(state, dropped, flags & libc::MSG_PEEK != 0);
                return if delivered == 0 {
                    negative_errno(libc::EFAULT)
                } else {
                    delivered as i64
                };
            }
            copied += length;
        }
        if name_capacity != 0
            && memory
                .user()
                .write(
                    message.msg_hdr.msg_name as usize as u64,
                    &name[..name_capacity.min(host_header.msg_namelen as usize)],
                )
                .is_err()
        {
            let dropped = rights.iter().map(|right| &right.file);
            release_dropped_proc_transfers(state, dropped, flags & libc::MSG_PEEK != 0);
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        let installed = match install_received_rights(
            state,
            &mut control_bytes,
            rights,
            flags & libc::MSG_CMSG_CLOEXEC != 0,
            flags & libc::MSG_PEEK != 0,
        ) {
            Ok(installed) => installed,
            Err(error) => {
                return if delivered == 0 {
                    error
                } else {
                    delivered as i64
                };
            }
        };
        if control_capacity != 0 {
            let mut guest_control = vec![0; control_capacity];
            guest_control[..control_bytes.len()].copy_from_slice(&control_bytes);
            if memory
                .user()
                .write(message.msg_hdr.msg_control as usize as u64, &guest_control)
                .is_err()
            {
                rollback_received_rights(state, &installed);
                return if delivered == 0 {
                    negative_errno(libc::EFAULT)
                } else {
                    delivered as i64
                };
            }
        }
        message.msg_hdr.msg_namelen = host_header.msg_namelen;
        message.msg_hdr.msg_controllen = control_bytes.len();
        message.msg_hdr.msg_flags = host_header.msg_flags;
        if flags & libc::MSG_CMSG_CLOEXEC == 0 {
            message.msg_hdr.msg_flags &= !libc::MSG_CMSG_CLOEXEC;
        }
        if stripped_unsupported {
            message.msg_hdr.msg_flags |= libc::MSG_CTRUNC;
        }
        message.msg_len = received as libc::c_uint;
        if write_struct(&mut ProviderMemory(memory), message_address, &message) != 0 {
            rollback_received_rights(state, &installed);
            return if delivered == 0 {
                negative_errno(libc::EFAULT)
            } else {
                delivered as i64
            };
        }
        delivered += 1;
    }
    delivered as i64
}

// General FIONREAD support was withdrawn in 345681e44bf9d07f8c9f52138ce2682633adfffe:
// SCM_RIGHTS does not retain synthetic proc-file semantics. Only an actual host
// pipe/FIFO can use this operation without that missing descriptor metadata.
pub(super) fn pipe_fionread<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    state: &LoadedStaticElf,
    guest_fd: libc::c_int,
    host_fd: libc::c_int,
    address: u64,
    capture_output: bool,
) -> i64 {
    if capture_output && output_alias(state, guest_fd).is_some() {
        return negative_errno(libc::ENOTTY);
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: stat has writable storage and host_fd belongs to this file table.
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized the complete structure.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return negative_errno(libc::ENOTTY);
    }
    if capture_output {
        // Received rights lose OutputAlias metadata. Compare actual objects so
        // a transferred capture backing pipe cannot expose supervisor bytes.
        // Guest close/dup/exec never close or replace host stdio; those retained
        // host references keep the identity live even after queued sender close.
        // As elsewhere in inherited-stdio handling, concurrent external host
        // replacement of these descriptors is outside the supported lifetime.
        for standard in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            let mut backing = std::mem::MaybeUninit::<libc::stat>::zeroed();
            // SAFETY: backing has writable storage; fstat checks the descriptor.
            if unsafe { libc::fstat(standard, backing.as_mut_ptr()) } != 0 {
                return negative_errno(libc::ENOTTY);
            }
            // SAFETY: successful fstat initialized the complete structure.
            let backing = unsafe { backing.assume_init() };
            if (stat.st_dev, stat.st_ino) == (backing.st_dev, backing.st_ino) {
                return negative_errno(libc::ENOTTY);
            }
        }
    }
    let mut count: libc::c_int = 0;
    // SAFETY: count is supervisor storage for one int. The kernel observes the
    // actual pipe under its own mutex without consuming any queued bytes.
    if unsafe { libc::ioctl(host_fd, libc::FIONREAD, &mut count) } != 0 {
        return io_error(std::io::Error::last_os_error());
    }
    if memory.put_user_i32(address, count).is_err() {
        return negative_errno(libc::EFAULT);
    }
    0
}
