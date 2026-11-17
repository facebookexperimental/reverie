/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest sendmsg or sendmmsg at an unpatched syscall site, trapped and run
//! through the installed Tool's fallback path, with control data, a msghdr
//! or a sendmmsg vector on a page under a protection key the guest denies,
//! allows, or allows only for reading. While a reserved descriptor exists
//! (the coordinator connection is one), the runtime runs such a send on a
//! checked copy of its message headers and control data
//! (<https://github.com/facebookexperimental/reverie/issues/56>), which it
//! makes, and into which it stores a sent message's msg_len, with the
//! interrupted guest's rights. Every case runs natively first, before the
//! Tool is installed, and then through the Tool, and the two are compared.

use core::arch::global_asm;
use std::path::Path;

/// What one case did: each call's result, each message the peer received
/// (its first byte and the inodes of the descriptors it carried), and the
/// msg_len words of the case's sendmmsg vector.
#[derive(Debug, PartialEq)]
struct Outcome {
    results: Vec<i64>,
    delivered: Vec<(u8, Vec<u64>)>,
    lengths: Vec<u32>,
}

const EFAULT: i64 = -(libc::EFAULT as i64);
const EBADF: i64 = -(libc::EBADF as i64);
const LABELS: [&str; 5] = [
    "denied control",
    "denied header",
    "allowed",
    "allowed vector",
    "read-only vector",
];

fn inode(fd: libc::c_int) -> u64 {
    let mut stat: libc::stat = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0, "fstat {fd}");
    stat.st_ino
}

fn read_pkru() -> u32 {
    let pkru: u32;
    unsafe {
        core::arch::asm!(
            "rdpkru",
            in("ecx") 0,
            out("eax") pkru,
            out("edx") _,
            options(nomem, nostack, preserves_flags)
        )
    };
    pkru
}

/// Every message queued on `socket`, without waiting, as an Outcome lists
/// them. The received descriptors are closed.
fn receive_all(socket: libc::c_int) -> Vec<(u8, Vec<u64>)> {
    let mut messages = Vec::new();
    loop {
        let mut byte = [0_u8; 8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        let mut control = [0_u64; 16];
        let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = core::mem::size_of_val(&control) as _;
        let flags = libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC;
        if unsafe { libc::recvmsg(socket, &raw mut message, flags) } < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            return messages;
        }
        let mut inodes = Vec::new();
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
        while !header.is_null() {
            let (level, kind, length) = unsafe {
                (
                    (*header).cmsg_level,
                    (*header).cmsg_type,
                    (*header).cmsg_len,
                )
            };
            if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
                let data = unsafe { libc::CMSG_DATA(header) }.cast::<libc::c_int>();
                let count = (length - unsafe { libc::CMSG_LEN(0) } as usize) / 4;
                for index in 0..count {
                    let fd = unsafe { data.add(index).read_unaligned() };
                    inodes.push(inode(fd));
                    assert_eq!(unsafe { libc::close(fd) }, 0);
                }
            }
            header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
        }
        messages.push((byte[0], inodes));
    }
}

/// Writes one SCM_RIGHTS record naming `fd` at `place` and returns its
/// msg_controllen (CMSG_SPACE of one descriptor).
fn write_rights(place: *mut u8, fd: libc::c_int) -> usize {
    let length = unsafe { libc::CMSG_LEN(4) } as u64;
    let space = unsafe { libc::CMSG_SPACE(4) } as usize;
    unsafe {
        core::ptr::write_bytes(place, 0, space);
        place.cast::<u64>().write(length);
        place.add(8).cast::<i32>().write(libc::SOL_SOCKET);
        place.add(12).cast::<i32>().write(libc::SCM_RIGHTS);
        place.add(16).cast::<i32>().write(fd);
    }
    space
}

/// A msghdr sending `iov`'s byte with `length` bytes of control data at
/// `control` (none when `length` is 0).
fn header(iov: *mut libc::iovec, control: *mut u8, length: usize) -> libc::msghdr {
    let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    if length > 0 {
        message.msg_control = control.cast();
        message.msg_controllen = length as _;
    }
    message
}

/// Calls the unpatched site with this thread's PKRU set to `pkru`, then puts
/// the PKRU back, and returns the call's result.
fn call(site: usize, number: i64, args: [u64; 3], pkru: u32) -> i64 {
    unsafe { fallback_scm_pkey_call(site, number, args[0], args[1], args[2], pkru) }
}

/// The descriptor numbers this process has open, from /proc/self/fd.
/// The listing itself opens a descriptor, so the numbers are collected
/// first and only those whose link still resolves once the listing has
/// closed are kept: the listing's own descriptor, and any other
/// transient one, is gone by then and fails to resolve.
fn fd_numbers() -> std::collections::BTreeSet<libc::c_int> {
    let mut listed = Vec::new();
    {
        let entries = std::fs::read_dir("/proc/self/fd").expect("list /proc/self/fd");
        for entry in entries {
            let entry = entry.expect("read /proc/self/fd entry");
            if let Ok(number) = entry.file_name().to_string_lossy().parse::<libc::c_int>() {
                listed.push(number);
            }
        }
    }
    listed
        .into_iter()
        .filter(|number| std::fs::read_link(format!("/proc/self/fd/{number}")).is_ok())
        .collect()
}

/// A descriptor the runtime reserved when the Tool was installed: one that
/// appeared after install and was not open before it. The difference from
/// the pre-install set decides, never a number range. Finding none is a
/// failure, not a skip: without a reserved descriptor the checked-copy
/// path this test guards is not in force.
fn reserved_descriptor(before: &std::collections::BTreeSet<libc::c_int>) -> libc::c_int {
    let after = fd_numbers();
    let appeared: Vec<libc::c_int> = after.difference(before).copied().collect();
    assert!(
        !appeared.is_empty(),
        "no runtime-reserved descriptor appeared after install; \
         the runtime copy is not on the fallback path"
    );
    appeared[0]
}

/// Sends one allowed message through the site naming `reserved_fd` in its
/// control data, and returns the result and what the peer received. On the
/// checked copy the runtime replaces a reserved descriptor with -1, so the
/// kernel answers EBADF and queues nothing; a raw forward of the guest's
/// headers would deliver the descriptor and succeed.
fn reserved_case(
    site: usize,
    keyed: *mut u8,
    pair: [libc::c_int; 2],
    reserved_fd: libc::c_int,
    allow: u32,
) -> (i64, Vec<(u8, Vec<u64>)>) {
    let mut byte = b'r';
    let mut iov = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let keyed_header = keyed.cast::<libc::msghdr>();
    let keyed_control = unsafe { keyed.add(512) };
    let length = write_rights(keyed_control, reserved_fd);
    unsafe { keyed_header.write(header(&raw mut iov, keyed_control, length)) };
    let result = call(
        site,
        libc::SYS_sendmsg,
        [pair[0] as u64, keyed_header as u64, 0],
        allow,
    );
    (result, receive_all(pair[1]))
}

/// The five cases, on `keyed`, a page under the key: `allow`, `deny` and
/// `read_only` are this thread's PKRU with the key allowed, denied, and
/// allowed for reading only. `file` is a pipe the guest owns.
fn cases(
    site: usize,
    keyed: *mut u8,
    pair: [libc::c_int; 2],
    file: libc::c_int,
    pkru: [u32; 3],
) -> Vec<Outcome> {
    let [allow, deny, read_only] = pkru;
    let mut payload = *b"abc01e";
    let base = payload.as_mut_ptr();
    let mut iovs: Vec<libc::iovec> = (0..payload.len())
        .map(|index| libc::iovec {
            iov_base: unsafe { base.add(index) }.cast(),
            iov_len: 1,
        })
        .collect();
    let iov_base = iovs.as_mut_ptr();
    let iov = |index: usize| -> *mut libc::iovec { unsafe { iov_base.add(index) } };
    let mut outcomes = Vec::new();
    let mut ordinary_control = [0_u64; 4];
    let ordinary = ordinary_control.as_mut_ptr().cast::<u8>();
    let keyed_header = keyed.cast::<libc::msghdr>();
    let keyed_control = unsafe { keyed.add(512) };
    let vector = unsafe { keyed.add(1024) }.cast::<libc::mmsghdr>();
    let vector_control = unsafe { keyed.add(1536) };
    let vector_lengths = move || unsafe { vec![(*vector).msg_len, (*vector.add(1)).msg_len] };
    let socket = pair[0] as u64;

    // Denied control: an ordinary msghdr whose control data, naming the
    // guest's pipe, is on the keyed page; the key denied.
    let length = write_rights(keyed_control, file);
    let message = header(iov(0), keyed_control, length);
    let results = vec![call(
        site,
        libc::SYS_sendmsg,
        [socket, (&raw const message) as u64, 0],
        deny,
    )];
    outcomes.push(Outcome {
        results,
        delivered: receive_all(pair[1]),
        lengths: Vec::new(),
    });

    // Denied header: the msghdr on the keyed page, its control data in
    // ordinary memory; the key denied.
    let length = write_rights(ordinary, file);
    unsafe { keyed_header.write(header(iov(1), ordinary, length)) };
    let results = vec![call(
        site,
        libc::SYS_sendmsg,
        [socket, keyed_header as u64, 0],
        deny,
    )];
    outcomes.push(Outcome {
        results,
        delivered: receive_all(pair[1]),
        lengths: Vec::new(),
    });

    // Allowed: the msghdr and its control data on the keyed page.
    let length = write_rights(keyed_control, file);
    unsafe { keyed_header.write(header(iov(2), keyed_control, length)) };
    let results = vec![call(
        site,
        libc::SYS_sendmsg,
        [socket, keyed_header as u64, 0],
        allow,
    )];
    outcomes.push(Outcome {
        results,
        delivered: receive_all(pair[1]),
        lengths: Vec::new(),
    });

    // Allowed vector: two messages on the keyed page, message 0 naming the
    // pipe in control data there. The guest sends the remainder until both
    // are counted, as a program that honours a short count does.
    let length = write_rights(vector_control, file);
    unsafe {
        vector.write(core::mem::zeroed());
        (*vector).msg_hdr = header(iov(3), vector_control, length);
        vector.add(1).write(core::mem::zeroed());
        (*vector.add(1)).msg_hdr = header(iov(4), core::ptr::null_mut(), 0);
    }
    let mut results = Vec::new();
    let mut sent = 0;
    while sent < 2 {
        let rest = unsafe { vector.add(sent) } as u64;
        let result = call(
            site,
            libc::SYS_sendmmsg,
            [socket, rest, (2 - sent) as u64],
            allow,
        );
        results.push(result);
        if result <= 0 {
            break;
        }
        sent += result as usize;
    }
    outcomes.push(Outcome {
        results,
        delivered: receive_all(pair[1]),
        lengths: vector_lengths(),
    });

    // Read-only vector: one message on the keyed page, which the guest may
    // read but not write. Linux sends it, cannot store its msg_len and
    // answers EFAULT.
    unsafe {
        vector.write(core::mem::zeroed());
        (*vector).msg_hdr = header(iov(5), core::ptr::null_mut(), 0);
        vector.add(1).write(core::mem::zeroed());
    }
    let results = vec![call(
        site,
        libc::SYS_sendmmsg,
        [socket, vector as u64, 1],
        read_only,
    )];
    outcomes.push(Outcome {
        results,
        delivered: receive_all(pair[1]),
        lengths: vector_lengths(),
    });
    outcomes
}

pub(super) fn run(path: &Path) {
    let features = core::arch::x86_64::__cpuid_count(7, 0);
    if features.ecx & (1 << 4) == 0 {
        println!("fallback scm pkeys: OSPKE unavailable");
        std::process::exit(77);
    }
    let (site, _) = super::prepare_site();
    let site = site as usize;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    // Allocating with rights zero enables this key for the calling thread.
    let key = unsafe { libc::syscall(libc::SYS_pkey_alloc, 0, 0) };
    assert!(key > 0, "pkey_alloc: {}", std::io::Error::last_os_error());
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                mapping,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                key,
            )
        },
        0
    );
    let shift = 2 * key as u32;
    let allow = read_pkru() & !(3 << shift);
    let pkru = [allow, allow | 1 << shift, allow | 2 << shift];
    let mut pair = [0 as libc::c_int; 2];
    let kind = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, pair.as_mut_ptr()) },
        0
    );
    let mut ends = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let file = ends[0];
    let keyed = mapping.cast::<u8>();

    let native = cases(site, keyed, pair, file, pkru);
    let before_install = fd_numbers();
    unsafe { reverie_liteinst::install_tool::<super::FallbackTool>(path) }.unwrap();
    let reserved_fd = reserved_descriptor(&before_install);
    let tool = cases(site, keyed, pair, file, pkru);
    let (reserved_result, reserved_delivered) =
        reserved_case(site, keyed, pair, reserved_fd, pkru[0]);
    // The reserved descriptor is still open after the send, so the
    // EBADF below cannot be the answer for a closed number.
    assert!(
        fd_numbers().contains(&reserved_fd),
        "case reserved descriptor: the reserved descriptor is no longer open"
    );

    // Linux's own answers, which make the comparison meaningful.
    let pipe = inode(file);
    let expected_native = [
        (vec![EFAULT], vec![], vec![]),
        (vec![EFAULT], vec![], vec![]),
        (vec![1], vec![(b'c', vec![pipe])], vec![]),
        (
            vec![2],
            vec![(b'0', vec![pipe]), (b'1', vec![])],
            vec![1, 1],
        ),
        (vec![EFAULT], vec![(b'e', vec![])], vec![0, 0]),
    ];
    for (index, (results, delivered, lengths)) in expected_native.into_iter().enumerate() {
        let label = LABELS[index];
        assert_eq!(
            native[index],
            Outcome {
                results,
                delivered,
                lengths,
            },
            "case {label}: native Linux did not give the expected answer"
        );
    }
    for index in [0, 1, 2, 4] {
        let label = LABELS[index];
        assert_eq!(
            tool[index], native[index],
            "case {label}: the Tool path differs from native"
        );
    }
    // The allowed vector: the runtime sends the whole vector through
    // the checked copy in one guest call, as Linux does, so the result
    // count [2] no longer shows which path the send took. The reserved
    // descriptor case is the direct evidence: only the checked copy
    // hides a reserved descriptor (as -1), so only it answers EBADF
    // with nothing delivered.
    assert_eq!(
        (&tool[3].delivered, &tool[3].lengths),
        (&native[3].delivered, &native[3].lengths),
        "case allowed vector: the Tool path differs from native"
    );
    assert_eq!(
        tool[3].results,
        [2_i64],
        "case allowed vector: the Tool path differs from native"
    );
    assert_eq!(
        reserved_result, EBADF,
        "case reserved descriptor: the runtime copy is not on the fallback path"
    );
    assert!(
        reserved_delivered.is_empty(),
        "case reserved descriptor: the runtime copy delivered a reserved descriptor"
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(site as *const u8, 3) },
        [0x0f, 0x05, 0xc3]
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
        0
    );
    // Six traps at the site in the Tool phase: the five cases (the
    // allowed vector is one call) plus the reserved
    // descriptor call.
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(site as u64),
        6
    );
    println!(
        "fallback scm pkeys: denied=matched allowed=matched vector=2 native=2 reserved=hidden read-only=matched traps=6 hooks=0"
    );
}

unsafe extern "C" {
    fn fallback_scm_pkey_call(
        site: usize,
        number: i64,
        a0: u64,
        a1: u64,
        a2: u64,
        pkru: u32,
    ) -> i64;
}

global_asm!(
    r#"
    .text
    .global fallback_scm_pkey_call
    .hidden fallback_scm_pkey_call
    .type fallback_scm_pkey_call,@function
fallback_scm_pkey_call:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
    xor ecx, ecx
    rdpkru
    push rax
    sub rsp, 8
    mov eax, r9d
    xor ecx, ecx
    xor edx, edx
    wrpkru
    mov rax, r13
    mov rdi, r14
    mov rsi, r15
    mov rdx, rbx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    call r12
    mov r13, rax
    add rsp, 8
    pop rax
    xor ecx, ecx
    xor edx, edx
    wrpkru
    mov rax, r13
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
    .size fallback_scm_pkey_call, .-fallback_scm_pkey_call
"#
);
