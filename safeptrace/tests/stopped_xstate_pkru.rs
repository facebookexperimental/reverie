/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */
//! Real stopped-child PKRU capture and complete opaque XState restoration.
//! A separate integration executable isolates the process-wide FPU-write ban.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeSet;
use std::io;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::time::Duration;
use std::time::Instant;

use safeptrace::Event;
use safeptrace::Options;
use safeptrace::Pid;
use safeptrace::Signal;
use safeptrace::Stopped;
use safeptrace::Wait;

const LIMIT: Duration = Duration::from_secs(3);
const EINTR: i64 = -(libc::EINTR as i64);

// This child uses raw syscalls and integer/stack-only code after raw fork:
// no allocation, Rust locks, formatting, errno access or unwinding.
unsafe fn raw(nr: i64, a: [u64; 6]) -> i64 {
    let result: i64;
    // SAFETY: each caller supplies its real kernel ABI operands. Memory effects
    // are retained; RCX/R11 are syscall-clobbered, no stack switch occurs.
    unsafe {
        core::arch::asm!(
            "syscall", inlateout("rax") nr => result,
            in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
            in("r10") a[3], in("r8") a[4], in("r9") a[5],
            lateout("rcx") _, lateout("r11") _, options(nostack),
        );
    }
    result
}
unsafe fn child_exit(code: u64) -> ! {
    // SAFETY: terminate this real fork child without libc/atexit/destructors.
    unsafe {
        raw(libc::SYS_exit_group, [code, 0, 0, 0, 0, 0]);
    }
    // The real exit syscall cannot return; a refusal is a child failure.
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}
unsafe fn child_pkru() -> u32 {
    let value: u32;
    // SAFETY: parent checked enabled PKU/OSPKE before fork on this one CPU.
    // This is the actual child's register, never the parent's PKRU substitute.
    unsafe {
        core::arch::asm!("rdpkru", in("ecx") 0_u32, lateout("eax") value,
            lateout("edx") _, options(nomem, nostack, preserves_flags));
    }
    value
}
unsafe fn child_report(fd: i32, words: &[u64; 8]) {
    // A complete report fits PIPE_BUF; nonblocking pipe has room for both
    // reports. EINTR repeats only the interrupted transport operation.
    loop {
        let result = unsafe {
            raw(
                libc::SYS_write,
                [
                    fd as u64,
                    words.as_ptr() as u64,
                    size_of::<[u64; 8]>() as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if result == EINTR {
            continue;
        }
        if result != size_of::<[u64; 8]>() as i64 {
            unsafe {
                child_exit(91);
            }
        }
        break;
    }
}
unsafe fn child(fd: i32, parent: i32, cpu: usize, xcr0: u64) -> ! {
    // Cover the interval before PTRACE_O_EXITKILL is installed. getppid closes
    // the death-before-prctl race; this child cannot survive its creating owner.
    if unsafe {
        raw(
            libc::SYS_prctl,
            [
                libc::PR_SET_PDEATHSIG as u64,
                libc::SIGKILL as u64,
                0,
                0,
                0,
                0,
            ],
        )
    } != 0
        || unsafe { raw(libc::SYS_getppid, [0; 6]) } != i64::from(parent)
        || unsafe {
            raw(
                libc::SYS_ptrace,
                [libc::PTRACE_TRACEME as u64, 0, 0, 0, 0, 0],
            )
        } != 0
    {
        unsafe {
            child_exit(92);
        }
    }
    // A newly allocated key is not assigned to any mapping by pkey_alloc.
    // Parent additionally checks actual stopped-child smaps before mutation.
    let key = unsafe { raw(libc::SYS_pkey_alloc, [0; 6]) };
    if !(1..16).contains(&key) {
        unsafe {
            child_exit(93);
        }
    }
    let original = unsafe { child_pkru() };
    let changed = original ^ (1_u32 << (2 * key as u32 + 1));
    let mut actual_cpu = 0_u32;
    if unsafe {
        raw(
            libc::SYS_getcpu,
            [(&raw mut actual_cpu) as u64, 0, 0, 0, 0, 0],
        )
    } != 0
        || actual_cpu as usize != cpu
        || unsafe { core::arch::x86_64::_xgetbv(0) } != xcr0
    {
        unsafe {
            child_exit(94);
        }
    }
    unsafe {
        child_report(
            fd,
            &[
                1,
                key as u64,
                original as u64,
                changed as u64,
                actual_cpu as u64,
                xcr0,
                0,
                0,
            ],
        );
    }
    // Prepare every input before the baseline stop. One assembly block keeps
    // compiler-generated FP/SIMD preparation out of the interval whose whole
    // XState is captured and restored at the second stop.
    unsafe {
        core::arch::asm!("int3", "wrpkru", "int3", in("eax") changed,
            in("ecx") 0_u32, in("edx") 0_u32, options(nostack));
    }
    let restored = unsafe { child_pkru() };
    if unsafe {
        raw(
            libc::SYS_getcpu,
            [(&raw mut actual_cpu) as u64, 0, 0, 0, 0, 0],
        )
    } != 0
        || actual_cpu as usize != cpu
        || unsafe { core::arch::x86_64::_xgetbv(0) } != xcr0
    {
        unsafe {
            child_exit(95);
        }
    }
    unsafe {
        child_report(
            fd,
            &[
                2,
                key as u64,
                restored as u64,
                original as u64,
                actual_cpu as u64,
                xcr0,
                0,
                0,
            ],
        );
    }
    if restored != original {
        unsafe {
            child_exit(96);
        }
    }
    if unsafe { raw(libc::SYS_pkey_free, [key as u64, 0, 0, 0, 0, 0]) } != 0 {
        unsafe {
            child_exit(97);
        }
    }
    unsafe {
        child_exit(0);
    }
}

struct Affinity {
    original: libc::cpu_set_t,
    cpu: usize,
    restored: bool,
}
impl Affinity {
    fn pin() -> io::Result<Self> {
        let mut original = MaybeUninit::<libc::cpu_set_t>::zeroed();
        if unsafe {
            libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), original.as_mut_ptr())
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let original = unsafe { original.assume_init() };
        let cpu = (0..libc::CPU_SETSIZE as usize)
            .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &original) })
            .ok_or_else(|| io::Error::other("empty actual CPU affinity"))?;
        let mut one = unsafe { MaybeUninit::<libc::cpu_set_t>::zeroed().assume_init() };
        unsafe {
            libc::CPU_SET(cpu, &mut one);
        }
        if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &one) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            original,
            cpu,
            restored: false,
        })
    }
    fn check(&self, pid: i32) -> io::Result<()> {
        let mut actual = MaybeUninit::<libc::cpu_set_t>::zeroed();
        if unsafe {
            libc::sched_getaffinity(pid, size_of::<libc::cpu_set_t>(), actual.as_mut_ptr())
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual = unsafe { actual.assume_init() };
        assert_eq!(unsafe { libc::CPU_COUNT(&actual) }, 1);
        assert!(unsafe { libc::CPU_ISSET(self.cpu, &actual) });
        assert_eq!(unsafe { libc::sched_getcpu() }, self.cpu as i32);
        Ok(())
    }
    fn restore(&mut self) -> io::Result<()> {
        if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &self.original) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for Affinity {
    fn drop(&mut self) {
        if !self.restored {
            // On an unwinding/error path still restore the real parent mask.
            // Explicit success path checks restoration and reports its failure.
            unsafe {
                libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &self.original);
            }
        }
    }
}

// Exclusive real-parent ownership is held from raw fork until terminal reap.
// Unreaped child PID cannot be reused; no external reaper/thread sees this PID.
struct ChildOwner {
    pid: i32,
    reaped: bool,
}
impl ChildOwner {
    fn status(&mut self) -> io::Result<i32> {
        let deadline = Instant::now() + LIMIT;
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.reaped = true;
                }
                return Ok(status);
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("child stop/exit deadline"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn stopped(&mut self) -> Result<Stopped, Box<dyn std::error::Error>> {
        let status = self.status()?;
        assert!(
            libc::WIFSTOPPED(status),
            "child did not reach actual int3: {status:#x}"
        );
        let (stopped, event) = Wait::from_raw(Pid::from_raw(self.pid), status)?.assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGTRAP));
        Ok(stopped)
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if !self.reaped {
            // This is our unreaped real fork child, never an unowned numeric TID.
            // EXITKILL and PDEATHSIG also cover abrupt parent/outer-guard death.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            }
            loop {
                let mut status = 0;
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        self.reaped = true;
                        break;
                    }
                    // No TRACEEXIT option is selected. Forward SIGKILL should
                    // an unexpected ptrace stop still be observed in cleanup.
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_CONT,
                            self.pid,
                            std::ptr::null_mut::<libc::c_void>(),
                            libc::SIGKILL as usize as *mut libc::c_void,
                        );
                    }
                } else if result == -1 {
                    match io::Error::last_os_error().raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::ECHILD) => {
                            self.reaped = true;
                            break;
                        }
                        // Do not silently abandon a possibly live child on an
                        // impossible wait error. PDEATHSIG/EXITKILL remain live.
                        _ => std::process::abort(),
                    }
                }
            }
        }
    }
}
fn report(fd: i32) -> io::Result<[u64; 8]> {
    let mut words = [0_u64; 8];
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), size_of::<[u64; 8]>())
    };
    let deadline = Instant::now() + LIMIT;
    let mut offset = 0;
    while offset < bytes.len() {
        let result = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if result > 0 {
            offset += result as usize;
            continue;
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short child report",
            ));
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("child report deadline"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(words)
}
fn mapped_keys(pid: i32) -> io::Result<BTreeSet<u32>> {
    let smaps = std::fs::read_to_string(format!("/proc/{pid}/smaps"))?;
    let mut keys = BTreeSet::new();
    let mut maps = 0;
    let mut fields = 0;
    for line in smaps.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        if first.split_once('-').is_some_and(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_hexdigit())
        }) {
            maps += 1;
        }
        if let Some(value) = line.strip_prefix("ProtectionKey:") {
            fields += 1;
            keys.insert(value.trim().parse().map_err(io::Error::other)?);
        }
    }
    assert!(maps > 0, "no actual child VMA ledger");
    assert_eq!(
        maps, fields,
        "every actual VMA requires a ProtectionKey observation"
    );
    Ok(keys)
}

#[test]
#[ignore = "requires x86_64 PKU/OSPKE, enabled XSAVE PKRU, kernel pkey/ptrace and readable child smaps; execute explicitly with --ignored"]
fn stopped_child_pkru_projection_and_complete_xstate_restore()
-> Result<(), Box<dyn std::error::Error>> {
    let mut affinity = Affinity::pin()?;
    affinity.check(0)?;
    let cpu = affinity.cpu;
    assert!(
        core::arch::x86_64::__cpuid(0).eax >= 0xd,
        "XSAVE CPUID required"
    );
    assert_eq!(
        core::arch::x86_64::__cpuid(1).ecx & ((1 << 26) | (1 << 27)),
        (1 << 26) | (1 << 27)
    );
    assert_eq!(
        core::arch::x86_64::__cpuid_count(7, 0).ecx & ((1 << 3) | (1 << 4)),
        (1 << 3) | (1 << 4)
    );
    let xcr0 = unsafe { core::arch::x86_64::_xgetbv(0) };
    assert_ne!(xcr0 & (1 << 9), 0, "PKRU must be enabled in XCR0");
    assert!(
        !safeptrace::fpu_register_writes_forbidden(),
        "must run in isolated integration binary"
    );
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let parent = unsafe { libc::getpid() };
    let pid = unsafe { raw(libc::SYS_fork, [0; 6]) };
    if pid < 0 {
        return Err(io::Error::from_raw_os_error((-pid) as i32).into());
    }
    if pid == 0 {
        unsafe {
            raw(libc::SYS_close, [read.as_raw_fd() as u64, 0, 0, 0, 0, 0]);
        }
        unsafe {
            child(write.as_raw_fd(), parent, cpu, xcr0);
        }
    }
    // Linux fork returns a positive pid_t (signed 32-bit); install the owner
    // before any fallible parent operation after fork.
    let mut owner = ChildOwner {
        pid: pid as i32,
        reaped: false,
    };
    drop(write);
    let stopped = owner.stopped()?;
    stopped.setoptions(Options::PTRACE_O_EXITKILL)?;
    affinity.check(owner.pid)?;
    let first = report(read.as_raw_fd())?;
    assert_eq!(first[0], 1);
    assert!((1..16).contains(&first[1]));
    let original_pkru = u32::try_from(first[2])?;
    let changed_pkru = u32::try_from(first[3])?;
    assert_eq!(
        changed_pkru,
        original_pkru ^ (1_u32 << (2 * first[1] as u32 + 1))
    );
    assert_ne!(changed_pkru, original_pkru);
    assert_eq!(
        (first[4], first[5], first[6], first[7]),
        (cpu as u64, xcr0, 0, 0)
    );
    assert!(
        !mapped_keys(owner.pid)?.contains(&(first[1] as u32)),
        "allocated key tags an existing child VMA"
    );
    let original = stopped.getxstate()?;
    // SAFETY: this exact stopped child and parent are pinned to the same actual
    // CPU; child reports matching XCR0; no migration or layout mutation occurs.
    assert_eq!(unsafe { original.pkru()? }, original_pkru);
    let _running = stopped.resume(None)?;
    let stopped = owner.stopped()?;
    affinity.check(owner.pid)?;
    let changed = stopped.getxstate()?;
    assert_eq!(unsafe { changed.pkru()? }, changed_pkru);
    assert_ne!(
        changed, original,
        "actual opaque captured state must change"
    );
    stopped.setxstate(&original)?;
    let readback = stopped.getxstate()?;
    assert_eq!(
        readback, original,
        "complete opaque original must read back unchanged"
    );
    assert_eq!(unsafe { readback.pkru()? }, original_pkru);
    let _running = stopped.resume(None)?;
    let status = owner.status()?;
    assert!(libc::WIFEXITED(status), "child final status: {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), 0);
    let last = report(read.as_raw_fd())?;
    assert_eq!(
        last,
        [
            2,
            first[1],
            original_pkru as u64,
            original_pkru as u64,
            cpu as u64,
            xcr0,
            0,
            0
        ],
        "child RDPKRU must confirm actual restoration"
    );
    affinity.check(0)?;
    affinity.restore()?;
    eprintln!(
        "STOPPED_PKRU_CONTROL child={pid} cpu={cpu} pkey={} original={original_pkru:#x} changed={changed_pkru:#x} child_restored={:#x} full_xstate_equal=true",
        first[1], last[2]
    );
    Ok(())
}
