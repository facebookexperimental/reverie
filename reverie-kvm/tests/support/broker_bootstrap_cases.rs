//! Real bootstrap syscall-boundary controls for the ordinary-main launcher.
//! No filesystem class is fabricated. The filter affects this isolated process
//! and its children only; the existing outer 30s/kill2s bound is unchanged.
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

use reverie_kvm::native_exit_broker::AmbientClass;
use reverie_kvm::native_exit_broker::BrokerOwner;
use reverie_kvm::native_exit_broker::StartupAuthority;

#[derive(Clone, Copy)]
enum Case {
    Procfs,
    Memfd,
    Null,
    PathOnly,
}

pub fn run(name: &str) -> i32 {
    let case = match name {
        "procfs-reject" => Case::Procfs,
        "memfd-accept" => Case::Memfd,
        "null-accept" => Case::Null,
        "opath-procfs-accept" => Case::PathOnly,
        _ => {
            eprintln!("BROKER_BOOTSTRAP_CASE_SETUP_FAILURE: unknown case {name}");
            return 125;
        }
    };
    let fixture = match Fixture::new(case) {
        Ok(fixture) => fixture,
        Err(error) => {
            eprintln!("BROKER_BOOTSTRAP_CASE_SETUP_FAILURE: {error}");
            return 125;
        }
    };
    let fd = fixture.fd.as_raw_fd();
    let before = match snapshot(fd, fixture.prefix_len) {
        Ok(before) => before,
        Err(error) => {
            eprintln!("BROKER_BOOTSTRAP_CASE_SETUP_FAILURE: {error}");
            return 125;
        }
    };
    let mask = match signal_mask() {
        Ok(mask) => mask,
        Err(error) => {
            eprintln!("BROKER_BOOTSTRAP_CASE_SETUP_FAILURE: {error}");
            return 125;
        }
    };
    if !matches!(case, Case::Memfd | Case::Null)
        && let Err(error) = install_filter(fd, case)
    {
        eprintln!("BROKER_BOOTSTRAP_CASE_SETUP_FAILURE: {error}");
        return 125;
    }
    // Flush before entering the classifier. On the old ordering, a real target
    // fstat/newfstatat/statx kills this process with SIGSYS, even under its mask.
    println!("BROKER_BOOTSTRAP_QUERY_READY case={name}");
    if let Err(error) = std::io::Write::flush(&mut std::io::stdout()) {
        eprintln!("BROKER_BOOTSTRAP_CASE_SETUP_FAILURE: flush ready marker: {error}");
        return 125;
    }
    // SAFETY: this dedicated early launcher branch has created only its owned
    // test descriptors. No thread, guest, concurrent fd mutator or reaper exists;
    // all originals stay held and the original thread owns every actual wait.
    let authority = unsafe { StartupAuthority::assert_exclusive_early_launch() };
    let outcome = match BrokerOwner::bootstrap(authority) {
        Ok(mut owner) => {
            let class = owner
                .ambient_descriptors()
                .iter()
                .find(|entry| entry.fd == fd)
                .map(|entry| entry.class);
            let wait = match crate::settle_broker(&mut owner) {
                Ok(wait) => wait,
                Err(error) => {
                    eprintln!("BROKER_BOOTSTRAP_CASE_FAILURE: actual broker settlement: {error}");
                    crate::retain_for_outer_guard(owner);
                }
            };
            crate::print_broker_wait(wait);
            drop(owner);
            Ok(class)
        }
        Err(failure) => {
            if failure.child.is_some() || !failure.unexpected_rights.is_empty() {
                eprintln!("BROKER_BOOTSTRAP_CASE_FAILURE: unexpected retained owners: {failure:?}");
                crate::retain_for_outer_guard(failure);
            }
            assert!(
                failure.mask_restore_error.is_none(),
                "bootstrap mask restore failed"
            );
            assert_eq!(
                failure.descriptor,
                Some(fd),
                "failure must name the held original"
            );
            Err(failure.cause)
        }
    };
    // Complete cleanup precedes all semantic assertions on accepted paths.
    // The target remains owned through both these checks and the whole bootstrap.
    assert_eq!(signal_mask().expect("read restored mask"), mask);
    assert_eq!(
        snapshot(fd, fixture.prefix_len).expect("original remains live"),
        before
    );
    let expected = match case {
        Case::Procfs => {
            let error = outcome.expect_err("unproved procfs must be rejected");
            assert_eq!(error.errno, libc::EOPNOTSUPP);
            "rejected-eopnotsupp"
        }
        Case::Memfd => {
            assert_eq!(
                outcome.expect("real tmpfs memfd accepted"),
                Some(AmbientClass::TmpfsRegular)
            );
            "accepted-tmpfs"
        }
        Case::Null => {
            assert_eq!(
                outcome.expect("real null device accepted"),
                Some(AmbientClass::NullDevice)
            );
            "accepted-null"
        }
        Case::PathOnly => {
            assert_eq!(
                outcome.expect("O_PATH fast path accepted"),
                Some(AmbientClass::PathOnly)
            );
            "accepted-path-only"
        }
    };
    println!(
        "BROKER_BOOTSTRAP_CASE_PASS case={name} expected={expected} mask_restored=true original_live=true"
    );
    0
}

struct Fixture {
    fd: OwnedFd,
    prefix_len: Option<usize>,
}
impl Fixture {
    fn new(case: Case) -> Result<Self, String> {
        let raw = unsafe {
            match case {
                Case::Memfd => libc::syscall(
                    libc::SYS_memfd_create,
                    c"bootstrap-query-control".as_ptr(),
                    libc::MFD_CLOEXEC,
                ) as i32,
                Case::Null => libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC),
                Case::PathOnly => libc::open(
                    c"/proc/self/status".as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC,
                ),
                Case::Procfs => libc::open(
                    c"/proc/self/status".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                ),
            }
        };
        if raw < 0 {
            return Err(last("create held test descriptor"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let prefix_len = match case {
            Case::Memfd => {
                let bytes = b"bootstrap-original-bytes\n";
                let written = unsafe { libc::write(raw, bytes.as_ptr().cast(), bytes.len()) };
                if written != bytes.len() as isize {
                    return Err(last("write memfd sentinel"));
                }
                Some(bytes.len())
            }
            Case::Procfs => Some(5), // Stable "Name:" prefix, not changing counters.
            Case::Null | Case::PathOnly => None,
        };
        if prefix_len.is_some() && unsafe { libc::lseek(raw, 3, libc::SEEK_SET) } != 3 {
            return Err(last("set original seek position"));
        }
        Ok(Self { fd, prefix_len })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    flags: i32,
    descriptor_flags: i32,
    position: Option<i64>,
    prefix: Vec<u8>,
}
fn snapshot(fd: RawFd, prefix_len: Option<usize>) -> Result<Snapshot, String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || descriptor_flags < 0 {
        return Err(last("original descriptor flags"));
    }
    let mut prefix = vec![0; prefix_len.unwrap_or(0)];
    let position = if let Some(length) = prefix_len {
        let position = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if position < 0 {
            return Err(last("original seek position"));
        }
        if unsafe { libc::pread(fd, prefix.as_mut_ptr().cast(), length, 0) } != length as isize {
            return Err(last("original descriptor bytes"));
        }
        Some(position)
    } else {
        None
    };
    Ok(Snapshot {
        flags,
        descriptor_flags,
        position,
        prefix,
    })
}
fn signal_mask() -> Result<u64, String> {
    let mut mask = 0u64;
    let rc = unsafe {
        crate::raw(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK as usize,
            0,
            (&mut mask as *mut u64) as usize,
            8,
            0,
            0,
        )
    };
    if rc < 0 {
        Err(format!("read kernel signal mask errno={}", -rc))
    } else {
        Ok(mask)
    }
}
fn last(operation: &str) -> String {
    format!("{operation}: {}", std::io::Error::last_os_error())
}

fn install_filter(fd: RawFd, case: Case) -> Result<(), String> {
    const ALLOW: usize = 9;
    const KILL: usize = 10;
    const FILESYSTEM: usize = 11;
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |index: usize, k: u32, yes: usize, no: usize| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: (yes - index - 1) as u8,
        jf: (no - index - 1) as u8,
        k,
    };
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    let filesystem_action = match case {
        Case::PathOnly => libc::SECCOMP_RET_KILL_PROCESS,
        Case::Procfs => libc::SECCOMP_RET_ALLOW,
        Case::Memfd | Case::Null => unreachable!("accepted controls use actual ordinary queries"),
    };
    // x86_64 seccomp_data: syscall number at0, arch at4, args[0] low32 at16.
    // Kernel fd arguments use their low32 bits as well. No pathname/class is mocked.
    let filter = [
        stmt(load, 4),
        jump(1, 0xc000_003e, 2, KILL), // AUDIT_ARCH_X86_64
        stmt(load, 16),
        jump(3, fd as u32, 4, ALLOW),
        stmt(load, 0),
        jump(5, libc::SYS_fstat as u32, KILL, 6),
        jump(6, libc::SYS_newfstatat as u32, KILL, 7),
        jump(7, libc::SYS_statx as u32, KILL, 8),
        jump(8, libc::SYS_fstatfs as u32, FILESYSTEM, ALLOW),
        stmt(ret, libc::SECCOMP_RET_ALLOW),
        stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(ret, filesystem_action),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // The fail-before control deliberately dies with SIGSYS. Disable dumps in
    // this isolated helper so that the host's piped coredumper is not invoked.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(last("disable intentional negative-control core dump"));
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(last("test-only PR_SET_NO_NEW_PRIVS"));
    }
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        return Err(last("install actual target-fd seccomp boundary"));
    }
    Ok(())
}
