/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(target_env = "gnu")]
use std::io::Write;
#[cfg(target_env = "gnu")]
use std::os::fd::AsRawFd;
#[cfg(target_env = "gnu")]
use std::os::fd::FromRawFd;
#[cfg(target_env = "gnu")]
use std::thread;
#[cfg(target_env = "gnu")]
use std::time::Duration;
#[cfg(target_env = "gnu")]
use std::time::Instant;

#[cfg(target_env = "gnu")]
use nix::errno::Errno;
#[cfg(target_env = "gnu")]
use nix::sys::ptrace;
#[cfg(target_env = "gnu")]
use nix::sys::signal::Signal;
#[cfg(target_env = "gnu")]
use nix::sys::signal::kill;
#[cfg(target_env = "gnu")]
use nix::sys::wait::WaitPidFlag;
#[cfg(target_env = "gnu")]
use nix::sys::wait::WaitStatus;
#[cfg(target_env = "gnu")]
use nix::sys::wait::waitpid;
#[cfg(target_env = "gnu")]
use nix::unistd::ForkResult;
#[cfg(target_env = "gnu")]
use nix::unistd::Pid;
#[cfg(target_env = "gnu")]
use nix::unistd::fork;

use super::*;

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn elf_header(bytes: &mut [u8], kind: u16, count: u16) {
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(bytes, 16, kind);
    put16(bytes, 18, header::EM_X86_64);
    put32(bytes, 20, 1);
    put64(bytes, 32, 64);
    put16(bytes, 52, 64);
    put16(bytes, 54, 56);
    put16(bytes, 56, count);
}

fn phdr(
    bytes: &mut [u8],
    index: usize,
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    size: u64,
) {
    let at = 64 + index * 56;
    put32(bytes, at, kind);
    put32(bytes, at + 4, flags);
    put64(bytes, at + 8, offset);
    put64(bytes, at + 16, address);
    put64(bytes, at + 32, size);
    put64(bytes, at + 40, size);
    put64(bytes, at + 48, 8);
}

fn runtime() -> Vec<u8> {
    let mut bytes = vec![0; 0x3000];
    elf_header(&mut bytes, header::ET_DYN, 4);
    phdr(&mut bytes, 0, ph::PT_LOAD, ph::PF_R, 0, 0, 0x1000);
    phdr(
        &mut bytes,
        1,
        ph::PT_LOAD,
        ph::PF_R | ph::PF_X,
        0x1000,
        0x1000,
        0x1000,
    );
    phdr(
        &mut bytes,
        2,
        ph::PT_LOAD,
        ph::PF_R | ph::PF_W,
        0x2000,
        0x2000,
        0x1000,
    );

    let strings = b"\0reverie_liteinst_initialize_host\0";
    bytes[0x500..0x500 + strings.len()].copy_from_slice(strings);
    put32(&mut bytes, 0x618, 1);
    bytes[0x61c] = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
    put16(&mut bytes, 0x61e, 1);
    put64(&mut bytes, 0x620, 0x1100);
    put64(&mut bytes, 0x628, 16);
    for (index, value) in [1, 2, 1, 0, 0].into_iter().enumerate() {
        put32(&mut bytes, 0x700 + index * 4, value);
    }
    put16(&mut bytes, 0x742, 1);
    bytes[0x1100..0x1110].fill(0x90);
    bytes[0x110f] = 0xc3;

    let tags = [
        (dynamic::DT_STRTAB, 0x500),
        (dynamic::DT_STRSZ, strings.len() as u64),
        (dynamic::DT_SYMTAB, 0x600),
        (dynamic::DT_SYMENT, 24),
        (dynamic::DT_HASH, 0x700),
        (dynamic::DT_VERSYM, 0x740),
        (dynamic::DT_NULL, 0),
    ];
    phdr(
        &mut bytes,
        3,
        ph::PT_DYNAMIC,
        ph::PF_R | ph::PF_W,
        0x2100,
        0x2100,
        (tags.len() * 16) as u64,
    );
    for (index, (tag, value)) in tags.into_iter().enumerate() {
        put64(&mut bytes, 0x2100 + index * 16, tag);
        put64(&mut bytes, 0x2108 + index * 16, value);
    }
    bytes
}

fn runtime_with_gnu_hash(keep_sysv: bool) -> Vec<u8> {
    let mut bytes = runtime();
    let hash = gnu_hash(INITIALIZER.as_bytes());
    put32(&mut bytes, 0x780, 1);
    put32(&mut bytes, 0x784, 1);
    put32(&mut bytes, 0x788, 1);
    put32(&mut bytes, 0x78c, 5);
    put64(
        &mut bytes,
        0x790,
        1_u64 << (hash & 63) | 1_u64 << ((hash >> 5) & 63),
    );
    put32(&mut bytes, 0x798, 1);
    put32(&mut bytes, 0x79c, hash | 1);

    let index = if keep_sysv { 6 } else { 4 };
    put64(&mut bytes, 0x2100 + index * 16, dynamic::DT_GNU_HASH);
    put64(&mut bytes, 0x2108 + index * 16, 0x780);
    if keep_sysv {
        put64(&mut bytes, 0x2170, dynamic::DT_NULL);
        put64(&mut bytes, 0x2178, 0);
        put64(&mut bytes, 64 + 3 * 56 + 32, 8 * 16);
        put64(&mut bytes, 64 + 3 * 56 + 40, 8 * 16);
    }
    bytes
}

fn runtime_with_gnu_coverage_hole() -> Vec<u8> {
    let mut bytes = runtime_with_gnu_hash(true);
    let strings = b"\0reverie_liteinst_initialize_host\0tail\0";
    bytes[0x500..0x500 + strings.len()].copy_from_slice(strings);
    put64(&mut bytes, 0x2118, strings.len() as u64);

    bytes.copy_within(0x618..0x630, 0x630);
    put32(&mut bytes, 0x618, 34);
    put64(&mut bytes, 0x620, 0x1120);
    bytes[0x1120..0x1130].fill(0x90);
    bytes[0x112f] = 0xc3;

    // SysV defines and reaches all three symbols. GNU starts and terminates at
    // the selected initializer at index 2, leaving only index 1 uncovered.
    put32(&mut bytes, 0x704, 3);
    put32(&mut bytes, 0x710, 2);
    put32(&mut bytes, 0x714, 0);
    put16(&mut bytes, 0x744, 1);
    put32(&mut bytes, 0x798, 2);
    put32(&mut bytes, 0x79c, 0);
    put32(&mut bytes, 0x7a0, gnu_hash(INITIALIZER.as_bytes()) | 1);
    bytes
}

fn assert_invalid(bytes: &[u8], message: &str) {
    let error = match parse_runtime(bytes) {
        Ok(_) => panic!("runtime unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), message);
}

fn append_runtime_load(
    bytes: &mut [u8],
    index: usize,
    flags: u32,
    offset: u64,
    address: u64,
    size: u64,
) {
    put16(bytes, 56, (index + 1) as u16);
    phdr(bytes, index, ph::PT_LOAD, flags, offset, address, size);
}

fn resolve_synthetic_runtime(
    target_runtime: &[u8],
    expected_runtime: &[u8],
) -> io::Result<TargetDlopen> {
    let mut main = vec![0; 0x2000];
    elf_header(&mut main, header::ET_EXEC, 4);
    phdr(&mut main, 0, ph::PT_LOAD, ph::PF_R, 0, 0x400000, 0x1000);
    phdr(&mut main, 1, ph::PT_PHDR, ph::PF_R, 64, 0x400040, 4 * 56);
    phdr(
        &mut main,
        2,
        ph::PT_LOAD,
        ph::PF_R | ph::PF_W,
        0x1000,
        0x401000,
        0x1000,
    );
    phdr(
        &mut main,
        3,
        ph::PT_DYNAMIC,
        ph::PF_R | ph::PF_W,
        0x1000,
        0x401000,
        32,
    );
    put64(&mut main, 0x1000, dynamic::DT_DEBUG);
    put64(&mut main, 0x1008, 0x900000);

    let mut interpreter = vec![0; 0x1000];
    elf_header(&mut interpreter, header::ET_DYN, 0);
    let mut links = vec![0; 0x1000];
    put32(&mut links, 0, 1);
    put64(&mut links, 8, 0x900100);
    put64(&mut links, 16, 0x800100);
    put64(&mut links, 32, 0x800000);
    put64(&mut links, 0x110, 0x401000);
    put64(&mut links, 0x118, 0x900140);
    put64(&mut links, 0x140, 0x700000);
    put64(&mut links, 0x150, 0x702100);
    put64(&mut links, 0x160, 0x900100);

    let maps = parse_maps(
        b"400000-401000 r--p 0 00:01 1 /main\n\
          401000-402000 rw-p 1000 00:01 1 /main\n\
          700000-701000 r--p 0 00:02 2 /runtime\n\
          701000-702000 r-xp 1000 00:02 2 /runtime\n\
          702000-703000 rw-p 2000 00:02 2 /runtime\n\
          800000-801000 r-xp 0 00:03 3 /loader\n\
          900000-901000 rw-p 0 00:00 0\n",
    )?;
    let regions = [
        (0x400000, main),
        (0x700000, target_runtime.to_vec()),
        (0x800000, interpreter),
        (0x900000, links),
    ];
    let aux = BTreeMap::from([
        (libc::AT_PHDR, 0x400040),
        (libc::AT_PHNUM, 4),
        (libc::AT_PHENT, 56),
        (libc::AT_BASE, 0x800000),
    ]);
    let provider = parse_runtime(expected_runtime)?;
    let mut memory = Memory::new(&maps, |address, bytes: &mut [u8]| {
        for (base, region) in &regions {
            if address >= *base
                && address
                    .checked_add(bytes.len() as u64)
                    .is_some_and(|end| end <= base + region.len() as u64)
            {
                let offset = (address - base) as usize;
                bytes.copy_from_slice(&region[offset..offset + bytes.len()]);
                return Ok(());
            }
        }
        Err(invalid("synthetic target read outside region"))
    });
    resolve(&mut memory, &aux, &provider)
}

#[cfg(target_env = "gnu")]
struct TracedChild(Option<Pid>);

#[cfg(target_env = "gnu")]
impl TracedChild {
    fn new(pid: Pid) -> Self {
        Self(Some(pid))
    }

    fn pid(&self) -> Pid {
        self.0.unwrap()
    }

    fn wait_bounded(&mut self) -> Result<WaitStatus, Errno> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match waitpid(self.pid(), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Ok(WaitStatus::StillAlive) => return Err(Errno::ETIMEDOUT),
                Ok(status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => {
                    self.0 = None;
                    return Ok(status);
                }
                Err(Errno::ECHILD) => {
                    self.0 = None;
                    return Err(Errno::ECHILD);
                }
                Err(Errno::EINTR) => {}
                result => return result,
            }
        }
    }

    fn resume_and_reap(mut self) -> Result<WaitStatus, Errno> {
        ptrace::cont(self.pid(), None)?;
        self.wait_bounded()
    }
}

#[cfg(target_env = "gnu")]
impl Drop for TracedChild {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = kill(pid, Signal::SIGKILL);
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(Errno::ECHILD) => {
                        break;
                    }
                    Ok(
                        WaitStatus::Stopped(..)
                        | WaitStatus::PtraceEvent(..)
                        | WaitStatus::PtraceSyscall(..),
                    ) => {
                        let _ = ptrace::cont(pid, None);
                    }
                    Ok(WaitStatus::StillAlive | WaitStatus::Continued(..)) | Err(Errno::EINTR) => {}
                    Err(_) => break,
                }
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

#[test]
fn accepts_exact_ordinary_unversioned_initializer_with_or_without_versym() {
    let bytes = runtime();
    let provider = parse_runtime(&bytes).unwrap();
    assert_eq!(provider.symbol.st_value, 0x1100);
    assert_eq!(provider.version, "unversioned");

    assert!(parse_runtime(&runtime_with_gnu_hash(false)).is_ok());
    assert!(parse_runtime(&runtime_with_gnu_hash(true)).is_ok());

    let mut without_versions = bytes;
    put64(&mut without_versions, 0x2150, dynamic::DT_NULL);
    assert!(parse_runtime(&without_versions).is_ok());
}

#[test]
fn ordinary_provider_composes_with_link_map_resolution_and_exact_bytes() {
    let target = runtime();
    assert_eq!(
        resolve_synthetic_runtime(&target, &target).unwrap(),
        TargetDlopen {
            tid: 0,
            start_ticks: 0,
            executable_phdr: 0x400040,
            link_map: 0x900140,
            load_bias: 0x700000,
            address: 0x701100,
            version: "unversioned".to_owned(),
            mapping_identity: (0, 2, 2),
        }
    );

    let mut mismatched = target.clone();
    mismatched[0x1100] ^= 1;
    assert!(resolve_synthetic_runtime(&target, &mismatched).is_err());
}

#[test]
#[cfg(target_env = "gnu")]
fn resolves_generated_runtime_for_real_stopped_tracee() {
    let mut bytes = runtime();
    for index in 0..3 {
        put64(&mut bytes, 64 + index * 56 + 48, 4096);
    }
    let fd = unsafe { libc::memfd_create(c"reverie-runtime-test".as_ptr(), libc::MFD_CLOEXEC) };
    assert_ne!(fd, -1);
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&bytes).unwrap();
    let path = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let error = unsafe { libc::dlerror() };
        let message = if error.is_null() {
            "unknown dlopen error".into()
        } else {
            unsafe { std::ffi::CStr::from_ptr(error) }.to_string_lossy()
        };
        panic!("failed to load generated runtime: {message}");
    }
    let address = unsafe { libc::dlsym(handle, c"reverie_liteinst_initialize_host".as_ptr()) };
    assert!(!address.is_null());
    let address = address as usize as u64;
    let mut link_map = std::ptr::null_mut::<libc::c_void>();
    assert_eq!(
        unsafe {
            libc::dlinfo(
                handle,
                libc::RTLD_DI_LINKMAP,
                std::ptr::addr_of_mut!(link_map).cast(),
            )
        },
        0
    );
    assert!(!link_map.is_null());
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::uninit();
    assert_ne!(
        unsafe { libc::dladdr(address as usize as *const _, info.as_mut_ptr()) },
        0
    );
    let load_bias = unsafe { info.assume_init() }.dli_fbase as usize as u64;
    let expected_phdr = unsafe { libc::getauxval(libc::AT_PHDR) };
    assert_ne!(expected_phdr, 0);
    let mapping = procfs::process::Process::myself()
        .unwrap()
        .maps()
        .unwrap()
        .into_iter()
        .find(|mapping| mapping.address.0 <= address && address < mapping.address.1)
        .unwrap();
    let expected_identity = (mapping.dev.0 as u64, mapping.dev.1 as u64, mapping.inode);

    match unsafe { fork() }.unwrap() {
        ForkResult::Child => {
            let trace = unsafe {
                libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };
            if trace == -1 || unsafe { libc::raise(libc::SIGSTOP) } != 0 {
                unsafe { libc::_exit(125) };
            }
            unsafe { libc::_exit(0) };
        }
        ForkResult::Parent { child } => {
            let mut child = TracedChild::new(child);
            let status = child.wait_bounded().unwrap();
            let (stopped, event) = safeptrace::Wait::try_from(status).unwrap().assume_stopped();
            assert_eq!(event, safeptrace::Event::Signal(Signal::SIGSTOP));
            assert_eq!(stopped.pid().as_raw(), child.pid().as_raw());
            stopped
                .setoptions(ptrace::Options::PTRACE_O_EXITKILL)
                .unwrap();
            let process = procfs::process::Process::new(child.pid().as_raw()).unwrap();
            let tasks = process
                .tasks()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(tasks.len(), 1, "test tracee must have one quiescent task");
            let expected_start_ticks = process.stat().unwrap().starttime;
            let result = resolve_host_initializer(&stopped, &bytes);

            let pid = child.pid();
            drop(stopped);
            assert_eq!(child.resume_and_reap().unwrap(), WaitStatus::Exited(pid, 0));

            let resolved = result.unwrap();
            assert_eq!(resolved.tid, pid.as_raw());
            assert_eq!(resolved.start_ticks, expected_start_ticks);
            assert_eq!(resolved.executable_phdr, expected_phdr);
            assert_eq!(resolved.link_map, link_map as usize as u64);
            assert_eq!(resolved.load_bias, load_bias);
            assert_eq!(resolved.address, address);
            assert_eq!(resolved.mapping_identity, expected_identity);
        }
    }
    // Keep this node stable for other fork-based tests in this test process.
    std::mem::forget(file);
}

#[test]
fn runtime_parser_rejects_unused_unreadable_and_incompatible_page_loads() {
    let mut readable_extra = runtime();
    append_runtime_load(&mut readable_extra, 4, ph::PF_R, 0, 0x4000, 0x100);
    assert!(parse_runtime(&readable_extra).is_ok());

    for flags in [0, ph::PF_X] {
        let mut unreadable_extra = runtime();
        append_runtime_load(&mut unreadable_extra, 4, flags, 0, 0x4000, 0x100);
        assert!(parse_runtime(&unreadable_extra).is_err());
    }

    let mut incongruent_extra = runtime();
    append_runtime_load(&mut incongruent_extra, 4, ph::PF_R, 0x100, 0x4000, 0x100);
    assert!(parse_runtime(&incongruent_extra).is_err());

    let mut compatible_shared_page = runtime();
    append_runtime_load(&mut compatible_shared_page, 4, ph::PF_R, 0, 0x4000, 0x800);
    append_runtime_load(
        &mut compatible_shared_page,
        5,
        ph::PF_R,
        0x800,
        0x4800,
        0x100,
    );
    assert!(parse_runtime(&compatible_shared_page).is_ok());

    let mut incompatible_projection = compatible_shared_page.clone();
    put64(&mut incompatible_projection, 64 + 5 * 56 + 8, 0x1800);
    assert!(parse_runtime(&incompatible_projection).is_err());

    let mut incompatible_permissions = compatible_shared_page;
    put32(
        &mut incompatible_permissions,
        64 + 5 * 56 + 4,
        ph::PF_R | ph::PF_X,
    );
    assert!(parse_runtime(&incompatible_permissions).is_err());
}

#[test]
fn refuses_versioned_hidden_local_ifunc_object_weak_undefined_and_reserved_exports() {
    for (offset, value) in [
        (0x742, 2),
        (0x743, 0x80),
        (0x61c, (sym::STB_GLOBAL << 4) | sym::STT_GNU_IFUNC),
        (0x61c, (sym::STB_GLOBAL << 4) | sym::STT_OBJECT),
        (0x61c, (sym::STB_WEAK << 4) | sym::STT_FUNC),
        (0x61c, sym::STT_FUNC),
        (0x61d, sym::STV_HIDDEN),
        (0x61e, 0),
        (0x61f, 0xff),
    ] {
        let mut bytes = runtime();
        bytes[offset] = value;
        assert!(
            parse_runtime(&bytes).is_err(),
            "offset {offset:#x} value {value}"
        );
    }
}

#[test]
fn refuses_duplicate_named_initializer_even_when_both_are_ordinary() {
    let mut bytes = runtime();
    bytes.copy_within(0x618..0x630, 0x630);
    put32(&mut bytes, 0x704, 3);
    put32(&mut bytes, 0x710, 2);
    put16(&mut bytes, 0x744, 1);
    assert_invalid(&bytes, "ambiguous ordinary initializer");
}

#[test]
fn refuses_gnu_hash_that_does_not_cover_every_symbol() {
    assert_invalid(
        &runtime_with_gnu_coverage_hole(),
        "malformed runtime GNU hash table",
    );
}

#[test]
fn refuses_missing_initializer_and_invalid_extent_or_executable_mapping() {
    let mut absent = runtime();
    absent[0x501] = b'x';
    assert!(parse_runtime(&absent).is_err());
    for (at, value) in [
        (0x628, 0),
        (0x628, 1024 * 1024 + 1),
        (0x620, 0x2000),
        (0x620, u64::MAX - 1),
        (0x628, 0x1000),
    ] {
        let mut bytes = runtime();
        put64(&mut bytes, at, value);
        assert!(parse_runtime(&bytes).is_err());
    }
    let mut writable = runtime();
    put32(&mut writable, 64 + 56 + 4, ph::PF_R | ph::PF_W | ph::PF_X);
    assert!(parse_runtime(&writable).is_err());
}

#[test]
fn refuses_duplicate_dynamic_metadata_and_raw_symbol_metadata_outside_ro_load() {
    let mut duplicate = runtime();
    put64(&mut duplicate, 0x2150, dynamic::DT_SYMENT);
    assert!(parse_runtime(&duplicate).is_err());

    let mut writable = runtime();
    put64(&mut writable, 0x2128, 0x2400);
    assert!(parse_runtime(&writable).is_err());

    let mut wrong_width = runtime();
    put64(&mut wrong_width, 0x2138, 16);
    assert!(parse_runtime(&wrong_width).is_err());

    let mut textrel = runtime();
    put64(&mut textrel, 0x2150, dynamic::DT_TEXTREL);
    assert!(parse_runtime(&textrel).is_err());

    let mut missing_hash = runtime();
    put64(&mut missing_hash, 0x2140, dynamic::DT_NULL);
    assert_invalid(&missing_hash, "missing runtime symbol hash table");

    let mut unreachable_sysv = runtime();
    put32(&mut unreachable_sysv, 0x708, 0);
    assert_invalid(
        &unreachable_sysv,
        "initializer is unreachable from runtime SysV hash",
    );

    let mut malformed_sysv = runtime();
    put32(&mut malformed_sysv, 0x708, 2);
    assert_invalid(&malformed_sysv, "malformed runtime SysV hash table");

    let mut cyclic_sysv = runtime();
    put32(&mut cyclic_sysv, 0x710, 1);
    assert_invalid(&cyclic_sysv, "malformed runtime SysV hash table");

    let mut wrong_sysv_bucket = runtime();
    put32(&mut wrong_sysv_bucket, 0x700, 2);
    put32(&mut wrong_sysv_bucket, 0x708, 0);
    put32(&mut wrong_sysv_bucket, 0x70c, 0);
    put32(&mut wrong_sysv_bucket, 0x710, 0);
    put32(&mut wrong_sysv_bucket, 0x714, 0);
    let wrong_bucket = 1 - elf_hash(INITIALIZER.as_bytes()) as usize % 2;
    put32(&mut wrong_sysv_bucket, 0x708 + wrong_bucket * 4, 1);
    assert_invalid(
        &wrong_sysv_bucket,
        "runtime SysV hash table disagrees with symbols",
    );

    let mut writable_sysv = runtime();
    writable_sysv.copy_within(0x700..0x714, 0x2700);
    put64(&mut writable_sysv, 0x2148, 0x2700);
    assert_invalid(
        &writable_sysv,
        "ELF range is not in required readable load bytes",
    );

    let mut disagreeing_gnu = runtime_with_gnu_hash(false);
    put32(
        &mut disagreeing_gnu,
        0x79c,
        gnu_hash(INITIALIZER.as_bytes()) ^ 2 | 1,
    );
    assert_invalid(
        &disagreeing_gnu,
        "runtime GNU hash table disagrees with symbols",
    );

    let mut missing_gnu_bloom = runtime_with_gnu_hash(false);
    put64(&mut missing_gnu_bloom, 0x790, 0);
    assert_invalid(
        &missing_gnu_bloom,
        "runtime GNU hash table disagrees with symbols",
    );

    let mut wrong_gnu_bucket = runtime_with_gnu_hash(false);
    let hash = gnu_hash(INITIALIZER.as_bytes());
    put32(&mut wrong_gnu_bucket, 0x780, 2);
    put32(&mut wrong_gnu_bucket, 0x798, 0);
    put32(&mut wrong_gnu_bucket, 0x79c, 0);
    put32(&mut wrong_gnu_bucket, 0x7a0, hash | 1);
    let wrong_bucket = 1 - hash as usize % 2;
    put32(&mut wrong_gnu_bucket, 0x798 + wrong_bucket * 4, 1);
    assert_invalid(
        &wrong_gnu_bucket,
        "runtime GNU hash table disagrees with symbols",
    );

    let mut malformed_gnu = runtime_with_gnu_hash(false);
    put32(&mut malformed_gnu, 0x788, 3);
    put64(&mut malformed_gnu, 0x790, 0);
    put64(&mut malformed_gnu, 0x798, 0);
    put64(&mut malformed_gnu, 0x7a0, 0);
    put32(&mut malformed_gnu, 0x7a8, 1);
    put32(
        &mut malformed_gnu,
        0x7ac,
        gnu_hash(INITIALIZER.as_bytes()) | 1,
    );
    assert_invalid(&malformed_gnu, "malformed runtime GNU hash table");

    let mut unreachable_gnu = runtime_with_gnu_hash(false);
    let strings = b"\0reverie_liteinst_initialize_host\0tail\0";
    unreachable_gnu[0x500..0x500 + strings.len()].copy_from_slice(strings);
    put64(&mut unreachable_gnu, 0x2118, strings.len() as u64);
    put32(&mut unreachable_gnu, 0x630, 34);
    unreachable_gnu[0x634] = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
    put16(&mut unreachable_gnu, 0x636, 1);
    put64(&mut unreachable_gnu, 0x638, 0x1120);
    put64(&mut unreachable_gnu, 0x640, 16);
    unreachable_gnu[0x1120..0x1130].fill(0x90);
    unreachable_gnu[0x112f] = 0xc3;
    let tail_hash = gnu_hash(b"tail");
    put64(
        &mut unreachable_gnu,
        0x790,
        1_u64 << (tail_hash & 63) | 1_u64 << ((tail_hash >> 5) & 63),
    );
    put32(&mut unreachable_gnu, 0x798, 2);
    put32(&mut unreachable_gnu, 0x79c, 0);
    put32(&mut unreachable_gnu, 0x7a0, tail_hash | 1);
    assert_invalid(
        &unreachable_gnu,
        "initializer is unreachable from runtime GNU hash",
    );

    let mut writable_gnu = runtime_with_gnu_hash(false);
    writable_gnu.copy_within(0x780..0x7a0, 0x2780);
    put64(&mut writable_gnu, 0x2148, 0x2780);
    assert_invalid(
        &writable_gnu,
        "ELF range is not in required readable load bytes",
    );

    let mut both_but_disagreeing = runtime_with_gnu_hash(true);
    put32(&mut both_but_disagreeing, 0x704, 3);
    assert_invalid(&both_but_disagreeing, "malformed runtime SysV hash table");

    let mut both_but_disagreeing_gnu = runtime_with_gnu_hash(true);
    put32(
        &mut both_but_disagreeing_gnu,
        0x79c,
        gnu_hash(INITIALIZER.as_bytes()) ^ 2 | 1,
    );
    assert_invalid(
        &both_but_disagreeing_gnu,
        "runtime GNU hash table disagrees with symbols",
    );
}

#[test]
fn runtime_only_accepts_exact_64_mib_and_refuses_one_byte_over_without_changing_libc_bound() {
    assert_eq!(MAX_FILE, 32 * 1024 * 1024);
    assert!(runtime_file_bound(MAX_RUNTIME_FILE).is_ok());
    assert!(runtime_file_bound(MAX_RUNTIME_FILE + 1).is_err());

    // Unmapped padding models non-loadable file data. The small valid ELF
    // remains within the target read budget.
    let mut bytes = Vec::with_capacity(MAX_RUNTIME_FILE + 1);
    bytes.extend_from_slice(&runtime());
    bytes.resize(MAX_RUNTIME_FILE, 0);
    assert!(parse_runtime(&bytes).is_ok());
    bytes.push(0);
    assert!(parse_runtime(&bytes).is_err());
}
