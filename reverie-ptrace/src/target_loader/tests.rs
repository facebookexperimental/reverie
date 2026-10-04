/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(target_env = "gnu")]
use std::ffi::CStr;
#[cfg(target_env = "gnu")]
use std::ffi::OsStr;
#[cfg(target_env = "gnu")]
use std::mem::MaybeUninit;
#[cfg(target_env = "gnu")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_env = "gnu")]
use std::path::Path;
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
fn provider() -> Vec<u8> {
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
    let strings = b"\0libc.so.6\0dlopen\0GLIBC_2.34\0";
    bytes[0x500..0x500 + strings.len()].copy_from_slice(strings);
    put32(&mut bytes, 0x618, 11);
    bytes[0x61c] = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
    put16(&mut bytes, 0x61e, 1);
    put64(&mut bytes, 0x620, 0x1100);
    put64(&mut bytes, 0x628, 16);
    // SysV hash supplies the two-entry dynamic symbol count without sections.
    for (index, value) in [1, 2, 1, 0, 0].into_iter().enumerate() {
        put32(&mut bytes, 0x700 + index * 4, value);
    }
    put16(&mut bytes, 0x742, 2);
    put16(&mut bytes, 0x780, 1);
    put16(&mut bytes, 0x784, 2);
    put16(&mut bytes, 0x786, 1);
    put32(&mut bytes, 0x788, elf_hash(b"GLIBC_2.34"));
    put32(&mut bytes, 0x78c, 20);
    put32(&mut bytes, 0x794, 18);
    bytes[0x1100..0x1110].fill(0x90);
    bytes[0x110f] = 0xc3;
    let tags = [
        (dynamic::DT_STRTAB, 0x500),
        (dynamic::DT_STRSZ, strings.len() as u64),
        (dynamic::DT_SYMTAB, 0x600),
        (dynamic::DT_SYMENT, 24),
        (dynamic::DT_HASH, 0x700),
        (dynamic::DT_VERSYM, 0x740),
        (dynamic::DT_VERDEF, 0x780),
        (dynamic::DT_VERDEFNUM, 1),
        (dynamic::DT_SONAME, 1),
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

const TARGET_MAPS: &[u8] = b"400000-401000 r--p 0 00:01 1 /main\n\
401000-402000 rw-p 1000 00:01 1 /main\n\
700000-701000 r--p 0 00:02 2 /provider\n\
701000-702000 r-xp 1000 00:02 2 /provider\n\
702000-703000 rw-p 2000 00:02 2 /provider\n\
800000-801000 r-xp 0 00:03 3 /loader\n\
900000-901000 rw-p 0 00:00 0\n";

struct Target {
    regions: Vec<(u64, Vec<u8>)>,
    maps: Vec<Map>,
    aux: BTreeMap<u64, u64>,
}
impl Target {
    fn new(provider: &[u8]) -> Self {
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
        let maps = parse_maps(TARGET_MAPS).unwrap();
        Self {
            regions: vec![
                (0x400000, main),
                (0x700000, provider.to_vec()),
                (0x800000, interpreter),
                (0x900000, links),
            ],
            maps,
            aux: BTreeMap::from([
                (libc::AT_PHDR, 0x400040),
                (libc::AT_PHNUM, 4),
                (libc::AT_PHENT, 56),
                (libc::AT_BASE, 0x800000),
            ]),
        }
    }
    fn read(&self, address: u64, bytes: &mut [u8]) -> io::Result<()> {
        for (base, region) in &self.regions {
            if address >= *base
                && address
                    .checked_add(bytes.len() as u64)
                    .is_some_and(|end| end <= base + region.len() as u64)
            {
                bytes.copy_from_slice(
                    &region[(address - base) as usize..(address - base) as usize + bytes.len()],
                );
                return Ok(());
            }
        }
        Err(invalid("synthetic target read outside region"))
    }
    fn resolve(&self, expected: &[u8]) -> io::Result<TargetDlopen> {
        let provider = Provider::parse(expected, "GLIBC_2.34")?;
        let mut memory = Memory::new(&self.maps, |a, b: &mut [u8]| self.read(a, b));
        resolve(&mut memory, &self.aux, &provider)
    }
}

fn target_snapshot() -> Snapshot {
    let mut auxv = Vec::new();
    for (tag, value) in [
        (libc::AT_PHDR, 0x400040_u64),
        (libc::AT_PHNUM, 4_u64),
        (libc::AT_PHENT, 56_u64),
        (libc::AT_BASE, 0x800000_u64),
        (0_u64, 0_u64),
    ] {
        auxv.extend_from_slice(&tag.to_ne_bytes());
        auxv.extend_from_slice(&value.to_ne_bytes());
    }
    Snapshot {
        start_ticks: 123,
        exe: (1, 11),
        mount_namespace: (2, 22),
        maps: TARGET_MAPS.to_vec(),
        auxv,
    }
}

#[test]
fn resolves_actual_mapped_provider_bytes_and_default_version_without_sections() {
    let bytes = provider();
    let target = Target::new(&bytes);
    let resolved = target.resolve(&bytes).unwrap();
    assert_eq!(resolved.address, 0x701100);
    assert_eq!(resolved.executable_phdr, 0x400040);
    assert_eq!(resolved.load_bias, 0x700000);
    assert_eq!(resolved.link_map, 0x900140);
    assert_eq!(resolved.mapping_identity, (0, 2, 2));
    assert_eq!(resolved.version, "GLIBC_2.34");
}

#[test]
fn observed_resolver_rejects_each_final_snapshot_change() {
    let bytes = provider();
    let target = Target::new(&bytes);
    let before = target_snapshot();
    for mutation in 0..5 {
        let mut after = before.clone();
        match mutation {
            0 => after.start_ticks += 1,
            1 => after.exe.1 += 1,
            2 => after.mount_namespace.1 += 1,
            3 => after.maps.push(b'\n'),
            4 => after.auxv.push(0),
            _ => unreachable!(),
        }
        let snapshots = std::cell::RefCell::new([before.clone(), after].into_iter());
        assert_eq!(
            resolve_dlopen_observed(
                321,
                &bytes,
                "GLIBC_2.34",
                || {
                    snapshots
                        .borrow_mut()
                        .next()
                        .ok_or_else(|| invalid("missing synthetic snapshot"))
                },
                |address, buffer: &mut [u8]| target.read(address, buffer),
            )
            .unwrap_err()
            .to_string(),
            "target process, maps, auxv or mount namespace changed",
            "mutation {mutation}"
        );
        assert!(snapshots.borrow_mut().next().is_none());
    }
}

#[cfg(target_env = "gnu")]
fn default_dlopen_version(bytes: &[u8]) -> String {
    let elf = Elf::parse(bytes).unwrap();
    let versions = elf.versym.as_ref().unwrap();
    let definitions: BTreeMap<_, _> = elf
        .verdef
        .as_ref()
        .unwrap()
        .iter()
        .map(|definition| {
            let name = definition
                .iter()
                .next()
                .and_then(|aux| elf.dynstrtab.get_at(aux.vda_name))
                .unwrap();
            (definition.vd_ndx, name)
        })
        .collect();
    let mut default_versions = elf
        .dynsyms
        .iter()
        .enumerate()
        .filter(|(_, symbol)| elf.dynstrtab.get_at(symbol.st_name) == Some("dlopen"))
        .filter_map(|(index, _)| {
            let version = versions.get_at(index)?;
            (!version.is_hidden() && version.version() > 1)
                .then(|| definitions.get(&version.version()).copied())?
        })
        .collect::<Vec<_>>();
    default_versions.sort_unstable();
    default_versions.dedup();
    assert_eq!(
        default_versions.len(),
        1,
        "loaded provider must have one default dlopen version"
    );
    default_versions[0].to_owned()
}

#[cfg(target_env = "gnu")]
fn loaded_dlopen_provider() -> (Vec<u8>, String, u64, u64, u64, (u64, u64, u64)) {
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"dlopen".as_ptr()) };
    assert!(
        !address.is_null(),
        "dlopen is unavailable in the test process"
    );

    let mut info = MaybeUninit::<libc::Dl_info>::uninit();
    assert_ne!(unsafe { libc::dladdr(address, info.as_mut_ptr()) }, 0);
    let info = unsafe { info.assume_init() };
    assert!(!info.dli_fname.is_null());
    let load_bias = info.dli_fbase as usize as u64;
    let handle = unsafe { libc::dlopen(info.dli_fname, libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    assert!(!handle.is_null());
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
    assert_eq!(unsafe { libc::dlclose(handle) }, 0);
    let path = Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(info.dli_fname) }.to_bytes(),
    ));
    let bytes = std::fs::read(path).unwrap();
    let version = default_dlopen_version(&bytes);
    let address = address as usize as u64;
    let mapping = procfs::process::Process::myself()
        .unwrap()
        .maps()
        .unwrap()
        .into_iter()
        .find(|mapping| mapping.address.0 <= address && address < mapping.address.1)
        .expect("dlopen address is absent from the test process maps");
    (
        bytes,
        version,
        address,
        load_bias,
        link_map as usize as u64,
        (mapping.dev.0 as u64, mapping.dev.1 as u64, mapping.inode),
    )
}

#[cfg(target_env = "gnu")]
struct TracedChild(Option<nix::unistd::Pid>);

#[cfg(target_env = "gnu")]
impl TracedChild {
    fn new(pid: nix::unistd::Pid) -> Self {
        Self(Some(pid))
    }

    fn pid(&self) -> nix::unistd::Pid {
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
#[cfg(target_env = "gnu")]
fn resolves_loaded_provider_for_real_stopped_tracee() {
    let (
        provider,
        version,
        expected_address,
        expected_load_bias,
        expected_link_map,
        expected_identity,
    ) = loaded_dlopen_provider();
    let expected_phdr = unsafe { libc::getauxval(libc::AT_PHDR) };
    assert_ne!(expected_phdr, 0);

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
            let result = resolve_dlopen(&stopped, &provider, &version);

            let pid = child.pid();
            drop(stopped);
            assert_eq!(child.resume_and_reap().unwrap(), WaitStatus::Exited(pid, 0));

            let resolved = result.unwrap();
            assert_eq!(resolved.tid, pid.as_raw());
            assert_eq!(resolved.start_ticks, expected_start_ticks);
            assert_eq!(resolved.executable_phdr, expected_phdr);
            assert_eq!(resolved.link_map, expected_link_map);
            assert_eq!(resolved.load_bias, expected_load_bias);
            assert_eq!(resolved.address, expected_address);
            assert_eq!(resolved.mapping_identity, expected_identity);
            assert_eq!(resolved.version, version);
        }
    }
}

#[test]
fn rejects_wrong_version_private_version_ifunc_hidden_and_undefined_symbols() {
    let bytes = provider();
    assert!(Provider::parse(&bytes, "GLIBC_2.2.5").is_err());
    assert!(Provider::parse(&bytes, "GLIBC_PRIVATE").is_err());
    for (offset, value) in [
        (0x61c, (sym::STB_GLOBAL << 4) | sym::STT_GNU_IFUNC),
        (0x61d, sym::STV_HIDDEN),
        (0x61e, 0),
        (0x743, 0x80),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert!(
            Provider::parse(&bad, "GLIBC_2.34").is_err(),
            "offset {offset:x}"
        );
    }
}

#[test]
fn rejects_malformed_versions_and_checked_address_overflow() {
    let bytes = provider();
    for offset in [0x788, 0x78c, 0x790, 0x798] {
        let mut bad = bytes.clone();
        put32(&mut bad, offset, u32::MAX);
        assert!(
            Provider::parse(&bad, "GLIBC_2.34").is_err(),
            "offset {offset:x}"
        );
    }
    let mut bad = bytes.clone();
    put64(&mut bad, 0x620, u64::MAX - 1);
    assert!(Provider::parse(&bad, "GLIBC_2.34").is_err());
}

#[test]
fn rejects_corrupted_code_mapping_offsets_identity_permissions_and_dynamic_range() {
    let bytes = provider();
    let mut target = Target::new(&bytes);
    target.regions[1].1[0x1100] ^= 1;
    assert!(target.resolve(&bytes).is_err());
    for mutation in 0..6 {
        let mut target = Target::new(&bytes);
        match mutation {
            0 => target.maps[3].offset += 1,
            1 => target.maps[3].identity.2 += 1,
            2 => target.maps[3].execute = false,
            3 => target.maps[4].identity.1 += 1,
            4 => target.maps[3].write = true,
            _ => target.maps[3].private = false,
        }
        assert!(target.resolve(&bytes).is_err(), "mutation {mutation}");
    }
}

#[test]
fn rejects_target_corruption_outside_the_selected_symbol_in_each_nonwritable_load() {
    let bytes = provider();
    for offset in [0x500, 0x1200] {
        let mut target = Target::new(&bytes);
        target.regions[1].1[offset] ^= 1;
        assert_eq!(
            target.resolve(&bytes).unwrap_err().to_string(),
            "expected provider is absent from default link map",
            "target file offset {offset:#x}"
        );
    }

    let mut target = Target::new(&bytes);
    target.maps[2].execute = true;
    assert_eq!(
        target.resolve(&bytes).unwrap_err().to_string(),
        "provider mapping identity, permissions or offset disagrees"
    );
}

#[test]
fn rejects_target_corruption_after_the_first_provider_read_chunk() {
    const EXTRA_OFFSET: usize = 0x3000;
    const EXTRA_SIZE: usize = 0x11000;
    let mut bytes = provider();
    bytes.resize(EXTRA_OFFSET + EXTRA_SIZE, 0x5a);
    put16(&mut bytes, 56, 5);
    phdr(
        &mut bytes,
        4,
        ph::PT_LOAD,
        ph::PF_R,
        EXTRA_OFFSET as u64,
        EXTRA_OFFSET as u64,
        EXTRA_SIZE as u64,
    );
    let mut target = Target::new(&bytes);
    target.maps.push(Map {
        start: 0x700000 + EXTRA_OFFSET as u64,
        end: 0x700000 + (EXTRA_OFFSET + EXTRA_SIZE) as u64,
        offset: EXTRA_OFFSET as u64,
        identity: (0, 2, 2),
        read: true,
        write: false,
        execute: false,
        private: true,
    });
    target.maps.sort_by_key(|mapping| mapping.start);
    assert!(target.resolve(&bytes).is_ok());

    target.regions[1].1[EXTRA_OFFSET + 65536] ^= 1;
    assert_eq!(
        target.resolve(&bytes).unwrap_err().to_string(),
        "expected provider is absent from default link map"
    );
}

#[test]
fn rejects_later_vma_disagreement_in_writable_dynamic_range() {
    let bytes = provider();
    let mut target = Target::new(&bytes);
    let index = target
        .maps
        .iter()
        .position(|mapping| mapping.start == 0x702000)
        .unwrap();
    let mut second = target.maps[index].clone();
    target.maps[index].end = 0x702150;
    second.start = 0x702150;
    second.offset = 0x2150;
    second.identity.2 += 1;
    target.maps.push(second);
    target.maps.sort_by_key(|mapping| mapping.start);
    assert_eq!(
        target.resolve(&bytes).unwrap_err().to_string(),
        "mapped ELF file range disagrees"
    );
}

#[test]
fn rejects_inconsistent_loader_membership_cycles_and_duplicate_provider() {
    let bytes = provider();
    for (offset, value) in [
        (24, 1),
        (0x160, 0),
        (0x158, 0x900140),
        (0x150, 0x702101),
        (0x100, 1),
    ] {
        let mut target = Target::new(&bytes);
        put64(&mut target.regions[3].1, offset, value);
        assert!(target.resolve(&bytes).is_err(), "offset {offset:x}");
    }
    let mut target = Target::new(&bytes);
    let duplicate = target.regions[3].1[0x140..0x168].to_vec();
    target.regions[3].1[0x180..0x1a8].copy_from_slice(&duplicate);
    put64(&mut target.regions[3].1, 0x158, 0x900180);
    put64(&mut target.regions[3].1, 0x1a0, 0x900140);
    assert!(target.resolve(&bytes).is_err());
}

#[test]
fn rejects_memory_change_on_readback_and_read_budget_excess() {
    let bytes = provider();
    let target = Target::new(&bytes);
    let parsed = Provider::parse(&bytes, "GLIBC_2.34").unwrap();
    let changing = std::cell::Cell::new(false);
    let mut memory = Memory::new(&target.maps, |a, b: &mut [u8]| {
        target.read(a, b)?;
        if changing.get() && !b.is_empty() {
            b[0] ^= 1;
        }
        Ok(())
    });
    resolve(&mut memory, &target.aux, &parsed).unwrap();
    changing.set(true);
    assert!(memory.recheck().is_err());
    const EXPECTED_MAX_READ: usize = 8 * 1024 * 1024;
    assert_eq!(MAX_READ, EXPECTED_MAX_READ);
    let budget_maps = [Map {
        start: 0x1000,
        end: 0x1000 + EXPECTED_MAX_READ as u64,
        offset: 0,
        identity: (0, 1, 1),
        read: true,
        write: false,
        execute: false,
        private: true,
    }];
    let mut memory = Memory::new(&budget_maps, |_address, bytes: &mut [u8]| {
        bytes.fill(0);
        Ok(())
    });
    assert_eq!(
        memory.get(0x1000, EXPECTED_MAX_READ).unwrap().len(),
        EXPECTED_MAX_READ
    );
    assert_eq!(
        memory.get(0x1000, 1).unwrap_err().to_string(),
        "target read budget exceeded"
    );
}

#[test]
fn resolver_rechecks_observed_memory_before_returning() {
    let bytes = provider();
    let target = Target::new(&bytes);
    let parsed = Provider::parse(&bytes, "GLIBC_2.34").unwrap();
    let code_reads = std::cell::Cell::new(0);
    let mut memory = Memory::new(&target.maps, |address, buffer: &mut [u8]| {
        target.read(address, buffer)?;
        if address == 0x701000 {
            let prior_reads = code_reads.get();
            code_reads.set(prior_reads + 1);
            if prior_reads > 0 {
                buffer[0] ^= 1;
            }
        }
        Ok(())
    });
    assert_eq!(
        resolve(&mut memory, &target.aux, &parsed)
            .unwrap_err()
            .to_string(),
        "target memory changed during resolution"
    );
    assert_eq!(code_reads.get(), 2);
}

#[test]
fn maps_and_auxv_refuse_malformed_or_ambiguous_inputs() {
    for text in [
        b"garbage\n".as_slice(),
        b"1000-1000 r--p 0 00:01 1\n",
        b"1000-2000 r--p 0 00:01 1\n1800-3000 r--p 0 00:01 2\n",
        b"1000-2000 rwxp! 0 00:01 1\n",
        b"1000-2000 r--p 0 00:01 1\n\n",
    ] {
        assert!(parse_maps(text).is_err());
    }
    assert!(parse_auxv(&[0; 15]).is_err());
    let mut aux = vec![0; 48];
    put64(&mut aux, 0, libc::AT_PHDR);
    put64(&mut aux, 16, libc::AT_PHDR);
    assert!(parse_auxv(&aux).is_err());
    assert!(parse_auxv(&aux[..16]).is_err());
}

#[test]
fn resolves_position_independent_executable_from_kernel_phdr() {
    let bytes = provider();
    let mut target = Target::new(&bytes);
    put16(&mut target.regions[0].1, 16, header::ET_DYN);
    for index in 0..4 {
        let at = 64 + index * 56 + 16;
        let value = u64_at(&target.regions[0].1, at);
        put64(&mut target.regions[0].1, at, value - 0x400000);
    }
    put64(&mut target.regions[3].1, 0x100, 0x400000);
    assert_eq!(target.resolve(&bytes).unwrap().address, 0x701100);
}

#[test]
fn rejects_unversioned_base_and_ambiguous_public_definitions() {
    let bytes = provider();
    for number in [0, 1] {
        let mut bad = bytes.clone();
        put16(&mut bad, 0x742, number);
        assert!(Provider::parse(&bad, "GLIBC_2.34").is_err());
    }
    let mut base = bytes.clone();
    put16(&mut base, 0x742, 1);
    put16(&mut base, 0x784, 1);
    put16(&mut base, 0x782, 1);
    assert!(Provider::parse(&base, "GLIBC_2.34").is_err());
    let mut duplicate = bytes.clone();
    duplicate[0x630..0x648].copy_from_slice(&bytes[0x618..0x630]);
    put32(&mut duplicate, 0x704, 3);
    put16(&mut duplicate, 0x744, 2);
    assert!(Provider::parse(&duplicate, "GLIBC_2.34").is_err());
}

#[test]
fn rejects_provider_load_disagreement_overlap_and_unterminated_dynamic_table() {
    let bytes = provider();
    for (offset, value) in [
        (64 + 3 * 56 + 16, 0x2101),
        (64 + 56 + 16, 0x800),
        (64 + 56 + 48, 3),
        (64 + 56 + 40, 1),
        (0x2100 + 9 * 16, dynamic::DT_DEBUG),
    ] {
        let mut bad = bytes.clone();
        put64(&mut bad, offset, value);
        assert!(
            Provider::parse(&bad, "GLIBC_2.34").is_err(),
            "offset {offset:x}"
        );
    }
    let mut textrel = bytes.clone();
    put64(&mut textrel, 0x2100 + 9 * 16, dynamic::DT_FLAGS);
    put64(&mut textrel, 0x2108 + 9 * 16, dynamic::DF_TEXTREL);
    put64(&mut textrel, 64 + 3 * 56 + 32, 11 * 16);
    put64(&mut textrel, 64 + 3 * 56 + 40, 11 * 16);
    assert!(Provider::parse(&textrel, "GLIBC_2.34").is_err());
}

#[test]
fn rejects_main_and_interpreter_relationship_disagreement() {
    let bytes = provider();
    for (region, offset, value) in [
        (0, 64 + 56 + 8, 65),
        (0, 64 + 3 * 56 + 16, 0x401001),
        (0, 64 + 3 * 56 + 40, 1),
        (3, 16, 0x700000),
        (3, 32, 0x800001),
    ] {
        let mut target = Target::new(&bytes);
        put64(&mut target.regions[region].1, offset, value);
        assert!(
            target.resolve(&bytes).is_err(),
            "region {region}, offset {offset:x}"
        );
    }
    let mut target = Target::new(&bytes);
    target.maps[5].offset = 1;
    assert!(target.resolve(&bytes).is_err());
}

// Insert a separately backed, same-layout DSO before the original provider.
// Link-map order is independent of the numerical order of its node addresses.
fn prepend_provider(target: &mut Target, earlier: &[u8]) {
    target.regions.push((0x600000, earlier.to_vec()));
    let mappings = target.maps[2..5].to_vec();
    for mut mapping in mappings {
        mapping.start -= 0x100000;
        mapping.end -= 0x100000;
        mapping.identity = (0, 4, 4);
        target.maps.push(mapping);
    }
    target.maps.sort_by_key(|mapping| mapping.start);
    let links = &mut target.regions[3].1;
    put64(links, 0x118, 0x900180);
    put64(links, 0x160, 0x900180);
    put64(links, 0x180, 0x600000);
    put64(links, 0x190, 0x602100);
    put64(links, 0x198, 0x900140);
    put64(links, 0x1a0, 0x900100);
}

fn different_provider(expected: &[u8]) -> Vec<u8> {
    let mut different = expected.to_vec();
    // XCHG EAX, ECX is a valid instruction of the same size as the original NOP.
    different[0x1100] = 0x91;
    assert_eq!(&different[..64], &expected[..64]);
    assert!(Provider::parse(&different, "GLIBC_2.34").is_ok());
    different
}

#[test]
fn resolves_exact_provider_after_valid_different_same_layout_dso() {
    let bytes = provider();
    let mut target = Target::new(&bytes);
    prepend_provider(&mut target, &different_provider(&bytes));
    assert_eq!(
        target.resolve(&bytes).unwrap(),
        TargetDlopen {
            tid: 0,
            start_ticks: 0,
            executable_phdr: 0x400040,
            link_map: 0x900140,
            load_bias: 0x700000,
            address: 0x701100,
            version: "GLIBC_2.34".to_owned(),
            mapping_identity: (0, 2, 2),
        }
    );
}

#[test]
fn rejects_absent_and_only_corrupted_provider_after_candidate_search() {
    let bytes = provider();
    let mut absent = Target::new(&bytes);
    put64(&mut absent.regions[3].1, 0x118, 0);
    assert_eq!(
        absent.resolve(&bytes).unwrap_err().to_string(),
        "expected provider is absent from default link map"
    );
    let different = different_provider(&bytes);
    let only_corrupted = Target::new(&different);
    assert_eq!(
        only_corrupted.resolve(&bytes).unwrap_err().to_string(),
        "expected provider is absent from default link map"
    );
}

#[test]
fn rejects_two_exact_providers_with_distinct_mappings() {
    let bytes = provider();
    let mut target = Target::new(&bytes);
    prepend_provider(&mut target, &bytes);
    assert_eq!(
        target.resolve(&bytes).unwrap_err().to_string(),
        "provider appears twice in default namespace"
    );
}

#[test]
fn preserves_provider_read_failures_before_or_at_the_exact_candidate() {
    let bytes = provider();
    let parsed = Provider::parse(&bytes, "GLIBC_2.34").unwrap();
    let mut target = Target::new(&bytes);
    prepend_provider(&mut target, &different_provider(&bytes));
    for failed_start in [0x600000, 0x600040, 0x601000, 0x700000, 0x700040, 0x701000] {
        let mut memory = Memory::new(&target.maps, |address, buffer: &mut [u8]| {
            if (failed_start..failed_start + 0x1000).contains(&address) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "synthetic short target read",
                ));
            }
            target.read(address, buffer)
        });
        assert_eq!(
            resolve(&mut memory, &target.aux, &parsed)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
            "failed read start {failed_start:x}"
        );
    }
}

#[test]
fn different_candidate_bytes_do_not_hide_later_mapping_failure() {
    let bytes = provider();
    let mut target = Target::new(&bytes);
    prepend_provider(&mut target, &different_provider(&bytes));
    // This dynamic-range check follows the differing executable bytes.
    let dynamic_map = target
        .maps
        .iter_mut()
        .find(|map| map.start == 0x602000)
        .unwrap();
    dynamic_map.identity.2 += 1;
    assert_eq!(
        target.resolve(&bytes).unwrap_err().to_string(),
        "mapped ELF file range disagrees"
    );
}

#[test]
fn rereads_different_candidate_bytes_after_finding_exact_provider() {
    let bytes = provider();
    let parsed = Provider::parse(&bytes, "GLIBC_2.34").unwrap();
    let mut target = Target::new(&bytes);
    prepend_provider(&mut target, &different_provider(&bytes));
    let changing = std::cell::Cell::new(false);
    let mut memory = Memory::new(&target.maps, |address, buffer: &mut [u8]| {
        target.read(address, buffer)?;
        if changing.get() && address == 0x601000 {
            buffer[0x100] ^= 1;
        }
        Ok(())
    });
    assert_eq!(
        resolve(&mut memory, &target.aux, &parsed).unwrap().address,
        0x701100
    );
    changing.set(true);
    assert_eq!(
        memory.recheck().unwrap_err().to_string(),
        "target memory changed during resolution"
    );
}

#[test]
fn resolves_exact_provider_after_valid_different_load_layout() {
    let bytes = provider();
    let mut different = bytes.clone();
    // Move the executable file segment without changing the ordered virtual
    // loads or PT_DYNAMIC RVA. Both offset and address remain page-aligned.
    different.resize(0x5000, 0);
    different[0x4000..0x5000].copy_from_slice(&bytes[0x1000..0x2000]);
    phdr(
        &mut different,
        1,
        ph::PT_LOAD,
        ph::PF_R | ph::PF_X,
        0x4000,
        0x1000,
        0x1000,
    );
    assert_eq!(&different[..64], &bytes[..64]);
    assert_eq!(
        Provider::parse(&different, "GLIBC_2.34").unwrap().dynamic,
        0x2100
    );
    let mut target = Target::new(&bytes);
    prepend_provider(&mut target, &different);
    let code_map = target
        .maps
        .iter_mut()
        .find(|map| map.start == 0x601000)
        .unwrap();
    code_map.offset = 0x4000;
    assert_eq!(target.regions.pop().unwrap().0, 0x600000);
    target
        .regions
        .push((0x600000, different[..0x1000].to_vec()));
    target
        .regions
        .push((0x601000, different[0x4000..0x5000].to_vec()));
    target
        .regions
        .push((0x602000, different[0x2000..0x3000].to_vec()));
    assert_eq!(
        target.resolve(&bytes).unwrap(),
        TargetDlopen {
            tid: 0,
            start_ticks: 0,
            executable_phdr: 0x400040,
            link_map: 0x900140,
            load_bias: 0x700000,
            address: 0x701100,
            version: "GLIBC_2.34".to_owned(),
            mapping_identity: (0, 2, 2),
        }
    );
}
