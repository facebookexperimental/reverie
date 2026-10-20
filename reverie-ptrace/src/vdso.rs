/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Provides APIs to disable VDSOs at runtime.
use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::sync::Mutex;

use nix::sys::mman::ProtFlags;
use nix::unistd;
use reverie::Errno;
use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mprotect;
use reverie::syscalls::Sysno;
use reverie::vdso::KnownEntry;
use reverie::vdso::PATCH_FILL;
use reverie::vdso::VdsoEntry;
use reverie::vdso::VdsoEntryKind;
use reverie::vdso::classify_vdso_exports;
use reverie::vdso::stubs as vdso_syms;
use reverie::vdso::vdso_exports;
use tracing::debug;
use tracing::warn;

/// The classified entry points of a vDSO image.
#[derive(Debug)]
struct VdsoTable {
    /// The length of the `[vdso]` mapping the image was read from.
    mapping_len: u64,
    entries: Vec<VdsoEntry>,
}

/// This process's own vDSO, classified, or `None` if it has no vDSO.
///
/// The ptrace backend assumes every guest maps the same image, which the kernel
/// shares between all 64-bit processes; [`vdso_patch`] refuses a guest whose
/// mapping has a different length. In-guest backends read their own vDSO.
static VDSO_TABLE: LazyLock<Result<Option<VdsoTable>, String>> = LazyLock::new(classify_this_vdso);

fn classify_this_vdso() -> Result<Option<VdsoTable>, String> {
    let maps = {
        let _open = crate::launch_window::TransientOpen::begin();
        procfs::process::Process::myself().and_then(|process| process.maps())
    }
    .map_err(|error| format!("cannot read this process's mappings: {error}"))?;
    let Some(vdso) = maps
        .iter()
        .find(|map| map.pathname == procfs::process::MMapPath::Vdso)
    else {
        return Ok(None);
    };
    let mapping_len = vdso.address.1 - vdso.address.0;
    // SAFETY: the kernel keeps the vDSO mapped, readable and unmodified for the
    // life of the process; this runs before any patch of this process's vDSO.
    let image =
        unsafe { std::slice::from_raw_parts(vdso.address.0 as *const u8, mapping_len as usize) };
    let entries = classify_vdso_exports(&vdso_exports(image)?)?;
    for entry in &entries {
        match entry.kind {
            VdsoEntryKind::Unknown => warn!(
                "vDSO exports unknown entry point {}; it is replaced by an -ENOSYS stub \
                 whenever the tool subscribes to any syscall",
                entry.describe()
            ),
            VdsoEntryKind::Known(kind) => debug!("vDSO entry point {}: {kind:?}", entry.describe()),
        }
    }
    Ok(Some(VdsoTable {
        mapping_len,
        entries,
    }))
}

/// The vDSO table, or the reason it could not be built.
fn vdso_table() -> Result<Option<&'static VdsoTable>, Error> {
    VDSO_TABLE
        .as_ref()
        .map(Option::as_ref)
        .map_err(|error| Error::from(std::io::Error::other(error.clone())))
}

/// The entry points `subscriptions` selects for replacement, with their stubs,
/// in address order.
///
/// Both the in-process and stopped-guest patch paths consume this, so their
/// selection is implemented in one place.
fn vdso_replacements(
    subscriptions: &Subscription,
) -> Result<Vec<(&'static VdsoEntry, &'static [u8])>, Error> {
    static REPORTED: LazyLock<Mutex<BTreeSet<String>>> = LazyLock::new(Default::default);
    let (replacements, report) = replacements_from(vdso_table, subscriptions, &REPORTED)?;
    match report {
        Some(NativeReport::First(native)) => warn!(
            "vDSO entry points left native because the tool does not subscribe to their \
             syscalls, so it does not observe these calls: {native}"
        ),
        Some(NativeReport::Repeat(native)) => debug!("vDSO entry points left native: {native}"),
        None => {}
    }
    Ok(replacements)
}

/// The entry points to replace, each with its stub, and the report of those
/// left native.
type Selection<'a> = (Vec<(&'a VdsoEntry, &'static [u8])>, Option<NativeReport>);

/// Runs [`select_replacements`] on the vDSO table, which `table` reads only if
/// the tool subscribes to some syscall: a tool that subscribes to none leaves
/// the vDSO alone, even one that could not be read or classified.
fn replacements_from<'a>(
    table: impl FnOnce() -> Result<Option<&'a VdsoTable>, Error>,
    subscriptions: &Subscription,
    reported: &Mutex<BTreeSet<String>>,
) -> Result<Selection<'a>, Error> {
    if subscriptions.iter_syscalls().next().is_none() {
        return Ok((Vec::new(), None));
    }
    Ok(match table()? {
        Some(table) => select_replacements(table, subscriptions, reported),
        None => (Vec::new(), None),
    })
}

/// How [`select_replacements`] reports the entry points it leaves native.
#[derive(Debug, PartialEq, Eq)]
enum NativeReport {
    /// This set of native entry points, described, is new to this process.
    First(String),
    /// The same set was already reported.
    Repeat(String),
}

/// The entry points of `table` that `subscriptions` selects for replacement,
/// with their stubs, and the report of those it leaves native.
///
/// A tool that subscribes to no syscall leaves the whole vDSO alone, and
/// nothing a vDSO function does can bypass it, so that is not reported. Any
/// other tool gets a report whenever an entry point stays native, including
/// when nothing at all is replaced, unless
/// [`VdsoHandling::Native`](reverie::vdso::VdsoHandling::Native) keeps it.
/// `reported` holds the sets already reported, so each distinct set is
/// [`NativeReport::First`] once.
fn select_replacements<'a>(
    table: &'a VdsoTable,
    subscriptions: &Subscription,
    reported: &Mutex<BTreeSet<String>>,
) -> Selection<'a> {
    if subscriptions.iter_syscalls().next().is_none() {
        return (Vec::new(), None);
    }
    let mut replacements = Vec::new();
    let mut native = Vec::new();
    for entry in &table.entries {
        match entry.replacement(subscriptions) {
            Some(stub) => replacements.push((entry, stub)),
            // Kept by its classification: it reads nothing the tool could
            // observe.
            None if entry.kind == VdsoEntryKind::Known(KnownEntry::Native) => {}
            None => native.push(entry.describe()),
        }
    }
    let report = (!native.is_empty()).then(|| {
        let native = native.join(", ");
        if reported.lock().unwrap().insert(native.clone()) {
            NativeReport::First(native)
        } else {
            NativeReport::Repeat(native)
        }
    });
    (replacements, report)
}

/// Does `subscriptions` require patching the vDSO? A vDSO that could not be
/// read or classified does, so that [`vdso_patch`] reports why.
pub fn is_patch_required(subscriptions: &Subscription) -> bool {
    !matches!(vdso_replacements(subscriptions), Ok(replacements) if replacements.is_empty())
}

/// One vDSO entry point rewritten for an in-guest syscall hook.
#[derive(Clone, Copy, Debug)]
pub struct VdsoSyscallSite {
    /// Address at which the in-guest backend should install its hook.
    pub address: u64,
    /// Linux syscall number implemented by this entry point.
    pub number: i64,
    /// Start of the special vDSO mapping containing this entry point.
    pub mapping_start: u64,
    /// Length of the special vDSO mapping containing this entry point.
    pub mapping_len: u64,
}

/// Rewrite the calling process's vDSO entry points into hookable syscalls.
///
/// Returns each rewritten syscall fast path's entry address and syscall number
/// so an in-guest patching backend can install its ordinary syscall trampoline
/// while the process is still single-threaded. The two-byte syscall is
/// deliberately placed at the aligned symbol entry: LiteInst needs a full patch
/// word after the hook address, which is not guaranteed at the tail of an
/// eight-byte pseudo-vDSO function. `__vdso_getrandom` is the exception: it
/// keeps the table's whole stub, which answers the parameter query without a
/// syscall, and its site is the stub's `syscall`, followed only by `ret` and
/// padding. Entry points with no syscall equivalent, known or not, get the
/// -ENOSYS stub, which needs no hook, except those
/// [`VdsoHandling::Native`](reverie::vdso::VdsoHandling::Native)
/// keeps. This shares the authoritative vDSO table
/// with ptrace's stopped-guest path instead of maintaining a backend-specific
/// list.
#[cfg(target_arch = "x86_64")]
pub fn patch_current_vdso(subscriptions: &Subscription) -> Result<Vec<VdsoSyscallSite>, Error> {
    rewrite_current_vdso(subscriptions, true)
}

/// Rewrite the calling process's vDSO entry points into trapping syscalls.
///
/// Writes the same stubs as ptrace's stopped-guest path (`vdso_patch`): each
/// syscall fast path becomes the table's whole `mov $nr, %eax; syscall; ret`
/// stub, so a process that installs no hooks takes every subscribed vDSO call
/// through its ordinary syscall trap. An in-guest backend with site patching
/// off uses this instead of [`patch_current_vdso`], whose bare `syscall`
/// relies on the installed hook to supply the syscall number.
#[cfg(target_arch = "x86_64")]
pub fn patch_current_vdso_trapping(subscriptions: &Subscription) -> Result<(), Error> {
    rewrite_current_vdso(subscriptions, false).map(drop)
}

/// Shared body of [`patch_current_vdso`] (`hooked`) and
/// [`patch_current_vdso_trapping`] (not `hooked`). Only `hooked` reports sites.
#[cfg(target_arch = "x86_64")]
fn rewrite_current_vdso(
    subscriptions: &Subscription,
    hooked: bool,
) -> Result<Vec<VdsoSyscallSite>, Error> {
    let replacements = vdso_replacements(subscriptions)?;
    if replacements.is_empty() {
        return Ok(Vec::new());
    }
    let process =
        procfs::process::Process::new(unistd::getpid().as_raw()).map_err(|_| Errno::ENOENT)?;
    let maps = process.maps().map_err(|_| Errno::EIO)?;
    let Some(vdso) = maps
        .iter()
        .find(|entry| entry.pathname == procfs::process::MMapPath::Vdso)
    else {
        return Err(Errno::ENOENT.into());
    };
    let start = vdso.address.0 as usize;
    let len = (vdso.address.1 - vdso.address.0) as usize;
    Errno::result(unsafe {
        libc::mprotect(
            start as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    })?;

    let mut syscall_sites = Vec::new();
    for (entry, bytes) in replacements {
        let symbol = start + entry.offset as usize;
        let size = entry.size;
        match entry.kind {
            VdsoEntryKind::Known(KnownEntry::Syscall(_, Sysno::getrandom)) if hooked => {
                // The parameter query must be answered before any syscall, so
                // this entry keeps its whole stub and is hooked at the stub's
                // `syscall`. Every byte after that `syscall` is a `ret` or
                // padding, which leaves the hook its full patch word.
                assert!(size >= bytes.len() + 8);
                let patch_len = entry.patch_len(bytes.len() + 8);
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), symbol as *mut u8, bytes.len());
                    core::ptr::write_bytes(
                        (symbol + bytes.len()) as *mut u8,
                        PATCH_FILL,
                        patch_len - bytes.len(),
                    );
                }
                syscall_sites.push(VdsoSyscallSite {
                    address: (symbol + vdso_syms::GETRANDOM_SYSCALL_OFFSET) as u64,
                    number: libc::SYS_getrandom,
                    mapping_start: start as u64,
                    mapping_len: len as u64,
                });
            }
            VdsoEntryKind::Known(KnownEntry::Syscall(_, sysno)) if hooked => {
                // The hook replaces a whole patch word at the `syscall`.
                assert!(size >= 8);
                let patch_len = entry.patch_len(8);
                unsafe {
                    core::ptr::write(symbol as *mut u8, 0x0f);
                    core::ptr::write((symbol + 1) as *mut u8, 0x05);
                    core::ptr::write((symbol + 2) as *mut u8, 0xc3);
                    core::ptr::write_bytes((symbol + 3) as *mut u8, PATCH_FILL, patch_len - 3);
                }
                syscall_sites.push(VdsoSyscallSite {
                    address: symbol as u64,
                    number: i64::from(sysno.id()),
                    mapping_start: start as u64,
                    mapping_len: len as u64,
                });
            }
            // Without a hook, a syscall entry keeps the table's whole stub,
            // exactly as `vdso_patch` writes it into a stopped guest.
            VdsoEntryKind::Known(KnownEntry::Syscall(..) | KnownEntry::Enosys)
            | VdsoEntryKind::Unknown => {
                assert!(size >= bytes.len());
                let patch_len = entry.patch_len(bytes.len());
                unsafe {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), symbol as *mut u8, bytes.len());
                    core::ptr::write_bytes(
                        (symbol + bytes.len()) as *mut u8,
                        PATCH_FILL,
                        patch_len - bytes.len(),
                    );
                }
            }
            VdsoEntryKind::Known(KnownEntry::Native) => {
                unreachable!("{} is kept native, never replaced", entry.describe())
            }
        }
        debug!("patched vDSO entry point {}", entry.describe());
    }

    Errno::result(unsafe {
        libc::mprotect(
            start as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_EXEC,
        )
    })?;
    Ok(syscall_sites)
}

/// Test-only: a hook for the tracee with the given raw PID.
#[cfg(test)]
type VdsoHookForTest = (i32, Box<dyn Fn()>);

#[cfg(test)]
thread_local! {
    /// Test-only: runs in [`vdso_patch`] of the tracee with the given raw PID,
    /// once its vDSO is writable, before it is patched.
    static VDSO_WRITABLE_FOR_TEST: std::cell::RefCell<Option<VdsoHookForTest>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only: installs a [`VDSO_WRITABLE_FOR_TEST`] hook for the tracee with
/// raw PID `pid` until the returned guard is dropped, including when the
/// patch future is dropped part way.
#[cfg(test)]
pub(crate) fn vdso_writable_hook_for_test(pid: i32, hook: Box<dyn Fn()>) -> impl Drop {
    struct Uninstall;
    impl Drop for Uninstall {
        fn drop(&mut self) {
            VDSO_WRITABLE_FOR_TEST.with(|slot| slot.borrow_mut().take());
        }
    }
    VDSO_WRITABLE_FOR_TEST.with(|slot| *slot.borrow_mut() = Some((pid, hook)));
    Uninstall
}

/// patch VDSOs when enabled
///
/// `guest` must be in one of ptrace's stopped states.
pub async fn vdso_patch<G, T>(guest: &mut G, subscriptions: &Subscription) -> Result<(), Error>
where
    G: Guest<T>,
    T: Tool,
{
    let replacements = vdso_replacements(subscriptions)?;
    let Some(table) = vdso_table()? else {
        return Ok(());
    };
    if replacements.is_empty() {
        return Ok(());
    }
    let guest_maps = {
        let _open = crate::launch_window::TransientOpen::begin();
        procfs::process::Process::new(guest.pid().as_raw()).map_or_else(
            |_| Vec::new(),
            |p| match p.maps() {
                Ok(maps) => maps.0,
                Err(_) => Vec::new(),
            },
        )
    };
    if let Some(vdso) = guest_maps
        .iter()
        .find(|e| e.pathname == procfs::process::MMapPath::Vdso)
    {
        // The plan was made from the tracer's own vDSO. A guest whose vDSO
        // differs (a 32-bit or foreign-ABI guest, say) would have its code
        // overwritten at the wrong offsets, so refuse it.
        let guest_len = vdso.address.1 - vdso.address.0;
        if guest_len != table.mapping_len {
            return Err(Error::from(std::io::Error::other(format!(
                "guest {} maps a {guest_len}-byte vDSO, but the patch plan is for the \
                 tracer's {}-byte vDSO",
                guest.pid(),
                table.mapping_len
            ))));
        }

        let mut memory = guest.memory();

        // Allow write access to the vdso memory page.
        guest
            .inject_with_retry(
                Mprotect::new()
                    .with_addr(AddrMut::from_raw(vdso.address.0 as usize))
                    .with_len(guest_len as usize)
                    .with_protection(
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                    ),
            )
            .await?;
        #[cfg(test)]
        VDSO_WRITABLE_FOR_TEST.with(|hook| {
            if let Some((pid, hook)) = hook.borrow().as_ref()
                && *pid == guest.pid().as_raw()
            {
                hook();
            }
        });

        for (entry, bytes) in replacements {
            let start = vdso.address.0 + entry.offset;
            assert!(bytes.len() <= entry.size);
            let patch_len = entry.patch_len(bytes.len());
            let rptr = AddrMut::from_raw(start as usize).ok_or(Errno::EFAULT)?;
            memory.write_exact(rptr, bytes)?;
            if patch_len > bytes.len() {
                let fill: Vec<u8> =
                    std::iter::repeat_n(PATCH_FILL, patch_len - bytes.len()).collect();
                memory.write_exact(unsafe { rptr.add(bytes.len()) }, &fill)?;
            }
            debug!(
                "{} patched {}@{:x}",
                guest.pid(),
                entry.names.join("/"),
                start
            );
        }

        guest
            .inject_with_retry(
                Mprotect::new()
                    .with_addr(AddrMut::from_raw(vdso.address.0 as usize))
                    .with_len(guest_len as usize)
                    .with_protection(ProtFlags::PROT_READ | ProtFlags::PROT_EXEC),
            )
            .await?;
    }
    Ok(())
}

/// Gives a stopped guest, before its first instruction, the vDSO and auxiliary
/// values every backend gives its guests, so that its start-up does not
/// depend on the host (<https://github.com/rrnewton/reverie/issues/947>):
///
/// - Each auxv entry that describes the CPU or the kernel gets its
///   `reverie::canonical_auxv_value`. The kernel decides which entries exist,
///   so only their values change.
/// - The canonical vDSO (`reverie::vdso::canonical_vdso_image`) is mapped at
///   its address and `AT_SYSINFO_EHDR` points at it, so that ld.so loads it in
///   place of the host kernel's. The host vDSO stays mapped, and patched by
///   [`vdso_patch`], but nothing the loader sets up refers to it. A guest whose
///   kernel supplied no `AT_SYSINFO_EHDR` is left without a vDSO.
///
/// `stack` is the guest's stack pointer at its exec stop, where `argc` is. The
/// auxiliary vector the kernel wrote follows `argv` and `envp`, and ld.so has
/// not read it yet. `/proc/<pid>/auxv` keeps the kernel's values.
#[cfg(target_arch = "x86_64")]
pub async fn canonicalize_new_image<G, T>(guest: &mut G, stack: u64) -> Result<(), Error>
where
    G: Guest<T>,
    T: Tool,
{
    use reverie::canonical_auxv_value;
    use reverie::syscalls::Addr;
    use reverie::syscalls::MapFlags;
    use reverie::syscalls::Mmap;
    use reverie::vdso::CANONICAL_VDSO_ADDRESS;
    use reverie::vdso::CANONICAL_VDSO_SIZE;
    use reverie::vdso::canonical_vdso_image;

    let mut memory = guest.memory();
    let read = |memory: &G::Memory, at: u64| -> Result<u64, Error> {
        let address: Addr<u64> = Addr::from_raw(at as usize).ok_or(Errno::EFAULT)?;
        Ok(memory.read_value(address)?)
    };
    // argc, argv[0..argc], NULL, envp.., NULL, then the auxv pairs.
    let argc = read(&memory, stack)?;
    let mut at = stack + 8 * (argc + 2);
    while read(&memory, at)? != 0 {
        at += 8;
    }
    at += 8;
    let mut sysinfo_ehdr = None;
    loop {
        let key = read(&memory, at)?;
        if key == libc::AT_NULL {
            break;
        }
        if key == reverie::AT_MINSIGSTKSZ {
            reverie::check_host_minsigstksz(read(&memory, at + 8)?)
                .map_err(|reason| Error::from(std::io::Error::other(reason)))?;
        }
        if key == libc::AT_SYSINFO_EHDR {
            sysinfo_ehdr = Some(at + 8);
        } else if let Some(value) = canonical_auxv_value(key) {
            let entry: AddrMut<u64> = AddrMut::from_raw(at as usize + 8).ok_or(Errno::EFAULT)?;
            memory.write_value(entry, &value)?;
        }
        at += 16;
    }
    let Some(sysinfo_ehdr) = sysinfo_ehdr else {
        return Ok(());
    };

    let mapped = guest
        .inject_with_retry(
            Mmap::new()
                .with_addr(Addr::from_raw(CANONICAL_VDSO_ADDRESS as usize))
                .with_len(CANONICAL_VDSO_SIZE as usize)
                .with_prot(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
                .with_flags(
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED_NOREPLACE,
                )
                .with_fd(-1)
                .with_offset(0),
        )
        .await?;
    if mapped as u64 != CANONICAL_VDSO_ADDRESS {
        return Err(Error::from(std::io::Error::other(format!(
            "guest {} got the canonical vDSO at {mapped:#x}, not {CANONICAL_VDSO_ADDRESS:#x}",
            guest.pid()
        ))));
    }
    let image = AddrMut::from_raw(CANONICAL_VDSO_ADDRESS as usize).ok_or(Errno::EFAULT)?;
    memory.write_exact(image, canonical_vdso_image())?;
    guest
        .inject_with_retry(
            Mprotect::new()
                .with_addr(AddrMut::from_raw(CANONICAL_VDSO_ADDRESS as usize))
                .with_len(CANONICAL_VDSO_SIZE as usize)
                .with_protection(ProtFlags::PROT_READ | ProtFlags::PROT_EXEC),
        )
        .await?;
    let entry: AddrMut<u64> = AddrMut::from_raw(sysinfo_ehdr as usize).ok_or(Errno::EFAULT)?;
    memory.write_value(entry, &CANONICAL_VDSO_ADDRESS)?;
    debug!(
        "{} mapped the canonical vDSO at {CANONICAL_VDSO_ADDRESS:#x}",
        guest.pid()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use goblin::elf::Elf;
    use reverie::vdso::VdsoExport;
    use reverie::vdso::VdsoSymbol;

    use super::*;

    #[test]
    fn can_find_vdso() {
        assert!(
            procfs::process::Process::new(unistd::getpid().as_raw())
                .map_or_else(
                    |_| Vec::new(),
                    |p| match p.maps() {
                        Ok(maps) => maps.0,
                        Err(_) => Vec::new(),
                    },
                )
                .iter()
                .any(|e| e.pathname == procfs::process::MMapPath::Vdso)
        );
    }

    fn host_table() -> &'static VdsoTable {
        VDSO_TABLE
            .as_ref()
            .expect("the host vDSO must classify cleanly")
            .as_ref()
            .expect("this host must map a vDSO")
    }

    /// Every [`VdsoSymbol`] that is a syscall fast path, with its stub.
    fn known_syscalls() -> impl Iterator<Item = (&'static str, &'static [u8], Sysno)> {
        VdsoSymbol::ALL
            .iter()
            .filter_map(|symbol| match KnownEntry::of(*symbol).unwrap() {
                KnownEntry::Syscall(stub, sysno) => Some((symbol.name(), stub, sysno)),
                KnownEntry::Enosys | KnownEntry::Native => None,
            })
    }

    /// The first syscall fast path in [`VdsoSymbol::ALL`], so the synthetic
    /// tests run unchanged on every architecture.
    fn a_known_syscall() -> (&'static str, &'static [u8], Sysno) {
        known_syscalls().next().unwrap()
    }

    fn export(name: &str, offset: u64, size: usize) -> VdsoExport {
        VdsoExport {
            name: name.to_owned(),
            offset,
            size,
            section_end: None,
        }
    }

    /// A vDSO of syscall fast paths only, as on aarch64 or an x86_64 kernel
    /// without SGX: one known fast path, and a subscription without its syscall.
    fn syscall_only_table() -> (VdsoTable, Sysno, Subscription) {
        let (known, _, sysno) = a_known_syscall();
        let table = VdsoTable {
            mapping_len: 0x2000,
            entries: classify_vdso_exports(&[export(known, 0x800, 100)]).unwrap(),
        };
        let unrelated = [if sysno == Sysno::read {
            Sysno::write
        } else {
            Sysno::read
        }]
        .into_iter()
        .collect();
        (table, sysno, unrelated)
    }

    #[test]
    fn native_entry_points_are_reported_when_nothing_is_replaced() {
        let (table, _, unrelated) = syscall_only_table();
        let native = table.entries[0].describe();
        let reported = Mutex::default();

        let (replacements, report) = select_replacements(&table, &unrelated, &reported);
        assert!(replacements.is_empty());
        assert_eq!(report, Some(NativeReport::First(native.clone())));

        let (_, report) = select_replacements(&table, &unrelated, &reported);
        assert_eq!(report, Some(NativeReport::Repeat(native)));
    }

    #[test]
    fn each_distinct_set_of_native_entry_points_is_reported_first() {
        let (known, _, sysno) = a_known_syscall();
        let table = VdsoTable {
            mapping_len: 0x2000,
            entries: classify_vdso_exports(&[
                export(known, 0x800, 100),
                export("__vdso_future_call", 0x900, 40),
            ])
            .unwrap(),
        };
        let reported = Mutex::default();
        let (_, report) = select_replacements(&table, &Subscription::all(), &reported);
        assert_eq!(report, None, "every entry point is replaced");
        let unrelated = syscall_only_table().2;
        let (replacements, report) = select_replacements(&table, &unrelated, &reported);
        assert_eq!(replacements.len(), 1, "only the unknown entry point");
        assert_eq!(
            report,
            Some(NativeReport::First(table.entries[0].describe()))
        );
        let only_known: Subscription = [sysno].into_iter().collect();
        let (replacements, report) = select_replacements(&table, &only_known, &reported);
        assert_eq!(replacements.len(), 2);
        assert_eq!(report, None);
    }

    #[test]
    fn a_tool_without_subscriptions_never_reads_the_vdso() {
        let unreadable = || -> Result<Option<&VdsoTable>, Error> {
            Err(std::io::Error::other("vDSO entry points overlap").into())
        };
        let (replacements, report) =
            replacements_from(unreadable, &Subscription::none(), &Mutex::default()).unwrap();
        assert!(replacements.is_empty());
        assert_eq!(report, None);
        let read: Subscription = [Sysno::read].into_iter().collect();
        assert!(
            replacements_from(unreadable, &read, &Mutex::default()).is_err(),
            "a subscribing tool must see why the vDSO could not be classified"
        );
    }

    #[test]
    fn a_tool_without_subscriptions_leaves_the_vdso_unreported() {
        let (table, _, _) = syscall_only_table();
        let (replacements, report) =
            select_replacements(&table, &Subscription::none(), &Mutex::default());
        assert!(replacements.is_empty());
        assert_eq!(report, None);
    }

    #[test]
    fn host_vdso_entry_points_are_all_classified() {
        let table = host_table();
        assert!(!table.entries.is_empty());
        // SAFETY: as in VDSO_TABLE; nothing in this test binary patches its
        // own vDSO.
        let exports = vdso_exports(
            procfs::process::Process::myself()
                .unwrap()
                .maps()
                .unwrap()
                .iter()
                .find(|map| map.pathname == procfs::process::MMapPath::Vdso)
                .map(|map| unsafe {
                    std::slice::from_raw_parts(
                        map.address.0 as *const u8,
                        (map.address.1 - map.address.0) as usize,
                    )
                })
                .unwrap(),
        )
        .unwrap();
        for export in &exports {
            assert_eq!(
                table
                    .entries
                    .iter()
                    .filter(|entry| entry.names.contains(&export.name))
                    .count(),
                1,
                "{} must be in exactly one entry point",
                export.name
            );
        }
        for entry in &table.entries {
            println!(
                "{}: {:?} ({} bytes)",
                entry.describe(),
                entry.kind,
                entry.size
            );
        }
        // At run time an unknown entry point is stubbed, which keeps it from
        // running unobserved; here it fails, so that it gets classified.
        let unknown: Vec<String> = table
            .entries
            .iter()
            .filter(|entry| entry.kind == VdsoEntryKind::Unknown)
            .map(VdsoEntry::describe)
            .collect();
        assert!(
            unknown.is_empty(),
            "the host vDSO exports entry points with no VdsoSymbol variant: {unknown:?}"
        );
    }

    /// The robust-futex unlock functions of Linux v7.2 keep the kernel's code,
    /// whatever the tool subscribes to, and are not reported as unobserved.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn futex_robust_unlock_entry_points_stay_native() {
        let (known, _, sysno) = a_known_syscall();
        let table = VdsoTable {
            mapping_len: 0x2000,
            entries: classify_vdso_exports(&[
                export(known, 0x800, 100),
                export("__vdso_futex_robust_list64_try_unlock", 0x880, 20),
                export("__vdso_futex_robust_list32_try_unlock", 0x8a0, 20),
            ])
            .unwrap(),
        };
        for entry in &table.entries[1..] {
            assert_eq!(entry.kind, VdsoEntryKind::Known(KnownEntry::Native));
            for subscriptions in [
                Subscription::all(),
                [Sysno::futex].into_iter().collect(),
                Subscription::none(),
            ] {
                assert_eq!(entry.replacement(&subscriptions), None);
            }
        }
        let (replacements, report) =
            select_replacements(&table, &Subscription::all(), &Mutex::default());
        assert_eq!(replacements.len(), 1, "only the syscall fast path");
        assert_eq!(report, None);
        let only_known: Subscription = [sysno].into_iter().collect();
        let (replacements, report) = select_replacements(&table, &only_known, &Mutex::default());
        assert_eq!(replacements.len(), 1);
        assert_eq!(report, None);
    }

    /// No host entry point's patch reaches past the end of its section; the
    /// host's last export, rounded up to 16, would.
    #[test]
    fn host_vdso_patches_stay_inside_their_sections() {
        let maps = procfs::process::Process::myself().unwrap().maps().unwrap();
        let vdso = maps
            .iter()
            .find(|map| map.pathname == procfs::process::MMapPath::Vdso)
            .unwrap();
        // SAFETY: as in VDSO_TABLE; nothing in this test binary patches its
        // own vDSO.
        let image = unsafe {
            std::slice::from_raw_parts(
                vdso.address.0 as *const u8,
                (vdso.address.1 - vdso.address.0) as usize,
            )
        };
        let elf = Elf::parse(image).unwrap();
        for entry in &host_table().entries {
            let section = elf
                .section_headers
                .iter()
                .find(|section| {
                    section.sh_addr <= entry.offset
                        && entry.offset < section.sh_addr + section.sh_size
                })
                .unwrap_or_else(|| panic!("no section contains {}", entry.describe()));
            assert!(
                entry.offset + entry.size as u64 <= section.sh_addr + section.sh_size,
                "{} may overwrite {} bytes, past the end of its section at {:#x}",
                entry.describe(),
                entry.size,
                section.sh_addr + section.sh_size
            );
        }
    }

    /// A subscription to no vDSO syscall requires patching exactly when the
    /// host vDSO exports an entry point with no syscall equivalent (on x86_64,
    /// `__vdso_sgx_enter_enclave`), because that entry point is stubbed for
    /// any tool that observes syscalls.
    #[test]
    fn patch_requirement_tracks_vdso_syscall_subscriptions() {
        assert!(!is_patch_required(&Subscription::none()));

        let table = host_table();
        let has_non_syscall_entry = table.entries.iter().any(|entry| {
            matches!(
                entry.kind,
                VdsoEntryKind::Known(KnownEntry::Enosys) | VdsoEntryKind::Unknown
            )
        });
        assert_eq!(
            is_patch_required(&[Sysno::read].into_iter().collect()),
            has_non_syscall_entry,
        );

        for entry in &table.entries {
            if let VdsoEntryKind::Known(KnownEntry::Syscall(_, sysno)) = entry.kind {
                assert!(
                    is_patch_required(&[sysno].into_iter().collect()),
                    "a subscription for vDSO syscall {sysno:?} must require patching",
                );
            }
        }
    }

    #[test]
    fn each_subscription_selects_only_its_own_vdso_syscall_entries() {
        let table = host_table();
        for entry in &table.entries {
            let VdsoEntryKind::Known(KnownEntry::Syscall(_, subscribed_sysno)) = entry.kind else {
                continue;
            };
            let subscriptions = [subscribed_sysno].into_iter().collect();
            let selected = vdso_replacements(&subscriptions).unwrap();

            assert!(
                selected
                    .iter()
                    .any(|(selected, _)| selected.offset == entry.offset),
                "{subscribed_sysno:?} did not select its own entry point"
            );
            for (selected, _) in selected {
                match selected.kind {
                    VdsoEntryKind::Known(KnownEntry::Syscall(_, selected_sysno)) => assert_eq!(
                        selected_sysno,
                        subscribed_sysno,
                        "subscription for {subscribed_sysno:?} also selected {}",
                        selected.describe()
                    ),
                    VdsoEntryKind::Known(KnownEntry::Enosys) | VdsoEntryKind::Unknown => {}
                    VdsoEntryKind::Known(KnownEntry::Native) => {
                        panic!("{} is kept native but was selected", selected.describe())
                    }
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn getcpu_only_leaves_other_vdso_syscall_entries_unselected() {
        let subscriptions = [Sysno::getcpu].into_iter().collect();
        let selected = vdso_replacements(&subscriptions)
            .unwrap()
            .into_iter()
            .filter(|(entry, _)| {
                matches!(entry.kind, VdsoEntryKind::Known(KnownEntry::Syscall(..)))
            })
            .map(|(entry, _)| entry.names[0].as_str())
            .collect::<Vec<_>>();

        assert_eq!(selected, vec!["__vdso_getcpu"]);
    }
}
