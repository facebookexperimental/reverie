/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! vDSO operations on a stopped guest, using the shared process classification.
use nix::sys::mman::ProtFlags;
use reverie::Errno;
use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mprotect;
use reverie::vdso::PATCH_FILL;
use reverie::vdso::current_vdso_mapping_len;
pub(crate) use reverie::vdso::is_patch_required;
use reverie::vdso::vdso_replacements;
use tracing::debug;

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
    let Some(mapping_len) = current_vdso_mapping_len()? else {
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
        if guest_len != mapping_len {
            return Err(Error::from(std::io::Error::other(format!(
                "guest {} maps a {guest_len}-byte vDSO, but the patch plan is for the \
                 tracer's {}-byte vDSO",
                guest.pid(),
                mapping_len
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
