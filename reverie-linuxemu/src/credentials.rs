/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The credentials a guest starts with and their change at execve (gVisor:
//! pkg/sentry/kernel/auth).
//!
//! A guest is a process its launcher spawns, so it starts with what a child
//! of the launcher has after exec: the launcher's capability sets put through
//! Linux's exec rule, its umask, and its personality. Its supplementary groups are the
//! launcher's, answered by the host (`getgroups` in the executor). LinuxEmu
//! changes no uid or gid (the Tool decides those calls), so whether the guest
//! counts as root at a later exec is fixed by the launcher's ids.

use std::sync::OnceLock;

/// A process's capability sets, one bit per capability number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilitySets {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

/// Which of a process's ids are root in its user namespace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RootIds {
    pub effective: bool,
    pub real: bool,
}

impl CapabilitySets {
    /// Linux's capability change at execve of a file that has no file
    /// capabilities and changes no id (`cap_bprm_creds_from_file` and
    /// `handle_privileged_root` in security/commoncap.c at v6.18):
    /// - a root effective or real uid gets pP' = cap_bset | pI (L840-843);
    /// - the ambient set is kept and joins pP' (L957-964);
    /// - pE' = pP' when the effective uid is root, else pA' (L848-849,
    ///   L970-973);
    /// - the inheritable and bounding sets do not change.
    ///
    /// <https://github.com/torvalds/linux/blob/v6.18/security/commoncap.c#L909>
    pub fn after_exec(self, root: RootIds) -> Self {
        let mut permitted = if root.effective || root.real {
            self.bounding | self.inheritable
        } else {
            0
        };
        permitted |= self.ambient;
        let effective = if root.effective {
            permitted
        } else {
            self.ambient
        };
        Self {
            effective,
            permitted,
            ..self
        }
    }
}

/// The launching process's credentials, as the host kernel reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LauncherCredentials {
    pub capabilities: CapabilitySets,
    pub root: RootIds,
    pub umask: libc::mode_t,
    pub personality: u32,
}

impl LauncherCredentials {
    /// This process's credentials, read once. A process does not change its
    /// own credentials while it runs guests.
    pub fn get() -> std::io::Result<Self> {
        static CREDENTIALS: OnceLock<Result<LauncherCredentials, (std::io::ErrorKind, String)>> =
            OnceLock::new();
        CREDENTIALS
            .get_or_init(|| Self::read().map_err(|error| (error.kind(), error.to_string())))
            .clone()
            .map_err(|(kind, message)| std::io::Error::new(kind, message))
    }

    fn read() -> std::io::Result<Self> {
        Ok(Self {
            capabilities: read_capability_sets()?,
            root: RootIds {
                // SAFETY: geteuid and getuid cannot fail.
                effective: unsafe { libc::geteuid() } == 0,
                // SAFETY: as above.
                real: unsafe { libc::getuid() } == 0,
            },
            umask: read_umask()?,
            personality: read_personality()?,
        })
    }

    /// The capability sets a guest this process spawns starts with.
    pub fn guest_capabilities(&self) -> CapabilitySets {
        self.capabilities.after_exec(self.root)
    }
}

/// The host kernel's highest capability number, from
/// /proc/sys/kernel/cap_last_cap, or the highest one `PR_CAPBSET_READ`
/// accepts when that file is unreadable.
pub fn last_capability() -> u64 {
    static LAST: OnceLock<u64> = OnceLock::new();
    *LAST.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .filter(|last| *last < 64)
            .unwrap_or_else(|| {
                // SAFETY: PR_CAPBSET_READ takes a capability number and no
                // pointer; it fails with EINVAL above the last one.
                (0..64_u64)
                    .take_while(|capability| unsafe {
                        libc::prctl(libc::PR_CAPBSET_READ, *capability, 0, 0, 0) >= 0
                    })
                    .last()
                    .unwrap_or(0)
            })
    })
}

/// One bit for every capability the host kernel has.
pub fn capability_mask() -> u64 {
    u64::MAX >> (63 - last_capability())
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn read_capability_sets() -> std::io::Result<CapabilitySets> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: header and data are the version-3 capget ABI's header and
    // two-element data array, writable for the call.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let join = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
    let mut bounding = 0;
    let mut ambient = 0;
    for capability in 0..=last_capability() {
        // SAFETY: both prctl operations take a capability number and no
        // pointer.
        let (in_bounding, in_ambient) = unsafe {
            (
                libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0),
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    capability,
                    0,
                    0,
                ),
            )
        };
        if in_bounding < 0 || in_ambient < 0 {
            return Err(std::io::Error::last_os_error());
        }
        bounding |= u64::from(in_bounding == 1) << capability;
        ambient |= u64::from(in_ambient == 1) << capability;
    }
    Ok(CapabilitySets {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
        bounding,
        ambient,
    })
}

/// The launching process's personality, queried as Linux queries it: the
/// query form of `personality(2)`
/// (<https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/exec_domain.c?h=v6.17#n38>).
/// A guest this process spawns inherits it, as a child process does at
/// fork (task copy in kernel/fork.c) and exec (fs/exec.c, binfmt_elf).
fn read_personality() -> std::io::Result<u32> {
    // SAFETY: the query sentinel takes no pointer.
    let result = unsafe { libc::personality(u32::MAX as libc::c_ulong) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(result as u32)
}

/// The personality a guest starts with: the launcher's, with
/// ADDR_NO_RANDOMIZE set. LinuxEmu always places mappings at fixed
/// addresses (its layout has no ASLR, as a traced guest's does under
/// Reverie's launcher, which sets the same bit on the tracee), so that
/// one bit is the layout LinuxEmu actually implements, not an inherited
/// choice.
pub fn guest_personality(launcher: u32) -> u32 {
    launcher | libc::ADDR_NO_RANDOMIZE as u32
}

/// Launcher personality bits a guest may not start with, because LinuxEmu
/// implements no effect for them (include/uapi/linux/personality.h): a
/// non-Linux execution domain (the low byte), ADDR_COMPAT_LAYOUT (legacy
/// bottom-up placement), MMAP_PAGE_ZERO and SHORT_INODE. A load under
/// such a launcher is refused rather than reporting flags with no effect.
pub const PERSONALITY_EXECUTION_DOMAIN: u32 = 0xff;
pub const PERSONALITY_ADDR_COMPAT_LAYOUT: u32 = 0x0020_0000;
pub const PERSONALITY_MMAP_PAGE_ZERO: u32 = 0x0010_0000;
pub const PERSONALITY_SHORT_INODE: u32 = 0x0100_0000;
pub const UNIMPLEMENTED_LAUNCHER_PERSONALITY: u32 = PERSONALITY_EXECUTION_DOMAIN
    | PERSONALITY_ADDR_COMPAT_LAYOUT
    | PERSONALITY_MMAP_PAGE_ZERO
    | PERSONALITY_SHORT_INODE;

/// The umask from /proc/self/status, which reads it without the set and
/// restore that umask(2) needs.
fn read_umask() -> std::io::Result<libc::mode_t> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|value| libc::mode_t::from_str_radix(value.trim(), 8).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "/proc/self/status has no Umask line",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u64 = (1 << 41) - 1;

    #[test]
    fn root_exec_gets_the_bounding_set_and_keeps_ambient() {
        let before = CapabilitySets {
            effective: 0,
            permitted: 0,
            inheritable: 1 << 3,
            bounding: ALL & !(1 << 5),
            ambient: 0,
        };
        let after = before.after_exec(RootIds {
            effective: true,
            real: true,
        });
        assert_eq!(after.permitted, ALL & !(1 << 5));
        assert_eq!(after.effective, after.permitted);
        assert_eq!(after.inheritable, 1 << 3);
        assert_eq!(after.bounding, before.bounding);
        assert_eq!(after.ambient, 0);
    }

    #[test]
    fn real_root_only_gets_permitted_but_not_effective() {
        let before = CapabilitySets {
            effective: ALL,
            permitted: ALL,
            inheritable: 0,
            bounding: ALL,
            ambient: 1 << 7,
        };
        let after = before.after_exec(RootIds {
            effective: false,
            real: true,
        });
        assert_eq!(after.permitted, ALL);
        assert_eq!(after.effective, 1 << 7, "pE' = pA' without effective root");
        assert_eq!(after.ambient, 1 << 7);
    }

    #[test]
    fn non_root_exec_keeps_only_ambient() {
        let before = CapabilitySets {
            effective: ALL,
            permitted: ALL,
            inheritable: (1 << 7) | (1 << 35),
            bounding: ALL,
            ambient: 1 << 7,
        };
        let after = before.after_exec(RootIds::default());
        assert_eq!(after.permitted, 1 << 7);
        assert_eq!(after.effective, 1 << 7);
        assert_eq!(after.inheritable, (1 << 7) | (1 << 35));
        assert_eq!(after.bounding, ALL);
        assert_eq!(after.ambient, 1 << 7);

        let none = CapabilitySets {
            ambient: 0,
            ..before
        }
        .after_exec(RootIds::default());
        assert_eq!((none.permitted, none.effective), (0, 0));
    }

    #[test]
    fn unimplemented_launcher_personality_covers_each_refused_bit() {
        for bit in [
            PERSONALITY_EXECUTION_DOMAIN,
            PERSONALITY_ADDR_COMPAT_LAYOUT,
            PERSONALITY_MMAP_PAGE_ZERO,
            PERSONALITY_SHORT_INODE,
        ] {
            assert_ne!(bit & UNIMPLEMENTED_LAUNCHER_PERSONALITY, 0, "bit {bit:#x}");
        }
        // The bits LinuxEmu does implement stay allowed.
        for bit in [libc::ADDR_NO_RANDOMIZE as u32, 0x0002_0000, 0x0400_0000] {
            assert_eq!(bit & UNIMPLEMENTED_LAUNCHER_PERSONALITY, 0, "bit {bit:#x}");
        }
    }

    #[test]
    fn launcher_credentials_are_this_process_s() {
        let credentials = LauncherCredentials::get().unwrap();
        // SAFETY: geteuid and getuid cannot fail.
        let (euid, uid) = unsafe { (libc::geteuid(), libc::getuid()) };
        assert_eq!(credentials.root.effective, euid == 0);
        assert_eq!(credentials.root.real, uid == 0);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| {
            let line = status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap();
            u64::from_str_radix(line.trim(), 16).unwrap()
        };
        assert_eq!(credentials.capabilities.inheritable, field("CapInh:"));
        assert_eq!(credentials.capabilities.permitted, field("CapPrm:"));
        assert_eq!(credentials.capabilities.effective, field("CapEff:"));
        assert_eq!(credentials.capabilities.bounding, field("CapBnd:"));
        assert_eq!(credentials.capabilities.ambient, field("CapAmb:"));
        let umask = status
            .lines()
            .find_map(|line| line.strip_prefix("Umask:"))
            .unwrap();
        assert_eq!(
            credentials.umask,
            libc::mode_t::from_str_radix(umask.trim(), 8).unwrap()
        );
        // SAFETY: the query sentinel takes no pointer.
        let personality = unsafe { libc::personality(u32::MAX as libc::c_ulong) };
        assert_eq!(credentials.personality, personality as u32);
        assert_eq!(
            guest_personality(credentials.personality),
            credentials.personality | libc::ADDR_NO_RANDOMIZE as u32
        );
        assert_eq!(
            credentials.capabilities.bounding & !capability_mask(),
            0,
            "no bounding bit above the host's last capability"
        );
    }
}
