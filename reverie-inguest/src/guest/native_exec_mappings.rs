//! Executable mapping checks against retained native immutable-object owners.
//!
//! These checks apply before every physical guest mapping operation. Procfs is
//! a current mapping observation; the unsafe installed owner supplies immutable
//! catalog identity, the protected address ranges and writer exclusion.

use super::native_exec_arguments::ArgumentRange;

const PAGE: u64 = 4096;
const MAX_MAP_BYTES: usize = 4 * 1024 * 1024;
const REQUIRED_SEALS: i32 = libc::F_SEAL_SEAL
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_GROW
    | libc::F_SEAL_WRITE
    | libc::F_SEAL_FUTURE_WRITE
    | 0x0020; // F_SEAL_EXEC.

/// Page-rounded file extent of a genuinely inspected executable PT_LOAD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutableExtent {
    /// Inclusive file offset, aligned to the native page size.
    pub start: u64,
    /// Exclusive page-rounded file end (the final page may contain ELF tail).
    pub end: u64,
}

/// Immutable backing authenticated by the actual installed native owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableBacking {
    /// The independently held descriptor retains all required memfd seals.
    Sealed,
    /// Exact named tmpfs copy in the admitted, frozen common root.
    ReadonlyRoot {
        /// Mount of the retained final readonly file descriptor.
        mount_id: u64,
        /// Entire independently observed regular-file mode, not a mask.
        mode: u32,
    },
}

/// Actual file identity, populated only by the native admission owner.
/// This data does not itself authenticate a file, an ELF or a launch.
pub struct ExecutableObject {
    /// Device queried from the independently retained admitted descriptor.
    pub device: u64,
    /// Inode queried from that same descriptor.
    pub inode: u64,
    /// Exact retained file length.
    pub size: u64,
    /// Independently authenticated immutability mechanism for this identity.
    pub backing: ExecutableBacking,
    /// Only the executable PT_LOAD file extents, not arbitrary file bytes.
    pub extents: Box<[ExecutableExtent]>,
}

/// Retained mapping policy of one actual installed native image.
pub struct ExecutableMappings {
    objects: Box<[ExecutableObject]>,
    protected: Box<[ArgumentRange]>,
}

impl ExecutableMappings {
    /// # Safety
    /// The caller is the actual native initializer, has joined each identity
    /// to independently expected bytes and complete ELF PT_LOADs, and
    /// retains the closed common root and all original file owners. `protected`
    /// covers every qualified Tool/gate/control/continuation mapping. There is
    /// exactly one guest thread, no mapping/fd-table mutation between check and
    /// physical operation, no mutable alias or external/asynchronous writer,
    /// and the owned proc maps leaf always names this actual running image.
    /// Root copies have been joined to their retained sealed sources, exact
    /// root/namespace/mount, final freeze and absence of writable aliases/FDs;
    /// readonly observations alone do not establish this premise.
    /// Guest requests cannot create or alter these expectations. Initial and
    /// completion map scans remain independently required.
    pub unsafe fn new(
        objects: Box<[ExecutableObject]>,
        protected: Box<[ArgumentRange]>,
    ) -> Result<Self, &'static str> {
        if objects.is_empty()
            || protected.iter().any(|range| range.start >= range.end)
            || objects.iter().any(|object| {
                object.inode == 0
                    || object.size == 0
                    || !backing_shape(object.backing)
                    || object.extents.is_empty()
                    || object.extents.iter().any(|extent| {
                        extent.start >= extent.end
                            || extent.start % PAGE != 0
                            || extent.end % PAGE != 0
                            || extent.end > object.size.saturating_add(PAGE - 1) / PAGE * PAGE
                    })
            })
        {
            return Err("native executable catalog is malformed");
        }
        if objects.iter().enumerate().any(|(index, object)| {
            objects[..index]
                .iter()
                .any(|other| other.device == object.device && other.inode == object.inode)
        }) {
            return Err("native executable backing identity is duplicated");
        }
        Ok(Self { objects, protected })
    }

    /// Inspect actual operands and current mappings immediately before the
    /// physical call. A refusal is a domain error, never a kernel errno.
    pub fn check(&self, number: i64, args: [u64; 6]) -> Result<(), &'static str> {
        if number == libc::SYS_personality {
            if args[0] as u32 != u32::MAX && args[0] as u32 & libc::READ_IMPLIES_EXEC as u32 != 0 {
                return Err("native guest READ_IMPLIES_EXEC is unsupported");
            }
            return Ok(());
        }
        if number == libc::SYS_remap_file_pages
            || (number == libc::SYS_shmat && args[2] as i32 & libc::SHM_EXEC != 0)
        {
            return Err("native executable remapping route is unsupported");
        }
        if !matches!(
            number,
            libc::SYS_mmap | libc::SYS_mprotect | libc::SYS_pkey_mprotect
        ) {
            return Ok(());
        }
        if args[2] as i32 & !(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) != 0 {
            return Err("native guest protection modifiers are unsupported");
        }
        let executable = args[2] as i32 & libc::PROT_EXEC != 0;
        let writable = args[2] as i32 & libc::PROT_WRITE != 0;
        if !executable && !writable {
            return Ok(());
        }
        // READ_IMPLIES_EXEC must also be absent in the actual current task,
        // regardless of whether it was requested through a guest callback.
        let personality = raw(libc::SYS_personality, [u32::MAX as u64, 0, 0, 0, 0, 0]);
        if personality < 0 || personality as u32 & libc::READ_IMPLIES_EXEC as u32 != 0 {
            return Err("native executable personality differs");
        }
        if executable && writable {
            return Err("native writable executable mapping is unsupported");
        }
        let length = round_length(args[1]).ok_or("native executable mapping range is malformed")?;
        if number == libc::SYS_mmap {
            let flags = args[3] as i32;
            if flags & libc::MAP_ANONYMOUS != 0 {
                return if executable {
                    Err("native anonymous executable mmap is unsupported")
                } else {
                    Ok(())
                };
            }
            if executable
                && (flags & libc::MAP_TYPE != libc::MAP_PRIVATE || !args[5].is_multiple_of(PAGE))
            {
                return Err("native executable mmap requires an admitted private file");
            }
            if executable && flags & (libc::MAP_FIXED | libc::MAP_FIXED_NOREPLACE) != 0 {
                self.check_range(args[0], length)?;
            }
            let fd = args[4] as i32;
            let mut stat = core::mem::MaybeUninit::<libc::stat>::zeroed();
            if raw(
                libc::SYS_fstat,
                [fd as u64, stat.as_mut_ptr() as u64, 0, 0, 0, 0],
            ) != 0
            {
                return if executable {
                    Err("native executable file descriptor is unavailable")
                } else {
                    Ok(())
                };
            }
            let stat = unsafe { stat.assume_init() };
            if !executable {
                // Prevent a private writable COW text page from later being
                // relabelled RX. Ordinary writable ELF data/BSS stays admitted.
                if self.objects.iter().any(|object| {
                    object.device == stat.st_dev
                        && object.inode == stat.st_ino
                        && extent_overlaps(object, args[5], length)
                }) {
                    return Err("native guest writable catalog text is unsupported");
                }
                return Ok(());
            }
            if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size < 0 {
                return Err("native executable mmap file or PT_LOAD is not admitted");
            }
            let mut admitted = self.objects.iter().filter(|object| {
                object.device == stat.st_dev
                    && object.inode == stat.st_ino
                    && object.size == stat.st_size as u64
                    && extent_contains(object, args[5], length)
            });
            let object = admitted
                .next()
                .ok_or("native executable mmap file or PT_LOAD is not admitted")?;
            if admitted.next().is_some() {
                return Err("native executable mmap has ambiguous backing authority");
            }
            check_backing(fd, &stat, object.backing)?;
            return Ok(());
        }
        if executable {
            self.check_range(args[0], length)?;
        }
        if executable && number == libc::SYS_pkey_mprotect && !matches!(args[3] as i32, -1 | 0) {
            return Err("native executable pkey is unsupported");
        }
        self.check_current_mappings(args[0], length, executable)
    }

    fn check_range(&self, start: u64, length: u64) -> Result<(), &'static str> {
        let end = start
            .checked_add(length)
            .ok_or("native executable range overflow")?;
        if start == 0
            || !start.is_multiple_of(PAGE)
            || self
                .protected
                .iter()
                .any(|range| start < range.end as u64 && end > range.start as u64)
        {
            return Err("native guest executable mapping overlaps protected runtime");
        }
        Ok(())
    }

    fn check_current_mappings(
        &self,
        start: u64,
        length: u64,
        executable: bool,
    ) -> Result<(), &'static str> {
        let end = start
            .checked_add(length)
            .ok_or("native executable range overflow")?;
        let fd = raw(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as i64 as u64,
                c"/proc/self/maps".as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        );
        if fd < 0 {
            return Err("native owned maps leaf is unavailable");
        }
        let result = self.read_mappings(fd as i32, start, end, executable);
        if raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) != 0 {
            return Err("native owned maps leaf close failed");
        }
        result
    }

    fn read_mappings(
        &self,
        fd: i32,
        mut cursor: u64,
        end: u64,
        executable: bool,
    ) -> Result<(), &'static str> {
        let mut block = [0u8; 4096];
        let mut line = [0u8; 4096];
        let mut used = 0usize;
        let mut total = 0usize;
        loop {
            let count = raw(
                libc::SYS_read,
                [
                    fd as u64,
                    block.as_mut_ptr() as u64,
                    block.len() as u64,
                    0,
                    0,
                    0,
                ],
            );
            if count < 0 {
                return Err("native owned maps read failed");
            }
            if count == 0 {
                break;
            }
            total += count as usize;
            if total > MAX_MAP_BYTES {
                return Err("native owned maps exceeds bound");
            }
            for byte in &block[..count as usize] {
                if *byte != b'\n' {
                    if used == line.len() {
                        return Err("native owned maps line exceeds bound");
                    }
                    line[used] = *byte;
                    used += 1;
                    continue;
                }
                let map = parse_map(&line[..used]).ok_or("native owned maps is malformed")?;
                used = 0;
                if map.end <= cursor || map.start >= end {
                    continue;
                }
                if map.start > cursor
                    || (executable && (!map.private || map.writable || map.inode == 0))
                {
                    return Err("native executable protection spans unadmitted memory");
                }
                let part_end = map.end.min(end);
                let offset = map
                    .offset
                    .checked_add(cursor - map.start)
                    .ok_or("native executable offset overflow")?;
                if executable {
                    if !self.objects.iter().any(|object| {
                        object.device == map.device
                            && object.inode == map.inode
                            && extent_contains(object, offset, part_end - cursor)
                    }) {
                        return Err("native executable protection is outside admitted PT_LOAD");
                    }
                } else if self.objects.iter().any(|object| {
                    object.device == map.device
                        && object.inode == map.inode
                        && extent_overlaps(object, offset, part_end - cursor)
                }) {
                    return Err("native guest writable catalog text is unsupported");
                }
                cursor = part_end;
            }
        }
        if used != 0 || cursor != end {
            return Err("native executable maps coverage is incomplete");
        }
        Ok(())
    }
}

fn round_length(length: u64) -> Option<u64> {
    (length != 0).then_some(length.checked_add(PAGE - 1)? / PAGE * PAGE)
}
fn backing_shape(backing: ExecutableBacking) -> bool {
    match backing {
        ExecutableBacking::Sealed => true,
        ExecutableBacking::ReadonlyRoot { mount_id, mode } => {
            mount_id != 0
                && mode & libc::S_IFMT == libc::S_IFREG
                && mode & (libc::S_ISUID | libc::S_ISGID | 0o222) == 0
                && mode & 0o111 != 0
        }
    }
}

fn check_backing(
    fd: i32,
    stat: &libc::stat,
    backing: ExecutableBacking,
) -> Result<(), &'static str> {
    match backing {
        ExecutableBacking::Sealed => {
            let seals = raw(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GET_SEALS as u64, 0, 0, 0, 0],
            );
            if seals < 0 || seals as i32 & REQUIRED_SEALS != REQUIRED_SEALS {
                return Err("native sealed executable lacks complete immutable seals");
            }
        }
        ExecutableBacking::ReadonlyRoot { mount_id, mode } => {
            if !backing_shape(backing) || stat.st_mode != mode {
                return Err("native root executable mode differs");
            }
            let mut sx = core::mem::MaybeUninit::<libc::statx>::zeroed();
            if raw(
                libc::SYS_statx,
                [
                    fd as u64,
                    c"".as_ptr() as u64,
                    (libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW) as u64,
                    libc::STATX_MNT_ID as u64,
                    sx.as_mut_ptr() as u64,
                    0,
                ],
            ) != 0
            {
                return Err("native root executable mount identity unavailable");
            }
            let sx = unsafe { sx.assume_init() };
            if sx.stx_mask & libc::STATX_MNT_ID == 0 || sx.stx_mnt_id != mount_id {
                return Err("native root executable mount identity differs");
            }
            // Linux x86_64 uses this exact layout for SYS_fstatfs;
            // libc::statfs keeps the flags word private, statfs64 exposes it.
            const {
                assert!(core::mem::size_of::<libc::statfs64>() == 120);
                assert!(core::mem::align_of::<libc::statfs64>() == 8);
                assert!(core::mem::offset_of!(libc::statfs64, f_flags) == 80);
            }
            let mut fs = core::mem::MaybeUninit::<libc::statfs64>::zeroed();
            // Linux exposes these mount flags through fstatfs; fstatvfs is a
            // libc conversion, not another syscall. Keep the active guard on
            // the same raw fixed syscall route as every other observation.
            if raw(
                libc::SYS_fstatfs,
                [fd as u64, fs.as_mut_ptr() as u64, 0, 0, 0, 0],
            ) != 0
            {
                return Err("native root executable filesystem policy unavailable");
            }
            let fs = unsafe { fs.assume_init() };
            let required = (libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV) as i64;
            if fs.f_type != libc::TMPFS_MAGIC
                || fs.f_flags & required != required
                || fs.f_flags & libc::ST_NOEXEC as i64 != 0
            {
                return Err("native root executable filesystem policy differs");
            }
        }
    }
    Ok(())
}

fn extent_contains(object: &ExecutableObject, start: u64, length: u64) -> bool {
    start.checked_add(length).is_some_and(|end| {
        object
            .extents
            .iter()
            .any(|extent| extent.start <= start && end <= extent.end)
    })
}
fn extent_overlaps(object: &ExecutableObject, start: u64, length: u64) -> bool {
    start.checked_add(length).is_none_or(|end| {
        object
            .extents
            .iter()
            .any(|extent| extent.start < end && extent.end > start)
    })
}
struct Map {
    start: u64,
    end: u64,
    offset: u64,
    device: u64,
    inode: u64,
    private: bool,
    writable: bool,
}
fn parse_map(line: &[u8]) -> Option<Map> {
    let mut fields = line
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty());
    let range = fields.next()?;
    let dash = range.iter().position(|byte| *byte == b'-')?;
    let perms = fields.next()?;
    let offset = number(fields.next()?, 16)?;
    let device = fields.next()?;
    let colon = device.iter().position(|byte| *byte == b':')?;
    let major = u32::try_from(number(&device[..colon], 16)?).ok()?;
    let minor = u32::try_from(number(&device[colon + 1..], 16)?).ok()?;
    let inode = number(fields.next()?, 10)?;
    let start = number(&range[..dash], 16)?;
    let end = number(&range[dash + 1..], 16)?;
    if start >= end
        || start % PAGE != 0
        || end % PAGE != 0
        || offset % PAGE != 0
        || perms.len() != 4
        || !matches!(perms[0], b'r' | b'-')
        || !matches!(perms[1], b'w' | b'-')
        || !matches!(perms[2], b'x' | b'-')
        || !matches!(perms[3], b'p' | b's')
    {
        return None;
    }
    Some(Map {
        start,
        end,
        offset,
        device: libc::makedev(major, minor),
        inode,
        private: perms[3] == b'p',
        writable: perms[1] == b'w',
    })
}
fn number(bytes: &[u8], radix: u32) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if u32::from(digit) >= radix {
            return None;
        }
        value
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))
    })
}
fn raw(number: i64, args: [u64; 6]) -> i64 {
    unsafe { crate::trap::raw_syscall6(number, args) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping_policy_parser_and_extent_bounds_are_exact() {
        let map = parse_map(b"1000-3000 r-xp 00001000 00:01 77 /catalog/object").unwrap();
        assert_eq!(
            (map.start, map.end, map.offset, map.device, map.inode),
            (0x1000, 0x3000, 0x1000, libc::makedev(0, 1), 77)
        );
        assert!(map.private && !map.writable);
        assert!(parse_map(b"1000-1000 r-xp 0000 00:01 77").is_none());
        assert!(parse_map(b"1000-3000 r-xp 0000 00:01 junk").is_none());
        let object = ExecutableObject {
            device: 1,
            inode: 77,
            size: 0x3000,
            backing: ExecutableBacking::Sealed,
            extents: vec![ExecutableExtent {
                start: 0x1000,
                end: 0x3000,
            }]
            .into_boxed_slice(),
        };
        assert!(extent_contains(&object, 0x1000, 0x2000));
        assert!(!extent_contains(&object, 0, 0x1000));
        assert!(!extent_contains(&object, 0x2000, 0x2000));
        assert!(!extent_contains(&object, u64::MAX, 1));
        assert!(extent_overlaps(&object, 0x2000, 0x2000));
        assert!(!extent_overlaps(&object, 0x3000, 0x1000));
        assert!(extent_overlaps(&object, u64::MAX, 1));
        assert_eq!(round_length(1), Some(PAGE));
        assert_eq!(round_length(0), None);
        assert_eq!(round_length(u64::MAX), None);
    }

    #[test]
    fn sealed_mapping_checks_the_actual_fd_without_root_policy_substitution() {
        use std::os::fd::AsRawFd;
        use std::os::fd::FromRawFd;
        use std::os::fd::OwnedFd;
        let fd = unsafe {
            libc::memfd_create(
                c"native-mapping-control".as_ptr(),
                // MFD_EXEC, matching production seal_bytes and avoiding a
                // host-default noexec memfd policy in this positive control.
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x0010,
            )
        };
        assert!(fd >= 0);
        let file = unsafe { OwnedFd::from_raw_fd(fd) };
        assert_eq!(unsafe { libc::ftruncate(fd, PAGE as i64) }, 0);
        assert_eq!(unsafe { libc::fchmod(fd, 0o555) }, 0);
        let mut stat = core::mem::MaybeUninit::<libc::stat>::zeroed();
        assert_eq!(
            unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) },
            0
        );
        let stat = unsafe { stat.assume_init() };
        assert!(check_backing(fd, &stat, ExecutableBacking::Sealed).is_err());
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, REQUIRED_SEALS) },
            0
        );
        assert!(check_backing(fd, &stat, ExecutableBacking::Sealed).is_ok());
        // Complete seals do not grant any root/mount identity.
        assert!(
            check_backing(
                fd,
                &stat,
                ExecutableBacking::ReadonlyRoot {
                    mount_id: u64::MAX,
                    mode: stat.st_mode
                }
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(feature = "launcher")]
    fn readonly_root_mapping_checks_real_file_mount_mode_and_extent() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        use std::panic::AssertUnwindSafe;
        let directory = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                assert_eq!(
                    unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) },
                    0
                );
                std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).unwrap();
                std::fs::write("/proc/self/setgroups", b"deny\n").unwrap();
                std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).unwrap();
                assert_eq!(
                    unsafe {
                        libc::mount(
                            core::ptr::null(),
                            c"/".as_ptr(),
                            core::ptr::null(),
                            libc::MS_REC | libc::MS_PRIVATE,
                            core::ptr::null(),
                        )
                    },
                    0
                );
                let path = std::ffi::CString::new(directory.path().as_os_str().as_encoded_bytes())
                    .unwrap();
                assert_eq!(
                    unsafe {
                        libc::mount(
                            c"tmpfs".as_ptr(),
                            path.as_ptr(),
                            c"tmpfs".as_ptr(),
                            libc::MS_NOSUID | libc::MS_NODEV,
                            c"size=1m".as_ptr().cast(),
                        )
                    },
                    0
                );
                let target = directory.path().join("code");
                std::fs::write(&target, [0_u8; PAGE as usize]).unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o555)).unwrap();
                let file = std::fs::File::open(&target).unwrap();
                let fd = file.as_raw_fd();
                let metadata = file.metadata().unwrap();
                let mut sx = core::mem::MaybeUninit::<libc::statx>::zeroed();
                assert_eq!(
                    unsafe {
                        libc::statx(
                            fd,
                            c"".as_ptr(),
                            libc::AT_EMPTY_PATH,
                            libc::STATX_MNT_ID,
                            sx.as_mut_ptr(),
                        )
                    },
                    0
                );
                let sx = unsafe { sx.assume_init() };
                assert_ne!(sx.stx_mask & libc::STATX_MNT_ID, 0);
                let backing = ExecutableBacking::ReadonlyRoot {
                    mount_id: sx.stx_mnt_id,
                    mode: metadata.mode(),
                };
                let object = ExecutableObject {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    size: PAGE,
                    backing,
                    extents: vec![ExecutableExtent {
                        start: 0,
                        end: PAGE,
                    }]
                    .into_boxed_slice(),
                };
                // Private test data reaches the pre-call refusal while the
                // mount is still writable; it grants no installed authority.
                let policy = ExecutableMappings {
                    objects: vec![object].into_boxed_slice(),
                    protected: Box::new([]),
                };
                let args = [
                    0,
                    PAGE,
                    libc::PROT_READ as u64 | libc::PROT_EXEC as u64,
                    libc::MAP_PRIVATE as u64,
                    fd as u64,
                    0,
                ];
                assert!(
                    policy.check(libc::SYS_mmap, args).is_err(),
                    "writable mount must refuse"
                );
                assert_eq!(
                    unsafe {
                        libc::mount(
                            core::ptr::null(),
                            path.as_ptr(),
                            core::ptr::null(),
                            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
                            core::ptr::null(),
                        )
                    },
                    0
                );
                assert!(policy.check(libc::SYS_mmap, args).is_ok());
                let mut stat = core::mem::MaybeUninit::<libc::stat>::zeroed();
                assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
                let stat = unsafe { stat.assume_init() };
                assert!(check_backing(fd, &stat, ExecutableBacking::Sealed).is_err());
                for wrong in [
                    ExecutableBacking::ReadonlyRoot {
                        mount_id: sx.stx_mnt_id + 1,
                        mode: metadata.mode(),
                    },
                    ExecutableBacking::ReadonlyRoot {
                        mount_id: sx.stx_mnt_id,
                        mode: metadata.mode() ^ 0o100,
                    },
                ] {
                    assert!(check_backing(fd, &stat, wrong).is_err());
                }
                let mut wrong = args;
                wrong[5] = PAGE;
                assert!(policy.check(libc::SYS_mmap, wrong).is_err());
                wrong = args;
                wrong[2] |= libc::PROT_WRITE as u64;
                assert!(policy.check(libc::SYS_mmap, wrong).is_err());
                assert_eq!(
                    unsafe {
                        libc::mount(
                            core::ptr::null(),
                            path.as_ptr(),
                            core::ptr::null(),
                            libc::MS_REMOUNT
                                | libc::MS_RDONLY
                                | libc::MS_NOSUID
                                | libc::MS_NODEV
                                | libc::MS_NOEXEC,
                            core::ptr::null(),
                        )
                    },
                    0
                );
                assert!(
                    policy.check(libc::SYS_mmap, args).is_err(),
                    "noexec mount must refuse"
                );
            }));
            unsafe { libc::_exit(if outcome.is_ok() { 0 } else { 125 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
