/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The host-kernel probes of a mapping of a file on overlayfs
// (`super::host_probe`, `super::vm_flags::FileVmFacts::of`), on overlays an
// unprivileged test makes in a user and mount namespace of its own: each test
// runs its body in a child process of this test binary (`in_namespace`),
// where it is root and mounts what it needs. The layers are tmpfs, whose
// `huge=` option it chooses, and a directory of the filesystem the test runs
// on, so the probe runs over a hook it can see and one it cannot.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::host_probe::PMD_SIZE;
use super::vm_flags::FileVmFacts;
use super::vm_flags::MapShape;

const PAGE: u64 = 4096;
const R: u8 = libc::PROT_READ as u8;
const RW: u8 = (libc::PROT_READ | libc::PROT_WRITE) as u8;
const RX: u8 = (libc::PROT_READ | libc::PROT_EXEC) as u8;

/// A directory of this test's own, removed when dropped.
pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    pub(super) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-linuxemu-host-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Between fork and exec: a new user namespace that maps the caller to
/// root, and a new mount namespace.
struct UserNamespace {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
}

impl UserNamespace {
    fn new() -> Self {
        // SAFETY: geteuid and getegid have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Self {
            uid_map: format!("0 {uid} 1").into_bytes(),
            gid_map: format!("0 {gid} 1").into_bytes(),
        }
    }

    fn write(path: &std::ffi::CStr, bytes: &[u8]) -> std::io::Result<()> {
        // SAFETY: path is NUL-terminated and bytes is a live buffer of its
        // length; the descriptor is closed before returning.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
            let error = std::io::Error::last_os_error();
            libc::close(fd);
            if written != bytes.len() as isize {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Only system calls, and no allocation: this runs in the forked child.
    fn enter(&self) -> std::io::Result<()> {
        // SAFETY: unshare takes no pointers.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Self::write(c"/proc/self/setgroups", b"deny")?;
        Self::write(c"/proc/self/uid_map", &self.uid_map)?;
        Self::write(c"/proc/self/gid_map", &self.gid_map)
    }
}

/// Whether this process is the child [`in_namespace`] started for `test`, a
/// test of the module whose path is `module` (its `module_path!()`). In the
/// parent, runs exactly that test in a child process of this test binary, in
/// a new user and mount namespace ([`UserNamespace`]), checks that it passed,
/// and answers false.
pub(super) fn in_namespace(module: &str, test: &str) -> bool {
    const TEST: &str = "REVERIE_LINUXEMU_HOST_PROBE_TEST";
    if std::env::var(TEST).as_deref() == Ok(test) {
        return true;
    }
    let results = Scratch::new();
    let log = results.0.join("libtest.log");
    let module = module.split_once("::").map_or(module, |(_, path)| path);
    let name = format!("{module}::{test}");
    let namespace = UserNamespace::new();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &name,
            "--nocapture",
            "--test-threads=1",
            "--logfile",
        ])
        .arg(&log)
        .env(TEST, test);
    // SAFETY: enter makes only system calls and allocates nothing.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut command, move || namespace.enter())
    };
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{test} in its namespace: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Exactly one completed, passing run of this test, and no other.
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        format!("ok {name}\n"),
        "{test}: the child's execution record"
    );
    false
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

/// Mounts `filesystem` at `target`, with mount data `data`.
fn mount(source: &str, target: &Path, filesystem: &str, flags: libc::c_ulong, data: &str) {
    let (source, filesystem, data) = (
        CString::new(source).unwrap(),
        CString::new(filesystem).unwrap(),
        CString::new(data).unwrap(),
    );
    let target = c_path(target);
    // SAFETY: the strings are NUL-terminated and live for the call.
    let mounted = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags | libc::MS_NOSUID | libc::MS_NODEV,
            data.as_ptr().cast(),
        )
    };
    assert_eq!(
        mounted,
        0,
        "mount {filesystem:?} at {target:?}: {}",
        std::io::Error::last_os_error()
    );
}

/// The mounts of [`overlay`], removed when dropped (before the directory
/// that holds them), so that nothing of them is left behind.
pub(super) struct Overlay {
    pub(super) merged: PathBuf,
    tmpfs: PathBuf,
}

impl Drop for Overlay {
    fn drop(&mut self) {
        for target in [&self.merged, &self.tmpfs] {
            let target = c_path(target);
            // SAFETY: the path is NUL-terminated and lives for the call.
            unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
        }
    }
}

/// In `root`: a tmpfs `tmpfs` mounted with `huge=<huge>`, holding `file` of
/// `size` bytes; a directory `disk` of the filesystem the test runs on,
/// holding `disk-file` of the same size; and a read-only overlay of the two
/// at `merged`, so that `merged/file` is the tmpfs layer's and
/// `merged/disk-file` the other's.
pub(super) fn overlay(root: &Path, huge: &str, size: u64) -> Overlay {
    let (tmpfs, disk, merged) = (root.join("tmpfs"), root.join("disk"), root.join("merged"));
    for directory in [&tmpfs, &disk, &merged] {
        std::fs::create_dir(directory).unwrap();
    }
    mount("tmpfs", &tmpfs, "tmpfs", 0, &format!("huge={huge}"));
    for (directory, name) in [(&tmpfs, "file"), (&disk, "disk-file")] {
        let file = std::fs::File::create(directory.join(name)).unwrap();
        file.set_len(size).unwrap();
    }
    mount(
        "overlay",
        &merged,
        "overlay",
        libc::MS_RDONLY,
        &format!("lowerdir={}:{}", tmpfs.display(), disk.display()),
    );
    Overlay { merged, tmpfs }
}

/// A file on overlayfs, from either kind of layer, has the facts of a file
/// whose hook adds no flag, once the host kernel's mapping of each shape the
/// guest asked for prints exactly the flags those facts give: read-only,
/// executable at an offset, shared, and private writable (charged). A file
/// on overlayfs with no shape probed has none, and a line's `THPeligible` is
/// probed for it.
#[test]
fn an_overlayfs_file_takes_the_neutral_facts_its_probes_find() {
    if !in_namespace(
        module_path!(),
        "an_overlayfs_file_takes_the_neutral_facts_its_probes_find",
    ) {
        return;
    }
    let scratch = Scratch::new();
    let overlay = overlay(&scratch.0, "never", 4 * PAGE);
    let merged = &overlay.merged;
    let shapes = [
        MapShape {
            prot: R,
            shared: false,
            offset: 0,
        },
        MapShape {
            prot: RX,
            shared: false,
            offset: PAGE,
        },
        MapShape {
            prot: R,
            shared: true,
            offset: 0,
        },
        MapShape {
            prot: RW,
            shared: false,
            offset: 2 * PAGE,
        },
    ];
    for name in ["file", "disk-file"] {
        let file = std::fs::File::open(merged.join(name)).unwrap();
        assert_eq!(
            FileVmFacts::of(&file, &shapes),
            Some(FileVmFacts {
                writable: false,
                write_sealed: false,
                noexec: false,
                refuses_sync: true,
            }),
            "{name}"
        );
        assert_eq!(FileVmFacts::of(&file, &[]), None, "{name}: nothing probed");
        assert!(super::vm_flags::thp_eligibility_is_probed(&file), "{name}");
    }
}

/// A flag the address space gives every new mapping (`mlockall(MCL_FUTURE)`'s
/// `VM_LOCKED`) is in the probe's mapping too, which then differs from what
/// the facts give: the file's facts are not known, until the address space
/// stops adding it.
#[test]
fn a_flag_the_address_space_adds_to_every_mapping_fails_the_probe() {
    if !in_namespace(
        module_path!(),
        "a_flag_the_address_space_adds_to_every_mapping_fails_the_probe",
    ) {
        return;
    }
    let scratch = Scratch::new();
    let overlay = overlay(&scratch.0, "never", 4 * PAGE);
    let file = std::fs::File::open(overlay.merged.join("file")).unwrap();
    let shapes = [MapShape {
        prot: R,
        shared: false,
        offset: 0,
    }];
    // SAFETY: changes only this child process's future mappings.
    assert_eq!(unsafe { libc::mlockall(libc::MCL_FUTURE) }, 0);
    let locked = FileVmFacts::of(&file, &shapes);
    // SAFETY: as above.
    assert_eq!(unsafe { libc::munlockall() }, 0);
    assert_eq!(locked, None);
    assert!(FileVmFacts::of(&file, &shapes).is_some());
}

/// The `THPeligible` of an overlayfs file's mapping is its layer's: on a
/// tmpfs layer mounted `huge=always`, which allows every order a file may
/// have, 1 for a read-only 2 MiB mapping of a 4 MiB file at an aligned
/// address, and 0 for one a page off, to which no such order's block is
/// aligned; on a `huge=never` layer, and on the other layer, whose files are
/// not shmem and that no advice reached, 0 under the host's settings but
/// `always`.
#[test]
fn thp_eligibility_of_an_overlayfs_file_follows_its_layer() {
    if !in_namespace(
        module_path!(),
        "thp_eligibility_of_an_overlayfs_file_follows_its_layer",
    ) {
        return;
    }
    let eligible = |merged: &Path, name: &str, start: u64| {
        let file = std::fs::File::open(merged.join(name)).unwrap();
        super::host_probe::thp_eligible(&file, R, false, 0, start, start + PMD_SIZE)
    };
    let aligned = 0x7f00_0000_0000;
    let always = Scratch::new();
    let overlay_always = overlay(&always.0, "always", 2 * PMD_SIZE);
    let merged = &overlay_always.merged;
    assert_eq!(eligible(merged, "file", aligned), Some(true));
    assert_eq!(eligible(merged, "file", aligned + PAGE), Some(false));
    let global = std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled").unwrap();
    if !global.contains("[always]") {
        assert_eq!(eligible(merged, "disk-file", aligned), Some(false));
    }
    let never = Scratch::new();
    let overlay_never = overlay(&never.0, "never", 2 * PMD_SIZE);
    assert_eq!(
        eligible(&overlay_never.merged, "file", aligned),
        Some(false)
    );
}
