/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Table-driven admission cases for bind and unmount. Every row
//! cites the page and section it comes from; each row faults in
//! exactly one way (or none), so no row depends on the model's
//! order among simultaneous faults. Cases marked "verified" were
//! additionally checked against the running kernel (the
//! differential test re-checks the admitted effects).

mod common;

use common::*;
use linux_ns_model::*;

#[derive(Clone, Copy)]
enum SeedKind {
    Standard,
    WithUnbindable,
}

#[derive(Debug)]
enum Expect {
    Admit,
    Refuse(Errno, &'static str),
}

struct BindCase {
    name: &'static str,
    cite: &'static str,
    seed: SeedKind,
    flags: u64,
    cap: bool,
    src: (u64, &'static [u8], FileType),
    tgt: (u64, &'static [u8], FileType),
    expect: Expect,
}

fn run_bind_case(case: &BindCase) {
    let (mut model, ns, _ids) = match case.seed {
        SeedKind::Standard => seeded_standard(),
        SeedKind::WithUnbindable => seeded_with_unbindable(),
    };
    let caller = caller(&model, ns, case.cap);
    let req = Request::Bind(BindRequest {
        source: b"/src".to_vec(),
        target: b"/tgt".to_vec(),
        flags: case.flags,
    });
    let facts = [
        fact(case.src.0, case.src.1, case.src.2, case.src.1.is_empty()),
        fact(case.tgt.0, case.tgt.1, case.tgt.2, case.tgt.1.is_empty()),
    ];
    match model.admit(&caller, &req, &facts).expect("no divergence") {
        Decision::Admit(pending) => {
            pending.abort();
            assert!(
                matches!(case.expect, Expect::Admit),
                "{} ({}): admitted, expected {:?}",
                case.name,
                case.cite,
                case.expect
            );
        }
        Decision::Refuse(r) => match &case.expect {
            Expect::Refuse(e, name) => {
                assert_eq!(r.errno, *e, "{} ({})", case.name, case.cite);
                assert_eq!(r.reason.name(), *name, "{} ({})", case.name, case.cite);
            }
            Expect::Admit => panic!(
                "{} ({}): refused {} {}, expected admit",
                case.name,
                case.cite,
                r.errno.code(),
                r.reason.name()
            ),
        },
    }
}

#[test]
fn bind_admission_table() {
    use FileType::*;
    let cases = [
        BindCase {
            name: "plain dir bind admitted",
            cite: "mount(2) MS_BIND: bind part of one filesystem onto another point",
            seed: SeedKind::Standard,
            flags: MS_BIND,
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Admit,
        },
        BindCase {
            name: "file bind admitted",
            cite: "mount(2) MS_BIND: since Linux 2.4 a file can be bound onto a file",
            seed: SeedKind::Standard,
            flags: MS_BIND,
            cap: true,
            src: (kid::ROOT, b"afile", RegularFile),
            tgt: (kid::ROOT, b"bfile", RegularFile),
            expect: Expect::Admit,
        },
        BindCase {
            name: "unassigned low flag bits are ignored",
            cite: "mount(2) MS_BIND (unassigned bits below 31 ignored; verified with a 64-bit sweep)",
            seed: SeedKind::Standard,
            flags: MS_BIND | (1 << 22) | (1 << 27) | (1 << 30),
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Admit,
        },
        BindCase {
            name: "kernel-internal flag bit 31",
            cite: "mount(2) ERRORS EINVAL (the kernel-internal MS_NOUSER bit; verified)",
            seed: SeedKind::Standard,
            flags: MS_BIND | (1 << 31),
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EINVAL, "invalid-flags"),
        },
        BindCase {
            name: "flag bits 32 and above",
            cite: "mount(2) ERRORS EINVAL (the kernel rejects the whole upper half; verified with a 64-bit sweep — an earlier untyped-FFI probe truncated to 32 bits and missed this)",
            seed: SeedKind::Standard,
            flags: MS_BIND | (1 << 40),
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EINVAL, "invalid-flags"),
        },
        BindCase {
            name: "flag bit 63",
            cite: "mount(2) ERRORS EINVAL (upper half, as above)",
            seed: SeedKind::Standard,
            flags: MS_BIND | (1 << 63),
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EINVAL, "invalid-flags"),
        },
        BindCase {
            name: "bind+remount on distinct objects",
            cite: "mount(2) MS_REMOUNT (with MS_BIND remounts an existing bind; distinct objects: EINVAL, verified)",
            seed: SeedKind::Standard,
            flags: MS_BIND | MS_REMOUNT,
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EINVAL, "invalid-flags"),
        },
        BindCase {
            name: "bind+remount on same object is a remount (unmodeled)",
            cite: "mount(2) MS_REMOUNT: MS_BIND specified in mountflags changes bind flags only",
            seed: SeedKind::Standard,
            flags: MS_BIND | MS_REMOUNT | MS_RDONLY,
            cap: true,
            src: (kid::SHARED, b"", Directory),
            tgt: (kid::SHARED, b"", Directory),
            expect: Expect::Refuse(errno::EPERM, "remount-bind"),
        },
        BindCase {
            name: "recursive bind (unmodeled)",
            cite: "mount(2) MS_REC: create recursive bind mounts (later slice, refused by name)",
            seed: SeedKind::Standard,
            flags: MS_BIND | MS_REC,
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EPERM, "recursive-bind"),
        },
        BindCase {
            name: "no CAP_SYS_ADMIN in owning user namespace",
            cite: "mount(2) ERRORS EPERM: no CAP_SYS_ADMIN in the user namespace owning the mount namespace",
            seed: SeedKind::Standard,
            flags: MS_BIND,
            cap: false,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EPERM, "not-capable"),
        },
        BindCase {
            name: "directory onto file",
            cite: "mount(2) ERRORS ENOTDIR (bind type mismatch, verified)",
            seed: SeedKind::Standard,
            flags: MS_BIND,
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bfile", RegularFile),
            expect: Expect::Refuse(errno::ENOTDIR, "type-mismatch"),
        },
        BindCase {
            name: "file onto directory",
            cite: "mount(2) ERRORS ENOTDIR (bind type mismatch, verified)",
            seed: SeedKind::Standard,
            flags: MS_BIND,
            cap: true,
            src: (kid::ROOT, b"afile", RegularFile),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::ENOTDIR, "type-mismatch"),
        },
        BindCase {
            name: "unbindable source root",
            cite: "mount_namespaces(7) unbindable: a bind mount cannot be created from it (EINVAL, verified)",
            seed: SeedKind::WithUnbindable,
            flags: MS_BIND,
            cap: true,
            src: (kid::UNBINDABLE, b"", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EINVAL, "unbindable-source"),
        },
        BindCase {
            name: "subdir of unbindable source",
            cite: "mount_namespaces(7) unbindable (EINVAL for subdirectories too, verified)",
            seed: SeedKind::WithUnbindable,
            flags: MS_BIND,
            cap: true,
            src: (kid::UNBINDABLE, b"sub", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Refuse(errno::EINVAL, "unbindable-source"),
        },
        BindCase {
            name: "option bits at creation are ignored",
            cite: "mount(2) MS_BIND: mountflags other than MS_REC ignored creating a bind (MS_RDONLY ignored, verified)",
            seed: SeedKind::Standard,
            flags: MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC,
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Admit,
        },
        BindCase {
            name: "propagation bit at creation is ignored",
            cite: "mount(2) MS_BIND: MS_PRIVATE given with MS_BIND does not change the new mount (verified)",
            seed: SeedKind::Standard,
            flags: MS_BIND | MS_PRIVATE,
            cap: true,
            src: (kid::ROOT, b"adir", Directory),
            tgt: (kid::ROOT, b"bdir", Directory),
            expect: Expect::Admit,
        },
        BindCase {
            name: "self bind (mount onto itself)",
            cite: "mount(2) MS_BIND: source and target may be the same point (stacking)",
            seed: SeedKind::Standard,
            flags: MS_BIND,
            cap: true,
            src: (kid::SHARED, b"", Directory),
            tgt: (kid::SHARED, b"", Directory),
            expect: Expect::Admit,
        },
    ];
    for case in &cases {
        run_bind_case(case);
    }
    assert_eq!(cases.len(), 17);
}

struct UmountCase {
    name: &'static str,
    cite: &'static str,
    flags: u64,
    cap: bool,
    kernel: u64,
    below: &'static [u8],
    is_root: bool,
    final_symlink: bool,
    expect: Expect,
}

fn run_umount_case(case: &UmountCase) {
    let (mut model, ns, _ids) = seeded_standard();
    let caller = caller(&model, ns, case.cap);
    let req = Request::Umount(UmountRequest {
        target: b"/tgt".to_vec(),
        flags: case.flags,
    });
    let mut f = fact(case.kernel, case.below, FileType::Directory, case.is_root);
    f.final_is_symlink = case.final_symlink;
    match model.admit(&caller, &req, &[f]).expect("no divergence") {
        Decision::Admit(p) => {
            p.abort();
            assert!(
                matches!(case.expect, Expect::Admit),
                "{} ({}): admitted, expected {:?}",
                case.name,
                case.cite,
                case.expect
            );
        }
        Decision::Refuse(r) => match &case.expect {
            Expect::Refuse(e, name) => {
                assert_eq!(r.errno, *e, "{} ({})", case.name, case.cite);
                assert_eq!(r.reason.name(), *name, "{} ({})", case.name, case.cite);
            }
            Expect::Admit => panic!("{} ({}): refused, expected admit", case.name, case.cite),
        },
    }
}

#[test]
fn umount_admission_table() {
    let cases = [
        UmountCase {
            name: "plain unmount admitted",
            cite: "umount2(2): unmount the filesystem mounted at target",
            flags: 0,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Admit,
        },
        UmountCase {
            name: "lazy unmount admitted",
            cite: "umount2(2) MNT_DETACH: lazy unmount",
            flags: MNT_DETACH,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Admit,
        },
        UmountCase {
            name: "MNT_FORCE accepted off NFS",
            cite: "umount2(2) MNT_FORCE (only for NFS mounts; accepted without effect elsewhere, verified)",
            flags: MNT_FORCE,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Admit,
        },
        UmountCase {
            name: "unknown flag bit",
            cite: "umount2(2) ERRORS EINVAL: flags contains an invalid flag (verified)",
            flags: 0x100,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Refuse(errno::EINVAL, "invalid-flags"),
        },
        UmountCase {
            name: "MNT_EXPIRE with MNT_DETACH",
            cite: "umount2(2) MNT_EXPIRE may not be combined (EINVAL, verified)",
            flags: MNT_EXPIRE | MNT_DETACH,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Refuse(errno::EINVAL, "invalid-flags"),
        },
        UmountCase {
            name: "MNT_EXPIRE alone (unmodeled)",
            cite: "umount2(2) MNT_EXPIRE (expiry bookkeeping unmodeled, refused by name)",
            flags: MNT_EXPIRE,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Refuse(errno::EPERM, "mnt-expire"),
        },
        UmountCase {
            name: "MNT_EXPIRE with UMOUNT_NOFOLLOW is valid but unmodeled",
            cite: "umount2(2) MNT_EXPIRE combinable with UMOUNT_NOFOLLOW (verified; refused by name)",
            flags: MNT_EXPIRE | UMOUNT_NOFOLLOW,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Refuse(errno::EPERM, "mnt-expire"),
        },
        UmountCase {
            name: "no CAP_SYS_ADMIN in owning user namespace",
            cite: "umount2(2) ERRORS EPERM: no CAP_SYS_ADMIN in the user namespace owning the mount namespace",
            flags: 0,
            cap: false,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Refuse(errno::EPERM, "not-capable"),
        },
        UmountCase {
            name: "target is not a mount point",
            cite: "umount2(2) ERRORS EINVAL: target is not a mount point (verified)",
            flags: 0,
            cap: true,
            kernel: kid::ROOT,
            below: b"plain-dir",
            is_root: false,
            final_symlink: false,
            expect: Expect::Refuse(errno::EINVAL, "not-mount-point"),
        },
        UmountCase {
            name: "UMOUNT_NOFOLLOW on a final symlink",
            cite: "umount2(2) UMOUNT_NOFOLLOW: don't dereference target if it is a symlink (then not a mount point; EINVAL, verified)",
            flags: UMOUNT_NOFOLLOW,
            cap: true,
            kernel: kid::SHARED,
            below: b"",
            is_root: true,
            final_symlink: true,
            expect: Expect::Refuse(errno::EINVAL, "nofollow-final-symlink"),
        },
        UmountCase {
            name: "namespace root",
            cite: "umount2(2) on the namespace root mount (EINVAL, verified)",
            flags: 0,
            cap: true,
            kernel: kid::ROOT,
            below: b"",
            is_root: true,
            final_symlink: false,
            expect: Expect::Refuse(errno::EINVAL, "namespace-root"),
        },
    ];
    for case in &cases {
        run_umount_case(case);
    }
    assert_eq!(cases.len(), 11);
}

/// Commit-level behavior the admission table cannot show: the
/// deferred bind root, propagation copies on bind and unmount,
/// superblock sharing, and detach visibility.
#[test]
fn commit_effects() {
    let (mut model, ns, mut ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let root_mid = model.mount_by_kernel(kid::ROOT).unwrap();
    let shared_mid = model.mount_by_kernel(kid::SHARED).unwrap();

    // Bind /shared/sub (a directory below the root of the shared
    // mount) onto /dst on the private root mount. The bind root
    // within the source filesystem is a deferred fact supplied by
    // the observed outcome.
    let req = Request::Bind(BindRequest {
        source: b"/shared/sub".to_vec(),
        target: b"/dst".to_vec(),
        flags: MS_BIND,
    });
    let facts = [
        fact(kid::SHARED, b"sub", FileType::Directory, false),
        fact(kid::ROOT, b"dst", FileType::Directory, false),
    ];
    let Decision::Admit(pending) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("bind refused");
    };
    let done = pending
        .commit(
            Observed::Bind {
                created: vec![ObservedMount {
                    kernel_mount_id: 900,
                    parent_kernel_mount_id: kid::ROOT,
                    root: b"/sub".to_vec(),
                    mount_point: b"/dst".to_vec(),
                }],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect("commit");
    assert_eq!(done.guest, Ok(()));
    assert_eq!(done.created.len(), 1);
    let new_mount = model.mount(done.created[0]).unwrap();
    assert_eq!(new_mount.root, b"/sub");
    assert_eq!(new_mount.parent, root_mid);
    // A bind shares the source superblock: same shown device,
    // different mount ID.
    assert_eq!(
        model.device_of(done.created[0]),
        model.device_of(shared_mid)
    );
    assert_ne!(done.created[0], shared_mid);
    // The source is shared: the new mount joins its peer group.
    assert_eq!(
        new_mount.propagation.peer_group(),
        model.mount(shared_mid).unwrap().propagation.peer_group()
    );
    let info = mountinfo(&model, ns);
    assert!(info.contains("/dst"), "mountinfo lacks /dst:\n{info}");

    // Unmounting it removes the record entirely.
    let req = Request::Umount(UmountRequest {
        target: b"/dst".to_vec(),
        flags: 0,
    });
    let facts = [fact(900, b"", FileType::Directory, true)];
    let Decision::Admit(pending) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("umount refused");
    };
    let done = pending
        .commit(
            Observed::Umount {
                removed_kernel_ids: vec![900],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect("commit");
    assert_eq!(done.guest, Ok(()));
    assert!(model.mount_by_kernel(900).is_none());
    assert!(!mountinfo(&model, ns).contains("/dst"));
}

/// Bind under a shared parent: a copy appears under its peer, and
/// unmounting the primary removes the copy too. The source here is
/// on the private root mount, so primary and copy form a new peer
/// group (verified against the kernel).
#[test]
fn propagation_copies() {
    let (mut model, ns, mut ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let req = Request::Bind(BindRequest {
        source: b"/adir".to_vec(),
        target: b"/shared/dst".to_vec(),
        flags: MS_BIND,
    });
    let facts = [
        fact(kid::ROOT, b"adir", FileType::Directory, false),
        fact(kid::SHARED, b"dst", FileType::Directory, false),
    ];
    let Decision::Admit(pending) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("bind refused");
    };
    let done = pending
        .commit(
            Observed::Bind {
                created: vec![
                    ObservedMount {
                        kernel_mount_id: 910,
                        parent_kernel_mount_id: kid::SHARED,
                        root: b"/adir".to_vec(),
                        mount_point: b"/shared/dst".to_vec(),
                    },
                    ObservedMount {
                        kernel_mount_id: 911,
                        parent_kernel_mount_id: kid::SHARED_PEER,
                        root: b"/adir".to_vec(),
                        mount_point: b"/shared-peer/dst".to_vec(),
                    },
                ],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect("commit");
    assert_eq!(done.created.len(), 2);
    let (a, b) = (
        model.mount(done.created[0]).unwrap(),
        model.mount(done.created[1]).unwrap(),
    );
    assert_eq!(a.propagation.peer_group(), b.propagation.peer_group());
    let parent_group = model
        .mount(model.mount_by_kernel(kid::SHARED).unwrap())
        .unwrap()
        .propagation
        .peer_group();
    assert_ne!(a.propagation.peer_group(), parent_group);

    // Unmount the primary: the peer copy goes too.
    let req = Request::Umount(UmountRequest {
        target: b"/shared/dst".to_vec(),
        flags: 0,
    });
    let facts = [fact(910, b"", FileType::Directory, true)];
    let Decision::Admit(pending) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("umount refused");
    };
    let done = pending
        .commit(
            Observed::Umount {
                removed_kernel_ids: vec![910, 911],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect("commit");
    assert_eq!(done.removed.len(), 2);
    assert!(!mountinfo(&model, ns).contains("dst"));
}

/// `/proc/self/mounts` rendering: per-mount tokens first, then
/// superblock tokens not already present, in the order the
/// kernel's `show_vfsmnt` merges them — measured on tmpfs, whose
/// superblock options (`rw,uid=…,gid=…,inode64`) extend the
/// per-mount `rw,relatime` exactly this way. The differential
/// test compares live `mounts` output as well; this pins the
/// merge order without a kernel.
#[test]
fn render_mounts_merges_options_like_the_kernel() {
    let mut model = Model::new();
    let mut ids = CounterIds::default();
    let user = model.add_namespace(NsKind::User, None, None, &mut ids);
    let ns = model.add_namespace(NsKind::Mount, None, Some(user), &mut ids);
    let mut facts = tmpfs_facts();
    facts.super_options = b"rw,uid=212630,gid=100,inode64".to_vec();
    model
        .seed_mounts(
            ns,
            &[SeedMount {
                kernel_mount_id: 42,
                parent_kernel_mount_id: None,
                mountpoint_in_parent: Vec::new(),
                root: b"/".to_vec(),
                mount_options: b"rw,relatime".to_vec(),
                propagation: Propagation::Private,
                superblock: 1,
                fs: facts,
                created: Timespec {
                    sec: 1_800_000_000,
                    nsec: 0,
                },
            }],
            &mut ids,
        )
        .expect("seed");
    let root = model.namespace(ns).unwrap().root_mount.unwrap();
    let text = model.render_mounts(
        ns,
        &PathInNs {
            mount: root,
            below_root: Vec::new(),
        },
    );
    assert_eq!(
        text,
        b"tmpfs / tmpfs rw,relatime,uid=212630,gid=100,inode64 0 0\n".to_vec()
    );
}

/// Path bytes at and above 0x80 are emitted as the kernel emits
/// them: single raw bytes, never re-encoded as multi-byte UTF-8
/// (converting `u8 as char` would expand 0xFF to 0xC3 0xBF).
#[test]
fn render_preserves_non_ascii_path_bytes() {
    let mut model = Model::new();
    let mut ids = CounterIds::default();
    let user = model.add_namespace(NsKind::User, None, None, &mut ids);
    let ns = model.add_namespace(NsKind::Mount, None, Some(user), &mut ids);
    let mut facts = tmpfs_facts();
    facts.source = b"src\xff".to_vec();
    model
        .seed_mounts(
            ns,
            &[SeedMount {
                kernel_mount_id: 43,
                parent_kernel_mount_id: None,
                mountpoint_in_parent: Vec::new(),
                root: b"/\xff\x80a b".to_vec(),
                mount_options: b"rw".to_vec(),
                propagation: Propagation::Private,
                superblock: 1,
                fs: facts,
                created: Timespec {
                    sec: 1_800_000_000,
                    nsec: 0,
                },
            }],
            &mut ids,
        )
        .expect("seed");
    let root = model.namespace(ns).unwrap().root_mount.unwrap();
    let text = model.render_mountinfo(
        ns,
        &PathInNs {
            mount: root,
            below_root: Vec::new(),
        },
    );
    assert!(
        text.windows(8).any(|w| w == b"/\xff\x80a\\040"),
        "non-ASCII path bytes must stay single raw bytes: {text:?}"
    );
    assert!(
        text.windows(4).any(|w| w == b"src\xff"),
        "non-ASCII source bytes must stay single raw bytes: {text:?}"
    );
}
