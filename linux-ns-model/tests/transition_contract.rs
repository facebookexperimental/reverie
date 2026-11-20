/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The transition contract: one pending transition holds the
//! model, commits apply only predicted effects, surprises are
//! divergences that change nothing (and consume no IDs), and
//! deferred facts (a bind's root) plug into the prediction.

mod common;

use common::*;
use linux_ns_model::*;

fn bind_req() -> Request {
    Request::Bind(BindRequest {
        source: b"/adir".to_vec(),
        target: b"/bdir".to_vec(),
        flags: MS_BIND,
    })
}

fn bind_facts() -> [IdentifiedPath; 2] {
    [
        fact(kid::ROOT, b"adir", FileType::Directory, false),
        fact(kid::ROOT, b"bdir", FileType::Directory, false),
    ]
}

fn observed_bind(root: &[u8]) -> Observed {
    Observed::Bind {
        created: vec![ObservedMount {
            kernel_mount_id: 920,
            parent_kernel_mount_id: kid::ROOT,
            root: root.to_vec(),
            mount_point: b"/bdir".to_vec(),
        }],
    }
}

/// A stale plan cannot exist: the pending transition holds the
/// model (`Pending` borrows it mutably, so starting a second
/// transition while one is pending does not compile). What can be
/// shown at runtime is the contract's consequence: after aborting
/// a plan and mounting over its source, re-admitting the same
/// request predicts from the new state, in Linux's call order.
#[test]
fn stale_plan_readmits_against_new_state() {
    let (mut model, ns, mut ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let shared_mid = model.mount_by_kernel(kid::SHARED).unwrap();

    // Admit bind /adir -> /bdir, then abort (drop) it.
    let Decision::Admit(stale) = model.admit(&caller, &bind_req(), &bind_facts()).unwrap() else {
        panic!("refused");
    };
    stale.abort();

    // Mount the shared mount over /adir: bind /shared -> /adir.
    // The covering mount has kernel id 930.
    let cover = Request::Bind(BindRequest {
        source: b"/shared".to_vec(),
        target: b"/adir".to_vec(),
        flags: MS_BIND,
    });
    let cover_facts = [
        fact(kid::SHARED, b"", FileType::Directory, true),
        fact(kid::ROOT, b"adir", FileType::Directory, false),
    ];
    let Decision::Admit(p) = model.admit(&caller, &cover, &cover_facts).unwrap() else {
        panic!("refused");
    };
    p.commit(
        Observed::Bind {
            created: vec![ObservedMount {
                kernel_mount_id: 930,
                parent_kernel_mount_id: kid::ROOT,
                root: b"/".to_vec(),
                mount_point: b"/adir".to_vec(),
            }],
        },
        &mut ids,
        &mut FixedClock,
    )
    .expect("commit");

    // Re-admit the original bind. Identification now resolves
    // /adir on the covering mount (930), so the new mount must
    // share the covering mount's superblock — Linux's answer for
    // this order of calls.
    let fresh_facts = [
        fact(930, b"", FileType::Directory, true),
        fact(kid::ROOT, b"bdir", FileType::Directory, false),
    ];
    let Decision::Admit(p) = model.admit(&caller, &bind_req(), &fresh_facts).unwrap() else {
        panic!("refused");
    };
    let done = p
        .commit(
            Observed::Bind {
                created: vec![ObservedMount {
                    kernel_mount_id: 931,
                    parent_kernel_mount_id: kid::ROOT,
                    root: b"/".to_vec(),
                    mount_point: b"/bdir".to_vec(),
                }],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect("commit");
    assert_eq!(
        model.device_of(done.created[0]),
        model.device_of(shared_mid),
        "bind after covering must take the covering mount's filesystem"
    );
}

#[test]
fn surprise_effects_are_divergences_and_change_nothing() {
    // Each surprise must leave the rendering and the ID counters
    // exactly as they were.
    let surprises: Vec<(&str, Observed)> = vec![
        (
            "extra created mount",
            Observed::Bind {
                created: vec![
                    ObservedMount {
                        kernel_mount_id: 920,
                        parent_kernel_mount_id: kid::ROOT,
                        root: b"/adir".to_vec(),
                        mount_point: b"/bdir".to_vec(),
                    },
                    ObservedMount {
                        kernel_mount_id: 921,
                        parent_kernel_mount_id: kid::ROOT,
                        root: b"/adir".to_vec(),
                        mount_point: b"/elsewhere".to_vec(),
                    },
                ],
            },
        ),
        (
            "wrong parent",
            Observed::Bind {
                created: vec![ObservedMount {
                    kernel_mount_id: 920,
                    parent_kernel_mount_id: kid::SHARED,
                    root: b"/adir".to_vec(),
                    mount_point: b"/bdir".to_vec(),
                }],
            },
        ),
        (
            "reused kernel mount id",
            Observed::Bind {
                created: vec![ObservedMount {
                    kernel_mount_id: kid::ROOT,
                    parent_kernel_mount_id: kid::ROOT,
                    root: b"/adir".to_vec(),
                    mount_point: b"/bdir".to_vec(),
                }],
            },
        ),
        ("unpdicted failure", Observed::Failed(errno::EACCES)),
        (
            "wrong outcome kind",
            Observed::Umount {
                removed_kernel_ids: vec![kid::SHARED],
            },
        ),
    ];
    for (name, observed) in surprises {
        let (mut model, ns, mut ids) = seeded_standard();
        let caller = caller(&model, ns, true);
        let before = mountinfo(&model, ns);
        let ids_before = ids.clone();
        let Decision::Admit(p) = model.admit(&caller, &bind_req(), &bind_facts()).unwrap() else {
            panic!("refused");
        };
        let err = p
            .commit(observed, &mut ids, &mut FixedClock)
            .expect_err(name);
        assert!(!err.detail.is_empty(), "{name}");
        assert_eq!(mountinfo(&model, ns), before, "{name}: model changed");
        assert_eq!(ids, ids_before, "{name}: IDs consumed by a divergence");
    }
}

#[test]
fn surprise_unmount_removal_set_is_a_divergence() {
    let (mut model, ns, mut ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let before = mountinfo(&model, ns);
    let req = Request::Umount(UmountRequest {
        target: b"/shared".to_vec(),
        flags: 0,
    });
    let facts = [fact(kid::SHARED, b"", FileType::Directory, true)];
    let Decision::Admit(p) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("refused");
    };
    // The peer of /shared is not a counterpart of unmounting
    // /shared itself (its parent is private), so reporting the
    // peer removed is a surprise.
    let err = p
        .commit(
            Observed::Umount {
                removed_kernel_ids: vec![kid::SHARED, kid::SHARED_PEER],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect_err("divergence");
    assert!(!err.detail.is_empty());
    assert_eq!(mountinfo(&model, ns), before);
}

#[test]
fn busy_unmount_is_guest_ebusy_with_model_unchanged() {
    let (mut model, ns, mut ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let before = mountinfo(&model, ns);
    let req = Request::Umount(UmountRequest {
        target: b"/shared".to_vec(),
        flags: 0,
    });
    let facts = [fact(kid::SHARED, b"", FileType::Directory, true)];
    let Decision::Admit(p) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("refused");
    };
    let done = p
        .commit(Observed::Failed(errno::EBUSY), &mut ids, &mut FixedClock)
        .expect("EBUSY is a predicted-acceptable outcome");
    assert_eq!(done.guest, Err(errno::EBUSY));
    assert_eq!(mountinfo(&model, ns), before);
}

/// The same bind request on the same mount table, with the source
/// symlink resolving differently: the two runs must produce the
/// two different bind roots, and neither is a divergence. (With
/// recursion the copied submount sets would differ the same way;
/// that is the recursive-bind slice's version of this test.)
#[test]
fn deferred_bind_root_follows_the_filesystem() {
    let mut roots = Vec::new();
    for resolved in [b"/a".as_slice(), b"/b".as_slice()] {
        let (mut model, ns, mut ids) = seeded_standard();
        let caller = caller(&model, ns, true);
        let Decision::Admit(p) = model.admit(&caller, &bind_req(), &bind_facts()).unwrap() else {
            panic!("refused");
        };
        let done = p
            .commit(observed_bind(resolved), &mut ids, &mut FixedClock)
            .expect("commit");
        roots.push(model.mount(done.created[0]).unwrap().root.clone());
        let info = mountinfo(&model, ns);
        let expect_root = core::str::from_utf8(resolved).unwrap();
        assert!(info.contains(expect_root), "{info}");
    }
    assert_ne!(roots[0], roots[1]);
}

/// A caller rooted below the namespace root: operand facts are
/// mount-relative as always, and observed mount points are
/// namespace-absolute, so a propagation copy that lands outside
/// the caller's root is still predicted and applied exactly.
#[test]
fn chrooted_caller_observed_paths_convert() {
    let (mut model, ns, mut ids) = seeded_standard();
    let shared_mid = model.mount_by_kernel(kid::SHARED).unwrap();
    let caller = CallerContext {
        task: TaskKey(9),
        mount_ns: ns,
        root: PathInNs {
            mount: shared_mid,
            below_root: Vec::new(),
        },
        cwd: PathInNs {
            mount: shared_mid,
            below_root: Vec::new(),
        },
        cap_sys_admin_in_owner: true,
    };
    // From inside /shared: bind /sub onto /dst (both on the shared
    // mount). The target's parent is shared, and its peer is in
    // the same namespace, so a copy lands under /shared-peer too —
    // outside the caller's root, exactly as Linux propagates it.
    let req = Request::Bind(BindRequest {
        source: b"/sub".to_vec(),
        target: b"/dst".to_vec(),
        flags: MS_BIND,
    });
    let facts = [
        fact(kid::SHARED, b"sub", FileType::Directory, false),
        fact(kid::SHARED, b"dst", FileType::Directory, false),
    ];
    let Decision::Admit(p) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("refused");
    };
    let done = p
        .commit(
            Observed::Bind {
                created: vec![
                    ObservedMount {
                        kernel_mount_id: 940,
                        parent_kernel_mount_id: kid::SHARED,
                        root: b"/sub".to_vec(),
                        mount_point: b"/shared/dst".to_vec(),
                    },
                    ObservedMount {
                        kernel_mount_id: 941,
                        parent_kernel_mount_id: kid::SHARED_PEER,
                        root: b"/sub".to_vec(),
                        mount_point: b"/shared-peer/dst".to_vec(),
                    },
                ],
            },
            &mut ids,
            &mut FixedClock,
        )
        .expect("commit");
    assert_eq!(done.created.len(), 2);
    // Rendered from the caller's root, only the primary shows;
    // the peer copy is outside it, exactly as Linux shows it.
    let view = String::from_utf8(model.render_mountinfo(
        ns,
        &PathInNs {
            mount: shared_mid,
            below_root: Vec::new(),
        },
    ))
    .expect("fixture paths are UTF-8");
    assert!(view.contains(" /dst "), "{view}");
    assert!(!view.contains("shared-peer"), "{view}");
    assert!(mountinfo(&model, ns).contains("/shared-peer/dst"));
}

#[test]
fn unknown_kernel_facts_are_divergences_not_guest_errors() {
    let (mut model, ns, _ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let facts = [
        fact(424242, b"adir", FileType::Directory, false),
        fact(kid::ROOT, b"bdir", FileType::Directory, false),
    ];
    assert!(model.admit(&caller, &bind_req(), &facts).is_err());
}

#[test]
fn detach_hides_but_keeps_the_record() {
    let (mut model, ns, mut ids) = seeded_standard();
    let caller = caller(&model, ns, true);
    let req = Request::Umount(UmountRequest {
        target: b"/shared".to_vec(),
        flags: MNT_DETACH,
    });
    let facts = [fact(kid::SHARED, b"", FileType::Directory, true)];
    let Decision::Admit(p) = model.admit(&caller, &req, &facts).unwrap() else {
        panic!("refused");
    };
    p.commit(
        Observed::Umount {
            removed_kernel_ids: vec![kid::SHARED],
        },
        &mut ids,
        &mut FixedClock,
    )
    .expect("commit");
    // Gone from the rendering, still resolvable by kernel ID for
    // descriptor-based lookups (umount2(2) MNT_DETACH: existing
    // descriptors still reach the mount).
    assert!(!mountinfo(&model, ns).contains("/shared "));
    let detached = model.mount_by_kernel(kid::SHARED).expect("record kept");
    assert_eq!(model.mount(detached).unwrap().state, MountState::Detached);
}
