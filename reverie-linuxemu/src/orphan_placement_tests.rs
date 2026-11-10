/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Orphan placement (`ProcessSignalControl::place_orphans`) and Tool-decided
// parent-death signals (`ProcessSignalControl::publish_parent_death_signal`),
// included into the process_signal_publication unit tests.

mod orphan_placement_tests {
    use reverie::ChildExitPublicationEffect;
    use reverie::OrphanPlacement;
    use reverie::OrphanPlacementResult;
    use reverie::OrphanReaper;
    use reverie::PlacedOrphan;
    use reverie::PlacedOrphanEffect;

    use super::*;

    /// A Tool that opted into placement, as an installed controlling Tool
    /// does (`enable_orphan_placement`, then the backend's installation).
    fn enable_placement(executor: &ElfExecutor) {
        executor
            .signal_registry
            .family
            .lock()
            .unwrap()
            .orphan_placement = true;
    }

    fn place(
        executor: &ElfExecutor,
        exited: SignalProcessId,
        placements: &[OrphanPlacement],
    ) -> OrphanPlacementResult {
        executor
            .backend_signal_control()
            .process
            .place_orphans(exited, placements)
    }

    fn committed(result: OrphanPlacementResult) -> Vec<PlacedOrphan> {
        match result {
            OrphanPlacementResult::Committed(receipt) => receipt.placed,
            other => panic!("placement did not commit: {other:?}"),
        }
    }

    fn to(child: SignalProcessId, reaper: SignalProcessId) -> OrphanPlacement {
        OrphanPlacement {
            child,
            reaper: OrphanReaper::Process(reaper),
        }
    }

    fn awaiting(executor: &ElfExecutor, exited: SignalProcessId) -> Option<Vec<i32>> {
        executor
            .signal_registry
            .family
            .lock()
            .unwrap()
            .awaiting_placement
            .get(&process_key(exited))
            .map(|children| children.keys().map(|child| child.0).collect())
    }

    fn wait_parent(executor: &ElfExecutor, child: SignalProcessId) -> Option<(i32, WaitPhase)> {
        executor
            .signal_registry
            .family
            .lock()
            .unwrap()
            .wait_publications
            .get(&process_key(child))
            .map(|publication| (publication.parent.tgid.as_raw(), publication.phase))
    }

    /// Claims `child`'s recorded exit and publishes it to its parent, as the
    /// runtime and a fencing Tool do before any other turn.
    fn announce_exit(child: &ElfExecutor) -> reverie::ChildExitCompletion {
        let ProcessFamilyExit::Child(snapshot) = child.claim_process_family_exit().unwrap() else {
            panic!("child exit has a live parent");
        };
        child_receipt(
            child
                .backend_signal_control()
                .process
                .publish_child_exit(snapshot.completion),
        );
        snapshot.completion
    }

    fn sigchld_pending(executor: &ElfExecutor) -> Option<SignalEvent> {
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .clone()
            .remove(libc::SIGCHLD)
    }

    fn set_sigchld(executor: &mut ElfExecutor, handler: u64, flags: u64) {
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let action = KernelSigaction {
            handler,
            flags,
            ..Default::default()
        };
        memory.write(0x200, &action.encode()).unwrap();
        assert_eq!(
            call(
                executor,
                &memory,
                libc::SYS_rt_sigaction,
                [libc::SIGCHLD as u64, 0x200, 0, 8, 0, 0]
            ),
            0
        );
    }

    /// The traced root is its namespace's init (pid 1, no parent): its exit
    /// ends the namespace, so its live child and its zombie go to the init,
    /// which is that teardown, even before the zombie's exit is claimed, and
    /// nothing moves: both keep their edges to the root, whose executor still
    /// joins them, and the live child's exit is a `RunTeardownChild`, as
    /// without placement. No process can adopt them.
    #[test]
    fn the_orphans_of_a_root_that_is_namespace_init_are_torn_down() {
        let root = namespace_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut zombie = root.fork_child(2, false, false).unwrap();
        let zombie_id = identity(&zombie);
        let mut live = root.fork_child(3, false, false).unwrap();
        let live_id = identity(&live);
        zombie.retire_current_thread(reverie::ExitStatus::Exited(2), false);

        let mut root = root;
        root.retire_current_thread(reverie::ExitStatus::Exited(0), false);
        assert_eq!(awaiting(&root, root_id), Some(vec![2, 3]));
        assert_eq!(
            place(&root, root_id, &[to(zombie_id, live_id)]),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
            "no process, even a live one, survives the namespace to adopt an orphan",
        );
        let init = |child| OrphanPlacement {
            child,
            reaper: OrphanReaper::NamespaceInit,
        };
        assert_eq!(
            committed(place(&root, root_id, &[init(zombie_id), init(live_id)])),
            vec![
                PlacedOrphan {
                    child: zombie_id,
                    reaper: OrphanReaper::NamespaceInit,
                    effect: PlacedOrphanEffect::NamespaceInit,
                },
                PlacedOrphan {
                    child: live_id,
                    reaper: OrphanReaper::NamespaceInit,
                    effect: PlacedOrphanEffect::NamespaceInit,
                },
            ],
        );
        assert_eq!(awaiting(&root, root_id), None);
        assert_eq!(wait_parent(&root, zombie_id), Some((1, WaitPhase::Pending)));
        assert_eq!(wait_parent(&root, live_id), Some((1, WaitPhase::Pending)));
        let (edges, orphans) = family_snapshot(&root);
        assert_eq!(
            edges[&process_key(root_id)].get(&process_key(zombie_id)),
            Some(&DirectChildState::WaitableZombie)
        );
        assert_eq!(
            edges[&process_key(root_id)].get(&process_key(live_id)),
            Some(&DirectChildState::Live)
        );
        assert!(orphans.is_empty(), "no init orphan record");
        assert!(
            !root
                .signal_registry
                .transferred_children_to_namespace_init(root_id),
            "the root's executor joins its own host children",
        );
        assert_eq!(getppid(&mut live), 1);
        live.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert!(matches!(
            live.signal_registry.process_family_exit(live_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(3)
            })
        ));
    }

    /// A traced root that is its PID namespace's init: pid 1, no parent
    /// (`NamespaceReaper::TracedRoot`).
    fn namespace_init_root() -> ElfExecutor {
        let mut state = native_loaded_state(std::path::Path::new("/tmp"));
        state.task_lifecycle = Arc::new(Mutex::new(TaskLifecycleTable::with_root(1, 1, 1, true)));
        ElfExecutor::new(state, false)
    }

    /// At a namespace init's exit, a refused placement (a live process as
    /// reaper, or a child the exit did not leave) moves nothing; the empty
    /// placement then sends every child to the namespace init, an exact
    /// duplicate returns that result, and any other request is refused.
    #[test]
    fn a_namespace_init_exit_refuses_moves_nothing_and_takes_the_empty_placement() {
        let root = namespace_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut zombie = root.fork_child(2, false, false).unwrap();
        let zombie_id = identity(&zombie);
        let live = root.fork_child(3, false, false).unwrap();
        let live_id = identity(&live);
        zombie.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        let mut root = root;
        root.retire_current_thread(reverie::ExitStatus::Exited(0), false);
        let init = |child| OrphanPlacement {
            child,
            reaper: OrphanReaper::NamespaceInit,
        };
        assert_eq!(
            place(&root, root_id, &[to(zombie_id, live_id)]),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
            "a live process reaper is refused",
        );
        assert_eq!(
            place(&root, root_id, &[init(root_id)]),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
            "a child the exit did not leave is refused",
        );
        assert_eq!(awaiting(&root, root_id), Some(vec![2, 3]), "refusals move nothing");
        let result = place(&root, root_id, &[]);
        assert_eq!(
            committed(result.clone()),
            [zombie_id, live_id]
                .into_iter()
                .map(|child| PlacedOrphan {
                    child,
                    reaper: OrphanReaper::NamespaceInit,
                    effect: PlacedOrphanEffect::NamespaceInit,
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(place(&root, root_id, &[]), result, "an exact duplicate");
        assert_eq!(
            place(&root, root_id, &[init(live_id)]),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
            "another request after the commit is refused",
        );
    }

    /// After a namespace init's exit, a member (its live child) exits with a
    /// live child of its own: the member's exit is a `RunTeardownChild`, and
    /// its child goes to the namespace init too, as Linux's
    /// `find_child_reaper` gives it to the dying init (the review's case).
    #[test]
    fn a_member_exit_after_the_namespace_init_places_its_child_with_the_init() {
        let root = namespace_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut child = root.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        let mut grandchild = child.fork_child(3, false, false).unwrap();
        let grandchild_id = identity(&grandchild);
        let mut root = root;
        root.retire_current_thread(reverie::ExitStatus::Exited(0), false);
        let init = |child| OrphanPlacement {
            child,
            reaper: OrphanReaper::NamespaceInit,
        };
        committed(place(&root, root_id, &[init(child_id)]));
        child.retire_current_thread(reverie::ExitStatus::Exited(2), false);
        assert!(matches!(
            child.signal_registry.process_family_exit(child_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(2)
            })
        ));
        assert_eq!(awaiting(&root, child_id), Some(vec![3]));
        assert_eq!(
            place(&root, child_id, &[to(grandchild_id, root_id)]),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
        );
        assert_eq!(
            committed(place(&root, child_id, &[init(grandchild_id)])),
            vec![PlacedOrphan {
                child: grandchild_id,
                reaper: OrphanReaper::NamespaceInit,
                effect: PlacedOrphanEffect::NamespaceInit,
            }],
        );
        assert_eq!(getppid(&mut grandchild), 2);
        grandchild.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert!(matches!(
            grandchild.signal_registry.process_family_exit(grandchild_id),
            Some(ProcessFamilyExit::RunTeardownChild {
                status: reverie::ExitStatus::Exited(3)
            })
        ));
        assert_eq!(
            committed(place(&root, grandchild_id, &[])),
            Vec::new(),
            "an exit without children places none",
        );
    }

    /// Root (pid 3, a child subreaper in the Tool's model) forks a parent
    /// (6) that forks a live child (7): the parent's exit leaves the child
    /// waiting, and the placement makes it the root's, for its waits, its
    /// later exit and `getppid`.
    #[test]
    fn a_live_orphan_goes_to_the_reaper_the_tool_names() {
        let root = outside_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        let mut orphan_thread = orphan.thread_child(10).unwrap();

        parent.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        // Until the Tool places it, the child waits: no init adopted it.
        assert_eq!(awaiting(&root, parent_id), Some(vec![7]));
        assert_eq!(family_snapshot(&root).1, BTreeSet::new());
        assert_eq!(getppid(&mut orphan), 6);
        assert!(
            root.signal_registry
                .transferred_children_to_namespace_init(parent_id),
            "the exited parent's host children still go to the orphanage",
        );

        assert_eq!(
            committed(place(&root, parent_id, &[to(orphan_id, root_id)])),
            vec![PlacedOrphan {
                child: orphan_id,
                reaper: OrphanReaper::Process(root_id),
                effect: PlacedOrphanEffect::Live,
            }],
        );
        assert_eq!(awaiting(&root, parent_id), None);
        assert_eq!(getppid(&mut orphan), 3);
        assert_eq!(getppid(&mut orphan_thread), 3, "threads share the parent");
        assert_eq!(
            orphan.parent_pid(),
            Some(reverie::Pid::from_raw(6)),
            "the traced-tree parent stays the fork-time parent",
        );
        assert_eq!(wait_parent(&root, orphan_id), Some((3, WaitPhase::Pending)));
        let (edges, orphans) = family_snapshot(&root);
        assert_eq!(
            edges[&process_key(root_id)].get(&process_key(orphan_id)),
            Some(&DirectChildState::Live)
        );
        assert!(orphans.is_empty());

        // The orphan's own exit is the reaper's child exit.
        orphan_thread.retire_current_thread(reverie::ExitStatus::Exited(7), true);
        orphan.retire_current_thread(reverie::ExitStatus::Exited(7), false);
        assert!(matches!(
            orphan.signal_registry.process_family_exit(orphan_id),
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.parent == root_id
                    && snapshot.completion.status == reverie::ExitStatus::Exited(7)
                    && snapshot.completion.waitable
        ));
        let completion = announce_exit(&orphan);
        assert_eq!(completion.parent, root_id);
        assert!(root.signal_registry.consume_child_wait(root_id, 6));
        assert!(root.signal_registry.consume_child_wait(root_id, 7));
        assert!(family_snapshot(&root).0.is_empty());
    }

    /// A zombie of the exiting parent (its exit claimed and announced to the
    /// parent, but not reaped) becomes the reaper's: announced again with its
    /// own SIGCHLD siginfo, and waitable by the reaper.
    #[test]
    fn a_zombie_orphan_is_announced_to_its_reaper() {
        let root = outside_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut zombie = parent.fork_child(8, false, false).unwrap();
        let zombie_id = identity(&zombie);
        zombie.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        assert_eq!(announce_exit(&zombie).parent, parent_id);
        // The parent's SIGCHLD came from the zombie's first announcement.
        assert!(sigchld_pending(&parent).is_some());

        parent.retire_current_thread(reverie::ExitStatus::Exited(4), false);
        assert_eq!(awaiting(&root, parent_id), Some(vec![8]));
        assert!(sigchld_pending(&root).is_none());
        assert_eq!(
            committed(place(&root, parent_id, &[to(zombie_id, root_id)])),
            vec![PlacedOrphan {
                child: zombie_id,
                reaper: OrphanReaper::Process(root_id),
                effect: PlacedOrphanEffect::Zombie(ChildExitPublicationEffect::Queued),
            }],
        );
        let event = sigchld_pending(&root).expect("the reaper's SIGCHLD");
        let info = event.siginfo();
        let field = |at: usize| i32::from_ne_bytes(info[at..at + 4].try_into().unwrap());
        assert_eq!(field(8), libc::CLD_EXITED);
        assert_eq!(field(16), 8, "si_pid names the zombie");
        assert_eq!(field(24), 9, "si_status is its exit status");
        assert!(matches!(
            zombie.signal_registry.process_family_exit(zombie_id),
            Some(ProcessFamilyExit::Child(snapshot))
                if snapshot.completion.parent == root_id && snapshot.completion.waitable
        ));
        assert_eq!(wait_parent(&root, zombie_id), Some((3, WaitPhase::Ready)));
        assert!(
            !root.signal_registry.consume_child_wait(parent_id, 8),
            "the dead parent cannot reap it"
        );
        assert!(root.signal_registry.consume_child_wait(root_id, 8));
    }

    /// A reaper whose SIGCHLD is ignored reaps an adopted zombie at once and
    /// gets no signal; one with SA_NOCLDWAIT reaps it at once but still gets
    /// the signal, as Linux's `do_notify_parent` decides.
    #[test]
    fn a_reaper_that_reaps_automatically_takes_no_zombie() {
        for (handler, flags, signaled) in [
            (libc::SIG_IGN as u64, 0, false),
            (libc::SIG_DFL as u64, libc::SA_NOCLDWAIT as u64, true),
        ] {
            let mut root = outside_init_root();
            enable_placement(&root);
            let root_id = identity(&root);
            let mut parent = root.fork_child(6, false, false).unwrap();
            let parent_id = identity(&parent);
            let mut zombie = parent.fork_child(8, false, false).unwrap();
            let zombie_id = identity(&zombie);
            zombie.retire_current_thread(reverie::ExitStatus::Exited(9), false);
            announce_exit(&zombie);
            set_sigchld(&mut root, handler, flags);
            parent.retire_current_thread(reverie::ExitStatus::Exited(4), false);

            assert_eq!(
                committed(place(&root, parent_id, &[to(zombie_id, root_id)])),
                vec![PlacedOrphan {
                    child: zombie_id,
                    reaper: OrphanReaper::Process(root_id),
                    effect: PlacedOrphanEffect::AutoReaped,
                }],
                "handler {handler} flags {flags}",
            );
            assert_eq!(sigchld_pending(&root).is_some(), signaled);
            assert!(!root.signal_registry.consume_child_wait(root_id, 8));
            assert!(matches!(
                zombie.signal_registry.process_family_exit(zombie_id),
                Some(ProcessFamilyExit::Child(snapshot))
                    if snapshot.completion.parent == root_id && !snapshot.completion.waitable
            ));
            assert_eq!(wait_parent(&root, zombie_id), Some((3, WaitPhase::Retired)));
        }
    }

    /// A child the Tool does not name, or names for the init, goes to the
    /// namespace init, as without placement.
    #[test]
    fn unnamed_orphans_go_to_the_namespace_init() {
        let root = outside_init_root();
        enable_placement(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut live = parent.fork_child(7, false, false).unwrap();
        let live_id = identity(&live);
        let mut zombie = parent.fork_child(8, false, false).unwrap();
        let zombie_id = identity(&zombie);
        zombie.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        announce_exit(&zombie);
        parent.retire_current_thread(reverie::ExitStatus::Exited(4), false);

        let named = [OrphanPlacement {
            child: zombie_id,
            reaper: OrphanReaper::NamespaceInit,
        }];
        assert_eq!(
            committed(place(&root, parent_id, &named)),
            vec![
                PlacedOrphan {
                    child: zombie_id,
                    reaper: OrphanReaper::NamespaceInit,
                    effect: PlacedOrphanEffect::NamespaceInit,
                },
                PlacedOrphan {
                    child: live_id,
                    reaper: OrphanReaper::NamespaceInit,
                    effect: PlacedOrphanEffect::NamespaceInit,
                },
            ],
        );
        assert_eq!(getppid(&mut live), 1);
        assert_eq!(
            family_snapshot(&root).1,
            BTreeSet::from([process_key(live_id)])
        );
        assert_eq!(wait_parent(&root, zombie_id), Some((6, WaitPhase::Retired)));
        assert_eq!(wait_parent(&root, live_id), Some((6, WaitPhase::Retired)));
        live.retire_current_thread(reverie::ExitStatus::Exited(5), false);
        assert_eq!(
            live.signal_registry.process_family_exit(live_id),
            Some(ProcessFamilyExit::ReapedByNamespaceInit {
                status: reverie::ExitStatus::Exited(5),
            }),
        );
        // A placed exit's own children wait for placement too.
        assert_eq!(awaiting(&root, live_id), Some(vec![]));
    }

    /// Nothing moves unless every placement is valid, and an exact duplicate
    /// returns the retained result.
    #[test]
    fn an_invalid_placement_moves_nothing() {
        use OrphanPlacementResult::RejectedBeforeCommit;

        let root = outside_init_root();
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let orphan = parent.fork_child(7, false, false).unwrap();
        let orphan_id = identity(&orphan);
        let mut sibling = root.fork_child(9, false, false).unwrap();
        let sibling_id = identity(&sibling);

        assert_eq!(
            place(&root, parent_id, &[to(orphan_id, root_id)]),
            RejectedBeforeCommit(Errno::ENOSYS),
            "a Tool that did not opt in places nothing",
        );
        enable_placement(&root);
        assert_eq!(
            place(&root, parent_id, &[to(orphan_id, root_id)]),
            RejectedBeforeCommit(Errno::EAGAIN),
            "the exit is not recorded yet",
        );
        parent.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        let stranger = SignalProcessId {
            generation: orphan_id.generation + 1,
            ..orphan_id
        };
        for (placements, errno) in [
            (vec![to(stranger, root_id)], Errno::EINVAL),
            (
                vec![to(orphan_id, root_id), to(orphan_id, root_id)],
                Errno::EINVAL,
            ),
            (vec![to(orphan_id, parent_id)], Errno::EINVAL),
            (vec![to(orphan_id, orphan_id)], Errno::EINVAL),
        ] {
            assert_eq!(
                place(&root, parent_id, &placements),
                RejectedBeforeCommit(errno),
                "{placements:?}"
            );
            assert_eq!(awaiting(&root, parent_id), Some(vec![7]));
        }
        sibling.retire_current_thread(reverie::ExitStatus::Exited(0), false);
        assert_eq!(
            place(&root, parent_id, &[to(orphan_id, sibling_id)]),
            RejectedBeforeCommit(Errno::ESRCH),
            "an exited reaper adopts nothing",
        );
        assert_eq!(awaiting(&root, parent_id), Some(vec![7]));

        let result = place(&root, parent_id, &[to(orphan_id, root_id)]);
        committed(result.clone());
        assert_eq!(place(&root, parent_id, &[to(orphan_id, root_id)]), result);
        assert_eq!(
            place(&root, parent_id, &[]),
            RejectedBeforeCommit(Errno::EINVAL),
            "a different repeat is not a duplicate",
        );
    }

    /// Every orphan of one exit has the same reaper, as in Linux.
    #[test]
    fn one_exit_places_its_orphans_with_one_reaper() {
        let root = outside_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let other = root.fork_child(5, false, false).unwrap();
        let other_id = identity(&other);
        let first = parent.fork_child(7, false, false).unwrap();
        let second = parent.fork_child(8, false, false).unwrap();
        parent.retire_current_thread(reverie::ExitStatus::Exited(3), false);
        assert_eq!(
            place(
                &root,
                parent_id,
                &[
                    to(identity(&first), root_id),
                    to(identity(&second), other_id)
                ]
            ),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
        );
        assert_eq!(awaiting(&root, parent_id), Some(vec![7, 8]));
    }

    /// An exit recorded for the exited process that no callback claimed has
    /// not been announced to anyone: the exit's fence should have published
    /// it, so placement refuses rather than guess its parent.
    #[test]
    fn an_unclaimed_child_exit_refuses_placement() {
        let root = outside_init_root();
        enable_placement(&root);
        let root_id = identity(&root);
        let mut parent = root.fork_child(6, false, false).unwrap();
        let parent_id = identity(&parent);
        let mut zombie = parent.fork_child(8, false, false).unwrap();
        let zombie_id = identity(&zombie);
        zombie.retire_current_thread(reverie::ExitStatus::Exited(9), false);
        parent.retire_current_thread(reverie::ExitStatus::Exited(4), false);
        assert_eq!(
            place(&root, parent_id, &[to(zombie_id, root_id)]),
            OrphanPlacementResult::RejectedBeforeCommit(Errno::EINVAL),
        );
    }

    /// The opt-in is closed by the backend's installation, like the
    /// parent-death protocol's.
    #[test]
    fn orphan_placement_opts_in_only_before_installation() {
        let root = outside_init_root();
        let control = root.backend_signal_control().process;
        assert_eq!(control.enable_orphan_placement(), Ok(()));
        root.signal_registry
            .parent_death_installation_closed
            .store(true, Ordering::Release);
        assert_eq!(control.enable_orphan_placement(), Err(Errno::EBUSY));
    }

    fn parent_death_event(target: SignalProcessId, signal: i32, code: i32) -> SignalEvent {
        let mut info = [0; reverie::SIGNAL_INFO_SIZE];
        info[..4].copy_from_slice(&signal.to_ne_bytes());
        info[8..12].copy_from_slice(&code.to_ne_bytes());
        info[16..20].copy_from_slice(&6_i32.to_ne_bytes());
        SignalEvent::new(
            signal,
            info,
            reverie::SignalTarget::Process { pid: target.tgid },
        )
        .unwrap()
    }

    /// A Tool-decided parent-death signal is a process-directed standard
    /// signal with SI_USER, never a stop signal or SIGCHLD, queued like an
    /// alarm.
    #[test]
    fn a_parent_death_signal_is_published_to_its_process() {
        use reverie::ProcessSignalPublicationResult::Committed;
        use reverie::ProcessSignalPublicationResult::RejectedBeforeCommit;

        let executor = executor();
        let id = identity(&executor);
        let control = executor.backend_signal_control().process;
        for signal in [
            libc::SIGSTOP,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGTTOU,
            libc::SIGCHLD,
            libc::SIGRTMIN(),
        ] {
            assert_eq!(
                control
                    .publish_parent_death_signal(id, parent_death_event(id, signal, libc::SI_USER)),
                RejectedBeforeCommit(Errno::EINVAL),
                "{signal}",
            );
        }
        assert_eq!(
            control.publish_parent_death_signal(
                id,
                parent_death_event(id, libc::SIGTERM, libc::SI_KERNEL)
            ),
            RejectedBeforeCommit(Errno::EINVAL),
            "a parent-death signal is the sender's SI_USER",
        );
        let other = SignalProcessId {
            tgid: reverie::Pid::from_raw(id.tgid.as_raw() + 1),
            ..id
        };
        assert_eq!(
            control.publish_parent_death_signal(
                id,
                parent_death_event(other, libc::SIGTERM, libc::SI_USER)
            ),
            RejectedBeforeCommit(Errno::EINVAL),
        );
        let event = parent_death_event(id, libc::SIGTERM, libc::SI_USER);
        assert!(matches!(
            control.publish_parent_death_signal(id, event),
            Committed(receipt) if !receipt.coalesced
        ));
        assert!(matches!(
            control.publish_parent_death_signal(id, event),
            Committed(receipt) if receipt.coalesced
        ));
        assert_eq!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .clone()
                .remove(libc::SIGTERM),
            Some(event),
        );
    }

    /// The signals this backend publishes are exactly the set it declares
    /// (`BackendCapabilities::KVM.publishable_parent_death_signals`): every
    /// other signal from 1 to 64 is rejected before commit.
    #[test]
    fn the_published_signals_are_exactly_the_declared_set() {
        let declared = reverie::BackendCapabilities::KVM.publishable_parent_death_signals;
        for signal in 1..=64 {
            let executor = executor();
            let id = identity(&executor);
            let control = executor.backend_signal_control().process;
            let result = control
                .publish_parent_death_signal(id, parent_death_event(id, signal, libc::SI_USER));
            let published = matches!(
                result,
                reverie::ProcessSignalPublicationResult::Committed(_)
            );
            assert_eq!(
                published,
                declared & (1 << (signal - 1)) != 0,
                "{signal}: {result:?}"
            );
        }
    }

    /// SIGKILL is published the same way: it cannot be blocked, so every
    /// thread is a recipient, and its delivery takes the default action. Only
    /// the delivery hook passes it; a Tool still cannot queue one itself.
    #[test]
    fn a_parent_death_sigkill_is_deliverable_to_every_thread() {
        let mut executor = executor();
        let id = identity(&executor);
        let mut memory = GuestMemory::new(0, 4096).unwrap();
        let mut all = KernelSigset::default();
        for signal in 1..=64 {
            all.insert(signal);
        }
        memory.write(0x80, &all.to_bytes()).unwrap();
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_rt_sigprocmask,
                [libc::SIG_SETMASK as u64, 0x80, 0, 8, 0, 0]
            ),
            0
        );
        let control = executor.backend_signal_control().process;
        let event = parent_death_event(id, libc::SIGKILL, libc::SI_USER);
        assert!(matches!(
            control.publish_parent_death_signal(id, event),
            reverie::ProcessSignalPublicationResult::Committed(_)
        ));
        assert_eq!(
            control.signal_recipients(id, libc::SIGKILL).unwrap().len(),
            1,
            "a mask never blocks SIGKILL",
        );
        assert_eq!(
            executor.signal_disposition(libc::SIGKILL),
            crate::executor::SignalDisposition::Terminate
        );
        let pending = executor
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap();
        assert_eq!(pending.event, event);
        // The delivery hook passes the published SIGKILL on as itself, under
        // the mask that blocks every other signal.
        assert_eq!(
            executor.prepare_filtered_signal_delivery(pending.event, pending.domain),
            Ok(Some(pending)),
        );
        // A Tool still cannot queue a SIGKILL itself.
        assert_eq!(
            executor.defer_signal_delivery(event),
            Err(Errno::ENOSYS),
            "defer_signal_delivery accepted a SIGKILL",
        );
        // A SIGKILL from anywhere else, and a stop signal, still is not one
        // this hook delivers.
        let mut tkill = event.siginfo();
        tkill[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
        let thread = reverie::SignalTarget::Thread {
            pid: id.tgid,
            tid: id.tgid,
        };
        for (signal, info, target) in [
            (libc::SIGKILL, tkill, thread),
            (
                libc::SIGSTOP,
                parent_death_event(id, libc::SIGSTOP, libc::SI_USER).siginfo(),
                event.target(),
            ),
        ] {
            let other = SignalEvent::new(signal, info, target).unwrap();
            assert_eq!(
                executor.prepare_filtered_signal_delivery(other, pending.domain),
                Err(Errno::ENOSYS),
                "{signal}",
            );
        }
    }
}
