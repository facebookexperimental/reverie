# KVM ordinary thread exits and process Tool ownership

An ordinary worker exit set the thread group's shared cancellation flag on main
90a650d920966b8e0b6b49462fa2381bd8975670. A subsequent pthread was created and
admitted but exited before executing its entry function. The same source also
constructed a new process Tool for every CLONE_THREAD worker, so a hierarchical
counter reported only the leader's exit.

The problem was exposed by combined validation for
https://github.com/rrnewton/reverie/pull/538. It reproduces independently of that
proposal, on current main with a three-pthread fixture using the actual Tool
runtime. Native and plain KVM complete all three create/join operations. Main's
Tool runtime exits at iteration one with `entered=0` and stale return storage.

Commit dc54ecf51fc19313aae28f308eed40b2d9354545 corrects ordinary nonleader
cancellation and performs worker child-tid cleanup before terminal Tool hooks.
Its unchanged hierarchical assertion still failed: the guest completed, but
`exited_threads` was 1 instead of 4. The subsequent process ownership repair
satisfies that assertion. No expected count was reduced.

One Arc<T> now owns a guest process's Tool. CLONE_THREAD shares it and receives
fresh thread state initialized from the creator. Fork constructs a fresh Tool
with T::new(child_pid), preserving the process constructor contract. A terminal
leader hook joins the workers before calling the thread hook and consuming the
process Tool. Arc::try_unwrap refuses a process hook if any worker still retains
its process state. GlobalTool remains shared across the process tree.

## Exit-path audit

| Path | Guest-selected exit and cleanup |
| --- | --- |
| handle_thread_start | Cancellation is checked after the start hook. An injected ordinary worker exit clears its child-tid and calls its thread hook without cancelling surviving workers. Group exit requests group cancellation. |
| Initial exec hook | Runs for the initial leader. A selected exit applies group/leader teardown, then cleanup and Tool exit. |
| Initial and repeated post_exec | A selected exit reaches the same exit decision. Existing post-exec-error hooks now also join workers before consuming the process Tool. Successful replacement remains subject to current leader-only exec support. |
| Ordinary syscall | Both subscribed injection and direct execution converge on pending_exit. Ordinary workers leave siblings alive; exit_group selects the group's status and cancels workers. |
| Page-zero fault | Existing group-signal selection and leader joins remain. Worker child-tid cleanup precedes the Tool hook. |
| rt_sigreturn | Existing fatal-return signal handling remains. Worker cleanup precedes the hook and process clear-tid registrations are discarded on the existing signal-return path. |
| Cancellation/group observation | Registered workers clear their child-tid and run their exit hook; the leader joins them before its consuming process hook. |
| Failed exec | A failed replacement preserves the process Tool and surviving workers; it does not create a replacement Tool. The live regression requires the surviving worker to finish after ENOENT. |

Existing handler/runtime-error returns are not uniform guest exits: several
start, initial-exec, signal and syscall errors propagate without a terminal Tool
hook. This bounded change does not claim complete error-path lifecycle delivery.
The legacy clear_tid_and_wake fallback also uses a readable-only memory write;
its permission behavior is a separate existing discrepancy.

Root initially requested suppressing wake after a failed permission-aware
clear-child-tid store. That request was withdrawn after reading Linux mm_release:
it explicitly ignores put_user failure and still calls do_futex(FUTEX_WAKE).
The retained Linux sources are /tmp/linux-fork-v6.13.c:1634 and
/tmp/linux-v6.18-fork.c:1432. Existing read-only failed-store wake, delayed waiter,
invalid-memory, callback-error and no-second-store tests remain unchanged. Commit
15820fcc88d56afba58a76ecb92e80787fcbb249 records their original native qualification
and mutation evidence. No wake helper was changed in this repair.

## Verification

The required-KVM all-features/all-targets package passed 597 tests, with zero
failures or ignores, in 23.203 seconds including build. The existing fatal and
cancelled-worker memory/slot controls are included. A new test tuple initially
triggered Clippy's type-complexity lint; a type alias resolved it. On final source,
the focused three-pthread test passed in 0.21 seconds and the four-case lifecycle
test in 0.52 seconds; Clippy and formatting passed. The type alias changes no
fixture or assertion. Complete commands and times are retained in:

- /tmp/astra-reverie-kvm-process-tool-final-checks.json
- /tmp/astra-reverie-kvm-process-tool-final-corrected-checks.json
- /tmp/astra-reverie-kvm-process-tool-final-package.log

The final hierarchical run reports one process and four exited threads, with the
exact native stdout `three-pthreads-executed-and-joined`. Its observed syscall
count was 69; the test does not assert scheduling-dependent pthread syscall totals.
The separate lifecycle Tool checks unique thread callbacks, distinct process
state and one process callback after every thread callback:

| Guest control | Exit | Per-process exited thread counts |
| --- | --- | --- |
| Ordinary worker exit, live sibling and failed exec | 0 | 3 |
| Parent thread exit followed by fork and child threads | 0 | Parent 2, child 3 |
| Root exit_group with two workers | 37 | 3 |
| Worker exit_group with root and sibling | 41 | 3 |

Two deliberate production regressions fail the retained test: reconstructing
Tool state per thread reports 1 instead of 4; restoring blanket worker
cancellation exits the guest at iteration one and reports 3 instead of 4.
Both source mutations were restored before positive verification. Evidence:
/tmp/astra-reverie-kvm-process-tool-fresh-thread-mutation.json and
/tmp/astra-reverie-kvm-process-tool-cancel-all-mutation.json.

## Explicit remaining leader-exit failure

https://github.com/rrnewton/reverie/issues/549 retains the complete native C
reproducer and acceptance criteria for raw SYS_exit from the thread-group leader.
Linux lets its remaining worker print and exit. Both plain and Tool KVM on main,
and on this repair, instead exit zero with empty stdout. The existing leader
cancellation/process-hook shortcut is preserved here, not qualified as Linux
parity. Repairing leader-first lifetime and final process status is separate work.

The fixed native/KVM comparison is retained in
/tmp/astra-reverie-kvm-leader-first-main-qualified.json and
/tmp/astra-reverie-kvm-leader-first-candidate-qualified.json, with full Rust control
/tmp/astra-reverie-kvm-leader-first-regression.rs. The initial control mistakenly
wrote 30 bytes from a 32-byte message and failed its native assertion before KVM;
those earlier logs remain harness failures, not product evidence. The corrected
native witness is unchanged between the main and repaired backend runs.
