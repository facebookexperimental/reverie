# KVM exit descriptor ordering

For exits through the signal-permit protocol, the controlled KVM backend must
finish descriptor retirement before another scheduled process can observe pipe
EOF. This covers exit syscalls and permit-protocol fatal signals. Synchronous
hardware faults such as SIGSEGV, SIGBUS and SIGILL bypass that protocol; their
EOF visibility remains host-timed. A terminal task's receipt is not enough
for a process with several threads: each executor owns duplicated host files,
and each CLONE_FILES executor owns the shared table as well.

## Two causal fences

The first fence is the existing SignalDeliveryPermit / terminal boundary.
Before reporting Terminated, KVM releases only the issuer's executor and backend
stdin references. Returning, ImageReplaced, Cancelled and Failed receipts do not
perform this early close. An individual SYS_exit must retain every live
CLONE_FILES sibling's descriptors.

On a final process transition, Detcore installs the second fence in the same
scheduler critical section that consumes the first receipt. It does so before
removing the first fence or logically killing the group. There is no interval
in which another deterministic turn may run between those operations.

A live direct parent already uses a generation-bound child-exit publication
reservation as this second fence. Root processes and processes whose direct
parent is terminal need an equivalent process-retirement reservation. The
Hermit companion adds that reservation to control_barrier and the scheduler's
empty-run completion check.

The first receipt logically kills peers and cancels their pending RPCs through
the existing KVM cancellation mechanism. It must not wait for their joins:
peers may be suspended in exactly those RPCs. Peers then run their ordinary
consuming cleanup, release their descriptors and table references, and return
to the leader's join. Constructed but unstarted workers are also cleaned before
that join completes.

After all workers have joined and the leader has released its own descriptors,
KVM invokes GlobalTool::on_backend_process_retired with the exact
SignalProcessId (numeric TGID and generation) and authoritative exit status.
It runs after existing family/child publication, but before leader consuming
hooks and joins of independent child processes. Those children may need later
scheduler turns, so waiting for them while the fence remains held would be a
cycle. Unstarted processes do not emit a retirement notification. A started
process that terminates through a synchronous hardware fault still emits this
physical-cleanup notification, even though it had no controlled terminal
receipt. Offering this callback requires BackendSignalControl; a Tool may
hold a fence for it only after installing ToolControlled mode.

Detcore validates the event against its exact recorded terminal process and
pending reservation. It removes only that reservation and records an exact
completed witness for duplicate recognition. Early, stale, unknown or
conflicting events fail the run before any barrier is removed. A live parent's
notification must follow its existing successful child publication and cannot
replace that publication. Cleanup errors and panics use the existing fatal
backend failure path; they never masquerade as successful retirement.

When there is no recorded controlled terminal transition, Detcore authenticates
the exact current process generation, including after its last task's consuming
hook. It rejects an event if that process still owns a delivery permit, exit
fence, child-publication reservation or process-retirement reservation. Otherwise
it records the completed notification without releasing a barrier, waking the
scheduler, changing membership or publishing a child event. Exact duplicates
remain idempotent and conflicting statuses remain errors. This preserves the
normal disposition of root and orphan hardware faults without treating an
early receipt for a controlled boundary as successful cleanup.

This distinction belongs in the consumer because its reservations say whether
it actually fenced the exit. A backend bit recording any earlier Terminated
receipt would be insufficient: a leader may exit individually through the
protocol before its last worker faults without a permit. Selecting callback
emission from the backend's initiating task would also have to account for
every peer's pending permit. Keeping the consumer's existing terminal records
authoritative avoids that independent inference. The cleanup notification
reports what finished; it does not manufacture a terminal boundary or a
determinism claim.

The companion must accompany the Reverie pin: the default GlobalTool hook is a
no-op for tools without this scheduler protocol. Adding only the backend hook
does not impose the second fence on an older Detcore.

## Determinism argument

The membership of each barrier is the exact process lifetime selected by the
guest-causal terminal transition, not the set of host threads that happen to
have completed by a polling deadline. There are two possible host orders after
the terminal receipt:

- The leader or a peer retires first. Its private file owners close, but the
  second fence remains until all worker joins and leader cleanup finish.
- A peer is suspended in a Tool RPC or owns a pending start. Logical retirement
  cancels the RPC / start; its cleanup is included in the same final join.

In either order, no unrelated guest read can be granted before the final
retirement receipt. The last host pipe-writer reference is gone when close
returns, so the next granted read observes EOF. The same argument applies when
a worker, rather than the leader, issued exit_group or received a permit-protocol
fatal signal. The leader still owns the final joins and retirement notification.

A live sibling after individual SYS_exit remains an owner and can still write.
An independently forked process is also a legitimate owner and is not included
in this thread-group retirement. EOF must continue to wait for that owner.
No turns, virtual-time increments, retries, log records or I/O comparisons are
invented or removed by the barrier.

## Lock and interrupt argument

release_files_on_exit has exclusive mutable access to its executor. It takes
files and stdin from the task-private LoadedStaticElf, clears private entry
identities and pending process action, and replaces only this executor's Arc to
the shared file table. It never reads or modifies a surviving FileTableState.
Consequently it does not need either the shared file-table mutex or the
process signal-transaction mutex. Acquiring those locks would introduce an
unnecessary dependency on a peer's blocking syscall before the terminal
receipt could cancel that peer's Tool RPC.

The implementation removes both acquisitions. Its per-executor FileRetirement
scope is fresh for fork/thread children and cannot be held by another executor.
Host files retire outside shared guards. Dropping the last table Arc also runs
without its mutex held; otherwise another owner retains it unchanged. The
controlled signal-publication path uses independent carriers and does not
upgrade the legacy weak table to own guest descriptors during this interval.

Therefore descriptor detachment does not depend on the timing of SIGURG. If a
peer already holds both locks, is about to acquire them, or has just released
them, the issuer can detach its private references in all three orders. The
regression holds both locks until release_files_on_exit has returned, then
proves that the sibling can still write and the final owner closes the pipe.
Restoring the old acquisitions fails that completion assertion without leaving
a blocked test worker behind.

This does not remove the existing backend's need to interrupt blocking host
operations during normal group cancellation and worker joins. It removes the
new pre-receipt shared-lock dependency; the second fence follows the already
used live-parent cancellation/join order.

## Host close and Linux semantics

Linux pipe(7) defines EOF by closure of every write-end reference. _exit(2)
distinguishes the raw SYS_exit task operation from process-wide exit_group.
Linux closes the exiting task's file ownership before reporting its final exit;
a shared table remains valid for a live sibling. The two fences select that
permitted ordering without prematurely closing another live owner's files.

The host File destructor still performs close. A TCP socket with SO_LINGER can
keep that close blocked for its configured linger interval, and a host file
system may impose its own I/O completion latency. No scheduler mutex is held
while this happens, but the deterministic fence remains held; allowing another
guest turn before descriptor retirement would reopen the EOF race. The test
suite does not establish a universal upper bound on host close latency.

This is an existing KVM modeling limitation: Linux process-exit socket cleanup
can linger in the background, whereas the backend releases a Rust File using
ordinary host close. Changing SO_LINGER on a shared open file description or
forcing an abortive close would change live-owner behavior or discard queued
data, so this patch does neither. The ordering guarantee concerns the state
visible after retirement completes, not a new guarantee of bounded external
host-I/O latency. Primary references: Linux _exit(2), pipe(7), and socket(7).

## Evidence

The runtime controls inspect real pipes inside actual boundary callbacks and
preserve usable descriptors on all non-Terminated outcomes. The executor
control holds both shared locks across issuer retirement. The guest regression
executes real multithreaded group exits and checks the process-retirement hook
before the backend is destroyed. Hermit scheduler tests cover Root and
DirectParentTerminal, exit_group and permit-protocol fatal termination, leader
and worker issuers, pending peer RPC cancellation, exact receipt validation, live-parent
publication preservation, and empty-run completion.

Strict Hermit verification uses INFO records and I/O buffer comparison; the
only permitted failure allowance in the original matrix is the intentional
exit 7 of root-exits. Repeated multithreaded root exit_group verification is a
compatibility check: those Root-class cells did not distinguish the retirement
barrier mutant in 11 pairs. The Detcore retirement unit tests and the Reverie
six-mode real-guest regression establish the barrier's necessity. Hardware-fault
regressions cover root and orphan SIGSEGV disposition and strict verification;
they do not establish deterministic EOF ordering for synchronous faults.
Exact results and mutation evidence are recorded with the signed candidate's
implementation handoff. Review approvals must refer to that new exact head and
the Hermit companion, not the preceding single-task fix.
