# Child-exit signals selected by a Tool

[`Guest::queue_child_exit_signal`](../reverie/src/guest.rs) accepts a complete
process-directed terminal `SIGCHLD` event with `CLD_EXITED`, `CLD_KILLED`, or
`CLD_DUMPED`. The caller authenticates the child identity, class-specific
terminal status, UID and CPU accounting and owns the event's deterministic
ordering. Queueing does not generate an automatic child notification or change
wait status and reaping policy.

KVM requires the current registered process leader, with no live sibling or
prepared thread creation, at a supported return-to-user boundary. Syscall,
signal and captured page-zero-fault callbacks provide such boundaries. Initial
thread-start, exec and post-exec callbacks refuse before effects. The event
must target the current process and contain zero `si_errno`, a positive child
PID and nonnegative CPU fields. `CLD_EXITED` carries an unsigned exit byte from
0 through 255. `CLD_KILLED` carries a signal from 1 through 64 whose Linux
default action terminates, including a core-default signal when no core bit is
reported. `CLD_DUMPED` carries a Linux core-default signal. Incoherent
class/status pairs, other producers, thread targets, stale identities and
unsupported contexts are refused.

Publication retains the first complete siginfo when standard signals coalesce
in the process pending set. Explicit `SIG_IGN` suppresses generation even when
blocked; `SIG_DFL` and `SA_NOCLDWAIT` do not suppress Tool observation. Blocked
events remain pending. Fork receives independent empty pending state, while
exec retains accepted events. Pending process events prevent creating an
unsupported competing thread consumer. A Tool-returned child event is
validated again before delivery.

[`ChildExitSignalOutcome`](../reverie/src/signal.rs) distinguishes rejection
before publication, accepted disposition, and `FailedAfterCommit` if a
signalfd readiness update fails after publication. The last outcome retains
the event and original error; callers must not blindly retry it. Acceptance
alone promises neither a guest handler nor `EINTR`. The operation executes no
guest instruction and invokes no recursive Tool callback or scheduler RPC.

Virtual signalfd records include child status and CPU fields for all three
terminal classes. Signalfd remains nonblocking and limited to supported
single-thread process lifetimes; fork with an open virtual signalfd is refused.
This compatibility receiver does not itself generate child events.
Stopped/continued/trapped child events, multi-thread-parent delivery, arbitrary
blocked-wait interruption, and Hermit's child-exit producer and scheduler
integration remain outside this API. See the
[backend signal limits](../reverie-kvm/README.md#bounded-signal-delivery).

Implementation is in [`executor.rs`](../reverie-kvm/src/executor.rs) and
[`runtime.rs`](../reverie-kvm/src/runtime.rs). The
[receiver controls](../reverie-kvm/tests/support/child_exit_signals.rs) exercise
explicit Tool publication separately from native child wait and reaping.
