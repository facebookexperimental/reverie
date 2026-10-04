# Terminal cancellation from KVM Tool callbacks

[`Guest::cancel_current_thread`](../reverie/src/guest.rs) abandons the current
callback without returning to guest instructions. It accepts no syscall or
status argument. `IntoGuest` forwards the operation. Other backends retain
the default exit-injection path and their existing restrictions.

KVM signals a distinct terminal outcome, suspends the callback and drops its
future before consuming thread state. It does not execute an injected
syscall, write a syscall result or treat cancellation as signal suppression.
An established backend group or fatal exit retains its status; otherwise
cancellation supplies status zero. Existing restrictions on tail injection
from signal, fault and thread-entry callbacks remain intact.

The static-ELF Tool loop uses the common `finish_tool_process` in
[`runtime.rs`](../reverie-kvm/src/runtime.rs). It retires the exact task,
releases its transport slot, completes registered clear-TID handling and
releases that task's file/stdin references. Worker hooks precede the leader's
consuming thread and process hooks; owner hooks precede collection of
independent fork children. Worker errors, owner-hook failures and child
cleanup errors remain errors. A worker transfers its child-process handles
to the owner instead of losing them on return.

Normal raw leader `SYS_exit` leaves live workers running and joins them
naturally. The process result comes from the final task or established group
exit, not from the order in which host handles are joined. Terminal
cancellation of the leader follows the cancellation path and does not
promise sibling survival. Nonleader cancellation leaves live peers and their
shared process state intact. Successful pending child starts must remain
owned and complete through the appropriate path.

See [`vm.rs`](../reverie-kvm/src/vm.rs) for worker ownership and joins, the
[terminal callback controls](../reverie-kvm/tests/support/terminal_cancellation.rs),
and [exec failure cleanup](kvm-exec-teardown-errors.md). Backend cleanup alone
does not qualify Hermit's scheduler retirement, pending-RPC cancellation,
record/replay or general parent/child scheduling. Non-leader exec and other
[backend limits](../reverie-kvm/README.md#current-limits) still apply.
