# Tool cleanup after exec worker failure

A leader exec cancels and joins its workers before replacing the address
space. If worker teardown fails, exec remains an error and must not execute
the replacement image. The started owner still owes its consuming thread and
process Tool hooks.

[`Error::ExecWorkerTeardown`](../reverie-kvm/src/error.rs) preserves the original
worker error from this boundary. The common `finish_tool_process` in
[`runtime.rs`](../reverie-kvm/src/runtime.rs) handles the static-ELF Tool loop's
terminal outcomes, including subscribed and unsubscribed exec failures. It
retires the exact task, releases its slot and file/stdin references, completes
registered clear-TID handling, and finishes worker cleanup before consuming
the owner's hooks. It attempts the process hook even if the thread hook
fails, then collects independent fork children.

The original exec-worker error is reported once; cached copies are not added
again. Additional owner-hook and child-cleanup errors remain in the returned
diagnostic. Error-cleanup hooks use status 255, but the backend result remains
an error rather than a successful guest exit.

The [exec error controls](../reverie-kvm/tests/support/exec_worker_error_diagnostic.rs)
cover both exec paths, successful replacement, original worker failure and
combinations of owner-hook failures. See [`vm.rs`](../reverie-kvm/src/vm.rs)
for the pre-replacement boundary. Non-leader exec remains subject to the
[backend's explicit refusal](../reverie-kvm/README.md#current-limits).
These cleanup rules do not establish Hermit scheduler progress or general
parent/child waitability.
