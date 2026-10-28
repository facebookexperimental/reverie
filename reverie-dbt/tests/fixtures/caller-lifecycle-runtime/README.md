# Native caller lifecycle fixture

This standalone package exports one concrete `LifecycleTool` through the normal
caller ABI. The host integration test includes `src/tool.rs` directly, so both
sides use the same typed configuration and RPC protocol. It has no tool-name
registry and no constructor-bearing in-guest dependency. Its library name,
`caller_lifecycle_tool`, is distinct from the Strace caller's library name.

The configuration passed to `output_with_caller_tool::<LifecycleGlobal>` has
version 1, nonce 73, a behavior case, a terminal syscall, and all six operands.
Default configuration is invalid. The actual Tool validates its constructor PID,
the same received configuration allocation at callbacks, initialized thread state,
and acknowledgements from the actual host Global. Startup, post-exec, selected
attempt, continuation, thread-exit, and process-exit observations use ordinary RPC.

`guest.S` is a static syscall-only application. It writes `before`, makes the
configured request with six explicit operands, and only the two continuation
cases may return. Those cases check the real result, make an independently
selected marker syscall, write `continued`, and exit through unselected
`exit_group(31)`. No native callback or terminal fact is called by the fixture.

| Host selector | Native cases and required observations |
| --- | --- |
| `caller_selected_terminal_tail_preserves_actual_status` | Selected `exit` and `exit_group`, each with 23 and 0x117; unchanged tail request, no continuation, waited status 23. |
| `caller_original_nonzero_and_masked_status_match_wait` | The same four cases with terminal syscalls unselected; no Tool attempt and exactly one consuming hook sequence. |
| `caller_suppressed_exit_resumes_before_later_consumption` | Selected `exit(23)` returns zero; guest continuation precedes one later consuming hook sequence and actual wait 31. |
| `caller_rewrite_away_from_exit_resumes_before_later_consumption` | Selected `exit(23)` tails to `getpid`; guest compares the result with its actual `gettid`, continues, and later waits 31. |
| `caller_rewrite_to_terminal_preserves_actual_status` | Selected `getpid` tails to `exit_group(23)` or `exit_group(0x117)`; no continuation and actual wait 23. |

Every case asserts the complete RPC event sequence and the same configuration.
An attempt-local destructor must run before a continuation or consuming hook.
The host requires exact stdout, empty stderr/diagnostic output, expected actual
waited status, and one thread/process hook each. Each case reexecutes its exact
test selector with exactly one successful harness summary and one completion
witness. The unchanged ten-second execution limit kills and reaps the helper's
process group on timeout. The assembly is compiled once, before that limit,
with `CC` (or `cc`) under Cargo's existing target temporary directory.

## Build and run

The package has its own workspace and checked-in lock. Its DBT dependency uses
`default-features = false`; workspace all-feature builds must not unify prototype
exports into this caller. An explicit build-time identity is mandatory: the
build script refuses missing or malformed `REVERIE_DBT_CALLER_INPUT_IDENTITY`.
Do not set a fabricated identity or export one for unrelated workspace builds.

From the repository root, with the same existing Cargo target directory and the
cached SDK required by the generic producer:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=8 \
  reverie-dbt/scripts/build-client.sh \
  --caller-manifest reverie-dbt/tests/fixtures/caller-lifecycle-runtime/Cargo.toml \
  --profile debug --jobs 8 --check
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=8 \
  cargo test -p reverie-dbt --test caller_lifecycle_live -- --test-threads=1
```

Use matching producer/test profiles. The standalone `validate` profile inherits
release with debug assertions and overflow checks enabled and LTO off. The
producer's required `--check` runs standalone all-target/all-feature check,
format check, Clippy with warnings denied, and rustdoc with warnings denied using
the actual generated identity. Main workspace gates remain required separately.
Both normal and hardware CI invoke this producer with `--check` before their
nonignored workspace tests. They retain the existing Strace caller producer and
legacy prototype producer prerequisites.

The host loads exactly
`<profile>/reverie-dbt-callers/caller-lifecycle/manifest.json`. Missing, invalid,
or stale manifests fail; there is no fallback. The existing generic producer
binds the standalone lock, root lock/toolchain, resolved local-package source
closure (including this guest and host test), its own producer sources, SDK
inventory/provenance, and both actual images. An immutable identity-named image
generation is staged before the small default manifest is atomically replaced.
The SDK's hash-bound inventory is checked against its actual files and symlinks.
The fixture adds no alternate SDK build or special staging protocol.

## Evidence limits

Exactly-once hooks after a physical native exit cover ordinary teardown. The
public caller API does not safely force a second native thread-exit notification;
these tests do not claim forced-native duplicate coverage. A synthetic call to
an exported callback would remain a separate boundary test. Also, an RPC record
of requested operands and a matching receipt/wait status are not an externally
retained snapshot of the final native registers. Existing native guard controls
have that separate scope.

The original Strace/LiteInst test bodies, selectors, and ten-second bounds are
unchanged and remain mandatory. This fixture's results cannot replace them.

## Native RPC disconnect extension

Four additional nonignored library selectors under
`launcher::tests::caller_transport_failure` use this same concrete Tool and
caller artifact:

- `caller_async_rpc_disconnect_is_native_transport_failure`
- `caller_sync_rpc_disconnect_is_native_transport_failure`
- `caller_thread_exit_rpc_disconnect_is_native_transport_failure`
- `caller_process_exit_rpc_disconnect_is_native_transport_failure`

The explicit Config adds a `DisconnectPoint`; ordinary lifecycle cases set it to
`None` and keep every original oracle. Async and sync cases select a real
`getpid` callback. Terminal cases leave the physical `exit_group(23)` unselected
and disconnect during the real consuming thread or process hook. All four guest
paths close application fd 2 before the target request. No fake native callback,
wire control, local Global, alternate transport or runtime test switch is used.

The host arms an observation channel on the same real Global, records the exact
request and its authenticated sender, then leaves its response pending. Only
after that witness does the owner shut down `RpcServer::serve_until`; it awaits
joined connection cancellation, requires one pending-request destructor and zero
active connections, and uses the existing launcher wait to reap the actual
native child. All four require status 123, one native backend-failure record,
one named native transport-failure diagnostic, empty guest stderr, no resumed
marker, no Finished receipt and the exact callback prefix. Sync unsupported is
an error, never an async fallback. The process-exit case requires the preceding
thread-exit RPC to have completed; the thread-exit case forbids a process-exit
request. These assertions do not manufacture a forced duplicate notification.

The same ten-second helper process-group supervisor applies. Native children
inherit that group, and the syscall-only guest cannot fork or change groups.
Protected-evidence mode creates another process group, so this draft does not
claim protected-evidence session coverage. Its backend-failure observation uses
the existing actual native stats record plus the named native diagnostic.

The public runner owns its server internally. These four controls therefore
live beside the launcher tests and use its existing private command/spawn/wait
helpers; they do not claim the public method's complete error-return path. A
separate source-backed public-route candidate is an intentionally panicking
controller request: the existing server unwinds/drops that actual connection.
That candidate needs distinct host-panic witnesses, guest nonpanic assertions,
and leak observations; it is not implemented by the four shutdown selectors.

Build this package with the same mandatory `--check` producer as above. Then,
with the matching admitted profile, list/run the four library selectors:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=8 \
  cargo test -p reverie-dbt --lib launcher::tests::caller_transport_failure:: \
  -- --test-threads=1
```

The owner-agreed `reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE: i32 = 123`
export and exact diagnostic `reverie-dbt: caller Tool RPC transport failure\n`
require the real `rpc_transport_fatal` context-only nonreturning callback. Its
product implementation is a prerequisite. The unlanded ABI16 table revision
must be 104 bytes with strict size checks and matched native/Rust/H adapters.
No local fallback constant or test-only fatal callback may fill that dependency.

## Public runner controller-failure control

The additional nonignored library selector
`launcher::tests::caller_transport_failure::caller_public_runner_retains_native_transport_failure_after_controller_panic`
uses the same concrete Tool with explicit AsyncControllerPanic Config. It calls
actual public output_with_caller_tool. The real Global waits for an independent
host observer to acknowledge the target request, then deliberately panics under
an asserted unwind strategy. Existing server unwinding closes the real socket.

The public Err must retain actual native status 123, exact `before\n` stdout and
exact `reverie-dbt: caller Tool RPC transport failure\n` stderr. The native
diagnostic descriptor survives the guest's close(2) through the launcher's
existing duplication; no separate diagnostic file is used for this control.
The expected controller panic is observed exactly once in the helper stderr,
separate from the exact nonpanic native output. No panic hook is suppressed.

Final actual Global/request Drop witnesses, exact RPC prefix and real native
backend-failure stats are required. The public activation-refusal message is
checked; there is no public receipt or connection-monitor getter. The original
ten-second group supervisor and mandatory normal/hardware producer --check
remain unchanged. The test does not enable protected evidence or claim forced
late native duplicate coverage. All seventeen fixture native cases remain
nonignored; existing original Strace/LiteInst oracles are unchanged.


## Startup disconnect before Started

The added nonignored library selector
`launcher::tests::caller_transport_failure::caller_startup_rpc_disconnect_before_started_is_native_transport_failure`
uses explicit Startup Config and the same actual Global/owned-server shutdown.
It witnesses the ordinary handle_thread_start RPC after real Claim and Tool
construction, while attachment state is Starting, before post-exec, Started,
application admission acknowledgement or first guest instruction. It is not a
post-Started activation case.

Required observations are exactly [StartHook], actual wait 123, one named native
fatal diagnostic, empty guest stdout/stderr, no Finished, one native backend
failure, one cancelled pending request and zero owned connections. The existing
ten-second supervised group and cleanup remain unchanged. Guest fd 2 is still
open in this case because the application has not run. The previous seventeen
native cases retain their separate oracles; the mandatory same-profile producer
--check and normal/hardware CI inclusion apply to all eighteen cases.
