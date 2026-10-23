# reverie-inguest

Part of [Hermit](https://hermetic-infra.org) and
[Reverie](https://docs.rs/reverie-core). See the
[API documentation](https://docs.rs/reverie-inguest) for embedding this runtime,
and [`hermit-run`](https://crates.io/crates/hermit-run) for the command-line
interface. Hermit selects this runtime only through optional backends.

Shared `LD_PRELOAD` + seccomp/`SIGSYS` instrumentation runtime for Reverie's
ld-preload backends (**e9patch** and **liteinst**). It exists so the ld-preload
mechanism is written and reviewed once instead of duplicated per backend (DRY).

## What it provides

| Module | Responsibility |
| --- | --- |
| `seccomp` | Trap-everything-but-the-trusted-gate classic-BPF filter (`TSYNC`), with a testable builder. |
| `trap` | Trusted syscall gate (asm), the `SIGSYS` handler, `raw_syscall6`, dispatcher registration. |
| `dispatch` | The `SyscallDispatcher` seam + shared fail-closed `PassthroughDispatcher`. |
| `fork` | Fork-following hook (the filter is inherited atomically; only per-process state resets). |
| `signal` | Signal multiplexing / reserved-signal (`SIGSYS`) policy + alt-stack. |
| `lifecycle` | `LifecycleController` guest-half seam: `InProcessSeccomp` and `HybridPtrace` install the same SIGSYS/seccomp mechanism; launcher selection is separate. |
| `rpc` (feature `coordinator-rpc`) | Synchronous coordinator client, **wire-compatible** with the async `reverie-rpc-transport` (`RpcServer<G>`). |

## Coverage boundaries

Established by the `research-ldpreload-derisking` task and enforced here: this
runtime is for **trusted, dynamically linked, non-`AT_SECURE`, no-exec** x86-64
guests. It does **not** cover vDSO fast paths, the ~40 loader/startup syscalls
before the constructor runs, static binaries, or `execve` (all fail closed).
`fork`/`clone` children *are* fully covered — the kernel inherits the filter
atomically, so there is no post-fork install race.

## Two ways to use it

* **As a library (`rlib`):** a backend embeds the runtime, registers its own
  `SyscallDispatcher`, and calls `reverie_inguest::install(...)`.
* **As a standalone `LD_PRELOAD` (`cdylib`):** set `REVERIE_INGUEST_TOOL`
  (`passthrough` or `spoof-getpid`) and preload `libreverie_inguest.so`.

```rust,ignore
use reverie_inguest::dispatch::PassthroughDispatcher;
use reverie_inguest::lifecycle::{InProcessSeccomp, RuntimeConfig};

// From a backend, before untrusted threads start:
unsafe {
    reverie_inguest::install(
        Box::new(PassthroughDispatcher::new()),
        &InProcessSeccomp,
        &RuntimeConfig::default(),
    )?;
}
```

## Hybrid-ptrace boundary

The `LifecycleController` trait separates *policy* (`SyscallDispatcher`) from
the guest-half trap mechanism. `lifecycle::HybridPtrace` is implemented and
installs the same in-process SIGSYS handler and trusted-gate seccomp filter as
`InProcessSeccomp`; it does not create or inspect a ptrace launcher. A caller may
pair it with a unit-tool `TracerBuilder<()>`: that launcher adds no
`PTRACE_EVENT_SECCOMP` syscall action, but it still sees residual SIGSYS as a
signal-delivery stop before reinjection. Neither controller closes the
dynamic-loader window before the preload constructor or covers vDSO fast paths;
`exec` requires caller-owned rebootstrap policy. The dispatcher, seccomp filter,
trap handler, and RPC client remain shared.

## Migration note for existing backends

`reverie-liteinst` predates this crate and currently carries its own copies of
the seccomp/`SIGSYS`/gate primitives. Folding it (and `reverie-e9patch`) onto
this shared runtime is a follow-up owned by those crates' maintainers; this
crate is deliberately standalone and does **not** modify them.

## Dormant keyed-owner qualification

`guest::tool_region::KeyedToolRegion` is an opt-in native setup owner. Its
mapping and owned protection key have process lifetime. This change activates
no guest stack, allocator, entry path, clock policy or protection cell. It
provides accidental-memory isolation for its owned interiors under the documented
unsafe native preconditions; `WRPKRU` and signal-return authority remain with
trusted in-process code.

Ordinary library tests select every existing test and the forced Unsupported
contract control. The 15 new native PKU cases use explicit ignored registrations.
Those omissions earn zero physical protection credit and do not impose a new
OSPKE requirement on ordinary library testing:

```sh
cargo test --offline --locked -p reverie-inguest --lib -- --test-threads=1
```

For the no-default-feature library artifact, the recorded discovery set has
170 IDs: 154 existing IDs, one ordinary Unsupported control and 15 ignored
hardware IDs. Verify the actual selected, ignored and filtered counts for the
features and fresh artifact being qualified. The injected Unsupported control
checks the optional API error contract; it does not measure an unsupported CPU
or earn a protection pass.

The following 15 exact IDs form the required supported-host selection for the
dormant owner. Run it in a trusted ordinary native process on x86-64 with OSPKE,
available pkeys, no installed seccomp filter, and the documented single-thread
setup conditions. Use the validation owner's existing resource containment and
exact clean-source/fresh-ELF guard; this recipe is not a substitute for those
bounds. Existing X64 or KVM runner labels do not establish PKU support.

```sh
set -eu
while IFS= read -r test_id; do
    cargo test --offline --locked --no-default-features -p reverie-inguest --lib \
        "$test_id" -- --exact --ignored --nocapture --test-threads=1
done <<'KEYED_OWNER_HARDWARE_IDS'
guest::tool_region::tests::keyed_oracle::actual_keyed_interiors_deny_read_write
guest::tool_region::tests::keyed_owner::collision_preserves_occupant_and_retains_failure
guest::tool_region::tests::keyed_owner::actual_key_exhaustion_is_retained_without_mapping
guest::tool_region::tests::keyed_owner::reuse_resets_keys_and_retention_keeps_owner_key
guest::tool_region::tests::keyed_owner::actual_reset_and_discard_failures_quarantine_extents
guest::tool_region::tests::keyed_owner::actual_unmapped_interior_quarantines_failed_lease_rollback
guest::tool_region::tests::keyed_owner::closed_key_descriptors_never_read_control
guest::tool_region::tests::keyed_owner::ready_fork_preserves_cow_occupied_stack_and_key
guest::tool_region::tests::keyed_owner::inherited_preparing_gate_never_resets_in_child
guest::tool_region::tests::keyed_owner::inherited_allocation_gate_refuses_and_drop_quarantines
guest::tool_region::tests::keyed_owner::failed_control_tagging_precedes_every_typed_write
guest::tool_region::tests::keyed_owner::uncertain_tagged_cleanup_keeps_mapping_and_key
guest::tool_region::tests::keyed_owner::key_free_failure_retains_key_after_complete_unmap
guest::tool_region::tests::keyed_owner::relocated_return_cleanup_never_unmaps_requested_occupant
guest::tool_region::tests::keyed_owner::copied_builder_cannot_publish_or_clean_inherited_resources
KEYED_OWNER_HARDWARE_IDS
```

When executing a previously built authenticated test ELF through the existing
bounded native runner, the equivalent exact argv is:

```text
ELF --exact ID --ignored --nocapture --test-threads=1
```

All 15 selected functions must execute and pass. The exact self-reexec supervisor
includes ignored tests for its one exact child ID and retains its 30-second
process, 3-second raw-fork, 64-KiB stream and descendant-cleanup bounds. Do not
replace its parent-supervised result with direct-child output capture.

The physical oracle still requires all 32 actual desired accesses, including
16 real `SEGV_PKUERR` denials with exact `si_addr` and literal MOV RIP, all 32
legacy access controls, all 32 `SEGV_ACCERR` guard controls, complete VMA coverage,
and unchanged allowed-byte and PKRU checks. A selected unsupported, setup,
compile, timeout or access-allowed failure is nonqualification. An ignored or
unselected case has zero measured protection rows. The five unfiltered
`reverie-liteinst-artifact` library tests remain an additional required gate:

```sh
cargo test --offline --locked -p reverie-liteinst-artifact --lib
```
