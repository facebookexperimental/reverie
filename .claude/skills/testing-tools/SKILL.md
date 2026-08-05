---
name: testing-tools
description: "How to build, run, and test Reverie tools — the nightly toolchain, validate.sh gate, package-scoped cargo commands, the host-dependent test skip list, running the reverie-examples tools (noop/strace/counter/chaos) over a backend, and the reverie-dbi test scripts. Read before validating a Reverie change or writing a new tool."
---

# Testing Reverie Tools

Reverie uses the **nightly** toolchain (`rust-toolchain.toml`). During iteration
prefer package- or test-scoped `cargo` commands; before handoff run the broadest
gate the host supports. A Reverie-only suite pass is floored at **L0** — it does
not establish an L1+ determinism guarantee (that needs an integrated Hermit run;
see the Assurance Levels table in `AGENTS.md`).

## The canonical gate: `./validate.sh`

`validate.sh` is the local repository gate. It writes an exact-SHA receipt and may
apply a derived `locally-validated` label; the label is only a cache. It sets
`RUSTFLAGS` (`-D warnings` plus an lzma link arg) and runs, in order:

1. **Skill discovery** — `scripts/check-skill-discovery.rs`
2. **Merge policy** — `scripts/check-merge-gate-policy.sh`
3. **Build** — `cargo build --workspace --all-features`
4. **Test** — `cargo test --workspace --all-features` with `--skip` for
   host-dependent cases (see list below)
5. **Doc tests** — `cargo test --workspace --doc`
6. **Clippy** — `cargo clippy --workspace --all-targets --all-features -- -D warnings`
7. **Rustfmt** — `cargo fmt --all -- --check`

Use focused tests while editing, then run this full local gate once at the
final committed head. For landing, Reverie's current authoritative
`merge-gate-v2` must dereference exact-head passing results for both
`Regular tests (GitHub-hosted)` and `Host-dependent tests (self-hosted)`. A
local receipt or `locally-validated` label is supplemental cache evidence, not
landing authority; missing, skipped, stale, or failed authoritative jobs are
not green.

## Package-scoped iteration

Full-workspace builds are expensive; scope to what you changed:

```bash
cargo build -p reverie-ptrace --all-features
cargo test  -p reverie-ptrace --all-features -- --test-threads=1
cargo test  -p reverie-ptrace --all-features -- <test_name_substring>
cargo clippy -p reverie-ptrace --all-targets --all-features -- -D warnings
```

Many integration tests spawn/ptrace real processes, so run them with
`--test-threads=1` when you see cross-test interference.

## Host-dependent tests to skip (and why)

These depend on host capabilities (privileged ports, CPU affinity, namespaces,
networking, seccomp-notify) and are `--skip`ped by `validate.sh`. Report them as
environment limitations — never weaken or delete them to make a devserver green:

```
container::tests::bind_to_low_port
container::tests::pin_affinity_to_all_cores
tests::domainname
tests::hostname
tests::local_networking_*
tests::mount_*
tests::pid_namespace
tests::port_isolation
tests::seccomp_notify
tests::uid_namespace
```

PMU/CPUID/RDTSC/ptrace/seccomp behavior is host-sensitive; include host,
toolchain, and PMU facts in any failure report.

## Running the example tools (`reverie-examples`)

The example tools are the fastest way to exercise the framework and a new
backend end-to-end. Each is a Cargo bin that runs a guest command under a tool:

| Bin | Tool | Use |
| --- | --- | --- |
| `noop` | minimal `Tool` | smoke test: does the backend run a guest at all |
| `strace` / `strace_minimal` | subscribe-all + decode | verify syscall observation |
| `counter1` | in-process `GlobalState` | RPC within one address space |
| `counter2` | UDS coordinator | out-of-process `GlobalState` (fork/exec tree) |
| `chunky_print` | stdout emitter | native stdout handling |
| `chrome_trace` | Chrome JSON trace | timeline output |
| `chaos` | scheduling perturbation | signal/timer handling |
| `debug` | debug hooks | inspection |
| `reverie-kvm-counter1/2` | KVM variants | counters over the KVM backend |
| `reverie-liteinst-examples`, `reverie-liteinst-env-guest` | liteinst | LD_PRELOAD backend |

Run one with:

```bash
cargo run -p reverie-examples --bin strace -- /bin/echo hello
cargo run -p reverie-examples --bin counter2 -- /bin/sh -c 'true; true'
```

Every tool takes a `--runner ptrace|kvm` selector (`reverie-examples/src/kvm_runner.rs`),
so the same binary exercises either backend. `noop` first, then `strace`, is the
standard "is a new backend wired up?" sequence.

## DBI (DynamoRIO) test scripts

`reverie-dbi/scripts/` holds the DBI harness (the DBI client must be
**release-built** — debug frames overflow the DynamoRIO stack; a Rust panic in a
DBI handler `SIGABRT`s):

- `build-client.sh` — build the DBI client `.so` (release).
- `test-echo.sh` — run a guest under the DBI backend.
- `test-cpuid.sh` — CPUID interception check.
- `test-example-tools.sh` — runs each example tool over DBI by env-var selector
  (`HERMIT_DBI_NOOP` / `STRACE` / `SYSCALL_HISTOGRAM` / `COUNTER1` / `COUNTER2` /
  `CHUNKY_PRINT` / `CHROME_TRACE` / `CHAOS`, plus test-only `REWRITE_EXIT` /
  `SET_REG` / `PPID` / `BACKTRACE`) under `drrun -c <client> -- <guest>`.

Rust integration tests for the alternate backends live in
`reverie-examples/tests/` (`kvm_cli.rs`, `liteinst.rs`); per-tool ptrace/KVM
tests are inline `#[cfg(test)]` modules (e.g. `noop.rs`).

## Adding regression coverage

- Add tests at the **narrowest useful layer** (unit over integration where it
  proves the same thing cheaper).
- Treat syscall/signal/clone/exec/memory/timer changes as concurrency-sensitive:
  cover lifecycle edge cases (thread start, post-exec, exit ordering).
- For a syscall added to an executing backend (KVM/DBI), add a test that runs a
  guest actually issuing that syscall over that backend.
- Bot-authored syscall entries need `// AUTONOMOUS-BOT-IMPLEMENTED` and
  `// TODO-HUMAN-REVIEW(PR-id)` markers (see `AGENTS.md`).

## Reporting results

Bind every claim to evidence: exact command, backend (`ptrace`/`KVM`/`DBI`), log
level, relaxations (state "none"), and observed output — not a paraphrase. For
determinism, name the level (L0–L4) and remember a Reverie-only run is L0. See
the Precise Communication section of `AGENTS.md`.

## Post-facto human-review criteria

Apply `post-facto-human-review` exactly when a PR contains at least one of
these four triggers:

1. new syscall support, after verifying `AUTONOMOUS-BOT-IMPLEMENTED` at the
   new dispatch/classification entry and `TODO-HUMAN-REVIEW(PR-id)` at the
   implementation or determinization block;
2. a Reverie API/core-abstraction change to the `Tool`, `Guest`, `Backend`,
   or syscall-interception model;
3. a new determinization strategy; or
4. a core DetCore scheduling change affecting how programs are scheduled,
   especially race search. Trigger 4 is always labeled.

Routine backend parity toward the golden ptrace reference implementation is not
a trigger merely because it changes a non-ptrace backend. It is labeled only if
it also meets one of the four triggers.

Every PR description requires `Summary`, mandatory `Determinism` (why the
change is deterministic plus its logic or informal proof), and `Validation`.
KVM PRs also require `Relationship to gVisor`. A labeled PR additionally
requires `Human Review Required`, naming the specific numbered trigger rather
than vague prose such as "backend change". The syscall tags above verify trigger
1; they are not blanket backend-change markers. Hermit
[PR #1151](https://github.com/rrnewton/hermit/pull/1151), which moved slowdown
into virtual-time/epoch scheduling, is the canonical good example for trigger 4.

## Related skills

- `reverie-architecture` — what the tools and backends are.
- `syscall-interception` — the handler logic the example tools demonstrate.
- `adding-a-backend` — validating a new backend with these tools.
- `repo-cleanliness` — keep experiments/binaries out of `reverie/`.
