---
name: liteinst-testing
description: "Use when adding LiteInst regressions, selecting focused test coverage, diagnosing guest hangs, or reporting backend and determinism evidence."
---

# LiteInst Testing

## Preconditions

Tests require Linux x86-64, dynamically linked guest programs, seccomp/SIGSYS,
and permission to load the generated preload DSO. Run process-wide runtime tests
serially with `--test-threads=1`.

## Coverage Matrix

Use `tests/strace.rs` for:

- first-trap patch installation and hook counts;
- built-in strace and compatibility event stability;
- event-fd isolation, spoof rejection, backpressure, and recovery;
- compatibility fork behavior and explicit unsafe clone/exec failures.

Use `tests/rpc_tool.rs` for:

- shared coordinator RPC and hook reentry bypass;
- preinstalled, pending, blocked, or spoofed SIGSYS states;
- syscall subscription, thread/process callbacks, and injected exit;
- typed tool guest access and coordinator interaction.

Use `../reverie-examples/tests/liteinst.rs` for:

- the public `LiteinstBackend` launcher and bootstrap contract;
- concrete no-op, counter, chaos, strace, and trace tools;
- output, environment, descriptor, allocator, and tool-option behavior.

## Commands

Start narrow, then broaden:

```bash
cargo test -p reverie-liteinst --test strace -- --test-threads=1
cargo test -p reverie-liteinst --test rpc_tool -- --test-threads=1
cargo test -p reverie-liteinst --all-features -- --test-threads=1
cargo test -p reverie-examples --test liteinst -- --test-threads=1
cargo fmt --all -- --check
cargo clippy -p reverie-liteinst --all-targets --all-features
```

Use a bounded external timeout while diagnosing a possible hang, but do not add
large internal sleeps or weaken assertions to mask it. Capture the exact test,
guest command, child/process state, and whether execution reached trap, hook,
tool dispatch, or RPC.

## Regression Design

- Test the owning contract at the lowest layer that exposes it.
- Assert externally visible behavior, not incidental log formatting or syscall
  totals, except for the dedicated first-trap/hook regression.
- For patching regressions, execute the same syscall site repeatedly and prove
  one discovery trap followed by hook entries. The established signature is
  `calls=32 traps=1 hooks=32`.
- For bootstrap and descriptor regressions, prove control state is sealed,
  consumed, protected, and hidden from the guest.
- For safety boundaries, assert explicit rejection and no hang.
- Avoid global environment leakage between tests; restore any process state the
  test owns.

## Evidence Discipline

Record the full commit SHA, host architecture, exact commands, and results.
Distinguish:

- a direct preload/crate test;
- a public Reverie `LiteinstBackend` examples test;
- a Hermit CLI run at compatible landed revisions.

The first two are L0 evidence. They do not establish Hermit L1 record or L2
strict verify. State unsupported signals, multi-threading, clocks, and
preemption directly rather than implying deterministic coverage.
