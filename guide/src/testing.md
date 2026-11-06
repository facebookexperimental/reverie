# Testing your tool

The defining test of a Reverie tool is not "does it work?" but "does
it work *identically on every backend it claims*?" Test at the
Reverie layer, against real guest programs, with the reference
backend as oracle.

## The cross-backend habit

The examples are built for this: one `Tool` implementation, launchers
that select a backend at run time, and an end-to-end harness that runs
the same tool + program across backends and compares observable
behaviour:

```console
$ reverie-examples/e2e/run.sh --backends ptrace,liteinst,in-guest-trap
$ reverie-examples/e2e/run.sh --backends kvm   # needs /dev/kvm; refused by name without it
```

Copy that shape for your tool: a small corpus of guest programs
(syscall-dense, thread-heavy, fork/exec-ing, signal-using), run under
each backend, with guest stdout/stderr, exit status, and your tool's
final global state compared exactly. Where a backend refuses a corpus
program, the test asserts the *named refusal* — a refusal is a passing
outcome; a divergence is not.

A subtlety the harness itself documents: without a per-environment
ledger of known-good verdicts, cross-backend results are *reported*,
not *judged*. For your own CI, pin the ledger: record the expected
verdict per (tool, program, backend) and fail on any change you did
not intend.

## Unit-testing handlers

Handler logic that does not need a live guest — argument rewriting
rules, RPC accounting, path policies — should be factored into plain
functions and unit-tested without a backend. Reserve live-guest tests
for what only a live guest can prove: lifecycle, memory access,
injection, signal interplay. The README's quick local run is:

```console
$ cargo test -- --test-threads=1
```

CI itself (`.github/workflows/ci.yml`) runs the workspace on the pinned
stable toolchain with the stable feature set in
`scripts/stable-features.sh` (every workspace feature except the
nightly-only ones): on hosted runners with the device-dependent crates
excluded (`--exclude reverie-kvm --exclude reverie-kvm-core
--exclude reverie-linuxemu --exclude reverie-inguest`) plus
`cargo test --workspace --doc`, and on the self-hosted hardware
job the full workspace. The nightly lane
(`.github/workflows/nightly.yml`) runs `--all-features` on a nightly
compiler. Quote CI, not the README, when you need the
authoritative invocation.

(Function-guest tests that collect printing macros need the nightly
feature on a nightly compiler, or run on stable with `--nocapture`;
the ptrace crate's README explains why.)

## Determinism of the test itself

You are testing an interceptor of nondeterminism with tests that are
themselves concurrent programs. Prefer corpus programs with exact,
small outputs; compare full traces only through the typed pretty
printer (stable formatting); and treat any test that needs a sleep to
pass as a failing test that hasn't confessed yet.

> 🚧 **Under construction — conformance scorecard.** TODO: publish the
> Reverie-alone conformance matrix (example tools × backends × corpus,
> with pass counts and wall times) from the validation lane (L7), and
> link each cell's expectation from this chapter.
> <!-- UC: testing-scorecard -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`testing-scorecard`).
>
## A copyable skeleton

One integration-test file carries the three shapes above: an oracle
comparison against the ptrace backend, one lifecycle case, and one
admission refusal asserted by name. It needs `reverie-core`,
`reverie-ptrace`, `serde` (derive), and `tokio` (`macros,rt,time`)
as dev-dependencies against a checkout — the admission surface is
newer than the published 0.5.0 pair in
[Getting started](getting-started.md). Save the two listings, in
order, as `tests/tool_oracle.rs`; as printed they pass
`cargo test -- --test-threads=1` (3 tests) against this tree.
Replace the counter with your tool and the two guest programs with
your corpus; keep the three assertions' shapes.

Listing RT-1 is the tool and runner: the counter from
[Your first tool](first-tool.md), plus a `run_guest` helper that
captures output through `run_with_output` on a current-thread
`LocalSet` (the backend future is not `Send`).

<span class="filename">Listing RT-1: tests/tool_oracle.rs (part 1)</span>

```rust,ignore
//! Copyable oracle tests for a new Reverie tool crate: ptrace-oracle
//! comparison, one admission refusal, one fork/exec lifecycle case.
//! Checkout APIs (selection/admission are newer than crates.io 0.5.0).
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use reverie::process::Command;
use reverie::selection::{
    AdmissionRequest, Density, EffectiveRequirements, EnvironmentSnapshot, ExplicitSelection,
    GuestProfile, RefusalCode, ToolQueries, ToolRequirements, admit,
};
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie::{Backend, Error, GlobalTool, Guest, Pid, Subscription, Tool};
use reverie_ptrace::PtraceBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone)]
pub struct CounterGlobal {
    num_syscalls: Arc<AtomicU64>,
}

impl CounterGlobal {
    pub fn total(&self) -> u64 {
        self.num_syscalls.load(Ordering::SeqCst)
    }
}

#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(pub Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, _msg: IncrMsg) {
        self.num_syscalls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
pub struct CounterLocal;

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let _ = guest.send_rpc(IncrMsg(syscall.number())).await;
        guest.tail_inject(syscall).await
    }
}

fn run_guest(program: &str, args: &[&str]) -> (Vec<u8>, i32, u64) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let local = tokio::task::LocalSet::new();
    let mut command = Command::new(program);
    for arg in args {
        command.arg(arg);
    }
    let (output, global, _stats) = local
        .block_on(
            &runtime,
            PtraceBackend::run_with_output::<CounterLocal>(command, ()),
        )
        .expect("ptrace backend run");
    (
        output.stdout,
        output.status.code().expect("guest exited by code"),
        global.total(),
    )
}

```

Listing RT-2 is the tests. The oracle is the same program run
*without* the tool; the lifecycle case is a shell that forks and
execs a child; the refusal is pure admission — no guest starts, and
the refusal must arrive under its exact name.

<span class="filename">Listing RT-2: tests/tool_oracle.rs (part 2)</span>

```rust,ignore
#[test]
fn oracle_echo_matches_uninstrumented() {
    let oracle = std::process::Command::new("/bin/echo")
        .arg("hello")
        .output()
        .expect("oracle run");
    let (stdout, code, total) = run_guest("/bin/echo", &["hello"]);
    assert_eq!(stdout, oracle.stdout, "guest stdout must match the oracle");
    assert_eq!(code, oracle.status.code().unwrap());
    assert!(total > 0, "tool must have observed syscalls");
}

#[test]
fn lifecycle_shell_child_matches_oracle() {
    // One lifecycle case: the shell forks and execs a child; both
    // processes' output must survive instrumentation unchanged.
    let script = "echo parent; /bin/echo child";
    let oracle = std::process::Command::new("/bin/sh")
        .args(["-c", script])
        .output()
        .expect("oracle run");
    let (stdout, code, total) = run_guest("/bin/sh", &["-c", script]);
    assert_eq!(stdout, oracle.stdout);
    assert_eq!(code, 0);
    assert!(total > 0);
}

#[test]
fn dense_requirement_is_refused_by_name() {
    // Admission is pure: no guest is started for this refusal.
    let stated = ToolRequirements {
        density: Density::Dense,
        ..ToolRequirements::default()
    };
    let request = AdmissionRequest {
        requirements: EffectiveRequirements::compute(
            stated,
            Subscription::all_syscalls(),
            ToolQueries::default(),
        ),
        guest: GuestProfile::HostProcessAny,
        env: EnvironmentSnapshot::default(),
        explicit: ExplicitSelection::Auto,
    };
    let refusal = admit(&request).expect_err("no translation cell is implemented");
    assert_eq!(refusal.code, RefusalCode::RDense);
}
```
