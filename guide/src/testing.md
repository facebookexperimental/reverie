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
> 🚧 **Under construction — tool test skeleton.** TODO: a copyable
> test module for a new tool crate: oracle comparison against ptrace,
> one refusal assertion, one lifecycle case.
> <!-- UC: testing-skeleton -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`testing-skeleton`).
