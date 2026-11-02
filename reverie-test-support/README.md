# First-party command tests

This package registers the existing first-party test sources in
`tests/basics.rs`, `exit.rs`, `stat.rs`, `vdso.rs`, `inject_then_tail.rs`,
`at_random.rs`, `stack.rs`, and `thread_start.rs`. Command helpers delegate to
ptrace's runtime, output capture, and caller-owned Tool configuration. Shared
Tools remain in `tests/tool_fixtures/`; inherited function tests keep the
original ptrace helpers and assertions.

The test dependency enables ptrace's existing `nightly` output-capture reset,
so inherited `println!` output reaches the guest pipe under ordinary libtest
capture. The workspace's pinned nightly toolchain supplies that API.

Run the registered targets with ordinary libtest capture:

```sh
cargo test -p reverie-test-support --test basics --test exit --test stat \
  --test vdso --test inject_then_tail --test at_random --test stack \
  --test thread_start -- --test-threads=1
```

The initial basics command selection remains:

```sh
cargo test -p reverie-test-support --test basics -- \
  --exact noop_tool_test counter_tool_test error_exit_test \
  run_guest_command_test run_guest_command_test_closure
```

The complete basics target also discovers the inherited function declarations;
the five command tests alone do not establish those other results. Existing
sanitizer exclusions and `should_panic` expectations remain unchanged.

## Rust guest commands and native fixtures

The eight Rust guest binaries are first-party test inputs. Cargo's explicit
`[[bin]]` declarations do not require an external backend feature. The native
BUCK declarations provide matching `rust_binary` targets and explicit
`CARGO_BIN_EXE_*` artifact paths to the corresponding `rust_unittest` targets.
`thread_start` has its own explicit test registration in both build descriptions.
These declarations describe source dependencies, not a configured or executed
native build result.

The Rust commands retain the original native/ptrace checks where the existing
oracle uses both. The AT_RANDOM and vDSO Rust command checks retain their
Tool-specific ptrace oracles; they do not gain an invented native equality
oracle. Checked assembly/C fixtures in `exit`, `stat`, `vdso`, and
`inject_then_tail` retain their native-first and actual-Tool checks. Missing
compiler capability or an unavailable required vDSO entry fails the relevant
test. Commands require x86-64 Linux, a C toolchain selected by `CC` or `cc`, and
executable temporary storage where the original fixture uses them. Helpers
retain their existing logging and have no local timeout; an enclosing validation
runner owns the deadline.

## Separate backend ownership

Only ptrace is implemented by this core package. External DBT and in-guest
adapters, their source-matched artifacts, and their positive, negative, and
missing-artifact controls belong to separate backend extensions. They must
install the caller-owned Tool and return its real global state. This package
provides no backend selector, name-based Tool substitution, silent fallback, or
physical qualification for those adapters.

The split retains the complete external sources and mixed-test controls by
immutable revision/blob records. Actual external adoption and its CI or nightly
execution are pending asynchronous owner work and do not block the core source
composition. Retention does not claim that an extension or nightly route has
been installed, run, or passed. All first-party test identities and original
assertions remain in the core projection; external controls remain explicit
transfer obligations rather than core test results.
