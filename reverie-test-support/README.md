# Generic command tests

This package registers the existing `tests/basics.rs` source. Its command
helpers delegate to ptrace's existing runtime, output capture and caller-owned
Tool configuration. The Tools live once in `tests/tool_fixtures/basics.rs`.
Inherited function tests still use the original ptrace helpers.
The test dependency enables ptrace's existing `nightly` output-capture reset,
so inherited `println!` output reaches the guest pipe under ordinary libtest
capture. The workspace's pinned nightly toolchain supplies that API.

Run the complete registered target with ordinary libtest capture:

```sh
cargo test -p reverie-test-support --test basics
```

The initial command selection is:

```sh
cargo test -p reverie-test-support --test basics -- \
  --exact noop_tool_test counter_tool_test error_exit_test \
  run_guest_command_test run_guest_command_test_closure
```

The target also discovers the other existing basics declarations; running the
five command tests does not establish those other results. Sanitizer exclusions
remain unchanged.

Only ptrace is implemented here. DBT and in-guest adapters must install the
same caller-owned Tool and return its real global state before they can run
these tests. No backend selector, name-based Tool substitution or fallback is
provided by this package.
