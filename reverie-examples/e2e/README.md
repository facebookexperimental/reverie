# Cross-backend end-to-end check

One set of Reverie tools runs the same programs on every backend through
Reverie's public entry points, and the results are compared with native
Linux. A backend only intercepts and injects, so every difference is a backend
defect: it must be a row of the expected-mismatch ledger, naming its issue, or
the check fails. A row that no longer describes what a backend does fails too.

- `../recorder.rs` (binary `recorder`): runs a program under the pass-through
  recorder (`../recorder_tool.rs`) on `--backend native|ptrace|kvm|liteinst|
  in-guest-trap|e9patch|dbt|sabre` and writes each syscall with its result.
  `native` observes the program with plain ptrace syscall stops, with no
  Reverie. A backend that cannot host the tool refuses by name (`REFUSED:`).
- `../backend.rs`: the run-time backend selector the tools share.
- `compare.rs`: runs each program of `corpus.tsv` natively twice (an unstable
  native baseline is its own verdict) and on each backend, compares call by
  call, and checks every verdict other than `match` against
  `expected-mismatches.tsv`.

The ledger is measured in Hermit's pinned validation root, where Hermit's
validation runs this check on the Reverie it pins. Its rows can differ on
other hosts (library versions, `/proc` contents), so `cargo test` runs only
the environment-independent part (`../tests/recorder.rs`).

```text
rust-script reverie-examples/e2e/compare.rs \
    --recorder target/debug/recorder \
    --backends ptrace,kvm,liteinst,in-guest-trap,e9patch,dbt,sabre \
    --corpus reverie-examples/e2e/corpus.tsv \
    --expected reverie-examples/e2e/expected-mismatches.tsv \
    --artifacts target/e2e
```
