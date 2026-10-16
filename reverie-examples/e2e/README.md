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
  Reverie. The in-guest backends (LiteInst, in-guest-trap, e9patch) host the
  recorder in the example preload, `libreverie_examples.so`, which selects it
  by name. A backend that cannot host the tool refuses by name (`REFUSED:`):
  DBT and SaBRe have no generic tool host.
- `../backend.rs`: the run-time backend selector the tools share.
- `compare.rs` (binary `reverie-e2e-compare`): runs each program of `corpus.tsv` natively twice (an unstable
  native baseline is its own verdict) and on each backend, compares call by
  call, and checks every verdict other than `match` against
  `expected-mismatches.tsv`. An in-guest tool starts at its preload's
  constructor, after the loader's calls, at the start and after each
  `execve`: for those backends the comparator first moves the native record
  to where the backend's next calls appear by name, then compares exactly.

The ledger is measured in Hermit's pinned validation root, where Hermit's
validation runs this check on the Reverie it pins. Its rows can differ on
other hosts (library versions, `/proc` contents), so `cargo test` runs only
the environment-independent part (`../tests/recorder.rs`).

```text
cargo build -p reverie-examples --lib --bin recorder --bin reverie-e2e-compare
target/debug/reverie-e2e-compare \
    --recorder target/debug/recorder \
    --backends ptrace,kvm,liteinst,in-guest-trap,e9patch,dbt,sabre \
    --corpus reverie-examples/e2e/corpus.tsv \
    --expected reverie-examples/e2e/expected-mismatches.tsv \
    --artifacts target/e2e
```
