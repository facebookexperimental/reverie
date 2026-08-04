# Backend sources

Reverie's large native backend dependencies are pinned as shallow Git
submodules under `third-party/`. A non-recursive clone leaves them absent;
`git submodule update --init --recursive` checks out every source at its pinned
revision. Cargo also initializes them when Reverie is consumed as a Git
dependency.

| Backend | Path | Pinned revision | License |
| --- | --- | --- | --- |
| DynamoRIO | `third-party/dynamorio` | `929840ad9190e5086775e8debc0f0b79b4208d59` | BSD-3-Clause plus bundled component licenses |
| SaBRe | `third-party/sabre` | `41113f849f8799932ed8c7883f5a4de616b9e9fa` | GPL-3.0-or-later, with per-file exceptions |
| e9patch | `third-party/e9patch` | `6c2c03c1da74b14daf1788a9f8dccfa354ce04a6` (`v1.0.1`) | GPL-3.0 |

These native backends wrap established binary-instrumentation projects —
[DynamoRIO](https://dynamorio.org),
[SaBRe](https://github.com/srg-imperial/SaBRe), and
[e9patch](https://github.com/GJDuck/e9patch). The revisions above are the exact
commits Reverie builds against; consult each upstream project for background on
its rewriting approach.

The in-tree `reverie-liteinst` prototype is self-contained and does not depend
on an external LiteInst checkout. The `reverie-e9patch` Rust crate builds
without initializing the e9patch source, but runtime rewriting requires the
separately built `e9tool` and `e9patch` executables.

## Activate one backend

Use the repository helper to initialize and verify exactly one source:

```bash
scripts/backend-submodule.sh activate dynamorio
scripts/backend-submodule.sh activate sabre
scripts/backend-submodule.sh activate e9patch
```

The helper performs a shallow, recursive checkout and verifies the resulting
HEAD against the superproject's gitlink. It never advances a submodule branch.
Use `all` instead of a backend name only when validating every backend.

After activation, build the selected backend:

```bash
scripts/backend-submodule.sh activate dynamorio
cargo build -p reverie-dbi

scripts/backend-submodule.sh activate sabre
cmake -S third-party/sabre -B target/sabre
cmake --build target/sabre
cargo build -p reverie-sabre-strace

scripts/backend-submodule.sh activate e9patch
make -C third-party/e9patch
```

The SaBRe and e9patch build commands require the system dependencies documented
by those upstream projects. A Cargo Git checkout initializes every pinned source;
a normal repository clone still leaves them absent until submodules are
explicitly initialized.

## Inspect or remove sources

```bash
scripts/backend-submodule.sh status all
scripts/backend-submodule.sh deactivate dynamorio
scripts/backend-submodule.sh deactivate sabre
scripts/backend-submodule.sh deactivate e9patch
```

Deactivation removes only the submodule worktree. Git retains its object cache,
so later activation can avoid another download when the pinned objects remain
available.

## CI

CI starts with submodules disabled and explicitly activates DynamoRIO because
the workspace includes `reverie-dbi`. SaBRe and e9patch remain absent in that
job because it activates only the source it builds. The
`reverie-e9patch` tests use a controlled executable fixture by default; its
opt-in real-tool test must activate and build only e9patch first.
