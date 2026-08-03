# Backend sources

Reverie's optional native backend dependencies have two representations. The
`third-party/` git submodules are developer reference checkouts. The Cargo
packages redistribute curated pinned source under their own `vendor/`
directories and build only that source inside Cargo `OUT_DIR`; Cargo does not
initialize or read the submodules.

| Backend | Path | Pinned revision | License |
| --- | --- | --- | --- |
| DynamoRIO | `reverie-dbi/vendor/dynamorio` | `929840ad9190e5086775e8debc0f0b79b4208d59` | BSD-3-Clause, LGPL-2.1-only drwrap, BSD-4-Clause Valgrind headers |
| SaBRe | `experimental/reverie-sabre/vendor/{sabre,libelf}` | `41113f849f8799932ed8c7883f5a4de616b9e9fa` | GPL-3.0-or-later plus documented GPL-2.0-only/BSD-3-Clause/MIT exceptions; LGPL-3.0-or-later libelf |
| e9patch | `reverie-e9patch/vendor/e9patch` | `6c2c03c1da74b14daf1788a9f8dccfa354ce04a6` (`v1.0.1`) | GPL-3.0-only, LGPL-3.0-or-later libdw, MIT Zydis |

These native backends wrap established binary-instrumentation projects —
[DynamoRIO](https://dynamorio.org),
[SaBRe](https://github.com/srg-imperial/SaBRe), and
[e9patch](https://github.com/GJDuck/e9patch). The revisions above are the exact
commits Reverie builds against; consult each upstream project for background on
its rewriting approach.

The in-tree `reverie-liteinst` prototype is self-contained and does not depend
on an external LiteInst checkout. `reverie-{dbi,sabre,e9patch}` source builds
produce their required native artifacts without a submodule or network path.

## Inspect a developer reference checkout

Use the repository helper to initialize and verify exactly one source:

```bash
scripts/backend-submodule.sh activate dynamorio
scripts/backend-submodule.sh activate sabre
scripts/backend-submodule.sh activate e9patch
```

The helper performs a shallow, recursive checkout and verifies the resulting
HEAD against the superproject's gitlink. It never advances a submodule branch.
Use `all` instead of a backend name only when validating every backend.

Activation is optional and is used only to compare or update the vendored
source. Normal Cargo builds do not require it. Build the packages directly:

```bash
cargo build -p reverie-dbi

cargo build -p reverie-sabre

cargo build -p reverie-e9patch
```

The native build prerequisites are documented in each package README. Source
revision markers and required sentinels are validated by each build script.

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

CI starts with submodules disabled. The workspace packages build their vendored
native sources, proving that a standalone Cargo source install does not depend
on developer submodule state.
