# Optional backend sources

Reverie's large native backend dependencies are pinned as shallow Git
submodules under `third-party/`. They are intentionally absent from a normal
clone. SaBRe and e9patch also use `update = none`, so a plain
`git submodule update --init` skips them. DynamoRIO permits checkout because
Cargo must initialize it when Reverie is consumed as a Git dependency.

| Backend | Path | Pinned revision | License |
| --- | --- | --- | --- |
| DynamoRIO | `third-party/dynamorio` | `929840ad9190e5086775e8debc0f0b79b4208d59` | BSD-3-Clause plus bundled component licenses |
| SaBRe | `third-party/sabre` | `05816ee066a7284bee8afd0e73eeb44455b254b4` | GPL-3.0-or-later, with per-file exceptions |
| e9patch | `third-party/e9patch` | `6c2c03c1da74b14daf1788a9f8dccfa354ce04a6` (`v1.0.1`) | GPL-3.0 |

The in-tree `reverie-liteinst` prototype is self-contained and does not depend
on an external LiteInst checkout. e9patch is pinned for the separate rewriting
backend work and is not part of a default Rust build.

## Activate one backend

Use the repository helper to initialize and verify exactly one source. For SaBRe
and e9patch, it explicitly overrides `update = none`:

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
by those upstream projects. Cargo never fetches those two sources implicitly. A
Cargo Git checkout does initialize pinned DynamoRIO so `reverie-dbi` remains
buildable; a normal repository clone still leaves it absent until explicitly
initialized.

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
the workspace includes `reverie-dbi`. SaBRe and e9patch remain absent because
the Rust workspace does not compile their upstream source trees. A backend job
that needs either source must activate only that backend first.
