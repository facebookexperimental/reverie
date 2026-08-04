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

## What "curated" removes

A vendored tree is not a byte copy of its upstream pin. Two classes of file are
dropped, and each is enforced by a test rather than by convention:

- **Binary files.** Upstream documentation and Windows-resource images —
  DynamoRIO's `api/docs/**` and `tools/DR*/res/*` images and e9patch's
  `.github/e9patch.png` — are removed. No build step reads them, and this
  repository does not carry binaries. Guarded by
  `vendored_dynamorio_source_contains_no_binary_files`
  (`reverie-dbi/tests/build_script_source.rs`),
  `the_vendored_source_contains_no_binary_files`
  (`reverie-e9patch/tests/vendor_source.rs`), and the same-named SaBRe test in
  `experimental/reverie-sabre/src/lib.rs`. Each scans real file bytes for NUL,
  so a renamed blob is caught too.
- **Components the build does not compile.** e9tool only decodes and formats
  instructions, so Zydis is compiled with upstream's `ZYDIS_DISABLE_ENCODER`
  switch and its encoder sources — including the generated 2.6 MB
  `contrib/zydis/src/Generated/EncoderTables.inc` — are not redistributed.
  Guarded by `the_zydis_encoder_is_disabled_and_its_sources_are_absent`.

One text file exceeds the repository's 2 MiB ceiling:
`reverie-e9patch/vendor/e9patch/contrib/zydis/src/Generated/InstructionDefinitions.inc`
(5.7 MB). Zydis commits `src/Generated/*.inc` as tracked source — they are
produced out of band by the separate `zydis-db` tooling, no generator exists in
any vendored tree, and `contrib/zydis/.gitignore` does not list them — and
`src/SharedData.c` `#include`s this one, so the decoder cannot be built without
it. It is the sole entry in `LARGE_TEXT_ALLOWLIST`
(`reverie-e9patch/tests/vendor_source.rs`); every other vendored tree has an
empty allowlist, and any new oversized file fails the corresponding test.

## Parallel builds of the vendored e9patch tree

`reverie-e9patch/build.rs` runs `make --jobs=N release` over its `OUT_DIR` copy.
Upstream's `dev` goal lists `contrib/zydis/libZydis.a`, `contrib/libdw/libdw.a`,
and `e9tool` as sibling prerequisites, so under `-j` the e9tool link can start
before either archive exists and the build fails with a missing archive or
undefined `Zydis*` / libdw references. The curated `Makefile` therefore attaches
both archives to `e9tool` as **order-only** prerequisites, selected by goal at
parse time (a `dev:`-scoped target variable is not visible while prerequisite
lists are expanded). `all` and `check` keep upstream behaviour and link the
system `-lZydis` / `-ldw`. `contrib_archives_are_ordered_before_the_e9tool_link`
and `the_system_library_goals_do_not_build_the_contrib_archives` assert both
sides against GNU make's own parsed dependency database.

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
