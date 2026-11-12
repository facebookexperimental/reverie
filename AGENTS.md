# Reverie Agent Guide

**Keep Hermit out of Reverie.** Reverie's main user is Hermit, but Reverie is
a standalone process-instrumentation layer that must be reusable without Hermit.
Everything in this repository must make sense to a Reverie user who has never
heard of Hermit or Detcore. That covers code, tests, documentation, comments,
names, feature flags and environment variables.

- Do not add Hermit or Detcore concepts to Reverie:
  - deterministic scheduling, virtual time, determinism policy or DETLOG;
  - Hermit command-line flags, Hermit test cells or Hermit file paths.
- When Hermit needs something new, add a generic Reverie mechanism, such as a
  `Tool`, `Guest` or backend capability or hook. Keep the Hermit-specific
  policy in the Hermit repository.
- Every backend must pass Reverie's own generic tests without Hermit,
  including the strace and counter example tools. The backends are ptrace,
  KVM, DBT, LiteInst and in-guest.

**Rebind pinned sources in the same change.** The LiteInst artifact pins
the raw size and sha256 of every source file listed in
`reverie-liteinst-artifact`'s `CONTENT_REVERIE_CATALOG`
(`reverie-liteinst-artifact/src/lib.rs`). That file also pins
`reverie-inguest/src/trap/fixed_gates.rs` the same way, in
`CONTENT_DETCORE_FIXED_GATE`, outside the catalog.

- Any change to one of those files, comments included (the pins are raw size
  and sha256), must update its pinned tuple in the same change and run
  `cargo test -p reverie-liteinst-artifact` at the exact head before landing.
- Update every occurrence of the old sha256, not only the catalog row. Some
  files are pinned again elsewhere in `reverie-liteinst-artifact/src/`, for
  example in `private_static/tls_sources.rs`,
  `private_static/selected_initializers/native_leaves.rs` and `lib.rs`'s
  `NO_INSTALLATION_SCOPE_SOURCE`. Grep that directory for the old sha256 to
  find them all.
- When a catalog row changes, add the replaced tuple to the test module's
  list of rejected prior tuples (after the `CONTENT_REVERIE_CATALOG.len()`
  assertion), as earlier row updates did. The test then proves the catalog
  refuses the old content.
- Run that test in a git checkout of the head: some of its tests run
  `git rev-parse HEAD`, so a copy without `.git` fails them.
- A landing that runs only the tests for what a change touches does not run
  this test for a pinned file in another crate. Two merge-queue ejections came
  from exactly that: one for a code change and one for a comment-only change.
