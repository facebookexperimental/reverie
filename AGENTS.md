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

**Rebind catalogued sources in the same change.** The LiteInst artifact pins
the raw size and sha256 of every source file listed in
`reverie-liteinst-artifact`'s `CONTENT_REVERIE_CATALOG`
(`reverie-liteinst-artifact/src/lib.rs`).

- Any change to a file listed in reverie-liteinst-artifact's
  CONTENT_REVERIE_CATALOG, comments included (the catalog pins raw size and
  sha256), must update that file's catalog row in the same change and run
  `cargo test -p reverie-liteinst-artifact` at the exact head before landing.
- Add the replaced tuple to that test module's list of rejected prior tuples,
  as earlier row updates did, so that a build from the older content fails.
- Run that test in a git checkout of the head: some of its tests run
  `git rev-parse HEAD`, so a copy without `.git` fails them.
- A soft-green landing runs only the tests for what a change touches, and a
  catalogued file's own tests do not include this one. Two merge-queue
  ejections came from exactly that: one for a code change and one for a
  comment-only change.
