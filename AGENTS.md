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
- Reviewers judge this from a change's design and dependencies; there is no
  counted check. Ownership metadata such as `REVERIE_ONCALL` is not leakage.
  Boundary cases: the `reverie-layering` skill.

**Review depth and post-facto tags.** Reverie is developed autonomously by
agents, with asynchronous human guidance. A change to core Reverie types
(`Tool`, `Guest`, `Backend`, the syscall-interception model) gets two
cold-context reviewers on two different models, neither of them the author;
any other change gets one cold-context reviewer who is not the author by
default. A core-type change also carries the commit trailer
`Post-facto-human-review: trigger-2 (<short reason>)` (trigger 2 is a change
to these core types, in the numbering Hermit's post-facto review uses), plus
the `post-facto-human-review` pull-request label where the forge has labels,
so a human can find it later with `git log --grep='^Post-facto-human-review:'`
when bisecting or building a changelog. The tag never waits for approval.

**Rebind pinned sources in the same change.** The LiteInst artifact pins
the raw size and sha256 of every source file listed in
`reverie-liteinst-artifact`'s `CONTENT_REVERIE_CATALOG`
(`reverie-liteinst-artifact/src/lib.rs`). That file also pins
`reverie-inguest/src/trap/fixed_gates.rs` the same way, in
`CONTENT_DETCORE_FIXED_GATE`, outside the catalog.

- Any change to one of those files, comments included (the pins are raw size
  and sha256), must update its pinned tuple in the same change and run
  `cargo test -p reverie-liteinst-artifact` at the exact head before
  submitting.
- A catalog rebind is append-only history. Two enforcers divide it:
  `scripts/check-catalog-bindings-append-only.rs` checks the three history
  tables across revisions (every BASE row of
  `CONTENT_REVERIE_CATALOG_BINDINGS`, `CONTENT_REVERIE_CATALOG_BINDING_SEALS`
  and `rejected_prior` must survive unchanged at HEAD; a missing or emptied
  table is refused), and the crate test in
  `reverie-liteinst-artifact/src/lib.rs` (`binding_seals_hold` and
  `catalogue_rebinds_recorded`) checks the seal and the rejected record
  within one revision. When a pinned source changes: update its
  `CONTENT_REVERIE_CATALOG` row; APPEND the new binding tuple to
  `CONTENT_REVERIE_CATALOG_BINDINGS`, keeping the old tuple; append ONE
  seal covering every binding to `CONTENT_REVERIE_CATALOG_BINDING_SEALS`;
  and add the old tuple to the test module's `rejected_prior` list. Never
  remove or modify an existing history row. Run
  `scripts/check-catalog-bindings-append-only.rs` against the merge-base
  before submitting: its default BASE is the merge-base with
  `origin/<landing branch>`, which needs a git checkout; without git use
  `--base REV` in a git export or `--base-file`/`--head-file`, and an
  unresolvable BASE exits 2, which is a failure, never a pass.
- Current-value pins are not history rows and still move with the source:
  update the catalog row AND every other current-value pin of the old
  tuple (grep `reverie-liteinst-artifact/src/` for the old sha256; for
  example `NO_INSTALLATION_SCOPE_SOURCE` in `lib.rs`, which pins
  `reverie-liteinst/src/patch_alloc.rs` against its live sha256). Never
  apply that update to a history row, where the old tuple must stay.
- Run that test in a git checkout of the head: some of its tests run
  `git rev-parse HEAD`, so a copy without `.git` fails them.
- The tests for what a change touches include this one for every pinned file
  it changes, even a file in another crate whose own tests do not run it. Two
  merge-queue ejections came from missing exactly that: one for a code change
  and one for a comment-only change.
