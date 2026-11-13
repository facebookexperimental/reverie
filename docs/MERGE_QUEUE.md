# Main branch landing

Changes reach `main` only through the merge queue.

A pull request may be submitted to the queue when it has all of these at its
exact head:

1. an approving review;
2. a Test plan in its description that names that exact head; and
3. green targeted tests for everything the change touches:
   - the tests of each crate it changes;
   - the crates that depend on a changed public interface (at least build
     them);
   - for a file outside any crate, such as `validate.sh` or a file under
     `ci/`, `scripts/` or `.github/workflows/`, the tests, script checks or
     validator nodes that run it;
   - any test that pins a changed file. The LiteInst artifact pins the raw
     size and sha256 of many source files in other crates, so a change to one
     of them needs `cargo test --locked -p reverie-liteinst-artifact`. To find
     out whether a file is pinned, search `reverie-liteinst-artifact/` for its
     path or its current sha256. The pins live in
     `reverie-liteinst-artifact/src/`, for example `CONTENT_REVERIE_CATALOG` in
     `lib.rs` and `private_static/tls_sources.rs`, and in
     `reverie-liteinst-artifact/tests/factory_sources_self_check.rs`. The
     section "Rebind pinned sources in the same change" in `AGENTS.md` says
     how to update them.

A clean rebase before submission, meaning one with no conflicts to resolve and
no manual edits, keeps the review and the targeted test results. The Test plan
then still names the head that was reviewed and tested, and the queue validates
the rebased head.

These are the requirements for submitting, not for landing. The queue takes
submitted pull requests one at a time and rebases each onto the current `main`.
Before `main` moves, it runs the repository's full `./validate.sh` on the
rebased candidate, which is the exact tree that will land. It ignores
per-check selection, so every `validate.sh` gate and count check runs, and the
candidate fast-forwards `main` only if that run is green. A rebase creates new
commits, so whoever rebases signs them; every commit as it lands on `main` is
signed. Nothing reaches `main` any other way, and nothing creates merge commits
on `main`.

Landing on an approving review and targeted tests alone, with the full
`./validate.sh` run afterwards and failures fixed forward, applies only to
branches the project owner controls, such as integration branches or stacks of
dependent branches. It never applies to `main`.

Hosted GitHub Actions may provide additional information. A green hosted run
does not replace the targeted tests or the queue's validation, a red or missing
hosted run does not block a landing by itself, and no hosted status context is
a landing requirement.

## Local validation

A full green `./validate.sh` run automatically creates and applies the
`locally-validated` label to the current branch's pull request. Set
`PR_NUMBER=<number>` when branch-based detection is unavailable. GitHub CLI,
authentication, proxy, missing-PR, and label-edit failures are warnings and do
not change validation's exit status.

Use `./validate.sh --no-label-pr` or `VALIDATE_LABEL_PR=0 ./validate.sh`
when a green run must not update GitHub.

The label records a full local validation run. It is additional evidence: it
does not replace the queue's validation, it is not a submission requirement,
and it never stands for a partial run. Apply it only through a full green
validator run on the exact pull request head.

## Repository settings

No ruleset is configured for `main`. Linear history without merge commits,
signed commits, reviewed pull requests, no force pushes to `main`, and never
deleting `main` are practices this project keeps; GitHub does not enforce them.
Do not make a hosted GitHub Actions status context a required check.
