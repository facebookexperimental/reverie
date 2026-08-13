# Reverie Agent Guide

This file applies to the entire repository.

Codex coordinator discipline: coordinate only; delegate nontrivial tool work to workers. Never paste raw tool
output into the user transcript; provide concise synthesized results to avoid the cybersecurity false-positive
filter. If a worker hits that filter, rephrase or replace the worker without stalling the coordinator.

## Project Context

Reverie is a Linux process instrumentation framework. The shared `reverie`
crate defines the `Tool`, `GlobalTool`, and `Guest` contracts, while
`reverie-ptrace` is the production ptrace/seccomp backend. The repository uses
the nightly toolchain selected by `rust-toolchain.toml`.

The public Cargo manifests are generated from Meta's internal build metadata.
Keep manifest changes narrow, preserve export markers, and explain any change
that must also be reflected in the generated source.

## Architecture Overview

This is the coordinator-level map; the canonical `.claude/skills/` files
(`reverie-architecture`, `syscall-interception`, `adding-a-backend`, and
`testing-tools`) are the task-level detail. Claude reads them through
`.llms/skills`; stock Codex reads the structured
`.agents/skills/<name>/SKILL.md` package links. **Read `reverie-architecture`
before working anywhere in the tree.**

Reverie is a Linux **process-instrumentation framework**: you write a *tool*
against a small, backend-agnostic contract, and a *backend* runs a guest process
tree and routes the guest's syscalls, signals, and CPU events to the tool. Hermit's
`Detcore` is the flagship tool built on this. The four contracts live in the
shared `reverie` crate:

| Contract | Location | Role |
| --- | --- | --- |
| `Tool` | `reverie/src/tool.rs:118` | Per-process instrumentation + `async handle_*` event handlers; declares `subscriptions` (`:153`), the main hook is `handle_syscall_event` (`:234`) |
| `GlobalTool` | `reverie/src/tool.rs:39` | Cross-process singleton; RPC via `receive_rpc` (`:62`), reached through `GlobalRPC::send_rpc` (`:337`) |
| `Guest<T>` | `reverie/src/guest.rs:29` | A handler's view of its thread: `memory` (`:73`), `regs`/`set_regs` (`:82`/`:98`), `inject` (`:131`), `tail_inject -> Never` (`:175`), `read_clock` (`:228`) |
| `Backend` | `reverie/src/backend.rs:147` | `#[async_trait(?Send)] async fn run<T>(command, config) -> (ExitStatus, T::GlobalState)` (`:160`); runs the whole guest lifecycle on a current-thread `LocalSet` executor |

**Backends** (how the guest is driven and syscalls trapped):

| Backend | Crate | Interception | Status |
| --- | --- | --- | --- |
| ptrace | `reverie-ptrace` | seccomp-BPF traps only subscribed syscalls; supervisor handles ptrace stops | production |
| DBT | `reverie-dbt` | DynamoRIO rewrites the code stream; tool compiled into a release-built client `.so` | in progress |
| KVM | `reverie-kvm` | guest runs in a VM; syscalls surface as hypercalls | in progress |
| e9patch / liteinst | `reverie-e9patch`, `reverie-liteinst`, `reverie-preload` | in-process rewriting + `LD_PRELOAD` + seccomp/SIGSYS runtime | experimental |

For ptrace and KVM the `GlobalState` lives in-process: `send_rpc` calls
`receive_rpc` as a direct in-address-space async call and no serialization runs
at runtime (ptrace does a `bincode` round-trip only under `debug_assertions` as a
self-check; KVM never does, and `reverie-kvm` does not depend on
`reverie-rpc-transport`). The out-of-process configurations — DBT (only when a
coordinator socket is configured so fork/exec children share one `GlobalState`),
e9patch, and liteinst/preload — route it to a coordinator process over
`reverie-rpc-transport` (UDS + bincode). The `Serialize + DeserializeOwned`
bounds on `GlobalTool::Request`/`Response` are a shared compile-time contract,
exercised at runtime only on those cross-process paths. Other core crates:
`reverie-syscalls` (typed syscall
decode + guest memory read/write), `reverie-memory`, `reverie-process`,
`reverie-util`, `safeptrace`. Reference tools live in `reverie-examples`
(`noop`, `strace`/`strace_minimal`, `counter1`/`counter2`, `chunky_print`,
`chrome_trace`, `chaos`, `debug`, plus KVM and liteinst variants).

**Build & test:** nightly toolchain (`rust-toolchain.toml`); the canonical gate is
`./validate.sh` (build + test + doc-test + clippy + rustfmt, all
`--workspace --all-features`). See the `testing-tools` skill for package-scoped
commands and the host-dependent `--skip` list. **Adding a backend:** implement
`Backend::run<T>` plus a concrete `Guest<T>`, wire `GlobalState` over
`reverie-rpc-transport` if out-of-process, and enumerate the syscalls the
executor services — see the `adding-a-backend` skill.

## Required Workspace Layout

The dev-hermit workspace uses nested layout v3: one Reverie primary checkout
and registered named slots that contain every product checkout:

```text
~/work/dev-hermit/
|-- reverie/                  primary checkout; main integration only
`-- worktrees/
    `-- <slot>/
        |-- hermit/
        |-- reverie/
        `-- liteinst2/
```

- The primary checkout stays on `main` and is mutated only by the landing
  coordinator.
- All feature, research, documentation, and test changes happen in a dedicated
  slot. Never do feature work in the primary checkout.
- Slot names are intentionally unrelated to branch names. A slot is reusable;
  a feature branch remains descriptive and task-specific.
- The parent permits at most twelve active worktrees and five clean parked
  slots. `worktrees/ACTIVE.md` records every active agent, task, branch, and
  owned path.
- Provision and release only through the parent
  `scripts/allocate-worktree.rs` and `scripts/release-worktree.rs`; never create
  a product worktree directly.
- A parked slot is clean and detached at the parent-pinned gitlink. An active
  slot has exactly one mutating owner. Another agent may join only through the
  allocator's explicit read-only operation; a registry entry never authorizes
  disjoint mutating ownership.

Use `git worktree list --porcelain` to inspect ownership. A branch may be
checked out in only one worktree.

## Non-Negotiable Worktree Discipline

Every mutating agent must follow these rules:

1. Inspect `git status --short --branch` before doing any work.
2. Use one unique worktree and feature branch for the task.
3. Do not modify files from the primary checkout.
4. Do not share a slot with another mutating agent.
5. Do not overwrite, reset, remove, or include changes you did not create.
6. Keep generated files, scratch output, and build artifacts out of Git.
7. End with all intended work committed on the task feature branch. Never use
   a stash as a handoff.
8. Register the slot and ownership in the parent before the first edit; do not
   use raw `git worktree add`, move, or removal commands.

Never use `git clean`, `git reset --hard`, `git checkout -- <path>`, or
similar discard operations to make a checkout look clean. Unexpected changes
belong to another agent until proven otherwise.

## Starting A Task

The coordinator assigns an idle slot from the dev-hermit root before editing:

```bash
with-proxy git -C reverie fetch origin main
test "$(git -C reverie rev-parse HEAD)" = \
  "$(git -C reverie rev-parse origin/main)"
./scripts/allocate-worktree.rs \
  --agent <agent> --slot <slot> --task <task-id> --product all \
  --reverie-branch <descriptive-feature-branch> \
  --purpose "<one-line outcome>"
git -C worktrees/<slot>/hermit switch --detach "$(git rev-parse HEAD:hermit)"
git -C worktrees/<slot>/liteinst2 switch --detach "$(git rev-parse HEAD:liteinst2)"
```

The coordinator first verifies that all three primaries are clean, on `main`,
and current under the parent guide. Fetching and comparing Reverie's target ref
before allocation ensures the new Reverie branch cannot start from a stale
`origin/main`; `--product all` creates the required nested slot shape. Detaching
the unchanged children at the parent gitlinks preserves the recorded Hermit and
LiteInst2 inputs instead of applying one global start point to all products. The
allocator verifies and records ownership. In the assigned
`worktrees/<slot>/reverie`, confirm a clean status and verify that the dedicated
feature branch starts at current `origin/main` unless the task names another
base. Run every mutating command with that slot as the explicit working
directory.

If no slot is available, do not fall back to the primary checkout or create a
non-canonical path. The coordinator must reclaim a clean parked slot or finish
existing work first.

## While Working

- Keep the task's diff limited to its stated files and behavior.
- Check status regularly, especially before and after generators, formatters,
  and broad tests.
- Use focused tests during iteration. Before handoff, run the broadest relevant
  checks that the environment supports.
- Do not run a formatter over another agent's dirty worktree.
- Do not switch branches in or move another agent's worktree.
- Do not create commits that mix work from different tasks or agents.
- Post task notes for important findings, decisions, test results, and
  blockers. Notes must name the branch and slot when work is handed off.

Useful Rust checks are:

```bash
cargo build --workspace --all-features
cargo test --workspace --all-features -- --test-threads=1 \
  --skip container::tests::pin_affinity_to_all_cores \
  --skip tests::seccomp_notify
cargo clippy --workspace --all-targets --all-features
cargo fmt --all -- --check
```

Start with package- or test-specific commands when the full workspace is
expensive. Report toolchain, hardware, PMU, ptrace, or dependency failures
instead of weakening tests to hide environment limitations.

## Clean Finish

A worker handoff must include:

- feature branch name and exact HEAD SHA, if committed;
- slot path;
- concise change summary;
- exact checks run and their results;
- known failures or untested behavior;
- a clean `git status --short`.

Commit only the task-owned files on the dedicated feature branch, push with an
explicit refspec, and open a draft PR unless the task explicitly forbids
publication. The author owns review fixes, rebases, exact-head revalidation,
and shepherding through landing.

When the `dev-hermit` parent is available, obtain the exact disclosure with
`./ci-hub/bin/who-am-i --tag --role ROLE`; paste it at the start of the commit
subject and do not reconstruct it. After the disclosure, use an imperative,
descriptive subject that states the substantive change.

The first commit-body section is exactly **Plain Language Summary and Project
Impact**. Explain what project capability, correctness property, evidence
quality, or developer workflow moves forward; connect it to the product vision
or owner request; and state the meaningful before/after difference.
Administrative history, task bookkeeping, and review mechanics come later.
Record `Task: <task-id>` after this opening section when the change implements
task work.

Only the coordinator closes or parks the slot. After the intended work is
committed and handed off, record exact SHAs and validation in
`worktrees/ARCHIVED.md`, then use the parent
`scripts/release-worktree.rs`. Never detach, delete, or repurpose a dirty slot;
a dirty recovery requires a documented recovery SHA.

## Precise Communication

Agent reports drive coordinator decisions, so every claim must be precise and
independently verifiable. Vague status language is a defect: it hides what was
and was not actually checked.

### Banned Vague Terms

Do not describe results with unquantified words. In particular, never report
that something is "working", "demonstrated", "audited", or that features are
"present together" without stating exactly what was run and observed. Replace
each with a concrete claim: the command, the backend, the assurance level, and
the observed output. If you cannot ground a word in evidence, do not use it.

### Assurance Levels

Determinism is a property of the integrated Hermit-over-Reverie system, so
determinism claims use the Hermit assurance ladder and must name the level
explicitly. The ladder is cumulative; each level presupposes the ones below it:

| Level | Meaning | How it is established |
| --- | --- | --- |
| L0 | Builds and tests pass | `cargo test --workspace --all-features` exits 0 |
| L1 | Runs deterministically under strict mode | `hermit run --strict` |
| L2 | Strict repeat parity | `hermit run --strict --verify --verify-strict --verify-json REPORT.json -- PROGRAM` compares exit status/stdout/stderr exactly and INFO messages under the declared canonical policy; the JSON result must report `bitwise_parity: true`, `compared_log_messages.left > 0`, and `compared_log_messages.right > 0`; KVM's output-only fallback cannot claim L2 |
| L3 | Memory determinism | L2's strict command and JSON predicate, adding `--detlog-heap --detlog-stack` before `-- PROGRAM` |
| L4 | Stress-hardened | L2/L3 repeated 20x with no divergence |

A Reverie-only change is floored at L0 (the Reverie suite green); it does not
establish L1 or higher on its own. Do not claim a determinism guarantee from a
Reverie-side change without an integrated Hermit run at the stated level.

### Required Run Context

Every result about a run states, explicitly:

- **Backend**: `ptrace`, `DBT`, or `KVM`.
- **Log level**: the `RUST_LOG`/`--log` level, or "default" when unset.
- **Relaxations**: any flag that weakens determinism, for example
  `--no-strict`. State "none" when there are none.

A non-strict result never counts as "passing" on its own. If a run used
`--no-strict` or any other relaxation, label it as such and do not present it
as a determinism guarantee.

Default `--verify` uses the lossy `Stripped` comparator and cannot establish
L2. `--verify-strict` preserves virtual-time values, retired-branch counts,
syscall arguments/results, sizes, flags, and other numeric INFO payloads. Its
declared canonical envelope still removes irreproducible wall-clock prefixes
and maps host addresses by first appearance, so report that envelope rather
than calling the log files literally byte-identical. L2 additionally requires
the `--verify-json` consumer predicate: `bitwise_parity` must be true and both
`compared_log_messages.left` and `.right` must be greater than zero. A more
aggressively normalized comparison may localize a divergence, but it is not L2
evidence.

### Completion Reports

Every completion report includes:

- the PR number as a full hyperlink, for example
  `https://github.com/rrnewton/reverie/pull/<n>`;
- the worktree slot path and current working directory;
- the feature branch name;
- the assurance level reached, with backend, log level, and relaxations;
- the exact commands run and their observed output, not a paraphrase.

### Evidence, Not Assertion

Ground every claim in evidence a reader can re-check: file paths with line
numbers, the exact command, and its output. Separate what you verified from
what you assume. Under-claiming beats false closure: if a check did not run,
say so and say why.

### No Dirty State

Commit and push each change immediately; never leave a checkout dirty or claim
"done" without a pushed commit behind it. A report that work is complete
implies a clean `git status` and a pushed branch.

## Autonomous Bot Audit Tags

New syscall support authored by a bot must leave two narrowly scoped
determinization breadcrumbs:

- Add `// AUTONOMOUS-BOT-IMPLEMENTED` at the new dispatch/classification entry.
- Add `// TODO-HUMAN-REVIEW(PR-id)` at the implementation or determinization
  block, replacing `PR-id` with the introducing pull request.
- Both markers are required for new syscall support. They are not blanket
  markers for API changes, backend work, or routine parity fixes. Do not remove
  or rename either marker autonomously.

## Dirty Checkout Recovery

When a checkout is unexpectedly dirty:

1. Stop before editing or switching branches.
2. Inspect `git status`, `git diff`, untracked files, current branch, and
   worktree ownership.
3. Attribute paths by task and agent. Do not combine unrelated changes.
4. Have the owning agent commit every coherent intended change to its feature
   or recovery branch. Do not stash, reset, clean, or absorb it into another
   task.
5. Record the recovery SHA, branch provenance, owned paths, and remaining
   blocker in the parent registry and task notes.
6. Keep the slot active until the state is cleanly handed off; only the
   coordinator may release or reclaim it through the registry-aware script.

Ambiguous files must be preserved and reported, not guessed away.

## Git And Pull Request Workflow

The primary development repository is `rrnewton/reverie`. The public
`facebookexperimental/reverie` repository is the upstream reference and
receives periodic reviewed pull requests rather than routine feature pushes.

The branch flow is:

```text
feature branches -> rrnewton/reverie main -> periodic upstream pull request
```

- Branch from current `origin/main` in an assigned slot.
- Keep one task and one owning worktree per feature branch.
- Run focused validation and the applicable formatting, lint, and test gates.
- Push the feature branch to `origin` and open the pull request against fork
  `main`; do not target upstream for routine CI iteration.
- The PR author owns review fixes, rebases, and exact-head validation through
  landing. Do not hand ordinary queue work to a separate lander.
- Reverie's current authoritative landing gate is `merge-gate-v2` at the exact
  PR head. It dereferences both `Regular tests (GitHub-hosted)` and
  `Host-dependent tests (self-hosted)` and requires both to pass. A local
  validation receipt, `locally-validated` label, raw exit, or copied comment is
  supplemental evidence only and cannot authorize landing. Await the two
  authoritative jobs; a missing, skipped, stale, or failed result is not green.
- Only an authorized coordinator lands changes and updates the parent gitlink
  through the serialized landing path.
- Never force-push `main`, rewrite shared branches, or merge around a genuine
  validation failure.

Apply `post-facto-human-review` exactly for: (1) new syscall support, with both
audit tags above; (2) a Reverie API/core-abstraction change to `Tool`, `Guest`,
`Backend`, or the syscall-interception model; (3) a new determinization
strategy; or (4) a core DetCore scheduling change affecting how programs are
scheduled, especially race search. Trigger 4 is always labeled. Hermit
[PR #1151](https://github.com/rrnewton/hermit/pull/1151), which moved slowdown
into virtual-time/epoch scheduling, is the canonical good example. Routine
backend-parity work toward the golden ptrace reference does not trigger review
unless it also meets one of these four criteria.

After the mandatory disclosure line, every PR description starts with **Plain
Language Summary and Project Impact**, giving the substantive outcome and its
connection to the product vision or owner request rather than administrative
history. It also requires **Determinism** (why the change is
deterministic plus a logic or informal proof, not only tests), and
**Validation**. KVM changes also require **Relationship to gVisor**. A labeled
PR additionally requires **Human Review Required**, naming the specific
numbered trigger rather than a vague category such as "backend change".

In Meta environments, use appropriate proxies for accessing the web.

```bash
git fetch origin
gh pr view -R rrnewton/reverie <number>
```

## Task Closure Policy

**The dev-hermit parent `AGENTS.md` is authoritative for task lifecycle.** This
section restates it for work done inside this repository and adds the
Reverie-specific evidence a claim must carry. Where the two could be read
differently, the parent wins; report the discrepancy rather than following this
file.

That reporting rule is not a formality. Two agents independently hit an earlier
version of this section contradicting the parent — it said agents must not close
and that a task is finished only once the change is on `main`, while the parent
says the owning agent closes on publication and that holding an evidenced task
open is itself a violation. Each document made the other's behaviour a defect,
so there was no reading that satisfied both, and both agents spent time deriving
that from scratch before proceeding.

**When you hit a discrepancy like that, note that the evidence does not change —
only the bookkeeping does.** The PR link, the exact SHA, the commands and their
results are identical under either rule. So record the evidence, choose the
parent's bookkeeping, and flag the conflict; never let an unresolved question
about *status* delay or degrade the *evidence*.

`closed` means **published and evidenced, NOT landed**. Landing debt does not
ride on the status — it rides on the `implemented` tag, which is what
`drain-implemented-to-landed` and `health-tick` enumerate. Holding an evidenced,
published task open until its PR merges is itself a defect: it is invisible to
the drain while still occupying the live queue.

The failure to avoid is not an agent closing its own task. It is an **unevidenced
close** — a task marked closed with no PR link, no exact SHA, and no validation.
Nothing mechanically blocks that, so the note *is* the audit trail. The rules
below are mandatory for every implementation and review agent.

1. **Record the evidence BEFORE you change status.** The order is load-bearing:
   commit and push the branch, post the PR link with its exact SHA and
   validation, add the `implemented` tag — and only then close. A close that
   precedes its evidence cannot be audited afterwards, because nobody can tell
   which SHA the claim was ever about.
2. **Add the `implemented` tag and post the PR
   link.** `IMPLEMENTED` is a tag, not a TaskGraph status, and it is what
   carries the landing debt after the task closes. "Complete" means the feature
   branch is pushed and a pull request is open against `rrnewton/reverie:main`.
   Preserve every existing tag because `--tags` replaces the
   full set:

   ```bash
   tg update <task> --tags <existing-tags>,implemented
   tg note <task> "IMPLEMENTED: https://github.com/rrnewton/reverie/pull/<n> \
     | branch <feature-branch> @ <40-hex SHA> | base origin/main <SHA> \
     | validation: <exact commands + results, assurance level, backend>"
   ```

   The PR link and the exact tested SHA are required, not optional. A branch
   name alone is not evidence.
3. **Adversarial review confirms the work exists in the PR.** A reviewer checks
   the claimed diff and exact-SHA validation. A Reverie-only change is floored
   at L0 and does not establish a determinism guarantee on its own. If the
   published artifact is missing, superseded, or does not contain the claim,
   strip the `implemented` tag and reopen the task. Review normally happens
   after the close, so the corrective action is reopening, not withholding.
4. **Then the owning agent closes its own task** — `tg update <task> --status
   closed`. No coordinator, no gateway. Close once rule 1 is satisfied and the
   PR is published; do **not** hold it open waiting for the merge. Work that is
   genuinely blocked is different: a task with no published artifact stays
   `in_progress` with the blocker and partial SHA recorded, and is never tagged
   `implemented`. If a published artifact disappears or the implementation claim
   proves false, strip the tag and reopen; do not invent a status TaskGraph does
   not have.
5. **After the PR lands, discharge the landing debt.** `./ci-hub/bin/close-task`
   is no longer a closure gate, but it is still the only writer of
   `CLOSURE-VERIFIED`, the note `health-tick` derives `landed` from. A task
   closed without it stays counted as owed forever. Once the PR is on `main`:

   ```bash
   ./ci-hub/bin/close-task <id> --code <PR-or-full-SHA> --repo rrnewton/reverie \
     --source <checkout>
   ```

   It verifies ancestry before recording. `REFUSED` (rc 1) and `UNVERIFIABLE`
   (rc 2) never close anything — leave the task closed and fix the evidence. A
   green local run, a GitHub state field, or a label is not landing evidence.

### Done vs. Not Done

Use these concrete examples to decide the correct status. When in doubt, choose
the lower status and say why in a task note.

**`closed` + `implemented` (the owning agent closes, once evidenced):**

- Branch pushed, PR open, exact-head validation green, awaiting merge.
- PR open but validation red, or an exact-head receipt missing/stale — still
  close it, and report the exact failure in the note. A red PR is published and
  evidenced; the debt rides on the tag, not on the status.
- Reverie change committed and pushed but the Hermit pin bump that consumes it
  has not landed — closed with the blocker and dependency SHAs named.

**`closed` + `CLOSURE-VERIFIED` (landing debt discharged):**

- PR #### is merged into `rrnewton/reverie:main` and `close-task` has verified
  the merge commit's freshly fetched ancestry. This is a later event than the
  close, not a precondition for it.
- A coordinated Hermit/Reverie change: the Reverie PR merged first, the Hermit
  consumer revalidated against the exact landed SHA, and the parent gitlink
  updated.

**Not done (stays `in_progress`, never tagged `implemented` or closed):**

- Code written but uncommitted or not pushed. Never use a stash as a handoff.
- "It builds/tests pass locally" with no pushed branch and no open PR.
- A green local `cargo test` presented as project completion — a Reverie-only
  suite pass is floored at L0 and is not an integrated determinism guarantee.
- Tests marked `#[ignore]`, masked, or deleted to make a checkout look green.

## Script Convention

- Project scripts use rust-script as `.rs` files with the shebang
  `#!/usr/bin/env rust-script`.
- Prefer rust-script over Python for all new scripts.
- Scripts are usually single files, but may be split into subdirectories when
  useful.
- Install rust-script with `cargo install rust-script` if it is not already
  available.

## Repository-Specific Change Guidelines

- Preserve the shared `reverie::Tool` and `Guest` contracts across backends.
- Add regression coverage at the narrowest useful layer.
- Treat syscall, signal, clone/exec, memory, and timer changes as
  concurrency-sensitive and validate lifecycle edge cases.
- Record architecture assumptions. Much of the backend is Linux-specific, and
  some functionality differs between x86-64 and aarch64.
- PMU, CPUID, RDTSC, seccomp, and ptrace behavior can depend on host
  capabilities. Include environment details in failure reports.
- Keep unrelated refactors and generated-manifest churn out of focused fixes.

## Pre-Commit Cleanliness Protocol

`reverie/` is a clean, focused implementation repository: product source, tests,
build config, and minimal curated documentation only. Experiments, bulk AI
research notes, binaries, and vendored clones do **not** belong here — they live
in the `dev-hermit` parent workspace at `~/work/dev-hermit/experiments/` and
`~/work/dev-hermit/ai_docs/`. The `repo-cleanliness` skill
(`.claude/skills/repo-cleanliness/SKILL.md`, also surfaced to Claude via
`.llms/skills` and to stock Codex via
`.agents/skills/repo-cleanliness/SKILL.md`) is the full standing rule; this
section is the mandatory pre-commit gate.

Before every commit, audit exactly what you are about to stage and fix any
misplaced file *before* committing — never "commit now, clean up later":

```bash
git status --short
git diff --cached --name-only    # exact staged paths
git diff --cached --numstat      # line counts; a '-' column means a binary file
```

Verify all of the following; a failure is a defect to fix before committing:

- **Right repo, right path.** Every staged file belongs in *this* repo at a
  sensible path — product code, tests, build config, or curated docs.
- **No experiments.** Do not add `reverie/experiments/`; experiments live at
  `~/work/dev-hermit/experiments/`. Reference external code by URL + commit SHA,
  never by vendoring a checkout.
- **No `ai_docs` slop.** Any `ai_docs/` change must be minimal, curated, durable
  reference, not a scratch dump; bulk research goes in the parent `ai_docs/`.
- **No binaries or large blobs.** No `.o`/`.a`/`.so`, archives, images, VM
  images, kernels, core dumps, or `*.perf.data`; no text file over 2 MiB without
  coordinator approval. Inspect anything suspicious with `file` and `du`.
- **No nested git repos.** `git diff --cached --name-only | grep -E '/\.git(/|$)'`
  must be empty.
- **Only your task's paths.** If the tree is dirty with another agent's work,
  stage your own paths explicitly; never `git add -A` past your ownership.

To unstage a misplaced file: `git restore --staged <path>`, move it to its
correct home, then commit.

## Discipline Verification

The coordinator should periodically run:

```bash
cd ~/work/dev-hermit
./scripts/allocate-worktree.rs --agent registry-audit --check-only
git -C reverie status --short --branch
git -C reverie worktree list --porcelain
```

Reconcile the allocator state, `worktrees/ACTIVE.md`, Git worktree registry, and
filesystem before assigning a slot. The expected idle state is a clean primary
checkout on latest `main` and clean detached parked slots. Every checkout uses
`rrnewton/reverie` as `origin` and `facebookexperimental/reverie` as `upstream`.
Any dirty or missing checkout blocks assignment until its state is attributed
and preserved.
