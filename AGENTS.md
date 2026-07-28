# Reverie Agent Guide

This file applies to the entire repository.

## Project Context

Reverie is a Linux process instrumentation framework. The shared `reverie`
crate defines the `Tool`, `GlobalTool`, and `Guest` contracts, while
`reverie-ptrace` is the production ptrace/seccomp backend. The repository uses
the nightly toolchain selected by `rust-toolchain.toml`.

The public Cargo manifests are generated from Meta's internal build metadata.
Keep manifest changes narrow, preserve export markers, and explain any change
that must also be reflected in the generated source.

## Architecture Overview

This is the coordinator-level map; the `.claude/skills/` files
(`reverie-architecture`, `syscall-interception`, `adding-a-backend`,
`testing-tools`, surfaced via `.llms/skills` and `.agents/skills`) are the
task-level detail. **Read `reverie-architecture` before working anywhere in the
tree.**

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
| DBI | `reverie-dbi` | DynamoRIO rewrites the code stream; tool compiled into a release-built client `.so` | in progress |
| KVM | `reverie-kvm` | guest runs in a VM; syscalls surface as hypercalls | in progress |
| e9patch / liteinst | `reverie-e9patch`, `reverie-liteinst`, `reverie-preload` | in-process rewriting + `LD_PRELOAD` + seccomp/SIGSYS runtime | experimental |

For ptrace the `GlobalState` lives in-process; the out-of-process backends (KVM,
DBI) run it in a coordinator process reached over `reverie-rpc-transport`
(UDS + bincode). Other core crates: `reverie-syscalls` (typed syscall
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

The dev-hermit workspace has one Reverie primary checkout and up to five
canonical nested slots:

```text
~/work/dev-hermit/
|-- reverie/                  primary checkout; main integration only
`-- worktrees/
    |-- slot01/
    |   `-- reverie/
    |-- slot02/
    |   `-- reverie/
    `-- slotNN/
        `-- reverie/
```

- The primary checkout stays on `main` and is mutated only by the landing
  coordinator.
- All feature, research, documentation, and test changes happen in a dedicated
  slot. Never do feature work in the primary checkout.
- Slot names are intentionally unrelated to branch names. A slot is reusable;
  a feature branch remains descriptive and task-specific.
- The parent harness permits at most five warm slots; use its registry and
  provisioning policy rather than creating product worktrees directly.
- An idle slot is clean and at detached HEAD. An active slot has exactly one
  feature branch and one mutating agent.

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
7. End with a clean worktree. Durable work is committed when the task permits;
   otherwise preserve it in a named stash and report the recovery command.

Never use `git clean`, `git reset --hard`, `git checkout -- <path>`, or
similar discard operations to make a checkout look clean. Unexpected changes
belong to another agent until proven otherwise.

## Starting A Task

The coordinator assigns an idle slot. Before editing:

```bash
PRIMARY=~/work/dev-hermit/reverie
SLOT=~/work/dev-hermit/worktrees/slot01/reverie
BRANCH=impl-example

git -C "$PRIMARY" status --short --branch
git -C "$SLOT" status --short --branch
git -C "$SLOT" fetch origin
git -C "$SLOT" switch --detach origin/main
git -C "$SLOT" switch -c "$BRANCH"
```

Both status checks must be clean. If the intended branch already exists and is
not checked out elsewhere, switch to it instead of creating it:

```bash
git -C "$SLOT" switch "$BRANCH"
```

Create feature branches from current `origin/main` unless the task explicitly
names a different base. Record the slot, branch, and task purpose in the task
note before the first edit. Run all mutating commands with the slot as the
working directory.

If all parent slots are active, do not fall back to the primary checkout. Wait
for a slot or obtain explicit approval for a temporary worktree.

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

If the task authorizes commits, commit only the task's files on its feature
branch. If committing is not authorized, preserve all task files, including
untracked files, in a clearly named stash:

```bash
git stash push -u -m "<agent/task>: <plain summary>" -- <task-paths...>
git stash show --stat --include-untracked stash@{0}
```

Post the stash name and contents in the task note. Never drop another agent's
stash.

After the work has landed or been safely preserved, release the slot:

```bash
git -C ~/work/dev-hermit/worktrees/slot01/reverie status --short
git -C ~/work/dev-hermit/worktrees/slot01/reverie switch --detach origin/main
```

Do not detach a dirty worktree. Do not delete permanent slot worktrees; their
build caches are intentionally reusable.

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
| L2 | Bitwise-identical repeat run | `hermit run --strict --verify` |
| L3 | Memory determinism | `hermit run --strict --verify --detlog-heap --detlog-stack` |
| L4 | Stress-hardened | L2/L3 repeated 20x with no divergence |

A Reverie-only change is floored at L0 (the Reverie suite green); it does not
establish L1 or higher on its own. Do not claim a determinism guarantee from a
Reverie-side change without an integrated Hermit run at the stated level.

### Required Run Context

Every result about a run states, explicitly:

- **Backend**: `ptrace`, `DBI`, or `KVM`.
- **Log level**: the `RUST_LOG`/`--log` level, or "default" when unset.
- **Relaxations**: any flag that weakens determinism, for example
  `--no-strict`. State "none" when there are none.

A non-strict result never counts as "passing" on its own. If a run used
`--no-strict` or any other relaxation, label it as such and do not present it
as a determinism guarantee.

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

Bot-authored syscall and API changes must leave an explicit audit trail:

- Add the exact marker `// AUTONOMOUS-BOT-IMPLEMENTED` at every syscall
  match entry added by an autonomous bot. Only a human reviewer removes this
  marker, and only after reviewing that entry.
- Add `// TODO-HUMAN-REVIEW(PR-id)` to every bot-added syscall implementation
  and API change, replacing `PR-id` with the pull request that introduced the
  change (for example, `// TODO-HUMAN-REVIEW(PR-123)`). Place it on the changed
  declaration or at the smallest code region it covers; do not use an unscoped
  file-level marker.
- A new syscall requires both markers: `// AUTONOMOUS-BOT-IMPLEMENTED` at its
  dispatch match entry and `// TODO-HUMAN-REVIEW(PR-id)` at its implementation
  or API surface. Do not remove or rename either marker autonomously.

## Dirty Checkout Recovery

When a checkout is unexpectedly dirty:

1. Stop before editing or switching branches.
2. Inspect `git status`, `git diff`, untracked files, current branch, and
   worktree ownership.
3. Attribute paths by task and agent. Do not combine unrelated changes.
4. Preserve each attributed group separately with a path-scoped named stash,
   including `-u` for untracked files.
5. Verify each stash with
   `git stash show --stat --include-untracked <stash>`.
6. Record stash names, branch provenance, and recovery instructions in task
   notes.
7. Confirm the checkout is clean before assigning it again.

Ambiguous files must be preserved and reported, not guessed away. Stashing is
a recovery mechanism, not the normal multi-agent workflow.

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
- Require the GitHub-hosted **Regular tests** job to pass at the PR head.
- The **Host-dependent tests** job is enabled by setting the repository
  variable `REVERIE_SELF_HOSTED=true` after a matching runner is registered.
- Only an authorized coordinator lands changes and updates the parent gitlink;
  use a reviewed pull request or an explicitly authorized fast-forward.
- Never force-push `main`, rewrite shared branches, or merge around failing CI.

In Meta environments, use appropriate proxies for accessing the web.

```bash
git fetch origin
gh pr view -R rrnewton/reverie <number>
```

## Task Closure Policy

A task is not finished when the code is written; it is finished when the change
is on `main`. Phantom closures — tasks marked closed while the work never landed
— are a recurring, expensive failure mode. Do not create one. The rules below
are mandatory for every implementation and review agent.

1. **Agents MUST NOT close tasks.** Never run `tg update <task> --status
   closed` (or any equivalent close/complete transition). Closing is reserved
   for the coordinator, who does it only after confirming the work is on
   `main`. An agent that closes its own task is asserting a landing it cannot
   witness.
2. **When your work is complete, set the task to `IMPLEMENTED` and post the PR
   link.** "Complete" means the feature branch is pushed and a pull request is
   open against `rrnewton/reverie:main`. Record the transition and evidence:

   ```bash
   tg update <task> --status implemented
   tg note <task> "Implemented: https://github.com/rrnewton/reverie/pull/<n> \
     | branch <feature-branch> @ <40-hex SHA> | base origin/main <SHA> \
     | validation: <exact commands + results, assurance level, backend>"
   ```

   The PR link and the exact tested SHA are required, not optional. A branch
   name alone is not evidence.
3. **Adversarial review confirms the work exists in the PR.** Before a task is
   trusted as `IMPLEMENTED`, a reviewer independently verifies that the claimed
   change is actually present in the pull request diff, that the cited tests
   exist and were run at the PR head SHA, and that the reported assurance level
   (L0–L4), backend, and relaxations match reality. A Reverie-only change is
   floored at L0 and does not establish a determinism guarantee on its own; a
   claim that does not survive this check is not `IMPLEMENTED`.
4. **The task stays `IMPLEMENTED` until the PR lands on `main`.** Open,
   in-review, CI-red, awaiting-merge, and blocked-on-a-dependency PRs are all
   still `IMPLEMENTED`, never `closed`. If the branch stops fast-forwarding, or
   CI goes red, or a required check is not green at the PR head, the task
   remains `IMPLEMENTED` (or moves back to `in_progress`) — it does not advance.
5. **Only the coordinator closes tasks, after landing confirmation.** The
   coordinator closes a task only after verifying the PR is merged into
   `rrnewton/reverie:main` (the required **Regular tests** job green at the
   merged head, the commit reachable from `main`), and, when the change is
   consumed by Hermit, that the Hermit-side reverie pin was bumped to the
   landed SHA. Landing confirmation is a merge commit on `main`, not a green
   local run.

### Done vs. Not Done

Use these concrete examples to decide the correct status. When in doubt, choose
the lower status and say why in a task note.

**Done (coordinator may close):**

- PR #### is merged into `rrnewton/reverie:main`; the merge commit is on `main`
  and the required **Regular tests** job was green at that head.
- A coordinated Hermit/Reverie change: the Reverie PR merged first, the Hermit
  consumer revalidated against the exact landed SHA, and the parent gitlink
  updated.

**`IMPLEMENTED` (agent's terminal state — do NOT close):**

- Branch pushed, PR open, CI green, awaiting coordinator merge.
- PR open but CI red, or a required check missing/queued/stale — still
  `IMPLEMENTED`; report the exact failure, do not close.
- Reverie change committed and pushed but the Hermit pin bump that consumes it
  has not landed — `IMPLEMENTED` with the dependent Hermit SHAs named.

**Not done (stays `in_progress`, never `IMPLEMENTED` or `closed`):**

- Code written but uncommitted, stashed, or not pushed.
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
(`.claude/skills/repo-cleanliness.md`, also surfaced via `.llms/skills` and
`.agents/skills`) is the full standing rule; this section is the mandatory
pre-commit gate.

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
PRIMARY=~/work/dev-hermit/reverie

test -f "$PRIMARY/AGENTS.md"
git -C "$PRIMARY" branch --list main
git -C "$PRIMARY" status --short --branch

for slot in ~/work/dev-hermit/worktrees/slot*/reverie; do
    test -d "$slot" || continue
    git -C "$slot" status --short --branch
    git -C "$slot" remote -v
done
```

The expected idle state is a clean primary checkout on `main` and clean,
detached parked slots. Every checkout uses `rrnewton/reverie` as `origin` and
`facebookexperimental/reverie` as `upstream`. Any dirty or missing checkout
blocks assignment until its state is attributed and preserved.
