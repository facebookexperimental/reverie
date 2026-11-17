---
name: reverie-layering
description: "Reverie is a standalone instrumentation layer that never names its consumers: the layering principle, boundary cases, and the mechanical check whose per-file counts may only fall. Use when adding or renaming any Reverie API, identifier, flag, file, manifest, build target or test, when a change touches scripts/layering-allowlist.txt, and when reviewing a change for consumer leakage."
---

# Reverie layering

Reverie is an instrumentation layer: it should not mention Hermit or Detcore in
its code, and it should hang together on its own. It keeps generic mechanisms
(`Tool`, `Guest` and `Backend` capabilities, interception and injection hooks,
lifecycle contracts) and never names a consumer, its policy, its flags, its
test cells or its paths. When a consumer needs something new, add the generic
mechanism here and keep the consumer's policy in the consumer's repository.
`AGENTS.md` states the rule; this skill holds the boundary cases and the check.

Boundary cases:

- A precise, controllable timer hook belongs here; a policy for how virtual
  time must behave belongs to the consumer.
- A backend capability query belongs here; a backend branch chosen for one
  consumer's scheduling policy does not.
- The example tools (strace, counter) prove the layer stands alone: every
  backend passes Reverie's generic tests with them and no consumer linked.
- A build or package edge from Reverie to a consumer is the worst leak: a
  Cargo dependency, or a Buck `load()` or dependency on a consumer's target.

## The check

`scripts/check-layering.sh` finds every file that contains `hermit` or
`detcore` in any case, or whose path does. It reads, as text, the content of
source, assembly and linker files (`.rs`, `.c`, `.h`, `.cc`, `.cpp`, `.hpp`,
`.S`, `.s`, `.py`, `.sh`, `.ld`) and manifests and build files (`.toml`,
`BUCK`, `TARGETS`, `PACKAGE`, `.bzl`), and of any other executable file that
is not binary; it checks the path of every file outside documentation
(`*.md`, `docs/`, `guide/`, `ai_docs/`). It does not read workflow YAML, JSON
or data fixtures, or `Cargo.lock`, where crates.io's unrelated `hermit-abi`
appears. In a git checkout it reads tracked files and untracked files git does
not ignore, from the working tree.

Each line of `scripts/layering-allowlist.txt` is `path -- N -- reason`, where
N counts the file's matching lines, plus one when its path matches
(`scripts/check-layering.sh --list` prints the live counts). The check fails
when a matching file has no line, when a file's count is above or below its N,
and when a listed file no longer matches. A leading `?` on the path marks a
file that only the primary repository carries, such as anything under
`fb-only/`. The primary tree is recognized by `fb-only/defs.bzl`: there a `?`
line is checked like any other, so deleting its file leaves a stale line,
while an exported tree must not contain a `?` file at all and skips its line.

Separately, and with no allowlist escape, it fails when a dependency, patch or
replace entry in a TOML manifest names a consumer crate or path (including
dotted `dependencies.<name>` keys), when a symlink's target names a consumer,
and when a directory holding a `BUCK` file is not wired into the declared tree
below.

It runs on every change in the primary repository through the Buck test
`check-layering` in the root `BUCK`, which checks the whole tree declared as
`layering-tree` (dot-entries included; each subpackage contributes a
`layering-files` group), and also in the validation DAG (`check.layering`), in
`validate.sh`'s serial path and in the GitHub `ci.yml` check. Run
`bash scripts/check-layering.sh` by hand before submitting; it takes about two
seconds. Exit status: 0 pass, 1 violation, 2 could not run.

The expected long-term residents are cross-repository ABI names: a symbol a
consumer defines that Reverie calls, or the reverse. Renaming one is a
coordinated change with the other side, never a drive-by edit. The check's own
script is listed because it carries the pattern.

## Counts only fall

The rule in `AGENTS.md` did not hold the line by itself: code files naming a
consumer grew from 165 on 2026-11-05 to 186 of 1,311 on 2026-11-17. The first
allowlist records all 218 files that match today (including manifests, build
files and `fb-only/`) at their exact counts, most with the reason
`pre-check baseline 2026-11-17, classify me`.

- A new matching line in a listed file raises its count and fails. Remove it;
  never raise N.
- Removing a matching line fails until N is lowered to match, so every cleanup
  is locked in. At zero, delete the line.
- The check cannot tell a new line from an old one, so review refuses any
  change that adds a line: add the generic mechanism instead.
- Classifying a baseline file means removing its mentions, or replacing the
  baseline reason with the specific one.
- A change that renames or deletes a listed file updates its line in the same
  change; the check fails on a stale line.

Known leaks to remove first: `experimental/BUCK` and
`tests/gdbserver-integration/BUCK` each `load()` a macro from the consumer's
tree; route them through `fb-only/defs.bzl`, which exists to hold such names.
