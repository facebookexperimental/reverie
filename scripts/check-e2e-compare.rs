#!/usr/bin/env rust-script
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Pin the hosted cross-backend comparison, `.github/workflows/e2e-compare.yml`,
//! and lint the Ubuntu e2e ledgers.
//!
//! That workflow's conclusion is the merge evidence for a rrnewton/liteinst2
//! pull request, so a weakening of it would read as a pass. This checker:
//!
//! 1. requires the workflow to equal the text pinned at the end of this file,
//!    byte for byte, and reports the first line that differs;
//! 2. checks the workflow's structure independently of that text, as a
//!    whitelist: the file must be ASCII with LF line ends and no control
//!    character but tab (YAML also breaks lines at a lone CR, and some
//!    parsers at NEL, LS and PS); every line outside a block scalar's body
//!    must be a plain `KEY:` or `KEY: VALUE` line or a `- ` list item
//!    opening one (no quoted key, no space before a colon, exactly one space
//!    after it, so that no value begins with more white space; no flow
//!    mapping, anchor, alias, merge key, tag, document marker or tab indent;
//!    a block scalar only as `|`, `|-`, `|+`, `>`, `>-` or `>+`; a quoted
//!    value closed on its own line; a flow sequence closed on its own line
//!    and holding plain scalars only, with no `#`; no key repeated within
//!    one mapping, at any depth or indent), and
//!    every key must be on the list of key paths below. The job's steps are
//!    read from that same classification, so a line inside a block scalar is
//!    never a step. `defaults:`, `working-directory:`, `continue-on-error` and
//!    `needs:` are refused everywhere; `shell:` is allowed only as
//!    `shell: bash`; `if:` only on an upload step, as `if: failure()`; the
//!    workflow's env and permissions values and the runner label must be the
//!    pinned ones. The first step must be exactly the pinned checkout, the
//!    second exactly the pinned Mode step, the step two before the comparison
//!    exactly the pinned LiteInst source and identity step (these decide and
//!    prove which LiteInst a run compares), the
//!    comparison step exactly its three pinned lines (name,
//!    `timeout-minutes: 100` and the run line, with all three backends in
//!    `--backends` and in `--require-compared`, `--report-only` nowhere and
//!    nothing chained after it), the step just before it exactly the pinned
//!    sources check, and every step after it a failure-only upload. Also
//!    required, read from the same classified keys: exactly one job,
//!    `e2e-compare`; the push trigger on `liteinst-main`, the `workflow_call`
//!    trigger and its required `liteinst2_sha` input; and, present as text,
//!    the mode step's two input checks and the identity check;
//! 3. lints every `reverie-examples/e2e/ledgers/ubuntu-*.tsv` against the
//!    ledger bar (backend ptrace, liteinst or in-guest-trap, never `native`;
//!    no `*` in the cell or signature column; no ` || `; verdict `mismatch`
//!    only; at most (corpus cells) x 3 rows, the cells counted from
//!    `reverie-examples/e2e/corpus.tsv` when the check runs), naming the file,
//!    line and rule of each violation, and reports how many ledgers it linted.
//!
//! What the structural layer proves, with the pin re-set to any text it
//! accepts: the pinned checkout runs first, the pinned Mode and LiteInst
//! steps decide and prove which LiteInst is compared (subject to the limit
//! below); the comparison step runs, unconditionally, exactly the pinned
//! command, with no shell or directory override at any level and, at the
//! YAML level, no environment variable beyond the pinned ones (each pinned
//! key occurring exactly once); only failure-only uploads follow it; and the
//! sources check runs just before it. That check fails the run if a file
//! under `reverie-examples/e2e` differs from the checked-out commit, which
//! catches an earlier step's accidental change. The limit: an earlier step
//! that commits its change or redirects git (through `$GITHUB_ENV` or
//! `$GITHUB_PATH`, say), and anything an earlier step's script or action
//! (`uses:`) does outside `reverie-examples/e2e` (editing
//! `reverie-liteinst/Cargo.toml` and `Cargo.lock` so the identity check
//! proves a different rev, for example), are guarded only by the byte pin and
//! review.
//!
//! `--self-test` requires every mutant in the table below to be refused with
//! a message naming what it changed. A workflow mutant runs against a pin
//! re-set to the mutant itself, so the structural checks, not the byte
//! comparison, must refuse it; a ledger mutant is a change to the synthetic
//! valid ledger below. The number of cases is pinned as a literal.
//!
//! ```text
//! check-e2e-compare.rs [ROOT]       # ROOT: the repository root, default .
//! check-e2e-compare.rs --self-test
//! ```

use std::fs;
use std::path::Path;
use std::process::ExitCode;

const WORKFLOW_PATH: &str = ".github/workflows/e2e-compare.yml";
const LEDGER_DIR: &str = "reverie-examples/e2e/ledgers";
const CORPUS_PATH: &str = "reverie-examples/e2e/corpus.tsv";
const BACKENDS: [&str; 3] = ["ptrace", "liteinst", "in-guest-trap"];
/// The comparison step's run line, exactly.
const COMPARE_RUN: &str = "      run: reverie-examples/e2e/run.sh --backends ptrace,liteinst,in-guest-trap --require-compared ptrace,liteinst,in-guest-trap --write-ledger \"$RUNNER_TEMP/e2e-rows.tsv\"";
/// The comparison step, exactly.
const COMPARE_STEP: [&str; 3] = [
    "    - name: Compare",
    "      timeout-minutes: 100",
    COMPARE_RUN,
];
/// The step just before the comparison, exactly.
const SOURCES_STEP: [&str; 15] = [
    "    - name: E2E sources as checked out",
    "      timeout-minutes: 1",
    "      shell: bash",
    "      run: |",
    "        set -euo pipefail",
    "        # run.sh, compare.rs, the corpus and the ledgers must match the",
    "        # checked-out commit when the comparison starts. This catches an",
    "        # earlier step's accidental change, addition or removal; a step that",
    "        # commits its change or redirects git is caught only by review.",
    "        git diff --exit-code HEAD -- reverie-examples/e2e",
    "        changed=$(git status --porcelain --untracked-files=all --ignored -- reverie-examples/e2e)",
    "        if [[ -n $changed ]]; then",
    "          printf '::error::files changed under reverie-examples/e2e before the comparison:\\n%s\\n' \"$changed\"",
    "          exit 1",
    "        fi",
];
/// The first step, the checkout, exactly: which commit is compared.
const CHECKOUT_STEP: [&str; 6] = [
    "    - uses: actions/checkout@v4",
    "      timeout-minutes: 2",
    "      with:",
    "        repository: ${{ github.event_name == 'pull_request' && 'rrnewton/reverie' || github.repository }}",
    "        ref: ${{ github.event_name == 'pull_request' && 'liteinst-main' || github.sha }}",
    "        submodules: false",
];
/// The second step, Mode, exactly: it decides which LiteInst a run compares.
const MODE_STEP_TEXT: &str = r####"    - name: Mode
      id: mode
      timeout-minutes: 1
      shell: bash
      env:
        LITEINST2_SHA: ${{ inputs.liteinst2_sha }}
      run: |
        set -euo pipefail
        # Total over the event and the input, before anything is built.
        case $GITHUB_EVENT_NAME in
          push | schedule | workflow_dispatch) mode=reverie ;;
          pull_request) mode=liteinst2-pr ;;
          *)
            printf '::error::e2e-compare does not run for event %q\n' "$GITHUB_EVENT_NAME"
            exit 1
            ;;
        esac
        if [[ $mode == reverie && -n $LITEINST2_SHA ]]; then
          printf '::error::liteinst2_sha given outside a liteinst2 pull request call: %q\n' "$LITEINST2_SHA"
          exit 1
        fi
        if [[ $mode == liteinst2-pr && ! $LITEINST2_SHA =~ ^[0-9a-f]{40}$ ]]; then
          printf '::error::liteinst2_sha missing or not a 40-hex commit: %q\n' "$LITEINST2_SHA"
          exit 1
        fi
        echo "mode=$mode" >> "$GITHUB_OUTPUT"
        echo "e2e-compare mode: $mode""####;
/// The step two before Compare, LiteInst source and identity, exactly: it
/// builds against the pull request's LiteInst in liteinst2-pr mode and proves
/// each crate's source in both modes.
const LITEINST_STEP_TEXT: &str = r####"    - name: LiteInst source and identity
      timeout-minutes: 5
      shell: bash
      env:
        MODE: ${{ steps.mode.outputs.mode }}
        LITEINST2_SHA: ${{ inputs.liteinst2_sha }}
      run: |
        set -euo pipefail
        {
          echo "## e2e-compare"
          echo "- mode: $MODE"
          echo "- reverie: $(git rev-parse HEAD)"
        } >> "$GITHUB_STEP_SUMMARY"
        crates=(liteinst liteinst-aarch64 liteinst-aarch64-patch)
        declare -A want
        if [[ $MODE == liteinst2-pr ]]; then
          # Reverie's liteinst-main, built against the pull request's LiteInst.
          src="$RUNNER_TEMP/liteinst2"
          git init -q "$src"
          git -C "$src" fetch -q --depth 1 https://github.com/rrnewton/liteinst2 "$LITEINST2_SHA"
          git -C "$src" checkout -q --detach FETCH_HEAD
          got=$(git -C "$src" rev-parse HEAD)
          if [[ $got != "$LITEINST2_SHA" ]]; then
            echo "::error::the liteinst2 checkout is $got, not $LITEINST2_SHA"
            exit 1
          fi
          echo "- liteinst2: $got" >> "$GITHUB_STEP_SUMMARY"
          declare -A dir=(
            [liteinst]="$src"
            [liteinst-aarch64]="$src/crates/liteinst-aarch64"
            [liteinst-aarch64-patch]="$src/crates/liteinst-aarch64-patch"
          )
          for crate in "${crates[@]}"; do
            if ! grep -qx "name = \"$crate\"" "${dir[$crate]}/Cargo.toml"; then
              echo "::error::liteinst2 $got has no package $crate in ${dir[$crate]}"
              exit 1
            fi
            want[$crate]="path ${dir[$crate]}"
          done
          config="${CARGO_HOME:-$HOME/.cargo}/config.toml"
          if [[ -e $config ]]; then
            echo "::error::$config exists; refusing to replace it with the liteinst2 patch"
            exit 1
          fi
          mkdir -p "$(dirname "$config")"
          {
            echo '[patch.crates-io]'
            echo "liteinst = { path = \"${dir[liteinst]}\" }"
            echo '[patch."https://github.com/rrnewton/liteinst2"]'
            echo "liteinst-aarch64 = { path = \"${dir[liteinst-aarch64]}\" }"
            echo "liteinst-aarch64-patch = { path = \"${dir[liteinst-aarch64-patch]}\" }"
          } > "$config"
          cargo update -p liteinst -p liteinst-aarch64 -p liteinst-aarch64-patch
        else
          # The sources the manifest pins, never the lock (which cargo tree
          # --locked only echoes): liteinst from crates.io at 0.2.x, and the
          # two liteinst2 crates as git sources at the manifest's one rev.
          revs=$(grep -E '^liteinst-aarch64(-patch)? = \{.*git = "https://github\.com/rrnewton/liteinst2"' reverie-liteinst/Cargo.toml | grep -oE 'rev = "[0-9a-f]{40}"' | sort -u || true)
          pins=$(printf '%s\n' "$revs" | grep -c . || true)
          if [[ $pins != 1 ]]; then
            echo "::error::reverie-liteinst/Cargo.toml does not pin one liteinst2 rev: ${revs:-none}"
            exit 1
          fi
          rev=${revs#rev = \"}
          rev=${rev%\"}
          want[liteinst]='registry ^liteinst v0\.2\.[0-9]+$'
          for crate in liteinst-aarch64 liteinst-aarch64-patch; do
            want[$crate]="git ^$crate v[0-9][^ ]* \\(https://github\\.com/rrnewton/liteinst2\\?rev=$rev#${rev:0:8}[0-9a-f]*\\)\$"
          done
        fi
        # The identity check, in both modes and never skipped: each crate
        # resolves to the source its mode requires, and any other source
        # (a path in reverie mode, the registry in pull request mode) fails.
        for crate in "${crates[@]}"; do
          if ! tree=$(cargo tree --locked --workspace --target x86_64-unknown-linux-gnu -i "$crate" --depth 0); then
            echo "::error::cargo tree -i $crate failed"
            exit 1
          fi
          line=${tree%%$'\n'*}
          kind=${want[$crate]%% *}
          expected=${want[$crate]#* }
          ok=0
          if [[ $kind == path ]]; then
            [[ $line == "$crate v"*" ($expected)" ]] && ok=1
          else
            [[ $line =~ $expected ]] && ok=1
          fi
          echo "- $crate: $line" >> "$GITHUB_STEP_SUMMARY"
          if ((ok == 0)); then
            echo "::error::$crate resolves to '$line', not the $kind source mode $MODE requires ($expected)"
            exit 1
          fi
        done"####;
/// Values pinned by key path: the workflow's environment, its token's
/// permissions and the runner.
const EXACT_VALUES: [(&str, &str); 4] = [
    ("env.CARGO_TERM_COLOR", "always"),
    ("env.RUSTFLAGS", "-C link-arg=-llzma"),
    ("permissions.contents", "read"),
    ("jobs.e2e-compare.runs-on", "ubuntu-24.04"),
];
const MODE_SHA_CHECK: &str =
    "if [[ $mode == liteinst2-pr && ! $LITEINST2_SHA =~ ^[0-9a-f]{40}$ ]]; then";
const MODE_OUTSIDE_PR_CHECK: &str = "if [[ $mode == reverie && -n $LITEINST2_SHA ]]; then";
const IDENTITY_CHECK: &str =
    "cargo tree --locked --workspace --target x86_64-unknown-linux-gnu -i \"$crate\" --depth 0";
/// The only block scalar indicators accepted.
const BLOCK_INDICATORS: [&str; 6] = ["|", "|-", "|+", ">", ">-", ">+"];
/// Every key path the workflow may use; `-` stands for a list item.
const ALLOWED_PATHS: [&str; 44] = [
    "name",
    "on",
    "on.push",
    "on.push.branches",
    "on.schedule",
    "on.schedule.-.cron",
    "on.workflow_dispatch",
    "on.workflow_call",
    "on.workflow_call.inputs",
    "on.workflow_call.inputs.liteinst2_sha",
    "on.workflow_call.inputs.liteinst2_sha.description",
    "on.workflow_call.inputs.liteinst2_sha.type",
    "on.workflow_call.inputs.liteinst2_sha.required",
    "permissions",
    "permissions.contents",
    "concurrency",
    "concurrency.group",
    "concurrency.cancel-in-progress",
    "env",
    "env.CARGO_TERM_COLOR",
    "env.RUSTFLAGS",
    "jobs",
    "jobs.e2e-compare",
    "jobs.e2e-compare.name",
    "jobs.e2e-compare.runs-on",
    "jobs.e2e-compare.timeout-minutes",
    "jobs.e2e-compare.steps",
    "jobs.e2e-compare.steps.-.name",
    "jobs.e2e-compare.steps.-.id",
    "jobs.e2e-compare.steps.-.uses",
    "jobs.e2e-compare.steps.-.with",
    "jobs.e2e-compare.steps.-.with.repository",
    "jobs.e2e-compare.steps.-.with.ref",
    "jobs.e2e-compare.steps.-.with.submodules",
    "jobs.e2e-compare.steps.-.with.name",
    "jobs.e2e-compare.steps.-.with.path",
    "jobs.e2e-compare.steps.-.with.if-no-files-found",
    "jobs.e2e-compare.steps.-.with.retention-days",
    "jobs.e2e-compare.steps.-.run",
    "jobs.e2e-compare.steps.-.shell",
    "jobs.e2e-compare.steps.-.env",
    "jobs.e2e-compare.steps.-.env.LITEINST2_SHA",
    "jobs.e2e-compare.steps.-.env.MODE",
    "jobs.e2e-compare.steps.-.timeout-minutes",
];
/// The path of a step's own keys.
const STEP_KEY: &str = "jobs.e2e-compare.steps.-.";
/// Keys refused wherever they appear, each with the refusal's wording.
const REFUSED_KEYS: [(&str, &str); 4] = [
    (
        "defaults",
        "defaults: (a shell or directory override for every step)",
    ),
    ("working-directory", "working-directory:"),
    ("continue-on-error", "continue-on-error"),
    ("needs", "needs: (a job dependency)"),
];
/// The self-test's case count, pinned: deleting a mutant must fail.
const SELF_TEST_CASES: usize = 101;
/// The synthetic corpus size the self-test lints against (23 x 3 = 69 rows).
const SYNTHETIC_CELLS: usize = 23;

/// The first line where `found` differs from `expected`, if it does.
fn byte_exact(found: &str, expected: &str) -> Result<(), String> {
    if found == expected {
        return Ok(());
    }
    let mut expected_lines = expected.split_inclusive('\n');
    let mut found_lines = found.split_inclusive('\n');
    let mut number = 0;
    loop {
        number += 1;
        match (expected_lines.next(), found_lines.next()) {
            (Some(e), Some(f)) if e == f => {}
            (Some(e), Some(f)) => {
                return Err(format!(
                    "{WORKFLOW_PATH} line {number}: expected {e:?} found {f:?}"
                ));
            }
            (Some(e), None) => return Err(format!("{WORKFLOW_PATH} line {number}: missing {e:?}")),
            (None, Some(f)) => return Err(format!("{WORKFLOW_PATH} line {number}: extra {f:?}")),
            (None, None) => return Err(format!("{WORKFLOW_PATH} differs from its pin")),
        }
    }
}

/// One step of the job: its name (from its first line) and its numbered
/// lines.
struct Step<'a> {
    name: String,
    lines: Vec<(usize, &'a str)>,
}

/// The job's steps, read from the classified key lines, so that the
/// sequence checks and the whitelist see one structure. A step opens at each
/// `- KEY` item directly under `jobs.e2e-compare.steps` and runs to the line
/// before the next step, or before the first key outside the steps list.
/// Lines inside another key's block scalar are never key lines, so they are
/// never steps.
fn steps<'a>(lines: &[&'a str], keys: &[KeyLine<'_>]) -> Vec<Step<'a>> {
    let mut opened: Vec<(usize, String)> = Vec::new();
    let mut ends: Vec<usize> = Vec::new();
    let mut open = false;
    for key in keys {
        let in_list = key.path.starts_with(STEP_KEY);
        let opens = in_list && key.item && !key.path[STEP_KEY.len()..].contains('.');
        if opens {
            if open {
                ends.push(key.number - 1);
            }
            let name = match key.key {
                "name" | "uses" => key.value.unwrap_or("").to_owned(),
                other => format!("{other}: {}", key.value.unwrap_or("")),
            };
            opened.push((key.number, name));
            open = true;
        } else if open && !in_list {
            ends.push(key.number - 1);
            open = false;
        }
    }
    if open {
        ends.push(lines.len());
    }
    opened
        .into_iter()
        .zip(ends)
        .map(|((first, name), last)| Step {
            name,
            lines: (first..=last)
                .map(|number| (number, lines[number - 1]))
                .collect(),
        })
        .collect()
}

/// The step that holds line `number`, if any.
fn step_of<'s, 'a>(steps: &'s [Step<'a>], number: usize) -> Option<&'s Step<'a>> {
    steps
        .iter()
        .find(|step| step.lines.iter().any(|(at, _)| *at == number))
}

/// Every classified key line at exactly this key path.
fn keys_at<'k, 'a>(keys: &'k [KeyLine<'a>], path: &str) -> Vec<&'k KeyLine<'a>> {
    keys.iter().filter(|key| key.path == path).collect()
}

/// A step's own key lines: the classified keys within its lines, at step
/// level. A line inside a block scalar is never a key line, so a script body
/// can never supply one.
fn own_keys<'k, 'a>(step: &Step<'_>, keys: &'k [KeyLine<'a>]) -> Vec<&'k KeyLine<'a>> {
    let first = step.lines.first().map_or(0, |(number, _)| *number);
    let last = step.lines.last().map_or(0, |(number, _)| *number);
    keys.iter()
        .filter(|key| key.number >= first && key.number <= last)
        .filter(|key| {
            key.path
                .strip_prefix(STEP_KEY)
                .is_some_and(|rest| !rest.contains('.'))
        })
        .collect()
}

/// A step's lines, blank lines left out.
fn step_text<'a>(step: &Step<'a>) -> Vec<&'a str> {
    step.lines
        .iter()
        .map(|(_, line)| *line)
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// The backends `flag` lists on a command line.
fn listed<'a>(line: &'a str, flag: &str) -> Vec<&'a str> {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .iter()
        .position(|word| *word == flag)
        .and_then(|at| words.get(at + 1))
        .map_or_else(Vec::new, |list| list.split(',').collect())
}

/// A plain YAML key: a letter or `_`, then letters, digits, `_` or `-`.
fn is_plain_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `KEY:` or `KEY: VALUE`, split; otherwise why the text is not a plain key.
fn split_key(text: &str) -> Result<(&str, Option<&str>), String> {
    let Some((key, rest)) = text.split_once(':') else {
        return Err("not a key, a list item or a block scalar's body".to_owned());
    };
    if key.starts_with('"') || key.starts_with('\'') {
        return Err("a quoted key".to_owned());
    }
    if key.ends_with(' ') {
        return Err("a space before the colon".to_owned());
    }
    if !is_plain_key(key) {
        return Err(format!("`{key}` is not a plain key"));
    }
    if rest.is_empty() {
        return Ok((key, None));
    }
    let Some(value) = rest.strip_prefix(' ') else {
        return Err(format!("no space after `{key}:`"));
    };
    if value.trim().is_empty() {
        return Err(format!("trailing space after `{key}:`"));
    }
    // YAML's white space is space and tab (YAML 1.2.2, s-white), and YAML
    // takes any run of it before a value. Exactly one space keeps every value
    // form below visible to value_problem and classify.
    if value.starts_with(|c: char| c == ' ' || c == '\t') {
        return Err(format!("more than one space, or a tab, after `{key}:`"));
    }
    Ok((key, Some(value)))
}

/// Whether a quoted value closes on its own line. A `"` value ends with an
/// unescaped `"` (an even run of `\` before it). A `'` value ends with an ODD
/// run of `'` after the opener, because `''` is an escaped quote: `''` and
/// `'x'''` close, `'''` and `'x''` do not.
fn closes(value: &str, quote: char) -> bool {
    if value.len() < 2 || !value.ends_with(quote) {
        return false;
    }
    if quote == '\'' {
        return value[1..].chars().rev().take_while(|c| *c == '\'').count() % 2 == 1;
    }
    let inner = &value[..value.len() - 1];
    inner.chars().rev().take_while(|c| *c == '\\').count() % 2 == 0
}

/// Why a value is outside the accepted forms, if it is.
fn value_problem(value: &str) -> Option<String> {
    match value.chars().next()? {
        '{' => Some("a flow mapping".to_owned()),
        '&' | '*' => Some("an anchor or alias".to_owned()),
        '!' => Some("a YAML tag".to_owned()),
        quote @ ('"' | '\'') if !closes(value, quote) => {
            Some("a quoted value that does not close on its line".to_owned())
        }
        '[' if !value.ends_with(']') => {
            Some("a flow sequence that does not close on its line".to_owned())
        }
        '[' if value[1..value.len() - 1]
            .contains(|c: char| matches!(c, '[' | '{' | ':' | '\'' | '"' | '#')) =>
        {
            Some("a flow sequence holding more than plain scalars".to_owned())
        }
        '|' | '>' if !BLOCK_INDICATORS.contains(&value) => Some(format!(
            "block scalar indicator `{value}` (only |, |-, |+, >, >- or >+)"
        )),
        _ => None,
    }
}

/// One key line: its number, its key path, its key, its value, whether it
/// opens a list item, and the line rewritten at its normalised indent (a
/// `- KEY:` item becomes `KEY:` two columns in).
struct KeyLine<'a> {
    number: usize,
    path: String,
    key: &'a str,
    value: Option<&'a str>,
    item: bool,
    normalised: String,
}

/// Classifies every line outside a block scalar's body, reporting by name
/// each line it cannot classify, and returns the key lines.
fn classify<'a>(lines: &[&'a str], problems: &mut Vec<String>) -> Vec<KeyLine<'a>> {
    let mut keys = Vec::new();
    // (indent, key, line), `-` for a list item, innermost last.
    let mut stack: Vec<(usize, &str, usize)> = Vec::new();
    // Each mapping's keys, by the line that opened the mapping (0 for the
    // top level; a list item's own line for its keys): YAML forbids a key
    // repeated in one mapping, whatever its indent.
    let mut seen: std::collections::HashMap<(usize, &str), usize> =
        std::collections::HashMap::new();
    // The indent a block scalar's body lines must exceed.
    let mut block: Option<usize> = None;
    for (index, &line) in lines.iter().enumerate() {
        let number = index + 1;
        let body = line.trim_start_matches(' ');
        let at = line.len() - body.len();
        if let Some(limit) = block {
            if body.trim().is_empty() || at > limit {
                continue;
            }
            block = None;
        }
        if body.trim().is_empty() || body.starts_with('#') {
            continue;
        }
        if body.starts_with('\t') {
            problems.push(format!("line {number}: a tab in the indentation"));
            continue;
        }
        if body == "---" || body == "..." || body.starts_with("--- ") {
            problems.push(format!("line {number}: a YAML document marker"));
            continue;
        }
        let (key_at, text) = match body.strip_prefix("- ") {
            Some(rest) => {
                while stack.last().is_some_and(|(open, _, _)| *open > at) {
                    stack.pop();
                }
                stack.push((at + 1, "-", number));
                (at + 2, rest)
            }
            None => {
                while stack.last().is_some_and(|(open, _, _)| *open >= at) {
                    stack.pop();
                }
                (at, body)
            }
        };
        // A flow mapping, an anchor, an alias or a tag in place of a key.
        if text.starts_with(|c: char| matches!(c, '{' | '&' | '*' | '!')) {
            if let Some(problem) = value_problem(text) {
                problems.push(format!("line {number}: {problem}"));
                continue;
            }
        }
        let parent: Vec<&str> = stack.iter().map(|(_, key, _)| *key).collect();
        let parent = parent.join(".");
        let mapping = stack.last().map_or(0, |(_, _, line)| *line);
        match split_key(text) {
            Err(problem) => problems.push(format!("line {number}: {problem}")),
            Ok((key, value)) => {
                if let Some(problem) = value.and_then(value_problem) {
                    problems.push(format!("line {number}: {problem}"));
                }
                match value {
                    None => stack.push((key_at, key, number)),
                    Some(value) if BLOCK_INDICATORS.contains(&value) => block = Some(key_at),
                    Some(_) => {}
                }
                let path = if parent.is_empty() {
                    key.to_owned()
                } else {
                    format!("{parent}.{key}")
                };
                match seen.entry((mapping, key)) {
                    std::collections::hash_map::Entry::Occupied(first) => problems.push(format!(
                        "line {number}: duplicate key `{path}` (first at line {})",
                        first.get()
                    )),
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(number);
                    }
                }
                keys.push(KeyLine {
                    number,
                    path,
                    key,
                    value,
                    item: key_at > at,
                    normalised: format!("{}{text}", " ".repeat(key_at)),
                });
            }
        }
    }
    keys
}

/// The structural checks: every problem found, by name.
fn structural(text: &str) -> Vec<String> {
    let mut problems = Vec::new();

    // ASCII with LF line ends and no control character but tab: every line
    // break YAML could see is one this checker sees too, and YAML's only
    // white space, space and tab, is the only white space a line can hold.
    for (index, line) in text.split('\n').enumerate() {
        let number = index + 1;
        if line.contains('\r') {
            problems.push(format!(
                "line {number}: a carriage return (LF line ends only)"
            ));
        }
        if let Some(c) = line
            .chars()
            .find(|c| c.is_ascii_control() && *c != '\t' && *c != '\r')
        {
            problems.push(format!(
                "line {number}: a control character U+{:04X} (tab and LF are the only controls)",
                u32::from(c)
            ));
        }
        if let Some(c) = line.chars().find(|c| !c.is_ascii()) {
            problems.push(format!(
                "line {number}: a non-ASCII character U+{:04X} (ASCII only)",
                u32::from(c)
            ));
        }
    }
    let lines: Vec<&str> = text.lines().collect();

    // The whitelist: every line classified, every key on the list, and the
    // steps read from the same classification.
    let keys = classify(&lines, &mut problems);
    let steps = steps(&lines, &keys);

    // Triggers and the one job, read from the classified keys, so that text
    // inside a block scalar can never stand in for them.
    if !matches!(keys_at(&keys, "on.push.branches").as_slice(), [key] if key.value == Some("[liteinst-main]"))
    {
        problems.push("the push trigger on liteinst-main is missing".to_owned());
    }
    if keys_at(&keys, "on.workflow_call").is_empty() {
        problems.push("the workflow_call trigger is missing".to_owned());
    }
    if !matches!(
        keys_at(&keys, "on.workflow_call.inputs.liteinst2_sha.required").as_slice(),
        [key] if key.value == Some("true")
    ) {
        problems
            .push("the workflow_call liteinst2_sha input is missing (required: true)".to_owned());
    }
    if keys_at(&keys, "jobs").is_empty() {
        problems.push("there is no jobs: section".to_owned());
    } else {
        let mut jobs: Vec<&str> = Vec::new();
        for key in &keys {
            if let Some(job) = key
                .path
                .strip_prefix("jobs.")
                .and_then(|rest| rest.split('.').next())
            {
                if !jobs.contains(&job) {
                    jobs.push(job);
                }
            }
        }
        if jobs != ["e2e-compare"] {
            problems.push(format!(
                "expected exactly one job, e2e-compare; found {jobs:?}"
            ));
        }
    }
    for (path, value) in EXACT_VALUES {
        let found: Vec<&KeyLine> = keys.iter().filter(|key| key.path == path).collect();
        match found.as_slice() {
            [] => problems.push(format!("`{path}` is missing; it must be exactly `{value}`")),
            [key] if key.value != Some(value) => problems.push(format!(
                "line {}: `{path}` must be exactly `{value}`",
                key.number
            )),
            [_] => {}
            many => problems.push(format!(
                "`{path}` occurs {} times (lines {}); it must occur exactly once",
                many.len(),
                many.iter()
                    .map(|key| key.number.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
    for key in &keys {
        let number = key.number;
        if let Some((_, refusal)) = REFUSED_KEYS.iter().find(|(name, _)| *name == key.key) {
            problems.push(format!("line {number}: {refusal}"));
            continue;
        }
        if key.key == "if" {
            if key.path == format!("{STEP_KEY}if") {
                let step = step_of(&steps, number);
                let upload = step.is_some_and(|step| {
                    own_keys(step, &keys)
                        .iter()
                        .any(|key| key.normalised == "      uses: actions/upload-artifact@v4")
                });
                if !upload || key.normalised != "      if: failure()" {
                    let name = step.map_or("(none)", |step| step.name.as_str());
                    problems.push(format!(
                        "line {number}: step `{name}` has an if:; only an upload may, as if: failure()"
                    ));
                }
            } else {
                problems.push(format!("line {number}: a job-level if:"));
            }
            continue;
        }
        if !ALLOWED_PATHS.contains(&key.path.as_str()) {
            let parent = key
                .path
                .rsplit_once('.')
                .map_or("(top level)", |(parent, _)| parent);
            problems.push(format!(
                "line {number}: key `{}` is not allowed at `{parent}`",
                key.key
            ));
        }
        if key.key == "shell" && key.value != Some("bash") {
            problems.push(format!(
                "line {number}: shell: {} (only shell: bash)",
                key.value.unwrap_or("")
            ));
        }
    }
    for (index, line) in lines.iter().enumerate() {
        if line.contains("--report-only") {
            problems.push(format!("line {}: --report-only", index + 1));
        }
    }

    // The comparison: one run line, exactly the command.
    let runs: Vec<(usize, &str)> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("e2e/run.sh"))
        .map(|(index, line)| (index + 1, *line))
        .collect();
    if runs.is_empty() {
        problems.push("the comparison command (reverie-examples/e2e/run.sh) is missing".to_owned());
    }
    for (number, line) in &runs {
        let after = line.split_once("run.sh").map_or("", |(_, rest)| rest);
        for chain in ["||", "&&", ";", "|", "&"] {
            if after.contains(chain) {
                problems.push(format!(
                    "line {number}: the comparison's run line chains `{chain}`"
                ));
                break;
            }
        }
        for flag in ["--backends", "--require-compared"] {
            let backends = listed(line, flag);
            for backend in BACKENDS {
                if !backends.contains(&backend) {
                    problems.push(format!(
                        "line {number}: the comparison's {flag} lacks {backend}"
                    ));
                }
            }
        }
        if *line != COMPARE_RUN {
            problems.push(format!(
                "line {number}: the comparison's run line is not exactly {:?}",
                COMPARE_RUN.trim_start()
            ));
        }
    }
    if runs.len() > 1 {
        problems.push(format!(
            "{} lines run reverie-examples/e2e/run.sh; one may",
            runs.len()
        ));
    }
    if let Some((first, _)) = runs.first() {
        let timed = step_of(&steps, *first).is_some_and(|step| {
            step.lines
                .iter()
                .any(|(_, line)| *line == "      timeout-minutes: 100")
        });
        if !timed {
            problems.push("the comparison step has no `timeout-minutes: 100`".to_owned());
        }
    }

    // The exact sequence: the pinned checkout first; the sources check, then
    // the comparison, then failure-only uploads.
    if steps
        .first()
        .is_none_or(|step| step_text(step) != CHECKOUT_STEP)
    {
        problems.push(
            "the first step is not the pinned checkout (uses, repository, ref, submodules)"
                .to_owned(),
        );
    }
    // The Mode step decides liteinst2-pr against reverie mode; it must be the
    // second step, exactly, so that the LiteInst step reads its output.
    if steps
        .get(1)
        .is_none_or(|step| step_text(step).join("\n") != MODE_STEP_TEXT)
    {
        problems.push(
            "the second step is not the pinned Mode step (its id, its LITEINST2_SHA input and its checks)"
                .to_owned(),
        );
    }
    let compares: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step.name == "Compare")
        .map(|(at, _)| at)
        .collect();
    match compares.as_slice() {
        [at] => {
            if step_text(&steps[*at]) != COMPARE_STEP {
                problems.push(
                    "the Compare step is not exactly its three pinned lines (name, timeout-minutes: 100, the run line)"
                        .to_owned(),
                );
            }
            let before = if *at == 0 {
                Vec::new()
            } else {
                step_text(&steps[*at - 1])
            };
            if before != SOURCES_STEP {
                problems.push(
                    "the step just before Compare is not the pinned sources check (E2E sources as checked out)"
                        .to_owned(),
                );
            }
            // Which LiteInst is compared: the pull request's in liteinst2-pr
            // mode, the manifest's in reverie mode, each proven.
            let liteinst = if *at < 2 {
                String::new()
            } else {
                step_text(&steps[*at - 2]).join("\n")
            };
            if liteinst != LITEINST_STEP_TEXT {
                problems.push(
                    "the step two before Compare is not the pinned LiteInst step (LiteInst source and identity)"
                        .to_owned(),
                );
            }
            for step in &steps[*at + 1..] {
                let own = own_keys(step, &keys);
                let names: Vec<&str> = own.iter().map(|key| key.key).collect();
                let upload = names == ["name", "if", "timeout-minutes", "uses", "with"]
                    && own
                        .iter()
                        .any(|key| key.normalised == "      if: failure()")
                    && own
                        .iter()
                        .any(|key| key.normalised == "      uses: actions/upload-artifact@v4");
                if !upload {
                    problems.push(format!(
                        "step `{}` after Compare is not a failure-only upload",
                        step.name
                    ));
                }
            }
        }
        [] => problems.push("there is no step named Compare".to_owned()),
        many => problems.push(format!("{} steps are named Compare; one may", many.len())),
    }

    // The mode step's input checks and the identity check.
    if !lines.iter().any(|line| line.trim() == MODE_SHA_CHECK) {
        problems.push("the mode step's 40-hex liteinst2_sha check is missing".to_owned());
    }
    if !lines
        .iter()
        .any(|line| line.trim() == MODE_OUTSIDE_PR_CHECK)
    {
        problems.push(
            "the mode step's check for a liteinst2_sha outside a liteinst2 pull request is missing"
                .to_owned(),
        );
    }
    if !lines.iter().any(|line| line.contains(IDENTITY_CHECK)) {
        problems.push("the identity check (cargo tree -i, both modes) is missing".to_owned());
    }
    problems
}

/// The corpus's cells: its lines other than blanks and `#` comments, as the
/// comparator reads them.
fn corpus_cells(text: &str) -> usize {
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .count()
}

/// The corpus's cell count, and a problem if the corpus could not be read
/// (`None`) or has no cell. Either way the cap is then 0, so every ledger row
/// also exceeds it.
fn corpus_check(name: &str, text: Option<&str>) -> (usize, Vec<String>) {
    let Some(text) = text else {
        return (
            0,
            vec![format!("{name}: missing, so no cell can be counted")],
        );
    };
    let cells = corpus_cells(text);
    let problems = if cells == 0 {
        vec![format!("{name}: no cells")]
    } else {
        Vec::new()
    };
    (cells, problems)
}

/// The ledger bar, each violation named by file, line and rule. `cells` is
/// the corpus size, which caps the rows at `cells` x 3.
fn lint_ledger(name: &str, text: &str, cells: usize) -> Vec<String> {
    let mut problems = Vec::new();
    let mut rows = 0;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        rows += 1;
        let at = format!("{name}:{}", index + 1);
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 5 {
            problems.push(format!(
                "{at}: needs 5 tab-separated fields, has {}",
                fields.len()
            ));
            continue;
        }
        let (cell, backend, verdict, signature, issue) =
            (fields[0], fields[1], fields[2], fields[3], fields[4]);
        if cell.is_empty() {
            problems.push(format!("{at}: an empty cell column"));
        }
        if cell.contains('*') {
            problems.push(format!("{at}: `*` in the cell column"));
        }
        if signature.contains('*') {
            problems.push(format!("{at}: `*` in the signature column"));
        }
        if line.contains(" || ") {
            problems.push(format!("{at}: ` || ` alternatives"));
        }
        if backend == "native" {
            problems.push(format!("{at}: a `native` row"));
        } else if !BACKENDS.contains(&backend) {
            problems.push(format!(
                "{at}: backend {backend} is not ptrace, liteinst or in-guest-trap"
            ));
        }
        if verdict != "mismatch" {
            problems.push(format!("{at}: verdict {verdict} is not `mismatch`"));
        }
        if !issue.starts_with("https://github.com/") {
            problems.push(format!("{at}: the issue column is not a full GitHub URL"));
        }
    }
    let max_rows = cells * BACKENDS.len();
    if rows > max_rows {
        problems.push(format!(
            "{name}: {rows} rows, more than {max_rows} ({cells} cells x 3 backends)"
        ));
    }
    problems
}

fn check(root: &Path) -> ExitCode {
    let mut problems = Vec::new();
    match fs::read_to_string(root.join(WORKFLOW_PATH)) {
        Ok(text) => {
            if let Err(problem) = byte_exact(&text, PINNED) {
                problems.push(problem);
            }
            problems.extend(structural(&text));
        }
        Err(error) => problems.push(format!("{WORKFLOW_PATH}: {error}")),
    }
    let corpus = fs::read_to_string(root.join(CORPUS_PATH));
    if let Err(error) = &corpus {
        problems.push(format!("{CORPUS_PATH}: {error}"));
    }
    let (cells, found) = corpus_check(CORPUS_PATH, corpus.as_deref().ok());
    problems.extend(found);
    let mut linted = 0;
    match fs::read_dir(root.join(LEDGER_DIR)) {
        Ok(entries) => {
            let mut names: Vec<String> = Vec::new();
            for entry in entries {
                match entry {
                    Ok(entry) => names.push(entry.file_name().to_string_lossy().into_owned()),
                    Err(error) => problems.push(format!("{LEDGER_DIR}: {error}")),
                }
            }
            names.sort();
            for name in names
                .iter()
                .filter(|name| name.starts_with("ubuntu-") && name.ends_with(".tsv"))
            {
                let path = format!("{LEDGER_DIR}/{name}");
                match fs::read_to_string(root.join(&path)) {
                    Ok(text) => problems.extend(lint_ledger(&path, &text, cells)),
                    Err(error) => problems.push(format!("{path}: {error}")),
                }
                linted += 1;
            }
        }
        Err(error) => problems.push(format!("{LEDGER_DIR}: {error}")),
    }
    println!("check-e2e-compare: linted {linted} ubuntu ledger(s)");
    if problems.is_empty() {
        println!("check-e2e-compare: {WORKFLOW_PATH} matches its pin and its structural checks");
        ExitCode::SUCCESS
    } else {
        for problem in &problems {
            eprintln!("check-e2e-compare: ERROR: {problem}");
        }
        ExitCode::from(1)
    }
}

/// A valid ledger under the bar: the self-test's positive ledger case and
/// the base of its ledger mutants.
const SYNTHETIC_LEDGER: &str = "# A synthetic ledger for the self-test, valid under the bar.\n\
# write: the stand-in defect this group names.\n\
alpha\tptrace\tmismatch\twrite=5 -> write=6\thttps://github.com/rrnewton/hermit/issues/4485\n\
beta\tliteinst\tmismatch\tbrk=ok -> mmap=ok\thttps://github.com/rrnewton/hermit/issues/4485\n";

/// A valid corpus: the self-test's positive corpus case and the base of its
/// corpus mutant.
const SYNTHETIC_CORPUS: &str = "# A synthetic corpus for the self-test.\nalpha\t/bin/true\n";

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Workflow,
    Ledger,
    Corpus,
    /// The corpus file itself is absent: the mutation only marks the case.
    CorpusMissing,
}

/// `text` with the first `from` replaced by `to`; None if `from` is absent,
/// so a mutant that no longer applies fails rather than passes.
fn replace_once(text: &str, from: &str, to: &str) -> Option<String> {
    text.contains(from).then(|| text.replacen(from, to, 1))
}

/// (name, what it mutates, the mutation, a phrase the refusal must name).
type Mutant = (&'static str, Kind, fn(&str) -> Option<String>, &'static str);

/// One table row. Passing each closure as a `fn` argument makes it a plain
/// function pointer.
fn mutant(
    name: &'static str,
    kind: Kind,
    mutate: fn(&str) -> Option<String>,
    phrase: &'static str,
) -> Mutant {
    (name, kind, mutate, phrase)
}

/// The sources check's text, one line per entry, for the mutants that move
/// or change it.
fn sources_text() -> String {
    SOURCES_STEP
        .iter()
        .map(|line| format!("{line}\n"))
        .collect()
}

/// The comparison step's text, one line per entry.
fn compare_text() -> String {
    COMPARE_STEP
        .iter()
        .map(|line| format!("{line}\n"))
        .collect()
}

fn mutants() -> Vec<Mutant> {
    vec![
        mutant(
            "push trigger removed",
            Kind::Workflow,
            |t| replace_once(t, "  push:\n    branches: [liteinst-main]\n", ""),
            "push trigger",
        ),
        mutant(
            "workflow_call removed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "  workflow_call:\n    inputs:\n      liteinst2_sha:\n        description: The rrnewton/liteinst2 commit a pull request compares.\n        type: string\n        required: true\n",
                    "",
                )
            },
            "workflow_call trigger",
        ),
        mutant(
            "liteinst2_sha input removed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      liteinst2_sha:\n        description: The rrnewton/liteinst2 commit a pull request compares.\n        type: string\n        required: true\n",
                    "",
                )
            },
            "liteinst2_sha input",
        ),
        mutant(
            "needs: regular added",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\n    needs: regular\n",
                )
            },
            "needs:",
        ),
        mutant(
            "continue-on-error on the job",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\n    continue-on-error: true\n",
                )
            },
            "continue-on-error",
        ),
        mutant(
            "continue-on-error on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      continue-on-error: true\n",
                )
            },
            "continue-on-error",
        ),
        mutant(
            "job if: false",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\n    if: false\n",
                )
            },
            "job-level if:",
        ),
        mutant(
            "comparison command removed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    &format!("{COMPARE_RUN}\n"),
                    "      run: echo comparison skipped\n",
                )
            },
            "comparison command",
        ),
        mutant(
            "--report-only added",
            Kind::Workflow,
            |t| replace_once(t, "e2e-rows.tsv\"\n", "e2e-rows.tsv\" --report-only\n"),
            "--report-only",
        ),
        mutant(
            "|| true appended",
            Kind::Workflow,
            |t| replace_once(t, "e2e-rows.tsv\"\n", "e2e-rows.tsv\" || true\n"),
            "chains",
        ),
        mutant(
            "liteinst dropped from --backends",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "--backends ptrace,liteinst,in-guest-trap",
                    "--backends ptrace,in-guest-trap",
                )
            },
            "--backends lacks liteinst",
        ),
        mutant(
            "in-guest-trap dropped from --require-compared",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "--require-compared ptrace,liteinst,in-guest-trap",
                    "--require-compared ptrace,liteinst",
                )
            },
            "--require-compared lacks in-guest-trap",
        ),
        mutant(
            "ptrace dropped from --require-compared",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "--require-compared ptrace,liteinst,in-guest-trap",
                    "--require-compared liteinst,in-guest-trap",
                )
            },
            "--require-compared lacks ptrace",
        ),
        mutant(
            "the mode step's sha check removed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    &format!("        {MODE_SHA_CHECK}\n"),
                    "        if false; then\n",
                )
            },
            "40-hex",
        ),
        mutant(
            "the liteinst2_sha-outside-a-pull-request check removed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    &format!("        {MODE_OUTSIDE_PR_CHECK}\n"),
                    "        if false; then\n",
                )
            },
            "outside a liteinst2 pull request",
        ),
        mutant(
            "the identity check removed",
            Kind::Workflow,
            |t| replace_once(t, IDENTITY_CHECK, "echo \"$crate\""),
            "identity check",
        ),
        mutant(
            "the comparison's timeout-minutes removed",
            Kind::Workflow,
            |t| replace_once(t, "      timeout-minutes: 100\n", ""),
            "timeout-minutes: 100",
        ),
        mutant(
            "if: failure() on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      if: failure()\n",
                )
            },
            "step `Compare` has an if:",
        ),
        // Key and value spellings the whitelist refuses, the step rules, and
        // the pinned sources check.
        mutant(
            "- if: false as the comparison's first key",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    - name: Compare\n      timeout-minutes: 100\n",
                    "    - if: false\n      name: Compare\n      timeout-minutes: 100\n",
                )
            },
            "has an if:",
        ),
        mutant(
            "shell: true {0} on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      shell: true {0}\n",
                )
            },
            "only shell: bash",
        ),
        mutant(
            "job-level defaults: run: shell:",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\n    defaults:\n      run:\n        shell: true {0}\n",
                )
            },
            "defaults:",
        ),
        mutant(
            "workflow-level defaults:",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "jobs:\n",
                    "defaults:\n  run:\n    shell: true {0}\n\njobs:\n",
                )
            },
            "defaults:",
        ),
        mutant(
            "\"if\": false on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      \"if\": false\n",
                )
            },
            "a quoted key",
        ),
        mutant(
            "'if': false on an upload",
            Kind::Workflow,
            |t| replace_once(t, "      if: failure()\n", "      'if': false\n"),
            "a quoted key",
        ),
        mutant(
            "if : false on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      if : false\n",
                )
            },
            "a space before the colon",
        ),
        mutant(
            "working-directory: on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      working-directory: reverie-examples\n",
                )
            },
            "working-directory:",
        ),
        mutant(
            "env: on the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      env:\n        BASH_ENV: stub\n",
                )
            },
            "key `BASH_ENV` is not allowed",
        ),
        mutant(
            "an anchor",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: &minutes 100\n",
                )
            },
            "an anchor or alias",
        ),
        mutant(
            "a flow-mapping step",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    &format!("    - name: Compare\n      timeout-minutes: 100\n{COMPARE_RUN}\n"),
                    "    - { name: Compare, timeout-minutes: 100, run: true }\n",
                )
            },
            "a flow mapping",
        ),
        mutant(
            "a non-upload step after the comparison",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    &format!("{COMPARE_RUN}\n"),
                    &format!("{COMPARE_RUN}\n    - name: Extra\n      run: true\n"),
                )
            },
            "after Compare is not a failure-only upload",
        ),
        mutant(
            "the sources check removed",
            Kind::Workflow,
            |t| replace_once(t, &sources_text(), ""),
            "pinned sources check",
        ),
        mutant(
            "the sources check moved after the comparison",
            Kind::Workflow,
            |t| {
                let sources = sources_text();
                let moved = replace_once(t, &sources, "")?;
                replace_once(
                    &moved,
                    &format!("{COMPARE_RUN}\n"),
                    &format!("{COMPARE_RUN}\n{sources}"),
                )
            },
            "pinned sources check",
        ),
        mutant(
            "the sources check made to pass",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        git diff --exit-code HEAD -- reverie-examples/e2e\n",
                    "        git diff --exit-code HEAD -- reverie-examples/e2e || true\n",
                )
            },
            "pinned sources check",
        ),
        mutant(
            "an unknown step key",
            Kind::Workflow,
            |t| replace_once(t, "      id: mode\n", "      id: mode\n      foo: bar\n"),
            "key `foo` is not allowed",
        ),
        mutant(
            "shell: sh on the mode step",
            Kind::Workflow,
            |t| replace_once(t, "      shell: bash\n", "      shell: sh\n"),
            "only shell: bash",
        ),
        mutant(
            "a fake block scalar hides an if:",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: 100\n      if: |2\n         false\n",
                )
            },
            "block scalar indicator",
        ),
        mutant(
            "a tab in the indentation",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "    \t  timeout-minutes: 100\n",
                )
            },
            "a tab in the indentation",
        ),
        mutant(
            "a second steps: key under the job holding only a failure-only upload",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        path: target/e2e\n        if-no-files-found: warn\n        retention-days: 3\n",
                    "        path: target/e2e\n        if-no-files-found: warn\n        retention-days: 3\n    steps:\n    - name: Upload per-cell logs\n      if: failure()\n      timeout-minutes: 2\n      uses: actions/upload-artifact@v4\n      with:\n        name: e2e-logs-${{ github.run_id }}-${{ github.run_attempt }}\n        path: target/e2e\n        if-no-files-found: warn\n        retention-days: 3\n",
                )
            },
            "duplicate key `jobs.e2e-compare.steps`",
        ),
        mutant(
            "a second on: at the top level",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "\npermissions:\n  contents: read\n",
                    "\non:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n",
                )
            },
            "duplicate key `on`",
        ),
        mutant(
            "a repeated name: in one step",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    - name: Dependencies\n",
                    "    - name: Dependencies\n      name: Dependencies\n",
                )
            },
            "duplicate key `jobs.e2e-compare.steps.-.name`",
        ),
        mutant(
            "a repeated key in a nested mapping that is not a step",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "  cancel-in-progress: false\n",
                    "  cancel-in-progress: false\n  cancel-in-progress: false\n",
                )
            },
            "duplicate key `concurrency.cancel-in-progress`",
        ),
        mutant(
            "a repeated key at an uneven indent four mappings deep",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        type: string\n",
                    "        type: string\n       type: string\n",
                )
            },
            "duplicate key `on.workflow_call.inputs.liteinst2_sha.type`",
        ),
        mutant(
            "BASH_ENV in the workflow env",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "  RUSTFLAGS: -C link-arg=-llzma\n",
                    "  RUSTFLAGS: -C link-arg=-llzma\n  BASH_ENV: stub\n",
                )
            },
            "key `BASH_ENV` is not allowed",
        ),
        mutant(
            "a second job",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "jobs:\n",
                    "jobs:\n  other:\n    runs-on: ubuntu-24.04\n    steps:\n    - run: true\n",
                )
            },
            "key `other` is not allowed",
        ),
        // Line-break forms (CR, NEL, LS, PS), pinned values, YAML forms outside
        // the classifier, the Compare count, and the corpus cap.
        mutant(
            "fake sources and Compare steps inside a trailing block scalar",
            Kind::Workflow,
            |t| {
                let rest = t.strip_prefix("name: E2E compare\n")?;
                let cut = rest.find("    - name: E2E sources as checked out\n")?;
                Some(format!(
                    "{}name: |\n  E2E compare\n{}{}",
                    &rest[..cut],
                    sources_text(),
                    compare_text()
                ))
            },
            "there is no step named Compare",
        ),
        mutant(
            "a lone CR hides defaults: and an if:",
            Kind::Workflow,
            |t| {
                let hidden = replace_once(
                    t,
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\r    defaults:\r      run:\r        shell: true {0}\n",
                )?;
                replace_once(
                    &hidden,
                    "      timeout-minutes: 5\n",
                    "      timeout-minutes: 5\r      if: false\n",
                )
            },
            "a carriage return",
        ),
        mutant(
            "NEL hides an if:",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 5\n",
                    "      timeout-minutes: 5\u{85}      if: false\n",
                )
            },
            "U+0085",
        ),
        mutant(
            "LS hides an if:",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 5\n",
                    "      timeout-minutes: 5\u{2028}      if: false\n",
                )
            },
            "U+2028",
        ),
        mutant(
            "PS hides an if:",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 5\n",
                    "      timeout-minutes: 5\u{2029}      if: false\n",
                )
            },
            "U+2029",
        ),
        mutant(
            "the checkout's ref changed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        ref: ${{ github.event_name == 'pull_request' && 'liteinst-main' || github.sha }}\n",
                    "        ref: some-branch\n",
                )
            },
            "pinned checkout",
        ),
        mutant(
            "RUSTFLAGS changed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "  RUSTFLAGS: -C link-arg=-llzma\n",
                    "  RUSTFLAGS: -C link-arg=-llzma -C opt-level=0\n",
                )
            },
            "`env.RUSTFLAGS` must be exactly",
        ),
        mutant(
            "permissions widened",
            Kind::Workflow,
            |t| replace_once(t, "  contents: read\n", "  contents: write\n"),
            "`permissions.contents` must be exactly",
        ),
        mutant(
            "another runner",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: self-hosted\n",
                )
            },
            "`jobs.e2e-compare.runs-on` must be exactly",
        ),
        mutant(
            "an if: right after a block body ends",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        echo \"e2e-compare mode: $mode\"\n",
                    "        echo \"e2e-compare mode: $mode\"\n      if: false\n",
                )
            },
            "has an if:",
        ),
        mutant(
            "an alias",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: *minutes\n",
                )
            },
            "an anchor or alias",
        ),
        mutant(
            "a tag",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 100\n",
                    "      timeout-minutes: !!int 100\n",
                )
            },
            "a YAML tag",
        ),
        mutant(
            "a document marker",
            Kind::Workflow,
            |t| Some(format!("---\n{t}")),
            "a YAML document marker",
        ),
        mutant(
            "a flow sequence holding a mapping",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    branches: [liteinst-main]\n",
                    "    branches: [liteinst-main, {x: y}]\n",
                )
            },
            "a flow sequence holding more",
        ),
        mutant(
            "no space after a colon",
            Kind::Workflow,
            |t| replace_once(t, "      id: mode\n", "      id:mode\n"),
            "no space after",
        ),
        mutant(
            "a trailing space after a colon",
            Kind::Workflow,
            |t| replace_once(t, "      id: mode\n", "      id: \n"),
            "trailing space after",
        ),
        mutant(
            "a key that is not plain",
            Kind::Workflow,
            |t| replace_once(t, "      id: mode\n", "      id.x: mode\n"),
            "is not a plain key",
        ),
        mutant(
            "a bare scalar line",
            Kind::Workflow,
            |t| replace_once(t, "      id: mode\n", "      id: mode\n      just text\n"),
            "not a key, a list item",
        ),
        mutant(
            "two Compare steps",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    &format!("{COMPARE_RUN}\n"),
                    &format!("{COMPARE_RUN}\n{}", compare_text()),
                )
            },
            "2 steps are named Compare",
        ),
        mutant(
            "no Compare step",
            Kind::Workflow,
            |t| replace_once(t, "    - name: Compare\n", "    - name: Comparison\n"),
            "there is no step named Compare",
        ),
        mutant(
            "an unclosed quoted value",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    - cron: \"41 5 * * 2\"\n",
                    "    - cron: \"41 5 * * 2\n",
                )
            },
            "a quoted value that does not close",
        ),
        mutant(
            "an unclosed flow sequence",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    branches: [liteinst-main]\n",
                    "    branches: [liteinst-main\n",
                )
            },
            "a flow sequence that does not close",
        ),
        mutant(
            "an empty corpus",
            Kind::Corpus,
            |t| replace_once(t, "alpha\t/bin/true\n", ""),
            "no cells",
        ),
        // Quote and flow-sequence closure, permissions and pinned env keys,
        // and a missing corpus.
        mutant(
            "a single-quoted value left open by ''",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "  group: e2e-compare-${{ github.event_name }}-${{ github.sha }}\n",
                    "  group: 'e2e-compare-${{ github.event_name }}-${{ github.sha }}''\n",
                )
            },
            "a quoted value that does not close",
        ),
        mutant(
            "a quote inside a flow sequence",
            Kind::Workflow,
            |t| replace_once(t, "        type: string\n", "        type: [string, 'x]\n"),
            "a flow sequence holding more",
        ),
        mutant(
            "a second permissions block",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "env:\n  CARGO_TERM_COLOR: always\n",
                    "permissions:\n  contents: write\n\nenv:\n  CARGO_TERM_COLOR: always\n",
                )
            },
            "`permissions.contents` occurs 2 times",
        ),
        mutant(
            "a CR on one line only",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 5\n",
                    "      timeout-minutes: 5\r\n",
                )
            },
            "a carriage return",
        ),
        mutant(
            "a pinned env key missing",
            Kind::Workflow,
            |t| replace_once(t, "  RUSTFLAGS: -C link-arg=-llzma\n", ""),
            "`env.RUSTFLAGS` is missing",
        ),
        mutant(
            "a missing corpus",
            Kind::CorpusMissing,
            |_| Some(String::new()),
            "missing, so no cell can be counted",
        ),
        // Comments and quotes inside flow sequences, and the exact Mode and
        // LiteInst pins.
        mutant(
            "a space-# comment inside a flow sequence",
            Kind::Workflow,
            |t| replace_once(t, "        type: string\n", "        type: [string #]\n"),
            "a flow sequence holding more",
        ),
        mutant(
            "a tab-# comment inside a flow sequence",
            Kind::Workflow,
            |t| replace_once(t, "        type: string\n", "        type: [string,\t#]\n"),
            "a flow sequence holding more",
        ),
        mutant(
            "a double quote inside a flow sequence",
            Kind::Workflow,
            |t| replace_once(t, "        type: string\n", "        type: [string, \"x]\n"),
            "a flow sequence holding more",
        ),
        mutant(
            "the LiteInst step's MODE fixed to reverie",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        MODE: ${{ steps.mode.outputs.mode }}\n",
                    "        MODE: reverie\n",
                )
            },
            "pinned LiteInst step",
        ),
        mutant(
            "the Mode step's id removed",
            Kind::Workflow,
            |t| replace_once(t, "      id: mode\n", ""),
            "pinned Mode step",
        ),
        mutant(
            "the Mode step's LITEINST2_SHA fixed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        LITEINST2_SHA: ${{ inputs.liteinst2_sha }}\n      run: |\n        set -euo pipefail\n        # Total over the event",
                    "        LITEINST2_SHA: 0123456789abcdef0123456789abcdef01234567\n      run: |\n        set -euo pipefail\n        # Total over the event",
                )
            },
            "pinned Mode step",
        ),
        mutant(
            "the LiteInst step's LITEINST2_SHA fixed",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "        MODE: ${{ steps.mode.outputs.mode }}\n        LITEINST2_SHA: ${{ inputs.liteinst2_sha }}\n",
                    "        MODE: ${{ steps.mode.outputs.mode }}\n        LITEINST2_SHA: 0123456789abcdef0123456789abcdef01234567\n",
                )
            },
            "pinned LiteInst step",
        ),
        // A value that begins with more white space after `KEY: `, which YAML
        // reads as a value form the classifier would otherwise never see (the
        // comparison only inside a `name:  |` block first), and the other
        // bytes that could pass for white space there.
        mutant(
            "the comparison only inside a `name:  |` block",
            Kind::Workflow,
            |t| {
                let rest = t.strip_prefix("name: E2E compare\n")?;
                let cut = rest.find("    - name: Compare\n")?;
                Some(format!(
                    "{}name:  |\n jobs:\n   e2e-compare:\n    steps:\n{}",
                    &rest[..cut],
                    compare_text()
                ))
            },
            "more than one space, or a tab, after `name:`",
        ),
        mutant(
            "a tab before a block indicator",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      run: |\n        sudo apt-get update\n",
                    "      run: \t|\n        sudo apt-get update\n",
                )
            },
            "more than one space, or a tab, after `run:`",
        ),
        mutant(
            "a quoted value left open after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 4\n",
                    "      timeout-minutes:  \"4\n",
                )
            },
            "more than one space, or a tab, after `timeout-minutes:`",
        ),
        mutant(
            "a flow mapping after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 4\n",
                    "      timeout-minutes:  {a: b}\n",
                )
            },
            "more than one space, or a tab, after `timeout-minutes:`",
        ),
        mutant(
            "an anchor after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 3\n",
                    "      timeout-minutes:  &a 3\n",
                )
            },
            "more than one space, or a tab, after `timeout-minutes:`",
        ),
        mutant(
            "a flow sequence left open after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    branches: [liteinst-main]\n",
                    "    branches:  [liteinst-main,\n",
                )
            },
            "more than one space, or a tab, after `branches:`",
        ),
        mutant(
            "a folded block indicator after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "    - name: Rust toolchain\n      timeout-minutes: 3\n      run: |\n",
                    "    - name: Rust toolchain\n      timeout-minutes: 3\n      run:  >\n",
                )
            },
            "more than one space, or a tab, after `run:`",
        ),
        mutant(
            "an alias after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 2\n",
                    "      timeout-minutes:  *a\n",
                )
            },
            "more than one space, or a tab, after `timeout-minutes:`",
        ),
        mutant(
            "a tag after two spaces",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      timeout-minutes: 5\n",
                    "      timeout-minutes:  !!int 5\n",
                )
            },
            "more than one space, or a tab, after `timeout-minutes:`",
        ),
        mutant(
            "NBSP before a block indicator",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      run: |\n        sudo apt-get update\n",
                    "      run: \u{a0}|\n        sudo apt-get update\n",
                )
            },
            "a non-ASCII character U+00A0",
        ),
        mutant(
            "VT before a block indicator",
            Kind::Workflow,
            |t| {
                replace_once(
                    t,
                    "      run: |\n        sudo apt-get update\n",
                    "      run: \u{b}|\n        sudo apt-get update\n",
                )
            },
            "a control character U+000B",
        ),
        // Facts read from the classified keys, never from raw lines, so text
        // inside a block scalar cannot supply them.
        mutant(
            "the push trigger only inside a `name: |` block",
            Kind::Workflow,
            |t| {
                let t = replace_once(t, "  push:\n    branches: [liteinst-main]\n", "")?;
                replace_once(
                    &t,
                    "name: E2E compare\n",
                    "name: |\n  E2E compare\n  push:\n    branches: [liteinst-main]\n",
                )
            },
            "the push trigger on liteinst-main is missing",
        ),
        mutant(
            "the workflow_call trigger only inside a `name: |` block",
            Kind::Workflow,
            |t| {
                let t = replace_once(t, "  workflow_call:\n", "")?;
                replace_once(
                    &t,
                    "name: E2E compare\n",
                    "name: |\n  E2E compare\n  workflow_call:\n",
                )
            },
            "the workflow_call trigger is missing",
        ),
        mutant(
            "an upload named only inside a run body",
            Kind::Workflow,
            |t| {
                let t = replace_once(
                    t,
                    "    - name: Dependencies\n      timeout-minutes: 4\n",
                    "    - name: Dependencies\n      if: failure()\n      timeout-minutes: 4\n",
                )?;
                replace_once(
                    &t,
                    "        sudo apt-get update\n",
                    "        sudo apt-get update\n        uses: actions/upload-artifact@v4\n",
                )
            },
            "step `Dependencies` has an if:",
        ),
        mutant(
            "`*` signature",
            Kind::Ledger,
            |t| replace_once(t, "write=5 -> write=6", "*"),
            "`*` in the signature",
        ),
        mutant(
            "`*` cell",
            Kind::Ledger,
            |t| replace_once(t, "alpha\t", "*\t"),
            "`*` in the cell",
        ),
        mutant(
            "` || ` alternatives",
            Kind::Ledger,
            |t| {
                replace_once(
                    t,
                    "write=5 -> write=6",
                    "write=5 -> write=6 || write=5 -> write=7",
                )
            },
            "` || `",
        ),
        mutant(
            "a native row",
            Kind::Ledger,
            |t| replace_once(t, "beta\tliteinst", "beta\tnative"),
            "`native` row",
        ),
        mutant(
            "a refused verdict",
            Kind::Ledger,
            |t| replace_once(t, "beta\tliteinst\tmismatch", "beta\tliteinst\trefused"),
            "not `mismatch`",
        ),
        mutant(
            "a backend outside the three",
            Kind::Ledger,
            |t| replace_once(t, "beta\tliteinst", "beta\tkvm"),
            "backend kvm",
        ),
        mutant(
            "70 rows",
            Kind::Ledger,
            |t| {
                let mut text = t.to_owned();
                for n in 0..68 {
                    text.push_str(&format!(
                    "cell{n}\tptrace\tmismatch\tread=1 -> read=2\thttps://github.com/rrnewton/hermit/issues/4485\n"
                ));
                }
                Some(text)
            },
            "70 rows",
        ),
    ]
}

fn self_test() -> ExitCode {
    let mut failures = Vec::new();
    // The positive cases: the pinned workflow, the synthetic ledger and the
    // synthetic corpus pass.
    if let Err(problem) = byte_exact(PINNED, PINNED) {
        failures.push(format!("the pin does not match itself: {problem}"));
    }
    for problem in structural(PINNED) {
        failures.push(format!(
            "the pinned workflow fails its structural checks: {problem}"
        ));
    }
    for problem in lint_ledger("synthetic", SYNTHETIC_LEDGER, SYNTHETIC_CELLS) {
        failures.push(format!("the synthetic ledger fails the lint: {problem}"));
    }
    for problem in corpus_check("synthetic corpus", Some(SYNTHETIC_CORPUS)).1 {
        failures.push(format!("the synthetic corpus fails its check: {problem}"));
    }
    let table = mutants();
    if table.len() != SELF_TEST_CASES {
        failures.push(format!(
            "the mutant table has {} cases; the pinned count is {SELF_TEST_CASES}",
            table.len()
        ));
    }
    for (name, kind, mutate, phrase) in &table {
        let base = match kind {
            Kind::Workflow => PINNED,
            Kind::Ledger => SYNTHETIC_LEDGER,
            Kind::Corpus | Kind::CorpusMissing => SYNTHETIC_CORPUS,
        };
        let Some(changed) = mutate(base).filter(|changed| changed.as_str() != base) else {
            failures.push(format!("mutant `{name}` does not apply"));
            continue;
        };
        let problems = match kind {
            Kind::Workflow => {
                // Against the real pin the byte comparison refuses it; with
                // the pin re-set to the mutant, the structural checks must.
                if byte_exact(&changed, PINNED).is_ok() {
                    failures.push(format!("mutant `{name}` passes the byte comparison"));
                }
                if byte_exact(&changed, &changed).is_err() {
                    failures.push(format!("mutant `{name}` does not match itself"));
                }
                structural(&changed)
            }
            Kind::Ledger => lint_ledger("synthetic", &changed, SYNTHETIC_CELLS),
            Kind::Corpus => corpus_check("synthetic corpus", Some(&changed)).1,
            Kind::CorpusMissing => corpus_check("synthetic corpus", None).1,
        };
        if !problems.iter().any(|problem| problem.contains(*phrase)) {
            failures.push(format!(
                "mutant `{name}` is not refused by name (wanted `{phrase}`; got {problems:?})"
            ));
        }
    }
    if failures.is_empty() {
        println!("check-e2e-compare self-test: {} cases", table.len());
        ExitCode::SUCCESS
    } else {
        for failure in &failures {
            eprintln!("check-e2e-compare self-test: FAIL: {failure}");
        }
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--self-test" => self_test(),
        [] => check(Path::new(".")),
        [root] if !root.starts_with('-') => check(Path::new(root)),
        _ => {
            eprintln!("usage: check-e2e-compare.rs [ROOT] | check-e2e-compare.rs --self-test");
            ExitCode::from(2)
        }
    }
}

/// The pinned text of .github/workflows/e2e-compare.yml, byte for byte.
const PINNED: &str = r###"name: E2E compare

# The cross-backend end-to-end comparison (reverie-examples/e2e/README.md) on
# a GitHub-hosted Ubuntu runner: native Linux against ptrace, LiteInst and
# in-guest-trap, judged against the ledger measured for the runner's
# environment. Every corpus cell must be compared on all three backends
# (--require-compared). Without a ledger for the environment the run fails by
# name (NO LEDGER) and uploads the rows it measured; a cell that a backend
# refuses, or that is otherwise not compared, also fails it by name
# (COVERAGE), after the rows are written. It never passes unjudged. The step
# just before the comparison fails the run if any file under
# reverie-examples/e2e differs from the checked-out commit, which catches an
# earlier step's accidental change; an earlier step that commits its change
# or redirects git is guarded only by review of this pinned file.
#
# It runs for every push to liteinst-main, weekly, on dispatch, and for every
# rrnewton/liteinst2 pull request, whose workflow calls this one with the
# pull request's head commit (liteinst2_sha): Reverie's liteinst-main is then
# built against that LiteInst. Best-effort signal only: it never gates a
# Reverie merge and must never become a required status check. For a
# liteinst2 pull request, this job's conclusion at the pull request's exact
# head commit is the merge evidence; a skipped, absent or cancelled run is no
# verdict.
#
# scripts/check-e2e-compare.rs pins this file byte for byte and checks its
# structure (validate.sh runs it): change the two together.
on:
  push:
    branches: [liteinst-main]
  schedule:
    - cron: "41 5 * * 2"
  workflow_dispatch:
  workflow_call:
    inputs:
      liteinst2_sha:
        description: The rrnewton/liteinst2 commit a pull request compares.
        type: string
        required: true

permissions:
  contents: read

concurrency:
  group: e2e-compare-${{ github.event_name }}-${{ github.sha }}
  cancel-in-progress: false

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -C link-arg=-llzma

jobs:
  e2e-compare:
    name: Cross-backend e2e (GitHub-hosted)
    runs-on: ubuntu-24.04
    # The steps before the comparison are bounded at 16 minutes together,
    # the comparison at 100 and the two failure uploads at 3: 119 of 120, so
    # a comparison that times out still uploads its evidence.
    timeout-minutes: 120

    steps:
    - uses: actions/checkout@v4
      timeout-minutes: 2
      with:
        repository: ${{ github.event_name == 'pull_request' && 'rrnewton/reverie' || github.repository }}
        ref: ${{ github.event_name == 'pull_request' && 'liteinst-main' || github.sha }}
        submodules: false
    - name: Mode
      id: mode
      timeout-minutes: 1
      shell: bash
      env:
        LITEINST2_SHA: ${{ inputs.liteinst2_sha }}
      run: |
        set -euo pipefail
        # Total over the event and the input, before anything is built.
        case $GITHUB_EVENT_NAME in
          push | schedule | workflow_dispatch) mode=reverie ;;
          pull_request) mode=liteinst2-pr ;;
          *)
            printf '::error::e2e-compare does not run for event %q\n' "$GITHUB_EVENT_NAME"
            exit 1
            ;;
        esac
        if [[ $mode == reverie && -n $LITEINST2_SHA ]]; then
          printf '::error::liteinst2_sha given outside a liteinst2 pull request call: %q\n' "$LITEINST2_SHA"
          exit 1
        fi
        if [[ $mode == liteinst2-pr && ! $LITEINST2_SHA =~ ^[0-9a-f]{40}$ ]]; then
          printf '::error::liteinst2_sha missing or not a 40-hex commit: %q\n' "$LITEINST2_SHA"
          exit 1
        fi
        echo "mode=$mode" >> "$GITHUB_OUTPUT"
        echo "e2e-compare mode: $mode"
    - name: Dependencies
      timeout-minutes: 4
      # Refresh the index first: the runner image's index can name package
      # versions the mirror no longer serves, and install then fails with 404.
      run: |
        sudo apt-get update
        sudo apt-get install -y libunwind-dev liblzma-dev cmake zlib1g-dev
    - name: Rust toolchain
      timeout-minutes: 3
      run: |
        if ! command -v rustup >/dev/null 2>&1; then
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
          export PATH="$HOME/.cargo/bin:$PATH"
          echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
        fi
        channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
        rustup toolchain install "$channel" --profile minimal
        rustc --version
    - name: LiteInst source and identity
      timeout-minutes: 5
      shell: bash
      env:
        MODE: ${{ steps.mode.outputs.mode }}
        LITEINST2_SHA: ${{ inputs.liteinst2_sha }}
      run: |
        set -euo pipefail
        {
          echo "## e2e-compare"
          echo "- mode: $MODE"
          echo "- reverie: $(git rev-parse HEAD)"
        } >> "$GITHUB_STEP_SUMMARY"
        crates=(liteinst liteinst-aarch64 liteinst-aarch64-patch)
        declare -A want
        if [[ $MODE == liteinst2-pr ]]; then
          # Reverie's liteinst-main, built against the pull request's LiteInst.
          src="$RUNNER_TEMP/liteinst2"
          git init -q "$src"
          git -C "$src" fetch -q --depth 1 https://github.com/rrnewton/liteinst2 "$LITEINST2_SHA"
          git -C "$src" checkout -q --detach FETCH_HEAD
          got=$(git -C "$src" rev-parse HEAD)
          if [[ $got != "$LITEINST2_SHA" ]]; then
            echo "::error::the liteinst2 checkout is $got, not $LITEINST2_SHA"
            exit 1
          fi
          echo "- liteinst2: $got" >> "$GITHUB_STEP_SUMMARY"
          declare -A dir=(
            [liteinst]="$src"
            [liteinst-aarch64]="$src/crates/liteinst-aarch64"
            [liteinst-aarch64-patch]="$src/crates/liteinst-aarch64-patch"
          )
          for crate in "${crates[@]}"; do
            if ! grep -qx "name = \"$crate\"" "${dir[$crate]}/Cargo.toml"; then
              echo "::error::liteinst2 $got has no package $crate in ${dir[$crate]}"
              exit 1
            fi
            want[$crate]="path ${dir[$crate]}"
          done
          config="${CARGO_HOME:-$HOME/.cargo}/config.toml"
          if [[ -e $config ]]; then
            echo "::error::$config exists; refusing to replace it with the liteinst2 patch"
            exit 1
          fi
          mkdir -p "$(dirname "$config")"
          {
            echo '[patch.crates-io]'
            echo "liteinst = { path = \"${dir[liteinst]}\" }"
            echo '[patch."https://github.com/rrnewton/liteinst2"]'
            echo "liteinst-aarch64 = { path = \"${dir[liteinst-aarch64]}\" }"
            echo "liteinst-aarch64-patch = { path = \"${dir[liteinst-aarch64-patch]}\" }"
          } > "$config"
          cargo update -p liteinst -p liteinst-aarch64 -p liteinst-aarch64-patch
        else
          # The sources the manifest pins, never the lock (which cargo tree
          # --locked only echoes): liteinst from crates.io at 0.2.x, and the
          # two liteinst2 crates as git sources at the manifest's one rev.
          revs=$(grep -E '^liteinst-aarch64(-patch)? = \{.*git = "https://github\.com/rrnewton/liteinst2"' reverie-liteinst/Cargo.toml | grep -oE 'rev = "[0-9a-f]{40}"' | sort -u || true)
          pins=$(printf '%s\n' "$revs" | grep -c . || true)
          if [[ $pins != 1 ]]; then
            echo "::error::reverie-liteinst/Cargo.toml does not pin one liteinst2 rev: ${revs:-none}"
            exit 1
          fi
          rev=${revs#rev = \"}
          rev=${rev%\"}
          want[liteinst]='registry ^liteinst v0\.2\.[0-9]+$'
          for crate in liteinst-aarch64 liteinst-aarch64-patch; do
            want[$crate]="git ^$crate v[0-9][^ ]* \\(https://github\\.com/rrnewton/liteinst2\\?rev=$rev#${rev:0:8}[0-9a-f]*\\)\$"
          done
        fi
        # The identity check, in both modes and never skipped: each crate
        # resolves to the source its mode requires, and any other source
        # (a path in reverie mode, the registry in pull request mode) fails.
        for crate in "${crates[@]}"; do
          if ! tree=$(cargo tree --locked --workspace --target x86_64-unknown-linux-gnu -i "$crate" --depth 0); then
            echo "::error::cargo tree -i $crate failed"
            exit 1
          fi
          line=${tree%%$'\n'*}
          kind=${want[$crate]%% *}
          expected=${want[$crate]#* }
          ok=0
          if [[ $kind == path ]]; then
            [[ $line == "$crate v"*" ($expected)" ]] && ok=1
          else
            [[ $line =~ $expected ]] && ok=1
          fi
          echo "- $crate: $line" >> "$GITHUB_STEP_SUMMARY"
          if ((ok == 0)); then
            echo "::error::$crate resolves to '$line', not the $kind source mode $MODE requires ($expected)"
            exit 1
          fi
        done
    - name: E2E sources as checked out
      timeout-minutes: 1
      shell: bash
      run: |
        set -euo pipefail
        # run.sh, compare.rs, the corpus and the ledgers must match the
        # checked-out commit when the comparison starts. This catches an
        # earlier step's accidental change, addition or removal; a step that
        # commits its change or redirects git is caught only by review.
        git diff --exit-code HEAD -- reverie-examples/e2e
        changed=$(git status --porcelain --untracked-files=all --ignored -- reverie-examples/e2e)
        if [[ -n $changed ]]; then
          printf '::error::files changed under reverie-examples/e2e before the comparison:\n%s\n' "$changed"
          exit 1
        fi
    - name: Compare
      timeout-minutes: 100
      run: reverie-examples/e2e/run.sh --backends ptrace,liteinst,in-guest-trap --require-compared ptrace,liteinst,in-guest-trap --write-ledger "$RUNNER_TEMP/e2e-rows.tsv"
    - name: Upload measured rows
      if: failure()
      timeout-minutes: 1
      uses: actions/upload-artifact@v4
      with:
        name: e2e-rows-${{ github.run_id }}-${{ github.run_attempt }}
        path: ${{ runner.temp }}/e2e-rows.tsv
        if-no-files-found: warn
        retention-days: 3
    - name: Upload per-cell logs
      if: failure()
      timeout-minutes: 2
      uses: actions/upload-artifact@v4
      with:
        name: e2e-logs-${{ github.run_id }}-${{ github.run_attempt }}
        path: target/e2e
        if-no-files-found: warn
        retention-days: 3
"###;
