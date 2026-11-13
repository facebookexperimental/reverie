#!/usr/bin/env -S rust-script --force
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
//! Refuse a change that removes or modifies recorded content-catalogue history.
//!
//! `reverie-liteinst-artifact/src/lib.rs` keeps three tables in its test module:
//! `CONTENT_REVERIE_CATALOG_BINDINGS` (every catalogue binding since that list
//! was added), `CONTENT_REVERIE_CATALOG_BINDING_SEALS` (digests over prefixes of
//! it) and the `rejected_prior` list of `content_source_identity_controls`. The
//! crate test checks one revision against itself, so an edit that rewrites a
//! table and its seals together passes there. This script compares the change
//! with an independent preceding state, its BASE, and requires every BASE row of
//! each table to be present, unchanged, at HEAD. Rows may be added anywhere.
//!
//! BASE is `--base REV`, else the merge-base of HEAD and the landing branch:
//! `origin/$REVERIE_LANDING_BRANCH`, or the branch `ci/landing-branches.env`
//! names, as validate.sh resolves it. Without a resolvable BASE the check fails
//! rather than skips. HEAD is the working tree's file, or `--head REV`.
//! `--base-file`/`--head-file` compare two files without git.
//!
//! A table BASE does not have yet (any BASE before the history tables existed)
//! is reported and not compared. It counts as absent only when none of its
//! identifiers occurs in the file at all: a table that is mentioned but whose
//! declaration is not in a recognized form, or that is declared more than once,
//! is an error rather than an exemption. A table HEAD lacks, or one that parses
//! to no rows where BASE had rows, is refused. The regression controls below run
//! before every check.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::process::ExitCode;

const LIB: &str = "reverie-liteinst-artifact/src/lib.rs";

const HELP: &str = "Usage: check-catalog-bindings-append-only.rs [--base REV | --base-file PATH] \
[--head REV | --head-file PATH] [--self-test]\n\
\n\
Refuse removed or modified rows of the content-catalogue history tables in\n\
reverie-liteinst-artifact/src/lib.rs (BINDINGS, BINDING_SEALS, rejected_prior)\n\
between BASE and HEAD. BASE defaults to the merge-base of HEAD and\n\
origin/<landing branch>; HEAD defaults to the working tree. --self-test runs\n\
only the regression controls. Exit 0 accepted, 1 refused, 2 usage or\n\
unresolvable input.\n";

/// One history table: its name, the line that opens it, the text that closes
/// it, how many fields each row has, and the identifiers whose presence means
/// the table exists in some form.
struct Table {
    name: &'static str,
    opens: &'static [&'static str],
    closes: &'static str,
    arity: usize,
    markers: &'static [&'static str],
}

const TABLES: [Table; 3] = [
    Table {
        name: "CONTENT_REVERIE_CATALOG_BINDINGS",
        opens: &["    const CONTENT_REVERIE_CATALOG_BINDINGS: &[(&str, u64, &str)] = &[\n"],
        closes: "\n    ];\n",
        arity: 3,
        markers: &["CONTENT_REVERIE_CATALOG_BINDINGS"],
    },
    Table {
        name: "CONTENT_REVERIE_CATALOG_BINDING_SEALS",
        opens: &["    const CONTENT_REVERIE_CATALOG_BINDING_SEALS: &[(usize, &str)] = &["],
        closes: "];\n",
        arity: 2,
        markers: &["CONTENT_REVERIE_CATALOG_BINDING_SEALS"],
    },
    Table {
        name: "rejected_prior",
        // The list was an inline loop literal before the history tables existed.
        opens: &[
            "        let rejected_prior = [\n",
            "        for (relative, old_size, old_digest) in [\n",
        ],
        closes: "\n        ]",
        arity: 3,
        // The inline loop never named the list; its loop variable marks it.
        markers: &["rejected_prior", "old_digest"],
    },
];

/// Whether `word` occurs in `source` as a whole identifier.
fn mentions(source: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    source.match_indices(word).any(|(at, _)| {
        !source[..at].chars().next_back().is_some_and(is_ident)
            && !source[at + word.len()..]
                .chars()
                .next()
                .is_some_and(is_ident)
    })
}

/// The rows of `table` in `source`, each as its fields' text, or `None` when the
/// table is absent: none of its markers occurs anywhere in `source`.
fn rows(source: &str, table: &Table) -> Result<Option<Vec<Vec<String>>>, String> {
    let declarations: Vec<(usize, &str)> = table
        .opens
        .iter()
        .flat_map(|open| source.match_indices(open).map(move |(at, _)| (at, *open)))
        .collect();
    let (start, open) = match declarations[..] {
        [declaration] => declaration,
        [] if table.markers.iter().any(|marker| mentions(source, marker)) => {
            return Err(format!(
                "{} is mentioned but has no declaration in a recognized form; \
                 refusing to treat it as absent",
                table.name
            ));
        }
        [] => return Ok(None),
        _ => {
            return Err(format!(
                "{} is declared {} times",
                table.name,
                declarations.len()
            ));
        }
    };
    let body_start = start + open.len();
    // An empty table's closing line shares the newline that ends its opening line.
    let search_from = body_start - usize::from(open.ends_with('\n'));
    let body_end = search_from
        + source[search_from..]
            .find(table.closes)
            .ok_or_else(|| format!("{}: no closing {:?}", table.name, table.closes))?;
    let fields = tokens(&source[body_start..body_end.max(body_start)])
        .map_err(|error| format!("{}: {error}", table.name))?;
    if fields.len() % table.arity != 0 {
        return Err(format!(
            "{}: {} fields do not form rows of {}",
            table.name,
            fields.len(),
            table.arity
        ));
    }
    Ok(Some(
        fields.chunks(table.arity).map(<[String]>::to_vec).collect(),
    ))
}

/// The string and integer literals of a table body, in order. Anything else
/// besides punctuation, whitespace and comments is refused.
fn tokens(body: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = body.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => {
                let mut text = String::new();
                loop {
                    match chars.next() {
                        Some((_, '"')) => break,
                        Some((_, '\\')) => return Err(format!("escape in a literal at {at}")),
                        Some((_, ch)) => text.push(ch),
                        None => return Err(format!("unterminated literal at {at}")),
                    }
                }
                out.push(format!("\"{text}\""));
            }
            '0'..='9' => {
                let mut text = c.to_string();
                while let Some(&(_, d)) = chars.peek() {
                    if !d.is_ascii_digit() {
                        break;
                    }
                    text.push(d);
                    chars.next();
                }
                out.push(text);
            }
            '/' if chars.peek().map(|&(_, ch)| ch) == Some('/') => {
                for (_, ch) in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
            }
            '(' | ')' | ',' | ' ' | '\n' => {}
            other => return Err(format!("unexpected {other:?} at {at}")),
        }
    }
    Ok(out)
}

/// Every refusal for BASE against HEAD, and the notes for tables BASE lacks.
fn compare(base: &str, head: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let mut refusals = Vec::new();
    let mut notes = Vec::new();
    for table in &TABLES {
        let base_rows = rows(base, table).map_err(|error| format!("BASE {error}"))?;
        let head_rows = rows(head, table).map_err(|error| format!("HEAD {error}"))?;
        match (base_rows, head_rows) {
            (_, None) => refusals.push(format!("HEAD has no {} table", table.name)),
            (None, Some(head_rows)) => notes.push(format!(
                "{}: BASE has no such table; HEAD's {} rows are new",
                table.name,
                head_rows.len()
            )),
            (Some(base_rows), Some(head_rows)) => {
                if !base_rows.is_empty() && head_rows.is_empty() {
                    refusals.push(format!("{} parses to no rows at HEAD", table.name));
                }
                for row in &base_rows {
                    if !head_rows.contains(row) {
                        refusals.push(format!(
                            "{} row ({}) was removed or modified",
                            table.name,
                            row.join(", ")
                        ));
                    }
                }
                notes.push(format!(
                    "{}: {} BASE rows retained, {} rows at HEAD",
                    table.name,
                    base_rows.len(),
                    head_rows.len()
                ));
            }
        }
    }
    if rows(head, &TABLES[0])?.is_some_and(|rows| rows.is_empty()) {
        refusals.push("CONTENT_REVERIE_CATALOG_BINDINGS is empty at HEAD".to_owned());
    }
    Ok((refusals, notes))
}

fn git(args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .map_err(|error| format!("git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("git {}: output is not UTF-8", args.join(" ")))
}

/// The landing branch, as validate.sh resolves it: the environment, else the
/// tracked ci/landing-branches.env.
fn landing_branch(root: &str) -> Result<String, String> {
    if let Ok(branch) = env::var("REVERIE_LANDING_BRANCH") {
        return Ok(branch);
    }
    let file = Path::new(root).join("ci/landing-branches.env");
    let text = fs::read_to_string(&file).map_err(|error| format!("{}: {error}", file.display()))?;
    text.lines()
        .find_map(|line| line.strip_prefix("REVERIE_LANDING_BRANCH="))
        .filter(|branch| !branch.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{} names no REVERIE_LANDING_BRANCH", file.display()))
}

fn regression_controls() -> Result<(), String> {
    // No line continuation here: it would also strip the indentation the tables are matched on.
    let base = "
    const CONTENT_REVERIE_CATALOG_BINDINGS: &[(&str, u64, &str)] = &[
        (
            \"a.rs\",
            1,
            \"11\",
        ),
        (
            \"a.rs\",
            2,
            \"22\",
        ),
    ];
    const CONTENT_REVERIE_CATALOG_BINDING_SEALS: &[(usize, &str)] = &[(2, \"s2\")];
        let rejected_prior = [
            (
                \"a.rs\",
                1,
                \"11\",
            ),
            (
                \"z.rs\",
                9,
                \"99\",
            ),
        ];
";
    let check = |head: &str| compare(base, head).map(|(refusals, _)| refusals);
    // Unchanged: accepted.
    if !check(base)?.is_empty() {
        return Err("control: an unchanged revision was refused".into());
    }
    // Appending a binding, a seal and a rejection: accepted.
    let appended = base
        .replace(
            "            \"22\",\n        ),\n    ];",
            "            \"22\",\n        ),\n        (\n            \"b.rs\",\n            3,\n            \"33\",\n        ),\n    ];",
        )
        .replace("&[(2, \"s2\")]", "&[(2, \"s2\"), (3, \"s3\")]");
    if !check(&appended)?.is_empty() {
        return Err("control: an append was refused".into());
    }
    // The review counterexample: the old tuple deleted from BOTH the bindings and
    // rejected_prior. Refused.
    let deleted = base
        .replacen("        (\n            \"a.rs\",\n            1,\n            \"11\",\n        ),\n", "", 1)
        .replace("            (\n                \"a.rs\",\n                1,\n                \"11\",\n            ),\n", "");
    let refusals = check(&deleted)?;
    if refusals.len() != 2
        || !refusals
            .iter()
            .all(|r| r.contains("(\"a.rs\", 1, \"11\") was removed"))
    {
        return Err(format!(
            "control: deleting from both tables gave {refusals:?}"
        ));
    }
    // An emptied table: refused, not an input error.
    let emptied = deleted.replace(
        "            (\n                \"z.rs\",\n                9,\n                \"99\",\n            ),\n",
        "",
    );
    if !check(&emptied)?
        .iter()
        .any(|r| r.contains("rejected_prior parses to no rows"))
    {
        return Err("control: an emptied rejected_prior was accepted".into());
    }
    // A modified seal: refused.
    if check(&base.replace("\"s2\"", "\"t2\""))?.is_empty() {
        return Err("control: a modified seal was accepted".into());
    }
    // A HEAD without the bindings table: refused.
    if check(&base.replace("CONTENT_REVERIE_CATALOG_BINDINGS:", "RENAMED:"))?.is_empty() {
        return Err("control: a missing table was accepted".into());
    }
    // A BASE whose tables are present but differently spelled: an error, never
    // an exemption, even against a HEAD that deletes their rows.
    let respaced = base
        .replace(
            "const CONTENT_REVERIE_CATALOG_BINDINGS",
            "const  CONTENT_REVERIE_CATALOG_BINDINGS",
        )
        .replace(
            "const CONTENT_REVERIE_CATALOG_BINDING_SEALS",
            "const  CONTENT_REVERIE_CATALOG_BINDING_SEALS",
        )
        .replace("let rejected_prior", "let  rejected_prior");
    if compare(&respaced, &deleted).is_ok() {
        return Err("control: a differently spelled BASE was exempted".into());
    }
    // A table declared twice in BASE: an error.
    if compare(&format!("{base}{base}"), base).is_ok() {
        return Err("control: a doubly declared BASE was accepted".into());
    }
    // A BASE from before the history tables: only rejected_prior compared.
    let old_base = "        for (relative, old_size, old_digest) in [\n            (\n                \"a.rs\",\n                1,\n                \"11\",\n            ),\n        ] {\n";
    let (refusals, notes) = compare(old_base, base)?;
    if !refusals.is_empty()
        || notes
            .iter()
            .filter(|n| n.contains("BASE has no such table"))
            .count()
            != 2
    {
        return Err(format!(
            "control: an old BASE gave {refusals:?} / {notes:?}"
        ));
    }
    Ok(())
}

fn run() -> Result<bool, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut base_rev = None;
    let mut base_file = None;
    let mut head_rev = None;
    let mut head_file = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--base" => base_rev = Some(value()?),
            "--base-file" => base_file = Some(value()?),
            "--head" => head_rev = Some(value()?),
            "--head-file" => head_file = Some(value()?),
            "--self-test" => {
                regression_controls()?;
                println!("check-catalog-bindings-append-only: regression controls passed");
                return Ok(true);
            }
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(true);
            }
            other => return Err(format!("unknown argument {other:?}\n{HELP}")),
        }
    }
    regression_controls()?;
    let root = match (&base_file, &head_file) {
        (Some(_), Some(_)) => String::new(),
        _ => git(&["rev-parse", "--show-toplevel"])?.trim().to_owned(),
    };
    let (base, base_name) = match (base_file, base_rev) {
        (Some(path), None) => (
            fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?,
            path,
        ),
        (None, Some(rev)) => (git(&["show", &format!("{rev}:{LIB}")])?, rev),
        (None, None) => {
            let landing = format!("origin/{}", landing_branch(&root)?);
            let merge_base = git(&["merge-base", "HEAD", &landing]).map_err(|error| {
                format!("no BASE: cannot find the merge-base of HEAD and {landing} ({error}); pass --base")
            })?;
            let rev = merge_base.trim().to_owned();
            (
                git(&["show", &format!("{rev}:{LIB}")])?,
                format!("{rev} (merge-base with {landing})"),
            )
        }
        (Some(_), Some(_)) => return Err("give --base or --base-file, not both".into()),
    };
    let (head, head_name) = match (head_file, head_rev) {
        (Some(path), None) => (
            fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?,
            path,
        ),
        (None, Some(rev)) => (git(&["show", &format!("{rev}:{LIB}")])?, rev),
        (None, None) => {
            let path = Path::new(&root).join(LIB);
            (
                fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?,
                "working tree".to_owned(),
            )
        }
        (Some(_), Some(_)) => return Err("give --head or --head-file, not both".into()),
    };
    let (refusals, notes) = compare(&base, &head)?;
    println!("check-catalog-bindings-append-only: BASE {base_name}, HEAD {head_name}");
    for note in &notes {
        println!("  {note}");
    }
    for refusal in &refusals {
        println!("  REFUSED: {refusal}");
    }
    Ok(refusals.is_empty())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("check-catalog-bindings-append-only: ERROR: {error}");
            ExitCode::from(2)
        }
    }
}
