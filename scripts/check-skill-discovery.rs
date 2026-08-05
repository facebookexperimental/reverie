#!/usr/bin/env rust-script
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
//! Verify that Claude and stock Codex discover the same Reverie product skills.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

const ROOT_SKILLS: &[&str] = &[
    "adding-a-backend",
    "repo-cleanliness",
    "reverie-architecture",
    "syscall-interception",
    "testing-tools",
];

const LITEINST_SKILLS: &[&str] = &[
    "liteinst-binary-instrumentation",
    "liteinst-testing",
    "liteinst-tool-lifecycle",
];

fn git_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|error| format!("could not run git rev-parse: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

fn require_symlink(path: &Path, expected: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_symlink() {
        return Err(format!("{} must be a symlink", path.display()));
    }
    let actual =
        fs::read_link(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "{} points to {:?}, expected {:?}",
            path.display(),
            actual,
            expected
        ));
    }
    Ok(())
}

fn canonical_within(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let resolved_root = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve repository root {}: {error}", root.display()))?;
    let resolved = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    if !resolved.starts_with(&resolved_root) {
        return Err(format!(
            "{} resolves outside repository root {}: {}",
            path.display(),
            resolved_root.display(),
            resolved.display()
        ));
    }
    Ok(resolved)
}

fn require_internal_symlink(path: &Path, expected: &Path, root: &Path) -> Result<(), String> {
    require_symlink(path, expected)?;
    canonical_within(path, root)?;
    Ok(())
}

fn require_real_directory(path: &Path, root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{} must be a real directory", path.display()));
    }
    canonical_within(path, root)?;
    Ok(())
}

fn frontmatter<'a>(contents: &'a str, path: &Path) -> Result<&'a str, String> {
    let rest = contents
        .strip_prefix("---\n")
        .ok_or_else(|| format!("{} lacks YAML frontmatter", path.display()))?;
    let closing = rest
        .find("\n---\n")
        .ok_or_else(|| format!("{} has unterminated YAML frontmatter", path.display()))?;
    Ok(&contents[..4 + closing + 5])
}

fn narrow_yaml_scalar<'a>(value: &'a str, field: &str, path: &Path) -> Result<&'a str, String> {
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            format!(
                "{} frontmatter {field} must be one nonempty double-quoted scalar",
                path.display()
            )
        })?;
    if inner.trim().is_empty() || inner.contains(['"', '\\']) {
        return Err(format!(
            "{} frontmatter {field} must be one nonempty double-quoted scalar without escapes",
            path.display()
        ));
    }
    Ok(inner)
}

fn checked_frontmatter<'a>(
    contents: &'a str,
    path: &Path,
    expected_name: &str,
) -> Result<&'a str, String> {
    let metadata = frontmatter(contents, path)?;
    let body = metadata
        .strip_prefix("---\n")
        .and_then(|value| value.strip_suffix("---\n"))
        .ok_or_else(|| format!("{} has malformed YAML delimiters", path.display()))?;
    let mut lines = body.lines();
    let name = lines
        .next()
        .and_then(|line| line.strip_prefix("name: "))
        .ok_or_else(|| {
            format!(
                "{} frontmatter must begin with exactly `name: <slug>`",
                path.display()
            )
        })?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!(
            "{} frontmatter name {:?} is not a lowercase-hyphenated slug",
            path.display(),
            name
        ));
    }
    if name != expected_name {
        return Err(format!(
            "{} declares name {:?}, expected {:?}",
            path.display(),
            name,
            expected_name
        ));
    }
    let description = lines
        .next()
        .and_then(|line| line.strip_prefix("description: "))
        .ok_or_else(|| {
            format!(
                "{} frontmatter must contain exactly one description after name",
                path.display()
            )
        })?;
    narrow_yaml_scalar(description, "description", path)?;
    if lines.next().is_some() {
        return Err(format!(
            "{} frontmatter contains unsupported or duplicate fields",
            path.display()
        ));
    }
    let instructions = contents
        .strip_prefix(metadata)
        .ok_or_else(|| format!("{} frontmatter boundary is inconsistent", path.display()))?;
    if instructions.trim().is_empty() {
        return Err(format!(
            "{} has metadata but no skill instructions",
            path.display()
        ));
    }
    Ok(metadata)
}

fn parser_regression_tests() -> Result<(), String> {
    let path = Path::new("<skill-frontmatter-fixture>");
    let valid = "---\nname: fixture-skill\ndescription: \"Useful guidance.\"\n---\n# Body\n";
    checked_frontmatter(valid, path, "fixture-skill")?;

    let invalid = [
        (
            "duplicate name",
            "---\nname: fixture-skill\nname: other\ndescription: \"Useful.\"\n---\n",
        ),
        (
            "null description",
            "---\nname: fixture-skill\ndescription: null\n---\n",
        ),
        (
            "empty block description",
            "---\nname: fixture-skill\ndescription: |\n---\n",
        ),
        (
            "empty quoted description",
            "---\nname: fixture-skill\ndescription: \"\"\n---\n",
        ),
        (
            "unterminated quote",
            "---\nname: fixture-skill\ndescription: \"Useful.\n---\n",
        ),
        (
            "unsupported field",
            "---\nname: fixture-skill\ndescription: \"Useful.\"\ncompatibility: both\n---\n",
        ),
        (
            "metadata-only skill",
            "---\nname: fixture-skill\ndescription: \"Useful.\"\n---\n",
        ),
    ];
    for (case, contents) in invalid {
        if checked_frontmatter(contents, path, "fixture-skill").is_ok() {
            return Err(format!(
                "parser regression fixture unexpectedly accepted {case}"
            ));
        }
    }
    Ok(())
}

struct FixtureRoot(PathBuf);

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn filesystem_regression_tests() -> Result<(), String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    let fixture = FixtureRoot(env::temp_dir().join(format!(
        "reverie-skill-discovery-{}-{nonce}",
        std::process::id()
    )));
    let root = fixture.0.join("repo");
    let outside = fixture.0.join("outside");
    fs::create_dir_all(outside.join("skills"))
        .map_err(|error| format!("cannot create filesystem fixture: {error}"))?;
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create filesystem fixture: {error}"))?;
    fs::write(root.join("AGENTS.md"), "fixture policy\n")
        .map_err(|error| format!("cannot write filesystem fixture: {error}"))?;
    symlink("AGENTS.md", root.join("CLAUDE.md"))
        .map_err(|error| format!("cannot create positive symlink fixture: {error}"))?;
    require_internal_symlink(&root.join("CLAUDE.md"), Path::new("AGENTS.md"), &root)?;

    symlink("missing", root.join("dangling"))
        .map_err(|error| format!("cannot create dangling symlink fixture: {error}"))?;
    if require_internal_symlink(&root.join("dangling"), Path::new("missing"), &root).is_ok() {
        return Err("filesystem regression accepted a dangling discovery link".to_owned());
    }

    fs::write(outside.join("target"), "outside\n")
        .map_err(|error| format!("cannot write escaping fixture: {error}"))?;
    symlink("../outside/target", root.join("escaping"))
        .map_err(|error| format!("cannot create escaping symlink fixture: {error}"))?;
    if require_internal_symlink(
        &root.join("escaping"),
        Path::new("../outside/target"),
        &root,
    )
    .is_ok()
    {
        return Err("filesystem regression accepted an escaping discovery link".to_owned());
    }

    symlink("../outside", root.join(".agents"))
        .map_err(|error| format!("cannot create ancestor symlink fixture: {error}"))?;
    if require_real_directory(&root.join(".agents/skills"), &root).is_ok() {
        return Err("filesystem regression accepted an escaping ancestor link".to_owned());
    }
    Ok(())
}

fn entry_names(path: &Path) -> Result<BTreeSet<String>, String> {
    fs::read_dir(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
            entry
                .file_name()
                .into_string()
                .map_err(|name| format!("non-UTF-8 skill entry: {name:?}"))
        })
        .collect()
}

fn expected_names(skills: &[&str], suffix: &str, readme: bool) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = skills
        .iter()
        .map(|name| format!("{name}{suffix}"))
        .collect();
    if readme {
        names.insert("README.md".to_owned());
    }
    names
}

fn check_group(
    root: &Path,
    canonical_root: &Path,
    codex_root: &Path,
    skills: &[&str],
    target_root: &str,
) -> Result<(), String> {
    require_real_directory(canonical_root, root)?;
    require_real_directory(codex_root, root)?;

    let actual_canonical = entry_names(canonical_root)?;
    let expected_canonical = expected_names(skills, "", false);
    if actual_canonical != expected_canonical {
        return Err(format!(
            "canonical entries differ in {}:\n  actual: {actual_canonical:?}\n  expected: {expected_canonical:?}",
            canonical_root.display()
        ));
    }

    let actual_codex = entry_names(codex_root)?;
    let expected_codex = expected_names(skills, "", true);
    if actual_codex != expected_codex {
        return Err(format!(
            "Codex entries differ in {}:\n  actual: {actual_codex:?}\n  expected: {expected_codex:?}",
            codex_root.display()
        ));
    }

    for name in skills {
        let canonical_dir = canonical_root.join(name);
        require_real_directory(&canonical_dir, root)?;
        let canonical_path = canonical_dir.join("SKILL.md");
        let canonical_file_metadata = fs::symlink_metadata(&canonical_path)
            .map_err(|error| format!("cannot inspect {}: {error}", canonical_path.display()))?;
        if !canonical_file_metadata.is_file() || canonical_file_metadata.file_type().is_symlink() {
            return Err(format!(
                "{} must be a regular file",
                canonical_path.display()
            ));
        }
        canonical_within(&canonical_path, root)?;
        let canonical = fs::read_to_string(&canonical_path)
            .map_err(|error| format!("cannot read {}: {error}", canonical_path.display()))?;
        checked_frontmatter(&canonical, &canonical_path, name)?;

        let entry = codex_root.join(name);
        require_internal_symlink(
            &entry,
            &PathBuf::from(format!("{target_root}/{name}")),
            root,
        )?;
        let resolved = fs::canonicalize(&entry)
            .map_err(|error| format!("cannot resolve {}: {error}", entry.display()))?;
        let expected = fs::canonicalize(&canonical_dir)
            .map_err(|error| format!("cannot resolve {}: {error}", canonical_dir.display()))?;
        if resolved != expected {
            return Err(format!(
                "{} resolves to {}, expected canonical package {}",
                entry.display(),
                resolved.display(),
                expected.display()
            ));
        }
        let resolved_skill = entry.join("SKILL.md");
        let resolved_metadata = fs::symlink_metadata(&resolved_skill)
            .map_err(|error| format!("cannot inspect {}: {error}", resolved_skill.display()))?;
        if !resolved_metadata.is_file() || resolved_metadata.file_type().is_symlink() {
            return Err(format!(
                "{} must resolve to a regular file",
                resolved_skill.display()
            ));
        }
    }

    Ok(())
}

fn check(root: &Path) -> Result<(), String> {
    require_internal_symlink(&root.join("CLAUDE.md"), Path::new("AGENTS.md"), root)?;
    require_internal_symlink(
        &root.join(".llms/skills"),
        Path::new("../.claude/skills"),
        root,
    )?;
    check_group(
        root,
        &root.join(".claude/skills"),
        &root.join(".agents/skills"),
        ROOT_SKILLS,
        "../../.claude/skills",
    )?;

    let liteinst = root.join("reverie-liteinst");
    require_real_directory(&liteinst, root)?;
    require_internal_symlink(&liteinst.join("CLAUDE.md"), Path::new("AGENTS.md"), root)?;
    require_internal_symlink(
        &liteinst.join(".claude/skills"),
        Path::new("../.llms/skills"),
        root,
    )?;
    check_group(
        root,
        &liteinst.join(".llms/skills"),
        &liteinst.join(".agents/skills"),
        LITEINST_SKILLS,
        "../../.llms/skills",
    )?;
    Ok(())
}

fn main() {
    if let Err(error) = parser_regression_tests() {
        eprintln!("check-skill-discovery: ERROR: {error}");
        std::process::exit(1);
    }
    if let Err(error) = filesystem_regression_tests() {
        eprintln!("check-skill-discovery: ERROR: {error}");
        std::process::exit(1);
    }
    let root = match env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => match git_root() {
            Ok(path) => path,
            Err(error) => {
                eprintln!("check-skill-discovery: ERROR: {error}");
                std::process::exit(1);
            }
        },
    };
    if let Err(error) = check(&root) {
        eprintln!("check-skill-discovery: ERROR: {error}");
        std::process::exit(1);
    }
    println!(
        "check-skill-discovery: PASS ({} root packages, {} LiteInst packages)",
        ROOT_SKILLS.len(),
        LITEINST_SKILLS.len()
    );
}
