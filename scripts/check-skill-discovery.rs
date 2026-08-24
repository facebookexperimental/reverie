#!/usr/bin/env rust-script
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
//! Verify that Claude and stock Codex discover the same Reverie product skills.
//!
//! There is deliberately NO roster in this file. The checker DISCOVERS every
//! skill host in the working tree and every skill package inside it, then
//! asserts the dual-client shape for whatever it found:
//!
//!   * exactly one of `<host>/.claude/skills` and `<host>/.llms/skills` is the
//!     canonical real directory holding the skill packages;
//!   * the other one is an internal symlink to it, so Claude reads the same
//!     bytes under either spelling;
//!   * `<host>/.agents/skills` is a real directory holding one whole-package
//!     symlink per canonical skill, spelled canonically, resolving inside the
//!     repository, so stock Codex reads those same bytes;
//!   * the two rosters match exactly in both directions — a package that only
//!     one client can see is a refusal, not a warning.
//!
//! As skills are regrown, they are picked up with no edit to this file, and the
//! shape above is enforced on each new one.
//!
//! Anti-vacuity: a discovery checker over an empty tree passes while asserting
//! nothing. So this one always reports the host and skill counts it discovered,
//! requires the repository's intended skill hosts to remain present, and refuses
//! outright if the repository-wide skill count is zero.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// The two directory names Claude reads skill packages from. Exactly one is
/// canonical per host; the other mirrors it.
const CLAUDE_SKILL_ROOTS: &[&str] = &[".claude/skills", ".llms/skills"];

/// The directory stock Codex reads skill packages from.
const CODEX_SKILL_ROOT: &str = ".agents/skills";

/// Client directories, used to prune the host walk.
const CLIENT_DIR_NAMES: &[&str] = &[".claude", ".llms", ".agents"];

/// Directory names never descended into while discovering hosts.
const PRUNED_DIR_NAMES: &[&str] = &[".git", "target", "node_modules"];

/// Quarantine directories from a skills bankruptcy hold preserved copies of
/// retired packages. They are not live skills and must not be discovered.
const QUARANTINE_PREFIX: &str = ".skill_reset";

/// The one non-package entry tolerated in a skill root.
const README: &str = "README.md";

/// Structural hosts that this repository intentionally exposes to both clients.
/// Skill package names remain fully dynamic; this only prevents discovery from
/// silently losing an entire host while another host keeps the global count
/// nonzero.
const REQUIRED_HOSTS: &[&str] = &[".", "reverie-liteinst"];

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

fn require_real_file(path: &Path, root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} must be a regular file", path.display()));
    }
    canonical_within(path, root)?;
    Ok(())
}

fn is_slug(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
    if !is_slug(name) {
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

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// A directory that at least one client is told to read skills from. Detected
/// by the presence of any client skill root, so a tree that only one client can
/// see is still discovered — and then refused below.
fn is_skill_host(dir: &Path) -> bool {
    CLAUDE_SKILL_ROOTS
        .iter()
        .chain(std::iter::once(&CODEX_SKILL_ROOT))
        .any(|name| exists(&dir.join(name)))
}

/// Enumerate every skill host in the working tree, as paths relative to `root`.
/// The repository root itself is a candidate; the empty path denotes it.
fn discover_hosts(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut hosts = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(relative) = stack.pop() {
        let directory = root.join(&relative);
        if is_skill_host(&directory) {
            hosts.push(relative.clone());
        }
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|name| format!("non-UTF-8 directory entry: {name:?}"))?;
            if PRUNED_DIR_NAMES.contains(&name.as_str())
                || CLIENT_DIR_NAMES.contains(&name.as_str())
                || name.starts_with(QUARANTINE_PREFIX)
            {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            // Symlinked directories are never descended into: they would let
            // the walk leave the repository or loop.
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                continue;
            }
            // A nested checkout (submodule or worktree) is a separate
            // repository and owns its own skill policy.
            if exists(&path.join(".git")) {
                continue;
            }
            stack.push(relative.join(name));
        }
    }
    hosts.sort();
    Ok(hosts)
}

fn host_label(relative: &Path) -> String {
    if relative.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        relative.display().to_string()
    }
}

struct Host {
    label: String,
    /// `.claude/skills` or `.llms/skills`, whichever holds the real packages.
    canonical_root: String,
    /// The other Claude spelling, a symlink to `canonical_root`.
    mirror_root: String,
    policy: &'static str,
    skills: BTreeSet<String>,
}

/// Which Claude spelling is canonical here, and which mirrors it. Discovered,
/// not assumed: the repository root and `reverie-liteinst` disagree today, and
/// either orientation is legal as long as the mirror is intact.
fn resolve_claude_roots(host: &Path) -> Result<(String, String), String> {
    let mut canonical = Vec::new();
    let mut mirrored = Vec::new();
    let mut absent = Vec::new();
    for name in CLAUDE_SKILL_ROOTS {
        let path = host.join(name);
        match fs::symlink_metadata(&path) {
            Err(_) => absent.push(*name),
            Ok(metadata) if metadata.file_type().is_symlink() => mirrored.push(*name),
            Ok(metadata) if metadata.is_dir() => canonical.push(*name),
            Ok(_) => {
                return Err(format!(
                    "{} must be a directory of skill packages or a symlink to one",
                    path.display()
                ));
            }
        }
    }
    if canonical.len() != 1 || mirrored.len() != 1 {
        return Err(format!(
            "{}: exactly one of {CLAUDE_SKILL_ROOTS:?} must be a real directory holding the skill \
             packages and the other must be a symlink to it, so both Claude spellings read the \
             same bytes (found real: {canonical:?}, symlink: {mirrored:?}, absent: {absent:?})",
            host.display()
        ));
    }
    Ok((
        canonical.remove(0).to_owned(),
        mirrored.remove(0).to_owned(),
    ))
}

/// Policy-file shape. Absence is tolerated on purpose: the 2026-08-16 skills
/// bankruptcy moved Reverie's `AGENTS.md`/`CLAUDE.md` into
/// `.skill_reset_20260816/` and the owner is regrowing them step by step. This
/// tolerance is DELIBERATE AND TEMPORARY — it is not a statement that a
/// repository should have no agent policy. When the files come back, the
/// symlink shape below is enforced again with no edit to this file.
fn check_policy_files(host: &Path, root: &Path) -> Result<&'static str, String> {
    let agents = host.join("AGENTS.md");
    let claude = host.join("CLAUDE.md");
    match (exists(&agents), exists(&claude)) {
        (false, false) => Ok("absent (tolerated while skills are regrown)"),
        _ => {
            require_real_file(&agents, root)?;
            require_internal_symlink(&claude, Path::new("AGENTS.md"), root)?;
            Ok("AGENTS.md with CLAUDE.md symlink")
        }
    }
}

/// Skill names in a canonical root: every entry is a package directory, apart
/// from an optional README.
fn discover_skills(canonical: &Path, root: &Path) -> Result<BTreeSet<String>, String> {
    let mut skills = BTreeSet::new();
    for name in entry_names(canonical)? {
        if name == README {
            require_real_file(&canonical.join(README), root)?;
            continue;
        }
        let package = canonical.join(&name);
        require_real_directory(&package, root)?;
        if !is_slug(&name) {
            return Err(format!(
                "{} is not a lowercase-hyphenated skill package name",
                package.display()
            ));
        }
        skills.insert(name);
    }
    Ok(skills)
}

fn check_host(root: &Path, relative: &Path) -> Result<Host, String> {
    let host = root.join(relative);
    let (canonical_root, mirror_root) = resolve_claude_roots(&host)?;
    let canonical = host.join(&canonical_root);
    require_real_directory(&canonical, root)?;

    // The mirror is spelled relative to its own parent directory, e.g.
    // `.llms/skills -> ../.claude/skills`.
    let mirror = host.join(&mirror_root);
    require_internal_symlink(
        &mirror,
        &PathBuf::from(format!("../{canonical_root}")),
        root,
    )?;
    if canonical_within(&mirror, root)? != canonical_within(&canonical, root)? {
        return Err(format!(
            "{} and {} must resolve to the same skill packages",
            mirror.display(),
            canonical.display()
        ));
    }

    let codex = host.join(CODEX_SKILL_ROOT);
    require_real_directory(&codex, root)?;

    let policy = check_policy_files(&host, root)?;
    let skills = discover_skills(&canonical, root)?;

    // Both directions. A package Codex cannot see is a skill Claude silently
    // has to itself; a Codex entry with no canonical package is a half-mirrored
    // leftover that resolves to nothing. Neither is a warning.
    let mut codex_entries = entry_names(&codex)?;
    if codex_entries.remove(README) {
        require_real_file(&codex.join(README), root)?;
    }
    if codex_entries != skills {
        let missing: Vec<&String> = skills.difference(&codex_entries).collect();
        let extra: Vec<&String> = codex_entries.difference(&skills).collect();
        return Err(format!(
            "{} and {} expose different skills:\n  canonical only (invisible to Codex): \
             {missing:?}\n  Codex only (no canonical package): {extra:?}",
            canonical.display(),
            codex.display()
        ));
    }

    for name in &skills {
        let package = canonical.join(name);
        let skill_file = package.join("SKILL.md");
        require_real_file(&skill_file, root)?;
        let contents = fs::read_to_string(&skill_file)
            .map_err(|error| format!("cannot read {}: {error}", skill_file.display()))?;
        checked_frontmatter(&contents, &skill_file, name)?;

        let entry = codex.join(name);
        require_internal_symlink(
            &entry,
            &PathBuf::from(format!("../../{canonical_root}/{name}")),
            root,
        )?;
        if canonical_within(&entry, root)? != canonical_within(&package, root)? {
            return Err(format!(
                "{} does not resolve to the canonical package {}",
                entry.display(),
                package.display()
            ));
        }
        require_real_file(&entry.join("SKILL.md"), root)?;
    }

    Ok(Host {
        label: host_label(relative),
        canonical_root,
        mirror_root,
        policy,
        skills,
    })
}

fn inspect(root: &Path) -> Result<Vec<Host>, String> {
    let relatives = discover_hosts(root)?;
    if relatives.is_empty() {
        return Err(format!(
            "discovered no skill hosts under {}; this check would assert nothing",
            root.display()
        ));
    }
    let discovered_hosts: BTreeSet<String> =
        relatives.iter().map(|path| host_label(path)).collect();
    let missing_hosts: Vec<&str> = REQUIRED_HOSTS
        .iter()
        .copied()
        .filter(|host| !discovered_hosts.contains(*host))
        .collect();
    if !missing_hosts.is_empty() {
        return Err(format!(
            "missing required skill host(s) {missing_hosts:?} under {}; discovered {discovered_hosts:?}. \
             Skill names are dynamic, but the repository root and reverie-liteinst must both remain \
             visible to Claude and Codex.",
            root.display()
        ));
    }
    let hosts: Vec<Host> = relatives
        .iter()
        .map(|relative| check_host(root, relative))
        .collect::<Result<_, _>>()?;
    let total: usize = hosts.iter().map(|host| host.skills.len()).sum();
    if total == 0 {
        return Err(format!(
            "discovered {} skill host(s) but zero skill packages under {}; a pass here would \
             assert nothing, so it is refused. Add a skill, or delete this check along with the \
             empty client directories.",
            hosts.len(),
            root.display()
        ));
    }
    Ok(hosts)
}

fn report(hosts: &[Host]) -> String {
    let mut out = String::new();
    let total: usize = hosts.iter().map(|host| host.skills.len()).sum();
    for host in hosts {
        let names: Vec<&str> = host.skills.iter().map(String::as_str).collect();
        let listed = if names.is_empty() {
            String::new()
        } else {
            format!(": {}", names.join(", "))
        };
        let _ = writeln!(
            out,
            "check-skill-discovery: host {} — canonical {}, Claude mirror {}, Codex {}, policy {}, \
             {} skill(s){listed}",
            host.label,
            host.canonical_root,
            host.mirror_root,
            CODEX_SKILL_ROOT,
            host.policy,
            host.skills.len(),
        );
    }
    let _ = write!(
        out,
        "check-skill-discovery: PASS (discovered {} host(s) and {total} skill(s); each is \
         reachable by both Claude and Codex)",
        hosts.len(),
    );
    out
}

struct FixtureRoot(PathBuf);

impl Drop for FixtureRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_root(tag: &str) -> Result<FixtureRoot, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "reverie-skill-discovery-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).map_err(|error| format!("cannot create fixture: {error}"))?;
    Ok(FixtureRoot(path))
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

fn filesystem_regression_tests() -> Result<(), String> {
    let fixture = fixture_root("fs")?;
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

fn write_skill_package(canonical: &Path, name: &str) -> Result<(), String> {
    let package = canonical.join(name);
    fs::create_dir_all(&package)
        .map_err(|error| format!("cannot create fixture package: {error}"))?;
    fs::write(
        package.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: \"Fixture skill.\"\n---\n# {name}\n"),
    )
    .map_err(|error| format!("cannot write fixture package: {error}"))
}

fn link(target: &str, path: &Path) -> Result<(), String> {
    symlink(target, path)
        .map_err(|error| format!("cannot create fixture link {}: {error}", path.display()))
}

fn expect_refusal(root: &Path, case: &str) -> Result<(), String> {
    match inspect(root) {
        Ok(_) => Err(format!(
            "discovery regression accepted a repository that {case}"
        )),
        Err(_) => Ok(()),
    }
}

fn expect_refusal_containing(root: &Path, case: &str, expected: &str) -> Result<(), String> {
    match inspect(root) {
        Ok(_) => Err(format!(
            "discovery regression accepted a repository that {case}"
        )),
        Err(error) if error.contains(expected) => Ok(()),
        Err(error) => Err(format!(
            "discovery regression refused a repository that {case}, but for the wrong reason: \
             expected {expected:?}, got {error:?}"
        )),
    }
}

/// README.md is metadata, not a skill package, but exempting its name must not
/// exempt its filesystem identity. Exercise both client roots against the three
/// non-file shapes most likely to hide drift: an external symlink, a directory,
/// and a Unix-domain socket.
fn exercise_readme_refusals(
    root: &Path,
    readme: &Path,
    outside: &Path,
    client: &str,
) -> Result<(), String> {
    let original = fs::read(readme)
        .map_err(|error| format!("cannot read positive {client} README fixture: {error}"))?;
    fs::remove_file(readme)
        .map_err(|error| format!("cannot remove positive {client} README fixture: {error}"))?;

    symlink(outside, readme)
        .map_err(|error| format!("cannot create external {client} README symlink: {error}"))?;
    expect_refusal_containing(
        root,
        &format!("uses an external symlink for the {client} README exemption"),
        "README.md must be a regular file",
    )?;
    fs::remove_file(readme)
        .map_err(|error| format!("cannot remove external {client} README symlink: {error}"))?;

    fs::create_dir(readme)
        .map_err(|error| format!("cannot create directory {client} README fixture: {error}"))?;
    expect_refusal_containing(
        root,
        &format!("uses a directory for the {client} README exemption"),
        "README.md must be a regular file",
    )?;
    fs::remove_dir(readme)
        .map_err(|error| format!("cannot remove directory {client} README fixture: {error}"))?;

    let socket = UnixListener::bind(readme)
        .map_err(|error| format!("cannot create socket {client} README fixture: {error}"))?;
    expect_refusal_containing(
        root,
        &format!("uses a nonregular socket for the {client} README exemption"),
        "README.md must be a regular file",
    )?;
    drop(socket);
    fs::remove_file(readme)
        .map_err(|error| format!("cannot remove socket {client} README fixture: {error}"))?;

    fs::write(readme, original)
        .map_err(|error| format!("cannot restore positive {client} README fixture: {error}"))?;
    inspect(root).map_err(|error| {
        format!("discovery regression left the {client} README fixture broken: {error}")
    })?;
    Ok(())
}

/// Prove the discovery pass can actually fail. Every mutation below is applied
/// to a well-formed fixture, refused, and then undone; the fixture is checked
/// again at the end so a failed restore cannot make a later case lie.
fn discovery_regression_tests() -> Result<(), String> {
    let fixture = fixture_root("discovery")?;
    let root = fixture.0.join("repo");
    let outside_readme = fixture.0.join("outside-readme");
    fs::write(&outside_readme, "outside fixture\n")
        .map_err(|error| format!("cannot create external README fixture: {error}"))?;

    // Host A: canonical under .claude, mirrored to .llms, with policy files.
    let a_canonical = root.join(".claude/skills");
    let a_codex = root.join(".agents/skills");
    fs::create_dir_all(&a_canonical).map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(&a_codex).map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(root.join(".llms")).map_err(|error| format!("cannot create: {error}"))?;
    fs::write(root.join("AGENTS.md"), "fixture policy\n")
        .map_err(|error| format!("cannot write fixture: {error}"))?;
    link("AGENTS.md", &root.join("CLAUDE.md"))?;
    link("../.claude/skills", &root.join(".llms/skills"))?;
    fs::write(a_canonical.join(README), "# canonical fixture\n")
        .map_err(|error| format!("cannot write fixture: {error}"))?;
    fs::write(a_codex.join(README), "# fixture\n")
        .map_err(|error| format!("cannot write fixture: {error}"))?;
    for name in ["alpha", "beta"] {
        write_skill_package(&a_canonical, name)?;
        link(&format!("../../.claude/skills/{name}"), &a_codex.join(name))?;
    }

    // Host B: the opposite orientation — canonical under .llms, mirrored to
    // .claude — and no policy files, which must be tolerated.
    let nested = root.join("reverie-liteinst");
    let b_canonical = nested.join(".llms/skills");
    let b_codex = nested.join(".agents/skills");
    fs::create_dir_all(&b_canonical).map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(&b_codex).map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(nested.join(".claude"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    link("../.llms/skills", &nested.join(".claude/skills"))?;
    write_skill_package(&b_canonical, "gamma")?;
    link("../../.llms/skills/gamma", &b_codex.join("gamma"))?;

    let hosts = inspect(&root)?;
    if hosts.len() != 2 {
        return Err(format!(
            "discovery regression found {} hosts in the fixture, expected 2",
            hosts.len()
        ));
    }
    let discovered: usize = hosts.iter().map(|host| host.skills.len()).sum();
    if discovered != 3 {
        return Err(format!(
            "discovery regression found {discovered} skills in the fixture, expected 3"
        ));
    }

    // Repository-wide non-emptiness is not enough: deleting either intended
    // host must fail even while the other still exposes real skills.
    for (host, hidden, label) in [
        (
            &root,
            root.join(".skill_reset-root-host"),
            "repository root",
        ),
        (
            &nested,
            root.join(".skill_reset-reverie-liteinst-host"),
            "reverie-liteinst",
        ),
    ] {
        if host == &root {
            let hidden_claude = hidden.join(".claude");
            let hidden_llms = hidden.join(".llms");
            let hidden_agents = hidden.join(".agents");
            fs::create_dir_all(&hidden)
                .map_err(|error| format!("cannot create hidden host fixture: {error}"))?;
            fs::rename(root.join(".claude"), &hidden_claude)
                .map_err(|error| format!("cannot hide root Claude host: {error}"))?;
            fs::rename(root.join(".llms"), &hidden_llms)
                .map_err(|error| format!("cannot hide root LLMS host: {error}"))?;
            fs::rename(root.join(".agents"), &hidden_agents)
                .map_err(|error| format!("cannot hide root Codex host: {error}"))?;
            expect_refusal_containing(
                &root,
                "omits the required repository-root host while reverie-liteinst remains nonempty",
                "missing required skill host(s) [\".\"]",
            )?;
            fs::rename(&hidden_claude, root.join(".claude"))
                .map_err(|error| format!("cannot restore root Claude host: {error}"))?;
            fs::rename(&hidden_llms, root.join(".llms"))
                .map_err(|error| format!("cannot restore root LLMS host: {error}"))?;
            fs::rename(&hidden_agents, root.join(".agents"))
                .map_err(|error| format!("cannot restore root Codex host: {error}"))?;
            fs::remove_dir(&hidden)
                .map_err(|error| format!("cannot remove hidden root host fixture: {error}"))?;
        } else {
            fs::rename(host, &hidden)
                .map_err(|error| format!("cannot hide {label} host: {error}"))?;
            expect_refusal_containing(
                &root,
                "omits the required reverie-liteinst host while the root remains nonempty",
                "missing required skill host(s) [\"reverie-liteinst\"]",
            )?;
            fs::rename(&hidden, host)
                .map_err(|error| format!("cannot restore {label} host: {error}"))?;
        }
        inspect(&root).map_err(|error| {
            format!("discovery regression left the {label} host broken after restore: {error}")
        })?;
    }

    exercise_readme_refusals(
        &root,
        &a_canonical.join(README),
        &outside_readme,
        "canonical",
    )?;
    exercise_readme_refusals(&root, &a_codex.join(README), &outside_readme, "Codex")?;

    // A skill Claude has and Codex cannot see.
    fs::remove_file(a_codex.join("beta")).map_err(|error| format!("cannot mutate: {error}"))?;
    expect_refusal(&root, "hides a canonical skill from Codex")?;
    link("../../.claude/skills/beta", &a_codex.join("beta"))?;

    // A Codex entry with no canonical package — exactly the leftover a skills
    // bankruptcy produces when it moves packages but not their mirrors.
    link("../../.claude/skills/delta", &a_codex.join("delta"))?;
    expect_refusal(&root, "exposes a Codex entry with no canonical package")?;
    fs::remove_file(a_codex.join("delta")).map_err(|error| format!("cannot restore: {error}"))?;

    // A Codex entry that is a real directory, so the two clients could drift.
    fs::remove_file(a_codex.join("beta")).map_err(|error| format!("cannot mutate: {error}"))?;
    write_skill_package(&a_codex, "beta")?;
    expect_refusal(&root, "forks a skill into a second copy under Codex")?;
    fs::remove_dir_all(a_codex.join("beta")).map_err(|error| format!("cannot restore: {error}"))?;
    link("../../.claude/skills/beta", &a_codex.join("beta"))?;

    // A Codex entry spelled through the mirror rather than the canonical root.
    // It resolves, but it leaves two spellings of the same package in the tree.
    fs::remove_file(a_codex.join("beta")).map_err(|error| format!("cannot mutate: {error}"))?;
    link("../../.llms/skills/beta", &a_codex.join("beta"))?;
    expect_refusal(&root, "spells a Codex mirror non-canonically")?;
    fs::remove_file(a_codex.join("beta")).map_err(|error| format!("cannot restore: {error}"))?;
    link("../../.claude/skills/beta", &a_codex.join("beta"))?;

    // A broken Claude mirror: one spelling reaches the skills, the other does
    // not. This is the repository root's state after the bankruptcy.
    fs::remove_file(root.join(".llms/skills"))
        .map_err(|error| format!("cannot mutate: {error}"))?;
    expect_refusal(&root, "leaves the second Claude spelling unreachable")?;
    link("../.claude/skills", &root.join(".llms/skills"))?;

    // A package whose frontmatter name no longer matches its directory.
    fs::write(
        a_canonical.join("beta/SKILL.md"),
        "---\nname: renamed\ndescription: \"Fixture skill.\"\n---\n# beta\n",
    )
    .map_err(|error| format!("cannot mutate: {error}"))?;
    expect_refusal(&root, "declares a skill name that is not its directory")?;
    write_skill_package(&a_canonical, "beta")?;

    // A host with client directories and no packages at all must not pass
    // silently — this is the vacuous-discovery trap.
    let empty = fixture_root("empty")?;
    let empty_root = empty.0.join("repo");
    fs::create_dir_all(empty_root.join(".claude/skills"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(empty_root.join(".agents/skills"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(empty_root.join(".llms"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    link("../.claude/skills", &empty_root.join(".llms/skills"))?;

    let empty_nested = empty_root.join("reverie-liteinst");
    fs::create_dir_all(empty_nested.join(".llms/skills"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(empty_nested.join(".agents/skills"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    fs::create_dir_all(empty_nested.join(".claude"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    link("../.llms/skills", &empty_nested.join(".claude/skills"))?;
    expect_refusal_containing(
        &empty_root,
        "contains both required hosts but no skill packages anywhere",
        "zero skill packages",
    )?;

    // And a tree with no client directories at all.
    let bare = fixture_root("bare")?;
    fs::create_dir_all(bare.0.join("repo"))
        .map_err(|error| format!("cannot create fixture: {error}"))?;
    expect_refusal(&bare.0.join("repo"), "has no skill hosts")?;

    // Every mutation above was undone; prove it.
    inspect(&root).map_err(|error| {
        format!("discovery regression left the fixture broken after restore: {error}")
    })?;
    Ok(())
}

fn main() {
    for test in [
        parser_regression_tests,
        filesystem_regression_tests,
        discovery_regression_tests,
    ] {
        if let Err(error) = test() {
            eprintln!("check-skill-discovery: ERROR: {error}");
            std::process::exit(1);
        }
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
    match inspect(&root) {
        Ok(hosts) => println!("{}", report(&hosts)),
        Err(error) => {
            eprintln!("check-skill-discovery: ERROR: {error}");
            std::process::exit(1);
        }
    }
}
