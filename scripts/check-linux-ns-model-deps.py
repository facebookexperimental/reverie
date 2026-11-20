#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Dependency guards for the linux-ns-model crate.

The crate is a pure leaf: it must depend on nothing (one allowlisted
dev-dependency for its kernel differential test), and within this
workspace nothing may depend on it yet (its two eventual dependents
live outside this workspace or do not exist yet; each gets added to
ALLOWED_DEPENDENTS by its own change). Manifests are parsed
with the standard library's `tomllib` and judged by effective
package (renames, path/git sources, workspace inheritance), so
no TOML spelling of a declaration can slip past a line scanner;
that makes this script the authoritative manifest check in git.
The Rust test linux-ns-model/tests/dependency_guard.rs is a
secondary, defense-in-depth scan that also runs where Python
does not (its Buck target cannot run cargo or a TOML crate
parser over the workspace), and the configured Buck graph
queries below are authoritative in fbsource. This script adds
the two workspace-wide checks a single crate's tests cannot see:

  forward closure   `cargo tree` over normal+build+dev edges for
                    all targets and features must equal the
                    allowlist exactly (a dev-dependency on a
                    backend fails here even though tests never ship)
  incoming edges    no other workspace member's manifest may
                    depend on linux-ns-model

Buck equivalent (run in fbsource, fbcode/hermetic_infra/reverie).
Use configured queries restricted to target deps: the
unconfigured uquery form follows toolchain edges and returns
most of fbsource, which proves nothing (measured at upload:
825,897 targets unconfigured vs 124 configured).

  buck2 cquery 'deps(//hermetic_infra/reverie:linux-ns-model \
    union //hermetic_infra/reverie:linux-ns-model-dependency-guard-test \
    union //hermetic_infra/reverie:linux-ns-model-kernel-differential-test, \
    100000, target_deps())'
  buck2 uquery 'rdeps(//hermetic_infra/reverie/..., //hermetic_infra/reverie:linux-ns-model)'

The first must list no first-party target besides the crate's own
(and third-party libc under the differential test); the library
alone has zero third-party Rust dependencies. The second must
list only the crate and its own test targets today.

Usage:
  check-linux-ns-model-deps.py [--repo-root DIR] [--self-test]

--self-test runs planted controls on scratch copies: each must make
its check fail, and the unplanted controls must pass. A guard that
cannot fail is not a guard.
"""

import subprocess
import tomllib
import sys
import tempfile
from pathlib import Path

CRATE = "linux-ns-model"
DEV_ALLOWLIST = {"libc"}
EXPECTED_CLOSURE = {CRATE, "libc"}
ALLOWED_DEPENDENTS: set = set()  # package names; empty today, by design

DEP_SECTIONS = ("dependencies", "build-dependencies", "dev-dependencies")


def _parse_manifest(text, name="<manifest>"):
    """Parse a manifest with the standard-library TOML parser.

    This is the authoritative manifest check: every TOML 1.0
    spelling of a dependency declaration (entry, dotted-key,
    table form, comments anywhere, basic/literal/triple-quoted
    strings) parses to the same structure, so there is no
    line-scanner shape left to evade. Spellings `tomllib`
    rejects (notably multi-line inline tables, measured in 0 of
    the 28 workspace manifests on 2026-11-20) fail closed by
    name instead of being normalized by hand.
    """
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"unparseable manifest (fail closed): {name}: {e}") from e


def _dep_tables(data, prefix=""):
    """Yield (section_label, is_dev, table) for each dependency
    table in a parsed manifest, including target-specific ones."""
    for section in DEP_SECTIONS:
        table = data.get(section)
        if table is None:
            continue
        if not isinstance(table, dict):
            raise ValueError(f"[{prefix}{section}] is not a table")
        yield f"{prefix}{section}", section == "dev-dependencies", table
    if not prefix:
        target = data.get("target")
        if target is None:
            return
        if not isinstance(target, dict):
            raise ValueError("[target] is not a table")
        for cfg, cfg_table in target.items():
            if not isinstance(cfg_table, dict):
                raise ValueError(f"[target.{cfg}] is not a table")
            yield from _dep_tables(cfg_table, f"target.{cfg}.")


def _source_basename(value):
    """Final component of a parsed declaration's `path` or `git`
    source, with a trailing `.git` removed, if either is a string."""
    if not isinstance(value, dict):
        return None
    for field in ("path", "git"):
        raw = value.get(field)
        if raw is None:
            continue
        if not isinstance(raw, str):
            raise ValueError(f"dependency {field} is not a string: {raw!r}")
        trimmed = raw.replace("\\", "/").rstrip("/")
        if trimmed.endswith(".git"):
            trimmed = trimmed[:-4]
        parts = [p for p in trimmed.split("/") if p not in ("", ".")]
        if parts:
            return parts[-1]
    return None


def effective_package(name, value, workspace_deps=None, seen=frozenset()):
    """The package a parsed declaration actually names.

    A plain version string names the local key. In a table, an
    explicit `package` rename wins; a `workspace = true`
    inheritance resolves through the workspace declaration of
    the same key; otherwise the basename of the `path`/`git`
    source is judged, which fails closed on an alias that merely
    borrows an allowlisted name.
    """
    if isinstance(value, str):
        return name
    if not isinstance(value, dict):
        raise ValueError(f"unrecognized dependency declaration for {name}: {value!r}")
    package = value.get("package")
    if package is not None:
        if not isinstance(package, str):
            raise ValueError(f"dependency package rename is not a string: {package!r}")
        return package
    if value.get("workspace") is True and workspace_deps and name not in seen:
        inherited = workspace_deps.get(name)
        if inherited is not None:
            return effective_package(name, inherited, workspace_deps, seen | {name})
    return _source_basename(value) or name


def manifest_violations(text, workspace_deps=None, name="<manifest>"):
    """Allowlist violations in one manifest, by effective package."""
    data = _parse_manifest(text, name)
    out = []
    for _section, is_dev, table in _dep_tables(data):
        for name, value in table.items():
            effective = effective_package(name, value, workspace_deps)
            if is_dev:
                if effective not in DEV_ALLOWLIST:
                    out.append(f"dev-dependency not on the allowlist: {effective}")
            else:
                out.append(f"library dependency is forbidden: {effective}")
    return out


def _workspace(data):
    workspace = data.get("workspace") or {}
    if not isinstance(workspace, dict):
        raise ValueError("[workspace] is not a table")
    return workspace


def workspace_members(root):
    """Workspace member directories from the parsed root manifest.

    Explicit member paths are returned as spelled; glob entries
    expand to the directories carrying a Cargo.toml.
    """
    data = _parse_manifest((root / "Cargo.toml").read_text(), str(root / "Cargo.toml"))
    members = _workspace(data).get("members")
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        raise ValueError("no workspace members array in root Cargo.toml")
    out = []
    for member in members:
        if any(ch in member for ch in "*?["):
            out.extend(
                str(p.parent.relative_to(root))
                for p in sorted(root.glob(f"{member}/Cargo.toml"))
            )
        else:
            out.append(member)
    return out


def _workspace_deps(root):
    data = _parse_manifest((root / "Cargo.toml").read_text(), str(root / "Cargo.toml"))
    deps = _workspace(data).get("dependencies") or {}
    if not isinstance(deps, dict):
        raise ValueError("[workspace.dependencies] is not a table")
    return deps


def incoming_violations(root):
    workspace_deps = _workspace_deps(root)
    out = []
    for member in workspace_members(root):
        manifest = root / member / "Cargo.toml"
        if not manifest.exists():
            continue
        data = _parse_manifest(manifest.read_text(), str(manifest))
        package = data.get("package") or {}
        pkg_name = package.get("name") if isinstance(package, dict) else None
        pkg_name = pkg_name if isinstance(pkg_name, str) else member
        if pkg_name == CRATE:
            continue
        for section, _is_dev, table in _dep_tables(data):
            for name, value in table.items():
                if effective_package(name, value, workspace_deps) == CRATE or (
                    isinstance(value, dict) and _source_basename(value) == CRATE
                ):
                    if pkg_name not in ALLOWED_DEPENDENTS:
                        out.append(
                            f"{pkg_name} depends on {CRATE} via [{section}] "
                            f"but is not an allowed dependent"
                        )
    return out


def cargo_tree_closure(root):
    proc = subprocess.run(
        [
            "cargo", "tree", "-p", CRATE,
            "-e", "normal,build,dev",
            "--target", "all", "--all-features",
            "--prefix", "none",
        ],
        cwd=root, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cargo tree failed:\n{proc.stderr}")
    names = set()
    for line in proc.stdout.splitlines():
        line = line.strip().rstrip(" (*)")
        if line:
            names.add(line.split()[0])
    return names


def check(root):
    violations = []
    manifest = (root / CRATE / "Cargo.toml").read_text()
    violations += manifest_violations(manifest, _workspace_deps(root), str(root / CRATE / "Cargo.toml"))
    closure = cargo_tree_closure(root)
    if closure != EXPECTED_CLOSURE:
        violations.append(
            f"forward closure is {sorted(closure)}, expected {sorted(EXPECTED_CLOSURE)}"
        )
    violations += incoming_violations(root)
    return violations


def self_test():
    failures = []

    def expect_flagged(label, violations):
        if not violations:
            failures.append(f"planted control did not fire: {label}")

    def expect_clean(label, violations):
        if violations:
            failures.append(f"clean control flagged: {label}: {violations}")

    def expect_unparseable(label, thunk, named=None):
        try:
            thunk()
        except ValueError as e:
            if "unparseable manifest (fail closed)" not in str(e):
                failures.append(f"unparseable control failed by the wrong name: {label}: {e}")
            elif named is not None and named not in str(e):
                failures.append(f"unparseable control did not name the file: {label}: {e}")
            return
        failures.append(f"unparseable control did not fail closed: {label}")

    expect_flagged(
        "forbidden normal dependency",
        manifest_violations('[dependencies]\nreverie-ptrace = "0.5"\n'),
    )
    expect_flagged(
        "forbidden dev dependency (a backend under a test root)",
        manifest_violations('[dev-dependencies]\nreverie-ptrace = "0.5"\n'),
    )
    expect_flagged(
        "table-form dependency (header names the package)",
        manifest_violations('[dependencies.reverie-ptrace]\npath = "../reverie-ptrace"\n'),
    )
    expect_flagged(
        "table-form target dev dependency",
        manifest_violations(
            "[target.'cfg(unix)'.dev-dependencies.reverie-ptrace]\nversion = \"0.5\"\n"
        ),
    )
    expect_clean(
        "allowlisted dev dependency",
        manifest_violations('[dev-dependencies]\nlibc = "0.2"\n'),
    )
    expect_clean(
        "allowlisted dev dependency, table form",
        manifest_violations('[dev-dependencies.libc]\nversion = "0.2"\n'),
    )
    expect_flagged(
        "renamed dev dependency hiding behind the libc alias (table form)",
        manifest_violations(
            '[dev-dependencies.libc]\npackage = "reverie-ptrace"\nversion = "0.5"\n'
        ),
    )
    expect_flagged(
        "renamed dev dependency, inline package rename",
        manifest_violations(
            '[dev-dependencies]\nlibc = { package = "reverie-ptrace", version = "0.5" }\n'
        ),
    )
    expect_clean(
        "renamed allowlisted dev dependency",
        manifest_violations(
            '[dev-dependencies]\nmy-libc = { package = "libc", version = "0.2" }\n'
        ),
    )
    expect_flagged(
        "dotted-key renamed dev dependency",
        manifest_violations(
            '[dev-dependencies]\nlibc.package = "reverie-ptrace"\nlibc.version = "0.5"\n'
        ),
    )
    expect_flagged(
        "literal-string renamed dev dependency (table form)",
        manifest_violations(
            "[dev-dependencies.libc]\npackage = 'reverie-ptrace'\nversion = '0.5'\n"
        ),
    )
    expect_clean(
        "dotted-key renamed allowlisted dev dependency, literal strings",
        manifest_violations(
            "[dev-dependencies]\nmy-libc.package = 'libc'\nmy-libc.version = '0.2'\n"
        ),
    )
    expect_flagged(
        "spaced section header with dotted rename",
        manifest_violations(
            '[ dev-dependencies ]\nlibc.package = "reverie-ptrace"\n'
        ),
    )
    # Multi-line inline tables are TOML 1.1/Cargo spellings that
    # tomllib (TOML 1.0) cannot parse: no workspace manifest uses
    # them (measured 0 of 28, 2026-11-20), so they fail closed by
    # name instead of being normalized by hand. The single-line
    # mutant of the same declaration still fires as a violation.
    expect_unparseable(
        "multi-line inline-table rename fails closed",
        lambda: manifest_violations(
            '[dev-dependencies]\nlibc = {\n  package = "reverie-ptrace",\n  version = "0.5",\n}\n',
            name="planted/Cargo.toml",
        ),
        named="planted/Cargo.toml",
    )
    expect_flagged(
        "multi-line inline-table rename, single-line mutant",
        manifest_violations(
            '[dev-dependencies]\nlibc = { package = "reverie-ptrace", version = "0.5" }\n'
        ),
    )
    expect_flagged(
        "path-source rename hiding behind the libc alias",
        manifest_violations(
            '[dev-dependencies]\nlibc = { path = "../reverie-ptrace" }\n'
        ),
    )
    expect_flagged(
        "git-source rename hiding behind the libc alias",
        manifest_violations(
            '[dev-dependencies]\nlibc = { git = "https://example.invalid/reverie-ptrace.git" }\n'
        ),
    )
    expect_flagged(
        "section header with trailing comment",
        manifest_violations(
            '[dev-dependencies] # dev-only\nlibc.package = "reverie-ptrace"\n'
        ),
    )
    expect_flagged(
        "brace in trailing comment must not swallow next declaration",
        manifest_violations(
            '[dev-dependencies]\n'
            'libc = { package = "libc", version = "0.2" } # {\n'
            'evil.package = "reverie-ptrace"\n'
        ),
    )
    expect_flagged(
        "triple-quoted rename (table form)",
        manifest_violations(
            '[dev-dependencies.libc]\npackage = """reverie-ptrace"""\n'
        ),
    )
    expect_flagged(
        "triple-quoted literal rename (inline)",
        manifest_violations(
            "[dev-dependencies]\nlibc = { package = '''reverie-ptrace''' }\n"
        ),
    )
    expect_flagged(
        "leading-newline triple-quoted rename (table form)",
        manifest_violations(
            '[dev-dependencies.libc]\npackage = """\nreverie-ptrace"""\n'
        ),
    )
    expect_flagged(
        "leading-newline triple-literal rename (table form)",
        manifest_violations(
            "[dev-dependencies.libc]\npackage = '''\nreverie-ptrace'''\n"
        ),
    )
    expect_flagged(
        "line-ending-backslash triple-quoted rename",
        manifest_violations(
            '[dev-dependencies.libc]\npackage = """reverie-\\\n    ptrace"""\n'
        ),
    )
    expect_clean(
        "forward-clean leading-newline triple-quoted libc",
        manifest_violations(
            '[dev-dependencies.libc] # don\'t { break\npackage = """\nlibc"""\n'
        ),
    )
    with tempfile.TemporaryDirectory(prefix="nsmodel-guard-") as td:
        root = Path(td)
        (root / CRATE).mkdir()
        (root / CRATE / "Cargo.toml").write_text(
            f'[package]\nname = "{CRATE}"\nversion = "0.0.0"\n'
        )
        (root / "core-crate").mkdir()
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            f'[dependencies]\n{CRATE} = {{ path = "../{CRATE}" }}\n'
        )
        (root / "Cargo.toml").write_text(
            f'[workspace]\nresolver = "2"\nmembers = ["{CRATE}", "core-crate"]\n'
        )
        expect_flagged(
            "incoming edge from an unallowed dependent",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
        )
        expect_clean("no incoming edge", incoming_violations(root))
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies.some-alias]\n'
            f'package = "{CRATE}"\npath = "../{CRATE}"\n'
        )
        expect_flagged(
            "renamed table-form incoming edge (package rename in body)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies.some-alias]\n'
            f'path = "../{CRATE}"\n'
        )
        expect_flagged(
            "renamed table-form incoming edge (path only)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            f'[dependencies]\n{CRATE}-utils = {{ path = "../{CRATE}-utils" }}\n'
        )
        expect_clean(
            "sibling crate whose name contains the crate name",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies]\n'
            f'some-alias.path = "../{CRATE}"\n'
        )
        expect_flagged(
            "dotted-key incoming edge (alias.path)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies]\n'
            f'some-alias.package = "{CRATE}"\n'
            'some-alias.version = "0.0.0"\n'
        )
        expect_flagged(
            "dotted-key incoming edge (alias.package)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies.some-alias]\n'
            f"path = '../{CRATE}'\n"
        )
        expect_flagged(
            "literal-string table-form incoming edge (path)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies]\n'
            f'some-alias = {{ git = "https://example.invalid/{CRATE}.git" }}\n'
        )
        expect_flagged(
            "git-source incoming edge (renamed)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies] # regular dependencies\n'
            f'some-alias = {{ path = "../{CRATE}" }}\n'
        )
        expect_flagged(
            "incoming edge under a header with trailing comment",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies]\n'
            'innocent = { path = "../innocent" } # {\n'
            f'some-alias.path = "../{CRATE}"\n'
        )
        expect_flagged(
            "incoming edge after a brace in a trailing comment",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies.some-alias]\n'
            f'package = """{CRATE}"""\n'
            f'path = "../{CRATE}"\n'
        )
        expect_flagged(
            "triple-quoted incoming edge (package rename)",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies.some-alias]\n'
            f'package = """\n{CRATE}"""\n'
            'version = "0.0.0"\n'
        )
        expect_flagged(
            "leading-newline triple-quoted incoming edge",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies.some-alias]\n'
            f"package = '''\n{CRATE}'''\n"
            'version = "0.0.0"\n'
        )
        expect_flagged(
            "leading-newline triple-literal incoming edge",
            incoming_violations(root),
        )
        (root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\n'
            f'members = ["{CRATE}", "core-crate"]\n'
            '[workspace.dependencies]\n'
            f'some-alias = {{ package = "{CRATE}", path = "{CRATE}" }}\n'
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies]\n'
            'some-alias.workspace = true\n'
        )
        expect_flagged(
            "workspace-inherited incoming edge",
            incoming_violations(root),
        )
        (root / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\n'
            'members = ["""\ncore-crate""", '
            f'"{CRATE}"]\n'
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            f'[dependencies]\n{CRATE} = {{ path = "../{CRATE}" }}\n'
        )
        expect_flagged(
            "workspace member spelled with leading-newline triple quote",
            incoming_violations(root),
        )
        (root / "core-crate" / "Cargo.toml").write_text(
            '[package]\nname = "core-crate"\nversion = "0.0.0"\n'
            '[dependencies]\n'
            'innocent = {\n  path = "../innocent",\n}\n'
        )
        expect_unparseable(
            "incoming scan fails closed on a multi-line inline table",
            lambda: incoming_violations(root),
            named="core-crate/Cargo.toml",
        )
    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}")
        return 1
    print("self-test: all planted controls fired, all clean controls passed")
    return 0


def main(argv):
    root = Path(__file__).resolve().parent.parent
    args = list(argv)
    if "--repo-root" in args:
        i = args.index("--repo-root")
        root = Path(args[i + 1]).resolve()
        del args[i : i + 2]
    if "--self-test" in args:
        return self_test()
    try:
        violations = check(root)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"dependency guard could not run: {e}")
        return 2
    if violations:
        for v in violations:
            print(f"VIOLATION: {v}")
        return 1
    print(
        "linux-ns-model dependency guard: clean "
        f"(closure {sorted(EXPECTED_CLOSURE)}, no unallowed dependents)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
