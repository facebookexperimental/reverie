#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Reverie layering check (.claude/skills/reverie-layering/SKILL.md).
#
# Reverie never names its consumers. This finds every file that does, by
# content or by path, and compares it with scripts/layering-allowlist.txt,
# where each line is `path -- N -- reason`. N is the number of the file's lines
# that match the pattern below (any case), plus one when its path matches. The
# check fails when a matching file has no line, when a file's count rises
# above its N (a new mention), when it falls below N (lower N to lock the
# cleanup in), and when a listed file no longer matches.
#
# A path written with a leading `?` names a file that only the primary
# repository carries. The primary tree is recognized by fb-only/defs.bzl:
# there, a `?` line is checked like any other, so a deleted file leaves a
# stale line. In an exported tree, which has no fb-only/, a `?` file must be
# absent and its line is skipped.
#
# Independently of the list, and with no allowlist escape, it fails when a
# dependency, patch or replace entry in a TOML manifest names a consumer
# crate or path, when a symlink's target names a consumer, and when a
# directory holding a BUCK file is not wired into the declared tree the Buck
# test checks (a layering-files group referenced from another BUCK file).
#
# Content is read in source, assembly and linker files (.rs .c .h .cc .cpp
# .hpp .S .s .py .sh .ld) and manifests and build files (.toml BUCK TARGETS
# PACKAGE .bzl), always as text, and in every other executable file unless it
# is binary. Paths are checked for every file outside documentation (*.md,
# docs/, guide/, ai_docs/). Cargo.lock is not read: crates.io's hermit-abi is
# an unrelated project.
#
# In a git checkout the files are the tracked ones plus untracked files git
# does not ignore, read from the working tree; elsewhere, every file below the
# root except version-control metadata. Either way target/ and buck-out/ at the
# root are build output and skipped.
#
# Usage: scripts/check-layering.sh [--list]
#   --list  print `path -- N` for every matching file and exit 0
# Exit status: 0 pass, 1 violation, 2 the check could not run.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd) || exit 2
cd "$root" || exit 2

allow=scripts/layering-allowlist.txt
pattern='hermit|detcore'
self='//hermetic_infra/reverie'

mode=check
if [ $# -gt 1 ]; then
    echo "usage: scripts/check-layering.sh [--list]" >&2
    exit 2
elif [ $# -eq 1 ]; then
    if [ "$1" = --list ]; then
        mode=list
    else
        echo "usage: scripts/check-layering.sh [--list]" >&2
        exit 2
    fi
fi

list_files() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git ls-files -z --cached --others --exclude-standard
    else
        find . \( -path ./.git -o -path ./.sl -o -path ./.hg \) -prune -o \
            \( -type f -o -type l \) -print0 | sed -z 's|^\./||'
    fi
}

mapfile -d '' -t files < <(list_files)
if ! wait $!; then
    echo "layering: cannot list the files below $root" >&2
    exit 2
fi

fail=0
declare -A count=()
text=()
exec_files=()
buck_files=()
for f in "${files[@]}"; do
    case "$f" in target/* | buck-out/*) continue ;; esac
    # Skip index entries deleted from the working tree, and submodules.
    [ -L "$f" ] || [ -f "$f" ] || continue
    case "$f" in
        *.md | docs/* | guide/* | ai_docs/*) ;;
        *) if [[ ${f,,} =~ $pattern ]]; then count[$f]=1; fi ;;
    esac
    if [ -L "$f" ]; then
        target=$(readlink -- "$f")
        if [[ ${target,,} =~ $pattern ]]; then
            echo "layering: symlink $f -> $target names a consumer (no allowlist line can excuse it)" >&2
            fail=1
        fi
        continue
    fi
    case "${f##*/}" in
        Cargo.lock) ;;
        *.rs | *.c | *.h | *.cc | *.cpp | *.hpp | *.S | *.s | *.py | *.sh | *.ld | \
            *.bzl | *.toml | TARGETS | PACKAGE) text+=("$f") ;;
        BUCK)
            text+=("$f")
            buck_files+=("$f")
            ;;
        *) if [ -x "$f" ]; then exec_files+=("$f"); fi ;;
    esac
done

# Count matching lines, one grep per batch; a grep error (status 2) stops
# xargs with a nonzero status.
count_matches() {
    local f n
    [ $# -gt 1 ] || return 0
    local flags=$1
    shift
    while IFS=$'\t' read -r f n; do
        if [ "$n" -gt 0 ]; then
            count[$f]=$((${count[$f]:-0} + n))
        fi
    done < <(printf '%s\0' "$@" |
        xargs -0 sh -c 'grep -c '"$flags"' -i -E -H -Z -e "$0" -- "$@"; [ $? -le 1 ] || exit 255' "$pattern" |
        tr '\0' '\t')
    if ! wait $!; then
        echo "layering: content search failed" >&2
        exit 2
    fi
}
count_matches -a "${text[@]}"
count_matches -I "${exec_files[@]}"

mapfile -t matched < <(printf '%s\n' "${!count[@]}" | sed '/^$/d' | LC_ALL=C sort)

if [ "$mode" = list ]; then
    for f in "${matched[@]}"; do
        printf '%s -- %s\n' "$f" "${count[$f]}"
    done
    exit 0
fi

for f in "${text[@]}"; do
    case "$f" in *.toml) ;; *) continue ;; esac
    if ! hits=$(awk -v pat="$pattern" '
        /^[[:space:]]*\[/ { dep = (tolower($0) ~ /dependencies|patch|replace/) }
        { key = $0; sub(/=.*/, "", key) }
        (dep || tolower(key) ~ /dependencies/) && tolower($0) ~ pat {
            printf "%s:%d: %s\n", FILENAME, FNR, $0
        }
    ' "$f"); then
        echo "layering: cannot read $f" >&2
        exit 2
    fi
    if [ -n "$hits" ]; then
        printf '%s\n' "$hits" | sed 's/^/layering: a dependency names a consumer (no allowlist line can excuse it): /' >&2
        fail=1
    fi
done

# Every package's BUCK must hold the exact glob below in its layering group,
# and every package but the root must be an entry
# `"<dir relative to its parent package>": "<self>/<dir>:layering-files"` in
# its nearest parent package's BUCK, so each group chains to the root's
# layering-tree. Comments are stripped and whitespace ignored before matching.
tree_glob='glob(["**",".*",".*/**","**/.*","**/.*/**",".*/**/.*",".*/**/.*/**"])'
flat_buck() {
    awk '{
        out = ""; in_str = 0
        for (i = 1; i <= length($0); i++) {
            c = substr($0, i, 1)
            if (in_str && c == "\\") { out = out c substr($0, i + 1, 1); i++; continue }
            if (c == "\"") in_str = !in_str
            if (!in_str && c == "#") break
            out = out c
        }
        printf "%s", out
    }' "$1" | tr -d ' \t\n'
}
declare -A is_package=()
for b in "${buck_files[@]}"; do
    case "$b" in BUCK) is_package[.]=1 ;; *) is_package[${b%/BUCK}]=1 ;; esac
done
for b in "${buck_files[@]}"; do
    if [ "$b" = BUCK ]; then
        d=.
        group='name="layering-tree"'
    else
        d=${b%/BUCK}
        group='name="layering-files"'
    fi
    flat=$(flat_buck "$b") || exit 2
    if [[ $flat != *"$group"* || $flat != *"$tree_glob"* ]]; then
        echo "layering: $b must define its layering group ($group) with $tree_glob" >&2
        fail=1
    fi
    [ "$d" != . ] || continue
    parent=${d%/*}
    [ "$parent" != "$d" ] || parent=.
    while [ "$parent" != . ] && [ -z "${is_package[$parent]+x}" ]; do
        case "$parent" in */*) parent=${parent%/*} ;; *) parent=. ;; esac
    done
    if [ "$parent" = . ]; then rel=$d; parent_buck=BUCK; else rel=${d#"$parent"/}; parent_buck=$parent/BUCK; fi
    want="\"$rel\":\"$self/$d:layering-files\""
    parent_flat=$(flat_buck "$parent_buck") || exit 2
    if [[ $parent_flat != *"$want"* ]]; then
        echo "layering: $b is not wired into the Buck tree: $parent_buck needs the entry \"$rel\": \"$self/$d:layering-files\" in its layering group" >&2
        fail=1
    fi
done

if [ ! -r "$allow" ]; then
    echo "layering: cannot read $allow" >&2
    exit 2
fi
primary=no
if [ -f fb-only/defs.bzl ]; then primary=yes; fi
declare -A listed=() optional=()
entry='^([?]?)([^[:space:]]+) -- ([1-9][0-9]*) -- (.*[^[:space:]].*)$'
n=0
while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in '' | '#'*) continue ;; esac
    if [[ ! $line =~ $entry ]]; then
        echo "layering: $allow:$n is not '[?]path -- N -- reason' with N >= 1: $line" >&2
        fail=1
        continue
    fi
    path=${BASH_REMATCH[2]}
    if [ -n "${listed[$path]+x}" ]; then
        echo "layering: $allow lists $path more than once" >&2
        fail=1
        continue
    fi
    listed[$path]=${BASH_REMATCH[3]}
    if [ -n "${BASH_REMATCH[1]}" ]; then optional[$path]=1; fi
done <"$allow"

total=0
for f in "${matched[@]}"; do
    c=${count[$f]}
    total=$((total + c))
    if [ -z "${listed[$f]+x}" ]; then
        echo "layering: $f names a consumer ($c) and is not in $allow; add a generic mechanism instead" >&2
        fail=1
    elif [ "$c" -gt "${listed[$f]}" ]; then
        echo "layering: $f has a count of $c, above its recorded ${listed[$f]}; remove the new matching lines" >&2
        fail=1
    elif [ "$c" -lt "${listed[$f]}" ]; then
        echo "layering: $f has a count of $c, below its recorded ${listed[$f]}; lower its count to $c" >&2
        fail=1
    fi
done

mapfile -t entries < <(printf '%s\n' "${!listed[@]}" | sed '/^$/d' | LC_ALL=C sort)
for f in "${entries[@]}"; do
    present=no
    if [ -e "$f" ] || [ -L "$f" ]; then present=yes; fi
    if [ -n "${optional[$f]+x}" ] && [ "$primary" = no ]; then
        if [ "$present" = yes ]; then
            echo "layering: $f is marked primary-only in $allow, but this exported tree has it" >&2
            fail=1
        fi
        continue
    fi
    [ -z "${count[$f]+x}" ] || continue
    echo "layering: $allow lists $f, which no longer names a consumer; delete its line" >&2
    fail=1
done

if [ "$fail" -eq 0 ]; then
    echo "layering: OK: ${#matched[@]} files name a consumer (total count $total); each is listed at its exact count ($([ "$primary" = yes ] && echo 'primary tree' || echo 'exported tree, primary-only lines skipped'))"
fi
exit "$fail"
