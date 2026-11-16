#!/usr/bin/env bash
# The Rustfmt gate for the Reverie workspace: the workspace pass plus a
# direct check of every file reached only through include!.
#
# cargo fmt follows module declarations, including #[path] modules, but
# it does not expand include!, so a file reached only through include!
# is never parsed by the workspace pass. reverie-liteinst's guest bins
# reach their bodies that way (`mod real { include!("real_bodies/<bin>.rs"); }`),
# so derive every literal include! target under reverie-liteinst/src/bin
# and check those files directly; rustfmt follows each one's own
# #[path] modules from there. The include targets elsewhere in the
# workspace (in reverie-kvm, reverie-linuxemu, reverie-ptrace,
# safeptrace and others) remain outside this gate.
#
# Callers: validate.sh, the DAG node in ci/dag/validate.json, and the
# nightly GitHub workflow's format step. Keep all three on this script
# so the copies cannot drift. The edition is reverie-liteinst's
# edition in its Cargo.toml, read there, not a second copy.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

rc=0
cargo fmt --all -- --check || rc=$?

edition=$(sed -n 's/^edition = "\([0-9]*\)".*/\1/p' reverie-liteinst/Cargo.toml | head -n 1)
if [[ -z $edition ]]; then
    echo "rustfmt gate: could not read the edition from reverie-liteinst/Cargo.toml" >&2
    exit 1
fi

# Scan with the exit status kept: a scan that fails, or finds nothing,
# is a refusal, not a pass. An include! line the literal form below
# cannot parse also refuses, by file, so a new spelling cannot slip
# past silently.
sites=$(grep -rn 'include!(' reverie-liteinst/src/bin) || {
    echo "rustfmt gate: the include! scan failed" >&2
    exit 1
}
if [[ -z $sites ]]; then
    echo "rustfmt gate: the include! scan found no sites" >&2
    exit 1
fi
targets=()
while IFS= read -r line; do
    file=${line%%:*}
    rest=${line#*include!(\"}
    if [[ $rest == "$line" ]]; then
        echo "rustfmt gate: unparsed include! form in $file: $line" >&2
        exit 1
    fi
    target=${rest%%\"*}
    if [[ $target != *.rs ]]; then
        echo "rustfmt gate: unparsed include! form in $file: $line" >&2
        exit 1
    fi
    dir=$(dirname "$file")
    targets+=("$dir/$target")
done <<< "$sites"
if ((${#targets[@]} == 0)); then
    echo "rustfmt gate: the include! scan found no targets" >&2
    exit 1
fi

rustfmt --edition "$edition" --check "${targets[@]}" || {
    status=$?
    if ((rc == 0)); then
        rc=$status
    fi
}
exit $rc
