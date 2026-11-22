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
# format steps of the nightly and extended GitHub workflows. Keep all
# four on this script so the copies cannot drift. The edition is
# reverie-liteinst's edition in its Cargo.toml, read there, not a second
# copy.
#
# Both passes run ONE pinned formatter, never the rustfmt or cargo fmt
# that PATH, rust-toolchain.toml or RUSTUP_TOOLCHAIN would pick:
# rustfmt.toml's doc-comment formatting, import grouping and
# one-import-per-item options are nightly-only, and the stable
# toolchain's rustfmt formats as if they were absent. The pin is
# ci/rustfmt-toolchain.toml: a nightly channel and the exact
# `rustfmt --version` line of its rustfmt. The toolchain is found in
# this order: REVERIE_RUSTFMT_TOOLCHAIN, a toolchain root holding
# bin/rustfmt and bin/cargo-fmt (for an environment without rustup);
# else rustup, running the pinned channel with auto-install off. The
# gate then runs that root's bin/cargo-fmt (with RUSTFMT set to a
# wrapper around its bin/rustfmt, described below) and bin/rustfmt by
# absolute path. A missing toolchain, a
# missing executable, or a rustfmt whose version line is not the pinned
# one exits 2 before anything is checked. The gate never installs a
# toolchain; the refusal names the command that does.
#
# `rustfmt-gate.sh --fix` formats instead of checking: the same pinned
# formatter, the same configuration and the same files, without
# --check. It is for a person reformatting the tree; no caller passes
# it, so every gate run is check-only.
#
# Files whose bytes cannot change yet (another file pins their sha256)
# are listed in ci/rustfmt-exclusions.txt, one
# `PATH REASON` per line, and both passes skip exactly those. rustfmt
# takes `ignore` only from a configuration file and resolves its entries
# against that file's directory, so the gate writes
# .tmp-rustfmt-gate-PID.toml into the repository root (gitignored,
# removed on exit): rustfmt.toml unchanged plus an `ignore` list of the
# listed paths, passed to both passes as --config-path. Before checking,
# the list must parse (each entry a repository-relative .rs path, listed
# once, with the reason `sha256-pinned in FILE[ and FILE...]`), every
# listed path must be a file whose sha256 each FILE contains (an entry
# nothing pins is refused: format that file instead; no FILE may be the
# list itself or a listed file, by path or as the same file), rustfmt.toml must
# set no `ignore` of its own, and the `ignore` list read back from the
# written file must be exactly the list; any failure exits 2 before
# anything is checked. `rustfmt-gate.sh --check-exclusions` runs those
# checks alone.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

EXCLUSIONS=ci/rustfmt-exclusions.txt
PIN=ci/rustfmt-toolchain.toml
refuse() {
    echo "rustfmt gate: $*" >&2
    exit 2
}

# No argument: check. --check-exclusions: the list checks alone, with no
# formatter. --fix: format with the pinned formatter instead of checking.
mode=check
if (($# > 1)); then
    refuse "takes at most one argument (--check-exclusions or --fix), got $#"
fi
case ${1:-} in
    "") ;;
    --check-exclusions) mode=exclusions ;;
    --fix) mode=fix ;;
    *) refuse "unknown argument \`$1\` (expected none, --check-exclusions or --fix)" ;;
esac

# The exclusion list: `PATH REASON` lines, PATH the first
# whitespace-delimited field and REASON the rest of the line, trimmed;
# `#` comment lines and blank lines are skipped. A line with a tab is
# refused, comment lines included: fbsource's linter refuses tabs in text
# files. rustfmt reads `ignore` entries as gitignore patterns, so a path
# with a pattern character, or with no `/` (which gitignore matches by
# name in every directory), would exclude more than one file.
[[ -f $EXCLUSIONS ]] || refuse "no $EXCLUSIONS"
pattern_chars='[][[:space:]*?!#"\]'
excluded=()
# The list's own path, compared with every FILE a reason names.
list_file=$EXCLUSIONS
pin_lines=()
pin_owners=()
pin_files=()
declare -A listed=()
number=0
while IFS= read -r line || [[ -n $line ]]; do
    number=$((number + 1))
    if [[ $line == *$'\t'* ]]; then
        refuse "$EXCLUSIONS:$number: has a tab; separate PATH and REASON with spaces (fbsource's linter refuses tabs in text files)"
    fi
    [[ $line == \#* || -z ${line//[[:space:]]/} ]] && continue
    if [[ $line == [[:space:]]* ]]; then
        refuse "$EXCLUSIONS:$number: starts with whitespace (expected PATH REASON)"
    fi
    path=${line%%[[:space:]]*}
    reason=${line#"$path"}
    reason=${reason#"${reason%%[![:space:]]*}"}
    reason=${reason%"${reason##*[![:space:]]}"}
    if [[ -z $reason ]]; then
        refuse "$EXCLUSIONS:$number: \`$path\` has no reason (expected PATH REASON)"
    fi
    if [[ $path != */* ]]; then
        refuse "$EXCLUSIONS:$number: \`$path\` has no \`/\`; rustfmt would read it as a pattern matching that name in every directory"
    fi
    if [[ $path != *.rs || $path == /* || /$path/ == *//* || /$path/ == */./* ||
        /$path/ == */../* || $path =~ $pattern_chars ]]; then
        refuse "$EXCLUSIONS:$number: \`$path\` is not a repository-relative .rs path free of gitignore pattern characters"
    fi
    if [[ -n ${listed[$path]:-} ]]; then
        refuse "$EXCLUSIONS:$number: \`$path\` is listed twice"
    fi
    listed[$path]=1
    if [[ ! -f $path || -L $path ]]; then
        refuse "$EXCLUSIONS:$number: \`$path\` is missing or not a regular file"
    fi
    # The one reason an entry may give: the files holding its sha256.
    pinned_in=${reason#sha256-pinned in }
    if [[ $pinned_in == "$reason" || -z $pinned_in ]]; then
        refuse "$EXCLUSIONS:$number: \`$path\`'s reason \`$reason\` is not \`sha256-pinned in FILE[ and FILE...]\`"
    fi
    pins=()
    while :; do
        pins+=("${pinned_in%% and *}")
        [[ $pinned_in == *" and "* ]] || break
        pinned_in=${pinned_in#* and }
    done
    digest=$(sha256sum -- "$path") || refuse "$EXCLUSIONS:$number: sha256sum $path failed"
    digest=${digest%% *}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || refuse "$EXCLUSIONS:$number: sha256sum $path printed no digest"
    for pin in "${pins[@]}"; do
        if [[ -z $pin || $pin =~ [[:space:]] || $pin == /* || /$pin/ == *//* ||
            /$pin/ == */./* || /$pin/ == */../* ]]; then
            refuse "$EXCLUSIONS:$number: \`$path\`'s reason \`$reason\` names a FILE that is not a repository-relative path"
        fi
        # The list cannot vouch for its own entries: a comment in it could
        # hold any digest.
        if [[ $pin == "$list_file" ]]; then
            refuse "$EXCLUSIONS:$number: \`$path\`'s reason names $EXCLUSIONS, the list itself; the list cannot vouch for its own entries"
        fi
        if [[ ! -f $pin || -L $pin ]]; then
            refuse "$EXCLUSIONS:$number: \`$path\`'s reason names \`$pin\`, which is missing or not a regular file"
        fi
        if [[ $pin -ef $list_file ]]; then
            refuse "$EXCLUSIONS:$number: \`$path\`'s reason names \`$pin\`, which is the same file as \`$EXCLUSIONS\`; neither the list nor a listed file can pin an entry"
        fi
        pin_lines+=("$number")
        pin_owners+=("$path")
        pin_files+=("$pin")
        if ! grep -qF -- "$digest" "$pin"; then
            refuse "$EXCLUSIONS:$number: \`$path\`'s sha256 $digest is not in \`$pin\`, so its reason does not hold; format the file and delete its entry instead"
        fi
    done
    excluded+=("$path")
done < "$EXCLUSIONS"
# Nor can a listed file, which itself escapes formatting, by path or as the
# same file under another name (a hard link).
for i in "${!pin_files[@]}"; do
    for other in "${excluded[@]}"; do
        if [[ ${pin_files[i]} == "$other" ]]; then
            refuse "$EXCLUSIONS:${pin_lines[i]}: \`${pin_owners[i]}\`'s reason names \`$other\`, which is itself listed; a listed file cannot pin an entry"
        fi
        if [[ ${pin_files[i]} -ef $other ]]; then
            refuse "$EXCLUSIONS:${pin_lines[i]}: \`${pin_owners[i]}\`'s reason names \`${pin_files[i]}\`, which is the same file as \`$other\`; neither the list nor a listed file can pin an entry"
        fi
    done
done

# The configuration both passes use: rustfmt.toml unchanged plus an
# `ignore` list of exactly the listed paths.
[[ -f rustfmt.toml ]] || refuse "no rustfmt.toml in $ROOT"
if grep -Eq '^[[:space:]]*ignore[[:space:]]*=' rustfmt.toml; then
    refuse "rustfmt.toml sets \`ignore\`; the only files the gate may skip are $EXCLUSIONS's"
fi
config=$ROOT/.tmp-rustfmt-gate-$$.toml
trap 'rm -f -- "$config"' EXIT
{
    cat rustfmt.toml
    [[ -z $(tail -c 1 rustfmt.toml) ]] || echo
    printf '\n# Generated by scripts/rustfmt-gate.sh from %s.\nignore = [\n' "$EXCLUSIONS"
    for path in "${excluded[@]}"; do
        printf '    "%s",\n' "$path"
    done
    printf ']\n'
} > "$config" || refuse "cannot write $config"
# Read the written file back: one `ignore` key, its entries exactly the
# list, and rustfmt.toml unchanged before it.
keys=$(grep -Ec '^[[:space:]]*ignore[[:space:]]*=' "$config")
ignored=$(sed -n '/^ignore = \[$/,/^\]$/s/^    "\(.*\)",$/\1/p' "$config")
expected=
if ((${#excluded[@]} > 0)); then
    expected=$(printf '%s\n' "${excluded[@]}")
fi
if [[ $keys != 1 || $ignored != "$expected" ]]; then
    refuse "$config ignores [${ignored//$'\n'/ }], but $EXCLUSIONS lists [${excluded[*]}]"
fi
if ! cmp -s -n "$(wc -c < rustfmt.toml)" rustfmt.toml "$config"; then
    refuse "$config does not start with rustfmt.toml unchanged"
fi
if [[ $mode == exclusions ]]; then
    echo "rustfmt gate: $EXCLUSIONS is consistent: ${#excluded[@]} excluded file(s), each a file with a reason, and exactly those in the generated \`ignore\` list"
    exit 0
fi

# The pin: two keys, `channel` and `identity`, each exactly once, as
# `key = "value"`; `#` comment lines and blank lines are skipped.
[[ -f $PIN ]] || refuse "no $PIN"
pin_line='^([a-z]+)[[:space:]]*=[[:space:]]*"([^"]+)"$'
channel=
identity=
number=0
while IFS= read -r line || [[ -n $line ]]; do
    number=$((number + 1))
    trimmed=${line#"${line%%[![:space:]]*}"}
    trimmed=${trimmed%"${trimmed##*[![:space:]]}"}
    [[ -z $trimmed || $trimmed == \#* ]] && continue
    if [[ ! $trimmed =~ $pin_line ]]; then
        refuse "$PIN:$number: expected \`key = \"value\"\`, found \`$trimmed\`"
    fi
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    case $key in
        channel)
            [[ -z $channel ]] || refuse "$PIN:$number: \`channel\` is set twice"
            channel=$value
            ;;
        identity)
            [[ -z $identity ]] || refuse "$PIN:$number: \`identity\` is set twice"
            identity=$value
            ;;
        *) refuse "$PIN:$number: unknown key \`$key\`" ;;
    esac
done < "$PIN"
[[ -n $channel ]] || refuse "$PIN: no \`channel\`"
[[ -n $identity ]] || refuse "$PIN: no \`identity\`"

# The toolchain root: REVERIE_RUSTFMT_TOOLCHAIN, else rustup running the
# pinned channel. rustup must not install it: with RUSTUP_AUTO_INSTALL=0
# an absent channel is a refusal, not a download.
install_hint="rustup toolchain install $channel --profile minimal --component rustfmt"
if [[ -n ${REVERIE_RUSTFMT_TOOLCHAIN:-} ]]; then
    source_desc="REVERIE_RUSTFMT_TOOLCHAIN=$REVERIE_RUSTFMT_TOOLCHAIN"
    toolchain_root=$REVERIE_RUSTFMT_TOOLCHAIN
elif rustup_bin=$(type -P rustup); then
    source_desc="rustup run $channel"
    toolchain_root=$(RUSTUP_AUTO_INSTALL=0 "$rustup_bin" run "$channel" rustc --print sysroot) ||
        refuse "\`rustup run $channel rustc --print sysroot\` failed: the pinned formatter's toolchain is not usable here, and the gate never installs it. Install it with \`$install_hint\`, or set REVERIE_RUSTFMT_TOOLCHAIN to a toolchain root holding bin/rustfmt and bin/cargo-fmt"
else
    refuse "no pinned formatter: REVERIE_RUSTFMT_TOOLCHAIN is unset and there is no rustup, and the gate never uses a rustfmt found on PATH. Install rustup and run \`$install_hint\`, or set REVERIE_RUSTFMT_TOOLCHAIN to a toolchain root holding bin/rustfmt and bin/cargo-fmt"
fi
toolchain_root=$(CDPATH='' cd -P -- "$toolchain_root" && pwd -P) ||
    refuse "$source_desc: the toolchain root is not a directory"
rustfmt_bin=$toolchain_root/bin/rustfmt
cargo_fmt_bin=$toolchain_root/bin/cargo-fmt
for bin in "$rustfmt_bin" "$cargo_fmt_bin"; do
    if [[ ! -f $bin || ! -x $bin ]]; then
        refuse "$source_desc: no executable $bin (with rustup: \`rustup component add rustfmt --toolchain $channel\`)"
    fi
done
# The identity: the exact `rustfmt --version` line the pin names.
found=$("$rustfmt_bin" --version) || refuse "$rustfmt_bin --version failed"
if [[ $found != "$identity" ]]; then
    refuse "refusing the formatter from $source_desc: its rustfmt --version is \`$found\`, but $PIN pins \`$identity\` (channel $channel)"
fi
echo "rustfmt gate: formatter $rustfmt_bin ($identity)" >&2

# cargo fmt runs rustfmt once per edition and returns the first nonzero
# exit code among those runs, so a rustfmt killed by a signal (an abort
# on a failed allocation, an out-of-memory kill), which leaves no exit
# code, counts as a pass, and every file it had not reached goes
# unchecked. The workspace pass therefore runs rustfmt through a
# wrapper, .tmp-rustfmt-gate-PID.rustfmt beside the configuration
# (gitignored, removed on exit), that returns bash's status for the run:
# 128 plus the signal number for a death by signal, a failure named on
# stderr. The direct pass below sees that status itself.
wrapper=$ROOT/.tmp-rustfmt-gate-$$.rustfmt
trap 'rm -f -- "$config" "$wrapper"' EXIT
cat > "$wrapper" << 'EOF' || refuse "cannot write $wrapper"
#!/usr/bin/env bash
"$REVERIE_RUSTFMT_GATE_RUSTFMT" "$@"
status=$?
if ((status > 128)); then
    echo "rustfmt gate: $REVERIE_RUSTFMT_GATE_RUSTFMT ended with status $status (signal $((status - 128))) before checking every file it was given" >&2
fi
exit "$status"
EOF
chmod u+x "$wrapper" || refuse "cannot make $wrapper executable"

check=(--check)
if [[ $mode == fix ]]; then
    check=()
fi

rc=0
REVERIE_RUSTFMT_GATE_RUSTFMT=$rustfmt_bin RUSTFMT=$wrapper "$cargo_fmt_bin" --all -- "${check[@]}" --config-path "$config" || rc=$?

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

"$rustfmt_bin" --edition "$edition" "${check[@]}" --config-path "$config" "${targets[@]}" || {
    status=$?
    if ((rc == 0)); then
        rc=$status
    fi
}
exit $rc
