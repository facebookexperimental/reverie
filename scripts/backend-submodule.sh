#!/usr/bin/env bash
set -euo pipefail

root="$(git -C "$(dirname -- "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"

usage() {
    cat >&2 <<'EOF'
usage: scripts/backend-submodule.sh <activate|deactivate|status> <backend|all>

backends:
  dynamorio   DynamoRIO source used by reverie-dbi
  sabre       SaBRe loader source used by reverie-sabre
  e9patch     e9patch source reserved for the rewriting backend
EOF
    exit 2
}

backend_path() {
    case "$1" in
        dynamorio|dbi) printf '%s\n' third-party/dynamorio ;;
        sabre) printf '%s\n' third-party/sabre ;;
        e9patch) printf '%s\n' third-party/e9patch ;;
        *) return 1 ;;
    esac
}

for_each_backend() {
    local action="$1"
    local requested="$2"
    if [[ "$requested" == all ]]; then
        "$action" dynamorio
        "$action" sabre
        "$action" e9patch
    else
        "$action" "$requested"
    fi
}

activate() {
    local backend="$1"
    local path
    path="$(backend_path "$backend")" || usage

    git -C "$root" \
        -c "submodule.${path}.update=checkout" \
        submodule update --init --checkout --depth 1 --recursive -- "$path"

    local expected actual
    expected="$(git -C "$root" rev-parse ":${path}")"
    actual="$(git -C "$root/$path" rev-parse HEAD)"
    if [[ "$actual" != "$expected" ]]; then
        echo "backend submodule $path is at $actual, expected $expected" >&2
        exit 1
    fi
    echo "$backend source ready at $path ($actual)"
}

deactivate() {
    local backend="$1"
    local path
    path="$(backend_path "$backend")" || usage
    git -C "$root" submodule deinit -f -- "$path"
}

status() {
    local backend="$1"
    local path
    path="$(backend_path "$backend")" || usage
    git -C "$root" submodule status -- "$path"
}

[[ $# -eq 2 ]] || usage
command="$1"
backend="$2"

case "$command" in
    activate) for_each_backend activate "$backend" ;;
    deactivate) for_each_backend deactivate "$backend" ;;
    status) for_each_backend status "$backend" ;;
    *) usage ;;
esac
