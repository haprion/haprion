#!/bin/bash
#
# Shared helpers for the installation scripts. Sourced, never executed.
#
# Two rules the scripts follow, and this file exists to make cheap:
#
#   * everything is idempotent. Running a script twice must be safe, because a
#     failed installation is resumed by running it again, not by unpicking it
#   * nothing is prompted for. All input comes from the answers file, so what a
#     script is about to do can be reviewed before it does it

# shellcheck shell=bash

set -Eeuo pipefail

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
step() { echo; echo "== $*"; }
warn() { echo "WARNING: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

need_root() {
    [[ $EUID -eq 0 ]] || die "run this with sudo"
}

need_not_root() {
    [[ $EUID -ne 0 ]] || die "run this as yourself, not with sudo"
}

#
# The answers file is shell, so a typo is a syntax error rather than a silently
# empty variable. It is sourced in a subshell first to check exactly that.
#
load_answers() {
    local file="${1:-}"
    [[ -n "$file" ]] || die "usage: $(basename "$0") <answers-file>"
    [[ -r "$file" ]] || die "answers file not readable: $file"
    ( set -e; # shellcheck disable=SC1090
      source "$file" ) >/dev/null 2>&1 || die "answers file is not valid shell: $file"
    # shellcheck disable=SC1090
    source "$file"
}

require_vars() {
    local name
    for name in "$@"; do
        [[ -n "${!name:-}" ]] || die "${name} is not set in the answers file"
    done
}

#
# Indirect lookup of a per-cluster answer, e.g. cluster_value NODES alpha.
#
cluster_value() {
    local prefix="$1" cluster="$2" var
    var="${prefix}_${cluster}"
    echo "${!var:-}"
}

valid_id() {
    [[ "$1" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]]
}

valid_abs_path() {
    [[ "$1" == /* && "$1" != *".."* ]]
}

#
# Create a directory with an exact owner and mode, or correct one that exists.
# Reported either way, because "already correct" and "just fixed" are different
# facts to an operator reading the output.
#
ensure_dir() {
    local path="$1" owner="$2" mode="$3"
    if [[ -d "$path" ]]; then
        local current
        current="$(stat -c '%U:%G %a' "$path")"
        if [[ "$current" == "${owner} ${mode}" ]]; then
            log "  ok       ${path}"
            return
        fi
        chown "$owner" "$path"
        chmod "$mode" "$path"
        log "  fixed    ${path}  (was ${current})"
        return
    fi
    mkdir -p "$path"
    chown "$owner" "$path"
    chmod "$mode" "$path"
    log "  created  ${path}"
}

ensure_group() {
    local group="$1"
    if getent group "$group" >/dev/null; then
        log "  ok       group ${group}"
    else
        groupadd --system "$group"
        log "  created  group ${group}"
    fi
}

#
# Write a file only if its content would change, so reruns do not churn
# timestamps and so the output says something true.
#
install_file() {
    local path="$1" owner="$2" mode="$3" content="$4"
    if [[ -f "$path" ]] && [[ "$(cat "$path")" == "$content" ]]; then
        chown "$owner" "$path"
        chmod "$mode" "$path"
        log "  ok       ${path}"
        return
    fi
    [[ -f "$path" ]] && cp -a "$path" "${path}.replaced-$(date +%Y%m%d-%H%M%S)"
    printf '%s\n' "$content" > "$path"
    chown "$owner" "$path"
    chmod "$mode" "$path"
    log "  written  ${path}"
}

each_cluster() {
    local cluster
    for cluster in $CLUSTERS; do
        valid_id "$cluster" || die "invalid cluster id: ${cluster}"
        echo "$cluster"
    done
}

#
# "node-a:node-a.example.com" -> name and management hostname.
#
node_name() { echo "${1%%:*}"; }
node_host() { echo "${1##*:}"; }

#
# node.conf as 04-node-prepare installs it, from the answers already loaded.
# Its own function so a node restore can be held to it: the restore derives an
# answers file from an archived node.conf, and a test renders that file back
# through exactly this template and expects the same bytes.
#
render_node_conf() {
    local cluster="$1" node_path="$2" logread_group="$3" node_conf
    node_conf="# Node configuration for haproxy-manager. Rendered by install/04-node-prepare.
#
# Read by the node-side scripts in /usr/local/sbin. Root-owned and not writable
# by anyone else: it names the account and key used to fetch configuration, so
# whoever can edit it can redirect this node to another source.

CLUSTER=\"${cluster}\"
MANAGER=\"${MANAGER_HOST}\"

# Where this node fetches its published configuration from.
CONFIG_PULL_USER=\"${PULL_USER}\"
CONFIG_PULL_KEY=\"${NODE_CONFIG_PULL_KEY}\"
CONFIG_REMOTE_PATH=\"${cluster}/current/${node_path}/\"

# Local accounts and groups a state backup captures. A rebuilt node with no way
# to log in is not a restored node, so operator accounts belong here too.
BACKUP_SERVICE_ACCOUNTS=\"${TRIGGER_USER} ${STATUS_USER} ${BACKUP_USER} ${LOGREAD_USER}\"
BACKUP_ACCOUNTS=\"${TRIGGER_USER} ${STATUS_USER} ${BACKUP_USER} ${LOGREAD_USER}${OPERATOR_ACCOUNTS:+ ${OPERATOR_ACCOUNTS}}\"
BACKUP_GROUPS=\"${logread_group}${EXTRA_BACKUP_GROUPS:+ ${EXTRA_BACKUP_GROUPS}}\"

# The operator's own files a state backup carries besides the product's -
# absolute paths, space-separated. A listed path that is missing fails the backup.
EXTRA_BACKUP_PATHS=\"${EXTRA_BACKUP_PATHS:-}\""
    if [[ -n "${CERT_PULL_USER:-}" ]]; then
        node_conf+="

# Where this node fetches certificates from. A separate account and key: a node
# that may read configuration has no business reading certificates it was not
# asked for.
CERT_PULL_USER=\"${CERT_PULL_USER}\"
CERT_PULL_KEY=\"${NODE_CERT_PULL_KEY}\""
    fi
    printf '%s\n' "$node_conf"
}
