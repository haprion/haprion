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

# shellcheck source=accounts.sh
source "$(dirname "${BASH_SOURCE[0]}")/accounts.sh"

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
#
# The project's accounts and groups (B266): one sysusers fragment from
# install/sysusers/, installed where systemd reads it at boot and applied now.
# systemd-sysusers creates what is missing and leaves what exists - an account
# made by an earlier installation keeps its UID and everything it owns.
#
apply_sysusers() {
    local fragment="$1" target
    #
    # Created when absent: a host that has never had a local fragment may not
    # have the directory at all (a node, 26-10-09). SYSUSERS_DIR is for tests.
    #
    local directory="${SYSUSERS_DIR:-/etc/sysusers.d}"
    install -d -m 755 "$directory"
    target="${directory}/$(basename "$fragment")"
    [[ -f "$fragment" ]] || die "missing ${fragment}"
    install_file "$target" root:root 644 "$(cat "$fragment")"
    systemd-sysusers "$target" || die "systemd-sysusers could not apply ${target}"
    log "  applied  ${target}"
}

load_answers() {
    local file="${1:-}" name
    [[ -n "$file" ]] || die "usage: $(basename "$0") <answers-file>"
    [[ -r "$file" ]] || die "answers file not readable: $file"
    #
    # Account, group and database names are fixed since B266 (accounts.sh). An
    # answers file still setting one is from before that, and is refused by name
    # rather than failing on a readonly variable or being silently overruled.
    #
    for name in "${RETIRED_ANSWERS[@]}"; do
        if grep -Eq "^[[:space:]]*(export[[:space:]]+)?${name}=" "$file"; then
            die "${file} sets ${name}, which is no longer an answer (B266): names and places are fixed.
  Remove the line; see install/accounts.sh for what is used now."
        fi
    done
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
#
# One value from /etc/haprion/ui-admin.conf, read rather than run. The file
# names DB_NAME, which accounts.sh holds read-only, so sourcing it from a step
# is fatal (26-10-09). The last assignment wins, as it would in a shell.
#
admin_value() {
    sed -n "s/^${2}=//p" "$1" | tail -n 1
}

#
# The port the web service listens on, read from ui.toml by the running
# release's own parser - the file the service itself reads, so a health check
# cannot ask a port the service was never told.
#
#
# The import package of the UI release a Python interpreter belongs to, asked of
# the release itself: the package behind its `haprion-worker` command. A release
# this one replaces or rolls back to may call its package something else; the
# command is what every release has. The same function in lib.sh,
# haprion-rollback and haprion-web, held together by a test.
#
release_module() {
    "$1" -I -c 'from importlib.metadata import entry_points
print(entry_points(group="console_scripts")["haprion-worker"].module.partition(".")[0])'
}

ui_port() {
    local python="${UI_ROOT}/current/venv/bin/python" module
    module="$(release_module "$python")" || return 1
    "$python" -I -c 'import importlib, sys; from pathlib import Path
load = importlib.import_module(sys.argv[1] + ".config").load
print(load(Path(sys.argv[2])).listen.port)' "$module" "$UI_CONFIG"
}

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
# The nginx lines that let a reverse proxy in front of the interface name the
# client (TRUSTED_PROXIES in the answers file, INSTALLATION 4.5). Only a
# connection from one of these addresses has its X-Forwarded-For believed; a
# client that reaches nginx directly and sends the header is still known by
# its own address. With `real_ip_recursive` the client is the last address in
# the header that is not a trusted proxy, so a value a client put in the
# header before it reached the proxy is skipped rather than believed.
#
# Addresses and networks only: a host name would be resolved once, when nginx
# starts, and "every address" would let anyone name any client.
#
render_real_ip() {
    local entry count=0
    local -a entries
    read -ra entries <<<"$1"
    echo "# Written by 05-platform-nginx from TRUSTED_PROXIES. Edit the answers file, not this."
    for entry in "${entries[@]}"; do
        if ! python3 -c 'import ipaddress, sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
sys.exit(1 if network.prefixlen == 0 else 0)' "$entry" 2>/dev/null; then
            echo "TRUSTED_PROXIES: ${entry} is not an address or a network narrower than every address" >&2
            return 1
        fi
        echo "set_real_ip_from ${entry};"
        count=$((count + 1))
    done
    if ((count > 0)); then
        echo "real_ip_header X-Forwarded-For;"
        echo "real_ip_recursive on;"
    fi
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
# Rollback copies, `<file>.replaced-<yyyymmdd-hhmmss>`, are kept for
# REPLACED_KEEP_DAYS and then removed by the next step that writes the same
# file - the only time a new one appears, so nothing else has to run for it.
# The newest copy of each file always stays, however old: a file that is
# rarely changed keeps the version before its last change. The age is the
# time in the name, not the file's own: `cp -a` keeps the original's mtime.
#
REPLACED_KEEP_DAYS=30

prune_replaced() {
    local path="$1" cutoff index
    local -a copies
    cutoff="$(date -d "-${REPLACED_KEEP_DAYS} days" +%Y%m%d-%H%M%S)"
    mapfile -t copies < <(
        compgen -G "${path}.replaced-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]" \
            | LC_ALL=C sort
    )
    for ((index = 0; index < ${#copies[@]} - 1; index++)); do
        [[ "${copies[index]##*.replaced-}" < "$cutoff" ]] || continue
        rm -f -- "${copies[index]}"
        log "  pruned   ${copies[index]}"
    done
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
        prune_replaced "$path"
        return
    fi
    [[ -f "$path" ]] && cp -a "$path" "${path}.replaced-$(date +%Y%m%d-%H%M%S)"
    printf '%s\n' "$content" > "$path"
    chown "$owner" "$path"
    chmod "$mode" "$path"
    log "  written  ${path}"
    prune_replaced "$path"
}

#
# dnsdist, from PowerDNS's own repository (B249): what serves a dns listener on
# the nodes, and what validates one on the manager. The key ships with the
# product beside this file and a test holds it to its fingerprint,
# 9FAA A557 7E8F CF62 093D  036C 1B0C 6205 FD38 0FBB; it is never fetched here.
# The file names are PowerDNS's own instructions', so a host where someone
# followed them by hand is taken over rather than given a second source.
#
# `mask` keeps the service from ever starting - the manager runs only the
# binary. Without it the node's drop-in decides (see 04-node-prepare).
#
DNSDIST_KEYRING="/etc/apt/keyrings/dnsdist-21-pub.asc"
#
# Wait for the package lock rather than fail on it: Ubuntu's unattended
# upgrades hold it for minutes at a time, and a node preparation that stopped
# on it left the node half-way (26-10-08). Ten minutes, then the error
# as before. apt 3.2's `DPkg::Lock::Timeout`, for `apt-get install`.
#
APT_LOCK_SECONDS=600
APT_LOCK_PAUSE=10
APT_WAIT=(-o "DPkg::Lock::Timeout=${APT_LOCK_SECONDS}")

#
# `apt-get update` takes the lists lock, which `DPkg::Lock::Timeout` does not
# cover: apt 3.2 gives up on it at once (measured 26-10-08). It is the lock
# Ubuntu's daily apt run holds on a fresh VM's first boot, so the update is
# asked again while the lock is all that stops it, as long as an install waits.
#
apt_update() {
    local started=$SECONDS output
    while true; do
        if output="$(apt-get update -q 2>&1)"; then
            return 0
        fi
        if [[ "$output" != *"Could not get lock"* ]] || (( SECONDS - started >= APT_LOCK_SECONDS )); then
            printf '%s\n' "$output" >&2
            return 1
        fi
        sleep "$APT_LOCK_PAUSE"
    done
}
ensure_dnsdist() {
    local hold="${1:-}" id codename version
    id="$(. /etc/os-release && echo "${ID:-}")"
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    case "${id}/${codename}" in
        ubuntu/resolute|debian/trixie) ;;
        *) die "dnsdist: ${id} ${codename} is not a supported distribution (Ubuntu 26.04, Debian 13)" ;;
    esac
    install -d -o root -g root -m 755 /etc/apt/keyrings
    install_file "$DNSDIST_KEYRING" root:root 644 "$(cat ./apt-keys/powerdns-dnsdist.asc)"
    install_file /etc/apt/sources.list.d/pdns.list root:root 644 \
        "deb [signed-by=${DNSDIST_KEYRING}] http://repo.powerdns.com/${id} ${codename}-dnsdist-21 main"
    install_file /etc/apt/preferences.d/dnsdist-21 root:root 644 \
        "$(printf 'Package: dnsdist*\nPin: origin repo.powerdns.com\nPin-Priority: 600')"
    if [[ "$hold" == mask ]]; then
        systemctl mask --quiet dnsdist.service
        log "  masked   dnsdist.service (the binary validates; nothing here serves dns)"
    fi
    apt_update || die "dnsdist: apt-get update failed"
    DEBIAN_FRONTEND=noninteractive apt-get "${APT_WAIT[@]}" install -y -q dnsdist >/dev/null \
        || die "dnsdist: the package could not be installed"
    version="$(dnsdist --version 2>/dev/null | head -n 1)"
    [[ "$version" == "dnsdist 2.1."* ]] || die "dnsdist: expected the 2.1 series, found '${version}'"
    log "  ok       ${version%% (*}"
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
    node_conf="# Node configuration for Haprion. Rendered by install/04-node-prepare.
#
# Read by the node-side scripts in /usr/sbin. Root-owned and not writable
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
    if [[ -n "${NODE_CERT_PULL_KEY:-}" ]]; then
        node_conf+="

# Where this node fetches certificates from. A separate account and key: a node
# that may read configuration has no business reading certificates it was not
# asked for.
CERT_PULL_USER=\"${CERT_PULL_USER}\"
CERT_PULL_KEY=\"${NODE_CERT_PULL_KEY}\""
    fi
    printf '%s\n' "$node_conf"
}
