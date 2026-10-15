#!/bin/bash
#
# Shared helpers for the installation scripts. Sourced, never executed.
#
# Two rules the scripts follow, and this file exists to make cheap:
#
#   * everything is idempotent. Running a script twice must be safe, because a
#     failed installation is resumed by running it again, not by unpicking it
#   * nothing is prompted for. All input comes from the answers file, or from
#     the defaults in defaults.sh when there is none, so what a script is about
#     to do can be reviewed before it does it

# shellcheck shell=bash

set -Eeuo pipefail

# shellcheck source=accounts.sh
source "$(dirname "${BASH_SOURCE[0]}")/accounts.sh"
# shellcheck source=defaults.sh
source "$(dirname "${BASH_SOURCE[0]}")/defaults.sh"

#
# What the script is doing right now, in words, for an error that has no words
# of its own (B302: an exit code alone helps nobody).
#
CURRENT_STEP=""

#
# Where the operator ran the step from. Every script that sources this file
# first does  cd "$(dirname "$0")"  (a test holds them to it), and that cd
# leaves the caller's directory in OLDPWD - so an answers file named relative
# to where the operator stood is still found.
#
CALLER_DIR="${OLDPWD:-$PWD}"
caller_path() { if [[ "$1" == /* ]]; then echo "$1"; else echo "${CALLER_DIR}/$1"; fi; }

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
step() { CURRENT_STEP="$*"; echo; echo "== $*"; }
warn() { echo "WARNING: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

#
# An error in three parts, the shape haprion-setup shows: what went wrong, why,
# and what to do about it. Every line is prefixed so the setup command can
# lift them out of a step's log.
#
fail() {
    local what="$1" why="${2:-}" todo="${3:-}" line
    echo "ERROR: ${what}" >&2
    # One prefix a line: a reason taken from a journal may be several.
    while IFS= read -r line; do
        [[ -z "$line" ]] || echo "WHY: ${line}" >&2
    done <<<"$why"
    while IFS= read -r line; do
        [[ -z "$line" ]] || echo "TODO: ${line}" >&2
    done <<<"$todo"
    exit 1
}

#
# Restart units and, when one does not come up, say why in the unit's own
# words: systemctl answers only "the control process exited with error code",
# and the reason - a path the sandbox cannot open, a missing file - is in the
# journal (26-10-13, the first machine).
#
restart_units() {
    local unit
    systemctl restart "$@" 2>/dev/null && return 0
    for unit in "$@"; do
        systemctl is-active --quiet "$unit" && continue
        fail "${unit} did not start" "$(unit_failure "$unit")" \
             "correct what the lines above name, then run this step again
the unit's whole journal: journalctl -u ${unit} -n 50"
    done
}

#
# The journal lines that say why a unit failed, without systemd's own
# bookkeeping around them: the last three different ones, in the order they
# were last said, since a unit that restarts says the same thing on every
# attempt.
#
unit_failure() {
    journalctl -u "$1" -n 200 -o cat --no-pager 2>/dev/null \
        | grep -Ev '^(Starting |Started |Stopped |Stopping |Failed to start |.*: Scheduled restart job|.*: Main process exited|.*: Failed with result|.*: Consumed )' \
        | tac | awk '!seen[$0]++' | tac | tail -n 3 || true
}

#
# A command that failed under `set -e` without a die of its own: named, with
# the step it stopped and its exit code, instead of the script ending in
# silence. Reported once, by the script itself - not again by each command
# substitution the failure passed through.
#
on_command_failed() {
    local status="$1" command="$2"
    [[ "$BASHPID" == "$$" ]] || return 0
    echo "ERROR: the command '${command}' stopped with exit code ${status}${CURRENT_STEP:+ while doing: ${CURRENT_STEP}}" >&2
    echo "TODO: the lines above it in this output are that command's own words" >&2
}
trap 'on_command_failed "$?" "$BASH_COMMAND"' ERR

need_root() {
    [[ $EUID -eq 0 ]] || die "run this with sudo"
}

need_not_root() {
    [[ $EUID -ne 0 ]] || die "run this as yourself, not with sudo"
}

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

#
# The answers file is optional (B302): without one the defaults in defaults.sh
# are the answers, and with one they fill in only what it leaves unset.
#
# The file is shell, so a typo is a syntax error rather than a silently empty
# variable. It is sourced in a subshell first to check exactly that.
#
load_answers() {
    local file="${1:-}" name
    # "-" stands for no file, for the steps that take a second argument.
    if [[ -z "$file" || "$file" == - ]]; then
        apply_default_answers
        return
    fi
    file="$(caller_path "$file")"
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
    apply_default_answers
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

#
# What the worker's sandbox opens beyond the product's own directories, read
# from the runtime policy by the current release (haprion.config,
# worker_writable_paths). One line, space separated.
#
worker_writable_paths() {
    "${UI_ROOT}/current/venv/bin/python" -I -c 'from haprion.config import load_policy, worker_writable_paths
print(" ".join(str(path) for path in worker_writable_paths(load_policy())))'
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

#
# True when PATH is still exactly the configuration file PACKAGE installed:
# dpkg records each conffile's MD5, and nothing else could have written those
# bytes. A file somebody changed is theirs and stays where it is.
#
is_packaged_conffile() {
    local package="$1" path="$2" recorded
    recorded="$(dpkg-query -W -f='${Conffiles}\n' "$package" 2>/dev/null \
        | awk -v path="$path" '$1 == path { print $2; exit }')"
    [[ -n "$recorded" && -f "$path" && ! -L "$path" ]] \
        && [[ "$(md5sum < "$path" | cut -d' ' -f1)" == "$recorded" ]]
}

#
# An empty directory that dpkg records as the package's own - nothing a person
# put there.
#
is_packaged_empty_dir() {
    local package="$1" path="$2"
    [[ -d "$path" && ! -L "$path" && -z "$(ls -A "$path")" ]] || return 1
    dpkg-query -S "$path" 2>/dev/null \
        | awk -v path="$path" -v package="$package" -F': ' '
            $2 == path { n = split($1, owners, ", "); for (i = 1; i <= n; i++) if (owners[i] == package) found = 1 }
            END { exit !found }'
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
    # A fresh machine may not have the directory yet (/etc/haprion on a new
    # node, Fas 18 finding 22); the caller's own ensure_dir, where there is
    # one, still sets what it should be.
    [[ -d "${path%/*}" ]] || ensure_dir "${path%/*}" root:root 755
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

#
# HAProxy from its maintainer's repository, on the branch the product is built
# for: what the configuration it generates needs (shm-stats-file, among
# others), and what the distributions' own packages are older than - Debian 13
# ships 3.0, Ubuntu 26.04 3.2 (Fas 18, 26-10-15). The same key, source and pin
# a restored node gets, from `haproxy_repository.repository_files`; a test
# holds the two to the same bytes.
#
# Only where HAProxy is older than the branch. A host that already runs it,
# from whatever source a person chose, is left exactly as it is: keeping
# HAProxy current stays with the operator (the manual's "Keeping HAProxy
# current"). And on a node, only while it serves no release - an upgrade
# restarts the data plane, which this step never does to live traffic.
#
HAPROXY_BRANCH="3.4"
OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
HAPROXY_CURRENT="${HAPROXY_CURRENT:-/etc/haproxy/current}"

haproxy_key() {
    local name="$1" found
    for found in "./apt-keys/${name}" "../src/haprion/apt-keys/${name}"; do
        [[ -r "$found" ]] && { echo "$found"; return 0; }
    done
    die "HAProxy: the repository key ${name} is not beside this step"
}

ensure_haproxy() {
    local role="${1:-}" installed id codename key keyring suite uri pin release
    installed="$(dpkg-query -W -f='${Version}' haproxy 2>/dev/null || true)"
    if [[ -n "$installed" ]] && dpkg --compare-versions "$installed" ge "${HAPROXY_BRANCH}~"; then
        log "  ok       haproxy ${installed}"
        return 0
    fi
    if [[ "$role" == node ]]; then
        release="$(readlink -e "$HAPROXY_CURRENT" 2>/dev/null || true)"
        if [[ -n "$release" && "${release##*/}" != 00000000-000000 ]]; then
            fail "HAProxy ${installed:-(none)} is older than ${HAPROXY_BRANCH}, and this node serves a release" \
                 "upgrading it restarts HAProxy, which this step does not do to a node carrying traffic" \
                 "upgrade HAProxy to ${HAPROXY_BRANCH} in a maintenance window, then run this step again"
        fi
    fi
    id="$(sed -n 's/^ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$OS_RELEASE")"
    codename="$(sed -n 's/^VERSION_CODENAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$OS_RELEASE")"
    case "${id}/${codename}" in
        ubuntu/resolute)
            key="haproxy-ubuntu-ppa.asc"
            uri="https://ppa.launchpadcontent.net/vbernat/haproxy-${HAPROXY_BRANCH}/ubuntu"
            suite="${codename}"
            pin="" ;;
        debian/trixie)
            key="haproxy-debian-net.asc"
            uri="https://haproxy.debian.net"
            suite="${codename}-backports-${HAPROXY_BRANCH}"
            #
            # haproxy.debian.net marks its suites NotAutomatic; without the pin
            # APT keeps Debian's own older HAProxy.
            #
            pin="$(printf 'Package: haproxy*\nPin: release o=PPA-haproxy,n=%s\nPin-Priority: 600' "$suite")" ;;
        *) die "HAProxy: ${id} ${codename} is not a supported distribution (Ubuntu 26.04, Debian 13)" ;;
    esac
    keyring="/etc/apt/keyrings/${key}"
    install -d -o root -g root -m 755 /etc/apt/keyrings
    install_file "$keyring" root:root 644 "$(cat "$(haproxy_key "$key")")"
    install_file "/etc/apt/sources.list.d/haproxy-${HAPROXY_BRANCH}.sources" root:root 644 \
        "$(printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nSigned-By: %s' \
            "$uri" "$suite" "$keyring")"
    [[ -z "$pin" ]] \
        || install_file "/etc/apt/preferences.d/haproxy-${HAPROXY_BRANCH}.pref" root:root 644 "$pin"
    apt_update || die "HAProxy: apt-get update failed"
    #
    # `confold`: a node's haproxy.cfg is a link into the release by now, which
    # dpkg reads as a changed configuration file and would otherwise ask about.
    #
    DEBIAN_FRONTEND=noninteractive apt-get "${APT_WAIT[@]}" \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        install -y -q haproxy >/dev/null \
        || die "HAProxy: the package could not be installed from ${uri}"
    installed="$(dpkg-query -W -f='${Version}' haproxy 2>/dev/null || true)"
    dpkg --compare-versions "$installed" ge "${HAPROXY_BRANCH}~" \
        || die "HAProxy: expected ${HAPROXY_BRANCH} or newer, found '${installed}'"
    log "  ok       haproxy ${installed} (from ${uri})"
}

#
# The clusters the cluster file holds and the nodes of one, through the
# engine's own reader: what Create cluster and the Nodes card have made, not
# what an answers file named at installation (B302). For the steps that run
# after the engine is installed.
#
CLUSTER_CONFIG="${CLUSTER_CONFIG:-/opt/haprion/current/bin/haprion-cluster-config}"
installed_clusters() {
    "$CLUSTER_CONFIG" --list \
        || fail "the cluster file could not be read" \
                "haprion-cluster-config --list did not answer; its own words are above" \
                "run sudo haprion-cluster-config --list and correct what it names"
}
installed_nodes() {
    "$CLUSTER_CONFIG" -c "$1" --field nodes \
        || fail "the nodes of cluster ${1} could not be read" \
                "haprion-cluster-config did not answer; its own words are above" \
                "run sudo haprion-cluster-config -c ${1} --field nodes and correct what it names"
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
# clusters.yaml as step 2 writes it, from the answers loaded. A function of its
# own so a test can hold it to the engine's reader (B302).
#
render_cluster_file() {
    local clusters_yaml cluster nodes node_path vip cert_ids default_cert display pair name host id
    #
    # Built as text rather than with a YAML library: this script runs before the
    # application is necessarily installed, and adding a Python dependency to step 2
    # would mean the installation could not repair itself.
    #
    clusters_yaml="# Cluster definitions. Rendered by install/02-manager-config.
#
# Every path here must stay inside the roots named in runtime-policy.yaml. The
# code refuses any path that escapes its root, so this file cannot widen the
# boundary - only use it.

schema_version: 1
"

    #
    # No cluster is a valid installation (B302): the first one is created in the
    # interface, Settings - Create cluster, which writes its entry here.
    #
    if [[ -z "$(each_cluster)" ]]; then
        clusters_yaml+="
clusters: {}"
    else
        clusters_yaml+="
clusters:"
    fi

    for cluster in $(each_cluster); do
        nodes="$(cluster_value NODES "$cluster")"
        [[ -n "$nodes" ]] || die "NODES_${cluster} is not set"
        node_path="$(cluster_value NODE_PATH "$cluster")"
        [[ -n "$node_path" ]] || die "NODE_PATH_${cluster} is not set"
        vip="$(cluster_value VIP "$cluster")"
        # The engine reads every cluster's VIP: it is what deploy checks ownership of.
        [[ -n "$vip" ]] || die "VIP_${cluster} is not set; every cluster needs its virtual address"
        cert_ids="$(cluster_value CERTIFICATE_IDS "$cluster")"
        default_cert="$(cluster_value DEFAULT_CERTIFICATE "$cluster")"

        display="$(tr '[:lower:]' '[:upper:]' <<<"${cluster:0:1}")${cluster:1}"

        clusters_yaml+="
  ${cluster}:
    display_name: ${display}"
        clusters_yaml+="
    vip: ${vip}"
        clusters_yaml+="
    config_path: ${CONFIG_ROOT}/${cluster}
    publish_path: ${PUBLISH_ROOT}/${cluster}
    node_path: ${node_path}
    nodes:"

        for pair in $nodes; do
            name="$(node_name "$pair")"
            host="$(node_host "$pair")"
            [[ "$name" != "$host" ]] || die "NODES_${cluster} entry '${pair}' is not name:hostname"
            clusters_yaml+="
      - name: ${name}
        mgmt_host: ${host}"
        done

        clusters_yaml+="
    validation_certs: ${VALIDATION_ROOT}/certs"

        if [[ -n "$cert_ids" ]]; then
            clusters_yaml+="
    certificate_ids:"
            for id in $cert_ids; do
                clusters_yaml+="
      - ${id}"
            done
            [[ -n "$default_cert" ]] && clusters_yaml+="
    default_certificate: ${default_cert}"
        fi
    done
    printf '%s\n' "$clusters_yaml"
}

#
# runtime-policy.yaml as step 2 writes it. Reads the DNS keys step 15 made, and
# nothing else from the machine.
#
render_policy() {
    local policy file
    local -a dns_keys
    policy="# Runtime policy. Rendered by install/02-manager-config.
#
# This is the outer path boundary, not a convenience file. Paths in
# ${CLUSTER_FILE}
# are refused if they fall outside the roots named here.
#
# Requirements the code enforces: root-owned, a regular file, not group- or
# world-writable, at most 1 MiB, schema_version exactly 1.

schema_version: 1

cluster_file: ${CLUSTER_FILE}
config_root: ${CONFIG_ROOT}
publish_root: ${PUBLISH_ROOT}
validation_certs_root: ${VALIDATION_ROOT}

deploy_identity:
  key: \"${KEY_DIR}/${CONFIG_DEPLOY_KEY}\""

    if [[ -n "${CERTIFICATE_ROOT:-}" ]]; then
        policy+="

# Central certificate distribution. Shared with whatever issues certificates,
# which is why certificate deploy syncs only what a cluster references.
certificate_root: ${CERTIFICATE_ROOT}

# A separate identity: a key that can push configuration must not be able to
# push certificates.
cert_deploy_identity:
  key: \"${KEY_DIR}/${CERT_DEPLOY_KEY}\"

# Which certificates exist, where each one goes and how it is renewed. Written
# by the certificate flows; Create cluster needs it (Fas 18, finding 3).
certificate_registry: ${CERTIFICATE_REGISTRY}"
        if [[ -n "${RECEIVER_ROOT:-}" ]]; then
            policy+="

# Where certificates for machines other than the nodes are published.
receiver_root: ${RECEIVER_ROOT}"
        fi
        #
        # The certbot platform step 14 installs, at the path it always installs it
        # at, and the keys step 15 made for sealing DNS provider credentials -
        # every one there is, since a profile may be sealed against any of them.
        # Without the profile block the interface cannot issue through a DNS
        # provider; without certbot named it would use the distribution's.
        #
        dns_keys=()
        while IFS= read -r file; do
            [[ -n "$file" ]] && dns_keys+=("$file")
        done < <(find "${DNS_PROFILE_KEYS:-${UI_SECRETS}/dns-profile-keys}" -maxdepth 1 -name '*.key' -type f 2>/dev/null | LC_ALL=C sort)
        policy+="

# Issuing certificates from the interface.
acme:
  certbot: /opt/haprion-certbot/current/venv/bin/certbot"
        if (( ${#dns_keys[@]} > 0 )); then
            policy+="
  dns_profiles:
    directory: /etc/haprion/dns-profiles
    private_keys:"
            for file in "${dns_keys[@]}"; do
                policy+="
      - ${file}"
            done
        fi
    fi

    #
    # The keys step 3 makes, named here so that the commands find them. Until
    # 2026-10-09 this step wrote neither status_identity nor probe_identity, and
    # `haprion-status` - which refuses to run without the first - did not work on a
    # manager built from these scripts until the lines were added by hand.
    #
    if [[ -n "${NODE_STATUS_KEY:-}" ]]; then
        policy+="

# Reads node status and nothing else; haprion-deploy reads with it too.
status_identity:
  key: \"${KEY_DIR}/${NODE_STATUS_KEY}\""
    fi

    if [[ -n "${NODE_PROBE_KEY:-}" ]]; then
        policy+="

# Asks a node to try a health check; the same account as status, its own key.
probe_identity:
  key: \"${KEY_DIR}/${NODE_PROBE_KEY}\""
    fi

    if [[ -n "${SERVER_STATE_KEY:-}" ]]; then
        policy+="

# Drain, maintenance and ready per server (B263); the trigger account, its own key.
server_state_identity:
  key: \"${KEY_DIR}/${SERVER_STATE_KEY}\""
    fi

    if [[ -n "${BACKUP_ROOT:-}" ]]; then
        policy+="

# Node state archives contain password hashes and private SSH keys. A separate
# forced-command identity fetches them, and only root can traverse this root.
backup_root: ${BACKUP_ROOT}
backup_identity:
  key: \"${KEY_DIR}/${NODE_BACKUP_KEY}\""
    fi
    printf '%s\n' "$policy"
}

#
# The operator editing policy as step 2 writes it: the editors, and a sudoedit
# rule for each path given. With no path - no cluster yet - only the editors:
# sudo refuses an empty alias, and Create cluster adds the alias and its rule
# with the first cluster's files (cluster_definition.sudoers_with, which a
# test holds to this).
#
render_edit_policy() {
    local editors="$1" i last
    shift
    local -a entries=()
    for i in "$@"; do
        entries+=("    sudoedit ${i}")
    done
    last=$(( ${#entries[@]} - 1 ))
    echo "# Installed by install/02-manager-config. Do not edit by hand."
    echo "#"
    echo "# Editing the handwritten configuration without a root shell."
    echo "#"
    echo "# Every path is named in full. Adding a handwritten fragment means"
    echo "# adding a line here first; REMOVING one means removing its line in"
    echo "# the same change, because sudoedit creates a file it does not find."
    echo "#"
    echo "User_Alias HAPROXY_EDITORS = ${editors}"
    if (( ${#entries[@]} > 0 )); then
        echo
        #
        # Every continued line needs its own trailing backslash, and the last
        # entry must not have one - which is also why a rule is removed by
        # rewriting the whole alias rather than by deleting its line.
        #
        echo "Cmnd_Alias HAPROXY_EDIT = \\"
        for i in "${!entries[@]}"; do
            if (( i < last )); then
                printf '%s, \\\n' "${entries[$i]}"
            else
                printf '%s\n' "${entries[$i]}"
            fi
        done
        echo
        echo "HAPROXY_EDITORS ALL = (root) HAPROXY_EDIT"
    fi
}

#
# The certificate registry a new installation starts with: no receivers and no
# certificates. Created by step 2 when missing, never rewritten.
#
render_certificate_registry() {
    printf '%s\n' "# Certificate registry. Written by the certificate flows; created empty by install/02-manager-config.

schema_version: 1
receivers: {}
certificates: {}"
}

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
