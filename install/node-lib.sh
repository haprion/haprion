#!/bin/bash
#
# The installation helpers a node's step needs, and the start every step
# shares: strict mode, the fixed names and defaults, log and die, the error
# trap. Sourced by lib.sh for the manager's steps, and on its own on a node.
#
# The node package carries this file and not lib.sh. Its digest is part of the
# record of which step 4 last ran (node-installation.sh), so a change made for
# the manager alone does not ask every node to run haprion-node-prepare again
# (review 26-10-25, decision point 3). A test holds this file to what the
# node's callers reach, and lib.sh to define nothing they call.

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
# A command that failed under `set -e` without a die of its own: named, with
# the step it stopped and its exit code, instead of the script ending in
# silence. Reported once, by the script itself - not again by each command
# substitution the failure passed through.
#
on_command_failed() {
    local status="$1" command="$2"
    [[ "$BASHPID" == "$$" ]] || return 0
    echo "ERROR: the command '${command}' stopped with exit code ${status}${CURRENT_STEP:+ while doing: ${CURRENT_STEP}}" >&2
}
trap 'on_command_failed "$?" "$BASH_COMMAND"' ERR

need_root() {
    [[ $EUID -eq 0 ]] || die "run this with sudo"
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
# Refuse a symbolic link where a step is about to chown or chmod a file in a
# directory an account owns or owned: both follow the link (5-14).
#
refuse_link() {
    local path
    for path; do
        [[ ! -L "$path" ]] || die "${path} is a symbolic link; refusing to change what it points at"
    done
}

#
# The home of an account reached only through forced commands: the nodes' on
# the manager, the manager's on a node. The account owns nothing in it. sshd
# accepts an authorized_keys owned by root as readily as one owned by the
# account, and a file the account cannot write is the difference between a
# forced command and a suggestion. The same goes for the home itself - an
# account that owns it could replace .ssh wholesale - and for the shell's
# dotfiles: Debian's bash sources ~/.bashrc for a command it runs on behalf of
# sshd, so a .bashrc the account could write would run before the forced
# command does.
#
# Every change is made to the path itself, never through a link: a link the
# account left in its home would have root change what it points at (review
# 26-10-24, 10-01 and 10-02). Such a link stops the step.
#
ensure_forced_home() {
    local user="$1" empty_note="$2"
    local home="/home/${user}"
    ensure_dir "$home" root:root 755
    local entry
    while IFS= read -r -d '' entry; do
        refuse_link "$entry"
        chown root:root "$entry"
        log "  claimed  ${entry}  (now root's; the account owns nothing in its home)"
    done < <(find "$home" -mindepth 1 -maxdepth 1 ! -name .ssh ! -user root -print0)
    ensure_dir "${home}/.ssh" root:root 755
    local keys="${home}/.ssh/authorized_keys"
    refuse_link "$keys"
    if [[ ! -f "$keys" ]]; then
        install -o root -g root -m 644 /dev/null "$keys"
        log "  created  ${keys}  (${empty_note})"
    else
        chown root:root "$keys"
        chmod 644 "$keys"
        log "  ok       ${keys}"
    fi
}

cluster_value() {
    local prefix="$1" cluster="$2" var
    #
    # A cluster ID may hold a hyphen, which no shell variable name may: the
    # answer for cluster `edge-a` is NODE_PATH_edge_a.
    #
    var="${prefix}_${cluster//-/_}"
    echo "${!var:-}"
}

#
# The engine's CLUSTER_ID (config.py), held to it by a test: a cluster the
# interface may create, a step on the node must accept (Fas 18 finding 55).
#
valid_id() {
    [[ "$1" =~ ^[a-z][a-z0-9-]{0,62}$ ]]
}

#
# Create a directory with an exact owner and mode, or correct one that exists.
# Reported either way, because "already correct" and "just fixed" are different
# facts to an operator reading the output.
#
ensure_dir() {
    local path="$1" owner="$2" mode="$3"
    #
    # Never through a link: chown and chmod follow one, and a directory an
    # account could replace would hand it whatever the link names (review
    # 2026-10-22, 5-14).
    #
    [[ ! -L "$path" ]] || die "${path} is a symbolic link; refusing to change what it points at"
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
        if output="$(apt-get -o Acquire::Retries=3 update -q 2>&1)"; then
            return 0
        fi
        if [[ "$output" != *"Could not get lock"* ]] || (( SECONDS - started >= APT_LOCK_SECONDS )); then
            printf '%s\n' "$output" >&2
            return 1
        fi
        sleep "$APT_LOCK_PAUSE"
    done
}
#
# What apt would install. A source that did not answer leaves `apt-get update`
# successful with a warning and the distribution's own, older package the
# candidate (apt 3.2, a 503 from Launchpad, 26-10-21): installing it and
# refusing it afterwards left the older one on the machine. Asked first.
#
apt_candidate() {
    LC_ALL=C apt-cache policy "$1" 2>/dev/null | sed -n 's/^  Candidate: //p'
}

ensure_dnsdist() {
    local hold="${1:-}" id codename version candidate
    id="$(. /etc/os-release && echo "${ID:-}")"
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    case "${id}/${codename}" in
        ubuntu/resolute|debian/trixie) ;;
        *) die "dnsdist: ${id} ${codename} is not a supported distribution (Ubuntu 26.04, Debian 13)" ;;
    esac
    install -d -o root -g root -m 755 /etc/apt/keyrings
    install_file "$DNSDIST_KEYRING" root:root 644 "$(cat ./apt-keys/powerdns-dnsdist.asc)"
    install_file /etc/apt/sources.list.d/pdns.list root:root 644 \
        "deb [signed-by=${DNSDIST_KEYRING}] https://repo.powerdns.com/${id} ${codename}-dnsdist-21 main"
    #
    # dnsdist from PowerDNS, and nothing else from it: a source this machine
    # trusts for one package could otherwise offer a newer version of any
    # other, and apt would take it (review 2026-10-22, 5-15). Measured with
    # apt-cache policy against the real source: dnsdist 600 in either order.
    #
    install_file /etc/apt/preferences.d/dnsdist-21 root:root 644 \
        "$(printf 'Package: dnsdist*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n\nPackage: *\nPin: origin repo.powerdns.com\nPin-Priority: 100')"
    if [[ "$hold" == mask ]]; then
        systemctl mask --quiet dnsdist.service
        log "  masked   dnsdist.service (the binary validates; nothing here serves dns)"
    fi
    apt_update || die "dnsdist: apt-get update failed"
    candidate="$(apt_candidate dnsdist)"
    [[ "$candidate" == 2.1.* ]] \
        || die "dnsdist: repo.powerdns.com offers no 2.1 (apt would install '${candidate:-nothing}');" \
               "check that this machine reaches it, then run this step again"
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

#
# systemd-run asks systemd over the system bus: the manager's candidate
# sandbox and a node restore's timed rollback both start that way. The bus
# the packages bring is not started until the next boot (measured on Debian
# 13, 26-10-15: dbus.socket static and inactive after apt installed it).
#
ensure_system_bus() {
    if systemctl is-active --quiet dbus.socket || systemctl is-active --quiet dbus.service; then
        log "  ok       the system bus"
        return
    fi
    systemctl start dbus.socket
    log "  started  the system bus"
}

ensure_haproxy() {
    local role="${1:-}" installed id codename key keyring suite uri pin release candidate
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
            #
            # HAProxy from the PPA, and nothing else from it (5-15). The
            # origin is the PPA's Release file's own (`LP-PPA-vbernat-haproxy-3.4`).
            #
            pin="$(printf 'Package: haproxy*\nPin: release o=LP-PPA-vbernat-haproxy-%s\nPin-Priority: 600\n\nPackage: *\nPin: release o=LP-PPA-vbernat-haproxy-%s\nPin-Priority: 100' \
                "$HAPROXY_BRANCH" "$HAPROXY_BRANCH")" ;;
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
    candidate="$(apt_candidate haproxy)"
    if [[ -z "$candidate" || "$candidate" == "(none)" ]] \
        || ! dpkg --compare-versions "$candidate" ge "${HAPROXY_BRANCH}~"; then
        die "HAProxy: ${uri} offers no ${HAPROXY_BRANCH} (apt would install '${candidate:-nothing}');" \
            "check that this machine reaches it, then run this step again"
    fi
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
    #
    # A running HAProxy keeps the command line it was started with, and its
    # reload runs that again: Debian's older unit reads no conf.d, so after
    # the upgrade no release's frontend was ever loaded (measured 26-10-15 in
    # the install test). Nothing is served here yet (above): started again,
    # from the new unit.
    #
    systemctl daemon-reload
    if systemctl is-active --quiet haproxy; then
        systemctl restart haproxy
        log "  restarted haproxy from the new package's unit"
    fi
}

#
# The manager's keys on a node (B317), one table for step 3, which prints them,
# step 4, which writes them, and the join, which is step 4 with the manager's
# answers: the purpose, the manager's key in step 3's answers, the node account
# the key reaches and the forced command it runs there. A node's answers carry
# each key as <PURPOSE>_PUBKEY. The node decides what a key may run; nothing
# the manager sends names a command.
#
# shellcheck disable=SC2034 # read by the steps that source this file
NODE_KEY_PURPOSES=(
    "DEPLOY CONFIG_DEPLOY_KEY TRIGGER_USER sudo -n /usr/sbin/haprion-pull-deploy"
    "CERT_DEPLOY CERT_DEPLOY_KEY TRIGGER_USER /usr/sbin/haprion-cert-trigger"
    "SERVER_STATE SERVER_STATE_KEY TRIGGER_USER /usr/sbin/haprion-server-state-trigger"
    "STATUS NODE_STATUS_KEY STATUS_USER sudo -n /usr/sbin/haprion-node-status --json"
    "PROBE NODE_PROBE_KEY STATUS_USER /usr/sbin/haprion-health-probe"
    "BACKUP NODE_BACKUP_KEY BACKUP_USER sudo -n /usr/sbin/haprion-state-export"
    "TRAFFIC_LOG TRAFFIC_COLLECTOR_KEY LOGREAD_USER /usr/sbin/haprion-traffic-log-read"
)
PUBKEY_PATTERN='^ssh-ed25519 [A-Za-z0-9+/]+=*$'

#
# Where the manager's keys may be used from (review 26-10-24, 10-05): its host
# and the IPv4 addresses that resolves to, as the manager binds the nodes'
# fetch keys to theirs (node_enrollment.pull_sources). sshd's UseDNS is off by
# default, so `from=` matches the connecting address and a name alone would
# lock the manager out. A manager at another address reaches no node until
# step 4 has run again on each of them (sudo haprion-node-prepare --manager <new>).
#
manager_sources() {
    local host="$1" addresses
    if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        echo "$host"
        return 0
    fi
    addresses="$(getent ahostsv4 "$host" | awk '!seen[$1]++ { printf "%s%s", sep, $1; sep = "," }')" \
        || true
    [[ -n "$addresses" ]] \
        || die "cannot resolve MANAGER_HOST ${host} to an IPv4 address; the manager's keys are bound to it"
    echo "${host},${addresses}"
}

#
# One key's line in its account's authorized_keys, written as root, usable from
# SOURCES alone (manager_sources). A line for the same forced command is
# replaced, so a rotated key does not leave the old one able to ask.
#
write_key_line() {
    local user="$1" command="$2" key="$3" sources="$4"
    [[ "$key" =~ $PUBKEY_PATTERN ]] \
        || die "a key for ${command} must be one ssh-ed25519 public key (type and key, no comment)"
    [[ "$sources" =~ ^[A-Za-z0-9.,-]+$ ]] || die "the manager's addresses are not usable: ${sources}"
    local keys="${KEYS_HOME:-/home}/${user}/.ssh/authorized_keys"
    local forced="command=\"${command}\""
    local line="from=\"${sources}\",restrict,${forced} ${key}"
    if grep -qxF "$line" "$keys"; then
        log "  ok       ${command} in ${keys}"
        return
    fi
    local tmp
    tmp="$(mktemp)"
    grep -vF "$forced" "$keys" > "$tmp" || true
    printf '%s\n' "$line" >> "$tmp"
    install -m 644 "$tmp" "$keys"
    rm -f "$tmp"
    # Root's, as the whole home is (step 4, ensure_account); KEYS_HOME is for tests.
    [[ "$EUID" -ne 0 ]] || chown root:root "$keys"
    log "  written  ${command} in ${keys}"
}

#
# A purpose's line taken out of its account's authorized_keys, written as root:
# the join's document leaves out a key the manager does not have, and a line an
# earlier manager left for that purpose would otherwise still let it ask
# (review 26-10-24, 10-04).
#
remove_key_line() {
    local user="$1" command="$2"
    local keys="${KEYS_HOME:-/home}/${user}/.ssh/authorized_keys"
    local forced="command=\"${command}\""
    if [[ ! -f "$keys" ]] || ! grep -qF "$forced" "$keys"; then
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    grep -vF "$forced" "$keys" > "$tmp" || true
    install -m 644 "$tmp" "$keys"
    rm -f "$tmp"
    [[ "$EUID" -ne 0 ]] || chown root:root "$keys"
    log "  removed  ${command} from ${keys}  (the manager sent no key for it)"
}

#
# The key a purpose's line in its account's authorized_keys carries, or nothing.
#
existing_key_of() {
    local user="$1" command="$2"
    local keys="${KEYS_HOME:-/home}/${user}/.ssh/authorized_keys"
    [[ -f "$keys" ]] || return 0
    grep -F "command=\"${command}\"" "$keys" | grep -oE 'ssh-ed25519 [A-Za-z0-9+/]+=*' \
        | head -n 1 || true
}

#
# The manager's keys, one line per purpose (NODE_KEY_PURPOSES), each usable from
# MANAGER_SOURCES alone. A key in the answers is written. A join's document is
# the whole set, so a purpose it leaves out is taken away. Otherwise - step 4
# run again, by hand or by haprion-node-prepare - the line already there is
# bound again to the manager's addresses as they are now: a manager that moved
# reached no node, and running the step again changed nothing (review 26-10-25,
# 3-01).
#
write_manager_keys() {
    local purpose_line purpose account_var command key_var key
    for purpose_line in "${NODE_KEY_PURPOSES[@]}"; do
        read -r purpose _ account_var command <<<"$purpose_line"
        key_var="${purpose}_PUBKEY"
        key="${!key_var:-}"
        if [[ -z "$key" ]]; then
            if [[ "${JOINED_BY_MANAGER:-}" == yes ]]; then
                remove_key_line "${!account_var}" "$command"
                continue
            fi
            key="$(existing_key_of "${!account_var}" "$command")"
            [[ -n "$key" ]] || continue
        fi
        write_key_line "${!account_var}" "$command" "$key" "$MANAGER_SOURCES"
    done
}

#
# A key pair this node authenticates with, made here and never anywhere else:
# a private key a node uses has no reason to exist on the management host.
#
generate_pull_key() {
    local path="$1" comment="$2"
    if [[ -f "$path" ]]; then
        log "  ok       ${path}"
        return
    fi
    install -o root -g root -m 700 -d "$(dirname "$path")"
    ssh-keygen -t ed25519 -N "" -C "$comment" -f "$path" >/dev/null
    chown root:root "$path" "${path}.pub"
    chmod 600 "$path"
    chmod 644 "${path}.pub"
    log "  created  ${path}"
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
