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
#
# What a node's step needs is in node-lib.sh, sourced first; this file adds
# what only the manager's steps use.

# shellcheck shell=bash

# shellcheck source=node-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/node-lib.sh"
# shellcheck source=defaults.sh
source "$(dirname "${BASH_SOURCE[0]}")/defaults.sh"

counted() { if [[ "$1" == 1 ]]; then echo "1 $2"; else echo "$1 ${3:-$2s}"; fi; }  # "1 row", "2 rows"

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

need_not_root() {
    [[ $EUID -ne 0 ]] || die "run this as yourself, not with sudo"
}

#
# A tmpfiles fragment from install/tmpfiles/, installed where systemd reads it
# at boot and applied now. TMPFILES_DIR is for tests.
#
apply_tmpfiles() {
    local fragment="$1" target
    target="${TMPFILES_DIR:-/etc/tmpfiles.d}/$(basename "$fragment")"
    [[ -f "$fragment" ]] || die "missing ${fragment}"
    install_file "$target" root:root 644 "$(cat "$fragment")"
    systemd-tmpfiles --create "$target" || die "systemd-tmpfiles could not apply ${target}"
    log "  applied  ${target}"
}

#
# The directories the worker's sandbox opens, made by step 07 and again by
# every update before it installs the worker's unit: a release whose unit opens
# one more would otherwise stop at a directory only the step makes (review
# 26-10-24, 14-02). `ReadWritePaths` names them without the leading dash on
# purpose (see the unit), so a path that does not exist stops the unit from
# starting at all rather than being skipped in silence. The import store is
# defined by the registry (user-manual.md, 'The certificate registry') and
# stays empty until the import helper exists; the deletion helper removes from
# it, so the unit opens it, and it has to be here before the unit is.
# Root-only, like the profile directory. The distribution root is checked by
# step 14.
#
ensure_worker_directories() {
    ensure_dir /etc/haprion/certificates root:root 700
    ensure_dir /etc/haprion/ndes-profiles root:root 700
    ensure_dir /etc/haprion/ndes-requests root:root 700
    # Step 15's, as it makes it; that step is optional and may come later.
    ensure_dir /etc/haprion/dns-profiles root:root 700
    #
    # Where the helpers behind sockets keep their answers for recovery (B367):
    # root's, read by the worker. Not in the worker's ReadWritePaths - it only
    # reads, and ProtectSystem=strict leaves /var/lib readable.
    #
    ensure_dir /var/lib/haprion/answers "root:${WORKER_USER}" 750
    #
    # Certbot's own three, made with the owner and mode certbot gives them when
    # they are missing - on a new machine no certbot has run yet, and the worker
    # would not start (26-10-13). Never corrected when they exist: they are
    # certbot's, and step 14 checks them.
    #
    local path
    for path in /etc/letsencrypt:755 /var/lib/letsencrypt:755 /var/log/letsencrypt:700; do
        if [[ -d "${path%:*}" ]]; then
            log "  ok       ${path%:*}"
        else
            install -d -o root -g root -m "${path##*:}" "${path%:*}"
            log "  created  ${path%:*}"
        fi
    done
}

#
# The identity directories of the optional steps 13 and 17, where that step
# ran: root's, open to the one account that reads them. An account that owned
# its directory could put a link where a step then changes owner and mode
# (review 2026-10-22, 5-14); an installation made before that is given the
# same by its next update (review 26-10-24, 14-02).
#
ensure_identity_directories() {
    if [[ -d /etc/haprion/traffic-collector ]]; then
        ensure_dir /etc/haprion/traffic-collector "root:${COLLECTOR_USER}" 550
    fi
    if [[ -d /etc/haprion/oidc ]]; then
        ensure_dir /etc/haprion/oidc "root:${OIDC_USER}" 550
    fi
}

#
# Indirect lookup of a per-cluster answer, e.g. cluster_value NODES alpha.
#
#
# One value from /etc/haprion/ui-admin.conf, read rather than run. The file
# names DB_NAME, which accounts.sh holds read-only, so sourcing it from a step
# is fatal (26-10-09). The last assignment wins, as it would in a shell.
#
#
# A root-owned KEY=value file a platform step wrote (ui-admin.conf, ui-tls.conf),
# read as haprion.admin_file reads it: comments, blank lines and plain
# assignments, anything else refused rather than interpreted, the last of a key
# winning. Only the keys named are set, as variables of the caller. The same
# function in install/lib.sh and in each command under install/platform/bin/
# that reads one, held together by a test (review 2026-10-22, 6-10).
#
read_admin_file() {
    local file="$1" line number=0 key
    local pattern='^([A-Z][A-Z0-9_]*)=([A-Za-z0-9_./:@+,=-]+)$'
    shift
    while IFS= read -r line || [[ -n "$line" ]]; do
        number=$((number + 1))
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == "#"* ]] && continue
        if [[ ! "$line" =~ $pattern ]]; then
            echo "ERROR: ${file}:${number}: not a plain assignment" >&2
            return 78
        fi
        for key; do
            if [[ "${BASH_REMATCH[1]}" == "$key" ]]; then
                printf -v "$key" '%s' "${BASH_REMATCH[2]}"
            fi
        done
    done < "$file"
    return 0
}

admin_value() {
    (
        read_admin_file "$1" "$2" || exit
        printf '%s\n' "${!2:-}"
    )
}

#
# A table in ui.toml (FILE), read by TOML's own parser rather than by a line match:
# `[oidc]  # comment` is a table a match missed, and the step then added a
# second one, which the web refuses to start with (review 26-10-24, 15-05).
# Succeeds when the file has TABLE, with its KEY - empty when it has none - in
# UI_TOML_VALUE; fails when it has not. A file that does not parse stops the
# step.
#
ui_toml_table() {
    local file="$1" table="$2" key="${3:-}" status=0
    # shellcheck disable=SC2034 # read by the steps that call this
    UI_TOML_VALUE="$(python3 -I -c 'import sys
import tomllib

path, table, key = sys.argv[1:4]
try:
    with open(path, "rb") as handle:
        section = tomllib.load(handle).get(table)
except (OSError, tomllib.TOMLDecodeError) as error:
    print(error, file=sys.stderr)
    sys.exit(2)
if not isinstance(section, dict):
    sys.exit(1)
value = section.get(key) if key else None
print(value if isinstance(value, str) else "")' "$file" "$table" "$key")" || status=$?
    (( status <= 1 )) || die "${file} does not parse as TOML; correct it and run the step again"
    return "$status"
}

#
# ui.toml (FILE) with TABLE and its LINES added at the end - a TOML file may always
# end with a new table - and proved to parse before it is installed.
#
add_ui_toml_table() {
    local file="$1" table="$2" lines="$3" content
    content="$(cat "$file")

[${table}]
${lines}"
    printf '%s\n' "$content" | python3 -I -c 'import sys
import tomllib

tomllib.loads(sys.stdin.read())' \
        || die "${file} would not parse with [${table}] added; nothing was changed"
    install_file "$file" "root:${PLATFORM_GROUP}" 640 "$content"
}

#
# The units a restore stopped and did not start again, one per line; the same
# path as RESTORE_STOPPED in haprion-backup, held together by a test. The file
# exists from the restore's first stop until a restore finishes.
#
# shellcheck disable=SC2034 # read by update-platform-release
RESTORE_STOPPED=/run/haprion/restore-stopped
RELEASE_LOCK=/run/haprion/ui-release.lock
#
# One change of the UI release at a time (review 26-10-29, A10): an update,
# a rollback, an activation or a setup run beside another paused the worker
# twice - the first one's resume lifting the second's pause mid-restart - and
# switched `current` in no order. Held on descriptor 9 until the command
# exits. A command it starts inherits the descriptor, and `flock` on that same
# descriptor succeeds where a second opening of the file fails. The same
# function in lib.sh and haprion-rollback, held together by a test.
#
hold_release_lock() {
    local holder mask again="run this again when it is done"
    if [[ "$(readlink "/proc/$$/fd/9" 2>/dev/null || true)" == "$RELEASE_LOCK" ]] && flock -n 9; then
        return 0
    fi
    mkdir -p -- "${RELEASE_LOCK%/*}"
    #
    # Root's alone: `flock` takes a file opened for reading too, and so any
    # account that could read it held every change off (review 26-10-29,
    # AA06). Made 0600: /run is emptied at every boot, and a `chmod` after
    # making it left a moment any account could open it in, the descriptor
    # outliving the `chmod` (AAA03). Set on the file each time too, for one an
    # older release made 0644.
    #
    mask="$(umask)"
    umask 077
    exec 9>>"$RELEASE_LOCK"
    umask "$mask"
    chmod 600 -- "$RELEASE_LOCK"
    if ! flock -n 9; then
        holder="$(head -1 "$RELEASE_LOCK" 2>/dev/null || true)"
        [[ -z "${DPKG_MAINTSCRIPT_PACKAGE:-}" ]] || again="when it is done: sudo dpkg --configure -a"
        die "another change of the UI release is running (pid ${holder:-unknown} or a command it started); ${again}"
    fi
    printf '%s\n' "$$" > "$RELEASE_LOCK"
}

#
# The import package of the UI release a Python interpreter belongs to, asked of
# the release itself: the package behind its `haprion-worker` command. A release
# this one replaces or rolls back to may call its package something else; the
# command is what every release has. The same function in lib.sh,
# haprion-backup, haprion-rollback and haprion-web, held together by a test.
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
    "${1:-${UI_ROOT}/current/venv/bin/python}" -I -c 'from haprion.config import load_policy, worker_writable_paths
print(" ".join(str(path) for path in worker_writable_paths(load_policy())))'
}

#
# A platform example with the accounts its step names put in: each step that
# installs one replaces TOKEN with ${TOKEN}, and the update installs them again
# without the step (review 2026-10-22, 6-5). A test holds the steps to this list.
#
render_example() {
    sed -e "s|WEB_USER|${WEB_USER}|g" \
        -e "s|WORKER_USER|${WORKER_USER}|g" \
        -e "s|OIDC_USER|${OIDC_USER}|g" \
        -e "s|COLLECTOR_USER|${COLLECTOR_USER}|g" \
        "$1"
}

#
# The nginx site, from the three values step 05 keeps in /etc/haprion/ui-tls.conf.
#
render_site() {
    local host="$1" certificate="$2" key="$3" example="$4"
    sed -e "s|SERVER_NAME|${host}|g" \
        -e "s|TLS_CERT|${certificate}|g" \
        -e "s|TLS_KEY|${key}|g" \
        "$example"
}

#
# The interface's HSTS line, from HSTS= in /etc/haprion/ui-tls.conf: yes or no,
# no when absent (review 26-10-24, 09-03). Written by platform step 05, by every
# update (refresh-platform-files) and by `haprion-tls hsts`; the copy in
# lib.sh and the one in haprion-tls are held to one text by a test.
#
hsts_snippet() {
    case "${1:-no}" in
        yes)
            printf '%s\n' "# Written from HSTS=yes in /etc/haprion/ui-tls.conf (haprion-tls hsts)." \
                'add_header Strict-Transport-Security "max-age=31536000" always;'
            ;;
        no)
            printf '%s\n' "# Written from HSTS=no in /etc/haprion/ui-tls.conf (haprion-tls hsts)."
            ;;
        *)
            echo "HSTS must be yes or no, not ${1}" >&2
            return 1
            ;;
    esac
}

#
# The web's only listener (haprion-web.socket): the socket nginx proxies to and
# the platform steps ask /healthz over, which only root and nginx's group may
# open (review 2026-10-22, 5-8).
#
# shellcheck disable=SC2034 # read by the platform steps that source lib.sh
WEB_SOCKET=/run/haprion-web.sock

valid_abs_path() {
    [[ "$1" == /* && "$1" != *".."* ]]
}

#
# The nginx lines that let a reverse proxy in front of the interface name the
# client (TRUSTED_PROXIES in the answers file; see
# user-manual.md, 'Behind another reverse proxy'). Only a
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
        [[ -n "$nodes" ]] || die "NODES_${cluster//-/_} is not set"
        node_path="$(cluster_value NODE_PATH "$cluster")"
        [[ -n "$node_path" ]] || die "NODE_PATH_${cluster//-/_} is not set"
        vip="$(cluster_value VIP "$cluster")"
        # The engine reads every cluster's VIP: it is what deploy checks ownership of.
        [[ -n "$vip" ]] || die "VIP_${cluster//-/_} is not set; every cluster needs its virtual address"
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
