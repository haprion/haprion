# shellcheck shell=bash
#
# What haprion-setup is made of, apart from the order of the steps: the checks
# it makes before it changes anything, and the way it reports a step that did
# not complete. Sourced by haprion-setup, and by the tests that hold both.
#
# The rule they serve (B302): an error says what went wrong, why, what to do
# and where the whole story is. An exit code alone helps nobody.
#

#
# The packages that carry the commands the steps run, by command, for the
# advice when one is missing. Debian's and Ubuntu's names agree for all of them.
#
declare -A SETUP_COMMAND_PACKAGES=(
    [curl]=curl
    [git]=git
    [nginx]=nginx
    [openssl]=openssl
    [psql]=postgresql-client
    [rrsync]=rsync
    [ssh-keygen]=openssh-client
    [systemd-sysusers]=systemd
    [visudo]=sudo
)

#
# Problems found before anything is changed. Each is recorded rather than
# reported at once, so one run names all of them instead of one per attempt.
#
SETUP_PROBLEMS=()
SETUP_NOTES=()

setup_problem() {
    local what="$1" why="$2" todo="$3"
    SETUP_PROBLEMS+=("${what}"$'\n'"${why}"$'\n'"${todo}")
}

setup_note() {
    SETUP_NOTES+=("$1")
}

setup_check_distribution() {
    local release="${1:-/etc/os-release}" id codename
    # shellcheck source=/dev/null # the system's own description of itself
    id="$(. "$release" && echo "${ID:-}")"
    # shellcheck source=/dev/null
    codename="$(. "$release" && echo "${VERSION_CODENAME:-}")"
    case "${id}/${codename}" in
        debian/trixie|ubuntu/resolute) ;;
        *) setup_problem "this machine runs ${id:-an unknown system} ${codename}" \
               "the packages are built and tested for Debian 13 (trixie) and Ubuntu 26.04 (resolute) only" \
               "install the manager on one of those two" ;;
    esac
}

setup_check_commands() {
    local command
    for command in "${!SETUP_COMMAND_PACKAGES[@]}"; do
        command -v "$command" >/dev/null 2>&1 && continue
        setup_problem "the command ${command} is not installed" \
            "an installation step runs it" \
            "install it: apt install ${SETUP_COMMAND_PACKAGES[$command]}"
    done
    if ! /usr/bin/python3 -I -c 'import nacl.public' 2>/dev/null; then
        setup_problem "Python cannot use the library that seals secrets (PyNaCl)" \
            "the keys that protect DNS provider credentials and the sign-in provider's secret are made with it" \
            "install it: apt install python3-nacl"
    fi
}

#
# PostgreSQL is installed by the database step when none runs, so a machine
# without one is fine. What stops that step is a server that runs and is too
# old - asked here before anything changes. The check before (review
# 2026-10-24) asked whether postgresql.service was active: that unit is
# postgresql-common's, a placeholder always active, so it passed everywhere,
# and its advice named the package the step deliberately avoids.
#
setup_check_database() {
    local running idle
    # The same readings and floor as platform/ensure-postgresql's (a test holds
    # the two together); not in lib.sh, which the nodes' steps source too.
    running="$(pg_lsclusters --no-header 2>/dev/null | awk '$4 == "online" { print $1 }' | sort -n | tail -n 1)"
    idle="$(pg_lsclusters --no-header 2>/dev/null | awk '$4 != "online" { printf "%s%s/%s (%s)", sep, $1, $2, $4; sep = " " }')"
    if [[ -n "$running" ]] && (( ${running%%.*} < 16 )); then
        setup_problem "PostgreSQL ${running} runs here" \
            "the web interface needs PostgreSQL 16 or newer" \
            "upgrade the cluster (pg_upgradecluster), then run haprion-setup again"
    elif [[ -z "$running" && -n "$idle" ]]; then
        setup_problem "PostgreSQL is here and no cluster runs: ${idle}" \
            "a second major version would be installed beside it, on another port" \
            "start it, or promote it if it is a standby (pg_ctlcluster <version> <name> start|promote), then run haprion-setup again"
    fi
}

#
# The name the interface answers to must lead back to this machine: step 5
# proves HTTPS by asking that name, and a browser will ask it too.
#
#
# A name that resolves can still be one only this machine knows: a short name
# from /etc/hosts' 127.0.1.1 line passes the lookup, and the certificate and the
# address the nodes resolve are then made for it (26-10-18). It may work on a
# network whose DNS adds the domain, so it is a note, not a problem.
#
#
# DNS's own addresses for a name, past this machine's /etc/hosts. With
# systemd-resolved running, `getent -s dns` asks its stub, which answers from
# /etc/hosts too - Debian's 127.0.1.1 line for the machine (lab 26-10-26, F2) -
# so resolved is asked with what it makes up itself turned off.
#
setup_dns_addresses() {
    local name="$1"
    if command -v resolvectl >/dev/null && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolvectl query --synthesize=no --cache=no --legend=no -- "$name" 2>/dev/null \
            | sed -E 's/^[^[:space:]]+:[[:space:]]+//' | awk 'NF { print $1 }' || true
    else
        getent -s dns ahosts "$name" 2>/dev/null | awk '{ print $1 }' || true
    fi
}

setup_check_server_name() {
    local name="$1" addresses
    if ! addresses="$(getent ahosts "$name" 2>/dev/null)"; then
        setup_problem "the name ${name} does not resolve to an address" \
            "it is the name the web interface answers to, taken from this machine's own name (hostname -f)" \
            "add it to DNS or to /etc/hosts, or name another in an answers file: SERVER_NAME=<name>"
        return
    fi
    local advice="its certificate is made for that name, and the nodes look it up. To use another: SERVER_NAME=<name> in a file given with haprion-setup --answers <file>"
    if [[ "$name" != *.* ]]; then
        setup_note "the web interface will answer to ${name}, a name without a domain; ${advice}"
    elif ! awk '{ print $1 }' <<<"$addresses" | grep -qvE '^(127\.|::1$)'; then
        #
        # Loopback alone here may be /etc/hosts' own line for this machine -
        # Debian's installer writes 127.0.1.1 for it - while DNS gives the other
        # machines its address (lab 26-10-26). DNS is asked alone before the note.
        #
        local dns
        dns="$(setup_dns_addresses "$name")"
        if [[ -z "$dns" ]] || ! grep -qvE '^(127\.|::1$)' <<<"$dns"; then
            setup_note "${name} leads only back to this machine, so other machines cannot reach the web interface by it. Add it to DNS, or choose another name: SERVER_NAME=<name> in a file given with haprion-setup --answers <file>"
        fi
    fi
}

#
# Ports 80 and 443 belong to nginx here. Anything else listening on them
# would make step 5 fail on a reason nginx states in its own words only.
#
setup_check_ports() {
    local port holder
    for port in 80 443; do
        # Nothing listening is the usual answer, and grep then finds nothing.
        holder="$(ss -Hltnp "sport = :${port}" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -n 1 | cut -d'"' -f2 || true)"
        [[ -z "$holder" || "$holder" == nginx ]] && continue
        setup_problem "port ${port} is already in use by ${holder}" \
            "the web interface is served by nginx on ports 80 and 443" \
            "stop or move ${holder}, then run haprion-setup again"
    done
}

setup_check_clock() {
    local synced
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    if [[ "$synced" != yes ]]; then
        setup_note "the clock is not synchronised with a time server. Certificates, sign-in and the logs depend on it: apt install systemd-timesyncd"
    fi
}

#
# Where the web interface's release stands: `first` with no release active,
# `other` with another one current, `done` when current is this one already.
# Before the first activation the parts platform step 07 installs - the
# worker's unit, its sudo rules, the helper sockets - are not there yet.
#
setup_activation() {
    local ui_root="$1" release_id="$2" current
    if [[ ! -e "${ui_root}/current" && ! -L "${ui_root}/current" ]]; then
        echo first
        return
    fi
    current="$(readlink -f "${ui_root}/current" 2>/dev/null || true)"
    if [[ "$current" == "$(readlink -f "${ui_root}/releases/${release_id}")" ]]; then
        echo "done"
    else
        echo other
    fi
}

#
# A release other than the running one is an update, and an update has its own
# command: it takes a database dump, checks that the step back stays safe
# before migrating, and puts the old release back when the switch fails. Run
# here, the migration ran with the old release still serving and none of that
# (review 26-10-24, 03-08).
#
setup_check_release_switch() {
    local ui_root="$1" release_id="$2" updater="$3"
    [[ "$(setup_activation "$ui_root" "$release_id")" == other ]] || return 0
    setup_problem "this installation runs $(basename "$(readlink -f "${ui_root}/current")"), not ${release_id}" \
        "moving a running installation to another release is an update, which haprion-setup does not do" \
        "run the update instead: sudo ${updater} ${release_id}"
}

#
# The problems, all of them, in the same shape as a failed step.
#
setup_report_problems() {
    local entry what why todo count="${#SETUP_PROBLEMS[@]}"
    (( count > 0 )) || return 0
    echo
    if (( count == 1 )); then
        echo "haprion-setup changed nothing: one thing needs fixing first."
    else
        echo "haprion-setup changed nothing: ${count} things need fixing first."
    fi
    for entry in "${SETUP_PROBLEMS[@]}"; do
        { IFS= read -r what; IFS= read -r why; IFS= read -r todo; } <<<"$entry"
        echo
        echo "  What is wrong:  ${what}"
        echo "  Why it matters: ${why}"
        echo "  What to do:     ${todo}"
    done
    echo
    echo "Then run haprion-setup again."
    return 1
}

#
# A heading and its lines, the first beside the heading and the rest under it.
#
setup_lines() {
    local heading="$1" line
    shift
    printf '  %-16s %s\n' "$heading" "$1"
    shift
    for line in "$@"; do
        printf '  %-16s %s\n' "" "$line"
    done
}

#
# A step that did not complete, from its own output: the last ERROR line and
# what follows it is the step's account of why it stopped (lib.sh's die, fail
# and the trap for a command that failed without one). WHY: and TODO: lines
# are its own reason and advice; the step's advice from haprion-setup is used
# when it gave none.
#
# A die inside a command substitution is followed by the trap's line for the
# assignment it failed: the die's own words are the account, so the trap's is
# passed over when there is one before it.
#
SETUP_TRAP_LINE="the command '"

setup_report_failure() {
    local number="$1" total="$2" title="$3" advice="$4" output="$5" log="$6"
    local -a what=() why=() todo=() earlier_what=() earlier_why=() earlier_todo=()
    local -a recent=() before=()
    local line found=0
    while IFS= read -r line; do
        if [[ "$line" == "ERROR: "* ]]; then
            if (( found )); then
                earlier_what=("${what[@]}") earlier_why=("${why[@]}") earlier_todo=("${todo[@]}")
            fi
            found=1
            before=("${recent[@]}")
            what=("${line#ERROR: }") why=() todo=()
        elif (( found )); then
            case "$line" in
                "WHY: "*) why+=("${line#WHY: }") ;;
                "TODO: "*) todo+=("${line#TODO: }") ;;
                *) [[ -n "${line// /}" ]] && what+=("${line#"${line%%[![:space:]]*}"}") ;;
            esac
        fi
        #
        # The last lines before an error, for a command that said nothing of
        # its own: what it printed is then the only why there is.
        #
        if [[ -n "${line// /}" && "$line" != "ERROR: "* && "$line" != "TODO: "* && "$line" != "WHY: "* ]]; then
            recent+=("${line#"${line%%[![:space:]]*}"}")
            (( ${#recent[@]} <= 3 )) || recent=("${recent[@]:1}")
        fi
    done < "$output"
    if (( found )) && [[ "${what[0]}" == "${SETUP_TRAP_LINE}"* ]]; then
        if (( ${#earlier_what[@]} > 0 )); then
            what=("${earlier_what[@]}") why=("${earlier_why[@]}") todo=("${earlier_todo[@]}")
        else
            why=("${before[@]}") todo=()
        fi
    fi
    #
    # No ERROR line: a check that reports in its own form, such as
    # check-compatibility's PASS and FAIL. Its last line is what went wrong
    # and its FAIL lines are why (26-10-13, first machine).
    #
    if (( ! found )); then
        local -a failed=()
        what=() why=()
        while IFS= read -r line; do
            [[ -n "${line// /}" ]] || continue
            what=("${line#"${line%%[![:space:]]*}"}")
            [[ "$line" =~ ^[[:space:]]*FAIL[[:space:]] ]] && failed+=("${line#"${line%%[![:space:]]*}"}")
        done < "$output"
        (( ${#what[@]} > 0 )) || what=("the step stopped without saying why")
        (( ${#failed[@]} == 0 )) || why=("${failed[@]:0:8}")
        (( ${#failed[@]} <= 8 )) || why+=("... and $(( ${#failed[@]} - 8 )) more")
    fi
    (( ${#todo[@]} > 0 )) || todo=("$advice")

    echo
    echo "haprion-setup stopped at step ${number} of ${total}: ${title}."
    echo
    setup_lines "What went wrong:" "${what[@]}"
    (( ${#why[@]} == 0 )) || setup_lines "Why:" "${why[@]}"
    setup_lines "What to do:" "${todo[@]}"
    echo "                   Then run haprion-setup again. What is done is kept; it"
    echo "                   continues from where it stopped."
    echo
    echo "  Everything the step said is in ${log}"
}

#
# The last words of a completed run. The first account is made by step
# install-ui-release when there is none (B196), so it is asked for here only
# when the count of accounts is 0 or could not be read (26-10-14: the closing
# words asked for an account the run had just made).
#
setup_closing_words() {
    local server_name="$1" accounts="$2" clusters="${3:-}" first=yes
    #
    # The first cluster and the self-signed certificate are the first run's
    # news only. Run again on an installation with clusters, they were not
    # true (R2 26-10-26, F12). A count that could not be read is a first run.
    #
    [[ ! "$clusters" =~ ^[1-9][0-9]*$ ]] || first=no
    echo
    if [[ "$first" == yes ]]; then
        cat <<DONE
The manager is installed. The web interface is at https://${server_name}/
with a self-signed certificate until a real one is chosen under Settings, and
the commands (haprion-status, haprion-deploy, haprion-cluster ...) are ready
in /usr/bin.
DONE
    else
        cat <<DONE
The manager is installed. The web interface is at https://${server_name}/, and
the commands (haprion-status, haprion-deploy, haprion-cluster ...) are in /usr/bin.
DONE
    fi
    echo
    if [[ "$accounts" =~ ^[1-9][0-9]*$ ]]; then
        [[ "$first" == no ]] || echo "Sign in: the Dashboard sets up the first cluster."
    else
        cat <<'DONE'
There is no account to sign in with yet. Make the first administrator:

    sudo haprion-user init-admin

DONE
        if [[ "$first" == yes ]]; then
            echo "Then sign in: the Dashboard sets up the first cluster."
        else
            echo "Then sign in."
        fi
    fi
}
