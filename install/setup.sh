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

setup_check_database() {
    if ! systemctl is-active --quiet postgresql; then
        setup_problem "the PostgreSQL database server is not running" \
            "the web interface keeps its users, jobs and history in it" \
            "install and start it: apt install postgresql, then systemctl enable --now postgresql"
    fi
}

#
# The name the interface answers to must lead back to this machine: step 5
# proves HTTPS by asking that name, and a browser will ask it too.
#
setup_check_server_name() {
    local name="$1"
    if ! getent ahosts "$name" >/dev/null 2>&1; then
        setup_problem "the name ${name} does not resolve to an address" \
            "it is the name the web interface answers to, taken from this machine's own name (hostname -f)" \
            "add it to DNS or to /etc/hosts, or name another in an answers file: SERVER_NAME=<name>"
    fi
}

#
# Ports 80 and 443 belong to nginx here. Anything else listening on them
# would make step 5 fail on a reason nginx states in its own words only.
#
setup_check_ports() {
    local port holder
    for port in 80 443; do
        holder="$(ss -Hltnp "sport = :${port}" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -n 1 | cut -d'"' -f2)"
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
    (( found )) || what=("the step stopped without saying why")
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
