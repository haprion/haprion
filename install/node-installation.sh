# shellcheck shell=bash
#
# What a node attests: the scripts whose digests it records, and the API level
# it speaks. Read by step 4 and by the node package's postinst, which records
# them again when apt upgrade has replaced the scripts (review 26-10-24, 03-01).
# Only step 4 wrote the record before, so an upgraded node reported its own
# scripts as changed and the next manager update stopped on it. And which
# step 4 last ran here, for the postinst to compare with the one it brings.
#
# shellcheck disable=SC2034  # read by the files that source this one
SCRIPTS=(
    haprion-pull-deploy
    haprion-cert-pull
    haprion-cert-remove
    haprion-cert-trigger
    haprion-node-status
    haprion-health-probe
    haprion-keepalived-state
    haprion-state-export
    haprion-traffic-log-read
    haprion-traffic-log-enable
    haprion-traffic-log-prune
    haprion-server-state
    haprion-server-state-trigger
)
# Unchanged. This level says whether the manager and a node may speak to each
# other; the traffic chain is opt-in and adds no operation the manager calls on
# a node that has not enabled it. Raising it here would mark every node in the
# fleet incompatible for a feature none of them was asked to run. The same
# holds for `cert-remove`: a node without the verb answers "unknown request"
# and the manager reports the copy as kept, so an older node is behind, not
# incompatible. And for the WAF engine (B231): a node whose status reports no
# `waf_engine` is one the manager does not offer the engine on. And for server
# state (B263): a node without the key line or the helper is one node that did
# not take a drain, reported by name in a `partial` job.
NODE_API=1

NODE_INSTALLATION="${NODE_INSTALLATION:-/etc/haprion/node-installation.json}"

#
# A compatibility level says whether two independently released components may
# speak to each other. The hashes say whether this particular installation still
# contains the package that declared that level. Keeping both avoids the two bad
# shortcuts: requiring every harmless edit to be deployed everywhere, or trusting
# a version marker beside scripts somebody later changed by hand.
#
# Written from the scripts in `$1` as they are on disk now. Needs node-lib.sh's
# install_file and log.
#
record_node_installation() {
    local sbin="$1" node_installation
    node_installation="$(/usr/bin/python3 - "$NODE_API" "$sbin" "${SCRIPTS[@]}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

scripts = {}
for name in sys.argv[3:]:
    scripts[name] = hashlib.sha256((Path(sys.argv[2]) / name).read_bytes()).hexdigest()
print(
    json.dumps(
        {"schema_version": 1, "node_api": int(sys.argv[1]), "scripts": scripts},
        sort_keys=True,
    )
)
PY
)"
    install_file "$NODE_INSTALLATION" root:root 644 "$node_installation"
    log "  recorded node API ${NODE_API} and ${#SCRIPTS[@]} script digests"
}

#
# Which step 4 last ran on this node: one digest of every file in the step's
# directory, which is the package's and nothing else. An upgrade replaces the
# step and runs nothing (B361); the package's postinst compares the step it
# brings with this record and says to run haprion-node-prepare when they
# differ. A digest rather than a level someone raises by hand: a change
# nobody marked is still a change.
#
NODE_PREPARED="${NODE_PREPARED:-/var/lib/haprion-node/prepared}"

step_digest() {
    (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) \
        | sha256sum | cut -d' ' -f1
}

record_node_prepared() {
    local digest
    digest="$(step_digest "$1")"
    install -d -m 700 "${NODE_PREPARED%/*}"
    printf '%s\n' "$digest" > "${NODE_PREPARED}.new"
    mv "${NODE_PREPARED}.new" "$NODE_PREPARED"
    log "  recorded this step as the one last run here"
}

# True when the step in `$1` is the one that last ran here.
node_prepared_by() {
    [[ -f "$NODE_PREPARED" && "$(cat "$NODE_PREPARED")" == "$(step_digest "$1")" ]]
}
