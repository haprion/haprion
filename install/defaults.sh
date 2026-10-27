# shellcheck shell=bash
#
# What an installation uses for every answer it is not given (B302). Sourced
# by lib.sh and applied by node-lib.sh's load_answers, after the answers file
# when there is one. The node package does not carry it (F10).
#
# The manager's answers only. What 04-node-prepare reads on a node - the
# manager's name, the node's own keys - has no default here: a value guessed
# on the node would change what its node.conf says.
#
# Only a variable the answers file leaves unset gets its default: a line that
# sets one to nothing keeps it empty, which is how an installation says "no
# backups" or "no certificate distribution". An installation without an
# answers file gets exactly these.
#
# shellcheck disable=SC2034 # read by the steps that source lib.sh

apply_default_answers() {
    local name
    #
    # The host's own fully qualified name: what the web interface answers to.
    #
    name="$(hostname -f 2>/dev/null || hostname)"

    # Where things live on the management host.
    : "${CONFIG_ROOT=/srv/haprion/config}"
    : "${PUBLISH_ROOT=/srv/haprion/published}"
    : "${VALIDATION_ROOT=/srv/haprion/validation}"
    : "${CLUSTER_FILE=/etc/haprion/registry/clusters.yaml}"
    : "${CERTIFICATE_REGISTRY=/etc/haprion/registry/certificates.yaml}"
    : "${BACKUP_ROOT=/srv/haprion/state-backups}"
    #
    # Beside the copy of the interface's own certificate that haprion-tls
    # writes at /srv/certdist/manager-ui.pem: one directory the certificate
    # flows publish into.
    #
    : "${CERTIFICATE_ROOT=/srv/certdist/haproxy}"
    : "${RECEIVER_ROOT=/srv/certdist/receivers}"

    # Accounts on the machines; none until somebody names them.
    : "${OPERATOR_ACCOUNTS=}"
    : "${CONFIG_EDITORS=}"
    : "${EXTRA_BACKUP_GROUPS=}"
    : "${EXTRA_BACKUP_PATHS=}"

    # The manager's identities, one job each.
    : "${KEY_DIR=/root/.ssh}"
    : "${CONFIG_DEPLOY_KEY=id_ed25519_config_deploy}"
    : "${CERT_DEPLOY_KEY=id_ed25519_cert_deploy}"
    : "${NODE_STATUS_KEY=id_ed25519_node_status}"
    : "${NODE_PROBE_KEY=id_ed25519_node_probe}"
    : "${NODE_BACKUP_KEY=id_ed25519_node_backup}"
    : "${SERVER_STATE_KEY=id_ed25519_server_state}"
    : "${SERVER_STATE_PUBKEY=}"

    #
    # No clusters: they are created in the interface, Settings - Create
    # cluster. MANAGER_HOST has no default: it is read on a node, where this
    # machine's own name would be the wrong answer.
    #
    : "${CLUSTERS=}"

    # The web platform.
    : "${SERVER_NAME=${name}}"
    : "${TRUSTED_PROXIES=}"
    : "${PROBE_SOCKET=yes}"
}
