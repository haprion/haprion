# shellcheck shell=bash
#
# Haprion's fixed account and group names (B266) a node's step uses, sourced by
# node-lib.sh. The step directory is carried by the node package and its digest
# is the record of which step last ran, so this file holds only what the node's
# step reads: a test fails on a name it does not. The manager's names are in
# manager-accounts.sh. All of them are also in src/haprion/accounts.py and
# install/sysusers/; a test keeps them in step.
#
# shellcheck disable=SC2034 # read by the steps that source node-lib.sh

# The management host's accounts, as the node creates them.
readonly PULL_USER=_haprion-pull
readonly CERT_PULL_USER=_haprion-cert-pull

# Each node.
readonly TRIGGER_USER=_haprion-trigger
readonly STATUS_USER=_haprion-status
readonly BACKUP_USER=_haprion-backup
readonly LOGREAD_USER=_haprion-logread
readonly LOGS_GROUP=_haprion-logs
readonly WAF_GROUP=_haprion-waf
readonly DNS_GROUP=_haprion-dns

# The names an answers file used to carry. One still setting them is from
# before B266, and is refused rather than silently overruled.
readonly RETIRED_ANSWERS=(
    CONFIG_GROUP PLATFORM_GROUP PULL_USER CERT_PULL_USER WEB_USER WORKER_USER
    POLLER_USER COLLECTOR_USER OIDC_USER DB_NAME DB_MIGRATION_ROLE TRIGGER_USER
    STATUS_USER BACKUP_USER LOGREAD_USER JOIN_USER ENVIRONMENT PLATFORM_ROOT
)
