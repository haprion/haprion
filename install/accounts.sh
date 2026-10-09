# shellcheck shell=bash
#
# Haprion's fixed account, group and database names (B266), for the
# installation steps. Sourced by lib.sh. The same names are in
# src/haproxy_mgmt/accounts.py and install/sysusers/; a test keeps the three in
# step.
#
# shellcheck disable=SC2034 # read by the steps that source lib.sh

# The management host.
readonly CONFIG_GROUP=haprion
readonly PLATFORM_GROUP=_haprion-ui
readonly PULL_USER=_haprion-pull
readonly CERT_PULL_USER=_haprion-cert-pull
readonly WEB_USER=_haprion-web
readonly WORKER_USER=_haprion-worker
readonly POLLER_USER=_haprion-poller
readonly COLLECTOR_USER=_haprion-collector
readonly OIDC_USER=_haprion-oidc
readonly DB_NAME=haprion
readonly WEB_UNIT=haprion-web.service
readonly WORKER_UNIT=haprion-worker.service
readonly POLLER_UNIT=haprion-poller.service
readonly WORKER_SUDOERS=haprion-worker
readonly POLLER_SUDOERS=haprion-poller
readonly DB_MIGRATION_ROLE=_haprion-migrate

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
    STATUS_USER BACKUP_USER LOGREAD_USER ENVIRONMENT
)
