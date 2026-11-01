# shellcheck shell=bash
#
# The names and places only the management host uses (B266): the platform's
# accounts, services, database and directories. Sourced by lib.sh after node-lib.sh, for the manager's steps.
# A node's package does not carry it; what a node's step uses is in accounts.sh.
#
# shellcheck disable=SC2034 # read by the steps that source lib.sh

# The management host.
readonly CONFIG_GROUP=haprion
readonly PLATFORM_GROUP=_haprion-ui
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

# Where the web platform lives: Debian's places for code, configuration and
# state. What grows with traffic is put on a volume of its own by mounting it
# at these paths, never by moving them (user manual, "Where the data lives").
readonly UI_ROOT=/opt/haprion-ui
readonly UI_CONFIG=/etc/haprion/ui.toml
readonly UI_SECRETS=/etc/haprion/ui-secrets
readonly UI_DATA=/var/lib/haprion-ui
# What the haprion-ui package installed: RELEASE_ID names its release.
readonly UI_PAYLOAD=/usr/lib/haprion/ui/PAYLOAD
