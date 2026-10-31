"""The installation's own accounts, groups, database names and places, fixed (B266).

They used to be answers - each installation named its own - and every script,
sudoers file and unit then had to be rendered from those answers. Fixed, the
packages can carry their sysusers fragments and sudoers files as they are.

Service accounts start with an underscore, as Debian asks of system accounts
(Policy 9.2.1); it also keeps an account from being named like the command it
runs. The group operators join does not, like `docker` or `libvirt`.

`install/accounts.sh` holds the same names for the installation steps, and
`install/sysusers/` the fragments; a test keeps all three in step.
"""

from __future__ import annotations

# The management host.
CONFIG_GROUP = "haprion"
PLATFORM_GROUP = "_haprion-ui"
PULL = "_haprion-pull"
CERT_PULL = "_haprion-cert-pull"
WEB = "_haprion-web"
WORKER = "_haprion-worker"
POLLER = "_haprion-poller"
COLLECTOR = "_haprion-collector"
OIDC = "_haprion-oidc"
#
# Reached by block clients (B412): one key per client, each forced to
# `haprion-block-ask <client>`.
#
BLOCK = "_haprion-block"
BLOCK_SUDOERS = "haprion-block"

# The platform's services and their sudoers files, named for what they run
# rather than after their accounts.
WEB_UNIT = "haprion-web.service"
WORKER_UNIT = "haprion-worker.service"
POLLER_UNIT = "haprion-poller.service"
WORKER_SUDOERS = "haprion-worker"
POLLER_SUDOERS = "haprion-poller"

# The database, and the role that owns it. The role has no operating-system
# account: root reaches it through pg_ident.
DATABASE = "haprion"
MIGRATION_ROLE = "_haprion-migrate"

# Where the web platform lives: Debian's places for code, configuration and
# state. What grows with traffic is put on a volume of its own by mounting it
# at these paths, never by moving them.
UI_ROOT = "/opt/haprion-ui"
UI_CONFIG = "/etc/haprion/ui.toml"
UI_SECRETS = "/etc/haprion/ui-secrets"
UI_DATA = "/var/lib/haprion-ui"
# What the haprion-ui package installed: RELEASE_ID names its release.
UI_PAYLOAD = "/usr/lib/haprion/ui/PAYLOAD"

# Each node.
TRIGGER = "_haprion-trigger"
STATUS = "_haprion-status"
BACKUP = "_haprion-backup"
LOGREAD = "_haprion-logread"
#
# Reached once, by the one-time key a new node's package makes (B317): the
# manager joins the node through it, and the key is gone afterwards.
#
JOIN = "_haprion-join"
LOGS_GROUP = "_haprion-logs"
WAF_GROUP = "_haprion-waf"
DNS_GROUP = "_haprion-dns"

#
# Which node account each of the manager's identities reaches. The trigger
# account takes configuration, certificates and server state; the status
# account answers status and the probe.
#
IDENTITY_ACCOUNTS = {
    "deploy_identity": TRIGGER,
    "cert_deploy_identity": TRIGGER,
    "server_state_identity": TRIGGER,
    "status_identity": STATUS,
    "probe_identity": STATUS,
    "backup_identity": BACKUP,
}
