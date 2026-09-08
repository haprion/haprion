# Node-side scripts

`04-node-prepare` installs these to `/usr/local/sbin` on a node.

| Script | What it does |
|---|---|
| `haproxy-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haproxy-cert-trigger` | unprivileged wrapper: validates certificate IDs, then escalates |
| `haproxy-cert-pull` | fetches the requested certificates, validates them, installs, reloads |
| `haproxy-node-status` | reports version, health, carried certificates, pool members and keepalived state |
| `haproxy-health-probe` | tries a health check against named servers, from this node, and reports whether they answered |
| `haproxy-keepalived-state` | records the keepalived transition to a state file |
| `haproxy-state-export` | writes this node's permanent state to stdout as a gzipped tar |
| `haproxy-traffic-log-trust` | fetches the public traffic-log CA and installs TLS forwarding |

## Nothing environment-specific is compiled in

Everything a node needs to know about itself — its cluster, its management host,
which account and key it fetches with — comes from one root-owned file,
`/etc/haproxy-manager/node.conf`, rendered by `04-node-prepare`:

```sh
CLUSTER="alpha"
MANAGER="mgr"
CONFIG_PULL_USER="svc-pull"
CONFIG_PULL_KEY="/root/.ssh/id_ed25519_config_pull"
CONFIG_REMOTE_PATH="alpha/current/a/"
CERT_PULL_USER="svc-cert-pull"
CERT_PULL_KEY="/root/.ssh/id_ed25519_cert_pull"
TRAFFIC_LOG_CA_REMOTE=".haproxy-manager/traffic-log-ca.pem"
TRAFFIC_LOG_PORT="6514"
```

A script that cannot read it, or finds a value missing, exits 78 (`EX_CONFIG`)
rather than guessing.

The file is mode 600 root-owned for a specific reason: it names the account and
key this node fetches configuration with, so whoever can edit it can point the
node at a different source.

This matters more than it looks. Before it existed, `haproxy-pull-deploy` was
maintained as three separate copies that differed only in one line — the
publication path — and each copy looked perfectly correct on its own. That is
the kind of drift that survives for years.

## Nothing is missing any more

`haproxy-state-export` was the last one out. It carried a hardcoded list of local
accounts — real operator names, which is why it could not be published — and that
list is now `BACKUP_ACCOUNTS` in `node.conf`. The hardcoded version had a second
problem the accounts hid: an account added after it was written was silently left
out of every backup.
