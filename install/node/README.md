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
| `haproxy-traffic-log-read` | returns bounded, whole JSONL records for one validated UTC day and cursor, or the WAF engine's journal lines after a journal cursor (`waf <cursor>`) |
| `haproxy-traffic-log-enable` | installs or removes the node's rsyslog route and its retention timer |
| `haproxy-traffic-log-prune` | deletes traffic day files past the 14-day window, whole and never renamed |

## Nothing environment-specific is compiled in

Everything a node needs to know about itself — its cluster, its management host,
which account and key it fetches with — comes from one root-owned file,
`/etc/haprion/node.conf`, rendered by `04-node-prepare`:

```sh
CLUSTER="alpha"
MANAGER="mgr"
CONFIG_PULL_USER="svc-pull"
CONFIG_PULL_KEY="/root/.ssh/id_ed25519_config_pull"
CONFIG_REMOTE_PATH="alpha/current/a/"
CERT_PULL_USER="svc-cert-pull"
CERT_PULL_KEY="/root/.ssh/id_ed25519_cert_pull"
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

## Bundle inventory

`haproxy-state-export` was the last one out. It carried a hardcoded list of local
accounts — real operator names, which is why it could not be published — and that
list is now `BACKUP_ACCOUNTS` in `node.conf`. The hardcoded version had a second
problem the accounts hid: an account added after it was written was silently left
out of every backup.

The traffic-log reader is attested as part of the same bundle. Its account, read group and empty
`authorized_keys` file are prepared by step 4. Step 4 does not turn the stream on: run
`sudo haproxy-traffic-log-enable` on a node whose published configuration enables the second log
stream, and `--disable` to take it away again. It also installs the daily retention timer. The
collector key is still to come; until the route is installed no structured traffic file is written,
and the empty account accepts no connection either way.

Retention deletes whole day files and never renames one. logrotate would move the file a fetch is
reading between two names, with no instant at which both names resolve - a run landing in that gap
reads an empty file and reports success, which is worse than an error.

`/var/log/haprion` is `syslog:haproxy-logread` mode **2750**, and the set-group-id bit is
load-bearing. rsyslog drops to `syslog:syslog` before it opens a log file, so it cannot place a
file in a group it does not belong to; letting the directory decide the group is what makes the
files readable to the reader account without widening the `syslog` account.
