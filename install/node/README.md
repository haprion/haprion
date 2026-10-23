# Node-side scripts

`04-node-prepare` installs these to `/usr/sbin` on a node.

| Script | What it does |
|---|---|
| `haprion-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haprion-cert-trigger` | unprivileged wrapper: validates certificate IDs, then escalates (`cert-pull`, `cert-remove`, and `ca-pull`, `ca-remove` for CA files) |
| `haprion-cert-pull` | fetches the requested certificates, validates them, installs, reloads; with `--authority`, CA files into `/etc/haproxy/certs/ca/`, reloaded only when the configuration names one |
| `haprion-cert-remove` | removes certificates nothing installed names; with `--authority`, CA files |
| `haprion-node-key` | prints this node's enrollment block for a manager to join it with; a new one-time key when the last is used or old |
| `haprion-node-join` | joins the node to the manager that connected with the block's key: runs step 4 from the manager's answers and installs its keys |
| `haprion-server-state-trigger` | unprivileged forced command for the server state key: validates the request, then escalates |
| `haprion-server-state` | sets a server to ready, drain or maintenance and keeps it through reloads, which it performs itself, and unblocks addresses |
| `haprion-node-status` | reports version, health, carried certificates, pool members and keepalived state |
| `haprion-health-probe` | tries a health check against named servers, from this node, and reports whether they answered |
| `haprion-keepalived-state` | records the keepalived transition to a state file |
| `haprion-state-export` | writes this node's permanent state to stdout as a gzipped tar |
| `haprion-traffic-log-read` | returns bounded, whole JSONL records for one validated UTC day and cursor, or the WAF engine's journal lines after a journal cursor (`waf <cursor>`) |
| `haprion-traffic-log-enable` | installs or removes the node's rsyslog route and its retention timer |
| `haprion-traffic-log-prune` | deletes traffic days past the 14-day window, or the oldest over the space budget, whole and never renamed; prints the hour limit the rsyslog rule writes |

## Nothing environment-specific is compiled in

Everything a node needs to know about itself — its cluster, its management host,
which account and key it fetches with — comes from one root-owned file,
`/etc/haprion/node.conf`, rendered by `04-node-prepare`:

```sh
CLUSTER="alpha"
MANAGER="mgr"
CONFIG_PULL_USER="_haprion-pull"
CONFIG_PULL_KEY="/root/.ssh/id_ed25519_config_pull"
CONFIG_REMOTE_PATH="alpha/current/a/"
CERT_PULL_USER="_haprion-cert-pull"
CERT_PULL_KEY="/root/.ssh/id_ed25519_cert_pull"
```

A script that cannot read it, or finds a value missing, exits 78 (`EX_CONFIG`)
rather than guessing.

The file is mode 600 root-owned for a specific reason: it names the account and
key this node fetches configuration with, so whoever can edit it can point the
node at a different source.

This matters more than it looks. Before it existed, `haprion-pull-deploy` was
maintained as three separate copies that differed only in one line — the
publication path — and each copy looked perfectly correct on its own. That is
the kind of drift that survives for years.

## Bundle inventory

`haprion-state-export` was the last one out. It carried a hardcoded list of local
accounts — real operator names, which is why it could not be published — and that
list is now `BACKUP_ACCOUNTS` in `node.conf`. The hardcoded version had a second
problem the accounts hid: an account added after it was written was silently left
out of every backup.

The traffic-log reader is attested as part of the same bundle. Its account, read group and empty
`authorized_keys` file are prepared by step 4. Step 4 does not turn the stream on: run
`sudo haprion-traffic-log-enable` on a node whose published configuration enables the second log
stream, and `--disable` to take it away again. It also installs the hourly retention timer. The
collector key is still to come; until the route is installed no structured traffic file is written,
and the empty account accepts no connection either way.

Retention deletes whole days and never renames a file. logrotate would move the file a fetch is
reading between two names, with no instant at which both names resolve - a run landing in that gap
reads an empty file and reports success, which is worse than an error.

rsyslog writes each hour to `traffic-YYYY-MM-DDTHH.jsonl` and stops that file at a twenty-fourth of
the space budget (`rotation.sizeLimit`, with no rotation command: the rest of the hour is dropped
and rsyslog logs that it refused). A day therefore never holds more than the budget. The reader
serves a day as its hours in order, so the collector still asks for a day and an offset.

`/var/log/haprion` is `syslog:_haprion-logs` mode **2750**, and the set-group-id bit is
load-bearing. rsyslog drops to `syslog:syslog` before it opens a log file, so it cannot place a
file in a group it does not belong to; letting the directory decide the group is what makes the
files readable to the reader account without widening the `syslog` account.
