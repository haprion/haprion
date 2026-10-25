# Node-side scripts

The `haprion-node` package installs these in `/usr/sbin` on a node; `04-node-prepare` checks that every
one is there.

| Script | What it does |
|---|---|
| `haprion-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haprion-cert-trigger` | unprivileged wrapper: validates certificate IDs, then escalates (`cert-pull`, `cert-remove`, and `ca-pull`, `ca-remove` for CA files) |
| `haprion-cert-pull` | fetches the requested certificates, validates them, installs, reloads; with `--authority`, CA files into `/etc/haproxy/certs/ca/`, reloaded only when the configuration names one |
| `haprion-cert-remove` | removes certificates nothing installed names; with `--authority`, CA files |
| `haprion-node-key` | makes this node's enrollment block for a manager to join it with; every run makes a new one-time key, so an earlier block stops working |
| `haprion-node-join` | joins the node to the manager that connected with the block's key: runs step 4 from the manager's answers and installs its keys |
| `haprion-node-prepare` | runs step 4 again on a prepared node, with the answers read back from `node.conf`; run it by hand when an upgrade says to |
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

The file is mode 600 and owned by root, because it names the account and key the
node fetches configuration with: whoever can edit it can point the node at a
different source.

Keeping every environment value in this one file is what lets the same scripts
run on every node. The local accounts a state backup must capture are listed
there too, as `BACKUP_ACCOUNTS`, so an account added later is not silently left
out of the backups.

## The traffic log

Step 4 prepares the traffic-log reader's account, its read group and its
`authorized_keys`. When the node is given the collector's key – which a node
joined from the interface is – step 4 also turns the node's log route on with
`haprion-traffic-log-enable`, which installs the rsyslog rule and the hourly
retention timer. `sudo haprion-traffic-log-enable --disable` turns it off again.
Until the route is on, no traffic file is written.

Retention deletes whole days and never renames a file. logrotate would move the file a fetch is
reading between two names, with no instant at which both names resolve - a run landing in that gap
reads an empty file and reports success, which is worse than an error.

rsyslog writes each hour to `traffic-YYYY-MM-DDTHH.jsonl` and stops that file at a twenty-fourth of
the space budget (`rotation.sizeLimit`, with no rotation command: the rest of the hour is dropped
and rsyslog logs that it refused). A day therefore never holds more than the budget. The reader
serves a day as its hours in order, so the collector still asks for a day and an offset.

`/var/log/haprion` is owned by the account rsyslog writes as – `syslog` on Ubuntu, `root` on Debian 13
– with the group `_haprion-logs` and mode **2750**. The set-group-id bit matters: rsyslog cannot give a
file a group it does not belong to, so the directory decides the group, and that is what lets the reader
account read the files without widening rsyslog's own account.
