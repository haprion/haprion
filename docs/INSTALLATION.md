# Installation

How to build a HAProxy Manager environment from nothing: one management host and one or more
clusters of HAProxy nodes.

Every name in this document is fictional. Substitute your own: the management host is `mgr`, the
clusters are `alpha` and `beta`, and each cluster has two nodes, `node-a` and `node-b`. Addresses
come from the documentation ranges in RFC 5737. Nothing here depends on those names — if a step
only works with the names used below, that is a bug in the software, not in this guide.

> **Looking for the steps?** They are in [`install/README.md`](../install/README.md): five scripts,
> three on the management host, one per node, one to check. This document explains what those
> scripts do and why, and covers the parts that are yours to decide. Read that one to install;
> read this one to understand.

> **Status.** This guide is written alongside the implementation and is completed phase by phase.
> The gaps that remain are listed in [What is still missing](#what-is-still-missing) rather than
> papered over.

## Contents

- [The shape of a deployment](#the-shape-of-a-deployment)
- [Prerequisites](#prerequisites)
- [Part 1 — the management host](#part-1--the-management-host)
- [Part 2 — the nodes](#part-2--the-nodes)
- [Part 3 — the versioned CLI release](#part-3--the-versioned-cli-release)
- [Part 4 — the web platform](#part-4--the-web-platform)
- [Verifying the installation](#verifying-the-installation)
- [What is still missing](#what-is-still-missing)

## The shape of a deployment

```text
                 mgr  (management host)
                  |
     authoritative config, published releases,
     the CLI, the privileged helpers, the keys
                  |
        +---------+---------+
        |                   |
     node-a              node-b        cluster alpha
     node-a              node-b        cluster beta
```

Three properties drive the whole design, and every step below follows from one of them:

1. **The management host never pushes.** It asks a node to pull, and nothing else. Every management
   SSH identity is a forced command; none of them can copy a file or run a shell on a node. A node
   fetches its own configuration from the management host over a separate, restricted account.
2. **Configuration is versioned before it is deployed.** Editing produces a draft; publishing
   produces an immutable release; deploying brings nodes to a published release. Each stage is a
   separate command with its own privilege.
3. **The application never holds privilege.** Privileged work happens in small root-owned helpers
   with no caller-supplied paths, reached through exact sudo rules. See
   [`PRIVILEGE.md`](PRIVILEGE.md) for the contract these rules implement.

## Prerequisites

HAProxy Manager manages HAProxy; it does not install it. Before starting, you need:

**On the management host**

- a current Linux distribution with `systemd`
- Python 3.12 or newer at `/usr/bin/python3`
- the operating-system PyYAML package, major version 6
- `git`, `rsync`, `openssh-client`
- `sudo` new enough to support the no-argument sudoers form (`command ""`)

**On the management host, only for the web platform (Part 4)**

- PostgreSQL 16 or newer. 16 is the floor rather than a preference: role
  membership carries its own `INHERIT` setting from that version, and the
  installation states it explicitly instead of depending on a role attribute as
  it happened to be when a grant was made
- nginx
- `uv`, for building a release environment from the committed lockfile

**On every node**

- HAProxy, installed and managed by `systemd`
- `keepalived`, if the cluster uses a virtual address
- `rsync` and `openssh-server`
- `sudo`

**Names and addresses you decide before you start**

| Thing | Example | Notes |
|---|---|---|
| management host | `mgr` | reachable by name from every node |
| cluster IDs | `alpha`, `beta` | lowercase, used in every command as `-c <cluster>` |
| node names | `node-a`, `node-b` | two per cluster in the reference layout |
| virtual address | `192.0.2.10` | per cluster, if keepalived is used |
| management network | `192.0.2.0/24` | how the host and nodes reach each other |

## Part 1 — the management host

### 1.1 Service accounts and the config group

The web, worker, and poller processes run as three distinct, locked, no-login accounts, and only
the worker joins the read-only configuration group. Account names are deployment data, so they are
supplied in a policy file rather than compiled in:

```bash
haproxy-render-sysusers --policy /etc/haproxy-manager/identity-policy.yaml
```

The command validates the policy and renders a `sysusers.d` fragment. It does not modify the
system — review the fragment, install it, and let `systemd-sysusers` apply it.

Human operators are deliberately absent from the fragment. Adding an administrator to the config
group is a separate action against an already existing account.

### 1.2 Directory layout

```text
/srv/haproxy-manager/config/alpha.git/            authoritative history, bare
/srv/haproxy-manager/config/alpha/                linked draft worktree - what you edit
/srv/haproxy-manager/config/alpha/{core,managed,manual}

/srv/haproxy-manager/published/alpha/releases/    immutable published releases
/srv/haproxy-manager/published/alpha/current      symlink to the current release

/srv/haproxy-manager/validation/certs/            validation-only certificate material
/srv/haproxy-manager/clusters.yaml                cluster definitions
/etc/haproxy-manager/runtime-policy.yaml          the outer path boundary
```

Only two of these paths are fixed by the software: `/etc/haproxy-manager/runtime-policy.yaml`, which
is where the code looks unless told otherwise, and `/opt/haproxy-mgmt`, where releases are installed.
Everything else above is a deployment choice — put the trees wherever your environment keeps them,
and name them in the runtime policy.

Repeat the first two blocks per cluster.

Config repositories and published releases are **root-owned and never group-writable**. The config
group reads; it does not write. Publishing is a write into root-owned history and therefore happens
through a helper, not directly.

The split between `alpha.git/` and `alpha/` is a bare repository plus a linked worktree. They are
held together by a path reference in each direction. Restoring only one of them breaks the link;
`git worktree repair` fixes it without touching configuration.

### 1.3 Runtime policy

`runtime-policy.yaml` is the outer security boundary, not a convenience file. It names the roots
that every path in `clusters.yaml` must stay inside, and the code refuses any cluster path that
escapes its root.

```yaml
schema_version: 1

cluster_file: /srv/haproxy-manager/clusters.yaml
config_root: /srv/haproxy-manager/config
publish_root: /srv/haproxy-manager/published
validation_certs_root: /srv/haproxy-manager/validation

deploy_identity:
  user: "svc-trigger"
  key: "/root/.ssh/id_ed25519_config_deploy"

certificate_root: /srv/certificates/haproxy
cert_deploy_identity:
  user: "svc-trigger"
  key: "/root/.ssh/id_ed25519_cert_deploy"

status_identity:
  user: "svc-status"
  key: "/root/.ssh/id_ed25519_status"
```

`status_identity` is the account `haproxy-status` becomes to read a node, and `haproxy-deploy`
uses it too: a rollout reads the pair before and after every step, and it reads with the identity
that cannot change a node rather than the one it triggers with. Both commands refuse to run
without it instead of falling back to the deploy identity. It is deliberately not
the deploy identity: reading status is the one thing the manager asks a node to do that cannot
change it, so it is the identity that can be granted most widely, and keeping it separate is what
preserves that difference. Without it, `haproxy-status` says exactly which field is missing.

The file must be root-owned, a regular file (not a symlink), not group- or world-writable, and at
most 1 MiB. The reader rejects unknown fields, so **install a release that understands a new field
before adding it** — otherwise every command that reads the policy fails, not only the new one.

### 1.4 Cluster definitions

```yaml
schema_version: 1

clusters:
  alpha:
    display_name: Alpha
    vip: 192.0.2.10
    config_path: /srv/haproxy-manager/config/alpha
    publish_path: /srv/haproxy-manager/published/alpha
    node_path: a
    nodes:
      - name: node-a
        mgmt_host: node-a.example.com
      - name: node-b
        mgmt_host: node-b.example.com
    validation_certs: /srv/haproxy-manager/validation/certs
    certificate_ids:
      - example.com
    default_certificate: example.com
```

`node_path` is the subdirectory a node fetches from on the management host. It is the only
per-cluster value the node side needs.

### 1.5 Validation certificate

Candidate validation runs a real `haproxy -c` against the candidate. Any configuration that
references a certificate therefore needs certificate material present during validation — but the
real private key must never be readable by the validating path.

A dedicated, self-signed certificate under `validation_certs_root` solves this. It is readable only
by root, is copied into the private candidate for the duration of validation, and is removed before
the helper returns. It never leaves the management host and is never deployed.

### 1.6 SSH identities

Four key pairs, each with exactly one job:

| Key on the management host | Connects as | Purpose |
|---|---|---|
| `id_ed25519_config_deploy` | `svc-trigger` on the node | trigger a configuration pull |
| `id_ed25519_cert_deploy` | `svc-trigger` on the node | trigger a certificate pull |
| `id_ed25519_node_status` | `svc-status` on the node | read node status |
| the node's own config pull key | `svc-pull` on the management host | read the published tree |
| the node's own cert pull key | `svc-cert-pull` on the management host | read the certificate tree |

A key that can push configuration must not be able to push certificates, and neither may read
status. Private keys are root-owned; no application identity can read any of them.

**The node's keys are generated on the node, by step 4, and never leave it.** A private key a node
authenticates with has no reason to exist on the management host; copying one there would make the
management host able to impersonate a node. Step 4 prints the public halves and the exact
`authorized_keys` lines for the management host, which is the mirror image of step 3.

One line per node, not one per cluster. Each node has its own key, so a node that is rebuilt or
compromised is revoked on its own.

The pull direction is the mirror image: an account on the management host, restricted to an
`rrsync`-style read-only export of the published tree, which the node authenticates to with its own
key.

`rrsync` is what makes that restriction real: the forced command is
`rrsync -ro <tree>`, which allows a read-only rsync of exactly one directory and nothing else.
Without it a forced `rsync` command is a shell in all but name.

**The published tree belongs to the pull account, not to the config group.** Giving it to the
config group looks reasonable and locks the nodes out of the only tree they are supposed to read —
deploys then fail while every permission still looks deliberate.

### 1.7 Sudo rules

Two separate policies, which must not be merged:

- **Application rules.** Exact helper paths, invoked with no arguments (`command ""`), so the
  helper reads its request as bounded JSON on stdin. No rule grants a shell, an interpreter, an
  editor, a wildcard path, environment preservation, or unrestricted arguments. The web identity
  has no sudo rule at all.
- **Operator rules.** A `sudoedit` policy listing the configuration files an administrator may
  edit, by exact path. `sudoedit` is what makes editing possible without making the repositories
  group-writable.

Every sudoers file is root-owned and read-only (`0440` or stricter). See [`PRIVILEGE.md`](PRIVILEGE.md)
for the full contract and the negative tests that prove it.

## Part 2 — the nodes

The scripts are in [`install/node/`](../install/node/) and are installed by
[`04-node-prepare`](../install/04-node-prepare), which also creates the accounts, the release
layout and the sudo rules. This section explains what they do and why; run the script rather than
following it by hand.


### 2.1 HAProxy and keepalived baseline

This project does not install HAProxy or keepalived, but it does **assume things about how they are
configured**. Get these wrong and nothing fails loudly — deploys just stop being safe, because the
ordering that protects live traffic quietly stops meaning anything.

**Both nodes must be able to bind the virtual address, whether or not they own it.**

```text
# /etc/sysctl.d/60-haproxy.conf
net.ipv4.ip_nonlocal_bind = 1
```

Without it, HAProxy on the node that does *not* hold the address fails to start: it is asked to
bind an address the kernel says is not there. With it, both nodes run continuously and the virtual
address decides which one traffic reaches. `04-node-prepare` sets this and reports it.

**Both nodes run keepalived as `BACKUP`, with `nopreempt`.**

```text
vrrp_instance alpha {
    state           BACKUP        # both nodes - not MASTER on either
    interface       eth0
    virtual_router_id 51          # unique per VRRP domain on the segment
    priority        100           # 100 on one node, 90 on the other
    nopreempt
    advert_int      1

    unicast_src_ip  192.0.2.11    # this node
    unicast_peer {
        192.0.2.12                # the other node
    }

    authentication {
        auth_type PASS
        auth_pass <shared secret>
    }

    virtual_ipaddress {
        192.0.2.10                # the VIP
    }

    notify_master "/usr/local/sbin/haproxy-keepalived-state MASTER"
    notify_backup "/usr/local/sbin/haproxy-keepalived-state BACKUP"
    notify_fault  "/usr/local/sbin/haproxy-keepalived-state FAULT"
}
```

Three details carry weight:

- **`state BACKUP` on both, plus `nopreempt`.** A node that comes back after a failure does not take
  the address back, even with the higher priority. Preemption would move live traffic for no reason
  — during a rebuild, exactly when you least want it. The priorities still decide who takes it on a
  cold start, when neither holds it.
- **Unicast, not multicast.** `unicast_peer` names the other node explicitly. Multicast VRRP works
  until something on the path quietly stops forwarding it, and then two nodes both believe they are
  master.
- **The `notify_` lines are not optional here.** They are how the management host learns who owns
  the address. Without them the state file is never written, node status cannot report an owner, and
  a deploy has no way to order the nodes.

**Why the ordering matters.** A rollout deploys the non-owner first and the address owner last. If
the new configuration breaks, it breaks on the node not carrying traffic, and the run stops before
reaching the other one. That protection is only real if the owner is actually known — which is why
the three points above are part of the installation and not an operational detail.

**One more assumption, in the cluster's own configuration rather than the node's.** Status and
metrics are read from a local HAProxy stats socket, so the published configuration is expected to
contain a line like:

```text
stats socket /run/haproxy/ui-status.sock mode 660 level user
```

`level user` is read-only — enough for status and metrics, not enough to change anything. It is a
local socket and must not be exposed on the network. An existing admin socket is separate and is not
replaced by it.

A copy-paste starting point for the keepalived side is in
[`install/examples/keepalived.conf.example`](../install/examples/keepalived.conf.example).

**One thing to expect after first provisioning.** A clean keepalived config reload does not
necessarily produce a VRRP state transition, so the state file may be empty until the first real
transition. Force one — stop keepalived on one node and start it again — or write the file once by
hand.

### 2.2 Node accounts

Three service accounts, identical on every node. They are system accounts with no password, a home
directory for `authorized_keys`, and — deliberately — a real login shell:

| Account | Reached by | May run |
|---|---|---|
| `svc-trigger` | the management host's deploy and cert-deploy keys | the pull scripts, through forced commands |
| `svc-backup` | the management host's backup path | the state export |
| `svc-status` | the management host's status key | the node status reporter, read-only |

**The shell looks like a mistake and is not.** sshd runs a forced command through the account's
login shell, so `nologin` here does not harden anything — it stops every forced command from
working, and the only symptom is a nologin message where output was expected.

What constrains these accounts is that each key carries `restrict` and its own forced command, so a
session cannot run anything else, and that their sudo rules name exact absolute commands. Neither
depends on the shell.

Each key in the account's `authorized_keys` carries its **own** forced command and the `restrict`
option. One key, one command: a shared forced command would make the keys interchangeable and
defeat the separation.

### 2.3 Node scripts

All root-owned under `/usr/local/sbin`, not group-writable:

| Script | What it does |
|---|---|
| `haproxy-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haproxy-cert-trigger` | unprivileged wrapper: validates certificate IDs, then escalates |
| `haproxy-cert-pull` | fetches the requested certificates, validates them, installs, reloads |
| `haproxy-node-status` | reports version, health, carried certificates and keepalived state |
| `haproxy-keepalived-state` | records the keepalived transition to a state file |
| `haproxy-state-export` | writes this node's permanent state to stdout as a gzipped tar |

Two of these deserve attention:

**`haproxy-cert-trigger` exists because sudoers cannot express a list.** The certificate IDs arrive
as SSH command arguments, and no wildcard rule can safely constrain them. So validation happens
twice: unprivileged in the wrapper, and again in the root helper. The wrapper escalates with
`sudo -n` and an exact `NOPASSWD` rule, so a policy mismatch fails immediately instead of falling
back to an interactive password prompt.

**`haproxy-pull-deploy` is generic except for its publication path.** Everything else — validation,
release creation, the atomic symlink swap, the rollback on failure — is identical on every node.

### 2.4 Node filesystem layout

```text
/etc/haproxy/current -> /etc/haproxy/releases/<timestamp>
/etc/haproxy/haproxy.cfg -> current/haproxy.cfg
/etc/haproxy/conf.d      -> current/conf.d
/etc/haproxy/maps        -> current/maps
/etc/haproxy/certs/          local certificate directory
/run/lock/haproxy-deploy.lock
```

A deploy never edits the running configuration. It builds a new immutable release directory, swaps
the `current` symlink atomically, validates again through exactly the paths `systemd` uses, and only
then reloads. If either validation or the reload fails, the symlink is swapped back.

### 2.5 Installing and changing node scripts

There is no automated path for this, by design. Every management identity is a forced command; none
of them can copy a file. Installing or changing a node script is a manual, interactive action over
an administrator's own login, escalating with `sudo` on the node.

Take a state backup before and after, in the same working session.

## Part 3 — the versioned CLI release

The management CLI is installed independently of the application data filesystem. Source and
development environments may live anywhere, but an installed release lives under
`/opt/haproxy-mgmt` so recovery and diagnostics remain available if application storage is not.

Application code is installed from a wheel. It is never imported from a checkout, an editable
environment, a developer-owned virtual environment, or any development path.

### Build and install

Run the complete repository gate before producing the wheel. Build into a protected staging
directory outside the repository and record its SHA-256 digest:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haproxy_manager-*.whl
```

Install the absolute wheel path with the digest printed by the previous command:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haproxy_manager-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The installer fails closed unless it runs as root and the supplied digest matches. It also rejects
unsafe wheel members and entry points, verifies the runtime baseline and imports, then installs:

```text
/opt/haproxy-mgmt/
├── current -> releases/<version>-<wheel-hash-prefix>
└── releases/
    └── <version>-<wheel-hash-prefix>/
        ├── INSTALLATION.json
        ├── bin/
        └── lib/
```

Release directories are `root:root`, directories and launchers are mode `555`, and other files are
mode `444`. The `current` link is replaced atomically only after the new release passes validation.
Short stable wrappers and exact sudoers rules may point into `current/bin`; they must never point
into a source checkout.

### Rollback

Re-run the same installer with the retained previous wheel and its recorded digest. An already
installed matching release is verified and `current` is atomically switched back. Releases are not
deleted automatically, which keeps rollback independent of the source checkout and application
storage.

### Order of operations

Install the release **before** adding runtime-policy fields that a new release introduces. The
policy reader rejects unknown fields, so the reverse order breaks every command that reads the
policy, not only the new one.

## Part 4 — the web platform

Optional, and separate on purpose. The command line is the authoritative engine
and installs and runs without any of this; a management host that only ever uses
the CLI never needs the platform at all. [`../install/platform/`](../install/platform/)
is what you follow; this section explains the shape.

### 4.1 What is installed where

```text
/apps/haproxy-manager/
├── current -> releases/<version>-<commit>/
├── releases/<version>-<commit>/venv/
├── config/          ui.toml, root-owned, readable by the platform group
├── secrets/         root-only, granted one file at a time
└── data/
    ├── dumps/       database backups, root-only
    └── logs/
```

Config, secrets and data sit **beside** the releases rather than inside one. A
release is replaced wholesale and rolled back by pointing `current` elsewhere,
so anything that has to survive that cannot live within it.

A release is a commit, and the installer refuses to build one from a source tree
with uncommitted changes. It is built at its final path against the system
interpreter — a virtual environment is not relocatable, and an interpreter under
someone's home directory is invisible to a service running with `ProtectHome`.
Both are checked before `current` is switched.

### 4.2 Identities

Three service accounts, one per service, each with its own database role. A
shared account for all three would make a web intrusion equal to worker access,
which is deploy rights. They share one group, and that group grants exactly one
thing: reading the configuration file.

Nothing authenticates to the database with a password. Connections use the local
socket with peer authentication, where the kernel states which operating-system
user is on the other end, and each account is named after its role — so there is
no password to leak, rotate, or find in a process listing.

### 4.3 The database

The migration role owns every object and has no operating-system account. That
is what makes "a service process cannot run DDL" true by construction rather
than by a grant somebody could add later: you cannot drop a table you do not
own. Running a migration is a deliberate root action, mapped explicitly in
`pg_ident.conf`.

Table grants live in the migration that creates the table, so a column's
permissions are versioned with the column. They name three contract roles —
`app_web`, `app_worker`, `app_poller` — and never an account; the installation
connects whatever the accounts are called to those roles. Columns are listed one
at a time, because a grant written as a whole table widens itself the next time
somebody adds one.

The web role may state what it wants done. It holds `insert` on three columns of
the job table and no `update` at all, so a queued job is immutable to the role
that queued it and there is no path from "I asked for this" to "this is what
happened". State, request ID and timestamps come from column defaults.

### 4.4 Verifying it

`install/platform/03-verify` is read-only and can be run at any time. It is
deliberately a **second description** of the privilege surface, compared against
what the running database reports, and it checks both directions.

Both directions matters more than it sounds. A suite that only asks what a role
must *not* do passes completely when a role has no privileges at all — which is
a broken system reading as a perfectly secured one. Ask what must work too.

### 4.5 HTTPS and the certificate

`install/platform/05-platform-nginx` puts nginx in front of the web service and
terminates HTTPS there. The web service itself listens only on
`127.0.0.1:8080`, in plain HTTP, and that leg stays plain deliberately: it never
leaves the host.

**This is the direct address, and it does not go through the HAProxy pair.**
That is the whole point of it. The UI is the tool used to repair that pair, so
putting the UI behind it means a broken publish locks you out of the only thing
that could revert it. A reverse proxy elsewhere — anything from another nginx to
a Proxy Manager on a container host — may be added in front as an *additional*
path, terminating with its own certificate. It must never become the only path.

**The certificate is what a browser meets at login**, not something internal. It
cannot come from the certbot chain the rest of this project uses: that chain is
ACME with DNS-01 against a public domain, and a management host named on an
internal domain cannot be validated that way. So the pair is either self-signed
or issued by your own PKI.

Three answers-file keys control it:

| Key | Meaning |
|---|---|
| `SERVER_NAME` | the name the UI is reached on directly. Required |
| `TLS_CERT` | defaults to `/etc/haproxy-manager/tls/ui.crt` |
| `TLS_KEY` | defaults to `/etc/haproxy-manager/tls/ui.key` |

If no pair exists at those paths, step 5 generates a self-signed one so the UI
is encrypted from the first login. Point the keys at a pair your clients already
trust and that step never runs.

**Plain HTTP is not a lesser option here, it is a non-working one.** The session
cookie is `Secure`, and a `Secure` cookie is never sent over HTTP, so login
simply stops working. Removing `Secure` to get around that would put the session
for a tool with deploy rights in clear text on the network. A self-signed
certificate gives a browser warning but real encryption, which is the better
trade while a proper pair is being arranged.

#### Replacing it

Not by rerunning the installer. The command that owns the certificate is
installed by step 5:

```bash
sudo haproxy-ui-tls show
sudo haproxy-ui-tls install --cert /path/to/ui.crt --key /path/to/ui.key
```

`install` checks that the certificate and key actually belong together by
comparing public halves, refuses an expired certificate, warns under 30 days,
installs the pair root-owned `0600`, runs `nginx -t`, and **puts the previous
pair back if nginx refuses the new one**. A management host whose UI stopped
answering is a worse outcome than a rejected replacement.

The site config has HSTS present but commented out, with the reason next to it:
HSTS makes a certificate warning unclickable, so enabling it while the
certificate is still self-signed locks every operator out of the UI — including
whoever would fix it. Enable it after installing a trusted pair.

#### Why there is no upload form

Replacing this certificate from the UI is planned, but never as a file upload.
The web identity must not be able to read private key material — that is a line
in the phase gate, verified as the real installed identity, and step 5 checks it
for all three application accounts. A form that accepts a private key would make
the web process a key handler, and a web intrusion sufficient to replace the
management host's own certificate.

The UI path being built instead: the pair is placed in a drop directory outside
the web process, the poller lists what is there, an admin picks one, and the web
process queues a job carrying only that candidate's id — never key bytes, never
a path. The worker calls the same `haproxy-ui-tls`. The web process chooses
*which*, never *what*. In practice the only difference is that the file arrives
by scp or CLI rather than through the browser.

Until then, replacement is the command above. See B21 in the decision log.

### 4.6 Accounts and signing in

There is no default password and no first-run setup page. Both are holes that
exist for the whole life of an installation in order to be useful for its first
thirty seconds: a shipped password survives in the field, and an
unauthenticated page that creates an administrator is exactly what it sounds
like.

So the first account is a local root action:

```bash
sudo haproxy-ui-user -e prod add operator --role admin
```

The password is typed at the terminal, twice, and there is deliberately no flag
to pass it as an argument — that would put it in the shell history and the
process list.

The same tool is the break-glass path when the only administrator is locked
out, forgotten, or gone:

| Command | What it does |
|---|---|
| `add <user> --role admin\|reader` | create an account |
| `reset <user>` | set a new password **and end every session that account has** |
| `disable <user>` | block sign-in and end every session |
| `enable <user>` | allow sign-in again |
| `unlock <user>` | clear the sign-in throttle |
| `revoke <user>` | end every session without changing the password |
| `list` | accounts, roles, and how many live sessions each has |

Reset and disable revoke sessions on purpose. An account that cannot sign in
again while its existing cookie keeps working has not actually been taken back
from whoever had it, which is usually why either command is being run.

`-e` names the environment, and each one is a root-owned file written by
`02-platform-database`: `/etc/haproxy-manager/ui-admin-<environment>.conf`,
holding the database name and the role to connect as. Prod and dev therefore
cannot be confused by an environment variable or a working directory.

**Root connects as the migration role**, the one that owns the schema, because
no application role holds `insert` or `update` on the account table. That is the
same boundary the running services live behind rather than an exception carved
out for tooling: the web process cannot create an administrator no matter what
it is asked to do.

#### How a session works

- **Passwords are Argon2id**, with parameters stated in the code rather than
  taken from library defaults, and a database CHECK refuses any hash that is not
  Argon2id. Changing algorithm has to be a migration, not a dependency upgrade.
- **The session token is opaque and lives only in the cookie.** The database
  stores its SHA-256 hash, so `app_session` read by anything — a dump, a backup,
  a mistake — cannot be replayed as a login. There are no claims in the token and
  no signing key to leak.
- **Cookies are `Secure`, `HttpOnly` and `SameSite=Lax`.** Lax rather than
  Strict, so arriving from a link in a mail or a dashboard still works, which is
  a normal way to reach an operations interface.
- **Two clocks, not one.** Roughly ten hours of inactivity ends a session, and an
  absolute lifetime caps one kept warm by a forgotten browser tab. The web role
  holds no `update` on `expires_at`, so use can move the first clock forward and
  nothing can move the second.
- **CSRF tokens are derived from the session token**, not stored. Producing one
  requires the cookie, which a cross-site form post can make a browser send but
  cannot read. The login form itself is protected the same way, by a short-lived
  cookie scoped to `/login`.
- **A new token on every login**, so nothing a browser held before signing in is
  still valid after.

#### The throttle

Failed sign-ins are counted per normalised username **and** client IP together.
Per username alone would let one attacker lock every real user out; per IP alone
would let one address work through a list of names.

The attempts table is **append-only by grant** — the web role can add a row and
read rows, and holds no update or delete. A counter the web process could reset
would be a lock whose key is kept behind the door. Clearing it is
`haproxy-ui-user unlock`, which is root.

The client address is taken from `X-Forwarded-For`, which the nginx site
*overwrites* rather than appends to, so a request cannot contribute its own. An
address that will not parse falls back to loopback rather than becoming an
unthrottled bucket of its own.

Every sign-in, failure, sign-out and account change is written to the audit
trail, in the same transaction as the thing it describes. What the login page
says, on the other hand, is one sentence for every kind of failure — unknown
account, wrong password, disabled account and throttled address are
indistinguishable from outside, and the same amount of time is spent on each.

### 4.6b Rolling a release back

```bash
sudo haproxy-ui-rollback --list
sudo haproxy-ui-rollback                       # the previous release
sudo haproxy-ui-rollback --to <release-id>     # a named one
```

"Point `current` back and restart" is the shape of the rollback, but doing only
that took the interface down when it was measured. Two reasons, neither visible
from the symlink:

- **Configuration is validated strictly.** Unknown keys are refused, which is
  what makes a typo an error rather than a setting that silently does nothing —
  and it means a configuration written for release N makes release N−1 refuse to
  start. **Configuration follows the same expand/contract rule as the schema:** a
  key added for a newer release has to be removed before rolling back past the
  release that introduced it.
- **Units name programs.** A unit installed for a newer release starts a program
  an older release does not contain. The poller and the worker did not exist in
  every release still on disk.

So the command checks both against the target *before* switching — asking the
target's own validator, because the answer is whatever that release says rather
than what the script believes — and verifies the interface answers afterwards,
**rolling forward by itself if it does not**. Somebody running this is already
having a bad day; leaving them on a release that does not answer, with the
rollback reported as done, is the worst outcome available.

Releases are offered oldest-last by build time rather than by name: an id ends
in a commit hash, which sorts alphabetically and says nothing about when it was
built.

### 4.7 Backups, and proving they restore

`install/platform/06-platform-backup` installs `haproxy-ui-backup`, a daily
timer, and a weekly restore check — then takes a dump and restores it
immediately, because the moment to discover that a backup does not work is
during installation rather than during an incident.

```bash
sudo haproxy-ui-backup dump            # what the daily timer runs
sudo haproxy-ui-backup verify-restore  # what the weekly timer runs
sudo haproxy-ui-backup list
```

**Dumps are root-owned `0600` in a `0700` directory**, and step 6 verifies that
none of the three application identities can read one. This is not tidiness: a
dump contains every Argon2id password hash and every session hash in the
installation, so it sits behind the same boundary as nginx's private key.

That constraint shapes the restore test. `pg_restore` there runs as the
`postgres` superuser — the only identity that may create and drop a database —
which must not be able to open the dump. So root opens the file and hands the
descriptor over: the archive is read without ever becoming readable to another
account.

#### What the dump does

- `pg_dump --format=custom`, written to a `.partial` name and renamed into
  place, so anything reading the directory sees a complete dump or none — never
  a file still being written that looks finished.
- Read back with `pg_restore --list` **before it is kept**. A zero exit from
  `pg_dump` says the command ran; this says the archive can be opened and its
  contents parsed, which is what a truncated or corrupt dump fails.
- One dump per day — today's replaces today's — and the seven newest are kept.
  Retention counts files rather than calendar days, so a week with the machine
  switched off does not delete the last dump that exists.
- Warns when the filesystem holding the dumps is over 85% full, and dumps
  anyway. A backup that refuses to run because a disk is filling is a backup
  that stops precisely when things are going wrong.

#### What the restore check does

It restores the newest dump into a scratch database that it creates and drops
itself — never a database named in configuration, because a restore test that
can be pointed at the wrong database will eventually overwrite something real.
Then it compares the result with what is live:

- row counts for `app_user`, `app_session`, `audit_event`, `login_attempt` and
  `job`, named explicitly so an empty restore cannot pass by matching zero
  against zero;
- a hard requirement that the restored `app_user` table is **not empty**, since
  an installation nobody can sign into is not a backup worth verifying;
- one row read back in full — the first account's hash must still be a valid
  Argon2id hash, because counts can match while the contents are unusable.

Any mismatch fails the unit, and the scratch database is dropped either way.

#### What is not covered

This is a database backup, and the database is not the whole installation. It
does not hold the HAProxy configuration — that lives in Git — nor the cluster
definitions, the keys, or the release tree. **Nothing here survives losing the
host**, and nor does anything else on it — the release tree, the runtime policy,
the keys, the sudoers rules. **Backing up the management host itself is a very
good idea**, and how that is done is entirely up to whoever runs it. If it is
backed up whole, these dumps are along for the ride.

That does not make them redundant. An image of a running database is
crash-consistent rather than transactionally clean, and restoring a single table
out of a machine image is not something anyone does under pressure. The dump is
what makes "put that one table back" an ordinary afternoon.

### 4.8 The worker and the poller

`install/platform/07-platform-services` installs both, each as its own operating
system account. That separation is the reason the interface can be safe at all:
a single application user would have made a web intrusion equivalent to deploy
rights.

| Identity | May | May not |
|---|---|---|
| web | authenticate, audit, queue a strictly validated job | no sudo rule, no management group, no key, cannot claim a job |
| worker | call the engine's exact helpers, claim and complete jobs | read key files, run DDL |
| poller | run exactly one read-only helper, write the status cache | read private trees directly, write a job, call any write operation |

#### The poller

It never reaches a node itself. The engine's configuration, the status account's
key and the published release tree are all outside this account's reach by
design, so the poller runs the same privileged helper the command line runs,
through one sudoers rule:

```
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-status-helper ""
```

The rule is exact because the helper **takes no arguments at all** — the cluster
arrives as a bounded JSON request on stdin. `PRIVILEGE.md` forbids wildcards in
sudoers argument matching, and without the no-argument form a rule naming a
cluster would need one. The helper also reads the release target from the
published tree rather than from its caller, so the poller cannot influence what
an operator is told is current, and it takes no lock, so a status stays
answerable while a deploy runs.

The request itself is built by the engine's own code, not by a copy of it in the
interface. Two constructions of the same request are two things to keep in step,
and each looks correct on its own — which is the hardest kind of divergence to
find.

Results go to the `cluster_status` table, one row per cluster, and every page
that shows a status also shows how old it is. `observed_at` is set by the
database — by default on insert and by trigger on update — and the poller holds
no `update` on that column: a poller that could write it could report a cluster
it never reached as freshly observed.

#### The sandbox, and the three ways it failed quietly

The poller's unit is hardened like the others, with three deliberate exceptions
that are written in the file with their reasons: `NoNewPrivileges=no`, because
sudo is setuid and the whole point of this service is to run one helper through
it; a capability set that permits changing uid, for the same reason; and network
address families, because the helper reaches nodes from inside this sandbox.

One more is worth stating separately, because it was found by running it rather
than by reasoning about it. The status identity's key is root-owned and lives
under `/root`, so the unit needs a hole in `ProtectHome` — and:

- `ProtectHome=yes` **masks** a `BindReadOnlyPaths` under `/root`. The file
  stays invisible and the service starts perfectly. `ProtectHome=tmpfs` is what
  works, because the bind then lands on top of the empty filesystem.
- A bind mount written with a leading dash is *optional*, and systemd skips it
  in silence when it cannot be satisfied. The service starts, and every cluster
  reports as unreachable — a failure that reads as a broken environment rather
  than as a missing file. The dash is deliberately not used.
- Both of those present identically: SSH exits 255 in under a tenth of a second
  and every node is `ssh_unreachable`. If that is what the cache shows, run the
  helper by hand outside the unit before suspecting the nodes:

```bash
printf '{"schema_version":1,"operation":"status","cluster":"<id>",'\
'"request_id":"'"$(uuidgen)"'","parameters":{}}' \
  | sudo -u <poller> sudo -n /opt/haproxy-mgmt/current/bin/haproxy-status-helper
```

If that answers `done`, the sandbox is the problem and not the environment.

**One poller, enforced by the database.** It holds a session-scoped advisory
lock for its whole life; a second one finds the lock taken and exits rather than
doubling the load on every node. The lock is released by the server when the
connection dies, including when the process is killed without cleanup — which is
exactly the case a lock file gets wrong.

Two failure kinds are kept apart in the table. `poll_error` means the poller
could not get an answer — sudo refused, the helper is missing, the output was
not JSON. An `outcome` of `failed` or `partial` means the cluster answered and
the answer is bad news. Collapsing them would send somebody to read sudoers when
a node is down, or the reverse.

#### The worker

It starts, connects, reports which database role it is actually running as, and
claims nothing, because management writes are off. That is deliberate rather
than unfinished: it is the state a rollback of the write path returns to, so it
has to be a state that runs.

Its unit is held **more tightly than the worker will eventually need** —
`NoNewPrivileges=yes`, an empty capability set, `AF_UNIX` only. The phase that
turns writes on has to relax that on purpose, in a diff somebody reviews, rather
than inheriting a permission nobody chose. What it will need is written in the
unit file so it is not rediscovered.

If management writes are switched on before that phase exists, the worker exits
78 and says so rather than pretending to work.

#### Which clusters get polled

`clusters` in `ui.toml`, because the application accounts cannot read the
engine's configuration and must not. The privileged helper still decides whether
each name is a real cluster; the list only says which ones to ask about. An
empty list means the poller has nothing to do and says so instead of starting.

### 4.9 A development platform beside production

The same steps install it, with a second answers file. Nothing is shared: its
own accounts, its own database and roles, its own release tree, its own port.

```bash
sudo ./01-platform-prepare   answers-dev.env
sudo ./02-platform-database  answers-dev.env
sudo UV_BIN=... ./install-ui-release answers-dev.env <source-tree>
sudo ALEMBIC_BIN=... ./migrate answers-dev.env
sudo ./04-platform-service   answers-dev.env
```

Steps 5, 6 and 7 are deliberately **not** run for development. There is no nginx
in front of it — it is reached over an SSH tunnel to its loopback port, not from
the network — it does not need backups, and it must not have the poller's
sudoers rule, because a development platform has no business reaching
production's nodes.

`ENVIRONMENT=dev` in the answers file also keeps the root commands in
`/usr/local/sbin` pointing at production. A development install would otherwise
aim the operator's rollback command at the development release, which is the one
moment a wrong answer is expensive.

#### Proving the two cannot reach each other

```bash
sudo ./08-verify-isolation answers.env answers-dev.env
```

Read-only and runnable at any time. It is every check that only exists in the
gap between the two installations, so nothing else finds it: each platform's own
privilege suite is green while asking only about its own accounts.

It asks in **both** directions. The asymmetry people expect — development is the
dangerous one — is not the only way this goes wrong: a production poller that
could write to the development database would be reporting into a void.

The first run failed on the database checks, in both directions, and the reason
is worth knowing before building anything similar. Grants in the migrations name
generic contract roles, `app_web` and friends, so that they never name a real
service account. Generic means **shared**, and two platforms on one PostgreSQL
cluster are both members of the same `app_web` — so `grant connect ... to
app_web` had given every development account a route into production.

`CONNECT` is not a column privilege, and it now goes to the environment's three
**login** roles instead, granted by the installer that knows which environment
it is installing. Column privileges stay in the migrations where they are
versioned with the column. Who may enter a database is the installation's
business; what they may do inside it is the schema's.

## Verifying the installation

Work outward, and stop at the first step that fails:

1. **Configuration status** — `haproxy-config-status -c alpha` reports the published version and a
   clean draft.
2. **Node status** — `haproxy-status -c alpha` reaches both nodes and reports the address owner,
   the release each node runs, and whether that is the published one. This proves the status key,
   its forced command, and the node reporter.
3. **A converged deploy** — `haproxy-deploy -c alpha` with nodes already current should skip both
   nodes and change nothing. A run that correctly does nothing is a real test. Step 2 should
   already have said the cluster was converged; if the two disagree, believe neither and find out
   why before deploying anything.
4. **A deploy that does something** — publish a harmless change and deploy it. Confirm the non-owner
   is deployed first, the owner last, and that the address does not move.
5. **The negative tests** in [`PRIVILEGE.md`](PRIVILEGE.md), run as the real installed identities
   rather than through mocks.

Do the last two on a cluster that carries no traffic if you have one.

## What is still missing

This guide is honest about its gaps rather than complete on paper:

- **Certificate distribution** is an interface this project consumes, not one it provides.
  Issuance is planned; renewal is deliberately out of scope and belongs to an ACME client.

Each gap is tracked in the implementation plan. The acceptance criterion for closing them is
mechanical: a new management host and a new pair of nodes, with names of your own choosing, built
from this repository alone by someone who has never seen the maintainer's environment.
