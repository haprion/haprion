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

`status_identity` is the account `haproxy-status` becomes to read a node. It is deliberately not
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
