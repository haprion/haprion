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
- [Keeping HAProxy current](#keeping-haproxy-current)
- [Part 1 — the management host](#part-1--the-management-host)
- [Part 2 — the nodes](#part-2--the-nodes)
- [Releasing a change](#releasing-a-change)
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

### Addresses, and what to call them

If you arrive from a NetScaler or an F5, three addresses are worth naming before anything else,
because only one of the three has a word that every product agrees on.

| What it is | Here, and in HAProxy | In keepalived | NetScaler | F5 |
|---|---|---|---|---|
| the address clients connect to | `vip`, bound by a frontend | `virtual_ipaddress` | VIP | virtual server address |
| the address we connect out from | `source`, per backend | `virtual_ipaddress`, same block | SNIP | SNAT address / self IP |
| the node's own fixed address | not named; it is just the host | `unicast_src_ip` | NSIP | management address |

Two things follow from the middle row, and both matter more than the vocabulary.

**Keepalived has no separate concept for an outgoing address.** To it, both are entries in the same
`virtual_ipaddress` block - and they belong in the same block, because only the node currently
holding an address answers for it. A source address that does not move together with the VIP sends
its replies to a node that no longer carries the traffic, and that failure appears at failover
rather than at configuration time.

**HAProxy takes the source per backend, not per listener.** A site may therefore leave from a
different address than the one it arrived on. Each VIP still names a default source, so the normal
case needs no words; the `sources` table below exists for the exception.

`unicast_src_ip` is spelled out in full everywhere in this document. It is the node's own address,
it never moves, and confusing it with a source address produces a cluster that looks correct and
cannot fail over.

## Prerequisites

HAProxy Manager manages HAProxy's configuration; it does not install, patch or upgrade
HAProxy itself. Before starting, you need:

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

## Keeping HAProxy current

Which HAProxy version runs, and when it is upgraded, stays with you. That is a boundary in the
design rather than an omission, and it is worth knowing why before it matters.

Upgrading the package restarts the data plane. The whole privilege model here exists so that this
tool cannot do that on its own: every management identity is a forced command that can ask a node
to *pull* something, and nothing else. There is no push path, and a tool that could silently
restart HAProxy on a live node would need one. Package upkeep belongs to whatever already patches
these hosts — unattended upgrades, a configuration-management run, your own maintenance window —
on a schedule you choose and can pause.

Two things this project does depend on:

**The branch you run should still be receiving fixes.** HAProxy publishes maintenance status per
branch at [haproxy.org](https://www.haproxy.org/), and the binary states it too:

```console
$ haproxy -v
HAProxy version 3.4.4 2026/08/28 - https://haproxy.org/
Status: long-term supported branch - will stop receiving fixes around Q2 2031.
```

Distribution packages are often frozen at an early point release of a branch and carry backported
security fixes only, which is a different thing from running the branch's current release. Both are
defensible; they are worth telling apart deliberately rather than by default.

**The management host and the nodes should run the same branch.** The management host validates a
candidate configuration with its own `haproxy -c` before any node is asked to pull it. That check
is only meaningful while it is at least as strict as the nodes are. A validator on a *newer* branch
can accept a directive the nodes then reject — the deploy fails on the first node and rolls back,
so nothing breaks, but the check stopped doing its job. When you upgrade, do the nodes first and
the management host last, and the validator is never the newer of the two.

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

**Read your handwritten layers before adding `default-path config`.** It changes how every relative
path in the configuration resolves, and a `crt`, `map` or `errorfile` written relatively would start
resolving somewhere else. Generated configuration writes absolute paths throughout, so only
`manual/` and `core/conf.d` need looking at.

`manual/reservations.yaml` is what the handwritten half of the configuration declares about itself:

```yaml
# Hostnames a handwritten frontend already answers for, and ports it already
# binds. A generated object claiming one is refused before anything is
# committed. Both lists are optional; `{}` reserves nothing, which is what a
# cluster that has never needed one carries.
hostnames:
  - legacy.example.com
tcp_ports:
  - 8443                 # every address this cluster has
  - 192.0.2.10:8443      # only that one
reviewed:
  # Each handwritten fragment, with the SHA-256 of the bytes you read.
  core/conf.d/0010-stats.cfg: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

A bare port and a port written `:8443` mean the same thing: claimed on every
address. That is what a `bind` line without an address does, so a handwritten
listener written that way really has taken the port everywhere. Give the address
when the claim belongs to one VIP — otherwise a cluster with several of them
cannot reserve anything without blocking every managed object on all the others.
An IPv6 address is bracketed, `[2001:db8::1]:8443`, exactly as a bind line
requires.

`reviewed:` is what keeps the promise current. A reservation written once and
never revisited looks exactly like a complete one, so a listener added to a
fragment afterwards would be invisible. Naming each fragment together with the
digest of what you read closes that: when the file changes, the digest stops
matching and the next publish asks you to look again. Get the digest with
`sha256sum core/conf.d/0010-stats.cfg`.

Which files it covers is fixed, not a selection: everything under
`core/conf.d/` and `manual/conf.d/`. Listing a fragment that reserves nothing is
how you say you read it and it claims no listener — that confirmation is the
point, not the reservations it did or did not produce. A confirmation for a file
outside those directories, or a digest that is not SHA-256 hex, is refused
rather than quietly ignored.

It proves currency and that somebody looked. It does not prove the promise is
complete — only reading the fragments could, and nothing here interprets
handwritten HAProxy configuration.

The file is seeded empty by step 1 and named in the operator editing policy by
step 2. Empty is correct while nothing handwritten defines a listener; a publish
says so when the cluster carries handwritten fragments this file does not
account for, and when a fragment has changed since it was confirmed.

`core/haproxy.cfg` is the handwritten `global` and `defaults` for the cluster — the file every
generated fragment is assembled behind. It must declare the TLS defaults every listener falls back
to when it names no policy of its own:

```haproxy
global
    # ... your own log, chroot, socket and user lines ...

    # Relative paths in the configuration resolve against the directory of the
    # file they are written in. A generated bind line reaches its certificate
    # list that way, and the node validates a copy of a release at one path
    # before installing it at another - one line, both places, nothing rewritten.
    default-path config

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
```

**A publish is refused while these disagree with the manager's own lists**, and the refusal prints
the exact line to write. The reason is that both halves are true at once: a generated bind line that
names a TLS policy carries the manager's list, and every listener naming no policy inherits this
one. While the two differ, what protects a given listener depends on which line HAProxy read last —
and each file looks entirely correct read on its own. That is how one such pair came to be a cipher
apart without anything reporting it.

The list is Mozilla's intermediate recommendation, guideline v5.7; the
manager holds it in `haproxy_mgmt/tls_policy.py` with the date it was last checked. Nothing fetches
it at run time. If you deliberately change it, change it there first and in every cluster's `core/`
after — the refusal will tell you which clusters are still behind.

A **revert** is never refused for this. Going back to a release that was good before must not depend
on a file being current.

An HTTPS object may override its VIP's TLS policy. The generated certificate list then contains an
explicit SNI-filtered row for every object, so several names may use the same wildcard certificate
with different policies. The first, unfiltered row is an intentional fallback: a client with no or
unknown SNI inherits the VIP/bind policy. When one listener carries several effective policies,
HAProxy also returns `421 Misdirected Request` if the HTTP Host belongs to a different policy group
than the connection's SNI; HTTP/2 connection reuse remains possible between names in the same group.

Nothing derives this file — `manual/` is read, never interpreted, and a promise a person writes is
the only thing available. It exists because both collisions are silent: two frontends binding one
port both bind it under `SO_REUSEPORT` and the kernel splits new connections between them at random,
so the publish reports success and the node answers correctly for about half the traffic, and a
hostname claimed twice is answered by whichever frontend HAProxy reached first.

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

probe_identity:
  user: "svc-status"
  key: "/root/.ssh/id_ed25519_probe"

backup_root: /srv/state-backups
backup_timer: haproxy-state-backup.timer
```

`certificate_root` is also what a publish reads to check that each site's certificate answers for
its hostnames. HAProxy loads a certificate; it does not check it against the objects using it, so a
name the certificate cannot answer for reaches visitors as a browser error while every layer here
reports success. **Leave the root unconfigured and that check does not run** - the publish succeeds
and nothing says the question went unasked. Choosing a certificate that does not cover the name on
purpose stays possible with the certificate mismatch override, which is asked for per publish rather
than written into the object.

`backup_root` is where the state backup engine writes one directory per node, and it is what
`haproxy-list-backups` reads. Called with no cluster, that command lists every configured cluster
in turn - it reads `clusters.yaml` as the calling user, the same way `haproxy-cluster-config` does,
only to learn which clusters exist. Each listing is still resolved inside the privilege boundary by
one helper call per cluster. Only metadata is ever reported from it - archive name, size and
modification time. The archives themselves hold password hashes and private SSH keys, so the root
stays root-owned and no command opens one; the helper exists precisely so that an unprivileged
caller can learn a backup exists without being able to read it.

`backup_timer` is the systemd timer that produces those archives, and it is optional. Declaring it
lets `haproxy-list-backups` answer the question the directory listing cannot: whether anything is
still taking backups, or whether these are the ones a timer stopped adding to. The command reads
the unit with `systemctl show`, which reports properties and changes nothing - it never enables,
starts or edits a unit, and no interface can. Leave it out and the listing simply says nothing
about a schedule, which is the honest answer for an installation whose backups are produced by
something this project does not know about.

Changing the schedule stays a systemd operation on the manager: `systemctl edit <unit>` followed by
`systemctl restart <unit>`, as root. Taking one backup right now stays `haproxy-state-backup`.

`status_identity` is the account `haproxy-status` becomes to read a node, and `haproxy-deploy`
uses it too: a rollout reads the pair before and after every step, and it reads with the identity
that cannot change a node rather than the one it triggers with. Both commands refuse to run
without it instead of falling back to the deploy identity. It is deliberately not
the deploy identity: reading status is the one thing the manager asks a node to do that cannot
change it, so it is the identity that can be granted most widely, and keeping it separate is what
preserves that difference. Without it, `haproxy-status` says exactly which field is missing.

`probe_identity` is what the interface uses to ask a node to *try* a health check - open a
connection to the servers an object names, from the address that object leaves from, and report
whether they answered. It logs in as the same account status does and still carries its own key,
because it is a different thing to grant: status reads what a node already knows, while this makes
the node open a connection to an address the caller chose. The forced command behind it needs no
sudo, returns a status and never a response body, and refuses anything that is not a bounded list
of targets. Leave it out and the button in the editor says the probe is unavailable; nothing else
changes.

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

    # Opt in to the separate structured stream used by the traffic-log
    # collector.  The setting reaches the nodes when an object is next
    # published; changing this file alone does not deploy a configuration.
    traffic_logging: true
```

`node_path` is the subdirectory a node fetches from on the management host. It is the only
per-cluster value the node side needs.

A release directory holds that subdirectory and, beside it, `MANIFEST.json` - the manager's own
record of what each object in that release amounts to. It is written outside `node_path`
deliberately: a node fetches that subdirectory whole with `--delete`, and HAProxy loads everything
in `conf.d` with `-f`, so a file the manager keeps for itself has no business being inside either.
Nothing on the node side reads it, and a release published before this existed simply has none -
the status then reports each object as unknown rather than guessing.

`address_prefix` and `address_interface` are optional and describe how this pair's nodes write an
address they carry:

```yaml
    address_prefix: 24          # from the nodes' own virtual_ipaddress block
    address_interface: ens192   # likewise; names differ between installations
```

They are used for one thing: rendering the keepalived address list a release carries. **Read both
values off the nodes rather than choosing them**: whatever stands in their `virtual_ipaddress`
block today is what the generated list has to reproduce. A line reading `<address>/24 dev ens192`
means `address_prefix: 24` and `address_interface: ens192`. Nothing here requires a particular
interface name - the field exists precisely because it differs between installations - and a
cluster whose nodes name no interface should leave `address_interface` out, so that keepalived
keeps using the `vrrp_instance`'s own. Omitted, an address is written bare, which
keepalived reads as `/32` on the `vrrp_instance`'s own interface. **A bare address is not the same
address:** a `/32` carries no subnet route and is not chosen as a source address for the segment,
so a cluster whose nodes use a prefix must say so or moving the list into the generated file would
change the network rather than only where the list is written.

They live here rather than in `managed/network.yaml` because a prefix length is a statement about
the network the pair sits on, not about which addresses the cluster serves - and `clusters.yaml` is
root-owned, so the interface cannot change them.

#### Optional per-cluster sections

Four sections may be added. All of them are optional, and a cluster that omits every one of them
behaves exactly as the example above.

```yaml
    # Named addresses the generated frontends bind, each with the source
    # address it connects to backends from - what an ADC calls a SNIP. A
    # proxy object names the VIP it sits on; it never names an address.
    # Omitted, the cluster has one VIP called `main`, taken from `vip` above.
    vips:
      internal:
        address: 192.0.2.10
        source: 192.0.2.15
      dmz:
        address: 198.51.100.10
        # Which TLS versions and ciphers this listener accepts: `intermediate`
        # for TLS 1.2 and 1.3, `modern` for 1.3 alone. Optional, and left out
        # the listener takes what core/ sets through ssl-default-bind-*, which
        # is what every cluster does today. Read that file before naming a
        # policy here: the bind line overrides those defaults in both
        # directions, so a policy can loosen a stricter cluster as well as
        # tighten a looser one.
        tls: modern
    default_vip: internal

    # The resolvers section in core/ that generated server lines point at.
    # Without it, a backend named by hostname is resolved once at startup and
    # not again until the next reload.
    resolvers: cluster-dns

    # Named source addresses an object may connect out from instead of the one
    # its VIP pairs with. HAProxy takes the source per backend, so the pairing
    # in `vips` is a default rather than a rule.
    sources:
      outbound: 192.0.2.15

    # Named address groups an object may restrict itself to with `allow_from`.
    # An object may also write an address or range directly, for what belongs
    # to one site alone.
    networks:
      office:
        - 198.51.100.0/24

    # What a request for a hostname no object claims is answered with. Without
    # it, HAProxy answers 503. Set exactly one of `status` or `redirect`.
    unknown_host:
      status: 404
```

`vip` keeps its original meaning and is unchanged: it is the address whose ownership `deploy`
checks before it acts. One node holds every virtual address at a time, so that single check answers
for all of them.

**Three of those tables have a second, preferred home.** `vips`, `sources` and `networks` may
instead live in `managed/network.yaml` inside the cluster repository, and that is where a new
installation puts them:

```yaml
# /configs/haproxy/<cluster>/managed/network.yaml
vips:
  internal:
    address: 192.0.2.10
    source: 192.0.2.15
default_vip: internal
sources:
  outbound: 192.0.2.35
networks:
  office:
    - 198.51.100.0/24
```

The file wins where it exists; a cluster without one keeps answering from `clusters.yaml`, and
nothing has to be migrated. The reason for the move is that these three describe *what gets
published*, while everything left in `clusters.yaml` describes *how the system itself runs* -
paths, identities, keys, the resolvers section, the certificate allowlist, and the `vip` line
above. The repository is owned by the application, which means these tables can be edited in the
interface through the same publish path as a proxy object, with the same lock, the same history and
the same revert, and without the web identities gaining any access to the engine's configuration.

`vip` deliberately did not move. It is what `deploy` checks node ownership against, and a control
the interface can rewrite is not a control. `managed/network.yaml` is refused outright if it names
it.

**Adding a VIP here does half the job by default.** The other half is keepalived on the nodes: no
node carries the address until it is in the `virtual_ipaddress` block, and until then no traffic
reaches the frontend however correct the generated configuration is. The same applies to a source
address, which additionally must sit in the *same* block as the VIP - see [Addresses, and what to
call them](#addresses-and-what-to-call-them).

**The other half can be handed to the deploy.** A published release carries
`keepalived/addresses.conf`, derived from `managed/network.yaml`: every VIP and every source
address, one per line, with a comment saying which is which. `haproxy-pull-deploy` installs it at
`/etc/keepalived/addresses.conf` on each node, and a node whose `keepalived.conf` includes that
path gets a `keepalived --config-test` and a reload - **only** on exit 0, because keepalived skips
an address it cannot parse at runtime and carries on, which would turn a mistyped address into a
VIP that never appears and never says why. A failed test restores the previous list and reports
the deploy as failed with the HAProxy configuration already live.

**That failure leaves the node half-way, and the status says which half.** The configuration is
live on the new release while the address list is the old one, so the release hash alone would
report the node as up to date and a second deploy would pass over the node that still needs the
work. `haproxy-node-status` therefore reports three measurements about the list - the digest the
release publishes, the digest the node installed, and whether `keepalived.conf` includes it - and
both `haproxy-status` and `haproxy-deploy` call a node current only when every component the
release owns is where it should be. Re-running the deploy after fixing the cause finishes the half
that was left; the node script syncs the addresses even on a release it already runs.

The include is reported and never compared. Putting that line into `keepalived.conf` is a person's
step, taken one node at a time (below), and a deploy that treated it as a target would try forever
to reach a state only a human can put the node in.

The application writes the address list and nothing else. `priority`, `virtual_router_id`,
`authentication`, `unicast_src_ip`, `unicast_peer` and the `notify_` lines stay in a file a person
edits. Those decide who owns an address, and getting one wrong gives two masters or none - neither
of which `--config-test` catches, because both are runtime behaviour rather than syntax. An extra
line in `virtual_ipaddress` cannot cause either, which is what makes this half safe to generate.

**Switching a node over, in this order:**

1. Deploy once, so `/etc/keepalived/addresses.conf` exists. Until a node's `keepalived.conf`
   mentions that path the file is installed and inert, and the deploy says so.
2. Compare it against the addresses in the node's own `virtual_ipaddress` block. They must already
   agree; this step changes where the list is written, not what is in it.
3. On **one node at a time, the address owner last**, with a backup of `keepalived.conf`: replace
   the addresses in the block with `include /etc/keepalived/addresses.conf`, run
   `keepalived --config-test -f /etc/keepalived/keepalived.conf`, and reload only if it passes.
4. Prove it from another host - the address still answers ARP from the same node - before touching
   the second node.

An `include` naming a file that does not exist yet is a keepalived that will not start. That is the
whole reason step 1 comes first.

**The node's status helper has to be able to follow that include.** `haproxy-node-status` reports
whether this node currently carries the address by reading the `virtual_ipaddress` block and
looking the address up on the interface. Once the block holds nothing but the include, a helper
that reads only the block finds no address and answers that ownership is unknown - on both nodes.
That is not a cosmetic answer: a deploy refuses to run without a known owner, so the whole cluster's
deployment path stops. Install the node scripts from the same release as the manager before
switching a node over, and confirm afterwards with `haproxy-status -c <cluster>` that the owner is
named and the state is `single_owner`.

**A cluster that sets `resolvers` must provide the section itself in `core/`**, since nameserver
addresses are environment values the generator never invents:

```text
resolvers cluster-dns
    nameserver ns1 192.0.2.53:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s
```

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
  helper reads its request as one bounded JSON line on stdin. A caller that runs an operation it may
  later need to stop keeps that stream open as a lifeline; see `PRIVILEGE.md`. No rule grants a shell, an interpreter, an
  editor, a wildcard path, environment preservation, or unrestricted arguments. The web identity
  has no sudo rule at all.
- **Operator rules.** A `sudoedit` policy listing the configuration files an administrator may
  edit, by exact path. `sudoedit` is what makes editing possible without making the repositories
  group-writable.

  **Remove the rule in the same change that removes the file.** `sudoedit` creates a file it does
  not find, so a rule naming a path that no longer exists is not merely stale - it is a standing
  way to place a new root-owned file at that path, in a directory the configuration is loaded from,
  outside the set anyone reviewed. Rewrite the whole alias rather than deleting the line: the last
  entry carries no trailing comma, so removing a line can move that position and leave the file
  syntactically broken. Validate with `visudo -cqf` before installing, and keep the backup outside
  `/etc/sudoers.d/` - a superseded policy file inside the directory the privilege system reads is
  protected only by the convention that names containing a dot are skipped.

Every sudoers file is root-owned and read-only (`0440` or stricter). See [`PRIVILEGE.md`](PRIVILEGE.md)
for the full contract and the negative tests that prove it.

## Part 2 — the nodes

The scripts are in [`install/node/`](../install/node/) and are installed by
[`04-node-prepare`](../install/04-node-prepare), which also creates the accounts, the release
layout and the sudo rules.

Later updates use the versioned node bundle in section 2.5. The bundle runs the same idempotent
step, but do not mistake that for a script-only copy: the step also reconciles service accounts,
directory ownership and modes, `node.conf`, sudoers, the HAProxy baseline and the complete script
attestation. Read every reported `created`, `fixed`, `written` and `installed` line on the pilot
before another node is touched.

This section explains what they do and why; run the script rather than following it by hand.


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

**The unit must load `conf.d`, and must load it exactly once.**

A node's configuration is a main file plus a directory of fragments, and systemd has to be told
about both:

```text
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f $CFGDIR -p $PIDFILE $EXTRAOPTS
```

Upstream's packaging does this and sets `CFGDIR=/etc/haproxy/conf.d`. Some distribution packages
ship a unit with only `-f $CONFIG`, and installations working around that have historically
smuggled the directory in through the variable itself:

```text
# Don't. This breaks the moment the unit gains -f $CFGDIR of its own.
Environment="CONFIG=/etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d"
```

Against a unit that already loads `CFGDIR`, that reads the directory **twice**, every proxy is
declared twice, and HAProxy refuses to start — duplicate proxy names are an error as of 3.3, where
they were a warning before. Check the effective invocation rather than the unit file, since
drop-ins and `/etc/default/haproxy` both feed into it:

```console
$ systemctl cat haproxy
$ grep -vE '^\s*#|^\s*$' /etc/default/haproxy
```

`systemctl show haproxy -p Environment` is not a substitute: it reports only the unit's own
`Environment=` lines. `EnvironmentFile=` is read when the service starts, never appears there, and
overrides them.

This matters beyond startup. `haproxy-pull-deploy` validates with its own explicit arguments —
each file named once — so a configuration can validate cleanly while the service will not start.
The two paths only agree if the unit names each path once too.

**Both nodes run keepalived as `BACKUP`, with `nopreempt`.**

```text
vrrp_instance alpha {
    state           BACKUP        # both nodes - not MASTER on either
    interface       eth0          # whatever carries the VIP on your nodes
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

Four service accounts, identical on every node. They are system accounts with no password, a home
directory for `authorized_keys`, and — deliberately — a real login shell:

| Account | Reached by | May run |
|---|---|---|
| `svc-trigger` | the management host's deploy and cert-deploy keys | the pull scripts, through forced commands |
| `svc-backup` | the management host's backup path | the state export |
| `svc-status` | the management host's status key | the node status reporter, read-only |
| `svc-logread` | the production collector's traffic-log key | the bounded traffic-log reader, read-only and without sudo |

**The shell looks like a mistake and is not.** sshd runs a forced command through the account's
login shell, so `nologin` here does not harden anything — it stops every forced command from
working, and the only symptom is a nologin message where output was expected.

What constrains these accounts is that each key carries `restrict` and its own forced command, so a
session cannot run anything else. Where sudo is needed, its rules name exact absolute commands;
`svc-logread` needs and receives no sudo rule. None of this depends on the shell.

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
| `haproxy-node-status` | reports version, health, carried certificates, keepalived state and the address list |
| `haproxy-keepalived-state` | records the keepalived transition to a state file |
| `haproxy-state-export` | writes this node's permanent state to stdout as a gzipped tar |
| `haproxy-health-probe` | opens one connection per named target and reports the status line |
| `haproxy-traffic-log-read` | returns whole records after a validated UTC day/cursor, capped at 8 MiB |
| `haproxy-traffic-log-enable` | installs or removes this node's rsyslog route and retention timer |
| `haproxy-traffic-log-prune` | deletes traffic day files past the 14-day window, whole and never renamed |

Step 4 also writes `/etc/haproxy-manager/node-installation.json`. It records the
node compatibility API and a SHA-256 digest for each of these ten scripts.
`haproxy-node-status` recomputes the digests on every reading, so copied metadata
cannot hide a script changed after installation. The report contains code
digests only, never node configuration or key material.

Two of these deserve attention:

**`haproxy-cert-trigger` exists because sudoers cannot express a list.** The certificate IDs arrive
as SSH command arguments, and no wildcard rule can safely constrain them. So validation happens
twice: unprivileged in the wrapper, and again in the root helper. The wrapper escalates with
`sudo -n` and an exact `NOPASSWD` rule, so a policy mismatch fails immediately instead of falling
back to an interactive password prompt.

**`haproxy-health-probe` is held to the same TLS floor as the configuration.** A pool whose object
names a `legacy` policy is reached by HAProxy over TLS 1.1, so a probe that kept a floor of its own
would refuse a backend HAProxy accepts and report a healthy pool as down. Each target therefore
carries a `min_version` — `TLSv1.1`, `TLSv1.2` or `TLSv1.3` — and the script refuses anything else.

A target that names none means `TLSv1.2`, which is what a manager older than the field sends. The
degradation runs the other way too and is worth knowing: a **node** older than the field ignores it
and probes at TLS 1.2 regardless, so a `legacy` pool reads as unreachable until that node's script
is updated. The configuration is unaffected — only the answer the card gives.

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

The releases root is `root:root 0750`. HAProxy, deployment, status and backup operations read it as
root; no forced-command service account needs to traverse it. Files inside an immutable release
may remain `0644` without thereby exposing the active configuration to those accounts.

A deploy never edits the running configuration. It builds a new immutable release directory, swaps
the `current` symlink atomically, validates again through exactly the paths `systemd` uses, and only
then reloads. If either validation or the reload fails, the symlink is swapped back.

`/run/lock` itself belongs to the operating system and is commonly mode `1777`. The node installer
requires it to exist but never changes its owner or permissions; HAProxy Manager owns only its
root-created lock files inside the directory.

### 2.5 Installing and changing node scripts

There is no unattended management-identity path for this, by design. Every management identity is
a forced command; none of them can copy a file. Installing or changing a node script crosses an
administrator's own interactive SSH login and escalates with `sudo` on the node.

The repository does automate everything around that interactive boundary. A node release is a
minimal tar archive containing only `04-node-prepare`, `lib.sh`, the ten attested node scripts and
an internal manifest. Platform installers, examples, caches and the source tree do not belong in
it. Environment answers remain a separate root-owned input; putting them in the code artifact
would make two installations of the same commit produce different releases.

#### Build and verify the bundle

Use a clean, committed source tree that has passed the complete repository gate. Build into a
protected staging directory outside the repository:

```bash
commit="$(git rev-parse --short=12 HEAD)"
bundle="/path/to/protected/staging/haproxy-manager-node-${commit}.tar.gz"

tools/node-bundle.py build \
  --source "$(pwd)" \
  --output "$bundle"
```

The builder refuses a dirty tree, an existing output file, a missing payload file, a symlink and an
unexpected Git file mode. It reads payload bytes and modes from the commit rather than the working
tree, then prints the full source commit, release name and SHA-256. Record the digest beside the
artifact; do not derive trust from a digest received with an untrusted copy.

The archive is deterministic: building the same commit twice produces identical bytes. Its
`MANIFEST.json` binds every path, mode and content digest to the full commit. Verify a retained or
transferred copy without extracting it:

```bash
tools/node-bundle.py verify \
  --bundle "$bundle" \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Verification rejects an external digest mismatch, an unsafe or duplicate path, a symlink, a
special file, an unmanifested member, changed bytes or modes, and files or archives over their hard
size limits.

#### Preflight and install one node

Measure the pair immediately before an update and select the node that does not own the virtual
address:

```bash
haproxy-status -c alpha
```

Run the transport as your administrator account, never as root. All paths must be absolute. The dry
run verifies the bundle locally, opens the operator's normal host-key-checked SSH path, checks the
node's cluster and prerequisites, and writes neither a backup nor a staging file:

```bash
tools/install-node-bundle --dry-run \
  --bundle /path/to/protected/staging/haproxy-manager-node-0123456789ab.tar.gz \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --answers /path/to/answers.env \
  --node node-b \
  --cluster alpha
```

Remove `--dry-run` to install. The tool:

1. verifies the external digest and complete internal manifest before contacting the node;
2. takes a state backup before the first remote write;
3. uses one multiplexed, strictly host-key-checked SSH session for staging and installation;
4. copies only the bundle and the separate answers file to a random mode-700 directory under
   `/tmp`, then verifies the bundle digest again on the node;
5. runs the bundle's own `04-node-prepare` through the operator's interactive `sudo` path;
6. takes another state backup and runs `haproxy-status` for the cluster; and
7. removes its remote and local staging automatically. A cleanup failure is a visible warning that
   names the exact directory; remove only that named directory after inspecting it.

The SSH login and the node's sudo authentication are deliberately interactive. The shared SSH
session means each is requested once per node, not once per file. The management identities remain
forced commands and gain no file-copy ability.

Stop after the first node and read both the install report and `haproxy-status`. A successful copy
proves bytes, modes and ownership; run the command that uses a changed script before proceeding.
Remeasure VIP ownership before every subsequent node — never assume it stayed where the previous
status reading found it.

`haproxy-traffic-log-enable` and its `--disable` path restart rsyslog because rsyslog does not load
a changed rule on HUP. HAProxy does not buffer while its local log socket is unavailable, so a
request during that sub-second restart can be absent from both the structured day file and the
classic log. Run the command on the node that does not own the VIP first, remeasure ownership, and
then run it on the owner. The command repeats this loss window in its final output; a successful
restart cannot recover a line emitted while rsyslog was down.

#### Rollback

Keep the previous node bundle and its recorded SHA-256. A code rollback is the same verified
installation command with that retained bundle; there is no special path that bypasses manifest or
hash checks. Re-run the functional command and `haproxy-status` afterwards.

State backups are taken on both sides of every update so account, policy and configuration changes
also have a recovery point. They are not restored automatically: an automatic whole-node restore
after a partial failure could overwrite unrelated state that changed during the window. Stop on a
failure, preserve the reported backup, note any cleanup warning and determine which reported
operation completed before restoring state.

Optional features have their own symmetric rollback. For traffic logging, disable the node route
with `sudo haproxy-traffic-log-enable --disable`, remove only that collector key's forced-command
line from `svc-logread` and disable the manager collector. Traffic files are deliberately retained;
rollback never deletes evidence.

## Releasing a change

Three things install independently — the CLI engine, the web platform, and the
node scripts — and a release ships only the ones a change actually touched.
Which of them a change touched is a question with a measurable answer, so
measure it rather than deciding by feel:

```bash
git show --stat <commit>
```

| What the commit touched | What to release |
|---|---|
| `src/haproxy_mgmt/`, `tools/`, `install/` | the CLI wheel — [Part 3](#part-3--the-versioned-cli-release) |
| `ui/` | the platform, `update-platform-release`, development then production |
| `install/node/`, node scripts | the node bundle, per [Part 2](#part-2--the-nodes) |
| more than one of those | **the CLI wheel first**, then the platform, then the nodes |

**The CLI wheel goes first when both move**, and the order is not a preference.
The platform check deliberately compares the independently installed CLI before
it activates a UI candidate, so releasing the UI first stops its own update —
correctly, but after it has already prepared and migrated.

**Development before production**, for the same reason both exist: production
is where the real configuration lives, so it is the environment where a bad
release costs something.

A CLI-only change does not need a UI release, and forcing one would be the
mistake the compatibility check was built to avoid. It compares engine API
levels and helper names, never release hashes, precisely so an engine
correction does not drag an unrelated UI rollout along with it. What decides
whether the running UI still fits the new engine is:

- `src/haproxy_mgmt/compatibility.json` — the engine API the wheel carries. A
  UI release declares the minimum it needs.
- the console scripts in `pyproject.toml` — the check requires every helper the
  UI names by name.

Unchanged in both means the running UI keeps working, whatever the new release
is called. Changed in either means the UI release moves with it, in that order.

**Prove it afterwards rather than assuming it.** The install steps each prove
their own result; the whole-installation check answers the different question of
whether the independently installed pieces still work together:

```bash
sudo install/platform/check-compatibility /path/to/answers.env
```

Run it against the production answers file after any of the three. Development
installs no CLI, no worker, no poller and no nodes — that is its isolation
boundary, not a skipped check — so its own check cannot say anything about an
engine release.

**Every release is a commit.** Both installers refuse a source tree with
uncommitted changes, because a release built from an edited tree is one nobody
can reproduce, and the moment it runs, "what is in it" has no answer. Run the
full repository gate before building; a release is not the place to find out
that a test fails.

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

`INSTALLATION.json` also records the engine compatibility API carried by the
wheel. A wheel from before that metadata existed remains installable for
rollback and is recorded as API zero; the whole-installation check will not
silently treat an unknown old engine as compatible with a newer UI.

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
├── releases/<version>-<commit>/migration/
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

The release is also compared with its source tree before activation. The check
covers Python, templates, CSS, JavaScript and the complete Alembic environment;
a build that reused an older local wheel or omitted a frontend asset is removed rather than activated. This keeps
the visible interface under the same “a release is a commit” rule as its server
code.

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

`install/platform/check-compatibility` is the read-only check above that local
database proof. Run it after the independently released pieces have been
installed:

```bash
sudo ./check-compatibility /path/to/answers.env
```

The running UI release supplies the accepted database revisions and minimum CLI
and node APIs. The command reports both release IDs, queries `alembic_version`,
checks that worker, poller and web really execute from `current`, compares the
active sudo rules with the helpers the UI requires, and reads each node bundle
through the existing status helper. It ends in one `COMPATIBLE` or `INCOMPATIBLE`
verdict and changes no file, row, service or HAProxy release.

For the development platform described below, the command follows its smaller
installed boundary: UI release, database revision and web process, plus the
absence of a sudo rule for the web account. Development deliberately has no
worker, poller or node access, so an empty `clusters` list and those absent
components are required isolation rather than missing production pieces.

For an update, first run `install-ui-release --prepare`. The candidate is built
and verified but `current` stays on the old release. Run `check-compatibility
--release <release-id> --before-migration` to prove its CLI, helper and node
requirements, then `migrate --release <release-id>`, `03-verify`, and the candidate
check again without `--before-migration`. Only after those pass is the same
prepared release activated by rerunning `install-ui-release` without `--prepare`.
The final ordinary compatibility check proves the processes after the switch.

The first bridge may encounter a running release from before compatibility
metadata existed. It can be activated only when its database head is exactly the
revision already running, so the operation makes no schema change. A candidate
that would migrate from such a release is refused because rollback safety cannot
be inferred without metadata.

`update-platform-release` owns that complete order for normal updates:

```bash
sudo ./update-platform-release /path/to/answers.env /path/to/source-tree
```

The CLI and node scripts remain independent installations; the command checks
them and stops before migration when either is too old. It also requires the
currently running UI to accept the candidate's declared database head. When a
new revision would not be safe for the old process and for rollback, first ship
a bridge UI release whose compatibility metadata accepts both revisions, then
ship the migration release. A failure after activation runs the installed UI
rollback command and checks the restored processes before returning failure.

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

#### What the two roles see

A **reader** sees every page and can press nothing. An **admin** can queue the
operations the interface offers, and sees two things a reader does not.

- **The error code** of an operation that did not end cleanly — the stable,
  environment-independent string the engine blamed, such as
  `cluster_not_converged` or `ssh_unreachable`. It is shown verbatim rather than
  translated, and it is the same string the command line prints beside its
  message and the audit trail records, so what a terminal said and what the page
  says can be compared without guessing.
- **The operation's diagnostics** — its redacted stderr, folded away under the
  job until asked for. Private keys, `token`/`password`/`secret` assignments and
  sensitive paths are masked before the text is ever stored, and it is capped at
  64 KiB.

The diagnostics contain **real host names, node names and the proxy's own
output**, which is what makes them worth showing. Masking covers secrets, not
the identity of the environment. So: a screenshot of that panel does not belong
in an issue, a README, a support ticket or anywhere else outside the
installation.

Withholding raw diagnostics from a *reader* is what the contract requires;
withholding them from an administrator as well was a habit that cost the one
person who had to open an SSH session at every failure, and bought nobody
anything in an installation where the reader and the administrator are the same
person.

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

### 4.8 Keeping jobs and metric history bounded

`install/platform/11-platform-retention` installs `haproxy-ui-retention` and a
daily timer. It is optional, and it is separate from the backup step because
it is the only thing here that removes rows from a live table. **The step itself
deletes nothing** — it reports what the first run would remove and leaves the
deciding to the timer or to an operator.

```bash
sudo haproxy-ui-retention report              # how many rows, how many removable
sudo haproxy-ui-retention prune --dry-run     # the same, deleting nothing
sudo haproxy-ui-retention prune               # what the daily timer runs
```

**It is a root command because no application role holds `delete` on any table,
and none is going to.** That is the same boundary as the audit trail and the
login attempts: a compromised web or worker process must not be able to remove
the record of what it did. The migration role owns the table and may therefore
delete from it, and the ident map lets root — and only root — be that role for
this database. The step verifies that last part rather than describing it: if an
application identity could connect as the owning role, nothing about `delete`
being ungranted would matter.

#### What it removes, and what it will not

- **Finished jobs older than seven days.** A management request older than that
  has been acted on or superseded, and *what it did* is in the audit trail,
  which this never touches.
- **Never a `pending` or `running` job**, however old. Those are the states the
  single-active-job index is built on, and removing one would let a second
  operation start against a cluster that is still being changed. Every other
  state carries a `finished_at` by the table's own constraint, so the age test
  cannot match a row that has no timestamp.
- **Never the twenty most recent rows**, whatever their age. Without that floor
  a quiet fortnight empties the jobs page completely, which reads as the
  interface having lost its history rather than as nothing having happened.
  Twenty is the number the page itself lists, **ordered the way the page orders
  them**, so the floor is exactly the set a reader can see. Ordered any other
  way it would select a different twenty rows and quietly stop promising
  anything.

The timer runs daily, after the daily dump rather than before it, so the newest
dump still contains the rows the prune removes.

The same command creates the metric tables' future partitions, writes the pool's
hourly rollup and removes expired partitions. It performs those actions in that
order. The rollup and its `metric_rollup_state` completion boundary are written
by one SQL statement; a failed statement advances neither. Only then may raw
pool partitions be dropped, and only when their complete day is at least one
further day behind that boundary. Listener metrics have no rollup and keep their
fixed seven-day raw retention.

The interface normally changes from raw pool samples to the hourly rollup at
seven days. If maintenance has fallen behind, it moves that boundary back to the
last continuously completed hour and reads the still-retained raw samples from
there. An hour with no samples still advances the boundary: the marker says the
interval was considered, whereas the newest rollup row cannot distinguish an
empty hour from an unprocessed one. `report` prints the boundary so lag is
visible without changing the database.

The timer is daily because that normally keeps the completed edge six days
ahead of the preferred reader boundary. The explicit boundary is what keeps a
longer outage correct; the schedule is no longer treated as proof that work
finished. The installed command also remains usable against revision `0020`
during a staged upgrade. There it rolls up before age-based pruning but cannot
publish a completion boundary until migration `0021` exists.

Unlike the backup step, this one is meant to be run for development too — a
development platform's job table grows exactly as production's does, and
rehearsal traffic fills it fastest. Its units are therefore named after the
environment, since a machine carrying both platforms would otherwise have two
timers pruning each other's database.

### 4.8b Mirroring node traffic logs

`install/platform/13-platform-traffic-collector` installs a fourth, deliberately
small identity and a timer that asks each node for its own traffic log. Optional,
production only, and last: nothing else on the platform depends on it.

```text
${PLATFORM_ROOT}/logs/mirror     collector writes, the interface reads
${PLATFORM_ROOT}/logs/staging    the collector's alone
/etc/haproxy-manager/traffic-collector/{id_ed25519,known_hosts}
/etc/haproxy-manager/traffic-collector.json
```

The collector program itself is installed with the CLI engine under
`/opt/haproxy-mgmt/current`, not inside the web release. This is a privilege boundary rather than
packaging trivia: web releases are traversable only by the platform group, while the collector
deliberately does not join that group and therefore cannot read `ui.toml`. The engine release is
root-owned, immutable and executable without granting access to the platform configuration.

**The direction is manager to node, and that is the whole design.** The first
attempt had each node forward its log to the management host over TLS, and a DMZ
node correctly could not open that connection. Nothing here asks for a new
network path in any topology: the management host already reaches every node
over SSH for configuration, certificates and status, so this adds one key to a
path the product already requires. An installation whose firewall differs still
needs nothing new.

**A fourth account that joins nothing.** The collector is not a member of the
configuration group, holds no database role and has no sudoers rule. It owns one
SSH key, and the far end of that key is a forced command that can return one
validated day of one node's traffic log and nothing else. The step checks that
boundary rather than describing it, and checks it by traversal: `ls` on a
directory fails whether or not an account can reach through it, so listing is not
evidence.

**Host keys are copied from what this host already trusts, never scanned.**
`ssh-keyscan` asks a node who it is and believes the answer. If a node has no
pinned key yet, the step refuses and says so; accept that one deliberately,
once, through the path that already exists.

**The mirror is a sibling of `data/`.** Reaching a mirror under `data/logs`
would mean opening `data/` for traversal by the web account, and `data/dumps`
holds every session and every audit record in one file. The mirror directory is
set-group-id, because the collector is deliberately outside the web account's
group and could not otherwise create a file the interface can read.

**No collector on a development platform.** The step refuses unless
`ENVIRONMENT` is `prod`. A development platform is built not to reach the real
nodes, and giving it a key and an inventory would undo exactly that.

The step fetches nothing on its own. It prints one `authorized_keys` line to add
to `svc-logread` on each node, and each node also needs its own log route
switched on with `sudo haproxy-traffic-log-enable`.

Enabling or disabling that node route restarts rsyslog; a reload does not apply
the rule. HAProxy does not buffer log lines during the brief restart, so apply
the change to the node that does not own the VIP first, verify it, remeasure VIP
ownership and only then change the owner. A request landing in the restart
window can be absent from both the structured and classic local logs.

The stream is also opt-in per cluster. Set `traffic_logging: true` in that
cluster's entry in `clusters.yaml`, then publish an actual object change so the
generator's log profile reaches the nodes. Rerun platform step 13 whenever a
node is added to or removed from `clusters.yaml`; `check-compatibility` refuses
a running traffic-log view while the collector's installed node list differs.

Only the structured stream removes query strings, and only that stream is
mirrored to the manager and shown in the interface. HAProxy's ordinary
`haproxy.log` remains byte-for-byte unchanged and its traditional HTTP log line
contains the complete request target, including any query string. Treat that
local file accordingly when choosing retention, backup and access controls.

The interface reads the mirror once `[traffic_logs]` is enabled in `ui.toml`. It
reads files and never asks a node anything, so an unreachable node cannot make a
page slow — it can only make its own mirror old. The page therefore names every
node and how old its mirror is **before** the records, because a node that
stopped answering renders an empty table that otherwise reads as calm. Log text
is written by whoever made the request and is escaped as text, never as markup.

### 4.9 The worker and the poller

`install/platform/07-platform-services` installs both, each as its own operating
system account. That separation is the reason the interface can be safe at all:
a single application user would have made a web intrusion equivalent to deploy
rights.

| Identity | May | May not |
|---|---|---|
| web | authenticate, audit, queue a strictly validated job | no sudo rule, no management group, no key, cannot claim a job |
| worker | call the engine's exact helpers, claim and complete jobs | read key files, run DDL |
| poller | run exact read-only metadata helpers, write the status, inventory and history caches | read private trees directly, write a job, call any write operation |

#### The poller

It never reaches a node itself. The engine's configuration, the status account's
key and the published release tree are all outside this account's reach by
design, so the poller runs the same privileged helper the command line runs,
through exact sudoers rules:

```
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-status-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-inventory-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-list-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-list-backups-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-list-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-network-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-objects-helper ""
```

##### How often it reads, and what wakes it

`poller.interval_seconds` in `ui.toml`, 20 by default, bounded to 10-3600. It is
a sleep *after* a pass rather than a fixed period, so the real cadence is the
interval plus however long a pass takes - measured at 2-3 seconds for two
clusters on the reference machine, where one pass is fourteen helper
invocations and two of them reach the nodes.

**A finished job wakes it as well as the clock.** Publishing or deploying
through the interface queues a job, and the poller reads the clusters again as
soon as that job ends - so those changes appear without waiting. What waits is a
change made *outside* the interface: `haproxy-publish` or `haproxy-deploy` run
on the command line queues no job, nothing is notified, and until the next tick
the pages show the reading taken before the change. An object deployed from the
command line therefore keeps its `Inactive - deploy to add` badge for up to one
interval, which is the interface being careful rather than wrong.

The configuration file is written by `01-platform-prepare` **only when it is
absent**, so an edit here survives every later release. Changing the value takes
effect when the poller is restarted; it reads its configuration once, at start.

**A rule under `/etc/sudoers.d/` does not travel with a release.** Adding a helper here means
installing its line separately, `visudo`-checked; a release that carries a helper nobody may run
fails at the first call with sudo's refusal in the diagnostics rather than at install time.

The rule is exact because the helper **takes no arguments at all** — the cluster
arrives as a bounded JSON request on one line of stdin. `PRIVILEGE.md` forbids wildcards in
sudoers argument matching, and without the no-argument form a rule naming a
cluster would need one. The helpers read their target inside the boundary. In
particular, inventory reads the exact commit named by the published RELEASE
stamp rather than the repository work tree, so an unpublished change cannot be
presented as live. The list helper reads saved commit metadata — version number,
timestamp and comment — and no file content at all. The backup helper reads
directory metadata under the state backup root and never opens an archive,
which is what lets an account that must not read password hashes and private
SSH keys still report that a backup exists. The certificate helper reports
metadata about the distribution root, and about which certificates certbot is
renewing on this host; private key material never reaches its output, because
what it parses is the leaf certificate alone. The network helper reads one
cluster's `managed/network.yaml` — a file whose directory is group-readable by
the engine's own group and by nobody else, which is why the interface cannot
simply open it — and reports the three address tables plus which of the two
possible sources they came from. None takes a lock, so these
reads stay answerable while a deploy runs.

`haproxy-list` itself does not use that helper: a person running it can already
read the cluster repository, so the command reads it directly and requiring
`sudo` for machine-readable output would be privilege for formatting. Both paths
build their result with the same function, so the two cannot come to describe
the same history differently.

The request itself is built by the engine's own code, not by a copy of it in the
interface. Two constructions of the same request are two things to keep in step,
and each looks correct on its own — which is the hardest kind of divergence to
find.

Results go to `cluster_status`, `cluster_inventory` and `cluster_history`, each
with one row per cluster, and every page shows how old the answer it uses is. `observed_at` is
set by the database — by default on insert and by trigger on update — and the
poller holds no `update` on that column: a poller that could write it could
report a cluster it never reached as freshly observed.

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

Once writes are on, each pass first settles jobs whose worker died. An expired
lease says only that the process holding a job stopped renewing its authority,
so the job is judged by what can be read rather than retried on assumption: a
publish, a revert or a managed-network publish by whether a version carrying that request exists and
whether its release was published, a deploy or a certificate deploy by nothing
at all, because those read the cluster before they act and repeating one is how
they work. Evidence older than the expired lease is not weak evidence but none —
it describes a world in which the operation could still have been running — and
such a job waits rather than being decided. A job is handed to a worker at most
twice; one that has been taken twice and answered neither time ends as
`unknown`, which is the outcome reserved for "nobody can say whether this took
effect" and is never retried automatically.

This too is below the writes check. With writes off nothing moves at all,
including a job somebody would rather see moved — which is what makes the flag a
rollback rather than a pause.

#### What the worker may run

Five helpers, each with no arguments, in `/etc/sudoers.d/<worker>`:

```
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-revert-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-network-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-objects-publish-helper ""
```

Publishing was deliberately absent from that list until the editor existed, on the reasoning that
it was an operator's decision made at a terminal. What changed is that the interface became where
those decisions are made: an editor that can only save a draft is an editor whose work has to be
finished somewhere else, and asking somebody to leave the screen and log in to a shell to complete
a change is how a change gets left unfinished. Publishing still writes nothing to a node — that is
deploy, a separate helper and a separate decision.

**`07-platform-services` installs this file**, `visudo`-checked, since 2026-09-03. Before that it
was installed by hand, and it fell behind exactly as this document warns: the file predated the
objects-publish helper, so the publish button would have met sudo's refusal on its first use. If you
are upgrading an installation that was built earlier, rerun that step.

**The worker may not touch `proxy_draft`.** Only the web role holds grants on it. The worker
publishes from the job payload, never from the table, which is why a draft that has been published
is cleared by the interface on its next read rather than by the worker as it finishes. The clearing
matches on the publish's idempotency key, which carries the draft revision — so a draft edited after
the publish was asked for has a different key and is left alone.

#### The web service, and why it has no sudoers rule at all

The web service asks the nodes exactly one thing: try this health check. Nothing
else it does reaches outside the database.

That one thing needs root, because the probe identity's key is root-owned — no
application account may hold a key that reaches a node. The obvious way to grant
it would be a sudoers rule, one exact no-argument helper, the way the poller's
seven are granted. **That does not work here, and it is worth knowing why before
somebody writes the rule again.**

The web unit carries `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`
and `RestrictSUIDSGID=yes`. Under `NoNewPrivileges` the kernel ignores the setuid
bit, so `sudo` fails *before it reads `/etc/sudoers.d/`* — it fails however the
rule is written, and the rule then sits on disk saying this account may become
root while granting nothing at all. The poller solves the same problem by
relaxing its own sandbox (`NoNewPrivileges=no`, a capability set that permits
changing uid); doing that to the web service would trade the one boundary most
worth keeping for a button.

So the privilege stays still and the request travels instead:

```
/run/haproxy-mgmt/probe.sock   root:<web> 0660, created by haproxy-probe-helper.socket
haproxy-probe-helper@.service  runs the helper as root, one instance per connection
```

The web service opens the socket, writes one JSON request, closes its write side,
and reads one JSON answer. The far end takes no arguments and does exactly one
thing, so reaching it is worth no more than the sudo rule would have been — and
the web account keeps a sandbox in which nothing it runs can gain privilege.

`haproxy-probe` on the command line still goes through `sudo`, because a person
running it has a terminal and a `%sudo` rule. Both build the request with the
same function, so the two paths cannot come to describe the same probe
differently.

**A development platform must not get this socket.** It reaches the real nodes.
`PROBE_SOCKET=no` in its answers file is the default, and its interface then says
the probe is unavailable rather than showing an empty result.

#### Which clusters get polled

`clusters` in `ui.toml`, because the application accounts cannot read the
engine's configuration and must not. The privileged helper still decides whether
each name is a real cluster; the list only says which ones to ask about. An
empty list means the poller has nothing to do and says so instead of starting.

### 4.10 A development platform beside production

The same steps install it, with a second answers file. Nothing is shared: its
own accounts, its own database and roles, its own release tree, its own port.

```bash
sudo ./01-platform-prepare   answers-dev.env
sudo ./02-platform-database  answers-dev.env
sudo ./install-ui-release   answers-dev.env <source-tree>
sudo ./migrate               answers-dev.env
sudo ./04-platform-service   answers-dev.env
```

Steps 5, 6 and 7 are deliberately **not** run for development. It does not need
backups, and it must not have the poller's sudoers rule, because a development
platform has no business reaching production's nodes.

By default development has no nginx site and is reached over an SSH tunnel to
its loopback port. If browser review needs a direct development address, add a
distinct `SERVER_NAME` to the dev answers file, provision DNS for it, and run:

```bash
sudo ./09-dev-nginx answers-dev.env
```

Step 9 is deliberately separate from production's step 5: it makes a second
nginx virtual host to the dev loopback port, with a separate certificate path
and `haproxy-ui-dev-tls` command. It neither exposes the development port
directly nor changes the production vhost or certificate. A self-signed pair is
generated when no development pair has been supplied; an internal-PKI pair can
later replace it through the dev-specific command.

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
3. **The stored objects** — `haproxy-objects -c alpha` lists the proxy objects as they are written,
   at the commit the repository is on, and `--show <name>` prints one document exactly as stored.
   Where `haproxy-inventory` parses what a node is serving, this reads the source that produced it -
   so an object the generator refuses is listed with the refusal rather than left out.
4. **A converged deploy** — `haproxy-deploy -c alpha` with nodes already current should skip both
   nodes and change nothing. A run that correctly does nothing is a real test. Step 2 should
   already have said the cluster was converged; if the two disagree, believe neither and find out
   why before deploying anything.
5. **A deploy that does something** — publish a harmless change and deploy it. Confirm the non-owner
   is deployed first, the owner last, and that the address does not move.
6. **The negative tests** in [`PRIVILEGE.md`](PRIVILEGE.md), run as the real installed identities
   rather than through mocks.

Do the last two on a cluster that carries no traffic if you have one.

## What is still missing

This guide is honest about its gaps rather than complete on paper:

- **Certificate distribution** is an interface this project consumes, not one it provides.
  Issuance is planned; renewal is deliberately out of scope and belongs to an ACME client.

Each gap is tracked in the implementation plan. The acceptance criterion for closing them is
mechanical: a new management host and a new pair of nodes, with names of your own choosing, built
from this repository alone by someone who has never seen the maintainer's environment.
