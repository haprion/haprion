# Installing Haprion

Five steps. Three run on the management host, one on each node, and the last one
checks your work.

Everything that can be scripted is scripted. A node needs one package: it prints
one line, its enrollment block, which you paste into the interface (the
Dashboard's *Set up your first cluster*, *Create cluster* or *Add node*). The management host then joins the node once,
with a key that only works for that, and prepares it itself.

[`../docs/user-manual.md`](../docs/user-manual.md) explains *why* each step
looks the way it does. This file is what you follow.

**This is a first installation.** Shipping a later change is a different
question — which of the CLI engine, the web platform and the node scripts it
touches, and in what order — and it is answered once in
[Releasing a change](../docs/user-manual.md#releasing-a-change).

## Before you start

The node package installs HAProxy and keepalived. For a cluster created in the
interface the deploy also writes each node's `keepalived.conf`
([keepalived on the nodes](../docs/user-manual.md#keepalived-on-the-nodes)).

**A cluster whose `keepalived.conf` a person writes** has to meet
[the keepalived baseline in the manual](../docs/user-manual.md#haproxy-and-keepalived-baseline):
both nodes binding the virtual address, both keepalived instances as `BACKUP`
with `nopreempt`, and the `notify_` lines that tell the management host who owns
the address. Getting those wrong does not fail loudly - it quietly makes deploys
unsafe. There is a working starting point in
[`examples/keepalived.conf.example`](examples/keepalived.conf.example), and step
4 checks all three and says so if one is missing.

The
management host needs Python 3.13+, the OS PyYAML, PyNaCl and psycopg 3 packages, `git`, `rsync`,
`openssh-client` and a `sudo` new enough for no-argument rules.

The answers file is optional. Without one every step uses the defaults in
[`defaults.sh`](defaults.sh) - standard places, no cluster - and the clusters are
created in the web interface. To choose differently, copy the example and keep
the lines you change; it is the only place you make decisions:

```bash
cp answers.example.env answers.env
$EDITOR answers.env
```

Pass it to each step below, or leave the argument out. `haprion-setup` runs the
manager's steps here and the platform's under `platform/` in order, checks what
it can before it changes anything, and reports a step that fails in words -
what went wrong, why, what to do - with its whole output in
`/var/log/haprion/setup.log` ([docs/install.md](../docs/install.md#1-choose-the-answers-or-keep-the-defaults)).

## Step 1 — prepare the management host

```bash
sudo ./01-manager-prepare answers.env
```

Creates the configuration group, the directory trees, and one Git repository per
cluster with the standard layout committed. Writes no configuration and contacts
no node.

## Step 2 — write the configuration

```bash
sudo ./02-manager-config answers.env
```

Renders `clusters.yaml` and `runtime-policy.yaml` from your answers - with no
cluster, an empty cluster file - creates the empty certificate registry the
policy names, and creates the validation-only certificate. Rendering them rather than hand-editing is the
point: what the code reads and what you reviewed cannot drift apart.

When `BACKUP_ROOT` is set it also installs the hardened
`haprion-state-backup@.service` template. A timer or *Back up now* starts one
validated cluster instance; the service itself never accepts a path or node.

It also installs the operator editing policy — the `sudoedit` rules that let the
accounts in `CONFIG_EDITORS` edit `core/haproxy.cfg` and `manual/reservations.yaml`
without a root shell, checked by `visudo` before anything is written. Leave
`CONFIG_EDITORS` empty and the step says it skipped it. The paths are written
once: after that *Create cluster* and *Remove cluster* keep them, and a rerun
changes only the editors.

## Step 3 — keys

```bash
sudo ./03-manager-keys answers.env | tee keys.txt
```

Generates the management key pairs. A node joined from the interface needs
nothing from this output: the management host hands its keys over itself.

For a node prepared by hand (below), the step prints one answers line per key -
`DEPLOY_PUBKEY=...`, `STATUS_PUBKEY=...` and so on - and `MANAGER_HOST_KEY=...`.
Put them in that node's answers file; step 4 writes each key with `restrict` and
its own forced command, and the management host's host key into root's
`known_hosts`.

## Step 4 — each node

The node package is built from the same commit on the management host:

```bash
tools/node-package.py build --source . --output-dir /path/to/protected/staging
```

Copy it to the node and install it:

```bash
sudo apt install ./haprion-node_<version>_all.deb
```

The package makes the node's accounts and the keys it fetches with, and prints
its enrollment block - one line starting with `haproxy-node-v2:` - and its host
key's fingerprint. Paste the block into the Dashboard's *Set up your first
cluster* (or *Settings* → *Create cluster*) for the first node of a cluster, or the cluster's *Add node* for the next; on the
command line it is `haprion-cluster add` or `haprion-node add` with the block on
stdin. `sudo haprion-node-key` prints a block again.

The block holds a one-time key, valid for 24 hours. The management host connects
with it once, as `_haprion-join`, whose only command is `haprion-node-join`: it
hands over its keys, its host key, the cluster and the VIP, and the node runs
`04-node-prepare` with them - the packages HAProxy and the rest need, the release
layout, the sudo rules, `node.conf`, sshd on the address the manager came in on.
Then the key is removed, and the manager asks the node for its status. Keep the
block to yourself until it is used: whoever holds it may join the node to a
manager. A node that names who may log in (`AllowUsers`, `AllowGroups`) must let
`_haprion-join` in; the package warns when it does not.

**By hand,** without the interface: an answers file with `MANAGER_HOST`, the two
fetch-key paths and step 3's lines, then

```bash
sudo /usr/share/haprion-node/install/04-node-prepare answers.env alpha
```

which prints a block naming the cluster (`haproxy-node-v1:`), added the same way.
Drain, maintenance and ready also need the admin socket line in each cluster's
`core/haproxy.cfg`; a cluster made by the interface has it.

## Step 5 — check

Back on the management host, as yourself:

```bash
./05-verify answers.env
```

Read-only. It checks file ownership and modes, that each cluster resolves, and —
the one that matters — that every node answers a status request through its own
key and forced command.

## Then prove it

`05-verify` passing means the installation answers. It does not mean it works.
Two more things, in this order, on a cluster that carries no traffic if you have
one:

1. `haprion-deploy -c alpha` with the nodes already current. It should skip both
   nodes and change nothing. A run that correctly does nothing tests the ordering
   logic for real.
2. Publish a harmless change and deploy it. Confirm the non-owner is deployed
   first, the owner last, and that the virtual address does not move.

## If a step fails

Every script is safe to run again. A failed installation is resumed by fixing
what it complained about and re-running the same step — nothing needs unpicking
first. The scripts check before they change, and say `ok`, `fixed`, `created` or
`written` per item so a second run tells you what was already right.

## Installing the CLI itself

Steps 1–3 assume the management CLI is installed. It is a separate, versioned,
hash-verified installation under `/opt/haprion`, described in
[`../docs/user-manual.md`](../docs/user-manual.md#part-3--the-versioned-cli-release).

One ordering rule from that section is worth repeating, because getting it
backwards breaks every command rather than one: **install a release before adding
runtime-policy fields that the release introduces.** The policy reader rejects
fields it does not know.
